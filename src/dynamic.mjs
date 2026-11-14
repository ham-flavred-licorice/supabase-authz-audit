// @ts-check
// Dynamic pass: act as user A, as an anonymous visitor, and as user A with self-edited
// user_metadata, exactly the way PostgREST does it (SET LOCAL ROLE + request.jwt.claims),
// and try to read, change, delete and forge rows that belong only to user B.
//
// Everything runs inside ONE transaction that is always rolled back, and each probe runs
// inside its own savepoint. The database is left exactly as it was found.

import { Params, quoteIdent, quoteLiteral, inlineParams } from './db.mjs'

const KIND = { r: 'table', p: 'table', v: 'view', m: 'materialized view' }
const TEXTISH = (type) => type === 'uuid' || type === 'text' || type === 'citext' || type.startsWith('character varying')
const singular = (name) => name.replace(/ies$/, 'y').replace(/s$/, '')
const normParam = (name) => String(name ?? '').toLowerCase().replace(/^(p_|in_|arg_|v_|_)+/, '')
const IDENTITY_PARAM = /(user|owner|uid|profile|account|member|author|customer|creator)/
const joinAnd = (list) => (list.length <= 1 ? list.join('') : `${list.slice(0, -1).join(', ')} and ${list.at(-1)}`)
const lowerFirst = (s) => s.charAt(0).toLowerCase() + s.slice(1)

function typeDefault(type) {
  if (/^(smallint|integer|bigint|numeric|real|double precision)/.test(type)) return '1'
  if (type === 'text' || type.startsWith('character')) return 'authz-audit'
  if (type === 'boolean') return 'true'
  if (type === 'json' || type === 'jsonb') return '{}'
  if (type === 'date' || type.startsWith('timestamp')) return new Date().toISOString()
  if (type.endsWith('[]')) return '{}'
  return null
}

/**
 * @param {import('./db.mjs').Db} db
 * @param {any} cat      result of loadCatalog()
 * @param {any} cfg      resolved config (see config.mjs)
 */
export async function runDynamic(db, cat, cfg) {
  const { ids, roles } = cfg
  /** @type {any[]} */
  const findings = []
  const coverage = { relations: /** @type {any[]} */ ([]), functions: /** @type {any[]} */ ([]) }

  const claims = (sub, extra = {}) => ({ sub, role: roles.authenticated, aud: 'authenticated', app_metadata: {}, user_metadata: {}, ...extra })
  const personas = {
    A: { key: 'A', label: 'Logged-in user A', role: roles.authenticated, claims: claims(ids.A) },
    B: { key: 'B', label: 'Logged-in user B', role: roles.authenticated, claims: claims(ids.B) },
    anon: { key: 'anon', label: 'An anonymous visitor', role: roles.anon, claims: { role: roles.anon } },
    forged: {
      key: 'A+user_metadata', label: 'User A, after editing their own user_metadata', role: roles.authenticated,
      claims: claims(ids.A, { user_metadata: cfg.forgedUserMetadata }),
    },
  }

  // ---- ownership model ---------------------------------------------------------------------
  const rels = cat.relations.map((r) => ({
    ...r,
    isTable: r.kind === 'r' || r.kind === 'p',
    ownerCols: cfg.ownership?.[r.ident]?.map(quoteIdent) ?? r.columns.filter((c) => c.type === 'uuid').map((c) => c.ident),
  }))
  const relByOid = new Map(rels.map((r) => [r.oid, r]))
  /** keys.get(`${who}:${parentOid}:${fcol}`) = key values of rows associated with that user */
  const keys = new Map()

  /** Rows associated with a user: an owner column equals their id, or a foreign key points at such a row. */
  const assocSql = (r, who, P) => {
    const terms = r.ownerCols.map((c) => `${c}::text = ${P.add(ids[who])}`)
    for (const fk of r.fks) {
      const k = keys.get(`${who}:${fk.parentOid}:${fk.fcol}`)
      if (k?.length) terms.push(`${fk.col}::text = ANY(${P.add(k)}::text[])`)
    }
    return terms.length ? `(${terms.join(' OR ')})` : 'false'
  }
  /** Rows that belong to `owner` and have no link to `other` (shared rows are never counted as leaks). */
  const privateSql = (r, P, owner = 'B', other = 'A') =>
    `${assocSql(r, owner, P)} AND NOT coalesce(${assocSql(r, other, P)}, false)`

  let sp = 0
  /** Run fn inside a savepoint that is rolled back no matter what. */
  const sandbox = async (fn) => {
    const name = `authz_audit_${++sp}`
    await db.exec(`SAVEPOINT ${name}`)
    try {
      return { ok: true, value: await fn(), code: null, message: '' }
    } catch (e) {
      const err = /** @type {any} */ (e)
      return { ok: false, value: undefined, code: err?.code ?? null, message: String(err?.message ?? e) }
    } finally {
      await db.exec(`ROLLBACK TO SAVEPOINT ${name}; RELEASE SAVEPOINT ${name}`)
    }
  }
  /** Become a persona the way PostgREST does for one request. */
  const become = async (p) => {
    await db.query(
      `SELECT set_config('request.jwt.claims', $1, true), set_config('request.jwt.claim.sub', $2, true),
              set_config('request.jwt.claim.role', $3, true)`,
      [JSON.stringify(p.claims), p.claims.sub ?? '', p.role],
    )
    await db.exec(`SET LOCAL ROLE ${quoteIdent(p.role)}`)
  }
  const repro = (p, statement, note) =>
    [
      'begin;',
      `select set_config('request.jwt.claims', ${quoteLiteral(JSON.stringify(p.claims))}, true);`,
      `set local role ${quoteIdent(p.role)};`,
      `${statement};${note ? `  -- ${note}` : ''}`,
      'rollback;',
    ].join('\n')
  const blockedBy = (res) => (res.code === '42501' ? 'denied' : `error ${res.code ?? ''}`.trim())

  /** Collect per-persona hits, then emit one finding per (rule, object). */
  const collector = (object) => {
    const hits = new Map()
    return {
      hit(rule, p, evidence, reproduce) {
        if (!hits.has(rule)) hits.set(rule, [])
        hits.get(rule).push({ p, evidence, reproduce })
      },
      /** @param {Record<string, { severity: (anon: boolean) => string, title: (who: string) => string, fix: string }>} spec */
      emit(spec) {
        for (const [rule, list] of hits) {
          const anon = list.some((h) => h.p.key === 'anon')
          const worst = list.find((h) => h.p.key === 'anon') ?? list[0]
          const who = joinAnd(list.map((h, i) => (i === 0 ? h.p.label : lowerFirst(h.p.label))))
          findings.push({
            id: `${rule}:${object}`, rule, source: 'dynamic', severity: spec[rule].severity(anon), object,
            personas: list.map((h) => h.p.label), title: spec[rule].title(who),
            evidence: Object.fromEntries(list.map((h) => [h.p.key, h.evidence])),
            reproduce: worst.reproduce, fix: spec[rule].fix,
          })
        }
      },
    }
  }
  const readSeverity = (anon) => (anon ? 'critical' : 'high')

  await db.exec('BEGIN')
  try {
    await db.exec(`SET LOCAL statement_timeout = ${Number(cfg.statementTimeoutMs)}`)

    // Follow foreign keys to a fixed point so child rows inherit their parent's owner.
    const wanted = new Map()
    for (const r of rels) for (const fk of r.fks) if (relByOid.get(fk.parentOid)?.isTable) wanted.set(`${fk.parentOid}:${fk.fcol}`, fk)
    for (let round = 0; round < 6; round++) {
      let changed = false
      for (const [k, fk] of wanted) {
        const parent = relByOid.get(fk.parentOid)
        for (const who of ['A', 'B']) {
          const P = new Params()
          const where = assocSql(parent, who, P)
          const rows = (await db.query(
            `SELECT DISTINCT ${fk.fcol}::text AS k FROM ${parent.ident} WHERE ${where} AND ${fk.fcol} IS NOT NULL LIMIT ${Number(cfg.maxKeys)}`,
            P.values,
          )).rows.map((x) => x.k).sort()
          const prev = keys.get(`${who}:${k}`) ?? []
          if (rows.length !== prev.length) { keys.set(`${who}:${k}`, rows); changed = true }
        }
      }
      if (!changed) break
    }

    const countPrivate = async (r, extra = '') => {
      const P = new Params()
      return (await db.query(`SELECT count(*)::int AS n FROM ${r.ident} WHERE ${privateSql(r, P)}${extra}`, P.values)).rows[0].n
    }

    // ---- tables and views -------------------------------------------------------------------
    for (const r of rels) {
      const cov = {
        relation: r.ident, kind: KIND[r.kind], rls: r.isTable ? r.rls : null, policies: r.policy_count,
        b_rows: 0, status: 'exercised', owner_can_read: /** @type {number|null} */ (null), probes: /** @type {any} */ ({}),
      }
      coverage.relations.push(cov)
      const linked = r.ownerCols.length > 0 || r.fks.length > 0
      const total = linked ? await countPrivate(r) : 0
      cov.b_rows = total
      if (!total) {
        cov.status = linked ? 'not exercised: no rows that belong only to user B' : 'not exercised: no ownership link found'
        continue
      }
      const col = collector(r.ident)

      const readAs = async (p) => {
        const P = new Params()
        const sql = `SELECT count(*)::int AS n FROM ${r.ident} WHERE ${privateSql(r, P)}`
        const res = await sandbox(async () => { await become(p); return (await db.query(sql, P.values)).rows[0].n })
        return { res, text: inlineParams(sql, P.values) }
      }
      cov.owner_can_read = (await readAs(personas.B)).res.value ?? 0

      const seen = {}
      for (const p of [personas.A, personas.anon]) {
        const probes = (cov.probes[p.key] = {})
        const rd = await readAs(p)
        seen[p.key] = rd.res.ok ? rd.res.value : 0
        probes.read = rd.res.ok ? `${rd.res.value}/${total}` : blockedBy(rd.res)
        if (rd.res.ok && rd.res.value > 0) {
          col.hit('cross-user-read', p, { visible_rows: rd.res.value, user_b_rows: total }, repro(p, rd.text, `expected 0, got ${rd.res.value}`))
        }
        if (!r.isTable || !cfg.writes) continue

        const writable = r.columns.filter((c) => c.generated === '' && c.identity !== 'a')
        const upCol = writable.find((c) => c.ident !== r.pk) ?? writable[0]
        // A constraint error (class 23) can only be raised for a row that already passed authorization.
        const authzPassed = (res) => (res.ok ? res.value > 0 : String(res.code ?? '').startsWith('23'))
        const how = (res) => (res.ok ? `${res.value} row(s) affected` : `authorization passed; stopped only by constraint ${res.code}`)

        // UPDATE and DELETE aimed at user B's rows.
        let updated = false
        if (upCol) {
          const P = new Params()
          const sql = `UPDATE ${r.ident} SET ${upCol.ident} = ${upCol.ident} WHERE ${privateSql(r, P)}`
          const res = await sandbox(async () => { await become(p); return (await db.query(sql, P.values)).rowCount })
          updated = authzPassed(res)
          probes.update = updated ? 'ALLOWED' : res.ok ? 'blocked' : blockedBy(res)
          if (updated) col.hit('cross-user-update', p, { result: how(res), user_b_rows: total }, repro(p, inlineParams(sql, P.values), 'expected 0 rows'))
        }
        let deleted = false
        {
          const P = new Params()
          const sql = `DELETE FROM ${r.ident} WHERE ${privateSql(r, P)}`
          const res = await sandbox(async () => { await become(p); return (await db.query(sql, P.values)).rowCount })
          deleted = authzPassed(res)
          probes.delete = deleted ? 'ALLOWED' : res.ok ? 'blocked' : blockedBy(res)
          if (deleted) col.hit('cross-user-delete', p, { result: how(res), user_b_rows: total }, repro(p, inlineParams(sql, P.values), 'expected 0 rows'))
        }

        // Blind writes: with no WHERE clause only the write policy applies, so a caller who
        // cannot read user B's rows may still be allowed to change them.
        if (!deleted) {
          const res = await sandbox(async () => {
            await become(p)
            await db.query(`DELETE FROM ${r.ident}`)
            await db.exec('RESET ROLE')
            return await countPrivate(r)
          })
          if (res.ok && res.value < total) {
            probes.delete = 'ALLOWED (blind)'
            col.hit('cross-user-delete', p, { blind: true, user_b_rows_before: total, user_b_rows_after: res.value },
              repro(p, `DELETE FROM ${r.ident}`, 'DESTRUCTIVE if committed: keep it inside this transaction'))
          }
        }
        const blindCol = writable.find(
          (c) => (c.type === 'text' || c.type.startsWith('character varying')) && c.ident !== r.pk &&
            !r.ownerCols.includes(c.ident) && !r.fks.some((fk) => fk.col === c.ident),
        )
        if (!updated && blindCol) {
          const marker = 'authz-audit-probe'
          const res = await sandbox(async () => {
            await become(p)
            await db.query(`UPDATE ${r.ident} SET ${blindCol.ident} = ${quoteLiteral(marker)}`)
            await db.exec('RESET ROLE')
            return await countPrivate(r, ` AND ${blindCol.ident} = ${quoteLiteral(marker)}`)
          })
          if (res.ok && res.value > 0) {
            probes.update = 'ALLOWED (blind)'
            col.hit('cross-user-update', p, { blind: true, user_b_rows_changed: res.value, user_b_rows: total },
              repro(p, `UPDATE ${r.ident} SET ${blindCol.ident} = ${quoteLiteral(marker)}`, 'DESTRUCTIVE if committed: keep it inside this transaction'))
          }
        }

        // Forged insert: replay an exact copy of one of user B's rows as this persona.
        if (writable.length) {
          const P0 = new Params()
          const img = (await db.query(
            `SELECT ${writable.map((c, i) => `${c.ident}::text AS c${i}`).join(', ')} FROM ${r.ident} WHERE ${privateSql(r, P0)} LIMIT 1`,
            P0.values,
          )).rows[0]
          const vals = writable.map((_, i) => img[`c${i}`])
          const sql = `INSERT INTO ${r.ident} (${writable.map((c) => c.ident).join(', ')}) VALUES (${writable.map((c, i) => `$${i + 1}::text::${c.type}`).join(', ')})`
          const res = await sandbox(async () => { await become(p); return (await db.query(sql, vals)).rowCount })
          const forged = res.ok || String(res.code ?? '').startsWith('23')
          probes.insert = forged ? 'ALLOWED' : blockedBy(res)
          if (forged) {
            col.hit('cross-user-insert', p,
              { result: res.ok ? 'row inserted' : `row passed the authorization check; only constraint ${res.code} stopped it (the probe replays an existing row)` },
              repro(p, inlineParams(sql, vals), 'expected: new row violates row-level security policy'))
          }
        }
      }

      // Does editing your own user_metadata unlock more rows?
      const fg = await readAs(personas.forged)
      if (fg.res.ok && fg.res.value > (seen.A ?? 0)) {
        cov.probes[personas.forged.key] = { read: `${fg.res.value}/${total}` }
        col.hit('metadata-escalation-read', personas.forged,
          { visible_rows_before: seen.A ?? 0, visible_rows_after: fg.res.value, forged_user_metadata: cfg.forgedUserMetadata },
          repro(personas.forged, fg.text, `expected ${seen.A ?? 0}, got ${fg.res.value}`))
      }

      col.emit({
        'cross-user-read': {
          severity: readSeverity, title: (who) => `${who} can read rows in ${r.ident} that belong only to user B`,
          fix: r.isTable
            ? `Scope the SELECT policy on ${r.ident} to the caller, for example USING (user_id = auth.uid()). If RLS is off, turn it on first.`
            : `Make the view respect the caller's row access: ALTER VIEW ${r.ident} SET (security_invoker = true);`,
        },
        'cross-user-update': {
          severity: () => 'critical', title: (who) => `${who} can update user B's rows in ${r.ident}`,
          fix: `Scope the UPDATE policy on ${r.ident} with both USING and WITH CHECK tied to the caller.`,
        },
        'cross-user-delete': {
          severity: () => 'critical', title: (who) => `${who} can delete user B's rows in ${r.ident}`,
          fix: `Scope the DELETE policy on ${r.ident} to the caller. A DELETE policy must never be wider than the SELECT policy.`,
        },
        'cross-user-insert': {
          severity: readSeverity, title: (who) => `${who} can insert rows into ${r.ident} that are attributed to user B`,
          fix: `Add WITH CHECK to the INSERT policy on ${r.ident} so the owner must be auth.uid().`,
        },
        'metadata-escalation-read': {
          severity: () => 'high', title: () => `Editing their own user_metadata lets user A read user B's rows in ${r.ident}`,
          fix: `Do not use user_metadata in access rules; users can change it themselves. Use app_metadata or a roles table.`,
        },
      })
    }

    // ---- functions exposed as RPC -------------------------------------------------------------
    if (cfg.rpc.enabled) {
      const tables = rels.filter((x) => x.isTable)
      const tokensB = new Set(), tokensAAny = new Set([ids.A]), tokensAPrivate = new Set()
      const byName = { A: new Map(), B: new Map() }
      const pkOf = { A: new Map(), B: new Map() }
      const harvest = async (r, where, P, onRow) => {
        const rows = (await db.query(
          `SELECT ${r.columns.map((c, i) => `${c.ident}::text AS c${i}`).join(', ')} FROM ${r.ident} WHERE ${where} LIMIT ${Number(cfg.maxRows)}`,
          P.values,
        )).rows
        rows.forEach((row, n) => onRow(row, n))
      }
      const tokensOf = (r, row) => r.columns.flatMap((c, i) => (TEXTISH(c.type) && row[`c${i}`] && row[`c${i}`].length >= 8 ? [row[`c${i}`]] : []))
      const remember = (who, r, row) => {
        const put = (k, v) => { const key = k.toLowerCase(); if (v != null && !byName[who].has(key)) byName[who].set(key, v) }
        r.columns.forEach((c, i) => put(c.name, row[`c${i}`]))
        const i = r.columns.findIndex((c) => c.ident === r.pk)
        if (i >= 0 && row[`c${i}`] != null) {
          pkOf[who].set(singular(r.name).toLowerCase(), row[`c${i}`])
          for (const k of [`${singular(r.name)}_id`, `${r.name}_id`]) put(k, row[`c${i}`])
        }
      }
      for (const r of tables) {
        let P = new Params()
        await harvest(r, privateSql(r, P), P, (row, n) => { tokensOf(r, row).forEach((t) => tokensB.add(t)); if (n === 0) remember('B', r, row) })
        P = new Params()
        await harvest(r, assocSql(r, 'A', P), P, (row) => tokensOf(r, row).forEach((t) => tokensAAny.add(t)))
        P = new Params()
        await harvest(r, privateSql(r, P, 'A', 'B'), P, (row, n) => { tokensOf(r, row).forEach((t) => tokensAPrivate.add(t)); if (n === 0) remember('A', r, row) })
      }
      for (const t of tokensAAny) tokensB.delete(t)
      tokensB.add(ids.B)

      /** Fingerprint of every row that belongs only to `owner`, per table. */
      const digests = async (owner, only) => {
        const other = owner === 'B' ? 'A' : 'B'
        const m = new Map()
        for (const r of only ?? tables) {
          const P = new Params()
          const row = (await db.query(
            `SELECT count(*)::int AS n, coalesce(md5(string_agg(h, '' ORDER BY h)), '-') AS d
               FROM (SELECT md5(_r::text) AS h FROM ${r.ident} AS _r WHERE ${privateSql(r, P, owner, other)}) s`,
            P.values,
          )).rows[0]
          m.set(r.ident, row)
        }
        return m
      }
      const baseline = { A: await digests('A'), B: await digests('B') }
      const watched = {
        A: tables.filter((r) => baseline.A.get(r.ident).n > 0),
        B: tables.filter((r) => baseline.B.get(r.ident).n > 0),
      }

      const overloaded = (f) => cat.functions.filter((g) => g.ident === f.ident).length > 1
      /** Pick argument values that point at `who`'s data. Overloads get every argument so the call is unambiguous. */
      const resolveArgs = async (f, who) => {
        const wantedArgs = overloaded(f) ? f.in_args : f.in_args.slice(0, f.in_args.length - f.ndefaults)
        const fill = (v) => String(v).replaceAll('{target}', ids[who]).replaceAll('{A}', ids.A).replaceAll('{B}', ids.B)
        const out = []
        for (const a of wantedArgs) {
          const override = cfg.rpc.args?.[f.signature]?.[a.name]
          const n = normParam(a.name)
          const tableHit = n === 'id' ? [...pkOf[who].keys()].find((t) => f.name.toLowerCase().includes(t)) : undefined
          if (override !== undefined && override !== null && typeof override === 'object') {
            const row = (await db.query(fill(override.sql))).rows[0]
            out.push({ name: a.name, value: row ? String(Object.values(row)[0]) : null, source: 'config (sql)' })
          } else if (override !== undefined) {
            out.push({ name: a.name, value: override === null ? null : fill(override), source: 'config' })
          } else if (tableHit) {
            out.push({ name: a.name, value: pkOf[who].get(tableHit), source: `a ${tableHit} id of the target user` })
          } else if (byName[who].has(n)) {
            out.push({ name: a.name, value: byName[who].get(n), source: `target user's data (${n})` })
          } else if (a.type === 'uuid' || (a.type === 'text' && IDENTITY_PARAM.test(n))) {
            out.push({ name: a.name, value: ids[who], source: `target user's id` })
          } else {
            out.push({ name: a.name, value: typeDefault(a.type), source: 'type default' })
          }
        }
        return out
      }
      const callSql = (f, n) => {
        const ph = Array.from({ length: n }, (_, i) => `$${i + 1}::text::${f.in_args[i].type}`).join(', ')
        return f.rettype === 'void'
          ? `SELECT ${f.ident}(${ph})`
          : `SELECT left(coalesce(jsonb_agg(to_jsonb(_r)), '[]'::jsonb)::text, 400000) AS out FROM ${f.ident}(${ph}) AS _r`
      }
      /** Call f as persona p, then (privileged again) check whether `watch`'s rows changed. */
      const invoke = async (f, p, args, watch) => {
        const sql = callSql(f, args.length)
        const vals = args.map((a) => a.value)
        const res = await sandbox(async () => {
          await become(p)
          const out = String((await db.query(sql, vals)).rows[0]?.out ?? '')
          await db.exec('RESET ROLE')
          const after = await digests(watch, watched[watch])
          const changed = watched[watch].flatMap((r) => {
            const b = baseline[watch].get(r.ident), a = after.get(r.ident)
            return a.d !== b.d ? [{ table: r.ident, rows_before: b.n, rows_after: a.n }] : []
          })
          return { out, changed }
        })
        // The report shows the plain call; the audit itself wraps it to capture the output as JSON.
        const ph = vals.map((_, i) => `$${i + 1}::${f.in_args[i].type}`).join(', ')
        const plain = f.rettype === 'void' ? `SELECT ${f.ident}(${ph})` : `SELECT * FROM ${f.ident}(${ph})`
        return { res, text: inlineParams(plain, vals) }
      }

      for (const f of cat.functions) {
        const cov = {
          function: f.signature, security_definer: f.secdef, fixed_search_path: f.has_search_path,
          execute: { anon: f.anon_exec, authenticated: f.auth_exec, service_role: f.service_exec, PUBLIC: f.public_exec },
          args: /** @type {any[]} */ ([]), results: /** @type {any} */ ({}), gap: false,
        }
        coverage.functions.push(cov)
        const skipped = cfg.rpc.skip.includes(f.signature) || cfg.rpc.skip.includes(f.ident)
        if (skipped || f.variadic || f.in_args.some((a) => a.type.startsWith('any'))) {
          cov.results.note = skipped ? 'skipped by config' : 'not exercised: variadic or polymorphic arguments'
          cov.gap = !skipped
          continue
        }
        const target = await resolveArgs(f, 'B')
        const own = await resolveArgs(f, 'A')
        cov.args = target.map((a) => ({ name: a.name, source: a.source }))
        const passed = new Set(target.map((a) => a.value))
        const ownArgs = new Set(own.map((a) => a.value))
        const col = collector(f.signature)
        const trivial = (out) => ['', '[]', 'null', '[null]'].includes(out)
        // Lazily computed: what user B gets for B's own values, and what user A gets for A's own values.
        let reference = null, control = null
        const getReference = async () => (reference ??= await invoke(f, personas.B, target, 'B'))
        const getControl = async () => (control ??= await invoke(f, personas.A, own, 'A'))

        for (const p of [personas.A, personas.anon]) {
          if (!(p.key === 'A' ? f.auth_exec : f.anon_exec)) { cov.results[p.key] = 'no EXECUTE privilege'; continue }
          const t = await invoke(f, p, target, 'B')
          if (!t.res.ok) {
            cov.results[p.key] = t.res.code === '42501' ? 'denied' : `refused (${t.res.code ?? 'error'}: ${t.res.message.slice(0, 70)})`
            continue
          }
          const out = t.res.value.out
          const leaked = [...tokensB].filter((tok) => !passed.has(tok) && out.includes(tok))
          const changed = t.res.value.changed
          // Numbers, enums and booleans carry no recognisable marker. So also compare results: if this
          // caller gets exactly what user B gets for B's values, and something else for A's own values,
          // the caller is being served user B's data.
          let sameAsOwner = false
          if (!leaked.length && target.length && !trivial(out) && f.auth_exec) {
            const ref = await getReference(), c = await getControl()
            sameAsOwner = ref.res.ok && ref.res.value.out === out && !(c.res.ok && c.res.value.out === out)
          }
          if (leaked.length) {
            col.hit('rpc-cross-user-read', p,
              { values_of_user_b_returned: leaked.length, sample: leaked.slice(0, 3).map((s) => (s.length > 28 ? s.slice(0, 28) + '…' : s)), arguments: cov.args },
              repro(p, t.text, "returns user B's data"))
          } else if (sameAsOwner) {
            col.hit('rpc-cross-user-read', p,
              { same_result_as_user_b_gets: true, differs_from_callers_own_result: true, result_bytes: out.length, arguments: cov.args },
              repro(p, t.text, 'returns exactly what user B gets'))
          }
          if (changed.length) {
            col.hit('rpc-cross-user-write', p, { changed, arguments: cov.args },
              repro(p, t.text, "changes user B's rows; DESTRUCTIVE if committed: keep it inside this transaction"))
          }
          const read = leaked.length > 0 || sameAsOwner
          if (read || changed.length) { cov.results[p.key] = [read && 'LEAK', changed.length && 'WRITE'].filter(Boolean).join(' + '); continue }
          if (p.key !== 'A' || target.length === 0) { cov.results[p.key] = 'no data of user B returned'; continue }
          // Control: when A passes A's own values, does the function do its job? If yes it is live and
          // the probe above means something. If not, the probe proved nothing and the report says so.
          const c = await getControl()
          const live = c.res.ok && (c.res.value.changed.length > 0 || !trivial(c.res.value.out) ||
            [...tokensAPrivate].some((tok) => !ownArgs.has(tok) && c.res.value.out.includes(tok)))
          cov.results[p.key] = !live ? 'no signal' : c.res.value.out === out && !c.res.value.changed.length ? 'same result for every caller' : 'scoped to caller'
          cov.gap = !live
        }
        col.emit({
          'rpc-cross-user-read': {
            severity: readSeverity, title: (who) => `${who} can read user B's data by calling ${f.signature}`,
            fix: `Inside ${f.signature}, take the identity from auth.uid() instead of an argument, or raise when they differ.`,
          },
          'rpc-cross-user-write': {
            severity: () => 'critical', title: (who) => `${who} can change user B's rows by calling ${f.signature}`,
            fix: `Inside ${f.signature}, verify the row belongs to auth.uid() before changing it (add "AND user_id = auth.uid()").`,
          },
        })
      }
    }
  } finally {
    await db.exec('ROLLBACK')
  }
  return { findings, coverage }
}
