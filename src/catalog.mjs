// @ts-check
// Static pass: read the system catalogs and flag configurations that commonly lead to
// cross-user access. Nothing here executes application code or touches application rows.

const IDENTITY_PARAM = /(user|owner|uid|profile|account|member|author|customer|creator)/i
const CALLER_CHECK = /auth\s*\.\s*(uid|jwt|role|email)\s*\(|request\.jwt|current_setting\s*\(\s*'request\./i
const USER_METADATA = /user_metadata|raw_user_meta_data/i
const POLICY_CMD = { r: 'SELECT', a: 'INSERT', w: 'UPDATE', d: 'DELETE', '*': 'ALL' }

/**
 * @param {import('./db.mjs').Db} db
 * @param {{ schemas: string[], roles: { anon: string, authenticated: string, service: string } }} cfg
 */
export async function loadCatalog(db, cfg) {
  const { schemas, roles } = cfg

  const found = (await db.query(`SELECT rolname FROM pg_roles WHERE rolname = ANY($1::text[])`, [
    [roles.anon, roles.authenticated, roles.service],
  ])).rows.map((r) => r.rolname)
  for (const needed of [roles.anon, roles.authenticated]) {
    if (!found.includes(needed)) {
      throw new Error(
        `Role "${needed}" does not exist in this database. This tool expects the Supabase/PostgREST API roles ` +
          `(override with --anon-role / --authenticated-role).`,
      )
    }
  }
  const serviceRole = found.includes(roles.service) ? roles.service : null

  const me = (await db.query(
    `SELECT current_user AS name, current_setting('server_version') AS version,
            coalesce((SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user), false) AS sees_all`,
  )).rows[0]

  const relations = (await db.query(
    `SELECT c.oid::int AS oid, format('%I.%I', n.nspname, c.relname) AS ident, n.nspname AS schema, c.relname AS name,
            c.relkind::text AS kind, c.relrowsecurity AS rls, c.relforcerowsecurity AS force_rls,
            (SELECT count(*)::int FROM pg_policy p WHERE p.polrelid = c.oid) AS policy_count,
            coalesce((SELECT o.option_value FROM pg_options_to_table(c.reloptions) o
                      WHERE o.option_name = 'security_invoker'), 'false') IN ('true', 'on', '1') AS security_invoker,
            pg_get_userbyid(c.relowner) AS owner,
            ARRAY(SELECT p FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) p
                  WHERE has_table_privilege($2::name, c.oid, p))::text[] AS anon_privs,
            ARRAY(SELECT p FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) p
                  WHERE has_table_privilege($3::name, c.oid, p))::text[] AS auth_privs
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = ANY($1::text[]) AND c.relkind IN ('r', 'p', 'v', 'm')
        AND NOT EXISTS (SELECT 1 FROM pg_depend d
                         WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
      ORDER BY 2`,
    [schemas, roles.anon, roles.authenticated],
  )).rows

  const columns = (await db.query(
    `SELECT a.attrelid::int AS rel, quote_ident(a.attname) AS ident, a.attname AS name,
            format_type(a.atttypid, a.atttypmod) AS type, a.attgenerated::text AS generated,
            a.attidentity::text AS identity
       FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = ANY($1::text[]) AND c.relkind IN ('r', 'p', 'v', 'm') AND a.attnum > 0 AND NOT a.attisdropped
      ORDER BY a.attrelid, a.attnum`,
    [schemas],
  )).rows

  const constraints = (await db.query(
    `SELECT con.contype::text AS type, con.conrelid::int AS rel, con.confrelid::int AS frel,
            (SELECT quote_ident(attname) FROM pg_attribute WHERE attrelid = con.conrelid AND attnum = con.conkey[1]) AS col,
            (SELECT quote_ident(attname) FROM pg_attribute WHERE attrelid = con.confrelid AND attnum = con.confkey[1]) AS fcol
       FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = ANY($1::text[]) AND con.contype IN ('f', 'p') AND array_length(con.conkey, 1) = 1`,
    [schemas],
  )).rows

  const policies = (await db.query(
    `SELECT format('%I.%I', n.nspname, c.relname) AS rel, p.polname AS name, p.polcmd::text AS cmd,
            p.polpermissive AS permissive,
            CASE WHEN p.polroles = '{0}'::oid[] THEN ARRAY['PUBLIC']
                 ELSE ARRAY(SELECT rolname::text FROM pg_roles WHERE oid = ANY(p.polroles)) END AS roles,
            pg_get_expr(p.polqual, p.polrelid) AS using_expr,
            pg_get_expr(p.polwithcheck, p.polrelid) AS check_expr
       FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = ANY($1::text[])
      ORDER BY 1, 2`,
    [schemas],
  )).rows

  const functions = (await db.query(
    `SELECT p.oid::int AS oid, format('%I.%I', n.nspname, p.proname) AS ident, n.nspname AS schema, p.proname AS name,
            pg_get_function_identity_arguments(p.oid) AS identity_args,
            p.prosecdef AS secdef, p.proargnames::text[] AS argnames, p.proargmodes::text[] AS argmodes,
            ARRAY(SELECT format_type(t.oid, NULL) FROM unnest(p.proargtypes::oid[]) WITH ORDINALITY AS t(oid, ord)
                  ORDER BY t.ord)::text[] AS argtypes,
            p.pronargdefaults::int AS ndefaults, p.provariadic <> 0 AS variadic,
            format_type(p.prorettype, NULL) AS rettype, p.proconfig::text[] AS config, l.lanname::text AS lang,
            CASE WHEN l.lanname IN ('sql', 'plpgsql') THEN p.prosrc END AS src,
            has_function_privilege($2::name, p.oid, 'EXECUTE') AS anon_exec,
            has_function_privilege($3::name, p.oid, 'EXECUTE') AS auth_exec,
            CASE WHEN $4::name IS NULL THEN NULL ELSE has_function_privilege($4::name, p.oid, 'EXECUTE') END AS service_exec,
            EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                     WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_exec
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
      WHERE n.nspname = ANY($1::text[]) AND p.prokind = 'f' AND p.prorettype <> 'trigger'::regtype
        AND NOT EXISTS (SELECT 1 FROM pg_depend d
                         WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
      ORDER BY 2, 5`,
    [schemas, roles.anon, roles.authenticated, serviceRole],
  )).rows

  // Which RLS-protected tables does each view read from?
  const viewDeps = (await db.query(
    `SELECT DISTINCT r.ev_class::int AS view_oid, d.refobjid::int AS table_oid
       FROM pg_rewrite r
       JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid
                       AND d.refclassid = 'pg_class'::regclass AND d.refobjid <> r.ev_class`,
  )).rows

  const byOid = new Map(relations.map((r) => [r.oid, r]))
  for (const r of relations) {
    r.columns = columns.filter((c) => c.rel === r.oid)
    r.pk = constraints.find((c) => c.type === 'p' && c.rel === r.oid)?.col ?? null
    r.fks = constraints
      .filter((c) => c.type === 'f' && c.rel === r.oid && byOid.has(c.frel))
      .map((c) => ({ col: c.col, parentOid: c.frel, fcol: c.fcol }))
    r.reads_rls_tables = viewDeps
      .filter((d) => d.view_oid === r.oid && byOid.get(d.table_oid)?.rls)
      .map((d) => byOid.get(d.table_oid).ident)
  }
  for (const f of functions) {
    const modes = f.argmodes
    const names = f.argnames ?? []
    // IN / INOUT / VARIADIC arguments, in call order.
    f.in_args = (f.argtypes ?? []).map((type, i) => {
      let name = null
      if (modes) {
        let seen = -1
        for (let j = 0; j < modes.length; j++) {
          if (['i', 'b', 'v'].includes(modes[j])) seen++
          if (seen === i) { name = names[j] || null; break }
        }
      } else {
        name = names[i] || null
      }
      return { name, type }
    })
    f.signature = `${f.ident}(${f.identity_args})`
    f.has_search_path = (f.config ?? []).some((c) => c.toLowerCase().startsWith('search_path='))
  }

  return { server: me, serviceRole, relations, policies, functions }
}

/**
 * @param {Awaited<ReturnType<typeof loadCatalog>>} cat
 * @param {{ roles: { anon: string, authenticated: string, service: string } }} cfg
 */
export function staticFindings(cat, cfg) {
  /** @type {any[]} */
  const out = []
  const apiRoles = new Set([cfg.roles.anon, cfg.roles.authenticated, 'PUBLIC'])

  for (const r of cat.relations) {
    const granted = [...new Set([...r.anon_privs, ...r.auth_privs])]
    if (['r', 'p'].includes(r.kind)) {
      if (!r.rls && granted.length) {
        out.push({
          id: `rls-disabled:${r.ident}`, rule: 'rls-disabled', severity: 'high', source: 'static', object: r.ident,
          title: `Row Level Security is off on ${r.ident} and the API roles can reach it`,
          evidence: { anon: r.anon_privs, authenticated: r.auth_privs },
          fix: `ALTER TABLE ${r.ident} ENABLE ROW LEVEL SECURITY;\n-- then add policies that scope rows to the caller, e.g.\n-- CREATE POLICY own_rows ON ${r.ident} FOR ALL TO authenticated\n--   USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());`,
        })
      } else if (r.rls && r.policy_count === 0) {
        out.push({
          id: `rls-no-policy:${r.ident}`, rule: 'rls-no-policy', severity: 'info', source: 'static', object: r.ident,
          title: `${r.ident} has RLS enabled and no policies (API roles are denied everything)`,
          evidence: {}, fix: `Intended for server-only tables. Otherwise add policies.`,
        })
      }
    } else if (r.anon_privs.includes('SELECT') || r.auth_privs.includes('SELECT')) {
      const who = { anon: r.anon_privs.includes('SELECT'), authenticated: r.auth_privs.includes('SELECT') }
      if (r.kind === 'm') {
        out.push({
          id: `matview-exposed:${r.ident}`, rule: 'matview-exposed', severity: r.reads_rls_tables.length ? 'high' : 'low',
          source: 'static', object: r.ident,
          title: `Materialized view ${r.ident} is readable by API roles; materialized views cannot enforce RLS`,
          evidence: { select: who, reads_rls_tables: r.reads_rls_tables },
          fix: `REVOKE SELECT ON ${r.ident} FROM ${cfg.roles.anon}, ${cfg.roles.authenticated};\n-- expose it through a SECURITY INVOKER function or a filtered view instead.`,
        })
      } else if (!r.security_invoker) {
        out.push({
          id: `view-definer-rights:${r.ident}`, rule: 'view-definer-rights',
          severity: r.reads_rls_tables.length ? 'high' : 'low', source: 'static', object: r.ident,
          title: `View ${r.ident} runs with its owner's rights, so RLS on the tables underneath is skipped`,
          evidence: { select: who, owner: r.owner, reads_rls_tables: r.reads_rls_tables },
          fix: `ALTER VIEW ${r.ident} SET (security_invoker = true);`,
        })
      }
    }
  }

  for (const p of cat.policies) {
    const exposed = p.roles.some((role) => apiRoles.has(role))
    if (!exposed) continue
    const cmd = POLICY_CMD[p.cmd] ?? p.cmd
    const exprs = [p.using_expr, p.check_expr].filter(Boolean)
    if (exprs.some((e) => e.trim() === 'true')) {
      const readOnly = cmd === 'SELECT'
      out.push({
        id: `policy-always-true:${p.rel}:${p.name}`, rule: 'policy-always-true', severity: readOnly ? 'medium' : 'high',
        source: 'static', object: p.rel,
        title: readOnly
          ? `Policy "${p.name}" on ${p.rel} lets every ${p.roles.join('/')} caller read every row`
          : `Policy "${p.name}" on ${p.rel} allows ${cmd} on every row for ${p.roles.join('/')}`,
        evidence: { command: cmd, roles: p.roles, using: p.using_expr, with_check: p.check_expr },
        fix: readOnly
          ? `If the table is public by design, accept this finding with a reason. Otherwise scope it:\n-- ALTER POLICY ${JSON.stringify(p.name)} ON ${p.rel} USING (user_id = auth.uid());`
          : `ALTER POLICY ${JSON.stringify(p.name)} ON ${p.rel}\n  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());  -- use the table's real owner column`,
      })
    }
    if (exprs.some((e) => USER_METADATA.test(e))) {
      out.push({
        id: `policy-user-metadata:${p.rel}:${p.name}`, rule: 'policy-user-metadata', severity: 'high', source: 'static',
        object: p.rel,
        title: `Policy "${p.name}" on ${p.rel} trusts user_metadata, which every user can edit for themselves`,
        evidence: { command: cmd, using: p.using_expr, with_check: p.check_expr },
        fix: `Read roles from app_metadata (server-controlled) or from a roles table:\n-- (auth.jwt() -> 'app_metadata' ->> 'role') = 'support'`,
      })
    }
  }

  for (const f of cat.functions) {
    if (!f.secdef) continue
    if (!f.has_search_path) {
      out.push({
        id: `definer-search-path:${f.signature}`, rule: 'definer-search-path', severity: 'medium', source: 'static',
        object: f.signature,
        title: `SECURITY DEFINER function ${f.signature} has no fixed search_path`,
        evidence: { config: f.config ?? [] },
        fix: `ALTER FUNCTION ${f.signature} SET search_path = '';\n-- and schema-qualify every object the function touches.`,
      })
    }
    if (f.anon_exec) {
      out.push({
        id: `definer-anon-exec:${f.signature}`, rule: 'definer-anon-exec', severity: 'medium', source: 'static',
        object: f.signature,
        title: `SECURITY DEFINER function ${f.signature} can be called without logging in`,
        evidence: { via_public_grant: f.public_exec, anon: f.anon_exec, authenticated: f.auth_exec, service_role: f.service_exec },
        fix: `REVOKE EXECUTE ON FUNCTION ${f.signature} FROM PUBLIC, ${cfg.roles.anon};\nGRANT EXECUTE ON FUNCTION ${f.signature} TO ${cfg.roles.authenticated};`,
      })
    }
    const idParams = f.in_args.filter((a) => a.name && ['uuid', 'text'].includes(a.type) && IDENTITY_PARAM.test(a.name))
    if (idParams.length && f.src && !CALLER_CHECK.test(f.src) && (f.anon_exec || f.auth_exec)) {
      out.push({
        id: `definer-caller-identity:${f.signature}`, rule: 'definer-caller-identity', severity: 'high', source: 'static',
        object: f.signature,
        title: `SECURITY DEFINER function ${f.signature} takes a user id from the caller and never checks who is calling`,
        evidence: { identity_parameters: idParams.map((a) => a.name), caller_check_found: false },
        fix: `Take the identity from the session, not from an argument:\n--   ... WHERE user_id = auth.uid()\n-- or reject mismatches at the top of the function:\n--   IF ${idParams[0].name} IS DISTINCT FROM auth.uid() THEN RAISE EXCEPTION 'not allowed'; END IF;`,
      })
    }
  }
  return out
}
