// @ts-check
import { readFileSync } from 'node:fs'
import { loadCatalog, staticFindings } from './catalog.mjs'
import { runDynamic } from './dynamic.mjs'

export { connectPg, connectPglite } from './db.mjs'
export { toMarkdown, toConsole } from './report.mjs'

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const rank = (s) => SEVERITIES.indexOf(s)
const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version

export const DEFAULTS = {
  schemas: ['public'],
  roles: { anon: 'anon', authenticated: 'authenticated', service: 'service_role' },
  /** owner columns per relation when they are not uuid columns: { "public.orders": ["customer_ref"] } */
  ownership: {},
  /** findings accepted by design: [{ match: "cross-user-read:public.profiles", reason: "..." }] ('*' wildcards allowed) */
  accept: [],
  /** what a user could write into their own user_metadata */
  forgedUserMetadata: { role: 'admin', is_admin: true, admin: true },
  rpc: { enabled: true, skip: [], args: {} },
  writes: true,
  maxRows: 200,
  maxKeys: 5000,
  statementTimeoutMs: 20000,
  failOn: 'high',
}

/** @param {any} input */
export function resolveConfig(input) {
  const cfg = {
    ...DEFAULTS, ...input,
    roles: { ...DEFAULTS.roles, ...(input.roles ?? {}) },
    rpc: { ...DEFAULTS.rpc, ...(input.rpc ?? {}) },
  }
  const { A, B } = cfg.ids ?? {}
  if (!A || !B) throw new Error('Two test users are required: ids.A and ids.B (--user-a, --user-b).')
  if (A === B) throw new Error('User A and user B must be different accounts.')
  if (!SEVERITIES.includes(cfg.failOn) && cfg.failOn !== 'none') throw new Error(`failOn must be one of ${SEVERITIES.join(', ')}, none`)
  for (const a of cfg.accept) if (!a.match || !a.reason) throw new Error('Every accept entry needs "match" and "reason".')
  return cfg
}

const globToRegex = (glob) => new RegExp('^' + glob.split('*').map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$')

/**
 * Run the full audit. The database is not modified: the dynamic pass runs in a
 * transaction that is always rolled back.
 * @param {import('./db.mjs').Db} db
 * @param {any} input  see DEFAULTS; ids: { A, B } is required
 */
export async function runAudit(db, input) {
  const cfg = resolveConfig(input)
  const cat = await loadCatalog(db, cfg)
  const dynamic = await runDynamic(db, cat, cfg)
  const all = [...dynamic.findings, ...staticFindings(cat, cfg)].sort(
    (a, b) => rank(a.severity) - rank(b.severity) || a.source.localeCompare(b.source) || a.id.localeCompare(b.id),
  )

  const accepts = cfg.accept.map((a) => ({ ...a, re: globToRegex(a.match), used: false }))
  const findings = [], accepted = []
  for (const f of all) {
    const hit = accepts.find((a) => a.re.test(f.id))
    if (hit) { hit.used = true; accepted.push({ ...f, accepted_reason: hit.reason }) } else findings.push(f)
  }

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]))
  const gaps = [
    ...dynamic.coverage.relations
      .filter((r) => r.status.startsWith('not exercised: no rows'))
      .map((r) => ({ object: r.relation, reason: 'No rows belong only to user B. Seed data for user B in this table to test it.' })),
    ...dynamic.coverage.functions
      .filter((f) => f.gap)
      .map((f) => ({ object: f.function, reason: f.results.note ?? 'The call returned neither user\'s data, so it proved nothing. Supply arguments under rpc.args in the config.' })),
  ]
  const blocking = counts.critical + counts.high
  const failing = cfg.failOn === 'none' ? 0 : findings.filter((f) => rank(f.severity) <= rank(cfg.failOn)).length

  return {
    tool: { name: 'supabase-authz-audit', version: VERSION },
    generated_at: new Date().toISOString(),
    target: {
      server_version: cat.server.version, connected_as: cat.server.name, connection_sees_all_rows: cat.server.sees_all,
      schemas: cfg.schemas, roles: cfg.roles,
    },
    users: cfg.ids,
    verdict: blocking > 0 ? 'BLOCK' : 'PASS',
    complete: gaps.length === 0,
    exit_code: failing > 0 ? 1 : 0,
    counts,
    findings,
    accepted,
    unused_accept_rules: accepts.filter((a) => !a.used).map((a) => a.match),
    gaps,
    coverage: dynamic.coverage,
    warnings: cat.server.sees_all ? [] : [
      `The connection role "${cat.server.name}" is neither superuser nor BYPASSRLS. It may not see every row, so user B's rows can be undercounted. Connect as a role that bypasses RLS.`,
    ],
  }
}
