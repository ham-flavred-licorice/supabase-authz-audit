// @ts-check
// Renders the audit result for people. The JSON result is the source of truth; this file only formats it.

const LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' }
const yn = (v) => (v === null || v === undefined ? '–' : v ? 'yes' : 'no')
const cell = (v) => String(v ?? '–').replace(/\|/g, '\\|')

function verdictLine(r) {
  const blocking = r.counts.critical + r.counts.high
  if (r.verdict === 'BLOCK') {
    return `**Verdict: BLOCK.** ${blocking} launch-blocking finding${blocking === 1 ? '' : 's'} ` +
      `(${r.counts.critical} critical, ${r.counts.high} high). At least one path lets one user reach another user's data.`
  }
  const tail = r.complete
    ? 'Every table, view and function that could be linked to a user was exercised.'
    : `${r.gaps.length} object${r.gaps.length === 1 ? ' was' : 's were'} not exercised (listed under "Not exercised"), so this result does not cover them.`
  return `**Verdict: PASS.** No cross-user path was found. ${tail}`
}

function findingBlock(f, n) {
  const lines = [
    `### ${n}. ${LABEL[f.severity]} · ${f.title}`,
    '',
    `\`${f.id}\` · ${f.source === 'dynamic' ? 'confirmed by a live test' : 'found in the database configuration'}`,
    '',
  ]
  if (f.accepted_reason) lines.push(`**Accepted by design:** ${f.accepted_reason}`, '')
  if (f.evidence && Object.keys(f.evidence).length) lines.push('Evidence:', '', '```json', JSON.stringify(f.evidence, null, 2), '```', '')
  if (f.reproduce) lines.push('Reproduce (safe: it rolls back):', '', '```sql', f.reproduce, '```', '')
  if (f.fix) lines.push('Fix:', '', '```sql', f.fix.split('\n').map((l) => (/^(ALTER|REVOKE|GRANT|CREATE|--|\s)/.test(l) ? l : `-- ${l}`)).join('\n'), '```', '')
  return lines.join('\n')
}

/** @param {any} r result of runAudit() */
export function toMarkdown(r) {
  const out = []
  out.push('# Authorization audit report', '', verdictLine(r), '')
  out.push(
    '| | |', '|---|---|',
    `| Question tested | Can user A, or a visitor who is not logged in, read or change anything that belongs to user B? |`,
    `| Database | PostgreSQL ${cell(r.target.server_version)}, schemas: ${r.target.schemas.join(', ')} |`,
    `| Test accounts | A = \`${r.users.A}\`, B = \`${r.users.B}\` (synthetic) |`,
    `| Generated | ${r.generated_at} by ${r.tool.name} ${r.tool.version} |`,
    '',
  )
  for (const w of r.warnings) out.push(`> **Warning:** ${w}`, '')

  out.push('## Summary', '', '| Severity | Open findings |', '|---|---|')
  for (const s of Object.keys(LABEL)) out.push(`| ${LABEL[s]} | ${r.counts[s]} |`)
  out.push(`| Accepted by design | ${r.accepted.length} |`, '')

  out.push('## Findings', '')
  if (!r.findings.length) out.push('No open findings.', '')
  r.findings.forEach((f, i) => out.push(findingBlock(f, i + 1)))

  if (r.accepted.length) {
    out.push('## Accepted by design', '', 'These were detected and are excluded from the verdict because the config says they are intended.', '')
    out.push('| Finding | Severity | Reason |', '|---|---|---|')
    for (const f of r.accepted) out.push(`| \`${cell(f.id)}\` | ${LABEL[f.severity]} | ${cell(f.accepted_reason)} |`)
    out.push('')
  }

  out.push('## Coverage', '', '### Tables and views', '')
  out.push('| Relation | Kind | RLS | Policies | Rows of B | A: read | A: update | A: delete | A: insert as B | anon: read | anon: writes |')
  out.push('|---|---|---|---|---|---|---|---|---|---|---|')
  for (const c of r.coverage.relations) {
    if (c.status !== 'exercised') {
      out.push(`| ${cell(c.relation)} | ${c.kind} | ${yn(c.rls)} | ${c.policies} | 0 | ${cell(c.status)} | | | | | |`)
      continue
    }
    const a = c.probes.A ?? {}, n = c.probes.anon ?? {}
    const anonWrites = [n.update, n.delete, n.insert].filter(Boolean)
    const anonW = anonWrites.length ? (anonWrites.some((x) => String(x).startsWith('ALLOWED')) ? 'ALLOWED' : 'blocked') : '–'
    out.push(`| ${cell(c.relation)} | ${c.kind} | ${yn(c.rls)} | ${c.policies} | ${c.b_rows} | ${cell(a.read)} | ${cell(a.update)} | ${cell(a.delete)} | ${cell(a.insert)} | ${cell(n.read)} | ${anonW} |`)
  }
  out.push('', '"A: read 0/2" means user A could see 0 of the 2 rows that belong only to user B.', '')

  if (r.coverage.functions.length) {
    out.push('### Functions callable through the API', '')
    out.push('| Function | SECURITY DEFINER | Fixed search_path | EXECUTE: anon / authenticated / service_role / PUBLIC | As user A | As anon |')
    out.push('|---|---|---|---|---|---|')
    for (const f of r.coverage.functions) {
      const e = f.execute
      out.push(`| ${cell(f.function)} | ${yn(f.security_definer)} | ${f.security_definer ? yn(f.fixed_search_path) : '–'} | ${yn(e.anon)} / ${yn(e.authenticated)} / ${yn(e.service_role)} / ${yn(e.PUBLIC)} | ${cell(f.results.A ?? f.results.note)} | ${cell(f.results.anon ?? '–')} |`)
    }
    out.push('')
  }

  out.push('## Not exercised', '')
  if (!r.gaps.length) out.push('Nothing. Every object that could be linked to a user was tested.', '')
  else { for (const g of r.gaps) out.push(`- \`${g.object}\`: ${g.reason}`); out.push('') }
  if (r.unused_accept_rules.length) out.push(`Accept rules that matched nothing (remove them): ${r.unused_accept_rules.map((m) => `\`${m}\``).join(', ')}`, '')

  out.push(
    '## Method and limits', '',
    '- **Static pass:** reads the system catalogs for RLS state, policies, grants, SECURITY DEFINER functions, search_path and view options.',
    '- **Dynamic pass:** switches to each API role with the same `SET LOCAL ROLE` and `request.jwt.claims` settings PostgREST uses for a request, then tries to read, update, delete and insert against rows that belong only to user B, and calls every exposed function with user B\'s values.',
    '- **Ownership:** a row belongs to a user when a uuid column holds their id, or when a foreign key leads to such a row. Rows linked to both users are treated as shared and never reported.',
    '- **Safety:** the whole dynamic pass runs in one transaction that is rolled back, and each probe runs in its own savepoint. Run it against a test or staging database, because functions with side effects outside the database (HTTP calls, emails) cannot be rolled back.',
    '- **Limits:** this tests authorization between users. It does not test authentication, storage buckets, Edge Functions, realtime channels, rate limits or business-logic flaws. A PASS means no cross-user path was found in what was exercised; the "Not exercised" section says what was left out.',
    '',
  )
  return out.join('\n')
}

/** Short console summary. @param {any} r */
export function toConsole(r) {
  const lines = [
    `${r.verdict}  critical=${r.counts.critical} high=${r.counts.high} medium=${r.counts.medium} low=${r.counts.low} info=${r.counts.info}` +
      `  accepted=${r.accepted.length}  not-exercised=${r.gaps.length}`,
  ]
  for (const f of r.findings) lines.push(`  [${LABEL[f.severity].padEnd(8)}] ${f.title}`)
  for (const w of r.warnings) lines.push(`  warning: ${w}`)
  return lines.join('\n')
}
