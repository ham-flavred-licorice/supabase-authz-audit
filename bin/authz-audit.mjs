#!/usr/bin/env node
// @ts-check
import { parseArgs } from 'node:util'
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runAudit, connectPg, connectPglite, toMarkdown, toConsole } from '../src/index.mjs'

const HELP = `supabase-authz-audit: can user A reach user B's data?

Usage
  authz-audit --database-url <url> --user-a <id> --user-b <id> [options]
  authz-audit demo [--out <dir>]

Options
  --database-url <url>   Postgres connection string of a TEST or STAGING database (env DATABASE_URL).
                         Connect as a role that can SET ROLE to the API roles and can see all rows
                         (on Supabase: the "postgres" user).
  --user-a <id>          auth.users id of synthetic test account A (env AUTHZ_AUDIT_USER_A)
  --user-b <id>          auth.users id of synthetic test account B (env AUTHZ_AUDIT_USER_B)
  --schemas <list>       Comma-separated exposed schemas (default: public)
  --config <file>        JSON config: accept rules, ownership overrides, rpc args (see README)
  --out <dir>            Write report.md and report.json here (default: ./authz-audit-report)
  --fail-on <level>      Exit 1 when an open finding is at or above: critical | high | medium | low | none (default: high)
  --no-rpc               Do not call functions
  --no-writes            Read probes only (no UPDATE/DELETE/INSERT attempts, even though they are rolled back)
  --json                 Print the JSON result to stdout instead of the summary
  -h, --help

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = could not run.`

const here = dirname(fileURLToPath(import.meta.url))
const examples = join(here, '..', 'examples')

function write(outDir, name, result) {
  mkdirSync(outDir, { recursive: true })
  writeFileSync(join(outDir, `${name}.json`), JSON.stringify(result, null, 2) + '\n')
  writeFileSync(join(outDir, `${name}.md`), toMarkdown(result))
}

async function demo(outDir) {
  const config = JSON.parse(readFileSync(join(examples, 'demo.config.json'), 'utf8'))
  const expected = { vulnerable: 'BLOCK', patched: 'PASS' }
  let ok = true
  for (const name of /** @type {const} */ (['vulnerable', 'patched'])) {
    const db = await connectPglite()
    try {
      for (const file of ['supabase-shim.sql', `${name}.sql`, 'seed.sql']) await db.exec(readFileSync(join(examples, file), 'utf8'))
      const result = await runAudit(db, config)
      write(outDir, name, result)
      console.log(`\n=== ${name}.sql ===\n${toConsole(result)}`)
      if (result.verdict !== expected[name]) { ok = false; console.error(`unexpected verdict for ${name}: ${result.verdict}`) }
    } finally {
      await db.close()
    }
  }
  console.log(`\nReports written to ${resolve(outDir)}`)
  return ok ? 0 : 2
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      'database-url': { type: 'string' }, 'user-a': { type: 'string' }, 'user-b': { type: 'string' },
      schemas: { type: 'string' }, config: { type: 'string' }, out: { type: 'string' }, 'fail-on': { type: 'string' },
      'anon-role': { type: 'string' }, 'authenticated-role': { type: 'string' }, 'service-role': { type: 'string' },
      'no-rpc': { type: 'boolean' }, 'no-writes': { type: 'boolean' }, json: { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
    },
  })
  if (values.help) { console.log(HELP); return 0 }
  if (positionals[0] === 'demo') return demo(values.out ?? join(examples, 'reports'))

  const url = values['database-url'] ?? process.env.DATABASE_URL
  if (!url) { console.error(HELP); return 2 }
  const file = values.config ? JSON.parse(readFileSync(values.config, 'utf8')) : {}
  const config = {
    ...file,
    ids: { A: values['user-a'] ?? process.env.AUTHZ_AUDIT_USER_A ?? file.ids?.A, B: values['user-b'] ?? process.env.AUTHZ_AUDIT_USER_B ?? file.ids?.B },
    ...(values.schemas ? { schemas: values.schemas.split(',').map((s) => s.trim()).filter(Boolean) } : {}),
    ...(values['fail-on'] ? { failOn: values['fail-on'] } : {}),
    ...(values['no-writes'] ? { writes: false } : {}),
    roles: {
      ...(file.roles ?? {}),
      ...(values['anon-role'] ? { anon: values['anon-role'] } : {}),
      ...(values['authenticated-role'] ? { authenticated: values['authenticated-role'] } : {}),
      ...(values['service-role'] ? { service: values['service-role'] } : {}),
    },
    rpc: { ...(file.rpc ?? {}), ...(values['no-rpc'] ? { enabled: false } : {}) },
  }
  const db = await connectPg(url)
  try {
    const result = await runAudit(db, config)
    const outDir = values.out ?? 'authz-audit-report'
    write(outDir, 'report', result)
    console.log(values.json ? JSON.stringify(result, null, 2) : `${toConsole(result)}\n\nReport: ${resolve(outDir, 'report.md')}`)
    return result.exit_code
  } finally {
    await db.close()
  }
}

main().then(
  (code) => { process.exitCode = code },
  (err) => { console.error(`authz-audit: ${err?.message ?? err}`); process.exitCode = 2 },
)
