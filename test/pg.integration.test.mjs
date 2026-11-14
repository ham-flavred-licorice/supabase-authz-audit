// Runs the same expectations against a real PostgreSQL server through the "pg" adapter.
// Needs DATABASE_URL pointing at a server where the user may create databases (it creates
// and drops a scratch database per case). Skipped when DATABASE_URL is not set.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runAudit, connectPg } from '../src/index.mjs'
import { load, example, demoConfig, fingerprint, edgeSql, edgeConfig, checkEdge, VULNERABLE_EXPECTED, A, B } from './helpers.mjs'

const admin = process.env.DATABASE_URL
const skip = admin ? false : 'DATABASE_URL not set'
const urlFor = (name) => { const u = new URL(admin); u.pathname = `/${name}`; return u.toString() }

async function scratch(name, fn, { owner, setup } = {}) {
  const dbName = `authz_audit_${name}_${process.pid}_${Date.now()}`
  const root = await connectPg(admin)
  await root.exec(`CREATE DATABASE ${dbName}${owner ? ` OWNER ${owner.name}` : ''}`)
  try {
    const url = new URL(urlFor(dbName))
    if (owner) { url.username = owner.name; url.password = owner.password }
    const db = await connectPg(url.toString())
    try { await (setup ?? ((d) => load(d, name)))(db); return await fn(db, url.toString()) } finally { await db.close() }
  } finally {
    await root.exec(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`)
    await root.close()
  }
}

test('real Postgres, vulnerable schema: same findings as the in-process engine', { skip }, async () => {
  await scratch('vulnerable', async (db) => {
    const before = await fingerprint(db)
    const r = await runAudit(db, demoConfig())
    assert.equal(r.verdict, 'BLOCK')
    assert.deepEqual(r.findings.map((f) => f.id).sort(), [...VULNERABLE_EXPECTED].sort())
    assert.equal(await fingerprint(db), before, 'database must be unchanged')
  })
})

test('real Postgres, patched schema: clean pass, database unchanged', { skip }, async () => {
  await scratch('patched', async (db) => {
    const before = await fingerprint(db)
    const r = await runAudit(db, demoConfig())
    assert.deepEqual(r.findings.map((f) => f.id), [])
    assert.equal(r.verdict, 'PASS')
    assert.equal(r.complete, true)
    assert.equal(await fingerprint(db), before, 'database must be unchanged')
  })
})

test('real Postgres, CLI: exit 1 on the vulnerable schema, 0 on the patched one', { skip }, async () => {
  const bin = fileURLToPath(new URL('../bin/authz-audit.mjs', import.meta.url))
  const cfg = fileURLToPath(new URL('../examples/demo.config.json', import.meta.url))
  for (const [name, code] of [['vulnerable', 1], ['patched', 0]]) {
    await scratch(name, async (_db, url) => {
      const out = mkdtempSync(join(tmpdir(), 'authz-audit-pg-'))
      const run = spawnSync(process.execPath, [bin, '--database-url', url, '--config', cfg, '--user-a', A, '--user-b', B, '--out', out], { encoding: 'utf8' })
      assert.equal(run.status, code, run.stdout + run.stderr)
    })
  }
})

test('real Postgres, edge-case schema: same result as the in-process engine', { skip }, async () => {
  await scratch('edge', async (db) => {
    const before = await fingerprint(db)
    checkEdge(await runAudit(db, edgeConfig()))
    assert.equal(await fingerprint(db), before, 'database must be unchanged')
  }, { setup: async (db) => { await db.exec(example('supabase-shim.sql')); await db.exec(edgeSql()) } })
})

test('real Postgres, connected as a non-superuser with BYPASSRLS (the shape of Supabase\'s postgres role)', { skip }, async () => {
  const owner = { name: 'authz_audit_admin', password: 'authz_audit_pw' }
  const root = await connectPg(admin)
  await root.exec(`
    do $$ begin
      if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
      if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
      if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
      if not exists (select 1 from pg_roles where rolname = '${owner.name}') then
        create role ${owner.name} login bypassrls password '${owner.password}';
      end if;
    end $$;
    grant anon, authenticated, service_role to ${owner.name};`)
  await root.close()
  for (const [name, verdict] of [['vulnerable', 'BLOCK'], ['patched', 'PASS']]) {
    await scratch(name, async (db) => {
      const before = await fingerprint(db)
      const r = await runAudit(db, demoConfig())
      assert.equal(r.target.connected_as, owner.name)
      assert.deepEqual(r.warnings, [])
      assert.equal(r.verdict, verdict)
      if (name === 'vulnerable') assert.deepEqual(r.findings.map((f) => f.id).sort(), [...VULNERABLE_EXPECTED].sort())
      else assert.deepEqual(r.findings, [])
      assert.equal(await fingerprint(db), before, 'database must be unchanged')
    }, { owner })
  }
})
