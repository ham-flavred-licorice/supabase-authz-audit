import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runAudit, toMarkdown } from '../src/index.mjs'
import { fresh, demoConfig, fingerprint, VULNERABLE_EXPECTED, A, B } from './helpers.mjs'

const ids = (r) => r.findings.map((f) => f.id)

test('vulnerable schema: every planted bug is found, and nothing else', async () => {
  const db = await fresh('vulnerable')
  const r = await runAudit(db, demoConfig())
  await db.close()
  assert.equal(r.verdict, 'BLOCK')
  assert.equal(r.exit_code, 1)
  assert.deepEqual(ids(r).sort(), [...VULNERABLE_EXPECTED].sort())
})

test('vulnerable schema: correctly protected tables are not reported', async () => {
  const db = await fresh('vulnerable')
  const r = await runAudit(db, demoConfig())
  await db.close()
  for (const safe of ['public.notes', 'public.invoices', 'public.messages']) {
    assert.equal(r.findings.filter((f) => f.object === safe).length, 0, `${safe} must have no findings`)
    const cov = r.coverage.relations.find((c) => c.relation === safe)
    assert.equal(cov.status, 'exercised')
    assert.equal(cov.probes.A.read, `0/${cov.b_rows}`)
    assert.equal(cov.owner_can_read, cov.b_rows, 'the owner must still be able to read their own rows')
  }
})

test('rows shared between A and B are never counted as user B\'s private rows', async () => {
  const db = await fresh('vulnerable')
  const r = await runAudit(db, demoConfig())
  await db.close()
  // 5 messages in the seed: 2 between A and B (shared), 1 from A to C, and 2 between B and C.
  assert.equal(r.coverage.relations.find((c) => c.relation === 'public.messages').b_rows, 2)
})

test('child rows inherit their owner through foreign keys', async () => {
  const db = await fresh('vulnerable')
  const r = await runAudit(db, demoConfig())
  await db.close()
  // note_attachments has no user column at all; ownership comes from notes.user_id.
  assert.equal(r.coverage.relations.find((c) => c.relation === 'public.note_attachments').b_rows, 2)
})

test('patched schema: no open findings and nothing left unexercised', async () => {
  const db = await fresh('patched')
  const r = await runAudit(db, demoConfig())
  await db.close()
  assert.deepEqual(ids(r), [])
  assert.equal(r.verdict, 'PASS')
  assert.equal(r.complete, true)
  assert.equal(r.exit_code, 0)
  assert.equal(r.accepted.length, 3)
  assert.deepEqual(r.unused_accept_rules, [])
  const fn = Object.fromEntries(r.coverage.functions.map((f) => [f.function, f.results]))
  assert.equal(fn['public.get_notes_for(p_user_id uuid)'].A, 'scoped to caller')
  assert.equal(fn['public.delete_note(p_note_id uuid)'].A, 'scoped to caller')
  assert.equal(fn['public.get_notes_for(p_user_id uuid)'].anon, 'no EXECUTE privilege')
})

for (const name of ['vulnerable', 'patched']) {
  test(`${name} schema: the audit leaves the database exactly as it found it`, async () => {
    const db = await fresh(name)
    const before = await fingerprint(db)
    await runAudit(db, demoConfig())
    await runAudit(db, demoConfig()) // twice: results must not depend on leftovers
    assert.equal(await fingerprint(db), before)
    await db.close()
  })
}

test('results are deterministic', async () => {
  const strip = (r) => JSON.stringify({ ...r, generated_at: null })
  const db1 = await fresh('vulnerable'), db2 = await fresh('vulnerable')
  const [a, b] = [await runAudit(db1, demoConfig()), await runAudit(db2, demoConfig())]
  await db1.close(); await db2.close()
  assert.equal(strip(a), strip(b))
})

test('accept rules: without them the public profile read is reported; unused rules are listed', async () => {
  const db = await fresh('patched')
  const open = await runAudit(db, { ids: { A, B } })
  assert.ok(ids(open).includes('cross-user-read:public.profiles'))
  assert.equal(open.verdict, 'BLOCK')
  const stale = await runAudit(db, { ...demoConfig(), accept: [...demoConfig().accept, { match: 'cross-user-read:public.gone', reason: 'old' }] })
  assert.deepEqual(stale.unused_accept_rules, ['cross-user-read:public.gone'])
  await db.close()
})

test('--no-writes equivalent: only read probes run', async () => {
  const db = await fresh('vulnerable')
  const r = await runAudit(db, { ...demoConfig(), writes: false })
  await db.close()
  assert.ok(!ids(r).some((id) => /cross-user-(update|delete|insert)/.test(id)))
  assert.ok(ids(r).includes('cross-user-read:public.note_attachments'))
  assert.equal(r.coverage.relations.find((c) => c.relation === 'public.notes').probes.A.update, undefined)
})

test('rpc can be disabled, and single functions can be skipped', async () => {
  const db = await fresh('vulnerable')
  const off = await runAudit(db, { ...demoConfig(), rpc: { enabled: false } })
  assert.ok(!ids(off).some((id) => id.startsWith('rpc-')))
  const skip = await runAudit(db, { ...demoConfig(), rpc: { skip: ['public.delete_note(p_note_id uuid)'] } })
  assert.ok(!ids(skip).includes('rpc-cross-user-write:public.delete_note(p_note_id uuid)'))
  assert.ok(ids(skip).includes('rpc-cross-user-read:public.get_notes_for(p_user_id uuid)'))
  await db.close()
})

test('a table with no rows for user B is reported as a gap, not as a pass', async () => {
  const db = await fresh('patched')
  await db.exec(`delete from public.drafts where user_id = '${B}'`)
  const r = await runAudit(db, demoConfig())
  await db.close()
  assert.equal(r.verdict, 'PASS')
  assert.equal(r.complete, false)
  assert.deepEqual(r.gaps.map((g) => g.object), ['public.drafts'])
})

test('config errors are rejected up front', async () => {
  const db = await fresh('patched')
  await assert.rejects(runAudit(db, { ids: { A, B: A } }), /different accounts/)
  await assert.rejects(runAudit(db, { ids: { A } }), /Two test users/)
  await assert.rejects(runAudit(db, { ids: { A, B }, accept: [{ match: 'x' }] }), /reason/)
  await assert.rejects(runAudit(db, { ids: { A, B }, roles: { anon: 'nope' } }), /does not exist/)
  await db.close()
})

test('markdown report contains verdict, reproduction steps and coverage', async () => {
  const db = await fresh('vulnerable')
  const md = toMarkdown(await runAudit(db, demoConfig()))
  await db.close()
  assert.match(md, /\*\*Verdict: BLOCK\.\*\*/)
  assert.match(md, /set local role "anon";/)
  assert.match(md, /SELECT \* FROM public\.get_notes_for\('bbbbbbbb-0000-4000-8000-000000000002'::uuid\)/)
  assert.match(md, /## Coverage/)
  assert.match(md, /## Accepted by design/)
})

test('CLI demo: exit 0, writes both reports', () => {
  const out = mkdtempSync(join(tmpdir(), 'authz-audit-'))
  const bin = fileURLToPath(new URL('../bin/authz-audit.mjs', import.meta.url))
  const run = spawnSync(process.execPath, [bin, 'demo', '--out', out], { encoding: 'utf8' })
  assert.equal(run.status, 0, run.stderr)
  for (const f of ['vulnerable.md', 'vulnerable.json', 'patched.md', 'patched.json']) assert.ok(existsSync(join(out, f)), f)
  assert.equal(JSON.parse(readFileSync(join(out, 'patched.json'), 'utf8')).verdict, 'PASS')
})

test('CLI: missing connection string exits 2', () => {
  const bin = fileURLToPath(new URL('../bin/authz-audit.mjs', import.meta.url))
  const run = spawnSync(process.execPath, [bin], { encoding: 'utf8', env: { ...process.env, DATABASE_URL: '' } })
  assert.equal(run.status, 2)
})
