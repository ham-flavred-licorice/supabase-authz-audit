import { test } from 'node:test'
import assert from 'node:assert/strict'
import { runAudit, connectPglite, toMarkdown } from '../src/index.mjs'
import { example, fingerprint, edgeSql, edgeConfig, checkEdge } from './helpers.mjs'

test('edge-case schema: audit completes, finds exactly the planted problems, changes nothing', async () => {
  const db = await connectPglite()
  await db.exec(example('supabase-shim.sql'))
  await db.exec(edgeSql())
  const before = await fingerprint(db)
  const r = await runAudit(db, edgeConfig())
  checkEdge(r)
  assert.equal(await fingerprint(db), before)
  assert.ok(toMarkdown(r).length > 2000)
  await db.close()
})

test('a text owner column is invisible without an ownership entry, and that is reported as untested', async () => {
  const db = await connectPglite()
  await db.exec(example('supabase-shim.sql'))
  await db.exec(edgeSql())
  const r = await runAudit(db, { ...edgeConfig(), ownership: {} })
  const cov = r.coverage.relations.find((c) => c.relation === 'public.legacy_orders')
  assert.equal(cov.status, 'not exercised: no ownership link found')
  await db.close()
})
