import { readFileSync } from 'node:fs'
import assert from 'node:assert/strict'
import { connectPglite } from '../src/index.mjs'

export const example = (file) => readFileSync(new URL(`../examples/${file}`, import.meta.url), 'utf8')
export const demoConfig = () => JSON.parse(example('demo.config.json'))
export const A = 'aaaaaaaa-0000-4000-8000-000000000001'
export const B = 'bbbbbbbb-0000-4000-8000-000000000002'

/** Load shim + schema + seed into any Db. */
export async function load(db, name) {
  for (const file of ['supabase-shim.sql', `${name}.sql`, 'seed.sql']) await db.exec(example(file))
  return db
}
export const fresh = async (name) => load(await connectPglite(), name)

/** One fingerprint of all application data and all security-relevant catalog state. */
export async function fingerprint(db) {
  const tables = (await db.query(
    `select format('%I.%I', schemaname, tablename) as t from pg_tables where schemaname in ('public', 'auth') order by 1`,
  )).rows.map((r) => r.t)
  const parts = []
  for (const t of tables) {
    const r = (await db.query(`select count(*)::int as n, coalesce(md5(string_agg(x::text, ',' order by x::text)), '-') as d from ${t} x`)).rows[0]
    parts.push(`${t}:${r.n}:${r.d}`)
  }
  const cat = (await db.query(
    `select (select count(*) from pg_policy)::int as policies,
            (select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public')::int as functions,
            (select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public')::int as relations,
            current_user::text as who, coalesce(current_setting('request.jwt.claims', true), '') as claims`,
  )).rows[0]
  return JSON.stringify({ parts, cat })
}

export const VULNERABLE_EXPECTED = [
  // BUG 1
  'cross-user-update:public.profiles', 'policy-always-true:public.profiles:profiles_update',
  // BUG 2
  'cross-user-read:public.note_attachments', 'cross-user-update:public.note_attachments',
  'cross-user-delete:public.note_attachments', 'cross-user-insert:public.note_attachments', 'rls-disabled:public.note_attachments',
  // BUG 3
  'metadata-escalation-read:public.support_tickets', 'policy-user-metadata:public.support_tickets:tickets_read',
  // BUG 4
  'cross-user-read:public.invoice_summary', 'view-definer-rights:public.invoice_summary',
  // BUG 5
  'cross-user-delete:public.drafts', 'policy-always-true:public.drafts:drafts_cleanup',
  // BUG 6
  'rpc-cross-user-read:public.get_notes_for(p_user_id uuid)', 'definer-caller-identity:public.get_notes_for(p_user_id uuid)',
  'definer-search-path:public.get_notes_for(p_user_id uuid)', 'definer-anon-exec:public.get_notes_for(p_user_id uuid)',
  // BUG 7
  'rpc-cross-user-write:public.delete_note(p_note_id uuid)', 'definer-search-path:public.delete_note(p_note_id uuid)',
  'definer-anon-exec:public.delete_note(p_note_id uuid)',
]

// ---- edge-case fixture ------------------------------------------------------------
export const edgeSql = () => readFileSync(new URL('./edge.sql', import.meta.url), 'utf8')
export const edgeConfig = () => ({
  ids: { A, B },
  schemas: ['public', 'api'],
  ownership: { 'public.legacy_orders': ['customer_ref'] },
  rpc: {
    args: {
      'public.bump(p_id bigint)': {
        p_id: { sql: `select "Id" from public."Mixed Case" where "Owner Id" = '{target}' order by 1 limit 1` },
      },
    },
  },
})
export const EDGE_DYNAMIC = [
  'cross-user-read:api.events', 'cross-user-update:api.events', 'cross-user-delete:api.events', 'cross-user-insert:api.events',
  'cross-user-read:public.metrics_2026', 'cross-user-update:public.metrics_2026', 'cross-user-delete:public.metrics_2026',
  'cross-user-insert:public.metrics_2026',
  'cross-user-read:public.mv_totals',
  'rpc-cross-user-read:public.lookup(p_owner uuid)', 'rpc-cross-user-read:public.lookup(p_owner uuid, p_limit integer)',
  'rpc-cross-user-read:public.scalar_total(p_owner uuid, p_factor numeric)',
  'rpc-cross-user-read:public.out_params(p_owner uuid, OUT total numeric, OUT n integer)',
  'rpc-cross-user-write:public.bump(p_id bigint)',
]
export const EDGE_STATIC_SOME = [
  'rls-disabled:api.events', 'rls-disabled:public.metrics_2026', 'matview-exposed:public.mv_totals',
  'definer-caller-identity:public.scalar_total(p_owner uuid, p_factor numeric)', 'definer-anon-exec:public.bump(p_id bigint)',
]

export function checkEdge(r) {
  const dynamic = r.findings.filter((f) => f.source === 'dynamic').map((f) => f.id).sort()
  assert.deepEqual(dynamic, [...EDGE_DYNAMIC].sort())
  const all = r.findings.map((f) => f.id)
  for (const id of EDGE_STATIC_SOME) assert.ok(all.includes(id), `missing ${id}`)
  const rel = Object.fromEntries(r.coverage.relations.map((c) => [c.relation, c]))
  // Correctly protected objects: exercised, nothing visible, owner still sees their rows.
  for (const [name, rows] of [['public."Mixed Case"', 2], ['public.child_items', 2], ['public.legacy_orders', 2], ['public.metrics', 1]]) {
    assert.equal(rel[name].status, 'exercised', name)
    assert.equal(rel[name].b_rows, rows, name)
    assert.equal(rel[name].probes.A.read, `0/${rows}`, name)
    assert.equal(rel[name].owner_can_read, rows, name)
    assert.equal(r.findings.filter((f) => f.object === name).length, 0, name)
  }
  const fn = Object.fromEntries(r.coverage.functions.map((f) => [f.function, f]))
  assert.match(fn['public.raises(p_user uuid)'].results.A, /^refused \(P0001/)
  assert.equal(fn['public.safe_ids()'].results.A, 'no data of user B returned')
  assert.equal(fn['public.bump(p_id bigint)'].args[0].source, 'config (sql)')
  assert.deepEqual(r.gaps.map((g) => g.object).sort(), ['public.poly(x anyelement)', 'public.variadic_fn(VARIADIC ids uuid[])'])
  assert.equal(r.verdict, 'BLOCK')
  assert.equal(r.complete, false)
}

