# Authorization audit report

**Verdict: BLOCK.** 16 launch-blocking findings (9 critical, 7 high). At least one path lets one user reach another user's data.

| | |
|---|---|
| Question tested | Can user A, or a visitor who is not logged in, read or change anything that belongs to user B? |
| Database | PostgreSQL 18.6, schemas: public |
| Test accounts | A = `aaaaaaaa-0000-4000-8000-000000000001`, B = `bbbbbbbb-0000-4000-8000-000000000002` (synthetic) |
| Generated | 2026-11-14T19:44:13.479Z by supabase-authz-audit 0.1.0 |

## Summary

| Severity | Open findings |
|---|---|
| CRITICAL | 9 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 0 |
| INFO | 0 |
| Accepted by design | 3 |

## Findings

### 1. CRITICAL · Logged-in user A can delete user B's rows in public.drafts

`cross-user-delete:public.drafts` · confirmed by a live test

Evidence:

```json
{
  "A": {
    "blind": true,
    "user_b_rows_before": 2,
    "user_b_rows_after": 0
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","aud":"authenticated","app_metadata":{},"user_metadata":{}}', true);
set local role "authenticated";
DELETE FROM public.drafts;  -- DESTRUCTIVE if committed: keep it inside this transaction
rollback;
```

Fix:

```sql
-- Scope the DELETE policy on public.drafts to the caller. A DELETE policy must never be wider than the SELECT policy.
```

### 2. CRITICAL · Logged-in user A and an anonymous visitor can delete user B's rows in public.note_attachments

`cross-user-delete:public.note_attachments` · confirmed by a live test

Evidence:

```json
{
  "A": {
    "result": "2 row(s) affected",
    "user_b_rows": 2
  },
  "anon": {
    "result": "2 row(s) affected",
    "user_b_rows": 2
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"role":"anon"}', true);
set local role "anon";
DELETE FROM public.note_attachments WHERE (id::text = 'bbbbbbbb-0000-4000-8000-000000000002' OR note_id::text = 'bbbbbbbb-0000-4000-8000-000000000002' OR note_id::text = ANY(ARRAY['10000000-0000-4000-8000-0000000000b1', '10000000-0000-4000-8000-0000000000b2']::text[])) AND NOT coalesce((id::text = 'aaaaaaaa-0000-4000-8000-000000000001' OR note_id::text = 'aaaaaaaa-0000-4000-8000-000000000001' OR note_id::text = ANY(ARRAY['10000000-0000-4000-8000-0000000000a1', '10000000-0000-4000-8000-0000000000a2']::text[])), false);  -- expected 0 rows
rollback;
```

Fix:

```sql
-- Scope the DELETE policy on public.note_attachments to the caller. A DELETE policy must never be wider than the SELECT policy.
```

### 3. CRITICAL · Logged-in user A and an anonymous visitor can insert rows into public.note_attachments that are attributed to user B

`cross-user-insert:public.note_attachments` · confirmed by a live test

Evidence:

```json
{
  "A": {
    "result": "row passed the authorization check; only constraint 23505 stopped it (the probe replays an existing row)"
  },
  "anon": {
    "result": "row passed the authorization check; only constraint 23505 stopped it (the probe replays an existing row)"
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"role":"anon"}', true);
set local role "anon";
INSERT INTO public.note_attachments (id, note_id, file_path) VALUES ('20000000-0000-4000-8000-0000000000b1'::text::uuid, '10000000-0000-4000-8000-0000000000b1'::text::uuid, 'user-b/passport-b1.pdf'::text::text);  -- expected: new row violates row-level security policy
rollback;
```

Fix:

```sql
-- Add WITH CHECK to the INSERT policy on public.note_attachments so the owner must be auth.uid().
```

### 4. CRITICAL · Logged-in user A and an anonymous visitor can read rows in public.invoice_summary that belong only to user B

`cross-user-read:public.invoice_summary` · confirmed by a live test

Evidence:

```json
{
  "A": {
    "visible_rows": 1,
    "user_b_rows": 1
  },
  "anon": {
    "visible_rows": 1,
    "user_b_rows": 1
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"role":"anon"}', true);
set local role "anon";
SELECT count(*)::int AS n FROM public.invoice_summary WHERE (user_id::text = 'bbbbbbbb-0000-4000-8000-000000000002') AND NOT coalesce((user_id::text = 'aaaaaaaa-0000-4000-8000-000000000001'), false);  -- expected 0, got 1
rollback;
```

Fix:

```sql
-- Make the view respect the caller's row access: ALTER VIEW public.invoice_summary SET (security_invoker = true);
```

### 5. CRITICAL · Logged-in user A and an anonymous visitor can read rows in public.note_attachments that belong only to user B

`cross-user-read:public.note_attachments` · confirmed by a live test

Evidence:

```json
{
  "A": {
    "visible_rows": 2,
    "user_b_rows": 2
  },
  "anon": {
    "visible_rows": 2,
    "user_b_rows": 2
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"role":"anon"}', true);
set local role "anon";
SELECT count(*)::int AS n FROM public.note_attachments WHERE (id::text = 'bbbbbbbb-0000-4000-8000-000000000002' OR note_id::text = 'bbbbbbbb-0000-4000-8000-000000000002' OR note_id::text = ANY(ARRAY['10000000-0000-4000-8000-0000000000b1', '10000000-0000-4000-8000-0000000000b2']::text[])) AND NOT coalesce((id::text = 'aaaaaaaa-0000-4000-8000-000000000001' OR note_id::text = 'aaaaaaaa-0000-4000-8000-000000000001' OR note_id::text = ANY(ARRAY['10000000-0000-4000-8000-0000000000a1', '10000000-0000-4000-8000-0000000000a2']::text[])), false);  -- expected 0, got 2
rollback;
```

Fix:

```sql
-- Scope the SELECT policy on public.note_attachments to the caller, for example USING (user_id = auth.uid()). If RLS is off, turn it on first.
```

### 6. CRITICAL · Logged-in user A and an anonymous visitor can update user B's rows in public.note_attachments

`cross-user-update:public.note_attachments` · confirmed by a live test

Evidence:

```json
{
  "A": {
    "result": "2 row(s) affected",
    "user_b_rows": 2
  },
  "anon": {
    "result": "2 row(s) affected",
    "user_b_rows": 2
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"role":"anon"}', true);
set local role "anon";
UPDATE public.note_attachments SET note_id = note_id WHERE (id::text = 'bbbbbbbb-0000-4000-8000-000000000002' OR note_id::text = 'bbbbbbbb-0000-4000-8000-000000000002' OR note_id::text = ANY(ARRAY['10000000-0000-4000-8000-0000000000b1', '10000000-0000-4000-8000-0000000000b2']::text[])) AND NOT coalesce((id::text = 'aaaaaaaa-0000-4000-8000-000000000001' OR note_id::text = 'aaaaaaaa-0000-4000-8000-000000000001' OR note_id::text = ANY(ARRAY['10000000-0000-4000-8000-0000000000a1', '10000000-0000-4000-8000-0000000000a2']::text[])), false);  -- expected 0 rows
rollback;
```

Fix:

```sql
-- Scope the UPDATE policy on public.note_attachments with both USING and WITH CHECK tied to the caller.
```

### 7. CRITICAL · Logged-in user A can update user B's rows in public.profiles

`cross-user-update:public.profiles` · confirmed by a live test

Evidence:

```json
{
  "A": {
    "result": "1 row(s) affected",
    "user_b_rows": 1
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","aud":"authenticated","app_metadata":{},"user_metadata":{}}', true);
set local role "authenticated";
UPDATE public.profiles SET display_name = display_name WHERE (id::text = 'bbbbbbbb-0000-4000-8000-000000000002') AND NOT coalesce((id::text = 'aaaaaaaa-0000-4000-8000-000000000001'), false);  -- expected 0 rows
rollback;
```

Fix:

```sql
-- Scope the UPDATE policy on public.profiles with both USING and WITH CHECK tied to the caller.
```

### 8. CRITICAL · Logged-in user A and an anonymous visitor can read user B's data by calling public.get_notes_for(p_user_id uuid)

`rpc-cross-user-read:public.get_notes_for(p_user_id uuid)` · confirmed by a live test

Evidence:

```json
{
  "A": {
    "values_of_user_b_returned": 6,
    "sample": [
      "10000000-0000-4000-8000-0000…",
      "10000000-0000-4000-8000-0000…",
      "B note one"
    ],
    "arguments": [
      {
        "name": "p_user_id",
        "source": "target user's data (user_id)"
      }
    ]
  },
  "anon": {
    "values_of_user_b_returned": 6,
    "sample": [
      "10000000-0000-4000-8000-0000…",
      "10000000-0000-4000-8000-0000…",
      "B note one"
    ],
    "arguments": [
      {
        "name": "p_user_id",
        "source": "target user's data (user_id)"
      }
    ]
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"role":"anon"}', true);
set local role "anon";
SELECT * FROM public.get_notes_for('bbbbbbbb-0000-4000-8000-000000000002'::uuid);  -- returns user B's data
rollback;
```

Fix:

```sql
-- Inside public.get_notes_for(p_user_id uuid), take the identity from auth.uid() instead of an argument, or raise when they differ.
```

### 9. CRITICAL · Logged-in user A and an anonymous visitor can change user B's rows by calling public.delete_note(p_note_id uuid)

`rpc-cross-user-write:public.delete_note(p_note_id uuid)` · confirmed by a live test

Evidence:

```json
{
  "A": {
    "changed": [
      {
        "table": "public.note_attachments",
        "rows_before": 2,
        "rows_after": 1
      },
      {
        "table": "public.notes",
        "rows_before": 2,
        "rows_after": 1
      }
    ],
    "arguments": [
      {
        "name": "p_note_id",
        "source": "target user's data (note_id)"
      }
    ]
  },
  "anon": {
    "changed": [
      {
        "table": "public.note_attachments",
        "rows_before": 2,
        "rows_after": 1
      },
      {
        "table": "public.notes",
        "rows_before": 2,
        "rows_after": 1
      }
    ],
    "arguments": [
      {
        "name": "p_note_id",
        "source": "target user's data (note_id)"
      }
    ]
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"role":"anon"}', true);
set local role "anon";
SELECT public.delete_note('10000000-0000-4000-8000-0000000000b1'::uuid);  -- changes user B's rows; DESTRUCTIVE if committed: keep it inside this transaction
rollback;
```

Fix:

```sql
-- Inside public.delete_note(p_note_id uuid), verify the row belongs to auth.uid() before changing it (add "AND user_id = auth.uid()").
```

### 10. HIGH · Editing their own user_metadata lets user A read user B's rows in public.support_tickets

`metadata-escalation-read:public.support_tickets` · confirmed by a live test

Evidence:

```json
{
  "A+user_metadata": {
    "visible_rows_before": 0,
    "visible_rows_after": 2,
    "forged_user_metadata": {
      "role": "admin",
      "is_admin": true,
      "admin": true
    }
  }
}
```

Reproduce (safe: it rolls back):

```sql
begin;
select set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","aud":"authenticated","app_metadata":{},"user_metadata":{"role":"admin","is_admin":true,"admin":true}}', true);
set local role "authenticated";
SELECT count(*)::int AS n FROM public.support_tickets WHERE (id::text = 'bbbbbbbb-0000-4000-8000-000000000002' OR user_id::text = 'bbbbbbbb-0000-4000-8000-000000000002') AND NOT coalesce((id::text = 'aaaaaaaa-0000-4000-8000-000000000001' OR user_id::text = 'aaaaaaaa-0000-4000-8000-000000000001'), false);  -- expected 0, got 2
rollback;
```

Fix:

```sql
-- Do not use user_metadata in access rules; users can change it themselves. Use app_metadata or a roles table.
```

### 11. HIGH · SECURITY DEFINER function public.get_notes_for(p_user_id uuid) takes a user id from the caller and never checks who is calling

`definer-caller-identity:public.get_notes_for(p_user_id uuid)` · found in the database configuration

Evidence:

```json
{
  "identity_parameters": [
    "p_user_id"
  ],
  "caller_check_found": false
}
```

Fix:

```sql
-- Take the identity from the session, not from an argument:
--   ... WHERE user_id = auth.uid()
-- or reject mismatches at the top of the function:
--   IF p_user_id IS DISTINCT FROM auth.uid() THEN RAISE EXCEPTION 'not allowed'; END IF;
```

### 12. HIGH · Policy "drafts_cleanup" on public.drafts allows DELETE on every row for authenticated

`policy-always-true:public.drafts:drafts_cleanup` · found in the database configuration

Evidence:

```json
{
  "command": "DELETE",
  "roles": [
    "authenticated"
  ],
  "using": "true",
  "with_check": null
}
```

Fix:

```sql
ALTER POLICY "drafts_cleanup" ON public.drafts
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());  -- use the table's real owner column
```

### 13. HIGH · Policy "profiles_update" on public.profiles allows UPDATE on every row for authenticated

`policy-always-true:public.profiles:profiles_update` · found in the database configuration

Evidence:

```json
{
  "command": "UPDATE",
  "roles": [
    "authenticated"
  ],
  "using": "true",
  "with_check": null
}
```

Fix:

```sql
ALTER POLICY "profiles_update" ON public.profiles
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());  -- use the table's real owner column
```

### 14. HIGH · Policy "tickets_read" on public.support_tickets trusts user_metadata, which every user can edit for themselves

`policy-user-metadata:public.support_tickets:tickets_read` · found in the database configuration

Evidence:

```json
{
  "command": "SELECT",
  "using": "((user_id = auth.uid()) OR (((auth.jwt() -> 'user_metadata'::text) ->> 'role'::text) = 'admin'::text))",
  "with_check": null
}
```

Fix:

```sql
-- Read roles from app_metadata (server-controlled) or from a roles table:
-- (auth.jwt() -> 'app_metadata' ->> 'role') = 'support'
```

### 15. HIGH · Row Level Security is off on public.note_attachments and the API roles can reach it

`rls-disabled:public.note_attachments` · found in the database configuration

Evidence:

```json
{
  "anon": [
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE"
  ],
  "authenticated": [
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE"
  ]
}
```

Fix:

```sql
ALTER TABLE public.note_attachments ENABLE ROW LEVEL SECURITY;
-- then add policies that scope rows to the caller, e.g.
-- CREATE POLICY own_rows ON public.note_attachments FOR ALL TO authenticated
--   USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
```

### 16. HIGH · View public.invoice_summary runs with its owner's rights, so RLS on the tables underneath is skipped

`view-definer-rights:public.invoice_summary` · found in the database configuration

Evidence:

```json
{
  "select": {
    "anon": true,
    "authenticated": true
  },
  "owner": "postgres",
  "reads_rls_tables": [
    "public.invoices"
  ]
}
```

Fix:

```sql
ALTER VIEW public.invoice_summary SET (security_invoker = true);
```

### 17. MEDIUM · SECURITY DEFINER function public.delete_note(p_note_id uuid) can be called without logging in

`definer-anon-exec:public.delete_note(p_note_id uuid)` · found in the database configuration

Evidence:

```json
{
  "via_public_grant": true,
  "anon": true,
  "authenticated": true,
  "service_role": true
}
```

Fix:

```sql
REVOKE EXECUTE ON FUNCTION public.delete_note(p_note_id uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.delete_note(p_note_id uuid) TO authenticated;
```

### 18. MEDIUM · SECURITY DEFINER function public.get_notes_for(p_user_id uuid) can be called without logging in

`definer-anon-exec:public.get_notes_for(p_user_id uuid)` · found in the database configuration

Evidence:

```json
{
  "via_public_grant": true,
  "anon": true,
  "authenticated": true,
  "service_role": true
}
```

Fix:

```sql
REVOKE EXECUTE ON FUNCTION public.get_notes_for(p_user_id uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_notes_for(p_user_id uuid) TO authenticated;
```

### 19. MEDIUM · SECURITY DEFINER function public.delete_note(p_note_id uuid) has no fixed search_path

`definer-search-path:public.delete_note(p_note_id uuid)` · found in the database configuration

Evidence:

```json
{
  "config": []
}
```

Fix:

```sql
ALTER FUNCTION public.delete_note(p_note_id uuid) SET search_path = '';
-- and schema-qualify every object the function touches.
```

### 20. MEDIUM · SECURITY DEFINER function public.get_notes_for(p_user_id uuid) has no fixed search_path

`definer-search-path:public.get_notes_for(p_user_id uuid)` · found in the database configuration

Evidence:

```json
{
  "config": []
}
```

Fix:

```sql
ALTER FUNCTION public.get_notes_for(p_user_id uuid) SET search_path = '';
-- and schema-qualify every object the function touches.
```

## Accepted by design

These were detected and are excluded from the verdict because the config says they are intended.

| Finding | Severity | Reason |
|---|---|---|
| `cross-user-read:public.profiles` | HIGH | Profiles are public to logged-in users by design (display name and bio only). |
| `policy-always-true:public.plans:plans_read` | MEDIUM | The price list is public. |
| `policy-always-true:public.profiles:profiles_read` | MEDIUM | Same decision: profiles are readable by every logged-in user. |

## Coverage

### Tables and views

| Relation | Kind | RLS | Policies | Rows of B | A: read | A: update | A: delete | A: insert as B | anon: read | anon: writes |
|---|---|---|---|---|---|---|---|---|---|---|
| public.drafts | table | yes | 3 | 2 | 0/2 | blocked | ALLOWED (blind) | denied | 0/2 | blocked |
| public.invoice_summary | view | – | 0 | 1 | 1/1 | – | – | – | 1/1 | – |
| public.invoices | table | yes | 1 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |
| public.messages | table | yes | 2 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |
| public.note_attachments | table | no | 0 | 2 | 2/2 | ALLOWED | ALLOWED | ALLOWED | 2/2 | ALLOWED |
| public.notes | table | yes | 1 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |
| public.plans | table | yes | 1 | 0 | not exercised: no ownership link found | | | | | |
| public.profiles | table | yes | 2 | 1 | 1/1 | ALLOWED | blocked | denied | 0/1 | blocked |
| public.support_tickets | table | yes | 2 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |

"A: read 0/2" means user A could see 0 of the 2 rows that belong only to user B.

### Functions callable through the API

| Function | SECURITY DEFINER | Fixed search_path | EXECUTE: anon / authenticated / service_role / PUBLIC | As user A | As anon |
|---|---|---|---|---|---|
| public.delete_note(p_note_id uuid) | yes | no | yes / yes / yes / yes | WRITE | WRITE |
| public.get_notes_for(p_user_id uuid) | yes | no | yes / yes / yes / yes | LEAK | LEAK |
| public.my_note_count() | no | – | yes / yes / yes / yes | no data of user B returned | no data of user B returned |

## Not exercised

Nothing. Every object that could be linked to a user was tested.

## Method and limits

- **Static pass:** reads the system catalogs for RLS state, policies, grants, SECURITY DEFINER functions, search_path and view options.
- **Dynamic pass:** switches to each API role with the same `SET LOCAL ROLE` and `request.jwt.claims` settings PostgREST uses for a request, then tries to read, update, delete and insert against rows that belong only to user B, and calls every exposed function with user B's values.
- **Ownership:** a row belongs to a user when a uuid column holds their id, or when a foreign key leads to such a row. Rows linked to both users are treated as shared and never reported.
- **Safety:** the whole dynamic pass runs in one transaction that is rolled back, and each probe runs in its own savepoint. Run it against a test or staging database, because functions with side effects outside the database (HTTP calls, emails) cannot be rolled back.
- **Limits:** this tests authorization between users. It does not test authentication, storage buckets, Edge Functions, realtime channels, rate limits or business-logic flaws. A PASS means no cross-user path was found in what was exercised; the "Not exercised" section says what was left out.
