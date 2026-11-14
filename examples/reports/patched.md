# Authorization audit report

**Verdict: PASS.** No cross-user path was found. Every table, view and function that could be linked to a user was exercised.

| | |
|---|---|
| Question tested | Can user A, or a visitor who is not logged in, read or change anything that belongs to user B? |
| Database | PostgreSQL 18.6, schemas: public |
| Test accounts | A = `aaaaaaaa-0000-4000-8000-000000000001`, B = `bbbbbbbb-0000-4000-8000-000000000002` (synthetic) |
| Generated | 2026-11-14T19:44:15.041Z by supabase-authz-audit 0.1.0 |

## Summary

| Severity | Open findings |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 0 |
| Accepted by design | 3 |

## Findings

No open findings.

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
| public.drafts | table | yes | 3 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |
| public.invoice_summary | view | – | 0 | 1 | 0/1 | – | – | – | 0/1 | – |
| public.invoices | table | yes | 1 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |
| public.messages | table | yes | 2 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |
| public.note_attachments | table | yes | 1 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |
| public.notes | table | yes | 1 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |
| public.plans | table | yes | 1 | 0 | not exercised: no ownership link found | | | | | |
| public.profiles | table | yes | 2 | 1 | 1/1 | blocked | blocked | denied | 0/1 | blocked |
| public.support_tickets | table | yes | 2 | 2 | 0/2 | blocked | blocked | denied | 0/2 | blocked |

"A: read 0/2" means user A could see 0 of the 2 rows that belong only to user B.

### Functions callable through the API

| Function | SECURITY DEFINER | Fixed search_path | EXECUTE: anon / authenticated / service_role / PUBLIC | As user A | As anon |
|---|---|---|---|---|---|
| public.delete_note(p_note_id uuid) | yes | yes | no / yes / yes / no | scoped to caller | no EXECUTE privilege |
| public.get_notes_for(p_user_id uuid) | yes | yes | no / yes / yes / no | scoped to caller | no EXECUTE privilege |
| public.my_note_count() | no | – | yes / yes / yes / yes | no data of user B returned | no data of user B returned |

## Not exercised

Nothing. Every object that could be linked to a user was tested.

## Method and limits

- **Static pass:** reads the system catalogs for RLS state, policies, grants, SECURITY DEFINER functions, search_path and view options.
- **Dynamic pass:** switches to each API role with the same `SET LOCAL ROLE` and `request.jwt.claims` settings PostgREST uses for a request, then tries to read, update, delete and insert against rows that belong only to user B, and calls every exposed function with user B's values.
- **Ownership:** a row belongs to a user when a uuid column holds their id, or when a foreign key leads to such a row. Rows linked to both users are treated as shared and never reported.
- **Safety:** the whole dynamic pass runs in one transaction that is rolled back, and each probe runs in its own savepoint. Run it against a test or staging database, because functions with side effects outside the database (HTTP calls, emails) cannot be rolled back.
- **Limits:** this tests authorization between users. It does not test authentication, storage buckets, Edge Functions, realtime channels, rate limits or business-logic flaws. A PASS means no cross-user path was found in what was exercised; the "Not exercised" section says what was left out.
