# supabase-authz-audit

> **Published for review.** You are welcome to read this code. Running it, copying it or building on it needs the author's permission. To have it run on your project, hire the author.

Answers one question about a Supabase (or any PostgREST-style) Postgres database before launch:

> **Can user A, or a visitor who is not logged in, read or change anything that belongs to user B?**

It reads the database configuration, then actually tries it with two synthetic accounts, and writes a report where every finding comes with the exact statement that reproduces it. The verdict comes from tests, not from opinion. There is no AI in the pass/fail path.

Not affiliated with Supabase.

## See it work in 30 seconds

No database, Docker or account needed. The demo runs an in-process Postgres.

```bash
npm install
npm run demo
```

It audits two versions of the same small app: [`examples/vulnerable.sql`](examples/vulnerable.sql), which contains seven realistic authorization bugs, and [`examples/patched.sql`](examples/patched.sql), where they are fixed.

```
=== vulnerable.sql ===
BLOCK  critical=9 high=7 medium=4 low=0 info=0  accepted=3  not-exercised=0
  [CRITICAL] Logged-in user A can delete user B's rows in public.drafts
  [CRITICAL] Logged-in user A and an anonymous visitor can read rows in public.note_attachments that belong only to user B
  [CRITICAL] Logged-in user A and an anonymous visitor can read user B's data by calling public.get_notes_for(p_user_id uuid)
  [CRITICAL] Logged-in user A and an anonymous visitor can change user B's rows by calling public.delete_note(p_note_id uuid)
  [HIGH    ] Editing their own user_metadata lets user A read user B's rows in public.support_tickets
  ...
=== patched.sql ===
PASS  critical=0 high=0 medium=0 low=0 info=0  accepted=3  not-exercised=0
```

Full sample reports: [vulnerable](examples/reports/vulnerable.md) · [patched](examples/reports/patched.md)

## The seven bugs in the demo

| # | Bug | Why reviews miss it | How it is caught |
|---|---|---|---|
| 1 | `UPDATE` policy `USING (true)` on profiles | Reads are fine, so the app looks fine | A updates B's row |
| 2 | Child table with RLS never enabled | The table has no `user_id` column at all | Ownership is followed through the foreign key to `notes` |
| 3 | Staff check reads `user_metadata` | Looks like a role check | A repeats the read with self-edited metadata |
| 4 | Reporting view over a protected table | The table's policy is correct | A reads B's totals through the view |
| 5 | `DELETE` policy wider than the `SELECT` policy | Nobody can *see* other users' rows | Blind `DELETE` with no `WHERE`, then a recount |
| 6 | `SECURITY DEFINER` function takes `p_user_id` | Table RLS is correct | A and anon call it with B's id and get B's rows back |
| 7 | `SECURITY DEFINER` function deletes by id | No user id in the signature | B's rows are fingerprinted before and after the call |

## Run it on your project

This needs the author's permission (see [LICENSE](LICENSE)); the simplest route is to hire the author to run it and walk you through the report. With permission, use a **test or staging** database. You need:

1. Two synthetic accounts, A and B, each owning a few rows in the tables you care about.
2. A connection string for a role that can `SET ROLE` to the API roles and can see all rows. On Supabase that is the `postgres` user.

```bash
git clone https://github.com/ham-flavred-licorice/supabase-authz-audit && cd supabase-authz-audit && npm install

node bin/authz-audit.mjs \
  --database-url "$DATABASE_URL" \
  --user-a 11111111-1111-4111-8111-111111111111 \
  --user-b 22222222-2222-4222-8222-222222222222 \
  --config authz-audit.config.json
```

It writes `authz-audit-report/report.md` and `report.json`. Without cloning: `npx github:ham-flavred-licorice/supabase-authz-audit --database-url … --user-a … --user-b …`.

| Exit code | Meaning |
|---|---|
| 0 | No open finding at or above `--fail-on` (default `high`) |
| 1 | Findings |
| 2 | Could not run |

Run `node bin/authz-audit.mjs --help` for all options (`--schemas`, `--no-rpc`, `--no-writes`, `--fail-on`, `--json`, custom role names).

### Keep it from coming back

Add it to CI so a migration that opens a cross-user path fails the build. [`examples/ci-for-your-app.yml`](examples/ci-for-your-app.yml) is a starting point for a project that uses the Supabase CLI.

## What it checks

**Configuration (static)**

- Tables the API roles can reach with RLS turned off, including partitions of a protected parent
- Policies that are always true, and policies that trust `user_metadata`
- `SECURITY DEFINER` functions: missing `search_path`, callable by `anon` or `PUBLIC`, taking a user id without checking the caller
- Views that run with their owner's rights over RLS-protected tables, and exposed materialized views
- `EXECUTE` grants for `anon`, `authenticated`, `service_role` and `PUBLIC` on every exposed function

**Behaviour (dynamic)**, as user A, as `anon`, and as user A with self-edited `user_metadata`:

- Read, update, delete and blind-delete/update against rows that belong only to B
- Insert a forged row attributed to B
- Call every exposed function with B's values. A leak is detected two ways: B's values appear in the output, or the caller gets exactly what B gets and something different for their own values (this catches numbers and enums, which carry no recognisable marker)
- Detect writes through functions by fingerprinting B's rows before and after each call

## How it decides what belongs to whom

A row belongs to a user when a `uuid` column holds their id, or when a foreign key leads to such a row (followed transitively). A row linked to both A and B, such as a message between them, is shared and is never reported.

Things that need a line of config:

```jsonc
{
  "ids": { "A": "…", "B": "…" },
  "schemas": ["public", "api"],
  // Owner stored in a non-uuid column
  "ownership": { "public.legacy_orders": ["customer_ref"] },
  // Intended exposure. Each entry needs a reason; it is listed in the report, not hidden.
  "accept": [
    { "match": "cross-user-read:public.profiles", "reason": "Profiles are public to logged-in users." }
  ],
  "rpc": {
    "skip": ["public.send_invoice_email(p_invoice_id uuid)"],
    // Arguments the tool cannot guess. {target} is the id of the user being targeted.
    "args": {
      "public.bump(p_id bigint)": {
        "p_id": { "sql": "select id from public.items where owner = '{target}' limit 1" }
      }
    }
  }
}
```

## Safety

- The whole dynamic pass runs in **one transaction that is always rolled back**. Each probe runs in its own savepoint.
- The test suite fingerprints every row and the security catalog before and after an audit and requires them to be identical.
- Reports quote data only from rows of synthetic user B: short samples of returned values, and one full row in the forged-insert reproduction. Use synthetic accounts, never real users.
- A function that calls out of the database (HTTP, email) cannot be rolled back. Run against a test database and list such functions under `rpc.skip`.

## Honest limits

- It reproduces the authorization context PostgREST sets for a request (`SET LOCAL ROLE` plus `request.jwt.claims`) at the SQL level. It does not send HTTP requests, so API gateway settings, exposed-schema settings and JWT validation are out of scope.
- It tests authorization between users. It does not test authentication, Storage buckets, Edge Functions, Realtime, rate limits or business-logic flaws.
- It can only test what has data. A table with no rows for user B is reported under **Not exercised**, and the verdict says so. A function whose call proves nothing is reported the same way. A PASS never silently covers something that was not tested.

## Verified on

| Engine | Result |
|---|---|
| PostgreSQL 18.6 (in-process, via PGlite) | 18 tests pass |
| PostgreSQL 16.15 (native server, `pg` driver) | 5 integration tests pass, including a run as a non-superuser `BYPASSRLS` role, the shape of Supabase's `postgres` user |

```bash
npm test                                             # in-process engine
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres npm run test:pg   # real server
```

The tests assert that the audit finds exactly the planted bugs and nothing else, that correctly protected tables produce no findings, that results are deterministic, and that the database is left unchanged.

## Layout

```
bin/authz-audit.mjs   CLI
src/catalog.mjs       static pass
src/dynamic.mjs       dynamic pass
src/report.mjs        Markdown and console output
src/index.mjs         runAudit(db, config)
examples/             demo schemas, seed, config, sample reports
test/                 test suite and an edge-case schema (quoted names, identity/generated
                      columns, enums, arrays, partitions, matviews, overloads, defaults)
```

## License

All rights reserved. See [LICENSE](LICENSE). This code is published to be read. Running, copying or reusing it requires the author's permission.
