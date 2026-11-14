-- "Notably", a fictional notes app. This version contains seven authorization bugs of the
-- kinds that reach production most often. Each one is marked BUG n. See patched.sql for the fixes.

-- Profiles are public by design (everyone logged in can read them)...
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null,
  bio text
);
alter table public.profiles enable row level security;
create policy profiles_read on public.profiles for select to authenticated using (true);
-- BUG 1: ...but this lets every logged-in user edit every profile.
create policy profiles_update on public.profiles for update to authenticated using (true);

-- Notes: the table policy is correct.
create table public.notes (
  id uuid primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  body text not null
);
alter table public.notes enable row level security;
create policy notes_owner on public.notes for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- BUG 2: a child table added later, and nobody enabled RLS on it.
create table public.note_attachments (
  id uuid primary key,
  note_id uuid not null references public.notes (id) on delete cascade,
  file_path text not null
);

-- Messages are shared between two people. Correct in both versions.
create table public.messages (
  id uuid primary key,
  sender_id uuid not null references auth.users (id),
  recipient_id uuid not null references auth.users (id),
  body text not null
);
alter table public.messages enable row level security;
create policy messages_participants on public.messages for select to authenticated
  using (auth.uid() in (sender_id, recipient_id));
create policy messages_send on public.messages for insert to authenticated
  with check (sender_id = auth.uid());

-- BUG 3: the "support staff" check reads user_metadata, which users can edit themselves.
create table public.support_tickets (
  id uuid primary key,
  user_id uuid not null references auth.users (id),
  subject text not null,
  body text not null
);
alter table public.support_tickets enable row level security;
create policy tickets_read on public.support_tickets for select to authenticated
  using (user_id = auth.uid() or (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
create policy tickets_create on public.support_tickets for insert to authenticated
  with check (user_id = auth.uid());

-- Invoices: the table policy is correct.
create table public.invoices (
  id uuid primary key,
  user_id uuid not null references auth.users (id),
  amount_cents integer not null,
  status text not null
);
alter table public.invoices enable row level security;
create policy invoices_owner on public.invoices for select to authenticated using (user_id = auth.uid());
-- BUG 4: a reporting view. Views run with their owner's rights unless told otherwise,
-- so this one skips the policy above and shows every customer's totals.
create view public.invoice_summary as
  select user_id, count(*)::int as invoices, sum(amount_cents)::int as total_cents
  from public.invoices group by user_id;

-- Drafts: reading is scoped correctly.
create table public.drafts (
  id uuid primary key,
  user_id uuid not null references auth.users (id),
  content text not null
);
alter table public.drafts enable row level security;
create policy drafts_read on public.drafts for select to authenticated using (user_id = auth.uid());
create policy drafts_write on public.drafts for insert to authenticated with check (user_id = auth.uid());
-- BUG 5: a "cleanup" policy wider than the read policy. Nobody can see other people's
-- drafts, but anybody can delete them.
create policy drafts_cleanup on public.drafts for delete to authenticated using (true);

-- BUG 6: runs as the table owner and trusts whatever user id the caller sends.
-- It also has no fixed search_path and is callable without logging in.
create function public.get_notes_for(p_user_id uuid) returns setof public.notes
language sql security definer as $$
  select * from public.notes where user_id = p_user_id
$$;

-- BUG 7: deletes by id with no ownership check.
create function public.delete_note(p_note_id uuid) returns void
language sql security definer as $$
  delete from public.notes where id = p_note_id
$$;

-- A correct function for contrast: it runs with the caller's rights, so RLS applies.
create function public.my_note_count() returns integer
language sql stable security invoker as $$
  select count(*)::int from public.notes
$$;

-- A lookup table with no owner. Public by design.
create table public.plans (
  code text primary key,
  name text not null,
  price_cents integer not null
);
alter table public.plans enable row level security;
create policy plans_read on public.plans for select to anon, authenticated using (true);
