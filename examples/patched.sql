-- "Notably" with all seven bugs fixed. Compare with vulnerable.sql.

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null,
  bio text
);
alter table public.profiles enable row level security;
create policy profiles_read on public.profiles for select to authenticated using (true);
-- FIX 1: you can only edit your own profile, and cannot hand it to someone else.
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

create table public.notes (
  id uuid primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  body text not null
);
alter table public.notes enable row level security;
create policy notes_owner on public.notes for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create table public.note_attachments (
  id uuid primary key,
  note_id uuid not null references public.notes (id) on delete cascade,
  file_path text not null
);
-- FIX 2: RLS on, and an attachment is reachable only through a note you own.
alter table public.note_attachments enable row level security;
create policy attachments_owner on public.note_attachments for all to authenticated
  using (exists (select 1 from public.notes n where n.id = note_id and n.user_id = auth.uid()))
  with check (exists (select 1 from public.notes n where n.id = note_id and n.user_id = auth.uid()));

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

create table public.support_tickets (
  id uuid primary key,
  user_id uuid not null references auth.users (id),
  subject text not null,
  body text not null
);
alter table public.support_tickets enable row level security;
-- FIX 3: staff role comes from app_metadata, which only the server can write.
create policy tickets_read on public.support_tickets for select to authenticated
  using (user_id = auth.uid() or (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
create policy tickets_create on public.support_tickets for insert to authenticated
  with check (user_id = auth.uid());

create table public.invoices (
  id uuid primary key,
  user_id uuid not null references auth.users (id),
  amount_cents integer not null,
  status text not null
);
alter table public.invoices enable row level security;
create policy invoices_owner on public.invoices for select to authenticated using (user_id = auth.uid());
-- FIX 4: the view now runs with the caller's rights, so the invoices policy applies.
create view public.invoice_summary with (security_invoker = true) as
  select user_id, count(*)::int as invoices, sum(amount_cents)::int as total_cents
  from public.invoices group by user_id;

create table public.drafts (
  id uuid primary key,
  user_id uuid not null references auth.users (id),
  content text not null
);
alter table public.drafts enable row level security;
create policy drafts_read on public.drafts for select to authenticated using (user_id = auth.uid());
create policy drafts_write on public.drafts for insert to authenticated with check (user_id = auth.uid());
-- FIX 5: you can only delete your own drafts.
create policy drafts_cleanup on public.drafts for delete to authenticated using (user_id = auth.uid());

-- FIX 6: the caller must be the user they ask about; fixed search_path; no anonymous access.
create function public.get_notes_for(p_user_id uuid) returns setof public.notes
language sql security definer set search_path = '' as $$
  select * from public.notes where user_id = p_user_id and p_user_id = auth.uid()
$$;
revoke execute on function public.get_notes_for(uuid) from public, anon;

-- FIX 7: only the owner's note can be deleted; fixed search_path; no anonymous access.
create function public.delete_note(p_note_id uuid) returns void
language sql security definer set search_path = '' as $$
  delete from public.notes where id = p_note_id and user_id = auth.uid()
$$;
revoke execute on function public.delete_note(uuid) from public, anon;

create function public.my_note_count() returns integer
language sql stable security invoker as $$
  select count(*)::int from public.notes
$$;

create table public.plans (
  code text primary key,
  name text not null,
  price_cents integer not null
);
alter table public.plans enable row level security;
create policy plans_read on public.plans for select to anon, authenticated using (true);
