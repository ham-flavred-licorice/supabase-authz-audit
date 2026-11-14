-- Awkward-but-legal schema used to make sure the audit copes with real-world variety:
-- quoted names, identity and generated columns, enums, arrays, bytea, composite keys,
-- a second schema, partitions, a materialized view, text owner columns, triggers,
-- overloads, defaults, OUT parameters, variadic and polymorphic functions.
create schema api;
grant usage on schema api to anon, authenticated, service_role;

create type public.mood as enum ('ok', 'bad');

create table public."Mixed Case" (
  "Id" bigint generated always as identity primary key,
  "Owner Id" uuid not null,
  mood public.mood not null default 'ok',
  tags text[] not null default '{}',
  payload jsonb not null default '{}',
  blob bytea,
  amount numeric(10,2) not null default 0,
  created timestamptz not null default now(),
  doubled numeric generated always as (amount * 2) stored,
  note varchar(40)
);
alter table public."Mixed Case" enable row level security;
create policy mc_owner on public."Mixed Case" for all to authenticated
  using ("Owner Id" = auth.uid()) with check ("Owner Id" = auth.uid());

create table public.child_items (
  parent_id bigint not null references public."Mixed Case" ("Id") on delete cascade,
  seq integer not null,
  label text not null,
  primary key (parent_id, seq)
);
alter table public.child_items enable row level security;
create policy ci_owner on public.child_items for all to authenticated
  using (exists (select 1 from public."Mixed Case" m where m."Id" = parent_id and m."Owner Id" = auth.uid()))
  with check (exists (select 1 from public."Mixed Case" m where m."Id" = parent_id and m."Owner Id" = auth.uid()));

-- Owner stored as text: needs an "ownership" entry in the config. Correctly protected.
create table public.legacy_orders (id serial primary key, customer_ref text not null, total integer not null);
alter table public.legacy_orders enable row level security;
create policy lo_owner on public.legacy_orders for all to authenticated
  using (customer_ref = auth.uid()::text) with check (customer_ref = auth.uid()::text);
create function public.touch_order() returns trigger language plpgsql as $$ begin new.total := new.total; return new; end $$;
create trigger legacy_orders_touch before update on public.legacy_orders for each row execute function public.touch_order();

-- Second schema, RLS forgotten.
create table api.events (id uuid primary key default gen_random_uuid(), actor uuid not null, kind text not null);
grant all on api.events to anon, authenticated;

-- Partitioned table: RLS on the parent does not protect a partition that is queried directly.
create table public.metrics (user_id uuid not null, day date not null, value integer not null) partition by range (day);
create table public.metrics_2026 partition of public.metrics for values from ('2026-01-01') to ('2027-01-01');
alter table public.metrics enable row level security;
create policy metrics_owner on public.metrics for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

insert into auth.users (id, email) values
  ('aaaaaaaa-0000-4000-8000-000000000001', 'user-a@authz-audit.test'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'user-b@authz-audit.test');
insert into public."Mixed Case" ("Owner Id", mood, tags, payload, blob, amount, note) values
  ('aaaaaaaa-0000-4000-8000-000000000001', 'ok', '{x,y}', '{"k": 1}', '\x00ff', 10.50, 'note-of-A-row'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'bad', '{z}', '{"k": 2}', '\xdead', 20.25, 'note-of-B-row'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'ok', '{}', '{}', null, 5.00, null);
insert into public.child_items values (1, 1, 'a-child'), (2, 1, 'b-child-one'), (3, 1, 'b-child-two');
insert into public.legacy_orders (customer_ref, total) values
  ('aaaaaaaa-0000-4000-8000-000000000001', 100), ('bbbbbbbb-0000-4000-8000-000000000002', 200), ('bbbbbbbb-0000-4000-8000-000000000002', 300);
insert into api.events (id, actor, kind) values
  ('e0000000-0000-4000-8000-0000000000a1', 'aaaaaaaa-0000-4000-8000-000000000001', 'login'),
  ('e0000000-0000-4000-8000-0000000000b1', 'bbbbbbbb-0000-4000-8000-000000000002', 'login'),
  ('e0000000-0000-4000-8000-0000000000b2', 'bbbbbbbb-0000-4000-8000-000000000002', 'export');
insert into public.metrics values
  ('aaaaaaaa-0000-4000-8000-000000000001', '2026-03-01', 1), ('bbbbbbbb-0000-4000-8000-000000000002', '2026-03-01', 2);

-- Materialized views cannot enforce RLS at all.
create materialized view public.mv_totals as
  select "Owner Id" as owner_id, sum(amount) as total from public."Mixed Case" group by 1;

-- Leaks only numbers and an enum: nothing a text search could recognise.
create function public.lookup(p_owner uuid) returns table (id bigint, mood public.mood)
language sql security definer set search_path = '' as $$
  select m."Id", m.mood from public."Mixed Case" m where m."Owner Id" = p_owner order by 1
$$;
-- Overload.
create function public.lookup(p_owner uuid, p_limit integer) returns table (id bigint, mood public.mood)
language sql security definer set search_path = '' as $$
  select m."Id", m.mood from public."Mixed Case" m where m."Owner Id" = p_owner order by 1 limit p_limit
$$;
-- Has a defaulted argument: the audit calls it with the required argument only.
create function public.scalar_total(p_owner uuid, p_factor numeric default 1) returns numeric
language sql security definer set search_path = '' as $$
  select sum(amount) * p_factor from public."Mixed Case" where "Owner Id" = p_owner
$$;
create function public.out_params(p_owner uuid, out total numeric, out n integer)
language sql security definer set search_path = '' as $$
  select sum(amount), count(*)::int from public."Mixed Case" where "Owner Id" = p_owner
$$;
-- Changes a row by id with no ownership check. Its argument cannot be guessed from the name.
create function public.bump(p_id bigint) returns void
language sql security definer set search_path = '' as $$
  update public."Mixed Case" set amount = amount + 1 where "Id" = p_id
$$;
create function public.raises(p_user uuid) returns integer language plpgsql security invoker as $$
begin raise exception 'not for you'; end $$;
create function public.variadic_fn(variadic ids uuid[]) returns integer language sql security invoker as $$ select cardinality(ids) $$;
create function public.poly(x anyelement) returns anyelement language sql security invoker as $$ select x $$;
create function public.safe_ids() returns setof bigint language sql stable security invoker as $$
  select "Id" from public."Mixed Case" order by 1
$$;
