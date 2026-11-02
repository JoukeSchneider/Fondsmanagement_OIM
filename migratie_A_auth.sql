-- Migratie A: rollen + policies voor ingelogde gebruikers (niet-brekend; anon-toegang blijft tot migratie B)
create table if not exists public.app_users (
  email text primary key check (email = lower(email)),
  role text not null default 'viewer' check (role in ('viewer','importer')),
  created_at timestamptz not null default now()
);
alter table public.app_users enable row level security;

create or replace function public.is_member() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.app_users u
                 where u.email = lower(coalesce(auth.jwt()->>'email','')));
$$;
create or replace function public.is_importer() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.app_users u
                 where u.email = lower(coalesce(auth.jwt()->>'email','')) and u.role = 'importer');
$$;
revoke all on function public.is_member(), public.is_importer() from public, anon;
grant execute on function public.is_member(), public.is_importer() to authenticated;

drop policy if exists app_users_read_own on public.app_users;
create policy app_users_read_own on public.app_users for select to authenticated
  using (email = lower(coalesce(auth.jwt()->>'email','')));

do $$
declare t text;
begin
  for t in select unnest(array['argus_line_map','assets','assumptions','covenants','funds','gl_account_map',
    'gl_balances','imports','kpi_definitions','kpi_values','leases','loans','nav_history','parking_tariffs',
    'portfolios','qpark_operational','qpark_subscriptions','report_narratives','report_snapshots',
    'scenario_cashflows','scenarios','turnover_rent_thresholds'])
  loop
    execute format('drop policy if exists members_read on public.%I', t);
    execute format('drop policy if exists importers_write on public.%I', t);
    execute format('create policy members_read on public.%I for select to authenticated using ((select public.is_member()))', t);
    execute format('create policy importers_write on public.%I for all to authenticated using ((select public.is_importer())) with check ((select public.is_importer()))', t);
  end loop;
end $$;

drop policy if exists imports_raw_member_select on storage.objects;
drop policy if exists imports_raw_importer_insert on storage.objects;
drop policy if exists imports_raw_importer_update on storage.objects;
create policy imports_raw_member_select on storage.objects for select to authenticated
  using (bucket_id = 'imports-raw' and (select public.is_member()));
create policy imports_raw_importer_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'imports-raw' and (select public.is_importer()));
create policy imports_raw_importer_update on storage.objects for update to authenticated
  using (bucket_id = 'imports-raw' and (select public.is_importer()))
  with check (bucket_id = 'imports-raw' and (select public.is_importer()));

alter function public.prevent_published_snapshot_change() set search_path = '';
alter function public.set_updated_at() set search_path = '';

insert into public.app_users(email, role) values
  ('r.kuiper@orangeim.nl','importer'),
  ('j.schneider@orangeim.nl','importer'),
  ('m.gerritsen@orangeim.nl','viewer'),
  ('f.prins@orangeim.nl','viewer')
on conflict (email) do update set role = excluded.role;
