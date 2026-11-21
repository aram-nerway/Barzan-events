-- BARZAN EVENTS: run this whole file once in Supabase > SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create or replace function public.is_barzan_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.admin_users
    where user_id = auth.uid()
  );
$$;
revoke all on function public.is_barzan_admin() from public;
grant execute on function public.is_barzan_admin() to authenticated;

create table if not exists public.decor_items (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  category text not null,
  image_url text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.bookings (
  id uuid primary key default gen_random_uuid(),
  customer_name text not null,
  phone text not null,
  event_date date not null,
  event_type text not null,
  decor_name text not null default 'Not selected',
  notes text not null default '',
  status text not null default 'pending' check (status in ('pending','confirmed','cancelled')),
  created_at timestamptz not null default now()
);

-- One active event per date. Cancelled requests release the date.
create unique index if not exists bookings_one_active_event_per_day
on public.bookings(event_date)
where status in ('pending','confirmed');

alter table public.admin_users enable row level security;
alter table public.decor_items enable row level security;
alter table public.bookings enable row level security;

-- SQL privileges are granted here; RLS policies below still decide which rows are visible or writable.
grant select on public.decor_items to anon, authenticated;
grant insert on public.decor_items to authenticated;
grant update, delete on public.decor_items to authenticated;
grant insert on public.bookings to anon, authenticated;
grant select, update, delete on public.bookings to authenticated;
grant select on public.admin_users to authenticated;

-- Admins can verify their own account; the security-definer helper avoids RLS recursion.
drop policy if exists "Admins can read own admin row" on public.admin_users;
create policy "Admins can read own admin row" on public.admin_users
for select to authenticated using (user_id = auth.uid());

-- Anyone can see the decor gallery. Only admins can manage it.
drop policy if exists "Anyone can view decor" on public.decor_items;
create policy "Anyone can view decor" on public.decor_items
for select to anon, authenticated using (true);
drop policy if exists "Admins manage decor" on public.decor_items;
create policy "Admins manage decor" on public.decor_items
for all to authenticated using (public.is_barzan_admin()) with check (public.is_barzan_admin());

-- Visitors may submit a pending booking, but cannot read customer records.
drop policy if exists "Visitors can request bookings" on public.bookings;
create policy "Visitors can request bookings" on public.bookings
for insert to anon, authenticated
with check (status = 'pending');
drop policy if exists "Admins read bookings" on public.bookings;
create policy "Admins read bookings" on public.bookings
for select to authenticated using (public.is_barzan_admin());
drop policy if exists "Admins update bookings" on public.bookings;
create policy "Admins update bookings" on public.bookings
for update to authenticated using (public.is_barzan_admin()) with check (public.is_barzan_admin());
drop policy if exists "Admins delete bookings" on public.bookings;
create policy "Admins delete bookings" on public.bookings
for delete to authenticated using (public.is_barzan_admin());

-- Public calendar endpoint returns dates only, never customer names or phone numbers.
create or replace function public.get_booked_dates()
returns table(event_date date)
language sql
stable
security definer
set search_path = public
as $$
  select b.event_date
  from public.bookings b
  where b.status in ('pending','confirmed')
  order by b.event_date;
$$;
revoke all on function public.get_booked_dates() from public;
grant execute on function public.get_booked_dates() to anon, authenticated;

-- Public image bucket; only authenticated Barzan admins may upload or delete files.
insert into storage.buckets (id, name, public)
values ('decor-images', 'decor-images', true)
on conflict (id) do update set public = true;

drop policy if exists "Public can view Barzan decor images" on storage.objects;
create policy "Public can view Barzan decor images" on storage.objects
for select to anon, authenticated using (bucket_id = 'decor-images');
drop policy if exists "Admins upload Barzan decor images" on storage.objects;
create policy "Admins upload Barzan decor images" on storage.objects
for insert to authenticated with check (bucket_id = 'decor-images' and public.is_barzan_admin());
drop policy if exists "Admins delete Barzan decor images" on storage.objects;
create policy "Admins delete Barzan decor images" on storage.objects
for delete to authenticated using (bucket_id = 'decor-images' and public.is_barzan_admin());

-- Starter gallery images. Replace/add your real Barzan decor photos from the admin panel.
insert into public.decor_items (name, category, image_url)
select v.name, v.category, v.image_url
from (values
 ('Classic floral stage','Wedding stage','https://images.unsplash.com/photo-1519741497674-611481863552?auto=format&fit=crop&w=900&q=85'),
 ('Elegant white stage','Wedding stage','https://images.unsplash.com/photo-1464366400600-7168b8af9bc3?auto=format&fit=crop&w=900&q=85'),
 ('Floral entrance','Event road decor','https://images.unsplash.com/photo-1519225421980-715cb0215aed?auto=format&fit=crop&w=900&q=85'),
 ('Luxury table setting','Table styling','https://images.unsplash.com/photo-1519167758481-83f550bb49b3?auto=format&fit=crop&w=900&q=85'),
 ('Candlelight table','Table styling','https://images.unsplash.com/photo-1511795409834-ef04bbd61622?auto=format&fit=crop&w=900&q=85'),
 ('Birthday celebration','Other celebration','https://images.unsplash.com/photo-1530103862676-de8c9debad1d?auto=format&fit=crop&w=900&q=85')
) as v(name, category, image_url)
where not exists (select 1 from public.decor_items);
