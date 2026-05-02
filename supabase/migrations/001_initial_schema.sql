-- Soyons Serein MVP - Initial Database Schema

create extension if not exists "pgcrypto";

-- =========================
-- ENUM-LIKE CHECK VALUES
-- =========================

-- roles: senior | family
-- medication log status: pending | taken | missed
-- emergency type: caregiver | emergency_services
-- emergency status: initiated | cancelled | completed

-- =========================
-- PROFILES
-- =========================

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('senior', 'family')),
  full_name text not null,
  phone text,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- =========================
-- SENIOR PROFILES
-- =========================

create table if not exists public.senior_profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete set null,
  display_name text not null,
  birth_date date,
  notes text,
  created_at timestamptz not null default now()
);

alter table public.senior_profiles enable row level security;

-- =========================
-- FAMILY LINKS
-- =========================

create table if not exists public.family_links (
  id uuid primary key default gen_random_uuid(),
  senior_id uuid not null references public.senior_profiles(id) on delete cascade,
  family_user_id uuid not null references public.profiles(id) on delete cascade,
  relation text,
  is_primary boolean not null default false,
  created_at timestamptz not null default now(),
  unique (senior_id, family_user_id)
);

alter table public.family_links enable row level security;

-- =========================
-- EMERGENCY CONTACTS
-- =========================

create table if not exists public.emergency_contacts (
  id uuid primary key default gen_random_uuid(),
  senior_id uuid not null references public.senior_profiles(id) on delete cascade,
  name text not null,
  relation text,
  phone text not null,
  whatsapp_enabled boolean not null default true,
  priority integer not null default 1,
  created_at timestamptz not null default now()
);

alter table public.emergency_contacts enable row level security;

-- =========================
-- MEDICATIONS
-- =========================

create table if not exists public.medications (
  id uuid primary key default gen_random_uuid(),
  senior_id uuid not null references public.senior_profiles(id) on delete cascade,
  name text not null,
  dosage text,
  instructions text,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

alter table public.medications enable row level security;

-- =========================
-- MEDICATION SCHEDULES
-- =========================

create table if not exists public.medication_schedules (
  id uuid primary key default gen_random_uuid(),
  medication_id uuid not null references public.medications(id) on delete cascade,
  scheduled_time time not null,
  days_of_week integer[] not null default array[1,2,3,4,5,6,7],
  created_at timestamptz not null default now()
);

alter table public.medication_schedules enable row level security;

-- =========================
-- MEDICATION LOGS
-- =========================

create table if not exists public.medication_logs (
  id uuid primary key default gen_random_uuid(),
  senior_id uuid not null references public.senior_profiles(id) on delete cascade,
  medication_id uuid references public.medications(id) on delete set null,
  schedule_id uuid references public.medication_schedules(id) on delete set null,
  scheduled_for timestamptz,
  status text not null check (status in ('pending', 'taken', 'missed')),
  confirmed_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.medication_logs enable row level security;

-- =========================
-- EMERGENCY EVENTS
-- =========================

create table if not exists public.emergency_events (
  id uuid primary key default gen_random_uuid(),
  senior_id uuid not null references public.senior_profiles(id) on delete cascade,
  type text not null check (type in ('caregiver', 'emergency_services')),
  status text not null check (status in ('initiated', 'cancelled', 'completed')),
  triggered_at timestamptz not null default now()
);

alter table public.emergency_events enable row level security;

-- =========================
-- DEVICE TOKENS
-- =========================

create table if not exists public.device_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  token text not null,
  platform text,
  created_at timestamptz not null default now(),
  unique (user_id, token)
);

alter table public.device_tokens enable row level security;

-- =========================
-- PAIRING CODES
-- =========================

create table if not exists public.pairing_codes (
  id uuid primary key default gen_random_uuid(),
  senior_id uuid not null references public.senior_profiles(id) on delete cascade,
  code text not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.pairing_codes enable row level security;

-- =========================
-- INDEXES
-- =========================

create index if not exists idx_profiles_role on public.profiles(role);
create index if not exists idx_senior_profiles_user_id on public.senior_profiles(user_id);
create index if not exists idx_family_links_senior_id on public.family_links(senior_id);
create index if not exists idx_family_links_family_user_id on public.family_links(family_user_id);
create index if not exists idx_emergency_contacts_senior_id on public.emergency_contacts(senior_id);
create index if not exists idx_medications_senior_id on public.medications(senior_id);
create index if not exists idx_medication_schedules_medication_id on public.medication_schedules(medication_id);
create index if not exists idx_medication_logs_senior_id on public.medication_logs(senior_id);
create index if not exists idx_medication_logs_status on public.medication_logs(status);
create index if not exists idx_emergency_events_senior_id on public.emergency_events(senior_id);
create index if not exists idx_device_tokens_user_id on public.device_tokens(user_id);
create index if not exists idx_pairing_codes_code on public.pairing_codes(code);

-- =========================
-- SECURITY HELPER FUNCTIONS
-- =========================

create or replace function public.is_linked_family(target_senior_id uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.family_links fl
    where fl.senior_id = target_senior_id
      and fl.family_user_id = auth.uid()
  );
$$;

create or replace function public.is_senior_owner(target_senior_id uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.senior_profiles sp
    where sp.id = target_senior_id
      and sp.user_id = auth.uid()
  );
$$;

-- =========================
-- RLS POLICIES
-- =========================

-- PROFILES
create policy "Users can read own profile"
on public.profiles
for select
using (id = auth.uid());

create policy "Users can update own profile"
on public.profiles
for update
using (id = auth.uid());

create policy "Users can insert own profile"
on public.profiles
for insert
with check (id = auth.uid());

-- SENIOR PROFILES
create policy "Senior owner can read senior profile"
on public.senior_profiles
for select
using (public.is_senior_owner(id));

create policy "Linked family can read senior profile"
on public.senior_profiles
for select
using (public.is_linked_family(id));

create policy "Family can create senior profile"
on public.senior_profiles
for insert
with check (true);

create policy "Linked family can update senior profile"
on public.senior_profiles
for update
using (public.is_linked_family(id));

-- FAMILY LINKS
create policy "Family can read own links"
on public.family_links
for select
using (family_user_id = auth.uid());

create policy "Family can create links"
on public.family_links
for insert
with check (family_user_id = auth.uid());

create policy "Family can update own links"
on public.family_links
for update
using (family_user_id = auth.uid());

-- EMERGENCY CONTACTS
create policy "Linked users can read emergency contacts"
on public.emergency_contacts
for select
using (
  public.is_linked_family(senior_id)
  or public.is_senior_owner(senior_id)
);

create policy "Linked family can manage emergency contacts"
on public.emergency_contacts
for all
using (public.is_linked_family(senior_id))
with check (public.is_linked_family(senior_id));

-- MEDICATIONS
create policy "Linked users can read medications"
on public.medications
for select
using (
  public.is_linked_family(senior_id)
  or public.is_senior_owner(senior_id)
);

create policy "Linked family can manage medications"
on public.medications
for all
using (public.is_linked_family(senior_id))
with check (public.is_linked_family(senior_id));

-- MEDICATION SCHEDULES
create policy "Linked users can read medication schedules"
on public.medication_schedules
for select
using (
  exists (
    select 1
    from public.medications m
    where m.id = medication_id
      and (
        public.is_linked_family(m.senior_id)
        or public.is_senior_owner(m.senior_id)
      )
  )
);

create policy "Linked family can manage medication schedules"
on public.medication_schedules
for all
using (
  exists (
    select 1
    from public.medications m
    where m.id = medication_id
      and public.is_linked_family(m.senior_id)
  )
)
with check (
  exists (
    select 1
    from public.medications m
    where m.id = medication_id
      and public.is_linked_family(m.senior_id)
  )
);

-- MEDICATION LOGS
create policy "Linked users can read medication logs"
on public.medication_logs
for select
using (
  public.is_linked_family(senior_id)
  or public.is_senior_owner(senior_id)
);

create policy "Senior can insert own medication logs"
on public.medication_logs
for insert
with check (public.is_senior_owner(senior_id));

create policy "Linked family can insert medication logs"
on public.medication_logs
for insert
with check (public.is_linked_family(senior_id));

create policy "Linked users can update medication logs"
on public.medication_logs
for update
using (
  public.is_linked_family(senior_id)
  or public.is_senior_owner(senior_id)
);

-- EMERGENCY EVENTS
create policy "Linked users can read emergency events"
on public.emergency_events
for select
using (
  public.is_linked_family(senior_id)
  or public.is_senior_owner(senior_id)
);

create policy "Senior can create emergency events"
on public.emergency_events
for insert
with check (public.is_senior_owner(senior_id));

create policy "Linked family can create emergency events"
on public.emergency_events
for insert
with check (public.is_linked_family(senior_id));

-- DEVICE TOKENS
create policy "Users can manage own device tokens"
on public.device_tokens
for all
using (user_id = auth.uid())
with check (user_id = auth.uid());

-- PAIRING CODES
create policy "Linked family can manage pairing codes"
on public.pairing_codes
for all
using (public.is_linked_family(senior_id))
with check (public.is_linked_family(senior_id));

create policy "Anyone authenticated can read valid pairing code"
on public.pairing_codes
for select
using (
  auth.uid() is not null
  and used_at is null
  and expires_at > now()
);