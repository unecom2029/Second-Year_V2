-- Run once in the Supabase SQL Editor before enabling the Cloudflare sign-in.
-- The public browser key can only read the signed-in student's own approval row.
create table public.study_hub_approved_emails (
  email text primary key,
  display_name text not null,
  created_at timestamptz not null default now(),
  constraint study_hub_approved_email_format check (email = lower(email) and email ~ '^[^@[:space:]]+@une\.edu$')
);

alter table public.study_hub_approved_emails enable row level security;
revoke all on public.study_hub_approved_emails from anon, authenticated;
grant select on public.study_hub_approved_emails to authenticated;

create policy "Students can read only their own approval"
on public.study_hub_approved_emails for select to authenticated
using (email = lower(auth.jwt() ->> 'email'));

-- Each student's durable identity is the Supabase Auth UUID, never an email or browser key.
-- Reserved for later progress synchronization; Phase 1 does not write quiz data.
create table public.study_hub_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.study_hub_profiles enable row level security;
revoke all on public.study_hub_profiles from anon, authenticated;
grant select, insert, update on public.study_hub_profiles to authenticated;

create policy "Students can read their own profile"
on public.study_hub_profiles for select to authenticated
using (
  user_id = (select auth.uid())
  and exists (select 1 from public.study_hub_approved_emails where email = lower(auth.jwt() ->> 'email'))
);

create policy "Approved students can create their own profile"
on public.study_hub_profiles for insert to authenticated
with check (
  user_id = (select auth.uid())
  and email = lower(auth.jwt() ->> 'email')
  and exists (select 1 from public.study_hub_approved_emails where email = lower(auth.jwt() ->> 'email'))
);

create policy "Approved students can update their own profile"
on public.study_hub_profiles for update to authenticated
using (
  user_id = (select auth.uid())
  and exists (select 1 from public.study_hub_approved_emails where email = lower(auth.jwt() ->> 'email'))
)
with check (user_id = (select auth.uid()) and email = lower(auth.jwt() ->> 'email'));

-- Initial approvals copied from the existing Study Hub list. Review before running.
insert into public.study_hub_approved_emails (email, display_name) values
  ('ahjort@une.edu', 'Abigail Hjort'),
  ('agerges@une.edu', 'Alexandra Gerges'),
  ('ameza1@une.edu', 'Andrea Meza'),
  ('aonorati@une.edu', 'Angelique Onorati'),
  ('opate@une.edu', 'Art Pate'),
  ('bkhaghani@une.edu', 'Benjamin Khaghani'),
  ('bafzal@une.edu', 'Bilal Afzal'),
  ('cboudreau3@une.edu', 'Callum Boudreau'),
  ('cnguon@une.edu', 'Cheng Nguon'),
  ('cheim@une.edu', 'Claudia Heim'),
  ('cguan@une.edu', 'Cindy Guan'),
  ('deverly@une.edu', 'David Everly'),
  ('esimpson8@une.edu', 'Elyssa Simpson'),
  ('hnaeem@une.edu', 'Haad Naeem'),
  ('naeemh@une.edu', 'Haad Naeem'),
  ('hbledsoe@une.edu', 'Hannah Bledsoe'),
  ('hatif@une.edu', 'Haris Atif'),
  ('jbatson2@une.edu', 'Jonathan Batson'),
  ('jmehta@une.edu', 'Jeevs'),
  ('kboyle8@une.edu', 'Kailey Boyle'),
  ('kboateng@une.edu', 'Kofi Boateng'),
  ('lphung1@une.edu', 'Landon'),
  ('lli3@une.edu', 'Linghua Li'),
  ('lpham5@une.edu', 'Linh Pham'),
  ('mnguyen23@une.edu', 'Marina Nguyen'),
  ('mtanega@une.edu', 'Maya Tanega'),
  ('mlong20@une.edu', 'Meghan Long'),
  ('nehtesham@une.edu', 'Nahian Ehtesham'),
  ('oriveravazquez@une.edu', 'Omaira Rivera Vazquez'),
  ('pabdulakbar@une.edu', 'Princess Maryam Abdul-Akbar'),
  ('rwolfe4@une.edu', 'Rachael Wolfe'),
  ('jgraber@une.edu', 'Remi Graber'),
  ('rfeng1@une.edu', 'Roxanne Feng'),
  ('ssalhi@une.edu', 'Sirine Salhi'),
  ('smukherjee@une.edu', 'Sohini Mukherjee')
on conflict (email) do nothing;
