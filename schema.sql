-- MINDLET schema.sql : 신규 빈 DB 전용 (샘플 데이터 없음)
-- 기존 데이터가 있는 DB에는 migration.sql 을 사용하세요.
-- 주의: anon / authenticated / service_role 은 Postgres 역할 이름이며 레거시 API 키 이름이 아닙니다.

create extension if not exists pgcrypto;

-- 1. 테이블 ---------------------------------------------------------------

create table if not exists public.memos (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 80),
  content text not null check (char_length(content) between 1 and 2000),
  color text not null default '#fef3c7' check (char_length(color) > 0),
  position integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.memo_credentials (
  memo_id uuid primary key references public.memos(id) on delete cascade,
  password_hash text not null
);

create table if not exists public.admin_sessions (
  token_hash text primary key,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists public.rate_limits (
  key text primary key,
  window_start timestamptz not null default now(),
  hits integer not null default 0
);

create index if not exists memos_created_at_idx on public.memos (created_at desc);
create index if not exists memos_position_idx on public.memos (position asc, created_at desc);
create index if not exists admin_sessions_expires_at_idx on public.admin_sessions (expires_at);

-- 2. 트리거 ---------------------------------------------------------------

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists memos_set_updated_at on public.memos;
create trigger memos_set_updated_at
before update on public.memos
for each row
execute function public.set_updated_at();

-- 3. 서버 전용 RPC (SECURITY INVOKER: service_role 의 테이블 권한으로만 실행) -----

create or replace function public.create_memo_with_credentials(
  p_title text,
  p_content text,
  p_password_hash text,
  p_color text default '#fef3c7'
)
returns public.memos
language plpgsql
set search_path = public
as $$
declare
  inserted_memo public.memos;
begin
  if char_length(p_title) < 1 or char_length(p_title) > 80 then
    raise exception 'Invalid title length';
  end if;

  if char_length(p_content) < 1 or char_length(p_content) > 2000 then
    raise exception 'Invalid content length';
  end if;

  if char_length(p_password_hash) < 50 then
    raise exception 'Invalid password hash';
  end if;

  insert into public.memos (title, content, color, position, created_at, updated_at)
  values (p_title, p_content, coalesce(nullif(p_color, ''), '#fef3c7'), 0, now(), now())
  returning * into inserted_memo;

  insert into public.memo_credentials (memo_id, password_hash)
  values (inserted_memo.id, p_password_hash);

  return inserted_memo;
end;
$$;

-- 원자적 고정 윈도우 카운터. 허용되면 true, 한도 초과면 false.
create or replace function public.rate_limit_hit(
  p_key text,
  p_limit integer,
  p_window_seconds integer
)
returns boolean
language plpgsql
set search_path = public
as $$
declare
  current_hits integer;
begin
  insert into public.rate_limits as r (key, window_start, hits)
  values (p_key, now(), 1)
  on conflict (key) do update
  set hits = case
        when r.window_start + make_interval(secs => p_window_seconds) <= now() then 1
        else r.hits + 1
      end,
      window_start = case
        when r.window_start + make_interval(secs => p_window_seconds) <= now() then now()
        else r.window_start
      end
  returning r.hits into current_hits;

  if random() < 0.01 then
    delete from public.rate_limits where window_start < now() - interval '1 day';
  end if;

  return current_hits <= p_limit;
end;
$$;

-- 증가 없이 현재 한도 도달 여부만 확인 (실패 횟수 제한용).
create or replace function public.rate_limit_is_blocked(
  p_key text,
  p_limit integer,
  p_window_seconds integer
)
returns boolean
language sql
stable
set search_path = public
as $$
  select exists (
    select 1
    from public.rate_limits r
    where r.key = p_key
      and r.hits >= p_limit
      and r.window_start + make_interval(secs => p_window_seconds) > now()
  );
$$;

-- 4. RLS ------------------------------------------------------------------

alter table public.memos enable row level security;
alter table public.memo_credentials enable row level security;
alter table public.admin_sessions enable row level security;
alter table public.rate_limits enable row level security;

-- 기존 정책 제거 (허용 정책이 남아 있지 않도록)
do $$
declare
  pol record;
begin
  for pol in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in ('memos', 'memo_credentials', 'admin_sessions', 'rate_limits')
  loop
    execute format('drop policy %I on %I.%I', pol.policyname, pol.schemaname, pol.tablename);
  end loop;
end;
$$;

create policy "Public memos are readable"
on public.memos
for select
to anon, authenticated
using (true);
-- memo_credentials / admin_sessions / rate_limits 에는 일반 사용자용 정책을 만들지 않습니다.

-- 5. GRANT ----------------------------------------------------------------

revoke all on public.memos from anon, authenticated;
revoke all on public.memo_credentials from anon, authenticated;
revoke all on public.admin_sessions from anon, authenticated;
revoke all on public.rate_limits from anon, authenticated;

grant select on public.memos to anon, authenticated;

grant all on public.memos to service_role;
grant all on public.memo_credentials to service_role;
grant all on public.admin_sessions to service_role;
grant all on public.rate_limits to service_role;

revoke all on function public.create_memo_with_credentials(text, text, text, text) from public, anon, authenticated;
revoke all on function public.rate_limit_hit(text, integer, integer) from public, anon, authenticated;
revoke all on function public.rate_limit_is_blocked(text, integer, integer) from public, anon, authenticated;
revoke all on function public.set_updated_at() from public, anon, authenticated;

grant execute on function public.create_memo_with_credentials(text, text, text, text) to service_role;
grant execute on function public.rate_limit_hit(text, integer, integer) to service_role;
grant execute on function public.rate_limit_is_blocked(text, integer, integer) to service_role;
