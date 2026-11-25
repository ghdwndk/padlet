-- MINDLET migration.sql : 기존 DB 변경용 (데이터 보존)
--
-- 적용 전제조건
--   1. Supabase 대시보드에서 백업(또는 Point-in-time recovery)을 확인했습니다.
--   2. 아래 [STEP 0] 확인 쿼리를 먼저 실행해 실제 구조를 확인했습니다.
--   3. 앱 테이블은 public.memos 이며, 암호 해시가 있었다면 public.memos.password_hash 컬럼에 있습니다.
--      (구조가 다르면 실행하지 말고 STEP 0 결과를 기준으로 이 파일을 수정하세요.)
--   4. 테스트(복제) DB에서 먼저 실행하는 것을 권장합니다.
--
-- anon / authenticated / service_role 은 Postgres 역할 이름이며 레거시 API 키 이름이 아닙니다.
-- 이 파일은 public.memos, memo_credentials, admin_sessions, rate_limits 와 앱 함수만 변경합니다.

-- ===== [STEP 0] 확인 쿼리 (읽기 전용, 먼저 단독 실행) =====
-- select column_name, data_type, is_nullable, column_default
--   from information_schema.columns where table_schema = 'public' and table_name = 'memos' order by ordinal_position;
-- select conname, pg_get_constraintdef(oid) from pg_constraint where conrelid = 'public.memos'::regclass;
-- select policyname, cmd, roles from pg_policies where schemaname = 'public' and tablename in ('memos','memo_credentials');
-- select grantee, privilege_type from information_schema.role_table_grants where table_schema = 'public' and table_name in ('memos','memo_credentials');
-- select count(*) as memos, count(password_hash) as with_hash from public.memos;   -- password_hash 컬럼이 있을 때만
-- select proname, prosecdef, pg_get_function_arguments(oid) from pg_proc where pronamespace = 'public'::regnamespace;

begin;

create extension if not exists pgcrypto;

-- ===== [STEP 1] 필요한 컬럼과 비공개 테이블 생성 =====

alter table public.memos add column if not exists color text not null default '#fef3c7';
alter table public.memos add column if not exists position integer not null default 0;
alter table public.memos add column if not exists created_at timestamptz not null default now();
alter table public.memos add column if not exists updated_at timestamptz not null default now();
alter table public.memos alter column color set default '#fef3c7';

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

-- ===== [STEP 2~4] 해시 이전, 누락·중복 검증, 공개 테이블 해시 제거 =====

do $$
declare
  missing_count integer;
  moved_count integer;
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'memos' and column_name = 'password_hash'
  ) then
    -- 이전: 기존 해시를 그대로 복사 (이미 이전된 행은 건드리지 않음)
    execute $q$
      insert into public.memo_credentials (memo_id, password_hash)
      select id, password_hash from public.memos
      where password_hash is not null and password_hash <> ''
      on conflict (memo_id) do nothing
    $q$;

    -- 누락 검증: 해시가 있었는데 이전되지 않은 메모가 있으면 중단(전체 롤백)
    execute $q$
      select count(*) from public.memos m
      where m.password_hash is not null and m.password_hash <> ''
        and not exists (select 1 from public.memo_credentials c where c.memo_id = m.id)
    $q$ into missing_count;
    if missing_count > 0 then
      raise exception 'Migration aborted: % memos have no migrated credentials', missing_count;
    end if;

    -- 해시가 원래 없던 메모는 암호 없이 삭제 불가가 되므로 알림만 남김
    select count(*) into moved_count from public.memo_credentials;
    raise notice 'memo_credentials rows after migration: %', moved_count;

    -- 해시 값 일치 검증 후 공개 테이블에서 제거 (NOT NULL 등 기존 제약도 함께 사라짐)
    execute $q$
      select count(*) from public.memos m
      join public.memo_credentials c on c.memo_id = m.id
      where m.password_hash is not null and m.password_hash <> c.password_hash
    $q$ into missing_count;
    if missing_count > 0 then
      raise exception 'Migration aborted: % credential hashes differ', missing_count;
    end if;

    alter table public.memos drop column password_hash;
  end if;
end;
$$;

-- 기존 데이터를 거부하지 않도록 NOT VALID 로 길이 제약 추가 (신규 쓰기에는 적용)
do $$
begin
  if not exists (select 1 from pg_constraint where conrelid = 'public.memos'::regclass and conname = 'memos_title_length_chk') then
    alter table public.memos add constraint memos_title_length_chk
      check (char_length(title) between 1 and 80) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conrelid = 'public.memos'::regclass and conname = 'memos_content_length_chk') then
    alter table public.memos add constraint memos_content_length_chk
      check (char_length(content) between 1 and 2000) not valid;
  end if;
end;
$$;

create index if not exists memos_created_at_idx on public.memos (created_at desc);
create index if not exists memos_position_idx on public.memos (position asc, created_at desc);
create index if not exists admin_sessions_expires_at_idx on public.admin_sessions (expires_at);

-- ===== [STEP 5] 트리거와 서버 전용 함수 =====

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

-- 기존 SECURITY DEFINER 버전을 SECURITY INVOKER 버전으로 교체
drop function if exists public.create_memo_with_credentials(text, text, text, text);

create function public.create_memo_with_credentials(
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

-- ===== [STEP 6] RLS, 기존 정책 제거, GRANT 재설정 =====

alter table public.memos enable row level security;
alter table public.memo_credentials enable row level security;
alter table public.admin_sessions enable row level security;
alter table public.rate_limits enable row level security;

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

commit;

-- ===== [STEP 7] 적용 후 검증 (읽기 전용) =====
-- select count(*) from public.memos;                                  -- 이전과 동일한지
-- select count(*) from public.memo_credentials;                       -- 해시가 있던 메모 수와 동일한지
-- select column_name from information_schema.columns where table_name = 'memos' and column_name = 'password_hash'; -- 0행
-- select tablename, rowsecurity from pg_tables where schemaname = 'public' and tablename in ('memos','memo_credentials','admin_sessions','rate_limits');
-- select policyname, tablename from pg_policies where schemaname = 'public';
