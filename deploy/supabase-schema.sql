-- ============================================================
-- AgentGuard — Supabase (PostgreSQL) schema
-- Run this in the Supabase SQL Editor, or via:
--   psql "$SUPABASE_DB_URL" -f deploy/supabase-schema.sql
--
-- Matches internal/database/database.go exactly:
--   table:   audit_logs
--   columns: session_id, method, payload, status, created_at
--   auth:    SUPABASE_URL + SUPABASE_KEY env vars (service role key)
-- ============================================================

create extension if not exists "pgcrypto";

-- --------------------------------------------------------------
-- audit_logs: one row per intercepted tool call, written by
-- AsyncLogger.sendLogToSupabase() via the REST API (POST /rest/v1/audit_logs)
-- --------------------------------------------------------------
create table if not exists audit_logs (
    id           uuid primary key default gen_random_uuid(),
    session_id   text not null,
    method       text not null,
    payload      text,                -- redacted JSON-RPC params, stored as text
    status       text not null,
    created_at   timestamptz not null default now()
);

create index if not exists idx_audit_logs_session_id
    on audit_logs (session_id);

create index if not exists idx_audit_logs_created_at
    on audit_logs (created_at desc);

create index if not exists idx_audit_logs_status
    on audit_logs (status);

-- --------------------------------------------------------------
-- sessions: rollup table for dashboard summaries. Not written
-- directly by the Go backend — kept in sync via the trigger below
-- whenever a new audit_logs row lands.
-- --------------------------------------------------------------
create table if not exists sessions (
    id            text primary key,
    first_seen_at timestamptz not null default now(),
    last_seen_at  timestamptz not null default now(),
    call_count    integer not null default 0,
    trip_count    integer not null default 0
);

create or replace function agentguard_touch_session()
returns trigger as $$
begin
    insert into sessions (id, first_seen_at, last_seen_at, call_count, trip_count)
    values (
        new.session_id,
        now(),
        now(),
        1,
        case when new.status = 'TRIPPED_CIRCUIT_BREAKER' then 1 else 0 end
    )
    on conflict (id) do update
    set last_seen_at = now(),
        call_count   = sessions.call_count + 1,
        trip_count   = sessions.trip_count + case when new.status = 'TRIPPED_CIRCUIT_BREAKER' then 1 else 0 end;
    return new;
end;
$$ language plpgsql;

drop trigger if exists trg_touch_session on audit_logs;
create trigger trg_touch_session
    after insert on audit_logs
    for each row
    execute function agentguard_touch_session();

-- --------------------------------------------------------------
-- Row Level Security
-- The Go backend writes using the service role key (SUPABASE_KEY),
-- which bypasses RLS entirely. These policies only matter if you
-- later expose Supabase directly to the browser via the anon key.
-- Locked down by default — no policies means no anon/authenticated access.
-- --------------------------------------------------------------
alter table audit_logs enable row level security;
alter table sessions enable row level security;