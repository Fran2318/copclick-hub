-- ============================================================
-- COPCLICK Hub — Esquema (va en el Supabase del ECOSISTEMA: xpglkncnekmcpxpeaznk)
-- Estas tablas son INTERNAS del Hub: solo las lee/escribe el backend con la
-- service_role key. Por eso: RLS activado y SIN políticas (nadie más entra),
-- y NO se agregan a Realtime.
-- ============================================================

-- Clientes/tiendas del ecosistema COPCLICK
create table if not exists public.print_clients (
  id                 uuid primary key default gen_random_uuid(),
  name               text not null,                  -- "Paradise"
  token_hash         text not null unique,           -- sha256 del token (NO el token plano)
  status             text not null default 'active', -- 'active' | 'blocked'
  store_name         text,                           -- default para el ticket
  store_web          text,                           -- "paradisemoda.com"
  -- Credenciales de LECTURA del Supabase de la tienda (para la ingesta por Realtime).
  -- Server-side only. (A futuro: mover a Supabase Vault.)
  store_supabase_url text,
  store_service_key  text,
  created_at         timestamptz not null default now(),
  last_seen_at       timestamptz
);

-- Cola de impresiones (no perder tickets si el agente está offline)
create table if not exists public.print_jobs (
  id          uuid primary key default gen_random_uuid(),
  client_id   uuid not null references public.print_clients(id) on delete cascade,
  order_ref   text,                                  -- order_number (trazabilidad)
  payload     jsonb not null,                        -- el new_order.data
  status      text not null default 'pending',       -- 'pending'|'sent'|'printed'|'error'
  created_at  timestamptz not null default now(),
  printed_at  timestamptz,
  error       text
);
create index if not exists idx_print_jobs_client_status on public.print_jobs (client_id, status);

-- Blindaje: RLS activado, sin políticas (solo la service_role del Hub accede).
alter table public.print_clients enable row level security;
alter table public.print_jobs    enable row level security;
