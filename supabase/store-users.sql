-- ============================================================
-- COPCLICK Hub — Login de tienda (código de acceso + usuarios internos)
-- Correr en el Supabase del ECOSISTEMA (xpglkncnekmcpxpeaznk) → SQL Editor.
-- Tablas internas del Hub: RLS activo, sin políticas (solo la service_role).
-- ============================================================

-- Código de acceso por tienda (de por vida). Vincula la Core del cliente a su tienda.
alter table public.print_clients add column if not exists access_code text unique;

-- Usuarios internos de cada tienda (los crea el propio dueño). 1º usuario = admin.
create table if not exists public.store_users (
  id            uuid primary key default gen_random_uuid(),
  client_id     uuid not null references public.print_clients(id) on delete cascade,
  name          text not null,
  password_hash text not null,                 -- scrypt (salt:hash) — nunca la contraseña plana
  role          text not null default 'user',  -- 'admin' | 'user'
  created_at    timestamptz not null default now(),
  unique (client_id, name)
);
alter table public.store_users enable row level security;

-- Código de acceso para PARADISE (dáselo al dueño para entrar a "Tienda"):
update public.print_clients
set access_code = 'PDX-4M9K2F7Q'
where name = 'Paradise';
