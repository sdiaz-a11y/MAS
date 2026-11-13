-- MAS · Etiquetas en las fotos y notificaciones.
-- Pégalo en SQL Editor y ejecútalo UNA vez (se puede repetir sin problema). Hazlo ANTES de publicar la versión nueva de la app.
--
--  1) Las fotos guardan a quién se etiquetó (etiquetados).
--  2) La lista de miembros registrados que la app sugiere al escribir un nombre.
--  3) Notificaciones: al etiquetar a alguien en una foto, a esa persona le llega un aviso (la campana de la barra).
--     Cada quien ve y gestiona solo las suyas. Las crea un disparador de la base, no el navegador.

-- ---------- 1) etiquetas en las fotos ----------
alter table public.fotos add column if not exists etiquetados uuid[] not null default '{}';

-- ---------- 2) miembros que se pueden etiquetar ----------
create or replace function public.miembros_etiquetables() returns table(id uuid, nombre text)
language sql security definer stable set search_path = public as $$
  select p.id, p.nombre from public.profiles p
   where p.estado = 'aprobado' and p.nombre <> '' and public.is_member()
   order by p.nombre;
$$;
revoke execute on function public.miembros_etiquetables() from public, anon;
grant  execute on function public.miembros_etiquetables() to authenticated;

-- ---------- 3) notificaciones ----------
create table if not exists public.notificaciones (
  id        bigint generated always as identity primary key,
  user_id   uuid not null references auth.users(id) on delete cascade,   -- a quién le llega
  tipo      text not null default 'etiqueta',
  foto_id   bigint references public.fotos(id) on delete cascade,
  de_nombre text not null default '',                                     -- quién lo hizo
  entrega   int,
  detalle   text not null default '',                                     -- descripción de la foto
  leida     boolean not null default false,
  creado    timestamptz not null default now()
);
create index if not exists notif_user on public.notificaciones (user_id, creado desc);
alter table public.notificaciones enable row level security;
drop policy if exists "notif propias ver"    on public.notificaciones;
drop policy if exists "notif propias marcar" on public.notificaciones;
drop policy if exists "notif propias borrar" on public.notificaciones;
create policy "notif propias ver"    on public.notificaciones for select to authenticated using (user_id = auth.uid());
create policy "notif propias marcar" on public.notificaciones for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "notif propias borrar" on public.notificaciones for delete to authenticated using (user_id = auth.uid());
-- sin política de insert: solo las crea el disparador de abajo

-- al etiquetar a alguien (o agregarlo después), le llega la notificación; a uno mismo no
create or replace function public.fotos_notifica() returns trigger
language plpgsql security definer set search_path = public as $$
declare quien text; viejos uuid[] := '{}';
begin
  if tg_op = 'UPDATE' then viejos := coalesce(old.etiquetados, '{}'); end if;
  select nombre into quien from public.profiles where id = auth.uid();
  insert into public.notificaciones(user_id, tipo, foto_id, de_nombre, entrega, detalle)
  select u, 'etiqueta', new.id, coalesce(quien, ''), new.entrega, left(new.titulo, 120)
    from unnest(coalesce(new.etiquetados, '{}')) as u
   where u is distinct from auth.uid()
     and not (u = any(viejos))
     and exists (select 1 from public.profiles p where p.id = u and p.estado = 'aprobado');
  return new;
end $$;
revoke execute on function public.fotos_notifica() from public, anon, authenticated;
drop trigger if exists fotos_notifica on public.fotos;
create trigger fotos_notifica after insert or update of etiquetados on public.fotos
  for each row execute function public.fotos_notifica();

-- avisos en vivo (sin recargar la página)
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'notificaciones') then
    alter publication supabase_realtime add table public.notificaciones;
  end if;
end $$;
