-- MAS · Datos del portal (notas, galería, apuntes, plan de acción, recursos, generaciones).
-- ORDEN: schema.sql → password_reset.sql → fechas.sql → este archivo. Se puede volver a correr sin perder datos.
--
-- Quién ve qué:
--   generaciones, fotos, recursos → los ven todos los miembros.
--   Fotos: las sube cualquier miembro (cada quien edita/borra las suyas; el admin, todas).
--   Recursos: los gestiona el admin; los de tipo 'notas' son el cuaderno de cada entrega y salen en la pestaña Notas.
--   apuntes, plan_acciones  → privados: cada quien ve, edita y borra solo lo suyo.
--   Storage (galeria, recursos) → buckets privados: leen los miembros; en recursos escribe el admin y en galeria cada miembro su carpeta.

create or replace function public.is_member() returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.profiles where id = auth.uid() and estado = 'aprobado');
$$;

-- ---------- generaciones ----------
create table if not exists public.generaciones (
  n       int primary key check (n > 0),
  anio    int not null,
  cerrada boolean not null default false,
  actual  boolean not null default false
);
create unique index if not exists generaciones_una_actual on public.generaciones (actual) where actual;
alter table public.generaciones enable row level security;
drop policy if exists "miembros ven generaciones" on public.generaciones;
drop policy if exists "admin edita generaciones"  on public.generaciones;
create policy "miembros ven generaciones" on public.generaciones for select to authenticated using (public.is_member());
create policy "admin edita generaciones"  on public.generaciones for all    to authenticated using (public.is_admin()) with check (public.is_admin());

insert into public.generaciones(n, anio, actual)
select 4, 2026, true where not exists (select 1 from public.generaciones);

-- cambia la generación actual (crea la fila si no existe); solo admin
create or replace function public.set_generacion_actual(p_n int, p_anio int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'no_autorizado'; end if;
  insert into public.generaciones(n, anio) values (p_n, p_anio) on conflict (n) do nothing;
  update public.generaciones set actual = false where actual and n <> p_n;
  update public.generaciones set actual = true where n = p_n;
end $$;
revoke execute on function public.set_generacion_actual(int, int) from public, anon;

-- nombres de los miembros aprobados (para etiquetar quién sale en cada foto)
create or replace function public.nombres_miembros() returns setof text
language sql security definer stable set search_path = public as $$
  select nombre from public.profiles where estado = 'aprobado' and public.is_member() order by nombre;
$$;
revoke execute on function public.nombres_miembros() from public, anon;

-- ---------- galería (compartida; archivos en el bucket 'galeria') ----------
create table if not exists public.fotos (
  id      bigint generated always as identity primary key,
  gen     int  not null references public.generaciones(n),
  entrega int  not null check (entrega between 1 and 12),
  titulo  text not null default 'Foto',
  nombres text[] not null default '{}',
  path    text not null,
  autor_id uuid default auth.uid() references auth.users(id) on delete set null,
  creado  timestamptz not null default now()
);
create index if not exists fotos_gen on public.fotos (gen, entrega);
alter table public.fotos enable row level security;
drop policy if exists "miembros ven fotos" on public.fotos;
drop policy if exists "admin edita fotos"  on public.fotos;
create policy "miembros ven fotos" on public.fotos for select to authenticated using (public.is_member());
create policy "admin edita fotos"  on public.fotos for all    to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "miembros suben fotos" on public.fotos;
drop policy if exists "autor edita fotos"    on public.fotos;
drop policy if exists "autor borra fotos"    on public.fotos;
create policy "miembros suben fotos" on public.fotos for insert to authenticated with check (public.is_member() and autor_id = auth.uid());
create policy "autor edita fotos"    on public.fotos for update to authenticated using (autor_id = auth.uid() and public.is_member()) with check (autor_id = auth.uid());
create policy "autor borra fotos"    on public.fotos for delete to authenticated using (autor_id = auth.uid() and public.is_member());

-- ---------- portadas de las entregas (imagen de cada tarjeta en Notas; el archivo va en el bucket galeria/portadas) ----------
create table if not exists public.entrega_portadas (
  gen     int  not null references public.generaciones(n),
  entrega int  not null check (entrega between 1 and 12),
  path    text not null,
  primary key (gen, entrega)
);
alter table public.entrega_portadas enable row level security;
drop policy if exists "miembros ven portadas" on public.entrega_portadas;
drop policy if exists "admin edita portadas"  on public.entrega_portadas;
create policy "miembros ven portadas" on public.entrega_portadas for select to authenticated using (public.is_member());
create policy "admin edita portadas"  on public.entrega_portadas for all    to authenticated using (public.is_admin()) with check (public.is_admin());

-- ---------- plantillas y ejercicios (compartidos; archivos en el bucket 'recursos') ----------
create table if not exists public.recursos (
  id        uuid primary key default gen_random_uuid(),
  tipo      text not null check (tipo in ('plantilla','ejercicio','notas')),
  entrega   int  check (entrega between 1 and 12),
  gen       int  references public.generaciones(n),   -- solo para el tipo 'notas'
  titulo    text not null,
  descr     text not null default '',
  url       text not null default '',
  file_path text,
  file_name text,
  file_size bigint,
  file_type text,
  creado    timestamptz not null default now()
);
alter table public.recursos enable row level security;
drop policy if exists "miembros ven recursos" on public.recursos;
drop policy if exists "admin edita recursos"  on public.recursos;
create policy "miembros ven recursos" on public.recursos for select to authenticated using (public.is_member());
create policy "admin edita recursos"  on public.recursos for all    to authenticated using (public.is_admin()) with check (public.is_admin());

-- ---------- apuntes (PRIVADOS: cada miembro solo ve los suyos) ----------
create table if not exists public.apuntes (
  id          uuid primary key,                      -- lo genera el navegador para poder guardar sin esperar
  user_id     uuid not null default auth.uid() references auth.users(id) on delete cascade,
  gen         int  not null references public.generaciones(n),
  entrega     int  not null default 5 check (entrega between 1 and 12),
  fecha       date,
  speaker     text not null default '',
  tema        text not null default '',
  h           int  not null default 1120,
  html        text not null default '',
  creado      timestamptz not null default now(),
  actualizado timestamptz not null default now()
);
create index if not exists apuntes_user on public.apuntes (user_id, gen);
alter table public.apuntes enable row level security;
drop policy if exists "apuntes propios" on public.apuntes;
create policy "apuntes propios" on public.apuntes for all to authenticated
  using (user_id = auth.uid() and public.is_member()) with check (user_id = auth.uid() and public.is_member());

create or replace function public.touch_actualizado() returns trigger language plpgsql as $$
begin new.actualizado := now(); return new; end $$;
drop trigger if exists apuntes_touch on public.apuntes;
create trigger apuntes_touch before update on public.apuntes for each row execute function public.touch_actualizado();

-- ---------- plan de acción (PRIVADO) ----------
create table if not exists public.plan_acciones (
  id      uuid primary key,
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  gen     int  not null references public.generaciones(n),
  accion  text not null,
  entrega int  not null check (entrega between 1 and 12),
  fecha   date not null,
  prio    text not null default 'media' check (prio in ('alta','media','baja')),
  estado  text not null default 'todo'  check (estado in ('todo','doing','done')),
  creado  timestamptz not null default now()
);
create index if not exists plan_user on public.plan_acciones (user_id, gen);
alter table public.plan_acciones enable row level security;
drop policy if exists "plan propio" on public.plan_acciones;
create policy "plan propio" on public.plan_acciones for all to authenticated
  using (user_id = auth.uid() and public.is_member()) with check (user_id = auth.uid() and public.is_member());

-- ---------- Storage: buckets privados ----------
insert into storage.buckets (id, name, public, file_size_limit)
values ('galeria', 'galeria', false, 10485760),      -- 10 MB por foto (el navegador ya las reduce)
       ('recursos', 'recursos', false, 26214400)     -- 25 MB por archivo
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit;

drop policy if exists "miembros leen galeria"  on storage.objects;
drop policy if exists "admin sube galeria"     on storage.objects;
drop policy if exists "admin edita galeria"    on storage.objects;
drop policy if exists "admin borra galeria"    on storage.objects;
drop policy if exists "suben galeria"          on storage.objects;
drop policy if exists "editan galeria"         on storage.objects;
drop policy if exists "borran galeria"         on storage.objects;
drop policy if exists "miembros leen recursos" on storage.objects;
drop policy if exists "admin sube recursos"    on storage.objects;
drop policy if exists "admin edita recursos"   on storage.objects;
drop policy if exists "admin borra recursos"   on storage.objects;

create policy "miembros leen galeria" on storage.objects for select to authenticated using (bucket_id = 'galeria' and public.is_member());
-- galería: cada miembro sube a su carpeta (<su id>/archivo.jpg); el admin, a cualquiera
create policy "suben galeria"  on storage.objects for insert to authenticated with check (bucket_id = 'galeria' and (public.is_admin() or (public.is_member() and (storage.foldername(name))[1] = auth.uid()::text)));
create policy "editan galeria" on storage.objects for update to authenticated using (bucket_id = 'galeria' and (public.is_admin() or (public.is_member() and (storage.foldername(name))[1] = auth.uid()::text)));
create policy "borran galeria" on storage.objects for delete to authenticated using (bucket_id = 'galeria' and (public.is_admin() or (public.is_member() and (storage.foldername(name))[1] = auth.uid()::text)));

create policy "miembros leen recursos" on storage.objects for select to authenticated using (bucket_id = 'recursos' and public.is_member());
create policy "admin sube recursos"    on storage.objects for insert to authenticated with check (bucket_id = 'recursos' and public.is_admin());
create policy "admin edita recursos"   on storage.objects for update to authenticated using (bucket_id = 'recursos' and public.is_admin());
create policy "admin borra recursos"   on storage.objects for delete to authenticated using (bucket_id = 'recursos' and public.is_admin());

-- ---------- etiquetas en las fotos y notificaciones ----------
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

-- ---------- portada de cada nota (imagen de la tarjeta en Memorias; el archivo va en el bucket galeria/portadas) ----------
alter table public.recursos add column if not exists portada text;

-- ---------- miniaturas de las fotos (ruta de la versión chica en el bucket galeria) ----------
alter table public.fotos add column if not exists thumb text;
