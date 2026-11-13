-- ======================================================================================================================
-- MAS · Portal de Miembros — BASE DE DATOS COMPLETA (un solo archivo)
--
-- Pégalo ENTERO en Supabase > SQL Editor y ejecútalo. Sirve para dos casos y es seguro repetirlo:
--   · Base nueva:       crea todo desde cero.
--   · Base ya andando:  deja todo al día (agrega lo que falte) sin borrar datos de nadie.
--
-- Antes de la primera vez en una base NUEVA (el admin inicial):
--   crea en Authentication > Users al usuario sdiaz@zigma3.com y ejecuta este archivo: lo deja como admin.
--
-- Quién ve qué:
--   · Cualquiera puede crear su cuenta y entra de inmediato; el admin puede quitar el acceso o cambiar contraseñas.
--   · Fotos y generaciones: las ven todos los miembros. Cada quien sube, edita y borra las suyas; el admin, todas.
--   · Recursos (plantillas, ejercicios y notas de cada entrega) y portadas: los ven todos; los gestiona el admin.
--   · Apuntes y plan de acción: PRIVADOS, cada quien solo ve lo suyo.
--   · Notificaciones: cada quien ve solo las suyas (las crea la base cuando te etiquetan en una foto).
--   · Archivos (bucket galeria y recursos): privados; se ven con enlaces temporales.
-- ======================================================================================================================

create extension if not exists pgcrypto with schema extensions;


-- ======================================================================================================================
-- 1) PERFILES Y ACCESO
-- ======================================================================================================================
create table if not exists public.profiles (
  id      uuid primary key references auth.users(id) on delete cascade,
  nombre  text not null,
  email   text not null unique,
  tel     text not null default '',
  foto    text not null default '',
  rol     text not null default 'miembro'   check (rol in ('admin','miembro')),
  estado  text not null default 'pendiente' check (estado in ('pendiente','aprobado','rechazado')),
  creado  timestamptz not null default now()
);
alter table public.profiles add column if not exists must_change boolean not null default false;   -- contraseña temporal pendiente de cambiar
alter table public.profiles enable row level security;

-- la foto de perfil solo puede ser una imagen (nunca texto arbitrario: ese texto se pintaría en la pantalla del admin)
update public.profiles
   set foto = ''
 where foto <> '' and foto !~ '^data:image/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$';
alter table public.profiles drop constraint if exists profiles_foto_es_imagen;
alter table public.profiles add constraint profiles_foto_es_imagen
  check (foto = '' or foto ~ '^data:image/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$');

-- ¿el usuario actual es admin / miembro aprobado?
create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.profiles where id = auth.uid() and rol = 'admin' and estado = 'aprobado');
$$;
create or replace function public.is_member() returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.profiles where id = auth.uid() and estado = 'aprobado');
$$;

drop policy if exists "perfil propio"   on public.profiles;
drop policy if exists "admin ve todos"  on public.profiles;
drop policy if exists "admin edita"     on public.profiles;
create policy "perfil propio"  on public.profiles for select to authenticated using (id = auth.uid());
create policy "admin ve todos" on public.profiles for select to authenticated using (public.is_admin());
create policy "admin edita"    on public.profiles for update to authenticated using (public.is_admin()) with check (public.is_admin());
-- sin políticas de insert/delete: los perfiles solo los crea el disparador de abajo.

-- alta: crea el perfil ya aprobado. La foto NO se toma de los datos de la cuenta (inflaban el token de sesión): se guarda con set_mi_foto.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
begin
  insert into public.profiles(id, nombre, email, tel, foto, estado)
  values (new.id,
          left(coalesce(new.raw_user_meta_data->>'nombre', ''), 120),
          lower(new.email),
          left(coalesce(new.raw_user_meta_data->>'tel', ''), 30),
          '',
          'aprobado');
  -- el correo se da por confirmado para que nadie quede bloqueado
  update auth.users set email_confirmed_at = coalesce(email_confirmed_at, now()) where id = new.id;
  return new;
end $$;
revoke execute on function public.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

-- guardar la foto de perfil (la app la llama ya con la sesión iniciada); rechaza todo lo que no sea una imagen
create or replace function public.set_mi_foto(p_foto text) returns void
language sql security definer set search_path = public as $$
  update public.profiles set foto = coalesce(p_foto, '')
   where id = auth.uid()
     and length(coalesce(p_foto, '')) < 400000
     and (coalesce(p_foto, '') = '' or p_foto ~ '^data:image/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$');
$$;
revoke execute on function public.set_mi_foto(text) from public, anon;
grant  execute on function public.set_mi_foto(text) to authenticated;

-- miembros que se pueden etiquetar en una foto (id y nombre)
create or replace function public.miembros_etiquetables() returns table(id uuid, nombre text)
language sql security definer stable set search_path = public as $$
  select p.id, p.nombre from public.profiles p
   where p.estado = 'aprobado' and p.nombre <> '' and public.is_member()
   order by p.nombre;
$$;
revoke execute on function public.miembros_etiquetables() from public, anon;
grant  execute on function public.miembros_etiquetables() to authenticated;


-- ======================================================================================================================
-- 2) RESTABLECER CONTRASEÑA CON APROBACIÓN DEL ADMIN
--    El miembro toca "¿Olvidaste tu contraseña?" -> queda un aviso para el admin -> el admin le asigna una contraseña
--    temporal -> al entrar, el miembro crea una personal. (Si un admin la olvida: Dashboard > Authentication > Users.)
-- ======================================================================================================================
create table if not exists public.password_requests (
  id       uuid primary key default gen_random_uuid(),
  user_id  uuid not null references public.profiles(id) on delete cascade,
  creado   timestamptz not null default now(),
  atendida boolean not null default false
);
alter table public.password_requests enable row level security;
drop policy if exists "admin ve avisos"      on public.password_requests;
drop policy if exists "admin atiende avisos" on public.password_requests;
create policy "admin ve avisos"      on public.password_requests for select to authenticated using (public.is_admin());
create policy "admin atiende avisos" on public.password_requests for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- cualquiera (aun sin sesión) puede avisar; responde siempre igual: no revela si el correo existe
create or replace function public.request_password_reset(p_email text) returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid;
begin
  select id into uid from public.profiles
   where email = lower(trim(coalesce(p_email, ''))) and estado = 'aprobado' and rol = 'miembro';
  if uid is not null and not exists (select 1 from public.password_requests where user_id = uid and not atendida) then
    insert into public.password_requests(user_id) values (uid);
  end if;
end $$;
revoke execute on function public.request_password_reset(text) from public;
grant  execute on function public.request_password_reset(text) to anon, authenticated;

-- solo un admin asigna contraseña, y solo a miembros (nunca a otro admin)
create or replace function public.admin_set_password(p_user uuid, p_pass text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_admin() then raise exception 'no autorizado'; end if;
  if length(coalesce(p_pass, '')) < 8 then raise exception 'contrasena_corta'; end if;
  if not exists (select 1 from public.profiles where id = p_user and rol = 'miembro') then raise exception 'usuario_invalido'; end if;
  update auth.users set encrypted_password = extensions.crypt(p_pass, extensions.gen_salt('bf')), updated_at = now() where id = p_user;
  update public.profiles set must_change = true where id = p_user;
  update public.password_requests set atendida = true where user_id = p_user and not atendida;
end $$;
revoke execute on function public.admin_set_password(uuid, text) from public, anon;
grant  execute on function public.admin_set_password(uuid, text) to authenticated;

-- el miembro marca que ya creó su contraseña personal
create or replace function public.clear_must_change() returns void
language sql security definer set search_path = public as $$
  update public.profiles set must_change = false where id = auth.uid();
$$;
revoke execute on function public.clear_must_change() from public, anon;
grant  execute on function public.clear_must_change() to authenticated;


-- ======================================================================================================================
-- 3) FECHAS IMPORTANTES (calendario de las entregas)
-- ======================================================================================================================
create table if not exists public.fechas (
  id     uuid primary key default gen_random_uuid(),
  fecha  date not null,
  titulo text not null,
  lugar  text not null default '',
  creado timestamptz not null default now()
);
alter table public.fechas enable row level security;
drop policy if exists "miembros ven fechas" on public.fechas;
drop policy if exists "admin edita fechas"  on public.fechas;
create policy "miembros ven fechas" on public.fechas for select to authenticated using (public.is_member());
create policy "admin edita fechas"  on public.fechas for all    to authenticated using (public.is_admin()) with check (public.is_admin());

-- calendario inicial (solo si la tabla está vacía)
insert into public.fechas(fecha, titulo, lugar)
select * from (values
  ('2026-10-27'::date, 'Primera entrega · Día 1', 'Barceló GDL'),
  ('2026-10-28'::date, 'Primera entrega · Día 2', 'Barceló GDL'),
  ('2026-10-29'::date, 'Primera entrega · Día 3', 'Barceló GDL'),
  ('2026-11-16'::date, 'Segunda entrega · Día 1', 'Expo GDL'),
  ('2026-11-17'::date, 'Segunda entrega · Día 2', 'Expo GDL'),
  ('2026-11-18'::date, 'Segunda entrega · Día 3', 'Expo GDL'),
  ('2027-01-19'::date, 'Tercera entrega · Día 1', 'Barceló GDL'),
  ('2027-01-20'::date, 'Tercera entrega · Día 2', 'Barceló GDL'),
  ('2027-01-21'::date, 'Tercera entrega · Día 3', 'Barceló GDL'),
  ('2027-02-24'::date, 'Cuarta entrega · Día 1', 'Expo GDL'),
  ('2027-02-25'::date, 'Cuarta entrega · Día 2', 'Expo GDL'),
  ('2027-02-26'::date, 'Cuarta entrega · Día 3', 'Expo GDL'),
  ('2027-03-15'::date, 'Quinta entrega · Día 1', 'Puerto Vallarta'),
  ('2027-03-16'::date, 'Quinta entrega · Día 2', 'Puerto Vallarta'),
  ('2027-03-17'::date, 'Quinta entrega · Día 3', 'Puerto Vallarta'),
  ('2027-03-18'::date, 'Quinta entrega · Día 4', 'Puerto Vallarta'),
  ('2027-03-19'::date, 'Quinta entrega · Día 5', 'Puerto Vallarta')
) v(fecha, titulo, lugar)
where not exists (select 1 from public.fechas);


-- ======================================================================================================================
-- 4) GENERACIONES
-- ======================================================================================================================
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


-- ======================================================================================================================
-- 5) GALERÍA (fotos de todos; los archivos van en el bucket 'galeria')
-- ======================================================================================================================
create table if not exists public.fotos (
  id       bigint generated always as identity primary key,
  gen      int  not null references public.generaciones(n),
  entrega  int  not null check (entrega between 1 and 12),
  titulo   text not null default 'Foto',                      -- la descripción de la foto
  nombres  text[] not null default '{}',                      -- a quién se etiquetó (nombres para mostrar)
  path     text not null,                                     -- foto completa en el bucket
  creado   timestamptz not null default now()
);
alter table public.fotos add column if not exists autor_id   uuid default auth.uid() references auth.users(id) on delete set null;
alter table public.fotos add column if not exists etiquetados uuid[] not null default '{}';   -- ids de los miembros etiquetados
alter table public.fotos add column if not exists thumb      text;                            -- miniatura (la Galería carga la chica)
create index if not exists fotos_gen on public.fotos (gen, entrega);
alter table public.fotos enable row level security;

drop policy if exists "miembros ven fotos"   on public.fotos;
drop policy if exists "admin edita fotos"    on public.fotos;
drop policy if exists "miembros suben fotos" on public.fotos;
drop policy if exists "autor edita fotos"    on public.fotos;
drop policy if exists "autor borra fotos"    on public.fotos;
create policy "miembros ven fotos"   on public.fotos for select to authenticated using (public.is_member());
create policy "admin edita fotos"    on public.fotos for all    to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "miembros suben fotos" on public.fotos for insert to authenticated with check (public.is_member() and autor_id = auth.uid());
create policy "autor edita fotos"    on public.fotos for update to authenticated using (autor_id = auth.uid() and public.is_member()) with check (autor_id = auth.uid());
create policy "autor borra fotos"    on public.fotos for delete to authenticated using (autor_id = auth.uid() and public.is_member());


-- ======================================================================================================================
-- 6) NOTIFICACIONES (te etiquetaron en una foto)
-- ======================================================================================================================
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

-- al etiquetar a alguien (o agregarlo después) le llega la notificación; a uno mismo no
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


-- ======================================================================================================================
-- 7) PORTADAS DE LAS ENTREGAS (la imagen de cada tarjeta en Memorias; el archivo va en galeria/portadas)
-- ======================================================================================================================
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


-- ======================================================================================================================
-- 8) PLANTILLAS, EJERCICIOS Y NOTAS DE CADA ENTREGA (los archivos van en el bucket 'recursos')
--    tipo 'notas' = el cuaderno de una entrega: sale en Memorias (dentro de su entrega) y también aquí.
-- ======================================================================================================================
create table if not exists public.recursos (
  id        uuid primary key default gen_random_uuid(),
  tipo      text not null,
  entrega   int  check (entrega between 1 and 12),
  titulo    text not null,
  descr     text not null default '',
  url       text not null default '',
  file_path text,
  file_name text,
  file_size bigint,
  file_type text,
  creado    timestamptz not null default now()
);
alter table public.recursos add column if not exists gen     int references public.generaciones(n);   -- solo para el tipo 'notas'
alter table public.recursos add column if not exists portada text;                                   -- imagen de la tarjeta (galeria/portadas)
alter table public.recursos drop constraint if exists recursos_tipo_check;
alter table public.recursos add constraint recursos_tipo_check check (tipo in ('plantilla','ejercicio','notas'));
alter table public.recursos enable row level security;
drop policy if exists "miembros ven recursos" on public.recursos;
drop policy if exists "admin edita recursos"  on public.recursos;
create policy "miembros ven recursos" on public.recursos for select to authenticated using (public.is_member());
create policy "admin edita recursos"  on public.recursos for all    to authenticated using (public.is_admin()) with check (public.is_admin());


-- ======================================================================================================================
-- 9) APUNTES Y PLAN DE ACCIÓN (PRIVADOS: cada quien solo ve y toca lo suyo)
-- ======================================================================================================================
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


-- ======================================================================================================================
-- 10) ARCHIVOS (Storage): buckets privados
-- ======================================================================================================================
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

-- galería: leen los miembros; cada miembro sube a su carpeta (<su id>/archivo.jpg); el admin, a cualquiera (incluye portadas/)
create policy "miembros leen galeria" on storage.objects for select to authenticated using (bucket_id = 'galeria' and public.is_member());
create policy "suben galeria"  on storage.objects for insert to authenticated with check (bucket_id = 'galeria' and (public.is_admin() or (public.is_member() and (storage.foldername(name))[1] = auth.uid()::text)));
create policy "editan galeria" on storage.objects for update to authenticated using (bucket_id = 'galeria' and (public.is_admin() or (public.is_member() and (storage.foldername(name))[1] = auth.uid()::text)));
create policy "borran galeria" on storage.objects for delete to authenticated using (bucket_id = 'galeria' and (public.is_admin() or (public.is_member() and (storage.foldername(name))[1] = auth.uid()::text)));

-- recursos: leen los miembros; escribe solo el admin
create policy "miembros leen recursos" on storage.objects for select to authenticated using (bucket_id = 'recursos' and public.is_member());
create policy "admin sube recursos"    on storage.objects for insert to authenticated with check (bucket_id = 'recursos' and public.is_admin());
create policy "admin edita recursos"   on storage.objects for update to authenticated using (bucket_id = 'recursos' and public.is_admin());
create policy "admin borra recursos"   on storage.objects for delete to authenticated using (bucket_id = 'recursos' and public.is_admin());


-- ======================================================================================================================
-- 11) ADMIN INICIAL (el usuario sdiaz@zigma3.com, creado antes en Authentication > Users)
-- ======================================================================================================================
insert into public.profiles(id, nombre, email, rol, estado)
select id, 'Samuel Díaz', lower(email), 'admin', 'aprobado' from auth.users where lower(email) = 'sdiaz@zigma3.com'
on conflict (id) do update set rol = 'admin', estado = 'aprobado';


-- ======================================================================================================================
-- 12) LIMPIEZA DE VERSIONES ANTERIORES (no hace nada en una base nueva)
-- ======================================================================================================================
-- quienes habían quedado "pendientes" de cuando se pedía aprobación entran también (los rechazados siguen sin acceso)
update public.profiles set estado = 'aprobado' where estado = 'pendiente';

-- la foto ya no viaja en los datos de la cuenta (inflaba el token de sesión): se quita de las cuentas ya creadas
update auth.users set raw_user_meta_data = raw_user_meta_data - 'foto' where raw_user_meta_data->>'foto' is not null;

-- ya no existe el código del grupo ni la lista de nombres de miembros (se reemplazó por miembros_etiquetables)
drop function if exists public.set_group_code(text);
drop function if exists public.nombres_miembros();
do $$
begin
  if to_regclass('public.app_secrets') is not null then
    delete from public.app_secrets where key in ('group_code', 'bootstrap');
  end if;
end $$;

-- (opcional) la tabla de notas de texto ya no se usa. Si no tienes notas de prueba que conservar, quita los guiones:
-- drop table if exists public.notas;


-- ======================================================================================================================
-- VERIFICACIÓN: debe mostrar el disparador del alta en "true" y cuántos perfiles hay
-- ======================================================================================================================
select
  exists (select 1 from pg_trigger t join pg_class c on c.oid = t.tgrelid
           where c.relname = 'users' and t.tgname = 'on_auth_user_created' and not t.tgisinternal) as disparador_del_alta,
  (select count(*) from public.profiles)                                        as perfiles,
  (select count(*) from public.profiles where estado = 'pendiente')             as pendientes,
  (select count(*) from public.profiles where rol = 'admin')                    as admins;
