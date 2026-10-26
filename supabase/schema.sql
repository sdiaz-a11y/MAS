-- MAS · Portal de miembros — esquema de acceso (Supabase)
-- ORDEN:
--  1) NOTA: auth.users no se puede alterar desde el SQL Editor. Para crear el primer admin desde el dashboard,
--     inserta antes ("bootstrap",1) en app_secrets (ver instrucciones), crea el usuario sdiaz@zigma3.com y bórralo después.
--  2) Dashboard > Authentication > Providers > Email: desactiva "Confirm email" (las altas las aprueba un admin).
--  3) Pega y ejecuta este archivo completo en SQL Editor.
--  4) Después ejecuta password_reset.sql (restablecer contraseñas con aprobación del admin).

create extension if not exists pgcrypto with schema extensions;

-- ---------- perfiles ----------
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
alter table public.profiles enable row level security;

-- ---------- secretos de la app (sin políticas: ningún cliente puede leerla) ----------
create table if not exists public.app_secrets (key text primary key, value text not null);
alter table public.app_secrets enable row level security;
revoke all on public.app_secrets from anon, authenticated;

-- código del grupo inicial: cámbialo aquí ANTES de ejecutar (este repo es público) o luego desde la pestaña Solicitudes.
insert into public.app_secrets(key, value)
values ('group_code', extensions.crypt('CAMBIAR-ESTE-CODIGO', extensions.gen_salt('bf')))
on conflict (key) do nothing;

-- ---------- ¿el usuario actual es admin aprobado? ----------
create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.profiles where id = auth.uid() and rol = 'admin' and estado = 'aprobado');
$$;

-- ---------- políticas ----------
drop policy if exists "perfil propio"   on public.profiles;
drop policy if exists "admin ve todos"  on public.profiles;
drop policy if exists "admin edita"     on public.profiles;
create policy "perfil propio"  on public.profiles for select to authenticated using (id = auth.uid());
create policy "admin ve todos" on public.profiles for select to authenticated using (public.is_admin());
create policy "admin edita"    on public.profiles for update to authenticated using (public.is_admin()) with check (public.is_admin());
-- sin políticas de insert/delete: los perfiles solo los crea el trigger de abajo.

-- ---------- alta: valida el código del grupo EN EL SERVIDOR y crea el perfil pendiente ----------
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare h text; c text := coalesce(new.raw_user_meta_data->>'codigo', '');
begin
  select value into h from public.app_secrets where key = 'group_code';
  if c = '' or h is null or extensions.crypt(c, h) <> h then
    raise exception 'codigo_invalido';
  end if;
  insert into public.profiles(id, nombre, email, tel, foto)
  values (new.id,
          coalesce(new.raw_user_meta_data->>'nombre', ''),
          lower(new.email),
          coalesce(new.raw_user_meta_data->>'tel', ''),
          coalesce(new.raw_user_meta_data->>'foto', ''));
  return new;
end $$;
revoke execute on function public.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

-- ---------- cambiar el código del grupo (solo admin) ----------
create or replace function public.set_group_code(nuevo text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_admin() then raise exception 'no autorizado'; end if;
  if length(coalesce(nuevo, '')) < 6 then raise exception 'codigo_corto'; end if;
  update public.app_secrets set value = extensions.crypt(nuevo, extensions.gen_salt('bf')) where key = 'group_code';
end $$;
revoke execute on function public.set_group_code(text) from public, anon;
grant  execute on function public.set_group_code(text) to authenticated;

-- ---------- el admin inicial (el usuario del paso 1) ----------
insert into public.profiles(id, nombre, email, rol, estado)
select id, 'Samuel Díaz', lower(email), 'admin', 'aprobado' from auth.users where lower(email) = 'sdiaz@zigma3.com'
on conflict (id) do update set rol = 'admin', estado = 'aprobado', nombre = excluded.nombre;

