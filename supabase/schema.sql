-- MAS · Portal de miembros — esquema de acceso (Supabase)
-- Pega y ejecuta este archivo en SQL Editor. Después, en este orden: password_reset.sql, fechas.sql y datos.sql
-- (o usa todo.sql, que trae los cuatro juntos).
-- Cualquiera puede crear su cuenta y entra de inmediato; el admin puede sacarlo o cambiarle la contraseña desde el portal.

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

-- ---------- alta: crea el perfil ya aprobado ----------
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
begin
  insert into public.profiles(id, nombre, email, tel, foto, estado)
  values (new.id,
          coalesce(new.raw_user_meta_data->>'nombre', ''),
          lower(new.email),
          coalesce(new.raw_user_meta_data->>'tel', ''),
          coalesce(new.raw_user_meta_data->>'foto', ''),
          'aprobado');
  -- el correo se da por confirmado para que nadie quede bloqueado
  update auth.users set email_confirmed_at = coalesce(email_confirmed_at, now()) where id = new.id;
  return new;
end $$;
revoke execute on function public.handle_new_user() from public, anon, authenticated;

-- la foto de perfil NO viaja en los datos de la cuenta (inflaba el token de sesión y la base respondía "Bad Request"):
-- la app la guarda con esta función, ya con la sesión iniciada
create or replace function public.set_mi_foto(p_foto text) returns void
language sql security definer set search_path = public as $
  update public.profiles set foto = coalesce(p_foto, '') where id = auth.uid() and length(coalesce(p_foto, '')) < 400000;
$;
revoke execute on function public.set_mi_foto(text) from public, anon;
grant  execute on function public.set_mi_foto(text) to authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

-- ---------- el admin inicial (el usuario del paso 1) ----------
insert into public.profiles(id, nombre, email, rol, estado)
select id, 'Samuel Díaz', lower(email), 'admin', 'aprobado' from auth.users where lower(email) = 'sdiaz@zigma3.com'
on conflict (id) do update set rol = 'admin', estado = 'aprobado', nombre = excluded.nombre;

