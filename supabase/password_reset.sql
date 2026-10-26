-- MAS · Restablecer contraseña con aprobación del admin (corre esto UNA vez en SQL Editor, después de schema.sql)
-- Flujo: el miembro toca "¿Olvidaste tu contraseña?" -> queda un aviso para el admin -> el admin le asigna una contraseña
-- temporal -> al entrar, el miembro está obligado a crear una personal.
-- Los admins no usan este flujo: si un admin olvida su contraseña, se cambia en Dashboard > Authentication > Users.

alter table public.profiles add column if not exists must_change boolean not null default false;

create table if not exists public.password_requests (
  id       uuid primary key default gen_random_uuid(),
  user_id  uuid not null references public.profiles(id) on delete cascade,
  creado   timestamptz not null default now(),
  atendida boolean not null default false
);
alter table public.password_requests enable row level security;

drop policy if exists "admin ve avisos"    on public.password_requests;
drop policy if exists "admin atiende avisos" on public.password_requests;
create policy "admin ve avisos"      on public.password_requests for select to authenticated using (public.is_admin());
create policy "admin atiende avisos" on public.password_requests for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- Cualquiera (aun sin sesión) puede avisar. Responde siempre igual: no revela si el correo existe.
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

-- Solo un admin asigna contraseña, y solo a miembros (nunca a otro admin).
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

-- El miembro marca que ya creó su contraseña personal.
create or replace function public.clear_must_change() returns void
language sql security definer set search_path = public as $$
  update public.profiles set must_change = false where id = auth.uid();
$$;
revoke execute on function public.clear_must_change() from public, anon;
grant  execute on function public.clear_must_change() to authenticated;
