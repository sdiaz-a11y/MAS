-- MAS · Arreglo de acceso: las cuentas nuevas entran de inmediato (sin aprobación de admin).
-- Pégalo en SQL Editor y ejecútalo (se puede repetir). Al final muestra las últimas cuentas y su estado para verificar.

-- 0) la columna que usa el inicio de sesión (la crea password_reset.sql; aquí se asegura)
alter table public.profiles add column if not exists must_change boolean not null default false;

-- 1) el alta crea el perfil YA aprobado
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

-- 1b) quita la foto de los datos de las cuentas ya creadas (ya está copiada en el perfil); así el token vuelve a ser chico
update auth.users set raw_user_meta_data = raw_user_meta_data - 'foto' where raw_user_meta_data->>'foto' is not null;

-- 2) las cuentas que quedaron pendientes entran también (los rechazados siguen sin acceso)
update public.profiles set estado = 'aprobado' where estado = 'pendiente';

-- 3) verificación: el disparador del alta debe existir y apuntar a handle_new_user
select
  exists (select 1 from pg_trigger t join pg_class c on c.oid = t.tgrelid
           where c.relname = 'users' and t.tgname = 'on_auth_user_created' and not t.tgisinternal) as disparador_del_alta,
  (select count(*) from public.profiles where estado = 'pendiente') as pendientes_ahora;

-- 4) las últimas cuentas creadas
select email, nombre, rol, estado, creado from public.profiles order by creado desc limit 5;
