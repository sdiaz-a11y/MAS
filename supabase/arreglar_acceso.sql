-- MAS · Arreglo de acceso: las cuentas nuevas entran de inmediato (sin aprobación de admin).
-- Pégalo en SQL Editor y ejecútalo (se puede repetir). Al final muestra las últimas cuentas y su estado para verificar.

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

-- 2) las cuentas que quedaron pendientes entran también (los rechazados siguen sin acceso)
update public.profiles set estado = 'aprobado' where estado = 'pendiente';

-- 3) verificación: el disparador del alta debe existir y apuntar a handle_new_user
select
  exists (select 1 from pg_trigger t join pg_class c on c.oid = t.tgrelid
           where c.relname = 'users' and t.tgname = 'on_auth_user_created' and not t.tgisinternal) as disparador_del_alta,
  (select count(*) from public.profiles where estado = 'pendiente') as pendientes_ahora;

-- 4) las últimas cuentas creadas
select email, nombre, rol, estado, creado from public.profiles order by creado desc limit 5;
