-- MAS · Acceso abierto: quien crea su cuenta con el código del grupo entra de inmediato (ya no hay aprobación).
-- Pégalo en SQL Editor y ejecútalo UNA vez. El código del grupo sigue siendo la única puerta: si se filtra, cámbialo en el portal.

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare h text; c text := coalesce(new.raw_user_meta_data->>'codigo', '');
begin
  -- modo arranque: con la fila 'bootstrap' en app_secrets se permite crear el primer admin desde el dashboard
  if not exists (select 1 from public.app_secrets where key = 'bootstrap') then
    select value into h from public.app_secrets where key = 'group_code';
    if c = '' or h is null or extensions.crypt(c, h) <> h then
      raise exception 'codigo_invalido';
    end if;
  end if;
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

-- quienes ya habían pedido acceso y seguían pendientes entran también (los rechazados siguen sin acceso)
update public.profiles set estado = 'aprobado' where estado = 'pendiente';
