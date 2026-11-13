-- MAS · Seguridad mínima: la foto de perfil solo puede ser una imagen.
-- Pégalo en SQL Editor y ejecútalo UNA vez (se puede repetir).
--
-- Por qué: hasta ahora la foto de perfil aceptaba cualquier texto. Un miembro podía guardar código en lugar de una
-- imagen, y ese código se ejecutaría en el navegador del admin al abrir la pestaña Usuarios.

-- 1) limpia cualquier "foto" que no sea una imagen de verdad
update public.profiles
   set foto = ''
 where foto <> '' and foto !~ '^data:image/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$';

-- 2) regla de la tabla: solo vacío o una imagen (protege todos los caminos, incluido el alta)
alter table public.profiles drop constraint if exists profiles_foto_es_imagen;
alter table public.profiles add constraint profiles_foto_es_imagen
  check (foto = '' or foto ~ '^data:image/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$');

-- 3) guardar la foto: la función rechaza lo que no sea imagen
create or replace function public.set_mi_foto(p_foto text) returns void
language sql security definer set search_path = public as $$
  update public.profiles set foto = coalesce(p_foto, '')
   where id = auth.uid()
     and length(coalesce(p_foto, '')) < 400000
     and (coalesce(p_foto, '') = '' or p_foto ~ '^data:image/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$');
$$;
revoke execute on function public.set_mi_foto(text) from public, anon;
grant  execute on function public.set_mi_foto(text) to authenticated;

-- 4) el alta ya no copia la foto de los datos de la cuenta (la foto se guarda con set_mi_foto, ya con sesión)
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
