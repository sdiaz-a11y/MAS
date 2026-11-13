-- MAS · Cuenta abierta + notas privadas. Pégalo en SQL Editor y ejecútalo UNA vez.
--  1) Ya no hay código del grupo: quien crea su cuenta entra de inmediato (el admin puede sacarlo o cambiarle la contraseña).
--  2) Las notas pasan a ser privadas, igual que los apuntes y el plan de acción: cada quien ve, edita y borra solo las suyas.

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

-- quienes seguían pendientes entran también (los rechazados siguen sin acceso)
update public.profiles set estado = 'aprobado' where estado = 'pendiente';

-- el código del grupo ya no existe
drop function if exists public.set_group_code(text);
delete from public.app_secrets where key in ('group_code', 'bootstrap');

-- notas privadas
drop policy if exists "miembros ven notas" on public.notas;
drop policy if exists "miembros publican"  on public.notas;
drop policy if exists "admin edita notas"  on public.notas;
drop policy if exists "admin borra notas"  on public.notas;
drop policy if exists "notas propias"      on public.notas;
create policy "notas propias" on public.notas for all to authenticated
  using (autor_id = auth.uid() and public.is_member()) with check (autor_id = auth.uid() and public.is_member());
