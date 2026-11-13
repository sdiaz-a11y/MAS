-- MAS · Actualización: cuenta abierta (sin código), cuaderno de notas por entrega y fotos de todos.
-- Pégalo en SQL Editor y ejecútalo UNA vez (se puede repetir sin problema).
--
--  1) Ya no hay código del grupo: quien crea su cuenta entra de inmediato (el admin puede sacarlo o cambiarle la contraseña).
--  2) Notas = el cuaderno (PDF) de cada entrega: lo sube el admin en "Plantillas y ejercicios" con el tipo "Notas".
--  3) Las fotos de la galería las sube cualquier miembro y las ven todos; cada quien edita o borra solo las suyas (el admin, todas).

-- ---------- 1) alta sin código ----------
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

update public.profiles set estado = 'aprobado' where estado = 'pendiente';   -- (los rechazados siguen sin acceso)
drop function if exists public.set_group_code(text);
delete from public.app_secrets where key in ('group_code', 'bootstrap');

-- ---------- 2) recursos: nuevo tipo "notas" (cuaderno de la entrega) y su generación ----------
alter table public.recursos drop constraint if exists recursos_tipo_check;
alter table public.recursos add constraint recursos_tipo_check check (tipo in ('plantilla','ejercicio','notas'));
alter table public.recursos add column if not exists gen int references public.generaciones(n);

-- ---------- 3) fotos de todos ----------
alter table public.fotos add column if not exists autor_id uuid default auth.uid() references auth.users(id) on delete set null;

drop policy if exists "miembros suben fotos" on public.fotos;
drop policy if exists "autor edita fotos"    on public.fotos;
drop policy if exists "autor borra fotos"    on public.fotos;
create policy "miembros suben fotos" on public.fotos for insert to authenticated
  with check (public.is_member() and autor_id = auth.uid());
create policy "autor edita fotos" on public.fotos for update to authenticated
  using (autor_id = auth.uid() and public.is_member()) with check (autor_id = auth.uid());
create policy "autor borra fotos" on public.fotos for delete to authenticated
  using (autor_id = auth.uid() and public.is_member());
-- (el admin ya podía todo con la política "admin edita fotos")

-- archivos: cada miembro sube a su propia carpeta (<su id>/archivo.jpg); el admin, a cualquiera
drop policy if exists "admin sube galeria"  on storage.objects;
drop policy if exists "admin edita galeria" on storage.objects;
drop policy if exists "admin borra galeria" on storage.objects;
drop policy if exists "suben galeria"       on storage.objects;
drop policy if exists "editan galeria"      on storage.objects;
drop policy if exists "borran galeria"      on storage.objects;
create policy "suben galeria"  on storage.objects for insert to authenticated
  with check (bucket_id = 'galeria' and (public.is_admin() or (public.is_member() and (storage.foldername(name))[1] = auth.uid()::text)));
create policy "editan galeria" on storage.objects for update to authenticated
  using (bucket_id = 'galeria' and (public.is_admin() or (public.is_member() and (storage.foldername(name))[1] = auth.uid()::text)));
create policy "borran galeria" on storage.objects for delete to authenticated
  using (bucket_id = 'galeria' and (public.is_admin() or (public.is_member() and (storage.foldername(name))[1] = auth.uid()::text)));

-- ---------- 4) la tabla de notas de texto ya no se usa ----------
-- Si no tienes notas de prueba que conservar, puedes borrarla quitando los guiones de la línea siguiente:
-- drop table if exists public.notas;
