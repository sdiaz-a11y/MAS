-- MAS · Portadas de las entregas (la imagen de cada tarjeta en la pestaña Notas).
-- Pégalo en SQL Editor y ejecútalo UNA vez (se puede repetir). Las ven todos los miembros; solo el admin las pone o quita.
-- La imagen se guarda en el bucket 'galeria' (carpeta portadas/), que ya permite escribir al admin.

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
