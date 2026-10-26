-- MAS · Fechas importantes (calendario 2026-2027). Corre esto UNA vez en SQL Editor, después de schema.sql.
-- Las ven todos los miembros aprobados; solo los admin agregan o quitan.

create or replace function public.is_member() returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.profiles where id = auth.uid() and estado = 'aprobado');
$$;

create table if not exists public.fechas (
  id     uuid primary key default gen_random_uuid(),
  fecha  date not null,
  titulo text not null,
  lugar  text not null default '',
  creado timestamptz not null default now()
);
alter table public.fechas enable row level security;

drop policy if exists "miembros ven fechas" on public.fechas;
drop policy if exists "admin edita fechas"  on public.fechas;
create policy "miembros ven fechas" on public.fechas for select to authenticated using (public.is_member());
create policy "admin edita fechas"  on public.fechas for all    to authenticated using (public.is_admin()) with check (public.is_admin());

-- calendario inicial (solo si la tabla está vacía)
insert into public.fechas(fecha, titulo, lugar)
select * from (values
  ('2026-10-27'::date, 'Primera entrega · Día 1', 'Barceló GDL'),
  ('2026-10-28'::date, 'Primera entrega · Día 2', 'Barceló GDL'),
  ('2026-10-29'::date, 'Primera entrega · Día 3', 'Barceló GDL'),
  ('2026-11-16'::date, 'Segunda entrega · Día 1', 'Expo GDL'),
  ('2026-11-17'::date, 'Segunda entrega · Día 2', 'Expo GDL'),
  ('2026-11-18'::date, 'Segunda entrega · Día 3', 'Expo GDL'),
  ('2027-01-19'::date, 'Tercera entrega · Día 1', 'Barceló GDL'),
  ('2027-01-20'::date, 'Tercera entrega · Día 2', 'Barceló GDL'),
  ('2027-01-21'::date, 'Tercera entrega · Día 3', 'Barceló GDL'),
  ('2027-02-24'::date, 'Cuarta entrega · Día 1', 'Expo GDL'),
  ('2027-02-25'::date, 'Cuarta entrega · Día 2', 'Expo GDL'),
  ('2027-02-26'::date, 'Cuarta entrega · Día 3', 'Expo GDL'),
  ('2027-03-15'::date, 'Quinta entrega · Día 1', 'Puerto Vallarta'),
  ('2027-03-16'::date, 'Quinta entrega · Día 2', 'Puerto Vallarta'),
  ('2027-03-17'::date, 'Quinta entrega · Día 3', 'Puerto Vallarta'),
  ('2027-03-18'::date, 'Quinta entrega · Día 4', 'Puerto Vallarta'),
  ('2027-03-19'::date, 'Quinta entrega · Día 5', 'Puerto Vallarta')
) v(fecha, titulo, lugar)
where not exists (select 1 from public.fechas);
