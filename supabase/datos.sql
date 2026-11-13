-- MAS · Datos del portal (notas, galería, apuntes, plan de acción, recursos, generaciones).
-- ORDEN: schema.sql → password_reset.sql → fechas.sql → este archivo. Se puede volver a correr sin perder datos.
--
-- Quién ve qué:
--   generaciones, notas, fotos, recursos → los ven todos los miembros aprobados; las fotos y recursos los gestiona un admin.
--                                          Las notas las publica cualquier miembro; editar/borrar es de admin.
--   apuntes, plan_acciones               → privados: cada miembro solo ve y toca lo suyo.
--   Storage (galeria, recursos)          → buckets privados: leen los miembros, escriben los admin.

create or replace function public.is_member() returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.profiles where id = auth.uid() and estado = 'aprobado');
$$;

-- ---------- generaciones ----------
create table if not exists public.generaciones (
  n       int primary key check (n > 0),
  anio    int not null,
  cerrada boolean not null default false,
  actual  boolean not null default false
);
create unique index if not exists generaciones_una_actual on public.generaciones (actual) where actual;
alter table public.generaciones enable row level security;
drop policy if exists "miembros ven generaciones" on public.generaciones;
drop policy if exists "admin edita generaciones"  on public.generaciones;
create policy "miembros ven generaciones" on public.generaciones for select to authenticated using (public.is_member());
create policy "admin edita generaciones"  on public.generaciones for all    to authenticated using (public.is_admin()) with check (public.is_admin());

insert into public.generaciones(n, anio, actual)
select 4, 2026, true where not exists (select 1 from public.generaciones);

-- cambia la generación actual (crea la fila si no existe); solo admin
create or replace function public.set_generacion_actual(p_n int, p_anio int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'no_autorizado'; end if;
  insert into public.generaciones(n, anio) values (p_n, p_anio) on conflict (n) do nothing;
  update public.generaciones set actual = false where actual and n <> p_n;
  update public.generaciones set actual = true where n = p_n;
end $$;
revoke execute on function public.set_generacion_actual(int, int) from public, anon;

-- nombres de los miembros aprobados (para etiquetar quién sale en cada foto)
create or replace function public.nombres_miembros() returns setof text
language sql security definer stable set search_path = public as $$
  select nombre from public.profiles where estado = 'aprobado' and public.is_member() order by nombre;
$$;
revoke execute on function public.nombres_miembros() from public, anon;

-- ---------- notas (compartidas) ----------
create table if not exists public.notas (
  id       bigint generated always as identity primary key,
  gen      int  not null references public.generaciones(n),
  entrega  int  not null check (entrega between 1 and 12),
  titulo   text not null,
  texto    text not null default '',
  autor    text not null default '',
  autor_id uuid references auth.users(id) on delete set null,
  fecha    date not null default current_date,
  creado   timestamptz not null default now()
);
create index if not exists notas_gen on public.notas (gen, entrega);
alter table public.notas enable row level security;

-- el autor lo pone la base (no el navegador), para que nadie firme con otro nombre
create or replace function public.notas_autor() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.autor_id := auth.uid();
  new.autor := coalesce((select nombre from public.profiles where id = auth.uid()), '');
  return new;
end $$;
revoke execute on function public.notas_autor() from public, anon, authenticated;
drop trigger if exists notas_autor on public.notas;
create trigger notas_autor before insert on public.notas for each row execute function public.notas_autor();

drop policy if exists "miembros ven notas"    on public.notas;
drop policy if exists "miembros publican"     on public.notas;
drop policy if exists "admin edita notas"     on public.notas;
drop policy if exists "admin borra notas"     on public.notas;
create policy "miembros ven notas" on public.notas for select to authenticated using (public.is_member());
create policy "miembros publican"  on public.notas for insert to authenticated with check (public.is_member() and autor_id = auth.uid());
create policy "admin edita notas"  on public.notas for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "admin borra notas"  on public.notas for delete to authenticated using (public.is_admin());

-- ---------- galería (compartida; archivos en el bucket 'galeria') ----------
create table if not exists public.fotos (
  id      bigint generated always as identity primary key,
  gen     int  not null references public.generaciones(n),
  entrega int  not null check (entrega between 1 and 12),
  titulo  text not null default 'Foto',
  nombres text[] not null default '{}',
  path    text not null,
  creado  timestamptz not null default now()
);
create index if not exists fotos_gen on public.fotos (gen, entrega);
alter table public.fotos enable row level security;
drop policy if exists "miembros ven fotos" on public.fotos;
drop policy if exists "admin edita fotos"  on public.fotos;
create policy "miembros ven fotos" on public.fotos for select to authenticated using (public.is_member());
create policy "admin edita fotos"  on public.fotos for all    to authenticated using (public.is_admin()) with check (public.is_admin());

-- ---------- plantillas y ejercicios (compartidos; archivos en el bucket 'recursos') ----------
create table if not exists public.recursos (
  id        uuid primary key default gen_random_uuid(),
  tipo      text not null check (tipo in ('plantilla','ejercicio')),
  entrega   int  check (entrega between 1 and 12),
  titulo    text not null,
  descr     text not null default '',
  url       text not null default '',
  file_path text,
  file_name text,
  file_size bigint,
  file_type text,
  creado    timestamptz not null default now()
);
alter table public.recursos enable row level security;
drop policy if exists "miembros ven recursos" on public.recursos;
drop policy if exists "admin edita recursos"  on public.recursos;
create policy "miembros ven recursos" on public.recursos for select to authenticated using (public.is_member());
create policy "admin edita recursos"  on public.recursos for all    to authenticated using (public.is_admin()) with check (public.is_admin());

-- ---------- apuntes (PRIVADOS: cada miembro solo ve los suyos) ----------
create table if not exists public.apuntes (
  id          uuid primary key,                      -- lo genera el navegador para poder guardar sin esperar
  user_id     uuid not null default auth.uid() references auth.users(id) on delete cascade,
  gen         int  not null references public.generaciones(n),
  entrega     int  not null default 5 check (entrega between 1 and 12),
  fecha       date,
  speaker     text not null default '',
  tema        text not null default '',
  h           int  not null default 1120,
  html        text not null default '',
  creado      timestamptz not null default now(),
  actualizado timestamptz not null default now()
);
create index if not exists apuntes_user on public.apuntes (user_id, gen);
alter table public.apuntes enable row level security;
drop policy if exists "apuntes propios" on public.apuntes;
create policy "apuntes propios" on public.apuntes for all to authenticated
  using (user_id = auth.uid() and public.is_member()) with check (user_id = auth.uid() and public.is_member());

create or replace function public.touch_actualizado() returns trigger language plpgsql as $$
begin new.actualizado := now(); return new; end $$;
drop trigger if exists apuntes_touch on public.apuntes;
create trigger apuntes_touch before update on public.apuntes for each row execute function public.touch_actualizado();

-- ---------- plan de acción (PRIVADO) ----------
create table if not exists public.plan_acciones (
  id      uuid primary key,
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  gen     int  not null references public.generaciones(n),
  accion  text not null,
  entrega int  not null check (entrega between 1 and 12),
  fecha   date not null,
  prio    text not null default 'media' check (prio in ('alta','media','baja')),
  estado  text not null default 'todo'  check (estado in ('todo','doing','done')),
  creado  timestamptz not null default now()
);
create index if not exists plan_user on public.plan_acciones (user_id, gen);
alter table public.plan_acciones enable row level security;
drop policy if exists "plan propio" on public.plan_acciones;
create policy "plan propio" on public.plan_acciones for all to authenticated
  using (user_id = auth.uid() and public.is_member()) with check (user_id = auth.uid() and public.is_member());

-- ---------- Storage: buckets privados ----------
insert into storage.buckets (id, name, public, file_size_limit)
values ('galeria', 'galeria', false, 10485760),      -- 10 MB por foto (el navegador ya las reduce)
       ('recursos', 'recursos', false, 26214400)     -- 25 MB por archivo
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit;

drop policy if exists "miembros leen galeria"  on storage.objects;
drop policy if exists "admin sube galeria"     on storage.objects;
drop policy if exists "admin edita galeria"    on storage.objects;
drop policy if exists "admin borra galeria"    on storage.objects;
drop policy if exists "miembros leen recursos" on storage.objects;
drop policy if exists "admin sube recursos"    on storage.objects;
drop policy if exists "admin edita recursos"   on storage.objects;
drop policy if exists "admin borra recursos"   on storage.objects;

create policy "miembros leen galeria" on storage.objects for select to authenticated using (bucket_id = 'galeria' and public.is_member());
create policy "admin sube galeria"    on storage.objects for insert to authenticated with check (bucket_id = 'galeria' and public.is_admin());
create policy "admin edita galeria"   on storage.objects for update to authenticated using (bucket_id = 'galeria' and public.is_admin());
create policy "admin borra galeria"   on storage.objects for delete to authenticated using (bucket_id = 'galeria' and public.is_admin());

create policy "miembros leen recursos" on storage.objects for select to authenticated using (bucket_id = 'recursos' and public.is_member());
create policy "admin sube recursos"    on storage.objects for insert to authenticated with check (bucket_id = 'recursos' and public.is_admin());
create policy "admin edita recursos"   on storage.objects for update to authenticated using (bucket_id = 'recursos' and public.is_admin());
create policy "admin borra recursos"   on storage.objects for delete to authenticated using (bucket_id = 'recursos' and public.is_admin());
