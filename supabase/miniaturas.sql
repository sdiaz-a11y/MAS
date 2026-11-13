-- MAS · Miniaturas de las fotos (la Galería carga la versión chica y baja la completa solo al abrirla).
-- Pégalo en SQL Editor y ejecútalo UNA vez (se puede repetir). Hazlo ANTES de publicar la versión nueva de la app.
-- Las fotos ya subidas siguen funcionando: usan la completa hasta que se vuelvan a subir.

alter table public.fotos add column if not exists thumb text;   -- ruta de la miniatura en el bucket 'galeria'
