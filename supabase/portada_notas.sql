-- MAS · Portada de cada nota (la imagen de la tarjeta del cuaderno de una entrega en Memorias).
-- Pégalo en SQL Editor y ejecútalo UNA vez (se puede repetir). La imagen se guarda en el bucket 'galeria' (carpeta portadas/).

alter table public.recursos add column if not exists portada text;
