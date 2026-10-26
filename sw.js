/* Service worker del portal MAS: permite instalarlo como app y abrir la app aunque la red falle.
   Solo cachea archivos del mismo origen; las llamadas a Supabase (otro origen) pasan directo a la red.
   Sube V cuando cambies la lista de archivos base. */
const V = 'mas-v1';
const SHELL = ['./', 'index.html', 'logo.png', 'manifest.webmanifest', 'icons/icon-192.png', 'icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(V).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin) return;
  if (r.mode === 'navigate') {   /* la página: siempre la versión nueva si hay red */
    e.respondWith(fetch(r).then(res => { const k = res.clone(); caches.open(V).then(c => c.put('index.html', k)); return res; })
      .catch(() => caches.match('index.html')));
    return;
  }
  e.respondWith(caches.match(r).then(hit => {   /* imágenes e íconos: del caché y se refrescan de fondo */
    const net = fetch(r).then(res => { if (res.ok) { const k = res.clone(); caches.open(V).then(c => c.put(r, k)); } return res; }).catch(() => hit);
    return hit || net;
  }));
});
