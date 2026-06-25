// SW PWA : app shell en NETWORK-FIRST (toujours le frais quand en ligne ; cache = SECOURS hors-ligne).
// Avant = stale-while-revalidate -> servait l'ancienne version (1 load de retard) après un déploiement.
// L'API (/api/) n'est JAMAIS mise en cache. Le daemon sert les assets en Cache-Control:no-cache -> le
// navigateur ET Cloudflare revalident aussi -> les déploiements apparaissent sans purge manuelle.
const VER = 'forge-v1';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k !== VER) await caches.delete(k); // purge les anciennes versions
  await self.clients.claim();
})()));
self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  // uniquement GET same-origin hors /api/ : les données live passent toujours au réseau
  if (req.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api/')) return;
  e.respondWith((async () => {
    const cache = await caches.open(VER);
    try {
      const res = await fetch(req);                       // NETWORK-FIRST : le frais d'abord
      if (res && res.ok) cache.put(req, res.clone());
      return res;
    } catch {
      return (await cache.match(req)) || new Response('hors-ligne', { status: 503 });   // secours hors-ligne
    }
  })());
});
