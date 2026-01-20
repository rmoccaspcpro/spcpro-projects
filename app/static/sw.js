const CACHE_NAME = 'spcpro-cache-v3';
const PRECACHE_URLS = [
  '/static/style.css',
  '/static/manifest.json',
  '/static/icons/icon-192.svg',
  '/static/icons/icon-512.svg'
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE_URLS))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    Promise.all([
      caches.keys().then(keys => Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      )),
      self.clients.claim()
    ])
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Never cache HTML navigations (avoids caching CSRF/session-bound pages).
  if (req.mode === 'navigate') {
    event.respondWith(fetch(req));
    return;
  }

  // Cache-first only for static assets.
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(CACHE_NAME);
        const cached = await cache.match(req);

        const updatePromise = fetch(req)
          .then(resp => {
            if (resp && resp.status === 200) {
              cache.put(req, resp.clone());
            }
            return resp;
          })
          .catch(() => null);

        if (cached) {
          event.waitUntil(updatePromise);
          return cached;
        }

        const fresh = await updatePromise;
        return fresh || cached;
      })()
    );
    return;
  }

  // Default: network-only.
  event.respondWith(fetch(req));
});
