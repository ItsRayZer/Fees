/* App-shell cache. /api and Firebase are never cached (live data + admin actions always hit the network). */
const V = 'fees-v15';
const SHELL = ['/', '/tailwind.css', '/vendor/qrcode.min.js', '/vendor/html2canvas.min.js', '/vendor/jsQR.js', '/manifest.webmanifest', '/icons/logo.png', '/icons/icon-192.png', '/icons/apple-touch-icon.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(V).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(k => Promise.all(k.filter(x => x !== V).map(x => caches.delete(x)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api') || u.pathname === '/verify' || u.pathname === '/verify.html') return;
  if (r.mode === 'navigate') {            // network first so updates arrive, cache as offline fallback
    e.respondWith(fetch(r).then(x => { const c = x.clone(); caches.open(V).then(h => h.put('/', c)); return x; }).catch(() => caches.match('/')));
    return;
  }
  e.respondWith(caches.match(r).then(h => h || fetch(r).then(x => { if (x.ok) { const c = x.clone(); caches.open(V).then(k => k.put(r, c)); } return x; })));
});
