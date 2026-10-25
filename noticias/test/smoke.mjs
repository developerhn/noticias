import w from '../src/index.js';
const stmt = () => ({ bind() { return this; }, all: async () => ({ results: [] }), first: async () => null, run: async () => ({}) });
const env = { DB: { prepare: stmt, batch: async () => [] }, CACHE: { get: async () => null, put: async () => {}, delete: async () => {} } };
let bad = 0;
for (const [p, st] of [['/', 200], ['/noticias?q=a', 200], ['/vulnerabilidades?kev=1', 200], ['/inteligencia', 200], ['/estado', 200], ['/robots.txt', 200], ['/sitemap.xml', 200], ['/noticias/0000000000000000', 404], ['/nada', 404]]) {
  const r = await w.fetch(new Request('https://x.test' + p), env, {});
  const ok = r.status === st && r.headers.get('x-content-type-options') === 'nosniff'; if (!ok) bad++;
  console.log(ok ? 'OK ' : 'FAIL', r.status, p);
}
const r1 = await w.fetch(new Request('https://x.test/admin/sync', { method: 'POST' }), env, {});
const r2 = await w.fetch(new Request('https://x.test/admin/sync', { method: 'POST', headers: { authorization: 'Bearer x' } }), { ...env, ADMIN_TOKEN: 'y' }, {});
for (const r of [r1, r2]) { if (r.status !== 401) bad++; console.log(r.status === 401 ? 'OK ' : 'FAIL', 'admin sin/ con token incorrecto →', r.status); }
process.exit(bad ? 1 : 0);
