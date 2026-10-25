// HackerNews.com.ar — Cloudflare Worker (SSR, sin dependencias). Bindings: DB (D1), CACHE (KV).
// Secrets opcionales: ADMIN_TOKEN (habilita /admin/sync), NVD_API_KEY (mejora el límite de NVD).
const FEEDS = [
  { id: 'thehackernews', name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' },
  { id: 'bleepingcomputer', name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
];
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGE = 20;
const E = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const now = () => new Date().toISOString();
const day = d => (d ? String(d).slice(0, 10) : '—');

/* ---------- ingestion ---------- */
const decode = s => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#0?39;/g, "'");
const strip = s => decode(s).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
const tag = (x, t) => { const m = x.match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`, 'i')); return m ? m[1] : ''; };
async function sha(s) { const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return [...new Uint8Array(b)].slice(0, 8).map(x => x.toString(16).padStart(2, '0')).join(''); }
const safeUrl = u => { try { const x = new URL(u.trim()); return x.protocol === 'https:' || x.protocol === 'http:' ? x.href : null; } catch { return null; } };
async function getJson(url, headers = {}) {
  const r = await fetch(url, { headers: { 'user-agent': 'hackernews.com.ar/1.0 (+https://hackernews.com.ar)', ...headers }, signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r;
}
async function batch(env, stmts) { for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50)); }
async function status(env, source, n, err) {
  const t = now();
  await env.DB.prepare(`INSERT INTO source_status(source,last_attempt,last_success,last_error,items) VALUES(?1,?2,?3,?4,?5)
    ON CONFLICT(source) DO UPDATE SET last_attempt=?2, last_success=COALESCE(?3,last_success), last_error=?4, items=CASE WHEN ?3 IS NULL THEN items ELSE ?5 END`)
    .bind(source, t, err ? null : t, err ? String(err.message || err).slice(0, 200) : null, n).run();
}
async function ingestFeed(env, f) {
  const xml = await (await getJson(f.url)).text();
  const items = [...xml.matchAll(/<item[\s>][\s\S]*?<\/item>/gi)].slice(0, 40).map(m => m[0]);
  const stmts = [];
  for (const it of items) {
    const url = safeUrl(decode(tag(it, 'link'))); const title = strip(tag(it, 'title'));
    if (!url || !title) continue;
    const pd = new Date(decode(tag(it, 'pubDate')));
    const pub = isNaN(pd) ? null : pd.toISOString();
    stmts.push(env.DB.prepare(`INSERT INTO articles(id,source,url,title,excerpt,lang,published_at,ingested_at) VALUES(?1,?2,?3,?4,?5,'en',?6,?7)
      ON CONFLICT(url) DO UPDATE SET title=excluded.title, excerpt=excluded.excerpt`).bind(await sha(url), f.name, url, title.slice(0, 300), strip(tag(it, 'description')).slice(0, 240), pub, now()));
  }
  await batch(env, stmts); return stmts.length;
}
async function ingestKev(env) {
  const j = await (await getJson(KEV_URL)).json();
  if (!Array.isArray(j.vulnerabilities)) throw new Error('Formato KEV inesperado');
  const t = now();
  const stmts = j.vulnerabilities.filter(v => /^CVE-\d{4}-\d+$/.test(v.cveID)).map(v => env.DB.prepare(
    `INSERT INTO vulns(cve_id,title,description,kev,kev_added,due_date,ransomware,vendor,product,ingested_at) VALUES(?1,?2,?3,1,?4,?5,?6,?7,?8,?9)
     ON CONFLICT(cve_id) DO UPDATE SET kev=1,kev_added=excluded.kev_added,due_date=excluded.due_date,ransomware=excluded.ransomware,
     vendor=excluded.vendor,product=excluded.product,title=COALESCE(vulns.title,excluded.title),description=COALESCE(vulns.description,excluded.description)`)
    .bind(v.cveID, String(v.vulnerabilityName || '').slice(0, 300), String(v.shortDescription || '').slice(0, 1500), v.dateAdded || null, v.dueDate || null, v.knownRansomwareCampaignUse || null, v.vendorProject || null, v.product || null, t));
  await batch(env, stmts); return stmts.length;
}
async function ingestNvd(env) {
  const end = new Date(), start = new Date(end - 2 * 86400000);
  const f = d => d.toISOString().slice(0, 23);
  const u = `${NVD_URL}?lastModStartDate=${f(start)}&lastModEndDate=${f(end)}&resultsPerPage=100`;
  const j = await (await getJson(u, env.NVD_API_KEY ? { apiKey: env.NVD_API_KEY } : {})).json();
  if (!Array.isArray(j.vulnerabilities)) throw new Error('Formato NVD inesperado');
  const t = now();
  const stmts = j.vulnerabilities.map(({ cve }) => {
    const m = cve.metrics || {}; const c = (m.cvssMetricV31 || m.cvssMetricV40 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
    const d = (cve.descriptions || []).find(x => x.lang === 'en');
    return env.DB.prepare(`INSERT INTO vulns(cve_id,description,severity,cvss,published_at,modified_at,in_nvd,ingested_at) VALUES(?1,?2,?3,?4,?5,?6,1,?7)
      ON CONFLICT(cve_id) DO UPDATE SET description=excluded.description,severity=excluded.severity,cvss=excluded.cvss,published_at=excluded.published_at,modified_at=excluded.modified_at,in_nvd=1`)
      .bind(cve.id, (d?.value || '').slice(0, 1500), (c?.cvssData?.baseSeverity || c?.baseSeverity || null)?.toUpperCase() || null, c?.cvssData?.baseScore ?? null, cve.published || null, cve.lastModified || null, t);
  });
  await batch(env, stmts); return stmts.length;
}
async function syncAll(env) {
  if (await env.CACHE.get('sync-lock')) return { skipped: 'sync en curso' };
  await env.CACHE.put('sync-lock', '1', { expirationTtl: 600 });
  const out = {};
  const jobs = [...FEEDS.map(f => [f.name, () => ingestFeed(env, f)]), ['CISA KEV', () => ingestKev(env)], ['NVD', () => ingestNvd(env)]];
  try {
    for (const [name, fn] of jobs) {
      try { const n = await fn(); await status(env, name, n, null); out[name] = { ok: true, items: n }; }
      catch (e) { await status(env, name, 0, e).catch(() => {}); out[name] = { ok: false, error: String(e.message || e).slice(0, 120) }; }
    }
  } finally { await env.CACHE.delete('sync-lock'); }
  return out;
}
function authed(req, env) {
  if (!env.ADMIN_TOKEN) return false;
  const a = (req.headers.get('authorization') || '').replace(/^Bearer /, ''), b = env.ADMIN_TOKEN;
  let d = a.length ^ b.length; for (let i = 0; i < b.length; i++) d |= (a.charCodeAt(i) || 0) ^ b.charCodeAt(i);
  return d === 0;
}

/* ---------- vistas ---------- */
const CSS = `:root{color-scheme:dark;--bg:#050b14;--s1:#0a1524;--ln:#173049;--tx:#e6f1fb;--mu:#8aa4bd;--cy:#38d6ff;--bl:#3b82f6;--am:#ffb02e;--rd:#ff5d6c}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 500px at 80% -10%,#38d6ff1f,transparent 60%),var(--bg);color:var(--tx);font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:inherit;text-decoration:none}a:hover{color:var(--cy)}:focus-visible{outline:2px solid var(--cy);outline-offset:2px}
.w{max-width:1100px;margin:0 auto;padding:0 18px}header{position:sticky;top:0;z-index:5;background:#050b14ee;backdrop-filter:blur(8px);border-bottom:1px solid var(--ln)}
.bar{display:flex;align-items:center;gap:16px;min-height:56px;flex-wrap:wrap}.logo{font:800 18px ui-monospace,Menlo,monospace;color:var(--cy)}.logo i{color:var(--mu);font-style:normal}
nav{margin-left:auto;display:flex;gap:4px;flex-wrap:wrap}nav a{padding:6px 12px;border-radius:6px;font:13px ui-monospace,Menlo,monospace;color:var(--mu)}nav a:hover,nav a[aria-current]{color:var(--cy);background:#38d6ff14}
h1{font-size:clamp(28px,5vw,46px);line-height:1.1;margin:34px 0 8px;letter-spacing:-.02em}h2{font-size:22px;margin:34px 0 12px}.mu{color:var(--mu)}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px}
.card{display:block;background:var(--s1);border:1px solid var(--ln);border-radius:10px;padding:14px 16px;margin:10px 0}.card:hover{border-color:var(--cy)}.card h3{margin:4px 0;font-size:17px}
.tag{display:inline-block;font:11px ui-monospace,monospace;border:1px solid var(--ln);border-radius:4px;padding:1px 7px;margin-right:6px;color:var(--cy)}.CRITICAL,.HIGH,.kev{color:var(--rd);border-color:var(--rd)}.MEDIUM{color:var(--am);border-color:var(--am)}.LOW{color:#4ade80;border-color:#4ade80}
form.f{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}input,select,button{background:var(--s1);color:var(--tx);border:1px solid var(--ln);border-radius:8px;padding:9px 12px;font:inherit}input{flex:1;min-width:180px}button{background:var(--bl);border-color:var(--bl);cursor:pointer}
.empty{border:1px dashed var(--ln);border-radius:10px;padding:22px;color:var(--mu);margin:14px 0}.pg{display:flex;gap:10px;margin:18px 0}.pg a{border:1px solid var(--ln);border-radius:6px;padding:6px 12px}
footer{border-top:1px solid var(--ln);margin-top:50px;padding:20px 0;color:var(--mu);font-size:13px}table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid var(--ln);padding:8px;text-align:left;font-size:14px}.ok{color:#4ade80}.er{color:var(--rd)}`;
function page(req, { title, desc, body, path, nav = '' }) {
  const o = new URL(req.url).origin, canon = o + (path || new URL(req.url).pathname);
  const links = [['/', 'Portada'], ['/noticias', 'Noticias'], ['/vulnerabilidades', 'Vulnerabilidades'], ['/inteligencia', 'Inteligencia'], ['/estado', 'Estado']];
  return new Response(`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${E(title)} — HackerNews.com.ar</title><meta name="description" content="${E(desc)}"><link rel="canonical" href="${E(canon)}">
<meta property="og:title" content="${E(title)}"><meta property="og:description" content="${E(desc)}"><meta property="og:url" content="${E(canon)}"><meta property="og:type" content="website"><meta property="og:locale" content="es_AR">
<style>${CSS}</style></head><body><header><div class="w bar"><a class="logo" href="/">HACKERNEWS<i>.com.ar</i></a>
<nav aria-label="Principal">${links.map(([h, l]) => `<a href="${h}"${h === nav ? ' aria-current="page"' : ''}>${l}</a>`).join('')}</nav></div></header>
<main class="w">${body}</main><footer><div class="w">Agregador de noticias y vulnerabilidades de ciberseguridad. Los titulares y extractos pertenecen a sus fuentes originales y enlazan a ellas. Datos: CISA KEV, NIST NVD, The Hacker News, BleepingComputer. Sin traducción automática: los textos se muestran en su idioma original.</div></footer></body></html>`,
    { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=60' } });
}
const artCard = a => `<a class="card" href="/noticias/${E(a.id)}"><span class="tag">${E(a.source)}</span><span class="tag">${E(a.lang.toUpperCase())}</span><h3>${E(a.title)}</h3><span class="mu mono">${day(a.published_at)}</span></a>`;
const vulnCard = v => `<a class="card" href="/vulnerabilidades/${E(v.cve_id)}"><span class="tag mono">${E(v.cve_id)}</span>${v.severity ? `<span class="tag ${E(v.severity)}">${E(v.severity)}${v.cvss != null ? ' ' + v.cvss : ''}</span>` : ''}${v.kev ? '<span class="tag kev">KEV</span>' : ''}<h3>${E(v.title || (v.description || '').slice(0, 110))}</h3><span class="mu mono">${day(v.published_at || v.kev_added)}</span></a>`;
const empty = m => `<div class="empty">${m}<br><span class="mono">Primera sincronización pendiente o sin coincidencias. Ver <a href="/estado" style="color:var(--cy)">estado de las fuentes</a>.</span></div>`;
const pager = (p, more, base) => `<div class="pg">${p > 1 ? `<a href="${base}${base.includes('?') ? '&' : '?'}p=${p - 1}">← Anterior</a>` : ''}${more ? `<a href="${base}${base.includes('?') ? '&' : '?'}p=${p + 1}">Siguiente →</a>` : ''}</div>`;
const num = (v, d = 1) => Math.max(1, parseInt(v) || d);

async function route(req, env, ctx) {
  const url = new URL(req.url), p = url.pathname.replace(/\/+$/, '') || '/';
  if (req.method === 'POST' && p === '/admin/sync') {
    if (!authed(req, env)) return new Response('No autorizado', { status: 401 });
    return Response.json(await syncAll(env), { headers: { 'cache-control': 'no-store' } });
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('Método no permitido', { status: 405 });
  if (p === '/robots.txt') return new Response(`User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: ${url.origin}/sitemap.xml\n`);
  if (p === '/sitemap.xml') {
    const a = (await env.DB.prepare('SELECT id FROM articles ORDER BY published_at DESC LIMIT 1000').all()).results;
    const v = (await env.DB.prepare('SELECT cve_id FROM vulns ORDER BY ingested_at DESC LIMIT 1000').all()).results;
    const u = ['/', '/noticias', '/vulnerabilidades', '/inteligencia', '/estado', ...a.map(x => '/noticias/' + x.id), ...v.map(x => '/vulnerabilidades/' + x.cve_id)];
    return new Response(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${u.map(x => `<url><loc>${E(url.origin + x)}</loc></url>`).join('')}</urlset>`, { headers: { 'content-type': 'application/xml' } });
  }
  if (p === '/') {
    const a = (await env.DB.prepare('SELECT * FROM articles ORDER BY published_at DESC LIMIT 8').all()).results;
    const v = (await env.DB.prepare('SELECT * FROM vulns WHERE kev=1 ORDER BY kev_added DESC LIMIT 6').all()).results;
    return page(req, { title: 'Ciberseguridad en español', desc: 'Noticias y vulnerabilidades explotadas activamente, con fuente y enlace al original.', nav: '/', body:
      `<h1>La amenaza no avisa.<br><span style="color:var(--cy)">Nosotros te ponemos al día.</span></h1><p class="mu">Noticias de ciberseguridad y vulnerabilidades (CISA KEV, NVD) agregadas de fuentes públicas, siempre con enlace al original.</p>
<form class="f" action="/noticias"><input name="q" placeholder="Buscar noticias…" aria-label="Buscar"><button>Buscar</button></form>
<h2>Últimas noticias</h2>${a.length ? a.map(artCard).join('') : empty('Todavía no hay noticias ingeridas.')}
<h2>Explotadas activamente (CISA KEV)</h2>${v.length ? v.map(vulnCard).join('') : empty('Todavía no hay vulnerabilidades ingeridas.')}` });
  }
  if (p === '/noticias') {
    const q = (url.searchParams.get('q') || '').slice(0, 80), src = url.searchParams.get('fuente') || '', pg = num(url.searchParams.get('p'));
    const like = `%${q.replace(/[%_\\]/g, '\\$&')}%`;
    const r = (await env.DB.prepare(`SELECT * FROM articles WHERE (title LIKE ?1 ESCAPE '\\' OR excerpt LIKE ?1 ESCAPE '\\') AND (?2='' OR source=?2) ORDER BY published_at DESC LIMIT ?3 OFFSET ?4`).bind(like, src, PAGE + 1, (pg - 1) * PAGE).all()).results;
    const base = `/noticias?q=${encodeURIComponent(q)}&fuente=${encodeURIComponent(src)}`;
    return page(req, { title: 'Noticias', desc: 'Noticias de ciberseguridad de fuentes públicas.', nav: '/noticias', path: '/noticias', body:
      `<h1>Noticias</h1><form class="f"><input name="q" value="${E(q)}" placeholder="Buscar…" aria-label="Buscar"><select name="fuente" aria-label="Fuente"><option value="">Todas las fuentes</option>${FEEDS.map(f => `<option${f.name === src ? ' selected' : ''}>${E(f.name)}</option>`).join('')}</select><button>Filtrar</button></form>
${r.length ? r.slice(0, PAGE).map(artCard).join('') : empty('Sin resultados.')}${pager(pg, r.length > PAGE, base)}` });
  }
  let m;
  if ((m = p.match(/^\/noticias\/([0-9a-f]{16})$/))) {
    const a = await env.DB.prepare('SELECT * FROM articles WHERE id=?').bind(m[1]).first();
    if (!a) return page(req, { title: 'No encontrado', desc: 'Artículo inexistente', body: '<h1>No encontrado</h1>' }), new Response('No encontrado', { status: 404 });
    return page(req, { title: a.title, desc: (a.excerpt || a.title).slice(0, 160), nav: '/noticias', body:
      `<h1>${E(a.title)}</h1><p class="mono mu">${E(a.source)} · ${day(a.published_at)} · idioma original: ${E(a.lang.toUpperCase())} · sin traducción automática</p>
<p>${E(a.excerpt)}</p><p><a class="card" href="${E(a.url)}" rel="noopener nofollow" target="_blank">Leer el artículo completo en ${E(a.source)} →</a></p>` });
  }
  if (p === '/vulnerabilidades') {
    const q = (url.searchParams.get('q') || '').slice(0, 80), sev = url.searchParams.get('sev') || '', kev = url.searchParams.get('kev') === '1' ? 1 : 0, pg = num(url.searchParams.get('p'));
    const like = `%${q.replace(/[%_\\]/g, '\\$&')}%`;
    const r = (await env.DB.prepare(`SELECT * FROM vulns WHERE (cve_id LIKE ?1 ESCAPE '\\' OR title LIKE ?1 ESCAPE '\\' OR description LIKE ?1 ESCAPE '\\' OR vendor LIKE ?1 ESCAPE '\\') AND (?2='' OR severity=?2) AND (?3=0 OR kev=1)
      ORDER BY COALESCE(kev_added,published_at) DESC LIMIT ?4 OFFSET ?5`).bind(like, sev, kev, PAGE + 1, (pg - 1) * PAGE).all()).results;
    const base = `/vulnerabilidades?q=${encodeURIComponent(q)}&sev=${encodeURIComponent(sev)}&kev=${kev}`;
    return page(req, { title: 'Vulnerabilidades', desc: 'CVE con severidad CVSS y estado de explotación (CISA KEV).', nav: '/vulnerabilidades', path: '/vulnerabilidades', body:
      `<h1>Vulnerabilidades</h1><form class="f"><input name="q" value="${E(q)}" placeholder="CVE, producto, fabricante…" aria-label="Buscar"><select name="sev" aria-label="Severidad"><option value="">Toda severidad</option>${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => `<option${s === sev ? ' selected' : ''}>${s}</option>`).join('')}</select>
<label class="mu" style="align-self:center"><input type="checkbox" name="kev" value="1" style="min-width:0"${kev ? ' checked' : ''}> Solo KEV</label><button>Filtrar</button></form>
${r.length ? r.slice(0, PAGE).map(vulnCard).join('') : empty('Sin resultados.')}${pager(pg, r.length > PAGE, base)}` });
  }
  if ((m = p.match(/^\/vulnerabilidades\/(CVE-\d{4}-\d{4,})$/))) {
    const v = await env.DB.prepare('SELECT * FROM vulns WHERE cve_id=?').bind(m[1]).first();
    if (!v) return new Response('No encontrado', { status: 404 });
    return page(req, { title: v.cve_id, desc: (v.title || v.description || v.cve_id).slice(0, 160), nav: '/vulnerabilidades', body:
      `<h1>${E(v.cve_id)}</h1><p>${v.severity ? `<span class="tag ${E(v.severity)}">${E(v.severity)} ${v.cvss ?? ''}</span>` : ''}${v.kev ? '<span class="tag kev">Explotada activamente (CISA KEV)</span>' : ''}</p>
<p>${E(v.title)}</p><p class="mu">${E(v.description)}</p>
<table><tr><th>Publicada</th><td>${day(v.published_at)}</td></tr><tr><th>Añadida a KEV</th><td>${day(v.kev_added)}</td></tr><tr><th>Fecha límite CISA</th><td>${day(v.due_date)}</td></tr><tr><th>Uso en ransomware</th><td>${E(v.ransomware || '—')}</td></tr><tr><th>Fabricante / producto</th><td>${E([v.vendor, v.product].filter(Boolean).join(' / ') || '—')}</td></tr></table>
<p>Fuentes: <a href="https://nvd.nist.gov/vuln/detail/${E(v.cve_id)}" rel="noopener" target="_blank" style="color:var(--cy)">NVD</a> · <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" rel="noopener" target="_blank" style="color:var(--cy)">CISA KEV</a></p>` });
  }
  if (p === '/inteligencia') {
    const s = (await env.DB.prepare(`SELECT COUNT(*) n, SUM(kev) k, SUM(ransomware='Known') r FROM vulns`).first()) || {};
    return page(req, { title: 'Inteligencia', desc: 'Resumen de vulnerabilidades explotadas.', nav: '/inteligencia', body:
      `<h1>Inteligencia</h1><table><tr><th>CVE almacenados</th><td>${s.n ?? 0}</td></tr><tr><th>En CISA KEV</th><td>${s.k ?? 0}</td></tr><tr><th>KEV con uso conocido en ransomware</th><td>${s.r ?? 0}</td></tr></table>
<div class="empty">Actores de amenaza y técnicas (MITRE ATT&amp;CK): <b>integración pendiente</b>. No se muestran perfiles ni flujos de ataque hasta ingerir datos documentados.</div>` });
  }
  if (p === '/estado') {
    const s = (await env.DB.prepare('SELECT * FROM source_status ORDER BY source').all()).results;
    return page(req, { title: 'Estado de las fuentes', desc: 'Resultado real de la última sincronización.', nav: '/estado', body:
      `<h1>Estado</h1>${s.length ? `<div style="overflow-x:auto"><table><tr><th>Fuente</th><th>Último intento</th><th>Último éxito</th><th>Items</th><th>Error</th></tr>${s.map(x => `<tr><td>${E(x.source)}</td><td class="mono">${E(x.last_attempt)}</td><td class="mono ok">${E(x.last_success || '—')}</td><td>${x.items}</td><td class="er">${E(x.last_error || '')}</td></tr>`).join('')}</table></div>` : empty('Aún no se ejecutó ninguna sincronización.')}
<p class="mu mono">Sincronización automática cada 30 min (Cron Trigger).</p>` });
  }
  return new Response('No encontrado', { status: 404 });
}

const SEC = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'x-frame-options': 'DENY', 'strict-transport-security': 'max-age=31536000',
  'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" };
export default {
  async fetch(req, env, ctx) {
    let res;
    try { res = await route(req, env, ctx); }
    catch (e) { console.error('route error', e?.message); res = new Response('Error interno', { status: 500 }); }
    res = new Response(res.body, res); for (const [k, v] of Object.entries(SEC)) res.headers.set(k, v);
    return res;
  },
  async scheduled(_e, env, ctx) { ctx.waitUntil(syncAll(env)); },
};
