// GET /api/check (owner, 11-11): "which Incidents touch the products I run?", for agents. A Function has about 10 ms
// of CPU, too little for a month file, so the collector writes check/index.json (normalized name -> product slugs) and
// one small check/p/<slug>.json per Product (collector/checks.py); this reads the index and the asked Products only.
// Nothing about a request is logged or stored, and the edge cache is not used, so asked names are kept nowhere.
import { productKey, SEARCH_ALIASES } from '../web/board.mjs';
import { readJson } from './shared.mjs';

const MAX_NAMES = 30;
const MAX_DOCS = 40; // product documents read for one request
const BROAD_MAX = 5; // Products a name matches by its start alone
const LEVELS = ['notice', 'high', 'highest'];
const NOTE = 'Summaries are AI-written from the sources; check the linked advisory before acting. No request data is stored.';
const HEADERS = { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*',
  'cache-control': 'public, max-age=300', 'x-content-type-options': 'nosniff' };

const json = (body, status = 200, more = {}) => new Response(JSON.stringify(body), { status, headers: { ...HEADERS, ...more } });
const error = (text, status = 400, more = {}) => json({ error: text }, status, more);
// No index yet (the collector not deployed) or a store that cannot be read: never kept, so the next request tries again.
const down = () => error('The product check is unavailable right now; try again in 10 minutes.', 503, { 'cache-control': 'no-store', 'retry-after': '600' });

// The query's names, days and min, or the 400's text.
export function readQuery(params) {
  const names = (params.get('products') || '').split(',').map((n) => n.trim()).filter(Boolean);
  if (!names.length || names.length > MAX_NAMES) return { error: `products: 1 to ${MAX_NAMES} comma-separated product names` };
  const days = params.get('days') ?? '30';
  if (!/^\d{1,2}$/.test(days) || +days < 1 || +days > 90) return { error: 'days: a whole number from 1 to 90' };
  const min = params.get('min') ?? 'notice';
  if (!LEVELS.includes(min)) return { error: 'min: notice, high or highest' };
  return { names, days: +days, min };
}

// Which product slugs each asked name stands for: its exact key; else its alias's English names (SEARCH_ALIASES, owner
// 11-11: 크롬 is Chrome), each by its exact key or broadly; else (broad) the keys that start with it and a space, the first
// BROAD_MAX Products of them by key. One pass over the index serves every name and alias name that missed.
function lookUp(index, names) {
  const keys = names.map(productKey);
  const has = (k) => Object.hasOwn(index, k);
  const aliases = names.map((name, n) => (has(keys[n]) ? null : SEARCH_ALIASES[name.toLowerCase().replace(/\s+/g, '')] || null));
  const tried = aliases.map((a) => (a || []).map(productKey));
  const missed = new Set([...keys, ...tried.flat()].filter((k) => !has(k)));
  const starts = new Map();
  if (missed.size) {
    for (const key of Object.keys(index)) {
      for (let at = key.indexOf(' '); at > 0; at = key.indexOf(' ', at + 1)) {
        const head = key.slice(0, at);
        if (missed.has(head)) starts.set(head, [...(starts.get(head) || []), key]);
      }
    }
  }
  const broad = (heads) => [...new Set(heads.flatMap((h) => (starts.get(h) || []).sort()).flatMap((key) => index[key]))].slice(0, BROAD_MAX);
  return keys.map((k, n) => {
    if (has(k)) return { slugs: index[k] };
    const exact = tried[n].filter(has);
    const slugs = [...new Set([...exact.flatMap((a) => index[a]), ...broad(tried[n].filter((a) => !has(a)))])];
    if (slugs.length) return { slugs, alias: aliases[n], ...(exact.length ? {} : { broad: true }) };
    const own = broad([k]);
    return own.length ? { slugs: own, broad: true } : null;
  });
}

const byRisk = (a, b) => (b.exploited - a.exploited) || (LEVELS.indexOf(b.level) - LEVELS.indexOf(a.level))
  || (a.published < b.published ? 1 : a.published > b.published ? -1 : 0);

async function answer(bucket, query, now) {
  const [index, status] = await Promise.all([readJson(bucket, 'check/index.json'),
    readJson(bucket, 'status.json').catch(() => null)]);
  if (!index) return down();
  const since = new Date(now - query.days * 86400000).toISOString().replace('.000', '');
  const least = LEVELS.indexOf(query.min);
  const docs = new Map(); // slug -> its document's read, at most MAX_DOCS
  const out = { ...(status?.updated ? { updated: status.updated } : {}), days: query.days, min: query.min, products: [], unmatched: [], note: NOTE };
  const matches = lookUp(index, query.names);
  for (const [n, match] of matches.entries()) {
    if (!match) { out.unmatched.push(query.names[n]); continue; }
    const slugs = match.slugs.filter((s) => docs.has(s) || (docs.size < MAX_DOCS && docs.set(s, readJson(bucket, `check/p/${s}.json`))));
    const read = (await Promise.all(slugs.map((s) => docs.get(s)))).filter(Boolean); // a document deleted since the index: skipped
    const seen = new Map();
    for (const doc of read) for (const i of doc.incidents) if (i.first_seen >= since && LEVELS.indexOf(i.level) >= least) seen.set(i.id, i);
    out.products.push({ asked: query.names[n], ...(match.alias ? { alias: match.alias } : {}), matched: read.map((d) => d.product), ...(match.broad ? { broad: true } : {}),
      ...(slugs.length < match.slugs.length ? { capped: true } : {}), incidents: [...seen.values()].sort(byRisk) });
  }
  return json(out);
}

// request: the incoming Request. GET answers; HEAD the same without the body; anything else 405.
export async function checkResponse(bucket, request, now = Date.now()) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return error('GET or HEAD only', 405, { allow: 'GET, HEAD' });
  const query = readQuery(new URL(request.url).searchParams);
  let res;
  try {
    res = query.error ? error(query.error) : await answer(bucket, query, now);
  } catch {
    res = down();
  }
  return request.method === 'HEAD' ? new Response(null, res) : res;
}
