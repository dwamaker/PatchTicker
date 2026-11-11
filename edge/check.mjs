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
const MAYBE_MAX = 10; // unmatched names one request sends to the model
const MAYBE_WAIT = 5000; // ms the model gets before it is given up
const MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
// Owner, 11-11, measured on 40 typed names: asked only for the official English name, the model read about 37 right.
const SYSTEM = 'You name software and hardware products. The user gives a JSON array of names as people type them: Korean transliterations, abbreviations, nicknames, typos, or a product with extra words. Answer with a JSON object {"names": [...]} holding one string per input, in order: the product\'s official English name as its vendor writes it, without the vendor\'s company name unless it is part of the product name; two products separated by \' | \' if it could be either; "NONE" if it is not a product you know.';
const NOTE = 'Summaries are AI-written from the sources; check the linked advisory before acting. No request data is stored. '
  + 'Names that match nothing are read by a language model on Cloudflare Workers AI to guess the product (the `maybe` list); verify `matched` before relying on it.';
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
  const starts = startsOf(index, [...keys, ...tried.flat()]);
  return keys.map((k, n) => {
    if (has(k)) return { slugs: index[k] };
    const match = byList(index, starts, tried[n]);
    return match ? { ...match, alias: aliases[n] } : byList(index, starts, [k]); // k is no exact key: broad or null
  });
}

// key -> the index keys that start with it and a space, for the keys that are not exact: one pass over the index, or none.
function startsOf(index, keys) {
  const missed = new Set(keys.filter((k) => !Object.hasOwn(index, k)));
  const starts = new Map();
  if (missed.size) {
    for (const key of Object.keys(index)) {
      for (let at = key.indexOf(' '); at > 0; at = key.indexOf(' ', at + 1)) {
        const head = key.slice(0, at);
        if (missed.has(head)) starts.set(head, [...(starts.get(head) || []), key]);
      }
    }
  }
  return starts;
}

// A list of keys (an alias's or the model's names): each by its exact key, else broadly; null when nothing matched.
function byList(index, starts, keys) {
  const has = (k) => Object.hasOwn(index, k);
  const exact = keys.filter(has);
  const broad = [...new Set(keys.filter((k) => !has(k)).flatMap((h) => (starts.get(h) || []).sort()).flatMap((key) => index[key]))].slice(0, BROAD_MAX);
  const slugs = [...new Set([...exact.flatMap((k) => index[k]), ...broad])];
  return slugs.length ? { slugs, ...(exact.length ? {} : { broad: true }) } : null;
}

// The model's official English name for each name, or null when it fails, is late or answers in any other shape.
async function readAs(ai, names) {
  let timer;
  try {
    const result = await Promise.race([ai.run(MODEL, { messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: JSON.stringify(names) }],
      max_tokens: 400, temperature: 0, response_format: { type: 'json_schema',
        json_schema: { type: 'object', properties: { names: { type: 'array', items: { type: 'string' } } }, required: ['names'] } } }),
    new Promise((resolve) => { timer = setTimeout(resolve, MAYBE_WAIT, null); })]);
    const response = typeof result?.response === 'string' ? JSON.parse(result.response) : result?.response;
    const read = response?.names;
    return Array.isArray(read) && read.length === names.length && read.every((r) => typeof r === 'string') ? read : null;
  } catch {
    return null; // quota used up, a binding error or unreadable JSON: answered as without the model
  } finally {
    clearTimeout(timer);
  }
}

// The names one answer of the model stands for: at most 2.
const guesses = (read) => read.split('|').slice(0, 2).map((g) => g.trim()).filter((g) => g && g.length <= 80 && g.toUpperCase() !== 'NONE');

const byRisk = (a, b) => (b.exploited - a.exploited) || (LEVELS.indexOf(b.level) - LEVELS.indexOf(a.level))
  || (a.published < b.published ? 1 : a.published > b.published ? -1 : 0);

// ai: the Workers AI binding, or undefined to answer without guesses.
async function answer(bucket, query, now, ai) {
  const [index, status] = await Promise.all([readJson(bucket, 'check/index.json'),
    readJson(bucket, 'status.json').catch(() => null)]);
  if (!index) return down();
  const since = new Date(now - query.days * 86400000).toISOString().replace('.000', '');
  const least = LEVELS.indexOf(query.min);
  const docs = new Map(); // slug -> its document's read, at most MAX_DOCS (products first, then maybe)
  // One products or maybe entry; label is { alias } or { read_as }.
  const entry = async (asked, label, match) => {
    const slugs = match.slugs.filter((s) => docs.has(s) || (docs.size < MAX_DOCS && docs.set(s, readJson(bucket, `check/p/${s}.json`))));
    const read = (await Promise.all(slugs.map((s) => docs.get(s)))).filter(Boolean); // a document deleted since the index: skipped
    const seen = new Map();
    for (const doc of read) for (const i of doc.incidents) if (i.first_seen >= since && LEVELS.indexOf(i.level) >= least) seen.set(i.id, i);
    return { asked, ...label, matched: read.map((d) => d.product), ...(match.broad ? { broad: true } : {}),
      ...(slugs.length < match.slugs.length ? { capped: true } : {}), incidents: [...seen.values()].sort(byRisk) };
  };
  const matches = lookUp(index, query.names);
  const misses = [...matches.keys()].filter((n) => !matches[n]);
  const sent = misses.filter((n) => query.names[n].length <= 60).slice(0, MAYBE_MAX);
  // Started before the product documents are read, so the model's wait overlaps theirs.
  const reading = ai && sent.length ? readAs(ai, sent.map((n) => query.names[n])) : null;
  const products = [];
  for (const [n, match] of matches.entries()) {
    if (match) products.push(await entry(query.names[n], match.alias ? { alias: match.alias } : {}, match));
  }
  const maybe = [];
  const found = new Set();
  const read = reading && await reading;
  if (read) {
    const tried = sent.map((n, k) => guesses(read[k]));
    const starts = startsOf(index, tried.flat().map(productKey)); // a second pass over the index only when a guess is no exact key
    const has = (k) => Object.hasOwn(index, k);
    // Owner, 11-11 (measured: "Jellyfin Server", "Android 15"): a model name that found nothing, exactly or broadly, is
    // tried once without its last word, as an exact key only. Then a name that adds nothing to the asked one is dropped.
    const shorter = (key, at = key.lastIndexOf(' ')) => (!has(key) && !starts.has(key) && at > 0 && has(key.slice(0, at)) ? key.slice(0, at) : key);
    for (const [k, n] of sent.entries()) {
      const own = productKey(query.names[n]);
      const pairs = tried[k].map((g) => [g, shorter(productKey(g))]).filter(([, key]) => key !== own);
      const match = pairs.length ? byList(index, starts, pairs.map(([, key]) => key)) : null;
      const got = match && await entry(query.names[n], { read_as: pairs.map(([g]) => g) }, match);
      if (got?.matched.length) { maybe.push(got); found.add(n); }
    }
  }
  return json({ ...(status?.updated ? { updated: status.updated } : {}), days: query.days, min: query.min, products,
    unmatched: misses.filter((n) => !found.has(n)).map((n) => query.names[n]), ...(maybe.length ? { maybe } : {}), note: NOTE });
}

// request: the incoming Request. GET answers; HEAD the same without the body (and never asks the model); anything else
// 405. ai: the Workers AI binding (env.AI) or undefined; a model that fails or is late leaves the answer as without it.
export async function checkResponse(bucket, request, now = Date.now(), ai = undefined) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return error('GET or HEAD only', 405, { allow: 'GET, HEAD' });
  const query = readQuery(new URL(request.url).searchParams);
  let res;
  try {
    res = query.error ? error(query.error) : await answer(bucket, query, now, request.method === 'GET' ? ai : undefined);
  } catch {
    res = down();
  }
  return request.method === 'HEAD' ? new Response(null, res) : res;
}
