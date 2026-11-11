// GET /api/check (owner, 11-11): an agent's product names plus a fake R2 binding in, a JSON Response out.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { checkResponse } from '../edge/check.mjs';
import { productKey } from '../web/board.mjs';

const NOW = Date.parse('2026-11-11T12:00:00Z');
const day = (n) => new Date(NOW - n * 86400000).toISOString().replace('.000', '');
const inc = (id, ago, more = {}) => ({ id, url: `https://patchticker.com/i/${id}`, first_seen: day(ago), published: day(ago),
  level: 'notice', exploited: false, cvss: 5, cve_count: 1, cves: [id], fixed: '', title_en: id, title_ko: id, ...more });

const SYNOLOGY = ['dsm', 'photos', 'router manager', 'drive', 'mailplus', 'calendar', 'office'];
const DOCS = {
  'check/index.json': {
    openssh: ['ssh', 'ssh-fork'], nginx: ['nginx'], 'nginx ui': ['nginx-ui'],
    ...Object.fromEntries(SYNOLOGY.map((p) => [`synology ${p}`, [`syn-${p}`]])),
    many: Array.from({ length: 60 }, (_, k) => `many-${k}`),
  },
  'status.json': { updated: '2026-11-11T11:50:00Z', collector: 'test' },
  'check/p/ssh.json': { product: 'OpenSSH', id: 'openbsd:openssh', incidents: [
    inc('CVE-2026-1', 1), inc('CVE-2026-2', 2, { level: 'highest', cvss: 9.8 }), inc('CVE-2026-3', 3, { exploited: true, level: 'high', cvss: 7.5 }),
    inc('CVE-2026-4', 40, { level: 'high', cvss: 8.1 }), inc('CVE-2026-5', 5, { level: 'high', cvss: 7.0 })] },
  'check/p/ssh-fork.json': { product: 'OpenSSH fork', id: 'name:openssh', incidents: [inc('CVE-2026-2', 2, { level: 'highest', cvss: 9.8 })] },
  'check/p/nginx.json': { product: 'nginx', id: 'f5:nginx', incidents: [inc('CVE-2026-9', 1)] },
  ...Object.fromEntries(SYNOLOGY.map((p) => [`check/p/syn-${p}.json`, { product: `Synology ${p}`, id: `synology:${p}`, incidents: [] }])),
  ...Object.fromEntries(Array.from({ length: 60 }, (_, k) => [`check/p/many-${k}.json`, { product: `Many ${k}`, id: `m:${k}`, incidents: [] }])),
};

const bucket = (docs = DOCS, reads = []) => ({ get: async (key) => { reads.push(key); return key in docs ? { text: async () => JSON.stringify(docs[key]) } : null; } });
const ask = (query, { docs, method = 'GET', reads } = {}) =>
  checkResponse(bucket(docs, reads), new Request(`https://patchticker.com/api/check?${query}`, { method }), NOW);
const body = async (query, opts) => (await ask(query, opts)).json();

test('names are normalized as the collector keys them: one shared fixture', () => {
  const kase = JSON.parse(readFileSync(new URL('./fixtures/board/product-key-case.json', import.meta.url), 'utf8'));
  for (const c of kase.cases) assert.equal(productKey(c.name), c.key, c.name);
});

test('an exact name answers its Products\' Incidents of the window, deduplicated, exploited first, then level, then newest', async () => {
  const out = await body('products=%20OpenSSH%20');
  assert.equal(out.updated, '2026-11-11T11:50:00Z');
  assert.equal(out.days, 30);
  assert.equal(out.min, 'notice');
  assert.deepEqual(out.unmatched, []);
  assert.match(out.note, /check the linked advisory/);
  assert.equal(out.products.length, 1);
  const [p] = out.products;
  assert.equal(p.asked, 'OpenSSH');
  assert.deepEqual(p.matched, ['OpenSSH', 'OpenSSH fork']);
  assert.equal(p.broad, undefined);
  assert.deepEqual(p.incidents.map((i) => i.id), ['CVE-2026-3', 'CVE-2026-2', 'CVE-2026-5', 'CVE-2026-1']); // CVE-2026-4 is 40 days old
  assert.deepEqual(p.incidents[0], DOCS['check/p/ssh.json'].incidents[2]);
});

test('days and min narrow the answer', async () => {
  const wide = await body('products=openssh&days=60&min=high');
  assert.deepEqual(wide.products[0].incidents.map((i) => i.id), ['CVE-2026-3', 'CVE-2026-2', 'CVE-2026-5', 'CVE-2026-4']);
  assert.equal(wide.days, 60);
  const top = await body('products=openssh&days=2&min=highest');
  assert.deepEqual(top.products[0].incidents.map((i) => i.id), ['CVE-2026-2']);
});

test('no exact name: the names that start with it, at most five Products, marked broad', async () => {
  const out = await body('products=synology,nginx');
  assert.equal(out.products[0].broad, true);
  assert.deepEqual(out.products[0].matched, ['Synology calendar', 'Synology drive', 'Synology dsm', 'Synology mailplus', 'Synology office']);
  assert.deepEqual(out.products[1].matched, ['nginx']); // exact: "nginx ui" is not added
  assert.equal(out.products[1].broad, undefined);
});

test('a name nothing matches is listed as unmatched, and an Object.prototype name is no product', async () => {
  const out = await body('products=foo,constructor,__proto__,nginx');
  assert.deepEqual(out.unmatched, ['foo', 'constructor', '__proto__']);
  assert.deepEqual(out.products.map((p) => p.asked), ['nginx']);
});

// Owner, 11-11: a Korean name people type for a well-known product (web/board.mjs SEARCH_ALIASES) is asked as its English names.
const ALIASED = { ...DOCS, 'check/index.json': { ...DOCS['check/index.json'], chrome: ['chrome'], 'pan-os': ['panos'] },
  'check/p/chrome.json': { product: 'Chrome', id: 'google:chrome', incidents: [inc('CVE-2026-7', 1)] },
  'check/p/panos.json': { product: 'PAN-OS', id: 'paloaltonetworks:pan-os', incidents: [] } };

test('a Korean name with an alias answers its English names, which the product entry lists', async () => {
  const out = await body('products=크롬,크%20롬,팔로알토', { docs: ALIASED });
  assert.deepEqual(out.unmatched, []);
  const [chrome, spaced, palo] = out.products;
  assert.deepEqual([chrome.asked, chrome.alias, chrome.matched, chrome.broad], ['크롬', ['Chrome'], ['Chrome'], undefined]);
  assert.deepEqual(chrome.incidents.map((i) => i.id), ['CVE-2026-7']);
  assert.deepEqual([spaced.alias, spaced.matched], [['Chrome'], ['Chrome']]); // spacing inside the name does not matter
  assert.deepEqual([palo.alias, palo.matched, palo.broad], [['Palo Alto', 'PAN-OS'], ['PAN-OS'], undefined]); // the second name matched
  assert.deepEqual(Object.keys(chrome).slice(0, 3), ['asked', 'alias', 'matched']);
});

test('an alias with no exact key goes broad; one that finds nothing stays unmatched', async () => {
  const out = await body('products=시놀로지,줌', { docs: ALIASED });
  assert.deepEqual(out.unmatched, ['줌']);
  const [syn] = out.products;
  assert.deepEqual([syn.asked, syn.alias, syn.broad], ['시놀로지', ['Synology'], true]);
  assert.deepEqual(syn.matched, ['Synology calendar', 'Synology drive', 'Synology dsm', 'Synology mailplus', 'Synology office']);
});

test('an exact key beats an alias, and an English name is answered as before', async () => {
  const docs = { ...ALIASED, 'check/index.json': { ...ALIASED['check/index.json'], 크롬: ['ko'] },
    'check/p/ko.json': { product: '크롬', id: 'name:크롬', incidents: [] } };
  const out = await body('products=크롬,chrome', { docs });
  assert.deepEqual(out.products.map((p) => [p.asked, p.matched, p.alias]), [['크롬', ['크롬'], undefined], ['chrome', ['Chrome'], undefined]]);
});

test('at most 40 product documents are read for one request', async () => {
  const reads = [];
  const out = await body('products=many', { reads });
  assert.equal(reads.filter((k) => k.startsWith('check/p/')).length, 40);
  assert.equal(out.products[0].matched.length, 40);
  assert.equal(out.products[0].capped, true);
});

test('400 with the limit for no names, an empty list, more than 30 names, or a bad days or min', async () => {
  for (const q of ['', 'products=', 'products=%20,%20', `products=${Array.from({ length: 31 }, (_, k) => `p${k}`).join(',')}`,
    'products=a&days=0', 'products=a&days=91', 'products=a&days=7.5', 'products=a&days=x', 'products=a&min=low']) {
    const res = await ask(q);
    assert.equal(res.status, 400, q);
    assert.equal(res.headers.get('content-type'), 'application/json; charset=utf-8');
    assert.match((await res.json()).error, /products|days|min/);
  }
  assert.match((await body('')).error, /1 to 30/);
  assert.equal((await ask(`products=${Array.from({ length: 30 }, (_, k) => `p${k}`).join(',')}`)).status, 200);
});

test('503 JSON while the collector has written no index, or when the store cannot be read', async () => {
  const res = await ask('products=openssh', { docs: {} });
  assert.equal(res.status, 503);
  assert.match((await res.json()).error, /unavailable/);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const down = await checkResponse({ get: async () => { throw new Error('R2 down'); } }, new Request('https://patchticker.com/api/check?products=a'), NOW);
  assert.equal(down.status, 503);
});

test('JSON for any page or agent, cached five minutes; HEAD without the body; other methods 405', async () => {
  const res = await ask('products=openssh');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/json; charset=utf-8');
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  assert.equal(res.headers.get('cache-control'), 'public, max-age=300');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  const head = await ask('products=openssh', { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get('content-type'), 'application/json; charset=utf-8');
  assert.equal(await head.text(), '');
  assert.equal((await ask('', { method: 'HEAD' })).status, 400);
  const post = await ask('products=openssh', { method: 'POST' });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get('allow'), 'GET, HEAD');
});
