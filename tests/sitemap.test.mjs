// The Incident sitemaps (ticket incident-pages/05), behind a fake R2 binding.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { sitemapResponse } from '../edge/sitemap.mjs';

const bucket = (doc) => ({ get: async (key) => (key === 'sitemap.json' && doc ? { text: async () => JSON.stringify(doc) } : null) });
const NOW = Date.parse('2026-11-10T12:00:00Z'); // 90 days back: 2026-08-12T12:00Z
const DOC = { pages: {
  'CVE-2026-1001': { first_seen: '2026-11-09T00:00:00Z', changed: '2026-11-09T12:00:00Z' },
  'hn-77': { first_seen: '2026-10-31T23:00:00Z', changed: '2026-11-01T08:00:00Z' },
  'CVE-2026-1005': { first_seen: '2026-08-13T00:00:00Z', changed: '2026-08-13T00:10:00Z' },
  'CVE-2026-1006': { first_seen: '2026-08-12T00:00:00Z', changed: '2026-08-12T00:10:00Z' }, // past 90 days by now: its page answers 410
} };
const xml = async (name, doc = DOC) => (await sitemapResponse(bucket(doc), name, NOW)).text();
// A small well-formedness check (Node has no XML parser): balanced tags, quoted attributes, no stray < or &.
function assertWellFormed(text) {
  const body = text.replace(/^<\?xml version="1.0" encoding="UTF-8"\?>\r?\n/, '').replace(/<!--(?:(?!--)[\s\S])*-->/g, '');
  const stack = [];
  for (const [, tag, text] of body.matchAll(/(<[^>]*>)|([^<]+)/g)) {
    if (text !== undefined) { assert.doesNotMatch(text, /&(?!(amp|lt|gt|quot|apos);)/, text); continue; }
    const m = /^<(\/?)([\w:]+)((?:\s+[\w:-]+="[^"<&]*")*)\s*(\/?)>$/.exec(tag);
    assert.ok(m, `bad tag ${tag}`);
    if (m[1]) assert.equal(stack.pop(), m[2]);
    else if (!m[4]) stack.push(m[2]);
  }
  assert.deepEqual(stack, []);
}
// One page's three addresses: Korean at the root, English and Japanese under their prefix.
const all = (slug, kind = 'i') => ['', '/en', '/ja'].map((p) => `https://patchticker.com${p}/${kind}/${slug}`);
const locs = (text) => [...text.matchAll(/<loc>([^<]*)<\/loc>/g)].map((m) => m[1]);

test('each monthly sitemap lists that month\'s pages (by first seen) in every language', async () => {
  assert.deepEqual(locs(await xml('incidents-0.xml')), all('CVE-2026-1001'));
  assert.deepEqual(locs(await xml('incidents-1.xml')), all('hn-77'));
  assert.deepEqual(locs(await xml('incidents-2.xml')), []);
  assert.deepEqual(locs(await xml('incidents-3.xml')), all('CVE-2026-1005'));
});

test('every URL names its last change and every language as hreflang alternates, Korean as x-default', async () => {
  const text = await xml('incidents-1.xml');
  const urls = text.match(/<url>.*?<\/url>/gs);
  assert.equal(urls.length, 3);
  for (const url of urls) {
    assert.match(url, /<lastmod>2026-11-01T08:00:00Z<\/lastmod>/);
    assert.match(url, /<xhtml:link rel="alternate" hreflang="ko" href="https:\/\/patchticker.com\/i\/hn-77"\/>/);
    assert.match(url, /<xhtml:link rel="alternate" hreflang="en" href="https:\/\/patchticker.com\/en\/i\/hn-77"\/>/);
    assert.match(url, /<xhtml:link rel="alternate" hreflang="ja" href="https:\/\/patchticker.com\/ja\/i\/hn-77"\/>/);
    assert.match(url, /<xhtml:link rel="alternate" hreflang="x-default" href="https:\/\/patchticker.com\/i\/hn-77"\/>/);
  }
  assert.match(text, /^<\?xml version="1.0" encoding="UTF-8"\?>\n<urlset xmlns="http:\/\/www.sitemaps.org\/schemas\/sitemap\/0.9" xmlns:xhtml="http:\/\/www.w3.org\/1999\/xhtml">/);
  assert.match(text, /<\/urlset>$/);
  assertWellFormed(text);
});

test('hostile entries cannot break the sitemap: odd slugs are dropped, an odd time loses its lastmod', async () => {
  const text = await xml('incidents-0.xml', { pages: {
    '"/><script>alert(1)</script>': { first_seen: '2026-11-09T00:00:00Z', changed: '2026-11-09T00:00:00Z' },
    '../admin': { first_seen: '2026-11-09T00:00:00Z', changed: '2026-11-09T00:00:00Z' },
    'CVE-2026-1001': { first_seen: '2026-11-09T00:00:00Z', changed: '<b>&' },
    'CVE-2026-1002': 'not an entry',
    'CVE-2026-1003': { first_seen: 20261109 },
  } });
  assert.doesNotMatch(text, /script|admin|<b>|&(?!amp;|lt;|gt;|quot;|apos;)/);
  assert.deepEqual(locs(text), all('CVE-2026-1001'));
  assert.doesNotMatch(text, /<lastmod>/);
  assertWellFormed(text);
});

test('a month over the 50,000-URL limit of one sitemap file keeps its newest pages', async () => {
  const pages = {};
  for (let n = 0; n <= 16666; n += 1) {
    const at = new Date(Date.parse('2026-11-01T00:00:00Z') + n * 1000).toISOString().replace('.000', '');
    pages[`CVE-2026-${100000 + n}`] = { first_seen: at, changed: at };
  }
  const found = locs(await xml('incidents-0.xml', { pages }));
  assert.equal(found.length, 49998); // 16,666 pages in three languages
  assert.ok(!found.includes('https://patchticker.com/i/CVE-2026-100000')); // the oldest page is the one left out
  assert.ok(found.includes('https://patchticker.com/i/CVE-2026-116666'));
});

test('503, never an empty list, for a document without its pages', async () => {
  for (const doc of [{}, { pages: [] }, 'pages']) {
    assert.equal((await sitemapResponse(bucket(doc), 'incidents-0.xml', NOW)).status, 503);
  }
});

test('answers XML with a short cache; 404 for any other name; 503 when the store cannot be read', async () => {
  const ok = await sitemapResponse(bucket(DOC), 'incidents-0.xml', NOW);
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('content-type'), 'application/xml; charset=utf-8');
  assert.match(ok.headers.get('cache-control'), /max-age=300/);
  for (const name of ['incidents-4.xml', 'incidents-0', '2026-11.xml', 'incidents-00.xml']) {
    assert.equal((await sitemapResponse(bucket(DOC), name, NOW)).status, 404, name);
  }
  assert.equal((await sitemapResponse(bucket(null), 'incidents-0.xml', NOW)).status, 503);
  assert.equal((await sitemapResponse({ get: async () => { throw new Error('R2 down'); } }, 'incidents-0.xml', NOW)).status, 503);
});

test('the static /sitemap.xml is an index of the home page\'s sitemap and the four monthly Incident sitemaps', () => {
  const index = readFileSync(new URL('../web/sitemap.xml', import.meta.url), 'utf8');
  assert.match(index, /<sitemapindex xmlns="http:\/\/www.sitemaps.org\/schemas\/sitemap\/0.9">/);
  assert.deepEqual(locs(index), ['https://patchticker.com/sitemap-home.xml',
    ...[0, 1, 2, 3].map((n) => `https://patchticker.com/sitemaps/incidents-${n}.xml`), 'https://patchticker.com/sitemaps/products.xml']);
  const home = readFileSync(new URL('../web/sitemap-home.xml', import.meta.url), 'utf8');
  assert.deepEqual(locs(home), ['https://patchticker.com/']);
  assertWellFormed(index);
  assertWellFormed(home);
  assert.match(readFileSync(new URL('../web/robots.txt', import.meta.url), 'utf8'), /^Sitemap: https:\/\/patchticker.com\/sitemap.xml$/m);
});

// Owner, 11-17: a page per product (/p/<slug>); the collector lists those worth a search (collector/checks.py product_pages).
test('the products sitemap lists each listed product page in every language; a document without the list gives an empty one', async () => {
  const doc = { ...DOC, products: ['3e96ab9cc2cec1ca', 'not-a-slug', '0f1e2d3c4b5a6978'] };
  const text = await xml('products.xml', doc);
  assertWellFormed(text);
  assert.deepEqual(locs(text), [...all('3e96ab9cc2cec1ca', 'p'), ...all('0f1e2d3c4b5a6978', 'p')]);
  assert.match(text, /<url><loc>https:\/\/patchticker.com\/p\/3e96ab9cc2cec1ca<\/loc><xhtml:link rel="alternate" hreflang="ko" href="https:\/\/patchticker.com\/p\/3e96ab9cc2cec1ca"\/><xhtml:link rel="alternate" hreflang="en" href="https:\/\/patchticker.com\/en\/p\/3e96ab9cc2cec1ca"\/>/);
  assert.deepEqual(locs(await xml('products.xml')), []); // the collector before product pages: none yet, not an error
  assert.equal((await sitemapResponse(bucket(null), 'products.xml', NOW)).status, 503);
});
