// The Incident sitemaps (ticket incident-pages/05), behind a fake R2 binding.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { sitemapResponse } from '../edge/sitemap.mjs';

const bucket = (doc) => ({ get: async (key) => (key === 'sitemap.json' && doc ? { text: async () => JSON.stringify(doc) } : null) });
const NOW = Date.parse('2026-11-10T12:00:00Z'); // 90 days back: 2026-08-12T12:00Z
const DOC = { pages: {
  'CVE-2026-1001': ['2026-11-09T00:00:00Z', '2026-11-09T12:00:00Z'],
  'hn-77': ['2026-10-31T23:00:00Z', '2026-11-01T08:00:00Z'],
  'CVE-2026-1005': ['2026-08-13T00:00:00Z', '2026-08-13T00:10:00Z'],
  'CVE-2026-1006': ['2026-08-12T00:00:00Z', '2026-08-12T00:10:00Z'], // past 90 days by now: its page answers 410
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
const locs = (text) => [...text.matchAll(/<loc>([^<]*)<\/loc>/g)].map((m) => m[1]);

test('each monthly sitemap lists that month\'s pages (by first seen) in both languages', async () => {
  assert.deepEqual(locs(await xml('incidents-0.xml')), ['https://patchticker.com/i/CVE-2026-1001', 'https://patchticker.com/en/i/CVE-2026-1001']);
  assert.deepEqual(locs(await xml('incidents-1.xml')), ['https://patchticker.com/i/hn-77', 'https://patchticker.com/en/i/hn-77']);
  assert.deepEqual(locs(await xml('incidents-2.xml')), []);
  assert.deepEqual(locs(await xml('incidents-3.xml')), ['https://patchticker.com/i/CVE-2026-1005', 'https://patchticker.com/en/i/CVE-2026-1005']);
});

test('every URL names its last change and both languages as hreflang alternates, Korean as x-default', async () => {
  const text = await xml('incidents-1.xml');
  const urls = text.match(/<url>.*?<\/url>/gs);
  assert.equal(urls.length, 2);
  for (const url of urls) {
    assert.match(url, /<lastmod>2026-11-01T08:00:00Z<\/lastmod>/);
    assert.match(url, /<xhtml:link rel="alternate" hreflang="ko" href="https:\/\/patchticker.com\/i\/hn-77"\/>/);
    assert.match(url, /<xhtml:link rel="alternate" hreflang="en" href="https:\/\/patchticker.com\/en\/i\/hn-77"\/>/);
    assert.match(url, /<xhtml:link rel="alternate" hreflang="x-default" href="https:\/\/patchticker.com\/i\/hn-77"\/>/);
  }
  assert.match(text, /^<\?xml version="1.0" encoding="UTF-8"\?>\n<urlset xmlns="http:\/\/www.sitemaps.org\/schemas\/sitemap\/0.9" xmlns:xhtml="http:\/\/www.w3.org\/1999\/xhtml">/);
  assert.match(text, /<\/urlset>$/);
  assertWellFormed(text);
});

test('hostile entries cannot break the sitemap: odd slugs are dropped, an odd time loses its lastmod', async () => {
  const text = await xml('incidents-0.xml', { pages: {
    '"/><script>alert(1)</script>': ['2026-11-09T00:00:00Z', '2026-11-09T00:00:00Z'],
    '../admin': ['2026-11-09T00:00:00Z', '2026-11-09T00:00:00Z'],
    'CVE-2026-1001': ['2026-11-09T00:00:00Z', '<b>&'],
    'CVE-2026-1002': 'not a pair',
  } });
  assert.doesNotMatch(text, /script|admin|<b>|&(?!amp;|lt;|gt;|quot;|apos;)/);
  assert.deepEqual(locs(text), ['https://patchticker.com/i/CVE-2026-1001', 'https://patchticker.com/en/i/CVE-2026-1001']);
  assert.doesNotMatch(text, /<lastmod>/);
  assertWellFormed(text);
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
    ...[0, 1, 2, 3].map((n) => `https://patchticker.com/sitemaps/incidents-${n}.xml`)]);
  const home = readFileSync(new URL('../web/sitemap-home.xml', import.meta.url), 'utf8');
  assert.deepEqual(locs(home), ['https://patchticker.com/']);
  assertWellFormed(index);
  assertWellFormed(home);
  assert.match(readFileSync(new URL('../web/robots.txt', import.meta.url), 'utf8'), /^Sitemap: https:\/\/patchticker.com\/sitemap.xml$/m);
});
