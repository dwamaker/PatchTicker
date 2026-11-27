// The list pages (owner, 11-27): /d/, /d/<day> and /p/ in Korean and English, /ja/ with /en/ as its canonical, from the
// collector's lists/index.json and lists/d/<day>.json (collector/cycle.py write_lists).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { homeLinks } from '../edge/home.mjs';
import { dayResponse, daysResponse, productsResponse } from '../edge/lists.mjs';
import { PAGE_CSP } from '../edge/page.mjs';

const entry = (n, extra = {}) => ({ id: `CVE-2026-${n}`, url: `https://patchticker.com/i/CVE-2026-${n}`, first_seen: '2026-11-26T02:00:00Z',
  published: '2026-11-20T00:00:00Z', level: 'high', exploited: false, cvss: 7.5, cve_count: 1, cves: [`CVE-2026-${n}`], fixed: '', title_en: `Flaw ${n}`, title_ko: `취약점 ${n}`, ...extra });
const INDEX = { days: { '2026-11-25': 1, '2026-11-27': 4, '2026-11-26': 2 },
  products: [{ slug: '3e96ab9cc2cec1ca', name: 'OpenSSH', count: 3 }, { slug: '5f8ec13e9d783f8a', name: 'Windows <그림판>', count: 12 }] };
const DAY = { day: '2026-11-26', incidents: [entry(120001, { level: 'highest', exploited: true, cve_count: 7,
  cves: ['CVE-2026-120001', 'CVE-2026-120002', 'CVE-2026-120003', 'CVE-2026-120004', 'CVE-2026-120005'], fixed: '9.9p2' }), entry(120010, { first_seen: '2026-11-25T16:00:00Z' })] };
const DOCS = { 'lists/index.json': INDEX, 'lists/d/2026-11-26.json': DAY };
function bucket(docs) {
  const reads = [];
  return { reads, get: async (key) => { reads.push(key); return Object.hasOwn(docs, key) ? { text: async () => JSON.stringify(docs[key]) } : null; } };
}
const broken = { get: async () => { throw new Error('R2 down'); } };

test('a day page lists the pages first seen that day, newest first, by first seen time, with prev and next days', async () => {
  const res = await dayResponse(bucket(DOCS), 'ko', '2026-11-26');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-security-policy'), PAGE_CSP);
  assert.equal(res.headers.get('cache-control'), 'public, max-age=300');
  const html = await res.text();
  assert.match(html, /<title>2026-11-26 보안 사건 · Patch Ticker<\/title>/);
  assert.match(html, /<meta name="description" content="2026-11-26에 처음 확인한 보안 사건 2건: 취약점 120001 · 취약점 120010">/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/d\/2026-11-26">/);
  assert.match(html, /<link rel="alternate" hreflang="en" href="https:\/\/patchticker.com\/en\/d\/2026-11-26">/);
  assert.doesNotMatch(html, /hreflang="ja" href/); // Japanese is no search language
  assert.match(html, /<h1>2026-11-26 보안 사건<\/h1>/);
  assert.match(html, /한국 시간/);
  const titles = [...html.matchAll(/<a class="pl-title" href="([^"]+)">([^<]+)<\/a>/g)].map((m) => [m[1], m[2]]);
  assert.deepEqual(titles, [['/i/CVE-2026-120001', '취약점 120001'], ['/i/CVE-2026-120010', '취약점 120010']]);
  assert.match(html, /<time datetime="2026-11-26T02:00:00.000Z">2026-11-26 11:00 KST<\/time>/); // first seen, not published
  assert.doesNotMatch(html, /2026-11-20T00:00:00/);
  assert.match(html, /고친 버전 9\.9p2 · CVE-2026-120001, CVE-2026-120002, CVE-2026-120003, CVE-2026-120004, CVE-2026-120005 외 2건/);
  assert.match(html, /<a href="\/d\/2026-11-25" rel="prev">이전 날짜<\/a><a href="\/d\/2026-11-27" rel="next">다음 날짜<\/a><a href="\/d\/">모든 날짜<\/a><a href="\/p\/">제품별 사건<\/a>/);
  const en = await (await dayResponse(bucket(DOCS), 'en', '2026-11-26')).text();
  assert.match(en, /<link rel="canonical" href="https:\/\/patchticker.com\/en\/d\/2026-11-26">/);
  assert.match(en, /<a class="pl-title" href="\/en\/i\/CVE-2026-120001">Flaw 120001<\/a>/);
  assert.match(en, /<a href="\/en\/d\/2026-11-25" rel="prev">Previous day<\/a>/);
});

test('the newest and the oldest day have no next or previous link', async () => {
  const docs = { ...DOCS, 'lists/d/2026-11-27.json': { day: '2026-11-27', incidents: [entry(1)] }, 'lists/d/2026-11-25.json': { day: '2026-11-25', incidents: [entry(2)] } };
  const newest = await (await dayResponse(bucket(docs), 'ko', '2026-11-27')).text();
  assert.doesNotMatch(newest, /rel="next"/);
  assert.match(newest, /href="\/d\/2026-11-26" rel="prev"/);
  const oldest = await (await dayResponse(bucket(docs), 'ko', '2026-11-25')).text();
  assert.doesNotMatch(oldest, /rel="prev"/);
});

test('a /ja/ list page names its /en/ twin canonical and still answers', async () => {
  for (const res of [await dayResponse(bucket(DOCS), 'ja', '2026-11-26'), await daysResponse(bucket(DOCS), 'ja'), await productsResponse(bucket(DOCS), 'ja')]) {
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /<html lang="ja">/);
    assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/en\/(d\/(2026-11-26)?|p\/)">/);
  }
});

test('the day index lists every day the index names, newest first, with its count', async () => {
  const res = await daysResponse(bucket({ 'lists/index.json': { ...INDEX, days: { ...INDEX.days, '../x': 3, '2026-11-24': 0, '2026-11-23': 'many' } } }), 'ko');
  assert.equal(res.status, 200);
  const html = await res.text();
  const days = [...html.matchAll(/<li><a href="([^"]+)">([^<]+)<\/a><span class="n">([^<]+)<\/span><\/li>/g)].map((m) => [m[1], m[3]]);
  assert.deepEqual(days, [['/d/2026-11-27', '4건'], ['/d/2026-11-26', '2건'], ['/d/2026-11-25', '1건']]);
  assert.match(html, /보안 사건 7건을 3일로/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/d\/">/);
  assert.match(html, /<a href="\/p\/">제품별 사건<\/a>/);
});

test('the product list links each product page under its escaped name with its count, and nothing else', async () => {
  const docs = { 'lists/index.json': { ...INDEX, products: [...INDEX.products, { slug: '../../x', name: 'Evil', count: 9 }, { slug: 'abcdef0123456789', name: '', count: 3 }] } };
  const html = await (await productsResponse(bucket(docs), 'en')).text();
  const rows = [...html.matchAll(/<li><a href="([^"]+)">([^<]+)<\/a><span class="n">([^<]+)<\/span><\/li>/g)].map((m) => m.slice(1));
  assert.deepEqual(rows, [['/en/p/3e96ab9cc2cec1ca', 'OpenSSH', '3'], ['/en/p/5f8ec13e9d783f8a', 'Windows &lt;그림판&gt;', '12']]);
  assert.match(html, /<h1>Security Incidents by product<\/h1>/);
  assert.match(html, /2 products with 3 or more/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/en\/p\/">/);
  assert.match(html, /<link rel="alternate" hreflang="ko" href="https:\/\/patchticker.com\/p\/">/);
});

test('a malformed day answers 404 without reading the store; a day with no document 404; no index or a store error 503', async () => {
  for (const day of ['2026-11-2', '../index', '2026-11-26.json', '2026-11-26/x']) {
    const store = bucket(DOCS);
    const res = await dayResponse(store, 'ko', day);
    assert.equal(res.status, 404, day);
    assert.deepEqual(store.reads, [], day);
  }
  const missing = await dayResponse(bucket(DOCS), 'ko', '2026-11-01');
  assert.equal(missing.status, 404);
  assert.match(await missing.text(), /noindex/);
  for (const store of [bucket({ 'lists/d/2026-11-26.json': DAY }), bucket({ 'lists/index.json': { days: [] } }), broken]) {
    for (const res of [await dayResponse(store, 'ko', '2026-11-26'), await daysResponse(store, 'en'), await productsResponse(store, 'ko')]) {
      assert.equal(res.status, 503); // retried, never cached, never an empty list
      assert.equal(res.headers.get('retry-after'), '600');
    }
  }
});

test('hostile text in a list document stays text, and only the site\'s own addresses become links', async () => {
  const evil = { day: '2026-11-26', incidents: [entry(120001, { title_ko: '<script>alert(1)</script>', url: 'javascript:alert(1)', level: '"><b>', fixed: '<i>' })] };
  const html = await (await dayResponse(bucket({ ...DOCS, 'lists/d/2026-11-26.json': evil }), 'ko', '2026-11-26')).text();
  assert.doesNotMatch(html, /<script>alert|javascript:|<b>|<i>/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /href="\/#i=CVE-2026-120001"/); // not its page's address: its Board row
});

test('the home page links the newest seven days, every day and every product page; no index, no list links', async () => {
  const days = Object.fromEntries(Array.from({ length: 9 }, (_, n) => [`2026-11-${String(10 + n).padStart(2, '0')}`, n + 1]));
  const html = await homeLinks({ incidents: [] }, { days: { ...days, bad: 3 }, products: [] });
  const linked = [...html.matchAll(/<a href="\/d\/(\d{4}-\d\d-\d\d)">\1 보안 사건 (\d+)건<\/a>/g)].map((m) => [m[1], m[2]]);
  assert.deepEqual(linked, [['2026-11-18', '9'], ['2026-11-17', '8'], ['2026-11-16', '7'], ['2026-11-15', '6'], ['2026-11-14', '5'], ['2026-11-13', '4'], ['2026-11-12', '3']]);
  for (const href of ['/d/', '/p/', '/en/d/', '/en/p/']) assert.match(html, new RegExp(`<a href="${href}"`));
  assert.equal(await homeLinks({ incidents: [] }, null), '');
  assert.equal(await homeLinks({ incidents: [] }, { incidents: [] }), ''); // not an index
});

// Every entry file is wired to its renderer and language, and answers HEAD as GET.
const context = (url, method, params) => ({ request: new Request(url, { method }), env: { DATA: bucket(DOCS) }, params, waitUntil: () => {} });
test('the nine list entry files answer GET and HEAD alike in their language', async () => {
  for (const [lang, pre] of [['ko', ''], ['en', 'en/'], ['ja', 'ja/']]) {
    for (const [file, path, params] of [['d/index.js', 'd/', {}], ['d/[day].js', 'd/2026-11-26', { day: '2026-11-26' }], ['p/index.js', 'p/', {}]]) {
      const fn = await import(`../functions/${pre}${file}`);
      const url = `https://patchticker.com/${pre}${path}`;
      const get = await fn.onRequestGet(context(url, 'GET', params));
      const head = await fn.onRequestHead(context(url, 'HEAD', params));
      assert.equal(get.status, 200, url);
      assert.equal(head.status, 200, url);
      assert.deepEqual([...head.headers], [...get.headers], url);
      assert.equal(await head.text(), '', url);
      assert.match(await get.text(), new RegExp(`<html lang="${lang}">`), url);
    }
  }
});
