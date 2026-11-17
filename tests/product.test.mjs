// Product pages (owner, 11-17: "site:patchticker.com gitea" found only the Board): /p/<slug> and /en/p/<slug>, plain HTML
// from the product's check document (collector/checks.py), and the Incident page's links to them.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pageResponse, PAGE_CSP } from '../edge/page.mjs';
import { checkSlug, PRODUCT_PAGE_MIN, productResponse } from '../edge/product.mjs';

const NOW = Date.parse('2026-11-17T12:00:00Z');
const SSH = '3e96ab9cc2cec1ca'; // collector/checks.py check_slug('openbsd:openssh')
const entry = (n, extra = {}) => ({ id: `CVE-2026-${n}`, url: `https://patchticker.com/i/CVE-2026-${n}`, first_seen: '2026-11-15T00:00:00Z',
  published: '2026-11-15T03:00:00Z', level: 'high', exploited: false, cvss: 7.5, cve_count: 1, cves: [`CVE-2026-${n}`], fixed: '', title_en: `Flaw ${n}`, title_ko: `취약점 ${n}`, ...extra });
const DOC = { product: 'OpenSSH', id: 'openbsd:openssh', incidents: [
  entry(1, { level: 'highest', exploited: true, cvss: 9.8, cve_count: 3, fixed: '9.9p2', published: '2026-11-16T00:30:00Z' }),
  entry(2),
  entry(3, { url: 'https://patchticker.com/#i=CVE-2026-3', level: 'notice', cvss: 4.3 })] };
const store = (docs) => ({ get: async (key) => (Object.hasOwn(docs, key) ? { text: async () => JSON.stringify(docs[key]) } : null) });
const render = async (lang, slug = SSH, docs = { [`check/p/${SSH}.json`]: DOC }) => productResponse(store(docs), lang, slug, NOW);

test('a product page slug is the check document name, as collector/checks.py makes it', async () => {
  assert.equal(await checkSlug('openbsd:openssh'), SSH);
  assert.equal(await checkSlug('name:windows 그림판'), '5f8ec13e9d783f8a');
});

test("a product page lists its Incidents of the last 90 days with level, title, date and fixed version, each linking to its page", async () => {
  const res = await render('ko');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-security-policy'), PAGE_CSP); // the Incident page's: one script by hash, no other
  const html = await res.text();
  assert.match(html, /<title>OpenSSH 보안 사건 · Patch Ticker<\/title>/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/p\/3e96ab9cc2cec1ca">/);
  assert.match(html, /<link rel="alternate" hreflang="en" href="https:\/\/patchticker.com\/en\/p\/3e96ab9cc2cec1ca">/);
  assert.match(html, /<link rel="alternate" type="application\/rss\+xml" title="[^"]*" href="\/feed.xml\?products=OpenSSH">/);
  assert.match(html, /<h1>OpenSSH 보안 사건<\/h1>/);
  assert.match(html, /<li class="risk-highest"><p class="pl-head"><span class="word">긴급<\/span> <span class="kev">공격 발생<\/span> <time datetime="2026-11-16T00:30:00.000Z">2026-11-16 09:30 KST<\/time><\/p><a class="pl-title" href="\/i\/CVE-2026-1">취약점 1<\/a><p class="pl-sub">고친 버전 9.9p2 · CVE 3건<\/p><\/li>/);
  assert.match(html, /<a class="pl-title" href="\/#i=CVE-2026-3">취약점 3<\/a>/); // no page: its row on the Board
  assert.doesNotMatch(html, /noindex/);
  const en = await (await render('en')).text();
  assert.match(en, /<h1>OpenSSH security Incidents<\/h1>/);
  assert.match(en, /<a class="pl-title" href="\/en\/i\/CVE-2026-1">Flaw 1<\/a><p class="pl-sub">Fixed in 9.9p2 · 3 CVEs<\/p>/);
  assert.match(en, /href="\/en\/feed.xml\?products=OpenSSH"/);
  const ja = await (await render('ja')).text(); // Japanese words, English titles (the check documents carry no Japanese)
  assert.match(ja, /<html lang="ja">/);
  assert.match(ja, /<h1>OpenSSH のセキュリティインシデント<\/h1>/);
  assert.match(ja, /<a class="pl-title" href="\/ja\/i\/CVE-2026-1">Flaw 1<\/a><p class="pl-sub">修正バージョン 9.9p2 · CVE 3件<\/p>/);
  assert.match(ja, /2026-11-16 09:30 JST/);
  assert.match(ja, /href="\/ja\/feed.xml\?products=OpenSSH"/);
  assert.match(ja, /<link rel="alternate" hreflang="ja" href="https:\/\/patchticker.com\/ja\/p\/3e96ab9cc2cec1ca">/);
});

test(`a product with fewer than ${PRODUCT_PAGE_MIN} Incidents is not offered to search engines (a thin page)`, async () => {
  const html = await (await render('ko', SSH, { [`check/p/${SSH}.json`]: { ...DOC, incidents: DOC.incidents.slice(0, 1) } })).text();
  assert.match(html, /<meta name="robots" content="noindex">/);
});

test('an unknown slug or a product with no document answers 404 like an unknown Incident; a store error 503', async () => {
  for (const slug of ['nothex', 'ABCDEF0123456789', '../check/index']) assert.equal((await render('ko', slug)).status, 404, slug);
  assert.equal((await render('ko', '0000000000000000')).status, 404);
  const broken = await productResponse({ get: async () => { throw new Error('R2 down'); } }, 'en', SSH, NOW);
  assert.equal(broken.status, 503);
});

test('hostile text in a check document stays text on the product page, and only the site\'s own addresses become links', async () => {
  const docs = { [`check/p/${SSH}.json`]: { ...DOC, product: '</title><script>alert(1)</script>', incidents: [{ ...entry(5), title_ko: '<img src=x onerror=alert(1)>', url: 'javascript:alert(1)' }] } };
  const html = await (await render('ko', SSH, docs)).text();
  assert.doesNotMatch(html, /<script>alert|<img |javascript:/);
  assert.match(html, /href="\/#i=CVE-2026-5"/);
});

test("an Incident page links to the pages of its products, operating systems aside", async () => {
  const doc = { id: 'CVE-2026-1001', cves: ['CVE-2026-1001'], first_seen: '2026-11-15T00:00:00Z', mentions: [], brief: { text: 'b' },
    products: [{ id: 'openbsd:openssh', name: 'OpenSSH' }],
    summary: { incident: true, products: ['OpenSSH'], platforms: ['Linux'], ko: { title: 'T', summary: 'S' }, en: { title: 'T', summary: 'S' } } };
  const html = await (await pageResponse(store({ 'pages/CVE-2026-1001.json': doc }), 'ko', 'CVE-2026-1001', NOW)).text();
  assert.match(html, /<p class="label" id="s-product-pages">제품별 사건<\/p><p class="others"><a href="\/p\/3e96ab9cc2cec1ca">OpenSSH<\/a><\/p>/);
  assert.doesNotMatch(html, /href="\/p\/[0-9a-f]{16}">Linux/);
  const en = await (await pageResponse(store({ 'pages/CVE-2026-1001.json': doc }), 'en', 'CVE-2026-1001', NOW)).text();
  assert.match(en, /Incidents by product<\/p><p class="others"><a href="\/en\/p\/3e96ab9cc2cec1ca">OpenSSH<\/a>/);
});
