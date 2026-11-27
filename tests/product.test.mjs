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
  // Owner, 11-27: the Japanese page names the English one canonical and no page lists a Japanese alternate.
  assert.match(ja, /<link rel="canonical" href="https:\/\/patchticker.com\/en\/p\/3e96ab9cc2cec1ca">/);
  assert.doesNotMatch(ja, /<link rel="alternate" hreflang="ja"/);
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
  assert.match(html, /<h2 class="label" id="s-product-pages">제품별 사건<\/h2><p class="others"><a href="\/p\/3e96ab9cc2cec1ca">OpenSSH<\/a><\/p>/);
  assert.doesNotMatch(html, /href="\/p\/[0-9a-f]{16}">Linux/);
  const en = await (await pageResponse(store({ 'pages/CVE-2026-1001.json': doc }), 'en', 'CVE-2026-1001', NOW)).text();
  assert.match(en, /Incidents by product<\/h2><p class="others"><a href="\/en\/p\/3e96ab9cc2cec1ca">OpenSSH<\/a>/);
});

test('a product page says what its list holds as a whole: Incidents by Risk, attacked, the newest; and names CVE IDs', async () => {
  const doc = { ...DOC, incidents: [
    { ...DOC.incidents[0], cves: ['CVE-2026-120001', 'CVE-2026-120002'], cve_count: 4 },
    { ...DOC.incidents[1], cves: ['CVE-2026-120010'] }, DOC.incidents[2]] };
  const html = await (await render('ko', SSH, { [`check/p/${SSH}.json`]: doc })).text();
  assert.match(html, /<dl class="facts"><dt>위험도<\/dt><dd>긴급 1건 · 위험 1건 · 참고 1건<\/dd><dt>공격 발생<\/dt><dd>1건<\/dd><dt>가장 최근<\/dt><dd><time datetime="2026-11-16T00:30:00.000Z">/);
  assert.match(html, /<meta name="description" content="최근 90일 동안 나온 OpenSSH 보안 사건 3건\(긴급 1건, 위험 1건, 참고 1건, 공격 발생 1건\)의/);
  assert.match(html, /고친 버전 9\.9p2 · CVE-2026-120001, CVE-2026-120002 외 2건<\/p>/);
  assert.match(html, /<p class="pl-sub">CVE-2026-120010<\/p>/);
  assert.match(html, /<a href="\/p\/">모든 제품<\/a><\/nav>/);
  assert.doesNotMatch(html, /최근 고친|newest fixed|<dt>CVE/i); // `fixed` and `cve_count` are the Incident's, not this product's
  const en = await (await render('en', SSH, { [`check/p/${SSH}.json`]: doc })).text();
  assert.match(en, /<dt>Risk<\/dt><dd>Urgent 1 · Elevated 1 · Notice 1<\/dd><dt>Attacked<\/dt><dd>1<\/dd><dt>Newest<\/dt>/);
  assert.match(en, /CVE-2026-120001, CVE-2026-120002 and 2 more/);
  assert.match(en, /<a href="\/en\/p\/">All products<\/a>/);
  const quiet = await (await render('ko', SSH, { [`check/p/${SSH}.json`]: { ...doc, incidents: [DOC.incidents[2]] } })).text();
  assert.doesNotMatch(quiet, /<dt>공격 발생/); // none attacked: no line for it
});
