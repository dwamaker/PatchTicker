// Incident pages (ticket incident-pages/02): a request's slug plus a fake R2 binding in, a Response out.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { slug } from '../web/board.mjs';
import { pageResponse } from '../edge/page.mjs';
import { cached } from '../edge/shared.mjs';

const NOW = Date.parse('2026-11-09T12:00:00Z');
const reads = [];
const bucket = (docs) => ({ get: async (key) => { reads.push(key); return key in docs ? { text: async () => JSON.stringify(docs[key]) } : null; } });
const page = async (doc, lang = 'ko', name = 'CVE-2026-123158') => pageResponse(bucket({ [`pages/${name}.json`]: doc }), lang, name, NOW);

const SSHOLE = {
  id: 'CVE-2026-123158', cves: ['CVE-2026-123158'], first_seen: '2026-11-06T00:46:00Z', published: '2026-11-05T10:00:00Z', cvss: 9.8,
  kev: true, kev_date: '2026-11-07',
  brief: { text: 'sshole', lead: 'https://www.openssh.com/txt/release-9.9p2' },
  mentions: [
    { kind: 'advisory', url: 'https://www.openssh.com/txt/release-9.9p2', title: 'OpenSSH 9.9p2 release notes' },
    { kind: 'cve_record', url: 'https://www.cve.org/CVERecord?id=CVE-2026-123158' },
    { kind: 'notice', url: 'https://www.boho.or.kr/kr/bbs/view.do?nttId=71234', title: 'OpenSSH 보안 업데이트 권고' },
  ],
  products: [{ id: 'openbsd:openssh', name: 'OpenSSH' }],
  summary: {
    incident: true, products: ['OpenSSH'], platforms: ['Linux'], command: 'sudo apk upgrade openssh', fixed: '9.9p2', stopgap: 'PasswordAuthentication no', stopgap_file: '/etc/ssh/sshd_config',
    ko: { title: 'OpenSSH sshd 인증 우회 (sshole)', easy: '리눅스 서버가 뚫릴 수 있습니다!', summary: 'musl 기반에서만 해당합니다.', conditions: ['Alpine 리눅스에서 sshd를 켜 둔 경우'], mitigation: '9.9p2로 업데이트하세요.' },
    en: { title: 'OpenSSH sshd authentication bypass (sshole)', easy: 'Linux servers can be broken into!', summary: 'Only musl-based systems.', conditions: ['sshd runs on Alpine Linux'], mitigation: 'Update to 9.9p2.' },
  },
};
const NOTICE = { ...SSHOLE, id: 'CVE-2026-55555', cves: ['CVE-2026-55555'], cvss: 5.3, kev: false, kev_date: undefined };

test('slugs match the collector: one shared fixture', async () => {
  const kase = JSON.parse(readFileSync(new URL('./fixtures/board/slug-case.json', import.meta.url), 'utf8'));
  for (const c of kase.cases) assert.equal(await slug(c.id), c.slug, c.id);
});

test('the Korean page names itself canonical, links the English one and previews the Incident', async () => {
  const res = await page(SSHOLE);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.match(res.headers.get('cache-control'), /public, max-age=300/);
  const html = await res.text();
  assert.match(html, /<html lang="ko">/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/i\/CVE-2026-123158">/);
  assert.match(html, /<link rel="alternate" hreflang="ko" href="https:\/\/patchticker.com\/i\/CVE-2026-123158">/);
  assert.match(html, /<link rel="alternate" hreflang="en" href="https:\/\/patchticker.com\/en\/i\/CVE-2026-123158">/);
  assert.match(html, /<link rel="alternate" hreflang="x-default" href="https:\/\/patchticker.com\/i\/CVE-2026-123158">/);
  assert.match(html, /<meta property="og:title" content="OpenSSH sshd 인증 우회 \(sshole\)">/);
  assert.match(html, /<meta property="og:description" content="리눅스 서버가 뚫릴 수 있습니다!">/);
  assert.match(html, /<meta property="og:image" content="https:\/\/patchticker.com\/og.png">/);
  assert.match(html, /<meta property="og:locale" content="ko_KR">/);
  assert.doesNotMatch(html, /noindex/); // exploited: search-worthy
  assert.doesNotMatch(html, /<script/i);
  assert.equal(html.match(/<h1/g).length, 1);
  assert.match(html, /<h1>OpenSSH sshd 인증 우회 \(sshole\)<\/h1>/);
});

test('a long CVE list shows its first IDs and folds the rest (owner, 11-10: IBM API Connect listed 204)', async () => {
  const cves = Array.from({ length: 25 }, (_, n) => `CVE-2026-${10001 + n}`);
  for (const [lang, more] of [['ko', 'CVE 15건 더 보기'], ['en', '15 more CVE IDs']]) {
    const html = await (await page({ ...SSHOLE, id: cves[0], cves }, lang, cves[0])).text();
    const [open, folded] = html.split('<details');
    assert.equal((open.match(/CVERecord\?id=CVE-2026-1\d{4}"/g) || []).length, 10);
    assert.match(folded, new RegExp(`<summary>${more}</summary>`));
    for (const cve of cves.slice(10)) assert.match(folded, new RegExp(`CVERecord\\?id=${cve}"`)); // still in the HTML
  }
  const few = await (await page(SSHOLE)).text();
  assert.doesNotMatch(few, /<details/);
});

test('a CVE record the CVE list already links is not listed again under Sources', async () => {
  const other = 'https://nvd.nist.gov/vuln/detail/CVE-2026-123158';
  const cves = ['CVE-2026-123158', 'CVE-2026-123159', 'CVE-2026-123160']; // a group: more than two, as on the Board
  const html = await (await page({ ...SSHOLE, cves, mentions: [...SSHOLE.mentions, { kind: 'cve_record', url: other }] })).text();
  const sources = html.split('id="s-mentions"')[1];
  assert.doesNotMatch(sources, /cve\.org\/CVERecord/); // already under CVE 번호
  assert.match(sources, /CVE 기록: <a href="https:\/\/nvd\.nist\.gov/); // a record elsewhere stays
});

test('a one-CVE Incident whose only Mention is its CVE record still shows Sources', async () => {
  const html = await (await page({ ...SSHOLE, mentions: [{ kind: 'cve_record', url: 'https://www.cve.org/CVERecord?id=CVE-2026-123158' }] })).text();
  assert.match(html, /id="s-mentions"/);
  assert.match(html.split('id="s-mentions"')[1], /CVE 기록: <a href="https:\/\/www.cve.org\/CVERecord\?id=CVE-2026-123158"/);
});

test('the page shows what the Board panel shows, with the Board rules', async () => {
  const html = await (await page(SSHOLE)).text();
  assert.match(html, />고위험</); // riskLevel: KEV
  assert.match(html, /악용 발생/);
  assert.match(html, /CISA KEV 등재 · 2026-11-07/); // exploitReason
  assert.match(html, /9\.8/);
  assert.match(html, /musl 기반에서만 해당합니다\./);
  assert.match(html, /Alpine 리눅스에서 sshd를 켜 둔 경우/);
  assert.match(html, /<code>sudo apk upgrade openssh<\/code>/); // easyAction: the command
  assert.match(html, /<code>PasswordAuthentication no<\/code>/); // the stopgap, a config line
  assert.match(html, /\/etc\/ssh\/sshd_config/);
  assert.match(html, />Linux</);
  assert.match(html, />OpenSSH</);
  assert.match(html, /href="https:\/\/www.cve.org\/CVERecord\?id=CVE-2026-123158"/);
  assert.match(html, /보호나라 공지[\s\S]*OpenSSH 보안 업데이트 권고/); // the KISA notice among the Mentions
  assert.match(html, /<time datetime="2026-11-05T10:00:00Z">2026-11-05 19:00/); // published, Korean time
  assert.match(html, /<time datetime="2026-11-06T00:46:00Z">/); // first seen
  assert.match(html, /href="\/#i=CVE-2026-123158"/); // open on the Board
  assert.match(html, /href="\/en\/i\/CVE-2026-123158" hreflang="en" lang="en" aria-label="English"><span class="full">English</);
  assert.match(html, /href="https:\/\/github.com\/dwamaker\/PatchTicker\/issues\/new\?[^"]*"/);
  assert.match(html, /NVD API/);
  assert.match(html, /The MITRE Corporation/);
  assert.match(html, /<p class="reason">CISA KEV 등재/); // a reason in Secondary Ink, not red
  assert.match(html, /<ul class="cves"><li><a href="https:\/\/www.cve.org\/CVERecord\?id=CVE-2026-123158"/); // the CVE IDs in their own list
});

test('no score and no exploit: the sign is dashed and says the score is pending, as on the Board (critique 13)', async () => {
  const unrated = { ...NOTICE, cvss: undefined };
  const ko = await (await page(unrated, 'ko', 'CVE-2026-55555')).text();
  assert.match(ko, /<div class="banner risk-notice unrated">/);
  assert.match(ko, /<small class="why unrated">점수 대기<\/small>/);
  assert.match(await (await page(unrated, 'en', 'CVE-2026-55555')).text(), /<small class="why unrated">Score pending<\/small>/);
  const exploited = await (await page({ ...SSHOLE, cvss: undefined })).text();
  assert.doesNotMatch(exploited, /class="why unrated"|class="banner[^"]*unrated/); // the ring alone still says "CVSS 점수 대기"
  assert.match(exploited, /<small class="why kev">악용 발생<\/small>/);
});

test('public exploit code is the one red reason line (critique 14)', async () => {
  const html = await (await page({ ...NOTICE, summary: { ...NOTICE.summary, poc_public: true } }, 'ko', 'CVE-2026-55555')).text();
  assert.match(html, /<p class="reason kev">/);
});

test('source links open in a new tab and say so, as on the Board; the Board and language links stay in the tab', async () => {
  const html = await (await page(SSHOLE)).text();
  assert.match(html, /<a href="https:\/\/www.openssh.com\/txt\/release-9.9p2" target="_blank" rel="noopener noreferrer">OpenSSH 9.9p2 release notes<span class="sr-only"> \(새 탭에서 열림\)<\/span><\/a>/);
  assert.match(html, /<a href="https:\/\/www.cve.org\/CVERecord\?id=CVE-2026-123158" target="_blank" rel="noopener noreferrer">CVE-2026-123158</);
  assert.match(html, /<a href="https:\/\/github.com\/dwamaker\/PatchTicker\/issues\/new\?[^"]*" target="_blank" rel="noopener noreferrer"><svg [^>]*aria-hidden="true">[\s\S]*?<\/svg>틀린 내용 알리기</);
  assert.match(html, /<a href="\/#i=CVE-2026-123158">/);
  assert.match(html, /<a class="lang" href="\/en\/i\/CVE-2026-123158" hreflang="en"/);
  assert.match(await (await page(SSHOLE, 'en')).text(), /<span class="sr-only"> \(opens in a new tab\)<\/span>/);
});

test('the English page is the English Summary, canonical to itself', async () => {
  const html = await (await page(SSHOLE, 'en')).text();
  assert.match(html, /<html lang="en">/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/en\/i\/CVE-2026-123158">/);
  assert.match(html, /<link rel="alternate" hreflang="x-default" href="https:\/\/patchticker.com\/i\/CVE-2026-123158">/);
  assert.match(html, /<h1>OpenSSH sshd authentication bypass \(sshole\)<\/h1>/);
  assert.match(html, /<meta property="og:locale" content="en_US">/);
  assert.match(html, />High risk</);
  assert.match(html, /Listed in CISA KEV/);
  assert.match(html, /<time datetime="2026-11-05T10:00:00Z">2026-11-05 10:00 UTC/);
  assert.match(html.split('</header>')[0], /<a class="lang" href="\/i\/CVE-2026-123158" hreflang="ko" lang="ko" aria-label="한국어"><span class="full">한국어<\/span><span class="short">한<\/span><\/a>/);
});

test('the header carries the logo home and the language switch; the links row holds the Board and report buttons', async () => {
  const html = await (await page(SSHOLE)).text();
  const header = html.split('</header>')[0].split('<header>')[1];
  assert.match(header, /<a class="brand" href="\/"><svg viewBox="0 0 64 56" aria-hidden="true">[\s\S]*?<\/svg>Patch Ticker<\/a>/);
  assert.match(header, /<a class="lang" href="\/en\/i\/CVE-2026-123158" hreflang="en" lang="en" aria-label="English"><span class="full">English<\/span><span class="short">EN<\/span><\/a>/);
  const links = html.split('<nav class="links"')[1].split('</nav>')[0];
  assert.deepEqual(links.match(/<a href="[^"]*/g).map((a) => a.slice(9).split('?')[0]), ['/#i=CVE-2026-123158', 'https://github.com/dwamaker/PatchTicker/issues/new']);
  assert.doesNotMatch(links, /hreflang/); // the language switch moved up
});

test('a note (404) keeps the logo header but has no language switch', async () => {
  const html = await (await pageResponse(bucket({}), 'ko', 'CVE-2026-99999', NOW)).text();
  assert.match(html, /<header><div class="wrap"><a class="brand" href="\/"><svg viewBox="0 0 64 56"[\s\S]*?Patch Ticker<\/a><\/div><\/header>/);
  assert.doesNotMatch(html, /hreflang|class="lang"/);
});

test('a 참고 page with a CVE is for sharing only: noindex', async () => {
  const html = await (await page(NOTICE, 'ko', 'CVE-2026-55555')).text();
  assert.match(html, /<meta name="robots" content="noindex">/);
  assert.match(html, />참고</);
});

test('hostile text is escaped and only http(s) links are kept', async () => {
  const hostile = {
    ...SSHOLE, kev: false,
    mentions: [{ kind: 'advisory', url: 'javascript:alert(1)', title: 'click me' }, { kind: 'writeup', url: 'https://example.com/"><script>x</script>', title: '<img src=x onerror=alert(1)>' }],
    summary: { ...SSHOLE.summary, exploited: true, exploited_source: 'javascript:alert(2)', ko: { ...SSHOLE.summary.ko, title: '</title><script>alert(1)</script>', easy: '"><script>alert(3)</script>' } },
  };
  const html = await (await page(hostile)).text();
  assert.doesNotMatch(html, /<script|<img /i);
  assert.doesNotMatch(html, /javascript:/i);
  assert.match(html, /&lt;\/title&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /href="https:\/\/example.com\/&quot;&gt;&lt;script&gt;x&lt;\/script&gt;"/);
});

test('410 past 90 days from first seen, with the Board and the CVE record', async () => {
  const res = await page({ ...SSHOLE, first_seen: '2026-08-10T00:00:00Z' });
  assert.equal(res.status, 410);
  const html = await res.text();
  assert.match(html, /보관 기간 90일이 지났어요/);
  assert.match(html, /href="\/#i=CVE-2026-123158"/);
  assert.match(html, /href="https:\/\/www.cve.org\/CVERecord\?id=CVE-2026-123158"/);
  assert.match(html, /noindex/);
  assert.equal((await page({ ...SSHOLE, first_seen: '2026-08-12T00:00:00Z' })).status, 200);
});

test('404 for an unknown slug, a malformed one (no store read) and an Incident that is not on the Board', async () => {
  assert.equal((await pageResponse(bucket({}), 'ko', 'CVE-2026-99999', NOW)).status, 404);
  reads.length = 0;
  assert.equal((await pageResponse(bucket({}), 'en', '../board/feed', NOW)).status, 404);
  assert.deepEqual(reads, []);
  const essay = { ...SSHOLE, id: 'https://news.ycombinator.com/item?id=77', cves: [], summary: { ...SSHOLE.summary, incident: false } };
  assert.equal((await page(essay, 'ko', 'hn-77')).status, 404);
  assert.equal((await page({ ...SSHOLE, summary: undefined })).status, 404);
});

// Ticket incident-pages/04: the collector leaves this in place of an absorbed Incident's page.
const MOVED = { id: 'CVE-2026-1002', moved_to: 'CVE-2026-123158', moved_to_id: 'CVE-2026-123158', moved: '2026-11-08T00:00:00Z' };
const moved = (doc, target = SSHOLE, lang = 'ko') => pageResponse(bucket({ 'pages/CVE-2026-1002.json': doc, ...(target ? { 'pages/CVE-2026-123158.json': target } : {}) }), lang, 'CVE-2026-1002', NOW);

test('a merged Incident answers 301 to the survivor in the same language', async () => {
  const ko = await moved(MOVED);
  assert.equal(ko.status, 301);
  assert.equal(ko.headers.get('location'), 'https://patchticker.com/i/CVE-2026-123158');
  const en = await moved(MOVED, SSHOLE, 'en');
  assert.equal(en.status, 301);
  assert.equal(en.headers.get('location'), 'https://patchticker.com/en/i/CVE-2026-123158');
});

test('410 when the move or the survivor is past 90 days', async () => {
  for (const [doc, target] of [[{ ...MOVED, moved: '2026-08-10T00:00:00Z' }, SSHOLE], [MOVED, { ...SSHOLE, first_seen: '2026-08-10T00:00:00Z' }]]) {
    const res = await moved(doc, target);
    assert.equal(res.status, 410);
    const html = await res.text();
    assert.match(html, /보관 기간 90일이 지났어요/);
    assert.match(html, /noindex/);
  }
  assert.equal((await moved({ ...MOVED, moved: '2026-08-12T00:00:00Z' })).status, 301);
});

test('302 to the survivor on the Board while the survivor has no page yet (owner, 11-10)', async () => {
  const story = { ...MOVED, moved_to: 'hn-77', moved_to_id: 'https://news.ycombinator.com/item?id=77' };
  for (const [doc, target] of [[MOVED, null], [MOVED, { ...SSHOLE, summary: undefined }], [story, null]]) {
    const res = await moved(doc, target, 'en');
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), `https://patchticker.com/#i=${encodeURIComponent(doc.moved_to_id)}`);
    assert.match(res.headers.get('cache-control'), /public, max-age=300/);
  }
});

test('a moved document never renders as a page, and a malformed target is never read', async () => {
  reads.length = 0;
  const res = await moved({ ...MOVED, moved_to: '../board/feed' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://patchticker.com/#i=CVE-2026-123158');
  assert.deepEqual(reads, ['pages/CVE-2026-1002.json']);
});

test('503 when the store cannot be read', async () => {
  const res = await pageResponse({ get: async () => { throw new Error('R2 down'); } }, 'ko', 'CVE-2026-123158', NOW);
  assert.equal(res.status, 503);
  assert.equal(res.headers.get('cache-control'), null);
  assert.match(await res.text(), /patchticker.com/);
});

test('503, never a runtime error or half a page, for a document the page cannot use', async () => {
  for (const doc of [{ ...SSHOLE, mentions: undefined }, { ...SSHOLE, cves: 'CVE-2026-123158' }, { ...MOVED, moved_to_id: undefined }]) {
    const res = await page(doc, 'ko', 'CVE-2026-1002');
    assert.equal(res.status, 503);
    assert.match(await res.text(), /지금은 사건 페이지를 불러올 수 없습니다/);
  }
});

test('expired, missing and moved answers carry a short cache time too, a 404 the shortest', async () => {
  const age = async (res) => Number(/max-age=(\d+)/.exec(res.headers.get('cache-control'))[1]);
  assert.equal(await age(await page({ ...SSHOLE, first_seen: '2026-08-10T00:00:00Z' })), 300);
  assert.equal(await age(await pageResponse(bucket({}), 'ko', 'CVE-2026-99999', NOW)), 60);
  assert.equal(await age(await pageResponse(bucket({}), 'ko', '../x', NOW)), 60);
  assert.equal(await age(await moved(MOVED)), 300);
});

test('the edge cache keeps 200, 301, 302, 404 and 410 answers, never a 503', async () => {
  const stored = [];
  const saved = globalThis.caches;
  globalThis.caches = { default: { match: async () => undefined, put: async (req, res) => { stored.push(res.status); } } };
  try {
    for (const status of [200, 301, 302, 404, 410, 503]) {
      const pending = [];
      const res = await cached({ request: new Request('https://patchticker.com/i/x'), waitUntil: (p) => pending.push(p) }, async () => new Response(null, { status }));
      await Promise.all(pending);
      assert.equal(res.status, status);
    }
  } finally {
    globalThis.caches = saved;
  }
  assert.deepEqual(stored, [200, 301, 302, 404, 410]);
});

// HEAD (link checkers, feed validators, preview bots): every entry file answers it as GET does, without the body.
// Without a HEAD handler Pages served index.html for it: 200, text/html, for a feed, a sitemap or an unknown slug.
const entry = async (path) => (await import(`../functions/${path}`));
const context = (url, method, docs, params = {}) => ({ request: new Request(url, { method }), env: { DATA: bucket(docs) }, params, waitUntil: () => {} });
async function headLikeGet(path, url, docs, params) {
  const fn = await entry(path);
  const get = await fn.onRequestGet(context(url, 'GET', docs, params));
  const head = await fn.onRequestHead(context(url, 'HEAD', docs, params));
  assert.equal(head.status, get.status, url);
  assert.deepEqual([...head.headers], [...get.headers], url);
  assert.equal(await head.text(), '', url);
  return get;
}

test('HEAD answers as GET does, without the body, on every function', async () => {
  const today = new Date().toISOString(); // the entry files render at the real time
  const live = { ...SSHOLE, first_seen: today };
  const feed = { 'board/feed.json': { incidents: [live] } };
  for (const [path, url] of [['feed.xml.js', 'https://patchticker.com/feed.xml'], ['en/feed.xml.js', 'https://patchticker.com/en/feed.xml']]) {
    const get = await headLikeGet(path, url, feed);
    assert.equal(get.status, 200);
    assert.match(get.headers.get('content-type'), /xml/);
  }
  const sitemap = await headLikeGet('sitemaps/[name].js', 'https://patchticker.com/sitemaps/incidents-0.xml',
    { 'sitemap.json': { pages: { 'CVE-2026-123158': { first_seen: today, changed: today } } } }, { name: 'incidents-0.xml' });
  assert.equal(sitemap.status, 200);
  assert.match(await sitemap.text(), /CVE-2026-123158/);
  const docs = { 'pages/CVE-2026-123158.json': live, 'pages/CVE-2026-1002.json': { ...MOVED, moved: today } };
  for (const [path, url, name, status] of [
    ['i/[slug].js', 'https://patchticker.com/i/CVE-2026-123158', 'CVE-2026-123158', 200],
    ['en/i/[slug].js', 'https://patchticker.com/en/i/CVE-2026-123158', 'CVE-2026-123158', 200],
    ['i/[slug].js', 'https://patchticker.com/i/CVE-2026-99999', 'CVE-2026-99999', 404],
    ['i/[slug].js', 'https://patchticker.com/i/CVE-2026-1002', 'CVE-2026-1002', 301],
  ]) assert.equal((await headLikeGet(path, url, docs, { slug: name })).status, status, url);
  assert.equal((await headLikeGet('feed.xml.js', 'https://patchticker.com/feed.xml', {})).status, 503); // Retry-After too
});

test('a HEAD shares the cache entry of a GET, and never stores a bodiless answer', async () => {
  // As the Workers Cache API: put() refuses anything but GET, match() finds GETs only.
  const store = new Map();
  const saved = globalThis.caches;
  globalThis.caches = { default: {
    match: async (req) => (req.method === 'GET' ? store.get(req.url)?.clone() : undefined),
    put: async (req, res) => { if (req.method !== 'GET') throw new TypeError('Cannot cache a non-GET request'); store.set(req.url, res); },
  } };
  try {
    let renders = 0;
    const render = async () => { renders += 1; return new Response('<rss/>', { headers: { 'content-type': 'application/rss+xml' } }); };
    const ask = async (method) => {
      const pending = [];
      const res = await cached({ request: new Request('https://patchticker.com/feed.xml', { method }), waitUntil: (p) => pending.push(p) }, render);
      await Promise.all(pending);
      return res;
    };
    assert.equal(await (await ask('HEAD')).text(), '');
    assert.equal(await (await ask('GET')).text(), '<rss/>'); // what the HEAD stored is the full answer
    assert.equal(await (await ask('HEAD')).text(), '');
    assert.equal(renders, 1);
    assert.equal((await ask('HEAD')).headers.get('content-type'), 'application/rss+xml');
  } finally {
    globalThis.caches = saved;
  }
});
