// Incident pages (ticket incident-pages/02): a request's slug plus a fake R2 binding in, a Response out.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
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
  assert.equal(html.match(/<script(?! type="application\/ld\+json")/gi).length, 1); // the times' own; the JSON-LD block runs nothing
  assert.equal(html.match(/<h1/g).length, 1);
  assert.match(html, /<h1>OpenSSH sshd 인증 우회 \(sshole\)<\/h1>/);
});

test('a long CVE list shows its first IDs and folds the rest (owner, 11-10: IBM API Connect listed 204)', async () => {
  const cves = Array.from({ length: 25 }, (_, n) => `CVE-2026-${10001 + n}`);
  for (const [lang, more] of [['ko', 'CVE 15건 더 보기'], ['en', '15 more CVE IDs']]) {
    const html = await (await page({ ...SSHOLE, id: cves[0], cves }, lang, cves[0])).text();
    const [open, folded] = html.split('</header>')[1].split('<details');
    assert.equal((open.match(/CVERecord\?id=CVE-2026-1\d{4}"/g) || []).length, 10);
    assert.match(folded, new RegExp(`<summary>${more}</summary>`));
    for (const cve of cves.slice(10)) assert.match(folded, new RegExp(`CVERecord\\?id=${cve}"`)); // still in the HTML
  }
  const few = await (await page(SSHOLE)).text();
  assert.doesNotMatch(few.split('</header>')[1], /<details/); // the header's language menu is one
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

test('a group whose only Mentions are its CVE records keeps the Lead record under Sources, in both languages', async () => {
  const cves = ['CVE-2026-123158', 'CVE-2026-123159', 'CVE-2026-123160'];
  const mentions = cves.map((c) => ({ kind: 'cve_record', url: `https://www.cve.org/CVERecord?id=${c}` }));
  for (const [lang, label] of [['ko', 'CVE 기록'], ['en', 'CVE record']]) {
    const sources = (await (await page({ ...SSHOLE, cves, mentions }, lang)).text()).split('id="s-mentions"')[1];
    assert.ok(sources, lang);
    assert.match(sources, new RegExp(`${label}: <a href="https://www.cve.org/CVERecord\\?id=CVE-2026-123158"`));
    assert.doesNotMatch(sources, /CVE-2026-12315[90]"/); // only the Lead, the rest stay under the CVE list
  }
});

test('the page shows what the Board panel shows, with the Board rules', async () => {
  const html = await (await page(SSHOLE)).text();
  assert.match(html, />긴급</); // riskLevel: KEV
  assert.match(html, /공격 발생/);
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
  assert.match(html, /<time datetime="2026-11-05T10:00:00.000Z">2026-11-05 19:00 KST<\/time>/); // published, Korean time
  assert.match(html, /<time datetime="2026-11-06T00:46:00.000Z">/); // first seen
  assert.match(html, /href="\/#i=CVE-2026-123158"/); // open on the Board
  assert.match(html, /href="\/en\/i\/CVE-2026-123158" hreflang="en" lang="en">English</);
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
  assert.match(exploited, /<small class="why kev">공격 발생<\/small>/);
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
  assert.match(html, /<a href="\/en\/i\/CVE-2026-123158" hreflang="en"/);
  assert.match(await (await page(SSHOLE, 'en')).text(), /<span class="sr-only"> \(opens in a new tab\)<\/span>/);
});

test('each tag links to the Board with that one filter, in the same tab, with a name that says so', async () => {
  const doc = { ...SSHOLE, summary: { ...SSHOLE.summary, devices: ['SonicWall TZ270', '<b>"x</b>'] } };
  const tags = (html) => html.split('<ul class="tags">')[1].split('</ul>')[0];
  const ko = tags(await (await page(doc)).text());
  assert.deepEqual(ko.match(/<a [^>]*>/g), [
    '<a href="/#p=os%3Alinux" aria-label="현황판에서 Linux 사건 보기">',
    '<a href="/#p=openbsd%3Aopenssh" aria-label="현황판에서 OpenSSH 사건 보기">',
    '<a href="/#q=SonicWall+TZ270" aria-label="현황판에서 SonicWall TZ270 사건 보기">',
    '<a href="/#q=%3Cb%3E%22x%3C%2Fb%3E" aria-label="현황판에서 &lt;b&gt;&quot;x&lt;/b&gt; 사건 보기">',
  ]);
  assert.match(ko, /<span class="os">Linux<\/span>/);
  assert.match(ko, /<span style="--line:#[0-9a-f]{6};--line-ink:#[0-9a-f]{6}">OpenSSH<\/span>/);
  assert.match(ko, />&lt;b&gt;&quot;x&lt;\/b&gt;<\/span>/);
  assert.doesNotMatch(ko, /target=|<b>/);
  assert.match(tags(await (await page(doc, 'en')).text()), /aria-label="See OpenSSH Incidents on the Board"/);
});

test('past five tags the page shows the first four and folds the rest, as the Board row does (CVE-2024-36309 had 51)', async () => {
  const names = Array.from({ length: 7 }, (_, k) => `AMD Ryzen ${k + 1}000`);
  const many = { ...SSHOLE, summary: { ...SSHOLE.summary, products: names } }; // Linux + 7 Products: 8 tags
  for (const [lang, more] of [['ko', '나머지 4개 보기'], ['en', 'Show 4 more']]) {
    const products = (await (await page(many, lang)).text()).split('id="s-products"')[1].split('</section>')[0];
    const [open, folded] = products.split('<details');
    assert.equal((open.match(/<a /g) || []).length, 4);
    assert.match(open, /<span class="os">Linux<\/span>[\s\S]*AMD Ryzen 3000/); // operating systems first
    assert.equal((folded.match(/<a /g) || []).length, 4);
    assert.match(folded, new RegExp(`^ class="more"><summary>${more}</summary><ul class="tags">`));
  }
  const few = { ...SSHOLE, summary: { ...SSHOLE.summary, products: names.slice(0, 2) } }; // Linux + 2: 3 tags
  const products = (await (await page(few)).text()).split('id="s-products"')[1].split('</section>')[0];
  assert.equal((products.match(/<a /g) || []).length, 3);
  assert.doesNotMatch(products, /<details/);
});

test('the English page is the English Summary, canonical to itself', async () => {
  const html = await (await page(SSHOLE, 'en')).text();
  assert.match(html, /<html lang="en">/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/en\/i\/CVE-2026-123158">/);
  assert.match(html, /<link rel="alternate" hreflang="x-default" href="https:\/\/patchticker.com\/i\/CVE-2026-123158">/);
  assert.match(html, /<h1>OpenSSH sshd authentication bypass \(sshole\)<\/h1>/);
  assert.match(html, /<meta property="og:locale" content="en_US">/);
  assert.match(html, />Urgent</);
  assert.match(html, /Listed in CISA KEV/);
  assert.match(html, /<time datetime="2026-11-05T10:00:00.000Z">2026-11-05 10:00 UTC<\/time>/);
  assert.match(html.split('</header>')[0], /<summary class="lang" aria-label="Language: English">[\s\S]*?<span class="full">English<\/span><span class="short">EN<\/span><\/summary>/);
  assert.match(html.split('</header>')[0], /<a href="\/i\/CVE-2026-123158" hreflang="ko" lang="ko">한국어<\/a>/);
});

test('where scripts run, the times show in the visitor zone, by the one script the page policy allows by its hash', async () => {
  const res = await page(SSHOLE);
  const script = (await res.text()).match(/<script>([^<]*)<\/script>/)[1];
  // Besides its own script, only the Web Analytics beacon Cloudflare injects (as web/_headers allows on the Board).
  const csp = res.headers.get('content-security-policy');
  assert.equal(csp.match(/script-src ([^;]*)/)[1], `'sha256-${createHash('sha256').update(script).digest('base64')}' https://static.cloudflareinsights.com`);
  assert.equal(csp.match(/connect-src ([^;]*)/)[1], 'https://cloudflareinsights.com');
  const times = ['2026-11-05T10:00:00Z', '2026-11-06T00:46:00Z', 'not a date'].map((dateTime) => ({ dateTime, textContent: 'fixed' }));
  runInNewContext(script, { document: { querySelectorAll: () => times } });
  for (const { dateTime, textContent } of times.slice(0, 2)) { // local time plus its offset is the stamp again
    const [, y, mo, d, h, mi, sign, oh = 0, om = 0] = textContent.match(/^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d) GMT(?:([+-])(\d{1,2})(?::(\d\d))?)?$/);
    assert.equal(Date.UTC(y, mo - 1, d, h, mi) - (sign === '-' ? -1 : 1) * (oh * 60 + +om) * 60000, Date.parse(dateTime), textContent);
  }
  assert.equal(times[2].textContent, 'fixed'); // a time the browser cannot read keeps the server's text
  assert.doesNotMatch(await (await page(null)).text(), /<script/); // the short notes have none
});

test('the header carries the logo home and the language switch; the links row holds the Board and report buttons', async () => {
  const html = await (await page(SSHOLE)).text();
  const header = html.split('</header>')[0].split('<header>')[1];
  assert.match(header, /<a class="brand" href="\/"><svg viewBox="0 0 64 56" aria-hidden="true">[\s\S]*?<\/svg>Patch Ticker<\/a>/);
  // The language menu (owner, 11-17): a details naming the page's language, its list linking this page in every language.
  assert.match(header, /<details class="langs"><summary class="lang" aria-label="언어: 한국어">[\s\S]*?<span class="full">한국어<\/span><span class="short">한<\/span><\/summary>/);
  assert.deepEqual(header.split('<ul>')[1].match(/<a [^>]*>[^<]*/g), ['<a href="/i/CVE-2026-123158" hreflang="ko" lang="ko" aria-current="page">한국어',
    '<a href="/en/i/CVE-2026-123158" hreflang="en" lang="en">English', '<a href="/ja/i/CVE-2026-123158" hreflang="ja" lang="ja">日本語']);
  const links = html.split('<nav class="links"')[1].split('</nav>')[0];
  assert.deepEqual(links.match(/<a href="[^"]*/g).map((a) => a.slice(9).split('?')[0]), ['/#i=CVE-2026-123158', 'https://github.com/dwamaker/PatchTicker/issues/new']);
  assert.doesNotMatch(links, /hreflang/); // the language switch moved up
});

test('the Japanese page is the interface in Japanese with the English Summary, canonical to itself', async () => {
  const html = await (await page(SSHOLE, 'ja')).text();
  assert.match(html, /<html lang="ja">/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/ja\/i\/CVE-2026-123158">/);
  assert.match(html, /<meta property="og:locale" content="ja_JP">/);
  assert.match(html, /<h1>OpenSSH sshd authentication bypass \(sshole\)<\/h1>/); // the English Summary
  assert.match(html, />緊急</);
  assert.match(html, /CISA KEV 掲載/);
  assert.match(html, /<time datetime="2026-11-05T10:00:00.000Z">2026-11-05 19:00 JST<\/time>/);
  assert.match(html, /<span class="full">日本語<\/span>/);
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
  assert.deepEqual(html.match(/<script(?! type="application\/ld\+json")|<img /gi), ['<script']); // the times' own
  const ld = /<script type="application\/ld\+json">([^<]*)<\/script>/.exec(html)[1]; // no '<' at all inside: it cannot close early
  assert.equal(JSON.parse(ld).headline, '</title><script>alert(1)</script>');
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

test('a group page shows each CVE with its one line, the Summary\'s else the record\'s, and a CVE with no line keeps its id (M3)', async () => {
  const cves = Array.from({ length: 14 }, (_, n) => `CVE-2026-${1000 + n}`);
  const lines = [{ cve: cves[0], text: '첫 번째 줄' }];
  const group = { ...SSHOLE, cves, cve_texts: { [cves[1]]: 'Record <b>text</b>', [cves[13]]: 'Last one' },
    summary: { ...SSHOLE.summary, ko: { ...SSHOLE.summary.ko, cve_lines: lines } } };
  const html = await (await page(group)).text();
  assert.match(html, /<ul class="cves lines"><li><strong><a href="https:\/\/www\.cve\.org\/CVERecord\?id=CVE-2026-1000"[^>]*>CVE-2026-1000<span[^>]*>[^<]*<\/span><\/a><\/strong> 첫 번째 줄<\/li>/);
  assert.match(html, /CVE-2026-1001<span[^>]*>[^<]*<\/span><\/a><\/strong> Record &lt;b&gt;text&lt;\/b&gt;<\/li>/); // escaped
  assert.match(html, /<li><a [^>]*>CVE-2026-1002<span[^>]*>[^<]*<\/span><\/a><\/li>/); // no line: the id alone
  assert.match(html, /<details class="more">[\s\S]*CVE-2026-1013<span[^>]*>[^<]*<\/span><\/a><\/strong> Last one<\/li>[\s\S]*<\/details>/); // past the fold too
});

// Step 4 (H3, N1): the three groups of the plan with the keys the collector adds (tests/fixtures/board/step4-groups.json).
const STEP4 = JSON.parse(readFileSync(new URL('./fixtures/board/step4-groups.json', import.meta.url), 'utf8')).groups.map((g) => g.full);
const KEV_LINK = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
const before = (i) => {
  const { cve_scores, kev_cves, top_cve, ...rest } = i;
  const { exploited_cves, ...summary } = i.summary;
  return { ...rest, summary };
};
const cveSection = (html) => html.split('id="s-cves"')[1].split('</section>')[0];

test('the score names its CVE in a group and not in a one-CVE Incident', async () => {
  const [chrome] = STEP4;
  const ko = await (await page(chrome, 'ko', chrome.id)).text();
  assert.match(ko, /aria-label="CVSS 9\.6 \(심각\) · CVE-2026-125345의 점수"/);
  assert.match(ko, /<p class="reason">CVE-2026-125345의 점수: CVSS 9\.6<\/p>/);
  const en = await (await page(chrome, 'en', chrome.id)).text();
  assert.match(en, /<p class="reason">Score of CVE-2026-125345: CVSS 9\.6<\/p>/);
  const one = await (await page({ ...SSHOLE, top_cve: 'CVE-2026-123158', cve_scores: { 'CVE-2026-123158': { cvss: 9.8, vector: 'CVSS:3.1/AV:N' } } })).text();
  assert.doesNotMatch(one, /의 점수/);
});

test('only the exploited CVE wears the mark, with the KEV link, and the reason names it', async () => {
  const [chrome] = STEP4;
  for (const [lang, word, listed] of [['ko', '공격 발생', 'CISA KEV 등재'], ['en', 'Attacked', 'Listed in CISA KEV']]) {
    const html = await (await page(chrome, lang, chrome.id)).text();
    const cves = cveSection(html);
    assert.equal(cves.match(/class="kev"/g).length, 1, lang);
    assert.match(cves, new RegExp(`^[^]*?<li><strong><a href="https://www.cve.org/CVERecord[?]id=CVE-2026-125350"[^]*?</strong> <span class="kev">${word}</span> <a href="${KEV_LINK}"[^>]*>CISA KEV<`)); // the Lead first
    assert.match(html, new RegExp(`<p class="reason">${listed} · 2026-11-10 · CVE-2026-125350</p>`));
  }
  // An attack the Summary's source names: its own link beside the CVE.
  const [, , fortios] = STEP4;
  const told = { ...fortios, summary: { ...fortios.summary, exploited: true, exploited_source: 'https://example.com/attacks', exploited_cves: ['CVE-2026-126255'] } };
  const cves = cveSection(await (await page(told, 'en', told.id)).text());
  assert.match(cves, /CVE-2026-126255<span[^]*?<\/strong> <span class="kev">Attacked<\/span> <a href="https:\/\/example\.com\/attacks"[^>]*>example\.com</);
});

test('a document without the step 4 keys shows no CVE beside the score and no mark', async () => {
  for (const doc of STEP4.map(before)) {
    const html = await (await page(doc, 'ko', doc.id)).text();
    assert.doesNotMatch(html, /의 점수/, doc.id);
    assert.doesNotMatch(cveSection(html), /class="kev"/, doc.id);
    assert.doesNotMatch(html, /<p class="reason">[^<]* · CVE-/, doc.id);
  }
});

// M4 and M1 (owner, 11-15): the Public date among the times, and the other Incidents link under the Mitigation. The
// counts come from board/others.json, read beside the page document (owner, 11-16).
const OTHERS = { since: '2026-10-10T12:00:00Z', counts: { 'openbsd:openssh': 5 } };
const withOthers = (doc, lang, others) => pageResponse(bucket({ 'pages/CVE-2026-123158.json': doc, 'board/others.json': others }), lang, 'CVE-2026-123158', NOW);

test('the page shows the Public date among the times and links the product\'s other Incidents under the Mitigation', async () => {
  const doc = { ...SSHOLE, public_date: '2026-10-30' };
  const ko = await (await withOthers(doc, 'ko', OTHERS)).text();
  const times = ko.slice(ko.indexOf('id="s-times"'));
  assert.match(times, /<p>공개일 2026-10-30<\/p>/);
  const todo = ko.slice(ko.indexOf('id="s-todo"'), ko.indexOf('id="s-products"'));
  // 5 counted, the Incident itself among them (published 11-05, inside the window): 4 others.
  assert.match(todo, /<p class="others"><a href="\/#p=openbsd%3Aopenssh">최근 30일 동안 이 제품의 다른 사건 4건<\/a><\/p><\/section>/);
  const en = await (await withOthers(doc, 'en', OTHERS)).text();
  assert.match(en, /<p>Public date 2026-10-30<\/p>/);
  assert.match(en, />4 other Incidents of this product in the last 30 days<\/a>/);
});

test('the page reads the counts once, and a missing or broken counts document only drops the link', async () => {
  reads.length = 0;
  await withOthers(SSHOLE, 'ko', OTHERS);
  assert.deepEqual(reads, ['pages/CVE-2026-123158.json', 'board/others.json']);
  const broken = { get: async (key) => (key === 'board/others.json' ? { text: async () => '{not json' } : { text: async () => JSON.stringify(SSHOLE) }) };
  const failing = { get: async (key) => { if (key === 'board/others.json') throw new Error('R2 down'); return { text: async () => JSON.stringify(SSHOLE) }; } };
  for (const store of [bucket({ 'pages/CVE-2026-123158.json': SSHOLE }), broken, failing]) {
    const res = await pageResponse(store, 'ko', 'CVE-2026-123158', NOW);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /OpenSSH sshd 인증 우회/);
    assert.doesNotMatch(html, /다른 사건/);
  }
});

test('a page without the new keys, or with unreadable ones, shows neither line', async () => {
  for (const [doc, others] of [[SSHOLE, undefined], [{ ...SSHOLE, public_date: '2026-10-30T00:00:00Z' }, { ...OTHERS, counts: { 'openbsd:openssh': 1 } }]]) {
    const html = await (await withOthers(doc, 'ko', others)).text();
    assert.doesNotMatch(html, /공개일|다른 사건/);
  }
});

// H4 (owner, 11-16): a group's condition of some CVEs only opens with their ids; the page shows them as a mark.
test('a group\'s condition shows the ids it holds for as a mark before its text, and an entry without them as today', async () => {
  const group = { ...SSHOLE, cves: ['CVE-2026-123158', 'CVE-2026-123159', 'CVE-2026-123160'],
    summary: { ...SSHOLE.summary, en: { ...SSHOLE.summary.en, conditions: [
      'CVE-2026-123159, CVE-2026-123160: the renderer process must first be compromised', 'Windows: version 11',
      'CVE-2026-999999: an id not of this Incident'] } } };
  const html = await (await page(group, 'en')).text();
  const conditions = html.slice(html.indexOf('id="s-conditions"'), html.indexOf('id="s-todo"'));
  assert.match(conditions, /<li><span class="cve-src">CVE-2026-123159<\/span>, <span class="cve-src">CVE-2026-123160<\/span> the renderer process must first be compromised<\/li>/);
  assert.match(conditions, /<li>Windows: version 11<\/li>/);
  assert.match(conditions, /<li>CVE-2026-999999: an id not of this Incident<\/li>/);
});

// Step 10 (owner, 11-15/16): the Distribution table, folded under the Mitigation, with its credit line (fixtures/board/distro-case.json).
const DISTRO = JSON.parse(readFileSync(new URL('./fixtures/board/distro-case.json', import.meta.url), 'utf8'));
const todoOf = (html) => html.slice(html.indexOf('id="s-todo"'), html.indexOf('id="s-products"'));

test('the page shows the table folded under the Mitigation in both languages with the credit line under it', async () => {
  const doc = { ...SSHOLE, distro_rows: DISTRO.one.distro_rows, distro_credits: DISTRO.one.distro_credits };
  const ko = todoOf(await (await page(doc, 'ko')).text());
  assert.match(ko, /<details class="more"><summary>배포판별 패키지 \(3\)<\/summary><ul class="cves lines">/);
  assert.ok(ko.indexOf('9.9p2') < ko.indexOf('<details class="more">')); // under the Mitigation
  assert.match(ko, /<li><strong><a href="https:\/\/ubuntu.com\/security\/CVE-2026-123158"[^>]*>Ubuntu 24.04 LTS<span class="sr-only">[^<]*<\/span><\/a><\/strong> openssh · 영향 없음<\/li>/);
  assert.match(ko, />Alpine 3.24<span[^>]*>[^<]*<\/span><\/a><\/strong> openssh · 10.3_p1-r2에서 수정됨<\/li>/);
  assert.match(ko, /openssh · 10\.3_p1-r2에서 수정됨<\/li><\/ul><p class="credits">출처: <a href="https:\/\/security-tracker.debian.org\/tracker\/"[^>]*>Debian Security Tracker<span/);
  assert.match(ko, />Ubuntu Security Notices \(Canonical\)<span[^>]*>[^<]*<\/span><\/a> \(<a href="https:\/\/creativecommons.org\/licenses\/by-sa\/4.0\/"[^>]*>CC BY-SA 4.0<span[^>]*>[^<]*<\/span><\/a>\)<\/p><\/details><\/section>/);
  assert.doesNotMatch(ko, /cve-src/); // one CVE: no ids on a line
  const en = todoOf(await (await page(doc, 'en')).text());
  assert.match(en, /<summary>Distribution packages \(3\)<\/summary>/);
  assert.match(en, /openssh-ssh1 · will not be fixed<\/li>/);
  assert.match(en, /<p class="credits">Sources: /);
});

test('a grouped Incident\'s table keeps each differing version with the ids it holds for', async () => {
  const doc = { ...SSHOLE, cves: DISTRO.group.cves, distro_rows: DISTRO.group.distro_rows, distro_credits: DISTRO.group.distro_credits };
  const en = todoOf(await (await page(doc, 'en')).text());
  assert.match(en, /linux · fixed in 6\.1\.192-1 <span class="cve-src">CVE-2026-99218<\/span><\/li>/);
  assert.match(en, /linux · fixed in 6\.1\.76-1 <span class="cve-src">CVE-2024-1086<\/span><\/li>/);
  assert.match(en, /linux-hwe-6\.2 · will not be fixed<\/li>/); // holds for both: no ids
});

test('a page without the table keys is unchanged, and an unknown state is plain text', async () => {
  const plain = await (await page(SSHOLE, 'ko')).text();
  assert.doesNotMatch(plain, /배포판별|class="credits"/);
  const odd = { ...SSHOLE, distro_rows: [{ label: 'RHEL 9', package: 'openssh', state: '<b>under_review</b>', url: 'javascript:alert(1)' }] };
  const res = await page(odd, 'en');
  assert.equal(res.status, 200);
  const todo = todoOf(await res.text());
  assert.match(todo, /<li><strong>RHEL 9<\/strong> openssh · &lt;b&gt;under_review&lt;\/b&gt;<\/li><\/ul><\/details>/); // no link, no credits
});

// Owner, 11-16: four or more fixed lines show on the page as an aligned list under the Mitigation, five in view.
const withFixes = (n) => ({ ...SSHOLE, summary: { ...SSHOLE.summary, command: '', stopgap: '',
  fixes: Array.from({ length: n }, (_, k) => ({ for: `Windows Server 20${10 + k}`, version: `10.0.${k}.1` })) } });
test('four or more fixed lines are an aligned list, five in view and the rest behind one disclosure', async () => {
  const ko = await (await page(withFixes(17), 'ko')).text();
  const todo = ko.slice(ko.indexOf('id="s-todo"'), ko.indexOf('id="s-products"'));
  assert.match(todo, /<div class="fix-table"><p class="fix-head">제품별 수정 버전<\/p><dl class="fix-list"><dt>Windows Server 2010<\/dt><dd>10\.0\.0\.1 이상<\/dd>/);
  assert.equal((todo.match(/<dt>/g) || []).length, 5);
  assert.equal((todo.match(/<dt class="rest">/g) || []).length, 12);
  // The label follows the state by CSS: "12줄 더 보기" closed, "접기" open.
  assert.match(todo, /<\/dl><details class="more fix-more"><summary><span class="closed">12줄 더 보기<\/span><span class="opened">접기<\/span><\/summary><\/details><\/div>/);
  assert.doesNotMatch(todo, /내 제품에 맞는 버전/); // one list, not two
  const en = await (await page(withFixes(5), 'en')).text();
  assert.match(en, /<p class="fix-head">Fixed version by product<\/p>/);
  assert.match(en, /<dd>10\.0\.4\.1 or later<\/dd><\/dl><\/div>/); // five: all shown, no disclosure
  const three = await (await page(withFixes(3), 'ko')).text();
  assert.doesNotMatch(three, /class="fix-list"/);
  assert.match(three, /<p>내 제품에 맞는 버전 이상으로 업데이트하세요:<\/p><ul><li><strong>Windows Server 2010<\/strong>/); // as before
});

// Owner, 11-17: search engines and agents read what the page states as schema.org data, in a block that runs nothing
// (the CSP's script-src does not apply to it) and holds no '<', so no text from the web or a model can close it.
test('an Incident page states its headline, description, dates, language and address as JSON-LD', async () => {
  const html = await (await page(SSHOLE)).text();
  const ld = JSON.parse(/<script type="application\/ld\+json">([^<]*)<\/script>/.exec(html)[1]);
  assert.deepEqual(ld, { '@context': 'https://schema.org', '@type': 'Article', headline: 'OpenSSH sshd 인증 우회 (sshole)',
    description: '리눅스 서버가 뚫릴 수 있습니다!', datePublished: '2026-11-05T10:00:00Z', dateCreated: '2026-11-06T00:46:00Z', inLanguage: 'ko',
    url: 'https://patchticker.com/i/CVE-2026-123158', mainEntityOfPage: 'https://patchticker.com/i/CVE-2026-123158',
    isAccessibleForFree: true, publisher: { '@type': 'Organization', name: 'Patch Ticker', url: 'https://patchticker.com/' } });
  const en = JSON.parse(/<script type="application\/ld\+json">([^<]*)<\/script>/.exec(await (await page(SSHOLE, 'en')).text())[1]);
  assert.equal(en.inLanguage, 'en');
  assert.equal(en.url, 'https://patchticker.com/en/i/CVE-2026-123158');
});
