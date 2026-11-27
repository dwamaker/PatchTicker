// The home page's static text for readers that run no script: the current static shell with the latest Incident links.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { EN_HEAD, homeLinks, homeResponse } from '../edge/home.mjs';
import { PINNED, WORDS } from '../web/board.mjs';

// app.mjs's TEXT.ko, TEXT.en and TEXT.ja loading words, in that order (app.mjs needs a DOM, so they are read from its source)
const [loadingKo, loadingEn, loadingJa] = [...readFileSync(new URL('../web/app.mjs', import.meta.url), 'utf8').matchAll(/ loading: '([^']+)'/g)].map((m) => m[1]);
const WORDS_APP = { ko: loadingKo, en: loadingEn, ja: loadingJa };

// The list documents the home page reads (collector/cycle.py write_lists): entries: one day's, or null for no documents.
const DAY_1 = '2026-11-27';
const bucket = (entries) => {
  const docs = entries ? { 'lists/index.json': { days: { [DAY_1]: entries.length }, products: [] }, [`lists/d/${DAY_1}.json`]: { day: DAY_1, incidents: entries } } : {};
  return { get: async (key) => (docs[key] ? { text: async () => JSON.stringify(docs[key]) } : null) };
};
const broken = { get: async () => { throw new Error('R2 down'); } };

const SHELL = '<html><head><title>t</title></head><body><main><section id="about"><p>x</p>\n<!--home-links-->\n</section></main></body></html>';
const assets = (status = 200, body = SHELL) => ({
  fetch: async (req) => {
    assert.equal(req.method, 'GET');
    assert.equal(new URL(req.url).pathname, '/');
    assert.equal(req.headers.get('if-none-match'), null);
    return new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'", etag: '"abc"', 'content-length': String(body.length) } });
  },
});
const context = (DATA, method = 'GET', ASSETS = assets()) => ({
  request: new Request('https://patchticker.com/', { method, headers: { 'if-none-match': '"abc"' } }),
  env: { ASSETS, DATA },
  waitUntil: () => {},
});

// A list document's entry (collector/checks.py entry): its page's address and its Korean title.
const incident = (n, title) => ({ id: `CVE-2026-${10000 + n}`, url: `https://patchticker.com/i/CVE-2026-${10000 + n}`, title_ko: title ?? `제목 ${n}`, title_en: `Title ${n}` });

test('homeLinks: the first 20 listed Incidents, linked to their Korean pages under their Korean titles, escaped', async () => {
  const doc = { incidents: [incident(0, '<b>A & "B"</b>'), ...Array.from({ length: 24 }, (_, n) => incident(n + 1))] };
  const html = await homeLinks(doc);
  assert.match(html, /^<h2>최근 주요 보안 사건<\/h2><ul>/);
  const links = [...html.matchAll(/<li><a href="([^"]*)">([^<]*)<\/a><\/li>/g)];
  assert.equal(links.length, 20);
  for (const [k, [, href]] of links.entries()) assert.equal(href, `/i/${doc.incidents[k].id}`);
  assert.equal(links[0][2], '&lt;b&gt;A &amp; &quot;B&quot;&lt;/b&gt;');
  assert.equal(links[1][2], '제목 1');
  assert.equal(await homeLinks({ incidents: [] }), '');
});

// Gemini review, 11-27: the home page linked the RSS feed's Incidents, none of them in a sitemap. Only an entry with its
// own page here is linked (an entry without one has its Board row's address), and the newest days are read in turn.
test('homeLinks links only an entry\'s own page on this site; homeResponse reads the newest days until 20', async () => {
  const row = { id: 'CVE-2026-1', url: 'https://patchticker.com/#i=CVE-2026-1', title_ko: 'row' };
  const away = { id: 'CVE-2026-2', url: 'https://evil.example/i/x', title_ko: 'away' };
  assert.equal(await homeLinks({ incidents: [row, away, incident(3)] }), '<h2>최근 주요 보안 사건</h2><ul><li><a href="/i/CVE-2026-10003">제목 3</a></li></ul>');
  const docs = { 'lists/index.json': { days: { '2026-11-27': 12, '2026-11-26': 12, '2026-11-25': 5 }, products: [] },
    'lists/d/2026-11-27.json': { incidents: Array.from({ length: 12 }, (_, n) => incident(n)) },
    'lists/d/2026-11-26.json': { incidents: Array.from({ length: 12 }, (_, n) => incident(100 + n)) } };
  const read = [];
  const store = { get: async (key) => { read.push(key); return docs[key] ? { text: async () => JSON.stringify(docs[key]) } : null; } };
  const body = await (await homeResponse(context(store))).text();
  const recent = /<h2>최근 주요 보안 사건<\/h2><ul>(.*?)<\/ul>/.exec(body)[1];
  assert.equal([...recent.matchAll(/href="\/i\/CVE-[\d-]+"/g)].length, 20);
  assert.match(recent, /CVE-2026-10011"[^]*CVE-2026-10100"/); // the newest day first
  assert.deepEqual(read, ['lists/index.json', 'lists/d/2026-11-27.json', 'lists/d/2026-11-26.json']); // 2026-11-25 not needed
});

test('homeResponse: the static shell with the list where the marker was; its CSP kept, etag and length dropped', async () => {
  const res = await homeResponse(context(bucket([incident(1)])));
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.doesNotMatch(body, /<!--home-links-->/);
  assert.match(body, /<section id="about"><p>x<\/p>\n<h2>최근 주요 보안 사건<\/h2><ul><li><a href="\/i\/CVE-2026-10001">제목 1<\/a><\/li><\/ul><h2>날짜별·제품별 보안 사건<\/h2>/);
  assert.equal(res.headers.get('content-security-policy'), "default-src 'none'");
  assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(res.headers.get('etag'), null);
  assert.equal(res.headers.get('content-length'), null);
});

test('homeResponse fails open: a store that throws or has no document still opens the Board, without the list', async () => {
  for (const store of [broken, bucket(null)]) {
    const res = await homeResponse(context(store));
    assert.equal(res.status, 200);
    const body = await res.text();
    assert.doesNotMatch(body, /<!--home-links-->|<ul>/);
    assert.match(body, /<section id="about"><p>x<\/p>\n\n<\/section>/);
  }
});

test('homeResponse passes a non-200 asset answer on unchanged', async () => {
  for (const status of [404, 500]) {
    const res = await homeResponse(context(bucket([incident(1)]), 'GET', assets(status, 'nope')));
    assert.equal(res.status, status);
    assert.equal(res.headers.get('etag'), '"abc"');
    assert.equal(await res.text(), 'nope');
  }
});

test('homeResponse: a HEAD gets the status and headers with no body', async () => {
  const res = await homeResponse(context(bucket([incident(1)]), 'HEAD'));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-security-policy'), "default-src 'none'");
  assert.equal(await res.text(), '');
});

test('the real index.html: one marker inside the about section, and the title the script will set anyway', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  assert.equal(html.split('<!--home-links-->').length, 2);
  assert.match(html, /<section id="about">(?:(?!<\/section>)[\s\S])*<!--home-links-->[\s\S]*?<\/section>/);
  assert.equal(/<title>([^<]*)<\/title>/.exec(html)[1], WORDS.ko.title);
});

test('the real index.html: the feed links name no hreflang (a feed is not this page in another language)', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const feeds = html.match(/<link rel="alternate" type="application\/rss\+xml"[^>]*>/g);
  assert.equal(feeds.length, 6); // /feed.xml and the whole-Board /feed/all.xml, each in three languages
  for (const link of feeds) assert.doesNotMatch(link, /hreflang/);
});

// CLS (owner, 11-17): the page paints before app.mjs runs, so the HTML itself holds the loading Board app.mjs then draws
// (render(), placeholder()): the Highlight frames and list rows, the heads' bars, 불러오는 중, the step buttons.
test('the real index.html paints the loading Board, so app.mjs taking over moves nothing', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const part = (id) => new RegExp(`<[a-z0-9]+ id="${id}"[^>]*>([\\s\\S]*?)</(?:ol|div|section|aside|p|h2)>\\r?\\n`).exec(html);
  const skel = '<div class="row"><span class="c-risk"><i class="sk sk-pill"></i></span><span class="c-title"><i class="sk sk-name"></i><i class="sk sk-sub"></i></span>'
    + '<span class="c-score"><i class="sk sk-ring"></i></span><span class="c-tags"><i class="sk sk-tag"></i><i class="sk sk-tag"></i></span>'
    + '<span class="c-date"><i class="sk sk-date"></i><i class="sk sk-time"></i></span></div>';
  // a Highlight opens on its header strip (risk sign and time) over the title, ring and badges (critique P2, 11-19)
  const pinSkel = '<div class="row"><span class="strip"><span class="c-risk"><i class="sk sk-pill"></i></span><span class="c-date"><i class="sk sk-date"></i><i class="sk sk-time"></i></span></span>'
    + '<span class="c-title"><i class="sk sk-name"></i><i class="sk sk-sub"></i></span><span class="c-score"><i class="sk sk-ring"></i></span>'
    + '<span class="c-tags"><i class="sk sk-tag"></i><i class="sk sk-tag"></i></span></div>';
  assert.equal(part('highlights')[1].split(`<li class="alert skel" aria-hidden="true">${pinSkel}</li>`).length - 1, PINNED);
  assert.equal(part('board')[1].split(`<li class="skel" aria-hidden="true">${skel}</li>`).length - 1, 6);
  for (const id of ['pinned', 'primer', 'step']) assert.doesNotMatch(new RegExp(`<[a-z]+ id="${id}"[^>]*>`).exec(html)[0], /\shidden/, id);
  assert.match(html, /<h2 id="pinned-head"><i class="sk sk-head"><\/i><\/h2>/);
  assert.match(html, /<h2 id="all-head" data-t="all" tabindex="-1"><i class="sk sk-head"><\/i><\/h2>/);
  assert.match(html, /<body class="loading">/);
  assert.match(html, new RegExp(`<p id="status"><span lang="ko">${WORDS_APP.ko}</span><span lang="en">${WORDS_APP.en}</span><span lang="ja">${WORDS_APP.ja}</span></p>`));
});

// Owner, 11-17/18 (a line never breaks inside a sentence; no forced breaks): index.html #collect-note and the empty
// search state (app.mjs noticeSince + noticeKeep) say the same sentences, each in its own box, joined by one space.
test('the collection notice in index.html is app.mjs\'s sentences, a box each, in ko, en and ja', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const app = readFileSync(new URL('../web/app.mjs', import.meta.url), 'utf8');
  const note = /<div id="collect-note"[^>]*><p>([\s\S]*?)<\/p>/.exec(html)[1];
  const texts = [...app.matchAll(/noticeSince: \['([^']+)', '([^']+)'\], noticeKeep: '([^']+)'/g)].map((m) => m.slice(1));
  assert.equal(texts.length, 3);
  ['ko', 'en', 'ja'].forEach((lang, n) => {
    const body = new RegExp(`<span lang="${lang}">((?:<span class="sentence">[^<]*</span> ?)+)</span>`).exec(note)[1];
    assert.equal(body, texts[n].map((s) => `<span class="sentence">${s}</span>`).join(' '), lang);
  });
});

// Owner, 11-17: in a Board transition the named rows lay over the frozen search bar. What stays put on screen gets a
// name of its own while one runs (app.mjs adds .vt-board), drawn after the rows, neither faded nor moved.
test('the real stylesheet keeps the frozen bar and the jump group above the rows in a Board transition', () => {
  const html = readFileSync(new URL('../web/board.css', import.meta.url), 'utf8');
  for (const sel of ['#filter', '.search-row', '#jump', '#new-above']) {
    assert.match(html, new RegExp(`\\.vt-board ${sel.replace(/[.#-]/g, '\\$&')} \\{ view-transition-name: vt-[a-z]+; view-transition-class: frozen; \\}`), sel);
  }
  assert.match(html, /:root::view-transition-old\(\*\.frozen\) \{ display: none; \}/);
  assert.match(html, /:root::view-transition-new\(\*\.frozen\), :root::view-transition-group\(\*\.frozen\) \{ animation: none; \}/);
  assert.match(html, /:root::view-transition-group\(\*\.frozen\) \{ z-index: 1; \}/); // the groups' own order drew rows on top
});

test('the real index.html: #about is the last child of <main>, and no top-level <section> is its 12th child', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const main = /<main class="wrap">([\s\S]*?)<\/main>/.exec(html)[1];
  const top = [];
  let depth = 0;
  for (const [tag, close] of main.matchAll(/<(\/?)[a-z][\w-]*[^>]*>/g)) {
    if (close) depth--;
    else {
      if (depth === 0) top.push(tag);
      if (!tag.endsWith('/>') && !tag.startsWith('<input')) depth++;
    }
  }
  assert.equal(depth, 0);
  // a visitor's content blocker hid section:nth-child(12), which the Highlights became when #about stood first (owner, 2026-11-11)
  assert.match(top.at(-1), /^<section id="about">/);
  assert.match(top.at(-2), /id="more"/);
  assert.match(html, /<\/section>\s*<\/main>/);
  for (const [k, tag] of top.entries()) if (tag.startsWith('<section')) assert.notEqual(k + 1, 12, tag);
});

// Owner, 11-17: agents read llms.txt literally, and a crawler followed its old "board/YYYY-MM.json" to a 404. It names no
// placeholder address, and the numbers it states are the code's.
test('llms.txt names no placeholder address, and its feed size and CVE count are the collector\'s', () => {
  const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
  const text = read('web/llms.txt');
  assert.doesNotMatch(text, /YYYY|\{month\}|<month>/);
  for (const url of text.match(/https:\/\/[^\s)`"<>]+/g)) assert.doesNotMatch(url, /YYYY|\{|\}/, url);
  assert.match(text, new RegExp(`newest ${/^FEED_SIZE = (\d+)/m.exec(read('collector/cycle.py'))[1]} Incidents`));
  assert.match(text, new RegExp(`first ${/^CVES_SHOWN = (\d+)/m.exec(read('collector/checks.py'))[1]} \`cves\``));
  assert.match(text, /`detail` \(below\)/);
});

test('the static about block, which only readers without script see, says where the data is in both languages', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const about = /<section id="about">([\s\S]*?)<\/section>/.exec(html)[1];
  assert.match(about, /<p>프로그램과 에이전트용 데이터: <a href="\/llms.txt">llms.txt<\/a>[^\n]*\/api\/check\?products=[^\n]*\/feed.xml\?products=/);
  assert.match(about, /<p lang="en">For programs and agents: <a href="\/llms.txt">llms.txt<\/a>[^\n]*\/api\/check\?products=[^\n]*\/en\/feed.xml\?products=/);
  assert.match(readFileSync(new URL('../web/board.css', import.meta.url), 'utf8'), /\.js #about \{ display: none; \}/); // so a visitor with script never sees it, and nothing moves
});

test('the static data line and llms.txt tell a program to name itself in its User-Agent (Cloudflare refuses urllib\'s default)', () => {
  const about = /<section id="about">([\s\S]*?)<\/section>/.exec(readFileSync(new URL('../web/index.html', import.meta.url), 'utf8'))[1];
  assert.match(about, /User-Agent를 보내세요\(Python urllib 기본값은 403/);
  assert.match(about, /Send a User-Agent that names your client: Python urllib's default one gets 403\./);
  assert.match(readFileSync(new URL('../web/llms.txt', import.meta.url), 'utf8'), /## Start here[\s\S]*Send a User-Agent that names your client[\s\S]*## For agents/);
});

// Owner, 11-17: a program that reads only the home page's headers finds the machine-readable entry points. Registered
// relation types only (RFC 8288 2.1.1, IANA): api-catalog (RFC 9727, its own home-page example), describedby (POWDER:
// "a resource providing information about the link's context") for llms.txt, alternate with the RSS type for the feeds,
// as the page's <link> elements say. Added beside any Link the asset carries (Pages' modulepreload hints).
test('homeResponse adds a Link header to the API catalog, llms.txt and the feeds, keeping the asset\'s own Link', async () => {
  const withLink = { fetch: async () => new Response(SHELL, { headers: { 'content-type': 'text/html; charset=utf-8', link: '<app.mjs>; rel="modulepreload"' } }) };
  for (const method of ['GET', 'HEAD']) {
    const link = (await homeResponse(context(bucket(null), method, withLink))).headers.get('link');
    assert.match(link, /^<app\.mjs>; rel="modulepreload", /);
    assert.match(link, /<\/\.well-known\/api-catalog>; rel="api-catalog"/);
    assert.match(link, /<\/llms\.txt>; rel="describedby"; type="text\/plain"/);
    assert.match(link, /<\/feed\.xml>; rel="alternate"; type="application\/rss\+xml"; title="Patch Ticker \(Korean\)"/);
    assert.match(link, /<\/en\/feed\.xml>; rel="alternate"; type="application\/rss\+xml"; title="Patch Ticker \(English\)"/);
    assert.match(link, /<\/feed\/all\.xml>; rel="alternate"; type="application\/rss\+xml"; title="Patch Ticker, whole Board \(Korean\)"/);
    assert.match(link, /<\/en\/feed\/all\.xml>; rel="alternate"; type="application\/rss\+xml"; title="Patch Ticker, whole Board \(English\)"/);
  }
  assert.match((await homeResponse(context(bucket(null)))).headers.get('link'), /^<\/\.well-known\/api-catalog>/); // no Link on the asset
});

test('the whole-Board feed is named where the other feeds are: the head links, the static line and llms.txt', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  assert.match(html, /<link rel="alternate" type="application\/rss\+xml" title="Patch Ticker 현황판 전체 \(한국어\)" href="\/feed\/all.xml">/);
  assert.match(html, /<link rel="alternate" type="application\/rss\+xml" title="Patch Ticker whole Board \(English\)" href="\/en\/feed\/all.xml">/);
  const about = /<section id="about">([\s\S]*?)<\/section>/.exec(html)[1];
  assert.match(about, /<code>\/feed\/all.xml<\/code>/);
  assert.match(about, /<code>\/en\/feed\/all.xml<\/code>/);
  const llms = readFileSync(new URL('../web/llms.txt', import.meta.url), 'utf8');
  assert.match(llms, /## Feeds[\s\S]*https:\/\/patchticker.com\/feed\/all.xml[\s\S]*newest 600[\s\S]*## Data/);
});

// Owner, 11-27: the list pages linked where a visitor sees them, under the drawn Board (#about is hidden under .js), in
// the page's language, as the collection notice switches.
test('the footer links the day and product lists in each language, and only the page language shows', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const nav = /<p class="foot-nav">([\s\S]*?)<\/p>/.exec(html)[1];
  for (const [lang, prefix] of [['ko', ''], ['en', '/en'], ['ja', '/ja']]) {
    const part = new RegExp(`<span lang="${lang}">([\\s\\S]*?)</span>`).exec(nav)[1];
    assert.deepEqual([...part.matchAll(/href="([^"]+)"/g)].map((m) => m[1]), [`${prefix}/d/`, `${prefix}/p/`], lang);
  }
  assert.match(readFileSync(new URL('../web/board.css', import.meta.url), 'utf8'), /:root:not\(\[lang="en"\]\) :is\(\.collect-note, \.foot-nav,/);
});

// Owner 11-28, Gemini review: the English Board at /en/: the same shell with an English head (canonical /en/, each
// address naming the other with hreflang) and English links; /en without the slash is one 301 away.
test('/en/ is the home page in English: English head and links, the shell otherwise the same', async () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  for (const [ko] of EN_HEAD) assert.ok(html.includes(ko), ko); // every line /en/ rewrites is in index.html
  for (const href of ['https://patchticker.com/', 'https://patchticker.com/en/']) assert.match(html, new RegExp(`<link rel="alternate" hreflang="(ko|en|x-default)" href="${href}">`));
  assert.doesNotMatch(html, / href="(?:app\.mjs|board\.mjs|vendors\.json|favicon\.svg)"| src="app\.mjs"/); // root paths: the shell serves /en/ too
  const shell = assets(200, html);
  const ctx = { ...context(bucket([incident(1)]), 'GET', shell), request: new Request('https://patchticker.com/en/') };
  const body = await (await homeResponse(ctx, 'en')).text();
  assert.match(body, /<html lang="en"/);
  assert.match(body, /<title>Patch Ticker · Live security vulnerability board<\/title>/);
  assert.match(body, /<link rel="canonical" href="https:\/\/patchticker.com\/en\/">/);
  assert.match(body, /<meta property="og:locale" content="en_US">\n  <meta property="og:locale:alternate" content="ko_KR">/);
  assert.doesNotMatch(body, /실시간 보안 취약점 현황판|ko_KR">\n  <meta property="og:locale:alternate" content="en_US"/);
  assert.match(body, /<h2>Latest major security Incidents<\/h2><ul><li><a href="\/en\/i\/CVE-2026-10001">Title 1<\/a><\/li><\/ul>/);
  assert.match(body, /<a href="\/en\/d\/2026-11-27">2026-11-27: 1 security Incidents<\/a>/);
  assert.match(body, /<a href="\/d\/" lang="ko">날짜별 보안 사건<\/a>/);
  const ko = await (await homeResponse({ ...context(bucket([incident(1)]), 'GET', shell) })).text();
  assert.match(ko, /<html lang="ko"/);
  assert.match(ko, /<a href="\/i\/CVE-2026-10001">제목 1<\/a>/);
  const bare = await homeResponse({ ...ctx, request: new Request('https://patchticker.com/en?x=1') }, 'en');
  assert.equal(bare.status, 301);
  assert.equal(bare.headers.get('location'), 'https://patchticker.com/en/?x=1');
});
