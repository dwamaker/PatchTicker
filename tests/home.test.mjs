// The home page's static text for readers that run no script: the current static shell with the latest Incident links.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { homeLinks, homeResponse } from '../edge/home.mjs';
import { PINNED, slug, WORDS } from '../web/board.mjs';

// app.mjs's TEXT.ko, TEXT.en and TEXT.ja loading words, in that order (app.mjs needs a DOM, so they are read from its source)
const [loadingKo, loadingEn, loadingJa] = [...readFileSync(new URL('../web/app.mjs', import.meta.url), 'utf8').matchAll(/ loading: '([^']+)'/g)].map((m) => m[1]);
const WORDS_APP = { ko: loadingKo, en: loadingEn, ja: loadingJa };

const bucket = (doc) => ({ get: async (key) => (key === 'board/feed.json' && doc ? { text: async () => JSON.stringify(doc) } : null) });
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

const incident = (n, title) => ({ id: `CVE-2026-${10000 + n}`, cves: [`CVE-2026-${10000 + n}`], brief: { text: `brief ${n}` }, summary: { ko: { title: title ?? `제목 ${n}` }, en: { title: `Title ${n}` } } });

test('homeLinks: the first 20 Incidents, linked to their Korean pages under their Korean titles, escaped', async () => {
  const doc = { incidents: [incident(0, '<b>A & "B"</b>'), ...Array.from({ length: 24 }, (_, n) => incident(n + 1))] };
  const html = await homeLinks(doc);
  assert.match(html, /^<h2>최근 주요 보안 사건<\/h2><ul>/);
  const links = [...html.matchAll(/<li><a href="([^"]*)">([^<]*)<\/a><\/li>/g)];
  assert.equal(links.length, 20);
  for (const [k, [, href]] of links.entries()) assert.equal(href, `/i/${await slug(doc.incidents[k].id)}`);
  assert.equal(links[0][2], '&lt;b&gt;A &amp; &quot;B&quot;&lt;/b&gt;');
  assert.equal(links[1][2], '제목 1');
  assert.equal(await homeLinks({ incidents: [] }), '');
});

test('homeResponse: the static shell with the list where the marker was; its CSP kept, etag and length dropped', async () => {
  const res = await homeResponse(context(bucket({ incidents: [incident(1)] })));
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.doesNotMatch(body, /<!--home-links-->/);
  assert.match(body, /<section id="about"><p>x<\/p>\n<h2>최근 주요 보안 사건<\/h2><ul><li><a href="\/i\/CVE-2026-10001">제목 1<\/a><\/li><\/ul>\n<\/section>/);
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
    const res = await homeResponse(context(bucket({ incidents: [incident(1)] }), 'GET', assets(status, 'nope')));
    assert.equal(res.status, status);
    assert.equal(res.headers.get('etag'), '"abc"');
    assert.equal(await res.text(), 'nope');
  }
});

test('homeResponse: a HEAD gets the status and headers with no body', async () => {
  const res = await homeResponse(context(bucket({ incidents: [incident(1)] }), 'HEAD'));
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
  assert.equal(part('highlights')[1].split(`<li class="alert skel" aria-hidden="true">${skel}</li>`).length - 1, PINNED);
  assert.equal(part('board')[1].split(`<li class="skel" aria-hidden="true">${skel}</li>`).length - 1, 6);
  for (const id of ['pinned', 'primer', 'step']) assert.doesNotMatch(new RegExp(`<[a-z]+ id="${id}"[^>]*>`).exec(html)[0], /\shidden/, id);
  assert.match(html, /<h2 id="pinned-head"><i class="sk sk-head"><\/i><\/h2>/);
  assert.match(html, /<h2 id="all-head" data-t="all" tabindex="-1"><i class="sk sk-head"><\/i><\/h2>/);
  assert.match(html, /<body class="loading">/);
  assert.match(html, new RegExp(`<p id="status"><span lang="ko">${WORDS_APP.ko}</span><span lang="en">${WORDS_APP.en}</span><span lang="ja">${WORDS_APP.ja}</span></p>`));
});

// Owner, 11-17: in a Board transition the named rows lay over the frozen search bar. What stays put on screen gets a
// name of its own while one runs (app.mjs adds .vt-board), drawn after the rows, neither faded nor moved.
test('the real index.html keeps the frozen bar and the jump group above the rows in a Board transition', () => {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
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
  assert.match(html, /\.js #about \{ display: none; \}/); // so a visitor with script never sees it, and nothing moves
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

