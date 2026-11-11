// The home page's static text for readers that run no script: the current static shell with the latest Incident links.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { homeLinks, homeResponse } from '../edge/home.mjs';
import { slug, WORDS } from '../web/board.mjs';

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
