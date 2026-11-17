// The Board page's security headers (web/_headers, audit 13 follow-up): the CSP must keep allowing what index.html runs.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { withJapanese } from '../web/board.mjs';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8').replace(/\r\n/g, '\n'); // the HTML parser reads CRLF as LF
const html = read('web/index.html');
const headers = read('web/_headers');
const value = (name) => new RegExp(`^\\s+${name}:\\s*(.+)$`, 'im').exec(headers)?.[1] ?? '';
const csp = Object.fromEntries(value('Content-Security-Policy').split(';').map((d) => d.trim().split(/\s+/)).map(([k, ...v]) => [k, v]));
const hash = (text) => `'sha256-${createHash('sha256').update(text).digest('base64')}'`;

test('every inline script and style block of index.html is allowed by its hash, and nothing else inline is', () => {
  const scripts = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  const styles = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)].map((m) => m[1]);
  assert.ok(scripts.length && styles.length);
  for (const s of scripts) assert.ok(csp['script-src'].includes(hash(s)), `script-src lacks ${hash(s)}`);
  for (const s of styles) assert.ok(csp['style-src'].includes(hash(s)), `style-src lacks ${hash(s)}`);
  assert.ok(!csp['script-src'].includes("'unsafe-inline'") && !csp['style-src'].includes("'unsafe-inline'"));
  assert.doesNotMatch(html, /\son[a-z]+=|\sstyle=/i); // a handler or style attribute would need 'unsafe-inline'
});

test("the CSP lets the page load its modules, its data hosts and the analytics beacon, and nothing frames it", () => {
  assert.deepEqual(csp['default-src'], ["'none'"]);
  assert.ok(csp['script-src'].includes("'self'"));
  for (const host of read('web/app.mjs').match(/DATA_URL = [\s\S]*?;/)[0].match(/https:\/\/[a-z.-]+/g)) {
    assert.ok(csp['connect-src'].includes(host), host);
  }
  assert.ok(csp['connect-src'].includes("'self'")); // vendors.json is a JSON module: connect-src
  assert.match(html, /<link rel="modulepreload" href="vendors\.json" as="json">/); // else it waits for board.mjs (11-10)
  assert.ok(csp['img-src'].includes("'self'")); // favicon.svg
  assert.deepEqual(csp['frame-ancestors'], ["'none'"]);
  assert.equal(value('X-Content-Type-Options'), 'nosniff');
  assert.equal(value('Referrer-Policy'), 'strict-origin-when-cross-origin');
  assert.equal(value('Permissions-Policy'), 'camera=(), microphone=(), geolocation=()');
});

test("the inline script starts the first load's four files, and getJson takes each once; main drops the rest", async () => {
  const vm = await import('node:vm');
  const calls = [];
  const limits = {};
  let ms; // getJson's time limit, set just before its fetch
  const fetch = (url, { signal }) => { limits[url] = signal.ms ?? ms; const n = calls.push(url); return Promise.resolve({ ok: true, text: async () => JSON.stringify({ url, n }) }); };
  const added = [];
  const ctx = vm.createContext({ location: { hostname: 'localhost' }, fetch, AbortSignal: { timeout: (t) => ({ ms: t }) }, AbortController, withJapanese,
    setTimeout: (f, t) => { ms = t; }, clearTimeout() {}, navigator: { language: 'ko-KR' },
    document: { documentElement: { dataset: { collectedSince: '2026-11-09' }, classList: { add: (c) => added.push(c) } } } });
  ctx.window = ctx;
  vm.runInContext(html.match(/<script>([^<]*vrEarly[^<]*)<\/script>/)[1], ctx);
  // hides the no-script about text before the first paint; the collection notice goes past its 90 days (cn-off); with
  // no storage the first-visit line is not drawn (pr-off), as app.mjs's primerOpen = !stored(SAVED_GUIDE, true)
  assert.deepEqual(added.filter((c) => c !== 'cn-off'), ['js', 'pr-off']);
  assert.equal(ctx.document.documentElement.lang, 'ko'); // the notice paints in the visitor's language
  assert.deepEqual(Object.keys(ctx.vrEarly).sort(), ['data/board/products.json', 'data/board/rows.json', 'data/index.json', 'data/status.json']);
  const app = read('web/app.mjs');
  const getJson = vm.runInContext(`const DATA_URL = 'data/'; ${app.match(/const SLOW_MS[\s\S]*?\n\};/)[0]} getJson`, ctx);
  assert.equal((await getJson('status.json')).n, 2); // the page-start fetch
  assert.equal((await getJson('status.json')).n, 5); // asked again
  await getJson('board/recent.json');
  // A request lost as the app closes fails instead of hanging (N4): 15 s for status.json, 2 minutes for the MBs and for
  // what main reads only after its modules arrive.
  assert.deepEqual(limits, { 'data/board/rows.json': 120_000, 'data/status.json': 15_000, 'data/index.json': 120_000,
    'data/board/products.json': 120_000, 'data/board/recent.json': 120_000 });
  assert.match(app.match(/async function main\(\)[\s\S]*?await first;/)[0], /getJson\('board\/products\.json'\)[\s\S]*window\.vrEarly = null;/);
  // The Board draws from the row views; without rows.json (rollout, a failed fetch) the full week, as before (owner, 11-10).
  assert.match(app.match(/async function main\(\)[\s\S]*?await first;/)[0], /getJson\('board\/rows\.json'\)\.catch\(\(\) => getJson\('board\/recent\.json'\)\)/);
});

test("the inline script draws the first-visit line from the first paint only while the guide is unseen (CLS, 11-17)", async () => {
  const vm = await import('node:vm');
  const early = html.match(/<script>([^<]*vrEarly[^<]*)<\/script>/)[1];
  const classes = (saved) => {
    const added = [];
    vm.runInContext(early, vm.createContext({ location: { hostname: 'localhost' }, fetch: () => Promise.resolve(), navigator: { language: 'ko-KR' },
      localStorage: { getItem: (k) => saved[k] ?? null },
      document: { documentElement: { dataset: { collectedSince: '2026-11-09' }, classList: { add: (c) => added.push(c) }, style: { setProperty() {} } } } }));
    return added;
  };
  assert.ok(!classes({}).includes('pr-off')); // a first visit: app.mjs will show it, so the page paints it
  assert.ok(classes({ 'vr-guide': 'seen' }).includes('pr-off'));
});

// The Board's requests and live checks (web/app.mjs, from getJson to the online listener) in node:vm. asked holds each
// request's signal, with its url and answer(value); unanswered, a request ends only by its abort. on.<type> fires a page event.
async function liveChecks(extra = {}) {
  const vm = await import('node:vm');
  const app = read('web/app.mjs');
  const on = {};
  const asked = [];
  const listen = (type, f) => { on[type] = f; };
  const fetch = (url, { signal }) => new Promise((yes, no) => {
    asked.push(Object.assign(signal, { url, answer: (value) => yes({ ok: true, text: async () => JSON.stringify(value) }) }));
    signal.addEventListener('abort', () => no(signal.reason));
  });
  const ctx = vm.createContext({ fetch, AbortController, withJapanese, setTimeout: (f, ms) => setTimeout(f, ms).unref(), clearTimeout, setInterval() {}, navigator: { onLine: true },
    window: {}, document: { hidden: false, addEventListener: listen }, addEventListener: listen, ...extra });
  vm.runInContext(`const DATA_URL = 'data/'; let updated = 'u', loadError = null, fullWeek = null;
    ${app.match(/const SLOW_MS[\s\S]*?\n\};/)[0]} ${app.match(/const CHECK_MS[\s\S]*?addEventListener\('online', back\);/)[0]}`, ctx);
  const hide = () => { ctx.document.hidden = true; on.visibilitychange(); };
  const show = () => { ctx.document.hidden = false; on.visibilitychange(); };
  return { on, asked, hide, show, ctx, run: (code) => vm.runInContext(code, ctx) };
}
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

test('a status check that never answers fails by its time limit and the next check runs; a hidden tab waits, a restored one checks (N4)', async () => {
  const { on, asked, ctx } = await liveChecks({ setTimeout: (f, ms) => setTimeout(f, ms && 5) });
  await on.focus(); // hangs until its time limit aborts it
  await on.focus();
  assert.equal(asked.length, 2); // the first check's mark was cleared
  ctx.document.hidden = true;
  await on.focus();
  assert.equal(asked.length, 2);
  ctx.document.hidden = false;
  on.pageshow({ persisted: false });
  on.pageshow({ persisted: true });
  await settle();
  assert.equal(asked.length, 3);
});

test('a request under way when the tab was hidden or the connection dropped is aborted on return and asked again at once (N4)', async () => {
  const { on, asked, hide, show } = await liveChecks();
  on.focus(); // under way, and never answers
  hide();
  show();
  await settle();
  assert.equal(asked[0].aborted, true);
  assert.equal(asked.length, 2);
  on.offline();
  on.online();
  await settle();
  assert.equal(asked[1].aborted, true);
  assert.equal(asked.length, 3);
});

test('whoever waited on a request aborted on return gets the fresh answer, with no error or fallback in between (N4)', async () => {
  const { asked, hide, show, run } = await liveChecks();
  const week = run("getJson('board/recent.json')"); // the full week for an open row, say
  hide();
  show();
  await settle();
  assert.equal(asked[0].aborted, true);
  asked.find((s) => s.url === 'data/board/recent.json' && !s.aborted).answer({ fresh: true });
  assert.deepEqual({ ...await week }, { fresh: true });
});

test('a request asked while the tab was hidden is aborted on return too, and one asked after the return is not (N4)', async () => {
  const { on, asked, hide, show, run } = await liveChecks();
  hide();
  run("getJson('board/rows.json')"); // a check's next step, asked after status.json answered in the background
  show();
  await settle();
  assert.equal(asked[0].aborted, true);
  assert.equal(asked.filter((s) => !s.aborted).length, 2); // rows.json asked again, and the return's check
});

test('a connection back while the tab is still hidden aborts nothing; the return in view does, once the connection is up (N4)', async () => {
  const { on, asked, hide, show, ctx } = await liveChecks();
  on.focus();
  hide();
  on.offline();
  on.online(); // still hidden
  await settle();
  assert.equal(asked.length, 1);
  ctx.navigator.onLine = false;
  show(); // in view, but the radio is not up yet
  await settle();
  assert.equal(asked.length, 1);
  ctx.navigator.onLine = true;
  on.online();
  await settle();
  assert.equal(asked[0].aborted, true);
  assert.equal(asked.length, 2);
});

test("an early first-load answer whose body never arrives is asked again on return, outside index.html's own limit (N4)", async () => {
  const stalled = Promise.resolve({ ok: true, text: () => new Promise(() => {}) });
  const { asked, hide, show, run } = await liveChecks({ window: { vrEarly: { 'data/board/rows.json': stalled } } });
  const rows = run("getJson('board/rows.json')");
  hide();
  show();
  await settle();
  asked.find((s) => s.url === 'data/board/rows.json').answer({ fresh: true });
  assert.deepEqual({ ...await rows }, { fresh: true });
});

test('a time limit that comes due while the tab is hidden waits on, and applies once the tab is in view again (N4)', async () => {
  const { on, asked, hide, ctx } = await liveChecks({ setTimeout: (f, ms) => setTimeout(f, ms && 5) });
  on.focus();
  hide();
  await settle();
  assert.equal(asked[0].aborted, false); // hidden: the return will ask again instead
  ctx.document.hidden = false; // in view with no event at all (offline while visible, say)
  await settle();
  assert.equal(asked[0].aborted, true);
});

test('a request asked after the return is not aborted by a later return event (N4)', async () => {
  const { on, asked, hide, show } = await liveChecks();
  on.focus();
  hide();
  show();
  await settle(); // asked[1] is the check of the return, slow but working
  on.online();
  on.pageshow({ persisted: true });
  await settle();
  assert.equal(asked[1].aborted, false);
  assert.equal(asked.length, 2);
});

test('return events arriving together start one check (N4)', async () => {
  const { on, asked, hide, show } = await liveChecks();
  on.focus();
  hide();
  show();
  on.pageshow({ persisted: true });
  on.online();
  on.focus();
  await settle();
  assert.equal(asked.length, 2);
});

test('a check lost while the app slept, with no time limit or abort reaching it, is given up once the clock passes the longest working check (N4)', async () => {
  let clock = 1_000_000;
  const { on, asked } = await liveChecks({ setTimeout() {}, clearTimeout() {}, Date: { now: () => clock } });
  on.focus(); // never answers
  clock += 300_000;
  on.focus();
  assert.equal(asked.length, 1); // status.json, rows.json, then recent.json, all slow but working, is still waited for
  clock += 61_000;
  on.focus();
  assert.equal(asked.length, 2);
});

// Owner, 11-17: without a top-level 404.html Pages serves the home page with 200 for every unknown path (scanners'
// probes counted as visits, soft 404s). The 404 page runs no script and its one style block is allowed by its hash,
// beside index.html's, in the same /* CSP (one more hash in style-src rather than a second rule or 'unsafe-inline').
test('404.html is small, in both languages, runs no script, and its style is allowed by the static CSP', () => {
  const page = read('web/404.html');
  assert.doesNotMatch(page, /<script/i);
  assert.doesNotMatch(page, /\son[a-z]+=|\sstyle=/i);
  const styles = [...page.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)].map((m) => m[1]);
  assert.equal(styles.length, 1);
  assert.ok(csp['style-src'].includes(hash(styles[0])), `style-src lacks ${hash(styles[0])}`);
  assert.match(page, /<meta name="robots" content="noindex">/);
  assert.match(page, /<html lang="ko">/);
  assert.match(page, /<h1>페이지를 찾을 수 없습니다<\/h1>/);
  assert.match(page, /<p lang="en">[^<]*Page not found/);
  assert.match(page, /<a href="\/">/);
  assert.ok(Buffer.byteLength(page) < 6000, `${Buffer.byteLength(page)} bytes`);
});

// Owner, 11-17: an API catalog as RFC 9727 defines it: a Linkset (RFC 9264) at /.well-known/api-catalog, served as
// application/linkset+json with the RFC's profile, and a Link header with rel="api-catalog" so a HEAD finds it too
// (section 2). One API, /api/check; llms.txt is its documentation, `service-doc` (RFC 8631: for people to read; a
// `service-desc` would be a machine description such as OpenAPI, which does not exist).
test('the API catalog lists /api/check with llms.txt as its documentation, served as a linkset with its Link header', () => {
  const catalog = JSON.parse(read('web/.well-known/api-catalog'));
  assert.deepEqual(catalog, { linkset: [{ anchor: 'https://patchticker.com/api/check',
    'service-doc': [{ href: 'https://patchticker.com/llms.txt', type: 'text/plain' }] }] });
  const block = /^\/\.well-known\/api-catalog\n((?:[ \t]+.*\n?)+)/m.exec(headers)?.[1] || '';
  assert.match(block, /^\s+Content-Type: application\/linkset\+json; profile="https:\/\/www\.rfc-editor\.org\/info\/rfc9727"$/m);
  assert.match(block, /^\s+Link: <\/\.well-known\/api-catalog>; rel="api-catalog"$/m);
});
