// The Board page's security headers (web/_headers, audit 13 follow-up): the CSP must keep allowing what index.html runs.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

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
  assert.ok(csp['img-src'].includes("'self'")); // favicon.svg
  assert.deepEqual(csp['frame-ancestors'], ["'none'"]);
  assert.equal(value('X-Content-Type-Options'), 'nosniff');
  assert.equal(value('Referrer-Policy'), 'strict-origin-when-cross-origin');
  assert.equal(value('Permissions-Policy'), 'camera=(), microphone=(), geolocation=()');
});

test("the inline script starts the first load's four files, and getJson takes each once; main drops the rest", async () => {
  const vm = await import('node:vm');
  const calls = [];
  const fetch = (url) => { const n = calls.push(url); return Promise.resolve({ ok: true, json: () => ({ url, n }) }); };
  const ctx = vm.createContext({ location: { hostname: 'localhost' }, fetch });
  ctx.window = ctx;
  vm.runInContext(html.match(/<script>([^<]*vrEarly[^<]*)<\/script>/)[1], ctx);
  assert.deepEqual(Object.keys(ctx.vrEarly).sort(), ['data/board/products.json', 'data/board/recent.json', 'data/index.json', 'data/status.json']);
  const app = read('web/app.mjs');
  const getJson = vm.runInContext(`const DATA_URL = 'data/'; ${app.match(/const getJson = async[\s\S]*?\n\};/)[0]} getJson`, ctx);
  assert.equal((await getJson('status.json')).n, 2); // the page-start fetch
  assert.equal((await getJson('status.json')).n, 5); // asked again
  assert.match(app.match(/async function main\(\)[\s\S]*?await first;/)[0], /getJson\('board\/products\.json'\)[\s\S]*window\.vrEarly = null;/);
});
