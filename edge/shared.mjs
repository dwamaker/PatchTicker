// What every Pages Function uses (spec: .scratch/incident-pages/spec.md; ADR 0002, 2026-11-10 revision): the site
// address, escaping, the store read that fails closed, the edge cache, and what to do (the page and the feed alike).
import { easyAction, easyLine, firstProduct, isShellCommand, riskLevel, usableFixes, WORDS } from '../web/board.mjs';

export const SITE = 'https://patchticker.com';
export const SLUG = /^(CVE-\d{4}-\d{4,7}|hn-\d+|u-[0-9a-f]{12})$/; // what slug() in web/board.mjs makes; anything else never reads R2

export const escapeXml = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);

export { titleOf } from '../web/board.mjs';

// bucket: the R2 binding (anything with get(key) -> { text() } or null). A missing document is null.
export async function readJson(bucket, key) {
  const obj = await bucket.get(key);
  return obj && JSON.parse(await obj.text());
}

// Fail closed: a store that cannot be read, or a document the renderer cannot use, answers down() (a 503 note with a
// way on), never a half-rendered answer or a runtime 500.
export async function failClosed(answer, down) {
  try {
    return await answer();
  } catch {
    return down();
  }
}

// The 503 for the feed and the sitemap: a reader or crawler retries later.
export const unavailable = (what) => new Response(`${what} is unavailable right now. ${SITE}/\n`,
  { status: 503, headers: { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '600' } });

// The edge cache in front of a renderer, so a burst of requests (crawlers on expired pages too) reads R2 once per
// cache time. Each answer's cache-control says how long; a 503 is never kept, so the next request tries R2 again.
// A HEAD gets GET's status and headers without the body, read from and kept under GET's entry (the Cache API keeps GETs
// only), so every entry file exports the same handler as onRequestGet and onRequestHead.
const CACHEABLE = new Set([200, 301, 302, 404, 410]);
export async function cached(context, render) {
  const head = context.request.method === 'HEAD';
  const key = head ? new Request(context.request, { method: 'GET' }) : context.request;
  const cache = globalThis.caches?.default;
  let res = cache && await cache.match(key);
  if (!res) {
    res = await render();
    if (cache && CACHEABLE.has(res.status)) context.waitUntil(cache.put(key, head ? res : res.clone()));
  }
  return head ? new Response(null, res) : res;
}

// What to do: the shared words (web/board.mjs WORDS), plus the edge's own.
const TODO = {
  ko: {
    ...WORDS.ko,
    orNewer: (v) => `${v} 이상`, // not in WORDS: the Board's keeps "이상" on the line with a no-break space
    caution: '설정을 잘못 바꾸면 서비스가 멈추거나 접속이 막힐 수 있어요. 바꾸기 전에 아래 원문 링크를 확인하세요.', // not in WORDS: English differs
  },
  en: {
    ...WORDS.en,
    orNewer: (v) => `${v} or later`, // not in WORDS: the Board's uses no-break spaces
    caution: 'A wrong setting can stop the service or lock you out. Check the source links below first.', // not in WORDS: the Board says "source link"
  },
};

export const strings = (list) => (Array.isArray(list) ? list.filter((x) => typeof x === 'string' && x) : []);
export const p = (text, cls = '') => (text ? `<p${cls ? ` class="${cls}"` : ''}>${escapeXml(text)}</p>` : '');
export const ul = (items, cls = '') => (items.length ? `<ul${cls ? ` class="${cls}"` : ''}>${items.map((x) => `<li>${x}</li>`).join('')}</ul>` : '');

const code = (text) => `<p class="command"><code>${escapeXml(text)}</code></p>`;
// A config line, not a shell command: no invitation to paste it into a terminal, and a warning (as the Board does).
const setting = (text, file, t) => p(typeof file === 'string' && file ? t.settingIn(file) : t.setting) + code(text) + p(t.caution, 'caution');

// What to do, as the Easy view words it (easyAction), on the Incident page and in the RSS feed alike: the Summary's
// advice, then the command, devices or versions.
export function whatToDo(i, lang) {
  const t = TODO[lang];
  const sum = i.summary;
  const s = sum[lang] || {};
  const level = riskLevel(i);
  const product = firstProduct(i, lang);
  const action = easyAction(sum);
  const out = [p(s.mitigation)];
  const fixes = usableFixes(sum);
  if (fixes.length > 1) out.push(p(t.fixesIntro), ul(fixes.map((f) => `<strong>${escapeXml(f.for)}</strong> ${escapeXml(t.orNewer(f.version))}`)));
  else if (action.kind === 'version' && !s.mitigation) out.push(p(t.version(action.fixed, product)));
  if (action.kind === 'command') {
    const cmd = String(action.command);
    out.push(isShellCommand(cmd) ? p(s.command_for ? t.commandFor(s.command_for) : t.command) + code(cmd) : setting(cmd, '', t));
  }
  if (action.kind === 'devices') out.push(p(easyLine(t.devices, level)), ul(strings(action.devices).map(escapeXml)), action.fixed ? p(t.fixedIn(action.fixed)) : '');
  if (action.kind === 'none' && !s.mitigation) out.push(p(s.easy_action || t.none));
  if (action.stopgap) {
    const stop = String(action.stopgap);
    out.push(p(t.stopgap), isShellCommand(stop) ? code(stop) : setting(stop, sum.stopgap_file, t), p(s.stopgap_then));
  }
  return out.join('');
}
