// The home page for readers that run no script (search crawlers): the current static index.html with links to the
// latest Incident pages in place of its <!--home-links--> marker. The shell is never cached (a cached one could meet a
// newer app.mjs after a deploy); only the link list is, for 300 seconds.
import { DAY } from './lists.mjs';
import { escapeXml, readJson, SITE } from './shared.mjs';

const MARKER = '<!--home-links-->';
// Owner, 11-17: the machine-readable entry points, for a program that reads the home page's headers. Registered relation
// types only (RFC 8288 2.1.1; IANA Link Relations): api-catalog (RFC 9727), describedby (llms.txt describes this site),
// alternate with the RSS type (the feeds, as index.html's <link> elements). Appended to any Link the asset carries.
const LINK = ['</.well-known/api-catalog>; rel="api-catalog"', '</llms.txt>; rel="describedby"; type="text/plain"',
  '</feed.xml>; rel="alternate"; type="application/rss+xml"; title="Patch Ticker (Korean)"',
  '</en/feed.xml>; rel="alternate"; type="application/rss+xml"; title="Patch Ticker (English)"',
  '</feed/all.xml>; rel="alternate"; type="application/rss+xml"; title="Patch Ticker, whole Board (Korean)"',
  '</en/feed/all.xml>; rel="alternate"; type="application/rss+xml"; title="Patch Ticker, whole Board (English)"',
  '</ja/feed.xml>; rel="alternate"; type="application/rss+xml"; title="Patch Ticker (Japanese)"',
  '</ja/feed/all.xml>; rel="alternate"; type="application/rss+xml"; title="Patch Ticker, whole Board (Japanese)"'].join(', ');
const LINKS_KEY = '/__home-links'; // the edge cache entry for the list; never a real path

// Owner, 11-27: the list pages (edge/lists.mjs) too, so one visit leads to every page the sitemaps list: the newest
// DAYS_LINKED days, every day and every product page. lists: the collector's lists/index.json; none, no list links.
const DAYS_LINKED = 7;
const RECENT = 20;
// Gemini review, 11-27: the 20 links were the RSS feed's newest search-worthy Incidents, none of them in the sitemaps;
// now the newest of the list pages' days (lists/d/<day>.json), the very Incidents the sitemaps offer. doc: {incidents:
// list entries, newest first}; an entry is linked only by its own page's address on this site.
const days = (lists) => (lists?.days && typeof lists.days === 'object'
  ? Object.entries(lists.days).filter(([d, n]) => DAY.test(d) && Number.isInteger(n) && n > 0).sort(([a], [b]) => (a < b ? 1 : -1)) : null);
const WORDS = {
  ko: { prefix: '', recent: '최근 주요 보안 사건', lists: '날짜별·제품별 보안 사건', day: (d, n) => `${d} 보안 사건 ${n}건`, allDays: '모든 날짜',
    products: '제품별 보안 사건', other: { prefix: '/en', lang: 'en', days: 'Security Incidents by day', products: 'Security Incidents by product' } },
  en: { prefix: '/en', recent: 'Latest major security Incidents', lists: 'Security Incidents by day and product', day: (d, n) => `${d}: ${n} security Incidents`,
    allDays: 'Every day', products: 'Security Incidents by product', other: { prefix: '', lang: 'ko', days: '날짜별 보안 사건', products: '제품별 보안 사건' } },
};
export async function homeLinks(doc, lists = null, lang = 'ko') {
  const w = WORDS[lang];
  const items = (doc.incidents || []).filter((e) => typeof e?.url === 'string' && e.url.startsWith(`${SITE}/i/`)).slice(0, RECENT);
  const li = items.map((e) => `<li><a href="${w.prefix}${escapeXml(e.url.slice(SITE.length))}">${escapeXml(String(e[`title_${lang}`] || e.title_ko || e.id))}</a></li>`);
  const recent = items.length ? `<h2>${w.recent}</h2><ul>${li.join('')}</ul>` : '';
  const listed = days(lists);
  if (!listed) return recent;
  const newest = listed.slice(0, DAYS_LINKED).map(([d, n]) => `<li><a href="${w.prefix}/d/${d}">${w.day(d, n)}</a></li>`);
  const o = w.other;
  return `${recent}<h2>${w.lists}</h2><ul>${newest.join('')}<li><a href="${w.prefix}/d/">${w.allDays}</a></li><li><a href="${w.prefix}/p/">${w.products}</a></li>`
    + `<li><a href="${o.prefix}/d/" lang="${o.lang}">${o.days}</a></li><li><a href="${o.prefix}/p/" lang="${o.lang}">${o.products}</a></li></ul>`;
}

// The English Board at /en/ (owner 11-28, Gemini review): the same shell, its head and language English. Each pair is a
// line of web/index.html and its English twin (tests/home.test.mjs checks every Korean line is there).
export const EN_HEAD = [
  ['<html lang="ko"', '<html lang="en"'],
  ['<title>Patch Ticker · 실시간 보안 취약점 현황판</title>', '<title>Patch Ticker · Live security vulnerability board</title>'],
  ['<meta name="description" content="새로 공개된 CVE·보안 취약점과 패치를 10분마다 모아 한국어로 요약하고, 내가 쓰는 제품 기준으로 보여 주는 실시간 현황판입니다.">',
    '<meta name="description" content="Live CVE and security vulnerability board, updated every 10 minutes: plain summaries, CISA KEV flags and fixed versions, filtered by the products you run.">'],
  ['<link rel="canonical" href="https://patchticker.com/">', '<link rel="canonical" href="https://patchticker.com/en/">'],
  ['<meta property="og:url" content="https://patchticker.com/">', '<meta property="og:url" content="https://patchticker.com/en/">'],
  ['<meta property="og:title" content="Patch Ticker · 실시간 보안 취약점 현황판">', '<meta property="og:title" content="Patch Ticker · Live security vulnerability board">'],
  ['<meta property="og:description" content="새로 공개된 CVE·보안 취약점과 패치를 10분마다 모아 한국어로 요약하고, 내가 쓰는 제품 기준으로 보여 주는 실시간 현황판입니다.">',
    '<meta property="og:description" content="Live CVE and security vulnerability board, updated every 10 minutes: plain summaries, CISA KEV flags and fixed versions, filtered by the products you run.">'],
  ['<meta property="og:image:alt" content="Patch Ticker 현황판 화면: 주요 사건과 위험도, CVSS 점수">',
    '<meta property="og:image:alt" content="The Patch Ticker Board: top Incidents with their risk and CVSS score">'],
  ['<meta property="og:locale" content="ko_KR">', '<meta property="og:locale" content="en_US">'],
  ['<meta property="og:locale:alternate" content="en_US">', '<meta property="og:locale:alternate" content="ko_KR">'],
];
const english = (html) => EN_HEAD.reduce((text, [ko, en]) => text.replace(ko, () => en), html);

// Fail open, the opposite of failClosed: the Board must open even when this list cannot be read.
async function links(context, lang) {
  try {
    const cache = globalThis.caches?.default;
    const key = new Request(new URL(`${LINKS_KEY}/${lang}`, context.request.url));
    const hit = cache && await cache.match(key);
    if (hit) return await hit.text();
    const lists = await readJson(context.env.DATA, 'lists/index.json');
    if (!lists) throw new Error('lists/index.json missing');
    const incidents = [];
    for (const [day] of (days(lists) || []).slice(0, DAYS_LINKED)) { // newest days until RECENT; a day holds ~70
      if (incidents.length >= RECENT) break;
      const doc = await readJson(context.env.DATA, `lists/d/${day}.json`).catch(() => null);
      if (Array.isArray(doc?.incidents)) incidents.push(...doc.incidents);
    }
    const html = await homeLinks({ incidents }, lists, lang);
    if (cache) context.waitUntil(cache.put(key, new Response(html, { headers: { 'cache-control': 'public, max-age=300' } })));
    return html;
  } catch {
    return '';
  }
}

export async function homeResponse(context, lang = 'ko') {
  const url = new URL(context.request.url);
  if (lang === 'en' && url.pathname === '/en') return Response.redirect(`${url.origin}/en/${url.search}`, 301); // one address
  // Unconditional, so the answer is always a full body to fill in, never a 304.
  const asset = await context.env.ASSETS.fetch(new Request(new URL('/', context.request.url)));
  if (asset.status !== 200) return asset;
  const list = await links(context, lang);
  const shell = await asset.text();
  const body = (lang === 'en' ? english(shell) : shell).replace(MARKER, () => list); // a function: "$&" or "$'" in a title stays text
  const headers = new Headers(asset.headers);
  headers.delete('etag'); // the body changed
  headers.delete('content-length');
  headers.append('link', LINK);
  return new Response(context.request.method === 'HEAD' ? null : body, { status: 200, headers });
}
