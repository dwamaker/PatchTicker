// Product pages (owner, 11-17: "site:patchticker.com gitea" found only the Board): /p/<slug> and /en/p/<slug>, one plain
// document per language from the product's check document (check/p/<slug>.json, collector/checks.py), the same file
// /api/check reads, so a page costs one small read. The Incident page's shell, look, head and CSP (edge/page.mjs).
// Names, titles and addresses come from the web and a model: every text is escaped, and only the site's own pages and
// Board rows become links.
import { tagHash, WORDS } from '../web/board.mjs';
import { LEVELS } from './check.mjs';
import { alternates, document, langMenu, LOCAL_TIME, note, PAGE_CSP, when } from './page.mjs';
import { SITE, escapeXml as esc, failClosed, readJson } from './shared.mjs';

export { checkSlug } from './shared.mjs';

// Fewer Incidents than this in 90 days and the page is a thin one: noindex, and no sitemap entry (collector/checks.py
// PRODUCT_PAGE_MIN keeps the same number for the sitemap).
export const PRODUCT_PAGE_MIN = 3;
const SLUG = /^[0-9a-f]{16}$/; // collector/checks.py check_slug: anything else never reads R2

const TEXT = {
  ko: { ...WORDS.ko, path: '/p/', page: '/i/', feed: '/feed.xml', locale: 'ko_KR',
    heading: (name) => `${name} 보안 사건`, count: (n) => `최근 90일 동안 ${n}건, 새로운 순. 사건마다 대처법과 원문은 사건 페이지에 있습니다.`,
    about: (name, n) => `최근 90일 동안 ${name}에 관한 보안 사건 ${n}건: 위험도, 고친 버전, 사건 페이지 링크.`,
    fixed: (v) => `고친 버전 ${v}`, cves: (n) => `CVE ${n}건`, rss: (name) => `${name} RSS 구독`, board: '현황판에서 보기',
    missing: '이 주소에는 제품 페이지가 없습니다.', down: '지금은 제품 페이지를 불러올 수 없습니다. 잠시 뒤 다시 시도하세요.', home: '현황판으로 가기', links: '이 제품 더 보기' },
  en: { ...WORDS.en, path: '/en/p/', page: '/en/i/', feed: '/en/feed.xml', locale: 'en_US',
    heading: (name) => `${name} security Incidents`, count: (n) => `${n} in the last 90 days, newest first. Each Incident page says what to do and links its sources.`,
    about: (name, n) => `${n} security Incidents of ${name} in the last 90 days: risk level, fixed version and a link to each Incident page.`,
    fixed: (v) => `Fixed in ${v}`, cves: (n) => `${n} CVE${n === 1 ? '' : 's'}`, rss: (name) => `RSS for ${name}`, board: 'Open on the Board',
    missing: 'There is no product page at this address.', down: 'Product pages cannot be loaded right now. Please try again shortly.', home: 'Go to the Board', links: 'More on this product' },
  ja: { ...WORDS.ja, path: '/ja/p/', page: '/ja/i/', feed: '/ja/feed.xml', locale: 'ja_JP',
    heading: (name) => `${name} のセキュリティインシデント`, count: (n) => `過去90日間に${n}件、新しい順。対処法と原文は各インシデントのページにあります。`,
    about: (name, n) => `過去90日間の ${name} に関するセキュリティインシデント${n}件: 危険度、修正バージョン、インシデントページへのリンク。`,
    fixed: (v) => `修正バージョン ${v}`, cves: (n) => `CVE ${n}件`, rss: (name) => `${name} の RSS`, board: 'ボードで見る',
    missing: 'このアドレスには製品ページがありません。', down: '現在製品ページを読み込めません。しばらくしてからもう一度お試しください。', home: 'ボードへ戻る', links: 'この製品をもっと見る' },
};

// The list, in the Incident page's look (DESIGN.md: product page): a panel per Incident edged in its Risk colour.
const CSS = `<style>.lede{color:var(--ink-2)}
.plist{list-style:none;margin:1.25rem 0 0;padding:0;display:grid;gap:.5rem}
.plist li{padding:.75rem 1rem;border:1px solid var(--rule-2);border-left:3px solid var(--note);border-radius:10px;background:var(--panel)}
.plist li.risk-highest{border-left-color:var(--high)}.plist li.risk-high{border-left-color:var(--mid-mark)}
.pl-head{display:flex;flex-wrap:wrap;align-items:center;gap:.25rem .625rem;margin:0 0 .375rem;color:var(--ink-2);font-size:.8125rem;font-variant-numeric:tabular-nums}
.pl-head .word{font-size:.8125rem;color:var(--note)}.risk-highest .pl-head .word{color:var(--high)}.risk-high .pl-head .word{color:var(--mid)}
.pl-title{color:var(--ink);font-weight:700;font-size:1.0625rem;line-height:1.4;text-decoration:none}
@media (hover:hover){.pl-title:hover{text-decoration:underline}}
.pl-sub{margin:.25rem 0 0;color:var(--ink-2);font-size:.875rem;font-variant-numeric:tabular-nums}</style>`;

// An Incident's address on this site: its page in this language, or its Board row; never anything else.
function href(e, t) {
  const page = /^https:\/\/patchticker\.com\/i\/([A-Za-z0-9-]+)$/.exec(typeof e.url === 'string' ? e.url : '');
  return page ? `${t.page}${page[1]}` : `/#i=${encodeURIComponent(String(e.id))}`;
}

function item(e, lang, t) {
  const level = LEVELS.includes(e.level) ? e.level : 'notice';
  const count = Number.isInteger(e.cve_count) ? e.cve_count : 0;
  const sub = [e.fixed ? t.fixed(e.fixed) : '', count ? t.cves(count) : ''].filter(Boolean).join(' · ');
  const stamp = e.published || e.first_seen;
  return `<li class="risk-${level}"><p class="pl-head"><span class="word">${esc(t.levels[level])}</span>`
    + `${e.exploited === true ? ` <span class="kev">${esc(t.kevReason)}</span>` : ''}${typeof stamp === 'string' ? ` ${when(stamp, lang)}` : ''}</p>`
    + `<a class="pl-title" href="${esc(href(e, t))}">${esc(e[`title_${lang}`] || e.title_en || e.id)}</a>${sub ? `<p class="pl-sub">${esc(sub)}</p>` : ''}</li>`;
}

export function productHtml(doc, lang, slug) {
  const t = TEXT[lang];
  const name = String(doc.product || '');
  const incidents = Array.isArray(doc.incidents) ? doc.incidents.filter((e) => e && typeof e.id === 'string') : [];
  const self = `${SITE}${t.path}${slug}`;
  const feed = `${t.feed}?products=${encodeURIComponent(name)}`;
  const head = [`<title>${esc(t.heading(name))} · Patch Ticker</title>`,
    `<meta name="description" content="${esc(t.about(name, incidents.length))}">`,
    ...(incidents.length < PRODUCT_PAGE_MIN ? ['<meta name="robots" content="noindex">'] : []),
    `<link rel="canonical" href="${self}">`,
    ...alternates((l) => `${SITE}${TEXT[l].path}${slug}`),
    `<link rel="alternate" type="application/rss+xml" title="${esc(t.rss(name))}" href="${esc(feed)}">`,
    '<meta property="og:type" content="website">',
    '<meta property="og:site_name" content="Patch Ticker">',
    `<meta property="og:url" content="${self}">`,
    `<meta property="og:title" content="${esc(t.heading(name))}">`,
    `<meta property="og:description" content="${esc(t.about(name, incidents.length))}">`,
    `<meta property="og:image" content="${SITE}/og.png">`,
    `<meta property="og:locale" content="${t.locale}">`,
    CSS].join('\n');
  const board = typeof doc.id === 'string' && doc.id ? `<a href="/${esc(tagHash({ pick: doc.id }))}">${esc(t.board)}</a>` : '';
  const main = [`<h1>${esc(t.heading(name))}</h1>`, `<p class="lede">${esc(t.count(incidents.length))}</p>`,
    `<ol class="plist">${incidents.map((e) => item(e, lang, t)).join('')}</ol>`,
    `<script>${LOCAL_TIME}</script>`,
    `<nav class="links" aria-label="${esc(t.links)}">${board}<a href="${esc(feed)}">${esc(t.rss(name))}</a></nav>`].join('\n');
  return document(lang, head, main, langMenu(lang, (l) => `${TEXT[l].path}${slug}`));
}

// bucket: the R2 binding (anything with get(key) -> { text() } or null). The document holds 90 days already.
export async function productResponse(bucket, lang, slug) {
  const t = TEXT[lang];
  const home = `<a href="/">${esc(t.home)}</a>`;
  if (!SLUG.test(slug)) return note(lang, 404, t.missing, [home]);
  return failClosed(async () => {
    const doc = await readJson(bucket, `check/p/${slug}.json`);
    if (!doc || !Array.isArray(doc.incidents) || !doc.incidents.length) return note(lang, 404, t.missing, [home]);
    return new Response(productHtml(doc, lang, slug), {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=300', 'content-security-policy': PAGE_CSP },
    });
  }, () => note(lang, 503, t.down, [`<a href="${SITE}/">${esc(t.home)}</a>`]));
}
