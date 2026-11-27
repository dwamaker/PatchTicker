// The list pages (owner, 11-27: "3, 4 일단 해봐"): plain HTML a crawler follows from the home page to every page the
// sitemaps list. Google visited one to eight times a day and the home page linked 20 Incident pages; now it links the
// newest days, every day (/d/) and every product page (/p/). /d/ lists the days, /d/<day> the Incident pages first seen
// that day at UTC+9 (collector/cycle.py LIST_DAY_HOURS), /p/ the product pages; Korean and English as search languages, /ja/ with /en/ as its canonical. All from
// the collector's lists/index.json and lists/d/<day>.json (collector/cycle.py write_lists), in the product page's look.
import { item, CSS as PRODUCT_CSS, PRODUCT_PAGE_MIN, TEXT as PRODUCT_TEXT } from './product.mjs';
import { alternates, clip, document, langMenu, LOCAL_TIME, note, PAGE_CSP } from './page.mjs';
import { SITE, escapeXml as esc, failClosed, readJson, searchLang } from './shared.mjs';

export const DAY = /^\d{4}-\d{2}-\d{2}$/; // anything else never reads R2
const PRODUCT = /^[0-9a-f]{16}$/; // collector/checks.py check_slug
const INDEX = 'lists/index.json';

const TEXT = {
  ko: { days: '/d/', products: '/p/', locale: 'ko_KR',
    daysHeading: '날짜별 보안 사건', daysLede: (d, n) => `최근 90일 동안 Patch Ticker가 처음 확인한 보안 사건 ${n}건을 ${d}일로 나눴습니다. 날짜는 한국 시간(UTC+9) 기준이며 최신순입니다.`,
    dayHeading: (d) => `${d} 보안 사건`, dayLede: (d, n) => `${d}(한국 시간)에 처음 확인한 보안 사건 ${n}건이며 최신순입니다. 대처법과 원문은 각 사건 페이지에 있습니다.`,
    dayAbout: (d, n, titles) => `${d}에 처음 확인한 보안 사건 ${n}건: ${titles}`,
    productsHeading: '제품별 보안 사건', productsLede: (n) => `최근 90일 동안 보안 사건이 ${PRODUCT_PAGE_MIN}건 이상인 제품 ${n}개를 이름순으로 모았습니다.`,
    count: (n) => `${n}건`, newer: '다음 날짜', older: '이전 날짜', allDays: '모든 날짜', allProducts: '제품별 사건', links: '목록 더 보기',
    missing: '이 주소에는 목록이 없습니다.', down: '지금은 목록을 불러올 수 없습니다. 잠시 뒤 다시 시도하세요.', home: '현황판으로 가기' },
  en: { days: '/en/d/', products: '/en/p/', locale: 'en_US',
    daysHeading: 'Security Incidents by day', daysLede: (d, n) => `The ${n} security Incidents Patch Ticker first saw in the last 90 days, over ${d} days. Days are Korea time (UTC+9), newest first.`,
    dayHeading: (d) => `Security Incidents of ${d}`, dayLede: (d, n) => `${n} security Incidents first seen on ${d} (Korea time, UTC+9), newest first. Each Incident page says what to do and links its sources.`,
    dayAbout: (d, n, titles) => `${n} security Incidents first seen on ${d}: ${titles}`,
    productsHeading: 'Security Incidents by product', productsLede: (n) => `${n} products with ${PRODUCT_PAGE_MIN} or more security Incidents in the last 90 days, by name.`,
    count: (n) => String(n), newer: 'Next day', older: 'Previous day', allDays: 'All days', allProducts: 'By product', links: 'More lists',
    missing: 'There is no list at this address.', down: 'Lists cannot be loaded right now. Please try again shortly.', home: 'Go to the Board' },
  ja: { days: '/ja/d/', products: '/ja/p/', locale: 'ja_JP',
    daysHeading: '日付別のセキュリティインシデント', daysLede: (d, n) => `過去90日間に Patch Ticker が初めて確認したセキュリティインシデント${n}件を${d}日に分けています。日付は UTC+9 の日付、新しい順です。`,
    dayHeading: (d) => `${d} のセキュリティインシデント`, dayLede: (d, n) => `${d}（UTC+9）に初めて確認したセキュリティインシデント${n}件、新しい順。対処法と原文は各インシデントのページにあります。`,
    dayAbout: (d, n, titles) => `${d} に初めて確認したセキュリティインシデント${n}件: ${titles}`,
    productsHeading: '製品別のセキュリティインシデント', productsLede: (n) => `過去90日間にセキュリティインシデントが${PRODUCT_PAGE_MIN}件以上ある製品${n}件、名前順。`,
    count: (n) => `${n}件`, newer: '次の日', older: '前の日', allDays: 'すべての日付', allProducts: '製品別', links: 'ほかの一覧',
    missing: 'このアドレスには一覧がありません。', down: '現在一覧を読み込めません。しばらくしてからもう一度お試しください。', home: 'ボードへ戻る' },
};

// A row per day or product: the name as the link, the count after it, each a 44px target.
const CSS = `<style>.dlist{list-style:none;margin:1.25rem 0 0;padding:0;display:grid;column-gap:2rem}
@media (min-width:40rem){.dlist.cols{grid-template-columns:repeat(2,minmax(0,1fr))}}
.dlist li{display:flex;align-items:center;justify-content:space-between;gap:1rem;border-bottom:1px solid var(--rule-2)}
.dlist a{flex:1;min-height:44px;display:flex;align-items:center;color:var(--ink);font-weight:600;text-decoration:none;overflow-wrap:anywhere}
@media (hover:hover){.dlist a:hover{text-decoration:underline}}
.dlist .n{color:var(--ink-2);font-size:.875rem;font-variant-numeric:tabular-nums;white-space:nowrap}</style>`;

const HEADERS = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=300', 'content-security-policy': PAGE_CSP };

// The days the index names, newest first, each with its count.
const daysOf = (index) => Object.entries(index.days).filter(([d, n]) => DAY.test(d) && Number.isInteger(n) && n > 0).sort(([a], [b]) => (a < b ? 1 : -1));

function head(lang, title, about, path) {
  const t = TEXT[lang];
  return [`<title>${esc(title)} · Patch Ticker</title>`,
    `<meta name="description" content="${esc(clip(about))}">`,
    `<link rel="canonical" href="${SITE}${path(searchLang(lang))}">`,
    ...alternates((l) => `${SITE}${path(l)}`),
    '<meta property="og:type" content="website">',
    '<meta property="og:site_name" content="Patch Ticker">',
    `<meta property="og:url" content="${SITE}${path(lang)}">`,
    `<meta property="og:title" content="${esc(title)}">`,
    `<meta property="og:description" content="${esc(clip(about))}">`,
    `<meta property="og:image" content="${SITE}/og.png">`,
    `<meta property="og:locale" content="${t.locale}">`,
    PRODUCT_CSS, CSS].join('\n');
}

const nav = (t, links) => `<nav class="links" aria-label="${esc(t.links)}">${links.join('')}<a href="/">${esc(t.home)}</a></nav>`;

export function daysHtml(index, lang) {
  const t = TEXT[lang];
  const days = daysOf(index);
  const total = days.reduce((n, [, c]) => n + c, 0);
  const lede = t.daysLede(days.length, total);
  const list = days.map(([d, n]) => `<li><a href="${t.days}${d}">${d}</a><span class="n">${esc(t.count(n))}</span></li>`);
  const main = [`<h1>${esc(t.daysHeading)}</h1>`, `<p class="lede">${esc(lede)}</p>`, `<ul class="dlist">${list.join('')}</ul>`,
    nav(t, [`<a href="${t.products}">${esc(t.allProducts)}</a>`])].join('\n');
  return document(lang, head(lang, t.daysHeading, lede, (l) => TEXT[l].days), main, langMenu(lang, (l) => TEXT[l].days));
}

export function dayHtml(doc, index, lang, day) {
  const t = TEXT[lang];
  const incidents = doc.incidents.filter((e) => e && typeof e.id === 'string');
  const days = daysOf(index).map(([d]) => d);
  const at = days.indexOf(day);
  const newer = at > 0 ? days[at - 1] : null;
  const older = at >= 0 && at < days.length - 1 ? days[at + 1] : null;
  const pt = PRODUCT_TEXT[lang];
  const titles = incidents.slice(0, 3).map((e) => e[`title_${lang}`] || e.title_en || e.id).join(' · ');
  const main = [`<h1>${esc(t.dayHeading(day))}</h1>`, `<p class="lede">${esc(t.dayLede(day, incidents.length))}</p>`,
    // first_seen, not published: the day is the one the Incident was first seen
    `<ol class="plist">${incidents.map((e) => item({ ...e, published: '' }, lang, pt)).join('')}</ol>`,
    `<script>${LOCAL_TIME}</script>`,
    nav(t, [...(older ? [`<a href="${t.days}${older}" rel="prev">${esc(t.older)}</a>`] : []),
      ...(newer ? [`<a href="${t.days}${newer}" rel="next">${esc(t.newer)}</a>`] : []),
      `<a href="${t.days}">${esc(t.allDays)}</a>`, `<a href="${t.products}">${esc(t.allProducts)}</a>`])].join('\n');
  return document(lang, head(lang, t.dayHeading(day), t.dayAbout(day, incidents.length, titles), (l) => `${TEXT[l].days}${day}`),
    main, langMenu(lang, (l) => `${TEXT[l].days}${day}`));
}

export function productsHtml(index, lang) {
  const t = TEXT[lang];
  const products = index.products.filter((p) => p && PRODUCT.test(p.slug) && typeof p.name === 'string' && p.name);
  const lede = t.productsLede(products.length);
  const list = products.map((p) => `<li><a href="${t.products}${p.slug}">${esc(p.name)}</a><span class="n">${esc(t.count(Number(p.count) || 0))}</span></li>`);
  const main = [`<h1>${esc(t.productsHeading)}</h1>`, `<p class="lede">${esc(lede)}</p>`, `<ul class="dlist cols">${list.join('')}</ul>`,
    nav(t, [`<a href="${t.days}">${esc(t.allDays)}</a>`])].join('\n');
  return document(lang, head(lang, t.productsHeading, lede, (l) => TEXT[l].products), main, langMenu(lang, (l) => TEXT[l].products));
}

// The index, or an error: a missing or broken index answers 503 (retried, never cached), never an empty list.
async function readIndex(bucket) {
  const index = await readJson(bucket, INDEX);
  if (!index || !index.days || typeof index.days !== 'object' || Array.isArray(index.days) || !Array.isArray(index.products)) throw new Error(`${INDEX} unusable`);
  return index;
}

const answer = (lang, render) => failClosed(async () => render(), () => note(lang, 503, TEXT[lang].down, [`<a href="${SITE}/">${esc(TEXT[lang].home)}</a>`]));
const html = (body) => new Response(body, { headers: HEADERS });

// bucket: the R2 binding (anything with get(key) -> { text() } or null).
export const daysResponse = (bucket, lang) => answer(lang, async () => html(daysHtml(await readIndex(bucket), lang)));
export const productsResponse = (bucket, lang) => answer(lang, async () => html(productsHtml(await readIndex(bucket), lang)));
export async function dayResponse(bucket, lang, day) {
  const t = TEXT[lang];
  if (!DAY.test(day)) return note(lang, 404, t.missing, [`<a href="${t.days}">${esc(t.allDays)}</a>`]);
  return answer(lang, async () => {
    const index = await readIndex(bucket);
    const doc = await readJson(bucket, `lists/d/${day}.json`, lang);
    if (!doc || !Array.isArray(doc.incidents) || !doc.incidents.length) return note(lang, 404, t.missing, [`<a href="${t.days}">${esc(t.allDays)}</a>`]);
    return html(dayHtml(doc, index, lang, day));
  });
}
