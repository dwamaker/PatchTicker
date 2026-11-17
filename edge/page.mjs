// Incident pages (spec: .scratch/incident-pages/spec.md; ADR 0002, 2026-11-10 revision). The Pages Function reads the
// collector's pages/<slug>.json from R2 and renders one plain document per language, whose one script shows the times in the
// reader's zone. The rules (risk level, exploited reason, easy action, Product names, on the Board, search-worthy) are
// the Board's own, imported from web/board.mjs, and so are the shared words (WORDS); only the page's own words live here. Titles, Summaries and URLs come from the web and a model: every text is
// escaped and only http(s) addresses become links.
import { conditionIds, cveExploit, cveLines, distroTable, cveUrl, cvssRating, easyLine, exploitedCves, exploitReason, scoreCve, foldTags, isExploited, MENTION_ORDER, onBoard, productLine, productOthers, productsOf, publicDay, reportUrl, riskLevel, searchWorthy, tagFilters, tagHash, withinPageDays, WORDS, LANGS } from '../web/board.mjs';
import { SITE, SLUG, checkSlug, escapeXml as esc, failClosed, host, http, p, readJson, strings, titleOf, ul, whatToDo } from './shared.mjs';

const NEW_TAB = ' target="_blank" rel="noopener noreferrer"';
// The Board's logo symbol (index.html #home) and its 틀린 내용 알리기 icon (app.mjs reportLink).
const LOGO = '<svg viewBox="0 0 64 56" aria-hidden="true"><path fill-rule="evenodd" d="M17 0H44A20 20 0 0 1 44 40H34V56H17V26.5H0V13.5H17ZM53.5 20A9.5 9.5 0 1 0 34.5 20A9.5 9.5 0 1 0 53.5 20Z"/></svg>';
const REPORT_ICON = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2.5 14 13H2Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 6.5v3M8 11.2v.1" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>';
const NVD_EN = 'This product uses data from the NVD API but is not endorsed or certified by the NVD.';
const MITRE = 'CVE&reg; records: Copyright &copy; 1999&ndash;2026, The MITRE Corporation. CVE is a registered trademark of The MITRE Corporation. CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE&reg;). Any copy you make for such purposes is authorized provided that you reproduce MITRE\'s copyright designation and this license in any such copy. <a href="https://www.cve.org/Legal/TermsOfUse">CVE Terms of Use</a>';

// The shared words (web/board.mjs WORDS) for what the page shows, plus the page's own.
const TEXT = {
  ko: {
    ...WORDS.ko,
    path: '/i/', productPath: '/p/', locale: 'ko_KR',
    rating: { critical: '심각', high: '높음', medium: '보통', low: '낮음', none: '없음' },
    productPages: '제품별 사건', summary: '요약', todo: '대처법', products: '대상 제품과 운영체제', cves: 'CVE 번호', moreCves: (n) => `CVE ${n}건 더 보기`, mentions: '원문 링크', times: '시각', links: '이 사건 더 보기',
    firstSeen: '처음 확인', zone: ' KST',
    board: '현황판에서 보기', cveRecord: 'CVE 기록 보기', tagLink: (name) => `현황판에서 ${name} 사건 보기`,
    expired: '보관 기간 90일이 지났어요. 이 사건 페이지는 더 이상 없습니다.', missing: '이 주소에는 사건 페이지가 없습니다.',
    down: '지금은 사건 페이지를 불러올 수 없습니다. 잠시 뒤 다시 시도하세요.', home: '현황판으로 가기',
  },
  en: {
    ...WORDS.en,
    path: '/en/i/', productPath: '/en/p/', locale: 'en_US',
    rating: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' },
    productPages: 'Incidents by product', summary: 'Summary', todo: 'What to do', products: 'Products and platforms', cves: 'CVE IDs', moreCves: (n) => `${n} more CVE IDs`, mentions: 'Sources', times: 'Times', links: 'More on this Incident',
    firstSeen: 'First seen', zone: ' UTC',
    board: 'Open on the Board', cveRecord: 'See the CVE record', tagLink: (name) => `See ${name} Incidents on the Board`,
    expired: 'This Incident page has expired: pages are kept for 90 days.', missing: 'There is no Incident page at this address.',
    down: 'Incident pages cannot be loaded right now. Please try again shortly.', home: 'Go to the Board',
  },
  // Japanese (owner, 11-17): the interface only; the Summary is the English one (board.mjs withJapanese).
  ja: {
    ...WORDS.ja,
    path: '/ja/i/', productPath: '/ja/p/', locale: 'ja_JP',
    rating: { critical: '緊急', high: '重要', medium: '警告', low: '注意', none: 'なし' },
    productPages: '製品別のインシデント', summary: '要約', todo: '対処法', products: '対象の製品と OS', cves: 'CVE 番号', moreCves: (n) => `CVE をあと${n}件表示`, mentions: '原文リンク', times: '日時', links: 'このインシデントをもっと見る',
    firstSeen: '初確認', zone: ' JST',
    board: 'ボードで見る', cveRecord: 'CVE レコードを見る', tagLink: (name) => `ボードで ${name} のインシデントを見る`,
    expired: '保存期間の90日を過ぎたため、このインシデントのページはもうありません。', missing: 'このアドレスにはインシデントのページがありません。',
    down: '現在インシデントのページを読み込めません。しばらくしてからもう一度お試しください。', home: 'ボードへ戻る',
  },
};

// On a touch screen a list link is a 44px box, ~10px of air over its text: the list under a label pulls up by that much.
// CVE columns: 9rem + a 1.25rem marker gap is the most that still gives two columns at 360px (328px less the list's 20px).
const CSS = `:root{color-scheme:light dark;--bg:light-dark(#f4f5f7,#121417);--panel:light-dark(#fff,#191c20);--panel-2:light-dark(#eceef1,#1f2328);--ink:light-dark(#16191d,#ececec);--ink-2:light-dark(#4f5862,#a8afb7);--ink-3:light-dark(#5f6872,#8c949d);--rule:light-dark(#dde1e5,#2a2f35);--rule-2:light-dark(#c4c9cf,#3a4048);--edge:light-dark(#858e97,#6b737c);--shadow:light-dark(rgb(20 25 30 / 0.07),rgb(0 0 0 / 0.32));--high:light-dark(#c4231c,#ff6b62);--mid:light-dark(#8a6100,#f5b400);--mid-mark:light-dark(#a87700,#f5b400);--note:light-dark(#5a6570,#9aa3ad);--focus:light-dark(#1a5fb4,#7cc4ff);--sans:"Pretendard Variable",Pretendard,"Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",system-ui,sans-serif;--mono:ui-monospace,"Cascadia Mono",Consolas,monospace}
*,*::before,*::after{box-sizing:border-box}
html{background:var(--bg);scrollbar-color:var(--rule-2) var(--bg)}
body{margin:0;background:var(--bg);color:var(--ink);font:400 0.9375rem/1.55 var(--sans);letter-spacing:-0.005em;word-break:keep-all;overflow-wrap:anywhere;-webkit-font-smoothing:antialiased}
a{color:var(--focus);text-underline-offset:3px}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
::selection{background:color-mix(in srgb,var(--focus) 32%,transparent)}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
.wrap{max-width:45rem;margin:0 auto;padding-inline:1rem}
header{border-bottom:1px solid var(--rule)}
header .wrap{min-height:4rem;display:flex;align-items:center;justify-content:space-between;gap:.75rem}
.brand{display:inline-flex;align-items:center;gap:.625rem;border-radius:8px;color:var(--ink);font:700 1.25rem/1 var(--sans);letter-spacing:-0.02em;text-decoration:none}
.brand svg{flex:none;height:1em;width:auto;fill:var(--focus)}
.links a,.lang{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;min-height:44px;min-width:44px;padding:0 1rem;border:1px solid var(--edge);border-radius:8px;background:none;color:var(--ink);font-size:.875rem;font-weight:500;text-decoration:none;transition:background-color 120ms ease-out,transform 100ms ease-out}
.links svg{flex:none;width:16px;height:16px}
@media (hover:hover){.links a:hover,.lang:hover{background:var(--panel-2)}}
.links a:active,.lang:active{transform:scale(.96)}
@media (prefers-reduced-motion:reduce){.links a:active,.lang:active{transform:none}}
.lang .short{display:none}
.langs{position:relative}
.langs summary{cursor:pointer;list-style:none}
.langs summary::-webkit-details-marker{display:none}
.langs summary svg{flex:none;width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.4}
.langs[open] summary{background:var(--panel-2)}
.langs ul{position:absolute;right:0;top:calc(100% + .25rem);z-index:5;min-width:9rem;margin:0;padding:.375rem;list-style:none;border:1px solid var(--rule-2);border-radius:10px;background:var(--panel);box-shadow:0 12px 28px -12px var(--shadow)}
.langs ul a{display:flex;align-items:center;min-height:44px;padding:0 .75rem;border-radius:8px;color:var(--ink);font-size:.875rem;text-decoration:none}
@media (hover:hover){.langs ul a:hover{background:var(--panel-2)}}
.langs ul a[aria-current]{font-weight:700}
main{padding-block:2.5rem 2rem}
@media (max-width:599px){.lang .full{display:none}.lang .short{display:inline}main{padding-top:1.75rem}}
h1{margin:0 0 1rem;font:700 1.5rem/1.3 var(--sans);letter-spacing:-0.02em;text-wrap:balance}
p{margin:.375rem 0}
ul{margin:.25rem 0;padding-left:1.25rem}
.banner{display:flex;flex-wrap:wrap;align-items:center;gap:.75rem 1rem;padding:1rem;border:1px solid var(--rule-2);border-left:3px solid var(--note);border-radius:10px;background:var(--panel);box-shadow:0 6px 18px -8px var(--shadow)}
.banner.risk-highest{border-left-color:var(--high);background:linear-gradient(90deg,color-mix(in srgb,var(--high) 7%,transparent),transparent 40%),var(--panel)}
.banner.risk-high{border-left-color:var(--mid-mark);background:linear-gradient(90deg,color-mix(in srgb,var(--mid-mark) 5%,transparent),transparent 40%),var(--panel)}
.sign{margin:0;display:flex;flex-direction:column;align-items:center;gap:.125rem;color:var(--note)}
.risk-highest .sign{color:var(--high)}
.risk-high .sign{color:var(--mid)}
.word{padding:calc(.25rem - 1.5px) calc(.75rem - 1.5px);border:1.5px solid var(--note);border-radius:999px;font-size:.9375rem;font-weight:800;line-height:1.2}
.risk-highest .word{border-color:var(--high)}
.risk-high .word{border-color:var(--mid-mark)}
.gauge{position:relative;flex:none;width:2.75rem;height:2.75rem;display:grid;place-items:center;color:var(--note)}
.gauge svg{position:absolute;inset:0;width:100%;height:100%;transform:rotate(-90deg)}
.gauge circle{fill:none;stroke-width:3.5}
.gauge .track{stroke:var(--rule-2)}
.gauge .arc{stroke:currentColor;stroke-dasharray:var(--fill) 1;stroke-linecap:round}
.gauge.sev-none .arc{display:none}
.gauge b{position:relative;color:var(--ink);font-size:.8125rem;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:-0.02em}
.gauge.unrated{border:2px dashed var(--rule-2);border-radius:50%;color:var(--ink-3);font-weight:600}
.sev-critical{color:var(--high)}
.sev-high{color:var(--mid-mark)}
.reason{flex-basis:100%;margin:0;color:var(--ink-2);font-size:.875rem;font-weight:600;font-variant-numeric:tabular-nums}
@media (pointer:coarse){.reason a{display:inline-block;padding:.625rem 0}}
.kev{color:var(--high);font-weight:700}
.why.kev{font-size:.875rem;font-weight:800}
.banner.unrated .word{border-style:dashed}
.why.unrated{color:var(--ink-2);font-size:.875rem;font-weight:700}
.easy{margin-top:1rem;font-size:1.0625rem;font-weight:600}
section{margin-top:1.5rem}
.label{margin:0 0 .375rem;color:var(--ink-2);font-size:.8125rem;font-weight:700}
#s-summary~p,#s-todo~p{line-height:1.7}
code{font-family:var(--mono);font-size:.875rem}
.command code{display:block;font:.875rem/1.5 var(--mono);background:var(--panel-2);border:1px solid var(--rule-2);border-radius:6px;padding:.375rem .625rem;white-space:pre-wrap;overflow-wrap:break-word}
.caution{color:var(--ink-2);font-size:.875rem}
.tags{display:flex;flex-wrap:wrap;gap:.375rem;padding:0;list-style:none}
.tags li{display:flex;max-width:100%}
.tags a{display:inline-flex;align-items:center;justify-content:center;max-width:100%;border-radius:999px;text-decoration:none}
.tags span{display:inline-flex;align-items:center;max-width:100%;min-height:1.625rem;padding:.1875rem .6875rem;border-radius:999px;background:var(--line);color:var(--line-ink);font-size:.78125rem;font-weight:600;line-height:1.2;letter-spacing:0;overflow-wrap:anywhere}
.tags .os{background:none;color:var(--ink-2);box-shadow:inset 0 0 0 1px var(--edge);font-weight:500}
@media (hover:hover) and (pointer:fine){.tags a:hover span{text-decoration:underline;text-underline-offset:2px}}
@media (pointer:coarse){.tags{row-gap:0}.tags a{min-height:44px;min-width:44px}}
.links{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:2rem;padding-top:1rem;border-top:1px solid var(--rule)}
.sources li+li{margin-top:.25rem}
.cves{display:grid;grid-template-columns:repeat(auto-fill,minmax(9rem,1fr));gap:.25rem 1.25rem}
.cves.lines{display:block}.cves.lines li+li{margin-top:.375rem}
.cves,time,#s-todo~ul li{font-variant-numeric:tabular-nums}
.cve-src{white-space:nowrap;font-size:.8125rem;font-variant-numeric:tabular-nums}
.credits{color:var(--ink-2);font-size:.875rem}
.fix-head{margin:.75rem 0 0;font-weight:700}
.fix-list{display:grid;grid-template-columns:fit-content(20rem) auto;justify-content:start;column-gap:1.25rem;row-gap:.25rem;margin:.375rem 0 0}
.fix-list dt{min-width:0;overflow-wrap:anywhere}
.fix-list dd{margin:0;font-variant-numeric:tabular-nums;white-space:nowrap}
.fix-list:has(+ .fix-more:not([open])) > .rest{display:none}
.fix-more[open] .closed,.fix-more:not([open]) .opened{display:none}
.more.fix-more summary{padding-block:.6875rem}
@media (max-width:22.5rem){.fix-list{grid-template-columns:minmax(0,1fr)}.fix-list dd{padding-left:.75rem;white-space:normal;overflow-wrap:anywhere}.fix-list dt:not(:first-child){margin-top:.25rem}}
@media (pointer:coarse){:is(.sources,.cves,.others,.credits) a{display:inline-flex;align-items:center;min-height:44px;padding-inline:.25rem}.label+:is(.sources,.cves){margin-top:-.625rem}}
.more summary{width:fit-content;padding:.375rem 0;color:var(--focus);font-weight:600;cursor:pointer;text-underline-offset:3px}
@media (pointer:coarse){.more summary{padding-block:.75rem}}
@media (hover:hover) and (pointer:fine){.more summary:hover{text-decoration:underline}}
footer{padding:1rem 0 2rem;border-top:1px solid var(--rule);color:var(--ink-3);font-size:.8125rem}`;

// A source link opens in a new tab, as on the Board (DESIGN.md), and says so to screen readers.
const link = (url, text, t) => (http(url) ? `<a href="${esc(url)}"${NEW_TAB}>${esc(text)}<span class="sr-only">${esc(t.newTab)}</span></a>` : '');
// A release can carry hundreds of CVEs (IBM API Connect: 204): the first CVE_SHOWN stay in view, the rest fold. Every
// link stays in the HTML for search engines; <details> needs no script.
const CVE_SHOWN = 10;
// Each CVE with its one line, as the Board's opened row shows it (cveLines, M3); a CVE with no line yet keeps its id. In
// the document's order, which the collector writes Lead CVE first (step 4). An exploited CVE wears 악용 발생 and its source.
const cveList = (i, lang, t) => {
  const text = new Map(cveLines(i, lang).map((l) => [l.cve, l.text]));
  const cls = text.size ? 'cves lines' : 'cves';
  const mark = (cve) => {
    const hit = cveExploit(i, cve);
    return hit ? ` <span class="kev">${esc(t.kevReason)}</span> ${link(hit.url, hit.kind === 'kev' ? t.kevSource : host(hit.url), t)}` : '';
  };
  const links = i.cves.map((cve) => (text.has(cve) ? `<strong>${link(cveUrl(cve), cve, t)}</strong>${mark(cve)} ${esc(text.get(cve))}` : link(cveUrl(cve), cve, t) + mark(cve)));
  if (links.length <= CVE_SHOWN + 2) return ul(links, cls); // two more are not worth a fold
  return ul(links.slice(0, CVE_SHOWN), cls)
    + `<details class="more"><summary>${esc(t.moreCves(links.length - CVE_SHOWN))}</summary>${ul(links.slice(CVE_SHOWN), cls)}</details>`;
};
const section = (key, label, body) => (body ? `<section aria-labelledby="s-${key}"><p class="label" id="s-${key}">${esc(label)}</p>${body}</section>` : '');
const pageUrl = (lang, slug) => `${SITE}${TEXT[lang].path}${slug}`;

// Without script, Korean and Japanese pages say their time (UTC+9, no daylight saving), English ones UTC. datetime is the instant in
// UTC, so the browser below reads the same one even from a stamp without a zone.
export function when(stamp, lang) {
  const at = Date.parse(stamp);
  if (Number.isNaN(at)) return esc(stamp);
  const d = new Date(at + (lang === 'en' ? 0 : 9 * 60 * 60 * 1000)).toISOString();
  return `<time datetime="${new Date(at).toISOString()}">${d.slice(0, 10)} ${d.slice(11, 16)}${TEXT[lang].zone}</time>`;
}
// The browser then shows each time in the visitor's zone, as the Board does, named like "GMT+9"; a browser without
// shortOffset keeps the text above. A string, not a function: the bundler rewrites code, and the CSP pins these bytes.
export const LOCAL_TIME = 'for(const t of document.querySelectorAll("time[datetime]"))try{const d=new Date(t.dateTime),two=(n)=>String(n).padStart(2,"0");t.textContent=d.getFullYear()+"-"+two(d.getMonth()+1)+"-"+two(d.getDate())+" "+two(d.getHours())+":"+two(d.getMinutes())+" "+new Intl.DateTimeFormat("en",{timeZoneName:"shortOffset"}).formatToParts(d).find((p)=>p.type==="timeZoneName").value}catch{}';
const LOCAL_TIME_SHA256 = 'oAEYH/gLR7li4Nk9meP5pB8aLXZMHwekOrjaIjs5Acs='; // tests/page.test.mjs recomputes it
// One script, LOCAL_TIME, by its hash; inline styles only (the Board's tokens and line colours). The product page's too.
export const PAGE_CSP = `default-src 'none'; script-src 'sha256-${LOCAL_TIME_SHA256}' https://static.cloudflareinsights.com; connect-src https://cloudflareinsights.com; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;

// The risk banner: the rule-based level, why it is exploited, and the CVSS ring.
function banner(i, t) {
  const level = riskLevel(i);
  const cvss = Number.isFinite(i.cvss) ? i.cvss : null;
  const rating = cvssRating(cvss);
  // Not rated yet, as on the Board (riskCell): the sign is dashed like the empty ring, 점수 대기 under it (critique 13).
  const pending = !isExploited(i) && !rating;
  // In a group the score names the CVE it belongs to (step 4): in the ring's label and a small line.
  const top = rating ? scoreCve(i) : null;
  const under = isExploited(i) ? `<small class="why kev">${esc(t.kevReason)}</small>` : pending ? `<small class="why unrated">${esc(t.unratedWhy)}</small>` : '';
  const sign = `<p class="sign"><b class="word">${esc(t.levels[level])}</b>${under ? ` ${under}` : ''}</p>`;
  const ring = rating
    ? `<span class="gauge sev-${rating}" role="img" aria-label="CVSS ${cvss.toFixed(1)} (${esc(t.rating[rating])})${top ? ` · ${esc(t.scoreOf(top))}` : ''}" style="--fill:${(Math.min(cvss, 10) / 10).toFixed(3)}"><svg viewBox="0 0 40 40" aria-hidden="true"><circle class="track" cx="20" cy="20" r="17" pathLength="1"/><circle class="arc" cx="20" cy="20" r="17" pathLength="1"/></svg><b>${cvss.toFixed(1)}</b></span>`
    : `<span class="gauge unrated" role="img" aria-label="${esc(t.unrated)}">—</span>`;
  const reason = exploitReason(i);
  let why = '';
  if (reason?.kind === 'kev') why = `${esc(t.kevListed)}${reason.date ? ` · ${esc(reason.date)}` : ''}`;
  if (reason?.kind === 'source') why = `${esc(t.attackSource)} ${link(reason.url, host(reason.url), t)}`;
  const hit = i.cves.length > 1 ? exploitedCves(i) : []; // which CVEs of a group are attacked; older data names none
  if (why && hit.length) why += ` · ${hit.map(esc).join(', ')}`;
  const poc = !reason && i.summary?.poc_public === true; // red like the Board's .kev line, the one red reason (critique 14)
  if (poc) why = esc(t.poc);
  const named = top ? `<p class="reason">${esc(t.scoreOf(top))}: CVSS ${cvss.toFixed(1)}</p>` : '';
  return `<div class="banner risk-${level}${pending ? ' unrated' : ''}">${sign}${ring}${named}${why ? `<p class="reason${poc ? ' kev' : ''}">${why}</p>` : ''}</div>`;
}

// Each tag links to the Board with that one filter (owner, 11-10), by the rule the Board's own tag buttons follow; same tab.
function products(i, lang) {
  const t = TEXT[lang];
  const items = tagFilters(i, lang).map((tag) => {
    const { bg, ink } = productLine(tag.pick || tag.name); // colours from the Board's fixed table, never from data
    const pill = tag.kind === 'os' ? `<span class="os">${esc(tag.name)}</span>` : `<span style="--line:${bg};--line-ink:${ink}">${esc(tag.name)}</span>`;
    return `<li><a href="/${esc(tagHash(tag))}" aria-label="${esc(t.tagLink(tag.name))}">${pill}</a></li>`;
  });
  if (!items.length) return '';
  // Past five tags the first four stay in view and the rest fold, as on the Board row (foldTags).
  const { shown, more } = foldTags(items);
  const rest = more ? `<details class="more"><summary>${esc(t.tagsRest(more))}</summary><ul class="tags">${items.slice(shown.length).join('')}</ul></details>` : '';
  return `<ul class="tags">${shown.join('')}</ul>${rest}`;
}

// Owner, 11-17: under the tags, each product's page (/p/<slug>, edge/product.mjs), operating systems aside.
// pages: [{ name, slug }] worked out by pageResponse (the slug is a hash, so async).
const productPages = (pages, t) => (pages.length
  ? `<p class="others">${pages.map((x) => `<a href="${t.productPath}${x.slug}">${esc(x.name)}</a>`).join(' · ')}</p>` : '');
const PRODUCT_LINKS = 5;
export const productPageList = async (i, lang) => Promise.all(productsOf(i, lang).filter((x) => !x.id.startsWith('os:')).slice(0, PRODUCT_LINKS)
  .map(async (x) => ({ name: x.name, slug: await checkSlug(x.id) })));

// M1 (owner, 11-15): under the Mitigation, the Board filtered to the first Product when it had other Incidents lately.
function othersLink(i, lang, t, others) {
  const found = productOthers(i, lang, others);
  return found ? `<p class="others"><a href="/${esc(found.hash)}">${esc(t.productOthers(found.n))}</a></p>` : '';
}

// H4 (owner, 11-16): a group's condition of some CVEs only shows their ids as a small mark before its text, as the
// Board's opened row does; any other entry is its text as written.
const idMark = (ids) => ids.map((id) => `<span class="cve-src">${esc(id)}</span>`).join(', ');
function condition(entry, cves) {
  const { ids, text } = conditionIds(entry, cves);
  return ids.length ? `${idMark(ids)} ${esc(text)}` : esc(entry);
}

// Step 10 (owner, 11-15/16): the Distribution table under the Mitigation, folded: release, package and state, the release
// linking that distribution's own page for the CVE, and in a group the CVEs a line holds for when not all. The credit
// line under it, inside the fold: each source linked, with its licence where the data gives one.
function distroFold(i, lang, t) {
  const table = distroTable(i, lang);
  if (!table) return '';
  const lines = table.lines.map((l) => `<strong>${link(l.url, l.label, t) || esc(l.label)}</strong> ${l.package ? `${esc(l.package)} · ` : ''}`
    + `${esc(l.state)}${l.ids.length ? ` ${idMark(l.ids)}` : ''}`);
  const credits = table.credits.map((c) => (link(c.url, c.name, t) || esc(c.name)) + (c.licence ? ` (${link(c.licenceUrl, c.licence, t) || esc(c.licence)})` : ''));
  return `<details class="more"><summary>${esc(table.title)}</summary>${ul(lines, 'cves lines')}`
    + `${credits.length ? `<p class="credits">${esc(t.distroSources)} ${credits.join(' · ')}</p>` : ''}</details>`;
}

// Every Mention by kind, in the Lead order; on the Korean page an English title shows the Summary's Korean line.
function mentions(i, lang, t) {
  const glosses = Array.isArray(i.summary?.titles_ko) ? i.summary.titles_ko : [];
  const named = (m) => (lang === 'ko' && glosses.find((g) => g?.url === m.url && typeof g.title === 'string')?.title) || m.title || host(m.url);
  const kinds = [...new Set([...MENTION_ORDER, ...i.mentions.map((m) => m.kind)])];
  // A group's CVE section links these already (IBM API Connect had 204 twice); with one or two, as on the Board, Sources keeps them.
  const listed = new Set(i.cves.length > 2 ? i.cves.map(cveUrl) : []);
  const shown = (m) => http(m.url) && !(m.kind === 'cve_record' && listed.has(m.url));
  // With every link hidden the Lead mention, the first CVE record by the Lead order, keeps Sources (H1, owner 11-15).
  if (!i.mentions.some(shown)) listed.delete(i.mentions.find((m) => http(m.url))?.url);
  return ul(kinds.flatMap((kind) => {
    const links = i.mentions.filter((m) => m.kind === kind && shown(m))
      .map((m) => link(m.url, named(m), t));
    return links.length ? [`${esc(t.mentionKinds[kind] || kind)}: ${links.join(' · ')}`] : [];
  }), 'sources');
}

const footer = (t) => `<footer><div class="wrap">${p(t.refNote)}${p(t.nvd)}<p lang="en">${NVD_EN}</p>${p(t.kevNote)}${p(t.cveNote)}<p lang="en">${MITRE}</p></div></footer>`;

// The header's language menu (owner, 11-17: a dropdown), without script: a details whose list links this document in
// every language, each named in itself. path(l): this document's address in language l.
export function langMenu(lang, path) {
  const t = TEXT[lang];
  const globe = '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.25"/><path d="M1.75 8h12.5M8 1.75c-3.2 3.4-3.2 9.1 0 12.5M8 1.75c3.2 3.4 3.2 9.1 0 12.5"/></svg>';
  const items = LANGS.map((l) => `<li><a href="${esc(path(l))}" hreflang="${l}" lang="${l}"${l === lang ? ' aria-current="page"' : ''}>${esc(WORDS[l].langName)}</a></li>`);
  return `<details class="langs"><summary class="lang" aria-label="${esc(`${t.langMenu}: ${t.langName}`)}">${globe}`
    + `<span class="full">${esc(t.langName)}</span><span class="short">${esc(t.langShort)}</span></summary><ul>${items.join('')}</ul></details>`;
}
// Each language's address of one document, for hreflang: Korean is also the x-default.
export const alternates = (url) => [...LANGS.map((l) => `<link rel="alternate" hreflang="${l}" href="${url(l)}">`),
  `<link rel="alternate" hreflang="x-default" href="${url('ko')}">`];

// other: the language menu for the header; the short notes have none. Also the product page's shell (edge/product.mjs).
export function document(lang, head, main, other = '') {
  const t = TEXT[lang];
  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${head}
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="theme-color" content="#f4f5f7" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#121417" media="(prefers-color-scheme: dark)">
<style>${CSS}</style>
</head>
<body>
<header><div class="wrap"><a class="brand" href="/">${LOGO}Patch Ticker</a>${other}</div></header>
<main class="wrap">${main}</main>
${footer(t)}
</body>
</html>`;
}

// Owner, 11-17: what the page states, as schema.org data for search engines and agents. A data block runs nothing, so the
// CSP's script-src does not apply to it; '<', '>', '&' and the two line separators are written as \u escapes, so no text
// from the web or a model can close the element or read as markup.
const LD_UNSAFE = new RegExp(`[<>&${String.fromCharCode(0x2028, 0x2029)}]`, 'g');
const jsonLd = (data) => `<script type="application/ld+json">${JSON.stringify(data)
  .replace(LD_UNSAFE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)}</script>`;

// others: board/others.json (M1), or null. pages: productPageList's answer (the products' pages), or none.
export function pageHtml(i, lang, slug, others = null, pages = []) {
  const t = TEXT[lang];
  const s = i.summary?.[lang] || {};
  const level = riskLevel(i);
  const title = titleOf(i, lang);
  const plain = s.easy ? easyLine(s.easy, level) : '';
  const description = plain || String(s.summary || '').split(/(?<=[.!?])\s/)[0] || i.brief?.text || title;
  const self = pageUrl(lang, slug);
  const head = [`<title>${esc(title)} · Patch Ticker</title>`,
    `<meta name="description" content="${esc(description)}">`,
    ...(searchWorthy(i) ? [] : ['<meta name="robots" content="noindex">']),
    `<link rel="canonical" href="${self}">`,
    ...alternates((l) => pageUrl(l, slug)),
    '<meta property="og:type" content="article">',
    '<meta property="og:site_name" content="Patch Ticker">',
    `<meta property="og:url" content="${self}">`,
    `<meta property="og:title" content="${esc(title)}">`,
    `<meta property="og:description" content="${esc(description)}">`,
    `<meta property="og:image" content="${SITE}/og.png">`,
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
    `<meta property="og:locale" content="${t.locale}">`,
    ...LANGS.filter((l) => l !== lang).map((l) => `<meta property="og:locale:alternate" content="${TEXT[l].locale}">`),
    '<meta name="twitter:card" content="summary_large_image">',
    jsonLd({ '@context': 'https://schema.org', '@type': 'Article', headline: title, description,
      datePublished: i.published || i.first_seen, dateCreated: i.first_seen, inLanguage: lang, url: self, mainEntityOfPage: self,
      isAccessibleForFree: true, publisher: { '@type': 'Organization', name: 'Patch Ticker', url: `${SITE}/` } })].join('\n');
  // M4: the Public date is a day as the CVE record gives it (UTC), so it is text, not a <time> the script rewrites.
  const times = [i.published ? `${esc(t.published)} ${when(i.published, lang)}` : '',
    publicDay(i) ? `${esc(t.publicDate)} ${esc(publicDay(i))}` : '', `${esc(t.firstSeen)} ${when(i.first_seen, lang)}`].filter(Boolean);
  const main = [`<article><h1>${esc(title)}</h1>`,
    banner(i, t),
    p(plain, 'easy'),
    section('summary', t.summary, p(s.summary)),
    section('conditions', t.conditions, ul(strings(s.conditions).map((c) => condition(c, i.cves)))),
    section('todo', t.todo, whatToDo(i, lang) + othersLink(i, lang, t, others) + distroFold(i, lang, t)),
    section('products', t.products, products(i, lang)),
    section('product-pages', t.productPages, productPages(pages, t)),
    section('cves', t.cves, cveList(i, lang, t)),
    section('mentions', t.mentions, mentions(i, lang, t)),
    section('times', t.times, times.map((x) => `<p>${x}</p>`).join('')),
    `<script>${LOCAL_TIME}</script>`,
    '</article>',
    `<nav class="links" aria-label="${esc(t.links)}"><a href="/#i=${esc(encodeURIComponent(i.id))}">${esc(t.board)}</a>`
      + `<a href="${esc(reportUrl(i, lang, self, slug))}"${NEW_TAB}>${REPORT_ICON}${esc(t.report)}</a></nav>`].join('\n');
  return document(lang, head, main, langMenu(lang, (l) => `${TEXT[l].path}${slug}`));
}

// Edge cache times: a page, a move and an expired page change at most once a cycle; a missing page may appear sooner.
const CACHE = 'public, max-age=300';
const CACHE_404 = 'public, max-age=60';

// A short note in place of a page (404, 410, 503): never indexed, always a way on. A 503 is never cached.
export function note(lang, status, text, links) {
  const head = `<title>Patch Ticker</title>\n<meta name="robots" content="noindex">`;
  const body = `<h1>${esc(text)}</h1><nav class="links">${links.join('')}</nav>`;
  const extra = { 503: { 'retry-after': '600' }, 404: { 'cache-control': CACHE_404 }, 410: { 'cache-control': CACHE } }[status];
  return new Response(document(lang, head, body), { status, headers: { 'content-type': 'text/html; charset=utf-8', ...extra } });
}

const redirect = (status, location) => new Response(null, { status, headers: { location, 'cache-control': CACHE } });

// bucket: the R2 binding (anything with get(key) -> { text() } or null). now: for the 90-day check.
export async function pageResponse(bucket, lang, slug, now = Date.now()) {
  const t = TEXT[lang];
  const home = `<a href="/">${esc(t.home)}</a>`;
  const expired = (page) => note(lang, 410, t.expired, page?.cves
    ? [`<a href="/#i=${esc(encodeURIComponent(page.id))}">${esc(t.board)}</a>`, ...(page.cves[0] ? [link(cveUrl(page.cves[0]), t.cveRecord, t)] : [])]
    : [home]);
  if (!SLUG.test(slug)) return note(lang, 404, t.missing, [home]);
  return failClosed(async () => {
    const doc = await readJson(bucket, `pages/${slug}.json`);
    if (!doc) return note(lang, 404, t.missing, [home]);
    if (doc.moved_to) {
      // An absorbed Incident (ticket 04): its address moves to the survivor's page while both are within PAGE_DAYS,
      // and to the survivor's row on the Board while the survivor has no page yet (owner, 11-10).
      if (!withinPageDays(doc.moved, now)) return expired(null);
      if (typeof doc.moved_to_id !== 'string' || !doc.moved_to_id) throw new Error(`pages/${slug}.json: no survivor`);
      const target = SLUG.test(doc.moved_to) ? await readJson(bucket, `pages/${doc.moved_to}.json`) : null;
      if (target?.first_seen && !withinPageDays(target.first_seen, now)) return expired(target);
      if (!target?.summary || target.moved_to || !onBoard(target)) return redirect(302, `${SITE}/#i=${encodeURIComponent(doc.moved_to_id)}`);
      return redirect(301, pageUrl(lang, doc.moved_to));
    }
    if (!withinPageDays(doc.first_seen, now)) return expired(doc);
    if (!doc.summary || !onBoard(doc)) return note(lang, 404, t.missing, [home]);
    // M1: the Products' counts, one read beside the page document; missing or unreadable, only the link is left out.
    const others = await readJson(bucket, 'board/others.json').catch(() => null);
    return new Response(pageHtml(doc, lang, slug, others, await productPageList(doc, lang)), {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': CACHE, 'content-security-policy': PAGE_CSP },
    });
  }, () => note(lang, 503, t.down, [`<a href="${SITE}/">${esc(t.home)}</a>`]));
}
