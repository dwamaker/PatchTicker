// Incident pages (spec: .scratch/incident-pages/spec.md; ADR 0002, 2026-11-10 revision). The Pages Function reads the
// collector's pages/<slug>.json from R2 and renders one plain document per language, without script. The rules (risk
// level, exploited reason, easy action, Product names, on the Board, search-worthy) are the Board's own, imported from
// web/board.mjs; only the words live here. Titles, Summaries and URLs come from the web and a model: every text is
// escaped and only http(s) addresses become links.
import { cvssRating, easyLine, exploitReason, isExploited, lineKeys, onBoard, productLine, riskLevel, rowTags, searchWorthy, withinPageDays } from '../web/board.mjs';
import { SITE, SLUG, escapeXml as esc, failClosed, p, readJson, strings, titleOf, ul, whatToDo } from './shared.mjs';

const ISSUES = 'https://github.com/dwamaker/PatchTicker/issues/new';
const NEW_TAB = ' target="_blank" rel="noopener noreferrer"';
const MENTION_ORDER = ['advisory', 'writeup', 'cve_record', 'discussion', 'curator', 'notice', 'repo'];
const NVD_EN = 'This product uses data from the NVD API but is not endorsed or certified by the NVD.';
const MITRE = 'CVE&reg; records: Copyright &copy; 1999&ndash;2026, The MITRE Corporation. CVE is a registered trademark of The MITRE Corporation. CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE&reg;). Any copy you make for such purposes is authorized provided that you reproduce MITRE\'s copyright designation and this license in any such copy. <a href="https://www.cve.org/Legal/TermsOfUse">CVE Terms of Use</a>';

// The Board's words (web/app.mjs TEXT) for what the page shows, plus the page's own.
const TEXT = {
  ko: {
    path: '/i/', locale: 'ko_KR', other: 'English', otherLang: 'en',
    levels: { highest: '고위험', high: '위험', notice: '참고' }, kevReason: '악용 발생', kevListed: 'CISA KEV 등재', attackSource: '공격 보고:', poc: '공격 코드 공개됨',
    unrated: 'CVSS 점수 대기', rating: { critical: '심각', high: '높음', medium: '보통', low: '낮음', none: '없음' },
    summary: '요약', conditions: '해당 조건', todo: '대처법', products: '대상 제품과 운영체제', cves: 'CVE 번호', moreCves: (n) => `CVE ${n}건 더 보기`, mentions: '원문 링크', times: '시각', links: '이 사건 더 보기',
    published: '처음 게시', firstSeen: '처음 확인', zone: '',
    mentionKinds: { advisory: '보안 공지', writeup: '분석 글', cve_record: 'CVE 기록', discussion: '토론', curator: '뉴스레터', notice: '보호나라 공지', repo: '저장소' },
    newTab: ' (새 탭에서 열림)', board: '게시판에서 보기', report: '틀린 내용 알리기', cveRecord: 'CVE 기록 보기',
    refNote: '이 게시판은 참고용입니다. 조치하기 전에 각 사건의 원문 공지를 확인하세요.',
    nvd: '이 서비스는 NVD API 데이터를 사용하지만 NVD의 보증이나 인증을 받지 않았습니다.',
    kevNote: '악용 발생 표시는 CISA의 알려진 악용 취약점(KEV) 목록이나, 실제 공격을 전한 원문을 바탕으로 합니다.',
    cveNote: 'CVE 정보는 MITRE의 CVE 이용 약관에 따라 사용합니다. 아래는 약관이 요구하는 저작권 표시와 라이선스 원문입니다.',
    expired: '보관 기간 90일이 지났어요. 이 사건 페이지는 더 이상 없습니다.', missing: '이 주소에는 사건 페이지가 없습니다.',
    down: '지금은 사건 페이지를 불러올 수 없습니다. 잠시 뒤 다시 시도하세요.', home: '게시판으로 가기',
  },
  en: {
    path: '/en/i/', locale: 'en_US', other: '한국어', otherLang: 'ko',
    levels: { highest: 'High risk', high: 'Elevated', notice: 'Notice' }, kevReason: 'Exploited', kevListed: 'Listed in CISA KEV', attackSource: 'Attacks reported:', poc: 'Exploit code is public',
    unrated: 'CVSS score pending', rating: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' },
    summary: 'Summary', conditions: 'Affected when', todo: 'What to do', products: 'Products and platforms', cves: 'CVE IDs', moreCves: (n) => `${n} more CVE IDs`, mentions: 'Sources', times: 'Times', links: 'More on this Incident',
    published: 'First published', firstSeen: 'First seen', zone: ' UTC',
    mentionKinds: { advisory: 'Advisory', writeup: 'Write-up', cve_record: 'CVE record', discussion: 'Discussion', curator: 'Newsletter', notice: 'KISA notice', repo: 'Repository' },
    newTab: ' (opens in a new tab)', board: 'Open on the Board', report: 'Report a mistake', cveRecord: 'See the CVE record',
    refNote: "This Board is for reference only. Check each Incident's source advisory before you act.",
    nvd: '',
    kevNote: 'Exploited flags come from the CISA Known Exploited Vulnerabilities catalog, or from sources that report attacks.',
    cveNote: 'CVE data is used under the CVE Terms of Use from MITRE; its required copyright notice and license follow.',
    expired: 'This Incident page has expired: pages are kept for 90 days.', missing: 'There is no Incident page at this address.',
    down: 'Incident pages cannot be loaded right now. Please try again shortly.', home: 'Go to the Board',
  },
};

const CSS = `:root{color-scheme:light dark;--bg:light-dark(#f4f5f7,#121417);--panel:light-dark(#fff,#191c20);--panel-2:light-dark(#eceef1,#1f2328);--ink:light-dark(#16191d,#ececec);--ink-2:light-dark(#4f5862,#a8afb7);--ink-3:light-dark(#5f6872,#8c949d);--rule:light-dark(#dde1e5,#2a2f35);--rule-2:light-dark(#c4c9cf,#3a4048);--edge:light-dark(#858e97,#6b737c);--high:light-dark(#c4231c,#ff6b62);--mid:light-dark(#8a6100,#f5b400);--mid-mark:light-dark(#a87700,#f5b400);--note:light-dark(#5a6570,#9aa3ad);--focus:light-dark(#1a5fb4,#7cc4ff);--sans:"Pretendard Variable",Pretendard,"Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",system-ui,sans-serif;--mono:ui-monospace,"Cascadia Mono",Consolas,monospace}
*,*::before,*::after{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--ink);font:400 0.9375rem/1.55 var(--sans);letter-spacing:-0.005em;word-break:keep-all;overflow-wrap:anywhere;-webkit-font-smoothing:antialiased}
a{color:var(--focus);text-underline-offset:3px}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
.wrap{max-width:45rem;margin:0 auto;padding:0 1rem}
header{border-bottom:1px solid var(--rule)}
header .wrap{min-height:3.5rem;display:flex;align-items:center;justify-content:space-between;gap:.75rem}
.brand{color:var(--ink);font-size:1.125rem;font-weight:700;letter-spacing:-0.02em;text-decoration:none}
main{padding:1.5rem 0 2rem}
h1{margin:0 0 1rem;font:700 1.5rem/1.3 var(--sans);letter-spacing:-0.02em}
p{margin:.375rem 0}
ul{margin:.25rem 0;padding-left:1.25rem}
.banner{display:flex;flex-wrap:wrap;align-items:center;gap:.75rem 1rem;padding:1rem;border:1px solid var(--rule);border-left:4px solid var(--note);border-radius:10px;background:var(--panel)}
.banner.risk-highest{border-left-color:var(--high)}
.banner.risk-high{border-left-color:var(--mid-mark)}
.sign{margin:0;display:flex;flex-direction:column;align-items:flex-start;gap:.25rem;color:var(--note)}
.risk-highest .sign{color:var(--high)}
.risk-high .sign{color:var(--mid)}
.word{padding:.2rem .75rem;border:1.5px solid currentColor;border-radius:999px;font-weight:800}
.why{font-size:.8125rem;font-weight:700}
.gauge{position:relative;flex:none;width:3rem;height:3rem;display:grid;place-items:center;color:var(--note)}
.gauge svg{position:absolute;inset:0;width:100%;height:100%;transform:rotate(-90deg)}
.gauge circle{fill:none;stroke-width:3.5}
.gauge .track{stroke:var(--rule-2)}
.gauge .arc{stroke:currentColor;stroke-dasharray:var(--fill) 1;stroke-linecap:round}
.gauge b{color:var(--ink);font-size:.875rem}
.gauge.unrated{border:2px dashed var(--rule-2);border-radius:50%;color:var(--ink-3)}
.sev-critical{color:var(--high)}
.sev-high{color:var(--mid-mark)}
.reason{flex-basis:100%;margin:0;color:var(--ink-2);font-size:.875rem}
.easy{margin-top:1rem;font-size:1.0625rem;font-weight:600}
section{margin-top:1.5rem}
.label{margin:0 0 .375rem;color:var(--ink-2);font-size:.8125rem;font-weight:700}
code{font-family:var(--mono);font-size:.875rem}
.command{padding:.5rem .75rem;border-radius:8px;background:var(--panel-2);white-space:pre-wrap;word-break:break-all}
.caution{color:var(--ink-2);font-size:.875rem}
.tags{display:flex;flex-wrap:wrap;gap:.375rem;padding:0;list-style:none}
.tags li{padding:.125rem .625rem;border-radius:999px;background:var(--line);color:var(--line-ink);font-size:.875rem;font-weight:600}
.tags .os{border:1px solid var(--edge);background:none;color:var(--ink)}
.links{display:flex;flex-wrap:wrap;gap:0 1.25rem;margin-top:2rem;padding-top:.5rem;border-top:1px solid var(--rule)}
.links a{display:inline-flex;align-items:center;min-height:44px}
.sources a{display:inline-flex;align-items:center;min-height:44px;padding-inline:.25rem}
.more summary{cursor:pointer;padding:.75rem 0;font-weight:600}
footer{padding:1rem 0 2rem;border-top:1px solid var(--rule);color:var(--ink-3);font-size:.8125rem}`;

const http = (url) => (typeof url === 'string' && /^https?:\/\//i.test(url) ? url : null);
// A source link opens in a new tab, as on the Board (DESIGN.md), and says so to screen readers.
const link = (url, text, t) => (http(url) ? `<a href="${esc(url)}"${NEW_TAB}>${esc(text)}<span class="sr-only">${esc(t.newTab)}</span></a>` : '');
const host = (url) => { try { return new URL(url).host.replace(/^www\./, ''); } catch { return String(url); } };
// A release can carry hundreds of CVEs (IBM API Connect: 204): the first CVE_SHOWN stay in view, the rest fold. Every
// link stays in the HTML for search engines; <details> needs no script.
const CVE_SHOWN = 10;
const cveList = (cves, t) => {
  const links = cves.map((cve) => link(cveUrl(cve), cve, t));
  if (links.length <= CVE_SHOWN + 2) return ul(links, 'sources'); // two more are not worth a fold
  return ul(links.slice(0, CVE_SHOWN), 'sources')
    + `<details class="more"><summary>${esc(t.moreCves(links.length - CVE_SHOWN))}</summary>${ul(links.slice(CVE_SHOWN), 'sources')}</details>`;
};
const section = (key, label, body) => (body ? `<section aria-labelledby="s-${key}"><p class="label" id="s-${key}">${esc(label)}</p>${body}</section>` : '');
const cveUrl = (cve) => `https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}`;
const pageUrl = (lang, slug) => `${SITE}${TEXT[lang].path}${slug}`;

// Korean readers get Korean time (UTC+9, no daylight saving), everyone else UTC.
function when(stamp, lang) {
  const at = Date.parse(stamp);
  if (Number.isNaN(at)) return esc(stamp);
  const d = new Date(at + (lang === 'ko' ? 9 * 60 * 60 * 1000 : 0)).toISOString();
  return `<time datetime="${esc(stamp)}">${d.slice(0, 10)} ${d.slice(11, 16)}${TEXT[lang].zone}</time>`;
}

// The risk banner: the rule-based level, why it is exploited, and the CVSS ring.
function banner(i, t) {
  const level = riskLevel(i);
  const cvss = Number.isFinite(i.cvss) ? i.cvss : null;
  const rating = cvssRating(cvss);
  const sign = `<p class="sign"><b class="word">${esc(t.levels[level])}</b>${isExploited(i) ? ` <small class="why">${esc(t.kevReason)}</small>` : ''}</p>`;
  const ring = rating
    ? `<span class="gauge sev-${rating}" role="img" aria-label="CVSS ${cvss.toFixed(1)} (${esc(t.rating[rating])})" style="--fill:${(Math.min(cvss, 10) / 10).toFixed(3)}"><svg viewBox="0 0 40 40" aria-hidden="true"><circle class="track" cx="20" cy="20" r="17" pathLength="1"/><circle class="arc" cx="20" cy="20" r="17" pathLength="1"/></svg><b>${cvss.toFixed(1)}</b></span>`
    : `<span class="gauge unrated" role="img" aria-label="${esc(t.unrated)}">—</span>`;
  const reason = exploitReason(i);
  let why = '';
  if (reason?.kind === 'kev') why = `${esc(t.kevListed)}${reason.date ? ` · ${esc(reason.date)}` : ''}`;
  if (reason?.kind === 'source') why = `${esc(t.attackSource)} ${link(reason.url, host(reason.url), t)}`;
  if (!reason && i.summary?.poc_public === true) why = esc(t.poc);
  return `<div class="banner risk-${level}">${sign}${ring}${why ? `<p class="reason">${why}</p>` : ''}</div>`;
}

function products(i, lang) {
  const os = new Set(strings(i.summary?.platforms));
  const keys = lineKeys(i, lang);
  const items = rowTags(i, lang).map((name) => {
    if (os.has(name)) return `<li class="os">${esc(name)}</li>`;
    const { bg, ink } = productLine(keys.get(name) || name); // colours from the Board's fixed table, never from data
    return `<li style="--line:${bg};--line-ink:${ink}">${esc(name)}</li>`;
  });
  return items.length ? `<ul class="tags">${items.join('')}</ul>` : '';
}

// Every Mention by kind, in the Lead order; on the Korean page an English title shows the Summary's Korean line.
function mentions(i, lang, t) {
  const glosses = Array.isArray(i.summary?.titles_ko) ? i.summary.titles_ko : [];
  const named = (m) => (lang === 'ko' && glosses.find((g) => g?.url === m.url && typeof g.title === 'string')?.title) || m.title || host(m.url);
  const kinds = [...new Set([...MENTION_ORDER, ...i.mentions.map((m) => m.kind)])];
  const listed = new Set(i.cves.map(cveUrl)); // the CVE section links these already (IBM API Connect had 204 twice)
  return ul(kinds.flatMap((kind) => {
    const links = i.mentions.filter((m) => m.kind === kind && http(m.url) && !(kind === 'cve_record' && listed.has(m.url)))
      .map((m) => link(m.url, named(m), t));
    return links.length ? [`${esc(t.mentionKinds[kind] || kind)}: ${links.join(' · ')}`] : [];
  }), 'sources');
}

// 틀린 내용 알리기: the Board's issue form (web/app.mjs reportLink), pointing at this page.
function reportUrl(i, lang, slug) {
  const titleIn = (l) => titleOf(i, l);
  const body = [`사건 / Incident: ${i.id}`, `제목: ${titleIn('ko')}`, `Title: ${titleIn('en')}`, `링크 / Link: ${pageUrl(lang, slug)}`, '',
    '무엇이 틀렸나요? / What is wrong?', '(예: 위험도, 영향받는 제품이나 버전, 요약 내용 / e.g. the risk level, the affected products or versions, the summary)',
    '', '', '근거가 있다면 링크를 적어 주세요. / Please add a link to your source if you have one.', ''].join('\n');
  return `${ISSUES}?${new URLSearchParams({ title: `[오류 제보 / Mistake] ${i.id}: ${titleIn(lang)}`, body })}`;
}

const footer = (t) => `<footer><div class="wrap">${p(t.refNote)}${p(t.nvd)}<p lang="en">${NVD_EN}</p>${p(t.kevNote)}${p(t.cveNote)}<p lang="en">${MITRE}</p></div></footer>`;

function document(lang, head, main) {
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
<header><div class="wrap"><a class="brand" href="/">Patch Ticker</a></div></header>
<main class="wrap">${main}</main>
${footer(t)}
</body>
</html>`;
}

export function pageHtml(i, lang, slug) {
  const t = TEXT[lang];
  const s = i.summary?.[lang] || {};
  const level = riskLevel(i);
  const title = titleOf(i, lang);
  const plain = s.easy ? easyLine(s.easy, level) : '';
  const description = plain || String(s.summary || '').split(/(?<=[.!?])\s/)[0] || i.brief?.text || title;
  const self = pageUrl(lang, slug);
  const ko = pageUrl('ko', slug);
  const head = [`<title>${esc(title)} · Patch Ticker</title>`,
    `<meta name="description" content="${esc(description)}">`,
    ...(searchWorthy(i) ? [] : ['<meta name="robots" content="noindex">']),
    `<link rel="canonical" href="${self}">`,
    `<link rel="alternate" hreflang="ko" href="${ko}">`,
    `<link rel="alternate" hreflang="en" href="${pageUrl('en', slug)}">`,
    `<link rel="alternate" hreflang="x-default" href="${ko}">`,
    '<meta property="og:type" content="article">',
    '<meta property="og:site_name" content="Patch Ticker">',
    `<meta property="og:url" content="${self}">`,
    `<meta property="og:title" content="${esc(title)}">`,
    `<meta property="og:description" content="${esc(description)}">`,
    `<meta property="og:image" content="${SITE}/og.png">`,
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
    `<meta property="og:locale" content="${t.locale}">`,
    `<meta property="og:locale:alternate" content="${TEXT[t.otherLang].locale}">`,
    '<meta name="twitter:card" content="summary_large_image">'].join('\n');
  const times = [i.published ? `${esc(t.published)} ${when(i.published, lang)}` : '', `${esc(t.firstSeen)} ${when(i.first_seen, lang)}`].filter(Boolean);
  const main = [`<article><h1>${esc(title)}</h1>`,
    banner(i, t),
    p(plain, 'easy'),
    section('summary', t.summary, p(s.summary)),
    section('conditions', t.conditions, ul(strings(s.conditions).map(esc))),
    section('todo', t.todo, whatToDo(i, lang)),
    section('products', t.products, products(i, lang)),
    section('cves', t.cves, cveList(i.cves, t)),
    section('mentions', t.mentions, mentions(i, lang, t)),
    section('times', t.times, times.map((x) => `<p>${x}</p>`).join('')),
    '</article>',
    `<nav class="links" aria-label="${esc(t.links)}"><a href="/#i=${esc(encodeURIComponent(i.id))}">${esc(t.board)}</a>`
      + `<a href="${t.otherLang === 'en' ? '/en/i/' : '/i/'}${slug}" hreflang="${t.otherLang}" lang="${t.otherLang}">${esc(t.other)}</a>`
      + `<a href="${esc(reportUrl(i, lang, slug))}"${NEW_TAB}>${esc(t.report)}</a></nav>`].join('\n');
  return document(lang, head, main);
}

// Edge cache times: a page, a move and an expired page change at most once a cycle; a missing page may appear sooner.
const CACHE = 'public, max-age=300';
const CACHE_404 = 'public, max-age=60';

// A short note in place of a page (404, 410, 503): never indexed, always a way on. A 503 is never cached.
function note(lang, status, text, links) {
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
    return new Response(pageHtml(doc, lang, slug), {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': CACHE,
        // No script on the page at all; inline styles only (the Board's tokens and line colours).
        'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" },
    });
  }, () => note(lang, 503, t.down, [`<a href="${SITE}/">${esc(t.home)}</a>`]));
}
