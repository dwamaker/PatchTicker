// Incident pages (spec: .scratch/incident-pages/spec.md; ADR 0002, 2026-11-10 revision). The Pages Function reads the
// collector's pages/<slug>.json from R2 and renders one plain document per language, whose one script shows the times in the
// reader's zone. The rules (risk level, exploited reason, easy action, Product names, on the Board, search-worthy) are
// the Board's own, imported from web/board.mjs, and so are the shared words (WORDS); only the page's own words live here. Titles, Summaries and URLs come from the web and a model: every text is
// escaped and only http(s) addresses become links.
import { conditionIds, cveExploit, cveHead, cveLines, cveScore, distroTable, cveUrl, cvssRating, easyLine, exploitedCves, exploitReason, scoreCve, foldTags, isExploited, mentionGroups, MENTIONS_SHOWN, onBoard, nameLine, pendingWhy, productOthers, provisionalLevel, severityWord, productsOf, publicDay, reportUrl, riskLevel, scorePair, searchWorthy, tagFilters, tagHash, withinPageDays, WORDS, LANGS } from '../web/board.mjs';
import { SEARCH_LANGS, SITE, SLUG, checkSlug, escapeXml as esc, failClosed, host, http, p, readJson, searchLang, strings, titleOf, ul, whatToDo } from './shared.mjs';

const NEW_TAB = ' target="_blank" rel="noopener noreferrer"';
// The Board's logo symbol (index.html #home) and its 틀린 내용 알리기 icon (app.mjs reportLink).
const LOGO = '<svg viewBox="0 0 64 56" aria-hidden="true"><path fill-rule="evenodd" d="M17 0H44A20 20 0 0 1 44 40H34V56H17V26.5H0V13.5H17ZM53.5 20A9.5 9.5 0 1 0 34.5 20A9.5 9.5 0 1 0 53.5 20Z"/></svg>';
const REPORT_ICON = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2.5 14 13H2Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 6.5v3M8 11.2v.1" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>';
const NVD_EN = 'This product uses data from the NVD API but is not endorsed or certified by the NVD.';
const MITRE = 'CVE&reg; records: Copyright &copy; 1999&ndash;2026, The MITRE Corporation. CVE is a registered trademark of The MITRE Corporation. CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE&reg;). Any copy you make for such purposes is authorized provided that you reproduce MITRE\'s copyright designation and this license in any such copy. <a href="https://www.cve.org/Legal/TermsOfUse">CVE Terms of Use</a>';

// The shared words (web/board.mjs WORDS) for what the page shows, plus the page's own.
// The opened row's own words (web/app.mjs TEXT), word for word, so a heading or a link reads the same on the Board and here.
const ROW = {
  ko: { mitigationHead: '대처법', aboutHead: '요약', scoreHead: '점수', cveHead: 'CVE', tagsHead: '제품', patchTag: '함께 공개',
    moreIds: (n) => ` 외 ${n}건`, cveCount: (n) => `CVE ${n}건`, cveLinesHead: (n) => `CVE ${n}건 각각의 내용`, moreLines: (n) => `${n}건 더 보기`,
    linkKind: { advisory: '공지', writeup: '분석' }, newTabAll: ' (아래 링크는 모두 새 탭에서 열림)',
    lead: { advisory: '공식 공지 읽기', writeup: '분석 글 읽기', cve_record: 'CVE 기록 읽기', discussion: '토론 읽기', curator: '뉴스레터 읽기', notice: '보호나라 공지 읽기', repo: '저장소 보기', other: '원문 읽기' } },
  en: { mitigationHead: 'Mitigation', aboutHead: 'Summary', scoreHead: 'Score', cveHead: 'CVE', tagsHead: 'Products', patchTag: 'Disclosed together',
    moreIds: (n) => ` and ${n} more`, cveCount: (n) => `${n} CVEs`, cveLinesHead: (n) => `Each of the ${n} CVEs`, moreLines: (n) => `Show ${n} more`,
    linkKind: { advisory: 'advisory', writeup: 'write-up' }, newTabAll: ' (every link below opens in a new tab)',
    lead: { advisory: 'Read the advisory', writeup: 'Read the write-up', cve_record: 'Read the CVE record', discussion: 'Read the discussion', curator: 'Read the newsletter', notice: 'Read the KISA notice', repo: 'See the repository', other: 'Read the source' } },
  ja: { mitigationHead: '対処法', aboutHead: '要約', scoreHead: 'スコア', cveHead: 'CVE', tagsHead: '製品', patchTag: '同時公開',
    moreIds: (n) => ` ほか${n}件`, cveCount: (n) => `CVE ${n}件`, cveLinesHead: (n) => `CVE ${n}件それぞれの内容`, moreLines: (n) => `あと${n}件を表示`,
    linkKind: { advisory: '勧告', writeup: '解説' }, newTabAll: '（下のリンクはすべて新しいタブで開きます）',
    lead: { advisory: '勧告を読む', writeup: '解説記事を読む', cve_record: 'CVE レコードを読む', discussion: '議論を読む', curator: 'ニュースレターを読む', notice: 'KISA の告知を読む', repo: 'リポジトリを見る', other: '原文を読む' } },
};

const TEXT = {
  ko: {
    ...WORDS.ko,
    ...ROW.ko,
    path: '/i/', productPath: '/p/', dayPath: '/d/', locale: 'ko_KR',
    related: (name) => `${name}의 다른 최근 사건`, dayLink: (day) => `${day} 보안 사건 모두 보기`,
    rating: { critical: '심각', high: '높음', medium: '보통', low: '낮음', none: '없음' },
    productPages: '제품별 사건', summary: '요약', todo: '대처법', products: '대상 제품과 운영체제', cves: 'CVE 번호', moreCves: (n) => `CVE ${n}건 더 보기`, mentions: '원문 링크', times: '시각', links: '이 사건 더 보기',
    firstSeen: '처음 확인', zone: ' KST',
    board: '현황판에서 보기', cveRecord: 'CVE 기록 보기', tagLink: (name) => `현황판에서 ${name} 사건 보기`,
    expired: '보관 기간 90일이 지나 이 사건 페이지는 더 이상 없습니다.', missing: '이 주소에는 사건 페이지가 없습니다.',
    down: '지금은 사건 페이지를 불러올 수 없습니다. 잠시 뒤 다시 시도하세요.', home: '현황판으로 가기',
  },
  en: {
    ...WORDS.en,
    ...ROW.en,
    path: '/en/i/', productPath: '/en/p/', dayPath: '/en/d/', locale: 'en_US',
    related: (name) => `Other recent Incidents of ${name}`, dayLink: (day) => `All Incidents of ${day}`,
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
    ...ROW.ja,
    path: '/ja/i/', productPath: '/ja/p/', dayPath: '/ja/d/', locale: 'ja_JP',
    related: (name) => `${name} のほかの最近のインシデント`, dayLink: (day) => `${day} のインシデント一覧`,
    rating: { critical: '緊急', high: '重要', medium: '警告', low: '注意', none: 'なし' },
    productPages: '製品別のインシデント', summary: '要約', todo: '対処法', products: '対象の製品と OS', cves: 'CVE 番号', moreCves: (n) => `CVE をあと${n}件表示`, mentions: '原文リンク', times: '日時', links: 'このインシデントをもっと見る',
    firstSeen: '初確認', zone: ' JST',
    board: 'ボードで見る', cveRecord: 'CVE レコードを見る', tagLink: (name) => `ボードで ${name} のインシデントを見る`,
    expired: '保存期間の90日を過ぎたため、このインシデントのページはもうありません。', missing: 'このアドレスにはインシデントのページがありません。',
    down: '現在インシデントのページを読み込めません。しばらくしてからもう一度お試しください。', home: 'ボードへ戻る',
  },
};

// The page's own rules (owner, 11-27: "디자인 왜 따로쓰냐"). Everything else is the Board's web/board.css, which every
// page links: the Incident page draws the opened row's markup and classes (web/app.mjs details()), so a design change
// on the Board reaches it. Here only what the Board has no part for: the page's header, its title, the language menu as
// a details, the closing links and the short notes.
const CSS = `.page .wrap{max-width:52rem}
.page .top .wrap{display:flex;align-items:center;justify-content:space-between;gap:.75rem;min-height:4rem}
.home{display:inline-flex;align-items:center;gap:.625rem;min-height:var(--tap);color:var(--ink);font:700 calc(1.25rem * var(--ts))/1 var(--sans);letter-spacing:-0.02em;text-decoration:none}
.home svg{flex:none;height:1em;width:auto;fill:var(--focus)}
.page main.wrap{min-height:0;padding-block:2rem}
.page main h1{display:block;margin:0 0 1rem;font:700 calc(1.5rem * var(--ts))/1.3 var(--sans);letter-spacing:-0.02em;white-space:normal;text-wrap:balance}
.p-head{display:grid;grid-template-columns:max-content minmax(0,1fr) max-content;align-items:center;gap:.5rem 1rem}
.p-head>*{grid-area:auto}
.page .p-head h1.title{margin:0;font-size:calc(1.375rem * var(--ts));line-height:1.35}
.p-head .sub{margin:.25rem 0 0;color:var(--ink-2);font-size:calc(var(--fs-meta) * var(--ts));font-variant-numeric:tabular-nums}
@media (max-width:599px){.p-head{grid-template-columns:minmax(0,1fr) max-content}.p-head .c-title{grid-column:1/-1;grid-row:2}}
.page .easy{margin:1rem 0 0;font-size:calc(1.0625rem * var(--ts));font-weight:600}
.page .details{margin-top:1.5rem;padding:0}
.page .details :is(h2.sec-head,h2.cve-lines-head){color:var(--ink)}
.page .details .others{margin:.75rem 0 0}
.fix-list:has(+ .fix-more:not([open])) > .rest{display:none}
.fix-more[open] .closed,.fix-more:not([open]) .opened{display:none}
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
@media (max-width:599px){.lang .full{display:none}.lang .short{display:inline}}
.links{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:2rem;padding-top:1rem;border-top:1px solid var(--rule)}
/* a note in place of a page (note()): Astryx EmptyState, centred, 32/24 padding, 16 gap, an icon over the title, the description in Secondary Ink, the way on one row */
.gone{display:flex;flex-direction:column;align-items:center;gap:1rem;padding:2rem 1.5rem;text-align:center}
.gone-icon{width:2rem;height:2rem;color:var(--ink-3)}
.page .gone h1{margin:0;font-size:calc(1.25rem * var(--ts))}
.gone p{margin:-.5rem 0 0;max-width:30rem;color:var(--ink-2)}
.gone .links{justify-content:center;margin:.25rem 0 0;padding:0;border:0}`;

// A source link opens in a new tab, as on the Board (DESIGN.md), and says so to screen readers.
const link = (url, text, t) => (http(url) ? `<a href="${esc(url)}"${NEW_TAB}>${esc(text)}<span class="sr-only">${esc(t.newTab)}</span></a>` : '');
// A link the opened row draws without its own new-tab note (app.mjs anchor(url, text, false)): its list says it once.
const quiet = (url, text, before = '') => (http(url) ? `<a href="${esc(url)}"${NEW_TAB}>${before ? `<span class="sr-only">${esc(before)}</span>` : ''}${esc(text)}</a>` : '');
const secHead = (text) => `<h2 class="sec-head">${esc(text)}</h2>`;
const fold = (summary, body, cls = 'models') => `<details class="${cls}"><summary>${summary}</summary>${body}</details>`;

// The CVE line (app.mjs idLine): one or two IDs, else the first and how many more.
const idLine = (cves, t) => (cves.length > 2 ? `${esc(cveHead(cves).id)}${esc(t.moreIds(cveHead(cves).more))}` : cves.map(esc).join(', '));

// Every CVE ID, each linked to its record (app.mjs: "CVE 3건" opens to every ID), when there are more than two.
const cveFold = (i, t) => (i.cves.length > 2
  ? fold(`${esc(t.cveCount(i.cves.length))}<span class="sr-only">${esc(t.newTabAll)}</span>`, ul(i.cves.map((c) => quiet(cveUrl(c), c))), 'models cve-fold') : '');

// Each CVE's own line (app.mjs cveList): its ID, what it does, its score and attack marks and its own links; three in
// view, the rest folded. Every link stays in the HTML for search engines; <details> needs no script.
function cveLineList(i, lang, t) {
  const lines = cveLines(i, lang);
  if (!lines.length) return '';
  const item = (line) => {
    const marks = [];
    if (i.cve_scores) {
      const score = cveScore(i, line.cve);
      marks.push(`<span class="cve-src">${esc(score == null ? t.unratedWhy : `CVSS ${score.toFixed(1)}`)}</span>`);
    }
    const hit = cveExploit(i, line.cve);
    if (hit) marks.push(`<span class="cve-src"><span class="kev">${esc(t.kevReason)}</span> ${quiet(hit.url, hit.kind === 'kev' ? t.kevSource : host(hit.url), `${line.cve} ${t.kevReason}: `)}</span>`);
    const own = (i.cve_links?.[line.cve] || []).filter((l) => http(l.url));
    const seen = {};
    const many = (kind) => own.filter((l) => l.kind === kind).length > 1; // two advisories read 공지 1 · 공지 2
    const links = own.map((l) => {
      seen[l.kind] = (seen[l.kind] || 0) + 1;
      const name = t.linkKind[l.kind] || host(l.url);
      return quiet(l.url, many(l.kind) ? `${name} ${seen[l.kind]}` : name, `${line.cve} `);
    });
    return `<strong>${quiet(cveUrl(line.cve), line.cve)}</strong>${esc(line.text)}${marks.length ? ` ${marks.join(' · ')}` : ''}`
      + `${links.length ? ` <span class="cve-src">${links.join(' · ')}</span>` : ''}`;
  };
  return `<h2 class="cve-lines-head">${esc(t.cveLinesHead(lines.length))}<span class="sr-only">${esc(t.newTabAll)}</span></h2>`
    + ul(lines.slice(0, 3).map(item), 'cve-lines')
    + (lines.length > 3 ? fold(esc(t.moreLines(lines.length - 3)), ul(lines.slice(3).map(item), 'cve-lines')) : '');
}
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
// One script, LOCAL_TIME, by its hash; the Board's web/board.css and the page's own inline styles and line colours.
// The product and list pages' too.
export const PAGE_CSP = `default-src 'none'; script-src 'sha256-${LOCAL_TIME_SHA256}' https://static.cloudflareinsights.com; connect-src https://cloudflareinsights.com; style-src 'self' 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;

// The row's risk sign (app.mjs riskCell): the level word, with why it is that high or that its score is pending.
function riskSign(i, t) {
  const level = riskLevel(i);
  const pending = !isExploited(i) && !cvssRating(i.cvss); // dashed like the empty ring, 점수 대기 under it (critique 13)
  const under = isExploited(i) ? ` <small class="why kev">${esc(t.kevReason)}</small>` : pending ? ` <small class="why unrated">${esc(pendingWhy(i, t))}</small>` : '';
  return `<span class="c-risk risk-${level} loud${pending ? ' unrated' : ''}"><b class="word">${esc(t.levels[level])}</b>${under}</span>`;
}

// The CVSS ring (app.mjs scoreCell): its arc to the score out of 10, coloured by rating, never filled (owner, 11-19); a
// dashed dash while unscored. In a group the score names its CVE in the label (step 4).
function ring(i, t) {
  const rating = cvssRating(i.cvss);
  if (!rating) return `<span class="c-score"><span class="gauge unrated" role="img" aria-label="${esc(t.unrated)}" title="${esc(t.unrated)}">—</span></span>`;
  const top = scoreCve(i);
  const named = `CVSS ${i.cvss.toFixed(1)}${top ? ` · ${t.scoreOf(top)}` : ''}`;
  return `<span class="c-score"><span class="gauge sev-${rating}" role="img" aria-label="${esc(named)}" title="${esc(named)}" style="--fill:${(Math.min(i.cvss, 10) / 10).toFixed(3)}">`
    + '<svg viewBox="0 0 40 40" aria-hidden="true"><circle class="track" cx="20" cy="20" r="17" pathLength="1"/><circle class="arc" cx="20" cy="20" r="17" pathLength="1"/></svg>'
    + `<b class="num">${i.cvss.toFixed(1)}</b></span></span>`;
}

// The opened row's facts (app.mjs details()): the CVE line, the score with the CVE it belongs to, the Public date, why
// it is attacked, a vendor's own rating; and, the page's own, when Patch Ticker first saw it (the Board's date tooltip).
// M4: the Public date is a day as the CVE record gives it (UTC), so it is text, not a <time> the script rewrites.
function facts(i, lang, t) {
  const rows = [];
  // One or two IDs: each linked to its record here, since no CVE fold does it (the Board's row is a button, its IDs text;
  // 30 of 22,911 pages on 11-27 had no other link to their CVE record).
  if (i.cves.length) rows.push([t.cveHead, i.cves.length > 2 ? idLine(i.cves, t) : i.cves.map((c) => link(cveUrl(c), c, t)).join(', ')]);
  const top = scoreCve(i);
  const pair = scorePair(i); // a score a page raised: both standards' scores, higher first (owner 11-18)
  if (pair || Number.isFinite(i.cvss)) rows.push([t.scoreHead, [pair || `CVSS ${i.cvss.toFixed(1)}`, top].filter(Boolean).map(esc).join(' · ')]);
  if (publicDay(i)) rows.push([t.publicDate, esc(publicDay(i))]);
  const reason = exploitReason(i);
  if (reason) {
    const hit = i.cves.length > 1 ? exploitedCves(i) : []; // which CVEs of a group are attacked; older data names none
    let why = reason.kind === 'kev' ? `${esc(t.kevListed)}${reason.date ? ` · <span class="nw">${esc(reason.date)}</span>` : ''}` : link(reason.url, host(reason.url), t);
    if (hit.length) why += ` · ${hit.map((c) => `<span class="nw">${esc(c)}</span>`).join(', ')}`;
    rows.push([reason.kind === 'kev' ? t.kevReason : t.attackSource.replace(/[:：]\s*$/, ''), why]);
  }
  const src = provisionalLevel(i) ? i.summary.severity_source : ''; // owner, 11-19: with the advisory's link
  if (src) rows.push([t.vendorRating, `${esc(severityWord(i))} · ${link(src, host(src), t)}`]);
  rows.push([t.firstSeen, when(i.first_seen, lang)]);
  return `<dl class="facts">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
}

// The opened row's 제품 line (app.mjs tagLine), each tag a link to the Board with that one filter (owner, 11-10) where
// the Board has a button; past five, the first four in view and the rest folded (foldTags). A release group's 함께 공개 leads.
function tagLine(i, lang, t) {
  const tags = tagFilters(i, lang);
  if (!tags.length) return '';
  const badge = (tag) => {
    if (tag.kind === 'os') return `<span class="ln os" title="${esc(tag.name)}"><span class="ln-t">${esc(tag.name)}</span></span>`;
    const { bg, ink } = nameLine(tag.name); // the Board's fixed colour table, by the shown name
    return `<span class="ln" title="${esc(tag.name)}" style="--line:${bg};--line-ink:${ink}"><span class="ln-t">${esc(tag.name)}</span></span>`;
  };
  const item = (tag) => `<a class="tag-btn" href="/${esc(tagHash(tag))}" aria-label="${esc(t.tagLink(tag.name))}">${badge(tag)}</a>`;
  const { shown, more } = foldTags(tags);
  const rest = more ? ` ${fold(esc(t.tagsRest(more)), tags.slice(shown.length).map(item).join(' '))}` : '';
  const group = i.cves.length > 2 ? `<span class="grp grp-patch">${esc(t.patchTag)}</span> ` : '';
  return `<div class="p-prod"><span class="p-label">${esc(t.tagsHead)}</span><div class="tag-line">${group}${shown.map(item).join(' ')}${rest}</div></div>`;
}

// Owner, 11-17: under the tags, each product's page (/p/<slug>, edge/product.mjs), operating systems aside.
// pages: [{ name, slug }] worked out by pageResponse (the slug is a hash, so async).
const productPages = (pages, t) => (pages.length
  ? `<p class="others">${esc(t.productPages)}: ${pages.map((x) => `<a href="${t.productPath}${x.slug}">${esc(x.name)}</a>`).join(' · ')}</p>` : '');
const PRODUCT_LINKS = 5;
export const productPageList = async (i, lang) => Promise.all(productsOf(i, lang).filter((x) => !x.id.startsWith('os:')).slice(0, PRODUCT_LINKS)
  .map(async (x) => ({ name: x.name, slug: await checkSlug(x.id) })));

// Gemini review, 11-28 (P1, P2): what the page links besides its products, read from the collector's documents.
// pages: productPageList's answer. A product page that moved (its id merged, collector/checks.py moved_docs) is linked
// at its new address, not through a 301; one that names another canonical (same_lists) keeps its own, which names the
// visitor's model. related: up to RELATED other Incidents of the first product that have a page, newest first (the
// check document's order). day: the day list (/d/<day>, the day of first sight in Korea, as collector/cycle.py
// list_docs) when the Incident is on it. Anything unreadable is left out, never an error.
const RELATED = 5;
const PRODUCT_SLUG = /^[0-9a-f]{16}$/; // check_slug in collector/checks.py
const LIST_DAY_MS = 9 * 3600e3; // collector/cycle.py LIST_DAY_HOURS
export async function pageLinks(bucket, i, pages) {
  const read = (key) => readJson(bucket, key).catch(() => null);
  const docs = await Promise.all(pages.map((x) => read(`check/p/${x.slug}.json`)));
  const linked = pages.map((x, k) => (typeof docs[k]?.moved === 'string' && PRODUCT_SLUG.test(docs[k].moved) ? { ...x, slug: docs[k].moved } : x));
  let first = docs[0];
  if (linked.length && linked[0].slug !== pages[0].slug) first = await read(`check/p/${linked[0].slug}.json`);
  const own = `${SITE}/i/`;
  const related = linked.length && Array.isArray(first?.incidents) ? first.incidents.filter((e) => e && e.id !== i.id
    && typeof e.url === 'string' && e.url.startsWith(own) && SLUG.test(e.url.slice(own.length))).slice(0, RELATED) : [];
  const day = Number.isFinite(Date.parse(i.first_seen)) ? new Date(Date.parse(i.first_seen) + LIST_DAY_MS).toISOString().slice(0, 10) : null;
  const list = day ? await read(`lists/d/${day}.json`) : null;
  const listed = Array.isArray(list?.incidents) && list.incidents.some((e) => e?.id === i.id);
  return { pages: linked, related: related.length ? { name: linked[0].name, items: related } : null, day: listed ? day : null };
}
const relatedBlock = (related, lang, t) => (related ? `<p class="others">${esc(t.related(related.name))}</p><ul class="mentions related">`
  + related.items.map((e) => `<li><a href="${t.path}${esc(e.url.slice(`${SITE}/i/`.length))}">${esc(String((lang === 'ko' ? e.title_ko : e.title_en) || e.id))}</a></li>`).join('')
  + '</ul>' : '');
const dayLine = (day, t) => (day ? `<p class="others"><a href="${t.dayPath}${day}">${esc(t.dayLink(day))}</a></p>` : '');

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
  const lines = table.lines.map((l) => `<strong>${quiet(l.url, l.label) || esc(l.label)}</strong>${l.package ? `${esc(l.package)} · ` : ''}`
    + `${esc(l.state)}${l.ids.length ? ` ${idMark(l.ids)}` : ''}`);
  const credits = table.credits.map((c) => (quiet(c.url, c.name) || esc(c.name)) + (c.licence ? ` (${quiet(c.licenceUrl, c.licence) || esc(c.licence)})` : ''));
  return fold(`${esc(table.title)}<span class="sr-only">${esc(t.newTabAll)}</span>`,
    `<div>${ul(lines, 'cve-lines')}${credits.length ? `<p class="credits">${esc(t.distroSources)} ${credits.join(' · ')}</p>` : ''}</div>`);
}

// The Lead mention (app.mjs leadLine): always the rule-based one, named by what it is, then where.
function leadLine(i, t) {
  const lead = i.brief?.lead;
  if (!http(lead)) return '';
  const kind = i.mentions.find((m) => m.url === lead)?.kind;
  return `<p class="lead">${link(lead, `${t.lead[kind] || t.lead.other} · ${host(lead)}`, t)}</p>`;
}

// Every Mention by kind (app.mjs details()), in the Lead order; a kind with more links than MENTIONS_SHOWN folds into one
// line (mentionGroups). A group's cve.org records are linked from its CVE fold, and an advisory or write-up a CVE line links
// is left out (step 4); a record elsewhere (NVD) stays, which the Board's panel drops. On the Korean page an English title shows the Summary's Korean line, the original in its title.
function mentions(i, lang, t) {
  const glosses = Array.isArray(i.summary?.titles_ko) ? i.summary.titles_ko : [];
  const linkOf = (m, fallback) => {
    const gloss = lang === 'ko' && m.title && glosses.find((g) => g?.url === m.url && typeof g.title === 'string')?.title;
    const a = link(m.url, gloss || m.title || fallback, t);
    return gloss ? a.replace('<a ', `<a title="${esc(m.title)}" `) : a;
  };
  const lastPart = (url) => {
    try {
      const u = new URL(url);
      return u.searchParams.get('id') || decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || ''); // cve.org: ?id=CVE-…
    } catch {
      return '';
    }
  };
  const onLines = new Set(cveLines(i, lang).flatMap((l) => (i.cve_links?.[l.cve] || []).map((x) => x.url)));
  const folded = new Set(i.cves.length > 2 ? i.cves.map(cveUrl) : []);
  const listed = i.mentions.filter((m) => http(m.url) && !folded.has(m.url) && !(['advisory', 'writeup'].includes(m.kind) && onLines.has(m.url)));
  const items = mentionGroups(listed).flatMap(({ kind, list, sites, fold: folded }) => {
    const label = t.mentionKinds[kind] ?? kind;
    if (!folded) return list.map((m) => `${esc(label)}: ${linkOf(m, host(m.url))}`);
    const inner = list.map((m) => linkOf(m, (list.filter((x) => host(x.url) === host(m.url)).length > 1 && lastPart(m.url)) || host(m.url)));
    return [fold(esc(t.mentionsMany(label, sites, list.length)), ul(inner))];
  });
  return items.length ? ul(items, 'mentions') : '';
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
// Each search language's address of one document, for hreflang (SEARCH_LANGS: no Japanese): Korean is also the x-default.
export const alternates = (url) => [...SEARCH_LANGS.map((l) => `<link rel="alternate" hreflang="${l}" href="${url(l)}">`),
  `<link rel="alternate" hreflang="x-default" href="${url('ko')}">`];
// A page's search lines: canonical and hreflang, or for a noindex page the noindex alone, with a canonical only to
// itself (Gemini review, 11-27: a noindex /ja/ page named its /en/ twin canonical, and Google's guide on duplicate URLs
// says not to mix noindex with a canonical elsewhere; a page out of the index is in no hreflang set). url(lang): the
// document's address in that language.
export function searchHead(noindex, lang, url) {
  const canonical = `<link rel="canonical" href="${url(searchLang(lang))}">`;
  if (!noindex) return [canonical, ...alternates(url)];
  return ['<meta name="robots" content="noindex">', ...(searchLang(lang) === lang ? [canonical] : [])];
}

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
<link rel="stylesheet" href="/board.css">
<style>${CSS}</style>
</head>
<body class="page">
<header class="top"><div class="wrap"><a class="home" href="/">${LOGO}<span>Patch Ticker</span></a>${other}</div></header>
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

// A description for a search result: at most DESCRIPTION_MAX characters, cut at a word's end with an ellipsis (search
// engines cut near there anyway, in the middle of a word; English first sentences ran to 326 characters).
const DESCRIPTION_MAX = 160;
const CHANGED = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/; // collector/cycle.py write_pages: the stamp of the page's last change
export function clip(text, max = DESCRIPTION_MAX) {
  const chars = [...String(text)]; // by code point: never half an emoji or a surrogate pair
  if (chars.length <= max) return chars.join('');
  const cut = chars.slice(0, max - 1).join('');
  const space = cut.lastIndexOf(' ');
  return `${(space > max / 2 ? cut.slice(0, space) : cut).replace(/[\s,;:·(\[-]+$/, '')}…`;
}

// others: board/others.json (M1), or null. pages: productPageList's answer (the products' pages), or none.
export function pageHtml(i, lang, slug, others = null, pages = [], links = {}) {
  const t = TEXT[lang];
  const s = i.summary?.[lang] || {};
  const level = riskLevel(i);
  const title = titleOf(i, lang);
  const plain = s.easy ? easyLine(s.easy, level) : '';
  // Owner, 2026-11-27: the Easy line and the Summary's first sentence, in that order. The Easy line alone was 28 to 46
  // characters on Korean pages and often names no product (Bing: "meta descriptions too short"); the Summary's first
  // sentence names the product and the version. Both are text the page already shows.
  const description = clip([plain, String(s.summary || '').split(/(?<=[.!?])\s/)[0]].filter(Boolean).join(' ') || i.brief?.text || title);
  // The page's own address for the report link; its canonical one (a /ja/ page's /en/ twin) for og:url and the JSON-LD,
  // which had named the /ja/ address and Japanese as the language of an English text (Gemini review, 11-27).
  const self = pageUrl(lang, slug);
  const canon = pageUrl(searchLang(lang), slug);
  const head = [`<title>${esc(title)} · Patch Ticker</title>`,
    `<meta name="description" content="${esc(description)}">`,
    ...searchHead(!searchWorthy(i), lang, (l) => pageUrl(l, slug)),
    '<meta property="og:type" content="article">',
    '<meta property="og:site_name" content="Patch Ticker">',
    `<meta property="og:url" content="${canon}">`,
    `<meta property="og:title" content="${esc(title)}">`,
    `<meta property="og:description" content="${esc(description)}">`,
    `<meta property="og:image" content="${SITE}/og.png">`,
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
    `<meta property="og:locale" content="${t.locale}">`,
    ...LANGS.filter((l) => l !== lang).map((l) => `<meta property="og:locale:alternate" content="${TEXT[l].locale}">`),
    '<meta name="twitter:card" content="summary_large_image">',
    jsonLd({ '@context': 'https://schema.org', '@type': 'Article', headline: title, description,
      datePublished: i.published || i.first_seen, dateCreated: i.first_seen, inLanguage: searchLang(lang), url: canon, mainEntityOfPage: canon,
      // Google's Article guide recommends image and author (with a url); dateModified when the collector last changed the page.
      ...(CHANGED.test(i.changed || '') ? { dateModified: i.changed } : {}), image: `${SITE}/og.png`,
      author: { '@type': 'Organization', name: 'Patch Ticker', url: `${SITE}/` },
      isAccessibleForFree: true, publisher: { '@type': 'Organization', name: 'Patch Ticker', url: `${SITE}/` } })].join('\n');
  // Owner, 11-27 ("디자인 왜 따로쓰냐"): the Board's row and its opened panel (web/app.mjs row(), details()) in the
  // Normal view, in that order: what to do first, then what it is and when it applies, the links last.
  const conditions = strings(s.conditions);
  const poc = i.summary?.poc_public === true && !isExploited(i); // a red line after the summary, as the Board's
  const main = ['<article>',
    `<div class="p-head risk-${level}">${riskSign(i, t)}<div class="c-title"><h1 class="title">${esc(title)}</h1>`
      + `${i.cves.length ? `<p class="sub"><span class="cve">${idLine(i.cves, t)}</span></p>` : ''}</div>`
      // the publish time only: a first sighting is never passed off as one (app.mjs dateCell); the facts say 처음 확인
      + `${i.published ? `<span class="c-date">${when(i.published, lang)}</span>` : ''}</div>`,
    p(plain, 'easy'),
    '<div class="details">',
    `<div class="p-top">${facts(i, lang, t)}<div class="p-side">${ring(i, t)}${tagLine(i, lang, t)}</div></div>`,
    // Everything the page said to do before, the command and the stopgap too, which the Board's Normal panel leaves to its
    // Easy view: a page is read on its own, often from a search, with no second view to switch to.
    secHead(t.mitigationHead) + whatToDo(i, lang, 'mitigation'),
    s.summary ? secHead(t.aboutHead) + p(s.summary, 'summary') : '',
    poc ? `<p class="kev">${esc(t.poc)}</p>` : '',
    conditions.length ? secHead(t.conditions) + (conditions.length === 1 ? `<p class="conditions">${condition(conditions[0], i.cves)}</p>`
      : `<ul class="cond-list">${conditions.map((c) => `<li>${condition(c, i.cves)}</li>`).join('')}</ul>`) : '',
    othersLink(i, lang, t, others),
    productPages(pages, t),
    relatedBlock(links.related, lang, t),
    dayLine(links.day, t),
    distroFold(i, lang, t),
    cveFold(i, t),
    leadLine(i, t),
    cveLineList(i, lang, t),
    mentions(i, lang, t),
    `<p class="share"><a class="btn" href="/#i=${esc(encodeURIComponent(i.id))}">${esc(t.board)}</a>`
      + `<a class="btn" href="${esc(reportUrl(i, lang, self, slug))}"${NEW_TAB}>${REPORT_ICON}<span>${esc(t.report)}</span></a></p>`,
    '</div>',
    `<script>${LOCAL_TIME}</script>`,
    '</article>'].filter(Boolean).join('\n');
  return document(lang, head, main, langMenu(lang, (l) => `${TEXT[l].path}${slug}`));
}

// Edge cache times: a page, a move and an expired page change at most once a cycle; a missing page may appear sooner.
const CACHE = 'public, max-age=300';
const CACHE_404 = 'public, max-age=60';

const GONE_PAGE = '<path d="M6 2.75h8l4.25 4.25V21.25H6Z M13.75 2.75V7.25h4.5M9.5 12.5l5 5m0-5-5 5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/>';
const GONE_DOWN = '<path d="M12 3.5 21.5 20h-19Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9.5v4.5M12 16.75v.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>';
// A short note in place of a page (404, 410, 503): never indexed, always a way on. A 503 is never cached.
export function note(lang, status, text, links) {
  const head = `<title>Patch Ticker</title>\n<meta name="robots" content="noindex">`;
  // the first sentence is the title, the rest its description; a dot inside a word (Node.js, 1.2) ends no sentence
  const [, title, desc] = /^(.+?(?:\.(?=\s)|。))\s*(.*)$/s.exec(text) || [, text, ''];
  const body = `<div class="gone"><svg class="gone-icon" viewBox="0 0 24 24" aria-hidden="true">${status === 503 ? GONE_DOWN : GONE_PAGE}</svg>`
    + `<h1>${esc(title)}</h1>${desc ? `<p>${esc(desc)}</p>` : ''}<nav class="links">${links.join('')}</nav></div>`;
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
    const doc = await readJson(bucket, `pages/${slug}.json`, lang);
    if (!doc) return note(lang, 404, t.missing, [home]);
    if (doc.moved_to) {
      // An absorbed Incident (ticket 04): its address moves to the survivor's page while both are within PAGE_DAYS,
      // and to the survivor's row on the Board while the survivor has no page yet (owner, 11-10).
      if (!withinPageDays(doc.moved, now)) return expired(null);
      if (typeof doc.moved_to_id !== 'string' || !doc.moved_to_id) throw new Error(`pages/${slug}.json: no survivor`);
      const target = SLUG.test(doc.moved_to) ? await readJson(bucket, `pages/${doc.moved_to}.json`, lang) : null;
      if (target?.first_seen && !withinPageDays(target.first_seen, now)) return expired(target);
      if (!target?.summary || target.moved_to || !onBoard(target)) return redirect(302, `${SITE}/#i=${encodeURIComponent(doc.moved_to_id)}`);
      return redirect(301, pageUrl(lang, doc.moved_to));
    }
    if (!withinPageDays(doc.first_seen, now)) return expired(doc);
    if (!doc.summary || !onBoard(doc)) return note(lang, 404, t.missing, [home]);
    // M1: the Products' counts, one read beside the page document; missing or unreadable, only the link is left out.
    const others = await readJson(bucket, 'board/others.json', lang).catch(() => null);
    const links = await pageLinks(bucket, doc, await productPageList(doc, lang));
    return new Response(pageHtml(doc, lang, slug, others, links.pages, links), {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': CACHE, 'content-security-policy': PAGE_CSP },
    });
  }, () => note(lang, 503, t.down, [`<a href="${SITE}/">${esc(t.home)}</a>`]));
}
