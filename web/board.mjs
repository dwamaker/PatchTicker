// The Board's filter: pure, so it runs the same in the browser and under `node --test`.
// first_seen is ISO-8601 UTC ("...Z"), so string order is time order.
// The filter in the page address: ?p=<product id>&p=...&q=<search>. Also the localStorage form.
// The whole filter lives in the address hash: p product/OS picks, q search, and the panel's r risk, k exploited,
// f/t published from/to (YYYY-MM-DD), c minimum CVSS, cv CVE yes/no, h link kinds, s sort.
import vendors from './vendors.json' with { type: 'json' };

// Vendor keys come from CVE records: without a prototype, "constructor" or "__proto__" finds no vendor (audit 2).
const VENDORS = Object.assign(Object.create(null), vendors);

const DAY = /^\d{4}-\d{2}-\d{2}$/;
export function filterFromQuery(search) {
  const params = new URLSearchParams(search);
  const day = (key) => (DAY.test(params.get(key) || '') ? params.get(key) : '');
  return {
    picks: [...new Set(params.getAll('p').map(ownId))], query: params.get('q') || '',
    risk: params.getAll('r').filter((r) => RISKS.includes(r)), kev: params.get('k') === '1',
    from: day('f'), to: day('t'), cvssMin: [4, 7, 9].includes(Number(params.get('c'))) ? Number(params.get('c')) : 0,
    cve: ['yes', 'no'].includes(params.get('cv')) ? params.get('cv') : '',
    has: params.getAll('h').filter((h) => LINK_KINDS.includes(h)), sort: SORTS.includes(params.get('s')) ? params.get('s') : 'new',
  };
}

export function filterToQuery({ picks, query, risk = [], kev = false, from = '', to = '', cvssMin = 0, cve = '', has = [], sort = 'new' }) {
  const params = new URLSearchParams([...picks.map((p) => ['p', p]), ...risk.map((r) => ['r', r]), ...has.map((h) => ['h', h])]);
  if (kev) params.set('k', '1');
  if (from) params.set('f', from);
  if (to) params.set('t', to);
  if (cvssMin) params.set('c', String(cvssMin));
  if (cve) params.set('cv', cve);
  if (sort !== 'new') params.set('s', sort);
  if (query) params.set('q', query);
  return params.toString();
}

export const SORTS = ['new', 'risk', 'cvss'];
export const LINK_KINDS = ['advisory', 'repo'];

export const RISKS = ['highest', 'high', 'notice'];
export const OSES = ['Windows', 'macOS', 'Linux', 'Android', 'iOS'];

const DAY_MS = 24 * 60 * 60 * 1000;

// The picker offers only Products seen in the last 90 days, so it is not cluttered with names that have no Incidents.
// An Incident's Products for the picker, search and the pick filter: NVD's and the CVE record's (vendor:product
// ids), the Summary's product names, and its operating systems ("os:windows"). A Summary name that contains a
// known Product's name is that Product, shown with the Summary's vendor-led name ("SonicOS" -> "SonicWall SonicOS").
// lang shows each Summary product by the name readers of that language know ("Windows 그림판"), as the badges do;
// ids stay language-free so a shared filter works in either language.
// The name a Product shows in this language. A Korean name stays ("Windows 그림판"); a Latin one that differs from the
// Summary's product name is the model shortening it ("Apache Axis2" for "Apache Axis2/Java"), so the product name wins.
const HANGUL = /[\uac00-\ud7a3]/;
function shownName(s, lang, k) {
  const local = s?.[lang]?.names?.[k];
  const product = s?.products?.[k];
  return local && product && !HANGUL.test(local) && local !== product ? product : local || product;
}

// A Summary-named Product's identity (critique 14: "GemBooking" and "GemBooking WordPress plugin" were two Products and
// picking one hid the other): letter case, brackets, company words ("Technology", "Co., Ltd."), a generic suffix
// ("WordPress plugin", "플러그인", "theme") and a known vendor in front ("IBM SevOne …" is "SevOne …") drop out. Names are
// never translated (the Summary prompt), so there is no language step. Also collector/incidents.py (product_key).
const SUFFIX = /\s+(?:(?:for\s+)?wordpress\s+)?(?:plugin|theme|플러그인|테마)(?:\s+for\s+wordpress)?$/u;
const COMPANY = /(^|\s)(?:technology|technologies|inc|corp|corporation|co|ltd|limited|gmbh|llc)\.?(?=\s|$)/gu;
const LED_BY = Object.values(VENDORS).map((v) => `${v.toLowerCase()} `);
export function productKey(name) {
  const plain = name.toLowerCase().replace(/[(),]/g, ' ').replace(COMPANY, '$1').replace(/\s+/g, ' ').trim();
  const key = plain.replace(SUFFIX, '').trim() || plain;
  const vendor = LED_BY.find((v) => key.startsWith(v) && key.length > v.length);
  return vendor ? key.slice(vendor.length) : key;
}
const nameId = (name) => `name:${productKey(name)}`;
// An id stored before critique 14 ("name:gembooking wordpress plugin" in products.json, a saved or shared pick) as the
// Product's id now.
const ownId = (id) => (id.startsWith('name:') ? nameId(id.slice(5)) : id);

export function productsOf(i, lang = 'en') {
  const found = new Map((i.products || []).map((p) => [p.id, p]));
  (i.summary?.products || []).forEach((name, k) => {
    const shown = shownName(i.summary, lang, k);
    const same = [...found.values()].find((p) => name.toLowerCase().includes(p.name.toLowerCase()));
    if (same) found.set(same.id, { ...same, name: shown });
    else found.set(nameId(name), { id: nameId(name), name: shown });
  });
  for (const os of i.summary?.platforms || []) {
    found.delete(`name:${os.toLowerCase()}`); // "Android" as a product and as a platform is one entry
    found.set(`os:${os.toLowerCase()}`, { id: `os:${os.toLowerCase()}`, name: os });
  }
  return [...found.values()];
}

// seen: the collector's board/products.json entries ({id, ko, en}, same 90 days), so a Product with no Incident in
// the loaded week can still be picked and show the all-clear sign; loaded Incidents name the ones they share.
// What a visitor typed in the Product picker, matched like a person would: case does not matter, a whole label or
// name wins, otherwise every Product whose label contains the text. label: the picker's own label (app.mjs).
export function matchProducts(products, text, label = (p) => p.name) {
  const want = text.trim().toLocaleLowerCase();
  if (!want) return [];
  const low = (p) => [label(p).toLocaleLowerCase(), p.name.toLocaleLowerCase()];
  const whole = products.filter((p) => low(p).includes(want));
  return whole.length ? whole : products.filter((p) => low(p).some((n) => n.includes(want)));
}

// A refresh while the page is open: the fresh week replaces what it holds (a Summary or exploited flag may have
// arrived), Incidents the page already had beyond it (older months) stay, and only ids it lacked are new.
// A row view (rows.json, marked rows) replaces a held full Incident only when what its row shows changed (owner, 11-10): a
// new KEV listing, score, Summary, quick title or HN points must show, but an unchanged one keeps the full object, whose
// details are still right.
const rowShows = (i) => JSON.stringify([i.summary?.at, i.kev, i.kev_date, i.cvss, i.published, i.mentions?.length,
  Math.max(0, ...(i.mentions || []).map((m) => m.points || 0)), i.summary_error?.final, (i.products || []).map((p) => p.id),
  i.quick_title?.ko?.title, i.quick_title?.en?.title, i.known, i.known_rank]);
// week: fresh is the full week (board/recent.json), the truth for row views; one it does not hold left the week or was
// merged into another Incident, and nothing could ever fill it, so it goes. Full Incidents beyond it (older months) stay.
export function mergeIncidents(current, fresh, week = false) {
  const byId = new Map(current.map((i) => [i.id, i]));
  const added = fresh.filter((i) => !byId.has(i.id)).map((i) => i.id);
  for (const i of fresh) {
    const held = byId.get(i.id);
    if (!i.rows || !held || held.rows || rowShows(i) !== rowShows(held)) byId.set(i.id, i);
  }
  if (week) for (const [id, i] of byId) if (i.rows) byId.delete(id); // the week's own are full by now
  return { incidents: [...byId.values()], added };
}

export function productList(incidents, now, lang = 'en', seen = []) {
  const since = new Date(now - 90 * DAY_MS).toISOString();
  const found = new Map(seen.map((p) => [ownId(p.id), { id: ownId(p.id), name: p[lang] || p.en }]));
  for (const i of incidents) if (i.first_seen >= since) for (const p of productsOf(i, lang)) found.set(p.id, p);
  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

// Highlight score. Exploited in the wild (CISA KEV) outranks everything; then discussion (HN points,
// up to 50 at 500 points; a curator's newsletter, 25 each for up to two); CVSS (up to 20) and the
// number of Mentions (up to MENTION_CAP) order the rest; among equal scores the newer comes first. An exploited
// Incident with no CVSS score counts as HIGHEST_CVSS, the floor of the band riskLevel gives it (owner, 11-10: CVE-less
// campaigns sank under every exploited CVE); one with a score keeps it. Also in
// collector/incidents.py (highlight_score, with HIGHLIGHTS in collector/cycle.py: board/rows.json keeps the week's
// Highlights whole), kept in step by tests/fixtures/board/rows-case.json.
// Highlights: every exploited candidate of the week is chosen, at least HIGHLIGHTS and at most HIGHLIGHTS_MAX in all
// (owner, 11-10: the week's eleventh exploited Incident was cut off); four are pinned at first so the newest list starts
// on the first screens of a phone (ten frames ran past 1,900px); 주요 사건 더 보기 pins the rest. Unpinned ones stay in 최신순.
export const HIGHLIGHTS = 10;
export const HIGHLIGHTS_MAX = 20;
export const PINNED = 4;
// Well known (owner, 11-11: a CVSS 9.6 Zoom flaw ranked 265th, as nothing in the score says a product is widely used):
// the collector stamps `known`, the product's label from collector/well_known.json or, for a product on no list that the
// Summary calls widely used, its name. Such a row at 최고 that is not exploited (those lead anyway) is lifted.
export const wellKnown = (i) => Boolean(i.known) && riskLevel(i) === 'highest' && !isExploited(i);
// The Highlights of the score-sorted candidates: every exploited one, then the best-scored well-known one of each product
// (the others stay ordinary rows), then the rest by score. The well-known ones go in the order of their labels in
// collector/well_known.json (known_rank; owner, 11-11: at the cap, a talked-about SAP NetWeaver row cut Zoom), and a
// label on no list after them all, by score. Also collector/cycle.py (highlights), kept in step by
// tests/fixtures/board/highlights-case.json.
const knownRank = (i) => i.known_rank ?? Number.MAX_SAFE_INTEGER;
export function pickHighlights(candidates) {
  const labels = new Set();
  const lead = [...candidates.filter(isExploited),
    ...candidates.filter((i) => wellKnown(i) && !labels.has(i.known) && labels.add(i.known))
      .sort((a, b) => knownRank(a) - knownRank(b))]; // a stable sort: equal ranks stay by score
  const rest = candidates.filter((i) => !lead.includes(i));
  return [...lead, ...rest].slice(0, Math.min(HIGHLIGHTS_MAX, Math.max(HIGHLIGHTS, lead.length)));
}
// Owner, 11-10: a release counts a record, an advisory and a write-up per CVE, so uncapped FFmpeg (331 Mentions), Chrome,
// IBM API Connect and FreeRDP took all four pins over 15 exploited Incidents. Also in collector/incidents.py.
const MENTION_CAP = 10;

// Why a row is pinned, when the row does not already show it: exploited and CVSS 9+ are on the row itself.
export function pinReason(i) {
  if (isExploited(i) || i.cvss >= HIGHEST_CVSS) return null;
  if (i.mentions.some((m) => m.kind === 'curator')) return 'curator';
  if (Math.max(0, ...i.mentions.map((m) => m.points || 0)) >= HN_BUZZ) return 'buzz';
  return null;
}

export function highlightScore(i) {
  const points = Math.max(0, ...i.mentions.map((m) => m.points || 0));
  const curated = i.mentions.filter((m) => m.kind === 'curator').length;
  const cvss = i.cvss ?? (isExploited(i) ? HIGHEST_CVSS : 0);
  return (isExploited(i) ? 100 : 0) + Math.min(points / 10, 50) + 25 * Math.min(curated, 2) + 2 * cvss + Math.min(i.mentions.length, MENTION_CAP);
}

// HN points from which a story is buzz (pinReason's "HN 화제"). Also in collector/hn.py (BUZZ_POINTS). A quiet HN-only
// story is never a Highlight now: with no score it is 참고, and 주요 사건 holds 위험 and above only.
const HN_BUZZ = 100;

// The Summary's text in both languages, Easy view included, so either language finds the Incident.
// Summaries written before the Easy view have no easy, command or stopgap.
const summaryText = (s) => (s ? [...['ko', 'en'].flatMap((l) => [s[l].title, s[l].summary, ...s[l].conditions, s[l].mitigation, s[l].easy || '']),
  ...s.products, s.command || '', s.stopgap || '', ...(s.devices || [])] : []);

// The note under a Brief: a Summary is coming, or the collector gave up after its last rejected try.
export const briefMarker = (i) => (i.summary_error?.final ? 'unavailable' : 'preparing');

// The saved default view; anything else (nothing saved, the old per-Incident list) is the normal view.
export const viewFromStorage = (saved) => (saved === 'easy' ? 'easy' : 'normal');

// Exploited: CISA lists it (KEV), or the Summary reports attacks its sources describe (user, 11-08: an attack campaign
// with no score or KEV listing sat in grey 참고). Both read 악용 발생 and count the same everywhere.
// Owner, 11-09 (critique 14): only with the source that reports the attacks (exploited_source); Brotli wore 악용 발생 from
// a write-up and PoC repos alone. Summaries from before then have no source and are re-made by the collector.
const sourced = (s) => s?.exploited === true && typeof s.exploited_source === 'string' && Boolean(s.exploited_source);
export const isExploited = (i) => Boolean(i.kev || sourced(i.summary));

// Why a row is 악용 발생, for the panel: the KEV listing (with its day when known), else the source reporting attacks.
export function exploitReason(i) {
  if (i.kev) return { kind: 'kev', date: i.kev_date || '' };
  return sourced(i.summary) ? { kind: 'source', url: i.summary.exploited_source } : null;
}

// The Easy view's Risk banner, set by rules: exploited (above) or the CVSS score.
// The 9.0 cutoff is also in collector/summaries.py (is_candidate) and collector/incidents.py (HIGHEST_CVSS).
const HIGHEST_CVSS = 9;
export function riskLevel(i) {
  if (isExploited(i) || i.cvss >= HIGHEST_CVSS) return 'highest';
  return i.cvss >= 7 ? 'high' : 'notice';
}

// Offered to search engines and the RSS feed (Incident page, CONTEXT.md): on the Board with a Summary, and at the 위험
// level or above, exploited, or without a CVE. Also in collector/incidents.py (search_worthy).
export const searchWorthy = (i) => Boolean(i.summary) && onBoard(i) && (riskLevel(i) !== 'notice' || !i.cves.length);

// An Incident page's address part: a CVE ID as is, an HN story as hn-<item>, any other URL ID as u-<12 hex of SHA-256>.
// It never changes, because an Incident's ID never does (a merge keeps the survivor's ID). The Board and the Pages
// Function (edge/) share this one rule; collector/incidents.py (page_slug) ports it, kept in step by
// tests/fixtures/board/slug-case.json.
const CVE_ID = /^CVE-\d{4}-\d{4,7}$/i;
const HN_ITEM = /^https:\/\/news\.ycombinator\.com\/item\?id=(\d+)$/;
export async function slug(id) {
  if (CVE_ID.test(id)) return id.toUpperCase();
  const hn = HN_ITEM.exec(id);
  if (hn) return `hn-${hn[1]}`;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(id)));
  return `u-${[...digest.slice(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

// An Incident page lives this long from first seen (also collector/cycle.py PAGE_DAYS); edge/page.mjs answers 410 after.
export const PAGE_DAYS = 90;
// Whether a time (an Incident's first seen, a move) is within PAGE_DAYS of now: the Board, the pages and the sitemaps.
export const withinPageDays = (stamp, now) => Date.parse(stamp) >= now - PAGE_DAYS * DAY_MS;

// "Copy this Incident's link": its Incident page in the visitor's language when it has one (a Summary, on the Board,
// first seen within PAGE_DAYS), else the Board's #i= link. pageSlug is slug(i.id) worked out ahead, so the click writes
// to the clipboard at once (Safari drops the click's permission across an await); undefined means not ready yet.
export function shareLink(i, pageSlug, lang, board, now = Date.now()) {
  const hasPage = pageSlug && i.summary && onBoard(i) && withinPageDays(i.first_seen, now);
  return hasPage ? new URL(`${lang === 'en' ? '/en' : ''}/i/${pageSlug}`, board).href : `${board}#i=${encodeURIComponent(i.id)}`;
}

// The Easy view's one action: update these devices, run the source's command, or update to the fixed version.
export function easyAction(s) {
  const stopgap = s.stopgap || '';
  if (s.devices?.length) return { kind: 'devices', devices: s.devices, fixed: s.fixed, stopgap };
  if (s.command) return { kind: 'command', command: s.command, stopgap };
  if (s.fixed) return { kind: 'version', fixed: s.fixed, stopgap };
  return { kind: 'none', stopgap };
}

// The Board's one order, for 주요 사건 and the rest alike (user, 11-08): newest first, or by risk level, or by CVSS score,
// each falling back to newest.
const newest = (a, b) => (publishedAt(a) < publishedAt(b) ? 1 : publishedAt(a) > publishedAt(b) ? -1 : 0);
// No score yet (and not exploited) is not "scored low" (critique 13): it sorts above the scored 참고 rows, below 위험.
const unscored = (i) => i.cvss == null;
const riskRank = (i) => { const k = RISKS.indexOf(riskLevel(i)); return k === 2 && unscored(i) ? 1.5 : k; };
const cvssKey = (i) => (unscored(i) ? 6.95 : i.cvss); // between 7.0 (위험) and 6.9: scores have one decimal
export function orderBy(sort) {
  return { __proto__: null, risk: (a, b) => riskRank(a) - riskRank(b) || newest(a, b),
    cvss: (a, b) => cvssKey(b) - cvssKey(a) || newest(a, b) }[sort] || newest;
}

// Korean words people type for systems and devices, matched as the English names sources use (critique 12: 윈도우 and
// 공유기 found nothing). Small on purpose: product names are typed as they are. The English names match only Product
// names, ids and OS tags, as whole words (critique 13: 자바 found javascript, 엣지 "knowledge").
// No prototype: the typed word is the key, and "constructor" must find no alias list (audit 13).
export const SEARCH_ALIASES = {
  __proto__: null,
  윈도우: ['Windows'], 윈도: ['Windows'], 맥: ['macOS', 'Mac OS'], 맥북: ['macOS'], 리눅스: ['Linux'], 안드로이드: ['Android'],
  아이폰: ['iOS', 'iPhone'], 아이패드: ['iPadOS', 'iPad'], 공유기: ['router'], 라우터: ['router'], 워드프레스: ['WordPress'],
  크롬: ['Chrome'], 엣지: ['Edge'], 파이어폭스: ['Firefox'], 자바: ['Java'], 파이썬: ['Python'], 오픈ssh: ['OpenSSH'],
  // critique 14: 아파치 and 깃허브 found nothing. Vendor and project names as their vendor keys and Product names write them.
  아파치: ['Apache'], 깃허브: ['GitHub'], 깃랩: ['GitLab'], 도커: ['Docker'], 쿠버네티스: ['Kubernetes'], 엔진엑스: ['nginx'],
  톰캣: ['Tomcat'], 노드: ['Node.js', 'nodejs'], 리액트: ['React'], 스프링: ['Spring'], 시스코: ['Cisco'], 포티넷: ['Fortinet'],
  마이크로소프트: ['Microsoft'], 구글: ['Google'], 애플: ['Apple'],
};
// A typed word inside a longer word that names something else is no hit (critique 14: 자바 found 자바스크립트 in Korean
// Summaries). Asked for by name, JavaScript is still found.
const NOT_INSIDE = { __proto__: null, 자바: /자바\s?스크립트/g, java: /java\s?script/g };
// Keys a Product is known by, for matching a pick against variants of its name (critique 14). A CPE-style id gives its
// vendor and product ("chengdu feiyuxing vw2100") and its product alone ("gemcode:gembooking" is the Summary's
// "GemBooking"), unless that is a word every vendor uses ("firmware").
const GENERIC = new Set(['firmware', 'router', 'server', 'app', 'application', 'camera', 'nas', 'web', 'cms', 'core']);
function productKeys(id) {
  if (id.startsWith('name:')) return [productKey(id.slice(5))];
  if (id.startsWith('os:') || !id.includes(':')) return [];
  const [vendor, product] = id.split(':').map((s) => s.replace(/_/g, ' '));
  const alone = productKey(product);
  return [productKey(`${vendor} ${product}`), ...(GENERIC.has(alone) ? [] : [alone])];
}
// Two CPE-style ids are one Product only when equal: two vendors' "Firmware" are not one.
const sameProduct = (a, b) => a === b
  || ((a.startsWith('name:') || b.startsWith('name:')) && productKeys(a).some((k) => productKeys(b).includes(k)));
// A whole word: no letter or digit on either side ("windows" in "microsoft:windows_11", not "java" in "javascript").
const hasWord = (text, word) => new RegExp(`(^|[^\\p{L}\\p{N}])${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^\\p{L}\\p{N}])`, 'iu').test(text);
// The search words that were also searched as English names, for the hint under the field ("‘맥’ … macOS").
export function aliasesUsed(query) {
  const key = (n) => n.replace(/\s/g, '').toLowerCase(); // "Mac OS" is said as macOS already
  return [...new Set(query.toLowerCase().split(/\s+/))].filter((w) => SEARCH_ALIASES[w])
    .map((word) => ({ word, names: SEARCH_ALIASES[word].filter((n, k, all) => all.findIndex((x) => key(x) === key(n)) === k) }));
}
// Search: every word of the query must appear somewhere in the Incident's text, Summary, CVE IDs or Products.
// Returns the visible Incidents newest first, and the Highlights (pickHighlights) of those published (else first seen) in
// the seven days before `now`.
// Picks: any picked Product and any picked OS, both when both kinds are picked (owner, 11-10: OpenSSH with Linux meant
// OpenSSH on Linux, not everything on Linux too).
export function filterBoard(incidents, picks = [], query = '', now = Date.now(),
  { risk = [], kev = false, from = '', to = '', cvssMin = 0, cve = '', has = [], sort = 'new' } = {}) {
  const oses = picks.filter((p) => p.startsWith('os:'));
  const products = picks.filter((p) => !p.startsWith('os:'));
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const variant = new Set(); // shown only through a variant of a picked name ("비슷한 이름 N건도 함께")
  const shown = incidents.filter((i) => {
    const own = picks.length ? productsOf(i) : [];
    if (oses.length && !own.some((p) => oses.includes(p.id))) return false;
    if (products.length && !own.some((p) => products.includes(p.id))) {
      if (!own.some((p) => products.some((q) => sameProduct(q, p.id)))) return false;
      variant.add(i);
    }
    if (risk.length && !risk.includes(riskLevel(i))) return false;
    if (kev && !isExploited(i)) return false;
    const day = publishedAt(i).slice(0, 10); // UTC date; a visitor far from UTC may see a row one day off
    if ((from && day < from) || (to && day > to)) return false;
    if (cvssMin && !(i.cvss >= cvssMin)) return false;
    if ((cve === 'yes' && !i.cves.length) || (cve === 'no' && i.cves.length)) return false;
    if (has.some((kind) => !i.mentions.some((m) => m.kind === kind))) return false;
    // Only a search builds the text (owner, 11-10: a row view of board/rows.json has none; the page fetches the full week first).
    if (!words.length) return true;
    // Mention titles carry the names people use ("sshole") that a Summary may not. A newsletter's title names only its
    // lead story, yet the newsletter is tied to many Incidents, so its title is left out.
    const names = [...productsOf(i).flatMap((p) => [p.name, p.id]), ...(i.summary?.devices || [])].join('\n');
    const titles = (i.mentions || []).filter((m) => m.kind !== 'curator').map((m) => m.title || '');
    const text = [i.brief.text, ...summaryText(i.summary), ...i.cves, names, ...titles].join('\n').toLowerCase();
    const free = (w) => (NOT_INSIDE[w] ? text.replace(NOT_INSIDE[w], ' ') : text).includes(w);
    return words.every((w) => free(w) || (SEARCH_ALIASES[w] || []).some((x) => hasWord(names, x)));
  });
  const list = shown.sort(orderBy(sort));
  const since = new Date(now - 7 * DAY_MS).toISOString(); // seven days: also in collector/summaries.py (is_candidate)
  // Newest first among equal scores, whatever the visitor's sort (owner, 11-10).
  const candidates = list.filter((i) => publishedAt(i) >= since && riskLevel(i) !== 'notice')
    .sort((a, b) => highlightScore(b) - highlightScore(a) || newest(a, b));
  const highlights = pickHighlights(candidates);
  return { highlights, list, variants: list.filter((i) => variant.has(i)).length };
}

// CVSS v3 qualitative rating, as a key the page words per language; null while NVD has not rated it.
export function cvssRating(cvss) {
  if (cvss == null) return null;
  return cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : cvss > 0 ? 'low' : 'none';
}

// An HN story with no CVE is on the Board only once its Summary calls it a real Incident (a flaw, attack or
// breach in something a reader runs); essays and anecdotes stay off. A story whose Summary failed for good
// is shown: never hide by mistake. Every other Incident is always shown.
// Security news sites: a CVE-less story from one waits for its Summary like an HN story (collector/incidents.py NEWS_HOSTS).
const NEWS_HOSTS = new Set(['bleepingcomputer.com', 'securityweek.com', 'therecord.media']);
const isNews = (url) => { try { return NEWS_HOSTS.has(new URL(url).hostname.replace(/^www\./, '')); } catch { return false; } };

export function onBoard(i) {
  if (i.cves.length || !(i.id.startsWith('https://news.ycombinator.com/') || isNews(i.id))) return true;
  if (i.summary) return i.summary.incident !== false;
  return Boolean(i.summary_error?.final);
}

// A command or stopgap a reader may paste into a terminal: it starts with a package manager or service tool.
// Anything else ("PasswordAuthentication no") is a line for a config file and must not look runnable.
const SHELL = /^(sudo\s+)?(apt|apt-get|apk|yum|dnf|zypper|pacman|opkg|brew|port|snap|flatpak|winget|choco|npm|pnpm|yarn|pip3?|pipx|gem|cargo|go|composer|docker|podman|kubectl|helm|systemctl|service|rc-service|launchctl)\s/;
// One plain invocation that installs or restarts: a source's page could chain "&& curl … | sh", quote a hook
// option, install from its own URL or run a package (audit 1). shortcut: an attacker-named package from a
// registry still passes; the collector must keep only commands from trusted sources (summaries.py parse).
const UNSAFE = /[;&|`<>\r\n$'"\\]|:\/\/|\s(run|exec|dlx|apply)\s/;
export const isShellCommand = (text) => SHELL.test(text.trim()) && !UNSAFE.test(text);

// One release's CVEs, each with what it does: the Summary's line in this language, else the CVE record's own (English)
// description. A Summary writes lines for its first CVEs only; the rest come later from batches (owner, 2026-11-10).
export function cveLines(incident, lang) {
  if (incident.cves.length < 2) return [];
  const own = new Map((incident.summary?.[lang]?.cve_lines || []).map((l) => [l.cve, l.text]));
  const texts = incident.cve_texts || {};
  return incident.cves.filter((c) => own.has(c) || texts[c]).map((cve) => ({ cve, text: own.get(cve) || texts[cve] }));
}

// The Easy sentence shouts only for the top Risk level: "!" everywhere teaches readers to ignore it.
export const easyLine = (text, level) => (level === 'highest' ? text : text.replace(/!+(\s*)$/, '.$1'));

// The Easy headline ends in its danger; at the lowest Risk level that word is 문제/issue, not 위험/risk (user, 11-08).
// The level comes from the rules, not the model, so the page decides the word and no Summary is re-made.
export const easyTitle = (text, level) => (level === 'notice' ? text.replace(/위험(\s*)$/, '문제$1').replace(/\brisk(\s*)$/i, 'issue$1') : text);

// The Easy headline names the product (critique 14: "서버 멈춤 위험" said whose server nowhere). names: the row's first
// Product as shown (put in front when missing), then its other names (the Korean or English one). One word of a name
// is enough ("Brotli" for Google Brotli, "SonicWall" for SonicWall SonicOS); words every plugin shares are not.
const SHARED_WORDS = new Set(['wordpress', 'plugin', 'theme', 'the', 'for', 'and', 'of']);
export function namedHeadline(title, names = []) {
  const low = title.toLocaleLowerCase();
  const words = names.flatMap((n) => n.toLocaleLowerCase().split(/\s+/)).filter((w) => w && !SHARED_WORDS.has(w));
  return !names.length || words.some((w) => low.includes(w)) ? title : `${names[0]}: ${title}`;
}

// A part other programs build in (Brotli, Qt, an npm or PyPI package): its version is not on any screen the reader
// sees, so the version help says to update the program or ask the host instead. The Summary says so (library, from
// critique 14); older Summaries and Briefs go by the name: library, SDK, framework, package, module, or Perl's "::".
// Device firmware is never one (IBM's "TS4500 tape library").
const PART_NAME = /\b(librar(y|ies)|lib|sdk|framework|package|module)\b|::/i;
export function isLibrary(i) {
  const s = i.summary;
  if (s?.devices?.length) return false;
  if (s?.library === true) return true;
  return [...(s?.products || []), ...(i.products || []).map((p) => p.name)].some((n) => PART_NAME.test(n));
}

// When the news first broke: the earliest source post time; Incidents stored before 11-08 only have first_seen.
export const publishedAt = (i) => i.published || i.first_seen;

// The row's name: the first CVE ID and how many more the Incident joins; null before any CVE exists.
export const cveHead = (cves = []) => (cves.length ? { id: cves[0], more: cves.length - 1 } : null);

// The row's 대상 column: the Summary's product names (vendor-led, "SonicWall SonicOS"), else the NVD Products'
// title-cased CPE names, then the Summary's devices; each name once.
// lang picks the Summary's names in that language ("Windows 그림판"); Summaries before 11-08 have none.
// Past this many device models a row shows the product alone; the Easy to-do list folds the models away
// (SNWLID-2026-0014 names 38 SonicWall models).
export const MANY_DEVICES = 4;
export const rowTags = (i, lang = 'en') => {
  const s = i.summary;
  const names = s?.products?.length ? s.products.map((_, k) => shownName(s, lang, k)) : (i.products || []).map(withVendor);
  // A Product that is also one of the operating systems ("Android", shown in Korean as "안드로이드") is the OS badge only.
  const os = new Set((s?.platforms || []).map((p) => p.toLowerCase()));
  const own = names.filter((_, k) => !os.has(String(s?.products?.[k] ?? '').toLowerCase()));
  const devices = (s?.devices || []).length > MANY_DEVICES ? [] : s?.devices || [];
  // Known systems in one fixed order on every row (Windows, macOS, Linux, Android, iOS; critique 12), others after.
  const rank = (p) => { const k = OSES.indexOf(p); return k < 0 ? OSES.length : k; };
  const platforms = [...(s?.platforms || [])].sort((a, b) => rank(a) - rank(b)); // stable: unknown ones keep their order
  return uniqueNames([...platforms, ...own, ...devices]); // operating systems first (user, 11-08)
};
// A row, its opened tag line and the Incident page show at most ROW_TAGS tags (owner, 11-11: CVE-2024-36309 drew 51 AMD
// processors, a row taller than the screen); past that, the first four and how many more. rowTags keeps every name.
export const ROW_TAGS = 5;
export const foldTags = (tags, max = ROW_TAGS) => (tags.length > max ? { shown: tags.slice(0, max - 1), more: tags.length - max + 1 } : { shown: tags, more: 0 });
// What pressing each of rowTags' names filters the Board by (owner, 11-10): an operating system or a Product adds a pick
// (exact, stacks, in the address), a name with no Product id (a device model) becomes the search.
export function tagFilters(i, lang = 'en') {
  const os = new Set(Array.isArray(i.summary?.platforms) ? i.summary.platforms : []);
  const keys = lineKeys(i, lang);
  return rowTags(i, lang).map((name) => {
    if (os.has(name)) return { name, kind: 'os', pick: `os:${name.toLowerCase()}` };
    return keys.has(name) ? { name, kind: 'product', pick: keys.get(name) } : { name, kind: 'query', query: name };
  });
}
// One tagFilters entry as the Board address that applies it alone ("#p=os%3Alinux", "#q=TZ270"): the Incident page's links.
export const tagHash = (tag) => `#${filterToQuery(tag.pick ? { picks: [tag.pick], query: '' } : { picks: [], query: tag.query })}`;

// The row's first Product that is not an operating system: what an update line, headline or fold line names.
export const firstProduct = (i, lang = 'en') => rowTags(i, lang).find((n) => !OSES.includes(n));

// An Incident's title in this language: the Summary's, else the quick title, else the source's own line, else its id.
export const titleOf = (i, lang) => i.summary?.[lang]?.title || i.quick_title?.[lang]?.title || i.brief?.text || i.id;

// Mentions are listed by kind in this order (the Lead order), on the Board and the Incident page alike.
export const MENTION_ORDER = ['advisory', 'writeup', 'cve_record', 'discussion', 'curator', 'notice', 'repo'];

// The words the Board (web/app.mjs), the Incident page and the RSS feed share, written once so they never drift apart.
// `nvd` is the Korean line beside the NVD notice; the required English sentence is static, so English has none.
export const WORDS = {
  ko: {
    title: 'Patch Ticker · 보안 취약점 게시판', other: 'English', otherShort: 'EN',
    command: '이 명령으로 업데이트하세요:', commandFor: (w) => `${w} 이 명령으로 업데이트하세요:`, devices: '이 기기들을 지금 업데이트하세요!',
    version: (v, p) => `${p ? `${p} ` : ''}${v} 이상으로 업데이트하세요.`, fixedIn: (v) => `${v} 버전에서 고쳐졌습니다.`,
    fixesIntro: '내 제품에 맞는 버전 이상으로 업데이트하세요:', stopgap: '당장 못 하면:',
    setting: '설정 파일에 이 줄을 넣으세요:', settingIn: (f) => `설정 파일 ${f}에 이 줄을 넣으세요:`,
    levels: { highest: '고위험', high: '위험', notice: '참고' }, kevReason: '악용 발생', kevListed: 'CISA KEV 등재', attackSource: '공격 보고:', poc: '공격 코드 공개됨',
    unrated: 'CVSS 점수 대기', unratedWhy: '점수 대기', conditions: '해당 조건', published: '처음 게시',
    none: '고친 버전을 아직 확인하지 못했습니다. 아래 원문 링크에서 확인하세요.',
    mentionKinds: { advisory: '보안 공지', writeup: '분석 글', cve_record: 'CVE 기록', discussion: '토론', curator: '뉴스레터', notice: '보호나라 공지', repo: '저장소' },
    newTab: ' (새 탭에서 열림)', report: '틀린 내용 알리기', tagsMore: (n) => `외 ${n}개`, tagsRest: (n) => `나머지 ${n}개 보기`,
    refNote: '이 게시판은 참고용입니다. 조치하기 전에 각 사건의 원문 공지를 확인하세요. 최대 90일의 사건만 저장합니다.',
    nvd: '이 서비스는 NVD API 데이터를 사용하지만 NVD의 보증이나 인증을 받지 않았습니다.',
    kevNote: '악용 발생 표시는 CISA의 알려진 악용 취약점(KEV) 목록이나, 실제 공격을 전한 원문을 바탕으로 합니다.',
    cveNote: 'CVE 정보는 MITRE의 CVE 이용 약관에 따라 사용합니다. 아래는 약관이 요구하는 저작권 표시와 라이선스 원문입니다.',
  },
  en: {
    title: 'Patch Ticker · vulnerability board', other: '한국어', otherShort: '한',
    command: 'Run this to update:', commandFor: (w) => `${w}, run this to update:`, devices: 'Update these devices now!',
    version: (v, p) => `Update ${p ? `${p} ` : ''}to ${v} or later.`, fixedIn: (v) => `Fixed in version ${v}.`,
    fixesIntro: 'Update to at least the version for your product:', stopgap: "Can't update yet?",
    setting: 'Add this line to the config file:', settingIn: (f) => `Add this line to ${f}:`,
    levels: { highest: 'High risk', high: 'Elevated', notice: 'Notice' }, kevReason: 'Exploited', kevListed: 'Listed in CISA KEV', attackSource: 'Attacks reported:', poc: 'Exploit code is public',
    unrated: 'CVSS score pending', unratedWhy: 'Score pending', conditions: 'Affected when', published: 'First published',
    none: 'We have not confirmed a fixed version yet. Check the source links below.',
    mentionKinds: { advisory: 'Advisory', writeup: 'Write-up', cve_record: 'CVE record', discussion: 'Discussion', curator: 'Newsletter', notice: 'KISA notice', repo: 'Repository' },
    newTab: ' (opens in a new tab)', report: 'Report a mistake', tagsMore: (n) => `+${n} more`, tagsRest: (n) => `Show ${n} more`,
    refNote: "This Board is for reference only. Check each Incident's source advisory before you act. Only Incidents of the last 90 days are kept.",
    nvd: '',
    kevNote: 'Exploited flags come from the CISA Known Exploited Vulnerabilities catalog, or from sources that report attacks.',
    cveNote: 'CVE data is used under the CVE Terms of Use from MITRE; its required copyright notice and license follow.',
  },
};

export const cveUrl = (cve) => `https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}`;

// The Summary's per-line fixes a reader can act on: a product line and its version, both given.
export const usableFixes = (s) => (Array.isArray(s.fixes) ? s.fixes : [])
  .filter((f) => typeof f?.for === 'string' && typeof f?.version === 'string' && f.for && f.version);

// 틀린 내용 알리기: a new issue in the public repository with the Incident filled in (ticket 09); link is where the visitor
// saw it (the Board's #i= address or its Incident page). Korean then English in both languages, so anyone can follow it (owner).
const ISSUES = 'https://github.com/dwamaker/PatchTicker/issues/new';
export function reportUrl(i, lang, link) {
  const body = [`사건 / Incident: ${i.id}`, `제목: ${titleOf(i, 'ko')}`, `Title: ${titleOf(i, 'en')}`, `링크 / Link: ${link}`, '',
    '무엇이 틀렸나요? / What is wrong?', '(예: 위험도, 영향받는 제품이나 버전, 요약 내용 / e.g. the risk level, the affected products or versions, the summary)',
    '', '', '근거가 있다면 링크를 적어 주세요. / Please add a link to your source if you have one.', ''].join('\n');
  return `${ISSUES}?${new URLSearchParams({ title: `[오류 제보 / Mistake] ${i.id}: ${titleOf(i, lang)}`, body })}`;
}

// A vendor as people write it, from the id's vendor part. Spellings live in vendors.json (the collector reads it too and
// lists vendors it lacks in unknown_vendors.json; how to add one: docs/agents/vendors.md). A fold line still needs a name
// for the rest: short codes in capitals (acme → ACME), else one capital (sonatype → Sonatype).
export const vendorName = (v) => VENDORS[v] || (v.length <= 4 ? v.toUpperCase() : v[0].toUpperCase() + v.slice(1));
// The vendor's own spelling, or '' when vendors.json lacks it: titles are never led by a guessed name
// ("Apache_software_foundation Apache Axis2", critique 14).
export const knownVendor = (v) => VENDORS[v] || '';
// An NVD or CVE-record name without its known vendor gets it in front ("Storage Scale" → "IBM Storage Scale"; critique 13),
// so a badge or fold line never names a product alone. Vendors not in the file are left as they are ("grav", not
// "Getgrav grav"): guessed casing mangles brands (D-Link, ownCloud), so they wait in unknown_vendors.json instead.
const withVendor = (p) => {
  const vendor = VENDORS[p.id.split(':')[0]];
  return vendor && !p.name.toLowerCase().includes(vendor.toLowerCase()) ? `${vendor} ${p.name}` : p.name;
};

// A vendor fold's member names its vendor in the title (critique 14: "Langflow OSS …" sat in the IBM fold, unexplained):
// the bare product name in the title becomes the vendor-led one, else the vendor-led name leads ("IBM Foo: …").
export function vendorLedTitle(title, vendor, product = '') {
  const low = title.toLowerCase();
  if (!vendor || low.includes(vendor.toLowerCase())) return title;
  const led = product.toLowerCase().startsWith(vendor.toLowerCase()) ? product : `${vendor} ${product}`.trim();
  const bare = led.slice(vendor.length).trim().toLowerCase();
  // the whole bare name, else its first word ("Db2" of "Db2 for Linux") when that is a name, not a short word
  const at = [bare, bare.split(' ')[0]].filter((n) => n.length >= 3).map((n) => low.indexOf(n)).find((k) => k >= 0) ?? -1;
  return at >= 0 ? `${title.slice(0, at)}${vendor} ${title.slice(at)}` : `${led}: ${title}`;
}

// Each name once, ignoring letter case (NVD gives "Qiskit SDK" and "Qiskit Sdk"): the first spelling stays.
export const uniqueNames = (names) => {
  const seen = new Set();
  return names.filter((n) => { const k = n.toLocaleLowerCase(); return !seen.has(k) && seen.add(k); });
};

// Line colours for Product badges, after the Seoul subway map: fill and the text colour that reads on it.
// No red, amber or grey hues, so a badge is never mistaken for a risk dot.
// Eight lines at least 0.13 apart in OKLab (11 before, but blue/navy, sky/periwinkle, teal/dark green and green/olive
// read as the same line at badge size). Operating systems are not lines: they get an outline badge.
// critique 13: mint (#77c4a3) was 0.05 from the dark Clear Green, so it became violet; teal darkened for white text (4.95).
export const LINES = [
  { bg: '#0052a4', ink: '#ffffff' }, { bg: '#00a84d', ink: '#0d0f12' }, { bg: '#00a5de', ink: '#0d0f12' },
  { bg: '#7f4f9a', ink: '#ffffff' }, { bg: '#b0ce18', ink: '#0d0f12' }, { bg: '#7340f2', ink: '#ffffff' },
  { bg: '#007c88', ink: '#ffffff' }, { bg: '#c25bb8', ink: '#0d0f12' },
];

// A Product's line from its language-free key (the Product id, "openbsd:openssh"), so it is the same on every visit,
// row and language. FNV-1a, then a final mix: plain FNV-1a mod 8 put six of ten real Products on one line (critique 4).
export function productLine(key) {
  let h = 0x811c9dc5;
  for (const ch of key) h = Math.imul(h ^ ch.codePointAt(0), 0x01000193);
  h = Math.imul(h ^ (h >>> 16), 0x85ebca6b);
  h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35);
  return LINES[((h ^ (h >>> 16)) >>> 0) % LINES.length];
}

// Each row badge's line key: the Product id behind a shown name (a Summary name in either language, an NVD name);
// a name with no Product (a device model) has none and keys by itself.
export function lineKeys(i, lang = 'en') {
  return new Map(productsOf(i, lang).flatMap((p) => [[p.name, p.id], [withVendor(p), p.id]])); // "IBM Storage Scale" keeps ibm:storage_scale's line
}

// How long ago, as a value and unit for Intl.RelativeTimeFormat; null from 30 days on (the date is shown instead).
export function relativeAge(iso, now) {
  const minutes = Math.max(1, Math.floor((now - Date.parse(iso)) / 60000));
  if (minutes < 60) return { value: -minutes, unit: 'minute' };
  if (minutes < 24 * 60) return { value: -Math.floor(minutes / 60), unit: 'hour' };
  if (minutes < 30 * 24 * 60) return { value: -Math.floor(minutes / (24 * 60)), unit: 'day' };
  return null;
}

// User, 2026-11-09: one vendor's bulk push (IBM put about 30 CVEs over 20 products in 80 minutes) folds into one list
// item once this many of its rows share a publish day; each row stays its own Incident inside. 0 turns the fold off.
// Owner, late 11-09: 3, not 5, so a smaller push folds too (Red Hat's three GStreamer CVEs in one minute).
export const VENDOR_FOLD_MIN = 3;
export const vendorOf = (i) => (i.products?.[0]?.id || '').split(':')[0];
// Owner, critique 14 c.1: WordPress plugins and themes are about a quarter of the list, so they fold as one pseudo-vendor,
// ahead of their own vendor's fold (one fold per row). WordPress itself is not a plugin. Also in collector/incidents.py
// (WP_PLUGIN, is_wordpress_plugin: a row view carries the answer as wp_plugin), kept in step by rows-case.json.
export const WORDPRESS = 'wordpress';
const WP_PLUGIN = /(?:wordpress|워드프레스)[^.;:!?\n]{0,40}?(?:plugin|theme|플러그인|테마)|(?:plugin|theme)s?\s+for\s+wordpress/i;
// Kept per Incident object: every redraw folds ~2,000 rows, and this regex over their text took half of a phone's
// view switch (11-10). Fresh data arrives as new objects (mergeIncidents), never as edits, so a kept answer stays true.
const wpPlugin = new WeakMap();
export const isWordPressPlugin = (i) => {
  if (typeof i.wp_plugin === 'boolean') return i.wp_plugin; // a row view (rows.json) lacks the text: the collector's answer
  if (wpPlugin.has(i)) return wpPlugin.get(i);
  const s = i.summary;
  const words = [i.brief?.text, ...['en', 'ko'].flatMap((l) => ['title', 'summary', 'easy_title', 'easy'].map((k) => s?.[l]?.[k])), ...(i.products || []).map((p) => p.id)];
  const answer = String(s?.products?.[0] ?? '').toLowerCase() !== WORDPRESS && WP_PLUGIN.test(words.filter(Boolean).join('\n'));
  wpPlugin.set(i, answer);
  return answer;
};
// Inside the WordPress fold the plugin words are said once, by the fold: "JWT Auth 워드프레스 플러그인" reads "JWT Auth".
export const pluginName = (n) => n.replace(/\s+(?:(?:for\s+)?(?:wordpress|워드프레스)\s+)?(?:plugin|theme|플러그인|테마)(?:\s+for\s+wordpress)?$/iu, '');
const foldKeyOf = (i) => (isWordPressPlugin(i) ? WORDPRESS : vendorOf(i));

// Where an Incident stands in the drawn list (rows and vendor folds; a fold member counts at its fold's place) and how
// many items `shown` must reach, in whole pages, to draw it; null when the list does not hold it. For #i= links (owner, 11-10).
export function linkedPlace(items, id, page) {
  const index = items.findIndex((x) => (x.fold ? x.incidents.some((i) => i.id === id) : x.id === id));
  return index < 0 ? null : { index, shown: (Math.floor(index / page) + 1) * page };
}

export function foldByVendor(rows, min = VENDOR_FOLD_MIN) {
  if (!min) return rows;
  const key = (i) => (foldKeyOf(i) ? `${foldKeyOf(i)} ${publishedAt(i).slice(0, 10)}` : '');
  const count = new Map();
  for (const i of rows) if (key(i)) count.set(key(i), (count.get(key(i)) || 0) + 1);
  const out = [];
  const folds = new Map();
  for (const i of rows) {
    const k = key(i);
    if (!k || count.get(k) < min) {
      out.push(i);
      continue;
    }
    if (!folds.has(k)) {
      const fold = { fold: k, vendor: foldKeyOf(i), incidents: [] };
      folds.set(k, fold);
      out.push(fold); // at the place of its first row in the visitor's order
    }
    folds.get(k).incidents.push(i);
  }
  return out;
}
