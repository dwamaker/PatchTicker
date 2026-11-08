import { LINK_KINDS, OSES, PINNED, RISKS, SORTS, pinReason, briefMarker, cveHead, easyLine, isShellCommand, onBoard, cvssRating, easyAction, filterBoard, filterFromQuery, filterToQuery, productLine, productList, publishedAt, relativeAge, riskLevel, rowTags, viewFromStorage } from './board.mjs';

// The store's base URL. Locally the collector writes into web/data/; ticket 02 points this at R2.
const DATA_URL = 'data/';
const SAVED = 'vr-filter';
const SAVED_LANG = 'vr-lang';
const SAVED_VIEW = 'vr-view';
// Also read by the inline script in index.html's head, so the remembered theme applies before first paint.
const SAVED_THEME = 'vr-theme';
// Every UI string, per language: the visitor's toggle, else the browser's language.
// Only CVE IDs, Product names, URLs and source data (the Brief's own line, Mention titles) are shown as they come.
// The NVD notice keeps its required English sentence in index.html; `nvd` is the Korean line beside it.
const TEXT = {
  ko: {
    other: 'English', otherShort: 'EN', title: 'vuln-radar · 보안 취약점 게시판', loading: '불러오는 중…',
    loadError: (msg) => `게시판을 불러오지 못했습니다: ${msg}`, retry: '다시 시도', filterBtn: '필터', fp: { title: '고급 필터', from: '게시일 시작', to: '게시일 끝', cvss: '최소 CVSS', cve: 'CVE', any: '전체', cveYes: 'CVE 있음', cveNo: 'CVE 아직 없음', risk: '위험 단계', flags: '조건', has: { advisory: '공식 공지 있음', repo: '공개 익스플로잇·PoC 있음' }, sort: '정렬', sorts: { new: '최신순', risk: '위험도순', cvss: 'CVSS 높은순' }, reset: '필터 초기화', apply: '필터 적용' }, textSizeGroup: '글자 크기', textDown: '글자 작게', textUp: '글자 크게', textReset: '기본 글자 크기', textNow: (p) => `글자 크기 ${p}%`, pinMore: (n) => `주목 더 보기 (${n})`, pinLess: '주목 접기', qfRisk: '위험 단계', qfKev: '악용 중만', noneForFilters: '고른 조건에 맞는 사건이 지금 게시판에 없습니다.', easyLevels: { highest: '심각', high: '경계', notice: '주의' }, why: { curator: '보안 뉴스레터 언급', buzz: 'HN 화제' }, skip: '주목 건너뛰고 최신순으로', found: (n) => `${n}건이 보입니다.`,
    status: (updated, shown, total) => `마지막 업데이트 ${updated} · 전체 ${total}건 중 ${shown}건`,
    products: '사용하는 제품', productsHint: '제품 이름을 입력해 찾기', picked: '고른 제품', remove: (name) => `${name} 빼기`,
    search: '검색', searchHint: '키워드, CVE ID, 버전', all: '최신순', theme: '어두운 화면',
    pin: '주목', noCve: 'CVE 번호 아직 없음', moreCves: (n) => ` 외 ${n}건`, published: '처음 게시', unrated: '점수 아직 없음', kevShort: '악용 중', kevReason: '실제 악용 중', kev: '실제 공격에 악용 중 (CISA KEV)', kevEasy: '지금 실제 공격에 쓰이고 있어요!',
    setting: '설정 파일에 이 줄을 넣으세요:', caution: '설정을 잘못 바꾸면 서비스가 멈추거나 접속이 막힐 수 있어요. 바꾸기 전에 아래 공식 링크를 확인하세요.',
    noneForPicks: (names) => `고른 제품(${names})에 해당하는 사건이 지금 게시판에 없습니다.`, noneForQuery: (q) => `‘${q}’에 맞는 사건이 없습니다.`, scopeWeek: '최근 7일 안에서 찾았습니다.', scopeMonths: '최근 3개월 안에서 찾았습니다.', searchOlder: '이전 사건에서도 찾기', loadedOlder: (n) => `이전 사건 ${n}건을 더 불러왔습니다.`,
    noIncidents: '아직 게시된 사건이 없습니다.', recentOnly: '최근 7일분', loadOlder: '이전 사건 불러오기 (최근 3개월)', showMore: (n) => `더 보기 (${n}건 남음)`, clearSearch: '검색 지우기', clearAll: '필터 모두 지우기',
    rating: { critical: '심각', high: '높음', medium: '보통', low: '낮음', none: '없음' },
    original: '원문', readAt: (site) => `${site}에서 읽기 →`,
    mentions: { advisory: '보안 공지', writeup: '분석 글', cve_record: 'CVE 기록', discussion: '토론', curator: '뉴스레터', repo: '저장소' },
    nvd: '이 서비스는 NVD API 데이터를 사용하지만 NVD의 보증이나 인증을 받지 않았습니다.',
    kevNote: '실제 악용 표시는 CISA의 알려진 악용 취약점(KEV) 목록에서 가져옵니다.',
    preparing: '요약 준비 중', unavailable: '요약을 만들지 못했습니다. 아래 대표 링크를 확인하세요.',
    conditions: '해당 조건', mitigation: '대처법', views: '보기 방식',
    normal: '기본', easy: '쉬운 설명', highest: '심각!', high: '경계', notice: '주의', levels: { highest: '고위험', high: '위험', notice: '참고' },
    command: '이 명령으로 업데이트하세요:', devices: '이 기기들을 지금 업데이트하세요!', version: (v) => `${v} 버전으로 업데이트하세요.`,
    fixedIn: (v) => `${v} 버전에서 고쳐졌습니다.`, none: '고친 버전을 아직 확인하지 못했습니다. 아래 공식 링크에서 확인하세요.', stopgap: '당장 못 하면:', copy: '복사', copied: '복사됨',
    paused: 'AI 요약이 잠시 멈췄습니다. 새 사건은 속보로만 보입니다.',
  },
  en: {
    other: '한국어', otherShort: '한', title: 'vuln-radar · vulnerability board', loading: 'Loading…',
    loadError: (msg) => `Could not load the Board: ${msg}`, retry: 'Try again', filterBtn: 'Filters', fp: { title: 'Advanced filters', from: 'Published from', to: 'Published to', cvss: 'Minimum CVSS', cve: 'CVE', any: 'Any', cveYes: 'Has a CVE', cveNo: 'No CVE yet', risk: 'Risk level', flags: 'Conditions', has: { advisory: 'Official advisory', repo: 'Public exploit or PoC' }, sort: 'Sort', sorts: { new: 'Newest', risk: 'Highest risk', cvss: 'Highest CVSS' }, reset: 'Reset filters', apply: 'Apply filters' }, textSizeGroup: 'Text size', textDown: 'Smaller text', textUp: 'Larger text', textReset: 'Default text size', textNow: (p) => `Text size ${p}%`, pinMore: (n) => `More Highlights (${n})`, pinLess: 'Fewer Highlights', qfRisk: 'Risk level', qfKev: 'Exploited only', noneForFilters: 'No Incident on the Board matches these filters.', easyLevels: { highest: 'Severe', high: 'Warning', notice: 'Caution' }, why: { curator: 'In security newsletters', buzz: 'Trending on HN' }, skip: 'Skip to newest', found: (n) => `${n} Incidents shown.`,
    status: (updated, shown, total) => `Last updated ${updated} · ${shown} of ${total} incidents`,
    products: 'Products you run', productsHint: 'Type to find a Product', picked: 'Picked Products', remove: (name) => `Remove ${name}`,
    search: 'Search', searchHint: 'Keyword, CVE ID, version', all: 'Newest first', theme: 'Dark theme',
    pin: 'Top', noCve: 'No CVE yet', moreCves: (n) => ` +${n}`, published: 'First published', unrated: 'Not rated yet', kevShort: 'Exploited', kevReason: 'Exploited in the wild', kev: 'Exploited in the wild (CISA KEV)', kevEasy: 'Attackers are using this right now!',
    setting: 'Add this line to the config file:', caution: 'A wrong setting can stop the service or lock you out. Check the official link below first.',
    noneForPicks: (names) => `No Incident on the Board touches the Products you picked (${names}).`, noneForQuery: (q) => `No Incident matches “${q}”.`, scopeWeek: 'Searched the last 7 days.', scopeMonths: 'Searched the last 3 months.', searchOlder: 'Search older Incidents too', loadedOlder: (n) => `Loaded ${n} older Incidents.`,
    noIncidents: 'No Incidents have been posted yet.', recentOnly: 'last 7 days', loadOlder: 'Load older Incidents (last 3 months)', showMore: (n) => `Show more (${n} left)`, clearSearch: 'Clear search', clearAll: 'Clear all filters',
    rating: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' },
    original: '', readAt: (site) => `Read at ${site} →`,
    mentions: { advisory: 'Advisory', writeup: 'Write-up', cve_record: 'CVE record', discussion: 'Discussion', curator: 'Newsletter', repo: 'Repository' },
    nvd: '',
    kevNote: 'Exploited-in-the-wild flags come from the CISA Known Exploited Vulnerabilities catalog.',
    preparing: 'Summary in preparation', unavailable: 'No Summary is available. See the Lead mention below.',
    conditions: 'Affected when', mitigation: 'Mitigation', views: 'View',
    normal: 'Normal', easy: 'Easy', highest: 'Severe!', high: 'Warning', notice: 'Caution', levels: { highest: 'High risk', high: 'Risk', notice: 'Notice' },
    command: 'Run this to update:', devices: 'Update these devices now!', version: (v) => `Update to version ${v}.`,
    fixedIn: (v) => `Fixed in version ${v}.`, none: 'We have not confirmed a fixed version yet. Check the official link below.', stopgap: 'Can\'t update yet?', copy: 'Copy', copied: 'Copied',
    paused: 'Summaries are paused for now; new Incidents show their Brief only.',
  },
};
let lang = loadLang();
// The Board-wide view (normal or Easy) the visitor chose at the top; remembered.
let defaultView = loadView();

function loadView() {
  try {
    return viewFromStorage(localStorage.getItem(SAVED_VIEW));
  } catch {
    return 'normal'; // storage blocked: normal view everywhere
  }
}

function setDefaultView(view) {
  defaultView = view;
  try {
    localStorage.setItem(SAVED_VIEW, view);
  } catch {
    // storage blocked: the choice lasts until reload
  }
  render();
}

function loadLang() {
  try {
    const saved = localStorage.getItem(SAVED_LANG);
    if (saved in TEXT) return saved;
  } catch {
    // storage blocked: fall back to the browser's language
  }
  return (navigator.language || '').toLowerCase().startsWith('ko') ? 'ko' : 'en';
}

const darkQuery = matchMedia('(prefers-color-scheme: dark)');
// The theme the page shows: the visitor's remembered choice, else the system's.
const theme = () => document.documentElement.dataset.theme || (darkQuery.matches ? 'dark' : 'light');

// Text size: 가− / 가+ step through these root sizes, remembered like the theme (index.html's inline script applies
// it before the first paint).
const TEXT_STEPS = [87.5, 100, 112.5, 125, 150];
const SAVED_TEXT = 'vr-text-pct';
const textPct = () => Math.round((parseFloat(document.documentElement.style.getPropertyValue('--ts')) || 1) * 1000) / 10;
function stepText(direction) {
  const next = TEXT_STEPS[Math.min(TEXT_STEPS.length - 1, Math.max(0, TEXT_STEPS.indexOf(textPct()) + direction))];
  // Only font sizes read --ts, so the text grows and the layout (gaps, columns, buttons) stays as it is.
  if (next === 100) document.documentElement.style.removeProperty('--ts');
  else document.documentElement.style.setProperty('--ts', String(next / 100));
  try {
    localStorage.setItem(SAVED_TEXT, String(next));
  } catch {
    // storage blocked: the choice lasts until reload
  }
  showTextSize();
}
function showTextSize() {
  const pct = textPct();
  $('text-down').disabled = pct === TEXT_STEPS[0];
  $('text-up').disabled = pct === TEXT_STEPS.at(-1);
}
function setTextIndex(index) {
  stepText(index - TEXT_STEPS.indexOf(textPct()));
  $('announce').textContent = TEXT[lang].textNow(textPct()); // the polite region says the new size
}

function toggleTheme() {
  const next = theme() === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem(SAVED_THEME, next);
  } catch {
    // storage blocked: the choice lasts until reload
  }
  pageText();
}

const getJson = async (name) => {
  const res = await fetch(DATA_URL + name, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  return res.json();
};

const $ = (id) => document.getElementById(id);
let incidents = [];
let products = [];
let updated = '';
let paused = false;
let loadError = null; // null while loading or once loaded; the error message if loading failed
// The Board opens on the last week (board/recent.json); older months come in when the visitor asks.
let olderMonths = [];
let loadingOlder = false;
// Rows of 최신순 drawn so far; a long list grows by PAGE on request instead of all at once.
const PAGE = 100;
let shown = PAGE;
// Rows the visitor opened, by Incident id, so a re-render (typing, language) keeps them open.
const open = new Set();
// The filter lives in the address hash, not the query, so opening a shared link never sends it to a server.
let filter = loadFilter();

function loadFilter() {
  const fromAddress = filterFromQuery(location.hash.slice(1));
  if (fromAddress.picks.length || fromAddress.query) return fromAddress;
  try {
    return filterFromQuery(localStorage.getItem(SAVED) || '');
  } catch {
    return fromAddress; // storage blocked (private window, cleared site data)
  }
}

function saveFilter() {
  const encoded = filterToQuery(filter);
  try {
    localStorage.setItem(SAVED, encoded);
  } catch {
    // storage blocked: the address still carries the filter
  }
  history.replaceState(null, '', encoded ? `#${encoded}` : location.pathname + location.search);
}

async function main() {
  render();
  try {
    const [index, st, recent] = await Promise.all([getJson('index.json'), getJson('status.json'), getJson('board/recent.json')]);
    incidents = recent.incidents.filter(onBoard);
    olderMonths = index.months.slice(-3);
    updated = st.updated;
    paused = st.summaries === 'paused'; // the collector hit its AI budget (ticket 07)
    refreshProducts();
    $('search').value = filter.query;
    saveFilter();
  } catch (err) {
    loadError = err.message;
  }
  render();
}

// Source URLs are untrusted too: only http(s) ever becomes a link target.
function anchor(url, text) {
  const a = document.createElement('a');
  a.href = /^https?:\/\//i.test(url) ? url : '#';
  a.rel = 'noopener';
  a.textContent = text;
  return a;
}

const host = (url) => URL.canParse(url) ? new URL(url).host.replace(/^www\./, '') : url;

// The picker's label: the vendor in brackets only when the name does not already say it; "Windows (OS)".
// The picker in the page's language, rebuilt when the data or the language changes.
function refreshProducts() {
  products = productList(incidents, Date.now(), lang);
  $('product-options').replaceChildren(...products.map((p) => new Option(label(p), label(p))));
}

const label = (p) => {
  const kind = p.id.split(':')[0];
  if (kind === 'os') return `${p.name} (OS)`;
  // The vendor in brackets only to tell apart two Products of the same name.
  const twin = products.some((o) => o !== p && o.name === p.name);
  return kind === 'name' || !twin ? p.name : `${p.name} (${kind})`;
};

// The page's own text: index.html marks each element with the TEXT key it shows.
function pageText() {
  const t = TEXT[lang];
  document.documentElement.lang = lang;
  showTextSize();
  document.title = t.title;
  for (const node of document.querySelectorAll('[data-t]')) {
    node.textContent = t[node.dataset.t];
    node.hidden = !node.textContent; // the Korean NVD line has no English twin
  }
  for (const node of document.querySelectorAll('[data-t-placeholder]')) node.placeholder = t[node.dataset.tPlaceholder];
  for (const node of document.querySelectorAll('[data-t-aria]')) node.setAttribute('aria-label', t[node.dataset.tAria]);
  // Full name on wide screens, a short code on phones (the header must fit 375px); screen readers get the full name.
  $('lang').replaceChildren(el('span', 'full', t.other), el('span', 'short', t.otherShort));
  $('lang').setAttribute('aria-label', t.other);
  $('lang').lang = lang === 'ko' ? 'en' : 'ko';
  for (const view of ['normal', 'easy']) $(`view-${view}`).setAttribute('aria-pressed', defaultView === view);
  $('theme').setAttribute('aria-pressed', theme() === 'dark');
}

function statusLine(list) {
  const t = TEXT[lang];
  if (loadError) return ''; // the message and its retry button sit in the empty-state block
  if (!updated) return t.loading;
  return t.status(ago(updated), list.length, incidents.length) + (olderMonths.length ? ` · ${t.recentOnly}` : '') + (paused ? ` · ${t.paused}` : '');
}

// The rest of the last three months, merged into the week already on screen.
async function loadOlder() {
  loadingOlder = true;
  render();
  try {
    const months = await Promise.all(olderMonths.map((m) => getJson(`board/${m}.json`)));
    const byId = new Map(incidents.map((i) => [i.id, i]));
    const before = byId.size;
    for (const i of months.flatMap((m) => m.incidents).filter(onBoard)) if (!byId.has(i.id)) byId.set(i.id, i);
    incidents = [...byId.values()];
    refreshProducts();
    olderMonths = [];
    clearTimeout(announcing); // a pending count from the last search must not talk over this
    $('announce').textContent = TEXT[lang].loadedOlder(byId.size - before); // also when nothing new came
  } catch (err) {
    loadError = err.message;
  }
  loadingOlder = false;
  render();
}

// Under the list: more rows of what is loaded, then older months.
function moreButtons(rest) {
  const t = TEXT[lang];
  const buttons = [];
  if (rest > 0) {
    const more = Object.assign(el('button', 'btn', t.showMore(rest)), { type: 'button' });
    more.addEventListener('click', () => { shown += PAGE; render(); });
    buttons.push(more);
  }
  if (olderMonths.length) {
    const older = Object.assign(el('button', 'btn', loadingOlder ? t.loading : t.loadOlder), { type: 'button', disabled: loadingOlder });
    older.addEventListener('click', loadOlder);
    buttons.push(older);
  }
  return buttons;
}

function render() {
  pageText();
  const { highlights: chosen, list } = filterBoard(incidents, filter.picks, filter.query, Date.now(), filter);
  // 주목 더 보기 adds only Highlights worth a notice: 위험 or above, or a reason the row cannot show (newsletter, HN).
  const extra = chosen.slice(PINNED).filter((i) => riskLevel(i) !== 'notice' || pinReason(i));
  const highlights = pinAll ? [...chosen.slice(0, PINNED), ...extra] : chosen.slice(0, PINNED);
  $('status').textContent = statusLine(list);
  $('skip').hidden = !highlights.length;
  announce(list.length);
  // Highlights are pinned on top like a board's notices; every other Incident follows, newest first.
  const pinned = new Set(highlights);
  rowCount = 0;
  // CVE text is untrusted input, so it only ever goes in through textContent.
  $('highlights').replaceChildren(...highlights.map((i) => row(i, true)));
  $('pinned').hidden = !highlights.length;
  $('pinned-head').replaceChildren(`${TEXT[lang].pin} `, el('span', 'n', String(highlights.length)));
  $('pinned-head').hidden = !highlights.length;
  $('pin-more').replaceChildren(...(extra.length ? [pinToggle(extra.length)] : []));
  const count = panelCount();
  $('filter-count').textContent = count ? String(count) : '';
  $('filter-count').hidden = !count;
  $('filter-btn').setAttribute('aria-expanded', !$('filters').hidden);
  const rest = list.filter((i) => !pinned.has(i));
  $('board').replaceChildren(...rest.slice(0, shown).map((i) => row(i, false)));
  $('more').replaceChildren(...(loadError || !updated ? [] : moreButtons(rest.length - shown)));
  // OS picks show as pressed buttons in the quick bar, so only Products become chips here.
  const chips = filter.picks.filter((p) => !p.startsWith('os:'));
  $('picks').replaceChildren(...chips.map(chip), ...conditionChips(), ...(activeFilters() > 1 ? [clearButton(TEXT[lang].clearAll, NO_FILTER)] : []));
  $('all-head').hidden = !list.some((i) => !pinned.has(i));
  // Before the data arrives, say nothing; if it never arrives, say so and offer a retry, not "no Incidents".
  const quiet = list.length > 0 || (!updated && !loadError);
  $('empty').hidden = quiet;
  $('empty').replaceChildren(...(quiet ? [] : loadError ? errorState() : emptyState()));
}

// Nothing to show: say so plainly. With products picked this is the good news, "not affected".
function errorState() {
  const t = TEXT[lang];
  const retry = Object.assign(el('button', 'btn', t.retry), { type: 'button' });
  retry.addEventListener('click', () => location.reload());
  const actions = el('p', 'actions');
  actions.append(retry);
  return [para('', t.loadError(loadError)), actions];
}

// Screen readers hear the count once the visitor stops changing the filter, not on every redraw.
let lastCount = null;
let announcing;
function announce(count) {
  if (!updated || count === lastCount) return;
  const first = lastCount === null;
  lastCount = count;
  clearTimeout(announcing);
  if (!first) announcing = setTimeout(() => { $('announce').textContent = TEXT[lang].found(count); }, 700);
}

function emptyState() {
  const t = TEXT[lang];
  const names = filter.picks.map((id) => products.find((p) => p.id === id)?.name || id).join(', ');
  // Only Products picked: name them ("not affected"); any quick filter in play: speak of conditions instead.
  const quick = panelCount() > 0;
  const message = filter.picks.length && !quick ? t.noneForPicks(names) : filter.query && !quick ? t.noneForQuery(filter.query)
    : quick ? t.noneForFilters : t.noIncidents;
  const buttons = el('p', 'actions');
  // Say how far back this looked: "nothing" in one week is not "nothing" in three months.
  const scope = para('scope', olderMonths.length ? t.scopeWeek : t.scopeMonths);
  if (olderMonths.length) {
    const older = Object.assign(el('button', 'btn', loadingOlder ? t.loading : t.searchOlder), { type: 'button', disabled: loadingOlder });
    older.addEventListener('click', loadOlder);
    buttons.append(older);
  }
  if (filter.query) buttons.append(clearButton(t.clearSearch, { query: '' }));
  // 모두 지우기 only when something besides the search is set; with a search alone it would repeat 검색 지우기.
  if (activeFilters() - (filter.query ? 1 : 0) > 0) buttons.append(clearButton(t.clearAll, NO_FILTER));
  return [para('', message), scope, ...(buttons.childElementCount ? [buttons] : [])];
}

function clearButton(text, change) {
  const button = Object.assign(el('button', 'btn', text), { type: 'button' });
  button.addEventListener('click', () => {
    if ('query' in change) $('search').value = change.query;
    update(change);
    $(change.picks ? 'product-pick' : 'search').focus();
  });
  return button;
}

function chip(id) {
  const name = products.find((p) => p.id === id)?.name || id;
  const button = Object.assign(el('button', 'chip'), { type: 'button' });
  const badge = lineBadge(name);
  badge.append(el('span', 'x'));
  button.append(badge);
  button.setAttribute('aria-label', TEXT[lang].remove(name));
  button.addEventListener('click', () => {
    update({ picks: filter.picks.filter((p) => p !== id) });
    $('product-pick').focus(); // the chip is gone; keep keyboard users in the filter
  });
  return button;
}

const PANEL_EMPTY = { risk: [], kev: false, from: '', to: '', cvssMin: 0, cve: '', has: [], sort: 'new' };
const NO_FILTER = { picks: [], query: '', ...PANEL_EMPTY };
const osPicks = () => filter.picks.filter((p) => p.startsWith('os:'));
// What the 필터 button's badge counts: everything set inside the panel.
const panelCount = () => filter.risk.length + (filter.kev ? 1 : 0) + osPicks().length + (filter.from || filter.to ? 1 : 0)
  + (filter.cvssMin ? 1 : 0) + (filter.cve ? 1 : 0) + filter.has.length + (filter.sort !== 'new' ? 1 : 0);
const activeFilters = () => filter.picks.length - osPicks().length + panelCount() + (filter.query ? 1 : 0);

// 주목 더 보기: pin every chosen Highlight (up to ten), or back to four.
let pinAll = false;
function pinToggle(rest) {
  const t = TEXT[lang];
  const button = Object.assign(el('button', 'btn', pinAll ? t.pinLess : t.pinMore(rest)), { type: 'button' });
  button.setAttribute('aria-expanded', pinAll);
  button.addEventListener('click', () => { pinAll = !pinAll; render(); });
  return button;
}

// The advanced filter panel under the 필터 button: built from the current filter each time it opens, applied
// as a whole with 필터 적용 (nothing changes while the visitor is still choosing).
function filterPanel() {
  const t = TEXT[lang];
  const f = t.fp;
  const field = (label, control, wide = false) => {
    const wrap = el('label', wide ? 'fp-field wide' : 'fp-field');
    wrap.append(el('span', 'fp-label', label), control);
    return wrap;
  };
  const input = (type, name, value) => Object.assign(document.createElement('input'), { type, name, value });
  const select = (name, options, value) => {
    const s = Object.assign(document.createElement('select'), { name });
    s.append(...options.map(([v, text]) => Object.assign(new Option(text, v), { selected: String(v) === String(value) })));
    return s;
  };
  const checks = (legend, name, items, isOn) => {
    const set = el('fieldset', 'fp-field wide fp-checks');
    set.append(el('legend', 'fp-label', legend));
    for (const [value, text, extra] of items) {
      const box = Object.assign(input('checkbox', name, value), { checked: isOn(value) });
      const chip = el('label', `fp-chip ${extra || ''}`);
      chip.append(box, el('span', '', text));
      set.append(chip);
    }
    return set;
  };
  const words = defaultView === 'easy' ? t.easyLevels : t.levels;
  const form = $('filters');
  const grid = el('div', 'fp-grid');
  grid.append(
    field(f.from, input('date', 'from', filter.from)),
    field(f.to, input('date', 'to', filter.to)),
    field(f.cvss, select('cvssMin', [[0, f.any], [4, '4.0+'], [7, '7.0+'], [9, '9.0+']], filter.cvssMin)),
    field(f.cve, select('cve', [['', f.any], ['yes', f.cveYes], ['no', f.cveNo]], filter.cve)),
    checks(f.risk, 'risk', RISKS.map((r) => [r, words[r], `risk-${r}`]), (r) => filter.risk.includes(r)),
    checks(f.flags, 'flag', [['kev', t.qfKev], ...LINK_KINDS.map((k) => [k, f.has[k]])], (v) => (v === 'kev' ? filter.kev : filter.has.includes(v))),
    checks('OS', 'os', OSES.map((os) => [`os:${os.toLowerCase()}`, os]), (v) => filter.picks.includes(v)),
    field(f.sort, select('sort', SORTS.map((s) => [s, f.sorts[s]]), filter.sort)),
  );
  const actions = el('div', 'fp-actions');
  const reset = Object.assign(el('button', 'btn', f.reset), { type: 'button' });
  reset.addEventListener('click', () => { update(PANEL_EMPTY_WITH_OS()); filterPanel(); });
  const apply = Object.assign(el('button', 'btn primary', f.apply), { type: 'submit' });
  actions.append(reset, apply);
  form.replaceChildren(el('h3', 'fp-title', f.title), grid, actions);
}

// Reset clears the panel only; Products picked at the top and the search stay.
const PANEL_EMPTY_WITH_OS = () => ({ ...PANEL_EMPTY, picks: filter.picks.filter((p) => !p.startsWith('os:')) });

function applyPanel(event) {
  event.preventDefault();
  const data = new FormData($('filters'));
  const flags = data.getAll('flag');
  update({
    from: data.get('from') || '', to: data.get('to') || '', cvssMin: Number(data.get('cvssMin')) || 0, cve: data.get('cve') || '',
    risk: data.getAll('risk'), kev: flags.includes('kev'), has: flags.filter((v) => v !== 'kev'), sort: data.get('sort') || 'new',
    picks: [...filter.picks.filter((p) => !p.startsWith('os:')), ...data.getAll('os')],
  });
  closePanel(); // the results are the answer; the applied conditions stay visible as chips
  // A start date before the loaded week needs the older months.
  const week = new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10);
  if (filter.from && filter.from < week && olderMonths.length) loadOlder();
}

function update(change) {
  filter = { ...filter, ...change };
  shown = PAGE;
  saveFilter();
  render();
  if (!$('filters').hidden) filterPanel(); // an open panel always shows the filter in force, never a stale draft
}

function closePanel() {
  $('filters').hidden = true;
  $('filter-btn').setAttribute('aria-expanded', 'false');
  $('filter-btn').focus();
}

// Each applied panel condition as a removable chip under the fields, so what is filtered stays in sight.
function conditionChips() {
  const t = TEXT[lang];
  const f = t.fp;
  const words = defaultView === 'easy' ? t.easyLevels : t.levels;
  const chips = [
    ...filter.risk.map((r) => [words[r], { risk: filter.risk.filter((x) => x !== r) }]),
    ...(filter.kev ? [[t.qfKev, { kev: false }]] : []),
    ...filter.has.map((h) => [f.has[h], { has: filter.has.filter((x) => x !== h) }]),
    ...filter.picks.filter((p) => p.startsWith('os:')).map((p) => [OSES.find((o) => `os:${o.toLowerCase()}` === p) || p, { picks: filter.picks.filter((x) => x !== p) }]),
    ...(filter.from || filter.to ? [[`${filter.from || '…'} ~ ${filter.to || '…'}`, { from: '', to: '' }]] : []),
    ...(filter.cvssMin ? [[`CVSS ${filter.cvssMin}.0+`, { cvssMin: 0 }]] : []),
    ...(filter.cve ? [[filter.cve === 'yes' ? f.cveYes : f.cveNo, { cve: '' }]] : []),
    ...(filter.sort !== 'new' ? [[f.sorts[filter.sort], { sort: 'new' }]] : []),
  ];
  return chips.map(([label, change]) => {
    const button = Object.assign(el('button', 'cond'), { type: 'button' });
    button.append(el('span', '', label), el('span', 'x'));
    button.setAttribute('aria-label', t.remove(label));
    button.addEventListener('click', () => { update(change); $('filter-btn').focus(); });
    return button;
  });
}

$('product-pick').addEventListener('change', (event) => {
  const text = event.target.value.trim();
  const picked = products.find((p) => label(p) === text);
  event.target.value = '';
  if (picked && !filter.picks.includes(picked.id)) update({ picks: [...filter.picks, picked.id] });
  // Not a listed Product ("공유기"): search for it instead of dropping it silently.
  if (!picked && text) {
    $('search').value = text;
    update({ query: text });
  }
});
$('lang').addEventListener('click', () => {
  lang = lang === 'ko' ? 'en' : 'ko';
  try {
    localStorage.setItem(SAVED_LANG, lang);
  } catch {
    // storage blocked: the choice lasts until reload
  }
  refreshProducts();
  render();
});
$('view-normal').addEventListener('click', () => setDefaultView('normal'));
$('view-easy').addEventListener('click', () => setDefaultView('easy'));
$('theme').addEventListener('click', toggleTheme);
document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && !$('filters').hidden) closePanel(); });
$('filters').addEventListener('submit', applyPanel);
$('filter-btn').addEventListener('click', () => {
  const form = $('filters');
  form.hidden = !form.hidden;
  if (!form.hidden) filterPanel();
  render();
});
$('text-down').addEventListener('click', () => setTextIndex(TEXT_STEPS.indexOf(textPct()) - 1));
$('text-up').addEventListener('click', () => setTextIndex(TEXT_STEPS.indexOf(textPct()) + 1));
// The filter lives in the hash, so the skip link moves focus itself instead of rewriting the address.
$('skip').addEventListener('click', (event) => {
  event.preventDefault();
  $('all-head').focus();
});
darkQuery.addEventListener('change', pageText);
// Typing waits a beat before the Board redraws, so a word is one redraw, not one per letter.
let typing;
$('search').addEventListener('input', (event) => {
  clearTimeout(typing);
  typing = setTimeout(() => update({ query: event.target.value }), 150);
});
window.addEventListener('hashchange', () => {
  filter = loadFilter();
  $('search').value = filter.query;
  render();
});

const el = (tag, className, textContent = '') => Object.assign(document.createElement(tag), { className, textContent });
// The page follows `lang`; source text in another language carries its own lang for screen readers.
const para = (className, textContent, language = lang) => Object.assign(el('p', className, textContent), { lang: language });

// "대처법: ..." with the label bold, so the answer is found by eye.
function labelled(className, label, text) {
  const p = para(className, '');
  p.append(el('b', '', `${label}: `), text);
  return p;
}

function summary(s) {
  const parts = [para('summary', s.summary)];
  if (s.conditions.length) parts.push(labelled('conditions', TEXT[lang].conditions, s.conditions.join(' · ')));
  if (s.mitigation) parts.push(labelled('mitigation', TEXT[lang].mitigation, s.mitigation));
  return parts;
}

// Until the Summary arrives the row's title is the Brief, the source's own line (English); this says why.
const briefNote = (incident) => [para('preparing', TEXT[lang][briefMarker(incident)])];

// The Lead mention is always the rule-based one (CONTEXT.md order), never the model's pick.
function leadLine(incident) {
  const lead = el('p', 'lead');
  lead.append(anchor(incident.brief.lead, TEXT[lang].readAt(host(incident.brief.lead))));
  return lead;
}

// A command from a source, shown as is, with a button that copies exactly the text shown.
function commandLine(text) {
  const p = el('p', 'command');
  const code = el('code', '', text);
  const button = Object.assign(el('button', 'btn', TEXT[lang].copy), { type: 'button' });
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = TEXT[lang].copied;
    } catch {
      getSelection().selectAllChildren(code); // clipboard blocked: select it for a manual copy
    }
  });
  p.append(code, ' ', button);
  return p;
}

// A config line, not a shell command: no copy button that invites pasting it into a terminal, and a warning.
function settingLine(text) {
  const t = TEXT[lang];
  const p = el('p', 'command');
  p.append(el('code', '', text));
  return [para('action', t.setting), p, para('caution', t.caution)];
}

function easyAnswer(s) {
  const t = TEXT[lang];
  const action = easyAction(s);
  const parts = []; // the plain sentence is already the row's second line
  if (action.kind === 'command') parts.push(...(isShellCommand(action.command) ? [para('action', t.command), commandLine(action.command)] : settingLine(action.command)));
  if (action.kind === 'version') parts.push(para('action', t.version(action.fixed)));
  // No fixed version, command or devices: the Summary's own advice ("run newer than 7.3.3-7015"), else say we have not confirmed one.
  if (action.kind === 'none') parts.push(para('action', s[lang].mitigation || t.none));
  if (action.kind === 'devices') {
    const list = el('ul', 'devices');
    list.append(...action.devices.map((d) => el('li', '', d)));
    parts.push(para('action', t.devices), list);
    if (action.fixed) parts.push(para('fixed', t.fixedIn(action.fixed)));
  }
  if (action.stopgap) parts.push(para('stopgap', t.stopgap), ...(isShellCommand(action.stopgap) ? [commandLine(action.stopgap)] : settingLine(action.stopgap)));
  return parts;
}

// The row's start: a dot in the rule-based Risk colour and its word (loud in the Easy view).
function riskCell(incident) {
  const level = riskLevel(incident);
  const cell = el('span', `c-risk risk-${level}`);
  const dot = el('i', 'dot');
  dot.setAttribute('aria-hidden', 'true');
  cell.append(dot, defaultView === 'easy' ? TEXT[lang][level] : TEXT[lang].levels[level]);
  // Why it is this high when the score alone would not say so: exploited in the wild lifts it to the top level.
  if (incident.kev) cell.append(el('small', 'why kev', TEXT[lang].kevReason));
  return cell;
}

// CVSS in both views: a ring filled to the score out of 10 with the number inside, coloured by its
// rating, then the rating word and the exploited flag.
function scoreCell(incident) {
  const t = TEXT[lang];
  const cell = el('span', 'c-score');
  const rating = cvssRating(incident.cvss);
  if (!rating) {
    // No score yet: a quiet word, not an empty 44px ring repeated down the Board.
    // A quiet dash, not the same words on most rows; the meaning is in the tooltip and for screen readers.
    const words = Object.assign(el('span', 'sev unrated'), { title: t.unrated });
    words.append(el('span', 'sr-only', t.unrated), Object.assign(el('span', '', '—'), { ariaHidden: 'true' }));
    if (incident.kev) words.append(el('span', 'kev', t.kevShort));
    cell.append(words);
    return cell;
  }
  const gauge = el('span', `gauge sev-${rating}`);
  gauge.setAttribute('role', 'img');
  // The words beside the ring are aria-hidden, so the exploited flag rides in the ring's label.
  gauge.setAttribute('aria-label', `CVSS ${incident.cvss} ${t.rating[rating]}` + (incident.kev ? `, ${t.kevShort}` : ''));
  gauge.style.setProperty('--fill', Math.min(incident.cvss, 10) / 10);
  gauge.innerHTML = '<svg viewBox="0 0 40 40" aria-hidden="true"><circle class="track" cx="20" cy="20" r="17" pathLength="1"/><circle class="arc" cx="20" cy="20" r="17" pathLength="1"/></svg>';
  gauge.append(el('b', 'num', incident.cvss.toFixed(1)));
  // One severity language: the risk word speaks; beside the ring only its name, the number and colour carry the score.
  const words = el('span', 'sev', 'CVSS');
  words.setAttribute('aria-hidden', 'true');
  cell.append(gauge, words);
  return cell;
}

// The Incident's own title: the Summary's, else the Brief marked as source text (English).
function describe(incident) {
  const t = TEXT[lang];
  if (incident.summary?.[lang].title) return [incident.summary[lang].title]; // empty for some news replies
  const brief = Object.assign(el('span', '', incident.brief.text), { lang: 'en' });
  return t.original ? [el('span', 'orig', t.original), ' ', brief] : [brief];
}

// A station sign: in the normal view the CVE ID is the bold name and the title the line under it. The
// Easy view leads with the plain headline over the one plain sentence; with no Summary yet, or no CVE
// yet, the title leads and the CVE line goes under it.
function titleCell(incident) {
  const t = TEXT[lang];
  const cell = el('span', 'c-title');
  const head = cveHead(incident.cves);
  const id = el('span', head ? 'cve' : 'cve none');
  if (head) {
    id.append(head.id);
    if (head.more) id.append(el('span', 'more', t.moreCves(head.more)));
    id.title = incident.cves.join(', ');
  } else id.append(t.noCve);
  const name = el('strong', 'title');
  const line = el('small', 'sub');
  const s = incident.summary?.[lang];
  if (defaultView === 'easy' && s?.title) {
    name.append(s.easy_title || s.title); // Summaries made before 11-08 have no easy_title
    line.append(easyLine(s.easy || s.summary, riskLevel(incident)));
    line.classList.add('say');
  } else if (head && defaultView !== 'easy') {
    name.append(id);
    line.append(...describe(incident));
  } else {
    name.append(...describe(incident));
    line.append(id);
  }
  cell.append(name, line);
  return cell;
}

// A Product's line badge, in that Product's fixed colour.
function lineBadge(name) {
  const badge = el('span', 'ln', name);
  const { bg, ink } = productLine(name);
  badge.style.setProperty('--line', bg);
  badge.style.setProperty('--line-ink', ink);
  return badge;
}

function tagsCell(incident) {
  const cell = el('span', 'c-tags');
  cell.append(...rowTags(incident, lang).map(lineBadge));
  return cell;
}

// "2시간 전" / "2 hours ago"; the date from 30 days on.
function ago(iso) {
  const age = relativeAge(iso, Date.now());
  return age ? new Intl.RelativeTimeFormat(lang, { numeric: 'always' }).format(age.value, age.unit) : iso.slice(0, 10);
}

// When the news first broke, in the visitor's time zone: the date over the time; how long ago in the tooltip.
function dateCell(incident) {
  const at = publishedAt(incident);
  const d = new Date(at);
  const two = (n) => String(n).padStart(2, '0');
  const time = el('time', 'c-date');
  time.dateTime = at;
  time.append(el('span', '', `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}`), el('span', '', `${two(d.getHours())}:${two(d.getMinutes())}`));
  time.title = `${TEXT[lang].published} · ${ago(at)}`;
  return time;
}

// Both views end with the Lead and every Mention, so links a CVE record gains later show up in either.
function details(incident) {
  const t = TEXT[lang];
  const easy = defaultView === 'easy';
  const parts = !incident.summary ? briefNote(incident) : easy ? easyAnswer(incident.summary) : summary(incident.summary[lang]);
  if (incident.kev && !easy) parts.push(para('kev', t.kev));
  // The Easy row leads with a plain headline, so the opened panel starts with the CVE IDs.
  if (easy && incident.kev) parts.unshift(para('kev', t.kevEasy));
  if (easy) parts.unshift(para('cve-line', incident.cves.join(', ') || t.noCve));
  const mentions = el('ul', 'mentions');
  for (const m of incident.mentions) {
    const item = el('li', '');
    item.append(`${t.mentions[m.kind] ?? m.kind}: `, anchor(m.url, m.title || host(m.url)));
    mentions.append(item);
  }
  return [...parts, leadLine(incident), mentions];
}

let rowCount = 0;


// One board row: a button that opens the details below it, like opening a post. A Highlight is a framed
// alert edged in its Risk colour, with the details inside the frame.
function row(incident, pinned) {
  const li = el('li', pinned ? `alert risk-${riskLevel(incident)}` : '');
  const body = Object.assign(el('div', 'details'), { id: `details-${++rowCount}`, hidden: !open.has(incident.id) });
  const button = Object.assign(el('button', 'row'), { type: 'button' });
  button.setAttribute('aria-controls', body.id);
  button.setAttribute('aria-expanded', !body.hidden);
  const chevron = el('i', 'chev');
  chevron.setAttribute('aria-hidden', 'true');
  const risk = riskCell(incident);
  const why = pinned && pinReason(incident);
  if (why) risk.append(el('small', 'why', TEXT[lang].why[why]));
  button.append(risk, titleCell(incident), scoreCell(incident), tagsCell(incident), dateCell(incident), chevron);
  button.addEventListener('click', () => {
    body.hidden = !body.hidden;
    button.setAttribute('aria-expanded', !body.hidden);
    if (body.hidden) open.delete(incident.id);
    else open.add(incident.id);
  });
  body.append(...details(incident));
  li.append(button, body);
  return li;
}

main();
