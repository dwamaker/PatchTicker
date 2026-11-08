import { briefMarker, cvssRating, easyAction, filterBoard, filterFromQuery, filterToQuery, productList, riskLevel, rowTags, viewFromStorage } from './board.mjs';

// The store's base URL. Locally the collector writes into web/data/; ticket 02 points this at R2.
const DATA_URL = 'data/';
const SAVED = 'vr-filter';
const SAVED_LANG = 'vr-lang';
const SAVED_VIEW = 'vr-view';
// Every UI string, per language: the visitor's toggle, else the browser's language.
// Only CVE IDs, Product names, URLs and source data (the Brief's own line, Mention titles) are shown as they come.
// The NVD notice keeps its required English sentence in index.html; `nvd` is the Korean line beside it.
const TEXT = {
  ko: {
    other: 'English', title: 'vuln-radar · 보안 취약점 게시판', loading: '불러오는 중…',
    loadError: (msg) => `게시판을 불러오지 못했습니다: ${msg}`,
    status: (updated, shown, total) => `마지막 업데이트 ${updated} · 전체 ${total}건 중 ${shown}건`,
    products: '사용하는 제품', productsHint: '제품 이름을 입력해 찾기', picked: '고른 제품', remove: (name) => `${name} 빼기`,
    search: '검색', searchHint: '키워드, CVE ID, 버전', all: '전체 사건 · 최신순',
    colRisk: '위험도', colCve: 'CVE', colTitle: '제목', colTags: '대상', colDate: '날짜',
    pin: '주목', noCve: 'CVE 미배정', unrated: '평가 전', kevShort: '악용 중', kev: '실제 공격에 악용 중 (CISA KEV)',
    rating: { critical: '심각', high: '높음', medium: '보통', low: '낮음', none: '없음' },
    original: '원문', readAt: (site) => `${site}에서 읽기 →`,
    mentions: { advisory: '보안 공지', writeup: '분석 글', cve_record: 'CVE 기록', discussion: '토론', curator: '뉴스레터', repo: '저장소' },
    nvd: '이 서비스는 NVD API 데이터를 사용하지만 NVD의 보증이나 인증을 받지 않았습니다.',
    kevNote: '실제 악용 표시는 CISA의 알려진 악용 취약점(KEV) 목록에서 가져옵니다.',
    preparing: '요약 준비 중', unavailable: '요약을 만들지 못했습니다. 아래 대표 링크를 확인하세요.',
    conditions: '해당 조건', mitigation: '대처법', views: '보기 방식',
    normal: '기본', easy: '쉬운 설명', highest: '고위험!', high: '위험', notice: '참고',
    command: '이 명령으로 업데이트하세요:', devices: '이 기기들을 지금 업데이트하세요!', version: (v) => `${v} 버전으로 업데이트하세요.`,
    fixedIn: (v) => `${v} 버전에서 고쳐졌습니다.`, none: '아직 나온 대처법이 없습니다. 아래 링크를 확인하세요.', stopgap: '당장 못 하면:', copy: '복사', copied: '복사됨',
    paused: 'AI 요약이 잠시 멈췄습니다. 새 사건은 속보로만 보입니다.',
  },
  en: {
    other: '한국어', title: 'vuln-radar · vulnerability board', loading: 'Loading…',
    loadError: (msg) => `Could not load the Board: ${msg}`,
    status: (updated, shown, total) => `Last updated ${updated} · ${shown} of ${total} incidents`,
    products: 'Products you run', productsHint: 'Type to find a Product', picked: 'Picked Products', remove: (name) => `Remove ${name}`,
    search: 'Search', searchHint: 'Keyword, CVE ID, version', all: 'All incidents, newest first',
    colRisk: 'Risk', colCve: 'CVE', colTitle: 'Title', colTags: 'Affects', colDate: 'Date',
    pin: 'Top', noCve: 'No CVE yet', unrated: 'Not rated yet', kevShort: 'Exploited', kev: 'Exploited in the wild (CISA KEV)',
    rating: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' },
    original: '', readAt: (site) => `Read at ${site} →`,
    mentions: { advisory: 'Advisory', writeup: 'Write-up', cve_record: 'CVE record', discussion: 'Discussion', curator: 'Newsletter', repo: 'Repository' },
    nvd: '',
    kevNote: 'Exploited-in-the-wild flags come from the CISA Known Exploited Vulnerabilities catalog.',
    preparing: 'Summary in preparation', unavailable: 'No Summary is available. See the Lead mention below.',
    conditions: 'Affected when', mitigation: 'Mitigation', views: 'View',
    normal: 'Normal', easy: 'Easy', highest: 'High risk!', high: 'Risk', notice: 'Notice',
    command: 'Run this to update:', devices: 'Update these devices now!', version: (v) => `Update to version ${v}.`,
    fixedIn: (v) => `Fixed in version ${v}.`, none: 'No mitigation is known yet. Check the link below.', stopgap: 'Can\'t update yet?', copy: 'Copy', copied: 'Copied',
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
    const [index, st] = await Promise.all([getJson('index.json'), getJson('status.json')]);
    const months = await Promise.all(index.months.slice(-3).map((m) => getJson(`months/${m}.json`)));
    incidents = months.flatMap((m) => m.incidents);
    products = productList(incidents, Date.now());
    updated = st.updated;
    paused = st.summaries === 'paused'; // the collector hit its AI budget (ticket 07)
    $('product-options').replaceChildren(...products.map((p) => new Option(label(p), label(p))));
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

const label = (p) => `${p.name} (${p.id.split(':')[0]})`;

// The page's own text: index.html marks each element with the TEXT key it shows.
function pageText() {
  const t = TEXT[lang];
  document.documentElement.lang = lang;
  document.title = t.title;
  for (const node of document.querySelectorAll('[data-t]')) {
    node.textContent = t[node.dataset.t];
    node.hidden = !node.textContent; // the Korean NVD line has no English twin
  }
  for (const node of document.querySelectorAll('[data-t-placeholder]')) node.placeholder = t[node.dataset.tPlaceholder];
  for (const node of document.querySelectorAll('[data-t-aria]')) node.setAttribute('aria-label', t[node.dataset.tAria]);
  $('lang').textContent = t.other;
  $('lang').lang = lang === 'ko' ? 'en' : 'ko';
  for (const view of ['normal', 'easy']) $(`view-${view}`).setAttribute('aria-pressed', defaultView === view);
}

function statusLine(list) {
  const t = TEXT[lang];
  if (loadError) return t.loadError(loadError);
  if (!updated) return t.loading;
  return t.status(updated, list.length, incidents.length) + (paused ? ` · ${t.paused}` : '');
}

function render() {
  pageText();
  const { highlights, list } = filterBoard(incidents, filter.picks, filter.query, Date.now());
  $('status').textContent = statusLine(list);
  // Highlights are pinned on top like a board's notices; every other Incident follows, newest first.
  const pinned = new Set(highlights);
  rowCount = 0;
  // CVE text is untrusted input, so it only ever goes in through textContent.
  $('board').replaceChildren(...highlights.map((i) => row(i, true)), ...list.filter((i) => !pinned.has(i)).map((i) => row(i, false)));
  $('picks').replaceChildren(...filter.picks.map(chip));
}

function chip(id) {
  const name = products.find((p) => p.id === id)?.name || id;
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = `${name} ×`;
  button.setAttribute('aria-label', TEXT[lang].remove(name));
  button.addEventListener('click', () => update({ picks: filter.picks.filter((p) => p !== id) }));
  return button;
}

function update(change) {
  filter = { ...filter, ...change };
  saveFilter();
  render();
}

$('product-pick').addEventListener('change', (event) => {
  const picked = products.find((p) => label(p) === event.target.value);
  event.target.value = '';
  if (picked && !filter.picks.includes(picked.id)) update({ picks: [...filter.picks, picked.id] });
});
$('lang').addEventListener('click', () => {
  lang = lang === 'ko' ? 'en' : 'ko';
  try {
    localStorage.setItem(SAVED_LANG, lang);
  } catch {
    // storage blocked: the choice lasts until reload
  }
  render();
});
$('view-normal').addEventListener('click', () => setDefaultView('normal'));
$('view-easy').addEventListener('click', () => setDefaultView('easy'));
$('search').addEventListener('input', (event) => update({ query: event.target.value }));
window.addEventListener('hashchange', () => {
  filter = loadFilter();
  $('search').value = filter.query;
  render();
});

const el = (tag, className, textContent = '') => Object.assign(document.createElement(tag), { className, textContent });
// The page follows `lang`; source text in another language carries its own lang for screen readers.
const para = (className, textContent, language = lang) => Object.assign(el('p', className, textContent), { lang: language });

function summary(s) {
  const parts = [para('summary', s.summary)];
  if (s.conditions.length) parts.push(para('conditions', `${TEXT[lang].conditions}: ${s.conditions.join(' · ')}`));
  if (s.mitigation) parts.push(para('mitigation', `${TEXT[lang].mitigation}: ${s.mitigation}`));
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
  const button = Object.assign(el('button', '', TEXT[lang].copy), { type: 'button' });
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

function easyAnswer(s) {
  const t = TEXT[lang];
  const action = easyAction(s);
  const parts = [para('easy', s[lang].easy || s[lang].summary)];
  if (action.kind === 'command') parts.push(para('action', t.command), commandLine(action.command));
  if (action.kind === 'version') parts.push(para('action', t.version(action.fixed)));
  if (action.kind === 'none') parts.push(para('action', t.none));
  if (action.kind === 'devices') {
    const list = el('ul', 'devices');
    list.append(...action.devices.map((d) => el('li', '', d)));
    parts.push(para('action', t.devices), list);
    if (action.fixed) parts.push(para('fixed', t.fixedIn(action.fixed)));
  }
  if (action.stopgap) parts.push(para('stopgap', t.stopgap), commandLine(action.stopgap));
  return parts;
}

// 위험도: the CVSS rating (and the exploited flag), or in the Easy view the rule-based Risk word.
function riskCell(incident) {
  const t = TEXT[lang];
  const cell = el('span', 'c-risk');
  if (defaultView === 'easy') {
    const level = riskLevel(incident);
    cell.append(el('span', `risk risk-${level}`, t[level]));
    return cell;
  }
  const rating = cvssRating(incident.cvss);
  cell.append(el('span', `sev sev-${rating}`, rating ? `${incident.cvss} ${t.rating[rating]}` : t.unrated));
  if (incident.kev) cell.append(el('span', 'kev', t.kevShort));
  return cell;
}

function titleCell(incident, pinned) {
  const t = TEXT[lang];
  const cell = el('span', 'c-title');
  if (pinned) cell.append(el('span', 'pin', t.pin), ' ');
  if (incident.summary) {
    cell.append(el('span', 'title', incident.summary[lang].title));
  } else {
    if (t.original) cell.append(el('span', 'orig', t.original), ' ');
    cell.append(Object.assign(el('span', 'title', incident.brief.text), { lang: 'en' }));
  }
  return cell;
}

function tagsCell(incident) {
  const cell = el('span', 'c-tags');
  cell.append(...rowTags(incident).map((name) => el('span', 'tag', name)));
  return cell;
}

function dateCell(incident) {
  const time = el('time', 'c-date', incident.first_seen.slice(0, 10));
  time.dateTime = incident.first_seen;
  time.title = incident.first_seen.replace('T', ' ').replace('Z', ' UTC');
  return time;
}

function details(incident) {
  const t = TEXT[lang];
  if (defaultView === 'easy') return [...(incident.summary ? easyAnswer(incident.summary) : briefNote(incident)), leadLine(incident)];
  const parts = incident.summary ? summary(incident.summary[lang]) : briefNote(incident);
  if (incident.kev) parts.push(para('kev', t.kev));
  const mentions = el('ul', 'mentions');
  for (const m of incident.mentions) {
    const item = el('li', '');
    item.append(`${t.mentions[m.kind] ?? m.kind}: `, anchor(m.url, m.title || host(m.url)));
    mentions.append(item);
  }
  return [...parts, leadLine(incident), mentions];
}

let rowCount = 0;

// One board row: a button with the five columns that opens the details below it, like opening a post.
function row(incident, pinned) {
  const li = el('li', pinned ? 'pinned' : '');
  const body = Object.assign(el('div', 'details'), { id: `details-${++rowCount}`, hidden: !open.has(incident.id) });
  const button = Object.assign(el('button', 'cols row'), { type: 'button' });
  button.setAttribute('aria-controls', body.id);
  button.setAttribute('aria-expanded', !body.hidden);
  button.append(riskCell(incident), el('span', 'c-cve', incident.cves.join(', ') || TEXT[lang].noCve), titleCell(incident, pinned), tagsCell(incident), dateCell(incident));
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
