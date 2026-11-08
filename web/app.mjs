import { easyAction, filterBoard, filterFromQuery, filterToQuery, productList, riskLevel } from './board.mjs';

// The store's base URL. Locally the collector writes into web/data/; ticket 02 points this at R2.
const DATA_URL = 'data/';
const SAVED = 'vr-filter';
const SAVED_LANG = 'vr-lang';
const SAVED_EASY = 'vr-easy';
// The Summary's language: the visitor's toggle, else the browser's language.
const TEXT = {
  ko: {
    other: 'English', preparing: '요약 준비 중', conditions: '해당 조건', mitigation: '대처법',
    normal: '기본', easy: '쉬운 설명', highest: '고위험!', high: '위험', notice: '참고',
    command: '이 명령으로 업데이트하세요:', devices: '이 기기들을 지금 업데이트하세요!', version: (v) => `${v} 버전으로 업데이트하세요.`,
    fixedIn: (v) => `${v} 버전에서 고쳐졌습니다.`, none: '아직 나온 대처법이 없습니다. 아래 링크를 확인하세요.', stopgap: '당장 못 하면:', copy: '복사', copied: '복사됨',
    paused: 'AI 요약이 잠시 멈췄습니다. 새 사건은 속보로만 보입니다.',
  },
  en: {
    other: '한국어', preparing: 'Summary in preparation', conditions: 'Affected when', mitigation: 'Mitigation',
    normal: 'Normal', easy: 'Easy', highest: 'High risk!', high: 'Risk', notice: 'Notice',
    command: 'Run this to update:', devices: 'Update these devices now!', version: (v) => `Update to version ${v}.`,
    fixedIn: (v) => `Fixed in version ${v}.`, none: 'No fix is out yet. Check the link below.', stopgap: 'Can\'t update yet?', copy: 'Copy', copied: 'Copied',
    paused: 'Summaries are paused for now; new Incidents show their Brief only.',
  },
};
let lang = loadLang();
// Incidents the visitor switched to the Easy view; every other Incident opens in the normal view.
let easyIds = loadEasy();

function loadEasy() {
  try {
    return new Set(JSON.parse(localStorage.getItem(SAVED_EASY) || '[]'));
  } catch {
    return new Set(); // storage blocked or unreadable: normal view everywhere
  }
}

function setView(id, easy) {
  easyIds.delete(id);
  if (easy) easyIds.add(id);
  try {
    // shortcut: the newest 200 choices are kept; upgrade if visitors keep more Incidents in the Easy view.
    localStorage.setItem(SAVED_EASY, JSON.stringify([...easyIds].slice(-200)));
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
    render();
  } catch (err) {
    $('status').textContent = `Could not load the Board: ${err.message}`;
  }
}

const MENTION_LABEL = { advisory: 'Advisory', writeup: 'Write-up', cve_record: 'CVE record', discussion: 'Discussion', curator: 'Newsletter', repo: 'Repository' };

// CVSS v3 qualitative ratings.
function severity(cvss) {
  if (cvss == null) return 'Severity not rated yet';
  const rating = cvss >= 9 ? 'Critical' : cvss >= 7 ? 'High' : cvss >= 4 ? 'Medium' : cvss > 0 ? 'Low' : 'None';
  return `CVSS ${cvss} ${rating}`;
}

// Source URLs are untrusted too: only http(s) ever becomes a link target.
function anchor(url, label) {
  const a = document.createElement('a');
  a.href = /^https?:\/\//i.test(url) ? url : '#';
  a.rel = 'noopener';
  a.textContent = label;
  return a;
}

const host = (url) => URL.canParse(url) ? new URL(url).host.replace(/^www\./, '') : url;

const label = (p) => `${p.name} (${p.id.split(':')[0]})`;

function render() {
  const { highlights, list } = filterBoard(incidents, filter.picks, filter.query, Date.now());
  $('status').textContent = `Last updated ${updated} · ${list.length} of ${incidents.length} incidents`
    + (paused ? ` · ${TEXT[lang].paused}` : '');
  // CVE text is untrusted input, so it only ever goes in through textContent.
  $('highlights').replaceChildren(...highlights.map(row));
  $('highlights-section').hidden = !highlights.length;
  $('board').replaceChildren(...list.map(row));
  $('picks').replaceChildren(...filter.picks.map(chip));
  $('lang').textContent = TEXT[lang].other;
  $('lang').lang = lang === 'ko' ? 'en' : 'ko';
}

function chip(id) {
  const name = products.find((p) => p.id === id)?.name || id;
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = `${name} ×`;
  button.setAttribute('aria-label', `Remove ${name}`);
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
$('search').addEventListener('input', (event) => update({ query: event.target.value }));
window.addEventListener('hashchange', () => {
  filter = loadFilter();
  $('search').value = filter.query;
  render();
});

// The rest of the page is English, so each Summary line carries its own language for screen readers.
const para = (className, textContent, language = lang) => Object.assign(document.createElement('p'), { className, textContent, lang: language });

function summary(s) {
  const parts = [para('title', s.title), para('summary', s.summary)];
  if (s.conditions.length) parts.push(para('conditions', `${TEXT[lang].conditions}: ${s.conditions.join(' · ')}`));
  if (s.mitigation) parts.push(para('mitigation', `${TEXT[lang].mitigation}: ${s.mitigation}`));
  return parts;
}

// A Brief is the source's own one line (English) until the Summary arrives.
function brief(b) {
  return [para('brief', b.text, 'en'), para('preparing', TEXT[lang].preparing)];
}

function tabs(incident, easy) {
  const bar = Object.assign(document.createElement('div'), { className: 'tabs' });
  for (const [view, on] of [['normal', !easy], ['easy', easy]]) {
    const button = Object.assign(document.createElement('button'), { type: 'button', textContent: TEXT[lang][view], lang });
    button.setAttribute('aria-pressed', on);
    button.addEventListener('click', () => setView(incident.id, view === 'easy'));
    bar.append(button);
  }
  return bar;
}

// A command from a source, shown as is, with a button that copies exactly the text shown.
function commandLine(text) {
  const p = Object.assign(document.createElement('p'), { className: 'command' });
  const code = Object.assign(document.createElement('code'), { textContent: text });
  const button = Object.assign(document.createElement('button'), { type: 'button', textContent: TEXT[lang].copy, lang });
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
    const list = Object.assign(document.createElement('ul'), { className: 'devices' });
    list.append(...action.devices.map((d) => Object.assign(document.createElement('li'), { textContent: d })));
    parts.push(para('action', t.devices), list);
    if (action.fixed) parts.push(para('fixed', t.fixedIn(action.fixed)));
  }
  if (action.stopgap) parts.push(para('stopgap', t.stopgap), commandLine(action.stopgap));
  return parts;
}

// The Easy view: a Risk banner in place of the CVE ID, plain words and the one action to take now.
function easyRow(li, incident) {
  const level = riskLevel(incident);
  li.append(Object.assign(document.createElement('p'), { className: `risk risk-${level}`, textContent: TEXT[lang][level], lang }));
  li.append(...(incident.summary ? easyAnswer(incident.summary) : brief(incident.brief)));
  const lead = document.createElement('p');
  lead.className = 'lead';
  const leadUrl = incident.summary?.lead || incident.brief.lead;
  lead.append(anchor(leadUrl, `Read at ${host(leadUrl)} →`));
  li.append(lead);
  return li;
}

function row(incident) {
  const li = document.createElement('li');
  const easy = easyIds.has(incident.id);
  li.append(tabs(incident, easy));
  if (easy) return easyRow(li, incident);
  const head = document.createElement('div');
  const name = document.createElement('strong');
  name.textContent = incident.cves.join(', ') || 'No CVE yet';
  const time = document.createElement('time');
  time.dateTime = incident.first_seen;
  time.textContent = incident.first_seen.replace('T', ' ').replace('Z', ' UTC');
  head.append(name, ' ', time);
  head.append(' ', Object.assign(document.createElement('span'), { className: 'cvss', textContent: severity(incident.cvss) }));
  if (incident.kev) head.append(' ', Object.assign(document.createElement('span'), { className: 'kev', textContent: 'Exploited in the wild (CISA KEV)' }));
  li.append(head, ...(incident.summary ? summary(incident.summary[lang]) : brief(incident.brief)));
  if (incident.products?.length) {
    li.append(Object.assign(document.createElement('p'), { className: 'products', textContent: incident.products.map((p) => p.name).join(' · ') }));
  }
  const lead = document.createElement('p');
  lead.className = 'lead';
  const leadUrl = incident.summary?.lead || incident.brief.lead;
  lead.append(anchor(leadUrl, `Read at ${host(leadUrl)} →`));
  const mentions = document.createElement('ul');
  mentions.className = 'mentions';
  for (const m of incident.mentions) {
    const item = document.createElement('li');
    item.append(`${MENTION_LABEL[m.kind] ?? m.kind}: `, anchor(m.url, m.title || host(m.url)));
    mentions.append(item);
  }
  li.append(lead, mentions);
  return li;
}

main();
