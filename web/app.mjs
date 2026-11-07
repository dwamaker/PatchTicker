import { filterBoard, filterFromQuery, filterToQuery, productList } from './board.mjs';

// The store's base URL. Locally the collector writes into web/data/; ticket 02 points this at R2.
const DATA_URL = 'data/';
const SAVED = 'vr-filter';

const getJson = async (name) => {
  const res = await fetch(DATA_URL + name, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  return res.json();
};

const $ = (id) => document.getElementById(id);
let incidents = [];
let products = [];
let updated = '';
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
  $('status').textContent = `Last updated ${updated} · ${list.length} of ${incidents.length} incidents`;
  // CVE text is untrusted input, so it only ever goes in through textContent.
  $('highlights').replaceChildren(...highlights.map(row));
  $('highlights-section').hidden = !highlights.length;
  $('board').replaceChildren(...list.map(row));
  $('picks').replaceChildren(...filter.picks.map(chip));
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
$('search').addEventListener('input', (event) => update({ query: event.target.value }));
window.addEventListener('hashchange', () => {
  filter = loadFilter();
  $('search').value = filter.query;
  render();
});

function row(incident) {
  const li = document.createElement('li');
  const head = document.createElement('div');
  const name = document.createElement('strong');
  name.textContent = incident.cves.join(', ') || 'No CVE yet';
  const time = document.createElement('time');
  time.dateTime = incident.first_seen;
  time.textContent = incident.first_seen.replace('T', ' ').replace('Z', ' UTC');
  head.append(name, ' ', time);
  head.append(' ', Object.assign(document.createElement('span'), { className: 'cvss', textContent: severity(incident.cvss) }));
  if (incident.kev) head.append(' ', Object.assign(document.createElement('span'), { className: 'kev', textContent: 'Exploited in the wild (CISA KEV)' }));
  const text = document.createElement('p');
  text.textContent = incident.brief.text;
  li.append(head, text);
  if (incident.products?.length) {
    li.append(Object.assign(document.createElement('p'), { className: 'products', textContent: incident.products.map((p) => p.name).join(' · ') }));
  }
  const lead = document.createElement('p');
  lead.className = 'lead';
  lead.append(anchor(incident.brief.lead, `Read at ${host(incident.brief.lead)} →`));
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
