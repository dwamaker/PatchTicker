import { filterBoard } from './board.mjs';

// The store's base URL. Locally the collector writes into web/data/; ticket 02 points this at R2.
const DATA_URL = 'data/';

const getJson = async (name) => {
  const res = await fetch(DATA_URL + name, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  return res.json();
};

async function main() {
  const board = document.getElementById('board');
  const status = document.getElementById('status');
  try {
    const [index, st] = await Promise.all([getJson('index.json'), getJson('status.json')]);
    const months = await Promise.all(index.months.slice(-3).map((m) => getJson(`months/${m}.json`)));
    const incidents = filterBoard(months.flatMap((m) => m.incidents));
    status.textContent = `Last updated ${st.updated} · ${incidents.length} incidents`;
    // CVE text is untrusted input, so it only ever goes in through textContent.
    board.replaceChildren(...incidents.map(row));
  } catch (err) {
    status.textContent = `Could not load the Board: ${err.message}`;
  }
}

const MENTION_LABEL = { advisory: 'Advisory', writeup: 'Write-up', cve_record: 'CVE record', discussion: 'Discussion', repo: 'Repository' };

// Source URLs are untrusted too: only http(s) ever becomes a link target.
function anchor(url, label) {
  const a = document.createElement('a');
  a.href = /^https?:\/\//i.test(url) ? url : '#';
  a.rel = 'noopener';
  a.textContent = label;
  return a;
}

const host = (url) => URL.canParse(url) ? new URL(url).host.replace(/^www\./, '') : url;

function row(incident) {
  const li = document.createElement('li');
  const head = document.createElement('div');
  const name = document.createElement('strong');
  name.textContent = incident.cves.join(', ') || 'No CVE yet';
  const time = document.createElement('time');
  time.dateTime = incident.first_seen;
  time.textContent = incident.first_seen.replace('T', ' ').replace('Z', ' UTC');
  head.append(name, ' ', time);
  const text = document.createElement('p');
  text.textContent = incident.brief.text;
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
  li.append(head, text, lead, mentions);
  return li;
}

main();
