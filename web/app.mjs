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

function row(incident) {
  const li = document.createElement('li');
  const head = document.createElement('div');
  const link = document.createElement('a');
  link.href = incident.brief.lead;
  link.rel = 'noopener';
  link.textContent = incident.cves.join(', ') || incident.id;
  const time = document.createElement('time');
  time.dateTime = incident.first_seen;
  time.textContent = incident.first_seen.replace('T', ' ').replace('Z', ' UTC');
  head.append(link, ' ', time);
  const text = document.createElement('p');
  text.textContent = incident.brief.text;
  li.append(head, text);
  return li;
}

main();
