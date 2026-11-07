// The Board's filter: pure, so it runs the same in the browser and under `node --test`.
// first_seen is ISO-8601 UTC ("...Z"), so string order is time order.
// The filter in the page address: ?p=<product id>&p=...&q=<search>. Also the localStorage form.
export function filterFromQuery(search) {
  const params = new URLSearchParams(search);
  return { picks: params.getAll('p'), query: params.get('q') || '' };
}

export function filterToQuery({ picks, query }) {
  const params = new URLSearchParams(picks.map((p) => ['p', p]));
  if (query) params.set('q', query);
  return params.toString();
}

const DAY_MS = 24 * 60 * 60 * 1000;

// The picker offers only Products seen in the last 90 days, so it is not cluttered with names that have no Incidents.
export function productList(incidents, now) {
  const since = new Date(now - 90 * DAY_MS).toISOString();
  const found = new Map();
  for (const i of incidents) if (i.first_seen >= since) for (const p of i.products || []) found.set(p.id, p);
  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

// Search: every word of the query must appear somewhere in the Incident's text, CVE IDs or Products.
export function filterBoard(incidents, picks = [], query = '') {
  const picked = new Set(picks);
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const shown = incidents.filter((i) => {
    if (picked.size && !(i.products || []).some((p) => picked.has(p.id))) return false;
    const text = [i.brief.text, ...i.cves, ...(i.products || []).flatMap((p) => [p.name, p.id])].join('\n').toLowerCase();
    return words.every((w) => text.includes(w));
  });
  return shown.sort((a, b) => (a.first_seen < b.first_seen ? 1 : a.first_seen > b.first_seen ? -1 : 0));
}
