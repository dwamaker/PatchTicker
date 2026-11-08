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

// Highlight score. Exploited in the wild (CISA KEV) outranks everything; then discussion (HN points,
// up to 50 at 500 points; a curator's newsletter, 25 each for up to two); CVSS (up to 20) and the
// number of Mentions order the rest.
export function highlightScore(i) {
  const points = Math.max(0, ...i.mentions.map((m) => m.points || 0));
  const curated = i.mentions.filter((m) => m.kind === 'curator').length;
  return (i.kev ? 100 : 0) + Math.min(points / 10, 50) + 25 * Math.min(curated, 2) + 2 * (i.cvss || 0) + i.mentions.length;
}

// A story seen only on HN (no CVE, no other discussion or curator pick) is a Highlight only from this
// many points, or general security news fills the pinned area. Also in collector/hn.py (BUZZ_POINTS).
const HN_BUZZ = 100;
const isHn = (url) => url.startsWith('https://news.ycombinator.com/');
const quietHnStory = (i) => !i.cves.length && i.mentions.every((m) => !['discussion', 'curator'].includes(m.kind) || isHn(m.url))
  && Math.max(0, ...i.mentions.map((m) => m.points || 0)) < HN_BUZZ;

// The Summary's text in both languages, Easy view included, so either language finds the Incident.
// Summaries written before the Easy view have no easy, command or stopgap.
const summaryText = (s) => (s ? [...['ko', 'en'].flatMap((l) => [s[l].title, s[l].summary, ...s[l].conditions, s[l].mitigation, s[l].easy || '']),
  ...s.products, s.command || '', s.stopgap || '', ...(s.devices || [])] : []);

// The note under a Brief: a Summary is coming, or the collector gave up after its last rejected try.
export const briefMarker = (i) => (i.summary_error?.final ? 'unavailable' : 'preparing');

// The saved default view; anything else (nothing saved, the old per-Incident list) is the normal view.
export const viewFromStorage = (saved) => (saved === 'easy' ? 'easy' : 'normal');

// The Easy view's Risk banner, set by rules and never by the model.
// The 9.0 cutoff is also in collector/summaries.py (is_candidate).
export function riskLevel(i) {
  if (i.kev || i.cvss >= 9) return 'highest';
  return i.cvss >= 7 ? 'high' : 'notice';
}

// The Easy view's one action: update these devices, run the source's command, or update to the fixed version.
export function easyAction(s) {
  const stopgap = s.stopgap || '';
  if (s.devices?.length) return { kind: 'devices', devices: s.devices, fixed: s.fixed, stopgap };
  if (s.command) return { kind: 'command', command: s.command, stopgap };
  if (s.fixed) return { kind: 'version', fixed: s.fixed, stopgap };
  return { kind: 'none', stopgap };
}

// Search: every word of the query must appear somewhere in the Incident's text, Summary, CVE IDs or Products.
// Returns the visible Incidents newest first, and the top ten of those first seen in the seven days before `now`.
export function filterBoard(incidents, picks = [], query = '', now = Date.now()) {
  const picked = new Set(picks);
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const shown = incidents.filter((i) => {
    if (picked.size && !(i.products || []).some((p) => picked.has(p.id))) return false;
    const text = [i.brief.text, ...summaryText(i.summary), ...i.cves, ...(i.products || []).flatMap((p) => [p.name, p.id])].join('\n').toLowerCase();
    return words.every((w) => text.includes(w));
  });
  const list = shown.sort((a, b) => (a.first_seen < b.first_seen ? 1 : a.first_seen > b.first_seen ? -1 : 0));
  const since = new Date(now - 7 * DAY_MS).toISOString(); // seven days: also in collector/summaries.py (is_candidate)
  // A stable sort keeps newest first among equal scores.
  const highlights = list.filter((i) => i.first_seen >= since && !quietHnStory(i)).sort((a, b) => highlightScore(b) - highlightScore(a)).slice(0, 10);
  return { highlights, list };
}
