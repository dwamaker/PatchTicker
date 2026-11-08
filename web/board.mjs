// The Board's filter: pure, so it runs the same in the browser and under `node --test`.
// first_seen is ISO-8601 UTC ("...Z"), so string order is time order.
// The filter in the page address: ?p=<product id>&p=...&q=<search>. Also the localStorage form.
// The whole filter lives in the address hash: p product/OS picks, q search, and the panel's r risk, k exploited,
// f/t published from/to (YYYY-MM-DD), c minimum CVSS, cv CVE yes/no, h link kinds, s sort.
const DAY = /^\d{4}-\d{2}-\d{2}$/;
export function filterFromQuery(search) {
  const params = new URLSearchParams(search);
  const day = (key) => (DAY.test(params.get(key) || '') ? params.get(key) : '');
  return {
    picks: params.getAll('p'), query: params.get('q') || '',
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
export function productsOf(i, lang = 'en') {
  const found = new Map((i.products || []).map((p) => [p.id, p]));
  const local = i.summary?.[lang]?.names || [];
  (i.summary?.products || []).forEach((name, k) => {
    const shown = local[k] || name;
    const same = [...found.values()].find((p) => name.toLowerCase().includes(p.name.toLowerCase()));
    if (same) found.set(same.id, { ...same, name: shown });
    else found.set(`name:${name.toLowerCase()}`, { id: `name:${name.toLowerCase()}`, name: shown });
  });
  for (const os of i.summary?.platforms || []) {
    found.delete(`name:${os.toLowerCase()}`); // "Android" as a product and as a platform is one entry
    found.set(`os:${os.toLowerCase()}`, { id: `os:${os.toLowerCase()}`, name: os });
  }
  return [...found.values()];
}

export function productList(incidents, now, lang = 'en') {
  const since = new Date(now - 90 * DAY_MS).toISOString();
  const found = new Map();
  for (const i of incidents) if (i.first_seen >= since) for (const p of productsOf(i, lang)) found.set(p.id, p);
  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

// Highlight score. Exploited in the wild (CISA KEV) outranks everything; then discussion (HN points,
// up to 50 at 500 points; a curator's newsletter, 25 each for up to two); CVSS (up to 20) and the
// number of Mentions order the rest.
// Highlights: up to ten are chosen, four are pinned at first so the newest list starts on the first screens of a
// phone (ten frames ran past 1,900px); 주목 더 보기 pins the rest. Unpinned ones stay in 최신순.
export const HIGHLIGHTS = 10;
export const PINNED = 4;

// Why a row is pinned, when the row does not already show it: exploited and CVSS 9+ are on the row itself.
export function pinReason(i) {
  if (i.kev || i.cvss >= 9) return null;
  if (i.mentions.some((m) => m.kind === 'curator')) return 'curator';
  if (Math.max(0, ...i.mentions.map((m) => m.points || 0)) >= HN_BUZZ) return 'buzz';
  return null;
}

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
export function filterBoard(incidents, picks = [], query = '', now = Date.now(),
  { risk = [], kev = false, from = '', to = '', cvssMin = 0, cve = '', has = [], sort = 'new' } = {}) {
  const picked = new Set(picks);
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const shown = incidents.filter((i) => {
    if (picked.size && !productsOf(i).some((p) => picked.has(p.id))) return false;
    if (risk.length && !risk.includes(riskLevel(i))) return false;
    if (kev && !i.kev) return false;
    const day = publishedAt(i).slice(0, 10); // UTC date; a visitor far from UTC may see a row one day off
    if ((from && day < from) || (to && day > to)) return false;
    if (cvssMin && !(i.cvss >= cvssMin)) return false;
    if ((cve === 'yes' && !i.cves.length) || (cve === 'no' && i.cves.length)) return false;
    if (has.some((kind) => !i.mentions.some((m) => m.kind === kind))) return false;
    // Mention titles carry the names people use ("sshole") that a Summary may not.
    const text = [i.brief.text, ...summaryText(i.summary), ...i.cves, ...productsOf(i).flatMap((p) => [p.name, p.id]),
      ...(i.mentions || []).map((m) => m.title || '')].join('\n').toLowerCase();
    return words.every((w) => text.includes(w));
  });
  const newest = (a, b) => (publishedAt(a) < publishedAt(b) ? 1 : publishedAt(a) > publishedAt(b) ? -1 : 0);
  const order = { risk: (a, b) => RISKS.indexOf(riskLevel(a)) - RISKS.indexOf(riskLevel(b)) || newest(a, b),
    cvss: (a, b) => (b.cvss ?? -1) - (a.cvss ?? -1) || newest(a, b) }[sort] || newest;
  const list = shown.sort(order);
  const since = new Date(now - 7 * DAY_MS).toISOString(); // seven days: also in collector/summaries.py (is_candidate)
  // A stable sort keeps newest first among equal scores.
  const highlights = list.filter((i) => i.first_seen >= since && !quietHnStory(i)).sort((a, b) => highlightScore(b) - highlightScore(a)).slice(0, HIGHLIGHTS);
  return { highlights, list };
}

// CVSS v3 qualitative rating, as a key the page words per language; null while NVD has not rated it.
export function cvssRating(cvss) {
  if (cvss == null) return null;
  return cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : cvss > 0 ? 'low' : 'none';
}

// An HN story with no CVE is on the Board only once its Summary calls it a real Incident (a flaw, attack or
// breach in something a reader runs); essays and anecdotes stay off. A story whose Summary failed for good
// is shown: never hide by mistake. Every other Incident is always shown.
export function onBoard(i) {
  if (i.cves.length || !i.id.startsWith('https://news.ycombinator.com/')) return true;
  if (i.summary) return i.summary.incident !== false;
  return Boolean(i.summary_error?.final);
}

// A command or stopgap a reader may paste into a terminal: it starts with a package manager or service tool.
// Anything else ("PasswordAuthentication no") is a line for a config file and must not look runnable.
const SHELL = /^(sudo\s+)?(apt|apt-get|apk|yum|dnf|zypper|pacman|opkg|brew|port|snap|flatpak|winget|choco|npm|npx|pnpm|yarn|pip3?|pipx|gem|cargo|go|composer|docker|podman|kubectl|helm|systemctl|service|rc-service|launchctl)\s/;
export const isShellCommand = (text) => SHELL.test(text.trim());

// The Easy sentence shouts only for the top Risk level: "!" everywhere teaches readers to ignore it.
export const easyLine = (text, level) => (level === 'highest' ? text : text.replace(/!+(\s*)$/, '.$1'));

// When the news first broke: the earliest source post time; Incidents stored before 11-08 only have first_seen.
export const publishedAt = (i) => i.published || i.first_seen;

// The row's name: the first CVE ID and how many more the Incident joins; null before any CVE exists.
export const cveHead = (cves = []) => (cves.length ? { id: cves[0], more: cves.length - 1 } : null);

// The row's 대상 column: the Summary's product names (vendor-led, "SonicWall SonicOS"), else the NVD Products'
// title-cased CPE names, then the Summary's devices; each name once.
// lang picks the Summary's names in that language ("Windows 그림판"); Summaries before 11-08 have none.
export const rowTags = (i, lang = 'en') => {
  const s = i.summary;
  const names = s?.[lang]?.names?.length ? s[lang].names : s?.products?.length ? s.products : (i.products || []).map((p) => p.name);
  return [...new Set([...names, ...(s?.platforms || []), ...(s?.devices || [])])];
};

// Line colours for Product badges, after the Seoul subway map: fill and the text colour that reads on it.
// No red, amber or grey hues, so a badge is never mistaken for a risk dot.
export const LINES = [
  { bg: '#0052a4', ink: '#ffffff' }, { bg: '#00a84d', ink: '#0d0f12' }, { bg: '#00a5de', ink: '#0d0f12' },
  { bg: '#7f4f9a', ink: '#ffffff' }, { bg: '#93a10c', ink: '#0d0f12' }, { bg: '#77c4a3', ink: '#0d0f12' },
  { bg: '#0c8e72', ink: '#0d0f12' }, { bg: '#b0ce18', ink: '#0d0f12' }, { bg: '#6789ca', ink: '#0d0f12' },
  { bg: '#2e3a8c', ink: '#ffffff' }, { bg: '#4a7c2a', ink: '#ffffff' },
];

// A Product's line: FNV-1a of its name picks the colour, so it is the same on every visit and every row.
export function productLine(name) {
  let h = 0x811c9dc5;
  for (const ch of name) h = Math.imul(h ^ ch.codePointAt(0), 0x01000193) >>> 0;
  return LINES[h % LINES.length];
}

// How long ago, as a value and unit for Intl.RelativeTimeFormat; null from 30 days on (the date is shown instead).
export function relativeAge(iso, now) {
  const minutes = Math.max(1, Math.floor((now - Date.parse(iso)) / 60000));
  if (minutes < 60) return { value: -minutes, unit: 'minute' };
  if (minutes < 24 * 60) return { value: -Math.floor(minutes / 60), unit: 'hour' };
  if (minutes < 30 * 24 * 60) return { value: -Math.floor(minutes / (24 * 60)), unit: 'day' };
  return null;
}
