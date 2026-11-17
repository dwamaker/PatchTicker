// The RSS feeds (spec: .scratch/incident-pages/spec.md; ADR 0002, 2026-11-10 revision). The Pages Function reads the
// collector's board/feed.json from R2 and renders RSS 2.0 per request. Titles, Summaries and links come from the web
// and a model: every text is escaped, and the only outside link is the Lead mention's, when it is http(s).
import { easyLine, riskLevel, rowTags, slug, WORDS } from '../web/board.mjs';
import { down, error, LEVELS, lookUp, MAX_DOCS, readQuery } from './check.mjs';
import { SITE, escapeXml, failClosed, host, http, readJson, titleOf, unavailable, whatToDo } from './shared.mjs';

const FEED_DOC = 'board/feed.json';

const TEXT = {
  ko: { title: WORDS.ko.title, about: '위험 이상, 공격 발생, CVE 없는 새 보안 사건', act: '대처법', feed: '/feed.xml', page: '/i/',
    aboutProducts: '고른 제품의 보안 사건 (Patch Ticker 제품 확인과 같은 기준)', unmatched: '찾지 못한 이름:', fixed: '고친 버전',
    cves: (n) => `CVE ${n}건`, more: (n) => ` 외 ${n}건` },
  en: { title: WORDS.en.title, about: 'New security Incidents: Elevated and up, attacked, or without a CVE yet', act: 'What to do', feed: '/en/feed.xml', page: '/en/i/',
    aboutProducts: 'Security Incidents of the products you named, matched as the Patch Ticker product check matches', unmatched: 'Names not found:',
    fixed: 'Fixed in', cves: (n) => `${n} CVE${n === 1 ? '' : 's'}`, more: (n) => ` and ${n} more` },
};

const rfc822 = (stamp) => new Date(stamp).toUTCString();

// The Lead mention's link, named as the Incident page names it, is the "source link below" a mitigation can point to (L4).
function leadLink(i, lang) {
  const lead = i.brief?.lead;
  const m = http(lead) && i.mentions?.find((x) => x.url === lead);
  if (!m) return '';
  const gloss = lang === 'ko' && (Array.isArray(i.summary?.titles_ko) ? i.summary.titles_ko : []).find((g) => g?.url === lead && typeof g.title === 'string')?.title;
  return `<p>${escapeXml(WORDS[lang].mentionKinds[m.kind] || m.kind)}: <a href="${escapeXml(lead)}">${escapeXml(gloss || m.title || host(lead))}</a></p>`;
}

async function item(i, lang) {
  const s = i.summary?.[lang] || {};
  // The plain explanation and what to do in the Incident page's words (easyLine, whatToDo), so the two never disagree.
  const body = [s.easy && easyLine(s.easy, riskLevel(i)), s.summary].filter(Boolean).map((t) => `<p>${escapeXml(t)}</p>`);
  const todo = i.summary ? whatToDo(i, lang) : '';
  if (todo) body.push(`<p><b>${TEXT[lang].act}</b></p>${todo}`);
  body.push(leadLink(i, lang));
  const page = `${SITE}${TEXT[lang].page}${await slug(i.id)}`; // slug() output is [A-Za-z0-9-] only: no escaping needed
  return ['<item>',
    `<title>${escapeXml(titleOf(i, lang))}</title>`,
    `<link>${page}</link>`,
    // The GUID has been the page address since ticket 01, so readers do not see items twice now that the link is too.
    `<guid isPermaLink="false">${page}</guid>`,
    `<pubDate>${rfc822(i.published || i.first_seen)}</pubDate>`,
    categories(rowTags(i, lang), WORDS[lang].levels[riskLevel(i)]),
    `<description>${escapeXml(body.join(''))}</description>`,
    '</item>'].join('');
}

// Owner, 11-17: a reader filters by category: the products as the row shows them, then the level in the feed's language.
export const categories = (names, level) => [...names, level].map((c) => `<category>${escapeXml(c)}</category>`).join('');

export async function feedXml(doc, lang) {
  const t = TEXT[lang];
  const incidents = doc.incidents || [];
  const built = incidents.length ? rfc822(incidents[0].published || incidents[0].first_seen) : new Date(0).toUTCString();
  const items = await Promise.all(incidents.map((i) => item(i, lang)));
  return ['<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>',
    `<title>${escapeXml(t.title)}</title>`,
    `<link>${SITE}/</link>`,
    `<description>${escapeXml(t.about)}</description>`,
    `<language>${lang}</language>`,
    `<atom:link href="${SITE}${t.feed}" rel="self" type="application/rss+xml"/>`,
    `<lastBuildDate>${built}</lastBuildDate>`,
    ...items,
    '</channel></rss>'].join('\n');
}

// The products feed (owner, 11-17): /feed.xml?products=<names> and /en/feed.xml?products=<names>, the same query as
// /api/check (products, days, min; edge/check.mjs readQuery) matched the same way without the model, from the check
// documents alone (no Summary there, and no page document is read per request). Like the API it is never kept in the
// edge cache, so asked names are stored nowhere; a reader may keep it 5 minutes.
const MAX_ITEMS = 100;
const RSS_HEADERS = { 'content-type': 'application/rss+xml; charset=utf-8', 'cache-control': 'public, max-age=300' };
// A check document's address is the site's own page or Board row; anything else (it never should be) becomes the row.
function itemLink(e, lang) {
  const url = typeof e.url === 'string' && e.url.startsWith(`${SITE}/`) ? e.url : `${SITE}/#i=${encodeURIComponent(String(e.id))}`;
  return lang === 'en' ? url.replace(`${SITE}/i/`, `${SITE}/en/i/`) : url;
}
function productItem(e, names, lang) {
  const t = TEXT[lang];
  const w = WORDS[lang];
  const cves = Array.isArray(e.cves) ? e.cves.filter((c) => typeof c === 'string') : [];
  const count = Number.isInteger(e.cve_count) ? e.cve_count : cves.length;
  const lines = [[w.levels[e.level] || w.levels.notice, e.exploited === true ? w.kevReason : '', Number.isFinite(e.cvss) ? `CVSS ${e.cvss.toFixed(1)}` : ''].filter(Boolean).join(' · '),
    e.fixed ? `${t.fixed}: ${e.fixed}` : '',
    count ? `${t.cves(count)}: ${cves.join(', ')}${count > cves.length ? t.more(count - cves.length) : ''}` : ''];
  const link = escapeXml(itemLink(e, lang));
  return ['<item>', `<title>${escapeXml(e[`title_${lang}`] || e.id)}</title>`, `<link>${link}</link>`, `<guid isPermaLink="false">${link}</guid>`,
    `<pubDate>${rfc822(e.published || e.first_seen)}</pubDate>`, categories(names, w.levels[e.level] || w.levels.notice),
    `<description>${escapeXml(lines.filter(Boolean).map((l) => `<p>${escapeXml(l)}</p>`).join(''))}</description>`, '</item>'].join('');
}

// request: the incoming Request (GET or HEAD); now: for `days`.
export async function productFeedResponse(bucket, request, lang, now = Date.now()) {
  const t = TEXT[lang];
  const params = new URL(request.url).searchParams;
  const query = readQuery(params);
  let res;
  if (query.error) res = error(query.error);
  else {
    try {
      const index = await readJson(bucket, 'check/index.json');
      if (!index) throw new Error('check/index.json missing');
      const since = new Date(now - query.days * 86400000).toISOString().replace('.000', '');
      const least = LEVELS.indexOf(query.min);
      const matches = lookUp(index, query.names);
      const slugs = [...new Set(matches.flatMap((m) => m?.slugs || []))].slice(0, MAX_DOCS);
      const docs = (await Promise.all(slugs.map((s) => readJson(bucket, `check/p/${s}.json`)))).filter(Boolean);
      const items = new Map(); // id -> { entry, names }
      for (const doc of docs) {
        for (const e of doc.incidents || []) {
          if (!(e.first_seen >= since) || LEVELS.indexOf(e.level) < least) continue;
          const seen = items.get(e.id) || items.set(e.id, { entry: e, names: [] }).get(e.id);
          seen.names.push(String(doc.product));
        }
      }
      const at = (e) => e.published || e.first_seen;
      const shown = [...items.values()].sort((a, b) => (at(a.entry) < at(b.entry) ? 1 : at(a.entry) > at(b.entry) ? -1 : 0)).slice(0, MAX_ITEMS);
      const missed = query.names.filter((_, n) => !matches[n]);
      const named = [...new Set(docs.map((d) => String(d.product)))];
      const self = `${SITE}${t.feed}?${new URLSearchParams([...params].filter(([k]) => ['products', 'days', 'min'].includes(k)))}`;
      const xml = ['<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>',
        `<title>${escapeXml(`Patch Ticker · ${named.join(', ') || query.names.join(', ')}`)}</title>`,
        `<link>${SITE}/</link>`,
        `<description>${escapeXml([t.aboutProducts, missed.length ? `${t.unmatched} ${missed.join(', ')}` : ''].filter(Boolean).join('. '))}</description>`,
        `<language>${lang}</language>`,
        `<atom:link href="${escapeXml(self)}" rel="self" type="application/rss+xml"/>`,
        ...(shown.length ? [`<lastBuildDate>${rfc822(at(shown[0].entry))}</lastBuildDate>`] : []),
        ...shown.map(({ entry, names }) => productItem(entry, names, lang)),
        '</channel></rss>'].join('\n');
      res = new Response(xml, { headers: RSS_HEADERS });
    } catch {
      res = down();
    }
  }
  return request.method === 'HEAD' ? new Response(null, res) : res;
}

// bucket: the R2 binding (anything with get(key) -> { text() } or null).
export const feedResponse = (bucket, lang) => failClosed(async () => {
  const doc = await readJson(bucket, FEED_DOC);
  if (!doc) throw new Error(`${FEED_DOC} missing`);
  return new Response(await feedXml(doc, lang), {
    headers: { 'content-type': 'application/rss+xml; charset=utf-8', 'cache-control': 'public, max-age=300' },
  });
}, () => unavailable('The RSS feed')); // a reader retries later, never gets a half feed
