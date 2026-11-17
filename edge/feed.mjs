// The RSS feeds (spec: .scratch/incident-pages/spec.md; ADR 0002, 2026-11-10 revision). The Pages Function reads the
// collector's board/feed.json from R2 and renders RSS 2.0 per request. Titles, Summaries and links come from the web
// and a model: every text is escaped, and the only outside link is the Lead mention's, when it is http(s).
import { easyLine, langPrefix, riskLevel, rowTags, slug, WORDS } from '../web/board.mjs';
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
  ja: { title: WORDS.ja.title, about: '警戒以上、攻撃発生、CVE 未採番の新しいセキュリティインシデント（要約は英語）', act: '対処法', feed: '/ja/feed.xml', page: '/ja/i/',
    aboutProducts: '指定した製品のセキュリティインシデント（Patch Ticker の製品チェックと同じ基準で照合）', unmatched: '見つからなかった名前:',
    fixed: '修正バージョン', cves: (n) => `CVE ${n}件`, more: (n) => ` ほか${n}件` },
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
  return lang === 'ko' ? url : url.replace(`${SITE}/i/`, `${SITE}${langPrefix(lang)}/i/`);
}
// guid: the item's GUID, the link itself unless given (the whole-Board feed gives the page address).
function productItem(e, names, lang, guid = '') {
  const t = TEXT[lang];
  const w = WORDS[lang];
  const cves = Array.isArray(e.cves) ? e.cves.filter((c) => typeof c === 'string') : [];
  const count = Number.isInteger(e.cve_count) ? e.cve_count : cves.length;
  const lines = [[w.levels[e.level] || w.levels.notice, e.exploited === true ? w.kevReason : '', Number.isFinite(e.cvss) ? `CVSS ${e.cvss.toFixed(1)}` : ''].filter(Boolean).join(' · '),
    e.fixed ? `${t.fixed}: ${e.fixed}` : '',
    count ? `${t.cves(count)}: ${cves.join(', ')}${count > cves.length ? t.more(count - cves.length) : ''}` : ''];
  const link = escapeXml(itemLink(e, lang));
  return ['<item>', `<title>${escapeXml(e[`title_${lang}`] || e.title_en || e.id)}</title>`, `<link>${link}</link>`, `<guid isPermaLink="false">${guid || link}</guid>`,
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

// The whole-Board feed (owner, 11-17): /feed/all.xml and /en/feed/all.xml from board/feed-all.json, the newest Board
// Incidents of every level as light items (collector/checks.py feed_entry: no Summary text). Its link is where /api/check
// sends (the Incident page, else the Board row); its GUID is the Incident page's address, as /feed.xml's, so an Incident
// in both is one item to a reader of both, and it stays when the Incident gains its page.
const ALL_DOC = 'board/feed-all.json';
const ALL = {
  ko: { title: 'Patch Ticker · 현황판 전체', about: '현황판의 모든 새 보안 사건, 참고 수준까지 (요약 없이 가볍게)', feed: '/feed/all.xml' },
  en: { title: 'Patch Ticker · The whole Board', about: 'Every new security Incident on the Board, notice level included, as light items', feed: '/en/feed/all.xml' },
  ja: { title: 'Patch Ticker · ボード全体', about: 'ボードのすべての新しいセキュリティインシデント、参考レベルまで（要約なしの軽い項目）', feed: '/ja/feed/all.xml' },
};
export const allFeedResponse = (bucket, lang) => failClosed(async () => {
  const doc = await readJson(bucket, ALL_DOC);
  if (!doc || !Array.isArray(doc.incidents)) throw new Error(`${ALL_DOC} missing`);
  const entries = doc.incidents.filter((e) => e && typeof e.id === 'string');
  const items = await Promise.all(entries.map(async (e) => productItem(e, Array.isArray(e.tags?.[lang]) ? e.tags[lang].map(String) : [], lang,
    `${SITE}${TEXT[lang].page}${await slug(e.id)}`)));
  const at = (e) => e.published || e.first_seen;
  const xml = ['<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>',
    `<title>${escapeXml(ALL[lang].title)}</title>`,
    `<link>${SITE}/</link>`,
    `<description>${escapeXml(ALL[lang].about)}</description>`,
    `<language>${lang}</language>`,
    `<atom:link href="${SITE}${ALL[lang].feed}" rel="self" type="application/rss+xml"/>`,
    ...(entries.length ? [`<lastBuildDate>${rfc822(at(entries[0]))}</lastBuildDate>`] : []),
    ...items,
    '</channel></rss>'].join('\n');
  return new Response(xml, { headers: RSS_HEADERS });
}, () => unavailable('The RSS feed')); // a reader retries later, never gets a half feed

// bucket: the R2 binding (anything with get(key) -> { text() } or null).
export const feedResponse = (bucket, lang) => failClosed(async () => {
  const doc = await readJson(bucket, FEED_DOC);
  if (!doc) throw new Error(`${FEED_DOC} missing`);
  return new Response(await feedXml(doc, lang), {
    headers: { 'content-type': 'application/rss+xml; charset=utf-8', 'cache-control': 'public, max-age=300' },
  });
}, () => unavailable('The RSS feed')); // a reader retries later, never gets a half feed
