// The RSS feeds (spec: .scratch/incident-pages/spec.md; ADR 0002, 2026-11-10 revision). The Pages Function reads the
// collector's board/feed.json from R2 and renders RSS 2.0 per request. Titles, Summaries and links come from the web
// and a model: every text is escaped, and the only links are our own.

export const SITE = 'https://patchticker.com';
const FEED_DOC = 'board/feed.json';

const TEXT = {
  ko: { title: 'Patch Ticker · 보안 취약점 게시판', about: '위험 이상, 실제 악용, CVE 없는 새 보안 사건', act: '대처법', feed: '/feed.xml', page: '/i/' },
  en: { title: 'Patch Ticker · vulnerability board', about: 'New security Incidents: high risk, exploited, or without a CVE yet', act: 'What to do', feed: '/en/feed.xml', page: '/en/i/' },
};

export const escapeXml = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
const HN_ITEM = /^https:\/\/news\.ycombinator\.com\/item\?id=(\d+)$/;

// An Incident page's address part: a CVE ID as is, an HN story as hn-<item>, any other URL ID as u-<12 hex of SHA-256>.
// It never changes, because an Incident's ID never does (a merge keeps the survivor's ID).
export async function slug(id) {
  if (CVE_ID.test(id)) return id.toUpperCase();
  const hn = HN_ITEM.exec(id);
  if (hn) return `hn-${hn[1]}`;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(id)));
  return `u-${[...digest.slice(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

export const titleOf = (i, lang) => i.summary?.[lang]?.title || i.quick_title?.[lang]?.title || i.brief?.text || i.id;
const rfc822 = (stamp) => new Date(stamp).toUTCString();

async function item(i, lang) {
  const s = i.summary?.[lang] || {};
  const body = [s.easy, s.summary].filter(Boolean).map((t) => `<p>${escapeXml(t)}</p>`);
  if (s.mitigation) body.push(`<p><b>${TEXT[lang].act}:</b> ${escapeXml(s.mitigation)}</p>`);
  return ['<item>',
    `<title>${escapeXml(titleOf(i, lang))}</title>`,
    // shortcut: the Board link until Incident pages exist (ticket 03 points it at the page); the GUID is already the page.
    `<link>${SITE}/#i=${encodeURIComponent(i.id)}</link>`,
    `<guid isPermaLink="false">${SITE}${TEXT[lang].page}${await slug(i.id)}</guid>`,
    `<pubDate>${rfc822(i.published || i.first_seen)}</pubDate>`,
    `<description>${escapeXml(body.join(''))}</description>`,
    '</item>'].join('');
}

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

// bucket: the R2 binding (anything with get(key) -> { text() } or null).
export async function feedResponse(bucket, lang) {
  let doc;
  try {
    const obj = await bucket.get(FEED_DOC);
    if (!obj) throw new Error(`${FEED_DOC} missing`);
    doc = JSON.parse(await obj.text());
  } catch {
    // Fail closed: a reader retries later, never gets a half feed.
    return new Response(`The feed is unavailable right now. ${SITE}/\n`, { status: 503, headers: { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '600' } });
  }
  return new Response(await feedXml(doc, lang), {
    headers: { 'content-type': 'application/rss+xml; charset=utf-8', 'cache-control': 'public, max-age=300' },
  });
}

// The edge cache in front of a renderer, so a burst of requests reads R2 once per cache time.
export async function cached(context, render) {
  const cache = globalThis.caches?.default;
  const hit = cache && await cache.match(context.request);
  if (hit) return hit;
  const res = await render();
  if (cache && res.ok) context.waitUntil(cache.put(context.request, res.clone()));
  return res;
}
