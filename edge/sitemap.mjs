// The Incident sitemaps (spec: .scratch/incident-pages/spec.md; ADR 0002, 2026-11-10 revision). The static
// web/sitemap.xml indexes four of them, /sitemaps/incidents-<n>.xml: the search-worthy pages first seen n calendar
// months ago (UTC) and within the last 90 days, so 90 days fit and no index needs a deploy when the month turns. One
// month is ~8,000 Incidents, ~16,000 URLs in two languages, well under a sitemap's 50,000. The Pages Function renders
// them from the collector's sitemap.json ({pages: {slug: [first_seen, last change]}}) in R2.
import { SITE } from './feed.mjs';
import { SLUG } from './page.mjs';

const DOC = 'sitemap.json';
const PAGE_DAYS = 90; // also collector/cycle.py (PAGE_DAYS) and edge/page.mjs
const NAME = /^incidents-([0-3])\.xml$/;
const STAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/; // the collector's STAMP, a W3C datetime

function urls(slug, changed) {
  const ko = `${SITE}/i/${slug}`;
  const en = `${SITE}/en/i/${slug}`;
  const lastmod = STAMP.test(changed) ? `<lastmod>${changed}</lastmod>` : '';
  const alternates = `<xhtml:link rel="alternate" hreflang="ko" href="${ko}"/><xhtml:link rel="alternate" hreflang="en" href="${en}"/>`
    + `<xhtml:link rel="alternate" hreflang="x-default" href="${ko}"/>`;
  return [ko, en].map((loc) => `<url><loc>${loc}</loc>${lastmod}${alternates}</url>`);
}

export function sitemapXml(doc, monthsAgo, now) {
  const at = new Date(now);
  at.setUTCDate(1); // before stepping back a month, so the 31st never overflows into the next one
  at.setUTCMonth(at.getUTCMonth() - monthsAgo);
  const month = at.toISOString().slice(0, 7);
  const since = now - PAGE_DAYS * 24 * 60 * 60 * 1000;
  const entries = Object.entries(doc?.pages || {}).filter(([slug, pair]) => SLUG.test(slug) && Array.isArray(pair)
    && typeof pair[0] === 'string' && pair[0].startsWith(month) && Date.parse(pair[0]) >= since);
  return ['<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">',
    ...entries.flatMap(([slug, [, changed]]) => urls(slug, changed)),
    '</urlset>'].join('\n');
}

// bucket: the R2 binding (anything with get(key) -> { text() } or null). name: the file name after /sitemaps/.
export async function sitemapResponse(bucket, name, now = Date.now()) {
  const slot = NAME.exec(name);
  if (!slot) return new Response('Not found\n', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  let doc;
  try {
    const obj = await bucket.get(DOC);
    if (!obj) throw new Error(`${DOC} missing`);
    doc = JSON.parse(await obj.text());
  } catch {
    // Fail closed: a crawler retries later, never reads a half list as "these pages are gone".
    return new Response(`The sitemap is unavailable right now. ${SITE}/\n`, { status: 503, headers: { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '600' } });
  }
  return new Response(sitemapXml(doc, Number(slot[1]), now), { headers: { 'content-type': 'application/xml; charset=utf-8', 'cache-control': 'public, max-age=300' } });
}
