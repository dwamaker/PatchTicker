// The Incident sitemaps (spec: .scratch/incident-pages/spec.md; ADR 0002, 2026-11-10 revision). The static
// web/sitemap.xml indexes four of them, /sitemaps/incidents-<n>.xml: the search-worthy pages first seen n calendar
// months ago (UTC) and within PAGE_DAYS, so 90 days fit and no index needs a deploy when the month turns. Each page is
// listed in the search languages (SEARCH_LANGS: Korean and English), well under a sitemap's 50,000. The Pages Function renders
// them from the collector's sitemap.json ({pages: {slug: {first_seen, changed}}}) in R2.
import { PAGE_KEEP_DAYS, langPrefix, withinKeepDays } from '../web/board.mjs';
import { SEARCH_LANGS, SITE, SLUG, failClosed, readJson, unavailable } from './shared.mjs';

const DOC = 'sitemap.json';
const MAX_PAGES = Math.floor(50000 / SEARCH_LANGS.length); // one URL per search language each: one sitemap file holds at most 50,000
// P4 (owner 11-28, Gemini review): a listed page stays PAGE_KEEP_DAYS, so 13 monthly files, n months ago, from the collector's
// sitemaps/<YYYY-MM>.json (collector/cycle.py write_sitemap_months); sitemap.json's pages when a month has none yet.
const MONTHS = Math.ceil(PAGE_KEEP_DAYS / 30); // 365 days back reach at most 12 calendar months back: 13 files
const NAME = /^(?:incidents-(0|[1-9]\d?)|(products))\.xml$/; // no incidents-05.xml twin
const PRODUCT = /^[0-9a-f]{16}$/; // collector/checks.py check_slug
const STAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/; // the collector's STAMP, a W3C datetime

function urls(slug, changed, kind = 'i') {
  const locs = SEARCH_LANGS.map((l) => `${SITE}${langPrefix(l)}/${kind}/${slug}`);
  const lastmod = STAMP.test(changed) ? `<lastmod>${changed}</lastmod>` : '';
  const alternates = SEARCH_LANGS.map((l, n) => `<xhtml:link rel="alternate" hreflang="${l}" href="${locs[n]}"/>`).join('')
    + `<xhtml:link rel="alternate" hreflang="x-default" href="${locs[0]}"/>`;
  return locs.map((loc) => `<url><loc>${loc}</loc>${lastmod}${alternates}</url>`);
}

export const monthOf = (monthsAgo, now) => {
  const at = new Date(now);
  at.setUTCDate(1); // before stepping back a month, so the 31st never overflows into the next one
  at.setUTCMonth(at.getUTCMonth() - monthsAgo);
  return at.toISOString().slice(0, 7);
};

// pages: {slug: {first_seen, changed}}: the month's document, or sitemap.json's pages.
export function sitemapXml(pages, monthsAgo, now) {
  const month = monthOf(monthsAgo, now);
  if (!pages || typeof pages !== 'object' || Array.isArray(pages)) throw new Error('no pages'); // never "all gone"
  const entries = Object.entries(pages).filter(([slug, page]) => SLUG.test(slug) && typeof page?.first_seen === 'string'
    && page.first_seen.startsWith(month) && withinKeepDays(page.first_seen, now))
    .sort(([, a], [, b]) => (a.first_seen < b.first_seen ? 1 : a.first_seen > b.first_seen ? -1 : 0))
    // shortcut: a month over MAX_PAGES loses its oldest pages from the sitemap; split the month into two files if a
    // month ever comes near it (~8,000 pages a month today).
    .slice(0, MAX_PAGES);
  return ['<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">',
    ...entries.flatMap(([slug, page]) => urls(slug, page.changed)),
    '</urlset>'].join('\n');
}

// Owner, 11-17: the product pages (/p/<slug>, edge/product.mjs) the collector lists as worth a search (sitemap.json
// products: enough Incidents, collector/checks.py product_pages); a document from before that list gives none.
export function productsXml(doc) {
  const list = Array.isArray(doc?.products) ? doc.products.filter((s) => typeof s === 'string' && PRODUCT.test(s)) : [];
  return ['<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">',
    ...list.slice(0, MAX_PAGES).flatMap((slug) => urls(slug, null, 'p')),
    '</urlset>'].join('\n');
}

// bucket: the R2 binding (anything with get(key) -> { text() } or null). name: the file name after /sitemaps/.
export async function sitemapResponse(bucket, name, now = Date.now()) {
  const slot = NAME.exec(name);
  if (!slot || (slot[1] && Number(slot[1]) >= MONTHS)) return new Response('Not found\n', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=60' } });
  return failClosed(async () => {
    const month = slot[1] && await readJson(bucket, `sitemaps/${monthOf(Number(slot[1]), now)}.json`);
    const doc = month ? null : await readJson(bucket, DOC);
    if (!month && !doc) throw new Error(`${DOC} missing`);
    return new Response(slot[2] ? productsXml(doc) : sitemapXml(month || doc.pages, Number(slot[1]), now), { headers: { 'content-type': 'application/xml; charset=utf-8', 'cache-control': 'public, max-age=300' } });
  }, () => unavailable('The sitemap')); // a crawler retries later, never reads a half list as "these pages are gone"
}
