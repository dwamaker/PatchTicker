// The home page for readers that run no script (search crawlers): the current static index.html with links to the
// latest Incident pages in place of its <!--home-links--> marker. The shell is never cached (a cached one could meet a
// newer app.mjs after a deploy); only the link list is, for 300 seconds.
import { slug } from '../web/board.mjs';
import { escapeXml, readJson, titleOf } from './shared.mjs';

const MARKER = '<!--home-links-->';
const LINKS_KEY = '/__home-links'; // the edge cache entry for the list; never a real path

export async function homeLinks(doc) {
  const items = (doc.incidents || []).slice(0, 20);
  if (!items.length) return '';
  const li = await Promise.all(items.map(async (i) => `<li><a href="/i/${await slug(i.id)}">${escapeXml(titleOf(i, 'ko'))}</a></li>`));
  return `<h2>최근 주요 보안 사건</h2><ul>${li.join('')}</ul>`;
}

// Fail open, the opposite of failClosed: the Board must open even when this list cannot be read.
async function links(context) {
  try {
    const cache = globalThis.caches?.default;
    const key = new Request(new URL(LINKS_KEY, context.request.url));
    const hit = cache && await cache.match(key);
    if (hit) return await hit.text();
    const doc = await readJson(context.env.DATA, 'board/feed.json');
    if (!doc) throw new Error('board/feed.json missing');
    const html = await homeLinks(doc);
    if (cache) context.waitUntil(cache.put(key, new Response(html, { headers: { 'cache-control': 'public, max-age=300' } })));
    return html;
  } catch {
    return '';
  }
}

export async function homeResponse(context) {
  // Unconditional, so the answer is always a full body to fill in, never a 304.
  const asset = await context.env.ASSETS.fetch(new Request(new URL('/', context.request.url)));
  if (asset.status !== 200) return asset;
  const list = await links(context);
  const body = (await asset.text()).replace(MARKER, () => list); // a function: "$&" or "$'" in a title stays text
  const headers = new Headers(asset.headers);
  headers.delete('etag'); // the body changed
  headers.delete('content-length');
  return new Response(context.request.method === 'HEAD' ? null : body, { status: 200, headers });
}
