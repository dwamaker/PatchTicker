import { cached } from '../../edge/feed.mjs';
import { sitemapResponse } from '../../edge/sitemap.mjs';

export const onRequestGet = (context) => cached(context, () => sitemapResponse(context.env.DATA, context.params.name));
