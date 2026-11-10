import { cached } from '../../edge/shared.mjs';
import { sitemapResponse } from '../../edge/sitemap.mjs';

export const onRequestGet = (context) => cached(context, () => sitemapResponse(context.env.DATA, context.params.name));
export const onRequestHead = onRequestGet;
