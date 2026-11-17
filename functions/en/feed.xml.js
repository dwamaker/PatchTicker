import { feedResponse, productFeedResponse } from '../../edge/feed.mjs';
import { cached } from '../../edge/shared.mjs';

// ?products=<names>: the products feed, like /api/check never kept in the edge cache (asked names are stored nowhere).
export const onRequestGet = (context) => (new URL(context.request.url).searchParams.has('products')
  ? productFeedResponse(context.env.DATA, context.request, 'en')
  : cached(context, () => feedResponse(context.env.DATA, 'en')));
export const onRequestHead = onRequestGet;
