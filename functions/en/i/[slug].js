import { cached } from '../../../edge/feed.mjs';
import { pageResponse } from '../../../edge/page.mjs';

export const onRequestGet = (context) => cached(context, () => pageResponse(context.env.DATA, 'en', context.params.slug));
