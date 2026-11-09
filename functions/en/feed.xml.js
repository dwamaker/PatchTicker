import { cached, feedResponse } from '../../edge/feed.mjs';

export const onRequestGet = (context) => cached(context, () => feedResponse(context.env.DATA, 'en'));
