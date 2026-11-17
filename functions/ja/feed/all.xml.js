import { allFeedResponse } from '../../../edge/feed.mjs';
import { cached } from '../../../edge/shared.mjs';

// The whole-Board feed (owner, 11-17): every level, light items, from board/feed-all.json.
export const onRequestGet = (context) => cached(context, () => allFeedResponse(context.env.DATA, 'ja'));
export const onRequestHead = onRequestGet;
