import { feedResponse } from '../edge/feed.mjs';
import { cached } from '../edge/shared.mjs';

export const onRequestGet = (context) => cached(context, () => feedResponse(context.env.DATA, 'ko'));
