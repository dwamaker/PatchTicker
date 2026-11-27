import { dayResponse } from '../../edge/lists.mjs';
import { cached } from '../../edge/shared.mjs';

export const onRequestGet = (context) => cached(context, () => dayResponse(context.env.DATA, 'ko', context.params.day));
export const onRequestHead = onRequestGet;
