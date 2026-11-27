import { daysResponse } from '../../../edge/lists.mjs';
import { cached } from '../../../edge/shared.mjs';

export const onRequestGet = (context) => cached(context, () => daysResponse(context.env.DATA, 'en'));
export const onRequestHead = onRequestGet;
