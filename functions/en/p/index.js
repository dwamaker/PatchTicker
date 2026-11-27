import { productsResponse } from '../../../edge/lists.mjs';
import { cached } from '../../../edge/shared.mjs';

export const onRequestGet = (context) => cached(context, () => productsResponse(context.env.DATA, 'en'));
export const onRequestHead = onRequestGet;
