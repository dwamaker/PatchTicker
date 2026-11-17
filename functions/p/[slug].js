import { productResponse } from '../../edge/product.mjs';
import { cached } from '../../edge/shared.mjs';

export const onRequestGet = (context) => cached(context, () => productResponse(context.env.DATA, 'ko', context.params.slug));
export const onRequestHead = onRequestGet;
