import { cached } from '../../../edge/shared.mjs';
import { pageResponse } from '../../../edge/page.mjs';

export const onRequestGet = (context) => cached(context, () => pageResponse(context.env.DATA, 'ja', context.params.slug));
export const onRequestHead = onRequestGet;
