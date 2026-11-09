import { cached } from '../../../edge/shared.mjs';
import { pageResponse } from '../../../edge/page.mjs';

export const onRequestGet = (context) => cached(context, () => pageResponse(context.env.DATA, 'en', context.params.slug));
