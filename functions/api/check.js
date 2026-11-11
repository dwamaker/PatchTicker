import { checkResponse } from '../../edge/check.mjs';

// One handler for every method: GET and HEAD answer, the rest get a 405 (with only onRequestGet, Pages would serve
// index.html for them).
export const onRequest = (context) => checkResponse(context.env.DATA, context.request);
