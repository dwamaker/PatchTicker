import { checkResponse } from '../../edge/check.mjs';

// One handler for every method: GET and HEAD answer, the rest get a 405 (with only onRequestGet, Pages would serve
// index.html for them). AI: the Workers AI binding that guesses names nothing matches (absent: no guesses).
export const onRequest = (context) => checkResponse(context.env.DATA, context.request, Date.now(), context.env.AI);
