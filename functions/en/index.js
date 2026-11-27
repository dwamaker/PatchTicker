import { homeResponse } from '../../edge/home.mjs';

// The English Board (owner 11-28, Gemini review): the home page's shell with an English head and links.
export const onRequestGet = (context) => homeResponse(context, 'en');
export const onRequestHead = onRequestGet;
