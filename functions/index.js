import { homeResponse } from '../edge/home.mjs';

export const onRequestGet = (context) => homeResponse(context);
export const onRequestHead = onRequestGet;
