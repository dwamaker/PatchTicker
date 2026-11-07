// The Board's filter: pure, so it runs the same in the browser and under `node --test`.
// first_seen is ISO-8601 UTC ("...Z"), so string order is time order.
export function filterBoard(incidents) {
  return [...incidents].sort((a, b) => (a.first_seen < b.first_seen ? 1 : a.first_seen > b.first_seen ? -1 : 0));
}
