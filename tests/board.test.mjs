// Seam 2: the Board's filter function.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { filterBoard } from '../web/board.mjs';

const incident = (id, first_seen) => ({ id, cves: [id], first_seen, brief: { text: id, lead: '' } });

test('returns Incidents newest first', () => {
  const incidents = [
    incident('CVE-2026-2', '2026-11-07T13:30:00Z'),
    incident('CVE-2026-3', '2026-12-01T00:05:00Z'),
    incident('CVE-2026-1', '2026-10-31T23:59:00Z'),
  ];
  assert.deepEqual(filterBoard(incidents).map((i) => i.id), ['CVE-2026-3', 'CVE-2026-2', 'CVE-2026-1']);
});

test('lists an Unassigned incident (no CVE yet) among CVE Incidents, newest first', () => {
  const unassigned = { ...incident('https://news.ycombinator.com/item?id=50378228', '2026-11-05T12:30:00Z'), cves: [] };
  const incidents = [incident('CVE-2026-1', '2026-11-05T12:00:00Z'), unassigned, incident('CVE-2026-2', '2026-11-05T13:00:00Z')];
  assert.deepEqual(filterBoard(incidents).map((i) => i.cves), [['CVE-2026-2'], [], ['CVE-2026-1']]);
});

test('does not reorder the caller\'s array', () => {
  const incidents = [incident('CVE-2026-1', '2026-11-01T00:00:00Z'), incident('CVE-2026-2', '2026-11-02T00:00:00Z')];
  filterBoard(incidents);
  assert.deepEqual(incidents.map((i) => i.id), ['CVE-2026-1', 'CVE-2026-2']);
});
