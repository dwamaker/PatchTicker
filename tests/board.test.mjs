// Seam 2: the Board's filter function.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { filterBoard, filterFromQuery, filterToQuery, productList } from '../web/board.mjs';

const incident = (id, first_seen) => ({ id, cves: [id], first_seen, mentions: [{ kind: 'cve_record', url: '' }], brief: { text: id, lead: '' } });

test('returns Incidents newest first', () => {
  const incidents = [
    incident('CVE-2026-2', '2026-11-07T13:30:00Z'),
    incident('CVE-2026-3', '2026-12-01T00:05:00Z'),
    incident('CVE-2026-1', '2026-10-31T23:59:00Z'),
  ];
  assert.deepEqual(filterBoard(incidents).list.map((i) => i.id), ['CVE-2026-3', 'CVE-2026-2', 'CVE-2026-1']);
});

test('lists an Unassigned incident (no CVE yet) among CVE Incidents, newest first', () => {
  const unassigned = { ...incident('https://news.ycombinator.com/item?id=50378228', '2026-11-05T12:30:00Z'), cves: [] };
  const incidents = [incident('CVE-2026-1', '2026-11-05T12:00:00Z'), unassigned, incident('CVE-2026-2', '2026-11-05T13:00:00Z')];
  assert.deepEqual(filterBoard(incidents).list.map((i) => i.cves), [['CVE-2026-2'], [], ['CVE-2026-1']]);
});

const openssh = { id: 'openbsd:openssh', name: 'Openssh' };
const dropbear = { id: 'dropbear_ssh_project:dropbear_ssh', name: 'Dropbear Ssh' };
const keycloak = { id: 'redhat:keycloak', name: 'Keycloak' };
const board = [
  { ...incident('CVE-2024-6387', '2026-11-03T00:00:00Z'), products: [openssh], brief: { text: 'regreSSHion: race in sshd before 9.8p1', lead: '' } },
  { ...incident('CVE-2026-1001', '2026-11-04T00:00:00Z'), products: [dropbear, openssh], brief: { text: 'Dropbear and OpenSSH key exchange flaw', lead: '' } },
  { ...incident('CVE-2026-120984', '2026-11-05T00:00:00Z'), products: [keycloak], brief: { text: 'A flaw was found in the Keycloak server', lead: '' } },
  { ...incident('CVE-2026-120839', '2026-11-06T00:00:00Z'), brief: { text: 'WpTravelly: from n/a through 2.3.8.', lead: '' } },
];
const ids = (list) => list.map((i) => i.id);

test('with no Products picked, every Incident shows', () => {
  assert.deepEqual(ids(filterBoard(board, []).list), ['CVE-2026-120839', 'CVE-2026-120984', 'CVE-2026-1001', 'CVE-2024-6387']);
});

test('picked Products hide Incidents with no matching Product', () => {
  assert.deepEqual(ids(filterBoard(board, [openssh.id]).list), ['CVE-2026-1001', 'CVE-2024-6387']);
  assert.deepEqual(ids(filterBoard(board, [dropbear.id, keycloak.id]).list), ['CVE-2026-120984', 'CVE-2026-1001']);
});

test('search matches title text, CVE ID, Product and version text, ignoring case', () => {
  assert.deepEqual(ids(filterBoard(board, [], 'KEYCLOAK server').list), ['CVE-2026-120984']);
  assert.deepEqual(ids(filterBoard(board, [], 'cve-2024-6387').list), ['CVE-2024-6387']);
  assert.deepEqual(ids(filterBoard(board, [], 'dropbear ssh').list), ['CVE-2026-1001']);
  assert.deepEqual(ids(filterBoard(board, [], '2.3.8').list), ['CVE-2026-120839']);
  assert.deepEqual(ids(filterBoard(board, [], '9.8P1').list), ['CVE-2024-6387']);
  assert.deepEqual(ids(filterBoard(board, [], '  ').list), ids(filterBoard(board).list));
  assert.deepEqual(ids(filterBoard(board, [], 'nothing matches this').list), []);
});

test('search and Product picks narrow together', () => {
  assert.deepEqual(ids(filterBoard(board, [openssh.id], 'race').list), ['CVE-2024-6387']);
  assert.deepEqual(ids(filterBoard(board, [keycloak.id], 'race').list), []);
});

test('the Product list holds each Product seen in the last 90 days once, by name', () => {
  const old = { ...incident('CVE-2026-1', '2026-08-01T00:00:00Z'), products: [{ id: 'old:only', name: 'Old Only' }, keycloak] };
  const now = new Date('2026-11-07T00:00:00Z');
  assert.deepEqual(productList([...board, old], now), [dropbear, keycloak, openssh]);
});

test('a filter written to the page address reads back the same', () => {
  const filter = { picks: [openssh.id, 'vendor:a,b&c'], query: 'heap overflow 9.8p1' };
  assert.deepEqual(filterFromQuery(filterToQuery(filter)), filter);
  assert.deepEqual(filterFromQuery('?' + filterToQuery(filter)), filter);
  assert.deepEqual(filterFromQuery(''), { picks: [], query: '' });
});

test('does not reorder the caller\'s array', () => {
  const incidents = [incident('CVE-2026-1', '2026-11-01T00:00:00Z'), incident('CVE-2026-2', '2026-11-02T00:00:00Z')];
  filterBoard(incidents);
  assert.deepEqual(incidents.map((i) => i.id), ['CVE-2026-1', 'CVE-2026-2']);
});

const NOW = new Date('2026-11-07T12:00:00Z').getTime();
const daysAgo = (d) => new Date(NOW - d * 24 * 60 * 60 * 1000).toISOString().replace('.000Z', 'Z');

test('Highlights are at most ten, all first seen in the last seven days, highest score first', () => {
  // Twelve recent Incidents, CVSS 4.5 to 10.0, newest has the lowest score; one older Incident scores highest.
  const recent = Array.from({ length: 12 }, (_, n) => ({ ...incident(`CVE-2026-${100 + n}`, daysAgo(6 - n / 2)), cvss: 10 - n / 2 }));
  const old = { ...incident('CVE-2026-1', daysAgo(8)), cvss: 10, kev: true };
  const { highlights, list } = filterBoard([...recent, old], [], '', NOW);
  assert.deepEqual(ids(highlights), ['CVE-2026-100', 'CVE-2026-101', 'CVE-2026-102', 'CVE-2026-103', 'CVE-2026-104',
    'CVE-2026-105', 'CVE-2026-106', 'CVE-2026-107', 'CVE-2026-108', 'CVE-2026-109']);
  assert.equal(list.length, 13);
});

test('exploited in the wild outranks HN buzz, which outranks a curator pick, which outranks CVSS 9.8 alone', () => {
  const kev = { ...incident('CVE-2026-201', daysAgo(1)), cvss: 5.3, kev: true };
  const hn = { ...incident('CVE-2026-202', daysAgo(1)), mentions: [{ kind: 'discussion', url: '', points: 640 }] };
  const curated = { ...incident('CVE-2026-203', daysAgo(1)), mentions: [{ kind: 'cve_record', url: '' }, { kind: 'curator', url: '' }] };
  const critical = { ...incident('CVE-2026-204', daysAgo(1)), cvss: 9.8 };
  const plain = incident('CVE-2026-205', daysAgo(1));
  assert.deepEqual(ids(filterBoard([plain, critical, curated, hn, kev], [], '', NOW).highlights),
    ['CVE-2026-201', 'CVE-2026-202', 'CVE-2026-203', 'CVE-2026-204', 'CVE-2026-205']);
});

test('an Incident older than seven days leaves the Highlights and stays in the list', () => {
  const kev = { ...incident('CVE-2026-301', '2026-11-01T12:00:00Z'), kev: true };
  const at = (iso) => filterBoard([kev], [], '', new Date(iso).getTime());
  assert.deepEqual(ids(at('2026-11-08T12:00:00Z').highlights), ['CVE-2026-301']); // exactly seven days
  assert.deepEqual(ids(at('2026-11-08T12:00:01Z').highlights), []);
  assert.deepEqual(ids(at('2026-11-08T12:00:01Z').list), ['CVE-2026-301']);
});

test('Product picks and search narrow the Highlights too', () => {
  // All four score the same, so they rank newest first: CVE-2024-6387 (1 day old) to CVE-2026-120839 (4 days).
  const recent = board.map((i, n) => ({ ...i, first_seen: daysAgo(n + 1), cvss: 9 }));
  assert.deepEqual(ids(filterBoard(recent, [], '', NOW).highlights), ['CVE-2024-6387', 'CVE-2026-1001', 'CVE-2026-120984', 'CVE-2026-120839']);
  assert.deepEqual(ids(filterBoard(recent, [openssh.id], '', NOW).highlights), ['CVE-2024-6387', 'CVE-2026-1001']);
  assert.deepEqual(ids(filterBoard(recent, [], 'keycloak', NOW).highlights), ['CVE-2026-120984']);
  assert.deepEqual(ids(filterBoard(recent, [keycloak.id], 'race', NOW).highlights), []);
});

test('the sshole replay Incident becomes a Highlight ahead of ten CVSS 9.8 Incidents', () => {
  // Written by the sshole replay in tests/test_mentions.py (seam 1), which asserts it matches.
  const sshole = JSON.parse(readFileSync(new URL('./fixtures/board/sshole.json', import.meta.url)));
  const critical = Array.from({ length: 10 }, (_, n) => ({ ...incident(`CVE-2026-40${n}`, daysAgo(1)), cvss: 9.8 }));
  const { highlights } = filterBoard([...critical, sshole], [], '', NOW);
  assert.equal(highlights.length, 10);
  assert.equal(highlights[0].id, sshole.id);
});
