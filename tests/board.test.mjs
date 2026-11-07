// Seam 2: the Board's filter function.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { filterBoard, filterFromQuery, filterToQuery, productList } from '../web/board.mjs';

const incident = (id, first_seen) => ({ id, cves: [id], first_seen, brief: { text: id, lead: '' } });

test('returns Incidents newest first', () => {
  const incidents = [
    incident('CVE-2026-2', '2026-11-07T13:30:00Z'),
    incident('CVE-2026-3', '2026-12-01T00:05:00Z'),
    incident('CVE-2026-1', '2026-10-31T23:59:00Z'),
  ];
  assert.deepEqual(filterBoard(incidents).map((i) => i.id), ['CVE-2026-3', 'CVE-2026-2', 'CVE-2026-1']);
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
  assert.deepEqual(ids(filterBoard(board, [])), ['CVE-2026-120839', 'CVE-2026-120984', 'CVE-2026-1001', 'CVE-2024-6387']);
});

test('picked Products hide Incidents with no matching Product', () => {
  assert.deepEqual(ids(filterBoard(board, [openssh.id])), ['CVE-2026-1001', 'CVE-2024-6387']);
  assert.deepEqual(ids(filterBoard(board, [dropbear.id, keycloak.id])), ['CVE-2026-120984', 'CVE-2026-1001']);
});

test('search matches title text, CVE ID, Product and version text, ignoring case', () => {
  assert.deepEqual(ids(filterBoard(board, [], 'KEYCLOAK server')), ['CVE-2026-120984']);
  assert.deepEqual(ids(filterBoard(board, [], 'cve-2024-6387')), ['CVE-2024-6387']);
  assert.deepEqual(ids(filterBoard(board, [], 'dropbear ssh')), ['CVE-2026-1001']);
  assert.deepEqual(ids(filterBoard(board, [], '2.3.8')), ['CVE-2026-120839']);
  assert.deepEqual(ids(filterBoard(board, [], '9.8P1')), ['CVE-2024-6387']);
  assert.deepEqual(ids(filterBoard(board, [], '  ')), ids(filterBoard(board)));
  assert.deepEqual(ids(filterBoard(board, [], 'nothing matches this')), []);
});

test('search and Product picks narrow together', () => {
  assert.deepEqual(ids(filterBoard(board, [openssh.id], 'race')), ['CVE-2024-6387']);
  assert.deepEqual(ids(filterBoard(board, [keycloak.id], 'race')), []);
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
