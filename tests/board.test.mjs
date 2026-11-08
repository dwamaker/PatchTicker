// Seam 2: the Board's filter function.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { easyAction, filterBoard, filterFromQuery, filterToQuery, productList, riskLevel } from '../web/board.mjs';

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

test('search matches the Summary in Korean and in English', () => {
  const summary = {
    ko: { title: '무슬 기반 OpenSSH 인증 우회', summary: '비밀번호 없는 계정이 257~1024자 비밀번호를 받아들입니다.', conditions: ['PAM 미사용'], mitigation: '10.6p2로 업데이트하세요.' },
    en: { title: 'OpenSSH on musl auth bypass', summary: 'Password-less accounts accept 257 to 1024 characters.', conditions: ['PAM not used'], mitigation: 'Update to 10.6p2.' },
    products: ['Alpine Linux'],
    lead: '',
  };
  const summarized = [...board, { ...incident('https://sshhole.com', '2026-11-05T12:30:00Z'), cves: [], brief: { text: 'sshole', lead: '' }, summary }];
  for (const query of ['비밀번호 없는', 'password-less', 'PAM 미사용', 'pam not used', '업데이트하세요', '1024', 'alpine linux']) {
    assert.deepEqual(ids(filterBoard(summarized, [], query).list), ['https://sshhole.com'], query);
  }
});

const easySummary = {
  ko: { title: 'OpenSSH 인증 우회', summary: '긴 비밀번호가 통합니다.', conditions: [], mitigation: '10.6p2로 업데이트하세요.', easy: '남이 아무 긴 비밀번호로 서버에 들어올 수 있습니다.' },
  en: { title: 'OpenSSH auth bypass', summary: 'Long passwords work.', conditions: [], mitigation: 'Update to 10.6p2.', easy: 'Strangers can get into your server with any long password.' },
  products: ['OpenSSH'], lead: '', fixed: '10.6p2', command: 'apk upgrade openssh', stopgap: 'PasswordAuthentication no', devices: [],
};

test('search matches the Easy text in both languages, and the normal text still', () => {
  const summarized = [...board, { ...incident('https://sshhole.com', '2026-11-05T12:30:00Z'), cves: [], summary: easySummary }];
  for (const query of ['남이 아무', 'strangers can', 'apk upgrade', '긴 비밀번호가 통합니다', 'long passwords work']) {
    assert.deepEqual(ids(filterBoard(summarized, [], query).list), ['https://sshhole.com'], query);
  }
});

test('a Summary written before the Easy view still shows and searches', () => {
  const { ko, en } = easySummary;
  const old = { ko: { ...ko, easy: undefined }, en: { ...en, easy: undefined }, products: [], lead: '' };
  const list = [{ ...incident('CVE-2026-1', '2026-11-05T12:30:00Z'), summary: old }];
  assert.deepEqual(ids(filterBoard(list, [], 'long passwords').list), ['CVE-2026-1']);
  assert.deepEqual(easyAction(old), { kind: 'none', stopgap: '' });
});

test('the Risk banner comes from rules: exploited or CVSS 9.0+ is highest, 7.0+ high, else notice', () => {
  assert.equal(riskLevel({ kev: true }), 'highest');
  assert.equal(riskLevel({ kev: true, cvss: 3.1 }), 'highest');
  assert.equal(riskLevel({ cvss: 9.0 }), 'highest');
  assert.equal(riskLevel({ cvss: 8.9 }), 'high');
  assert.equal(riskLevel({ cvss: 7.0 }), 'high');
  assert.equal(riskLevel({ cvss: 6.9 }), 'notice');
  assert.equal(riskLevel({}), 'notice'); // no score yet
});

test('the Easy action: devices first, then the source\'s command, then the fixed version', () => {
  const router = { ...easySummary, command: '', devices: ['Archer AX21', 'Archer AX55'] };
  assert.deepEqual(easyAction(router), { kind: 'devices', devices: ['Archer AX21', 'Archer AX55'], fixed: '10.6p2', stopgap: 'PasswordAuthentication no' });
  assert.deepEqual(easyAction(easySummary), { kind: 'command', command: 'apk upgrade openssh', stopgap: 'PasswordAuthentication no' });
  // The collector drops a command not found in the sources; the page then says "update to version X".
  assert.deepEqual(easyAction({ ...easySummary, command: '' }), { kind: 'version', fixed: '10.6p2', stopgap: 'PasswordAuthentication no' });
  assert.deepEqual(easyAction({ ...easySummary, command: '', fixed: '', stopgap: '' }), { kind: 'none', stopgap: '' });
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
