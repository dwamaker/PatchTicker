// Seam 2: the Board's filter function.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { foldByVendor, isExploited, matchProducts, mergeIncidents, LINES, orderBy, pinReason, briefMarker, cveHead, easyLine, easyTitle, isShellCommand, onBoard, productsOf, cvssRating, easyAction, filterBoard, filterFromQuery, filterToQuery, lineKeys, productLine, productList, publishedAt, relativeAge, riskLevel, rowTags, uniqueNames, viewFromStorage } from '../web/board.mjs';

const incident = (id, first_seen) => ({ id, cves: [id], first_seen, mentions: [{ kind: 'cve_record', url: '' }], brief: { text: id, lead: '' } });

test('a row is named by its first CVE and counts the rest; no CVE gives no name', () => {
  assert.deepEqual(cveHead(['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3']), { id: 'CVE-2026-1', more: 2 });
  assert.deepEqual(cveHead(['CVE-2026-1']), { id: 'CVE-2026-1', more: 0 });
  assert.equal(cveHead([]), null);
  assert.equal(cveHead(undefined), null);
});

test('the CVSS rating follows the v3 bands, and an unrated Incident has none', () => {
  assert.deepEqual([9, 8.9, 7, 6.9, 4, 3.9, 0.1, 0, null, undefined].map(cvssRating),
    ['critical', 'high', 'high', 'medium', 'medium', 'low', 'low', 'none', null, null]);
});

test('a row\'s tags are its Products, then the Summary\'s devices, each name once', () => {
  const i = { products: [{ id: 'a:x', name: 'OpenSSH' }, { id: 'b:x', name: 'Router' }], summary: { devices: ['Router', 'NAS'] } };
  assert.deepEqual(rowTags(i), ['OpenSSH', 'Router', 'NAS']);
  assert.deepEqual(rowTags({}), []);
  // The Summary's vendor-led names win over title-cased CPE names.
  assert.deepEqual(rowTags({ ...i, summary: { products: ['SonicWall SonicOS'], devices: [] } }), ['SonicWall SonicOS']);
  // Each language shows the names its readers know.
  const paint = { summary: { products: ['Microsoft Paint'], devices: [], ko: { names: ['Windows 그림판'] }, en: { names: ['Microsoft Paint'] } } };
  assert.deepEqual([rowTags(paint, 'ko'), rowTags(paint, 'en')], [['Windows 그림판'], ['Microsoft Paint']]);
});

test('a name that differs only in letter case shows once (Qiskit SDK / Qiskit Sdk)', () => {
  assert.deepEqual(rowTags({ products: [{ id: 'ibm:qiskit_sdk', name: 'Qiskit SDK' }, { id: 'ibm:qiskit', name: 'Qiskit Sdk' }] }), ['Qiskit SDK']);
  assert.deepEqual(uniqueNames(['Qiskit SDK', 'qiskit sdk', 'Perl']), ['Qiskit SDK', 'Perl']);
});

test("operating systems lead a row's tags in one fixed order, whatever order the Summary gave", () => {
  const i = { summary: { products: ['Perl'], platforms: ['Linux', 'Windows', 'macOS'], devices: [] } };
  assert.deepEqual(rowTags(i), ['Windows', 'macOS', 'Linux', 'Perl']);
  assert.deepEqual(rowTags({ summary: { products: ['X'], platforms: ['iOS', 'FreeBSD', 'Android'], devices: [] } }), ['Android', 'iOS', 'FreeBSD', 'X']);
});

test('a long device list stays off the row: past four models the badges are the product alone', () => {
  const few = { summary: { products: ['TP-Link Archer'], devices: ['TP-Link Archer C6', 'TP-Link Archer AX10'] } };
  assert.deepEqual(rowTags(few), ['TP-Link Archer', 'TP-Link Archer C6', 'TP-Link Archer AX10']);
  const many = { summary: { products: ['SonicWall SonicOS'], devices: ['TZ 270', 'TZ 370', 'TZ 470', 'TZ 570', 'TZ 670'].map((m) => `SonicWall ${m}`) } };
  assert.deepEqual(rowTags(many), ['SonicWall SonicOS']);
});

test('returns Incidents newest first', () => {
  const incidents = [
    incident('CVE-2026-2', '2026-11-07T13:30:00Z'),
    incident('CVE-2026-3', '2026-12-01T00:05:00Z'),
    incident('CVE-2026-1', '2026-10-31T23:59:00Z'),
  ];
  assert.deepEqual(filterBoard(incidents).list.map((i) => i.id), ['CVE-2026-3', 'CVE-2026-2', 'CVE-2026-1']);
});

test('orders by when the news first broke, falling back to first seen', () => {
  const incidents = [
    { ...incident('CVE-2026-1', '2026-11-08T03:00:00Z'), published: '2026-11-01T00:00:00Z' },
    incident('CVE-2026-2', '2026-11-05T00:00:00Z'),
  ];
  assert.deepEqual(filterBoard(incidents).list.map((i) => i.id), ['CVE-2026-2', 'CVE-2026-1']);
  assert.equal(publishedAt(incidents[0]), '2026-11-01T00:00:00Z');
});

test('an HN story without a CVE waits for its Summary and stays off when it is not an Incident', () => {
  const story = { id: 'https://news.ycombinator.com/item?id=1', cves: [] };
  assert.equal(onBoard(story), false);
  assert.equal(onBoard({ ...story, summary: { incident: true } }), true);
  assert.equal(onBoard({ ...story, summary: { incident: false } }), false);
  assert.equal(onBoard({ ...story, summary: {} }), true); // a Summary from before the flag
  assert.equal(onBoard({ ...story, summary_error: { tries: 3, final: true } }), true);
  assert.equal(onBoard({ id: 'CVE-2026-1', cves: ['CVE-2026-1'] }), true);
  assert.equal(onBoard({ id: 'https://seclists.org/oss-sec/2026/q4/563', cves: [] }), true);
});

test('Products come from NVD or the CVE record, the Summary and its operating systems, each once', () => {
  const i = { products: [{ id: 'openbsd:openssh', name: 'OpenSSH' }],
    summary: { products: ['OpenSSH', 'musl'], platforms: ['Linux'] } };
  assert.deepEqual(productsOf(i).map((p) => p.id), ['openbsd:openssh', 'name:musl', 'os:linux']);
  const sonic = { products: [{ id: 'sonicwall:sonicos', name: 'SonicOS' }], summary: { products: ['SonicWall SonicOS'] } };
  assert.deepEqual(productsOf(sonic), [{ id: 'sonicwall:sonicos', name: 'SonicWall SonicOS' }]);
  assert.deepEqual(productsOf({ summary: { products: ['iOS', 'Android'], platforms: ['iOS', 'Android'] } }).map((p) => p.id), ['os:ios', 'os:android']);
  const paint = { id: 'CVE-2026-83844', cves: ['CVE-2026-83844'], first_seen: '2026-11-08T00:00:00Z', mentions: [], brief: { text: '' },
    summary: { products: ['Microsoft Paint'], platforms: ['Windows'], ...Object.fromEntries(['ko', 'en'].map((l) => [l, { title: '', summary: '', conditions: [], mitigation: '' }])) } };
  assert.deepEqual(filterBoard([paint], ['os:windows']).list.length, 1);
  assert.deepEqual(rowTags(paint, 'en'), ['Windows', 'Microsoft Paint']); // operating systems lead
});

test('only package-manager and service lines count as shell commands; config lines do not', () => {
  assert.equal(isShellCommand('apk upgrade openssh'), true);
  assert.equal(isShellCommand('sudo apt-get install --only-upgrade openssh-server'), true);
  assert.equal(isShellCommand('systemctl restart sshd'), true);
  assert.equal(isShellCommand('PasswordAuthentication no'), false);
  assert.equal(isShellCommand('LoginGraceTime 0'), false);
  assert.equal(isShellCommand(''), false);
});

test('the Easy sentence keeps its "!" only at the top Risk level', () => {
  assert.equal(easyLine('PC를 해킹당할 수 있습니다!', 'highest'), 'PC를 해킹당할 수 있습니다!');
  assert.equal(easyLine('PC를 해킹당할 수 있습니다!', 'high'), 'PC를 해킹당할 수 있습니다.');
  assert.equal(easyLine('계정이 털렸을 수 있습니다!! ', 'notice'), '계정이 털렸을 수 있습니다. ');
  assert.equal(easyLine('조용한 문장입니다.', 'notice'), '조용한 문장입니다.');
});

test('an Easy headline at the lowest Risk level calls the danger a 문제, not a 위험', () => {
  assert.equal(easyTitle('Apache Allura 협업 사이트 뚫림 위험', 'notice'), 'Apache Allura 협업 사이트 뚫림 문제');
  assert.equal(easyTitle('Perl graph module freeze risk', 'notice'), 'Perl graph module freeze issue');
  assert.equal(easyTitle('Windows 그림판 해킹 위험', 'high'), 'Windows 그림판 해킹 위험');
  assert.equal(easyTitle('SonicWall 원격접속 장비 뚫림 위험', 'highest'), 'SonicWall 원격접속 장비 뚫림 위험');
  assert.equal(easyTitle('AI 채팅 대화 털림', 'notice'), 'AI 채팅 대화 털림');
  assert.equal(easyTitle('위험한 위험 앱 경고', 'notice'), '위험한 위험 앱 경고');
});

test('a pinned row says why only when the row does not show it already', () => {
  const base = { cves: [], mentions: [] };
  assert.equal(pinReason({ ...base, kev: true, mentions: [{ kind: 'curator' }] }), null);
  assert.equal(pinReason({ ...base, cvss: 9.8 }), null);
  assert.equal(pinReason({ ...base, mentions: [{ kind: 'curator' }] }), 'curator');
  assert.equal(pinReason({ ...base, mentions: [{ kind: 'discussion', points: 2935 }] }), 'buzz');
  assert.equal(pinReason({ ...base, mentions: [{ kind: 'discussion', points: 40 }] }), null);
});

test('quick filters keep only the chosen Risk levels and, when asked, exploited Incidents; they ride in the hash', () => {
  const a = { ...incident('CVE-2026-1', '2026-11-08T00:00:00Z'), kev: true, cvss: 5 };
  const b = { ...incident('CVE-2026-2', '2026-11-08T00:00:00Z'), cvss: 7.5 };
  const c = incident('CVE-2026-3', '2026-11-08T00:00:00Z');
  const pick = (opts) => filterBoard([a, b, c], [], '', NOW, opts).list.map((i) => i.id).sort();
  assert.deepEqual(pick({ risk: ['high'] }), ['CVE-2026-2']);
  assert.deepEqual(pick({ risk: ['highest', 'notice'] }), ['CVE-2026-1', 'CVE-2026-3']);
  assert.deepEqual(pick({ kev: true }), ['CVE-2026-1']);
  const f = { picks: ['os:linux'], query: 'ssh', risk: ['highest'], kev: true, from: '2026-11-01', to: '2026-11-08', cvssMin: 7, cve: 'yes', has: ['advisory'], sort: 'risk' };
  assert.deepEqual(filterFromQuery(filterToQuery(f)), f);
  assert.deepEqual(filterFromQuery('r=bogus').risk, []);
});

test('the panel narrows by date, CVSS, CVE and link kind, and sorts by risk or CVSS', () => {
  const at = (id, day, extra = {}) => ({ ...incident(id, `${day}T00:00:00Z`), ...extra });
  const a = at('CVE-2026-1', '2026-11-01', { cvss: 9.8 });
  const b = at('CVE-2026-2', '2026-11-05', { cvss: 7.5, mentions: [{ kind: 'advisory', url: '' }] });
  const c = { ...at('x', '2026-11-07'), cves: [], mentions: [{ kind: 'repo', url: '' }] };
  const run = (opts) => filterBoard([a, b, c], [], '', NOW, opts).list.map((i) => i.id);
  assert.deepEqual(run({ from: '2026-11-02', to: '2026-11-06' }), ['CVE-2026-2']);
  assert.deepEqual(run({ cvssMin: 9 }), ['CVE-2026-1']);
  assert.deepEqual(run({ cve: 'no' }), ['x']);
  assert.deepEqual(run({ has: ['advisory'] }), ['CVE-2026-2']);
  assert.deepEqual(run({ sort: 'cvss' }), ['CVE-2026-1', 'CVE-2026-2', 'x']);
  assert.deepEqual(run({ sort: 'risk' }), ['CVE-2026-1', 'CVE-2026-2', 'x']);
  assert.deepEqual(run({}), ['x', 'CVE-2026-2', 'CVE-2026-1']);
});

test('search finds an Incident by a name only its Mentions use', () => {
  const joined = { ...incident('CVE-2026-123158', '2026-11-08T05:00:00Z'),
    mentions: [{ kind: 'cve_record', url: '' }, { kind: 'discussion', url: 'https://news.ycombinator.com/item?id=50399400', title: '*sshole, or when are we going to get rid of C?' }] };
  assert.deepEqual(filterBoard([joined, incident('CVE-2026-1', '2026-11-08T05:00:00Z')], [], 'sshole').list.map((i) => i.id), ['CVE-2026-123158']);
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

test('a Brief says a Summary is in preparation until the collector gives up, then that none is available', () => {
  assert.equal(briefMarker(incident('CVE-2026-1', '2026-11-05T12:30:00Z')), 'preparing');
  assert.equal(briefMarker({ summary_error: { tries: 2, reason: 'x' } }), 'preparing');
  assert.equal(briefMarker({ summary_error: { tries: 3, reason: 'x', final: true } }), 'unavailable');
});

test('the Board opens in the remembered view', () => {
  assert.equal(viewFromStorage('easy'), 'easy');
  assert.equal(viewFromStorage(null), 'normal'); // nothing saved: the normal view
  assert.equal(viewFromStorage('["CVE-2026-1"]'), 'normal'); // the old per-Incident list
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

// The picker takes what a visitor types, not only an exact pick from the list (critique 9: "Kyv" and "kyverno" were
// answered with "not in the list" although Kyverno was listed).
test('the Product picker matches typed names regardless of case, whole names first, then parts', () => {
  const kyverno = { id: 'kyverno:kyverno', name: 'Kyverno' };
  const ssh = { id: 'openbsd:openssh', name: 'OpenSSH' };
  const portable = { id: 'x:openssh_portable', name: 'OpenSSH Portable' };
  const win = { id: 'os:windows', name: 'Windows' };
  const list = [kyverno, ssh, portable, win];
  const label = (p) => (p.id.startsWith('os:') ? `${p.name} (OS)` : p.name);
  assert.deepEqual(matchProducts(list, 'Kyverno', label), [kyverno]);
  assert.deepEqual(matchProducts(list, 'kyverno', label), [kyverno]);
  assert.deepEqual(matchProducts(list, '  Kyv ', label), [kyverno]);
  assert.deepEqual(matchProducts(list, 'openssh', label), [ssh]); // a whole name beats a longer name that contains it
  assert.deepEqual(matchProducts(list, 'ssh', label), [ssh, portable]);
  assert.deepEqual(matchProducts(list, 'Windows (OS)', label), [win]);
  assert.deepEqual(matchProducts(list, 'windows', label), [win]);
  assert.deepEqual(matchProducts(list, '공유기', label), []);
  assert.deepEqual(matchProducts(list, '   ', label), []);
});

// A refresh while the page is open: the new week replaces the Incidents it holds, older months already loaded stay,
// and only ids the page did not have count as new (a Summary arriving later is a change, not a new Incident).
test('a refresh merges the new week into what the page holds and names only the new ids', () => {
  const a = { id: 'a', v: 1 }, b = { id: 'b', v: 1 }, old = { id: 'old', v: 1 };
  const { incidents, added } = mergeIncidents([a, b, old], [{ id: 'a', v: 2 }, b, { id: 'c', v: 1 }]);
  assert.deepEqual(incidents.map((i) => [i.id, i.v]).sort(), [['a', 2], ['b', 1], ['c', 1], ['old', 1]]);
  assert.deepEqual(added, ['c']);
  assert.deepEqual(mergeIncidents([a], [a]).added, []);
});

// The collector's board/products.json (collector.incidents.product_list) must name Products as the page does.
test('the collector\'s Product list matches the page\'s for the same Incidents, in both languages', () => {
  const kase = JSON.parse(readFileSync(new URL('./fixtures/board/products-case.json', import.meta.url), 'utf8'));
  const byId = (a, b) => (a.id < b.id ? -1 : 1);
  for (const lang of ['ko', 'en']) {
    assert.deepEqual(productList(kase.incidents.filter(onBoard), new Date(kase.now), lang).sort(byId),
      kase.expected.map((p) => ({ id: p.id, name: p[lang] })));
  }
});

test('the picker also lists Products with no Incident loaded, and loaded Incidents name the shared ones', () => {
  const seen = [{ id: 'iptime:firmware', ko: 'ipTIME 공유기', en: 'ipTIME router' }, { id: openssh.id, ko: 'x', en: 'x' }];
  const list = productList(board, new Date('2026-11-07T00:00:00Z'), 'ko', seen);
  assert.deepEqual(list.map((p) => p.name), ['Dropbear Ssh', 'ipTIME 공유기', 'Keycloak', 'Openssh']);
});

test('a filter written to the page address reads back the same', () => {
  const filter = { picks: [openssh.id, 'vendor:a,b&c'], query: 'heap overflow 9.8p1', risk: [], kev: false, from: '', to: '', cvssMin: 0, cve: '', has: [], sort: 'new' };
  assert.deepEqual(filterFromQuery(filterToQuery(filter)), filter);
  assert.deepEqual(filterFromQuery('?' + filterToQuery(filter)), filter);
  assert.deepEqual(filterFromQuery(''), { picks: [], query: '', risk: [], kev: false, from: '', to: '', cvssMin: 0, cve: '', has: [], sort: 'new' });
});

test('does not reorder the caller\'s array', () => {
  const incidents = [incident('CVE-2026-1', '2026-11-01T00:00:00Z'), incident('CVE-2026-2', '2026-11-02T00:00:00Z')];
  filterBoard(incidents);
  assert.deepEqual(incidents.map((i) => i.id), ['CVE-2026-1', 'CVE-2026-2']);
});

const NOW = new Date('2026-11-07T12:00:00Z').getTime();
const daysAgo = (d) => new Date(NOW - d * 24 * 60 * 60 * 1000).toISOString().replace('.000Z', 'Z');

test('Highlights are at most ten, 위험 or above from the last seven days, highest score first', () => {
  // Twelve recent Incidents, CVSS 4.5 to 10.0, newest has the lowest score; one older Incident scores highest.
  const recent = Array.from({ length: 12 }, (_, n) => ({ ...incident(`CVE-2026-${100 + n}`, daysAgo(6 - n / 2)), cvss: 10 - n / 2 }));
  const old = { ...incident('CVE-2026-1', daysAgo(8)), cvss: 10, kev: true };
  const { highlights, list } = filterBoard([...recent, old], [], '', NOW);
  // CVSS 6.5 and below (CVE-2026-107 on) are 참고 and stay in the list only (user, 2026-11-09).
  assert.deepEqual(ids(highlights), ['CVE-2026-100', 'CVE-2026-101', 'CVE-2026-102', 'CVE-2026-103', 'CVE-2026-104',
    'CVE-2026-105', 'CVE-2026-106']);
  assert.equal(list.length, 13);
});

test('exploited in the wild outranks HN buzz, which outranks a curator pick, which outranks CVSS 9.8 alone', () => {
  const kev = { ...incident('CVE-2026-201', daysAgo(1)), cvss: 5.3, kev: true };
  const hn = { ...incident('CVE-2026-202', daysAgo(1)), cvss: 7.5, mentions: [{ kind: 'discussion', url: '', points: 640 }] };
  const curated = { ...incident('CVE-2026-203', daysAgo(1)), cvss: 7.5, mentions: [{ kind: 'cve_record', url: '' }, { kind: 'curator', url: '' }] };
  const critical = { ...incident('CVE-2026-204', daysAgo(1)), cvss: 9.8 };
  const plain = incident('CVE-2026-205', daysAgo(1));
  assert.deepEqual(ids(filterBoard([plain, critical, curated, hn, kev], [], '', NOW).highlights),
    ['CVE-2026-201', 'CVE-2026-202', 'CVE-2026-203', 'CVE-2026-204']); // the plain 참고 row is not one
});

test('an Incident older than seven days leaves the Highlights and stays in the list', () => {
  const kev = { ...incident('CVE-2026-301', '2026-11-01T12:00:00Z'), kev: true };
  const at = (iso) => filterBoard([kev], [], '', new Date(iso).getTime());
  assert.deepEqual(ids(at('2026-11-08T12:00:00Z').highlights), ['CVE-2026-301']); // exactly seven days
  assert.deepEqual(ids(at('2026-11-08T12:00:01Z').highlights), []);
  assert.deepEqual(ids(at('2026-11-08T12:00:01Z').list), ['CVE-2026-301']);
});

test('Highlights count the seven days from when the news was published, not when the Board first saw it', () => {
  const old = { ...incident('CVE-2026-83844', daysAgo(1)), published: daysAgo(26), cvss: 9.8 };
  const fresh = { ...incident('CVE-2026-1002', daysAgo(1)), cvss: 9.8 }; // no publish time: the first sighting counts
  const { highlights, list } = filterBoard([old, fresh], [], '', NOW);
  assert.deepEqual(ids(highlights), ['CVE-2026-1002']);
  assert.deepEqual(ids(list).sort(), ['CVE-2026-1002', 'CVE-2026-83844']);
});

test('Product picks and search narrow the Highlights too', () => {
  // All four score the same, so they rank newest first: CVE-2024-6387 (1 day old) to CVE-2026-120839 (4 days).
  const recent = board.map((i, n) => ({ ...i, first_seen: daysAgo(n + 1), cvss: 9 }));
  assert.deepEqual(ids(filterBoard(recent, [], '', NOW).highlights), ['CVE-2024-6387', 'CVE-2026-1001', 'CVE-2026-120984', 'CVE-2026-120839']);
  assert.deepEqual(ids(filterBoard(recent, [openssh.id], '', NOW).highlights), ['CVE-2024-6387', 'CVE-2026-1001']);
  assert.deepEqual(ids(filterBoard(recent, [], 'keycloak', NOW).highlights), ['CVE-2026-120984']);
  assert.deepEqual(ids(filterBoard(recent, [keycloak.id], 'race', NOW).highlights), []);
});

test('주요 사건 holds only 위험 or above: a 참고 row stays in the list (user, 2026-11-09)', () => {
  const notice = { ...incident('CVE-2026-601', daysAgo(1)), cvss: 5.3 };
  const high = { ...incident('CVE-2026-602', daysAgo(1)), cvss: 7.1 };
  const { highlights, list } = filterBoard([notice, high], [], '', NOW);
  assert.deepEqual(ids(highlights), ['CVE-2026-602']);
  assert.equal(list.length, 2);
});

test('a story seen only on HN, with no score, is never a Highlight however many points, and stays in the list', () => {
  // The real 2026-11-08 run: general security news with no CVE and no Product filled the Highlights.
  const story = (item, points) => ({ id: `https://news.ycombinator.com/item?id=${item}`, cves: [], first_seen: daysAgo(1),
    mentions: [{ kind: 'discussion', url: `https://news.ycombinator.com/item?id=${item}`, points }, { kind: 'writeup', url: `https://example.com/${item}` }],
    brief: { text: `story ${item}`, lead: '' } });
  const plain = incident('CVE-2026-501', daysAgo(2));
  const { highlights, list } = filterBoard([story(1, 23), story(2, 99), story(3, 100), plain], [], '', NOW);
  assert.deepEqual(ids(highlights), []); // 참고 level: 주요 사건 holds 위험 and above only (user, 2026-11-09)
  assert.equal(list.length, 4);
});

test('the sshole replay Incident becomes a Highlight ahead of ten CVSS 9.8 Incidents', () => {
  // Written by the sshole replay in tests/test_mentions.py (seam 1), which asserts it matches.
  const sshole = JSON.parse(readFileSync(new URL('./fixtures/board/sshole.json', import.meta.url)));
  const critical = Array.from({ length: 10 }, (_, n) => ({ ...incident(`CVE-2026-40${n}`, daysAgo(1)), cvss: 9.8 }));
  const { highlights } = filterBoard([...critical, { ...sshole, cvss: 8.1 }], [], '', NOW); // its NVD score; the fixture is a Brief
  assert.equal(highlights.length, 10);
  assert.equal(highlights[0].id, sshole.id);
});

test('a Product keeps its line colour, and Products spread over the lines', () => {
  assert.equal(productLine('openbsd:openssh'), productLine('openbsd:openssh'));
  assert.ok(LINES.includes(productLine('')));
  // Critique 4: six of ten real Products shared one mint line. Ids as the Board keys them (CPE, CVE record, Summary name).
  const ids = ['openbsd:openssh', 'sonicwall:sonicos', 'name:microsoft paint', 'name:cpython', 'apache:allura', 'apache:axis2',
    'forgerock:access_management', 'infinitewp:infinitewp_client', 'name:hotta studio tower of fantasy', 'name:rrd::cgi::image',
    'name:perl sql::abstract', 'openwrt:openwrt', 'alpinelinux:alpine_linux', 'microsoft:windows', 'python:python',
    'redhat:keycloak', 'dropbear_ssh_project:dropbear_ssh', 'wordpress:wordpress', 'google:chrome', 'mozilla:firefox',
    'apple:safari', 'linux:linux_kernel', 'synology:diskstation_manager', 'tp-link:archer_c6', 'iptime:firmware',
    'fortinet:fortios', 'paloaltonetworks:pan-os', 'cisco:ios_xe', 'ivanti:connect_secure', 'citrix:netscaler',
    'atlassian:confluence', 'gitlab:gitlab', 'jenkins:jenkins', 'apache:tomcat', 'nginx:nginx', 'php:php', 'nodejs:node.js',
    'oracle:java', 'vmware:esxi', 'zyxel:firmware'];
  const per = LINES.map((line) => ids.filter((id) => productLine(id) === line).length);
  assert.ok(Math.max(...per) <= ids.length / 4, `lines hold ${per}`);
});

test('a Product\'s line follows its id, so Korean and English pages colour it the same', () => {
  const paint = { products: [], summary: { products: ['Microsoft Paint'], platforms: ['Windows'],
    ko: { names: ['Windows 그림판'] }, en: { names: ['Microsoft Paint'] }, devices: ['TP-Link Archer'] } };
  const [ko, en] = ['ko', 'en'].map((lang) => lineKeys(paint, lang));
  assert.equal(ko.get('Windows 그림판'), 'name:microsoft paint');
  assert.equal(ko.get('Windows 그림판'), en.get('Microsoft Paint'));
  assert.equal(ko.get('TP-Link Archer'), undefined); // devices have no id: the badge keys by the model name itself
});

// WCAG relative luminance and contrast of two #rrggbb colours.
const lum = (hex) => [1, 3, 5].map((n) => parseInt(hex.slice(n, n + 2), 16) / 255)
  .map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)).reduce((s, c, n) => s + c * [0.2126, 0.7152, 0.0722][n], 0);
const contrast = (a, b) => (Math.max(lum(a), lum(b)) + 0.05) / (Math.min(lum(a), lum(b)) + 0.05);
const hue = (hex) => {
  const [r, g, b] = [1, 3, 5].map((n) => parseInt(hex.slice(n, n + 2), 16) / 255);
  const max = Math.max(r, g, b), d = max - Math.min(r, g, b);
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return { h: (h * 60 + 360) % 360, s: max ? d / max : 0 };
};

test('every line badge reads at AA and never looks like a risk colour (red, amber, grey)', () => {
  for (const { bg, ink } of LINES) {
    assert.ok(contrast(bg, ink) >= 4.5, `${bg} on ${ink}: ${contrast(bg, ink).toFixed(2)}`);
    const { h, s } = hue(bg);
    assert.ok(h > 60 && h < 330 && s > 0.3, `${bg}: hue ${h.toFixed(0)}, saturation ${s.toFixed(2)}`);
  }
});

// OKLab distance: two line colours closer than this read as the same line at badge size (11-08: #0052a4 vs #2e3a8c).
const oklab = (hex) => {
  const [r, g, b] = [1, 3, 5].map((n) => parseInt(hex.slice(n, n + 2), 16) / 255).map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  const [l, m, q] = [[0.4122214708, 0.5363325363, 0.0514459929], [0.2119034982, 0.6806995451, 0.1073969566], [0.0883024619, 0.2817188376, 0.6299787005]]
    .map(([x, y, z]) => Math.cbrt(x * r + y * g + z * b));
  return [0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * q, 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * q, 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * q];
};
test('no two line colours are near twins', () => {
  for (const [n, a] of LINES.entries()) {
    for (const b of LINES.slice(n + 1)) {
      const [x, y] = [oklab(a.bg), oklab(b.bg)];
      const gap = Math.hypot(x[0] - y[0], x[1] - y[1], x[2] - y[2]);
      assert.ok(gap >= 0.13, `${a.bg} and ${b.bg} are ${gap.toFixed(3)} apart`);
    }
  }
});

test('a row\'s age is minutes, hours or days ago, and nothing from 30 days on', () => {
  const now = Date.parse('2026-11-08T12:00:00Z');
  assert.deepEqual(relativeAge('2026-11-08T11:59:50Z', now), { value: -1, unit: 'minute' });
  assert.deepEqual(relativeAge('2026-11-08T12:05:00Z', now), { value: -1, unit: 'minute' }); // clock skew
  assert.deepEqual(relativeAge('2026-11-08T11:01:00Z', now), { value: -59, unit: 'minute' });
  assert.deepEqual(relativeAge('2026-11-08T10:00:00Z', now), { value: -2, unit: 'hour' });
  assert.deepEqual(relativeAge('2026-11-07T11:00:00Z', now), { value: -1, unit: 'day' });
  assert.deepEqual(relativeAge('2026-10-10T12:00:01Z', now), { value: -28, unit: 'day' });
  assert.equal(relativeAge('2026-10-09T12:00:00Z', now), null);
});
test('an attack the sources report counts as exploited, as a KEV listing does', () => {
  const campaign = { ...incident('CVE-2026-5', '2026-11-06T00:00:00Z'), cves: [], summary: { exploited: true, products: [], ...Object.fromEntries(['ko', 'en'].map((l) => [l, { title: '', summary: '', conditions: [], mitigation: '' }])) } };
  const quiet = { ...incident('CVE-2026-6', '2026-11-06T00:00:00Z'), cvss: 5 };
  assert.equal(isExploited(campaign), true);
  assert.equal(isExploited({ ...quiet, kev: true }), true);
  assert.equal(isExploited(quiet), false);
  assert.equal(riskLevel(campaign), 'highest');
  assert.deepEqual(filterBoard([campaign, quiet], [], '', Date.parse('2026-11-07T00:00:00Z'), { kev: true }).list.map((i) => i.id), [campaign.id]);
  // A CVE-less story with few HN points is no Highlight, unless its sources report attacks.
  assert.deepEqual(filterBoard([campaign], [], '', Date.parse('2026-11-07T00:00:00Z')).highlights.map((i) => i.id), [campaign.id]);
});

test('operating systems lead the tags of a row', () => {
  const lib = { summary: { products: ['CPython'], platforms: ['Windows', 'Linux'], devices: [] } };
  assert.deepEqual(rowTags(lib, 'en'), ['Windows', 'Linux', 'CPython']);
});

test('a Product that is also an operating system shows once, as the OS badge', () => {
  const campaign = { summary: { products: ['iOS', 'Android'], platforms: ['iOS', 'Android'], devices: [],
    ko: { names: ['iOS', '안드로이드'] }, en: { names: ['iOS', 'Android'] } } };
  assert.deepEqual(rowTags(campaign, 'ko'), ['Android', 'iOS']);
  assert.deepEqual(rowTags(campaign, 'en'), ['Android', 'iOS']);
});

test('one sort orders both groups: newest first, or by risk, or by score', () => {
  const a = { ...incident('CVE-2026-1', '2026-11-01T00:00:00Z'), cvss: 9.8 };
  const b = { ...incident('CVE-2026-2', '2026-11-03T00:00:00Z'), cvss: 5 };
  const c = { ...incident('CVE-2026-3', '2026-11-02T00:00:00Z'), cvss: 7.5 };
  const ids = (sort) => [a, b, c].sort(orderBy(sort)).map((i) => i.id);
  assert.deepEqual(ids('new'), ['CVE-2026-2', 'CVE-2026-3', 'CVE-2026-1']);
  assert.deepEqual(ids('risk'), ['CVE-2026-1', 'CVE-2026-3', 'CVE-2026-2']);
  assert.deepEqual(ids('cvss'), ['CVE-2026-1', 'CVE-2026-3', 'CVE-2026-2']);
});

test('a Latin display name that is not the product name falls back to it, so one Product reads one way', () => {
  const axis = { summary: { products: ['Apache Axis2/Java'], platforms: [], devices: [], ko: { names: ['Apache Axis2'] }, en: { names: ['Apache Axis2'] } } };
  assert.deepEqual(rowTags(axis, 'ko'), ['Apache Axis2/Java']);
  const paint = { summary: { products: ['Microsoft Paint'], platforms: [], devices: [], ko: { names: ['Windows 그림판'] } } };
  assert.deepEqual(rowTags(paint, 'ko'), ['Windows 그림판']); // a Korean name stays
});

test("one vendor's bulk push folds into one list item from five rows of a day, at the first row's place (user, 2026-11-09)", () => {
  const ibm = (n, day = '2026-11-08') => ({ id: `CVE-2026-${n}`, cves: [`CVE-2026-${n}`], first_seen: `${day}T17:00:00Z`, published: `${day}T16:0${n % 10}:00Z`,
    products: [{ id: `ibm:product_${n}`, name: `Product ${n}` }], mentions: [], brief: { text: '' } });
  const other = { id: 'CVE-2026-900', cves: ['CVE-2026-900'], first_seen: '2026-11-08T17:00:00Z', published: '2026-11-08T16:30:00Z',
    products: [{ id: 'openbsd:openssh', name: 'OpenSSH' }], mentions: [], brief: { text: '' } };
  const rows = [ibm(1), other, ibm(2), ibm(3), ibm(4), ibm(5), ibm(6, '2026-11-07')];
  const items = foldByVendor(rows, 5);
  assert.equal(items.length, 3);
  assert.deepEqual(items[0].incidents.map((i) => i.id), ['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3', 'CVE-2026-4', 'CVE-2026-5']);
  assert.equal(items[0].vendor, 'ibm');
  assert.equal(items[1], other);
  assert.equal(items[2].id, 'CVE-2026-6'); // another day stays a row
  assert.equal(foldByVendor(rows, 6).length, rows.length); // below the minimum nothing folds
  assert.equal(foldByVendor(rows, 0).length, rows.length); // 0 turns the fold off
});

test('search understands the Korean words people use for systems and devices (윈도우, 공유기)', () => {
  const win = { ...incident('CVE-2026-11', '2026-11-08T00:00:00Z'), products: [{ id: 'microsoft:windows_11', name: 'Microsoft Windows 11' }] };
  const router = { ...incident('CVE-2026-12', '2026-11-08T00:00:00Z'), brief: { text: 'Buffer overflow in TP-Link Archer router firmware' } };
  const ids = (q) => filterBoard([win, router], [], q, NOW).list.map((i) => i.id);
  assert.deepEqual(ids('윈도우'), [win.id]);
  assert.deepEqual(ids('공유기'), [router.id]);
  assert.deepEqual(ids('리눅스'), []);
});
