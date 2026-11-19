// The one search bar's Product suggestions (owner, 11-19, after Astryx PowerSearch / Tokenizer): pickerEntries and
// rankEntries in web/board.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { familyName, pickerEntries, productKey, rankEntries } from '../web/board.mjs';

const named = (list) => list.map((p) => ({ id: p.id, name: p.en }));
const fixture = named(JSON.parse(readFileSync(new URL('./fixtures/board/picker-case.json', import.meta.url))).products);
const entryOf = (entries, id) => entries.find((e) => e.ids.includes(id));

test('a platform tail drops out of the name, from the closed list only', () => {
  assert.equal(familyName('.NET 10.0 installed on Mac OS'), '.NET 10.0');
  assert.equal(familyName('Red Hat JBoss Enterprise Application Platform 8.1 for RHEL 9'), 'Red Hat JBoss Enterprise Application Platform 8.1');
  assert.equal(familyName('Microsoft SQL Server 2025 for x64-based Systems (CU9)'), 'Microsoft SQL Server 2025');
  for (const keep of ['Telerik UI for Blazor', 'Snowflake Connector for .NET', 'Firefox for iOS', 'Dell Terraform Provider for PowerStore'])
    assert.equal(familyName(keep), keep);
});

test('the .NET platform names are one entry per version, holding every id', () => {
  const entries = pickerEntries(fixture);
  const net = entries.filter((e) => e.name.startsWith('.NET'));
  assert.deepEqual(net.map((e) => e.name), ['.NET 10.0', '.NET 11.0', '.NET 8.0', '.NET 9.0']);
  assert.deepEqual(entryOf(entries, 'microsoft:.net_10.0_installed_on_mac_os').ids.sort(),
    ['microsoft:.net_10.0_installed_on_linux', 'microsoft:.net_10.0_installed_on_mac_os', 'microsoft:.net_10.0_installed_on_windows']);
});

test('names that only look alike stay apart', () => {
  const entries = pickerEntries(fixture);
  const apart = [['progress_software:telerik_ui_for_blazor', 'progress_software:telerik_ui_for_wpf'],
    ['snowflake:snowflake_connector_for_.net', 'snowflake:snowflake_connector_for_python'],
    ['mozilla:firefox', 'mozilla:firefox_for_ios'],
    ['microsoft:.net_10.0_installed_on_linux', 'microsoft:.net_11.0_installed_on_linux'],
    ['microsoft:microsoft_sql_server_2017_(gdr)', 'microsoft:microsoft_sql_server_2019_(gdr)'],
    ['automattic:mongoose', 'cesanta:mongoose']]; // two vendors' Mongoose are two Products
  for (const [a, b] of apart) assert.notEqual(entryOf(entries, a), entryOf(entries, b), `${a} / ${b}`);
});

test('one vendor\'s spellings and a Summary-named id join one entry', () => {
  const entries = pickerEntries(fixture);
  const ps = entryOf(entries, 'adobe:photoshop');
  assert.deepEqual(ps.ids.sort(), ['adobe:adobe_photoshop', 'adobe:photoshop', 'name:photoshop']);
  assert.equal(ps.name, 'Adobe Photoshop');
  const sql25 = entryOf(entries, 'microsoft:microsoft_sql_server_2025_cu10');
  assert.equal(sql25, entryOf(entries, 'microsoft:microsoft_sql_server_2025_for_x64-based_systems_(gdr)'));
  assert.equal(sql25.name, 'Microsoft SQL Server 2025');
  assert.equal(entryOf(entries, 'microsoft:microsoft_sql_server_2019_(gdr)'), entryOf(entries, 'microsoft:microsoft_sql_server_2019_for_x64-based_systems_(cu32)'));
  const win = pickerEntries([{ id: 'microsoft:windows_10_1607', name: 'Windows 10 1607' }, { id: 'microsoft:windows_10_version_1607', name: 'Windows 10 Version 1607' }]);
  assert.equal(win.length, 1);
});

test('counts add up per entry and order equal ranks', () => {
  const entries = pickerEntries(fixture, { 'microsoft:.net_10.0_installed_on_linux': 2, 'microsoft:.net_10.0_installed_on_windows': 3, 'microsoft:.net_9.0_installed_on_linux': 9 });
  assert.equal(entryOf(entries, 'microsoft:.net_10.0_installed_on_mac_os').n, 5);
  assert.deepEqual(rankEntries(entries, '.net').slice(0, 2).map((e) => e.name), ['.NET 9.0', '.NET 10.0']);
});

test('ranked suggestions: whole name, then start, then a word inside, at most ten', () => {
  const entries = [{ name: 'OpenSSH', n: 0 }, { name: 'OpenSSH Server Toolkit', n: 0 }, { name: 'Portable OpenSSH', n: 4 }, { name: 'libssh', n: 9 }]
    .map((e, k) => ({ ...e, key: String(k), ids: [String(k)] }));
  assert.deepEqual(rankEntries(entries, 'openssh').map((e) => e.name), ['OpenSSH', 'OpenSSH Server Toolkit', 'Portable OpenSSH']);
  assert.deepEqual(rankEntries(entries, 'ssh').map((e) => e.name), ['libssh', 'Portable OpenSSH', 'OpenSSH', 'OpenSSH Server Toolkit']);
  assert.deepEqual(rankEntries(entries, '  '), []);
  const many = Array.from({ length: 30 }, (_, k) => ({ key: String(k), name: `Tool ${k}`, ids: [String(k)], n: 0 }));
  assert.equal(rankEntries(many, 'tool').length, 10);
});

test('a Korean name the search knows suggests the English Product', () => {
  const entries = pickerEntries(fixture);
  assert.equal(rankEntries(entries, '크롬')[0]?.name, 'Google Chrome');
});

// The real list (git-ignored web/data, present where the preview runs): no suggestion keeps a platform tail.
const real = new URL('../web/data/board/products.json', import.meta.url);
test('the real Product list has no "installed on" suggestion and fewer entries than ids', { skip: !existsSync(real) }, () => {
  const products = named(JSON.parse(readFileSync(real)).products);
  const entries = pickerEntries(products);
  assert.deepEqual(entries.filter((e) => / installed on /i.test(e.name)).map((e) => e.name), []);
  assert.ok(entries.length < products.length);
  assert.deepEqual(rankEntries(entries, '.net 10').map((e) => e.name), ['.NET 10.0']);
});

// pickerEntries looks a named Product's family up in a Map (audit 11-19: the scan over every group key made the first row
// open 2x slower than live). The scan it replaced, kept here as the reference: both must give the same entries.
function scanEntries(products, counts = {}) {
  const own = (name) => productKey(name.replace(/\bversion\s+(?=\d)/giu, ''));
  const groups = new Map();
  const add = (key, p, name) => {
    const entry = groups.get(key) || groups.set(key, { key, name, ids: [], n: 0, os: p.id.startsWith('os:') }).get(key);
    entry.ids.push(p.id);
    entry.n += counts[p.id] || 0;
    if (name.length > entry.name.length) entry.name = name;
  };
  const named = [];
  for (const p of products) {
    const name = familyName(p.name);
    if (p.id.startsWith('os:')) add(p.id, p, p.name);
    else if (p.id.startsWith('name:')) named.push([p, name]);
    else add(`${p.id.split(':')[0]}|${own(name)}`, p, name);
  }
  for (const [p, name] of named) {
    const key = own(name);
    const vendors = [...groups.keys()].filter((k) => k.slice(k.indexOf('|') + 1) === key && !k.startsWith('os:'));
    add(vendors.length === 1 ? vendors[0] : `name|${key}`, p, name);
  }
  return [...groups.values()].sort((a, b) => a.name.localeCompare(b.name) || a.key.localeCompare(b.key));
}
const others = new URL('../web/data/board/others.json', import.meta.url);
test('the Map lookup gives the same entries as the scan it replaced', () => {
  assert.deepEqual(pickerEntries(fixture), scanEntries(fixture));
});
test('… and on the real Product list, in both languages, with counts', { skip: !existsSync(real) }, () => {
  const list = JSON.parse(readFileSync(real)).products;
  const counts = existsSync(others) ? JSON.parse(readFileSync(others)).counts : {};
  for (const lang of ['en', 'ko']) {
    const products = list.map((p) => ({ id: p.id, name: p[lang] || p.en }));
    assert.ok(products.some((p) => p.id.startsWith('name:')));
    assert.deepEqual(pickerEntries(products, counts), scanEntries(products, counts));
  }
});
test('a Summary-named Product joins its one vendor, stays apart from two, and shares a name-only entry', () => {
  const products = [
    { id: 'adobe:photoshop', name: 'Photoshop' }, { id: 'name:photoshop', name: 'Photoshop' }, // one vendor: joins it
    { id: 'a:widget', name: 'Widget' }, { id: 'b:widget', name: 'Widget' }, { id: 'name:widget', name: 'Widget' }, // two
    { id: 'name:gizmo_9', name: 'Gizmo 9' }, { id: 'name:gizmo_version_9', name: 'Gizmo Version 9' }, // no vendor: one entry
  ];
  const entries = pickerEntries(products);
  assert.deepEqual(entries, scanEntries(products));
  assert.equal(entryOf(entries, 'name:photoshop').key, 'adobe|photoshop');
  assert.ok(entryOf(entries, 'name:widget').key.startsWith('name|'));
  assert.equal(entryOf(entries, 'name:gizmo_9'), entryOf(entries, 'name:gizmo_version_9'));
});
