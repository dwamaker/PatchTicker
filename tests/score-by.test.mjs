// A score a page raised (collector: sheets.page_scores, board_view's score_by) shows both standards' scores where the
// score is already stated in text, higher first: "CVSS 4.0 9.2 / CVSS 3.1 8.1" (owner 11-18).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { scorePair } from '../web/board.mjs';
import { pageResponse } from '../edge/page.mjs';

const NOW = Date.parse('2026-11-18T12:00:00Z');
const JAVA = {
  id: 'CVE-2026-114938', cves: ['CVE-2026-114938', 'CVE-2026-114939'], top_cve: 'CVE-2026-114938', first_seen: '2026-11-17T20:00:00Z',
  cvss: 9.2, score_by: { cvss: 9.2, version: '4.0', record: 8.1, record_version: '3.1' },
  brief: { text: 'Java4Shell', lead: 'https://calif.example/java4shell' },
  mentions: [{ kind: 'advisory', url: 'https://www.oracle.com/security-alerts/cpunov2026.html', title: 'Oracle Critical Patch Update' }],
  products: [{ id: 'oracle:jdk', name: 'Oracle Java SE' }],
  summary: {
    incident: true, products: ['Oracle Java SE'], platforms: [], fixed: '17.0.21.1',
    ko: { title: 'Oracle Java SE Base64 디코더 결함 (Java4Shell)', easy: 'Java 프로그램이 해킹당할 수 있습니다!', summary: 'OpenJDK의 Base64 디코더 결함입니다.', conditions: [], mitigation: '업데이트하세요.' },
    en: { title: 'Oracle Java SE Base64 decoder flaw (Java4Shell)', easy: 'Java programs can be hacked!', summary: "A flaw in OpenJDK's Base64 decoder.", conditions: [], mitigation: 'Update.' },
  },
};
const { score_by: _, ...PLAIN } = JAVA;

test('a raised score shows both scores with their CVSS versions, higher first; an unknown version is "CVSS" alone', () => {
  assert.equal(scorePair(JAVA), 'CVSS 4.0 9.2 / CVSS 3.1 8.1');
  assert.equal(scorePair({ ...JAVA, score_by: { ...JAVA.score_by, version: '', record_version: '' } }), 'CVSS 9.2 / CVSS 8.1');
});

test('no pair without a page raise, or when the shown score is no longer the raised one', () => {
  assert.equal(scorePair(PLAIN), '');
  assert.equal(scorePair({ ...JAVA, cvss: 9.8 }), ''); // a later, higher record score is shown
  assert.equal(scorePair({ ...JAVA, score_by: { cvss: 9.2, version: '4.0' } }), '');
});

const page = async (doc, lang) => pageResponse({ get: async (key) => (key === `pages/${JAVA.id}.json` ? { text: async () => JSON.stringify(doc) } : null) },
  lang, JAVA.id, NOW).then((res) => res.text());

test('the Incident page states the pair where it states the score, the same in every language', async () => {
  assert.match(await page(JAVA, 'en'), /<p class="reason">Score of CVE-2026-114938: CVSS 4.0 9.2 \/ CVSS 3.1 8.1<\/p>/);
  assert.match(await page(JAVA, 'ko'), /<p class="reason">CVE-2026-114938의 점수: CVSS 4.0 9.2 \/ CVSS 3.1 8.1<\/p>/);
  assert.match(await page(JAVA, 'ja'), /<p class="reason">CVE-2026-114938 のスコア: CVSS 4.0 9.2 \/ CVSS 3.1 8.1<\/p>/);
  assert.match(await page(PLAIN, 'en'), /<p class="reason">Score of CVE-2026-114938: CVSS 9.2<\/p>/); // as before
  // One CVE: no "Score of" line before; a raised one gets the pair alone, a plain one still nothing.
  const one = { ...JAVA, cves: ['CVE-2026-114938'], top_cve: undefined };
  assert.match(await page(one, 'en'), /<p class="reason">CVSS 4.0 9.2 \/ CVSS 3.1 8.1<\/p>/);
  const { score_by: __, ...plainOne } = one;
  assert.doesNotMatch(await page(plainOne, 'en'), /<p class="reason">CVSS/);
});
