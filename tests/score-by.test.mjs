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

test('a raised score shows both scores with their CVSS versions, higher first, only when both versions are known and differ', () => {
  assert.equal(scorePair(JAVA), 'CVSS 4.0 9.2 / CVSS 3.1 8.1');
  // SonicWall (11-18): the page wrote "CVSS Score: 5.2", no version: the line stays "CVSS 5.2 · CVE-…".
  assert.equal(scorePair({ ...JAVA, cvss: 5.2, score_by: { cvss: 5.2, version: '', record: 5.1, record_version: '3.1' } }), '');
  assert.equal(scorePair({ ...JAVA, score_by: { ...JAVA.score_by, version: '3.1' } }), ''); // the same standard twice
});

test('no pair without a page raise, or when the shown score is no longer the raised one', () => {
  assert.equal(scorePair(PLAIN), '');
  assert.equal(scorePair({ ...JAVA, cvss: 9.8 }), ''); // a later, higher record score is shown
  assert.equal(scorePair({ ...JAVA, score_by: { cvss: 9.2, version: '4.0' } }), '');
});

const page = async (doc, lang) => pageResponse({ get: async (key) => (key === `pages/${JAVA.id}.json` ? { text: async () => JSON.stringify(doc) } : null) },
  lang, JAVA.id, NOW).then((res) => res.text());

test('the Incident page states the pair where it states the score, the same in every language', async () => {
  // Owner, 11-27: among the opened row's facts, as the Board says it ("CVSS 4.0 9.2 / CVSS 3.1 8.1 · CVE-…").
  assert.match(await page(JAVA, 'en'), /<dt>Score<\/dt><dd>CVSS 4.0 9.2 \/ CVSS 3.1 8.1 · CVE-2026-114938<\/dd>/);
  assert.match(await page(JAVA, 'ko'), /<dt>점수<\/dt><dd>CVSS 4.0 9.2 \/ CVSS 3.1 8.1 · CVE-2026-114938<\/dd>/);
  assert.match(await page(JAVA, 'ja'), /<dt>スコア<\/dt><dd>CVSS 4.0 9.2 \/ CVSS 3.1 8.1 · CVE-2026-114938<\/dd>/);
  assert.match(await page(PLAIN, 'en'), /<dt>Score<\/dt><dd>CVSS 9.2 · CVE-2026-114938<\/dd>/); // as before
  // One CVE: no CVE beside the score; a raised one gets the pair, a plain one its score (owner 11-19: every scored row).
  const one = { ...JAVA, cves: ['CVE-2026-114938'], top_cve: undefined };
  assert.match(await page(one, 'en'), /<dt>Score<\/dt><dd>CVSS 4.0 9.2 \/ CVSS 3.1 8.1<\/dd>/);
  const { score_by: __, ...plainOne } = one;
  assert.match(await page(plainOne, 'en'), /<dt>Score<\/dt><dd>CVSS 9.2<\/dd>/);
});
