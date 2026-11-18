// A page's raised score (collector: sheets.page_scores, board_view's score_by): one plain line under the Summary on the
// Board and the Incident page, nothing beside the score (owner 11-18).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { scoreByLine } from '../web/board.mjs';
import { pageResponse } from '../edge/page.mjs';

const NOW = Date.parse('2026-11-18T12:00:00Z');
const JAVA = {
  id: 'CVE-2026-114938', cves: ['CVE-2026-114938', 'CVE-2026-114939'], top_cve: 'CVE-2026-114938', first_seen: '2026-11-17T20:00:00Z',
  cvss: 9.2, score_by: { cvss: 9.2, by: 'Calif', record: 8.1 },
  brief: { text: 'Java4Shell', lead: 'https://calif.example/java4shell' },
  mentions: [{ kind: 'advisory', url: 'https://www.oracle.com/security-alerts/cpunov2026.html', title: 'Oracle Critical Patch Update' }],
  products: [{ id: 'oracle:jdk', name: 'Oracle Java SE' }],
  summary: {
    incident: true, products: ['Oracle Java SE'], platforms: [], fixed: '17.0.21.1',
    ko: { title: 'Oracle Java SE Base64 디코더 결함 (Java4Shell)', easy: 'Java 프로그램이 해킹당할 수 있습니다!', summary: 'OpenJDK의 Base64 디코더 결함입니다.', conditions: [], mitigation: '업데이트하세요.' },
    en: { title: 'Oracle Java SE Base64 decoder flaw (Java4Shell)', easy: 'Java programs can be hacked!', summary: "A flaw in OpenJDK's Base64 decoder.", conditions: [], mitigation: 'Update.' },
  },
};

test('the line says whose the raised score is and what the CVE record gives, in three languages', () => {
  assert.equal(scoreByLine(JAVA, 'ko'), '9.2는 Calif에서 매긴 점수입니다. CVE 기록의 점수는 8.1입니다.');
  assert.equal(scoreByLine(JAVA, 'en'), "The 9.2 score is Calif's. The CVE record gives 8.1.");
  assert.equal(scoreByLine(JAVA, 'ja'), '9.2 は Calif が付けたスコアです。CVE レコードのスコアは 8.1 です。');
});

test('no line without a page raise, or when the shown score is no longer the raised one', () => {
  const { score_by: _, ...plain } = JAVA;
  assert.equal(scoreByLine(plain, 'ko'), '');
  assert.equal(scoreByLine({ ...JAVA, cvss: 9.8 }, 'en'), ''); // a later, higher record score is shown
  assert.equal(scoreByLine({ ...JAVA, score_by: { cvss: 9.2, by: '', record: 8.1 } }, 'en'), '');
  assert.equal(scoreByLine({ ...JAVA, score_by: { cvss: 9.2, by: 'Calif' } }, 'en'), '');
});

const page = async (doc, lang) => pageResponse({ get: async (key) => (key === `pages/${JAVA.id}.json` ? { text: async () => JSON.stringify(doc) } : null) },
  lang, JAVA.id, NOW).then((res) => res.text());

test('the Incident page puts the line right after the summary text, as plain body text', async () => {
  const html = await page(JAVA, 'en');
  assert.match(html, /<p class="label" id="s-summary">Summary<\/p><p>A flaw in OpenJDK&apos;s Base64 decoder.<\/p><p class="score-by">The 9.2 score is Calif&apos;s. The CVE record gives 8.1.<\/p><\/section>/);
  assert.match(html, /\.score-by\{color:var\(--ink-2\)\}/);
  const { score_by: _, ...plain } = JAVA;
  assert.doesNotMatch(await page(plain, 'ko'), /class="score-by"/);
});
