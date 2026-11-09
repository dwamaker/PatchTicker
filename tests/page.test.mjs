// Incident pages (ticket incident-pages/02): a request's slug plus a fake R2 binding in, a Response out.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { slug } from '../edge/feed.mjs';
import { pageResponse } from '../edge/page.mjs';

const NOW = Date.parse('2026-11-09T12:00:00Z');
const reads = [];
const bucket = (docs) => ({ get: async (key) => { reads.push(key); return key in docs ? { text: async () => JSON.stringify(docs[key]) } : null; } });
const page = async (doc, lang = 'ko', name = 'CVE-2026-123158') => pageResponse(bucket({ [`pages/${name}.json`]: doc }), lang, name, NOW);

const SSHOLE = {
  id: 'CVE-2026-123158', cves: ['CVE-2026-123158'], first_seen: '2026-11-06T00:46:00Z', published: '2026-11-05T10:00:00Z', cvss: 9.8,
  kev: true, kev_date: '2026-11-07',
  brief: { text: 'sshole', lead: 'https://www.openssh.com/txt/release-9.9p2' },
  mentions: [
    { kind: 'advisory', url: 'https://www.openssh.com/txt/release-9.9p2', title: 'OpenSSH 9.9p2 release notes' },
    { kind: 'cve_record', url: 'https://www.cve.org/CVERecord?id=CVE-2026-123158' },
    { kind: 'notice', url: 'https://www.boho.or.kr/kr/bbs/view.do?nttId=71234', title: 'OpenSSH 보안 업데이트 권고' },
  ],
  products: [{ id: 'openbsd:openssh', name: 'OpenSSH' }],
  summary: {
    incident: true, products: ['OpenSSH'], platforms: ['Linux'], command: 'sudo apk upgrade openssh', fixed: '9.9p2', stopgap: 'PasswordAuthentication no', stopgap_file: '/etc/ssh/sshd_config',
    ko: { title: 'OpenSSH sshd 인증 우회 (sshole)', easy: '리눅스 서버가 뚫릴 수 있습니다!', summary: 'musl 기반에서만 해당합니다.', conditions: ['Alpine 리눅스에서 sshd를 켜 둔 경우'], mitigation: '9.9p2로 업데이트하세요.' },
    en: { title: 'OpenSSH sshd authentication bypass (sshole)', easy: 'Linux servers can be broken into!', summary: 'Only musl-based systems.', conditions: ['sshd runs on Alpine Linux'], mitigation: 'Update to 9.9p2.' },
  },
};
const NOTICE = { ...SSHOLE, id: 'CVE-2026-55555', cves: ['CVE-2026-55555'], cvss: 5.3, kev: false, kev_date: undefined };

test('slugs match the collector: one shared fixture', async () => {
  const kase = JSON.parse(readFileSync(new URL('./fixtures/board/slug-case.json', import.meta.url), 'utf8'));
  for (const c of kase.cases) assert.equal(await slug(c.id), c.slug, c.id);
});

test('the Korean page names itself canonical, links the English one and previews the Incident', async () => {
  const res = await page(SSHOLE);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.match(res.headers.get('cache-control'), /public, max-age=300/);
  const html = await res.text();
  assert.match(html, /<html lang="ko">/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/i\/CVE-2026-123158">/);
  assert.match(html, /<link rel="alternate" hreflang="ko" href="https:\/\/patchticker.com\/i\/CVE-2026-123158">/);
  assert.match(html, /<link rel="alternate" hreflang="en" href="https:\/\/patchticker.com\/en\/i\/CVE-2026-123158">/);
  assert.match(html, /<link rel="alternate" hreflang="x-default" href="https:\/\/patchticker.com\/i\/CVE-2026-123158">/);
  assert.match(html, /<meta property="og:title" content="OpenSSH sshd 인증 우회 \(sshole\)">/);
  assert.match(html, /<meta property="og:description" content="리눅스 서버가 뚫릴 수 있습니다!">/);
  assert.match(html, /<meta property="og:image" content="https:\/\/patchticker.com\/og.png">/);
  assert.match(html, /<meta property="og:locale" content="ko_KR">/);
  assert.doesNotMatch(html, /noindex/); // exploited: search-worthy
  assert.doesNotMatch(html, /<script/i);
  assert.equal(html.match(/<h1/g).length, 1);
  assert.match(html, /<h1>OpenSSH sshd 인증 우회 \(sshole\)<\/h1>/);
});

test('the page shows what the Board panel shows, with the Board rules', async () => {
  const html = await (await page(SSHOLE)).text();
  assert.match(html, />고위험</); // riskLevel: KEV
  assert.match(html, /악용 발생/);
  assert.match(html, /CISA KEV 등재 · 2026-11-07/); // exploitReason
  assert.match(html, /9\.8/);
  assert.match(html, /musl 기반에서만 해당합니다\./);
  assert.match(html, /Alpine 리눅스에서 sshd를 켜 둔 경우/);
  assert.match(html, /<code>sudo apk upgrade openssh<\/code>/); // easyAction: the command
  assert.match(html, /<code>PasswordAuthentication no<\/code>/); // the stopgap, a config line
  assert.match(html, /\/etc\/ssh\/sshd_config/);
  assert.match(html, />Linux</);
  assert.match(html, />OpenSSH</);
  assert.match(html, /href="https:\/\/www.cve.org\/CVERecord\?id=CVE-2026-123158"/);
  assert.match(html, /보호나라 공지[\s\S]*OpenSSH 보안 업데이트 권고/); // the KISA notice among the Mentions
  assert.match(html, /<time datetime="2026-11-05T10:00:00Z">2026-11-05 19:00/); // published, Korean time
  assert.match(html, /<time datetime="2026-11-06T00:46:00Z">/); // first seen
  assert.match(html, /href="\/#i=CVE-2026-123158"/); // open on the Board
  assert.match(html, /href="\/en\/i\/CVE-2026-123158" hreflang="en" lang="en">English</);
  assert.match(html, /href="https:\/\/github.com\/dwamaker\/PatchTicker\/issues\/new\?[^"]*"/);
  assert.match(html, /NVD API/);
  assert.match(html, /The MITRE Corporation/);
});

test('the English page is the English Summary, canonical to itself', async () => {
  const html = await (await page(SSHOLE, 'en')).text();
  assert.match(html, /<html lang="en">/);
  assert.match(html, /<link rel="canonical" href="https:\/\/patchticker.com\/en\/i\/CVE-2026-123158">/);
  assert.match(html, /<link rel="alternate" hreflang="x-default" href="https:\/\/patchticker.com\/i\/CVE-2026-123158">/);
  assert.match(html, /<h1>OpenSSH sshd authentication bypass \(sshole\)<\/h1>/);
  assert.match(html, /<meta property="og:locale" content="en_US">/);
  assert.match(html, />High risk</);
  assert.match(html, /Listed in CISA KEV/);
  assert.match(html, /<time datetime="2026-11-05T10:00:00Z">2026-11-05 10:00 UTC/);
  assert.match(html, /href="\/i\/CVE-2026-123158" hreflang="ko" lang="ko">한국어</);
});

test('a 참고 page with a CVE is for sharing only: noindex', async () => {
  const html = await (await page(NOTICE, 'ko', 'CVE-2026-55555')).text();
  assert.match(html, /<meta name="robots" content="noindex">/);
  assert.match(html, />참고</);
});

test('hostile text is escaped and only http(s) links are kept', async () => {
  const hostile = {
    ...SSHOLE, kev: false,
    mentions: [{ kind: 'advisory', url: 'javascript:alert(1)', title: 'click me' }, { kind: 'writeup', url: 'https://example.com/"><script>x</script>', title: '<img src=x onerror=alert(1)>' }],
    summary: { ...SSHOLE.summary, exploited: true, exploited_source: 'javascript:alert(2)', ko: { ...SSHOLE.summary.ko, title: '</title><script>alert(1)</script>', easy: '"><script>alert(3)</script>' } },
  };
  const html = await (await page(hostile)).text();
  assert.doesNotMatch(html, /<script|<img /i);
  assert.doesNotMatch(html, /javascript:/i);
  assert.match(html, /&lt;\/title&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /href="https:\/\/example.com\/&quot;&gt;&lt;script&gt;x&lt;\/script&gt;"/);
});

test('410 past 90 days from first seen, with the Board and the CVE record', async () => {
  const res = await page({ ...SSHOLE, first_seen: '2026-08-10T00:00:00Z' });
  assert.equal(res.status, 410);
  const html = await res.text();
  assert.match(html, /보관 기간 90일이 지났어요/);
  assert.match(html, /href="\/#i=CVE-2026-123158"/);
  assert.match(html, /href="https:\/\/www.cve.org\/CVERecord\?id=CVE-2026-123158"/);
  assert.match(html, /noindex/);
  assert.equal((await page({ ...SSHOLE, first_seen: '2026-08-12T00:00:00Z' })).status, 200);
});

test('404 for an unknown slug, a malformed one (no store read) and an Incident that is not on the Board', async () => {
  assert.equal((await pageResponse(bucket({}), 'ko', 'CVE-2026-99999', NOW)).status, 404);
  reads.length = 0;
  assert.equal((await pageResponse(bucket({}), 'en', '../board/feed', NOW)).status, 404);
  assert.deepEqual(reads, []);
  const essay = { ...SSHOLE, id: 'https://news.ycombinator.com/item?id=77', cves: [], summary: { ...SSHOLE.summary, incident: false } };
  assert.equal((await page(essay, 'ko', 'hn-77')).status, 404);
  assert.equal((await page({ ...SSHOLE, summary: undefined })).status, 404);
});

test('503 when the store cannot be read', async () => {
  const res = await pageResponse({ get: async () => { throw new Error('R2 down'); } }, 'ko', 'CVE-2026-123158', NOW);
  assert.equal(res.status, 503);
  assert.match(await res.text(), /patchticker.com/);
});
