// The RSS feeds' renderer and response (ticket incident-pages/01), behind a fake R2 binding.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { feedResponse } from '../edge/feed.mjs';
import { slug } from '../web/board.mjs';

const bucket = (doc) => ({ get: async (key) => (key === 'board/feed.json' && doc ? { text: async () => JSON.stringify(doc) } : null) });

const SSHOLE = {
  id: 'CVE-2026-123158', cves: ['CVE-2026-123158'], first_seen: '2026-11-06T00:46:00Z', published: '2026-11-05T10:00:00Z',
  brief: { text: 'sshole' },
  summary: {
    ko: { title: 'OpenSSH sshd 인증 우회 (sshole)', easy: '리눅스 서버가 뚫릴 수 있습니다!', summary: 'musl 기반에서만 해당합니다.', mitigation: '9.9p2로 업데이트하세요.' },
    en: { title: 'OpenSSH sshd authentication bypass (sshole)', easy: 'Linux servers can be broken into!', summary: 'Only musl-based systems.', mitigation: 'Update to 9.9p2.' },
  },
};
const STORY = { id: 'https://news.ycombinator.com/item?id=50378228', cves: [], first_seen: '2026-11-05T09:00:00Z', brief: { text: 'sshole' } };

test('slugs never change: a CVE ID as is, an HN story by its item, any other URL by a short hash', async () => {
  assert.equal(await slug('CVE-2026-123158'), 'CVE-2026-123158');
  assert.equal(await slug(STORY.id), 'hn-50378228');
  const other = await slug('https://www.bleepingcomputer.com/news/security/nikke/');
  assert.match(other, /^u-[0-9a-f]{12}$/);
  assert.equal(other, await slug('https://www.bleepingcomputer.com/news/security/nikke/'));
});

test('the Korean and English feeds carry each Incident in their language, linked to their Incident pages', async () => {
  const doc = { incidents: [SSHOLE, STORY] };
  const ko = await (await feedResponse(bucket(doc), 'ko')).text();
  assert.match(ko, /<language>ko<\/language>/);
  assert.match(ko, /<title>OpenSSH sshd 인증 우회 \(sshole\)<\/title>/);
  assert.match(ko, /<link>https:\/\/patchticker.com\/i\/CVE-2026-123158<\/link>/);
  assert.match(ko, /<guid isPermaLink="false">https:\/\/patchticker.com\/i\/CVE-2026-123158<\/guid>/);
  assert.match(ko, /<pubDate>Thu, 05 Nov 2026 10:00:00 GMT<\/pubDate>/);
  assert.match(ko, /&lt;b&gt;대처법:&lt;\/b&gt; 9.9p2로 업데이트하세요./);
  assert.match(ko, /<link>https:\/\/patchticker.com\/i\/hn-50378228<\/link>/);
  const en = await (await feedResponse(bucket(doc), 'en')).text();
  assert.match(en, /<atom:link href="https:\/\/patchticker.com\/en\/feed.xml"/);
  assert.match(en, /<guid isPermaLink="false">https:\/\/patchticker.com\/en\/i\/hn-50378228<\/guid>/); // unchanged since ticket 01
  assert.match(en, /<link>https:\/\/patchticker.com\/en\/i\/hn-50378228<\/link>/);
  assert.match(en, /<title>sshole<\/title>/); // no Summary: the Brief
});

test('the GUID stays when the Summary is rewritten', async () => {
  const before = await (await feedResponse(bucket({ incidents: [SSHOLE] }), 'ko')).text();
  const rewritten = { ...SSHOLE, summary: { ...SSHOLE.summary, ko: { ...SSHOLE.summary.ko, title: '새 제목' } } };
  const after = await (await feedResponse(bucket({ incidents: [rewritten] }), 'ko')).text();
  const guid = (xml) => /<guid[^>]*>([^<]*)<\/guid>/.exec(xml)[1];
  assert.equal(guid(after), guid(before));
});

test('hostile text from a source cannot break out of the feed', async () => {
  const hostile = { ...SSHOLE, summary: { ...SSHOLE.summary, ko: { title: '</title><script>alert(1)</script>', easy: '<img src=x onerror=alert(1)>' } } };
  const xml = await (await feedResponse(bucket({ incidents: [hostile] }), 'ko')).text();
  assert.doesNotMatch(xml, /<script>|<img /);
  assert.match(xml, /&lt;\/title&gt;&lt;script&gt;/);
  assert.match(xml, /&amp;lt;img src=x onerror=alert\(1\)&amp;gt;/); // escaped inside the escaped HTML body
});

test('answers RSS with a short cache, and 503 when the store cannot be read', async () => {
  const ok = await feedResponse(bucket({ incidents: [] }), 'ko');
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('content-type'), 'application/rss+xml; charset=utf-8');
  assert.match(ok.headers.get('cache-control'), /max-age=300/);
  assert.equal((await feedResponse(bucket(null), 'ko')).status, 503);
  assert.equal((await feedResponse({ get: async () => { throw new Error('R2 down'); } }, 'en')).status, 503);
});
