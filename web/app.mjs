import { WORDPRESS, pluginName, aliasesUsed, exploitReason, isLibrary, namedHeadline, knownVendor, vendorLedTitle, vendorName, foldByVendor, uniqueNames, matchProducts, mergeIncidents, LINK_KINDS, OSES, PINNED, RISKS, SORTS, pinReason, briefMarker, cveHead, easyLine, easyTitle, isShellCommand, MANY_DEVICES, onBoard, cvssRating, easyAction, filterBoard, isExploited, lineKeys, orderBy, filterFromQuery, filterToQuery, productLine, productList, publishedAt, relativeAge, riskLevel, rowTags, viewFromStorage } from './board.mjs';

// The store's base URL: web/data/ on this machine, the R2 bucket's own domain everywhere else.
const DATA_URL = ['localhost', '127.0.0.1'].includes(location.hostname) ? 'data/' : 'https://patchticker-data.dwamaker.com/';
const SAVED = 'vr-filter';
const SAVED_LANG = 'vr-lang';
const SAVED_VIEW = 'vr-view';
const SAVED_FOLD = 'vr-fold'; // 'off': the visitor ungrouped vendor folds (묶음 풀기)
// Where the visitor was, kept for this tab only: a reload comes back to the same rows and the same place.
const SAVED_PLACE = 'vr-place';
const reloaded = ['reload', 'back_forward'].includes(performance.getEntriesByType('navigation')[0]?.type);
history.scrollRestoration = 'manual'; // the browser would restore it before the rows arrive, i.e. to the top
// Also read by the inline script in index.html's head, so the remembered theme applies before first paint.
const SAVED_THEME = 'vr-theme';
// Every UI string, per language: the visitor's toggle, else the browser's language.
// Only CVE IDs, Product names, URLs and source data (the Brief's own line, Mention titles) are shown as they come.
// The NVD notice keeps its required English sentence in index.html; `nvd` is the Korean line beside it.
const TEXT = {
  ko: {
    other: 'English', otherShort: 'EN', brand: 'Patch Ticker', title: 'Patch Ticker · 보안 취약점 게시판', loading: '불러오는 중…',
    notListed: (text) => `제품 목록에 없는 이름이라 검색어로 찾았습니다: ${text}`,
    variants: (n) => `비슷한 이름 ${n}건도 함께 보여 줍니다.`, manyProducts: (n) => `맞는 제품이 ${n}개입니다. 목록에서 하나를 고르세요.`,
    loadDetail: (msg) => `자세한 내용: ${msg}`, olderDone: (n) => (n ? `최근 3개월 사건을 모두 불러왔습니다 (${n}건 추가).` : '최근 3개월 사건을 모두 불러왔습니다. 이미 보이는 것 말고는 더 없습니다.'),
    loadError: '게시판을 불러오지 못했습니다. 인터넷 연결을 확인하고 다시 시도하세요.', retry: '다시 시도', filterBtn: '필터', fp: { title: '필터', from: '게시일 시작', to: '게시일 끝', cvss: '최소 CVSS 점수', cve: 'CVE 번호', any: '전체', cveYes: 'CVE 번호 있음', cveNo: 'CVE 번호 아직 없음', risk: '위험 단계', flags: '공격·공지 여부', has: { advisory: '공식 공지 있음', repo: '공격 코드 공개됨' }, sort: '정렬', sorts: { new: '최신순', risk: '위험도순', cvss: 'CVSS 높은순' }, close: '닫기', reset: '필터 초기화', apply: '필터 적용', applyN: (n) => `필터 적용 · ${n}건`, zeroChip: '이 조건을 더하면 0건이 됩니다', riskNote: '점수 대기 사건은 실제 공격이 아니면 참고에 들어 있습니다.', osNote: '고른 운영체제에서 돌아가는 프로그램이 모두 나옵니다. 워드프레스 플러그인처럼 어디서나 도는 웹 프로그램도 함께 나옵니다.', zeroNote: '점선 칩은 지금 조건에 더하면 0건이 되는 칩입니다.', dropCond: (l) => `‘${l}’ 빼기` }, textSizeGroup: '글자 크기', textGlyph: '가', textDown: '글자 작게', textUp: '글자 크게', textNow: (p) => `글자 크기 ${p}%`, pinMore: (n) => `주요 사건 더 보기 (${n})`, pinLess: '주요 사건 접기', qfKev: '악용 발생만', noneForFilters: '고른 조건에 맞는 사건이 지금 게시판에 없습니다.', easyLevels: { highest: '심각!', high: '경계', notice: '주의' }, why: { curator: '보안 뉴스레터 언급', buzz: 'HN 화제' }, skip: '주요 사건 건너뛰고 최신순으로', skipTop: '게시판으로 건너뛰기', found: (n) => `${n}건이 보입니다.`, sorted: (s) => `${s}으로 정렬했습니다.`,
    status: (updated, shown, total) => `마지막 업데이트 ${updated} · ` + (shown === total ? `${total}건` : `전체 ${total}건 중 ${shown}건`),
    products: '사용하는 제품', productsHint: '제품 이름을 입력해 찾기', productsHintShort: '제품 이름', picked: '고른 제품', fpApplied: '적용한 필터', remove: (name) => `${name} 빼기`,
    search: '검색', searchHint: '키워드, CVE 번호, 버전', searchHintShort: '키워드, CVE 번호', all: '최신순', sortLabel: '정렬', expandAll: '모두 펼치기', collapseAll: '모두 접기', unfold: '묶음 풀기', refold: '묶어 보기', groupTag: '묶음', patchTag: '함께 패치', prefs: '화면 설정', toTop: '맨 위로', toBottom: '맨 아래로', newAbove: (n) => `새 사건 ${n}건`, newAdded: (n) => `새 사건 ${n}건이 추가되었습니다.`, toNew: '첫 새 사건으로 이동', foldEnd: (v) => `${v} 묶음 접기`, foldOpened: (v, n, wp) => `${v} 묶음을 펼쳤습니다 (${wp ? '플러그인' : '공지'} ${n}건).`, theme: '어두운 화면',
    pin: '주요 사건', noCve: 'CVE 번호 아직 없음', moreCves: (n) => ` 외 ${n}건`, published: '처음 게시', firstSeen: '게시 시각을 모르는 사건이라 이 게시판이 처음 확인한 시각입니다', firstSeenAt: (t) => `처음 확인 ${t}`, unrated: 'CVSS 점수 대기', kevReason: '악용 발생', easyWhen: '이럴 때만 해당돼요:', foldClosed: (v) => `${v} 묶음을 접었습니다.`, kevEasy: '지금 실제 공격에 쓰이고 있어요!', unratedWhy: '점수 대기', kevListed: 'CISA KEV 등재', attackSource: '공격 보고:', poc: '공격 코드 공개됨', pocEasy: '공격 코드가 공개됐어요!', originalEn: '원문(영어)',
    setting: '설정 파일에 이 줄을 넣으세요:', settingIn: (f) => `설정 파일 ${f}에 이 줄을 넣으세요:`, commandFor: (w) => `${w} 이 명령으로 업데이트하세요:`, caution: '설정을 잘못 바꾸면 서비스가 멈추거나 접속이 막힐 수 있어요. 바꾸기 전에 아래 원문 링크를 확인하세요.',
    noneForPicks: (names) => `고른 제품(${names})에 해당하는 사건이 지금 게시판에 없습니다.`, noneForQuery: (q) => `‘${q}’에 맞는 사건이 없습니다.`, noneForBoth: (names, q) => `고른 제품(${names}) 가운데 ‘${q}’에 맞는 사건이 없습니다.`, restore: (label, n) => `${label} · ${n}건 보기`, stale: '업데이트가 멈춰 있습니다. 수집이 멈춰 최근 사건이 빠졌을 수 있습니다.', staleShort: '업데이트 멈춤', scopeWeek: '이 게시판에 최근 7일 동안 올라온 사건에서 찾았습니다.', scopeMonths: '이 게시판에 최근 3개월 동안 올라온 사건에서 찾았습니다.', searchOlder: '이전 사건에서도 찾기',
    clearWeek: '최근 7일 동안 게시된 사건이 없습니다', clearMonths: '최근 3개월 동안 게시된 사건이 없습니다', clearNote: '고른 제품은 주소에 저장됩니다. 즐겨찾기해 두면 다음에도 바로 확인할 수 있습니다.', searchOlderMonths: '이전 사건에서도 찾기 (최근 3개월)',
    noIncidents: '아직 게시된 사건이 없습니다.', loadOlder: '이전 사건 불러오기 (최근 3개월)', showMore: (n) => `더 보기 (${n}건 남음)`, clearSearch: '검색 지우기', clearAll: '필터 모두 지우기',
    rating: { critical: '심각', high: '높음', medium: '보통', low: '낮음', none: '없음' },
    original: '원문', lead: { advisory: '공식 공지 읽기', writeup: '분석 글 읽기', cve_record: 'CVE 기록 읽기', discussion: '토론 읽기', curator: '뉴스레터 읽기', repo: '저장소 보기', other: '원문 읽기' },
    aliasHint: (w, names) => `‘${w}’${ro(w)} 검색해 ${names.join(', ')}도 함께 찾았습니다.`,
    mentions: { advisory: '보안 공지', writeup: '분석 글', cve_record: 'CVE 기록', discussion: '토론', curator: '뉴스레터', repo: '저장소' },
    refNote: '이 게시판은 참고용입니다. 조치하기 전에 각 사건의 원문 공지를 확인하세요.',
    nvd: '이 서비스는 NVD API 데이터를 사용하지만 NVD의 보증이나 인증을 받지 않았습니다.',
    kevNote: '악용 발생 표시는 CISA의 알려진 악용 취약점(KEV) 목록이나, 실제 공격을 전한 원문을 바탕으로 합니다.',
    preparing: '요약 준비 중', unavailable: '요약을 만들지 못했습니다. 아래 원문 링크를 확인하세요.',
    conditions: '해당 조건', mitigation: '대처법', mentionsMany: (label, site, n) => `${label} ${n}건: ${site}`, cveLines: (n) => `CVE ${n}건 각각의 내용`, vendorFold: (v, n) => `${v} 보안 공지 ${n}건 묶음`, wpFold: '워드프레스 플러그인', wpFoldTitle: (n) => `워드프레스 플러그인 ${n}건 묶음`, moreProducts: (n) => `외 ${n}개 제품`, cveCount: (n) => `CVE ${n}건`, moreLines: (n) => `${n}건 더 보기`, easyBrief: (p) => `${p ? `${p} ` : ''}새 보안 문제`, easyPrepTag: '쉬운 설명 준비 중', origOnly: '원문만 있음', unfoldDone: '묶음을 풀었습니다.', refoldDone: '다시 묶었습니다.', foldLess: '접기', linkKind: { advisory: '공지', writeup: '분석' }, views: '보기 방식',
    normal: '기본', easy: '쉬운 설명', highest: '심각!', high: '경계', notice: '주의', levels: { highest: '고위험', high: '위험', notice: '참고' },
    command: '이 명령으로 업데이트하세요:', devices: '이 기기들을 지금 업데이트하세요!', version: (v, p) => `${p ? `${p} ` : ''}${v} 이상으로 업데이트하세요.`,
    fixedIn: (v) => `${v} 버전에서 고쳐졌습니다.`, none: '고친 버전을 아직 확인하지 못했습니다. 아래 원문 링크에서 확인하세요.', stopgap: '당장 못 하면:', copy: '복사', copied: '복사됨', share: '이 사건 링크 복사', linkNotFound: '링크의 사건을 게시판에서 찾지 못했습니다. 최근 3개월이 지나 내려갔을 수 있습니다.',
    paused: 'AI 요약이 잠시 멈췄습니다. 새 사건은 요약 없이 원문 제목과 링크만 보입니다.',
    versionHelp: (cve) => (cve ? `내 버전은 보통 그 프로그램의 설정이나 ‘정보’ 화면에 나와요. 모르겠으면 AI 챗봇에 ${cve} 번호로 물어보세요.` : '내 버전은 보통 그 프로그램의 설정이나 ‘정보’ 화면에 나와요.'),
    libraryHelp: '앱에 들어 있는 부품이라 직접 확인이 어려워요. 쓰는 프로그램을 업데이트하거나, 서버 관리자·호스팅 업체에 물어보세요.',
    newTab: ' (새 탭에서 열림)', newTabAll: ' (아래 링크는 모두 새 탭에서 열림)', fixesIntro: '내 제품에 맞는 버전 이상으로 업데이트하세요:', noneEasy: '아직 고친 버전 소식이 없어요. 아래 원문 링크에서 새 소식을 확인하세요.', orNewer: (v) => `${v}\u00a0이상`, models: (n) => `해당 모델 보기 (${n}개)`,
    guideBtn: '읽는 법',
    guide: {
      title: '이 게시판 읽는 법', close: '닫기',
      primer: { highest: '실제 공격·9점 이상', high: '7점 이상', notice: '그 밖', unrated: '점수 대기', ring: 'CVSS 점수 (10점 만점)', more: '읽는 법 자세히', dismiss: '안내 닫기' },
      risk: { highest: '실제 공격에 쓰이고 있거나("악용 발생"), CVSS 점수가 10점 중 9점 이상', high: 'CVSS 점수 10점 중 7점 이상', notice: '그 밖의 사건.' },
      unrated: '점수 대기: CVSS 점수가 아직 없는 사건입니다. 실제 공격이 아니면 참고 단계에 두되 점선으로 그리고, 위험도순과 CVSS 높은순에서는 점수가 있는 참고 사건보다 위에 둡니다.',
      ring: 'CVSS 점수: 취약점이 얼마나 심각한지 10점 만점으로 매긴 국제 기준 점수입니다. 링이 점수만큼 차고 색도 점수를 따릅니다. 실제 공격에 쓰이면 점수와 상관없이 맨 위 단계로 올라갑니다. 점수가 아직 없으면 점선 링 안에 —로 보입니다.',
      tags: '색 배지는 영향받는 제품과 기기로, 제품마다 늘 같은 색입니다. 테두리 배지는 그 제품이 돌아가는 OS입니다.',
      date: '처음 게시된 날짜와 시각 (내 시간대 기준). 원문에 시각이 없으면 "처음 확인"과 함께 이 게시판이 처음 본 시각을 보여 줍니다.',
      pin: '‘위험’이나 ‘고위험’ 사건(실제 공격이 있거나 CVSS 점수 7점 이상) 가운데 최근 7일 안에 공개된 것에서 중요한 4건을 골라 위에 고정합니다. 주요 사건 더 보기를 누르면 나머지가 그 아래에 붙습니다.',
      group: '한 번의 업데이트로 함께 고쳐진 CVE 묶음입니다. 링은 그중 가장 높은 점수이고, 펼치면 CVE마다 한 줄씩 나옵니다.',
      brief: '아직 요약 전이라 원문을 그대로 보여 주는 사건입니다. 영어일 수 있습니다.',
      open: '행을 누르면 요약, 해당 조건, 대처법, 원문 링크가 펼쳐집니다. 키보드로는 ↑ ↓ 키로 행 사이를 옮겨 다닙니다.',
      fold: '한 회사가 같은 날 5건 이상 낸 공지와 같은 날의 워드프레스 플러그인 5건 이상은 "묶음" 한 줄로 모읍니다. 누르면 그 자리에서 펼쳐지고, 목록 제목 옆 "묶음 풀기"로 모두 풀 수 있습니다. "함께 패치" 줄은 한 번의 업데이트로 고쳐진 CVE들이라 풀리지 않습니다.',
      prep: '쉬운 설명은 조금 늦게 만들어집니다. 그동안 쉬운 제목만 먼저 보여 줍니다.',
      easy: '위쪽에서 바꾸면 무엇이 위험한지와 지금 할 일을 쉬운 말로 보여줍니다.',
      filterWord: '제품 · 필터',
      filter: '사용하는 제품을 고르거나 필터로 좁힐 수 있습니다. 고른 조건은 주소에 남아 즐겨찾기로 다시 열 수 있습니다.',
      note: '요약은 AI가 원문을 읽고 만듭니다. 조치하기 전에 원문 링크를 확인하세요.',
    },
  },
  en: {
    other: '한국어', otherShort: '한', brand: 'Patch Ticker', title: 'Patch Ticker · vulnerability board', loading: 'Loading…',
    notListed: (text) => `Not in the product list, so it was searched for instead: ${text}`, variants: (n) => `Also showing ${n} under a similar name.`, manyProducts: (n) => `${n} products match. Pick one from the list.`,
    loadDetail: (msg) => `Details: ${msg}`, olderDone: (n) => (n ? `All Incidents of the last three months are loaded (${n} more).` : 'All Incidents of the last three months are loaded; there were no others.'),
    loadError: 'Could not load the Board. Check your connection and try again.', retry: 'Try again', filterBtn: 'Filters', fp: { title: 'Filters', from: 'Published from', to: 'Published to', cvss: 'Minimum CVSS', cve: 'CVE ID', any: 'Any', cveYes: 'Has a CVE', cveNo: 'No CVE yet', risk: 'Risk level', flags: 'Attacks and advisories', has: { advisory: 'Official advisory', repo: 'Attack code published' }, sort: 'Sort', sorts: { new: 'Newest', risk: 'Highest risk', cvss: 'Highest CVSS' }, close: 'Close', reset: 'Reset filters', apply: 'Apply filters', applyN: (n) => `Apply filters · ${n}`, zeroChip: 'Adding this leaves nothing', riskNote: 'Incidents with a score pending are under Notice unless exploited.', osNote: 'Shows everything that runs on the chosen systems, including web software such as WordPress plugins that runs anywhere.', zeroNote: 'A dashed chip would leave nothing if added.', dropCond: (l) => `Drop “${l}”` }, textSizeGroup: 'Text size', textGlyph: 'A', textDown: 'Smaller text', textUp: 'Larger text', textNow: (p) => `Text size ${p}%`, pinMore: (n) => `More Highlights (${n})`, pinLess: 'Fewer Highlights', qfKev: 'Exploited only', noneForFilters: 'No Incident on the Board matches these filters.', easyLevels: { highest: 'Severe!', high: 'Warning', notice: 'Caution' }, why: { curator: 'In security newsletters', buzz: 'Trending on HN' }, skip: 'Skip to newest', skipTop: 'Skip to the Board', found: (n) => `${n} Incidents shown.`, sorted: (s) => `Sorted: ${s}.`,
    status: (updated, shown, total) => `Last updated ${updated} · ` + (shown === total ? `${total} incidents` : `${shown} of ${total} incidents`),
    products: 'Products you run', productsHint: 'Type to find a Product', productsHintShort: 'Product name', picked: 'Picked Products', fpApplied: 'Applied filters', remove: (name) => `Remove ${name}`,
    search: 'Search', searchHint: 'Keyword, CVE ID, version', searchHintShort: 'Keyword or CVE ID', all: 'Newest first', sortLabel: 'Sort', expandAll: 'Expand all', collapseAll: 'Collapse all', unfold: 'Ungroup', refold: 'Group again', groupTag: 'Group', patchTag: 'One fix', prefs: 'Display settings', toTop: 'Back to top', toBottom: 'Go to bottom', newAbove: (n) => `${n} new`, newAdded: (n) => `${n} new Incidents added.`, toNew: 'Go to the first new Incident', foldEnd: (v) => `Fold ${v} back`, foldOpened: (v, n, wp) => `Opened the ${v} group (${n} ${wp ? 'plugins' : 'notices'}).`, theme: 'Dark theme',
    pin: 'Highlights', noCve: 'No CVE yet', moreCves: (n) => ` and ${n} more`, published: 'First published', firstSeen: 'No source gave a time, so this is when the Board first saw it', firstSeenAt: (t) => `first seen ${t}`, unrated: 'CVSS score pending', kevReason: 'Exploited', kevReasonEasy: 'Under attack', unratedWhy: 'Score pending', easyWhen: 'Only affects you if:', foldClosed: (v) => `Folded the ${v} group.`, kevEasy: 'Attackers are using this right now!', kevListed: 'Listed in CISA KEV', attackSource: 'Attacks reported:', poc: 'Exploit code is public', pocEasy: 'Exploit code is public!', originalEn: 'Source text',
    setting: 'Add this line to the config file:', settingIn: (f) => `Add this line to ${f}:`, commandFor: (w) => `${w}, run this to update:`, caution: 'A wrong setting can stop the service or lock you out. Check the source link below first.',
    noneForPicks: (names) => `No Incident on the Board touches the Products you picked (${names}).`, noneForQuery: (q) => `No Incident matches “${q}”.`, noneForBoth: (names, q) => `No Incident from your picked Products (${names}) matches “${q}”.`, restore: (label, n) => `${label} · show ${n}`, stale: 'Updates have stopped. Collection may be down, so recent Incidents may be missing.', staleShort: 'Updates stopped', scopeWeek: 'Searched Incidents added to the Board in the last 7 days.', scopeMonths: 'Searched Incidents added to the Board in the last 3 months.', searchOlder: 'Search older Incidents too',
    clearWeek: 'No Incident posted in the last 7 days', clearMonths: 'No Incident posted in the last 3 months', clearNote: 'Your picks are saved in the address. Bookmark it to check again next time.', searchOlderMonths: 'Search older Incidents too (last 3 months)',
    noIncidents: 'No Incidents have been posted yet.', loadOlder: 'Load older Incidents (last 3 months)', showMore: (n) => `Show more (${n} left)`, clearSearch: 'Clear search', clearAll: 'Clear all filters',
    rating: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' },
    original: '', lead: { advisory: 'Read the advisory', writeup: 'Read the write-up', cve_record: 'Read the CVE record', discussion: 'Read the discussion', curator: 'Read the newsletter', repo: 'See the repository', other: 'Read the source' },
    aliasHint: (w, names) => `‘${w}’ was also searched as ${names.join(', ')}.`,
    mentions: { advisory: 'Advisory', writeup: 'Write-up', cve_record: 'CVE record', discussion: 'Discussion', curator: 'Newsletter', repo: 'Repository' },
    refNote: "This Board is for reference only. Check each Incident's source advisory before you act.",
    nvd: '',
    kevNote: 'Exploited flags come from the CISA Known Exploited Vulnerabilities catalog, or from sources that report attacks.',
    preparing: 'Summary in preparation', unavailable: 'No Summary is available. See the source link below.',
    conditions: 'Affected when', mitigation: 'Mitigation', mentionsMany: (label, site, n) => `${label} (${n}): ${site}`, cveLines: (n) => `Each of the ${n} CVEs`, vendorFold: (v, n) => `${v}: ${n} security notices, grouped`, wpFold: 'WordPress plugins', wpFoldTitle: (n) => `WordPress plugins: ${n}, grouped`, moreProducts: (n) => `and ${n} more products`, cveCount: (n) => `${n} CVEs`, moreLines: (n) => `Show ${n} more`, easyBrief: (p) => `New security issue${p ? ` in ${p}` : ''}`, easyPrepTag: 'Plain summary coming', origOnly: 'Source only', unfoldDone: 'Groups opened up.', refoldDone: 'Grouped again.', foldLess: 'Show less', linkKind: { advisory: 'advisory', writeup: 'write-up' }, views: 'View',
    normal: 'Normal', easy: 'Easy', highest: 'Severe!', high: 'Warning', notice: 'Caution', levels: { highest: 'High risk', high: 'Elevated', notice: 'Notice' },
    command: 'Run this to update:', devices: 'Update these devices now!', version: (v, p) => `Update ${p ? `${p} ` : ''}to ${v} or later.`,
    fixedIn: (v) => `Fixed in version ${v}.`, none: 'We have not confirmed a fixed version yet. Check the source link below.', stopgap: 'Can\'t update yet?', copy: 'Copy', copied: 'Copied', share: 'Copy link to this Incident', linkNotFound: 'The linked Incident is not on the Board; it may be older than three months.',
    paused: 'Summaries are paused for now; new Incidents show only the source title and link.',
    versionHelp: (cve) => (cve ? `Your version is usually shown in the program's settings or About screen. If not, ask an AI chatbot about ${cve}.` : "Your version is usually shown in the program's settings or About screen."),
    libraryHelp: "It is a part built into other apps, so it is hard to check yourself. Update the programs you use, or ask your server admin or hosting company.",
    newTab: ' (opens in a new tab)', newTabAll: ' (every link below opens in a new tab)', fixesIntro: 'Update to at least the version for your product:', noneEasy: 'No fixed version has been announced yet. Watch the source link below for news.', orNewer: (v) => `${v}\u00a0or\u00a0later`, models: (n) => `Affected models (${n})`,
    guideBtn: 'How to read',
    guide: {
      title: 'How to read this Board', close: 'Close',
      primer: { highest: 'Exploited or 9+', high: '7+', notice: 'Everything else', unrated: 'Score pending', ring: 'CVSS score (out of 10)', more: 'How to read', dismiss: 'Dismiss this note' },
      risk: { highest: 'Exploited (attacks reported), or a CVSS score of 9 or more out of 10', high: 'A CVSS score of 7 or more out of 10', notice: 'Everything else.' },
      unrated: 'Score pending: no CVSS score yet. Unless exploited it stays at Notice, drawn dashed, and sorts above scored Notice rows by risk or by CVSS.',
      ring: 'The CVSS score: how severe a flaw is, out of 10, on an international standard. The ring fills to the score and its colour follows the score. Reported attacks lift an Incident to the top level whatever its score. No score yet shows as — in a dashed ring.',
      tags: 'Filled badges are the affected Products and devices, each always in the same colour. Outlined badges are the systems they run on.',
      date: 'When it was first published, in your time zone. With no time in the source, "first seen" shows when the Board first saw it.',
      pin: 'The four most important Incidents at the Elevated level or above (exploited, or scored 7 or more) made public in the last seven days stay on top. More Highlights adds the rest below them.',
      group: 'CVEs fixed together in one update, shown as one row. The ring is the highest score among them; open it for a line on each.',
      brief: '',
      open: 'Open a row for the summary, who is affected, the fix and the source links. On a keyboard, ↑ and ↓ move between rows.',
      fold: 'Five or more notices from one vendor on one day, or five or more WordPress plugins on one day, fold into one "Group" row. Open it in place, or use "Ungroup" beside the list heading to show them all. "One fix" rows are CVEs fixed by one update and stay together.',
      prep: 'Plain summaries come a little later; until then the row shows a plain title only.',
      easy: 'Switch at the top for what is dangerous and what to do now, in plain words.',
      filterWord: 'Products · Filters',
      filter: 'Pick the Products you run or narrow with filters. Your choices stay in the address, so a bookmark brings them back.',
      note: 'Summaries are written by AI from the sources. Check the source links before you act.',
    },
  },
};
let lang = loadLang();
// The Board-wide view (normal or Easy) the visitor chose at the top; remembered.
let defaultView = loadView();

function loadView() {
  try {
    return viewFromStorage(localStorage.getItem(SAVED_VIEW));
  } catch {
    return 'normal'; // storage blocked: normal view everywhere
  }
}

function setDefaultView(view) {
  defaultView = view;
  $('view-easy').classList.remove('beckon');
  $('views').classList.remove('beckon');
  try {
    if (view === 'easy') localStorage.setItem('vr-easy-tried', '1');
  } catch {
    // storage blocked
  }
  try {
    localStorage.setItem(SAVED_VIEW, view);
  } catch {
    // storage blocked: the choice lasts until reload
  }
  // Each row on screen changes its words in place: the old text leaves downwards, the new one rises in, and rows whose
  // height changed glide (index.html, .vt-view). Reduced motion: a plain cross-fade.
  document.documentElement.classList.add('vt-view');
  boardTransition(() => {
    render();
    if (!$('filters').hidden) filterPanel(); // risk words differ between the views
  }).finally(() => setTimeout(() => document.documentElement.classList.remove('vt-view'), 400));
}

function loadLang() {
  try {
    const saved = localStorage.getItem(SAVED_LANG);
    if (saved in TEXT) return saved;
  } catch {
    // storage blocked: fall back to the browser's language
  }
  return (navigator.language || '').toLowerCase().startsWith('ko') ? 'ko' : 'en';
}

const darkQuery = matchMedia('(prefers-color-scheme: dark)');
// The theme the page shows: the visitor's remembered choice, else the system's.
const theme = () => document.documentElement.dataset.theme || (darkQuery.matches ? 'dark' : 'light');

// Text size: 가− / 가+ step through these root sizes, remembered like the theme (index.html's inline script applies
// it before the first paint).
const TEXT_STEPS = [87.5, 100, 112.5, 125, 150];
const SAVED_TEXT = 'vr-text-pct';
const textPct = () => Math.round((parseFloat(document.documentElement.style.getPropertyValue('--ts')) || 1) * 1000) / 10;
function stepText(direction) {
  const next = TEXT_STEPS[Math.min(TEXT_STEPS.length - 1, Math.max(0, TEXT_STEPS.indexOf(textPct()) + direction))];
  // Only font sizes read --ts, so the text grows and the layout (gaps, columns, buttons) stays as it is.
  if (next === 100) document.documentElement.style.removeProperty('--ts');
  else document.documentElement.style.setProperty('--ts', String(next / 100));
  try {
    localStorage.setItem(SAVED_TEXT, String(next));
  } catch {
    // storage blocked: the choice lasts until reload
  }
  showTextSize();
  placePill(); // the switch's labels changed width
  pageText(); // placeholders: the short ones from 125%
  measureStick(); // the frozen row grew or shrank with the text
}
function showTextSize() {
  const pct = textPct();
  $('text-down').disabled = pct === TEXT_STEPS[0];
  $('text-up').disabled = pct === TEXT_STEPS.at(-1);
}
function setTextIndex(index) {
  stepText(index - TEXT_STEPS.indexOf(textPct()));
  $('announce').textContent = TEXT[lang].textNow(textPct()); // the polite region says the new size
}

function toggleTheme() {
  // Decided inside the cross-fade: a second click before the first fade lands still flips the theme again.
  crossFade(() => {
    const next = theme() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem(SAVED_THEME, next);
    } catch {
      // storage blocked: the choice lasts until reload
    }
    pageText();
    pop($('theme').querySelector(next === 'dark' ? '.sun' : '.moon'), 'rotate(-90deg) scale(0.6)', 260);
  });
}

const getJson = async (name) => {
  const res = await fetch(DATA_URL + name, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  return res.json();
};

const $ = (id) => document.getElementById(id);
let incidents = [];
let products = [];
let seenProducts = [];
let pickNote = '';
let visibleIds = []; // the rows drawn now, for 모두 펼치기 / 모두 접기
const allOpen = () => visibleIds.length > 0 && visibleIds.every((id) => open.has(id)); // a name typed in the picker that is not a listed Product, now searched for instead // board/products.json: every Product of 90 days, so one with no loaded Incident can be picked
let updated = '';
let paused = false;
let loadError = null; // null while loading or once loaded; the error message if loading failed
// The Board opens on the last week (board/recent.json); older months come in when the visitor asks.
let olderMonths = [];
let loadingOlder = false;
let olderAdded = null; // how many 이전 사건 불러오기 added, said where the button stood
// Rows of 최신순 drawn so far; a long list grows by PAGE on request instead of all at once.
const PAGE = 100;
let shown = PAGE;
let folding = (() => {
  try {
    return localStorage.getItem(SAVED_FOLD) !== 'off';
  } catch {
    return true;
  }
})();
// The last place, only on a reload or back/forward (a fresh visit starts at the top with four Highlights).
const place = (() => {
  if (!reloaded) return null;
  try {
    return JSON.parse(sessionStorage.getItem(SAVED_PLACE));
  } catch {
    return null;
  }
})();
// Rows the visitor opened, by Incident id, so a re-render (typing, language) keeps them open.
const open = new Set();
// The filter lives in the address hash, not the query, so opening a shared link never sends it to a server.
let filter = loadFilter();

// A link's own filter wins whole (a shared "#r=highest" is not mixed with this browser's picks). Otherwise the saved
// picks and panel conditions come back, shown as chips; a search word never does: an old search silently narrowing a
// later visit would hide Incidents by mistake (critique 4).
function loadFilter() {
  const fromAddress = filterFromQuery(location.hash.slice(1));
  if (location.hash.length > 1) return fromAddress;
  try {
    return { ...filterFromQuery(localStorage.getItem(SAVED) || ''), query: '' }; // saved before 11-08 late: may hold q
  } catch {
    return fromAddress; // storage blocked (private window, cleared site data)
  }
}

// push: a filter change the visitor made becomes a step in the browser's history, so Back undoes it (owner, 11-09);
// typing in search only rewrites the current step, or every letter would be a step.
function saveFilter(push = false) {
  const encoded = filterToQuery(filter);
  try {
    localStorage.setItem(SAVED, filterToQuery({ ...filter, query: '' }));
  } catch {
    // storage blocked: the address still carries the filter
  }
  const next = encoded ? `#${encoded}` : location.pathname + location.search;
  const now = location.hash || location.pathname + location.search;
  if (push && next !== now) history.pushState(null, '', next);
  else history.replaceState(null, '', next);
}

// Back / Forward: the filter of that step comes back, with the Board's motion.
addEventListener('popstate', () => {
  filter = filterFromQuery(location.hash.slice(1));
  pickNote = '';
  shown = PAGE;
  $('search').value = filter.query;
  try {
    localStorage.setItem(SAVED, filterToQuery({ ...filter, query: '' }));
  } catch {
    // storage blocked
  }
  boardTransition(() => {
    render();
    if (!$('filters').hidden) filterPanel();
  });
});

let linked = false; // the page was opened by a link to one Incident (#i=)
async function main() {
  render();
  try {
    // A missing Product list (data from before it existed) only narrows the picker; it must not stop the Board.
    const [index, st, recent, seen] = await Promise.all([getJson('index.json'), getJson('status.json'),
      getJson('board/recent.json'), getJson('board/products.json').catch(() => ({ products: [] }))]);
    incidents = recent.incidents.filter(onBoard);
    seenProducts = seen.products;
    olderMonths = index.months.slice(-3);
    updated = st.updated;
    paused = st.summaries === 'paused'; // the collector hit its AI budget (ticket 07)
    refreshProducts();
    $('search').value = filter.query;
    linked = !place && new URLSearchParams(location.hash.slice(1)).has('i');
    if (!linked) saveFilter();
    if (place) {
      if (place.older && olderMonths.length) olderAdded = await fetchOlder().catch(() => null); // the button stays if it fails
      shown = Math.max(PAGE, Number(place.shown) || PAGE);
      pinAll = Boolean(place.pinAll);
      for (const id of place.open || []) open.add(id);
      for (const key of place.folds || []) openFolds.add(key);
    }
  } catch (err) {
    loadError = err.message;
  }
  // The one authored moment: as the Board first arrives, each CVSS ring fills to its score (CSS, only when motion is
  // allowed). Later redraws (filters, views) do not replay it.
  document.body.classList.add('arriving');
  render();
  if (place && !loadError) scrollTo(0, Number(place.y) || 0);
  if (linked) {
    await openLinked();
    saveFilter(); // the address returns to the filter form; the opened row stays open
  }
  if (!loadError) settleRows();
  // A light sweep across 쉬운 설명 twice as the Board arrives, until the visitor has tried that view once.
  let tried = true;
  try {
    tried = Boolean(localStorage.getItem('vr-easy-tried'));
  } catch {
    // storage blocked: no sweep, it could never stop
  }
  if (!loadError && defaultView === 'normal' && !tried) {
    $('view-easy').classList.add('beckon');
    $('views').classList.add('beckon');
    setTimeout(() => { $('view-easy').classList.remove('beckon'); $('views').classList.remove('beckon'); }, 3800);
  }
  setTimeout(() => document.body.classList.remove('arriving'), 1200);
}

// Live updates. Every 10 minutes (the collector's cycle) and whenever the tab comes back into view, the page reads
// status.json (a few bytes); only a new update time fetches the week again. New Incidents go where the visitor's sort
// puts them: at the top of the page they come in with the Board's motion; further down, the rows on screen stay where
// they were (the scroll is corrected by what was added above) and a notice at the top of the window says how many
// arrived above. Each new row wears a blue edge until it has been on screen four seconds.
const CHECK_MS = 30 * 1000; // live like a ticker (owner, 2026-11-09): status.json is a few bytes, so check often
const fresh = new Set(); // ids that arrived by a refresh and have not been seen yet
let checking = false;
async function checkForNew() {
  if (checking || !updated || loadError) return;
  checking = true;
  try {
    const st = await getJson('status.json');
    if (st.updated === updated) return;
    const [recent, seen] = await Promise.all([getJson('board/recent.json'), getJson('board/products.json').catch(() => null)]);
    const merged = mergeIncidents(incidents, recent.incidents.filter(onBoard));
    // the row at the top of the window, and where it is, so the page can hold it there
    const anchor = [...document.querySelectorAll('li[data-vt]')].find((li) => li.getBoundingClientRect().bottom > 0);
    const anchorId = anchor?.dataset.vt;
    const anchorTop = anchor?.getBoundingClientRect().top;
    const atTop = scrollY < 160;
    incidents = merged.incidents;
    if (seen) seenProducts = seen.products;
    updated = st.updated;
    paused = st.summaries === 'paused';
    for (const id of merged.added) fresh.add(id);
    refreshProducts();
    lastCount = null; // the redraw's own "N건이 보입니다" stays quiet: this refresh says what is new instead
    if (atTop) await boardTransition(render);
    else {
      render();
      const again = anchorId && document.querySelector(`li[data-vt="${anchorId}"]`);
      if (again) scrollBy(0, again.getBoundingClientRect().top - anchorTop);
      for (const li of document.querySelectorAll('li.fresh')) {
        const box = li.getBoundingClientRect();
        if (box.bottom > 0 && box.top < innerHeight) li.animate(reducedMotion.matches ? [{ opacity: 0 }, { opacity: 1 }]
          : [{ opacity: 0, translate: '0 -14px' }, { opacity: 1, translate: '0 0' }], { duration: 420, easing: EASE_OUT });
      }
    }
    // only what the visitor's filter shows counts, in the notice and for screen readers
    const visible = shownList.filter((i) => merged.added.includes(i.id)).length;
    if (visible) {
      clearTimeout(announcing);
      $('announce').textContent = TEXT[lang].newAdded(visible);
    }
    if (!atTop) noticeAbove();
  } catch {
    // offline or the store is busy: the next check tries again; an hour without news shows the stale notice
  } finally {
    checking = false;
  }
}
setInterval(checkForNew, CHECK_MS);
document.addEventListener('visibilitychange', () => { if (!document.hidden) checkForNew(); });
// Coming back from another window (the tab stayed visible, so no visibilitychange) checks too (owner, 2026-11-09).
addEventListener('focus', checkForNew);

// The notice at the top of the window: how many highlighted rows sit above it. It leaves once they are reached.
function noticeAbove() {
  const above = [...document.querySelectorAll('li.fresh')].filter((li) => li.getBoundingClientRect().bottom < 0).length;
  const box = $('new-above');
  box.classList.toggle('off', !above);
  if (above) {
    box.querySelector('span').textContent = TEXT[lang].newAbove(above);
    box.setAttribute('aria-label', `${TEXT[lang].newAbove(above)}, ${TEXT[lang].toNew}`); // what it shows and where it goes
  }
}
$('new-above').addEventListener('click', () => {
  $('new-above').classList.add('off');
  const first = document.querySelector('li.fresh');
  if (!first) return scrollTo({ top: 0, behavior: reducedMotion.matches ? 'auto' : 'smooth' });
  first.scrollIntoView({ block: 'center', behavior: reducedMotion.matches ? 'auto' : 'smooth' });
  first.querySelector('button.row')?.focus({ preventScroll: true });
});
addEventListener('scroll', () => { if (!$('new-above').classList.contains('off')) noticeAbove(); }, { passive: true });

// A highlighted row loses its edge four seconds after it is mostly on screen (it fades out in CSS); rows drawn again
// before that keep it, because the id stays in `fresh` until then.
const freshSeen = new IntersectionObserver((entries) => {
  for (const entry of entries) {
    if (!entry.isIntersecting) continue;
    const li = entry.target;
    freshSeen.unobserve(li);
    setTimeout(() => clearFresh(li), 4000);
  }
}, { threshold: 0.5 });
// The edge goes when the row has been seen: four seconds on screen, or at once when the pointer or the keyboard
// reaches it. It leaves with its own short fade (index.html, .fresh-out) rather than just vanishing.
function clearFresh(li) {
  if (!li.classList.contains('fresh')) return;
  for (const id of li.dataset.ids.split(' ')) fresh.delete(id);
  li.classList.replace('fresh', 'fresh-out');
  li.addEventListener('animationend', () => li.classList.remove('fresh-out'), { once: true });
  setTimeout(() => li.classList.remove('fresh-out'), 700); // reduced motion or no animation: still let go
  if (!$('new-above').classList.contains('off')) noticeAbove();
}
function watchFresh() {
  freshSeen.disconnect();
  for (const li of document.querySelectorAll('li.fresh')) {
    freshSeen.observe(li);
    li.addEventListener('pointerenter', () => clearFresh(li), { once: true });
    li.addEventListener('focusin', () => clearFresh(li), { once: true });
  }
}

// #i=<id>: a link to one Incident. The Board opens with that row open, in view, focused and edged in blue (the
// same edge a new arrival wears); a member of a vendor fold is shown ungrouped; an older one loads the three months.
async function openLinked() {
  const id = new URLSearchParams(location.hash.slice(1)).get('i');
  if (!id || loadError) return false;
  let found = incidents.find((i) => i.id === id);
  if (!found && olderMonths.length) {
    await fetchOlder().catch(() => {});
    found = incidents.find((i) => i.id === id);
  }
  if (!found) {
    $('pick-hint').textContent = TEXT[lang].linkNotFound;
    return false;
  }
  open.add(id);
  render();
  let li = [...document.querySelectorAll('li[data-ids]')].find((x) => x.dataset.ids === id);
  if (!li) { // inside a closed vendor fold: open that fold only
    const host = [...document.querySelectorAll('li.vendor-fold')].find((x) => x.dataset.ids.split(' ').includes(id));
    const key = host?.querySelector('button.row[data-fold]')?.dataset.fold;
    if (key) openFolds.add(key);
    render();
    li = [...document.querySelectorAll('li[data-ids]')].find((x) => x.dataset.ids === id);
  }
  if (!li) return false;
  li.scrollIntoView({ block: 'start' });
  li.querySelector('button.row')?.focus({ preventScroll: true });
  // The edge goes on after the focus, so the focus itself does not count as having seen it; it leaves after four
  // seconds on screen or when the pointer reaches it.
  fresh.add(id);
  li.classList.add('fresh');
  freshSeen.observe(li);
  li.addEventListener('pointerenter', () => clearFresh(li), { once: true });
  return true;
}

function shareLine(incident) {
  const p = el('p', 'share');
  const button = Object.assign(el('button', 'btn'), { type: 'button' });
  const icon = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6.5 9.5a3 3 0 0 0 4.2 0l2.1-2.1a3 3 0 0 0-4.2-4.2l-.7.7M9.5 6.5a3 3 0 0 0-4.2 0L3.2 8.6a3 3 0 0 0 4.2 4.2l.7-.7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
  const idle = () => { button.innerHTML = icon; button.append(el('span', '', TEXT[lang].share)); };
  idle();
  button.addEventListener('click', async () => {
    const url = `${location.origin}${location.pathname}#i=${encodeURIComponent(incident.id)}`;
    try {
      await navigator.clipboard.writeText(url);
      const ok = el('span', 'ok');
      ok.setAttribute('aria-hidden', 'true');
      ok.innerHTML = '<svg viewBox="0 0 16 16"><path d="m3.5 8.3 2.8 2.8 6.2-6.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
      const label = el('span', '', TEXT[lang].copied);
      button.replaceChildren(ok, label);
      draw(ok.querySelector('path'), 280);
      pop(label, 'translateX(-4px)', 200);
      $('announce').textContent = TEXT[lang].copied;
      clearTimeout(button.settle);
      button.settle = setTimeout(idle, 2000);
    } catch {
      // clipboard blocked: the address in a selected field under the button, to copy by hand
      const field = p.querySelector('input') || Object.assign(document.createElement('input'), { readOnly: true, className: 'share-url' });
      field.value = url;
      field.setAttribute('aria-label', TEXT[lang].share);
      p.append(field);
      field.select();
    }
  });
  p.append(button);
  return p;
}

addEventListener('pagehide', () => {
  try {
    sessionStorage.setItem(SAVED_PLACE, JSON.stringify({ y: scrollY, shown, pinAll, older: updated && !olderMonths.length,
      open: [...open], folds: [...openFolds] }));
  } catch {
    // storage blocked: a reload starts at the top
  }
});

// Something the visitor just opened eases in from where it was opened: a short drop for panels, a rise for the
// phone's bottom sheet; with reduced motion only the fade remains, so the change is still seen.
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
function reveal(node, from = '0 -6px', duration = 200) {
  const start = reducedMotion.matches ? { opacity: 0 } : { opacity: 0, translate: from };
  node.animate([start, { opacity: 1, translate: '0 0' }], { duration, easing: 'cubic-bezier(0.16, 1, 0.3, 1)' });
}

// Small confirmations: a check that draws itself, a badge or icon that pops in. Reduced motion keeps the end state
// (and a fade for pop), never the movement.
const EASE_OUT = 'cubic-bezier(0.16, 1, 0.3, 1)';
function draw(path, duration = 320, delay = 0) {
  if (reducedMotion.matches) return;
  path.setAttribute('pathLength', '1');
  path.style.strokeDasharray = '1';
  path.animate([{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { duration, delay, easing: EASE_OUT, fill: 'backwards' });
}
function pop(node, from = 'scale(0.6)', duration = 220) {
  const start = reducedMotion.matches ? { opacity: 0 } : { opacity: 0, transform: from };
  node.animate([start, { opacity: 1, transform: 'none' }], { duration, easing: EASE_OUT });
}
// Opening and closing a panel moves its height, so the rows below glide instead of jumping: open in 220ms, close
// faster (160ms). A click mid-way turns it round at once. Reduced motion: no movement, the panel just appears.
function fold(node, opening, done = () => {}) {
  node.folding?.cancel();
  if (reducedMotion.matches) return done();
  const cs = getComputedStyle(node);
  const full = { height: `${node.scrollHeight}px`, paddingTop: cs.paddingTop, paddingBottom: cs.paddingBottom, opacity: 1 };
  if (!opening) full.height = `${node.offsetHeight}px`;
  const shut = { height: '0px', paddingTop: '0px', paddingBottom: '0px', opacity: 0 };
  node.style.overflow = 'hidden';
  node.folding = node.animate(opening ? [shut, full] : [full, shut],
    { duration: opening ? 220 : 160, easing: opening ? EASE_OUT : 'cubic-bezier(0.4, 0, 1, 1)' });
  node.folding.onfinish = () => {
    node.style.overflow = '';
    node.folding = null;
    done();
  };
}

// Board redraws the visitor asked for (filters, sort, 주요 사건 더 보기, 더 보기, 모두 펼치기) keep each row's identity: a row
// that stays glides to its new place, a new one fades in, a gone one fades out (View Transitions; each row is named in
// row()). Reduced motion: nothing moves, the change only cross-fades. Typing in search redraws plainly.
const rowNames = new Map();
const rowName = (id) => rowNames.get(id) || rowNames.set(id, `row-${rowNames.size + 1}`).get(id);
// Only rows on or near the screen are named: every named row is captured, and off-screen ones cost memory for nothing.
function nameRows() {
  for (const li of document.querySelectorAll('li[data-vt]')) {
    const box = li.getBoundingClientRect();
    li.style.viewTransitionName = box.bottom > -200 && box.top < innerHeight + 200 ? li.dataset.vt : '';
  }
}
// Resolves once the new Board is drawn (a caller that reads the drawn rows waits for it).
function boardTransition(change) {
  if (!document.startViewTransition) return Promise.resolve(change());
  document.documentElement.classList.toggle('vt-still', reducedMotion.matches);
  nameRows();
  const transition = document.startViewTransition(() => {
    change();
    nameRows();
  });
  transition.ready.catch(() => {}); // a newer redraw skipped this one: nothing is wrong
  transition.finished.finally(() => {
    for (const li of document.querySelectorAll('li[data-vt]')) li.style.viewTransitionName = '';
  });
  return transition.updateCallbackDone.catch(() => {});
}

// Theme and language change the whole page at once: cross-fade it (View Transitions, where the browser has them).
function crossFade(change) {
  if (reducedMotion.matches || !document.startViewTransition) return change();
  document.startViewTransition(change);
}

// Source URLs are untrusted too: only http(s) ever becomes a link target.
// note: false where one line above already said it for a whole list (a group's CVE lines carry dozens of links).
function anchor(url, text, note = true) {
  const a = document.createElement('a');
  a.href = /^https?:\/\//i.test(url) ? url : '#';
  // Every source opens in a new tab so the Board, its filters and to-do ticks stay where they were (user, 11-08).
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  a.textContent = text;
  if (note) a.append(el('span', 'sr-only', TEXT[lang].newTab)); // screen readers are told before the tab changes
  return a;
}

const host = (url) => URL.canParse(url) ? new URL(url).host.replace(/^www\./, '') : url;

// The picker's label: the vendor in brackets only when the name does not already say it; "Windows (OS)".
// The picker in the page's language, rebuilt when the data or the language changes.
function refreshProducts() {
  products = productList(incidents, Date.now(), lang, seenProducts);
  $('product-options').replaceChildren(...products.map((p) => new Option(label(p), label(p))));
}

const label = (p) => {
  const kind = p.id.split(':')[0];
  if (kind === 'os') return `${p.name} (OS)`;
  // The vendor in brackets only to tell apart two Products of the same name.
  const twin = products.some((o) => o !== p && o.name === p.name);
  return kind === 'name' || !twin ? p.name : `${p.name} (${kind})`;
};

// The page's own text: index.html marks each element with the TEXT key it shows.
function pageText() {
  const t = TEXT[lang];
  document.documentElement.lang = lang;
  showTextSize();
  document.title = t.title;
  for (const node of document.querySelectorAll('[data-t]')) {
    node.textContent = t[node.dataset.t];
    node.hidden = !node.textContent; // the Korean NVD line has no English twin
  }
  searchPlaceholder();
  for (const node of document.querySelectorAll('[data-t-aria]')) node.setAttribute('aria-label', t[node.dataset.tAria]);
  // Full name on wide screens, a short code on phones (the header must fit 375px); screen readers get the full name.
  $('lang').replaceChildren(el('span', 'full', t.other), el('span', 'short', t.otherShort));
  $('lang').setAttribute('aria-label', t.other);
  $('lang').lang = lang === 'ko' ? 'en' : 'ko';
  for (const view of ['normal', 'easy']) $(`view-${view}`).setAttribute('aria-pressed', defaultView === view);
  placePill();
  $('theme').setAttribute('aria-pressed', theme() === 'dark');
}

// The fields' hints: short ones on phones and from 125% text; on a phone while the copy of 필터 and 정렬 rides beside
// it, the search field says only "검색" (critique 13: the hint was cut at 320px).
function searchPlaceholder() {
  const t = TEXT[lang];
  const narrow = phoneSheet();
  for (const node of document.querySelectorAll('[data-t-placeholder]')) {
    const key = node.dataset.tPlaceholder;
    node.placeholder = node.id === 'search' && narrow && stuckOn ? t.search : ((narrow || textPct() >= 125) && t[`${key}Short`]) || t[key];
  }
}

// The 기본|쉬운 설명 switch: one dark pill under the pressed side that slides across when the view changes.
function placePill() {
  const views = $('views');
  const on = $(`view-${defaultView}`);
  views.style.setProperty('--pill-x', `${on.offsetLeft}px`);
  views.style.setProperty('--pill-w', `${on.offsetWidth}px`);
  if (!views.classList.contains('slid')) {
    views.classList.add('slid');
    requestAnimationFrame(() => requestAnimationFrame(() => views.classList.add('ready'))); // no slide on first paint
  }
}

// The collector runs every 10 minutes; an hour without an update (six missed runs) is said out loud, not left to
// the small status line. Checked every minute too, so a tab left open goes stale where the visitor can see it.
const STALE_MS = 60 * 60 * 1000;
const WARN = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2.2 14.5 13.5h-13Z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M8 6.5v3.3M8 11.6v.1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
const isStale = () => Boolean(updated) && !loadError && Date.now() - Date.parse(updated) > STALE_MS;
function staleNote() {
  const note = $('stale');
  const stale = isStale();
  const text = stale ? TEXT[lang].stale : ''; // the age is in the status line just above (critique 12)
  if (note.textContent === text) return; // unchanged: screen readers hear it once (role=status)
  note.hidden = !stale;
  note.innerHTML = stale ? WARN : '';
  if (stale) note.append(el('span', '', text));
}
let shownList = [];
// The status line; on phones a stale Board says so on this line in two words (critique 13: the notice box pushed the
// first row down), while the notice itself stays for screen readers (index.html hides it visually there).
function showStatus() {
  const short = isStale() ? [el('span', 'stale-short', ` · ${TEXT[lang].staleShort}`)] : [];
  short[0]?.setAttribute('aria-hidden', 'true');
  $('status').replaceChildren(statusLine(shownList), ...short);
  staleNote();
}
setInterval(showStatus, 60_000);

function statusLine(list) {
  const t = TEXT[lang];
  if (loadError) return ''; // the message and its retry button sit in the empty-state block
  if (!updated) return t.loading;
  return t.status(ago(updated), list.length, incidents.length) + (paused ? ` · ${t.paused}` : '');
}

// 이 게시판 읽는 법 opens only on request. A first visit gets one line instead (the three risk signs and the ring, with
// 읽는 법 자세히), so the first screen still shows Incidents (critique 9: the full guide pushed the first row below the
// fold). Closing that line or the full guide marks the guide as seen; the line never comes back.
const SAVED_GUIDE = 'vr-guide';
let guideOpen = false;
let primerOpen = (() => {
  try {
    return !localStorage.getItem(SAVED_GUIDE);
  } catch {
    return false; // storage blocked: it could never be dismissed for good, so the 읽는 법 button carries it alone
  }
})();

function setGuide(open) {
  guideOpen = open;
  primerOpen = false; // either way the visitor has met the guide
  try {
    if (!open) localStorage.setItem(SAVED_GUIDE, 'seen');
  } catch {
    // storage blocked: closed until reload
  }
  render();
}

// Each mark is drawn with the row's own parts (risk dot and word in the current view, CVSS ring, line badge),
// so the legend can never drift from what the rows show.
function guide() {
  const t = TEXT[lang];
  const g = t.guide;
  const box = $('guide');
  primer();
  $('guide-btn').setAttribute('aria-expanded', guideOpen);
  box.hidden = !guideOpen;
  if (!guideOpen) return box.replaceChildren();
  const close = Object.assign(el('button', 'btn', g.close), { type: 'button' });
  close.addEventListener('click', () => { setGuide(false); $('guide-btn').focus(); });
  const head = el('div', 'g-head');
  head.append(Object.assign(el('h2', '', g.title), { id: 'guide-title' }), close);
  const list = el('dl', 'legend');
  let next = 'g-item';
  const item = (text, ...sample) => {
    const row = el('div', next);
    const dt = el('dt', '');
    dt.append(...sample);
    row.append(dt, el('dd', '', text));
    list.append(row);
    next = 'g-item';
  };
  const rule = () => { next = 'g-item group'; }; // the next item starts a new group under a hairline
  const sample = { highest: 9.8, high: 7.5, notice: 4.3 };
  for (const level of Object.keys(sample)) item(g.risk[level], riskCell({ cvss: sample[level] }));
  item(g.unrated, riskCell({}), scoreCell({})); // the dashed sign and ring, as an unscored row draws them (critique 13)
  rule();
  item(g.ring, scoreCell({ cvss: 9.8 }));
  // The example badge is the top Highlight's Product, so the guide shows a line the reader will see first on the Board.
  const top = filterBoard(incidents, [], '', Date.now()).highlights[0];
  const example = top && rowTags(top, lang).find((n) => !(top.summary?.platforms || []).includes(n));
  item(g.tags, example ? lineBadge(example, lineKeys(top, lang).get(example)) : lineBadge('OpenSSH'), osBadge('Windows'));
  const when = el('span', 'c-date');
  when.append(el('span', '', '2026-11-08'), el('span', '', '09:30'));
  item(g.date, when);
  const group = el('span', 'cve');
  group.append('CVE-2026-124446', el('span', 'cve-more', t.moreCves(28)));
  item(g.group, patchTag(), group);
  if (t.original) item(g.brief, el('span', 'orig', t.original)); // the English page shows sources without a tag
  item(g.prep, el('small', 'sub', t.easyPrepTag)); // plain hint words, as the row shows them (not a tag)
  item(g.fold, groupTag(), el('span', 'g-word', t.vendorFold('IBM', 25)));
  rule();
  item(g.pin, el('span', 'g-pin', t.pin));
  const chev = el('i', 'chev');
  chev.setAttribute('aria-hidden', 'true');
  item(g.open, chev);
  const views = el('span', 'g-views');
  views.append(el('span', '', t.normal), el('span', 'on', t.easy));
  item(g.easy, views);
  item(g.filter, el('span', 'g-word', g.filterWord));
  box.replaceChildren(head, list, el('p', 'g-note', g.note));
}

// The first-visit line: the row's own risk signs and ring, each with a few words, then 읽는 법 자세히 and a close button.
function primer() {
  const box = $('primer');
  box.hidden = !primerOpen || guideOpen;
  if (box.hidden) return box.replaceChildren();
  const p = TEXT[lang].guide.primer;
  const keys = el('dl', 'p-keys');
  const key = (sample, text) => {
    const pair = el('div', 'p-key');
    const dt = el('dt', '');
    dt.append(sample);
    pair.append(dt, el('dd', '', text));
    keys.append(pair);
  };
  for (const [level, cvss] of [['highest', 9.8], ['high', 7.5], ['notice', 4.3]]) key(riskCell({ cvss }), p[level]);
  // No score yet: the dashed sign and the dashed ring together, the words once beside them (critique 13).
  const pending = el('span', 'p-pair');
  pending.append(riskCell({}), scoreCell({}));
  pending.querySelector('.why')?.remove();
  key(pending, p.unrated);
  key(scoreCell({ cvss: 9.8 }), p.ring);
  const more = Object.assign(el('button', 'btn p-more', p.more), { type: 'button' }); // phones: the 읽는 법 button just above does it
  more.addEventListener('click', () => {
    setGuide(true);
    reveal($('guide'));
    $('guide').querySelector('.g-head .btn')?.focus({ preventScroll: true });
  });
  const close = Object.assign(el('button', 'btn p-close'), { type: 'button' });
  close.setAttribute('aria-label', p.dismiss);
  close.append(el('span', 'x'));
  close.addEventListener('click', () => fold($('primer'), false, () => { setGuide(false); $('guide-btn').focus({ preventScroll: true }); }));
  box.replaceChildren(keys, more, close);
}

// The rest of the last three months, merged into the week already on screen.
async function fetchOlder() {
  const months = await Promise.all(olderMonths.map((m) => getJson(`board/${m}.json`)));
  const byId = new Map(incidents.map((i) => [i.id, i]));
  const before = byId.size;
  for (const i of months.flatMap((m) => m.incidents).filter(onBoard)) if (!byId.has(i.id)) byId.set(i.id, i);
  incidents = [...byId.values()];
  refreshProducts();
  olderMonths = [];
  return byId.size - before;
}

async function loadOlder() {
  loadingOlder = true;
  render();
  try {
    const added = await fetchOlder();
    clearTimeout(announcing); // a pending count from the last search must not talk over this
    $('announce').textContent = TEXT[lang].olderDone(added); // the same sentence the screen shows (critique 13)
    olderAdded = added;
  } catch (err) {
    loadError = err.message;
  }
  loadingOlder = false;
  render();
  // The button that had focus is gone: the next control in the same place takes it, and the page does not move.
  if (document.activeElement === document.body) ($('more').querySelector('button') || $('empty').querySelector('button') || $('more').querySelector('.older-done'))?.focus({ preventScroll: true });
}

// Under the list: more rows of what is loaded, then older months.
function moreButtons(rest) {
  const t = TEXT[lang];
  const buttons = [];
  if (rest > 0) {
    const more = Object.assign(el('button', 'btn', t.showMore(rest)), { type: 'button' });
    more.addEventListener('click', () => boardTransition(() => {
      shown += PAGE;
      render();
      $('more').querySelector('button')?.focus({ preventScroll: true }); // render() replaced it; keep the place
    }));
    buttons.push(more);
  }
  if (!olderMonths.length && olderAdded !== null) buttons.push(Object.assign(el('p', 'older-done', t.olderDone(olderAdded)), { tabIndex: -1 })); // takes the focus when the button is gone
  if (olderMonths.length) {
    const label = activeFilters() ? t.searchOlderMonths : t.loadOlder; // with a search or filter on, it is a search
    const older = Object.assign(el('button', 'btn', loadingOlder ? t.loading : label), { type: 'button', disabled: loadingOlder });
    older.addEventListener('click', loadOlder);
    buttons.push(older);
  }
  return buttons;
}

function render() {
  pageText();
  const { highlights: chosen, list, variants } = filterBoard(incidents, filter.picks, filter.query, Date.now(), filter);
  // 주요 사건 더 보기 adds only Highlights worth a notice: 위험 or above, or a reason the row cannot show (newsletter, HN).
  const extra = chosen.slice(PINNED); // filterBoard already keeps 주요 사건 to 위험 and above (user, 2026-11-09)
  // Which Incidents are pinned is decided by importance (highlightScore); the order they show in is the visitor's sort.
  // 더 보기 appends below the first four, which keep their place (user, 2026-11-09).
  const highlights = [...chosen.slice(0, PINNED).sort(orderBy(filter.sort)), ...(pinAll ? [...extra].sort(orderBy(filter.sort)) : [])];
  shownList = list;
  showStatus();
  guide();
  // A Korean word searched as English names too says so under the field (critique 13), so a hit on "macOS" for 맥 is not a puzzle.
  const hint = aliasesUsed(filter.query).map(({ word, names }) => TEXT[lang].aliasHint(word, names)).join(' ');
  if ($('alias-hint').textContent !== hint) $('alias-hint').textContent = hint; // unchanged: not said again (role=status)
  $('skip').hidden = !highlights.length;
  announce(list.length, filterToQuery({ ...filter, sort: 'new' })); // a new sort says 정렬 itself
  // Highlights are pinned on top like a board's notices; every other Incident follows, newest first.
  const pinned = new Set(highlights);
  rowCount = 0;
  // CVE text is untrusted input, so it only ever goes in through textContent.
  $('highlights').replaceChildren(...highlights.map((i) => row(i, true)));
  $('pinned').hidden = !highlights.length;
  $('pinned-head').replaceChildren(`${TEXT[lang].pin} `, el('span', 'n', String(highlights.length)));
  $('pinned-head').hidden = !highlights.length;
  $('pin-more').replaceChildren(...(extra.length ? [pinToggle(extra.length)] : []));
  const count = panelCount();
  $('filter-count').textContent = count ? String(count) : '';
  $('filter-count').hidden = !count;
  $('stuck-count').textContent = count ? String(count) : '';
  $('stuck-count').hidden = !count;
  if (count && count !== shownCount) { pop($('filter-count')); if (stuckOn) pop($('stuck-count')); }
  shownCount = count;
  for (const id of ['filter-btn', 'stuck-filter']) $(id).setAttribute('aria-expanded', !$('filters').hidden);
  const rest = list.filter((i) => !pinned.has(i));
  // A search or a picked Product shows every row as it is; otherwise one vendor's bulk push folds (board.mjs, foldByVendor).
  const folded = filter.picks.length || filter.query ? rest : foldByVendor(rest);
  const items = folding ? folded : rest;
  // 묶음 풀기 / 묶어 보기: only where a fold exists to undo or to bring back.
  $('fold-toggle').hidden = folded === rest || !folded.some((i) => i.fold);
  $('fold-toggle').textContent = folding ? TEXT[lang].unfold : TEXT[lang].refold;
  $('board').replaceChildren(...items.slice(0, shown).flatMap((i) => (i.fold ? foldRows(i) : [row(i, false)])));
  // Nothing found: the empty state below carries 이전 사건에서도 찾기 itself, so the buttons under the list stay away.
  $('more').replaceChildren(...(loadError || !updated || !list.length ? [] : moreButtons(items.length - shown)));
  // OS picks show as pressed buttons in the quick bar, so only Products become chips here.
  const chips = filter.picks.filter((p) => !p.startsWith('os:'));
  const conds = conditionChips();
  const clearAll = activeFilters() > 1 && list.length ? [clearButton(TEXT[lang].clearAll, NO_FILTER)] : []; // with no result the empty state has its own
  $('picks').replaceChildren(...chips.map(chip), ...(conds.length ? [] : clearAll),
    ...(pickNote ? [el('p', 'pick-note', TEXT[lang].notListed(pickNote))] : []),
    // A picked Product also shows Incidents filed under a variant of its name (board.mjs, critique 14); say how many.
    ...(variants && list.length ? [el('p', 'pick-note', TEXT[lang].variants(variants))] : []));
  $('conds').replaceChildren(...conds, ...(conds.length ? clearAll : []));
  $('all-head').hidden = !list.some((i) => !pinned.has(i));
  $('all-head').textContent = TEXT[lang].fp.sorts[filter.sort]; // the list's heading says its order
  $('sort').replaceChildren(...SORTS.map((key) => Object.assign(new Option(TEXT[lang].fp.sorts[key], key), { selected: key === filter.sort })));
  $('stuck-sort').replaceChildren(...[...$('sort').options].map((o) => o.cloneNode(true)));
  $('stuck-sort').value = filter.sort;
  visibleIds = [...highlights, ...items.slice(0, shown).flatMap((i) => (i.fold ? (openFolds.has(i.fold) ? i.incidents : []) : [i]))].map((i) => i.id);
  $('expand-all').hidden = !visibleIds.length;
  // With no Highlights, 모두 펼치기 stands at the list's head, not alone on the 주요 사건 line (critique 14).
  const expandHome = highlights.length ? $('pinned-head') : $('all-head');
  if ($('expand-all').previousElementSibling !== expandHome) expandHome.after($('expand-all'));
  $('expand-all').textContent = allOpen() ? TEXT[lang].collapseAll : TEXT[lang].expandAll;
  // While the data loads, the Board stands in its own shape (four Highlight frames, then list rows) under a scan line,
  // so the page does not blink from blank to full; nothing moves under it when the rows arrive.
  if (!updated && !loadError) {
    $('pinned').hidden = false;
    $('pinned-head').hidden = false;
    $('pinned-head').replaceChildren(el('i', 'sk sk-head'));
    $('highlights').replaceChildren(...Array.from({ length: PINNED }, () => placeholder(true)));
    $('board').replaceChildren(...Array.from({ length: 6 }, () => placeholder(false)));
    $('pin-more').replaceChildren(el('i', 'sk sk-btn')); // where 주요 사건 더 보기 will stand
    $('all-head').hidden = false;
    $('all-head').replaceChildren(el('i', 'sk sk-head'));
    document.body.classList.add('loading');
  } else document.body.classList.remove('loading');
  // Before the data arrives, say nothing; if it never arrives, say so and offer a retry, not "no Incidents".
  const quiet = list.length > 0 || (!updated && !loadError);
  $('empty').hidden = quiet;
  $('empty').replaceChildren(...(quiet ? [] : loadError ? errorState() : emptyState()));
  const check = $('empty').querySelector('.allclear .mark path');
  if (check && !hadAllClear) draw(check, 420, 120);
  hadAllClear = Boolean(check);
  watchFresh();
  measureStick();
  placeJump();
}
let shownCount = 0;

// A row-shaped stand-in: the same grid cells as row(), filled with bars, a pill and a ring track. Hidden from
// screen readers (the status line says 불러오는 중).
function placeholder(pinned) {
  const li = el('li', pinned ? 'alert skel' : 'skel');
  li.setAttribute('aria-hidden', 'true');
  const r = el('div', 'row');
  const cell = (cls, ...bars) => {
    const c = el('span', cls);
    c.append(...bars.map((b) => el('i', `sk ${b}`)));
    return c;
  };
  r.append(cell('c-risk', 'sk-pill'), cell('c-title', 'sk-name', 'sk-sub'), cell('c-score', 'sk-ring'),
    cell('c-tags', 'sk-tag', 'sk-tag'), cell('c-date', 'sk-date', 'sk-time'));
  li.append(r);
  return li;
}

// The rows settle in where the scan stood: those on screen rise 8px and fade in, top to bottom (28ms apart, at most
// twelve, so the last starts by 310ms). Reduced motion: a plain fade, all at once.
function settleRows() {
  const rows = [...document.querySelectorAll('#highlights > li, #board > li')]
    .filter((li) => { const b = li.getBoundingClientRect(); return b.bottom > 0 && b.top < innerHeight; }).slice(0, 12);
  rows.forEach((li, n) => li.animate(reducedMotion.matches ? [{ opacity: 0 }, { opacity: 1 }]
    : [{ opacity: 0, translate: '0 8px' }, { opacity: 1, translate: '0 0' }],
  { duration: reducedMotion.matches ? 200 : 360, delay: reducedMotion.matches ? 0 : n * 28, easing: EASE_OUT, fill: 'backwards' }));
}

// The Easy view: the plain answer, then the affected models when there are too many to list inline.
function easyPanel(incident) {
  const s = incident.summary;
  const parts = easyAnswer(s, riskLevel(incident), incident.cves?.[0], rowTags(incident, lang).find((n) => !OSES.includes(n)), isLibrary(incident));
  // "Does this touch me?" comes before "what to do": the Summary's conditions, in its own words, at body weight so the
  // action stays the one heavy line. One condition on the line, several as a list.
  // The everyday-words version when the Summary has one (easy_conditions, after critique 12), else the conditions as written.
  const when = (s[lang].easy_conditions?.length ? s[lang].easy_conditions : s[lang].conditions || []).filter((c) => typeof c === 'string' && c);
  if (when.length === 1) parts.unshift(para('when', `${TEXT[lang].easyWhen} ${when[0]}`));
  if (when.length > 1) {
    const list = el('ul', 'cond-list');
    list.append(...when.map((c) => el('li', '', c)));
    parts.unshift(para('when', TEXT[lang].easyWhen), list);
  }
  if ((s.devices || []).length > MANY_DEVICES) parts.push(modelList(s.devices, fixLines(s)));
  return parts;
}

let hadAllClear = false;

// Nothing to show: say so plainly. With products picked this is the good news, "not affected".
function errorState() {
  const t = TEXT[lang];
  const retry = Object.assign(el('button', 'btn', t.retry), { type: 'button' });
  retry.addEventListener('click', () => location.reload());
  const actions = el('p', 'actions');
  actions.append(retry);
  return [para('', t.loadError), para('load-detail', t.loadDetail(loadError)), actions];
}

// Screen readers hear the count once the visitor stops changing the filter, not on every redraw. A new filter says its
// count even when it is the same number (critique 14: a second search with 0 results was silent). key: the filter.
let lastCount = null;
let lastKey = null;
let announcing;
function announce(count, key) {
  if (!updated || (count === lastCount && key === lastKey)) return;
  const first = lastCount === null;
  lastCount = count;
  lastKey = key;
  clearTimeout(announcing);
  if (first) return;
  // Nothing found: the empty state's own sentence, not its buttons (critique 13: #empty was a live region holding them).
  announcing = setTimeout(() => {
    $('announce').textContent = count ? TEXT[lang].found(count) : $('empty').querySelector('p, strong')?.textContent || '';
  }, 700);
}

function emptyState() {
  const t = TEXT[lang];
  const names = filter.picks.map((id) => products.find((p) => p.id === id)?.name || id).join(', ');
  // Only Products picked: name them ("not affected"); any quick filter in play: speak of conditions instead.
  const quick = panelCount() > 0;
  // Picks and a search together: the search is named first, so "nothing for OpenSSH" never hides an OpenSSH row the
  // search left out (PRODUCT.md principle 2).
  const message = filter.picks.length && filter.query && !quick ? t.noneForBoth(names, filter.query)
    : filter.picks.length && !quick ? t.noneForPicks(names) : filter.query && !quick ? t.noneForQuery(filter.query)
    : quick ? t.noneForFilters : t.noIncidents;
  const buttons = el('p', 'actions');
  // Say how far back this looked: "nothing" in one week is not "nothing" in three months.
  const scope = para('scope', olderMonths.length ? t.scopeWeek : t.scopeMonths);
  if (olderMonths.length) {
    const older = Object.assign(el('button', 'btn', loadingOlder ? t.loading : t.searchOlder), { type: 'button', disabled: loadingOlder });
    older.addEventListener('click', loadOlder);
    buttons.append(older);
  }
  if (filter.query) buttons.append(clearButton(t.clearSearch, { query: '' }, true));
  // Filters left nothing: each condition can go on its own, the ones that bring the most back first (at most three).
  if (quick) {
    const count = (change) => { const n = { ...filter, ...change }; return filterBoard(incidents, n.picks, n.query, Date.now(), n).list.length; };
    const drops = conditionList().map(([label, change]) => [label, change, count(change)]).filter(([, , n]) => n > 0)
      .sort((a, b) => b[2] - a[2]).slice(0, 3);
    for (const [label, change] of drops) buttons.append(clearButton(t.fp.dropCond(label), change, true));
  }
  // 모두 지우기 only when something besides the search is set; with a search alone it would repeat 검색 지우기.
  if (activeFilters() - (filter.query ? 1 : 0) > 0) buttons.append(clearButton(t.clearAll, NO_FILTER, true));
  const actions = buttons.childElementCount ? [buttons] : [];
  // Only Products picked and none on the Board: the visitor's good news, said as a sign, never as "safe".
  if (filter.picks.length && !quick && !filter.query) return [allClear(), ...actions];
  return [para('', message), scope, ...actions];
}

function allClear() {
  const t = TEXT[lang];
  const sign = el('div', 'allclear');
  const mark = el('span', 'mark');
  mark.setAttribute('aria-hidden', 'true');
  mark.innerHTML = '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m7.5 12.3 3 3 6-6.3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const tags = el('span', 'c-tags');
  tags.append(...filter.picks.map((id) => lineBadge(products.find((p) => p.id === id)?.name || id.replace(/^os:/, ''), id)));
  const lines = el('span', 'lines');
  lines.append(tags, el('strong', '', olderMonths.length ? t.clearWeek : t.clearMonths), el('span', 'note', t.clearNote));
  sign.append(mark, lines);
  return sign;
}

// In the empty state the button says how many Incidents it brings back, so the visitor sees which narrowing hid them.
function clearButton(text, change, counted = false) {
  const next = { ...filter, ...change };
  const n = counted ? filterBoard(incidents, next.picks, next.query, Date.now(), next).list.length : 0;
  const button = Object.assign(el('button', 'btn', n ? TEXT[lang].restore(text, n) : text), { type: 'button' });
  button.addEventListener('click', () => {
    if ('query' in change) $('search').value = change.query;
    const drawn = update(change);
    // The field only when that field is what changed (a phone would raise its keyboard over the rows otherwise);
    // else the first row that came back, or the top of the Board (critique 11).
    if ('query' in change && Object.keys(change).length === 1) return $('search').focus({ preventScroll: true });
    if (change.picks && Object.keys(change).length === 1) return $('product-pick').focus({ preventScroll: true });
    drawn.then(() => ($('highlights').querySelector('button.row') || $('board').querySelector('button.row') || $('board-start')).focus({ preventScroll: true }));
  });
  return button;
}

function chip(id) {
  const name = products.find((p) => p.id === id)?.name || id;
  const button = Object.assign(el('button', 'chip'), { type: 'button' });
  const badge = lineBadge(name, id);
  badge.append(el('span', 'x'));
  button.append(badge);
  button.setAttribute('aria-label', TEXT[lang].remove(name));
  button.addEventListener('click', () => {
    update({ picks: filter.picks.filter((p) => p !== id) });
    $('product-pick').focus(); // the chip is gone; keep keyboard users in the filter
  });
  return button;
}

const PANEL_EMPTY = { risk: [], kev: false, from: '', to: '', cvssMin: 0, cve: '', has: [] }; // sort is not a filter: it has its own control
const NO_FILTER = { picks: [], query: '', ...PANEL_EMPTY };
const osPicks = () => filter.picks.filter((p) => p.startsWith('os:'));
// What the 필터 button's badge counts: everything set inside the panel.
const panelCount = () => filter.risk.length + (filter.kev ? 1 : 0) + osPicks().length + (filter.from || filter.to ? 1 : 0)
  + (filter.cvssMin ? 1 : 0) + (filter.cve ? 1 : 0) + filter.has.length;
const activeFilters = () => filter.picks.length - osPicks().length + panelCount() + (filter.query ? 1 : 0);

// 주요 사건 더 보기: pin every chosen Highlight (up to ten), or back to four.
let pinAll = false;
function pinToggle(rest) {
  const t = TEXT[lang];
  const button = Object.assign(el('button', 'btn', pinAll ? t.pinLess : t.pinMore(rest)), { type: 'button' });
  button.setAttribute('aria-expanded', pinAll);
  button.addEventListener('click', () => boardTransition(() => {
    pinAll = !pinAll;
    render();
    const again = $('pin-more').querySelector('button'); // render() built a new one: keep keyboard users on it
    const added = pinAll && $('highlights').children[PINNED]?.querySelector('button.row');
    (added || again)?.focus({ preventScroll: true });
    (added || again)?.scrollIntoView({ block: 'nearest' });
  }));
  return button;
}

// The advanced filter panel under the 필터 button: built from the current filter each time it opens, applied
// as a whole with 필터 적용 (nothing changes while the visitor is still choosing).
function filterPanel() {
  const t = TEXT[lang];
  const f = t.fp;
  const field = (label, control, wide = false) => {
    const wrap = el('label', wide ? 'fp-field wide' : 'fp-field');
    wrap.append(el('span', 'fp-label', label), control);
    return wrap;
  };
  const input = (type, name, value) => Object.assign(document.createElement('input'), { type, name, value });
  const select = (name, options, value) => {
    const s = Object.assign(document.createElement('select'), { name });
    s.append(...options.map(([v, text]) => Object.assign(new Option(text, v), { selected: String(v) === String(value) })));
    return s;
  };
  const checks = (legend, name, items, isOn) => {
    const set = el('fieldset', 'fp-field wide fp-checks');
    set.append(el('legend', 'fp-label', legend));
    for (const [value, text, extra] of items) {
      const box = Object.assign(input('checkbox', name, value), { checked: isOn(value) });
      const chip = el('label', `fp-chip ${extra || ''}`);
      chip.append(box, el('span', '', text));
      set.append(chip);
    }
    return set;
  };
  const words = defaultView === 'easy' ? t.easyLevels : t.levels;
  const form = $('filters');
  const grid = el('div', 'fp-grid');
  // The conditions most visitors use come first (risk, exploited, OS); dates, which few set, come last, so a phone sheet
  // opens on what matters instead of two date pickers.
  // The two dates are one range: side by side, never one left alone on its own grid row.
  const dates = el('div', 'fp-dates');
  dates.append(field(f.from, input('date', 'from', filter.from)), field(f.to, input('date', 'to', filter.to)));
  grid.append(
    (() => { const set = checks(f.risk, 'risk', RISKS.map((r) => [r, words[r], `risk-${r}`]), (r) => filter.risk.includes(r)); set.append(el('p', 'fp-note', f.riskNote)); return set; })(),
    checks(f.flags, 'flag', [['kev', t.qfKev], ...LINK_KINDS.map((k) => [k, f.has[k]])], (v) => (v === 'kev' ? filter.kev : filter.has.includes(v))),
    (() => { const set = checks('OS', 'os', OSES.map((os) => [`os:${os.toLowerCase()}`, os]), (v) => filter.picks.includes(v)); set.append(el('p', 'fp-note', f.osNote)); return set; })(),
    // What a dashed chip means: one full-width line right under the chips, and each dashed chip points to it (critique 13).
    Object.assign(el('p', 'fp-note fp-zero-note', f.zeroNote), { id: 'fp-zero-note' }),
    field(f.cvss, select('cvssMin', [[0, f.any], [4, '4.0+'], [7, '7.0+'], [9, '9.0+']], filter.cvssMin)),
    field(f.cve, select('cve', [['', f.any], ['yes', f.cveYes], ['no', f.cveNo]], filter.cve)),
    dates,
  );
  const actions = el('div', 'fp-actions');
  const reset = Object.assign(el('button', 'btn', f.reset), { type: 'button' });
  reset.addEventListener('click', () => { update(PANEL_EMPTY_WITH_OS()); filterPanel(); });
  const apply = Object.assign(el('button', 'btn primary', f.apply), { type: 'submit' });
  actions.append(reset, apply);
  // A visible way out, as the reading guide has: the phone sheet covers the Board and Escape is not on a phone keyboard.
  const close = Object.assign(el('button', 'btn', f.close), { type: 'button' });
  close.addEventListener('click', closePanel);
  const head = el('div', 'g-head fp-head');
  head.append(Object.assign(el('h3', 'fp-title', f.title), { id: 'fp-title' }), close);
  form.replaceChildren(head, grid, actions);
  countDraft();
}

// Reset clears the panel only; Products picked at the top and the search stay.
const PANEL_EMPTY_WITH_OS = () => ({ ...PANEL_EMPTY, picks: filter.picks.filter((p) => !p.startsWith('os:')) });

// What the panel's choices would set, read from the form (the panel applies as a whole).
function panelDraft() {
  const data = new FormData($('filters'));
  const flags = data.getAll('flag');
  return {
    from: data.get('from') || '', to: data.get('to') || '', cvssMin: Number(data.get('cvssMin')) || 0, cve: data.get('cve') || '',
    risk: data.getAll('risk'), kev: flags.includes('kev'), has: flags.filter((v) => v !== 'kev'),
    picks: [...filter.picks.filter((p) => !p.startsWith('os:')), ...data.getAll('os')],
  };
}
// 필터 적용 · N건: how many Incidents the choices would leave, counted as they change, so an empty combination shows
// before the Board is lost to it (critique 10).
function countDraft() {
  const count = (draft) => { const next = { ...filter, ...draft }; return filterBoard(incidents, next.picks, next.query, Date.now(), next).list.length; };
  const n = count(panelDraft());
  const apply = $('filters').querySelector('button[type=submit]');
  if (apply) {
    apply.textContent = TEXT[lang].fp.applyN(n);
    apply.classList.toggle('primary', n > 0); // nothing to show: no longer the obvious next step
  }
  // A chip that would leave nothing if added (악용 발생만 with 위험, say) is marked before it is chosen.
  for (const box of $('filters').querySelectorAll('.fp-chip input')) {
    let zero = false; // a chosen chip is not "would leave nothing if added"
    if (!box.checked) {
      box.checked = true;
      zero = count(panelDraft()) === 0;
      box.checked = false;
    }
    box.closest('.fp-chip').classList.toggle('zero', zero);
    box.closest('.fp-chip').title = zero ? TEXT[lang].fp.zeroChip : '';
    if (zero) box.setAttribute('aria-describedby', 'fp-zero-note');
    else box.removeAttribute('aria-describedby');
  }
  // the dashed style says what it means while any chip wears it
  $('filters').classList.toggle('has-zero', Boolean($('filters').querySelector('.fp-chip.zero')));
}
$('filters').addEventListener('change', countDraft);

function applyPanel(event) {
  event.preventDefault();
  const fromCopy = panelFrom?.opener === $('stuck-filter');
  const drawn = update(panelDraft());
  closePanel(true); // the results are the answer; the applied conditions stay visible as chips
  if (fromCopy) drawn.then(toBoardHead); // opened mid-list: the new results start under the frozen row
  // A start date before the loaded week needs the older months.
  const week = new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10);
  if (filter.from && filter.from < week && olderMonths.length) loadOlder();
}

function update(change, animate = true) {
  pickNote = ''; // the note answers one typed name; any later change makes it stale
  // A search word rewrites its own step; starting a search (from none) is a new step, so Back first clears the search.
  const onlyQuery = Object.keys(change).length === 1 && 'query' in change;
  const push = !onlyQuery || (!filter.query && Boolean(change.query));
  filter = { ...filter, ...change };
  shown = PAGE;
  saveFilter(push);
  const redraw = () => {
    render();
    if (!$('filters').hidden) filterPanel(); // an open panel always shows the filter in force, never a stale draft
  };
  if (animate) return boardTransition(redraw); // resolves once the new Board is drawn
  redraw();
  return Promise.resolve();
}

// While the phone sheet covers the Board, everything else is inert (no taps, no reading) until it closes.
function sheetInert(on) {
  for (const node of document.querySelectorAll('header.top, footer, #jump, main > *:not(#filters):not(#announce)')) node.inert = on;
}

// The panel remembers who opened it and where the page stood (critique 13: closing it threw the reader to the top and
// the focus to the bar's 필터). Closed without 필터 적용, both come back.
let panelFrom = null;
const phoneSheet = () => matchMedia('(max-width: 599px)').matches;
function openPanel(opener) {
  const form = $('filters');
  panelFrom = { opener, y: scrollY };
  // A phone's bottom sheet, or (wider) the panel opened from the frozen copy floating under the frozen row: a modal
  // dialog over the page, which stays where it was. From the bar on wider screens it opens inline under the bar.
  // Floating is set before it shows, or the inline panel would push the page (scroll anchoring) for a frame.
  const floating = opener === $('stuck-filter') && !phoneSheet();
  form.classList.toggle('floating', floating);
  form.hidden = false;
  filterPanel();
  render();
  if (phoneSheet() || floating) {
    form.setAttribute('role', 'dialog');
    form.setAttribute('aria-modal', 'true');
    form.setAttribute('aria-labelledby', 'fp-title');
    sheetInert(true);
    reveal(form, floating ? '0 -6px' : '0 100%', floating ? 200 : 300);
    form.querySelector('.fp-head .btn').focus({ preventScroll: true });
  } else {
    for (const name of ['role', 'aria-modal', 'aria-labelledby']) form.removeAttribute(name);
    reveal(form);
  }
}

function closePanel(applied = false) {
  const from = panelFrom;
  panelFrom = null;
  sheetInert(false);
  $('filters').hidden = true;
  $('filters').classList.remove('floating');
  for (const id of ['filter-btn', 'stuck-filter']) $(id).setAttribute('aria-expanded', 'false');
  if (!applied && from && scrollY !== from.y) scrollTo(0, from.y);
  const back = from?.opener?.offsetParent ? from.opener : $('filter-btn'); // the copy may have left meanwhile
  back.focus({ preventScroll: true });
}

// The Board's head (the bar with 주요 사건) just under the frozen row: where a new order or filter starts reading.
const toBoardHead = () => $('board-start').scrollIntoView({ block: 'start', behavior: glide() });

// Each applied panel condition as a removable chip under the fields, so what is filtered stays in sight.
// Each applied panel condition as [label, the change that removes it].
function conditionList() {
  const t = TEXT[lang];
  const f = t.fp;
  const words = defaultView === 'easy' ? t.easyLevels : t.levels;
  return [
    ...filter.risk.map((r) => [words[r], { risk: filter.risk.filter((x) => x !== r) }]),
    ...(filter.kev ? [[t.qfKev, { kev: false }]] : []),
    ...filter.has.map((h) => [f.has[h], { has: filter.has.filter((x) => x !== h) }]),
    ...filter.picks.filter((p) => p.startsWith('os:')).map((p) => [OSES.find((o) => `os:${o.toLowerCase()}` === p) || p, { picks: filter.picks.filter((x) => x !== p) }]),
    ...(filter.from || filter.to ? [[`${filter.from || '…'} ~ ${filter.to || '…'}`, { from: '', to: '' }]] : []),
    ...(filter.cvssMin ? [[`CVSS ${filter.cvssMin}.0+`, { cvssMin: 0 }]] : []),
    ...(filter.cve ? [[filter.cve === 'yes' ? f.cveYes : f.cveNo, { cve: '' }]] : []),
  ];
}

function conditionChips() {
  const t = TEXT[lang];
  return conditionList().map(([label, change]) => {
    const button = Object.assign(el('button', 'cond'), { type: 'button' });
    button.append(el('span', '', label), el('span', 'x'));
    button.setAttribute('aria-label', t.remove(label));
    button.addEventListener('click', () => { update(change); $('filter-btn').focus(); });
    return button;
  });
}

$('product-pick').addEventListener('change', (event) => {
  const text = event.target.value.trim();
  const found = matchProducts(products, text, label);
  // Several Products contain it ("ssh"): keep the text so the list narrows to them, and say so.
  if (found.length > 1) {
    pickNote = '';
    $('announce').textContent = TEXT[lang].manyProducts(found.length);
    $('pick-hint').textContent = TEXT[lang].manyProducts(found.length);
    return;
  }
  event.target.value = '';
  $('pick-hint').textContent = '';
  const [picked] = found;
  if (picked && !filter.picks.includes(picked.id)) update({ picks: [...filter.picks, picked.id] });
  // Not a listed Product ("공유기"): search for it instead of dropping it silently.
  if (!picked && text) {
    $('search').value = text;
    update({ query: text });
    pickNote = text;
    render();
  }
});
$('product-pick').addEventListener('input', () => { $('pick-hint').textContent = ''; });
$('lang').addEventListener('click', () => crossFade(() => {
  lang = lang === 'ko' ? 'en' : 'ko';
  try {
    localStorage.setItem(SAVED_LANG, lang);
  } catch {
    // storage blocked: the choice lasts until reload
  }
  clearTimeout(announcing);
  $('announce').textContent = ''; // nothing said in the old language stays (critique 14: 글자 크기 100% on the English page)
  refreshProducts();
  render();
  if (!$('filters').hidden) filterPanel(); // an open panel speaks the new language (an unapplied choice there resets)
}));
$('view-normal').addEventListener('click', () => setDefaultView('normal'));
$('view-easy').addEventListener('click', () => setDefaultView('easy'));
$('theme').addEventListener('click', toggleTheme);
// Escape closes what is open, the latest layer first: the filter panel, then the reading guide, then the row the focus is in.
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (!$('filters').hidden) return closePanel();
  if (guideOpen) {
    setGuide(false);
    return $('guide-btn').focus();
  }
  let item = document.activeElement;
  while (item && !(item.tagName === 'LI' && item.querySelector(':scope > h3.row-h'))) item = item.parentElement;
  const row = item?.querySelector(':scope > h3.row-h > button.row');
  if (row?.getAttribute('aria-expanded') === 'true') {
    row.click();
    row.focus();
  }
});
// The phone sheet is a dialog: Tab stays inside it while it covers the Board.
document.addEventListener('keydown', (event) => {
  const form = $('filters');
  if (event.key !== 'Tab' || form.getAttribute('aria-modal') !== 'true' || form.hidden) return;
  const stops = [...form.querySelectorAll('button, input, select')].filter((x) => !x.disabled && x.offsetParent);
  const [first, last] = [stops[0], stops.at(-1)];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
});
document.addEventListener('keydown', (event) => {
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key) || !event.target.classList?.contains('row')) return;
  const rows = [...document.querySelectorAll('button.row')];
  const at = rows.indexOf(event.target);
  const next = rows[{ ArrowDown: at + 1, ArrowUp: at - 1, Home: 0, End: rows.length - 1 }[event.key]];
  if (next) {
    event.preventDefault();
    next.focus();
  }
});
// The sheet (and the floating panel) dims the Board behind it (CSS); a tap on the dimmed Board closes it, as a sheet does.
document.addEventListener('pointerdown', (event) => {
  const form = $('filters');
  if (form.hidden || form.getAttribute('aria-modal') !== 'true') return;
  if (!form.contains(event.target)) closePanel();
});
$('filters').addEventListener('submit', applyPanel);
// '/' jumps to the search box, as on many sites; not while typing somewhere.
document.addEventListener('keydown', (event) => {
  if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
  if (event.target.closest?.('input, textarea, select, [contenteditable]')) return;
  event.preventDefault();
  $('search').focus();
});
// The frozen copy of 정렬: a new order is read from its start, so the Board's head comes up under the frozen row
// (critique 13: the reader was left mid-list in the new order).
$('stuck-sort').addEventListener('change', (event) => sortBy(event.target.value).then(toBoardHead));
// The frozen copy of 필터 opens the panel where the reader is: a sheet on a phone, a panel under the frozen row wider.
$('stuck-filter').addEventListener('click', () => {
  if ($('filters').hidden) openPanel($('stuck-filter'));
  else $('filters').querySelector('input, select, button')?.focus();
});
$('sort').addEventListener('change', (event) => sortBy(event.target.value));
function sortBy(sort) {
  $('sort').value = sort;
  $('stuck-sort').value = sort;
  const drawn = update({ sort });
  // The count does not change with the order, so say the order itself (the count line stays quiet).
  $('announce').textContent = TEXT[lang].sorted(TEXT[lang].fp.sorts[sort]);
  return drawn;
}
$('fold-toggle').addEventListener('click', () => boardTransition(() => {
  folding = !folding;
  try {
    folding ? localStorage.removeItem(SAVED_FOLD) : localStorage.setItem(SAVED_FOLD, 'off');
  } catch {
    // storage blocked: the choice lasts until reload
  }
  render();
  $('fold-toggle').focus({ preventScroll: true });
  clearTimeout(announcing);
  $('announce').textContent = folding ? TEXT[lang].refoldDone : TEXT[lang].unfoldDone;
}));
$('expand-all').addEventListener('click', () => boardTransition(() => {
  const closing = allOpen();
  for (const id of visibleIds) closing ? open.delete(id) : open.add(id);
  render();
  $('expand-all').focus({ preventScroll: true });
}));
$('filter-btn').addEventListener('click', () => ($('filters').hidden ? openPanel($('filter-btn')) : closePanel()));
function setPrefs(open) {
  const box = $('prefs');
  $('prefs-btn').setAttribute('aria-expanded', open);
  box.closing?.cancel();
  if (open) {
    box.classList.add('open');
    return reveal(box, '0 -4px', 160);
  }
  if (!box.classList.contains('open')) return;
  if (reducedMotion.matches) return box.classList.remove('open');
  box.closing = box.animate([{ opacity: 1 }, { opacity: 0, translate: '0 -4px' }], { duration: 120, easing: 'cubic-bezier(0.4, 0, 1, 1)' });
  box.closing.onfinish = () => { box.closing = null; box.classList.remove('open'); };
}
$('prefs-btn').addEventListener('click', () => setPrefs(!$('prefs').classList.contains('open')));
document.addEventListener('pointerdown', (event) => {
  if ($('prefs').classList.contains('open') && !$('prefs').contains(event.target) && !$('prefs-btn').contains(event.target)) setPrefs(false);
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && $('prefs').classList.contains('open')) {
    setPrefs(false);
    $('prefs-btn').focus();
  }
});

// The search row stays at the top while the Board scrolls (like frozen panes); its height is kept in --stick so
// rows scrolled into view, the new-Incidents pill and the jump buttons clear it.
const stickyPart = () => (matchMedia('(max-width: 767px)').matches ? document.querySelector('.search-row') : $('filter'));
function measureStick() {
  document.documentElement.style.setProperty('--stick', `${stickyPart().offsetHeight}px`);
}
addEventListener('resize', measureStick);
// 맨 위로 / 맨 아래로 at the bottom right: each shows only when there is somewhere to go.
let jumpQueued = false;
function placeJump() {
  jumpQueued = false;
  const room = innerHeight * 0.6;
  $('to-top').classList.toggle('off', scrollY < room);
  $('to-bottom').classList.toggle('off', scrollY + innerHeight > document.documentElement.scrollHeight - room);
  document.body.classList.toggle('scrolled', scrollY > 40);
  // the bar's 필터 and 정렬 have passed under the frozen row: their copy shows at the end of the search line
  const past = $('board-start').getBoundingClientRect().bottom < stickyPart().getBoundingClientRect().bottom;
  stuckTools(past);
  // 맨 위로 wears how far down the page is, as a ring that fills clockwise
  const room2 = document.documentElement.scrollHeight - innerHeight;
  $('to-top').style.setProperty('--read', room2 > 0 ? Math.min(scrollY / room2, 1).toFixed(3) : 0);
  // phones: the jump buttons rest out of the way 2 s after the page stops moving
  document.body.classList.remove('jump-idle');
  clearTimeout(jumpIdle);
  jumpIdle = setTimeout(() => document.body.classList.add('jump-idle'), 2000);
}
let jumpIdle;
// The frozen copy of 필터 and 정렬 rises into the frozen row as the bar passes under it (owner: "자연스럽게 올라가는").
// It rises 10px into place while its width opens (280ms), and sinks and closes faster when the bar comes back.
// Reduced motion: it simply appears.
let stuckOn = false;
function stuckTools(on) {
  if (on === stuckOn) return;
  stuckOn = on;
  const box = $('stuck-tools');
  box.sliding?.cancel();
  // Tab meets one 필터 and one 정렬 (critique 13): the bar's originals leave the tab order while the copy shows, and a
  // focus inside the leaving copy moves to the original it stands for.
  for (const id of ['filter-btn', 'sort']) if (on) $(id).setAttribute('tabindex', '-1'); else $(id).removeAttribute('tabindex');
  if (!on && box.contains(document.activeElement)) (document.activeElement === $('stuck-sort') ? $('sort') : $('filter-btn')).focus({ preventScroll: true });
  box.hidden = false;
  searchPlaceholder();
  const done = () => { box.style.overflow = ''; box.sliding = null; box.hidden = !stuckOn; measureStick(); };
  if (reducedMotion.matches) return done();
  // Its width opens with it, so the search field gives way smoothly (owner kept this after critique 13); the controls
  // sit at the right edge of the opening box, so they are under the pointer from the first frame.
  const full = `${box.scrollWidth}px`;
  const shut = { width: '0px', opacity: 0, transform: 'translateY(10px)' };
  const open = { width: full, opacity: 1, transform: 'none' };
  box.style.overflow = 'clip';
  box.sliding = box.animate(on ? [shut, open] : [open, shut], { duration: on ? 280 : 180, easing: on ? EASE_OUT : 'cubic-bezier(0.4, 0, 1, 1)' });
  box.sliding.onfinish = done;
}
// 맨 위로 / 맨 아래로: the arrow leaves the way the page will go and comes back from the other side.
function launch(button, up) {
  if (reducedMotion.matches) return;
  const out = up ? -10 : 10;
  button.querySelector('svg').animate([
    { transform: 'none', opacity: 1 },
    { transform: `translateY(${out}px)`, opacity: 0, offset: 0.4 },
    { transform: `translateY(${-out}px)`, opacity: 0, offset: 0.41 },
    { transform: 'none', opacity: 1 },
  ], { duration: 440, easing: EASE_OUT });
}
addEventListener('scroll', () => {
  if (!jumpQueued) {
    jumpQueued = true;
    requestAnimationFrame(placeJump);
  }
}, { passive: true });
const glide = () => (reducedMotion.matches ? 'auto' : 'smooth');
$('to-top').addEventListener('click', () => scrollTo({ top: 0, behavior: glide() }));
// The logo goes back to the main Board (owner, 11-09): panel conditions and search cleared, picked Products kept,
// since they are the visitor's own setting. A modified click still opens the address in a new tab.
$('home').addEventListener('click', (e) => {
  if (e.button || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  $('search').value = '';
  update({ query: '', ...PANEL_EMPTY });
  scrollTo({ top: 0, behavior: glide() });
});
$('to-top').addEventListener('click', (event) => launch(event.currentTarget, true));
$('to-bottom').addEventListener('click', (event) => launch(event.currentTarget, false));
$('to-bottom').addEventListener('click', () => scrollTo({ top: document.documentElement.scrollHeight, behavior: glide() }));

$('guide-btn').addEventListener('click', () => {
  setGuide(!guideOpen);
  if (guideOpen) reveal($('guide'));
});
$('text-down').addEventListener('click', () => setTextIndex(TEXT_STEPS.indexOf(textPct()) - 1));
$('text-up').addEventListener('click', () => setTextIndex(TEXT_STEPS.indexOf(textPct()) + 1));
// The filter lives in the hash, so the skip link moves focus itself instead of rewriting the address.
$('skip-top').addEventListener('click', (event) => {
  event.preventDefault();
  $('board-start').focus();
});
$('skip').addEventListener('click', (event) => {
  event.preventDefault();
  $('all-head').focus();
});
darkQuery.addEventListener('change', pageText);
// Typing waits a beat before the Board redraws, so a word is one redraw, not one per letter.
let typing;
$('search').addEventListener('input', (event) => {
  clearTimeout(typing);
  typing = setTimeout(() => update({ query: event.target.value }, false), 150); // no transition under the caret
});
window.addEventListener('resize', placePill);
document.fonts?.ready.then(placePill);
window.addEventListener('hashchange', () => {
  filter = loadFilter();
  $('search').value = filter.query;
  render();
});

const el = (tag, className, textContent = '') => Object.assign(document.createElement(tag), { className, textContent });
// A CVE ID is never cut at its hyphens (critique 13: "CVE-2026-" ended a line at 320px in the Easy text).
const keepIds = (text) => String(text).split(/(CVE-\d{4}-\d{4,})/).map((part, n) => (n % 2 ? el('span', 'nw', part) : part));
// The page follows `lang`; source text in another language carries its own lang for screen readers.
const para = (className, text, language = lang) => {
  const p = Object.assign(el('p', className), { lang: language });
  p.append(...keepIds(text));
  return p;
};
// 으로 after a final consonant, 로 after a vowel or ㄹ ("맥으로", "윈도우로", "오픈ssh로").
function ro(word) {
  const code = word.charCodeAt(word.length - 1) - 0xac00;
  return code < 0 || code > 11171 || code % 28 === 0 || code % 28 === 8 ? '로' : '으로';
}

// "대처법: ..." with the label bold, so the answer is found by eye.
function labelled(className, label, text) {
  const p = para(className, '');
  p.append(el('b', '', `${label}: `), text);
  return p;
}

function summary(s) {
  const parts = [para('summary', s.summary)];
  // One condition stays on its line; several are a list ("팩스·SMS" has its own dot, so " · " between them misread).
  if (s.conditions.length === 1) parts.push(labelled('conditions', TEXT[lang].conditions, s.conditions[0]));
  if (s.conditions.length > 1) {
    const list = el('ul', 'cond-list');
    list.append(...s.conditions.map((c) => el('li', '', c)));
    parts.push(labelled('conditions', TEXT[lang].conditions, ''), list);
  }
  if (s.mitigation) parts.push(labelled('mitigation', TEXT[lang].mitigation, s.mitigation));
  return parts;
}

// One release's CVEs grouped into one Incident (collector: group_releases): the Normal view names what each one does,
// from the Summary's Korean/English lines, else each CVE record's own description (English) until the Summary comes.
function cveList(incident) {
  if (incident.cves.length < 2) return [];
  const fromSummary = incident.summary?.[lang]?.cve_lines;
  const texts = incident.cve_texts || {};
  const lines = fromSummary?.length ? fromSummary : incident.cves.filter((c) => texts[c]).map((cve) => ({ cve, text: texts[cve] }));
  if (!lines.length) return [];
  const item = (line) => {
    const li = el('li');
    const id = el('strong');
    id.append(anchor(`https://www.cve.org/CVERecord?id=${encodeURIComponent(line.cve)}`, line.cve, false));
    li.append(id, line.text);
    const own = incident.cve_links?.[line.cve] || [];
    if (own.length) {
      const src = el('span', 'cve-src');
      const many = (kind) => own.filter((l) => l.kind === kind).length > 1; // two advisories read 공지 1 · 공지 2
      const seen = {};
      own.forEach((l, n) => {
        seen[l.kind] = (seen[l.kind] || 0) + 1;
        const name = TEXT[lang].linkKind[l.kind] || host(l.url);
        const a = anchor(l.url, many(l.kind) ? `${name} ${seen[l.kind]}` : name, false);
        a.setAttribute('aria-label', `${line.cve} ${a.textContent}`);
        src.append(...(n ? [' · '] : []), a);
      });
      li.append(' ', src);
    }
    return li;
  };
  const list = el('ul', 'cve-lines');
  list.append(...lines.slice(0, 3).map(item));
  const head = para('cve-lines-head', TEXT[lang].cveLines(lines.length));
  head.append(el('span', 'sr-only', TEXT[lang].newTabAll)); // said once for the list, not after each of its links
  const out = [head, list];
  if (lines.length > 3) {
    const fold = el('details', 'models');
    const rest = el('ul', 'cve-lines');
    rest.append(...lines.slice(3).map(item));
    const label = el('summary', '', TEXT[lang].moreLines(lines.length - 3));
    fold.addEventListener('toggle', () => { label.textContent = fold.open ? TEXT[lang].foldLess : TEXT[lang].moreLines(lines.length - 3); });
    fold.append(label, rest);
    out.push(fold);
  }
  return out;
}

// Until the Summary arrives the row's title is the quick title, else the Brief; the panel is the same in both views
// (critique 14): the note, then the source's own line under its label, then the links.
const briefNote = (incident) => {
  const source = para('brief-src', '');
  source.append(el('span', 'orig', TEXT[lang].originalEn), ' ');
  source.append(Object.assign(el('span', '', incident.brief.text), { lang: 'en' })); // the source's own words, not the quick title
  return [para('preparing', TEXT[lang][briefMarker(incident)]), source];
};

// One or two CVE IDs on a line, each kept whole ("CVE-2026-" never ends a line).
function idLine(cves) {
  const p = para('cve-line', '');
  cves.forEach((cve, n) => p.append(...(n ? [', '] : []), el('span', '', cve)));
  return p;
}

// The Lead mention is always the rule-based one (CONTEXT.md order), never the model's pick.
function leadLine(incident) {
  const lead = el('p', 'lead');
  // Named by what it is, then where (critique 13: the domain alone did not say advisory or write-up).
  const kind = incident.mentions.find((m) => m.url === incident.brief.lead)?.kind;
  const words = TEXT[lang].lead;
  lead.append(anchor(incident.brief.lead, `${words[kind] || words.other} · ${host(incident.brief.lead)}`));
  return lead;
}

// A command from a source, shown as is, with a button that copies exactly the text shown.
function commandLine(text) {
  const p = el('p', 'command');
  const code = el('code', '', text);
  const button = Object.assign(el('button', 'btn', TEXT[lang].copy), { type: 'button' });
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(code.textContent);
      // A stamp: the button says 복사됨 with a check and the command lights up, then both settle back.
      const ok = el('span', 'ok');
      ok.setAttribute('aria-hidden', 'true');
      ok.innerHTML = '<svg viewBox="0 0 16 16"><path d="m3.5 8.3 2.8 2.8 6.2-6.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
      const label = el('span', '', TEXT[lang].copied);
      button.replaceChildren(ok, label);
      draw(ok.querySelector('path'), 280);
      pop(label, 'translateX(-4px)', 200);
      $('announce').textContent = TEXT[lang].copied;
      p.classList.add('stamped');
      clearTimeout(button.settle);
      button.settle = setTimeout(() => { button.textContent = TEXT[lang].copy; p.classList.remove('stamped'); }, 2000);
    } catch {
      getSelection().selectAllChildren(code); // clipboard blocked: select it for a manual copy
    }
  });
  p.append(code, ' ', button);
  return p;
}

// A config line, not a shell command: no copy button that invites pasting it into a terminal, and a warning.
// file: the config file a source names for it ("/etc/ssh/sshd_config"), else the reader is told only "the config file".
function settingLine(text, file = '', cls = 'action') {
  const t = TEXT[lang];
  const p = el('p', 'command');
  p.append(el('code', '', text));
  const caution = para('caution', '');
  caution.innerHTML = WARN;
  caution.append(el('span', '', t.caution));
  return [para(cls, typeof file === 'string' && file ? t.settingIn(file) : t.setting), p, caution];
}

// product: the row's first Product, so an update line says what to update ("OpenEMR 8.3.0 이상으로"; critique 13).
// library: a part built into other programs (isLibrary), whose version the reader cannot see on any screen.
function easyAnswer(s, level, cve = '', product = '', library = false) {
  const t = TEXT[lang];
  const action = easyAction(s);
  const parts = []; // the plain sentence is already the row's second line
  // Product lines with their own fixed versions (SonicWall Gen7 7.3.4-7013, Gen8 8.2.3-8015): one line each, and the
  // long model list folded away under them.
  const fixes = (Array.isArray(s.fixes) ? s.fixes : []).filter((f) => typeof f?.for === 'string' && typeof f?.version === 'string' && f.for && f.version);
  if (fixes.length > 1) {
    const list = el('ul', 'fixes');
    for (const f of fixes) {
      const li = el('li', '');
      li.append(el('strong', '', f.for), ' ', el('span', 'ver', t.orNewer(f.version)));
      list.append(li);
    }
    parts.push(para('action', t.fixesIntro), list);
  } else {
    const where = s[lang].command_for; // "Alpine 리눅스라면": the command is for one system only
    // A command for one system only: everyone else (OpenWrt, Buildroot…) still gets the version to reach, first.
    const others = action.kind === 'command' && where && s.fixed && !fixes.length;
    if (others) parts.push(para('action', t.version(s.fixed, product)));
    if (action.kind === 'command') parts.push(...(isShellCommand(action.command) ? [para(others ? 'step' : 'action', where ? t.commandFor(where) : t.command), commandLine(action.command)] : settingLine(action.command)));
    if (action.kind === 'version') parts.push(para('action', t.version(action.fixed, product)));
    // No fixed version, command or devices: the Summary's plain action sentence; Summaries made before it existed fall
    // back to the normal advice ("run newer than 7.3.3-7015"), else say we have not confirmed one.
    if (action.kind === 'none') parts.push(para('action', s[lang].easy_action || s[lang].mitigation || t.noneEasy));
    if (action.kind === 'devices') {
      const list = el('ul', 'devices');
      list.append(...action.devices.map((d) => el('li', '', d)));
      // A long model list sits folded in step 1 ("이 제품을 쓰고 있나요?"), where the reader looks for their model.
      parts.push(para('action', easyLine(t.devices, level)), ...(action.devices.length > MANY_DEVICES ? [] : [list]));
      if (action.fixed) parts.push(para('fixed', t.fixedIn(action.fixed)));
    }
  }
  // A version to compare with: one line on where to look, not a how-to (user, 11-08: readers ask the vendor or an AI).
  const versionToCheck = fixes.length > 1 || action.kind === 'version' || (action.kind === 'devices' && action.fixed)
    || (action.kind === 'command' && s[lang].command_for && s.fixed && !fixes.length);
  if (versionToCheck) parts.push(para('hint', library ? t.libraryHelp : t.versionHelp(cve)));
  if (action.stopgap) parts.push(para('stopgap', t.stopgap), ...(isShellCommand(action.stopgap) ? [commandLine(action.stopgap)] : settingLine(action.stopgap, s.stopgap_file, 'step')));
  // The step the stopgap needs to take effect ("바꾼 뒤 sshd를 다시 시작하세요."), when a source says it.
  if (action.stopgap && s[lang].stopgap_then) parts.push(para('step', s[lang].stopgap_then));
  return parts;
}

// Fix lines that name their own models (SonicWall Gen7: TZ270, TZ370...), so the reader finds their model under its line.
const fixLines = (s) => (Array.isArray(s.fixes) ? s.fixes : []).filter((f) => typeof f?.for === 'string' && f.for
  && Array.isArray(f.devices) && f.devices.length && f.devices.every((d) => typeof d === 'string'));

// A long list of affected models, folded: the reader opens it only to find their own model. With fix lines, the models
// sit under their line's name, and any model no line names comes last.
function modelList(models, lines = []) {
  const box = el('details', 'models');
  const list = el('ul', lines.length ? 'lines' : '');
  const plain = (names) => names.map((m) => el('li', '', m));
  if (lines.length) {
    const named = new Set(lines.flatMap((f) => f.devices));
    for (const f of lines) {
      const li = el('li', '');
      const sub = el('ul', '');
      // Under "SonicWall Gen7" the models drop the vendor they share with it: "TZ 270", not "SonicWall TZ 270" 22 times.
      const vendor = `${f.for.split(' ')[0]} `;
      sub.append(...plain(f.devices.map((d) => (d.startsWith(vendor) && d.length > vendor.length ? d.slice(vendor.length) : d))));
      li.append(el('strong', '', f.for), sub);
      list.append(li);
    }
    list.append(...plain(models.filter((m) => !named.has(m))));
  } else list.append(...plain(models));
  const summary = el('summary', '', TEXT[lang].models(models.length));
  // The same fold as a row: the browser would snap the list open and shut.
  summary.addEventListener('click', (event) => {
    event.preventDefault();
    const opening = !box.open || Boolean(box.dataset.closing); // clicked while closing: open again
    delete box.dataset.closing;
    if (opening) {
      box.open = true;
      fold(list, true);
    } else {
      box.dataset.closing = '1';
      fold(list, false, () => { if (box.dataset.closing) box.open = false; delete box.dataset.closing; });
    }
  });
  box.append(summary, list);
  return box;
}

// The row's start: the rule-based Risk word as a ring sign in its colour (both views, all three levels).
function riskCell(incident) {
  const level = riskLevel(incident);
  const easy = defaultView === 'easy';
  // In both views the risk word is a sign (index.html, .loud); only the words differ.
  // Not rated yet: 참고 is only the level for now, not a low score (critique 12); its sign is dashed like the empty
  // score ring (critique 13), and 점수 대기 sits under it like 악용 발생, one word in both views.
  const pending = !isExploited(incident) && !cvssRating(incident.cvss);
  const cell = el('span', `c-risk risk-${level} loud${pending ? ' unrated' : ''}`);
  cell.append(el('b', 'word', easy ? TEXT[lang][level] : TEXT[lang].levels[level]));
  // Why it is this high when the score alone would not say so: exploited (KEV, or attacks its sources report) lifts it to the top level.
  // The space keeps screen readers from running the two words together ("심각!악용 발생"); flex hides it on screen.
  if (isExploited(incident)) cell.append(' ', el('small', 'why kev', (easy && TEXT[lang].kevReasonEasy) || TEXT[lang].kevReason));
  else if (pending) cell.append(' ', el('small', 'why unrated', TEXT[lang].unratedWhy));
  return cell;
}

// CVSS in both views: a ring filled to the score out of 10 with the number inside, coloured by its rating.
// "Exploited" is said once, under the risk word.
function scoreCell(incident) {
  const t = TEXT[lang];
  const cell = el('span', 'c-score');
  const rating = cvssRating(incident.cvss);
  if (!rating) {
    // No score yet: a quiet dash, not an empty ring or the same words down the Board; the meaning is in the
    // tooltip and for screen readers.
    const ring = Object.assign(el('span', 'gauge unrated', '—'), { title: t.unrated });
    ring.setAttribute('role', 'img');
    ring.setAttribute('aria-label', t.unrated);
    cell.append(ring);
    return cell;
  }
  const gauge = el('span', `gauge sev-${rating}`);
  gauge.setAttribute('role', 'img');
  gauge.setAttribute('aria-label', `CVSS ${incident.cvss}`); // the risk word is the one severity word
  gauge.style.setProperty('--fill', Math.min(incident.cvss, 10) / 10);
  gauge.innerHTML = '<svg viewBox="0 0 40 40" aria-hidden="true"><circle class="track" cx="20" cy="20" r="17" pathLength="1"/><circle class="arc" cx="20" cy="20" r="17" pathLength="1"/></svg>';
  gauge.title = `CVSS ${incident.cvss.toFixed(1)}`;
  gauge.append(el('b', 'num', incident.cvss.toFixed(1)));
  // The ring alone: the risk word is the one severity word, and the reading guide names the ring.
  cell.append(gauge);
  return cell;
}

// The Incident's own title: the Summary's, else the Brief marked as source text (English).
function describe(incident) {
  const t = TEXT[lang];
  if (incident.summary?.[lang].title) return [incident.summary[lang].title]; // empty for some news replies
  if (incident.quick_title?.[lang]?.title) return [incident.quick_title[lang].title]; // titles first, Summary later (collector)
  const brief = Object.assign(el('span', '', incident.brief.text), { lang: 'en' });
  return t.original ? [el('span', 'orig', t.original), ' ', brief] : [brief];
}

// A station sign: in the normal view the CVE ID is the bold name and the title the line under it. The
// Easy view leads with the plain headline over the one plain sentence; with no Summary yet, or no CVE
// yet, the title leads and the CVE line goes under it.
function titleCell(incident, vendor = '') {
  const t = TEXT[lang];
  const cell = el('span', 'c-title');
  const head = cveHead(incident.cves);
  const id = el('span', head ? 'cve' : 'cve none');
  if (head) {
    id.append(head.id);
    if (head.more) id.append(el('span', 'cve-more', t.moreCves(head.more)));
    id.title = incident.cves.join(', ');
  } else id.append(t.noCve);
  const name = el('strong', 'title');
  const line = el('small', 'sub');
  const s = incident.summary?.[lang];
  // An Easy headline names its product (critique 14): the row's first Product, in this language and the other.
  const firstProduct = (l) => rowTags(incident, l).find((n) => !OSES.includes(n));
  // Inside a vendor fold the title names that vendor (critique 14: "Langflow OSS …" in the IBM fold).
  const led = (title) => (vendor ? vendorLedTitle(title, vendor, firstProduct(lang)) : title);
  const named = (title) => led(namedHeadline(easyTitle(title, riskLevel(incident)), [firstProduct(lang), firstProduct(lang === 'ko' ? 'en' : 'ko')].filter(Boolean)));
  if (defaultView === 'easy' && s?.title) {
    name.append(s.easy_title ? named(s.easy_title) : led(s.title)); // Summaries made before 11-08 have no easy_title
    line.append(...keepIds(easyLine(s.easy || s.summary, riskLevel(incident))));
    line.classList.add('say');
  } else if (defaultView === 'easy' && !s?.title) {
    const product = rowTags(incident, lang).find((n) => !OSES.includes(n));
    const quick = incident.quick_title?.[lang]?.easy_title;
    // No quick title and no Product to name: the source's own line, not a blank "새 보안 문제" (critique 10).
    name.append(quick ? named(quick) : product ? t.easyBrief(product) : Object.assign(el('span', '', incident.brief.text), { lang: 'en' }));
    // A Summary that failed for good is not "coming": the row says the source is all there is. Plain hint words in the
    // line under the title, not a square tag that reads like 묶음 / 함께 패치 (critique 13).
    line.append(briefMarker(incident) === 'unavailable' ? t.origOnly : t.easyPrepTag);
  } else {
    // Both views lead with what happened (owner, 11-09): the CVE ID is the line under it.
    name.append(...describe(incident).map((part) => (typeof part === 'string' ? led(part) : part)));
    line.append(id);
  }
  cell.append(name, line);
  return cell;
}

// A Product's line badge, in that Product's fixed colour.
// key: the Product id (language-free), so a Product keeps its line in both languages; else the name itself.
function lineBadge(name, key = name) {
  // One line always: a long name ends in "…" inside the pill and shows whole on hover (title) and to screen readers.
  const badge = Object.assign(el('span', 'ln'), { title: name });
  badge.append(el('span', 'ln-t', name));
  const { bg, ink } = productLine(key);
  badge.style.setProperty('--line', bg);
  badge.style.setProperty('--line-ink', ink);
  return badge;
}

// An operating system the software runs on: an outline, not a line colour, so it never reads as the Product.
// Screen readers hear "(OS)" once, after the last one ("Windows macOS Linux (OS) Perl"); sighted readers see the outline.
const osBadge = (name, last = true) => {
  const badge = el('span', 'ln os', name);
  if (last) badge.append(el('span', 'sr-only', ' (OS)'));
  return badge;
};

// A release group (more than two CVEs fixed together) or a vendor fold: one row standing for several Incidents.
const isGroup = (incident) => (incident.cves?.length || 0) > 2;
// Its tag leads the badge cell: a square-cornered outline in ink, so it never reads as a Product (filled pill) or an
// OS (outlined pill).
const groupTag = () => el('span', 'grp', TEXT[lang].groupTag);
// A release group is one Incident (CVEs fixed by one update), not a fold: its own word, so 묶음 풀기 leaves it alone without contradiction.
const patchTag = () => el('span', 'grp', TEXT[lang].patchTag);

function tagsCell(incident) {
  const cell = el('span', 'c-tags');
  if (isGroup(incident)) cell.append(patchTag(), ' ');
  const os = new Set(Array.isArray(incident.summary?.platforms) ? incident.summary.platforms : []);
  const keys = lineKeys(incident, lang);
  const names = rowTags(incident, lang);
  const lastOs = names.findLastIndex((name) => os.has(name));
  // Spaces between badges keep screen readers from running the names together; the flex row hides them.
  names.forEach((name, n) => cell.append(...(n ? [' '] : []), os.has(name) ? osBadge(name, n === lastOs) : lineBadge(name, keys.get(name))));
  return cell;
}

// "2시간 전" / "2 hours ago"; the date from 30 days on.
function ago(iso) {
  const age = relativeAge(iso, Date.now());
  return age ? new Intl.RelativeTimeFormat(lang, { numeric: 'always' }).format(age.value, age.unit) : iso.slice(0, 10);
}

// When the news first broke, in the visitor's time zone: the date over the time; how long ago in the tooltip.
function dateCell(incident) {
  const at = publishedAt(incident);
  const d = new Date(at);
  const two = (n) => String(n).padStart(2, '0');
  const time = el('time', 'c-date');
  time.dateTime = at;
  const clock = `${two(d.getHours())}:${two(d.getMinutes())}`;
  // No source gave a time: the Board's first sighting, said as such, never passed off as the publish time.
  // The space keeps screen readers from reading the date and time as one run (critique 14); flex hides it on screen.
  time.append(el('span', '', `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}`), ' ', el('span', '', incident.published ? clock : TEXT[lang].firstSeenAt(clock)));
  time.title = `${incident.published ? TEXT[lang].published : TEXT[lang].firstSeen} · ${ago(at)}`;
  return time;
}

// Both views end with the Lead and every Mention, so links a CVE record gains later show up in either.
function details(incident) {
  const t = TEXT[lang];
  const easy = defaultView === 'easy';
  const parts = !incident.summary ? briefNote(incident) : easy ? easyPanel(incident) : summary(incident.summary[lang]);
  const list = easy ? [] : cveList(incident); // every CVE's issue in the Normal view (user, 2026-11-09)
  // Public exploit code without reported attacks: no sign, a red line in the summary text (owner, 2026-11-09).
  if (incident.summary?.poc_public === true && !isExploited(incident)) parts.splice(easy ? 0 : 1, 0, para('kev', easy ? t.pocEasy : t.poc));
  // Why the row is 악용 발생 (critique 14): the KEV listing, else the source that reports the attacks, first in the panel.
  const reason = exploitReason(incident);
  if (reason) {
    const why = para('why-line', reason.kind === 'kev' ? t.kevListed : `${t.attackSource} `);
    if (reason.kind === 'kev' && reason.date) why.append(' · ', el('span', 'nw', reason.date)); // the day never breaks at its hyphens
    if (reason.kind === 'source') why.append(anchor(reason.url, host(reason.url)));
    parts.unshift(why);
  }
  // The Easy row leads with a plain headline, so the opened panel starts with the CVE IDs.
  if (easy && isExploited(incident)) parts.unshift(para('kev', t.kevEasy));
  // Easy: a few IDs lead the panel; a group's count follows the action instead of a wall of IDs.
  // Easy: "CVE 3건" opens to every ID, each linked to its CVE record (owner, 11-09).
  if (easy && incident.cves.length > 2) {
    const fold = el('details', 'models cve-fold');
    const ids = el('ul', '');
    for (const cve of incident.cves) {
      const li = el('li', '');
      li.append(anchor(`https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}`, cve, false));
      ids.append(li);
    }
    const head = el('summary', '', t.cveCount(incident.cves.length));
    head.append(el('span', 'sr-only', t.newTabAll));
    fold.append(head, ids);
    parts.push(fold);
  }
  else if (easy && incident.cves.length) parts.unshift(idLine(incident.cves));
  const mentions = el('ul', 'mentions');
  const order = ['advisory', 'writeup', 'cve_record', 'discussion', 'curator', 'repo'];
  const rank = (m) => (order.includes(m.kind) ? order.indexOf(m.kind) : order.length);
  const lastPart = (url) => {
    try {
      const u = new URL(url);
      return u.searchParams.get('id') || decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || ''); // cve.org: ?id=CVE-…
    } catch {
      return ''; // a malformed address from a source: the site name stands in
    }
  };
  const linkOf = (m, fallback) => {
    // On the Korean page an English title shows the Summary's Korean line; the original stays in the tooltip.
    const gloss = lang === 'ko' && m.title && (incident.summary?.titles_ko || []).find((g) => g?.url === m.url && typeof g.title === 'string')?.title;
    const link = anchor(m.url, gloss || m.title || fallback);
    if (gloss) link.title = m.title;
    return link;
  };
  // A release group brings dozens of advisories from one site ("보안 공지: github.com" 29 times): three or more of one
  // kind on one site fold into one line, each link named by the last part of its address (GHSA-xxxx).
  const groups = new Map();
  const linkedAbove = incident.cves.length > 2; // a group links each CVE record from its CVE list
  for (const m of [...incident.mentions].sort((a, b) => rank(a) - rank(b))) {
    if (linkedAbove && (m.kind === 'cve_record' || (incident.cve_links && ['advisory', 'writeup'].includes(m.kind)))) continue; // on each CVE's line
    const key = `${m.kind} ${host(m.url)}`;
    groups.set(key, [...(groups.get(key) || []), m]);
  }
  for (const list of groups.values()) {
    const label = t.mentions[list[0].kind] ?? list[0].kind;
    if (list.length < 3) {
      for (const m of list) {
        const item = el('li', '');
        item.append(`${label}: `, linkOf(m, host(m.url)));
        mentions.append(item);
      }
      continue;
    }
    const fold = el('details', 'models');
    const inner = el('ul', '');
    for (const m of list) {
      const li = el('li', '');
      li.append(linkOf(m, lastPart(m.url) || host(m.url)));
      inner.append(li);
    }
    fold.append(el('summary', '', t.mentionsMany(label, host(list[0].url), list.length)), inner);
    const item = el('li', '');
    item.append(fold);
    mentions.append(item);
  }
  return [...parts, leadLine(incident), ...list, mentions, shareLine(incident)];
}

let rowCount = 0;

// A vendor's bulk push as one line ("IBM 보안 공지 25건 · 최고 9.9"); opened, its rows follow it as ordinary rows.
const openFolds = new Set();

// The fold is drawn as an ordinary row (same risk sign, ring, title, badge and date columns), so it reads as part of
// the list: the gravest member's risk and the highest score, the vendor as its badge, the newest date; the title says
// how many it holds and the line under it names the products. Opened, the fold and its members stand on the panel
// ground (as an opened row's details do) in one list item, members in their own list, and a closing line 〈IBM 묶음
// 접기〉 marks where the group ends, so the sort below it is not read as broken (critique 9). Columns stay aligned.
function foldRows(group) {
  const t = TEXT[lang];
  const opened = openFolds.has(group.fold);
  const members = group.incidents;
  const gravest = [...members].sort((a, b) => RISKS.indexOf(riskLevel(a)) - RISKS.indexOf(riskLevel(b)))[0];
  const top = [...members].sort((a, b) => (b.cvss || 0) - (a.cvss || 0))[0];
  const newest = [...members].sort((a, b) => publishedAt(b).localeCompare(publishedAt(a)))[0];
  const li = el('li', opened ? 'vendor-fold open' : 'vendor-fold');
  li.dataset.ids = members.map((i) => i.id).join(' ');
  if (members.some((i) => fresh.has(i.id))) li.classList.add('fresh');
  li.dataset.vt = rowName(`fold:${group.fold}`);
  const button = Object.assign(el('button', 'row'), { type: 'button' });
  button.dataset.fold = group.fold;
  button.setAttribute('aria-expanded', opened);
  const wp = group.vendor === WORDPRESS; // the WordPress fold (critique 14 c.1): same row, its own words
  const vendor = wp ? t.wpFold : vendorName(group.vendor);
  const foldTitle = wp ? t.wpFoldTitle(members.length) : t.vendorFold(vendor, members.length);
  const listId = `fold-${group.fold.replace(/[^\w-]/g, '-')}`;
  if (opened) button.setAttribute('aria-controls', listId);
  const title = el('span', 'c-title');
  const products = uniqueNames(members.map((i) => rowTags(i, lang).find((n) => !OSES.includes(n))).filter(Boolean).map((n) => (wp ? pluginName(n) : n)));
  title.append(el('strong', 'title', foldTitle),
    el('small', 'sub', products.slice(0, 3).join(', ') + (products.length > 3 ? ` ${t.moreProducts(products.length - 3)}` : '')));
  const tags = el('span', 'c-tags');
  tags.append(groupTag(), ' ', lineBadge(wp ? 'WordPress' : vendor, group.vendor)); // Product names are never translated
  const chevron = el('i', 'chev');
  chevron.setAttribute('aria-hidden', 'true');
  button.append(riskCell(gravest), title, scoreCell(top), tags, dateCell(newest), chevron);
  const foldRow = () => document.querySelector(`button.row[data-fold="${CSS.escape(group.fold)}"]`);
  const toggle = (closing) => {
    if (closing) {
      const body = foldRow()?.closest('li').querySelector(':scope > .fold-body');
      const done = () => {
        openFolds.delete(group.fold);
        render();
        clearTimeout(announcing);
        $('announce').textContent = t.foldClosed(vendor);
        foldRow()?.focus({ preventScroll: true });
        foldRow()?.scrollIntoView({ block: 'nearest' }); // closed from the bottom: bring the row back into view
      };
      return body ? fold(body, false, done) : done();
    }
    openFolds.add(group.fold);
    render();
    const body = foldRow()?.closest('li').querySelector(':scope > .fold-body');
    foldRow()?.focus({ preventScroll: true });
    if (body) {
      fold(body, true);
      if (!reducedMotion.matches) {
        [...body.querySelectorAll('.fold-members > li')].slice(0, 10).forEach((m, n) => m.animate(
          [{ opacity: 0, translate: '0 -6px' }, { opacity: 1, translate: '0 0' }],
          { duration: 240, delay: 40 + n * 24, easing: EASE_OUT, fill: 'backwards' }));
      }
    }
    clearTimeout(announcing);
    $('announce').textContent = t.foldOpened(vendor, members.length, wp);
  };
  button.addEventListener('click', () => toggle(opened));
  const heading = el('h3', 'row-h');
  heading.append(button);
  li.append(heading);
  if (opened) {
    const list = Object.assign(el('ol', 'fold-members'), { id: listId });
    list.setAttribute('aria-label', foldTitle);
    list.append(...members.map((i) => row(i, false, knownVendor(group.vendor))));
    const end = el('div', 'fold-end');
    const close = Object.assign(el('button', 'btn'), { type: 'button' });
    const up = el('i', 'chev');
    up.setAttribute('aria-hidden', 'true');
    close.append(up, t.foldEnd(vendor));
    close.addEventListener('click', () => toggle(true));
    end.append(close);
    const body = el('div', 'fold-body');
    body.append(list, end);
    li.append(body);
  }
  return [li];
}


// One board row: a button that opens the details below it, like opening a post. A Highlight is a framed
// alert edged in its Risk colour, with the details inside the frame.
function row(incident, pinned, vendor = '') {
  const li = el('li', pinned ? `alert risk-${riskLevel(incident)}` : isGroup(incident) ? 'grouped' : '');
  li.dataset.ids = incident.id;
  if (fresh.has(incident.id)) li.classList.add('fresh');
  li.dataset.vt = rowName(incident.id); // boardTransition names it: the same row before and after a redraw
  const body = Object.assign(el('div', defaultView === 'easy' ? 'details easy' : 'details'), { id: `details-${++rowCount}`, hidden: !open.has(incident.id) });
  const button = Object.assign(el('button', 'row'), { type: 'button' });
  button.setAttribute('aria-controls', body.id);
  button.setAttribute('aria-expanded', !body.hidden);
  const chevron = el('i', 'chev');
  chevron.setAttribute('aria-hidden', 'true');
  const risk = riskCell(incident);
  const why = pinned && pinReason(incident);
  if (why) risk.append(el('small', 'why', TEXT[lang].why[why]));
  const cells = { risk, title: titleCell(incident, vendor), score: scoreCell(incident), tags: tagsCell(incident), date: dateCell(incident) };
  for (const [k, cell] of Object.entries(cells)) cell.id = `${body.id}-${k}`;
  cells.title.querySelector('.title').id = `${body.id}-name`;
  cells.title.querySelector('.sub').id = `${body.id}-sub`;
  // Screen readers hear the bold title and risk as the row's name, the rest as its description, not one long name.
  button.setAttribute('aria-labelledby', `${body.id}-name ${body.id}-risk`);
  button.setAttribute('aria-describedby', `${body.id}-sub ${body.id}-score ${body.id}-tags ${body.id}-date`);
  button.append(...Object.values(cells), chevron);
  button.addEventListener('click', () => {
    const opening = !open.has(incident.id);
    button.setAttribute('aria-expanded', opening);
    if (opening) {
      open.add(incident.id);
      body.hidden = false;
      fold(body, true);
    } else {
      open.delete(incident.id);
      fold(body, false, () => { body.hidden = !open.has(incident.id); }); // reopened mid-way: stay open
    }
  });
  body.append(...details(incident));
  const heading = el('h3', 'row-h');
  heading.append(button);
  li.append(heading, body);
  return li;
}

main();
