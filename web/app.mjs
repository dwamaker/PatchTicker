import { cveLines, cveExploit, cveScore, exploitedCves, scorePair, scoreCve, searchedCve, WORDPRESS, pluginName, aliasesUsed, exploitReason, isLibrary, namedHeadline, knownVendor, vendorLedTitle, vendorName, foldByVendor, uniqueNames, pickerEntries, rankEntries, mergeIncidents, LINK_KINDS, OSES, PINNED, RISKS, SORTS, pinReason, briefMarker, cveHead, easyLine, easyTitle, isShellCommand, MANY_DEVICES, onBoard, cvssRating, easyAction, filterBoard, isExploited, lineKeys, rowPlatforms, orderBy, filterFromQuery, filterToQuery, nameLine, productList, publishedAt, relativeAge, riskLevel, pendingWhy, severityWord, provisionalLevel, rowTags, shareLink, slug, viewFromStorage, firstProduct, mentionGroups, cveUrl, usableFixes, reportUrl, WORDS, tagFilters, foldTags, linkedPlace, productOthers, publicDay, conditionIds, distroTable, foldNewest, localDay, fixTable, fixesLead, FIXES_SHOWN, rowKey, pinOrder, stepDistance, nextPage, sinceStillTrue, productLine, answerCounts, MENTION_ORDER } from './board.mjs';
import { feedPath, productFeed, statusCounts, LANGS, withJapanese, giveJapanese, groupKey, listboxStep, restingStop } from './board.mjs';


// The store's base URL: web/data/ on this machine, the R2 bucket's own domain everywhere else.
// shortcut: the first address (patchticker.dwamaker.com) keeps its own data domain until it redirects to patchticker.com;
// drop that branch once the redirect is on.
const DATA_URL = ['localhost', '127.0.0.1'].includes(location.hostname) ? 'data/'
  : location.hostname.endsWith('.dwamaker.com') ? 'https://patchticker-data.dwamaker.com/' : 'https://data.patchticker.com/';
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
// Storage can be blocked (private windows): a read then gives `blocked`, a write does nothing and the choice lasts until reload.
function stored(key, blocked = null) {
  try {
    return localStorage.getItem(key);
  } catch {
    return blocked;
  }
}
function store(key, value) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // blocked
  }
}
// Every UI string, per language: the visitor's toggle, else the browser's language.
// The words the Incident page and the RSS feed show too come from WORDS (web/board.mjs), so they are written once.
// Only CVE IDs, Product names, URLs and source data (the Brief's own line, Mention titles) are shown as they come.
// The NVD notice keeps its required English sentence in index.html; `nvd` is the Korean line beside it.
const TEXT = {
  ko: {
    ...WORDS.ko,
    brand: 'Patch Ticker', loading: '불러오는 중…',
    variants: (n) => `비슷한 이름 ${n}건도 함께 보여 줍니다.`,
    loadDetail: (msg) => `자세한 내용: ${msg}`, olderDone: (n) => (n ? `이전 사건을 모두 불러왔습니다 (${n}건 추가).` : '이전 사건은 이미 모두 목록에 있습니다.'),
    loadError: '현황판을 불러오지 못했습니다. 인터넷 연결을 확인하고 다시 시도하세요.', olderFailed: '이전 사건을 불러오지 못했습니다. 인터넷 연결을 확인하고 다시 시도하세요.', retry: '다시 시도', filterBtn: '필터', fp: { title: '필터', published: '게시일', from: '게시일 시작', to: '게시일 끝', cvss: '최소 CVSS 점수', cve: 'CVE 번호', any: '전체', cveYes: 'CVE 번호 있음', cveNo: 'CVE 번호 아직 없음', risk: '위험 단계', flags: '공격·공지 여부', has: { advisory: '공식 공지 있음', repo: '공격 코드 공개됨' }, sort: '정렬', sorts: { new: '최신순', risk: '위험도순', cvss: 'CVSS 높은순' }, close: '닫기', reset: '필터 초기화', apply: '필터 적용', applyN: (n) => `필터 적용 · ${n}건`, zeroChip: '이 조건을 더하면 0건이 됩니다', riskNote: '점수 대기: CVSS 점수가 아직 없는 사건. 실제 공격이 보고된 사건은 점수가 없어도 맨 위 단계에 들어 있습니다.', osNote: '고른 운영체제에서 돌아가는 프로그램이 모두 나옵니다.', zeroNote: '점선 칩은 지금 조건에 더하면 0건이 됩니다.', dropCond: (l) => `‘${l}’ 빼기` }, textSizeGroup: '글자 크기', textGlyph: '가', textDown: '글자 작게', textUp: '글자 크게', textNow: (p) => `글자 크기 ${p}%`, pinMore: (n) => `주요 사건 더 보기 (${n})`, pinLess: '주요 사건 접기', pinShown: (s, n) => `${n}건 중 ${s}건 표시`, qfKev: '공격 발생만', noneForFilters: '고른 조건에 맞는 사건이 지금 현황판에 없습니다.', easyLevels: { highest: '긴급!', high: '경계', pending: '점수 대기', notice: '주의' }, why: { curator: '보안 뉴스레터 언급', buzz: 'HN 화제' }, reportedBy: (h) => `${h} 보도`, skip: '주요 사건 건너뛰고 최신순으로', skipTop: '현황판으로 건너뛰기', found: (n) => `${n}건이 보입니다.`, sorted: (s) => `${s}으로 정렬했습니다.`,
    status: (updated) => `마지막 업데이트 ${updated}`, counts: (today, week) => ` · 오늘 ${today}건 · 7일 ${week}건`, countAll: (n) => ` · 전체 ${n}건`, shownOf: (shown, all) => ` · ${all}건 중 ${shown}건`,
    products: '사용하는 제품', tokensSet: (n) => `선택 ${n}개`, sgHead: '제품', sgCount: (n) => `최근 30일 ${n}건`, resultCount: (n) => `${n.toLocaleString('ko')}건`, picked: '고른 제품', fpApplied: '적용한 필터', remove: (name) => `${name} 빼기`,
    repo: 'GitHub 저장소', search: '검색', clearSearch: '검색어 지우기', noticeClose: '알림 닫기', noticeSince: ['Patch Ticker는 2026년 11월 9일부터 수집을 시작했습니다.', '그 전에 공개된 취약점은 목록에 없을 수 있습니다.'], noticeKeep: '패치가 나와도 사건은 지워지지 않고 90일 동안 남습니다.', searchHint: '제품, 키워드, CVE 번호', searchHintShort: '제품, 키워드', all: '최신순', sortLabel: '정렬', expandAll: '모두 펼치기', collapseAll: '모두 접기', unfold: '묶음 풀기', refold: '묶어 보기', groupTag: '묶음', patchTag: '함께 공개', prefs: '화면 설정', toTop: '맨 위로', toBottom: '맨 아래로', stepUp: '한 화면 위로', stepDown: '한 화면 아래로', stepGroup: '한 화면씩 이동', newAbove: (n) => `새 사건 ${n}건`, newAdded: (n) => `새 사건 ${n}건이 추가되었습니다.`, toNew: '첫 새 사건으로 이동', foldEnd: (v) => `${v} 묶음 접기`, foldOpened: (v, n, wp) => `${v} 묶음을 펼쳤습니다 (${wp ? '플러그인' : '공지'} ${n}건).`, theme: '어두운 화면',
    pin: '주요 사건', pinOne: '주요 사건', noCve: 'CVE 번호 아직 없음', moreCves: (n) => ` 외 ${n}건`, firstSeen: '게시 시각을 모르는 사건이라 이 현황판이 처음 확인한 시각입니다', firstSeenAt: (t) => `처음 확인 ${t}`, easyWhen: '이럴 때만 해당돼요:', someFlaws: '일부 취약점만', foldClosed: (v) => `${v} 묶음을 접었습니다.`, kevEasy: '지금 실제 공격에 쓰이고 있어요!', pocEasy: '공격 코드가 공개됐어요!', originalEn: '원문(영어)',
    caution: '설정을 잘못 바꾸면 서비스가 멈추거나 접속이 막힐 수 있어요. 바꾸기 전에 아래 원문 링크를 확인하세요.',
    noneForPicks: (names) => `고른 제품(${names})에 해당하는 사건이 지금 현황판에 없습니다.`, noneForQuery: (q) => `‘${q}’에 맞는 사건이 없습니다.`, noneForBoth: (names, q) => `고른 제품(${names}) 가운데 ‘${q}’에 맞는 사건이 없습니다.`, restore: (label, n) => `${label} · ${n}건 보기`, stale: '업데이트가 멈춰 있습니다. 수집이 끊겨 최근 사건이 빠졌을 수 있습니다.', staleShort: '업데이트 멈춤', scopeWeek: '이 현황판에 최근 7일 동안 올라온 사건에서 찾았습니다.', scopeMonths: '불러온 이전 사건까지 포함해 현황판 전체에서 찾았습니다.', searchOlder: '이전 사건에서도 찾기',
    linkNotFound: '이 링크의 사건을 찾지 못했습니다. 보관 기간 90일이 지났거나 다른 사건과 합쳐졌을 수 있습니다.',
    clearWeek: '최근 7일 동안 게시된 사건이 없습니다', clearMonths: '이전 사건까지 살펴봐도 게시된 사건이 없습니다', clearNote: '고른 제품은 주소에 저장됩니다. 즐겨찾기해 두면 다음에도 바로 확인할 수 있습니다.',
    noIncidents: '아직 게시된 사건이 없습니다.', loadOlder: '이전 사건 불러오기', showMore: (n) => `더 보기 (${n}건 남음)`, moreDone: (n, rest) => `${n}건을 더 불러왔습니다.${rest ? ` ${rest}건 남음` : ''}`, clearSearch: '검색 지우기', clearAll: '필터 모두 지우기',
    original: '원문', lead: { advisory: '공식 공지 읽기', writeup: '분석 글 읽기', cve_record: 'CVE 기록 읽기', discussion: '토론 읽기', curator: '뉴스레터 읽기', notice: '보호나라 공지 읽기', repo: '저장소 보기', other: '원문 읽기' },
    aliasHint: (w, names) => `‘${w}’${ro(w)} 검색해 ${names.join(', ')}도 함께 찾았습니다.`,
    aliasTextHint: (w, names) => `제품 이름이 ${names.join(', ')}인 사건은 없어 본문에서 찾았습니다.`,
    searched: (cve) => `검색한 ${cve}`, notExploited: '공격 보고 없음',
    answer: (who, when, n) => `${who}: ${when ? `${when} ` : ''}${n}건`, answerWeek: '최근 7일', answerHeld: '최근 90일',
    preparing: '요약 준비 중', unavailable: '요약을 만들지 못했습니다. 아래 원문 링크를 확인하세요.',
    mitigation: '대처법', cveLines: (n) => `CVE ${n}건 각각의 내용`, vendorFold: (v, n) => `${v} 보안 공지 ${n}건 묶음`, wpFold: '워드프레스 플러그인', wpFoldTitle: (n) => `워드프레스 플러그인 ${n}건 묶음`, moreProducts: (n) => `외 ${n}개 제품`, cveCount: (n) => `CVE ${n}건`, moreLines: (n) => `${n}건 더 보기`, easyBrief: (p) => `${p ? `${p} ` : ''}새 보안 문제`, easyPrepTag: '쉬운 설명 준비 중', origOnly: '원문만 있음', unfoldDone: '묶음을 풀었습니다.', refoldDone: '다시 묶었습니다.',linkKind: { advisory: '공지', writeup: '분석' }, views: '보기 방식',
    normal: '기본', easy: '쉬운 설명', highest: '긴급!', high: '경계', notice: '주의',
    aboutHead: '요약', scoreHead: '점수', cveHead: 'CVE', // the opened row's section and fact labels (Astryx inspector)
    copy: '복사', copied: '복사됨', copyFailed: '복사하지 못했습니다. 선택된 명령을 직접 복사하세요.', share: '이 사건 링크 복사',
    feeds: 'RSS 피드', feedsHead: 'RSS로 받아 보기', feedMain: '주요 피드', feedMainNote: '위험 이상 사건과 CVE 번호 전 속보',
    feedAll: '현황판 전체', feedAllNote: '참고까지 모든 사건', feedMine: '내 제품', feedPick: '제품 고르기',
    feedNone: '위의 ‘사용하는 제품’ 칸에서 제품을 고르면, 그 제품의 사건만 오는 주소가 여기 생깁니다.',
    feedMore: (n) => ` 외 ${n}개`, feedLeft: (n) => `주소 하나에는 제품 30개까지 담깁니다. 나머지 ${n}개는 빠졌습니다.`,
    tagsHead: '제품', tagOnly: (name) => `${name} 사건만 보기`,
    paused: 'AI 요약이 잠시 멈췄습니다. 새 사건은 요약 없이 원문 제목과 링크만 보입니다.',
    versionHelp: (cve) => (cve ? `내 버전은 보통 그 프로그램의 설정이나 ‘정보’ 화면에 나와요. 모르겠으면 AI 챗봇에 ${cve} 번호로 물어보세요.` : '내 버전은 보통 그 프로그램의 설정이나 ‘정보’ 화면에 나와요.'),
    libraryHelp: '앱에 들어 있는 부품이라 직접 확인이 어려워요. 쓰는 프로그램을 업데이트하거나, 서버 관리자·호스팅 업체에 물어보세요.',
    newTabAll: ' (아래 링크는 모두 새 탭에서 열림)', noneEasy: '아직 고친 버전 소식이 없어요. 아래 원문 링크에서 새 소식을 확인하세요.', orNewer: (v) => `${v}\u00a0이상`, models: (n) => `해당 모델 보기 (${n}개)`,
    guideBtn: '읽는 법',
    guide: {
      title: '이 현황판 읽는 법', close: '닫기',
      primer: { highest: '실제 공격·9점 이상', high: '7점 이상', notice: '7점 미만', unrated: '점수 대기', ring: 'CVSS 점수 (10점 만점)', more: '읽는 법 자세히', dismiss: '안내 닫기' },
      pin: '최근 7일 사건 가운데 가장 중요한 것을 맨 위에 먼저 보여 줍니다.',
      easy: '무엇이 위험하고 지금 무엇을 하면 되는지 쉬운 말로 보여 줍니다.',
      filterWord: '제품 · 필터',
      filter: '사용하는 제품을 고르거나 필터를 걸면 해당 사건만 남습니다.',
      note: 'AI가 쓴 요약이므로 조치하기 전에 원문 링크를 확인하세요.',
    },
  },
  en: {
    ...WORDS.en,
    brand: 'Patch Ticker', loading: 'Loading…',
    variants: (n) => `Also showing ${n} under a similar name.`,
    loadDetail: (msg) => `Details: ${msg}`, olderDone: (n) => (n ? `Earlier Incidents are loaded (${n} more).` : 'There are no earlier Incidents: they are already all in the list.'),
    loadError: 'Could not load the Board. Check your connection and try again.', olderFailed: 'Could not load earlier Incidents. Check your connection and try again.', retry: 'Try again', filterBtn: 'Filters', fp: { title: 'Filters', published: 'Published', from: 'Published from', to: 'Published to', cvss: 'Minimum CVSS', cve: 'CVE ID', any: 'Any', cveYes: 'Has a CVE', cveNo: 'No CVE yet', risk: 'Risk level', flags: 'Attacks and advisories', has: { advisory: 'Official advisory', repo: 'Attack code published' }, sort: 'Sort', sorts: { new: 'Newest', risk: 'Highest risk', cvss: 'Highest CVSS' }, close: 'Close', reset: 'Reset filters', apply: 'Apply filters', applyN: (n) => `Apply filters · ${n}`, zeroChip: 'Adding this leaves nothing', riskNote: 'Score pending: no CVSS score yet. An attacked Incident is at the top level even without one.', osNote: 'Shows everything that runs on the chosen systems.', zeroNote: 'A dashed chip would leave nothing if added.', dropCond: (l) => `Drop “${l}”` }, textSizeGroup: 'Text size', textGlyph: 'A', textDown: 'Smaller text', textUp: 'Larger text', textNow: (p) => `Text size ${p}%`, pinMore: (n) => `More Highlights (${n})`, pinLess: 'Fewer Highlights', pinShown: (s, n) => `${s} of ${n} shown`, qfKev: 'Attacked only', noneForFilters: 'No Incident on the Board matches these filters.', easyLevels: { highest: 'Urgent!', high: 'Warning', pending: 'Score pending', notice: 'Caution' }, why: { curator: 'In security newsletters', buzz: 'Trending on HN' }, reportedBy: (h) => `reported by ${h}`, skip: 'Skip to newest', skipTop: 'Skip to the Board', found: (n) => `${n} Incidents shown.`, sorted: (s) => `Sorted: ${s}.`,
    status: (updated) => `Last updated ${updated}`, counts: (today, week) => ` · today ${today} · 7 days ${week}`, countAll: (n) => ` · all ${n}`, shownOf: (shown, all) => ` · ${shown} of ${all}`,
    products: 'Products you run', tokensSet: (n) => `${n} set`, sgHead: 'Products', sgCount: (n) => `${n} in 30 days`, resultCount: (n) => `${n.toLocaleString('en')} ${n === 1 ? 'result' : 'results'}`, picked: 'Picked Products', fpApplied: 'Applied filters', remove: (name) => `Remove ${name}`,
    repo: 'GitHub repository', search: 'Search', clearSearch: 'Clear search', noticeClose: 'Dismiss notice', noticeSince: ['Patch Ticker has collected since 9 November 2026.', 'Vulnerabilities published before then may be missing.'], noticeKeep: 'An Incident is not removed when a patch ships; it stays for 90 days.', searchHint: 'Product, keyword, CVE ID', searchHintShort: 'Product or keyword', all: 'Newest first', sortLabel: 'Sort', expandAll: 'Expand all', collapseAll: 'Collapse all', unfold: 'Ungroup', refold: 'Group again', groupTag: 'Group', patchTag: 'Disclosed together', prefs: 'Display settings', toTop: 'Back to top', toBottom: 'Go to bottom', stepUp: 'Up one screen', stepDown: 'Down one screen', stepGroup: 'Move one screen', newAbove: (n) => `${n} new`, newAdded: (n) => `${n} new Incidents added.`, toNew: 'Go to the first new Incident', foldEnd: (v) => `Fold ${v} back`, foldOpened: (v, n, wp) => `Opened the ${v} group (${n} ${wp ? 'plugins' : 'notices'}).`, theme: 'Dark theme',
    pin: 'Highlights', pinOne: 'Highlight', noCve: 'No CVE yet', moreCves: (n) => ` and ${n} more`, firstSeen: 'No source gave a time, so this is when the Board first saw it', firstSeenAt: (t) => `first seen ${t}`, kevReasonEasy: 'Under attack', easyWhen: 'Only affects you if:', someFlaws: 'some of the flaws only', foldClosed: (v) => `Folded the ${v} group.`, kevEasy: 'Attackers are using this right now!', pocEasy: 'Exploit code is public!', originalEn: 'Source text',
    caution: 'A wrong setting can stop the service or lock you out. Check the source link below first.',
    noneForPicks: (names) => `No Incident on the Board touches the Products you picked (${names}).`, noneForQuery: (q) => `No Incident matches “${q}”.`, noneForBoth: (names, q) => `No Incident from your picked Products (${names}) matches “${q}”.`, restore: (label, n) => `${label} · show ${n}`, stale: 'Updates have stopped. Collection may be down, so recent Incidents may be missing.', staleShort: 'Updates stopped', scopeWeek: 'Searched Incidents added to the Board in the last 7 days.', scopeMonths: 'Searched Incidents added to the Board, loaded earlier Incidents included.', searchOlder: 'Search older Incidents too',
    linkNotFound: "This link's Incident was not found. It may be past the 90 days kept, or merged into another Incident.",
    clearWeek: 'No Incident posted in the last 7 days', clearMonths: 'No Incident posted, loaded earlier Incidents included', clearNote: 'Your picks are saved in the address. Bookmark it to check again next time.',
    noIncidents: 'No Incidents have been posted yet.', loadOlder: 'Load older Incidents', showMore: (n) => `Show more (${n} left)`, moreDone: (n, rest) => `Loaded ${n} more.${rest ? ` ${rest} left` : ''}`, clearSearch: 'Clear search', clearAll: 'Clear all filters',
    original: '', lead: { advisory: 'Read the advisory', writeup: 'Read the write-up', cve_record: 'Read the CVE record', discussion: 'Read the discussion', curator: 'Read the newsletter', notice: 'Read the KISA notice', repo: 'See the repository', other: 'Read the source' },
    aliasHint: (w, names) => `‘${w}’ was also searched as ${names.join(', ')}.`,
    aliasTextHint: (w, names) => `No product is named ${names.join(', ')}, so the text was searched for it.`,
    searched: (cve) => `You searched ${cve}`, notExploited: 'No attacks reported',
    answer: (who, when, n) => `${who}: ${n} Incident${n === 1 ? '' : 's'}${when ? ` ${when}` : ''}`, answerWeek: 'in the last 7 days', answerHeld: 'in the last 90 days',
    preparing: 'Summary in preparation', unavailable: 'No Summary is available. See the source link below.',
    mitigation: 'Mitigation', cveLines: (n) => `Each of the ${n} CVEs`, vendorFold: (v, n) => `${v}: ${n} security notices, grouped`, wpFold: 'WordPress plugins', wpFoldTitle: (n) => `WordPress plugins: ${n}, grouped`, moreProducts: (n) => `and ${n} more products`, cveCount: (n) => `${n} CVEs`, moreLines: (n) => `Show ${n} more`, easyBrief: (p) => `New security issue${p ? ` in ${p}` : ''}`, easyPrepTag: 'Plain summary coming', origOnly: 'Source only', unfoldDone: 'Groups opened up.', refoldDone: 'Grouped again.',linkKind: { advisory: 'advisory', writeup: 'write-up' }, views: 'View',
    normal: 'Normal', easy: 'Easy', highest: 'Urgent!', high: 'Warning', notice: 'Caution',
    aboutHead: 'Summary', scoreHead: 'Score', cveHead: 'CVE',
    copy: 'Copy', copied: 'Copied', copyFailed: 'Could not copy. The command is selected: copy it yourself.', share: 'Copy link to this Incident',
    feeds: 'RSS feeds', feedsHead: 'Follow by RSS', feedMain: 'Main feed', feedMainNote: 'Elevated and up, attacked, or no CVE yet',
    feedAll: 'The whole Board', feedAllNote: 'Every Incident, Notice too', feedMine: 'My products', feedPick: 'Pick products',
    feedNone: 'Pick products in “Products you run” above, and an address with only their Incidents appears here.',
    feedMore: (n) => ` and ${n} more`, feedLeft: (n) => `One address holds up to 30 products; the other ${n} are left out.`,
    tagsHead: 'Products', tagOnly: (name) => `Show only ${name} Incidents`,
    paused: 'Summaries are paused for now; new Incidents show only the source title and link.',
    versionHelp: (cve) => (cve ? `Your version is usually shown in the program's settings or About screen. If not, ask an AI chatbot about ${cve}.` : "Your version is usually shown in the program's settings or About screen."),
    libraryHelp: "It is a part built into other apps, so it is hard to check yourself. Update the programs you use, or ask your server admin or hosting company.",
    newTabAll: ' (every link below opens in a new tab)', noneEasy: 'No fixed version has been announced yet. Watch the source link below for news.', orNewer: (v) => `${v}\u00a0or\u00a0later`, models: (n) => `Affected models (${n})`,
    guideBtn: 'How to read',
    guide: {
      title: 'How to read this Board', close: 'Close',
      primer: { highest: 'Attacked or 9+', high: '7+', notice: 'Below 7', unrated: 'Score pending', ring: 'CVSS score (out of 10)', more: 'How to read', dismiss: 'Dismiss this note' },
      pin: 'The most important Incidents of the last seven days, shown first.',
      easy: 'What is dangerous and what to do now, in plain words.',
      filterWord: 'Products · Filters',
      filter: 'Pick the Products you run, or set filters, to keep only their Incidents.',
      note: 'Summaries are written by AI: check the source links before you act.',
    },
  },  // Japanese (owner, 11-17): the interface only; Summaries come in English (board.mjs withJapanese), so the guide says so.
  ja: {
    ...WORDS.ja,
    brand: 'Patch Ticker', loading: '読み込み中…',
    variants: (n) => `似た名前の${n}件もあわせて表示しています。`,
    loadDetail: (msg) => `詳細: ${msg}`, olderDone: (n) => (n ? `以前のインシデントをすべて読み込みました（${n}件追加）。` : '以前のインシデントはこれ以上ありません。すでにすべて一覧にあります。'),
    loadError: 'ボードを読み込めませんでした。インターネット接続を確認して、もう一度お試しください。', olderFailed: '以前のインシデントを読み込めませんでした。インターネット接続を確認して、もう一度お試しください。', retry: '再試行', filterBtn: 'フィルター', fp: { title: 'フィルター', published: '公開日', from: '公開日（開始）', to: '公開日（終了）', cvss: '最小 CVSS スコア', cve: 'CVE 番号', any: 'すべて', cveYes: 'CVE 番号あり', cveNo: 'CVE 番号なし', risk: '危険度', flags: '攻撃・勧告の有無', has: { advisory: '公式勧告あり', repo: '攻撃コード公開済み' }, sort: '並び順', sorts: { new: '新しい順', risk: '危険度順', cvss: 'CVSS の高い順' }, close: '閉じる', reset: 'フィルターをリセット', apply: 'フィルターを適用', applyN: (n) => `フィルターを適用 · ${n}件`, zeroChip: 'この条件を加えると0件になります', riskNote: 'スコア待ち: CVSS スコアがまだないインシデント。実際の攻撃が報告されたものは、スコアがなくても最上位に入ります。', osNote: '選んだ OS で動くプログラムがすべて表示されます。', zeroNote: '点線のチップは、今の条件に加えると0件になるチップです。', dropCond: (l) => `「${l}」を外す` }, textSizeGroup: '文字サイズ', textGlyph: 'あ', textDown: '文字を小さく', textUp: '文字を大きく', textNow: (p) => `文字サイズ ${p}%`, pinMore: (n) => `注目のインシデントをもっと見る (${n})`, pinLess: '注目のインシデントを閉じる', pinShown: (s, n) => `${n}件中${s}件を表示`, qfKev: '攻撃発生のみ', noneForFilters: '選んだ条件に合うインシデントは、今ボードにありません。', easyLevels: { highest: '緊急！', high: '警戒', pending: 'スコア待ち', notice: '注意' }, why: { curator: 'セキュリティニュースレターで言及', buzz: 'HN で話題' }, reportedBy: (h) => `${h} の報告`, skip: '注目をとばして新しい順へ', skipTop: 'ボードへスキップ', found: (n) => `${n}件を表示しています。`, sorted: (s) => `${s}に並べ替えました。`,
    status: (updated) => `最終更新 ${updated}`, counts: (today, week) => ` · 今日 ${today}件 · 7日間 ${week}件`, countAll: (n) => ` · 全${n}件`, shownOf: (shown, all) => ` · ${all}件中${shown}件`,
    products: '使っている製品', tokensSet: (n) => `${n}件選択`, sgHead: '製品', sgCount: (n) => `直近30日 ${n}件`, resultCount: (n) => `${n.toLocaleString('ja')}件`, picked: '選んだ製品', fpApplied: '適用中のフィルター', remove: (name) => `${name}を外す`,
    repo: 'GitHub リポジトリ', search: '検索', clearSearch: '検索をクリア', noticeClose: 'お知らせを閉じる', noticeSince: ['Patch Ticker は2026年11月9日から収集しています。', 'それ以前に公開された脆弱性は一覧にない場合があります。'], noticeKeep: 'パッチが出てもインシデントは消えず、90日間残ります。', searchHint: '製品、キーワード、CVE 番号', searchHintShort: '製品、キーワード', all: '新しい順', sortLabel: '並び順', expandAll: 'すべて開く', collapseAll: 'すべて閉じる', unfold: 'まとめを解除', refold: 'まとめて表示', groupTag: 'まとめ', patchTag: '同時公開', prefs: '表示設定', toTop: '先頭へ', toBottom: '末尾へ', stepUp: '1画面上へ', stepDown: '1画面下へ', stepGroup: '1画面ずつ移動', newAbove: (n) => `新着 ${n}件`, newAdded: (n) => `新しいインシデントが${n}件追加されました。`, toNew: '最初の新着インシデントへ移動', foldEnd: (v) => `${v} のまとめを閉じる`, foldOpened: (v, n, wp) => `${v} のまとめを開きました（${wp ? 'プラグイン' : '勧告'} ${n}件）。`, theme: 'ダークテーマ',
    pin: '注目のインシデント', pinOne: '注目のインシデント', noCve: 'CVE 番号なし', moreCves: (n) => ` ほか${n}件`, firstSeen: '公開時刻が不明なため、このボードが最初に確認した時刻です', firstSeenAt: (t) => `初確認 ${t}`, kevReasonEasy: '攻撃されています', easyWhen: '次の場合にだけ該当します:', someFlaws: '一部の脆弱性のみ', foldClosed: (v) => `${v} のまとめを閉じました。`, kevEasy: '今まさに実際の攻撃に使われています！', pocEasy: '攻撃コードが公開されました！', originalEn: '原文（英語）',
    caution: '設定を誤るとサービスが止まったり、接続できなくなったりすることがあります。変更する前に下の原文リンクを確認してください。',
    noneForPicks: (names) => `選んだ製品（${names}）に該当するインシデントは、今ボードにありません。`, noneForQuery: (q) => `「${q}」に一致するインシデントはありません。`, noneForBoth: (names, q) => `選んだ製品（${names}）のうち「${q}」に一致するインシデントはありません。`, restore: (label, n) => `${label} · ${n}件を表示`, stale: '更新が止まっています。収集が止まり、最近のインシデントが抜けている可能性があります。', staleShort: '更新停止中', scopeWeek: 'このボードに過去7日間に載ったインシデントから検索しました。', scopeMonths: '読み込んだ以前のインシデントも含めて検索しました。', searchOlder: '以前のインシデントからも検索',
    linkNotFound: 'このリンクのインシデントが見つかりませんでした。保存期間の90日を過ぎたか、ほかのインシデントに統合された可能性があります。',
    clearWeek: '過去7日間に公開されたインシデントはありません', clearMonths: '以前のインシデントまで見ても、公開されたインシデントはありません', clearNote: '選んだ製品はアドレスに保存されます。ブックマークしておけば次回もすぐ確認できます。',
    noIncidents: 'まだ公開されたインシデントはありません。', loadOlder: '以前のインシデントを読み込む', showMore: (n) => `もっと見る（残り${n}件）`, moreDone: (n, rest) => `${n}件を追加で読み込みました。${rest ? ` 残り${rest}件` : ''}`, clearSearch: '検索をクリア', clearAll: 'フィルターをすべてクリア',
    original: '原文', lead: { advisory: '勧告を読む', writeup: '解説記事を読む', cve_record: 'CVE レコードを読む', discussion: '議論を読む', curator: 'ニュースレターを読む', notice: 'KISA の告知を読む', repo: 'リポジトリを見る', other: '原文を読む' },
    aliasHint: (w, names) => `「${w}」で ${names.join('、')} もあわせて検索しました。`,
    aliasTextHint: (w, names) => `製品名が ${names.join('、')} のインシデントはないため、本文から探しました。`,
    searched: (cve) => `検索した ${cve}`, notExploited: '攻撃の報告なし',
    answer: (who, when, n) => `${who}: ${when ? `${when} ` : ''}${n}件`, answerWeek: '直近7日', answerHeld: '直近90日',
    preparing: '要約を準備中', unavailable: '要約を作成できませんでした。下の原文リンクを確認してください。',
    mitigation: '対処法', cveLines: (n) => `CVE ${n}件それぞれの内容`, vendorFold: (v, n) => `${v} のセキュリティ勧告 ${n}件のまとめ`, wpFold: 'WordPress プラグイン', wpFoldTitle: (n) => `WordPress プラグイン ${n}件のまとめ`, moreProducts: (n) => `ほか${n}製品`, cveCount: (n) => `CVE ${n}件`, moreLines: (n) => `あと${n}件を表示`, easyBrief: (p) => `${p ? `${p} の` : ''}新しいセキュリティ問題`, easyPrepTag: 'やさしい説明を準備中', origOnly: '原文のみ', unfoldDone: 'まとめを解除しました。', refoldDone: 'まとめ直しました。', linkKind: { advisory: '勧告', writeup: '解説' }, views: '表示方法',
    normal: '標準', easy: 'やさしい説明', highest: '緊急！', high: '警戒', notice: '注意',
    aboutHead: '要約', scoreHead: 'スコア', cveHead: 'CVE',
    copy: 'コピー', copied: 'コピーしました', copyFailed: 'コピーできませんでした。選択されたコマンドを手動でコピーしてください。', share: 'このインシデントのリンクをコピー',
    feeds: 'RSS フィード', feedsHead: 'RSS で受け取る', feedMain: 'メインフィード', feedMainNote: '警戒以上、実際の攻撃、CVE 未採番のインシデント',
    feedAll: 'ボード全体', feedAllNote: '参考を含むすべてのインシデント', feedMine: '自分の製品', feedPick: '製品を選ぶ',
    feedNone: '上の「使っている製品」で製品を選ぶと、その製品のインシデントだけが届くアドレスがここに表示されます。',
    feedMore: (n) => ` ほか${n}件`, feedLeft: (n) => `1つのアドレスに入る製品は30件までです。残りの${n}件は含まれていません。`,
    tagsHead: '製品', tagOnly: (name) => `${name} のインシデントだけを表示`,
    paused: 'AI 要約を一時停止しています。新しいインシデントは要約なしで、原文のタイトルとリンクだけが表示されます。',
    versionHelp: (cve) => (cve ? `お使いのバージョンは、たいていそのプログラムの設定や「バージョン情報」画面に表示されます。わからなければ AI チャットボットに ${cve} について聞いてみてください。` : 'お使いのバージョンは、たいていそのプログラムの設定や「バージョン情報」画面に表示されます。'),
    libraryHelp: 'アプリに組み込まれた部品なので、自分で確認するのは難しいです。使っているプログラムを更新するか、サーバー管理者やホスティング会社に問い合わせてください。',
    newTabAll: '（下のリンクはすべて新しいタブで開きます）', noneEasy: '修正版の知らせはまだありません。下の原文リンクで最新情報を確認してください。', orNewer: (v) => `${v} 以降`, models: (n) => `該当モデルを表示 (${n})`,
    guideBtn: '見方',
    guide: {
      title: 'このボードの見方', close: '閉じる',
      primer: { highest: '実際の攻撃・9点以上', high: '7点以上', notice: '7点未満', unrated: 'スコア待ち', ring: 'CVSS スコア（10点満点）', more: '見方を詳しく', dismiss: '案内を閉じる' },
      pin: '過去7日間で最も重要なインシデントを、いちばん上に先に表示します。',
      easy: '何が危険で、今何をすべきかをやさしい言葉で表示します。',
      filterWord: '製品 · フィルター',
      filter: '使っている製品を選ぶかフィルターをかけると、該当するインシデントだけが残ります。',
      note: 'AI が英語で書いた要約なので、対応する前に原文リンクを確認してください。',
    },
  },
};
let lang = loadLang();
// The Board-wide view (normal or Easy) the visitor chose at the top; remembered.
let defaultView = loadView();

function loadView() {
  return viewFromStorage(stored(SAVED_VIEW)); // storage blocked: normal view everywhere
}

function setDefaultView(view) {
  defaultView = view;
  $('view-easy').classList.remove('beckon');
  $('views').classList.remove('beckon');
  if (view === 'easy') store('vr-easy-tried', '1');
  store(SAVED_VIEW, view);
  // Each row on screen changes its words in place: the old text leaves downwards, the new one rises in, and rows whose
  // height changed glide (index.html, .vt-view). Reduced motion: a plain cross-fade.
  document.documentElement.classList.add('vt-view');
  boardTransition(() => {
    render();
    if (!$('filters').hidden) filterPanel(); // risk words differ between the views
  }).finally(() => setTimeout(() => document.documentElement.classList.remove('vt-view'), 400));
}

function loadLang() {
  const saved = stored(SAVED_LANG); // storage blocked: the browser's language below
  if (Object.hasOwn(TEXT, saved ?? '')) return saved; // `in` would take "constructor" as a language
  const browser = (navigator.language || '').toLowerCase().slice(0, 2);
  return LANGS.includes(browser) ? browser : 'en';
}

const darkQuery = matchMedia('(prefers-color-scheme: dark)');
// The theme the page shows: the visitor's remembered choice, else the system's.
const theme = () => document.documentElement.dataset.theme || (darkQuery.matches ? 'dark' : 'light');
// Phones tint the browser's own bar from the theme-color metas, which follow the system: a remembered choice writes the
// page's ground into both, so the bar matches the page.
function paintBar() {
  if (!document.documentElement.dataset.theme) return;
  const ground = getComputedStyle(document.body).backgroundColor;
  for (const m of document.querySelectorAll('meta[name="theme-color"]')) m.content = ground;
}

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
  store(SAVED_TEXT, String(next));
  showTextSize();
  placePill(); // the switch's labels changed width
  pageText(); // placeholders: the short ones from 125%
  measureStick(); // the frozen row grew or shrank with the text
}
// Astryx Button, Props, isDisabled: "uses aria-disabled instead of native disabled": an end step keeps the focus.
function showTextSize() {
  const pct = textPct();
  $('text-down').setAttribute('aria-disabled', pct === TEXT_STEPS[0]);
  $('text-up').setAttribute('aria-disabled', pct === TEXT_STEPS.at(-1));
  rest(document.querySelector('.sizes'));
}
function setTextIndex(index) {
  if (!TEXT_STEPS[index]) return; // a press on an end step: nothing to say
  stepText(index - TEXT_STEPS.indexOf(textPct()));
  $('announce').textContent = TEXT[lang].textNow(textPct()); // the polite region says the new size
}

function toggleTheme() {
  // Decided inside the cross-fade: a second click before the first fade lands still flips the theme again.
  crossFade(() => {
    const next = theme() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    store(SAVED_THEME, next);
    pageText();
    pop($('theme').querySelector(next === 'dark' ? '.sun' : '.moon'), 'rotate(-90deg) scale(0.6)', 260);
  });
}

// A request lost as the app closes would hang for good and stop live updates (N4): each has a time limit (status.json is
// a few bytes; the rest are MBs on a slow phone), and one under way while the tab was away is aborted when it comes back.
const SLOW_MS = 2 * 60 * 1000;
const underWay = new Set(); // each request's controller, while it lasts
// Documents parsed without the Japanese twins and maybe not yet in the Board's state (a Promise.all still waiting on a
// sibling): setLang gives them the twins with the state. Emptied a task after the last request ends, so never a leak.
const plainDocs = new Set();
let away = document.hidden; // hidden, or the connection dropped: what is under way meanwhile is asked again on return
const getJson = async (name) => {
  // index.html's inline script asked for the first load's files already: take each response once (main drops the rest).
  const early = window.vrEarly?.[DATA_URL + name];
  if (early) delete window.vrEarly[DATA_URL + name];
  const ctl = new AbortController();
  // A timer, not AbortSignal.timeout: older browsers lack it. One due while hidden waits on: the return asks again.
  const ms = name === 'status.json' ? 15_000 : SLOW_MS;
  const expire = () => { if (document.hidden) limit = setTimeout(expire, ms); else ctl.abort(new Error(`${name}: no answer in time`)); };
  let limit = setTimeout(expire, ms);
  underWay.add(ctl);
  try {
    const read = (early || fetch(DATA_URL + name, { cache: 'no-cache', signal: ctl.signal })).then((res) => {
      if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
      return res.text().then((text) => {
        if (lang === 'ja') return JSON.parse(text, withJapanese); // a Japanese page reads the English Summary
        const doc = JSON.parse(text); // the reviver costs ~5x the parse: only a Japanese page pays it
        plainDocs.add(doc);
        return doc;
      });
    });
    // An early request carries index.html's signal, not this one: the limit and the abort on return reach it by a race.
    return await (early ? Promise.race([read, new Promise((_, no) => ctl.signal.addEventListener('abort', () => no(new Error(`${name}: no answer`))))]) : read);
  } catch (err) {
    if (ctl.back) return getJson(name); // aborted on return: asked again at once, and this caller gets the fresh answer
    throw err;
  } finally {
    clearTimeout(limit);
    underWay.delete(ctl);
    // a task later: every caller has stored its documents by then, and a .catch(() => getJson(...)) has started its own
    if (!underWay.size) setTimeout(() => underWay.size || plainDocs.clear());
  }
};

const $ = (id) => document.getElementById(id);
let incidents = [];
let products = [];
let seenProducts = []; // board/products.json: every Product of 90 days, so one with no loaded Incident can be picked
let entries = []; // the bar's Products (pickerEntries): one per Product as a person names it, holding every id
let entryOf = new Map(); // id -> its entry
let visibleIds = []; // the rows drawn now, for 모두 펼치기 / 모두 접기
const allOpen = () => visibleIds.length > 0 && visibleIds.every((id) => open.has(id));
let updated = '';
let weekSince = ''; // the week file's window start, for the status line's 7-day count
let total = null; // every Board Incident the store holds (status.json; absent before the collector sends it)
let paused = false;
let loadError = null; // null while loading or once loaded; the error message if loading failed
// The Board opens on the last week (board/recent.json); older months come in when the visitor asks.
let olderMonths = [];
let loadingOlder = false;
let olderAdded = null; // how many 이전 사건 불러오기 added, said where the button stood
// Rows of 최신순 drawn so far; a long list grows by PAGE on request instead of all at once.
const PAGE = 100;
let shown = PAGE;
let folding = stored(SAVED_FOLD) !== 'off';
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
  if (location.hash.length > 1) return filterFromQuery(location.hash.slice(1));
  return { ...filterFromQuery(stored(SAVED) || ''), query: '' }; // saved before 11-08 late: may hold q
}

// push: a filter change the visitor made becomes a step in the browser's history, so Back undoes it (owner, 11-09);
// typing in search only rewrites the current step, or every letter would be a step.
function saveFilter(push = false) {
  const encoded = filterToQuery(filter);
  store(SAVED, filterToQuery({ ...filter, query: '' })); // storage blocked: the address still carries the filter
  const next = encoded ? `#${encoded}` : location.pathname + location.search;
  const now = location.hash || location.pathname + location.search;
  if (push && next !== now) history.pushState(null, '', next);
  else history.replaceState(null, '', next);
}

// Back / Forward: the filter of that step comes back, with the Board's motion.
addEventListener('popstate', () => {
  filter = filterFromQuery(location.hash.slice(1));
  shown = PAGE;
  $('search').value = filter.query;
  store(SAVED, filterToQuery({ ...filter, query: '' }));
  boardTransition(() => {
    render();
    if (!$('filters').hidden) filterPanel();
  });
});

let linked = false; // the page was opened by a link to one Incident (#i=)
async function main() {
  render();
  try {
    // Only the week is needed to draw the Board. A missing Product list only narrows the picker, a missing month index
    // only hides 이전 사건, and the update time also rides in recent.json: Googlebot once failed status.json alone and
    // the whole Board drew as a load error (Search Console, 11-10).
    const first = Promise.all([getJson('index.json').catch(() => ({ months: [] })),
      // Row views first (owner, 11-10); rows.json missing (rollout) or failing: the full week, as before.
      getJson('status.json').catch(() => null), getJson('board/rows.json').catch(() => getJson('board/recent.json')),
      getJson('board/products.json').catch(() => ({ products: [] }))]);
    window.vrEarly = null; // whatever is left was fetched at page start: a refresh minutes later must ask again
    const [index, st, recent, seen] = await first;
    const state = st || recent.status;
    if (!state) throw new Error('status.json');
    incidents = recent.incidents.filter(onBoard);
    seenProducts = seen.products;
    olderMonths = index.months; // only kept months: the store holds 90 days, up to four calendar months (owner, 11-10)
    updated = state.updated;
    weekSince = recent.since;
    total = state.total ?? null;
    paused = state.summaries === 'paused'; // the collector hit its AI budget (ticket 07)
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
  // Astryx Banner, Best Practices: "Announce async outcomes from the transition handler with useAnnounce." (#empty is no live region)
  if (loadError) $('announce').textContent = TEXT[lang].loadError;
  // A restored search, an open row or a #i= link that is a row view (or a search field focused before the data came) needs
  // the full week first: the restore scroll would land on another row while that row shows one loading line (owner, 11-10).
  const rowView = (id) => incidents.find((i) => i.id === id)?.rows;
  const linkedId = linked && new URLSearchParams(location.hash.slice(1)).get('i');
  if (filter.query || document.activeElement === $('search') || [...open, linkedId].some(rowView)) await ensureFull().catch(() => {});
  if (place && !loadError) scrollTo(0, Number(place.y) || 0);
  if (linked) {
    await openLinked();
    saveFilter(); // the address returns to the filter form; the opened row stays open
  }
  if (!loadError) settleRows();
  // A light sweep across 쉬운 설명 twice as the Board arrives, until the visitor has tried that view once.
  const tried = Boolean(stored('vr-easy-tried', true)); // storage blocked: no sweep, it could never stop
  if (!loadError && defaultView === 'normal' && !tried) {
    $('view-easy').classList.add('beckon');
    $('views').classList.add('beckon');
    setTimeout(() => { $('view-easy').classList.remove('beckon'); $('views').classList.remove('beckon'); }, 3800);
  }
  setTimeout(() => document.body.classList.remove('arriving'), 1200);
}

// Live updates. Every 30 seconds while the tab is in view, and whenever it comes back into view, the page reads
// status.json (a few bytes); only a new update time fetches the week again. New Incidents go where the visitor's sort
// puts them: at the top of the page they come in with the Board's motion; further down, the rows on screen stay where
// they were (the scroll is corrected by what was added above) and a notice at the top of the window says how many
// arrived above. Each new row wears a blue edge until it has been on screen four seconds.
const CHECK_MS = 30 * 1000; // live like a ticker (owner, 2026-11-09): status.json is a few bytes, so check often
const fresh = new Set(); // ids that arrived by a refresh and have not been seen yet
// When the running check began, 0 when none. A backstop to the time limits and the abort on return: a working check
// takes at most status.json, rows.json, then recent.json (three limits), so one older was lost (N4). abs: a clock set
// back does not hold checks off.
let checking = 0;
async function checkForNew() {
  if (Math.abs(Date.now() - checking) < 3 * SLOW_MS || fullWeek || !updated || loadError || document.hidden) return; // the full week on its way: its merge goes first; hidden: checked on return
  const began = checking = Date.now();
  try {
    const st = await getJson('status.json');
    if (st.updated === updated || checking !== began) return; // given up meanwhile: no week for it
    // An open row or a search needs details: the full week, so an open row is refreshed whole with no loading flash.
    // Otherwise the row views (owner, 11-10): mergeIncidents keeps a held full Incident unless its row changed.
    const whole = open.size > 0 || Boolean(filter.query);
    const week = whole ? getJson('board/recent.json') : getJson('board/rows.json').catch(() => getJson('board/recent.json')); // rows.json missing (rollout): the week
    const [recent, seen] = await Promise.all([week, getJson('board/products.json').catch(() => null)]);
    if (fullWeek || checking !== began) return; // asked for meanwhile, or this check was given up: two merges never cross
    // A file with no row view is the full week (recent.json, or a week short enough to be all whole): the truth for row views.
    const merged = mergeIncidents(incidents, recent.incidents.filter(onBoard), !recent.incidents.some((i) => i.rows));
    const atTop = scrollY < 160;
    incidents = merged.incidents;
    if (seen) seenProducts = seen.products;
    const state = recent.status || st; // the merged file's own: status.json may have been read before the app slept
    updated = state.updated;
    weekSince = recent.since;
    total = state.total ?? null;
    paused = state.summaries === 'paused';
    fullFailed = false; // the store answers again: a waiting search or row may ask for the week again
    for (const id of merged.added) fresh.add(id);
    refreshProducts();
    lastCount = null; // the redraw's own "N건이 보입니다" stays quiet: this refresh says what is new instead
    if (atTop) await boardTransition(render);
    else {
      holdPlace(render);
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
    if (checking === began) checking = 0;
  }
}
// Coming back in view (visible, restored from the back/forward cache, online) aborts what is under way, all asked before
// the return, as it may never answer (N4); getJson asks each again for whoever waits on it (a running check, the full
// week, older months), so nothing fails or falls back. A check starts if none runs; a second return event finds nothing
// away, so what is asked after the return is left alone.
const leave = () => { away = true; };
function back() {
  if (document.hidden || !navigator.onLine) return; // not back yet: the return in view, or online, does it
  if (away) {
    away = false;
    for (const ctl of underWay) {
      ctl.back = true;
      ctl.abort();
    }
  }
  checkForNew();
}
setInterval(checkForNew, CHECK_MS);
document.addEventListener('visibilitychange', () => (document.hidden ? leave() : back()));
// Coming back from another window (the tab stayed visible, so no visibilitychange) checks too (owner, 2026-11-09).
addEventListener('focus', checkForNew);
addEventListener('offline', leave);
addEventListener('pageshow', (e) => { if (e.persisted) back(); });
addEventListener('online', back);

// Owner 11-20 ("펼치기 누르면 해당 내용으로 화면 이동해 고정, 닫으면 원복"): a row or a vendor fold the visitor opens comes
// up to just under the frozen bar (index.html scroll-padding-top) and is held there while redraws change its panel (the
// full Incident arriving, the view, the text size); closing it goes back to where the page was. One at a time: opening
// another (a row inside a held fold too) holds that one, whose close goes back to where the first had brought the page.
// Owner 11-22 ("펼쳤을때 화면에 전부 보이면 이동x"): an item whose header and whole panel already fit in the window,
// under the bar, stays where it is, and so does its close; a panel that grows past the window's edge (a row view's full
// Incident arriving) rises then. A scroll of the visitor's own lets go, and the item then closes where it is. Only a
// click starts a hold (row(), foldRows()); 모두 펼치기, a filter or tag and rows drawn open by a reload never do.
// held: { key (a fold's is fold:<its key>), top: its place in the window before the open, at: when the glide began,
// from: its place in the window then, ms: the glide's length, still: fits (held at top, not under the bar), back:
// closing (the glide goes back to top, and the hold ends where it lands) }
let held = null;
// The rise runs with the panel's unfold and the way back with its fold (fold(): 300ms and 240ms on FOLD_EASE), so each
// reads as one motion from the tap frame (owner 11-21, MuMu: a smooth scroll starts slow and only moved once the panel
// was out or shut). The place is read again every frame: a redraw or a panel that grows re-aims the glide, never
// restarts it. The glide runs in window places, not scrollY: a Board redraw lays the rows above the window out at their
// content-visibility stand-in height (index.html) for a moment, and the browser's scroll anchoring kept that shift, so a
// fold below the list's tenth item jumped by 100-270px on opening (owner 11-22).
let rising = 0; // the glide's frame (holdRow)
function holdRow(frame) {
  const owed = !frame && rising; // a call between frames (a redraw) takes the next frame's place, so it runs it too
  cancelAnimationFrame(rising);
  rising = 0;
  const li = held && document.querySelector(`li[data-vt="${rowName(held.key)}"]`);
  if (!li) {
    if (held?.back) held = null; // a closing row redrawn away: nothing left to go back with
    return;
  }
  // a redrawn row is skipped (index.html content-visibility) until a frame finds it on screen: no height to hold by
  const item = li.closest('#board > li');
  if (item) item.style.contentVisibility = 'visible';
  const box = li.getBoundingClientRect();
  const bar = parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) || 0;
  // judged on the full height: mid-unfold the panel is short, and its done() asks again
  const body = li.querySelector(':scope > .details, :scope > .fold-body');
  if (held.still && !held.back && !body?.folding && (held.top < bar || held.top + box.height > innerHeight)) {
    Object.assign(held, { still: false, at: performance.now() });
  }
  const place = held.back || held.still ? held.top : bar;
  const p = reducedMotion.matches ? 1 : Math.min(1, (performance.now() - held.at) / held.ms);
  const at = held.from + (place - held.from) * (1 - (1 - p) ** 3); // FOLD_EASE is an ease-out cubic
  const y = scrollY;
  scrollTo({ top: y + box.top - at, behavior: 'instant' });
  // a frame more after each correction: skipped rows the glide brought near the window take their real height then
  if (p < 1 || owed || Math.abs(scrollY - y) >= 1) rising = requestAnimationFrame(holdRow);
  else if (held.back) held = null;
}
const letGo = () => { held = null; };
addEventListener('wheel', letGo, { passive: true });
addEventListener('touchmove', letGo, { passive: true });
addEventListener('pointerdown', (e) => { if (e.target === document.documentElement) letGo(); }); // the scrollbar
addEventListener('keydown', (e) => { if (/^(Page(Up|Down)|Home|End|Arrow(Up|Down))$/.test(e.key) || (e.key === ' ' && e.target === document.body)) letGo(); });
document.addEventListener('click', (e) => { if (e.target.closest?.('#jump, .skip, #new-above')) letGo(); });

// A redraw that changes what stands above the window (a refresh, the full week arriving) holds the row at the top of the
// window where it was, and a focused row keeps the focus.
function holdPlace(redraw) {
  const anchor = [...document.querySelectorAll('li[data-vt]')].find((li) => li.getBoundingClientRect().bottom > 0);
  const anchorTop = anchor?.getBoundingClientRect().top;
  const focused = document.activeElement?.matches('button.row') && document.activeElement.closest('li[data-vt]')?.dataset.vt;
  redraw();
  const again = anchor && document.querySelector(`li[data-vt="${anchor.dataset.vt}"]`);
  if (held) holdRow(); // a row the visitor opened stays where it was brought (render did it; the anchor must not undo it)
  else if (again) scrollBy(0, again.getBoundingClientRect().top - anchorTop);
  if (focused) document.querySelector(`li[data-vt="${focused}"] button.row`)?.focus({ preventScroll: true });
}

// Owner, 11-10: the Board draws from board/rows.json, whose row views (marked rows) carry no details and no search text.
// The full week (board/recent.json) comes only when something needs it, never in the background: opening a row view, or
// a search. Whether anything is missing is read from the Incidents held (a refresh can bring row views back), never kept
// in a flag; nor is a fetched week kept: one fetch at a time, and every later need reads the week again.
let fullFailed = false; // the last fetch failed: redraws stop asking; a visitor's action or a working refresh clears it
let fullWeek = null;
const partial = () => incidents.some((i) => i.rows);
function ensureFull() {
  if (!updated || loadError || !partial()) return Promise.resolve(); // nothing drawn yet, or nothing missing
  fullFailed = false;
  return (fullWeek ||= getJson('board/recent.json').then((recent) => {
    incidents = mergeIncidents(incidents, recent.incidents.filter(onBoard), true).incidents;
    refreshProducts();
    holdPlace(render);
  }, (err) => {
    fullFailed = true;
    showStatus();
    throw err;
  }).finally(() => {
    fullWeek = null;
    checkForNew(); // a check skipped while the week came (a return, say) runs now
  }));
}

// M1 (owner, 11-16): board/others.json, the Products' counts of the last 30 days, fetched once, the first time a row
// opens, by getJson's time limits; the Board redraws once it comes, so an open row gains its link. A failure only leaves
// the link out until the next visit (an empty document stands in, so it is not asked again on every opening).
let productCounts = null;
let othersAsked = false;
function ensureOthers() {
  if (othersAsked) return;
  othersAsked = true;
  getJson('board/others.json').then((doc) => {
    productCounts = doc;
    refreshProducts();
    if (document.activeElement === $('search')) suggest(); // the open list gains its counts and their order
    setTimeout(() => holdPlace(render)); // its own task, so the first row open is not one long task (audit 11-19)
  }, () => { productCounts = {}; });
}

// The notice at the top of the window: how many highlighted rows sit above it. It leaves once they are reached.
function noticeAbove() {
  // Counted by Incident: a pinned one's list copy is not a second new Incident.
  const above = new Set([...document.querySelectorAll('li.fresh')].filter((li) => li.getBoundingClientRect().bottom < 0).map((li) => li.dataset.ids)).size;
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
// same edge a new arrival wears); a member of a vendor fold is shown ungrouped; an older one loads the 90 days.
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
  letGo(); // the link's row is brought into view here, not a held one
  open.add(id);
  // Past the first page (owner, 11-10: a link from 11-04 landed on the top with nothing open): draw up to its page.
  // A pinned Highlight is reached on top (its list copy waits at its own place): no page of the list is drawn for it.
  const lists = boardLists();
  const onTop = [...lists.pinned].some((i) => i.id === id);
  // A Highlight behind 주요 사건 더 보기 is reached in the list, where its copy keys apart (rowKey): open that copy.
  if (!onTop && [...highlightedNow].some((i) => i.id === id)) open.add(`list:${id}`);
  shown = Math.max(shown, onTop ? 0 : linkedPlace(lists.items, id, PAGE)?.shown || 0);
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

// After a copy: the button says 복사됨 with a check drawn in; each caller settles it back.
function stampCopied(button) {
  const ok = el('span', 'ok');
  ok.setAttribute('aria-hidden', 'true');
  ok.innerHTML = '<svg viewBox="0 0 16 16"><path d="m3.5 8.3 2.8 2.8 6.2-6.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const label = el('span', '', TEXT[lang].copied);
  button.replaceChildren(ok, label);
  draw(ok.querySelector('path'), 280);
  pop(label, 'translateX(-4px)', 200);
  $('announce').textContent = TEXT[lang].copied;
}

function shareLine(incident) {
  const p = el('p', 'share');
  const button = Object.assign(el('button', 'btn'), { type: 'button' });
  const icon = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6.5 9.5a3 3 0 0 0 4.2 0l2.1-2.1a3 3 0 0 0-4.2-4.2l-.7.7M9.5 6.5a3 3 0 0 0-4.2 0L3.2 8.6a3 3 0 0 0 4.2 4.2l.7-.7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
  const idle = () => { button.innerHTML = icon; button.append(el('span', '', TEXT[lang].share)); };
  idle();
  let pageSlug; // ready long before a click; until then the Board link
  slug(incident.id).then((s) => { pageSlug = s; }, () => {});
  button.addEventListener('click', async () => {
    const url = shareLink(incident, pageSlug, lang, `${location.origin}${location.pathname}`);
    try {
      await navigator.clipboard.writeText(url);
      stampCopied(button);
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
  p.append(button, reportLink(incident));
  return p;
}

// 틀린 내용 알리기 (reportUrl). Opening it needs a GitHub account; nothing is sent until the visitor submits the form there.
function reportLink(incident) {
  const t = TEXT[lang];
  const page = `${location.origin}${location.pathname}#i=${encodeURIComponent(incident.id)}`;
  const a = Object.assign(el('a', 'btn'), { href: reportUrl(incident, lang, page, incident.id), target: '_blank', rel: 'noopener noreferrer' });
  slug(incident.id).then((s) => { a.href = reportUrl(incident, lang, page, s); }, () => {}); // no crypto.subtle (plain http): the id stays
  a.innerHTML = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2.5 14 13H2Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 6.5v3M8 11.2v.1" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>';
  a.append(el('span', '', t.report));
  a.append(el('span', 'sr-only', t.newTab)); // Astryx Link, Props, newTabLabel: "SR text announcing an external link opens in a new tab"
  return a;
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
// The Board's two curves (index.html --ease-out / --ease-exit; WAAPI easing cannot read a CSS variable).
const EASE_OUT = 'cubic-bezier(0.16, 1, 0.3, 1)';
const EASE_EXIT = 'cubic-bezier(0.4, 0, 1, 1)';
function reveal(node, from = '0 -6px', duration = 200) {
  const start = reducedMotion.matches ? { opacity: 0 } : { opacity: 0, translate: from };
  // Astryx Motion, Respecting User Preferences: under reduced motion "opacity only, in 200 ms or less"
  node.animate([start, { opacity: 1, translate: '0 0' }], { duration: reducedMotion.matches ? Math.min(duration, 200) : duration, easing: EASE_OUT });
}

// Small confirmations: a check that draws itself, a badge or icon that pops in. Reduced motion keeps the end state
// (and a fade for pop), never the movement.
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
// Opening and closing a panel moves its height, so the rows below glide instead of jumping: open in 300ms, close
// in 240ms. A click mid-way turns it round at once. Reduced motion: no movement, the panel just appears.
// Both ways on one gentle ease-out (MuMu, frame by frame, owner 11-10): EASE_OUT was three quarters open in 50ms, so a
// phone-tall panel just appeared; an ease-in close barely moved for 80ms and then shut in three frames.
const FOLD_EASE = 'cubic-bezier(0.33, 1, 0.68, 1)';
// A row's details and the reading guide: fold() with motion; under reduced motion they fade and nothing moves. fold()
// stays as it is for the rest (vendor folds appear at once, DESIGN.md). Astryx Motion, Respecting User Preferences:
// "opacity only, in 200 ms or less".
// shift: how much the header above grew (closing) or shrank (opening) in the same frame, which the fold starts from so
// the rows below never step (an opened row's tags leave the header's own line on narrow screens: carry).
function foldOrFade(node, opening, done = () => {}, shift = 0) {
  if (!reducedMotion.matches) return fold(node, opening, done, shift);
  node.folding?.cancel();
  const run = node.animate([{ opacity: opening ? 0 : 1 }, { opacity: opening ? 1 : 0 }], { duration: 200, easing: EASE_OUT, fill: 'forwards' });
  node.folding = run;
  run.onfinish = () => {
    node.folding = null;
    done();
    run.cancel(); // the held end frame lets go only after done() has hidden a closed row
  };
}
function fold(node, opening, done = () => {}, shift = 0) {
  node.folding?.cancel();
  if (reducedMotion.matches) return done();
  const cs = getComputedStyle(node);
  const full = { height: `${node.scrollHeight}px`, paddingTop: cs.paddingTop, paddingBottom: cs.paddingBottom, opacity: 1 };
  if (!opening) full.height = `${Math.max(0, node.offsetHeight - shift)}px`;
  const shut = { height: `${opening ? shift : 0}px`, paddingTop: '0px', paddingBottom: '0px', opacity: 0 };
  node.style.overflow = 'hidden';
  node.folding = node.animate(opening ? [shut, full] : [full, shut],
    { duration: opening ? 300 : 240, easing: FOLD_EASE });
  node.folding.onfinish = () => {
    node.style.overflow = '';
    node.folding = null;
    done();
  };
}

// Board redraws the visitor asked for (filters, sort, 주요 사건 더 보기, 모두 펼치기, the view; 더 보기 only when it draws the
// whole Board, not when it adds rows) keep each row's identity: a row
// that stays glides to its new place, a new one fades in, a gone one fades out (View Transitions; each row is named in
// row()). Reduced motion: nothing moves, the change only cross-fades. Typing in search uses it too, quicker.
const rowNames = new Map();
const rowName = (id) => rowNames.get(id) || rowNames.set(id, `row-${rowNames.size + 1}`).get(id);
// Only rows on or near the screen are named: every named row is captured, and off-screen ones cost memory for nothing.
function nameRows() {
  // every box read before any name is written: a read after a write would restyle the page once per row (789 at the end)
  const rows = [...document.querySelectorAll('li[data-vt]')];
  const near = rows.map((li) => { const box = li.getBoundingClientRect(); return box.bottom > -200 && box.top < innerHeight + 200; });
  rows.forEach((li, n) => { li.style.viewTransitionName = near[n] ? li.dataset.vt : ''; });
}
// Resolves once the new Board is drawn (a caller that reads the drawn rows waits for it).
let boardRuns = 0;
function boardTransition(change) {
  // Under the phone sheet or the floating panel (still fading out included) the Board redraws at once: the transition's
  // named rows are drawn above the whole page, so they showed through the sheet (owner, 11-19, MuMu: 필터 초기화).
  if (!document.startViewTransition || panelOver()) return Promise.resolve(change());
  document.documentElement.classList.toggle('vt-still', reducedMotion.matches);
  // the frozen search bar and the jump group get names of their own while it runs (index.html, .vt-board), so the moving
  // rows pass under them; counted, so a transition that cuts in keeps them named until the last one ends
  boardRuns++;
  document.documentElement.classList.add('vt-board');
  nameRows();
  const transition = document.startViewTransition(() => {
    change();
    nameRows();
  });
  transition.ready.catch(() => {}); // a newer redraw skipped this one: nothing is wrong
  transition.finished.finally(() => {
    for (const li of document.querySelectorAll('li[data-vt]')) li.style.viewTransitionName = '';
    if (--boardRuns === 0) document.documentElement.classList.remove('vt-board', 'vt-search');
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
  entries = pickerEntries(products, productCounts?.counts);
  entryOf = new Map(entries.flatMap((e) => e.ids.map((id) => [id, e])));
  const names = new Map();
  for (const e of entries) names.set(e.name, (names.get(e.name) || 0) + 1);
  for (const e of entries) e.twin = names.get(e.name) > 1;
}

// The vendor in brackets only to tell apart two Products of the same name.
const label = (e) => (e.os ? `${e.name} (OS)` : e.twin && !e.key.startsWith('name|') ? `${e.name} (${e.key.split('|')[0]})` : e.name);

// The page's own text: index.html marks each element with the TEXT key it shows.
function pageText() {
  const t = TEXT[lang];
  document.documentElement.lang = lang;
  showTextSize();
  paintBar(); // at the start and after each theme switch
  document.title = t.title;
  for (const node of document.querySelectorAll('[data-t]')) {
    node.textContent = t[node.dataset.t];
    node.hidden = !node.textContent; // the Korean NVD line has no English twin
  }
  searchPlaceholder();
  for (const node of document.querySelectorAll('[data-t-aria]')) node.setAttribute('aria-label', t[node.dataset.tAria]);
  // Astryx Link, Props, newTabLabel: "SR text announcing an external link opens in a new tab" (the footer's link: its span)
  $('repo').setAttribute('aria-label', t.repo + t.newTab);
  $('support').querySelector('[data-t="newTab"]').lang = lang; // the link itself is lang="en"
  // Icons alone are ambiguous: each icon button also says its name on hover. Astryx IconButton, Best Practices:
  // "Don't: Skip tooltip: label only reaches screen readers; sighted users need hover hint."
  for (const node of document.querySelectorAll('#jump button, #theme, #repo, #feeds-btn, #prefs-btn, #search-clear')) node.dataset.tip = node.getAttribute('aria-label');
  $('filter-btn').dataset.tip = t.filterBtn; // named by its word, hidden below 1024px
  // The language menu's button names the page's language (full on wide screens, a short code on phones: the header must
  // fit 375px); screen readers hear what it opens. Each entry is in its own language and marks the current one.
  $('lang').setAttribute('aria-label', `${t.langMenu}: ${t.langName}`);
  for (const item of document.querySelectorAll('#langs [data-lang]')) item.setAttribute('aria-current', item.dataset.lang === lang);
  for (const view of ['normal', 'easy']) $(`view-${view}`).setAttribute('aria-pressed', defaultView === view);
  placePill();
  // Astryx ToggleButton, Best Practices: "Don't use ToggleButton for persistent settings; use Switch instead."
  $('theme').setAttribute('aria-checked', theme() === 'dark');
}

// The fields' hints: short ones on phones and from 125% text; where even that does not fit beside 필터 and 정렬, the
// search field says only "검색" (critique 13: the hint was cut at 320px). Measured, since language and text size decide it.
const measure = document.createElement('canvas').getContext('2d');
function searchPlaceholder() {
  const t = TEXT[lang];
  const narrow = phoneSheet();
  for (const node of document.querySelectorAll('[data-t-placeholder]')) {
    const key = node.dataset.tPlaceholder;
    node.placeholder = ((narrow || textPct() >= 125) && t[`${key}Short`]) || t[key];
    if (node.id !== 'search') continue;
    measure.font = getComputedStyle(node).font;
    const fits = (text) => measure.measureText(text).width <= node.clientWidth;
    if (!fits(node.placeholder)) node.placeholder = fits(t[`${key}Short`]) ? t[`${key}Short`] : t.search;
  }
}
addEventListener('resize', searchPlaceholder);

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
// Astryx Banner anatomy: the first sentence is the title, the rest the description in Secondary Ink.
function bannerText(text) {
  const [, title, desc] = /^(.+?(?:\.(?=\s)|。))\s*(.*)$/s.exec(text) || [, text, '']; // a dot inside a word (1.2) ends no sentence
  const box = el('span', 'b-text');
  box.append(el('b', '', title), el('span', 'b-desc', desc));
  return box;
}
function staleNote() {
  const note = $('stale');
  const stale = isStale();
  const text = stale ? TEXT[lang].stale : ''; // the age is in the status line just above (critique 12)
  if (note.dataset.text === text) return; // unchanged: screen readers hear it once (role=status)
  note.dataset.text = text;
  note.hidden = !stale;
  note.innerHTML = stale ? WARN : '';
  if (stale) note.append(bannerText(text));
}
let shownList = [];
// The status line; on phones a stale Board says so on this line in two words (critique 13: the notice box pushed the
// first row down), while the notice itself stays for screen readers (index.html hides it visually there).
function showStatus() {
  const short = isStale() ? [el('span', 'stale-short', ` · ${TEXT[lang].staleShort}`)] : [];
  short[0]?.setAttribute('aria-hidden', 'true');
  $('status').replaceChildren(...statusLine(shownList), ...short);
  staleNote();
}
setInterval(showStatus, 60_000);

// Parts for #status: the "all" count is its own span, hidden visually on phones (index.html).
function statusLine(list) {
  const t = TEXT[lang];
  if (loadError) return []; // the message and its retry button sit in the empty-state block
  if (!updated) return [t.loading];
  const n = (x) => x.toLocaleString(lang);
  const waiting = filter.query && !applied() ? ` · ${fullFailed ? t.loadError : t.loading}` : ''; // the search waits for the full week
  const tail = (paused ? ` · ${t.paused}` : '') + waiting;
  if (list.length !== incidents.length) return [t.status(ago(updated)) + t.shownOf(n(list.length), n(incidents.length)) + tail];
  const { today, week } = statusCounts(incidents, weekSince);
  const all = total == null ? [] : [el('span', 'status-all', t.countAll(n(total)))];
  return [t.status(ago(updated)) + t.counts(n(today), n(week)), ...all, tail];
}

// 이 현황판 읽는 법 opens only on request. A first visit gets one line instead (the three risk signs and the ring, with
// 읽는 법 자세히), so the first screen still shows Incidents (critique 9: the full guide pushed the first row below the
// fold). Showing that line once marks the guide as seen (critique 11-17); the line never comes back.
const SAVED_GUIDE = 'vr-guide';
let guideOpen = false;
// Storage blocked: closed, since it could never be dismissed for good, so the 읽는 법 button carries it alone.
let primerOpen = !stored(SAVED_GUIDE, true);

// 읽는 법 opens and closes with the rows' fold (owner, 11-19: it had no motion); reduced motion: the 200ms fade. Its top
// margin moves with it, so nothing below jumps when the fold ends. A press mid-close turns it round.
function guideEdges(box, opening) {
  if (reducedMotion.matches) return;
  box.edging?.cancel(); // a reopen mid-close reads the resting margin, not the one in flight
  const cs = getComputedStyle(box);
  // A border never draws thinner than 1px, so the margin also takes back the two border lines.
  const full = { marginTop: cs.marginTop };
  const none = { marginTop: `-${parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth)}px` };
  box.edging = box.animate(opening ? [none, full] : [full, none], { duration: opening ? 300 : 240, easing: FOLD_EASE });
}
function openGuide(focusClose = false) {
  const box = $('guide');
  if (box.dataset.leaving) delete box.dataset.leaving; // closing: turn round where it stands
  else setGuide(true);
  $('guide-btn').setAttribute('aria-expanded', 'true');
  guideEdges(box, true);
  foldOrFade(box, true);
  if (focusClose) box.querySelector('.g-head .btn')?.focus({ preventScroll: true });
}
function closeGuide() {
  const box = $('guide');
  box.dataset.leaving = '1';
  $('guide-btn').setAttribute('aria-expanded', 'false');
  $('guide-btn').focus({ preventScroll: true }); // 닫기 sits inside the box that folds away
  guideEdges(box, false);
  foldOrFade(box, false, () => {
    delete box.dataset.leaving;
    setGuide(false);
    $('guide-btn').scrollIntoView({ block: 'nearest' }); // closed from deep inside: 읽는 법, now holding the focus, comes back into view
  });
}
function setGuide(open) {
  guideOpen = open;
  primerOpen = false; // either way the visitor has met the guide
  if (!open) store(SAVED_GUIDE, 'seen');
  render();
}

// Each mark is drawn with the row's own parts (risk dot and word in the current view, CVSS ring, line badge),
// so the legend can never drift from what the rows show.
function guide() {
  const t = TEXT[lang];
  const g = t.guide;
  const box = $('guide');
  primer();
  $('guide-btn').setAttribute('aria-expanded', guideOpen && !box.dataset.leaving);
  box.hidden = !guideOpen;
  if (!guideOpen) return box.replaceChildren();
  const close = Object.assign(el('button', 'btn', g.close), { type: 'button' });
  close.addEventListener('click', closeGuide);
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
  // Only what a first visit needs to read a row (owner, 11-22: "핵심만 남겨"). The marks reuse the first-visit line's
  // words: that line is gone once seen and never shows beside the guide, so the guide still carries them.
  const p = g.primer;
  // No 공격 발생 under the top sign: "Urgent Attacked" overflows the phone's sample column; the words say it.
  for (const [level, cvss] of [['highest', 9.8], ['high', 7.5], ['notice', 4.3]]) item(p[level], riskCell({ cvss }));
  const pending = riskCell({}); // the dashed sign and ring, as an unscored row draws them (critique 13); the words once
  pending.querySelector('.why')?.remove();
  item(p.unrated, pending, scoreCell({}));
  item(p.ring, scoreCell({ cvss: 9.8 }));
  rule();
  item(g.pin, el('span', 'g-pin', t.pin));
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
  more.addEventListener('click', () => openGuide(true));
  const close = Object.assign(el('button', 'btn p-close'), { type: 'button' });
  close.setAttribute('aria-label', p.dismiss);
  close.dataset.tip = p.dismiss; // Astryx IconButton, Best Practices: "Don't: Skip tooltip: label only reaches screen readers; sighted users need hover hint."
  close.append(el('span', 'x'));
  close.addEventListener('click', () => fold($('primer'), false, () => { setGuide(false); $('guide-btn').focus({ preventScroll: true }); }));
  box.replaceChildren(keys, more, close);
  // Shown once (critique 11-17): the next visit has only 읽는 법, as after closing it. Marked once the Board is drawn.
  if (updated) store(SAVED_GUIDE, 'seen');
}

// The rest of the 90 days the store keeps (every month index.json lists), merged into the week already on screen.
async function fetchOlder() {
  const months = await Promise.all(olderMonths.map((m) => getJson(`board/${m}.json`)));
  const byId = new Map(incidents.map((i) => [i.id, i]));
  const before = byId.size;
  // a month file holds the whole Incident: it replaces a row view of the week (owner, 11-10)
  for (const i of months.flatMap((m) => m.incidents).filter(onBoard)) if (!byId.get(i.id) || byId.get(i.id).rows) byId.set(i.id, i);
  incidents = [...byId.values()];
  refreshProducts();
  olderMonths = [];
  return byId.size - before;
}

async function loadOlder() {
  if (loadingOlder) return; // the loading button stays focusable, so a second press arrives here
  loadingOlder = true;
  render();
  // render() replaced the pressed button: its loading twin takes the focus, so it never falls to <body>
  if (document.activeElement === document.body) document.querySelector('#more [aria-busy="true"], #empty [aria-busy="true"]')?.focus({ preventScroll: true });
  try {
    const added = await fetchOlder();
    clearTimeout(announcing); // a pending count from the last search must not talk over this
    $('announce').textContent = TEXT[lang].olderDone(added); // the same sentence the screen shows (critique 13)
    olderAdded = added;
  } catch {
    // the button comes back for another try, and the Board stays live: loadError would stop its checks for good (N4)
    clearTimeout(announcing);
    $('announce').textContent = TEXT[lang].olderFailed;
  }
  loadingOlder = false;
  render();
  // The button that had focus is gone: the next control in the same place takes it, and the page does not move.
  if (document.activeElement === document.body) ($('more').querySelector('button') || $('empty').querySelector('button') || $('more').querySelector('.older-done'))?.focus({ preventScroll: true });
}

// 이전 사건 불러오기 / 이전 사건에서도 찾기. Astryx Button, Props, isLoading: "blocks re-activation but stays focusable
// (aria-disabled, not native disabled); announces via live region" (loadOlder() says the outcome in #announce).
function olderButton(label) {
  const button = Object.assign(el('button', 'btn', loadingOlder ? TEXT[lang].loading : label), { type: 'button' });
  if (loadingOlder) {
    button.setAttribute('aria-disabled', 'true');
    button.setAttribute('aria-busy', 'true');
  }
  button.addEventListener('click', loadOlder);
  return button;
}

// Under the list: more rows of what is loaded, then older months.
function moreButtons(rest) {
  const t = TEXT[lang];
  const buttons = [];
  if (rest > 0) {
    const more = Object.assign(el('button', 'btn', t.showMore(rest)), { type: 'button' });
    more.addEventListener('click', () => {
      const done = () => {
        $('more').querySelector('button')?.focus({ preventScroll: true }); // replaced; keep the place
        clearTimeout(announcing); // a pending count from the last search must not talk over this
        $('announce').textContent = t.moreDone(Math.min(PAGE, rest), Math.max(0, rest - PAGE)); // the last page can be short
      };
      // Rows only added under the drawn ones: nothing drawn moves, so no transition (owner, 11-17: its old picture of the
      // button and footer showed through the new rows). The whole Board drawn again (it changed since): the transition.
      const page = nextPage(drawn, { result: filtered(), folding, pinAll }, PAGE);
      if (page) {
        addPage(page);
        done();
      } else boardTransition(() => { shown += PAGE; render(); done(); });
    });
    buttons.push(more);
  }
  if (!olderMonths.length && olderAdded !== null) buttons.push(Object.assign(el('p', 'older-done', t.olderDone(olderAdded)), { tabIndex: -1 })); // takes the focus when the button is gone
  if (olderMonths.length) {
    const label = activeFilters() ? t.searchOlder : t.loadOlder; // with a search or filter on, it is a search
    buttons.push(olderButton(label));
  }
  return buttons;
}

// The last filterBoard answer: a view, language or open-row redraw asks the same question again (owner, 11-10: phones).
// incidents is always replaced, never edited, and the minute covers the time-based parts (ages, the seven-day Highlights).
let lastBoard = {};
// The search in force: none while a row view is held (it has no text to search), so the list, its counts and what is said
// about them stay as they are until the full week is there.
const applied = (f = filter) => (partial() ? '' : f.query);
const board = (f, now = Date.now()) => filterBoard(incidents, f.picks, applied(f), now, f);
function filtered() {
  const now = Date.now();
  const key = JSON.stringify([filter, Math.floor(now / 60000)]);
  if (lastBoard.incidents !== incidents || lastBoard.key !== key) {
    lastBoard = { incidents, key, result: board(filter, now) };
  }
  return lastBoard.result;
}

let highlightedNow = new Set(); // every Highlight, pinned or behind 주요 사건 더 보기: edged in the list
// What render() draws, in its order: the pinned Highlights, then the list items (rows and vendor folds); openLinked counts
// a linked row's place in the same items, so the two never disagree.
function boardLists() {
  const { highlights: chosen, list, variants, inText, now } = filtered();
  // A product or search filter is a question: no pinned block repeating the list's own rows above it, one sentence
  // answering instead (answerLine; critique 11-17, P1). The list still edges its Highlights (highlightedNow). A search
  // counts from the moment it is typed or restored, so no block shows while it waits for the full week (applied).
  const answering = Boolean(filter.picks.length || filter.query);
  // The four shown first are the Highlights ranked 1 to 4, whatever the visitor's sort (owner, 11-22; pinOrder);
  // 주요 사건 더 보기 appends the rest below them in the same order.
  const { pins, rest: extra } = answering ? { pins: [], rest: [] } : pinOrder(chosen, now);
  const highlights = [...pins, ...(pinAll ? extra : [])];
  const pinned = new Set(highlights);
  // Owner, 11-16: the list is the whole Board in the visitor's order, Highlights included at their own place (edged in
  // their Risk colour, row()); a pinned one is drawn twice, each copy keyed apart (rowKey).
  const rest = list;
  highlightedNow = new Set(chosen);
  // A search or a picked Product shows every row as it is; otherwise one vendor's bulk push folds (board.mjs, foldByVendor).
  // A Highlight never folds (owner, 11-17): it stands at its own place, banded, and its fold counts the rest.
  const folded = filter.picks.length || applied() ? rest : foldByVendor(rest, undefined, undefined, (i) => highlightedNow.has(i));
  return { list, variants, inText, extra, highlights, pinned, rest, folded, items: folding ? folded : rest, answering };
}

// The filtered Board's answer, one sentence over its list: "Gitea: 최근 7일 2건 · 위험 2 · 공격 보고 없음". The period is the
// one searched (the week, or the 90 days once the older months are in); a date condition, shown as a chip, replaces it.
function answerLine(list) {
  const t = TEXT[lang];
  const c = answerCounts(list);
  const n = (x) => x.toLocaleString(lang);
  const names = pickNames();
  // Two names, then a count: a saved filter of many Products keeps the sentence to a line or two (the chips list them all).
  const shown = names.length > 3 ? [names.slice(0, 2).join(', '), t.moreProducts(names.length - 2)].join(' ') : names.join(', ');
  const who = [shown, ...(applied() ? [`‘${applied()}’`] : [])].filter(Boolean).join(', ');
  const when = filter.from || filter.to ? '' : olderMonths.length ? t.answerWeek : t.answerHeld;
  const easy = defaultView === 'easy';
  const levels = ['highest', 'high', 'notice'].filter((l) => c[l]).map((l) => `${easy ? t[l] : t.levels[l]} ${n(c[l])}`);
  const attacked = c.exploited ? `${(easy && t.kevReasonEasy) || t.kevReason} ${n(c.exploited)}` : t.notExploited;
  return [t.answer(who, when, n(c.total)), ...levels, attacked].join(' · ');
}

function render() {
  pageText();
  feedRows();
  if (filter.query && !fullFailed) ensureFull().catch(() => {}); // typed, restored, from a link or Back; after a failure the visitor asks
  const { list, variants, inText, extra, highlights, pinned, rest, folded, items, answering } = boardLists();
  shownList = list;
  showStatus();
  guide();
  // A Korean word searched as English names too says so under the field (critique 13), so a hit on "macOS" for 맥 is not a puzzle.
  const hint = aliasesUsed(applied()).map(({ word, names }) => TEXT[lang][inText ? 'aliasTextHint' : 'aliasHint'](word, names)).join(' ');
  if ($('alias-hint').textContent !== hint) $('alias-hint').textContent = hint; // unchanged: not said again (role=status)
  $('skip').hidden = !highlights.length;
  announce(list.length, filterToQuery({ ...filter, query: applied(), sort: 'new' })); // a new sort says 정렬 itself
  // Highlights are pinned on top like a board's notices; every other Incident follows, newest first.
  rowCount = 0;
  // CVE text is untrusted input, so it only ever goes in through textContent.
  $('highlights').replaceChildren(...highlights.map((i) => row(i, true)));
  $('pinned').hidden = !highlights.length;
  $('pinned-head').replaceChildren(`${TEXT[lang].pin} `, ...pinCount(highlights.length, highlights.length + (pinAll ? 0 : extra.length)));
  $('pinned-head').hidden = !highlights.length;
  $('pin-more').replaceChildren(...(extra.length ? [pinToggle(extra.length)] : []));
  const count = panelCount();
  if (count) $('filter-count').textContent = String(count); // gone, it keeps its number while it fades out (index.html)
  $('filter-count').hidden = !count;
  if (count && count !== shownCount) pop($('filter-count'));
  shownCount = count;
  $('filter-btn').setAttribute('aria-expanded', !$('filters').hidden);
  // 묶음 풀기 / 묶어 보기: only where a fold exists to undo or to bring back.
  $('fold-toggle').hidden = folded === rest || !folded.some((i) => i.fold);
  $('fold-toggle').textContent = folding ? TEXT[lang].unfold : TEXT[lang].refold;
  $('board').replaceChildren(...items.slice(0, shown).flatMap(itemRows));
  // Nothing found: the empty state below carries 이전 사건에서도 찾기 itself, so the buttons under the list stay away.
  $('more').replaceChildren(...(loadError || !updated || !list.length ? [] : moreButtons(items.length - shown)));
  barEnd(list);
  // A picked Product also shows Incidents filed under a variant of its name (board.mjs, critique 14); say how many.
  $('picks').replaceChildren(...(variants && list.length ? [el('p', 'pick-note', TEXT[lang].variants(variants))] : []));
  // Not a live region: #announce already says the count; with nothing found the empty state answers instead. While the
  // data loads it stands empty, keeping its line (index.html), so the rows do not move when the answer arrives.
  $('answer').hidden = !answering || (updated && !list.length) || Boolean(loadError);
  const waiting = filter.query && !applied(); // the list is not the search's yet
  $('answer').textContent = $('answer').hidden || !updated || waiting ? '' : answerLine(list);
  $('all-head').hidden = !list.length;
  $('all-head').textContent = TEXT[lang].fp.sorts[filter.sort]; // the list's heading says its order
  const sorts = TEXT[lang].fp.sorts;
  $('sort-now').textContent = sorts[filter.sort];
  $('sort').setAttribute('aria-label', `${TEXT[lang].sortLabel}: ${sorts[filter.sort]}`);
  $('sorts').setAttribute('aria-label', TEXT[lang].sortLabel);
  $('sorts').replaceChildren(...SORTS.map((key) => {
    const option = Object.assign(el('div', 'mi', sorts[key]), { tabIndex: -1 });
    option.dataset.sort = key;
    option.setAttribute('role', 'option');
    option.setAttribute('aria-selected', String(key === filter.sort));
    return option;
  }));
  // Keys, not ids: a Highlight's list copy opens on its own (rowKey), so 모두 펼치기 counts each drawn row once.
  visibleIds = [...highlights.map((i) => i.id), ...itemKeys(items.slice(0, shown))];
  drawn = { result: lastBoard.result, folding, pinAll, items, shown };
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
  holdRow();
}
let shownCount = 0;
// A list item as rows (a vendor fold is several), and the keys 모두 펼치기 counts for the drawn ones.
const itemRows = (i) => (i.fold ? foldRows(i) : [row(i, false)]);
const itemKeys = (items) => items.flatMap((i) => (i.fold ? (openFolds.has(i.fold) ? i.incidents : []) : [i])).map((i) => rowKey(i, highlightedNow, false));
// What render() last drew of the list (nextPage): 더 보기 adds to it while it still stands.
let drawn = {};
function addPage(page) {
  shown += PAGE;
  const added = page.flatMap(itemRows);
  $('board').append(...added);
  // the added rows that reach the screen fade in on their own (reduced motion: they are just there)
  if (!reducedMotion.matches) {
    for (const li of added) {
      if (li.getBoundingClientRect().top >= innerHeight) break;
      li.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: EASE_OUT });
    }
  }
  visibleIds.push(...itemKeys(page));
  drawn.shown = shown;
  $('expand-all').textContent = allOpen() ? TEXT[lang].collapseAll : TEXT[lang].expandAll;
  $('more').replaceChildren(...moreButtons(drawn.items.length - shown));
  watchFresh();
  placeJump();
}

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
  const [risk, title, score, tags, date] = [cell('c-risk', 'sk-pill'), cell('c-title', 'sk-name', 'sk-sub'), cell('c-score', 'sk-ring'),
    cell('c-tags', 'sk-tag', 'sk-tag'), cell('c-date', 'sk-date', 'sk-time')];
  if (pinned) { // a Highlight's header strip, as row() draws it
    const strip = el('span', 'strip');
    strip.append(risk, date);
    r.append(strip, title, score, tags);
  } else r.append(risk, title, score, tags, date);
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

// The Easy view: the plain answer, the affected models when there are too many to list inline, then when it applies.
function easyPanel(incident) {
  const s = incident.summary;
  // The chatbot hint names the CVE the visitor searched for when it is not the Lead (N1), else the Lead.
  const cve = searchedCve(filter.query, incident, lang)?.cve || incident.cves?.[0];
  const parts = easyAnswer(s, riskLevel(incident), cve, firstProduct(incident, lang), isLibrary(incident), `easy:${incident.id}`);
  if ((s.devices || []).length > MANY_DEVICES) parts.push(modelList(s.devices, fixLines(s)));
  // Critique P2 (11-19): "what to do" first, then "does this touch me?" (critique 11 had it the other way round): the
  // Summary's conditions, in its own words, at body weight so the action stays the one heavy line. One condition on the
  // line, several as a list.
  // The everyday-words version when the Summary has one (easy_conditions, after critique 12), else the conditions as written.
  // H4 (owner, 11-16): no CVE id here; a condition of some CVEs only says so in words after its text.
  const when = (s[lang].easy_conditions?.length ? s[lang].easy_conditions : s[lang].conditions || []).filter((c) => typeof c === 'string' && c)
    .map((c) => { const { ids, text } = conditionIds(c, incident.cves); return ids.length ? `${text} (${TEXT[lang].someFlaws})` : c; });
  // Under a heading, as the Normal view's 해당 조건: one condition as a line, several as a list.
  if (when.length) parts.push(secHead(TEXT[lang].easyWhen.replace(/[:：]\s*$/, '')));
  if (when.length === 1) parts.push(para('conditions', when[0]));
  if (when.length > 1) {
    const list = el('ul', 'cond-list');
    list.append(...when.map((c) => el('li', '', c)));
    parts.push(list);
  }
  return parts;
}

let hadAllClear = false;

// Nothing to show: say so plainly. With products picked this is the good news, "not affected".
function errorState() {
  const t = TEXT[lang];
  const retry = Object.assign(el('button', 'btn', t.retry), { type: 'button' });
  retry.addEventListener('click', () => location.reload());
  // Astryx EmptyState, Best Practices: "Don't: Use an EmptyState for error messages that require immediate action; use
  // a Banner instead": the warning banner, the cause under its description, 다시 시도 at its end.
  const banner = errorBanner();
  banner.querySelector('.b-text').append(el('span', 'b-desc load-detail', t.loadDetail(loadError)));
  banner.append(retry);
  return [banner];
}
// The warning banner for data that did not arrive: the Board's load error, and an opened row whose details failed.
function errorBanner() {
  const banner = el('div', 'load-err');
  banner.innerHTML = WARN;
  banner.append(bannerText(TEXT[lang].loadError));
  return banner;
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
  const names = pickNames().join(', ');
  // Only Products picked: name them ("not affected"); any quick filter in play: speak of conditions instead.
  const quick = panelCount() > 0;
  const query = applied(); // a search still waiting for the full week has found nothing yet
  // Picks and a search together: the search is named first, so "nothing for OpenSSH" never hides an OpenSSH row the
  // search left out (PRODUCT.md principle 2).
  const message = filter.picks.length && query && !quick ? t.noneForBoth(names, query)
    : filter.picks.length && !quick ? t.noneForPicks(names) : query && !quick ? t.noneForQuery(query)
    : quick ? t.noneForFilters : t.noIncidents;
  const buttons = el('p', 'actions');
  // Say how far back this looked: "nothing" in one week is not "nothing" in 90 days.
  const scope = para('scope', olderMonths.length ? t.scopeWeek : t.scopeMonths);
  if (olderMonths.length) {
    buttons.append(olderButton(t.searchOlder));
  }
  if (query) buttons.append(clearButton(t.clearSearch, { query: '' }, true));
  // Filters left nothing: each condition can go on its own, the ones that bring the most back first (at most three).
  if (quick) {
    const count = (change) => board({ ...filter, ...change }).list.length;
    const drops = conditionList().map(([label, change]) => [label, change, count(change)]).filter(([, , n]) => n > 0)
      .sort((a, b) => b[2] - a[2]).slice(0, 3);
    for (const [label, change] of drops) buttons.append(clearButton(t.fp.dropCond(label), change, true));
  }
  // 모두 지우기 only when something besides the search is set; with a search alone it would repeat 검색 지우기.
  if (activeFilters() - (query ? 1 : 0) > 0) buttons.append(clearButton(t.clearAll, NO_FILTER, true));
  const actions = buttons.childElementCount ? [buttons] : [];
  // Only Products picked and none on the Board: the visitor's good news, said as a sign, never as "safe".
  if (filter.picks.length && !quick && !query) return [allClear(), ...actions];
  // Astryx EmptyState, Best Practices: "Do: Use an illustration or icon that reinforces the context": the search glyph,
  // or the filter funnel when quick filters emptied the Board.
  const icon = el('span', 'e-icon');
  icon.setAttribute('aria-hidden', 'true');
  icon.innerHTML = quick && !query ? EMPTY_FILTER : EMPTY_SEARCH;
  // A search that found nothing says what the Board holds (owner, 11-17: "why is my October CVE missing?"), whether or
  // not the notice under the header was closed; past the store's 90 days only the retention sentence stays.
  // Each sentence its own box, as in index.html #collect-note: lines break between sentences (owner, 11-18).
  const lines = sinceStillTrue(document.documentElement.dataset.collectedSince, Date.now()) ? [...t.noticeSince, t.noticeKeep] : [t.noticeKeep];
  const facts = Object.assign(el('p', 'scope'), { lang });
  lines.forEach((line, n) => { const box = el('span', 'sentence'); box.append(...keepIds(line)); facts.append(...(n ? [' ', box] : [box])); });
  const text = el('div', 'e-text');
  text.append(para('', message), scope, ...(query ? [facts] : []));
  return [icon, text, ...actions];
}
const EMPTY_SEARCH = '<svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m15.5 15.5 5 5M8 8l5 5m0-5-5 5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>';
const EMPTY_FILTER = '<svg viewBox="0 0 24 24"><path d="M3.5 4.5h17l-6.5 8v5.5l-4 2v-7.5Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>';

function allClear() {
  const t = TEXT[lang];
  const sign = el('div', 'allclear');
  const mark = el('span', 'mark');
  mark.setAttribute('aria-hidden', 'true');
  mark.innerHTML = '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m7.5 12.3 3 3 6-6.3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const tags = el('span', 'c-tags');
  tags.append(...pickedEntries().map((e) => lineBadge(e.name, e.ids[0])), ...osPicks().map((id) => lineBadge(osName(id), id)));
  const lines = el('span', 'lines');
  lines.append(tags, el('strong', '', olderMonths.length ? t.clearWeek : t.clearMonths), el('span', 'note', t.clearNote));
  sign.append(mark, lines);
  return sign;
}

// In the empty state the button says how many Incidents it brings back, so the visitor sees which narrowing hid them.
function clearButton(text, change, counted = false) {
  const next = { ...filter, ...change };
  const n = counted ? board(next).list.length : 0;
  const button = Object.assign(el('button', 'btn', n ? TEXT[lang].restore(text, n) : text), { type: 'button' });
  button.addEventListener('click', () => {
    if ('query' in change) $('search').value = change.query;
    const drawn = update(change);
    // The field only when that field is what changed (a phone would raise its keyboard over the rows otherwise);
    // else the first row that came back, or the top of the Board (critique 11).
    if ('query' in change && Object.keys(change).length === 1) return $('search').focus({ preventScroll: true });
    drawn.then(() => ($('highlights').querySelector('button.row') || $('board').querySelector('button.row') || $('board-start')).focus({ preventScroll: true }));
  });
  return button;
}

// The bar (index.html #bar; owner, 11-19, after Astryx PowerSearch / Tokenizer / Typeahead). Picked Products are tokens
// before the typed text, one per entry however many of its ids are picked; the typed text is the keyword search and
// suggests Products. OS picks stay the filter panel's (they show among its conditions under the bar).
const productPicks = () => filter.picks.filter((p) => !p.startsWith('os:'));
function pickedEntries() {
  const seen = new Map();
  for (const id of productPicks()) {
    const e = entryOf.get(id) || { key: id, name: products.find((p) => p.id === id)?.name || id, ids: [id] };
    if (!seen.has(e.key)) seen.set(e.key, e);
  }
  return [...seen.values()];
}
// What the picks are called in a sentence: one name per token, then the OS picks.
const osName = (id) => OSES.find((o) => `os:${o.toLowerCase()}` === id) || id.slice(3);
const pickNames = () => [...pickedEntries().map((e) => e.name), ...osPicks().map(osName)];
function unpick(e) {
  update({ picks: filter.picks.filter((p) => !e.ids.includes(p)) });
  $('search').focus({ preventScroll: true }); // the token is gone; keep keyboard users in the bar
}
// Every token in the bar, in order: picked Products, then the filter panel's conditions (Astryx PowerSearch: each
// filter is a token). [text nodes, name, remove]
function barTokens() {
  const products = pickedEntries().map((e) => [[label(e)], label(e), () => unpick(e), `p:${e.ids.join()}`]);
  const conditions = conditionList().map(([value, change, field, key]) => [field ? [el('span', 'f', `${field} `), el('b', '', value)] : [value],
    field ? `${field} ${value}` : value, () => { update(change); $('search').focus({ preventScroll: true }); }, key]);
  return [...products, ...conditions];
}
function token([text, name, remove, key]) {
  const item = el('span');
  item.dataset.key = key;
  item.setAttribute('role', 'listitem');
  const button = Object.assign(el('button', 'token'), { type: 'button' });
  const words = el('span', 't');
  words.append(...text);
  button.append(words, el('span', 'x'));
  button.setAttribute('aria-label', TEXT[lang].remove(name));
  button.addEventListener('click', remove);
  item.append(button);
  return item;
}
// The end lane: how many the Board shows while anything narrows it (PowerSearch resultCount), and one clear-all button
// for the picks, the search and the panel's conditions (PowerSearch hasClear); every row of tokens stops short of it.
function barEnd(list) {
  const t = TEXT[lang];
  const tokens = barTokens();
  const box = $('tokens');
  // A token that was not there pops in, one that went shrinks out (owner, 11-19); a redraw that keeps them (typing, a
  // refresh, the first draw, a new language) moves nothing. Keys do not depend on the language.
  const before = tokensLang === lang ? [...box.children].filter((n) => !n.classList.contains('leaving')) : null;
  tokensLang = lang;
  box.replaceChildren(...tokens.map(token));
  if (before) {
    const was = new Set(before.map((n) => n.dataset.key));
    const now = new Set(tokens.map((t) => t[3]));
    for (const item of box.children) if (!was.has(item.dataset.key)) pop(item.firstChild, 'scale(0.8)', 180);
    before.forEach((old, n) => { if (!now.has(old.dataset.key)) tokenLeave(old, box.children[n] || null); });
  }
  $('bar').classList.toggle('has-tokens', tokens.length > 0);
  const narrowed = activeFilters() > 0 || Boolean($('search').value);
  $('result-count').hidden = !narrowed || !updated || Boolean(loadError) || (filter.query && !applied());
  $('result-count').textContent = $('result-count').hidden ? '' : t.resultCount(list.length);
  $('search-clear').hidden = !narrowed;
  tokenOverflow();
}
let tokensLang = null; // the language the bar's tokens were last drawn in; null before the first draw
// A removed token stays a moment as an inert copy where it was, shrinking out; reduced motion: it only fades.
function tokenLeave(item, next) {
  item.classList.add('leaving');
  item.inert = true;
  item.setAttribute('aria-hidden', 'true');
  item.removeAttribute('role');
  $('tokens').insertBefore(item, next);
  const gap = getComputedStyle($('bar')).columnGap;
  const out = reducedMotion.matches ? [{ opacity: 1 }, { opacity: 0 }]
    : [{ opacity: 1, scale: '1', width: `${item.offsetWidth}px`, marginInlineEnd: '0px' }, { opacity: 0, scale: '0.8', width: '0px', marginInlineEnd: `-${gap}` }];
  item.animate(out, { duration: 160, easing: EASE_EXIT }).finished.finally(() => item.remove());
}
// Unfocused, the bar keeps its tokens on one row (Astryx Tokenizer tokenOverflowBehavior "unfocusedInline", index.html
// .sbar:not(:focus-within)) and says how many it cannot show; focused, every token wraps into view.
function tokenOverflow() {
  const bar = $('bar');
  const edge = bar.getBoundingClientRect().right - parseFloat(getComputedStyle(bar).paddingRight) + 0.5;
  const tokens = [...bar.querySelectorAll('#tokens > :not(.leaving) > .token')];
  const hidden = tokens.filter((t) => !t.offsetWidth || t.getBoundingClientRect().right > edge).length;
  const all = hidden > 0 && hidden === tokens.length; // a phone's closed bar shows none: say what is set, as a token
  $('token-more').hidden = !hidden;
  $('token-more').classList.toggle('all', all);
  $('token-more').textContent = !hidden ? '' : all ? TEXT[lang].tokensSet(hidden) : `+${hidden}`;
}
new ResizeObserver(tokenOverflow).observe($('bar'));
// Every row of tokens stops short of the end lane (index.html .bar, --lane), whatever it holds at the moment: a render
// can run while the bar is not laid out, so its width is watched, not read once.
new ResizeObserver(([entry]) => $('bar').style.setProperty('--lane', `${Math.ceil(entry.target.offsetWidth)}px`))
  .observe($('bar').querySelector('.bar-end'));
// Suggestions: ranked Products for the typed text, at most ten (PowerSearch maxSearchResults), ones already picked left out.
let suggested = [];
let active = -1; // the suggestion the arrows moved to
function suggest() {
  const t = TEXT[lang];
  const input = $('search');
  const picked = new Set(productPicks());
  suggested = document.activeElement === input ? rankEntries(entries.filter((e) => !e.ids.every((id) => picked.has(id))), input.value, label) : [];
  active = -1;
  const box = $('suggest');
  box.hidden = !suggested.length;
  input.setAttribute('aria-expanded', String(!box.hidden));
  input.removeAttribute('aria-activedescendant');
  if (box.hidden) return box.replaceChildren();
  const head = el('p', 'menu-head', t.sgHead);
  head.setAttribute('aria-hidden', 'true');
  box.replaceChildren(head, ...suggested.map((e, n) => {
    const option = Object.assign(el('div', 'mi sg-item'), { id: `sg-${n}` });
    option.setAttribute('role', 'option');
    option.setAttribute('aria-selected', 'false');
    option.append(el('span', 't', label(e)), ...(e.n ? [el('span', 'd', t.sgCount(e.n))] : []));
    for (const type of ['pointerdown', 'mousedown']) option.addEventListener(type, (event) => event.preventDefault()); // the input keeps the focus
    option.addEventListener('click', () => pickEntry(e));
    return option;
  }));
}
function closeSuggest() {
  suggested = [];
  active = -1;
  $('suggest').hidden = true;
  $('suggest').replaceChildren();
  $('search').setAttribute('aria-expanded', 'false');
  $('search').removeAttribute('aria-activedescendant');
}
function moveActive(step) {
  if (!suggested.length) return;
  active = active < 0 ? (step > 0 ? 0 : suggested.length - 1) : (active + step + suggested.length) % suggested.length;
  $('suggest').querySelectorAll('.sg-item').forEach((o, n) => o.setAttribute('aria-selected', String(n === active)));
  const option = $(`sg-${active}`);
  $('search').setAttribute('aria-activedescendant', option.id);
  option.scrollIntoView({ block: 'nearest' });
}
function pickEntry(e) {
  clearTimeout(typing);
  $('search').value = '';
  update({ picks: [...new Set([...filter.picks, ...e.ids])], query: '' });
  suggest();
}

const PANEL_EMPTY = { risk: [], kev: false, from: '', to: '', cvssMin: 0, cve: '', has: [] }; // sort is not a filter: it has its own control
const NO_FILTER = { picks: [], query: '', ...PANEL_EMPTY };
const osPicks = () => filter.picks.filter((p) => p.startsWith('os:'));
// What the 필터 button's badge counts: everything set inside the panel.
const panelCount = () => filter.risk.length + (filter.kev ? 1 : 0) + osPicks().length + (filter.from || filter.to ? 1 : 0)
  + (filter.cvssMin ? 1 : 0) + (filter.cve ? 1 : 0) + filter.has.length;
const activeFilters = () => filter.picks.length - osPicks().length + panelCount() + (filter.query ? 1 : 0);

// The 주요 사건 header's count: "4/20" while 주요 사건 더 보기 holds some back (spoken as a sentence), else the one number.
function pinCount(shown, total) {
  if (total <= shown) return [el('span', 'n', String(shown))];
  const n = el('span', 'n', `${shown}/${total}`);
  n.setAttribute('aria-hidden', 'true');
  return [n, el('span', 'sr-only', TEXT[lang].pinShown(shown, total))];
}

// 주요 사건 더 보기: pin every chosen Highlight (pickHighlights: twenty at most), or back to four.
let pinAll = false;
// Where 더 보기 stood in the window when pressed: 접기 puts the new 더 보기 back there (owner, 11-22: back to the screen
// before), by the button and not an old scrollY. Reaching 접기 takes a scroll, so no scroll cancels it; a reload has none.
let pinFrom = null;
function pinToggle(rest) {
  const t = TEXT[lang];
  const button = Object.assign(el('button', 'btn', pinAll ? t.pinLess : t.pinMore(rest)), { type: 'button' });
  button.setAttribute('aria-expanded', pinAll);
  button.addEventListener('click', () => {
    const from = pinAll ? pinFrom : button.getBoundingClientRect().top;
    boardTransition(() => {
      pinAll = !pinAll;
      pinFrom = pinAll ? from : null;
      render();
      const again = $('pin-more').querySelector('button'); // render() built a new one: keep keyboard users on it
      const added = pinAll && $('highlights').children[PINNED]?.querySelector('button.row');
      (added || again)?.focus({ preventScroll: true });
      if (!pinAll && from !== null && again) scrollBy(0, again.getBoundingClientRect().top - from);
      else (added || again)?.scrollIntoView({ block: 'nearest' });
    });
  });
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
  // A choice of three or four (최소 CVSS, CVE 번호) is a segmented control, every option in sight, not a select (Astryx
  // Selector, Best Practices: "Don't: Use when there are only two options; use a SegmentedControl or radio buttons";
  // SegmentedControl: "Use for switching between 2-5 mutually exclusive views or modes where all options should be visible").
  const segments = (legend, name, items, value) => {
    const set = el('fieldset', 'fp-field fp-seg');
    const track = el('div', 'fp-seg-track');
    for (const [v, text] of items) {
      const box = Object.assign(input('radio', name, v), { checked: String(v) === String(value) });
      const option = el('label', '');
      option.append(box, el('span', '', text));
      track.append(option);
    }
    set.append(el('legend', 'fp-label', legend), track);
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
    // Astryx Field, Best Practices: "Do: Wire inputID/descriptionID to htmlFor and aria-describedby on the inner control." (each note describes its group)
    (() => { const set = checks(f.risk, 'risk', RISKS.map((r) => [r, words[r], `risk-${r}`]), (r) => filter.risk.includes(r)); set.setAttribute('aria-describedby', 'fp-risk-note'); return set; })(),
    checks(f.flags, 'flag', [['kev', t.qfKev], ...LINK_KINDS.map((k) => [k, f.has[k]])], (v) => (v === 'kev' ? filter.kev : filter.has.includes(v))),
    (() => { const set = checks('OS', 'os', OSES.map((os) => [`os:${os.toLowerCase()}`, os]), (v) => filter.picks.includes(v)); set.setAttribute('aria-describedby', 'fp-os-note'); return set; })(),
    segments(f.cvss, 'cvssMin', [[0, f.any], [4, '4.0+'], [7, '7.0+'], [9, '9.0+']], filter.cvssMin),
    segments(f.cve, 'cve', [['', f.any], ['yes', f.cveYes], ['no', f.cveNo]], filter.cve),
    dates,
  );
  const actions = el('div', 'fp-actions');
  const reset = Object.assign(el('button', 'btn', f.reset), { type: 'button' });
  // The panel is drawn again under the pressed button: 필터 초기화 in the new one takes the focus, never <body>. It is
  // redrawn inside the Board transition (update), not before it, so the chosen chips cross-fade to clear (owner, 11-19).
  const refocus = () => $('filters').querySelector('.fp-actions .btn')?.focus({ preventScroll: true });
  // Under a sheet the Board redraws without a transition (boardTransition), so the cleared choices fade in themselves.
  reset.addEventListener('click', () => {
    const over = panelOver();
    update(PANEL_EMPTY_WITH_OS()).then(() => {
      refocus();
      if (over) $('filters').querySelector('.fp-grid')?.animate([{ opacity: 0.4 }, { opacity: 1 }], { duration: 160, easing: EASE_OUT });
    });
  });
  const apply = Object.assign(el('button', 'btn primary', f.apply), { type: 'submit' });
  actions.append(reset, apply);
  // The groups' notes sit in the footer, left of the buttons (owner, 11-19); each group still points to its own note.
  // The dashed-chip note shows only while a dashed chip does (countDraft), and each dashed chip points to it.
  const notes = el('div', 'fp-notes');
  notes.append(...[['fp-risk-note', f.riskNote], ['fp-os-note', f.osNote], ['fp-zero-note', f.zeroNote]]
    .map(([id, text]) => Object.assign(el('p', id === 'fp-zero-note' ? 'fp-note fp-zero-note' : 'fp-note', text), { id })));
  const foot = el('div', 'fp-foot');
  foot.append(notes, actions);
  // A visible way out, as the reading guide has: the phone sheet covers the Board and Escape is not on a phone keyboard.
  // Astryx Dialog's header: the title and an icon-only ghost close, named and with its hover hint.
  const close = Object.assign(el('button', 'btn fp-close'), { type: 'button' });
  close.setAttribute('aria-label', f.close);
  close.dataset.tip = f.close;
  close.append(el('span', 'x'));
  close.addEventListener('click', () => closePanel());
  const head = el('div', 'g-head fp-head');
  head.append(Object.assign(el('h3', 'fp-title', f.title), { id: 'fp-title' }), close);
  form.replaceChildren(head, grid, foot);
  for (const track of form.querySelectorAll('.fp-seg-track')) new ResizeObserver(placeSegs).observe(track); // text size, width
  countDraft();
}
// 최소 CVSS and CVE 번호: one pill under the chosen option that slides across, as the 기본|쉬운 설명 switch's does (placePill).
function placeSegs() {
  for (const track of $('filters').querySelectorAll('.fp-seg-track')) {
    const on = track.querySelector('input:checked')?.parentElement;
    if (!on) continue;
    track.style.setProperty('--pill-x', `${on.offsetLeft}px`);
    track.style.setProperty('--pill-w', `${on.offsetWidth}px`);
    if (!track.classList.contains('slid')) {
      track.classList.add('slid');
      requestAnimationFrame(() => requestAnimationFrame(() => track.classList.add('ready'))); // no slide as the panel opens
    }
  }
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
  const count = (draft) => board({ ...filter, ...draft }).list.length;
  const n = count(panelDraft());
  const apply = $('filters').querySelector('button[type=submit]');
  if (apply) {
    // the number swaps in quickly when a choice changes it, never as the panel opens (a new button has no data-n yet)
    const was = apply.dataset.n;
    apply.dataset.n = n;
    const words = el('span', '', TEXT[lang].fp.applyN(n));
    apply.replaceChildren(words);
    if (was !== undefined && was !== String(n)) {
      words.animate([reducedMotion.matches ? { opacity: 0 } : { opacity: 0, translate: '0 0.375em' }, { opacity: 1, translate: '0 0' }],
        { duration: 160, easing: EASE_OUT });
    }
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
$('filters').addEventListener('change', () => { countDraft(); placeSegs(); });

function applyPanel(event) {
  event.preventDefault();
  const fromCopy = panelFrom?.stuck;
  // the results are the answer; the applied conditions stay visible as chips. The panel shuts inside the Board
  // transition, so its old picture fades out while the rows glide up once (no fade of its own, which would keep it in
  // the page a moment and drop the rows again after the transition).
  // Over the Board (sheet, floating) it fades out on its own while the Board redraws at once under it (boardTransition).
  const draft = panelDraft();
  const drawn = panelOver() ? (closePanel(true), update(draft)) : update(draft, true, () => closePanel(true));
  if (fromCopy) drawn.then(toBoardHead); // opened mid-list: the new results start under the frozen row
  // A start date before the loaded week needs the older months.
  const week = new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10);
  if (filter.from && filter.from < week && olderMonths.length) loadOlder();
}

function update(change, animate = true, first = () => {}) {
  letGo(); // a new filter is a new Board: no row is held (holdRow)
  // A search word rewrites its own step; starting a search (from none) is a new step, so Back first clears the search.
  const onlyQuery = Object.keys(change).length === 1 && 'query' in change;
  const push = !onlyQuery || (!filter.query && Boolean(change.query));
  filter = { ...filter, ...change };
  shown = PAGE;
  saveFilter(push);
  const redraw = () => {
    first();
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
let stuckOn = false; // placeJump: the reader is mid-list, the Board's head gone under the frozen row
const phoneSheet = () => matchMedia('(max-width: 599px)').matches;
// the panel is over the Board (a phone's sheet, or floating mid-list) and still drawn, fading out included
const panelOver = () => (phoneSheet() || $('filters').classList.contains('floating')) && getComputedStyle($('filters')).display !== 'none';
function openPanel(opener) {
  const form = $('filters');
  panelFrom = { opener, y: scrollY, stuck: stuckOn };
  // A phone's bottom sheet, or (wider) the panel opened from the frozen row mid-list floating under it: a modal dialog
  // over the page, which stays where it was. At the top of the page on wider screens it opens inline under the fields.
  // Floating is set before it shows, or the inline panel would push the page (scroll anchoring) for a frame.
  const floating = stuckOn && !phoneSheet();
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
  } else {
    for (const name of ['role', 'aria-modal', 'aria-labelledby']) form.removeAttribute(name);
    slidePanel(form, true);
  }
  // inline too (audit F8): else the next Tab went to 정렬, past the panel just opened
  form.querySelector('.fp-head .btn').focus({ preventScroll: true });
}

// The inline panel grows open and shrinks shut, so the Board below slides down and back up instead of jumping
// (owner, 11-19). Height is animated on purpose: the push is the point, and it runs once per open or close.
// Reduced motion keeps a fade, never the slide.
function slidePanel(form, opening) {
  form.getAnimations().forEach((a) => a.cancel());
  if (reducedMotion.matches) {
    form.animate([{ opacity: opening ? 0 : 1 }, { opacity: opening ? 1 : 0 }], { duration: 160 });
    return;
  }
  const cs = getComputedStyle(form);
  const full = { height: `${form.offsetHeight}px`, paddingTop: cs.paddingTop, paddingBottom: cs.paddingBottom, marginBottom: cs.marginBottom, borderTopWidth: cs.borderTopWidth, borderBottomWidth: cs.borderBottomWidth, opacity: 1 };
  const none = { height: '0px', paddingTop: '0px', paddingBottom: '0px', marginBottom: '0px', borderTopWidth: '0px', borderBottomWidth: '0px', opacity: 0 };
  form.style.overflow = 'clip';
  const run = form.animate(opening ? [none, full] : [full, none], opening
    ? { duration: 260, easing: EASE_OUT }
    : { duration: 160, easing: EASE_EXIT, fill: 'forwards' }); // the CSS keeps it drawn 160ms (index.html .filters[hidden])
  run.finished.then(() => { form.style.overflow = ''; run.cancel(); }, () => { form.style.overflow = ''; });
}

function closePanel(applied = false) {
  const from = panelFrom;
  panelFrom = null;
  sheetInert(false);
  // applied inline: the Board transition carries it out (applyPanel); a sheet or floating panel fades out on its own
  const inline = !phoneSheet() && !$('filters').classList.contains('floating');
  $('filters').classList.toggle('shut', applied && inline);
  if (inline && !applied) slidePanel($('filters'), false);
  $('filters').hidden = true; // else it fades out (index.html .filters[hidden]); floating stays until the next open sets it
  $('filter-btn').setAttribute('aria-expanded', 'false');
  if (!applied && from && scrollY !== from.y) scrollTo(0, from.y);
  $('filter-btn').focus({ preventScroll: true });
}

// The phone sheet's head is its handle (Astryx BottomSheet: "drag region at the top of the panel"): dragged down it follows
// the finger, and let go past 80px it closes; short of that it springs back.
{
  const form = $('filters');
  let drag = null;
  form.addEventListener('pointerdown', (event) => {
    if (!phoneSheet() || form.hidden || !event.target.closest('.fp-head') || event.target.closest('button')) return;
    drag = { y: event.clientY, id: event.pointerId };
    form.setPointerCapture(event.pointerId);
  });
  form.addEventListener('pointermove', (event) => {
    if (drag?.id === event.pointerId) form.style.translate = `0 ${Math.max(0, event.clientY - drag.y)}px`;
  });
  const drop = (event) => {
    if (drag?.id !== event.pointerId) return;
    const far = event.type === 'pointerup' && event.clientY - drag.y > 80;
    drag = null;
    form.style.translate = '';
    if (far) closePanel();
  };
  form.addEventListener('pointerup', drop);
  form.addEventListener('pointercancel', drop);
}

// Icon-only buttons name themselves in a small inverted bubble (Astryx Tooltip: "Add a tooltip to icon-only buttons";
// useTooltip.tsx: Primary Ink ground, the surface's colour on it, 4px by 8px in, delay 200, placement above, flipping
// below where there is no room): after 200ms under a hovering pointer, at once on a keyboard focus, never on touch.
// The name is the button's aria-label already, so the bubble is hidden from readers. A button showing its word has none.
{
  const tip = Object.assign(document.createElement('div'), { className: 'tip', hidden: true }); // el() is defined further down
  tip.setAttribute('aria-hidden', 'true');
  document.body.append(tip);
  let timer = 0;
  const hide = () => { clearTimeout(timer); tip.hidden = true; };
  const show = (node) => {
    if (node.querySelector(':scope > span:not(.x, .count)')?.offsetWidth > 1) return; // its word is on screen
    tip.textContent = node.dataset.tip;
    tip.hidden = false;
    const r = node.getBoundingClientRect();
    const above = r.top - tip.offsetHeight - 6 >= 0;
    const x = Math.min(innerWidth - tip.offsetWidth - 8, Math.max(8, r.left + r.width / 2 - tip.offsetWidth / 2));
    tip.style.translate = `${Math.round(x)}px ${Math.round(above ? r.top - tip.offsetHeight - 6 : r.bottom + 6)}px`;
  };
  document.addEventListener('pointerover', (event) => {
    const node = event.target.closest?.('[data-tip]');
    if (!node || event.pointerType === 'touch' || node.contains(event.relatedTarget)) return;
    hide();
    timer = setTimeout(() => show(node), 200);
  });
  document.addEventListener('pointerout', (event) => {
    const node = event.target.closest?.('[data-tip]');
    if (node && !node.contains(event.relatedTarget)) hide();
  });
  document.addEventListener('focusin', (event) => {
    hide();
    const node = event.target;
    if (!node.matches?.('[data-tip]:focus-visible')) return;
    // A panel still sliding open (the phone sheet rises 300ms, audit F6) would leave the bubble where the button was:
    // it shows once the panel has landed, if the button still has the focus.
    const moving = node.closest('#filters')?.getAnimations() ?? [];
    if (!moving.length) return show(node);
    Promise.all(moving.map((a) => a.finished)).then(() => node.matches(':focus-visible') && show(node), () => {});
  });
  document.addEventListener('focusout', hide);
  document.addEventListener('pointerdown', hide);
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') hide(); });
  addEventListener('scroll', hide, { passive: true });
}

// The Board's head (the bar with 주요 사건) just under the frozen row: where a new order or filter starts reading.
const toBoardHead = () => $('board-start').scrollIntoView({ block: 'start', behavior: glide() });

// Each applied panel condition as a removable chip under the fields, so what is filtered stays in sight.
// Each applied panel condition as [label, the change that removes it].
function conditionList() {
  const t = TEXT[lang];
  const f = t.fp;
  const words = defaultView === 'easy' ? t.easyLevels : t.levels;
  // [value, change, field, key]: a token reads "field value" (Astryx PowerSearch token, the value bold); a value that
  // names itself ("공격 발생만") has no field. The key names the condition alone (a change carries its siblings), so
  // the bar's tokens pop in and shrink out one by one (barEnd).
  return [
    ...filter.risk.map((r) => [words[r], { risk: filter.risk.filter((x) => x !== r) }, f.risk, `risk:${r}`]),
    ...(filter.kev ? [[t.qfKev, { kev: false }, undefined, 'kev']] : []),
    ...filter.has.map((h) => [f.has[h], { has: filter.has.filter((x) => x !== h) }, undefined, `has:${h}`]),
    ...osPicks().map((p) => [osName(p), { picks: filter.picks.filter((x) => x !== p) }, 'OS', p]),
    ...(filter.from || filter.to ? [[`${filter.from || '…'} ~ ${filter.to || '…'}`, { from: '', to: '' }, f.published, `date:${filter.from}~${filter.to}`]] : []),
    ...(filter.cvssMin ? [[`${filter.cvssMin}.0+`, { cvssMin: 0 }, 'CVSS', `cvss:${filter.cvssMin}`]] : []),
    ...(filter.cve ? [[filter.cve === 'yes' ? f.cveYes : f.cveNo, { cve: '' }, undefined, `cve:${filter.cve}`]] : []),
  ];
}

// The language menu (owner, 11-17: a dropdown now that there are three): a popover like the RSS menu below; where the
// browser has no popovers the button steps to the next language instead.
const langsOpen = () => canPop && $('langs').matches(':popover-open');
const setLang = (next) => crossFade(() => {
  // Turning Japanese: what was parsed in Korean or English gains the twins once (products is redrawn below)
  if (next === 'ja' && lang !== 'ja') for (const doc of [incidents, seenProducts, productCounts, ...plainDocs]) giveJapanese(doc);
  lang = next;
  store(SAVED_LANG, lang);
  clearTimeout(announcing);
  $('announce').textContent = ''; // nothing said in the old language stays (critique 14: 글자 크기 100% on the English page)
  refreshProducts();
  render();
  if (!$('filters').hidden) filterPanel(); // an open panel speaks the new language (an unapplied choice there resets)
});
$('langs').addEventListener('click', (event) => {
  const item = event.target.closest('[data-lang]');
  if (!item) return;
  $('langs').hidePopover();
  if (item.dataset.lang !== lang) setLang(item.dataset.lang);
});
$('view-normal').addEventListener('click', () => setDefaultView('normal'));
$('view-easy').addEventListener('click', () => setDefaultView('easy'));
$('theme').addEventListener('click', toggleTheme);
// Escape closes what is open, the latest layer first: the filter panel, then the reading guide, then the row the focus is in.
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape' || sortsOpen()) return; // an open 정렬 menu takes the Escape alone
  if (!$('filters').hidden) return closePanel();
  if (guideOpen && !$('guide').dataset.leaving) return closeGuide();
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
// 정렬 changed mid-list (the frozen row): a new order is read from its start, so the Board's head comes up under the
// frozen row (critique 13: the reader was left mid-list in the new order).
function pickSort(sort) {
  if (canPop) $('sorts').hidePopover();
  if (sort === filter.sort) return;
  const mid = stuckOn;
  sortBy(sort).then(() => mid && toBoardHead());
}
function sortBy(sort) {
  const drawn = update({ sort });
  // The count does not change with the order, so say the order itself (the count line stays quiet).
  $('announce').textContent = TEXT[lang].sorted(TEXT[lang].fp.sorts[sort]);
  return drawn;
}
$('fold-toggle').addEventListener('click', () => boardTransition(() => {
  folding = !folding;
  store(SAVED_FOLD, folding ? null : 'off');
  render();
  $('fold-toggle').focus({ preventScroll: true });
  clearTimeout(announcing);
  $('announce').textContent = folding ? TEXT[lang].refoldDone : TEXT[lang].unfoldDone;
}));
$('expand-all').addEventListener('click', () => boardTransition(() => {
  letGo(); // the rows open or close where they are (held)
  const closing = allOpen();
  if (!closing) fullFailed = false; // opening rows is the visitor asking: row views ask for the week again
  for (const id of visibleIds) closing ? open.delete(id) : open.add(id);
  render();
  $('expand-all').focus({ preventScroll: true });
}));
// 필터 opens the panel where the reader is: a sheet on a phone, inline at the top, floating under the frozen row mid-list.
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
  box.closing = box.animate([{ opacity: 1 }, { opacity: 0, translate: '0 -4px' }], { duration: 120, easing: EASE_EXIT });
  box.closing.onfinish = () => { box.closing = null; box.classList.remove('open'); };
}
$('prefs-btn').addEventListener('click', () => setPrefs(!$('prefs').classList.contains('open')));
document.addEventListener('pointerdown', (event) => {
  if ($('prefs').classList.contains('open') && !$('prefs').contains(event.target) && !$('prefs-btn').contains(event.target)
    && !$('feeds').contains(event.target) && !$('langs').contains(event.target)) setPrefs(false); // a menu opened from the panel keeps it
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && $('prefs').classList.contains('open') && !feedsOpen() && !langsOpen() && !sortsOpen()) { // Escape closes an open menu alone
    setPrefs(false);
    $('prefs-btn').focus();
  }
});

// The RSS menu (owner, 11-17; DESIGN.md "RSS menu"): the brand row's button, or on phones the settings panel's, opens one
// popover. The browser opens and closes it (commandfor), closes it on Escape or a click elsewhere and returns focus to
// the button. Each entry links its feed in the page's language with its address to copy; 내 제품 follows the picks.
const feedButtons = ['feeds-btn', 'feeds-btn-phone'].map($);
const canPop = Object.hasOwn(HTMLElement.prototype, 'popover'); // without it index.html does not draw the buttons
const feedsOpen = () => canPop && $('feeds').matches(':popover-open');
function feedRows() {
  const t = TEXT[lang];
  const set = (id, path) => {
    $(id).href = path;
    $(`${id}-url`).textContent = $(id).href;
  };
  set('feed-main', feedPath(lang));
  set('feed-all', feedPath(lang, 'all'));
  // Products only (OS picks are the panel's, and the feeds have no OS documents); before products.json arrives a pick
  // is asked by its id's tail, which the check index also knows ("openbsd:openssh" is "openssh").
  const names = filter.picks.filter((p) => !p.startsWith('os:'))
    .map((id) => products.find((p) => p.id === id)?.name || id.slice(id.indexOf(':') + 1).replace(/_/g, ' '));
  const feed = productFeed(names, lang);
  $('feed-mine').hidden = !feed;
  $('feed-none').hidden = Boolean(feed);
  if (!feed) return;
  set('feed-products', feed.href);
  $('feed-names').textContent = feed.names.slice(0, 3).join(', ') + (feed.names.length > 3 ? t.feedMore(feed.names.length - 3) : '');
  $('feed-left').hidden = !feed.left;
  $('feed-left').textContent = feed.left ? t.feedLeft(feed.left) : '';
}
// A header menu's popover (the RSS menu, the language menu) and the buttons that open it. Given its entries (`items`,
// read at key time: the RSS menu hides some), it is keyed as 정렬's list is (audit F7): open, the focus starts on the
// current entry or the first, and the arrows, Home and End move it; Enter, Tab and Escape stay the browser's.
function popMenu(menu, buttons, items) {
  const isOpen = () => menu.matches(':popover-open');
  // Invoker commands are newer than popovers: without them the buttons toggle the menu here.
  if (!('commandForElement' in HTMLButtonElement.prototype)) {
    for (const button of buttons) {
      button.addEventListener('click', (event) => {
        event.preventDefault();
        if (isOpen()) menu.hidePopover();
        else menu.showPopover({ source: button });
      });
    }
  }
  menu.addEventListener('toggle', (event) => {
    const opening = event.newState === 'open';
    for (const button of buttons) button.setAttribute('aria-expanded', opening);
    // Without anchor positioning: under the visible button, kept inside the screen, above it when there is no room below.
    if (!opening || CSS.supports('position-area: block-end')) return;
    const box = buttons.find((b) => b.getClientRects().length).getBoundingClientRect();
    const left = Math.max(8, Math.min(box.left, innerWidth - menu.offsetWidth - 8));
    const below = box.bottom + 4 + menu.offsetHeight <= innerHeight || box.top - 4 - menu.offsetHeight < 0;
    menu.style.left = `${left}px`;
    menu.style.top = `${below ? box.bottom + 4 : box.top - 4 - menu.offsetHeight}px`;
  });
  // Tab past the last entry leaves the menu: it closes, so focus never stays behind it.
  document.addEventListener('focusin', (event) => {
    if (isOpen() && !menu.contains(event.target) && !buttons.includes(event.target)) menu.hidePopover();
  });
  if (!items) return;
  menu.addEventListener('toggle', (event) => {
    if (event.newState === 'open') (items().find((i) => i.getAttribute('aria-current') === 'true') || items()[0])?.focus();
  });
  menu.addEventListener('keydown', (event) => {
    const list = items();
    const next = listboxStep(event.key, list.indexOf(document.activeElement), list); // no typed text: only the length is read
    if (next < 0) return;
    event.preventDefault();
    list[next].focus();
  });
}
if (canPop) popMenu($('langs'), [$('lang')], () => [...$('langs').querySelectorAll('[data-lang]')]);
else $('lang').addEventListener('click', () => setLang(LANGS[(LANGS.indexOf(lang) + 1) % LANGS.length]));
// 정렬 (owner, 11-19: its native list was the browser's own): a button opening a listbox menu like the language menu's,
// keyed as a listbox; without popovers the button steps to the next order, as 언어 does.
const sortsOpen = () => canPop && $('sorts').matches(':popover-open');
const sortOptions = () => [...$('sorts').querySelectorAll('[role="option"]')];
if (canPop) {
  const menu = $('sorts');
  popMenu(menu, [$('sort')]);
  menu.addEventListener('click', (event) => {
    const option = event.target.closest('[data-sort]');
    if (option) pickSort(option.dataset.sort);
  });
  // Open, the focus starts on the current order (APG listbox); closing returns it to the button (the browser's popover).
  menu.addEventListener('toggle', (event) => {
    if (event.newState === 'open') sortOptions().find((o) => o.getAttribute('aria-selected') === 'true')?.focus();
  });
  let typed = '';
  let typedAt = 0;
  menu.addEventListener('keydown', (event) => {
    const options = sortOptions();
    const at = options.indexOf(document.activeElement);
    if ((event.key === 'Enter' || event.key === ' ') && at >= 0) {
      event.preventDefault();
      return pickSort(options[at].dataset.sort);
    }
    // shortcut: type-ahead reads event.key, so Korean typed through an IME ("Process") finds nothing; arrows still work.
    const printed = event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey;
    if (printed) {
      typed = (event.timeStamp - typedAt < 600 ? typed : '') + event.key;
      typedAt = event.timeStamp;
    }
    const next = listboxStep(event.key, at, options.map((o) => o.textContent), printed ? typed : '');
    if (next < 0) return;
    event.preventDefault();
    options[next].focus();
  });
  // The closed button opens the list on an arrow key, as a select does.
  $('sort').addEventListener('keydown', (event) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    event.preventDefault();
    if (!sortsOpen()) menu.showPopover({ source: $('sort') });
  });
} else $('sort').addEventListener('click', () => pickSort(SORTS[(SORTS.indexOf(filter.sort) + 1) % SORTS.length]));
// The frosted menus are an experiment (owner, 11-19): ?menu=solid draws them solid to compare (index.html .menu-solid).
if (new URLSearchParams(location.search).get('menu') === 'solid') document.documentElement.classList.add('menu-solid');
if (canPop) {
  const menu = $('feeds');
  popMenu(menu, feedButtons, () => [...menu.querySelectorAll('a, button')].filter((x) => x.getClientRects().length));
  menu.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-copy]');
    if (!button) return;
    try {
      await navigator.clipboard.writeText($(button.dataset.copy).href);
      stampCopied(button);
      clearTimeout(button.settle);
      button.settle = setTimeout(() => { button.textContent = TEXT[lang].copy; }, 2000);
    } catch {
      getSelection().selectAllChildren($(`${button.dataset.copy}-url`)); // clipboard blocked: the address selected, to copy by hand
    }
  });
  // No product picked: 제품 고르기 closes the menu and puts the visitor in the picker.
  $('feed-pick').addEventListener('click', () => {
    menu.hidePopover();
    setPrefs(false);
    $('search').focus();
  });
}

// The search row stays at the top while the Board scrolls (like frozen panes); its height is kept in --stick so
// rows scrolled into view, the new-Incidents pill and the jump buttons clear it.
const stickyPart = () => (matchMedia('(max-width: 767px)').matches ? document.querySelector('.search-row') : $('filter'));
function measureStick() {
  const stick = `${stickyPart().offsetHeight}px`;
  // Unchanged: not written again, since a property on the root restyles the whole page (a second layout per redraw).
  if (document.documentElement.style.getPropertyValue('--stick') !== stick) document.documentElement.style.setProperty('--stick', stick);
}
addEventListener('resize', measureStick);
// 맨 위로 / 맨 아래로 at the bottom right: each shows only when there is somewhere to go.
let jumpQueued = false;
function placeJump() {
  jumpQueued = false;
  const room = innerHeight * 0.6;
  $('jump-up').classList.toggle('off', scrollY < room);
  $('jump-down').classList.toggle('off', scrollY + innerHeight > document.documentElement.scrollHeight - room);
  document.body.classList.toggle('scrolled', scrollY > 40);
  // the Board's head has passed under the frozen row: 필터 opens a floating panel, a new order scrolls back to the head
  stuckOn = $('board-start').getBoundingClientRect().bottom < stickyPart().getBoundingClientRect().bottom;
  // 맨 위로 wears how far down the page is, as a ring that fills clockwise
  const room2 = document.documentElement.scrollHeight - innerHeight;
  $('jump-up').style.setProperty('--read', room2 > 0 ? Math.min(scrollY / room2, 1).toFixed(3) : 0);
  // phones: the jump buttons rest out of the way 2 s after the page stops moving
  // 한 화면 위로 / 아래로: the pill shows while the page scrolls at all; a step with nowhere to go is disabled
  const max = document.documentElement.scrollHeight - innerHeight;
  $('step').hidden = max < 2;
  // Astryx IconButton, Props, isDisabled: "uses aria-disabled instead of native disabled": an end step keeps the focus
  $('step-up').setAttribute('aria-disabled', scrollY <= 1);
  $('step-down').setAttribute('aria-disabled', scrollY >= max - 1);
  rest($('step'));
  document.body.classList.remove('jump-idle');
  clearTimeout(jumpIdle);
  // after a step press the group stays STEP_HOLD, not 2 s, so the next press finds it under the finger
  jumpIdle = setTimeout(() => document.body.classList.add('jump-idle'), Date.now() - stepPressed < STEP_HOLD ? STEP_HOLD : 2000);
}
// Owner, 11-17 ("스크롤 말고 눌러서 이동"): 한 화면 위로 / 아래로 move one screen below the frozen search row (stepDistance), smooth
// unless motion is reduced; Page Up/Down, Space, Home and End stay the browser's own.
let stepPressed = 0;
const STEP_HOLD = 5000; // owner, 11-19: five seconds
const frozenHeight = () => { const r = stickyPart().getBoundingClientRect(); return r.top <= 1 && r.bottom > 0 ? r.bottom : 0; };
for (const [id, sign] of [['step-up', -1], ['step-down', 1]]) {
  $(id).addEventListener('click', () => {
    if ($(id).getAttribute('aria-disabled') === 'true') return; // nowhere to go
    stepPressed = Date.now();
    scrollBy({ top: sign * stepDistance(innerHeight, frozenHeight()), behavior: reducedMotion.matches ? 'auto' : 'smooth' });
  });
}
let jumpIdle;
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
$('jump-up').addEventListener('click', () => scrollTo({ top: 0, behavior: glide() }));
// The logo goes back to the main Board (owner, 11-09): panel conditions and search cleared, picked Products kept,
// since they are the visitor's own setting. A modified click still opens the address in a new tab.
$('home').addEventListener('click', (e) => {
  if (e.button || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  $('search').value = '';
  update({ query: '', ...PANEL_EMPTY });
  scrollTo({ top: 0, behavior: glide() });
});
$('jump-up').addEventListener('click', (event) => launch(event.currentTarget, true));
$('jump-down').addEventListener('click', (event) => launch(event.currentTarget, false));
$('jump-down').addEventListener('click', () => scrollTo({ top: document.documentElement.scrollHeight, behavior: glide() }));

$('guide-btn').addEventListener('click', () => (guideOpen && !$('guide').dataset.leaving ? closeGuide() : openGuide()));
// While the focus is outside a group, its Tab stop rests on a member that can act (restingStop); inside, it follows the focus.
function rest(group) {
  if (group.contains(document.activeElement)) return;
  const members = [...group.querySelectorAll('button')];
  const stop = restingStop(members.map((b) => b.getAttribute('aria-disabled') === 'true'));
  members.forEach((b, n) => { b.tabIndex = n === stop ? 0 : -1; });
}
// Two-button groups take one Tab stop and move by arrows (groupKey, Astryx ButtonGroup): 가−/가+ left and right, with
// Home/End; 한 화면 위로/아래로 up and down only, since Home and End stay the browser's (DESIGN.md, jump buttons).
function rove(group, keys) {
  const members = [...group.querySelectorAll('button')];
  rest(group);
  group.addEventListener('focusin', (event) => { for (const b of members) b.tabIndex = b === event.target ? 0 : -1; });
  group.addEventListener('focusout', (event) => { if (!group.contains(event.relatedTarget)) setTimeout(() => rest(group)); }); // left on a dimmed end
  group.addEventListener('keydown', (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return; // Alt+arrows: the browser's Back/Forward
    const to = groupKey(event.key, members.indexOf(event.target), members.length, keys);
    if (to < 0) return;
    event.preventDefault();
    members[to].focus();
  });
}
rove(document.querySelector('.sizes'), {});
rove($('step'), { prev: ['ArrowUp'], next: ['ArrowDown'], ends: false });
// 기본|쉬운 설명 answers the arrows as a two-way switch: either arrow picks the other view and takes the focus. Astryx
// SegmentedControl (description): "the selection slides to the new segment, whether a tap, an arrow key or a new value moved it".
$('views').addEventListener('keydown', (event) => {
  if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return; // Alt+arrows: the browser's Back/Forward
  const views = ['normal', 'easy'];
  const to = groupKey(event.key, views.indexOf(event.target.id.slice(5)), 2, { ends: false, wrap: true });
  if (to < 0) return;
  event.preventDefault();
  if (views[to] !== defaultView) setDefaultView(views[to]);
  $(`view-${views[to]}`).focus();
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
$('search').addEventListener('focus', () => {
  ensureFull().catch(() => {}); // under way before the first letter
  ensureOthers(); // the Incident counts rank the suggestions
  suggest();
});
$('search').addEventListener('blur', closeSuggest);
// Clear all (owner, 11-19: it replaced the separate 필터 모두 지우기 button; Astryx PowerSearch hasClear): shown while
// anything narrows the Board, it empties the bar and the panel's conditions and gives the field the focus back.
$('search-clear').addEventListener('click', () => {
  $('search').value = '';
  clearTimeout(typing);
  document.documentElement.classList.add('vt-search');
  update(NO_FILTER);
  $('search').focus();
});
$('search').addEventListener('input', (event) => {
  ensureFull().catch(() => {}); // typing asks again after a failure
  suggest();
  $('search-clear').hidden = !event.target.value && activeFilters() === 0;
  clearTimeout(typing);
  typing = setTimeout(() => searchTransition(event.target.value), 150);
});
// Typing redraws the Board with the same row-keeping transition, only quicker (index.html, .vt-search; owner, 11-19:
// "no animation at all when it switches"). A keystroke during one cuts it to its end: a new View Transition skips the
// running one, so nothing queues. boardTransition takes the class off when the last transition ends.
function searchTransition(query) {
  document.documentElement.classList.add('vt-search');
  update({ query });
}
// The keys of Astryx Typeahead: arrows move through the suggestions, Enter picks the one moved to (with none, the typed
// words stay the search), Escape closes the list, Backspace in an empty field takes the last token back. Never while
// an input method is still composing (Korean): its Enter and Backspace belong to the syllable.
$('search').addEventListener('keydown', (event) => {
  if (event.isComposing || event.keyCode === 229) return;
  const input = event.target;
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    if (!suggested.length) return;
    event.preventDefault();
    moveActive(event.key === 'ArrowDown' ? 1 : -1);
  } else if (event.key === 'Enter' && active >= 0) {
    event.preventDefault();
    pickEntry(suggested[active]);
  } else if (event.key === 'Escape' && suggested.length) {
    event.preventDefault();
    closeSuggest();
  } else if (event.key === 'Backspace' && !input.value && input.selectionStart === 0) {
    barTokens().at(-1)?.[2]();
  }
});
$('bar').addEventListener('click', (event) => { if (!event.target.closest('button, .sg-item')) $('search').focus(); }); // the bar's ground, its count or '+N'
window.addEventListener('resize', placePill);
document.fonts?.ready.then(placePill);
window.addEventListener('hashchange', () => {
  filter = loadFilter();
  $('search').value = filter.query;
  render();
});

const el = (tag, className = '', textContent = '') => Object.assign(document.createElement(tag), { className, textContent });
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

// An opened row's section heading (대처법, 요약, 해당 조건), as the Astryx inspector heads each group (pages/incident-console
// page.tsx: Heading over its content); h4, since the row's own button sits in an h3.
const secHead = (text) => el('h4', 'sec-head', text);

// The facts of an opened row (CVE, score, public date) as label-value pairs, after Astryx MetadataList (label column in
// Secondary Ink, value in Ink). rows: [label, [nodes or strings]].
function factList(rows) {
  const dl = el('dl', 'facts');
  for (const [label, value] of rows) {
    const dd = el('dd');
    dd.append(...value);
    dl.append(el('dt', '', label), dd);
  }
  return dl;
}

// H4 (owner, 11-16): a group's condition of some CVEs only shows their ids as a small mark before its text, like the step-4
// marks beside a CVE line (.cve-src); any other entry is its text as written.
const idMarks = (ids) => ids.flatMap((id, n) => [...(n ? [', '] : []), el('span', 'cve-src', id)]);
function condition(entry, cves) {
  const { ids, text } = conditionIds(entry, cves);
  return ids.length ? [...idMarks(ids), ' ', text] : [entry];
}

// Step 10 (owner, 11-15/16): the Distribution table under the Mitigation, folded like a group's other long lists: release
// (linking that distribution's own page for the CVE), package and state, and in a group the CVEs a line holds for when not
// all (the conditions' id mark). The credit line under it, inside the fold: each source linked, its licence where given.
function distroFold(incident) {
  const table = distroTable(incident, lang);
  if (!table) return [];
  const t = TEXT[lang];
  const linkOr = (url, text) => (/^https?:\/\//i.test(url) ? anchor(url, text, false) : text);
  const list = el('ul', 'cve-lines');
  list.append(...table.lines.map((l) => {
    const li = el('li');
    const name = el('strong');
    name.append(linkOr(l.url, l.label));
    li.append(name, l.package ? `${l.package} · ${l.state}` : l.state);
    if (l.ids.length) li.append(' ', ...idMarks(l.ids));
    return li;
  }));
  const body = el('div');
  body.append(list);
  if (table.credits.length) {
    const credits = para('credits', `${t.distroSources} `);
    table.credits.forEach((c, n) => {
      credits.append(...(n ? [' · '] : []), linkOr(c.url, c.name));
      if (c.licence) credits.append(' (', linkOr(c.licenceUrl, c.licence), ')');
    });
    body.append(credits);
  }
  const head = el('summary', '', table.title);
  head.append(el('span', 'sr-only', t.newTabAll)); // said once for the table, not after each of its links
  return [foldable(el('details', 'models'), head, body)];
}

// Normal view (critique P2, 11-19): 대처법 first and heaviest, the fixed versions under it, then what it is and when it applies.
function summary(incident) {
  const s = incident.summary[lang];
  const cves = incident.cves;
  // Owner, 11-16: four or more fixed lines as an aligned list (the Easy view draws its own, in easyAnswer).
  const table = fixTable(incident.summary);
  // Always said, so the panel always opens on what to do, even with no known fix. Beside a folded list its text spells
  // out the same versions (Microsoft: 17 of them), so it steps down a weight rather than set ten bold lines.
  const parts = [secHead(TEXT[lang].mitigation), para(table?.more ? 'mitigation listing' : 'mitigation', s.mitigation || TEXT[lang].none)];
  if (table) parts.push(...fixList(table, `normal:${incident.id}`, TEXT[lang].fixesTitle));
  parts.push(secHead(TEXT[lang].aboutHead), para('summary', s.summary));
  // One condition stays on its line; several are a list ("팩스·SMS" has its own dot, so " · " between them misread).
  if (s.conditions.length) parts.push(secHead(TEXT[lang].conditions));
  if (s.conditions.length === 1) {
    const line = para('conditions', '');
    line.append(...condition(s.conditions[0], cves));
    parts.push(line);
  }
  if (s.conditions.length > 1) {
    const list = el('ul', 'cond-list');
    list.append(...s.conditions.map((c) => { const li = el('li', ''); li.append(...condition(c, cves)); return li; }));
    parts.push(list);
  }
  return parts;
}

// Step 4: one CVE's own score (점수 대기 when the collector keeps scores per CVE but has none for it; nothing on older data,
// whose ring is the only score) and 악용 발생 with its source: the KEV catalogue, else the source reporting the attacks.
function cveMarks(incident, cve, note = true) {
  const t = TEXT[lang];
  const out = [];
  if (incident.cve_scores) {
    const score = cveScore(incident, cve);
    out.push(el('span', 'cve-src', score == null ? t.unratedWhy : `CVSS ${score.toFixed(1)}`));
  }
  const hit = cveExploit(incident, cve);
  if (hit) {
    const mark = el('span', 'cve-src');
    const a = anchor(hit.url, hit.kind === 'kev' ? t.kevSource : host(hit.url), note);
    // Astryx Link, Best Practices: "Don't: Set `label` on text links; `aria-label` prevents assistive technology from reading the actual link content."
    if (!note) a.prepend(el('span', 'sr-only', `${cve} ${t.kevReason}: `));
    mark.append(el('span', 'kev', t.kevReason), ' ', a);
    out.push(mark);
  }
  return out.flatMap((part, n) => (n ? [' · ', part] : [part]));
}

// One release's CVEs grouped into one Incident (collector: group_releases): the Normal view names what each one does,
// from the Summary's Korean/English lines, else each CVE record's own description (English) until the Summary comes.
function cveList(incident) {
  const lines = cveLines(incident, lang);
  if (!lines.length) return [];
  const item = (line) => {
    const li = el('li');
    const id = el('strong');
    id.append(anchor(cveUrl(line.cve), line.cve, false));
    li.append(id, line.text);
    const marks = cveMarks(incident, line.cve, false);
    if (marks.length) li.append(' ', ...marks);
    const own = incident.cve_links?.[line.cve] || [];
    if (own.length) {
      const src = el('span', 'cve-src');
      const many = (kind) => own.filter((l) => l.kind === kind).length > 1; // two advisories read 공지 1 · 공지 2
      const seen = {};
      own.forEach((l, n) => {
        seen[l.kind] = (seen[l.kind] || 0) + 1;
        const name = TEXT[lang].linkKind[l.kind] || host(l.url);
        const a = anchor(l.url, many(l.kind) ? `${name} ${seen[l.kind]}` : name, false);
        a.prepend(el('span', 'sr-only', `${line.cve} `)); // Astryx Link, Best Practices: "Don't: Set `label` on text links; …" (as above)
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
    out.push(foldable(fold, label, rest, (on) => { label.textContent = on ? TEXT[lang].foldLess : TEXT[lang].moreLines(lines.length - 3); }));
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
  if (cves.length > 2) {
    const head = cveHead(cves);
    p.append(el('span', '', head.id), TEXT[lang].moreCves(head.more));
  } else cves.forEach((cve, n) => p.append(...(n ? [', '] : []), el('span', '', cve)));
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
// Astryx CodeBlock: one framed block, the code in its own column and Copy a ghost button in the end column beside it
// (src/CodeBlock/CodeBlock.tsx:155-161 rootCorner, 1163 copy IconButton variant="ghost"); ours keeps the word.
const COPY_ICON = '<span class="ic" aria-hidden="true"><svg viewBox="0 0 16 16"><rect x="5.5" y="5.5" width="8" height="8" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10.5 3.5v-.5a1 1 0 0 0-1-1H3.5a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h.5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg></span>';
function commandLine(text) {
  const p = el('p', 'command');
  const code = el('code', '', text);
  const button = Object.assign(el('button', 'copy'), { type: 'button' });
  const idle = () => { button.innerHTML = COPY_ICON; button.append(el('span', '', TEXT[lang].copy)); };
  idle();
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(code.textContent);
      // A stamp: the button says 복사됨 with a check and the command lights up, then both settle back.
      stampCopied(button);
      p.classList.add('stamped');
      clearTimeout(button.settle);
      button.settle = setTimeout(() => { idle(); p.classList.remove('stamped'); }, 2000);
    } catch {
      getSelection().selectAllChildren(code); // clipboard blocked: select it for a manual copy
      // Astryx CodeBlock, Props, onCopyError: "The copy button shows a cross and is named and announced as "Failed to copy value to clipboard."" (ours: said, the selection shown)
      $('announce').textContent = TEXT[lang].copyFailed;
    }
  });
  p.append(code, button);
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
// key: the row's id in its view, so a shown fixed-version list stays shown through a redraw (fixList).
function easyAnswer(s, level, cve = '', product = '', library = false, key = '') {
  const t = TEXT[lang];
  const action = easyAction(s);
  const parts = []; // the plain sentence is already the row's second line
  // Product lines with their own fixed versions (SonicWall Gen7 7.3.4-7013, Gen8 8.2.3-8015): one line each, and the
  // long model list folded away under them. From four lines on, the aligned list (owner, 11-16).
  const fixes = usableFixes(s);
  const table = fixTable(s);
  if (table) parts.push(para('action', fixesLead(s, lang)), ...fixList(table, key));
  else if (fixes.length > 1) {
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
  return foldable(box, el('summary', '', TEXT[lang].models(models.length)), list);
}

// A folded list in an opened row opens and shuts with the row's own fold: the browser would snap it. Enter and Space on
// a summary click it, so the keyboard takes the same path. onSwitch(opening) runs at the press (a label swap).
function foldable(box, summary, body, onSwitch = () => {}) {
  summary.addEventListener('click', (event) => {
    event.preventDefault();
    const opening = !box.open || Boolean(box.dataset.closing); // clicked while closing: open again
    delete box.dataset.closing;
    onSwitch(opening);
    if (opening) {
      box.open = true;
      fold(body, true);
    } else {
      box.dataset.closing = '1';
      fold(body, false, () => { if (box.dataset.closing) box.open = false; delete box.dataset.closing; });
    }
  });
  box.append(summary, body);
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
  // The space keeps screen readers from running the two words together ("긴급!악용 발생"); flex hides it on screen.
  if (isExploited(incident)) cell.append(' ', el('small', 'why kev', (easy && TEXT[lang].kevReasonEasy) || TEXT[lang].kevReason));
  else if (pending) cell.append(' ', el('small', 'why unrated', pendingWhy(incident, TEXT[lang])));
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
  // In a group the score names the CVE it belongs to (step 4; tooltip and screen readers only, the row has no room).
  const top = scoreCve(incident);
  const named = top ? ` · ${t.scoreOf(top)}` : '';
  gauge.setAttribute('aria-label', `CVSS ${incident.cvss}${named}`); // the risk word is the one severity word
  gauge.style.setProperty('--fill', Math.min(incident.cvss, 10) / 10);
  gauge.innerHTML = '<svg viewBox="0 0 40 40" aria-hidden="true"><circle class="track" cx="20" cy="20" r="17" pathLength="1"/><circle class="arc" cx="20" cy="20" r="17" pathLength="1"/></svg>';
  gauge.title = `CVSS ${incident.cvss.toFixed(1)}${named}`;
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
  const product = firstProduct(incident, lang);
  // Inside a vendor fold the title names that vendor (critique 14: "Langflow OSS …" in the IBM fold).
  const led = (title) => (vendor ? vendorLedTitle(title, vendor, product) : title);
  const named = (title) => led(namedHeadline(easyTitle(title, riskLevel(incident)), [product, firstProduct(incident, lang === 'ko' ? 'en' : 'ko')].filter(Boolean)));
  if (defaultView === 'easy' && s?.title) {
    name.append(s.easy_title ? named(s.easy_title) : led(s.title)); // Summaries made before 11-08 have no easy_title
    line.append(...keepIds(easyLine(s.easy || s.summary, riskLevel(incident))));
    line.classList.add('say');
  } else if (defaultView === 'easy' && !s?.title) {
    const quick = incident.quick_title?.[lang]?.easy_title;
    // No quick title and no Product to name: the source's own line, not a blank "새 보안 문제" (critique 10).
    name.append(quick ? named(quick) : product ? t.easyBrief(product) : Object.assign(el('span', '', incident.brief.text), { lang: 'en' }));
    // A Summary that failed for good is not "coming": the row says the source is all there is. Plain hint words in the
    // line under the title, not a square tag that reads like 묶음 / 함께 공개 (critique 13).
    line.append(briefMarker(incident) === 'unavailable' ? t.origOnly : t.easyPrepTag);
  } else {
    // Both views lead with what happened (owner, 11-09): the CVE ID is the line under it.
    name.append(...describe(incident).map((part) => (typeof part === 'string' ? led(part) : part)));
    line.append(id);
  }
  cell.append(name, line);
  return cell;
}

// A Product's line badge, in the fixed colour of the name it shows (nameLine), so one name is one colour on every
// screen. Callers still pass the Product id as a second argument; it no longer decides the colour.
function lineBadge(name) {
  // A long name wraps inside the pill, never cut (critique 12); the title repeats it on hover.
  const badge = Object.assign(el('span', 'ln'), { title: name });
  badge.append(el('span', 'ln-t', name));
  const { bg, ink } = nameLine(name);
  badge.style.setProperty('--line', bg);
  badge.style.setProperty('--line-ink', ink);
  return badge;
}

// An operating system the software runs on: an outline, not a line colour, so it never reads as the Product.
// Screen readers hear "(OS)" once, after the last one ("Windows macOS Linux (OS) Perl"); sighted readers see the outline.
const osBadge = (name, last = true) => {
  // the same inner label as a line badge, so a closed row can end a long name with "…" (the title gives it whole)
  const badge = Object.assign(el('span', 'ln os'), { title: name });
  badge.append(el('span', 'ln-t', name));
  if (last) badge.append(el('span', 'sr-only', ' (OS)'));
  return badge;
};

// A release group (more than two CVEs fixed together) or a vendor fold: one row standing for several Incidents.
const isGroup = (incident) => (incident.cves?.length || 0) > 2;
// Its tag leads the badge cell: a square-cornered outline in ink, so it never reads as a Product (filled pill) or an
// OS (outlined pill).
// Each kind of group has its own colour, on its tag and its frame's band (owner, 11-16): CSS .grp-fold and .grp-patch.
const groupTag = () => el('span', 'grp grp-fold', TEXT[lang].groupTag);
// A release group is one Incident (CVEs fixed by one update), not a fold: its own word, so 묶음 풀기 leaves it alone without contradiction.
const patchTag = () => el('span', 'grp grp-patch', TEXT[lang].patchTag);

function tagsCell(incident) {
  const cell = el('span', 'c-tags');
  if (isGroup(incident)) cell.append(patchTag(), ' ');
  const os = new Set(rowPlatforms(incident));
  const keys = lineKeys(incident, lang);
  // Past five tags the row shows four and says how many more (foldTags); opened, the panel's top takes them over (p-side).
  const { shown: names, more } = foldTags(rowTags(incident, lang));
  const lastOs = names.findLastIndex((name) => os.has(name));
  // Spaces between badges keep screen readers from running the names together; the flex row hides them.
  names.forEach((name, n) => cell.append(...(n ? [' '] : []), os.has(name) ? osBadge(name, n === lastOs) : lineBadge(name, keys.get(name))));
  if (more) cell.append(' ', el('span', 'tag-more', TEXT[lang].tagsMore(more)));
  return cell;
}

const relativeFormats = {}; // one per language: making one per row cost ~17 ms of a redraw at 4x CPU
const relativeFormat = (code) => (relativeFormats[code] ||= new Intl.RelativeTimeFormat(code, { numeric: 'always' }));
// "2시간 전" / "2 hours ago"; the date from 30 days on.
function ago(iso) {
  const age = relativeAge(iso, Date.now());
  return age ? relativeFormat(lang).format(age.value, age.unit) : iso.slice(0, 10);
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
  time.append(el('span', '', localDay(at)), ' ', el('span', '', incident.published ? clock : TEXT[lang].firstSeenAt(clock)));
  time.title = `${incident.published ? TEXT[lang].published : TEXT[lang].firstSeen} · ${ago(at)}`;
  return time;
}

// Both views end with the Lead and every Mention, so links a CVE record gains later show up in either.
// Critique P2 (11-19): what to do comes first in both views. The Normal panel keeps its small ID, score and date lines on
// top as a header strip; the Easy panel opens on the red line and the action, and keeps those identifiers at its foot.
// Since 11-19 (owner) both open on the row's ring and tags, moved down from the header (p-side).
function details(incident, onStrip = false) {
  const t = TEXT[lang];
  const easy = defaultView === 'easy';
  const body = !incident.summary ? briefNote(incident) : easy ? easyPanel(incident) : summary(incident);
  const head = [];
  // N1 (owner, 11-15): the CVE the visitor searched for, when it is not the Lead, gets one line on top of the card: its
  // own line, score and whether it is attacked. Title and Summary stay the Incident's.
  const searched = searchedCve(filter.query, incident, lang);
  if (searched) {
    const line = para('why-line', `${t.searched(searched.cve)}:`);
    if (searched.text) line.append(' ', searched.text);
    const marks = cveMarks(incident, searched.cve);
    if (searched.exploited === false) marks.push(...(marks.length ? [' · '] : []), t.notExploited);
    if (marks.length) line.append(' · ', ...marks);
    head.push(line);
  }
  const facts = [];
  // Every Incident with a CVE has the same line, as the row header writes it ("CVE-… 외 212건"), so it can be copied
  // (owner, 11-10: the line came and went by count); the full list stays in the fold.
  if (incident.cves.length) facts.push([t.cveHead, [...idLine(incident.cves).childNodes]]);
  // The group's score with the CVE it belongs to (step 4), in both views. A score a page raised shows both standards'
  // scores there instead (owner 11-18), one-CVE Incidents too: "CVSS 4.0 9.2 / CVSS 3.1 8.1 · CVE-…".
  // Owner 11-19: every scored row shows its score here, one-CVE rows too.
  const top = scoreCve(incident);
  const pair = scorePair(incident);
  if (pair || Number.isFinite(incident.cvss)) facts.push([t.scoreHead, keepIds([pair || `CVSS ${incident.cvss.toFixed(1)}`, top].filter(Boolean).join(' · '))]);
  // M4 (owner, 11-15): the Lead CVE's Public date, when it is not the day of the Published time.
  if (publicDay(incident)) facts.push([t.publicDate, [publicDay(incident)]]);
  // A Brief has no plain sentence to lead with, so its identifiers stay on top in both views (critique 14).
  const idsAtFoot = easy && Boolean(incident.summary);
  // Why the row is 악용 발생 (critique 14): the KEV listing, else the source that reports the attacks. A Highlight's strip
  // already says "CISA KEV 등재 <day>" (evidenceCell), so its panel does not say it again unless it names the attacked CVEs
  // of a group; a reporting source stays, as the strip has no link. With the facts on top it is one of them (공격 발생).
  const reason = exploitReason(incident);
  const hit = reason && incident.cves.length > 1 ? exploitedCves(incident) : [];
  let why = null;
  if (reason && !(onStrip && reason.kind === 'kev' && !hit.length)) {
    why = para('why-line', reason.kind === 'kev' ? t.kevListed : idsAtFoot ? `${t.attackSource} ` : '');
    if (reason.kind === 'kev' && reason.date) why.append(' · ', el('span', 'nw', reason.date)); // the day never breaks at its hyphens
    if (reason.kind === 'source') why.append(anchor(reason.url, host(reason.url)));
    // In a group, which CVEs are attacked (step 4: the KEV listing and the Summary name them; older data names none).
    if (hit.length) why.append(' · ', ...hit.flatMap((cve, n) => [...(n ? [', '] : []), el('span', 'nw', cve)]));
    if (!idsAtFoot) facts.push([reason.kind === 'kev' ? t.kevReason : t.attackSource.replace(/[:：]\s*$/, ''), [...why.childNodes]]);
  }
  // A provisional level (owner, 11-19): the sign says "제조사 등급" (11-20); here the sentence with the advisory's link, as the
  // attack source is shown ("제조사 등급: Critical · <host>").
  const rated = provisionalLevel(incident) ? incident.summary.severity_source : '';
  let vendorLine = null;
  if (rated) {
    vendorLine = para('why-line', idsAtFoot ? `${t.vendorRating}: ` : '');
    vendorLine.append(`${severityWord(incident)} · `, anchor(rated, host(rated)));
    if (!idsAtFoot) facts.push([t.vendorRating, [...vendorLine.childNodes]]);
  }
  const ids = facts.length ? [factList(facts)] : [];
  // Owner 11-19: opening a row moves its ring and tags from the header down into the panel's top, the tags as working
  // filters, so no one scrolls past a long panel to pick one; they travel there with the fold (carry). They stand straight
  // under their header places from 768px (index.html .p-top), beside the facts; the Easy view's facts sit at its foot.
  const side = el('div', 'p-side');
  side.append(scoreCell(incident));
  const tags = tagLine(incident);
  if (tags.length) {
    const products = el('div', 'p-prod');
    products.append(el('span', 'p-label', t.tagsHead), ...tags);
    side.append(products);
  }
  const block = el('div', 'p-top');
  block.append(...(idsAtFoot ? [] : ids), side);
  head.push(block);
  if (easy && isExploited(incident)) head.push(para('kev', t.kevEasy));
  if (why && idsAtFoot) head.push(why);
  if (vendorLine && idsAtFoot) head.push(vendorLine);
  // Public exploit code without reported attacks: no sign, a red line (owner, 2026-11-09); in the Easy view over the
  // action with the other red line, in the Normal view after the summary sentence, as before, so 대처법 still leads.
  if (incident.summary?.poc_public === true && !isExploited(incident)) {
    if (easy) head.push(para('kev', t.pocEasy));
    else body.splice(body.findIndex((n) => n.classList.contains('summary')) + 1, 0, para('kev', t.poc));
  }
  const parts = [...head, ...body];
  // M1 (owner, 11-15): under the answer, the Board filtered to the row's first Product when it had other Incidents
  // in the last 30 days; same tab, as the address is this page's own filter.
  ensureOthers();
  const elsewhere = productOthers(incident, lang, productCounts);
  if (elsewhere) {
    const line = para('others', '');
    line.append(Object.assign(el('a', '', t.productOthers(elsewhere.n)), { href: elsewhere.hash }));
    parts.push(line);
  }
  if (!easy) parts.push(...distroFold(incident)); // Normal view only (owner, 11-16)
  const list = easy ? [] : cveList(incident); // every CVE's issue in the Normal view (user, 2026-11-09)
  // "CVE 3건" opens to every ID, each linked to its CVE record (owner, 11-09). Both views show the IDs as text:
  // the row is a button, and browsers do not let a drag select text inside one (owner, 11-10: "CVE를 긁을 수가 없어").
  const cveFold = [];
  if (incident.cves.length > 2) {
    const fold = el('details', 'models cve-fold');
    const all = el('ul', '');
    for (const cve of incident.cves) {
      const li = el('li', '');
      li.append(anchor(cveUrl(cve), cve, false));
      all.append(li);
    }
    const label = el('summary', '', t.cveCount(incident.cves.length));
    label.append(el('span', 'sr-only', t.newTabAll));
    cveFold.push(foldable(fold, label, all));
  }
  if (idsAtFoot) {
    const foot = el('div', 'id-foot');
    foot.append(...ids, ...cveFold);
    if (foot.childElementCount) parts.push(foot);
  } else parts.push(...cveFold);
  const mentions = el('ul', 'mentions');
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
  const linkedAbove = incident.cves.length > 2; // a group links each CVE record from its CVE list
  // Step 4 (owner, 11-15: 347 group links were shown nowhere): an advisory or write-up is left out only when a drawn CVE
  // line links it; the Easy view draws none.
  const onLines = new Set(easy ? [] : cveLines(incident, lang).flatMap((l) => (incident.cve_links?.[l.cve] || []).map((x) => x.url)));
  const listed = incident.mentions.filter((m) => !((linkedAbove && m.kind === 'cve_record') || (['advisory', 'writeup'].includes(m.kind) && onLines.has(m.url))));
  // A kind with more links than MENTIONS_SHOWN folds into one line (mentionGroups). Inside, an untitled link is named by the
  // last part of its address (GHSA-xxxx) when its site repeats there, else by its site.
  for (const { kind, list, sites, fold } of mentionGroups(listed)) {
    const label = t.mentionKinds[kind] ?? kind;
    if (!fold) {
      for (const m of list) {
        const item = el('li', '');
        item.append(`${label}: `, linkOf(m, host(m.url)));
        mentions.append(item);
      }
      continue;
    }
    const inner = el('ul', '');
    for (const m of list) {
      const li = el('li', '');
      const repeats = list.filter((x) => host(x.url) === host(m.url)).length > 1;
      li.append(linkOf(m, (repeats && lastPart(m.url)) || host(m.url)));
      inner.append(li);
    }
    const item = el('li', '');
    item.append(foldable(el('details', 'models'), el('summary', '', t.mentionsMany(label, sites, list.length)), inner));
    mentions.append(item);
  }
  return [...parts, leadLine(incident), ...list, mentions, shareLine(incident)];
}

// The opened row's 제품 line (owner, 11-10; at the panel's top since 11-19): each tag as a button that adds its Product or OS to the
// picks (or takes it out again), or searches a device name; only here, since the closed row is one button already.
// A release group's 함께 공개 leads it as on the row, as a mark, not a button.
// Past five tags the line shows four and a 나머지 N개 보기 toggle that opens the rest in place (foldTags); a pressed tag
// always shows with the first ones, so a filter in force is never folded away. Opened lines stay open through a redraw.
const openTagLines = new Set();
function tagLine(incident) {
  const t = TEXT[lang];
  const tags = tagFilters(incident, lang);
  if (!tags.length) return [];
  const line = el('div', 'tag-line');
  if (isGroup(incident)) line.append(patchTag());
  const isPicked = (tag) => Boolean(tag.pick) && filter.picks.includes(tag.pick);
  const folded = new Set(tags.slice(foldTags(tags).shown.length).filter((tag) => !isPicked(tag)));
  const rest = [];
  tags.forEach((tag, n) => {
    const button = Object.assign(el('button', 'tag-btn'), { type: 'button' });
    button.dataset.n = n;
    button.append(tag.kind === 'os' ? osBadge(tag.name, false) : lineBadge(tag.name, tag.pick));
    button.setAttribute('aria-label', t.tagOnly(tag.name));
    const picked = isPicked(tag);
    if (tag.pick) button.setAttribute('aria-pressed', picked);
    button.addEventListener('click', () => {
      if (!tag.pick) $('search').value = tag.query;
      const drawn = tag.pick ? update({ picks: picked ? filter.picks.filter((p) => p !== tag.pick) : [...filter.picks, tag.pick] })
        : update({ query: tag.query });
      // The redrawn row keeps the focus on the same tag (folded away again: on the toggle); gone from the list, the
      // first row or the Board's head takes it.
      drawn.then(() => {
        const li = [...document.querySelectorAll('li[data-ids]')].find((x) => x.dataset.ids === incident.id);
        (li?.querySelector(`.tag-btn[data-n="${n}"]:not([hidden])`) || li?.querySelector('.tag-toggle') || $('highlights').querySelector('button.row')
          || $('board').querySelector('button.row') || $('board-start')).focus({ preventScroll: true });
      });
    });
    if (folded.has(tag)) rest.push(button);
    else line.append(button);
  });
  if (rest.length) {
    const toggle = Object.assign(el('button', 'tag-toggle'), { type: 'button' });
    const show = (on) => {
      toggle.setAttribute('aria-expanded', on);
      toggle.textContent = on ? t.foldLess : t.tagsRest(rest.length);
      for (const button of rest) button.hidden = !on;
    };
    let fades = [];
    toggle.addEventListener('click', () => {
      const on = !openTagLines.has(incident.id);
      if (on) openTagLines.add(incident.id);
      else openTagLines.delete(incident.id);
      // The line moves its height as fold() does, so the rows below glide; a press mid-way turns it from where it stands.
      const from = line.getBoundingClientRect().height;
      line.folding?.cancel();
      fades.forEach((a) => a.cancel());
      show(on); // the focus stays on the toggle
      if (reducedMotion.matches) return;
      const to = line.getBoundingClientRect().height;
      for (const button of rest) button.hidden = false; // closing: they fade inside the shrinking line, hidden at the end
      const timing = { duration: on ? 300 : 240, easing: FOLD_EASE };
      line.style.overflow = 'hidden';
      line.folding = line.animate([{ height: `${from}px` }, { height: `${to}px` }], timing);
      fades = rest.map((button) => button.animate([{ opacity: on ? 0 : 1 }, { opacity: on ? 1 : 0 }], timing));
      line.folding.onfinish = () => {
        line.style.overflow = '';
        line.folding = null;
        show(on);
      };
    });
    show(openTagLines.has(incident.id));
    line.append(toggle, ...rest);
  }
  return [line];
}

let rowCount = 0;

// Owner, 11-16: the Summary's fixed versions from four lines on, one dt/dd pair per line in one grid, so the versions line
// up. Critique P2 (11-19): past FIXES_SHOWN lines the whole list folds under the panel's one action, with the panel's own
// fold motion; whether it is open is kept by row and view (key) through every redraw.
const openFixLists = new Set();
function fixList(table, key, head = '') {
  const t = TEXT[lang];
  const list = el('dl', 'fix-list');
  for (const f of table.rows) list.append(el('dt', '', f.for), el('dd', '', t.orNewer(f.version)));
  if (!table.more) return [...(head ? [para('fix-head', head)] : []), list];
  const box = Object.assign(el('details', 'models fix-fold'), { open: openFixLists.has(key) });
  const label = el('summary', '', t.fixesFold(table.rows.length));
  return [foldable(box, label, list, (on) => { if (on) openFixLists.add(key); else openFixLists.delete(key); })];
}

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
  const gravest = members.toSorted((a, b) => RISKS.indexOf(riskLevel(a)) - RISKS.indexOf(riskLevel(b)))[0];
  const top = members.toSorted((a, b) => (b.cvss || 0) - (a.cvss || 0))[0];
  const newest = foldNewest(group);
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
  const products = uniqueNames(members.map((i) => firstProduct(i, lang)).filter(Boolean).map((n) => (wp ? pluginName(n) : n)));
  title.append(el('strong', 'title', foldTitle),
    el('small', 'sub', products.slice(0, 3).join(', ') + (products.length > 3 ? ` ${t.moreProducts(products.length - 3)}` : '')));
  const tags = el('span', 'c-tags');
  // Product names are never translated. A vendor named like an OS ("Linux") keeps the OS outline its name has on every row.
  tags.append(groupTag(), ' ', OSES.includes(vendor) ? osBadge(vendor, false) : lineBadge(wp ? 'WordPress' : vendor));
  const chevron = el('i', 'chev');
  chevron.setAttribute('aria-hidden', 'true');
  button.append(riskCell(gravest), title, scoreCell(top), tags, dateCell(newest), chevron);
  const foldRow = () => document.querySelector(`button.row[data-fold="${CSS.escape(group.fold)}"]`);
  const key = `fold:${group.fold}`; // held like a row (holdRow), by the name its li carries
  const placeOf = () => foldRow()?.closest('li').getBoundingClientRect().top;
  const toggle = (closing) => {
    const top = placeOf();
    if (closing) {
      const body = foldRow()?.closest('li').querySelector(':scope > .fold-body');
      const back = held?.key === key;
      if (back) {
        Object.assign(held, { ms: 240, back: true, at: performance.now(), from: top });
        holdRow();
      }
      const done = () => {
        const was = placeOf();
        openFolds.delete(group.fold);
        render();
        clearTimeout(announcing);
        $('announce').textContent = t.foldClosed(vendor);
        foldRow()?.focus({ preventScroll: true });
        const now = placeOf();
        if (was !== undefined && now !== undefined) scrollBy(0, now - was); // the redraw's shift (holdRow)
        if (!back) foldRow()?.scrollIntoView({ block: 'nearest' }); // closed from the bottom: bring the row back into view
      };
      return body ? fold(body, false, done) : done();
    }
    openFolds.add(group.fold);
    render();
    const body = foldRow()?.closest('li').querySelector(':scope > .fold-body');
    foldRow()?.focus({ preventScroll: true });
    held = { key, top, from: top, ms: 300, still: true, at: performance.now() };
    holdRow();
    if (body) {
      fold(body, true, () => { if (held?.key === key) holdRow(); });
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


// A Highlight's header strip says in a few words why it is 공격 발생; the link stays in the panel (the row is a button).
function evidenceCell(incident) {
  const reason = exploitReason(incident);
  if (!reason) return null;
  const t = TEXT[lang];
  return el('small', 'c-ev', reason.kind === 'kev' ? [t.kevListed, reason.date].filter(Boolean).join(' ') : t.reportedBy(host(reason.url)));
}

// Owner 11-19, 11-21: opening or closing a row carries its ring and tags between the header and the panel's top as one
// motion with the fold (same duration and curve). A ghost, a copy of the header's (the panel clips its own while it
// folds), travels inside the row while the real copies are held invisible by animations, so a finish or a cancel leaves
// no trace. The ring travels whole and hands over on landing, on phones too (owner 11-21: "원도 똑같이 움직여야지", which
// ends 11-19's phone cross-fade). The tags move one by one (FLIP, Paul Lewis, aerotwist.com/blog/flip-your-animations):
// each pill of the ghost line slides from where it is seen to its own place in the other line, matched by name, so none
// blinks; a piece only one line has (외 N개, 나머지 N개 보기, a tag past the header's four) fades out early or in late,
// and a pill whose size differs (a name the header cut with "…") cross-fades with its real copy at the far end.
// Not a View Transition (Chrome's modern-web-guidance, same-document and scoped-component transitions): it draws
// snapshots on an overlay over the root, where "any animations will appear to be paused" (the fold, the scroll glide in
// holdRow); the overlay blocks pointer events, so a click could not turn the row round mid-way; one runs at a time (the
// Board's redraws use it); and Element.startViewTransition, scoped to the row, is Chrome 147+ only.
// Reduced motion: no travel, a 200ms cross-fade. starts: where each piece is seen before the change (in its ghost when a
// click turns it round mid-way), from carryStarts.
// The header's ring and tags and the panel's, by index (0 ring, 1 tags); null where one is missing.
function carryParts(button, body) {
  const side = body.querySelector(':scope > .p-top > .p-side');
  return [[button.querySelector(':scope > .c-score'), side?.querySelector(':scope > .c-score')],
    [button.querySelector(':scope > .c-tags'), side?.querySelector('.tag-line')]];
}
// A tag line's shown pieces (a tag button by its pill, which is what both lines show) and the name that pairs them.
const carryPieces = (line) => [...(line?.children || [])].filter((x) => x.getClientRects().length).map((x) => (x.matches('.tag-btn') ? x.firstElementChild : x));
const pieceKey = (x) => x.querySelector(':scope > .ln-t')?.textContent ?? x.className;
function carryStarts(button, body, flights, opening) {
  const [[ring, ringThere], [tags, line]] = carryParts(button, body);
  // a ghost still in flight is where its copy is seen; one that has landed is gone from the page
  const flying = (n) => flights[n]?.ghost.isConnected && flights[n].ghost;
  const pieces = [...carryPieces(opening ? tags : line), ...(flying(1) ? flying(1).children : [])];
  return [(flying(0) || (opening ? ring : ringThere))?.getBoundingClientRect(),
    { box: tags?.getBoundingClientRect(), pieces: new Map(pieces.map((x) => [pieceKey(x), x.getBoundingClientRect()])) }];
}
function carry(li, button, body, opening, starts, flights) {
  flights.forEach((f) => f?.stop());
  const [[ring, ringThere], [tags, line]] = carryParts(button, body);
  if (!ringThere) return []; // no group in the panel (a row still loading): the header keeps its own
  const box = li.getBoundingClientRect();
  const still = reducedMotion.matches;
  const timing = { duration: still ? 200 : opening ? 300 : 240, easing: still ? EASE_OUT : FOLD_EASE, fill: 'forwards' };
  const runs = [];
  const ghosts = [];
  // Every box is read before anything is written: the animations start together at the end (play) and the ghosts are
  // placed once, as each write between two reads made the browser restyle and lay out the row again (a group's dozen
  // pills, a dozen layouts in the tap's frame).
  const plays = [];
  const play = (x, keys) => plays.push([x, keys]);
  // opacity frames as [offset, value]; offsets are of the eased way, so "late" is near the landing place
  const fade = (x, ...frames) => play(x, frames.map(([offset, opacity]) => ({ offset, opacity })));
  const move = ([x, y]) => `translate(${x}px, ${y}px)`;
  const ghostOf = (x, at) => {
    const ghost = x.cloneNode(true);
    for (const y of [ghost, ...ghost.querySelectorAll('[id]')]) y.removeAttribute('id');
    ghost.classList.add('ghost');
    ghost.setAttribute('aria-hidden', 'true');
    Object.assign(ghost.style, { left: `${at.left - box.left}px`, top: `${at.top - box.top}px`, width: `${x.getBoundingClientRect().width || at.width}px`, fontSize: getComputedStyle(x).fontSize });
    return ghost;
  };
  let placed = false;
  const place = () => { // the ghosts' frame, then the ghosts, once
    if (placed) return;
    placed = true;
    li.classList.add('carrying');
    li.append(...ghosts.filter(Boolean));
  };
  const a = starts[0];
  if (ring?.childElementCount && a?.width) {
    const b = (opening ? ringThere : ring).getBoundingClientRect();
    ghosts[0] = ghostOf(ring, a);
    play(ghosts[0], [{ transform: 'none', opacity: 1 }, { transform: still ? 'none' : move([b.left - a.left, b.top - a.top]), opacity: still ? 0 : 1 }]);
    fade(opening ? ring : ringThere, [0, 0], [1, 0]);
    fade(opening ? ringThere : ring, [0, 0], [1, still ? 1 : 0]);
  }
  const { box: was, pieces: seen } = starts[1];
  if (tags?.childElementCount && line && (!opening || was?.width)) {
    // the ghost line stands at the header's place (gone from the layout once open on narrow screens: where it was)
    const ghost = ghostOf(tags, opening ? was : tags.getBoundingClientRect());
    ghosts[1] = ghost;
    place(); // the pills' own places are read from the ghost line below
    const panel = new Map(carryPieces(line).map((x) => [pieceKey(x), x]));
    const same = (p, q) => Math.abs(p.width - q.width) < 1 && Math.abs(p.height - q.height) < 1;
    const shows = new Map(); // a paired pill's ghost seen at the start and at the end (0: its real copy is, cross-fading)
    // Closing below 1024px the header's line comes back into the layout and pushes the panel down in the click's frame:
    // what the panel shows of its own then goes at once rather than step down (the pills fly from where they were seen).
    const pushed = !opening && !was?.width;
    let way = [[0, 0], [0, 0]]; // the last pill's travel: a piece only the header has goes along with it
    [...ghost.children].forEach((g, n) => {
      const key = pieceKey(g);
      const home = g.getBoundingClientRect();
      const now = seen.get(key);
      const there = panel.get(key)?.getBoundingClientRect();
      const off = (r) => [r.left - home.left, r.top - home.top];
      const from = now ? off(now) : way[0];
      const to = opening ? (there ? off(there) : way[1]) : [0, 0];
      let frames;
      if (there) {
        way = [from, to];
        const ends = [now && (pushed || same(now, home)) ? 1 : 0, opening && !same(there, home) ? 0 : 1];
        shows.set(key, ends);
        frames = still ? [[0, ends[0]], [1, 0]] : [[0, ends[0]], [0.1, 1], [0.9, 1], [1, ends[1]]];
      } else if (opening) frames = still ? [[0, 1], [1, 0]] : [[0, 1], [0.4, 0], [1, 0]];
      else frames = still ? [[0, 0], [1, 0]] : [[0, 0], [0.6, 0], [1, 1]];
      const keys = frames.map(([offset, opacity]) => ({ offset, opacity }));
      keys[0].transform = move(from);
      keys.at(-1).transform = move(still ? from : to);
      play(g, keys);
      if (!opening) fade(tags.children[n], [0, 0], [1, still ? 1 : 0]); // the header's own shows when the ghost lands
    });
    // the panel's own: held while its ghost is seen, else shown late (opening) or gone early (closing)
    for (const [key, x] of panel) {
      const ends = shows.get(key);
      if (still) fade(x, [0, opening ? 0 : 1], [1, opening ? 1 : 0]);
      else if (ends?.[opening ? 1 : 0]) fade(x, [0, 0], [1, 0]);
      else if (opening) fade(x, [0, 0], [ends ? 0.9 : 0.6, 0], [1, 1]);
      else fade(x, [0, pushed ? 0 : 1], [ends ? 0.1 : 0.4, 0], [1, 0]);
    }
    // What stands in the pills' way shows once they have passed it and goes before they come: the line's 제품 label, and
    // below 1024px, where the header's line sits above the facts and the panel's under them, the facts.
    const label = line.parentElement.querySelector(':scope > .p-label');
    const facts = line.closest('.p-top').querySelector(':scope > .facts');
    const [f, l, h] = [facts, line, ghost].map((x) => x?.getBoundingClientRect());
    const crossed = f && f.top < Math.max(l.top, h.top) && f.bottom > Math.min(l.top, h.top) && f.left < l.right && f.right > l.left;
    if (!still) for (const [x, go] of [[label, 0.1], [crossed && facts, 0.15]]) if (x) fade(x, ...(opening ? [[0, 0], [0.9, 0], [1, 1]] : [[0, pushed ? 0 : 1], [go, 0], [1, 0]]));
  }
  place();
  for (const [x, keys] of plays) runs.push(x.animate(keys, timing));
  const stop = () => {
    runs.forEach((r) => r.cancel());
    ghosts.forEach((g) => g?.remove());
    if (!li.querySelector(':scope > .ghost')) li.classList.remove('carrying');
  };
  if (!runs.length) return stop() || [];
  runs[0].onfinish = stop;
  return ghosts.map((ghost) => ghost && { ghost, stop });
}

// One board row: a button that opens the details below it, like opening a post. A Highlight is one alert of the
// 주요 사건 band: a header strip (risk sign, 공격 발생 and its evidence, time, chevron) over its title, ring and badges.
function row(incident, pinned, vendor = '') {
  const li = el('li', pinned ? `alert risk-${riskLevel(incident)}` : isGroup(incident) ? 'grouped' : '');
  li.dataset.ids = incident.id;
  if (fresh.has(incident.id)) li.classList.add('fresh');
  // A Highlight's list copy keys apart (rowKey): its own open state and transition name, never a duplicate.
  const key = rowKey(incident, highlightedNow, pinned);
  // A Highlight in the list says so in words under its sign (critique P2, 11-19: no edge, so a row never wears two).
  const marked = !pinned && highlightedNow.has(incident);
  li.dataset.vt = rowName(key); // boardTransition names it: the same row before and after a redraw
  const body = Object.assign(el('div', defaultView === 'easy' ? 'details easy' : 'details'), { id: `details-${++rowCount}`, hidden: !open.has(key) });
  const button = Object.assign(el('button', 'row'), { type: 'button' });
  button.setAttribute('aria-controls', body.id);
  button.setAttribute('aria-expanded', !body.hidden);
  const chevron = el('i', 'chev');
  chevron.setAttribute('aria-hidden', 'true');
  const risk = riskCell(incident);
  const why = pinned && pinReason(incident);
  if (why) risk.append(el('small', 'why', TEXT[lang].why[why]));
  if (marked) risk.append(' ', el('small', 'why pin', TEXT[lang].pinOne)); // part of the row's name, read after its level
  const ev = pinned && evidenceCell(incident);
  const cells = { risk, title: titleCell(incident, vendor), score: scoreCell(incident), tags: tagsCell(incident), date: dateCell(incident), ...(ev ? { ev } : {}) };
  for (const [k, cell] of Object.entries(cells)) cell.id = `${body.id}-${k}`;
  cells.title.querySelector('.title').id = `${body.id}-name`;
  cells.title.querySelector('.sub').id = `${body.id}-sub`;
  // Screen readers hear the bold title and risk as the row's name, the rest as its description, not one long name.
  button.setAttribute('aria-labelledby', `${body.id}-name ${body.id}-risk`);
  button.setAttribute('aria-describedby', `${body.id}-sub ${ev ? `${body.id}-ev ` : ''}${body.id}-score ${body.id}-tags ${body.id}-date`);
  if (pinned) {
    const strip = el('span', 'strip');
    strip.append(cells.risk, ...(ev ? [ev] : []), cells.date, chevron);
    button.append(strip, cells.title, cells.score, cells.tags);
  } else button.append(cells.risk, cells.title, cells.score, cells.tags, cells.date, chevron);
  // Details are built when a row first opens: every closed row's hidden details made 62% of the page's elements, and
  // a phone took half a second to redraw them on a view switch (owner, 2026-11-10).
  // A row view (rows.json) has no details: a loading line until ensureFull redraws the Board with the full Incident, the
  // load error if that fails; after a failure a redraw shows the error and only opening the row asks again (owner, 11-10).
  const fill = (asked = false) => {
    if (!incident.rows) return body.childElementCount || body.append(...details(incident, Boolean(ev)));
    if (fullFailed && !asked) return body.replaceChildren(errorBanner());
    body.replaceChildren(para('preparing', TEXT[lang].loading));
    ensureFull().catch(() => { // Astryx Banner, Best Practices: "Announce async outcomes from the transition handler with useAnnounce."
      body.replaceChildren(errorBanner());
      $('announce').textContent = TEXT[lang].loadError;
    });
  };
  let flights = []; // the ring and tags in flight between the header and the panel (carry)
  button.addEventListener('click', () => {
    const opening = !open.has(key);
    const top = li.getBoundingClientRect().top; // where the row stood, to go back to on close (held)
    // Where the ring and tags are seen now and how tall the header is, before the change moves them.
    const starts = carryStarts(button, body, flights, opening);
    const before = heading.offsetHeight;
    button.setAttribute('aria-expanded', opening);
    if (opening) {
      open.add(key);
      fill(true);
      body.hidden = false;
    } else open.delete(key);
    const shift = Math.max(0, opening ? before - heading.offsetHeight : heading.offsetHeight - before);
    flights = carry(li, button, body, opening, starts, flights);
    // the row is held after every box above was read (a ghost flies from where its copy was seen) and before the panel
    // folds, whose full height says whether it fits; once the panel is out it is brought up again, as a row near the
    // Board's end could not rise while the panel was still short
    // closing goes back by the row, not the old scrollY: a row above that changed meanwhile would leave this one elsewhere
    if (opening || held?.key === key) {
      held = opening ? { key, top, ms: 300, still: true } : { ...held, ms: 240, back: true };
      Object.assign(held, { at: performance.now(), from: li.getBoundingClientRect().top });
      holdRow();
    }
    if (opening) foldOrFade(body, true, () => { if (held?.key === key) holdRow(); }, shift);
    else foldOrFade(body, false, () => { body.hidden = !open.has(key); }, shift); // reopened mid-way: stay open
  });
  if (!body.hidden) fill();
  const heading = el('h3', 'row-h');
  heading.append(button);
  li.append(heading, body);
  return li;
}

main();
