import { LINK_KINDS, OSES, PINNED, RISKS, SORTS, pinReason, briefMarker, cveHead, easyLine, easyTitle, isShellCommand, MANY_DEVICES, onBoard, cvssRating, easyAction, filterBoard, isExploited, lineKeys, orderBy, filterFromQuery, filterToQuery, productLine, productList, publishedAt, relativeAge, riskLevel, rowTags, viewFromStorage } from './board.mjs';

// The store's base URL. Locally the collector writes into web/data/; ticket 02 points this at R2.
const DATA_URL = 'data/';
const SAVED = 'vr-filter';
const SAVED_LANG = 'vr-lang';
const SAVED_VIEW = 'vr-view';
// Also read by the inline script in index.html's head, so the remembered theme applies before first paint.
const SAVED_THEME = 'vr-theme';
// Every UI string, per language: the visitor's toggle, else the browser's language.
// Only CVE IDs, Product names, URLs and source data (the Brief's own line, Mention titles) are shown as they come.
// The NVD notice keeps its required English sentence in index.html; `nvd` is the Korean line beside it.
const TEXT = {
  ko: {
    other: 'English', otherShort: 'EN', title: 'vuln-radar · 보안 취약점 게시판', loading: '불러오는 중…',
    notListed: (text) => `제품 목록에 없는 이름이라 검색어로 찾았어요: ${text}`,
    loadError: (msg) => `게시판을 불러오지 못했습니다. 인터넷 연결을 확인하고 다시 시도하세요. (${msg})`, retry: '다시 시도', filterBtn: '필터', fp: { title: '필터', from: '게시일 시작', to: '게시일 끝', cvss: '최소 CVSS', cve: 'CVE 번호', any: '전체', cveYes: 'CVE 번호 있음', cveNo: 'CVE 번호 아직 없음', risk: '위험 단계', flags: '조건', has: { advisory: '공식 공지 있음', repo: '공격 코드(PoC) 공개됨' }, sort: '정렬', sorts: { new: '최신순', risk: '위험도순', cvss: 'CVSS 높은순' }, close: '닫기', reset: '필터 초기화', apply: '필터 적용' }, textSizeGroup: '글자 크기', textGlyph: '가', textDown: '글자 작게', textUp: '글자 크게', textReset: '기본 글자 크기', textNow: (p) => `글자 크기 ${p}%`, pinMore: (n) => `주목 더 보기 (${n})`, pinLess: '주목 접기', qfRisk: '위험 단계', qfKev: '악용 발생만', noneForFilters: '고른 조건에 맞는 사건이 지금 게시판에 없습니다.', easyLevels: { highest: '심각', high: '경계', notice: '주의' }, why: { curator: '보안 뉴스레터 언급', buzz: 'HN 화제' }, skip: '주목 건너뛰고 최신순으로', skipTop: '게시판으로 건너뛰기', found: (n) => `${n}건이 보입니다.`,
    status: (updated, shown, total) => `마지막 업데이트 ${updated} · ` + (shown === total ? `${total}건` : `전체 ${total}건 중 ${shown}건`),
    products: '사용하는 제품', productsHint: '제품 이름을 입력해 찾기', productsHintShort: '제품 이름', picked: '고른 제품', remove: (name) => `${name} 빼기`,
    search: '검색', searchHint: '키워드, CVE 번호, 버전', all: '최신순', sortLabel: '정렬', expandAll: '모두 펼치기', collapseAll: '모두 접기', theme: '어두운 화면',
    pin: '주목', noCve: 'CVE 번호 아직 없음', moreCves: (n) => ` 외 ${n}건`, published: '처음 게시', unrated: '점수 아직 없음', kevReason: '악용 발생', kevEasy: '지금 실제 공격에 쓰이고 있어요!',
    setting: '설정 파일에 이 줄을 넣으세요:', settingIn: (f) => `설정 파일 ${f}에 이 줄을 넣으세요:`, commandFor: (w) => `${w} 이 명령으로 업데이트하세요:`, caution: '설정을 잘못 바꾸면 서비스가 멈추거나 접속이 막힐 수 있어요. 바꾸기 전에 아래 원문 링크를 확인하세요.',
    noneForPicks: (names) => `고른 제품(${names})에 해당하는 사건이 지금 게시판에 없습니다.`, noneForQuery: (q) => `‘${q}’에 맞는 사건이 없습니다.`, scopeWeek: '최근 7일 안에서 찾았습니다.', scopeMonths: '최근 3개월 안에서 찾았습니다.', searchOlder: '이전 사건에서도 찾기', loadedOlder: (n) => `이전 사건 ${n}건을 더 불러왔습니다.`,
    clearWeek: '최근 7일 동안 게시된 사건이 없습니다', clearMonths: '최근 3개월 동안 게시된 사건이 없습니다', clearNote: '고른 제품은 주소에 저장됩니다. 즐겨찾기해 두면 다음에도 바로 확인할 수 있습니다.', searchOlderMonths: '이전 사건에서도 찾기 (최근 3개월)',
    noIncidents: '아직 게시된 사건이 없습니다.', loadOlder: '이전 사건 불러오기 (최근 3개월)', showMore: (n) => `더 보기 (${n}건 남음)`, clearSearch: '검색 지우기', clearAll: '필터 모두 지우기',
    rating: { critical: '심각', high: '높음', medium: '보통', low: '낮음', none: '없음' },
    original: '원문', readAt: (site) => `${site}에서 읽기 →`,
    mentions: { advisory: '보안 공지', writeup: '분석 글', cve_record: 'CVE 기록', discussion: '토론', curator: '뉴스레터', repo: '저장소' },
    nvd: '이 서비스는 NVD API 데이터를 사용하지만 NVD의 보증이나 인증을 받지 않았습니다.',
    kevNote: '악용 발생 표시는 CISA의 알려진 악용 취약점(KEV) 목록이나, 실제 공격을 전한 원문을 바탕으로 합니다.',
    preparing: '요약 준비 중', unavailable: '요약을 만들지 못했습니다. 아래 원문 링크를 확인하세요.',
    conditions: '해당 조건', mitigation: '대처법', views: '보기 방식',
    normal: '기본', easy: '쉬운 설명', highest: '심각!', high: '경계', notice: '주의', levels: { highest: '고위험', high: '위험', notice: '참고' },
    command: '이 명령으로 업데이트하세요:', devices: '이 기기들을 지금 업데이트하세요!', version: (v) => `${v} 버전으로 업데이트하세요.`,
    fixedIn: (v) => `${v} 버전에서 고쳐졌습니다.`, none: '고친 버전을 아직 확인하지 못했습니다. 아래 원문 링크에서 확인하세요.', stopgap: '당장 못 하면:', copy: '복사', copied: '복사됨',
    paused: 'AI 요약이 잠시 멈췄습니다. 새 사건은 요약 없이 원문 제목과 링크만 보입니다.',
    todo: { title: '지금 할 일', use: '이 제품을 쓰고 있나요?', yes: '써요', no: '안 써요', unsure: '몰라요', usedYes: '쓰고 있어요.', usedNo: '안 써요. 할 일이 없어요.', usedUnsure: '잘 모르겠어요. 쓰는 걸로 보고 아래 할 일을 확인하세요.', findDevice: '모델 이름은 기기 뒷면 라벨이나 관리 화면에서 볼 수 있어요.', versionHelp: (cve) => (cve ? `내 버전을 모르겠으면 제조사 사이트에서 찾거나, AI 도우미에게 ${cve} 번호로 물어보세요.` : '내 버전을 모르겠으면 제조사 사이트에서 제품 이름으로 찾아보세요.'), findApp: '설치된 프로그램 목록이나 앱 정보에서 이름과 버전을 볼 수 있어요.', runsOn: (os) => `${os}에서 돌아가요`, locked: '1번에 먼저 답하면 체크할 수 있어요.', finishedCount: '완료', change: '처음부터 다시', act: '할 일', doneLabel: '다 했어요', allDone: '조치 완료! 이 브라우저에 기억해 둘게요.', notUsed: '해당 없음으로 표시했어요.', markDone: '조치함', markNo: '해당 없음', count: (a, b) => `${b}단계 중 ${a}단계`, note: '체크는 이 브라우저에만 저장돼요.' },
    newTab: ' (새 탭에서 열림)', pinDone: (n) => `${n}건 처리`, fixesIntro: '내 제품에 맞는 버전 이상으로 업데이트하세요:', noneEasy: '아직 고친 버전 소식이 없어요. 아래 원문 링크에서 새 소식을 확인하세요.', orNewer: (v) => `${v}\u00a0이상`, models: (n) => `해당 모델 보기 (${n}개)`,
    guideBtn: '읽는 법',
    guide: {
      title: '이 게시판 읽는 법', close: '닫기',
      risk: { highest: '실제 공격에 쓰이고 있거나, 위험 점수가 10점 중 9점 이상', high: '위험 점수 10점 중 7점 이상', notice: '그 밖의 사건. 점수가 아직 없는 사건도 여기에 들어갑니다.' },
      ring: '위험 점수(CVSS, 10점 만점). 링이 점수만큼 차고 색도 점수를 따릅니다. 실제 공격에 쓰이면 점수와 상관없이 맨 위 단계로 올라갑니다. 점수가 아직 없으면 —로 보입니다.',
      tags: '색 배지는 영향받는 제품과 기기로, 제품마다 늘 같은 색입니다. 테두리 배지는 그 제품이 돌아가는 OS입니다.',
      date: '처음 게시된 날짜와 시각 (내 시간대 기준)',
      pin: '악용이 발생했거나 점수가 높거나 보안 뉴스레터·HN에서 화제인 사건을 위에 최대 4건 고정합니다.',
      open: '행을 누르면 요약, 해당 조건, 대처법, 원문 링크가 펼쳐집니다.',
      easy: '위쪽에서 바꾸면 무엇이 위험한지와 지금 할 일을 쉬운 말로 보여줍니다.',
      filterWord: '제품 · 필터',
      filter: '사용하는 제품을 고르거나 필터로 좁힐 수 있습니다. 고른 조건은 주소에 남아 즐겨찾기로 다시 열 수 있습니다.',
      note: '요약은 AI가 원문을 읽고 만듭니다. 조치하기 전에 원문 링크를 확인하세요.',
    },
  },
  en: {
    other: '한국어', otherShort: '한', title: 'vuln-radar · vulnerability board', loading: 'Loading…',
    notListed: (text) => `Not in the product list, so it was searched for instead: ${text}`,
    loadError: (msg) => `Could not load the Board. Check your connection and try again. (${msg})`, retry: 'Try again', filterBtn: 'Filters', fp: { title: 'Filters', from: 'Published from', to: 'Published to', cvss: 'Minimum CVSS', cve: 'CVE ID', any: 'Any', cveYes: 'Has a CVE', cveNo: 'No CVE yet', risk: 'Risk level', flags: 'Conditions', has: { advisory: 'Official advisory', repo: 'Attack code (PoC) public' }, sort: 'Sort', sorts: { new: 'Newest', risk: 'Highest risk', cvss: 'Highest CVSS' }, close: 'Close', reset: 'Reset filters', apply: 'Apply filters' }, textSizeGroup: 'Text size', textGlyph: 'A', textDown: 'Smaller text', textUp: 'Larger text', textReset: 'Default text size', textNow: (p) => `Text size ${p}%`, pinMore: (n) => `More Highlights (${n})`, pinLess: 'Fewer Highlights', qfRisk: 'Risk level', qfKev: 'Exploited only', noneForFilters: 'No Incident on the Board matches these filters.', easyLevels: { highest: 'Severe', high: 'Warning', notice: 'Caution' }, why: { curator: 'In security newsletters', buzz: 'Trending on HN' }, skip: 'Skip to newest', skipTop: 'Skip to the Board', found: (n) => `${n} Incidents shown.`,
    status: (updated, shown, total) => `Last updated ${updated} · ` + (shown === total ? `${total} incidents` : `${shown} of ${total} incidents`),
    products: 'Products you run', productsHint: 'Type to find a Product', productsHintShort: 'Product name', picked: 'Picked Products', remove: (name) => `Remove ${name}`,
    search: 'Search', searchHint: 'Keyword, CVE ID, version', all: 'Newest first', sortLabel: 'Sort', expandAll: 'Expand all', collapseAll: 'Collapse all', theme: 'Dark theme',
    pin: 'Highlights', noCve: 'No CVE yet', moreCves: (n) => ` +${n}`, published: 'First published', unrated: 'Not rated yet', kevReason: 'Exploited', kevEasy: 'Attackers are using this right now!',
    setting: 'Add this line to the config file:', settingIn: (f) => `Add this line to ${f}:`, commandFor: (w) => `${w}, run this to update:`, caution: 'A wrong setting can stop the service or lock you out. Check the source link below first.',
    noneForPicks: (names) => `No Incident on the Board touches the Products you picked (${names}).`, noneForQuery: (q) => `No Incident matches “${q}”.`, scopeWeek: 'Searched the last 7 days.', scopeMonths: 'Searched the last 3 months.', searchOlder: 'Search older Incidents too', loadedOlder: (n) => `Loaded ${n} older Incidents.`,
    clearWeek: 'No Incident posted in the last 7 days', clearMonths: 'No Incident posted in the last 3 months', clearNote: 'Your picks are saved in the address. Bookmark it to check again next time.', searchOlderMonths: 'Search older Incidents too (last 3 months)',
    noIncidents: 'No Incidents have been posted yet.', loadOlder: 'Load older Incidents (last 3 months)', showMore: (n) => `Show more (${n} left)`, clearSearch: 'Clear search', clearAll: 'Clear all filters',
    rating: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' },
    original: '', readAt: (site) => `Read at ${site} →`,
    mentions: { advisory: 'Advisory', writeup: 'Write-up', cve_record: 'CVE record', discussion: 'Discussion', curator: 'Newsletter', repo: 'Repository' },
    nvd: '',
    kevNote: 'Exploited flags come from the CISA Known Exploited Vulnerabilities catalog, or from sources that report attacks.',
    preparing: 'Summary in preparation', unavailable: 'No Summary is available. See the source link below.',
    conditions: 'Affected when', mitigation: 'Mitigation', views: 'View',
    normal: 'Normal', easy: 'Easy', highest: 'Severe!', high: 'Warning', notice: 'Caution', levels: { highest: 'High risk', high: 'Elevated', notice: 'Notice' },
    command: 'Run this to update:', devices: 'Update these devices now!', version: (v) => `Update to version ${v}.`,
    fixedIn: (v) => `Fixed in version ${v}.`, none: 'We have not confirmed a fixed version yet. Check the source link below.', stopgap: 'Can\'t update yet?', copy: 'Copy', copied: 'Copied',
    paused: 'Summaries are paused for now; new Incidents show only the source title and link.',
    todo: { title: 'What to do now', use: 'Do you use this?', yes: 'Yes', no: 'No', unsure: 'Not sure', usedYes: 'I use it.', usedNo: 'Not used. Nothing to do.', usedUnsure: 'Not sure. Treat it as in use and check the step below.', findDevice: 'The model name is on the label under the device or in its admin page.', versionHelp: (cve) => (cve ? `Not sure of your version? Look on the vendor's site, or ask an AI assistant about ${cve}.` : 'Not sure of your version? Look the product up on the vendor\'s site.'), findApp: 'Your list of installed programs or the app\'s About page shows its name and version.', runsOn: (os) => `Runs on ${os}`, locked: 'Answer step 1 first to tick this.', finishedCount: 'Done', change: 'Start over', act: 'To do', doneLabel: "I've done it", allDone: 'All done! This browser will remember it.', notUsed: 'Marked as not used.', markDone: 'Done', markNo: 'Not used', count: (a, b) => `Step ${a} of ${b}`, note: 'Checks are saved in this browser only.' },
    newTab: ' (opens in a new tab)', pinDone: (n) => `${n} handled`, fixesIntro: 'Update to at least the version for your product:', noneEasy: 'No fixed version has been announced yet. Watch the source link below for news.', orNewer: (v) => `${v}\u00a0or\u00a0later`, models: (n) => `Affected models (${n})`,
    guideBtn: 'How to read',
    guide: {
      title: 'How to read this Board', close: 'Close',
      risk: { highest: 'Exploited (attacks reported), or a risk score of 9 or more out of 10', high: 'A risk score of 7 or more out of 10', notice: 'Everything else, including Incidents with no score yet.' },
      ring: 'The risk score (CVSS, out of 10). The ring fills to the score and its colour follows the score. Reported attacks lift an Incident to the top level whatever its score. No score yet shows as —.',
      tags: 'Filled badges are the affected Products and devices, each always in the same colour. Outlined badges are the systems they run on.',
      date: 'When it was first published, in your time zone',
      pin: 'Up to four Incidents that are exploited, scored high, or talked about in security newsletters or on HN stay on top.',
      open: 'Open a row for the summary, who is affected, the fix and the source links.',
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
  try {
    localStorage.setItem(SAVED_VIEW, view);
  } catch {
    // storage blocked: the choice lasts until reload
  }
  render();
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
// Rows of 최신순 drawn so far; a long list grows by PAGE on request instead of all at once.
const PAGE = 100;
let shown = PAGE;
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

function saveFilter() {
  const encoded = filterToQuery(filter);
  try {
    localStorage.setItem(SAVED, filterToQuery({ ...filter, query: '' }));
  } catch {
    // storage blocked: the address still carries the filter
  }
  history.replaceState(null, '', encoded ? `#${encoded}` : location.pathname + location.search);
}

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
    saveFilter();
  } catch (err) {
    loadError = err.message;
  }
  // The one authored moment: as the Board first arrives, each CVSS ring fills to its score (CSS, only when motion is
  // allowed). Later redraws (filters, views) do not replay it.
  document.body.classList.add('arriving');
  render();
  setTimeout(() => document.body.classList.remove('arriving'), 1200);
}

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

// Theme and language change the whole page at once: cross-fade it (View Transitions, where the browser has them).
function crossFade(change) {
  if (reducedMotion.matches || !document.startViewTransition) return change();
  document.startViewTransition(change);
}

// Source URLs are untrusted too: only http(s) ever becomes a link target.
function anchor(url, text) {
  const a = document.createElement('a');
  a.href = /^https?:\/\//i.test(url) ? url : '#';
  // Every source opens in a new tab so the Board, its filters and to-do ticks stay where they were (user, 11-08).
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  a.textContent = text;
  a.append(el('span', 'sr-only', TEXT[lang].newTab)); // screen readers are told before the tab changes
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
  const narrow = matchMedia('(max-width: 599px)').matches;
  for (const node of document.querySelectorAll('[data-t-placeholder]')) {
    const key = node.dataset.tPlaceholder;
    node.placeholder = (narrow && t[`${key}Short`]) || t[key];
  }
  for (const node of document.querySelectorAll('[data-t-aria]')) node.setAttribute('aria-label', t[node.dataset.tAria]);
  // Full name on wide screens, a short code on phones (the header must fit 375px); screen readers get the full name.
  $('lang').replaceChildren(el('span', 'full', t.other), el('span', 'short', t.otherShort));
  $('lang').setAttribute('aria-label', t.other);
  $('lang').lang = lang === 'ko' ? 'en' : 'ko';
  for (const view of ['normal', 'easy']) $(`view-${view}`).setAttribute('aria-pressed', defaultView === view);
  placePill();
  $('theme').setAttribute('aria-pressed', theme() === 'dark');
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

function statusLine(list) {
  const t = TEXT[lang];
  if (loadError) return ''; // the message and its retry button sit in the empty-state block
  if (!updated) return t.loading;
  return t.status(ago(updated), list.length, incidents.length) + (paused ? ` · ${t.paused}` : '');
}

// 이 게시판 읽는 법: opens by itself on a first visit and stays shut once closed. Not on phones (under 600px,
// the header's phone width): there it fills about a screen before the first row, so it waits for the button.
const SAVED_GUIDE = 'vr-guide';
let guideOpen = null; // decided at the first draw, when the page's width is settled

function firstVisitGuide() {
  try {
    return !localStorage.getItem(SAVED_GUIDE) && !matchMedia('(max-width: 599px)').matches;
  } catch {
    return false; // storage blocked: it could never be dismissed for good, so it waits for the button
  }
}

function setGuide(open) {
  guideOpen = open;
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
  guideOpen ??= firstVisitGuide();
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
  rule();
  item(g.ring, scoreCell({ cvss: 9.8 }));
  // The example badge is the top Highlight's Product, so the guide shows a line the reader will see first on the Board.
  const top = filterBoard(incidents, [], '', Date.now()).highlights[0];
  const example = top && rowTags(top, lang).find((n) => !(top.summary?.platforms || []).includes(n));
  item(g.tags, example ? lineBadge(example, lineKeys(top, lang).get(example)) : lineBadge('OpenSSH'), osBadge('Windows'));
  const when = el('span', 'c-date');
  when.append(el('span', '', '2026-11-08'), el('span', '', '09:30'));
  item(g.date, when);
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

// The rest of the last three months, merged into the week already on screen.
async function loadOlder() {
  loadingOlder = true;
  render();
  try {
    const months = await Promise.all(olderMonths.map((m) => getJson(`board/${m}.json`)));
    const byId = new Map(incidents.map((i) => [i.id, i]));
    const before = byId.size;
    for (const i of months.flatMap((m) => m.incidents).filter(onBoard)) if (!byId.has(i.id)) byId.set(i.id, i);
    incidents = [...byId.values()];
    refreshProducts();
    olderMonths = [];
    clearTimeout(announcing); // a pending count from the last search must not talk over this
    $('announce').textContent = TEXT[lang].loadedOlder(byId.size - before); // also when nothing new came
  } catch (err) {
    loadError = err.message;
  }
  loadingOlder = false;
  render();
}

// Under the list: more rows of what is loaded, then older months.
function moreButtons(rest) {
  const t = TEXT[lang];
  const buttons = [];
  if (rest > 0) {
    const more = Object.assign(el('button', 'btn', t.showMore(rest)), { type: 'button' });
    more.addEventListener('click', () => { shown += PAGE; render(); });
    buttons.push(more);
  }
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
  const { highlights: chosen, list } = filterBoard(incidents, filter.picks, filter.query, Date.now(), filter);
  // 주목 더 보기 adds only Highlights worth a notice: 위험 or above, or a reason the row cannot show (newsletter, HN).
  const extra = chosen.slice(PINNED).filter((i) => riskLevel(i) !== 'notice' || pinReason(i));
  // Which Incidents are pinned is decided by importance (highlightScore); the order they show in is the visitor's sort.
  const highlights = (pinAll ? [...chosen.slice(0, PINNED), ...extra] : chosen.slice(0, PINNED)).sort(orderBy(filter.sort))
    .sort((a, b) => Boolean(answeredAtLoad[a.id]) - Boolean(answeredAtLoad[b.id])); // stable: the rest keep their order
  $('status').textContent = statusLine(list);
  guide();
  $('skip').hidden = !highlights.length;
  announce(list.length);
  // Highlights are pinned on top like a board's notices; every other Incident follows, newest first.
  const pinned = new Set(highlights);
  rowCount = 0;
  // CVE text is untrusted input, so it only ever goes in through textContent.
  $('highlights').replaceChildren(...highlights.map((i) => row(i, true)));
  $('pinned').hidden = !highlights.length;
  $('pinned-head').replaceChildren(`${TEXT[lang].pin} `, el('span', 'n', String(highlights.length)));
  const handled = highlights.filter((i) => finished(i.id)).length;
  if (handled) $('pinned-head').append(el('span', 'handled', TEXT[lang].pinDone(handled)));
  $('pinned-head').hidden = !highlights.length;
  $('pin-more').replaceChildren(...(extra.length ? [pinToggle(extra.length)] : []));
  const count = panelCount();
  $('filter-count').textContent = count ? String(count) : '';
  $('filter-count').hidden = !count;
  if (count && count !== shownCount) pop($('filter-count'));
  shownCount = count;
  $('filter-btn').setAttribute('aria-expanded', !$('filters').hidden);
  const rest = list.filter((i) => !pinned.has(i));
  $('board').replaceChildren(...rest.slice(0, shown).map((i) => row(i, false)));
  // Nothing found: the empty state below carries 이전 사건에서도 찾기 itself, so the buttons under the list stay away.
  $('more').replaceChildren(...(loadError || !updated || !list.length ? [] : moreButtons(rest.length - shown)));
  // OS picks show as pressed buttons in the quick bar, so only Products become chips here.
  const chips = filter.picks.filter((p) => !p.startsWith('os:'));
  $('picks').replaceChildren(...chips.map(chip), ...conditionChips(), ...(activeFilters() > 1 ? [clearButton(TEXT[lang].clearAll, NO_FILTER)] : []),
    ...(pickNote ? [el('p', 'pick-note', TEXT[lang].notListed(pickNote))] : []));
  $('all-head').hidden = !list.some((i) => !pinned.has(i));
  $('all-head').textContent = TEXT[lang].fp.sorts[filter.sort]; // the list's heading says its order
  $('sort').replaceChildren(...SORTS.map((key) => Object.assign(new Option(TEXT[lang].fp.sorts[key], key), { selected: key === filter.sort })));
  visibleIds = [...highlights, ...rest.slice(0, shown)].map((i) => i.id);
  $('expand-all').hidden = !visibleIds.length;
  $('expand-all').textContent = allOpen() ? TEXT[lang].collapseAll : TEXT[lang].expandAll;
  $('expand-all').setAttribute('aria-pressed', allOpen());
  // Before the data arrives, say nothing; if it never arrives, say so and offer a retry, not "no Incidents".
  const quiet = list.length > 0 || (!updated && !loadError);
  $('empty').hidden = quiet;
  $('empty').replaceChildren(...(quiet ? [] : loadError ? errorState() : emptyState()));
  const check = $('empty').querySelector('.allclear .mark path');
  if (check && !hadAllClear) draw(check, 420, 120);
  hadAllClear = Boolean(check);
  if (changed) afterTodo();
}
let shownCount = 0;

// The Easy view's to-do list: 1 do you use it, 2 the action, then "조치함" on the row. The visitor's answers stay in
// this browser (nothing leaves it, PRODUCT.md principle 5); "조치함" is their own word, not a check we ran.
const SAVED_DONE = 'vr-done';
const MAX_DONE = 500; // oldest answers go first; ~40 bytes each
function readProgress() {
  try {
    const saved = JSON.parse(localStorage.getItem(SAVED_DONE));
    return saved && typeof saved === 'object' && !Array.isArray(saved) ? saved : saved === null ? {} : null;
  } catch {
    return null; // storage blocked or broken: answers live in this page until reload
  }
}
let progress = readProgress() ?? {};
const answeredAtLoad = Object.fromEntries(Object.keys(progress).filter((id) => progress[id]?.used === false || progress[id]?.done).map((id) => [id, true]));
// Another tab ticked something: show it here too.
window.addEventListener('storage', (event) => {
  if (event.key !== SAVED_DONE) return;
  progress = readProgress() ?? progress;
  render();
});
let changed = null; // {id, key, finished}: the to-do control just used, so the redraw can refocus and confirm it
const stateOf = (id) => progress[id] || {};
const fillOf = (id) => {
  const st = stateOf(id);
  return st.used === false ? 1 : ((st.used !== undefined ? 1 : 0) + (st.done ? 1 : 0)) / 2;
};
const finished = (id) => (stateOf(id).used === false ? 'no' : stateOf(id).done ? 'done' : null);

function setTodo(id, next, key) {
  const before = finished(id);
  const fromFill = fillOf(id);
  progress = readProgress() ?? progress; // storage is the truth: another tab may have saved meanwhile
  delete progress[id]; // re-added last, so the oldest answers are the ones dropped past MAX_DONE
  if (next) progress[id] = next;
  for (const old of Object.keys(progress).slice(0, -MAX_DONE)) delete progress[old];
  try {
    localStorage.setItem(SAVED_DONE, JSON.stringify(progress));
  } catch {
    // storage blocked: the answers last until reload
  }
  changed = { id, key, fromFill, finished: !before && finished(id) };
  render();
}

const CHECK = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m3.5 8.3 2.8 2.8 6.2-6.4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function markChip(mine) {
  const chip = el('small', `why mine ${mine}`);
  chip.innerHTML = CHECK;
  chip.append(TEXT[lang].todo[mine === 'done' ? 'markDone' : 'markNo']);
  return chip;
}

function todoList(incident) {
  const s = incident.summary;
  const parts = easyAnswer(s, riskLevel(incident), incident.cves?.[0]);
  // Nothing a reader can do yet (no version, command, devices or advice): no list to tick, just say so.
  if (easyAction(s).kind === 'none' && !s[lang].easy_action && !s[lang].mitigation) return parts;
  const c = TEXT[lang].todo;
  const id = incident.id;
  const st = stateOf(id);
  const box = el('section', 'todo');
  box.dataset.todo = id;
  box.setAttribute('aria-label', c.title);
  const total = st.used === false ? 1 : 2;
  const count = (st.used !== undefined ? 1 : 0) + (st.done ? 1 : 0);
  const head = el('div', 'todo-head');
  const meter = el('span', 'todo-count');
  meter.style.setProperty('--fill', count / total);
  meter.classList.toggle('zero', !count); // a round cap would leave a dot at 0
  meter.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle class="track" cx="12" cy="12" r="9.5" pathLength="1"/><circle class="arc" cx="12" cy="12" r="9.5" pathLength="1"/></svg>';
  meter.append(finished(id) ? c.finishedCount : c.count(count, total));
  head.append(el('strong', '', c.title), meter);

  const steps = el('ol', 'todo-steps');
  const step = (n, done, off, ...content) => {
    const li = el('li', `step${done ? ' done' : ''}${done === 'unsure' ? ' unsure' : ''}${off ? ' off' : ''}`);
    const num = el('span', 'num');
    if (done === 'unsure') num.append('?'); // answered, but not a sure yes
    else if (done) num.innerHTML = CHECK;
    else num.append(String(n));
    const body = el('div', 'body');
    body.append(...content);
    li.append(num, body);
    return li;
  };
  const button = (text, key, onClick, cls = 'btn') => {
    const b = Object.assign(el('button', cls, text), { type: 'button' });
    b.dataset.k = key;
    b.addEventListener('click', onClick);
    return b;
  };
  // 1: do you use it? The badges say which Products the question is about.
  const tags = el('span', 'c-tags');
  const os = new Set(Array.isArray(s.platforms) ? s.platforms : []);
  const keys = lineKeys(incident, lang);
  tags.append(...rowTags(incident, lang).filter((name) => !os.has(name)).map((name) => lineBadge(name, keys.get(name))));
  // The Summary's own question names the condition that makes a reader affected ("Alpine 리눅스에서 OpenSSH 서버를
  // 돌리나요?"), so only those who are say 써요; Summaries without one ask about the product.
  const question = Object.assign(el('p', 'q', s[lang].use_question || c.use), { id: `todo-q-${++rowCount}` });
  const first = [question, ...(tags.childElementCount ? [tags] : [])];
  if (os.size) first.push(el('p', 'runs', c.runsOn([...os].join('·'))));
  if (st.used === undefined) {
    const choices = el('div', 'choices');
    choices.setAttribute('role', 'group');
    choices.setAttribute('aria-labelledby', question.id); // screen readers hear the question with 써요 / 안 써요 / 몰라요
    // 몰라요 counts as in use: when unsure, the Board shows the risk rather than hiding it (PRODUCT.md principle 2).
    choices.append(button(c.yes, 'yes', () => setTodo(id, { used: true }, 'act')),
                   button(c.no, 'no', () => setTodo(id, { used: false }, 'change')),
                   button(c.unsure, 'unsure', () => setTodo(id, { used: 'unsure' }, 'act')));
    first.push(choices);
  } else {
    const answer = el('p', 'answer', st.used === 'unsure' ? c.usedUnsure : st.used ? c.usedYes : c.usedNo);
    answer.append(' ', button(c.change, 'change', () => setTodo(id, null, 'yes'), 'linkish'));
    first.push(answer);
    if (st.used === 'unsure') first.push(el('p', 'hint', (s.devices || []).length ? c.findDevice : c.findApp));
  }
  // The long model list comes after the answer, so opening it never pushes 써요 / 안 써요 / 몰라요 away from the question.
  if (Array.isArray(s.devices) && s.devices.length > MANY_DEVICES) first.push(modelList(s.devices, fixLines(s)));
  steps.append(step(1, st.used === 'unsure' ? 'unsure' : st.used !== undefined, false, ...first));
  // 2: the action itself, then the visitor's own tick.
  if (st.used !== false) {
    const tick = el('label', 'check');
    const using = st.used === true || st.used === 'unsure';
    const input = Object.assign(document.createElement('input'), { type: 'checkbox', checked: Boolean(st.done), disabled: !using });
    input.dataset.k = 'act';
    input.addEventListener('change', () => setTodo(id, { used: st.used, ...(input.checked ? { done: true } : {}) }, 'act'));
    tick.append(input, el('span', '', c.doneLabel));
    const after = [tick];
    if (!using) {
      const why = Object.assign(el('p', 'hint', c.locked), { id: `todo-lock-${++rowCount}` });
      input.setAttribute('aria-describedby', why.id);
      after.push(why);
    }
    steps.append(step(2, Boolean(st.done), false, el('p', 'q', c.act), ...parts, ...after));
  }
  box.append(head, steps);
  const mine = finished(id);
  if (mine === 'done') {
    const done = el('p', 'todo-done');
    done.innerHTML = CHECK;
    done.append(c.allDone);
    box.append(done);
  } else if (!mine) box.append(el('p', 'todo-note', c.note)); // 안 써요 already said "할 일이 없어요"

  return [box];
}

// After a redraw caused by the to-do list: focus returns to the same control, and a finished list confirms itself.
function afterTodo() {
  const { id, key, fromFill, finished: justFinished } = changed;
  changed = null;
  const box = [...document.querySelectorAll('.todo')].find((b) => b.dataset.todo === id);
  if (!box) return;
  box.querySelector(`[data-k="${key}"]`)?.focus();
  const meter = box.querySelector('.todo-count .arc');
  if (meter && !reducedMotion.matches) meter.animate([{ strokeDasharray: `${fromFill} 1` }, { strokeDasharray: `${fillOf(id)} 1` }], { duration: 450, easing: EASE_OUT });
  for (const path of box.querySelectorAll('.step.done .num path')) draw(path, 260);
  if (justFinished) {
    const doneLine = box.querySelector('.todo-done');
    if (doneLine) {
      pop(doneLine, 'translateY(4px)', 260);
      draw(doneLine.querySelector('path'), 360, 80);
    }
    const chip = box.closest('li')?.querySelector('.why.mine');
    if (chip) pop(chip, 'scale(0.6)', 260);
    $('announce').textContent = finished(id) === 'done' ? TEXT[lang].todo.allDone : TEXT[lang].todo.notUsed;
  }
}
let hadAllClear = false;

// Nothing to show: say so plainly. With products picked this is the good news, "not affected".
function errorState() {
  const t = TEXT[lang];
  const retry = Object.assign(el('button', 'btn', t.retry), { type: 'button' });
  retry.addEventListener('click', () => location.reload());
  const actions = el('p', 'actions');
  actions.append(retry);
  return [para('', t.loadError(loadError)), actions];
}

// Screen readers hear the count once the visitor stops changing the filter, not on every redraw.
let lastCount = null;
let announcing;
function announce(count) {
  if (!updated || count === lastCount) return;
  const first = lastCount === null;
  lastCount = count;
  clearTimeout(announcing);
  if (!first) announcing = setTimeout(() => { $('announce').textContent = TEXT[lang].found(count); }, 700);
}

function emptyState() {
  const t = TEXT[lang];
  const names = filter.picks.map((id) => products.find((p) => p.id === id)?.name || id).join(', ');
  // Only Products picked: name them ("not affected"); any quick filter in play: speak of conditions instead.
  const quick = panelCount() > 0;
  const message = filter.picks.length && !quick ? t.noneForPicks(names) : filter.query && !quick ? t.noneForQuery(filter.query)
    : quick ? t.noneForFilters : t.noIncidents;
  const buttons = el('p', 'actions');
  // Say how far back this looked: "nothing" in one week is not "nothing" in three months.
  const scope = para('scope', olderMonths.length ? t.scopeWeek : t.scopeMonths);
  if (olderMonths.length) {
    const older = Object.assign(el('button', 'btn', loadingOlder ? t.loading : t.searchOlder), { type: 'button', disabled: loadingOlder });
    older.addEventListener('click', loadOlder);
    buttons.append(older);
  }
  if (filter.query) buttons.append(clearButton(t.clearSearch, { query: '' }));
  // 모두 지우기 only when something besides the search is set; with a search alone it would repeat 검색 지우기.
  if (activeFilters() - (filter.query ? 1 : 0) > 0) buttons.append(clearButton(t.clearAll, NO_FILTER));
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

function clearButton(text, change) {
  const button = Object.assign(el('button', 'btn', text), { type: 'button' });
  button.addEventListener('click', () => {
    if ('query' in change) $('search').value = change.query;
    update(change);
    $(change.picks ? 'product-pick' : 'search').focus();
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

// 주목 더 보기: pin every chosen Highlight (up to ten), or back to four.
let pinAll = false;
function pinToggle(rest) {
  const t = TEXT[lang];
  const button = Object.assign(el('button', 'btn', pinAll ? t.pinLess : t.pinMore(rest)), { type: 'button' });
  button.setAttribute('aria-expanded', pinAll);
  button.addEventListener('click', () => { pinAll = !pinAll; render(); });
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
    checks(f.risk, 'risk', RISKS.map((r) => [r, words[r], `risk-${r}`]), (r) => filter.risk.includes(r)),
    checks(f.flags, 'flag', [['kev', t.qfKev], ...LINK_KINDS.map((k) => [k, f.has[k]])], (v) => (v === 'kev' ? filter.kev : filter.has.includes(v))),
    checks('OS', 'os', OSES.map((os) => [`os:${os.toLowerCase()}`, os]), (v) => filter.picks.includes(v)),
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
}

// Reset clears the panel only; Products picked at the top and the search stay.
const PANEL_EMPTY_WITH_OS = () => ({ ...PANEL_EMPTY, picks: filter.picks.filter((p) => !p.startsWith('os:')) });

function applyPanel(event) {
  event.preventDefault();
  const data = new FormData($('filters'));
  const flags = data.getAll('flag');
  update({
    from: data.get('from') || '', to: data.get('to') || '', cvssMin: Number(data.get('cvssMin')) || 0, cve: data.get('cve') || '',
    risk: data.getAll('risk'), kev: flags.includes('kev'), has: flags.filter((v) => v !== 'kev'),
    picks: [...filter.picks.filter((p) => !p.startsWith('os:')), ...data.getAll('os')],
  });
  closePanel(); // the results are the answer; the applied conditions stay visible as chips
  // A start date before the loaded week needs the older months.
  const week = new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10);
  if (filter.from && filter.from < week && olderMonths.length) loadOlder();
}

function update(change) {
  pickNote = ''; // the note answers one typed name; any later change makes it stale
  filter = { ...filter, ...change };
  shown = PAGE;
  saveFilter();
  render();
  if (!$('filters').hidden) filterPanel(); // an open panel always shows the filter in force, never a stale draft
}

function closePanel() {
  $('filters').hidden = true;
  $('filter-btn').setAttribute('aria-expanded', 'false');
  $('filter-btn').focus();
}

// Each applied panel condition as a removable chip under the fields, so what is filtered stays in sight.
function conditionChips() {
  const t = TEXT[lang];
  const f = t.fp;
  const words = defaultView === 'easy' ? t.easyLevels : t.levels;
  const chips = [
    ...filter.risk.map((r) => [words[r], { risk: filter.risk.filter((x) => x !== r) }]),
    ...(filter.kev ? [[t.qfKev, { kev: false }]] : []),
    ...filter.has.map((h) => [f.has[h], { has: filter.has.filter((x) => x !== h) }]),
    ...filter.picks.filter((p) => p.startsWith('os:')).map((p) => [OSES.find((o) => `os:${o.toLowerCase()}` === p) || p, { picks: filter.picks.filter((x) => x !== p) }]),
    ...(filter.from || filter.to ? [[`${filter.from || '…'} ~ ${filter.to || '…'}`, { from: '', to: '' }]] : []),
    ...(filter.cvssMin ? [[`CVSS ${filter.cvssMin}.0+`, { cvssMin: 0 }]] : []),
    ...(filter.cve ? [[filter.cve === 'yes' ? f.cveYes : f.cveNo, { cve: '' }]] : []),
  ];
  return chips.map(([label, change]) => {
    const button = Object.assign(el('button', 'cond'), { type: 'button' });
    button.append(el('span', '', label), el('span', 'x'));
    button.setAttribute('aria-label', t.remove(label));
    button.addEventListener('click', () => { update(change); $('filter-btn').focus(); });
    return button;
  });
}

$('product-pick').addEventListener('change', (event) => {
  const text = event.target.value.trim();
  const picked = products.find((p) => label(p) === text);
  event.target.value = '';
  if (picked && !filter.picks.includes(picked.id)) update({ picks: [...filter.picks, picked.id] });
  // Not a listed Product ("공유기"): search for it instead of dropping it silently.
  if (!picked && text) {
    $('search').value = text;
    update({ query: text });
    pickNote = text;
    render();
  }
});
$('lang').addEventListener('click', () => crossFade(() => {
  lang = lang === 'ko' ? 'en' : 'ko';
  try {
    localStorage.setItem(SAVED_LANG, lang);
  } catch {
    // storage blocked: the choice lasts until reload
  }
  refreshProducts();
  render();
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
// The phone sheet dims the Board behind it (CSS); a tap on the dimmed Board closes it, as a sheet does.
document.addEventListener('pointerdown', (event) => {
  const form = $('filters');
  if (form.hidden || !matchMedia('(max-width: 599px)').matches) return;
  if (!form.contains(event.target) && !$('filter-btn').contains(event.target)) closePanel();
});
$('filters').addEventListener('submit', applyPanel);
// '/' jumps to the search box, as on many sites; not while typing somewhere.
document.addEventListener('keydown', (event) => {
  if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
  if (event.target.closest?.('input, textarea, select, [contenteditable]')) return;
  event.preventDefault();
  $('search').focus();
});
$('sort').addEventListener('change', (event) => update({ sort: event.target.value }));
$('expand-all').addEventListener('click', () => {
  const closing = allOpen();
  for (const id of visibleIds) closing ? open.delete(id) : open.add(id);
  render();
  $('expand-all').focus();
});
$('filter-btn').addEventListener('click', () => {
  const form = $('filters');
  form.hidden = !form.hidden;
  if (!form.hidden) filterPanel();
  render();
  if (form.hidden) return;
  // On a phone the panel covers the Board as a sheet: a modal dialog with the focus inside. On wider screens it is an
  // inline panel under its button, and the page around it stays usable.
  const sheet = matchMedia('(max-width: 599px)').matches;
  if (sheet) {
    form.setAttribute('role', 'dialog');
    form.setAttribute('aria-modal', 'true');
    form.setAttribute('aria-labelledby', 'fp-title');
    reveal(form, '0 100%', 300);
    form.querySelector('.fp-head .btn').focus();
  } else {
    for (const name of ['role', 'aria-modal', 'aria-labelledby']) form.removeAttribute(name);
    reveal(form);
  }
});
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
  typing = setTimeout(() => update({ query: event.target.value }), 150);
});
window.addEventListener('resize', placePill);
document.fonts?.ready.then(placePill);
window.addEventListener('hashchange', () => {
  filter = loadFilter();
  $('search').value = filter.query;
  render();
});

const el = (tag, className, textContent = '') => Object.assign(document.createElement(tag), { className, textContent });
// The page follows `lang`; source text in another language carries its own lang for screen readers.
const para = (className, textContent, language = lang) => Object.assign(el('p', className, textContent), { lang: language });

// "대처법: ..." with the label bold, so the answer is found by eye.
function labelled(className, label, text) {
  const p = para(className, '');
  p.append(el('b', '', `${label}: `), text);
  return p;
}

function summary(s) {
  const parts = [para('summary', s.summary)];
  if (s.conditions.length) parts.push(labelled('conditions', TEXT[lang].conditions, s.conditions.join(' · ')));
  if (s.mitigation) parts.push(labelled('mitigation', TEXT[lang].mitigation, s.mitigation));
  return parts;
}

// Until the Summary arrives the row's title is the Brief, the source's own line (English); this says why.
const briefNote = (incident) => [para('preparing', TEXT[lang][briefMarker(incident)])];

// The Lead mention is always the rule-based one (CONTEXT.md order), never the model's pick.
function leadLine(incident) {
  const lead = el('p', 'lead');
  lead.append(anchor(incident.brief.lead, TEXT[lang].readAt(host(incident.brief.lead))));
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
function settingLine(text, file = '') {
  const t = TEXT[lang];
  const p = el('p', 'command');
  p.append(el('code', '', text));
  const caution = para('caution', '');
  caution.innerHTML = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2.2 14.5 13.5h-13Z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M8 6.5v3.3M8 11.6v.1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
  caution.append(el('span', '', t.caution));
  return [para('action', typeof file === 'string' && file ? t.settingIn(file) : t.setting), p, caution];
}

function easyAnswer(s, level, cve = '') {
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
    if (action.kind === 'command') parts.push(...(isShellCommand(action.command) ? [para('action', where ? t.commandFor(where) : t.command), commandLine(action.command)] : settingLine(action.command)));
    if (action.kind === 'version') parts.push(para('action', t.version(action.fixed)));
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
  if (fixes.length > 1 || action.kind === 'version' || (action.kind === 'devices' && action.fixed)) parts.push(para('hint', t.todo.versionHelp(cve)));
  if (action.stopgap) parts.push(para('stopgap', t.stopgap), ...(isShellCommand(action.stopgap) ? [commandLine(action.stopgap)] : settingLine(action.stopgap, s.stopgap_file)));
  // The step the stopgap needs to take effect ("바꾼 뒤 sshd를 다시 시작하세요."), when a source says it.
  if (action.stopgap && s[lang].stopgap_then) parts.push(para('action', s[lang].stopgap_then));
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

// The row's start: a dot in the rule-based Risk colour and its word (loud in the Easy view).
function riskCell(incident) {
  const level = riskLevel(incident);
  const cell = el('span', `c-risk risk-${level}`);
  const dot = el('i', 'dot');
  dot.setAttribute('aria-hidden', 'true');
  cell.append(dot, defaultView === 'easy' ? TEXT[lang][level] : TEXT[lang].levels[level]);
  // Why it is this high when the score alone would not say so: exploited in the wild lifts it to the top level.
  if (isExploited(incident)) cell.append(el('small', 'why kev', TEXT[lang].kevReason));
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
    const words = Object.assign(el('span', 'sev unrated'), { title: t.unrated });
    words.append(el('span', 'sr-only', t.unrated), Object.assign(el('span', '', '—'), { ariaHidden: 'true' }));
    cell.append(words);
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
  const brief = Object.assign(el('span', '', incident.brief.text), { lang: 'en' });
  return t.original ? [el('span', 'orig', t.original), ' ', brief] : [brief];
}

// A station sign: in the normal view the CVE ID is the bold name and the title the line under it. The
// Easy view leads with the plain headline over the one plain sentence; with no Summary yet, or no CVE
// yet, the title leads and the CVE line goes under it.
function titleCell(incident) {
  const t = TEXT[lang];
  const cell = el('span', 'c-title');
  const head = cveHead(incident.cves);
  const id = el('span', head ? 'cve' : 'cve none');
  if (head) {
    id.append(head.id);
    if (head.more) id.append(el('span', 'more', t.moreCves(head.more)));
    id.title = incident.cves.join(', ');
  } else id.append(t.noCve);
  const name = el('strong', 'title');
  const line = el('small', 'sub');
  const s = incident.summary?.[lang];
  if (defaultView === 'easy' && s?.title) {
    name.append(s.easy_title ? easyTitle(s.easy_title, riskLevel(incident)) : s.title); // Summaries made before 11-08 have no easy_title
    line.append(easyLine(s.easy || s.summary, riskLevel(incident)));
    line.classList.add('say');
  } else if (head && defaultView !== 'easy') {
    name.append(id);
    line.append(...describe(incident));
  } else {
    name.append(...describe(incident));
    line.append(id);
  }
  cell.append(name, line);
  return cell;
}

// A Product's line badge, in that Product's fixed colour.
// key: the Product id (language-free), so a Product keeps its line in both languages; else the name itself.
function lineBadge(name, key = name) {
  const badge = el('span', 'ln', name);
  const { bg, ink } = productLine(key);
  badge.style.setProperty('--line', bg);
  badge.style.setProperty('--line-ink', ink);
  return badge;
}

// An operating system the software runs on: an outline, not a line colour, so it never reads as the Product.
const osBadge = (name) => {
  const badge = el('span', 'ln os', name);
  badge.append(el('span', 'sr-only', ' (OS)')); // sighted readers tell it by the outline
  return badge;
};

function tagsCell(incident) {
  const cell = el('span', 'c-tags');
  const os = new Set(Array.isArray(incident.summary?.platforms) ? incident.summary.platforms : []);
  const keys = lineKeys(incident, lang);
  cell.append(...rowTags(incident, lang).map((name) => (os.has(name) ? osBadge(name) : lineBadge(name, keys.get(name)))));
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
  time.append(el('span', '', `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}`), el('span', '', `${two(d.getHours())}:${two(d.getMinutes())}`));
  time.title = `${TEXT[lang].published} · ${ago(at)}`;
  return time;
}

// Both views end with the Lead and every Mention, so links a CVE record gains later show up in either.
function details(incident) {
  const t = TEXT[lang];
  const easy = defaultView === 'easy';
  const parts = !incident.summary ? briefNote(incident) : easy ? todoList(incident) : summary(incident.summary[lang]);
  // The Easy row leads with a plain headline, so the opened panel starts with the CVE IDs.
  if (easy && isExploited(incident)) parts.unshift(para('kev', t.kevEasy));
  if (easy && incident.cves.length) parts.unshift(para('cve-line', incident.cves.join(', ')));
  const mentions = el('ul', 'mentions');
  const order = ['advisory', 'writeup', 'cve_record', 'discussion', 'curator', 'repo'];
  const rank = (m) => (order.includes(m.kind) ? order.indexOf(m.kind) : order.length);
  for (const m of [...incident.mentions].sort((a, b) => rank(a) - rank(b))) {
    const item = el('li', '');
    // On the Korean page an English title shows the Summary's Korean line; the original stays in the tooltip.
    const gloss = lang === 'ko' && m.title && (incident.summary?.titles_ko || []).find((g) => g?.url === m.url && typeof g.title === 'string')?.title;
    const link = anchor(m.url, gloss || m.title || host(m.url));
    if (gloss) link.title = m.title;
    item.append(`${t.mentions[m.kind] ?? m.kind}: `, link);
    mentions.append(item);
  }
  return [...parts, leadLine(incident), mentions];
}

let rowCount = 0;


// One board row: a button that opens the details below it, like opening a post. A Highlight is a framed
// alert edged in its Risk colour, with the details inside the frame.
function row(incident, pinned) {
  const li = el('li', pinned ? `alert risk-${riskLevel(incident)}` : '');
  if (finished(incident.id)) li.classList.add('answered');
  const body = Object.assign(el('div', 'details'), { id: `details-${++rowCount}`, hidden: !open.has(incident.id) });
  const button = Object.assign(el('button', 'row'), { type: 'button' });
  button.setAttribute('aria-controls', body.id);
  button.setAttribute('aria-expanded', !body.hidden);
  const chevron = el('i', 'chev');
  chevron.setAttribute('aria-hidden', 'true');
  const risk = riskCell(incident);
  const why = pinned && pinReason(incident);
  if (why) risk.append(el('small', 'why', TEXT[lang].why[why]));
  const mine = finished(incident.id);
  if (mine) risk.append(markChip(mine));
  const cells = { risk, title: titleCell(incident), score: scoreCell(incident), tags: tagsCell(incident), date: dateCell(incident) };
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
