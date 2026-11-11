<p align="center">
  <a href="https://patchticker.com"><img src="docs/assets/logo.svg" width="88" alt="Patch Ticker 로고"></a>
</p>

<h1 align="center">Patch Ticker</h1>

<p align="center"><a href="README.md"><b>English</b></a> | <b>한국어</b></p>

<p align="center">
  <b>새로 터진 보안 취약점을, 내가 쓰는 제품 기준으로 빠르게.</b><br>
  로그인 없이 누구나 보는 한국어 실시간 보안 취약점 현황판.
</p>

<p align="center">
  <a href="https://patchticker.com"><img src="https://img.shields.io/badge/live-patchticker.com-1a5fb4?style=for-the-badge" alt="사이트: patchticker.com"></a>
  <img src="https://img.shields.io/badge/updates-every%2010%20min-2e7d32?style=for-the-badge" alt="10분마다 갱신">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-555?style=for-the-badge" alt="라이선스: MIT"></a>
</p>

<p align="center">
  <em>도움이 되셨다면 커피 한 잔으로 응원해 주세요.</em><br>
  <a href="https://buymeacoffee.com/dwamaker"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buymeacoffee&logoColor=black" alt="Buy Me a Coffee"></a>
</p>

<p align="center">
  <a href="https://patchticker.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/screenshot-ko-dark.png">
      <img src="docs/assets/screenshot-ko-light.png" width="860" alt="Patch Ticker 현황판: 위에 주요 사건, 사건마다 위험도와 CVSS 점수, 제품 표시">
    </picture>
  </a>
</p>

## 왜 만들었나요

보안 뉴스에 새 취약점이 뜨면 궁금한 건 두 가지입니다. **내가 쓰는 것과 상관이 있나**, 있다면 **지금 뭘 해야 하나**.
Patch Ticker는 이 두 질문에 몇 초 안에 답합니다. 보안 담당자뿐 아니라 집에서 서버를 돌리는 분, 작은 회사의 관리자,
보안을 잘 모르는 분도 쓸 수 있게 만들었습니다.

## 할 수 있는 일

- **실시간 최신순**: 10분마다 모으고, 열어 둔 페이지는 새로고침 없이 바뀝니다.
- **내 제품만 보기**: 쓰는 제품을 고르면 그 제품의 사건만 남습니다. 고른 제품은 내 브라우저에만 저장됩니다.
- **부르는 이름 그대로 검색**: 아웃룩, 파폭, vscode처럼 평소 쓰는 이름으로 Outlook, Firefox, Visual Studio Code를 찾습니다.
- **한국어 요약**: 무엇이 문제인지, 누가 영향을 받는지, 언제 위험한지, 어떻게 막는지 정리합니다.
- **쉬운 설명**: 보안 용어 없이 위험도와 "지금 할 일" 하나만 보여 줍니다.
- **CVE 번호가 나오기 전에도**: 분석 글과 메일링 리스트 소식을 바로 올리고, 번호가 붙으면 합칩니다.
- **묶음**: 한 회사가 같은 날 낸 공지, 한 번의 업데이트로 함께 고쳐진 취약점은 한 줄로 묶습니다.
- **모든 내용은 원문으로**: 업데이트 명령어는 원문에 그대로 적혀 있을 때만 보여 줍니다.
- **공유하기 쉽게**: 요약이 있는 사건마다 따로 페이지와 주소가 있고, 필터도 주소에 담깁니다. 밝은·어두운 테마, 휴대폰 화면을 지원합니다.
- **RSS 구독**: 위험 이상, 실제 악용, CVE 없는 새 사건을 [한국어](https://patchticker.com/feed.xml)와 [영어](https://patchticker.com/en/feed.xml) 피드로 받습니다.
- **AI 에이전트용 주소**: `GET https://patchticker.com/api/check?products=openssh,크롬`에 쓰는 제품 이름을 보내면 해당하는
  사건을 JSON으로 답합니다. 쓰는 법은 [llms.txt](https://patchticker.com/llms.txt)에 있습니다.

## 위험도

위험도는 AI가 아니라 정해진 규칙이 정합니다.

| 표시 | 기준 |
| --- | --- |
| **고위험** | 실제 공격 확인(CISA KEV, 또는 공격을 전한 원문) 또는 CVSS 9.0 이상 |
| **위험** | CVSS 7.0 이상 |
| **참고** | 그 밖의 사건 |

"악용 발생"에는 항상 근거가 함께 표시됩니다. 공격 코드가 공개되기만 한 경우는 "공격 코드 공개됨"으로 따로 알립니다.

## 데이터 출처

| 출처 | 쓰는 곳 |
| --- | --- |
| [CVE 목록 (cvelistV5)](https://github.com/CVEProject/cvelistV5) | 새 CVE, 영향받는 제품과 버전, 공식 공지 |
| [NVD](https://nvd.nist.gov/) | CVSS 점수, 제품 정보 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 실제로 악용된 취약점 |
| [oss-security](https://www.openwall.com/lists/oss-security/), Hacker News, GitHub | CVE 번호가 나오기 전의 소식과 분석 글 |
| tl;dr sec, Risky Business News | 주목받는 사건 |
| [BleepingComputer](https://www.bleepingcomputer.com/), [SecurityWeek](https://www.securityweek.com/) | 뉴스로 먼저 알려진 공격과 해킹 (CVE 번호가 없는 경우가 많음) |
| [KISA 보호나라](https://www.boho.or.kr/) | 사건의 CVE에 대한 한국어 보안 공지 |

요약은 Anthropic의 Claude가 위 원문만 읽고 씁니다. 원문에 없는 숫자나 버전이 들어간 요약은 버리고 다시 씁니다.
`/api/check`에서 일치하는 제품이 없는 이름은 Cloudflare Workers AI의 Llama 3.3이 읽어 영어 제품 이름만 추측합니다. 일치 여부는
우리 색인이 정하고, 그렇게 찾은 결과는 `maybe`로 따로 표시합니다.

## 개인정보

로그인, 쿠키, 광고 추적기가 없습니다. 방문 수는 Cloudflare Web Analytics가 익명으로 셉니다(쿠키 없음, 개인정보 없음).
고른 제품과 필터는 내 브라우저 밖으로 나가지 않습니다. `/api/check`는 요청 내용을 저장하지 않고, 일치하지 않은 이름만 위 모델로
보냅니다.

## 틀린 내용을 발견하면

사건을 펼쳐 **틀린 내용 알리기**를 누르면, 사건 정보가 채워진 이슈 양식이 이 저장소에 열립니다.
[이슈 목록](https://github.com/dwamaker/PatchTicker/issues)에서 직접 남겨도 됩니다.

## 작동 방식

```
수집기 (Docker, 10분마다)  ──쓰기──▶  Cloudflare R2 (공개 JSON)  ◀──읽기──  웹 페이지 (Cloudflare Pages)
   CVE 목록, NVD, KEV,                 월별 사건 파일, status.json            필터와 검색은 브라우저에서
   메일링 리스트, HN, GitHub
```

방문자의 요청에 답하는 우리 서버는 없습니다. 페이지는 공개 파일을 읽고, 사건 페이지와 RSS, 홈 화면의 링크 목록, `/api/check`는
Cloudflare Pages Functions가 같은 파일로 만듭니다. 직접 실행하는 법: [docs/development.md](docs/development.md).

## 고지와 라이선스

- 이 현황판은 참고용입니다. 조치하기 전에 각 사건의 원문 공지를 확인하세요. 사건은 최대 90일까지만 보관합니다.
- This product uses data from the NVD API but is not endorsed or certified by the NVD.
- CVE® records: Copyright © 1999–2026, The MITRE Corporation. CVE is a registered trademark of The MITRE Corporation.
  Used under the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse).
- 코드는 [MIT 라이선스](LICENSE)를 따릅니다. CVE와 NVD 데이터는 각자의 이용 조건을 따르고, 수집한 데이터와 요약문은
  이 라이선스에 포함되지 않습니다.
