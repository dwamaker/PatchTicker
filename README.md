<p align="center">
  <img src="docs/assets/logo.svg" width="72" alt="">
</p>

<h1 align="center">Patch Ticker</h1>

<p align="center">
  새로 터진 보안 취약점을, 내가 쓰는 제품 기준으로 빠르게.<br>
  로그인 없이 누구나 보는 한국어 보안 취약점 게시판.
</p>

<p align="center">
  <a href="https://patchticker.dwamaker.com"><b>patchticker.dwamaker.com</b></a>
  &nbsp;·&nbsp;
  <a href="https://github.com/dwamaker/vuln-radar/issues/new">틀린 내용 알리기</a>
  &nbsp;·&nbsp;
  <a href="#english">English</a>
</p>

---

## 이런 분께

보안 뉴스에 새 취약점 소식이 뜨면 궁금한 건 두 가지입니다. **내가 쓰는 것과 상관이 있나?** 있다면 **지금 뭘 해야 하나?**

Patch Ticker는 이 두 질문에 몇 초 안에 답하려고 만들었습니다. 보안 담당자뿐 아니라 집에서 서버를 돌리는 분, 작은 회사의
관리자, 보안을 잘 모르는 분도 쓸 수 있게 했습니다.

## 할 수 있는 일

- **최신순 게시판**: 새 사건이 맨 위에 올라옵니다. 데이터는 10분마다 모이고, 열어 둔 페이지는 새로고침하지 않아도 바뀝니다.
- **주요 사건**: 실제 공격이 확인됐거나 위험도가 높은 사건을 위에 따로 고정해 보여 줍니다.
- **내 제품만 보기**: 쓰는 제품을 고르면 그 제품의 사건만 남습니다. 고른 제품은 내 브라우저에만 저장됩니다.
- **한국어 요약**: 사건마다 무엇이 문제인지, 누가 영향을 받는지, 어떤 조건에서 위험한지, 어떻게 막는지를 정리합니다.
- **쉬운 설명**: 보안 용어 없이 위험도와 "지금 할 일" 하나만 보여 주는 보기입니다.
- **원문 링크**: 모든 내용은 공식 공지와 원문으로 이어집니다. 조치하기 전에는 꼭 원문을 확인하세요.
- **묶음**: 한 회사가 같은 날 한꺼번에 낸 공지, 한 번의 업데이트로 함께 고쳐진 취약점은 한 줄로 묶어 보여 줍니다.
- **CVE 번호가 나오기 전 소식도**: 분석 글이나 메일링 리스트에 먼저 나온 사건도 바로 올리고, 번호가 붙으면 합칩니다.
- **링크 공유**: 사건마다 링크를 복사해 바로 그 사건을 열 수 있습니다. 필터 상태도 주소에 담깁니다.
- 한국어와 영어, 밝은 테마와 어두운 테마, 휴대폰 화면을 지원합니다.

## 위험도는 이렇게 정합니다

위험도는 AI가 아니라 정해진 규칙이 정합니다.

| 표시 | 기준 |
| --- | --- |
| **고위험** | 실제 공격이 확인됨(CISA KEV 목록, 또는 공격을 전한 원문) 또는 CVSS 9.0 이상 |
| **위험** | CVSS 7.0 이상 |
| **참고** | 그 밖의 사건 |

"악용 발생"은 근거가 있을 때만 붙고, 패널에 그 근거(KEV 등재일이나 공격을 전한 원문)를 함께 보여 줍니다. 공격 코드가
공개되기만 한 경우는 "공격 코드 공개됨"으로 따로 알립니다.

## 데이터는 어디서 오나요

| 출처 | 쓰는 곳 |
| --- | --- |
| [CVE 목록 (cvelistV5)](https://github.com/CVEProject/cvelistV5) | 새 CVE, 영향받는 제품과 버전, 공식 공지 링크 |
| [NVD](https://nvd.nist.gov/) | CVSS 점수, 제품 정보 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 실제로 악용된 취약점 |
| [oss-security](https://www.openwall.com/lists/oss-security/), Hacker News, GitHub | CVE 번호가 나오기 전의 소식과 분석 글 |
| 보안 뉴스레터(tl;dr sec, Risky Business News) | 주목받는 사건 |

요약은 Anthropic의 Claude가 위 원문만 읽고 씁니다. 원문에 없는 숫자나 버전이 들어간 요약은 버리고 다시 씁니다.
업데이트 명령어는 원문에 그대로 적혀 있을 때만 보여 줍니다.

## 개인정보

로그인, 쿠키, 방문 분석, 외부 추적기가 없습니다. 고른 제품과 필터는 내 브라우저에만 저장되고 서버로 가지 않습니다.
페이지는 정적 파일이고, 데이터는 공개 JSON 파일입니다.

## 틀린 내용을 발견하면

요약과 판단은 AI가 먼저 하고, 고치는 일은 읽는 분들의 제보로 합니다. 사건을 펼쳐 **틀린 내용 알리기**를 누르면 이
저장소에 사건 정보가 채워진 이슈 양식이 열립니다(GitHub 계정이 필요합니다). [이슈 목록](https://github.com/dwamaker/vuln-radar/issues)에서
직접 남겨도 됩니다.

## 어떻게 돌아가나요

```
수집기 (Docker, 10분마다)  ──쓰기──▶  Cloudflare R2 (공개 JSON)  ◀──읽기──  웹 페이지 (Cloudflare Pages)
   CVE 목록, NVD, KEV,                 월별 사건 파일, status.json            필터와 검색은 브라우저에서
   메일링 리스트, HN, GitHub
```

방문자의 요청에 답하는 서버가 없습니다. 개발과 실행 방법은 [docs/development.md](docs/development.md)에 있습니다.

## 고지

- 이 게시판은 참고용입니다. 조치하기 전에 각 사건의 원문 공지를 확인하세요.
- This product uses data from the NVD API but is not endorsed or certified by the NVD.
- CVE® records: Copyright © 1999–2026, The MITRE Corporation. CVE is a registered trademark of The MITRE Corporation.
  Used under the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse).

---

<h2 id="english">English</h2>

**Patch Ticker** is a free, public, no-login board of security vulnerabilities, Korean first with English alongside.
When news of a vulnerability breaks, it tells you within seconds whether it touches something you run and what to
do next.

- **Newest first, every 10 minutes.** An open page updates without a reload.
- **Your products only.** Pick what you run; the picks stay in your browser.
- **Plain summaries** in Korean and English (what it is, who is affected, when it is dangerous, how to fix it) and an
  **Easy view** with one clear action for non-experts.
- **Risk by rules, not by the model**: exploited (CISA KEV or a source reporting attacks) or CVSS 9.0+ is the top
  level, 7.0+ the next. Exploited is shown only with its evidence.
- **Before a CVE exists**: write-ups and mailing-list posts appear at once and merge when the CVE is assigned.
- **Every claim links to its source.** Commands are shown only when a source states them word for word.
- **No login, no cookies, no analytics, no trackers.**

Data: CVE List (cvelistV5), NVD, CISA KEV, oss-security, Hacker News, GitHub and security newsletters. Summaries are
written by Anthropic's Claude from those sources only.

Found a mistake? Open the Incident and use **Report a mistake**, or [open an issue](https://github.com/dwamaker/vuln-radar/issues/new).
Development notes: [docs/development.md](docs/development.md).
