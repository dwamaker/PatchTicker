# Security

[한국어](#한국어)

## Reporting a vulnerability in Patch Ticker

If you find a security problem in this code or on patchticker.com (for example a way to inject content into a
page, to make the site serve wrong data, or to abuse `/api/check`), please report it privately:

**[Report a vulnerability](https://github.com/dwamaker/PatchTicker/security/advisories/new)** (GitHub's private
reporting form; only the maintainer sees it).

Please do not open a public issue for it. Say what you did, what happened and what you expected; a short proof is
enough. The answer comes in the same form.

## Not a security report

- A wrong summary, title, product or risk level on the site: press **Report a mistake** on the Incident, or open an
  [issue](https://github.com/dwamaker/PatchTicker/issues).
- A vulnerability in some other product: report it to that product's vendor. Patch Ticker only collects what is
  already public.

## What is in scope

The code in this repository and the site it runs: the page, the Cloudflare Pages Functions (Incident pages, feeds,
`/api/check`) and the collector. The data comes from public sources; a mistake in a source is not a vulnerability
here.

---

## 한국어

### Patch Ticker의 취약점을 알리려면

이 코드나 patchticker.com에서 보안 문제를 찾으셨다면(예: 페이지에 내용을 끼워 넣는 방법, 잘못된 데이터를 내보내게 하는
방법, `/api/check`를 악용하는 방법) 공개 이슈 대신 비공개로 알려 주세요.

**[취약점 신고하기](https://github.com/dwamaker/PatchTicker/security/advisories/new)** (GitHub의 비공개 신고 양식이며
관리자만 볼 수 있습니다.)

무엇을 했고, 어떤 일이 일어났고, 무엇을 기대했는지 적어 주세요. 짧은 재현 방법이면 충분합니다. 답은 그 양식에서
드립니다.

### 보안 신고가 아닌 것

- 사이트의 요약, 제목, 제품, 위험도가 틀린 경우: 사건의 **틀린 내용 알리기**를 누르거나
  [이슈](https://github.com/dwamaker/PatchTicker/issues)를 남겨 주세요.
- 다른 제품의 취약점: 그 제품의 제조사에 알려 주세요. Patch Ticker는 이미 공개된 내용만 모읍니다.

### 범위

이 저장소의 코드와 그것으로 돌아가는 사이트입니다. 페이지, Cloudflare Pages Functions(사건 페이지, RSS, `/api/check`),
수집기가 해당합니다. 데이터는 공개 출처에서 오므로, 출처의 오류는 이곳의 취약점이 아닙니다.
