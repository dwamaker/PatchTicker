"""The number check: the number and version tokens of a text, so a Summary's numbers can be compared with its input's."""

import re
from decimal import Decimal

NUMBER_RE = re.compile(r"\d+(?:\.\d+)*(?:[a-z]+\d+)?", re.IGNORECASE)
# Number words that scale the number before them, so Korean "1억 3,300만" and "$133 million" are one value.
SCALES = {"천": 3, "만": 4, "억": 8, "조": 12, "thousand": 3, "million": 6, "billion": 9, "trillion": 12, "M": 6, "bn": 9}
# Korean pieces add up ("1억 3300만", "7천715"); bare digits count only right after a unit. Never from inside a
# version: "4.3.2만" is "only 4.3.2", not 4. and 3.2만 (11-16: Zephyr rejected for "4.32000").
# 천/만/억/조 is a scale only before a counter ("3만 대", "580만여 명", "1억 2천만 명"): 만 also means "only"
# ("CVE-2026-126067만", "Windows 11만", "TLS 1.3만"), and 조 an article ("제3조") (11-16, Rails; audit F7).
KO_COUNTER = (r"(?=\s?여?\s?(?:명|원|달러|건|개|대|곳|회|번|가구|위안|엔|유로|파운드|배|장|줄|바이트|단어|페이지|행|가지|마리|권|채"
              r"|시간|개월|년|톤|사용자|고객|기업|계정|기기|사이트|서버))")
KO_AMOUNT_RE = re.compile(r"(?<![\d.])(?<![Cc][Vv][Ee]-\d{4}-)\d+(?:\.\d+)?\s?[천만억조]+(?:\s?\d+(?:\.\d+)?\s?[천만억조]+)*(?:\d+(?![\d.]))?"
                          + KO_COUNTER)
KO_PIECE_RE = re.compile(r"(\d+(?:\.\d+)?)\s?([천만억조]*)")
EN_AMOUNT_RE = re.compile(r"(?<![\d.])(\d+(?:\.\d+)?)\s?(thousand|million|billion|trillion|M|bn)\b")


# An English month name is its number, so "October 23" and "10월 23일" agree (owner, 2026-11-10: NIKKE's gist was
# rejected three times for "10"). Short names count only before a day, and "May" only then, so "may" never does.
MONTH_RE = re.compile(r"\b(?:(January|February|March|April|June|July|August|September|October|November|December)\b"
                      r"|(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sept|Sep|Oct|Nov|Dec)\.?(?=\s*\d))")
MONTHS = {m: n for n, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def numbers(text):
    """Number and version tokens, so "1,024" == "1024", "05" == "5", "580만" == "5.8 million" and "October" == "10"."""
    months = {str(MONTHS[(m[1] or m[2])[:3].lower()]) for m in MONTH_RE.finditer(text)}
    # Not \b after the three digits: a Korean counter ("7,715명") is a word character.
    text = re.sub(r"(?<=\d),(?=\d{3}(?!\d))", "", text)
    text = KO_AMOUNT_RE.sub(lambda m: plain(sum(Decimal(n) * 10 ** sum(SCALES[u] for u in units)
                                                for n, units in KO_PIECE_RE.findall(m[0]))), text)
    text = EN_AMOUNT_RE.sub(lambda m: plain(Decimal(m[1]) * 10 ** SCALES[m[2]]), text)
    return {t.lstrip("0") or "0" if t.isdigit() else t.lower() for t in NUMBER_RE.findall(text)} | months


SENTENCE_END = re.compile(r"(?<=[.!?;])\s+|\n")
# A version to install or an amount, never a line: "to 1.19", "1.19로", "1.19 or later", "1.19 이상", "1.5 million".
TARGET_BEFORE = re.compile(r"\bto\s+(?:version\s+)?v?$", re.I)
TARGET_AFTER = re.compile(rf"\s*(?:으?로|이상|이후|\+|or (?:later|higher|newer|above)|and (?:later|above)|(?:{'|'.join(SCALES)})\b)", re.I)
# A line named as a line, with no fix beside it ("A fixed version for the Vault Enterprise 1.20 line is not confirmed").
LINE_WORD = re.compile(r"(?:\.x)?\s*(?:line|branch|series|계열|라인|브랜치|버전대)|\.x(?![A-Za-z0-9])", re.I)  # not \b: "6.3.x와"
WORDED = re.compile(r"line|branch|series|계열|라인|브랜치|버전대", re.I)
# A line word after one or more listed lines ("12.3 및 12.4 계열", "12.0 to 12.3 lines", "6.3.x와 5.19.x 계열").
LINE_AFTER = re.compile(rf"(?:(?:\.x)?\s*(?:,|및|와|과|~|–|and|to|through|or|또는)\s*v?\d+(?:\.\d+)*)*(?:{LINE_WORD.pattern})", re.I)


def without_line_names(text, fixed, known):
    """text without the product lines a sentence names beside a version of that line ("the 26.1 line to 26.1.11",
    "10.2.7 for 10.2", "the 1.19 line needs 1.19.26"): a dotted prefix of one of the reply's fixed versions (fixed),
    where the same sentence names an input version (known) that starts with it, or a prefix of an input version followed
    by a line word ("the 1.20 line", "1.20 계열", "1.20.x"), also a major alone ("the 48 line", "16 라인" beside 48.0.7,
    16.20.1) and each of several lines before one line word ("12.3 및 12.4 계열", 11-16 night: these kept Wasmtime,
    Frappe HRMS and GitLab Summaries old for three tries). Both are numbers() tokens. A prefix as the version to install
    ("update to 1.19", "1.19 or later") or a count ("4건") stays, so the number check still rejects it."""
    def line(token, versions):
        return any(v.startswith(f"{token}.") for v in versions)

    def strip(sentence):
        here = numbers(sentence) & known

        def name(m):
            t = m[0].lower()
            after = LINE_AFTER.match(sentence, m.end())
            # A line word names a line; a bare ".x" ("Update 26.1.x to 26.1.11") also needs the reply's own fix on it.
            if after and line(t, known) and (WORDED.search(after[0]) or line(t, fixed)):
                return True
            return ("." in t and not TARGET_BEFORE.search(sentence[:m.start()]) and not TARGET_AFTER.match(sentence, m.end())
                    and line(t, fixed) and line(t, here))
        return NUMBER_RE.sub(lambda m: " " if name(m) else m[0], sentence)
    return "\n".join(map(strip, SENTENCE_END.split(text)))


def plain(value):
    return f"{value.normalize():f}"  # 133000000, not 1.33E+8


# Owner, 2026-11-10: Korean words whose digit is part of the word, not a number ("제3자", third party: CVE-2026-106007
# failed three times on it). To add one, append the whole word; never a pattern, so "3자리" stays a number.
# 11-19: the Korean for MFA, which the Easy view may not write as "MFA" (EASY_BANNED): CVE-2026-16021's group was given
# up on "2단계 인증" and "2단계 로그인" where no input version held a bare 2.
KO_DIGIT_WORDS = ("제3자", "2단계 인증", "2단계인증", "2단계 로그인", "2차 인증", "2차인증", "2FA")
KO_DIGIT_WORD_RE = re.compile("|".join(map(re.escape, KO_DIGIT_WORDS)))


def ko_numbers(text):
    """numbers() of Korean text, without the digits of KO_DIGIT_WORDS ("제3자에게" has none)."""
    return numbers(KO_DIGIT_WORD_RE.sub(" ", text))


# Owner, 2026-11-10: a per-CVE line may write as a digit a number its CVE's description spells ("division by zero",
# "eight-byte" -> "0", "8"); the check stays exact otherwise. Owner, 2026-11-11: the Summary's check (parse) and the
# quick titles' (title_now) allow it too, from their own input (CVE-2026-58805: "zero arbitrary secure memory" -> "0").
# No "one": it is a pronoun far too often ("one of", "no one") and would let any "1" through; only before a unit it is
# the number (httpd's "1바이트" beside "a one-byte overwrite", "by one byte" was refused in every trial round).
NUMBER_WORDS = {w: str(n) for n, w in enumerate("zero one two three four five six seven eight nine ten eleven twelve".split()) if w != "one"}
NUMBER_WORD_RE = re.compile(rf"\b(?:{'|'.join(NUMBER_WORDS)}|one(?=[\s-](?:byte|bit|character)s?\b))\b", re.I)


def number_words(text):
    return {NUMBER_WORDS.get(w.lower(), "1") for w in NUMBER_WORD_RE.findall(text)}
