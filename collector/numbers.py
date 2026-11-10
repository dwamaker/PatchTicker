"""The number check: the number and version tokens of a text, so a Summary's numbers can be compared with its input's."""

import re
from decimal import Decimal

NUMBER_RE = re.compile(r"\d+(?:\.\d+)*(?:[a-z]+\d+)?", re.IGNORECASE)
# Number words that scale the number before them, so Korean "1억 3,300만" and "$133 million" are one value.
SCALES = {"천": 3, "만": 4, "억": 8, "조": 12, "thousand": 3, "million": 6, "billion": 9, "trillion": 12, "M": 6, "bn": 9}
# Korean pieces add up ("1억 3300만", "7천715"); bare digits count only right after a unit.
KO_AMOUNT_RE = re.compile(r"\d+(?:\.\d+)?\s?[천만억조]+(?:\s?\d+(?:\.\d+)?\s?[천만억조]+)*(?:\d+(?![\d.]))?")
KO_PIECE_RE = re.compile(r"(\d+(?:\.\d+)?)\s?([천만억조]*)")
EN_AMOUNT_RE = re.compile(r"(\d+(?:\.\d+)?)\s?(thousand|million|billion|trillion|M|bn)\b")


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


def plain(value):
    return f"{value.normalize():f}"  # 133000000, not 1.33E+8


# Owner, 2026-11-10: Korean words whose digit is part of the word, not a number ("제3자", third party: CVE-2026-106007
# failed three times on it). To add one, append the whole word; never a pattern, so "3자리" stays a number.
KO_DIGIT_WORDS = ("제3자",)
KO_DIGIT_WORD_RE = re.compile("|".join(map(re.escape, KO_DIGIT_WORDS)))


def ko_numbers(text):
    """numbers() of Korean text, without the digits of KO_DIGIT_WORDS ("제3자에게" has none)."""
    return numbers(KO_DIGIT_WORD_RE.sub(" ", text))


# Owner, 2026-11-10: a per-CVE line may write as a digit a number its CVE's description spells ("division by zero",
# "eight-byte" -> "0", "8"); the check stays exact otherwise. Only save_lines uses it, never the Summary's check.
# No "one": it is a pronoun far too often ("one of", "no one") and would let any "1" through.
NUMBER_WORDS = {w: str(n) for n, w in enumerate("zero one two three four five six seven eight nine ten eleven twelve".split()) if w != "one"}
NUMBER_WORD_RE = re.compile(rf"\b(?:{'|'.join(NUMBER_WORDS)})\b", re.I)


def number_words(text):
    return {NUMBER_WORDS[w.lower()] for w in NUMBER_WORD_RE.findall(text)}
