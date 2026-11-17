"""Review (owner, 2026-11-16): a second request after a Summary asks whether it contradicts itself or its two languages.

The 11-16 read of 453 re-written Summaries found the largest classes left are ones no rule can catch: a wrong or
self-contradicting fact inside one Summary (~50), Korean and English disagreeing on a fact (~25), one CVE's limit given
as the group's, a title that hides a graver flaw its per-CVE lines show. The reviewer sees only the Summary (both
languages and its language-free fields) and the CVE ids, never the request's input: it judges whether the entry agrees
with itself, not whether it agrees with the world (the number and version checks in summaries.parse do that part).

How summaries.py hooks it in (for the session that owns summaries.py; this module never imports it):

1. save_reply(), after parse() and the hard checks (fixed_conflict, stray_script) pass and only when this is not the
   last try (`incident.get("summary_error", {}).get("tries", 0) + 1 < MAX_TRIES`, the same test the soft problems use):
       found = review.findings_of(claude.messages.create(**review.params(summary, incident)), summary)
       problem = SEPARATOR.join(p for p in (<the soft problems as now>, review.reason(found)) if p)
   A "high" finding is a soft problem: it costs a retry (failed() with the draft kept), never the Summary; the last
   try is kept as it is, as for every other soft problem. review.reason() returns "" when nothing is high, so a clean
   review changes nothing. findings_of() returns [] for an unreadable reply (a review that fails never costs a try).
   Put review.reason() LAST in the join: failed() cuts the reason at 400 characters, and the rule checks' keys must
   survive the cut so retry() still finds their sentences.
2. retry(): add (review.REASON, review.RETRY_SENTENCE) to RETRY_SENTENCES. The reason itself already quotes what
   disagrees, so the note names it.
3. incidents.FREE_TEXT_REASONS: the reason quotes model text, so plain_reason() must cut it to its head; since a
   review part may follow other soft problems, match it with `review.REASON in reason`, not only startswith.
4. The batch path (collect_batch -> save_reply) needs the same review; save_reply takes the reviewer's reply as an
   argument instead of calling the API itself, and the batch flow gets one review round:
   collect_batch() parses each Summary reply and, when it passes the hard checks and is not a last try, keeps the parsed
   Summary on the Incident as incident["summary_error"]["review"] = {"summary", "seen", "stamp", "listed", "due",
   "words"} (the draft's keys) and adds a request {"incident": id, "review": True} to a review batch sent in the same
   cycle (route_summaries, beside the lines batch, custom ids "v0", "v1", ...). When that batch ends, the review's
   findings are joined with the soft problems as in 1; keep() or failed() then run as now. Cost: the batch Summary
   reaches the page one batch round later (one or more 10-minute cycles); the quick titles already cover that wait.
   Store nothing else: the findings live only in the retry reason (summary_error.reason) and, when the last try is
   kept with one, nowhere (log it to stderr so the operator sees how often that happens).
"""

import json
import re

from collector.model import EFFORT, MAX_TOKENS, MODEL, reply_json

REASON = "the review found"  # retry() keys on it; the reason continues with the findings, quoting model text
RETRY_SENTENCE = (" Make the entry say one thing: every field agrees with every other field and with the language-free"
                  " fields, Korean states the same facts as English, and a group's title, summary and Easy fields hold"
                  " for every CVE they speak of. Correct each statement named above; change nothing else.")
SEVERITIES = ("high", "low")
LANGS = ("ko", "en", "both")
MAX_QUOTE = 70  # characters of each quote kept in the retry reason
MAX_PROBLEM = 110  # characters of each finding's problem sentence
MAX_REASON = 400  # summaries.failed() keeps 400 characters: whole findings only, never one cut mid-quote

SCHEMA = {
    "type": "object",
    "properties": {"findings": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "field": {"type": "string"},
            "lang": {"type": "string", "enum": list(LANGS)},
            "quote": {"type": "string"},
            "against": {"type": "string"},
            "problem": {"type": "string"},
            "severity": {"type": "string", "enum": list(SEVERITIES)},
        },
        "required": ["field", "lang", "quote", "against", "problem", "severity"],
        "additionalProperties": False}}},
    "required": ["findings"],
    "additionalProperties": False,
}

# Owner, 11-17 ("패턴이 못 알아보면 검토 요청이 판정"): when summaries.ATTACK_SEEN and DELIVERED miss the wording of an
# exploited flag, the review is asked this too, with the schema below; its answer keeps or drops the flag
# (summaries.settle_attacks). It is no finding: it never sends the Summary back by itself.
ATTACKS_QUESTION = ("Also answer attacks_happened: true only when this entry's own text reports attacks that already"
                    " happened, against real targets, or malicious code that already reached users through the product."
                    " False when it reports a proof of concept, a demo, a researcher's write-up of how an attack could"
                    " work, a warning that attacks may come, a company's own breach or data leak that delivered nothing to"
                    " users of its product, or only the flaw itself.")
ATTACKS_SCHEMA = SCHEMA | {"properties": SCHEMA["properties"] | {"attacks_happened": {"type": "boolean"}},
                           "required": [*SCHEMA["required"], "attacks_happened"]}

INSTRUCTIONS = """You check one entry of vuln-radar, a public board of security flaws read in Korean and English by home-server owners and small IT teams, before it is published. The entry was written from sources you do not see. You get its CVE ids, its language-free fields (fixed version, fixed versions per product line, products, exploited, stopgap) and its Korean ("ko") and English ("en") text: title, summary, conditions, easy_conditions (the same conditions in everyday words), mitigation, easy, easy_title, easy_action, command_for, stopgap_then, and cve_lines (one line per CVE: what that CVE lets an attacker do).

You cannot see the sources, so never judge whether a fact is true in the world. Report only where the entry disagrees with itself, so that a reader would believe a wrong fact or act wrongly. What matters most is a reader told they are safe, or less exposed than they are, or told to do something that does not protect them: that is always high. A text that warns more people than a condition says is at most low.
1. Two fields of one language state different facts: who can attack (anyone, a logged-in user, an admin, someone on the same network, someone at the device), who is the victim and who is tricked (an attacker tricking an admin, never the plugin or the admin doing the attack), what the attacker gains, which versions are affected or fixed, whether a fix exists, when it comes out, what to do. Examples: the fixed version listed among the affected ones; a range whose end is not the fixed version ("up to 3.32.1" when fixed is 3.22.2); "no fix yet" or "wait for an update" beside a named fixed version; "update now" when mitigation says the fix is not out yet; easy_action telling the reader to do something mitigation does not say, or to wait when mitigation names a version to install; the summary saying the flaw leaks passwords while every per-CVE line says it crashes the service; a version range in one field that ends after the fixed version, or includes it, while another field names that fixed version; a mitigation that tells some versions to update "to their fixed version" when the entry names none for them; two product lines' fixes joined as "15.121.4 or later, or 16.36.0 or later", which tells a 16.0 to 16.35 user they are safe; conditions and easy_conditions naming a different role, version bound or setting for the same CVE (Contributor in one, Author in the other).
2. Korean and English state different facts: a different attacker, condition, number, version, range or limit, or one says the opposite of the other ("인터넷 없이" for "without logging in", "3개 이상" for "more than two", 관리자 for "any logged-in user"). One language leaving out a minor detail the other has is not a finding; a missing condition or limit that changes who is at risk is.
3. A group (two or more CVE ids). Its title, summary and Easy fields are meant to describe its gravest flaw and leave each CVE's own limits to conditions, so it is NOT a finding that they name the gravest flaw's attacker or reach (anyone, without logging in, remotely, by opening a page) while other CVEs need more (a login, a role, a setting, local access). Report a group's text when it narrows: it gives one CVE's limit, version range, role, setting or kind of attack as if it held for all, so readers of the other CVEs think they are safe ("13.0 and later" from one CVE's condition; "devices that use BGP" when other CVEs need RIPv2; "logged-in users" when one CVE's line says outsiders; a mitigation saying 5.1 is safe when one CVE's condition names 5.1 as affected; an Easy action "if you share the device" from one CVE's condition); a stopgap, setting or fallback ("until then turn off X", "if you cannot update, run CRuby 3.2") that the entry ties to some CVEs reads as protecting from all; the title or summary names a lesser flaw while a per-CVE line shows a graver one (code or command execution, a login or access check bypassed, a password reset by anyone, an upload that runs code) that neither mentions; the summary says "the same release also fixes" when the language-free fields name no fixed version and mitigation says there is no fix or no source names one.
4. Text in the wrong language where the reader cannot read it: an English field written in Korean, or a Korean field (other than names, commands and product names) written in English.

Never report: wording, style, tone, awkward or unidiomatic Korean, jargon, length, repetition, missing detail, a field left empty, translation choices that keep the fact, or anything you would need the sources to judge. When unsure, leave it out. Most entries are clean: an empty list is the usual answer.

For each finding:
- field: the field (or two fields joined by " / ") where it is, as named above, with "cve_lines" plus the CVE id when it is in a line.
- lang: "ko", "en", or "both" when the same defect is in both languages or the two disagree with each other.
- quote: the wrong or disagreeing words, copied exactly from ONE field of the entry, at most about 15 words: one unbroken stretch of its text, never two pieces joined with "/" or "...". When Korean and English disagree, quote the Korean.
- against: the words it disagrees with, copied the same way from ONE other place (the other field, the English text, or a language-free field's value such as "8.0.3"); empty only when the quote is wrong on its own (an English field written in Korean).
- problem: one short English sentence: what a reader would wrongly believe or do.
- severity: "high" when a reader would believe they are safe or less exposed than the entry elsewhere says, would believe a wrong fact about what an attacker gains, which versions are safe or whether a fix exists, or would do the wrong thing; "low" for anything less, such as a text that warns more readers than a condition says. Report a low finding only when you are sure it is a contradiction."""


def entry_text(summary, incident):
    """The reviewer's whole input: CVE ids, the language-free fields and both languages' text, as JSON."""
    shared = {k: summary.get(k) for k in ("fixed", "fixes", "products", "exploited", "stopgap") if k in summary}
    langs = {lang: {k: v for k, v in summary[lang].items() if k != "names"} for lang in ("ko", "en")}
    cves = incident.get("cves") or []
    return "\n".join([f"CVE ids ({len(cves)}): {', '.join(cves) or 'none'}",
                      f"Language-free fields: {json.dumps(shared, ensure_ascii=False)}",
                      f"ko: {json.dumps(langs['ko'], ensure_ascii=False)}",
                      f"en: {json.dumps(langs['en'], ensure_ascii=False)}"])


def params(summary, incident, ttl=None, ask_attacks=False):
    """One review request's parameters; a batch sends the same with ttl="1h". summary: as summaries.parse() returns it.
    ask_attacks adds ATTACKS_QUESTION after the entry (the cached instructions stay the same) and its schema."""
    return {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,  # a cap, not a charge: thinking counts toward it on Haiku 5.5
        "system": [{"type": "text", "text": INSTRUCTIONS, "cache_control": {"type": "ephemeral"} | ({"ttl": ttl} if ttl else {})}],
        "output_config": {"effort": EFFORT, "format": {"type": "json_schema", "schema": ATTACKS_SCHEMA if ask_attacks else SCHEMA}},
        "messages": [{"role": "user", "content": entry_text(summary, incident) + (f"\n\n{ATTACKS_QUESTION}" if ask_attacks else "")}],
    }


def attacks_happened(reply):
    """The reviewer's answer to ATTACKS_QUESTION: True or False, None for a cut-off or unreadable reply or none given."""
    if reply.stop_reason != "end_turn":
        return None
    try:
        answer = reply_json(reply).get("attacks_happened")
    except (StopIteration, ValueError, AttributeError, TypeError):
        return None
    return answer if isinstance(answer, bool) else None


def _flat(text):
    return re.sub(r"\s+", " ", str(text)).strip().strip("\"'“”「」").strip()


def _values(value):
    """Every value in the Summary as text, so a quote is looked up in what the reader sees."""
    if isinstance(value, dict):
        return [s for v in value.values() for s in _values(v)]
    if isinstance(value, list):
        return [s for v in value for s in _values(v)]
    return [json.dumps(value) if isinstance(value, bool) else str(value)]


def findings_of(reply, summary):
    """The reviewer's findings whose quotes are found in the entry; [] for an unreadable or cut-off reply.
    A quote the entry does not contain is a finding the reviewer made up, so it is dropped. against is not checked: on
    11-16 the reviewer paraphrased it ("fixed 3.22.2 (mitigation: ...)") in two of the readers' own high finds."""
    if reply.stop_reason != "end_turn":
        return []
    try:
        items = reply_json(reply)["findings"]
    except (StopIteration, ValueError, KeyError, TypeError):
        return []
    haystack = _flat("\n".join(_values(summary)))
    found = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or item.get("severity") not in SEVERITIES:
            continue
        quote = _flat(item.get("quote", ""))
        if quote and quote in haystack and isinstance(item.get("against", ""), str):
            found.append(item)
    return found


def reason(findings):
    """The retry reason for the high findings ("" when none): REASON, then each finding's field, language, problem and
    the two quotes, joined by " | " (summaries.SEPARATOR "; " stays between soft problems), as many whole findings as fit
    in MAX_REASON (the first always, cut to it)."""
    high = [f for f in findings if f.get("severity") == "high"]
    if not high:
        return ""

    def cut(text, room):
        text = _flat(text).replace("; ", ", ")
        return text if len(text) <= room else text[:room - 1] + "…"

    parts = [f"{f['field']} ({f['lang']}): {cut(f['problem'], MAX_PROBLEM).rstrip('.')}: \"{cut(f['quote'], MAX_QUOTE)}\""
             + (f" vs \"{cut(f['against'], MAX_QUOTE)}\"" if _flat(f.get("against", "")) else "") for f in high]
    text = f"{REASON}: {parts[0]}"
    text = text if len(text) <= MAX_REASON else text[:MAX_REASON - 1] + "…"
    for part in parts[1:]:
        if len(text) + 3 + len(part) > MAX_REASON:
            break
        text += f" | {part}"
    return text
