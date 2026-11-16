"""What every request to the model and every reply check shares: the model, its limits, the reply's JSON and CVE IDs."""

import json
import re

MODEL = "claude-haiku-5-5"
# Decided by the 2026-11-07 low vs medium comparison (plan.md).
EFFORT = "low"
# Thinking counts toward max_tokens on Haiku 5.5; replies measured 500-900 tokens, but SonicWall's 38 models (listed in
# devices and again per fix line) ran past 4000 on 11-08. A cap, not a charge: only tokens used are billed.
MAX_TOKENS = 8000
MAX_TOKENS_RETRY = 16000  # once a reply was cut off at MAX_TOKENS, every later try gets this much room (7 such on 11-10)
# 11-16: a group's reply carries per-CVE conditions and up to twelve per-CVE lines in two languages; 23 of 228 group
# replies ran past 8000 and 3 past 16000 (Zephyr's 13 CVEs were given up). Haiku 5.5 takes up to 128K; past 21,333 the
# SDK refuses a plain (non-streaming) create unless the call names its timeout, so the instant path passes REQUEST_TIMEOUT.
MAX_TOKENS_GROUP = 32000
REQUEST_TIMEOUT = 600  # seconds: the SDK's own default for a non-streaming request
# shortcut: at most this many batch requests per cycle (each fetches up to three pages for its input), and only Incidents
# first seen in the last summaries.BATCH_DAYS; raise both if a backlog after a pause clears too slowly.
MAX_PER_BATCH = 200
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


def reply_json(reply):
    """The JSON in a reply's first text block; raises StopIteration or ValueError for the caller to report."""
    return json.loads(next(b.text for b in reply.content if b.type == "text"))
