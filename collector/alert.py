"""Cycle failure alerts (owner, 11-16: a bug that would have ended every cycle was found by hand; nothing would have
told the owner). compose.yaml's loop runs `python -m collector --cycle-end <exit code>` after every cycle, so a cycle
killed by its 50-minute timeout (no Python handler runs) is reported like one that raised. main() leaves the uncaught
exception's type and first line in the state file for that step. The state file sits beside VR_BACKUP_DB (the /backup
volume), so the count survives a failing store (R2). The first failure posts at once, then at most one line an hour
while they continue, and one line when a cycle succeeds again."""

import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

STATE_FILE = "cycle_alert.json"
TIMEOUT_S = 3000  # compose.yaml's `timeout -k 60 3000` (a test keeps them equal)
TIMED_OUT = 124  # timeout(1)'s exit code when it stopped the cycle
REPEAT = timedelta(hours=1)
REASON_CHARS = 200
KST = timezone(timedelta(hours=9))
HEAD = "Patch Ticker 수집기:"
# A URL's query string or fragment, which may hold a token (?X-Amz-Signature=..., ?key=...).
QUERY = re.compile(r"(\b[a-z][\w+.-]*://[^\s?#'\"<>]*)[?#][^\s'\"<>]*", re.I)


def state_path(settings):
    """Beside the SQLite backup when there is one (the container's /backup), else the temp folder."""
    db = settings.get("VR_BACKUP_DB")
    return Path(db).parent / STATE_FILE if db else Path(tempfile.gettempdir()) / STATE_FILE


def clean(text):
    """Text from an exception, safe to post: no environment value (secrets come from there), no query string, one
    line, at most REASON_CHARS characters."""
    text = str(text)
    for value in sorted({v for v in os.environ.values() if len(v) >= 8}, key=len, reverse=True):
        text = text.replace(value, "…")
    line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    return QUERY.sub(r"\1", line)[:REASON_CHARS]


def read(path):
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def write(path, state):
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as err:
        print(f"alert: state not saved: {type(err).__name__}", file=sys.stderr)


def record_error(path, err, now):
    """Called by main() as an uncaught exception leaves the cycle; never raises."""
    try:
        reason = clean(f"{type(err).__name__}: {err}" if str(err) else type(err).__name__)
        write(path, read(path) | {"error": {"reason": reason, "at": stamp(now)}})
    except Exception as failure:  # noqa: BLE001 - the cycle's own exception must be the one that ends it
        print(f"alert: error not recorded: {type(failure).__name__}", file=sys.stderr)


def cycle_end(path, code, notify, now):
    """After a cycle that exited with code: count it and post when due. notify: discord.make_notifier's function, or
    None (nothing is counted or posted). Returns the line posted, or ""."""
    if notify is None:
        return ""
    state = read(path)
    error = state.pop("error", None)
    failed = state.get("failed", 0) if isinstance(state.get("failed"), int) else 0
    if code == 0:
        write(path, {})
        if not failed:
            return ""
        return post(notify, f"{HEAD} 수집 주기 복구 · {failed}회 연속 실패 뒤 성공 · {kst(now)}")
    how = (f"제한 시간 {TIMEOUT_S}초 초과" if code == TIMED_OUT
           else f"`{error['reason'].replace('`', chr(39))}`" if isinstance(error, dict) and error.get("reason")
           else f"종료 코드 {code}")
    state |= {"failed": failed + 1, "since": state.get("since") or stamp(now), "last": how}
    line = ""
    if failed == 0:
        line = f"{HEAD} 수집 주기 실패 · {how} · {kst(now)}"
    elif now - parse(state.get("posted")) >= REPEAT:
        line = f"{HEAD} 수집 주기 {failed + 1}회 연속 실패 · {kst(parse(state['since']))}부터 · 마지막: {how}"
    if line:
        state["posted"] = stamp(now)
        post(notify, line)
    write(path, state)
    return line


def post(notify, line):
    try:
        notify(line)
    except Exception as err:  # noqa: BLE001 - an alert never changes a cycle's outcome
        print(f"alert: post failed: {type(err).__name__}", file=sys.stderr)
    return line


def stamp(now):
    return now.astimezone(timezone.utc).isoformat()


def parse(text):
    try:
        return datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)


def kst(now):
    return now.astimezone(KST).strftime("%Y-%m-%d %H:%M KST")


TEST_LINE = f"{HEAD} 알림 시험 · 손으로 보낸 줄이며 수집 주기 실패가 아닙니다"
