"""The lasting log (owner, 11-18: "앞으로 로그 따로 남기게 해"; a redeploy recreates the container and its output, the
only log, went with it). With VR_LOG_DIR set, everything the collector prints also goes, line by line with a UTC time,
into one file a day there (collector-YYYY-MM-DD.log), files older than KEEP_DAYS are deleted and a day's file stops at
DAY_BYTES; the container's own output stays as it was. Each cycle ends with one `cycle` line (CycleLine). No setting
value that is a secret ever reaches the file (SECRETS)."""

import atexit
import sys
import urllib.error
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

KEEP_DAYS = 30
DAY_BYTES = 20 << 20  # a usual day is well under 1 MB; 30 full days are 600 MB at most
PREFIX, SUFFIX = "collector-", ".log"
# Settings never written to the file, should any message carry one (the webhook's path is its secret).
SECRETS = ("ANTHROPIC_API_KEY", "VR_DISCORD_WEBHOOK", "VR_R2_ENDPOINT", "VR_R2_ACCESS_KEY_ID", "VR_R2_SECRET_ACCESS_KEY",
           "VR_NVD_API_KEY", "VR_GITHUB_TOKEN", "VR_INDEXNOW_KEY")
REFUSED = (401, 403, 429)  # an answer that refuses the request, as opposed to a page that is gone


def path_for(folder, now):
    return Path(folder) / f"{PREFIX}{now:%Y-%m-%d}{SUFFIX}"


def prune(folder, now):
    """Delete this log's own day files older than KEEP_DAYS; nothing else in the folder."""
    oldest = path_for(folder, now - timedelta(days=KEEP_DAYS)).name
    for path in Path(folder).glob(f"{PREFIX}????-??-??{SUFFIX}"):
        if path.name < oldest:
            path.unlink(missing_ok=True)


class Tee:
    """A stream that writes as before and copies each whole line, secrets taken out, into the day's file."""

    def __init__(self, stream, day, secrets, now):
        self.stream, self.day, self.secrets, self.now, self.partial = stream, day, secrets, now, ""

    def write(self, text):
        self.stream.write(text)
        *lines, self.partial = (self.partial + text).split("\n")
        for line in lines:
            self.day.line(line, self.secrets, self.now())
        return len(text)

    def flush(self):
        self.stream.flush()

    def close_line(self):
        if self.partial:
            self.day.line(self.partial, self.secrets, self.now())
            self.partial = ""

    def __getattr__(self, name):  # encoding, isatty, fileno... as the real stream has them
        return getattr(self.stream, name)


class Day:
    def __init__(self, file, size):
        self.file, self.size = file, size

    def line(self, text, secrets, now):
        if self.size >= DAY_BYTES:
            return
        for value in secrets:
            text = text.replace(value, "…")
        out = f"{now:%Y-%m-%dT%H:%M:%SZ} {text}\n" if self.size + len(text) < DAY_BYTES else \
            f"{now:%Y-%m-%dT%H:%M:%SZ} log: this day's file is full ({DAY_BYTES} bytes); the rest is in the container's output\n"
        self.file.write(out)
        self.file.flush()
        self.size += len(out.encode("utf-8"))


def start(settings, now=None, clock=lambda: datetime.now(timezone.utc)):
    """Copy stdout and stderr into the day's file under settings' VR_LOG_DIR; nothing when it is unset. A folder that
    cannot be written is one stderr line, and the run goes on with its container output only. Returns the file or None."""
    folder = settings.get("VR_LOG_DIR")
    if not folder:
        return None
    now = now or clock()
    try:
        Path(folder).mkdir(parents=True, exist_ok=True)
        prune(folder, now)
        path = path_for(folder, now)
        file = open(path, "a", encoding="utf-8")  # noqa: SIM115 - open for the whole run
        day = Day(file, path.stat().st_size)
    except OSError as err:
        print(f"log: VR_LOG_DIR not written: {type(err).__name__}: {err.strerror or ''}", file=sys.stderr)
        return None
    secrets = sorted({settings[k] for k in SECRETS if len(settings.get(k) or "") >= 8}, key=len, reverse=True)
    sys.stdout, sys.stderr = Tee(sys.stdout, day, secrets, clock), Tee(sys.stderr, day, secrets, clock)
    for tee in (sys.stdout, sys.stderr):
        atexit.register(tee.close_line)
    return file


STAGES = ("read", "link", "distros", "sheets", "summaries", "board")
COUNTS = ("new", "summaries_asked", "summaries_kept_back", "summaries_failed", "summaries_batched", "sheets_asked",
          "sheets_kept_back", "sheets_failed", "summaries_deadline", "titles_kept_back", "distros_asked", "distros_kept_back")


class CycleLine:
    """One line a cycle, `cycle key=value ...` in a fixed order (docs/development.md lists the fields): when it started,
    how long it and each stage took (seconds; "off" when not set up, "stopped" or "paused" for a Summary step an API error
    ended, "-" for a stage a failed cycle never reached), counts, refused requests, skipped sources and the result."""

    def __init__(self, start, clock):
        self.start, self.clock = start, clock
        self.began = self.last = clock()
        self.stage, self.times, self.marks = STAGES[0], {}, {}
        self.counts = dict.fromkeys(COUNTS, 0)
        self.skipped, self.refused = [], Counter()
        self.fixes_lines = 0  # lines the union added to fixes in the Summaries stored this cycle (cycle.route_summaries)

    def lap(self, stage, then=None):
        """The time since the last lap goes to `stage`; `then` is the stage running from here."""
        now = self.clock()
        self.times[stage] = self.times.get(stage, 0) + now - self.last
        self.last, self.stage = now, then or stage

    def mark(self, stage, word):
        self.marks[stage] = word

    def count(self, key, n=1):
        self.counts[key] += n

    def skip(self, source):
        self.skipped.append(source)

    def counting(self, http_get):
        """http_get that counts the requests answered 401, 403 or 429, by host."""
        def get(url, headers=None):
            try:
                return http_get(url) if headers is None else http_get(url, headers)
            except urllib.error.HTTPError as err:
                if err.code in REFUSED:
                    self.refused[urlsplit(url).hostname or "?"] += 1
                raise
        return get

    def text(self, error=None):
        stage = lambda s: self.marks.get(s) or (f"{round(self.times[s])}" if s in self.times else "-")  # noqa: E731
        hosts = ",".join(h for h, _ in self.refused.most_common(5)) or "-"
        result = "ok" if error is None else f"failed:{self.stage}:{type(error).__name__}"
        return " ".join([
            "cycle", f"start={self.start}", f"took={round(self.clock() - self.began)}",
            *(f"{s}={stage(s)}" for s in STAGES), *(f"{k}={v}" for k, v in self.counts.items()),
            f"refused={sum(self.refused.values())}", f"refused_hosts={hosts}", f"skipped={','.join(self.skipped) or '-'}",
            f"fixes_lines={self.fixes_lines}",
            f"result={result}"])
