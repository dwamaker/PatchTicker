"""Discord webhook (owner, 11-10: "내가 쌓였는지 알 방법이 없잖아"): one message a cycle when a Summary is newly given up
or a same_as merge happened, so the owner knows without opening summary_failures.json or merge_log.json."""

import re
import sys
import urllib.error
from urllib.parse import quote

# The webhook's path is its secret, so only a Discord webhook address is used and the value is never printed.
WEBHOOK = re.compile(r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[\w-]+", re.ASCII)
LIMIT = 1800  # Discord takes 2,000 characters; "외 N건" fits in the rest
BOARD = "https://patchticker.com/#i="


def make_notifier(url, post):
    """A function that posts one message, or None when VR_DISCORD_WEBHOOK is unset (silently) or not a Discord webhook
    address (one stderr line). post: net.make_http_post's http_post. A failed post is one stderr line, never retried."""
    if not url:
        return None
    if not WEBHOOK.fullmatch(url):
        print("discord: VR_DISCORD_WEBHOOK refused: not a https://discord.com/api/webhooks/ address; nothing is sent", file=sys.stderr)
        return None
    print("discord: VR_DISCORD_WEBHOOK set", file=sys.stderr)

    def notify(text):
        try:
            # The text quotes model output and source titles: no @everyone, role or user ping may fire.
            post(url, {"content": text, "allowed_mentions": {"parse": []}})
        except (OSError, ValueError) as err:
            # Only the status or the error's kind: an error's text may hold the URL.
            print(f"discord: post failed: {err.code if isinstance(err, urllib.error.HTTPError) else type(err).__name__}", file=sys.stderr)

    return notify


def message(failures, merges):
    """The message for newly given-up Summaries (summary_failures entries; one still showing an older Summary first) and
    accepted same_as merges (merge_log entries plus "into", the survivor's id), or "" when there is none. Text sits in
    code spans so Discord makes no markdown or link of it; each item's one link is in <> so it makes no embed."""
    code = lambda text: f"`{(text or '-').replace('`', chr(39))}`"
    link = lambda incident_id: f"<{BOARD}{quote(incident_id, safe='')}>"
    lines = [f"- 요약 포기 · {'주의: 옛 요약 노출' if f['shows'] == 'summary' else '속보만 노출'} · {code(f['id'])} · {code(f['reason'])} {link(f['id'])}"
             for f in sorted(failures, key=lambda f: f["shows"] != "summary")]
    lines += [f"- 같은 사건 합침 · {code(m['incident']['title'])} + {code(m['same_as']['title'])} {link(m['into'])}" for m in merges]
    if not lines:
        return ""
    out = [f"Patch Ticker 수집기: 새 소식 {len(lines)}건"]
    for k, line in enumerate(lines):
        if len("\n".join(out + [line])) > LIMIT:
            out.append(f"외 {len(lines) - k}건")
            break
        out.append(line)
    return "\n".join(out)
