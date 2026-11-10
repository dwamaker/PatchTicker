"""Run one collection cycle: python -m collector [path/to/envfile]  (default: .env)

Rebuild the store from the SQLite backup instead: python -m collector --restore [path/to/envfile]
Copy the whole store into the SQLite backup once:  python -m collector --seed-backup [path/to/envfile]
Send one small real request of every schema request shape: python -m collector --smoke [path/to/envfile]  (exit 1 on a rejection)
"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic

from collector import curators, cve_lines, discord, kisa, news, summaries
from collector.cycle import run_cycle
from collector.net import make_http_get, make_http_post
from collector.store import BackedUpStore, FolderStore, SqliteStore, r2_store, restore

REQUIRED = ("VR_COLLECTOR_ID", "VR_CONTACT")
R2 = ("VR_R2_ENDPOINT", "VR_R2_BUCKET", "VR_R2_ACCESS_KEY_ID", "VR_R2_SECRET_ACCESS_KEY")
OPTIONAL = ("VR_STORE_DIR", "VR_BACKUP_DB", "VR_NVD_API_KEY", "VR_GITHUB_TOKEN", "VR_CURATOR_FEEDS", "ANTHROPIC_API_KEY",
            "VR_DISCORD_WEBHOOK") + R2


def load_settings(path):
    """KEY=VALUE lines from the env file; real environment variables win (as with Docker env_file)."""
    settings = {}
    if Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and not key.startswith("#"):
                settings[key.strip()] = value.strip()
    settings.update({k: os.environ[k] for k in REQUIRED + OPTIONAL if os.environ.get(k)})
    missing = [k for k in REQUIRED if not settings.get(k)]
    if not settings.get("VR_STORE_DIR"):
        missing += [k for k in R2 if not settings.get(k)]  # no folder means the R2 bucket, all four needed
    if missing:
        sys.exit(f"missing settings in {path}: {', '.join(missing)} (set VR_STORE_DIR, or all of {', '.join(R2)})")
    return settings


def make_store(settings, backup=True):
    """A folder when VR_STORE_DIR is set (laptops, tests), otherwise the R2 bucket; with VR_BACKUP_DB set,
    every write also goes into that SQLite file."""
    store = main_store(settings)
    if backup and settings.get("VR_BACKUP_DB"):
        return BackedUpStore(store, SqliteStore(settings["VR_BACKUP_DB"]))
    return store


def main_store(settings):
    if settings.get("VR_STORE_DIR"):
        return FolderStore(settings["VR_STORE_DIR"])
    return r2_store(
        endpoint=settings["VR_R2_ENDPOINT"],
        access_key_id=settings["VR_R2_ACCESS_KEY_ID"],
        secret_access_key=settings["VR_R2_SECRET_ACCESS_KEY"],
        bucket=settings["VR_R2_BUCKET"],
    )


def main():
    args = sys.argv[1:]
    if args[:1] == ["--restore"]:
        return restore_main(args[1] if len(args) > 1 else ".env")
    if args[:1] == ["--seed-backup"]:
        return seed_backup_main(args[1] if len(args) > 1 else ".env")
    if args[:1] == ["--smoke"]:
        sys.exit(smoke_main(args[1] if len(args) > 1 else ".env"))
    settings = load_settings(args[0] if args else ".env")
    key = settings.get("ANTHROPIC_API_KEY")
    agent = f"vuln-radar/0.1 ({settings['VR_CONTACT']})"
    run_cycle(
        make_store(settings),
        make_http_get(agent),
        datetime.now(timezone.utc),
        settings["VR_COLLECTOR_ID"],
        nvd_api_key=settings.get("VR_NVD_API_KEY", ""),
        github_token=settings.get("VR_GITHUB_TOKEN") or None,
        curator_feeds=[u.strip() for u in settings["VR_CURATOR_FEEDS"].split(",") if u.strip()]
        if "VR_CURATOR_FEEDS" in settings else curators.FEEDS,
        news_feeds=news.FEEDS,
        kisa_feed=kisa.FEED,
        # The key is passed in, never left for the SDK to find in a login profile; no key, no Summaries.
        claude=anthropic.Anthropic(api_key=key) if key else None,
        notify=discord.make_notifier(settings.get("VR_DISCORD_WEBHOOK"), make_http_post(agent)),
    )



SMOKE_TOKENS = 100  # a reply cut here still passes: the request was accepted, which is all --smoke checks
SMOKE_TEXT = "A made-up flaw in Widget 1.0 lets a visitor read any file."
SMOKE_INCIDENT = {"id": "CVE-2026-0001", "cves": ["CVE-2026-0001"], "products": [{"name": "Widget"}],
                  "brief": {"text": SMOKE_TEXT, "lead": ""}, "cve_texts": {"CVE-2026-0001": SMOKE_TEXT}}


def smoke(claude):
    """One small real request of every shape the collector sends with a schema, built by the cycle's own functions
    (2026-11-11: one more required Summary field made Anthropic reject every request, "The compiled grammar is too
    large", which no unit test can see). Batch requests send these same parameters, so no batch is made. Prints one
    line a shape and returns the exit code: 0 when all are accepted, 1 when any is rejected."""
    shapes = {
        "summary": summaries.params(f"Incident: CVE-2026-0001\nProducts: Widget\n{SMOKE_TEXT}"),
        "quick titles": summaries.title_params([SMOKE_INCIDENT]),
        "cve lines": cve_lines.lines_params(cve_lines.lines_input(SMOKE_INCIDENT, SMOKE_INCIDENT["cves"])),
    }
    code = 0
    for name, params in shapes.items():
        try:
            claude.messages.create(**params | {"max_tokens": SMOKE_TOKENS})
            print(f"smoke: {name} ok")
        except anthropic.APIError as err:
            print(f"smoke: {name} FAILED: {type(err).__name__}: {' '.join(err.message.split())[:200]}")
            code = 1
    return code


def smoke_main(path):
    """The collector's own settings and key; reads nothing from the store and writes nothing to it."""
    key = load_settings(path).get("ANTHROPIC_API_KEY")
    if not key:
        print("smoke: ANTHROPIC_API_KEY is not set; nothing was checked")
        return 1
    return smoke(anthropic.Anthropic(api_key=key))


def restore_main(path):
    settings = load_settings(path)
    db = settings.get("VR_BACKUP_DB")
    if not db or not Path(db).exists():
        sys.exit(f"no backup to restore from: VR_BACKUP_DB={db or '(not set)'}")
    backup = SqliteStore(db)
    try:
        count = restore(backup, make_store(settings, backup=False))
    finally:
        backup.close()
    print(f"restored {count} documents from {db}")


def seed_backup_main(path):
    """Writes made before the backup was switched on are only in the main store; copy everything over once."""
    settings = load_settings(path)
    db = settings.get("VR_BACKUP_DB")
    if not db:
        sys.exit("VR_BACKUP_DB is not set")
    backup = SqliteStore(db)
    try:
        count = restore(make_store(settings, backup=False), backup)
    finally:
        backup.close()
    print(f"copied {count} documents into {db}")


if __name__ == "__main__":
    main()
