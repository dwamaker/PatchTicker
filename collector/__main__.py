"""Run one collection cycle: python -m collector [path/to/envfile]  (default: .env)"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic

from collector import curators
from collector.cycle import run_cycle
from collector.net import make_http_get
from collector.store import FolderStore

REQUIRED = ("VR_STORE_DIR", "VR_COLLECTOR_ID", "VR_CONTACT")
OPTIONAL = ("VR_NVD_API_KEY", "VR_GITHUB_TOKEN", "VR_CURATOR_FEEDS", "ANTHROPIC_API_KEY")


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
    if missing:
        sys.exit(f"missing settings in {path}: {', '.join(missing)}")
    return settings


def main():
    settings = load_settings(sys.argv[1] if len(sys.argv) > 1 else ".env")
    key = settings.get("ANTHROPIC_API_KEY")
    run_cycle(
        FolderStore(settings["VR_STORE_DIR"]),
        make_http_get(f"vuln-radar/0.1 ({settings['VR_CONTACT']})"),
        datetime.now(timezone.utc),
        settings["VR_COLLECTOR_ID"],
        nvd_api_key=settings.get("VR_NVD_API_KEY", ""),
        github_token=settings.get("VR_GITHUB_TOKEN") or None,
        curator_feeds=[u.strip() for u in settings["VR_CURATOR_FEEDS"].split(",") if u.strip()]
        if "VR_CURATOR_FEEDS" in settings else curators.FEEDS,
        # The key is passed in, never left for the SDK to find in a login profile; no key, no Summaries.
        claude=anthropic.Anthropic(api_key=key) if key else None,
    )


if __name__ == "__main__":
    main()
