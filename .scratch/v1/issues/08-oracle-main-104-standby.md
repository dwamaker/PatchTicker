# 08: Oracle main collector, .104 standby, SQLite backup

**What to build:** The collector image runs on the Oracle VM (Docker installed there) as the main collector and on .104 as the standby, each with its own API key. Every cycle the standby reads the status file: it runs a full cycle only when the last update is older than 45 minutes, writes its identity, and stands down once the main collector writes again. Each collector keeps an SQLite copy of the store as a backup and can restore R2 from it.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Failover (seam 1, fake clock and store): status 46 minutes old, the standby runs and writes; 30 minutes old, it does nothing; after the main writes again, it stands down.
- [ ] Two collectors never both write in the same cycle window in the test.
- [x] Restoring from the SQLite backup rebuilds the monthly files and index.
- [ ] On the real boxes: stopping the Oracle collector leads to a .104 update within about an hour; restarting it hands back (checked once, by hand).
- [ ] Neither box accepts inbound connections for this service; the proxy on the Oracle VM keeps working.

## Comments

**2026-11-09, late:**
- Oracle main collector is live (see ticket 02 Comments). The owner put **the .104 standby, failover and each box's
  own Anthropic key last**, after ticket 09.
- SQLite backup done: `SqliteStore`, `BackedUpStore` (writes the backup first, reads the main store), `restore()`;
  `python -m collector --seed-backup` and `--restore`; Compose mounts `./backup` (owned by uid 65534) and sets
  `VR_BACKUP_DB=/backup/store.sqlite`. On Oracle: seeded 9 documents, and a restore into a folder inside a throwaway
  container rebuilt all 9. Not tried: a restore into R2 itself.
- Pitfall: an "is a cycle running" check that greps `/proc/*/cmdline` for `collector` matches its own shell, so it
  never reads idle. Recreating the container then cut a running cycle; nothing was lost (no batch left unrecorded).

**2026-11-09 night, later:** cycles now start on the 10-minute marks; the collector reads at most 500 cvelist records
a cycle (oldest first) and fetches the records of cited CVEs it never read; a 7-day backfill was started on Oracle.
Still open and put last by the owner: the .104 standby with failover, and each box's own Anthropic key.
