# 08: Oracle main collector, .104 standby, SQLite backup

**What to build:** The collector image runs on the Oracle VM (Docker installed there) as the main collector and on .104 as the standby, each with its own API key. Every cycle the standby reads the status file: it runs a full cycle only when the last update is older than 45 minutes, writes its identity, and stands down once the main collector writes again. Each collector keeps an SQLite copy of the store as a backup and can restore R2 from it.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Failover (seam 1, fake clock and store): status 46 minutes old, the standby runs and writes; 30 minutes old, it does nothing; after the main writes again, it stands down.
- [ ] Two collectors never both write in the same cycle window in the test.
- [ ] Restoring from the SQLite backup rebuilds the monthly files and index.
- [ ] On the real boxes: stopping the Oracle collector leads to a .104 update within about an hour; restarting it hands back (checked once, by hand).
- [ ] Neither box accepts inbound connections for this service; the proxy on the Oracle VM keeps working.
