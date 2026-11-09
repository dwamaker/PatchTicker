# 02: Board live on the internet: R2 store and Cloudflare Pages

**What to build:** The collector runs as a container (one image, Docker Compose) and writes to a Cloudflare R2 bucket instead of a local folder. The page is deployed on Cloudflare Pages and reads the data through a custom subdomain of the user's existing domain, with a CORS rule for the page's origin. Data updates never trigger a Pages deploy.

**Blocked by:** 01

**Status:** done (2026-11-09, late)

**Owner, 2026-11-09:** public name 패치레이더 (PatchRadar); address `patchradar.dwamaker.com` (dwamaker.com is on Cloudflare). The Cloudflare plugin (skills + MCP) is installed for Claude Code (user scope); a new session loads it, and the first Cloudflare tool use asks the owner to approve in the browser. Touch only what this ticket needs in the account; ask before changing or deleting any existing DNS record. The page's visible name (header, tab title) still says vuln-radar: change it here.

- [x] An R2 implementation of the store passes the same store tests as the fake.
- [x] The container image builds and runs one cycle on demand and on a 10-minute schedule (owner, 11-09; was 15). `status.json` must be served with a cache
  time of 30 s or less (the page checks it every 30 s, owner 11-09), or the page sees an old update time.
- [x] The page on its Pages address shows the Board from R2 data through the custom subdomain (checked with curl and in a browser).
- [x] A data update appears on the live page without a Pages deploy.
- [x] No secret is in the image or the repository; credentials come from the environment file.

## Comments

**2026-11-09, late (done):**
- Public name changed to **Patch Ticker** (owner; one English name in both languages). patchradar.com is a game
  patch-notes site and "SyncNet Patch Radar" is a security-alert WordPress plugin.
- Page: Cloudflare Pages project `patchradar` (pages.dev name `patchradar-6na`, since `patchradar` was taken), custom
  domain `patchticker.dwamaker.com` (proxied CNAME). Deployed by `npx wrangler@4 pages deploy <dir> --project-name
  patchradar --branch main` from a folder holding only index.html, app.mjs, board.mjs and vendors.json (never `web/`,
  which holds the git-ignored local data). Wrangler is logged in on this PC.
- Data: R2 bucket `patchradar` (APAC), custom domain `patchticker-data.dwamaker.com`, CORS GET/HEAD for
  `https://patchticker.dwamaker.com` and `https://patchradar-6na.pages.dev`. Each object: JSON, `max-age=30`.
  `app.mjs` reads `data/` on localhost/127.0.0.1 and the data domain everywhere else.
- Collector: Oracle VM, Docker from Ubuntu's `docker.io` + `docker-compose-v2`, `~/vuln-radar` (build context + `.env`,
  mode 600), `docker compose up -d` (restart unless-stopped; Docker enabled at boot). First cycle into R2 took ~9 min
  (every risky Incident summarized at once); later cycles are short. One cycle by hand:
  `sudo docker compose run --rm collector python -m collector` (plain `run` starts the loop).
- Oracle `.env` holds the R2 token (Object Read & Write on `patchradar` only, made by the owner) and, for now, the
  same Anthropic key as this PC (ticket 08 wants each box's own key).
- The `patchradar.dwamaker.com` and `patchradar-data.dwamaker.com` names made earlier the same evening were removed.
- Open: the Pages custom domain still showed "pending" while already serving 200; recheck it. JSON is not cached at
  the edge (no cache rule), so each poll is an R2 read; add a cache rule if traffic grows.
