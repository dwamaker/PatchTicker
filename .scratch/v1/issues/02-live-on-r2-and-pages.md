# 02: Board live on the internet: R2 store and Cloudflare Pages

**What to build:** The collector runs as a container (one image, Docker Compose) and writes to a Cloudflare R2 bucket instead of a local folder. The page is deployed on Cloudflare Pages and reads the data through a custom subdomain of the user's existing domain, with a CORS rule for the page's origin. Data updates never trigger a Pages deploy.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] An R2 implementation of the store passes the same store tests as the fake.
- [ ] The container image builds and runs one cycle on demand and on a 10-minute schedule (owner, 11-09; was 15). `status.json` must be served with a cache
  time of 30 s or less (the page checks it every 30 s, owner 11-09), or the page sees an old update time.
- [ ] The page on its Pages address shows the Board from R2 data through the custom subdomain (checked with curl and in a browser).
- [ ] A data update appears on the live page without a Pages deploy.
- [ ] No secret is in the image or the repository; credentials come from the environment file.
