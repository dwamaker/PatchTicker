# A Pipeline of four parts over one SQLite working store; R2 only publishes

Status: accepted (owner, 2026-11-22); replaces the store part of ADR 0002 once the cutover is done.

One program did everything every ten minutes and kept its state as JSON documents in the public R2 bucket, a whole
month of Incidents in one document rewritten whole, with SQLite only as a copy of those documents. A change to any step
took the whole collector down (93 of the 182 collector commits of two weeks touched the Summary code alone), one startup
error stopped every step (2026-11-21), and working state (drafts, batch inputs, checkpoints) was readable at the site's
data address. So the Pipeline is split into four parts that run on their own: the Fetcher reads every Source and keeps
what it read, pages' HTML included; the Processor links Mention groups into Incidents and reduces pages to their
essential text and Page sheets; the Summarizer writes and checks what readers read; the Publisher alone writes the
site's files. They share one SQLite database with a record per Incident and per page (WAL), which is the store of
record; R2 holds only what the site reads, and the database is replicated continuously to a private bucket with seven
days of point-in-time recovery.

## Considered options

- **Keep one program, fix the storage only.** Cheaper, but a Summary change would still stop fetching, and a broken
  step would still stop the cycle.
- **Three parts, the Summarizer publishing.** Rejected: the site would stop updating whenever the Summarizer is down;
  with a Publisher apart, new Incidents still show as Briefs.
- **Ship step by step to the live service.** Rejected by the owner: the service is live, so the new Pipeline is built
  and run against real Sources on a test server beside the old collector, and replaces it in one cutover once it has
  matched it for five days in a row (same Incidents, joins and Board files, every difference explained), each part has
  been stopped and restarted without the others stopping, and no cycle failed. No way back is kept after the cutover.
- **A standby collector on a second machine** (ADR 0002). Dropped: it was never built; one machine, restored from the
  replicated database if it is lost.

## Consequences

- Every Source is read each minute where its limits allow, with requests that fetch only what changed; a Source that
  refuses is slowed alone. The first aim of the split is isolation; faster news is what it then makes possible.
- Page HTML is kept as long as its Incident (90 days), so pages can be processed and summarized again without being
  fetched again.
- Vendors' advisory pages that offer no feed become Sources (Apple first).
- A change to one part is deployed and tested alone, by running that part once; two parts change together only when a
  table they share changes shape, which is kept rare by adding columns rather than changing them.
