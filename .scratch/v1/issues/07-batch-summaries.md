# 07: Batch Summaries, re-summaries and budget stop

**What to build:** All other Incidents are summarized through the Message Batches API: one batch submitted per cycle, results collected on later cycles. Re-summary fires on a new official advisory or fixed version, a new KEV listing, or a newly attached CVE, at most three Summaries per Incident. A credit-exhausted or spend-limit error pauses Summaries while Briefs keep flowing, and the status file says so.

**Blocked by:** 06

**Status:** resolved (f423ac0)

- [ ] An ordinary Incident has only a Brief after the submitting cycle and a Summary after the cycle that collects the batch result (seam 1, fake client).
- [ ] A batch that expires or partly fails leaves those Incidents as Briefs and resubmits them later.
- [ ] Re-summary triggers fire on each of the three events and stop after three Summaries.
- [ ] A credit-exhausted error from the fake client keeps Briefs flowing and sets 'summaries paused' in the status file; the page shows a short notice.
- [ ] Batch requests use the one-hour cache TTL on the fixed instructions.

## Comments

- 2026-11-08: done in f423ac0 on `ticket-07-batch-summaries`. Same request and parse path as 06/10 (`params(..., ttl="1h")`, `parse`); pending batches and their inputs live in the store's `batches.json` so the reply is checked against what was sent. Live run (one batch, 3 new CVEs): ended in 331 s, $0.00121 ($0.0004 per Incident), cache written once and read twice; the code check rejected 2 of 3 replies (a version in one language only, a stray "2"), so the monthly estimate for ~650/day is ~$8 at one try and up to ~$16 if that rejection rate holds (plan.md). Limits: only Incidents first seen in the last 30 days are batched, at most 200 a cycle; an Incident waiting in a batch is skipped by both paths, so a KEV listing during the wait is summarized after the batch ends (costing one of the three Summaries); "new official advisory" means a new `advisory` Mention, and a fixed version is noticed only through one (cvelist reads new records, not updates); Summaries from before this ticket have no `summary_basis` and are never re-summarized; an errored request counts as one of the three tries, an expired one does not; the budget error is told apart by status 402 or a 400 naming the credit balance or usage limit, and 'paused' clears on the next cycle that makes a call (after a pause, the first batch is a one-request probe), so a cycle with nothing to summarize clears it too; a network error halfway through reading results can store a result twice on the next cycle. The page notice is not covered by a test (DOM code).
- 2026-11-08: review fixes on `fix/review-findings`. A KEV listing that the last Summary did not cover (`kev` set, `summary_basis.kev` not) now routes to the instant path regardless of first-seen age, so an Incident older than the 30-day batch window is re-summarized (or summarized for the first time) when it is listed; the per-cycle cap and the three-Summary limit still apply. The language-free Summary fields are named once (`SHARED_FIELDS`) instead of `SCHEMA["required"][2:]`.
