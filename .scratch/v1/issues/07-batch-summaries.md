# 07: Batch Summaries, re-summaries and budget stop

**What to build:** All other Incidents are summarized through the Message Batches API: one batch submitted per cycle, results collected on later cycles. Re-summary fires on a new official advisory or fixed version, a new KEV listing, or a newly attached CVE, at most three Summaries per Incident. A credit-exhausted or spend-limit error pauses Summaries while Briefs keep flowing, and the status file says so.

**Blocked by:** 06

**Status:** ready-for-agent

- [ ] An ordinary Incident has only a Brief after the submitting cycle and a Summary after the cycle that collects the batch result (seam 1, fake client).
- [ ] A batch that expires or partly fails leaves those Incidents as Briefs and resubmits them later.
- [ ] Re-summary triggers fire on each of the three events and stop after three Summaries.
- [ ] A credit-exhausted error from the fake client keeps Briefs flowing and sets 'summaries paused' in the status file; the page shows a short notice.
- [ ] Batch requests use the one-hour cache TTL on the fixed instructions.
