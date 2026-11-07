# 10: Easy view with Risk banner and one action

**What to build:** Each Incident on the Board gets a normal/Easy tab (normal by default, the choice remembered). The Easy view shows a loud Risk banner instead of the CVE number, one or two plain sentences on what the problem means for an ordinary user, and the single action to take now: a copyable command ("run this to update"), or for a device Incident "update these devices now!" with the device list, or "update to version X". The Summary request (instant and batch paths alike) returns the Easy text and action in Korean and English; the Risk banner comes from rules, not the model.

**Blocked by:** 06

**Status:** ready-for-agent

- [ ] Risk banner rules (seam 2 or a pure function): exploited in the wild or CVSS 9.0+ → highest ("고위험!"), CVSS 7.0+ → high, otherwise notice; an Incident with no score yet shows notice.
- [ ] With a fake Claude client, the sshole replay yields an Easy action of `apk upgrade openssh` with the `PasswordAuthentication no` stopgap, both taken from the write-up text in the input (seam 1).
- [ ] A command the model returns that does not appear verbatim in the input text is dropped and replaced by "update to version X" (seam 1).
- [ ] A device Incident (affected products are device firmware) shows the device list with "update these devices now!".
- [ ] The tab works per Incident, the default view is normal, and the choice survives a reload.
- [ ] The copy button copies exactly the command shown.
- [ ] Search still matches the normal-view text in both languages; the Easy text is searchable too.
- [ ] One manual live run records the extra output tokens and cost per Incident in the plan.
