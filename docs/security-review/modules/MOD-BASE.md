# MOD-BASE — every review

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] Every kit `uses:` in the app is pinned to one full 40-hex commit SHA; `kit_watermark`
      `WATERMARK_BOUND` with its `source_commit` (the copy's `.neutral-export-watermark.json`, read by
      the run) (S9).
- [ ] One security caller; the caller job's `Security gate` is the required check on the default branch.
- [ ] A security run on the commit under review, younger than its 30-day artifacts (S16).
- [ ] `routing_result` and every `advisory_causes` entry read and explained.
- [ ] `controls_unavailable`, `controls_reduced`, `controls_skipped` empty, or each item answered (S2, S3).
- [ ] `weakening_attribution` `WEAKENING_AT_BASELINE`, or `WEAKENING_ATTRIBUTED` (approved: an evidence
      reference, a reason, a named owner, an expiry inside the ceiling,
      and an approver on a registered list (never the requester); `WEAKENING_NOT_APPROVED` is S4/S5, `WEAKENING_SELF_APPROVED` blocks.
- [ ] `secret_gate` `PASS` (or `EXCEPTED` with each secret rotated, S13); `kev_state` `AVAILABLE` and
      `kev_verdict` `CLEAR` (or `EXCEPTED`, S13).
- [ ] No scanner row `UNAVAILABLE`, `COLLECTION_FAILED`, `PARTIAL` or `FAILED` left unanswered; every
      `COVERAGE_GAP` named in the sign-off.
- [ ] Capability floor `HELD` (`GAP_DECIDED` is S10; `BREACHED` blocks).
- [ ] `policy_source` and `rung_effective` match what the app's risk calls for (S11).
- [ ] `leak_gates`: no `UNKNOWN` left unanswered (S1); `NO_LEAK_GATE_SHOWN` has a plan.
- [ ] Job token preflight `TOKEN_ACCEPTED` (S17).
- [ ] `no_kit_adapter` empty, or `MOD-OUTSIDE-KIT` taken for each kind.
- [ ] `kit-security-record-<attempt>` kept with the review; the rows of `../OBTAIN-SEPARATELY.md` the
      review relies on obtained, by role.
- [ ] The app's workflows pass `workflow-policy-check.yml` with `soft_fail: false`.
- [ ] `test_only_seed_artifact` empty in every non-test caller (S12).
