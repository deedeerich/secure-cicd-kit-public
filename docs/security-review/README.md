# Security review sheets — for a reviewer brought in on an app that uses the kit

```
Truth State:  Authored, not field-tested (2026-11-03). Written from the kit's own documents and code
              on the trunk; no reviewer has run a real review with these sheets yet.
Audience:     a security reviewer (AppSec or a security team member) asked to review the security of
              one application that builds or deploys through this kit
Authority:    the kit's code, assurance-taxonomy.yaml and docs/architecture/* win over these sheets.
              Where a sheet and the kit disagree, the sheet is wrong: report it.
```

## Which sheet to use when

| You are about to... | Use |
|---|---|
| do the **security review of a change going to CAB** (cloud or app): is it safe, on what evidence? | [`CAB-CHANGE-SAFETY-STEPS.md`](CAB-CHANGE-SAFETY-STEPS.md) for the steps; fill in [`CAB-CHANGE-REVIEW-CHECKLIST.md`](CAB-CHANGE-REVIEW-CHECKLIST.md); cloud reads in [`CLOUD-CHECKS.md`](CLOUD-CHECKS.md), one list by intent with Azure, AWS, GitHub and "other cloud" columns (the old Z/W/H ids are aliases) |
| answer someone who pulled you in **before the CAB presentation exists** | [`EARLY-REVIEW-REQUESTS.md`](EARLY-REVIEW-REQUESTS.md) |
| explain **why** a check is asked: the principle, the source, the gotcha | [`PRINCIPLES-AND-SOURCES.md`](PRINCIPLES-AND-SOURCES.md) |
| start a review, and want the order to do it in | [`APP-REVIEW-CHECKLIST.md`](APP-REVIEW-CHECKLIST.md) |
| read a run summary and do not know what a word means | [`READING-THE-RUN-SUMMARY.md`](READING-THE-RUN-SUMMARY.md) |
| talk to the app team for the first time | [`QUESTIONS-FOR-APP-TEAMS.md`](QUESTIONS-FOR-APP-TEAMS.md) |
| decide whether to pause and ask the app team something | [`STOP-AND-ASK.md`](STOP-AND-ASK.md) |
| decide whether this is no longer an app review at all | [`ESCALATE-BROADER.md`](ESCALATE-BROADER.md) |
| write down what you reviewed, and what you may claim | [`SIGN-OFF.md`](SIGN-OFF.md) |
| approve a **CAB change** or the **adoption** of an internally built app | [`CAB-AND-ADOPTION-REVIEW.md`](CAB-AND-ADOPTION-REVIEW.md) |
| look up which checklist modules an app needs (kind × environment) | [`APPROVAL-MATRIX.md`](APPROVAL-MATRIX.md), then [`modules/`](modules/) |
| find out what the kit cannot see (admin-only settings, an automation's runtime) and whom to ask | [`OBTAIN-SEPARATELY.md`](OBTAIN-SEPARATELY.md) |

**"Security reviewed" or "LGTM" on a CAB ticket is not a security sign-off.** The accepted sign-off is
the checklist's paste block: the outcome, what the reviewer understood the change to be, the evidence
they looked at, and the open questions. "Not reviewed — outside my knowledge, routed to `<role>`" and
"Paused — broader conversation opened" are correct outcomes, not failures. These sheets are the
security review of a change; the CAB process itself is the organisation's and is not defined here.

## Any cloud

Every check is stated once, by what it is for, and then implemented per platform: Azure, AWS,
GitHub, and, for any other cloud, how to find the equivalent (`CLOUD-CHECKS.md`). A sovereign or
government cloud uses the same checks against its own endpoints. What is Azure-specific is the
kit's **deploy**: it releases only to its Azure targets, so on AWS or any other cloud the kit scans
the code and the release is outside it (`modules/MOD-OUTSIDE-KIT.md`).

## The three rules the sheets lean on

1. **Read the verdict, not the colour.** A green job can carry findings, a softened control or
   missing evidence. The verdict is `routing_result` (explainer part 03).
2. **Absence is not a negative.** "Nothing found", "nothing exists", "nothing was looked at" and
   "the control is off" are four different states. `UNKNOWN`, `UNAVAILABLE` and
   `COLLECTION_FAILED` are never clean.
3. **The authority is never where the automation can write.** An exception, a weakening, an
   approval or a readiness value the app team set for itself is a question, not an answer.

## Two outcomes that are not "pass" or "fail"

- **Stop and ask** — something in the evidence needs an answer from the app team before you go on.
  The review pauses on that item; the rest can continue. See `STOP-AND-ASK.md`.
- **Escalate** — the item belongs to someone other than the app team and is bigger than this app
  (platform, licensing, identity, data, a third party, regulation, an incident, policy, AI agents).
  You hand it over, record the hand-off, and either continue or pause. See `ESCALATE-BROADER.md`.

## The machine-readable record (KDEC-036)

Every signal these sheets ask for is also a workflow output and a field of a JSON record a program can
read: `kit-security-record.json` in the security run's artifact `kit-security-record-<attempt>`
(the `security_record` output), and `review-signals.json` in each deploy's
`deploy-evidence-<run_id>-<attempt>` (the `review_signals` output). With the lease off, each release
also leaves a durable GitHub deployment (`task: kit-release-record`; `release_record_ref` is its id) that
outlives the artifacts. What the kit cannot read at all is in `OBTAIN-SEPARATELY.md`.

## Where the kit's words are defined

- Every state word: `assurance-taxonomy.yaml` (the authority).
- The verdict and its outputs: `docs/explainer/03-VOCABULARY-AND-VERDICT.md`.
- Weakenings and the policy register: `docs/explainer/05-WEAKENINGS-AND-POSTURE.md`,
  `docs/adoption/POLICY_REGISTER.md`.
- Deploy, rollback, promotion: `docs/explainer/07-BUILD-PROVENANCE-DEPLOY-ROLLBACK.md`,
  `docs/architecture/LZ_KIT_SEAM_CONTRACT.md`, `docs/architecture/LZ_KIT_HANDOFF_CONTRACT.md`.
- Leak gates: `docs/adoption/LEAK_GATES.md`.
- The reviewer signals (weakening authority, verdict provenance, tier and readiness source, watermark,
  durable record, deploy coverage): KDEC-036 in `.context/products/secure-cicd-kit/decisions.md`.
- What is built and what is only designed: `docs/explainer/09-STATUS-BUILT-VS-DESIGNED.md`,
  `docs/KNOWN_DEFECTS.md`.
