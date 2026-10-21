# Start here

Three doors. Pick the one matching what you're actually trying to do — you do not need the rest.

---

## 🚪 Door 1 — I want to use this

Follow in order. About an hour.

| # | Do | Read |
|---|---|---|
| **1** | Understand what it does and **what each scanner needs in order to see anything** | [`adoption/USAGE.md`](adoption/USAGE.md) |
| **2** | Let other repos consume the kit — **it is invisible until you do**, and the error won't say so | [`adoption/SETUP.md`](adoption/SETUP.md) **§1.5** |
| **3** | Add a caller to **one** repo (start from [`templates/security.yml`](../templates/security.yml); grant `contents: read`, `security-events: write`, `actions: read`), with `advisory_mode: true` and an attributed weakening, and run it manually | [`adoption/USAGE.md`](adoption/USAGE.md) → *Adopting this* |
| **4** | Read the results. **Your first run will find things — that is the system working** | [`operations/FINDING_CLASSIFICATION.md`](operations/FINDING_CLASSIFICATION.md) |
| **5** | *Azure only:* OIDC, GUI and CLI for every step | [`adoption/SETUP.md`](adoption/SETUP.md) |

> **Start in `advisory_mode`.** Everything runs and reports; non-secret findings do not block.
> **Secrets block in every mode — advisory mode never covers them.** A leaked credential is live
> exposure, not inherited debt, and the remediation is unambiguous: rotate it. The same holds for a
> credential baked into a container image and for a known-malicious package. (Fixed at `09f073e`;
> proven by `tests/prove_secrets_always_block.py`, which runs the shipped Enforce step in advisory
> mode; the flagship's `secret_gate` output is evaluated separately and never suppressed.)
>
> Advisory mode is itself a recorded weakening: an unattributed one routes `DECISION_REQUIRED`, so
> set `weakening_reason`, `weakening_authority` and `weakening_expires` beside it (explainer part 05).
> Learn your inherited baseline before you gate on it — a hard gate dropped onto an unknown backlog
> gets the control switched off, which costs more coverage than the gate would ever have bought.

---

## 🚪 Door 2 — Something failed

| Symptom | Go to |
|---|---|
| **Findings I need to act on** | [`operations/FINDING_CLASSIFICATION.md`](operations/FINDING_CLASSIFICATION.md) — **classify before changing anything** |
| A job behaved strangely | [`operations/FAILURE_MODES.md`](operations/FAILURE_MODES.md) — eight classes, all of which really happened |
| A short, specific trap (mostly Azure OIDC) | [`operations/GOTCHAS.md`](operations/GOTCHAS.md) |
| A job failed with **zero steps** | Not a workflow bug — a protection rule or billing refused it. [`operations/FAILURE_MODES.md`](operations/FAILURE_MODES.md) §4 |
| **Green, but suspiciously quiet** | [`operations/FAILURE_MODES.md`](operations/FAILURE_MODES.md) §1 — the most expensive failure class here |

**The rule that matters most:** a run that correctly finds real vulnerabilities is a **successful
test of the pipeline** and a **failed assessment of the repository**. Those are different events.
Only one justifies changing the kit.

---

## 🚪 Door 3 — I need to understand or change it

| Question | Read |
|---|---|
| What is actually **proven**, with run IDs? | [`assurance/RELEASE_1_EVIDENCE_MANIFEST.md`](assurance/RELEASE_1_EVIDENCE_MANIFEST.md) — one row per capability, each tied to a run or a proof, plus the outputs a consumer reads (in three parts: this file, [`_PART2`](assurance/RELEASE_1_EVIDENCE_MANIFEST_PART2.md) and [`_PART3`](assurance/RELEASE_1_EVIDENCE_MANIFEST_PART3.md)). The machine-checked source is `tests/reconcile_validation.py` |
| What does the kit still lack? | [`assurance/COMPLETION_LEDGER.md`](assurance/COMPLETION_LEDGER.md) — designed vs built, row by row, and the lane plan |
| Why is CI red when nothing is broken? | [`assurance/VALIDATION_DEBT.md`](assurance/VALIDATION_DEBT.md) — how debt is dated, owned and expiring, so **red always means act now** |
| Which action versions, and why? | [`assurance/PINNING.md`](assurance/PINNING.md) — includes the **Node 20 removal deadline** |
| What does the governance gate enforce? | [`architecture/POLICY.md`](architecture/POLICY.md) |
| **Can I use the deploy workflows?** | Yes, on Azure App Service and Container Apps: both are proven live on a sandbox subscription — verdict refusal, healthy deploy of a kit-built digest, verified rollback, a second actor's change refused (run ids in the manifest). Read [`explainer/11-INTEGRATING-WITH-THE-KIT.md`](explainer/11-INTEGRATING-WITH-THE-KIT.md) first; the contract they implement is [`architecture/ROLLBACK_CONTRACT.md`](architecture/ROLLBACK_CONTRACT.md). Not yet live: attestation signing, a scan → deploy chain in one run, empty/unknown prior state |
| What was deliberately left undone? | [`roadmap/FUTURE_WORK.md`](roadmap/FUTURE_WORK.md) |
| **When is a guardrail actually proven?** | [`PROOF_RULE.md`](PROOF_RULE.md) — four cases per guardrail, both receipts kept. **Read this before claiming a control works** |

`architecture/CAPABILITY_INVENTORY.md`, `assurance/TEST_COVERAGE_AUDIT.md`,
`architecture/ASSURANCE_MODEL_CANDIDATES.md` and `architecture/NVD_ABSTRACTION_ACCOUNTING.md` are
**working notes** — provenance for decisions, not instructions. Read them when you want to know
*why*, never to find out *how*.

---

## The three rules everything else follows from

1. **Silence is never a correct outcome.** Every scanner produces findings, an explicit *"nothing to
   scan, and here is the path I searched"*, or a loud failure. Get none of those three and it's a
   defect — report it rather than assuming clean.
2. **Never change scanner configuration to make a real run green.** Classify first. Only a genuine
   kit defect justifies touching the kit.
3. **Detection immediately, enforcement deliberately.**

## It does not need GitHub Advanced Security

Code scanning is free on public repos and otherwise requires GHAS, sold to organisations on
Enterprise plans. **This kit does not depend on it.** Every engine is open source; GHAS only ever
supplied the Security tab, PR annotations and triage. Findings always persist as build artifacts and
render into the job summary, and when Security-tab publication is unavailable the job warns
"NOT published to the Security tab … ANALYSIS=COMPLETE, enforcement already ran" and names the
artifact holding the redacted SARIF (the NVD workflow prints `PUBLICATION=DEGRADED`) — never a
failed scan.
