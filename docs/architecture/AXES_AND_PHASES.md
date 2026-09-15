# Six axes — what decides whether a scanner runs, how hard, and whether it blocks

```
Phase: design  ·  Truth State: modelled 2026-09-14 from a live design session + the reference estate inspection
Audience: anyone about to add a config input to this kit
Decision Supported: where a new knob belongs, and which axis it must NOT contaminate
Deferred Depth: the reference estate WORKFLOW_ORCHESTRATION_DESIGN.md (stage model) · assurance-taxonomy.yaml
```

> Every config input in this kit is currently **flat**. A caller sets `codeql_queries` once and gets
> the same behaviour on a typo fix and a production release. That is not a missing feature so much
> as six separate decisions collapsed into one knob.

---

## The six axes

| axis | decided by | question | must never decide |
|---|---|---|---|
| **APPLICABILITY** | discovery | is there anything here to scan? | how hard, or whether it blocks |
| **STAGE** | pipeline ordering | what must finish before this starts? | whether something is in scope |
| **DEPTH** | trigger context × application class | how hard do we look this time? | whether a finding blocks |
| **ENVIRONMENT CONSEQUENCE** | promotion target | how much does being wrong cost here? | what gets scanned |
| **TEAM PATTERN** | headcount | which human controls can exist at all? | scanner truth |
| **ENFORCEMENT** | consequence × team | what result blocks what action? | what gets scanned |

**Six, not four.** Environment consequence and team pattern were originally folded into enforcement
and they are independent inputs to it. A full-size team does not need a deeper scanner because it has
six developers — it needs different approval, routing and governance behaviour. And a solo repository
still needs the scanner to tell the same truth; it simply cannot demonstrate some approval controls.

**Team pattern must never affect scanner truth.** It affects required reviewers, CODEOWNERS routing,
separation of duties, auto-merge eligibility, who may approve a disposition, whether self-approval is
unavoidable or prohibited, and backup-owner models. Nothing else.

**Contaminating one axis with another is the defect.** A scanner skipped because "it's only a PR"
is indistinguishable, in the Actions UI, from one skipped because the language isn't present — and
those are `NOT_APPLICABLE` and `DEPTH_REDUCED`, which mean opposite things about coverage.

### Why STAGE and DEPTH are not the same thing

the reference estate's `WORKFLOW_ORCHESTRATION_DESIGN.md` uses "Phase 1–5" for **pipeline stages**:

```
1 detection & quick scans  →  2 code analysis  →  3 comprehensive  →  4 build & test  →  5 deploy
```

That is a dependency graph inside ONE run. It is not the same as PR-vs-nightly, which is the
trigger context the same graph executes under. Merging them would mean "nightly" had to become a
stage, which it is not.

This kit currently has **no stage model at all** — every scanner hangs off `discover` and runs in
parallel. That is fine for cost and wrong for sequencing: a comprehensive scan runs whether or not
the quick scans already failed, and a build starts without waiting for either.

---

## DEPTH by trigger context

| context | CodeQL | secrets | scope | posture |
|---|---|---|---|---|
| **PR** | `default` suite *(see note)* | diff only | changed paths | advisory on new categories |
| **merge to main** | `security-extended` | full tree | whole repo | blocking |
| **nightly** | `security-and-quality` | **full git history** | whole repo | report only |
| **release / promotion** | extended + SBOM + attestation | full | whole repo | hard gate |
| **post-deploy revalidation** | *none* | *none* | **image digest + SBOM only** | incident path |

The last row is the one people get wrong: continuous revalidation scans **what is running**, not the
branch. No source scanning at all — the source did not change, the world did.

### What the CodeQL suites actually differ by

| suite | contains |
|---|---|
| `default` | high-precision security baseline. **Taint tracking is included.** |
| `security-extended` | the default suite **plus** queries trading precision for coverage — lower severity, lower confidence, more recall, more triage |
| `security-and-quality` | security-extended plus maintainability and reliability |

It is a **precision/recall** choice, not presence-versus-absence of dataflow. An earlier version of
this document said the default suite omits taint tracking; it does not.

**So the PR row is a starting point, not doctrine.** For an application with meaningful untrusted
input and security-sensitive flows, broader coverage at PR time on changed code is exactly right —
waiting until merge to discover a dataflow issue is late. Application class should be able to deepen
the profile; discovery only says whether the language is applicable at all.

`scan_git_history` is the sharpest example of a flat input that should be phased. Full-history secret
scanning on every PR costs minutes for a question whose answer only changes when history changes.

---

## ENFORCEMENT by environment tier

Gating stringency increases along the promotion path. **UAT and prod are both production** for this
purpose — UAT usually holds production-shaped data and is the last place a defect is cheap.

| tier | new critical/high | existing dispositioned | scanner UNAVAILABLE / failed |
|---|---|---|---|
| **sandbox** | warn | allow | warn |
| **dev** | warn | allow | warn |
| **test** | block | allow | warn |
| **uat** *(production)* | block | allow if unexpired | **block** |
| **prod** *(production)* | block | allow if unexpired | **block** |

"Scanner did not run" must block at production tiers. `UNDETERMINED` is not `PASS`, and the
promotion gate is the last place that distinction is free.

---

## ENFORCEMENT by team pattern

Some controls cannot exist below a headcount, and pretending otherwise produces a gate nobody can
satisfy.

| pattern | size | what is actually available |
|---|---|---|
| **solo dev** | 1 | branch protection, required status checks, auto-merge rules. **No** reviewer separation — the author is the only approver |
| **pair devs** | 2 | mutual review possible; no separation of duties on a two-person exception |
| **small team** | 3–4 | real review, CODEOWNERS routing, rotation |
| **full team** | **5+** | approval separation, security-reviewer role distinct from author and approver |

**A solo repository cannot prove the human half of the operating model.** Required reviewers,
CODEOWNERS routing and approval separation are `UNVALIDATED HUMAN-WORKFLOW PATHS` — not failures,
and not to be reported as passing either.

---

## What discovery should and should not turn on

**Should** — applicability is exactly what discovery establishes:

- no JavaScript → no JS CodeQL queries. **A Terraform-only repo has no dataflow to track**, and
  running taint analysis there is not thoroughness, it is noise with a cost.
- no Dockerfile / no image ref → no image scan, `NOT_APPLICABLE`
- no IaC → no checkov
- GHAS unavailable → CodeQL `UNAVAILABLE`, which is a platform action and not a developer one

**Should not** — discovery cannot know the trigger context or the target environment. It cannot tell
a PR from a release, and it has no business deciding whether a finding blocks.

> Discovery decides **applicable**. Phase decides **depth**. Environment and team decide
> **enforcement**.

---

## Gaps found while modelling this — 2026-09-14

**~~The kit's NVD workflow has no `schedule:`~~ — CORRECTED.** A `workflow_call` workflow is invoked
*by a caller*, and the caller supplies the schedule. Reusable workflows cannot schedule themselves
and are not meant to. That framing was wrong.

**The real gap, now closed:** the NVD workflow could only be pointed at *source* — filesystem,
Dependency-Check, and Dockerfiles for misconfiguration. Scanning a Dockerfile is not scanning what is
running; the Dockerfile says what the image was *meant* to contain. It now accepts `sbom_path` and
`image_ref`.

**`trivy sbom` is the mechanism for continuous revalidation.** The SBOM is the durable record of what
a build produced; re-scanning it on a schedule finds vulnerabilities disclosed *after* that build
passed. The software did not change, the database did — which is exactly why zero-days matter here,
since they land in NVD when classified, long after the artifact shipped.

**The revalidation contract should eventually carry:** `deployed_artifact_digest` · `sbom` ·
`deployment_environment` · `deployment_id` · `last_approved_assurance_state` ·
`current_vulnerability_feed_time`. Then a run can say *same artifact, same SBOM, new intelligence →
assurance state changed*, which is far stronger than re-scanning `main`.

**the reference estate's NVD image scanning is a stub.** `nvd-cve-scanning.yml:196` reads
`# This step would scan images if they exist`. The workflow runs daily at 05:00 and does not scan a
deployed artifact. Written, not plugged in — LM-016.

**No environment tier concept exists anywhere in the kit.** No input, no gate variation, no
distinction between sandbox and prod.

**No team-pattern concept exists.** Approval and reviewer controls are neither configured nor
reported as unvalidatable.

**No stage ordering.** Every scanner runs in parallel off `discover`; nothing waits for anything.

---

## Where a new config input belongs

Before adding one, name its axis:

1. Does discovery know the answer? → applicability, and it should be **derived**, not an input.
2. Does it change with the trigger? → depth, belongs in the **profile**.
3. Does it change with the target environment or team size? → enforcement, belongs in **policy**.
4. Does it change the dependency graph? → stage.

An input that answers more than one of those is two inputs.
