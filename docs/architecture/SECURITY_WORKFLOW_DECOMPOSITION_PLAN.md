# Decomposition plan: `reusable-security.yml`

**Status:** PROPOSAL, **PARTLY SUPERSEDED 2026-09-23 — Phase 1 (Candidate D) has shipped.**
The census, the boundary analysis and the candidate comparison stand as written. Two statements
in it no longer describe the tree, and they are corrected here rather than edited away:

- *"Nothing in `.github/workflows/` has been changed"* is no longer true. `reusable-security.yml`
  now carries one bootstrap job, `kit-scripts`, which writes the canonical scripts once and
  publishes them as a run-scoped artifact; every other job fetches them into `/tmp`, which is the
  path every call site already invoked. **623,411 -> 347,976 bytes (608.8 -> 339.8 KB).** The
  `workflow_call` contract — inputs, secrets, outputs — is byte-identical. §6.3's hazard is
  handled exactly as §6.3 specifies, except that scanners keep their existing `if:` expressions
  and the gate reads `needs.kit-scripts.result` explicitly (a `skipped` scanner therefore still
  cannot present as `NOT_APPLICABLE` when the bootstrap failed, because the gate raises
  `undetermined` and `fail` from the bootstrap result itself).

- **§5.2 overstates what is established about `$/`.** Re-verified against primary sources on
  2026-09-23: the changelog (2026-07-30) says `$/` "resolves to your workflow's own repository at
  the exact commit that is running"; the `uses:` reference page does not mention `$/` at all; the
  action-authoring page says only "the same repository at the running commit" and that "the `$/`
  syntax is not available in GitHub Enterprise Server"; the reuse-workflows page adds that a `$/`
  reference must not carry an `@{ref}` suffix. **No primary source states how `$/` resolves inside
  a reusable workflow invoked from another repository** — the sentence quoted in §5.2 was not
  found. The documented *intent* is consistent with the claim; the claim itself is not
  established, and it additionally carries two consumer-environment preconditions the kit cannot
  assert (GHES, runner >= 2.336.0). Phase 1 therefore deliberately depends on none of it. §5.2's
  own conclusion — prove it with a Level 2 two-repo test before Phase 2 ships — is unchanged and
  now also covers establishing the documentation, not only the behaviour.

- **§7 step 8 (the Phase 2 go/no-go) PASSED on 2026-10-13. MEASURED, not inferred.** A genuinely separate
  private repository (the Level 2 consumer) called a probe reusable workflow in this kit, pinned
  to a full SHA (`0196aaa`, branch `probe/level2-self-ref`). Evidence from run 38434823833:
  - The `$/` composite step ran with `action_path=/home/runner/work/_actions/<owner>/secure-cicd-kit/0196aaa…/.github/actions/probe-self-ref`
    while `GITHUB_REPOSITORY` was the consumer. It printed a marker file that exists only in the
    kit (`SELF_REF_RESULT=RESOLVED_TO_KIT`). So `$/` inside a cross-repo reusable workflow
    resolves to the kit, at the commit the caller pinned.
  - The contrast, `./` with no checkout, failed with "Can't find 'action.yml' … under
    …/<consumer-repo>/…", which is F10 reproduced.

  - **`$/` brings the WHOLE repository, not only the action folder** (run 38468728084, probe
    `6bfa93c`). From the composite, `scripts/scan_report.py`, `scripts/finding_identity.py`,
    `scripts/finding_subject.py` and `assurance-taxonomy.yaml` were all present under
    `_actions/<owner>/secure-cicd-kit/<sha>/`. Their sha256 prefixes matched the pinned commit byte for
    byte. **Consequence for Phase 2:** a composite runs the canonical `scripts/*.py` in place, so
    there is one copy, no generated heredoc and no digest pin. Integrity comes from the caller's SHA
    pin, which `$/` honours. That is stronger than §E.4's projection, which inlined the shared blocks
    into each composite, and it is why decomposition is the correct fix for C1 (KDEC-002). The report
    composite imports the identity modules from the same directory, and the 512,000-byte limit stops
    applying, because nothing is inlined.

  **Still not established:** GHES (documented as unsupported), and runners older than 2.336.0. The
  probe could not read the runner version (`RUNNER_VERSION` is unset on hosted runners). These are
  consumer-environment preconditions, and they must be stated as such in START-HERE when Phase 2 ships.

**Date:** 2026-09-22 (superseding note 2026-09-23; step 8 result 2026-10-13)
**Base:** `fix/normalization-and-discovery` @ `5c2335e`

---

## 0. The defect, and the headline

`.github/workflows/reusable-security.yml` is **623,411 bytes (608.8 KB)** across **11,237
lines**. GitHub refuses to start a workflow file above 500 KB, so the file has produced a startup
failure — zero jobs, not a failing job — on every push since it crossed the limit at `412ed634`
(2026-09-16).

Two findings from this pass dominate everything else:

> **1. The file is not big because it does too much. One generated block — the SARIF redactor,
> inlined 13 times — is 45.1% of the file on its own. Generated blocks are 66.6%. The
> hand-written workflow is 203 KB, which was never near the limit.**

> **2. The platform constraint that forced the inlining has been lifted.** The kit inlines
> everything because `uses: ./...` resolves against the *caller's* workspace, so the kit's own
> `scripts/` and composite actions are unreachable at consumer runtime. GitHub shipped `$/`
> (self-repository) syntax on **2026-07-30**, documented to resolve against *the repository of
> the file it appears in*, explicitly including the cross-repo case. **The architectural premise
> recorded throughout this repo is now out of date on github.com** (not on GHES).

That second finding is what makes the owner's registry-and-composite model (Candidate E)
buildable rather than blocked. It is also the single most load-bearing claim in this document,
and §5.2 states exactly how far it is established.

A third axis, added after the size work was scoped:

> **3. Job count is a recurring cost.** GitHub bills per job, rounded up to the minute.
> Repacking scanners into fewer jobs takes a polyglot run from 21 to 17 billed minutes and a
> single-language run — the consumer case — from 12 to 9. **But this is only safe once scanners
> are composites that emit their own verdicts** (§F.6), because today a scanner *is* a job and
> grouping would destroy attribution. Cost packing is therefore Phase 3, not Phase 1.

### Measurement basis, and a trap in it

All byte figures are **LF bytes** from the git blob — what GitHub measures.

A Windows checkout materialises the file with CRLF, where `wc -c` reports **634,648** — inflated
by one byte per line (11,237). Use:

```
git cat-file -s $(git rev-parse HEAD:.github/workflows/reusable-security.yml)   ->  623411
```

Do not size this file with `wc -c` on Windows.

---

## 1. SIZE CENSUS

### 1.1 By job

| Job | Lines | Bytes | KB | % |
|---|---:|---:|---:|---:|
| *(header, `workflow_call` contract, permissions)* | 278 | 14,565 | 14.2 | 2.3 |
| `discover` | 619 | 37,183 | 36.3 | 6.0 |
| `secret-scan` | 807 | 43,040 | 42.0 | 6.9 |
| `code-quality` | 245 | 13,637 | 13.3 | 2.2 |
| `sast-semgrep` | 614 | 33,658 | 32.9 | 5.4 |
| `sast-bandit` | 554 | 30,503 | 29.8 | 4.9 |
| `codeql` | 513 | 27,154 | 26.5 | 4.4 |
| `deps-scan` | 697 | 37,923 | 37.0 | 6.1 |
| `iac-scan` | 841 | 46,336 | 45.2 | 7.4 |
| `sast-dotnet` | 673 | 37,875 | 37.0 | 6.1 |
| `sast-java` | 638 | 35,808 | 35.0 | 5.7 |
| `sast-go` | 829 | 46,365 | 45.3 | 7.4 |
| `sast-cpp` | 847 | 48,006 | 46.9 | 7.7 |
| `image-scan` | 29 | 1,197 | 1.2 | 0.2 |
| `malicious-deps` | 546 | 29,639 | 28.9 | 4.8 |
| `sbom` | 755 | 40,411 | 39.5 | 6.5 |
| `report` | 1,480 | 84,636 | 82.7 | 13.6 |
| `security-gate` | 273 | 15,476 | 15.1 | 2.5 |
| **TOTAL** | **11,237** | **623,411** | **608.8** | **100** |

Read alone this says "seventeen jobs, no outlier, so it needs many children." **That reading is
wrong**, and it is the reading a split-first plan would rest on.

### 1.2 By content class

| Class | Bytes | KB | % |
|---|---:|---:|---:|
| Inline `run:` script bodies | 547,867 | 535.0 | **87.9** |
| Comment lines (2,212) | 178,290 | 174.1 | 28.6 |
| **Literally duplicated lines** (>25 chars, 2+ occurrences) | **248,646** | **242.8** | **39.9** |

### 1.3 By generated block — the actual mass

The duplication is generated by `scripts/inline_normalizer.py` and enforced by `self-test`
re-running it in `--check` mode. Blocks are delimited `# BEGIN <TOKEN>` / `# END <TOKEN>`:

| Block | Copies | Bytes | KB | % | Per copy |
|---|---:|---:|---:|---:|---:|
| `REDACT_SARIF` | **13** | **281,437** | **274.8** | **45.1** | 21,649 |
| `SCAN_STATUS` | 12 | 54,937 | 53.6 | 8.8 | 4,578 |
| `SCAN_REPORT` | 1 | 50,346 | 49.2 | 8.1 | 50,346 |
| `NORMALIZE_SARIF` | 3 | 18,549 | 18.1 | 3.0 | 6,183 |
| `SBOM_LICENSES` | 1 | 9,877 | 9.6 | 1.6 | 9,877 |
| **All generated** | **30** | **415,146** | **405.4** | **66.6** | |
| **Hand-written remainder** | | **208,265** | **203.4** | **33.4** | |

### 1.4 Per job: generated vs. its own logic

| Job | Total | Generated | Own logic | Blocks |
|---|---:|---:|---:|---|
| `discover` | 37,183 | 0 | 37,183 | — |
| `secret-scan` | 43,040 | 26,237 | 16,803 | redactor, status |
| `code-quality` | 13,637 | 4,566 | 9,071 | status |
| `sast-semgrep` | 33,658 | 26,229 | 7,429 | redactor, status |
| `sast-bandit` | 30,503 | 26,227 | 4,276 | redactor, status |
| `codeql` | 27,154 | 21,649 | 5,505 | redactor |
| `deps-scan` | 37,923 | 32,431 | 5,492 | redactor, normaliser, status |
| `iac-scan` | 46,336 | 32,452 | 13,884 | redactor, normaliser, status |
| `sast-dotnet` | 37,875 | 26,213 | 11,662 | redactor, status |
| `sast-java` | 35,808 | 26,220 | 9,588 | redactor, status |
| `sast-go` | 46,365 | 32,390 | 13,975 | redactor, normaliser, status |
| `sast-cpp` | 48,006 | 26,215 | 21,791 | redactor, status |
| `image-scan` | 1,197 | 0 | 1,197 | — |
| `malicious-deps` | 29,639 | 26,235 | 3,404 | redactor, status |
| `sbom` | 40,411 | 36,087 | 4,324 | redactor, licence scan, status |
| `report` | 84,636 | 71,995 | 12,641 | redactor, reporter |
| `security-gate` | 15,476 | 0 | 15,476 | — |

`malicious-deps` is 29,639 bytes of which 3,404 — 11% — is about malicious dependencies.

**The owner's reading of the structure is correct:** the workflow is already one-job-per-scanner,
each gated on a `discover` output. The structure is right. The mass is the 9–16 inlined steps
per job, and overwhelmingly the shared ones.

### 1.5 Why the duplication exists

`scripts/inline_normalizer.py`:

> A reusable workflow resolves `uses: ./...` against the CALLER's checkout, so anything under
> `scripts/` does not exist at consumer runtime. The kit already learned this the expensive
> way — 14 Azure gitleaks rules that silently never loaded while its own CI stayed green.

Two hard constraints follow, and both are now partially superseded (§5.2):

1. **`scripts/` is unreachable at consumer runtime.** So "move it to `scripts/` and call it" —
   the brief's instruction — cannot be implemented naively for the blocks that dominate the file.
2. **Redaction must happen in the producing job, before `upload-artifact`.**
   `tests/prove_redaction_chain.py` seeds secret-shaped values and proves nothing leaks;
   `check_redaction_parity.py` proves redaction is *ordered before* every publication step.
   Centralising redaction into `report` is not available as a size reduction.

The redactor genuinely must be *present in 13 jobs at runtime*. What is **not** forced is that it
be present **13 times in the file**. That distinction is the whole of this plan.

---

## 2. Established platform facts

Everything in this section is quoted from docs.github.com and is load-bearing below.

| # | Fact | Source |
|---|---|---|
| F1 | **Workflow file limit is 500 KB per file**; "A workflow file larger than 500 KB will not start runs"; not raisable via support | [limits](https://docs.github.com/en/actions/reference/limits#workflow-file-size) |
| F2 | **Nesting: 10 levels total** — top-level caller plus up to 9 reusable. Raised from 4 on 2025-11-06. GHES: 4. | [reuse-workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#nesting-reusable-workflows) |
| F3 | **50 unique reusable workflows** per workflow file, including nested trees. GHES: 20. | [reusing-workflow-configurations](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#limitations-of-reusable-workflows) |
| F4 | **`secrets: inherit` is ONE HOP.** "in the workflow chain A > B > C, workflow C will only receive secrets from A if they have been passed from A to B, and then from B to C." | [reuse-workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#passing-secrets-to-nested-workflows) |
| F5 | **`inherit` is org/enterprise-scoped:** "can be used to pass secrets across repositories within the same organization, or across organizations within the same enterprise." | [workflow-syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idsecretsinherit) |
| F6 | **Nested access is transitive to the INITIAL caller:** "A workflow that contains nested reusable workflows will fail if any of the nested workflows is inaccessible to the initial caller workflow." | [reusing-workflow-configurations](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#access-and-permissions-for-nested-workflows) |
| F7 | **Permissions only narrow with depth:** "`GITHUB_TOKEN` permissions can only be the same or more restrictive in nested workflows." | same |
| F8 | **YAML anchors/aliases ARE supported** since 2025-09-18, "automatically enabled for all GitHub Actions users and repositories". **Merge keys (`<<:`) are NOT documented.** github.com only, not GHES. | [changelog](https://github.blog/changelog/2025-09-18-actions-yaml-anchors-and-non-public-workflow-templates/), [reference](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#yaml-anchors-and-aliases) |
| F9 | **`$/` resolves against the file's own repository, cross-repo.** "if a reusable workflow in one repository is called by a workflow in another repository, a `$/` reference in the called workflow resolves to the called workflow's repository, not the calling workflow's repository." Works for "workflow steps, composite action steps, nested composition, and reusable workflow calls." GA 2026-07-30; runner ≥ 2.336.0; **not on GHES**. | [workflow-syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_iduses), [changelog](https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax/) |
| F10 | **Step-level `./` resolves against the runner workspace**, confirming the kit's original lesson: "the `./` path resolves against the runner's workspace rather than the repository of the running workflow." | [workflow-syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_iduses) |
| F11 | **No count limit on `workflow_call` outputs.** Only size: 1 MB per job, 50 MB per run. | [workflow-syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idoutputs) |
| F12 | **`workflow_dispatch` inputs: now 25**, raised from 10 on 2025-12-04. | [changelog](https://github.blog/changelog/2025-12-04-actions-workflow-dispatch-workflows-now-support-25-inputs/) |

### 2.1 NOT established

| # | Question | State |
|---|---|---|
| U1 | Does a bare `./.github/workflows/child.yml` **inside a workflow called cross-repo** resolve against KIT or CONSUMER? | **The documentation does not say.** A full search of `github/docs` found no sentence resolving it. Community reports (non-authoritative) say it resolves against the *calling* repo. Only `$/` (F9) has documented cross-repo semantics. |
| U2 | If a called workflow runs but **all its internal jobs skip**, is the calling job's `result` `success` or `skipped`? | **Not documented.** The docs state the possible values but never the derivation rule. This is the `NOT_APPLICABLE`/`CLEAN` collapse question and it is open. |
| U3 | What does `needs.<child>.outputs.<name>` evaluate to when the producing job skipped? | **Not documented.** Empty-string behaviour is inference. |
| U4 | **Is the 500 KB limit measured before or after YAML anchor expansion?** | **Not documented.** Decisive for Candidate C. |
| U5 | Does the 500 KB limit apply to composite `action.yml` files? | **Not documented.** F1 says "Each workflow file in the `.github/workflows` directory" — composites live in `.github/actions/`, so the limit as written does not reach them, but no doc states a composite limit either way. |

**Nothing in this plan's recommendation depends on U1–U3.** U4 and U5 gate specific candidates
and are called out where they bite.

---

## 3. How the gate works today

The gate does **not** read custom outputs from scanners. It reads **job results**:

```
for r in "secret-scan=${{ needs.secret-scan.result }}" ... "image-scan=${{ needs.image-scan.result }}"; do
```

projecting each into the kit's vocabulary:

```
success)   st=PASS ;
skipped)   st=NOT_APPLICABLE ;
cancelled) st=UNAVAILABLE ;
*)         st=UNAVAILABLE ;
```

with `codeql:skipped -> UNAVAILABLE` as a deliberate exception, because CodeQL skipping means
"nobody supplied the licence/token", not "no such code exists".

A failing job fails the gate via `case "$res" in success|skipped) ;; *) fail=1`, and `fail=1`
reaches `exit 1` unless `advisory_mode` — which never covers secrets.

`report` separately declares `needs:` on all 15 upstream jobs and consumes each
`needs.<job>.result`. Its own comment records why:

> An expression naming a job that is not in `needs` does not error in GitHub Actions — it
> evaluates to the empty string — so the container-image row has been rendering from an empty
> result on every run since it was added.

**Any candidate that moves scanners out of the parent must re-plumb 14 per-scanner verdicts, and
the failure mode of getting it wrong is the empty string, which reads as a state rather than
erroring.** That is the central risk of the splitting candidates and the reason the
non-splitting ones are preferred.

---

## 4. Candidates

Five. A and B split into child workflows; C and D keep one file; **E is the owner's
registry-and-composite model.**

### Candidate A — split by concern (6 child workflows)

| File | Projected KB | Contents |
|---|---:|---|
| `reusable-security.yml` (parent) | 75.0 | header, `discover`, `image-scan`, `security-gate`, 6 call stanzas |
| `…-sast-interpreted.yml` | 98.0 | semgrep, bandit, codeql |
| `…-sast-compiled.yml` | 172.9 | dotnet, java, go, cpp |
| `…-secrets.yml` | 50.8 | secret-scan |
| `…-supplychain.yml` | 114.2 | deps-scan, malicious-deps, sbom |
| `…-iac.yml` | 67.4 | iac-scan, code-quality |
| `…-report.yml` | 91.4 | report |
| **Largest** | **172.9** | |
| **Total repo bytes** | **669.7** | *up from 608.8* |

**Cost.** Total bytes *increase* ~61 KB. Nothing is deduplicated — 13 redactor copies still
exist, now scattered across seven files. It relocates bytes, which the brief warned against, and
buys headroom ordinary growth reconsumes.

It also inherits **U1** (may simply not resolve for external consumers), **U2** (the collapse),
**F4/F5** (`SEMGREP_APP_TOKEN` must be explicitly re-passed at each hop, and `inherit` is
unavailable to consumers outside the org), and **F7** (`security-events: write` must be threaded
down or SARIF upload breaks in every child).

### Candidate B — split by language (~10 children)

Strictly worse than A. Per-child header overhead paid ~10 times (~+30 KB more). The language axis
does not match the job axis: `secret-scan`, `deps-scan`, `sbom`, `iac-scan` are
language-agnostic; `sast-semgrep` spans several languages. Multiplies every boundary crossing in
§6 for no size benefit over A. **Rejected; recorded as considered.**

### Candidate C — YAML anchors, no structural change

F8 makes this newly available: hoist each generated block into an anchored step once and alias it
in the other jobs.

```yaml
x-blocks:
  redact: &redact_step
    name: Redact SARIF
    run: |
      # BEGIN REDACT_SARIF ... (one copy)
jobs:
  sast-go:
    steps:
      - *redact_step
```

Projected: the 12 redundant `REDACT_SARIF` copies, 11 `SCAN_STATUS`, 2 `NORMALIZE_SARIF` become
short aliases. **File text drops to ≈ 300 KB.**

**Cost, and why it is not recommended as the primary fix.**

- **U4 is decisive and unanswered.** If GitHub measures the file *after* anchor expansion, the
  file is still 608.8 KB and this achieves exactly nothing. The docs do not say. Testing it
  requires a push, which is outside this pass.
- **github.com only (F8)** — no GHES. For a kit distributed to consumers, that is a portability
  regression of the same class the kit exists to avoid.
- Merge keys are undocumented (F8), so only whole-node reuse is available; the anchored step must
  be byte-identical across jobs. The generated blocks are, today.
- Anchors are invisible in the rendered run view, adding a debugging indirection with none of the
  structural benefit of E.

**Verdict: cheap, possibly a no-op, and platform-narrowing. Useful only as a fallback if E and D
are both rejected, and only after U4 is answered empirically.**

### Candidate D — bootstrap job single-sources the blocks at runtime

One `bootstrap` job holds one copy of each module, writes them to disk, uploads a run-scoped
artifact; every consuming job downloads it.

| Change | Bytes |
|---|---:|
| Baseline | 623,411 |
| Drop 12 of 13 `REDACT_SARIF` | −259,788 |
| Drop 11 of 12 `SCAN_STATUS` | −50,359 |
| Drop 2 of 3 `NORMALIZE_SARIF` | −12,366 |
| Add bootstrap + ~15 download steps | +10,000 |
| **Projected** | **≈ 310,900 (≈ 303.6 KB)** |

Artifacts are **run-scoped**, so cross-repo resolvability is preserved by construction — this
depends on none of U1–U5. The pattern is already in use: `report` downloads `sarif-*` via
`actions/download-artifact@v8`.

**Cost.** A `needs: bootstrap` fan-in whose failure marks every scanner `skipped` ->
`NOT_APPLICABLE` -> **green gate**. That must be wired as `COLLECTION_FAILED` + `undetermined=1`
(§6.3). Plus per-run latency, and rework of `inline_normalizer.py` and
`prove_redaction_chain.py`.

**Verdict: the safest *certain* size reduction, and the best fallback if `$/` is unavailable.**

### Candidate E — registry + per-scanner composites (THE OWNER'S MODEL)

Each scanner's steps move into a composite action; the job becomes a ~10-line shell; a registry
file lists the scanners and is used to **validate** the workflow.

#### E.1 The constraint, stated plainly

**GitHub cannot generate jobs from a file at parse time. There is no `jobs: ${{ from registry }}`.**
The workflow graph is fixed when the file is parsed. So a registry can either drive a **runtime
matrix**, or act as a **denominator that validates hand-written jobs**. These are the only two
shapes, and they are assessed separately below.

#### E.2 Variant (a) — dynamic matrix in one job

`discover` emits a JSON list; one job consumes `matrix: ${{ fromJson(needs.discover.outputs.scanners) }}`.
This is the only way to get registry-*driven* job creation.

A clarification on the mechanics, because it changes the argument: **a matrix does not share a
runner.** Each leg is a separate job on its own runner with its own log and its own annotations.
So "shares a runner and collapses the per-scanner annotations" is not the reason to reject it.

**The real reason to reject it is fatal and specific:**

- `needs.<matrix-job>.result` is **one aggregate value for all legs**. The gate reads 14 distinct
  results. With a matrix it gets one. Per-scanner verdicts would have to travel via job outputs —
  and **matrix legs overwrite each other's outputs.** GitHub documents exactly this hazard for
  the reusable-workflow case: "the output will be the output set by the last successful
  completing reusable workflow of the matrix which actually sets a value."
- So `sast-go: NOT_APPLICABLE` and `sast-cpp: FINDINGS` collapse into a single verdict, chosen by
  completion order. **That is `NOT_APPLICABLE`, `CLEAN` and `FINDINGS` collapsing into one
  value — the exact failure the kit forbids, introduced structurally.**
- `codeql:skipped -> UNAVAILABLE` and the secrets-always-block rule are per-scanner special
  cases that have nowhere to live.

**Variant (a) is rejected, and the owner's instinct against it is right — for a stronger reason
than the one offered.**

#### E.3 Variant (b) — explicit jobs, registry as DENOMINATOR (RECOMMENDED)

Jobs stay explicit and hand-written — 17 of them, as today. A registry
(e.g. `assurance-taxonomy.yaml`, which already exists) gains a row per scanner:

```yaml
scanners:
  sast-go:
    composite: .github/actions/scan-gosec
    capability: sast-go
    discover_flag: has_go
    sarif: gosec.sarif
```

and a checker asserts, for every registered scanner:

1. a job of that name exists in `reusable-security.yml`;
2. that job `uses:` the registered composite;
3. `security-gate.needs` contains it **and** the gate's scanner loop reads its `.result`;
4. `report.needs` contains it;
5. its capability name appears in `CAPABILITY_REGISTRY`;

and — the half that matters most — **that no job exists which is not registered.**

**The owner's central claim is correct: this converts the hand-written "does the gate enumerate
every job?" check into arithmetic.** `tests/check_gate.py` exists today precisely because the
enumeration is hand-kept; its own docstring says the kit "shipped exactly that defect once". A
denominator makes the comparison total rather than a spot-check, and it closes the gap that
`check_gate.py` cannot see today: the gate's `needs:` list and the gate's *scanner loop* are two
different enumerations, and `image-scan` was once in the first and missing from the second. The
workflow's own comment records it:

> `image-scan` WAS IN `needs` AND NOT IN THIS LIST, WHICH IS THE WORST OF BOTH. The gate waited
> for the container scan and then never read its result… `tests/check_gate.py` compares `needs`
> against the job list and cannot see this, because enumerating a dependency is not the same as
> enforcing on it.

**A registry-as-denominator check is the first mechanism proposed here that would have caught
that.** That is a genuine gain, independent of file size.

#### E.4 Projected sizes

| File | KB |
|---|---:|
| `reusable-security.yml` (parent: header, 17 job shells, full gate logic) | **≈ 42** |
| `.github/actions/redact-sarif/action.yml` | 21.6 |
| `.github/actions/scan-report/action.yml` | 50.3 |
| `.github/actions/discover/action.yml` | 37.2 |
| `.github/actions/sbom-licenses/action.yml` | 9.9 |
| `.github/actions/normalize-sarif/action.yml` | 6.2 |
| `.github/actions/scan-status/action.yml` | 4.6 |
| 13 per-scanner composites (3.4 – 21.8 KB each) | ≈ 127 |
| **Largest single file** | **≈ 50** |
| **Total repo bytes** | **≈ 299** (from 608.8) |

**Parent ≈ 42 KB — 8% of the limit. Largest file ≈ 50 KB. Total bytes halve**, because the
shared blocks are deduplicated *and* the per-scanner logic leaves the workflow. This is the best
result on every size axis, and it is the only candidate that also improves the enforcement
story.

#### E.5 What E costs — including what the owner flagged

- **`uses: ./` does not work cross-repo (F10).** This is the original reason for inlining and it
  is real. **E is viable only via `$/` (F9)**, which is documented to resolve against the kit's
  own repo. That means: **github.com only, runner ≥ 2.336.0, no GHES.** If the kit must support
  GHES, **E is blocked** and the answer is D.
- **Composites cannot define jobs.** Correct, and it is why variant (b) keeps 17 explicit jobs.
  The composite holds *steps*; the job shell holds `if:`, `needs:`, `timeout-minutes`,
  `permissions` and the result contract. Nothing about the gate changes.
- **Debugging indirection.** A step's logic is no longer visible in the workflow file. Composite
  steps do appear in the run log, so runtime visibility is preserved, but reading the *file* no
  longer tells you what a scanner does. Real cost, partially offset by the registry naming the
  composite for every scanner.
- **Pin drift multiplies.** 19 composite directories are 19 more places a pinned action version
  can drift. `scripts/pin-actions.sh` and `tests/check_pinned_artifacts.py` already exist and
  **must be extended to `.github/actions/**` before E ships, not after.** This is a genuine new
  surface and it is the cost most likely to be underestimated.
- **`check_export_safety.py` / `export_for_adoption.py`** operate on a file set that E changes;
  `scripts/export-deny.txt` will need review.
- **U5**: composite size limits are undocumented. At ≈50 KB max this is not close to any
  plausible limit, but it is unverified.

#### E.6 Does a registry actually simplify `reconcile_validation.py` and `capability_inventory.py`?

**Partially, and the distinction matters — it should not be oversold.**

**Genuine simplification (drift):** today the scanner set is written out by hand in *at least
five* places — `security-gate.needs`, the gate's scanner loop, `report.needs`,
`CAPABILITY_REGISTRY`, and `capability_inventory.py`'s `INVOCATION` patterns. A registry makes
one of these the denominator and the other four *derived or checked*. Divergence between them
becomes impossible rather than merely discouraged. Given that this repo has four recorded
incidents of exactly that divergence, this is a real and substantial gain.

**Not simplified (authoring):** adding a scanner still means writing a composite, a job shell,
and a registry row. The registry removes the *duplication* of the enumeration, not the *entry*.
Anyone claiming a registry means "add a scanner by editing one file" is describing variant (a),
which §E.2 rejects.

**Relocated, not removed:** `CAPABILITY_REGISTRY` could be *generated from* the registry rather
than hand-kept — but the mapping from capability to *what proves it* (the `VALIDATION` table,
with its `observed` / `unknown` / `never-referenced` states and its expiry dates) is a judgement
about evidence and **cannot be derived from a registry**. That half stays hand-maintained, and
should. The kit's own framing applies: the registry "absorbed that promise for the
machine-readable half and left the prose half exactly where it was."

**What a registry cannot do:** it can assert that `sast-go` has a job, a composite, a gate edge
and a capability name. **It cannot assert that the composite actually runs gosec.** That remains
the job of `validate-scanners.yml` (proves the tool) and `consumer-path-test.yml` (proves the
contract). A registry that was mistaken for proof of behaviour would be this kit's founding
defect in a new location.

---

### Candidate F — cost packing: group scanners into fewer jobs

**Decided: F-A, SAST by language** (§F.3). F-B, one combined SAST group, is retained as a
documented alternative with its cost (§F.4).

File size is not the only axis. **GitHub bills per job, rounded up to the minute**, so job count
is a recurring cost the plan must price.

#### F.1 The model, checked against a real run

`validate-scanners` run `35770960425`: 15 jobs, 373 s of actual work, **17 billed minutes**,
10.8 minutes of pure rounding — **174% overhead**. Applying `ceil(seconds/60)` per job to the
published per-job durations (gosec 130 s, checkov 46, semgrep 29, flawfinder 23, osv 22, dotnet
21, trivy 21, syft 18, plus seven short jobs) reproduces **exactly 17**. The model is sound.

**One caveat before it is generalised:** `validate-scanners` is a *probe* workflow of very short
jobs, which is why its overhead is 174%. `reusable-security`'s jobs additionally pay checkout,
toolchain setup, redaction and SARIF upload, so they are longer and the *proportional* waste is
smaller. The cost axis is real; the 174% figure is specific to the probe workflow and should not
be quoted for `reusable-security`.

#### F.2 The asymmetry that makes grouping work

> **A skipped JOB is free. A skipped STEP inside a running job is not — the minute is already
> paid.**

Discovery already solves the *inapplicable* case: a scanner whose `if:` is false bills nothing
today. What discovery does **not** solve is the **applicable-but-fast** case, which is most
scanners: a 21-second scan bills a full minute.

Two consequences, and the second corrects a natural reading of the first:

1. **A group must carry its own job-level `if:`, and it must be the exact OR of its members'
   applicability.** Otherwise a group with nothing to do still runs and bills a minute — turning
   a free skip into a paid one. This is the one way grouping can cost *more* than today.
2. **Given that `if:`, grouping can never cost more than the current shape.** For any
   non-negative durations, `ceil(a) + ceil(b) >= ceil(a+b)`. Worked from the measured numbers:

   | Split | Grouped |
   |---|---|
   | `ceil(29) + ceil(21)` = 2 | `ceil(50)` = **1** |
   | `ceil(20) + ceil(25)` = 2 | `ceil(45)` = **1** |
   | `ceil(130) + ceil(213)` = 7 | `ceil(343)` = **6** |
   | `ceil(46) + ceil(21)` = 2 | `ceil(67)` = 2 |

   So grouping is **weakly better on billing, always**. Sharing an applicability signal maximises
   the *saving*; it is not required to avoid a *penalty*. The real price of grouping is wall
   clock and attribution granularity — not money.

#### F.3 F-A — SAST by language (OWNER'S DECISION, RECOMMENDED)

| Group | Members | Seconds | Billed |
|---|---|---:|---:|
| `discover` | — | 60 | 1 |
| `sast-python` | bandit + codeql | 110 | 2 |
| `sast-go` | gosec | 130 | 3 |
| `sast-dotnet` | — | 21 | 1 |
| `sast-java` | — | ~40 | 1 |
| `sast-cpp` | flawfinder | 23 | 1 |
| `sast-multi` | **semgrep — multi-language, `always()`** | 29 | 1 |
| `sca` | trivy + osv + depcheck + syft | 101 | 2 |
| `secrets` | gitleaks/detect-secrets | 20 | 1 |
| `iac` | checkov | 46 | 1 |
| `container` | trivy-image | 21 | 1 |
| `code-quality` | lint | 25 | 1 |
| `report` + `security-gate` | — | 20 | 1 |
| **TOTAL** | **13 jobs** | | **17** |

**Three structural points that must not be lost in implementation:**

- **`semgrep` is multi-language and runs `always()`. It is NOT a language group and must not be
  forced into one language's bucket.** It gets its own job, `sast-multi`.
- **`sast-python` (bandit + codeql) is the only genuine grouping inside SAST.** It saves nothing
  today — `ceil(110/60) = 2 = ceil(15/60) + ceil(90/60)` — **but it is where CodeQL's 90 s
  lives. Re-cost it if CodeQL expands to more languages**, because that is the one cell in this
  table that changes character as the kit grows.
- **Each language group's `if:` comes straight from `discover`'s existing per-language outputs.**
  The gating writes itself; no new discovery logic is required. This is why F-A is cheap to
  implement once E exists.

**Where the savings actually come from** — not from SAST at all:

| Source | Saving |
|---|---:|
| `sca`: 4 jobs → 1 | 2 min |
| `report` + `security-gate`: 2 → 1 | 1 min |
| SAST by language: 7 → 6 jobs | 1 min |
| **Every skipped language group on a real repo** | **the rest** |

#### F.4 F-B — one combined SAST group (ALTERNATIVE, not chosen)

| Group | Seconds | Billed |
|---|---:|---:|
| one **SAST** job (semgrep, bandit, codeql, dotnet, java, gosec, flawfinder) | 343 | 6 |
| *(all other groups as F-A)* | | 8 |
| **TOTAL** | **8 jobs** | **14** |

#### F.5 The comparison — and why 17 vs 14 is NOT a straight loss

| Shape | Jobs | Billed (polyglot) | Wall clock |
|---|---:|---:|---:|
| Today, one job each | 18 | 21 min | 130 s |
| **F-A, SAST by language (chosen)** | **13** | **17 min** | **130 s** |
| F-B, one SAST group | 8 | 14 min | 343 s |

**The 3-minute gap is the wrong headline, and the plan says so deliberately.**

> **All three figures assume a repository containing ALL SEVEN LANGUAGES — which is the kit's own
> fixture, not a consumer.** On a single-language repository the two shapes are **equivalent**,
> because the irrelevant language groups **skip entirely, and a skipped job is free** (§F.2).

Worked, for a Python-only repository:

| Shape | Billed |
|---|---:|
| Today | **12 min** |
| F-A by language | `discover 1` + `sast-python 2` + `sast-multi 1` + `sca 2` + `secrets 1` + `code-quality 1` + `report+gate 1` = **9 min** |
| F-B one SAST group | `discover 1` + `SAST 3` *(bandit 15 s + codeql 90 s + semgrep 29 s = 134 s; the other four skip as steps)* + `sca 2` + `secrets 1` + `code-quality 1` + `report+gate 1` = **9 min** |

**F-B cannot beat F-A here** — it pays the same minutes for a group whose irrelevant steps skip
*inside* it, which costs exactly what skipping them as jobs costs: nothing extra, but nothing
saved either. A **25–33% saving on the shape a real consumer actually runs**, identical under
both.

*(Figure note: the measured comparison supplied for the Python-only case was 12 → 8. My model
reproduces 12 → 9. The one-minute divergence turns on whether `code-quality` and `container` are
applicable in that fixture. I have not reconciled it and am reporting my own arithmetic rather
than adopting a number I cannot derive.)*

**So the trade the owner has bought is:** up to **3 billed minutes on polyglot repositories
only**, in exchange for:

1. **Wall clock** — gosec stays at 130 s instead of serialising behind six other scanners
   (343 s). F-A is the *only* packed shape that keeps the critical path where it is today.
2. **Per-language attribution** — a Go failure is a `sast-go` failure, visible as its own check,
   not a step buried inside a blob. This matters most for the surface §F.6(c) identifies as
   degraded under grouping, and F-A preserves it for the axis consumers care about.

**This is a good trade and the recommendation adopts it.** The cost falls only on the polyglot
case, which is the kit's test fixture rather than its consumers, while the benefits fall on every
repository.

#### F.5a What still cannot be grouped

**The owner's three families (SAST / SCA / secrets) do not cover everything, and the gap is
named here rather than filled silently.** **IaC (checkov), container/image scanning, and
code-quality/lint are none of SAST, SCA or secrets.** They have different artifacts and different
applicability signals — IaC keys on Terraform/ARM/Bicep presence, container on `image_ref` being
supplied, code-quality on `enforce_lint`. Forcing them into one of the three would couple
unrelated applicability signals and violate §F.2's requirement that a group's `if:` be its
members' exact OR. **They are proposed as three groups of their own** in the F-A table.

**`discover` and `security-gate` cannot be grouped.** `discover` is structurally first — every
other job's `if:` reads its outputs. The gate is structurally last and consumes every result.
**`report` + `security-gate` CAN merge**, since both are `if: always()` at the end — one free
minute. (This merges the one job the gate deliberately checks *as itself* rather than as a
scanner; the gate's existing "report is not exempt" logic must become an internal step check —
see §7 step 15.)

#### F.6 Does per-scanner attribution actually survive the repacking?

The owner's insight — **composites decouple scanner identity from job packaging** — is correct,
and it is the reason F is possible at all. Today a scanner *is* a job, so grouping would destroy
attribution. With each scanner a composite emitting its own result, one job can run several and
the gate can still consume N distinct verdicts. But the claim needs testing rather than
assuming, and three things genuinely change:

**(a) The gate can no longer read `needs.<scanner>.result`.** Six scanners in one job produce
**one** job result. Per-scanner verdicts must move to **job outputs**
(`needs.sast.outputs.gosec_state`). F11 confirms there is no count limit on outputs, and — unlike
the matrix in §E.2 — a single non-matrix job's outputs do not overwrite each other. **So the
mechanism works.**

This is arguably an *improvement*: deriving state from a job result is exactly what creates the
`skipped -> NOT_APPLICABLE` collapse risk. Explicit per-scanner state outputs are more precise.

**But it introduces a specific new failure mode.** A job result is produced by GitHub and cannot
be omitted. An output must be *written by the job*. If the runner dies, times out, or is
cancelled, **every scanner in that group reports the empty string** — and the empty string reads
as a state (§3). **Required mitigation:** the gate treats the group's job result as an envelope —
if `needs.<group>.result != success`, every member whose output is empty is `COLLECTION_FAILED`,
never `NOT_APPLICABLE`. The registry (§E.3) is what tells the gate which scanners belong to which
group, so F **depends on E(b)** and must not ship before it.

**(b) A scanner failing mid-group blocks the rest.** Steps run sequentially; a failed step skips
the remainder. Grouping seven scanners means scanner 1 failing silently costs coverage of 2–7.
**Required mitigation:** each scanner step runs with `continue-on-error: true` and records its own
verdict, with an `if: always()` aggregation step. The consequence must be stated plainly: **this
moves enforcement out of the job result and into the outputs.** A scanner failure no longer fails
the job; it fails the gate via its recorded state. That is a real transfer of trust from a
platform-enforced signal to a self-reported one, mitigated only by the envelope rule in (a).

**(c) Annotations survive; check-level granularity does not.** `::error` / `::warning` and
`$GITHUB_STEP_SUMMARY` are step-scoped, so per-scanner annotations and summary rows are
unaffected. **What is lost is the per-scanner row in the PR checks list** — seven red X's become
one. For a kit whose gate summary is explicitly "what a reviewer actually reads before approving
a promotion", that is a real UX regression and should be weighed, not waved through.

**Verdict: the owner's claim holds, conditionally.** Attribution survives — but only with the
envelope rule, `continue-on-error` plus explicit result capture, and the registry as denominator.
**Without all three, grouping produces a gate that cannot attribute a failure, and the saving is
not worth that.**

#### F.7 Wall clock vs. billed minutes

They are different costs and, under F-B, move in opposite directions. **Under F-A they do not** —
which is the decisive practical argument for the owner's choice.

| Shape | Jobs | Billed (polyglot) | Billed (single-language) | Wall clock |
|---|---:|---:|---:|---:|
| Current | 18 | 21 min | 12 min | 130 s |
| **F-A (chosen)** | **13** | **17 min** | **9 min** | **130 s — unchanged** |
| F-B | 8 | 14 min | 9 min | 343 s (2.6×) |

F-B buys its extra 3 polyglot minutes by serialising gosec behind six other scanners. **F-A takes
the saving that costs nothing and declines the one that costs the critical path.** Since the
single-language column — the consumer case — is identical under both, F-B's advantage exists only
for the kit's own fixture.

If the gate sits in a PR path, wall clock is developer latency paid in attention, and F-A is
clearly correct. If it only ever runs nightly, F-B's 3 minutes become arguable. That residual
judgement is decision 11.

---

## 5. Recommendation

**Two phases. Unblock with D; adopt E as the target architecture. F rides on E, not before it.**

### Phase 1 — Candidate D (immediate, ≈ 304 KB)

Because it depends on **none** of U1–U5, uses only mechanisms already present in this repo, and
is one commit against one file with a clean `git revert`.

### Phase 2 — Candidate E variant (b) (target, parent ≈ 42 KB)

Because it is the only candidate that also fixes an enforcement gap (§E.3), halves total bytes,
and matches the structure the workflow already has. **Conditional on the `$/` decision (§5.2).**

### Phase 3 — Candidate F-A (cost packing by language, 21 → 17 billed min polyglot / 12 → 9 single-language)

**F must come after E, never before it.** F's correctness depends on three things E provides:
per-scanner composites that emit their own verdicts, the registry that tells the gate which
scanner belongs to which group, and the envelope rule that distinguishes a dead runner from a
clean scan (§F.5). Grouping scanners *before* they are composites would mean grouping jobs whose
only verdict channel is the job result — which is precisely the attribution loss the owner
identified and the kit forbids.

Sequencing all three: **D removes the duplication, E moves the logic and makes the registry the
denominator, F then repacks jobs purely as a cost decision** — and by then job packaging is
independent of what the gate enumerates, which is the whole point of the owner's insight.

### 5.1 Why not E immediately

E is the right destination and the wrong first move while the workflow cannot start:

- E rests on **F9**, which is seven weeks old at time of writing and which this repository has
  never exercised.
- E touches 20+ files and four validators. D touches one file.
- D's rollback is `git revert`. E's is not.
- **D and E are not in conflict.** D deduplicates the shared blocks; E moves them into
  composites. D's `bootstrap` job is deleted by E. Phase 1 is not wasted work — it is the same
  deduplication, staged.

### 5.2 The `$/` claim — exactly how far it is established

**Established:** GitHub documents that `$/` "resolves to the called workflow's repository, not
the calling workflow's repository", explicitly for the cross-repo case, and the changelog states
it works for "workflow steps, composite action steps, nested composition, and reusable workflow
calls." That is a direct documentary answer to the exact question the kit's inlining decision was
built around.

**Not established:** this repository has never run it. No artifact here uses `$/`. The kit has
never been called from a genuinely separate repository at all —
`consumer-path-test.yml` says so itself:

> it uses a `./` reference, so it cannot prove cross-repository resolution or the private-repo
> access policy. LEVEL 2 is a genuinely separate repository calling
> `<owner>/secure-cicd-kit/.github/workflows/reusable-security.yml@<ref>`, and only Level 2
> makes the security surface handoff-ready.

**Therefore: `$/` must be proven by a Level 2 two-repo test before Phase 2 ships.** Adopting E on
documentation alone would repeat the kit's founding error — trusting that a referenced thing
resolved because nothing said it hadn't. The 14 gitleaks rules failed *silently* with green CI;
a `$/` misresolution would fail the same way.

---

## 6. Boundary behaviour

### 6.1 Under D and E: unchanged

Neither crosses a workflow boundary. The gate keeps reading `needs.<job>.result` for 17 explicit
jobs in one file. `NOT_APPLICABLE` / `CLEAN` / `COVERAGE_GAP` cannot collapse across a boundary
that does not exist. **The proof that a failing job fails the gate is the proof that already
exists**, and `tests/check_gate.py` keeps working unmodified.

### 6.2 Under A or B: three separate breakages

1. **U2 — the collapse.** If a child runs with all internal jobs skipped and reports `success`,
   `NOT_APPLICABLE` becomes `PASS`: "no Go code here" becomes "Go was scanned and was clean."
   Undocumented; must be established empirically, not reasoned about. Mitigation: every child
   exports an explicit per-scanner state output (F11 confirms no count limit) set from a job with
   `if: always()`, and the parent reads **that**, never the child's job result, for
   applicability.
2. **Secrets (F4/F5).** `SEMGREP_APP_TOKEN` must be re-declared and re-passed at every hop.
   `inherit` is unavailable to consumers outside the kit's org — so an external consumer's calls
   break in a way in-repo testing cannot reveal.
3. **The empty string (§3).** 14 verdicts re-plumbed through child outputs; a mis-named reference
   evaluates to `""` rather than erroring.

### 6.3 Under D: the one new hazard

`needs: bootstrap` means a bootstrap failure marks scanners `skipped` -> `NOT_APPLICABLE` ->
**green gate**. Design requirements:

1. `bootstrap` carries no scanner logic; it writes files and uploads one artifact.
2. The gate enumerates `bootstrap` and maps its failure to `COLLECTION_FAILED` ->
   `undetermined=1` — never to a scanner state. The vocabulary already has `COLLECTION_FAILED`.
3. Scanners guard with `if: always() && needs.bootstrap.result == 'success'`, and the gate
   special-cases that combination as it already special-cases `codeql:skipped`.
4. `tests/check_gate.py` will *require* `bootstrap` in the gate's `needs` — **the existing check
   already covers D's new edge, and does not cover A's.**

### 6.4 What the existing checks catch, per candidate

| Check | Today | Under A/B | Under D | Under E(b) |
|---|---|---|---|---|
| `check_gate.py` | Every job in the one file is in the gate's `needs` | **Blind to children** — `WF`/`GATE` hardcoded; a child's job could sit outside any gate. Must become recursive. | Works; requires `bootstrap` enumerated | Works, and is **subsumed by the registry check**, which is stronger |
| `capability_inventory.py` | Finds the job, checks it is in `security-gate.needs` | Breaks silently — gate `needs` names children, not scanners; capabilities drop from `ENFORCED (static)` | Works | Works; `INVOCATION` patterns must also scan `.github/actions/**` |
| `reconcile_validation.py` | Globs `.github/workflows/*.yml`; unregistered artifact = `VALIDATION_COVERAGE_GAP` | Each child needs a registry entry — **fails loudly, therefore safe** | No change | `CAPABILITY_REGISTRY` can be generated from the registry; `VALIDATION` stays hand-kept |
| `prove_redaction_chain.py` | Extracts the redactor *from the workflow* | Finds fewer redactors than scanners | Must extract from `bootstrap` and assert each job acquires it | Must extract from the composite and assert each job uses it |
| `check_pinned_artifacts.py` | Workflows | unchanged | unchanged | **Must extend to `.github/actions/**`** |

Note the asymmetry under A/B: `reconcile_validation.py` fails **loudly**; `check_gate.py` and
`capability_inventory.py` fail **silently**, both in the direction of reporting clean.

### 6.5 Capability identity and the debt ratchet

`reconcile_validation.py` records:

> registering a capability on two artifacts does NOT double-count the debt, because accepted
> deferrals are deduplicated by capability.

So **moving** a capability does not raise debt, provided none is renamed or invented.
`MAX_ACCEPTED_DEBT = 15`, currently 15/15.

**No candidate here requires a deferral, and none requires raising the cap** — provided:

- `bootstrap` (D) is **not** given a capability name. It is infrastructure, not an assurance
  claim; naming it would invent a claim to satisfy a registry.
- E's composites inherit the capability names of the jobs they implement. A composite is an
  implementation of `sast-go`, not a new capability.

The pressure point under A/B is different: six new artifacts each need a `CAPABILITY_REGISTRY`
entry, and the tempting fix for the resulting `VALIDATION_COVERAGE_GAP` is to invent a capability
per child — which would raise the cap for bookkeeping reasons.

---

## 7. Migration sequence

Steps 1–3 are test/tooling only and do not alter the shipped workflow.

### Phase 1 — D

| # | Step | Verify | Revert |
|---|---|---|---|
| 0 | Record baseline: 12 validators exit 0; blob = 623,411 B (§8.1) | Re-run §8.1 | n/a |
| 1 | Teach `check_gate.py` that a bootstrap-class job must be enumerated and maps to `COLLECTION_FAILED` | Exits 0 against the **unmodified** workflow | one file |
| 2 | Teach `prove_redaction_chain.py` to locate the redactor in a named job and assert each consumer acquires it | **Must pass against today's 13-copy layout first** — otherwise it is not testing the change | one file |
| 3 | Rework `inline_normalizer.py` to emit one copy per module | `--check` shows the intended diff and nothing else | one file |
| 4+5 | Add `bootstrap`; remove the redundant copies. **One commit** | Blob < 320 KB; yamllint 0; actionlint unchanged; 12 validators 0; `inline_normalizer.py --check` 0 | `git revert` |
| 6 | Dispatch `consumer-path-test.yml` | Workflow **starts**; clean fixture PASSes; negative fixture FAILs the caller | `git revert` |
| 7 | Force `bootstrap` to fail on a scratch branch | Gate reports `COLLECTION_FAILED` / `undetermined=true` — **not** `NOT_APPLICABLE`, **not** green | discard branch |

**Steps 4 and 5 cannot be separated:** step 4 alone increases file size, and the file is already
over the limit, so an intermediate commit still would not start. This is the only non-atomic
point, and its rollback is one `git revert`.

### Phase 2 — E(b), gated on §5.2

| # | Step | Verify | Revert |
|---|---|---|---|
| 8 | **Level 2 test: a genuinely separate repository calls the kit, and the kit uses one `$/` composite.** Nothing else in Phase 2 starts until this passes | The composite's step appears in the run log of a cross-repo run | n/a — this is a go/no-go |
| 9 | Extend `pin-actions.sh` and `check_pinned_artifacts.py` to `.github/actions/**` | Exit 0 before any composite is added | one file each |
| 10 | Add the registry rows and the denominator checker, asserting today's structure | Checker exits 0 against the **unmodified** workflow — proves the denominator is right before it is relied on | one file |
| 11 | Extract shared blocks to composites (redact, status, normalize, report, sbom) one at a time | After each: 12 validators 0; `consumer-path-test.yml` dispatch | per-composite revert |
| 12 | Extract per-scanner logic, one scanner per commit | As above | per-scanner revert |
| 13 | Delete `bootstrap`; retire `inline_normalizer.py` | Blob ≈ 42 KB; all validators 0 | `git revert` |

### Phase 3 — F, gated on E being complete

| # | Step | Verify | Revert |
|---|---|---|---|
| 14 | Add the envelope rule to the gate: for any group job, `result != success` means every member with an empty state output is `COLLECTION_FAILED`, never `NOT_APPLICABLE` | Unit-test the gate logic against a synthetic empty-output case **before** any job is merged | one file |
| 15 | Merge `report` + `security-gate` (both `if: always()`); convert the gate's "report is not exempt" check into an internal step check | Gate still fails when reporting fails — the existing behaviour must be re-proven, not assumed | one commit |
| 16 | Group one family at a time, starting with **SCA** (4 scanners, 101 s — the lowest-risk group: short, shared applicability, no wall-clock impact) | Per-scanner rows still appear in the step summary; `capability_inventory.py` still reports each as `ENFORCED` | per-group revert |
| 17 | Prove attribution under failure: force one scanner inside a group to fail | The gate names **that scanner**, the later scanners in the group still ran (`continue-on-error`), and the group's other verdicts are intact | scratch branch |
| 18 | Remaining groups, **SAST last**, split **by language** per F-A. Each language job's `if:` reads `discover`'s existing per-language output — no new discovery logic | Per-language attribution visible: a seeded Go finding surfaces as `sast-go`, not as a step in a blob | per-group revert |

**Step 17 is the gate on Phase 3.** If a scanner failing inside a group cannot be attributed to
that scanner, F does not ship — the 7 minutes/run are not worth a gate that cannot say what
failed.

**Rollback for the decomposition itself.** Phase 1 is one commit. Phase 2 is deliberately
sequenced one composite per commit, and Phase 3 one group per commit, so that every intermediate
state is a working workflow and any single step reverts alone. **Do not batch step 12 or 18.**

**Do not claim the workflow runs until step 6 has actually been dispatched.** Steps 0–5 are
static checks; none starts a workflow.

---

## 8. Evidence from this pass

### 8.1 Validator exit codes (baseline, unmodified tree)

| Validator | Exit |
|---|---:|
| `tests/check_source_hygiene.py` | 0 |
| `tests/check_export_safety.py` | 0 |
| `tests/check_artifact_identity.py` | 0 |
| `tests/check_buildonly_contract.py` | 0 |
| `tests/check_doc_currency.py` | 0 |
| `tests/check_reversal_preconditions.py` | 0 |
| `tests/lint_injection.py` | 0 |
| `scripts/reconcile_taxonomy.py` | 0 |
| `tests/reconcile_validation.py` | 0 |
| `tests/capability_inventory.py` | 0 |
| `tests/check_gate.py` | 0 |
| `tests/check_redaction_parity.py` | 0 |

### 8.2 Control-byte scan

All `.github/workflows/*.yml`, `scripts/*` and `tests/*.py` scanned for bytes < 0x20 excluding
tab/LF/CR: **0 found.** The backspace-escape class of damage is not currently present.

### 8.3 Linters

- **yamllint** (config inlined from `self-test.yml`): **exit 0** on LF-normalised content —
  warnings only (`line-length`, one `comments-indentation`), no errors.
  *On the Windows working tree it exits 1 with 23 `new-lines` errors. Those are a CRLF checkout
  artifact and do not occur on CI. Verified by re-running against an LF-normalised copy.*
- **actionlint 1.7.7**: **acquired successfully** (2,229,473-byte release archive — a real
  download, not the 92-byte truncation this repo has been bitten by) and run. **Exit 1, one
  finding:**

  ```
  .github/workflows/verify-azure-oidc.yml:55:3: maximum number of inputs for
  "workflow_dispatch" event is 10 but 11 inputs are provided.
  ```

  **This is almost certainly a false positive from a stale linter rule.** Per F12, GitHub raised
  the `workflow_dispatch` input cap from 10 to 25 on **2025-12-04**; actionlint 1.7.7 encodes the
  old limit. It should be confirmed and then either waived or fixed by upgrading actionlint —
  **it should not be "fixed" by removing an input.**

  **`reusable-security.yml` itself is actionlint-clean.**

---

## 9. Risks

**R1 — A child's verdict never reaches the parent gate.** The risk the owner named. Under A/B,
`check_gate.py` is hardcoded to one file and would be **blind to every child's internal jobs**;
`capability_inventory.py`'s `ENFORCED` detection breaks at the same moment, in the same
direction — toward reporting clean. Two of three registries fail silently. **Absent under D and
E**, which keep one file, one gate, 17 jobs. **E actively reduces this risk** (§E.3).

**R2 — `NOT_APPLICABLE` collapses into `CLEAN`.** Three doors: §6.2 (split, undocumented U2),
§6.3 (D's bootstrap edge), §E.2 (matrix output overwrite). D's door is one edge in one file and
is closeable by design and provable by step 7. The others are structural.

**R3 — Cross-repo resolution.** U1 is **not documented**. If it resolves against the consumer,
A/B convert a loud startup failure into a **silent** failure for every external consumer —
strictly worse. D takes no cross-repo risk. E takes a *documented* one (F9) that must still be
proven (step 8).

**R4 — The empty string reads as a state.** Applies to A/B only; already happened once to
`image-scan`. D and E re-plumb nothing.

**R5 — `bootstrap` as a single point of failure.** New under D. Contained, loud if wired per
§6.3, provable by step 7 — which gates shipping D.

**R6 — Pin drift across 19 composite directories.** New under E. `pin-actions.sh` and
`check_pinned_artifacts.py` must be extended **before** step 11, not after. Most likely cost to
be underestimated.

**R7 — "608 KB means too many jobs."** The census says otherwise. A split on that premise adds
overhead, spreads the duplication across more files, and leaves the real cause — 13 copies of one
module — in place.

**R8 — A registry mistaken for proof.** E's registry proves *wiring*, never *behaviour*. It
cannot establish that a composite runs the scanner it claims. Overselling it would reproduce the
kit's founding defect — a name read as a capability — one layer out.

**R9 — Measuring on Windows.** `wc -c` overstates by 11,237 bytes (§0). Someone could "verify" a
fix that has not cleared the limit, or reject one that has.

**R10 — `$/` is seven weeks old.** F9 is documented but new, github.com-only, and requires runner
≥ 2.336.0. Self-hosted runners below that version would fail. Unknown whether any consumer uses
GHES or pinned older runners — **that is a question for the owner, not an assumption to make.**

**R11 — Enforcement moves from the job result to a self-reported output.** New under F. Grouping
requires `continue-on-error` per scanner (§F.6b), so a scanner failure no longer fails its job; it
fails the gate via a state it wrote itself. A dead runner writes nothing, and the empty string
reads as a state. **Mitigated only by the envelope rule (§F.6a) plus the registry as denominator
(§E.3) — which is why F must not ship before E.** This is the most consequential behavioural
change in the plan and should not be approved as a cost optimisation alone.

**R12 — A group's `if:` drifts from its members'.** If a group's job-level condition is coarser
than the exact OR of its members, the group runs with nothing to do and pays a minute that used to
be free — grouping then costs *more* than today (§F.2). Under F-A the language groups take their
condition directly from `discover`'s existing per-language outputs, which makes drift unlikely but
not impossible. **The registry check (§E.3) should assert that every scanner's applicability
signal appears in its group's `if:`.**

**R13 — Per-scanner check granularity is lost where scanners are grouped.** `sca` collapses four
checks into one; `sast-python` two into one. Annotations and summary rows survive (§F.6c); the PR
checks list does not. **F-A deliberately preserves granularity on the language axis and spends it
on the SCA axis** — a defensible asymmetry, but one that should be chosen knowingly rather than
inherited from the packing.

**R14 — The cost model is calibrated on a probe workflow.** All billed-minute figures derive from
`validate-scanners` run `35770960425` and tool-level proxies, not from measured
`reusable-security` durations — that workflow has not started since 2026-09-16, so no recent
measurement exists. The model reproduces the known total exactly (§F.1), but
`reusable-security`'s jobs carry additional checkout/toolchain/redaction/upload time, so absolute
minutes will be higher and proportional savings lower. **Re-measure after Phase 1, when the
workflow starts again, before committing to Phase 3.**

---

## 10. What is needed from the owner — decisions, not tasks

1. **Approve the two-phase shape (D now, E as target), or direct otherwise.** If a split (A/B) is
   directed instead, U1 and U2 must be answered empirically first — they are the difference
   between a fix and a silent outage for external consumers.

2. **Must the kit support GitHub Enterprise Server, or self-hosted runners below 2.336.0?**
   This single answer decides Phase 2. `$/` is github.com-only (F9); YAML anchors are too (F8).
   **If GHES is required, E and C are both blocked and D is the terminal answer at ≈304 KB.**
   Nothing else in this plan turns on one fact as sharply as this.

3. **Accept ≈304 KB after Phase 1**, against a 300 KB target and a 500 KB limit — on the
   understanding that Phase 2 takes the parent to ≈42 KB. If ~304 KB is not acceptable even as an
   interim, Phase 2 must start immediately and decision 2 becomes urgent.

4. **Ratify the bootstrap-failure semantics:** a `bootstrap` failure presents as
   `COLLECTION_FAILED` + `undetermined=true`, never `NOT_APPLICABLE`, never a green gate. §7
   step 7 is written to prove whichever answer is given.

5. **Confirm `bootstrap` gets no capability name**, and that E's composites inherit the
   capability names of the jobs they implement. Otherwise the 15/15 ratchet takes pressure for
   bookkeeping reasons.

6. **Authorise the Level 2 cross-repo test as a funded piece of work.** It is step 8's go/no-go
   for Phase 2, and it closes a gap `consumer-path-test.yml` documents about itself. It needs a
   real second repository; it cannot be done from inside this one.

7. **Decide how much of `CAPABILITY_REGISTRY` should be generated** from the scanner registry.
   Recommendation: generate the capability-to-artifact mapping; **keep the `VALIDATION` evidence
   table hand-maintained**, because what proves a capability is a judgement, not a lookup.

8. **Triage or log `verify-azure-oidc.yml`'s actionlint finding** (§8.3). Probable stale-rule
   false positive; currently failing the lint job; unrelated to this decomposition.

9. **Confirm F-A (SAST by language) over F-B, now recorded as decided.** The plan is built around
   it. The cost is up to 3 billed minutes **on polyglot repositories only** — the kit's own
   fixture, not its consumers — bought back in wall clock and per-language attribution (§F.5).
   **Noting one consequence the decision implies:** the kit's own `consumer-path-test.yml` runs
   the polyglot fixture, so **the kit pays the 3 minutes on every self-test while consumers pay
   none.** That is the right way round, but it should be a known choice rather than a surprise in
   a billing report.

10. **Ratify the enforcement transfer in §F.6, or stop F.** Grouping requires that a scanner
    failure be reported by the scanner rather than enforced by GitHub (R11). This is a change in
    what the gate trusts. **If it is not acceptable, F does not ship and the plan ends at Phase 2**
    — which still delivers the size fix and the registry. The 7-minute saving is not worth a gate
    that cannot attribute a failure, and §7 step 17 exists to prove it can.

11. **Is this gate on the PR path or nightly?** Wall clock is developer latency on the former and
    nearly free on the latter. F-A keeps the critical path at 130 s and is correct either way;
    the answer only determines whether F-B's extra 3 polyglot minutes were ever worth
    reconsidering.

12. **Approve re-measuring before Phase 3 (R14).** Every cost figure here is modelled from a probe
    workflow, because `reusable-security` has not run since 2026-09-16. Phase 1 makes it startable
    again; **the packing decision should be re-costed on real durations at that point**, not
    committed to on these numbers.
