# Job topology and budget — what each run bills, and what grouping would change

**The saving is real and smaller than it looks, and the largest single line of it is a defect fix rather than a redesign.**

```
Phase: design — a measured cost model and a proposed topology, not an implementation
Truth State: measured 2026-09-23 from git HEAD (623,411 B, 17 jobs) and the working tree
             (349,029 B, 18 jobs). Every DURATION is assumed; every BYTE COUNT is measured.
Audience: the owner, deciding whether to repack jobs and whether kit-scripts stays
Decision Supported: how many jobs reusable-security.yml should declare, and whether the
             bootstrap job is still earning its minute
Deferred Depth: SECURITY_WORKFLOW_DECOMPOSITION_PLAN.md (candidates A-F, 12 decisions) ·
             AXES_AND_PHASES.md (the six axes) ·
             ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md (the rung, and who declares it)
```

> **Nothing described here is built.** Not the grouped topology, not per-step status capture, not
> the merged report-and-gate job. `.github/workflows/reusable-security.yml` is unmodified by this
> document and no commit or dispatch was made. What follows is a cost model and a proposal.
>
> **This document coins nothing.** Every controlled term in it is already registered in
> `assurance-taxonomy.yaml`. One term was drafted and withdrawn; §9.5 records what was checked and
> why the registry already covers it.

---

## 0 · What this settles, and what it deliberately does not

**Settled here:**

- What the current topology bills, per repository shape, with the arithmetic shown.
- The floor — what a run costs when discovery finds nothing at all.
- A grouped topology that honours the owner's own grouping, and what it bills.
- Whether `kit-scripts` survives. It does, decisively, and the reason is not the one assumed.
- Which admin jobs can merge and which structurally cannot.
- What merging costs in correctness, in elapsed time, and in modularity — three separate axes.

**Deliberately not settled:** whether to build any of it. Real scanner durations. Runner queue
time. Whether the enforcement transfer that grouping requires is acceptable — that is decision 10
of the prior plan and it is still open.

---

## 1 · Primary sources, and one claim that is not sourced

| claim | status | source |
|---|---|---|
| Minutes are rounded up per job | **VERIFIED** | "GitHub rounds the minutes and partial minutes each job uses up to the nearest whole minute." — docs.github.com/en/billing/reference/actions-minute-multipliers |
| Standard Linux 2-core runner rate | **VERIFIED** | $0.006 per minute, same page, SKU `actions_linux` |
| A matrix creates one job per combination | **VERIFIED** | "A job will run for each possible combination of the variables." — docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations |
| Workflow file hard limit is 500 KB | **VERIFIED** | reproduced in this repository 2026-09-16; `tests/check_workflow_size.py` documents the startup failure |
| `download-artifact` default path is `$GITHUB_WORKSPACE`; tilde expansion supported | **VERIFIED** | actions/download-artifact README |
| An absolute `path:` (the kit uses `/tmp`) is honoured | **UNVERIFIED** | The README documents the default and tilde expansion. It does not address absolute paths either way. The kit relies on this on every run of every job. See §8. |
| **A skipped job bills nothing; a skipped step inside a running job bills** | **UNVERIFIED against primary documentation** | No GitHub page states it. It is the owner's established invariant, and it is *derivable* from the rounding sentence above — billing counts "the minutes and partial minutes each job uses", and a job that never starts uses none. Recorded as UNVERIFIED rather than dropped, because the entire model rests on it. |

The corollary of that last row is the one that matters and it runs the other way from intuition:
**merging N jobs into 1 is never more expensive in money.** `ceil(a) + ceil(b) >= ceil(a + b)`,
and the merged job runs only when at least one member would have run — provided its job-level `if:`
is the exact disjunction of its members' applicability. The cost of merging is not money. It is
blast radius, elapsed time, and rigidity, and those are §5, §6 and §7.

---

## 2 · The current topology, measured

18 declared jobs. **That is not the billable count.**

```
kit-scripts     no if:                                  bills on EVERY run
discover        no if:                                  bills on EVERY run
secret-scan     if: always()                            bills on EVERY run
sast-semgrep    if: always()                            bills on EVERY run
deps-scan       if: always()                            bills on EVERY run
report          if: always()                            bills on EVERY run
security-gate   if: always()                            bills on EVERY run
sbom            if: inputs.enable_sbom                  default true  -> bills on EVERY run
malicious-deps  if: inputs.enable_malicious_pkg_scan    default true  -> bills on EVERY run
code-quality    if: needs.discover.outputs.python
sast-bandit     if: needs.discover.outputs.python
sast-go         if: needs.discover.outputs.go
sast-dotnet     if: needs.discover.outputs.dotnet
sast-java       if: needs.discover.outputs.java
sast-cpp        if: needs.discover.outputs.cpp
iac-scan        if: needs.discover.outputs.iac
image-scan      if: inputs.image_ref != ''
codeql          if: OR of all six languages  ·  strategy.matrix.include has SIX entries
```

### 2.1 The matrix defect — five jobs that bill to do nothing

`codeql` carries one job-level `if:` — the disjunction of all six languages — and then expands to
six matrix legs. Per-language gating happens at **step** level: `if: matrix.gate == 'true'` on
checkout, init, autobuild and analyse.

A matrix leg has no `if:` of its own. GitHub evaluates the job-level condition once and, when it is
true, **spawns all six legs**. Each leg's first step is the generated fetch block, which carries
`if: always()`, so every leg does real work: it boots a runner, resolves an action, downloads the
`kit-scripts` artifact, and then skips everything else.

**Five of the six legs on a single-language repository are billed minutes spent downloading a
tarball.** That is the largest single waste in the file, it is invisible in the declared job count,
and it is not something grouping is needed to fix.

### 2.2 Two further defects the measurement surfaced

- **`code-quality` runs ESLint behind a Python gate.** Its job-level condition is
  `needs.discover.outputs.python == 'true'`, and its ESLint steps are gated on
  `inputs.language == 'node' || inputs.language == 'multi'`. **A pure-JS repository gets no
  ESLint at all**, because the job it lives in never starts. This is the exact hazard §5 warns
  about, already shipped: a merged job whose job-level condition is narrower than the disjunction
  of its members' applicability. It is also the best available evidence that step-gating inside a
  merged job is not hypothetical — it is in the file, and it is already wrong.
- **`sast-dotnet` contains a dependency scanner.** Its "Vulnerable + deprecated NuGet packages"
  step is SCA living inside a SAST job because that is where the toolchain is. Under the owner's
  grouping this is an axis collision with no free answer, and §4.4 states it rather than resolving
  it silently.

---

## 3 · Cost model: the current topology

### 3.1 Assumed durations — every number in this table is ASSUMED

`reusable-security.yml` has not completed a run since 2026-09-16. There is no history to measure.
These are the inputs to both models; the arithmetic is exact, the inputs are not.

| item | assumed min | item | assumed min |
|---|---:|---|---:|
| runner boot + "Set up job" | 0.30 | trivy filesystem | 1.00 |
| post-job cleanup | 0.20 | trivy config | 0.40 |
| checkout | 0.25 | trivy image | 1.00 |
| fetch `kit-scripts` artifact | 0.15 | checkov | 1.50 |
| redaction over the workspace | 0.10 | osv-scanner (install + scan) | 0.70 |
| upload + publish, per scanner | 0.20 | syft | 0.60 |
| discover | 0.60 | licence inventory | 0.20 |
| write the canonical scripts | 0.20 | gitleaks (install + scan) | 0.70 |
| semgrep, generic rulesets | 1.50 | detect-secrets | 0.50 |
| semgrep, one language pack | 0.80 | bandit | 0.25 |
| gosec | 0.40 | ruff + mypy | 0.50 |
| cppcheck | 0.60 | eslint | 0.60 |
| flawfinder | 0.20 | report assembly | 0.80 |
| language toolchain setup | 0.25-0.60 | gate evaluation | 0.20 |
| .NET restore | 1.20 | | |
| CodeQL: py 2.50 · node 3.00 · go 3.50 · .NET 4.00 · java 4.50 · cpp 5.00 | | | |

### 3.2 Four repository shapes

Inputs at their defaults: `enable_sbom: true`, `enable_malicious_pkg_scan: true`.

**S1 — pure JS.** `node=true`, nothing else.

```
kit-scripts           1.05 -> 2      codeql[python]  IDLE  0.85 -> 1
discover              1.35 -> 2      codeql[node]          4.20 -> 5
secret-scan           2.60 -> 3      codeql[go]      IDLE  0.85 -> 1
sast-semgrep          2.70 -> 3      codeql[dotnet]  IDLE  0.85 -> 1
deps-scan             2.20 -> 3      codeql[java]    IDLE  0.85 -> 1
malicious-deps        1.90 -> 2      codeql[cpp]     IDLE  0.85 -> 1
sbom                  2.00 -> 2      report                1.80 -> 2
                                     security-gate         0.70 -> 1
                                     ------------------------------------
                                     15 jobs · 24.75 raw · 30 BILLED · $0.180
```

**S2 — Python + IaC + container.** `python=true`, `iac=true`, `image_ref` set.

```
kit-scripts 2 · discover 2 · secret-scan 3 · sast-semgrep 3 · deps-scan 3
malicious-deps 2 · sbom 2 · code-quality 3 · sast-bandit 2 · iac-scan 4
image-scan 2 · codeql[python] 4 · five IDLE legs 5 · report 2 · security-gate 1
------------------------------------------------------------------------------
19 jobs · 33.55 raw · 40 BILLED · $0.240
```

**S3 — Java monorepo.** `java=true`, `node=true`, `iac=true`, `image_ref` set.

```
kit-scripts 2 · discover 2 · secret-scan 3 · sast-semgrep 3 · deps-scan 3
malicious-deps 2 · sbom 2 · sast-java 3 · iac-scan 4 · image-scan 2
codeql[node] 5 · codeql[java] 6 · four IDLE legs 4 · report 2 · security-gate 1
------------------------------------------------------------------------------
18 jobs · 37.15 raw · 44 BILLED · $0.264
```

**S4 — discovery finds nothing. This is the floor.**

```
kit-scripts           1.05 -> 2
discover              1.35 -> 2
secret-scan           2.60 -> 3
sast-semgrep          2.70 -> 3
deps-scan             2.20 -> 3
malicious-deps        1.90 -> 2
sbom                  2.00 -> 2
report                1.80 -> 2
security-gate         0.70 -> 1
----------------------------------
9 jobs · 16.30 raw · 20 BILLED · $0.120
```

**The floor is 20 billed minutes.** A repository containing nothing this kit can scan still pays
20 minutes, of which 16.3 is work and 3.7 is rounding. Nine jobs run because nine jobs have either
no `if:` at all or an `if:` that discovery does not reach. Turning both default-true toggles off
takes the floor to 7 jobs and 16 billed minutes; it does not get below that, because
`secret-scan`, `sast-semgrep`, `deps-scan`, `report` and `security-gate` are `always()` by design
and `kit-scripts` and `discover` have no condition at all.

Rounding overhead across the four shapes: 21%, 19%, 18%, 23%.

---

## 4 · The proposed grouped topology

The owner's grouping, applied literally: secrets separate; SCA combined; **SAST by language, not
by tool**; admin combined where it legitimately can be.

**13 declared jobs.**

| # | job | `if:` | members |
|---|---|---|---|
| 1 | `discover` | none | discovery probes |
| 2 | `secrets` | `always()` | gitleaks · detect-secrets |
| 3 | `sca` | `always()` | trivy filesystem · osv-scanner · syft · licence inventory |
| 4 | `sast-multi` | `always()` | semgrep, generic rulesets — see §4.2 |
| 5 | `sast-python` | `python` | bandit · semgrep python pack · CodeQL python · ruff + mypy |
| 6 | `sast-node` | `node` | eslint · semgrep JS pack · CodeQL javascript-typescript |
| 7 | `sast-go` | `go` | gosec · semgrep go pack · CodeQL go |
| 8 | `sast-dotnet` | `dotnet` | semgrep C# pack · CodeQL csharp |
| 9 | `sast-java` | `java` | semgrep java pack · CodeQL java-kotlin |
| 10 | `sast-cpp` | `cpp` | cppcheck · flawfinder · CodeQL c-cpp |
| 11 | `iac` | `iac` | checkov · trivy config |
| 12 | `container` | `image_ref != ''` | trivy image |
| 13 | `report-and-gate` | `always()` | report assembly, then gate evaluation |

`kit-scripts` is absent from that list **only because §7 is where it is decided.** It is not
removed; the count becomes 14 if it stays, which it does.

### 4.1 What CodeQL's matrix becomes

It disappears. Each language's CodeQL pack moves into that language's job, gated by the job's own
`if:`. The six legs become six conditional jobs that genuinely skip. This is where the money is
(§5.2), and it is independent of everything else in this section.

### 4.2 `sast-multi` is not a language bucket and must not become one

`sast-semgrep` runs `always()` today with `p/default p/owasp-top-ten p/xss` across the whole tree.
It is the only control that sees a language discovery does not recognise. Folding it into the
per-language jobs would mean a repository written in something unsupported gets no SAST **and no
record that it got none** — `NOT_APPLICABLE` where the honest answer is `COVERAGE_GAP`. It keeps
its own `always()` job and its own `scanner_state`. The prior plan reached the same conclusion; it
is restated because it is the one grouping that looks obviously available and is not.

### 4.3 `code-quality` dissolves, and that repairs §2.2

ESLint moves to `sast-node`, ruff and mypy to `sast-python`. Each then sits behind the gate for
the language it actually inspects, which is what the current job's condition fails to do. Lint
findings keep their own `scanner_state` and `inputs.enforce_lint` keeps deciding whether they
block — grouping changes where a scanner runs, never what its result means.

### 4.4 The .NET dependency audit is an unresolved axis collision

The NuGet vulnerability audit is SCA by subject and .NET by toolchain. Putting it in `sca` means
`sca` carries a conditional .NET setup and restore — roughly 2.1 assumed minutes it does not
otherwise need, paid on every .NET repository. Leaving it in `sast-dotnet` means the SCA group is
not the whole SCA story and `report` must know that. **The model below leaves it where it is** and
records the collision rather than resolving it by preference. It is a decision, not a detail.

### 4.5 Which admin jobs cannot merge, and why

| job | mergeable | why |
|---|---|---|
| `discover` | **No, with anything** | Every language group's job-level `if:` reads `needs.discover.outputs.*`. A job cannot depend on a value produced inside itself. Discovery is structurally first, and if it were merged into a scanner group the whole applicability model would collapse into step-level conditions evaluated after the minute was already committed. |
| `security-gate` | **Not with any scanner** | A gate that runs in the same job as the thing it judges is not a gate. Its verdict would be an ordering accident, a scanner crash would take the gate with it, and there would be no separate job result for a branch protection rule to require. |
| `report` + `security-gate` | **Yes** | Both are `always()`, both are terminal, and the gate does not judge the report — it checks that the report *ran*, which a step-outcome check inside one job establishes as well as a job result does. Report steps run first, uploads carry `if: always()`, gate evaluation is last. One constraint: the report must remain unable to be suppressed by the gate's verdict, which step ordering plus `always()` gives. |
| `kit-scripts` | **No, with anything** | Same structural reason as `discover` — every consumer needs its artifact before its own first step. §7. |
| `container` | **Technically yes, into `sca`** | Both are dependency-shaped. Rejected: the finding subject differs (`IMAGE` versus `SOURCE`), they are gated by different axes (`image_ref` is a caller declaration, `sca` is `always()`), and merging would make `sca` bill its image path on every run. |
| `iac` | **No, into SAST or SCA** | Different subject again (`IAC_PLAN`), different applicability signal, different tools. It is its own group. |

**Net admin merge available: exactly one pair.** `report` + `security-gate`. Everything else the
word "admin" suggests is structurally pinned. That is one billed minute per run, and it is worth
saying plainly that the "combine whatever other admin jobs you can" instruction, followed
honestly, yields one merge.

---

## 5 · Cost model: the proposal, side by side

Same assumed durations, same shapes.

| shape | current jobs / billed | proposed jobs / billed | saving |
|---|---|---|---|
| S1 pure JS | 15 / **30** | 6 / **21** | 9 min · 30% · $0.054 |
| S2 python + IaC + container | 19 / **40** | 8 / **26** | 14 min · 35% · $0.084 |
| S3 java monorepo | 18 / **44** | 9 / **35** | 9 min · 20% · $0.054 |
| S4 nothing found (the floor) | 9 / **20** | 5 / **14** | 6 min · 30% · $0.036 |

Proposed, shown long, for S2:

```
discover              1.35 -> 2
secrets               2.45 -> 3
sca                   3.95 -> 4
sast-multi            2.55 -> 3
sast-python           5.95 -> 6      (setup 0.25 + bandit 0.25 + semgrep 0.80
iac                   3.15 -> 4       + CodeQL 2.50 + ruff/mypy 0.50 + 4 x 0.20
container             1.95 -> 2       + 0.30 + 0.20 + 0.25 + 0.10)
report-and-gate       1.85 -> 2
----------------------------------
8 jobs · 23.20 raw · 26 BILLED · $0.156
```

### 5.1 Do not inflate this. In dollars it is trivial.

At $0.006 per minute the largest saving in the table is **8.4 cents per run**. A thousand runs a
month on the S2 shape saves $84 a year. If the case for this work is money, the case is weak. The
case is the matrix defect, the ESLint gate defect, and per-language attribution — and those are
correctness, which is why they are in §2 rather than here.

### 5.2 More than half the saving is a defect fix, not the redesign

Decomposing the saving into (a) giving CodeQL's languages real job-level conditions and (b)
everything else grouping does:

| shape | current | after the matrix fix alone | after full grouping | share from the matrix fix |
|---|---:|---:|---:|---:|
| S1 pure JS | 30 | **25** | 21 | 5 of 9 · 56% |
| S2 python + IaC | 40 | **35** | 26 | 5 of 14 · 36% |
| S3 java monorepo | 44 | **40** | 35 | 4 of 9 · 44% |
| S4 nothing found | 20 | 20 | 14 | 0 of 6 · 0% |

**The matrix fix is available on its own.** It changes one job, merges nothing, touches no
`scanner_state`, and carries none of §6. On a single-language repository it is the majority of the
saving. If only one thing is done, it is this.

The remainder of the saving comes from rounding recovered on short jobs — `malicious-deps` (1.90
raw, 2 billed), `sbom` (2.00, 2), `sast-bandit` (1.70, 2) — which is exactly the owner's original
reason for wanting short runs combined. The model confirms it. It also shows the amount: 4 to 9
minutes, depending on shape.

---

## 6 · Wall clock — a separate axis, and it moves the other way

Billed minutes and elapsed time are different quantities and must not be collapsed into one
number. Merging serialises scanners that previously ran in parallel. Longest path through the
graph, unrounded, same assumed durations:

| shape | current elapsed | proposed elapsed | delta |
|---|---:|---:|---:|
| S1 pure JS | 8.05 | 9.35 | **+1.30** |
| S2 python + IaC + container | 7.55 | 9.15 | **+1.60** |
| S3 java monorepo | 9.55 | 10.25 | **+0.70** |
| S4 nothing found | 6.55 | 7.15 | **+0.60** |

**Cheaper and slower, in every shape.** The cause is single and identifiable: CodeQL is the long
pole, and moving it inside a language group puts it in series with that group's other scanners
instead of in parallel with them.

The dial, stated so the owner can set it rather than have it set:

- **Group including CodeQL** — cheapest, slowest. The table above.
- **Group excluding CodeQL**, CodeQL kept as six separately-conditioned jobs. Costs about one
  billed minute per language present relative to full grouping, and returns the elapsed time.
  On S3 that is 35 to roughly 37 billed minutes and elapsed back to about 9.6.
- **Matrix fix only, no grouping** — §5.2's middle column. Elapsed time unchanged from today,
  56% of the S1 saving, blast radius nil.

Which of those is right depends on whether this gate sits on the pull-request path, where 1.6
minutes is developer latency, or on a nightly, where it is nearly free. That is the prior plan's
decision 11 and it is still unanswered. **This document does not choose.**

---

## 7 · Does `kit-scripts` survive? Yes, and the premise for doubting it is wrong

The premise offered was: 13 copies of the redaction block existed because there were 13 jobs, so
fewer jobs means fewer copies, so grouping alone might do the size work and the bootstrap job
could go.

**The 13 copies did not exist because there were 13 jobs. They existed because 13 jobs upload a
SARIF**, and the redactor must run before the first upload in each job or it protects nothing.
Grouping does not change that requirement; it changes only how many jobs have uploads.

### 7.1 Measured copy counts

| block | bytes per copy | copies at HEAD (17 jobs) | copies under grouping (13 jobs) |
|---|---:|---:|---:|
| `REDACT_SARIF` | 21,649 | 13 | **11** |
| `SCAN_STATUS` | 4,578 mean | 12 | **10** |
| `NORMALIZE_SARIF` | 6,183 | 3 | **3** |
| `SBOM_LICENSES` | 9,877 | 1 | 1 |
| `SCAN_REPORT` | 50,346 | 1 | 1 |

Thirteen becomes eleven. Two copies. 43,298 bytes off a file that needs to lose 137,011 to reach
the fail threshold from HEAD.

### 7.2 Grouping makes the file *larger*, because SAST by language replicates CodeQL

Measured: the CodeQL job's steps are **4,144 bytes** excluding its own job header and its
redaction block. Today that appears once, behind a matrix. Under SAST-by-language it appears six
times: `+24,864`, less the 5,504-byte job it replaces, for a measured **+19,360 bytes**.

### 7.3 The arithmetic

Hand-written residue per job, measured at HEAD with generated blocks removed, recombined into the
13 grouped jobs: **212,824 bytes**. Header, unchanged because the `workflow_call` contract is
byte-identical: **14,581**. Four estimates are flagged EST and are worth 600 to 1,500 bytes each —
a job preamble, a semgrep language pack for node (which has none today), and the preamble
reclaimed when two jobs become one.

**A — grouped, 13 jobs, no bootstrap job:**

```
header                                        14,581
residue                                      212,824
REDACT_SARIF    x 11  @ 21,649               238,139
SCAN_STATUS     x 10  @  4,578                45,780
NORMALIZE_SARIF x  3  @  6,183                18,549
SBOM_LICENSES   x  1                           9,877
SCAN_REPORT     x  1                          50,346
                                            --------
                                             590,096  =  576.3 KB
```

**590,096 bytes. GitHub's hard limit is 512,000. The workflow would be 78,096 bytes over — 76.3 KB
past the point where it stops starting.** Not over the 475 KB fail threshold. Over the ceiling. It
would produce zero jobs on every trigger, which is the exact outage of 2026-09-16.

**B — grouped, 13 jobs, bootstrap retained:**

```
header                                        14,581
residue                                      212,824
kit-scripts job (canonical copies)            99,594
fetch step      x 12  @    476                 5,712
redact step     x 11  @  1,270                13,970
status step     x 10  @    960                 9,600
                                            --------
                                             356,281  =  347.9 KB     ok
```

### 7.4 The verdict

**`kit-scripts` is not a minute bought for nothing. It is the only reason the grouped topology is
expressible at all.** Grouping without it is 78 KB past the ceiling.

Three further things follow, and two of them are uncomfortable:

1. **Grouping is not a size fix.** B is 356,281 bytes against today's 349,029 — **+7,252 bytes.**
   Grouping makes the file slightly bigger, because §7.2 outweighs §7.1. Anyone reaching for
   grouping to buy size headroom is reaching for the wrong tool.
2. **B leaves 2.1 KB of margin under the 350 KB warn threshold.** It would be one edit away from
   warning. The warn threshold is where the useful signal lives, so this is not a failure — it is
   notice that grouping consumes almost all the headroom the deduplication just bought.
3. **The serialisation point is real and is the honest cost.** `kit-scripts` has no `if:`, so it
   bills on every run including the floor, and every scanner waits for it. In the model it adds
   1.05 raw minutes, 2 billed, and 0.5 to the critical path. That is the price. It buys a file
   that starts.

One narrowing is available and worth naming: `kit-scripts` currently runs `checkout` and the
workspace redaction, 0.35 assumed minutes it may not need, since it writes scripts it already
contains. If that is so it drops to roughly 0.70 raw — still 1 billed minute, but 0.35 off the
critical path of every run. Unverified; it needs a reading of the job, not this model.

---

## 8 · Blast radius: what merging can break, and the containment

This is where merging can do real harm, and none of it is about money.

### 8.1 Four requirements, each closing a specific collapse

**R1 · The job-level condition must be the exact disjunction of its members' applicability.**
Narrower and a member silently never runs — which is §2.2, already shipped, ESLint behind a Python
gate. Broader and the group bills when nothing in it applies, which is the *only* way grouping can
cost more than today. This is checkable statically: for each group, the set of discovery outputs
named in the job `if:` must equal the union of the sets named by its members' step conditions.

**R2 · Per-step status capture replaces per-job status capture.** Today a scanner *is* a job and
`needs.<scanner>.result` is its verdict. After merging, three scanners share one job result, and a
single value cannot carry three states. Each member must write its own `scanner_state` — and the
generated status block is already invoked per scanner rather than per job, so the mechanism exists;
what changes is that the consumer must read N values from one job instead of one value from N jobs.

**R3 · The envelope rule, which is the one that prevents the forbidden collapse.** If the group's
job result is not success, then **every member whose own state is absent is `COLLECTION_FAILED`,
never `NOT_APPLICABLE`.** A crash in semgrep must not mark bandit unscanned, and it must equally
not mark bandit clean. This is `absence_is_not_a_negative_observation` applied at a boundary the
current topology did not have: GitHub used to supply the per-scanner envelope for free by giving
each scanner a job, and grouping takes that away. It has to be rebuilt explicitly or the
distinction `NOT_APPLICABLE` / `PASS` / `COVERAGE_GAP` collapses into whichever one the aggregation
step happens to default to. **A merged job that reports one verdict for three scanners is the
forbidden collapse, and it is the failure mode of the naive implementation, not an edge case.**

**R4 · The gate must read member states, not the group result.** A gate reading
`needs.sast-python.result` after merging learns that *something* in that job went wrong. It cannot
learn which control is missing, and `PARTIAL` reported as a job failure is indistinguishable from
`FAILED`. The gate's needs list stays, but what it reads changes from a result to a set of outputs.

### 8.2 `continue-on-error` per step is not the fix, and the distinction is precise

Putting `continue-on-error: true` on each scanner step so one crash does not end the job is the
obvious move and it is the exact shape of the defect this kit already shipped once, in the input
that makes SAST findings advisory by default.

The registry already draws the line, in `suppression_reason`:

- **`FAILURE_ISOLATION_WITH_STATE_CAPTURE`** — "`continue-on-error` is only correct when THE ERROR
  BECOMES DATA." Execution continues so siblings can still produce evidence, **and** the failure is
  captured as explicit state that propagates to the gate and the report.
- **`UNSAFE`** — the signal that determines truth is destroyed.

What separates them is not the YAML. It is identical. It is whether three things are true:

1. **Captured.** The step's outcome is read in the same job — `steps.<id>.outcome` — and mapped
   into a `scanner_state` value, not left as a log line.
2. **Propagated.** That state reaches the gate and the report as data, and the gate's arithmetic
   treats `FAILED` and `COLLECTION_FAILED` as blocking. If the state exists and nothing consumes
   it, this is `a_node_is_not_a_path` and the tolerance is silent after all.
3. **Surfaced.** An annotation and a row in the step summary say which scanner degraded and why,
   so a human reading a green check can see the hole.

The shipped defect fails all three. It converts a real finding into an exit code of zero, nothing
records that suppression occurred, and the gate cannot distinguish the result from clean. The kit
has vocabulary for it — `GATE_SOFTENED`, `WEAKENING_IN_FORCE` — and the registry's own annotation
requirement is the test: name **what distinction is being discarded** and **where it survives**. A
`continue-on-error` that cannot answer both is `|| true` wearing YAML.

### 8.3 What is lost and cannot be recovered

**Per-scanner rows in the checks list.** Today a repository can require `sast-bandit` as a
protected-branch check. After merging it can require `sast-python`, which is coarser. Seven red
marks become one, and the failing scanner's name is inside the job rather than in the list. The
report and the annotations carry it; branch protection cannot. This is not containable — it is the
price, and it is the substance of the prior plan's decision 10.

---

## 9 · The third axis: what merging costs in modularity

The bound on this optimisation is the owner's own: budget-conscious **but not to the point that we
cannot be flexible or modular.** Money and elapsed time are §5 and §6. This is the third axis, and
it is the one that decides how far to go.

### 9.1 Can a consumer still choose? Mostly they cannot today either

Measured, from the `workflow_call` input list. The per-scanner switches that exist:

| switch | granularity |
|---|---|
| `enable_sbom` | one scanner |
| `enable_malicious_pkg_scan` | one scanner |
| `iac_mode: disabled` | one group, loudly reported |
| `image_ref: ''` | one group |
| `language` | read by `discover` as a hint, and by `code-quality` at step level |
| `enforce_lint`, `advisory_mode`, `soft_fail_sast` | enforcement, not selection |

**There is no `enable_semgrep`, no `enable_bandit`, no `enable_codeql`, no `enable_gosec`.** So the
honest answer to "can they still run semgrep without bandit" is: **they cannot do that today
either, by any input.** Applicability is derived from discovery by design — that is
`AXES_AND_PHASES.md`'s first rule, that a question discovery can answer should be derived and not
an input.

What merging changes is the **cost of adding such a switch later**, and it changes it in two ways
that pull against each other:

- A job-level `if:` per scanner is one line, and it makes the excluded scanner **free**.
- A step-level `if:` inside a group is also one line, but the excluded scanner is
  `EXCLUDED_BY_SELECTOR` **inside a job whose minute is already paid.** Disabling bandit on a
  Python repository would save nothing.

So the modularity loss is not "the consumer can no longer choose". It is: **after merging, a
consumer's choice to disable a scanner stops being worth money.** That is a genuine reduction in
what the flexibility is good for, and it deserves to sit next to the 8.4 cents.

### 9.2 Permission unions — small, measured, and with two real exceptions

Merging jobs merges their `permissions`. Measured from the file:

- The **workflow-level default is already** `contents: read` + `security-events: write`, and
  **10 of 18 jobs inherit it unchanged.** Merging scanners therefore widens almost nothing: the
  union has already been granted workflow-wide.
- `codeql` adds `actions: read`. Folding CodeQL into six language groups spreads `actions: read`
  to six jobs. Read-only, narrow, and the honest cost of §4.1.
- **`report` narrows itself to `contents: read` today.** Merging it with `security-gate`, which
  inherits the default, gives the report steps `security-events: write` — the ability to write to
  code scanning, granted to a job whose whole purpose is to *read* SARIF and render it. This is a
  real widening and the only one in the proposal that grants a write. It is containable by
  declaring `permissions: contents: read` on the merged job, since neither report nor gate uploads
  SARIF — but it must be declared, not inherited, or the union happens by default.
- `discover` keeps `security-events: read` and merges with nothing, so it is unaffected.

**Net: one read-scope widening across six jobs, and one write-scope widening that must be closed
by an explicit declaration.** This axis is not the reason to stop, but the second item is not
optional.

### 9.3 Blast radius as rigidity

"One scanner failing cannot fail them all, just needs to be documented correctly." §8 is the
correctness reading of that. The modularity reading is different and additional: **in a grouped
job, changing one scanner means editing a job that nine other things depend on.** A change to
bandit's invocation now risks `sast-python`'s CodeQL upload, because they share a workspace, a
toolchain setup, a redaction pass and an artifact namespace. Today those are isolated by job
boundary for free.

That is not a reason to refuse grouping. It is the reason the prior plan sequences composites
*before* packing: with per-scanner composite actions, a grouped job is a list of calls and editing
one scanner means editing one composite. **Grouping before extraction trades a boundary away with
nothing to replace it.**

### 9.4 The point of diminishing returns, named

| merge depth | jobs | S2 billed | saving so far | rigidity added |
|---|---:|---:|---:|---|
| 0 · today | 18 | 40 | — | none |
| 1 · CodeQL gets real job conditions | 23 declared / 14 billable | 35 | 5 | **none** |
| 2 · merge `report` + `security-gate` | 22 | 34 | 6 | one pair, both `always()`, no scanner |
| 3 · merge SCA: trivy + osv + syft | 20 | 32 | 8 | three scanners share a job; R2 and R3 now required |
| 4 · SAST by language, CodeQL joins the groups | 14 | 26 | 14 | +1.6 min elapsed; per-scanner checks rows gone; every SAST edit is a group edit |
| 5 · one SAST group, all languages | 9 | ~24 | ~16 | prior plan measured elapsed 2.6x; language attribution gone |

**The knee is between 3 and 4.**

Depths 1, 2 and 3 deliver **8 of the 14 available minutes — 57% of the saving — with no elapsed-time
cost, no loss of per-language attribution, and no change to what branch protection can require.**
Depth 1 needs nothing from §8 at all. Depths 2 and 3 need R2 and R3, on two merges that are easy to
reason about: the report-and-gate pair, and three dependency scanners that already share a subject
and a workspace.

Depth 4 buys the remaining 6 minutes and is where every cost in this document arrives at once —
elapsed time, the checks list, permission spread, and an edit surface where every SAST change is a
group change.

Depth 5 is rejected on the prior plan's own measurement and on the owner's bound: it collapses
language attribution, which is the distinction that tells a Java team their Java was scanned.

**Recommendation: stop at 3 unless CodeQL grows.** Depth 4's case is not its 6 minutes — it is
per-language attribution of the CodeQL results, which matters more as the CodeQL suite widens.
Re-cost it on real durations at that point, which is the prior plan's decision 12 and is still the
right instruction.

**This does not change the verdict on `kit-scripts`, and it does change the recommended endpoint.**
Stated rather than quietly revised: the brief asked for the grouped topology and §4 gives it in
full. §9.4 recommends implementing three of its four depths. The `kit-scripts` verdict is
unaffected and in fact strengthened — at depth 3 the file is *smaller* than at depth 4, because
§7.2's CodeQL replication has not happened, and the bootstrap job is still the only thing keeping
either under the ceiling.

### 9.5 No new vocabulary is proposed, and that is a finding rather than an omission

A term was drafted for the state R3 defends against: a member scanner whose own `scanner_state` is
absent because the job it shares with others did not complete, where the current topology would
have given it an independent job result.

**It was withdrawn before being written down, because the registry already covers it and a second
spelling of one concept is the defect the reconciler exists to catch.** What was checked, in the
order the drift remedy prescribes:

- **`COLLECTION_FAILED`** — "The scanner ran, but gathering its results failed, producing an empty
  but well-formed output that is indistinguishable from a clean scan." This is exactly R3's
  projection, it blocks, and its own rule already says *emit this or `UNKNOWN`, never an empty
  success*. It fits.
- **`UNAVAILABLE`** — asserts the scanner never ran. Correct for a group whose job-level condition
  was false; wrong for a member inside a group that started.
- **`PARTIAL`** — asserts it executed and a prerequisite was missing. Warns rather than blocks, so
  using it here would let a lost envelope pass.
- **`UNDETERMINED`** — the aggregate claim, one level up. It is what the run reports *because of*
  the member state, not the member state itself.

So R3 is expressible today with `COLLECTION_FAILED` and no registration is needed. The general
point is worth keeping: **grouping does not require new vocabulary. It requires a new producer for
vocabulary that already exists**, because GitHub used to produce the per-scanner envelope for free
and after merging nothing does. A proposal that needed a new term here would be a sign the envelope
rule had not been thought through, not a sign the registry was short a word. `MAX_ACCEPTED_DEBT` is
at 15/15, which is a second reason to be glad of the answer.

---

## 10 · What could not be established

Every number below is either assumed or unverifiable from here. They are listed so none of them
gets quoted as measured.

**Assumed — no run history exists.** `reusable-security.yml` has not completed a run since
2026-09-16. Every duration in §3.1 is assumed: all 28 scanner and toolchain durations, the six
CodeQL per-language figures, runner boot, checkout, artifact fetch, redaction, publish, report and
gate. The arithmetic over them is exact; they are not.

**Not establishable from this repository:**

- **Runner queue time.** Not modelled anywhere above, and it is not knowable without run history.
  Whether it is billed at all is UNVERIFIED — if pre-job provisioning is billable, every figure in
  §3 and §5 is understated by a constant per job, which would make grouping look *better* than
  modelled, since it runs fewer jobs.
- **Whether `download-artifact` honours the absolute `path: /tmp`.** The README documents the
  `$GITHUB_WORKSPACE` default and tilde expansion and is silent on absolute paths. Every job
  depends on it. UNVERIFIED, and it is a runtime assertion away from being VERIFIED.
- **Whether a skipped job is genuinely free.** §1. Derivable, owner-established, unsourced.
- **CodeQL autobuild durations** for Java and .NET, which dominate §6's elapsed-time result and
  vary by an order of magnitude with project size. The relative ranking of the §6 options is
  robust; the magnitudes are not.
- **Whether `kit-scripts` needs its checkout and workspace redaction.** §7.4. Would change the
  critical path of every run by 0.35 assumed minutes.
- **The four EST byte figures in §7.3** — job preamble, the semgrep language pack node does not
  yet have, and the preamble reclaimed per merge. Worth 600 to 1,500 bytes each. Result A is
  78,096 bytes over the ceiling, so no plausible combination of them changes that verdict.
- **Whether the 500 KB limit is measured before or after any future use of YAML anchors.** Carried
  forward unresolved from the prior plan; it does not affect anything here, because nothing here
  proposes anchors.
