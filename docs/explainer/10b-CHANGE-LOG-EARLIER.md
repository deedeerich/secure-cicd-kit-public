# 10b · Change log, earlier versions (1.8 back to 1)

The continuation of `10-CHANGE-LOG.md`, which holds version 1.9 onward and says what changed most
recently. This part is history: each entry was true at its version and commit, and later versions
may have changed what it says. Newest first. Commit ids are on the build trunk
`fix/normalization-and-discovery`.

## Version 1.8 — 2026-10-15 (trunk `47fe6bb`)

| commit / run | change | parts affected |
|---|---|---|
| `b293e36` | the identity probe refused a genuine caller: GitHub issues the token's subject in an ID-qualified form (`repo:owner@<id>/name@<id>:...`) and the probe only accepted the plain form. It now accepts the ID form only when both ids equal the token's own repository-owner and repository id claims, and records which form it verified | 07 |
| runs 38826929579, 38826938462 | **identity mismatch proven on the real Azure tenant.** With a deliberately wrong expected tenant, the real login succeeded and the context-integrity step then hard-failed ("landed in an UNEXPECTED context. Refusing"); with nothing declared, the same step passed. Deferrals: 7 left, none blocking | 07, 09 |

## Version 1.7 — 2026-10-15 (trunk, evening)

| commit / run | change | parts affected |
|---|---|---|
| `a992811` | **live ticketing on a real Jira** (the owner's personal tracker). R-1: four deliberately broken settings (host, token, project, stamp field) each refused at run start, naming the right setting, with zero writes. It found one defect, fixed test-first: Jira answers a bad token like an anonymous visitor (404, not 401), so the refusal blamed the project; the credential is now checked first. R-2: the first run created one ticket and the identical second run, a joined finding and a narrowed finding created nothing. The person-only steps (duplicate, close, refusable reopen) follow | 06, 09 |
| `f236a7a` | five deferrals closed by local proof with the real tools: the Python and Node toolchain installs now report what they installed; the build job's own steps (build, SBOM, push capability, push, identity check, provenance, posture) run against a real local registry, the pushed digest is served back, and a different image's digest is refused. Deferrals: 8 left, none blocking | 05, 07, 08 |

## Version 1.6 — 2026-10-15 (lane `lane/hosted-closures` on trunk `1a5f6f9`)

| commit / run | change | parts affected |
|---|---|---|
| run 38817782084 | **CodeQL ran at Level 2** — a separate private repository calling the kit by `owner/repo@sha`: 5 Python and 4 JavaScript results under `/language:python/` and `/language:javascript-typescript/`, four absent languages NOT_APPLICABLE; publication refused (no licence) while the analysis ran. It exposed two gate defects below | 04, 08, 09 |
| `6431c5e` | the gate's CodeQL rows read the file analyze writes (`javascript.sarif`, `java.sarif`, `cpp.sarif`), not the matrix leg's name; a four-result analysis had rendered NONE | 04 |
| `f7a7ed1` | a retained CodeQL analysis is applicable whatever the platform pre-flight said: the licence governs publication, not analysis. The resolve position still caps on the pre-flight — KNOWN_DEFECTS D-10 | 04 |
| run 38820564939 | **CodeQL closed** on the re-run at `f7a7ed1`: the gate's rows read both analyses (APPLICABLE / COMPLETE / RETAINED / PASS); deferral removed, ratchet 15 → 14 | 08, 09 |
| `8b36c09` | the Azure context-integrity step takes a caller-declared expected tenant / subscription / identity, compared in addition to the login's secrets, so its refusal can be dispatched without touching a secret; proven locally against a stub `az`. **Not closed**: run 38820603012 was refused before its first step — no environment's deployment branch policy admits a lane branch | 08 |

## Version 1.5 — 2026-10-15 (trunk at `13f1518`)

| commit / run | change | parts affected |
|---|---|---|
| `2bf2e49` | KDEC-011 built: the end-to-end test generates its seeded secrets on the runner and hands them to the secret scan through a TEST-ONLY input that can only ADD files (it refuses hidden files such as an ignore file, scanner config or baselines, overwrites, symlinks and path tricks) | 05, 09 |
| `3996c26` | the discover job moved into a composite action (like resolve); the main workflow is 441 KB as GitHub reads it, under the 475 KB fail line | 02, 08 |
| run 38811950471 | **END-TO-END PROVEN ON THE TRUNK.** The consumer path on `13f1518`: 20/20 seeded signals detected, each by the scanner that should detect it, across Python, Node, .NET, Java, Go (two roots each where seeded), C, Terraform, a Dockerfile and three cloud-credential classes; the negative control stayed clean; the seeded findings blocked the caller. Self-test run 38811959160 green on the same commit | 09 |

## Version 1.4 — 2026-10-15 (trunk at `16a6141`)

| commit | change | parts affected |
|---|---|---|
| `700dd9c` | hosted end-to-end defects fixed: an enforce step that failed switched off the NEXT scanner in the same job (C# Semgrep, flawfinder, OSV evidence); OSV and SBOM ignored the caller's `paths`; the NuGet audit blocked but kept no evidence; a stale fixture pin; manifests counted as packages. 17 of 17 delivered seeded signals now detected by the right tool | 04, 05, 09 |
| `a09b89c` | **KDEC-010: the capability selects the scanner.** If the default scanner cannot read the code's target version and another carried scanner can, the scan runs on that one, labelled a SUBSTITUTION (never "equivalent"). If none can, the result is annotated `VERSION_GAP` and capped at `PARTIAL`, never `PASS`. A scanner whose range is not established counts as unable to read | 02, 04, 09 |
| `cd0ffe1` | KDEC-011: the end-to-end test's seeded secrets will arrive through a test-only, add-files-only input (in progress) | 09 |
| `3dcb82d` | the build's push now checks capability and writes a change-manifest entry first (deploy-model gap 10 closed); the image's secret scan is its own report row; four more reports pass a validity check before upload; both deploy workflows carry a posture record | 05, 06, 07 |
| `16a6141` | **self-test green on GitHub** (run 38796577183, every step ran); syft and Semgrep installs pinned and checksummed; every vocabulary word in use is defined | 08, 09 |

| commit | change | parts affected |
|---|---|---|
| `8df70a8`, `77ceb03`, + report commit (lane/capability-selection) | **KDEC-010: the capability selects the scanner.** Ordered candidates per capability in the registry; resolve selects the first that can read the target (UNVERIFIED never capable); the gate and the report cap a scanner that cannot read the code at PARTIAL, never PASS, and label a substitution as one; a version-gap PARTIAL routes `PROCEED_WITH_ADVISORY`, not `EVIDENCE_UNTRUSTED` | 03, 09, 11 |
| `adbd93c` | **KDEC-009: the landing zone vends, the kit deploys** — hand-off contract drafted | 07, 11 |
| `e11d6b7`, `abfb23d`, `b08761a`, `eaef20b` | first hosted milestone runs: four load-time defects GitHub would not start (an expression-bearing script over 21,000 characters, a broken deploy output, `cancelled()` in env, an expression in a comment) and a permission ceiling (callers granted less than called jobs request). All fixed; three new checks catch the class locally (actionlint, expression length, caller permissions) | 08, 11 |
| `b08761a` | the ledger proposal moved to its own reusable workflow so the security scan never needs a write scope; callers grant `actions: read` (CodeQL) and the build's attest scopes | 06, 11 |
| `0b44892` | version fitness merged (Release 2): version probes, capability table, coverage, the resolve position as a composite; surfaced, not yet enforced | 09 |
| run 38779788549 | **the end-to-end test ran on GitHub** for the first time since 2026-09-16; it surfaced behaviour defects (seeded cloud secrets not flagged, multi-language jobs skipped, a stale clean-fixture pin) now being fixed on a dedicated lane | 09 |

## Version 1.2 — 2026-10-15 (trunk at `b02ea43`)

| commit | change | parts affected |
|---|---|---|
| `bf5899f` | flagship validity: defaults are the baseline (OD-7); known-malicious packages block in every mode with a pinned OSV; bandit/cppcheck/NuGet/gosec never read no-evidence as zero; regression tests for jobs that published a report nothing wrote; image evidence retained; licence verdict reaches the gate; Trivy keeps every severity and blocks only at the threshold; no caller input in any script body; validity checked before upload; overlay calls the kit by owner/repo@sha | 03, 04, 05, 09 |
| `a70df7f` | identity wiring: findings JSON; durable identity, anchored correlation and the baseline cascade in the report; baseline read from the protected branch; `propose-ledger` job (pushes only its proposal branch); dispositions on the durable key with a legacy window to 2026-11-13; malformed SARIF is one row | 06, 09 |
| `84fe5a6` | deploy and rollback: deploy reads the verdict and refuses before login; ATTEMPTED vs NOW SERVING; snapshot + manifest; reversal derivation; serving digest read back; six-question outcome report; irreversible deploys refused at uat/prod — all against a stub cloud | 07, 09 |
| `97b450a` | provenance: build inputs recorded, template branches on verdict and identity, stamp refuses unproven identity, build once, attest job and verify (signing and live lookup owe a hosted run), NVD workflow honest, pinned installs | 07, 09 |
| `41523a0` | NVD trivy and Dockerfile capabilities proven locally; deferrals closed; ratchet back to 15 | 08 |
| `b02ea43` | Release 2 libraries: rung ladder, policy registration, enforcement axes, severity/SLA/track — not yet in the gate | 09 |


## Version 1.1 — 2026-10-14 (trunk at `db681bc`)

| commit | change | parts affected |
|---|---|---|
| `dad00f0` | ticketing lane merged: Jira and Azure DevOps backends built to TICKETING_BACKENDS.md and proven against stubbed APIs (T-1..T-12, B-1); one backend per run enforced; calibration probe resolves a known ticket; a run that checked nothing never exits 0; ticket titles capped at 255; clusters are anchored, not chained; separate post-merge reconcile workflow (owes a hosted run) | 06, 09 |
| `db681bc` | the live proof on the owner's personal trackers is a dated deferral (2026-10-23) until tracker setup is done | 08, 09 |

## Version 1 — 2026-10-14, explainer first written (trunk at `54a9c94`)

Everything in parts 01–09 describes the trunk at this commit. What changed in the kit during the two
days before this version was written, so a reader of an earlier brief knows what is now different:

| commit | change | parts affected |
|---|---|---|
| `54a9c94` | owner decisions KDEC-006 (hosted runs per milestone, private repo), KDEC-007 (Release 1 line), KDEC-008 (defaults for OD-2/4/6/7/10) | 03, 05, 07, 09 |
| `b1b4217` | an unreadable weakening expiry (`never`, non-ISO, impossible date) is treated as expired → DECISION_REQUIRED, in all four posture records | 05 |
| `37fa320`, `3dcf57d` | two neutrality leaks closed; deny list tightened (and spares a public cloud service name) | 01 |
| `3912bdb` | identity, ledger, cascade, alias table, lineage integrity and anchored correlation built as proven libraries — not yet wired | 06, 09 |
| `d4cac90` | **Semgrep could never block**: it writes no `level` on results; findings are now counted by the SARIF effective level (Semgrep and Checkov) | 04 |
| `2b569e3` | a secret scan that read nothing (empty scope, zero commits) is COLLECTION_FAILED; detect-secrets scans all files and its count is evidence | 03, 04 |
| `9b2ea0f` | **the flagship emits `routing_result`** and the full control-posture record; deploy is to read it | 03, 05, 07 |
| `ca3211f` | a credential baked into a container image blocks in every mode (image scan split into vulnerabilities and secrets) | 04 |
| `aa455db` | lint findings can fail the job when `enforce_lint` is on; Node-only repositories are linted | 04 |
| `31ac5a6`, `c7ad2de` | expired validation deferrals answered (0 BLOCKING); hosted-run deferrals to 2026-10-23 | 08 |
| `c7ad2de` | ticketing: Jira first, Azure DevOps second (KDEC-004); `TICKETING_BACKENDS.md` | 06 |
| earlier (2026-10-13/14) | report runs where shipped (C1); secrets block in advisory mode (C2); assurance follows findings evidence (C3); every upload redacted first; history scan fetches history; evidence pointer correct; tests leave the tree clean; decomposition steps 8–11 | 02, 03, 08 |

## Lanes in progress at version 1

Flagship evidence validity (L15 OSV, L08, L12, L16, L17, L38, L01/L02, OD-7/OD-10 defaults); identity
wiring (report, propose-ledger job, OD-6 key migration); ticketing (Jira + Azure DevOps backends);
provenance and NVD; deploy and rollback; version fitness; rung ladder and SLA. Each will update the
affected part and add a row here when it merges.
