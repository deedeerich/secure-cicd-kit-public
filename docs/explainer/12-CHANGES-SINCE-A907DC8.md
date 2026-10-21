# 12 · What changed since explainer v1.10 (`a907dc8`), by what you must do differently

For a reader whose last copy of this explainer was **v1.10** (trunk `a907dc8`, 2026-10-16). It covers
every behavioural change on the trunk from `a907dc8` to **`078ef90`** (explainer v1.12), grouped by
what an integrator must do differently, each with its commit. `main` is still Release 1 (`ef4b15d`):
everything here is on the trunk only unless it says otherwise. Version history: `10-CHANGE-LOG.md`.

**Truth labels** (part 00): **VERIFIED** — the named proof or check was run at `078ef90` for this part,
or the workflow was read there, or a hosted run was read back. **READ** — taken from the commit
message or merge record, not re-run here. **DESIGNED** — specified, not built. Nothing below was
proven live after `a907dc8` except where a run id or a live record is cited.

**Parts to replace** if you hold v1.10: 00, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, and add 10b and
12. Part 01 is unchanged. The evidence manifest is now three files (section 8).

## 1. If you call a deploy reusable — pass the causes, and read an absent ruling as a fault

| commit | change | what you do | label |
|---|---|---|---|
| `1c20a0b` | **KDEC-014.** The security gate emits a new output `advisory_causes` (`VERSION_GAP`, `VERSION_GAP_UNVERIFIED`, `COVERAGE_PARTIAL`, `WEAKENING_ATTRIBUTED`, `FINDINGS_NOT_BLOCKED`) when `routing_result` is `PROCEED_WITH_ADVISORY`. Both deploy reusables take a new input `advisory_causes`. At `uat`/`prod` a proven `VERSION_GAP` is refused before login unless the weakening record names an accepter (`weakening_authority`), a reason and an unexpired `weakening_expires`; `VERSION_GAP_UNVERIFIED` proceeds, recorded loudly; an advisory with no or an unregistered cause is refused. Below `uat` any gap is recorded and proceeds | pass `advisory_causes: ${{ needs.security.outputs.advisory_causes }}` to every deploy; set required reviewers on the `uat` and `prod` environments (the approval half of the exception); to accept a gap, supply the three `weakening_*` fields in the deploy call | VERIFIED: `prove_version_gap_production.py` (stub cloud); no live run |
| `078ef90` | **The verdict step always answers.** It writes exactly one `version_gap_ruling` on every path it reaches, refused or not; new value `VERSION_GAP_NOT_ENGAGED` when no gap rule applied. An **empty** ruling means the step never ran or never finished: the deploy's own posture routes `EVIDENCE_UNTRUSTED` (a `BLOCKED` stands) and its summary reads "not reported" instead of "not engaged" | treat "not reported", or a deploy `routing_result` of `EVIDENCE_UNTRUSTED` with no ruling, as a pipeline fault, never as "no gap". If you parse `outcome.json`, expect a ruling whenever the verdict step ran | VERIFIED: `prove_version_gap_production.py`, `prove_deploy_posture.py`; tracer 8 UNGUARDED → 0 (READ) |
| `71a3d63` | **Silent reversal is unavailable reversal.** With `rollback_on_failure: true` (the default), a rollback-capability step that succeeded but wrote no verdict used to read as "rollback available"; it now reads `UNAVAILABLE`, so the deploy lists `reversal` in `controls_unavailable` and routes `EVIDENCE_UNTRUSTED` | expect `EVIDENCE_UNTRUSTED` from a deploy whose capability step said nothing, and fix the pipeline, not the code | VERIFIED: workflow read; `prove_deploy_posture.py` |

The deploy outcome (ruling included) is still **not** a workflow output: read the job summary or
`outcome.json` in `deploy-evidence-<run_id>-<attempt>` (parts 07, 11).

## 2. If you read scanner states or the report — some results change

| commit | change | what you do | label |
|---|---|---|---|
| `fa19c02` | **Hollow scan per tool (KDEC-008 OD-2).** A clean Bandit run's report row read NOT ESTABLISHED ("a pipeline defect") while the job and gate called it clean; it now reads clean. A Bandit run that could not parse a file (an error in either SARIF notification array) reads NOT ESTABLISHED | stop treating clean Bandit NOT ESTABLISHED rows as expected noise | VERIFIED: `prove_hollow_scan.py` |
| `1542c05` | **Semgrep `--strict`.** In `sast-semgrep`, the C# and the Java jobs a file Semgrep cannot parse is exit 3 and `COLLECTION_FAILED`, not a warning and a zero | a repository with unparseable files will now see `COLLECTION_FAILED` (evidence missing, never clean) where it saw a clean row: fix or exclude those files | VERIFIED: `prove_semgrep_strict.py` (Semgrep 1.178.0); the `sast-semgrep` job's 1.90.0 container owes a hosted run |
| `1542c05` | **CodeQL autobuild read.** An autobuild that did not succeed reads `PARTIAL`, not `COMPLETE` | read the summary or annotation; the gate does not read this state, so it does not change `routing_result` | VERIFIED: `prove_codeql_build_outcome.py` |
| `11db350` | **Discovery depth bound 8.** A language not found within 8 directory levels, in a scope that has deeper entries, is `UNDETERMINED` and its scanner **runs** (was `NOT_APPLICABLE`), with a `BeyondSearchDepth` coverage gap; Node/.NET/Go root enumerations search 8 levels (was 6) | in a deep repository expect more scanner jobs and a coverage-gap annotation; narrowing with `paths` is a recorded weakening | VERIFIED: `prove_discovery_depth.py` |
| `655a2e5` | the weekly tool probe (`validate-scanners.yml`) probes the versions the flagship runs, and its negative control can fail | nothing for a caller; trust the weekly probe more | VERIFIED: `prove_validate_scanners.py`; hosted run 39618320185 on `078ef90` green |

## 3. If you keep a baseline ledger — you can now establish one, only by an approved pull request

| commit | change | what you do | label |
|---|---|---|---|
| `a636f5e` | **F-01 fixed.** `reusable-propose-ledger.yml` has a new optional input `establish-approver-role` (no default). With no ledger and no role it refuses; with a role it opens an **ESTABLISH pull request** naming the role and asserting no age, only if CODEOWNERS on the default branch covers the ledger path. New workflow outputs `status` and `why`. A role given when a ledger exists is ignored and said so | to establish: add a CODEOWNERS rule over the ledger path, call the reusable once on the default branch with the role, and merge the pull request; read `status`/`why` | VERIFIED: `prove_propose_ledger_establishment.py`; no hosted run; no template calls it |
| `b036f5c` | **One move record.** A moved finding is re-keyed (`first_seen` kept) and the move is a lineage event in `.security/finding-lineage.jsonl` (+ head anchor) in the same pull request; `move_history` in an entry is refused by name. The composite's output is `tree`, not `content-file` | if you wrote or read `move_history`, stop; a direct caller of the composite reads `tree` | READ (proof `prove_propose_ledger.py` in the sweep) |
| `417c6ae` | **Scanner-generation hold.** A finding first reported by a pinned scanner's unreconciled new generation is held, never admitted NEW; one reconciliation report per (scanner, from, to) under `.security/reconciliations/`, window `reconciliation-window-days` (composite input, placeholder 30, owner decision O-06) | after a scanner upgrade, a named approver accepts the reconciliation report before its findings enter | VERIFIED: `prove_propose_ledger_generation.py` |
| `4329f2b` | **Presence in an environment** is a declared, dated assumption (`environment_presence` in the ledger header), written on an environment's first proposal and never re-dated | nothing; review the declaration in the pull request | READ |
| `c1c3dae` | **The ticket ledger joins the ledger pull request.** New optional input `ticket-ledger-artifact` names the ticket reconciler's artifact; a changed ticket ledger travels at `.security/ticket-ledger.json` | pass the reconcile run's artifact name so ticket bindings persist; without it the next run after a successor reads `BINDING_AMBIGUOUS` | VERIFIED: `prove_propose_ledger_ticket_ledger.py` |

Both new inputs are classified inert in the weakening record (neither softens a control).

## 4. If you run ticketing — descriptions are safe, updates are deltas, and a PR gate is core

| commit | change | what you do | label |
|---|---|---|---|
| `795d13c`, `8265fce` | **T-02 fixed.** An update reads the description in full and replaces only the kit's delimited block; human text around it survives (Jira ADF, Azure DevOps HTML with a revision precondition). An unreadable description is never written: the update is owed and the ticketing claim is `EVIDENCE_UNTRUSTED` | nothing; people may write around the block | VERIFIED: `prove_ticket_backends.py`; live on the personal Jira per the L-T merge `85bd33d` (READ) |
| `c712a41` | **Delta updates.** A bound ticket is written only when members, effective severity, contributing scanners (a stopped one named "no longer contributing") or members not seen this run (`POTENTIALLY_ABSENT`) change; an unchanged run writes nothing. The registry calls ticket reconciliation observed at **tool** level, not workflow | expect far fewer writes; do not read the registry as an armed-workflow proof | READ |
| `1193914` | **Reopen classes** (`REOPENED_BY_LAPSE`, falsified, unbacked) recorded and posted once as a comment. The scheduled sweep runs in its own job with **no environment and no secret**. The live runner breaks a fifth setting (`JIRA_TRANSITION_REOPEN` / `AZDO_STATE_REOPEN`). A degraded obligation counts consecutive runs; past `TICKET_DEGRADED_RUN_THRESHOLD` (owner-set; 0 = count, never escalate) it escalates as `DECISION_REQUIRED` | set the threshold if you want escalation; the sweep needs no credential | READ |
| `82a2151`, `9b18e49` | **KDEC-013: the pull-request Jira reference gate is core** (`reusable-ticket-reference.yml`, on main and now on the trunk): inputs `tracker_host`, `project_key`, optional `min_digits`/`max_digits` (both or neither; **no default range**); outputs a typed outcome; a non-pull-request event is `NOT_A_PULL_REQUEST`, never passed | call it on pull requests; a consumer that limits ticket numbers passes the range in its own caller. It checks the format only | VERIFIED: `prove_ticket_reference_gate.py` |
| `71a3d63` | ticket-reconcile: an absent exit code has its own case arm (same behaviour, stated) | nothing | READ |

## 5. If you run the identity probe or the NVD workflow

| commit | change | what you do | label |
|---|---|---|---|
| `71a3d63` | `verify-azure-oidc.yml`: the adjudicate step counted a baseline step that never wrote its answer as a baseline taken; it is now UNAVAILABLE; the terminal gate defaults to NOT_ATTEMPTED rather than empty | a silent baseline step is now counted as no baseline taken; read the probe's `verdict` as before | READ (tracer clean, VERIFIED) |
| `71a3d63` | `reusable-nvd-cve.yml`: the summary's unavailable list is read only when the summary wrote its state | nothing | READ |

## 6. If you copy or export the kit (adoption, a public mirror)

| commit | change | what you do | label |
|---|---|---|---|
| `970a0dd`, `3500e23` | `.context/` (continuity records) is never exported | nothing | VERIFIED: `prove_export_scope.py` |
| `bc98cc5` | an absent or empty deny list **refuses** the export (it used to export with nothing checked); the export profile is recorded in the watermark and an incremental under another profile is refused; the kit's own consumer-path harness workflow is no longer exported | keep a deny list next to the exporter; re-run a full export if your watermark predates the profile field | VERIFIED: `prove_export_scope.py` |
| `b352729`, `53d2962`, `69e652e`, `fdd0a0c` | every deny pattern carries samples it must match and must not match; a word-boundary corrupted to a control byte is refused; more name forms denied | a consumer's own deny additions need `#+` samples | VERIFIED: `prove_deny_samples.py` |
| `c82b34f` | `check_export_safety.py` reads never-lift patterns as the export gate does and refuses if the two pattern sets disagree | nothing | VERIFIED: the check run at `078ef90` |
| `c7309f1` | the watermark records the source commit and drops the branch name | nothing | READ |
| `5fde1e4` | the consumer census writes to the system temp directory or `CONSUMER_COVERAGE_OUT`, never inside the kit | set `CONSUMER_COVERAGE_OUT` if you want it elsewhere | VERIFIED: `prove_census_outside_kit.py` |
| `754f80d` | Dependabot never updates the deliberately vulnerable test fixtures | nothing | READ |

## 7. Decisions recorded (no code change for a caller beyond the above)

- **KDEC-014** (`1c20a0b`): version-gap-only advisory is dev/test only; uat/prod refuse it until the
  gap closes or a named person accepts it (section 1).
- **KDEC-015** (`1c20a0b`): the split "the landing zone vends, the kit releases" covers internal tools
  too: each gets its own empty target and its own deploy identity (part 11).
- **KDEC-013** (`82a2151`): the Jira reference gate is core (section 4).

## 8. Documentation-only changes

- `2a4b677`: `docs/assurance/COMPLETION_LEDGER.md`, 202 designed-vs-built rows at `53d2962`.
- `59d2a4c`, `89109d5` (lane L-G): consumer documents made true to the code (advisory mode never
  covered secrets; the deploy workflows are proven live; no example sets the dead `enable_iac`);
  `check_doc_currency.py` reads them. Main proven end to end on main itself (run 38934329462).
- `e32c7f6`, `bb7ef0d`: tracer-visible outputs and two self-descriptions corrected; no behaviour.
- v1.12 (this delivery): the evidence manifest is three standalone files —
  `RELEASE_1_EVIDENCE_MANIFEST.md` (part 1), `_PART2.md`, `_PART3.md`; the change log split (`10b`);
  part 00 separates VERIFIED from READ; parts 06, 09 and 11 no longer say F-01 and T-02 are open
  (v1.11 had missed the L-F and L-T merges).

## 9. Still true, and still owed

No live run has carried a real gate verdict into a deploy in one pipeline; the trunk owes the
consumer-path run on a commit after `ef4b15d`; no hosted establish-then-propose ledger run; Azure
DevOps live and an armed hosted ticket-reconcile run are owed; attestation signing is held by plan.
Self-test on `078ef90` (run 39618329392) failed in the export-scope proof: a scanner archive downloaded
into the runner's working tree tripped the deny list during the proof's own export. The exporter
excluded only gitignored files, so the download would also have shipped. Fixed in `904bc7a`: whatever
git does not track is neither scanned nor exported; self-test 39622321744 green (VERIFIED; part 09).
Deferrals: 0 BLOCKING, 3, ratchet 3/3 (VERIFIED, `reconcile_validation.py` at `078ef90`).
