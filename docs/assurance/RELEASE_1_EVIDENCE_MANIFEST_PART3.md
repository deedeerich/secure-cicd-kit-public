# Release 1 evidence manifest, part 3 of 3

```
Covers:             sections 2, 3 and 4
Parts:              1 `RELEASE_1_EVIDENCE_MANIFEST.md`: truth state, legend, 1A scan and gate
                    (rows 1-30), 1B NVD, policy, provenance, composites (rows 31-40).
                    2 `RELEASE_1_EVIDENCE_MANIFEST_PART2.md`: 1C identity, build, deploy (rows
                    41-64), 1D ticketing (rows 65-68), the row counts for all 68 rows.
                    3 this file: the consumer interface and its gaps, what the trunk has added
                    since main, where the next proof is owed.
                    Each part is under 20 KB and stands alone.
Labels:             VERIFIED (code or run read for this file), READ (a registry comment or
                    document says so and was not re-derived), INFERRED (reasoned).
Truth State:        tied to `main` = ef4b15d (Release 1; self-test 38926152571 success).
                    Trunk deltas marked against fix/normalization-and-discovery at 078ef90.
Authority:          tests/reconcile_validation.py and the workflows at the SHAs above. Where
                    this file and they disagree, they win and this file is wrong.
Written:            2026-10-16, lane L-G; split in three and brought to 078ef90 on
                    2026-10-21, lane L-G2.
```

Row numbers below refer to the capability rows in parts 1 (rows 1-40) and 2 (rows 41-68).

## 2 · The consumer interface

What a consumer reads, by its actual name, where it is produced, and whether its shape is documented.
"Taxonomy" means every value is registered in `assurance-taxonomy.yaml` (vocabulary, not a schema).

### 2A · Workflow outputs (`workflow_call` outputs)

| output | produced by (workflow → job/step) | values / shape | documented |
|---|---|---|---|
| `routing_result` | `reusable-security.yml` → `security-gate`/`posture`; also build, both deploys, NVD, policy, ticket-reconcile | PROCEED · PROCEED_WITH_ADVISORY · DECISION_REQUIRED · BLOCKED · EVIDENCE_UNTRUSTED | taxonomy; explainer 03 |
| `advisory_causes` | `reusable-security.yml` → `security-gate`/`posture` (**trunk only**) | comma list: VERSION_GAP · VERSION_GAP_UNVERIFIED · COVERAGE_PARTIAL · WEAKENING_ATTRIBUTED · FINDINGS_NOT_BLOCKED | taxonomy `advisory_cause`; explainer 03, 11 |
| `assurance_state`, `enforcement_state` | security → `security-gate`/`gate`; NVD → `nvd-cve-scan` | PASS · FINDINGS · PARTIAL · UNDETERMINED / BLOCKED · ALLOWED · ADVISORY | taxonomy (`scanner_state`, `api_boundary`); explainer 03 |
| `gate_decision` | security | deprecated alias of `enforcement_state` | explainer 03 |
| `secret_gate` | security | PASS · FAIL | output description |
| `scanner_states` | security | compact JSON map scanner → `scanner_state` | values: taxonomy; **JSON shape: not schematised** |
| `undetermined` | security, NVD | true · false | output description |
| `established`, `unestablished` | security | capability names with states / reasons | **shape not schematised** |
| `discovery_state` | security | COMPLETE · DISCOVERY_PARTIAL · DISCOVERY_UNAVAILABLE | output description; explainer 03 |
| `evidence_artifact` | security → `security-gate` (names `report`'s upload); NVD | `security-report-<run_attempt>`; NVD `nvd-scan-results` | explainer 02, 03 |
| `controls_required/executed/unavailable/reduced/skipped` | security, NVD, build, deploys, policy; ticket-reconcile emits `controls_unavailable` only | comma lists of control names | taxonomy `control_weakening`; explainer 05 |
| `weakenings`, `weakening_attribution`, `weakening_record` | security, NVD, build, deploys, policy | JSON array / enum / JSON object | explainer 05; **JSON shape not schematised** |
| `nvd_database_state`, `cache_state` | NVD | UPDATED · STALE · UNAVAILABLE / RESTORED_COMPLETE · RESTORED_PARTIAL · COLD | taxonomy (`capability_metadata`, `scanner_state`) |
| `image_digest`, `image_config_digest` | `reusable-build-docker.yml` → `build` | `sha256:…`; digest empty on a build-only run | output description; USAGE |
| `artifact_identity` | build | REGISTRY_IDENTITY_PROVEN · LOCAL_BUILD_ONLY · IDENTITY_UNVERIFIED · NOT_ESTABLISHED | taxonomy |
| `sbom_sha256` | build | SHA-256 of the SPDX SBOM | output description |
| `build_inputs` | build | compact JSON (base images, lockfiles, toolchain) | output description; **not schematised** |
| `attestation_url` | build → `attest` | URL, empty when nothing was signed | output description |
| `app_url`; `revision` (Container Apps only) | deploys → `deploy` | URL; revision name | output description |
| `armed` | ticket-reconcile → `guard` | true · false | output description |
| `verdict`, `subject`, `subject_form`, `claim_*`, `job_workflow_ref`, `resolution`, `discrimination`, `mutation_state`, `assertions` | `verify-azure-oidc.yml` → `verify` | PASS/FAIL; strings; `assertions` JSON | taxonomy for the enums; SETUP §7 |
| `outcome`, `reference` | `reusable-ticket-reference.yml` (main, and the trunk since `9b18e49`) | seven outcome states, each named in the workflow's own output description | output description |
| `status`, `why` | `reusable-propose-ledger.yml` (**trunk only**, `a636f5e`) | whether the proposal ran or was refused, and why | output description |

### 2B · Artifacts (evidence)

| artifact | produced by | contents | documented |
|---|---|---|---|
| `security-report-<run_attempt>` | security → `report` | `_states/`: one `state-*.json` per scanner row, the redacted SARIF they name, `findings.json` | contents described in explainer 02/03; **`state-*.json` and `findings.json` have no JSON schema** — the record shape lives in `scripts/scan_report.py` and the `scan-report` composite's output description |
| `sarif-<scanner>-<run_attempt>` (16 names, CodeQL per language) | each scanner job | redacted SARIF | SARIF 2.1.0 |
| `sbom` | security → `sbom` | CycloneDX SBOM | CycloneDX; **the only flagship artifact with no run-attempt suffix** |
| `sbom-<digest>` / `sbom-localbuild-<sha>` / `sbom-IDENTITY-UNVERIFIED-<sha>` | build | SPDX SBOM, named by what it is evidence of | output description |
| `build-evidence-<run_id>-<attempt>` | build | `snapshot.json`, `capability.json`, `manifest.json` for the push | DCR §5 gap 10; not schematised |
| `deploy-evidence-<run_id>-<attempt>` | both deploys | `snapshot`, `manifest`, `capability`, `verification`, `reversal`, `outcome` (`deployment_outcome`, NOW SERVING, KDEC-014 ruling), `provenance` (.json) | explainer 07, DCR §3.4; **not schematised** |
| `nvd-scan-results` | NVD | Trivy/Dependency-Check reports | — |
| `ticket-reconcile-<run_attempt>` | ticket-reconcile | the plan/record and `ticket-ledger-proposal.json` | TICKETING_CONTRACT.md §7; on main nothing consumes the proposal (T-20); on the trunk `reusable-propose-ledger.yml`'s `ticket-ledger-artifact` carries it into the ledger pull request (`c1c3dae`) |

### 2C · Consumer-interface gaps (outputs a consumer needs and cannot read as an output)

1. **No machine run record.** `schemas/assurance-result.schema.json` describes `assurance-result.json`
   "emitted alongside every run"; nothing emits it (ledger L36). VERIFIED.
2. **The deploy outcome is not an output.** `deployment_outcome`, ATTEMPTED vs NOW SERVING, the reversal
   result and the KDEC-014 ruling exist only in the job summary and `deploy-evidence-…/outcome.json`;
   a calling pipeline must download the artifact to branch on them, and the file has no schema. VERIFIED.
   (On the trunk since `078ef90` the ruling is always present when the verdict step ran; the summary
   reads "not reported" when it did not, and the deploy's `routing_result` is then EVIDENCE_UNTRUSTED.)
3. **Coverage and version-gap detail is not an output.** `resolve` computes `version_gaps`, `coverage`,
   `capability_gaps`, `capped_jobs`, `proven_gap_jobs`, `substitutions`, `plan` and the platform probe
   (Dependabot, dataflow), but they are job outputs only; a consumer sees them only as
   `advisory_causes` and PARTIAL rows in `scanner_states`. VERIFIED.
4. **Findings are reachable only through the artifact.** `findings.json` is not a workflow output and
   has no published schema; `identity_routing` and `baseline_state` (scan-report outputs) are not
   workflow outputs and the gate does not read them. VERIFIED.
5. **Only the flagship emits causes.** Build, NVD and policy can route `PROCEED_WITH_ADVISORY` without
   `advisory_causes`, and at uat/prod the deploys refuse a causeless advisory (trunk). A pipeline that
   combines verdicts (the starter's `verdict` job) has no cause list for its combined result. VERIFIED code,
   INFERRED consequence.
6. **The deploy reusables do not take `artifact_identity`** and do not perform V1 attestation
   verification; both live in the starter template only, so a direct caller bypasses them. VERIFIED.
7. **JSON-valued outputs are not schematised**: `scanner_states`, `established`/`unestablished`,
   `weakenings`, `weakening_record`, `build_inputs`, `assertions`. Their enums are registered; their
   shapes are prose. VERIFIED.
8. **`reusable-ticket-reconcile.yml` exposes no posture rows** beyond `routing_result` and
   `controls_unavailable`. `reusable-propose-ledger.yml` exposes no output on main; on the trunk it
   exposes `status` and `why` (`a636f5e`) but still not the pull request it opened. VERIFIED.
9. **The flagship's SBOM artifact is named `sbom`**, with no run-attempt suffix and no hash output;
   every other flagship artifact carries the attempt (so does no NVD artifact: `nvd-scan-results`).
   INFERRED: a re-run attempt may collide on the name.
10. **main and the trunk expose different interfaces.** Both have `reusable-ticket-reference.yml`
    (KDEC-013; on the trunk since `9b18e49`). Only the trunk has `advisory_causes` (KDEC-014), the
    always-written ruling, and `reusable-propose-ledger.yml`'s `establish-approver-role`,
    `ticket-ledger-artifact`, `status` and `why`. VERIFIED (workflows read at `078ef90`).

## 3 · What the trunk has added since main (ef4b15d → 078ef90)

| commit | change | interface effect |
|---|---|---|
| `754f80d` | Dependabot skips the deliberately vulnerable fixtures | none |
| `2a4b677`, `d107fe9` | `docs/assurance/COMPLETION_LEDGER.md` (202 rows at 53d2962) | none |
| `1c20a0b`, `3830edb` | KDEC-014 (`advisory_causes`; uat/prod refuse a proven version gap without a named, dated acceptance) and KDEC-015 recorded | new output `advisory_causes`; new deploy input `advisory_causes`; stub-proven only |
| (lineage) | the trunk carries consumer overlays (`overlays/`), which never merge to main (KDEC-003) | none for a neutral consumer |
| `9b18e49` | KDEC-013's core reference gate, which main had from `release/main-candidate`, merged onto the trunk | the trunk now matches main here |
| `a0e8b16` (lane L-F) | F-01 fixed: a ledger is established only by an approved ESTABLISH pull request under CODEOWNERS; one move record (lineage); scanner-generation hold; environment presence declared; the ticket ledger travels in the ledger pull request | new propose-ledger inputs `establish-approver-role`, `ticket-ledger-artifact`, `reconciliation-window-days` (composite); outputs `status`, `why`; proven locally |
| `85bd33d` (lane L-T) | T-02 fixed (updates keep human text); delta-only updates; reopen classes; credential-free sweep job; degraded streak | none in outputs; ticket descriptions change |
| `f01ef04` (lane L-G) | consumer documents true to the code; this manifest | none |
| `a279f5a` (merge of 13 commits) | export gate and safety check agree; deny samples; tracer reads `env:`/`needs` and ten defects fixed; hollow-scan OD-2; Semgrep `--strict`; CodeQL autobuild read; discovery depth 8; weekly probe fixes; census outside the kit; `.context` not exported | Semgrep exit 3 and depth-hidden languages change scanner states; a silent capability step routes the deploy EVIDENCE_UNTRUSTED |
| `078ef90` | KDEC-014: exactly one ruling on every verdict path (`VERSION_GAP_NOT_ENGAGED`); an absent ruling routes EVIDENCE_UNTRUSTED | deploy summary and `outcome.json` always carry a ruling; stub-proven |

## 4 · Where the next proof is owed (from completion ledger section 4)

Re-run the consumer path on the trunk commit that becomes the next main (rows 1–3, 5, 9, 15 are
proven on main `ef4b15d` by run 38934329462; rows 2, 3, 5, 9 cite row 1's runs). One hosted run
of the starter template, scan → verdict → build → deploy (rows 60–61). Live B, D and EMPTY on the
sandbox (rows 55–58). Armed ticketing on the personal Jira (row 67, O-18). Attestation on a public
repository (row 46, O-20). Keyed NVD run (row 32). One hosted establish-then-propose ledger run
(row 24). The `sast-semgrep` job's 1.90.0 container under `--strict` (row 6).
