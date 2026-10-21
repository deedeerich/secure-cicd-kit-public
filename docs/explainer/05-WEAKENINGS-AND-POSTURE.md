# 05 · Inputs, weakenings and the control-posture record

## The rule

**A weakening is a governed exception, not a boolean preference.** Any input that can soften, skip,
narrow or reduce a control is listed in an emitted record with its class, its baseline, the value used,
and who decided. The enumeration is **total** over the workflow's inputs: `tests/check_weakening_record.py`
fails the build if an input exists without a classification, if an input that describes itself as
softening is labelled inert, if any of the nine record rows is missing, or if any of the five routing
outcomes is unreachable.

## The flagship's inputs (VERIFIED at `078ef90`: 26 inputs, all enumerated)

**Defaults are the baseline (KDEC-008, OD-7, applied in `127438d`):** `soft_fail_sast: false`, `language:
auto`. A caller who changes nothing gets every control at full strength and `PROCEED` on a clean run.
The new `environment` input names the baseline-ledger environment; empty is TARGET_NOT_SUPPLIED.

| input | class | baseline | governs | notes |
|---|---|---|---|---|
| `language` | SCOPE_NARROWED | `auto` or `multi` | which ecosystems run | can only EXCLUDE what discovery found |
| `paths` | SCOPE_NARROWED | `.` | every scanner | |
| `iac_mode` | CONTROL_DISABLED | anything but `disabled` | iac-scan | `required` makes absence a finding |
| `enable_iac` | CONTROL_SURFACE_DEAD | `false` | — | deprecated; read by nothing; setting it is reported as dead |
| `codeql_queries` | DEPTH_REDUCED | `security-extended` | codeql | |
| `license_deny` | TARGET_NOT_SUPPLIED | non-empty | licence gate | empty = inventory only, not a weakening: licence policy is the consumer's |
| `image_ref` | TARGET_NOT_SUPPLIED | non-empty | image-scan | empty = NOT_APPLICABLE, never clean |
| `semgrep_config` | SCOPE_NARROWED | `p/default p/owasp-top-ten p/xss` | sast-semgrep | |
| `fail_on_severity` | SEVERITY_RAISED | `CRITICAL,HIGH` | deps-scan, image vulnerabilities | |
| `enable_sbom` | CONTROL_DISABLED | `true` | sbom | |
| `enable_malicious_pkg_scan` | CONTROL_DISABLED | `true` | malicious-deps | |
| `advisory_mode` | GATE_SOFTENED | `false` | the gate | never softens secrets or toolchain failures |
| `scan_git_history` | DEPTH_REDUCED | `false`, or deeper | secret-scan | turning it ON is never a weakening |
| `soft_fail_sast` | GATE_SOFTENED | `false` | SAST jobs | |
| `enforce_lint` | GATE_SOFTENED | `false`, or stronger | code-quality | lint is not a security control; ON only strengthens |
| `python_version`, `node_version`, `dotnet_version`, `go_version`, `java_version` | NOT_A_CONTROL_SURFACE | — | toolchains | |
| `environment` | TARGET_NOT_SUPPLIED | non-empty | the baseline ledger | names the ledger cell; empty grandfathers nothing and makes the identity claim EVIDENCE_UNTRUSTED, never changes what blocks |
| `test_only_seed_artifact` | NOT_A_CONTROL_SURFACE | `""` | — | TEST-ONLY (KDEC-011): can only ADD files to the scanned tree; overwrite, dotfiles, scanner config and traversal are refused; the secret-scan job warns when it is in force |
| `weakening_reason`, `weakening_authority`, `weakening_exception_ref`, `weakening_expires` | EXCEPTION_ATTRIBUTION | — | the record itself | |

Classes are terms in `assurance-taxonomy.yaml :: control_weakening`. A class that is not registered makes
the record untrustworthy, and the route becomes `EVIDENCE_UNTRUSTED`.

## How the record decides

For each input: at baseline → nothing recorded as weakened. Otherwise, by class:

| class | the control | counted as |
|---|---|---|
| CONTROL_DISABLED | skipped | a weakening in force |
| GATE_SOFTENED | runs and reports; only the block is withheld | reduced; a weakening in force |
| SCOPE_NARROWED / SEVERITY_RAISED / DEPTH_REDUCED | runs, differently | reduced; `CONTROL_RECONFIGURED` (different is not provably weaker, so it owes a decision) |
| TARGET_NOT_SUPPLIED | skipped for want of a target | skipped, **not** a weakening |
| CONTROL_SURFACE_DEAD | — | reported as a dead input |

Then **attribution**:

| situation | `weakening_attribution` |
|---|---|
| nothing weakened | `WEAKENING_AT_BASELINE` |
| weakened, reason **and** authority supplied, expiry valid and not passed | `WEAKENING_ATTRIBUTED` |
| weakened, reason or authority missing | `WEAKENING_UNATTRIBUTED` |
| weakened, expiry passed, **or not a real YYYY-MM-DD date** | `WEAKENING_EXCEPTION_EXPIRED` |

A reason without an authority is an explanation, not a decision. An expiry nobody can read (`never`,
`31/12/2099`) is treated as expired: it cannot be shown to be in force (VERIFIED: `prove_gate_routing.py`
expiry scenarios). Silence never renews an exception.

Then **routing** (part 03): unattributed or expired → `DECISION_REQUIRED`; attributed → at most
`PROCEED_WITH_ADVISORY`; everything at baseline and a clean gate → `PROCEED`.

## How a caller weakens a control properly

```yaml
with:
  soft_fail_sast: true
  weakening_reason: "first adoption on an inherited backlog; baseline being burned down"
  weakening_authority: "security lead"
  weakening_exception_ref: "<ticket or disposition id>"
  weakening_expires: "2026-12-31"
```

That run routes `PROCEED_WITH_ADVISORY` on an otherwise clean gate, shows the weakening in every summary,
and reverts to `DECISION_REQUIRED` the day after the expiry unless someone re-decides it.

## The other reusable workflows

`reusable-nvd-cve.yml`, `reusable-build-docker.yml`, `workflow-policy-check.yml` and both deploy
reusables carry the same record and expose the same nine posture outputs (the deploys' routing is
proven by `tests/prove_deploy_posture.py`). `reusable-ticket-reconcile.yml` records its inputs but
exposes only `routing_result` and `controls_unavailable` as workflow outputs. `check_weakening_record.py`
reports 10 workflows RECORDED at `078ef90`, and one exempt (below). `reusable-propose-ledger.yml`'s
inputs `establish-approver-role` and `ticket-ledger-artifact` are classified inert: neither softens a
control (part 06).

**In the deploy reusables, silence is never a pass** (VERIFIED at `078ef90`: `prove_deploy_posture.py`,
`prove_version_gap_production.py`). With reversal required (`rollback_on_failure: true`, the default),
a rollback-capability step that succeeded but wrote no verdict
reads as reversal **UNAVAILABLE**, never available (`71a3d63`), so the deploy's posture lists it in
`controls_unavailable` and routes `EVIDENCE_UNTRUSTED`. A KDEC-014 version-gap ruling that is empty
(the verdict step never answered) routes `EVIDENCE_UNTRUSTED` too, unless the route is already
`BLOCKED` (`078ef90`, part 03). In the deploy reusables the four `weakening_*` fields are also the **KDEC-014 exception**:
at uat/prod a proven `VERSION_GAP` is accepted only when `weakening_authority` names the accepter,
`weakening_reason` says why and `weakening_expires` has not passed (part 03, part 11). Only the OIDC
verifier (`verify-azure-oidc.yml`) is still **exempt with a dated expiry (2026-10-31)**: its inputs
are probe expectations, not control settings; the exemption is printed on every run. (Its stated
closing condition — the two Azure deferrals closing — was met on 2026-10-15, and its reason still
says the probe was never dispatched; the exemption is owed a fresh decision.)
