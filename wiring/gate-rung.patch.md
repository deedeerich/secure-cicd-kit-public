# Wiring the rung into the gate — the exact change, its proof, and what it implies for the posture record

```
For:    the coordinator (this lane does not edit .github/workflows/reusable-security.yml)
From:   lane/rung-sla, commits 6de9529 (L33), 3d45d5a (L32), c5df9de (L47)
Proof:  tests/prove_gate_reads_rung.py -- FAILS today with 41 named items, PASSES once this is
        applied as written. Add it to self-test.yml beside prove_gate_routing.py at that point.
Rule:   wiring is a separate small step (SINGLE_PIPELINE_TARGET.md section 5.1 puts resolution in
        a `resolve` job; until that job exists, the gate job is the only place that already reads
        every result, so stage 1 runs there, first). Zero bytes are added to any scanner job.
```

## 0 · What this does and does not do

Does: resolves the rung, tier, team pattern, cherry-picks and derived `policy_mode` from the
registration on the protected default branch **before the gate reads results**; emits the registered
rung, the effective minimum per control and every divergence (ETFB section 2.2); folds the
resolution's own routing into `routing_result` by the registered precedence; exits on the verdict.

Does not: replace `inputs.advisory_mode` / `inputs.soft_fail_sast` in the fourteen scanner jobs with
the derived `policy_mode`. That is the `resolve` job of SINGLE_PIPELINE_TARGET.md section 5.1 and a
dated deferral (see the lane report). What this patch does make true now: when the derived mode is
`strict` and a caller still sets `advisory_mode: true` or `soft_fail_sast: true`, the posture record
already records `GATE_SOFTENED` / `WEAKENING_IN_FORCE` for those inputs, so the run routes
`DECISION_REQUIRED` unless attributed — the softening below the rung is visible in the record, which
is the whole of ETFB 2.2.

## 1 · New composite: `.github/actions/resolve-policy/action.yml`

Same shape as `scan-report`: runs the kit's script from the kit delivered by `$/`, reads the governance
file from the **fetched default branch**, never from the checkout. Register it in
`tests/reconcile_validation.py` with no capability, exactly like `scan-report` (section 5) — evidence
assembly, not an assurance claim, so no deferral and no ratchet change.

```yaml
name: resolve-policy
description: >-
  Stage 1. Resolves the registered rung, environment tier, team pattern and cherry-picks for this run
  from .security/policy-registration.json on the PROTECTED DEFAULT BRANCH, derives policy_mode from the
  rung, and refuses by name when the policy is defective or unreadable. Nothing resolves to crawl
  because it could not read the file. ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md sections 1-4;
  docs/architecture/RUNG_DERIVATION_TABLE.md.
inputs:
  default-branch:
    description: The protected default branch. The registration is read from origin/<this>, by ref.
    required: true
  environment:
    description: >-
      The environment this run targets. Empty means the highest environment the ref reaches without a
      human gate (a pull request, or a post-merge push). A named environment can never select below that.
    required: false
    default: ''
  event:
    description: github.event_name.
    required: true
  supplied-inputs:
    description: >-
      toJSON(inputs) of the calling workflow -- every input the run RECEIVED. Any spelling of policy_mode
      among them refuses the run; a rung among them is compared against the registered one.
    required: true
outputs:
  policy_state:                 {value: "${{ steps.r.outputs.policy_state }}"}
  policy_routes_to:             {value: "${{ steps.r.outputs.policy_routes_to }}"}
  policy_environment:           {value: "${{ steps.r.outputs.policy_environment }}"}
  policy_environment_tier:      {value: "${{ steps.r.outputs.policy_environment_tier }}"}
  policy_team_pattern:          {value: "${{ steps.r.outputs.policy_team_pattern }}"}
  policy_rung_declared:         {value: "${{ steps.r.outputs.policy_rung_declared }}"}
  policy_rung_effective:        {value: "${{ steps.r.outputs.policy_rung_effective }}"}
  policy_rung_divergence:       {value: "${{ steps.r.outputs.policy_rung_divergence }}"}
  policy_policy_mode:           {value: "${{ steps.r.outputs.policy_policy_mode }}"}
  policy_policy_mode_source:    {value: "${{ steps.r.outputs.policy_policy_mode_source }}"}
  policy_effective_minimum:     {value: "${{ steps.r.outputs.policy_effective_minimum }}"}
  policy_divergences:           {value: "${{ steps.r.outputs.policy_divergences }}"}
  policy_weakenings:            {value: "${{ steps.r.outputs.policy_weakenings }}"}
  policy_unvalidated_human_workflow_paths: {value: "${{ steps.r.outputs.policy_unvalidated_human_workflow_paths }}"}
  policy_stops_on_evidence_untrusted:      {value: "${{ steps.r.outputs.policy_stops_on_evidence_untrusted }}"}
runs:
  using: composite
  steps:
    - name: Resolve the enforcement policy from the protected default branch
      id: r
      shell: bash
      env:
        # CALLER INPUT ARRIVES AS DATA, NEVER AS SCRIPT TEXT (tests/lint_injection.py).
        DEFAULT_BRANCH: ${{ inputs.default-branch }}
        TARGET_ENVIRONMENT: ${{ inputs.environment }}
        EVENT_NAME: ${{ inputs.event }}
        SUPPLIED_INPUTS: ${{ inputs.supplied-inputs }}
      run: |
        set -uo pipefail
        kit_root="$(cd "${GITHUB_ACTION_PATH}/../../.." && pwd)"
        resolver="${kit_root}/scripts/policy_registration.py"
        # A MISSING RESOLVER IS NOT A RESOLVED POLICY. Without it the run has no rung, and a run
        # with no rung must not be read as one at the bottom of the ladder.
        if [ ! -s "$resolver" ]; then
          echo "::error title=Policy resolver absent::${resolver} is not in the kit delivered by \$/."
          echo "policy_state=REGISTRATION_UNAVAILABLE" >> "$GITHUB_OUTPUT"
          echo "policy_routes_to=EVIDENCE_UNTRUSTED" >> "$GITHUB_OUTPUT"
          exit 1
        fi
        # THE REGISTRATION COMES FROM THE PROTECTED DEFAULT BRANCH, NEVER FROM THIS CHECKOUT. On a
        # pull_request run the workspace IS the PR's tree; a registration read from it is a PR
        # demoting its own rung. A failed fetch leaves no ref, and the resolver reports
        # REGISTRATION_UNAVAILABLE -- never a local-file fallback.
        def_branch="${DEFAULT_BRANCH:-main}"
        git fetch --depth=1 origin "$def_branch" >/dev/null 2>&1 || true
        # Every input the run received, as --supplied key=value. The resolver refuses any
        # spelling of policy_mode and compares a supplied rung against the registered one.
        supplied=()
        while IFS= read -r kv; do
          [ -n "$kv" ] && supplied+=(--supplied "$kv")
        done < <(printf '%s' "${SUPPLIED_INPUTS:-{}}" | python3 -c 'import json,sys; d=json.load(sys.stdin) or {}; [print("%s=%s" % (k, v)) for k, v in d.items()]')
        python3 "$resolver" --repo . --default-ref FETCH_HEAD \
          --environment "${TARGET_ENVIRONMENT:-}" --event "${EVENT_NAME:-}" \
          "${supplied[@]}" \
          --out "${RUNNER_TEMP}/policy-resolution.json" \
          --github-output "$GITHUB_OUTPUT"
        rc=$?
        # The resolver's own exit says resolved (0) or refused (1). The posture record folds the
        # refusal into routing_result and the verdict step exits on it; this step does not fail
        # the job itself, so the record is still written. suppression:
        # FAILURE_ISOLATION_WITH_STATE_CAPTURE -- discards: the exit code; preserved_by:
        # policy_state and policy_routes_to in $GITHUB_OUTPUT, read by the posture step.
        echo "resolver exit $rc (0 resolved, 1 refused by name -- see policy_state)"
        exit 0
```

## 2 · One new input on `reusable-security.yml`

```yaml
      target_environment:
        description: >-
          The environment this run targets, as named in the repository's policy registration
          (.security/policy-registration.json on the protected default branch). Leave empty for a
          pull request or a post-merge push: the run is then evaluated at the rung of the highest
          environment the ref reaches without a human gate. Naming an environment can only select
          a cell at or above that one; it is not a knob that lowers anything.
        type: string
        required: false
        default: ''
```

Posture classification (totality; `tests/check_weakening_record.py`):

```
          posture target_environment        NOT_A_CONTROL_SURFACE - -
```

Why that class: it changes no control's strength, scope, depth or enforcement by itself. The
resolver evaluates at the higher of the named cell and the highest cell the ref reaches unattended
(`tests/prove_policy_registration.py`, the "naming dev on a branch that reaches prod" case), so the
input cannot select a weaker rung than the merge already reaches. The rung is a property of the
registered policy; this input only says which cell, and only upward.

**No input named `policy_mode`, `rung` or any spelling of either may ever be declared.** GitHub
refuses an undeclared input at the call site, which is the structural half of the refusal; the
resolver refusing any spelling it is handed in `toJSON(inputs)` is the runtime half, and it is what
keeps the property true if someone later declares one.

## 3 · The gate job: a `policy` step before `gate`

Insert as the FIRST step of `security-gate`, before `- name: Enforce required scans` (`id: gate`):

```yaml
      - name: Resolve the enforcement policy from the protected default branch
        id: policy
        # STAGE 1 RUNS BEFORE ANY RESULT IS READ. The rung is registered on the protected default
        # branch and read from there; policy_mode is DERIVED from it and never received. A refusal
        # is named (policy_resolution) and nothing resolves to crawl because it could not read the
        # file. docs/architecture/RUNG_DERIVATION_TABLE.md; tests/prove_gate_reads_rung.py.
        uses: $/.github/actions/resolve-policy
        with:
          default-branch: ${{ github.event.repository.default_branch }}
          environment: ${{ inputs.target_environment }}
          event: ${{ github.event_name }}
          supplied-inputs: ${{ toJSON(inputs) }}
```

The gate job already runs on `ubuntu-latest` without a checkout; `$/` composites are resolved by
the platform from the kit's pinned ref, and the composite's `git fetch` needs a repository in the
workspace. `security-gate` must therefore gain the same checkout the scanner jobs have, before the
policy step:

```yaml
      - uses: actions/checkout@v7
        with:
          fetch-depth: 1
```

(Pin by SHA per POLICY R2 when `pin-actions.sh --apply` runs; the kit's other `uses:` lines are in
the same state.)

## 4 · The posture step: read the resolution, record the rung, fold the route

### 4.1 `env:` additions on the posture step

```yaml
          # What stage 1 resolved, as data (wiring/gate-rung.patch.md).
          P_RESOLUTION: ${{ steps.policy.outputs.policy_state }}
          P_ROUTES: ${{ steps.policy.outputs.policy_routes_to }}
          P_RUNG_DECLARED: ${{ steps.policy.outputs.policy_rung_declared }}
          P_RUNG_EFFECTIVE: ${{ steps.policy.outputs.policy_rung_effective }}
          P_RUNG_DIVERGENCE: ${{ steps.policy.outputs.policy_rung_divergence }}
          P_POLICY_MODE: ${{ steps.policy.outputs.policy_policy_mode }}
          P_ENVIRONMENT: ${{ steps.policy.outputs.policy_environment }}
          P_TIER: ${{ steps.policy.outputs.policy_environment_tier }}
          P_TEAM: ${{ steps.policy.outputs.policy_team_pattern }}
          P_EFFECTIVE_MINIMUM: ${{ steps.policy.outputs.policy_effective_minimum }}
          P_DIVERGENCES: ${{ steps.policy.outputs.policy_divergences }}
          P_WEAKENINGS: ${{ steps.policy.outputs.policy_weakenings }}
          P_UNVALIDATED: ${{ steps.policy.outputs.policy_unvalidated_human_workflow_paths }}
          P_STOPS_ON_UNTRUSTED: ${{ steps.policy.outputs.policy_stops_on_evidence_untrusted }}
          W_TARGET_ENVIRONMENT: ${{ inputs.target_environment }}
```

### 4.2 Bash: after the `auth=` block ("WHO DECIDED"), before "ROUTING, by the registered precedence"

```bash
          # THE RUNG (wiring/gate-rung.patch.md). Stage 1 resolved the policy from the protected
          # branch, or refused by name. A refusal is not crawl: a policy DEFECT (a supplied
          # policy_mode, a cherry-pick below the floor, non-monotone cells) routes BLOCKED and a
          # missing input (unreadable registration, unregistered cell, unconfigured number) routes
          # EVIDENCE_UNTRUSTED; both are folded into the route below by precedence. A rung
          # demotion, or a supplied rung below the registered one, arrives as weakening rows with
          # their own attribution and joins the record like any other weakening.
          case "${P_RESOLUTION:-}" in
            POLICY_RESOLVED) : ;;
            "") P_ROUTES=EVIDENCE_UNTRUSTED
                echo "::error title=Policy not resolved::the resolve-policy step emitted nothing; this run has no rung." ;;
            *)  echo "::error title=Policy ${P_RESOLUTION}::see the resolve-policy step. Nothing resolves to crawl because it could not read the file." ;;
          esac
          if [ -n "${P_WEAKENINGS:-}" ] && [ "${P_WEAKENINGS}" != "[]" ]; then
            pw="${P_WEAKENINGS#[}"; wk="$wk,${pw%]}"
            inforce=$((inforce+1))
            if printf '%s' "$P_WEAKENINGS" | grep -Eq 'WEAKENING_UNATTRIBUTED|WEAKENING_EXCEPTION_EXPIRED'; then
              auth=WEAKENING_UNATTRIBUTED
            elif [ "$auth" = WEAKENING_AT_BASELINE ]; then
              auth=WEAKENING_ATTRIBUTED
            fi
          fi
```

### 4.3 Bash: after `route` is computed, before `emit()`

```bash
          # FOLD THE RESOLUTION'S OWN ROUTING BY THE REGISTERED PRECEDENCE. BLOCKED from the
          # policy check is an observed refusal: the check fired, by name.
          rank() { case "$1" in BLOCKED) echo 5;; EVIDENCE_UNTRUSTED) echo 4;; DECISION_REQUIRED) echo 3;; PROCEED_WITH_ADVISORY) echo 2;; PROCEED) echo 1;; *) echo 0;; esac; }
          if [ "$(rank "${P_ROUTES:-}")" -gt "$(rank "$route")" ]; then route="$P_ROUTES"; fi
```

### 4.4 Bash: new `emit` lines beside the existing ones

```bash
          emit rung_declared "${P_RUNG_DECLARED:-}"
          emit rung_effective "${P_RUNG_EFFECTIVE:-}"
          emit rung_divergence "${P_RUNG_DIVERGENCE:-}"
          emit policy_mode "${P_POLICY_MODE:-}"
          emit policy_resolution "${P_RESOLUTION:-}"
          emit effective_minimum "${P_EFFECTIVE_MINIMUM:-{}}"
          emit policy_divergences "${P_DIVERGENCES:-[]}"
          emit environment_tier "${P_TIER:-}"
          emit team_pattern "${P_TEAM:-}"
          emit unvalidated_human_workflow_paths "${P_UNVALIDATED:-}"
```

### 4.5 Step summary: the governance position, not only the result (ETFB section 10)

Append to the posture step's `$GITHUB_STEP_SUMMARY` block:

```bash
          {
            echo "### Enforcement policy (stage 1)"
            echo ""
            echo "| | |"; echo "|---|---|"
            echo "| resolution | \`${P_RESOLUTION:-}\` |"
            echo "| environment / tier / team | \`${P_ENVIRONMENT:-}\` / \`${P_TIER:-}\` / \`${P_TEAM:-}\` |"
            echo "| rung declared / effective | \`${P_RUNG_DECLARED:-}\` / \`${P_RUNG_EFFECTIVE:-}\`${P_RUNG_DIVERGENCE:+ (\`$P_RUNG_DIVERGENCE\`)} |"
            echo "| policy_mode (derived) | \`${P_POLICY_MODE:-}\` |"
            echo "| effective minimum per control | \`${P_EFFECTIVE_MINIMUM:-{}}\` |"
            echo "| divergences from the floor | \`${P_DIVERGENCES:-[]}\` |"
            [ -n "${P_UNVALIDATED:-}" ] && echo "| unvalidated human-workflow paths | \`${P_UNVALIDATED}\` -- reported, never passing |"
          } >> "$GITHUB_STEP_SUMMARY"
```

## 5 · The verdict step: exit on the folded route

Append as the LAST step of `security-gate`:

```yaml
      - name: Exit on the verdict
        id: verdict
        if: always()
        env:
          ROUTE: ${{ steps.posture.outputs.routing_result }}
          STOPS_ON_UNTRUSTED: ${{ steps.policy.outputs.policy_stops_on_evidence_untrusted }}
          RESOLUTION: ${{ steps.policy.outputs.policy_state }}
        run: |
          # THE GATE EXITS ON A VERDICT, NOT A JOB RESULT (SINGLE_PIPELINE_TARGET.md section 5.2).
          # BLOCKED stops at every tier. EVIDENCE_UNTRUSTED stops at production tiers -- and
          # always when the policy itself could not be resolved, because the rung is a
          # BLOCKED-floor control: a run with no readable rung is not a run at crawl.
          case "${ROUTE:-}" in
            BLOCKED) echo "::error title=BLOCKED::a control refused this run"; exit 1 ;;
            EVIDENCE_UNTRUSTED)
              if [ "${STOPS_ON_UNTRUSTED:-}" = "true" ] || [ "${RESOLUTION:-}" != "POLICY_RESOLVED" ]; then
                echo "::error title=EVIDENCE_UNTRUSTED::the result cannot be relied on, and this tier does not proceed on untrusted evidence"; exit 1
              fi
              echo "::warning title=EVIDENCE_UNTRUSTED::proceeding at a non-production tier; the result cannot be relied on" ;;
            "") echo "::error title=No verdict::the posture step emitted no routing_result"; exit 1 ;;
          esac
```

## 6 · Job outputs on `security-gate`

```yaml
      rung_declared: ${{ steps.posture.outputs.rung_declared }}
      rung_effective: ${{ steps.posture.outputs.rung_effective }}
      rung_divergence: ${{ steps.posture.outputs.rung_divergence }}
      policy_mode: ${{ steps.posture.outputs.policy_mode }}
      policy_resolution: ${{ steps.posture.outputs.policy_resolution }}
      effective_minimum: ${{ steps.posture.outputs.effective_minimum }}
      policy_divergences: ${{ steps.posture.outputs.policy_divergences }}
      environment_tier: ${{ steps.posture.outputs.environment_tier }}
      team_pattern: ${{ steps.posture.outputs.team_pattern }}
      unvalidated_human_workflow_paths: ${{ steps.posture.outputs.unvalidated_human_workflow_paths }}
```

And on the `workflow_call.outputs` block, the same ten names mapped from `jobs.security-gate.outputs`,
so a caller's deploy stage can read the rung beside `routing_result`.

## 7 · `tests/reconcile_validation.py`

```python
    # STAGE 1 RESOLUTION, NOT AN ASSURANCE CLAIM. Same reasoning as scan-report: it reads a
    # governance file and emits what it found; it establishes nothing about the code. Its proof
    # is tests/prove_gate_reads_rung.py (wiring) and tests/prove_policy_registration.py (reader).
    "action:resolve-policy": [],
```

## 8 · `self-test.yml`

In the step "Policy is resolved from the registered rung on the protected branch, never supplied",
add `python3 tests/prove_gate_reads_rung.py` as the last line. It passes only once sections 1-7 are
applied as written.

## 9 · What the proof asserts, item by item

`tests/prove_gate_reads_rung.py` checks: no `policy_mode` / `rung` input in any spelling;
`target_environment` declared and classified; `id: policy` before `id: gate`, using the composite;
the posture `env:` reads all fourteen `steps.policy.outputs.*`; the posture emits the nine `emit`
names and the job exposes them; the route folds `P_ROUTES` by `rank`; an `id: verdict` step exists;
the composite exists, runs `scripts/policy_registration.py --github-output` against `FETCH_HEAD`;
`action:resolve-policy` is registered; and, dynamically, the resolver emits every key the posture
step reads against a throwaway git repository holding the shipped example registration.

## 10 · Byte budget

`reusable-security.yml` grows by the input (section 2, ~0.6 KB), the policy step and checkout
(section 3, ~1 KB), the posture additions (section 4, ~3.5 KB), the verdict step (section 5, ~1 KB)
and the outputs (section 6, ~1 KB): about 7 KB against the 512,000-byte start limit, none of it in a
scanner job. Run `tests/check_workflow_size.py` after applying.

## 11 · Not in this patch, named

- Scanner jobs consuming the derived `policy_mode` instead of `inputs.advisory_mode` /
  `inputs.soft_fail_sast`: the `resolve` job (SINGLE_PIPELINE_TARGET.md section 5.1). Deferred,
  dated in the lane report.
- The per-finding use of the effective minimum (NEW critical/high versus PRE-EXISTING on a track)
  needs the cascade's output per finding in the gate, which the report job does not yet hand it
  (`scan_report.py` keeps only the composite identity; ledger L41/L52). Until then the effective
  minimum is emitted and recorded, and the existing job-level enforcement stands beneath it.
- Severity, fix availability and the SLA (c5df9de) have no runtime consumer until the ledger
  carries `effective_severity`, `fix_availability` and `sla_deadline` per entry; `propose_ledger.py`
  is where they would be written, under review. Deferred, dated in the lane report.
