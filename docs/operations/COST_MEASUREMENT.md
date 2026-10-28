# Cost measurement: the acceptance test for the cost redesign

```
Phase: plan + tool (lane L-COST, steps 1-3). Nothing in this document has been run yet.
Truth State: the tool's arithmetic is fixture-tested (scripts/measure_cost.py --self-test).
             No before/after run exists. Every saving in the proposal stays an ESTIMATE until this
             procedure has produced >= 5 before and >= 5 after runs per class.
Who runs it: the coordinator, after lane/cost-step1-3 is merged. Not the lane.
```

## What it decides

The redesign passes for a class only when **all four** hold:

1. **Billed minutes drop.** Median billed per run, after against before, from >= 5 runs each.
2. **Every invariant holds per scanner identity.** For each scanner (gitleaks, semgrep,
   codeql-python, checkov, ...), the same applicability, execution and gate state and the same SARIF
   result count, before and after, on the same fixture commit. A scanner present before and absent
   after is a difference, not a saving.
3. **The consumer path still holds 24/24** (`consumer-path-test.yml`, its expected-signal grade).
4. **The negative control still blocks** (`consumer-path-negative.yml`, `scope: full`, ends red at
   the gate on the seeded secrets).

**A green run is not a pass.** A cheaper run that establishes less is a regression.

## What "billed" means

GitHub's run `timing` endpoint returned 0 billable ms for every run measured on 2026-10-23, private
repositories included. So the tool **computes** billed minutes from measured job durations:

- per job: `max(1, ceil((completed_at - started_at) / 60))`, times the runner multiplier (Linux 1,
  Windows 2, macOS 10); a skipped job bills nothing and is excluded;
- per run: the sum over its jobs. Raw minutes are the unrounded sum; wall clock is the last
  `completed_at` minus the first `started_at`.

Every billed figure is labelled **"computed billed minutes from measured durations, not
invoice-reconciled"**. Only the latest attempt of a run is read; a run that is not `completed`, or
that left no `security-report-*` artifact, is excluded and named, and the tool exits 1.

## Classes and where they run

All on free public repositories. `<test-owner>` is the owner's test account.

| class | repository | workflow and input | fixture |
|---|---|---|---|
| small | `<test-owner>/hello-world` | its Security caller (from `templates/security.yml`), `workflow_dispatch` | the seeded Python + JS + Terraform + Dockerfile tree already there |
| monorepo | `<test-owner>/secure-cicd-kit-public` | `consumer-path-negative.yml`, `scope=full` | `tests/consumer-fixture/full/` (six languages + IaC) |
| iac-heavy | `<test-owner>/secure-cicd-kit-public` | `consumer-path-negative.yml`, `scope=iac` | `tests/consumer-fixture/iac-heavy/` (six Terraform modules, no code) |

The `scope=iac` leg is a small addition to `consumer-path-negative.yml` (lane L-COST). The fixture
reaches the public mirror through the export, like every committed fixture.

## Before and after, on the same fixture

- **before** = the kit at `fecc3a5` (`origin/fix/normalization-and-discovery` when the lane
  branched).
- **after** = the merge of `lane/cost-step1-3`.

The mirror is a history-less export, so its commit ids differ from the kit's. Prepare, on the
mirror:

- `cost/after`: the export of the merged lane.
- `cost/before`: the export of `fecc3a5` plus **one** commit adding only
  `tests/consumer-fixture/iac-heavy/**` and the `scope=iac` leg. That commit adds a fixture and a
  caller leg; it changes no kit code under test.

On `hello-world`, prepare `cost/before` and `cost/after` branches whose Security caller pins the
mirror's before and after commit respectively, and nothing else.

Then confirm the fixture bytes match across the pair before dispatching anything:

```bash
git diff --stat cost/before cost/after -- tests/consumer-fixture/   # must print nothing
```

## Commands

Dry run first. `dispatch` prints and writes nothing unless `--execute` is given.

```bash
M=cost-manifest.json
for phase in before after; do
  python3 scripts/measure_cost.py dispatch --class small --phase $phase \
      --repo <test-owner>/hello-world --workflow security.yml --ref cost/$phase \
      --runs 5 --manifest $M --execute
  python3 scripts/measure_cost.py dispatch --class monorepo --phase $phase \
      --repo <test-owner>/secure-cicd-kit-public --workflow consumer-path-negative.yml \
      --ref cost/$phase --field scope=full --runs 5 --manifest $M --execute
  python3 scripts/measure_cost.py dispatch --class iac-heavy --phase $phase \
      --repo <test-owner>/secure-cicd-kit-public --workflow consumer-path-negative.yml \
      --ref cost/$phase --field scope=iac --runs 5 --manifest $M --execute
done
python3 scripts/measure_cost.py compute --manifest $M --json cost-result.json
```

`dispatch --execute` waits for each run before starting the next (`--no-wait` disables it), so runs
do not compete for the runner pool and distort wall clock. If the workflow file on `hello-world` is
not `security.yml`, pass its actual name.

Then run the two remaining criteria at the after commit: `consumer-path-test.yml` (24/24) and
`consumer-path-negative.yml` with `scope=full` (must end red at the gate).

## How the numbers are combined

- **Medians** per (class, phase) of billed, raw minutes, wall clock and billed job count
  (`statistics.median`).
- **Savings** are printed only when the class has >= 5 usable before runs and >= 5 usable after
  runs. Otherwise the class prints `INSUFFICIENT_RUNS` and any quoted saving remains an estimate.
- **Invariants** are read from each run's `security-report-<attempt>` artifact: every
  `state-<scanner>.json` (applicability, execution, gate, SARIF name) and the result count of the
  SARIF it names. Per scanner, all before runs must agree with each other (else `UNSTABLE_BEFORE`),
  all after runs must agree (`UNSTABLE_AFTER`), and the two must be equal (`CHANGED`). A scanner
  missing from a phase is recorded as `ABSENT` and compared like any other value. Any difference
  exits 1.

## Reporting

Report each class as the proposal's reporting rule requires: commit SHA (before and after), the
medians, the computed-billed label, the coverage delta (per-scanner invariant differences, expected
to be none), and the negative-control and 24/24 results. Attach `cost-result.json`.

## What this does not establish

- Invoice-level cost. The figures are computed from durations; reconcile against the billing page
  separately if a number is to be quoted as money.
- Larger-runner or self-hosted cost. Every class runs on `ubuntu-latest`.
- A real monorepo. The six-language fixture is small, so its CodeQL legs are a floor.
