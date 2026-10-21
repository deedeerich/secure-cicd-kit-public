# Known gaps — what a green run of `reusable-security.yml` does NOT cover

Every item here is **stated, not fixed**. They are named because an annotated gap is honest and a
silent one is a lie, and because the only thing worse than a control that does not exist is a
control everybody believes exists.

**Each gap is reflected in a VERDICT, not only in this file.** A caveat printed underneath a row
that still says `CLEAN` is the same false statement with better manners. Where a scanner
establishes nothing, its row in the scan report reads `COVERAGE_GAP` or `NOT ESTABLISHED`, and the
gate reprints this list in the run summary on every run — green ones included.

Vocabulary is `assurance-taxonomy.yaml`. Nothing here coins a term.

---

## 1. Container image findings are produced and then discarded — CLOSED 2026-10-14

> **Closed** (L12). Both image SARIFs are redacted and retained as artifacts and published per
> category; the report row is APPLICABLE when an image is named and COLLECTION_FAILED when its
> report is missing. Proven by `tests/prove_image_scan_retains.py`. History below as written.
>
> **Remainder closed 2026-10-15.** Image SECRETS now have a report row of their own,
> `trivy-image-secret`, on the report's roster beside `trivy-image`: APPLICABLE when an image is
> named (established with its findings when `trivy-image-secret.sarif` arrived; NOT ESTABLISHED,
> machine output ABSENT, gate UNDETERMINED when it is missing), NOT_APPLICABLE when no image is
> named. The subject map answers IMAGE for it, so its findings can hold a durable identity. They
> still block through the gate's `secret_fail` in every mode. Proven by
> `tests/prove_image_secret_row.py`.

`image-scan` runs Trivy against `inputs.image_ref`, writes `trivy-image.sarif`, and the job ends.
There is no redaction step, no `upload-artifact`, and no `upload-sarif`. The findings exist for the
life of the runner and are then destroyed.

Until this was named, the report rendered a `trivy-image` row whose verdict came from the **job
conclusion** — so a successful scan that published nothing read as `PASS`. That is a clean verdict
sourced from a green job rather than from evidence, which is the substitution this kit exists to
refuse.

**Now:** when an image is named, the row reports `COVERAGE_GAP` and the job emits a warning saying
the findings were not retained. When no image is named it reports `NOT_APPLICABLE`, as before.

**To close it:** give `image-scan` the same four steps every other scanner job has — the generated
redaction step, an `upload-artifact` of `trivy-image.sarif`, an `upload-sarif` publication with
`category: trivy-image`, and a degraded-publication notice.

**Closed in the job (ledger L12):** `image-scan` now fetches the kit scripts and, for BOTH
`trivy-image.sarif` and `trivy-image-secret.sarif`, runs the generated redaction step, keeps the
file as an artifact (`sarif-trivy-image-<attempt>`, `sarif-trivy-image-secret-<attempt>`),
publishes it (`category: trivy-image` / `trivy-image-secret`) and states a degraded publication.
`tests/prove_image_scan_retains.py` checks the order and runs the job's redaction over a real
Trivy secret report. **Still open:** the consolidated report's `trivy-image` row still reports
`COVERAGE_GAP`; reading the retained artifacts there belongs to the report job, which is changed
separately.

## 2. ESLint is unreachable on a Node-only repository — CLOSED 2026-10-14

> **Closed.** The job now starts on `python == 'true' || node == 'true'`, and each toolchain's
> steps key on its own discovery flag. The same change made lint findings able to fail the job
> with `enforce_lint` on, which they could not before: the Ruff step exited with mypy's status,
> and the ESLint fallback read findings as "not configured". Proven by
> `tests/prove_code_quality_enforces.py`. The `eslint` report row is now applicable wherever Node
> is discovered and, like ruff, NOT ESTABLISHED for want of SARIF (section 3). The history below
> is kept as written.

An axis collision. The `code-quality` job gates on **discovered** Python
(`needs.discover.outputs.python == 'true'`); its ESLint steps gate on **declared** language
(`inputs.language == 'node'`). On a repository that is only Node, the job never starts, so ESLint
never runs — and there was no row at all, which reads as nothing to report.

**Now:** `eslint` has its own row. Where Node was discovered it reports `COVERAGE_GAP`: the code is
present, a control is owed, nothing looked.

**To close it:** put both on the same axis — gate the job on `python == 'true' || node == 'true'`
and gate each toolchain's steps on its own discovery flag. One line each. It is deferred only
because it changes which jobs start, and the immediate objective was a workflow that starts at all.

## 3. Five scanners emit no machine-readable result — `NOT ESTABLISHED`

`detect-secrets`, `ruff`/`mypy` (as `code-quality`), the `dotnet list package --vulnerable` audit,
`eslint` and `sbom` write no SARIF. Their output is visible in the job log and nowhere else:
nothing downstream can read it, correlate it, disposition it or gate on it.

Four of these previously had **no row of their own** and were carried by a neighbour's verdict —
detect-secrets by gitleaks, the NuGet audit by Semgrep-C#, ESLint by ruff. Each now has its own row
reading `NOT ESTABLISHED`.

## 4. The CodeQL matrix starts six legs and uses one — waste, not a coverage gap

`strategy.matrix.include` carries six languages gated at **step** level (`if: matrix.gate ==
'true'`). Matrix gating happens before the steps, so all six legs spawn whenever any language is
discovered; five boot a runner, download the script bundle, and skip everything.

Coverage is unaffected — the legs that skip would have found nothing anyway — so this is a cost
defect, not an assurance one. GitHub documents the fix (build the matrix from a preceding job's
output with `fromJSON`, verified against
<https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations>),
and `discover` would need to emit the language array.

**Deliberately deferred.** A malformed or empty matrix expression fails the `codeql` job at
run time, and the immediate objective is a first dispatch that starts and completes. Runner waste
on a proving run is cheaper than a matrix error on it.

**Coverage is no longer collapsed, though.** The six legs are separate jobs at run time and each
writes `codeql-results/<language>.sarif`, so the report now carries six per-language verdicts
instead of one aggregate `codeql: PASS` that spoke for all of them.

## 5. No build provenance is issued — `ABSENT`

The kit stamps its own version metadata. It issues **no signed attestation**: there is no
`actions/attest-build-provenance`, no `attestations: write` permission, no in-toto statement and no
SLSA provenance anywhere in this repository. Nothing produced here proves what built an artifact,
from which commit, on which runner.

A separate design effort owns this. It is recorded here so that "the kit does CI/CD with
provenance" is not read off the presence of version stamping.

## 6. The NVD workflow blocks nothing at its shipped defaults — by design, now stated

`reusable-nvd-cve.yml` ships `fail_on_cvss: 11` (CVSS maxes at 10, so no score can reach it) and
`trivy_fail_severities: ""` (no severity named). Both are deliberate: a reusable workflow must not
silently start failing other people's builds.

The posture record has always enumerated these as `GATE_SOFTENED` / `WEAKENING_IN_FORCE`. That is
precise and easy to read past, so the run summary now opens with an explicit
**"THIS RUN BLOCKED NOTHING, BY CONFIGURATION"** declaration naming both values and how to change
them, and the posture table restates it in words.

**Changing the defaults is an interface version with migration guidance, and was deliberately not
done here** — mixing a behavioural break into a restoration commit is how a repair becomes an
outage.

**Still open:** the posture record travels as workflow *outputs* and step-summary text. It is not
written into the `nvd-scan-results` evidence artifact, so a consumer reading the artifact alone
does not get it.

## 7. `soft_fail_sast` defaulted to `true` (CLOSED by KDEC-008 OD-7)

Until KDEC-008 OD-7 the flagship shipped `soft_fail_sast: true` and `language: python`, so a caller
who changed nothing got un-enforced SAST, a Python-only selector, and DECISION_REQUIRED on a clean
run. The shipped defaults are now the baseline: `soft_fail_sast: false` and `language: auto`.
`tests/prove_gate_routing.py` reads the defaults from the workflow and proves a caller who changes
nothing gets `PROCEED` on a clean gate and `BLOCKED` on enforced findings.

**This is a behavioural change for existing callers that relied on the old defaults:** SAST findings
now block. A caller that wants the old behaviour sets `soft_fail_sast: true`, which is recorded as a
`GATE_SOFTENED` weakening and should be attributed with `weakening_reason` and
`weakening_authority`.

## 8. What no static check in this repository can establish

- **Detection.** Every green row says a scanner RAN. None says it would have found anything. Only a
  run against seeded defects establishes that, and `tests/verify_expected_signals.py` needs a live
  run to do it.
- **Enforcement.** That a real finding actually blocked a real promotion.
- **Startup.** Under the size limit, parsing, and linting clean are three facts. **Starting is a
  fourth**, and only a dispatch settles it.

## 9. Properties the kit does not claim

Recorded because their absence has been mistaken for their presence:

- **Not modular.** Capabilities are not independently selectable; the unit of adoption is the whole
  workflow.
- **Not flexible.** Scanner choice, ordering and severity mapping are fixed by the kit.
- **Not budget-aware.** There is no runner-minute accounting, no cost ceiling, and no per-job
  budget. `timeout-minutes` bounds a stall; it does not bound spend.
