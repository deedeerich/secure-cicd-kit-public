# The single pipeline — consolidated target architecture

**The kit stops being a security add-on and becomes the whole pipeline. This is what that has to
mean, stage by stage, and the two coupling mechanisms it must refuse in order to mean it.**

```
Phase: design — a written contract, not an implementation
Truth State: modelled 2026-09-24 from the owner's consolidation decision, against the
             workflows as they stand in secure-cicd-kit, the read-only reference estate
             in the reference estate service repository and the reference estate infrastructure repository, the nine
             architecture documents this one consolidates, and the registered vocabulary
             in secure-cicd-kit/assurance-taxonomy.yaml (v1)
Audience: whoever builds the consolidated pipeline, and whoever has to explain in six
             months why a repository was allowed to delete a workflow
Decision Supported: whether the post-scan phase lives in the scan's run or a second one;
             what each of the fifteen stages owes; what a migration must prove before a
             workflow is deleted; what one kit serving four repositories may and may not
             let a repository override
Deferred Depth: every document in this directory. This one is the join, not a
             replacement for any of them
```

> **Nothing described here is built.** Not the consolidated run graph, not the post-scan
> phase, not the retirement register, not the verdict output, not the deployment gate that
> reads it. No workflow, script or test was changed to write this document, and one of them is
> being repaired by somebody else while it is written. The kit's own rule applies to this file
> first: **registering a term is not implementing it, and writing it down does not make it
> so.**
>
> **No vocabulary is coined here.** Every enforcement word below is already registered in
> `assurance-taxonomy.yaml`. Where this design needed a word the registry did not have, the
> concept is written in lower case so that `scripts/reconcile_taxonomy.py` does not read a
> proposal as an adopted term — that checker matches the literal token, not the intent, and
> spelling a candidate in capitals would register it by making the gate green.
>
> **Every claim about an external platform is cited to primary documentation or marked
> UNVERIFIED.** A confident guess about a platform behaviour is how an architecture acquires a
> defect it cannot see.

---

## 0 · What this settles, and what it deliberately does not

**Settled here:** whether the post-scan phase can share a run with the scan, and exactly what
crosses the boundary where it cannot; why the two mechanisms the reference estate uses to
couple its pipeline are refused, stated so that neither is re-proposed; what each of the
fifteen stages has today in the kit and in the reference estate, what its target is, and what
closing the gap takes; the shape of the run graph and which stages each trigger context arms;
how deployment becomes a stage of the pipeline rather than a workflow beside it; how provenance
is designed around a plan restriction the owner cannot lift; how the governance the kit already
leads on extends past scanning to ticketing and deployment; the mechanism that makes a
migration prove coverage equivalence before a workflow is deleted; and what one kit serving
four repositories may configure per repository versus what must never be overridable.

**Not settled here, and named in §10:** whether a full merge-depth re-scan on every merge is
affordable at estate scale; how a reviewed ledger on a protected branch behaves at estate size;
whether `$/` resolves as intended for a reusable workflow invoked cross-repository; whether a
ticket backend exists to target; whether the reference estate's out-of-repository reusable
workflows do what their inputs imply; how a registration-driven kit serves many products and
environments given that GitHub Actions has no dynamic secret resolution; and every number.

**Deliberately out of scope:** the scanner coverage delta between the kit and the reference
estate. That is another piece of work, and §7 specifies the gate that consumes it rather than
the census that produces it.

---

## 1 · What the decision changes

The kit was built as a security-scanning reusable workflow that a repository calls alongside
whatever else it runs. The owner's decision is that it becomes the pipeline: policy, discovery,
scanning, adjudication, ticketing, deployment, verification and the governance record around
all of them, for every repository, replacing what is local to the reference estate.

Three consequences follow immediately and none of them are optional.

**The kit acquires stages it has never had.** There is no post-scan phase in the kit at all —
no deduplication, no correlation, no baseline, no ticketing, no ingest. Today
`reusable-security.yml` runs a bootstrap job, a `discover` job, fourteen scanner jobs, a
`report` job and a `security-gate` job that reads job results, and then the run ends.
Everything the reference estate does after a scan, the kit does not do. That is the largest
architectural hole in this document and it is stage 13.

**Deployment stops being a workflow beside the pipeline and becomes a stage inside it.** The
kit ships `reusable-deploy-appservice.yml` and `reusable-deploy-containerapp.yml`, and
`ROLLBACK_CONTRACT.md` holds both at `requires-integration-environment` pending a rollback
contract neither satisfies. The shipped caller template wires deployment behind
`workflow_dispatch` only, with the comment *"push builds, but push does NOT deploy."* A
pipeline whose deployment stage is dispatch-only and ungated by a scan verdict is not a
pipeline; it is two pipelines with a human in the seam.

**The kit becomes the only place a control can be weakened, which raises the cost of getting
governance wrong.** Today a repository that disagrees with the kit keeps its own workflow. After
consolidation it cannot, so every legitimate difference has to be expressible as registered
configuration — and every illegitimate one has to be refused in a way that says why. §8 is that
boundary.

---

## 2 · The question this document exists to answer

> **Can the post-scan phase live inside the same run as the scan, or does it genuinely need a
> second trigger?**

### 2.1 Why it decides the shape

Every other decision hangs off this one. If the post-scan phase needs a second run, then
something has to carry the scan's output across a run boundary, and the only general mechanism
GitHub offers for that is an artifact hand-off — the mechanism that failed at every site
simultaneously and silently in the reference estate (§3.1). If it does not, then the evidence
never leaves the run that produced it and the failure mode does not exist.

### 2.2 The two facts, stated fairly

**Fact one, for the same run.** A same-run phase keeps every piece of evidence inside the
workspace that produced it. No artifact is uploaded for a consumer, no consumer has to name a
producing run, and no download can silently return zero bytes. It also costs less: a second run
pays a fresh runner boot, a fresh checkout and a fresh minute rounding for every consumer, and
the reference estate pays that four times over (§9.2).

**Fact two, against the same run.** Ticket writes want credentials a pull-request run must
never hold, and the ticketing contract already places ticketing post-merge and outside the
pull-request run for exactly that reason. `TICKETING_CONTRACT.md` §7.1 gives two reasons and
says the second is the stronger: *"Ticketing does not belong in a pull-request run at all, and
this was already decided."* It cites `ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` §9.2 —
*"Correlation and ticketing happen outside the PR run. Both need the ledger and the ticket
system; the PR run must not write to either. A PR run consumes cluster identity; it does not
create it."* — and §5.4, where ledger updates *"are produced by the post-merge or nightly run
and merged to the protected branch under CODEOWNERS. A PR run may only read."*

### 2.3 Do they conflict? No — and the reason is that they are about different things

They look like they conflict because "the run" is being used for two different objects.

Fact one is about **a run boundary**: does data have to cross from one workflow run into
another. Fact two is about **a trigger context**: may a run started by a pull request hold a
write credential. Those are orthogonal axes, and the apparent contradiction dissolves the
moment they are separated:

```
                        | pull-request context | protected-branch context
 -----------------------+----------------------+-------------------------
 scanning               | armed                | armed
 adjudication, gating   | armed                | armed
 ledger write           | refused              | armed
 ticket reconciliation  | refused              | armed
 deployment             | refused              | armed, environment-gated
```

Nothing in that table requires data to cross a run boundary. It requires **stages to be armed
by context**, which is a condition inside one run, not a second run.

### 2.4 The answer

> **The post-scan phase lives inside the same run as the scan, in every trigger context. There
> is no second trigger for the post-scan phase. What differs between contexts is which
> post-scan stages are armed — and the stages that write to a governance surface are armed only
> in a run whose ref is the protected default branch.**

Concretely, the kit runs the same stage graph three ways:

| context | trigger | `scan_depth` | armed through | refused |
|---|---|---|---|---|
| pull request | `pull_request` | `pr` | stage 12, gating. Ledger and tracker **read only** | ledger write, ticket write, deploy |
| post-merge | `push` to the protected default branch | `merge` | stage 15, everything | nothing structural; deployment is still environment-gated |
| revalidation | `schedule`, plus `workflow_dispatch` | `nightly` or `revalidate` | stages 13 and 14; stage 6 scoped to the deployed artefact and its SBOM | source scanning, which is not what changed |

The second row is the one that matters. The post-merge run is **not a continuation of the
pull-request run**. It is a complete, independent execution of the whole pipeline, at a
different `scan_depth`, on a different ref, deriving everything it needs from that ref. It
re-scans; it does not collect.

**The re-scan is not redundant work.** `AXES_AND_PHASES.md` already specifies that merge depth
differs from pull-request depth — `security-extended` rather than `default`, full tree rather
than diff, whole repository rather than changed paths, blocking rather than advisory. The
merge-depth scan was always going to happen. The post-scan phase attaches to a scan that was
already required, and pays for nothing new except its own adjudication.

### 2.5 What crosses the boundary, exactly

Between the pull-request run and the post-merge run, this and only this crosses:

| crosses | mechanism | why it is not a hand-off |
|---|---|---|
| the merge commit identity | the `push` event payload, as `github.sha` | supplied by the platform to the run that is starting. Not produced by the earlier run, and not fetched from it |
| the source tree at that commit | `actions/checkout` | the run reads the repository. The earlier run is not a party to this |
| the baseline ledger | a file in that same checkout, on the protected default branch | a governance artefact committed under CODEOWNERS, not a run output |
| the rule-family alias table | same | same |
| merged dispositions | same | same |
| the registered rung, cherry-picks and profile for the (repo, environment) cell | same | same |
| **nothing else** | — | — |

In particular: **no SARIF crosses, no normalised finding set crosses, no cluster map crosses, no
gate verdict crosses, and no run identifier crosses.** The post-merge run does not know the
pull-request run existed and does not need to.

The reverse direction is the same shape. A pull-request run reads the ledger, the alias table,
the dispositions and the rung **from the protected default branch**, which
`ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` §5.4 already requires for an independent reason:
*"Read from the protected default branch, never from the PR under evaluation… A baseline read
from the PR head is not a weaker baseline; it is a self-signed certificate."* That read is a git
operation inside the run's own checkout — a fetch of the default branch, and the merge base for
grandfathering per §5.4. It is not an artifact download.

### 2.6 Why this is not the reference estate defect wearing a different hat

The objection deserves a direct answer, because "we also have two runs" is superficially the
same sentence.

**The reference estate's pattern has a data dependency across a run boundary. This one has
none.** That is the whole difference, and every other difference follows from it.

| | reference estate | this design |
|---|---|---|
| what the second run needs from the first | its uploaded artifacts | nothing |
| how it obtains it | `actions/download-artifact`, which must be told which run | `actions/checkout`, which is told a ref |
| what it must name correctly | the producing run's id, plus a token, plus `actions: read` | a ref, which the event supplies |
| what happens when that is wrong | zero bytes, and the consumer proceeds | the checkout fails and the job fails |
| what happens when the input is absent | an empty directory, which every downstream reader treats as zero findings | a missing ledger is a typed state — `NOT_ESTABLISHED` for the cell, never an empty set |
| failure visibility | silent, and further silenced by `continue-on-error: true` | loud, because a failed checkout is a failed job |

Three properties make the distinction structural rather than a promise to be careful.

**The correctness of a checkout does not depend on naming another run.** `actions/checkout`
takes a ref, and the run that is executing was started *by* that ref. There is no identifier to
get wrong, so there is no wrong-run failure mode to hide. The reference estate's defect is not
that it used two runs; it is that the cross-run fetch has a required parameter with a
plausible-looking default. `actions/download-artifact` documents that default explicitly: *"If
unspecified, the action will download artifacts from the current repo and the current workflow
run"*, `run-id` is *"Optional. Default is `${{ github.run_id }}`"*, and `github-token` is
*"required when downloading artifacts from a different repository or from a different workflow
run"* ([actions/download-artifact](https://github.com/actions/download-artifact)). A default
that is wrong for the only reason anyone reaches for the feature is the known hard part of the
pattern, and it failed at four sites at once.

**An absent input is a typed state, never an empty set.** This is the rule the reference
estate's post-scan chain breaks in the most expensive possible way:
`deduplicate-vulnerabilities.yml` processes an empty tree and then *publishes* a structurally
valid report asserting zero vulnerabilities, which the next consumer in the chain is designed to
read. A manufactured authoritative zero is worse than a crash. In this design, absence of a
ledger is `NOT_ESTABLISHED` and absence of coverage is `COVERAGE_GAP` — both registered, both
routing away from `PROCEED`, and neither reachable by a reader that merely found no files.

**The second run is not downstream of the first.** It is downstream of a **merge**, which is a
governed act performed by a human with write access to a protected branch.
`TICKETING_CONTRACT.md` §7.2 rejects the alternative in one line, and it is the reference
estate's pattern by name: *"a run chained off a pull-request workflow's completion… executes
privileged logic on the default branch in response to something a fork caused. Cheaper to not
have the pattern than to reason about it every time the bridge is edited."*

### 2.7 What a pull-request run can compute without writing anything

The design only works if a pull-request run can reach a correct verdict without creating any of
the governance state it is forbidden to create. It can, and the reason is worth stating because
it is not obvious.

- **Baseline matching is a read.** The three fingerprint components are computed from the
  observations and the tree; the ledger is read from the protected branch; the cascade in
  `ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` §5.3 is a pure function of the two. Nothing is
  written.
- **Anchored correlation is deterministic.** Clustering on a shared external identifier plus
  matching package coordinates depends only on the observations and the alias table, both of
  which the run already holds. §9.4 calls this tier `anchored` and clusters it automatically.
- **Proposed correlation is computed and not acted on.** §9.4 is explicit that the heuristic
  tier is *"proposed only. Not applied to enforcement."* A pull-request run may render it for a
  human and must not gate on it, which is exactly what "consumes cluster identity, does not
  create it" means in practice.
- **Enforcement counts clusters, and the clusters it counts are the anchored ones.** §9.2:
  *"Enforcement counts clusters, not observations."*

What the pull-request run cannot do is **persist** any of that. It recomputes it every run,
which is affordable because it is arithmetic over the run's own output, and which has the
additional property that a pull-request verdict is reproducible from its inputs by anyone who
can read the branch.

### 2.8 The residual, named

**A finding introduced in a pull request gets its ticket after the merge, not on the pull
request.** `TICKETING_CONTRACT.md` §7.2 states this as a deliberate consequence: the pull
request gets the finding, the routing and the summary; what it does not get is a write to a
governance surface. This design inherits that, unchanged, and it is a real cost — an author who
wants a tracking item before merging has to open one by hand.

**The pull-request verdict and the post-merge verdict can differ, legitimately.** Different
depth, different scope, and a merge that combined two branches. A design that hid that would be
lying; the reporting stage names which context produced a verdict, and the two are never
presented as one number.

---

## 3 · What the kit refuses, with the reason stated so nobody re-proposes it

Two mechanisms are refused. Both are load-bearing in the reference estate today. Both are
recorded here with evidence rather than preference, because a refusal without a reason gets
overturned by the next person who finds the pattern convenient.

### 3.1 Refused: `workflow_run` artifact hand-off as the coupling mechanism

**The finding.** Four post-scan consumers in `reference estate service repo, workflow `
are triggered by `workflow_run` and every one of them calls `actions/download-artifact@v4` with
**no `run-id`**, **no `github-token`**, and **no `actions: read` permission**:

- `create-issues-from-scans.yml`
- `deduplicate-vulnerabilities.yml`
- `ingest-scan-results.yml` (two such steps)
- `ingest-scan-results-to-dashboard.yml`

Each block has the same shape, and `continue-on-error: true` sits on the download step itself:

```yaml
      - name: Download scan artifacts
        uses: actions/download-artifact@v4
        with:
          path: scan-results
          pattern: '*-scan-results'
          merge-multiple: true
        continue-on-error: true
```

Without `run-id` the action scopes to `github.run_id` — the consumer's own run, which has
uploaded nothing. **The entire post-scan pipeline processes zero bytes and reports green.**

**Why this is the known hard part of the pattern and not a local slip.** It failed at four sites
at once, in two repositories, written by people who had diagnosed the trigger wiring and
believed they had fixed the data flow: `WORKFLOW_DEPENDENCIES.md` records *"Some workflows use
workflow_run but don't specify which workflows"* and prescribes naming the upstream workflows,
which was done. Naming the upstream workflow is not fetching its artifacts, and that document
never mentions `run-id`, a token, or `actions: read`. One consumer,
`update-roadmap-from-scans.yml`, documents the failure in its own step output — *"Note: Artifact
download from workflow_run context has limited access"* — and routes around it rather than
repairing it, then runs against a directory nothing populates. A defect that four independent
implementations reproduce, and that one of them documents without fixing, is a property of the
mechanism rather than of the authors.

**The mechanism has a second, quieter cost.** `workflow_run` fans out. That same file carries a
`sleep 30` with the comment *"This prevents 50+ queued workflows when multiple scans complete at
once"* — the fan-out was observed in production and mitigated with a sleep.

**Partial repair is evidence for the refusal, not against it.**
`reference estate infra repo, workflow create-issues-from-scans.yml` does the cross-run
fetch correctly, with a run id and with `actions: read` — and then **falls back** to the same
defective `actions/download-artifact` block with `continue-on-error: true`. A pattern whose
correct form is routinely shipped alongside its incorrect form as a fallback has not been made
safe by knowing about it.

**The refusal.** The kit does not couple pipeline stages by uploading an artifact in one run and
downloading it in another. Where two runs are genuinely involved, the later run derives its
inputs from the repository at a ref, not from the earlier run. This does not ban artifacts —
they remain correct for publication, retention and human retrieval — it bans them as the
**coupling** between stages.

**One narrow exception, already shipped and deliberately different.** `reusable-security.yml`
has a `kit-scripts` bootstrap job that publishes the canonical scripts as an artifact every
other job fetches. That is an **intra-run** artifact: same run, default run id correct by
construction, and the gate reads `needs.kit-scripts.result` explicitly so a bootstrap failure
cannot present as `NOT_APPLICABLE`. The exception is that the default is right, which is exactly
the property the cross-run case lacks.

### 3.2 Refused: the orchestrator pattern

**The finding.** `reference estate service repo, workflow 00-orchestrator.yml` declares
nine jobs. **Two do real work** — `detect-changes`, and `phase-2-code-quality`, the only job
that calls anything. The other seven are `echo` statements, each carrying a comment of the form
*"is not reusable, so we skip this phase in orchestrator"*.

Eight job-level `if:` clauses contain **fourteen** `always() || …` terms. One clause carries
five:

```yaml
    if: |
      needs.detect-changes.outputs.run-build == 'true' &&
      (always() || needs.phase-2-code-quality.result == 'success' || ...) &&
      (always() || needs.phase-2-security.result == 'success' || ...) &&
      ...
```

`always()` short-circuits the disjunction to true, so every dependency-result term is inert and
the condition reduces to the `detect-changes` flag. Worse, **an `if:` containing a status
function disables the default skip-on-failed-`needs` behaviour**, so `phase-5-deploy` executes
after total upstream failure. The declared purpose — *"Proper dependency chain… Failures cascade
correctly"* — is defeated by the conditions written to express it.

`detect-changes` additionally reads `${{ steps.detect.outputs.* }}` inside the step that
produces those outputs, so they interpolate as empty strings and most derived flags come out
false on every run.

And the migration plan named four of these `echo` jobs as required status checks for branch
protection. Whether that was applied is UNVERIFIED — branch protection state is not on disk —
but the intent to make `echo` a required check is on disk.

**The refusal, and it is broader than one file.** The kit does not model stage ordering as a
parent workflow whose jobs announce other workflows. Ordering is expressed as `needs:` between
jobs **in one run**, where a failed dependency skips its dependants by default and no condition
has to be written to make that happen. The general rule both refusals share:

> **A dependency that has to be described is a dependency that can be described wrongly. Prefer
> the coupling whose correct behaviour is the platform's default.**

`needs:` is correct when you write nothing. `actions/download-artifact` across runs is wrong
when you write nothing. `always() || X` is a condition whose author believed it meant "X, and
also run anyway", and it means neither.

### 3.3 What is kept from the reference estate

Refusing two mechanisms is not refusing the work. Four things in the reference estate are ahead
of the kit and are absorbed rather than discarded:

- **Richer build inputs.** `gov-prod-deploy-<service>-api.yml` records a lockfile hash and an SBOM
  hash alongside the image digest. The kit records neither.
  `PROVENANCE_AND_ATTESTATION.md` §3 lists this as link 3 of the chain, present in the reference
  estate and absent in the kit.
- **Build gated on security jobs.** `needs: [codeql, semgrep]`, with the header comment *"All
  security lanes are REQUIRED (no soft fails)"*.
- **Plan, then artifact, then apply, with both halves environment-bound.**
  The reference estate's production deploy workflow binds both its plan and its apply job to `environment: gov-prod`, and
  the apply additionally requires `workflow_dispatch` plus a typed break-glass string. That is
  the break-glass model this design adopts (§6.2).
- **A real image gate.** `build-push-a reference estate service.yml` runs `trivy image --exit-code 1 --severity
  HIGH,CRITICAL` with no `continue-on-error`, before the push. It is the strongest gate in the
  reference estate. Its caveat, `--ignore-unfixed`, is a policy choice the kit must make
  explicitly rather than inherit silently.

---

## 4 · The fifteen stages — what exists, what the target is, what it takes

`kit` and `the reference estate` describe what is **implemented on a path something actually runs**. `probe`
means implemented but reachable only from a self-test. A dash means absent.

| # | stage | kit today | the reference estate today | target | what it takes |
|---|---|---|---|---|---|
| 1 | policy resolution | — | — | the registered rung for the (repo, environment) cell, cherry-picks, `environment_tier`, `team_pattern` and the derived `policy_mode`, all read from the protected default branch | a registration file per repository under CODEOWNERS; a derivation table from rung to `policy_mode`; a check that fails a run in which `policy_mode` was supplied rather than computed |
| 2 | discovery | **has** — the `discover` job, seven presence probes plus an unsupported-language sweep plus a platform probe | — | unchanged in substance; gains a written design and emits `discovery_state` per class rather than booleans | write the design that was never written; project probe results into `ARTIFACT_PRESENT`, `UNDETERMINED_PRESENT`, `DISCOVERY_PARTIAL`, `NOT_APPLICABLE` |
| 3 | version discovery | — | — | for each discovered class, the language or runtime version the code is written for, with its detection strength | the probe set in `PIPELINE_ORDERING_AND_SCAN_VALIDITY.md` §2.2; `VERSION_DISCOVERED` versus `VERSION_UNKNOWN` |
| 4 | capability selection | partial — per-job `if:` on discover outputs selects tools by presence | — | for each (class, version), whether a configured tool can read it, declared **before** the scan | the capability table in §2.4 of that document; `SCANNER_SUPPORTS`, `VERSION_UNSUPPORTED`, `VERSION_SUPPORT_UNDETERMINED`; `ARTIFACT_PRESENT` plus `CAPABILITY_REQUIRED` plus an incapable tool resolves to `COVERAGE_GAP` |
| 5 | execution planning | — | — | the concrete job set, depth and ordering for this run, emitted as data a human can read before anything runs | **the one stage with neither a design nor a build.** It needs the profile-by-depth model from `AXES_AND_PHASES.md` and the grouped topology from `JOB_TOPOLOGY_AND_BUDGET.md` §4 joined into one plan object |
| 6 | scanning | **has** — fourteen scanner jobs | **has** — roughly thirty workflows | unchanged in substance; grouped per `JOB_TOPOLOGY_AND_BUDGET.md` §4, with the CodeQL matrix defect fixed first | the matrix fix is available on its own and is the majority of the saving on a single-language repository |
| 7 | evidence validity | partial — file non-empty plus one `jq` expression | — | did each report come from a tool that read something; a zero-finding, zero-artefact SARIF is `PARTIAL`, never clean | the validity profile in §4.4 of the ordering document. This is the weakest link in what the kit already ships |
| 8 | normalization | **has** — `normalize_sarif.py`, the merge and reroot scripts, `redact_sarif.py` before every publication | — | unchanged in substance; gains a written design and an explicit ordering guarantee that redaction precedes publication | write the design; keep the ordering, which is already correct and is the whole control |
| 9 | baseline and classification | **partial, and wrongly** — `scan_report.py` computes a fingerprint over scanner, rule id, path and message. No ledger, no `first_seen`, no cross-run persistence | — | the three-component fingerprint, the matching cascade, `first_seen` on the protected branch, `finding_classification` per finding | the existing fingerprint contains **two of the components §5.2 forbids** — the scanner name and the rule id — so a scanner upgrade resets it. It has to be replaced, not extended. Then the ledger, the alias table, the cascade, and the forced-failure demonstration required for `run` |
| 10 | severity and disposition | **partial** — `scan_report.py` derives severity from the SARIF security-severity property, falling back to level, and suppresses on an approved, unexpired disposition with an exactly-registered `DISPOSITION_TYPE` | — | organisation-derived severity preserving every scanner's number; dispositions consumed from the **protected branch** only; fix availability as its own axis | the disposition file is read from a caller-supplied path and is not schema-validated at runtime; the protected-branch rule is not enforced. Add the SLA clock and the fix-availability axis |
| 11 | correlation | **a count, not a cluster** — one line reporting how many findings more than one tool reported | **has**, four times over, mutually inconsistent | observations preserved forever; a cluster layer above them; one cluster is one obligation is at most one ticket; `OBSERVED_CORROBORATED` with every contributing scanner named | the anchored / proposed / singleton tiers, and the rule that only anchored acts. The existing count is the right instinct and carries no cluster key |
| 12 | gating | **partial** — `security-gate` reads job results and projects them into `PASS`, `NOT_APPLICABLE`, `UNAVAILABLE`; no tier, no rung, and **no routing result**, which the kit's three other reusable workflows already emit | partial — real gates on three of seven deploy paths, absent on four | the rung's per-control floor, the precedence maximum across controls, and a **verdict emitted as a job output** | the rung ladder; and giving the security workflow the output contract the other three already have (§5.2) |
| 13 | ticket reconciliation | — | **has, and it is the only stage running in production anywhere** | the idempotency cascade, the umbrella sweep, the delta-only write path, in a protected-branch run with an environment-gated credential | everything in `TICKETING_CONTRACT.md`. This is the largest hole |
| 14 | reporting | **has** — the `report` job | partial | unchanged in substance; gains the six questions an outcome report must answer and the context label on every verdict | write the design; add the context label |
| 15 | deployment and verification | probe — two deploy workflows held at `requires-integration-environment`; the shipped template never passes provenance | **has** — seven deploy paths, one digest-bound, none with rollback | deployment as a stage, gated on the stage-12 verdict, digest-bound, environment-bound, break-glass, health-checked, reconciled against live state, reversible under the rollback contract | gate 1 and gate 2 of `ROLLBACK_CONTRACT.md`, plus the release object |

### 4.1 Two defaults the consolidation must decide rather than inherit

Two of the kit's own inputs currently default to not blocking, and after consolidation those
defaults become estate policy by accident unless somebody chooses them on purpose.

- **`soft_fail_sast` defaults to true** in `reusable-security.yml`. Every consumer that does not
  set it gets advisory SAST.
- **`fail_on_cvss` defaults to 11** in `reusable-nvd-cve.yml`, and the maximum CVSS score is 10.
  The default therefore never blocks, and the `trivy_fail_severities` default is empty.

Neither is wrong as a shipping default for an opt-in add-on — an add-on that blocks on first
install gets uninstalled. Both are wrong as the default for the only pipeline in the estate, and
the registered invariant is already pointed at exactly this:
`defaults_are_suspicious_at_assurance_boundaries`. The rung is the right place to settle them,
because under §8.3 the rung derives what blocks and a caller cannot pass one.

### 4.2 One stage produces no evidence at all, and is counted anyway

`image-scan` runs Trivy and then **nothing**: no redaction step, no artifact upload, no SARIF
publish, no result summary. Its output does not survive the job. Meanwhile `trivy-image` is on
the roster the `report` job expects, so the run's own accounting records a missing result for a
scanner that ran successfully.

That is stage 6 succeeding and stage 7 having nothing to validate, and it is the cleanest
available illustration of why the two stages must be distinct: a scanner that exits zero and
publishes nothing is indistinguishable, in a job-result-based gate, from a scanner that found
nothing. `publication_state` already has the vocabulary for it, and nothing emits it.

### 4.3 The four that run without a design, and why that is its own risk

Discovery, scanning, normalization and reporting are the four stages that actually execute, and
none of them has a design document. That is not a documentation gap; it is an **unfalsifiability
gap**. A stage with a design can be wrong against it. A stage without one can only be wrong
against somebody's memory, and the kit has already shipped the consequence: `code-quality` runs
ESLint behind a Python gate, so a pure-JavaScript repository gets no ESLint at all, and the
defect is invisible because no document says what that job is for.

The consolidation makes this worse before it makes it better, because these four are the stages
every other stage now depends on. Stage 9 cannot compute an identity from a normalization
nobody specified.

### 4.4 The one with neither

**Stage 5, execution planning, has no design and no build.** It is also the stage that makes
stages 2, 3 and 4 useful: version discovery and capability selection produce answers, and
without a planning stage there is nowhere to put them. `PIPELINE_ORDERING_AND_SCAN_VALIDITY.md`
§1.6 records the structural version of this — *"R2, R3 and R6 have nowhere to attach, because
there is no position between `discover` and the scanners and no position between the scanners
and the gate"* — and the answer is that the positions have to be created before the checks can
be put in them.

### 4.5 Stage 13 runs in production against a design that assumes a different world

`create-issues-from-scans.yml` is the only one of the fifteen stages executing in production
anywhere in the estate, and four facts about it matter more than its existence:

- **It has no idempotency check.** There is no lookup of existing issues before creation. Issue
  identity is the title string, and the branch it opens is date-stamped, so re-running on a
  later day produces a second branch for the same finding. `TICKETING_CONTRACT.md` §3 makes the
  lookup the first thing that happens and §9.5 warns that without it *"the team learns within a
  fortnight that the pipeline is noise."*
- **It has four incompatible notions of what a finding is.** The Trivy path keys on the
  advisory id plus package name; the Bandit path keys on test id, filename, **line number** and
  CWE; the ingestion path uses the same key minus the CWE; the normalised report re-groups on
  bare advisory id and bare CWE. Two of the four carry a line number, which
  `ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` §5.2 lists first among things a fingerprint must
  never contain, because *"one unrelated import added at the top of a file, and every finding in
  it is NEW."*
- **It treats a ticket as an outcome rather than a request.** Nothing in it distinguishes a
  request from a disposition, which is the distinction the whole ticketing contract is built on.
- **And it processes zero bytes** (§3.1), so none of the above has yet produced a visible
  consequence. That is the most dangerous property in the list: the design defects are latent
  behind a transport defect, and repairing the transport alone would activate all of them at
  once.

---

## 5 · The run graph

### 5.1 One run, one dependency chain

```
kit-scripts  (bootstrap; publishes the canonical scripts intra-run)
     |
  resolve            stages 1-5   policy, discovery, versions, capability, plan
     |
  scan-*             stage 6      grouped per JOB_TOPOLOGY_AND_BUDGET.md section 4
     |
  adjudicate         stages 7-11, 14
     |                            validity, normalization, baseline, classification,
     |                            severity, disposition, correlation, report
     +----------------------------+
     |                            |
   gate                       [protected-branch runs only]
   stage 12                     reconcile-tickets   stage 13
   reads the verdict            propose-ledger      stage 9 write path
   and exits on it
     |
  [release runs only]
   build  ->  attest  ->  deploy  ->  verify        stage 15
```

**Why `resolve` is one job and not five.** Stages 1 to 5 are metadata work: reading a
registration file, probing for file presence, reading declared versions, consulting a capability
table, emitting a plan. None of them runs a scanner and none of them produces a per-scanner
verdict, so the attribution loss `JOB_TOPOLOGY_AND_BUDGET.md` §8 warns about does not apply.
Splitting them costs five runner boots and five billed minutes to save nothing.

**Why `adjudicate` and `gate` are two jobs and not one.** The gate has to be able to fail while
the report still exists. Inside one job a failing step stops the steps after it, and
`JOB_TOPOLOGY_AND_BUDGET.md` §8.2 is explicit that per-step `continue-on-error` is not the fix.
So `adjudicate` always runs to completion, always produces the report, and always writes a
verdict; `gate` does nothing but read that verdict and exit on it. `gate` is the job branch
protection requires, and it is a few seconds of work in a billed minute — which is the correct
place to spend a minute, because it is the only job whose result is a control.

### 5.2 The gate emits a verdict, not a job result

This is the single most important structural change to what the kit already has — and it is a
smaller change than it looks, because **three of the kit's four reusable workflows already do
it.**

`reusable-build-docker.yml`, `reusable-nvd-cve.yml` and `workflow-policy-check.yml` each emit a
`routing_result` output alongside a control-posture record: which controls were required, which
executed, which were unavailable, which were reduced, which were skipped, and what weakenings
were in force with what attribution. They also each accept weakening inputs — a reason, an
authority, an exception reference and an expiry — so that a weakening arrives attributed or is
recorded as `WEAKENING_UNATTRIBUTED`.

**`reusable-security.yml` is the only one of the four without that contract.** It emits an
assurance state, an enforcement state, a gate decision and a scanner-state map, and no routing
result. So the consolidation's central requirement is not to invent a verdict; it is to give the
workflow that needs it most the contract the other three already ship. That the gap sits exactly
there is consistent with the kit's own recent history — the most recent commit on this tree is
titled *"a weakening is a governed exception, and one workflow blocked nothing by default."*

Today `security-gate` reads `needs.<job>.result` and projects `success`, `skipped`, `cancelled`
and everything else into `PASS`, `NOT_APPLICABLE` and `UNAVAILABLE`. That projection is
defensible for a status check and it is **insufficient for a deployment gate**, because a job
result is a boolean wearing four labels: it cannot distinguish `DECISION_REQUIRED` from
`BLOCKED`, and it cannot express `PROCEED_WITH_ADVISORY` at all.

The target:

- `adjudicate` computes the run's routing result as the **precedence maximum** across controls,
  under the registered rung for the targeted environment, using the registered order
  `BLOCKED` above `EVIDENCE_UNTRUSTED` above `DECISION_REQUIRED` above `PROCEED_WITH_ADVISORY`
  above `PROCEED`.
- It emits that value, plus the contributing controls, as **job outputs**.
- `gate` exits non-zero on `BLOCKED` and on `EVIDENCE_UNTRUSTED` at production tiers, per
  `AXES_AND_PHASES.md`.
- **The deploy stage reads the verdict**, not `needs.gate.result`. A deploy that merely depends
  on a gate job inherits the reference estate's defect in reverse: `gov-prod-deploy-<service>-api.yml`
  declares `needs: [build, provenance]` and reads only the build outputs, so *"if it produced a
  contradiction, nothing would notice."*

The kit's own caller template already has the right skeleton — `needs: [security, policy]`, then
`needs: [build]`, with the digest passed as a job output, all in one run, no `workflow_run`
anywhere. What it lacks is a verdict to read. Adding one is a smaller change than it looks and
is the difference between a pipeline that orders its stages and a pipeline that gates them.

### 5.3 What each trigger arms

| stage | `pr` | `merge` | `nightly` | `revalidate` | `release` |
|---|---|---|---|---|---|
| 1-5 resolve | armed | armed | armed | armed | armed |
| 6 scanning | diff-scoped | full tree | full tree, full history | deployed artefact and SBOM only | full tree, plus SBOM and attestation |
| 7-11 adjudication | armed, read-only | armed | armed | armed | armed |
| 12 gating | advisory on new categories | blocking | report only | incident path | hard gate |
| 13 ticketing | **refused** | armed | armed | armed | armed |
| 9 ledger write | **refused** | armed, as a reviewed proposal | armed, as a reviewed proposal | armed | armed |
| 14 reporting | armed | armed | armed | armed | armed |
| 15 deployment | **refused** | armed, environment-gated | — | — | armed, environment-gated |

The `revalidate` row is the one people get wrong, and `AXES_AND_PHASES.md` already flags it: it
scans **what is running**, not the branch. No source scanning at all — the source did not change,
the world did. It is also the only context in which stage 15's verification half runs without its
deployment half, re-reading the image reference the platform is actually serving and comparing it
to what the release recorded.

---

## 6 · The four things the kit must absorb

### 6.1 The post-scan phase

The kit has none. This is stage 13 and the stages either side of it, and it is the largest
architectural hole in the consolidation.

What "absorbing it" means concretely, in the order the pieces have to exist:

1. **A finding identity.** Three components carried separately — what, where, content — with
   line numbers, rule ids, scanner names and versions, paths as a strong component, commit shas,
   image digests, severity and the scanner's own partial fingerprints all excluded, each for a
   stated reason. Without this nothing downstream is possible, because "have I seen this before"
   has no answer.
2. **A ledger on the protected default branch**, keyed by finding identity and environment, read
   by every run and written by none of them directly.
3. **Classification**, using the registered `finding_classification` values, so that a backlog is
   a set of decisions rather than a number.
4. **Correlation above the observations, never replacing them.** Corroboration is not
   duplication: `OBSERVED_CORROBORATED` with every contributing scanner named, because dropping
   tool attribution *"is what caught a dead flawfinder covered for by cppcheck."*
5. **Ticket reconciliation**, delta-only, with an umbrella sweep whose cost is a function of
   tickets that exist rather than findings observed — `1 + ceil(T / P) + U + C` calls, in which
   the finding count does not appear.

**And the ledger write is the one genuine write path in the whole design, so it is worth being
precise about it.** The run does not push to the protected branch. It opens a pull request
carrying the proposed ledger delta, and the branch's own protection plus CODEOWNERS is what
enforces the review. That keeps `ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` §5.4's rule — *"The
ledger is a governance artifact, not a scanner output"* — structural rather than promised. Its
cost is named honestly in §9.3: this job, and only this job, needs write authority to a
non-protected ref, and it must be the only one that has it.

### 6.2 Deployment as a first-class stage

Today deployment is a reusable workflow nobody calls on the shipped path. The target is a stage
inside the pipeline with seven properties, all of which already have a design and none of which
is built:

| property | mechanism | status |
|---|---|---|
| gated on the scan verdict | `deploy` reads the stage-12 verdict output, not a job result | the verdict output does not exist |
| digest-bound | the existing regex guard refusing anything that is not a full `sha256` digest, before login | **built**, and `PROVENANCE_AND_ATTESTATION.md` §7 confirms this link is not where the chain breaks |
| environment-bound | a GitHub environment whose deployment branch policy refuses every ref but the protected branch. Environment secrets *"are only available to workflow jobs that use the environment"* and such jobs *"can only access these secrets after any configured rules (for example, required reviewers) pass"* ([Managing environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)) | partially built — the workflows take an environment input; the branch policy is repository configuration and is not verifiable from disk |
| break-glass | `workflow_dispatch` plus a typed confirmation string plus the environment's required reviewers, which is the reference estate's `gov-prod` pattern | not in the kit |
| health-checked | a probe that can fail the job — not `curl -f … \|\| echo`, which is the reference estate's non-fatal form on its commercial path | **built** in `reusable-deploy-containerapp.yml`, which fails the deploy when the probe never passes |
| reconciled against live state | the layered model: objects exist, dependencies reachable, inputs present, intended artefact loaded, health verified, **and the consumer path reaches it** | not built. The kit has the health assertion and not the serving assertion, and the prior control-plane design paid for that distinction with an incident |
| reversible | pre-change snapshot, change manifest, per-object preconditions, live-state verification after reversal | not built. `ROLLBACK_CONTRACT.md` gate 1 is open |

**Two rules the consolidation must carry across unchanged.** Concurrency is a safety setting for
mutating work, not a cost setting: validation cancels in progress, deployment does not, serialized
per environment and target. And `timeout-minutes` stays off mutating jobs deliberately, because a
bound that produces an unreversible half-state manufactures the exact condition the rollback
contract exists to avoid.

**One hazard the consolidation inherits and should not inherit silently.** The kit's deploy
workflows interpolate `inputs.image_digest` into a `run:` block. It is validated by a strict
regex, but the validation step itself interpolates before it validates. The caller is trusted, so
this is `CALLER_CONTROLLED_INPUT_INTERPOLATION` rather than the fork-reachable class — but a
pipeline that becomes the only pipeline is called by more callers, and the registered fix,
`SAFE_ENV_TRANSPORT`, is cheap.

### 6.3 Provenance, and a gate the owner cannot lift

**The hard finding, verified at source.** *"Artifact attestations are available in public
repositories for all current GitHub plans… If you are on a GitHub Free, GitHub Pro, or GitHub
Team plan, artifact attestations are only available for public repositories. To use artifact
attestations in private or internal repositories, you must be on a GitHub Enterprise Cloud
plan"* ([actions/attest-build-provenance](https://github.com/actions/attest-build-provenance)).
The owner is on Pro. Every private consumer of this kit therefore **cannot produce or verify an
attestation**, and no amount of design changes that.

The design consequence is not "adopt it anyway" and it is not "drop it".

**Verification is registered as held, with a trigger rather than a date.**
`validation_debt_state.IMPLEMENTATION_HELD` is defined for exactly this — a component whose
blocker is an unbuilt capability, carrying an activation trigger *"because it returns to scope
when the thing it waits on starts."* The activation trigger is the **plan**, not a date: the debt
returns to scope when the account moves to Enterprise Cloud, or when a repository the kit builds
is public. On a public repository it arms immediately, because there the capability is free on all
current plans.

**Wiring it as a live gate is forbidden**, and the reason is registered: a permanently red check
*"is not a control, it is training: people learn red means 'known backlog', stop reading it, and a
real regression arrives wearing the same colour."* At `uat` and `prod` a `not-establishable`
verification result stops the run, so an armed gate on a private Pro repository is a permanent
stop.

**And the two must render differently.** This is the half of the requirement that is easy to lose:

| what happened | how it must render | who can fix it |
|---|---|---|
| this plan does not offer attestations | a recorded platform limitation, established **once at discovery**, carried as held debt with a plan trigger | **nobody in this estate.** It is a billing decision, not an engineering one |
| this image has no attestation | a gap in production — the producing side never ran, or ran without the permission | **the owner**, by wiring the attest job |

If those two render the same, then on the day the plan changes nobody will notice that the second
one has become a real finding. One is fixable by her and one is not, and a control that cannot
tell them apart is reporting the wrong thing to the only person who could act.

**What to build now, because it has no plan gate at all.** Links 2, 3 and 4 of the chain — base
image digest, lockfile hash, toolchain versions — cost nothing, need no permission, and work on
every plan. The kit records none of them; the reference estate records the lockfile hash. Without
them an attestation would sign a statement whose interesting fields are empty, so this is the
first step even if attestation is never adopted.

**And the permission, which is the real cost.** Exactly one job may hold `attestations: write`,
and it is a job that does nothing else — no Azure login, no registry login, no Dockerfile, no
caller-supplied script. In a reusable workflow the file-level `permissions:` block is the ceiling
for every job in the file, so this must be declared at job level and never promoted. Signing
authority handed to the process that builds from untrusted input is the worst available candidate
for a permission union.

### 6.4 Governance, extended past scanning

The kit leads on four governance mechanisms and every one of them currently stops at the scanner.
Extending them is most of what makes the consolidation defensible.

**Taxonomy enforcement.** `reconcile_taxonomy.py` reads `.github/workflows`, `docs`, `tests`,
`scripts` and `profiles`. After consolidation, deployment states, reversal dispositions, ticket
states and release transitions all become enforcement words, and all of them must be registered
before anything branches on them. The namespaces already exist — `rollback_state`,
`reversal_conflict`, `reversal_disposition`, `release_ownership`, `transition_reason`,
`change_artefact` — and are currently **orphans**: registered, used nowhere. That is the correct
state for vocabulary registered ahead of its implementation, and it becomes a defect the moment an
implementation invents a second spelling beside it.

**The weakening record.** `control_weakening` today covers a disabled scanner and a softened gate.
After consolidation it must also cover: a deployment that proceeded without a rollback capability;
a break-glass dispatch; a retired legacy workflow (§7.5); and — the largest single control change
available in the system — a business declaring its rung **downward**. That last one needs a named
authority, a stated reason, an expiry, and `WEAKENING_IN_FORCE` on every affected run, or the root
declaration becomes the softest bypass the kit ships and it is reached by editing one word.

**The gate.** Extending it past scanning means it reads a rung, an environment tier and a team
pattern, none of which exists in the kit today, and emits a routing result rather than an exit
code. §5.2.

**The epistemic vocabulary.** The distinction the kit is built on — `NOT_APPLICABLE` is not
`PASS`, `POTENTIALLY_ABSENT` is not fixed, `EVIDENCE_UNTRUSTED` is not a decision — has to survive
into three new places: a ticket that exists is not a disposition; a reversal command exiting zero
is not restored service; and an attestation that could not be checked is not an attestation that
checked out. Each of those is the same error in a new costume, and each already has a registered
word waiting for it.

---

## 7 · Migration must prove coverage, not assume it

### 7.1 The failure this exists to prevent

Deleting a workflow that detects something the kit does not is a silent loss that fails no gate.
Nothing turns red. The scanner simply stops existing, and the next finding it would have raised is
never raised — which is indistinguishable, in every report the kit produces, from there being
nothing to find.

This is `absence_is_not_a_negative_observation` applied to the migration itself, and it is the one
place where the consolidation can make the estate less safe while every dashboard improves.

### 7.2 The retirement register

A file on the protected default branch, under CODEOWNERS, holding one entry per legacy workflow
being retired. Each entry carries:

```
the workflow being retired            path, and the repository it lives in
the detections it is claimed to make  one row per detection, not one row per workflow
for each detection:
    the kit control claimed to subsume it
    the outcome                       reproduced | not-applicable | accepted-gap
    the evidence reference            a run in which the claim was demonstrated
    an owner                          a role, never a person
    an expiry                         for accepted-gap only
status                                shadowing | retired
```

**One row per detection, not per workflow, is the load-bearing detail.** A workflow-level claim
("the kit replaces `comprehensive-code-scan.yml`") cannot be false in any useful way. A
detection-level claim can, and the delta the other piece of work produces is expressed in exactly
those terms.

### 7.3 The shadow period, and what is compared

While an entry is `shadowing`, both pipelines run on the same commit, and the comparison is
**on findings, not on scanner names**.

Comparing configurations is the trap. "Both run Semgrep" is a statement about two YAML files and
says nothing about whether the same defect is reported, because the rulesets, the versions, the
paths and the severity filters all differ. What is compared instead:

```
for each finding the legacy workflow reported on this commit:
    does a kit observation cluster with it at the anchored tier?
        yes -> reproduced
        no  -> it is in the delta, and the entry cannot be retired on it
```

Anchored, not proposed. `ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` §9.4 permits only the
anchored tier to act, and a migration is the last place to let a heuristic decide that two
findings are the same one. A proposed match is reported to the reviewer and is not evidence.

For the classes where no external anchor exists — SAST above all — the comparison cannot be
automatic, and the design must say so rather than pretend. There the evidence is the forced-failure
demonstration in §7.4, which is stronger anyway.

### 7.4 What retirement requires per detection

Exactly three outcomes are permitted, and the absence of a fourth is the point.

**reproduced.** The kit detects it, **demonstrated on a seeded corpus, not asserted from
configuration.** This is `capability_maturity.DETECTION_PROVEN` and the standard is the one the
kit already holds its own scanners to: a deliberately introduced instance of the defect the legacy
workflow caught is shown to appear in the kit's output. A check that cannot be shown to fail is
decoration, and so is a migration claim that cannot be shown to fail.

**not-applicable.** The detection has no subject in this repository — no Dockerfile, no IaC, no
such language. This is `NOT_APPLICABLE`, and it must come from discovery's own probe rather than
from somebody's belief, because a detection that is not applicable today becomes applicable the
first time somebody adds a Dockerfile.

**accepted-gap.** The kit does not detect it, nobody is going to make it, and the loss is being
taken deliberately. This is `COVERAGE_GAP` plus a `DEFERRALS` entry carrying the four fields the
kit's validation-debt mechanism already requires — reason, owner, `proves`, and an **expiry** —
because *"silence must never renew a deferral."* An expired entry goes blocking and forces a fresh
decision.

**There is no fourth outcome, and in particular there is no "probably fine".** An unclassified
detection blocks the retirement. That is the whole mechanism: the register cannot reach `retired`
while any of its detection rows is unresolved, and a check reads the register and fails when a
retired entry has an unresolved row or an expired `accepted-gap`.

### 7.5 Deletion is mechanically coupled to the register

The check has to bite on the commit that deletes the file, or it is advice.

- A commit that removes a workflow listed in the register as `shadowing` **fails**. The register
  entry must reach `retired` first, in its own reviewed change.
- A commit that removes a workflow **not** in the register fails, because an unregistered
  retirement is exactly the silent loss this exists to catch. Drift is always blocking; the kit's
  validation-debt gate already applies that rule to unregistered workflows and this is the same
  rule pointed at deletions.
- Retiring an entry is a **weakening event**, recorded as `control_weakening.CONTROL_DISABLED`
  with a named authority and a reason. Without them it is `WEAKENING_UNATTRIBUTED`, which routes
  to `DECISION_REQUIRED`.

**And the gate must be under test itself.** The kit's self-test already runs a negative control
against its validation-debt gate — it forces every deferral past expiry and requires a non-zero
exit. The retirement gate needs the same: a fixture with an unresolved detection row that must
fail, because a migration gate that has never been shown to refuse a migration is a migration gate
nobody should trust.

### 7.6 The asymmetry, stated

Adding a kit control is free and needs no register entry. Retiring a legacy control is expensive
and needs evidence. That asymmetry is deliberate and is the same shape as the floor rule
everywhere else in the kit: **strengthening takes effect at once; weakening requires review.**

---

## 8 · One kit, many repositories

### 8.1 What was measured, which is not quite what was assumed

The estate is described as four repositories with registrations, six products and three
environments each. What is actually on disk:

- **Four repositories, four subscriptions, four app registrations, one-to-one**, per the
  reference estate's own subscription mapping, with **five** federated identity credentials
  because one repository needs two environments. The subject format is fixed as
  `repo:<org>/<repository>:environment:<environment>`.
- **Four deployable components** enumerated in the reference estate's stack deploy workflow, plus
  fire-and-forget dispatch into **three further repositories** that are not part of the two read
  here. So six products is plausible and is not established from these two repositories.
- **Five distinct environment names in use**, not three per repository, and they are not a
  consistent set: two repositories share `dev`, and `production`, `commercial-sbx` and `gov-prod`
  each appear once or twice.
- **No product matrix and no environment matrix exists anywhere.** The only `strategy: matrix`
  blocks are over scan types and a single-element language list.

That last point is not an oversight, and §8.4 explains why.

### 8.2 How one kit serves all of them without a per-repo fork

Three mechanisms, all of which the kit either has or has designed:

**A registration file per repository, on its protected default branch, under CODEOWNERS.** This is
the thing the kit does not have and needs most. It holds the rung per (repo, environment) cell,
the cherry-picks, the environment-to-tier mapping, the team pattern, and the profile selection.
`consumer-coverage.json` is not this — it is a discovery census of seven repositories and
thirty-seven non-repositories produced by `scripts/inventory_consumers.py`, and it records
ecosystems and manifests, not policy.

**Profiles for depth.** `profiles/` already holds three, with a schema, and each already declares
a deployment block — target, partitions, digest-binding, whether it is gated, a health path and
whether rollback applies. **They are inert.** Nothing reads a profile to set an input; the only
references to them anywhere are a lint step and a schema-validation step in the kit's own
self-test, and the schema says so in its own words: *"A profile is the intent; the reusable
workflows are the implementation."* Wiring profiles into `resolve` is therefore not new design —
it is connecting a declaration that already exists to a stage that does not.

**Overlays for employer-specific integration and policy.** a consumer overlay under `overlays/` is the worked
example, and the registered `capability_origin` values already separate
`OVERLAY_SPECIFIC_INTEGRATION` and `OVERLAY_SPECIFIC_POLICY` from
`PREEXISTING_NEUTRAL_IMPLEMENTATION`. That separation is what lets one kit carry a ticketing rule
belonging to one employer without that rule becoming doctrine.

### 8.3 The boundary

**Legitimately per repository — configuration:**

| what | why it varies | how it is constrained |
|---|---|---|
| the registered rung per (repo, environment) | it is the business's declared posture | monotone along the promotion path; `uat` equals `prod`; a pull request is evaluated at the rung of the highest environment its merge can reach without a further human gate |
| cherry-picked controls | a business may care more about one control | **strengthen only.** A cherry-pick may raise a floor and may never lower one |
| environment names, and their mapping to `environment_tier` | estates name environments differently | the tier vocabulary is fixed; the mapping is declared |
| `team_pattern` | headcount is a fact | it changes **how** a floor is satisfied, never **whether** |
| scope and path exclusions | monorepos, vendored trees | every narrowing is recorded as `SCOPE_NARROWED` |
| deployment target — registry, resource names, adapter, health path | the estate is what it is | digest-binding and environment-binding are not negotiable |
| ticket backend and project | one estate, one tracker | the credential's reach is fixed by §7.3 of the ticketing contract |
| toolchain versions | a repository targets a runtime | **these should be derived from stage 3, not supplied.** Where a caller supplies one, the run compares it against what the repository declares and records divergence |

**Never overridable — the kit would stop being one kit:**

- **The rung is not a workflow input.** If a caller passes one, the run compares it against the
  registered value and records a downward divergence as `WEAKENING_IN_FORCE`; with no reason and no
  authority attached it is `WEAKENING_UNATTRIBUTED`. A rung a caller can simply pass is a
  governance position expressed as a config flag.
- **`policy_mode` is derived from the rung and never set.** A derived value a caller can still
  override is not derived, and a run in which it was supplied rather than computed must fail.
- **Secrets block at every rung, and are never grandfathered.** A leaked credential is live
  exposure, not inherited debt.
- **Redaction runs before every publication step**, without exception, including into a tracker. A
  redactor after the upload protects nothing while looking exactly like protection.
- **The evidence-validity check, and what a zero-finding zero-artefact report means.** A repository
  cannot opt into treating an empty SARIF as clean.
- **The finding identity scheme and the alias table format.** Two repositories with two
  fingerprints cannot be correlated, and an estate that cannot correlate has no baseline.
- **The meaning of every registered vocabulary value.** This is what the taxonomy gate enforces and
  it has no exemption clause.
- **Deploy-by-digest.** A tag is mutable, and an attestation or a scan bound to a digest means
  nothing if the deployment resolves a tag at deploy time.
- **The ordering of the stage graph.** Depth is configurable; sequence is not. A validity check
  after the gate validates nothing while looking exactly like validation.

### 8.4 The constraint that actually makes this hard

The reference estate's own notes record it, in a comment, as the reason its design looks the way
it does:

> *"GitHub Actions doesn't support dynamic secret access. So we need to pass them explicitly from
> the calling workflow."*

That is why the product-by-environment matrix anyone would expect is absent: without dynamic secret
resolution, **every product-by-environment-by-subscription combination has to be enumerated as an
explicit `secrets:` block at the call site.** The observed cost in the reference estate is roughly
thirty-six secret entries to express four identities, because each repository's environment holds
both a generic and a subscription-specific copy of the same value.

This design does not solve it. What it does is confine it: the enumeration lives in the **caller
template**, which is per repository and is the one place a per-repository fact belongs, and the
kit's reusable workflows take a single set of generically-named inputs. The environment is what
supplies both the federated subject and the subscription, which is the mechanism the kit's own
build workflow already relies on.

**Two observations that must not be lost in the migration.** The reference estate's documentation
of this pattern is **behind its code** — three credential sets appear in the workflows and in no
mapping document. And two deploy paths to the same container app read the same three configuration
names from **different stores**, one from repository variables and one from secrets. Consolidation
onto one kit fixes the second by construction and does not fix the first: the mapping has to be
re-established from the code, not from the document.

---

## 9 · What this costs

Every duration below is **assumed**. `reusable-security.yml` has not completed a run since
2026-09-16, so there is no history to measure, and the arithmetic is exact while its inputs are
not.

### 9.1 Jobs

Against the grouped topology already proposed in `JOB_TOPOLOGY_AND_BUDGET.md` §4, taking its S2
shape — a Python repository with IaC and a container:

| | jobs | billed minutes |
|---|---:|---:|
| the kit today, ungrouped | 19 | 40 |
| grouped, as already proposed | 8 | 26 |
| grouped, plus this design, pull-request context | **10** | **28** |
| grouped, plus this design, protected-branch context | **12** | **30** |
| protected-branch context with a release | **16** | **~36** |

The post-scan phase adds `adjudicate` and `gate` on every run, `reconcile-tickets` and
`propose-ledger` on protected-branch runs, and `build`, `attest`, `deploy` and `verify` on a
release. Adjudication is arithmetic over the run's own output with the ledger already in the
checkout, so it is short; `gate` is seconds of work in a billed minute and that minute buys the
one job whose result is a control.

### 9.2 Minutes, compared with the alternative rather than with zero

The honest comparison is not against doing nothing. It is against the second-trigger design, which
is what the estate runs today.

The reference estate's post-scan phase is four separate workflow runs, each paying a runner boot,
a checkout and a minute rounding — and it fans out badly enough that one of them carries a
`sleep 30` to avoid queuing fifty-plus workflows. Four consumers at one to two billed minutes each
is four to eight billed minutes to produce, currently, zeros.

**So the same-run design is cheaper as well as safer**, and the four to six billed minutes this
design adds per protected-branch run are approximately what the second-trigger design already
spends without the correctness. In dollars the whole argument is trivial — at the rate
`JOB_TOPOLOGY_AND_BUDGET.md` uses, the largest figure in §9.1 is a few cents a run — and the case
for this work is correctness, not money.

**Wall clock moves the other way and should be said.** Adding `adjudicate` and `gate` in series
after the scanners adds their duration to the critical path of every pull request. That is a real
cost paid by a human waiting, and it is the strongest argument for keeping adjudication to one job
and for making `gate` do nothing but read a value.

### 9.3 Permissions, which is the cost that matters

Declared per job. Never at file level, because in a reusable workflow the file-level block is the
ceiling for every job in the file.

| job | permissions | note |
|---|---|---|
| `kit-scripts` | `contents: read` | already declares this explicitly rather than inheriting |
| `resolve` | `contents: read` | |
| `scan-*` | `contents: read`; `security-events: write` **only on the jobs that upload** | |
| `adjudicate` | `contents: read` | reads the ledger from the checkout. No token, no network |
| `gate` | `contents: read` | |
| `reconcile-tickets` | `contents: read`, plus `issues: write` on the GitHub backend **or** a tracker credential from a protected environment. Nothing else | protected-branch runs only. The credential may create and comment in **one** project, transition within it, and nothing more: no delete, no administration, no read outside it |
| `propose-ledger` | `contents: write` to a non-protected ref, `pull-requests: write` | **the only write authority in the design.** It opens a pull request; branch protection and CODEOWNERS do the enforcing |
| `build` | `contents: read`, `id-token: write` | |
| `attest` | `contents: read`, `id-token: write`, `attestations: write` | **job level, never promoted.** No Azure login, no registry login, no Dockerfile, no caller script. `packages: write` is not added — the kit publishes to a federated registry, not to the one GitHub's example uses |
| `deploy` | `contents: read`, `id-token: write`, plus `environment:` | verification at deploy needs no new write permission; `gh attestation verify` reads |
| `verify` | `contents: read`, `id-token: write` | |

**Three things the table is asserting.**

`attestations: write` is held by one job that does nothing else. A token with authority to sign
statements *about* artefacts, handed to the process that produces them from caller-supplied input,
is the worst available candidate for a permission union — and permission unions across merged jobs
produce regressions that are invisible until something uses the extra authority.

`propose-ledger` is the design's single write path and it is deliberately narrow. It cannot write
to the protected branch. Its output is a pull request a human merges. If that job's authority ever
grows to include the protected branch, the ledger has stopped being a governance artifact and the
whole baseline becomes a scanner output.

**No job holds a tracker credential in a pull-request context**, and the mechanism is not
discipline. The credential lives in a protected environment whose deployment branch policy refuses
every ref but the protected branch, and environment secrets *"can only access these secrets after
any configured rules… pass."* A run on any other ref cannot mint them, and the registered state for
an environment refusing a ref is `POLICY_REFUSED`.

### 9.4 The cost that is not minutes or permissions

**Review burden.** Every protected-branch run may open a ledger pull request. On a legacy estate
with a large day-one cohort that is a large diff, and
`ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` §13 already names this as unsettled: *"A ledger nobody
can review is a governance artifact in name only."*

**Blast radius.** One pipeline means one defect reaches every repository. The kit has already
shipped a workflow that produced a startup failure — zero jobs, not a failing job — for days.
Consolidation turns that from one repository's bad week into the estate's.

**Wall clock on every pull request**, per §9.2.

---

## 10 · What could not be settled

Named plainly, because a document that answered everything about an architecture nobody has built
would be lying.

**Whether a full merge-depth re-scan on every merge is affordable.** The whole same-run answer
rests on the merge run being a complete, independent execution rather than a continuation. That is
correct and it is not free: four repositories, merging at whatever rate they merge, each paying a
full-tree scan. The rate is not measured and the durations are assumed. If it turns out
unaffordable, the pressure to hand something across a run boundary returns, and §3.1 is the
argument that must be re-won rather than quietly conceded.

**Ledger storage at estate scale.** Inherited unchanged from
`ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` §13. It is not established that a reviewed file on a
protected branch is the right storage for tens of thousands of entries, nor what reviewing a diff
of that size consists of, nor whether CODEOWNERS routing survives it. Every ticket binding
inherits the same question.

**Whether `$/` resolves as intended for a reusable workflow invoked from another repository.**
UNVERIFIED. `SECURITY_WORKFLOW_DECOMPOSITION_PLAN.md` re-verified this against primary sources and
found that **no primary source states how it resolves in that case**; the documented intent is
consistent with the claim and the claim itself is not established, and it carries two consumer
environment preconditions the kit cannot assert. This matters here because the registry-and-composite
target depends on it, and without it the consolidated pipeline stays one very large file.

**Whether a ticket backend exists to target.** `TICKETING_CONTRACT.md` §11.1: not established, and
nothing in either repository establishes it. An overlay expects a Jira project; that is evidence
somebody expected one, not evidence one exists. GitHub Issues is the backend that can be built
against verified documentation today.

**Whether the reference estate's out-of-repository reusable workflows do what their inputs imply.**
The one digest-bound deploy path in the estate calls reusable workflows in a repository not present
locally, pinned to a **mutable ref**. Every claim about digest enforcement, severity gating,
health-check enforcement and environment protection on that path rests on inputs passed, not on
behaviour verified. UNVERIFIED, and it is the estate's strongest-looking deploy path.

**Whether GitHub environment protection rules are actually configured.** Environment keys exist in
YAML across both repositories. Required reviewers, wait timers and deployment branch policies live
in repository settings, which are not on disk. The entire credential-confinement argument in §9.3
depends on the deployment branch policy being set, and that has not been observed.

**Whether branch protection currently requires the reference estate's `echo` jobs.** The migration
plan names four of them as required checks. Whether it was applied is unreadable from disk. If it
was, branch protection in that repository is currently satisfied by `echo`.

**Whether cross-scanner identity is achievable at all.** §7.3's comparison depends on anchored
clustering, which works for dependency findings and does not exist for SAST. The argument that it
is unachievable beyond heuristics is an argument, not a measurement: nobody here has run two SAST
engines over one corpus and counted how often the heuristic is right. For the migration gate this
is load-bearing, because SAST is exactly where the reference estate's coverage is densest.

**Whether the plan gate will ever lift, and what happens if it does not.** The attestation design
registers verification as held with a plan trigger. It does not decide whether to pursue a
non-GitHub signing path instead, and `PROVENANCE_AND_ATTESTATION.md` §0 explicitly leaves that
open. If the plan never changes and no alternative is adopted, links 8, 9 and 12 of the chain stay
permanently open and the honest reporting of that is the whole of the control.

**Where the release object lives.** `DEPLOYMENT_CONTRACT_RECONCILIATION.md` §7.5 sketches its
shape. There is no store, no schema and no writer, and the rollback contract's multi-release
recovery reads from it.

**Whether any repository holds a disposition file at all.** Stage 10 already suppresses on an
approved, unexpired disposition, and the path is supplied by the caller rather than fixed.
Whether any repository in the estate has ever supplied one is UNVERIFIED. If none has, then the
suppression path — the one piece of stage 10 that is built — has never executed against real
input, and the protected-branch consumption rule that the whole exception model rests on has
never been exercised at all.

**Every number.** The consecutive-run count for a promotion, the shadow period's length, the
per-run creation ceiling, the reformat threshold, the SLA table, and every duration in §9. All
placeholders, and none of them should be implemented as a constant.

---

## 11 · The one-paragraph version

The post-scan phase lives in the same run as the scan, in every trigger context, and what varies
is which stages are armed: a pull-request run scans, adjudicates and gates while reading the
ledger, the dispositions and the rung from the protected default branch and writing nothing; a
post-merge run is a complete independent execution of the same pipeline at merge depth which
additionally reconciles tickets, proposes a ledger change as a reviewed pull request, and deploys
behind an environment gate. Nothing crosses a run boundary except the merge commit and the files
in its checkout, which is why this is not the reference estate's defect in a new costume — that
pattern needs the earlier run's artifacts and names the wrong run by default, and this one needs a
ref the event supplies. Both `workflow_run` artifact hand-off and the orchestrator-of-echoes are
refused by name, on the shared principle that a dependency which has to be described can be
described wrongly. Of the fifteen stages, four run without a design, one has neither design nor
build, one is partial, nine are designed and unbuilt, and the only one running in production
anywhere is ticketing in the reference estate, where it has no idempotency check, four
incompatible notions of a finding's identity, and zero bytes to process. Migration proves coverage
rather than assuming it: a retirement register on the protected branch, one row per detection, a
shadow period compared on anchored findings rather than on scanner names, three permitted outcomes
and no fourth, deletion mechanically refused until the register says retired, and retirement
recorded as a weakening event with a named authority. One kit serves every repository through a
registration file, a profile and an overlay, with the rung, the vocabulary, the ordering,
digest-binding and redaction-before-publication never overridable — and the hard part is not the
design but that GitHub Actions has no dynamic secret resolution, so every identity has to be
enumerated at the call site. It costs about two extra billed minutes on a pull request and four on
a merge, which is roughly what the pattern it replaces already spends producing zeros; the cost
that matters is that exactly one job may sign, exactly one job may write, and neither of them is
the job that builds.

---

> **Neutralisation note.** This document originally named a consumer estate's repositories and
> products. Those names are denied from the neutral core by `scripts/export-deny.txt`, and the
> remedy is substitution rather than deletion: the meaning is preserved and the identity is not.
> Where a specific repository mattered to an argument, it now reads as **the reference estate** --
> the estate this kit is qualified against, whose own assessment lives in
> a consumer overlay's `docs/` folder. Nothing about the findings changed.
