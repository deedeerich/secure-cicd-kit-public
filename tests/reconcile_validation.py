#!/usr/bin/env python3
"""
Reconcile three registries and fail CI when they diverge.

  IMPLEMENTATION  what workflows/jobs/actions actually exist
  CAPABILITY      what each claims to provide
  VALIDATION      what probe proves it

Absence from the matrix is an ERROR STATE, not a way to avoid scrutiny. This exists
because a hand-maintained table drifted four times: the gate under-enforced, the harness
hid its own errors, the matrix omitted a whole workflow, and the audit of those misses
published a contradictory count. Humans cannot keep this synchronized. Machines can.

Exit 1 on VALIDATION_COVERAGE_GAP.  --json for machine output.
"""
from __future__ import annotations
import argparse, datetime, glob, json, os, sys
import yaml

# ---------------------------------------------------------------- registries

# Declared per artifact. New artifact with no entry => VALIDATION_COVERAGE_GAP.
CAPABILITY_REGISTRY: dict[str, list[str]] = {
    "reusable-security.yml": [
        "secret-scan", "code-quality", "sast-semgrep", "sast-bandit", "sast-dotnet",
        "sast-java", "sast-go", "sast-cpp", "deps-scan", "iac-scan",
        "malicious-deps", "sbom", "security-gate",
        # Both are jobs the gate waits for and reads, and neither was registered here -- so the
        # validation census could not see them at all, and nothing could ever report them unproven.
        # Found by tests/check_scanner_registry.py on its first run (N55).
        "codeql", "image-scan",
    ],
    "reusable-nvd-cve.yml": ["nvd-dependency-check", "nvd-trivy", "nvd-dockerfile"],
    # The kit invoking its own reusable NVD workflow. It exercises the same capabilities
    # rather than adding new ones -- and registering a capability on two artifacts does NOT
    # double-count the debt, because accepted deferrals are deduplicated by capability.
    # It exists because the reusable workflow is `workflow_call`-only: with no caller and no
    # dispatch trigger it was unvalidatable by construction, not merely unvalidated.
    "nvd-cve.yml": ["nvd-dependency-check", "nvd-trivy", "nvd-dockerfile"],
    "reusable-build-docker.yml": ["image-build", "image-push"],
    # W-1 (TICKETING_BACKENDS.md section 5). Proven LOCALLY by extraction
    # (tests/prove_ticket_reconcile_workflow.py) and, on pull requests, by self-test.yml calling it
    # as a negative control (the guard must refuse). The ARMED path -- a protected environment,
    # a real tracker -- has never run. The capability is registered observed at TOOL level only:
    # the reconciler itself, live against a personal Jira (see `ticket-reconciliation` below).
    # The armed workflow is completion ledger row T-19, owed (G-02).
    "reusable-ticket-reconcile.yml": ["ticket-reconciliation"],
    # KDEC-013 (2026-10-16): the pull-request Jira reference gate, moved from one consumer's overlay
    # into the core with NO default issue-number range. Reads the PR description; writes nothing.
    "reusable-ticket-reference.yml": ["ticket-reference"],
    # KDEC-018 item 4 (lane L-FX, 2026-10-22): exceptions resurface when they come due, onto their
    # Jira ticket, with their history. Lists without a credential; resurfaces from the protected
    # environment on a schedule. Self-test calls it on push (list only; the resurface job is not armed).
    "reusable-exception-due.yml": ["exception-resurfacing"],
    # FUTURE_WORK section 6, owner 2026-10-22: Dependabot PRs auto-merge (`--auto --squash`, so
    # branch protection still decides) only when every section 6 criterion the kit can establish
    # holds; the rest go to a human with the reason, and excluded fixture paths are closed.
    # TWO CAPABILITIES, because the halves have different evidence: the DECISION (and the gh
    # commands it issues) is proven locally; the GITHUB half -- the token scopes suffice, and
    # branch protection really holds an armed auto-merge until the checks pass -- needs a hosted run.
    "reusable-dependabot-triage.yml": ["dependabot-triage", "dependabot-merge-hosted"],
    "reusable-deploy-appservice.yml": ["deploy-appservice"],
    "reusable-deploy-containerapp.yml": ["deploy-containerapp"],
    "workflow-policy-check.yml": ["workflow-policy"],
    # `authorization-boundary-isolation` SPLIT OUT 2026-09-22, when the probe was rewritten from
    # an authentication check into a boundary check. It is NOT azure-oidc-auth at a finer grain:
    # that capability claims an identity can AUTHENTICATE, and three identities that all hold
    # Contributor on the whole subscription satisfy it completely while being entirely
    # un-isolated. It is not context-integrity either -- that one's own comment says an ambient
    # context is NOT an authorization decision, which is exactly the line between them. A
    # capability whose halves have different evidence is two capabilities, same rule as the
    # composites split on 2026-09-18.
    "verify-azure-oidc.yml": ["azure-oidc-auth", "context-integrity",
                              "authorization-boundary-isolation"],
    "action:azure-login-oidc": ["azure-oidc-auth"],
    "action:determine-changes": ["change-detection"],
    "action:docker-build-push": ["image-build", "image-push"],
    # SPLIT 2026-09-18, after the probes ran. Each composite was ONE capability bundling two
    # independent claims, and a successful probe proved only one of them. Leaving the pair
    # `unknown` would have understated what was proven; promoting the pair to `observed` would
    # have asserted an install branch nobody has ever executed. A capability whose halves have
    # different evidence is two capabilities.
    "action:render-version-metadata": ["version-metadata-render", "version-metadata-wired"],
    # V1 verification at deploy (ledger L89; PROVENANCE_AND_ATTESTATION.md section 6). Its
    # classification and rung routing are proven locally against recorded gh answers; the live
    # signature lookup is held behind the plan (see the DEFERRALS entry).
    "action:verify-attestation": ["attestation-verify"],
    "action:setup-node": ["toolchain-node-version", "toolchain-node-install"],
    "action:setup-python": ["toolchain-python-version", "toolchain-python-install"],
    "action:setup-terraform": ["toolchain-terraform"],
    # EVIDENCE ASSEMBLY, NOT AN ASSURANCE CLAIM. Decomposition plan §6.5: infrastructure gets no
    # capability name, because naming it would invent a claim to satisfy a registry. The report
    # renders what the scanners established; it establishes nothing about the code itself. Its
    # proof is tests/prove_report_runs_as_shipped.py, and its failure is read by the gate as
    # `needs.report.result`.
    "action:scan-report": [],
    # STAGE 1 RESOLUTION, NOT AN ASSURANCE CLAIM. Same reasoning as scan-report: it reads the policy
    # register and emits what it found; it establishes nothing about the code. Its proofs are
    # tests/prove_gate_reads_rung.py (wiring), tests/prove_gate_policy_enforcement.py (behaviour)
    # and tests/prove_policy_registration.py (the reader).
    "action:resolve-policy": [],
    # THE RUN RECORD (ledger L36): evidence assembly, not an assurance claim -- it restates what the
    # gate established, validated against the schema. Proof: tests/prove_gate_run_record.py.
    "action:run-record": [],
    # THE LEDGER'S WRITE PATH, NOT AN ASSURANCE CLAIM, by the same rule as scan-report: it
    # establishes nothing about the code. Its behaviour is proven by tests/prove_propose_ledger.py
    # (the payload) and tests/prove_propose_ledger_job_scope.py (the job can push one ref and
    # nothing else, run live against a throwaway remote).
    "action:propose-ledger": [],
    # GOVERNANCE, NOT A SCANNER: the only write path (a pull request to the ledger). Moved out of the
    # security workflow 2026-10-15 so no consumer grants the scan a write scope. Its proof is
    # tests/prove_propose_ledger_job_scope.py plus the hosted PR negative control in self-test.
    "reusable-propose-ledger.yml": [],
    # THE POSITION BETWEEN DISCOVER AND THE SCANNERS, NOT AN ASSURANCE CLAIM, by the same rule as
    # scan-report: infrastructure gets no capability name (decomposition plan §6.5). It declares
    # what the scanners CAN read before they run; it establishes nothing about the code. Proven
    # as shipped by tests/test_resolve.py, which runs its steps from this composite; its failure
    # is read by the gate as `needs.resolve.result` (tooling, never NOT_APPLICABLE).
    "action:resolve": [],
    # DISCOVERY, NOT AN ASSURANCE CLAIM, by the same rule: it decides which scanners start and
    # declares what nothing can read (COVERAGE_GAP); it establishes nothing about the code.
    # Proven as shipped by tests/test_discovery.py, which runs its steps from this composite; its
    # failure is read by the gate as `needs.discover.result` (tooling, never NOT_APPLICABLE).
    "action:discover": [],
    # SCANNER COMPOSITES (ledger L64; decomposition plan §6.5): a composite is an IMPLEMENTATION of
    # the job's capability, never a new one, so it carries the job's own name and adds no debt
    # (deferrals are deduplicated by capability). The job still runs it, the gate still reads
    # `needs.<job>.result`; tests/prove_composite_move_equivalence.py holds the move.
    "action:secret-scan": ["secret-scan"],
    "action:sast-cpp": ["sast-cpp"],
    "action:sast-java": ["sast-java"],
    "action:sast-dotnet": ["sast-dotnet"],
    "action:deps-scan": ["deps-scan"],
    "action:iac-scan": ["iac-scan"],
    # D-VF-4 (ledger V-02), lane L-C1: re-measures the IaC scanners' version ranges over the seeded
    # Terraform corpus and fails when scanner-registry.yaml claims more than was measured. A
    # MEASUREMENT OF WHAT A SCANNER CAN READ, not an assurance claim about code -- the same rule as
    # action:resolve, which consumes the ranges. Proven locally by tests/prove_iac_corpus.py.
    "probe-scanner-corpora.yml": [],
}

# What is actually proven, and how. States:
#   observed                          executed + expected behavior on seeded input
#   unknown                           probe exists, has not passed
#   untested                          no probe at all, but something DOES call it
#   never-referenced                  nothing in this repo invokes it -- a decision,
#                                     not a task. A probe cannot close this.
#   requires-integration-environment  provable, but needs resources not provisioned here
VALIDATION_REGISTRY: dict[str, dict] = {
    # tool-level probes in validate-scanners.yml (prove the TOOL, not the workflow wiring)
    "sast-semgrep":  {"probe": "scanners/semgrep",   "state": "observed",  "level": "tool"},
    "sast-bandit":   {"probe": "scanners/bandit",    "state": "observed",   "level": "tool"},
    "sast-go":       {"probe": "scanners/gosec",     "state": "observed",  "level": "tool"},
    "sast-cpp":      {"probe": "scanners/flawfinder","state": "observed",  "level": "tool"},
    "sast-dotnet":   {"probe": "scanners/dotnet",    "state": "observed",  "level": "tool"},
    "deps-scan":     {"probe": "scanners/trivy",     "state": "observed",  "level": "tool"},
    "malicious-deps":{"probe": "scanners/osv",       "state": "observed",  "level": "tool"},
    "iac-scan":      {"probe": "scanners/checkov",   "state": "observed",   "level": "tool"},
    "sbom":          {"probe": "scanners/syft",      "state": "observed",   "level": "tool"},
    "secret-scan":   {"probe": "secret-rules",       "state": "observed",   "level": "tool"},
    "nvd-dependency-check": {"probe": "scanners/depcheck", "state": "observed", "level": "tool",
                             "blocker": "detection on the seeded fixture is proven; currency against a LIVE NVD feed "
                                        "is a separate claim and remains unproven without a sustained NVD_API_KEY run"},
    # workflow/governance-level
    "security-gate":   {"probe": "gate-behavior", "state": "observed", "level": "workflow"},
    "workflow-policy": {"probe": "self-test/dogfood-policy", "state": "observed", "level": "workflow"},
    # Proven through the CONSUMER path (run 31850914867), not merely wired. sast-java in
    # particular previously had NO scanner step at all and reported success on every run.
    # Proven live 2026-08-14 against a real tenant: run 31821678979, environment `prod`,
    # subject repo:<ORG>/<REPO>:environment:prod, `az account show` returned, 0 resources created.
    # STILL observed, and the citation now needs a caveat it did not need before. The probe file
    # was REWRITTEN on 2026-09-22, so the cited run exercised a prior implementation. The evidence
    # survives because what it established -- that this federated credential subject is accepted
    # and mints a usable Azure session -- depends on the login step and the subject form, and
    # both are unchanged. Everything the rewrite added sits AFTER login and is claimed separately
    # under authorization-boundary-isolation. If the login step or the subject form changes, this
    # citation dies with it.
    "azure-oidc-auth": {"probe": "verify-azure-oidc.yml", "state": "observed", "level": "workflow"},
    # OBSERVED 2026-10-15 against the real tenant, environment `test`, on its own stated condition
    # (all three halves of the deferral's `proves`):
    #   run 38832628162 (trunk 1e7ce9f)  verdict PASS, estate UNCHANGED: own workload and entitled
    #                    shared groups REACHED; a sibling product's workload group, an empty
    #                    opposite-tier group holding no assignments, and a subscription-scope
    #                    validate all REFUSED. Discrimination DISTINCTION_NOT_OBSERVABLE: the
    #                    nonexistent control scope is also refused, so a REFUSED proves the name is
    #                    unreadable to this identity, not that it denotes a real group -- the
    #                    sibling and opposite-tier groups are known to exist from outside the run.
    #   run 38832634828  SEEDED: a group the identity CAN read, declared in the refused position,
    #                    was REACHED -> boundary_breaches=1, verdict FAIL, run failed, estate
    #                    UNCHANGED. The assertion fails when it should.
    #   run 38850408850 (trunk f398206, carrying 2d79dd4)  the same inputs, PASS, and every refused
    #                    row now prints its body: "(AuthorizationFailed) The client ... does not have
    #                    authorization to perform action
    #                    'Microsoft.Resources/subscriptions/resourcegroups/read'" for the sibling and
    #                    opposite-tier groups, and {"code": "AuthorizationFailed", ...} for the
    #                    subscription-scope validate. Before 2d79dd4 that body reached no log.
    # Bound: one identity, one environment, resource-group READ and subscription-scope VALIDATE.
    # Write refusal inside a sibling group is not probed; it is implied by read refusal only for
    # role definitions that pair them, which is the usual case and not a proof.
    "authorization-boundary-isolation": {"probe": "verify-azure-oidc.yml (runs 38832628162, "
                                                  "38832634828, 38850408850)",
                                         "state": "observed", "level": "workflow"},
    # Positive path observed 2026-08-14 (run 31825375559): tenant, subscription and workload
    # identity all matched the declared values. The REFUSAL path has no fixture — an assertion
    # that has never failed is decoration, so this stays unknown until a deliberate mismatch
    # is proven to hard-fail. Same standard the negative control holds the scanners to.
    # OBSERVED 2026-10-15, REFUSAL PATH, against the real tenant, from the trunk branch the `test`
    # environment admits (b293e36):
    #   run 38826929579  expect_tenant_id declared as the nil GUID. Token claims PASS (subject form
    #                    ID_QUALIFIED), the real OIDC login SUCCEEDS, then "Assert context integrity"
    #                    HARD FAILS: "tenant observed does not equal declared (DECLARED) ...
    #                    Authentication succeeded but landed in an UNEXPECTED context. Refusing".
    #                    Nothing after it ran.
    #   run 38826938462  the control, nothing declared: the same step PASSES on the same login.
    #                    (It then stopped at the scope snapshot on placeholder resource-group names --
    #                    the authorization-boundary capability, still deferred, not this one.)
    # A mismatch that the step could never see before 8b36c09 (it compared the session only to
    # the secrets the login used) is now seen and refused, and the matching case is not.
    "context-integrity": {"probe": "verify-azure-oidc.yml (runs 38826929579, 38826938462)",
                          "state": "observed", "level": "workflow"},
    # OBSERVED 2026-09-18, self-test run 35393378558, job `Normalizer drift`. The probe requested a
    # version the runner was demonstrably NOT on and asserted the requested one became ACTIVE:
    #
    #   runner has python 3.12 / node 22 ; requested 3.11 / 20
    #   python: requested 3.11, active 3.11.16   ok
    #   node:   requested 20,   active 20.20.2   ok
    #
    # That asymmetry is what makes it evidence. A probe asserting "some python exists" passes
    # against a composite that does nothing at all.
    "toolchain-python-version": {"probe": "self-test/toolchain-probes", "state": "observed", "level": "action"},
    "toolchain-node-version":   {"probe": "self-test/toolchain-probes", "state": "observed", "level": "action"},
    # OBSERVED in the same run: the composite rendered, carried the identity chain, and refused to
    # overclaim. It ALSO caught a real defect on its first execution -- an all-digit sbom hash
    # passed unquoted was typed by YAML as a number and reached the stamp as "1.11111111111111E+63".
    # Shape validation and the quoted probe input are both in place and re-run.
    "version-metadata-render":  {"probe": "self-test/provenance-probe", "state": "observed", "level": "action"},
    # OBSERVED 2026-10-14, locally, by running the job's OWN Ruff and ESLint steps extracted from
    # the workflow as shipped, with the real tools, against seeded and clean fixtures:
    # tests/prove_code_quality_enforces.py. Seeded violations fail with enforce_lint on and are
    # reported without blocking when it is off. The probe found and closed two defects on its first
    # run: both steps exited 0 on violations with enforcement on. Level `tool`, not `workflow`: the
    # job's place in a real dispatched run is the end-to-end claim tracked separately.
    "code-quality": {"probe": "tests/prove_code_quality_enforces.py", "state": "observed",
                     "level": "tool"},
    # OBSERVED 2026-10-14, locally: the job's own scan and enforce steps, extracted as shipped and
    # run with the real semgrep, find a seeded SQL-built-by-concatenation flaw
    # (java.lang.security.audit.formatted-sql-string), count it, and fail enforcement with
    # soft_fail_sast off; clean Java yields zero; a tree with no Java skips.
    # tests/prove_sast_java_detects.py. The steps needed no fix -- this closes the deferral by proof.
    # OBSERVED 2026-10-14, locally, by running the NVD workflow's own shipped Trivy steps with the
    # real Trivy: seeded CVEs reach the SARIF the summary reads and the armed gate fails on them; a
    # clean tree passes; the Dockerfile step reports a seeded misconfiguration and skips explicitly
    # when there is none (report-only by design). Closed by proof, not by a new date (KDEC-005).
    "nvd-trivy": {"probe": "tests/prove_nvd_trivy_detects.py", "state": "observed", "level": "tool"},
    "nvd-dockerfile": {"probe": "tests/prove_nvd_dockerfile_detects.py", "state": "observed",
                       "level": "tool"},
    "sast-java": {"probe": "tests/prove_sast_java_detects.py", "state": "observed",
                  "level": "tool"},
    # OBSERVED 2026-10-14, locally: the job's trivy-action `with:` blocks, read as shipped and
    # translated flag for flag, run by the real Trivy against images built byte by byte (outdated
    # openssl; a credential; nothing). CVEs fail with advisory off and are reported with it on; a
    # credential fails in every mode; a clean image passes. tests/prove_image_scan_enforces.py.
    # The probe found and closed one defect on its first run: one step scanned vuln+secret under
    # an advisory exit code, so a baked-in credential passed in advisory mode.
    "image-scan": {"probe": "tests/prove_image_scan_enforces.py", "state": "observed",
                   "level": "tool"},
    # OBSERVED 2026-10-15 ON THE LEVEL 2 CONSUMER -- a genuinely separate private repository
    # calling reusable-security.yml by owner/repo@sha -- on its own stated closing condition:
    #   run 38817782084 (kit at 1a5f6f9): seeded flaws in two languages produced CodeQL results
    #     under the expected SARIF categories -- python.sarif, automationDetails.id
    #     /language:python/, 5 results (py/command-line-injection, py/path-injection,
    #     py/reflective-xss, py/unsafe-deserialization, py/weak-sensitive-data-hashing);
    #     javascript.sarif, /language:javascript-typescript/, 4 results (js/code-injection,
    #     js/command-line-injection, js/missing-rate-limiting, js/reflected-xss); CodeQL 2.27.2,
    #     security-extended; the job's own state COMPLETE for both legs. The four languages
    #     absent from that repository (go, csharp, java-kotlin, c-cpp) read NOT_APPLICABLE in the
    #     gate's state files. Publication to the Security tab was refused (no licence on a
    #     private repository); the analysis ran anyway, which is exactly what the deferral's
    #     "skipped/unlicensed states" needed one dispatch to establish.
    #   That run ALSO found two defects in how the gate READ those results -- the
    #     javascript-typescript row looked for a file analyze never writes, and a retained
    #     analysis was called UNAVAILABLE on the platform pre-flight (6431c5e, f7a7ed1;
    #     tests/prove_codeql_rows_read_sarif.py) -- so the closure is cited on the re-run:
    #   run 38820564939 (kit at f7a7ed1): same results, same categories, and the gate's rows now
    #     read them -- codeql-python and codeql-javascript-typescript APPLICABLE / COMPLETE /
    #     their SARIF RETAINED / PASS; the four absent languages NOT_APPLICABLE.
    # Level `workflow`: the job, its matrix gating, its SARIF categories and the gate's reading
    # of them, on a runner, cross-repository. Still open and recorded elsewhere: the resolve
    # position caps the job PARTIAL on the same pre-flight (docs/KNOWN_DEFECTS.md D-10).
    "codeql": {"probe": "Level 2 consumer dispatch (runs 38817782084, 38820564939)",
               "state": "observed", "level": "workflow"},
    # OBSERVED 2026-10-15, locally: the composite's own install step, extracted as shipped and run
    # with a real pip in a throwaway venv, installs a pinned fixture requirement (importable
    # afterwards at the pinned version) and REPORTS it; a requirement nothing can resolve FAILS the
    # step for that reason; an absent file is SKIPPED and says so. The probe found the half the
    # deferral named on its first run -- the composite installed and reported nothing -- and the
    # fix (a typed install_state and an `installed` list from pip's own report) is what it now
    # proves. Closed by proof, not by a new date (KDEC-005). tests/prove_setup_python_installs.py.
    "toolchain-python-install": {"probe": "tests/prove_setup_python_installs.py",
                                 "state": "observed", "level": "action"},
    # OBSERVED 2026-10-15, locally: the composite's install step, extracted as shipped and run with
    # the real npm, installs a lockfile fixture (one package, pinned by version and integrity) and
    # REPORTS it from what is on disk; a lockfile out of sync with package.json and a missing
    # lockfile each FAIL for that reason, so nothing is ever installed from a floating resolution;
    # install=false is SKIPPED and says so. First run found the composite reported nothing; the fix
    # (install branch taken in-script so SKIPPED is written, typed install_state, on-disk
    # `installed` list) is what it now proves. Closed by proof (KDEC-005).
    "toolchain-node-install": {"probe": "tests/prove_setup_node_installs.py",
                               "state": "observed", "level": "action"},
    # OBSERVED 2026-10-15, locally, against a REAL registry: a local `registry:2` (the OCI
    # distribution API an ACR speaks) on a free loopback port, and the build job's own steps --
    # built, sbom, build_inputs, push_capability, push, assert_identity, provenance, posture --
    # extracted as shipped and run with the real docker, buildx, jq and syft. The only translation
    # is docker/build-push-action's `with:` block, flag for flag, refusing any key it cannot
    # translate (the image-scan proof's method). tests/prove_build_push_round_trip.py.
    #   image-build   the config digest the build reported is the one `built` establishes; the SBOM
    #                 names the fixture component (kit-fixture-component 1.2.3) and sbom_sha256 is
    #                 its hash
    #   image-push    the digest the push step emitted is served by the registry at
    #                 /v2/<repo>/manifests/<digest> (an HTTP read, independent of docker) with a
    #                 matching Docker-Content-Digest; assert_identity passes; the class is
    #                 REGISTRY_IDENTITY_PROVEN; an unreachable registry refuses BEFORE the push; a
    #                 digest never pushed is 404, not manufactured
    #   version-metadata-wired
    #                 the job `outputs:` map, the workflow `outputs:` map and the shipped caller
    #                 template's `with:` map, read from the YAML and substituted as GitHub does,
    #                 carry that digest, the scanned config, the identity class, the sbom hash and
    #                 the build inputs into render-version-metadata as shipped; a failed round trip
    #                 (scanned bytes are not the pushed bytes) reaches the stamp as
    #                 IDENTITY_UNVERIFIED, never PROVEN. READING: the composite is called by
    #                 templates/build-deploy.yml, the kit's shipped build-and-deploy path; neither
    #                 reusable calls it, by design (PROVENANCE_AND_ATTESTATION.md section 2.3). If
    #                 "a deploy workflow" is read as the reusable only, reopen this one.
    # Level `tool`, not `workflow`: the Trivy gate (a `uses:` step, tests/prove_image_scan_enforces.py)
    # is not run and posture reads it as skipped; a hosted dispatch of reusable-build-docker.yml
    # against an ACR behind Azure identity is the end-to-end claim and is still owed. The steps
    # needed no fix -- closed by proof (KDEC-005), the way sast-java was.
    # RAISED TO `workflow` 2026-10-15 by the end-to-end claim the paragraph above said was owed:
    # reusable-build-docker.yml dispatched through live-deploy-acceptance.yml (adapter=build, the
    # trunk ref, environment test) against a sandbox ACR behind the test identity's OIDC login.
    # Runs 38857011286, 38857017667, 38857024014 (the three tests/fixtures/deploy-probe images):
    # build once, the Trivy gate RAN before the push (success), SBOM, push-capability, push of the
    # scanned bytes, identity assertion -> REGISTRY_IDENTITY_PROVEN. The digests the runs printed
    # (329256a0..., 18a007d0..., 926745b2...) were confirmed independently by `az acr repository
    # show`, and the same digests were then deployed by the deploy reusables (runs 38857259257,
    # 38857271571, 38858033863) -- one artefact identity from build to running revision.
    "image-build": {"probe": "live-deploy-acceptance.yml adapter=build (runs 38857011286, "
                             "38857017667, 38857024014); tests/prove_build_push_round_trip.py",
                    "state": "observed", "level": "workflow"},
    "image-push": {"probe": "live-deploy-acceptance.yml adapter=build (runs 38857011286, "
                            "38857017667, 38857024014); tests/prove_build_push_round_trip.py",
                   "state": "observed", "level": "workflow"},
    # OBSERVED 2026-10-15 against a real Azure Container App (multiple revision mode, pulling from
    # the sandbox ACR with its own identity), dispatched from the trunk through
    # live-deploy-acceptance.yml, on the deferral's stated condition -- "rollback contract
    # implemented, then revision rollback verified live, INCLUDING a reversal that meets an object
    # changed by a later release and defers to it rather than reversing out of order":
    #   38853176286  routing_result BLOCKED: refused at the gate step, Azure login never ran,
    #                DEPLOY_REFUSED.
    #   38855599716, 38857259257  A: the created revision probed on its OWN name before traffic,
    #                traffic moved, consumer name verified, DEPLOY_HEALTHY; the second deploys the
    #                digest reusable-build-docker pushed (run 38857017667).
    #   38855747496, 38858033863  C: /health 404 on the new revision, traffic never moved,
    #                REVERSAL_REMOVE (deactivated), ROLLBACK_VERIFIED against a fresh live read,
    #                NOW SERVING the prior revision; the second deploys a kit-built digest.
    #   38855929525  SECOND ACTOR: while the health probe waited, an operator created a newer
    #                revision stamped release_id=run-operator-later-1. The reversal derived
    #                REVERSAL_DEFERRED_TO_SUCCESSOR (P6, "descendant release(s) run-operator-later-1
    #                still stand; reverse them first"), performed nothing, and reported
    #                ROLLBACK_PARTIAL naming both standing revisions -- deferred, not reversed out
    #                of order -- with production still on the prior revision.
    #   38856714492  traffic following the latest revision (the shape `create` leaves): pinned
    #                before the update (ece9d00); public /health answered 200 on all sixteen
    #                samples during the run; ROLLBACK_VERIFIED.
    # Two defects were found BY these runs and fixed test-first: ece9d00 (traffic following latest
    # moved to an unverified revision at once -- observed before any dispatch) and fe606ae (the
    # pin's restore withheld as UNTRUSTED because `revision list` omits inactive revisions). The
    # 38856714492 evidence stands; fe606ae removes the withheld residue it showed.
    # Not claimed: B (partial mutation) and D (reconciliation lost) were not induced live -- they
    # remain stub-proven (prove_deploy_outcome gap8); E needs a release graph.
    "deploy-containerapp": {"probe": "live-deploy-acceptance.yml (runs 38853176286, 38855599716, "
                                     "38857259257, 38855747496, 38858033863, 38855929525, "
                                     "38856714492)",
                            "state": "observed", "level": "workflow"},
    # OBSERVED 2026-10-16, LIVE, against a sandbox Linux web app on the owner's test subscription,
    # through live-deploy-acceptance.yml calling reusable-deploy-appservice.yml as a consumer does,
    # direct path (slot ''), kit-built digests pulled from the sandbox registry with the app's own
    # identity:
    #   38853184615  tier prod with no slot: refused before login (an irreversible deploy at prod).
    #   38857271571  A: a kit-built healthy digest deployed and serving, prior image recorded.
    #   38878189985  C: an unhealthy kit-built digest; the platform's start record showed the
    #                INTENDED image started (2/18), /health never answered 200, REVERSAL_RESTORE_PRIOR
    #                performed and ROLLBACK_VERIFIED; production read back on the prior image.
    #   38886279650  SECOND ACTOR: while the health probe waited, production was changed to another
    #                image. The run read it back ("not running" this release; "read back" the
    #                actor's image), the reversal derived REVERSAL_REFUSED_CONFLICT
    #                (MODIFIED_BY_EXTERNAL_ACTOR), performed nothing, and reported ROLLBACK_PARTIAL
    #                naming the refused entry -- the deferral's stated condition.
    # Defects found BY these runs and fixed test-first: 6ee04c3 (a 200 from the PREVIOUS container
    # was read as the new one's health -- run 38857408542), bc152db (an unreadable start log named),
    # 6e40dad (an idle F1 site never started its container until requested -- run 38867771912),
    # 95bd5cc (a refused reversal was summarised ROLLBACK_VERIFIED and "now serves" echoed the
    # run's own write -- run 38879879589).
    #   38912063363  SLOT A (2026-10-16, plan at S1 for the test, owner-approved): a healthy kit-built
    #                digest into `staging`, the platform's start record showed the intended image, health
    #                passed on the slot, SWAPPED; production read back on the new image.
    #   38912546778  SLOT C: an unhealthy digest into `staging`; /health never 200 on the slot, NO swap,
    #                production untouched, staging REVERSAL_RESTORE_PRIOR and ROLLBACK_VERIFIED.
    # The slot was deleted and the plan returned to F1 after the test (S1 for 12 minutes).
    # NOT claimed live: a post-SWAP production failure (stub-proven, prove_deploy_outcome live_appservice_reversal_reads_each_entry_fresh); "now serving" compares the CONFIGURED image
    # with the platform's last start reported beside it.
    "deploy-appservice":   {"probe": "live-deploy-acceptance.yml (runs 38853184615, 38857271571, "
                                     "38878189985, 38886279650, 38912063363, 38912546778)",
                            "state": "observed", "level": "workflow"},
    # OBSERVED 2026-10-15/16, LIVE, on the owner's PERSONAL Jira (never a consumer's tracker), by
    # tests/live_ticketing_run.py with transcripts kept outside this neutral repository:
    #   R-1  four deliberately broken settings (host, token, project, stamp field) each refused at
    #        run start BY NAME, zero writes (after a992811: Jira answers a bad token as anonymous,
    #        so the credential is now established first).
    #   R-2  T-1 the first run created one ticket and the identical second run none; T-2 a joined
    #        and a narrowed finding created nothing new.
    #   T-8  the ticket closed with no reopen transition configured: a SUCCESSOR was created carrying
    #        the same stamp and a `predecessor` row, the predecessor kept, reason recorded.
    #   T-7  the successor closed with JIRA_TRANSITION_REOPEN set: the run REOPENED it by that
    #        transition and created nothing.
    #   T-6  a second ticket carrying the same stamp (made by the operator on the owner's account):
    #        BINDING_AMBIGUOUS naming both candidates, nothing written to either.
    # NOT claimed: Azure DevOps live (its inherited process and field exist; the owner has not yet
    # moved the project onto that process). The Azure DevOps backend is proven against stubs only.
    # LEVEL "tool", NOT "workflow" (G-02): the probe is a local script calling the reconciler, never
    # reusable-ticket-reconcile.yml. NOT claimed either: the T-02/T-08/T-13 changes of lane L-T --
    # the live runs above predate them, and the T-2 "joined" run took the description-erasing path
    # T-02 fixed. A live R-2 re-run on the personal Jira is owed for them.
    "ticket-reconciliation": {"probe": "tests/live_ticketing_run.py on a personal Jira (R-1, R-2, T-6..T-8)",
                              "state": "observed", "level": "tool"},
    # OBSERVED 2026-10-16, locally, by running the gate's OWN step extracted from
    # .github/workflows/reusable-ticket-reference.yml as shipped, under bash, with the env: block a
    # runner substitutes: tests/prove_ticket_reference_gate.py (G1..G9). No default range (a
    # two-digit and a five-digit key both pass unconfigured), a consumer range applied to the whole
    # number, a half range refused as a platform problem, the PR body inert in four injection
    # shapes, and a non-PR event NOT ASSESSED. Level `tool`: the self-test calls it on push and
    # dispatch, where it must answer NOT ASSESSED; a pull-request run on a consumer is the end-to-end.
    "ticket-reference": {"probe": "tests/prove_ticket_reference_gate.py", "state": "observed",
                         "level": "tool"},
    # OBSERVED 2026-10-22, locally, by running the workflow's OWN evidence, decision and action steps
    # extracted from .github/workflows/reusable-dependabot-triage.yml under bash with a gh shim:
    # tests/prove_dependabot_triage.py (D1..D8, 42 decisions). Level `tool`: nothing here has run on
    # a runner against a real Dependabot PR; the hosted plan is docs/adoption/DEPENDABOT_TRIAGE.md
    # section 6. Provenance/signature checking (a section 6 criterion) is NOT built and is recorded
    # in every decision as NOT_ESTABLISHED.
    "dependabot-triage": {"probe": "tests/prove_dependabot_triage.py", "state": "observed",
                          "level": "tool"},
    # OBSERVED 2026-10-22, locally (lane L-FX): scripts/exception_due.py against fixture registers and
    # caller workflows, its Jira path against a RECORDING FAKE (comment, reopen, create once, refuse a
    # non-Jira tracker, NOT_CONFIGURED without credentials), and the workflow's own list step run as
    # shipped: tests/prove_exception_due.py (E1..E11). Level `tool`: no hosted run, no real Jira.
    "exception-resurfacing": {"probe": "tests/prove_exception_due.py", "state": "observed",
                              "level": "tool"},
    "version-metadata-wired": {"probe": "tests/prove_build_push_round_trip.py",
                               "state": "observed", "level": "tool"},
    }

# reusable-security.yml has been invoked END-TO-END from a consumer-style caller and every
# seeded signal was detected. Set False the moment that stops being true — this flag is a
# claim about evidence, and a stale claim here re-creates precisely the illusion the
# consumer-path test was built to destroy.
#   evidence: consumer-path-test.yml run 31850914867 (2026-08-14)
#             16/16 seeded signals DETECTED across python, node, dotnet, java, go, cpp,
#             terraform, dockerfile and three Azure/Entra secret classes;
#             1/1 negative controls clean; seeded findings blocked the caller.
#
# SET FALSE 2026-09-22. The moment this comment warned about has arrived, and the flag's own
# instruction is being followed rather than argued with.
#
# reusable-security.yml crossed GitHub's 500 KB workflow-file limit at commit 412ed634 on
# 2026-09-16 (472.1 -> 506.8 KB, now 608.8 KB). GitHub does not fail such a workflow; IT NEVER
# STARTS IT. Zero jobs, a startup failure on every trigger, for six days.
#
# So run 31850914867 is not wrong -- it was true when it was taken, against a ~160 KB file. It is
# EVIDENCE THAT HAS OUTLIVED ITS SUBJECT. The consumer path cannot be proven today because the
# workflow it exercises cannot be invoked at all, and a cited run id is not a freshness
# guarantee: nothing in this registry noticed that its subject had stopped being runnable.
#
# That is the same defect as an SBOM stamped as deployment provenance for an artifact that was
# never pushed. Both are real measurements pointing at something that has since moved.
#
# Restore to True only after reusable-security.yml starts again AND a fresh consumer-path run is
# cited here by id. Not after the split lands -- after a RUN.
#
# RESTORED 2026-10-15, after a RUN, on the trunk commit.
#   evidence: consumer-path-test.yml run 38811950471 on 13f1518 (fix/normalization-and-discovery),
#             its negative run 38811969419; 20/20 seeded signals DETECTED, each pinned scanner
#             independently (python, node, dotnet, java, go incl. second roots, cpp via flawfinder
#             and cppcheck, terraform, dockerfile, and the three Azure/Entra secret classes by
#             gitleaks, delivered through the test-only seed input, KDEC-011); 1/1 negative
#             control clean; 0 expectations absent; seeded findings blocked the caller.
#             Self-test run 38811959160 on the same commit: success. The flagship is 441 KB as
#             the runner reads it -- if it crosses the size line again, this goes back to False.
CONSUMER_PATH_PROVEN = True

# Provable, but needs resources not provisioned. NOT the same as untestable.
REQUIRES_INTEGRATION_ENV = {
    # `deploy-appservice` left this dict 2026-10-16: a real App Service target is provisioned
    # and observed (see its VALIDATION_REGISTRY entry).
    # `image-push` left this dict 2026-10-15: "a container registry" IS provisioned, by the proof
    # itself (a local registry:2). What a registry cannot stand in for -- an ACR behind the Azure
    # identity -- is azure-oidc-auth's claim and the hosted dispatch, not a registry gap.
}


# ---------------------------------------------------------------- deferrals
# A permanently red check is not a control — it is training. People learn that red means
# "known backlog" and stop reading it, and then a REAL regression arrives wearing the same
# colour as the noise. So there are exactly two outcomes here:
#
#   BLOCKING  something is unaccounted for, or a deferral expired. Act now.
#   ACCEPTED  a deliberate, dated, owned deferral that has not yet expired. Reported, not red.
#
# Every capability that is not `observed` MUST have an entry here. No entry = BLOCKING, which
# preserves the original property: absence is an error state, not a way to avoid scrutiny.
#
# Four required fields, and each exists to stop a specific way deferrals rot:
#   reason   why it is not proven          (stops "we forgot")
#   owner    a role, never a person        (stops orphaning at handoff; keeps the kit portable)
#   proves   what evidence would close it  (stops a deferral becoming a wish)
#   expires  ISO date                      (stops "temporary" becoming permanent)
#
# One OPTIONAL field:
#   trigger  what brings it back into scope (for IMPLEMENTATION_HELD: the blocker is an unbuilt
#            capability, not an unwritten probe, so a date is the wrong instrument. A held item
#            returns when the thing it waits on STARTS, and the date is only a backstop so it
#            cannot be held forever without anyone looking.)
#
# An expired deferral goes BLOCKING. That is the mechanism: it forces a fresh decision instead
# of letting silence renew the old one. Re-dating is a legitimate outcome — doing it without
# looking is not, which is why the reason has to be rewritten to move the date.
DEFERRALS: dict[str, dict] = {
    # -- cheap: no infrastructure needed, so the only cost is someone writing the probe -----
    # Re-dated 2026-09-18 on a FRESH DECISION, not by silence. The old reason -- "composite never
    # executed" -- is no longer true: both now run at the end of the self-test's normalizer-drift
    # job. What is still unproven is narrower and is stated as such.
    #
    # The first execution immediately found something no amount of reading had: `setup-node`
    # hardcoded `cache: npm` with no `cache-dependency-path`, and upstream looks for a lock file in
    # the REPOSITORY ROOT ONLY. It would have failed on first use in this repo and in any monorepo.
    # A composite is not correct because it parses.
    # THE HALVES THE PROBES DID NOT REACH. Split from the pair on 2026-09-18 rather than left
    # whole: a successful probe that closes half a capability must not be allowed to close the
    # other half by association, and it must not be forced to leave the proven half open either.
    # `toolchain-node-install` CLOSED 2026-10-15 by proof (KDEC-005): see the VALIDATION_REGISTRY
    # entry. Its `proves` -- "a fixture repository where `npm ci` installs from a lockfile and the
    # composite reports what it installed" -- is met locally, with the real npm; the hosted
    # install:false probe stands, and the argument for not assuming this half was fine held: the
    # first execution found the composite reporting nothing.
    # `toolchain-python-install` CLOSED 2026-10-15 by proof (KDEC-005): see the VALIDATION_REGISTRY
    # entry. Its `proves` -- "a fixture requirements file is installed and the composite reports
    # what it installed" -- is met locally, with real pip; the hosted SKIP-branch probe stands.
    # `version-metadata-wired` CLOSED 2026-10-15 by proof (KDEC-005): see the VALIDATION_REGISTRY
    # entry, including the stated reading of "a deploy workflow calls the composite" (the shipped
    # caller template does; the reusables do not, by design).
    # HELD, NOT DEFERRED. Investigated 2026-09-17 rather than retired on the first reading.
    #
    # No current scanner needs the Terraform CLI -- checkov and trivy parse HCL statically -- and
    # that was the whole basis for an initial "retire" recommendation. It was the wrong question.
    # The kit's own ASSURANCE_MODEL_CANDIDATES.md C-1 (code-to-cloud drift reconciliation) is a
    # designed capability, and Terraform plan/state/refresh is one of its comparison surfaces.
    # Several other stages would consume the CLI too, and none of them is a scanner:
    #
    #   semantic validation   `terraform validate` proves configuration is valid against provider
    #                         and module semantics, which static HCL parsing cannot establish
    #   plan-time assurance   `plan -out` + `show -json` yields the actual proposed resource graph:
    #                         what is created, changed or DESTROYED, whether a public endpoint or an
    #                         RBAC change is being introduced, whether the plan matches what a
    #                         reviewer approved. Source files cannot answer any of that.
    #   drift reconciliation  declared config vs state vs provider-observed remote -- the C-1 lens
    #   version assurance     required_version and required_providers are DISCOVERY inputs (see D6),
    #                         and the CLI is how "is the runner compatible with what this repo
    #                         targets" gets established rather than assumed
    #   post-deploy verify    confirming the applied result matches the analysed plan
    #
    # It is NOT needed for container or image scanning; that works off the artifact, the registry
    # and runtime APIs, and Terraform is orthogonal there.
    #
    # A BOUNDARY THAT MUST SURVIVE THIS: Terraform ASSURANCE capability does not imply Terraform
    # MUTATION authority. validate, plan, analyse and compare all produce evidence without any
    # right to `apply`. Mutation belongs behind the environment and enforcement axes, and applying
    # infrastructure at a production tier is a materially different authority from inspecting it.
    #
    # And Terraform must never become the authoritative inventory of the estate: not everything is
    # Terraform-managed, resources predate it, other systems create them, state goes stale, and a
    # workspace only sees what it owns. It is one managed-INTENT lens over reality, never reality.
    "toolchain-terraform": {"reason": "IMPLEMENTATION_HELD -- the CLI has no consumer until the "
                                      "Terraform assurance model (validate / plan analysis / drift "
                                      "reconciliation, ASSURANCE_MODEL_CANDIDATES C-1) is "
                                      "specified. Retiring it would delete a precursor to a "
                                      "designed capability; probing it now would test an orphan in "
                                      "a fixture.",
                            "owner": "kit-maintainer",
                            "proves": "the Terraform assurance model is specified, and this "
                                      "composite is either the implementation it needs or is "
                                      "replaced by one that is",
                            "trigger": "Terraform assurance / deployment model specification begins",
                            "expires": "2026-12-31"},
    # HELD, NOT DEFERRED, decided 2026-09-18. Same instrument as toolchain-terraform and for the
    # same reason: the blocker is an unbuilt capability, not an unwritten probe.
    #
    # A seeded-diff probe is perfectly writable, and it would prove that dorny/paths-filter filters
    # paths. That is not what this composite is FOR. Under the reconciled release model it is the
    # producer of SOURCE_DELTA -- one of four change artefacts, and the weakest of them:
    #
    #   SOURCE_DELTA            what changed in code and config      <- this composite
    #   PLANNED_MUTATION_SET    what the deployment intends to alter
    #   OBSERVED_MUTATION_SET   what actually changed
    #   REVERSAL_MANIFEST       how each observed mutation is compensated
    #
    # A git diff cannot tell you a deployment created a revision, shifted three traffic weights,
    # generated an identity assignment and half-applied a migration. Rollback reads OBSERVED and
    # REVERSAL; it never reads SOURCE_DELTA. So proving the filter now would test an orphan in a
    # fixture and say nothing about the manifest it is meant to feed -- and the manifest does not
    # exist. The date is a backstop so it cannot be held indefinitely without anyone looking.
    # See docs/architecture/DEPLOYMENT_CONTRACT_RECONCILIATION.md §7.3.
    "change-detection":    {"reason": "IMPLEMENTATION_HELD -- the composite produces SOURCE_DELTA, "
                                      "whose consumer (the change manifest) is unbuilt. A seeded-diff "
                                      "probe would prove paths-filter filters paths and nothing about "
                                      "the artefact this is supposed to produce.",
                            "owner": "kit-maintainer",
                            "proves": "the change-manifest model is specified, and this composite is "
                                      "either SOURCE_DELTA's implementation or is replaced by one",
                            "trigger": "change-manifest / mutation-set modelling begins",
                            "expires": "2026-12-31"},
    # Re-dated 2026-09-18 on a fresh decision. The composite now runs, and it now carries the
    # artefact identity CHAIN rather than a bare digest: a stamp that says only `image_digest`
    # reads to every later reader as proof the running artefact was assured, and it is not.
    # technical_provenance is NOT_ESTABLISHED by construction there -- artefact identity is one of
    # eight conditions and this composite can observe none of the other seven.
    # HELD, NOT DEFERRED (ledger L89; PROVENANCE_AND_ATTESTATION.md section 6.4). The blocker is a
    # PLAN, not an unwritten probe: on GitHub Free/Pro/Team a private repository can neither produce
    # nor verify an attestation. The step's five-outcome classification and rung routing are proven
    # locally by tests/prove_attestation_verify.py against recorded gh answers; what no local run can
    # show is a real `gh attestation verify oci://<acr>/...@sha256` lookup (section 11.2).
    # FUTURE_WORK section 6 (owner, 2026-10-22). Proven locally by running the shipped steps; nothing
    # in this repository invokes it, by design: its caller must trigger on pull_request_target and
    # grant write scopes, and the kit's self-test is no place for either. The proof that is owed is a
    # hosted run on the owner's public test repository (Actions minutes there are free), planned in
    # docs/adoption/DEPENDABOT_TRIAGE.md section 6.
    "dependabot-merge-hosted": {"reason": "a hosted run needs a repository receiving Dependabot PRs, "
                                      "with auto-merge allowed and required checks; Actions minutes "
                                      "on the kit's own account are blocked by billing",
                            "owner": "kit-maintainer",
                            "proves": "on a public test repository: a patch dev update is armed with "
                                      "--auto --squash and merges only after the required checks "
                                      "pass; a major is labelled, commented and left open; an "
                                      "excluded-path update is closed with its reason; a "
                                      "pull_request caller is refused",
                            "trigger": "the coordinator's hello-world run (DEPENDABOT_TRIAGE.md "
                                       "section 6)",
                            "expires": "2026-12-31"},
    "attestation-verify":  {"reason": "IMPLEMENTATION_HELD -- the owner's plan (Pro) offers no "
                                      "attestations on private repositories, so V1 cannot be armed "
                                      "there; classification and routing are proven locally only",
                            "owner": "kit-maintainer",
                            "proves": "a hosted run on a PUBLIC repository (or Enterprise Cloud) in "
                                      "which the attest job signs a pushed digest and V1 reads "
                                      "ATTESTATION_VERIFIED for it, and ATTESTATION_ABSENT for an "
                                      "unsigned digest",
                            "trigger": "a repository the kit builds is public, or the account "
                                       "moves to GitHub Enterprise Cloud",
                            "expires": "2026-12-31"},
    # `version-metadata` DELETED 2026-10-21 (completion ledger G-01, lane L-E). It was an ORPHAN:
    # the capability was split on 2026-09-18 into `version-metadata-render` and
    # `version-metadata-wired`, both now observed, and no artifact registers a capability of the
    # old name -- so classify_gap never asked for it, and its 2026-09-30 expiry passed in silence.
    # An expired deferral nobody can reach is the one state the expiry mechanism cannot see.
    # stale_deferrals() below now refuses a deferral key no artifact registers, or one whose
    # capability is already observed.

    # -- needs fixture work ----------------------------------------------------------------
    # `code-quality` CLOSED 2026-10-14 by proof, not by a new date (KDEC-005): see the
    # VALIDATION_REGISTRY entry.
    # `sast-java` CLOSED 2026-10-14 by proof (KDEC-005): see the VALIDATION_REGISTRY entry.
    # FRESH DATED DECISION 2026-10-14 (KDEC-005), not silence: the 2026-09-30 date EXPIRED and was
    # answered by the owner, who chose "ASAP". The NVD workflow carries known defects of its own
    # (ledger L90/L91: $OUTDIR undefined, crashed steps reported executed, fitness check after
    # download) that are fixed and proven locally first; the date is the planned hosted run.
    # `codeql` CLOSED 2026-10-15 by a dispatched run on the Level 2 consumer, on its own stated
    # condition (runs 38817782084 and 38820564939): see the VALIDATION_REGISTRY entry. The
    # deferral's reason -- "its per-language SARIF names and skipped/unlicensed states need one
    # dispatch" -- was right on both counts: the dispatch showed the SARIF names the gate expected
    # were wrong for three legs, and that an unlicensed private repository still runs the
    # analysis and only loses publication. Both are fixed on the evidence, test-first.
    # NEW, 2026-10-14 (KDEC-005). The key is the one this file's end-to-end check classifies under.
    # Fifteen capabilities are proven at tool level, several by running the job's own steps as
    # shipped -- which is stronger than tool level and still not a dispatched run: input threading,
    # job conditions, SARIF categories and the gate's reading of real job results are only proven
    # by GitHub executing the workflow.
    # NEW 2026-10-14. Locally proven against a stubbed HTTP layer (T-1..T-12, B-1); the LIVE proof is
    # tests/live_ticketing_run.py R-1/R-2 on the owner's personal Jira and Azure DevOps, blocked on
    # owner setup: a fresh Jira API token, the Jira stamp field / epic / calibration ticket, and an
    # inherited process for the Azure DevOps project (the Basic system process holds no custom field).
    # `ticket-reconciliation` CLOSED 2026-10-16 on its stated condition, live on Jira: see
    # the VALIDATION_REGISTRY entry. Azure DevOps live remains owed and is not claimed.
    # REASON REWRITTEN 2026-09-22, DATE DELIBERATELY NOT MOVED. The rewrite of the probe gave the
    # refusal path a MECHANISM it did not have: a caller now declares `expect_repository` and
    # `expect_job_workflow_ref_prefix`, so a deliberately wrong declaration can be dispatched and
    # the job must hard-fail on it. That is a fixture that can be built without new
    # infrastructure, where before there was none.
    #
    # It is NOT this deferral's closing condition and `proves` is unchanged. That mechanism
    # compares TOKEN CLAIMS against a declared expectation; this capability is about the
    # tenant / subscription / workload identity observed from the Azure session after login, a
    # different comparison in a different layer. And nothing has been dispatched, so neither has
    # been observed to fail. Moving the date because the path got shorter would be silence
    # renewing the deferral wearing a fresh reason, so the eight-day clock keeps running.
    #
    # REASON REWRITTEN AGAIN 2026-10-15, DATE STILL NOT MOVED. The step compared the session against
    # the three secrets the login had just used, and a changed secret fails the LOGIN one step
    # earlier -- so the refusal was unreachable by any permitted action, at the layer this deferral
    # is about. verify-azure-oidc.yml now takes expect_tenant_id / expect_subscription_id /
    # expect_client_id (compared IN ADDITION to the secrets; tests/prove_context_integrity_refuses.py
    # proves the step as shipped hard-fails on each declared mismatch and leaks no value). That is
    # the fixture at the RIGHT layer, and it is still not a dispatch: run 38820603012 (lane
    # lane/hosted-closures, environment `test`, nil declared tenant) was refused before its first
    # step -- "Branch is not allowed to deploy to test due to environment protection rules" -- and
    # prod admits only main, dev and test only fix/normalization-and-discovery. Admitting a branch
    # is an owner's settings change, not a kit change, and the clock keeps running.
    # `authorization-boundary-isolation` CLOSED 2026-10-15 on its own stated condition: runs
    # 38832628162 (refusals, discrimination reported), 38832634828 (seeded reachable scope in the
    # refused position FAILED) and 38850408850 (the AuthorizationFailed bodies printed, after 2d79dd4).
    # See the VALIDATION_REGISTRY entry. The ratchet follows it down, 7 -> 6.

    # -- genuinely needs infrastructure ----------------------------------------------------
    # `image-build` and `image-push` CLOSED 2026-10-15 by proof (KDEC-005): their reasons were "no
    # registry provisioned" / "no container registry", and a registry is a container the proof
    # starts itself. See the VALIDATION_REGISTRY entry for what the proof established and what it
    # still does not claim (an ACR behind Azure identity; a hosted dispatch).
    # SHARPENED 2026-09-21, and deliberately NOT SPLIT into new entries. The debt ratchet is at
    # 14/14 and the reversal-precondition work (DEPLOYMENT_CONTRACT_RECONCILIATION.md section 8)
    # adds nothing these two do not already own: "this deploy surface is unproven" already covers
    # "its reversal preconditions are unproven". Opening a third deferral for it would exceed the
    # cap and would also be double-counting -- the same capability, described at a finer grain.
    #
    # What DID change is `proves`. It was "rollback verified live", which a single happy-path
    # rollback demo satisfies, and a happy-path demo proves precisely the case the design is not
    # worried about. The bar is now the case that cannot be faked: an object modified or depended
    # on by something else BETWEEN deploy and reversal, and a reversal that refuses to delete it
    # and says so. A deferral whose closing condition is easy to meet is a deferral that closes
    # without the risk going away.
    #
    # LIVE TARGETS EXIST, 2026-10-15; NO DISPATCH YET. A sandbox Container App (multiple revision
    # mode) and a sandbox Linux web app are provisioned, and live-deploy-acceptance.yml is the
    # caller. Before any dispatch, the target itself found a defect: in the shape `az containerapp
    # create` leaves (traffic following the latest revision), the mutate call moved all public
    # traffic to the unverified revision at once, and the stub of that shape showed an unhealthy
    # deploy ending ROLLBACK_PARTIAL with production still on the failed image (fixed and proven
    # in ece9d00). The App Service STAGING SLOT is not provisioned: slots need Standard or higher,
    # so the swap path stays unexercised live until a tier that holds one is approved.
    # `deploy-appservice` CLOSED 2026-10-16 on its stated condition, live: see the
    # VALIDATION_REGISTRY entry (runs 38878189985 rollback verified; 38886279650 second
    # actor refused and reported). The slot swap path is not claimed.
    # `deploy-containerapp` CLOSED 2026-10-15 on its stated condition, live: see the
    # VALIDATION_REGISTRY entry (runs 38855747496 / 38858033863 revision rollback verified;
    # 38855929525 deferred to a later release rather than reversing out of order).

}

# Ratchet. Accepted debt may shrink, never grow. A new deferral must displace an old one or
# raise this number deliberately, in a reviewable diff, with a reason in the commit message.
MAX_ACCEPTED_DEBT = 4    # RAISED 3 -> 4 on 2026-10-22 for dependabot-merge-hosted (FUTURE_WORK 6): a
                         # NEW capability -- the GitHub half of the Dependabot triage (token scopes,
                         # auto-merge held by branch protection) -- whose proof needs a hosted run on
                         # a repository receiving Dependabot PRs. Nothing existing became provable in
                         # this change, so nothing could be displaced. Ratchet it back when it closes.
                         # LOWERED 4 -> 3 on 2026-10-16: ticket-reconciliation observed live on Jira
                         # (R-1, R-2 T-1/T-2, T-6, T-7, T-8).
                         # LOWERED 5 -> 4 on 2026-10-16: deploy-appservice observed live (runs
                         # 38878189985, 38886279650 and the rest cited in its entry).
                         # LOWERED 6 -> 5 on 2026-10-15: deploy-containerapp observed live (runs
                         # 38855747496, 38858033863, 38855929525 and the rest cited in its entry).
                         # LOWERED 7 -> 6 on 2026-10-15: authorization-boundary-isolation observed on
                         # the real tenant (runs 38832628162, 38832634828, 38850408850).
                         # LOWERED 8 -> 7 on 2026-10-15: context-integrity refusal observed on the real
                         # tenant (runs 38826929579, 38826938462).
                         # LOWERED to 8 on 2026-10-15 at the coordinator merge: codeql (Level 2
                         # dispatch) and five closed by local proof below; the limit follows
                         # the debt down.
                         # version-metadata-wired closed by proof against a real local registry.
                         # LOWERED 14 -> 13 on 2026-10-15: toolchain-node-install closed by proof.
                         # LOWERED 15 -> 14 on 2026-10-15: toolchain-python-install closed by proof.
                         # LOWERED 17 -> 15 on 2026-10-14: nvd-trivy and nvd-dockerfile closed by proof,
                         # and a ratchet holds only if its limit follows the debt DOWN as well.
                         # RAISED 14 -> 15 on 2026-09-22 for authorization-boundary-isolation.
                         # RAISED 15 -> 16 on 2026-10-14 for ticket-reconciliation: a NEW capability
                         # (reusable-ticket-reconcile.yml) whose proof needs the owner to provision
                         # tracker prerequisites; it displaces nothing because nothing else closed.
                         # RAISED 16 -> 17 on 2026-10-14 for attestation-verify (L89): a new capability
                         # whose blocker is the owner's plan, held with a plan trigger. The two
                         # raises were made in parallel lanes and are combined at merge.
# Raised, not displaced, because nothing was available to displace: no existing deferral became
# provable in this change. Raising the cap to admit a claim nobody had made before is the
# sanctioned move; quietly not registering the claim so the number stayed at 14 would have been a
# gate reporting clean on a narrower denominator, which this file exists to prevent. Ratchet it
# back the moment that entry closes -- it needs a dispatch, not infrastructure.

DEFERRAL_WARN_DAYS = 14      # surface an approaching expiry before it turns red

# The one deferral key no artifact registers by design: classify_gap() asks for it when a tool-level
# capability exists while CONSUMER_PATH_PROVEN is False (the end-to-end claim, not a capability).
synthetic_deferral_keys = frozenset({"azure-oidc-auth-e2e"})


def stale_deferrals() -> list[str]:
    """-> one BLOCKING line per deferral that can no longer be reached or is no longer owed.

    A deferral is consulted only when classify_gap() asks for its capability. So a key that no
    artifact registers is never consulted -- its expiry passes and nothing turns red (G-01: the
    `version-metadata` orphan expired 2026-09-30 and was silently ignored for three weeks). And a
    deferral for a capability already observed is never consulted either, while its text still
    tells a reader the capability is unproven. Both are refused by name.
    """
    registered = {c for caps in CAPABILITY_REGISTRY.values() for c in caps}
    out = []
    for key in sorted(DEFERRALS):
        if key in synthetic_deferral_keys:
            continue
        if key not in registered:
            out.append(f"deferral `{key}` is an ORPHAN: no artifact in CAPABILITY_REGISTRY registers "
                       f"a capability of that name, so nothing ever consults it and its expiry "
                       f"({DEFERRALS[key].get('expires')}) can pass in silence. Delete it, or "
                       f"register the capability it defers.")
        elif VALIDATION_REGISTRY.get(key, {}).get("state") == "observed":
            out.append(f"deferral `{key}` is STALE: VALIDATION_REGISTRY already records the "
                       f"capability as observed, so the deferral is never consulted while its "
                       f"text still says it is unproven. Delete it.")
    return out

# ---------------------------------------------------------------- discovery

def classify(path: str) -> str:
    doc = yaml.safe_load(open(path, encoding="utf-8")) or {}
    on = doc.get("on", doc.get(True)) or {}
    if isinstance(on, dict) and "workflow_call" in on:
        return "reusable"
    name = os.path.basename(path)
    if name in ("self-test.yml", "validate-scanners.yml",
                "consumer-path-test.yml", "consumer-path-negative.yml",
                "live-deploy-acceptance.yml"):
        return "test-harness"
    return "orchestration"



def composite_callers() -> dict:
    """-> {action name: [files that use it]}. Empty list means nothing invokes it.

    A composite that exists and is referenced nowhere is not an untested capability. It is an
    undecided one: wired-and-never-finished, retired-but-not-removed, or intended for consumers to
    call directly. Reporting it as "untested" offers a probe as the fix, and a probe would exercise
    it in a fixture while the pipeline still never touches it.
    """
    callers: dict = {}
    for p in sorted(glob.glob(".github/actions/*/action.yml")):
        callers[os.path.basename(os.path.dirname(p))] = []
    hay = sorted(glob.glob(".github/workflows/*.yml")) + sorted(glob.glob("templates/*.yml"))
    for f in hay:
        try:
            body = open(f, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for a in callers:
            # `uses: ./.github/actions/<name>` in any of its spellings.
            if ("actions/" + a) in body:
                callers[a].append(os.path.basename(f))
    return callers


def discover() -> tuple[dict, list]:
    arts: dict[str, dict] = {}
    for p in sorted(glob.glob(".github/workflows/*.yml")):
        n = os.path.basename(p)
        kind = classify(p)
        doc = yaml.safe_load(open(p, encoding="utf-8")) or {}
        arts[n] = {"kind": kind, "jobs": sorted(doc.get("jobs") or {})}
    for p in sorted(glob.glob(".github/actions/*/action.yml")):
        arts["action:" + os.path.basename(os.path.dirname(p))] = {"kind": "composite-action", "jobs": []}
    return arts, sorted(arts)


_CALLERS: dict = {}


def main() -> int:
    global _CALLERS
    _CALLERS = composite_callers()
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--today", default=None,
                    help="ISO date override; makes expiry behaviour testable instead of "
                         "depending on the day the suite happens to run")
    a = ap.parse_args()

    today = (datetime.date.fromisoformat(a.today) if a.today else datetime.date.today())

    arts, _ = discover()
    blocking: list[str] = []      # act now
    accepted: list[dict] = []     # dated, owned, not yet expired
    rows: list[dict] = []

    classified: set[str] = set()

    def classify_gap(cap: str, why: str) -> None:
        """Unproven capability -> BLOCKING unless a complete, unexpired deferral covers it."""
        # ONE CAPABILITY IS ONE DECISION, whichever artifact surfaced it.
        #
        # The accepted path already deduplicated -- "registered on more than one artifact; still
        # one piece of debt" -- and the BLOCKING path did not, because every blocking.append
        # returns before reaching that guard. So an ACCEPTED deferral counted once and an EXPIRED
        # one counted twice: nvd-trivy and nvd-dockerfile are registered on both
        # reusable-nvd-cve.yml and nvd-cve.yml, and reported 8 BLOCKING where 6 decisions exist.
        #
        # Inflating its own count is a specific harm for this file, not a cosmetic one. The whole
        # argument for the ratchet is that red means act now; a red that overstates what it is
        # counting teaches the reader to discount it, which is the same failure as a permanently
        # red check arriving by a different route.
        #
        # The per-artifact detail is not lost: `rows` still carries a row per artifact. Only the
        # duplicate decision line is suppressed.
        if cap in classified:
            return
        classified.add(cap)
        d = DEFERRALS.get(cap)
        if d is None:
            blocking.append(f"{why} — and no deferral in DEFERRALS. Either write the probe, or "
                            f"record a dated deferral saying why not.")
            return
        missing = [k for k in ("reason", "owner", "proves", "expires") if not d.get(k)]
        if missing:
            blocking.append(f"deferral for `{cap}` is incomplete: missing {', '.join(missing)}. "
                            f"An incomplete deferral is an excuse, not a decision.")
            return
        try:
            exp = datetime.date.fromisoformat(d["expires"])
        except ValueError:
            blocking.append(f"deferral for `{cap}` has an unparseable expires: {d['expires']!r}")
            return
        if exp < today:
            blocking.append(f"deferral for `{cap}` EXPIRED {d['expires']} "
                            f"({(today - exp).days}d ago). Prove it, or make a fresh dated "
                            f"decision — silence must not renew a deferral.")
            return
        if any(x["capability"] == cap for x in accepted):
            return          # registered on more than one artifact; still one piece of debt
        accepted.append({"capability": cap, "days": (exp - today).days, **d})

    for name, meta in arts.items():
        if meta["kind"] == "test-harness":
            continue                                    # the harness is not the thing under test
        caps = CAPABILITY_REGISTRY.get(name)
        if caps is None:
            blocking.append(f"{name}: exists but has NO capability registration. A new artifact "
                            f"nobody registered is drift — this can never be deferred.")
            continue
        for cap in caps:
            v = VALIDATION_REGISTRY.get(cap)
            if v is None:
                if cap in REQUIRES_INTEGRATION_ENV:
                    rows.append({"artifact": name, "capability": cap, "probe": "-",
                                 "state": "requires-integration-environment",
                                 "note": REQUIRES_INTEGRATION_ENV[cap]})
                    # "needs infrastructure" is a reason to defer, never a reason to be exempt.
                    # Without this it would sit unproven forever and never appear as debt.
                    classify_gap(cap, f"{name}: capability `{cap}` needs an integration environment")
                elif name.startswith("action:") and not _CALLERS.get(name[7:], []):
                    # NOT A TESTING GAP. Nothing in this repository invokes this composite, so
                    # there is no in-situ execution a probe could verify. Writing one would prove
                    # the action works in a fixture and say nothing about the kit.
                    rows.append({"artifact": name, "capability": cap, "probe": "-",
                                 "state": "never-referenced",
                                 "note": "no workflow or template uses it"})
                    classify_gap(cap, f"{name}: capability `{cap}` is NEVER REFERENCED -- "
                                      f"nothing in this repo invokes the composite. Decide what it "
                                      f"is (wire it, retire it, or declare it consumer-facing) "
                                      f"before deciding whether to test it.")
                else:
                    rows.append({"artifact": name, "capability": cap, "probe": "-",
                                 "state": "untested", "note": ""})
                    classify_gap(cap, f"{name}: capability `{cap}` has NO validation probe")
            else:
                rows.append({"artifact": name, "capability": cap, "probe": v["probe"],
                             "state": v["state"], "note": v.get("blocker", ""),
                             "level": v.get("level", "")})

    # Workflow-level wiring is a distinct claim from tool-level execution.
    # Previously every tool-level probe was reported as a gap, because reusable-security.yml
    # had never been invoked as a consumer invokes it. It has now: consumer-path-test.yml
    # drives it against a 16-signal multi-language fixture and every signal was DETECTED
    # (run 31850914867, 2026-08-14), with the negative control staying clean. Tool-level proof
    # is no longer the only evidence, so this is no longer a coverage gap.
    tool_only = [r for r in rows if r.get("level") == "tool" and not CONSUMER_PATH_PROVEN]
    if tool_only:
        classify_gap("azure-oidc-auth-e2e",
                     f"{len(tool_only)} capabilities are proven at TOOL level only — "
                     "reusable-security.yml has never been invoked end-to-end, so input threading, "
                     "language selectors, SARIF categories and gate wiring are UNPROVEN")

    # A probe that exists but has never passed is unproven too, and is deferred like anything else.
    for r in rows:
        if r["state"] == "unknown":
            classify_gap(r["capability"],
                         f"{r['artifact']}: capability `{r['capability']}` has a probe that has NOT passed")

    # A deferral nothing consults is debt the ratchet cannot see (G-01).
    blocking.extend(stale_deferrals())

    # Ratchet: debt may shrink, never grow.
    if len(accepted) > MAX_ACCEPTED_DEBT:
        blocking.append(f"accepted debt grew to {len(accepted)}, over the ratchet of "
                        f"{MAX_ACCEPTED_DEBT}. New debt must displace old debt, or the ratchet "
                        f"must be raised deliberately in a reviewable diff.")

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1

    if a.json:
        print(json.dumps({"artifacts": arts, "rows": rows, "counts": counts,
                          "blocking": blocking, "accepted": accepted}, indent=2))
    else:
        by_kind: dict[str, list[str]] = {}
        for n, m in arts.items():
            by_kind.setdefault(m["kind"], []).append(n)
        print("== IMPLEMENTATION INVENTORY ==")
        for k in sorted(by_kind):
            print(f"  {k} ({len(by_kind[k])}): {', '.join(sorted(by_kind[k]))}")
        print("\n== CAPABILITY x VALIDATION ==")
        print(f"  {'capability':24s} {'artifact':34s} {'probe':22s} state")
        for r in sorted(rows, key=lambda x: (x["state"], x["capability"])):
            print(f"  {r['capability']:24s} {r['artifact']:34s} {r['probe']:22s} {r['state']}"
                  + (f"   [{r['note']}]" if r["note"] else ""))
        print("\n== COUNTS ==")
        for s, c in sorted(counts.items()):
            print(f"  {s:34s} {c}")
        print(f"  {'TOTAL capabilities':34s} {sum(counts.values())}")
        if accepted:
            print(); print("== ACCEPTED DEBT — dated, owned, expiring. NOT a failure. ==")
            for d in sorted(accepted, key=lambda x: x["days"]):
                soon = "  <-- EXPIRES SOON" if d["days"] <= DEFERRAL_WARN_DAYS else ""
                print(f"  {d['capability']:24s} expires {d['expires']} "
                      f"({d['days']:>3}d) owner={d['owner']}{soon}")
                print(f"  {'':24s}   closes when: {d['proves']}")
            print(); print(f"  {len(accepted)}/{MAX_ACCEPTED_DEBT} of the debt ratchet used.")

        if blocking:
            print(); print("== BLOCKING — ACT NOW ==")
            for b in blocking:
                print(f"  ! {b}")

    for d in accepted:
        if d["days"] <= DEFERRAL_WARN_DAYS:
            print(f"::warning title=Deferral expiring::`{d['capability']}` goes BLOCKING in "
                  f"{d['days']}d ({d['expires']}). Closes when: {d['proves']}")

    if blocking:
        print(); print(f"::error::VALIDATION_COVERAGE_GAP — {len(blocking)} BLOCKING. This is not backlog: "
              "something is unregistered, undeferred, or a deferral expired.")
        return 1

    print(); print(f"::notice::Validation coverage OK — 0 blocking, {len(accepted)} accepted deferrals "
          "(all dated, owned, unexpired). Red here always means act now.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
