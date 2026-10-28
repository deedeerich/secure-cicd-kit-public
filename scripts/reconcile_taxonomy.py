#!/usr/bin/env python3
"""Reconcile the controlled vocabulary in use against assurance-taxonomy.yaml.

WHY THIS IS A CONTROL AND NOT A GLOSSARY

These words drive enforcement. `UNAVAILABLE` decides whether a build blocks. `PARTIAL` decides
whether a claim was established. Before this existed they were used across fourteen files and
defined in none, while two disposition classes lived only in conversation.

This kit has already produced the exact failure a scattered vocabulary invites: the same decisions
recorded in two places, one stale, the stale one looking authoritative. A registry nobody checks
becomes the second list.

So it is checked two ways:

  DRIFT     a taxonomy-shaped token used in the kit but absent from the registry
  ORPHAN    a registered term used nowhere, which is either dead vocabulary or an unimplemented
            promise -- both worth knowing, neither automatically wrong

Orphans WARN. Drift FAILS: an enforcement word nobody defined is how `PARTIAL` quietly becomes
`PASS` three layers downstream.
"""

import io
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("PyYAML required"); sys.exit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REG = os.path.join(ROOT, "assurance-taxonomy.yaml")

SCAN_DIRS = [".github/workflows", "docs", "tests", "scripts", "profiles"]
SCAN_EXT = (".yml", ".yaml", ".md", ".py", ".json")
# Explicitly a CANDIDATES document: it proposes vocabulary rather than using adopted
# vocabulary. Registering its proposals would assert they were decided.
SKIP_FILES = {"ASSURANCE_MODEL_CANDIDATES.md"}
# A FROZEN PROTOTYPE PROPOSES VOCABULARY; IT DOES NOT USE ADOPTED VOCABULARY.
#
# Same rule as SKIP_FILES above, applied to a directory. `docs/architecture/prototypes/` holds a
# design experiment that is deliberately NOT under .github/workflows -- it is not globbed by the
# size check, not linted as a workflow, and nothing dispatches it. Its generator's Python
# constants (CQ_INIT, FETCH_STEP_STATE and friends) delimit regions and name steps; nothing
# branches on them and no consumer receives them.
#
# Registering them would be the worse error by a distance: it would assert that this kit has
# DECIDED a vocabulary it is still experimenting with, and the prototype's whole purpose is to
# stay undecided until real timings exist. A registry that absorbs every proposal stops being a
# record of what was decided.
SKIP_DIRS = {os.path.join("docs", "architecture", "prototypes")}

# SCREAMING_SNAKE tokens that are environment variables, GitHub contexts or tool names -- not
# vocabulary. Kept explicit rather than heuristic, because a heuristic that quietly swallows a real
# taxonomy term would defeat the whole check.
NOT_VOCABULARY = {
    "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_STEP_SUMMARY", "GITHUB_PATH", "GITHUB_TOKEN",
    # The runner's REST API base URL, read by scripts/environment_protection.py to read an
    # environment's protection rules back. A platform environment variable, same class as above.
    "GITHUB_API_URL",
    # The runner's per-job temp directory -- a platform environment variable of the same class
    # as GITHUB_OUTPUT, named as a string by the deploy-step harness that stands it in locally.
    "RUNNER_TEMP",
    # The Azure CLI's own configuration-directory variable. The deploy harness points it at an
    # empty directory so that nothing it runs could ever reach a signed-in CLI.
    "AZURE_CONFIG_DIR",
    # Git for Windows' own switches that stop it rewriting "/health"-shaped values into Windows
    # paths; the deploy harness sets them so a local run passes values byte-exact, as Linux does.
    "MSYS2_ENV_CONV_EXCL", "MSYS_NO_PATHCONV",
    "NVD_API_KEY", "SEMGREP_APP_TOKEN", "AZURE_CLIENT_ID", "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID", "JAVA_HOME", "MIN_JAVA", "NVD_UPDATE_FAILED", "PATH", "PWD",
    "NORMALIZE_PY", "MERGE_PY", "REROOT_PY", "IFS", "MAX_ACCEPTED_DEBT", "FLAWFINDER_SARIF",
    "NODE_SCA_PARTIAL", "CPP_ANALYSIS_PARTIAL", "DPKG", "HOME", "TMPDIR",
    "SARIF", "JSON", "YAML", "CSV", "XML", "HTML", "URL", "URI", "CVE", "CVSS", "CWE", "SBOM",
    "OIDC", "GHAS", "API", "CLI", "PR", "CI", "OK", "ID", "OS", "IP", "TODO", "NOTE", "WARN",
    "ANALYSIS", "GATE", "PUBLICATION", "DETECT", "EXEC", "RUN", "BEGIN", "END", "MSG", "PY",
    # Document FILENAMES. A doc named after a concept is not a use of the vocabulary.
    "ROLLBACK_CONTRACT", "VALIDATION_DEBT", "TEST_COVERAGE_AUDIT", "CAPABILITY_MATRIX",
    "CAPABILITY_INVENTORY", "FINDING_CLASSIFICATION", "FAILURE_MODES", "FUTURE_WORK",
    "START_HERE", "SKILL_TAXONOMY", "NVD_ABSTRACTION_ACCOUNTING", "ASSURANCE_MODEL_CANDIDATES",
    "EXPECTED_SIGNALS", "ORG_MIGRATION_CHECKLIST", "REPO_CUSTODY_MAP", "DECISION_LEDGER",
    # Cited by its short name ("JOB_TOPOLOGY §4") in the resolve job, its harness and the
    # execution-planning design. A citation of a document is not a use of its vocabulary.
    "JOB_TOPOLOGY",
    # Lane L-SCAN-B (KDEC-026): identifiers INSIDE the generated platform fixtures (C macros, Apple
    # CommonCrypto names, Gradle environment names), build-tool flags and environment switches the
    # proofs pass to CMake, apt and dotnet, a shell variable, the step-name constants of a proof, and
    # the fixture contract's FILENAME (PLATFORM_SIGNALS.json, like EXPECTED_SIGNALS). None is a state.
    "BUF_LEN", "CC_LONG", "CC_MD5", "CC_MD5_DIGEST_LENGTH", "KEY_PASSWORD", "STORE_PASSWORD",
    "DCMAKE_EXPORT_COMPILE_COMMANDS", "FATAL_ERROR", "DEBIAN_FRONTEND", "DOTNET_CLI_TELEMETRY_OPTOUT",
    "DOTNET_NOLOGO", "IN_DISCOVERED_KOTLIN", "MOBSF_ENFORCE_STEP", "RULES_ENFORCE_STEP",
    "PLATFORM_SIGNALS",
    # Script-internal identifiers and shell variables.
    "WF_DIR", "TX_PY", "STRIP_PY", "TRUSTED_ORGS", "WORKFLOWS_PATH", "SCAN_DIRS", "SCAN_EXT",
    "NOT_VOCABULARY", "CAPABILITY_REGISTRY", "VALIDATION_REGISTRY", "TEST_RESOURCE_GROUP",
    # Python CONSTANT NAMES, not enforcement vocabulary. Each is a container or a literal this
    # code reads -- a marker character, a minimum length, a set membership test -- and none is a
    # word a downstream consumer could mistake for a state. Registering them would put invented
    # definitions in the taxonomy for things that are not states, which is worse than the drift:
    # the register would then describe vocabulary that does not exist.
    # EXPORT TOOLING, which the assurance taxonomy does not govern. These name a marker
    # character, a directory exclusion set and a profile directive verb in the export gate -- a
    # different domain from pipeline enforcement, and no downstream consumer could read them as a
    # finding state. Only these three are exempted here: the other drift terms belong to the
    # assurance domain and are their owners' call, not this one. Exempting somebody else's
    # constant to turn a gate green is the same move as relaxing a scanner to get a clean run.
    "NEVER_LIFT_MARKER", "NEVER_LIFT", "EXCLUDE_TOP", "INCLUDE_OVERLAY",
    "EXCLUDE_TREES",
    # A Python constant in scripts/reconcile_tickets.py that POINTS AT a registered value rather
    # than being one: `UNCLASSIFIED_DEFAULT = BINDING_UNESTABLISHED`. It exists so that a future
    # branch which forgets to classify its lookup outcome lands on the safe value by construction
    # instead of by remembering to type it. Nothing is ever projected from the name, no consumer
    # receives it, and the value it holds IS registered under ticket_lookup_outcome. It appears
    # unassigned only in tests/prove_ticket_idempotency.py, which quotes the assignment as the
    # target text of a mutation.
    "UNCLASSIFIED_DEFAULT",
    "SUBSCRIPTION_ID", "REQUIRE_SHA", "TLS1_0", "TLS1_2", "MIN_JAVA", "DC_VER",
    # Annotation titles emitted to the operator -- messages, not states.
    "VALIDATION_COVERAGE_GAP",
    # Platform/tooling identifiers and fixture content -- not this kit's vocabulary.
    "ACTIONS_ID_TOKEN_REQUEST_URL", "EXAMPLE_NOT_A_REAL_KEY", "EXPORT_MANIFEST",
    "NORMALIZE_SARIF", "PRE_TEST_RESOURCE_COUNT", "POST_CLEANUP_RESOURCE_COUNT",
    # Tracker credential/config keys read from .env by scripts/check_env.py. These name a
    # SETTING, not a state -- nothing branches on their VALUE being one of a fixed set.
    "JIRA_EMAIL", "JIRA_TOKEN", "JIRA_HOST", "JIRA_PROJECT",
    "AZDO_PAT", "AZDO_ORG", "AZDO_PROJECT",
    # Same class, read by scripts/reconcile_tickets.py: which tracker is authoritative, which
    # repository or project it writes to, the umbrella label a human provisions once, and the
    # per-site custom field holding the cluster stamp. Each names a SETTING whose value is a
    # repository name, a label or a field id -- none of them is a state, and nothing projects a
    # verdict from one. TICKET_BACKEND is the near miss worth naming: its value IS one of a fixed
    # pair, but the pair is `github` and `jira`, deliberately lower-case so that the backend
    # names stay tool identifiers rather than becoming this kit's vocabulary.
    "TICKET_BACKEND", "TICKET_REPO", "TICKET_STAMP_LABEL", "JIRA_STAMP_FIELD",
    # The same class, named by docs/architecture/TICKETING_BACKENDS.md 3.1 and 4.1 (KDEC-004):
    # ids of a calibration ticket and a product epic, issue-type and transition/state NAMES on
    # somebody else's tracker, a stamp field's reference name, an organisation URL and a numeric
    # ceiling. Each is a SETTING read from the environment. The type, transition and state values
    # are the tracker's own words (`Story`, `To Do`), never this kit's vocabulary, which is why
    # they are configuration rather than constants.
    "JIRA_CALIBRATION_ISSUE", "JIRA_EPIC_ID", "JIRA_TYPE_CLUSTER", "JIRA_TYPE_INSTANCE",
    "JIRA_TRANSITION_REOPEN", "JIRA_TRANSITION_DONE",
    "AZDO_ORG_URL", "AZDO_STAMP_FIELD", "AZDO_EPIC_ID", "AZDO_CALIBRATION_ITEM",
    "AZDO_TYPE_CLUSTER", "AZDO_TYPE_INSTANCE", "AZDO_STATE_REOPEN", "AZDO_STATE_DONE",
    "TICKET_CREATE_CEILING", "TICKET_CALIBRATION_REF", "TICKET_RETRY_CEILING",
    "TICKET_INSTANCE_THRESHOLD",
    # The same class (completion ledger row T-06): the owner-set number of consecutive degraded
    # runs after which a carried obligation is escalated to a person (TICKETING_CONTRACT.md 4.1).
    # A numeric SETTING; nothing branches on its value being one of a fixed set.
    "TICKET_DEGRADED_RUN_THRESHOLD",
    # The same class (KDEC-024, lane L-TKT): the per-run call budget and the Jira priority ladder
    # the SLA escalation climbs, and the GitHub Issues token's secret name in the reusable
    # workflow. SETTINGS whose values are a number, a list of the tracker's own priority names
    # and a credential -- never states.
    "TICKET_CALL_BUDGET", "JIRA_PRIORITY_LADDER", "GH_TICKET_TOKEN",
    # The same class (KDEC-028, lane L-AM): Jira auth and test-ticketing SETTINGS -- the auth mode
    # (basic|bearer), the site's cloud id, the real project keys a test run checks itself
    # against, and the ticketing mode the reusable workflow DERIVES from the ref (real|test,
    # lower-case values, never a state). And the constants and step env names that carry them:
    # the test label and summary prefix, the test-binding ledger prefix, the guard's
    # TEST_ENVIRONMENT; the routing proof's placeholder constants and a checkov rule id used as a
    # fixture value (somebody else's identifier).
    "JIRA_AUTH_MODE", "JIRA_CLOUD_ID", "JIRA_REAL_PROJECTS", "TICKETING_MODE", "TEST_ENVIRONMENT",
    "TEST_LABEL", "TEST_PREFIX", "TEST_LEDGER_PREFIX", "CREATEMETA_STORY", "ORIGIN_CENTRAL",
    "ORIGIN_REPOSITORY", "CKV_AZURE_1",
    # Platform environment variables the reconciler reads to link a ticket to its run and commit,
    # the same class as GITHUB_OUTPUT.
    "GITHUB_SERVER_URL", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_REPOSITORY",
    # Python constant names, referenced as attributes from another module (so the structural
    # assignment rule cannot see them): the model's actor string for an unattended mutation, and
    # the ticket proofs' placeholder configurations and forbidden-field pattern. Containers of
    # values, never states.
    "ROUTINE_ACTOR", "AZDO_KW", "GH_ENV", "JIRA_ENV", "FORBIDDEN_FIELD",
    # Environment-variable NAMES of .github/workflows/reusable-ticket-reconcile.yml's steps, set
    # by tests/prove_ticket_reconcile_workflow.py when it runs the extracted steps. Each carries a
    # path, a date, an exit code or a caller input as DATA; none is a state. The W_* names follow
    # the posture-record convention every reusable already uses (tests/check_weakening_record.py).
    "EVENT_NAME", "FINDINGS_FILE", "KIT_DIR", "LEDGER_PATH", "RUNNER_TEMP", "TODAY_OVERRIDE",
    "W_APPLY", "W_FINDINGS_ARTIFACT", "W_WEAKENING_AUTHORITY", "W_WEAKENING_EXCEPTION_REF",
    "W_WEAKENING_EXPIRES", "W_WEAKENING_REASON",
    # THIRD-PARTY PLATFORM CONSTANTS named in scanner documentation. A WordPress PHP
    # constant is a setting on somebody else's platform -- this kit branches on nothing
    # about it, and registering it would claim a vocabulary the kit does not own.
    "DISALLOW_FILE_EDIT", "WP_DEBUG",
    # Python's own zipfile compression constant, used by the export's --zip step
    # (scripts/export_for_adoption.py, tests/prove_export_scope.py E10). A standard-library
    # identifier, not a state the kit defines or branches on.
    "ZIP_DEFLATED",
    # The same class, read by the resolve job's version probes and seeded in their fixtures: a
    # CMake variable name and a Gradle enum member are somebody else's identifiers. The kit
    # reads them to learn a C++ standard or a Java level; it defines nothing by them.
    "CMAKE_CXX_STANDARD", "CMAKE_C_STANDARD", "VERSION_17",
    # Env-var names and heredoc tags introduced by the reporting/redaction chain.
    "GH_TOKEN", "RUN_URL", "JOB_STATUS", "SCAN_REPORT", "SCAN_REPORT_PY", "SCAN_STATUS",
    "SCAN_STATUS_SH", "REDACT_SARIF", "REDACT_SARIF_PY", "PR_BODY", "TICKET_HOST",
    "TICKET_PROJECT", "ENFORCE_DIGIT_RANGE", "MIN_DIGITS", "MAX_DIGITS", "IN_PATHS",
    "IN_LANGUAGE", "IN_IAC_MODE", "REDACTED_MARK", "DECLARED_KEYS", "DECLARED_LABEL",
    # The optional SECRET name of .github/workflows/reusable-dependabot-triage.yml (a credential
    # for fetch-metadata's lookups) and the template's suggested repository secret. Names of
    # settings, not states; the triage's own states are lowercase rule ids.
    "METADATA_TOKEN", "DEPENDABOT_METADATA_TOKEN",
    # Env-var NAMES of .github/workflows/reusable-ticket-reference.yml's step (KDEC-013): a Jira
    # site host and a project key, carried as DATA. Each names a SETTING; nothing branches on its
    # value being one of a fixed set. The gate's states are ticket_reference_outcome.
    "TRACKER_HOST", "PROJECT_KEY",
    # Seeded FIXTURE content in tests/prove_redaction_chain.py -- a fake credential and the
    # vendor rule ids that report it. Registering a Checkov rule id as this kit's vocabulary
    # would assert we own a word Bridgecrew defines.
    "CKV_SECRET_6", "DB_PASSWORD", "AKIA", "B105",
    # Git refs, repository-variable names and generated output filenames.
    "FETCH_HEAD", "DEFAULT_BRANCH", "TICKET_ENFORCE_DIGIT_RANGE", "TICKET_MAX_DIGITS",
    "TICKET_MIN_DIGITS", "CAPABILITY_INVENTORY_GENERATED",
    # DELIBERATELY REJECTED SPELLINGS of ACCEPTED_RISK. They appear only where the code asserts
    # they must NOT suppress a finding. Registering them as vocabulary would assert the opposite
    # -- that they are valid dispositions -- which is the defect the assertions exist to prevent.
    # The decision itself is recorded under disposition_type.rejected_synonyms.
    "RISK_ACCEPTED", "RISK_ACCEPTANCE",
    # Same reasoning, one namespace over. GATE_RELAXED is a DELIBERATELY UNREGISTERED near-miss
    # of control_weakening.GATE_SOFTENED, and it exists in exactly one place: the W3 mutant in
    # tests/check_weakening_record.py, whose whole purpose is to assert that an unregistered
    # class is REFUSED. Registering it would make that mutant clean and silently disarm the rule
    # -- the check would then pass because its bad fixture had become a good one, which is the
    # fixture-that-proves-nothing failure this repository has already shipped once.
    "GATE_RELAXED",
    # THE SAME REASONING AGAIN, for scan_examination. SOME_FUTURE_VALUE exists in exactly one
    # place: the rogue-state assertion in scripts/scan_report.py's self-test, which proves that an
    # examination state NOT in COUNTABLE_EXAMINATION fails closed. That assertion is the guarantee
    # that the check is membership of an allowed set rather than inequality with one bad value --
    # so a value added to the namespace later, and not to the allowed set, refuses instead of
    # passing. Registering it would make the rogue value legitimate and silently disarm the
    # assertion, which is the fixture-that-proves-nothing failure this kit has shipped once.
    "SOME_FUTURE_VALUE",
    # THE SAME REASONING TWICE MORE, in scripts/ticket_model.py's self-test. NOT_A_SUBJECT is fed
    # to the compliance pairing table to prove an unrecognised subject returns
    # PAIRING_NOT_ESTABLISHED rather than inheriting a neighbouring subject's governance
    # consequence. SOME_FUTURE_RULE is fed to the closure evaluator to prove an unrecognised
    # closure rule FAILS CLOSED rather than falling through to permitted. Registering either would
    # make the bad fixture a good one and silently disarm the assertion it exists to carry.
    "NOT_A_SUBJECT", "SOME_FUTURE_RULE",
    # Another repository's SECRET NAME, quoted in a roadmap note describing how the reference estate gated on
    # GHAS. Not this kit's vocabulary -- and the approach it names is superseded by the discover
    # job, which probes rather than trusting a hand-set declaration.
    "GITHUB_ADVANCED_SECURITY_ENABLED",
    # Generated output filenames and heredoc tags.
    "CAPABILITY_CUSTODY", "SBOM_LICENSES", "SBOM_LICENSES_PY",
    # GENERATOR MARKERS AND HEREDOC TAGS introduced when reusable-security.yml stopped inlining
    # every script at every call site. Same class as SCAN_STATUS / REDACT_SARIF above: they
    # delimit a region scripts/inline_normalizer.py rewrites, and they decide nothing. Nothing
    # branches on them, no state is projected from them, and no consumer receives them --
    # registering them as vocabulary would assert this kit defines words it merely greps for.
    "FETCH_KIT_SCRIPTS", "REDACT_STEP", "STATUS_STEP", "REDACT_ALL", "REDACT_ALL_SH",
    "PIN_KIT_SCRIPTS",
    # Another repository's document filename, cited in an architecture note.
    "WORKFLOW_ORCHESTRATION_DESIGN",
    # ---- Classified one by one on 2026-10-15 (self-test "Vocabulary in use must be registered",
    # 47 terms). Each entry below names a THING THAT IS NOT A STATE; the two terms on that list
    # that WERE states went the other way: NO_FINDINGS_COUNT is registered under
    # publication_state, and the three near-misses (PREVIOUS_STATE, PROMOTION_VERIFIED,
    # OVERLAY_REQUESTED) were corrected at the use site, remedies 1 and 4, never here.
    #
    # Platform environment variables, the same class as GITHUB_OUTPUT: the checkout root the
    # scanners `cd` into, the caller repository `gh api` is pointed at, and the runner version
    # a probe found unset on hosted runners.
    "GITHUB_WORKSPACE", "GITHUB_REPOSITORY", "RUNNER_VERSION",
    # The same class: a composite action's own directory, which the propose-ledger composite
    # resolves the kit root from and tests/prove_propose_ledger_establishment.py sets by name when it
    # runs that composite's step as shipped. A path, never a state.
    "GITHUB_ACTION_PATH",
    # The same class: the run id and attempt the build job's push-capability step stamps into
    # its change manifest (`${GITHUB_RUN_ID:-local}`), set by name when
    # tests/prove_build_push_round_trip.py runs that step against a real registry. Identifiers
    # of a run, never a state.
    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
    # Environment variables the proofs READ: an alternative workflow revision to prove against
    # (tests/_scan_step_harness.py) and the path of an osv-scanner binary
    # (tests/prove_malicious_deps_enforces.py). Each carries a path, never a state.
    "KIT_PROOF_WORKFLOW", "OSV_SCANNER",
    # Repository-VARIABLE names of the landing-zone handoff contract (`vars.KIT_*` in
    # docs/architecture/LZ_KIT_HANDOFF_CONTRACT.md): a registry host, an app name, a cloud, a
    # tier, an image repository and a resource group. Settings, exactly as TICKET_REPO is. The
    # tier variable's VALUE is an environment_tier value, which is registered; its NAME is not
    # one.
    "KIT_ACR_LOGIN_SERVER", "KIT_APP_NAME", "KIT_CLOUD", "KIT_ENVIRONMENT_TIER",
    "KIT_IMAGE_REPOSITORY", "KIT_RESOURCE_GROUP",
    # A SETTING, never a state: where the consumer census writes its record
    # (scripts/inventory_consumers.py, W4K-114).
    "CONSUMER_COVERAGE_OUT",
    # A NAME, never a state: the flagship shell variable holding the gosec image, which
    # tests/prove_validate_scanners.py reads to compare the weekly probe's pin (W4K-116).
    "GOSEC_IMAGE",
    # FIXTURE CONTENT: the owner/repo placeholders in a constructed `uses:` path
    # (tests/prove_custody_overlays.py), a fake Checkov rule id a probe result carries
    # (tests/prove_sarif_effective_level.py, same class as CKV_SECRET_6), and the constant that
    # holds a seeded apk database (tests/prove_image_scan_enforces.py).
    "KIT_OWNER", "KIT_REPO", "CKV_PROBE_1", "APK_INSTALLED",
    # The same class: the owner placeholder in templates/ `uses:` paths, which
    # tests/check_action_pins.py accepts (in templates only) beside forty zeros. A path, never a state.
    "YOUR_ORG",
    # SETTINGS, never states: scripts/pin-actions.sh's API base (set to a local stand-in by
    # tests/prove_pin_actions_names_release.py) and the directories it walks (docs/assurance/PINNING.md).
    "GITHUB_API_URL", "SEARCH_PATHS",
    # Python CONSTANT NAMES in the assurance scripts -- the class the export-tooling note above
    # left to its owner, classified here on the owner's instruction. Every one is a CONTAINER OF
    # REGISTERED VALUES or a literal: BY_SCANNER maps scanner names to finding_subject values;
    # COUNTABLE_EXAMINATION, NO_COUNT_STATES and NO_COUNT_APPLIC are membership sets over
    # scan_examination, execution_state and platform_applicability; COMPLIANCE_PAIRING maps
    # subjects to compliance_review_type values; TERMINAL_TASK_STATES is the pair of task_state
    # values the closure evaluator treats as terminal; MIN_APPROVAL_REASON is a length;
    # CODE_PATTERNS and OVERLAY_DIRS are path lists; X_OK is os.X_OK. Nothing projects a state
    # from any of these names, and the values they hold are the registered ones -- the same
    # reasoning as UNCLASSIFIED_DEFAULT above.
    "BY_SCANNER", "COUNTABLE_EXAMINATION", "NO_COUNT_STATES", "NO_COUNT_APPLIC",
    "COMPLIANCE_PAIRING", "TERMINAL_TASK_STATES", "MIN_APPROVAL_REASON", "CODE_PATTERNS",
    "OVERLAY_DIRS", "X_OK",
    # Document SHORT NAMES cited without their extension ("PIPELINE_ORDERING 4.5",
    # "SINGLE_PIPELINE_TARGET section 5.2", "ENFORCEMENT_TIERS section 1.1", "KNOWN_GAPS
    # section 2"), the same class as JOB_TOPOLOGY above. The files are
    # docs/architecture/PIPELINE_ORDERING_AND_SCAN_VALIDITY.md, SINGLE_PIPELINE_TARGET.md,
    # ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md and docs/assurance/KNOWN_GAPS.md.
    "PIPELINE_ORDERING", "PIPELINE_ORDERING_AND_SCAN_VALIDITY", "SINGLE_PIPELINE_TARGET",
    "ENFORCEMENT_TIERS", "KNOWN_GAPS",
    # docs/KNOWN_DEFECTS.md, cited by its short name in the change log.
    "KNOWN_DEFECTS",
    # Shell variable names in verify-azure-oidc.yml's context-integrity step and its proof
    # (tests/prove_context_integrity_refuses.py): a declared expectation, the value the login
    # secrets carried, and the subscription the input declared. Names, not states.
    "EXPECTED_SID", "FROM_SECRETS", "IN_EXPECT_SID",
    # The claims step's shell variables (verify-azure-oidc.yml) and the runner's token-request
    # variable, set by name in tests/prove_oidc_subject_forms.py. Names, not states.
    "EXPECT_REPO", "EXPECT_ENVIRONMENT", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    # Generator marker and heredoc tag for the inlined validity script, the same class as
    # FETCH_KIT_SCRIPTS above (scripts/inline_normalizer.py).
    "SARIF_VALIDITY", "SARIF_VALIDITY_PY",
    # The gate's SHELL VARIABLE for the resolve job's version-gap count, printed BY NAME in the
    # summary row "VERSION_GAP_COUNT UNDETERMINED" and quoted by tests/prove_bootstrap_failure.py
    # as the text it expects. The state in that row is UNDETERMINED; the name beside it is the
    # variable that holds no count.
    "VERSION_GAP_COUNT",
    # QUOTED PROBE OUTPUT. docs/architecture/SECURITY_WORKFLOW_DECOMPOSITION_PLAN.md records the
    # marker a cross-repository probe printed (`SELF_REF_RESULT=RESOLVED_TO_KIT`, run
    # 38434823833) as evidence that `$/` resolved to the kit. The probe lives on its own branch;
    # nothing in this tree emits or branches on the marker, and rewording a quoted observation
    # would falsify the evidence it is. The decided vocabulary for that boundary is
    # reusable_workflow_resolution.
    "SELF_REF_RESULT", "RESOLVED_TO_KIT",
    # THIRD-PARTY TOOL ENVIRONMENT NAMES: the trivy action's own `env:` interface
    # (TRIVY_SEVERITY and friends), named as strings by tests/prove_trivy_threshold.py to map the
    # action's inputs onto the environment it sets. Somebody else's identifiers, the same class
    # as CMAKE_CXX_STANDARD above.
    "TRIVY_SEVERITY", "TRIVY_EXIT_CODE", "TRIVY_FORMAT", "TRIVY_IGNORE_UNFIXED", "TRIVY_INPUT",
    "TRIVY_OUTPUT", "TRIVY_SCANNERS", "TRIVY_TIMEOUT",
    # KDEC-027 (lane L-PIN, ghe.com support), classified at integration (L-INT1). Third-party
    # tool ENVIRONMENT NAMES, never states: Trivy's database-cache directory, now that the kit
    # installs the binary itself; the gh CLI's host selector; git's own environment switches
    # that tests/_github_refs.py clears so a ref lookup never reads the developer's config or
    # prompts; and the loader/runtime variables tests/check_output_writes.py names as unsafe to
    # write into $GITHUB_ENV. Somebody else's identifiers, the same class as the TRIVY_* above.
    "TRIVY_CACHE_DIR", "GH_HOST", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM", "GIT_DIR", "GIT_WORK_TREE", "GIT_TERMINAL_PROMPT", "LD_PRELOAD",
    "NODE_OPTIONS",
    # SETTINGS, never states (KDEC-027): scripts/pin-actions.sh's public-actions API base and
    # the token-host pin the pin checker reads, both set to local stand-ins by the ghe.com proofs.
    # The same class as PIN_ACTIONS' GITHUB_API_URL and SEARCH_PATHS above.
    "PIN_ACTIONS_API", "PIN_CHECK_TOKEN_HOST",
    # KDEC-029 (lane L-PROMO): SETTINGS and names, never states. The environment the promotion steps
    # read (the KEV composite's outputs passed in, the e2e command's PROMOTION_* context, the clock
    # override KIT_PROMOTION_NOW, the template's repository variable KIT_DAST_COMMAND, the runner's
    # GITHUB_REF, the deployed-scan composite's RESOURCE_GROUP/CONTAINERAPP_NAME), the proofs' stand-in
    # switches (FAKE_*, API_ROOT), two document titles cited by name, and a Python constant name.
    "KEV_STATE", "KEV_BLOCKING", "PROMOTION_APP_URL", "PROMOTION_CHECK_PHASE", "PROMOTION_ENVIRONMENT",
    "KIT_PROMOTION_NOW", "KIT_DAST_COMMAND", "PROMOTION_DAST_SARIF", "GITHUB_REF", "RESOURCE_GROUP", "CONTAINERAPP_NAME",
    "FAKE_API_ROOT", "FAKE_DAST_RESULTS", "FAKE_DAST_NO_REPORT", "API_ROOT",
    "KIT_E2E_TEST_COMMAND", "KIT_PROMOTION_PREDECESSOR",
    "COMPLETION_LEDGER", "DEPLOYMENT_CONTRACT_RECONCILIATION", "NOT_VERIFIED",
    # KDEC-030 draft (lane L-SEAM2): SETTINGS, never states. The environment variable the landing zone
    # vends to opt a deploy into the target lease, the lease CLI's bearer override (the proof's
    # stand-in token) and break-authority list, and the LZ snippet's variable naming the target.
    "KIT_TARGET_LEASE_ACCOUNT", "TARGET_LEASE_BEARER", "TARGET_LEASE_BREAK_AUTHORITY", "TARGET_RESOURCE_ID",
    # The token-file override the az fence and the hold read, and the proof's az stand-in log.
    "KIT_TARGET_LEASE_TOKEN", "AZ_STUB_LOG",
    # The leak-gate helpers (developer-safety/, docs/adoption/LEAK_GATES.md): bash's own version
    # variable, which both scripts test to refuse a non-bash shell (tests/prove_push_ruleset_secret_files.py
    # looks for the guard by that name) -- somebody else's identifier, the same class as GH_HOST --
    # and merge-baseline.sh's positional-argument NAME in its usage line and exit table, a path the
    # caller passes, the same class as SEARCH_PATHS. Neither is a state; the scripts' refusal
    # reasons ARE states and are registered (prerequisite_readiness, leak_gate_setup_refusal).
    "BASH_VERSION", "REPO_DIR",
    # KDEC-032 PROPOSED (Release 4 feed mirrors, lane L-MIRROR): SETTINGS and names, never states. The
    # caller's repository/organisation VARIABLES that name the mirror, its policy, its fallback, the
    # private runner and the scanner-image registry (KIT_FEED_MIRROR_*, KIT_SCANNER_IMAGE_REGISTRY, the
    # same class as KIT_DAST_COMMAND); the composites' step environment names (M_*, K_*), set by name
    # when tests/prove_feed_mirror.py runs those steps as shipped; the NVD path's environment flag
    # NVD_MIRROR_REFUSED and datafeed variable (the same class as NVD_UPDATE_FAILED); and Trivy's own
    # update switches (somebody else's identifiers, the same class as the TRIVY_* above). The states
    # themselves are registered: feed_mirror and feed_mirror_refresh.
    "KIT_FEED_MIRROR_URL", "KIT_FEED_MIRROR_ACCOUNT", "KIT_FEED_MIRROR_MAX_AGE_HOURS", "KIT_FEED_MIRROR_FALLBACK", "KIT_FEED_MIRROR_RUNNER",
    "KIT_SCANNER_IMAGE_REGISTRY", "M_FEED", "M_URL", "M_MAX_AGE", "M_FALLBACK", "M_NOW", "M_STATE", "M_USABLE",
    "M_WHY", "K_CVE_FINDINGS", "K_SARIF", "K_SARIF_JOB", "K_EXCEPTIONS", "K_POLICY_STATE", "K_FEED_URL", "K_DAY",
    "K_MIRROR_STATE", "K_MIRROR_USABLE", "K_MIRROR_URL", "K_MIRROR_FILE", "K_MIRROR_SHA256", "K_MIRROR_WHY",
    "NVD_MIRROR_REFUSED", "W_NVD_DATAFEED", "TRIVY_SKIP_DB_UPDATE", "TRIVY_SKIP_JAVA_DB_UPDATE",
    "TRIVY_SKIP_CHECK_UPDATE", "MAX_AGE_HOURS_CEILING",
    # The gaps closed (KDEC-032): Trivy's custom-check path and osv-scanner's database directory (somebody
    # else's identifiers), the kit's own offline switch and image-registry step variable, and two constants.
    "TRIVY_CONFIG_CHECK", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "KIT_OSV_OFFLINE", "W_IMAGE_REGISTRY",
    "CHECKS_FILE", "CHECKS_SUB", "OSV_SUB", "OSV_ECOSYSTEMS", "OSV_UPSTREAM", "DIGEST_RE",
    # The Trivy steps' own scan-root variable (deps-scan, reusable-nvd-cve), read BY NAME by
    # tests/prove_security_caller_triggers.py to compare the two configurations (KDEC-033). A name.
    "SCAN_REF",
    # The self-test verdict's environment (KDEC-033): the runner's event name and the two JSON values
    # the `required` job hands scripts/selftest_required.py. Names, not states.
    "GITHUB_EVENT_NAME", "NEEDS_JSON", "PLAN_SKIPS",
}

TOKEN = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")


def registered_terms(doc):
    out = {}
    for ns, body in (doc.get("namespaces") or {}).items():
        for val in (body.get("values") or {}):
            out.setdefault(val.upper(), []).append(ns)
        # field lists are vocabulary too
        for val in (body.get("artifacts") or {}):
            out.setdefault(val.upper(), []).append(ns + ".artifact")
        for extra in ("required_fields", "fields"):
            for f in (body.get(extra) or []):
                out.setdefault(str(f).upper(), []).append(ns + ".field")
        # A TIERED SUB-AXIS IS STILL THE REGISTRY, and this reader could not see one.
        #
        # `provenance_identity.observation_time.sources` registers DECLARED_IN_CONTENT, SIDECAR,
        # FILENAME, FILE_MTIME and UNKNOWN, each with a definition, a tier and a `claimable`
        # flag -- they are as registered as anything in a `values:` block and are branched on the
        # same way. Because this function only read `values`, using one of them in code was
        # reported as DRIFT: the gate was telling a correct author to register a term the
        # registry already held, which is remedy 1 pointed at the wrong file. FILE_MTIME was on
        # the drift list for exactly that reason.
        for sub in (body.get("observation_time") or {}).get("sources") or {}:
            out.setdefault(str(sub).upper(), []).append(ns + ".observation_time")
    return out


def scan_files():
    skip = tuple(os.path.join(ROOT, d) for d in SKIP_DIRS)
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d)
        for dp, _, fns in os.walk(base):
            if dp.startswith(skip):
                continue
            for f in fns:
                if f.endswith(SCAN_EXT):
                    yield os.path.join(dp, f)


def main(argv):
    doc = yaml.safe_load(io.open(REG, encoding="utf-8"))
    reg = registered_terms(doc)

    used = {}
    for p in scan_files():
        base = os.path.basename(p)
        if base in ("assurance-taxonomy.yaml", "reconcile_taxonomy.py") or base in SKIP_FILES:
            continue
        try:
            t = io.open(p, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        # A SHELL VARIABLE IS NOT VOCABULARY, and this is structural rather than a denylist:
        # variables appear as `X=`, `$X` or `${X}`. Growing an exclusion list by hand would make
        # the check a chore that eventually gets disabled -- which is how controls die here.
        # STRUCTURAL, not a denylist. Identifiers are distinguishable from vocabulary by where
        # they appear: shell expansion, an assignment, a YAML key, a heredoc marker, or an
        # angle-bracket placeholder in docs. A hand-maintained exclusion list would become a
        # chore, and chores get disabled -- which is how controls die around here.
        ident = set(re.findall(r"\$\{?([A-Z][A-Z0-9_]+)\}?", t))          # $X / ${X}
        ident |= set(re.findall(r"^\s*([A-Z][A-Z0-9_]+)\s*=", t, re.M))    # X= / X =
        ident |= set(re.findall(r"^\s*([A-Z][A-Z0-9_]+):", t, re.M))          # YAML env: keys
        ident |= set(re.findall(r"<([A-Z][A-Z0-9_]+)>", t))                  # <PLACEHOLDER>
        ident |= set(re.findall(r"<<\'?([A-Z][A-Z0-9_]+)\'?", t))            # heredoc markers
        # A DOCUMENT NAME IS NOT A STATE. `AXES_AND_PHASES.md` cited in a comment was
        # reported as enforcement drift. Structural, like the five above: vocabulary does not
        # carry a file extension. Kept as a rule rather than an exclusion entry, because this
        # file already argues that a hand-maintained denylist becomes a chore and chores get
        # disabled -- and a checker that cries wolf is on that road.
        ident |= set(re.findall(r"\b([A-Z][A-Z0-9_]+)\.(?:md|ya?ml|csv|json|txt|py|sh)\b", t))
        for m in TOKEN.finditer(t):
            tok = m.group(0)
            if tok in NOT_VOCABULARY or tok in ident:
                continue
            used.setdefault(tok, set()).add(os.path.relpath(p, ROOT).replace("\\", "/"))

    drift = {k: v for k, v in used.items() if k not in reg}

    # ORPHAN detection cannot rely on the token regex: it requires an underscore, so single-word
    # terms (PASS, FAILED, PARTIAL, READY) would ALWAYS look unused and every one would be reported
    # as dead vocabulary. That is the checker committing the exact error it exists to catch --
    # a measuring instrument that lies more convincingly than the thing measured. Search directly.
    corpus = []
    for p2 in scan_files():
        if os.path.basename(p2) in ("assurance-taxonomy.yaml", "reconcile_taxonomy.py"):
            continue
        try:
            corpus.append(io.open(p2, encoding="utf-8", errors="ignore").read())
        except OSError:
            pass
    blob = "\n".join(corpus)
    orphan = [k for k in reg
              if not re.search(r"\b" + re.escape(k) + r"\b", blob)
              and not re.search(r"\b" + re.escape(k.lower()) + r"\b", blob)]

    print("taxonomy: %d registered terms, %d vocabulary tokens in use" % (len(reg), len(used)))

    if orphan:
        print("\n-- ORPHANS (registered, used nowhere) --")
        for k in sorted(orphan):
            print("   %-38s declared in %s" % (k, ",".join(sorted(set(reg[k])))))
        print("   Either dead vocabulary or an unimplemented promise. Both worth knowing.")

    if drift:
        print("\n== DRIFT — enforcement words nobody defined ==")
        for k in sorted(drift):
            where = sorted(drift[k])[:3]
            print("   %-38s used in %s%s" % (k, ", ".join(where),
                                             " (+%d more)" % (len(drift[k]) - 3) if len(drift[k]) > 3 else ""))

        # HOW TO FIX IT, not just what is wrong.
        #
        # This gate used to stop at "register them or stop using them". That is an instruction only
        # to someone who already knows the file, the nesting and the required fields. To everybody
        # else it is a red pipeline with no exit, and a gate people cannot clear is a gate people
        # route around -- which is how the control ends up deleted rather than satisfied.
        #
        # So: print the three real options in the order they should be considered, and emit a
        # paste-ready block at the correct indentation. The cheapest moment to make a control
        # followable is the moment it first blocks somebody.
        print("\n" + "-" * 78)
        print("HOW TO CLEAR THIS  (docs/operations/TAXONOMY_DRIFT.md has the long version)")
        print("-" * 78)
        print("""
FOUR REMEDIES, IN ORDER. Registration is the THIRD, not the first -- a gate that hands you a
green button is not a gate. Green-by-taxonomy-inflation is `ignoreFailures: true` wearing
reading glasses.

  1  CORRECT AN ACCIDENTAL OR MALFORMED TERM.
     Check the registered list above. If your token is one character off something that
     already exists, the taxonomy is right and the code is wrong. Fix the spelling in the
     code. A near-miss value is WORSE than a wild one: consumers read it as blank, and
     blank renders as unqualified. Registering the typo would canonise it.

  2  REUSE AN EXISTING CANONICAL TERM when the concept is equivalent.
     Two spellings of one concept is the defect this gate exists to catch. If a registered
     value already means what you mean, use it -- even if you would have named it
     differently.

  3  REGISTER A GENUINELY NEW CONCEPT -- and only after reviewing four things:
       * SEMANTICS       what is true when something is in this state, precisely
       * NAMESPACE       does an existing namespace already own this concept? Adding a
                         value to one beats inventing a namespace beside it
       * TRANSITIONS     what may move into and out of it, and what may never
       * CONSUMERS       who branches on it, and what each of them does with it
     The block printed below is a CANDIDATE REGISTRATION, not a fix. It is scaffolding to
     save you typing the nesting; it is not evidence that the term deserves to exist, and
     pasting it unreviewed converts a red pipeline into a permanently wrong vocabulary.

  4  USE ORDINARY PROSE FORMATTING when the phrase is explanatory rather than machine
     vocabulary. This reader is deliberately broad and looks at all-caps tokens in files
     that drive behaviour. A constant, an environment variable, a log string, or a
     sentence that happens to be shouting is a false positive -- write it in mixed case
     and it stops looking like a state.

It is NOT an option to delete the check or add an exemption. A gate with an exemption
clause is a gate with a bypass, and this one exists because an undefined enforcement word
is how PARTIAL quietly becomes PASS three layers downstream.
""")
        print("Paste-ready starting point — replace the description, rule and definitions:\n")
        print("  your_namespace_name:")
        print("    description: >-")
        print("      What this set of values is ABOUT, in one sentence a stranger can act on.")
        print("    consumers: [the file or job that branches on these values]")
        print("    rule: >-")
        print("      THE INVARIANT THIS VOCABULARY PROTECTS. What must never be collapsed into what.")
        print("    values:")
        for k in sorted(drift):
            print("      %s:" % k)
            print("        definition: What is true when a thing is in this state.")
            print("        rule: When this value must NOT be treated as one of its neighbours.")
        print("")
        print("::error title=Taxonomy drift::%d term(s) drive behaviour but are not in "
              "assurance-taxonomy.yaml. The step output above prints the four "
              "remedies in order -- registration is the THIRD -- and a CANDIDATE block, and "
              "docs/operations/TAXONOMY_DRIFT.md has worked examples. An undefined enforcement "
              "word is how PARTIAL quietly becomes PASS three layers downstream." % len(drift))
        return 1

    print("\ntaxonomy OK — every vocabulary token in use is registered.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
