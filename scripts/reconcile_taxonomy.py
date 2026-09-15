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

# SCREAMING_SNAKE tokens that are environment variables, GitHub contexts or tool names -- not
# vocabulary. Kept explicit rather than heuristic, because a heuristic that quietly swallows a real
# taxonomy term would defeat the whole check.
NOT_VOCABULARY = {
    "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_STEP_SUMMARY", "GITHUB_PATH", "GITHUB_TOKEN",
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
    # Script-internal identifiers and shell variables.
    "WF_DIR", "TX_PY", "STRIP_PY", "TRUSTED_ORGS", "WORKFLOWS_PATH", "SCAN_DIRS", "SCAN_EXT",
    "NOT_VOCABULARY", "CAPABILITY_REGISTRY", "VALIDATION_REGISTRY", "TEST_RESOURCE_GROUP",
    "SUBSCRIPTION_ID", "REQUIRE_SHA", "TLS1_0", "TLS1_2", "MIN_JAVA", "DC_VER",
    # Annotation titles emitted to the operator -- messages, not states.
    "VALIDATION_COVERAGE_GAP",
    # Platform/tooling identifiers and fixture content -- not this kit's vocabulary.
    "ACTIONS_ID_TOKEN_REQUEST_URL", "EXAMPLE_NOT_A_REAL_KEY", "EXPORT_MANIFEST",
    "NORMALIZE_SARIF", "PRE_TEST_RESOURCE_COUNT", "POST_CLEANUP_RESOURCE_COUNT",
    # Env-var names and heredoc tags introduced by the reporting/redaction chain.
    "GH_TOKEN", "RUN_URL", "JOB_STATUS", "SCAN_REPORT", "SCAN_REPORT_PY", "SCAN_STATUS",
    "SCAN_STATUS_SH", "REDACT_SARIF", "REDACT_SARIF_PY", "PR_BODY", "TICKET_HOST",
    "TICKET_PROJECT", "ENFORCE_DIGIT_RANGE", "MIN_DIGITS", "MAX_DIGITS", "IN_PATHS",
    "IN_LANGUAGE", "IN_IAC_MODE", "REDACTED_MARK", "DECLARED_KEYS", "DECLARED_LABEL",
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
    # Another repository's SECRET NAME, quoted in a roadmap note describing how the reference estate gated on
    # GHAS. Not this kit's vocabulary -- and the approach it names is superseded by the discover
    # job, which probes rather than trusting a hand-set declaration.
    "GITHUB_ADVANCED_SECURITY_ENABLED",
    # Generated output filenames and heredoc tags.
    "CAPABILITY_CUSTODY", "SBOM_LICENSES", "SBOM_LICENSES_PY",
    # Another repository's document filename, cited in an architecture note.
    "WORKFLOW_ORCHESTRATION_DESIGN",
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
    return out


def scan_files():
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d)
        for dp, _, fns in os.walk(base):
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
        print("\n::error title=Taxonomy drift::%d term(s) drive behaviour but are not in "
              "assurance-taxonomy.yaml. Register them or stop using them. An undefined enforcement "
              "word is how PARTIAL quietly becomes PASS three layers downstream." % len(drift))
        return 1

    print("\ntaxonomy OK — every vocabulary token in use is registered.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
