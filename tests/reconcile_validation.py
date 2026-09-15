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
    ],
    "reusable-nvd-cve.yml": ["nvd-dependency-check", "nvd-trivy", "nvd-dockerfile"],
    # The kit invoking its own reusable NVD workflow. It exercises the same capabilities
    # rather than adding new ones -- and registering a capability on two artifacts does NOT
    # double-count the debt, because accepted deferrals are deduplicated by capability.
    # It exists because the reusable workflow is `workflow_call`-only: with no caller and no
    # dispatch trigger it was unvalidatable by construction, not merely unvalidated.
    "nvd-cve.yml": ["nvd-dependency-check", "nvd-trivy", "nvd-dockerfile"],
    "reusable-build-docker.yml": ["image-build", "image-push"],
    "reusable-deploy-appservice.yml": ["deploy-appservice"],
    "reusable-deploy-containerapp.yml": ["deploy-containerapp"],
    "workflow-policy-check.yml": ["workflow-policy"],
    "verify-azure-oidc.yml": ["azure-oidc-auth", "context-integrity"],
    "action:azure-login-oidc": ["azure-oidc-auth"],
    "action:determine-changes": ["change-detection"],
    "action:docker-build-push": ["image-build", "image-push"],
    "action:render-version-metadata": ["version-metadata"],
    "action:setup-node": ["toolchain-node"],
    "action:setup-python": ["toolchain-python"],
    "action:setup-terraform": ["toolchain-terraform"],
}

# What is actually proven, and how. States:
#   observed                          executed + expected behavior on seeded input
#   unknown                           probe exists, has not passed
#   untested                          no probe at all
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
    "azure-oidc-auth": {"probe": "verify-azure-oidc.yml", "state": "observed", "level": "workflow"},
    # Positive path observed 2026-08-14 (run 31825375559): tenant, subscription and workload
    # identity all matched the declared values. The REFUSAL path has no fixture — an assertion
    # that has never failed is decoration, so this stays unknown until a deliberate mismatch
    # is proven to hard-fail. Same standard the negative control holds the scanners to.
    "context-integrity": {"probe": "verify-azure-oidc.yml", "state": "unknown", "level": "workflow",
                          "blocker": "positive path proven; no negative fixture forces a mismatch to fail"},
}

# reusable-security.yml has been invoked END-TO-END from a consumer-style caller and every
# seeded signal was detected. Set False the moment that stops being true — this flag is a
# claim about evidence, and a stale claim here re-creates precisely the illusion the
# consumer-path test was built to destroy.
#   evidence: consumer-path-test.yml run 31850914867 (2026-08-14)
#             16/16 seeded signals DETECTED across python, node, dotnet, java, go, cpp,
#             terraform, dockerfile and three Azure/Entra secret classes;
#             1/1 negative controls clean; seeded findings blocked the caller.
CONSUMER_PATH_PROVEN = True

# Provable, but needs resources not provisioned. NOT the same as untestable.
REQUIRES_INTEGRATION_ENV = {
    "deploy-appservice":     "real Azure App Service target",
    "deploy-containerapp":   "real Azure Container Apps target",
    "image-push":            "a container registry",
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
# An expired deferral goes BLOCKING. That is the mechanism: it forces a fresh decision instead
# of letting silence renew the old one. Re-dating is a legitimate outcome — doing it without
# looking is not, which is why the reason has to be rewritten to move the date.
DEFERRALS: dict[str, dict] = {
    # -- cheap: no infrastructure needed, so the only cost is someone writing the probe -----
    "toolchain-node":      {"reason": "composite never executed", "owner": "kit-maintainer",
                            "proves": "run the composite, assert the requested node version is active",
                            "expires": "2026-09-15"},
    "toolchain-python":    {"reason": "composite never executed", "owner": "kit-maintainer",
                            "proves": "run the composite, assert the requested python version is active",
                            "expires": "2026-09-15"},
    "toolchain-terraform": {"reason": "composite never executed", "owner": "kit-maintainer",
                            "proves": "run the composite, assert terraform resolves at the pinned version",
                            "expires": "2026-09-15"},
    "change-detection":    {"reason": "composite never executed", "owner": "kit-maintainer",
                            "proves": "seeded diff produces the expected filter outputs, and a no-op diff does not",
                            "expires": "2026-09-15"},
    "version-metadata":    {"reason": "composite never executed", "owner": "kit-maintainer",
                            "proves": "emits digest, SBOM hash, git SHA and run id in DEPLOY_PROVENANCE",
                            "expires": "2026-09-15"},

    # -- needs fixture work ----------------------------------------------------------------
    "code-quality":  {"reason": "no probe; ruff/eslint path never exercised", "owner": "kit-maintainer",
                      "proves": "seeded lint violation fails the job; clean fixture does not",
                      "expires": "2026-09-30"},
    "sast-java":     {"reason": "no Java fixture exists", "owner": "kit-maintainer",
                      "proves": "seeded vulnerable Java produces the expected finding class",
                      "expires": "2026-09-30"},
    "nvd-trivy":     {"reason": "reusable-nvd-cve.yml has never run on a runner", "owner": "kit-maintainer",
                      "proves": "trivy path in the NVD workflow detects a seeded CVE",
                      "expires": "2026-09-30"},
    "nvd-dockerfile":{"reason": "reusable-nvd-cve.yml has never run on a runner", "owner": "kit-maintainer",
                      "proves": "seeded Dockerfile misconfiguration is detected",
                      "expires": "2026-09-30"},
    "context-integrity": {"reason": "positive path observed; refusal path has no fixture",
                      "owner": "kit-maintainer",
                      "proves": "a deliberately mismatched tenant/subscription/identity HARD FAILS the job",
                      "expires": "2026-09-30"},

    # -- genuinely needs infrastructure ----------------------------------------------------
    "image-build":   {"reason": "no registry provisioned", "owner": "kit-maintainer",
                      "proves": "build emits a digest and an SBOM containing known fixture components",
                      "expires": "2026-10-31"},
    "image-push":    {"reason": "no container registry", "owner": "kit-maintainer",
                      "proves": "pushed image is retrievable by the digest the build emitted",
                      "expires": "2026-10-31"},
    "deploy-appservice":   {"reason": "blocked on ROLLBACK_CONTRACT.md — a DESIGN gate, not access",
                      "owner": "kit-maintainer",
                      "proves": "rollback contract implemented, then deploy + induced-failure rollback verified live",
                      "expires": "2026-10-31"},
    "deploy-containerapp": {"reason": "blocked on ROLLBACK_CONTRACT.md — a DESIGN gate, not access",
                      "owner": "kit-maintainer",
                      "proves": "rollback contract implemented, then revision rollback verified live",
                      "expires": "2026-10-31"},

}

# Ratchet. Accepted debt may shrink, never grow. A new deferral must displace an old one or
# raise this number deliberately, in a reviewable diff, with a reason in the commit message.
MAX_ACCEPTED_DEBT = 14   # ratchet tightened: azure-oidc-auth-e2e closed by evidence

DEFERRAL_WARN_DAYS = 14      # surface an approaching expiry before it turns red

# ---------------------------------------------------------------- discovery

def classify(path: str) -> str:
    doc = yaml.safe_load(open(path, encoding="utf-8")) or {}
    on = doc.get("on", doc.get(True)) or {}
    if isinstance(on, dict) and "workflow_call" in on:
        return "reusable"
    name = os.path.basename(path)
    if name in ("self-test.yml", "validate-scanners.yml",
                "consumer-path-test.yml", "consumer-path-negative.yml"):
        return "test-harness"
    return "orchestration"


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


def main() -> int:
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

    def classify_gap(cap: str, why: str) -> None:
        """Unproven capability -> BLOCKING unless a complete, unexpired deferral covers it."""
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
