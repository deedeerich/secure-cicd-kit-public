#!/usr/bin/env python3
"""CANONICAL SARIF path normalizer. Re-root scanner paths onto the repository.

THIS FILE IS THE SINGLE SOURCE OF TRUTH.

It is INLINED into the reusable workflows rather than called as `uses: ./...`, because a reusable
workflow resolves local paths against the CALLER's checkout — so anything under `scripts/` simply
does not exist at consumer runtime. That is the same failure that left 14 Azure gitleaks rules
silently unloaded for every consumer while the kit's own CI stayed green.

Inlining three copies would reintroduce drift, which is the defect family this kit exists to catch
(a fix applied to the probe and not the workflow; a tag bumped in one place and not another). So the
copies are CHECKED: `self-test` asserts every inlined block is byte-identical to this file. Drift
becomes a build failure instead of a silent divergence.

WHY NORMALIZATION IS NEEDED AT ALL
----------------------------------
A scanner invoked with a subdirectory as its working directory reports URIs relative to THAT
directory, not the repository:

  gosec  runs per Go module   -> `go/vuln.go` and `services/worker/vuln.go` BOTH arrive as `vuln.go`
  Trivy  roots at the scan scope -> `infra/main.tf` where Checkov reports the full repo-relative path

Two files acquire one identity, or one file acquires two. Everything downstream inherits it:
annotations point at paths that do not exist, finding history cannot separate components across
runs, one scanner silently "covers for" another in a tool-pinned assertion, and correlation later
merges findings from different components as though they were the same finding.

The component root CANNOT be recovered afterwards — merged filenames use `tr '/' '_'`, which is
lossy. So normalization happens at the POINT OF CAPTURE, while the root is still known.

INVARIANT: normalize only after source identity is bound. Never merge first and reconstruct
provenance later.

USAGE
    python3 normalize_sarif.py <src.sarif> <dst.sarif> <prefix>

`<prefix>` is the component root relative to the repository. `.` or empty is a no-op, so callers
need no special case for a root-level project. Idempotent: a URI already carrying the prefix is left
alone, so re-running cannot double-root.

Reads SRC and writes DST — never rewrites in place. Containerized scanners produce ROOT-OWNED files;
opening one for writing fails with EACCES, which turned a misreported finding into an absent one.
"""

import io
import json
import sys


def reroot(uri, prefix):
    if not uri or not isinstance(uri, str):
        return uri
    u = uri.replace("\\", "/")
    if u.startswith("file://"):
        u = u[7:]
    while u.startswith("./"):
        u = u[2:]
    # An absolute path inside a CONTAINER says nothing about the repository.
    if u.startswith("/src/"):
        u = u[5:]
    u = u.lstrip("/")
    if prefix in ("", "."):
        return u
    if u == prefix or u.startswith(prefix + "/"):
        return u          # idempotent: never double-root
    return prefix + "/" + u


def fix_locs(locs, prefix):
    for loc in locs or []:
        if not isinstance(loc, dict):
            continue
        phys = loc.get("physicalLocation")
        if isinstance(phys, dict):
            art = phys.get("artifactLocation")
            if isinstance(art, dict) and "uri" in art:
                art["uri"] = reroot(art["uri"], prefix)


def normalize(doc, prefix):
    for run in doc.get("runs", []) or []:
        for art in run.get("artifacts", []) or []:      # what viewers resolve against
            al = (art or {}).get("location")
            if isinstance(al, dict) and "uri" in al:
                al["uri"] = reroot(al["uri"], prefix)
        for res in run.get("results", []) or []:
            fix_locs(res.get("locations"), prefix)
            fix_locs(res.get("relatedLocations"), prefix)
            at = res.get("analysisTarget")
            if isinstance(at, dict) and "uri" in at:
                at["uri"] = reroot(at["uri"], prefix)
            # A partially re-rooted code flow is worse than none — it still looks authoritative.
            for flow in res.get("codeFlows", []) or []:
                for tf in (flow or {}).get("threadFlows", []) or []:
                    for step in (tf or {}).get("locations", []) or []:
                        if isinstance(step, dict):
                            fix_locs([step.get("location")], prefix)
    return doc


def main(argv):
    if len(argv) != 4:
        print("usage: normalize_sarif.py <src> <dst> <prefix>", file=sys.stderr)
        return 2
    src, dst = argv[1], argv[2]
    prefix = argv[3].replace("\\", "/").strip("/")
    doc = json.load(io.open(src, encoding="utf-8"))
    json.dump(normalize(doc, prefix), io.open(dst, "w", encoding="utf-8"))
    n = sum(len(r.get("results", []) or []) for r in doc.get("runs", []) or [])
    print("normalize_sarif: %s -> %s rooted at '%s' (%d result(s))" % (src, dst, prefix or ".", n))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
