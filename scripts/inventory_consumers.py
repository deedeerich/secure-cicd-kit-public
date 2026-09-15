#!/usr/bin/env python3
"""Consumer Coverage Registry -- what is actually in the estate, and what this kit can scan.

WHY THIS EXISTS
    The kit's language support was chosen from the author's assumptions about what repositories
    contain. That is a declared truth. This walks the actual filesystem and produces the actual
    truth, so the gap between them stops being invisible.

THREE DIFFERENT COVERAGE QUESTIONS, DELIBERATELY NOT MERGED
    implementation coverage  the kit claims a scanner for this ecosystem
    consumer coverage        a real repository exists that exercises it
    assurance coverage       the workflow has been PROVEN to discover, scan and interpret it

    Only the first two are answerable from a filesystem walk. The third requires a run against a
    real consumer, and this script must not imply otherwise -- it reports UNPROVEN for all of it
    rather than leaving a column that looks answered.

WHAT IT REFUSES TO DO
    It does not report a repository as "no Python" when it could not read the repository. Every
    unreadable root is counted and named. A survey that cannot distinguish "nothing there" from
    "could not look" is the defect this whole kit exists to eliminate, and a tool that measures
    coverage is the last place it should appear.
"""

import io
import json
import os
import sys

# Extension -> ecosystem. Only ecosystems the kit has a scanner for are marked supported.
SUPPORTED = {
    ".py": "python", ".js": "node", ".jsx": "node", ".ts": "node", ".tsx": "node",
    ".go": "go", ".cs": "dotnet", ".java": "java",
    ".c": "cpp", ".cc": "cpp", ".cpp": "cpp", ".h": "cpp", ".hpp": "cpp",
    ".tf": "iac", ".bicep": "iac",
}
UNSUPPORTED = {
    ".rs": "rust", ".rb": "ruby", ".php": "php", ".swift": "swift", ".kt": "kotlin",
    ".scala": "scala", ".ex": "elixir", ".exs": "elixir", ".erl": "erlang", ".hs": "haskell",
    ".lua": "lua", ".pl": "perl", ".pm": "perl", ".r": "r", ".jl": "julia", ".dart": "dart",
    ".groovy": "groovy", ".clj": "clojure", ".zig": "zig", ".nim": "nim",
    ".vb": "vbnet", ".fs": "fsharp", ".sh": "shell", ".ps1": "powershell", ".sql": "sql",
    ".m": "objc-or-matlab",  # genuinely ambiguous; recorded as ambiguous, not guessed
}
MANIFESTS = {
    "requirements.txt": "python", "pyproject.toml": "python", "setup.py": "python",
    "package.json": "node", "go.mod": "go", "pom.xml": "java",
    "build.gradle": "java", "build.gradle.kts": "java",
    "Cargo.toml": "rust", "Gemfile": "ruby", "composer.json": "php",
    "Chart.yaml": "iac", "kustomization.yaml": "iac", "azuredeploy.json": "iac",
}
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
             "dist", "build", "bin", "obj", ".terraform", "target", "packages"}
# Directories whose presence means the tree contains code the repo did not write.
GENERATED = {"node_modules", "vendor", "dist", "build", "obj", ".terraform", "packages"}


def walk_repo(root, max_files=200000):
    """Return (counts, manifests, traits, module_roots, unreadable, truncated)."""
    counts, manifests, traits, module_roots = {}, {}, set(), []
    unreadable, seen = [], 0
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: unreadable.append(str(e))):
        base = os.path.basename(dirpath)
        if base in GENERATED:
            traits.add("has-generated-or-vendor")
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            seen += 1
            if seen > max_files:
                truncated = True
                return counts, manifests, traits, module_roots, unreadable, truncated
            if fn in MANIFESTS:
                manifests[fn] = manifests.get(fn, 0) + 1
                if fn in ("go.mod", "pom.xml", "package.json", "Cargo.toml"):
                    module_roots.append(os.path.relpath(dirpath, root))
            if fn.startswith("Dockerfile"):
                traits.add("containerized")
            ext = os.path.splitext(fn)[1].lower()
            eco = SUPPORTED.get(ext) or UNSUPPORTED.get(ext)
            if eco:
                counts[eco] = counts.get(eco, 0) + 1
    return counts, manifests, traits, module_roots, unreadable, truncated


def is_repo(path):
    return os.path.isdir(os.path.join(path, ".git")) or os.path.isfile(os.path.join(path, ".git"))


def main(roots):
    repos, non_repos, failed = [], [], []

    candidates = []
    for r in roots:
        if not os.path.isdir(r):
            failed.append((r, "root does not exist or is not a directory"))
            continue
        try:
            for name in sorted(os.listdir(r)):
                p = os.path.join(r, name)
                if os.path.isdir(p):
                    candidates.append(p)
        except OSError as e:
            failed.append((r, "could not list: %s" % e))

    for p in candidates:
        try:
            counts, manifests, traits, module_roots, unreadable, truncated = walk_repo(p)
        except OSError as e:
            failed.append((p, "walk failed: %s" % e))
            continue
        rec = {
            "path": p,
            "name": os.path.basename(p),
            "git": is_repo(p),
            "ecosystems": counts,
            "manifests": manifests,
            "traits": sorted(traits),
            "module_roots": len(module_roots),
            "multi_root": len(module_roots) > 1,
            "unreadable_subtrees": len(unreadable),
            "truncated": truncated,
        }
        (repos if rec["git"] else non_repos).append(rec)

    # ---- Estate coverage ---------------------------------------------------
    est_sup, est_unsup = {}, {}
    for rec in repos + non_repos:
        for eco, n in rec["ecosystems"].items():
            tgt = est_sup if eco in set(SUPPORTED.values()) else est_unsup
            tgt.setdefault(eco, {"files": 0, "repos": 0})
            tgt[eco]["files"] += n
            tgt[eco]["repos"] += 1

    print("=" * 78)
    print("CONSUMER COVERAGE REGISTRY")
    print("=" * 78)
    print("%d git repositories, %d non-git directories, %d roots failed to scan"
          % (len(repos), len(non_repos), len(failed)))
    if failed:
        print("\nCOULD NOT SCAN -- these are UNKNOWN, not empty:")
        for p, why in failed:
            print("   %-46s %s" % (os.path.basename(p) or p, why))

    print("\n--- ECOSYSTEMS THE KIT SUPPORTS (consumer coverage) ---")
    print("   %-12s %10s %8s   %s" % ("ecosystem", "files", "repos", "verdict"))
    for eco in sorted(set(SUPPORTED.values())):
        d = est_sup.get(eco)
        if d:
            print("   %-12s %10d %8d   real consumer available" % (eco, d["files"], d["repos"]))
        else:
            print("   %-12s %10s %8s   NO REAL CONSUMER -- needs a reference repo" % (eco, "-", "-"))

    if est_unsup:
        print("\n--- PRESENT IN THE ESTATE, NO SCANNER IN THE KIT (coverage gap) ---")
        for eco, d in sorted(est_unsup.items(), key=lambda x: -x[1]["files"]):
            print("   %-16s %8d files across %d repo(s)" % (eco, d["files"], d["repos"]))

    print("\n--- TOPOLOGY TRAITS (what shapes we can actually exercise) ---")
    multi = [r for r in repos + non_repos if r["multi_root"]]
    cont = [r for r in repos + non_repos if "containerized" in r["traits"]]
    gen = [r for r in repos + non_repos if "has-generated-or-vendor" in r["traits"]]
    trunc = [r for r in repos + non_repos if r["truncated"]]
    unread = [r for r in repos + non_repos if r["unreadable_subtrees"]]
    print("   multi-module-root repos : %d" % len(multi))
    print("   containerized repos     : %d" % len(cont))
    print("   with vendor/generated   : %d" % len(gen))
    print("   TRUNCATED (incomplete)  : %d" % len(trunc))
    print("   with unreadable subtrees: %d" % len(unread))
    for r in trunc:
        print("      ! %s exceeded the file cap -- its counts are a LOWER BOUND" % r["name"])
    for r in unread:
        print("      ! %s had %d unreadable subtree(s) -- counts are a LOWER BOUND"
              % (r["name"], r["unreadable_subtrees"]))

    print("\n--- LARGEST CANDIDATES BY SUPPORTED-CODE VOLUME ---")
    ranked = sorted(repos + non_repos,
                    key=lambda r: -sum(v for k, v in r["ecosystems"].items()
                                       if k in set(SUPPORTED.values())))
    for r in ranked[:12]:
        ecos = ", ".join("%s:%d" % (k, v) for k, v in
                         sorted(r["ecosystems"].items(), key=lambda x: -x[1])[:5])
        flags = []
        if r["multi_root"]:
            flags.append("multi-root")
        if "containerized" in r["traits"]:
            flags.append("docker")
        if not r["git"]:
            flags.append("non-git")
        print("   %-34s %-52s %s" % (r["name"][:34], ecos[:52], " ".join(flags)))

    print("\n--- ASSURANCE COVERAGE ---")
    print("   UNPROVEN for every ecosystem. A filesystem walk establishes that a consumer EXISTS.")
    print("   It establishes nothing about whether the workflow discovers, scans, and correctly")
    print("   interprets it. That requires a run against a real consumer and has not happened.")

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                       "consumer-coverage.json")
    io.open(out, "w", encoding="utf-8").write(json.dumps(
        {"repos": repos, "non_repos": non_repos, "failed": failed,
         "supported": est_sup, "unsupported": est_unsup}, indent=2))
    print("\nfull record: %s" % os.path.normpath(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["."]))
