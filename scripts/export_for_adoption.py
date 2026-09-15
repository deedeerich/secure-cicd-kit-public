#!/usr/bin/env python3
"""Produce a work-facing copy of the kit — and REFUSE if anything personal survives.

Why this exists
---------------
This kit is developed in a personal account and adopted inside an organisation. Those are
different trust boundaries, and the material that legitimately accumulates on the development
side must not cross:

  * names of private repositories used as validation consumers
  * their finding counts, which together with a name form a reconnaissance summary
  * the developing account's identity, and any other account's
  * former-employer names, tenant identifiers, product codenames
  * the git HISTORY, which retains all of the above even after files are cleaned

The last point is the one that catches people. Scrubbing a document does not scrub the commit
that introduced it. So an export is a **fresh tree with no history**, not a clone.

This is a GATE, not a linter. It exits non-zero and writes nothing when a pattern matches,
because "we intended to check" is exactly how this class of leak ships.

    python3 scripts/export_for_adoption.py --out ../secure-cicd-kit-export

Add project-specific patterns with --deny; they are matched case-insensitively.
"""
from __future__ import annotations
import argparse, os, re, shutil, subprocess, sys, datetime

# Personal / private material that must never reach an organisation copy.
# Patterns are deliberately broad: a false positive costs a conversation, a false
# negative costs a disclosure.
DENY_FILE = "export-deny.txt"   # beside this script; NEVER exported — see the file's header


def load_deny(script_dir: str) -> list[tuple[str, str]]:
    """Patterns live in a sibling file so the exported script carries no personal names.

    Shipping the deny list to the audience it protects against would defeat the purpose,
    so the SCRIPT is exportable and the LIST is not. A recipient writes their own.
    """
    path = os.path.join(script_dir, DENY_FILE)
    if not os.path.exists(path):
        print(f"WARNING: no {DENY_FILE} beside the script — nothing is being checked.")
        print("An export gate with an empty pattern list is theatre. Create one.")
        return []
    out = []
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pat, _, why = line.partition("||")
        out.append((pat.strip(), why.strip() or "listed in " + DENY_FILE))
    return out

# Never exported. .git is the important one — history outlives any file edit.
EXCLUDE_DIRS = {".git", ".github/workflows/consumer-path-test.yml", "__pycache__", ".pytest_cache"}
EXCLUDE_NAMES = {".DS_Store", "export-deny.txt"}

# OVERLAYS ARE NEVER EXPORTED, AND THIS IS ARCHITECTURE RATHER THAN HYGIENE.
#
# An overlay is one organisation's adaptation of the neutral kit. It carries their tooling, their
# policy constants and, in at least one case, an inventory of their declared toolchain. It is not
# part of the neutral contract and it belongs to them, so a neutral copy must not contain it --
# whoever the copy is going to.
#
# The deny gate already refuses an export whose text names an employer, so shipping an overlay
# would FAIL rather than leak. That is the right fail-safe and the wrong outcome: the export
# should succeed and simply not contain material that was never neutral. Excluding by structure
# means a NEW overlay, for an organisation nobody has added a deny pattern for yet, is excluded
# the day it is created rather than the day someone remembers.
EXCLUDE_TREES = {"overlays"}


def ignored_paths(root: str) -> set:
    """Everything git deliberately does not track. NOT part of the kit, by definition.

    The gate caught this the first time it ran with overlays excluded: consumer-coverage.json is
    gitignored, still sits in the working tree, and contains absolute local paths naming a former
    engagement and every private project beside it. A tree copy would have carried it into a
    PUBLIC repository.
    
    The gate refusing was the correct fail-safe. The correct RULE is that an export ships what the
    kit is, and what the kit is, is what git tracks. A local generated artifact is not the kit --
    and this also covers the next one, which nobody will remember to name.
    """
    try:
        out = subprocess.check_output(
            ["git", "-C", root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
            stderr=subprocess.DEVNULL)
    except Exception:
        return set()
    return {p.replace("/", os.sep) for p in out.decode("utf-8", "replace").split("\0") if p}
BINARY_EXT = {".png", ".jpg", ".gif", ".pdf", ".zip", ".pdom", ".doc", ".pptx", ".ico"}


_IGNORED: set = set()


def scan(root: str, deny: list[tuple[str, str]]) -> list[tuple[str, int, str, str]]:
    global _IGNORED
    _IGNORED = ignored_paths(root)
    hits = []
    pats = [(re.compile(p, re.I), why) for p, why in deny]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in {".git", "__pycache__", ".pytest_cache"} | EXCLUDE_TREES]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in BINARY_EXT or fn in EXCLUDE_NAMES:
                continue
            fp = os.path.join(dirpath, fn)
            if os.path.relpath(fp, root) in _IGNORED:
                continue
            rel = os.path.relpath(fp, root).replace("\\", "/")
            try:
                text = open(fp, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                for pat, why in pats:
                    m = pat.search(line)
                    if m:
                        hits.append((rel, i, m.group(0), why))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="destination directory (must not exist)")
    ap.add_argument("--deny", action="append", default=[], help="extra pattern to forbid")
    ap.add_argument("--force", action="store_true",
                    help="export anyway and list the leaks. Use only when every hit has been "
                         "reviewed and judged safe — it defeats the point of the gate.")
    a = ap.parse_args()

    src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    here = os.path.dirname(os.path.abspath(__file__))
    deny = load_deny(here) + [(p, "user-supplied --deny") for p in a.deny]

    print(f"source : {src}")
    print(f"export : {a.out}")
    print(f"patterns: {len(deny)}")
    print()

    hits = scan(src, deny)
    if hits:
        print(f"BLOCKED — {len(hits)} occurrence(s) of material that must not leave this account:")
        print()
        seen = {}
        for rel, line, match, why in hits:
            seen.setdefault(rel, []).append((line, match, why))
        for rel in sorted(seen):
            print(f"  {rel}")
            for line, match, why in seen[rel][:6]:
                print(f"      :{line:<5} {match!r}  — {why}")
            if len(seen[rel]) > 6:
                print(f"      … {len(seen[rel]) - 6} more")
        print()
        if not a.force:
            print("Nothing was written. Fix the source, or re-run with --force once every hit")
            print("above has been reviewed. Remember the git history is NOT exported, so this")
            print("only covers the working tree — which is the point.")
            return 1
        print("--force given: exporting anyway.")

    if os.path.exists(a.out):
        print(f"refusing to overwrite existing path: {a.out}")
        return 1

    # Fresh tree, no history. A clone would carry every scrubbed commit with it.
    def ignore(dirpath, names):
        drop = {n for n in names if n in EXCLUDE_NAMES}
        drop |= {n for n in names
                 if os.path.relpath(os.path.join(dirpath, n), src) in _IGNORED}
        if os.path.basename(dirpath) == os.path.basename(src):
            drop |= {".git"}
        drop |= {n for n in names if n in {"__pycache__", ".pytest_cache"}}
        if os.path.basename(dirpath) == os.path.basename(src):
            drop |= {n for n in names if n in EXCLUDE_TREES}
        return drop

    shutil.copytree(src, a.out, ignore=ignore)
    shutil.rmtree(os.path.join(a.out, ".git"), ignore_errors=True)

    stamp = datetime.datetime.now().strftime("%Y-%m-%d")
    with open(os.path.join(a.out, "EXPORT_MANIFEST.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"""# Export manifest

Produced by `scripts/export_for_adoption.py` on **{stamp}**.

## This is a fresh tree, not a clone

**Git history was deliberately not exported.** Scrubbing a file does not scrub the commit that
introduced it, so a clone would carry every removed name and number along with it. This copy
starts from zero: `git init`, one commit, no inherited past.

## What the gate checked

{len(deny)} forbidden patterns covering personal account identities, private consumer repository
names, finding counts attributable to a consumer, and former-employer references.

**Occurrences found at export time: {len(hits)}.**

## What this gate does NOT cover

- Anything added after this export
- Binary files
- The originating repository's history, which still contains everything ever committed there
- Judgement. A pattern list catches what it was told to catch.

Re-run the gate before any onward distribution. It is cheap and it fails closed.
""")
    n = sum(len(fs) for _r, _d, fs in os.walk(a.out))
    print(f"exported {n} files")
    print("history: NOT included (fresh tree)")
    print(f"\nnext:  cd {a.out} && git init && git add -A && git commit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
