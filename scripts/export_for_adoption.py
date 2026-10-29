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
import argparse, hashlib, json, os, re, shutil, subprocess, sys, datetime

# ── INCREMENTAL EXPORT: the second and every later time ──────────────────────────────
#
# A full export answers "give them the kit". It cannot answer "give them what changed", and that
# is the question from the second export onward. Re-copying the whole tree each time would do two
# unacceptable things: it would overwrite work-side edits made since the last export, and it would
# touch files nobody changed, making the resulting commit unreviewable — a diff that includes
# everything says nothing about what moved.
#
# So the destination carries a WATERMARK recording what it last received: the source commit, and a
# hash of every file as it was handed over. That turns the next export into a three-way question
# this tool can answer honestly:
#
#     source changed, destination untouched since  ->  safe to update
#     source changed, destination ALSO changed     ->  CONFLICT, reported, never silently resolved
#     source deleted it                            ->  reported, applied only when asked
#
# The watermark lives in the destination rather than here, because it is a fact about what THAT
# copy received. One source can feed several destinations, each at a different point, and a
# watermark kept here could only ever describe one of them.
WATERMARK = ".neutral-export-watermark.json"


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_watermark(dest: str) -> dict | None:
    p = os.path.join(dest, WATERMARK)
    if not os.path.isfile(p):
        return None
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return None


def git_out(root: str, *args: str) -> str:
    return subprocess.check_output(["git", "-C", root, *args],
                                   stderr=subprocess.DEVNULL).decode("utf-8", "replace")


def exportable(rel: str) -> bool:
    """Is this path part of what an export ships?

    Mirrors the full-export exclusions exactly. They must not drift: a file the full export
    withholds but the incremental one sends would leak on the second run, which is precisely the
    kind of difference nobody looks for after the first one worked.
    """
    parts = rel.split("/")
    if parts[0] in EXCLUDE_TREES and not overlay_allowed(rel):
        return False
    if parts[0] in EXCLUDE_TOP or (len(parts) > 1 and parts[1] in EXCLUDE_TOP):
        return False
    if any(p in {".git", "__pycache__", ".pytest_cache"} for p in parts):
        return False
    if os.path.basename(rel) in EXCLUDE_NAMES:
        return False
    if os.path.basename(rel) == WATERMARK:
        return False
    if rel in EXCLUDE_PATHS:
        return False
    return True


def changed_since(src: str, base: str) -> tuple[list[str], list[str]]:
    """-> (changed-or-added, deleted) exportable paths between `base` and HEAD.

    Renames are decomposed into a delete and an add rather than carried as renames. The
    destination is a different repository with its own history; a rename there is not the same
    object moving, and pretending otherwise would produce a delete the operator never saw.
    """
    out = git_out(src, "diff", "--name-status", "-M", f"{base}..HEAD")
    changed, deleted = [], []
    for line in out.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        code = cols[0]
        if code.startswith("R") and len(cols) >= 3:
            deleted.append(cols[1])
            changed.append(cols[2])
        elif code.startswith("D"):
            deleted.append(cols[1])
        elif len(cols) >= 2:
            changed.append(cols[1])
    return ([p for p in sorted(set(changed)) if exportable(p)],
            [p for p in sorted(set(deleted)) if exportable(p)])

# Personal / private material that must never reach an organisation copy.
# Patterns are deliberately broad: a false positive costs a conversation, a false
# negative costs a disclosure.
DENY_FILE = "export-deny.txt"   # beside this script; NEVER exported — see the file's header


def load_deny(script_dir: str) -> list[tuple[str, str, bool]] | None:
    """Patterns live in a sibling file so the exported script carries no personal names.

    Shipping the deny list to the audience it protects against would defeat the purpose,
    so the SCRIPT is exportable and the LIST is not. A recipient writes their own.

    -> None when the file is absent. The caller REFUSES on that, and on a file with no pattern in
    it. This used to print a warning and return an empty list, and the export then proceeded with
    nothing checked -- the comment called that theatre and then performed it. Because this list
    never ships, every recipient who runs the shipped script onward starts in exactly that state,
    so the warning path was not a corner case: it was the default for everyone but the author.
    """
    path = os.path.join(script_dir, DENY_FILE)
    if not os.path.exists(path):
        return None
    out = []
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pat, _, why = line.partition("||")
        pat = pat.strip()
        # A leading `!` marks a pattern no export profile may lift. Stripped before compiling,
        # so the regex itself is unaffected and an existing list keeps working unchanged.
        never = pat.startswith(NEVER_LIFT_MARKER)
        if never:
            pat = pat[len(NEVER_LIFT_MARKER):].strip()
        out.append((pat, why.strip() or "listed in " + DENY_FILE, never))
    return out

# ── PROFILES: WHO A COPY IS FOR, AND WHAT THAT CHANGES ──────────────────────────────
#
# See scripts/export-profiles/README.md. The short version: a neutral export carries no overlay
# and refuses every denied name. A consumer-destined copy should carry THEIR overlay and may name
# THEM -- and forcing that through the neutral gate means reaching for --force, which disables the
# protection for everybody else at the same time. A profile lets the right export succeed normally.
PROFILE_DIR = "export-profiles"

# PATTERNS NO PROFILE MAY EVER LIFT -- MARKED IN THE DENY FILE, NEVER LISTED HERE.
#
# Everything else in the deny list is contextual: a consumer's name is denied in a neutral copy
# and legitimate in their own. Some patterns are not contextual. They are the developing account's
# identity, and no recipient is entitled to them for any reason a profile could state. A profile
# naming one is REFUSED outright rather than having the line ignored -- a profile that silently
# drops a directive is worse than one that fails, because the operator believes it took effect.
#
# THE FIRST VERSION OF THIS HARDCODED THE NAMES IN THIS FILE, AND THE GATE CAUGHT IT.
#
# That is the one mistake this whole repository is arranged to prevent: the SCRIPT is exported and
# the LIST is not, precisely so the protected names never travel to the audience they are being
# protected from. Writing them into the script to express "never lift these" put them on the next
# export of the script itself -- a leak introduced by the mechanism meant to prevent one.
#
# So unliftability is a PROPERTY OF THE LIST, declared in the file that never ships: prefix the
# pattern with `!`. The code here knows only that a flag exists, never what it protects.
NEVER_LIFT_MARKER = "!"


def load_profile(script_dir: str, name: str, deny: list[tuple[str, str]]):
    """-> (overlays to include, deny list with the profile's lifts removed, lift notes).

    Raises ValueError with an operator-readable reason rather than returning a partial result.
    Every failure here is a case where proceeding would produce a copy whose contents do not
    match what the operator believes they authorised.
    """
    path = os.path.join(script_dir, PROFILE_DIR, name + ".txt")
    if not os.path.isfile(path):
        avail = []
        d = os.path.join(script_dir, PROFILE_DIR)
        if os.path.isdir(d):
            avail = sorted(x[:-4] for x in os.listdir(d) if x.endswith(".txt"))
        raise ValueError(f"no profile {name!r} in {PROFILE_DIR}/. "
                         + (f"Available: {', '.join(avail)}" if avail else "There are none yet."))

    overlays, lifts = [], []
    for ln, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        verb, _, rest = line.partition(" ")
        verb = verb.upper()
        if verb == "INCLUDE_OVERLAY":
            overlays.append(rest.strip())
        elif verb == "LIFT":
            pat, _, why = rest.partition("||")
            pat, why = pat.strip(), why.strip()
            if not why:
                raise ValueError(f"{name}.txt line {ln}: LIFT with no reason after '||'. "
                                 "A lift without a stated reason cannot be reviewed later.")
            lifts.append((pat, why, ln))
        else:
            raise ValueError(f"{name}.txt line {ln}: unknown directive {verb!r}. "
                             "Expected INCLUDE_OVERLAY or LIFT.")

    known = {p: never for p, _w, never in deny}
    for pat, _why, ln in lifts:
        if pat not in known:
            raise ValueError(
                f"{name}.txt lifts {pat!r}, which is not a pattern in {DENY_FILE}. "
                "A lift that matches nothing silently protects nothing while appearing to lift "
                "something; fix the profile or the deny list so they agree.")
        if known[pat]:
            raise ValueError(
                f"{name}.txt line {ln}: {DENY_FILE} marks this pattern unliftable, and no profile "
                "may override that. It is denied because of what it IS, not because of who is "
                "receiving the copy, so no statement about the recipient can justify it.")

    lifted = {p for p, _w, _l in lifts}
    kept = [(p, w, n) for p, w, n in deny if p not in lifted]
    return overlays, kept, [(p, w) for p, w, _l in lifts]


# Never exported. .git is the important one — history outlives any file edit; it, __pycache__
# and .pytest_cache are pruned by name wherever they occur (exportable, scan, and the copy).
EXCLUDE_NAMES = {".DS_Store", "export-deny.txt"}

# EXACT PATHS, from the source root, that never ship.
#
# This used to be a set named for directories that held this path beside .git and the cache names,
# and nothing ever read it: from the day it was written (2026-08-16) the file it names shipped in
# every full and every incremental export. The intent is recoverable from what the file is: the
# kit's OWN Level 1 consumer-path harness, which calls the reusables by `./` against this
# repository's fixtures on a weekly schedule. It tests the kit where it is developed; in a
# recipient's copy it is a scheduled job billing their minutes to re-test our fixtures, not part
# of what they adopt. tests/prove_export_scope.py E2 and E6.
EXCLUDE_PATHS = {".github/workflows/consumer-path-test.yml"}

# NEITHER THE DENY LIST NOR THE PROFILES TRAVEL.
#
# Both describe the protection rather than being protected by it. export-deny.txt names what is
# being kept from the recipient; a profile names which of those the recipient is allowed and,
# by omission, which other parties exist. Shipping either to the audience they concern would
# disclose by describing. .claude/ holds agent worktrees -- nested checkouts of this very repo,
# which would otherwise be exported as if they were content.
#
# .context/ IS THE WORKSHOP, NOT THE KIT (2026-10-16). It holds this repository's continuity
# records for the sessions that build it: which trackers the owner proves against, which platform
# receives the explainer, the private commits each record was reconciled against. Found in the
# first export prepared for the public mirror after the release to main, read before it was pushed.
# A recipient's copy has its own history and needs none of it. tests/prove_export_scope.py.
EXCLUDE_TOP = {"export-profiles", ".claude", ".context"}

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

# Overlay directories a profile has explicitly included. Empty for a neutral export, which is the
# safe default: an overlay is excluded unless something names it, so a new one added tomorrow is
# excluded from the day it exists rather than from the day somebody remembers it.
_INCLUDED_OVERLAYS: set = set()


def overlay_allowed(rel: str) -> bool:
    """Is this overlays/ path one the current profile includes?"""
    parts = rel.replace("\\", "/").split("/")
    return len(parts) >= 2 and parts[0] == "overlays" and parts[1] in _INCLUDED_OVERLAYS


def ignored_paths(root: str) -> set:
    """Everything git deliberately does not track. NOT part of the kit, by definition.

    The gate caught this the first time it ran with overlays excluded: consumer-coverage.json is
    gitignored, still sits in the working tree, and contains absolute local paths naming a former
    engagement and every private project beside it. A tree copy would have carried it into a
    PUBLIC repository.
    
    The gate refusing was the correct fail-safe. The correct RULE is that an export ships what the
    kit is, and what the kit is, is what git tracks. A local generated artifact is not the kit --
    and this also covers the next one, which nobody will remember to name.

    UNTRACKED IS NOT TRACKED EITHER (2026-10-21). Only ignored files were excluded, so an untracked
    file nobody had thought to ignore -- a scanner tarball a CI step downloaded into the checkout --
    was scanned (a denied short name matched three bytes of compressed data, self-test run
    39618329392) and would have shipped. Both kinds are excluded now. tests/prove_export_scope.py E8.
    """
    found = set()
    for extra in (["--ignored", "--exclude-standard"], ["--exclude-standard"]):
        try:
            out = subprocess.check_output(
                ["git", "-C", root, "ls-files", "--others", *extra, "-z"],
                stderr=subprocess.DEVNULL)
        except Exception:
            continue
        found |= {p.replace("/", os.sep) for p in out.decode("utf-8", "replace").split("\0") if p}
    return found


BINARY_EXT = {".png", ".jpg", ".gif", ".pdf", ".zip", ".pdom", ".doc", ".pptx", ".ico"}


_IGNORED: set = set()


def scan(root: str, deny: list[tuple[str, str]]) -> list[tuple[str, int, str, str]]:
    global _IGNORED
    _IGNORED = ignored_paths(root)
    hits = []
    pats = [(re.compile(p, re.I), why) for p, why, _never in deny]
    for dirpath, dirnames, filenames in os.walk(root):
        # An INCLUDED overlay is descended into and scanned like everything else. Pruning it
        # would leave the one tree whose contents are least reviewed -- consumer-specific
        # material, written for one audience -- as the only tree never checked before it ships.
        # It is scanned against the deny list MINUS this recipient's own lifted patterns, so
        # their own name passes and a DIFFERENT consumer's name still blocks.
        keep = []
        for d in dirnames:
            if d in {".git", "__pycache__", ".pytest_cache"} or d in EXCLUDE_TOP:
                continue
            rel_d = os.path.relpath(os.path.join(dirpath, d), root).replace("\\", "/")
            if d in EXCLUDE_TREES and os.path.dirname(rel_d) == "":
                # overlays/ itself: descend only if some overlay under it is included
                if not _INCLUDED_OVERLAYS:
                    continue
                keep.append(d)
                continue
            if rel_d.startswith("overlays/") and rel_d.count("/") == 1:
                if d not in _INCLUDED_OVERLAYS:
                    continue
            keep.append(d)
        dirnames[:] = keep
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


NEUTRAL_PROFILE = "neutral"


def profile_label(name: str | None) -> str:
    return name or NEUTRAL_PROFILE


# GENERATED FILES DESCRIBE THE TREE THEY SIT IN (2026-10-21). The capability inventory is generated
# from the workflows present; copied from the source it named the internal consumer-path workflow
# the export withholds, and the copy's own self-test ("Normalizer drift") failed on the first public
# PR of Release 2. Each generated file is regenerated inside the copy, from the copy.
# tests/prove_export_scope.py E9.
GENERATED = ("docs/assurance/CAPABILITY_INVENTORY_GENERATED.csv",)


def regenerate_generated(dest: str) -> str | None:
    """Regenerate GENERATED inside `dest` from `dest`. -> None, or why it could not."""
    tool = os.path.join(dest, "tests", "capability_inventory.py")
    if not os.path.isfile(tool):
        return None
    # PYTHONDONTWRITEBYTECODE: this runs INSIDE the copy, and nothing it imports may leave a
    # compiled file behind in what ships (tests/prove_export_scope.py E10).
    p = subprocess.run([sys.executable, tool], cwd=dest, capture_output=True, text=True,
                       encoding="utf-8", errors="replace",
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    if p.returncode != 0:
        return f"tests/capability_inventory.py exited {p.returncode}: {(p.stdout + p.stderr)[-300:]}"
    return None


def write_watermark(src: str, dest: str, head: str, branch: str, shipped: dict,
                    unresolved: dict | None = None, dirty_flag: bool = False,
                    profile: str | None = None) -> None:
    data = {
        # WHO THIS COPY IS FOR. The rules a copy was taken under (which overlays it carries, which
        # names it may hold) are a fact about the destination, like the files it received, so they
        # are recorded here and every later incremental is refused unless it runs under the same
        # ones. "neutral" means no profile. scripts/export-profiles/README.md promised this
        # binding before the field existed; tests/prove_export_scope.py E5.
        "profile": profile_label(profile),
        # THE COMMIT, NOT THE BRANCH (owner's choice for the public copy, 2026-10-16). The
        # three-way incremental needs only the commit; a branch name describes how the source
        # repository is worked on, which is not the recipient's to know. tests/prove_export_scope E7.
        "source": "the kit's source repository (commit recorded; branch names are not)",
        "source_commit": head,
        "source_dirty": dirty_flag,
        "exported_at_utc": datetime.datetime.now(datetime.timezone.utc)
                                   .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": ("Written by scripts/export_for_adoption.py. It records what this copy RECEIVED, "
                 "so the next export can tell a source change from a change made here. Deleting "
                 "it does not break anything; it only forces the next export to be told its "
                 "baseline with --baseline."),
        # A CONFLICT REPORTED ONCE AND THEN FORGOTTEN IS A LOST CHANGE.
        #
        # Found by testing rather than by reasoning. Skipping a conflicted file is right -- it
        # protects work done on the destination side -- but the watermark then advanced to HEAD,
        # and the source edit that was skipped fell out of every later diff. The destination kept
        # its own version forever and nobody was told again. Silent divergence, which is worse
        # than either overwriting or refusing, because it looks like success.
        #
        # So an unresolved conflict is carried in the watermark and re-reported every run until
        # it is actually dealt with -- by taking the source version (--overwrite <path>) or by
        # reconciling the file by hand, after which its hash matches and it clears itself.
        "unresolved_conflicts": unresolved or {},
        "files": shipped,
    }
    with open(os.path.join(dest, WATERMARK), "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def incremental(src: str, a, deny: list, hit_count: int) -> int:
    dest = os.path.abspath(a.into)
    if not os.path.isdir(dest):
        print(f"--into must be an existing directory: {dest}")
        return 1

    wm = read_watermark(dest)

    # THE PROFILE IS BOUND TO THE DESTINATION. An incremental under different rules from the copy
    # it updates would mix two recipients' scopes in one tree: a neutral copy acquiring one
    # consumer's overlay and names, or a consumer's copy re-checked under rules that no longer
    # lift their own. Refused by name, before anything is classified. A watermark that predates
    # the field records no rules at all, and guessing them is the thing being refused; the
    # operator who knows can add "profile" to it by hand, which leaves a record of who decided.
    if wm is not None:
        want = profile_label(a.profile)
        if "profile" not in wm:
            print(f"REFUSED: the watermark in {dest} records no profile, so this tool cannot tell")
            print(f"which rules that copy was taken under, and will not assume {want!r}.")
            print(f"If you know it, add \"profile\": \"<name or {NEUTRAL_PROFILE}>\" to {WATERMARK}")
            print("and run this again; otherwise take a fresh full export with --out.")
            return 1
        if wm.get("profile") != want:
            print(f"REFUSED: {dest} was exported under profile {wm.get('profile')!r}; this run is "
                  f"{want!r}.")
            print("An incremental must use the rules of the copy it updates. Re-run with "
                  + (f"--profile {wm.get('profile')}" if wm.get("profile") != NEUTRAL_PROFILE
                     else "no --profile")
                  + ", or take a fresh full export with --out for the other recipient.")
            return 1

    base = a.baseline or (wm or {}).get("source_commit")
    if not base:
        print(f"no {WATERMARK} in {dest}, and no --baseline given.")
        print()
        print("This destination has no record of what it last received, so a diff against it")
        print("would be a guess. Either pass --baseline <commit> (the source commit that copy")
        print("was taken from), or take a fresh full export with --out.")
        return 1

    try:
        head = git_out(src, "rev-parse", "HEAD").strip()
        branch = git_out(src, "rev-parse", "--abbrev-ref", "HEAD").strip()
        git_out(src, "cat-file", "-e", f"{base}^{{commit}}")
    except subprocess.CalledProcessError:
        print(f"the baseline commit {base!r} is not in this repository.")
        print("If the destination came from a different clone or a rewritten branch, take a")
        print("fresh full export rather than diffing against a commit that does not exist here.")
        return 1

    # "NOTHING CHANGED AT THE SOURCE" IS NOT "NOTHING TO REPORT".
    #
    # An unresolved conflict is a source change that has not landed, and this early return made
    # it invisible again the moment the source stopped moving -- the exact disappearance the
    # carried-conflict list was added to prevent, reintroduced one line away from the feature
    # itself. The test for that feature is what caught it.
    carried_now = (wm or {}).get("unresolved_conflicts", {})
    if head == base and not carried_now:
        print(f"destination is already at {head[:9]} on {branch} -- nothing changed since.")
        return 0
    if head == base:
        print(f"destination is at {head[:9]} on {branch}: no new source changes, but "
              f"{len(carried_now)} conflict(s) still unresolved.")
        print()

    changed, deleted = changed_since(src, base)
    recorded = (wm or {}).get("files", {})

    # Conflicts carried forward from earlier runs. They are not in this diff -- that is the whole
    # problem -- so they are added back to the work list and re-examined. One that has since been
    # reconciled by hand will now hash equal and drop out on its own.
    carried = (wm or {}).get("unresolved_conflicts", {})
    for rel in carried:
        if rel not in changed and exportable(rel) and os.path.isfile(
                os.path.join(src, rel.replace("/", os.sep))):
            changed.append(rel)
    changed = sorted(set(changed))

    # ── CLASSIFY BEFORE TOUCHING ANYTHING ───────────────────────────────────────────
    #
    # Every file is sorted into exactly one bucket and the whole plan is printed before a byte
    # moves. An export that writes as it decides cannot be reviewed, and this one lands in a copy
    # someone else may be working in.
    safe, conflicts, new_files, missing, resolved = [], [], [], [], []
    total = len(changed)
    for i, rel in enumerate(changed, 1):
        sp = os.path.join(src, rel.replace("/", os.sep))
        dp = os.path.join(dest, rel.replace("/", os.sep))
        if not os.path.isfile(sp):
            continue
        if not os.path.exists(dp):
            (new_files if rel not in recorded else missing).append(rel)
        elif rel not in recorded:
            # Present in the destination but never shipped by this tool: it arrived some other
            # way, so there is no baseline hash and no way to tell an edit from a coincidence.
            conflicts.append((rel, "present in the destination but not in the watermark"))
        elif sha256_of(dp) == sha256_of(sp):
            # ALREADY IDENTICAL TO THE SOURCE. Tested first, because it outranks both of the
            # cases below: a file reconciled by hand on the destination side looks like a
            # conflict by hash-against-baseline, and reporting it as one forever would train the
            # operator to ignore the conflict list. Nothing to copy, and it clears itself.
            resolved.append(rel)
        elif sha256_of(dp) != recorded[rel]:
            why = "changed in the destination since the last export"
            if rel in carried:
                why += f"; UNRESOLVED since {carried[rel]}"
            conflicts.append((rel, why))
        else:
            safe.append(rel)
        if i % 25 == 0 or i == total:
            print(f"      [{i:4}/{total:<4}] classified", flush=True)

    print()
    print(f"baseline : {base[:9]}")
    print(f"head     : {head[:9]} on {branch}")
    print(f"deny hits: {hit_count}")
    print()
    print(f"  new in destination        {len(new_files):4}")
    print(f"  update, destination clean {len(safe):4}")
    print(f"  CONFLICT, left alone      {len(conflicts):4}")
    print(f"  reconciled by hand        {len(resolved):4}")
    print(f"  deleted at source         {len(deleted):4}")
    print(f"  shipped before, now gone  {len(missing):4}")
    print()

    for rel in new_files[:40]:
        print(f"  +  {rel}")
    for rel in safe[:40]:
        print(f"  M  {rel}")
    shown = len(new_files[:40]) + len(safe[:40])
    if len(new_files) + len(safe) > shown:
        print(f"     … {len(new_files) + len(safe) - shown} more")
    if conflicts:
        print()
        print("  CONFLICTS -- not written, because overwriting them would discard work:")
        for rel, why in conflicts:
            print(f"  !  {rel}")
            print(f"         {why}")
        print("     RE-REPORTED every run until resolved. Two ways to resolve one:")
        print("       reconcile it by hand in the destination  (it then clears itself), or")
        print("       --overwrite <path>  to take the source version, backing the other up first.")
        print(f"     To take all {len(conflicts)}: --overwrite-all-conflicts {len(conflicts)}")
    if missing:
        print()
        print("  shipped previously and no longer in the destination -- deleted there on purpose?")
        for rel in missing:
            print(f"  ?  {rel}")
        print("     Not resurrected. Name one with --overwrite <path> to send it again.")
    if deleted:
        print()
        print("  deleted at source:")
        for rel in deleted:
            print(f"  -  {rel}")
        if not a.apply_deletes:
            print("     Left in place. --apply-deletes removes them.")

    if not a.apply:
        print()
        print("PLAN ONLY -- nothing was written. Re-run with --apply.")
        return 0

    # Resolve exactly which conflicted files the operator authorised, and refuse anything
    # ambiguous. A name that matches no conflict is far more likely a typo or a stale path from
    # an earlier run than an intention, and acting on the ones that DID match while silently
    # dropping the rest is how a half-applied overwrite happens.
    conflict_paths = [rel for rel, _ in conflicts]
    authorised = []
    if a.overwrite_all_conflicts is not None:
        if a.overwrite_all_conflicts != len(conflict_paths):
            print()
            print(f"--overwrite-all-conflicts {a.overwrite_all_conflicts} was given, but "
                  f"{len(conflict_paths)} conflict(s) were found.")
            print("Refusing: the set you reviewed is not the set in front of you now. Re-read the")
            print("plan above and pass the number it reports, or name files with --overwrite.")
            return 1
        authorised = list(conflict_paths)
    unknown = [p for p in a.overwrite if p not in conflict_paths and p not in missing]
    if unknown:
        print()
        print("--overwrite named path(s) that are not conflicted:")
        for p in unknown:
            print(f"    {p}")
        print("Refusing rather than acting on the rest. Copy paths exactly from the plan.")
        return 1
    authorised += [p for p in a.overwrite if p not in authorised]

    to_write = list(new_files) + list(safe) + authorised
    shipped = dict(recorded)

    # ── BACK UP BEFORE DISCARDING ───────────────────────────────────────────────────
    #
    # Only the authorised overwrites need this: new files destroy nothing, and a clean update
    # replaces a copy identical to what was shipped. What is being discarded here is somebody's
    # work, and it lives nowhere else -- the destination may not have committed it.
    backup_dir = ""
    if authorised:
        stampdir = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_dir = os.path.join(dest, ".neutral-export-backups", stampdir)
        for rel in authorised:
            dp = os.path.join(dest, rel.replace("/", os.sep))
            if not os.path.isfile(dp):
                continue
            bp = os.path.join(backup_dir, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(bp), exist_ok=True)
            shutil.copy2(dp, bp)
        print()
        print(f"backed up {len(authorised)} destination file(s) before overwriting:")
        print(f"    {os.path.relpath(backup_dir, dest)}")

    print()
    n = len(to_write)
    for i, rel in enumerate(to_write, 1):
        sp = os.path.join(src, rel.replace("/", os.sep))
        dp = os.path.join(dest, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dp), exist_ok=True)
        shutil.copy2(sp, dp)
        shipped[rel] = sha256_of(sp)
        print(f"      [{i:4}/{n:<4}] {rel}", flush=True)

    removed = 0
    if a.apply_deletes:
        for rel in deleted:
            dp = os.path.join(dest, rel.replace("/", os.sep))
            if os.path.isfile(dp):
                os.remove(dp)
                removed += 1
            shipped.pop(rel, None)

    # The watermark advances to HEAD even when conflicts were skipped, and that is correct: it
    # records what this copy was LAST COMPARED AGAINST, not a claim that every file matches. The
    # skipped files keep their old hashes, so they surface as conflicts again next time rather
    # than quietly becoming the new baseline.
    # Carried forward so a skipped conflict cannot quietly become the new normal. Anything just
    # written is resolved by definition; anything reconciled by hand already dropped out above.
    still = {rel: carried.get(rel, datetime.datetime.now(datetime.timezone.utc)
                                              .strftime("%Y-%m-%d"))
             for rel, _why in conflicts if rel not in to_write}

    # Generated files are regenerated from the destination and recorded as shipped in THAT form,
    # so the next incremental does not mistake the regenerated file for a local edit.
    why = regenerate_generated(dest)
    if why:
        print(f"REFUSED: a generated file could not be regenerated in the destination ({why}).")
        return 1
    for rel in GENERATED:
        fp = os.path.join(dest, rel.replace("/", os.sep))
        if os.path.isfile(fp):
            shipped[rel] = sha256_of(fp)

    write_watermark(src, dest, head, branch, shipped, still, a.allow_dirty, a.profile)

    print()
    print(f"wrote {len(to_write)} file(s), removed {removed}, "
          f"skipped {len(conflicts) - len(authorised)} conflict(s)")
    if authorised:
        print(f"OVERWROTE {len(authorised)} conflicted file(s), discarding the destination's "
              f"version of each:")
        for rel in authorised:
            print(f"    {rel}")
        print(f"The discarded versions are under {os.path.relpath(backup_dir, dest)} if needed.")
    if still:
        print(f"{len(still)} unresolved conflict(s) recorded; they will be re-reported next run")
    print(f"watermark advanced to {head[:9]} on {branch}")
    print()
    print("History was NOT exported, here or ever. Review the diff in the destination, then")
    print("commit it there as its own change.")
    return 0


# ── THE ZIP: WHAT LEAVES THIS MACHINE, CHECKED AT THE MOMENT IT IS PACKED ───────────────────
#
# The copy step above prunes __pycache__ and .pytest_cache, and the work package for 4060290
# still carried 32 compiled .pyc files (2026-10-26). The copy was clean when it was written; the
# copy's own checks were then run INSIDE it, Python cached every module they imported beside the
# source, and the tree was zipped by hand afterwards. The exclusion guarded a step that was not
# the last one.
#
# So the zip is made here, from the tree, and the tree is checked as it is packed: anything a
# check run can leave (compiled files, test caches) and anything that must never ship (history,
# continuity records, agent worktrees, export profiles, the deny list, an overlay the copy's own
# profile did not include) is a REFUSAL, naming each path, with no zip written. Not a silent
# skip: a tree holding them was used for something after the export, and the operator should
# re-export or run the checks on a copy rather than learn to trust a filter.
# tests/prove_export_scope.py E10.
ZIP_REFUSE_DIRS = {".git", "__pycache__", ".pytest_cache", ".claude", ".context", "export-profiles"}
ZIP_REFUSE_SUFFIXES = (".pyc", ".pyo")


def zip_refusals(tree: str, allowed_overlays: set) -> list[str]:
    """-> every path in `tree` that must not be packed, relative and with forward slashes."""
    bad = []
    for dirpath, dirnames, filenames in os.walk(tree):
        rel_dir = os.path.relpath(dirpath, tree).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        for d in sorted(dirnames):
            if d in ZIP_REFUSE_DIRS:
                bad.append(rel_dir + d + "/")
            elif rel_dir == "overlays/" and d not in allowed_overlays:
                bad.append(rel_dir + d + "/  (an overlay this copy's profile does not include)")
        dirnames[:] = [d for d in dirnames if d not in ZIP_REFUSE_DIRS
                       and not (rel_dir == "overlays/" and d not in allowed_overlays)]
        for fn in sorted(filenames):
            rel = rel_dir + fn
            if fn.endswith(ZIP_REFUSE_SUFFIXES) or fn in EXCLUDE_NAMES or rel in EXCLUDE_PATHS:
                bad.append(rel)
    return bad


def zip_tree(tree: str, zip_path: str, allowed_overlays: set) -> int:
    """Pack `tree` into `zip_path` under one top folder, or refuse and write nothing."""
    import zipfile
    tree = os.path.abspath(tree)
    if not os.path.isdir(tree):
        print(f"REFUSED: {tree} is not a directory.")
        return 1
    if not os.path.isfile(os.path.join(tree, WATERMARK)):
        print(f"REFUSED: {tree} has no {WATERMARK}, so it is not a tree this tool exported.")
        return 1
    if os.path.exists(zip_path):
        print(f"REFUSED: {zip_path} already exists. A zip is never overwritten; move it aside.")
        return 1
    bad = zip_refusals(tree, allowed_overlays)
    if bad:
        print(f"REFUSED: the tree holds {len(bad)} path(s) that must not be packed:")
        for b in bad[:40]:
            print(f"    {b}")
        if len(bad) > 40:
            print(f"    ... {len(bad) - 40} more")
        print()
        print("Compiled files and test caches mean something was run INSIDE the exported tree")
        print("after the export. Re-export, and run the copy's checks on a COPY of it, not on the")
        print("tree you zip. Nothing was written.")
        return 1
    top = os.path.basename(tree.rstrip("\\/"))
    files = []
    for dirpath, _dn, fns in os.walk(tree):
        for fn in fns:
            fp = os.path.join(dirpath, fn)
            files.append((os.path.relpath(fp, tree).replace("\\", "/"), fp))
    files.sort()
    partial = zip_path + ".partial"
    try:
        with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rel, fp in files:
                zf.write(fp, top + "/" + rel)
        with zipfile.ZipFile(partial) as zf:
            names = zf.namelist()
            broken = zf.testzip()
        # Re-check what was actually written, not what was meant to be.
        leaked = [n for n in names if n.endswith(ZIP_REFUSE_SUFFIXES)
                  or any(p in ZIP_REFUSE_DIRS for p in n.split("/")[:-1])]
        if broken or leaked or len(names) != len(files):
            print(f"REFUSED: the written zip did not verify (bad entry {broken!r}, "
                  f"{len(leaked)} forbidden entr(ies), {len(names)} of {len(files)} files).")
            os.remove(partial)
            return 1
        os.replace(partial, zip_path)
    except Exception:
        if os.path.exists(partial):
            os.remove(partial)
        raise
    print(f"zip    : {zip_path} ({len(names)} files, {os.path.getsize(zip_path)} bytes, "
          f"top folder {top}/)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="FULL export: destination directory (must not exist)")
    ap.add_argument("--into", help="INCREMENTAL export: an existing destination that already "
                                   "received a full export and carries its watermark")
    ap.add_argument("--baseline", help="source commit the destination last received. Only needed "
                                       "when --into has no watermark, e.g. the first incremental "
                                       "after a full export taken before this tool recorded one.")
    ap.add_argument("--apply", action="store_true",
                    help="actually write. Without it --into reports the plan and changes nothing, "
                         "because this writes into a copy somebody else may be working in.")
    ap.add_argument("--apply-deletes", action="store_true",
                    help="also remove files the source deleted. Separate from --apply because "
                         "deleting in a destination you do not own is the one irreversible move.")
    # OVERWRITING IS NAMED, COUNTED AND BACKED UP -- NEVER A BARE SWITCH.
    #
    # `--overwrite-conflicts` as a boolean was the most dangerous thing in this tool. One word
    # discarded every work-side edit in one go, the set it applied to was whatever happened to be
    # conflicted at that moment, and the operator could not see what they were agreeing to because
    # the flag was typed before the plan was printed. Worse, it was the remedy the output itself
    # recommended, so the dangerous path was also the advertised one.
    #
    # Three changes, each closing a different way it could go wrong:
    #
    #   --overwrite PATH          names ONE file, repeatable, paths copied from the plan. The
    #                             normal way. You cannot overwrite something you did not name.
    #   --overwrite-all-conflicts N
    #                             the bulk escape hatch, but N must EQUAL the conflict count
    #                             actually found. If the situation changed between looking and
    #                             acting -- someone else edited the destination, the source moved
    #                             on -- the number no longer matches and it refuses. An operator
    #                             who types 3 is asserting they reviewed three.
    #   backups                   every overwritten file is copied to .neutral-export-backups/
    #                             <utc>/ first. Discarding work is recoverable or it is not
    #                             allowed; this makes it recoverable.
    ap.add_argument("--overwrite", action="append", default=[], metavar="PATH",
                    help="take the source version of this ONE file, discarding the destination's. "
                         "Repeatable. Use the exact path shown in the plan. The destination copy "
                         "is backed up first.")
    ap.add_argument("--overwrite-all-conflicts", type=int, default=None, metavar="N",
                    help="take the source version of ALL conflicted files. N must equal the "
                         "number of conflicts found, so a situation that changed since you "
                         "looked refuses instead of acting on a set you never saw.")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="export with uncommitted source changes. The watermark is marked "
                         "source_dirty so the record stays honest, but the next incremental "
                         "diff will be measured from a commit the destination never matched.")
    ap.add_argument("--profile", help="who this copy is for: a name in scripts/export-profiles/. "
                                      "Includes that recipient's overlay and lifts the deny "
                                      "patterns naming them. Omit for a neutral copy.")
    ap.add_argument("--deny", action="append", default=[], help="extra pattern to forbid")
    ap.add_argument("--force", action="store_true",
                    help="export anyway and list the leaks. Use only when every hit has been "
                         "reviewed and judged safe — it defeats the point of the gate.")
    ap.add_argument("--zip", metavar="PATH",
                    help="pack the copy into this zip (must not exist), refusing if the tree "
                         "holds compiled files, caches, history or anything that never ships. "
                         "With --out it packs the copy just written; with --zip-tree, a copy "
                         "exported earlier.")
    ap.add_argument("--zip-tree", metavar="DIR",
                    help="with --zip: an existing exported tree to pack. Nothing is exported.")
    a = ap.parse_args()

    if a.zip_tree:
        if not a.zip or a.out or a.into:
            print("--zip-tree takes --zip and nothing else: it packs a tree exported earlier.")
            return 1
        wm = read_watermark(a.zip_tree) or {}
        prof = wm.get("profile")
        allowed = set()
        if prof and prof != NEUTRAL_PROFILE:
            here = os.path.dirname(os.path.abspath(__file__))
            listed = load_deny(here) or []
            try:
                allowed = set(load_profile(here, prof, listed)[0])
            except ValueError as e:
                print(f"REFUSED: the tree was exported under profile {prof!r}, which cannot be "
                      f"read here: {e}")
                return 1
        return zip_tree(a.zip_tree, a.zip, allowed)
    if a.zip and a.into:
        print("--zip packs a FULL export (--out) or an existing tree (--zip-tree), not --into.")
        return 1

    if bool(a.out) == bool(a.into):
        print("give exactly one of --out (full export to a new directory) or "
              "--into (incremental export into an existing one).")
        return 1

    # ── A DIRTY TREE MAKES THE WATERMARK LIE, AND THE WATERMARK IS THE WHOLE MECHANISM ──
    #
    # The export copies the WORKING TREE. The watermark records HEAD. When the tree is clean those
    # are the same thing; when it is not, the destination receives HEAD-plus-uncommitted-edits
    # while the watermark claims it received HEAD.
    #
    # Caught by a test, not by reading the code. The consequence is quiet: the next incremental
    # diffs from a commit the destination never actually matched, so a file that was exported in
    # its uncommitted form and then committed unchanged looks "already reconciled", while one
    # whose uncommitted edit was later REVERTED would never be corrected. Divergence with no
    # symptom, which is the kind this tool exists to prevent.
    src_probe = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        dirty = [l for l in git_out(src_probe, "status", "--porcelain").splitlines()
                 if l.strip() and not l.startswith("??")]
    except subprocess.CalledProcessError:
        dirty = []
    if dirty and not a.allow_dirty:
        print(f"the source working tree has {len(dirty)} uncommitted change(s):")
        for l in dirty[:10]:
            print(f"    {l}")
        if len(dirty) > 10:
            print(f"    ... {len(dirty) - 10} more")
        print()
        print("An export copies the working tree but records HEAD, so exporting now would write a")
        print("watermark that does not describe what the destination actually received, and every")
        print("later incremental would diff from the wrong point.")
        print()
        print("Commit (or stash) first. --allow-dirty exports anyway and marks the watermark")
        print("source_dirty, which keeps the record honest but does not make the diff reliable.")
        return 1

    src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    here = os.path.dirname(os.path.abspath(__file__))
    # NO DENY LIST IS A REFUSAL, NOT A WARNING. Nothing has been written yet, and nothing will be.
    listed = load_deny(here)
    if not listed:
        why = "does not exist" if listed is None else "holds no pattern"
        print(f"REFUSED: {DENY_FILE} beside this script {why}, so nothing would be checked.")
        print()
        print("An export with nothing to check is a copy, not a gate, and it would say nothing")
        print("about what it carried. The list never travels with the kit, so a fresh copy of")
        print(f"this script always starts without one: write scripts/{DENY_FILE} (one regex per")
        print("line, '<pattern> || <why>') naming what must not leave, then run this again.")
        print("Nothing was written.")
        return 1
    deny = listed + [(p, "user-supplied --deny", False) for p in a.deny]

    # Applied BEFORE the scan, because the scan is what the profile changes. Also before the
    # overlay exclusion, since an included overlay must be scanned like everything else -- a
    # consumer's own overlay is still not allowed to name a DIFFERENT consumer.
    include_overlays, lifts = [], []
    if a.profile == NEUTRAL_PROFILE:
        # The watermark spells "no profile" this way; a profile of that name would be
        # indistinguishable from none in the record that binds a copy to its rules.
        print(f"profile refused: {NEUTRAL_PROFILE!r} is reserved for a copy taken with no profile.")
        return 1
    if a.profile:
        try:
            include_overlays, deny, lifts = load_profile(here, a.profile, deny)
        except ValueError as e:
            print(f"profile refused: {e}")
            return 1
        missing_ov = [o for o in include_overlays
                      if not os.path.isdir(os.path.join(src, "overlays", o))]
        if missing_ov:
            print(f"profile {a.profile!r} includes overlay(s) that do not exist: "
                  f"{', '.join(missing_ov)}")
            return 1
        _INCLUDED_OVERLAYS.update(include_overlays)

    print(f"source : {src}")
    print(f"export : {a.out or a.into}")
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

    # ── INCREMENTAL ─────────────────────────────────────────────────────────────────
    #
    # Reached only AFTER the deny scan above, and that scan covers the WHOLE source tree rather
    # than just the changed files. That is deliberate and costs a second: the deny list grows, and
    # a pattern added today must catch a file exported last month. Scanning only the diff would
    # mean a newly-forbidden name already sitting in the destination is never noticed again.
    if a.into:
        return incremental(src, a, deny, len(hits))

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
        rel_here = os.path.relpath(dirpath, src).replace("\\", "/")
        drop |= {n for n in names if n in EXCLUDE_TOP}
        drop |= {n for n in names
                 if (n if rel_here == "." else rel_here + "/" + n) in EXCLUDE_PATHS}
        if rel_here == ".":
            # overlays/ as a whole: withheld entirely unless the profile named something in it
            drop |= {n for n in names if n in EXCLUDE_TREES and not _INCLUDED_OVERLAYS}
        if rel_here == "overlays":
            # and then only the named ones travel. Every other consumer's overlay stays here.
            drop |= {n for n in names if n not in _INCLUDED_OVERLAYS}
        return drop

    shutil.copytree(src, a.out, ignore=ignore)
    shutil.rmtree(os.path.join(a.out, ".git"), ignore_errors=True)
    why = regenerate_generated(a.out)
    if why:
        print(f"REFUSED: a generated file could not be regenerated from the copy ({why}). The copy")
        print(f"at {a.out} would describe the source instead of itself; it is left for inspection.")
        return 1

    stamp = datetime.datetime.now().strftime("%Y-%m-%d")
    with open(os.path.join(a.out, "EXPORT_MANIFEST.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"""# Export manifest

Produced by `scripts/export_for_adoption.py` on **{stamp}**.

## This is a fresh tree, not a clone

**Git history was deliberately not exported.** Scrubbing a file does not scrub the commit that
introduced it, so a clone would carry every removed name and number along with it. This copy
starts from zero: `git init`, one commit, no inherited past.

That is for a NEW standalone repository only. **Never run `git init` inside an existing clone.**
To bring this copy into a repository that already exists, copy it in on a branch and commit it
there like any other change, reviewing what it would overwrite first.

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
    # The watermark is written by the FULL export too, so the first incremental has a baseline
    # instead of having to be told one. Without this the second export is the hard one, which is
    # exactly backwards — the second export is the routine one.
    try:
        head = git_out(src, "rev-parse", "HEAD").strip()
        branch = git_out(src, "rev-parse", "--abbrev-ref", "HEAD").strip()
        shipped = {}
        for dirpath, _dn, fns in os.walk(a.out):
            for fn in fns:
                fp = os.path.join(dirpath, fn)
                rel = os.path.relpath(fp, a.out).replace("\\", "/")
                if rel in {WATERMARK, "EXPORT_MANIFEST.md"}:
                    continue
                shipped[rel] = sha256_of(fp)
        write_watermark(src, a.out, head, branch, shipped, None, a.allow_dirty, a.profile)
        print(f"watermark: {head[:9]} on {branch} ({len(shipped)} files recorded)")
    except subprocess.CalledProcessError:
        print("watermark: NOT WRITTEN — the source is not a git repository, so an incremental")
        print("           export from this copy will need an explicit --baseline.")

    n = sum(len(fs) for _r, _d, fs in os.walk(a.out))
    print(f"exported {n} files")
    print("history: NOT included (fresh tree)")
    if a.zip:
        rc = zip_tree(a.out, a.zip, set(_INCLUDED_OVERLAYS))
        if rc:
            return rc
        print("Run the copy's checks on an UNZIPPED COPY, never on the tree that was zipped.")
    print(f"\nnext (a NEW standalone repository only -- never inside an existing clone):")
    print(f"       cd {a.out} && git init && git add -A && git commit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
