#!/usr/bin/env python3
"""Compare EXPECTED signals against OBSERVED findings, through the consumer path.

Counting green jobs proves nothing. A job is green when its scanner ran, not when its scanner
FOUND the thing the fixture deliberately planted — and a scanner pointed at the wrong path,
given the wrong config, or silently producing an empty report is green all day.

Illusions of exactly that kind shipped in this kit and survived a fully green
validate-scanners: a trivy-action tag that never existed, 14 Azure secret rules the reusable
workflow never loaded, and three SAST jobs that ran no scanner at all. Every one was invisible
because the probes tested the TOOLS. This tests the CONTRACT.

Matching is TOOL-AGNOSTIC BY DEFAULT — a signal asserts that *something* flagged the seeded
file. Overlapping coverage is a design property of this kit, and pinning every signal to one
named scanner would make the suite brittle against it.

But that default has a failure mode of its own, and it bit us: `cpp/vuln.c` seeds conditions
that BOTH flawfinder and cppcheck detect, so either scanner silently covered for the other.
The contract would have read 19/19 with a freshly-repaired cppcheck path completely broken —
verifying everything except the capability just fixed.

So a signal MAY pin a `tool`. Use it for exactly one reason: when the point of the assertion is
that a SPECIFIC scanner's path works. Otherwise leave it off.

The chain asserted here is:

    scanner executed -> expected signal produced -> report structurally VALID -> report persisted

An unreadable report is a HARD FAILURE, never a skip. flawfinder once wrote its crash message
to stdout, which the redirect captured as the report: a non-empty file that was not JSON. A
malformed report is not a clean report.

Usage:
    verify_expected_signals.py --fixture <dir> --sarif-dir <dir> [--json]
"""
from __future__ import annotations
import argparse, glob, json, os, re, sys

# Artifacts are published as `sarif-<category>-<run_attempt>`; the category is the scanner
# identity the workflow assigned. Falls back to the SARIF driver name.
ARTIFACT_DIR = re.compile(r"^sarif-(.+?)(?:-\d+)?$")


def tool_of(path: str, doc: dict) -> str:
    m = ARTIFACT_DIR.match(os.path.basename(os.path.dirname(path)))
    if m:
        return m.group(1)
    for run in doc.get("runs", []):
        name = run.get("tool", {}).get("driver", {}).get("name")
        if name:
            return name.lower()
    return "unknown"


def collect_observed(sarif_dir: str) -> tuple[dict[str, set[str]], int, list[str]]:
    """Map every flagged artifact URI to the set of scanners that flagged it."""
    seen: dict[str, set[str]] = {}
    unreadable: list[str] = []
    files = 0
    for path in sorted(glob.glob(os.path.join(sarif_dir, "**", "*.sarif"), recursive=True)):
        files += 1
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except Exception as e:
            # NEVER treat unreadable as clean. This is how a crash message masqueraded as a
            # report and produced a green job on a repository full of real defects.
            unreadable.append(f"{os.path.relpath(path, sarif_dir)}: {e}")
            continue
        tool = tool_of(path, doc)
        for run in doc.get("runs", []):
            for res in run.get("results", []):
                for loc in res.get("locations", []):
                    uri = (loc.get("physicalLocation", {})
                              .get("artifactLocation", {})
                              .get("uri", ""))
                    if uri:
                        seen.setdefault(uri.replace("\\", "/").lstrip("./"), set()).add(tool)
    return seen, files, unreadable


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--sarif-dir", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    expected = json.load(open(os.path.join(a.fixture, "EXPECTED_SIGNALS.json"), encoding="utf-8"))
    observed, n_sarif, unreadable = collect_observed(a.sarif_dir)

    print(f"collected {n_sarif} SARIF file(s); {len(observed)} distinct flagged path(s)")
    tools = sorted({t for ts in observed.values() for t in ts})
    print(f"scanners that produced findings: {', '.join(tools) or 'NONE'}")
    print()

    detected, missed, wrong_tool = [], [], []
    negatives_ok, negatives_bad = [], []

    for item in expected:
        rel, signal = item["path"], item["expected_signal"]
        want = item.get("tool")                      # optional; absent = tool-agnostic
        # Tools report paths relative to different roots, so match on suffix.
        hits = {t for uri, ts in observed.items() if uri.endswith(rel) for t in ts}

        if signal.startswith("negative:"):
            # A negative control MUST NOT be flagged. A scanner that fires on documented
            # near-misses is worse than one that misses: it trains people to ignore it.
            (negatives_ok if not hits else negatives_bad).append((rel, signal, sorted(hits)))
        elif not hits:
            missed.append((rel, signal, want))
        elif want and want not in hits:
            # Flagged, but not by the scanner whose path this signal exists to prove.
            wrong_tool.append((rel, signal, want, sorted(hits)))
        else:
            detected.append((rel, signal, want, sorted(hits)))

    print(f"{'STATUS':11} {'EXPECTED SIGNAL':30} {'PINNED':11} PATH  [by]")
    for rel, sig, want, by in detected:
        print(f"{'DETECTED':11} {sig:30} {want or '-':11} {rel}  [{','.join(by)}]")
    for rel, sig, by in negatives_ok:
        print(f"{'CLEAN-OK':11} {sig:30} {'-':11} {rel}")
    for rel, sig, want, by in wrong_tool:
        print(f"{'WRONG-TOOL':11} {sig:30} {want:11} {rel}  [got {','.join(by)}]")
    for rel, sig, want in missed:
        print(f"{'MISSED':11} {sig:30} {want or '-':11} {rel}")
    for rel, sig, by in negatives_bad:
        print(f"{'FALSE-POS':11} {sig:30} {'-':11} {rel}  [{','.join(by)}]")

    total_pos = len(detected) + len(missed) + len(wrong_tool)
    print()
    print(f"detected {len(detected)}/{total_pos} seeded signals; "
          f"{len(negatives_ok)}/{len(negatives_ok) + len(negatives_bad)} negative controls clean")

    if a.json:
        json.dump({"detected": detected, "missed": missed, "wrong_tool": wrong_tool,
                   "negatives_ok": negatives_ok, "negatives_bad": negatives_bad,
                   "unreadable": unreadable},
                  open("expected-signals-result.json", "w", encoding="utf-8"), indent=2)

    rc = 0
    if unreadable:
        print()
        print("::error title=Malformed SARIF::A report that does not parse is NOT a clean report. "
              "This is how a scanner crash was once captured as its own output and produced a "
              "green job.")
        for u in unreadable:
            print(f"::error::{u}")
        rc = 1
    if missed:
        print()
        print("::error title=Seeded signals NOT detected::The consumer path did not surface "
              f"{len(missed)} deliberately planted condition(s). Green jobs, absent detection.")
        for rel, sig, _w in missed:
            print(f"::error file={rel}::expected `{sig}` and nothing flagged this file")
        rc = 1
    if wrong_tool:
        print()
        print("::error title=Detected by the WRONG scanner::These signals are pinned because the "
              "point of the assertion is that a specific scanner's path works. Another scanner "
              "covering for it is exactly the blind spot the pin exists to remove.")
        for rel, sig, want, by in wrong_tool:
            print(f"::error file={rel}::`{sig}` requires `{want}`; flagged only by {', '.join(by)}")
        rc = 1
    if negatives_bad:
        print()
        print("::error title=False positives on negative controls::A scanner flagged a documented "
              "near-miss. False positives train people to ignore the scanner, which costs more "
              "coverage than the finding was worth.")
        rc = 1
    if rc == 0:
        print()
        print("::notice::Every seeded signal was detected through the consumer path — including "
              "each pinned scanner independently — no negative control was flagged, and every "
              "report parsed.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
