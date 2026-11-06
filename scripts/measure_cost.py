#!/usr/bin/env python3
"""Measure what a security run COSTS and what it ESTABLISHES, before and after a topology change.

WHY THIS EXISTS
    The cost redesign (Release 4, KDEC "Cost redesign, owner rulings") changes which jobs run and
    how they are grouped. Its acceptance test has two halves, and a run that only answers one of
    them is not a pass:

      1. COST. Billed minutes drop, measured on >= 5 runs before and >= 5 after, per fixture class.
      2. INVARIANTS. For every scanner identity, the same state and the same SARIF result count on
         the same fixture commit. A cheaper run that finds less is a regression, not a saving.

    A green run alone proves neither.

WHAT "BILLED" MEANS HERE (read this before quoting a number)
    GitHub's run `timing` endpoint returned 0 billable ms for every run measured on 2026-10-23,
    private repositories included. So billed minutes are COMPUTED, never read:

        per job:  max(1, ceil((completed_at - started_at) / 60)) x runner multiplier
                  (Linux 1, Windows 2, macOS 10). Skipped jobs bill nothing and are excluded.
        per run:  the sum over its jobs.

    Every billed figure this tool prints carries the label
        "computed billed minutes from measured durations, not invoice-reconciled".
    Projected savings are ESTIMATES until each class has >= 5 before and >= 5 after runs; with
    fewer, this tool prints INSUFFICIENT_RUNS and no saving.

SUBCOMMANDS
    dispatch  Dispatch N runs of a workflow on a repository and ref. DRY RUN BY DEFAULT: it prints
              what it would dispatch. --execute dispatches (gh workflow run), then finds each new
              run id and appends it to the manifest.
    compute   For every run in a manifest: fetch its jobs (paginated, latest attempt), compute
              billed / raw / wall clock, download the security report artifact and read each
              scanner's state file and SARIF result count; then medians per (class, phase) and the
              per-scanner invariant comparison, before against after.

    --self-test  compute() over recorded fixture JSON (tests/fixtures/measure_cost/recorded_runs.json),
                 no network: per-job ceiling, skipped jobs excluded, < 5 runs refused a saving, an
                 invariant mismatch detected and an unchanged scanner not flagged.

USAGE
    python3 scripts/measure_cost.py dispatch --class small --phase before \
        --repo <test-owner>/hello-world --workflow security.yml --ref cost/before \
        --runs 5 --manifest cost-manifest.json [--field key=value ...] [--execute]
    python3 scripts/measure_cost.py compute --manifest cost-manifest.json [--json out.json]
    python3 scripts/measure_cost.py --self-test [--fixture <recorded_runs.json>]

    The procedure, the classes and the pass criteria: docs/operations/COST_MEASUREMENT.md.

EXIT
    0  computed (or self-test passed, or dry run printed)
    1  an invariant differs, a run could not be measured, or the self-test failed
    2  could not run (bad arguments, gh missing)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import io
import json
import math
import os
import statistics
import subprocess
import sys
import time
import zipfile

LABEL = "computed billed minutes from measured durations, not invoice-reconciled"
MIN_RUNS = 5
PHASES = ("before", "after")
MULTIPLIER = (("windows", 2), ("macos", 10))
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_FIXTURE = os.path.join(ROOT, "tests", "fixtures", "measure_cost", "recorded_runs.json")


# ── time and billing ─────────────────────────────────────────────────────────────────────

def _ts(s):
    if not s:
        return None
    return _dt.datetime.strptime(s.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z")


def _multiplier(job):
    labels = " ".join(job.get("labels") or []).lower()
    for key, mult in MULTIPLIER:
        if key in labels:
            return mult
    return 1


def job_cost(job):
    """-> None for a job that bills nothing (skipped, never started), else a dict."""
    if (job.get("conclusion") or "") == "skipped":
        return None
    start, end = _ts(job.get("started_at")), _ts(job.get("completed_at"))
    if start is None or end is None:
        return None
    seconds = max(0.0, (end - start).total_seconds())
    billed = max(1, math.ceil(seconds / 60.0)) * _multiplier(job)
    return {"name": job.get("name", ""), "seconds": seconds, "billed": billed,
            "start": start, "end": end, "conclusion": job.get("conclusion")}


def run_cost(jobs):
    costed = [c for c in (job_cost(j) for j in jobs) if c is not None]
    if not costed:
        return {"jobs": 0, "billed": 0, "raw_min": 0.0, "wall_min": 0.0, "skipped": len(jobs)}
    wall = (max(c["end"] for c in costed) - min(c["start"] for c in costed)).total_seconds()
    return {"jobs": len(costed), "skipped": len(jobs) - len(costed),
            "billed": sum(c["billed"] for c in costed),
            "raw_min": round(sum(c["seconds"] for c in costed) / 60.0, 2),
            "wall_min": round(wall / 60.0, 2)}


# ── scanner invariants ───────────────────────────────────────────────────────────────────

def sarif_count(doc):
    """Result count of a SARIF document; None when it is not one (never zero by default)."""
    try:
        return sum(len(r.get("results") or []) for r in doc["runs"])
    except (KeyError, TypeError, AttributeError):
        return None


def scanner_rows(states, sarifs):
    """states: {scanner: state dict}; sarifs: {file name: SARIF doc} -> {scanner: row}."""
    rows = {}
    for scanner, st in sorted(states.items()):
        sf = st.get("sarif") or ""
        count = sarif_count(sarifs[sf]) if sf in sarifs else None
        rows[scanner] = {"applicability": st.get("applicability"),
                         "execution": st.get("execution"),
                         "gate": st.get("gate"),
                         "sarif": sf,
                         "results": count if sf else "NO_SARIF"}
    return rows


def _phase_value(values):
    """One phase's rows for one scanner across runs: the value if every run agrees."""
    keyed = sorted({json.dumps(v, sort_keys=True) for v in values})
    if len(keyed) == 1:
        return json.loads(keyed[0]), True
    return [json.loads(k) for k in keyed], False


def compare_invariants(before_runs, after_runs):
    """-> list of differences. Each phase must agree with itself and with the other phase."""
    diffs = []
    names = set()
    for r in before_runs + after_runs:
        names.update(r["scanners"])
    for name in sorted(names):
        b = [r["scanners"].get(name, "ABSENT") for r in before_runs]
        a = [r["scanners"].get(name, "ABSENT") for r in after_runs]
        bv, bstable = _phase_value(b) if b else (None, True)
        av, astable = _phase_value(a) if a else (None, True)
        if not bstable:
            diffs.append({"scanner": name, "why": "UNSTABLE_BEFORE", "before": bv})
        if not astable:
            diffs.append({"scanner": name, "why": "UNSTABLE_AFTER", "after": av})
        if bstable and astable and b and a and bv != av:
            diffs.append({"scanner": name, "why": "CHANGED", "before": bv, "after": av})
    return diffs


# ── sources: live (gh) and recorded (fixture) ───────────────────────────────────────────

class GhSource:
    """Reads GitHub through the gh CLI. Used only by `compute` and `dispatch --execute`."""

    def _api(self, path, raw=False):
        out = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github+json", path],
                             capture_output=True, check=True)
        return out.stdout if raw else json.loads(out.stdout.decode("utf-8"))

    def run(self, repo, run_id):
        return self._api("repos/%s/actions/runs/%s" % (repo, run_id))

    def jobs(self, repo, run_id):
        jobs, page = [], 1
        while True:
            doc = self._api("repos/%s/actions/runs/%s/jobs?per_page=100&filter=latest&page=%d"
                            % (repo, run_id, page))
            batch = doc.get("jobs") or []
            jobs.extend(batch)
            if len(jobs) >= int(doc.get("total_count") or 0) or not batch:
                return jobs
            page += 1

    def report(self, repo, run_id):
        """-> (states, sarifs) from the run's security-report-<attempt> artifact (latest attempt)."""
        arts, page = [], 1
        while True:
            doc = self._api("repos/%s/actions/runs/%s/artifacts?per_page=100&page=%d"
                            % (repo, run_id, page))
            batch = doc.get("artifacts") or []
            arts.extend(batch)
            if len(arts) >= int(doc.get("total_count") or 0) or not batch:
                break
            page += 1
        reports = sorted((a for a in arts if a.get("name", "").startswith("security-report-")
                          and not a.get("expired")), key=lambda a: a.get("name"))
        if not reports:
            return None, None
        blob = self._api(reports[-1]["archive_download_url"], raw=True)
        states, sarifs = {}, {}
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for n in z.namelist():
                base = os.path.basename(n)
                if base.startswith("state-") and base.endswith(".json"):
                    st = json.loads(z.read(n).decode("utf-8"))
                    states[st.get("scanner") or base[6:-5]] = st
                elif base.endswith(".sarif"):
                    try:
                        sarifs[base] = json.loads(z.read(n).decode("utf-8"))
                    except ValueError:
                        sarifs[base] = None
        return states, sarifs


class FixtureSource:
    """Recorded runs, keyed by run id. No network."""

    def __init__(self, recorded):
        self.r = recorded

    def run(self, repo, run_id):
        return self.r[str(run_id)]["run"]

    def jobs(self, repo, run_id):
        return self.r[str(run_id)]["jobs"]

    def report(self, repo, run_id):
        rec = self.r[str(run_id)]
        if "states" not in rec:
            return None, None
        return rec["states"], rec.get("sarifs") or {}


# ── compute ──────────────────────────────────────────────────────────────────────────────

def measure_run(src, entry):
    repo, rid = entry["repo"], entry["run_id"]
    meta = src.run(repo, rid)
    out = {"class": entry["class"], "phase": entry["phase"], "repo": repo, "run_id": rid,
           "head_sha": meta.get("head_sha"), "attempt": meta.get("run_attempt"),
           "conclusion": meta.get("conclusion"), "excluded": None}
    if meta.get("status") != "completed":
        out["excluded"] = "run not completed (status %s)" % meta.get("status")
        return out
    out.update(run_cost(src.jobs(repo, rid)))
    states, sarifs = src.report(repo, rid)
    if states is None:
        out["excluded"] = "no security-report artifact: the invariants cannot be read"
        return out
    out["scanners"] = scanner_rows(states, sarifs)
    return out


def _median(vals):
    return round(statistics.median(vals), 2) if vals else None


def compute(src, manifest):
    runs = [measure_run(src, e) for e in manifest["runs"]]
    classes = sorted({r["class"] for r in runs})
    summary, failures = {}, []
    for c in classes:
        cs = {}
        phase_runs = {}
        for p in PHASES:
            rs = [r for r in runs if r["class"] == c and r["phase"] == p and not r["excluded"]]
            phase_runs[p] = rs
            shas = sorted({r["head_sha"] for r in rs})
            cs[p] = {"n": len(rs), "head_shas": shas,
                     "median_billed": _median([r["billed"] for r in rs]),
                     "median_raw_min": _median([r["raw_min"] for r in rs]),
                     "median_wall_min": _median([r["wall_min"] for r in rs]),
                     "median_jobs": _median([r["jobs"] for r in rs])}
        nb, na = cs["before"]["n"], cs["after"]["n"]
        if nb >= MIN_RUNS and na >= MIN_RUNS:
            b, a = cs["before"]["median_billed"], cs["after"]["median_billed"]
            cs["savings"] = {"state": "MEASURED", "billed_delta": round(a - b, 2),
                             "billed_delta_pct": round(100.0 * (a - b) / b, 1) if b else None,
                             "label": LABEL}
        else:
            cs["savings"] = {"state": "INSUFFICIENT_RUNS",
                             "why": "%d before / %d after; %d of each are required. Any saving "
                                    "quoted for this class is an ESTIMATE." % (nb, na, MIN_RUNS)}
        cs["invariant_differences"] = compare_invariants(phase_runs["before"], phase_runs["after"])
        if cs["invariant_differences"]:
            failures.append("%s: %d scanner invariant difference(s)"
                            % (c, len(cs["invariant_differences"])))
        summary[c] = cs
    excluded = [{"run_id": r["run_id"], "class": r["class"], "phase": r["phase"],
                 "why": r["excluded"]} for r in runs if r["excluded"]]
    if excluded:
        failures.append("%d run(s) could not be measured" % len(excluded))
    return {"label": LABEL, "min_runs_per_phase": MIN_RUNS, "classes": summary,
            "runs": [{k: v for k, v in r.items() if k != "scanners"} for r in runs],
            "excluded": excluded, "failures": failures}


def print_summary(res):
    print("Billed figures: %s." % res["label"])
    for c, cs in res["classes"].items():
        print("\n== class %s" % c)
        for p in PHASES:
            s = cs[p]
            print("  %-6s n=%d  billed(median)=%s  raw_min=%s  wall_min=%s  jobs=%s  shas=%s"
                  % (p, s["n"], s["median_billed"], s["median_raw_min"], s["median_wall_min"],
                     s["median_jobs"], ",".join(x[:8] for x in s["head_shas"] if x)))
        sv = cs["savings"]
        if sv["state"] == "MEASURED":
            print("  savings: %s billed (%s%%), %s" % (sv["billed_delta"], sv["billed_delta_pct"],
                                                      sv["label"]))
        else:
            print("  savings: INSUFFICIENT_RUNS -- %s" % sv["why"])
        diffs = cs["invariant_differences"]
        print("  invariants: %s" % ("HOLD per scanner identity" if not diffs
                                    else "%d DIFFERENCE(S)" % len(diffs)))
        for d in diffs:
            print("    - %s" % json.dumps(d, sort_keys=True))
    for e in res["excluded"]:
        print("EXCLUDED run %s (%s/%s): %s" % (e["run_id"], e["class"], e["phase"], e["why"]))
    print("\nA green run is not a pass. The pass also needs consumer path 24/24 and the negative "
          "control still blocking (docs/operations/COST_MEASUREMENT.md).")


# ── dispatch ─────────────────────────────────────────────────────────────────────────────

def dispatch(a):
    cmd = ["gh", "workflow", "run", a.workflow, "-R", a.repo, "--ref", a.ref]
    for f in a.field or []:
        cmd += ["-f", f]
    if not a.execute:
        print("DRY RUN (pass --execute to dispatch). Would run %d time(s):" % a.runs)
        print("  " + " ".join(cmd))
        print("  then record each new run id as class=%s phase=%s in %s"
              % (a.klass, a.phase, a.manifest))
        return 0
    manifest = {"runs": []}
    if os.path.exists(a.manifest):
        with io.open(a.manifest, encoding="utf-8") as f:
            manifest = json.load(f)
    seen = set()
    for i in range(a.runs):
        before = _list_runs(a)
        subprocess.run(cmd, check=True)
        rid = None
        for _ in range(30):
            time.sleep(4)
            new = [r for r in _list_runs(a) if r not in before and r not in seen]
            if new:
                rid = min(new)
                break
        if rid is None:
            print("could not find the run for dispatch %d; nothing recorded for it" % (i + 1))
            return 1
        seen.add(rid)
        manifest["runs"].append({"class": a.klass, "phase": a.phase, "repo": a.repo,
                                 "run_id": rid, "workflow": a.workflow, "ref": a.ref})
        with io.open(a.manifest, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print("dispatched %d/%d: run %s" % (i + 1, a.runs, rid))
        # One at a time: concurrent runs compete for the account's runner pool and distort wall clock.
        if i + 1 < a.runs and a.wait:
            subprocess.run(["gh", "run", "watch", str(rid), "-R", a.repo, "--exit-status"])
    return 0


def _list_runs(a):
    out = subprocess.run(["gh", "run", "list", "-R", a.repo, "-w", a.workflow, "-b", a.ref,
                          "-e", "workflow_dispatch", "-L", "50", "--json", "databaseId"],
                         capture_output=True, check=True)
    return {r["databaseId"] for r in json.loads(out.stdout.decode("utf-8"))}


# ── self-test ────────────────────────────────────────────────────────────────────────────

def self_test(path):
    with io.open(path, encoding="utf-8") as f:
        fx = json.load(f)
    res = compute(FixtureSource(fx["recorded"]), fx["manifest"])
    exp = fx["expect"]
    bad = []

    def check(ok, what):
        print("  %s  %s" % ("ok  " if ok else "FAIL", what))
        if not ok:
            bad.append(what)

    by_id = {r["run_id"]: r for r in res["runs"]}
    for rid, want in exp["run_billed"].items():
        got = by_id[int(rid)].get("billed")
        check(got == want, "run %s billed %s == %s (per-job ceiling, skipped excluded)"
              % (rid, got, want))
    for rid, want in exp["run_jobs"].items():
        got = by_id[int(rid)].get("jobs")
        check(got == want, "run %s counts %s billed job(s) == %s (skipped excluded)" % (rid, got, want))
    for c, want in exp["savings_state"].items():
        got = res["classes"][c]["savings"]["state"]
        check(got == want, "class %s savings %s == %s" % (c, got, want))
    for c, want in exp["median_billed"].items():
        for p in PHASES:
            got = res["classes"][c][p]["median_billed"]
            check(got == want[p], "class %s %s median billed %s == %s" % (c, p, got, want[p]))
    for c, want in exp["invariant_diff_scanners"].items():
        got = sorted(d["scanner"] for d in res["classes"][c]["invariant_differences"])
        check(got == sorted(want), "class %s invariant differences %s == %s" % (c, got, want))
    check(all(res["classes"][c]["savings"].get("label", LABEL) == LABEL for c in res["classes"]),
          "every measured saving carries the not-invoice-reconciled label")
    check(job_cost({"conclusion": "success", "started_at": "2026-10-23T00:00:00Z",
                    "completed_at": "2026-10-23T00:01:01Z", "labels": ["windows-latest"]})["billed"]
          == 4, "a 61 s Windows job bills 2 minutes x 2")
    check(sarif_count({"runs": "not a list"}) is None, "a malformed SARIF is unknown, never zero")
    print("\nSELF-TEST %s (%d check(s) failed)" % ("PASSED" if not bad else "FAILED", len(bad)))
    return 0 if not bad else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--self-test" in argv:
        ap = argparse.ArgumentParser()
        ap.add_argument("--self-test", action="store_true")
        ap.add_argument("--fixture", default=DEFAULT_FIXTURE)
        return self_test(ap.parse_args(argv).fixture)
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dispatch")
    d.add_argument("--class", dest="klass", required=True)
    d.add_argument("--phase", choices=PHASES, required=True)
    d.add_argument("--repo", required=True)
    d.add_argument("--workflow", required=True)
    d.add_argument("--ref", required=True)
    d.add_argument("--runs", type=int, default=MIN_RUNS)
    d.add_argument("--field", action="append", help="workflow_dispatch input, key=value")
    d.add_argument("--manifest", required=True)
    d.add_argument("--execute", action="store_true", help="really dispatch (default: dry run)")
    d.add_argument("--no-wait", dest="wait", action="store_false",
                   help="do not wait for each run before dispatching the next")
    c = sub.add_parser("compute")
    c.add_argument("--manifest", required=True)
    c.add_argument("--json", help="also write the full result here")
    a = ap.parse_args(argv)
    if a.cmd == "dispatch":
        return dispatch(a)
    with io.open(a.manifest, encoding="utf-8") as f:
        manifest = json.load(f)
    res = compute(GhSource(), manifest)
    print_summary(res)
    if a.json:
        with io.open(a.json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, default=str)
    return 1 if res["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
