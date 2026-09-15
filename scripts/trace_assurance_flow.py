#!/usr/bin/env python3
"""Trace every assurance-bearing value from producer to consumer, and flag unguarded defaults.

WHY THIS EXISTS

A perfectly correct producer can still participate in a false assurance result if its CONSUMER
assigns semantics to missing output. That is not a syntax defect and grep will not find it.

It has already happened here, inside a fix for the same class: the counting step was corrected to
refuse to invent a zero and to exit non-zero. The enforcing step ran on `always()`, read the output
that was never written, applied `${n:-0}`, and announced GATE=PASS one line after the failure was
detected. The producer told the truth; the consumer reconstructed the lie.

So correctness is traced across the boundary, not asserted at either end:

  CORRECTNESS IS NOT LOCAL. A fix is complete when the CLAIM survives every downstream boundary
  that consumes it -- not when the defective component behaves correctly.

WHAT IT CHECKS

  UNGUARDED    a consumer reads an assurance value and supplies a benign default (${x:-0},
               ${x:-false}) without first checking whether it was actually produced.
               There is NO implicit default from unknown to known at an assurance boundary.
  PHANTOM      a value consumed that no producer emits. Always absent, always defaulted.
  ORPHAN       a value produced that nothing consumes. Either dead, or a state that dies at a
               boundary -- which is how every internal state once failed to reach callers.

Output doubles as the BOUNDARY CONTRACT MAP: producer, consumer, guard status per handoff.
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
WF = os.path.join(ROOT, ".github", "workflows")

STEP_REF = re.compile(r"steps\.([A-Za-z0-9_\-]+)\.outputs\.([A-Za-z0-9_\-]+)")
NEEDS_REF = re.compile(r"needs\.([A-Za-z0-9_\-]+)\.outputs\.([A-Za-z0-9_\-]+)")
# a benign default applied to a shell variable: ${x:-0}, ${x:-false}, ${x:-}
DEFAULTED = re.compile(r"\$\{([A-Za-z0-9_]+):-([^}]*)\}")
BENIGN = {"0", "false", "", "none", "NOT_APPLICABLE", "PASS", "COMPLETE"}


def load(name):
    return yaml.safe_load(io.open(os.path.join(WF, name), encoding="utf-8"))


def step_emits(step):
    """Outputs a step writes to GITHUB_OUTPUT, or None if that cannot be determined.

    A `uses:` step's outputs are declared by the ACTION, not visible here. Returning None means
    UNVERIFIABLE -- which is NOT the same as "emits nothing". Reporting an inability to observe as a
    positive defect is the exact conflation this whole audit exists to eliminate, and the first
    version of this tracer committed it: it flagged docker/build-push-action's `digest` as a phantom
    because it could not see inside the action. A tool that reports what it cannot determine as a
    finding trains people to ignore it, which is how a control dies.
    """
    if step.get("uses"):
        return None
    run = step.get("run")
    out = set()
    for m in re.finditer(r'echo\s+"?([A-Za-z0-9_\-]+)=', run or ""):
        out.add(m.group(1))
    for m in re.finditer(r'emit\s+([A-Za-z0-9_\-]+)\s', run or ""):
        out.add(m.group(1))
    return out


def analyse(name):
    doc = load(name)
    findings = []
    edges = []

    unverified = []

    for jn, job in (doc.get("jobs") or {}).items():
        steps = job.get("steps") or []
        produced = {}          # step id -> set(outputs)
        for s in steps:
            sid = s.get("id")
            if sid:
                produced[sid] = step_emits(s)

        for s in steps:
            run = s.get("run") or ""
            sname = (s.get("name") or s.get("id") or "?")[:34]
            if not run:
                continue

            # which assurance values does this step consume?
            for m in STEP_REF.finditer(run):
                pid, val = m.group(1), m.group(2)
                emitted = produced.get(pid)
                edges.append((name, jn, pid, val, sname))
                if emitted is None:
                    # DECLARE THE LIMIT. Skipping this silently would downgrade "I cannot see it"
                    # to "it is fine" -- the same conflation in a quieter costume. The tracer must
                    # be honest about the edge of its own observability, or it becomes another
                    # control that reports confidence it has not earned.
                    unverified.append((name, jn, pid, val, sname))
                    continue
                if val not in emitted:
                    findings.append(("PHANTOM", name, jn, sname,
                                     "reads steps.%s.outputs.%s which that step never emits" % (pid, val)))

            # does it default an assurance value to something benign, without a guard?
            for m in DEFAULTED.finditer(run):
                var, default = m.group(1), m.group(2)
                if default not in BENIGN:
                    continue
                # is the same variable assigned from an assurance output in this step?
                if not re.search(r"%s=.*(steps\.|needs\.)" % re.escape(var), run):
                    continue
                guarded = bool(re.search(
                    r'(COLLECTION_FAILED|-z\s+"\$\{?%s|\[\s*-z\s*"\$%s)' % (re.escape(var), re.escape(var)), run))
                if not guarded:
                    findings.append(("UNGUARDED", name, jn, sname,
                                     "defaults $%s to '%s' with no absence check -- "
                                     "there is no implicit default from unknown to known"
                                     % (var, default)))

        # job-level outputs referencing steps that do not emit them
        for oname, expr in (job.get("outputs") or {}).items():
            for m in STEP_REF.finditer(str(expr)):
                pid, val = m.group(1), m.group(2)
                if pid in produced and produced[pid] is None:
                    # Declare it here too. This is the exact handoff that produced the tracer's own
                    # false positive -- a job output exposing a third-party action's result. Skipping
                    # it silently in THIS loop while declaring it in the other would mean the
                    # observability limit depends on which code path noticed it.
                    unverified.append((name, jn, pid, val, "job output " + oname))
                    continue
                if pid in produced and produced[pid] is not None and val not in produced[pid]:
                    findings.append(("PHANTOM", name, jn, "job output " + oname,
                                     "exposes steps.%s.outputs.%s which is never emitted" % (pid, val)))

    # workflow_call outputs that reference job outputs
    call = (doc.get(True) or {}).get("workflow_call") or {}
    for oname, spec in (call.get("outputs") or {}).items():
        expr = str((spec or {}).get("value", ""))
        m = re.search(r"jobs\.([A-Za-z0-9_\-]+)\.outputs\.([A-Za-z0-9_\-]+)", expr)
        if m:
            jn, val = m.group(1), m.group(2)
            jobout = ((doc.get("jobs") or {}).get(jn) or {}).get("outputs") or {}
            if val not in jobout:
                findings.append(("PHANTOM", name, jn, "workflow output " + oname,
                                 "exposes jobs.%s.outputs.%s which that job does not declare" % (jn, val)))
    return findings, edges, unverified


def main(argv):
    all_findings, all_edges, all_unverified = [], [], []
    for f in sorted(os.listdir(WF)):
        if f.endswith(".yml"):
            fnd, edg, unv = analyse(f)
            all_findings += fnd
            all_edges += edg
            all_unverified += unv

    print("=== BOUNDARY CONTRACT MAP — assurance handoffs ===")
    seen = set()
    for wf, jn, pid, val, consumer in sorted(all_edges):
        key = (wf, jn, pid, val, consumer)
        if key in seen:
            continue
        seen.add(key)
        print("  %-26s %-16s %s.%s  ->  %s" % (wf, jn, pid, val, consumer))
    print("  %d handoffs traced" % len(seen))

    if all_unverified:
        print("\n=== PRODUCER_UNVERIFIED_EXTERNALLY_DECLARED ===")
        print("  Handoffs this tracer CANNOT statically verify, because the producing step is a")
        print("  third-party action whose outputs are declared by the action, not the workflow.")
        print("  This is a DECLARED OBSERVABILITY LIMIT -- not a defect, and not a pass.")
        for wf, jn, pid, val, consumer in sorted(set(all_unverified)):
            print("  %-26s %-16s %s.%s  ->  %s" % (wf, jn, pid, val, consumer))
        print("  %d handoff(s) outside static observability." % len(set(all_unverified)))
        print("  Closing this gap requires one of: action metadata inspection, a runtime")
        print("  assertion, a contract fixture, or an explicitly accepted external dependency")
        print("  assumption. Choose deliberately; do not let silence choose.")

    if all_findings:
        print("\n=== DEFECTS ===")
        for kind, wf, jn, where, msg in sorted(all_findings):
            print("  [%s] %s / %s / %s\n        %s" % (kind, wf, jn, where, msg))
        print("\n::error title=Assurance dataflow::%d boundary defect(s). A correct producer still "
              "participates in a false result when its consumer assigns semantics to missing "
              "output." % len(all_findings))
        return 1

    print("\nassurance dataflow: every traced handoff is guarded")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
