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
               NOT IMPLEMENTED: this check is described here and performed nowhere (stated
               2026-10-16, independent review W4K-113). Nor are composite actions read; a
               `uses:` of one is a declared observability limit like any other action.

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


# A `run:` line that hands the step to one of this kit's scripts: `python3 "$RUNNER_TEMP/kit-deploy/
# deploy_contract.py" serving ...`. Only the basename is matched; it is resolved under scripts/,
# which is where the inlined copies are generated FROM (scripts/inline_deploy_scripts.py --check
# fails if a copy drifts), so reading the canonical file reads what the runner executes.
SCRIPT_CALL = re.compile(r'python3?\s+(?:-I\s+)?"?[^\s"]*?/([A-Za-z0-9_\-]+\.py)"?')
# Python writing GITHUB_OUTPUT: a literal handed to .write() whose lines are `name=...`, or the
# deploy contract's `output(name=value)` helper.
PY_WRITE_LITERAL = re.compile(r"""\.write\(\s*(['"])(.*?)\1""")
PY_OUTPUT_KW = re.compile(r"\boutput\(\s*([A-Za-z0-9_\-]+)=")
# A keyword helper the body defines for itself -- `def out(**kv)` writing each pair to
# GITHUB_OUTPUT (the cppcheck converter). Every keyword of every call to it is an output.
PY_KW_HELPER = re.compile(r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\*\*")


def python_emits(text):
    """Output names a Python body writes to GITHUB_OUTPUT, read from its own source.

    Two producers the shell-only reader could not see, and reported as PHANTOM: the osv count
    step writes `state=%s\\nmalicious=%d\\nids=%s\\n` to GITHUB_OUTPUT from a heredoc, and the
    deploy `serving` step delegates to deploy_contract.py, whose `output(app_url=...)` appends to
    the same file. Both outputs are produced on every run that reaches them; the tracer said
    "never emitted" because it only knew `echo` and `emit`. A reader that cannot see a producer
    must say so, not convict it -- and a producer whose source is in this tree is observable, so
    the honest move is to read it rather than declare a limit. Only text that names
    GITHUB_OUTPUT is read: a script that writes other files is not a producer of outputs.
    """
    out = set()
    if "GITHUB_OUTPUT" not in text:
        return out
    for m in PY_WRITE_LITERAL.finditer(text):
        for n in re.finditer(r"(?:^|\\n)([A-Za-z0-9_\-]+)=", m.group(2)):
            out.add(n.group(1))
    for m in PY_OUTPUT_KW.finditer(text):
        out.add(m.group(1))
    # Found when the tracer first read env mappings: the cppcheck converter's `out(collection=...,
    # count=0, sarif=...)` was invisible, so two env-transported reads of it read as PHANTOM.
    # Every keyword of a call counts, not only the first.
    for helper in set(PY_KW_HELPER.findall(text)) | {"output"}:
        for m in re.finditer(r"\b%s\(([^()]*)\)" % re.escape(helper), text):
            for k in re.finditer(r"(?:^|,)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", m.group(1)):
                out.add(k.group(1))
    return out


def step_emits(step, script_dir=None):
    """Outputs a step writes to GITHUB_OUTPUT, or None if that cannot be determined.

    A `uses:` step's outputs are declared by the ACTION, not visible here. Returning None means
    UNVERIFIABLE -- which is NOT the same as "emits nothing". Reporting an inability to observe as a
    positive defect is the exact conflation this whole audit exists to eliminate, and the first
    version of this tracer committed it: it flagged docker/build-push-action's `digest` as a phantom
    because it could not see inside the action. A tool that reports what it cannot determine as a
    finding trains people to ignore it, which is how a control dies.

    A `run:` step emits what its shell echoes, what its `emit` helper writes, what an inline
    Python body writes (python_emits), and what a kit script it delegates to writes -- resolved
    by basename under `script_dir` (scripts/ by default). A script that is not in the tree is
    not read, and a step that only calls one contributes nothing: an absent producer stays absent.
    """
    if step.get("uses"):
        return None
    run = step.get("run") or ""
    out = set()
    for m in re.finditer(r'echo\s+"?([A-Za-z0-9_\-]+)=', run):
        out.add(m.group(1))
    for m in re.finditer(r'emit\s+([A-Za-z0-9_\-]+)\s', run):
        out.add(m.group(1))
    out |= python_emits(run)
    for m in SCRIPT_CALL.finditer(run):
        p = os.path.join(script_dir or os.path.join(ROOT, "scripts"), m.group(1))
        if os.path.isfile(p):
            out |= python_emits(io.open(p, encoding="utf-8", errors="replace").read())
    return out


def self_test():
    """The reader must see the two producer shapes it once missed, and must still convict a
    step that declares an output nothing writes. A reader that cannot fail proves nothing."""
    import tempfile
    heredoc = {"id": "osv_count", "run": "python3 - <<'PY'\nimport io, os\n"
               "with io.open(os.environ['GITHUB_OUTPUT'], 'a') as o:\n"
               "    o.write('state=%s\\nmalicious=%d\\nids=%s\\n' % (s, n, i))\nPY\n"}
    d = tempfile.mkdtemp(prefix="trace-self-test-")
    try:
        io.open(os.path.join(d, "contract.py"), "w", encoding="utf-8").write(
            "import os\ndef output(**kv):\n    path = os.environ.get('GITHUB_OUTPUT')\n"
            "    ...\noutput(app_url='https://x')\n")
        io.open(os.path.join(d, "silent.py"), "w", encoding="utf-8").write(
            "print('nothing is written to GITHUB_OUTPUT here')\n")
        delegating = {"id": "serving", "run": 'python3 "$RUNNER_TEMP/kit-deploy/contract.py" serving'}
        silent = {"id": "quiet", "run": 'python3 "$RUNNER_TEMP/kit-deploy/silent.py" report'}
        absent = {"id": "gone", "run": 'python3 "$RUNNER_TEMP/kit-deploy/not_in_tree.py" x'}
        helper = {"id": "conv", "run": "python3 - <<'PY'\nimport io, os\ndef out(**kv):\n"
                  "    with io.open(os.environ['GITHUB_OUTPUT'], 'a') as o:\n"
                  "        o.write('x')\nout(collection='NOT_APPLICABLE', count=0, sarif='false')\nPY\n"}
        got = (step_emits(heredoc), step_emits(delegating, d), step_emits(silent, d),
               step_emits(absent, d), step_emits(helper))
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    want = ({"state", "malicious", "ids"}, {"app_url"}, set(), set(),
            {"collection", "count", "sarif"})
    if got != want:
        print("SELF-TEST FAILED: step_emits saw %r, wanted %r" % (got, want))
        return 1
    return 0


def env_transported(*mappings):
    """-> {VAR: expression} for every env entry whose value reads a step or job output.

    THE KIT'S OWN INJECTION FIX MOVED MOST HAND-OFFS HERE, OUT OF THE TRACER'S SIGHT (2026-10-16).
    The rule that an expression must never be interpolated into a `run:` script (lint_injection)
    moves `${{ steps.x.outputs.y }}` into `env: {Y: ...}` and leaves `"$Y"` in the script. That is
    the right fix, and it made this tracer read 14 of the flagship's 35 step-output hand-offs: it
    looked only at run text, so PHANTOM could not see a renamed output behind an env mapping and
    UNGUARDED could not see `${Y:-0}` at all, because the assignment it looked for was in the
    run text. Step-level and job-level env both count; a step's own entry shadows the job's.
    """
    out = {}
    for m in mappings:
        for k, v in (m or {}).items():
            v = str(v)
            if STEP_REF.search(v) or NEEDS_REF.search(v):
                out[str(k)] = v
    return out


def case_names_empty(var, run):
    """Does a `case "${VAR:-}" in` in this script give the EMPTY value an arm of its own?

    An explicit absence check, and as good as `-z`: the reader can see where absence goes. A
    case whose only route for absence is a `*)` catch-all is NOT one -- `*) echo PASS` and
    `*) fail` look the same from here, so the tracer keeps flagging it and the author states
    the empty case (`'')`) instead. `-n` counts for the same reason `-z` does.
    """
    for m in re.finditer(r'case\s+"\$\{%s(?::-[^}]*)?\}"\s+in\b(.*?)\besac\b' % re.escape(var),
                         run, re.S):
        for arm in re.finditer(r"^\s*\(?([^()\n]*)\)", m.group(1), re.M):
            if any(alt.strip() in ("''", '""') for alt in arm.group(1).split("|")):
                return True
    return False


def needs_outputs(doc, job_name):
    """-> the set of outputs job `job_name` declares, None when they cannot be read here, or
    False when no such job exists. A job that calls a reusable workflow declares its outputs in
    THAT file: read when it is a local `./` file in this directory, a declared limit otherwise."""
    jobs = doc.get("jobs") or {}
    job = jobs.get(job_name)
    if not isinstance(job, dict):
        return False
    uses = job.get("uses")
    if uses:
        prefix = "./.github/workflows/"
        if not str(uses).startswith(prefix):
            return None
        target = os.path.join(WF, str(uses)[len(prefix):])
        if not os.path.isfile(target):
            return None
        called = yaml.safe_load(io.open(target, encoding="utf-8")) or {}
        call = ((called.get(True) or called.get("on") or {}) or {})
        call = call.get("workflow_call") if isinstance(call, dict) else None
        return set(((call or {}).get("outputs") or {}).keys())
    return set((job.get("outputs") or {}).keys())


def analyse(name):
    return analyse_doc(load(name), name)


def analyse_doc(doc, name):
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
        job_env = job.get("env") or {}

        def consume_step_ref(pid, val, where):
            edges.append((name, jn, pid, val, where))
            if pid not in produced:
                findings.append(("PHANTOM", name, jn, where,
                                 "reads steps.%s.outputs.%s but no step in this job has id %r"
                                 % (pid, val, pid)))
                return
            emitted = produced[pid]
            if emitted is None:
                # DECLARE THE LIMIT. Skipping this silently would downgrade "I cannot see it"
                # to "it is fine" -- the same conflation in a quieter costume. The tracer must
                # be honest about the edge of its own observability, or it becomes another
                # control that reports confidence it has not earned.
                unverified.append((name, jn, pid, val, where))
                return
            if val not in emitted:
                findings.append(("PHANTOM", name, jn, where,
                                 "reads steps.%s.outputs.%s which that step never emits" % (pid, val)))

        def consume_needs_ref(dep, val, where):
            edges.append((name, jn, "needs." + dep, val, where))
            declared = needs_outputs(doc, dep)
            if declared is False:
                findings.append(("PHANTOM", name, jn, where,
                                 "reads needs.%s.outputs.%s but this workflow has no job %r"
                                 % (dep, val, dep)))
            elif declared is None:
                unverified.append((name, jn, "needs." + dep, val, where))
            elif val not in declared:
                findings.append(("PHANTOM", name, jn, where,
                                 "reads needs.%s.outputs.%s which that job does not declare"
                                 % (dep, val)))

        # Job-level env is read once per job: it is one mapping, consumed by every step.
        for var, expr in sorted(env_transported(job_env).items()):
            for m in NEEDS_REF.finditer(expr):
                consume_needs_ref(m.group(1), m.group(2), "job env " + var)

        for s in steps:
            run = s.get("run") or ""
            sname = (s.get("name") or s.get("id") or "?")[:34]
            step_env = s.get("env") or {}

            # which assurance values does this step consume? In its own env mapping first --
            # where the injection rule puts them -- and then in the script text.
            for var, expr in sorted(env_transported(step_env).items()):
                for m in STEP_REF.finditer(expr):
                    consume_step_ref(m.group(1), m.group(2), sname + " (env " + var + ")")
                for m in NEEDS_REF.finditer(expr):
                    consume_needs_ref(m.group(1), m.group(2), sname + " (env " + var + ")")
            if not run:
                continue
            for m in STEP_REF.finditer(run):
                consume_step_ref(m.group(1), m.group(2), sname)
            for m in NEEDS_REF.finditer(run):
                consume_needs_ref(m.group(1), m.group(2), sname)

            transported = env_transported(job_env, step_env)

            # does it default an assurance value to something benign, without a guard?
            for m in DEFAULTED.finditer(run):
                var, default = m.group(1), m.group(2)
                if default not in BENIGN:
                    continue
                # is the same variable assigned from an assurance output -- in this step's
                # script, or by an env mapping (the step's or the job's) that carries one?
                if not (re.search(r"%s=.*(steps\.|needs\.)" % re.escape(var), run)
                        or var in transported):
                    continue
                guarded = (bool(re.search(
                    r'(COLLECTION_FAILED|-[zn]\s+"\$\{?%s\b|\[\s*-[zn]\s*"\$%s\b)'
                    % (re.escape(var), re.escape(var)), run))
                    or case_names_empty(var, run))
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
    # `on:` may be a string or a list (`on: push`), which carries no workflow_call outputs.
    triggers = doc.get(True) or doc.get("on") or {}
    call = (triggers.get("workflow_call") if isinstance(triggers, dict) else None) or {}
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
    if self_test():
        return 1
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
