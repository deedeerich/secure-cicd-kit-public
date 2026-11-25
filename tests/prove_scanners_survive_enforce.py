#!/usr/bin/env python3
"""A blocking verdict from one scanner must not switch off the next scanner in the same job.

WHY THIS EXISTS

    GitHub skips every later step with no `if:` once a step fails -- the implicit condition is
    `success()`. An ENFORCE step fails BY DESIGN when its scanner found something. So in a job
    that runs two scanners in sequence, the first scanner finding a real defect silently
    switched the second scanner OFF, and the job then failed for the wrong reason.

    Measured on the hosted negative run 38779814703 (commit ec73600), all three ways:
      * sast-dotnet:    "NuGet audit -- enforce" failed on two vulnerable packages, so the
                        "Semgrep (C#)" step was SKIPPED; its own enforce step then reported
                        "No count was produced" -- a C# SAST scan that never ran, read as a
                        collection failure, and no C# SARIF reached the evidence.
      * sast-cpp:       "cppcheck -- enforce" failed on the seeded double free, so "flawfinder"
                        was SKIPPED; the seeded `sast:cpp-flawfinder` signal came back
                        WRONG-TOOL because flawfinder never executed.
      * malicious-deps: "OSV -- enforce" failed, so "OSV -- is there anything to publish?"
                        was skipped and the OSV SARIF was never kept as an artifact -- the
                        one run where the evidence mattered most is the one that lost it.

    The more a repository has wrong with it, the less of it was scanned. That is the inverse
    of what a gate is for.

THE RULE

    In every job of every shipped (reusable-*) workflow, every step AFTER the first step whose name contains
    "enforce" must carry an `if:` that runs after a failure (`always()`, `failure()` or
    `!cancelled()`). Steps that should only run in some cases say so alongside `always()`, as
    the publication steps already do.

EXIT
    0  every post-enforce step runs whatever the enforce step decided
    1  a step after an enforce step would be skipped by a blocking verdict
    2  could not be checked (no PyYAML, no workflows) -- UNKNOWN, never PASS
"""
import glob
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# The kit's SHIPPED workflows -- what a consumer calls. The self-test's own step names use
# "enforce" as prose; they are not scanner pipelines.
WORKFLOWS = os.path.join(ROOT, '.github', 'workflows', 'reusable-*.yml')
RUNS_AFTER_FAILURE = ('always()', 'failure()', '!cancelled()')


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def offenders(doc):
    """-> [(job, step name, its if)] for steps a failing enforce step would skip."""
    out = []
    for job_name, job in ((doc or {}).get('jobs') or {}).items():
        seen_enforce = None
        for step in (job.get('steps') or []):
            name = step.get('name') or step.get('uses') or '?'
            cond = str(step.get('if') or '')
            if seen_enforce and not any(t in cond.replace(' ', '') for t in RUNS_AFTER_FAILURE):
                out.append((job_name, name, cond or '(none: implicit success())', seen_enforce))
            if 'enforce' in name.lower() and not seen_enforce:
                seen_enforce = name
    return out


def self_test():
    """The detector must say NO to the measured shape, and YES to the repaired one."""
    bad = {'jobs': {'j': {'steps': [{'name': 'a'}, {'name': 'a -- enforce', 'if': 'always()'},
                                    {'name': 'second scanner'}]}}}
    good = {'jobs': {'j': {'steps': [{'name': 'a'}, {'name': 'a -- enforce', 'if': 'always()'},
                                     {'name': 'second scanner', 'if': 'always()'},
                                     {'name': 'keep', 'if': "always() && steps.x.outputs.e == 'true'"}]}}}
    before = {'jobs': {'j': {'steps': [{'name': 'install'}, {'name': 'scan'}]}}}
    fails = []
    if [o[1] for o in offenders(bad)] != ['second scanner']:
        fails.append('a step skipped after a failing enforce step was not reported')
    if offenders(good):
        fails.append('a step guarded by always() was reported')
    if offenders(before):
        fails.append('steps BEFORE any enforce step were reported (they may rely on success())')
    return fails


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    st = self_test()
    if st:
        for f in st:
            print('SELF-TEST FAILED: %s' % f)
        return 2
    files = sorted(glob.glob(WORKFLOWS))
    if not files:
        print('UNKNOWN: no workflows found under %s' % WORKFLOWS)
        return 2
    found = []
    for f in files:
        doc = _expand(yaml.safe_load(io.open(f, encoding='utf-8')))
        for job, step, cond, enforce in offenders(doc):
            found.append('%s / %s: step %r follows %r and has if: %s'
                         % (os.path.basename(f), job, step, enforce, cond))
    if found:
        for x in found:
            print('FAIL: %s' % x)
        print('A failing enforce step skips these. A finding in one scanner must never switch '
              'off the next scanner, or the evidence that scanner keeps.')
        return 1
    print('PASS: across %d workflow(s), every step after an enforce step runs whatever that '
          'step decided.' % len(files))
    return 0


if __name__ == '__main__':
    sys.exit(main())
