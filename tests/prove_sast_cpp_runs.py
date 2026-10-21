#!/usr/bin/env python3
"""Run the sast-cpp job's steps in order and prove flawfinder RUNS and cppcheck's output is KEPT
through to publication (W4C-001 regression).

WHY THIS EXISTS

    sast-cpp once installed flawfinder, ran cppcheck instead, and published `flawfinder.sarif`,
    which nothing wrote (fixed in c483d6d). Before that, cppcheck's XML was written and never
    converted, so 159 real defects on a legacy consumer reached nothing downstream. Both are
    "the job is green and a scanner's evidence is missing" -- invisible to every check that reads
    the workflow rather than running it.

    This runs the job's own steps, in order, with the real cppcheck and flawfinder: the analyzer
    check (tools already present, so no package install), cppcheck and its enforce step, flawfinder
    and its enforce step, and the generated redaction step that runs before the uploads. Then it
    asserts what the upload steps will publish: BOTH reports exist, parse, and carry the seeded
    findings -- and that the upload steps name exactly those files.

EXIT
    0  both scanners' evidence reaches the upload steps
    1  a scanner did not run, or its report was lost before publication
    2  could not be checked (no bash, cppcheck, flawfinder) -- UNKNOWN, never PASS
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB = 'sast-cpp'
ORDER = ['Install analyzers', 'cppcheck', 'flawfinder', 'Redact credential material before upload']
SEEDED = ('#include <string.h>\nint copy(const char *in) {\n  char buf[4];\n  strcpy(buf, in);\n'
          '  buf[10] = 1;\n  return buf[0];\n}\n')


def sarif_results(path):
    doc = json.load(open(path, encoding='utf-8'))
    return [r for run_ in doc.get('runs', []) for r in (run_.get('results') or [])]


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    job = h.job(JOB)
    steps = job.get('steps') or []
    names = [s.get('name') for s in steps]
    bad = []
    for n in ORDER[1:3]:
        if n not in names:
            bad.append('job %r has no step %r -- that scanner never runs' % (JOB, n))
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    sb = h.Sandbox('sast-cpp-probe-').with_bundle()
    try:
        for tool in ('cppcheck', 'flawfinder', 'jq'):
            if not h.have(bash, tool, h.path_prefix(sb.shim)):
                print('UNKNOWN: %s is required to RUN the steps.' % tool)
                return 2
        ws = sb.workspace('tree', {'src/copy.c': SEEDED})
        genv = os.path.join(sb.root, 'github_env')
        open(genv, 'w').close()
        vals = {'inputs.paths': '.', 'inputs.soft_fail_sast': 'true',
                'inputs.advisory_mode': 'false', 'github.run_attempt': '1'}
        ran = []
        for s in steps:
            nm = s.get('name') or ''
            if nm in ORDER:
                rc, log, out, unk = sb.run(bash, s, vals, ws, env={'GITHUB_ENV': genv})
                ran.append(nm)
                print('  %-45s exit=%d %s' % (nm, rc, ' '.join('%s=%s' % kv for kv in
                                                              sorted(out.items()))[:80]))
                if unk:
                    bad.append('%r reads unmodelled %s' % (nm, unk))
                if nm == 'Install analyzers' and rc != 0:
                    bad.append('the analyzer check failed (exit %d)\n%s' % (rc, log[-500:]))
                for k, v in out.items():
                    vals['steps.%s.outputs.%s' % (s.get('id'), k)] = v
        uploads = [str((s.get('with') or {}).get('sarif_file') or (s.get('with') or {}).get('path'))
                   for s in steps if 'upload' in str(s.get('uses', ''))]
        for f, tool in (('cppcheck.sarif', 'cppcheck'), ('flawfinder.sarif', 'flawfinder')):
            p = os.path.join(ws, f)
            if f not in uploads:
                bad.append('no upload step publishes %s' % f)
            if not os.path.isfile(p):
                bad.append('%s is absent when the uploads run -- %s\'s evidence is lost' % (f, tool))
                continue
            try:
                res = sarif_results(p)
            except ValueError as exc:
                bad.append('%s does not parse at publication (%s)' % (f, exc))
                continue
            print('  %-18s %d result(s) at publication: %s' % (
                f, len(res), ', '.join(sorted({r.get('ruleId', '') for r in res}))[:100]))
            if not res:
                bad.append('%s carries no result for the seeded strcpy overrun -- %s did not run '
                           'or its findings were dropped' % (f, tool))
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: flawfinder runs and cppcheck\'s converted output survives to the upload steps; '
          'both reports carry the seeded overrun.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
