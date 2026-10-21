#!/usr/bin/env python3
"""Run the sast-cpp job's cppcheck and enforce steps, as shipped, with the real cppcheck.

WHY THIS EXISTS (ledger L08: "cppcheck converter writes empty SARIF on failure")

    cppcheck writes XML; an inline converter turns it into the SARIF the job publishes. When the
    XML was absent or unparseable, the converter printed a warning and wrote a SARIF with
    `results: []` anyway -- a well-formed, empty, CLEAN-looking report from a scan that produced
    nothing. Nothing counted it and nothing enforced on it.

MEASURED, NOT ASSUMED (cppcheck 2.21.0, 2026-10-14)
    * findings, including severity `error`, exit 0 -- the exit code never signals a finding;
    * a clean tree writes `<results version="2"> ... <errors></errors>`;
    * an output path cppcheck cannot write ALSO exits 0, with no XML -- so the exit code cannot
      vouch for the report either;
    * a scope with no C/C++ sources exits 1: "could not find or open any of the paths given".

    So the XML decides: absent or unparseable is COLLECTION_FAILED and NO SARIF is written;
    "no paths" is NOT_APPLICABLE; otherwise the findings are converted and the `error`-severity
    ones counted.

SCENARIOS
    seeded          buffer overrun + null deref, soft_fail off -> errors >= 1, enforce FAILS
    clean           one pure function                          -> 0, enforce passes
    no_sources      no C/C++ under the scope                   -> NOT_APPLICABLE, passes
    no_xml          cppcheck exits 0 and writes no XML         -> COLLECTION_FAILED, no SARIF
    bad_xml         cppcheck writes XML that does not parse    -> COLLECTION_FAILED, no SARIF

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, no cppcheck) -- UNKNOWN, never PASS
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB = 'sast-cpp'
SCAN, ENFORCE = 'cppcheck', 'cppcheck — enforce'

SEEDED = ('#include <string.h>\nint main(void) {\n  char buf[4];\n  int *p = 0;\n'
          '  strcpy(buf, "overflowing");\n  buf[10] = 1;\n  return *p;\n}\n')
CLEAN = 'int add(int a, int b) { return a + b; }\n'

# Fault injection: a cppcheck that behaves like the real one except for the XML it leaves.
FAULTY = r'''#!/usr/bin/env bash
mode="%s"
for a in "$@"; do case "$a" in --output-file=*) out="${a#--output-file=}" ;; esac; done
if [ -n "${out:-}" ]; then
  [ "$mode" = "bad_xml" ] && printf '<results version="2"><errors><error id=' > "$out"
  exit 0
fi
exec "$REAL_CPPCHECK" "$@"
'''


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
    steps = h.steps_by_name(JOB)
    if SCAN not in steps:
        print('UNKNOWN: no step %r in job %r.' % (SCAN, JOB))
        return 2
    if ENFORCE not in steps:
        print('FAIL: job %r has no step %r. cppcheck findings are converted and published but '
              'never counted or enforced, and a failed conversion publishes an empty report.'
              % (JOB, ENFORCE))
    sb = h.Sandbox('cppcheck-probe-')
    bad = [] if ENFORCE in steps else ['no enforce step']
    try:
        if not h.have(bash, 'cppcheck', h.path_prefix(sb.shim)):
            print('UNKNOWN: cppcheck is required to RUN the step.')
            return 2
        env = dict(os.environ, PATH=h.path_prefix(sb.shim) + os.pathsep + os.environ['PATH'])
        import subprocess
        real = subprocess.run([bash, '-c', 'command -v cppcheck'], env=env, capture_output=True,
                              text=True).stdout.strip()
        faults = {}
        for mode in ('no_xml', 'bad_xml'):
            d = os.path.join(sb.root, 'fault-' + mode)
            h.write(os.path.join(d, 'cppcheck'), FAULTY % mode)
            os.chmod(os.path.join(d, 'cppcheck'), 0o755)
            faults[mode] = d
        scenarios = [
            # name, files, fault, expected collection, expect errors (None=any), enforce ok
            ('seeded', {'src/a.c': SEEDED}, None, 'COMPLETE', True, False),
            ('clean', {'src/a.c': CLEAN}, None, 'COMPLETE', False, True),
            ('no_sources', {'README.md': 'no C here\n'}, None, 'NOT_APPLICABLE', False, True),
            ('no_xml', {'src/a.c': SEEDED}, 'no_xml', 'COLLECTION_FAILED', None, False),
            ('bad_xml', {'src/a.c': SEEDED}, 'bad_xml', 'COLLECTION_FAILED', None, False),
        ]
        for name, files, fault, want_coll, errors, enforce_ok in scenarios:
            ws = sb.workspace(name, files)
            vals = {'inputs.paths': '.', 'inputs.soft_fail_sast': 'false',
                    'inputs.advisory_mode': 'false'}
            rc, log, out, unk = sb.run(bash, steps[SCAN], vals, ws, extra_path=faults.get(fault),
                                       env={'REAL_CPPCHECK': real})
            if unk:
                bad.append('%s: scan step reads unmodelled %s' % (name, unk))
            sarif = os.path.join(ws, 'cppcheck.sarif')
            results = None
            if os.path.isfile(sarif):
                try:
                    doc = json.load(open(sarif, encoding='utf-8'))
                    results = [r for run_ in doc.get('runs', []) for r in run_.get('results', [])]
                except ValueError:
                    results = 'unparseable'
            erc = None
            if ENFORCE in steps:
                evals = dict(vals, **{'steps.cppcheck.outputs.%s' % k: out.get(k, '')
                                      for k in ('count', 'collection')})
                erc, elog, _o, unk = sb.run(bash, steps[ENFORCE], evals, ws)
                if unk:
                    bad.append('%s: enforce step reads unmodelled %s' % (name, unk))
            coll = out.get('collection', '')
            print('  %-11s scan exit=%d collection=%-18s count=%-3s sarif=%-12s enforce=%s'
                  % (name, rc, coll or '-', out.get('count', '-'),
                     'absent' if results is None else (results if isinstance(results, str)
                                                       else '%d result(s)' % len(results)), erc))
            if coll != want_coll:
                bad.append('%s: collection=%r, expected %r\n%s' % (name, coll, want_coll,
                                                                   log[-500:]))
            if want_coll == 'COLLECTION_FAILED':
                if results is not None:
                    bad.append('%s: a SARIF was written although cppcheck produced no usable '
                               'report -- an empty, clean-looking report from a scan that '
                               'produced nothing' % name)
                if rc == 0:
                    bad.append('%s: the scan step exited 0 on COLLECTION_FAILED' % name)
            if errors is True and not (out.get('count', '').isdigit() and int(out['count']) >= 1):
                bad.append('%s: the seeded overrun produced no counted error' % name)
            if errors is False and out.get('count', '0') not in ('0',):
                bad.append('%s: count=%r, expected 0' % (name, out.get('count')))
            if erc is not None and enforce_ok and erc != 0:
                bad.append('%s: enforce failed (exit %d)' % (name, erc))
            if erc is not None and not enforce_ok and erc == 0:
                bad.append('%s: enforce PASSED where it must fail' % name)
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the shipped cppcheck step converts real findings, counts error severity and '
          'enforces it, reads no sources as NOT_APPLICABLE, and on an absent or unparseable XML '
          'writes NO SARIF and reports COLLECTION_FAILED.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
