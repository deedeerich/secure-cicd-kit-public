#!/usr/bin/env python3
"""Run the per-job summary (scan_status.sh, as INLINED in the workflow) over hollow and crashed
reports and prove it never prints `Findings | 0` for them (ledger L05).

WHY THIS EXISTS

    scan_status.sh's own header states the rule: "Zero says someone looked." It then counted
    `[.runs[].results[]] | length` over any parseable file, so a report that is structurally
    a SARIF but evidences no examination printed `Findings | 0` under `Execution | COMPLETE`:
      * `runs: []` -- the tool reported no run at all;
      * a run whose tool said it FAILED: an error-level notification (SARIF 2.1.0 section
        3.20.21: "SHALL mean that the run failed ... SHALL NOT assume ... complete") -- the exact
        shape bandit 1.9.4 writes when a file does not parse (measured), with exit 0;
      * `executionSuccessful: false` (section 3.20.14);
    and a run with `results` absent (section 3.14.23: "did not attempt") printed a parse failure
    rather than "not established".

    The summary is not the gate, but it is what a person debugging the job reads; a zero there
    is a statement that the code was looked at.

    The script is taken from the workflow's kit-scripts bundle (not scripts/), sourced under bash
    exactly as the generated status step sources it, and its markdown read back.

SCENARIOS (sarif shape, execution -> Findings cell)
    genuine_clean      bandit's measured clean shape: results [], executionSuccessful true -> 0
    findings           three results                                          -> 3
    no_runs            runs: []                                               -> NOT ESTABLISHED
    error_notification bandit's measured unparsed-file shape                  -> NOT ESTABLISHED
    exec_unsuccessful  executionSuccessful false                              -> NOT ESTABLISHED
    results_absent     a run with no results key                              -> NOT ESTABLISHED
    crashed            any report, execution FAILED                           -> NOT ESTABLISHED

EXIT
    0  every scenario printed what it must
    1  a hollow or crashed scan printed a number
    2  could not be checked (no bash, no jq) -- UNKNOWN, never PASS
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402


def run_(results=True, n=0, notes=None, success=True, invocations=True):
    r = {'tool': {'driver': {'name': 'Bandit', 'rules': []}}}
    if invocations:
        inv = {'executionSuccessful': success}
        if notes:
            inv['toolConfigurationNotifications'] = notes
        r['invocations'] = [inv]
    if results:
        r['results'] = [{'ruleId': 'B602', 'level': 'error', 'message': {'text': 'x'}}] * n
    return r


def sarif(*runs):
    return json.dumps({'version': '2.1.0', 'runs': list(runs)})


ERR_NOTE = [{'message': {'text': 'syntax error while parsing AST from file'}, 'level': 'error'}]
SCENARIOS = [
    ('genuine_clean', sarif(run_()), 'COMPLETE', '0'),
    ('findings', sarif(run_(n=3)), 'COMPLETE', '3'),
    ('no_runs', sarif(), 'COMPLETE', None),
    ('error_notification', sarif(run_(notes=ERR_NOTE)), 'COMPLETE', None),
    ('exec_unsuccessful', sarif(run_(success=False)), 'COMPLETE', None),
    ('results_absent', sarif(run_(results=False)), 'COMPLETE', None),
    ('crashed', sarif(run_(n=2)), 'FAILED', None),
]

STEP = '. /tmp/scan_status.sh\nscan_status "Probe" "%s" "report.sarif" "python"\n'


def main():
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    try:
        sb = h.Sandbox('scan-status-probe-').with_bundle()
    except RuntimeError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    bad = []
    try:
        if not h.have(bash, 'jq', h.path_prefix(sb.shim)):
            print('UNKNOWN: jq is required to RUN the summary.')
            return 2
        for name, doc, exe, want in SCENARIOS:
            ws = sb.workspace(name, {'report.sarif': doc})
            summ = os.path.join(sb.root, 'meta', 'summary')
            if os.path.exists(summ):
                os.remove(summ)
            rc, log, _o, _u = sb.run(bash, {'run': STEP % exe}, {}, ws)
            text = open(summ, encoding='utf-8').read() if os.path.exists(summ) else ''
            m = re.search(r'\| Findings \| ([^|]*) \|', text)
            cell = m.group(1).strip() if m else '(none)'
            print('  %-19s execution=%-8s Findings | %s' % (name, exe, cell))
            if rc != 0:
                bad.append('%s: the summary exited %d -- a summary must never fail a job' % (name, rc))
            if want is None:
                if re.fullmatch(r'\d+', cell):
                    bad.append('%s: printed `Findings | %s` -- a number says someone looked, and '
                               'nobody did' % (name, cell))
                elif 'NOT ESTABLISHED' not in cell:
                    bad.append('%s: printed %r, expected NOT ESTABLISHED' % (name, cell))
            elif cell != want:
                bad.append('%s: printed %r, expected %s' % (name, cell, want))
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the per-job summary prints a count only for a run that evidences it ran, and '
          'NOT ESTABLISHED for no runs, a failed run, an unattempted run or a crashed job.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
