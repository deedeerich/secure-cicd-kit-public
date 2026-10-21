#!/usr/bin/env python3
"""A refusal's own body must reach the run log, not only an output nobody can read on dispatch.

WHY THIS EXISTS

    authorization-boundary-isolation closes on "a dispatched run in which at least one scope
    returns REFUSED with an AuthorizationFailed body". verify-azure-oidc.yml's step `probe`
    captured that body -- `record` stores it as the `evidence` field of each assertion -- and then
    showed it nowhere a reader of a DISPATCHED run can see: the log line printed id, scope,
    expected, observed, verdict and reason; the step summary prints the same columns; and the
    `assertions` output that carries the evidence is visible only to a workflow_call caller.
    Hosted run 38832628162 (2026-10-15) classified three scopes REFUSED on
    `rbac-authorization-denied` -- a pattern set that matches AuthorizationFailed AND several
    other 403 shapes -- and the body that decided it was unreadable. A classification nobody can
    check against its input is the same claim as a classification asserted without one.

WHAT THE STEP MUST DO

    For every assertion it records, print the redacted, truncated evidence excerpt (the text the
    classifier read) on the line after the verdict line, so the body is in the log of a dispatched
    run. Redaction is the step's own `redact` -- the excerpt passes through `short`, which applies
    it -- so a token-shaped string in an Azure error body is never printed.

WHAT THIS PROVES, LOCALLY

    The shipped step is EXTRACTED (never re-implemented) and run under bash with a shim `az` that
    answers `group show` and `deployment sub validate` per scope: an AuthorizationFailed body for
    the refused scopes and the nonexistent control scope, success for the reachable ones. `jq`,
    `sed`, `grep`, `tr` and `cut` are real. Rows:

      E1  every REFUSED assertion's log shows the AuthorizationFailed body it was classified from
      E2  the subscription-scope probe's body is shown too
      E3  a JWT-shaped string inside a body is printed as [redacted-jwt], never verbatim
      E4  the verdict lines are unchanged (expected/observed/verdict still printed)

WHAT IT CANNOT ESTABLISH
    What Azure returns for a given identity. Only a hosted dispatch can show that.

EXIT  0 every row holds   1 a row failed   2 the step could not be run (UNKNOWN, never PASS)
"""
import io
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

WF = '.github/workflows/verify-azure-oidc.yml'
JOB = 'verify'
STEP = 'probe'

# Invented scope names and a JWT-shaped string built at run time; nothing denotes a real estate.
REACHABLE = ['rg-example-own', 'rg-example-shared']
REFUSED = ['rg-example-sibling', 'rg-example-opposite']
FAKE_JWT = 'eyJ' + 'a' * 20 + '.' + 'b' * 24 + '.' + 'c' * 16

AZ_SHIM = r'''
args="$*"
for r in $STUB_REACHABLE; do
  case "$args" in *"--name $r "*) exit 0 ;; esac
done
if printf '%s' "$args" | grep -q 'deployment sub validate'; then
  echo "ERROR: (AuthorizationFailed) The client 'x' with object id 'y' does not have authorization to perform action 'Microsoft.Resources/deployments/validate/action' over scope '/subscriptions/z'"
  exit 1
fi
echo "ERROR: (AuthorizationFailed) The client 'x' does not have authorization to perform action 'Microsoft.Resources/subscriptions/resourcegroups/read'. token=$STUB_JWT"
exit 1
'''

PRELUDE = ('if command -v cygpath >/dev/null 2>&1; then _d=$(cygpath -u "$STUB_DIR"); '
           'else _d="$STUB_DIR"; fi\nexport PATH="$_d:$PATH"\n')


def main():
    import _step_harness as H
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s); the step was not run.' % why)
        return 2
    if not shutil.which('jq'):
        print('UNKNOWN: jq is not on PATH; the step records with it and was not run.')
        return 2
    step = H.step(WF, JOB, STEP)
    if step is None:
        print('FAIL: no step %r in job %r of %s.' % (STEP, JOB, WF))
        return 1

    fails = []

    def row(name, ok, detail=''):
        print('  %s  %s%s' % ('ok  ' if ok else 'FAIL', name, ('  -- ' + detail) if detail else ''))
        if not ok:
            fails.append(name)

    ws = tempfile.mkdtemp(prefix='oidc-evidence-')
    try:
        shim_dir = os.path.join(ws, 'shim')
        H.shim(shim_dir, 'az', AZ_SHIM)
        H.shim(shim_dir, 'sleep', 'exit 0')
        rt = os.path.join(ws, 'rt')
        os.makedirs(rt)
        io.open(os.path.join(rt, 'scopes-reachable.txt'), 'w', newline='\n').write(
            'own-workload|%s\nentitled-shared|%s\n' % tuple(REACHABLE))
        io.open(os.path.join(rt, 'scopes-refused.txt'), 'w', newline='\n').write(
            'sibling-workload|%s\nopposite-tier-shared|%s\n' % tuple(REFUSED))
        ctx = {'inputs.subscription_probe_location': 'westus2',
               'secrets.AZURE_SUBSCRIPTION_ID': '00000000-0000-0000-0000-000000000000'}
        extra = {'STUB_DIR': shim_dir, 'STUB_REACHABLE': ' '.join(REACHABLE),
                 'STUB_JWT': FAKE_JWT, 'RUNNER_TEMP': rt.replace('\\', '/'),
                 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}
        s = dict(step)
        s['run'] = PRELUDE + (step.get('run') or '')
        r = H.run(bash, s, ctx, ws, extra_env=extra)
        log = r['log']
        lines = log.splitlines()
        row('step ran (exit 0)', r['rc'] == 0, 'rc=%s' % r['rc'])

        def evidence_after(marker):
            for i, l in enumerate(lines):
                if marker in l and 'expected=' in l:
                    return lines[i + 1] if i + 1 < len(lines) else ''
            return None

        for rg in REFUSED:
            ev = evidence_after(rg)
            row('E1 %s: verdict line present' % rg, ev is not None)
            row('E1 %s: the AuthorizationFailed body follows it' % rg,
                bool(ev) and 'AuthorizationFailed' in ev and 'evidence' in ev, repr(ev))
        ev = evidence_after('refused.subscription-mutation')
        row('E2 subscription probe body shown',
            bool(ev) and 'deployments/validate/action' in ev, repr(ev))
        row('E3 the JWT-shaped string is never printed verbatim', FAKE_JWT not in log)
        row('E3 it is printed redacted', '[redacted-jwt]' in log)
        row('E4 verdict lines unchanged',
            all(any(rg in l and 'expected=REFUSED' in l and 'observed=REFUSED' in l for l in lines)
                for rg in REFUSED))
    finally:
        shutil.rmtree(ws, ignore_errors=True)

    if fails:
        print('\nFAIL: %d row(s): %s' % (len(fails), '; '.join(fails)))
        return 1
    print('\nPASS: every recorded assertion prints the redacted body it was classified from, '
          'so a dispatched run shows WHY a scope was REFUSED, not only that it was.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
