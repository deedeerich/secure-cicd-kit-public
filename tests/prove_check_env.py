#!/usr/bin/env python3
"""check_env.py asks for the CONFIGURED backend's values, and only those (C-1, OD-5).

WHY THIS EXISTS

    `scripts/check_env.py` required Jira AND Azure DevOps credentials together. Exactly one ticket
    backend is authoritative per (repo, environment) cell (TICKETING_CONTRACT.md 4.6;
    TICKETING_BACKENDS.md section 1), so a checker that demands both is either asking an operator
    to hold credentials the run must never use, or telling a correctly configured operator they
    are wrong. Both teach people to ignore it.

HOW IT RUNS

    The script locates `.env` beside its own parent directory. So it is COPIED into a throwaway
    tree with a `.env` written there, and run as shipped. The repository's own `.env` (if any) is
    never read, and no value here is a real credential. No network: the checker makes no request.

THE FOUR CASES (docs/PROOF_RULE.md)

    allowed           Jira alone, complete -> 0.  Azure DevOps alone, complete -> 0.
    attack            Jira selected, one Jira value missing -> 1, naming it.
    missing evidence  no TICKET_BACKEND -> 1 naming TICKET_BACKEND; no .env at all -> 2.
    recovery          the missing value supplied -> 0.

EXIT  0 proven  1 a case failed  2 could not be checked
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, 'scripts', 'check_env.py')

JIRA = {'TICKET_BACKEND': 'jira', 'JIRA_HOST': 'https://example.atlassian.net',
        'JIRA_EMAIL': 'someone@example.invalid', 'JIRA_TOKEN': 'placeholder-not-a-token',
        'JIRA_PROJECT': 'KIT', 'JIRA_STAMP_FIELD': 'customfield_10001', 'JIRA_EPIC_ID': '10000',
        'JIRA_CALIBRATION_ISSUE': '10002', 'TICKET_CREATE_CEILING': '25'}
AZDO = {'TICKET_BACKEND': 'azdo', 'AZDO_ORG_URL': 'https://dev.azure.com/example',
        'AZDO_PROJECT': 'kit', 'AZDO_PAT': 'placeholder-not-a-pat',
        'AZDO_STAMP_FIELD': 'Custom.KitClusterKey', 'AZDO_EPIC_ID': '1',
        'AZDO_CALIBRATION_ITEM': '2', 'TICKET_CREATE_CEILING': '25'}


def run(values):
    """Copy the script into a fresh tree, write `values` as its .env (None = no .env), run it."""
    tmp = tempfile.mkdtemp(prefix='check-env-')
    try:
        os.makedirs(os.path.join(tmp, 'scripts'))
        shutil.copyfile(SCRIPT, os.path.join(tmp, 'scripts', 'check_env.py'))
        if values is not None:
            io.open(os.path.join(tmp, '.env'), 'w', encoding='utf-8').write(
                ''.join('%s=%s\n' % kv for kv in values.items()))
        p = subprocess.run([sys.executable, os.path.join(tmp, 'scripts', 'check_env.py')],
                           capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout + p.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def without(d, key):
    d = dict(d)
    d.pop(key)
    return d


def main():
    if not os.path.exists(SCRIPT):
        print('UNKNOWN: %s is absent, so nothing was checked.' % SCRIPT)
        return 2
    fails = []
    cases = [
        ('allowed: Jira alone, complete', JIRA, 0, None),
        ('allowed: Azure DevOps alone, complete', AZDO, 0, None),
        ('allowed: Azure DevOps by the legacy org variable',
         dict(without(AZDO, 'AZDO_ORG_URL'), AZDO_ORG='https://example.visualstudio.com'), 0,
         None),
        ('attack: Jira selected, JIRA_EMAIL missing', without(JIRA, 'JIRA_EMAIL'), 1,
         'JIRA_EMAIL'),
        ('attack: Azure DevOps selected, the calibration item missing',
         without(AZDO, 'AZDO_CALIBRATION_ITEM'), 1, 'AZDO_CALIBRATION_ITEM'),
        ('attack: an unknown backend named', dict(JIRA, TICKET_BACKEND='both'), 1,
         'TICKET_BACKEND'),
        ('missing: no backend selected', without(JIRA, 'TICKET_BACKEND'), 1, 'TICKET_BACKEND'),
        ('missing: no .env at all', None, 2, 'UNKNOWN'),
        ('recovery: the missing value supplied', JIRA, 0, None),
    ]
    for label, values, want, needle in cases:
        rc, out = run(values)
        ok = rc == want and (needle is None or needle in out)
        # A credential must never be echoed back.
        for v in (JIRA['JIRA_TOKEN'], AZDO['AZDO_PAT']):
            if v in out:
                ok = False
                fails.append('%s: the output echoed a credential value' % label)
        if rc == want and needle and needle not in out:
            fails.append('%s: exit %d as expected but %s was not named' % (label, rc, needle))
        elif rc != want:
            fails.append('%s: exit %d, expected %d. %s' % (label, rc, want, out.strip()[-300:]))
        print('  %-62s exit %d  %s' % (label, rc, 'ok' if ok else 'FAIL'))
    if fails:
        print('')
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('::error title=check_env asks for the wrong backend::%d failure(s)' % len(fails))
        return 1
    print('check_env requires the configured backend\'s values and only those; it names the '
          'missing one, never echoes a credential, and reports no .env as UNKNOWN.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
