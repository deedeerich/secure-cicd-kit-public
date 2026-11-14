#!/usr/bin/env python3
"""KREQ-558: DAST and the deployed scan read a live-target authorisation record first, and stop without one.

WHY THIS EXISTS (scripts/live_target_authorisation.py)
    Configuration stood in for authorisation: a DAST command or a scheduled deployed scan ran against a
    live target whenever it was set. The record (schemas/live-target-authorisation.schema.json) names
    the scan, the environment and the target exactly, who authorised it (a role), when, until when, and
    the change that records the owner's agreement. Absent, malformed, expired, not yet valid, over-long
    or out of scope is PREREQUISITE_UNAVAILABLE: the scan is not run, and DAST's evidence says so.

THE CASES
    A  decide(): in force (and on its last day) -> LIVE_TARGET_AUTHORISED; absent, malformed (four ways),
       expired, not yet valid, a window over 366 days, and out of scope by environment, target and scan
       -> PREREQUISITE_UNAVAILABLE with the reason.
    C  the CLI: a refused DAST writes dast.json PREREQUISITE_UNAVAILABLE into the deploy evidence and
       exits 1; an authorised one writes none and exits 0; the record is read through the contents API.
    G  the composite's own shell glue emits live_target_authorisation.
    S  structure: in all three deploy reusables the authorisation step (scan dast, not at prod, only when
       DAST is configured) runs before the DAST step, and the DAST step runs only when it answered
       LIVE_TARGET_AUTHORISED; in the deployed scan the authorisation step runs, unconditionally, before
       Azure login.
    W  the shipped Container Apps job in the harness: DAST configured and not authorised -> the DAST step
       is skipped; authorised -> it runs.
    M  mutants, each must turn a case red: expiry unchecked; scope unchecked; absence treated as
       authorised; the DAST gate removed; the deployed scan's authorisation step removed.

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import base64
import copy
import datetime
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _deploy_steps as D  # noqa: E402
import _workflow_runner as W  # noqa: E402
import live_target_authorisation as L  # noqa: E402

DEPLOYS = ('reusable-deploy-containerapp.yml', 'reusable-deploy-appservice.yml', 'reusable-deploy-staticwebapp.yml')
SCAN_WF = 'reusable-deployed-scan.yml'
USES = '$/.github/actions/live-target-authorisation'
ACTION = os.path.join(ROOT, '.github', 'actions', 'live-target-authorisation', 'action.yml')
DAST_STEP = 'DAST baseline against this environment (never prod)'
TODAY = datetime.date(2026, 11, 13)


def entry(**over):
    e = {'id': 'LTA-001', 'environment': 'dev', 'targets': ['web'], 'scans': ['dast', 'deployed-scan'],
         'authorised_by': 'application security lead', 'authorised_on': '2026-11-01',
         'expires_on': '2027-01-31', 'reference': 'CHG-1'}
    e.update(over)
    return e


def rec(*entries):
    return {'schema_version': 1, 'authorisations': list(entries) or [entry()]}


CASES = [
    ('in force', rec(), 'dast', 'dev', 'web', TODAY, L.AUTHORISED),
    ('deployed scan in force', rec(), 'deployed-scan', 'dev', 'web', TODAY, L.AUTHORISED),
    ('last day', rec(), 'dast', 'dev', 'web', datetime.date(2027, 1, 31), L.AUTHORISED),
    ('absent', None, 'dast', 'dev', 'web', TODAY, L.UNAVAILABLE),
    ('schema version 2', dict(rec(), schema_version=2), 'dast', 'dev', 'web', TODAY, L.UNAVAILABLE),
    ('no expiry', rec(entry(expires_on='')), 'dast', 'dev', 'web', TODAY, L.UNAVAILABLE),
    ('unknown scan kind', rec(entry(scans=['dast', 'pentest'])), 'dast', 'dev', 'web', TODAY, L.UNAVAILABLE),
    ('bad date', rec(entry(expires_on='31/01/2027')), 'dast', 'dev', 'web', TODAY, L.UNAVAILABLE),
    ('expired', rec(), 'dast', 'dev', 'web', datetime.date(2027, 2, 1), L.UNAVAILABLE),
    ('not yet valid', rec(entry(authorised_on='2026-12-01')), 'dast', 'dev', 'web', TODAY, L.UNAVAILABLE),
    ('window over 366 days', rec(entry(authorised_on='2026-01-01', expires_on='2027-06-01')), 'dast', 'dev', 'web',
     TODAY, L.UNAVAILABLE),
    ('another environment', rec(), 'dast', 'prod', 'web', TODAY, L.UNAVAILABLE),
    ('another target', rec(), 'dast', 'dev', 'api', TODAY, L.UNAVAILABLE),
    ('another scan', rec(entry(scans=['deployed-scan'])), 'dast', 'dev', 'web', TODAY, L.UNAVAILABLE),
]


def section_a():
    fails = []
    for label, record, scan, envn, target, today, want in CASES:
        got, reason, _ = L.decide(copy.deepcopy(record), scan, envn, target, today)
        print('  A  %-22s -> %-26s %s' % (label, got, reason[:70]))
        if got != want:
            fails.append('A %s: %s, wanted %s (%s)' % (label, got, want, reason))
    return fails


def run_cli(args):
    tmp = tempfile.mkdtemp(prefix='kreq558-')
    try:
        ev = os.path.join(tmp, 'deploy-evidence')
        out = os.path.join(tmp, 'lta.json')
        rc = L.main(args(tmp) + ['--dast-evidence', ev, '--out', out, '--today', str(TODAY)])
        dast = os.path.join(ev, 'dast.json')
        return rc, json.load(io.open(out)), (json.load(io.open(dast)) if os.path.exists(dast) else None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def contents_api(root, record):
    p = os.path.join(root, 'repos', 'o', 'r', 'contents', '.kit')
    os.makedirs(p, exist_ok=True)
    io.open(os.path.join(p, 'live-target-authorisation.json'), 'w').write(json.dumps(
        {'content': base64.b64encode(json.dumps(record).encode()).decode()}))
    return 'file:///' + root.replace('\\', '/').lstrip('/')


def section_c():
    fails = []

    def local(record):
        def args(tmp):
            p = os.path.join(tmp, 'record.json')
            io.open(p, 'w').write(json.dumps(record))
            return ['--scan', 'dast', '--environment', 'dev', '--target', 'web', '--record', p]
        return args
    rc, doc, dast = run_cli(local(rec(entry(expires_on='2026-11-12'))))
    print('  C  expired, DAST                   rc=%s dast.json=%s' % (rc, dast and dast.get('result')))
    if rc != 1 or not dast or dast.get('result') != L.UNAVAILABLE:
        fails.append('C: an expired authorisation did not stop DAST with dast.json %s' % L.UNAVAILABLE)
    rc, doc, dast = run_cli(local(rec()))
    print('  C  in force, DAST                  rc=%s dast.json=%s' % (rc, dast))
    if rc != 0 or dast is not None or doc['live_target_authorisation'] != L.AUTHORISED:
        fails.append('C: an authorised DAST was refused or left a dast.json')

    def api(tmp):
        os.environ['GITHUB_REPOSITORY'] = 'o/r'
        os.environ['GITHUB_API_URL'] = contents_api(os.path.join(tmp, 'api'), rec())
        return ['--scan', 'deployed-scan', '--environment', 'dev', '--target', 'web']
    rc, doc, _ = run_cli(api)
    print('  C  contents API, deployed scan     rc=%s %s' % (rc, doc['live_target_authorisation']))
    if rc != 0 or doc['live_target_authorisation'] != L.AUTHORISED:
        fails.append('C: the record on the default branch (contents API) was not read: %s' % doc['reason'])

    def no_api(tmp):
        os.environ['GITHUB_API_URL'] = 'file:///nonexistent-kit-api-root'
        return ['--scan', 'deployed-scan', '--environment', 'dev', '--target', 'web']
    rc, doc, _ = run_cli(no_api)
    print('  C  no record on the branch         rc=%s %s' % (rc, doc['live_target_authorisation']))
    if rc != 1 or doc['live_target_authorisation'] != L.UNAVAILABLE or 'absent' not in doc['reason']:
        fails.append('C: an absent record did not answer %s (absent)' % L.UNAVAILABLE)
    return fails


def section_g():
    bash, why = D.bash()
    if not bash:
        return ['G: no bash (%s)' % why]
    step = D.load(ACTION)['runs']['steps'][0]
    tmp = tempfile.mkdtemp(prefix='kreq558-glue-')
    try:
        env = {'GITHUB_ACTION_PATH': os.path.dirname(ACTION), 'GITHUB_REPOSITORY': 'o/r',
               'GITHUB_API_URL': contents_api(os.path.join(tmp, 'api'), rec(entry(expires_on='2026-01-31',
                                                                                  authorised_on='2026-01-01'))),
               'I_SCAN': 'dast', 'I_ENVIRONMENT': 'dev', 'I_TARGET': 'web',
               'I_DAST_EVIDENCE': os.path.join(tmp, 'ev'), 'RUNNER_TEMP': tmp}
        rc, outs, log, _ = D.run_script(bash, step['run'], env)
        dast = os.path.join(tmp, 'ev', 'dast.json')
        print('  G  composite, expired              rc=%s %s dast.json=%s' % (rc, outs.get('live_target_authorisation'),
                                                                          os.path.exists(dast)))
        if rc != 1 or outs.get('live_target_authorisation') != L.UNAVAILABLE or not os.path.exists(dast):
            return ['G: the composite did not refuse an expired record: %s' % log[-400:]]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return []


def structure(docs):
    fails = []
    for n in DEPLOYS:
        doc = docs[n]
        st = D.steps(doc)
        names = [s.get('name') for s in st]
        lta = [i for i, s in enumerate(st) if s.get('uses') == USES]
        di = names.index(DAST_STEP) if DAST_STEP in names else -1
        if len(lta) != 1 or not lta[0] < di:
            fails.append('%s: no single authorisation step before DAST' % n)
            continue
        s = st[lta[0]]
        cond = str(s.get('if'))
        if (s.get('with') or {}).get('scan') != 'dast' or s.get('id') != 'lta' or \
                "inputs.dast_command != ''" not in cond or "inputs.environment_tier != 'prod'" not in cond:
            fails.append('%s: the authorisation step is not scan dast / id lta / DAST-configured, non-prod' % n)
        if "steps.lta.outputs.live_target_authorisation == 'LIVE_TARGET_AUTHORISED'" not in str(st[di].get('if')):
            fails.append('%s: the DAST step does not wait for LIVE_TARGET_AUTHORISED' % n)
    sc = docs[SCAN_WF]['jobs']['scan']['steps']
    names = [s.get('name') for s in sc]
    lta = [i for i, s in enumerate(sc) if s.get('uses') == USES]
    login = names.index('Azure login (OIDC)') if 'Azure login (OIDC)' in names else -1
    if len(lta) != 1 or not lta[0] < login or sc[lta[0]].get('if') is not None or \
            (sc[lta[0]].get('with') or {}).get('scan') != 'deployed-scan':
        fails.append('%s: no unconditional deployed-scan authorisation step before Azure login' % SCAN_WF)
    print('  S  structure (3 deploys + deployed scan) %s' % ('ok' if not fails else 'FAIL'))
    return fails


def section_w():
    fails = []
    inputs = dict(github_environment='env', routing_result='PROCEED', environment_tier='dev', resource_group='rg-a',
                  containerapp_name='web', acr_login_server=W.REG, image_repository=W.REPO, image_digest=W.NEW,
                  cloud='commercial', health_path='/health', health_retries=2, health_interval_seconds=0,
                  rollback_on_failure=True, version_metadata='', dast_command='true')
    for answer, want in ((L.UNAVAILABLE, 'skipped'), (L.AUTHORISED, 'ran')):
        res, _f, _c = W.run_world(D.CONTAINERAPP, inputs, W.containerapp_state(),
                                  uses_outputs={'lta': {'live_target_authorisation': answer}})
        got = dict(res['order']).get(DAST_STEP)
        verdict = 'skipped' if got == 'skipped' else 'ran'
        print('  W  authorisation %-26s DAST step %s' % (answer, got))
        if verdict != want:
            fails.append('W: with %s the DAST step %s, wanted %s' % (answer, got, want))
    return fails


def mutants(docs):
    caught = []
    saved = L.decide

    def no_expiry(record, scan, envn, target, today):
        return saved(record, scan, envn, target, datetime.date(2026, 11, 13))
    L.decide = no_expiry
    caught.append(('expiry unchecked', bool(section_a())))

    def no_scope(record, scan, envn, target, today):
        return saved(record, 'dast', 'dev', 'web', today) if record else saved(record, scan, envn, target, today)
    L.decide = no_scope
    caught.append(('scope unchecked', bool(section_a())))

    def absent_ok(record, scan, envn, target, today):
        return (L.AUTHORISED, 'absent', None) if record is None else saved(record, scan, envn, target, today)
    L.decide = absent_ok
    caught.append(('absence authorised', bool(section_a())))
    L.decide = saved
    m = copy.deepcopy(docs)
    for s in D.steps(m['reusable-deploy-appservice.yml']):
        if s.get('name') == DAST_STEP:
            s['if'] = "!cancelled() && steps.serving.outcome == 'success'"
    caught.append(('DAST gate removed', bool(structure(m))))
    m = copy.deepcopy(docs)
    m[SCAN_WF]['jobs']['scan']['steps'] = [s for s in m[SCAN_WF]['jobs']['scan']['steps'] if s.get('uses') != USES]
    caught.append(('deployed-scan step removed', bool(structure(m))))
    return caught


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    docs = {n: D.load(os.path.join(ROOT, '.github', 'workflows', n)) for n in DEPLOYS + (SCAN_WF,)}
    fails = section_a() + section_c() + section_g() + structure(docs) + section_w()
    print('  -- mutants (each must be caught) --')
    for label, was in mutants(docs):
        print('  M  %-28s %s' % (label, 'caught' if was else 'NOT CAUGHT'))
        if not was:
            fails.append('M: the mutant "%s" passed every case' % label)
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: DAST and the deployed scan read the live-target authorisation first; absent, malformed, '
          'expired, not yet valid, over-long or out of scope is PREREQUISITE_UNAVAILABLE and the scan does not '
          'run; every mutant is caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
