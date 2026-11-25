#!/usr/bin/env python3
"""KREQ-717: every mutating deploy job is time-bounded, and a kill mid-change is reconciled by the NEXT run.

WHY THIS EXISTS (docs/architecture/ROLLBACK_CONTRACT.md, "Timeouts are a cancellation vector";
scripts/deploy_interruption.py)

    A bound on a mutating job is safe only when what a kill leaves is designed. The design: the change
    manifest at the kill decides the outcome (PARTIAL_APPLY inside the mutating call, STATUS_UNTRUSTED
    after it -- DCR-8, as for a cancel), the always() record names INTERRUPTED_DEPLOY_RECONCILIATION_
    REQUIRED, and the next run of the target is refused until a person names the reconciled run.

THE CASES
    S  structure, all three deploy reusables: the deploy job's `timeout-minutes` resolves to the input
       inside 30..360 and to 90 outside it (never unbounded); the check step (op check) runs before
       Azure login; the record step (op record, `if: always()`, the job's cancelled status) runs after
       the outcome report and before the run record is kept.
    K  mocked sleeper through the SHIPPED Container Apps job against the stub cloud: each step "takes"
       simulated minutes; the kill lands in the first step whose cumulative time passes the resolved
       bound (modelled by the harness as a cancellation after that step; a kill inside the mutating
       call is the stub's apply-then-error fault).
         K1 positive  finishes inside the bound -> DEPLOY_HEALTHY; the record owes nothing; next run CLEAR
         K2 negative  killed after the mutation -> STATUS_UNTRUSTED; the record names
                      INTERRUPTED_DEPLOY_RECONCILIATION_REQUIRED; the next run is refused naming the run;
                      a wrong run id is still refused; the right one is INTERRUPTED_DEPLOY_RECONCILED_BY_HAND
         K3 negative  killed inside the mutating call -> PARTIAL_APPLY; reconciliation required
         K4 killed before login -> nothing recorded (no snapshot); the previous state stands
    B  the bound: 20 and 400 minutes refused; 60 with a 240-minute test period refused; 90 with a
       15-minute period and DAST accepted. Unreadable state -> INTERRUPTION_CHECK_INCOMPLETE.
    G  the composite's own shell glue runs the script and emits the state (check and record).
    M  mutants, each must turn a case red: timeout removed; clamp removed; record step's always()
       removed; reconciliation skipped (nothing owed after a kill); any run id accepted; bound unchecked.

THE OTHER MUTATING JOBS (KDEC-061 M2, lane deploy-bounds; ROLLBACK_CONTRACT.md kill tables)
    S2 structure: reusable-rollback-sequence.yml (rollback_timeout_minutes, clamp 180; the check
       before Azure login; the always() record with the cancelled status, kind rollback-sequence,
       uploaded as the target's state), reusable-build-docker.yml (build_timeout_minutes, clamp 90;
       the bound first; the always() registry-push record before the kept build evidence; the
       attest job signs only a successful build job's proven identity -- no always()/cancelled()),
       live-deploy-acceptance.yml (its timeout_minutes reaches every reusable; its own job bounded).
    R  the REAL sequence engine (scripts/rollback_sequence.py) against the stub cloud, two deploys
       by the shipped Container Apps job:
         R1 positive  the sequence completes -> the record owes nothing; the next check CLEAR
         R2 negative  KILLED (process tree) inside the test period after step 1 reversed the live
                      target -> no sequence record; STATUS_UNTRUSTED, INTERRUPTED_DEPLOY_RECONCILIATION_
                      REQUIRED; the next sequence AND the next deploy of the target (one artifact
                      name) are refused naming the run; naming it proceeds (reconciled by hand)
         R3 negative  the same kill one write earlier (the newest step has no reversal record) ->
                      PARTIAL_APPLY, reconciliation required
         R4 killed before any step -> nothing recorded; the previous state stands
       bound: 3 steps x 15 min needs 75 (60 refused, naming rollback_timeout_minutes; 180 clear);
       3 x 240 cannot fit 360 (refused).
    P  the registry push: the SHIPPED push_capability and push steps with docker shimmed, then the
       registry-push record:
         P1 positive  pushed and proven, not cancelled -> nothing owed, nothing unpromotable
         P2 negative  killed inside the push (manifest `planned`) -> PARTIAL_APPLY, INTERRUPTED_PUSH_UNPROMOTABLE
         P3 negative  pushed, identity never asserted, cancelled -> STATUS_UNTRUSTED, unpromotable
         P4 negative  proven, then the job cancelled (the attest job never runs) -> unpromotable
         P5 killed before the capability step -> nothing recorded
       and why "unpromotable" holds: scripts/promotion.py judge refuses ATTESTATION_ABSENT
       (PROMOTION_REFUSED_SIGNATURE), break-glass included; ATTESTATION_VERIFIED is allowed.
    M2 mutants: rollback timeout removed / clamp removed / record not always(); build timeout removed;
       attest job made always(); a killed sequence owes nothing; a killed push promotable; break-glass
       lifts the signature refusal.

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import copy
import io
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _deploy_steps as D  # noqa: E402
import _workflow_runner as W  # noqa: E402
import deploy_interruption as DI  # noqa: E402

WORKFLOWS = {'reusable-deploy-containerapp.yml': 'containerapp_name',
             'reusable-deploy-appservice.yml': 'webapp_name',
             'reusable-deploy-staticwebapp.yml': 'site_name'}
ACTION = os.path.join(ROOT, '.github', 'actions', 'deploy-interruption', 'action.yml')
USES = '$/.github/actions/deploy-interruption'


# ----------------------------------------------------------------------------- S structure
def resolve_timeout(expr, minutes, name='deploy_timeout_minutes'):
    """Evaluate the job's timeout-minutes expression for one input value (the && / || idiom)."""
    m = re.fullmatch(r'\s*\$\{\{\s*(.*?)\s*\}\}\s*', str(expr))
    if not m:
        return expr
    src = m.group(1).replace('inputs.' + name, repr(minutes))
    if re.search(r'[A-Za-z_]', src.replace('&&', '').replace('||', '')):
        return 'unresolvable: %s' % m.group(1)
    return eval(src.replace('&&', ' and ').replace('||', ' or '), {'__builtins__': {}}, {})  # noqa: S307


def structure(doc, name):
    fails = []
    job = D.job(doc)
    t = job.get('timeout-minutes')
    if t is None:
        return ['%s: the deploy job has no timeout-minutes (KREQ-717)' % name]
    for given, want in ((90, 90), (120, 120), (30, 30), (360, 360), (0, 90), (29, 90), (361, 90), (100000, 90)):
        got = resolve_timeout(t, given)
        if got != want:
            fails.append('%s: timeout-minutes resolves to %r for input %s, wanted %s (governed, never unbounded)'
                         % (name, got, given, want))
    names = [s.get('name') for s in D.steps(doc)]
    uses = [(i, s) for i, s in enumerate(D.steps(doc)) if s.get('uses') == USES]
    check = [(i, s) for i, s in uses if (s.get('with') or {}).get('op') == 'check']
    record = [(i, s) for i, s in uses if (s.get('with') or {}).get('op') == 'record']
    login = names.index('Azure login (OIDC)') if 'Azure login (OIDC)' in names else -1
    report = names.index('Reconcile and report outcome') if 'Reconcile and report outcome' in names else -1
    keep = names.index('Keep the run record (deploy evidence)') if 'Keep the run record (deploy evidence)' in names else -1
    if len(check) != 1 or not 0 <= check[0][0] < login:
        fails.append('%s: the interruption check is not one step before Azure login' % name)
    elif check[0][1].get('if') is not None or (check[0][1].get('with') or {}).get('timeout-minutes') != \
            '${{ inputs.deploy_timeout_minutes }}':
        fails.append('%s: the check is conditional or does not check the job\'s own bound' % name)
    if len(record) != 1 or not report < record[0][0] < keep:
        fails.append('%s: the state record is not one step between the outcome report and the kept run record' % name)
    else:
        r = record[0][1]
        if 'always()' not in str(r.get('if')) or (r.get('with') or {}).get('cancelled') != "${{ job.status == 'cancelled' }}":
            fails.append('%s: the state record does not run on a cancelled or timed-out job, or does not '
                         'carry the cancelled status' % name)
    return fails


def section_s(docs):
    fails = []
    for name, doc in docs.items():
        f = structure(doc, name)
        print('  S  %-36s %s' % (name, 'ok' if not f else 'FAIL'))
        fails += f
    return fails


# ----------------------------------------------------------------------------- fake API
def api_with_state(root, state):
    repo = os.path.join(root, 'repos', 'o', 'r', 'actions')
    os.makedirs(repo, exist_ok=True)
    arts = []
    if state is not None:
        z = os.path.join(root, 'state.zip')
        with zipfile.ZipFile(z, 'w') as zf:
            zf.writestr('deploy-state.json', json.dumps(state))
        arts.append({'name': DI.state_name('env', 'rg-a', 'web'), 'expired': False,
                     'created_at': '2026-11-13T00:00:00Z',
                     'archive_download_url': 'file:///' + z.replace('\\', '/').lstrip('/')})
    io.open(os.path.join(repo, 'artifacts'), 'w', encoding='utf-8').write(
        json.dumps({'total_count': len(arts), 'artifacts': arts}))
    return 'file:///' + root.replace('\\', '/').lstrip('/')


def run_check(state, reconciled='', timeout='90', period='15', dast='false', api_url=None,
              bound_name='deploy_timeout_minutes'):
    tmp = tempfile.mkdtemp(prefix='kreq717-check-')
    try:
        os.environ['GITHUB_REPOSITORY'] = 'o/r'
        os.environ['GITHUB_API_URL'] = api_url or api_with_state(os.path.join(tmp, 'api'), state)
        out = os.path.join(tmp, 'check.json')
        rc = DI.main(['check', '--environment', 'env', '--resource-group', 'rg-a', '--name', 'web',
                      '--timeout', timeout, '--test-period', period, '--dast', dast,
                      '--reconciled-run', reconciled, '--out', out, '--bound-name', bound_name])
        doc = json.load(io.open(out, encoding='utf-8'))
        return rc, doc['deploy_interruption'], doc['why']
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def record_from(evidence, cancelled, run_id='4242'):
    tmp = tempfile.mkdtemp(prefix='kreq717-record-')
    try:
        ev = os.path.join(tmp, 'deploy-evidence')
        os.makedirs(ev)
        for f, body in evidence.items():
            if f.endswith('.json'):
                io.open(os.path.join(ev, f), 'w', encoding='utf-8').write(
                    body if isinstance(body, str) else json.dumps(body))
        DI.main(['record', '--environment', 'env', '--resource-group', 'rg-a', '--name', 'web',
                 '--evidence-dir', ev, '--out-dir', os.path.join(tmp, 'state'), '--cancelled',
                 'true' if cancelled else 'false', '--run-id', run_id, '--run-attempt', '1'])
        p = os.path.join(tmp, 'state', 'deploy-state.json')
        return json.load(io.open(p, encoding='utf-8')) if os.path.exists(p) else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ----------------------------------------------------------------------------- K mocked sleeper
def ca_inputs():
    return dict(github_environment='env', routing_result='PROCEED', environment_tier='dev',
                resource_group='rg-a', containerapp_name='web', acr_login_server=W.REG,
                image_repository=W.REPO, image_digest=W.NEW, cloud='commercial', health_path='/health',
                health_retries=2, health_interval_seconds=0, rollback_on_failure=True, version_metadata='',
                deploy_timeout_minutes=90)


def kill_point(doc, inputs, sleeps):
    """-> the step the bound kills, or None. `sleeps`: {step name: simulated minutes}; others take 1."""
    bound = resolve_timeout(D.job(doc)['timeout-minutes'], inputs['deploy_timeout_minutes'])
    spent = 0
    for s in D.steps(doc):
        spent += sleeps.get(s.get('name'), 1 if 'run' in s else 0)
        if spent > bound:
            return s.get('name'), bound
    return None, bound


DEPLOY_STEP = 'Deploy by digest'
HEALTH_STEP = 'Verify the intended digest is loaded and healthy (before traffic moves)'


def sleeper_run(doc, sleeps, state_faults=None):
    inputs = ca_inputs()
    killed, bound = kill_point(doc, inputs, sleeps)
    faults = dict(state_faults or {})
    if killed == DEPLOY_STEP:
        faults['apply_then_fail'] = ['containerapp update']   # the kill lands inside the mutating call
    res, _final, _calls = W.run_world(D.CONTAINERAPP, inputs, W.containerapp_state(**faults), cancel_after=killed)
    return killed, bound, res


def section_k(doc):
    fails = []
    # K1 positive: everything inside the bound.
    killed, bound, res = sleeper_run(doc, {DEPLOY_STEP: 5, HEALTH_STEP: 3})
    out = (res['evidence'].get('outcome.json') or {}).get('deployment_outcome')
    st = record_from(res['evidence'], cancelled=bool(killed))
    rc, got, _why = run_check(st)
    print('  K1 inside the bound (%s min)      killed=%s outcome=%s owed=%s next=%s'
          % (bound, killed, out, st and st['reconciliation_required'], got))
    if killed or out != 'DEPLOY_HEALTHY' or not st or st['reconciliation_required'] or got != DI.CLEAR or rc:
        fails.append('K1: a deploy inside its bound was not healthy and clear (%s, %s, %s)' % (killed, out, got))
    # K2 negative: the health verification stalls past the bound, after the mutation.
    killed, bound, res = sleeper_run(doc, {DEPLOY_STEP: 5, HEALTH_STEP: 200})
    out = (res['evidence'].get('outcome.json') or {}).get('deployment_outcome')
    st = record_from(res['evidence'], cancelled=bool(killed))
    rc, got, why = run_check(st)
    rc_w, got_w, _ = run_check(st, reconciled='999')
    rc_h, got_h, _ = run_check(st, reconciled='4242')
    print('  K2 killed after the mutation       killed=%s outcome=%s reconciliation=%s next=%s wrong-id=%s right-id=%s'
          % (killed and killed[:22], out, st and st['reconciliation'], got, got_w, got_h))
    if killed != HEALTH_STEP or out != 'STATUS_UNTRUSTED':
        fails.append('K2: the kill after the mutation was not STATUS_UNTRUSTED (%s at %s)' % (out, killed))
    if not st or st.get('reconciliation') != DI.REQUIRED or not st.get('interrupted'):
        fails.append('K2: the record of the killed run does not name %s' % DI.REQUIRED)
    if got != DI.REQUIRED or rc != 1 or '4242' not in why:
        fails.append('K2: the next run was not refused naming the interrupted run (%s: %s)' % (got, why))
    if got_w != DI.REQUIRED or rc_w != 1:
        fails.append('K2: a wrong reconciled run id let the next run proceed (%s)' % got_w)
    if got_h != DI.by_hand or rc_h != 0:
        fails.append('K2: naming the reconciled run did not proceed as %s (%s)' % (DI.by_hand, got_h))
    # K3 negative: the mutating call itself stalls past the bound.
    killed, bound, res = sleeper_run(doc, {DEPLOY_STEP: 200})
    out = (res['evidence'].get('outcome.json') or {}).get('deployment_outcome')
    st = record_from(res['evidence'], cancelled=bool(killed))
    rc, got, _ = run_check(st)
    print('  K3 killed inside the mutating call killed=%s outcome=%s next=%s' % (killed, out, got))
    if killed != DEPLOY_STEP or out != 'PARTIAL_APPLY' or not st or st.get('reconciliation') != DI.REQUIRED \
            or got != DI.REQUIRED:
        fails.append('K3: a kill inside the mutating call was not PARTIAL_APPLY with reconciliation owed '
                     '(%s, %s)' % (out, got))
    # K4: killed before login -- nothing touched, nothing recorded, the previous state stands.
    killed, bound, res = sleeper_run(doc, {'Gate verdict (refuse before login)': 200})
    st = record_from(res['evidence'], cancelled=bool(killed))
    print('  K4 killed before login             killed=%s state written=%s' % (killed and killed[:22], st is not None))
    if st is not None:
        fails.append('K4: a run that never reached the target wrote a state that would mask the previous one')
    return fails


# ----------------------------------------------------------------------------- B bound, incomplete
def section_b():
    fails = []
    for timeout, period, dast, want in (('20', '0', 'false', DI.time_bound), ('400', '0', 'false', DI.time_bound),
                                        ('60', '240', 'false', DI.time_bound), ('90', '15', 'true', DI.CLEAR),
                                        ('abc', '0', 'false', DI.time_bound)):
        rc, got, why = run_check(None, timeout=timeout, period=period, dast=dast)
        print('  B  bound %-4s period %-4s dast %-5s -> %s' % (timeout, period, dast, got))
        if got != want or (rc == 0) != (want == DI.CLEAR):
            fails.append('B: bound %s/%s/%s decided %s, wanted %s' % (timeout, period, dast, got, want))
    rc, got, _ = run_check(None, api_url='file:///nonexistent-kit-api-root')
    print('  B  unreadable state                -> %s' % got)
    if got != DI.INCOMPLETE or rc != 1:
        fails.append('B: an unreadable state was %s, not %s' % (got, DI.INCOMPLETE))
    return fails


# ----------------------------------------------------------------------------- G composite glue
def section_g():
    fails = []
    bash, why = D.bash()
    if not bash:
        return ['G: no bash (%s)' % why]
    act = D.load(ACTION)
    steps = {s['id']: s for s in act['runs']['steps'] if s.get('id')}
    tmp = tempfile.mkdtemp(prefix='kreq717-glue-')
    try:
        api = api_with_state(os.path.join(tmp, 'api'), {'kind': 'kit-deploy-state', 'run_id': '77',
                                                         'reconciliation_required': True, 'deployment_outcome':
                                                         'STATUS_UNTRUSTED', 'changed': [], 'evidence_artifact': 'x'})
        env = {'GITHUB_ACTION_PATH': os.path.dirname(ACTION), 'GITHUB_REPOSITORY': 'o/r', 'GITHUB_API_URL': api,
               'DEPLOY_ENVIRONMENT': 'env', 'RESOURCE_GROUP': 'rg-a', 'I_TARGET': 'web', 'I_TIMEOUT': '90',
               'I_PERIOD': '15', 'I_DAST': 'false', 'I_RECONCILED': '', 'RUNNER_TEMP': tmp}
        rc, outs, log, _ = D.run_script(bash, steps['c']['run'], env)
        print('  G  composite check                 rc=%s deploy_interruption=%s' % (rc, outs.get('deploy_interruption')))
        if rc != 1 or outs.get('deploy_interruption') != DI.REQUIRED:
            fails.append('G: the composite check did not refuse with %s (rc %s): %s' % (DI.REQUIRED, rc, log[-400:]))
        ev = os.path.join(tmp, 'deploy-evidence')
        io.open(os.path.join(ev, 'snapshot.json'), 'w').write('{}')
        io.open(os.path.join(ev, 'manifest.json'), 'w').write(json.dumps({'entries': [{'action': 'CREATED', 'object': 'r'}]}))
        rc, outs, log, _ = D.run_script(bash, steps['r']['run'], dict(env, I_CANCELLED='true', GITHUB_RUN_ID='88'))
        print('  G  composite record                rc=%s reconciliation=%s' % (rc, outs.get('reconciliation')))
        if rc != 0 or outs.get('reconciliation') != DI.REQUIRED or outs.get('state_name') != DI.state_name('env', 'rg-a', 'web'):
            fails.append('G: the composite record did not name %s for a cancelled run with no outcome: %s'
                         % (DI.REQUIRED, log[-400:]))
        # op=bound (the build reusable): the bound alone, named by the job's own input; no state read.
        for t, want_rc in (('400', 1), ('90', 0)):
            rc, outs, log, _ = D.run_script(bash, steps['c']['run'], dict(
                env, I_OP='bound', I_BOUND_NAME='build_timeout_minutes', I_TIMEOUT=t, I_PERIOD='0',
                GITHUB_API_URL='file:///nonexistent-kit-api-root'))
            want = DI.time_bound if want_rc else DI.CLEAR
            print('  G  composite bound %-4s           rc=%s deploy_interruption=%s' % (t, rc, outs.get('deploy_interruption')))
            if rc != want_rc or outs.get('deploy_interruption') != want or (want_rc and 'build_timeout_minutes' not in log):
                fails.append('G: the composite bound-only check of %s decided %s (rc %s): %s'
                             % (t, outs.get('deploy_interruption'), rc, log[-400:]))
        # kind=registry-push: the build evidence, unpromotable when the push never applied.
        bev = os.path.join(tmp, 'build-evidence')
        os.makedirs(bev)
        io.open(os.path.join(bev, 'snapshot.json'), 'w').write('{}')
        io.open(os.path.join(bev, 'manifest.json'), 'w').write(json.dumps(
            {'status': 'planned', 'entries': [{'action': 'MODIFIED', 'object': 'r/a:t'}]}))
        rc, outs, log, _ = D.run_script(bash, steps['r']['run'], dict(
            env, I_CANCELLED='true', GITHUB_RUN_ID='89', I_KIND='registry-push', I_IDENTITY='IDENTITY_UNVERIFIED'))
        print('  G  composite record registry-push  rc=%s reconciliation=%s' % (rc, outs.get('reconciliation')))
        if rc != 0 or outs.get('reconciliation') != DI.unpromotable or \
                not os.path.exists(os.path.join(bev, 'deploy-state.json')):
            fails.append('G: the composite registry-push record did not name %s in the build evidence: %s'
                         % (DI.unpromotable, log[-400:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return fails


# ----------------------------------------------------------------------------- S2 the other mutating jobs
ROLLBACK_WF = 'reusable-rollback-sequence.yml'
BUILD_WF = 'reusable-build-docker.yml'
ACCEPT_WF = 'live-deploy-acceptance.yml'
CANCELLED = "${{ job.status == 'cancelled' }}"


def _clamp_fails(job, label, name, fallback):
    t = job.get('timeout-minutes')
    if t is None:
        return ['%s: the mutating job has no timeout-minutes (KREQ-717)' % label]
    fails = []
    for given, want in ((fallback, fallback), (120, 120), (30, 30), (360, 360), (0, fallback), (29, fallback),
                        (361, fallback), (100000, fallback)):
        got = resolve_timeout(t, given, name)
        if got != want:
            fails.append('%s: timeout-minutes resolves to %r for %s=%s, wanted %s (governed, never unbounded)'
                         % (label, got, name, given, want))
    return fails


def structure_rollback(doc):
    label = ROLLBACK_WF
    job = doc['jobs']['rollback']
    fails = _clamp_fails(job, label, 'rollback_timeout_minutes', 180)
    steps = job.get('steps') or []
    names = [s.get('name') for s in steps]
    ids = [s.get('id') for s in steps]
    login = names.index('Azure login (OIDC)') if 'Azure login (OIDC)' in names else -1
    seq = ids.index('sequence') if 'sequence' in ids else -1
    keep = next((i for i, n in enumerate(names) if str(n).startswith('Keep the sequence record')), -1)
    chk = ids.index('interruption') if 'interruption' in ids else -1
    if not 0 <= chk < login or steps[chk].get('if') is not None or \
            'deploy_interruption.py" check' not in str(steps[chk].get('run')) or \
            '--bound-name rollback_timeout_minutes' not in str(steps[chk].get('run')) or \
            (steps[chk].get('env') or {}).get('I_TIMEOUT') != '${{ inputs.rollback_timeout_minutes }}':
        fails.append('%s: the interruption check is not one unconditional step before Azure login that checks '
                     'the job\'s own rollback_timeout_minutes' % label)
    rec = ids.index('interruption_record') if 'interruption_record' in ids else -1
    if not seq < rec < keep or 'always()' not in str(steps[rec].get('if')) or \
            (steps[rec].get('env') or {}).get('I_CANCELLED') != CANCELLED or \
            '--kind rollback-sequence' not in str(steps[rec].get('run')):
        fails.append('%s: the sequence state record is not an always() step after the sequence, before the kept '
                     'record, carrying the cancelled status (kind rollback-sequence)' % label)
    up = [s for s in steps if 'upload-artifact' in str(s.get('uses')) and
          'steps.interruption_record.outputs.state_name' in str((s.get('with') or {}).get('name'))]
    if len(up) != 1 or 'always()' not in str(up[0].get('if')):
        fails.append('%s: the sequence state is not uploaded under the target\'s state name on every path' % label)
    return fails


def structure_build(doc):
    label = BUILD_WF
    job = doc['jobs']['build']
    fails = _clamp_fails(job, label, 'build_timeout_minutes', 90)
    steps = job.get('steps') or []
    names = [s.get('name') for s in steps]
    first = steps[0] if steps else {}
    w = first.get('with') or {}
    if first.get('uses') != USES or w.get('op') != 'bound' or first.get('if') is not None or \
            w.get('timeout-minutes') != '${{ inputs.build_timeout_minutes }}' or w.get('bound-name') != 'build_timeout_minutes':
        fails.append('%s: the first step is not the unconditional time-bound check of build_timeout_minutes' % label)
    rec = [(i, s) for i, s in enumerate(steps) if s.get('uses') == USES and (s.get('with') or {}).get('op') == 'record']
    cls = names.index('Classify what the SBOM is evidence of') if 'Classify what the SBOM is evidence of' in names else -1
    keep = names.index('Keep the run record (build evidence)') if 'Keep the run record (build evidence)' in names else -1
    if len(rec) != 1 or not cls < rec[0][0] < keep:
        fails.append('%s: the registry-push record is not one step between the identity class and the kept evidence'
                     % label)
    else:
        r = rec[0][1]
        rw = r.get('with') or {}
        if 'always()' not in str(r.get('if')) or rw.get('cancelled') != CANCELLED or rw.get('kind') != 'registry-push' \
                or rw.get('identity') != '${{ steps.provenance.outputs.class }}':
            fails.append('%s: the registry-push record does not run on a cancelled job with its identity class' % label)
    att = str((doc['jobs'].get('attest') or {}).get('if'))
    if "needs.build.outputs.artifact_identity == 'REGISTRY_IDENTITY_PROVEN'" not in att or \
            any(f in att for f in ('always()', 'cancelled()', 'failure()')):
        fails.append('%s: the attest job could sign after a cancelled build or an unproven identity (if: %s)'
                     % (label, att))
    return fails


def structure_acceptance(doc):
    label = ACCEPT_WF
    fails = []
    if 'timeout_minutes' not in ((doc.get('on') or doc.get(True) or {}).get('workflow_dispatch') or {}).get('inputs', {}):
        fails.append('%s: no timeout_minutes dispatch input' % label)
    want = {'containerapp': 'deploy_timeout_minutes', 'appservice': 'deploy_timeout_minutes',
            'build': 'build_timeout_minutes'}
    for job, key in want.items():
        if (doc['jobs'][job].get('with') or {}).get(key) != '${{ fromJSON(inputs.timeout_minutes) }}':
            fails.append('%s: job %s does not hand timeout_minutes to the reusable as %s' % (label, job, key))
    for name, job in doc['jobs'].items():
        if 'uses' not in job and job.get('timeout-minutes') is None:
            fails.append('%s: job %s runs unbounded' % (label, name))
    return fails


def section_s2(docs):
    fails = []
    for label, fn in ((ROLLBACK_WF, structure_rollback), (BUILD_WF, structure_build), (ACCEPT_WF, structure_acceptance)):
        f = fn(docs[label])
        print('  S2 %-36s %s' % (label, 'ok' if not f else 'FAIL'))
        fails += f
    return fails


# ----------------------------------------------------------------------------- R the sequence engine, killed
def _kill_tree(p):
    if os.name == 'nt':
        import subprocess
        subprocess.run(['taskkill', '/T', '/F', '/PID', str(p.pid)], capture_output=True)
    else:
        import signal
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            p.kill()
    try:
        p.wait(timeout=60)
    except Exception:  # noqa: BLE001
        p.kill()


def record_rollback(work, record_path, cancelled=True, run_id='5151'):
    tmp = tempfile.mkdtemp(prefix='kreq717-rb-record-')
    try:
        DI.main(['record', '--kind', 'rollback-sequence', '--environment', 'env', '--resource-group', 'rg-a',
                 '--name', 'web', '--evidence-dir', work, '--sequence-record', record_path,
                 '--out-dir', os.path.join(tmp, 'state'), '--cancelled', 'true' if cancelled else 'false',
                 '--run-id', run_id, '--run-attempt', '1'])
        p = os.path.join(tmp, 'state', 'deploy-state.json')
        return json.load(io.open(p, encoding='utf-8')) if os.path.exists(p) else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def killed_sequence(world, steps):
    """Run the engine as the reusable does and kill its process tree once step 1's test period is
    running (the e2e command has started). -> (work dir, record path, mutating calls, killed)."""
    import subprocess
    import time
    import prove_rollback_sequence as PRS
    seq = os.path.join(world.dir, 'kill-sequence.json')
    io.open(seq, 'w', encoding='utf-8').write(json.dumps({'sequence_id': 'killed', 'steps': steps}))
    marker = os.path.join(world.dir, 'e2e-started')
    hang = os.path.join(world.dir, 'hang.py')
    io.open(hang, 'w', encoding='utf-8').write(
        'import io, time\nio.open(%r, "w").close()\ntime.sleep(45)\n' % marker)
    work, out = os.path.join(world.dir, 'kill-work'), os.path.join(world.dir, 'kill-record.json')
    env = dict(os.environ)
    env.update(world.env())
    env.update({'PATH': world.bin + os.pathsep + env.get('PATH', ''), 'health_retries'.upper(): '1',
                'health_interval_seconds'.upper(): '0'})
    for k in ('GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY'):
        env.pop(k, None)
    io.open(world.log, 'w').close()
    argv = [sys.executable, PRS.ENGINE, 'run', '--sequence', seq, '--evidence-root', world.evidence,
            '--work', work, '--out', out, '--e2e-command', '"%s" "%s"' % (sys.executable, hang),
            '--e2e-timeout-seconds', '120', '--test-period-seconds', '1', '--locked-target', 'rg-a/web']
    p = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=(os.name != 'nt'))
    killed = False
    try:
        for _ in range(240):             # bounded: at most 120 s
            if os.path.exists(marker):
                break
            if p.poll() is not None:
                break
            time.sleep(0.5)
        killed = p.poll() is None and os.path.exists(marker)
    finally:
        _kill_tree(p)
    return work, out, PRS.mutating(world.calls()), killed


def section_r():
    fails = []
    try:
        import prove_rollback_sequence as PRS
        base = PRS.World(W.containerapp_state(mode='Multiple'))
    except Exception as exc:  # noqa: BLE001
        return ['R: the stub world could not be built: %s' % exc]
    worlds = [base]
    try:
        for run_id, digest in getattr(PRS, 'ca_runs'.upper())[:2]:
            res = base.deploy(D.CONTAINERAPP, PRS.ca_inputs(digest), run_id)
            if res['failed']:
                return ['R: the healthy deploy of run %s failed; nothing can be proven' % run_id]
        steps = [PRS.step(r) for r, _d in getattr(PRS, 'ca_runs'.upper())[:2]]
        # R1 positive: the sequence completes.
        w = base.clone()
        worlds.append(w)
        rc, r, _e2e, _calls = w.sequence(steps, lock='rg-a/web')
        st = record_rollback(os.path.join(w.dir, 'work'), os.path.join(w.dir, 'record.json'), cancelled=False)
        rc2, got, _ = run_check(st)
        print('  R1 sequence completes            result=%s owed=%s next=%s'
              % (r.get('result'), st and st['reconciliation_required'], got))
        if r.get('result') != 'ROLLBACK_SEQUENCE_VERIFIED' or not st or st['reconciliation_required'] or got != DI.CLEAR:
            fails.append('R1: a completed sequence was not verified and clear (%s, %s)' % (r.get('result'), got))
        # R2 negative: killed inside step 1's test period, after a live reversal.
        w = base.clone()
        worlds.append(w)
        work, out, muts, killed = killed_sequence(w, steps)
        st = record_rollback(work, out, cancelled=True)
        rc, got, why = run_check(st)
        rc_d, got_d, _ = run_check(st)   # the deploy reusables read the SAME artifact name
        rc_h, got_h, _ = run_check(st, reconciled='5151')
        same = DI.state_name('env', 'rg-a', 'web') == 'kit-deploy-state-' + DI.RH.target_key('env', 'rg-a', 'web')
        print('  R2 killed mid-sequence            killed=%s live changes=%d record=%s outcome=%s next=%s by-hand=%s'
              % (killed, len(muts), os.path.exists(out), st and st['deployment_outcome'], got, got_h))
        if not killed or not muts or os.path.exists(out):
            fails.append('R2: the kill did not land mid-sequence after a live reversal (killed=%s, %d mutating '
                         'calls, record written=%s) -- the case does not reach the guard' % (killed, len(muts),
                                                                                             os.path.exists(out)))
        if not st or st['deployment_outcome'] != 'STATUS_UNTRUSTED' or st.get('reconciliation') != DI.REQUIRED:
            fails.append('R2: a sequence killed after a reversal was not STATUS_UNTRUSTED with %s (%s)'
                         % (DI.REQUIRED, st and st['deployment_outcome']))
        if got != DI.REQUIRED or rc != 1 or '5151' not in why or got_d != DI.REQUIRED or not same:
            fails.append('R2: the next run of the target was not refused naming the killed sequence (%s)' % got)
        if got_h != DI.by_hand or rc_h != 0:
            fails.append('R2: naming the reconciled sequence did not proceed (%s)' % got_h)
        # R3: the same kill one write earlier -- the newest step's reversal never confirmed.
        if st:
            newest = sorted(d for d in os.listdir(work) if d.startswith('step-'))[-1]
            rv = os.path.join(work, newest, 'deploy-evidence', 'reversal.json')
            if os.path.exists(rv):
                os.remove(rv)
            st3 = record_rollback(work, out, cancelled=True)
            print('  R3 killed inside the reversal     outcome=%s reconciliation=%s'
                  % (st3 and st3['deployment_outcome'], st3 and st3['reconciliation']))
            if not st3 or st3['deployment_outcome'] != 'PARTIAL_APPLY' or st3.get('reconciliation') != DI.REQUIRED:
                fails.append('R3: a kill inside a reversal was not PARTIAL_APPLY with reconciliation owed')
        # R4: killed before any step.
        empty = os.path.join(w.dir, 'empty-work')
        os.makedirs(empty)
        st4 = record_rollback(empty, os.path.join(w.dir, 'no-record.json'))
        print('  R4 killed before any step         state written=%s' % (st4 is not None))
        if st4 is not None:
            fails.append('R4: a sequence that reached no step wrote a state that would mask the previous one')
    finally:
        for x in worlds:
            x.close()
    # The sequence's bound: 30 + steps x the test period.
    for timeout, period, want in (('60', '45', DI.time_bound), ('180', '45', DI.CLEAR), ('360', '720', DI.time_bound)):
        rc, got, why = run_check(None, timeout=timeout, period=period, bound_name='rollback_timeout_minutes')
        print('  R  bound %-4s steps x period %-4s -> %s' % (timeout, period, got))
        if got != want or (want != DI.CLEAR and 'rollback_timeout_minutes' not in why):
            fails.append('R: rollback bound %s/%s decided %s, wanted %s naming rollback_timeout_minutes'
                         % (timeout, period, got, want))
    return fails


# ----------------------------------------------------------------------------- P the registry push
PUSH_DOCKER = r'''
case "$1 $2" in
  "buildx imagetools") printf '{"digest":"%s","mediaType":"application/vnd.oci.image.manifest.v1+json"}\n' "$SHIM_PRIOR" ;;
  "push "*) echo "push $2" >> "$SHIM_LOG"; [ "$SHIM_PUSH" = killed ] && exit 137; exit 0 ;;
  "image inspect") printf '%s@%s\n' "$SHIM_REPO" "$SHIM_PUSHED" ;;
  *) echo "docker shim: unhandled $*" >&2; exit 64 ;;
esac
'''
P_REPO = 'registry.example/app'
P_IMAGE = P_REPO + ':t'


def push_world(tmp, name, push_mode, run_steps=True):
    import _step_harness as H
    bash, why = H.usable_bash()
    ws = os.path.join(tmp, name)
    os.makedirs(ws)
    shims = os.path.join(tmp, 'shim')
    H.shim(shims, 'docker', PUSH_DOCKER)
    log = os.path.join(ws, 'pushes.log')
    io.open(log, 'w').close()
    env = {'SHIM_PRIOR': 'sha256:' + '3' * 64, 'SHIM_PUSHED': 'sha256:' + '7' * 64, 'SHIM_REPO': P_REPO,
           'SHIM_LOG': log, 'SHIM_PUSH': push_mode, 'REPO': P_REPO, 'IMAGE': P_IMAGE, 'RUNNER_TEMP': ws,
           'MSYS2_ENV_CONV_EXCL': '*', 'MSYS_NO_PATHCONV': '1'}
    pushed = False
    if run_steps:
        wf = '.github/workflows/' + BUILD_WF
        for sid in ('push_capability', 'push'):
            H.run(bash, H.step(wf, 'build', sid), {'inputs.push': 'true'}, ws, shims, env)
        pushed = bool(io.open(log, encoding='utf-8').read().strip())
    return os.path.join(ws, 'build-evidence'), pushed


def record_push(evidence, identity, cancelled):
    tmp = tempfile.mkdtemp(prefix='kreq717-push-record-')
    try:
        DI.main(['record', '--kind', 'registry-push', '--environment', 'env', '--resource-group', 'registry.example',
                 '--name', P_IMAGE, '--evidence-dir', evidence, '--out-dir', os.path.join(tmp, 'state'),
                 '--identity', identity, '--cancelled', 'true' if cancelled else 'false', '--run-id', '66'])
        p = os.path.join(tmp, 'state', 'deploy-state.json')
        return json.load(io.open(p, encoding='utf-8')) if os.path.exists(p) else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def judge_promotion(attestation, path='normal'):
    import datetime
    import promotion as PR
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    d = 'sha256:' + '7' * 64
    # The fields a deploy writes (KDEC-070 re-evaluates this bound evidence at a prod promotion).
    rec = {'artifact': {'digest': d, 'sbom_sha256': 'e' * 64,
                        'version_metadata': json.dumps({'built_at': PR.iso(now)})}, 'state': PR.VERIFIED,
           'environment': {'name': 'test', 'tier': 'test', 'adapter': 'containerapp',
                           'target_resource_id': '/subscriptions/s/resourceGroups/rg-a/providers/Microsoft.App/containerApps/web'},
           'provenance': {'source_ref': 'refs/heads/main', 'gate_routing_result': 'PROCEED',
                          'attestation_outcome': 'ATTESTATION_VERIFIED'},
           'validity': {'verified_at': PR.iso(now)},
           'run': {'id': '1'}}
    ctx = {'digest': d, 'required_predecessor': 'test', 'source_environment': 'test', 'source': rec,
           'destination_tier': 'prod', 'expected_target': rec['environment']['target_resource_id'],
           'history': [], 'revocations': [], 'rescan': {'state': 'COMPLETE', 'critical': [], 'high': []},
           'kev': {'state': 'AVAILABLE', 'blocking': []}, 'attestation': attestation, 'release_path': path,
           'exception': {'exception_ref': 'EX-1'}, 'now': now}
    return PR.judge(ctx)


def section_p():
    import _step_harness as H
    bash, why = H.usable_bash()
    if not bash or not shutil.which('jq'):
        return ['P: bash and jq are required to run the shipped push steps (%s)' % (why or 'no jq')]
    fails = []
    tmp = tempfile.mkdtemp(prefix='kreq717-push-')
    try:
        ev, pushed = push_world(tmp, 'p1', 'ok')
        st = record_push(ev, 'REGISTRY_IDENTITY_PROVEN', False)
        print('  P1 pushed, proven                 outcome=%s reconciliation=%s'
              % (st and st['deployment_outcome'], st and st['reconciliation']))
        if not pushed or not st or st['deployment_outcome'] != 'REGISTRY_IDENTITY_PROVEN' or st['reconciliation']:
            fails.append('P1: a proven push was not recorded clean (%s)' % (st and st['reconciliation']))
        ev, pushed = push_world(tmp, 'p2', 'killed')
        man = json.load(io.open(os.path.join(ev, 'manifest.json'), encoding='utf-8'))
        st = record_push(ev, 'IDENTITY_UNVERIFIED', True)
        print('  P2 killed inside the push         manifest=%s outcome=%s reconciliation=%s'
              % (man.get('status'), st and st['deployment_outcome'], st and st['reconciliation']))
        if not pushed or man.get('status') != 'planned':
            fails.append('P2: the kill did not land inside the push (pushed=%s, manifest %s)' % (pushed, man.get('status')))
        if not st or st['deployment_outcome'] != 'PARTIAL_APPLY' or st['reconciliation'] != DI.unpromotable \
                or st.get('promotable') is not False:
            fails.append('P2: a push killed mid-way was not PARTIAL_APPLY and %s' % DI.unpromotable)
        ev, _ = push_world(tmp, 'p3', 'ok')
        st = record_push(ev, 'IDENTITY_UNVERIFIED', True)
        print('  P3 pushed, identity never proven  outcome=%s reconciliation=%s'
              % (st and st['deployment_outcome'], st and st['reconciliation']))
        if not st or st['deployment_outcome'] != 'STATUS_UNTRUSTED' or st['reconciliation'] != DI.unpromotable:
            fails.append('P3: an unproven push was not STATUS_UNTRUSTED and %s' % DI.unpromotable)
        ev, _ = push_world(tmp, 'p4', 'ok')
        st = record_push(ev, 'REGISTRY_IDENTITY_PROVEN', True)
        print('  P4 proven, then cancelled         reconciliation=%s' % (st and st['reconciliation']))
        if not st or st['reconciliation'] != DI.unpromotable:
            fails.append('P4: a proven push whose job was cancelled (never attested) was not %s' % DI.unpromotable)
        ev, _ = push_world(tmp, 'p5', 'ok', run_steps=False)
        st = record_push(ev, 'NOT_ESTABLISHED', True)
        print('  P5 killed before the capability   state written=%s' % (st is not None))
        if st is not None:
            fails.append('P5: a run that never reached the registry wrote a push state')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ok = judge_promotion('ATTESTATION_VERIFIED')
    absent = judge_promotion('ATTESTATION_ABSENT')
    glass = judge_promotion('ATTESTATION_ABSENT', path='break-glass')
    print('  P  promotion: verified=%s absent=%s absent+break-glass=%s'
          % (ok['verdict'], absent['verdict'], glass['verdict']))
    if ok['verdict'] != 'PROMOTION_ALLOWED':
        fails.append('P: the promotion fixture is not allowed with a verified attestation (%s) -- the negatives '
                     'would not reach the signature guard' % ok['refusals'])
    for label, j in (('absent', absent), ('break-glass', glass)):
        if j['verdict'] != 'PROMOTION_REFUSED_SIGNATURE':
            fails.append('P: an unattested digest (%s) was not refused PROMOTION_REFUSED_SIGNATURE (%s)'
                         % (label, j['verdict']))
    return fails


# ----------------------------------------------------------------------------- M mutants
def mutants(docs, ca_doc):
    caught = []
    name = 'reusable-deploy-containerapp.yml'
    m = copy.deepcopy(docs[name])
    D.job(m).pop('timeout-minutes', None)
    caught.append(('timeout removed', bool(structure(m, name))))
    m = copy.deepcopy(docs[name])
    D.job(m)['timeout-minutes'] = '${{ inputs.deploy_timeout_minutes }}'
    caught.append(('clamp removed', bool(structure(m, name))))
    m = copy.deepcopy(docs[name])
    for s in D.steps(m):
        if s.get('uses') == USES and (s.get('with') or {}).get('op') == 'record':
            s.pop('if', None)
    caught.append(('record not always()', bool(structure(m, name))))
    saved = DI.needs_reconciliation
    DI.needs_reconciliation = lambda *a: False
    try:
        caught.append(('reconciliation skipped', bool(section_k(ca_doc))))
    finally:
        DI.needs_reconciliation = saved
    saved = DI.decide

    def any_id(state, reconciled_run):
        o, w = saved(state, reconciled_run)
        return (DI.by_hand, w) if o == DI.REQUIRED and reconciled_run else (o, w)
    DI.decide = any_id
    try:
        caught.append(('any run id accepted', bool(section_k(ca_doc))))
    finally:
        DI.decide = saved
    saved = DI.bound_problem
    DI.bound_problem = lambda *a: None
    try:
        caught.append(('bound unchecked', bool(section_b())))
    finally:
        DI.bound_problem = saved
    return caught


def mutants_m2(docs):
    caught = []
    m = copy.deepcopy(docs[ROLLBACK_WF])
    m['jobs']['rollback'].pop('timeout-minutes', None)
    caught.append(('rollback timeout removed', bool(structure_rollback(m))))
    m = copy.deepcopy(docs[ROLLBACK_WF])
    m['jobs']['rollback']['timeout-minutes'] = '${{ inputs.rollback_timeout_minutes }}'
    caught.append(('rollback clamp removed', bool(structure_rollback(m))))
    m = copy.deepcopy(docs[ROLLBACK_WF])
    for s in m['jobs']['rollback']['steps']:
        if s.get('id') == 'interruption_record':
            s.pop('if', None)
    caught.append(('rollback record not always()', bool(structure_rollback(m))))
    m = copy.deepcopy(docs[BUILD_WF])
    m['jobs']['build'].pop('timeout-minutes', None)
    caught.append(('build timeout removed', bool(structure_build(m))))
    m = copy.deepcopy(docs[BUILD_WF])
    m['jobs']['attest']['if'] = 'always() && ' + str(m['jobs']['attest']['if'])
    caught.append(('attest after a cancelled build', bool(structure_build(m))))
    saved = DI.build_rollback_state

    def not_owed(*a, **k):
        st = saved(*a, **k)
        if st:
            st.update(reconciliation_required=False, reconciliation=None)
        return st
    DI.build_rollback_state = not_owed
    try:
        caught.append(('killed sequence owes nothing', bool(section_r())))
    finally:
        DI.build_rollback_state = saved
    saved_p = DI.build_registry_state

    def promotable(*a, **k):
        st = saved_p(*a, **k)
        if st:
            st.update(reconciliation=None, promotable=True)
        return st
    DI.build_registry_state = promotable
    try:
        caught.append(('killed push promotable', bool(section_p())))
    finally:
        DI.build_registry_state = saved_p
    import promotion as PR
    bgo = 'break_glass_overrides'.upper()   # the gate's constant, by name
    saved_o = getattr(PR, bgo)
    setattr(PR, bgo, saved_o + ('PROMOTION_REFUSED_SIGNATURE',))
    try:
        caught.append(('break-glass lifts signature', bool(section_p())))
    finally:
        setattr(PR, bgo, saved_o)
    return caught


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    docs = {n: D.load(os.path.join(ROOT, '.github', 'workflows', n)) for n in WORKFLOWS}
    fails = section_s(docs)
    fails += section_k(docs['reusable-deploy-containerapp.yml'])
    fails += section_b()
    fails += section_g()
    others = {n: D.load(os.path.join(ROOT, '.github', 'workflows', n)) for n in (ROLLBACK_WF, BUILD_WF, ACCEPT_WF)}
    fails += section_s2(others)
    fails += section_r()
    fails += section_p()
    print('  -- mutants (each must be caught) --')
    for label, was_caught in mutants(docs, docs['reusable-deploy-containerapp.yml']) + mutants_m2(others):
        print('  M  %-28s %s' % (label, 'caught' if was_caught else 'NOT CAUGHT'))
        if not was_caught:
            fails.append('M: the mutant "%s" passed every case' % label)
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: every mutating deploy job is bounded (30..360, clamped to 90, refused before login outside it); '
          'a kill mid-change is STATUS_UNTRUSTED or PARTIAL_APPLY, recorded as %s, and the next run is refused '
          'until the run is named; the rollback sequence and the build-and-push job are bounded the same way '
          '(a killed sequence owes reconciliation to the next deploy or sequence of its target; a killed push is '
          '%s and the promotion gate refuses it); every mutant is caught.' % (DI.REQUIRED, DI.unpromotable))
    return 0


if __name__ == '__main__':
    sys.exit(main())
