#!/usr/bin/env python3
"""Sequential rollback, tested end to end between every step -- proven against the stub cloud.
(KDEC-019 item 4, owner 2026-10-22; lane L-RB; scripts/rollback_sequence.py.)

WHY THIS EXISTS

    Owner, relaying a colleague: when several deployments must be rolled back and each can be --
    "because nothing else touched the resource and/or because the resource was shared but still
    able to be rolled back for that particular application or deployment" -- the rollbacks run in
    reverse order and "we should do end to end tests to make sure that between each rollback things
    still work." A step whose tests fail halts the sequence for a human decision.

HOW

    The deployments are REAL runs of the shipped deploy reusables (tests/_workflow_runner.py, every
    step in file order) against ONE stateful stub cloud (tests/_fake_az.py), each with its own run
    id, so their evidence -- snapshot, manifest, capability, outcome -- is what the deploys really
    write. They are deployed once; each scenario starts from a copy of that world. The sequence is
    then run by scripts/rollback_sequence.py as the reusable workflow runs it, with an end-to-end
    test command that reads the stub cloud the way a real test reads the application.

WHAT IT PROVES

    S1  three stacked deployments of one Container App, all eligible and healthy: reversed newest
        first, the e2e tests run after EACH step (3 times, in that order), every step
        ELIGIBLE_UNTOUCHED and ROLLBACK_STEP_VERIFIED, ROLLBACK_SEQUENCE_VERIFIED, the cloud back
        at the state before the first deployment; the e2e command never held the deploy
        identity's Azure session; the record validates against its schema
    S2  step 2 of 3 fails its e2e tests: ROLLBACK_SEQUENCE_HALTED_E2E_FAILED; step 3 is
        ROLLBACK_STEP_NOT_REACHED and its deployment is untouched; the tests ran exactly twice
    S3  an ineligible step (another actor re-stamped its revision): the sequence stops BEFORE it
        (ROLLBACK_REQUIRES_HUMAN_DECISION, P1), nothing of it or after it is touched
    S4  a shared resource whose app-owned part is intact (another actor's inactive revision on the
        app): ELIGIBLE_OWNED_PART_SEPARABLE, reversed and verified
    S5  no e2e command: ROLLBACK_SEQUENCE_REFUSED_NO_E2E before the first step, ZERO mutating calls
    S6  a partial rollback (the revision cannot be deactivated): ROLLBACK_PARTIAL halts the
        sequence (ROLLBACK_SEQUENCE_HALTED_ROLLBACK_UNVERIFIED); never verified, no e2e after it
    S7  a step declared forward-fix only: ROLLBACK_PROHIBITED, stopped before it
    S8  two resources of one release (App Service slot+swap, then a Container App): reversed newest
        first, both verified, App Service production back on its prior image
    S9  a sequence listed in the wrong order: the first step executed has later releases standing
        on it (P6), so the sequence stops before touching anything
    S10 the health probe fails after a verified reversal: ROLLBACK_SEQUENCE_HALTED_HEALTH_FAILED,
        the e2e tests are not run on it
    S11 the e2e tests hang: bounded, timed out, halted -- a hang is not a pass
    S12 a sequence naming evidence of another run: ROLLBACK_SEQUENCE_REFUSED_INPUT, nothing touched

    STUBBED, NOT LIVE. Whether Azure answers as the stub does is the hosted run, owed (risks R-04).

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _workflow_runner as W  # noqa: E402

ENGINE = os.path.join(ROOT, 'scripts', 'rollback_sequence.py')
D1, D2, D3 = ('sha256:' + c * 64 for c in '123')
CA_RUNS = (('101', D1), ('102', D2), ('103', D3))

# The application's end-to-end tests, as the stub cloud lets one be written: what the app's public
# name serves must answer, and must not be an image the scenario marks broken. It records every
# invocation, and the Azure config directory it was given, so the proof can count and inspect them.
E2E_FIXTURE = '''import io, json, os, sys, time
s = json.load(io.open(os.environ['fake_az_state'], encoding='utf-8'))
rec = {k: os.environ.get(k.upper(), '') for k in ('rollback_step', 'rollback_deployment',
       'rollback_app_url', 'rollback_steps_total', 'azure_config_dir')}
io.open(os.environ['e2e_log'], 'a', encoding='utf-8').write(json.dumps(rec) + '\\n')
if s.get('e2e_hangs'):
    time.sleep(30)
a = s.get('containerapp') or {}
serving = []
for t in a.get('traffic') or []:
    if (t.get('weight') or 0) > 0:
        n = a['latestRevisionName'] if t.get('latestRevision') else t.get('revisionName')
        serving.append(a['revisions'][n]['image'])
bad = [i for i in serving if i in (s.get('e2e_broken_images') or [])]
sys.exit(1 if bad or (a and not serving) else 0)
'''


def ca_inputs(digest):
    return dict(github_environment='env', routing_result='PROCEED', environment_tier='dev',
                resource_group='rg-a', containerapp_name='web', acr_login_server=W.REG,
                image_repository=W.REPO, image_digest=digest, cloud='commercial',
                health_path='/health', health_retries=1, health_interval_seconds=0,
                rollback_on_failure=True, version_metadata='')


def as_inputs(digest):
    return dict(github_environment='env', routing_result='PROCEED', environment_tier='dev',
                resource_group='rg-a', webapp_name='web', acr_login_server=W.REG,
                image_repository=W.REPO, image_digest=digest, cloud='commercial', slot='staging',
                swap_on_healthy=True, health_path='/health', health_retries=1,
                health_interval_seconds=0, version_metadata='', rollback_on_failure=True)


class World(object):
    """One stub cloud, its call log, the az/curl stand-ins, and an evidence root."""

    def __init__(self, state):
        self.dir = tempfile.mkdtemp(prefix='rollback-seq-')
        self.state = os.path.join(self.dir, 'state.json')
        self.log = os.path.join(self.dir, 'calls.jsonl')
        self.evidence = os.path.join(self.dir, 'evidence')
        os.makedirs(self.evidence)
        api = os.path.join(self.dir, 'api', 'repos', 'o', 'r', 'environments')
        os.makedirs(api)
        io.open(os.path.join(api, 'env'), 'w', encoding='utf-8').write(json.dumps(getattr(W, 'protected_environment'.upper())))
        self.write(state)
        io.open(self.log, 'w').close()
        self.bin = W.stub_bin(self.state, self.log)

    def write(self, state):
        io.open(self.state, 'w', encoding='utf-8').write(json.dumps(state))

    def read(self):
        return json.load(io.open(self.state, encoding='utf-8'))

    def env(self):
        return {'MSYS2_ENV_CONV_EXCL': '*', 'MSYS_NO_PATHCONV': '1', 'fake_az_state': self.state,
                'fake_az_log': self.log, 'AZURE_CONFIG_DIR': os.path.join(self.dir, 'deploy-azure-config'),
                'GITHUB_REPOSITORY': 'o/r',
                'GITHUB_API_URL': 'file:///' + os.path.join(self.dir, 'api').replace('\\', '/').lstrip('/')}

    def deploy(self, workflow, inputs, run_id):
        rt = tempfile.mkdtemp(prefix='runner-temp-', dir=self.dir)
        env = dict(self.env(), GITHUB_RUN_ID=run_id, GITHUB_RUN_ATTEMPT='1')
        res = W.run_job(workflow, inputs, path_prepend=self.bin, extra_env=env, workdir=rt)
        shutil.copytree(os.path.join(rt, 'deploy-evidence'),
                        os.path.join(self.evidence, 'deploy-evidence-%s-1' % run_id))
        return res

    def calls(self):
        return [json.loads(x) for x in io.open(self.log, encoding='utf-8') if x.strip()]

    def clone(self):
        other = copy.copy(self)
        other.dir = tempfile.mkdtemp(prefix='rollback-seq-')
        for name in ('evidence', 'api'):
            shutil.copytree(os.path.join(self.dir, name), os.path.join(other.dir, name))
        other.state = os.path.join(other.dir, 'state.json')
        other.log = os.path.join(other.dir, 'calls.jsonl')
        other.evidence = os.path.join(other.dir, 'evidence')
        shutil.copyfile(self.state, other.state)
        io.open(other.log, 'w').close()
        other.bin = W.stub_bin(other.state, other.log)
        return other

    def sequence(self, steps, e2e=True, timeout=120, extra_state=None):
        """Run the engine. -> (rc, record, e2e invocations, az calls made by the sequence)."""
        if extra_state:
            s = self.read()
            extra_state(s)
            self.write(s)
        io.open(self.log, 'w').close()
        seq = os.path.join(self.dir, 'sequence.json')
        io.open(seq, 'w', encoding='utf-8').write(json.dumps({'sequence_id': 'release-x', 'steps': steps}))
        fixture = os.path.join(self.dir, 'e2e_fixture.py')
        io.open(fixture, 'w', encoding='utf-8').write(E2E_FIXTURE)
        e2e_log = os.path.join(self.dir, 'e2e.jsonl')
        io.open(e2e_log, 'w').close()
        out = os.path.join(self.dir, 'record.json')
        env = dict(os.environ)
        env.update(self.env())
        env.update({'PATH': self.bin + os.pathsep + env.get('PATH', ''), 'e2e_log': e2e_log,
                    'health_retries'.upper(): '1', 'health_interval_seconds'.upper(): '0'})
        for k in ('GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY'):
            env.pop(k, None)
        cmd = '"%s" "%s"' % (sys.executable, fixture) if e2e else ''
        p = subprocess.run([sys.executable, ENGINE, 'run', '--sequence', seq, '--evidence-root',
                            self.evidence, '--work', os.path.join(self.dir, 'work'), '--out', out,
                            '--e2e-command', cmd, '--e2e-timeout-seconds', str(timeout)],
                           env=env, capture_output=True, text=True, encoding='utf-8', errors='replace')
        try:
            record = json.load(io.open(out, encoding='utf-8'))
        except (OSError, ValueError):
            record = {'result': None, 'why': p.stdout[-800:] + p.stderr[-800:], 'steps': []}
        e2e_runs = [json.loads(x) for x in io.open(e2e_log, encoding='utf-8') if x.strip()]
        return p.returncode, record, e2e_runs, self.calls()

    def close(self):
        shutil.rmtree(self.bin, ignore_errors=True)
        shutil.rmtree(self.dir, ignore_errors=True)


def step(run_id, adapter='containerapp', **extra):
    s = {'deployment': 'run %s' % run_id, 'run_id': run_id, 'run_attempt': '1', 'adapter': adapter,
         'health_path': '/health'}
    s.update(extra)
    return s


STACK = [step(r) for r, _d in CA_RUNS]   # deployment order, oldest first


def mutating(calls):
    verbs = ('update', 'set', 'swap', 'activate', 'deactivate', 'restart')
    return [c for c in calls if c[0] == 'az' and any(v in c[1:5] for v in verbs)]


def ca_serving(state):
    a = state['containerapp']
    return [(t.get('revisionName') or a['latestRevisionName'], t.get('weight')) for t in a['traffic']
            if (t.get('weight') or 0) > 0]


def active(state):
    return sorted(n for n, r in state['containerapp']['revisions'].items() if r['active'])


def main():
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    try:
        import yaml  # noqa: F401  (the runner reads the workflows with it)
        base = World(W.containerapp_state(mode='Multiple'))
    except Exception as exc:  # noqa: BLE001
        print('UNKNOWN: the stub world could not be built: %s' % exc)
        return 2
    worlds = [base]
    try:
        for run_id, digest in CA_RUNS:
            res = base.deploy(W.D.CONTAINERAPP, ca_inputs(digest), run_id)
            if res['failed']:
                print('UNKNOWN: the healthy deploy of run %s failed; nothing can be proven:\n%s'
                      % (run_id, res['log'][-1500:]))
                return 2
        stacked = base.read()
        print('  deployed runs 101, 102, 103: serving %s, active %s' % (ca_serving(stacked), active(stacked)))

        # ---- S1 all good ------------------------------------------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK)
        final = w.read()
        print('  S1  %s rc=%d e2e=%s' % (r.get('result'), rc, [x['rollback_step'] for x in e2e]))
        check(rc == 0 and r.get('result') == 'ROLLBACK_SEQUENCE_VERIFIED',
              'S1: an all-eligible, all-healthy sequence did not verify: %r -- %s' % (r.get('result'), r.get('why')))
        check([s['deployment'] for s in r.get('steps', [])] == ['run 103', 'run 102', 'run 101'],
              'S1: not reversed newest first: %r' % [s['deployment'] for s in r.get('steps', [])])
        check([s['step_result'] for s in r.get('steps', [])] == ['ROLLBACK_STEP_VERIFIED'] * 3,
              'S1: a step is not verified: %r' % [s['step_result'] for s in r.get('steps', [])])
        check([(s.get('eligibility') or {}).get('basis') for s in r.get('steps', [])] == ['ELIGIBLE_UNTOUCHED'] * 3,
              'S1: the eligibility bases are %r' % [(s.get('eligibility') or {}).get('basis') for s in r.get('steps', [])])
        check([x['rollback_step'] for x in e2e] == ['1', '2', '3']
              and [x['rollback_deployment'] for x in e2e] == ['run 103', 'run 102', 'run 101'],
              'S1: the e2e tests did not run after EACH step in order: %r' % e2e)
        check(all(x['azure_config_dir'] and x['azure_config_dir'] != w.env()['AZURE_CONFIG_DIR'] for x in e2e),
              'S1: the e2e command was handed the deploy identity\'s Azure session: %r' % e2e)
        check(ca_serving(final) == [('web--r1', 100)] and active(final) == ['web--r1'],
              'S1: the cloud is not back at the state before the first deployment: serving %s, active %s'
              % (ca_serving(final), active(final)))
        check(all(s['rollback']['result'] == 'ROLLBACK_VERIFIED' and s['health']['result'] == 'passed'
                  and s['e2e']['result'] == 'passed' for s in r.get('steps', [])),
              'S1: a step lacks a verified rollback, a passed health probe or passed e2e tests')
        import rollback_sequence as rs
        check(not rs.validate(r), 'S1: the record does not validate: %s' % rs.validate(r)[:3])

        # ---- S2 step 2 fails its e2e tests --------------------------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, extra_state=lambda s: s.update(e2e_broken_images=[W.ref(D1)]))
        final = w.read()
        st = [s['step_result'] for s in r.get('steps', [])]
        print('  S2  %s steps=%s e2e runs=%d' % (r.get('result'), st, len(e2e)))
        check(rc == 1 and r.get('result') == 'ROLLBACK_SEQUENCE_HALTED_E2E_FAILED',
              'S2: a failing e2e test after step 2 did not halt the sequence: %r' % r.get('result'))
        check(st == ['ROLLBACK_STEP_VERIFIED', 'ROLLBACK_STEP_HALTED', 'ROLLBACK_STEP_NOT_REACHED'],
              'S2: step results %r' % st)
        check(len(e2e) == 2, 'S2: the e2e tests ran %d times; the sequence continued past a failure' % len(e2e))
        check(ca_serving(final) == [('web--r2', 100)] and 'web--r2' in active(final),
              'S2: step 3\'s deployment (run 101, web--r2) was touched: serving %s, active %s'
              % (ca_serving(final), active(final)))
        check(r.get('escalation') and r['escalation'].get('permitted_agent_action'),
              'S2: a halted sequence carries no escalation contract')
        check(not rs.validate(r), 'S2: the record does not validate: %s' % rs.validate(r)[:3])

        # ---- S3 an ineligible step: someone else re-stamped its revision ---------------------------
        def restamp(s):
            s['containerapp']['revisions']['web--r3']['env']['release_ownership_stamp'] = 'release_id=someone-else'
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, extra_state=restamp)
        final = w.read()
        st = [s['step_result'] for s in r.get('steps', [])]
        el = (r.get('steps') or [{}, {}])[1].get('eligibility') or {}
        print('  S3  %s steps=%s step2=%s' % (r.get('result'), st, el.get('disposition')))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_STOPPED_INELIGIBLE' and
              st == ['ROLLBACK_STEP_VERIFIED', 'ROLLBACK_STEP_INELIGIBLE', 'ROLLBACK_STEP_NOT_REACHED'],
              'S3: an ineligible step 2 did not stop the sequence before it: %r %r' % (r.get('result'), st))
        check(el.get('disposition') == 'ROLLBACK_REQUIRES_HUMAN_DECISION' and
              any(c['check'] == 'P1 ownership' and not c['held'] for c in el.get('checks') or []),
              'S3: the ineligible step is not a human decision on P1: %r' % el)
        check(ca_serving(final) == [('web--r3', 100)] and {'web--r2', 'web--r3'} <= set(active(final)),
              'S3: the ineligible step (or the one after it) was touched: serving %s, active %s'
              % (ca_serving(final), active(final)))
        check(len(e2e) == 1, 'S3: e2e ran %d times; only step 1 ran' % len(e2e))

        # ---- S4 a shared resource, the app-owned part separable ----------------------------------
        def other_actor(s):
            a = s['containerapp']
            a['counter'] += 1
            a['revisions']['web--x9'] = {'active': False, 'image': 'registry.example/other@sha256:' + 'e' * 64,
                                         'env': {'release_ownership_stamp': 'release_id=another-team'},
                                         'createdTime': '2026-10-14T00:00:59Z', 'fqdn': 'web--x9.revision.example'}
            a['latestRevisionName'] = 'web--x9'
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, extra_state=other_actor)
        final = w.read()
        bases = [(s.get('eligibility') or {}).get('basis') for s in r.get('steps', [])]
        print('  S4  %s bases=%s' % (r.get('result'), bases))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_VERIFIED' and bases and
              all(b == 'ELIGIBLE_OWNED_PART_SEPARABLE' for b in bases),
              'S4: a shared app whose deployments\' own parts are intact was not reversed as owned parts: '
              '%r %r -- %s' % (r.get('result'), bases, r.get('why')))
        check('web--x9' in final['containerapp']['revisions'] and ca_serving(final) == [('web--r1', 100)],
              'S4: the other actor\'s revision was touched, or the app is not back: %s' % ca_serving(final))

        # ---- S5 no e2e supplied -------------------------------------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, e2e=False)
        print('  S5  %s mutating calls=%d' % (r.get('result'), len(mutating(calls))))
        check(rc == 1 and r.get('result') == 'ROLLBACK_SEQUENCE_REFUSED_NO_E2E',
              'S5: a sequence with no e2e tests was not refused: %r' % r.get('result'))
        check(not mutating(calls) and w.read() == stacked,
              'S5: the refused sequence changed the cloud: %s' % mutating(calls)[:2])
        check(all(s['step_result'] == 'ROLLBACK_STEP_NOT_REACHED' for s in r.get('steps', [])) and
              len(r.get('steps', [])) == 3, 'S5: the refused sequence does not list its steps as not reached')

        # ---- S6 a partial rollback ----------------------------------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, extra_state=lambda s: s.update(fail=['containerapp revision deactivate']))
        s1 = (r.get('steps') or [{}])[0]
        print('  S6  %s step1 rollback=%s' % (r.get('result'), (s1.get('rollback') or {}).get('result')))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_HALTED_ROLLBACK_UNVERIFIED' and
              (s1.get('rollback') or {}).get('result') == 'ROLLBACK_PARTIAL',
              'S6: a partial rollback was not a halt: %r / %r' % (r.get('result'), s1.get('rollback')))
        check(not e2e and s1.get('e2e', {}).get('result') == 'not-run',
              'S6: the e2e tests ran on a partial rollback')
        check([s['step_result'] for s in r['steps']][1:] == ['ROLLBACK_STEP_NOT_REACHED'] * 2,
              'S6: steps after the partial one were run')

        # ---- S7 forward-fix only ------------------------------------------------------------------
        w = base.clone()
        worlds.append(w)
        steps7 = [step('101'), step('102', forward_fix_only='carries an emergency mitigation'), step('103')]
        rc, r, e2e, calls = w.sequence(steps7)
        el = (r.get('steps') or [{}, {}])[1].get('eligibility') or {}
        print('  S7  %s step2=%s' % (r.get('result'), el.get('disposition')))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_STOPPED_INELIGIBLE' and el.get('disposition') == 'ROLLBACK_PROHIBITED',
              'S7: a forward-fix-only step was not ROLLBACK_PROHIBITED: %r %r' % (r.get('result'), el))

        # ---- S9 listed in the wrong order -----------------------------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(list(reversed(STACK)))
        el = (r.get('steps') or [{}])[0].get('eligibility') or {}
        print('  S9  %s first=%s mutating=%d' % (r.get('result'), (r.get('steps') or [{}])[0].get('deployment'),
                                                 len(mutating(calls))))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_STOPPED_INELIGIBLE' and
              any(c['check'] == 'P6 order' and not c['held'] for c in el.get('checks') or []),
              'S9: an out-of-order sequence was not stopped on P6: %r %r' % (r.get('result'), el))
        check(not mutating(calls), 'S9: the out-of-order sequence mutated the cloud')

        # ---- S10 health fails after a verified reversal -----------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, extra_state=lambda s: s.update(unhealthy_images=[W.ref(D2)]))
        s1 = (r.get('steps') or [{}])[0]
        print('  S10 %s health=%s e2e runs=%d' % (r.get('result'), (s1.get('health') or {}).get('result'), len(e2e)))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_HALTED_HEALTH_FAILED' and not e2e and
              (s1.get('rollback') or {}).get('result') == 'ROLLBACK_VERIFIED',
              'S10: a failed health probe after a verified reversal did not halt before the e2e tests: %r'
              % r.get('result'))

        # ---- S11 the e2e tests hang ---------------------------------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, timeout=3, extra_state=lambda s: s.update(e2e_hangs=True))
        s1 = (r.get('steps') or [{}])[0]
        print('  S11 %s e2e=%s' % (r.get('result'), (s1.get('e2e') or {}).get('result')))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_HALTED_E2E_FAILED' and
              (s1.get('e2e') or {}).get('result') == 'timed-out',
              'S11: a hung e2e command was not bounded and halted: %r %r' % (r.get('result'), s1.get('e2e')))

        # ---- S12 evidence of another run ----------------------------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence([step('101'), step('102', evidence='deploy-evidence-103-1')])
        print('  S12 %s mutating=%d' % (r.get('result'), len(mutating(calls))))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_REFUSED_INPUT' and not mutating(calls),
              'S12: a step whose evidence belongs to another run was not refused before anything: %r'
              % r.get('result'))

        # ---- S8 two resources of one release -------------------------------------------------------
        mixed = W.appservice_state()
        mixed.update(W.containerapp_state(mode='Multiple'))
        w = World(mixed)
        worlds.append(w)
        for wf, inp, run_id in ((W.D.APPSERVICE, as_inputs(D1), '201'), (W.D.CONTAINERAPP, ca_inputs(D2), '202')):
            res = w.deploy(wf, inp, run_id)
            if res['failed']:
                print('UNKNOWN: the healthy deploy of run %s failed:\n%s' % (run_id, res['log'][-1500:]))
                return 2
        rc, r, e2e, calls = w.sequence([step('201', adapter='appservice'), step('202')])
        final = w.read()
        prod = final['webapp']['slots']['production']['linuxFxVersion']
        print('  S8  %s order=%s production=%s' % (r.get('result'), [s['deployment'] for s in r.get('steps', [])],
                                                  prod[-12:]))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_VERIFIED' and
              [s['deployment'] for s in r.get('steps', [])] == ['run 202', 'run 201'],
              'S8: a two-resource release was not reversed newest first and verified: %r -- %s'
              % (r.get('result'), r.get('why')))
        check(prod == 'DOCKER|' + W.ref(W.GOOD) and ca_serving(final) == [('web--r1', 100)],
              'S8: the release\'s resources are not back on their prior state: %s, %s' % (prod, ca_serving(final)))
        check(len(e2e) == 2, 'S8: the e2e tests did not run after each of the two steps (%d)' % len(e2e))
    finally:
        for w in worlds:
            w.close()

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: deployments are reversed newest first; each step runs only when eligible (untouched, or '
          'its own part of a shared app separable), is verified by the deploy contract, probed, and '
          'end-to-end tested; a failing or hung e2e test, a failed probe, a partial rollback or an '
          'ineligible step halts the sequence before anything later is touched; no e2e tests is a refusal '
          'that changes nothing; ROLLBACK_SEQUENCE_VERIFIED only when every step is.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
