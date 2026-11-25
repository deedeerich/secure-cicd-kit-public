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

    KDEC-021 (owner, 2026-10-23) -- a TEST PERIOD after every step, App Service slots restored to the
    REQUESTED version, and deployments frozen (or, if one lands anyway, rolled back first):
    S13 a test period with an interval: health and e2e at the start, at each interval and at the end
        of the period after EVERY step (the final step included), each check timed in the record,
        and the end check no sooner than the period after the start
    S14 the e2e tests pass at the start of step 2's period and fail at its END: halted for a human
        on that step, step 3 untouched -- a pass at the start is not the period
    S15 a test period of 0 minutes is ROLLBACK_SEQUENCE_REFUSED_NO_TEST_PERIOD, and one past the
        bound is ROLLBACK_SEQUENCE_REFUSED_INPUT -- both before anything is touched
    S16 two stacked App Service slot+swap deployments: rolled back to the version the request
        names; production AND the staging slot (which the swaps moved images through) each read
        back live on the version it held before the deployments; a request naming a version the
        app never held, or none, is refused before anything is touched
    S17 a slot changed by an actor other than the kit (no kit stamp): halted for a human with the
        reason, nothing touched -- and a foreign stamp on a slot is not mistaken for a kit deploy
    S18 a KIT deployment lands mid-sequence (after step 1): detected on the re-read before step 2,
        fetched, put at the FRONT of what remains, rolled back first with its own test period and
        recorded as inserted; then the sequence carries on to the state before the first deployment
    S19 the deploy reusables and the rollback reusable share ONE concurrency group per target (a
        deploy queues behind a rollback of the same target, never cancelled), and a sequence whose
        step lies outside the target it holds the lock for is refused

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
D1, D2, D3, D4 = ('sha256:' + c * 64 for c in '1234')
OLD = 'sha256:' + '9' * 64   # what the App Service staging slot held before any deployment
CA_RUNS = (('101', D1), ('102', D2), ('103', D3))

# The application's end-to-end tests, as the stub cloud lets one be written: what the app's public
# name serves must answer, and must not be an image the scenario marks broken. It records every
# invocation, and the Azure config directory it was given, so the proof can count and inspect them.
E2E_FIXTURE = '''import io, json, os, sys, time
s = json.load(io.open(os.environ['fake_az_state'], encoding='utf-8'))
rec = {k: os.environ.get(k.upper(), '') for k in ('rollback_step', 'rollback_deployment',
       'rollback_app_url', 'rollback_steps_total', 'azure_config_dir', 'rollback_check_phase')}
io.open(os.environ['e2e_log'], 'a', encoding='utf-8').write(json.dumps(rec) + '\\n')
if s.get('e2e_hangs'):
    time.sleep(30)
here = [rec['rollback_step'], rec['rollback_check_phase']]
inj = s.get('inject_after')
if inj and here == inj['at']:
    # Another KIT deployment lands now, mid-sequence: the state its real deploy left.
    io.open(os.environ['fake_az_state'], 'w', encoding='utf-8').write(
        io.open(inj['state_file'], encoding='utf-8').read())
if here == s.get('e2e_fail_at'):
    sys.exit(1)
a = s.get('containerapp') or {}
serving = []
for t in a.get('traffic') or []:
    if (t.get('weight') or 0) > 0:
        n = a['latestRevisionName'] if t.get('latestRevision') else t.get('revisionName')
        serving.append(a['revisions'][n]['image'])
bad = [i for i in serving if i in (s.get('e2e_broken_images') or [])]
sys.exit(1 if bad or (a and not serving) else 0)
'''

# How the reusable fetches a deployment's evidence (`gh run download`), as the stub lets it: copy
# the run's deploy-evidence directory from where its deploy left it.
FETCH_FIXTURE = '''import os, shutil, sys
e = lambda k: os.environ[k.upper()]
name = 'deploy-evidence-%s-%s' % (e('rollback_fetch_run_id'), e('rollback_fetch_run_attempt'))
src = os.path.join(os.environ['fetch_from'], name)
if not os.path.isdir(src):
    sys.exit(1)
shutil.copytree(src, e('rollback_fetch_dir'))
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
        W.write_default_api(os.path.join(self.dir, 'api'))   # no rollback marker (KDEC-023)
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

    def sequence(self, steps, e2e=True, timeout=120, extra_state=None, period=1, interval=0,
                 period_minutes=None, target_version=None, lock=None, fetch=None):
        """Run the engine. -> (rc, record, e2e invocations, az calls made by the sequence).
        `period` is the test period in SECONDS (the engine's local form; the reusable passes
        minutes); `period_minutes` passes the reusable's form instead. `fetch` is a directory of
        deploy evidence the engine may fetch a mid-sequence deployment's evidence from."""
        if extra_state:
            s = self.read()
            extra_state(s)
            self.write(s)
        io.open(self.log, 'w').close()
        seq = os.path.join(self.dir, 'sequence.json')
        body = {'sequence_id': 'release-x', 'steps': steps}
        if target_version is not None:
            body['target_version'] = target_version
        io.open(seq, 'w', encoding='utf-8').write(json.dumps(body))
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
        argv = [sys.executable, ENGINE, 'run', '--sequence', seq, '--evidence-root', self.evidence,
                '--work', os.path.join(self.dir, 'work'), '--out', out, '--e2e-command', cmd,
                '--e2e-timeout-seconds', str(timeout)]
        if period_minutes is not None:
            argv += ['--test-period-minutes', str(period_minutes)]
        else:
            argv += ['--test-period-seconds', str(period)]
        if interval:
            argv += ['--check-interval-seconds', str(interval)]
        if lock:
            argv += ['--locked-target', lock]
        if fetch:
            fetcher = os.path.join(self.dir, 'fetch_fixture.py')
            io.open(fetcher, 'w', encoding='utf-8').write(FETCH_FIXTURE)
            env['fetch_from'] = fetch
            argv += ['--fetch-evidence-command', '"%s" "%s"' % (sys.executable, fetcher)]
        p = subprocess.run(argv, env=env, capture_output=True, text=True, encoding='utf-8',
                           errors='replace')
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
        rc, r, e2e, calls = w.sequence(STACK, lock='rg-a/web')
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
        # KDEC-021: a test period after EACH step, checked at its start and at its end.
        check([(x['rollback_step'], x['rollback_check_phase']) for x in e2e] ==
              [('1', 'start'), ('1', 'end'), ('2', 'start'), ('2', 'end'), ('3', 'start'), ('3', 'end')]
              and [x['rollback_deployment'] for x in e2e] == ['run 103'] * 2 + ['run 102'] * 2 + ['run 101'] * 2,
              'S1: the e2e tests did not run at the start and end of a test period after EACH step, in '
              'order: %r' % [(x.get('rollback_step'), x.get('rollback_check_phase')) for x in e2e])
        check(all([c['phase'] for c in ((s.get('test_period') or {}).get('checks') or [])] == ['start', 'end']
                  and all(c['health'] == 'passed' and c['e2e'] == 'passed' and c.get('at')
                          for c in s['test_period']['checks']) for s in r.get('steps', [])),
              'S1: a step\'s test period does not record a passed, timed start and end check: %r'
              % [s.get('test_period') for s in r.get('steps', [])])
        check((r.get('lock') or {}).get('target') == 'rg-a/web',
              'S1: the record does not name the target whose lock it held: %r' % r.get('lock'))
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
        check(len(e2e) == 3, 'S2: the e2e tests ran %d times (step 1 start+end, step 2 start); the '
              'sequence continued past a failure' % len(e2e))
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
        check(len(e2e) == 2, 'S3: e2e ran %d times; only step 1 (start and end of its period) ran' % len(e2e))

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

        # ---- S13 a test period with an interval -----------------------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, period=2, interval=1)
        periods = [(s.get('test_period') or {}) for s in r.get('steps', [])]
        phases = [[c['phase'] for c in p.get('checks') or []] for p in periods]
        print('  S13 %s phases=%s' % (r.get('result'), phases))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_VERIFIED' and phases == [['start', 'interval', 'end']] * 3,
              'S13: a 2 s period with a 1 s interval did not check at start, interval and end after every '
              'step (the final one included): %r %r -- %s' % (r.get('result'), phases, r.get('why')))
        check(all(p.get('checks') and p['checks'][-1]['offset_seconds'] >= 2 and p.get('seconds') == 2
                  for p in periods),
              'S13: an end check came sooner than the period after the start: %r' % periods)
        check(len(e2e) == 9, 'S13: the e2e tests ran %d times, not 3 per step' % len(e2e))
        check(not rs.validate(r), 'S13: the record does not validate: %s' % rs.validate(r)[:3])

        # ---- S14 passes at the start of the period, fails at its end ------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, extra_state=lambda s: s.update(e2e_fail_at=['2', 'end']))
        final = w.read()
        st = [s['step_result'] for s in r.get('steps', [])]
        s2 = (r.get('steps') or [{}, {}])[1]
        chk = [(c['phase'], c['e2e']) for c in ((s2.get('test_period') or {}).get('checks') or [])]
        print('  S14 %s steps=%s step2 checks=%s' % (r.get('result'), st, chk))
        check(rc == 1 and r.get('result') == 'ROLLBACK_SEQUENCE_HALTED_E2E_FAILED' and
              st == ['ROLLBACK_STEP_VERIFIED', 'ROLLBACK_STEP_HALTED', 'ROLLBACK_STEP_NOT_REACHED'],
              'S14: a failure at the END of step 2\'s test period did not halt it: %r %r' % (r.get('result'), st))
        check(chk == [('start', 'passed'), ('end', 'failed')],
              'S14: the record does not show a pass at the start and a failure at the end: %r' % chk)
        check(ca_serving(final) == [('web--r2', 100)] and 'web--r2' in active(final),
              'S14: step 3 was touched after the halt: %s' % ca_serving(final))
        check('end' in (r.get('why') or ''), 'S14: the halt does not say the period\'s end check failed: %s'
              % r.get('why'))

        # ---- S15 no test period; a period past the bound --------------------------------------------
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, period_minutes=0)
        print('  S15 0 min: %s mutating=%d' % (r.get('result'), len(mutating(calls))))
        check(rc == 1 and r.get('result') == 'ROLLBACK_SEQUENCE_REFUSED_NO_TEST_PERIOD' and not mutating(calls)
              and not e2e and w.read() == stacked,
              'S15: a 0-minute test period was not refused before anything: %r' % r.get('result'))
        check(not rs.validate(r), 'S15: the refusal record does not validate: %s' % rs.validate(r)[:3])
        rc, r, e2e, calls = w.sequence(STACK, period_minutes=241)
        print('  S15 241 min: %s mutating=%d' % (r.get('result'), len(mutating(calls))))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_REFUSED_INPUT' and not mutating(calls),
              'S15: a test period past the 240-minute bound was not refused: %r' % r.get('result'))

        # ---- S18 a kit deployment lands mid-sequence ------------------------------------------------
        # Its real deploy is made in a copy of the world as it stands after step 1 (run 103 reversed);
        # the scenario then lands that state at the END of step 1's test period, and the engine has to
        # find the deployment, fetch its evidence and roll it back first.
        pre = base.clone()
        worlds.append(pre)
        pre.sequence([step('103')])
        res = pre.deploy(W.D.CONTAINERAPP, ca_inputs(D4), '104')
        if res['failed']:
            print('UNKNOWN: the mid-sequence deploy of run 104 failed:\n%s' % res['log'][-1500:])
            return 2
        landed = os.path.join(pre.dir, 'state-after-104.json')
        shutil.copyfile(pre.state, landed)
        inject = lambda s: s.update(inject_after={'at': ['1', 'end'], 'state_file': landed})  # noqa: E731
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, extra_state=inject, fetch=pre.evidence, lock='rg-a/web')
        final = w.read()
        order = [s['deployment'] for s in r.get('steps', [])]
        ins = [s for s in r.get('steps', []) if s.get('inserted')]
        print('  S18 %s order=%s inserted=%s' % (r.get('result'), order, r.get('inserted')))
        check(rc == 0 and r.get('result') == 'ROLLBACK_SEQUENCE_VERIFIED' and len(order) == 4 and
              order[0] == 'run 103' and order[1].startswith('run 104') and order[2:] == ['run 102', 'run 101'],
              'S18: a kit deployment landing mid-sequence was not put at the front of what remained and '
              'rolled back first: %r %r -- %s' % (r.get('result'), order, r.get('why')))
        check(len(ins) == 1 and ins[0]['run_id'] == '104' and ins[0].get('inserted_because') and
              ins[0]['step_result'] == 'ROLLBACK_STEP_VERIFIED' and
              [c['phase'] for c in (ins[0].get('test_period') or {}).get('checks') or []] == ['start', 'end'] and
              r.get('inserted') == ['run-104-1'],
              'S18: the inserted deployment is not recorded, verified and tested with its own period: %r'
              % ins)
        check(len(order) > 1 and
              [x['rollback_deployment'] for x in e2e if x['rollback_step'] == '2'] == [order[1]] * 2,
              'S18: the inserted deployment did not get its own test period (start and end)')
        check(ca_serving(final) == [('web--r1', 100)] and active(final) == ['web--r1'],
              'S18: the app is not back at the state before the first deployment: %s %s'
              % (ca_serving(final), active(final)))
        check(not rs.validate(r), 'S18: the record does not validate: %s' % rs.validate(r)[:3])
        # The same landing with no way to fetch its evidence: a human decision, nothing more touched.
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, extra_state=inject)
        st = [s['step_result'] for s in r.get('steps', [])]
        el = (r.get('steps') or [{}, {}])[1].get('eligibility') or {}
        print('  S18 no evidence: %s steps=%s' % (r.get('result'), st))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_STOPPED_INELIGIBLE' and
              el.get('disposition') == 'ROLLBACK_REQUIRES_HUMAN_DECISION' and
              st[0] == 'ROLLBACK_STEP_VERIFIED' and 'ROLLBACK_STEP_VERIFIED' not in st[1:],
              'S18: a mid-sequence kit deployment whose evidence cannot be fetched did not stop for a '
              'human: %r %r %r' % (r.get('result'), st, el))
        check(w.read() == json.load(io.open(landed, encoding='utf-8')),
              'S18: with no evidence for the landed deployment, something after it was touched')

        # ---- S19 one concurrency group per target, deploys and rollback ---------------------------
        import _deploy_steps as DS
        rb_path = os.path.join(ROOT, '.github', 'workflows', 'reusable-rollback-sequence.yml')
        vals = {'inputs.github_environment': 'env', 'inputs.resource_group': 'rg-a',
                'inputs.webapp_name': 'web', 'inputs.containerapp_name': 'web',
                'inputs.target_resource_group': 'rg-a', 'inputs.target_name': 'web', 'inputs.slot': 'staging'}
        groups, cancels = {}, {}
        for label, path in (('appservice', DS.APPSERVICE), ('containerapp', DS.CONTAINERAPP),
                            ('rollback', rb_path)):
            conc = DS.load(path).get('concurrency') or {}
            groups[label] = DS.resolve(str(conc.get('group', '')), vals)
            cancels[label] = conc.get('cancel-in-progress')
        other = DS.resolve(str((DS.load(rb_path).get('concurrency') or {}).get('group', '')),
                           dict(vals, **{'inputs.target_name': 'another-app'}))
        print('  S19 groups=%s' % groups)
        check(len(set(groups.values())) == 1 and all(groups.values()),
              'S19: a deploy and a rollback of the same target do not share one concurrency group, so a '
              'deploy would race the rollback instead of queueing: %r' % groups)
        check(all(v is False for v in cancels.values()),
              'S19: cancel-in-progress is not false on every one: %r' % cancels)
        check(other != groups['rollback'], 'S19: a rollback of another target takes the same lock')
        w = base.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(STACK, lock='rg-a/another-app')
        print('  S19 outside the lock: %s mutating=%d' % (r.get('result'), len(mutating(calls))))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_REFUSED_INPUT' and not mutating(calls),
              'S19: a sequence whose steps lie outside the target it holds the lock for was not refused: %r'
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
        rc, r, e2e, calls = w.sequence([step('201', adapter='appservice'), step('202')],
                                       target_version=W.ref(W.GOOD))
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
        check(len(e2e) == 4, 'S8: the e2e tests did not run at the start and end of the period after '
              'each of the two steps (%d)' % len(e2e))

        # ---- S16 stacked App Service slot+swap deployments, back to the REQUESTED version ----------
        astate = W.appservice_state()
        astate['webapp']['slots']['staging']['linuxFxVersion'] = 'DOCKER|' + W.ref(OLD)
        aw = World(astate)
        worlds.append(aw)
        for run_id, digest in (('301', D1), ('302', D2)):
            res = aw.deploy(W.D.APPSERVICE, as_inputs(digest), run_id)
            if res['failed']:
                print('UNKNOWN: the healthy App Service deploy of run %s failed:\n%s' % (run_id, res['log'][-1500:]))
                return 2
        slots = lambda st: dict((k, v['linuxFxVersion']) for k, v in st['webapp']['slots'].items())  # noqa: E731
        print('  deployed runs 301, 302 (slot+swap): %s' % dict((k, v[-6:]) for k, v in slots(aw.read()).items()))
        AS_STACK = [step('301', adapter='appservice'), step('302', adapter='appservice')]
        w = aw.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(AS_STACK, target_version=W.ref(W.GOOD), lock='rg-a/web')
        final = slots(w.read())
        restored = [[(x['slot'], x['held']) for x in s.get('restored') or []] for s in r.get('steps', [])]
        print('  S16 %s restored=%s final=%s' % (r.get('result'), restored,
                                                  dict((k, v[-6:]) for k, v in final.items())))
        check(rc == 0 and r.get('result') == 'ROLLBACK_SEQUENCE_VERIFIED' and
              [s['deployment'] for s in r.get('steps', [])] == ['run 302', 'run 301'],
              'S16: two stacked App Service slot+swap deployments were not rolled back newest first and '
              'verified: %r -- %s' % (r.get('result'), r.get('why')))
        check(final == {'production': 'DOCKER|' + W.ref(W.GOOD), 'staging': 'DOCKER|' + W.ref(OLD)},
              'S16: the slots are not each back on the version they held before the deployments: %s' % final)
        check(all(rs_ and all(h for _s, h in rs_) and {'production', 'staging'} <= set(x for x, _h in rs_)
                  for rs_ in restored),
              'S16: a step does not record a live read of every slot it affected, each held: %r' % restored)
        fv = r.get('final_version') or {}
        check(fv.get('requested') == W.ref(W.GOOD) and fv.get('held') is True and fv.get('live') == W.ref(W.GOOD),
              'S16: the record does not show production read back live on the requested version: %r' % fv)
        check(not rs.validate(r), 'S16: the record does not validate: %s' % rs.validate(r)[:3])
        w = aw.clone()
        worlds.append(w)
        rc, r, e2e, calls = w.sequence(AS_STACK, target_version=W.ref(D3))
        print('  S16 never-held version: %s mutating=%d' % (r.get('result'), len(mutating(calls))))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_REFUSED_INPUT' and not mutating(calls),
              'S16: a request naming a version the app did not hold before the deployments was not '
              'refused before anything: %r' % r.get('result'))
        rc, r, e2e, calls = w.sequence(AS_STACK)
        print('  S16 no version named: %s mutating=%d' % (r.get('result'), len(mutating(calls))))
        check(r.get('result') == 'ROLLBACK_SEQUENCE_REFUSED_INPUT' and not mutating(calls),
              'S16: an App Service rollback request naming no version was not refused: %r' % r.get('result'))

        # ---- S17 a slot changed by an actor other than the kit ---------------------------------------
        def foreign_image(s):
            s['webapp']['slots']['staging']['linuxFxVersion'] = 'DOCKER|registry.example/other@sha256:' + 'f' * 64
        def foreign_stamp(s):
            s['webapp']['slots']['production']['tags']['release_ownership_stamp'] = 'release_id=someone-else'
        for label, fn in (('foreign image', foreign_image), ('foreign stamp', foreign_stamp)):
            w = aw.clone()
            worlds.append(w)
            rc, r, e2e, calls = w.sequence(AS_STACK, target_version=W.ref(W.GOOD), extra_state=fn)
            el = (r.get('steps') or [{}])[0].get('eligibility') or {}
            print('  S17 %s: %s %s inserted=%s' % (label, r.get('result'), el.get('disposition'), r.get('inserted')))
            check(r.get('result') == 'ROLLBACK_SEQUENCE_STOPPED_INELIGIBLE' and
                  el.get('disposition') == 'ROLLBACK_REQUIRES_HUMAN_DECISION' and not mutating(calls)
                  and not r.get('inserted'),
                  'S17 (%s): a slot changed outside the kit did not halt for a human before anything: %r %r'
                  % (label, r.get('result'), el))
            check('other than the kit' in (el.get('why') or ''),
                  'S17 (%s): the halt does not say the slot was changed by an actor other than the kit: %s'
                  % (label, el.get('why')))
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
          'that changes nothing; ROLLBACK_SEQUENCE_VERIFIED only when every step is. KDEC-021: a test '
          'period after every step (start, interval, end; a failure at its end halts; 0 is refused); '
          'stacked App Service slot+swap deployments return to the requested version, every slot read '
          'back; a slot changed outside the kit halts for a human; a kit deployment landing mid-sequence '
          'is rolled back first; deploys and rollbacks of one target share one concurrency group.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
