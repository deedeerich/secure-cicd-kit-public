#!/usr/bin/env python3
"""Sequential rollback: several deployments reversed in REVERSE deployment order, with the
application's end-to-end tests run after EACH step. (KDEC-019 item 4, owner 2026-10-22; lane L-RB.)

WHY THIS EXISTS

    Owner, relaying a colleague: "if multiples are required and can be done because nothing else
    touched the resource and/or because the resource was shared but still able to be rolled back
    for that particular application or deployment ... intelligently then we should do end to end
    tests to make sure that between each rollback things still work. He's right."

    Each deploy reusable already reverses ITS OWN failed change, inside its own run
    (scripts/deploy_contract.py `reverse`, ROLLBACK_CONTRACT.md). Nothing reversed SEVERAL standing
    deployments -- several runs' manifests, or several resources of one release -- and nothing
    checked that the application still works between one reversal and the next. Undoing three
    releases back to back and testing only at the end is how a broken intermediate state reaches
    users for the length of the sequence, and how the step that broke it is lost.

WHAT A SEQUENCE IS

    A list of deployments in DEPLOYMENT order (oldest first), each named by the run that made it
    and the deploy evidence that run uploaded (`deploy-evidence-<run_id>-<attempt>`: snapshot.json,
    manifest.json, capability.json, outcome.json). It is executed in REVERSE order, newest first,
    because a later release may stand on an earlier one (DCR section 8.1 P6).

    {"sequence_id": "...",
     "steps": [{"deployment": "label", "run_id": "101", "run_attempt": "1",
                "adapter": "containerapp" | "appservice", ["evidence": "dir under the root"],
                ["health_path": "/health"], ["forward_fix_only": "why reversal is worse"]}]}

PER STEP, IN ORDER -- a step is complete only when all four hold

    1  ELIGIBLE, decided from a FRESH live read just before the step, against what the run
       recorded (eligibility below). Not eligible: the sequence STOPS BEFORE the step, which is
       ROLLBACK_REQUIRES_HUMAN_DECISION (or ROLLBACK_PROHIBITED for a step declared forward-fix
       only), and nothing of it is touched.
    2  REVERSED by the deploy contract itself (deploy_contract.py `reverse`, the same code the
       deploys run), whose per-object preconditions are judged again as it acts. Only
       ROLLBACK_VERIFIED counts; ROLLBACK_PARTIAL or STATUS_UNTRUSTED halts the sequence.
    3  HEALTHY: the deploy's own health probe answers 200 on the consumer-facing name.
    4  END-TO-END TESTS PASS: the caller's command (`--e2e-command`) exits 0 within its bound. It
       runs with the step named in its environment ($ROLLBACK_STEP, $ROLLBACK_STEPS_TOTAL,
       $ROLLBACK_DEPLOYMENT, $ROLLBACK_ADAPTER, $ROLLBACK_APP_URL, $ROLLBACK_SEQUENCE_ID) and WITHOUT
       the deploy identity's Azure session (its Azure config directory is an empty one).
       A failure or a timeout HALTS the sequence: ROLLBACK_SEQUENCE_HALTED_E2E_FAILED, for a human
       decision. It never continues on a broken intermediate state.

ELIGIBILITY (the two bases the owner named; anything else stops before the step)

    ELIGIBLE_UNTOUCHED              nothing else touched the resource: every object the run's
                                    manifest names holds exactly what the run left (P1 stamp, P2
                                    version), no later release stands on it (P6), and nothing
                                    else on the resource moved
    ELIGIBLE_OWNED_PART_SEPARABLE   the resource is shared and something else on it moved, but
                                    THIS deployment's part -- its revision and its traffic on a
                                    Container App -- is intact and is reversed on its own (DCR
                                    8.1, "the unit of conflict is the mutation")

    App Service is eligible only UNTOUCHED: the deploy contract verifies a reversal by comparing
    EVERY slot it captured, so a slot another actor moved would make the reversal unverifiable;
    the step stops before it instead of being run to a certain ROLLBACK_PARTIAL.

NO END-TO-END TESTS IS NOT A PASS -- IT IS A REFUSAL (the fail-safe chosen, and why)

    With no `--e2e-command` the sequence is ROLLBACK_SEQUENCE_REFUSED_NO_E2E before the first
    step and changes nothing. A health probe is one request, not functional validation (the deploy
    contract says so of promotion), and the owner's rule is tests BETWEEN steps; running the
    reversals anyway would be exactly the untested intermediate state the rule forbids, and a
    recorded gap after the fact cannot un-break a user path. Refusing touches nothing, which is the
    non-destructive branch: each deploy's own single-run reversal is unaffected.

THE RECORD (schemas/rollback-sequence.schema.json, validated before it is written)

    One JSON record: the sequence result, why, and every step -- deployment, eligibility basis or
    disposition with the checks that decided it, rollback result, health, e2e result, timestamps.
    ROLLBACK_SEQUENCE_VERIFIED only when EVERY step is ROLLBACK_STEP_VERIFIED.

USAGE
    rollback_sequence.py run --sequence FILE --evidence-root DIR --work DIR --out FILE
                             [--e2e-command CMD] [--e2e-timeout-seconds N] [--summary FILE]
                             [--github-output FILE]
    rollback_sequence.py --self-test

EXIT  0 ROLLBACK_SEQUENCE_VERIFIED   1 refused, stopped or halted (named)   2 usage / self-test
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploy_contract as dc  # noqa: E402

SCHEMA = os.path.join(os.path.dirname(HERE), 'schemas', 'rollback-sequence.schema.json')

# rollback_sequence (assurance-taxonomy.yaml)
SEQUENCE_VERIFIED = 'ROLLBACK_SEQUENCE_VERIFIED'
REFUSED_NO_E2E = 'ROLLBACK_SEQUENCE_REFUSED_NO_E2E'
REFUSED_INPUT = 'ROLLBACK_SEQUENCE_REFUSED_INPUT'
STOPPED_INELIGIBLE = 'ROLLBACK_SEQUENCE_STOPPED_INELIGIBLE'
HALTED_ROLLBACK = 'ROLLBACK_SEQUENCE_HALTED_ROLLBACK_UNVERIFIED'
HALTED_HEALTH = 'ROLLBACK_SEQUENCE_HALTED_HEALTH_FAILED'
HALTED_E2E = 'ROLLBACK_SEQUENCE_HALTED_E2E_FAILED'
# rollback_sequence_step
STEP_VERIFIED = 'ROLLBACK_STEP_VERIFIED'
STEP_HALTED = 'ROLLBACK_STEP_HALTED'
STEP_INELIGIBLE = 'ROLLBACK_STEP_INELIGIBLE'
STEP_NOT_REACHED = 'ROLLBACK_STEP_NOT_REACHED'
UNTOUCHED = 'ELIGIBLE_UNTOUCHED'
OWNED_PART = 'ELIGIBLE_OWNED_PART_SEPARABLE'
# rollback_state, reused unchanged
HUMAN = 'ROLLBACK_REQUIRES_HUMAN_DECISION'
PROHIBITED = 'ROLLBACK_PROHIBITED'
VERIFIED = 'ROLLBACK_VERIFIED'

ADAPTERS = ('containerapp', 'appservice')
STEP_KEYS = ('deployment', 'run_id', 'run_attempt', 'adapter', 'evidence', 'health_path',
             'forward_fix_only')


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _s(v):
    return v.strip() if isinstance(v, str) else ''


# ----------------------------------------------------------------------------- input
def read_sequence(path, root):
    """-> (sequence, problems). Every step's evidence is read here, BEFORE anything is touched: a
    sequence that cannot be read whole is refused whole."""
    try:
        seq = json.load(io.open(path, encoding='utf-8'))
    except (OSError, ValueError) as exc:
        return None, ['the sequence could not be read: %s' % exc]
    p = []
    if not isinstance(seq, dict) or not isinstance(seq.get('steps'), list) or not seq['steps']:
        return None, ['the sequence is not an object with a non-empty steps list']
    if not _s(seq.get('sequence_id')):
        p.append('sequence_id is missing')
    for k in seq:
        if k not in ('sequence_id', 'steps', 'notes'):
            p.append('unknown top-level field %r (the reader is an allowlist)' % k)
    seen = set()
    for i, st in enumerate(seq['steps']):
        where = 'steps[%d]' % i
        if not isinstance(st, dict):
            p.append('%s is not an object' % where)
            continue
        for k in st:
            if k not in STEP_KEYS:
                p.append('%s carries unknown field %r' % (where, k))
        if st.get('adapter') not in ADAPTERS:
            p.append('%s adapter %r is not containerapp or appservice' % (where, st.get('adapter')))
        rid, att = _s(str(st.get('run_id') or '')), _s(str(st.get('run_attempt') or '1'))
        if not rid.isdigit() or not att.isdigit():
            p.append('%s run_id / run_attempt must be the deploying run\'s numbers' % where)
            continue
        if (rid, att) in seen:
            p.append('%s names run %s attempt %s twice' % (where, rid, att))
        seen.add((rid, att))
        st['run_id'], st['run_attempt'] = rid, att
        st.setdefault('deployment', 'run %s attempt %s' % (rid, att))
        d = os.path.join(root, _s(st.get('evidence')) or 'deploy-evidence-%s-%s' % (rid, att))
        ev = {}
        for name in ('snapshot.json', 'manifest.json', 'capability.json', 'outcome.json'):
            try:
                ev[name] = json.load(io.open(os.path.join(d, name), encoding='utf-8'))
            except (OSError, ValueError) as exc:
                p.append('%s: %s could not be read from %s (%s)' % (where, name, d, exc))
        st['_dir'], st['_ev'] = d, ev
        man = ev.get('manifest.json') or {}
        if man and man.get('release_id') != 'run-%s-%s' % (rid, att):
            p.append('%s: the manifest belongs to %r, not run %s attempt %s' % (
                where, man.get('release_id'), rid, att))
        snap = ev.get('snapshot.json') or {}
        if snap and snap.get('adapter') not in (None, st.get('adapter')):
            p.append('%s: the evidence is a %s deployment, the step says %s' % (
                where, snap.get('adapter'), st.get('adapter')))
    return seq, p


# ----------------------------------------------------------------------------- environment
def step_env(st):
    """The deploy contract reads its target from the environment, as in the deploy job."""
    snap = st['_ev']['snapshot.json']
    e = {'resource_group': snap.get('resource_group', ''), 'github_run_id': st['run_id'],
         'github_run_attempt': st['run_attempt'], 'health_path': st.get('health_path') or '/health'}
    if st['adapter'] == 'containerapp':
        e['containerapp_name'] = snap.get('app', '')
    else:
        e['webapp_name'] = snap.get('app', '')
        target = snap.get('target') or 'production'
        e['slot'] = '' if target == 'production' else target
    return dict((k.upper(), v) for k, v in e.items())


@contextlib.contextmanager
def environment(values, runner_temp):
    saved = dict(os.environ)
    try:
        for k in ('github_output', 'github_step_summary'):
            os.environ.pop(k.upper(), None)
        os.environ.update(values)
        os.environ['RUNNER_TEMP'] = runner_temp
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


# ----------------------------------------------------------------------------- eligibility
def ineligible(disposition, check, why, checks):
    checks.append({'check': check, 'held': False, 'detail': why})
    return {'eligible': False, 'basis': None, 'disposition': disposition, 'why': why,
            'checks': checks}


def held(check, detail, checks):
    checks.append({'check': check, 'held': True, 'detail': detail})


def eligibility(st):
    """-> eligibility dict, from the evidence and a FRESH live read (the caller has set the
    step's environment). Every unknown resolves to a human decision, never to the reversal."""
    ev, checks = st['_ev'], []
    if _s(st.get('forward_fix_only')):
        return ineligible(PROHIBITED, 'forward-fix only', 'declared forward-fix only: %s'
                          % _s(st['forward_fix_only']), checks)
    outcome = (ev.get('outcome.json') or {}).get('deployment_outcome')
    if outcome != 'DEPLOY_HEALTHY':
        return ineligible(HUMAN, 'a standing deployment', 'the deployment\'s own outcome was %r, so '
                          'it is not a standing deployment to reverse' % outcome, checks)
    held('a standing deployment', 'the deploy reported DEPLOY_HEALTHY', checks)
    man = ev.get('manifest.json') or {}
    if man.get('status') != 'applied' or not man.get('entries'):
        return ineligible(HUMAN, 'manifest complete', 'the change manifest is %r, not applied: what '
                          'the run owns is not known' % man.get('status'), checks)
    cap = (ev.get('capability.json') or {}).get('rollback_capability')
    if cap not in ('AVAILABLE', 'NO_PRIOR_STATE'):
        return ineligible(HUMAN, 'rollback capability', 'rollback_capability was %r when it '
                          'deployed: %s' % (cap, (ev.get('capability.json') or {}).get('why')), checks)
    held('rollback capability', cap, checks)
    release = man['release_id']
    if st['adapter'] == 'containerapp':
        return eligibility_containerapp(man, ev['snapshot.json'], release, checks,
                                        st.get('_sequence_objects') or set())
    return eligibility_appservice(man, ev['snapshot.json'], release, checks)


def eligibility_containerapp(man, snap, release, checks, ours_before=frozenset()):
    """`ours_before`: revisions created by deployments this sequence has already reversed -- a
    later step of the same release train, not another actor."""
    app, rg = dc.env('containerapp_name'), dc.env('resource_group')
    readable, latest, traffic, ours, ours_props, descendants = dc._containerapp_live(app, rg)
    ok, revs, _err = dc.az('containerapp', 'revision', 'list', '-n', app, '-g', rg, '--all')
    if not readable or not ok or not isinstance(revs, list):
        return ineligible(HUMAN, 'live state readable', 'the container app could not be read', checks)
    if snap.get('revision_mode') != 'Multiple' and snap.get('previous_state') == 'EXISTING_DEPLOYMENT':
        return ineligible(HUMAN, 'mechanism valid', 'single revision mode: the prior revision cannot '
                          'be reactivated beside this one', checks)
    created = [e for e in man['entries'] if e.get('action') == 'CREATED']
    if not created or not ours or not ours_props:
        return ineligible(HUMAN, 'P1 ownership', 'the revision this run created (%s) is not on the '
                          'app' % (ours or 'none recorded'), checks)
    stamp = dc._stamp_release(dc._rev_stamp(ours_props))
    if stamp != release:
        return ineligible(HUMAN, 'P1 ownership', 'revision %s carries the stamp of %r, not %s: '
                          'someone else claims it' % (ours, stamp or 'nobody', release), checks)
    image = (((ours_props.get('template') or {}).get('containers') or [{}])[0]).get('image')
    if image != created[-1].get('post'):
        return ineligible(HUMAN, 'P2 version', 'revision %s runs %s, not the %s this run recorded'
                          % (ours, image, created[-1].get('post')), checks)
    if not ours_props.get('active'):
        return ineligible(HUMAN, 'P2 version', 'revision %s is no longer active: something else '
                          'deactivated it' % ours, checks)
    held('P1 ownership', '%s carries this release\'s stamp' % ours, checks)
    held('P2 version', '%s still runs %s' % (ours, image), checks)
    if descendants is None:
        return ineligible(HUMAN, 'P6 order', 'an unstamped later revision is active: the release '
                          'graph cannot be read', checks)
    if descendants:
        return ineligible(HUMAN, 'P6 order', 'later release(s) %s stand on this one and are not '
                          'earlier in this sequence' % ', '.join(descendants), checks)
    held('P6 order', 'no later release stands on it', checks)
    redirects = [e for e in man['entries'] if e.get('action') == 'REDIRECTED']
    if redirects:
        want, have = dc._canon(redirects[-1].get('post'), latest), dc._canon(traffic, latest)
        if want != have:
            return ineligible(HUMAN, 'P2 traffic', 'traffic is %s, not the %s this run left: '
                              'someone else moved it' % (have, want), checks)
        held('P2 traffic', 'traffic is what this run left (%s)' % have, checks)
    labels = [t.get('label') for t in traffic
              if t.get('label') and (latest if t.get('latestRevision') else t.get('revisionName')) == ours]
    if labels:
        return ineligible(HUMAN, 'P5 dependents', 'traffic label(s) %s now point at %s'
                          % (', '.join(labels), ours), checks)
    held('P5 dependents', 'nothing labels %s' % ours, checks)
    others = []
    if latest != ours and latest not in ours_before:
        others.append('the latest revision is now %s' % latest)
    extra = sorted(set(r.get('name') for r in revs) - set(snap.get('revisions') or {}) - {ours}
                   - set(ours_before))
    if extra:
        others.append('revision(s) %s were created by another actor (inactive)' % ', '.join(extra))
    if others:
        held('owned part separable', '%s; this deployment\'s revision and traffic are intact and '
             'are reversed on their own' % '; '.join(others), checks)
        return {'eligible': True, 'basis': OWNED_PART, 'disposition': None,
                'why': 'the app is shared and moved (%s), but this deployment\'s part is intact'
                       % '; '.join(others), 'checks': checks}
    held('untouched', 'nothing else on the app moved since this deployment', checks)
    return {'eligible': True, 'basis': UNTOUCHED, 'disposition': None,
            'why': 'nothing else touched the app since this deployment', 'checks': checks}


def _slot_stamp(slot):
    args = ['webapp', 'show', '-n', dc.env('webapp_name'), '-g', dc.env('resource_group')]
    if slot != 'production':
        args += ['--slot', slot]
    ok, shown, _ = dc.az(*args)
    if not ok or not isinstance(shown, dict):
        return None
    return dc._stamp_release((shown.get('tags') or {}).get('release_ownership_stamp', ''))


def eligibility_appservice(man, snap, release, checks):
    images = dict(snap.get('images') or {})
    want = dict(images)
    owned = set()
    strip = lambda v: (v or '').split('|', 1)[-1] if v else ''  # noqa: E731
    for e in man['entries']:
        if e.get('action') == 'MODIFIED':
            want[e['object']] = strip(e.get('post'))
            owned.add(e['object'])
    swaps = [e for e in man['entries'] if e.get('action') == 'REDIRECTED']
    if swaps:
        # A swap moved this run's image into production and production's into the slot.
        want['production'] = strip(swaps[-1].get('post'))
        want[swaps[-1].get('from_slot')] = images.get('production', '')
        owned.add('production')
    for slot in sorted(want):
        live = dc.appservice_slot_image(slot)
        if live is None:
            return ineligible(HUMAN, 'live state readable', 'slot %s could not be read' % slot, checks)
        if slot in owned:
            stamp = _slot_stamp(slot)
            if stamp is None:
                return ineligible(HUMAN, 'P1 ownership', 'slot %s\'s stamp could not be read' % slot,
                                  checks)
            if stamp != release:
                return ineligible(HUMAN, 'P1 ownership', 'slot %s carries the stamp of %r, not %s'
                                  % (slot, stamp or 'nobody', release), checks)
            if live != want[slot]:
                return ineligible(HUMAN, 'P2 version', 'slot %s holds %s, not the %s this run left'
                                  % (slot, live or 'nothing', want[slot]), checks)
            held('P1 P2 %s' % slot, '%s holds what this run left, under its stamp' % slot, checks)
        elif live != want[slot]:
            return ineligible(HUMAN, 'untouched', 'slot %s, which this run did not change, moved (%s '
                              'is now %s); the reversal verifies every slot it captured, so it could '
                              'not be verified complete' % (slot, want[slot], live or 'nothing'), checks)
    held('untouched', 'every captured slot holds what this run left', checks)
    return {'eligible': True, 'basis': UNTOUCHED, 'disposition': None,
            'why': 'nothing else touched the app since this deployment', 'checks': checks}


# ----------------------------------------------------------------------------- one step
def app_url(adapter):
    if adapter == 'containerapp':
        ok, shown, _ = dc.az('containerapp', 'show', '-n', dc.env('containerapp_name'),
                             '-g', dc.env('resource_group'))
        host = ((((shown or {}).get('properties') or {}).get('configuration') or {})
                .get('ingress') or {}).get('fqdn', '') if ok else ''
    else:
        host = dc.appservice_host('production')
    return 'https://%s' % host if host else ''


def reverse(st, step_dir, contract):
    """Run the deploy contract's own reversal for this deployment. -> reversal.json or None."""
    ev = os.path.join(step_dir, 'deploy-evidence')
    env = dict(os.environ)
    p = subprocess.run([sys.executable, contract, 'reverse', '--adapter', st['adapter']], env=env,
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    sys.stdout.write(p.stdout)
    try:
        return json.load(io.open(os.path.join(ev, 'reversal.json'), encoding='utf-8'))
    except (OSError, ValueError):
        return None


def end_to_end(cmd, timeout, extra):
    """-> ('passed'|'failed'|'timed-out', exit code or None). The command runs without the deploy
    identity's Azure session: its Azure config directory is a fresh empty one."""
    cfg = tempfile.mkdtemp(prefix='e2e-azure-config-')
    env = dict(os.environ)
    for k in ('github_output', 'github_step_summary'):
        env.pop(k.upper(), None)
    env.update(extra)
    env['azure_config_dir'.upper()] = cfg
    try:
        p = subprocess.run(cmd, shell=True, env=env, timeout=timeout)  # noqa: S602 (the caller's own tests)
        return ('passed' if p.returncode == 0 else 'failed'), p.returncode
    except subprocess.TimeoutExpired:
        return 'timed-out', None
    finally:
        shutil.rmtree(cfg, ignore_errors=True)


def run_step(st, n, total, seq_id, work, e2e_cmd, e2e_timeout, contract):
    rec = {'position': st['_position'], 'executed_as': n, 'deployment': st['deployment'],
           'run_id': st['run_id'], 'run_attempt': st['run_attempt'], 'adapter': st['adapter'],
           'target': (st['_ev'].get('snapshot.json') or {}).get('app') or None,
           'started_at': now(), 'finished_at': None, 'eligibility': None,
           'rollback': {'result': 'not-run', 'reversal_path': None, 'not_reversed': []},
           'health': {'result': 'not-run', 'url': None},
           'e2e': {'result': 'not-run', 'exit_code': None}, 'step_result': STEP_NOT_REACHED}
    step_dir = os.path.join(work, 'step-%02d' % n)
    ev = os.path.join(step_dir, 'deploy-evidence')
    os.makedirs(ev, exist_ok=True)
    # A COPY of what the deploying run recorded: the deploy contract reads its manifest from here
    # (the run's own record is never written to) and writes this step's reversal.json beside it.
    for name in ('snapshot.json', 'manifest.json', 'capability.json'):
        shutil.copyfile(os.path.join(st['_dir'], name), os.path.join(ev, name))
    halt = None
    with environment(step_env(st), step_dir):
        el = eligibility(st)
        rec['eligibility'] = el
        if not el['eligible']:
            rec['step_result'] = STEP_INELIGIBLE
            halt = (STOPPED_INELIGIBLE, 'step %d (%s) is not eligible -- %s: %s. Stopped BEFORE it; '
                    'nothing of it was touched' % (n, st['deployment'], el['disposition'], el['why']))
        else:
            rv = reverse(st, step_dir, contract)
            rec['rollback'] = {'result': (rv or {}).get('result') or 'STATUS_UNTRUSTED',
                               'reversal_path': (rv or {}).get('reversal_path'),
                               'not_reversed': (rv or {}).get('not_reversed') or []}
            if rec['rollback']['result'] != VERIFIED:
                halt = (HALTED_ROLLBACK, 'step %d (%s): the reversal is %s, not %s -- a partial '
                        'rollback is never verified' % (n, st['deployment'], rec['rollback']['result'],
                                                        VERIFIED))
            else:
                url = app_url(st['adapter'])
                rec['health']['url'] = url or None
                good = bool(url) and dc.probe(url + (st.get('health_path') or '/health'))
                rec['health']['result'] = 'passed' if good else 'failed'
                if not good:
                    halt = (HALTED_HEALTH, 'step %d (%s): rolled back and verified, but the health '
                            'probe on %s never answered 200' % (n, st['deployment'], url or 'no host'))
                else:
                    extra = {'rollback_step': str(n), 'rollback_steps_total': str(total),
                             'rollback_deployment': st['deployment'], 'rollback_adapter': st['adapter'],
                             'rollback_app_url': url, 'rollback_sequence_id': seq_id}
                    res, code = end_to_end(e2e_cmd, e2e_timeout,
                                           dict((k.upper(), v) for k, v in extra.items()))
                    rec['e2e'] = {'result': res, 'exit_code': code}
                    if res != 'passed':
                        halt = (HALTED_E2E, 'step %d (%s): rolled back, verified and healthy, but the '
                                'end-to-end tests %s%s. The sequence halts here for a human decision; '
                                'it never continues on a broken intermediate state'
                                % (n, st['deployment'], res, '' if code is None else ' (exit %d)' % code))
            rec['step_result'] = STEP_HALTED if halt else STEP_VERIFIED
    rec['finished_at'] = now()
    return rec, halt


# ----------------------------------------------------------------------------- the sequence
def run(seq_path, root, work, e2e_cmd, e2e_timeout, contract=None):
    contract = contract or os.path.join(HERE, 'deploy_contract.py')
    started = now()
    record = {'schema_version': 1, 'sequence_id': None, 'started_at': started, 'finished_at': None,
              'result': None, 'why': None, 'order': 'reverse of deployment order (newest first)',
              'e2e': {'supplied': bool(_s(e2e_cmd)),
                      'command_sha256': hashlib.sha256(_s(e2e_cmd).encode('utf-8')).hexdigest()
                      if _s(e2e_cmd) else None, 'timeout_seconds': e2e_timeout},
              'steps': [], 'escalation': None}
    seq, problems = read_sequence(seq_path, root)
    if seq is not None:
        record['sequence_id'] = _s(seq.get('sequence_id')) or None
    if problems:
        return finish(record, REFUSED_INPUT, 'the sequence was refused before anything was touched: '
                      + '; '.join(problems))
    if not _s(e2e_cmd):
        for i, st in enumerate(seq['steps']):
            record['steps'].append(skeleton(st, i))
        return finish(record, REFUSED_NO_E2E, 'no end-to-end test command was supplied. Tests between '
                      'every step are the rule (KDEC-019 item 4); without them no intermediate state '
                      'can be judged, so nothing was touched')
    steps = list(enumerate(seq['steps']))
    for i, st in steps:
        st['_position'] = i + 1
    order = list(reversed(steps))
    halt, done = None, set()
    for n, (i, st) in enumerate(order, 1):
        if halt:
            record['steps'].append(skeleton(st, i, n))
            continue
        st['_sequence_objects'] = set(done)
        rec, halt = run_step(st, n, len(order), record['sequence_id'], work, e2e_cmd, e2e_timeout,
                             contract)
        record['steps'].append(rec)
        done |= set(e.get('object') for e in st['_ev']['manifest.json'].get('entries') or []
                    if e.get('action') == 'CREATED' and e.get('object'))
    if halt:
        return finish(record, halt[0], halt[1])
    return finish(record, SEQUENCE_VERIFIED, 'every step was eligible, reversed and verified, healthy, '
                  'and passed the end-to-end tests')


def skeleton(st, i, n=None):
    return {'position': i + 1, 'executed_as': n, 'deployment': st.get('deployment') or '',
            'run_id': st.get('run_id') or '', 'run_attempt': st.get('run_attempt') or '',
            'adapter': st.get('adapter') or '', 'target': None, 'started_at': None,
            'finished_at': None, 'eligibility': None,
            'rollback': {'result': 'not-run', 'reversal_path': None, 'not_reversed': []},
            'health': {'result': 'not-run', 'url': None}, 'e2e': {'result': 'not-run', 'exit_code': None},
            'step_result': STEP_NOT_REACHED}


def finish(record, result, why):
    record['result'], record['why'], record['finished_at'] = result, why, now()
    if result != SEQUENCE_VERIFIED:
        record['escalation'] = {
            'resolution_owner': 'platform operations',
            'next_action': {REFUSED_NO_E2E: 'Supply the application\'s end-to-end test command and '
                                            'run the sequence again.',
                            REFUSED_INPUT: 'Correct the sequence or fetch the missing deploy evidence.'}
            .get(result, 'Decide the halted step from this record and its reversal evidence; the '
                         'steps before it are rolled back and verified, the steps after it untouched.'),
            'required_artefacts': ['this record', 'each executed step\'s deploy-evidence and reversal.json'],
            'permitted_agent_action': {'may': dc.MAY, 'may_not': getattr(dc, 'may_not'.upper())}}
    return record


# ----------------------------------------------------------------------------- output
TYPES = {'object': dict, 'array': list, 'string': str, 'boolean': bool, 'null': type(None)}


def _is(node, t):
    if t == 'integer':
        return isinstance(node, int) and not isinstance(node, bool)
    return isinstance(node, TYPES.get(t, object))


def validate(record, schema_path=SCHEMA):
    """-> problems. jsonschema when present; otherwise the subset this schema uses (type lists
    with null, const, enum, required, additionalProperties, items, minimum), applied recursively.
    A runner without jsonschema still validates; it never skips."""
    schema = json.load(io.open(schema_path, encoding='utf-8'))
    try:
        import jsonschema
        v = jsonschema.Draft202012Validator(schema)
        return ['%s: %s' % ('/'.join(str(x) for x in e.path) or '(root)', e.message)
                for e in v.iter_errors(record)]
    except ImportError:
        pass
    out = []

    def walk(node, sch, where):
        types = sch.get('type')
        types = [types] if isinstance(types, str) else list(types or [])
        if types and not any(_is(node, t) for t in types):
            out.append('%s: %r is not %s' % (where, node, '/'.join(types)))
            return
        if 'const' in sch and node != sch['const']:
            out.append('%s: %r is not %r' % (where, node, sch['const']))
        if 'enum' in sch and node not in sch['enum']:
            out.append('%s: %r is not one of %s' % (where, node, sch['enum']))
        if isinstance(node, dict) and ('properties' in sch or 'object' in types):
            for r in sch.get('required', []):
                if r not in node:
                    out.append('%s: %s is required' % (where, r))
            props = sch.get('properties', {})
            for k, val in node.items():
                if k in props:
                    walk(val, props[k], '%s/%s' % (where, k))
                elif sch.get('additionalProperties') is False:
                    out.append('%s: %s is not allowed' % (where, k))
        if isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, sch.get('items', {}), '%s/%d' % (where, i))
        if _is(node, 'integer') and 'minimum' in sch and node < sch['minimum']:
            out.append('%s: %r is below %r' % (where, node, sch['minimum']))
    walk(record, schema, '(root)')
    return out


def summary_lines(r):
    out = ['### Sequential rollback: `%s`' % r['result'], '', r['why'] or '', '',
           'Order: %s. End-to-end tests supplied: %s.' % (r['order'], 'yes' if r['e2e']['supplied'] else 'NO'),
           '', '| # | deployment | eligibility | rollback | health | e2e | step |', '|---|---|---|---|---|---|---|']
    for s in r['steps']:
        el = s.get('eligibility') or {}
        basis = el.get('basis') or el.get('disposition') or 'not judged'
        out.append('| %s | %s | %s | %s | %s | %s | %s |' % (
            s.get('executed_as') or '-', str(s.get('deployment')).replace('|', '/'), basis,
            s['rollback']['result'], s['health']['result'], s['e2e']['result'], s['step_result']))
    return out


def main(argv):
    if argv and argv[0] == '--self-test':
        return self_test()
    ap = argparse.ArgumentParser(description='Sequential rollback with end-to-end tests between steps.')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('run')
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--sequence', help='a sequence file')
    src.add_argument('--sequence-env', help='the (lower-case) name of an environment variable holding '
                     'the sequence JSON -- how the reusable workflow passes its input, as data')
    p.add_argument('--evidence-root', required=True)
    p.add_argument('--work', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--e2e-command', default='')
    p.add_argument('--e2e-timeout-seconds', type=int, default=1800)
    p.add_argument('--summary', default='')
    p.add_argument('--github-output', default='')
    lr = sub.add_parser('list-runs', help='print "run_id run_attempt" per step, for fetching evidence')
    lr.add_argument('--sequence-env', required=True)
    a = ap.parse_args(argv)
    if a.cmd == 'list-runs':
        try:
            seq = json.loads(os.environ.get(a.sequence_env.upper(), ''))
            for st in seq['steps']:
                rid, att = str(st['run_id']).strip(), str(st.get('run_attempt') or '1').strip()
                if not (rid.isdigit() and att.isdigit()):
                    raise ValueError('run_id / run_attempt not numeric')
                print('%s %s' % (rid, att))
        except (ValueError, KeyError, TypeError) as exc:
            print('the sequence is not readable: %s' % exc, file=sys.stderr)
            return 1
        return 0
    os.makedirs(a.work, exist_ok=True)
    seq_path = a.sequence
    if a.sequence_env:
        seq_path = os.path.join(a.work, 'sequence.json')
        io.open(seq_path, 'w', encoding='utf-8').write(os.environ.get(a.sequence_env.upper(), ''))
    record = run(seq_path, a.evidence_root, a.work, a.e2e_command, a.e2e_timeout_seconds)
    problems = validate(record)
    if problems:
        print('::error title=Rollback sequence record invalid::%s' % '; '.join(problems[:5]))
        record = finish(record, record['result'] if record['result'] != SEQUENCE_VERIFIED
                        else HALTED_ROLLBACK, 'the record did not validate against its schema: '
                        + '; '.join(problems[:5]))
    io.open(a.out, 'w', encoding='utf-8').write(json.dumps(record, indent=1, sort_keys=True))
    text = '\n'.join(summary_lines(record))
    print(text)
    if a.summary:
        io.open(a.summary, 'a', encoding='utf-8').write(text + '\n')
    if a.github_output:
        with io.open(a.github_output, 'a', encoding='utf-8') as fh:
            fh.write('sequence_result=%s\n' % record['result'])
            fh.write('steps_verified=%d\n' % sum(1 for s in record['steps'] if s['step_result'] == STEP_VERIFIED))
            fh.write('steps_total=%d\n' % len(record['steps']))
    return 0 if record['result'] == SEQUENCE_VERIFIED else 1


def self_test():
    """Input refusals and the no-e2e refusal touch nothing and need no cloud."""
    work = tempfile.mkdtemp(prefix='rollback-sequence-selftest-')
    fails = []
    try:
        seq = os.path.join(work, 'seq.json')
        io.open(seq, 'w', encoding='utf-8').write(json.dumps(
            {'sequence_id': 's', 'steps': [{'run_id': '1', 'adapter': 'containerapp'}]}))
        r = run(seq, work, work, 'true', 60)
        if r['result'] != REFUSED_INPUT:
            fails.append('missing evidence was not refused: %s' % r['result'])
        ev = os.path.join(work, 'deploy-evidence-1-1')
        os.makedirs(ev)
        for name, body in (('snapshot.json', {'adapter': 'containerapp'}),
                           ('manifest.json', {'release_id': 'run-1-1', 'status': 'applied', 'entries': []}),
                           ('capability.json', {}), ('outcome.json', {})):
            io.open(os.path.join(ev, name), 'w', encoding='utf-8').write(json.dumps(body))
        r = run(seq, work, work, '', 60)
        if r['result'] != REFUSED_NO_E2E or r['steps'][0]['step_result'] != STEP_NOT_REACHED:
            fails.append('no e2e command was not refused before any step: %s' % r['result'])
        if validate(r):
            fails.append('the refusal record does not validate: %s' % validate(r)[:3])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for f in fails:
        print('SELF-TEST FAILED: ' + f)
    if fails:
        return 2
    print('rollback_sequence self-test ok: unreadable evidence and a missing e2e command are refused '
          'before anything is touched; the record validates. The full proof is '
          'tests/prove_rollback_sequence.py.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
