#!/usr/bin/env python3
"""Sequential rollback: several deployments reversed in REVERSE deployment order, with a TEST PERIOD
after EACH step in which the application's health probe and end-to-end tests must keep passing.
(KDEC-019 item 4, owner 2026-10-22, lane L-RB; KDEC-021, owner 2026-10-23, lane L-RB2.)

WHY THIS EXISTS

    Owner, relaying a colleague: "if multiples are required and can be done because nothing else
    touched the resource and/or because the resource was shared but still able to be rolled back
    for that particular application or deployment ... intelligently then we should do end to end
    tests to make sure that between each rollback things still work. He's right."

    Owner, 2026-10-23 (KDEC-021): "There needs to be an end to end test period." -- App Service slots
    "should rollback to the previous code that is being requested" -- "A deployment rolling mid
    rollback means the deployment has to be rolled back."

    Each deploy reusable already reverses ITS OWN failed change, inside its own run
    (scripts/deploy_contract.py `reverse`, ROLLBACK_CONTRACT.md). Nothing reversed SEVERAL standing
    deployments -- several runs' manifests, or several resources of one release -- and nothing
    checked that the application still works between one reversal and the next. Undoing three
    releases back to back and testing only at the end is how a broken intermediate state reaches
    users for the length of the sequence, and how the step that broke it is lost. One test run
    straight after a step is not enough either: a state that passes at minute 0 and fails at minute
    10 (a cache, a queue, a cold dependency) is the state the owner's test period exists to catch.

WHAT A SEQUENCE IS

    A list of deployments in DEPLOYMENT order (oldest first), each named by the run that made it
    and the deploy evidence that run uploaded (`deploy-evidence-<run_id>-<attempt>`: snapshot.json,
    manifest.json, capability.json, outcome.json). It is executed in REVERSE order, newest first,
    because a later release may stand on an earlier one (DCR section 8.1 P6).

    {"sequence_id": "...", ["target_version": "registry/repo@sha256:..." -- the version to return
     to; REQUIRED when any step is App Service],
     "steps": [{"deployment": "label", "run_id": "101", "run_attempt": "1",
                "adapter": "containerapp" | "appservice", ["evidence": "dir under the root"],
                ["health_path": "/health"], ["forward_fix_only": "why reversal is worse"]}]}

PER STEP, IN ORDER -- a step is complete only when all of these hold

    0  NO KIT DEPLOYMENT LANDED SINCE THE SEQUENCE STARTED (KDEC-021 rule 3). The target is re-read
       before every step; a kit-stamped release that was not on it when the sequence started and is
       not in the sequence is a deployment that landed mid-rollback. It is fetched
       (--fetch-evidence-command), put at the FRONT of what remains and rolled back first, with its
       own test period, and recorded as inserted. A deployment whose evidence cannot be fetched or
       read stops the sequence for a human. The reusable freezes deploys to the target while it
       runs (one concurrency group per target, shared with the deploy reusables), so this is the
       backstop for a deploy outside that lock, not the normal path.
    1  ELIGIBLE, decided from a FRESH live read just before the step, against what the run
       recorded (eligibility below). Not eligible: the sequence STOPS BEFORE the step, which is
       ROLLBACK_REQUIRES_HUMAN_DECISION (or ROLLBACK_PROHIBITED for a step declared forward-fix
       only), and nothing of it is touched. A slot or revision changed by an actor OTHER than the
       kit -- no kit stamp -- is always this, with the reason.
    2  REVERSED by the deploy contract itself (deploy_contract.py `reverse`, the same code the
       deploys run), whose per-object preconditions are judged again as it acts. Only
       ROLLBACK_VERIFIED counts; ROLLBACK_PARTIAL or STATUS_UNTRUSTED halts the sequence. Each
       slot (App Service) or the serving traffic (Container Apps) the step affected is then READ
       BACK LIVE and compared with the version it held before that deployment.
    3  THE TEST PERIOD (KDEC-021 rule 1): `--test-period-minutes` (the reusable's setting, default
       15, bounded 0 < m <= 240) long. The health probe, then the caller's end-to-end command
       (`--e2e-command`), run at its START, at each `--check-interval-*` if one is set, and at its
       END. Any failure at any check -- a probe that never answers 200, a test that fails or
       exceeds its bound -- HALTS the sequence for a human there, on the last state it reached:
       ROLLBACK_SEQUENCE_HALTED_HEALTH_FAILED or ROLLBACK_SEQUENCE_HALTED_E2E_FAILED. The final step
       gets its period too: the sequence is never reported verified before it ends. Every check's
       phase, time, offset and result are in the record.
       The command runs with the step named in its environment ($ROLLBACK_STEP,
       $ROLLBACK_STEPS_TOTAL, $ROLLBACK_DEPLOYMENT, $ROLLBACK_ADAPTER, $ROLLBACK_APP_URL,
       $ROLLBACK_SEQUENCE_ID, $ROLLBACK_CHECK_PHASE = start | interval | end) and WITHOUT the deploy
       identity's Azure session (its Azure config directory is an empty one).

    After the last step, the target is read back once more against `target_version` (KDEC-021
    rule 2): what serves production must be the version the request named.

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
    the step stops before it instead of being run to a certain ROLLBACK_PARTIAL. Stacked App
    Service deployments reverse cleanly because each reversal hands the slot's ownership stamp back
    to the release it held before (deploy_contract.py, MODIFIED `prior_stamp`, KDEC-021).

REFUSALS -- BEFORE ANYTHING IS TOUCHED (the fail-safes chosen, and why)

    No `--e2e-command`: ROLLBACK_SEQUENCE_REFUSED_NO_E2E. A health probe is one request, not
    functional validation, and the owner's rule is tests BETWEEN steps; running the reversals anyway
    would be exactly the untested intermediate state the rule forbids.
    A test period of 0 (or none): ROLLBACK_SEQUENCE_REFUSED_NO_TEST_PERIOD -- one instant is not a
    period, the same family. A period past the bound, a negative interval, an App Service sequence
    naming no `target_version`, a `target_version` the target did not hold before the deployments
    being reversed (that would be a deploy, not a rollback), or a step outside the target whose lock
    the reusable holds (`--locked-target`): ROLLBACK_SEQUENCE_REFUSED_INPUT. Refusing touches
    nothing, which is the non-destructive branch: each deploy's own single-run reversal is
    unaffected.

CROSS-EDITED RESOURCES -- `adapter: arm` (KDEC-023, owner 2026-10-23, lane L-RB3)

    A step whose deployment changed Azure resources through ARM (its evidence is `resources.json`,
    scripts/rollback_dependencies.py) is judged by a DEPENDENCY REVIEW instead of the per-adapter
    eligibility: each resource is SHARED_MULTI_CONFIG (only the product's entries are reversed and
    every other entry is read back byte-identical: ROLLBACK_SCOPED_TO_PRODUCT_CONFIG) or STABLE
    (rollback-resource-classes.yaml). A node another actor changed refuses the FULL rollback; the
    nodes independent of it are reversed (ROLLBACK_PARTIAL_DEPENDENCY_CONFLICT, the step
    ROLLBACK_STEP_PARTIAL, its test period still run) or, with none, nothing is
    (ROLLBACK_REFUSED_DEPENDENCY_CONFLICT). Either stops the sequence for a human,
    ROLLBACK_SEQUENCE_STOPPED_DEPENDENCY_CONFLICT, with ROLLBACK_REQUIRES_HUMAN_DECISION as the
    record's rollback_state and the dependency graph (JSON and Mermaid) in the step's record, its
    evidence directory (dependency-graph.json, dependency-graph.mmd) and the run summary. An App
    Service or Container App step changed outside the kit carries a one-node graph the same way.

THE RECORD (schemas/rollback-sequence.schema.json, schema_version 3, validated before it is written)

    One JSON record: the sequence result, why, the test period, the lock, the requested and
    final version, the kit releases on each target when the sequence started, the deployments
    inserted mid-sequence, and every step -- deployment, inserted or not, eligibility basis or
    disposition with the checks that decided it, rollback result, the live read-back of what it
    restored, the test period's checks, timestamps. ROLLBACK_SEQUENCE_VERIFIED only when EVERY
    step is ROLLBACK_STEP_VERIFIED and production is on the requested version.

USAGE
    rollback_sequence.py run --sequence FILE --evidence-root DIR --work DIR --out FILE
                             [--e2e-command CMD] [--e2e-timeout-seconds N]
                             [--test-period-minutes M | --test-period-seconds S]
                             [--check-interval-minutes M | --check-interval-seconds S]
                             [--locked-target RG/NAME] [--fetch-evidence-command CMD]
                             [--summary FILE] [--github-output FILE]
    rollback_sequence.py --self-test

    --fetch-evidence-command runs by /bin/sh (or the platform shell) with $ROLLBACK_FETCH_RUN_ID,
    $ROLLBACK_FETCH_RUN_ATTEMPT and $ROLLBACK_FETCH_DIR set; it must leave the run's deploy
    evidence in that directory. --test-period-seconds is the local form (the proof uses it); the
    reusable passes minutes.

EXIT  0 ROLLBACK_SEQUENCE_VERIFIED   1 refused, stopped or halted (named)   2 usage / self-test
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploy_contract as dc  # noqa: E402
import rollback_dependencies as rd  # noqa: E402

SCHEMA = os.path.join(os.path.dirname(HERE), 'schemas', 'rollback-sequence.schema.json')

# rollback_sequence (assurance-taxonomy.yaml)
SEQUENCE_VERIFIED = 'ROLLBACK_SEQUENCE_VERIFIED'
REFUSED_NO_E2E = 'ROLLBACK_SEQUENCE_REFUSED_NO_E2E'
REFUSED_NO_PERIOD = 'ROLLBACK_SEQUENCE_REFUSED_NO_TEST_PERIOD'
REFUSED_INPUT = 'ROLLBACK_SEQUENCE_REFUSED_INPUT'
STOPPED_INELIGIBLE = 'ROLLBACK_SEQUENCE_STOPPED_INELIGIBLE'
HALTED_ROLLBACK = 'ROLLBACK_SEQUENCE_HALTED_ROLLBACK_UNVERIFIED'
HALTED_HEALTH = 'ROLLBACK_SEQUENCE_HALTED_HEALTH_FAILED'
HALTED_E2E = 'ROLLBACK_SEQUENCE_HALTED_E2E_FAILED'
STOPPED_DEPENDENCY = 'ROLLBACK_SEQUENCE_STOPPED_DEPENDENCY_CONFLICT'
# rollback_sequence_step
STEP_PARTIAL = 'ROLLBACK_STEP_PARTIAL'
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

ADAPTERS = ('containerapp', 'appservice', 'arm')
# The deploy evidence each adapter's step reads.
EVIDENCE = {'arm': ('resources.json', 'outcome.json')}
DEFAULT_EVIDENCE = ('snapshot.json', 'manifest.json', 'capability.json', 'outcome.json')
STEP_KEYS = ('deployment', 'run_id', 'run_attempt', 'adapter', 'evidence', 'health_path',
             'forward_fix_only')
TOP_KEYS = ('sequence_id', 'steps', 'notes', 'target_version')
# KDEC-021 rule 1. The default and the bound of the reusable's `e2e_test_period_minutes`.
DEFAULT_PERIOD_MINUTES = 15
MAX_PERIOD_MINUTES = 240
# How many deployments may land mid-sequence before the sequence stops for a human: past this the
# target is being deployed to faster than it is rolled back, and the freeze is not holding.
MAX_INSERTED = 5
# A kit release id, as the deploy contract stamps it (release_id=run-<run id>-<attempt>).
KIT_RELEASE = re.compile(r'^run-(\d+)-(\d+)$')


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def release_of(st):
    return 'run-%s-%s' % (st['run_id'], st['run_attempt'])


def target_of(st):
    if st.get('adapter') == 'arm':
        t = (st['_ev'].get('resources.json') or {}).get('target') or {}
        return '%s/%s' % (t.get('resource_group', ''), t.get('name', ''))
    snap = st['_ev'].get('snapshot.json') or {}
    return '%s/%s' % (snap.get('resource_group', ''), snap.get('app', ''))


def same_version(requested, have):
    """A requested version names the image by reference (registry/repo@digest) or by digest."""
    if not requested or not have:
        return False
    if '@' in requested:
        return requested == have
    return have.endswith('@' + requested)


# ----------------------------------------------------------------------------- input
FOREIGN = 'ROLLBACK_REFUSED_FOREIGN_EVIDENCE'
PLATFORM_OWNED = rd.PLATFORM_OWNED


def foreign_evidence(st, locked):
    """OF-5 K-5 (KDEC-030): with the seam in force, an `arm` step's resources.json must be the evidence
    of a KIT deploy (release_id run-<id>-<attempt>, no landing-zone producer) of the LOCKED target.
    A landing-zone apply's evidence fed to the kit's rollback would have two systems reversing the
    same entries. -> the refusal text, or None."""
    res = st['_ev'].get('resources.json') or {}
    rel = _s(res.get('release_id'))
    producer = _s(res.get('producer')).lower()
    if not KIT_RELEASE.match(rel):
        return ('%s: resources.json belongs to %r, which is not a kit deploy run (run-<id>-<attempt>) -- a '
                'landing-zone apply\'s evidence is reversed only by the landing zone\'s recovery' % (FOREIGN, rel))
    if producer and (producer.startswith('lz') or 'landing' in producer):
        return '%s: resources.json was produced by %r, not by a kit deploy' % (FOREIGN, res.get('producer'))
    if locked and target_of(st) != locked:
        return ('%s: resources.json is the evidence of %s, not of the locked target %s' % (FOREIGN, target_of(st),
                                                                                              locked))
    return None


def load_step(st, root, where, p, locked=None, seam=False):
    """Read one step's deploy evidence into it. Problems are appended to `p`."""
    for k in st:
        if k not in STEP_KEYS and not k.startswith('_'):
            p.append('%s carries unknown field %r' % (where, k))
    if st.get('adapter') not in ADAPTERS:
        p.append('%s adapter %r is not containerapp, appservice or arm' % (where, st.get('adapter')))
    rid, att = _s(str(st.get('run_id') or '')), _s(str(st.get('run_attempt') or '1'))
    if not rid.isdigit() or not att.isdigit():
        p.append('%s run_id / run_attempt must be the deploying run\'s numbers' % where)
        return False
    st['run_id'], st['run_attempt'] = rid, att
    st.setdefault('deployment', 'run %s attempt %s' % (rid, att))
    d = os.path.join(root, _s(st.get('evidence')) or 'deploy-evidence-%s-%s' % (rid, att))
    ev = {}
    for name in EVIDENCE.get(st.get('adapter'), DEFAULT_EVIDENCE):
        try:
            ev[name] = json.load(io.open(os.path.join(d, name), encoding='utf-8'))
        except (OSError, ValueError) as exc:
            p.append('%s: %s could not be read from %s (%s)' % (where, name, d, exc))
    st['_dir'], st['_ev'] = d, ev
    if seam and st.get('adapter') == 'arm' and ev.get('resources.json') is not None:
        why = foreign_evidence(st, locked)
        if why:
            p.append('%s: %s' % (where, why))
            return True
    man = ev.get('manifest.json') or ev.get('resources.json') or {}
    if man and man.get('release_id') != 'run-%s-%s' % (rid, att):
        p.append('%s: the manifest belongs to %r, not run %s attempt %s' % (
            where, man.get('release_id'), rid, att))
    if st.get('adapter') == 'arm' and ev.get('resources.json') is not None and \
            not isinstance((ev['resources.json'] or {}).get('nodes'), list):
        p.append('%s: resources.json names no nodes' % where)
    snap = ev.get('snapshot.json') or {}
    if snap and snap.get('adapter') not in (None, st.get('adapter')):
        p.append('%s: the evidence is a %s deployment, the step says %s' % (
            where, snap.get('adapter'), st.get('adapter')))
    if locked and snap and target_of(st) != locked:
        p.append('%s: the deployment is on %s, but the lock this rollback holds is for %s -- a '
                 'deploy to %s would not queue behind it' % (where, target_of(st), locked,
                                                             target_of(st)))
    return True


def read_sequence(path, root, locked=None, seam=False):
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
        if k not in TOP_KEYS:
            p.append('unknown top-level field %r (the reader is an allowlist)' % k)
    if 'target_version' in seq and not _s(seq.get('target_version')):
        p.append('target_version is present but empty')
    seen = set()
    for i, st in enumerate(seq['steps']):
        where = 'steps[%d]' % i
        if not isinstance(st, dict):
            p.append('%s is not an object' % where)
            continue
        if not load_step(st, root, where, p, locked, seam):
            continue
        if (st['run_id'], st['run_attempt']) in seen:
            p.append('%s names run %s attempt %s twice' % (where, st['run_id'], st['run_attempt']))
        seen.add((st['run_id'], st['run_attempt']))
    return seq, p


def pre_sequence_version(st):
    """What production served before this (earliest) deployment: App Service production's image;
    the Container App's serving images. -> string ('' when it served nothing)."""
    snap = st['_ev'].get('snapshot.json') or {}
    if st['adapter'] == 'appservice':
        return (snap.get('images') or {}).get('production', '')
    return ','.join(sorted(set(_ca_snapshot_serving(snap))))


def _ca_snapshot_serving(snap):
    revs = snap.get('revisions') or {}
    out = []
    for t in snap.get('traffic') or []:
        if (t.get('weight') or 0) <= 0:
            continue
        n = snap.get('latest_revision') if t.get('latestRevision') else t.get('revisionName')
        out.append((revs.get(n) or {}).get('image', ''))
    return out


def check_target_version(seq):
    """KDEC-021 rule 2: the request names the version to return to, and it must be the version each
    target held before the deployments being reversed. -> problems."""
    want = _s(seq.get('target_version'))
    # An ARM step returns each resource to its recorded prior body; it has no image version.
    steps = [st for st in seq['steps'] if isinstance(st, dict) and st.get('_ev') and st.get('adapter') != 'arm']
    if not want:
        if any(st.get('adapter') == 'appservice' for st in steps):
            return ['target_version is missing: an App Service rollback restores each slot it '
                    'affected to the version the request names, so the request must name it']
        return []
    p = []
    earliest = {}
    for st in steps:
        earliest.setdefault(target_of(st), st)    # steps are oldest first
    for tgt, st in sorted(earliest.items()):
        have = pre_sequence_version(st)
        if not all(same_version(want, h) for h in (have.split(',') if have else [''])):
            p.append('target_version %s is not what %s held before the deployments being reversed '
                     '(%s); returning it to a version it did not hold would be a deploy, not a '
                     'rollback' % (want, tgt, have or 'nothing'))
    return p


# ----------------------------------------------------------------------------- environment
def step_env(st):
    """The deploy contract reads its target from the environment, as in the deploy job."""
    if st['adapter'] == 'arm':
        t = (st['_ev'].get('resources.json') or {}).get('target') or {}
        return {'resource_group'.upper(): t.get('resource_group', ''),
                'github_run_id'.upper(): st['run_id'], 'github_run_attempt'.upper(): st['run_attempt'],
                'health_path'.upper(): st.get('health_path') or '/health'}
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


# ----------------------------------------------------------------------------- kit releases live
def _slots_of(st):
    snap = st['_ev'].get('snapshot.json') or {}
    slots = set((snap.get('images') or {}).keys()) | {'production'}
    for e in (st['_ev'].get('manifest.json') or {}).get('entries') or []:
        if e.get('action') == 'REDIRECTED' and e.get('from_slot'):
            slots.add(e['from_slot'])
    return sorted(slots)


def live_kit_releases(st):
    """-> {release_id: newest-first sort key} of the KIT releases standing on the step's target
    now, or None when it cannot be read. The caller has set the step's environment. Container Apps:
    the stamp of every ACTIVE revision; App Service: the stamp on every slot the step names. A
    stamp that is not a kit release id is another actor's, and is left to eligibility."""
    out = {}
    if st['adapter'] == 'arm':
        return arm_kit_releases(st)
    if st['adapter'] == 'containerapp':
        ok, revs, _ = dc.az('containerapp', 'revision', 'list', '-n', dc.env('containerapp_name'),
                            '-g', dc.env('resource_group'), '--all')
        if not ok or not isinstance(revs, list):
            return None
        for r in revs:
            props = r.get('properties') or {}
            if not props.get('active'):
                continue
            rel = dc._stamp_release(dc._rev_stamp(props))
            m = KIT_RELEASE.match(rel or '')
            if m:
                out[rel] = (int(m.group(1)), int(m.group(2)))
        return out
    for slot in _slots_of(st):
        rel = _slot_stamp(slot)
        if rel is None:
            return None
        m = KIT_RELEASE.match(rel)
        if m:
            out[rel] = (int(m.group(1)), int(m.group(2)))
    return out


def arm_kit_releases(st):
    """The kit stamps on the STABLE resources an ARM step names (entries carry no tags). A resource
    that is gone is left to the review; one that cannot be read makes the target unreadable."""
    reg = rd.load_registry()
    out = {}
    for n in (st['_ev'].get('resources.json') or {}).get('nodes') or []:
        info = rd.resolve(reg, n.get('id', ''))
        if info['entry'] or info['class'] is None:
            continue
        state, body = rd.arm_get(n['id'], rd.api_version(info))
        if state == 'error':
            return None
        rel = rd._stamp_of(body) if state == 'ok' else ''
        m = KIT_RELEASE.match(rel or '')
        if m:
            out[rel] = (int(m.group(1)), int(m.group(2)))
    return out


def all_kit_releases(st):
    """The baseline: every kit release on the target when the sequence starts (inactive Container
    App revisions included -- they were there before the sequence, so they did not land during it)."""
    if st['adapter'] != 'containerapp':
        return live_kit_releases(st)
    ok, revs, _ = dc.az('containerapp', 'revision', 'list', '-n', dc.env('containerapp_name'),
                        '-g', dc.env('resource_group'), '--all')
    if not ok or not isinstance(revs, list):
        return None
    return dict((rel, 0) for rel in (dc._stamp_release(dc._rev_stamp(r.get('properties') or {}))
                                     for r in revs) if KIT_RELEASE.match(rel or ''))


def fetch_evidence(rid, att, root, cmd):
    """Fetch a mid-sequence deployment's evidence into the evidence root. -> (dir name, problem)."""
    name = 'deploy-evidence-%s-%s' % (rid, att)
    d = os.path.join(root, name)
    if os.path.isdir(d):
        return name, None
    if not _s(cmd):
        return name, ('no way to fetch its deploy evidence was given (--fetch-evidence-command), '
                      'and %s is not in the evidence root' % name)
    env = dict(os.environ)
    env.update({'rollback_fetch_run_id'.upper(): rid, 'rollback_fetch_run_attempt'.upper(): att,
                'rollback_fetch_dir'.upper(): d})
    p = subprocess.run(cmd, shell=True, env=env, capture_output=True, text=True,  # noqa: S602
                       encoding='utf-8', errors='replace')
    sys.stdout.write(p.stdout)
    if p.returncode != 0 or not os.path.isdir(d):
        return name, 'its deploy evidence (%s) could not be fetched (exit %d): %s' % (
            name, p.returncode, (p.stderr or '').strip()[-300:])
    return name, None


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
                          'someone else claims it -- changed by an actor other than the kit'
                          % (ours, stamp or 'nobody', release), checks)
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
                          'graph cannot be read -- changed by an actor other than the kit', checks)
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
                if KIT_RELEASE.match(stamp):
                    return ineligible(HUMAN, 'P6 order', 'slot %s carries kit release %s\'s stamp, '
                                      'not %s: a later kit deployment that was already standing '
                                      'when the sequence started and is not in it -- list it in '
                                      'the sequence' % (slot, stamp, release), checks)
                return ineligible(HUMAN, 'P1 ownership', 'slot %s carries the stamp of %r, not %s: '
                                  'it was changed by an actor other than the kit'
                                  % (slot, stamp or 'nobody', release), checks)
            if live != want[slot]:
                return ineligible(HUMAN, 'P2 version', 'slot %s holds %s, not the %s this run left, '
                                  'while still under this run\'s stamp: it was changed by an actor '
                                  'other than the kit' % (slot, live or 'nothing', want[slot]), checks)
            held('P1 P2 %s' % slot, '%s holds what this run left, under its stamp' % slot, checks)
        elif live != want[slot]:
            return ineligible(HUMAN, 'untouched', 'slot %s, which this run did not change, moved (%s '
                              'is now %s) -- changed by an actor other than the kit; the reversal '
                              'verifies every slot it captured, so it could not be verified '
                              'complete' % (slot, want[slot], live or 'nothing'), checks)
    held('untouched', 'every captured slot holds what this run left', checks)
    return {'eligible': True, 'basis': UNTOUCHED, 'disposition': None,
            'why': 'nothing else touched the app since this deployment', 'checks': checks}


# ----------------------------------------------------------------------------- one step
def app_url(adapter, st=None):
    if adapter == 'arm':
        return _s(((st or {}).get('_ev', {}).get('resources.json') or {}).get('app_url')).rstrip('/')
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


def read_back(st):
    """KDEC-021 rule 2: read live what the step restored, against what it held before this
    deployment. App Service: every slot the step affected (production, the deploy slot, and the
    slot a swap moved images through). Container Apps: the images serving traffic."""
    snap = st['_ev'].get('snapshot.json') or {}
    out = []
    if st['adapter'] == 'appservice':
        images = snap.get('images') or {}
        for slot in _slots_of(st):
            want = images.get(slot)
            if want is None:
                continue
            live = dc.appservice_slot_image(slot)
            out.append({'slot': slot, 'want': want, 'live': live, 'held': live == want})
        return out
    serving = dc.containerapp_serving()
    want = ','.join(sorted(set(_ca_snapshot_serving(snap))))
    live = None if serving is None else ','.join(sorted(set(s['image'] for s in serving)))
    return [{'slot': 'serving traffic', 'want': want, 'live': live, 'held': live == want}]


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


def period_plan(period, interval):
    """-> [(phase, offset seconds)]: start, every interval strictly inside the period, end."""
    plan = [('start', 0.0)]
    if interval and interval > 0:
        k = 1
        while interval * k < period - 1e-9:
            plan.append(('interval', interval * k))
            k += 1
    plan.append(('end', float(period)))
    return plan


def test_period(st, n, total, seq_id, url, cfg):
    """KDEC-021 rule 1. -> (period record, None | (kind, check)). Stops at the first failure."""
    rec = {'seconds': cfg['period'], 'interval_seconds': cfg['interval'], 'started_at': now(),
           'ended_at': None, 'checks': []}
    t0 = time.time()
    failure = None
    for phase, offset in period_plan(cfg['period'], cfg['interval']):
        wait = t0 + offset - time.time()
        if wait > 0:
            time.sleep(wait)
        c = {'phase': phase, 'at': now(), 'offset_seconds': round(time.time() - t0, 3),
             'health': 'not-run', 'e2e': 'not-run', 'exit_code': None}
        good = bool(url) and dc.probe(url + (st.get('health_path') or '/health'))
        c['health'] = 'passed' if good else 'failed'
        if not good:
            rec['checks'].append(c)
            failure = ('health', c)
            break
        extra = {'rollback_step': str(n), 'rollback_steps_total': str(total),
                 'rollback_deployment': st['deployment'], 'rollback_adapter': st['adapter'],
                 'rollback_app_url': url, 'rollback_sequence_id': seq_id or '',
                 'rollback_check_phase': phase}
        res, code = end_to_end(cfg['e2e_cmd'], cfg['e2e_timeout'],
                               dict((k.upper(), v) for k, v in extra.items()))
        c['e2e'], c['exit_code'] = res, code
        rec['checks'].append(c)
        if res != 'passed':
            failure = ('e2e', c)
            break
    rec['ended_at'] = now()
    return rec, failure


def new_step_record(st, n):
    return {'position': st['_position'], 'executed_as': n, 'deployment': st['deployment'],
            'run_id': st['run_id'], 'run_attempt': st['run_attempt'], 'adapter': st['adapter'],
            'target': ((st['_ev'].get('snapshot.json') or {}).get('app') or
                       ((st['_ev'].get('resources.json') or {}).get('target') or {}).get('name') or None),
            'inserted': bool(st.get('_inserted_because')),
            'inserted_because': st.get('_inserted_because'),
            'started_at': now(), 'finished_at': None, 'eligibility': None,
            'rollback': {'result': 'not-run', 'reversal_path': None, 'not_reversed': []},
            'restored': [], 'health': {'result': 'not-run', 'url': None},
            'e2e': {'result': 'not-run', 'exit_code': None}, 'test_period': None,
            'dependency_review': None, 'step_result': STEP_NOT_REACHED}


def run_period(st, n, total, seq_id, cfg, rec, label, what='rolled back and verified'):
    """The test period after a reversal (KDEC-021 rule 1), into `rec`. -> halt or None."""
    url = app_url(st['adapter'], st)
    rec['health']['url'] = url or None
    period, failure = test_period(st, n, total, seq_id, url, cfg)
    rec['test_period'] = period
    checks = period['checks']
    rec['health']['result'] = 'failed' if any(c['health'] == 'failed' for c in checks) else 'passed'
    last = checks[-1] if checks else {}
    if failure and failure[0] == 'e2e':
        e2e_result = failure[1]['e2e']
    else:
        e2e_result = 'passed' if any(c['e2e'] == 'passed' for c in checks) else 'not-run'
    rec['e2e'] = {'result': e2e_result, 'exit_code': last.get('exit_code')}
    if failure and failure[0] == 'health':
        c = failure[1]
        return (HALTED_HEALTH, '%s: %s, but at the %s check of its test period (%.0f s in) the health '
                'probe on %s never answered 200; the end-to-end tests were not run on it. The sequence '
                'halts here for a human decision' % (label, what, c['phase'], c['offset_seconds'],
                                                     url or 'no host'))
    if failure:
        c = failure[1]
        return (HALTED_E2E, '%s: %s and healthy, but at the %s check of its test period (%.0f s in) the '
                'end-to-end tests %s%s. The sequence halts here for a human decision; it never '
                'continues on a broken intermediate state' % (
                    label, what, c['phase'], c['offset_seconds'], c['e2e'],
                    '' if c['exit_code'] is None else ' (exit %d)' % c['exit_code']))
    return None


def run_step(st, n, total, seq_id, work, cfg, contract):
    if st['adapter'] == 'arm':
        return run_arm_step(st, n, total, seq_id, work, cfg)
    rec = new_step_record(st, n)
    step_dir = os.path.join(work, 'step-%02d' % n)
    ev = os.path.join(step_dir, 'deploy-evidence')
    os.makedirs(ev, exist_ok=True)
    # A COPY of what the deploying run recorded: the deploy contract reads its manifest from here
    # (the run's own record is never written to) and writes this step's reversal.json beside it.
    for name in ('snapshot.json', 'manifest.json', 'capability.json'):
        shutil.copyfile(os.path.join(st['_dir'], name), os.path.join(ev, name))
    halt = None
    label = 'step %d (%s)' % (n, st['deployment'])
    with environment(step_env(st), step_dir):
        el = eligibility(st)
        rec['eligibility'] = el
        if not el['eligible']:
            rec['step_result'] = STEP_INELIGIBLE
            if 'other than the kit' in el['why']:
                # KDEC-023: a stable resource changed by another actor -- the whole release is this
                # one resource, so the review is one node, refused, with its reason.
                rec['dependency_review'] = write_graph(
                    rd.single(st['adapter'], target_of(st), el['why']), step_dir)
            halt = (STOPPED_INELIGIBLE, '%s is not eligible -- %s: %s. Stopped BEFORE it; nothing of '
                    'it was touched' % (label, el['disposition'], el['why']))
        else:
            rv = reverse(st, step_dir, contract)
            rec['rollback'] = {'result': (rv or {}).get('result') or 'STATUS_UNTRUSTED',
                               'reversal_path': (rv or {}).get('reversal_path'),
                               'not_reversed': (rv or {}).get('not_reversed') or []}
            if rec['rollback']['result'] != VERIFIED:
                halt = (HALTED_ROLLBACK, '%s: the reversal is %s, not %s -- a partial rollback is '
                        'never verified' % (label, rec['rollback']['result'], VERIFIED))
            else:
                rec['restored'] = read_back(st)
                bad = [x for x in rec['restored'] if not x['held']]
                if bad:
                    halt = (HALTED_ROLLBACK, '%s: verified by the deploy contract, but the live read '
                            'back does not hold: %s' % (label, '; '.join(
                                '%s is %s, not %s' % (x['slot'], x['live'], x['want']) for x in bad)))
            if not halt:
                halt = run_period(st, n, total, seq_id, cfg, rec, label)
            rec['step_result'] = STEP_HALTED if halt else STEP_VERIFIED
    rec['finished_at'] = now()
    return rec, halt


def write_graph(review, step_dir):
    """The dependency graph into the step's evidence (uploaded with the rollback work directory):
    dependency-graph.json and dependency-graph.mmd. -> the review, with graph_path set."""
    try:
        os.makedirs(step_dir, exist_ok=True)
        io.open(os.path.join(step_dir, 'dependency-graph.json'), 'w', encoding='utf-8').write(json.dumps(
            {'outcome': review['outcome'], 'nodes': review['nodes'], 'edges': review['edges']},
            indent=1, sort_keys=True))
        io.open(os.path.join(step_dir, 'dependency-graph.mmd'), 'w', encoding='utf-8').write(
            review['mermaid'] + '\n')
        review['graph_path'] = os.path.basename(step_dir) + '/dependency-graph.json'
    except OSError:
        review['graph_path'] = None
    return review


def run_arm_step(st, n, total, seq_id, work, cfg):
    """KDEC-023: a step that changed Azure resources through ARM, judged by the dependency review."""
    rec = new_step_record(st, n)
    step_dir = os.path.join(work, 'step-%02d' % n)
    ev_dir = os.path.join(step_dir, 'deploy-evidence')
    os.makedirs(ev_dir, exist_ok=True)
    shutil.copyfile(os.path.join(st['_dir'], 'resources.json'), os.path.join(ev_dir, 'resources.json'))
    label = 'step %d (%s)' % (n, st['deployment'])
    halt, rv = None, None
    reg = rd.load_registry()
    with environment(step_env(st), step_dir):
        outcome = (st['_ev'].get('outcome.json') or {}).get('deployment_outcome')
        if _s(st.get('forward_fix_only')):
            el = ineligible(PROHIBITED, 'forward-fix only', 'declared forward-fix only: %s'
                            % _s(st['forward_fix_only']), [])
        elif outcome != 'DEPLOY_HEALTHY':
            el = ineligible(HUMAN, 'a standing deployment', 'the deployment\'s own outcome was %r, so it '
                            'is not a standing deployment to reverse' % outcome, [])
        else:
            rv = rd.review(st['_ev']['resources.json'], reg, st.get('_sequence_releases') or (),
                           seam=cfg.get('seam', False))
            free = [n for n in rv['_nodes'].values() if n.get('decision') == 'reverse']
            checks = [{'check': 'a standing deployment', 'held': True, 'detail': 'the deploy reported DEPLOY_HEALTHY'},
                      {'check': 'dependency review', 'held': rv['outcome'] in (rd.CLEAR, rd.SCOPED),
                       'detail': '%s: %s' % (rv['outcome'], rv['why'])}]
            el = {'eligible': rv['outcome'] != rd.REFUSED and (rv['outcome'] != PLATFORM_OWNED or bool(free)),
                  'basis': rv['basis'],
                  'disposition': HUMAN if rv['outcome'] in (rd.PARTIAL, rd.REFUSED, PLATFORM_OWNED) else None,
                  'why': rv['why'], 'checks': checks}
        rec['eligibility'] = el
        if not el['eligible']:
            rec['step_result'] = STEP_INELIGIBLE
            halt = ((STOPPED_DEPENDENCY if rv else STOPPED_INELIGIBLE),
                    '%s is not eligible -- %s: %s. Stopped BEFORE it; nothing of it was touched'
                    % (label, el['disposition'], el['why']))
        else:
            result = rd.reverse(rv, reg)
            held_ = result == (VERIFIED if rv['outcome'] in (rd.CLEAR, rd.SCOPED) else 'ROLLBACK_PARTIAL') \
                and all(r['applied'] and r['verified'] for r in rv['reversed']) \
                and all(o['identical'] for o in rv['others_untouched'])
            rec['rollback'] = {'result': result, 'reversal_path': 'arm (rollback_dependencies.py)',
                               'not_reversed': rv['not_reversed']}
            rec['restored'] = [{'slot': r['id'], 'want': 'absent' if r['op'].startswith('delete') else 'prior',
                                'live': r.get('live'), 'held': bool(r['applied'] and r['verified'])}
                               for r in rv['reversed']]
            io.open(os.path.join(ev_dir, 'reversal.json'), 'w', encoding='utf-8').write(json.dumps(
                {'result': result, 'reversed': rv['reversed'], 'not_reversed': rv['not_reversed'],
                 'others_untouched': rv['others_untouched'], 'problems': rv.get('problems') or []},
                indent=1, sort_keys=True))
            if not held_:
                bad = [r['id'] for r in rv['reversed'] if not (r['applied'] and r['verified'])] + \
                      [o['id'] for o in rv['others_untouched'] if not o['identical']]
                halt = (HALTED_ROLLBACK, '%s: the reversal of the nodes the review freed did not hold '
                        '(%s): %s' % (label, result, ', '.join(bad) or '; '.join(rv.get('problems') or [])))
            else:
                what = 'rolled back and verified' if rv['outcome'] in (rd.CLEAR, rd.SCOPED) else \
                    'partly rolled back (the parts independent of the cross-edit, verified)'
                halt = run_period(st, n, total, seq_id, cfg, rec, label, what)
                if not halt and rv['outcome'] in (rd.PARTIAL, PLATFORM_OWNED):
                    halt = (STOPPED_DEPENDENCY, '%s: %s. Reversed and verified: %s. Left for a human '
                            'decision: %s. The test period passed on that state; nothing after it was '
                            'touched' % (label, rv['why'], ', '.join(r['id'].rsplit('/', 1)[-1] for r in rv['reversed'])
                                         or 'nothing', '; '.join('%s (%s)' % (x['id'].rsplit('/', 1)[-1], x['reason'])
                                                                 for x in rv['not_reversed'])))
                    rec['step_result'] = STEP_PARTIAL
            if rec['step_result'] != STEP_PARTIAL:
                rec['step_result'] = STEP_HALTED if halt else STEP_VERIFIED
        if rv is not None:
            rec['dependency_review'] = write_graph(rd.public(rv), step_dir)
    rec['finished_at'] = now()
    return rec, halt


def inserted_step(rel, adapter, health_path, root, cmd, locked, position, at):
    """A kit deployment that landed mid-sequence, as a step. -> (step, problems)."""
    m = KIT_RELEASE.match(rel)
    rid, att = m.group(1), m.group(2)
    st = {'deployment': 'run %s attempt %s (landed mid-sequence)' % (rid, att), 'run_id': rid,
          'run_attempt': att, 'adapter': adapter, 'health_path': health_path,
          '_position': position,
          '_inserted_because': 'kit release %s was not on the target when the sequence started '
                               'and appeared on it before %s; it is rolled back first' % (rel, at)}
    name, problem = fetch_evidence(rid, att, root, cmd)
    if problem:
        st['_ev'] = {}
        return st, [problem]
    p = []
    load_step(st, root, 'the deployment that landed mid-sequence', p, locked)
    st['evidence'] = name
    return st, p


def blocked_step_record(st, n, why):
    rec = new_step_record(dict(st, _ev=st.get('_ev') or {}), n)
    rec['eligibility'] = ineligible(HUMAN, 'mid-sequence deployment', why, [])
    rec['step_result'] = STEP_INELIGIBLE
    rec['finished_at'] = now()
    return rec


# ----------------------------------------------------------------------------- the sequence
def run(seq_path, root, work, e2e_cmd, e2e_timeout, contract=None, period=None, interval=0.0,
        period_minutes=None, locked=None, fetch_cmd='', seam=False):
    """`period` in seconds; `period_minutes` is the reusable's form and wins when given; with
    neither, the default (DEFAULT_PERIOD_MINUTES)."""
    contract = contract or os.path.join(HERE, 'deploy_contract.py')
    if period_minutes is not None:
        period = float(period_minutes) * 60
    elif period is None:
        period = DEFAULT_PERIOD_MINUTES * 60.0
    started = now()
    record = {'schema_version': 3, 'sequence_id': None, 'rollback_state': None, 'started_at': started, 'finished_at': None,
              'result': None, 'why': None, 'order': 'reverse of deployment order (newest first)',
              'e2e': {'supplied': bool(_s(e2e_cmd)),
                      'command_sha256': hashlib.sha256(_s(e2e_cmd).encode('utf-8')).hexdigest()
                      if _s(e2e_cmd) else None, 'timeout_seconds': e2e_timeout},
              'test_period': {'seconds': period, 'interval_seconds': interval or 0,
                              'checks_at': 'start, %send' % ('every %g s, ' % interval
                                                             if interval else '')},
              'lock': {'target': locked} if locked else None,
              'target_version': None, 'final_version': None, 'baseline': {}, 'inserted': [],
              'steps': [], 'escalation': None}
    seq, problems = read_sequence(seq_path, root, locked, seam)
    if seq is not None:
        record['sequence_id'] = _s(seq.get('sequence_id')) or None
        record['target_version'] = _s(seq.get('target_version')) or None
        if not problems:
            problems = check_target_version(seq)
    if period > MAX_PERIOD_MINUTES * 60:
        problems = list(problems) + ['the test period (%g minutes) is past the %d-minute bound'
                                     % (period / 60, MAX_PERIOD_MINUTES)]
    if interval is not None and interval < 0:
        problems = list(problems) + ['the check interval is negative']
    if problems:
        return finish(record, REFUSED_INPUT, 'the sequence was refused before anything was touched: '
                      + '; '.join(problems))
    skeletons = [skeleton(st, i) for i, st in enumerate(seq['steps'])]
    if not _s(e2e_cmd):
        record['steps'] = skeletons
        return finish(record, REFUSED_NO_E2E, 'no end-to-end test command was supplied. Tests between '
                      'every step are the rule (KDEC-019 item 4); without them no intermediate state '
                      'can be judged, so nothing was touched')
    if not period or period <= 0:
        record['steps'] = skeletons
        return finish(record, REFUSED_NO_PERIOD, 'the end-to-end test period is 0. A test period '
                      'after every step is the rule (KDEC-021: "There needs to be an end to end test '
                      'period"); one instant is not a period, so nothing was touched')
    cfg = {'period': period, 'interval': interval or 0, 'e2e_cmd': e2e_cmd, 'e2e_timeout': e2e_timeout,
           'seam': seam}
    for i, st in enumerate(seq['steps']):
        st['_position'] = i + 1
    queue = list(reversed(seq['steps']))
    known = set(release_of(st) for st in seq['steps'])
    # The baseline: the kit releases standing on each target when the sequence starts.
    for st in seq['steps']:
        tgt = target_of(st)
        if tgt in record['baseline']:
            continue
        with environment(step_env(st), work):
            rels = all_kit_releases(st)
        if rels is None:
            record['steps'] = skeletons
            return finish(record, STOPPED_INELIGIBLE, 'the target %s could not be read when the '
                          'sequence started, so a deployment landing during it could not be told '
                          'apart; nothing was touched' % tgt)
        record['baseline'][tgt] = sorted(rels)
    halt, done, n = None, set(), 0
    while queue:
        st = queue[0]
        if halt:
            record['steps'].append(skeleton(st, st['_position'] - 1, None))
            queue.pop(0)
            continue
        # KDEC-021 rule 3(b): re-read the target before every step.
        with environment(step_env(st), work):
            live = live_kit_releases(st)
        if live is None:
            record['steps'].append(blocked_step_record(st, n + 1, 'the target could not be read '
                                                       'before the step'))
            halt = (STOPPED_INELIGIBLE, 'the target %s could not be read before step %d; nothing '
                    'more was touched' % (target_of(st), n + 1))
            queue.pop(0)
            continue
        landed = sorted((rel for rel in live
                         if rel not in known and rel not in record['baseline'].get(target_of(st), [])),
                        key=lambda rel: live[rel], reverse=True)
        if landed:
            if len(record['inserted']) + len(landed) > MAX_INSERTED:
                halt = (STOPPED_INELIGIBLE, 'more than %d kit deployments landed on %s during the '
                        'sequence (%s): the deploy freeze is not holding; stopped for a human'
                        % (MAX_INSERTED, target_of(st), ', '.join(landed)))
                continue
            new = []
            top = max([s['_position'] for s in seq['steps']] +
                      [s['_position'] for s in queue] + [0])
            for k, rel in enumerate(landed):
                ins, p = inserted_step(rel, st['adapter'], st.get('health_path'), root, fetch_cmd,
                                       locked, top + len(landed) - k,
                                       'step %d (%s)' % (n + 1, st['deployment']))
                known.add(rel)
                record['inserted'].append(rel)
                if p:
                    n += 1
                    record['steps'].append(blocked_step_record(
                        ins, n, 'kit release %s landed on %s mid-sequence, and %s' % (
                            rel, target_of(st), '; '.join(p))))
                    halt = (STOPPED_INELIGIBLE, 'kit release %s landed on %s mid-sequence and has to '
                            'be rolled back first, but %s. Stopped for a human; nothing after it was '
                            'touched' % (rel, target_of(st), '; '.join(p)))
                    break
                new.append(ins)
            if not halt:
                queue[0:0] = new
            continue
        queue.pop(0)
        n += 1
        st['_sequence_objects'] = set(done)
        st['_sequence_releases'] = set(known)
        rec, halt = run_step(st, n, n + len(queue), record['sequence_id'], work, cfg, contract)
        record['steps'].append(rec)
        done |= set(e.get('object') for e in (st['_ev'].get('manifest.json') or {}).get('entries') or []
                    if e.get('action') == 'CREATED' and e.get('object'))
    if halt:
        return finish(record, halt[0], halt[1])
    if record['target_version']:
        fv = final_version(seq, record['target_version'], work)
        record['final_version'] = fv
        if not fv['held']:
            return finish(record, HALTED_ROLLBACK, 'every step was verified, but production is not on '
                          'the requested version %s: %s' % (record['target_version'], '; '.join(
                              '%s serves %s' % (t['target'], t['live']) for t in fv['targets'])))
    return finish(record, SEQUENCE_VERIFIED, 'every step was eligible, reversed and verified, healthy, '
                  'and passed the end-to-end tests at every check of its test period%s' % (
                      ' (%d deployment(s) that landed mid-sequence rolled back first)'
                      % len(record['inserted']) if record['inserted'] else '') +
                  ('; production is on the requested version' if record['target_version'] else ''))


def final_version(seq, want, work):
    """Read each target's production version live after the last step (KDEC-021 rule 2)."""
    earliest = {}
    for st in seq['steps']:
        if st.get('adapter') != 'arm':   # an ARM step has no image version; its review read it back
            earliest.setdefault(target_of(st), st)
    targets = []
    for tgt, st in sorted(earliest.items()):
        with environment(step_env(st), work):
            if st['adapter'] == 'appservice':
                live = dc.appservice_slot_image('production')
            else:
                serving = dc.containerapp_serving()
                live = None if serving is None else ','.join(sorted(set(s['image'] for s in serving)))
        ok = live is not None and all(same_version(want, x) for x in (live.split(',') if live else ['']))
        targets.append({'target': tgt, 'live': live, 'held': ok})
    return {'requested': want, 'live': targets[0]['live'] if len(targets) == 1 else
            ','.join(str(t['live']) for t in targets),
            'held': bool(targets) and all(t['held'] for t in targets), 'targets': targets}


def skeleton(st, i, n=None):
    return {'position': (st.get('_position') or i + 1) if isinstance(st, dict) else i + 1,
            'executed_as': n, 'deployment': st.get('deployment') or '',
            'run_id': st.get('run_id') or '', 'run_attempt': st.get('run_attempt') or '',
            'adapter': st.get('adapter') or '', 'target': None,
            'inserted': bool(st.get('_inserted_because')),
            'inserted_because': st.get('_inserted_because'), 'started_at': None,
            'finished_at': None, 'eligibility': None,
            'rollback': {'result': 'not-run', 'reversal_path': None, 'not_reversed': []},
            'restored': [], 'health': {'result': 'not-run', 'url': None},
            'e2e': {'result': 'not-run', 'exit_code': None}, 'test_period': None,
            'dependency_review': None, 'step_result': STEP_NOT_REACHED}


def rollback_state(record, result):
    """rollback_state (assurance-taxonomy.yaml) for the sequence as a whole. A refusal before
    anything was touched decides nothing (null: correct the input); a verified sequence is
    ROLLBACK_VERIFIED; a step declared forward-fix only is ROLLBACK_PROHIBITED; every other stop or
    halt leaves a state a PERSON must decide -- ROLLBACK_REQUIRES_HUMAN_DECISION (KDEC-023: the
    census found this value was never emitted)."""
    if result == SEQUENCE_VERIFIED:
        return VERIFIED
    if result in (REFUSED_NO_E2E, REFUSED_NO_PERIOD, REFUSED_INPUT):
        return None
    if any(((s.get('eligibility') or {}).get('disposition') == PROHIBITED) for s in record['steps']):
        return PROHIBITED
    return HUMAN


def finish(record, result, why):
    record['result'], record['why'], record['finished_at'] = result, why, now()
    record['rollback_state'] = rollback_state(record, result)
    if result == STOPPED_DEPENDENCY:
        record['escalation'] = {
            'resolution_owner': 'platform operations, with the owners of the resources left',
            'next_action': 'Read the step\'s dependency review and graph: each node left was changed by '
                           'another actor, or depends on (or is evaluated together with) one that was. '
                           'Decide those with whoever changed them; what the review freed is already '
                           'reversed and verified, and the steps after it are untouched.',
            'required_artefacts': ['this record', 'the step\'s dependency-graph.json and .mmd',
                                   'the step\'s reversal.json'],
            'permitted_agent_action': {'may': dc.MAY, 'may_not': getattr(dc, 'may_not'.upper())}}
        return record
    if result != SEQUENCE_VERIFIED:
        record['escalation'] = {
            'resolution_owner': 'platform operations',
            'next_action': {REFUSED_NO_E2E: 'Supply the application\'s end-to-end test command and '
                                            'run the sequence again.',
                            REFUSED_NO_PERIOD: 'Set a test period greater than 0 (the default is %d '
                                               'minutes) and run the sequence again.'
                                               % DEFAULT_PERIOD_MINUTES,
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
    if t == 'number':
        return isinstance(node, (int, float)) and not isinstance(node, bool)
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
        if _is(node, 'number') and 'minimum' in sch and node < sch['minimum']:
            out.append('%s: %r is below %r' % (where, node, sch['minimum']))
    walk(record, schema, '(root)')
    return out


def summary_lines(r):
    tp = r.get('test_period') or {}
    out = ['### Sequential rollback: `%s`' % r['result'], '', r['why'] or '', '',
           'Order: %s. End-to-end tests supplied: %s. Test period after each step: %s s (checks at %s).'
           % (r['order'], 'yes' if r['e2e']['supplied'] else 'NO', tp.get('seconds'), tp.get('checks_at')),
           'Lock held for: %s. Requested version: %s. Inserted mid-sequence: %s.'
           % ((r.get('lock') or {}).get('target') or 'none', r.get('target_version') or 'not named',
              ', '.join(r.get('inserted') or []) or 'none'),
           '', '| # | deployment | eligibility | rollback | health | e2e checks | step |',
           '|---|---|---|---|---|---|---|']
    for s in r['steps']:
        el = s.get('eligibility') or {}
        basis = el.get('basis') or el.get('disposition') or 'not judged'
        checks = ((s.get('test_period') or {}).get('checks') or [])
        e2e = ', '.join('%s %s' % (c['phase'], c['e2e']) for c in checks) or s['e2e']['result']
        out.append('| %s | %s%s | %s | %s | %s | %s | %s |' % (
            s.get('executed_as') or '-', str(s.get('deployment')).replace('|', '/'),
            ' (inserted)' if s.get('inserted') else '', basis, s['rollback']['result'],
            s['health']['result'], e2e, s['step_result']))
    out += ['', 'rollback_state: `%s`.' % (r.get('rollback_state') or 'none -- nothing was touched')]
    for s in r['steps']:
        if s.get('dependency_review'):
            out += rd.summary(s['dependency_review'], 'Step %s (%s)' % (s.get('executed_as') or '-',
                                                                        s.get('deployment')))
    return out


def main(argv):
    if argv and argv[0] == '--self-test':
        return self_test()
    ap = argparse.ArgumentParser(description='Sequential rollback with a test period between steps.')
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
    per = p.add_mutually_exclusive_group()
    per.add_argument('--test-period-minutes', type=float, default=None,
                     help='the test period after each step (default %d, bound 0 < m <= %d)'
                     % (DEFAULT_PERIOD_MINUTES, MAX_PERIOD_MINUTES))
    per.add_argument('--test-period-seconds', type=float, default=None,
                     help='the same in seconds (local use)')
    itv = p.add_mutually_exclusive_group()
    itv.add_argument('--check-interval-minutes', type=float, default=None)
    itv.add_argument('--check-interval-seconds', type=float, default=None)
    p.add_argument('--locked-target', default='',
                   help='RG/NAME of the target whose concurrency lock the caller holds; a step on '
                        'any other target is refused')
    p.add_argument('--fetch-evidence-command', default='')
    p.add_argument('--seam-ownership', action='store_true',
                   help='OF-5 K-5 (KDEC-030): the landing zone owns the platform; refuse its entries '
                        '(ROLLBACK_REFUSED_PLATFORM_OWNED) and its evidence (ROLLBACK_REFUSED_FOREIGN_EVIDENCE)')
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
    interval = (a.check_interval_minutes * 60 if a.check_interval_minutes is not None
                else (a.check_interval_seconds or 0.0))
    record = run(seq_path, a.evidence_root, a.work, a.e2e_command, a.e2e_timeout_seconds,
                 period=a.test_period_seconds, interval=interval,
                 period_minutes=a.test_period_minutes, locked=_s(a.locked_target) or None,
                 fetch_cmd=a.fetch_evidence_command, seam=a.seam_ownership)
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
            fh.write('rollback_state=%s\n' % (record.get('rollback_state') or ''))
            if FOREIGN in (record.get('why') or ''):
                fh.write('rollback_refusal=%s\n' % FOREIGN)
    return 0 if record['result'] == SEQUENCE_VERIFIED else 1


def self_test():
    """Input refusals, the no-e2e refusal and the no-test-period refusal touch nothing and need no
    cloud."""
    work = tempfile.mkdtemp(prefix='rollback-sequence-selftest-')
    fails = []
    try:
        seq = os.path.join(work, 'seq.json')
        io.open(seq, 'w', encoding='utf-8').write(json.dumps(
            {'sequence_id': 's', 'steps': [{'run_id': '1', 'adapter': 'containerapp'}]}))
        r = run(seq, work, work, 'true', 60, period=1)
        if r['result'] != REFUSED_INPUT:
            fails.append('missing evidence was not refused: %s' % r['result'])
        ev = os.path.join(work, 'deploy-evidence-1-1')
        os.makedirs(ev)
        for name, body in (('snapshot.json', {'adapter': 'containerapp'}),
                           ('manifest.json', {'release_id': 'run-1-1', 'status': 'applied', 'entries': []}),
                           ('capability.json', {}), ('outcome.json', {})):
            io.open(os.path.join(ev, name), 'w', encoding='utf-8').write(json.dumps(body))
        r = run(seq, work, work, '', 60, period=1)
        if r['result'] != REFUSED_NO_E2E or r['steps'][0]['step_result'] != STEP_NOT_REACHED:
            fails.append('no e2e command was not refused before any step: %s' % r['result'])
        if validate(r):
            fails.append('the refusal record does not validate: %s' % validate(r)[:3])
        r = run(seq, work, work, 'true', 60, period_minutes=0)
        if r['result'] != REFUSED_NO_PERIOD or validate(r):
            fails.append('a 0-minute test period was not refused before any step: %s %s'
                         % (r['result'], validate(r)[:3]))
        r = run(seq, work, work, 'true', 60, period_minutes=MAX_PERIOD_MINUTES + 1)
        if r['result'] != REFUSED_INPUT:
            fails.append('a test period past the bound was not refused: %s' % r['result'])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for f in fails:
        print('SELF-TEST FAILED: ' + f)
    if fails:
        return 2
    print('rollback_sequence self-test ok: unreadable evidence, a missing e2e command, a 0-minute '
          'test period and one past the bound are refused before anything is touched; the record '
          'validates. The full proof is tests/prove_rollback_sequence.py.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
