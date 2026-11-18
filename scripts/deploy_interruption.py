#!/usr/bin/env python3
"""KREQ-717: a time-bounded deploy job, and the interrupted deploy the NEXT run must reconcile.

WHY THIS EXISTS (docs/architecture/ROLLBACK_CONTRACT.md, "Timeouts are a cancellation vector")

    The deploy jobs were deliberately unbounded: a timeout is a cancellation nobody chose, and a
    deploy killed mid-change strands a half-applied change. The owner's direction (KDEC-052, rows
    review L4a) is to bound them anyway -- a stalled job bills without limit -- on one condition:
    the outcome of a kill is DESIGNED. What a kill leaves is decided by the change manifest at the
    moment of the kill (deploy_contract.py derive_outcome, DCR-8):

      killed before the first mutation   no manifest entry: nothing changed (DEPLOY_REFUSED)
      killed inside the mutating call    PARTIAL_APPLY  (issued, never confirmed)
      killed after it, before the end    STATUS_UNTRUSTED (cancelled, no reversal record)
      killed after a verified reversal   ROLLBACK_VERIFIED (the target is back; nothing owed)

    The first and last are reconciled states. The middle two are not, and the run that was killed
    cannot reconcile them -- so the NEXT run of the same target must, and must say so by name. This
    script is both halves:

      record  (every run that reached the target, `if: always()`, after the outcome report): the
              run's outcome, its manifest entries, and whether reconciliation is owed, uploaded as
              the artifact `kit-deploy-state-<target key>` (same target key as the rollback marker).
      check   (before login): the time bound is inside its governed range, and the newest state of
              this target owes nothing. An interruption still owed is
              INTERRUPTED_DEPLOY_RECONCILIATION_REQUIRED -- refused, naming the run, its outcome and
              what it changed -- until a person who reconciled it by hand names that run in
              `reconciled_interrupted_run` (INTERRUPTED_DEPLOY_RECONCILED_BY_HAND, recorded). The
              run that then deploys writes the newest state, which supersedes the interrupted one.

    Vocabulary: assurance-taxonomy.yaml :: deploy_interruption. Proof: tests/prove_deploy_interruption.py.

THE OTHER MUTATING JOBS (KDEC-061 M2: the same design, one script; ROLLBACK_CONTRACT.md kill tables)
    record --kind rollback-sequence  (reusable-rollback-sequence.yml): the sequence record
              (rollback-sequence.json) is written only when the sequence reaches its verdict. A run
              killed before it, with a step's work directory on disk, left the target mid-sequence:
              PARTIAL_APPLY when the newest step has no reversal record (a reversal may have been
              issued, never confirmed), STATUS_UNTRUSTED when it has one (reversed, the read-back or
              test period unfinished). Either owes INTERRUPTED_DEPLOY_RECONCILIATION_REQUIRED, under the
              SAME artifact name as a deploy of that target, so the next deploy AND the next sequence
              are refused until the run is named. A sequence that reached its verdict owes nothing here
              (a halt is already a person's decision: its record, marker and held lease).
    record --kind registry-push  (reusable-build-docker.yml): written into the build evidence. A
              push killed or failed before the registry's digest was known (manifest `planned`) is
              PARTIAL_APPLY; pushed but the identity never asserted is STATUS_UNTRUSTED; either, or a
              proven push whose job was then cancelled, is INTERRUPTED_PUSH_UNPROMOTABLE: the attest
              job signs only after a successful build job with REGISTRY_IDENTITY_PROVEN, and the
              promotion gate refuses anything V1 did not verify, so nothing a kill leaves is promoted.
              No next-run refusal is needed (and the build reusable holds no actions: read).
    check --bound-only  the time bound alone (the registry push has no state to read).

THE TIME BOUND (governed, never unbounded)
    deploy_timeout_minutes: 30 <= m <= 360, and at least 30 + the e2e test period (when e2e is
    configured) + 30 (when DAST is configured). Outside it: DEPLOY_REFUSED_TIME_BOUND before login.
    The job's `timeout-minutes` expression also clamps an out-of-range value to 90, so a value that
    slipped past this check still cannot make the job unbounded.

EXIT  check: 0 proceed, 1 refused.   record: 0 (written or nothing to record), 2 usage.
"""
import argparse
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rollback_hold as RH  # noqa: E402  (the target key, the GitHub API reader, the artifact download)

CLEAR = 'INTERRUPTION_CHECK_CLEAR'
REQUIRED = 'INTERRUPTED_DEPLOY_RECONCILIATION_REQUIRED'
by_hand = 'INTERRUPTED_DEPLOY_RECONCILED_BY_HAND'
INCOMPLETE = 'INTERRUPTION_CHECK_INCOMPLETE'
time_bound = 'DEPLOY_REFUSED_TIME_BOUND'
unpromotable = 'INTERRUPTED_PUSH_UNPROMOTABLE'
REFUSING = (REQUIRED, INCOMPLETE, time_bound)
KINDS = ('deploy', 'rollback-sequence', 'registry-push')

bound_min, bound_max, bound_default = 30, 360, 90
UNRECONCILED = ('PARTIAL_APPLY', 'STATUS_UNTRUSTED')   # DCR-8: the extent or the result is not known
RECONCILED_ON_INTERRUPT = ('DEPLOY_HEALTHY', 'ROLLBACK_VERIFIED', 'DEPLOY_REFUSED')


def state_name(environment, resource_group, name):
    return 'kit-deploy-state-' + RH.target_key(environment, resource_group, name)


def bound_problem(timeout, test_period, dast, name='deploy_timeout_minutes'):
    """-> None when the bound is governed, else why it is refused. `name` is the job's own input."""
    try:
        t = float(timeout)
        p = float(test_period or 0)
    except (TypeError, ValueError):
        return '%s %r is not a number' % (name, timeout)
    if not bound_min <= t <= bound_max:
        return ('%s %g is outside %d..%d: a mutating job is bounded, never '
                'unbounded, and never shorter than its own work' % (name, t, bound_min, bound_max))
    need = 30 + max(p, 0) + (30 if str(dast).lower() == 'true' else 0)
    if t < need:
        return ('%s %g is below what this job configures to do (%g: 30 for the '
                'change itself + the %g-minute test period%s); the bound would kill every run '
                'mid-change' % (name, t, need, p, ' + 30 for DAST' if str(dast).lower() == 'true' else ''))
    return None


def needs_reconciliation(outcome, entries, interrupted):
    """The design table above. Owed when something was changed and the result is not established."""
    if not entries:
        return False
    if outcome in UNRECONCILED:
        return True
    return bool(interrupted) and outcome not in RECONCILED_ON_INTERRUPT


def _read(path):
    try:
        return json.load(io.open(path, encoding='utf-8'))
    except (OSError, ValueError):
        return None


def _out(path, **kv):
    RH._out(path, **kv)


def _summary(path, text):
    if path:
        io.open(path, 'a', encoding='utf-8').write(text + '\n')
    print(text)


# ----------------------------------------------------------------------------- record
def build_state(evidence_dir, cancelled, environment, resource_group, name, run_id, run_attempt):
    """-> the state document, or None when the run never reached the target (no snapshot)."""
    if _read(os.path.join(evidence_dir, 'snapshot.json')) is None:
        return None
    out = _read(os.path.join(evidence_dir, 'outcome.json')) or {}
    man = _read(os.path.join(evidence_dir, 'manifest.json')) or {}
    entries = [e for e in man.get('entries') or [] if isinstance(e, dict)]
    interrupted = str(cancelled).lower() == 'true'
    outcome = out.get('deployment_outcome')
    if not outcome:
        # The report never wrote its verdict (killed inside it): a run that changed something and
        # cannot say what it left is STATUS_UNTRUSTED, never "done".
        outcome = 'STATUS_UNTRUSTED' if entries else 'DEPLOY_REFUSED'
    owed = needs_reconciliation(outcome, entries, interrupted)
    return {'schema_version': 1, 'kind': 'kit-deploy-state',
            'target': {'environment': environment, 'resource_group': resource_group, 'name': name},
            'run_id': str(run_id), 'run_attempt': str(run_attempt),
            'recorded_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'deployment_outcome': outcome, 'why': out.get('why') or 'no outcome report was written',
            'interrupted': interrupted, 'reconciliation_required': owed,
            'reconciliation': REQUIRED if owed else None,
            'manifest_status': man.get('status'),
            # A CREATED revision is unnamed until the platform answers: its type stands in.
            'changed': [{'action': e.get('action'), 'object': e.get('object') or e.get('object_type') or 'unnamed'}
                        for e in entries],
            'evidence_artifact': 'deploy-evidence-%s-%s' % (run_id, run_attempt)}


def _state(environment, resource_group, name, run_id, run_attempt, outcome, why, interrupted, owed,
           changed, artifact, reconciliation=None, **extra):
    doc = {'schema_version': 1, 'kind': 'kit-deploy-state',
           'target': {'environment': environment, 'resource_group': resource_group, 'name': name},
           'run_id': str(run_id), 'run_attempt': str(run_attempt),
           'recorded_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
           'deployment_outcome': outcome, 'why': why, 'interrupted': interrupted,
           'reconciliation_required': owed, 'reconciliation': reconciliation or (REQUIRED if owed else None),
           'changed': changed, 'evidence_artifact': artifact}
    doc.update(extra)
    return doc


def build_rollback_state(work_dir, record_path, cancelled, environment, resource_group, name, run_id,
                         run_attempt):
    """The sequential rollback (reusable-rollback-sequence.yml). -> the state, or None when no step
    was reached (the target's previous state stands)."""
    interrupted = str(cancelled).lower() == 'true'
    artifact = 'rollback-sequence-%s-%s' % (run_id, run_attempt)
    rec = _read(record_path) if record_path else None
    if isinstance(rec, dict) and rec.get('result'):
        # The sequence reached its verdict: a halt is already a person's decision (its record, the
        # marker and the lease it keeps mutating). Nothing more is owed to the next run here.
        acted = [s for s in rec.get('steps') or [] if isinstance(s, dict) and isinstance(s.get('rollback'), dict)]
        if not acted:
            return None
        return _state(environment, resource_group, name, run_id, run_attempt, rec['result'],
                      'the sequence reached its verdict', interrupted, False,
                      [{'action': 'REVERSED (%s)' % (s['rollback'].get('result') or 'unknown'),
                        'object': s.get('deployment') or 'step %s' % s.get('position')} for s in acted],
                      artifact, sequence_record=True)
    steps = sorted(d for d in (os.listdir(work_dir) if os.path.isdir(work_dir) else [])
                   if d.startswith('step-') and os.path.isdir(os.path.join(work_dir, d)))
    if not steps:
        return None
    changed, newest_reversed = [], False
    for d in steps:
        ev = os.path.join(work_dir, d, 'deploy-evidence')
        rv = _read(os.path.join(ev, 'reversal.json'))
        rel = (_read(os.path.join(ev, 'manifest.json')) or {}).get('release_id') or 'release unknown'
        newest_reversed = rv is not None
        changed.append({'action': ('REVERSED (%s)' % ((rv or {}).get('result') or 'unknown')) if rv is not None
                        else 'reversal possibly issued, never confirmed', 'object': '%s (%s)' % (d, rel)})
    outcome = 'STATUS_UNTRUSTED' if newest_reversed else 'PARTIAL_APPLY'
    why = ('the sequence never reached its verdict (no sequence record) after reaching %d step(s): %s'
           % (len(steps), 'the newest step was reversed but its read-back or test period never finished'
              if newest_reversed else 'a reversal of the newest step may have been issued and was never confirmed'))
    return _state(environment, resource_group, name, run_id, run_attempt, outcome, why, interrupted, True,
                  changed, artifact, sequence_record=False)


def build_registry_state(evidence_dir, identity, cancelled, environment, resource_group, name, run_id,
                         run_attempt):
    """The registry push (reusable-build-docker.yml). -> the state, or None when the push was never
    reached (no snapshot, or the capability step refused before the point of no return)."""
    if _read(os.path.join(evidence_dir, 'snapshot.json')) is None:
        return None
    man = _read(os.path.join(evidence_dir, 'manifest.json'))
    if not isinstance(man, dict) or not man.get('entries'):
        return None
    interrupted = str(cancelled).lower() == 'true'
    proven = identity == 'REGISTRY_IDENTITY_PROVEN'
    if man.get('status') != 'applied':
        outcome, why = 'PARTIAL_APPLY', ('the push was reached and the registry\'s digest never recorded: '
                                         'the tag may hold a partial or unproven image')
    elif not proven:
        outcome, why = 'STATUS_UNTRUSTED', ('pushed, and the registry round trip never proved it is the scanned '
                                            'image (artifact_identity %s)' % (identity or 'absent'))
    else:
        outcome, why = 'REGISTRY_IDENTITY_PROVEN', 'pushed and the registry round trip proved the scanned image'
    owed_name = unpromotable if (outcome != 'REGISTRY_IDENTITY_PROVEN' or interrupted) else None
    if owed_name:
        why += ('; never attested (the attest job signs only after a successful build job with a proven '
                'identity), so V1 and the promotion gate refuse it: it is never promoted')
    e = [x for x in man['entries'] if isinstance(x, dict)]
    return _state(environment, resource_group, name, run_id, run_attempt, outcome, why, interrupted, False,
                  [{'action': x.get('action'), 'object': x.get('object') or 'unnamed'} for x in e],
                  'build-evidence-%s-%s' % (run_id, run_attempt), reconciliation=owed_name,
                  manifest_status=man.get('status'), promotable=False if owed_name else None)


def cmd_record(a):
    if a.kind == 'rollback-sequence':
        st = build_rollback_state(a.evidence_dir, a.sequence_record, a.cancelled, a.environment,
                                  a.resource_group, a.name, a.run_id, a.run_attempt)
    elif a.kind == 'registry-push':
        st = build_registry_state(a.evidence_dir, a.identity, a.cancelled, a.environment,
                                  a.resource_group, a.name, a.run_id, a.run_attempt)
    else:
        st = build_state(a.evidence_dir, a.cancelled, a.environment, a.resource_group, a.name,
                         a.run_id, a.run_attempt)
    if st is None:
        _summary(a.summary, 'Deploy state (KREQ-717): this run never reached the target (no pre-change '
                 'snapshot); the target\'s previous state record stands.')
        _out(a.github_output, state_written='false')
        return 0
    os.makedirs(a.out_dir, exist_ok=True)
    name = state_name(a.environment, a.resource_group, a.name)
    body = json.dumps(st, indent=1, sort_keys=True)
    io.open(os.path.join(a.out_dir, 'deploy-state.json'), 'w', encoding='utf-8').write(body)
    if os.path.isdir(a.evidence_dir):
        io.open(os.path.join(a.evidence_dir, 'deploy-state.json'), 'w', encoding='utf-8').write(body)
    if st['reconciliation_required']:
        _summary(a.summary, '### Deploy state: `%s`\n\nThis run %s with outcome `%s` after changing %d '
                 'object(s). The next deploy of this target is refused until a person reconciles live '
                 'state against `%s` (snapshot and manifest) and names run `%s` in '
                 '`reconciled_interrupted_run`.' % (REQUIRED, 'was cancelled or timed out' if st['interrupted']
                                                     else 'ended', st['deployment_outcome'],
                                                     len(st['changed']), st['evidence_artifact'], st['run_id']))
        print('::error title=Deploy state %s::outcome %s; the next run of this target must reconcile run %s'
              % (REQUIRED, st['deployment_outcome'], st['run_id']))
    elif st['reconciliation'] == unpromotable:
        _summary(a.summary, '### Registry push state: `%s`\n\nOutcome `%s` (%s). Whatever this run left under '
                 '`%s` is never promoted; if anything outside the kit pulls that tag, a person re-points or '
                 'removes it against `%s`.' % (unpromotable, st['deployment_outcome'], st['why'], a.name,
                                                 st['evidence_artifact']))
        print('::warning title=Registry push %s::outcome %s; nothing this run left is promotable'
              % (unpromotable, st['deployment_outcome']))
    else:
        _summary(a.summary, 'Deploy state (KREQ-717): outcome `%s`; nothing owed to the next run.'
                 % st['deployment_outcome'])
    _out(a.github_output, state_written='true', state_name=name,
         reconciliation=st['reconciliation'] or 'none')
    return 0


# ----------------------------------------------------------------------------- check
def decide(state, reconciled_run):
    """-> (outcome, why) from the newest recorded state of the target."""
    if not state or not state.get('reconciliation_required'):
        return CLEAR, ('the newest state of this target owes nothing (run %s, %s)'
                       % ((state or {}).get('run_id', 'none'), (state or {}).get('deployment_outcome', 'no record')))
    run = str(state.get('run_id') or '')
    what = ('run %s ended %s%s after changing %s; reconcile live state against %s'
            % (run, state.get('deployment_outcome'), ' (cancelled or timed out)' if state.get('interrupted') else '',
               ', '.join('%s %s' % (c.get('action'), c.get('object')) for c in state.get('changed') or []) or 'objects',
               state.get('evidence_artifact')))
    if run and str(reconciled_run or '').strip() == run:
        return by_hand, 'a person recorded reconciling it by hand: ' + what
    return REQUIRED, what


def cmd_check(a):
    doc = {'deploy_interruption': None, 'why': '', 'target': {'environment': a.environment,
           'resource_group': a.resource_group, 'name': a.name},
           'time_bound_minutes': a.timeout, 'state': None}

    def finish(outcome, why):
        doc['deploy_interruption'], doc['why'] = outcome, why
        if a.out:
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            io.open(a.out, 'w', encoding='utf-8').write(json.dumps(doc, indent=1, sort_keys=True))
        _summary(a.summary, '### Interrupted-deploy check (KREQ-717): `%s`\n\n%s' % (outcome, why))
        one = why.replace('\n', ' ').replace('::', ': :')
        print('::%s title=Deploy %s::%s' % ('error' if outcome in REFUSING else 'notice', outcome, one))
        _out(a.github_output, deploy_interruption=outcome)
        return 1 if outcome in REFUSING else 0

    problem = bound_problem(a.timeout, a.test_period, a.dast, a.bound_name)
    if problem:
        return finish(time_bound, problem)
    if a.bound_only:
        return finish(CLEAR, '%s %s is governed; this job keeps no target state for its next run to '
                      'reconcile (an interrupted registry push is %s: never promoted)'
                      % (a.bound_name, a.timeout, unpromotable))
    name = state_name(a.environment, a.resource_group, a.name)
    try:
        listing = RH.api('actions/artifacts', {'name': name, 'per_page': 100})
        found = [x for x in (listing or {}).get('artifacts') or [] if not x.get('expired')]
        state = None
        if found:
            newest = sorted(found, key=lambda x: x.get('created_at') or '')[-1]
            state = RH.download_json(newest.get('archive_download_url') or '')
            if not isinstance(state, dict) or state.get('kind') != 'kit-deploy-state':
                raise RH.Unreadable('the state record %s is not a kit deploy state' % name)
    except RH.Unreadable as exc:
        return finish(INCOMPLETE, 'the target\'s deploy state could not be read (%s); never deployed blind' % exc)
    doc['state'] = state
    outcome, why = decide(state, a.reconciled_run)
    return finish(outcome, why)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    for n in ('check', 'record'):
        p = sub.add_parser(n)
        p.add_argument('--environment', default='')
        p.add_argument('--resource-group', default='')
        p.add_argument('--name', default='')
        p.add_argument('--github-output', default='')
        p.add_argument('--summary', default='')
        if n == 'check':
            p.add_argument('--timeout', default=str(bound_default))
            p.add_argument('--test-period', default='0')
            p.add_argument('--dast', default='false')
            p.add_argument('--reconciled-run', default='')
            p.add_argument('--out', default='')
            p.add_argument('--bound-name', default='deploy_timeout_minutes')
            p.add_argument('--bound-only', action='store_true')
        else:
            p.add_argument('--evidence-dir', required=True)
            p.add_argument('--out-dir', required=True)
            p.add_argument('--cancelled', default='false')
            p.add_argument('--kind', choices=KINDS, default='deploy')
            p.add_argument('--sequence-record', default='')
            p.add_argument('--identity', default='')
            p.add_argument('--run-id', default='')
            p.add_argument('--run-attempt', default='1')
    a = ap.parse_args(argv)
    return cmd_check(a) if a.cmd == 'check' else cmd_record(a)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
