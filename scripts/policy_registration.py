#!/usr/bin/env python3
"""The POLICY REGISTRATION: one file per repository on the protected default branch, under
CODEOWNERS, and the only sanctioned way to read it. Stage 1 of the pipeline (L32, L33).

WHAT THE FILE IS (ETFB sections 4, 10; SINGLE_PIPELINE_TARGET.md sections 8.2-8.3)

    The business's declared posture, and everything enforcement reads downstream of it:

        .security/policy-registration.json
        {
          "schema_version": 1,
          "team_pattern":   solo_dev | pair_devs | small_team | full_team,
          "numbers":        { every placeholder the design refuses to make a constant },
          "environments":   { <name>: { tier, rung, approver_role, registered_on, review_trigger,
                                        reachable_from_merge_without_human_gate,
                                        [promotion_evidence], [history] } },
          "cherry_picks":   [ { control, minimum, reason, authority, expires | review_trigger,
                                [requires_human_control] } ]
        }

    The rung is per (repository, environment) cell. environment_tier and team_pattern are read
    HERE, through the file -- never as workflow inputs -- and they change ENFORCEMENT, never what
    is scanned (AXES_AND_PHASES.md: "an input that answers more than one axis is two inputs").

HOW IT IS READ (the same rule as the baseline ledger, for the same reason)

    From a GIT REF, never from the working tree. A registration read from the PR under evaluation
    lets the PR demote its own rung in the same change -- the self-signed certificate ETFB
    section 5.4 refuses for the ledger. `read_at_ref` reads the blob at the protected default
    branch's tip; nothing here opens the file in the checkout.

WHAT RESOLUTION REFUSES, BY NAME (policy_resolution in assurance-taxonomy.yaml)

    POLICY_MODE_SUPPLIED          the run received policy_mode as an input. Derived, never set.
    CHERRY_PICK_BELOW_FLOOR       a pick weaker than the rung's floor. A floor is a floor.
    CELLS_NOT_MONOTONE            rung(sandbox) <= ... <= rung(uat) = rung(prod) violated.
    CELL_NOT_REGISTERED           no cell for the targeted environment.
    REGISTRATION_UNAVAILABLE      absent, unparseable, unreachable ref, or malformed.
    POLICY_NUMBER_NOT_CONFIGURED  a number the mechanism needs is missing. Never defaulted.

    The first three are policy DEFECTS observed by this check and route BLOCKED. The last three
    are a missing input to enforcement and route EVIDENCE_UNTRUSTED. Both stop a gate; the
    difference tells a person which problem they have. Nothing here ever resolves to crawl because
    it could not read the file: an unregistered repository is not a repository at the bottom rung.

USAGE
    python3 policy_registration.py --self-test
    python3 policy_registration.py --repo . --default-ref origin/main --environment prod \
        --event "$GITHUB_EVENT_NAME" [--supplied key=value ...] [--out resolution.json] \
        [--github-output "$GITHUB_OUTPUT"]

EXIT  0 resolved   1 refused (state printed)   2 usage, or self-test failed
"""
import argparse
import datetime
import io
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import enforcement_axes as ax  # noqa: E402
import rung_ladder as rl  # noqa: E402

SCHEMA_VERSION = 1
default_registration_path = '.security/policy-registration.json'

# Parse states. Readable is the only one resolve() proceeds from; the rest become
# REGISTRATION_UNAVAILABLE with the notes attached.
registration_readable = 'readable'
registration_absent = 'absent'
registration_malformed = 'malformed'

TEAM_PATTERNS = ax.TEAM_PATTERNS

TOP_REQUIRED = ('schema_version', 'team_pattern', 'numbers', 'environments')
TOP_OPTIONAL = ('cherry_picks', 'repository', 'notes')
CELL_REQUIRED = ('tier', 'rung', 'approver_role', 'registered_on', 'review_trigger',
                 'reachable_from_merge_without_human_gate')
CELL_OPTIONAL = ('promotion_evidence', 'history', 'notes')
PICK_REQUIRED = ('control', 'minimum', 'reason', 'authority')
PICK_OPTIONAL = ('expires', 'review_trigger', 'requires_human_control', 'notes')
HISTORY_FIELDS = ('from', 'to', 'date', 'reason', 'authority', 'expires', 'evidence_refs', 'approver_role')

# The team and tier axes live in scripts/enforcement_axes.py (L33); this reader hands them the
# values it read from the file and nothing else.
HUMAN_CONTROL_UNVALIDATED = ax.HUMAN_CONTROL_UNVALIDATED
HUMAN_CONTROLS = ax.HUMAN_CONTROLS


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def _date_ok(s):
    try:
        datetime.date.fromisoformat(s)
        return True
    except (TypeError, ValueError):
        return False


tier_behaviour = ax.tier_behaviour
human_controls = ax.human_controls


def parse_registration(text):
    """-> (doc, state, notes). Refuses the WHOLE file on any fault: a half-read policy is a policy
    somebody else wrote."""
    if not _s(text):
        return ({}, registration_malformed, ['the registration file is empty'])
    try:
        doc = json.loads(text)
    except ValueError as exc:
        return ({}, registration_malformed, ['not valid JSON: %s' % exc])
    if not isinstance(doc, dict):
        return ({}, registration_malformed, ['the registration is not a JSON object'])
    notes = []
    if doc.get('schema_version') != SCHEMA_VERSION:
        notes.append('schema_version is %r, this reader understands %d' % (doc.get('schema_version'), SCHEMA_VERSION))
    for k in doc:
        if k not in TOP_REQUIRED + TOP_OPTIONAL:
            notes.append('unknown top-level field %r: the registration reads through an allowlist, so '
                         'nothing arrives under a name nobody reviewed' % k)
    for k in TOP_REQUIRED:
        if k not in doc:
            notes.append('missing %s' % k)
    if notes:
        return ({}, registration_malformed, notes)
    if _s(doc.get('team_pattern')) not in TEAM_PATTERNS:
        notes.append('team_pattern %r is not a registered team_pattern' % (doc.get('team_pattern'),))
    if not isinstance(doc.get('numbers'), dict):
        notes.append('numbers is not an object')
    envs = doc.get('environments')
    if not isinstance(envs, dict) or not envs:
        notes.append('environments is not a non-empty object')
        envs = {}
    for name, cell in envs.items():
        if not isinstance(cell, dict):
            notes.append('environment %s is not an object' % name)
            continue
        for k in cell:
            if k not in CELL_REQUIRED + CELL_OPTIONAL:
                notes.append('environment %s carries unknown field %r' % (name, k))
        for k in CELL_REQUIRED:
            if k not in cell:
                notes.append('environment %s lacks %s' % (name, k))
        if _s(cell.get('tier')) not in rl.tier_order:
            notes.append('environment %s: tier %r is not a registered environment_tier' % (name, cell.get('tier')))
        if _s(cell.get('rung')) not in rl.RUNGS:
            notes.append('environment %s: rung %r is not a registered enforcement_rung' % (name, cell.get('rung')))
        if not _s(cell.get('approver_role')):
            notes.append('environment %s: a rung nobody approved is not a registration' % name)
        if not _date_ok(cell.get('registered_on')):
            notes.append('environment %s: registered_on %r is not an ISO date' % (name, cell.get('registered_on')))
        if not isinstance(cell.get('reachable_from_merge_without_human_gate'), bool):
            notes.append('environment %s: reachable_from_merge_without_human_gate must be a boolean; a '
                         'PR is evaluated at the highest environment its merge reaches, so this cannot '
                         'be left unsaid' % name)
        hist = cell.get('history', [])
        if not isinstance(hist, list):
            notes.append('environment %s: history is not a list' % name)
        else:
            for i, ev in enumerate(hist):
                if not isinstance(ev, dict) or _s(ev.get('from')) not in rl.RUNGS or _s(ev.get('to')) not in rl.RUNGS:
                    notes.append('environment %s: history[%d] must carry registered from/to rungs' % (name, i))
                    continue
                for k in ev:
                    if k not in HISTORY_FIELDS:
                        notes.append('environment %s: history[%d] carries unknown field %r' % (name, i, k))
    picks = doc.get('cherry_picks', [])
    if not isinstance(picks, list):
        notes.append('cherry_picks is not a list')
    else:
        for i, p in enumerate(picks):
            if not isinstance(p, dict):
                notes.append('cherry_picks[%d] is not an object' % i)
                continue
            for k in p:
                if k not in PICK_REQUIRED + PICK_OPTIONAL:
                    notes.append('cherry_picks[%d] carries unknown field %r' % (i, k))
            for k in PICK_REQUIRED:
                if not _s(p.get(k)):
                    notes.append('cherry_picks[%d] lacks %s: a pick with no reason or authority is a '
                                 'decision nobody made' % (i, k))
            if not _s(p.get('expires')) and not _s(p.get('review_trigger')):
                notes.append('cherry_picks[%d] carries neither an expiry nor a review trigger (ETFB section 10)' % i)
            if _s(p.get('requires_human_control')) and _s(p.get('requires_human_control')) not in HUMAN_CONTROLS:
                notes.append('cherry_picks[%d]: requires_human_control %r is not one of %s'
                             % (i, p.get('requires_human_control'), ', '.join(HUMAN_CONTROLS)))
    if notes:
        return ({}, registration_malformed, notes)
    return (doc, registration_readable, ['%d environment cell(s), %d cherry-pick(s)' % (len(envs), len(picks))])


def _git(repo, *args):
    p = subprocess.run(['git', '-C', repo] + list(args), capture_output=True)
    return p.returncode, p.stdout, p.stderr.decode('utf-8', 'replace').strip()


def read_at_ref(repo, ref, path=default_registration_path):
    """-> (doc, state, notes, sha). Reads the BLOB at the ref, never a working tree."""
    rc, out, err = _git(repo, 'rev-parse', '--verify', '--quiet', '%s^{commit}' % ref)
    if rc != 0:
        return ({}, registration_malformed, ['ref %r cannot be resolved (%s). Cannot read is not '
                                             'unregistered-at-crawl' % (ref, err or 'no such ref')], '')
    sha = out.decode().strip()
    rc, out, err = _git(repo, 'cat-file', '-e', '%s:%s' % (sha, path))
    if rc != 0:
        return ({}, registration_absent, ['no registration at %s:%s. Nobody has declared a posture for '
                                          'this repository on the protected branch' % (ref, path)], sha)
    rc, out, err = _git(repo, 'show', '%s:%s' % (sha, path))
    if rc != 0:
        return ({}, registration_malformed, ['cannot read %s:%s: %s' % (ref, path, err)], sha)
    doc, state, notes = parse_registration(out.decode('utf-8', 'replace'))
    return (doc, state, notes, sha)


def _blank(state, routes_to, why, notes=None, **extra):
    out = {'state': state, 'axis': 'enforcement', 'routes_to': routes_to, 'why': why,
           'notes': list(notes or []), 'environment': None, 'environment_tier': None,
           'team_pattern': None, 'rung_declared': None, 'rung_effective': None,
           'rung_divergence': None, 'policy_mode': None, 'policy_mode_source': None,
           'floor': {}, 'effective_minimum': {}, 'divergences': [], 'defects': [],
           'weakenings': [], 'human_controls': {}, 'unvalidated_human_workflow_paths': [],
           'breach_authority': {}, 'tier_behaviour': {}, 'numbers': {}, 'promotion_missing': []}
    out.update(extra)
    return out


def resolve(doc, environment, event, supplied_inputs, today):
    """Stage 1. -> the resolution record (see module docstring). Pure over its arguments."""
    supplied_inputs = dict(supplied_inputs or {})
    # 1  policy_mode supplied: refused before anything else is read, whatever its value.
    sup = rl.refuse_supplied_policy_mode(supplied_inputs)
    if sup['state'] == rl.POLICY_MODE_SUPPLIED:
        return _blank(sup['state'], 'BLOCKED', sup['why'], defects=[sup['why']])
    if not isinstance(doc, dict) or not doc:
        return _blank(rl.REGISTRATION_UNAVAILABLE, 'EVIDENCE_UNTRUSTED',
                      'no readable registration was handed to the resolver')
    team = _s(doc.get('team_pattern'))
    if team not in TEAM_PATTERNS:
        return _blank(rl.REGISTRATION_UNAVAILABLE, 'EVIDENCE_UNTRUSTED',
                      'team_pattern %r is not registered' % (team or None))
    cells = doc.get('environments') or {}
    # 2  cells monotone along the promotion path.
    defects = rl.check_cells_monotone(cells)
    if defects:
        return _blank(rl.CELLS_NOT_MONOTONE, 'BLOCKED', 'the registered cells violate the promotion-path '
                      'ordering; a cell that violates it is a policy defect', defects=defects,
                      team_pattern=team)
    # 3  which cell. A pull request -- and any run that names no environment, which is what a
    #    post-merge push on the default branch is -- is evaluated at the highest environment the
    #    ref reaches without a further human gate. A NAMED environment can never select BELOW
    #    that: "evaluate me at dev" on a branch whose merge auto-deploys to prod is a rung a
    #    caller passed, in a different costume.
    env = _s(environment)
    reach_env, reach_rung = rl.rung_for_pull_request(cells)
    basis = 'named environment'
    if event in ('pull_request', 'pull_request_target') or not env:
        env, basis = reach_env, 'highest environment reachable without a human gate'
        if env is None:
            return _blank(rl.CELL_NOT_REGISTERED, 'EVIDENCE_UNTRUSTED',
                          '%s: no environment is marked reachable from a merge without a human gate, '
                          'so there is no rung to evaluate this run at' % (event or 'no environment named'),
                          team_pattern=team)
    if env not in cells:
        return _blank(rl.CELL_NOT_REGISTERED, 'EVIDENCE_UNTRUSTED',
                      'environment %r has no registered cell. The rung is per (repository, '
                      'environment); an unregistered cell has no floor to apply' % (env or None),
                      team_pattern=team)
    if (reach_env is not None and env != reach_env
            and rl.rung_index(reach_rung) > rl.rung_index(_s(cells[env].get('rung')))):
        basis = ('named environment %s sits below %s, which the merge reaches without a human gate; '
                 'evaluated at %s' % (env, reach_env, reach_env))
        env = reach_env
    cell = cells[env]
    tier = _s(cell.get('tier'))
    numbers = doc.get('numbers') if isinstance(doc.get('numbers'), dict) else {}
    # 4  declared versus effective.
    eff = rl.effective_rung(cell, numbers)
    if eff['state'] in (rl.POLICY_NUMBER_NOT_CONFIGURED, rl.CELL_NOT_REGISTERED):
        return _blank(eff['state'], 'EVIDENCE_UNTRUSTED', eff['why'], environment=env,
                      environment_tier=tier, team_pattern=team, promotion_missing=eff['missing'])
    rung = eff['effective']
    # 5  the floor and the cherry-picks.
    em = rl.effective_minimum(rung, doc.get('cherry_picks') or [])
    hc = human_controls(team)
    for d, pick in zip([x for x in em['divergences']], _picks_in_order(doc, em)):
        req = _s((pick or {}).get('requires_human_control'))
        if req:
            d['requires_human_control'] = req
            d['human_control'] = hc.get(req, HUMAN_CONTROL_UNVALIDATED)
    if em['state'] == rl.CHERRY_PICK_BELOW_FLOOR:
        return _blank(em['state'], 'BLOCKED', 'a cherry-pick sits below the rung floor; a floor is a '
                      'floor and the downward direction has no representation', defects=em['defects'],
                      environment=env, environment_tier=tier, team_pattern=team,
                      rung_declared=eff['declared'], rung_effective=rung, floor=em['floor'])
    # 6  weakenings: demotions in the history, and a supplied rung below the registered one.
    weak = rl.demotion_record(cell.get('history') or [], today)
    sr = _s(supplied_inputs.get('rung'))
    if sr in rl.RUNGS and rl.rung_index(sr) < rl.rung_index(rung):
        ev = {'from': rung, 'to': sr, 'date': today, 'reason': _s(supplied_inputs.get('weakening_reason')),
              'authority': _s(supplied_inputs.get('weakening_authority')),
              'expires': _s(supplied_inputs.get('weakening_expires'))}
        rows = rl.demotion_record([ev], today)
        for r in rows:
            r['input'] = 'rung (supplied by the caller)'
            r['why'] = ('the caller passed rung=%s against the registered %s. The registered value '
                        'governs; the divergence is recorded as a weakening. ' % (sr, rung)) + r['why']
        weak.extend(rows)
    unval = [k for k, v in hc.items() if v == HUMAN_CONTROL_UNVALIDATED]
    # 7  routing of the resolution itself (findings route later, under the effective set).
    routes = None
    if any(w['attribution'] != rl.WEAKENING_ATTRIBUTED for w in weak):
        routes = 'DECISION_REQUIRED'
    elif weak:
        routes = 'PROCEED_WITH_ADVISORY'
    return _blank(rl.POLICY_RESOLVED, routes, 'resolved from the registration on the protected branch; '
                  'cell chosen by: %s' % basis, environment=env, environment_tier=tier, team_pattern=team,
                  rung_declared=eff['declared'], rung_effective=rung,
                  rung_divergence=(eff['state'] if eff['state'] != rl.POLICY_RESOLVED else None),
                  promotion_missing=eff['missing'], policy_mode=rl.derive_policy_mode(rung),
                  policy_mode_source='derived', floor=em['floor'], effective_minimum=em['effective'],
                  divergences=em['divergences'], weakenings=weak, human_controls=hc,
                  unvalidated_human_workflow_paths=unval, breach_authority=ax.breach_authority(team),
                  tier_behaviour=tier_behaviour(tier), numbers=dict(numbers))


def _picks_in_order(doc, em):
    """The picks that produced each divergence, in order (defective picks produce none)."""
    by_control = {}
    for p in (doc.get('cherry_picks') or []):
        if isinstance(p, dict):
            by_control.setdefault(_s(p.get('control')), []).append(p)
    out = []
    for d in em['divergences']:
        lst = by_control.get(d['control']) or [None]
        out.append(lst.pop(0))
    return out


def resolve_from_ref(repo, default_ref, path, environment, event, supplied_inputs, today):
    """Read at the protected ref, then resolve. The working tree is never consulted."""
    sup = rl.refuse_supplied_policy_mode(supplied_inputs or {})
    if sup['state'] == rl.POLICY_MODE_SUPPLIED:
        return _blank(sup['state'], 'BLOCKED', sup['why'], defects=[sup['why']])
    doc, state, notes, sha = read_at_ref(repo, default_ref, path)
    if state != registration_readable:
        return _blank(rl.REGISTRATION_UNAVAILABLE, 'EVIDENCE_UNTRUSTED',
                      'the registration at %s:%s is %s. Unreadable is not crawl: the input to '
                      'enforcement is missing' % (default_ref, path, state), notes=notes,
                      registration_ref=sha or None)
    out = resolve(doc, environment, event, supplied_inputs, today)
    out['registration_ref'] = sha
    out['notes'] = notes + out['notes']
    return out


def _selftest():
    fails = []
    doc = {'schema_version': 1, 'team_pattern': 'full_team',
           'numbers': {'promotion_consecutive_clean_runs': 1},
           'environments': {'prod': {'tier': 'prod', 'rung': 'crawl', 'approver_role': 'sec',
                                     'registered_on': '2026-01-01', 'review_trigger': 'x',
                                     'reachable_from_merge_without_human_gate': False}}}
    _d, state, notes = parse_registration(json.dumps(doc))
    if state != registration_readable:
        fails.append('a well-formed registration did not parse: %r' % notes)
    r = resolve(doc, 'prod', 'push', {}, '2026-10-14')
    if r['state'] != rl.POLICY_RESOLVED or r['policy_mode'] != 'adoption':
        fails.append('a crawl cell did not resolve to adoption: %r' % r['why'])
    if resolve(doc, 'prod', 'push', {'policy_mode': 'adoption'}, '2026-10-14')['state'] != rl.POLICY_MODE_SUPPLIED:
        fails.append('a supplied policy_mode was not refused')
    if resolve({}, 'prod', 'push', {}, '2026-10-14')['routes_to'] != 'EVIDENCE_UNTRUSTED':
        fails.append('no registration did not route EVIDENCE_UNTRUSTED')
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('policy_registration selftest ok: a registration parses and resolves, a supplied policy_mode '
          'is refused, no registration is EVIDENCE_UNTRUSTED. The git-ref rules are proven by '
          'tests/prove_policy_registration.py.')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='Resolve the enforcement policy from the protected branch.')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--repo', default='.')
    ap.add_argument('--default-ref', default='')
    ap.add_argument('--path', default=default_registration_path)
    ap.add_argument('--environment', default='')
    ap.add_argument('--event', default='')
    ap.add_argument('--supplied', action='append', default=[],
                    help='key=value for every input the run RECEIVED (repeatable)')
    ap.add_argument('--today', default='')
    ap.add_argument('--out', default='')
    ap.add_argument('--github-output', default='')
    a = ap.parse_args(argv)
    if a.self_test:
        return _selftest()
    if not a.default_ref:
        print('--default-ref is required: the registration is read from the protected default branch, '
              'and there is no default for which branch that is', file=sys.stderr)
        return 2
    supplied = {}
    for kv in a.supplied:
        k, _sep, v = kv.partition('=')
        supplied[k.strip()] = v
    today = a.today or datetime.date.today().isoformat()
    r = resolve_from_ref(a.repo, a.default_ref, a.path, a.environment, a.event, supplied, today)
    print('%s  routes_to=%s  environment=%s tier=%s team=%s rung declared=%s effective=%s policy_mode=%s'
          % (r['state'], r['routes_to'], r['environment'], r['environment_tier'], r['team_pattern'],
             r['rung_declared'], r['rung_effective'], r['policy_mode']))
    print('  ' + r['why'])
    for n in r['notes'] + r['defects']:
        print('  ' + n)
    if a.out:
        with io.open(a.out, 'w', encoding='utf-8') as fh:
            json.dump(r, fh, indent=2, sort_keys=True)
    if a.github_output:
        with io.open(a.github_output, 'a', encoding='utf-8') as fh:
            for k in ('state', 'routes_to', 'environment', 'environment_tier', 'team_pattern',
                      'rung_declared', 'rung_effective', 'rung_divergence', 'policy_mode', 'policy_mode_source'):
                fh.write('policy_%s=%s\n' % (k, r.get(k) if r.get(k) is not None else ''))
            fh.write('policy_effective_minimum=%s\n' % json.dumps(r['effective_minimum'], sort_keys=True))
            fh.write('policy_divergences=%s\n' % json.dumps(r['divergences'], sort_keys=True))
            fh.write('policy_weakenings=%s\n' % json.dumps(r['weakenings'], sort_keys=True))
            fh.write('policy_unvalidated_human_workflow_paths=%s\n' % ','.join(r['unvalidated_human_workflow_paths']))
            fh.write('policy_stops_on_evidence_untrusted=%s\n'
                     % str(bool(r['tier_behaviour'].get('stops_on_evidence_untrusted'))).lower())
    return 0 if r['state'] == rl.POLICY_RESOLVED else 1


if __name__ == '__main__':
    sys.exit(main())
