#!/usr/bin/env python3
"""The registration file is read from the protected branch, and resolves policy -- never the reverse.

WHY THIS EXISTS (ledger L32, L33; ETFB sections 3, 4, 8.6, 10; SINGLE_PIPELINE_TARGET.md stage 1, 8.2-8.3)

    Stage 1, policy resolution, has no code: "a registration file per repository under CODEOWNERS;
    a derivation table from rung to policy_mode; a check that fails a run in which policy_mode was
    supplied rather than computed". This proves the reader and the resolver against a REAL
    throwaway git repository, the way tests/prove_ledger_read_authority.py proves the ledger:

      1  READ FROM THE PROTECTED BRANCH, NEVER THE PR. A PR that lowers its own rung in its own
         branch, or in the working tree, is evaluated at the registered rung. (The attack.)
      2  AN UNREADABLE REGISTRATION IS NOT crawl. Absent, malformed, or an unresolvable ref is
         REGISTRATION_UNAVAILABLE and routes EVIDENCE_UNTRUSTED -- the input to enforcement is
         missing, and a run must not proceed as if it had been registered at the bottom rung.
      3  policy_mode SUPPLIED IS REFUSED, even beside a perfectly good registration, and the
         refusal is an observed one: BLOCKED. (The adversarial case.)
      4  A CELL THAT IS NOT REGISTERED IS NOT RESOLVED. An environment with no cell refuses by name.
      5  A PULL REQUEST resolves at the highest environment its merge reaches without a human gate.
      6  environment_tier AND team_pattern ARRIVE THROUGH THE FILE (L33). Production tiers stop on
         EVIDENCE_UNTRUSTED; non-production tiers do not, except on a control whose floor is
         BLOCKED. solo_dev makes approval separation an UNVALIDATED human-workflow path, reported
         as such and never as passing. The resolution changes enforcement, never scanner truth:
         it carries no language, path, depth or scanner field.
      7  A SUPPLIED RUNG is compared with the registered one; a lower supplied value is a
         weakening, unattributed unless a reason and an authority came with it.
      8  EVERY NUMBER IS CONFIGURATION. A registration with no numbers block refuses
         POLICY_NUMBER_NOT_CONFIGURED; nothing in the code supplies one.
      9  THE EXAMPLE TEMPLATE VALIDATES against the schema, and the schema refuses an unknown field.

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

REG_PATH = '.security/policy-registration.json'
TEMPLATE = os.path.join(ROOT, 'templates', 'policy-registration.example.json')
SCHEMA = os.path.join(ROOT, 'schemas', 'policy-registration.schema.json')


def git(repo, *args):
    p = subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
                        '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main'] + list(args),
                       cwd=repo, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError('git %s: %s' % (' '.join(args), p.stderr.strip()[:300]))
    return p.stdout


def registration(**over):
    doc = {
        'schema_version': 1,
        'team_pattern': 'small_team',
        'numbers': {'promotion_consecutive_clean_runs': 3},
        'environments': {
            'dev': {'tier': 'dev', 'rung': 'crawl', 'approver_role': 'security-lead',
                    'registered_on': '2026-10-01', 'review_trigger': 'environment set changes',
                    'reachable_from_merge_without_human_gate': True},
            'prod': {'tier': 'prod', 'rung': 'walk', 'approver_role': 'security-lead',
                     'registered_on': '2026-10-01', 'review_trigger': 'environment set changes',
                     'reachable_from_merge_without_human_gate': False,
                     'promotion_evidence': {'walk': {
                         'controls_executed_at_baseline': {'consecutive_clean_runs': 3, 'evidence_ref': 'runs/1-3'},
                         'ledger_populated_and_owned': 'ledger@a1', 'entries_classified': 'ledger@a1',
                         'human_controls_assessed': 'review/2'}}},
        },
        'cherry_picks': [],
    }
    doc.update(over)
    return doc


def main():
    try:
        import rung_ladder as rl
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    try:
        import policy_registration as pr
    except ImportError as exc:
        print('FAIL: no registration reader exists (%s). SINGLE_PIPELINE_TARGET.md stage 1 is designed '
              'and not built: nothing reads a rung, a tier or a team pattern from the protected branch.'
              % exc)
        return 1

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def write(repo, doc):
        path = os.path.join(repo, REG_PATH)
        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(json.dumps(doc, indent=2, sort_keys=True) + '\n')

    work = tempfile.mkdtemp(prefix='policy-reg-')
    try:
        repo = os.path.join(work, 'repo')
        os.makedirs(repo)
        git(repo, 'init', '-q')
        write(repo, registration())
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'register')
        git(repo, 'checkout', '-qb', 'pr')
        # THE ATTACK: the PR demotes prod to crawl in its own branch AND in the working tree.
        low = registration()
        low['environments']['prod']['rung'] = 'crawl'
        write(repo, low)
        git(repo, 'commit', '-qam', 'pr lowers its own rung')
        write(repo, low)

        def resolve(**kw):
            args = dict(repo=repo, default_ref='main', path=REG_PATH, environment='prod',
                        event='push', supplied_inputs={}, today='2026-10-14')
            args.update(kw)
            return pr.resolve_from_ref(**args)

        r = resolve()
        check(r['state'] == rl.POLICY_RESOLVED, 'a registered cell did not resolve: %r' % r.get('why'))
        check(r['rung_declared'] == 'walk' and r['rung_effective'] == 'walk',
              'rule 1: the PR\'s own demotion was read (declared %r, effective %r)'
              % (r.get('rung_declared'), r.get('rung_effective')))
        check(r['policy_mode'] == 'adoption' and r['policy_mode_source'] == 'derived',
              'policy_mode was not derived from the rung: %r' % r.get('policy_mode'))
        check(r['environment_tier'] == 'prod' and r['team_pattern'] == 'small_team',
              'tier and team pattern did not arrive through the file: %r / %r'
              % (r.get('environment_tier'), r.get('team_pattern')))
        check(r['tier_behaviour']['production'] is True and r['tier_behaviour']['stops_on_evidence_untrusted'] is True,
              'prod did not stop on EVIDENCE_UNTRUSTED: %r' % r.get('tier_behaviour'))
        check(r['effective_minimum']['secrets'] == 'BLOCKED', 'secrets not BLOCKED in the effective set')
        check(r['routes_to'] in (None, 'PROCEED'), 'a clean resolution routed %r' % r.get('routes_to'))
        # L33: enforcement, never scanner truth.
        for forbidden in ('language', 'paths', 'scan_depth', 'scanners', 'codeql_queries', 'iac_mode'):
            check(forbidden not in r, 'the resolution carries %r: a policy input answering the '
                                      'applicability or depth axis is two inputs' % forbidden)
        check(r.get('axis') == 'enforcement', 'the resolution does not declare its axis')

        # Rule 2: unreadable is not crawl.
        r = resolve(default_ref='no-such-branch')
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE and r['routes_to'] == 'EVIDENCE_UNTRUSTED',
              'an unresolvable ref resolved to %r / %r' % (r['state'], r.get('routes_to')))
        check(r.get('rung_effective') is None and r.get('policy_mode') is None,
              'an unavailable registration still produced a rung or a policy_mode')
        r = resolve(path='no/such/file.json')
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'an absent registration read as %r' % r['state'])
        git(repo, 'checkout', '-q', '--', '.')
        git(repo, 'checkout', '-q', 'main')
        with io.open(os.path.join(repo, REG_PATH), 'w', encoding='utf-8') as fh:
            fh.write('{not json')
        git(repo, 'commit', '-qam', 'break it')
        r = resolve()
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE and r['notes'],
              'a malformed registration read as %r without saying why' % r['state'])
        git(repo, 'reset', '-q', '--hard', 'HEAD~1')
        git(repo, 'checkout', '-q', 'pr')

        # Rule 3: policy_mode supplied is refused beside a good registration, and it is BLOCKED.
        for value in ('adoption', 'strict'):
            r = resolve(supplied_inputs={'policy_mode': value, 'language': 'python'})
            check(r['state'] == rl.POLICY_MODE_SUPPLIED and r['routes_to'] == 'BLOCKED',
                  'policy_mode=%r supplied: state %r routes %r' % (value, r['state'], r.get('routes_to')))
            check(r.get('policy_mode') is None, 'a refused run still emitted a policy_mode')

        # Rule 4: unregistered cell.
        r = resolve(environment='staging')
        check(r['state'] == rl.CELL_NOT_REGISTERED and r['routes_to'] == 'EVIDENCE_UNTRUSTED',
              'an unregistered environment resolved to %r / %r' % (r['state'], r.get('routes_to')))

        # Rule 5: a pull request resolves at the highest reachable environment (dev here, since
        # prod sits behind a human gate), and at prod once prod is reachable.
        r = resolve(event='pull_request', environment='')
        check(r['state'] == rl.POLICY_RESOLVED and r['environment'] == 'dev' and r['rung_effective'] == 'crawl',
              'a PR did not resolve at the highest reachable environment: %r' % r.get('environment'))
        reach = registration()
        reach['environments']['prod']['reachable_from_merge_without_human_gate'] = True
        r = pr.resolve(reach, environment='', event='pull_request', supplied_inputs={}, today='2026-10-14')
        check(r['environment'] == 'prod' and r['rung_effective'] == 'walk',
              'a PR whose merge reaches prod unattended was not evaluated at prod: %r' % r.get('environment'))
        # A post-merge push names no environment: the same rule applies.
        r = pr.resolve(reach, environment='', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['environment'] == 'prod', 'a push naming no environment was not evaluated at the highest '
                                          'reachable one: %r' % r.get('environment'))
        # ADVERSARIAL: naming dev on a branch whose merge reaches prod unattended. Not honoured.
        r = pr.resolve(reach, environment='dev', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['environment'] == 'prod' and r['rung_effective'] == 'walk',
              'naming a lower environment selected a lower rung than the merge reaches: %r' % r.get('environment'))
        # Naming a HIGHER cell than the reachable one is honoured: that only strengthens.
        r = pr.resolve(registration(), environment='prod', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['environment'] == 'prod', 'naming prod behind a human gate was not honoured')

        # Rule 6: tiers and team patterns.
        r = pr.resolve(registration(), environment='dev', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['tier_behaviour']['production'] is False and r['tier_behaviour']['stops_on_evidence_untrusted'] is False,
              'dev stopped on EVIDENCE_UNTRUSTED: %r' % r.get('tier_behaviour'))
        check(r['tier_behaviour']['blocked_floor_stops_when_untrusted'] is True,
              'a BLOCKED-floor control (secrets) must stop when untrusted at every tier')
        solo = registration(team_pattern='solo_dev', cherry_picks=[
            {'control': 'deps-scan', 'minimum': 'BLOCKED', 'reason': 'x', 'authority': 'y',
             'requires_human_control': 'approval_separation'}])
        r = pr.resolve(solo, environment='prod', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['state'] == rl.POLICY_RESOLVED, 'solo_dev refused a valid registration: %r' % r.get('why'))
        hc = r['human_controls']
        check(hc.get('approval_separation') == 'HUMAN_CONTROL_UNVALIDATED'
              and hc.get('second_reviewer') == 'HUMAN_CONTROL_UNVALIDATED',
              'solo_dev did not mark separation and a second reviewer as unvalidated paths: %r' % hc)
        check(r['unvalidated_human_workflow_paths'], 'solo_dev reported no unvalidated human-workflow path')
        check(r['effective_minimum'].get('deps-scan') == 'BLOCKED',
              'team size lowered a floor: the pick was not applied at solo_dev')
        check(any(d.get('human_control') == 'HUMAN_CONTROL_UNVALIDATED' for d in r['divergences']),
              'a pick needing separation at solo_dev was reported as satisfied')
        check(r['breach_authority']['escalates_outside_repository'] is True,
              'solo_dev breach decisions did not escalate outside the repository')
        pair = pr.resolve(registration(team_pattern='pair_devs'), environment='prod', event='push',
                          supplied_inputs={}, today='2026-10-14')
        check(pair['human_controls'].get('approval_separation') == 'HUMAN_CONTROL_NO_SEPARATION',
              'pair_devs did not record no separation of duties: %r' % pair['human_controls'])
        full = pr.resolve(registration(team_pattern='full_team'), environment='prod', event='push',
                          supplied_inputs={}, today='2026-10-14')
        check(all(v == 'HUMAN_CONTROL_AVAILABLE' for v in full['human_controls'].values()),
              'full_team did not have every human control available: %r' % full['human_controls'])
        r = pr.resolve(registration(team_pattern='committee'), environment='prod', event='push',
                       supplied_inputs={}, today='2026-10-14')
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'an unregistered team_pattern was accepted')

        # Rule 7: a supplied rung below the registered one is a weakening.
        r = pr.resolve(registration(), environment='prod', event='push', supplied_inputs={'rung': 'crawl'},
                       today='2026-10-14')
        check(r['rung_effective'] == 'walk', 'a supplied rung replaced the registered one')
        check(any(w['attribution'] == 'WEAKENING_UNATTRIBUTED' for w in r['weakenings'])
              and r['routes_to'] == 'DECISION_REQUIRED',
              'a lower supplied rung was not an unattributed weakening routing DECISION_REQUIRED: %r'
              % r.get('weakenings'))
        r = pr.resolve(registration(), environment='prod', event='push',
                       supplied_inputs={'rung': 'crawl', 'weakening_reason': 'adoption week',
                                        'weakening_authority': 'security-lead',
                                        'weakening_expires': '2099-01-01'}, today='2026-10-14')
        check(r['routes_to'] == 'PROCEED_WITH_ADVISORY' and r['rung_effective'] == 'walk',
              'an attributed lower supplied rung did not route PROCEED_WITH_ADVISORY at the registered rung')
        r = pr.resolve(registration(), environment='prod', event='push', supplied_inputs={'rung': 'run'},
                       today='2026-10-14')
        check(r['rung_effective'] == 'walk' and not r['weakenings'],
              'a higher supplied rung was honoured or recorded as a weakening; declaring up needs evidence')

        # A demotion in the history without attribution owes a decision.
        demoted = registration()
        demoted['environments']['prod']['history'] = [{'from': 'run', 'to': 'walk', 'date': '2026-10-02'}]
        r = pr.resolve(demoted, environment='prod', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['routes_to'] == 'DECISION_REQUIRED', 'an unattributed demotion did not route DECISION_REQUIRED')

        # A cherry-pick below the floor is a policy defect and BLOCKED.
        bad = registration(cherry_picks=[{'control': 'iac-scan', 'minimum': 'PROCEED', 'reason': 'x', 'authority': 'y'}])
        r = pr.resolve(bad, environment='prod', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['state'] == rl.CHERRY_PICK_BELOW_FLOOR and r['routes_to'] == 'BLOCKED',
              'a below-floor cherry-pick resolved %r / %r' % (r['state'], r.get('routes_to')))
        # Non-monotone cells are a policy defect.
        nm = registration()
        nm['environments']['dev']['rung'] = 'run'
        r = pr.resolve(nm, environment='prod', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['state'] == rl.CELLS_NOT_MONOTONE and r['routes_to'] == 'BLOCKED',
              'rung(dev)=run over rung(prod)=walk resolved %r' % r['state'])

        # Rule 8: numbers are configuration.
        r = pr.resolve(registration(numbers={}), environment='prod', event='push', supplied_inputs={},
                       today='2026-10-14')
        check(r['state'] == rl.POLICY_NUMBER_NOT_CONFIGURED and r['routes_to'] == 'EVIDENCE_UNTRUSTED',
              'a registration with no numbers resolved %r' % r['state'])
        # A declared rung above its evidence is effective at the evidenced rung; both are carried.
        over = registration()
        over['environments']['prod']['rung'] = 'run'
        r = pr.resolve(over, environment='prod', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['rung_declared'] == 'run' and r['rung_effective'] == 'walk'
              and r['rung_divergence'] == rl.RUNG_EFFECTIVE_BELOW_DECLARED,
              'declared run with walk evidence: declared %r effective %r divergence %r'
              % (r.get('rung_declared'), r.get('rung_effective'), r.get('rung_divergence')))
        check(r['policy_mode'] == 'adoption', 'policy_mode followed the declared rung, not the effective one')

        # Rule 9: the shipped example validates; an unknown field is refused.
        doc = json.load(io.open(TEMPLATE, encoding='utf-8'))
        _d, state, notes = pr.parse_registration(json.dumps(doc))
        check(state == pr.registration_readable, 'the shipped example does not parse: %r' % notes)
        r = pr.resolve(doc, environment='production', event='push', supplied_inputs={}, today='2026-10-14')
        check(r['state'] == rl.POLICY_RESOLVED, 'the shipped example does not resolve: %r' % r.get('why'))
        _d, state, notes = pr.parse_registration(json.dumps(dict(doc, colour='red')))
        check(state != pr.registration_readable, 'an unknown top-level field was accepted')
        try:
            import jsonschema
            jsonschema.validate(doc, json.load(io.open(SCHEMA, encoding='utf-8')))
            try:
                jsonschema.validate(dict(doc, colour='red'), json.load(io.open(SCHEMA, encoding='utf-8')))
                check(False, 'the schema accepted an unknown top-level field')
            except jsonschema.ValidationError:
                pass
        except ImportError:
            print('note: jsonschema not installed; the schema itself was not exercised here')
    except RuntimeError as exc:
        print('UNKNOWN: the fixture repository could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: against a real git repository, a PR\'s own demotion is never read; an absent, '
          'malformed or unreachable registration is unavailable and EVIDENCE_UNTRUSTED, never crawl; '
          'a supplied policy_mode is BLOCKED beside a good registration; an unregistered cell refuses; '
          'a PR resolves at the highest reachable environment; tier and team pattern arrive through '
          'the file and change enforcement only; solo_dev reports unvalidated human-workflow paths '
          'and lowers no floor; a lower supplied rung is a weakening; numbers are configuration; '
          'the shipped example resolves and an unknown field is refused.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
