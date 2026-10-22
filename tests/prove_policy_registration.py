#!/usr/bin/env python3
"""The policy register: per org, team, product, repository and environment tier, signed off by a
person, read from places a pull request cannot write, resolved by a stated precedence. (L32, L33)

WHY THIS EXISTS (owner requirements 2026-10-22, relayed by the coordinator; ETFB sections 1-4, 10)

    At work the kit is one private repository called by private repositories in TWO organisations,
    by dev groups with different needs per product. So enforcement policy is registered per scope,
    the most specific registration wins, and every departure from what a scope would otherwise
    inherit is a decision a named person made, with a reason and an expiry. The register is also
    the input a separate harness tool PROPOSES and a human SIGNS OFF, so its format is versioned
    and validated strictly. This proves, against REAL throwaway git repositories:

      1  NO REGISTER ANYWHERE = THE KIT DEFAULT, crawl: only secrets block, every other control is
         PROCEED_WITH_ADVISORY, recorded as policy_source KIT_DEFAULT. Never PROCEED for a finding.
      2  READ FROM THE PROTECTED BRANCH, NEVER THE PR. A PR that edits or deletes the repository's
         own registration is evaluated at the protected branch's.
      3  UNREADABLE IS NOT THE DEFAULT. An unresolvable ref, or a file that does not parse, is
         REGISTRATION_UNAVAILABLE (EVIDENCE_UNTRUSTED) and carries no rung.
      4  PRECEDENCE, most specific wins: kit default < enterprise < org < org+team < org+product <
         org+team+product < repository; at each level an entry without environment_tier ranks
         below the same scope with one. The repository's own file is the repository level.
      5  CONFLICTS ARE REFUSED BY NAME (POLICY_REGISTER_CONFLICT, BLOCKED): two entries with one
         scope, a duplicated JSON key, one environment name mapped to two tiers, a repository-file
         entry beside a central one for the same repository and tier.
      6  EVERY ENTRY IS AN ATTRIBUTED DECISION: authority, reason, decided_on, an unexpired expiry;
         uat/prod departures also name the environment's required reviewers. Missing ->
         POLICY_DECISION_UNATTRIBUTED (BLOCKED). The register itself names who signed it off.
      7  AN EXPIRED DECISION NEVER SOFTENS ANYTHING: an expired tightening stays in force, an
         expired softening reverts, and the run routes DECISION_REQUIRED (POLICY_DECISION_EXPIRED).
      8  NARROWER SCOPES ONLY TIGHTEN (KDEC-018): a central entry softening what a registered
         entry above it set is POLICY_BELOW_AUTHORITY_FLOOR (BLOCKED), decision or not
         (tests/prove_authority_floor.py proves every scope). The authority's softening of the kit
         default deploy approval is a weakening row (rule 13). The repository's own file may only
         tighten (REPOSITORY_FILE_SOFTENING, BLOCKED).
      9  SECRETS NEVER SOFTEN and no control is set to PROCEED (CHERRY_PICK_BELOW_FLOOR).
     10  SCHEMA VIOLATIONS REFUSE THE WHOLE REGISTER (REGISTRATION_UNAVAILABLE), naming the field.
     11  policy_mode SUPPLIED IS BLOCKED; non-monotone tiers are CELLS_NOT_MONOTONE.
     12  WHICH TIER: a PR or an unnamed run at the declared merge reach (prod when undeclared); an
         unknown environment name is CELL_NOT_REGISTERED.
     13  DEPLOY APPROVAL per scope (owner, 2026-10-22): the approver group, self-review prevented,
         ai_review advisory only -- never a gate. uat/prod default to one reviewer with self-review
         prevented.
     14  THE SHIPPED EXAMPLES VALIDATE (--validate), a harness-proposed register needs a sign-off,
         and the CLI emits every key the gate reads.

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
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
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

REG_PATH = '.security/policy-registration.json'
TEMPLATE = os.path.join(ROOT, 'templates', 'policy-registration.example.json')
CENTRAL_TEMPLATE = os.path.join(ROOT, 'templates', 'policy-register.central.example.json')
SCHEMA = os.path.join(ROOT, 'schemas', 'policy-registration.schema.json')
TODAY = '2026-10-22'
SCHEMA_VERSION = 2   # the register version this proof holds the reader to


def git(repo, *args):
    p = subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
                        '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main'] + list(args),
                       cwd=repo, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError('git %s: %s' % (' '.join(args), p.stderr.strip()[:300]))
    return p.stdout


def decision(**over):
    d = {'authority': 'Dana Example', 'approver_role': 'security-lead', 'reason': 'adoption plan',
         'decided_on': '2026-10-20', 'expires': '2099-01-31', 'exception_ref': 'SEC-1'}
    d.update(over)
    return d


def prod_decision(**over):
    return decision(environment_reviewers=['platform-approvers'], **over)


def entry(eid, scope, **fields):
    e = {'id': eid, 'scope': scope}
    e.update(fields)
    if 'decision' not in e:
        tiers = scope.get('environment_tier')
        e['decision'] = prod_decision() if tiers in (None, 'uat', 'prod') else decision()
    return e


def central(policies, **over):
    doc = {'schema_version': 2,
           'register_id': 'test-central',
           'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-21',
                        'reference': 'REG-1'},
           'repositories': {'acme/ledger-api': {'team': 'payments', 'product': 'ledger'},
                            'acme/other': {'team': 'web'}},
           'policies': policies}
    doc.update(over)
    return doc


def precedence_register():
    # Tighten-only, as KDEC-018 requires: each narrower or tier-qualified entry raises what it
    # inherits (prove_authority_floor.py proves the refusal of anything that does not).
    return central([
        entry('org', {'org': 'acme'}, rung='crawl'),
        entry('team', {'org': 'acme', 'team': 'payments'}, team_pattern='small_team'),
        entry('team-dev', {'org': 'acme', 'team': 'payments', 'environment_tier': 'dev'},
              rung='crawl'),
        entry('team-test', {'org': 'acme', 'team': 'payments', 'environment_tier': 'test'},
              rung='walk'),
        entry('product-uat', {'org': 'acme', 'product': 'ledger', 'environment_tier': 'uat'},
              rung='run'),
        entry('product-prod', {'org': 'acme', 'product': 'ledger', 'environment_tier': 'prod'},
              rung='run'),
        entry('repo-test', {'repository': 'acme/ledger-api', 'environment_tier': 'test'},
              controls={'deps-scan': 'BLOCKED'}),
    ])


def main():
    try:
        import rung_ladder as rl
        import policy_registration as pr
    except ImportError as exc:
        print('FAIL: the policy reader cannot be imported: %s' % exc)
        return 1
    for attr in ('SCHEMA_VERSION', 'resolve', 'resolve_from_ref', 'parse_registration', 'validate'):
        if not hasattr(pr, attr):
            print('FAIL: scripts/policy_registration.py has no %s: the multi-scope register '
                  '(schema_version 2) is not built' % attr)
            return 1
    if pr.SCHEMA_VERSION != SCHEMA_VERSION:
        print('FAIL: scripts/policy_registration.py reads schema_version %r; the multi-scope register '
              'is schema_version 2' % pr.SCHEMA_VERSION)
        return 1

    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def res(cen, repo_doc=None, repository='acme/ledger-api', environment='prod', event='push',
            supplied=None, today=TODAY):
        return pr.resolve(cen, repo_doc, repository, environment, event, supplied or {}, today)

    # ---- 1  the kit default -------------------------------------------------------------------
    r = res(None)
    check(r['state'] == rl.POLICY_RESOLVED and r['policy_source'] == 'KIT_DEFAULT',
          'rule 1: no register anywhere resolved %r / %r' % (r['state'], r.get('policy_source')))
    check(r['rung_effective'] == 'crawl' and r['policy_mode'] == 'adoption',
          'rule 1: the kit default is not crawl/adoption: %r' % r.get('rung_effective'))
    em = r['effective_minimum']
    check(em.get('secrets') == 'BLOCKED', 'rule 1: secrets do not block by default')
    for c in ('new_critical_high', 'pre_existing_on_track', 'pre_existing_track_lapsed', 'other_findings'):
        check(em.get(c) == 'PROCEED_WITH_ADVISORY',
              'rule 1: %s is %r by default; every non-secret control is advisory' % (c, em.get(c)))
    jm = r['job_minimums']
    check(jm.get('secret-scan') == 'BLOCKED' and jm.get('malicious-deps') == 'BLOCKED',
          'rule 1: a secret-class job is not BLOCKED by default: %r' % jm)
    for j in ('deps-scan', 'sast-semgrep', 'iac-scan', 'codeql', 'image-scan', 'sbom'):
        check(jm.get(j) == 'PROCEED_WITH_ADVISORY', 'rule 1: job %s is %r by default' % (j, jm.get(j)))
    check(r['routes_to'] in (None, ''), 'rule 1: the kit default itself routed %r' % r.get('routes_to'))

    # ---- 4  precedence ------------------------------------------------------------------------
    reg = precedence_register()
    _d, problems = pr.parse_registration(json.dumps(reg), 'central')
    check(not problems, 'rule 4: the precedence register did not parse: %r' % problems)
    want = {'dev': ('crawl', 'team-dev'), 'test': ('walk', 'repo-test'), 'uat': ('run', 'product-uat'),
            'prod': ('run', 'product-prod')}
    for tier, (rung, last) in sorted(want.items()):
        r = res(reg, environment=tier)
        check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == rung,
              'rule 4: %s resolved %r at %r, expected %s (chain %r; %s)'
              % (tier, r['state'], r.get('rung_effective'), rung, r.get('chain'), r.get('why')))
        check((r.get('chain') or [''])[-1] == last,
              'rule 4: the most specific entry at %s is %r, expected %s' % (tier, r.get('chain'), last))
        check(r['policy_source'] == 'REGISTER', 'rule 4: a registered run is not policy_source REGISTER')
    r = res(reg, environment='test')
    check(r['job_minimums'].get('deps-scan') == 'BLOCKED', 'rule 4: the repository cherry-pick was not applied')
    check(r['chain'] == ['org', 'team', 'team-test', 'repo-test'], 'rule 4: chain order %r' % r.get('chain'))
    # KDEC-018: a narrower entry softening what a registered entry set is refused -- the team's
    # crawl at dev beneath the team's walk is POLICY_BELOW_AUTHORITY_FLOOR, decision or not.
    floor_reg = central([entry('org', {'org': 'acme'}, rung='walk'),
                         entry('team-dev', {'org': 'acme', 'team': 'payments', 'environment_tier': 'dev'},
                               rung='crawl')])
    r = res(floor_reg, environment='dev')
    check(r['state'] == 'POLICY_BELOW_AUTHORITY_FLOOR' and r['routes_to'] == 'BLOCKED'
          and r['rung_effective'] == 'walk' and not r['weakenings'],
          'rule 8: a narrower softening with a decision was not refused below the floor: %r / %r / %r'
          % (r['state'], r.get('routes_to'), r.get('weakenings')))
    # Another repository in the org inherits the org; another org gets the kit default.
    r = res(reg, repository='acme/other', environment='prod')
    check(r['rung_effective'] == 'crawl' and r['chain'] == ['org'] and r['scope'].get('team') == 'web',
          'rule 4: another repository in the org: %r %r' % (r.get('rung_effective'), r.get('chain')))
    r = res(reg, repository='globex/thing', environment='prod')
    check(r['policy_source'] == 'KIT_DEFAULT' and r['rung_effective'] == 'crawl',
          'rule 4: another organisation did not get the kit default: %r' % r.get('policy_source'))
    check(r['scope'].get('org') == 'globex', 'rule 4: the org was not read from the repository name')
    # Org names compare case-insensitively (GitHub owners do).
    r = res(reg, repository='ACME/ledger-api', environment='prod')
    check(r['rung_effective'] == 'run', 'rule 4: the org did not match case-insensitively')

    # ---- 5  conflicts ---------------------------------------------------------------------------
    dup = central([entry('a', {'org': 'acme', 'team': 'payments'}, rung='walk'),
                   entry('b', {'org': 'acme', 'team': 'payments'}, rung='run')])
    r = res(dup)
    check(r['state'] == 'POLICY_REGISTER_CONFLICT' and r['routes_to'] == 'BLOCKED',
          'rule 5: two entries with one scope resolved %r / %r' % (r['state'], r.get('routes_to')))
    check(any('a' in n and 'b' in n for n in r['defects']), 'rule 5: the conflict does not name both ids')
    same_id = central([entry('a', {'org': 'acme'}, rung='crawl'),
                       entry('a', {'org': 'acme', 'team': 'web'}, rung='walk')])
    check(res(same_id)['state'] == 'POLICY_REGISTER_CONFLICT', 'rule 5: a duplicated entry id was accepted')
    text = json.dumps(central([]))
    text = text.replace('"repositories": {', '"repositories": {"acme/ledger-api": {"team": "web"}, ', 1)
    _d, problems = pr.parse_registration(text, 'central')
    check(any(c == 'POLICY_REGISTER_CONFLICT' for c, _m in problems),
          'rule 5: a repository mapped twice (a duplicated JSON key) was accepted: %r' % problems)
    names_c = central([], environment_names={'production': 'prod'})
    names_r = {'schema_version': 2, 'register_id': 'repo', 'sign_off': central([])['sign_off'],
               'environment_names': {'production': 'uat'}, 'policies': []}
    r = res(names_c, names_r, environment='production')
    check(r['state'] == 'POLICY_REGISTER_CONFLICT', 'rule 5: one environment name mapped to two tiers: %r' % r['state'])
    both_c = central([entry('c', {'repository': 'acme/ledger-api', 'environment_tier': 'test'}, rung='walk')])
    both_r = dict(names_r, environment_names={},
                  policies=[entry('r', {'environment_tier': 'test'}, rung='walk')])
    r = res(both_c, both_r, environment='test')
    check(r['state'] == 'POLICY_REGISTER_CONFLICT',
          'rule 5: a repository-file entry beside a central one for the same tier: %r' % r['state'])

    # ---- 6  attribution -------------------------------------------------------------------------
    for missing in ('authority', 'reason', 'expires', 'decided_on'):
        d = prod_decision()
        del d[missing]
        r = res(central([entry('x', {'org': 'acme'}, rung='walk', decision=d)]))
        check(r['state'] == 'POLICY_DECISION_UNATTRIBUTED' and r['routes_to'] == 'BLOCKED',
              'rule 6: a decision without %s resolved %r / %r' % (missing, r['state'], r.get('routes_to')))
    r = res(central([entry('x', {'org': 'acme', 'environment_tier': 'prod'}, rung='walk',
                           decision=decision())]))
    check(r['state'] == 'POLICY_DECISION_UNATTRIBUTED',
          'rule 6: a prod departure without environment_reviewers resolved %r' % r['state'])
    r = res(central([entry('x', {'org': 'acme'}, rung='walk', decision=decision())]))
    check(r['state'] == 'POLICY_DECISION_UNATTRIBUTED',
          'rule 6: a tier-less departure (it applies at uat/prod) without environment_reviewers: %r' % r['state'])
    r = res(central([entry('x', {'org': 'acme', 'environment_tier': 'dev'}, rung='crawl',
                           decision=decision())]), environment='dev')
    check(r['state'] == rl.POLICY_RESOLVED, 'rule 6: a dev entry needs no environment reviewers: %r' % r.get('why'))
    nosign = central([])
    del nosign['sign_off']
    r = res(nosign)
    check(r['state'] == 'POLICY_DECISION_UNATTRIBUTED', 'rule 6: a register nobody signed off resolved %r' % r['state'])

    # ---- 7  expiry ------------------------------------------------------------------------------
    exp_tight = central([entry('t', {'org': 'acme'}, rung='walk', decision=prod_decision(expires='2026-10-01'))])
    r = res(exp_tight)
    check(r['state'] == 'POLICY_DECISION_EXPIRED' and r['routes_to'] == 'DECISION_REQUIRED',
          'rule 7: an expired tightening resolved %r / %r' % (r['state'], r.get('routes_to')))
    check(r['rung_effective'] == 'walk', 'rule 7: an expired tightening lapsed to %r' % r.get('rung_effective'))
    # The only softening left (KDEC-018) is the authority's of the kit default deploy approval.
    exp_soft = central([entry('s', {'org': 'acme', 'environment_tier': 'prod'},
                              deploy_approval={'self_review_prevented': 'not_required'},
                              decision=prod_decision(expires='2026-10-01'))])
    r = res(exp_soft)
    check(r['state'] == 'POLICY_DECISION_EXPIRED' and not r['weakenings']
          and r['deploy_approval']['prod']['self_review_prevented'] == 'required',
          'rule 7: an expired softening stayed in force: %r %r' % (r.get('deploy_approval', {}).get('prod'),
                                                                 r.get('weakenings')))
    for bad in ('never', '31/12/2099', '2099-13-45'):
        r = res(central([entry('t', {'org': 'acme'}, rung='walk', decision=prod_decision(expires=bad))]))
        check(r['state'] != rl.POLICY_RESOLVED, 'rule 7: an expiry %r read as unexpired' % bad)

    # ---- 8  repository file: tighten only ---------------------------------------------------------
    work = tempfile.mkdtemp(prefix='policy-reg-')
    try:
        repo = os.path.join(work, 'repo')
        os.makedirs(os.path.join(repo, '.security'))
        git(repo, 'init', '-q')

        def write(doc):
            if not os.path.isdir(os.path.join(repo, '.security')):
                os.makedirs(os.path.join(repo, '.security'))
            with io.open(os.path.join(repo, REG_PATH), 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(json.dumps(doc, indent=2, sort_keys=True) + '\n')

        tight = {'schema_version': 2, 'register_id': 'ledger-api', 'sign_off': central([])['sign_off'],
                 'policies': [entry('own-prod', {'environment_tier': 'prod'}, rung='walk'),
                              entry('own-uat', {'environment_tier': 'uat'}, rung='walk')]}
        write(tight)
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'register')
        git(repo, 'checkout', '-qb', 'pr')
        # THE ATTACK: the PR deletes its own registration, and leaves a softer one in the worktree.
        git(repo, 'rm', '-q', REG_PATH)
        git(repo, 'commit', '-qm', 'pr removes its own rung')
        soft = copy.deepcopy(tight)
        soft['policies'][0]['rung'] = 'crawl'
        write(soft)

        def rref(**kw):
            args = dict(repo=repo, default_ref='main', path=REG_PATH, central_path='', repository='acme/ledger-api',
                        environment='prod', event='pull_request', supplied_inputs={}, today=TODAY)
            args.update(kw)
            return pr.resolve_from_ref(**args)

        r = rref()
        check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'walk',
              'rule 2: the PR\'s own deletion or worktree edit was read: %r %r'
              % (r['state'], r.get('rung_effective')))
        check(r.get('registration_ref'), 'rule 2: the record does not carry the commit it was read at')
        r = rref(default_ref='no-such-branch')
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE and r['routes_to'] == 'EVIDENCE_UNTRUSTED'
              and r.get('rung_effective') is None,
              'rule 3: an unresolvable ref resolved %r / %r / %r' % (r['state'], r.get('routes_to'), r.get('rung_effective')))
        r = rref(path='.security/absent.json')
        check(r['state'] == rl.POLICY_RESOLVED and r['policy_source'] == 'KIT_DEFAULT',
              'rule 1: a readable ref with no registration is the kit default: %r' % r['state'])
        git(repo, 'checkout', '-qf', 'main')
        with io.open(os.path.join(repo, REG_PATH), 'w', encoding='utf-8') as fh:
            fh.write('{not json')
        git(repo, 'commit', '-qam', 'break it')
        r = rref()
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE and r['notes'] and r.get('rung_effective') is None,
              'rule 3: a malformed registration resolved %r' % r['state'])
        # The central register comes from a file path (the kit delivered by $/), not the checkout.
        cpath = os.path.join(work, 'central.json')
        with io.open(cpath, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(precedence_register()))
        git(repo, 'reset', '-q', '--hard', 'HEAD~1')
        r = rref(central_path=cpath, environment='prod', event='push')
        # The repository file asks walk where the central register says run: both were read, and
        # the repository's own file may not soften the central one.
        check(r['state'] == 'REPOSITORY_FILE_SOFTENING',
              'rule 4/8: central and repository files were not both read: %r' % r['state'])
        with io.open(cpath, 'w', encoding='utf-8') as fh:
            fh.write('{broken')
        r = rref(central_path=cpath)
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'rule 3: a malformed central register resolved %r' % r['state'])
    except RuntimeError as exc:
        print('UNKNOWN: the fixture repository could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    soft_repo = {'schema_version': 2, 'register_id': 'r', 'sign_off': central([])['sign_off'],
                 'policies': [entry('own', {'environment_tier': 'prod'}, rung='crawl')]}
    r = res(central([entry('t', {'org': 'acme'}, rung='walk')]), soft_repo)
    check(r['state'] == 'REPOSITORY_FILE_SOFTENING' and r['routes_to'] == 'BLOCKED',
          'rule 8: a repository file softening the central register resolved %r' % r['state'])
    r = res(None, {'schema_version': 2, 'register_id': 'r', 'sign_off': central([])['sign_off'],
                   'policies': [entry('own', {'org': 'acme'}, rung='walk')]})
    check(r['state'] == rl.REGISTRATION_UNAVAILABLE,
          'rule 10: a repository file naming an org scope was accepted: %r' % r['state'])

    # ---- 9  secrets never soften; nothing is set to PROCEED -------------------------------------
    for ctl, val in (('secrets', 'PROCEED_WITH_ADVISORY'), ('secret-scan', 'DECISION_REQUIRED'),
                     ('malicious-deps', 'PROCEED_WITH_ADVISORY'), ('deps-scan', 'PROCEED'),
                     ('other_findings', 'PROCEED')):
        r = res(central([entry('x', {'org': 'acme'}, controls={ctl: val})]))
        check(r['state'] == rl.CHERRY_PICK_BELOW_FLOOR and r['routes_to'] == 'BLOCKED',
              'rule 9: %s=%s resolved %r' % (ctl, val, r['state']))

    # ---- 10  schema violations ------------------------------------------------------------------
    bads = {
        'unknown top-level field': central([], colour='red'),
        'retired schema_version 1': dict(central([]), schema_version=1),
        'unknown scope dimension': central([entry('x', {'org': 'acme', 'division': 'x'}, rung='walk')]),
        'unknown rung': central([entry('x', {'org': 'acme'}, rung='sprint')]),
        'unknown tier': central([entry('x', {'org': 'acme', 'environment_tier': 'staging'}, rung='walk')]),
        'unknown control': central([entry('x', {'org': 'acme'}, controls={'lint-everything': 'BLOCKED'})]),
        'team without org': central([entry('x', {'team': 'payments'}, rung='walk')]),
        'repository not owner/name': central([entry('x', {'repository': 'ledger-api'}, rung='walk')]),
        'repository outside its org': central([entry('x', {'org': 'acme', 'repository': 'globex/a'}, rung='walk')]),
        'decided_on not a date': central([entry('x', {'org': 'acme'}, rung='walk',
                                                decision=prod_decision(decided_on='yesterday'))]),
        'merge reach on a tier entry': central([entry('x', {'org': 'acme', 'environment_tier': 'dev'},
                                                      merge_reaches_tier='prod')]),
        'policies not a list': central({}),
        'ai_review as a gate': central([entry('x', {'org': 'acme'}, deploy_approval={'ai_review': 'required'})]),
        'two approvers': central([entry('x', {'org': 'acme'}, deploy_approval={'approvers_required': 2})]),
    }
    for why, doc in sorted(bads.items()):
        r = res(doc)
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE and r['routes_to'] == 'EVIDENCE_UNTRUSTED' and r['notes'],
              'rule 10: %s resolved %r / %r' % (why, r['state'], r.get('routes_to')))

    # ---- 11  supplied policy_mode; monotone ----------------------------------------------------
    for key in ('policy_mode', 'Policy-Mode'):
        r = res(precedence_register(), supplied={key: 'strict'})
        check(r['state'] == rl.POLICY_MODE_SUPPLIED and r['routes_to'] == 'BLOCKED' and r.get('policy_mode') is None,
              'rule 11: %s supplied resolved %r' % (key, r['state']))
    nm = central([entry('p', {'org': 'acme', 'environment_tier': 'prod'}, rung='walk')])
    r = res(nm)
    check(r['state'] == rl.CELLS_NOT_MONOTONE and r['routes_to'] == 'BLOCKED',
          'rule 11: prod at walk with uat at crawl resolved %r' % r['state'])

    # ---- 12  which tier --------------------------------------------------------------------------
    reach = central([entry('o', {'org': 'acme'}, merge_reaches_tier='dev'),
                     entry('u', {'org': 'acme', 'environment_tier': 'uat'}, rung='walk'),
                     entry('p', {'org': 'acme', 'environment_tier': 'prod'}, rung='walk')])
    r = res(reach, environment='', event='pull_request')
    check(r['environment_tier'] == 'dev' and r['rung_effective'] == 'crawl',
          'rule 12: a PR did not resolve at the declared merge reach: %r' % r.get('environment_tier'))
    r = res(reach, environment='prod', event='pull_request')
    check(r['environment_tier'] == 'dev', 'rule 12: a PR named its own tier: %r' % r.get('environment_tier'))
    r = res(central([entry('u', {'org': 'acme', 'environment_tier': 'uat'}, rung='walk'),
                     entry('p', {'org': 'acme', 'environment_tier': 'prod'}, rung='walk')]),
            environment='', event='pull_request')
    check(r['environment_tier'] == 'prod' and r['rung_effective'] == 'walk',
          'rule 12: an undeclared merge reach is not the strictest tier: %r' % r.get('environment_tier'))
    r = res(reach, environment='prod', event='push')
    check(r['environment_tier'] == 'prod' and r['rung_effective'] == 'walk', 'rule 12: a named prod push')
    r = res(central([], environment_names={'production': 'prod'}), environment='production')
    check(r['environment_tier'] == 'prod' and r['environment'] == 'production', 'rule 12: a mapped name')
    r = res(None, environment='staging')
    check(r['state'] == rl.CELL_NOT_REGISTERED and r['routes_to'] == 'EVIDENCE_UNTRUSTED',
          'rule 12: an unknown environment name resolved %r' % r['state'])
    r = res(None, environment='dev')
    check(r['tier_behaviour']['stops_on_evidence_untrusted'] is False, 'dev stops on EVIDENCE_UNTRUSTED')
    r = res(None, environment='prod')
    check(r['tier_behaviour']['stops_on_evidence_untrusted'] is True, 'prod does not stop on EVIDENCE_UNTRUSTED')
    solo = central([entry('o', {'org': 'acme'}, team_pattern='solo_dev')])
    r = res(solo)
    check(r['team_pattern'] == 'solo_dev' and 'approval_separation' in r['unvalidated_human_workflow_paths'],
          'solo_dev did not report approval separation as an unvalidated path: %r' % r.get('unvalidated_human_workflow_paths'))

    # ---- 13  deploy approval -----------------------------------------------------------------------
    r = res(None)
    da = r['deploy_approval']
    check(da['prod']['self_review_prevented'] == 'required' and da['prod']['approvers_required'] == 1
          and da['uat']['self_review_prevented'] == 'required',
          'rule 13: uat/prod do not default to one reviewer with self-review prevented: %r' % da)
    check(da['dev']['approvers_required'] == 0, 'rule 13: dev demands an approver by default: %r' % da['dev'])
    check(all(v['ai_review'] in ('advisory', 'none') for v in da.values()), 'rule 13: ai_review is not advisory-only')
    solo_prod = central([entry('o', {'org': 'acme'}, team_pattern='solo_dev',
                               deploy_approval={'approver_groups': ['architects', 'security', 'platform'],
                                                'ai_review': 'advisory'})])
    r = res(solo_prod)
    check(r['state'] == rl.POLICY_RESOLVED, 'rule 13: a deploy approval entry did not resolve: %r' % r.get('why'))
    check(r['deploy_approval']['prod']['approver_groups'] == ['architects', 'platform', 'security'],
          'rule 13: the approver groups did not resolve: %r' % r['deploy_approval']['prod'])
    check(r['deploy_approval']['dev']['ai_review'] == 'advisory', 'rule 13: ai_review advisory not carried')
    soft_da = central([entry('o', {'org': 'acme', 'environment_tier': 'prod'},
                             deploy_approval={'self_review_prevented': 'not_required'})])
    r = res(soft_da)
    check(any(w['control'] == 'deploy-approval' for w in r['weakenings']) and r['routes_to'] == 'PROCEED_WITH_ADVISORY',
          'rule 13: dropping self-review prevention at prod was not an attributed weakening: %r' % r.get('weakenings'))

    # ---- 14  examples, harness input, CLI -----------------------------------------------------------
    for path, origin in ((TEMPLATE, 'repository'), (CENTRAL_TEMPLATE, 'central')):
        if not os.path.isfile(path):
            check(False, 'rule 14: %s does not exist' % os.path.relpath(path, ROOT))
            continue
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'policy_registration.py'),
                            '--validate', path, '--origin', origin, '--today', TODAY],
                           capture_output=True, text=True)
        check(p.returncode == 0, 'rule 14: %s does not validate: %s' % (os.path.basename(path), (p.stdout + p.stderr)[-400:]))
    harness = central([entry('o', {'org': 'acme'}, rung='crawl')], proposed_by='team-type harness 0.1 run 7')
    check(res(harness)['state'] == rl.POLICY_RESOLVED, 'rule 14: a signed-off harness proposal did not resolve')
    try:
        schema = json.load(io.open(SCHEMA, encoding='utf-8'))
        check(schema.get('properties', {}).get('schema_version', {}).get('const') == 2
              and schema.get('additionalProperties') is False,
              'rule 14: schemas/policy-registration.schema.json is not the schema_version 2 register')
        try:
            import jsonschema
            for path in (TEMPLATE, CENTRAL_TEMPLATE):
                if os.path.isfile(path):
                    jsonschema.validate(json.load(io.open(path, encoding='utf-8')), schema)
            try:
                jsonschema.validate(central([], colour='red'), schema)
                check(False, 'rule 14: the JSON schema accepted an unknown top-level field')
            except jsonschema.ValidationError:
                pass
        except ImportError:
            print('note: jsonschema not installed; the JSON schema file was checked for shape only')
    except (OSError, ValueError) as exc:
        check(False, 'rule 14: the schema file cannot be read: %s' % exc)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: no register is the kit default (crawl: only secrets block, the rest advisory); the '
          'protected branch is read, never the PR; unreadable is EVIDENCE_UNTRUSTED, never the default; '
          'precedence is kit < org < team < product < team+product < repository, tier-qualified above '
          'each; conflicts, unattributed decisions, repository-file softenings, secret softenings and '
          'non-monotone tiers are refused by name; an expired decision never softens; schema violations '
          'refuse the register; deploy approval is expressed per scope; the examples validate.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
