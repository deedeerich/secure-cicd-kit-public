#!/usr/bin/env python3
"""The highest authority's rung is the FLOOR for everything beneath it; narrower scopes only tighten.
(KDEC-018 items 1-3, owner 2026-10-22; lane L-FX.)

WHY THIS EXISTS

    Owner: "whatever is allocated at the org or enterprise (if there is a higher authority) must be
    the level we run at across the entire enterprise. So if they say walk everyone is at walk."
    Until lane L-FX a narrower central entry (team, product, repository, a tier) could SOFTEN what
    the org set, with an unexpired decision, and the run routed PROCEED_WITH_ADVISORY. That is now
    refused by name. Per-finding exceptions are not rung changes and are unaffected.

WHAT IT PROVES (against scripts/policy_registration.py, the real resolver)

    A1  an `enterprise` scope exists above `org`: the central register's `orgs` map says which
        enterprise an org belongs to, and an enterprise entry applies to every repository of
        every org mapped to it (and to no other org)
    A2  an org entry that leaves anything weaker than its enterprise's entry is refused:
        POLICY_BELOW_AUTHORITY_FLOOR (BLOCKED), even with an unexpired decision; the floor stays
    A3  every narrower scope -- team, product, team+product, a central repository entry, and a
        tier-qualified entry beneath a tier-less one at the same scope -- that leaves the rung or
        any control weaker than the floor is refused the same way; tightening is applied
    A4  a deploy-approval softening of the KIT DEFAULT is a decision only the authority (enterprise
        or org scope) may make -- a narrower scope doing it is refused, and so is any scope
        softening a deploy approval a registered entry set
    A5  the repository's own file still may only tighten (REPOSITORY_FILE_SOFTENING)
    A6  crawl is the absolute floor in the register: no rung below crawl, secrets never soften, the
        kit default blocks secrets at every tier
    A7  per-finding secret exceptions are NOT rung changes: a narrower entry carrying only a secret
        exception, under an org at walk, resolves and the exception is in force
    A8  structure: an enterprise scope combined with org/team/product/repository, an enterprise no
        org maps to, an `orgs` map in a repository file, are refused (REGISTRATION_UNAVAILABLE)
    A9  --validate reports a below-floor entry for every repository and org it would reach
    A10 POLICY_BELOW_AUTHORITY_FLOOR is a registered policy_resolution value routing BLOCKED

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
TODAY = '2026-10-22'
FLOOR = 'POLICY_BELOW_AUTHORITY_FLOOR'


def decision(**over):
    d = {'authority': 'Dana Example', 'approver_role': 'security-lead', 'reason': 'adoption plan',
         'decided_on': '2026-10-20', 'expires': '2099-01-31', 'environment_reviewers': ['platform-approvers']}
    d.update(over)
    return d


def entry(eid, scope, **fields):
    e = {'id': eid, 'scope': scope}
    e.update(fields)
    e.setdefault('decision', decision())
    return e


def central(policies, **over):
    doc = {'schema_version': 2, 'register_id': 'floor',
           'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-21'},
           'orgs': {'acme': 'acme-group', 'acme-labs': 'acme-group'},
           'repositories': {'acme/ledger-api': {'team': 'payments', 'product': 'ledger'}},
           'policies': policies}
    doc.update(over)
    return doc


def main():
    try:
        import policy_registration as pr
        import rung_ladder as rl
        import yaml
    except ImportError as exc:
        print('UNKNOWN: cannot import the resolver or PyYAML: %s' % exc)
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def res(cen, repo_doc=None, repository='acme/ledger-api', environment='prod'):
        return pr.resolve(cen, repo_doc, repository, environment, 'push', {}, TODAY)

    def refused(r, code=FLOOR):
        return r['state'] == code and r.get('routes_to') == 'BLOCKED'

    # ---- A1 enterprise scope -----------------------------------------------------------------------
    ent_walk = entry('ent', {'enterprise': 'acme-group'}, rung='walk')
    r = res(central([ent_walk]))
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'walk' and r['chain'] == ['ent'],
          'A1: an enterprise entry did not bind its org: %r %r %r' % (r['state'], r.get('rung_effective'), r.get('why')))
    r = res(central([ent_walk]), repository='acme-labs/tool')
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'walk',
          'A1: an enterprise entry did not bind a second org mapped to it: %r %r' % (r['state'], r.get('why')))
    r = res(central([ent_walk]), repository='globex/thing')
    check(r['state'] == rl.POLICY_RESOLVED and r['policy_source'] == 'KIT_DEFAULT',
          'A1: an enterprise entry reached an org not mapped to it: %r' % r.get('chain'))
    check((r.get('scope') or {}).get('enterprise') in (None, ''),
          'A1: an unmapped org was given an enterprise: %r' % r.get('scope'))
    r = res(central([ent_walk]))
    check((r.get('scope') or {}).get('enterprise') == 'acme-group', 'A1: the resolved scope does not name '
          'the enterprise: %r' % r.get('scope'))

    # ---- A2 an org softening its enterprise --------------------------------------------------------
    r = res(central([ent_walk, entry('org', {'org': 'acme'}, rung='crawl')]))
    check(refused(r), 'A2: an org softening the enterprise walk resolved %r / %r' % (r['state'], r.get('routes_to')))
    check(r.get('rung_effective') == 'walk', 'A2: the floor did not hold: rung %r' % r.get('rung_effective'))
    check(not r.get('weakenings'), 'A2: a refused softening was still recorded as a weakening in force: %r'
          % r.get('weakenings'))
    r = res(central([ent_walk, entry('org', {'org': 'acme'}, rung='run')]))
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'run',
          'A2: an org TIGHTENING its enterprise was refused: %r' % r['state'])

    # ---- A3 every narrower scope -------------------------------------------------------------------
    org_walk = entry('org', {'org': 'acme'}, rung='walk')
    narrower = {
        'team': {'org': 'acme', 'team': 'payments'},
        'product': {'org': 'acme', 'product': 'ledger'},
        'team+product': {'org': 'acme', 'team': 'payments', 'product': 'ledger'},
        'repository (central)': {'repository': 'acme/ledger-api'},
        'tier beneath tier-less org': {'org': 'acme', 'environment_tier': 'prod'},
        'tier beneath tier-less enterprise': {'enterprise': 'acme-group', 'environment_tier': 'prod'},
    }
    for why, scope in sorted(narrower.items()):
        base = [ent_walk] if 'enterprise' in scope else [org_walk]
        r = res(central(base + [entry('soft', scope, rung='crawl')]))
        check(refused(r), 'A3: a %s entry softening the floor (walk -> crawl) with an unexpired decision '
              'resolved %r / %r' % (why, r['state'], r.get('routes_to')))
        check(any('soft' in d for d in r.get('defects') or []), 'A3: the %s refusal does not name the entry' % why)
        tight = [entry('tight', scope, rung='run')]
        if 'environment_tier' in scope:
            # uat = prod (CELLS_NOT_MONOTONE otherwise): a tier tightening is registered for both.
            tight.append(entry('tight-uat', dict(scope, environment_tier='uat'), rung='run'))
        r = res(central(base + tight))
        check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'run',
              'A3: a %s entry TIGHTENING the floor was refused: %r' % (why, r['state']))
    pick = entry('org', {'org': 'acme'}, controls={'deps-scan': 'BLOCKED'})
    r = res(central([pick, entry('soft', {'org': 'acme', 'team': 'payments'},
                                 controls={'deps-scan': 'PROCEED_WITH_ADVISORY'})]))
    check(refused(r) and r['job_minimums'].get('deps-scan') == 'BLOCKED',
          'A3: a team softening a control the org blocks resolved %r (deps-scan %r)'
          % (r['state'], r.get('job_minimums', {}).get('deps-scan')))
    # The tier floor binds at every tier, and a tier entry tightening above it is applied.
    r = res(central([org_walk, entry('dev', {'org': 'acme', 'environment_tier': 'dev'}, rung='crawl',
                                     decision=decision(environment_reviewers=None))]), environment='dev')
    check(refused(r), 'A3: an org dev entry below the tier-less org walk resolved %r' % r['state'])

    # ---- A4 deploy approval ------------------------------------------------------------------------
    soft_da = {'self_review_prevented': 'not_required'}
    r = res(central([entry('org', {'org': 'acme', 'environment_tier': 'prod'}, deploy_approval=soft_da)]))
    check(r['state'] == rl.POLICY_RESOLVED and any(w['control'] == 'deploy-approval' for w in r['weakenings']),
          'A4: the authority (org) softening the kit default deploy approval with a decision is not an '
          'attributed weakening: %r %r' % (r['state'], r.get('weakenings')))
    r = res(central([entry('team', {'org': 'acme', 'team': 'payments', 'environment_tier': 'prod'},
                           deploy_approval=soft_da)]))
    check(refused(r), 'A4: a TEAM softening the kit default deploy approval resolved %r' % r['state'])
    r = res(central([entry('org', {'org': 'acme'}, deploy_approval={'approvers_required': 1,
                                                                      'self_review_prevented': 'required'}),
                     entry('org-prod', {'org': 'acme', 'environment_tier': 'prod'}, deploy_approval=soft_da)]))
    check(refused(r), 'A4: an org tier entry softening the deploy approval its tier-less entry set resolved %r'
          % r['state'])

    # ---- A5 the repository file --------------------------------------------------------------------
    repo_file = {'schema_version': 2, 'register_id': 'r', 'sign_off': central([])['sign_off'],
                 'policies': [entry('own', {'environment_tier': 'prod'}, rung='crawl')]}
    r = res(central([org_walk]), repo_file)
    check(r['state'] == 'REPOSITORY_FILE_SOFTENING' and r['routes_to'] == 'BLOCKED',
          'A5: a repository file softening the org resolved %r' % r['state'])

    # ---- A6 crawl is the absolute floor ------------------------------------------------------------
    for tier in rl.tier_order:
        r = res(None, environment=tier)
        check(r['effective_minimum'].get('secrets') == 'BLOCKED' and r['job_minimums'].get('secret-scan') == 'BLOCKED',
              'A6: the kit default does not block secrets at %s' % tier)
    for bad_rung in ('none', 'off', 'below-crawl'):
        r = res(central([entry('x', {'org': 'acme'}, rung=bad_rung)]))
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'A6: rung %r below crawl was accepted: %r' % (bad_rung, r['state']))
    r = res(central([entry('x', {'org': 'acme'}, controls={'secret-scan': 'PROCEED_WITH_ADVISORY'})]))
    check(r['state'] == rl.CHERRY_PICK_BELOW_FLOOR, 'A6: an org softening secrets resolved %r' % r['state'])

    # ---- A7 per-finding exceptions are unaffected --------------------------------------------------
    sx = {'finding': 'a1b2c3d4e5f6', 'ticket': 'SEC-1234', 'explanation': 'fixture credential, rotated',
          'approver': 'Dana Example', 'expires': '2099-01-31', 'environment_reviewers': ['platform-approvers']}
    r = res(central([org_walk, entry('team-sx', {'org': 'acme', 'team': 'payments'}, secret_exceptions=[sx])]))
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'walk'
          and [x['finding'] for x in r['secret_exceptions']] == ['a1b2c3d4e5f6'],
          'A7: a team entry carrying only a secret exception under an org at walk did not resolve with the '
          'exception in force: %r %r' % (r['state'], r.get('secret_exceptions')))

    # ---- A8 structure ------------------------------------------------------------------------------
    bads = {
        'enterprise with org': central([entry('x', {'enterprise': 'acme-group', 'org': 'acme'}, rung='walk')]),
        'enterprise with team': central([entry('x', {'enterprise': 'acme-group', 'team': 'payments'}, rung='walk')]),
        'enterprise nobody maps': central([entry('x', {'enterprise': 'other-group'}, rung='walk')]),
        'orgs not an object': central([], orgs=['acme']),
        'orgs value empty': central([], orgs={'acme': ''}),
    }
    for why, doc in sorted(bads.items()):
        r = res(doc)
        check(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'A8: %s resolved %r' % (why, r['state']))
    r = res(None, {'schema_version': 2, 'register_id': 'r', 'sign_off': central([])['sign_off'],
                   'orgs': {'acme': 'acme-group'}, 'policies': []})
    check(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'A8: a repository file carrying an orgs map resolved %r' % r['state'])

    # ---- A9 --validate -----------------------------------------------------------------------------
    work = tempfile.mkdtemp(prefix='authority-floor-')
    try:
        path = os.path.join(work, 'central.json')
        with io.open(path, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(central([org_walk, entry('soft', {'org': 'acme', 'team': 'payments'}, rung='crawl')])))
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'policy_registration.py'), '--validate',
                            path, '--origin', 'central', '--today', TODAY], capture_output=True, text=True)
        check(p.returncode == 1 and FLOOR in p.stdout, 'A9: --validate did not refuse a below-floor entry: rc %d %s'
              % (p.returncode, p.stdout[-300:]))
    finally:
        try:
            os.remove(os.path.join(work, 'central.json'))
            os.rmdir(work)
        except OSError:
            pass

    # ---- A10 the taxonomy --------------------------------------------------------------------------
    tax = yaml.safe_load(io.open(os.path.join(ROOT, 'assurance-taxonomy.yaml'), encoding='utf-8'))
    vals = (((tax.get('namespaces') or {}).get('policy_resolution') or {}).get('values') or {})
    check(FLOOR in vals, 'A10: %s is not a registered policy_resolution value' % FLOOR)
    routes = pr.resolve(central([entry('org', {'org': 'acme'}, rung='walk'),
                                 entry('soft', {'org': 'acme', 'team': 'payments'}, rung='crawl')]),
                        None, 'acme/ledger-api', 'prod', 'push', {}, TODAY).get('routes_to')
    check(routes == 'BLOCKED', 'A10: %s does not route BLOCKED (%r)' % (FLOOR, routes))

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: an enterprise binds every org mapped to it; the highest authority\'s rung and controls are '
          'the floor -- every narrower scope (org under enterprise, team, product, team+product, '
          'repository, a tier beneath a tier-less entry) only tightens, and leaving anything weaker is '
          'POLICY_BELOW_AUTHORITY_FLOOR (BLOCKED) even with an unexpired decision; only the authority may '
          'soften the kit default deploy approval; crawl is absolute; per-finding exceptions are unaffected.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
