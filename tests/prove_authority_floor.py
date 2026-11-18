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
    A11 (KDEC-020, correcting KDEC-019 item 1) an org the central `orgs` map does not name RUNS: it
        is rolled in at the enterprise floor -- the one enterprise's rung, or with several the
        STRICTEST of them at each tier (never lower) -- with a named, visible notice
        ORG_UNMAPPED_RAN_AT_ENTERPRISE_FLOOR (enterprise, rung, "add it to the orgs map") in the
        resolution's notices, notes and GitHub outputs; never a refusal, never silent. Its own org
        entry that goes LOWER is POLICY_BELOW_AUTHORITY_FLOOR; one that tightens is honoured. A
        mapped org carries no notice; with no enterprise defined nothing changes; --validate no
        longer refuses an unmapped org; ORG_NOT_UNDER_ENTERPRISE is no longer emitted anywhere
    A12 (KDEC-022 item 1, owner 2026-10-23: "Yes you should get the strictest from the orgs.") with
        an `orgs` map or org entries but NO enterprise entry, an org the register does not know runs
        at the STRICTEST registered org, tier by tier (KDEC-020's comparison), with the notice
        ORG_UNMAPPED_RAN_AT_STRICTEST_ORG; its own repository file may tighten above it and never go
        below; the floor org's per-finding exceptions do not travel; a registered org is untouched;
        with an enterprise entry KDEC-020 still governs

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
RETIRED = 'ORG_NOT_UNDER_ENTERPRISE'
NOTICE = 'ORG_UNMAPPED_RAN_AT_ENTERPRISE_FLOOR'
NOTICE_ORG = 'ORG_UNMAPPED_RAN_AT_STRICTEST_ORG'


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
        return pr.resolve(cen, repo_doc, repository, environment, 'push', {}, TODAY,
                          history=pr.committed_once(cen, repo_doc))

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
    # An org the map does not name is rolled in at the enterprise floor (KDEC-020, A11).
    r = res(central([ent_walk]), repository='globex/thing')
    check(r['state'] == rl.POLICY_RESOLVED and 'ent' in (r.get('chain') or []) and r.get('rung_effective') == 'walk',
          'A1: an unmapped org was not rolled in at the enterprise floor: %r %r %r'
          % (r['state'], r.get('chain'), r.get('why')))
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

    # ---- A11 an unmapped org runs at the enterprise floor (KDEC-020, correcting KDEC-019 item 1) ---
    # Owner, 2026-10-22: "No run with the enterprise floor even if unmapped previously" -- meaning
    # "No -- RUN with the enterprise floor"; 2026-10-23: "I thought we agreed unmapped orgs would be
    # rolled in at whatever level the enterprise or other orgs are at".
    def notice_of(r):
        return [n for n in r.get('notices') or [] if n.get('code') == NOTICE]

    for env in ('prod', 'dev', ''):
        r = res(central([ent_walk]), repository='globex/thing', environment=env)
        check(r['state'] == rl.POLICY_RESOLVED and r.get('rung_effective') == 'walk' and 'ent' in r['chain'],
              'A11: an unmapped org did not run at the single enterprise\'s walk (env %r): %r %r %r'
              % (env, r['state'], r.get('rung_effective'), r.get('why')))
        n = notice_of(r)
        check(bool(n) and n[0].get('enterprise') == 'acme-group' and n[0].get('org') == 'globex'
              and n[0].get('rung') == 'walk' and 'add it to the orgs map' in (n[0].get('why') or ''),
              'A11: no named notice for the unmapped org (env %r): %r' % (env, r.get('notices')))
        check(any(NOTICE in x for x in r.get('notes') or []), 'A11: the notice is not in the notes: %r' % r.get('notes'))
        lines = pr.github_output_lines(r)
        check(any(x.startswith('policy_notices=') and NOTICE in x and 'acme-group' in x for x in lines),
              'A11: the notice is not in the GitHub outputs (policy_notices)')
        check((r.get('scope') or {}).get('enterprise') == 'acme-group', 'A11: the scope does not name the '
              'enterprise used: %r' % r.get('scope'))
    # Two enterprises, at walk and at run: the unmapped org gets the STRICTER, at every tier.
    two_ent = [entry('e-walk', {'enterprise': 'acme-group'}, rung='walk'),
               entry('e-run', {'enterprise': 'beta-group'}, rung='run')]
    two_orgs = {'acme': 'acme-group', 'beta': 'beta-group'}
    for env in ('prod', 'dev', ''):
        r = res(central(two_ent, orgs=two_orgs), repository='globex/thing', environment=env)
        check(r['state'] == rl.POLICY_RESOLVED and r.get('rung_effective') == 'run' and r['chain'] == ['e-run'],
              'A11: with enterprises at walk and run the unmapped org did not get run (env %r): %r %r %r'
              % (env, r['state'], r.get('rung_effective'), r.get('chain')))
        n = notice_of(r)
        check(bool(n) and n[0].get('enterprise') == 'beta-group',
              'A11: the notice does not name the stricter enterprise: %r' % r.get('notices'))
    # Mapped orgs keep their own enterprise and carry no notice, whatever the case of the name.
    r = res(central(two_ent, orgs=two_orgs), repository='ACME/x')
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'walk' and not notice_of(r),
          'A11: a mapped org was moved or noticed: %r %r %r' % (r['state'], r.get('rung_effective'), r.get('notices')))
    # The unmapped org's own entry may tighten above the floor, never go below it.
    r = res(central([ent_walk, entry('globex-crawl', {'org': 'globex'}, rung='crawl')]), repository='globex/thing')
    check(refused(r, FLOOR) and r.get('rung_effective') == 'walk',
          'A11: an unmapped org\'s own entry below the enterprise floor resolved %r / %r (rung %r)'
          % (r['state'], r.get('routes_to'), r.get('rung_effective')))
    r = res(central(two_ent + [entry('globex-walk', {'org': 'globex'}, rung='walk')], orgs=two_orgs),
            repository='globex/thing')
    check(refused(r, FLOOR) and r.get('rung_effective') == 'run',
          'A11: an unmapped org\'s entry at walk beneath the stricter enterprise (run) resolved %r (rung %r)'
          % (r['state'], r.get('rung_effective')))
    r = res(central([ent_walk, entry('globex-run', {'org': 'globex'}, rung='run')]), repository='globex/thing')
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'run' and r['chain'] == ['ent', 'globex-run'],
          'A11: an unmapped org\'s own tightening was not honoured: %r %r %r'
          % (r['state'], r.get('rung_effective'), r.get('chain')))
    # An orgs map with NO enterprise entry is KDEC-022 item 1 (A12): the strictest registered org, not
    # the enterprise floor -- with no org entries anywhere that is crawl, under the A12 notice.
    r = res(central([]), repository='globex/thing')
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'crawl' and not notice_of(r)
          and [n for n in r.get('notices') or [] if n.get('code') == NOTICE_ORG],
          'A11/A12: an orgs map with no enterprise entry did not run the unmapped org at the strictest org '
          '(crawl, none registered above it) with the A12 notice: %r %r' % (r['state'], r.get('notices')))
    # No register at all: unchanged -- the kit default, and no notice.
    r = res(None, repository='globex/thing')
    check(r['state'] == rl.POLICY_RESOLVED and r['policy_source'] == 'KIT_DEFAULT' and not r.get('notices'),
          'A11: with no register an unnamed org did not resolve to the kit default without a notice: %r %r'
          % (r['state'], r.get('notices')))
    # --validate no longer refuses a register that mentions unmapped orgs: they run, at the floor.
    work = tempfile.mkdtemp(prefix='authority-floor-')
    path = os.path.join(work, 'central.json')
    try:
        doc = central([org_walk, entry('globex-org', {'org': 'globex'}, rung='walk')],
                      repositories={'acme/ledger-api': {'team': 'payments', 'product': 'ledger'},
                                    'initech/tps': {'team': 'reports'}})
        with io.open(path, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(doc))
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'policy_registration.py'), '--validate',
                            path, '--origin', 'central', '--today', TODAY], capture_output=True, text=True)
        check(p.returncode == 0 and RETIRED not in p.stdout,
              'A11: --validate refused a register mentioning unmapped orgs: rc %d %s' % (p.returncode, p.stdout[-400:]))
    finally:
        try:
            os.remove(path)
            os.rmdir(work)
        except OSError:
            pass
    src = io.open(os.path.join(ROOT, 'scripts', 'policy_registration.py'), encoding='utf-8').read()
    check(RETIRED not in src, 'A11: the resolver still carries the %s refusal' % RETIRED)
    notice_vals = (((tax.get('namespaces') or {}).get('policy_notice') or {}).get('values') or {})
    check(NOTICE in notice_vals, 'A11: %s is not a registered policy_notice value' % NOTICE)

    # ---- A12 no enterprise entry: an unmapped org runs at the STRICTEST registered org (KDEC-022) --
    # Owner, 2026-10-23: "Yes you should get the strictest from the orgs."
    def org_notice(r):
        return [n for n in r.get('notices') or [] if n.get('code') == NOTICE_ORG]

    acme_walk = entry('acme-walk', {'org': 'acme'}, rung='walk')
    beta_run = entry('beta-run', {'org': 'beta'}, rung='run')
    for label, doc in (('no orgs map', central([acme_walk, beta_run], orgs=None)),
                       ('an orgs map, no enterprise entry', central([acme_walk, beta_run],
                                                                    orgs={'acme': 'acme-group', 'beta': 'beta-group'}))):
        if doc.get('orgs') is None:
            del doc['orgs']
        for env in ('prod', 'dev', ''):
            r = res(doc, repository='globex/thing', environment=env)
            n = org_notice(r)
            check(r['state'] == rl.POLICY_RESOLVED and r.get('rung_effective') == 'run' and r['chain'] == ['beta-run'],
                  'A12 (%s, env %r): the unmapped org did not run at the strictest org (beta, run): %r %r %r'
                  % (label, env, r['state'], r.get('rung_effective'), r.get('chain')))
            check(bool(n) and n[0].get('org') == 'globex' and n[0].get('floor_org') == 'beta'
                  and n[0].get('rung') == 'run' and 'globex' in (n[0].get('why') or ''),
                  'A12 (%s, env %r): no named %s notice: %r' % (label, env, NOTICE_ORG, r.get('notices')))
            check(not notice_of(r), 'A12 (%s): the enterprise-floor notice fired with no enterprise entry' % label)
            check(any(x.startswith('policy_notices=') and NOTICE_ORG in x and 'beta' in x
                      for x in pr.github_output_lines(r)),
                  'A12 (%s): the notice is not in the GitHub outputs (policy_notices)' % label)
            check(any(NOTICE_ORG in x for x in r.get('notes') or []), 'A12 (%s): the notice is not in the notes' % label)
    # Tier by tier: acme is walk everywhere, beta is run only at uat/prod (crawl below). At dev the
    # strictest is acme (walk), at prod beta (run) -- the same comparison KDEC-020 makes per tier.
    beta_tiers = [entry('beta-prod', {'org': 'beta', 'environment_tier': 'prod'}, rung='run'),
                  entry('beta-uat', {'org': 'beta', 'environment_tier': 'uat'}, rung='run')]
    no_map = central([acme_walk] + beta_tiers)
    del no_map['orgs']
    for env, rung, floor_org in (('dev', 'walk', 'acme'), ('prod', 'run', 'beta')):
        r = res(no_map, repository='globex/thing', environment=env)
        n = org_notice(r)
        check(r['state'] == rl.POLICY_RESOLVED and r.get('rung_effective') == rung and n
              and n[0].get('floor_org') == floor_org,
              'A12: at %s the unmapped org did not take the strictest org for that tier (%s, %s): %r %r %r'
              % (env, floor_org, rung, r['state'], r.get('rung_effective'), r.get('notices')))
    # It may tighten above that floor (its own repository file), never go below it.
    repo_run = {'schema_version': 2, 'register_id': 'r', 'sign_off': central([])['sign_off'],
                'policies': [entry('own', {}, rung='run')]}
    repo_crawl = {'schema_version': 2, 'register_id': 'r', 'sign_off': central([])['sign_off'],
                  'policies': [entry('own', {}, rung='crawl')]}
    walk_only = central([acme_walk])
    del walk_only['orgs']
    r = res(walk_only, repo_run, repository='globex/thing')
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'run',
          'A12: the unmapped org\'s own file tightening above the strictest org was not honoured: %r %r'
          % (r['state'], r.get('rung_effective')))
    r = res(walk_only, repo_crawl, repository='globex/thing')
    check(r['state'] == 'REPOSITORY_FILE_SOFTENING' and r['rung_effective'] == 'walk',
          'A12: the unmapped org\'s own file going below the strictest org resolved %r (rung %r)'
          % (r['state'], r.get('rung_effective')))
    # The floor org's per-finding exceptions are its own: they never travel to the unmapped org.
    sx_beta = entry('beta-run', {'org': 'beta'}, rung='run', secret_exceptions=[sx])
    sx_doc = central([sx_beta])
    del sx_doc['orgs']
    r = res(sx_doc, repository='globex/thing')
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'run' and not r.get('secret_exceptions'),
          'A12: the floor org\'s secret exception travelled to the unmapped org: %r' % r.get('secret_exceptions'))
    # A registered org keeps its own entries and carries no notice.
    r = res(no_map, repository='acme/x', environment='prod')
    check(r['state'] == rl.POLICY_RESOLVED and r['rung_effective'] == 'walk' and not org_notice(r),
          'A12: a registered org was moved to the strictest org or noticed: %r %r %r'
          % (r['state'], r.get('rung_effective'), r.get('notices')))
    # With an enterprise entry, KDEC-020 still governs (the enterprise floor, its own notice).
    r = res(central([ent_walk, entry('beta-run', {'org': 'beta'}, rung='run')],
                    orgs={'acme': 'acme-group', 'beta': 'acme-group'}), repository='globex/thing')
    check(r['rung_effective'] == 'walk' and notice_of(r) and not org_notice(r),
          'A12: with an enterprise entry the unmapped org did not stay at the enterprise floor (KDEC-020): %r %r'
          % (r.get('rung_effective'), r.get('notices')))
    check(NOTICE_ORG in notice_vals, 'A12: %s is not a registered policy_notice value' % NOTICE_ORG)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: an enterprise binds every org mapped to it; the highest authority\'s rung and controls are '
          'the floor -- every narrower scope (org under enterprise, team, product, team+product, '
          'repository, a tier beneath a tier-less entry) only tightens, and leaving anything weaker is '
          'POLICY_BELOW_AUTHORITY_FLOOR (BLOCKED) even with an unexpired decision; only the authority may '
          'soften the kit default deploy approval; crawl is absolute; per-finding exceptions are unaffected; '
          'an org outside the orgs map runs at the strictest enterprise floor with a named notice '
          '(ORG_UNMAPPED_RAN_AT_ENTERPRISE_FLOOR) and may only tighten above it.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
