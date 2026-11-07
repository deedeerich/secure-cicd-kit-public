#!/usr/bin/env python3
"""One approver list: the policy register's deploy approval names its approver groups from a named list,
kept inline or in a shared file the landing zone reads too. (OF-5 K-9, the LZ-vs-kit review's P6)

WHY THIS EXISTS

    The landing zone wrote the uat/prod reviewers from its tenant worksheet; the kit checked them against
    its policy register's approver_groups. Two lists drift, and every release is then refused
    (ENVIRONMENT_APPROVER_GROUP_MISSING) -- or, worse, both drift together the wrong way. The review
    adopted ONE list: the landing zone's hand-off write READS the kit register's list and refuses a
    worksheet that disagrees. The kit side: the register can hold the list once, by name, and point
    every tier's deploy approval at it, and the list can live in its own file (the configurable source)
    that both sides read.

      approver_lists            {name: [group, ...]}, central register only
      approver_lists_source     a path, relative to the central register, of a JSON file holding
                                {"approver_lists": {name: [group, ...]}} -- the shared list file
      deploy_approval.approver_groups_from   the list's name, instead of approver_groups

CASES
    A1  inline lists: every tier that names a list resolves to its groups (deploy_approval output)
    A2  the source file, read beside the central register through resolve_from_ref and --validate:
        the same groups; the file's sha256 is in the resolution notes
    A3  approver_groups and approver_groups_from in one entry -> POLICY_REGISTER_CONFLICT
    A4  a name no list defines -> REGISTRATION_UNAVAILABLE (refused, never the default)
    A5  the source file missing or not a list of names -> REGISTRATION_UNAVAILABLE
    A6  inline lists AND a source -> POLICY_REGISTER_CONFLICT (two sources of one list)
    A7  a repository file naming a list -> refused: the list is the central register's
    A8  the deploy's environment_protection holds the environment to the resolved groups: a reviewer
        outside the list -> ENVIRONMENT_APPROVER_GROUP_MISSING; from the list -> VERIFIED
    A9  the schema admits the new keys and the example register validates

EXIT 0 proven   1 a case failed   2 could not be checked
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
import prove_policy_registration as PP  # noqa: E402  (its register builders)

FAILS = []
TODAY = '2026-10-28'
GROUPS = ['architects', 'platform', 'security']


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def reg(da_prod, da_uat=None, **top):
    pols = [PP.entry('org', {'org': 'acme'}, rung='crawl'),
            PP.entry('prod', {'org': 'acme', 'environment_tier': 'prod'}, deploy_approval=da_prod)]
    if da_uat is not None:
        pols.append(PP.entry('uat', {'org': 'acme', 'environment_tier': 'uat'}, deploy_approval=da_uat))
    return PP.central(pols, **top)


def main():
    try:
        import policy_registration as pr
        import rung_ladder as rl
        import environment_protection as ep
    except ImportError as exc:
        print('FAIL: %s' % exc)
        return 1

    def res(cen, repo_doc=None, env='prod'):
        return pr.resolve(cen, repo_doc, 'acme/ledger-api', env, 'push', {}, TODAY,
                          history=pr.committed_once(cen, repo_doc))

    def da(r, tier):
        return ((r.get('deploy_approval') or {}).get(tier) or {})

    from_list = {'approver_groups_from': 'deployment-approvers', 'approvers_required': 1,
                 'self_review_prevented': 'required'}
    lists = {'deployment-approvers': GROUPS}
    r = res(reg(from_list, from_list, approver_lists=lists))
    expect(r['state'] == rl.POLICY_RESOLVED and da(r, 'prod').get('approver_groups') == GROUPS and
           da(r, 'uat').get('approver_groups') == GROUPS and da(r, 'prod').get('approver_groups_from') == 'deployment-approvers',
           'A1 inline: uat and prod resolve the named list (%s, %s)' % (r['state'], da(r, 'prod')))

    both = dict(from_list, approver_groups=['security'])
    r = res(reg(both, approver_lists=lists))
    expect(r['state'] == pr.POLICY_REGISTER_CONFLICT, 'A3 approver_groups and approver_groups_from in one entry -> '
           'POLICY_REGISTER_CONFLICT (%s)' % r['state'])
    r = res(reg(dict(from_list, approver_groups_from='nobody'), approver_lists=lists))
    expect(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'A4 a list nobody defines -> REGISTRATION_UNAVAILABLE (%s)' % r['state'])
    r = res(reg(from_list))
    expect(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'A4 no lists at all -> REGISTRATION_UNAVAILABLE (%s)' % r['state'])
    r = res(reg(from_list, approver_lists=lists, approver_lists_source='approver-lists.json'))
    expect(r['state'] == pr.POLICY_REGISTER_CONFLICT, 'A6 inline lists and a source -> POLICY_REGISTER_CONFLICT (%s)'
           % r['state'])
    repo_doc = {'schema_version': 2, 'register_id': 'own', 'sign_off': PP.central([])['sign_off'],
                'policies': [PP.entry('own-prod', {'environment_tier': 'prod'}, rung='walk',
                                      deploy_approval={'approver_groups_from': 'deployment-approvers'})]}
    r = res(reg({'approver_groups': GROUPS}), repo_doc=repo_doc)
    expect(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'A7 a repository file naming a list is refused (%s)' % r['state'])

    work = tempfile.mkdtemp(prefix='approver-lists-')
    try:
        cen = reg(from_list, from_list, approver_lists_source='approver-lists.json')
        cpath = os.path.join(work, 'policy-registration.json')
        io.open(cpath, 'w', encoding='utf-8').write(json.dumps(cen, indent=1))
        src = os.path.join(work, 'approver-lists.json')
        io.open(src, 'w', encoding='utf-8').write(json.dumps({'approver_lists': lists}))
        repo = os.path.join(work, 'repo')
        os.makedirs(repo)
        PP.git(repo, 'init', '-q')
        PP.git(repo, 'commit', '-q', '--allow-empty', '-m', 'empty')

        def rref():
            return pr.resolve_from_ref(repo=repo, default_ref='HEAD', path='.security/policy-registration.json',
                                       central_path=cpath, repository='acme/ledger-api', environment='prod',
                                       event='push', supplied_inputs={}, today=TODAY)
        r = rref()
        import hashlib
        sha = hashlib.sha256(io.open(src, 'rb').read()).hexdigest()
        expect(r['state'] == rl.POLICY_RESOLVED and da(r, 'prod').get('approver_groups') == GROUPS and
               any(sha in n for n in r.get('notes') or []),
               'A2 the source file beside the central register resolves the list, its sha256 noted (%s, %s)'
               % (r['state'], da(r, 'prod').get('approver_groups')))
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'policy_registration.py'), '--validate',
                            cpath, '--origin', 'central', '--today', TODAY], capture_output=True, text=True)
        expect(p.returncode == 0, 'A2 --validate reads the source beside the file (rc=%d %s)' % (p.returncode,
                                                                                          (p.stdout + p.stderr)[-300:]))
        os.remove(src)
        r = rref()
        expect(r['state'] == rl.REGISTRATION_UNAVAILABLE and r.get('rung_effective') is None,
               'A5 the source file missing -> REGISTRATION_UNAVAILABLE, never the default (%s)' % r['state'])
        io.open(src, 'w', encoding='utf-8').write(json.dumps({'approver_lists': {'deployment-approvers': 'security'}}))
        r = rref()
        expect(r['state'] == rl.REGISTRATION_UNAVAILABLE, 'A5 a source that is not lists of names -> refused (%s)'
               % r['state'])
    finally:
        shutil.rmtree(work, ignore_errors=True)

    r = res(reg(from_list, from_list, approver_lists=lists))
    demand = json.dumps(r.get('deploy_approval') or {})
    d, _n = ep.demand_for('prod', demand)

    def env_doc(*slugs):
        return {'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': True,
                                      'reviewers': [{'type': 'Team', 'reviewer': {'slug': s, 'name': s}} for s in slugs]}]}
    expect(ep.evaluate(env_doc('platform'), d)[0] == 'ENVIRONMENT_PROTECTION_VERIFIED' and
           ep.evaluate(env_doc('platform', 'marketing'), d)[0] == 'ENVIRONMENT_APPROVER_GROUP_MISSING',
           'A8 the deploy holds the environment to the resolved list (inside the list: ENVIRONMENT_PROTECTION_VERIFIED; outside it: ENVIRONMENT_APPROVER_GROUP_MISSING)')

    try:
        import jsonschema
    except ImportError:
        jsonschema = None
    schema = json.load(io.open(os.path.join(ROOT, 'schemas', 'policy-registration.schema.json'), encoding='utf-8'))
    if jsonschema is None:
        props = schema.get('properties') or {}
        expect('approver_lists' in props and 'approver_lists_source' in props, 'A9 the schema names the new keys')
    else:
        errs = list(jsonschema.Draft202012Validator(schema).iter_errors(reg(from_list, approver_lists=lists)))
        expect(not errs, 'A9 a register with a named list validates against the schema (%s)' % [e.message for e in errs][:2])
        errs = list(jsonschema.Draft202012Validator(schema).iter_errors(reg(from_list, approver_lists_source='x.json')))
        expect(not errs, 'A9 a register with a list source validates against the schema')
    ex = json.load(io.open(os.path.join(ROOT, 'templates', 'policy-register.central.example.json'), encoding='utf-8'))
    expect('approver_lists' in ex and any((p.get('deploy_approval') or {}).get('approver_groups_from')
                                          for p in ex.get('policies') or []),
           'A9 the central example shows one named list used by the deploy approval')
    if FAILS:
        print('FAIL: %d case(s).' % len(FAILS))
        return 1
    print('PASS: the register names its approver groups once, inline or in a shared list file both sides read; '
          'each tier\'s deploy approval resolves from it; two lists in one entry, two sources of one list, an '
          'unknown name, an unreadable source and a repository-level list are refused by name; the deploy holds '
          'the environment to the resolved list.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
