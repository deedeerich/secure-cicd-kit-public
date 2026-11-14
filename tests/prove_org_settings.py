#!/usr/bin/env python3
"""Governed kit settings come from the org overlay in the kit copy; the Azure cloud is per environment. (owner 2026-11-07)

WHY THIS EXISTS
    GitHub resolves a variable or secret at its LOWEST level (environment, then repository, then organisation;
    docs.github.com "Variables reference" and "Secrets reference", retrieved 2026-11-07), so a repository can
    shadow an organisation value and a job cannot tell which level it read. The owner ruled that governed kit
    settings -- approver pools, the app team and small-team self-approval, the default adoption level, the
    Azure cloud per environment and ticket routing -- come from the org overlay inside the org's kit
    repository, read by the reusable workflow from its own checkout, and that consumer values may only
    tighten. scripts/org_settings.py reads it; .github/actions/org-settings runs it in the deploys; the
    rollback runs it from its kit checkout.

WHAT IT PROVES (no network; the neutral fixture tests/fixtures/org-overlay)
    O1  loading: the overlay naming the owner applies; none is ABSENT; two naming one org is AMBIGUOUS; an
        unreadable file or an unknown key is INVALID (positives P1-P3, negatives N1-N4)
    O2  small-team self-approval: in force only for a declared team of two or fewer with no pools and no
        external group, all five weakening fields, within its review and unexpired (P4; N5-N12)
    O3  the Azure cloud per environment: the overlay map (a repo-qualified key first), one declared cloud as
        the default, no overlay -> the environment's KIT_CLOUD then the input (P5-P9); unmapped with two
        clouds, a call or an org-wide KIT_CLOUD that disagrees, an unknown word, an unreadable overlay (N13-N17)
    O4  the composite AS SHIPPED, under bash, over a kit root holding the fixture: outputs, exit codes, the
        cloud written to CLOUD for the sign-in, nothing written on a refusal
    O5  wiring: every deploy runs the org-settings step before bind and login, its protection step reads
        KIT_ORG_SETTINGS from it, every Azure sign-in and lease reads the resolved cloud; the rollback runs
        the reader and the read-back before its sign-in
    O6  adoption: crawl unless the overlay overrides; the crawl clock says on track / past optimal (4 weeks) /
        advisory (8) / escalate (26, six months) and never promotes or extends
    O7  mutants: each rule removed from scripts/org_settings.py is caught by O1-O3
    O8  the fixture is neutral: every org it names is example-*; the template carries only placeholders

EXIT 0 proven   1 a rule failed   2 could not be checked (no bash, no PyYAML)
"""
import importlib.util
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
sys.path.insert(0, HERE)
FIX = os.path.join(HERE, 'fixtures', 'org-overlay')
TODAY = '2026-11-07'
DEPLOYS = ['.github/workflows/reusable-deploy-appservice.yml', '.github/workflows/reusable-deploy-containerapp.yml',
           '.github/workflows/reusable-deploy-staticwebapp.yml']
ROLLBACK = '.github/workflows/reusable-rollback-sequence.yml'
REC = {'approved_by': 'the organisation owner (role)', 'ref': 'DEC-1', 'date': '2026-11-01',
       'reason': 'two developers, no external approver group', 'expires': '2027-01-30', 'review_days': 90,
       'external_approver_group_available': False}


def overlay(org, **kw):
    d = {'schema': 'kit-org-settings/1', 'github_orgs': [org]}
    d.update(kw)
    return d


def kit_with(tmp, docs):
    """A kit root holding overlays/<name>/kit-org-settings.json for each (name, doc or raw text)."""
    root = tempfile.mkdtemp(dir=tmp)
    for name, doc in docs.items():
        d = os.path.join(root, 'overlays', name)
        os.makedirs(d)
        io.open(os.path.join(d, 'kit-org-settings.json'), 'w', encoding='utf-8').write(
            doc if isinstance(doc, str) else json.dumps(doc))
    return root


def o1_load(M, check, tmp):
    doc, st, src, _w = M.load(FIX, 'example-org')
    check(st == M.APPLIED and src.endswith('example-org/kit-org-settings.json'), 'P1 the example-org overlay applies (%s)' % st)
    check(M.load(FIX, 'EXAMPLE-SOLO')[1] == M.APPLIED, 'P2 the org name matches case-insensitively')
    check(M.load(FIX, 'someone-else')[1] == M.ABSENT, 'P3 an org no overlay names is ABSENT (the kit unchanged)')
    two = kit_with(tmp, {'a': overlay('o'), 'b': overlay('o')})
    check(M.load(two, 'o')[1] == M.AMBIGUOUS, 'N1 two overlays naming one org are AMBIGUOUS')
    bad = kit_with(tmp, {'a': '{not json'})
    check(M.load(bad, 'o')[1] == M.INVALID, 'N2 an unreadable overlay is INVALID, never ABSENT')
    unk = kit_with(tmp, {'a': overlay('o', surprise=True)})
    check(M.load(unk, 'o')[1] == M.INVALID, 'N3 an unknown key is INVALID (the reader is an allowlist)')
    wk = kit_with(tmp, {'a': overlay('o', adoption={'crawl_weeks_maximum': 40})})
    check(M.load(wk, 'o')[1] == M.INVALID, 'N4 a crawl maximum beyond six months (26 weeks) is INVALID')


def o2_small(M, check):
    def st(team=None, rec=None, **kw):
        e = {'team': '@o/devs', 'size': 2, 'members': ['@dev1', 'dev2']}
        e.update(team or {})
        kw.setdefault('known_solo_developers', {'o': ['dev1', 'dev2']})
        if rec is not False:
            e['small_team_self_approval'] = dict(REC, **(rec or {}))
        return M.small_team(overlay('o', app_teams={'o/r': e}, **kw), 'o/r', TODAY)[0]
    check(st() == M.ST_IN_FORCE, 'P4 a declared team of two, no pools, five fields, in its review: SMALL_TEAM_SELF_APPROVAL')
    check(st(rec=False) == M.ST_NOT_DECLARED, 'N5 nothing declared is NOT_DECLARED (self-review stays required)')
    check(st({'size': 3}) == M.ST_TOO_LARGE, 'N6 a team of three is TEAM_TOO_LARGE')
    check(st(approver_pools={'security': ['@o/security-approvers']}) == M.ST_POOLS, 'N7 approver pools exist: POOLS_EXIST')
    check(st(rec={'external_approver_group_available': True}) == M.ST_EXTERNAL, 'N8 an external group available: refused')
    check(st(rec={'ref': ''}) == M.ST_INCOMPLETE, 'N9 a weakening field missing (ref): INCOMPLETE')
    check(st(rec={'expires': '2027-03-30'}) == M.ST_BEYOND, 'N10 expiring past date + review_days: BEYOND_REVIEW')
    check(st(rec={'date': '2026-01-01', 'expires': '2026-03-01'}) == M.ST_EXPIRED, 'N11 expired: EXPIRED')
    check(st({'size': None}) == M.ST_INCOMPLETE, 'N12 no declared size: INCOMPLETE')
    # owner ruling 2026-11-07: only KNOWN solo developers the org names, never inferred from team size
    check(st(known_solo_developers={'someone-else': ['dev1', 'dev2']}) == M.ST_NOT_KNOWN_SOLO,
          'N17 the repository owner is not in known_solo_developers: refused, even for a team of two')
    check(st({'size': 1, 'members': ['@stranger']}) == M.ST_NOT_KNOWN_SOLO,
          'N18 an unlisted team of one: refused (team size alone never grants it)')
    check(st({'members': None}) == M.ST_NOT_KNOWN_SOLO, 'N19 an app team with no members listed: refused')
    check(st(known_solo_developers=None) == M.ST_NOT_KNOWN_SOLO, 'N20 no known_solo_developers at all: refused')
    check(st({'size': 1, 'members': ['DEV1']}) == M.ST_IN_FORCE,
          'P4b a listed solo developer (login case ignored) of a listed owner: SMALL_TEAM_SELF_APPROVAL')


def o3_cloud(M, check):
    multi = overlay('o', azure_clouds={'declared': ['commercial', 'gov'],
                                       'environments': {'prod': 'commercial', 'o/gov-app:prod': 'gov'}})
    one = overlay('o', azure_clouds={'declared': ['gov']})
    A = M.APPLIED
    check(M.azure_cloud(multi, A, 'o/app', 'prod', 'commercial', '')[:2] == ('commercial', M.AC_MAP), 'P5 mapped environment')
    check(M.azure_cloud(multi, A, 'o/gov-app', 'prod', 'gov', 'gov')[:2] == ('gov', M.AC_MAP),
          'P6 a repo-qualified key wins over the bare environment name')
    check(M.azure_cloud(one, A, 'o/app', 'uat', 'auto', '')[:2] == ('gov', M.AC_SINGLE), 'P7 one declared cloud is the default')
    check(M.azure_cloud(None, M.ABSENT, 'o/app', 'uat', 'commercial', 'gov')[:2] == ('gov', M.AC_ENV),
          'P8 no overlay: the environment\'s KIT_CLOUD')
    check(M.azure_cloud(None, M.ABSENT, 'o/app', 'uat', '', '')[:2] == ('commercial', M.AC_INPUT),
          'P9 no overlay, nothing set: commercial, as before')
    check(M.azure_cloud(multi, A, 'o/app', 'uat', 'commercial', '')[1] == M.AC_UNSET,
          'N13 two declared clouds and the environment unmapped: UNSET_FOR_ENVIRONMENT')
    check(M.azure_cloud(multi, A, 'o/gov-app', 'prod', 'commercial', '')[1] == M.AC_CONFLICT,
          'N14 the call says commercial, the overlay maps gov: CONFLICTS_WITH_ORG')
    check(M.azure_cloud(multi, A, 'o/gov-app', 'prod', 'gov', 'commercial')[1] == M.AC_CONFLICT,
          'N15 an organisation-wide KIT_CLOUD=commercial shadowing a gov environment: CONFLICTS_WITH_ORG')
    check(M.azure_cloud(None, M.ABSENT, 'o/app', 'uat', 'mars', '')[1] == M.AC_UNKNOWN, 'N16 an unknown cloud word: VALUE_UNKNOWN')
    check(M.azure_cloud(None, M.INVALID, 'o/app', 'uat', 'gov', '')[1] == M.AC_NOT_ESTABLISHED,
          'N17 an unreadable overlay: NOT_ESTABLISHED, never the input')


def o4_composite(check, tmp, yaml, bash):
    import prove_bootstrap_failure as _pbf  # noqa: F401 -- bash comes from main
    doc = yaml.safe_load(io.open(os.path.join(ROOT, '.github', 'actions', 'org-settings', 'action.yml'), encoding='utf-8'))
    body = doc['runs']['steps'][0]['run']
    kit = os.path.join(tmp, 'kit')
    shutil.copytree(os.path.join(FIX, 'overlays'), os.path.join(kit, 'overlays'))
    os.makedirs(os.path.join(kit, 'scripts'))
    shutil.copyfile(os.path.join(ROOT, 'scripts', 'org_settings.py'), os.path.join(kit, 'scripts', 'org_settings.py'))
    apath = os.path.join(kit, '.github', 'actions', 'org-settings')
    os.makedirs(apath)
    script = os.path.join(tmp, 'org-step.sh')
    io.open(script, 'w', encoding='utf-8', newline='\n').write(body)
    for cid, repo, envn, cloud, bound, rc, want_cloud, want_state in (
            ('C1', 'example-org/app', 'prod', 'commercial', '', 0, 'commercial', 'AZURE_CLOUD_FROM_ORG_MAP'),
            ('C2', 'example-org/gov-app', 'prod', 'auto', 'gov', 0, 'gov', 'AZURE_CLOUD_FROM_ORG_MAP'),
            ('C3', 'example-org/app', 'staging-eu', 'commercial', '', 1, '', 'AZURE_CLOUD_UNSET_FOR_ENVIRONMENT'),
            ('C4', 'example-org/gov-app', 'prod', 'gov', 'commercial', 1, '', 'AZURE_CLOUD_CONFLICTS_WITH_ORG'),
            ('C5', 'nobody/app', 'prod', 'gov', '', 0, 'gov', 'AZURE_CLOUD_FROM_INPUT')):
        out, envf = os.path.join(tmp, cid + '.out'), os.path.join(tmp, cid + '.env')
        io.open(out, 'w').close()
        io.open(envf, 'w').close()
        env = dict(os.environ, GITHUB_ACTION_PATH=apath, GITHUB_OUTPUT=out, GITHUB_ENV=envf, GITHUB_REPOSITORY=repo,
                   OS_ENVIRONMENT=envn, OS_CLOUD=cloud, OS_BOUND_CLOUD=bound, OS_AZURE='true')
        env.pop('GITHUB_STEP_SUMMARY', None)
        p = subprocess.run([bash, script], capture_output=True, text=True, env=env)
        o = dict(l.rstrip('\n').split('=', 1) for l in io.open(out, encoding='utf-8') if '=' in l)
        e = io.open(envf, encoding='utf-8').read()
        check(p.returncode == rc and o.get('azure_cloud_state') == want_state and o.get('azure_cloud', '') == want_cloud,
              'O4 %s as shipped: exit %d, %s %r (want %d, %s %r)%s' % (cid, p.returncode, o.get('azure_cloud_state'),
                                                                     o.get('azure_cloud'), rc, want_state, want_cloud,
                                                                     '' if p.returncode == rc else (p.stdout + p.stderr)[-200:]))
        check(('CLOUD=%s' % want_cloud in e) if rc == 0 else ('CLOUD=' not in e),
              'O4 %s: the sign-in cloud %s CLOUD' % (cid, 'is written to' if rc == 0 else 'is NOT written to'))
        if cid == 'C1':
            res = json.loads(o.get('org_settings') or '{}')
            check(res.get('state') == 'ORG_OVERLAY_APPLIED' and 'platform-approvers' in (res.get('pools') or []),
                  'O4 C1: the resolved overlay carries the pools for the protection step')


def o5_wiring(check, yaml):
    for wf in DEPLOYS:
        doc = yaml.safe_load(io.open(os.path.join(ROOT, wf), encoding='utf-8'))
        steps = doc['jobs']['deploy']['steps']
        ids = [s.get('id') for s in steps]
        org = next((s for s in steps if s.get('id') == 'org_settings'), {})
        login = [i for i, s in enumerate(steps) if str(s.get('uses', '')).startswith('azure/login@')]
        check(org.get('uses') == '$/.github/actions/org-settings', 'O5 %s runs the org-settings composite from $/' % wf)
        check('org_settings' in ids and 'bind' in ids and ids.index('org_settings') < ids.index('bind') and login and
              ids.index('org_settings') < login[0], 'O5 %s: org settings before bind and before login' % wf)
        prot = next((s for s in steps if s.get('id') == 'protection'), {})
        check((prot.get('env') or {}).get('KIT_ORG_SETTINGS') == '${{ steps.org_settings.outputs.org_settings }}',
              'O5 %s: the protection step reads the overlay the composite resolved' % wf)
        for i in login:
            w = steps[i].get('with') or {}
            check('steps.org_settings.outputs.azure_cloud' in str(w.get('environment')) and
                  'inputs.cloud' not in str(w.get('environment')) + str(w.get('audience')),
                  'O5 %s: azure/login signs in to the resolved cloud, never the raw input' % wf)
        lease = [s for s in steps if str(s.get('uses', '')).endswith('/target-lease') and (s.get('with') or {}).get('op') == 'acquire']
        check(all((s.get('with') or {}).get('cloud') == '${{ steps.org_settings.outputs.azure_cloud }}' for s in lease),
              'O5 %s: the lease names the resolved cloud' % wf)
    doc = yaml.safe_load(io.open(os.path.join(ROOT, ROLLBACK), encoding='utf-8'))
    steps = doc['jobs']['rollback']['steps']
    ids = [s.get('id') for s in steps]
    login = next(i for i, s in enumerate(steps) if str(s.get('uses', '')).startswith('azure/login@'))
    check('org_settings' in ids and 'protection' in ids and ids.index('org_settings') < ids.index('protection') < login,
          'O5 rollback: the org reader and the read-back run before the sign-in (owner O-42c)')
    check('environment_protection.py' in steps[ids.index('protection')].get('run', '') and
          '--tier-optional' in steps[ids.index('protection')].get('run', ''),
          'O5 rollback: the read-back is the deploys\' own script')
    w = steps[login].get('with') or {}
    check('steps.org_settings.outputs.azure_cloud' in str(w.get('environment')), 'O5 rollback: signs in to the resolved cloud')


def o6_adoption(M, check):
    doc, _s, _p, _w = M.load(FIX, 'example-org')
    check(M.adoption(doc, 'example-org/app')['default_level'] == 'crawl', 'P10 adoption starts at crawl')
    check(M.adoption(doc, 'example-org/strict-app')['default_level'] == 'walk', 'P11 the overlay overrides one repository')
    check(M.adoption(None, 'x/y')['default_level'] == 'crawl', 'P12 no overlay: crawl')
    for start, want in (('2026-11-01', 'CRAWL_ON_TRACK'), ('2026-10-01', 'CRAWL_PAST_OPTIMAL'),
                        ('2026-09-01', 'CRAWL_ADVISORY'), ('2026-04-01', 'CRAWL_MAXIMUM_ESCALATE'),
                        ('2027-01-01', 'CRAWL_START_UNKNOWN')):
        check(M.crawl_clock(start, TODAY)[0] == want, 'O6 crawl started %s: %s' % (start, want))
    src = io.open(os.path.join(ROOT, 'scripts', 'org_settings.py'), encoding='utf-8').read()
    check('promote' not in src.split('def crawl_clock')[1].split('def ')[0].replace('promotes', ''),
          'O6 the crawl clock only reports; nothing promotes or extends')


MUTANTS = [
    ('unset_refused', "        return '', AC_UNSET,", "        return 'commercial', AC_MAP,"),
    ('conflict_checked', '        if v and v != cloud:', '        if False:'),
    ('pools_block_small_team', '    if pools_of(doc):\n        return ST_POOLS', '    if False:\n        return ST_POOLS'),
    ('team_size', '    if size > SMALL_TEAM_MAX:', '    if False:'),
    ('known_solo', "        return ST_NOT_KNOWN_SOLO, rec, (", "        if False: return ST_NOT_KNOWN_SOLO, rec, ("),
    ('expiry', '    if t and x < t:', '    if False:'),
    ('review_window', '    if (x - d).days > rd:', '    if False:'),
    ('five_fields', '    if missing:\n        return ST_INCOMPLETE', '    if False:\n        return ST_INCOMPLETE'),
    ('org_match', "any(str(o).strip().lower() == (owner or '').strip().lower() for o in orgs)", 'True'),
    ('allowlist', "    for k in sorted(set(doc) - TOP_KEYS):", "    for k in []:"),
    ('invalid_not_input', "    if state in (INVALID, AMBIGUOUS):\n        return '', AC_NOT_ESTABLISHED",
     "    if False:\n        return '', AC_NOT_ESTABLISHED"),
]


def o7_mutants(check, tmp):
    src = io.open(os.path.join(ROOT, 'scripts', 'org_settings.py'), encoding='utf-8').read()
    for name, old, new in MUTANTS:
        if old not in src:
            check(False, 'O7 mutant %s: its target text is not in the script' % name)
            continue
        p = os.path.join(tmp, 'os_%s.py' % name)
        io.open(p, 'w', encoding='utf-8', newline='\n').write(src.replace(old, new, 1))
        spec = importlib.util.spec_from_file_location('os_%s' % name, p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fails = []
        sub = tempfile.mkdtemp(dir=tmp)
        for f in (o1_load, ):
            f(mod, lambda c, m: fails.append(m) if not c else None, sub)
        o2_small(mod, lambda c, m: fails.append(m) if not c else None)
        o3_cloud(mod, lambda c, m: fails.append(m) if not c else None)
        print('  O7 mutant %-24s %s' % (name, 'caught (%s)' % fails[0][:60] if fails else 'MISSED'))
        check(bool(fails), 'O7 mutant %s was not caught' % name)


def o8_neutral(check):
    for d in sorted(os.listdir(os.path.join(FIX, 'overlays'))):
        doc = json.load(io.open(os.path.join(FIX, 'overlays', d, 'kit-org-settings.json'), encoding='utf-8'))
        check(d.startswith('example-') and all(o.startswith('example-') for o in doc['github_orgs']),
              'O8 fixture overlay %s names only example-* organisations' % d)
    t = json.load(io.open(os.path.join(ROOT, 'templates', 'kit-org-settings.example.json'), encoding='utf-8'))
    import org_settings as M
    check(bool(M.placeholders(t)), 'O8 the template carries placeholders')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'org_settings.py'), 'validate',
                        os.path.join(ROOT, 'templates', 'kit-org-settings.example.json')], capture_output=True, text=True)
    check(p.returncode == 1 and 'placeholder' in p.stdout, 'O8 validate refuses the unfilled template (exit %d)' % p.returncode)


def main():
    try:
        import yaml
        import org_settings as M
        import prove_bootstrap_failure as pbf
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    bad = []

    def check(c, m):
        print('  %s %s' % ('ok  ' if c else 'FAIL', m))
        if not c:
            bad.append(m)

    tmp = tempfile.mkdtemp(prefix='org-settings-')
    try:
        o1_load(M, check, tmp)
        o2_small(M, check)
        o3_cloud(M, check)
        o4_composite(check, tmp, yaml, bash)
        o5_wiring(check, yaml)
        o6_adoption(M, check)
        o7_mutants(check, tmp)
        o8_neutral(check)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        print('FAIL: %d check(s)' % len(bad))
        return 1
    print('PASS: governed settings come from the org overlay in the kit copy, small-team self-approval only as a declared '
          'five-field weakening, the Azure cloud per environment (an unmapped one refused when two clouds are declared), '
          'adoption at crawl unless the overlay says otherwise; every rule removed is caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
