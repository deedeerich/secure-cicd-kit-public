#!/usr/bin/env python3
"""The negative-test manifest tells a known fixture seed from a new alert, and never by directory.

WHAT IS PROVEN (scripts/fixture_seeds.py, tests/negative-test-manifest.json; owner 2026-11-19)
    N1  the eight Dependabot alerts dismissed on 2026-11-19 (log4j-core GHSA-h383-gmxw-35v2 and the
        seven phpmailer 5.2.18 advisories), in the Dependabot API shape with the version read from the
        tree, each classify KNOWN_SEED
    N2  the real tree holds: `check` passes (T1-T7)
    N3  NEW, each with its cause: a new advisory on a seeded package, a missing advisory id, a changed
        pin (in the alert, and in the tree), a new dependency beside a seed, another file in a seed's
        directory, the directory itself, an unrecorded code-scanning rule
    N4  the tree check refuses: a pin bumped in a fixture (T1), a dependency added to a fixture (T2), a
        manifest format it cannot read (T3), an expected signal with no seed (T4), a dependency seed with
        no advisory id and no reason (T7); `classify` exits 1 on a NEW alert and 0 when all are known
    M   mutants of the checker, each caught: a directory-wide match, a missing advisory id accepted, a
        changed pin ignored, and the tree check skipping undeclared pins

EXIT  0 proven   1 a claim failed (named)   2 could not be checked
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
SCRIPT = os.path.join(ROOT, 'scripts', 'fixture_seeds.py')
fails = []


def claim(ok, text):
    print('%s  %s' % ('PASS' if ok else 'FAIL', text))
    if not ok:
        fails.append(text)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


DISMISSED = [   # D:/handoffs KIT_FIXTURE_ALERT_DISMISSALS_2026-11-19: alert, package, advisory, file
    (105, 'org.apache.logging.log4j:log4j-core', 'GHSA-h383-gmxw-35v2', 'tests/consumer-fixture/full/java/pom.xml'),
    (106, 'phpmailer/phpmailer', 'GHSA-4pc3-96mx-wwc8', 'tests/consumer-fixture/full/php/composer.lock'),
    (107, 'phpmailer/phpmailer', 'GHSA-58mj-pw57-4vm2', 'tests/consumer-fixture/full/php/composer.lock'),
    (108, 'phpmailer/phpmailer', 'GHSA-4x5h-cr29-fhp6', 'tests/consumer-fixture/full/php/composer.lock'),
    (109, 'phpmailer/phpmailer', 'GHSA-7w4p-72j7-v7c2', 'tests/consumer-fixture/full/php/composer.lock'),
    (110, 'phpmailer/phpmailer', 'GHSA-f7hx-fqxw-rvvj', 'tests/consumer-fixture/full/php/composer.lock'),
    (111, 'phpmailer/phpmailer', 'GHSA-77mr-wc79-m8j3', 'tests/consumer-fixture/full/php/composer.lock'),
    (112, 'phpmailer/phpmailer', 'GHSA-7q44-r25x-wm4q', 'tests/consumer-fixture/full/php/composer.lock'),
]


def dependabot(num, pkg, ghsa, path):
    return {'number': num, 'dependency': {'manifest_path': path, 'package': {'name': pkg}},
            'security_advisory': {'ghsa_id': ghsa}}


LOCK = 'tests/consumer-fixture/full/php/composer.lock'
# (label, alert, want match, want cause) -- run against any module, so the mutants can be judged.
CASES = [
    ('a new advisory on a seeded package', {'path': LOCK, 'package': 'phpmailer/phpmailer', 'version': '5.2.18',
                                            'advisory': 'GHSA-aaaa-bbbb-cccc'}, 'NEW', 'ADVISORY_NOT_IN_MANIFEST'),
    ('a missing advisory id', {'path': LOCK, 'package': 'phpmailer/phpmailer', 'version': '5.2.18'},
     'NEW', 'NO_ADVISORY_ID'),
    ('a changed pin in the alert', {'path': LOCK, 'package': 'phpmailer/phpmailer', 'version': '6.5.0',
                                    'advisory': 'GHSA-4pc3-96mx-wwc8'}, 'NEW', 'PIN_CHANGED'),
    ('a new dependency beside a seed', {'path': LOCK, 'package': 'guzzlehttp/guzzle', 'version': '6.0.0',
                                        'advisory': 'GHSA-4pc3-96mx-wwc8'}, 'NEW', 'NOT_A_SEED'),
    ('another file in the seed directory', {'path': 'tests/consumer-fixture/full/php/other.lock',
                                            'package': 'phpmailer/phpmailer', 'version': '5.2.18',
                                            'advisory': 'GHSA-4pc3-96mx-wwc8'}, 'NEW', 'NOT_A_SEED'),
    ('the directory itself', {'path': 'tests/consumer-fixture/full/php', 'package': 'phpmailer/phpmailer',
                              'version': '5.2.18', 'advisory': 'GHSA-4pc3-96mx-wwc8'}, 'NEW', 'NOT_A_SEED'),
    ('an unrecorded rule on a recorded seed', {'path': 'tests/consumer-fixture/full/python/vuln.py',
                                               'rule': 'B999', 'tool': 'bandit'}, 'NEW', 'RULE_NOT_IN_MANIFEST'),
    ('a rule on a seed with none recorded', {'path': 'tests/consumer-fixture/full/cpp/vuln.c', 'rule': 'FF1001',
                                             'tool': 'flawfinder'}, 'NEW', 'RULE_NOT_RECORDED'),
    ('a recorded rule', {'path': 'tests/consumer-fixture/full/python/vuln.py', 'rule': 'B602', 'tool': 'bandit'},
     'KNOWN_SEED', None),
    ('the exact seed', {'path': LOCK, 'package': 'phpmailer/phpmailer', 'version': 'v5.2.18',
                        'advisory': 'GHSA-7q44-r25x-wm4q'}, 'KNOWN_SEED', None),
]


def case_failures(mod, root):
    seeds = mod.load_manifest(root)['seeds']
    out = []
    tv = mod.tree_versions(root)
    for num, pkg, ghsa, path in DISMISSED:
        r = mod.classify_one(dependabot(num, pkg, ghsa, path), seeds, tv)
        if r['match'] != 'KNOWN_SEED':
            out.append('N1 dismissed alert %d (%s %s) read %s/%s' % (num, pkg, ghsa, r['match'], r['cause']))
    for label, alert, want, cause in CASES:
        r = mod.classify_one(alert, seeds, tv)
        if (r['match'], r['cause']) != (want, cause):
            out.append('N3 %s read %s/%s, want %s/%s' % (label, r['match'], r['cause'], want, cause))
    return out


def copy_tree(dst):
    for rel in ('tests/consumer-fixture', 'tests/fixtures/deploy-probe'):
        shutil.copytree(os.path.join(ROOT, rel), os.path.join(dst, rel))
    for rel in ('tests/make_fixture.py', 'tests/negative-test-manifest.json', 'scripts/fixture_seeds.py'):
        os.makedirs(os.path.dirname(os.path.join(dst, rel)), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, rel), os.path.join(dst, rel))


def run(root, *args):
    env = dict(os.environ, KIT_PROOF_ROOT=root)
    p = subprocess.run([sys.executable, os.path.join(root, 'scripts', 'fixture_seeds.py')] + list(args),
                       capture_output=True, text=True, env=env, timeout=120, cwd=root)
    return p.returncode, p.stdout + p.stderr


def edit(root, rel, old, new):
    p = os.path.join(root, rel)
    text = io.open(p, encoding='utf-8').read()
    if old not in text:
        raise AssertionError('%s: %r not found' % (rel, old))
    io.open(p, 'w', encoding='utf-8', newline='\n').write(text.replace(old, new, 1))


def tree_case(label, rule, mutate):
    tmp = tempfile.mkdtemp(prefix='ntm-')
    try:
        copy_tree(tmp)        # no .git here: the checker walks the tree, as in an export
        rc0, out0 = run(tmp, 'check')
        if rc0 != 0:
            claim(False, 'N4 the unmutated copy holds (rc %d): %s' % (rc0, out0.strip()[-300:]))
            return
        mutate(tmp)
        rc, out = run(tmp, 'check')
        claim(rc == 1 and rule in out, 'N4 %s is refused by %s (rc %d)%s' % (
            label, rule, rc, '' if rc == 1 and rule in out else ': ' + out.strip()[-300:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    if not os.path.isfile(SCRIPT):
        print('UNKNOWN: %s is missing' % SCRIPT)
        return 2
    mod = load(SCRIPT, 'fixture_seeds_real')

    # N1, N3 on the real manifest.
    got = case_failures(mod, ROOT)
    for f in got:
        claim(False, f)
    claim(not [f for f in got if f.startswith('N1')],
          'N1 the 8 alerts dismissed on 2026-11-19 each classify KNOWN_SEED (Dependabot shape, version from the tree)')
    claim(not [f for f in got if f.startswith('N3')],
          'N3 a new advisory, a missing id, a changed pin, a new dependency, another file, the directory and '
          'an unrecorded rule each read NEW with their cause; an exact seed and a recorded rule read KNOWN_SEED')

    # N2: the real tree.
    rc, out = run(ROOT, 'check')
    claim(rc == 0, 'N2 the real tree holds (%s)' % out.strip().splitlines()[-1][:200])
    rc, out = run(ROOT, '--self-test')
    claim(rc == 0, 'N2 the checker\'s own self-test passes')

    # N4: classify's exit code, and the tree refusals.
    tmp = tempfile.mkdtemp(prefix='ntm-alerts-')
    try:
        known = os.path.join(tmp, 'known.json')
        json.dump([dependabot(*d) for d in DISMISSED], io.open(known, 'w', encoding='utf-8'))
        rc, out = run(ROOT, 'classify', known)
        claim(rc == 0 and '8 KNOWN_SEED, 0 NEW' in out, 'N4 classify exits 0 on the 8 known seeds (rc %d)' % rc)
        paged = os.path.join(tmp, 'paged.json')   # `gh api --paginate`: one array per page, back to back
        io.open(paged, 'w', encoding='utf-8').write(
            json.dumps([dependabot(*d) for d in DISMISSED[:4]]) + '\n' + json.dumps([dependabot(*d) for d in DISMISSED[4:]]))
        rc, out = run(ROOT, 'classify', paged)
        claim(rc == 0 and '8 KNOWN_SEED, 0 NEW' in out,
              'N4 classify reads the back-to-back pages `gh api --paginate` prints (rc %d)' % rc)
        mixed = os.path.join(tmp, 'mixed.json')
        json.dump([dependabot(*DISMISSED[0]),
                   dependabot(200, 'phpmailer/phpmailer', 'GHSA-aaaa-bbbb-cccc', LOCK)], io.open(mixed, 'w', encoding='utf-8'))
        rc, out = run(ROOT, 'classify', mixed, '--json')
        res = json.loads(out) if rc in (0, 1) else {}
        claim(rc == 1 and res.get('outcome') == 'NEW_ALERTS'
              and [r['match'] for r in res.get('results', [])] == ['KNOWN_SEED', 'NEW'],
              'N4 classify exits 1 when one alert is NEW, and names outcome and cause separately (rc %d)' % rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    tree_case('a phpmailer pin bumped in composer.lock', 'T1',
              lambda r: edit(r, LOCK, '"version": "v5.2.18"', '"version": "v6.5.0"'))
    tree_case('a dependency added to a fixture package.json', 'T2',
              lambda r: edit(r, 'tests/consumer-fixture/full/node/package.json', '"axios": "0.18.0"',
                             '"axios": "0.18.0",\n    "left-pad": "1.0.0"'))
    tree_case('a fixture manifest in a format the checker cannot read', 'T3',
              lambda r: io.open(os.path.join(r, 'tests/consumer-fixture/full/node/yarn.lock'), 'w').write('x\n'))
    tree_case('an expected signal with no seed', 'T4',
              lambda r: edit(r, 'tests/consumer-fixture/iac-heavy/EXPECTED_SIGNALS.json', '[',
                             '[{"path": "modules/new/main.tf", "expected_signal": "iac:tf-new"},', ))
    tree_case('a dependency seed with no advisory and no reason', 'T7',
              lambda r: edit(r, 'tests/negative-test-manifest.json',
                             '"advisories_not_established": "trivy fs reads no NuGet pin',
                             '"advisories_unexplained": "trivy fs reads no NuGet pin'))

    # The changed pin seen through a Dependabot alert (no version in the alert): read from the tree.
    tmp = tempfile.mkdtemp(prefix='ntm-pin-')
    try:
        copy_tree(tmp)
        edit(tmp, LOCK, '"version": "v5.2.18"', '"version": "v6.5.0"')
        m = load(os.path.join(tmp, 'scripts', 'fixture_seeds.py'), 'fixture_seeds_tmp')
        r = m.classify_one(dependabot(*DISMISSED[1]), m.load_manifest(tmp)['seeds'], m.tree_versions(tmp))
        claim((r['match'], r['cause']) == ('NEW', 'PIN_CHANGED'),
              'N4 a Dependabot alert on a pin changed in the tree reads NEW/PIN_CHANGED (%s/%s)' % (r['match'], r['cause']))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # M: mutants of the checker.
    src = io.open(SCRIPT, encoding='utf-8').read()
    mutants = [
        ('MU1 a directory-wide match',
         "at_path = [s for s in seeds if norm_path(s.get('path')) == path]",
         "at_path = [s for s in seeds if os.path.dirname(norm_path(s.get('path'))) == os.path.dirname(path)]"),
        ('MU2 a missing advisory id accepted',
         "        if not adv:\n",
         "        if not adv:\n            out.update(match='KNOWN_SEED', cause=None, seed=hit[0].get('id'))\n"
         "            return out\n"),
        ('MU3 a changed pin ignored',
         "hit = [s for s in same if norm_ver(s.get('version')) == norm_ver(ver)]",
         "hit = same"),
        ('MU4 the tree check skips undeclared pins',
         "if (rel, norm_pkg(pk), norm_ver(v)) not in declared:",
         "if False:"),
    ]
    for label, old, new in mutants:
        if old not in src:
            claim(False, '%s: the mutation site is gone from the checker' % label)
            continue
        tmp = tempfile.mkdtemp(prefix='ntm-mu-')
        try:
            copy_tree(tmp)
            mp = os.path.join(tmp, 'scripts', 'fixture_seeds.py')
            io.open(mp, 'w', encoding='utf-8', newline='\n').write(src.replace(old, new, 1))
            caught = bool(case_failures(load(mp, 'mu_%d' % mutants.index((label, old, new))), tmp))
            if not caught:      # a tree-check mutant shows on the tree, not the matcher
                edit(tmp, 'tests/consumer-fixture/full/node/package.json', '"axios": "0.18.0"',
                     '"axios": "0.18.0",\n    "left-pad": "1.0.0"')
                rc, _ = run(tmp, 'check')
                caught = rc != 1
            claim(caught, '%s is caught' % label)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print()
    if fails:
        print('FAIL: %d claim(s) failed.' % len(fails))
        return 1
    print('PASS: the negative-test manifest tells every known seed from a new alert, never by directory; '
          'the tree check refuses drift; 4 mutants caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
