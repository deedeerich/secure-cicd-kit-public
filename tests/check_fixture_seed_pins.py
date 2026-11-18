#!/usr/bin/env python3
"""The test fixtures' deliberately vulnerable pins cannot change without a deliberate, reviewed edit.

WHY (owner, 2026-11-06)
    Dependabot PR #10 bumped phpmailer/phpmailer 5.2.18 -> 6.5.0 inside
    tests/consumer-fixture/full/php and was MERGED to main. That pin is the seed of the expected
    signal `deps:php-cve` (EXPECTED_SIGNALS.json): with it gone, the consumer-path negative grades a
    detection that has nothing left to detect, and the seeded assertion is silently disabled. The
    README warned; nothing failed. dependabot.yml now ignores the fixture, but an ignore is a
    configuration somebody can change, and a hand edit is a change too.

THE RULE
    Every dependency manifest committed under tests/consumer-fixture/ (requirements, composer,
    npm, maven, gradle, go, NuGet, Gemfile, Cargo, Pipfile, pyproject, Dockerfile) is held to a
    committed registry, tests/consumer-fixture/SEED_PINS.json:
      S1  every manifest on disk is in the registry, and every registry entry is on disk;
      S2  each manifest's content (line endings normalised) has the registered sha256;
      S3  the named seed pins are present -- the vulnerable versions the expected signals depend on.
    Changing a seed is a deliberate act: edit the manifest AND the registry in the same pull
    request (`python3 tests/check_fixture_seed_pins.py --update` rewrites the hashes; S3's seeds are
    edited by hand), where CODEOWNERS reviews it. A Dependabot bump changes the manifest only, so it
    fails S2 and S3 in Normalizer drift, a required check.

EXIT  0 held   1 a manifest or seed changed (named)   2 could not be checked
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get('KIT_PROOF_ROOT') or os.path.dirname(HERE)
FIXTURE = 'tests/consumer-fixture'
REGISTRY = FIXTURE + '/SEED_PINS.json'
MANIFEST = re.compile(r'(?i)(^|/)(requirements[^/]*\.txt|composer\.(json|lock)|package(-lock)?\.json|'
                      r'yarn\.lock|pnpm-lock\.yaml|pom\.xml|build\.gradle(\.kts)?|go\.(mod|sum)|[^/]+\.csproj|'
                      r'packages\.(config|lock\.json)|gemfile(\.lock)?|cargo\.(toml|lock)|pipfile(\.lock)?|'
                      r'pyproject\.toml|dockerfile)$')


def manifests(root):
    try:
        out = subprocess.run(['git', '-C', root, 'ls-files', '-z', '--', FIXTURE], capture_output=True,
                             check=True).stdout.decode('utf-8', 'replace')
        names = [n for n in out.split('\0') if n]
    except Exception:                                 # noqa: BLE001 - an export without git
        names = []
        for dp, _dn, fns in os.walk(os.path.join(root, FIXTURE)):
            for fn in fns:
                names.append(os.path.relpath(os.path.join(dp, fn), root).replace(os.sep, '/'))
    return sorted(n for n in names if MANIFEST.search(n))


def digest(root, rel):
    data = io.open(os.path.join(root, rel), 'rb').read().replace(b'\r\n', b'\n')
    return hashlib.sha256(data).hexdigest()


def check(root):
    """-> list of failures."""
    reg_path = os.path.join(root, REGISTRY)
    if not os.path.isfile(reg_path):
        return ['S1 %s is missing: nothing holds the fixture seeds' % REGISTRY]
    reg = json.load(io.open(reg_path, encoding='utf-8'))
    held = reg.get('manifests') or {}
    fails = []
    found = manifests(root)
    for rel in found:
        if rel not in held:
            fails.append('S1 %s is a fixture manifest the registry does not hold' % rel)
        elif digest(root, rel) != held[rel]:
            fails.append('S2 %s changed (sha256 %s, registered %s): a fixture pin moved without the '
                         'registry -- a seed may be gone' % (rel, digest(root, rel)[:12], held[rel][:12]))
    for rel in held:
        if rel not in found:
            fails.append('S1 %s is registered but not on disk' % rel)
    for seed in reg.get('seeds') or []:
        p = os.path.join(root, seed['path'])
        text = io.open(p, encoding='utf-8', errors='replace').read() if os.path.isfile(p) else ''
        if not re.search(seed['pattern'], text):
            fails.append('S3 the seed %s is gone from %s (%s) -- the expected signal %s has nothing to detect'
                         % (seed['pin'], seed['path'], seed['pattern'], seed.get('signal', '?')))
    return fails


def update(root):
    reg_path = os.path.join(root, REGISTRY)
    reg = json.load(io.open(reg_path, encoding='utf-8')) if os.path.isfile(reg_path) else {}
    reg['manifests'] = dict((rel, digest(root, rel)) for rel in manifests(root))
    io.open(reg_path, 'w', encoding='utf-8', newline='\n').write(json.dumps(reg, indent=1, sort_keys=True) + '\n')
    print('rewrote %s: %d manifest(s)' % (REGISTRY, len(reg['manifests'])))


def main(argv):
    if '--update' in argv:
        update(ROOT)
        return 0
    fails = check(ROOT)
    n = len(manifests(ROOT))
    if fails:
        for f in fails:
            print('FAIL ' + f)
        print('::error title=Fixture seed changed::%d check(s): a deliberately vulnerable fixture pin changed '
              'without its registry (%s). Revert the bump; a deliberate change edits both.' % (len(fails), REGISTRY))
        return 1
    if n == 0:
        print('UNKNOWN: no fixture manifest found under %s.' % FIXTURE)
        return 2
    print('PASS: %d fixture manifest(s) hold their registered content and every named seed is present.' % n)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
