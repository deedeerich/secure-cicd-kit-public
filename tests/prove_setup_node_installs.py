#!/usr/bin/env python3
"""The setup-node composite must run `npm ci` from a lockfile and REPORT what it installed.

WHY THIS EXISTS (validation deferral `toolchain-node-install`)

    The hosted toolchain probe (self-test, Normalizer drift job) runs the composite with
    `install: false`, so `npm ci` had never executed under the kit's eye -- and the FIRST execution
    of the half that did run found a defect no reading had (a cache keyed on a lock file in the
    repository root only). That is the argument for not assuming this half is fine. The deferral
    named what would close it: "a fixture repository where `npm ci` installs from a lockfile and
    the composite reports what it installed". The composite reported nothing: a green step that
    installed everything and one that installed nothing read the same (D7).

WHAT IS RUN
    The composite's install step, extracted from action.yml AS SHIPPED, under the composite shell
    (bash --noprofile --norc -eo pipefail), with the REAL node and npm on PATH, in a throwaway
    workspace holding a fixture package.json and package-lock.json (one dependency-free package,
    pinned by version and integrity). Nothing is shimmed. Network: the npm registry, once per case.

CASES (docs/PROOF_RULE.md)
    allowed           package.json + lockfile pin escape-string-regexp 4.0.0 -> exit 0; that version
                      is on disk under node_modules; install_state=INSTALLED; `installed` names it
    attack            package.json asks for a version the lockfile does not pin -> `npm ci` FAILS for
                      that reason (out of sync); install_state is never INSTALLED; nothing on disk
    missing-evidence  no lockfile at all -> `npm ci` FAILS for that reason; nothing is installed from
                      a floating resolution; install_state is never INSTALLED
    skipped           install=false -> exit 0, install_state=SKIPPED, nothing on disk
    recovery          the attack's workspace with package.json restored -> allowed

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

ACTION = '.github/actions/setup-node/action.yml'
STEP = 'npm ci'
PKG, VER, OTHER = 'escape-string-regexp', '4.0.0', '5.0.0'
PACKAGE_JSON = {'name': 'kit-toolchain-fixture', 'version': '0.0.0', 'private': True,
                'dependencies': {PKG: VER}}
# Generated once by `npm install --package-lock-only` and recorded here, integrity included, so
# the install is from a lockfile and nothing else.
LOCK = {
    'name': 'kit-toolchain-fixture', 'version': '0.0.0', 'lockfileVersion': 3, 'requires': True,
    'packages': {
        '': {'name': 'kit-toolchain-fixture', 'version': '0.0.0', 'dependencies': {PKG: VER}},
        'node_modules/' + PKG: {
            'version': VER,
            'resolved': 'https://registry.npmjs.org/%s/-/%s-%s.tgz' % (PKG, PKG, VER),
            'integrity': 'sha512-TtpcNJ3XAzx3Gq8sWRzJaVajRs0uVxA2YAkdb1jm2YkPz4G6egUFAyA3n5vtEIZefPk5Wa4UXbKuS5fKkJWdgA==',
            'license': 'MIT', 'engines': {'node': '>=10'}},
    },
}
NETWORK = ('ENOTFOUND', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'getaddrinfo')


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def fixture(ws, requested=VER, lock=True):
    pj = dict(PACKAGE_JSON, dependencies={PKG: requested})
    write(os.path.join(ws, 'package.json'), json.dumps(pj, indent=2) + '\n')
    if lock:
        write(os.path.join(ws, 'package-lock.json'), json.dumps(LOCK, indent=2) + '\n')


def on_disk(ws):
    p = os.path.join(ws, 'node_modules', PKG, 'package.json')
    if not os.path.isfile(p):
        return None
    try:
        return json.load(io.open(p, encoding='utf-8')).get('version')
    except ValueError:
        return 'UNPARSEABLE'


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    if not shutil.which('npm') or not shutil.which('node'):
        print('UNKNOWN: node/npm not on PATH; `npm ci` cannot be run.')
        return 2
    step = H.step(ACTION, None, STEP)
    if step is None:
        print('UNKNOWN: %s has no step %r.' % (ACTION, STEP))
        return 2
    if step.get('shell') != 'bash':
        print('FAIL: the install step is not `shell: bash`; a composite step must name its shell.')
        return 1

    bad = []
    tmp = tempfile.mkdtemp(prefix='setup-node-probe-')
    try:
        def run(name, ws, install='true'):
            r = H.run(bash, step, {'inputs.install': install}, ws, composite=True)
            if any(code in r['log'] for code in NETWORK):
                print('UNKNOWN: npm could not reach the registry; nothing was installed.\n%s'
                      % r['log'][-400:])
                return None
            return r

        def allowed(name, ws):
            r = run(name, ws)
            if r is None:
                return 2
            got = on_disk(ws)
            print('  %-18s exit=%d %s=%s install_state=%s installed=%r'
                  % (name, r['rc'], PKG, got, r['outputs'].get('install_state'),
                     r['outputs'].get('installed')))
            if r['rc'] != 0 or got != VER:
                bad.append('%s: `npm ci` did not install %s@%s (exit %d, on disk %r)\n%s'
                           % (name, PKG, VER, r['rc'], got, r['log'][-500:]))
            if r['outputs'].get('install_state') != 'INSTALLED':
                bad.append('%s: install_state=%r. The composite installed and REPORTED NOTHING: a '
                           'green step that installed nothing would look exactly the same'
                           % (name, r['outputs'].get('install_state')))
            if '%s@%s' % (PKG, VER) not in (r['outputs'].get('installed') or '').split():
                bad.append('%s: `installed` is %r and does not name %s@%s -- the composite does '
                           'not report what it installed' % (name, r['outputs'].get('installed'),
                                                             PKG, VER))
            if '%s@%s' % (PKG, VER) not in r['summary']:
                bad.append('%s: the step summary does not name %s@%s' % (name, PKG, VER))
            return 0

        # ---- allowed
        ws = os.path.join(tmp, 'allowed')
        fixture(ws)
        if allowed('allowed', ws) == 2:
            return 2

        # ---- attack: package.json and the lockfile disagree -> refused, for that reason
        ws_a = os.path.join(tmp, 'attack')
        fixture(ws_a, requested=OTHER)
        r = run('attack', ws_a)
        if r is None:
            return 2
        print('  %-18s exit=%d install_state=%s on_disk=%s'
              % ('attack', r['rc'], r['outputs'].get('install_state'), on_disk(ws_a)))
        if r['rc'] == 0:
            bad.append('attack: `npm ci` "succeeded" with package.json asking for %s@%s and the '
                       'lockfile pinning %s' % (PKG, OTHER, VER))
        elif 'in sync' not in r['log']:
            bad.append('attack: the step failed, but not because the lockfile is out of sync\n%s'
                       % r['log'][-400:])
        if r['outputs'].get('install_state') == 'INSTALLED':
            bad.append('attack: install_state=INSTALLED after a refused install')
        if on_disk(ws_a) is not None:
            bad.append('attack: %s is on disk after a refused install' % PKG)

        # ---- missing-evidence: no lockfile -> refused; nothing installed from a floating resolution
        ws_m = os.path.join(tmp, 'missing')
        fixture(ws_m, lock=False)
        r = run('missing-evidence', ws_m)
        if r is None:
            return 2
        print('  %-18s exit=%d install_state=%s on_disk=%s'
              % ('missing-evidence', r['rc'], r['outputs'].get('install_state'), on_disk(ws_m)))
        if r['rc'] == 0:
            bad.append('missing-evidence: `npm ci` "succeeded" with no lockfile -- whatever it '
                       'installed was resolved today, not pinned')
        elif 'package-lock.json' not in r['log']:
            bad.append('missing-evidence: the step failed, but not for want of a lockfile\n%s'
                       % r['log'][-400:])
        if r['outputs'].get('install_state') == 'INSTALLED':
            bad.append('missing-evidence: install_state=INSTALLED with no lockfile')
        if on_disk(ws_m) is not None:
            bad.append('missing-evidence: %s is on disk after a refused install' % PKG)

        # ---- skipped: install=false runs nothing, and says so
        ws_s = os.path.join(tmp, 'skipped')
        fixture(ws_s)
        r = run('skipped', ws_s, install='false')
        if r is None:
            return 2
        print('  %-18s exit=%d install_state=%s on_disk=%s'
              % ('skipped', r['rc'], r['outputs'].get('install_state'), on_disk(ws_s)))
        if r['rc'] != 0:
            bad.append('skipped: install=false failed the step (exit %d)\n%s' % (r['rc'], r['log'][-300:]))
        if r['outputs'].get('install_state') != 'SKIPPED':
            bad.append('skipped: install_state=%r, want SKIPPED -- a skipped install must be '
                       'reported as skipped, not left to read as installed'
                       % r['outputs'].get('install_state'))
        if on_disk(ws_s) is not None:
            bad.append('skipped: %s was installed with install=false' % PKG)

        # ---- recovery: the attack's workspace, package.json restored
        fixture(ws_a)
        if allowed('recovery', ws_a) == 2:
            return 2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the setup-node composite installs a pinned fixture from its lockfile with real npm, '
          'reports install_state and what it installed as found on disk, refuses an out-of-sync '
          'lockfile and a missing one for those reasons, and reports install=false as SKIPPED.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
