#!/usr/bin/env python3
"""The setup-python composite must INSTALL a requirements file and REPORT what it installed.

WHY THIS EXISTS (validation deferral `toolchain-python-install`)

    The hosted toolchain probe (self-test, Normalizer drift job) runs the composite with a
    requirements path that does not exist, deliberately, to exercise the SKIP branch -- the branch
    a consumer without a requirements file takes. So `pip install -r` had never executed under the
    kit's eye, and the deferral named what would close it: "a fixture requirements file is
    installed and the composite reports what it installed". The second half was not true of the
    composite at all: it installed and said nothing, so a green step was indistinguishable from
    one that installed nothing, which is the same silence as a scanner that runs and reports
    nothing (D7).

WHAT IS RUN
    The composite's `Install requirements` step, extracted from action.yml AS SHIPPED, under the
    composite shell (bash --noprofile --norc -eo pipefail), with a REAL python and pip in a
    throwaway virtual environment per case, against a fixture requirements file. Nothing is
    shimmed. Network: PyPI, for pip's own upgrade and one small pinned distribution.

CASES (docs/PROOF_RULE.md)
    allowed           requirements pins six==1.17.0 -> exit 0; `import six` in that venv reports
                      1.17.0; install_state=INSTALLED; `installed` names six==1.17.0
    attack            requirements names a distribution that does not exist -> the step FAILS, and
                      install_state is never INSTALLED
    missing-evidence  the requirements path does not exist -> exit 0, install_state=SKIPPED,
                      `installed` empty, and the summary says nothing was installed
    recovery          the attack's venv with the requirements corrected -> allowed

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile
import venv

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

ACTION = '.github/actions/setup-python/action.yml'
STEP = 'Install requirements'
PKG, VER = 'six', '1.17.0'
GOOD = '%s==%s\n' % (PKG, VER)
BAD = 'kit-probe-no-such-distribution-7f3a1==9.9.9\n'


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def make_venv(tmp, name):
    """A fresh venv -> (bin dir, python executable)."""
    vdir = os.path.join(tmp, 'venv-' + name)
    venv.EnvBuilder(with_pip=True).create(vdir)
    vbin = os.path.join(vdir, 'Scripts' if os.name == 'nt' else 'bin')
    py = os.path.join(vbin, 'python.exe' if os.name == 'nt' else 'python')
    return vbin, py


def installed_version(py):
    p = subprocess.run([py, '-c', 'import %s; print(%s.__version__)' % (PKG, PKG)],
                       capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else None


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
    step = H.step(ACTION, None, STEP)
    if step is None:
        print('UNKNOWN: %s has no step %r.' % (ACTION, STEP))
        return 2
    if step.get('shell') != 'bash':
        print('FAIL: the install step is not `shell: bash`; a composite step must name its shell.')
        return 1

    bad = []
    tmp = tempfile.mkdtemp(prefix='setup-python-probe-')
    try:
        def run(name, vbin, req_path):
            ws = os.path.join(tmp, 'ws-' + name)
            os.makedirs(ws, exist_ok=True)
            r = H.run(bash, step, {'inputs.requirements-file': req_path}, ws, vbin, composite=True)
            # A network failure is not an observation of the step, in either direction.
            if 'Could not fetch URL' in r['log'] or 'Temporary failure in name resolution' in r['log']:
                print('UNKNOWN: pip could not reach PyPI; nothing was installed.\n%s' % r['log'][-400:])
                return None, ws
            return r, ws

        def allowed(name, vbin, py):
            req = os.path.join(tmp, name + '-requirements.txt')
            write(req, GOOD)
            r, ws = run(name, vbin, req)
            if r is None:
                return 2
            got = installed_version(py)
            print('  %-18s exit=%d %s=%s install_state=%s installed=%r'
                  % (name, r['rc'], PKG, got, r['outputs'].get('install_state'),
                     r['outputs'].get('installed')))
            if r['rc'] != 0 or got != VER:
                bad.append('%s: the step did not install %s (exit %d, version %r)\n%s'
                           % (name, GOOD.strip(), r['rc'], got, r['log'][-500:]))
            if r['outputs'].get('install_state') != 'INSTALLED':
                bad.append('%s: install_state=%r. The composite installed and REPORTED NOTHING: a '
                           'green step that installed nothing would look exactly the same'
                           % (name, r['outputs'].get('install_state')))
            if '%s==%s' % (PKG, VER) not in (r['outputs'].get('installed') or '').split():
                bad.append('%s: `installed` is %r and does not name %s==%s -- the composite does '
                           'not report what it installed' % (name, r['outputs'].get('installed'),
                                                             PKG, VER))
            if '%s==%s' % (PKG, VER) not in r['summary']:
                bad.append('%s: the step summary does not name %s==%s' % (name, PKG, VER))
            return 0

        # ---- allowed
        vbin, py = make_venv(tmp, 'allowed')
        if allowed('allowed', vbin, py) == 2:
            return 2

        # ---- attack: a requirement nothing can resolve must FAIL the step, loudly
        vbin, py = make_venv(tmp, 'attack')
        req = os.path.join(tmp, 'attack-requirements.txt')
        write(req, BAD)
        r, ws = run('attack', vbin, req)
        if r is None:
            return 2
        print('  %-18s exit=%d install_state=%s' % ('attack', r['rc'],
                                                      r['outputs'].get('install_state')))
        if r['rc'] == 0:
            bad.append('attack: a requirements file naming a distribution that does not exist '
                       'installed "successfully" (exit 0)')
        elif 'No matching distribution found for ' + BAD.split('==')[0] not in r['log']:
            # Refused, but not for the stated reason: a coincidence, and coincidences get
            # refactored away (docs/PROOF_RULE.md).
            bad.append('attack: the step failed, but not because the distribution does not '
                       'exist\n%s' % r['log'][-400:])
        if r['outputs'].get('install_state') == 'INSTALLED':
            bad.append('attack: install_state=INSTALLED after a failed install')
        if installed_version(py) is not None:
            bad.append('attack: %s is importable in a venv that was only ever handed a bad '
                       'requirements file' % PKG)

        # ---- missing-evidence: no requirements file -> SKIPPED, and said so
        vbin_m, py_m = make_venv(tmp, 'missing')
        r, ws = run('missing-evidence', vbin_m, os.path.join(tmp, 'no-such-requirements.txt'))
        if r is None:
            return 2
        print('  %-18s exit=%d install_state=%s installed=%r'
              % ('missing-evidence', r['rc'], r['outputs'].get('install_state'),
                 r['outputs'].get('installed')))
        if r['rc'] != 0:
            bad.append('missing-evidence: an absent requirements file failed the step (exit %d); '
                       'the SKIP branch is the one a consumer without one takes\n%s'
                       % (r['rc'], r['log'][-400:]))
        if r['outputs'].get('install_state') != 'SKIPPED':
            bad.append('missing-evidence: install_state=%r, want SKIPPED -- a skipped install '
                       'must be reported as skipped, not left to read as installed'
                       % r['outputs'].get('install_state'))
        if (r['outputs'].get('installed') or '').strip():
            bad.append('missing-evidence: `installed` is %r after a skip' % r['outputs'].get('installed'))
        if 'nothing installed' not in r['summary'].lower():
            bad.append('missing-evidence: the step summary does not say nothing was installed')
        if installed_version(py_m) is not None:
            bad.append('missing-evidence: %s is importable after a skip' % PKG)

        # ---- recovery: the attack's venv, requirements corrected
        if allowed('recovery', vbin, py) == 2:
            return 2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the setup-python composite installs a pinned fixture requirement with real pip, '
          'reports install_state and what it installed, fails loudly on a requirement nothing can '
          'resolve, and reports an absent requirements file as SKIPPED with nothing installed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
