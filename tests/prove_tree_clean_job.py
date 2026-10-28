#!/usr/bin/env python3
"""The tree-clean sweep runs in its own self-test job, on the same pinned tools as Normalizer drift.

WHY THIS EXISTS (public run 40687057324, 2026-10-28)

    `Normalizer drift` exceeded its 30-minute bound: the step running
    tests/prove_tests_leave_tree_clean.py -- every test, in a throwaway clone -- had grown to 1036 s
    (879 s on the run before it), and the job's own comment said what to do when thirty is not
    enough: split the job, do not raise it again. The sweep is now its own job, `tree-clean`.

    A split can quietly lose coverage. The sweep reports exit 2 (UNKNOWN) for a test whose tool the
    host lacks, so a job that installs fewer tools than the drift job passes with more UNKNOWNs and
    checks less than before. And two jobs with two copies of one pin list drift apart the first time
    somebody bumps one. So the tools are installed by ONE composite, .github/actions/selftest-tools,
    which both jobs call and nothing else inlines; its pins are verified by tests/check_pinned_installs.py
    like every other in-scope install.

WHAT MUST HOLD (static, over .github/workflows/self-test.yml and the composite)
    J1  a job `tree-clean` runs tests/prove_tests_leave_tree_clean.py, and `normalizer-drift` does
        not: the sweep runs once, in the job built for it
    J2  both jobs call `./.github/actions/selftest-tools` before any step that runs a proof
    J3  neither job installs, inline, a tool the composite carries (comment lines ignored); the
        composite's Semgrep is the version the flagship's sast-semgrep image is (tests/_semgrep_pin)
    J4  the composite is in tests/check_pinned_installs.py SCOPE, so every install in it is a pinned
        version with verified bytes, or that check fails
    J5  each job is bounded: tree-clean carries timeout-minutes between 40 and 60 (twice the measured
        1036 s plus installs, still a bound), normalizer-drift at most 30
    J6  tree-clean checks out full history (fetch-depth: 0): the sweep runs check_context_current.py,
        which resolves the reconciled commit; a depth-1 checkout refused on the private repo
    J7  tree-clean carries no `if:` and `required` needs it (tests/prove_selftest_required.py S2
        holds the whole list; this names the one job this split added)
    J8  no step of normalizer-drift after the setup-python toolchain probe runs a proof: the probe
        switches the active python to one without the pinned tools (public run 40778089130: the
        KDEC-033 step, appended after the probes, died on `import yaml`)
    M*  mutations, each caught: the composite step dropped from tree-clean; an inline semgrep pin in
        normalizer-drift; the sweep put back into normalizer-drift; fetch-depth dropped; tree-clean
        dropped from required's needs; tree-clean's timeout removed; a proof appended after the
        setup-python probe

EXIT  0 all hold   1 a violation   2 could not be checked
"""
import copy
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

WF = os.path.join(ROOT, '.github', 'workflows', 'self-test.yml')
COMPOSITE = '.github/actions/selftest-tools'
ACTION = os.path.join(ROOT, COMPOSITE, 'action.yml')
SWEEP = 'tests/prove_tests_leave_tree_clean.py'
DRIFT, CLEAN, REQUIRED = 'normalizer-drift', 'tree-clean', 'required'

# What the composite carries. A job that mentions one of these in a non-comment `run:` line is
# installing it a second time, from a second list.
TOOL_MARKS = [
    ('semgrep', re.compile(r'pip3? install[^\n]*semgrep')),
    ('bandit', re.compile(r'pip3? install[^\n]*bandit')),
    ('detect-secrets', re.compile(r'pip3? install[^\n]*detect-secrets')),
    ('trivy', re.compile(r'aquasecurity/trivy/[^\n]*install\.sh')),
    ('osv-scanner', re.compile(r'google/osv-scanner/releases')),
    ('gosec', re.compile(r'securego/gosec/releases')),
    ('syft', re.compile(r'anchore/syft/releases')),
    ('gitleaks', re.compile(r'gitleaks/gitleaks/releases')),
    ('cppcheck/flawfinder', re.compile(r'apt-get[^\n]*install[^\n]*\b(?:cppcheck|flawfinder)\b')),
]


def _code(text):
    """`run:` text with comment lines removed: a comment that names a tool does not install it."""
    return '\n'.join(l for l in str(text).split('\n') if not l.strip().startswith('#'))


def _run_steps(job):
    return [s for s in (job.get('steps') or []) if isinstance(s, dict) and s.get('run')]


def _uses_index(job):
    """-> index of the first step calling the composite, or None."""
    for i, s in enumerate(job.get('steps') or []):
        if isinstance(s, dict) and str(s.get('uses', '')).rstrip('/') == './' + COMPOSITE:
            return i
    return None


PROOF_RX = re.compile(r'python3?\s+(?:tests|scripts)/')


def _first_proof_index(job):
    for i, s in enumerate(job.get('steps') or []):
        if isinstance(s, dict) and s.get('run') and PROOF_RX.search(_code(s['run'])):
            return i
    return None


def _setup_python_probe_index(job):
    """-> index of the toolchain probe that calls ./.github/actions/setup-python, or None."""
    for i, s in enumerate(job.get('steps') or []):
        if isinstance(s, dict) and str(s.get('uses', '')).rstrip('/') == './.github/actions/setup-python':
            return i
    return None


def check(doc, sem_version):
    bad = []
    jobs = doc.get('jobs') or {}
    drift, clean, req = jobs.get(DRIFT), jobs.get(CLEAN), jobs.get(REQUIRED)
    if not drift or not clean:
        return ['J1 self-test lacks the %s job (or %s): the sweep has no job of its own' % (CLEAN, DRIFT)]
    # J1
    runs_sweep = lambda j: any(SWEEP in _code(s['run']) for s in _run_steps(j))  # noqa: E731
    if not runs_sweep(clean):
        bad.append('J1 %s does not run %s' % (CLEAN, SWEEP))
    if runs_sweep(drift):
        bad.append('J1 %s still runs %s: the sweep would run twice, and the drift job grows back' % (DRIFT, SWEEP))
    # J2
    for jid, job in ((DRIFT, drift), (CLEAN, clean)):
        ui, pi = _uses_index(job), _first_proof_index(job)
        if ui is None:
            bad.append('J2 %s does not call %s: its tools come from somewhere else, or nowhere' % (jid, COMPOSITE))
        elif pi is not None and pi < ui:
            bad.append('J2 %s runs a proof (step %d) before the composite installs the tools (step %d)' % (jid, pi, ui))
    # J3
    for jid, job in ((DRIFT, drift), (CLEAN, clean)):
        for s in _run_steps(job):
            code = _code(s['run'])
            for tool, rx in TOOL_MARKS:
                if rx.search(code):
                    bad.append('J3 %s installs %s inline (step %r): a second pin list' % (jid, tool, s.get('name')))
    if os.path.isfile(ACTION):
        atext = _code(io.open(ACTION, encoding='utf-8').read())
        pins = set(re.findall(r'semgrep==(\d+\.\d+\.\d+)', atext))
        if sem_version and pins != {sem_version}:
            bad.append('J3 the composite pins semgrep %s; the flagship sast-semgrep image is %s'
                       % (sorted(pins) or 'nowhere', sem_version))
        missing = [t for t, rx in TOOL_MARKS if not rx.search(atext)]
        if missing:
            bad.append('J3 the composite carries no install for %s' % ', '.join(missing))
    else:
        bad.append('J3 %s/action.yml does not exist' % COMPOSITE)
    # J4
    try:
        import check_pinned_installs as cpi
        in_scope = any((e if isinstance(e, str) else e[0]) == COMPOSITE + '/action.yml' for e in cpi.SCOPE)
        if not in_scope:
            bad.append('J4 %s/action.yml is not in check_pinned_installs.SCOPE: its pins are checked by nothing' % COMPOSITE)
    except ImportError as e:
        bad.append('J4 cannot import tests/check_pinned_installs.py: %s' % e)
    # J5
    t = clean.get('timeout-minutes')
    if not isinstance(t, int) or not 40 <= t <= 60:
        bad.append('J5 %s timeout-minutes is %r; want 40..60 (twice the measured sweep plus installs, still a bound)' % (CLEAN, t))
    td = drift.get('timeout-minutes')
    if not isinstance(td, int) or td > 30:
        bad.append('J5 %s timeout-minutes is %r; the sweep left, it must not grow past 30' % (DRIFT, td))
    # J6
    co = next((s for s in (clean.get('steps') or []) if isinstance(s, dict) and str(s.get('uses', '')).startswith('actions/checkout@')), None)
    if not co or (co.get('with') or {}).get('fetch-depth') != 0:
        bad.append('J6 %s must check out with fetch-depth: 0 (the sweep runs check_context_current.py)' % CLEAN)
    # J7
    if 'if' in clean:
        bad.append('J7 %s carries an if: (%r); it must always run' % (CLEAN, clean['if']))
    needs = (req or {}).get('needs') or []
    needs = [needs] if isinstance(needs, str) else list(needs)
    if CLEAN not in needs:
        bad.append('J7 %s is not among %s\'s needs: its failure would not reach the required check' % (CLEAN, REQUIRED))
    # J8
    pi = _setup_python_probe_index(drift)
    if pi is not None:
        for i, s in enumerate(drift.get('steps') or []):
            if i > pi and isinstance(s, dict) and s.get('run') and PROOF_RX.search(_code(s['run'])):
                bad.append('J8 %s step %r runs a proof after the setup-python toolchain probe (step %d): '
                           'the probe switches the active python to one without the pinned tools'
                           % (DRIFT, s.get('name'), pi))
    return bad


def mutations(doc, sem_version):
    blind = []

    def caught(m):
        return bool(check(m, sem_version))
    m = copy.deepcopy(doc)
    m['jobs'][CLEAN]['steps'] = [s for s in m['jobs'][CLEAN]['steps'] if str(s.get('uses', '')) != './' + COMPOSITE]
    if not caught(m):
        blind.append('composite step dropped from %s' % CLEAN)
    m = copy.deepcopy(doc)
    m['jobs'][DRIFT]['steps'].append({'name': 'x', 'run': 'python3 -m pip install --quiet semgrep==%s\n' % (sem_version or '1.0.0')})
    if not caught(m):
        blind.append('inline semgrep pin in %s' % DRIFT)
    m = copy.deepcopy(doc)
    m['jobs'][DRIFT]['steps'].append({'name': 'x', 'run': 'python3 %s\n' % SWEEP})
    if not caught(m):
        blind.append('sweep put back into %s' % DRIFT)
    m = copy.deepcopy(doc)
    for s in m['jobs'][CLEAN]['steps']:
        if str(s.get('uses', '')).startswith('actions/checkout@'):
            s.pop('with', None)
    if not caught(m):
        blind.append('fetch-depth dropped from %s' % CLEAN)
    m = copy.deepcopy(doc)
    m['jobs'][REQUIRED]['needs'] = [n for n in m['jobs'][REQUIRED]['needs'] if n != CLEAN]
    if not caught(m):
        blind.append('%s dropped from required needs' % CLEAN)
    m = copy.deepcopy(doc)
    m['jobs'][CLEAN].pop('timeout-minutes', None)
    if not caught(m):
        blind.append('timeout removed from %s' % CLEAN)
    m = copy.deepcopy(doc)
    m['jobs'][DRIFT]['steps'].append({'name': 'x', 'run': 'python3 tests/prove_tree_clean_job.py\n'})
    if _setup_python_probe_index(m['jobs'][DRIFT]) is not None and not caught(m):
        blind.append('proof appended after the setup-python probe in %s' % DRIFT)
    return blind


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    try:
        import _semgrep_pin
        _img, sem_version, problem = _semgrep_pin.flagship()
        if problem:
            print('UNKNOWN: the flagship Semgrep pin cannot be read: %s' % problem)
            return 2
    except Exception as e:  # noqa: BLE001
        print('UNKNOWN: tests/_semgrep_pin.py: %s' % e)
        return 2
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    bad = check(doc, sem_version)
    if not any(b.startswith('J1 self-test lacks') for b in bad):
        bad += ['M mutation went undetected: %s' % b for b in mutations(doc, sem_version)]
    for b in bad:
        print('VIOLATION: ' + b)
    if bad:
        print('FAIL: %d violation(s)' % len(bad))
        return 1
    print('PASS: the tree-clean sweep runs once, in its own bounded job with full history; both jobs '
          'install the one pinned tool list through %s (semgrep %s, in check_pinned_installs scope); '
          'required needs it; no proof runs after the setup-python probe; 7 mutations caught.' % (COMPOSITE, sem_version))
    return 0


if __name__ == '__main__':
    sys.exit(main())
