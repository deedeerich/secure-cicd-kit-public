#!/usr/bin/env python3
"""The local battery: run the checks self-test's required jobs run, here, with an rc per check.

WHY THIS EXISTS

    The pre-push battery (CP-018) lived in a session scratchpad and was lost with it. A battery that
    is a copy of a list drifts from the list the hosted self-test runs, and Release 3 already went red
    hosted on a check no local gate ran (tests/check_yamllint.py). So this battery holds NO list of
    its own: it reads `.github/workflows/self-test.yml`, takes the jobs the `Self-test required`
    check needs, and runs what their steps run.

HOW A STEP BECOMES A CHECK

    - Each top-level line of a `run:` block that invokes `python`/`python3` on a file under tests/,
      scripts/ or tools/ is ONE check, run on its own, with its own rc. (Lines nested inside an
      `if`/`for` are not top level and are not split out.)
    - A step that has no such line but does run Python (an inline heredoc, a negative control written
      `if python3 ...; then exit 1`) runs WHOLE, under bash, as one check named by the step.
    - `pip install` lines are setup, not checks, and are not run (install from CONTRIBUTING.md).
    - A step that reads the runner's expression context (`${{ ... }}` in its script), runs `sudo`,
      or a job that is a reusable-workflow call (`uses:`), is HOSTED-ONLY and listed as such.
    - EXTRAS: checks the pre-push battery runs that self-test runs only inside the tree-clean sweep
      (check_context_current.py), listed in EXTRAS below with the reason.

    rc 0 = PASS. rc 2 = UNKNOWN (the kit's convention: a tool or credential this host lacks).
    Any other rc, or a timeout, = FAIL. The summary names every FAIL and UNKNOWN.

USAGE
    python tools/battery.py               every check, including the tree-clean sweep (slow)
    python tools/battery.py --fast        skip the tree-clean sweep (every test in a clone)
    python tools/battery.py --list        print the plan, run nothing
    python tools/battery.py --only REGEX  run only checks whose name matches
    python tools/battery.py --strict      UNKNOWN fails the battery too (rc 2)
    tools/battery.sh / tools/battery.ps1 are the shell twins; they find bash and python and call this.

EXIT  0 no check failed (UNKNOWN allowed unless --strict)   1 one or more FAILED
      2 --strict and one or more UNKNOWN, or the plan could not be read
"""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SELF_TEST = os.path.join(ROOT, '.github', 'workflows', 'self-test.yml')
VERDICT_JOB = 'required'
SWEEP = 'tests/prove_tests_leave_tree_clean.py'
TIMEOUT = 1800

# Run by the pre-push battery (continuation.md, CP-018) but by self-test only inside the sweep.
EXTRAS = [
    ('python3 tests/check_context_current.py',
     'the context record names a commit on this history (self-test runs it inside the sweep only)'),
]

# Steps whose check has a local twin that reads the step's own configuration (so the two cannot drift)
# and corrects for this host: the twin runs; the step is listed, not run twice.
SUPERSEDED = {
    'yamllint': 'tests/check_yamllint.py extracts this step config and lints LF-normalised copies',
}

# Expression values a step's `env:` may carry, as a local run answers them. Anything else is left
# unset (a token, a repository name): the check then answers as it does without it.
LOCAL_EXPRESSIONS = {
    '${{ github.event_name }}': 'workflow_dispatch',
}

CHECK_LINE = re.compile(r'^(?:[A-Z_][A-Z0-9_]*=\S+\s+)*python3?\s+(?:tests|scripts|tools)/\S+')
SETUP_LINE = re.compile(r'^python3?\s+-m\s+pip\s+install\b')


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        return None, 'PyYAML is not installed (python -m pip install PyYAML)'
    try:
        with open(path, encoding='utf-8') as fh:
            return yaml.safe_load(fh), None
    except (OSError, ValueError) as e:  # yaml.YAMLError is a ValueError subclass's sibling
        return None, 'could not read %s: %s' % (path, e)
    except Exception as e:  # noqa: BLE001 -- any parse failure is "could not plan"
        return None, 'could not parse %s: %s' % (path, e)


def top_level_lines(script):
    """Lines at column 0 of a run block, outside heredoc bodies and shell compound statements."""
    out, heredoc, depth = [], None, 0
    for raw in script.splitlines():
        line = raw.rstrip()
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        m = re.search(r"<<-?\s*'?\"?([A-Za-z_]+)'?\"?", line)
        if m:
            heredoc = m.group(1)
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if line[:1] in (' ', '\t'):
            continue
        word = stripped.split()[0]
        if word in ('if', 'for', 'while', 'until', 'case') and not re.search(
                r'(;|\s)(fi|done|esac)\s*$', stripped):
            depth += 1
            continue
        if word in ('fi', 'done', 'esac') or stripped.startswith(('fi;', 'done;')):
            depth = max(0, depth - 1)
            continue
        if depth == 0:
            out.append(stripped)
    return out


def strip_comment(line):
    """Drop a trailing ` # comment` that is outside quotes."""
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in ('"', "'"):
            q = ch
        elif ch == '#' and i > 0 and line[i - 1] in ' \t':
            return line[:i].rstrip()
    return line


def plan(workflow_path=SELF_TEST, fast=False):
    """Return (checks, hosted_only, error). A check is a dict: name, kind, cmd, job, step."""
    doc, err = load_yaml(workflow_path)
    if err:
        return [], [], err
    jobs = (doc or {}).get('jobs') or {}
    verdict = jobs.get(VERDICT_JOB)
    if not verdict:
        return [], [], 'no `%s` job in %s' % (VERDICT_JOB, workflow_path)
    needs = verdict.get('needs') or []
    if isinstance(needs, str):
        needs = [needs]
    checks, hosted = [], []
    for jname in needs:
        job = jobs.get(jname) or {}
        if 'uses' in job:
            hosted.append((jname, '-', 'a reusable-workflow call (%s): GitHub runs it' % job['uses']))
            continue
        for step in job.get('steps') or []:
            sname = step.get('name') or step.get('uses') or '(unnamed)'
            if 'uses' in step:
                continue  # checkout, setup-python, the tools composite: setup, not checks
            script = str(step.get('run') or '')
            if not script.strip():
                continue
            if sname in SUPERSEDED:
                hosted.append((jname, sname, 'superseded locally: %s' % SUPERSEDED[sname]))
                continue
            senv = {}
            for k, v in (step.get('env') or {}).items():
                v = str(v)
                if '${{' not in v:
                    senv[k] = v
                elif v.strip() in LOCAL_EXPRESSIONS:
                    senv[k] = LOCAL_EXPRESSIONS[v.strip()]
            lines = top_level_lines(script)
            plain = [strip_comment(ln) for ln in lines if CHECK_LINE.match(ln)]
            if plain:
                for ln in plain:
                    if fast and SWEEP in ln:
                        hosted.append((jname, sname, 'skipped by --fast (the sweep runs every test)'))
                        continue
                    checks.append({'name': ln, 'kind': 'line', 'cmd': ln, 'job': jname, 'step': sname,
                                   'env': senv})
                continue
            if '${{' in script:
                hosted.append((jname, sname, 'reads the runner expression context'))
                continue
            if re.search(r'(^|\s)sudo\s', script):
                hosted.append((jname, sname, 'needs sudo on the runner'))
                continue
            if step.get('id') and not re.search(r'(tests|scripts)/', script):
                hosted.append((jname, sname, 'a runner probe whose outputs feed later `uses:` steps'))
                continue
            if re.search(r'\bpython3?\b', script):
                body = '\n'.join(ln for ln in script.splitlines() if not SETUP_LINE.match(ln.strip()))
                checks.append({'name': 'step: %s' % sname, 'kind': 'step', 'cmd': body,
                               'job': jname, 'step': sname, 'env': senv})
            else:
                hosted.append((jname, sname, 'no Python check in this step (runner probe or tooling)'))
    for cmd, why in (EXTRAS if os.path.abspath(workflow_path) == os.path.abspath(SELF_TEST) else []):
        checks.append({'name': cmd, 'kind': 'line', 'cmd': cmd, 'job': '(extra)', 'step': why})
    return checks, hosted, None


def find_bash():
    env = os.environ.get('BATTERY_BASH')
    if env:
        return env
    if os.name == 'nt':
        for c in (r'C:\Program Files\Git\bin\bash.exe', r'C:\Program Files\Git\usr\bin\bash.exe'):
            if os.path.exists(c):
                return c
    return shutil.which('bash') or 'bash'


def run_check(check, root, tmp, timeout, bash):
    env = dict(os.environ)
    env.update({'RUNNER_TEMP': tmp, 'GITHUB_OUTPUT': os.path.join(tmp, 'github_output'),
                'GITHUB_ENV': os.path.join(tmp, 'github_env'),
                'GITHUB_STEP_SUMMARY': os.path.join(tmp, 'step_summary'),
                'PYTHONIOENCODING': 'utf-8'})
    env.update(check.get('env') or {})
    cmd = check['cmd'].replace('$PWD', root).replace('"$RUNNER_TEMP', '"' + tmp).replace('$RUNNER_TEMP', tmp)
    if check['kind'] == 'line' and not re.search(r'[|;&<>`$]', cmd):
        try:
            argv = shlex.split(cmd)
        except ValueError:
            argv = None
        if argv:
            while argv and re.match(r'^[A-Z_][A-Z0-9_]*=', argv[0]):
                k, v = argv.pop(0).split('=', 1)
                if os.path.exists(v):
                    env[k] = v  # a tool path the runner downloaded; locally only if present
            if argv and argv[0] in ('python', 'python3'):
                argv[0] = sys.executable
            proc_args, shell = argv, False
        else:
            proc_args, shell = [bash, '-c', cmd], False
    else:
        script = 'set -uo pipefail\n' + cmd if check['kind'] == 'step' else cmd
        proc_args, shell = [bash, '-c', script], False
    t0 = time.time()
    m = re.search(r'python3?\s+((?:tests|scripts|tools)/\S+?\.py)', cmd) if check['kind'] == 'line' else None
    if m and not os.path.exists(os.path.join(root, m.group(1))):
        # python exits 2 for a file it cannot open -- the UNKNOWN code. A check that is gone is a FAIL.
        return 1, 'the check %s does not exist in this tree' % m.group(1), 0.0
    try:
        p = subprocess.run(proc_args, cwd=root, env=env, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=timeout, shell=shell)
        rc, out = p.returncode, (p.stdout or '') + (p.stderr or '')
    except subprocess.TimeoutExpired:
        rc, out = 'timeout', ''
    except OSError as e:
        rc, out = 2, 'could not start: %s' % e
    return rc, out, time.time() - t0


def tree_status(root):
    try:
        p = subprocess.run(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root,
                           capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        return set(p.stdout.splitlines()) if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def verdict_of(rc):
    if rc == 0:
        return 'PASS'
    if rc == 2:
        return 'UNKNOWN'
    return 'FAIL'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--workflow', default=SELF_TEST)
    ap.add_argument('--root', default=ROOT)
    ap.add_argument('--fast', action='store_true')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--only')
    ap.add_argument('--strict', action='store_true')
    ap.add_argument('--timeout', type=int, default=TIMEOUT)
    ap.add_argument('--json', help='also write the per-check results to this file')
    a = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError):
            pass

    checks, hosted, err = plan(a.workflow, fast=a.fast)
    if err:
        print('UNKNOWN: could not plan the battery: %s' % err)
        return 2
    if a.only:
        rx = re.compile(a.only)
        checks = [c for c in checks if rx.search(c['name'])]
    if a.list:
        for c in checks:
            print('%-20s %s' % (c['job'], c['name'].splitlines()[0][:150]))
        print('\n%d checks; hosted-only:' % len(checks))
        for j, s, why in hosted:
            print('  %-20s %s -- %s' % (j, s, why))
        return 0

    bash = find_bash()
    tmp = tempfile.mkdtemp(prefix='battery-')
    results = []
    try:
        before = tree_status(a.root)
        for i, c in enumerate(checks, 1):
            rc, out, secs = run_check(c, a.root, tmp, a.timeout, bash)
            v = verdict_of(rc)
            after = tree_status(a.root)
            if before is not None and after is not None and after - before:
                # A check that leaves files in the working tree is a FAIL (N51): name them.
                left = sorted(after - before)
                v, rc = 'FAIL', 'dirty'
                out = (out or '') + '\nleft in the working tree: %s' % ', '.join(left[:10])
                before = after
            results.append({'check': c['name'], 'job': c['job'], 'rc': rc, 'verdict': v,
                            'seconds': round(secs, 1), 'tail': out.strip().splitlines()[-15:]})
            print('[%3d/%d] %-7s rc=%-7s %5.1fs  %s' % (i, len(checks), v, rc, secs,
                                                         c['name'].splitlines()[0][:110]), flush=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    fails = [r for r in results if r['verdict'] == 'FAIL']
    unknown = [r for r in results if r['verdict'] == 'UNKNOWN']
    print('\n== battery summary: %d checks, %d PASS, %d FAIL, %d UNKNOWN; %d hosted-only steps not run'
          % (len(results), len(results) - len(fails) - len(unknown), len(fails), len(unknown), len(hosted)))
    for r in fails:
        print('FAIL    rc=%s  %s' % (r['rc'], r['check'].splitlines()[0]))
        for ln in r['tail']:
            print('          %s' % ln)
    for r in unknown:
        print('UNKNOWN rc=2  %s  (%s)' % (r['check'].splitlines()[0], (r['tail'] or ['-'])[-1][:120]))
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as fh:
            json.dump({'results': results, 'hosted_only': hosted}, fh, indent=1)
    if fails:
        return 1
    if unknown and a.strict:
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
