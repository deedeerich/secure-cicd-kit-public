#!/usr/bin/env python3
"""Run the sast-java job's own Semgrep and enforce steps against seeded and clean Java.

WHY THIS EXISTS (validation deferral `sast-java`, expired 2026-09-30)

    The deferral said "no Java fixture exists" and named what would close it: "seeded vulnerable
    Java produces the expected finding class". This job once ran NO scanner at all and reported
    success on every run, so the claim worth proving is not "semgrep works" -- the tool-level probe
    already says that -- but that THIS JOB'S STEPS, as shipped, find a seeded flaw, count it, and
    hand the enforce step a number it acts on.

    Each step is extracted from the workflow as shipped, its `${{ }}` inputs substituted, and run
    under bash with the real semgrep against a throwaway workspace. The scan step's outputs are read
    back from its GITHUB_OUTPUT and fed to the enforce step, exactly as the runner would.

SCENARIOS
    seeded_enforce   SQL built by concatenation, soft_fail_sast off -> >=1 SQL finding, enforce FAILS
    seeded_soft      the same, soft_fail_sast on (a weakening) -> finding counted, enforce passes
    clean            no flaw                                        -> 0 findings, enforce passes
    no_java          no .java files                                  -> scan step skips, exit 0

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, no semgrep, no registry access) -- UNKNOWN, never PASS
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402  (shared extraction and bash probe)

JOB = 'sast-java'
SCAN, ENFORCE = 'Semgrep (Java)', 'Semgrep (Java) — enforce'
EXPECTED_CLASS = 'sql'      # the seeded flaw is SQL built by string concatenation (CWE-89)

SEEDED = '''import java.sql.*;

public class Seeded {
    public ResultSet byId(Connection c, String id) throws SQLException {
        Statement s = c.createStatement();
        return s.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
'''
CLEAN = '''public class Clean {
    public int add(int a, int b) {
        return a + b;
    }
}
'''


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def steps():
    import yaml
    doc = _expand(yaml.safe_load(io.open(pbf.WF, encoding='utf-8')))
    found = {}
    for s in (doc['jobs'][JOB].get('steps') or []):
        if s.get('name') in (SCAN, ENFORCE):
            found[s['name']] = s.get('run')
    return found.get(SCAN), found.get(ENFORCE)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def outputs(path):
    out = {}
    for line in io.open(path, encoding='utf-8', errors='replace'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            out[k] = v
    return out


def run(bash, script, ws, extra_path, env_extra=None):
    out = os.path.join(ws, '.gh_output_%d' % len(os.listdir(ws)))
    io.open(out, 'w').close()
    summ = os.path.join(ws, '.gh_summary')
    io.open(summ, 'a').close()
    f = os.path.join(ws, '.step.sh')
    # The count site calls /tmp/sarif_validity.py from the kit bundle (L02): supply it.
    io.open(f, 'w', encoding='utf-8', newline='\n').write(pbf.with_kit_bundle(script))
    # Hosted runners are UTF-8. A Windows host's default code page makes semgrep crash while
    # WRITING its SARIF -- a host fact, not a kit one -- so the probe gives the step the runner's
    # encoding rather than reporting the host's.
    env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ, GITHUB_WORKSPACE=ws,
               PYTHONUTF8='1', PYTHONIOENCODING='utf-8',
               PATH=extra_path + os.pathsep + os.environ.get('PATH', ''), **(env_extra or {}))
    p = subprocess.run([bash, f], capture_output=True, text=True, encoding='utf-8', errors='replace',
                       env=env, cwd=ws)
    return p.returncode, (p.stdout or '') + (p.stderr or ''), outputs(out)


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    if not shutil.which('semgrep') or not shutil.which('jq'):
        print('UNKNOWN: semgrep and jq are required to RUN the step.')
        return 2
    scan, enforce = steps()
    if not scan or not enforce:
        print('UNKNOWN: step %r or %r missing from job %r.' % (SCAN, ENFORCE, JOB))
        return 2

    tmp = tempfile.mkdtemp(prefix='sast-java-probe-')
    bad = []
    try:
        shim = os.path.join(tmp, 'shim')
        # `python3` on a Windows host is the Store stub; the runner's python3 is the interpreter.
        write(os.path.join(shim, 'python3'),
              '#!/usr/bin/env bash\nexec "%s" "$@"\n' % sys.executable.replace('\\', '/'))
        os.chmod(os.path.join(shim, 'python3'), 0o755)

        scenarios = [
            ('seeded_enforce', SEEDED, 'false', 'fail', True),
            ('seeded_soft', SEEDED, 'true', 'pass', True),
            ('clean', CLEAN, 'false', 'pass', False),
            ('no_java', None, 'false', 'skip', False),
        ]
        for name, source, soft, expect, must_find in scenarios:
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            if source:
                write(os.path.join(ws, 'src', 'main', 'java', 'App.java'), source)
            else:
                write(os.path.join(ws, 'README.md'), 'no java here\n')
            ctx = {'inputs.paths': '.', 'inputs.soft_fail_sast': soft,
                   'inputs.advisory_mode': 'false'}
            body, _ = pbf.substitute(scan, ctx)
            rc, log, out = run(bash, body, ws, shim, pbf.env_for_run(scan, ctx))
            if expect == 'skip':
                print('  %-15s scan exit=%d (skip)' % (name, rc))
                if rc != 0 or 'count' in out:
                    bad.append('%s: a tree with no Java must skip cleanly, got exit %d' % (name, rc))
                continue
            if rc != 0 or 'count' not in out:
                if 'Failed to download' in log or 'ConnectionError' in log:
                    print('UNKNOWN: semgrep could not fetch its registry rules.')
                    return 2
                bad.append('%s: the scan step did not produce a count (exit %d)\n%s'
                           % (name, rc, log[-600:]))
                continue
            n = int(out['count'])
            sarif = os.path.join(ws, 'java-semgrep.sarif')
            rules = []
            if os.path.isfile(sarif):
                doc = json.load(io.open(sarif, encoding='utf-8'))
                rules = sorted({r.get('ruleId', '') for run_ in doc.get('runs', [])
                                for r in run_.get('results', [])})
            ectx = dict(ctx)
            ectx['steps.java_semgrep.outputs.count'] = out.get('count', '')
            ectx['steps.java_semgrep.outputs.collection'] = out.get('collection', '')
            ebody, _ = pbf.substitute(enforce, ectx)
            erc, elog, _ = run(bash, ebody, ws, shim, pbf.env_for_run(enforce, ectx))
            print('  %-15s findings=%d enforce exit=%d %s' % (name, n, erc, ','.join(rules)))
            if must_find:
                if n < 1:
                    bad.append('%s: the seeded flaw produced no finding' % name)
                elif not any(EXPECTED_CLASS in r.lower() for r in rules):
                    bad.append('%s: findings %s are not the seeded class (%s)'
                               % (name, rules, EXPECTED_CLASS))
            elif n != 0:
                bad.append('%s: the clean fixture produced %d finding(s): %s' % (name, n, rules))
            if expect == 'fail' and erc == 0:
                bad.append('%s: enforce passed a seeded finding with soft_fail_sast off' % name)
            if expect == 'pass' and erc != 0:
                bad.append('%s: enforce failed (exit %d) where it must pass\n%s'
                           % (name, erc, elog[-400:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the shipped sast-java steps find the seeded SQL-injection class, count it, and '
          'enforce on it when soft_fail_sast is off; clean Java yields zero; no Java skips.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
