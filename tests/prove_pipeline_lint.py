#!/usr/bin/env python3
"""The pipeline linters run where their files are, detect the seeded findings, and are skipped -- free
-- where their files are not (lane L-SCAN-A, KDEC-025).

WHY THIS EXISTS

    GitHub Actions workflows, shell scripts, PowerShell and Dockerfiles were COVERAGE_GAP rows: present
    in a consumer's repository and read by nothing in this kit. The owner's ruling was that every gap
    is closed, cost-beneficially. So each class got a pinned linter INSIDE a job that already runs --
    actionlint + zizmor, shellcheck and PSScriptAnalyzer in deps-scan (always on), hadolint in
    iac-scan (on whenever a Dockerfile is, since a Dockerfile is IaC) -- gated by discovery, so a
    repository without the files pays nothing.

    A gated linter is three claims, and each is asserted separately, by running the steps AS SHIPPED
    (expanded from the composites) with the real tools the install steps fetch and verify:

      P1  SKIPPED WHEN ABSENT   every lint step's `if:` evaluates false when discovery said false,
                                and true when it said true -- read from the shipped expressions.
      P2  PINNED                every tool is fetched by exact version and checked against a sha256
                                written in the step; nothing floats (no `latest`, no unversioned URL).
      P3  RUNS AND DETECTS      over tests/corpora/pipeline_lint_corpus.py each SARIF exists, parses,
                                names its tool, carries ONLY repository-relative paths that exist,
                                and holds every seeded rule (the error-level ones at error level).
      P4  REFUSES WHAT IT CANNOT READ   a zsh script and a PowerShell script that #Requires a newer
                                PowerShell are NAMED as VERSION_GAP and not passed as clean.
      P5  REPORTS, THE GATE ENFORCES   error-level findings hand findings_state=FINDINGS to the gate
                                and the job does not fail on them; advisory_mode softens the hand-off.
      P6  CANNOT SCAN -> FAILS  a linter whose binary is absent is COLLECTION_FAILED and the enforce
                                step fails the job: could-not-look is never a clean result.
      P7  ONE ROW EACH          the report's state builder, as shipped, writes a row per linter; a row
                                whose linter NAMED a file it could not read is PARTIAL, never PASS.

EXIT  0 all hold   1 a claim failed   2 could not be checked here (P3-P6 need Linux with bash, python3,
      jq, curl, pwsh and network to the release hosts) -- UNKNOWN, never PASS. P1, P2 and P7 run
      anywhere with a bash (P7 needs jq).
"""
import io
import json
import os
import platform
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'corpora'))
import _scan_step_harness as h  # noqa: E402
import pipeline_lint_corpus as corpus  # noqa: E402

DEPS = 'deps-scan'
IAC = 'iac-scan'
INSTALL = 'Pipeline lint — install pinned tools'
WF = 'Workflow lint (actionlint + zizmor)'
SH = 'Shell lint (shellcheck)'
PS = 'PowerShell lint (PSScriptAnalyzer)'
ENF = 'Pipeline lint — enforce'
PUB = 'Pipeline lint — is there anything to publish?'
HD = 'Dockerfile lint (hadolint)'
HENF = 'hadolint — enforce'
HPUB = 'hadolint — is there anything to publish?'
# step -> the discovery output(s) that must gate it
GATES = {INSTALL: ('workflows', 'shell', 'powershell'), WF: ('workflows',), SH: ('shell',),
         PS: ('powershell',), HD: ('dockerfile',)}
SARIF = {'actionlint': 'actionlint.sarif', 'zizmor': 'zizmor.sarif', 'shellcheck': 'shellcheck.sarif',
         'psscriptanalyzer': 'psscriptanalyzer.sarif', 'hadolint': 'hadolint.sarif'}


def evaluate_if(expr, values):
    """A GitHub `if:` over the subset these steps use: always(), ==, !=, &&, ||, !, (), 'str'."""
    if expr is None or expr == '':
        return True
    e = str(expr).strip()
    if e.startswith('${{') and e.endswith('}}'):
        e = e[3:-2]
    e = e.replace('always()', 'True').replace('success()', 'True')

    def ref(m):
        return repr(str(values.get(m.group(0), '')))
    e = re.sub(r'\b(?:needs|inputs|steps|matrix|github)\.[A-Za-z0-9_.-]+', ref, e)
    e = e.replace('&&', ' and ').replace('||', ' or ')
    e = re.sub(r'!(?!=)', ' not ', e)
    return bool(eval(e, {'__builtins__': {}}, {'True': True, 'False': False}))  # noqa: S307


def steps_of(job):
    return {s.get('name'): s for s in (h.job(job).get('steps') or [])}


def p1_gating(dep, iac, bash):
    """Each lint step reads discovery's answer as data (env APPLIES) and, given 'false', does nothing:
    exit 0, nothing fetched, no SARIF -- run as shipped, on any host with a bash."""
    bad = []
    present = [n for n in GATES if (dep.get(n) or iac.get(n))]
    for name in GATES:
        if name not in present:
            bad.append('P1: no step %r -- that linter never runs' % name)
    if bad:
        return bad
    for name, classes in GATES.items():
        st = dep.get(name) or iac.get(name)
        on = str((st.get('env') or {}).get('APPLIES', ''))
        for c in classes:
            if '${{ needs.plan.outputs.%s }}' % c not in on:
                bad.append('P1: %r is not gated on discovery output %r (env APPLIES=%r)' % (name, c, on))
    if not bash or bad:
        return bad
    sb = h.Sandbox('pipeline-lint-skip-').with_bundle()
    try:
        ws = sb.workspace('none', {'app/main.py': 'x\n'})
        r = Runner(sb, bash, ws, values_for(set()))
        for name in (INSTALL, WF, SH, PS, ENF, HD, HENF):
            st = dep.get(name) or iac.get(name)
            rc, log, out = r.step(st)
            if rc != 0:
                bad.append('P1: %r failed (exit %s) with nothing to scan\n%s' % (name, rc, log[-400:]))
            if out.get('collection') not in (None, 'NOT_APPLICABLE') or out.get('findings_state'):
                bad.append('P1: %r claimed a result with nothing to scan: %s' % (name, out))
        left = [f for f in os.listdir(ws) if f.endswith('.sarif')]
        fetched = [d for d in ('kit-lint', 'kit-hadolint') if os.path.isdir(os.path.join(sb.root, 'meta', d))]
        if left:
            bad.append('P1: a SARIF was written with nothing to scan: %s' % left)
        if fetched:
            bad.append('P1: tools were fetched with nothing to scan (%s) -- not free' % fetched)
        print('  P1 skip: %d lint step(s) ran as shipped with discovery false: exit 0, nothing fetched, '
              'no SARIF' % 7)
    finally:
        sb.close()
    return bad


PIN = re.compile(r'(https://[^\s"\']+)["\']?\s+([0-9a-f]{64})\b')


def p2_pins(dep, iac):
    bad = []
    for name, want in ((INSTALL, ('actionlint', 'zizmor', 'shellcheck', 'PSScriptAnalyzer')),
                       (HD, ('hadolint',))):
        st = dep.get(name) or iac.get(name) or {}
        text = str(st.get('run') or '')
        pins = PIN.findall(text)
        for tool in want:
            hit = [(u, d) for u, d in pins if tool.lower() in u.lower()]
            if not hit:
                bad.append('P2: %r fetches %s with no URL + sha256 pair in the step' % (name, tool))
            for u, _ in hit:
                if 'latest' in u or not re.search(r'\d+\.\d+\.\d+', u):
                    bad.append('P2: %s URL is not an exact release: %s' % (tool, u))
        if 'sha256sum -c' not in text:
            bad.append('P2: %r never checks a digest (sha256sum -c)' % name)
    return bad


def p7_report_rows(bash):
    """The report's state builder, as shipped: one row per linter, and a row whose linter NAMED a
    file it could not read is PARTIAL, never PASS. Runs on any host with bash and jq."""
    bad = []
    step = h.steps_by_name('security-gate').get('Build per-scanner state')
    if not step:
        return ['P7: the report job has no "Build per-scanner state" step']
    if not h.have(bash, 'jq'):
        return ['UNKNOWN-P7: jq is not on PATH']
    sarif = json.dumps({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'x'}}, 'results': []}]})
    sb = h.Sandbox('pipeline-lint-rows-')
    try:
        ws = sb.workspace('rows', {'_sarif/actionlint.sarif': sarif, '_sarif/zizmor.sarif': sarif,
                                   '_sarif/shellcheck.sarif': sarif, '_sarif/hadolint.sarif': sarif})
        vals = {'needs.plan.outputs.state': 'COMPLETE', 'needs.deps-scan.result': 'success',
                'needs.iac-scan.result': 'success'}
        for c in ('workflows', 'shell', 'powershell', 'dockerfile', 'iac'):
            vals['needs.plan.outputs.%s' % c] = 'true'
        vals['needs.deps-scan.outputs.lint_version_gaps'] = 'scripts/fancy.sh ops/future.ps1'
        vals['needs.iac-scan.outputs.lint_version_gaps'] = ''
        rc, log, _out, _unk = sb.run(bash, step, vals, ws)
        st = {}
        for n in ('actionlint', 'zizmor', 'shellcheck', 'psscriptanalyzer', 'hadolint'):
            p = os.path.join(ws, '_states', 'state-%s.json' % n)
            if not os.path.isfile(p):
                bad.append('P7: no report row for %s (exit %s)\n%s' % (n, rc, log[-600:]))
                continue
            st[n] = json.load(io.open(p, encoding='utf-8'))
        want = {'actionlint': 'PASS', 'zizmor': 'PASS', 'hadolint': 'PASS',
                'shellcheck': 'PARTIAL',          # it named scripts/fancy.sh and did not read it
                'psscriptanalyzer': 'UNDETERMINED'}  # no report arrived: never PASS, never PARTIAL-from-PASS
        for n, g in want.items():
            if n in st and st[n].get('gate') != g:
                bad.append('P7: %s row gate=%r, want %r (row=%s)' % (n, st[n].get('gate'), g, st[n]))
        if 'shellcheck' in st and 'scripts/fancy.sh' not in st['shellcheck'].get('scope', ''):
            bad.append('P7: the shellcheck row does not name the file it could not read')
        if 'shellcheck' in st and 'ops/future.ps1' in st['shellcheck'].get('scope', ''):
            bad.append('P7: a PowerShell file was attributed to the shellcheck row')
        print('  P7 report rows: %s' % ', '.join('%s=%s' % (n, s.get('gate')) for n, s in sorted(st.items())))
    finally:
        sb.close()
    return bad


def linux_ready(bash):
    if platform.system() != 'Linux':
        return 'not Linux (%s); run in CI or a Linux container' % platform.system()
    for tool in ('python3', 'jq', 'curl', 'pwsh', 'tar', 'unzip', 'xz'):
        if not h.have(bash, tool):
            return '%s is not on PATH' % tool
    p = subprocess.run([bash, '-c', 'curl -sSfI https://github.com >/dev/null 2>&1'])
    if p.returncode != 0:
        return 'no network to github.com'
    return ''


class Runner(object):
    """Runs shipped steps in order, carrying $GITHUB_ENV and step outputs as the runner does."""

    def __init__(self, sb, bash, ws, values):
        self.sb, self.bash, self.ws, self.values = sb, bash, ws, values
        self.genv = os.path.join(sb.root, 'github_env_%s' % os.path.basename(ws))
        io.open(self.genv, 'w').close()
        self.env = {}

    def step(self, st, extra_env=None):
        if not evaluate_if(st.get('if'), self.values):
            return None, '', {}
        env = dict(self.env, GITHUB_ENV=self.genv, **(extra_env or {}))
        rc, log, out, unk = self.sb.run(self.bash, st, self.values, self.ws, env=env)
        for line in io.open(self.genv, encoding='utf-8', errors='replace'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                self.env[k] = v
        for k, v in out.items():
            self.values['steps.%s.outputs.%s' % (st.get('id'), k)] = v
        if unk:
            log += '\nUNMODELLED: %s' % unk
        return rc, log, out


def sarif_rows(path):
    doc = json.load(io.open(path, encoding='utf-8'))
    rows = []
    for run_ in doc.get('runs') or []:
        lv = {r.get('id'): (r.get('defaultConfiguration') or {}).get('level')
              for r in (run_.get('tool', {}).get('driver', {}).get('rules') or [])}
        name = run_.get('tool', {}).get('driver', {}).get('name', '')
        for r in run_.get('results') or []:
            uris = [((loc.get('physicalLocation') or {}).get('artifactLocation') or {}).get('uri', '')
                    for loc in r.get('locations') or []]
            rows.append({'tool': name, 'rule': r.get('ruleId'),
                         'level': r.get('level') or lv.get(r.get('ruleId')) or 'warning',
                         'uris': uris})
    return rows


def values_for(classes, advisory='false'):
    v = {'inputs.paths': '.', 'inputs.advisory_mode': advisory, 'inputs.fail_on_severity': 'CRITICAL,HIGH',
         'github.run_attempt': '1', 'github.workspace': '.'}
    for c in ('workflows', 'shell', 'powershell', 'dockerfile'):
        v['needs.plan.outputs.%s' % c] = 'true' if c in classes else 'false'
    return v


def run_lint(sb, bash, ws, dep, iac, values, only=None, extra_env=None):
    r = Runner(sb, bash, ws, values)
    logs = {}
    for name in (INSTALL, WF, SH, PS, ENF, PUB, HD, HENF, HPUB):
        if only and name not in only:
            continue
        st = dep.get(name) or iac.get(name)
        rc, log, out = r.step(st, extra_env if name != INSTALL else None)
        logs[name] = (rc, log, out)
    return r, logs


def p3_to_p5(sb, bash, dep, iac):
    bad = []
    ws = sb.workspace('seeded')
    corpus.write(ws)
    r, logs = run_lint(sb, bash, ws, dep, iac, values_for({'workflows', 'shell', 'powershell', 'dockerfile'}))
    for name, (rc, log, out) in logs.items():
        print('  %-48s exit=%s %s' % (name, rc, ' '.join('%s=%s' % kv for kv in sorted(out.items()))[:110]))
        if rc not in (0, None):
            bad.append('P5: %r exited %s on a scan that could run -- the job fails only when it cannot '
                       'scan\n%s' % (name, rc, log[-1500:]))
    for tool, f in SARIF.items():
        p = os.path.join(ws, f)
        if not os.path.isfile(p):
            bad.append('P3: %s was not written -- %s did not run or its report was lost' % (f, tool))
            continue
        try:
            rows = sarif_rows(p)
        except ValueError as exc:
            bad.append('P3: %s does not parse (%s)' % (f, exc))
            continue
        rules = {x['rule'] for x in rows}
        errors = {x['rule'] for x in rows if x['level'] == 'error'}
        want, want_err = corpus.EXPECTED[tool]
        print('  %-22s %2d result(s): %s' % (f, len(rows), ', '.join(sorted(rules))[:150]))
        if rows and not all(x['tool'].lower().startswith(tool[:5].lower()) for x in rows):
            bad.append('P3: %s names another tool: %s' % (f, sorted({x['tool'] for x in rows})))
        if want - rules:
            bad.append('P3: %s missed seeded rule(s) %s' % (tool, sorted(want - rules)))
        if want_err - errors:
            bad.append('P3: %s did not report %s at error level' % (tool, sorted(want_err - errors)))
        for x in rows:
            for u in x['uris']:
                if not u or u.startswith(('/', './', 'file:')) or re.match(r'^[A-Za-z]:', u) \
                        or not os.path.isfile(os.path.join(ws, *u.split('/'))):
                    bad.append('P3: %s carries a path that is not repository-relative: %r' % (f, u))
                    break
        for refused in corpus.REFUSED.get(tool, []):
            if any(refused in x['uris'] for x in rows):
                bad.append('P4: %s reported %s as if it had read it' % (tool, refused))
    refused = ' '.join(v for k, v in r.values.items() if k.endswith('outputs.version_gaps'))
    for tool, files in corpus.REFUSED.items():
        for f in files:
            if f not in refused:
                bad.append('P4: %s is not NAMED as a VERSION_GAP (version_gaps=%r)' % (f, refused))
    if r.values.get('steps.lint_enforce.outputs.findings_state') != 'FINDINGS':
        bad.append('P5: deps-scan lint did not hand findings_state=FINDINGS to the gate')
    if r.values.get('steps.hadolint_enforce.outputs.findings_state') != 'FINDINGS':
        bad.append('P5: hadolint did not hand findings_state=FINDINGS to the gate')

    # advisory_mode: the findings stay, the hand-off is softened, the job still succeeds.
    ws2 = sb.workspace('advisory')
    corpus.write(ws2, only={'shell'})
    r2, logs2 = run_lint(sb, bash, ws2, dep, iac, values_for({'shell'}, advisory='true'))
    if r2.values.get('steps.lint_enforce.outputs.findings_state'):
        bad.append('P5: advisory_mode did not soften the hand-off')
    if (logs2.get(ENF) or (1,))[0] != 0:
        bad.append('P5: the enforce step failed under advisory_mode with a complete scan')
    if not os.path.isfile(os.path.join(ws2, 'shellcheck.sarif')):
        bad.append('P5: advisory_mode lost the findings themselves')
    return bad


def p6_cannot_scan(sb, bash, dep, iac):
    bad = []
    ws = sb.workspace('nobinary')
    corpus.write(ws, only={'workflows'})
    empty = os.path.join(sb.root, 'emptybin')
    os.makedirs(empty, exist_ok=True)
    values = values_for({'workflows'})
    r = Runner(sb, bash, ws, values)
    r.step(dep[INSTALL])
    r.env['kit_lint_bin'] = empty.replace(os.sep, '/')   # the binaries vanished after install
    rc, log, out = r.step(dep[WF])
    if out.get('collection') != 'COLLECTION_FAILED':
        bad.append('P6: a missing actionlint was not COLLECTION_FAILED (outputs=%s)' % out)
    rc, log, out = r.step(dep[ENF])
    if rc == 0:
        bad.append('P6: the enforce step passed over a linter that could not run')
    if os.path.isfile(os.path.join(ws, 'actionlint.sarif')):
        bad.append('P6: a SARIF was written by a linter that never ran -- it would read as clean')
    return bad


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    dep, iac = steps_of(DEPS), steps_of(IAC)
    bash, why = h.pbf.usable_bash()
    bad = p1_gating(dep, iac, bash) + p2_pins(dep, iac)
    if bash:
        p7 = p7_report_rows(bash)
        if any(b.startswith('UNKNOWN-P7') for b in p7):
            print('  P7 not run here: jq is not on PATH')
        else:
            bad += p7
    print('P1 gating + P2 pins + P7 report rows: %s' % ('FAIL' if bad else 'PASS'))
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    not_ready = linux_ready(bash) if bash else 'no bash (%s)' % why
    if not_ready:
        print('UNKNOWN: P3-P6 not run -- %s. P1, P2 and P7 hold.' % not_ready)
        return 2
    sb = h.Sandbox('pipeline-lint-').with_bundle()
    try:
        bad += p3_to_p5(sb, bash, dep, iac)
        bad += p6_cannot_scan(sb, bash, dep, iac)
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: each linter is skipped where its files are absent, pinned by version and sha256, '
          'detects every seeded rule with repository-relative paths, names what it cannot read, hands '
          'error-level findings to the gate, and fails only when it cannot scan.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
