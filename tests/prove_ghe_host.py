#!/usr/bin/env python3
"""Simulate a GitHub Enterprise Cloud data-residency host (`<tenant>.ghe.com`) and prove the kit
works there: every token stays on the run's host, every gh call names it, no link assumes
github.com, no action fetches a github.com repository through the run's server, and no step crashes
on an API error body (KDEC-027).

WHY THIS EXISTS

    The owner's work copy runs on a GHE.com tenant and its consumer path failed hard:
      * `.github/actions/resolve` "Consume the platform-probe values" ran `gh api` against
        github.com with the tenant's token ("Bad credentials") and wrote the multi-line JSON error
        body into $GITHUB_OUTPUT: `Unable to process file command 'output' successfully`. The step
        whose contract is "an error is UNAVAILABLE" crashed the job instead.
      * every Trivy step used aquasecurity/trivy-action -> aquasecurity/setup-trivy, whose inner
        actions/checkout of `aquasecurity/trivy` resolves `repository:` against github.server_url
        (the tenant), where that repository does not exist. Every Trivy scan failed to install.
      * the pin checker sent the tenant token to api.github.com (tests/prove_github_token_stays_on_its_host.py).

WHAT IT PROVES, with GITHUB_SERVER_URL=https://example.ghe.com and
GITHUB_API_URL=https://api.example.ghe.com

    H1  every workflow/composite step that runs `gh` sets GH_HOST (env or in its script) before
        the first gh call -- with or without a token in sight;
    H2  no shipped workflow, composite, template, overlay or script sends a token to a hard-coded
        api.github.com (a `GITHUB_API_URL` fallback default is allowed: unset means github.com);
    H3  no link is built as github.com/<this repository> -- run, PR and ticket links come from
        github.server_url / GITHUB_SERVER_URL;
    H4  no step uses aquasecurity/trivy-action or aquasecurity/setup-trivy, nor any other action
        known to check out a github.com repository through the run's server;
    H5  every $GITHUB_OUTPUT/$GITHUB_ENV write of external text is sanitised
        (tests/check_output_writes.py, run here);
    H6  DYNAMIC: the resolve platform step, run as shipped under bash with a stub `gh` that answers
        like the tenant did (exit 1, a multi-line "Bad credentials" JSON body), exits 0, writes a
        $GITHUB_OUTPUT the runner can parse, degrades to dependabot_state=UNAVAILABLE, and the
        stub saw GH_HOST=example.ghe.com.

    H7  every GHAS-dependent step (codeql-action init/analyze/upload-sarif, dependency review) is
        continue-on-error, so a tenant without the feature degrades visibly instead of failing.

    KIT_PROOF_RESOLVE=<file> points H6 at another revision of the resolve composite, so the proof
    can be shown FAILING on the revision that carried the defect.

EXIT  0 all hold   1 any does not   2 H6 could not be run (no usable bash or jq) -- UNKNOWN
"""
import glob
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

SERVER = 'https://example.ghe.com'
API = 'https://api.example.ghe.com'
SHIPPED_YAML = ['.github/workflows/*.yml', '.github/actions/**/action.yml', 'templates/**/*.yml',
                'overlays/**/*.yml']
SHIPPED_CODE = SHIPPED_YAML + ['scripts/**/*.py', 'scripts/**/*.sh', 'overlays/**/*.py',
                               'overlays/**/*.sh']
GH_CALL = re.compile(r'(^|[\s;(|&$"\'=])gh\s+(api|run|attestation|pr|issue|release|workflow|repo|'
                     r'label|secret|variable|cache|search|auth|browse|gist|project|ruleset)\b', re.M)
# Actions that fetch a github.com repository with actions/checkout or the run's server URL.
GITHUB_COM_FETCHERS = ('aquasecurity/trivy-action', 'aquasecurity/setup-trivy')
LINK = re.compile(r'https?://github\.com/(\$\{\{\s*github\.repository|\$\{?GITHUB_REPOSITORY|'
                  r"['\"]\s*\+|%s|\{repo|\$\{?REPO\b|\$\{\{\s*github\.event\.repository)")
FAILS = []


def check(cond, msg, detail=()):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    for d in detail:
        print('       ' + d)
    if not cond:
        FAILS.append(msg)


def files(patterns):
    seen = set()
    for pat in patterns:
        for f in sorted(glob.glob(os.path.join(ROOT, pat), recursive=True)):
            if os.path.isfile(f) and f not in seen and '/tests/' not in f.replace('\\', '/'):
                seen.add(f)
                yield f


def rel(f):
    return os.path.relpath(f, ROOT).replace('\\', '/')


def steps_of(path):
    import yaml
    try:
        doc = yaml.safe_load(io.open(path, encoding='utf-8').read()) or {}
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(doc, dict):
        return []
    wenv = doc.get('env') or {}
    out = []
    for job in (doc.get('jobs') or {}).values():
        if isinstance(job, dict):
            jenv = dict(wenv, **(job.get('env') or {}))
            out += [(jenv, s) for s in job.get('steps') or [] if isinstance(s, dict)]
    if isinstance(doc.get('runs'), dict):
        out += [(wenv, s) for s in doc['runs'].get('steps') or [] if isinstance(s, dict)]
    return out


def h1():
    bare = []
    for f in files(SHIPPED_YAML):
        for env, st in steps_of(f):
            run = st.get('run')
            if not isinstance(run, str):
                continue
            # Comment lines are prose: `# gh api defaults to github.com` runs nothing.
            run = '\n'.join(ln for ln in run.split('\n') if not ln.lstrip().startswith('#'))
            m = GH_CALL.search(run)
            if not m:
                continue
            if 'GH_HOST' in dict(env, **(st.get('env') or {})):
                continue
            h = re.search(r'\bGH_HOST=', run)
            if h and h.start() < m.start():
                continue
            bare.append('%s: step "%s"' % (rel(f), st.get('name') or st.get('id') or '?'))
    check(not bare, 'H1 every step running gh sets GH_HOST first (%d without)' % len(bare), bare)


def h2():
    bad = []
    for f in files(SHIPPED_CODE):
        for i, line in enumerate(io.open(f, encoding='utf-8', errors='replace').read().split('\n')):
            if 'api.github.com' not in line or line.lstrip().startswith('#'):
                continue
            # A fallback for an unset GITHUB_API_URL is github.com by definition, not a hard-code.
            if re.search(r'GITHUB_API_URL[\'"]?\s*,\s*[\'"]https://api\.github\.com|'
                         r'GITHUB_API_URL:-https://api\.github\.com|PIN_ACTIONS_API:-https://api\.github\.com|'
                         r"api_url or 'https://api\.github\.com'", line):
                continue
            bad.append('%s:%d: %s' % (rel(f), i + 1, line.strip()[:120]))
    check(not bad, 'H2 no hard-coded api.github.com in shipped code (%d)' % len(bad), bad)


def h3():
    bad = []
    for f in files(SHIPPED_CODE):
        for i, line in enumerate(io.open(f, encoding='utf-8', errors='replace').read().split('\n')):
            if LINK.search(line):
                bad.append('%s:%d: %s' % (rel(f), i + 1, line.strip()[:120]))
    check(not bad, 'H3 no link built as github.com/<this repository> (%d)' % len(bad), bad)


def h4():
    bad = []
    for f in files(SHIPPED_YAML):
        for _env, st in steps_of(f):
            u = str(st.get('uses') or '')
            if any(u.lower().startswith(x) for x in GITHUB_COM_FETCHERS):
                bad.append('%s: step "%s" uses %s' % (rel(f), st.get('name') or '?', u.split('@')[0]))
    check(not bad, 'H4 no action that checks out a github.com repository via the run server (%d)'
          % len(bad), bad)


def h5():
    import check_output_writes as cow
    found = []
    for f in files(SHIPPED_YAML):
        found += ['%s: step "%s": %s' % (rel(f), s, why) for s, _n, _l, why in cow.scan_file(f)]
    check(not found and not cow.self_test(),
          'H5 every $GITHUB_OUTPUT/$GITHUB_ENV write of external text is sanitised (%d)' % len(found),
          found)


GHAS_STEP = re.compile(r'github/codeql-action/|actions/dependency-review-action')


def h7():
    """A tenant without GHAS refuses code scanning and CodeQL. Such a step must degrade (and the
    kit states PUBLICATION=DEGRADED / UNAVAILABLE beside it), never fail the consumer path."""
    bad = []
    for f in files(SHIPPED_YAML):
        for _env, st in steps_of(f):
            if GHAS_STEP.search(str(st.get('uses') or '')) and \
                    str(st.get('continue-on-error')).lower() != 'true':
                bad.append('%s: step "%s" (%s)' % (rel(f), st.get('name') or '?',
                                                   str(st.get('uses')).split('@')[0]))
    check(not bad, 'H7 every GHAS-dependent step degrades (continue-on-error) instead of failing (%d)'
          % len(bad), bad)


STUB_GH = r'''#!/usr/bin/env bash
printf 'GH_HOST=%s\n' "${GH_HOST:-}" >> "$STUB_LOG"
printf '{\n  "message": "Bad credentials",\n  "documentation_url": "https://docs.github.com/rest",\n  "status": "401"\n}\n'
echo 'gh: Bad credentials (HTTP 401)' >&2
exit 1
'''


def h6():
    import yaml
    import prove_bootstrap_failure as pbf
    bash, why = pbf.usable_bash()
    if not bash:
        print('  ???? H6 UNKNOWN: no usable bash (%s)' % why)
        return 2
    path = os.environ.get('KIT_PROOF_RESOLVE') or os.path.join(ROOT, '.github', 'actions', 'resolve',
                                                                'action.yml')
    doc = yaml.safe_load(io.open(path, encoding='utf-8').read())
    st = [s for s in doc['runs']['steps'] if s.get('name') == 'Consume the platform-probe values']
    if len(st) != 1:
        check(False, 'H6 the resolve platform step exists exactly once')
        return 1
    st = st[0]
    work = tempfile.mkdtemp(prefix='ghe-host-')
    try:
        binp = os.path.join(work, 'bin')
        os.makedirs(binp)
        io.open(os.path.join(binp, 'gh'), 'w', newline='\n').write(STUB_GH)
        os.chmod(os.path.join(binp, 'gh'), 0o755)
        script = os.path.join(work, 'step.sh')
        io.open(script, 'w', encoding='utf-8', newline='\n').write(st['run'])
        out, summ, log = (os.path.join(work, n) for n in ('output', 'summary', 'stub.log'))
        for p in (out, summ, log):
            io.open(p, 'w').close()

        def posix(p):
            return p.replace('\\', '/')
        env = dict(os.environ)
        env.update({'GITHUB_SERVER_URL': SERVER, 'GITHUB_API_URL': API,
                    'GITHUB_REPOSITORY': 'tenant-org/app', 'GITHUB_OUTPUT': posix(out),
                    'GITHUB_STEP_SUMMARY': posix(summ), 'STUB_LOG': posix(log),
                    'GH_TOKEN': 'ghs_tenant_token_placeholder',
                    'p_ghas_available': 'UNKNOWN', 'p_code_scanning': 'UNKNOWN',
                    'p_secret_scanning': 'UNKNOWN', 'p_push_protection': 'UNKNOWN',
                    'p_dependabot_alerts': 'ENABLED', 'p_dependabot_updates': 'UNKNOWN',
                    'p_dependabot_config': 'PRESENT', 'p_visibility': 'private',
                    'p_platform_source': 'probe'})
        env.pop('GH_HOST', None)
        prefix = 'export PATH="%s:$PATH"; ' % posix(binp)
        if os.name == 'nt':
            prefix = 'export PATH="$(cygpath -u "%s"):$PATH"; ' % posix(binp)
        p = subprocess.run([bash, '-c', prefix + 'source "%s"' % posix(script)], env=env, cwd=work,
                           capture_output=True, text=True, encoding='utf-8', errors='replace',
                           timeout=120)
        lines = io.open(out, encoding='utf-8').read().split('\n')
        # The runner's file-command grammar: `name=value`, or `name<<DELIM` ... `DELIM`.
        badl, delim = [], None
        for ln in lines:
            if delim is not None:
                if ln == delim:
                    delim = None
                continue
            if not ln:
                continue
            m = re.match(r'^[A-Za-z_][A-Za-z0-9_-]*<<(.+)$', ln)
            if m:
                delim = m.group(1)
                continue
            if not re.match(r'^[A-Za-z_][A-Za-z0-9_-]*=', ln):
                badl.append(ln)
        kv = dict(ln.split('=', 1) for ln in lines if re.match(r'^[A-Za-z_][A-Za-z0-9_-]*=', ln))
        seen = io.open(log, encoding='utf-8').read().split()
        check(p.returncode == 0, 'H6 the platform step exits 0 on a tenant API error (rc=%d)'
              % p.returncode, [p.stderr.strip()[-300:]] if p.returncode else [])
        check(not badl, 'H6 $GITHUB_OUTPUT parses as file commands (%d unparseable line(s))'
              % len(badl), ['%r' % b for b in badl[:4]])
        check(kv.get('dependabot_state') == 'UNAVAILABLE',
              'H6 dependabot_state=UNAVAILABLE, never PASS (%r)' % kv.get('dependabot_state'))
        check(seen and all(s == 'GH_HOST=example.ghe.com' for s in seen),
              'H6 gh was called with GH_HOST=example.ghe.com (%s)' % (', '.join(seen) or 'not called'))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    os.environ['GITHUB_SERVER_URL'] = SERVER
    os.environ['GITHUB_API_URL'] = API
    print('simulated host: GITHUB_SERVER_URL=%s GITHUB_API_URL=%s' % (SERVER, API))
    h1()
    h2()
    h3()
    h4()
    h5()
    h7()
    unknown = h6()
    print()
    if FAILS:
        print('FAIL: %d check(s): the kit does not yet work on a GHE.com host.' % len(FAILS))
        return 1
    if unknown:
        print('UNKNOWN: the static checks hold; H6 could not be run.')
        return 2
    print('PASS: on a simulated GHE.com host every token stays on the run host, every gh call names '
          'it, no link or action assumes github.com, and an API error degrades instead of crashing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
