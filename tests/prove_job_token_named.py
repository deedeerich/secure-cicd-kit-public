#!/usr/bin/env python3
"""A rejected job token is NAMED once, early, with an owner role -- and nothing downstream crashes on it.

WHY THIS EXISTS (2026-11-02)

    On an organisation's private repository every API call the kit makes with the job's own
    `github.token` was answered 401 "Bad credentials": the resolve platform step, the consumer
    path's dispatch and collect steps, the pin checker. Each said it differently -- a runner
    refusing the output file (`Invalid format '  "message": "Bad credentials",'`), a raw
    `HTTP 401` with `Try authenticating with: gh auth login`, a "rate-limited" UNKNOWN although
    GITHUB_TOKEN was set. Nobody could act on any of them: the cause is an organisation setting
    (IP allow list, workflow permissions, a proxy, a host mismatch) and no line said so.

    The kit cannot fix an organisation's token. It must never crash on one, and it must say which
    of five things happened, who owns it and what to check.

THE CAUSES (assurance-taxonomy.yaml, api_token_preflight)

    TOKEN_ACCEPTED, JOB_TOKEN_REJECTED (401), ORG_IP_ALLOW_LIST_BLOCKS_RUNNER (403, IP allow list),
    ORG_SSO_BLOCKS_TOKEN (403, SAML/SSO), RATE_LIMITED, API_UNREACHABLE (no HTTP answer),
    TOKEN_PREFLIGHT_UNCLASSIFIED (any other refusal).

WHAT IT PROVES

    T1  the canonical shell classifier (scripts/api_token_cause.sh, kit_api_cause) names every
        case in the table below.
    T2  the Python classifier the pin checkers use (tests/_github_refs.py, api_cause) gives the
        same word for every case.
    T3  every inlined copy of the shell library (the discover and resolve composites, the consumer
        path's preflight steps) is byte-identical to scripts/api_token_cause.sh.
    T4  the discover composite's platform step, run as shipped with a stub gh answering 401 to
        every call: exits 0, $GITHUB_OUTPUT parses, token_preflight=JOB_TOKEN_REJECTED, the summary
        names the cause with the owner role and the checklist, an ::error annotation carries the
        cause as its title, and no raw API body reaches the output file or the log. With a 403 IP
        allow list body: ORG_IP_ALLOW_LIST_BLOCKS_RUNNER. With a good answer: TOKEN_ACCEPTED and the
        repository's visibility still read from it.
    T5  the resolve composite's "Consume the platform-probe values" step, as shipped, stub gh 401:
        exits 0, $GITHUB_OUTPUT parses, dependabot_state=UNAVAILABLE and dependabot_basis names
        JOB_TOKEN_REJECTED, with no raw body line.
    T6  consumer-path-test.yml: every job with a `gh` step runs the preflight step first; with a stub
        gh answering 401 the step fails with ::error title=JOB_TOKEN_REJECTED and the summary names
        the owner role; with a good answer it passes; on a simulated GHE.com host (a stub that
        accepts only GH_HOST=example.ghe.com) it passes, so the token went to the tenant.
    T7  the pin checkers (check_pinned_artifacts.py, check_action_pins.py --online), with git unable
        to reach github.com and the REST API answering 401 / a rate limit / nothing: still exit 2
        (UNKNOWN, contract unchanged), and the UNKNOWN message names JOB_TOKEN_REJECTED (HTTP 401),
        RATE_LIMITED, or "no token api.github.com issued" -- never "rate-limited" for a 401.
    T8  Trivy is never set up by an action that checks out a repository with the run's token:
        no aquasecurity/trivy-action, no setup-trivy, no checkout of aquasecurity/trivy; every
        Trivy install verifies a sha256 and sends no Authorization header.

    T9  in an EXPORTED COPY that was NOT SENT consumer-path-test.yml (it carries
        .neutral-export-watermark.json, its exporter's EXCLUDE_PATHS lists the file, and the
        watermark records neither shipping it nor including it), T3's consumer-path part and T6
        are SOURCE-ONLY by name, as prove_export_scope.py E9 is. A copy whose profile SENT it (the
        consumer-am kit host, INCLUDE_PATH, 2026-11-03: its watermark lists the file) is CHECKED
        like the source -- the shipped file passes, and an older work-side file left at that path
        instead fails, because it is not the kit's. Without the watermark, or when the exporter
        does not exclude the file, a missing file still fails. Proven on throwaway trees.

    KIT_PROOF_ROOT=<dir> points T3..T6 and T8 at another tree, so the proof can be shown FAILING
    on the revision before the fix.

EXIT  0 all hold   1 any does not   2 bash/PyYAML unavailable -- UNKNOWN
"""
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TREE = os.environ.get('KIT_PROOF_ROOT') or ROOT
sys.path.insert(0, HERE)

LIB = os.path.join(ROOT, 'scripts', 'api_token_cause.sh')
BEGIN = '# >>> kit api token cause'
END = '# <<< kit api token cause'
REPO = 'example-org/app'
FAILS = []

BODY_401 = '{\n  "message": "Bad credentials",\n  "documentation_url": "https://docs.github.com/rest",\n  "status": "401"\n}'
BODY_IP = ('{\n  "message": "Although you appear to have the correct authorization credentials, the '
           '`example-org` organization has an IP allow list enabled, and your IP address is not '
           'permitted to access this resource.",\n  "status": "403"\n}')
BODY_SAML = ('{\n  "message": "Resource protected by organization SAML enforcement. You must grant your '
             'Personal Access token access to this organization.",\n  "status": "403"\n}')
BODY_RATE = '{\n  "message": "API rate limit exceeded for installation ID 1.",\n  "status": "403"\n}'

# (label, http status or None, text gh/urllib/git produced, expected cause)
CASES = [
    ('401 Bad credentials', 401, BODY_401 + '\ngh: Bad credentials (HTTP 401)', 'JOB_TOKEN_REJECTED'),
    ('403 IP allow list', 403, BODY_IP + '\ngh: Although you appear ... (HTTP 403)',
     'ORG_IP_ALLOW_LIST_BLOCKS_RUNNER'),
    ('403 SAML enforcement', 403, BODY_SAML + '\ngh: Resource protected by organization SAML '
     'enforcement. (HTTP 403)', 'ORG_SSO_BLOCKS_TOKEN'),
    ('403 primary rate limit', 403, BODY_RATE + '\ngh: API rate limit exceeded (HTTP 403)', 'RATE_LIMITED'),
    ('429 secondary rate limit', 429, 'You have exceeded a secondary rate limit. (HTTP 429)', 'RATE_LIMITED'),
    ('gh cannot connect', None, 'error connecting to api.github.com\ncheck your internet connection or '
     'https://githubstatus.com', 'API_UNREACHABLE'),
    ('DNS from gh', None, 'Get "https://api.github.com/repos/x/y": dial tcp: lookup api.github.com: '
     'no such host', 'API_UNREACHABLE'),
    ('DNS from urllib', None, '<urlopen error [Errno -3] Temporary failure in name resolution>',
     'API_UNREACHABLE'),
    ('git cannot resolve', None, "fatal: unable to access 'https://github.com/a/b/': Could not resolve "
     'host: github.com', 'API_UNREACHABLE'),
    ('403 not accessible', 403, '{"message":"Resource not accessible by integration"}\ngh: Resource not '
     'accessible by integration (HTTP 403)', 'TOKEN_PREFLIGHT_UNCLASSIFIED'),
]

STUB_GH = r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG"
case "$STUB_MODE" in
  ok)
    case "$*" in
      *"repos/$GITHUB_REPOSITORY"|*"repos/$GITHUB_REPOSITORY "*)
        printf '{"full_name":"%s","visibility":"private","default_branch":"main"}\n' "$GITHUB_REPOSITORY"; exit 0 ;;
    esac
    printf '{"message":"Not Found","status":"404"}\n'; echo 'gh: Not Found (HTTP 404)' >&2; exit 1 ;;
  ghe)
    # Answers like a GHE.com tenant: only a call on the tenant's own host is accepted.
    if [ "${GH_HOST:-}" = "example.ghe.com" ]; then
      printf '{"full_name":"%s","visibility":"private"}
' "$GITHUB_REPOSITORY"; exit 0
    fi
    printf '{
  "message": "Bad credentials",
  "status": "401"
}
'; echo 'gh: Bad credentials (HTTP 401)' >&2; exit 1 ;;
  ip)
    printf '%s\n' "$STUB_BODY_IP"; echo 'gh: Although you appear to have the correct authorization credentials (HTTP 403)' >&2; exit 1 ;;
  *)
    printf '{\n  "message": "Bad credentials",\n  "documentation_url": "https://docs.github.com/rest",\n  "status": "401"\n}\n'
    echo 'gh: Bad credentials (HTTP 401)' >&2
    echo 'Try authenticating with:  gh auth login -h github.com' >&2
    exit 1 ;;
esac
'''


def check(cond, msg, detail=()):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        for d in detail:
            print('       ' + str(d)[:400])
        FAILS.append(msg)


def posix(p):
    return p.replace('\\', '/')


def parse_output(path):
    """The runner's file-command grammar: `name=value`, or `name<<DELIM` ... `DELIM`."""
    lines = io.open(path, encoding='utf-8').read().split('\n')
    bad, kv, delim = [], {}, None
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
            bad.append(ln)
            continue
        k, v = ln.split('=', 1)
        kv[k] = v
    return kv, bad


def canonical_block():
    if not os.path.isfile(LIB):
        return None
    text = io.open(LIB, encoding='utf-8').read()
    i, j = text.find(BEGIN), text.find(END)
    if i < 0 or j < 0:
        return None
    return text[i:text.index('\n', j)]


def inlined_blocks(text):
    """-> [dedented block] for every BEGIN..END pair in a YAML file's text."""
    out = []
    lines = text.split('\n')
    i = 0
    while i < len(lines):
        if lines[i].strip() == BEGIN:
            ind = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
            blk = []
            while i < len(lines):
                ln = lines[i]
                blk.append(ln[len(ind):] if ln.startswith(ind) else ln.lstrip())
                if ln.strip() == END:
                    break
                i += 1
            out.append('\n'.join(blk))
        i += 1
    return out


def run_script(bash, body, env_extra, mode='401', cwd=None):
    work = tempfile.mkdtemp(prefix='token-named-')
    try:
        binp = os.path.join(work, 'bin')
        os.makedirs(binp)
        io.open(os.path.join(binp, 'gh'), 'w', newline='\n').write(STUB_GH)
        os.chmod(os.path.join(binp, 'gh'), 0o755)
        script = os.path.join(work, 'step.sh')
        io.open(script, 'w', encoding='utf-8', newline='\n').write(body)
        out, summ, log = (os.path.join(work, n) for n in ('output', 'summary', 'stub.log'))
        for p in (out, summ, log):
            io.open(p, 'w').close()
        env = dict(os.environ)
        env.update({'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_API_URL': 'https://api.github.com',
                    'GITHUB_REPOSITORY': REPO, 'GITHUB_OUTPUT': posix(out),
                    'GITHUB_STEP_SUMMARY': posix(summ), 'STUB_LOG': posix(log), 'STUB_MODE': mode,
                    'STUB_BODY_IP': BODY_IP, 'GH_TOKEN': 'ghs_job_token_placeholder',
                    'RUNNER_TEMP': posix(work)})
        env.update(env_extra)
        env.pop('GH_HOST', None)
        prefix = 'export PATH="%s:$PATH"; ' % posix(binp)
        if os.name == 'nt':
            prefix = 'export PATH="$(cygpath -u "%s"):$PATH"; ' % posix(binp)
        # The runner runs `bash --noprofile --norc -eo pipefail {0}`: -e included.
        p = subprocess.run([bash, '--noprofile', '--norc', '-eo', 'pipefail', '-c',
                            prefix + 'source "%s"' % posix(script)], env=env, cwd=cwd or work,
                           capture_output=True, text=True, encoding='utf-8', errors='replace',
                           timeout=120)
        kv, bad = parse_output(out)
        return {'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr, 'kv': kv, 'bad': bad,
                'summary': io.open(summ, encoding='utf-8').read(),
                'raw_out': io.open(out, encoding='utf-8').read()}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def t1(bash):
    if not os.path.isfile(LIB):
        check(False, 'T1 scripts/api_token_cause.sh exists')
        return
    for label, _status, text, want in CASES:
        p = subprocess.run([bash, '--noprofile', '--norc', '-eo', 'pipefail', '-c',
                            'source "$1"; kit_api_cause "$2"', '_', posix(LIB), text],
                           capture_output=True, text=True, timeout=60)
        got = p.stdout.strip()
        check(got == want, 'T1 shell: %s -> %s (%s)' % (label, want, got or p.stderr.strip()[-120:]))


def t2():
    try:
        import _github_refs
    except Exception as e:  # noqa: BLE001
        check(False, 'T2 tests/_github_refs.py imports (%s)' % e)
        return
    f = getattr(_github_refs, 'api_cause', None)
    if f is None:
        check(False, 'T2 tests/_github_refs.py has api_cause(status, text)')
        return
    for label, status, text, want in CASES:
        got = f(status, text)
        check(got == want, 'T2 python: %s -> %s (%s)' % (label, want, got))


CPT = '.github/workflows/consumer-path-test.yml'
WATERMARK = '.neutral-export-watermark.json'


def exporter_excludes(tree):
    """The exporter's EXCLUDE_PATHS, read (never imported) from the tree's own exporter; None when
    it cannot be read -- and then nothing is source-only."""
    import ast
    f = os.path.join(tree, 'scripts', 'export_for_adoption.py')
    if not os.path.isfile(f):
        return None
    m = re.search(r'^EXCLUDE_PATHS\s*=\s*(\{[^}]*\})', io.open(f, encoding='utf-8').read(), re.M)
    try:
        return set(ast.literal_eval(m.group(1))) if m else None
    except (ValueError, SyntaxError):
        return None


def sent_to_copy(tree, rel):
    """Did the export that made this copy send `rel`? Its watermark lists every file it shipped and
    every withheld path its profile included (INCLUDE_PATH)."""
    try:
        wm = json.load(io.open(os.path.join(tree, WATERMARK), encoding='utf-8'))
    except (OSError, ValueError):
        return False
    return rel in (wm.get('files') or {}) or rel in (wm.get('included_paths') or [])


def source_only(rel, tree):
    """SOURCE-ONLY (the way prove_export_scope.py E9 does it): an exported copy -- it carries the
    export watermark -- whose exporter leaves `rel` out by design, and which was not sent it, has no
    kit copy of it to check. Whatever sits at that path in such a copy (a work repository's older
    harness) is not the kit's. A copy that WAS sent it (a kit host's profile includes it) is checked.
    Without the watermark, or when the exporter does not exclude it, a missing file still fails."""
    if not os.path.isfile(os.path.join(tree, WATERMARK)):
        return False
    ex = exporter_excludes(tree)
    if ex is None or rel not in ex:
        return False
    if sent_to_copy(tree, rel):
        print('  CHECKED %s: this exported copy was sent the file (its watermark lists it), so the copy '
              'here must be the kit\'s and is checked like the source.' % rel)
        return False
    print('  SOURCE-ONLY %s: this is an exported copy (%s present) and the exporter leaves the file '
          'out by design (EXCLUDE_PATHS); its checks ran on the source at the commit the watermark '
          'records. Nothing was checked here, and nothing passed.' % (rel, WATERMARK))
    return True


def t3(tree=None):
    tree = tree or TREE
    canon = canonical_block()
    if canon is None:
        check(False, 'T3 scripts/api_token_cause.sh has its %s ... %s block' % (BEGIN, END))
        return
    need = {'.github/actions/discover/action.yml': 1, '.github/actions/resolve/action.yml': 1,
            '.github/workflows/consumer-path-test.yml': 3}
    for rel, n in sorted(need.items()):
        if source_only(rel, tree):
            continue
        f = os.path.join(tree, rel)
        blocks = inlined_blocks(io.open(f, encoding='utf-8').read()) if os.path.isfile(f) else []
        same = [b for b in blocks if b == canon]
        check(len(blocks) >= n and len(same) == len(blocks),
              'T3 %s inlines the library %d time(s), every copy byte-identical (%d found, %d identical)'
              % (rel, n, len(blocks), len(same)))


def load(rel, tree=None):
    import yaml
    f = os.path.join(tree or TREE, rel)
    return yaml.safe_load(io.open(f, encoding='utf-8').read()) if os.path.isfile(f) else {}


def common_raw_leak(r):
    """True when a raw API body line reached the output file or the log."""
    blob = r['raw_out'] + '\n' + r['stdout']
    return '"message"' in blob or 'Try authenticating' in blob


def t4(bash):
    doc = load('.github/actions/discover/action.yml')
    st = [s for s in (doc.get('runs') or {}).get('steps', []) if s.get('id') == 'platform']
    if len(st) != 1:
        check(False, 'T4 the discover platform step exists exactly once')
        return
    body = st[0]['run']
    repo = tempfile.mkdtemp(prefix='token-named-repo-')
    try:
        subprocess.run(['git', 'init', '-q'], cwd=repo, capture_output=True, timeout=60)
        r = run_script(bash, body, {}, '401', cwd=repo)
        check(r['rc'] == 0, 'T4 401: the platform step exits 0 (rc=%d)' % r['rc'], [r['stderr'][-300:]])
        check(not r['bad'], 'T4 401: $GITHUB_OUTPUT parses (%d unparseable)' % len(r['bad']), r['bad'][:3])
        check(r['kv'].get('token_preflight') == 'JOB_TOKEN_REJECTED',
              'T4 401: token_preflight=JOB_TOKEN_REJECTED (%r)' % r['kv'].get('token_preflight'))
        s = r['summary']
        for word in ('JOB_TOKEN_REJECTED', 'HTTP 401', 'organisation owner', 'workflow maintainer',
                     'IP allow list', 'Workflow permissions', 'Authorization', 'GITHUB_SERVER_URL'):
            check(word in s, 'T4 401: the summary says %r' % word)
        check('::error title=JOB_TOKEN_REJECTED' in r['stdout'],
              'T4 401: an ::error annotation is titled JOB_TOKEN_REJECTED')
        check(not common_raw_leak(r), 'T4 401: no raw API body in the output file or the log')
        r = run_script(bash, body, {}, 'ip', cwd=repo)
        check(r['rc'] == 0 and r['kv'].get('token_preflight') == 'ORG_IP_ALLOW_LIST_BLOCKS_RUNNER',
              'T4 403 IP allow list: token_preflight=ORG_IP_ALLOW_LIST_BLOCKS_RUNNER (rc=%d, %r)'
              % (r['rc'], r['kv'].get('token_preflight')))
        r = run_script(bash, body, {}, 'ok', cwd=repo)
        check(r['rc'] == 0 and r['kv'].get('token_preflight') == 'TOKEN_ACCEPTED'
              and r['kv'].get('visibility') == 'private',
              'T4 good answer: TOKEN_ACCEPTED and visibility read from it (rc=%d, %r, %r)'
              % (r['rc'], r['kv'].get('token_preflight'), r['kv'].get('visibility')))
        outs = doc.get('outputs') or {}
        check('token_preflight' in outs and 'steps.platform.outputs.token_preflight' in
              str((outs.get('token_preflight') or {}).get('value', '')),
              'T4 the discover composite declares the token_preflight output')
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def t5(bash):
    doc = load('.github/actions/resolve/action.yml')
    st = [s for s in (doc.get('runs') or {}).get('steps', [])
          if s.get('name') == 'Consume the platform-probe values']
    if len(st) != 1:
        check(False, 'T5 the resolve platform step exists exactly once')
        return
    env = {'p_ghas_available': 'UNKNOWN', 'p_code_scanning': 'UNKNOWN', 'p_secret_scanning': 'UNKNOWN',
           'p_push_protection': 'UNKNOWN', 'p_dependabot_alerts': 'ENABLED',
           'p_dependabot_updates': 'UNKNOWN', 'p_dependabot_config': 'PRESENT', 'p_visibility': 'private',
           'p_platform_source': 'none'}
    r = run_script(bash, st[0]['run'], env, '401')
    check(r['rc'] == 0, 'T5 401: the resolve platform step exits 0 (rc=%d)' % r['rc'], [r['stderr'][-300:]])
    check(not r['bad'], 'T5 401: $GITHUB_OUTPUT parses (%d unparseable)' % len(r['bad']), r['bad'][:3])
    check(r['kv'].get('dependabot_state') == 'UNAVAILABLE',
          'T5 401: dependabot_state=UNAVAILABLE (%r)' % r['kv'].get('dependabot_state'))
    check('JOB_TOKEN_REJECTED' in r['kv'].get('dependabot_basis', ''),
          'T5 401: dependabot_basis names JOB_TOKEN_REJECTED (%r)' % r['kv'].get('dependabot_basis', '')[:160])
    check('JOB_TOKEN_REJECTED' in r['summary'], 'T5 401: the summary row names JOB_TOKEN_REJECTED')
    check(not common_raw_leak(r), 'T5 401: no raw API body in the output file or the log')


def t6(bash, tree=None):
    tree = tree or TREE
    if source_only(CPT, tree):
        return
    doc = load(CPT, tree)
    jobs = doc.get('jobs') or {}
    gh_re = re.compile(r'(^|[\s;(|&$])gh\s+(api|run|workflow)\b', re.M)
    seen = 0
    for jid, job in sorted(jobs.items()):
        steps = job.get('steps') or []
        first_gh = next((i for i, s in enumerate(steps) if gh_re.search(s.get('run') or '')
                         and BEGIN not in (s.get('run') or '')), None)
        if first_gh is None:
            continue
        seen += 1
        pre = [i for i, s in enumerate(steps) if BEGIN in (s.get('run') or '')]
        check(bool(pre) and pre[0] < first_gh,
              'T6 %s: the job token preflight runs before its first gh step' % jid)
        if not pre:
            continue
        body = steps[pre[0]]['run']
        r = run_script(bash, body, {'GH_REPO': REPO}, '401')
        check(r['rc'] != 0 and '::error title=JOB_TOKEN_REJECTED' in r['stdout'],
              'T6 %s 401: the preflight fails with ::error title=JOB_TOKEN_REJECTED (rc=%d)' % (jid, r['rc']),
              [r['stdout'][-300:]])
        check('organisation owner' in r['summary'] and 'JOB_TOKEN_REJECTED' in r['summary'],
              'T6 %s 401: the summary names the cause and the owner role' % jid)
        check(not common_raw_leak(r), 'T6 %s 401: no raw API body in the log' % jid)
        r = run_script(bash, body, {'GH_REPO': REPO}, 'ok')
        check(r['rc'] == 0, 'T6 %s good answer: the preflight passes (rc=%d)' % (jid, r['rc']), [r['stdout'][-300:]])
        r = run_script(bash, body, {'GITHUB_SERVER_URL': 'https://example.ghe.com',
                                    'GITHUB_API_URL': 'https://api.example.ghe.com'}, 'ghe')
        check(r['rc'] == 0, 'T6 %s on a GHE.com host: the preflight asks the tenant, not github.com (rc=%d)'
              % (jid, r['rc']), [r['stdout'][-300:]])
    check(seen >= 3, 'T6 consumer-path-test has at least three jobs that call gh (%d)' % seen)


class _Resp(object):
    def __init__(self, data):
        self._d = data

    def read(self, *a):
        return self._d

    def getcode(self):
        return 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def t7():
    import contextlib
    import urllib.error
    import urllib.request
    import _github_refs
    import check_pinned_artifacts as cpa
    import check_action_pins as cap

    def git_unreachable(args, cwd, timeout):
        return 128, '', "fatal: unable to access 'https://github.com/x/y/': Could not resolve host: github.com"

    def scenario(answer):
        def urlopen(req, timeout=None):
            if answer is None:
                raise urllib.error.URLError('[Errno -3] Temporary failure in name resolution')
            code, body = answer
            raise urllib.error.HTTPError(req.full_url, code, 'x', {}, io.BytesIO(body.encode('utf-8')))
        return urlopen

    saved = (_github_refs._git, urllib.request.urlopen, cpa.resolves, dict(os.environ))
    rows = [('401', (401, BODY_401), {'GITHUB_TOKEN': 'ghs_x'}, ['JOB_TOKEN_REJECTED', 'HTTP 401'], ['rate-limited']),
            ('rate limit', (403, BODY_RATE), {'GITHUB_TOKEN': 'ghs_x'}, ['RATE_LIMITED', 'HTTP 403'], ['JOB_TOKEN_REJECTED']),
            ('no network', None, {'GITHUB_TOKEN': 'ghs_x'}, ['API_UNREACHABLE'], ['JOB_TOKEN_REJECTED']),
            ('no token', (401, BODY_401), {}, ['no token api.github.com issued'], ['JOB_TOKEN_REJECTED'])]
    try:
        _github_refs._git = git_unreachable
        cpa.resolves = lambda repo, tag, timeout=15: (repo, tag) == tuple(cpa.SELF_TEST_GOOD)
        for label, answer, env, must, mustnot in rows:
            for k in ('GITHUB_TOKEN', 'GH_TOKEN', 'PIN_CHECK_TOKEN_HOST'):
                os.environ.pop(k, None)
            os.environ['GITHUB_API_URL'] = 'https://api.github.com'
            os.environ.update(env)
            urllib.request.urlopen = scenario(answer)
            if hasattr(_github_refs, 'reset'):
                _github_refs.reset()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cpa.self_test()
            text = buf.getvalue()
            check(rc == 2 and all(m in text for m in must) and not any(m in text for m in mustnot),
                  'T7 check_pinned_artifacts %s: UNKNOWN exit 2 naming %s (rc=%r)' % (label, must, rc),
                  [text.strip()[-400:]])
            if hasattr(_github_refs, 'reset'):
                _github_refs.reset()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cap.main(['--online'])
            text = buf.getvalue()
            check(rc == 2 and all(m in text for m in must) and not any(m in text for m in mustnot),
                  'T7 check_action_pins --online %s: UNKNOWN exit 2 naming %s (rc=%r)' % (label, must, rc),
                  [text.strip()[-400:]])
    finally:
        _github_refs._git, urllib.request.urlopen, cpa.resolves, env0 = saved
        os.environ.clear()
        os.environ.update(env0)


def t8():
    pats = ['.github/workflows/*.yml', '.github/actions/**/action.yml', 'templates/**/*.yml']
    fetchers, installs = [], []
    for pat in pats:
        for f in sorted(glob.glob(os.path.join(TREE, pat), recursive=True)):
            text = io.open(f, encoding='utf-8').read()
            rel = os.path.relpath(f, TREE).replace('\\', '/')
            for m in re.finditer(r'aquasecurity/(trivy-action|setup-trivy)@|repository:\s*aquasecurity/trivy\b|'
                                 r'aquasecurity/trivy/[^\s]*/contrib/install\.sh', text):
                fetchers.append('%s: %s' % (rel, m.group(0)))
            for m in re.finditer(r'trivy/releases/download', text):
                seg = text[max(0, m.start() - 1500):m.start() + 1500]
                # The download command itself: its line and the two before (a `curl ... \` split).
                ls = text.rfind('\n', 0, m.start())
                for _ in range(2):
                    ls = text.rfind('\n', 0, max(ls, 0))
                cmd = text[max(ls, 0):text.find('\n', m.start())]
                installs.append((rel, 'sha256' in seg, bool(re.search(r'Authorization|GITHUB_TOKEN|GH_TOKEN|github\.token', cmd))))
    check(not fetchers, 'T8 no Trivy setup action and no checkout of aquasecurity/trivy (%d)' % len(fetchers), fetchers[:6])
    check(installs and all(s for _, s, _ in installs),
          'T8 every Trivy release download verifies a sha256 (%d site(s))' % len(installs),
          [r for r, s, _ in installs if not s])
    check(installs and not any(a for _, _, a in installs),
          'T8 no Trivy release download carries a token or an Authorization header',
          [r for r, _, a in installs if a])


def t9(bash):
    """T3/T6 on an exported copy: SOURCE-ONLY with the watermark and the exporter's exclusion; a
    failure without the watermark, or when the exporter does not exclude the file."""
    import contextlib
    import shutil as _sh
    work = tempfile.mkdtemp(prefix='token-named-t9-')
    try:
        for rel in ('.github/actions/discover/action.yml', '.github/actions/resolve/action.yml',
                    'scripts/export_for_adoption.py'):
            os.makedirs(os.path.dirname(os.path.join(work, rel)), exist_ok=True)
            _sh.copy(os.path.join(ROOT, rel), os.path.join(work, rel))
        wm = os.path.join(work, WATERMARK)
        exp = os.path.join(work, 'scripts', 'export_for_adoption.py')
        exp_text = io.open(exp, encoding='utf-8').read()

        def run(label):
            mark = len(FAILS)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                t3(work)
                t6(bash, work)
            got = FAILS[mark:]
            del FAILS[mark:]
            return got, buf.getvalue()

        io.open(wm, 'w').write('{"source_commit": "0000000", "profile": "neutral", "files": {}, '
                               '"included_paths": []}\n')
        got, out = run('copy')
        check(not got and out.count('SOURCE-ONLY ' + CPT) == 2,
              'T9 an exported copy (watermark, exporter excludes the file): T3 and T6 are SOURCE-ONLY for %s, '
              'by name, and fail nothing' % CPT, got + [out[-300:]])
        cpt = os.path.join(work, CPT)
        os.makedirs(os.path.dirname(cpt), exist_ok=True)
        io.open(cpt, 'w').write('name: an older harness\non: workflow_dispatch\njobs: {}\n')
        got, out = run('copy with an older file')
        check(not got and 'SOURCE-ONLY ' + CPT in out,
              'T9 an exported copy holding an older work-side %s: still SOURCE-ONLY (not the kit\'s copy)' % CPT, got)
        # A KIT HOST'S COPY WAS SENT THE FILE (consumer-am, INCLUDE_PATH): it is checked, not skipped.
        io.open(wm, 'w').write(json.dumps({'source_commit': '0000000', 'profile': 'consumer-am',
                                           'files': {CPT: '0' * 64}, 'included_paths': [CPT]}) + '\n')
        _sh.copy(os.path.join(ROOT, CPT), cpt)
        got, out = run('host copy, the kit\'s file')
        check(not got and 'SOURCE-ONLY ' + CPT not in out and 'CHECKED ' + CPT in out,
              'T9 a kit host\'s copy that was sent %s: T3 and T6 CHECK it, and the kit\'s file passes' % CPT,
              got + [out[-300:]])
        io.open(cpt, 'w').write('name: an older harness\non: workflow_dispatch\njobs: {}\n')
        got, out = run('host copy, an older file')
        check(any(g.startswith('T3') and CPT in g for g in got) and any(g.startswith('T6') for g in got),
              'T9 a kit host\'s copy holding an older work-side %s instead of the one it was sent: T3 and T6 FAIL'
              % CPT, got)
        os.remove(cpt)
        got, out = run('host copy, file missing')
        check(any(g.startswith('T3') and CPT in g for g in got) and any(g.startswith('T6') for g in got),
              'T9 a kit host\'s copy that was sent %s but lacks it: T3 and T6 FAIL' % CPT, got)
        os.remove(wm)
        got, out = run('no watermark')
        check(any(CPT in g and g.startswith('T3') for g in got) and any(g.startswith('T6') for g in got)
              and 'SOURCE-ONLY' not in out,
              'T9 no watermark and %s missing: T3 and T6 still FAIL' % CPT, got)
        io.open(wm, 'w').write('{}\n')
        io.open(exp, 'w', encoding='utf-8').write(exp_text.replace(CPT, 'somewhere/else.yml'))
        got, out = run('not excluded')
        check(any(CPT in g for g in got) and 'SOURCE-ONLY' not in out,
              'T9 watermark present but the exporter does not exclude %s: T3/T6 still FAIL' % CPT, got)
    finally:
        _sh.rmtree(work, ignore_errors=True)


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    import prove_bootstrap_failure as pbf
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    print('tree under proof: %s' % TREE)
    t1(bash)
    t2()
    t3()
    t4(bash)
    t5(bash)
    t6(bash)
    t7()
    t8()
    t9(bash)
    print()
    if FAILS:
        print('FAIL: %d check(s): a rejected job token is not yet named once with its owner.' % len(FAILS))
        return 1
    print('PASS: a rejected job token is named once, early, with its owner role; nothing crashes on it.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
