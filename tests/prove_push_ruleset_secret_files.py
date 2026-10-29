#!/usr/bin/env python3
"""The push ruleset template blocks secret-file paths server-side, and lets `.env.example` through.

WHY THIS EXISTS (lane L-LEAK, KDEC-031)

    A GitHub PAT leaked when a `.env` file was committed to a repository with none of the layers
    in place, and Tines GitSync pushes never run a local hook. A push ruleset is the server-side
    layer that needs no secret-scanning licence: it refuses a push by FILE PATH or EXTENSION, not
    by content. developer-safety/branch-protection/push-ruleset-secret-files.json is the template;
    apply-push-ruleset.sh applies it.

WHAT IT PROVES
    R1  the JSON has the documented REST shape for POST /repos/{owner}/{repo}/rulesets: name,
        target "push", enforcement "active", bypass_actors a list, rules of type
        file_path_restriction (restricted_file_paths) and file_extension_restriction
        (restricted_file_extensions) -- nothing else, no unknown key. Limits: 200 entries of at
        most 200 characters per rule (GitHub docs, "Available rules for rulesets").
    R2  no pattern uses syntax GitHub's matcher does not support: a backslash, a complemented set
        (`[^..]`, and `[!..]`, whose support is UNVERIFIED), or an extglob brace (extglob is
        not supported). Every extension is written `*.ext`: GitHub refused a bare `.ext`
        live with HTTP 422 "File extension must start with *." (2026-10-26).
    R3  under Ruby File.fnmatch with the pathname flag semantics (GitHub's documented matcher; emulated here,
        no Ruby needed) every secret-file path the owner named is BLOCKED -- at the root, nested,
        and under a dot-directory -- and `.env.example` is ALLOWED wherever it sits.
    R4  the emulator can fail: the naive `**/.env.*` would block `.env.example`, and R3's
        allow-check says so (a check that cannot fail proves nothing).
    R5  the apply script sends the token only to the run's host (GH_HOST from --host, GH_HOST or
        GITHUB_SERVER_URL; never a hard-coded api.github.com) and is idempotent (PUT when a
        ruleset of that name exists, POST otherwise).
    R6  the apply script checks its prerequisites before it prints any plan, in the dry run and
        the real run alike, and each failure exits with its own code and named reason:
        PREREQUISITE_UNAVAILABLE for gh (11), jq (12) and a gh login to the run's host (13, from
        `gh auth status --hostname HOST`), REPO_NOT_READABLE (14), RULESET_LOOKUP_FAILED (15);
        PREREQUISITE_UNAVAILABLE for bash (10) is guarded before `set -o pipefail`. The reason
        names are registered in assurance-taxonomy.yaml (prerequisite_readiness and
        leak_gate_setup_refusal); the exit code tells the four prerequisites apart.
        Only a successful lookup prints `existing_id`, and a dry run never writes. It runs the
        script against a stub `gh` and `jq` on a PATH that holds nothing else, so it needs bash
        but no network, no token and no real gh. Before this, a dry run with gh missing or logged
        out printed `existing_id=none` and exited 0: a plan that proved nothing.

WHAT IT CANNOT PROVE
    That GitHub's matcher behaves exactly like the emulator (UNVERIFIED until the ruleset is
    applied to a real private repository and a `.env` push is refused), or that a repository's
    plan offers push rulesets. docs/adoption/LEAK_GATES.md records both.

EXIT  0 all hold   1 any does not
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RULESET = os.path.join(ROOT, 'developer-safety', 'branch-protection', 'push-ruleset-secret-files.json')
APPLY = os.path.join(ROOT, 'developer-safety', 'branch-protection', 'apply-push-ruleset.sh')
FAILS = []

# The documented rule shapes (REST "Create a repository ruleset", apiVersion 2022-11-28).
RULE_PARAMS = {'file_path_restriction': 'restricted_file_paths',
               'file_extension_restriction': 'restricted_file_extensions'}
TOP_KEYS = {'name', 'target', 'enforcement', 'bypass_actors', 'rules'}

MUST_BLOCK = [
    '.env', 'app/.env', 'a/b/c/.env', '.devcontainer/.env', 'svc/.config/.env',
    '.env.local', '.env.production', 'web/.env.prod', '.env.staging', '.env.dev', '.env.test',
    '.env.Example', '.env.e', '.env.ex', '.env.exa', '.env.exam', '.env.examp', '.env.exampl',
    '.env.edge', '.env.exe', '.env.example.bak', 'x/.env.example2', '.env.backup', '.env.1',
    'id_rsa', 'id_rsa.pub', 'home/.ssh/id_rsa', 'keys/id_ed25519', 'id_ecdsa',
    'terraform.tfstate', 'infra/terraform.tfstate', 'infra/terraform.tfstate.backup',
    'credentials.json', 'gcp/service-credentials.json', 'aws-credentials-prod.json',
    'certs/server.pem', 'tls.key', 'a/b/client.pfx', 'store.p12', 'release.jks',
    'debug.keystore', 'putty.ppk', 'traces/login.har',
]
MUST_ALLOW = [
    '.env.example', 'app/.env.example', 'a/b/.env.example', '.devcontainer/.env.example',
    'src/app.py', 'README.md', 'docs/env.md', 'environment.yml', 'src/envelope.py',
    'credentials.md', 'keyboard.json', 'pemfile.txt', 'terraform.tf', '.envrc.md',
]


def check(cond, msg, detail=()):
    print('  %s %s' % ('PASS' if cond else 'FAIL', msg))
    if not cond:
        for d in detail:
            print('       %s' % d)
        FAILS.append(msg)


# ---------------------------------------------------------------- Ruby File.fnmatch with the pathname flag
def _match(p, s, comp_start=True):
    """Ruby File.fnmatch with the pathname flag, without the dotmatch and extglob flags, case-sensitive.
    `**/` matches zero or more directories not starting with '.'; `*`, `?` and a set never match
    '/', nor a '.' that starts a path component."""
    if not p:
        return not s
    if p.startswith('**/'):
        rest = s
        while True:
            if _match(p[3:], rest, True):
                return True
            i = rest.find('/')
            # consume one whole directory, which `**/` may do only if it does not start with '.'
            if i <= 0 or rest.startswith('.'):
                return False
            rest = rest[i + 1:]
    c = p[0]
    if c == '*':
        if s[:1] == '.' and comp_start:
            return False
        j = 0
        while True:
            if _match(p[1:], s[j:], False):
                return True
            if j >= len(s) or s[j] == '/':
                return False
            j += 1
    if not s:
        return False
    if c == '?':
        if s[0] == '/' or (s[0] == '.' and comp_start):
            return False
        return _match(p[1:], s[1:], False)
    if c == '[':
        end = p.find(']', 2)
        if end == -1:
            return s[0] == '[' and _match(p[1:], s[1:], False)
        body = p[1:end]
        if s[0] == '/' or (s[0] == '.' and comp_start):
            return False
        ok, k = False, 0
        while k < len(body):
            if k + 2 < len(body) and body[k + 1] == '-':
                ok |= body[k] <= s[0] <= body[k + 2]
                k += 3
            else:
                ok |= body[k] == s[0]
                k += 1
        return ok and _match(p[end + 1:], s[1:], False)
    if c != s[0]:
        return False
    return _match(p[1:], s[1:], c == '/')


def fnmatch(pattern, path):
    return _match(pattern, path, True)


def blocked(doc, path):
    """-> the first rule entry that refuses `path`, or None."""
    for r in doc.get('rules') or []:
        prm = r.get('parameters') or {}
        if r.get('type') == 'file_path_restriction':
            for pat in prm.get('restricted_file_paths') or []:
                if fnmatch(pat, path):
                    return pat
        if r.get('type') == 'file_extension_restriction':
            # GitHub requires each entry as `*.ext` (HTTP 422 "File extension must start with *."
            # otherwise, live on 2026-10-26); the extension compared is the part after the `*`.
            ext = os.path.splitext(path.rsplit('/', 1)[-1])[1]
            exts = [e[1:] for e in prm.get('restricted_file_extensions') or [] if e.startswith('*')]
            if ext and ext in exts:
                return 'ext *' + ext
    return None


def r1_r2(doc):
    check(set(doc) <= TOP_KEYS and {'name', 'target', 'enforcement', 'rules'} <= set(doc),
          'R1 top-level keys are the documented ones (%s)' % sorted(doc))
    check(doc.get('target') == 'push', 'R1 target is "push" (%r)' % doc.get('target'))
    check(doc.get('enforcement') == 'active', 'R1 enforcement is "active" (%r)' % doc.get('enforcement'))
    check(isinstance(doc.get('bypass_actors', []), list), 'R1 bypass_actors is a list')
    types = [r.get('type') for r in doc.get('rules') or []]
    check(sorted(types) == sorted(RULE_PARAMS), 'R1 rules are exactly %s (%s)' % (sorted(RULE_PARAMS), types))
    for r in doc.get('rules') or []:
        want = RULE_PARAMS.get(r.get('type'))
        prm = r.get('parameters') or {}
        check(set(r) == {'type', 'parameters'} and list(prm) == [want],
              'R1 %s carries only parameters.%s (%s)' % (r.get('type'), want, sorted(prm)))
        vals = prm.get(want) or []
        check(0 < len(vals) <= 200 and all(isinstance(v, str) and 0 < len(v) <= 200 for v in vals),
              'R1 %s: %d entries, each 1..200 characters' % (want, len(vals)))
        check(len(set(vals)) == len(vals), 'R1 %s has no duplicate entry' % want)
        bad = [v for v in vals if '\\' in v or '[^' in v or '[!' in v or '{' in v]
        check(not bad, 'R2 %s uses no unsupported syntax (backslash, complement, extglob)' % want, bad)
        if want == 'restricted_file_extensions':
            nostar = [v for v in vals if not v.startswith('*.') or '/' in v or '*' in v[1:]]
            check(not nostar, 'R2 every extension is "*.ext" (GitHub refuses a bare ".ext" with 422)', nostar)


def r3(doc):
    missed = [p for p in MUST_BLOCK if not blocked(doc, p)]
    check(not missed, 'R3 every named secret-file path is blocked (%d paths)' % len(MUST_BLOCK), missed)
    wrong = ['%s <- %s' % (p, blocked(doc, p)) for p in MUST_ALLOW if blocked(doc, p)]
    check(not wrong, 'R3 .env.example and ordinary files are allowed (%d paths)' % len(MUST_ALLOW), wrong)


def r4():
    naive = {'rules': [{'type': 'file_path_restriction',
                        'parameters': {'restricted_file_paths': ['**/.env', '**/.env.*']}}]}
    check(bool(blocked(naive, '.env.example')),
          'R4 the naive `**/.env.*` is caught blocking .env.example (the allow-check can fail)')
    check(fnmatch('**/.env', '.env') and fnmatch('**/.env', 'a/b/.env')
          and not fnmatch('**/.env', 'a/.hidden/.env') and not fnmatch('*.json', 'a/b.json'),
          'R4 the emulator follows the pathname flag (`**/` spans plain directories, not dot ones; `*` stops at /)')


def r5():
    if not os.path.isfile(APPLY):
        check(False, 'R5 %s exists' % os.path.relpath(APPLY, ROOT))
        return
    src = io.open(APPLY, encoding='utf-8').read()
    check('api.github.com' not in src, 'R5 the apply script names no api.github.com')
    check(re.search(r'export GH_HOST', src) is not None and 'GITHUB_SERVER_URL' in src,
          'R5 the apply script exports GH_HOST, from --host / GH_HOST / GITHUB_SERVER_URL')
    check(re.search(r'--method PUT', src) is not None and re.search(r'--method POST', src) is not None,
          'R5 the apply script updates an existing ruleset (PUT) or creates one (POST): idempotent')
    check('push-ruleset-secret-files.json' in src, 'R5 the apply script applies the shipped template')


# ---------------------------------------------------------------- R6: prerequisites, against stubs
# The stubs use builtins only: the PATH the script sees holds nothing but them.
STUB_GH = r'''#!/bin/bash
# Stub gh (tests/prove_push_ruleset_secret_files.py R6). Mode from STUB_GH_MODE; every call logged.
printf '%s\n' "$*" >> "$STUB_LOG"
mode="${STUB_GH_MODE:-ok}"
if [ "$1 $2" = "auth status" ]; then
  if [ "$mode" = unauth ]; then echo "You are not logged into any GitHub hosts." >&2; exit 1; fi
  exit 0
fi
if [ "$1" = api ]; then
  case "$*" in
    *--method*) echo "stub write"; exit 0 ;;
    *rulesets*)
      if [ "$mode" = lookupfail ]; then echo "HTTP 500: lookup failed" >&2; exit 1; fi
      if [ "$mode" = existing ]; then echo 42; fi
      exit 0 ;;
    *)
      if [ "$mode" = norepo ]; then echo "HTTP 404: Not Found" >&2; exit 1; fi
      echo "owner/repo"; exit 0 ;;
  esac
fi
echo "stub gh: unexpected call: $*" >&2
exit 99
'''
STUB_JQ = '#!/bin/bash\n# Stub jq: the apply script reads only `.name` from the template.\necho %s\n'
HOST = 'ghe.example.test'


def usable_bash():
    """A REAL bash (never the WSL launcher stub): tests/prove_bootstrap_failure.py usable_bash."""
    sys.path.insert(0, HERE)
    import prove_bootstrap_failure as pbf
    return pbf.usable_bash()[0]


def run_apply(bash, tools, mode, *args):
    """-> (rc, stdout, stderr, gh calls) for the apply script with only `tools` stubbed on PATH."""
    work = tempfile.mkdtemp(prefix='apply-ruleset-')
    try:
        bindir = os.path.join(work, 'bin')
        os.makedirs(bindir)
        log = os.path.join(work, 'gh.log')
        io.open(log, 'w').close()
        name = json.load(io.open(RULESET, encoding='utf-8'))['name']
        stubs = {'gh': STUB_GH, 'jq': STUB_JQ % json.dumps(name)}
        for t in tools:
            path = os.path.join(bindir, t)
            io.open(path, 'w', encoding='utf-8', newline='\n').write(stubs[t])
            os.chmod(path, 0o755)
        env = {k: v for k, v in os.environ.items()
               if not k.startswith('GH_') and k not in ('GITHUB_TOKEN', 'GITHUB_SERVER_URL', 'PATH')}
        env.update(PATH=bindir, STUB_GH_MODE=mode, STUB_LOG=log.replace('\\', '/'))
        p = subprocess.run([bash, APPLY.replace('\\', '/'), 'owner/repo', '--host', HOST] + list(args),
                           capture_output=True, text=True, env=env, timeout=60)
        calls = [ln for ln in io.open(log, encoding='utf-8').read().splitlines() if ln]
        return p.returncode, p.stdout, p.stderr, calls
    finally:
        shutil.rmtree(work, ignore_errors=True)


def r6():
    src = io.open(APPLY, encoding='utf-8').read()
    guard, setopt = src.find('BASH_VERSION'), src.find('set -euo pipefail')
    check(0 <= guard < setopt and 'PREREQUISITE_UNAVAILABLE: this script needs bash' in src and 'exit 10' in src,
          'R6 a non-bash shell is refused (PREREQUISITE_UNAVAILABLE, 10) before `set -o pipefail`')
    dash = shutil.which('dash')
    if dash:
        # An LF copy, as a Linux checkout holds it: dash cannot parse a CRLF working copy at all.
        work = tempfile.mkdtemp(prefix='apply-ruleset-dash-')
        try:
            lf = os.path.join(work, 'apply-push-ruleset.sh')
            io.open(lf, 'w', encoding='utf-8', newline='\n').write(src.replace('\r\n', '\n'))
            p = subprocess.run([dash, lf.replace('\\', '/'), 'owner/repo', '--dry-run'],
                               capture_output=True, text=True, timeout=60)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        check(p.returncode == 10 and 'PREREQUISITE_UNAVAILABLE: this script needs bash' in p.stderr
              and 'existing_id' not in p.stdout,
              'R6 run under dash: exit 10 PREREQUISITE_UNAVAILABLE (bash) (rc=%d)' % p.returncode, [p.stderr.strip()[-300:]])
    bash = usable_bash()
    if not bash:
        check(False, 'R6 a usable bash is available to run the apply script')
        return
    refusals = [
        ('gh missing', ('jq',), 'ok', 11, 'PREREQUISITE_UNAVAILABLE: gh (GitHub CLI) is not on PATH'),
        ('jq missing', ('gh',), 'ok', 12, 'PREREQUISITE_UNAVAILABLE: jq is not on PATH'),
        ('gh not authenticated', ('gh', 'jq'), 'unauth', 13, 'PREREQUISITE_UNAVAILABLE: gh is not authenticated to'),
        ('repository not readable', ('gh', 'jq'), 'norepo', 14, 'REPO_NOT_READABLE'),
        ('ruleset lookup failed', ('gh', 'jq'), 'lookupfail', 15, 'RULESET_LOOKUP_FAILED'),
    ]
    for label, tools, mode, code, reason in refusals:
        for args in (['--dry-run'], []):
            rc, out, err, calls = run_apply(bash, tools, mode, *args)
            run = 'dry run' if args else 'real run'
            check(rc == code and reason in err and 'existing_id' not in out and 'would' not in out
                  and not any('--method' in c for c in calls),
                  'R6 %s, %s: exit %d %s, no plan, no write (rc=%d)' % (label, run, code, reason, rc),
                  ['stdout: ' + out.strip()[-300:], 'stderr: ' + err.strip()[-300:], 'gh calls: %s' % calls])
    rc, out, err, calls = run_apply(bash, ('gh', 'jq'), 'unauth', '--dry-run')
    check(('auth status --hostname %s' % HOST) in calls,
          'R6 authentication is checked against the run\'s host (`gh auth status --hostname %s`)' % HOST,
          ['gh calls: %s' % calls])
    rc, out, err, calls = run_apply(bash, ('gh', 'jq'), 'ok', '--dry-run')
    check(rc == 0 and 'existing_id=none' in out and 'would POST repos/owner/repo/rulesets' in out
          and not any('--method' in c for c in calls),
          'R6 a successful lookup with no ruleset: dry run prints existing_id=none, would POST, writes nothing (rc=%d)' % rc,
          ['stdout: ' + out.strip()[-300:], 'stderr: ' + err.strip()[-300:]])
    rc, out, err, calls = run_apply(bash, ('gh', 'jq'), 'existing', '--dry-run')
    check(rc == 0 and 'existing_id=42' in out and 'would PUT repos/owner/repo/rulesets/42' in out
          and not any('--method' in c for c in calls),
          'R6 a successful lookup of an existing ruleset: dry run prints existing_id=42, would PUT (rc=%d)' % rc,
          ['stdout: ' + out.strip()[-300:], 'stderr: ' + err.strip()[-300:]])
    rc, out, err, calls = run_apply(bash, ('gh', 'jq'), 'existing')
    check(rc == 0 and any(c.startswith('api --method PUT repos/owner/repo/rulesets/42') for c in calls),
          'R6 the real run updates the existing ruleset with PUT (rc=%d)' % rc,
          ['stderr: ' + err.strip()[-300:], 'gh calls: %s' % calls])


def main():
    try:
        doc = json.load(io.open(RULESET, encoding='utf-8'))
    except (OSError, ValueError) as e:
        print('FAIL: %s unreadable: %s' % (RULESET, e))
        return 1
    r1_r2(doc)
    r3(doc)
    r4()
    r5()
    r6()
    print()
    if FAILS:
        print('FAIL: %d check(s).' % len(FAILS))
        return 1
    print('PASS: the push ruleset has the documented shape, blocks every named secret-file path '
          'and lets .env.example through; the apply script refuses, by name, to plan without its '
          'prerequisites.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
