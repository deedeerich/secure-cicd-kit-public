#!/usr/bin/env python3
"""Every leak gate between a developer's `.env` and the default branch is recorded ON, OFF or
UNKNOWN on every run -- a missing one as a weakening, an unreadable one never as ON.

WHY THIS EXISTS (lane L-LEAK, KDEC-031 PROPOSED)

    A GitHub PAT leaked when a `.env` file was committed to a repository with none of the layers
    in place, and Tines GitSync pushes never run a local hook. The employer may not license GitHub
    secret scanning or push protection. So the kit must show plainly which layers are missing:

      1  local rails       the baseline .gitignore and the gitleaks pre-commit hook
      2a push protection   GitHub secret scanning push protection (may be unlicensed)
      2b push ruleset      a push ruleset refusing secret-file PATHS (no licence needed)
      3  CI secret scan    the kit's own; blocks in every mode (proven elsewhere)
      4  branch gate       a PR and the `Security gate` check required on the default branch
      +  secret scanning   alerts after the fact

    The discover job's platform step reads them (cheap: a few GETs in a job that already runs);
    the security-gate job's `leakgates` step records them. No new job and no new check name.

WHAT IT PROVES -- the discover composite's platform step, run as shipped under bash with a stub
`gh` answering like GitHub, in a throwaway git repository:
    D1  everything in place: push ruleset ON (an active push ruleset carrying the kit template),
        branch gate ON (rules: pull_request + required check `security / Security gate`),
        local rails ON (.gitignore ignores .env, a gitleaks pre-commit hook);
    D2  nothing in place: rulesets readable and empty, branch unprotected, no .gitignore -> all OFF;
    D3  every API answer 403: push ruleset and branch gate UNKNOWN, never ON or OFF;
    D4  a push ruleset in `evaluate` mode, or one that does not cover .env, is OFF;
    D5  classic branch protection: the required check read from the branch, the PR requirement
        from the admin-only protection endpoint; that endpoint refusing leaves the gate UNKNOWN;
    D6  every gh call carried GH_HOST=example.ghe.com (KDEC-027: the token stays on its host), and
        $GITHUB_OUTPUT parses as file commands.
and the security-gate job's `leakgates` step, run as shipped:
    G1  all ON -> no weakening, no alarm;
    G2  each OFF layer is one control_weakening row (CONTROL_DISABLED, WEAKENING_IN_FORCE,
        WEAKENING_UNATTRIBUTED) and a warning; with NONE of push protection, push ruleset or local
        rails shown ON the louder NO_LEAK_GATE_SHOWN alarm fires -- and the step exits 0 (crawl);
    G3  UNKNOWN and empty inputs are UNKNOWN in the record, never ON, and not weakenings;
    G4  a value outside the vocabulary (an injection attempt) is UNKNOWN;
    G5  the step never writes routing_result: at crawl a missing leak gate does not move the verdict.

EXIT  0 all hold   1 any does not   2 could not be run (no usable bash, jq or git) -- UNKNOWN
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
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402

DISCOVER = os.path.join(ROOT, '.github', 'actions', 'discover', 'action.yml')
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
TEMPLATE = os.path.join(ROOT, 'developer-safety', 'branch-protection', 'push-ruleset-secret-files.json')
REPO = 'tenant-org/app'
FAILS = []


def L(layer):
    """The leakgates step's env name for a layer (`L_` + the layer, upper-cased)."""
    return 'L_' + layer.upper()

# The stub answers `gh api <path>` from $STUB_DIR/<key>.json (+ <key>.rc, default 0); a path with
# no file answers 404. <key> is the path with every non-alphanumeric character turned into `_`.
STUB_GH = r'''#!/usr/bin/env bash
printf 'GH_HOST=%s\n' "${GH_HOST:-}" >> "$STUB_LOG"
path=""
for a in "$@"; do case "$a" in api|--paginate|-H|--method|GET) ;; repos/*) path="$a" ;; esac; done
key="$(printf '%s' "$path" | sed 's/[^A-Za-z0-9]/_/g')"
if [ -f "$STUB_DIR/$key.json" ]; then
  cat "$STUB_DIR/$key.json"
  rc=0; [ -f "$STUB_DIR/$key.rc" ] && rc="$(cat "$STUB_DIR/$key.rc")"
  exit "$rc"
fi
if [ -f "$STUB_DIR/ALL.rc" ]; then
  printf '{"message":"Resource not accessible by integration","status":"403"}\n'
  echo 'gh: Resource not accessible by integration (HTTP 403)' >&2
  exit 1
fi
printf '{"message":"Not Found","status":"404"}\n'
echo 'gh: Not Found (HTTP 404)' >&2
exit 1
'''


def check(cond, msg, detail=()):
    print('  %s %s' % ('PASS' if cond else 'FAIL', msg))
    if not cond:
        for d in detail:
            print('       %s' % d)
        FAILS.append(msg)


def key(path):
    return re.sub(r'[^A-Za-z0-9]', '_', path)


def posix(p):
    return p.replace('\\', '/')


def parse_output(path):
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


def step_of(doc_steps, sid):
    return next((s for s in doc_steps if s.get('id') == sid), None)


def run_discover(bash, step, answers, files=None, all403=False):
    """answers: {api path: (json body, rc)}; files: {repo path: text}. -> (outputs, bad lines,
    GH_HOST values seen, summary, rc)."""
    work = tempfile.mkdtemp(prefix='leak-gates-')
    try:
        binp, stub, repo = (os.path.join(work, n) for n in ('bin', 'stub', 'repo'))
        for d in (binp, stub, repo):
            os.makedirs(d)
        io.open(os.path.join(binp, 'gh'), 'w', newline='\n').write(STUB_GH)
        os.chmod(os.path.join(binp, 'gh'), 0o755)
        for path, (body, rc) in answers.items():
            io.open(os.path.join(stub, key(path) + '.json'), 'w', newline='\n').write(
                body if isinstance(body, str) else json.dumps(body))
            if rc:
                io.open(os.path.join(stub, key(path) + '.rc'), 'w').write(str(rc))
        if all403:
            io.open(os.path.join(stub, 'ALL.rc'), 'w').write('1')
        subprocess.run(['git', 'init', '-q'], cwd=repo, capture_output=True, timeout=60)
        for rel, text in (files or {}).items():
            os.makedirs(os.path.dirname(os.path.join(repo, rel)) or repo, exist_ok=True)
            io.open(os.path.join(repo, rel), 'w', newline='\n').write(text)
        script = os.path.join(work, 'step.sh')
        io.open(script, 'w', encoding='utf-8', newline='\n').write(step['run'])
        out, summ, log = (os.path.join(work, n) for n in ('output', 'summary', 'stub.log'))
        for p in (out, summ, log):
            io.open(p, 'w').close()
        env = dict(os.environ)
        env.update({'GITHUB_SERVER_URL': 'https://example.ghe.com',
                    'GITHUB_API_URL': 'https://api.example.ghe.com', 'GITHUB_REPOSITORY': REPO,
                    'GITHUB_OUTPUT': posix(out), 'GITHUB_STEP_SUMMARY': posix(summ),
                    'STUB_LOG': posix(log), 'STUB_DIR': posix(stub), 'GH_TOKEN': 'ghs_placeholder'})
        env.pop('GH_HOST', None)
        prefix = 'export PATH="%s:$PATH"; ' % posix(binp)
        if os.name == 'nt':
            prefix = 'export PATH="$(cygpath -u "%s"):$PATH"; ' % posix(binp)
        p = subprocess.run([bash, '-c', prefix + 'source "%s"' % posix(script)], env=env, cwd=repo,
                           capture_output=True, text=True, encoding='utf-8', errors='replace',
                           timeout=120)
        kv, bad = parse_output(out)
        seen = io.open(log, encoding='utf-8').read().split()
        return kv, bad, seen, io.open(summ, encoding='utf-8').read(), p.returncode, p.stderr
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_gate_step(bash, step, values):
    work = tempfile.mkdtemp(prefix='leak-gate-step-')
    try:
        out, summ = os.path.join(work, 'o'), os.path.join(work, 's')
        io.open(out, 'w').close()
        io.open(summ, 'w').close()
        f = os.path.join(work, 'step.sh')
        io.open(f, 'w', encoding='utf-8', newline='\n').write(step['run'])
        env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ)
        for k in step.get('env') or {}:
            env[k] = values.get(k, '')
        p = subprocess.run([bash, f], capture_output=True, text=True, encoding='utf-8',
                           errors='replace', env=env, cwd=work, timeout=60)
        kv, bad = parse_output(out)
        return kv, bad, io.open(summ, encoding='utf-8').read(), p.returncode, p.stdout + p.stderr
    finally:
        shutil.rmtree(work, ignore_errors=True)


REPO_JSON = {'visibility': 'private', 'default_branch': 'main'}
GITIGNORE = '.env\n.env.*\n!.env.example\n*.pem\n'
PRECOMMIT = 'repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.21.2\n    hooks:\n      - id: gitleaks\n'
RULES_URL = 'repos/%s/rulesets?includes_parents=true&per_page=100' % REPO
BRANCH_RULES = 'repos/%s/rules/branches/main' % REPO
BRANCH = 'repos/%s/branches/main' % REPO
PROTECTION = 'repos/%s/branches/main/protection' % REPO
GATE_RULES = [{'type': 'pull_request', 'parameters': {'required_approving_review_count': 0}},
              {'type': 'required_status_checks',
               'parameters': {'required_status_checks': [{'context': 'security / Security gate'}]}}]


def discover_cases(bash, step):
    tmpl = json.load(io.open(TEMPLATE, encoding='utf-8'))
    full = dict(tmpl, id=7, source_type='Repository')
    rs_list = [{'id': 7, 'name': tmpl['name'], 'target': 'push', 'enforcement': 'active'},
               {'id': 9, 'name': 'main', 'target': 'branch', 'enforcement': 'active'}]
    base = {'repos/' + REPO: (REPO_JSON, 0)}

    kv, bad, seen, summ, rc, err = run_discover(bash, step, dict(base, **{
        RULES_URL: (rs_list, 0), 'repos/%s/rulesets/7' % REPO: (full, 0),
        BRANCH_RULES: (GATE_RULES, 0), BRANCH: ({'name': 'main', 'protected': True}, 0)}),
        files={'.gitignore': GITIGNORE, '.pre-commit-config.yaml': PRECOMMIT})
    got = (kv.get('push_ruleset'), kv.get('branch_gate'), kv.get('local_baseline'))
    check(rc == 0 and got == ('ON', 'ON', 'ON'),
          'D1 everything in place -> push_ruleset/branch_gate/local_baseline ON (%s, rc=%d)' % (got, rc),
          [err[-400:]])
    check(not bad, 'D6 $GITHUB_OUTPUT parses as file commands (D1)', bad[:4])
    check(seen and all(s == 'GH_HOST=example.ghe.com' for s in seen),
          'D6 every gh call carried GH_HOST=example.ghe.com (%d calls)' % len(seen), sorted(set(seen)))
    check('Push ruleset' in summ and 'Branch gate' in summ and 'Local rails' in summ,
          'D1 the platform summary has a row per leak gate')

    kv, bad, seen, summ, rc, err = run_discover(bash, step, dict(base, **{
        RULES_URL: ([], 0), BRANCH_RULES: ([], 0), BRANCH: ({'name': 'main', 'protected': False}, 0)}))
    got = (kv.get('push_ruleset'), kv.get('branch_gate'), kv.get('local_baseline'))
    check(rc == 0 and got == ('OFF', 'OFF', 'OFF'), 'D2 nothing in place -> all OFF (%s)' % (got,),
          [err[-400:]])

    kv, bad, seen, summ, rc, err = run_discover(bash, step, {}, all403=True,
                                                files={'.gitignore': GITIGNORE})
    got = (kv.get('push_ruleset'), kv.get('branch_gate'))
    check(rc == 0 and got == ('UNKNOWN', 'UNKNOWN'),
          'D3 every API answer 403 -> push_ruleset/branch_gate UNKNOWN, never ON or OFF (%s)' % (got,),
          [err[-400:]])
    check(not bad, 'D6 $GITHUB_OUTPUT parses as file commands (D3, error bodies)', bad[:4])
    check(kv.get('local_baseline') == 'OFF',
          'D3 a .gitignore without the gitleaks hook is local_baseline OFF (%r)' % kv.get('local_baseline'))

    evaluate = [dict(rs_list[0], enforcement='evaluate')]
    kv, *_ = run_discover(bash, step, dict(base, **{RULES_URL: (evaluate, 0),
                                                    'repos/%s/rulesets/7' % REPO: (full, 0)}))
    check(kv.get('push_ruleset') == 'OFF', 'D4 an evaluate-mode push ruleset is OFF (%r)' % kv.get('push_ruleset'))
    narrow = dict(full, rules=[{'type': 'max_file_size', 'parameters': {'max_file_size': 10}}])
    kv, *_ = run_discover(bash, step, dict(base, **{RULES_URL: (rs_list, 0),
                                                    'repos/%s/rulesets/7' % REPO: (narrow, 0)}))
    check(kv.get('push_ruleset') == 'OFF',
          'D4 a push ruleset that does not refuse .env is OFF (%r)' % kv.get('push_ruleset'))
    kv, *_ = run_discover(bash, step, dict(base, **{RULES_URL: (rs_list, 0),
                                                    'repos/%s/rulesets/7' % REPO: ({'message': 'x'}, 1)}))
    check(kv.get('push_ruleset') == 'UNKNOWN',
          'D4 an active push ruleset that cannot be read is UNKNOWN, not OFF (%r)' % kv.get('push_ruleset'))

    classic = {'name': 'main', 'protected': True,
               'protection': {'required_status_checks': {'contexts': ['security / Security gate']}}}
    kv, *_ = run_discover(bash, step, dict(base, **{
        BRANCH_RULES: ([], 0), BRANCH: (classic, 0),
        PROTECTION: ({'required_pull_request_reviews': {'required_approving_review_count': 1}}, 0)}))
    check(kv.get('branch_gate') == 'ON',
          'D5 classic protection with a PR and the check -> branch_gate ON (%r)' % kv.get('branch_gate'))
    kv, *_ = run_discover(bash, step, dict(base, **{
        BRANCH_RULES: ([], 0), BRANCH: (classic, 0),
        PROTECTION: ({'message': 'Resource not accessible by integration'}, 1)}))
    check(kv.get('branch_gate') == 'UNKNOWN',
          'D5 the PR requirement unreadable (admin-only endpoint) -> branch_gate UNKNOWN (%r)'
          % kv.get('branch_gate'))
    nocheck = dict(classic, protection={'required_status_checks': {'contexts': ['lint']}})
    kv, *_ = run_discover(bash, step, dict(base, **{BRANCH_RULES: ([], 0), BRANCH: (nocheck, 0)}))
    check(kv.get('branch_gate') == 'OFF',
          'D5 a protected branch that does not require the Security gate -> OFF (%r)' % kv.get('branch_gate'))


def gate_cases(bash, step):
    on = {L('secret_scanning'): 'ENABLED', L('push_protection'): 'ENABLED', L('push_ruleset'): 'ON',
          L('branch_gate'): 'ON', L('local_baseline'): 'ON'}
    kv, bad, summ, rc, log = run_gate_step(bash, step, on)
    gates = json.loads(kv.get('leak_gates') or '{}')
    check(rc == 0 and set(gates.values()) == {'ON'} and len(gates) == 5,
          'G1 all ON -> five layers ON (%s, rc=%d)' % (gates, rc), [log[-300:]])
    check(json.loads(kv.get('leak_gate_weakenings') or 'null') == [] and not kv.get('leak_gate_alarm'),
          'G1 all ON -> no weakening, no alarm')
    check(not bad, 'G1 $GITHUB_OUTPUT parses', bad[:4])

    off = {L('secret_scanning'): 'UNAVAILABLE', L('push_protection'): 'NOT_CONFIGURED',
           L('push_ruleset'): 'OFF', L('branch_gate'): 'OFF', L('local_baseline'): 'OFF'}
    kv, bad, summ, rc, log = run_gate_step(bash, step, off)
    rows = json.loads(kv.get('leak_gate_weakenings') or '[]')
    shape = all(r.get('class') == 'CONTROL_DISABLED' and r.get('state') == 'WEAKENING_IN_FORCE'
                and r.get('attribution') == 'WEAKENING_UNATTRIBUTED' for r in rows)
    check(rc == 0, 'G2 nothing in place -> the step exits 0: it records, it does not block at crawl')
    check(len(rows) == 5 and shape,
          'G2 each OFF layer is one control_weakening row (%d rows, vocabulary %s)' % (len(rows), shape))
    check(kv.get('leak_gate_alarm') == 'NO_LEAK_GATE_SHOWN' and 'NO_LEAK_GATE_SHOWN' in log
          and 'No leak gate' in summ, 'G2 the louder alarm fires, as an annotation and in the summary')
    check(log.count('::warning title=Leak gate missing') == 5, 'G2 one warning per missing layer')

    part = dict(on, **{L('push_protection'): 'UNKNOWN', L('push_ruleset'): 'OFF', L('local_baseline'): 'OFF'})
    kv, bad, summ, rc, log = run_gate_step(bash, step, part)
    gates = json.loads(kv.get('leak_gates') or '{}')
    check(gates.get('push_protection') == 'UNKNOWN' and kv.get('leak_gate_alarm') == 'NO_LEAK_GATE_SHOWN',
          'G2/G3 push protection UNKNOWN + no ruleset + no local rails -> the alarm still fires (UNKNOWN is not ON)')

    kv, bad, summ, rc, log = run_gate_step(bash, step, {})
    gates = json.loads(kv.get('leak_gates') or '{}')
    check(rc == 0 and len(gates) == 5 and set(gates.values()) == {'UNKNOWN'}
          and json.loads(kv.get('leak_gate_weakenings') or 'null') == [],
          'G3 empty inputs (discover did not run) -> all UNKNOWN, no weakening claimed (%s)' % gates)

    evil = dict(on, **{L('push_ruleset'): 'ON"}; echo pwned', L('branch_gate'): '$(id)'})
    kv, bad, summ, rc, log = run_gate_step(bash, step, evil)
    gates = json.loads(kv.get('leak_gates') or '{}')
    check(gates.get('push_ruleset') == 'UNKNOWN' and gates.get('branch_gate') == 'UNKNOWN'
          and 'pwned' not in json.dumps(kv), 'G4 a value outside the vocabulary is UNKNOWN (%s)' % gates)

    check('routing_result' not in (step.get('run') or ''),
          'G5 the leak-gate step never writes routing_result (crawl: it does not move the verdict)')


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    if not shutil.which('jq') or not shutil.which('git'):
        print('UNKNOWN: jq and git are needed to run the steps as shipped.')
        return 2
    comp = yaml.safe_load(io.open(DISCOVER, encoding='utf-8'))
    dstep = step_of(comp['runs']['steps'], 'platform')
    wf = yaml.safe_load(io.open(WF, encoding='utf-8'))
    gstep = step_of(wf['jobs']['security-gate'].get('steps') or [], 'leakgates')
    if not dstep or not gstep:
        print('FAIL: the discover platform step (%s) or the security-gate leakgates step (%s) is missing.'
              % (bool(dstep), bool(gstep)))
        return 1
    gstep_env = gstep.get('env') or {}
    wants = {L('secret_scanning'): 'secret_scanning', L('push_protection'): 'push_protection',
             L('push_ruleset'): 'push_ruleset', L('branch_gate'): 'branch_gate',
             L('local_baseline'): 'local_baseline'}
    wired = all('needs.plan.outputs.%s' % v in str(gstep_env.get(k, '')) for k, v in wants.items())
    check(wired, 'wiring: the leakgates step reads all five layers from needs.discover.outputs, as data')
    outs = (wf['jobs']['plan'].get('outputs') or {})   # G1: discovery is a part of plan
    check(all('steps.platform.outputs.%s' % v in str(outs.get(v, '')) for v in
              ('push_ruleset', 'branch_gate', 'local_baseline')),
          'wiring: the discover job exposes push_ruleset, branch_gate and local_baseline')
    check(gstep.get('if') == 'always()', 'wiring: the leakgates step runs always()')
    discover_cases(bash, dstep)
    gate_cases(bash, gstep)
    print()
    if FAILS:
        print('FAIL: %d check(s).' % len(FAILS))
        return 1
    print('PASS: every leak gate is recorded ON, OFF or UNKNOWN; a missing one is a weakening and a '
          'warning, none shown ON is a louder alarm, and nothing here blocks at crawl.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
