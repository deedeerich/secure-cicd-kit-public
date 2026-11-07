#!/usr/bin/env python3
"""The kit's OWN Dependabot triage caller: the owner's merge strategy, dogfooded on this repository.

WHY THIS EXISTS (owner, 2026-11-04: "Are we going to do my dependabot merge strategy finally?")

    The strategy (2026-10-22) was built as a reusable (.github/workflows/reusable-dependabot-triage.yml)
    and a template, and proven by running its steps (tests/prove_dependabot_triage.py) -- but nothing
    in this repository called it, so this repository's own Dependabot PRs (PR #5, setup-java 5 -> 6)
    sat unmerged with no decision at all. .github/workflows/dependabot-triage.yml is that caller.
    This proof holds it to the strategy, through the reusable's SHIPPED evidence and decision steps
    with THIS caller's inputs and THIS repository's real update shapes.

WHAT IT PROVES
    K1  the caller: pull_request_target only (the caller and the reusable come from the default
        branch); top-level `permissions: {}`; ONE job, guarded on the PR AUTHOR being
        dependabot[bot], granting exactly the union of what the reusable's jobs request; it calls
        this repository's reusable by `./`; nothing checks anything out
    K2  the policy it passes: required_checks names only checks this repository emits (a job
        `name:` in self-test.yml), and names `Self-test required` (KDEC-033); auto_merge_update_types
        within the ceiling patch,minor; the fixture excluded; the review label set; azure/login,
        actions/attest and github/codeql-action protected; and DEPENDABOT_TRIAGE.md section 3a
        lists the owner's repository-setting steps for every named check
    K3  this repository's Dependabot PRs, decided by the shipped steps with this caller's inputs:
          an actions patch bump, SHA-pinned, main requiring `Self-test required`  -> auto_merge
          the same PR against today's ruleset (7 checks, not that one)             -> human_review
                                                                                  (scan_gate_not_required)
          setup-java v5.7.0 -> v6.2.0 (PR #5's update)                            -> human_review (major_update)
          azure/login minor                                                      -> human_review (critical_package)
          github/codeql-action/upload-sarif minor                                -> human_review (critical_package)
          the azurerm provider in infra/feed-mirrors                             -> human_review (critical_ecosystem)
          busybox in a deploy probe                                              -> human_review (critical_ecosystem)
          a pin bump inside this caller                                          -> human_review (triage_chain)
          a fixture package                                                      -> close (excluded_path)
        and the counter-case: the same patch bump with the CALLER's required_checks emptied goes to
        a human (scan_gate_unnamed) -- the auto_merge above is earned by the caller's policy

USAGE  python3 tests/prove_kit_dependabot_triage_caller.py
EXIT   0 all hold   1 any does not   2 bash or PyYAML unavailable (UNKNOWN)
"""
import io
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML not available. Failure to observe is not an observation.')
    sys.exit(2)

import prove_dependabot_triage as T  # noqa: E402

CALLER_REL = '.github/workflows/dependabot-triage.yml'
CALLER = os.path.join(ROOT, *CALLER_REL.split('/'))
SELFTEST = os.path.join(ROOT, '.github', 'workflows', 'self-test.yml')
DOC = os.path.join(ROOT, 'docs', 'adoption', 'DEPENDABOT_TRIAGE.md')
LOCAL = './.github/workflows/reusable-dependabot-triage.yml'
KIT_REPO = 'owner/secure-cicd-kit'
KIT_CALLER_REF = '%s/%s@refs/heads/main' % (KIT_REPO, CALLER_REL)
# The checks the kit repository's `main` ruleset required on 2026-11-04 (read through the API).
TODAY = ['YAML lint', 'actionlint', 'Contract shape', 'Profile schema', 'Normalizer drift',
         'Validation coverage', 'Policy gate (dogfood) / Workflow policy']
MUST_PROTECT = ('azure/login', 'actions/attest', 'github/codeql-action')

FAILS = []


def check(cond, label):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def split(v):
    return [x.strip() for x in re.split(r'[,\n]', str(v or '')) if x.strip()]


def emitted_checks():
    """Every check name self-test.yml can emit: a job's `name:`, and `<caller name> / <name>` for a
    call into a local reusable."""
    d = yaml.safe_load(io.open(SELFTEST, encoding='utf-8'))
    out = set()
    for jid, j in (d.get('jobs') or {}).items():
        n = j.get('name') or jid
        out.add(n)
        u = str(j.get('uses') or '')
        if u.startswith('./'):
            sub = yaml.safe_load(io.open(os.path.join(ROOT, *u[2:].split('/')), encoding='utf-8'))
            for sid, sj in (sub.get('jobs') or {}).items():
                out.add('%s / %s' % (n, sj.get('name') or sid))
    return out


def k1(doc):
    on = T.on_of(doc)
    # The TRIAGE job acts only on pull_request_target. The caller also carries push (main), schedule
    # and dispatch for its keep-current job (owner 2026-11-06; tests/prove_dependabot_keep_current.py),
    # which the triage job's author guard skips: a push carries no pull request.
    check(isinstance(on, dict) and 'pull_request_target' in on and
          set(on) <= {'pull_request_target', 'push', 'schedule', 'workflow_dispatch'},
          'K1 the caller triggers on pull_request_target (+ push/schedule/dispatch for keep-current only) (%r)'
          % (list(on) if isinstance(on, dict) else on))
    check(doc.get('permissions') == {}, 'K1 top-level permissions: {}')
    jobs = doc.get('jobs') or {}
    triage = {k: v for k, v in jobs.items() if str(v.get('uses', '')) == LOCAL}
    others = set(jobs) - set(triage) - {k for k, v in jobs.items()
                                        if 'reusable-dependabot-keep-current.yml' in str(v.get('uses', ''))}
    check(len(triage) == 1 and not others, 'K1 exactly one triage job, plus only keep-current (%r)' % sorted(jobs))
    job = list(triage.values())[0] if triage else {}
    check(job.get('uses') == LOCAL, 'K1 it calls this repository\'s reusable by `./` (%r)' % job.get('uses'))
    check("github.event.pull_request.user.login == 'dependabot[bot]'" in str(job.get('if', '')),
          'K1 guarded on the PR author being dependabot[bot]')
    union = {}
    for perms in T.JOB_PERMS.values():
        for k, v in perms.items():
            if union.get(k) != 'write':
                union[k] = v
    check(job.get('permissions') == union, 'K1 grants exactly %r (got %r)' % (union, job.get('permissions')))
    check('steps' not in job and 'actions/checkout' not in io.open(CALLER, encoding='utf-8').read().split('jobs:', 1)[-1],
          'K1 nothing is checked out')
    return job


def k2(job):
    w = job.get('with') or {}
    names = split(w.get('required_checks'))
    emitted = emitted_checks()
    check(bool(names), 'K2 required_checks is not empty (%r)' % names)
    check('Self-test required' in names, 'K2 required_checks names `Self-test required` (KDEC-033)')
    unknown = [n for n in names if n not in emitted]
    check(not unknown, 'K2 every named check is one self-test.yml emits %s' % (unknown or ''))
    types = split(w.get('auto_merge_update_types', 'patch,minor'))
    check(set(types) <= {'patch', 'minor'} and types, 'K2 auto-merge ceiling patch,minor (%r)' % types)
    check('tests/consumer-fixture/**' in split(w.get('excluded_paths', 'tests/consumer-fixture/**')),
          'K2 the deliberately vulnerable fixture is excluded')
    check(bool(str(w.get('review_label', 'needs-human-review')).strip()), 'K2 a review label is set')
    crit = split(w.get('critical_packages'))
    for p in MUST_PROTECT:
        check(p in crit, 'K2 %s is a protected package' % p)
    doc = io.open(DOC, encoding='utf-8').read()
    sec = doc.split('### 3a', 1)[-1].split('\n## ', 1)[0] if '### 3a' in doc else ''
    check(bool(sec), 'K2 DEPENDABOT_TRIAGE.md has section 3a (this repository\'s owner steps)')
    check('allow_auto_merge' in sec and 'Allow auto-merge' in sec, 'K2 section 3a names "Allow auto-merge" and its API call')
    for n in names:
        check(('`%s`' % n) in sec, 'K2 section 3a names the required check `%s`' % n)
    return w


def k3(w):
    import _step_harness as H
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    tdoc = T.load(T.WF)
    ev_step = dict(T.find_step(tdoc['jobs']['classify'], 'evidence'))
    de_step = dict(T.find_step(tdoc['jobs']['classify'], 'decide'))
    inputs = {k: str(v) for k, v in w.items()}
    rules_with = [{'type': 'required_status_checks', 'parameters': {'required_status_checks':
                  [{'context': c} for c in TODAY + ['Self-test required']]}}]
    rules_today = [{'type': 'required_status_checks', 'parameters': {'required_status_checks':
                   [{'context': c} for c in TODAY]}}]
    s1, s2 = 'a' * 40, 'b' * 40

    def ap(action, a, b, path='.github/workflows/reusable-security.yml'):
        return [T.f(path, 2, '@@ -10,7 +10,7 @@\n-      - uses: %s@%s # %s\n+      - uses: %s@%s # %s\n'
                    % (action, s1, a, action, s2, b))]

    def gha(name, ut, a, b):
        return [T.dep(name, ut, a, b, dtype='direct:production', eco='github_actions')]
    cases = [
        ('K3 actions patch bump, main requires Self-test required -> auto',
         gha('actions/cache', 'patch', 'v6.1.0', 'v6.1.1'), ap('actions/cache', 'v6.1.0', 'v6.1.1'),
         rules_with, {}, 'auto_merge', 'all_conditions_met'),
        ('K3 the same PR against today\'s ruleset -> human (fail closed)',
         gha('actions/cache', 'patch', 'v6.1.0', 'v6.1.1'), ap('actions/cache', 'v6.1.0', 'v6.1.1'),
         rules_today, {}, 'human_review', 'scan_gate_not_required'),
        ('K3 setup-java v5.7.0 -> v6.2.0 (PR #5) -> human',
         gha('actions/setup-java', 'major', 'v5.7.0', 'v6.2.0'),
         ap('actions/setup-java', 'v5.7.0', 'v6.2.0', '.github/actions/sast-java/action.yml'),
         rules_with, {}, 'human_review', 'major_update'),
        ('K3 azure/login minor -> human', gha('azure/login', 'minor', 'v3.1.0', 'v3.2.0'),
         ap('azure/login', 'v3.1.0', 'v3.2.0'), rules_with, {}, 'human_review', 'critical_package'),
        ('K3 codeql-action/upload-sarif minor -> human',
         gha('github/codeql-action/upload-sarif', 'minor', 'v4.1.0', 'v4.2.0'),
         ap('github/codeql-action/upload-sarif', 'v4.1.0', 'v4.2.0'), rules_with, {},
         'human_review', 'critical_package'),
        ('K3 azurerm provider in infra/feed-mirrors -> human',
         [T.dep('hashicorp/azurerm', 'minor', '4.20.0', '4.21.0', eco='terraform', dtype='direct:production')],
         [T.f('infra/feed-mirrors/.terraform.lock.hcl'), T.f('infra/feed-mirrors/versions.tf')],
         rules_with, {}, 'human_review', 'critical_ecosystem'),
        ('K3 busybox in a deploy probe -> human',
         [T.dep('busybox', 'patch', '1.36.1', '1.36.2', eco='docker', dtype='direct:production')],
         [T.f('tests/fixtures/deploy-probe/healthy-a/Dockerfile')], rules_with, {},
         'human_review', 'critical_ecosystem'),
        ('K3 a pin bump inside this caller -> human',
         gha('actions/cache', 'patch', 'v6.1.0', 'v6.1.1'), ap('actions/cache', 'v6.1.0', 'v6.1.1', CALLER_REL),
         rules_with, {}, 'human_review', 'triage_chain'),
        ('K3 a fixture package -> close',
         [T.dep('requests', 'minor', '2.19.1', '2.33.0', eco='pip')],
         [T.f('tests/consumer-fixture/clean/requirements.txt')], rules_with, {}, 'close', 'excluded_path'),
        ('K3 counter-case: the caller\'s required_checks emptied -> human',
         gha('actions/cache', 'patch', 'v6.1.0', 'v6.1.1'), ap('actions/cache', 'v6.1.0', 'v6.1.1'),
         rules_with, {'required_checks': ''}, 'human_review', 'scan_gate_unnamed'),
    ]
    root_work = tempfile.mkdtemp(prefix='kit-triage-')
    try:
        for label, deps, files, rules, override, want, rule in cases:
            work = tempfile.mkdtemp(dir=root_work)
            ws = os.path.join(work, 'ws')
            os.makedirs(ws)
            c = T.case(label, deps, files=files, want=want, rule=rule, branch=T.UNPROTECTED, rules=rules)
            fix = T.setup_fixture(work, c)
            shims = os.path.join(work, 'bin')
            H.shim(shims, 'gh', T.GH_SHIM)
            env = {'RUNNER_TEMP': ws, 'FIX': fix, 'GH_LOG': os.path.join(work, 'gh.log'), 'FILES_RC': '0'}
            ctx = T.ctx_for(c, dict(inputs, **override))
            ctx['runner.temp'] = ws
            ctx['github.repository'] = KIT_REPO
            ctx['github.workflow_ref'] = KIT_CALLER_REF
            ctx['github.event.pull_request.html_url'] = 'https://github.com/%s/pull/42' % KIT_REPO
            r1 = H.run(bash, ev_step, ctx, ws, shim_dir=shims, extra_env=env)
            r2 = H.run(bash, de_step, ctx, ws, shim_dir=shims, extra_env=env)
            out = r2['outputs']
            got = (out.get('action'), out.get('rule'))
            check(r1['rc'] == 0 and r2['rc'] == 0 and got == (want, rule),
                  '%s (got %s / %s)' % (label, got[0], got[1]))
    finally:
        shutil.rmtree(root_work, ignore_errors=True)
    return 0


def main():
    if not os.path.isfile(CALLER):
        print('FAIL: %s does not exist -- this repository does not run its own Dependabot triage' % CALLER_REL)
        return 1
    doc = yaml.safe_load(io.open(CALLER, encoding='utf-8'))
    job = k1(doc)
    w = k2(job)
    if k3(w) == 2:
        return 2
    if FAILS:
        print('FAIL: %d check(s) -- the kit does not run the owner\'s Dependabot strategy as stated.' % len(FAILS))
        return 1
    print('PASS: the kit triages its own Dependabot PRs: safe patch/minor pins auto-merge behind '
          '`Self-test required`; majors, protected actions, infra and the triage chain go to a human; '
          'the fixture is closed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
