#!/usr/bin/env python3
"""The hosted kit-harness pair never mints its token beside PR code, never reads a moving ref, and never reads an absent credential as a pass. NO NETWORK.

WHY (KDEC-052 item 9, KDEC-058)
    .github/workflows/kit-harness-pair.yml checks the evidence harness out with a read-only GitHub App token at
    the commit .github/harness-pair.json pins and runs tests/prove_kit_harness_pair.py. The owner has not
    created the App yet, so today the job's only honest outcome is HARNESS_LEG_NOT_RUN. This proves the
    decision (scripts/harness_pair_gate.py) and the workflow's shape offline.

WHAT IT PROVES
    G1  POSITIVE  a push to the default branch with the key, client id, OWNER/REPO and a 40-hex pin -> HARNESS_PAIR_RUN
                  with that commit, owner and repo; a dispatch from the default branch likewise
    G2  POSITIVE  run(): a checkout whose HEAD is the pin runs the pair proof (seam) and its rc decides (0 -> 0, 1 -> 1)
    N1  NEGATIVE  credential absent (no key; no client id) -> HARNESS_LEG_NOT_RUN / CREDENTIAL_ABSENT, run() exit 1,
                  an ::error annotation naming the state, and a step-summary line saying it is not a pass
    N2  NEGATIVE  pull_request, pull_request_target, a push to another branch -> EVENT_NOT_TRUSTED (no mint)
    N3  NEGATIVE  pin null -> PIN_NOT_SET; pin 'main', 'v1.2.3', 'HEAD', a 7-hex short SHA, an upper-case SHA
                  -> PIN_NOT_A_COMMIT
    N4  NEGATIVE  run(): the checkout's HEAD differs from the pin -> HARNESS_PIN_MISMATCH, the proof never runs;
                  no checkout -> HARNESS_CHECKOUT_MISSING
    N5  NEGATIVE  HARNESS_REPOSITORY empty, a URL, or HOST/OWNER/REPO -> HARNESS_REPOSITORY_NOT_SET
    N6  NEGATIVE  the real pin file today (null) -> not run, never a pass
    W1  the workflow: while the pin is null (setup not done) workflow_dispatch ONLY, so an unconfigured pair is
        not red on every push; once the pin names a commit, push(main) and workflow_dispatch only; never
        pull_request*; environment kit-harness-pair, the
        mint step gated on the plan, SHA-pinned create-github-app-token with permission-contents: read and NO other
        permission-*, repositories from the plan; the harness checkout uses ref = the plan's commit, the App token
        and persist-credentials: false; the last step runs always() and no step after the mint receives the token
        in env; no github.com / api.github.com literal (KDEC-027)
    MUTANTS
        gate_accepts_unpinned_ref   a decide() that takes any non-empty ref        -> N3 'main' runs under it: caught
        gate_trusts_pull_request    a decide() that adds pull_request to trusted   -> N2 runs under it: caught
        gate_absent_is_pass         a run() that returns 0 when not established    -> N1 passes under it: caught
        wf_pull_request_trigger     pull_request added to the workflow             -> W1 fails: caught
        wf_unpinned_ref             the harness checkout's ref set to main          -> W1 fails: caught
        wf_contents_write           permission-contents: write                     -> W1 fails: caught
        wf_token_in_env             the token handed to the run step's env         -> W1 fails: caught
        wf_push_before_setup        push(main) added while the pin is null          -> W1 fails: caught
        wf_dispatch_only_after_setup the pin set but push(main) not restored        -> W1 fails: caught

EXIT  0 all hold   1 any does not   2 could not be checked (PyYAML missing)
"""
import contextlib
import copy
import io
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import harness_pair_gate as g  # noqa: E402

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML required')
    sys.exit(2)

WF = os.path.join(ROOT, '.github', 'workflows', 'kit-harness-pair.yml')
SHA = 'a5ec659' + '0' * 33
FAILS = []


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)
    return bool(cond)


def env(**kw):
    base = {'EVENT': 'push', 'REF': 'refs/heads/main', 'DEFAULT_BRANCH': 'main', 'HAS_APP_KEY': 'true',
            'APP_CLIENT_ID': 'Iv23liExample', 'HARNESS_REPOSITORY': 'example-owner/evidence-harness'}
    base.update(kw)
    return base


def codes(d):
    return set(r.split(':')[0] for r in d['reasons'])


def captured(fn, *a, **kw):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = fn(*a, **kw)
    return rc, out.getvalue()


def wf_problems(doc, pin=None):
    """pin: the harness commit .github/harness-pair.json names (None until setup)."""
    bad = []
    on = doc.get('on', doc.get(True)) or {}
    if pin is None:
        if set(on) != {'workflow_dispatch'}:
            bad.append('W1 triggers are %s (want workflow_dispatch only until the pin is set: an unconfigured '
                       'pair would be red on every push)' % sorted(on))
    elif set(on) != {'push', 'workflow_dispatch'} or (on.get('push') or {}).get('branches') != ['main']:
        bad.append('W1 triggers are %s (the pin is set: want push: [main] and workflow_dispatch only)' % sorted(on))
    job = (doc.get('jobs') or {}).get('pair') or {}
    if job.get('environment') != 'kit-harness-pair':
        bad.append('W1 the job is not bound to the kit-harness-pair environment')
    steps = job.get('steps') or []
    mint = [s for s in steps if str(s.get('uses', '')).startswith('actions/create-github-app-token@')]
    co = [s for s in steps if str(s.get('uses', '')).startswith('actions/checkout@') and
          (s.get('with') or {}).get('path') == '_harness']
    if len(mint) != 1 or len(co) != 1:
        return bad + ['W1 want one mint step and one harness checkout, found %d / %d' % (len(mint), len(co))]
    m, c = mint[0], co[0]
    w = m.get('with') or {}
    sha = m['uses'].split('@', 1)[1]
    if len(sha) != 40 or any(ch not in '0123456789abcdef' for ch in sha):
        bad.append('W1 create-github-app-token is not SHA-pinned')
    if m.get('if') != "steps.plan.outputs.run == 'true'":
        bad.append('W1 the mint step is not gated on the plan')
    perms = dict((k, v) for k, v in w.items() if k.startswith('permission-'))
    if perms != {'permission-contents': 'read'}:
        bad.append('W1 the token asks for %s (want permission-contents: read only)' % perms)
    if w.get('repositories') != '${{ steps.plan.outputs.repo }}' or 'github-api-url' in w:
        bad.append('W1 the token is not scoped to the planned repository on the run host')
    cw = c.get('with') or {}
    if cw.get('ref') != '${{ steps.plan.outputs.commit }}':
        bad.append('W1 the harness checkout ref is %r, not the pinned commit' % cw.get('ref'))
    if cw.get('token') != '${{ steps.token.outputs.token }}' or cw.get('persist-credentials') is not False:
        bad.append('W1 the harness checkout does not use the App token with persist-credentials: false')
    if c.get('if') != "steps.plan.outputs.run == 'true'":
        bad.append('W1 the harness checkout is not gated on the plan')
    last = steps[-1]
    if last.get('if') != 'always()' or 'harness_pair_gate.py run' not in str(last.get('run')):
        bad.append('W1 the last step is not an always() harness_pair_gate.py run')
    for s in steps[steps.index(m) + 1:]:
        if 'steps.token.outputs.token' in str(s.get('env') or {}) or 'steps.token' in str(s.get('run') or ''):
            bad.append('W1 the token reaches a run step (%s)' % s.get('name'))
    text = yaml.safe_dump(doc)
    if 'api.github.com' in text or 'https://github.com' in text:
        bad.append('W1 a github.com literal (KDEC-027: the run host only)')
    return bad


def main():
    print('G positives')
    d = g.decide(env(), SHA)
    check(d['state'] == g.RUN and d['commit'] == SHA and d['owner'] == 'example-owner'
          and d['repo'] == 'evidence-harness', 'G1 a push to main, configured and pinned -> %s' % d['state'])
    d = g.decide(env(EVENT='workflow_dispatch'), SHA)
    check(d['state'] == g.RUN, 'G1 a dispatch from main -> %s' % d['state'])
    seen = []
    for want in (0, 1):
        rc, _ = captured(g.run, env(), SHA, ROOT, head=lambda r: SHA, proof=lambda r, w=want: seen.append(r) or w)
        check(rc == want and seen and seen[-1] == ROOT, 'G2 HEAD is the pin: the pair proof runs, its rc %d -> %d'
              % (want, rc))

    print('N negatives')
    for label, e in (('no key', env(HAS_APP_KEY='false')), ('no client id', env(APP_CLIENT_ID=''))):
        d = g.decide(e, SHA)
        rc, out = captured(g.run, e, SHA, ROOT, head=lambda r: SHA, proof=lambda r: 0)
        check(d['state'] == g.NOT_RUN and 'CREDENTIAL_ABSENT' in codes(d) and rc == 1
              and '::error title=HARNESS_LEG_NOT_RUN' in out,
              'N1 %s -> HARNESS_LEG_NOT_RUN / CREDENTIAL_ABSENT, exit %d, annotated' % (label, rc))
    fd, summ = tempfile.mkstemp(suffix='.md')
    os.close(fd)
    os.environ['GITHUB_STEP_SUMMARY'] = summ
    try:
        captured(g.run, env(HAS_APP_KEY='false'), SHA, ROOT)
        text = io.open(summ, encoding='utf-8').read()
    finally:
        del os.environ['GITHUB_STEP_SUMMARY']
        if os.path.exists(summ):
            os.remove(summ)
    check('HARNESS_LEG_NOT_RUN' in text and 'not a pass' in text, 'N1 the step summary names it and says it is not a pass')
    for ev, ref in (('pull_request', 'refs/pull/7/merge'), ('pull_request_target', 'refs/heads/main'),
                    ('push', 'refs/heads/feature'), ('workflow_dispatch', 'refs/heads/feature')):
        d = g.decide(env(EVENT=ev, REF=ref), SHA)
        check(d['state'] == g.NOT_RUN and 'EVENT_NOT_TRUSTED' in codes(d) and not d['commit'],
              'N2 %s on %s -> EVENT_NOT_TRUSTED, nothing planned to mint' % (ev, ref))
    d = g.decide(env(), None)
    check('PIN_NOT_SET' in codes(d) and d['state'] == g.NOT_RUN, 'N3 pin null -> PIN_NOT_SET')
    for bad in ('main', 'v1.2.3', 'HEAD', 'a5ec659', SHA.upper(), 'refs/heads/main'):
        d = g.decide(env(), bad)
        check('PIN_NOT_A_COMMIT' in codes(d) and d['state'] == g.NOT_RUN, 'N3 pin %r -> PIN_NOT_A_COMMIT' % bad)
    ran = []
    rc, out = captured(g.run, env(), SHA, ROOT, head=lambda r: 'b' * 40, proof=lambda r: ran.append(r) or 0)
    check(rc == 1 and not ran and 'HARNESS_PIN_MISMATCH' in out, 'N4 HEAD differs from the pin -> HARNESS_PIN_MISMATCH, '
          'the proof never ran')
    rc, out = captured(g.run, env(), SHA, os.path.join(ROOT, 'no-such-harness'), head=lambda r: SHA, proof=lambda r: 0)
    check(rc == 1 and 'HARNESS_CHECKOUT_MISSING' in out, 'N4 no checkout -> HARNESS_CHECKOUT_MISSING')
    for repo in ('', 'https://example.ghe.com/o/r', 'example.ghe.com/o/r', 'justaname'):
        d = g.decide(env(HARNESS_REPOSITORY=repo), SHA)
        check('HARNESS_REPOSITORY_NOT_SET' in codes(d), 'N5 repository %r -> HARNESS_REPOSITORY_NOT_SET' % repo)
    real = g.read_pin()
    rc, out = captured(g.run, env(), real, ROOT, head=lambda r: SHA, proof=lambda r: 0)
    check(rc == 1 and 'HARNESS_LEG_NOT_RUN' in out, 'N6 the real pin today (%r) -> not run, exit %d' % (real, rc))

    print('W the workflow')
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    probs = wf_problems(doc, real)
    check(not probs, 'W1 kit-harness-pair.yml holds every rule for pin %r %s' % (real, probs[:2]))

    print('MUTANTS (each must be caught)')
    real_decide, real_trusted = g.decide, g.TRUSTED_EVENTS

    def accepts_unpinned(e, pin):
        d = real_decide(e, SHA if pin else pin)
        return dict(d, commit=pin) if d['state'] == g.RUN else d
    d = accepts_unpinned(env(), 'main')
    check(d['state'] == g.RUN and 'PIN_NOT_A_COMMIT' in codes(real_decide(env(), 'main')),
          'mutant gate_accepts_unpinned_ref caught: it runs at %r, the real gate refuses' % d['commit'])
    g.TRUSTED_EVENTS = real_trusted + ('pull_request',)
    try:
        d = g.decide(env(EVENT='pull_request', REF='refs/heads/main'), SHA)
    finally:
        g.TRUSTED_EVENTS = real_trusted
    check(d['state'] == g.RUN and 'EVENT_NOT_TRUSTED' in codes(g.decide(env(EVENT='pull_request', REF='refs/heads/main'), SHA)),
          'mutant gate_trusts_pull_request caught: it would mint on pull_request, the real gate refuses')
    real_not_run = g.not_run
    g.not_run = lambda reasons: 0
    try:
        rc, _ = captured(g.run, env(HAS_APP_KEY='false'), SHA, ROOT, head=lambda r: SHA, proof=lambda r: 0)
    finally:
        g.not_run = real_not_run
    check(rc == 0, 'mutant gate_absent_is_pass caught: it exits 0 with no credential, the real gate exits 1 (N1)')
    job = lambda x: x['jobs']['pair']  # noqa: E731
    harness = lambda x: next(s for s in job(x)['steps'] if (s.get('with') or {}).get('path') == '_harness')  # noqa: E731
    mint = lambda x: next(s for s in job(x)['steps'] if 'create-github-app-token' in str(s.get('uses')))  # noqa: E731
    muts = {
        'wf_pull_request_trigger': lambda x: x.get('on', x.get(True)).update({'pull_request': None}),
        'wf_unpinned_ref': lambda x: harness(x)['with'].update({'ref': 'main'}),
        'wf_contents_write': lambda x: mint(x)['with'].update({'permission-contents': 'write'}),
        'wf_token_in_env': lambda x: job(x)['steps'][-1]['env'].update({'GH_TOKEN': '${{ steps.token.outputs.token }}'}),
    }
    for name, fn in sorted(muts.items()):
        m = copy.deepcopy(doc)
        fn(m)
        check(bool(wf_problems(m, real)), 'mutant %s caught: %s' % (name, (wf_problems(m, real) or ['NOT CAUGHT'])[0][:90]))
    # The trigger follows the setup state: each state's mutant is caught, and its correct form passes.
    dispatch_only = copy.deepcopy(doc)
    dispatch_only[('on' if 'on' in dispatch_only else True)] = {'workflow_dispatch': None}
    with_push = copy.deepcopy(doc)
    with_push[('on' if 'on' in with_push else True)] = {'push': {'branches': ['main']}, 'workflow_dispatch': None}
    check(not wf_problems(dispatch_only, None) and not wf_problems(with_push, SHA),
          'W1 the correct form for each state passes (dispatch-only at pin null; push+dispatch at a pin)')
    for name, m, pin in (('wf_push_before_setup', with_push, None), ('wf_dispatch_only_after_setup', dispatch_only, SHA)):
        check(bool(wf_problems(m, pin)), 'mutant %s caught: %s' % (name, (wf_problems(m, pin) or ['NOT CAUGHT'])[0][:90]))
    print('PASS' if not FAILS else 'FAIL: %d check(s) failed' % len(FAILS))
    return 1 if FAILS else 0


if __name__ == '__main__':
    sys.exit(main())
