#!/usr/bin/env python3
"""Dependabot PRs are kept current with no babysitting: one `@dependabot rebase` per base commit (2026-11-06).

WHY THIS EXISTS
    main requires branches to be up to date. A Dependabot PR that is only BEHIND (not conflicting)
    waited for a person to type `@dependabot rebase`. .github/workflows/reusable-dependabot-keep-current.yml
    types it. This proof runs that workflow's three steps AS SHIPPED (tests/_step_harness.py) under
    bash with a `gh` shim answering from fixtures, and holds the callers to it.

WHAT IT PROVES
  POSITIVE
    K1  a behind Dependabot PR gets exactly one comment, starting `@dependabot rebase`, carrying the
        base commit's marker
    K2  when main moves again, the same PR is asked again (once per BASE COMMIT, not once ever)
    K3  a conflicting Dependabot PR gets exactly one `@dependabot recreate`
    K4  a fixture Dependabot PR (tests/consumer-fixture/**) is CLOSED with the reason
  NEGATIVE
    N1  not twice: the same base commit with the marker already posted -> no comment
    N2  never a human PR: a behind PR by a person is not commented on, and is not even read further
    N3  a PR listed as Dependabot's on a branch that is not dependabot/* -> nothing
    N4  never a rebase on a fixture PR (it is closed instead)
    N5  a comment list that cannot be read posts nothing (an unread fact is not "not asked yet")
    N6  an open-PR list that cannot be read fails the step, and nothing is posted
    N7  recreate only once: the recreate marker present -> nothing
    N8  clean, draft and unknown states -> nothing
    N9  a non-numeric PR number in the list is never used in a command
  STRUCTURE
    S1  callable only; permissions {} at the top; ONE job holding exactly contents read +
        pull-requests write; it refuses pull_request and pull_request_target by its condition;
        nothing is checked out; no expression inside any run: block
    S2  the kit's caller and the template: push to main, a schedule and dispatch reach the job, which
        is guarded off pull_request_target; each grants exactly what the reusable's job requests

EXIT 0 all hold   1 any does not   2 bash, jq or PyYAML unavailable (UNKNOWN)
"""
import io
import json
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

WF_REL = '.github/workflows/reusable-dependabot-keep-current.yml'
CALLER_REL = '.github/workflows/dependabot-triage.yml'
TPL_REL = 'templates/dependabot-triage.yml'
REPO = 'example-org/example-app'
BASE1 = 'a' * 40
BASE2 = 'b' * 40
JOB_PERMS = {'contents': 'read', 'pull-requests': 'write'}
FAILS = []

GH_SHIM = r'''
printf '%s\n' "$*" >> "$GH_LOG"
case "$*" in
  "api repos/"*"/branches/"*)
    echo "$BASE_SHA" ;;
  "api --paginate repos/"*"/pulls?state=open"*)
    [ "${OPEN_RC:-0}" = 0 ] || { echo "HTTP 502" >&2; exit 1; }
    cat "$FIX/open.jsonl" ;;
  "api --paginate repos/"*"/pulls/"*"/files"*)
    n="$(printf '%s' "$*" | sed -E 's#.*/pulls/([0-9]+)/files.*#\1#')"
    cat "$FIX/files-$n.txt" 2>/dev/null ;;
  "api --paginate repos/"*"/issues/"*"/comments"*)
    [ "${COMMENTS_RC:-0}" = 0 ] || { echo "HTTP 500" >&2; exit 1; }
    n="$(printf '%s' "$*" | sed -E 's#.*/issues/([0-9]+)/comments.*#\1#')"
    cat "$FIX/comments-$n.jsonl" 2>/dev/null; exit 0 ;;
  "api repos/"*"/pulls/"*)
    n="$(printf '%s' "$*" | sed -E 's#.*/pulls/([0-9]+).*#\1#')"
    cat "$FIX/pr-$n.json" ;;
  "pr comment"*)
    shift 2 2>/dev/null; exit 0 ;;
  "pr close"*)
    exit 0 ;;
  *) exit 0 ;;
esac
'''


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def load(rel):
    return yaml.safe_load(io.open(os.path.join(ROOT, rel), encoding='utf-8'))


def on_of(doc):
    return doc.get('on', doc.get(True)) or {}


def pr(num, login='dependabot[bot]', head='dependabot/npm_and_yarn/lodash-4.17.21', state='behind', draft=False):
    return {'number': num, 'user': {'login': login}, 'head': {'ref': head}, 'mergeable_state': state,
            'draft': draft, 'html_url': 'https://github.com/%s/pull/%s' % (REPO, num)}


def scenario(H, bash, steps, prs, files=None, comments=None, base=BASE1, env_extra=None, listed=None):
    """Run the three steps. -> (rc of decide, gh log lines, decision.json, act outputs)."""
    work = tempfile.mkdtemp(prefix='dkc-')
    try:
        ws = os.path.join(work, 'ws'); os.makedirs(ws)
        fix = os.path.join(work, 'fix'); os.makedirs(fix)
        shims = os.path.join(work, 'bin')
        H.shim(shims, 'gh', GH_SHIM)
        log = os.path.join(work, 'gh.log')
        io.open(log, 'w').close()
        rows = listed if listed is not None else [
            {'number': p['number'], 'login': p['user']['login'], 'head_ref': p['head']['ref'], 'draft': p['draft']}
            for p in prs]
        with io.open(os.path.join(fix, 'open.jsonl'), 'w', encoding='utf-8', newline='\n') as fh:
            for r in rows:
                fh.write(json.dumps(r) + '\n')
        for p in prs:
            n = p['number']
            io.open(os.path.join(fix, 'pr-%s.json' % n), 'w', encoding='utf-8', newline='\n').write(json.dumps(p))
            io.open(os.path.join(fix, 'files-%s.txt' % n), 'w', encoding='utf-8', newline='\n').write(
                '\n'.join((files or {}).get(n, ['package-lock.json', 'package.json'])) + '\n')
            with io.open(os.path.join(fix, 'comments-%s.jsonl' % n), 'w', encoding='utf-8', newline='\n') as fh:
                for c in (comments or {}).get(n, []):
                    fh.write(json.dumps({'login': 'github-actions[bot]', 'body': c}) + '\n')
        env = {'RUNNER_TEMP': ws, 'FIX': fix, 'GH_LOG': log, 'BASE_SHA': base}
        env.update(env_extra or {})
        ctx = {'github.token': 't', 'github.repository': REPO, 'inputs.base_branch': 'main',
               'inputs.max_pull_requests': '50', 'inputs.excluded_paths': '',
               "secrets.COMMAND_TOKEN || github.token": 't', 'runner.temp': ws}
        r1 = H.run(bash, steps['evidence'], ctx, ws, shim_dir=shims, extra_env=env)
        r2 = H.run(bash, steps['decide'], ctx, ws, shim_dir=shims, extra_env=env)
        r3 = H.run(bash, steps['act'], ctx, ws, shim_dir=shims, extra_env=env) if r2['rc'] == 0 else {'outputs': {}, 'rc': None, 'log': ''}
        dec_p = os.path.join(ws, 'dependabot-keep-current', 'decision.json')
        dec = json.load(io.open(dec_p, encoding='utf-8')) if os.path.exists(dec_p) else {}
        lines = io.open(log, encoding='utf-8').read().splitlines()
        bodies = {}
        for f in os.listdir(os.path.join(ws, 'dependabot-keep-current')) if os.path.isdir(os.path.join(ws, 'dependabot-keep-current')) else []:
            m = re.match(r'body-(\d+)\.md$', f)
            if m:
                bodies[int(m.group(1))] = io.open(os.path.join(ws, 'dependabot-keep-current', f), encoding='utf-8').read()
        return {'rc1': r1['rc'], 'rc2': r2['rc'], 'rc3': r3['rc'], 'log': lines, 'dec': dec,
                'out': r3['outputs'], 'bodies': bodies, 'steplog': r2['log'] + r3['log']}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def posted(res, verb):
    return [ln for ln in res['log'] if ln.startswith('pr %s' % verb)]


def rule_of(res, n):
    for d in res['dec'].get('decisions', []):
        if d['number'] == n:
            return d['rule'], d['action']
    return None, None


def structure():
    raw = io.open(os.path.join(ROOT, WF_REL), encoding='utf-8').read()
    doc = load(WF_REL)
    on = on_of(doc)
    check(isinstance(on, dict) and set(on) == {'workflow_call'}, 'S1 the reusable is callable only')
    check(doc.get('permissions') == {}, 'S1 top-level permissions: {}')
    jobs = doc.get('jobs') or {}
    check(set(jobs) == {'keep-current'}, 'S1 exactly one job, keep-current (%r)' % sorted(jobs))
    job = jobs.get('keep-current') or {}
    check(job.get('permissions') == JOB_PERMS, 'S1 the job holds exactly contents read + pull-requests write (%r)'
          % job.get('permissions'))
    cond = str(job.get('if', ''))
    check("github.event_name != 'pull_request'" in cond and "github.event_name != 'pull_request_target'" in cond,
          'S1 the job refuses pull_request and pull_request_target by its condition')
    check('actions/checkout' not in raw.split('jobs:', 1)[1], 'S1 nothing is checked out')
    bad = [s.get('name') for s in job.get('steps') or [] if '${{' in str(s.get('run', ''))]
    check(not bad, 'S1 no expression inside any run: block', ', '.join(map(str, bad)))
    for rel in (CALLER_REL, TPL_REL):
        c = load(rel)
        con = on_of(c)
        check(isinstance(con, dict) and {'push', 'schedule', 'workflow_dispatch', 'pull_request_target'} <= set(con),
              'S2 %s: push, schedule and dispatch reach keep-current (triage keeps pull_request_target)' % rel)
        check(((con.get('push') or {}).get('branches') or []) == ['main'], 'S2 %s: the push is to main only' % rel)
        kc = [j for j in (c.get('jobs') or {}).values() if 'reusable-dependabot-keep-current.yml' in str(j.get('uses', ''))]
        check(len(kc) == 1, 'S2 %s calls keep-current exactly once' % rel)
        for j in kc:
            check(j.get('permissions') == JOB_PERMS, 'S2 %s grants exactly %r (%r)' % (rel, JOB_PERMS, j.get('permissions')))
            check("github.event_name != 'pull_request_target'" in str(j.get('if', '')),
                  'S2 %s: keep-current is guarded off pull_request_target' % rel)
        tri = [j for j in (c.get('jobs') or {}).values() if 'reusable-dependabot-triage.yml' in str(j.get('uses', ''))]
        check(len(tri) == 1 and "github.event.pull_request.user.login == 'dependabot[bot]'" in str(tri[0].get('if', '')),
              'S2 %s: the triage job still runs only for a Dependabot PR (a push carries none)' % rel)
    return job


def main():
    import _step_harness as H
    if not shutil.which('jq'):
        print('UNKNOWN: jq is not on PATH (the evidence step uses it, as the runner does).')
        return 2
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    print('Dependabot keep current (%s):' % WF_REL)
    job = structure()
    steps = {}
    for s in job.get('steps') or []:
        s = dict(s); s['_job_env'] = {}
        steps[s.get('id')] = s
    if set(steps) != {'evidence', 'decide', 'act'}:
        check(False, 'the job has the steps evidence, decide, act (%r)' % sorted(steps))
        return 1

    # K1 + N2 + N3 + N4 + N8 in one run: a realistic queue.
    prs = [pr(11), pr(12, login='a-person', head='feature/x'), pr(13, head='feature/spoof'),
           pr(14, head='dependabot/composer/tests/consumer-fixture/full/php/x'), pr(15, state='clean'),
           pr(16, draft=True), pr(17, state='unknown'), pr(18, state='dirty')]
    files = {14: ['tests/consumer-fixture/full/php/composer.lock']}
    res = scenario(H, bash, steps, prs, files=files)
    check(res['rc2'] == 0 and res['rc3'] == 0, 'the run completes', res['steplog'][-400:])
    comments = posted(res, 'comment')
    c11 = [ln for ln in comments if ln.startswith('pr comment 11 ')]
    check(len(c11) == 1, 'K1 a behind Dependabot PR gets exactly one comment (%d)' % len(c11))
    body = res['bodies'].get(11, '')
    check(body.startswith('@dependabot rebase\n') and ('kit-dependabot-keep-current:rebase:' + BASE1) in body,
          'K1 the comment starts `@dependabot rebase` and carries the base commit marker', body[:120])
    check(res['out'].get('asked_rebase') == '1', 'K1 the run reports one rebase asked (%r)' % res['out'].get('asked_rebase'))
    check(not any(ln.startswith('pr comment 12 ') for ln in comments) and
          not any('/pulls/12' in ln or '/issues/12' in ln for ln in res['log']),
          'N2 a human PR is never commented on, and not even read further')
    check(not any(ln.startswith('pr comment 13 ') for ln in comments) and rule_of(res, 13)[0] == 'not_dependabot',
          'N3 a Dependabot-listed PR on a non-dependabot/* branch gets nothing (not_dependabot)')
    check(rule_of(res, 14) == ('excluded_path', 'close') and any(ln.startswith('pr close 14 ') for ln in res['log']),
          'K4 a fixture Dependabot PR is closed with the reason')
    check(not any(ln.startswith('pr comment 14 ') for ln in comments), 'N4 a fixture PR is never asked to rebase')
    for n, want in ((15, 'up_to_date'), (16, 'draft'), (17, 'not_actionable_unknown')):
        check(rule_of(res, n) == (want, 'none') and not any(ln.startswith('pr comment %d ' % n) for ln in comments),
              'N8 PR %d gets nothing (%s)' % (n, want))
    c18 = [ln for ln in comments if ln.startswith('pr comment 18 ')]
    check(len(c18) == 1 and res['bodies'].get(18, '').startswith('@dependabot recreate\n'),
          'K3 a conflicting Dependabot PR gets exactly one `@dependabot recreate`')

    # N1: same base, marker already there -> nothing.
    mark = '@dependabot rebase\n\n<!-- kit-dependabot-keep-current:rebase:%s -->' % BASE1
    res = scenario(H, bash, steps, [pr(11)], comments={11: [mark]})
    check(not posted(res, 'comment') and rule_of(res, 11)[0] == 'already_asked',
          'N1 not twice: the same base commit, already asked -> no comment')
    # K2: main moved -> asked again.
    res = scenario(H, bash, steps, [pr(11)], comments={11: [mark]}, base=BASE2)
    check(len(posted(res, 'comment')) == 1 and ('rebase:' + BASE2) in res['bodies'].get(11, ''),
          'K2 main moved: asked again, with the new base commit marker')
    # N7: recreate once.
    res = scenario(H, bash, steps, [pr(18, state='dirty')],
                   comments={18: ['@dependabot recreate\n\n<!-- kit-dependabot-keep-current:recreate -->']})
    check(not posted(res, 'comment') and rule_of(res, 18)[0] == 'recreate_already_asked',
          'N7 recreate is asked once per PR')
    # N5: comments unreadable.
    res = scenario(H, bash, steps, [pr(11)], env_extra={'COMMENTS_RC': '1'})
    check(not posted(res, 'comment') and rule_of(res, 11)[0] == 'comments_unreadable',
          'N5 an unreadable comment list posts nothing')
    # N6: open list unreadable.
    res = scenario(H, bash, steps, [pr(11)], env_extra={'OPEN_RC': '1'})
    check(res['rc2'] == 1 and not posted(res, 'comment'), 'N6 an unreadable PR list fails the step and posts nothing')
    # N9: a non-numeric number is never used.
    listed = [{'number': '11; touch /tmp/pwn', 'login': 'dependabot[bot]', 'head_ref': 'dependabot/x', 'draft': False}]
    res = scenario(H, bash, steps, [], listed=listed)
    check(not posted(res, 'comment') and not any('pwn' in ln for ln in res['log']),
          'N9 a non-numeric PR number is never used in a command')

    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: behind Dependabot PRs are asked to rebase once per base commit; human and fixture PRs never are.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
