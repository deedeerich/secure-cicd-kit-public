#!/usr/bin/env python3
"""A dispatched run is paired by its correlation id, never by "the latest run on the branch" (item 11).

WHY THIS EXISTS (a defect found by an external review, 2026-11-06)
    consumer-path-test.yml dispatched the negative workflow and then took the LATEST run of it on the
    branch. Another person's dispatch, or a scheduled run, of the same workflow on that branch can be
    the latest; a green pre-flight could then rest on someone else's negative run. Now every dispatch
    passes a unique correlation id as an input, the dispatched workflow carries it in its run-name, and
    the run is selected ONLY by that id -- exactly one match, read back, or NOT_ESTABLISHED. The same
    rule holds in the kit API client (scripts/kit_api.py _find_run) and the cost tool
    (scripts/measure_cost.py dispatch).

WHAT IT PROVES
  STRUCTURE
    S1  every copy of the `kit dispatch correlated` block in the workflows is byte-identical, and every
        `gh workflow run` in a workflow goes through it
    S2  no workflow selects a run by `--limit 1` / "latest"; the negative workflow takes a
        correlation_id input and puts it, in brackets, in its run-name
  POSITIVE
    P1  with a concurrent DECOY (another person's newer negative run, which failed as a negative
        should), assert-seeded-blocks and assert-php-blocks pair THEIR OWN runs and pass
    P2  the kit API client finds the one run named for its correlation id among others
    P3  the cost tool pairs the one run carrying its id
  NEGATIVE
    N1  the decoy's id is never accepted: a run whose title lacks our id -> NOT_ESTABLISHED, the job fails
    N2  two runs carrying the same id -> NOT_ESTABLISHED (never the first or the newest)
    N4  the matched run must read back as a dispatch on this ref carrying the id, or it is refused
    N3  the kit API client and the cost tool answer NOT_ESTABLISHED for two runs with one id
  MUTANTS
    M1  the old "latest run" selection, put back into the shipped step, pairs the DECOY (the defect is real)
    M2  a selection that ignores the id (`select(true)`) is caught: NOT_ESTABLISHED, the job fails

EXIT 0 all hold   1 any does not   2 bash, jq or PyYAML unavailable
"""
import glob
import io
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

FAILS = []
BEGIN, END = '# >>> kit dispatch correlated', '# <<< kit dispatch correlated'
OLD_LATEST = '''before=$(gh run list --workflow=consumer-path-negative.yml --branch "$REF" \\
                     --limit 1 --json databaseId --jq '.[0].databaseId // 0')
          gh workflow run consumer-path-negative.yml --ref "$REF"
          rid=0
          for _ in $(seq 1 20); do
            sleep 10
            rid=$(gh run list --workflow=consumer-path-negative.yml --branch "$REF" \\
                    --limit 1 --json databaseId --jq '.[0].databaseId // 0')
            [ "$rid" != "$before" ] && [ "$rid" != "0" ] && break
          done
'''


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[-600:]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def blocks(text):
    out, pos = [], 0
    while True:
        i = text.find(BEGIN, pos)
        if i < 0:
            return out
        j = text.find(END, i)
        out.append('\n'.join(ln.strip() for ln in text[i:j].splitlines()))
        pos = j + 1


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    import prove_bootstrap_failure as pbf
    import prove_consumer_path_preflight as CP
    bash, why = pbf.usable_bash()
    if not bash or not shutil.which('jq'):
        print('UNKNOWN: bash or jq unavailable (%s)' % why)
        return 2
    print('Dispatch correlation (item 11):')

    # S1 / S2
    copies, dispatch_lines, latest = [], [], []
    for p in sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml')) +
                    glob.glob(os.path.join(ROOT, '.github', 'actions', '*', 'action.yml'))):
        t = io.open(p, encoding='utf-8').read()
        copies += blocks(t)
        for n, ln in enumerate(t.splitlines(), 1):
            s = ln.strip()
            if s.startswith('gh workflow run '):
                dispatch_lines.append('%s:%d' % (os.path.basename(p), n))
            if 'gh run list' in s and re.search(r'--limit 1(?![0-9])', s):
                latest.append('%s:%d' % (os.path.basename(p), n))
    # SOURCE-ONLY in an exported copy (2026-11-06, public run 42317591967): the dispatch block lives in
    # consumer-path-test.yml, which the neutral export withholds. S1's count and P1/N1/N2/N4/M1/M2 (which run
    # that workflow's jobs) say so by name; S2 and the kit API client and cost tool cases still run.
    cpt_withheld = CP.copy_lacks_cpt('S1/P1/N1/N2/N4/M1/M2')
    if not cpt_withheld:
        check(len(copies) >= 2 and len(set(copies)) == 1, 'S1 %d copies of the dispatch block, all identical' % len(copies))
    check(len(dispatch_lines) == len(copies), 'S1 every `gh workflow run` is inside the block (%s)' % dispatch_lines)
    check(not latest, 'S2 no workflow selects a run by --limit 1 (%s)' % latest)
    neg = yaml.safe_load(io.open(os.path.join(ROOT, '.github', 'workflows', 'consumer-path-negative.yml'), encoding='utf-8'))
    on = neg.get('on', neg.get(True)) or {}
    check('correlation_id' in ((on.get('workflow_dispatch') or {}).get('inputs') or {}) and
          '[${{ inputs.correlation_id' in str(neg.get('run-name', '')),
          'S2 the negative workflow takes correlation_id and carries it, in brackets, in its run-name')

    jobs = {} if cpt_withheld else CP.load_cpt()['jobs']
    states = '{"bandit":"PASS"}'
    ctx = {'github.token': 'ghs_job_token_placeholder', 'github.repository': CP.REPO, 'github.run_id': '777',
           'github.ref_name': 'main', 'needs.clean.result': 'success', 'needs.multi.result': 'success',
           'needs.clean.outputs.scanner_states': states, 'needs.multi.outputs.scanner_states': states,
           'needs.clean.outputs.routing_result': 'PROCEED_WITH_ADVISORY',
           'needs.multi.outputs.routing_result': 'PROCEED_WITH_ADVISORY'}

    def run(job, env, mutate=None):
        w = CP.World(bash)
        try:
            CP.seed_artifacts(w)
            j = jobs[job]
            if mutate:
                j = dict(j, steps=[dict(s, run=mutate(s['run'])) if 'run' in s else s for s in j['steps']])
            try:
                rc, log, outs = w.run_job(j, ctx, env)
            except KeyError as e:
                rc, log, outs = 99, str(e), {}
            return rc, log
        finally:
            w.close()

    if not cpt_withheld:
        # P1: a concurrent decoy (newer, failed) is ignored; our own run is paired.
        rc, log = run('assert-seeded-blocks', {'stub_decoy': '1'})
        check(rc == 0 and re.search(r'negative run: 101 \(paired by its correlation id\)', log) and
              'Negative control passed' in log, 'P1 with a decoy, the full negative pairs ITS run (101, not the decoy 102)', log)
        rc, log = run('assert-php-blocks', {'stub_decoy': '1'})
        check(rc == 0 and 'PHP-only negative run: 101 (paired' in log, 'P1 with a decoy, the PHP negative pairs ITS run', log)
        # N1: our run never shows our id -> NOT_ESTABLISHED.
        rc, log = run('assert-seeded-blocks', {'stub_nomatch': '1', 'stub_decoy': '1'})
        check(rc != 0 and 'NOT_ESTABLISHED' in log and 'Negative control passed' not in log,
              'N1 no run carries our id (only a decoy with its own): NOT_ESTABLISHED, the job fails', log)
        # N2: two runs carry the same id.
        rc, log = run('assert-seeded-blocks', {'stub_dupe': '1'})
        check(rc != 0 and re.search(r'NOT_ESTABLISHED::2 runs', log), 'N2 two runs with one id: NOT_ESTABLISHED', log)
        # N4: the run listed with our id reads back as something else (not a dispatch): refused.
        rc, log = run('assert-seeded-blocks', {'stub_view_event': 'schedule'})
        check(rc != 0 and 'did not read back as the dispatched run' in log, 'N4 a run that does not read back as our dispatch is refused', log)
        # M1: the old "latest run" selection pairs the decoy.
        call = re.compile(r'dispatch_correlated consumer-path-negative\.yml "\$REF" "[^"]*full[^"]*" \|\| exit 1\n(\s*)rid="\$DC_RID"\n')

        def to_latest(body):
            return call.sub(lambda m: OLD_LATEST, body) if call.search(body) else body
        rc, log = run('assert-seeded-blocks', {'stub_decoy': '1'}, to_latest)
        check('negative run: 102' in log or ('rid' in log and '102' in log),
              'M1 the old "latest run" code, under the same decoy, pairs the DECOY 102 (the defect is real)', log)
        # M2: the selection ignores the id.

        def ignore_id(body):
            return body.replace('select(.displayTitle | contains(\\"[$cid]\\"))', 'select(true)')
        rc, log = run('assert-seeded-blocks', {'stub_decoy': '1'}, ignore_id)
        check(rc != 0 and 'NOT_ESTABLISHED' in log, 'M2 a selection that ignores the id is caught (NOT_ESTABLISHED)', log)

    # P2/N3 the kit API client
    import kit_api as KA

    class Client(object):
        def __init__(self, runs):
            self.runs = runs

        def get(self, path):
            return 200, {'workflow_runs': self.runs}, {}, ''
    cid = 'kapi-20261106T000000Z-0123456789ab'
    mine = {'id': 5, 'display_title': KA.run_title(cid), 'status': 'completed'}
    decoy = {'id': 6, 'display_title': KA.run_title('kapi-20261106T000000Z-ffffffffffff'), 'status': 'completed'}
    r, why = KA._find_run(Client([decoy, mine]), 'o/r', cid, 'kit-api.yml')
    check(r is mine and not why, 'P2 the kit API client finds its own run among others')
    r, why = KA._find_run(Client([dict(mine, id=7), mine]), 'o/r', cid, 'kit-api.yml')
    check(r is None and why.startswith('NOT_ESTABLISHED'), 'N3 the kit API client: two runs with one id -> NOT_ESTABLISHED')
    # P3/N3 the cost tool
    import measure_cost as MC
    rows = [{'databaseId': 9, 'displayTitle': 'security [cost-x-1]'}, {'databaseId': 10, 'displayTitle': 'security [other]'}]
    check(MC.match_correlated(rows, 'cost-x-1') == (9, ''), 'P3 the cost tool pairs the run carrying its id')
    rid, why = MC.match_correlated(rows + [{'databaseId': 11, 'displayTitle': 'x [cost-x-1]'}], 'cost-x-1')
    check(rid is None and why.startswith('NOT_ESTABLISHED'), 'N3 the cost tool: two runs with one id -> NOT_ESTABLISHED')
    rid, why = MC.match_correlated(rows, 'cost-x-12')
    check(rid is None, 'N1 the cost tool never accepts a different id (cost-x-1 is not cost-x-12)')

    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: every dispatched run is paired by its own correlation id, or the answer is NOT_ESTABLISHED.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
