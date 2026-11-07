#!/usr/bin/env python3
"""The external findings workflow pulls read-only and submits only behind the review gate (owner, 2026-11-06).

Runs .github/workflows/reusable-external-findings.yml's steps AS SHIPPED (tests/_step_harness.py): the
pull step against the stand-in SonarQube of tests/prove_external_findings_pull.py, and the submit step
against a `gh` shim that records each dispatch.

  POSITIVE
    W1  the pull step: SOURCE_PULLED, the item count as an output, the summary written, batches cut for a
        review id with their evidence hashes
    W2  the submit step sends each batch, unchanged, as a tickets.submit request the kit's own intake
        accepts, with an idempotency key derived from the evidence hash, to the kit API workflow
  NEGATIVE
    W3  a refused pull (bad token) fails the step with its named state, never "no findings"
    W4  the token is masked before anything runs, and appears nowhere else in the log
    W5  a batch cut for another review is refused before anything is sent; no batches -> fails
    W6  structure: the pull job reads only (contents read); submit waits in the review environment and
        holds actions write only for the dispatch; top-level permissions {}; no expression inside a run:
        block; the secrets reach the script only through env:; the callers grant exactly what the jobs ask

EXIT 0 all hold   1 any does not   2 bash or PyYAML unavailable
"""
import io
import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML unavailable.')
    sys.exit(2)

import prove_external_findings_pull as PF  # noqa: E402
import _step_harness as H  # noqa: E402

WF = '.github/workflows/reusable-external-findings.yml'
FAILS = []
GH_SHIM = r'''
printf '%s\n' "$*" >> "$GH_LOG"
if [ "$1 $2" = "workflow run" ]; then cat >> "$GH_STDIN"; printf '\n' >> "$GH_STDIN"; exit "${DISPATCH_RC:-0}"; fi
exit 0
'''


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[-500:]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def main():
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    doc = yaml.safe_load(io.open(os.path.join(ROOT, WF), encoding='utf-8'))
    jobs = doc['jobs']
    print('External findings workflow (%s):' % WF)

    # W6 structure
    check(doc.get('permissions') == {}, 'W6 top-level permissions: {}')
    check(jobs['pull'].get('permissions') == {'contents': 'read'}, 'W6 the pull job reads only')
    check(jobs['submit'].get('permissions') == {'contents': 'read', 'actions': 'write'} and
          '${{ inputs.review_environment }}' in str(jobs['submit'].get('environment')),
          'W6 submit waits in the review environment, with actions write for the dispatch only')
    runs = [s for j in jobs.values() for s in j.get('steps') or [] if 'run' in s]
    check(not [s.get('name') for s in runs if '${{' in s['run']], 'W6 no expression inside a run: block')
    check(all('secrets.' in str(v) for s in runs for k, v in (s.get('env') or {}).items()
              if k in ('SONAR_TOKEN', 'AIKIDO_CLIENT_ID', 'AIKIDO_CLIENT_SECRET')),
          'W6 the secrets reach the script only through env:')
    for rel in ('templates/external-findings.yml', '.github/workflows/external-findings.yml'):
        c = yaml.safe_load(io.open(os.path.join(ROOT, rel), encoding='utf-8'))
        calls = [j for j in c['jobs'].values() if 'reusable-external-findings.yml' in str(j.get('uses', ''))]
        check(calls and all(j.get('permissions') == {'contents': 'read', 'actions': 'write'} for j in calls) and
              c.get('permissions') == {}, 'W6 %s grants exactly what the jobs ask' % rel)

    pull = dict(next(s for s in jobs['pull']['steps'] if s.get('id') == 'pull'))
    pull['_job_env'] = {}
    srv = HTTPServer(('127.0.0.1', 0), PF.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host = 'http://127.0.0.1:%d' % srv.server_address[1]
    work = tempfile.mkdtemp(prefix='efw-')
    try:
        def run_pull(token, review=''):
            ws = tempfile.mkdtemp(dir=work)
            for d in ('scripts', 'api'):
                shutil.copytree(os.path.join(ROOT, d), os.path.join(ws, d))
            rt = tempfile.mkdtemp(dir=work)
            ctx = {'inputs.source': 'sonar', 'secrets.SONAR_TOKEN': token, 'secrets.SONAR_HOST_URL': host,
                   'inputs.sonar_organization': 'example-org', 'inputs.sonar_projects': 'proj-a',
                   'inputs.repo_map': json.dumps({'proj-a': 'example-org/app-a'}), 'inputs.environment_label': 'code',
                   'inputs.review_id': review, 'inputs.aikido_api_base': '', 'secrets.AIKIDO_CLIENT_ID': '',
                   'secrets.AIKIDO_CLIENT_SECRET': ''}
            r = H.run(bash, pull, ctx, ws, extra_env={'RUNNER_TEMP': rt})
            return r, rt
        r, rt = run_pull(PF.SONAR_TOKEN, review='REV-2026-11-06')
        check(r['rc'] == 0 and r['outputs'].get('state') == 'SOURCE_PULLED' and r['outputs'].get('items') == '5'
              and 'External findings: sonar -- SOURCE_PULLED' in r['summary'],
              'W1 the pull step: SOURCE_PULLED, 5 items, the summary written', r['log'])
        bdir = os.path.join(rt, 'external-findings', 'batches')
        batches = sorted(os.listdir(bdir)) if os.path.isdir(bdir) else []
        check(batches == ['batch-001.params.json'] and 'evidence_sha256' in r['summary'],
              'W1 a batch cut for the review, its evidence hash in the summary', batches)
        lines = [ln for ln in r['log'].splitlines() if PF.SONAR_TOKEN in ln]
        check(all(ln.startswith('::add-mask::') for ln in lines) and lines,
              'W4 the token is masked first and appears nowhere else in the log', lines)
        r2, _ = run_pull('squ_wrong')
        check(r2['rc'] == 1 and r2['outputs'].get('state') == 'SOURCE_AUTH_REFUSED' and 'not \\"no findings\\"' not in r2['log']
              and 'this is not "no findings"' in r2['log'], 'W3 a bad token fails the step, named, never "no findings"', r2['log'])

        # W2 / W5 the submit step
        sub = dict(next(s for s in jobs['submit']['steps'] if s.get('name', '').startswith('Send each batch')))
        sub['_job_env'] = {}

        def run_submit(review, make_batches=True):
            ws = tempfile.mkdtemp(dir=work)
            for d in ('scripts', 'api'):
                shutil.copytree(os.path.join(ROOT, d), os.path.join(ws, d))
            rt2 = tempfile.mkdtemp(dir=work)
            if make_batches:
                shutil.copytree(os.path.join(rt, 'external-findings'), os.path.join(rt2, 'external-findings'))
            shims = os.path.join(work, 'bin-%d' % len(os.listdir(work)))
            H.shim(shims, 'gh', GH_SHIM)
            log, stdin = os.path.join(rt2, 'gh.log'), os.path.join(rt2, 'gh.stdin')
            io.open(log, 'w').close()
            io.open(stdin, 'w').close()
            ctx = {'github.token': 't', 'inputs.review_id': review, 'inputs.from_run_id': '4242',
                   'inputs.kit_api_workflow': 'kit-api.yml', 'github.event.repository.default_branch': 'main'}
            res = H.run(bash, sub, ctx, ws, shim_dir=shims, extra_env={'RUNNER_TEMP': rt2, 'GH_LOG': log, 'GH_STDIN': stdin, 'GITHUB_REPOSITORY': 'example-org/kit-host', 'GITHUB_SERVER_URL': 'https://example.ghe.com'})
            return res, io.open(log).read(), [json.loads(x) for x in io.open(stdin).read().splitlines() if x.strip()]
        res, glog, sent = run_submit('REV-2026-11-06')
        import kit_api as KA
        import ticket_templates as TT
        ok = res['rc'] == 0 and len(sent) == 1 and 'workflow run kit-api.yml --ref main --json' in glog
        if ok:
            req = json.loads(sent[0]['request'])
            params = json.load(io.open(os.path.join(rt, 'external-findings', 'batches', 'batch-001.params.json')))
            ok = (KA.check_request(req) is None and req['operation'] == 'tickets.submit' and req['params'] == params and
                  sent[0]['idempotency_key'] == 'xf-' + TT.evidence_set_sha256(params)[:40])
        check(ok, 'W2 each batch is sent unchanged as a valid tickets.submit, keyed by its evidence hash', res['log'] + glog)
        res, glog, sent = run_submit('REV-another')
        check(res['rc'] == 1 and not sent, 'W5 a batch cut for another review is refused, nothing sent', res['log'])
        res, glog, sent = run_submit('REV-2026-11-06', make_batches=False)
        check(res['rc'] == 1 and not sent, 'W5 no batches: the step fails, nothing sent', res['log'])
    finally:
        srv.shutdown()
        srv.server_close()
        shutil.rmtree(work, ignore_errors=True)
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: the intake pulls read-only, names a refusal, and submits only what the review concurred with.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
