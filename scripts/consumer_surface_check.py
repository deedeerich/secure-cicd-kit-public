#!/usr/bin/env python3
"""The consumer surface of Release 4, checked on the kit host before any repository is wired (2026-11-06).

WHY THIS EXISTS
    The owner: "Is the consumer path updated for the new changes?" The consumer path test proved the
    scan-and-gate chain; Release 4 (KDEC-035, KDEC-036, KDEC-037, the Jira host secret, the Dependabot
    strategy) changed what a CONSUMER must write and what the kit decides for it, and none of that was
    in the consumer path. This checks, on the host the consumer path runs on, that the starter
    templates a consumer copies and the kit's own decision code agree with Release 4 -- each row
    PASS or FAIL, with the reason. It needs no Azure and no tracker: the decisions are run in-process
    on the kit's own functions, the templates are read as a consumer copies them.

ROWS (positive control first, then the refusal that proves the rule is live)
    R1 deploy callers    every template job calling a deploy reusable grants deployments: write and
                         pull-requests: read (a caller without them gets a startup failure)
    R2 five fields       wherever a template passes a weakening field to a kit reusable it passes all
                         five; an exception with all five and a listed approver is APPROVED; one with
                         no approver is NOT_APPROVED naming it; the requester as approver is SELF_APPROVED
    R3 readiness file    the shipped attestation (templates/zone-readiness.example.json, and the consumer
                         fixture's .kit/zone-readiness.json) is accepted for its environment while
                         unexpired; an expired one, or one for another environment, is refused
    R4 verdicts          a typed verdict with an AppSec reviewer, a reference and a recent date is a
                         MANUAL_REVIEW_VERDICT; without them, a TYPED_VERDICT; the template forwards the
                         three manual-review fields on its promotion
    R5 release record    the deploy writes a deployment (task kit-release-record, the record as payload)
                         and a status; an API that refuses is RELEASE_RECORD_NOT_KEPT, never "kept"
    R6 JIRA_HOST         every template that passes JIRA_HOST passes it as a SECRET, never a variable
    R7 kit API           a well-formed v1 request is accepted by the kit's intake; v0 is refused
                         API_VERSION_UNSUPPORTED; the template's API caller grants what the reusable asks
    R8 Dependabot        the triage template calls triage (pull_request_target) and keep-current (push,
                         schedule, dispatch) with exactly the permissions each asks for

USAGE  python3 scripts/consumer_surface_check.py [--root DIR] [--json FILE]
EXIT   0 every row PASS   1 a row FAILED   2 could not check (PyYAML missing)
"""
import argparse
import datetime
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIVE = ('weakening_reason', 'weakening_authority', 'weakening_approver', 'weakening_exception_ref',
        'weakening_expires')
DEPLOY_REUSABLES = ('reusable-deploy-containerapp.yml', 'reusable-deploy-appservice.yml',
                    'reusable-deploy-staticwebapp.yml')


def load_yaml(path):
    import yaml
    with io.open(path, encoding='utf-8') as fh:
        return yaml.safe_load(fh) or {}


def jobs_calling(doc, names):
    for jn, j in ((doc or {}).get('jobs') or {}).items():
        uses = str((j or {}).get('uses') or '')
        if any(n in uses for n in names):
            yield jn, j


def run(root):
    sys.path.insert(0, os.path.join(root, 'scripts'))
    import reviewer_signals as RS
    import kit_api as KA
    rows = []

    def row(rid, ok, why):
        rows.append({'row': rid, 'verdict': 'PASS' if ok else 'FAIL', 'why': why})

    tdir = os.path.join(root, 'templates')
    templates = {n: load_yaml(os.path.join(tdir, n)) for n in sorted(os.listdir(tdir)) if n.endswith('.yml')}

    # R1 deploy callers
    bad, seen = [], 0
    for n, doc in templates.items():
        for jn, j in jobs_calling(doc, DEPLOY_REUSABLES):
            seen += 1
            p = j.get('permissions') or {}
            if p.get('deployments') != 'write' or p.get('pull-requests') not in ('read', 'write'):
                bad.append('%s:%s' % (n, jn))
    row('R1', seen > 0 and not bad, 'checked %d deploy caller(s); %s' % (
        seen, ('missing deployments: write / pull-requests: read in ' + ', '.join(bad)) if bad else 'all grant both'))

    # R2 five fields
    partial = []
    for n, doc in templates.items():
        for jn, j in ((doc or {}).get('jobs') or {}).items():
            w = (j or {}).get('with') or {}
            have = [f for f in FIVE if f in w]
            if have and len(have) != len(FIVE):
                partial.append('%s:%s lacks %s' % (n, jn, ', '.join(f for f in FIVE if f not in w)))
    day = datetime.date.today()
    lists = {'release-approvers': ['approver-one']}
    good = {'reason': 'hotfix for an outage', 'authority': 'platform-owner', 'approver': 'approver-one',
            'exception_ref': 'CHG-1', 'expires': (day + datetime.timedelta(days=7)).isoformat()}
    c_ok = RS.weakening_check(good, ['requester-one'], set(), lists, day, 90)
    c_no = RS.weakening_check(dict(good, approver=''), ['requester-one'], set(), lists, day, 90)
    c_self = RS.weakening_check(dict(good, approver='requester-one'), ['requester-one'], set(), lists, day, 90)
    ok = (not partial and c_ok['state'] == RS.ATTRIBUTED and c_no['state'] == RS.NOT_APPROVED and
          'approver' in c_no['missing'] and c_self['state'] == RS.SELF_APPROVED)
    row('R2', ok, 'templates pass all five or none%s; all five -> %s; no approver -> %s (missing %s); '
        'self-approved -> %s' % ((' (NOT: ' + '; '.join(partial) + ')') if partial else '', c_ok['state'],
                                 c_no['state'], ', '.join(c_no['missing']), c_self['state']))

    # R3 readiness attestation file
    files = [os.path.join(tdir, 'zone-readiness.example.json'),
             os.path.join(root, 'tests', 'consumer-fixture', 'release4', '.kit', 'zone-readiness.json')]
    probs = []
    for f in files:
        if not os.path.exists(f):
            probs.append('%s is missing' % os.path.relpath(f, root))
            continue
        att = json.load(io.open(f, encoding='utf-8'))
        env = att['environment'][0] if isinstance(att.get('environment'), list) else att.get('environment')
        issued = datetime.date.fromisoformat(att['issued_on'])
        st, p = RS.attestation_ok(att, env, issued)
        if not st:
            probs.append('%s refused on its issue day: %s' % (os.path.relpath(f, root), '; '.join(p)))
        exp = datetime.date.fromisoformat(att['expires_on']) + datetime.timedelta(days=1)
        if RS.attestation_ok(att, env, exp)[0]:
            probs.append('%s accepted after it expired' % os.path.relpath(f, root))
        if RS.attestation_ok(att, 'some-other-environment', issued)[0]:
            probs.append('%s accepted for another environment' % os.path.relpath(f, root))
    row('R3', not probs, '; '.join(probs) or 'both attestations accepted for their environment, refused expired and elsewhere')

    # R4 typed and manual verdicts
    alists = {'appsec': ['appsec-reviewer']}
    m_ok = RS.judge_manual('appsec-reviewer', 'SEC-1', day.isoformat(), alists, 'appsec', {'requester-one'}, day)
    m_typed = RS.judge_manual('', '', '', alists, 'appsec', {'requester-one'}, day)
    m_self = RS.judge_manual('requester-one', 'SEC-1', day.isoformat(), {'appsec': ['requester-one']}, 'appsec',
                             {'requester-one'}, day)
    tpl = templates.get('build-deploy.yml') or {}
    fwd = [jn for jn, j in jobs_calling(tpl, DEPLOY_REUSABLES)
           if all(k in ((j.get('with') or {})) for k in ('manual_review_by', 'manual_review_ref', 'manual_review_date'))]
    row('R4', m_ok[0] and not m_typed[0] and not m_self[0] and bool(fwd),
        'attributed manual review accepted: %s; bare typed verdict accepted: %s; self-reviewed accepted: %s; '
        'template jobs forwarding the manual-review fields: %s' % (m_ok[0], m_typed[0], m_self[0], ', '.join(fwd) or 'none'))

    # R5 durable release record (the API recorded, then refusing)
    calls = []
    real_post = RS.api_post
    try:
        def recorder(path, body):
            calls.append((path, body))
            return {'id': 4242} if path == 'deployments' else {}
        RS.api_post = recorder
        st, ref, _ = RS.keep_deployment_record({'routing_result': 'PROCEED', 'deployment_outcome': 'DEPLOY_HEALTHY',
                                                'digest': 'sha256:' + 'a' * 64}, True, 'prod', 'https://app.example')
        kept = (st == RS.KEPT_DEPLOYMENT and ref == '4242' and calls and calls[0][0] == 'deployments' and
                calls[0][1].get('task') == 'kit-release-record' and calls[1][0] == 'deployments/4242/statuses' and
                calls[1][1].get('state') == 'success')

        def refuser(path, body):
            raise OSError('403')
        RS.api_post = refuser
        st2, _, _ = RS.keep_deployment_record({}, True, 'prod', '')
    finally:
        RS.api_post = real_post
    row('R5', kept and st2 == RS.NOT_KEPT, 'a healthy release keeps a deployment with task kit-release-record and a '
        'success status: %s; a refusing API -> %s' % (kept, st2))

    # R6 JIRA_HOST as a secret
    wrong, right = [], 0
    for n, doc in templates.items():
        for jn, j in ((doc or {}).get('jobs') or {}).items():
            for sect in ('secrets', 'with', 'env'):
                v = ((j or {}).get(sect) or {})
                if isinstance(v, dict) and 'JIRA_HOST' in v:
                    if sect == 'secrets' and 'secrets.JIRA_HOST' in str(v['JIRA_HOST']):
                        right += 1
                    else:
                        wrong.append('%s:%s (%s)' % (n, jn, sect))
    row('R6', right > 0 and not wrong, '%d template call(s) pass JIRA_HOST as a secret%s' % (
        right, ('; NOT as a secret: ' + ', '.join(wrong)) if wrong else ''))

    # R7 kit API
    req = KA.build_request('findings.search', {'run_id': 'latest'}, correlation_id='kapi-20261106T000000Z-0000000000aa')
    accepted = KA.check_request(req)
    refused = KA.check_request(dict(req, api_version='v0'))
    api_tpl = templates.get('kit-api.yml') or {}
    api_calls = list(jobs_calling(api_tpl, ('reusable-kit-api.yml',)))
    rdoc = load_yaml(os.path.join(root, '.github', 'workflows', 'reusable-kit-api.yml'))
    need = {}
    for j in (rdoc.get('jobs') or {}).values():
        for k, v in ((j or {}).get('permissions') or {}).items():
            if need.get(k) != 'write':
                need[k] = v
    short = [jn for jn, j in api_calls
             if any((j.get('permissions') or {}).get(k) not in (v, 'write') for k, v in need.items())]
    row('R7', accepted is None and (refused or {}).get('code') == KA.API_VERSION_UNSUPPORTED,
        'a v1 findings.search request: %s; a v0 request: %s' % ('accepted' if accepted is None else json.dumps(accepted),
                                                                 (refused or {}).get('code', 'ACCEPTED')))
    if short or not api_calls:
        rows[-1]['verdict'] = 'FAIL'
        rows[-1]['why'] += '; the template API caller(s) %s grant less than the reusable asks (%s)' % (
            ', '.join(short) or '(none found)', need)

    # R8 Dependabot triage caller
    dt = templates.get('dependabot-triage.yml') or {}
    on = dt.get('on', dt.get(True)) or {}
    tri = list(jobs_calling(dt, ('reusable-dependabot-triage.yml',)))
    kc = list(jobs_calling(dt, ('reusable-dependabot-keep-current.yml',)))
    ok = (isinstance(on, dict) and {'pull_request_target', 'push', 'schedule', 'workflow_dispatch'} <= set(on) and
          len(tri) == 1 and len(kc) == 1 and
          kc[0][1].get('permissions') == {'contents': 'read', 'pull-requests': 'write'} and
          "github.event_name != 'pull_request_target'" in str(kc[0][1].get('if', '')))
    row('R8', ok, 'triage on pull_request_target and keep-current on push/schedule/dispatch, least privilege: %s' % ok)
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description='Release 4 consumer surface check.')
    ap.add_argument('--root', default=os.path.dirname(HERE))
    ap.add_argument('--json')
    a = ap.parse_args(argv)
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML is required (python3 -m pip install pyyaml)')
        return 2
    rows = run(os.path.abspath(a.root))
    for r in rows:
        print('%-3s %-5s %s' % (r['row'], r['verdict'], r['why']))
    summ = os.environ.get('GITHUB_STEP_SUMMARY')
    if summ:
        with io.open(summ, 'a', encoding='utf-8') as fh:
            fh.write('### Release 4 consumer surface\n\n| row | verdict | why |\n|---|---|---|\n')
            for r in rows:
                fh.write('| %s | %s | %s |\n' % (r['row'], r['verdict'], r['why'].replace('|', '/')))
    if a.json:
        io.open(a.json, 'w', encoding='utf-8').write(json.dumps(rows, indent=1))
    failed = [r['row'] for r in rows if r['verdict'] != 'PASS']
    print('FAIL: %s' % ', '.join(failed) if failed else 'PASS: the Release 4 consumer surface holds (%d rows).' % len(rows))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
