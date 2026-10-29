#!/usr/bin/env python3
"""Ticketing, matured: the whole lifecycle of a finding's ticket, on every backend, with fakes.

(KDEC-024, lane L-TKT, owner 2026-10-23: "We need to finish and fully mature tickets and ticket
handling." Nothing below is left as future work.)

WHAT IT PROVES -- NO NETWORK: urlopen is the Replay of tests/prove_ticket_backends.py, driving its
STATEFUL Jira, Azure DevOps and GitHub stand-ins, so a ticket created in one run is there to be
found, closed, reopened and escalated in the next.

    T-19   the report's findings file reaches the reconciler: a record shaped as scan_report.py
           writes it (state, rule_id, canonical_path) is clustered, not withheld; a template
           caller runs the reconciler after the security job in the SAME run, from that job's
           evidence artifact, on push to the default branch only
    T-17   the clock runs on a schedule, as ONE small job (no guard job, no scan): lapsed
           dispositions reopen and SLA breaches escalate with no new scan
    T-09   a finding that clears is CLOSED (Done/Closed) with a comment citing the run and the
           commit that proved it absent -- only on positive evidence: the scanner that saw it
           ran, was established, and covered its file. Anything less is POTENTIALLY_ABSENT and
           closes nothing. A cleared finding that comes back is RECURRED, not `falsified`
    D5     NEW, RECURRED and REOPENED_BY_LAPSE end to end on Jira, Azure DevOps and GitHub; the
           reusable workflow wires every backend the script supports
    D4     one cluster key function for the kit (L48), byte-identical to the stamps already on
           live tickets; cross-scanner duplicates already ticketed separately are MERGED into the
           oldest ticket, which names every scanner; the absorbed ticket is closed as superseded
    FW-3a  a peer scanner of the same detection class that covered the file and did not report
           makes the cluster CONTESTED_ANCHORED, with a disagreement note and label, routed to a
           person once; differing severities are recorded and the worst taken, never averaged
    SLA    the due date comes from the register's numbers (sla_period_days); an overdue ticket
           is escalated once: a comment, a priority bump and a label
    LINK   the ticket names the run, the commit, file:line and the exception; the exception's
           resurfacing comment names the finding ticket back
    IDEM   re-running never duplicates; a run's calls are bounded by a budget, with backoff by
           default; an unreachable tracker is TICKETING_UNAVAILABLE, exit 3, never a silent pass,
           and the security gate does not wait for ticketing
    FW-3b  the correlation-triage skill exists

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import prove_ticket_backends as ptb  # noqa: E402  the fakes live there and are extended there

TEMPLATE = os.path.join(ROOT, 'templates', 'ticket-reconcile.yml')
REUSABLE = os.path.join(ROOT, '.github', 'workflows', 'reusable-ticket-reconcile.yml')
SKILL = os.path.join(ROOT, 'skills', 'tools', 'correlation-triage', 'SKILL.md')
JIRA_ENV = dict(ptb.JIRA_ENV, JIRA_TRANSITION_REOPEN='Reopen')
RUN1 = {'run_url': 'https://github.example/o/r/actions/runs/1001', 'commit': 'a' * 40}
RUN2 = {'run_url': 'https://github.example/o/r/actions/runs/1002', 'commit': 'b' * 40}
NUMBERS = {'sla_period_days': {'CRITICAL': 7, 'HIGH': 30, 'MEDIUM': 90, 'LOW': 180}}


def obs(scanner, rule, path, ident, aliases, job='deps-scan', severity='HIGH',
        subject='SOURCE_DEPENDENCY', fp='0123456789ab', line=3, state='FINGERPRINTED'):
    """One observation EXACTLY as scripts/scan_report.py observation_of() writes it."""
    return {'scanner': scanner, 'tool': scanner, 'scanner_version': '', 'rule_id': rule,
            'severity': severity, 'line': line, 'canonical_path': path,
            'finding_subject': subject, 'state': state, 'identity': ident, 'what': rule,
            'where': path, 'content': '', 'identity_scope': '', 'what_aliases': list(aliases),
            'cwe': '', 'reason': '', 'detail': '', 'fp': fp, 'job': job,
            'row_established': True}


def cov(**rows):
    """Coverage as the report records it: scanner -> its row. A value is True (established,
    complete), 'PARTIAL', or a dict overriding fields."""
    out = {}
    for name, v in rows.items():
        name = name.replace('_', '-')
        row = {'scanner': name, 'job': 'deps-scan', 'applicability': 'APPLICABLE',
               'execution': 'COMPLETE', 'gate': 'PASS', 'scope': '', 'established': True,
               'scanner_version': '0.56.1'}
        if v == 'PARTIAL':
            row['gate'] = 'PARTIAL'
        elif v is False:
            row.update(established=False, execution='FAILED', gate='FAILED')
        elif isinstance(v, dict):
            row.update(v)
        out[name] = row
    return out


def ctx(run=RUN1, coverage=None, numbers=None, exceptions=None):
    return dict(run, coverage=coverage, numbers=numbers, exceptions=exceptions or {})


# ── the three trackers, behind one shape ─────────────────────────────────────────────────

class Jira(object):
    name = 'jira'

    def __init__(self, rt):
        self.rt = rt
        self.r = ptb.install(ptb.Replay())
        self.t = ptb.JiraTracker(self.r)
        REPLAYS.append(self.r)

    def backend(self, **env):
        return ptb.backend(self.rt, dict(JIRA_ENV, **env))

    def tickets(self):
        return [i for i in self.t.issues.values() if i['type'] == 'Story']

    def closed(self, ref):
        return (self.t.status_of(ref).get('statusCategory') or {}).get('key') == 'done'

    def comments(self, ref):
        return [c for i, c in self.t.comments if str(i) == str(ref)]

    def labels(self, ref):
        return list(self.t.issues[str(ref)]['fields'].get('labels') or [])

    def priority(self, ref):
        return self.t.issues[str(ref)]['fields'].get('priority') or 'Medium'

    def body(self, ref):
        return ptb.adf_text(self.t.issues[str(ref)].get('description'))

    def close_by_hand(self, ref):
        self.t.issues[str(ref)]['fields']['status'] = {'name': 'Done',
                                                       'statusCategory': {'key': 'done'}}


class Azdo(object):
    name = 'azdo'

    def __init__(self, rt):
        self.rt = rt
        self.r = ptb.install(ptb.Replay())
        self.t = ptb.AzdoTracker(self.r)
        REPLAYS.append(self.r)

    def backend(self, **env):
        b = self.rt.AzureDevOps(**ptb.AZDO_KW)
        for k, v in env.items():
            setattr(b, k, v)
        return b

    def tickets(self):
        return [i for i in self.t.items.values() if i.get('type') == 'Issue']

    def closed(self, ref):
        return self.t.items[int(ref)]['fields'].get('System.State') == 'Done'

    def comments(self, ref):
        return [c for i, c in self.t.comments if str(i) == str(ref)]

    def labels(self, ref):
        return [x.strip() for x in str(self.t.items[int(ref)]['fields'].get('System.Tags') or '')
                .split(';') if x.strip()]

    def priority(self, ref):
        return self.t.items[int(ref)]['fields'].get('Microsoft.VSTS.Common.Priority')

    def body(self, ref):
        import html
        return html.unescape(str(self.t.items[int(ref)]['fields'].get('System.Description')))

    def close_by_hand(self, ref):
        self.t.items[int(ref)]['fields']['System.State'] = 'Done'


class GitHub(object):
    name = 'github'

    def __init__(self, rt):
        self.rt = rt
        self.r = ptb.install(ptb.Replay())
        self.t = ptb.GitHubTracker(self.r)
        REPLAYS.append(self.r)

    def backend(self, **env):
        return ptb.backend(self.rt, dict(ptb.GH_ENV, **env))

    def tickets(self):
        return [i for n, i in self.t.issues.items() if n != 7]

    def closed(self, ref):
        return self.t.issues[int(ref)]['state'] == 'closed'

    def comments(self, ref):
        return [c for i, c in self.t.comments if str(i) == str(ref)]

    def labels(self, ref):
        return [lb['name'] for lb in self.t.issues[int(ref)]['labels']]

    def priority(self, ref):
        return None

    def body(self, ref):
        return self.t.issues[int(ref)]['body']

    def close_by_hand(self, ref):
        self.t.issues[int(ref)]['state'] = 'closed'


TRACKERS = (Jira, Azdo, GitHub)
REPLAYS = []


def case_t12(rt, fails):
    """TC 5.2 / T-12 across the WHOLE lifecycle: no write any case above sent -- closure,
    supersede, reopen, escalation, labels, block updates -- set a due date, a disposition, an
    approver, an expiry, an SLA or a resolution field. Escalation raises priority and adds a
    label; it never writes a deadline."""
    writes = 0
    for r in REPLAYS:
        for q in r.requests:
            if q['method'] in ('PUT', 'PATCH') or (q['method'] == 'POST' and not re.search(
                    r'search/jql|wiql|workitemsbatch', q['url'])):
                writes += 1
                for n in ptb._field_names(q['json'], []):
                    if ptb.FORBIDDEN_FIELD.search(n):
                        fails.append('T-12: a lifecycle write set field %r (%s %s)'
                                     % (n, q['method'], q['url'][:80]))
    if writes < 50:
        fails.append('T-12: only %d lifecycle write(s) were observed, so nothing was checked'
                     % writes)


def run(rt, tracker, records, ledger, today, context, apply_changes=True, **env):
    clusters, withheld = rt.build_clusters(records)
    return rt.reconcile(clusters, withheld, tracker.backend(**env), ledger, apply_changes,
                        today=today, context=context)


def only_ref(ledger):
    refs = [e.get('ref') for e in ledger.values() if isinstance(e, dict) and e.get('ref')
            and not e.get('merged_into')]
    return refs[0] if len(refs) == 1 else None


# ── T-19 ─────────────────────────────────────────────────────────────────────────────────

def case_t19(rt, fails):
    # (a) THE HANDOFF. A record as the report writes it must cluster. Before this lane the
    #     reconciler read `identity_state`, `rule` and `uri`, and the report writes `state`,
    #     `rule_id` and `canonical_path`: every real finding was withheld IDENTITY_NOT_ESTABLISHED.
    clusters, withheld = rt.build_clusters([obs('trivy', 'CVE-19', 'go.mod', 'id-19', ['cve-19'])])
    if withheld or len(clusters) != 1:
        fails.append('T-19: a findings.json record (state/rule_id/canonical_path) was withheld: '
                     '%d cluster(s), withheld %r' % (len(clusters), [w[2] for w in withheld]))
    elif clusters[0]['members'][0].get('rule') != 'CVE-19' or \
            clusters[0]['members'][0].get('uri') != 'go.mod':
        fails.append('T-19: the report record was clustered but its rule/path did not reach the '
                     'ticket (rule %r, uri %r)' % (clusters[0]['members'][0].get('rule'),
                                                    clusters[0]['members'][0].get('uri')))
    # (a2) END TO END: the REAL reporter writes findings.json and findings-coverage.json, and the
    #      reconciler clusters what it wrote and reads what each scanner established.
    work = tempfile.mkdtemp(prefix='ticket-handoff-')
    try:
        sarif = {'version': '2.1.0', 'runs': [{
            'tool': {'driver': {'name': 'Trivy', 'version': '0.56.1', 'rules': [
                {'id': 'CVE-2018-18074', 'properties': {'security-severity': '9.1'}}]}},
            'invocations': [{'executionSuccessful': True}],
            'results': [{'ruleId': 'CVE-2018-18074', 'level': 'error',
                         'message': {'text': 'requests 2.19.1: header leak'},
                         'properties': {'purl': 'pkg:pypi/requests@2.19.1',
                                        'package': 'requests', 'fixed_version': '2.31.0'},
                         'locations': [{'physicalLocation': {
                             'artifactLocation': {'uri': 'requirements.txt'},
                             'region': {'startLine': 7}}}]}]}]}
        io.open(os.path.join(work, 'trivy.sarif'), 'w', encoding='utf-8').write(json.dumps(sarif))
        io.open(os.path.join(work, 'state-trivy.json'), 'w', encoding='utf-8').write(json.dumps(
            {'scanner': 'trivy', 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
             'scope': '', 'sarif': 'trivy.sarif', 'artifact': 'RETAINED', 'upload': 'COMPLETE',
             'gate': 'FAIL', 'job': 'deps-scan'}))
        gh_out = os.path.join(work, 'gh_output')
        io.open(gh_out, 'w').close()
        subprocess.run([sys.executable, '-E', '-s', os.path.join(ROOT, 'scripts',
                                                               'scan_report.py'),
                        '--batch', work, '--max-detail', '5', '--expect', 'trivy'],
                       capture_output=True, text=True, timeout=300,
                       env=dict(os.environ, GITHUB_OUTPUT=gh_out, GITHUB_STEP_SUMMARY=''))
        fpath = os.path.join(work, 'findings.json')
        coverage, note = rt.load_coverage(os.path.join(work, 'findings-coverage.json'))
        if not os.path.exists(fpath) or coverage is None:
            fails.append('T-19: the reporter did not write findings.json and findings-coverage.json'
                         ' (%s)' % note)
        else:
            recs = json.load(io.open(fpath, encoding='utf-8'))
            c2, w2 = rt.build_clusters(recs)
            if len(c2) != 1 or w2:
                fails.append('T-19: the REAL report\'s finding did not reach a cluster (%d '
                             'cluster(s), withheld %r)' % (len(c2), [w[2] for w in w2]))
            if (coverage.get('trivy') or {}).get('scanner_version') != '0.56.1':
                fails.append('T-09/T-19: the coverage record does not carry the scanner version a '
                             'clearance must name: %r' % coverage.get('trivy'))
            if not rt.row_established(coverage.get('trivy')):
                fails.append('T-19: the coverage record does not show trivy established: %r'
                             % coverage.get('trivy'))
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    # (b) THE TEMPLATE CALLER.
    if not os.path.exists(TEMPLATE):
        fails.append('T-19: templates/ticket-reconcile.yml does not exist')
        return
    import yaml
    doc = yaml.safe_load(io.open(TEMPLATE, encoding='utf-8'))
    on = doc.get('on', doc.get(True)) or {}
    jobs = doc.get('jobs') or {}
    sec = [n for n, j in jobs.items() if 'reusable-security.yml' in str(j.get('uses'))]
    tick = [n for n, j in jobs.items() if 'reusable-ticket-reconcile.yml' in str(j.get('uses'))
            and (j.get('with') or {}).get('mode', 'reconcile') == 'reconcile']
    if len(sec) != 1 or len(tick) != 1:
        fails.append('T-19: the template must call the security reusable once and the ticket '
                     'reusable once in mode reconcile (got %r, %r)' % (sec, tick))
        return
    tj = jobs[tick[0]]
    needs = tj.get('needs') or []
    needs = [needs] if isinstance(needs, str) else needs
    if sec[0] not in needs:
        fails.append('T-19: the ticket job does not `needs:` the security job, so it is not wired '
                     'after the security run')
    w = tj.get('with') or {}
    if '%s.outputs.evidence_artifact' % sec[0] not in str(w.get('findings_artifact')):
        fails.append('T-19: findings_artifact is %r, not the security job\'s evidence_artifact '
                     '(the same-run artifact holding findings.json)' % w.get('findings_artifact'))
    if 'push' not in str(tj.get('if')):
        fails.append('T-19: the reconcile job is not limited to push (%r); a pull request must '
                     'never reach the credentialed job' % tj.get('if'))
    if 'push' not in on:
        fails.append('T-19: the template does not run on push to the default branch')
    for k in ('backend', 'environment', 'default_branch', 'kit_repository', 'kit_ref'):
        if k not in w:
            fails.append('T-19: the ticket job does not pass %s' % k)
    # The gate does not wait for ticketing: nothing the security job (or a deploy) needs is a
    # ticket job.
    for n, j in jobs.items():
        nd = j.get('needs') or []
        nd = [nd] if isinstance(nd, str) else nd
        if n in sec and any(x in nd for x in tick):
            fails.append('T-19: the security job needs the ticket job -- ticketing must never '
                         'gate the verdict')


# ── T-17 ─────────────────────────────────────────────────────────────────────────────────

def case_t17(rt, fails):
    if not os.path.exists(TEMPLATE):
        fails.append('T-17: no template, so nothing schedules the clock')
        return
    import yaml
    doc = yaml.safe_load(io.open(TEMPLATE, encoding='utf-8'))
    on = doc.get('on', doc.get(True)) or {}
    if not (on.get('schedule') or []):
        fails.append('T-17: the template has no schedule')
    jobs = doc.get('jobs') or {}
    clock = [(n, j) for n, j in jobs.items() if 'reusable-ticket-reconcile.yml' in str(j.get('uses'))
             and (j.get('with') or {}).get('mode') == 'resurface']
    if len(clock) != 1:
        fails.append('T-17: no template job calls the ticket reusable in mode resurface')
    else:
        n, j = clock[0]
        if 'schedule' not in str(j.get('if')):
            fails.append('T-17: the clock job is not limited to the schedule (%r)' % j.get('if'))
        if j.get('needs'):
            fails.append('T-17: the clock job needs %r -- the scheduled clock must not run a scan'
                         % j.get('needs'))
    sec = [j for j in jobs.values() if 'reusable-security.yml' in str(j.get('uses'))]
    if sec and 'schedule' not in str(sec[0].get('if')):
        fails.append('T-17: the security job runs on the schedule too -- the clock must cost one '
                     'small job, not a full scan')
    wf = yaml.safe_load(io.open(REUSABLE, encoding='utf-8'))
    rj = [(n, j) for n, j in (wf.get('jobs') or {}).items()
          if 'resurface' in str(j.get('if'))]
    if len(rj) != 1:
        fails.append('T-17: the reusable has no single job for mode resurface')
    else:
        n, j = rj[0]
        if j.get('needs'):
            fails.append('T-17: the resurface job needs %r: a guard job in front of it makes the '
                         'scheduled clock two billed jobs' % j.get('needs'))
        if 'refs/heads/' not in str(j.get('if')) or 'pull_request' in str(j.get('if')):
            fails.append('T-17: the resurface job\'s own `if:` does not hold the guard (default '
                         'branch, push/schedule/dispatch only): %r' % j.get('if'))
        if not j.get('timeout-minutes'):
            fails.append('T-17: the resurface job has no timeout')
    # Behaviour, through the script, with no scan: a lapsed disposition and an SLA breach.
    if not hasattr(rt, 'resurface'):
        fails.append('T-17: reconcile_tickets has no resurface() (the scheduled clock with writes)')
        return
    jt = Jira(rt)
    ledger = {}
    run(rt, jt, [obs('trivy', 'CVE-17', 'go.mod', 'id-17', ['cve-17'])], ledger, '2026-09-01',
        ctx(numbers=NUMBERS))
    ref = only_ref(ledger)
    res = rt.resurface(ledger, jt.backend(), True, '2026-10-23', numbers=NUMBERS)
    if not res.get('escalations') or jt.priority(ref) != 'High':
        fails.append('T-17: the scheduled clock did not escalate an SLA breach with no scan '
                     '(escalations %r, priority %r)' % (res.get('escalations'), jt.priority(ref)))
    # THE CLOCK'S LEDGER IS NOT PERSISTED (no propose-ledger follows a scheduled run), so the next
    # day starts from the SAME ledger. The tracker's own label is what stops a second escalation.
    n = len(jt.comments(ref))
    stale = json.loads(json.dumps(ledger))
    for e in stale.values():
        e.pop('sla_escalated', None)
    rt.resurface(stale, jt.backend(), True, '2026-10-24', numbers=NUMBERS)
    if len(jt.comments(ref)) != n or jt.priority(ref) != 'High':
        fails.append('T-17: with the ledger not persisted, the next day escalated the same breach '
                     'again (priority %r, %d comment(s) more)' % (jt.priority(ref),
                                                              len(jt.comments(ref)) - n))


# ── T-09 and RECURRED ───────────────────────────────────────────────────────────────────

def case_t09(rt, fails):
    rec = obs('trivy', 'CVE-9', 'go.mod', 'id-9', ['cve-9'])
    for T in TRACKERS:
        tr = T(rt)
        ledger = {}
        run(rt, tr, [rec], ledger, '2026-10-01', ctx(RUN1, coverage=cov(trivy=True)))
        ref = only_ref(ledger)
        if not ref:
            fails.append('T-09 %s: the first run created no ticket' % tr.name)
            continue
        # NEGATIVES FIRST: absence without positive coverage closes nothing.
        for label, coverage, extra in (
                ('no coverage supplied', None, []),
                ('the scanner was PARTIAL', cov(trivy='PARTIAL'), []),
                ('the scanner failed', cov(trivy=False), []),
                ('the scanner covered another directory', cov(trivy={'scope': 'services/api'}),
                 []),
                ('an unidentified finding from the same scanner at the same file',
                 cov(trivy=True), [obs('trivy', 'CVE-9', 'go.mod', '', [],
                                       state='UNFINGERPRINTABLE')])):
            res = run(rt, tr, extra, ledger, '2026-10-02', ctx(RUN2, coverage=coverage))
            if tr.closed(ref):
                fails.append('T-09 %s: CLOSED on %s -- absence of evidence closed a ticket'
                             % (tr.name, label))
                break
            if not any(p.get('ref') == ref for p in res.get('potentially_absent') or []):
                fails.append('T-09 %s: %s was not reported POTENTIALLY_ABSENT' % (tr.name, label))
        # POSITIVE: the scanner ran, established, covered the file, and did not report it.
        res = run(rt, tr, [], ledger, '2026-10-03', ctx(RUN2, coverage=cov(trivy=True)))
        if not tr.closed(ref):
            fails.append('T-09 %s: a verified clearance did not close the ticket (cleared %r)'
                         % (tr.name, res.get('cleared')))
        said = ' '.join(tr.comments(ref))
        if RUN2['run_url'] not in said or RUN2['commit'][:12] not in said:
            fails.append('T-09 %s: the closing comment does not cite the run and commit that '
                         'proved it absent: %r' % (tr.name, said[:300]))
        # OWNER 2026-10-23: "proven and which commit fixed it and the date and everything".
        for need, what in (('fixed by %s' % RUN2['commit'], 'the first clean commit as "fixed by"'),
                           ('last present at %s' % RUN1['commit'], 'the last commit it was present'),
                           ('trivy 0.56.1', 'each verifying scanner with its version'),
                           ('id-9', 'the finding identity'), ('go.mod', 'the file')):
            if need not in said:
                fails.append('T-09 %s: the closing comment does not state %s (%r)'
                             % (tr.name, what, need))
        if not re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', said):
            fails.append('T-09 %s: the closing comment carries no UTC date and time' % tr.name)
        cl = (next(iter(ledger.values())) or {}).get('clearance') or {}
        if cl.get('fixed_by') != RUN2['commit'] or cl.get('last_present_commit') != RUN1['commit'] \
                or not re.search(r'Z$', str(cl.get('at') or '')) or cl.get('run') != RUN2['run_url'] \
                or 'trivy 0.56.1' not in ' '.join(cl.get('scanners') or []) \
                or not any('id-9' in m and 'go.mod' in m for m in cl.get('members') or []):
            fails.append('T-09 %s: the ledger\'s clearance record lacks fixed_by, the last present '
                         'commit, the UTC time, the run, scanner versions or identity and file: %r'
                         % (tr.name, cl))
        before = len(tr.r.requests)
        run(rt, tr, [], ledger, '2026-10-04', ctx(RUN2, coverage=cov(trivy=True)))
        writes = [q for q in tr.r.requests[before:] if q['method'] in ('PUT', 'PATCH') or (
            q['method'] == 'POST' and not re.search(r'search/jql|wiql|workitemsbatch', q['url']))]
        if writes:
            fails.append('T-09 %s: a second cleared run wrote again (%d write(s)); a closed, '
                         'cleared ticket owes nothing' % (tr.name, len(writes)))
        # RECURRED: it comes back.
        res = run(rt, tr, [rec], ledger, '2026-10-05', ctx(RUN1, coverage=cov(trivy=True)))
        if tr.closed(ref):
            fails.append('T-09 %s: a cleared finding that came back did not reopen its ticket'
                         % tr.name)
        cls = [x.get('classification') for x in res.get('reopened') or []]
        if cls != ['RECURRED']:
            fails.append('T-09 %s: the recurrence was classified %r, not RECURRED (and never '
                         '`falsified`, which is an approved REMEDIATED the scanner reproduces)'
                         % (tr.name, cls))
        if not any('RECURRED' in c and 'did not hold' in c for c in tr.comments(ref)):
            fails.append('T-09 %s: no RECURRED comment saying the fix did not hold' % tr.name)
        if len(tr.tickets()) != 1:
            fails.append('T-09 %s: %d tickets over close and recurrence; expected one'
                         % (tr.name, len(tr.tickets())))
    # THE LAST PRESENT COMMIT UNKNOWN (a ledger written before it was recorded): said, not omitted.
    tr = Jira(rt)
    ledger = {}
    run(rt, tr, [rec], ledger, '2026-10-01', ctx(RUN1, coverage=cov(trivy=True)))
    for e in ledger.values():
        e.pop('last_seen_commit', None)
        for seen in (e.get('members') or {}).values():
            for o in seen:
                o.pop('last_seen_commit', None)
    run(rt, tr, [], ledger, '2026-10-02', ctx(RUN2, coverage=cov(trivy=True)))
    said = ' '.join(tr.comments(only_ref(ledger)))
    if 'last present at UNKNOWN' not in said:
        fails.append('T-09: with no recorded last-present commit the closing comment did not say it '
                     'is UNKNOWN: %r' % said[:400])
    # ONLY ROUTINE FINDING TICKETS CLOSE. The epic, a request-class ticket and any ticket the sweep
    # did not return as a stamped tier-0 item are never closed, whatever the ledger says.
    tr = Jira(rt)
    tr.t.issues['10000'] = {'id': '10000', 'key': 'KIT-EPIC', 'type': 'Epic', 'fields': {
        'customfield_10001': 'k-epic', 'labels': ['secure-cicd-kit'],
        'status': {'name': 'To Do', 'statusCategory': {'key': 'new'}}}}
    ledger = {}
    run(rt, tr, [rec], ledger, '2026-10-01', ctx(RUN1, coverage=cov(trivy=True)))
    ref_f = only_ref(ledger)
    ledger['k-epic'] = {'ref': '10000', 'member_identities': ['id-epic'],
                        'members': {'id-epic': [{'scanner': 'trivy', 'path': 'go.mod'}]}}
    entry = next(e for k, e in ledger.items() if k != 'k-epic')
    entry['ticket_class'] = 'ACCEPTED_RISK_REQUEST'
    run(rt, tr, [], ledger, '2026-10-02', ctx(RUN2, coverage=cov(trivy=True)))
    if any(i in ('10000', str(ref_f)) for i, _t in tr.t.transitions_posted):
        fails.append('T-09: a non-finding ticket was closed (the epic, or a request-class ticket): '
                     '%r' % tr.t.transitions_posted)
    # A workflow that REFUSES the reopen: the recurrence rides a successor (TC 4.2), still RECURRED,
    # and the contradicted clearance moves into the ledger's history.
    tr = Jira(rt)
    ledger = {}
    run(rt, tr, [rec], ledger, '2026-10-01', ctx(RUN1, coverage=cov(trivy=True)))
    run(rt, tr, [], ledger, '2026-10-02', ctx(RUN2, coverage=cov(trivy=True)))
    tr.t.refuse_reopen = True
    res = run(rt, tr, [rec], ledger, '2026-10-03', ctx(RUN1, coverage=cov(trivy=True)))
    entry = next(iter(ledger.values()))
    if [s.get('classification') for s in res.get('successors') or []] != ['RECURRED'] or \
            entry.get('clearance') or len(entry.get('recurrences') or []) != 1:
        fails.append('T-09: a refused reopen did not carry the recurrence on a RECURRED successor '
                     'with the clearance moved to history: %r / %r'
                     % (res.get('successors'), sorted(entry)))


# ── D5: NEW, RECURRED (above), REOPENED_BY_LAPSE, on every backend; the workflow wires all ──

def case_d5(rt, fails):
    for T in TRACKERS:
        tr = T(rt)
        ledger = {}
        res = run(rt, tr, [obs('trivy', 'CVE-5', 'go.mod', 'id-5', ['cve-5'])], ledger,
                  '2026-10-01', ctx())
        made = [c for c in res.get('created') or [] if c.get('ref')]
        if not made or made[0].get('trigger') != 'NEW':
            fails.append('D5 %s: a first-seen finding was not raised as NEW: %r' % (tr.name, made))
            continue
        ref = made[0]['ref']
        if 'NEW' not in tr.body(ref):
            fails.append('D5 %s: the ticket does not say it was raised as NEW' % tr.name)
        # REOPENED_BY_LAPSE FROM THE CALENDAR: closed under an accepted risk that has expired.
        tr.close_by_hand(ref)
        key = next(iter(ledger))
        ledger[key]['backing'] = {'disposition_type': 'ACCEPTED_RISK', 'expires': '2026-10-10'}
        if not hasattr(rt, 'resurface'):
            fails.append('D5: no resurface() -- REOPENED_BY_LAPSE cannot come from the calendar')
            return
        res = rt.resurface(ledger, tr.backend(), True, '2026-10-20')
        if tr.closed(ref):
            fails.append('D5 %s: an expired acceptance did not reopen its ticket on the clock'
                         % tr.name)
        if not any('REOPENED_BY_LAPSE' in c for c in tr.comments(ref)):
            fails.append('D5 %s: the lapse reopen does not say REOPENED_BY_LAPSE' % tr.name)
        n = len(tr.r.requests)
        rt.resurface(ledger, tr.backend(), True, '2026-10-21')
        if any(q['method'] in ('PUT', 'PATCH') or (q['method'] == 'POST' and not re.search(
                r'search/jql|wiql|workitemsbatch', q['url'])) for q in tr.r.requests[n:]):
            fails.append('D5 %s: the clock reopened or commented on the same lapse twice' % tr.name)
        # REOPENED_BY_LAPSE WITH A SCAN: still reported, the disposition it carried has expired.
        tr2 = T(rt)
        ledger2 = {}
        rec = obs('trivy', 'CVE-5L', 'go.mod', 'id-5l', ['cve-5l'])
        run(rt, tr2, [rec], ledger2, '2026-10-01', ctx())
        ref2 = only_ref(ledger2)
        tr2.close_by_hand(ref2)
        rec_d = dict(rec, disposition={'disposition_type': 'ACCEPTED_RISK', 'state': 'approved',
                                       'expires': '2026-10-05'})
        res = run(rt, tr2, [rec_d], ledger2, '2026-10-02', ctx())
        if not tr2.closed(ref2) or res.get('reopened'):
            fails.append('D5 %s: a closure backed by an UNEXPIRED acceptance was reopened'
                         % tr2.name)
        res = run(rt, tr2, [rec_d], ledger2, '2026-10-09', ctx())
        cls = [x.get('classification') for x in res.get('reopened') or []]
        if tr2.closed(ref2) or cls != ['REOPENED_BY_LAPSE']:
            fails.append('D5 %s: the scan beside a lapsed acceptance reopened as %r, not '
                         'REOPENED_BY_LAPSE' % (tr2.name, cls))
    # The workflow wires every backend the script supports.
    text = io.open(REUSABLE, encoding='utf-8').read()
    for need in ('TICKET_REPO', 'GH_TOKEN', 'TICKET_CALIBRATION_REF', 'JIRA_TRANSITION_DONE',
                 'AZDO_STATE_DONE', 'TICKET_CALL_BUDGET'):
        if need not in text:
            fails.append('D5: reusable-ticket-reconcile.yml does not wire %s' % need)
    if not re.search(r'description: "jira, azdo or github', text):
        fails.append('D5: the backend input does not offer github')


# ── D4: one key; cross-scanner duplicates merged ────────────────────────────────────────

def case_d4(rt, fails):
    import finding_correlation as fc
    if not hasattr(fc, 'cluster_key'):
        fails.append('D4/L48: finding_correlation has no public cluster_key(); the ticket key is '
                     'still computed separately')
    else:
        recs = [obs('trivy', 'CVE-4', 'go.mod', 'id-4a', ['CVE-4', 'GHSA-4']),
                obs('grype', 'GHSA-4', 'go.mod', 'id-4b', ['GHSA-4', 'CVE-4'], job='image-scan')]
        clusters, _w = rt.build_clusters(recs)
        corr = fc.correlate([dict(r, where=r['where']) for r in recs])
        if sorted(c['cluster_key'] for c in clusters) != sorted(
                c['cluster_key'] for c in corr['clusters']):
            fails.append('D4/L48: the ticket clusters and the report clusters carry different '
                         'keys for the same input')
        legacy = hashlib.sha256(('CLUSTER/%s/%s/%s' % ('SOURCE_DEPENDENCY', 'go.mod', 'cve-4'))
                                .encode('utf-8')).hexdigest()[:32]
        if [c['cluster_key'] for c in clusters] != [legacy]:
            fails.append('D4/L48: the unified key is not byte-identical to the stamp already on '
                         'live tickets; every existing ticket would be orphaned (%r vs %r)'
                         % ([c['cluster_key'] for c in clusters], legacy))
    # THE MERGE. Two tickets raised separately for what is now one anchored finding.
    for T in TRACKERS:
        tr = T(rt)
        ledger = {}
        run(rt, tr, [obs('trivy', 'CVE-44', 'go.mod', 'id-t', ['CVE-44'])], ledger,
            '2026-10-01', ctx())
        run(rt, tr, [obs('grype', 'GHSA-44', 'go.mod', 'id-g', ['GHSA-44'], job='image-scan')],
            ledger, '2026-10-02', ctx())
        refs = sorted((e['ref'] for e in ledger.values()), key=lambda x: int(x))
        if len(refs) != 2:
            fails.append('D4 %s: setup made %d tickets, expected 2' % (tr.name, len(refs)))
            continue
        both = [obs('trivy', 'CVE-44', 'go.mod', 'id-t', ['CVE-44']),
                obs('grype', 'GHSA-44', 'go.mod', 'id-g', ['GHSA-44', 'CVE-44'],
                    job='image-scan')]
        res = run(rt, tr, both, ledger, '2026-10-03', ctx())
        if len(tr.tickets()) != 2:
            fails.append('D4 %s: the merge created a ticket (%d now)' % (tr.name, len(tr.tickets())))
        survivor, absorbed = refs[0], refs[1]
        if not res.get('merged'):
            fails.append('D4 %s: cross-scanner duplicates were not merged: outcomes %r'
                         % (tr.name, res.get('outcomes')))
            continue
        if not tr.closed(absorbed) or tr.closed(survivor):
            fails.append('D4 %s: the absorbed ticket %s should be closed as superseded and the '
                         'oldest %s kept open' % (tr.name, absorbed, survivor))
        if not any(str(survivor) in c and 'superseded' in c.lower()
                   for c in tr.comments(absorbed)):
            fails.append('D4 %s: the absorbed ticket does not say it is superseded by %s'
                         % (tr.name, survivor))
        body = tr.body(survivor)
        if 'trivy' not in body or 'grype' not in body:
            fails.append('D4 %s: the surviving ticket does not list every scanner that reported '
                         'the finding' % tr.name)
        n = len(tr.r.requests)
        res = run(rt, tr, both, ledger, '2026-10-04', ctx())
        if res.get('merged') or res.get('needs_decision'):
            fails.append('D4 %s: a second run merged again or asked for a decision: %r'
                         % (tr.name, res.get('needs_decision')))
        if any(q['method'] in ('PUT', 'PATCH') or (q['method'] == 'POST' and not re.search(
                r'search/jql|wiql|workitemsbatch', q['url'])) for q in tr.r.requests[n:]):
            fails.append('D4 %s: the steady state after a merge still writes' % tr.name)


# ── FW-§3a: confidence and disagreement ─────────────────────────────────────────────────

def case_fw3a(rt, fails):
    for T in TRACKERS:
        tr = T(rt)
        ledger = {}
        coverage = cov(trivy=True, osv_scanner=True)
        res = run(rt, tr, [obs('trivy', 'CVE-3A', 'go.mod', 'id-3a', ['cve-3a'])], ledger,
                  '2026-10-01', ctx(coverage=coverage))
        ref = only_ref(ledger)
        if not ref:
            fails.append('FW-3a %s: no ticket' % tr.name)
            continue
        body = tr.body(ref)
        if 'CONTESTED_ANCHORED' not in body or 'osv-scanner' not in body:
            fails.append('FW-3a %s: a peer that covered the file and did not report was not '
                         'recorded: the ticket has no CONTESTED_ANCHORED confidence naming '
                         'osv-scanner' % tr.name)
        if not any('disagreement' in x for x in tr.labels(ref)):
            fails.append('FW-3a %s: the contested ticket carries no disagreement label: %r'
                         % (tr.name, tr.labels(ref)))
        if (res.get('ticketing_claim') or {}).get('routing_result') != 'DECISION_REQUIRED' or \
                not res.get('disagreements'):
            fails.append('FW-3a %s: a disagreement did not route to a person (claim %r)'
                         % (tr.name, (res.get('ticketing_claim') or {}).get('routing_result')))
        res = run(rt, tr, [obs('trivy', 'CVE-3A', 'go.mod', 'id-3a', ['cve-3a'])], ledger,
                  '2026-10-02', ctx(coverage=coverage))
        if res.get('disagreements'):
            fails.append('FW-3a %s: an unchanged disagreement was escalated again (noise)'
                         % tr.name)
    # Severity disagreement: recorded, the worst taken, never averaged.
    tr = Jira(rt)
    ledger = {}
    run(rt, tr, [obs('trivy', 'CVE-S', 'go.mod', 'id-s', ['cve-s'], severity='HIGH'),
                 obs('grype', 'CVE-S', 'go.mod', 'id-s', ['cve-s'], severity='LOW',
                     job='image-scan')], ledger, '2026-10-01', ctx())
    body = tr.body(only_ref(ledger)) if only_ref(ledger) else ''
    if 'severity disagreement' not in body.lower() or 'grype: low' not in body.lower():
        fails.append('FW-3a: differing severities are not recorded as a disagreement naming each '
                     'scanner\'s value: %r' % body[-600:])
    if '| effective severity | high' not in body:
        fails.append('FW-3a: the effective severity is not the worst of the contributors')
    # SAST rule sets are not comparable: a silent peer is not a negative observation.
    clusters, w = rt.build_clusters([obs('semgrep', 'py.sqli', 'app.py', 'id-q', [],
                                         job='sast-semgrep', subject='SOURCE')])
    res = rt.reconcile(clusters, w, rt.RecordingBackend(), {}, False, today='2026-10-01',
                       context=ctx(coverage=cov(semgrep={'job': 'sast-semgrep'},
                                                bandit={'job': 'sast-bandit'})))
    if res.get('disagreements'):
        fails.append('FW-3a: a SAST finding was contested by a different SAST tool\'s silence; '
                     'rule sets differ, so that silence observes nothing about this rule')


# ── SLA by severity, from the register's numbers ────────────────────────────────────────

def case_sla(rt, fails):
    for T in TRACKERS:
        tr = T(rt)
        ledger = {}
        rec = obs('trivy', 'CVE-SLA', 'go.mod', 'id-sla', ['cve-sla'], severity='HIGH')
        run(rt, tr, [rec], ledger, '2026-10-01', ctx(numbers=NUMBERS))
        ref = only_ref(ledger)
        if not ref:
            fails.append('SLA %s: no ticket' % tr.name)
            continue
        if '2026-10-31' not in tr.body(ref):
            fails.append('SLA %s: the ticket does not carry the due date from numbers.'
                         'sla_period_days.HIGH (2026-10-31)' % tr.name)
        p0 = tr.priority(ref)
        run(rt, tr, [rec], ledger, '2026-11-05', ctx(numbers=NUMBERS))
        said = ' '.join(tr.comments(ref))
        if 'overdue' not in said.lower() or '2026-10-31' not in said:
            fails.append('SLA %s: an overdue ticket got no escalation comment naming its due date'
                         % tr.name)
        if not any('sla-overdue' in x for x in tr.labels(ref)):
            fails.append('SLA %s: no overdue label: %r' % (tr.name, tr.labels(ref)))
        want = {'jira': 'High', 'azdo': 1, 'github': None}[tr.name]
        if tr.priority(ref) != want:
            fails.append('SLA %s: priority %r -> %r, expected %r' % (tr.name, p0, tr.priority(ref),
                                                                     want))
        n = len(tr.comments(ref))
        run(rt, tr, [rec], ledger, '2026-11-06', ctx(numbers=NUMBERS))
        if len(tr.comments(ref)) != n:
            fails.append('SLA %s: the same breach was escalated twice' % tr.name)
    # No number: said, never defaulted.
    tr = Jira(rt)
    ledger = {}
    res = run(rt, tr, [obs('trivy', 'CVE-N', 'go.mod', 'id-n', ['cve-n'])], ledger, '2026-10-01',
              ctx(numbers={}))
    if 'POLICY_NUMBER_NOT_CONFIGURED' not in tr.body(only_ref(ledger) or '0') and \
            'POLICY_NUMBER_NOT_CONFIGURED' not in rt.render_summary(res):
        fails.append('SLA: with no sla_period_days the run did not say POLICY_NUMBER_NOT_CONFIGURED')


# ── LINK ────────────────────────────────────────────────────────────────────────────────

def case_link(rt, fails):
    tr = Jira(rt)
    ledger = {}
    rec = obs('trivy', 'CVE-L', 'go.mod', 'id-l', ['cve-l'], fp='abcdefabcdef', line=42)
    run(rt, tr, [rec], ledger, '2026-10-01', ctx(RUN1, exceptions={'abcdefabcdef': 'KIT-77'}))
    ref = only_ref(ledger)
    body = tr.body(ref) if ref else ''
    for need, what in ((RUN1['run_url'], 'the run'), (RUN1['commit'], 'the commit'),
                       ('go.mod:42', 'file:line'), ('KIT-77', 'the exception ticket')):
        if need not in body:
            fails.append('LINK: the ticket does not name %s (%s)' % (what, need))
    # The exception's resurfacing comment names the finding ticket back.
    import exception_due as ed
    work = tempfile.mkdtemp(prefix='ticket-link-')
    try:
        reg = {'schema_version': 2, 'register_id': 'repo',
               'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-21'},
               'policies': [{'id': 'own', 'scope': {'environment_tier': 'dev'}, 'rung': 'crawl',
                             'decision': {'authority': 'Dana Example', 'reason': 'adoption',
                                          'decided_on': '2026-10-01', 'expires': '2099-01-01'},
                             'secret_exceptions': [{
                                 'finding': 'abcdefabcdef', 'ticket': 'KIT-77',
                                 'explanation': 'fixture', 'approver': 'Dana Example',
                                 'expires': '2026-10-25'}]}]}
        rp = os.path.join(work, 'reg.json')
        lp = os.path.join(work, 'ledger.json')
        io.open(rp, 'w', encoding='utf-8').write(json.dumps(reg))
        rt.save_ledger(lp, ledger)
        fake = _FakeJiraForDue()
        old = sys.stdout
        sys.stdout = io.StringIO()
        try:
            ed.main(['--repository-register', rp, '--ticket-ledger', lp, '--today', '2026-10-22',
                     '--resurface', '--apply'],
                    env={'JIRA_HOST': 'https://example.atlassian.net'},
                    backend_factory=lambda env: (fake, 'ok'))
        except SystemExit as exc:
            fails.append('LINK: exception_due refused --ticket-ledger (exit %s): it cannot name '
                         'the finding ticket' % exc.code)
        finally:
            sys.stdout = old
        said = ' '.join(c[2] for c in fake.calls if c[0] == 'comment')
        key = (next(iter(ledger.values())) or {}).get('key') or ref
        if not said or str(key) not in said:
            fails.append('LINK: the exception\'s resurfacing comment does not name the finding '
                         'ticket %s: %r' % (key, said[:300]))
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


class _FakeJiraForDue(object):
    name = 'jira'
    create_ceiling = 5

    def __init__(self):
        self.calls = []

    def resolve(self, ref):
        return {'key': ref, 'fields': {'status': {'statusCategory': {'key': 'new'}}}}, True, 'ok'

    def comment(self, ref, text):
        self.calls.append(('comment', ref, text))
        return True, 'ok'

    def reopen(self, ref):
        return True, 'ok'


# ── IDEM: no duplicates, bounded calls, backoff, TICKETING_UNAVAILABLE ──────────────────

def case_idem(rt, fails):
    for T in TRACKERS:
        tr = T(rt)
        ledger = {}
        recs = [obs('trivy', 'CVE-I', 'go.mod', 'id-i', ['cve-i']),
                obs('osv-scanner', 'CVE-I', 'go.mod', 'id-i', ['cve-i'])]
        for d in ('2026-10-01', '2026-10-02'):
            run(rt, tr, recs, ledger, d, ctx(RUN1, coverage=cov(trivy=True, osv_scanner=True),
                                              numbers=NUMBERS))
        n = len(tr.r.requests)
        run(rt, tr, recs, ledger, '2026-10-03', ctx(RUN1, coverage=cov(trivy=True,
                                                                         osv_scanner=True),
                                                      numbers=NUMBERS))
        writes = [q for q in tr.r.requests[n:] if q['method'] in ('PUT', 'PATCH') or (
            q['method'] == 'POST' and not re.search(r'search/jql|wiql|workitemsbatch', q['url']))]
        if len(tr.tickets()) != 1 or writes:
            fails.append('IDEM %s: three runs made %d ticket(s) and the third wrote %d time(s)'
                         % (tr.name, len(tr.tickets()), len(writes)))
    # THE CALL BUDGET.
    tr = Jira(rt)
    b = tr.backend(TICKET_CALL_BUDGET='4')
    clusters, w = rt.build_clusters([obs('trivy', 'CVE-B', 'go.mod', 'id-b', ['cve-b'])])
    res = rt.reconcile(clusters, w, b, {}, True, today='2026-10-01', context=ctx())
    if len(tr.r.requests) > 4:
        fails.append('IDEM: a run with TICKET_CALL_BUDGET=4 sent %d request(s)' % len(tr.r.requests))
    if (res.get('ticketing_claim') or {}).get('routing_result') != 'EVIDENCE_UNTRUSTED' or \
            'budget' not in rt.render_summary(res).lower():
        fails.append('IDEM: an exhausted call budget did not make the claim untrusted and say so')
    b, _n = rt.choose_backend(dict(JIRA_ENV))
    if not isinstance(getattr(b, 'call_budget', None), int) or b.call_budget <= 0:
        fails.append('IDEM: with no TICKET_CALL_BUDGET set the run is UNBOUNDED (call_budget %r)'
                     % getattr(b, 'call_budget', None))
    if not getattr(b, 'retry_ceiling', 0) > 0:
        fails.append('IDEM: with no TICKET_RETRY_CEILING set the first throttle ends the request: '
                     'there is no backoff by default')
    # UNREACHABLE: TICKETING_UNAVAILABLE, visible, exit 3 -- never a silent pass.
    ptb.install(ptb.Replay())
    clusters, w = rt.build_clusters([obs('trivy', 'CVE-U', 'go.mod', 'id-u', ['cve-u'])])
    res = rt.reconcile(clusters, w, ptb.backend(rt, JIRA_ENV), {}, True, today='2026-10-01',
                       context=ctx())
    if res.get('ticketing_state') != 'TICKETING_UNAVAILABLE' or \
            'TICKETING_UNAVAILABLE' not in rt.render_summary(res):
        fails.append('IDEM: an unreachable tracker is not TICKETING_UNAVAILABLE in the run record '
                     'and the summary (state %r)' % res.get('ticketing_state'))
    work = tempfile.mkdtemp(prefix='ticket-unavail-')
    try:
        fp = os.path.join(work, 'findings.json')
        io.open(fp, 'w', encoding='utf-8').write(json.dumps(
            [obs('trivy', 'CVE-U', 'go.mod', 'id-u', ['cve-u'])]))
        env = dict((k, v) for k, v in os.environ.items()
                   if not k.startswith(('TICKET_', 'JIRA_', 'AZDO_', 'GH_', 'GITHUB_')))
        env.update(JIRA_ENV, JIRA_HOST='https://127.0.0.1:9', TICKET_RETRY_CEILING='0')
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'reconcile_tickets.py'),
                            '--findings', fp, '--ledger', os.path.join(work, 'l.json'), '--apply',
                            '--today', '2026-10-01'], env=env, capture_output=True, text=True,
                           timeout=120)
        if p.returncode != 3 or 'TICKETING_UNAVAILABLE' not in p.stdout:
            fails.append('IDEM: an unreachable tracker exited %d without TICKETING_UNAVAILABLE in '
                         'the output' % p.returncode)
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


# ── FW-§3b ──────────────────────────────────────────────────────────────────────────────

def case_fw3b(rt, fails):
    if not os.path.exists(SKILL):
        fails.append('FW-3b: skills/tools/correlation-triage/SKILL.md does not exist')
        return
    text = io.open(SKILL, encoding='utf-8').read()
    if not text.startswith('---') or 'name: correlation-triage' not in text or \
            'description:' not in text.split('---')[1]:
        fails.append('FW-3b: the skill has no frontmatter naming it correlation-triage with a '
                     'description')
    for need in ('anchored', 'proposed', 'singleton', 'CONTESTED_ANCHORED', 'DECISION_REQUIRED',
                 'finding_correlation.py'):
        if need not in text:
            fails.append('FW-3b: the skill does not cover %s' % need)


CASES = [('T-19 template caller and the findings handoff', case_t19),
         ('T-17 the scheduled clock, one small job', case_t17),
         ('T-09 close on verified clearance; RECURRED', case_t09),
         ('D5 NEW / RECURRED / REOPENED_BY_LAPSE per backend', case_d5),
         ('D4 one key; cross-scanner merge', case_d4),
         ('FW-3a confidence and disagreement', case_fw3a),
         ('SLA due date and escalation', case_sla),
         ('LINK run, commit, file:line, exception', case_link),
         ('IDEM duplicates, budget, backoff, unavailable', case_idem),
         ('FW-3b correlation-triage skill', case_fw3b),
         ('T-12 no governance field written anywhere above', case_t12)]


def main():
    try:
        import reconcile_tickets as rt
    except Exception as exc:                          # noqa: BLE001
        print('UNKNOWN: could not import reconcile_tickets: %s' % exc)
        return 2
    real = urllib.request.urlopen
    fails = []
    try:
        ptb._sleeps(rt)
        for label, fn in CASES:
            before = len(fails)
            try:
                fn(rt, fails)
            except Exception as exc:                  # noqa: BLE001 - a crash is a failure
                import traceback
                fails.append('%s crashed: %s: %s\n%s' % (label, type(exc).__name__, exc,
                                                         traceback.format_exc()[-600:]))
            print('  %-50s %s' % (label, 'ok' if len(fails) == before else 'FAIL'))
    finally:
        urllib.request.urlopen = real
    if fails:
        print('')
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('::error title=Ticket lifecycle unproven::%d failure(s)' % len(fails))
        return 1
    print('ticketing lifecycle proven on Jira, Azure DevOps and GitHub stand-ins: the report\'s '
          'findings reach the reconciler; a template runs it after the scan and the clock on a '
          'schedule in one job; verified clearance closes with the run and commit cited, and a '
          'return is RECURRED; NEW and REOPENED_BY_LAPSE end to end; one cluster key, and '
          'cross-scanner duplicates merged into the oldest ticket; contested confidence and '
          'severity disagreement recorded and routed once; SLA due dates from the register and '
          'one escalation; run, commit, file:line and exception linked both ways; no duplicates, '
          'a bounded call budget with backoff, and TICKETING_UNAVAILABLE exits 3. No request '
          'left the machine.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
