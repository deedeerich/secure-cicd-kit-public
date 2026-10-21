#!/usr/bin/env python3
"""The ticket reconcile workflow arms only where the contract allows it, and holds nothing else.

WHY THIS EXISTS

    TICKETING_BACKENDS.md section 5 and TICKETING_CONTRACT.md section 7: ticketing runs after the
    merge and on a schedule, NEVER in a pull request and never chained off one; ONE job holds the
    tracker credential, from a protected environment, with `contents: read` and a timeout; finding
    text reaches the tracker as data through `env:`, never `${{ }}` inside `run:`.

    A workflow can state all of that in its comments and do none of it. So this reads the shipped
    file's STRUCTURE, and then EXTRACTS the guard step and the reconcile step and RUNS them under
    bash with stub inputs -- the kit's designed local proof (KIT-DESIGN-GAP-LEDGER section 6). No
    tracker is contacted: the reconcile step runs with no credential, so the script must refuse.

WHAT IT CANNOT PROVE

    That GitHub honours the environment's branch policy, that the caller's trigger wiring is right,
    or that the job starts. Those need a hosted run (owed; see the validation registry).

EXIT  0 proven  1 a case failed  2 could not be checked
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-ticket-reconcile.yml')
BASH = shutil.which('bash')


def run_step(script, env, cwd):
    """Run an extracted `run:` block under bash, the way the runner would. -> (rc, out, outputs)."""
    tmp = tempfile.mkdtemp(prefix='ticket-wf-')
    try:
        out_file = os.path.join(tmp, 'output')
        summ = os.path.join(tmp, 'summary')
        io.open(out_file, 'w').close()
        io.open(summ, 'w').close()
        e = dict((k, v) for k, v in os.environ.items()
                 if not k.startswith(('TICKET_', 'JIRA_', 'AZDO_', 'GH_', 'GITHUB_')))
        e.update(env)
        e.update({'GITHUB_OUTPUT': out_file, 'GITHUB_STEP_SUMMARY': summ, 'RUNNER_TEMP': tmp})
        path = os.path.join(tmp, 'step.sh')
        io.open(path, 'w', encoding='utf-8', newline='\n').write(script)
        p = subprocess.run([BASH, '-e', path], cwd=cwd, env=e, capture_output=True, text=True,
                           timeout=300)
        outputs = dict(line.split('=', 1) for line in io.open(out_file, encoding='utf-8')
                       .read().splitlines() if '=' in line)
        return p.returncode, p.stdout + p.stderr + io.open(summ, encoding='utf-8').read(), outputs
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable. Failure to observe is not an observation.')
        return 2
    if not os.path.exists(WF):
        print('FAIL: %s does not exist (W-1)' % WF)
        return 1
    if not BASH:
        print('UNKNOWN: no bash to run the extracted steps')
        return 2
    text = io.open(WF, encoding='utf-8').read()
    doc = yaml.safe_load(text) or {}
    fails = []

    on = doc.get('on', doc.get(True)) or {}
    if set(on) != {'workflow_call'}:
        fails.append('triggers are %r; a reusable reconcile is called by its caller and nothing '
                     'else (no pull_request, no workflow_run)' % sorted(on))
    if (doc.get('permissions') or {}) != {'contents': 'read'}:
        fails.append('file-level permissions are %r, not contents: read' % doc.get('permissions'))
    jobs = doc.get('jobs') or {}
    guard, rec = jobs.get('guard') or {}, jobs.get('reconcile') or {}
    if not guard or not rec:
        fails.append('expected exactly a guard job and a reconcile job, got %r' % sorted(jobs))
        return report(fails)

    # ONE job holds the credential: the reconcile job, behind the guard, in an environment.
    if 'secrets.' in yaml.safe_dump(guard):
        fails.append('the guard job references a secret; only the reconcile job may')
    if 'environment' in guard:
        fails.append('the guard job requests an environment; it must hold nothing')
    if rec.get('needs') not in ('guard', ['guard']):
        fails.append('the reconcile job does not need the guard')
    if 'needs.guard.outputs.armed' not in str(rec.get('if') or ''):
        fails.append('the reconcile job does not run on the guard\'s armed output: %r'
                     % rec.get('if'))
    if not rec.get('environment'):
        fails.append('the reconcile job holds no protected environment, so the credential is not '
                     'gated to the default branch')
    if (rec.get('permissions') or {}) != {'contents': 'read'}:
        fails.append('reconcile job permissions are %r, not contents: read'
                     % rec.get('permissions'))
    if not rec.get('timeout-minutes'):
        fails.append('the reconcile job has no timeout-minutes; an outage would bill unbounded')

    # T-21 / TC 7.2: LEAST PRIVILEGE BY MODE. The scheduled deferral sweep reads the ledger and a
    # date and contacts no tracker, so it must not hold the tracker credential at all: its own
    # job, with no protected environment and no secret, and the credentialed job never runs for
    # it. Requesting the environment for a sweep put the credential in reach of a job that needs
    # none (completion ledger row T-21).
    sweep_job = jobs.get('sweep') or {}
    if not sweep_job:
        fails.append('T-21: there is no separate sweep job; the scheduled sweep runs inside the '
                     'job that requests the protected environment and holds the credential')
    else:
        if 'environment' in sweep_job:
            fails.append('T-21: the sweep job requests an environment; it contacts no tracker')
        if 'secrets.' in yaml.safe_dump(sweep_job):
            fails.append('T-21: the sweep job references a secret; it needs none')
        if sweep_job.get('needs') not in ('guard', ['guard']) or \
                'needs.guard.outputs.armed' not in str(sweep_job.get('if') or '') or \
                "inputs.mode == 'sweep'" not in str(sweep_job.get('if') or ''):
            fails.append('T-21: the sweep job does not run on the guard and mode sweep only: %r'
                         % sweep_job.get('if'))
        if (sweep_job.get('permissions') or {}) != {'contents': 'read'} or \
                not sweep_job.get('timeout-minutes'):
            fails.append('T-21: the sweep job lacks contents: read or a timeout')
    if "inputs.mode != 'sweep'" not in str(rec.get('if') or ''):
        fails.append('T-21: the credentialed reconcile job still runs in mode sweep: %r'
                     % rec.get('if'))

    # DATA, NEVER CODE: no expression inside any run: block.
    for name, job in jobs.items():
        for st in job.get('steps') or []:
            if '${{' in str(st.get('run') or ''):
                fails.append('job %s step %r interpolates an expression inside run: (TC 7.4)'
                             % (name, st.get('name')))

    # ── RUN THE GUARD, extracted, against every context. ────────────────────────────────
    g = [s for s in guard.get('steps') or [] if s.get('id') == 'decide']
    if not g:
        fails.append('the guard has no step with id: decide')
        return report(fails)
    gs = g[0]['run']
    cases = [
        ('a pull request', 'pull_request', 'refs/pull/7/merge', 'false'),
        ('pull_request_target', 'pull_request_target', 'refs/heads/main', 'false'),
        ('a run chained off another workflow', 'workflow_run', 'refs/heads/main', 'false'),
        ('a push to a feature branch', 'push', 'refs/heads/feature', 'false'),
        ('a push to the protected default branch', 'push', 'refs/heads/main', 'true'),
        ('a schedule on the default branch', 'schedule', 'refs/heads/main', 'true'),
        ('a manual dispatch on the default branch', 'workflow_dispatch', 'refs/heads/main',
         'true'),
    ]
    for label, event, ref, want in cases:
        rc, out, outputs = run_step(gs, {'EVENT_NAME': event, 'REF': ref,
                                         'DEFAULT_BRANCH': 'main'}, ROOT)
        if rc != 0 or outputs.get('armed') != want:
            fails.append('guard, %s: armed=%r (rc %d), expected %s' % (label, outputs.get('armed'),
                                                                      rc, want))
    rc, out, outputs = run_step(gs, {'EVENT_NAME': 'push', 'REF': 'refs/heads/main',
                                     'DEFAULT_BRANCH': ''}, ROOT)
    if outputs.get('armed') != 'false':
        fails.append('an EMPTY default branch armed the job; it must fail closed')

    # ── RUN THE RECONCILE STEP, extracted, with no credential: it must refuse, exit 3. ──
    r = [s for s in rec.get('steps') or [] if s.get('id') == 'reconcile']
    if not r:
        fails.append('the reconcile job has no step with id: reconcile')
        return report(fails)
    rs = r[0]['run']
    # Credentials only from secrets, and only in this step's env.
    for name, job in jobs.items():
        for st in job.get('steps') or []:
            if st is r[0]:
                continue
            if re.search(r'secrets\.', yaml.safe_dump(st)):
                fails.append('step %r in job %s touches a secret; only the reconcile step may'
                             % (st.get('name'), name))
    tmp =tempfile.mkdtemp(prefix='ticket-wf-ws-')
    try:
        findings = os.path.join(tmp, 'findings.json')
        io.open(findings, 'w').write('[]')
        base = {'KIT_DIR': ROOT, 'MODE': 'reconcile', 'FINDINGS_FILE': findings,
                'LEDGER_PATH': os.path.join(tmp, 'ledger.json'), 'APPLY': 'false',
                'TODAY_OVERRIDE': '2026-10-14', 'TICKET_BACKEND': 'jira'}
        rc, out, _o = run_step(rs, base, tmp)
        if rc != 3:
            fails.append('the extracted reconcile step with no credential exited %d, expected 3 '
                         '(EVIDENCE_UNTRUSTED): %s' % (rc, out[-400:]))
        # The runner's bash is `-e` (as run_step runs it): the exit code must still reach the
        # posture step as `rc`, or a decision owed (1) reads as no verdict at all.
        if _o.get('rc') != '3':
            fails.append('the reconcile step under bash -e did not write rc=3 for the posture '
                         'step (got %r): the script\'s non-zero exit aborted the step first'
                         % _o.get('rc'))
        rc, out, _o = run_step(rs, dict(base, FINDINGS_FILE=os.path.join(tmp, 'absent.json')),
                               tmp)
        if rc != 3 or 'EVIDENCE_UNTRUSTED' not in out:
            fails.append('an ABSENT findings file did not exit 3 naming EVIDENCE_UNTRUSTED (an '
                         'absent input is a typed state, never zero findings): rc %d' % rc)
        io.open(base['LEDGER_PATH'], 'w').write(
            '{"schema": 1, "clusters": {"%s": {"ref": "1", "deferrals": {"t/1": '
            '{"reason": "upstream", "until": "2026-01-01"}}}}}' % ('c' * 32))
        # The sweep runs in its OWN job (T-21): extracted and run with no credential at all.
        sw = [s for s in (jobs.get('sweep') or {}).get('steps') or [] if s.get('id') == 'sweep']
        if not sw:
            fails.append('T-21: the sweep job has no step with id: sweep')
        else:
            sbase = {'KIT_DIR': ROOT, 'LEDGER_PATH': base['LEDGER_PATH'],
                     'TODAY_OVERRIDE': '2026-10-14'}
            rc, out, so = run_step(sw[0]['run'], sbase, tmp)
            if rc != 1 or 'PAST DUE' not in out or so.get('routing_result') != \
                    'DECISION_REQUIRED':
                fails.append('the scheduled sweep job did not report an elapsed deferral with exit '
                             '1 and routing DECISION_REQUIRED: rc %d, %r' % (rc, so))
            rc, out, so = run_step(sw[0]['run'], dict(sbase, LEDGER_PATH=os.path.join(
                tmp, 'no-ledger.json')), tmp)
            if rc != 3 or so.get('routing_result') != 'EVIDENCE_UNTRUSTED':
                fails.append('the sweep job with NO ledger did not exit 3 with routing '
                             'EVIDENCE_UNTRUSTED (nothing swept is not "nothing elapsed"): rc '
                             '%d, %r' % (rc, so))
        for mode in ('anything', 'sweep'):
            # The credentialed step serves mode reconcile only; anything else is misuse.
            rc, out, _o = run_step(rs, dict(base, MODE=mode), tmp)
            if rc == 0:
                fails.append('the reconcile step exited 0 for MODE=%s' % mode)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ── RUN THE POSTURE STEP, extracted: the route follows what actually happened. ────
    p = [s for s in rec.get('steps') or [] if s.get('id') == 'posture']
    if not p:
        fails.append('the reconcile job emits no posture record')
        return report(fails)
    ps = p[0]['run']
    tmp = tempfile.mkdtemp(prefix='ticket-wf-posture-')
    try:
        defect = os.path.join(tmp, 'defect.json')
        io.open(defect, 'w').write('{"notes": ["CONFIGURATION DEFECT: jira and azdo"]}')
        clean = {'W_FINDINGS_ARTIFACT': 'findings', 'W_APPLY': 'true', 'W_WEAKENING_REASON': '',
                 'W_WEAKENING_AUTHORITY': '', 'W_WEAKENING_EXCEPTION_REF': '',
                 'W_WEAKENING_EXPIRES': '', 'RECORD': os.path.join(tmp, 'none.json')}
        for label, change, want in (
                ('a clean run', {'RC': '0'}, 'PROCEED'),
                ('a decision owed', {'RC': '1'}, 'DECISION_REQUIRED'),
                ('an untrusted claim', {'RC': '3'}, 'EVIDENCE_UNTRUSTED'),
                ('no exit code at all', {'RC': ''}, 'EVIDENCE_UNTRUSTED'),
                ('two backends configured', {'RC': '3', 'RECORD': defect}, 'BLOCKED'),
                ('a plan-only run nobody attributed', {'RC': '0', 'W_APPLY': 'false'},
                 'DECISION_REQUIRED'),
                ('a plan-only run, attributed', {'RC': '0', 'W_APPLY': 'false',
                                                 'W_WEAKENING_REASON': 'first adoption',
                                                 'W_WEAKENING_AUTHORITY': 'platform-security'},
                 'PROCEED_WITH_ADVISORY')):
            rc, out, outputs = run_step(ps, dict(clean, **change), tmp)
            if outputs.get('routing_result') != want:
                fails.append('posture, %s: routing_result %r, expected %s'
                             % (label, outputs.get('routing_result'), want))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return report(fails)


def report(fails):
    if fails:
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('::error title=Ticket reconcile workflow unproven::%d failure(s) (W-1)' % len(fails))
        return 1
    print('reusable-ticket-reconcile.yml: called only; the guard arms on push/schedule/dispatch to '
          'the default branch and refuses pull requests, chained runs and other refs; one job '
          'holds the environment, contents: read and a timeout; no expression in any run: block; '
          'the extracted step refuses with no credential and with absent findings (exit 3) and '
          'hands its exit code to the posture step under bash -e; the scheduled sweep runs in its '
          'own job with no environment and no secret (T-21) and reports an elapsed deferral. '
          'Hosted behaviour is NOT proven here.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
