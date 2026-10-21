#!/usr/bin/env python3
"""The pull-request ticket-reference gate, run as shipped: its ACTUAL step, out of the workflow file.

WHY THIS EXISTS

    A pull request must carry a well-formed reference to the Jira work item it implements. That gate
    used to live only in one consumer's overlay, with that consumer's 3-4 digit issue-number rule
    baked into its defaults. The owner decided on 2026-10-16 that the Jira reference gate is CORE
    (KDEC-013): every consumer gets it, and the only consumer-specific part left is the issue-number
    range a consumer may choose to impose. So the core ships the gate with NO range by default, and a
    consumer constrains the key format through two inputs.

    This proof extracts `jobs.validate-reference.steps[validate].run` from
    .github/workflows/reusable-ticket-reference.yml, feeds it the env: block the workflow declares
    (with the expression values a runner would substitute), writes it to a file and runs it under
    bash, which is what a runner does with a `run:` block. What runs here is what the runner runs.

WHAT IT PROVES
    G1  structure: called only (workflow_call), contents/pull-requests read, a timeout, and every
        caller value reaches the script through env: -- no expression inside the run: text
    G2  NO DEFAULT RESTRICTION: with no range configured a two-digit key is accepted. A neutral kit
        that rejected it would have adopted one consumer's numbering as everyone's policy
    G3  a consumer-supplied range is applied to the WHOLE number, first-valid-wins, and the rejected
        candidates are named with their digit counts
    G4  a half-configured or non-numeric range is refused as a PLATFORM problem, never as a pass and
        never as the developer's fault
    G5  missing reference / empty body fail; unconfigured blames the platform, not the developer
    G6  transport: no PR body shape executes, and a lone double quote does not truncate the body
    G7  the host is a literal, not a regex
    G8  a non-pull-request event is NOT ASSESSED: exit 0, and the summary says nothing was checked
    G9  every exit path prints ACTION REQUIRED and the assurance boundary

WHAT IT CANNOT PROVE
    That GitHub substitutes the expressions as the env: block says -- a hosted run proves that. And,
    by design, nothing here (or in the gate) establishes that the referenced issue EXISTS.

USAGE  python3 tests/prove_ticket_reference_gate.py
EXIT   0 every case behaved, 1 otherwise, 2 could not run
"""
import io
import os
import re
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML not available. Failure to observe is not an observation.')
    sys.exit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-ticket-reference.yml')
JOB = 'validate-reference'
HOST = 'jira.example.net'
PROJ = 'WORK'
B = 'https://%s/browse/%s' % (HOST, PROJ)


def _bash():
    """A POSIX bash that can see this repository (on Windows, plain `bash` may be WSL's)."""
    env = os.environ.get('BASH')
    if env and os.path.exists(env):
        return env
    pf = os.environ.get('ProgramFiles', 'C:' + os.sep + 'Program Files')
    for c in (os.path.join(pf, 'Git', 'bin', 'bash.exe'),
              os.path.join(pf, 'Git', 'usr', 'bin', 'bash.exe'),
              '/bin/bash', '/usr/bin/bash'):
        if os.path.exists(c):
            return c
    return 'bash'


BASH = _bash()


def load():
    return yaml.safe_load(io.open(WF, encoding='utf-8'))


def the_step(doc):
    for s in doc['jobs'][JOB]['steps']:
        if isinstance(s, dict) and s.get('id') == 'validate':
            return s
    raise KeyError('no step with id: validate in job %s' % JOB)


def structure(doc):
    """G1. -> list of problems."""
    p = []
    on = doc.get('on', doc.get(True)) or {}
    if not isinstance(on, dict) or set(on) != {'workflow_call'}:
        p.append('the workflow must be callable only (on: workflow_call), got %r' % (on,))
    ins = ((on or {}).get('workflow_call') or {}).get('inputs') or {}
    for name in ('tracker_host', 'project_key', 'min_digits', 'max_digits'):
        if name not in ins:
            p.append('input %s is not declared' % name)
    for name in ('min_digits', 'max_digits'):
        d = (ins.get(name) or {}).get('default', None)
        if d not in ('', None):
            p.append('input %s defaults to %r -- the core may not ship a ticket-number range'
                     % (name, d))
    job = doc['jobs'][JOB]
    perms = job.get('permissions', doc.get('permissions'))
    if perms != {'contents': 'read', 'pull-requests': 'read'} and \
            doc.get('permissions') != {'contents': 'read', 'pull-requests': 'read'}:
        p.append('permissions must be contents: read, pull-requests: read; got %r' % (perms,))
    if not job.get('timeout-minutes'):
        p.append('the job has no timeout-minutes')
    step = the_step(doc)
    run = step.get('run') or ''
    if '${{' in run:
        p.append('an expression appears INSIDE the run: script -- caller text would become code')
    env = step.get('env') or {}
    want = {
        'PR_BODY': 'github.event.pull_request.body',
        'EVENT_NAME': 'github.event_name',
        'TRACKER_HOST': 'inputs.tracker_host',
        'PROJECT_KEY': 'inputs.project_key',
        'MIN_DIGITS': 'inputs.min_digits',
        'MAX_DIGITS': 'inputs.max_digits',
    }
    for k, expr in want.items():
        if expr not in str(env.get(k, '')):
            p.append('env %s does not carry %s' % (k, expr))
    return p


def run(script, body, event='pull_request', mind='', maxd='', host=HOST, proj=PROJ):
    env = dict(os.environ)
    env.update({'PR_BODY': body, 'EVENT_NAME': event, 'TRACKER_HOST': host,
                'PROJECT_KEY': proj, 'MIN_DIGITS': mind, 'MAX_DIGITS': maxd})
    work = tempfile.mkdtemp(prefix='ticket-ref-')
    summ = os.path.join(work, 'summary.md')
    outp = os.path.join(work, 'output.txt')
    io.open(summ, 'w').close()
    io.open(outp, 'w').close()
    env['GITHUB_STEP_SUMMARY'] = summ
    env['GITHUB_OUTPUT'] = outp
    # Written to a file and executed, never `bash -c`: on Windows the command line rewrites
    # backslashes on the way in, and a runner executes a run: block from a file anyway.
    spath = os.path.join(work, 'step.sh')
    io.open(spath, 'w', encoding='utf-8', newline='\n').write(script)
    try:
        p = subprocess.run([BASH, spath], env=env, capture_output=True, text=True, cwd=work)
        out = p.stdout + p.stderr
        s = io.open(summ, encoding='utf-8', errors='replace').read()
        o = io.open(outp, encoding='utf-8', errors='replace').read()
    finally:
        for f in (spath, summ, outp):
            try:
                os.unlink(f)
            except OSError:
                pass
        try:
            os.rmdir(work)
        except OSError:
            pass
    return p.returncode, out, s, o


def main():
    if not os.path.exists(WF):
        print('FAIL: %s does not exist -- the core has no pull-request ticket-reference gate'
              % os.path.relpath(WF, ROOT))
        return 1
    doc = load()
    fails = ['G1 %s' % x for x in structure(doc)]
    script = the_step(doc)['run']

    # (label, body, kwargs, expect_rc, needle in summary/output, outcome output or None)
    cases = [
        ('G2 valid link, no range', 'See %s-1234' % B, {}, 0, 'WORK-1234', 'REFERENCE_FOUND'),
        ('G2 two-digit key accepted with no range', 'See %s-12' % B, {}, 0, 'WORK-12',
         'REFERENCE_FOUND'),
        ('G2 five-digit key accepted with no range', 'See %s-10034' % B, {}, 0, 'WORK-10034',
         'REFERENCE_FOUND'),
        ('G3 out-of-range first, in-range second',
         'Old/reference ticket: %s-12\nActual story: %s-1004' % (B, B),
         {'mind': '3', 'maxd': '4'}, 0, 'WORK-1004', 'REFERENCE_FOUND'),
        ('G3 five bad then one good',
         ' '.join('%s-%d' % (B, i) for i in range(1, 6)) + ' %s-1004' % B,
         {'mind': '3', 'maxd': '4'}, 0, 'WORK-1004', 'REFERENCE_FOUND'),
        ('G3 every candidate outside the range', '%s-1 and %s-22' % (B, B),
         {'mind': '3', 'maxd': '4'}, 1, 'WORK-22 (2 digits)', 'NO_CANDIDATE_PASSED'),
        ('G3 whole number counted (not truncated)', '%s-10034' % B,
         {'mind': '3', 'maxd': '4'}, 1, '5 digits', 'NO_CANDIDATE_PASSED'),
        ('G3 a different consumer range', '%s-123456' % B,
         {'mind': '6', 'maxd': '8'}, 0, 'WORK-123456', 'REFERENCE_FOUND'),
        ('G4 min without max refused', 'See %s-1234' % B, {'mind': '3'}, 1,
         'Platform owner', 'POLICY_MISCONFIGURED'),
        ('G4 non-numeric range refused', 'See %s-1234' % B, {'mind': 'three', 'maxd': '4'}, 1,
         'Platform owner', 'POLICY_MISCONFIGURED'),
        ('G4 min greater than max refused', 'See %s-1234' % B, {'mind': '5', 'maxd': '3'}, 1,
         'Platform owner', 'POLICY_MISCONFIGURED'),
        ('G5 no link', 'nothing here', {}, 1, 'NOT FOUND', 'NO_CANDIDATE'),
        ('G5 empty body', '', {}, 1, 'NOT FOUND', 'NO_TEXT'),
        ('G5 unconfigured blames the platform', 'x %s-1234' % B, {'host': '', 'proj': ''}, 1,
         'Developer action: **NONE**', 'NOT_CONFIGURED'),
        ('G6 quote before the link does not truncate',
         'He said "done" then linked %s-1234' % B, {}, 0, 'WORK-1234', 'REFERENCE_FOUND'),
        ('G7 dots in the host are literal', 'https://jiraXexampleXnet/browse/WORK-1234', {}, 1,
         'NOT FOUND', 'NO_CANDIDATE'),
        ('G8 a push is NOT ASSESSED, not passed', 'See %s-1234' % B, {'event': 'push'}, 0,
         'NOT ASSESSED', 'NOT_A_PULL_REQUEST'),
        ('G8 pull_request_target is assessed', 'See %s-1234' % B,
         {'event': 'pull_request_target'}, 0, 'WORK-1234', 'REFERENCE_FOUND'),
    ]

    print('%-46s %-4s %s' % ('case', 'rc', 'verdict'))
    print('-' * 78)
    for label, body, kw, want_rc, needle, outcome in cases:
        rc, out, summ, outputs = run(script, body, **kw)
        ok = rc == want_rc and (needle.lower() in summ.lower() or needle.lower() in out.lower())
        if outcome and ('outcome=%s' % outcome) not in outputs:
            ok = False
        print('%-46s %-4s %s' % (label[:46], rc, 'ok' if ok else
                                 'FAIL (wanted rc=%s, %r, outcome=%s; outputs=%r)'
                                 % (want_rc, needle, outcome, outputs.strip())))
        if not ok:
            fails.append(label)
        # G9: every path says who acts and what was NOT checked.
        if 'ACTION REQUIRED' not in summ:
            fails.append('G9 %s: no ACTION REQUIRED section' % label)
        if 'exists in Jira' not in summ and 'Nothing was checked' not in summ:
            fails.append('G9 %s: no assurance boundary on this path' % label)

    # G6: PR text must never execute, however it is shaped.
    canary = os.path.join(tempfile.gettempdir(), 'ticket_ref_canary_%d' % os.getpid())
    canary_posix = canary.replace('\\', '/')
    for shape in ('$(touch %s)' % canary_posix, '`touch %s`' % canary_posix,
                  '"; touch %s; "' % canary_posix, "'; touch %s; '" % canary_posix):
        run(script, 'ticket %s-1234 and %s' % (B, shape))
        if os.path.exists(canary):
            fails.append('G6 INJECTION: the PR body executed via %s' % shape[:20])
            os.unlink(canary)
    print('%-46s %-4s %s' % ('G6 PR body cannot execute (4 shapes)', '-',
                             'ok' if not any('INJECTION' in f for f in fails) else 'FAIL'))

    print('')
    if fails:
        print('FAILURES:')
        for f in fails:
            print('  - %s' % f)
        return 1
    print('PASS: the gate in the workflow file finds a well-formed Jira reference with NO default')
    print('      restriction on the issue number, applies a consumer-supplied range to the whole')
    print('      number, refuses a half-configured range as a platform problem, keeps the PR body')
    print('      as data, and reports a non-pull-request event as NOT ASSESSED rather than passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
