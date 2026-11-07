#!/usr/bin/env python3
"""The Jira host may be a SECRET: read from secrets first, the variable second, and never written out.
NO NETWORK.

WHY (owner, 2026-11-04)
    "Yes jira host is now a secret." A personal or organisation Jira site is information about the
    tracker's owner. On a public repository every variable is printed verbatim in run logs; a
    secret is masked. The kit read `vars.JIRA_HOST` only, so a host held as a secret never reached
    the tracker step, and the only working configuration put the host in the log.

WHAT IT PROVES
    H1  every reusable workflow that hands JIRA_HOST to a step reads
        `secrets.JIRA_HOST || vars.JIRA_HOST`, and declares JIRA_HOST as an OPTIONAL workflow_call
        secret (a caller without it still works from the variable).
    H2  every shipped template that passes JIRA_TOKEN to a reusable also passes
        `JIRA_HOST: ${{ secrets.JIRA_HOST }}`.
    H3  the expression, evaluated: a secret-only configuration yields the secret; a variable-only
        one the variable; both, the secret.
    H4  no step script names $JIRA_HOST (nothing echoes or writes it; the scripts read it from env).
    H5  end to end through the reconciler on a stateful stand-in Jira, configured with the host
        alone (as the step's env has it from the secret): tickets are created, and the host appears
        in none of stdout, stderr, the result or the ledger. The cloud-id lookup refusal (bearer
        with no JIRA_CLOUD_ID, the lookup answering no id) names JIRA_HOST, never its value.
    H6  mutants: a reusable reading `vars.JIRA_HOST` alone fails H1; a caller that drops the
        secret fails H2; an output carrying the host fails H5's scan.
    H7  EITHER FORM (2026-11-06): the reconciler accepts the bare host (`<site>.atlassian.net`) as
        well as `https://<site>.atlassian.net` (a trailing slash allowed) and talks to the same https
        origin; plain http, another scheme, a path, credentials and an empty value stay refused. With
        the reference gate's G11 this lets ONE JIRA_HOST value serve every reader.

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import contextlib
import glob
import io
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

FAILS = []
SENTINEL = 'sentinel-host-7f3a'
HOST = 'https://%s.atlassian.net' % SENTINEL
WANT_EXPR = '${{ secrets.JIRA_HOST || vars.JIRA_HOST }}'


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)


def reusable_problems(name, text):
    """-> problems for one reusable workflow's text (H1)."""
    import yaml
    doc = yaml.safe_load(text) or {}
    on = doc.get('on', doc.get(True)) or {}
    declared = (((on.get('workflow_call') or {}).get('secrets')) or {})
    probs = []
    uses = 0
    for jname, job in (doc.get('jobs') or {}).items():
        for st in (job.get('steps') or []):
            env = st.get('env') or {}
            if 'JIRA_HOST' in env:
                uses += 1
                if str(env['JIRA_HOST']).strip() != WANT_EXPR:
                    probs.append('%s job %s step %r reads JIRA_HOST as %r, not %s'
                                 % (name, jname, st.get('name') or st.get('id'), env['JIRA_HOST'], WANT_EXPR))
    if uses:
        d = declared.get('JIRA_HOST')
        if not isinstance(d, dict):
            probs.append('%s does not declare JIRA_HOST as a workflow_call secret' % name)
        elif d.get('required') not in (False, None):
            probs.append('%s declares JIRA_HOST as a REQUIRED secret (the variable must still work)' % name)
    return uses, probs


def caller_problems(name, text):
    """-> problems for one template's text (H2)."""
    import yaml
    doc = yaml.safe_load(text) or {}
    probs = []
    for jname, job in (doc.get('jobs') or {}).items():
        sec = job.get('secrets')
        if isinstance(sec, dict) and 'JIRA_TOKEN' in sec:
            if str(sec.get('JIRA_HOST', '')).strip() != '${{ secrets.JIRA_HOST }}':
                probs.append('%s job %s passes JIRA_TOKEN but not JIRA_HOST from secrets' % (name, jname))
    return probs


def evaluate(expr, secrets, variables):
    """The two-operand `a || b` this check requires, evaluated as GitHub does (empty is falsy)."""
    m = re.match(r'^\$\{\{\s*secrets\.(\w+)\s*\|\|\s*vars\.(\w+)\s*\}\}$', expr.strip())
    if not m:
        raise ValueError('not the required expression: %r' % expr)
    return secrets.get(m.group(1)) or variables.get(m.group(2)) or ''


def h1_h2_h4():
    wf = sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', 'reusable-*.yml')))
    total = 0
    for p in wf:
        text = io.open(p, encoding='utf-8').read()
        uses, probs = reusable_problems(os.path.basename(p), text)
        total += uses
        for pr in probs:
            check(False, 'H1 ' + pr)
        if uses and not probs:
            check(True, 'H1 %s: %d step(s) read the secret first, the secret is declared optional'
                  % (os.path.basename(p), uses))
        for rx in (r'\$JIRA_HOST\b', r'\$\{JIRA_HOST\}'):
            hit = re.search(rx, text)
            check(not hit, 'H4 %s: no step script names JIRA_HOST' % os.path.basename(p))
    check(total >= 4, 'H1 the Jira host reaches %d step(s) across the reusables (at least 4 expected)' % total)
    for p in sorted(glob.glob(os.path.join(ROOT, 'templates', '*.yml'))):
        probs = caller_problems(os.path.basename(p), io.open(p, encoding='utf-8').read())
        for pr in probs:
            check(False, 'H2 ' + pr)
    check(not [f for f in FAILS if f.startswith('H2')], 'H2 every template passing JIRA_TOKEN passes JIRA_HOST from secrets')


def h3():
    check(evaluate(WANT_EXPR, {'JIRA_HOST': HOST}, {}) == HOST, 'H3 secret only: the secret is used')
    check(evaluate(WANT_EXPR, {}, {'JIRA_HOST': 'https://v.atlassian.net'}) == 'https://v.atlassian.net',
          'H3 variable only: the variable is used')
    check(evaluate(WANT_EXPR, {'JIRA_HOST': HOST}, {'JIRA_HOST': 'https://v.atlassian.net'}) == HOST,
          'H3 both: the secret wins')


def leaks(blob):
    return SENTINEL in blob


def h5():
    import prove_ticket_backends as ptb
    import prove_jira_auth_and_routing as par
    import reconcile_tickets as rt
    real = urllib.request.urlopen
    try:
        r = ptb.install(ptb.Replay())
        jira = par.TwoProjectJira(r)
        ledger = {}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            res1 = par._run(rt, jira, par.RECORDS, ledger, None, extra={'JIRA_HOST': HOST})
            res2 = par._run(rt, jira, par.RECORDS, ledger, None, extra={'JIRA_HOST': HOST})
        created = len(jira.created_in)
        check(created >= 1, 'H5 a host-only (secret) configuration reconciles: %d ticket(s) created' % created)
        check(all(SENTINEL in x['url'] for x in r.requests if 'atlassian.net' in x['url']) and
              any(SENTINEL in x['url'] for x in r.requests),
              'H5 the requests went to the secret host')
        blob = json.dumps([res1, res2, ledger], default=str) + buf.getvalue()
        check(not leaks(blob), 'H5 the host appears in no stdout, stderr, result or ledger')
        # The cloud-id lookup refusal: bearer, no cloud id, the lookup answers no id.
        r2 = ptb.install(ptb.Replay())
        r2.on('GET', r'/_edge/tenant_info$', ptb.ok({}))
        env = dict(ptb.JIRA_ENV, JIRA_HOST=HOST, JIRA_AUTH_MODE='bearer')
        env.pop('JIRA_EMAIL', None)
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2), contextlib.redirect_stderr(buf2):
            try:
                b, note = rt.choose_backend(env)
                said = note or ''
                if b is not None:
                    ok, why = b.validate() if hasattr(b, 'validate') else (None, '')
                    said += ' %s' % (why,)
            except Exception as exc:                  # noqa: BLE001
                said = '%s: %s' % (type(exc).__name__, exc)
        out = said + buf2.getvalue()
        check('JIRA_CLOUD_ID' in out or 'tenant_info' in out,
              'H5 the cloud-id lookup refusal is named (%s)' % out.strip()[:120].replace(SENTINEL, '<host>'))
        check(not leaks(out), 'H5 the cloud-id lookup refusal names JIRA_HOST, never its value')
    finally:
        urllib.request.urlopen = real


def h6():
    p = os.path.join(ROOT, '.github', 'workflows', 'reusable-ticket-reconcile.yml')
    text = io.open(p, encoding='utf-8').read()
    _, probs = reusable_problems('mutant', text.replace(WANT_EXPR, '${{ vars.JIRA_HOST }}'))
    check(bool(probs), 'H6 mutant: a reusable reading vars.JIRA_HOST alone is caught by H1')
    tp = os.path.join(ROOT, 'templates', 'ticket-reconcile.yml')
    ttext = io.open(tp, encoding='utf-8').read()
    check(bool(caller_problems('mutant', re.sub(r'\n\s*JIRA_HOST: \$\{\{ secrets\.JIRA_HOST \}\}', '', ttext))),
          'H6 mutant: a template that drops the JIRA_HOST secret is caught by H2')
    check(leaks(json.dumps({'url': HOST + '/rest/api/3/issue/1'})), 'H6 mutant: an output carrying the host is caught by H5')


def h7():
    """Either form: the bare host and the https:// form both reach the same https origin; anything
    else the reconciler refused before is still refused."""
    import prove_ticket_backends as ptb
    import reconcile_tickets as rt
    bare = '%s.atlassian.net' % SENTINEL
    for label, value in (('the bare host', bare), ('the https:// form', HOST),
                         ('the https:// form with a slash', HOST + '/'), ('the bare host with a slash', bare + '/'),
                         ('the bare host with spaces', '  %s  ' % bare)):
        env = dict(ptb.JIRA_ENV, JIRA_HOST=value)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            b, note = rt.choose_backend(env)
        check(b is not None and getattr(b, 'host', None) == HOST,
              'H7 %s is accepted and becomes the https origin (%s)' % (
                  label, (note or '').replace(SENTINEL, '<host>')[:80]))
    for label, value in (('a plain-http host', 'http://%s' % bare), ('a bare host with a path', bare + '/jira'),
                         ('a bare host with credentials', 'u:p@%s' % bare), ('another scheme', 'ftp://%s' % bare),
                         ('an empty host', '   ')):
        env = dict(ptb.JIRA_ENV, JIRA_HOST=value)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            b, note = rt.choose_backend(env)
        check(b is None, 'H7 %s is still refused (%s)' % (label, (note or '').replace(SENTINEL, '<host>')[:90]))


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    h1_h2_h4()
    h3()
    h5()
    h6()
    h7()
    print()
    if FAILS:
        print('FAIL: %d check(s): the Jira host cannot yet be held as a secret.' % len(FAILS))
        return 1
    print('PASS: the Jira host is read from a secret first (the variable second), passed by every template,')
    print('      named by no step script, and written to no output, result or ledger.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
