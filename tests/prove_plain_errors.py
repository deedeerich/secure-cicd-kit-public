#!/usr/bin/env python3
"""A developer reads the plain sentence first, and every refusal the kit can show has one (owner, 2026-11-06).

WHY THIS EXISTS
    Developers new to security tooling were handed state names (BLOCKED, ENVIRONMENT_REVIEWERS_ABSENT,
    PROMOTION_REFUSED_NOT_VERIFIED) and pointers to records they had never seen. docs/errors/errors.json
    says each in plain words -- what happened, why it matters, the exact fix, a link -- and the workflows
    put that sentence at the top of the run page (an annotation titled with it) and first in the job
    summary, with the state in brackets after it. This holds all of that.

WHAT IT PROVES
  POSITIVE
    P1  scripts/plain_errors.py check passes on this tree: every namespace of assurance-taxonomy.yaml is
        scoped, every value of a developer namespace has an entry or is listed as not a failure, every
        entry is complete and links to a file that exists, and ERRORS.md is the rendered catalogue
    P2  a BLOCKED gate: the annotation's TITLE is the plain sentence and its message ends "[BLOCKED]" with
        the fix; the summary section "What happened, in plain words" carries what, why, fix and link, with
        the plain sentence before the state name
    P3  the six outputs are wired: the gate, the three deploys, ticketing (both jobs), the triage, the API
        (refusal and every answer) and the preflight (verify-azure-oidc) each run the explanation on every
        path (if: always(), the API refusal on its own condition), BEFORE the gate's exit and before each
        deploy keeps its evidence; every step a states line reads exists in that job; every namespace a
        states line names is a developer namespace of the catalogue
    P4  parsing: comma lists, a detail after a colon (NO_KIT_ADAPTER:aks), empty values skipped, a
        not-a-failure state says nothing, a bare state is found in its namespace
    P5  the composite, run as shipped under bash with GITHUB_ACTION_PATH at its own directory, writes the
        annotation and the summary and exits 0
  NEGATIVE
    N1  a state the catalogue lacks is still shown, BY NAME, never dropped
    N2  an unreadable catalogue: the summary exits 0 with a warning (explaining never fails a job)
    N3  a newline or % in an entry cannot start a second workflow command (escaped)
  MUTANTS (scripts/plain_errors.py --self-test, run here, and one of this proof's own)
    M1  an entry removed -> C2 names it            M2  a new taxonomy value with no entry -> C2
    M3  an unscoped namespace -> C1                M4  an entry with no fix -> C3
    M5  a hand edit of ERRORS.md -> C5             M6  the gate's explanation step removed -> P3 refuses

EXIT 0 all hold   1 any does not   2 could not run (PyYAML or bash missing)
"""
import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML not available.')
    sys.exit(2)
import plain_errors as PE  # noqa: E402

FAILS = []
WF = os.path.join(ROOT, '.github', 'workflows')
# (workflow, job, source, the step it must precede or None)
WIRED = [
    ('reusable-security.yml', 'security-gate', 'gate', 'Exit on the verdict'),
    ('reusable-deploy-containerapp.yml', 'deploy', 'deploy', 'Keep the run record (deploy evidence)'),
    ('reusable-deploy-appservice.yml', 'deploy', 'deploy', 'Keep the run record (deploy evidence)'),
    ('reusable-deploy-staticwebapp.yml', 'deploy', 'deploy', 'Keep the run record (deploy evidence)'),
    ('reusable-ticket-reconcile.yml', 'reconcile', 'ticketing', 'Keep the run record and the ledger proposal'),
    ('reusable-ticket-reconcile.yml', 'resurface', 'ticketing', "Keep the clock's run record"),
    ('reusable-dependabot-triage.yml', 'classify', 'triage', 'Keep the decision record'),
    ('reusable-kit-api.yml', 'intake', 'api', None),
    ('reusable-kit-api.yml', 'tickets', 'api', None),
    ('reusable-kit-api.yml', 'finish', 'api', None),
    ('verify-azure-oidc.yml', 'verify', 'preflight', 'Fail the run if the boundary was not established'),
]


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[:500]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)
    return cond


def explain_steps(job):
    out = []
    for i, s in enumerate(job.get('steps') or []):
        if ('plain-errors' in str(s.get('uses', '')) or 'plain_errors.py summary' in str(s.get('run', '')) or
                'dependabot_triage_rule' in str(s.get('run', ''))):
            text = str((s.get('with') or {}).get('states', '')) + str((s.get('env') or {}).get('PE_STATES', ''))
            out.append((i, s, text))
    return out


def wiring_problems(docs, cat):
    probs = []
    for wf, jn, source, before in WIRED:
        job = (docs[wf].get('jobs') or {}).get(jn) or {}
        steps = job.get('steps') or []
        ex = explain_steps(job)
        if not ex:
            probs.append('%s job %s: no plain-English step' % (wf, jn))
            continue
        ids = {s.get('id') for s in steps if s.get('id')}
        names = [s.get('name') for s in steps]
        for i, s, text in ex:
            cond = str(s.get('if', ''))
            if 'dependabot_triage_rule' in str(s.get('run', '')):
                if 'always()' not in cond or 'T_RULE' not in str(s.get('env', '')):
                    probs.append('%s job %s: the triage sentence does not run on every decision' % (wf, jn))
                continue
            if 'always()' not in cond and "accepted != 'true'" not in cond:
                probs.append('%s job %s: the explanation does not run on every path (if: %r)' % (wf, jn, cond))
            if before and before in names and i > names.index(before):
                probs.append('%s job %s: the explanation comes after %r' % (wf, jn, before))
            for ref in re.findall(r'steps\.([A-Za-z0-9_-]+)\.outputs', text):
                if ref not in ids:
                    probs.append('%s job %s: reads steps.%s, which this job does not have' % (wf, jn, ref))
            for ns in re.findall(r'(?:^|\s)([a-z_]+):\$\{\{', text):
                if cat['scope'].get(ns) != 'developer':
                    probs.append('%s job %s: %s is not a developer namespace of the catalogue' % (wf, jn, ns))
            src = str((s.get('with') or {}).get('source', '')) or ('ticketing' if '--source ticketing' in str(s.get('run', '')) else '')
            if src != source:
                probs.append('%s job %s: source %r, not %r' % (wf, jn, src, source))
    return probs


def main():
    cat = PE.load()
    print('POSITIVE')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'plain_errors.py'), 'check'],
                       capture_output=True, text=True)
    check(p.returncode == 0, 'P1 plain_errors.py check: every taxonomy refusal has a plain entry', p.stdout[-600:])
    out = io.StringIO()
    summ = tempfile.NamedTemporaryFile('w', delete=False, suffix='.md')
    summ.close()
    try:
        PE.summary(cat, PE.parse_states('routing_result:BLOCKED advisory_cause:'), 'gate', out=out, summary_path=summ.name)
        ann = out.getvalue().strip().splitlines()
        md = io.open(summ.name, encoding='utf-8').read()
    finally:
        os.unlink(summ.name)
    ent = cat['entries']['routing_result.BLOCKED']
    title = PE.esc_prop(ent['what'][:240])
    check(len(ann) == 1 and ann[0].startswith('::error title=%s::' % title) and '[BLOCKED]' in ann[0] and 'Fix: ' in ann[0],
          'P2 the annotation is titled with the plain sentence; the state follows in brackets', ann)
    check('What happened, in plain words' in md and md.index(ent['what']) < md.index('[BLOCKED]') and
          ent['fix'] in md and ent['link'] in md and ent['why'] in md,
          'P2 the summary leads with the plain sentence, then why, the fix and the link')
    docs = {wf: yaml.safe_load(io.open(os.path.join(WF, wf), encoding='utf-8')) for wf in {w[0] for w in WIRED}}
    probs = wiring_problems(docs, cat)
    check(not probs, 'P3 gate, deploys, ticketing, triage, API and preflight explain every refusal, first', probs)
    toks = PE.parse_states('deployment_outcome:DEPLOY_REFUSED advisory_cause:VERSION_GAP,KEV_UNAVAILABLE x:  '
                           'deploy_coverage:NO_KIT_ADAPTER:aks routing_result:PROCEED')
    check(toks == ['deployment_outcome.DEPLOY_REFUSED', 'advisory_cause.VERSION_GAP', 'advisory_cause.KEV_UNAVAILABLE',
                   'deploy_coverage.NO_KIT_ADAPTER', 'routing_result.PROCEED'], 'P4 lists, details and empties parse', toks)
    rows = PE.explain_lines(cat, toks)
    check([r[1] for r in rows] == toks[:4], 'P4 a not-a-failure state (PROCEED) says nothing; the rest are explained', rows)
    check(PE.lookup(cat, 'ENVIRONMENT_REVIEWERS_ABSENT')[0][0] == 'environment_protection.ENVIRONMENT_REVIEWERS_ABSENT',
          'P4 a bare state is found in its namespace')
    bash = shutil.which('bash')
    if bash:
        a = yaml.safe_load(io.open(os.path.join(ROOT, '.github', 'actions', 'plain-errors', 'action.yml'), encoding='utf-8'))
        body = a['runs']['steps'][0]['run']
        tmp = tempfile.mkdtemp()
        try:
            sp = os.path.join(tmp, 'summary.md')
            script = os.path.join(tmp, 'step.sh')
            io.open(script, 'w', encoding='utf-8', newline='\n').write(body)
            env = dict(os.environ, GITHUB_ACTION_PATH=os.path.join(ROOT, '.github', 'actions', 'plain-errors').replace('\\', '/'),
                       GITHUB_STEP_SUMMARY=sp.replace('\\', '/'), PE_STATES='environment_protection:ENVIRONMENT_REVIEWERS_ABSENT',
                       PE_SOURCE='deploy', KIT_DOCS_BASE='https://example.ghe.com/acme/kit/blob/abc')
            r = subprocess.run([bash, script.replace('\\', '/')], capture_output=True, text=True, env=env)
            md = io.open(sp, encoding='utf-8').read() if os.path.exists(sp) else ''
            check(r.returncode == 0 and '::error title=' in r.stdout and '[ENVIRONMENT_REVIEWERS_ABSENT]' in r.stdout and
                  'https://example.ghe.com/acme/kit/blob/abc/docs/adoption/SETUP.md' in r.stdout and '(deploy)' in md,
                  'P5 the composite, run as shipped, explains and exits 0', (r.returncode, r.stdout[-300:], r.stderr[-300:]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        print('UNKNOWN: bash is required for P5.')
        return 2
    print('NEGATIVE')
    out = io.StringIO()
    PE.summary(cat, ['routing_result.SOMETHING_NEW'], 'gate', out=out, summary_path=os.devnull)
    check('[SOMETHING_NEW]' in out.getvalue() and out.getvalue().startswith('::error'),
          'N1 a state with no entry is shown by name, never dropped', out.getvalue())
    bad = tempfile.mkdtemp()
    try:
        saved = PE.CATALOGUE
        PE.CATALOGUE = os.path.join(bad, 'missing.json')
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = PE.main(['summary', '--states', 'routing_result:BLOCKED'])
        PE.CATALOGUE = saved
        check(rc == 0 and 'could not be read' in buf.getvalue() and '::error' not in buf.getvalue(),
              'N2 an unreadable catalogue: the summary exits 0 and says so (explaining never fails a job)', buf.getvalue())
    finally:
        shutil.rmtree(bad, ignore_errors=True)
    evil = copy.deepcopy(cat)
    evil['entries']['routing_result.BLOCKED'] = dict(ent, what='Bad.\n::error::injected %0A', why='w\r\nx', fix='f%')
    out = io.StringIO()
    PE.summary(evil, ['routing_result.BLOCKED'], 'gate', out=out, summary_path=os.devnull)
    lines = [l for l in out.getvalue().splitlines() if l.startswith('::')]
    check(len(lines) == 1 and '%0A' in lines[0] and '%25' in lines[0], 'N3 a newline or % cannot start a second command', lines)
    print('MUTANTS')
    r = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'plain_errors.py'), '--self-test'],
                       capture_output=True, text=True)
    check(r.returncode == 0 and '5 mutants refused' in r.stdout, 'M1-M5 the check refuses each mutant', r.stdout[-300:])
    m6 = copy.deepcopy(docs)
    steps = m6['reusable-security.yml']['jobs']['security-gate']['steps']
    m6['reusable-security.yml']['jobs']['security-gate']['steps'] = [s for s in steps if 'plain-errors' not in str(s.get('uses', ''))]
    check(any('security-gate' in p for p in wiring_problems(m6, cat)), 'M6 the gate without its explanation is refused')
    if FAILS:
        print('FAIL: %d check(s): %s' % (len(FAILS), '; '.join(FAILS)))
        return 1
    print('PASS: every refusal the kit can show has a plain sentence, and the six outputs put it first.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
