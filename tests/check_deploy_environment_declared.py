#!/usr/bin/env python3
"""No kit deploy reaches an environment without GitHub's own environment wait, whatever the trigger. (KDEC-042)

WHY THIS EXISTS (owner, 2026-11-06)
    "Never a prod deployment without a human approval", EVEN IF someone pushes straight from a branch to
    main. GitHub holds a job that declares `environment: <name>` until that environment's required
    reviewers approve; a job without `environment:` is never held. The kit's deploy reusables are pinned by
    SHA in the caller, so the caller cannot remove the declaration -- provided it is there, unconditional,
    and fed by a required input. A push and a workflow_dispatch reach the same job, so the same wait.

THE RULES (each refusal names the file and job)
    E1  every job of a kit deploy reusable (DEPLOY_REUSABLES) that signs in to a cloud declares
        `environment: ${{ inputs.github_environment }}` exactly -- no other value, nothing conditional
    E2  that input is `required: true` with no default
    E3  every other workflow job, in any workflow or template, that runs a deploy command (az webapp /
        containerapp update / staticwebapp / swa deploy / slot swap) declares an environment
    E4  the three deploys run the `protection` step with no `if:` and no continue-on-error, before any login
    E5  every caller (templates/*.yml and the kit's own workflows) of a kit deploy reusable passes
        github_environment as a non-empty literal or one plain `${{ inputs.X }}` / `${{ needs.J.outputs.X }}`
        / `${{ matrix.X }}` -- never an expression that picks by trigger, branch or event, never empty
    E6  where that is `${{ inputs.X }}` of a workflow_dispatch, X's default is not empty

USAGE   python3 tests/check_deploy_environment_declared.py [--root DIR] | --self-test (mutants)
EXIT    0 held   1 a rule refused   2 could not run (PyYAML missing)
"""
import argparse
import glob
import io
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEPLOY_REUSABLES = ['reusable-deploy-appservice.yml', 'reusable-deploy-containerapp.yml',
                    'reusable-deploy-staticwebapp.yml', 'reusable-rollback-sequence.yml']
GATED_STEP_REUSABLES = DEPLOY_REUSABLES[:3]
WANT_ENV = '${{ inputs.github_environment }}'
LOGIN_RX = re.compile(r'azure/login@|\baz login\b|aws-actions/configure-aws-credentials@')
DEPLOY_RX = re.compile(r'\baz webapp (config container set|deployment)|\baz containerapp update\b|'
                       r'\baz staticwebapp\b|\bswa deploy\b|\bslot swap\b')
PLAIN_REF = re.compile(r'^\$\{\{\s*(inputs\.[\w-]+|needs\.[\w-]+\.outputs\.[\w-]+|matrix\.[\w-]+)\s*\}\}$')
LITERAL = re.compile(r'^[A-Za-z0-9][\w.-]*$')


def _load(path):
    import yaml
    with io.open(path, encoding='utf-8') as fh:
        return yaml.safe_load(fh) or {}


def _on(doc):
    return doc.get('on', doc.get(True)) or {}


def _steps_text(job):
    out = []
    for s in job.get('steps') or []:
        out.append(str(s.get('uses') or '') + '\n' + str(s.get('run') or ''))
    return '\n'.join(out)


def problems(root):
    probs = []
    wf_dir = os.path.join(root, '.github', 'workflows')
    for name in DEPLOY_REUSABLES:
        p = os.path.join(wf_dir, name)
        if not os.path.isfile(p):
            probs.append('E1 %s: a kit deploy reusable is missing' % name)
            continue
        doc = _load(p)
        inp = ((_on(doc).get('workflow_call') or {}).get('inputs') or {}).get('github_environment') or {}
        if inp.get('required') is not True or 'default' in inp:
            probs.append('E2 %s: github_environment is not a required input without a default' % name)
        for jn, job in (doc.get('jobs') or {}).items():
            text = _steps_text(job)
            if not (LOGIN_RX.search(text) or DEPLOY_RX.search(text)):
                continue
            env = job.get('environment')
            env = env.get('name') if isinstance(env, dict) else env
            if str(env or '').strip() != WANT_ENV:
                probs.append('E1 %s job %s signs in or deploys with environment %r, not %s'
                             % (name, jn, env, WANT_ENV))
            if name in GATED_STEP_REUSABLES:
                steps = job.get('steps') or []
                ids = [s.get('id') for s in steps]
                first_login = next((i for i, s in enumerate(steps) if LOGIN_RX.search(str(s.get('uses') or ''))
                                    or str(s.get('name') or '').lower().startswith(('azure login', 'aws login'))),
                                   len(steps))
                if 'protection' not in ids:
                    probs.append('E4 %s job %s has no protection step' % (name, jn))
                else:
                    s = steps[ids.index('protection')]
                    if 'if' in s or s.get('continue-on-error'):
                        probs.append('E4 %s job %s: the protection step can be skipped (if / continue-on-error)' % (name, jn))
                    if ids.index('protection') > first_login:
                        probs.append('E4 %s job %s: the protection step runs after a login' % (name, jn))
    callers = sorted(glob.glob(os.path.join(root, 'templates', '*.yml')) + glob.glob(os.path.join(wf_dir, '*.yml')))
    for p in callers:
        rel = os.path.relpath(p, root).replace('\\', '/')
        doc = _load(p)
        dispatch = ((_on(doc).get('workflow_dispatch') or {}) if isinstance(_on(doc), dict) else {}) or {}
        dinputs = dispatch.get('inputs') or {}
        for jn, job in (doc.get('jobs') or {}).items():
            uses = str(job.get('uses') or '')
            if os.path.basename(p) not in DEPLOY_REUSABLES and not uses and DEPLOY_RX.search(_steps_text(job)) \
                    and not job.get('environment'):
                probs.append('E3 %s job %s runs a deploy command with no environment' % (rel, jn))
            if not any(uses.split('@')[0].endswith('/' + r) for r in DEPLOY_REUSABLES):
                continue
            val = (job.get('with') or {}).get('github_environment')
            sval = str(val if val is not None else '').strip()
            if not sval or not (LITERAL.match(sval) or PLAIN_REF.match(sval)):
                probs.append('E5 %s job %s passes github_environment %r: not a literal name or one plain reference'
                             % (rel, jn, val))
                continue
            m = re.match(r'^\$\{\{\s*inputs\.([\w-]+)\s*\}\}$', sval)
            if m and m.group(1) in dinputs and not str(dinputs[m.group(1)].get('default', 'x') or '').strip() \
                    and dinputs[m.group(1)].get('type') != 'choice':
                probs.append('E6 %s job %s: workflow_dispatch input %s defaults to empty' % (rel, jn, m.group(1)))
    return probs


MUTANTS = [
    ('E1', '.github/workflows/reusable-deploy-containerapp.yml', '    environment: ${{ inputs.github_environment }}\n', ''),
    ('E1', '.github/workflows/reusable-deploy-appservice.yml', '    environment: ${{ inputs.github_environment }}\n',
     "    environment: ${{ github.event_name == 'push' && 'dev' || inputs.github_environment }}\n"),
    ('E1', '.github/workflows/reusable-rollback-sequence.yml', '    environment: ${{ inputs.github_environment }}\n', ''),
    ('E2', '.github/workflows/reusable-deploy-staticwebapp.yml',
     '      github_environment:\n', '      github_environment:\n        default: ""\n'),
    ('E4', '.github/workflows/reusable-deploy-appservice.yml', '        id: protection\n',
     '        id: protection\n        continue-on-error: true\n'),
    ('E5', 'templates/build-deploy.yml', '      github_environment: dev\n',
     "      github_environment: ${{ github.event_name == 'push' && '' || 'dev' }}\n"),
    ('E5', 'templates/build-deploy-static.yml', '      github_environment: test\n', '      github_environment: ""\n'),
    ('E3', 'templates/security.yml', '\njobs:\n', '\njobs:\n  rogue:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - run: az containerapp update -n app -g rg --image x\n'),
    ('E6', 'templates/build-deploy.yml', '        default: "dev"\n', '        default: ""\n'),
]


def self_test():
    base = problems(ROOT)
    if base:
        print('FAIL: the kit tree itself does not hold:\n  ' + '\n  '.join(base))
        return 2
    work = tempfile.mkdtemp(prefix='envdecl-')
    bad = []
    try:
        for rule, rel, old, new in MUTANTS:
            tree = os.path.join(work, 't')
            shutil.rmtree(tree, ignore_errors=True)
            for d in ('.github/workflows', 'templates'):
                shutil.copytree(os.path.join(ROOT, d), os.path.join(tree, d))
            p = os.path.join(tree, rel)
            t = io.open(p, encoding='utf-8').read()
            if old not in t:
                bad.append('mutant %s: %r not found in %s' % (rule, old.strip(), rel))
                continue
            io.open(p, 'w', encoding='utf-8', newline='\n').write(t.replace(old, new, 1))
            got = [x for x in problems(tree) if x.startswith(rule)]
            print('  mutant %-3s %-52s %s' % (rule, rel, 'caught' if got else 'MISSED'))
            if not got:
                bad.append('mutant %s in %s was not caught' % (rule, rel))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print('FAIL: ' + b)
    if bad:
        return 2
    print('check_deploy_environment_declared selftest ok: %d mutants caught.' % len(MUTANTS))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--root', default=ROOT)
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML is not installed')
        return 2
    if a.self_test:
        return self_test()
    probs = problems(a.root)
    for pr in probs:
        print('FAIL: ' + pr)
    if probs:
        return 1
    print('PASS: every kit deploy job declares environment: ${{ inputs.github_environment }} from a required input, '
          'runs the protection step before login, and every caller names its environment plainly: a push and a '
          'dispatch wait on the same environment reviewers.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
