#!/usr/bin/env python3
"""KIT_CLOUD is Azure-only: no AWS job reads it, and only Azure paths do. (owner 2026-11-07)

WHY THIS EXISTS
    The estate mixes Azure commercial, Azure Government and AWS commercial. KIT_CLOUD names an AZURE cloud
    (commercial or gov). Read by an AWS job it would mean nothing, or worse, be taken for an AWS partition;
    read organisation-wide it would classify every tenant alike, which is why the deploys take the cloud per
    environment from the org overlay (scripts/org_settings.py). This check holds the tree to that:

    K1  every workflow job that reads KIT_CLOUD (vars.KIT_CLOUD, or the job env carrying it) signs in to Azure
        (an azure/login step, the azure-login-oidc composite) or calls a kit Azure reusable (a deploy, the
        rollback sequence); every composite action that reads it is an Azure one
    K2  no job that signs in to AWS (aws-actions/*, an AWS role or the AWS CLI's credentials) reads KIT_CLOUD
    K3  every script that names KIT_CLOUD is on the list below, each with its Azure-only reason
    K4  the AWS jobs found are listed by name (today: none in the kit); the rule holds for every one that appears
    --self-test  mutants: an AWS job that reads KIT_CLOUD, a job that reads it with no Azure step, and a new
        script that reads it are each refused

EXIT 0 holds   1 a rule refused (each named)   2 could not be checked (no PyYAML)
"""
import glob
import io
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS_ALLOWED = {
    'scripts/kit_init.py': 'writes KIT_CLOUD into the checklist of a repository that deploys to Azure',
    'scripts/reconcile_taxonomy.py': 'lists the variable names the hand-off vends (an inventory, never a read)',
    'scripts/org_settings.py': 'the Azure cloud resolver itself (KIT_CLOUD arrives as --bound-cloud)',
    'scripts/kit_org_init.py': 'names KIT_CLOUD among the variables wrong at organisation level (a name check, never a read)',
}
AZURE_REUSABLES = ('reusable-build-docker.yml', 'reusable-deploy-appservice.yml', 'reusable-deploy-containerapp.yml', 'reusable-deploy-staticwebapp.yml',
                   'reusable-rollback-sequence.yml', 'verify-azure-oidc.yml')
AWS_RX = re.compile(r'aws-actions/|AWS_ROLE_ARN|role-to-assume|AWS_ACCESS_KEY_ID|AWS_WEB_IDENTITY')
READ_RX = re.compile(r'\bKIT_CLOUD\b')


def _jobs(path):
    import yaml
    try:
        doc = yaml.safe_load(io.open(path, encoding='utf-8').read()) or {}
    except Exception:  # noqa: BLE001 -- an unreadable workflow is a different check's failure
        return {}
    return doc.get('jobs') or {}


def job_facts(job):
    import yaml
    text = yaml.safe_dump(job, sort_keys=True)
    uses = [str((s or {}).get('uses') or '') for s in (job.get('steps') or [])] + [str(job.get('uses') or '')]
    azure = any(u.startswith('azure/login@') or u.endswith('/azure-login-oidc') or
                any(u.split('@')[0].endswith(r) for r in AZURE_REUSABLES) for u in uses)
    return bool(READ_RX.search(text)), azure, bool(AWS_RX.search(text))


def problems(root):
    probs, aws_jobs = [], []
    files = sorted(glob.glob(os.path.join(root, '.github', 'workflows', '*.yml')) +
                   glob.glob(os.path.join(root, 'templates', '*.yml')) +
                   glob.glob(os.path.join(root, 'overlays', '*', 'workflows', '*.yml')) +
                   glob.glob(os.path.join(root, 'overlays', '*', 'templates', '*.yml')))
    for p in files:
        rel = os.path.relpath(p, root).replace(os.sep, '/')
        if rel == '.github/workflows/self-test.yml':
            continue   # the kit's own CI names the setting in its proofs' comments; it never signs in with it
        for jn, job in _jobs(p).items():
            reads, azure, aws = job_facts(job or {})
            if aws:
                aws_jobs.append('%s:%s' % (rel, jn))
                if reads:
                    probs.append('K2 %s job %s signs in to AWS and reads KIT_CLOUD (an Azure-only setting)' % (rel, jn))
            elif reads and not azure:
                probs.append('K1 %s job %s reads KIT_CLOUD but signs in to no Azure cloud' % (rel, jn))
    for p in sorted(glob.glob(os.path.join(root, '.github', 'actions', '*', 'action.yml'))):
        rel = os.path.relpath(p, root).replace(os.sep, '/')
        t = io.open(p, encoding='utf-8').read()
        if READ_RX.search(t) and not ('azure/login@' in t or 'azure' in rel or 'org-settings' in rel):
            probs.append('K1 %s reads KIT_CLOUD and is not an Azure composite' % rel)
        if READ_RX.search(t) and AWS_RX.search(t):
            probs.append('K2 %s reads KIT_CLOUD beside an AWS sign-in' % rel)
    for p in sorted(glob.glob(os.path.join(root, 'scripts', '*.py')) + glob.glob(os.path.join(root, 'scripts', '*.sh'))):
        rel = os.path.relpath(p, root).replace(os.sep, '/')
        if READ_RX.search(io.open(p, encoding='utf-8', errors='replace').read()) and rel not in SCRIPTS_ALLOWED:
            probs.append('K3 %s names KIT_CLOUD and is not on the Azure-only list in tests/check_kit_cloud_scope.py' % rel)
    return probs, aws_jobs


def self_test():
    work = tempfile.mkdtemp(prefix='kit-cloud-')
    try:
        os.makedirs(os.path.join(work, '.github', 'workflows'))
        os.makedirs(os.path.join(work, 'scripts'))
        cases = [
            ('aws', 'jobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n'
                    '        with: {role-to-assume: r, aws-region: us-east-1}\n      - run: echo "${{ vars.KIT_CLOUD }}"\n', 'K2'),
            ('noazure', 'jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo "${{ vars.KIT_CLOUD }}"\n', 'K1'),
            ('ok', 'jobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: azure/login@v2\n'
                   '        with: {environment: "${{ vars.KIT_CLOUD }}"}\n', None),
            ('awsclean', 'jobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n', None),
        ]
        bad = 0
        for name, text, want in cases:
            for f in glob.glob(os.path.join(work, '.github', 'workflows', '*.yml')):
                os.remove(f)
            io.open(os.path.join(work, '.github', 'workflows', name + '.yml'), 'w', encoding='utf-8').write(text)
            probs, _a = problems(work)
            got = probs[0][:2] if probs else None
            print('  mutant %-9s %s' % (name, 'caught (%s)' % got if want and got == want else
                                       ('clean' if not want and not probs else 'WRONG: %r' % probs)))
            bad += (got != want)
        io.open(os.path.join(work, 'scripts', 'new.py'), 'w', encoding='utf-8').write("x = os.environ['KIT_CLOUD']\n")
        probs, _a = problems(work)
        k3 = any(p.startswith('K3') for p in probs)
        print('  mutant script    %s' % ('caught (K3)' if k3 else 'MISSED'))
        bad += not k3
        print('check_kit_cloud_scope selftest %s' % ('ok' if not bad else 'FAILED'))
        return 0 if not bad else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv):
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable')
        return 2
    if '--self-test' in argv:
        return self_test()
    probs, aws = problems(ROOT)
    print('AWS sign-in jobs found: %s' % (', '.join(aws) or 'none in this kit (the rule still holds for any that appears)'))
    for p in probs:
        print('FAIL: ' + p)
    if probs:
        return 1
    print('PASS: KIT_CLOUD is read only by Azure jobs, Azure composites and the listed scripts; no AWS job reads it.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
