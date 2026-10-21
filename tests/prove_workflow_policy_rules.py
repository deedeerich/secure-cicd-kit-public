#!/usr/bin/env python3
"""Every rule of the workflow policy gate refuses a seeded violation (completion ledger L83).

WHY THIS EXISTS

    workflow-policy-check.yml is the gate a consumer runs over its own workflows (POLICY R1-R9). Its
    only proof was the kit's dogfood run -- one tree, soft-failed -- so no rule had a fixture that
    showed it can say no. Reading it found four holes:

      job uses   a JOB-level `uses:` (a reusable-workflow call, with the caller's secrets) was never
                 checked for pinning; only steps were
      images     `container:` and `services:` images, and `docker://` steps, were never checked
      R9         `inputs.*` was not an injectable context, though a dispatch input is typed text
      zero       a `workflows_path` that matched nothing exited 0: a green gate over zero files

WHAT IT PROVES
    The policy script is extracted from the shipped step and run against one constructed workflow
    per rule (the real tree is never read):
      R1 no ref; R1 moving branch; R2 untrusted tag; R3 no permissions; R4 pull_request_target head
      checkout; R5 azure/login creds; R6 deploy on push ungated; R7 deploy by tag; R8 secrets inherit
      (a WARN); R9 issue title in run; and the new rules -- a reusable-workflow call by tag, an
      unpinned container image, a tag-pinned service image, a `docker://` step on `latest`, and
      `inputs.*` in run -- each named in the output with the expected severity.
    ZERO   no workflow files: the script exits non-zero and records files_scanned=0, and the posture
           step, run as shipped, routes that EVIDENCE_UNTRUSTED (unavailable, not clean)
    CONTROL a clean workflow passes (rc 0, no ERROR)

EXIT  0 all hold   1 any does not   2 could not be checked
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
sys.path.insert(0, HERE)
WF = '.github/workflows/workflow-policy-check.yml'
SHA = 'a' * 40

HEAD = 'name: t\non:\n  push:\npermissions:\n  contents: read\njobs:\n'
CASES = [
    # (label, workflow text, want severity, substring of the finding)
    ('R1 step with no ref', HEAD + '  a:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - uses: someone/tool\n', 'ERROR', 'has no ref'),
    ('R1 moving branch', HEAD + '  a:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - uses: someone/tool@main\n', 'ERROR', 'moving branch'),
    ('R2 untrusted tag', HEAD + '  a:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - uses: someone/tool@v2\n', 'ERROR', 'not SHA-pinned'),
    ('R3 no permissions', 'name: t\non:\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n'
     '    steps:\n      - run: echo hi\n', 'ERROR', 'no `permissions:`'),
    ('R4 pull_request_target head', 'name: t\non:\n  pull_request_target:\npermissions:\n'
     '  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - uses: actions/checkout@v4\n        with:\n'
     '          ref: ${{ github.event.pull_request.head.sha }}\n', 'ERROR', 'fork code'),
    ('R5 azure/login creds', HEAD + '  a:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - uses: azure/login@v2\n        with:\n          creds: ${{ secrets.X }}\n',
     'ERROR', 'long-lived'),
    ('R6 deploy on push ungated', HEAD + '  deploy:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - run: echo deploying\n', 'ERROR', 'deploy-shaped job reachable from `push`'),
    ('R7 deploy by tag', HEAD + '  a:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - run: az containerapp update --name x --image myreg.io/app:1.2\n',
     'ERROR', 'without an `@sha256:` digest'),
    ('R8 secrets inherit', HEAD + '  a:\n    uses: actions/reusable/.github/workflows/x.yml@v1\n'
     '    secrets: inherit\n', 'WARN', 'secrets: inherit'),
    ('R9 issue title in run', HEAD + '  a:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - run: echo "${{ github.event.issue.title }}"\n', 'ERROR', 'attacker-controlled'),
    ('L83 reusable workflow by tag', HEAD + '  a:\n'
     '    uses: someone/kit/.github/workflows/x.yml@v1\n', 'ERROR', 'not SHA-pinned'),
    ('L83 reusable workflow on a branch', HEAD + '  a:\n'
     '    uses: someone/kit/.github/workflows/x.yml@main\n', 'ERROR', 'moving branch'),
    ('L83 container unpinned', HEAD + '  a:\n    runs-on: ubuntu-latest\n    container: node\n'
     '    steps:\n      - run: echo hi\n', 'ERROR', 'image `node` is unpinned'),
    ('L83 service image by tag', HEAD + '  a:\n    runs-on: ubuntu-latest\n    services:\n'
     '      db:\n        image: postgres:16\n    steps:\n      - run: echo hi\n',
     'ERROR', 'mutable tag'),
    ('L83 docker step on latest', HEAD + '  a:\n    runs-on: ubuntu-latest\n    steps:\n'
     '      - uses: docker://alpine:latest\n', 'ERROR', 'image `alpine:latest` is unpinned'),
    ('L83 inputs in run', 'name: t\non:\n  workflow_dispatch:\n    inputs:\n      who:\n'
     '        type: string\npermissions:\n  contents: read\njobs:\n  a:\n'
     '    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ inputs.who }}"\n',
     'ERROR', 'attacker-controlled'),
]
CLEAN = (HEAD + '  a:\n    runs-on: ubuntu-latest\n'
         '    container: node@sha256:' + 'b' * 64 + '\n    steps:\n'
         '      - uses: actions/checkout@v4\n'
         '      - uses: someone/tool@' + SHA + '  # v1.2.3\n'
         '      - env:\n          WHO: ${{ inputs.who }}\n        run: echo "$WHO"\n')


INPUTS = {'inputs.trusted_orgs': 'actions,github,azure,docker,hashicorp',
          'inputs.require_sha_pinning': 'true', 'inputs.allow_deploy_on_push': 'false'}


def policy_step():
    import _step_harness as H
    return H.step(WF, 'policy-check', 'policy')


def policy_script(step):
    m = re.search(r"<<'PYEOF'\n(.*?)\nPYEOF", step.get('run') or '', re.S)
    return m.group(1) if m else None


def run_policy(step, script, wf_dir, work):
    import _step_harness as H
    # ONE RELOCATION, declared: the script records its file count in /tmp for the shell to emit;
    # a probe must not write outside its own temp directory.
    script = script.replace('/tmp/policy_files_scanned', os.path.join(work, 'count').replace('\\', '/'))
    # The step's OWN env block, substituted as the runner does: the variable names are the shipped
    # ones, never retyped here.
    ctx = dict(INPUTS, **{'inputs.workflows_path': wf_dir})
    env = dict(os.environ, PYTHONUTF8='1')
    for k, v in (step.get('env') or {}).items():
        env[str(k)] = H.substitute(v, ctx)[0]
    env.pop('GITHUB_STEP_SUMMARY', None)
    env.pop('GITHUB_OUTPUT', None)
    p = subprocess.run([sys.executable, '-c', script], cwd=work, env=env, capture_output=True,
                       text=True, encoding='utf-8', errors='replace')
    return p.returncode, p.stdout + p.stderr


def finding(out, sev, text):
    return any(sev in ln and text in ln for ln in out.splitlines())


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    pstep = policy_step()
    script = policy_script(pstep) if pstep else None
    if not script:
        print('UNKNOWN: no policy heredoc in %s' % WF)
        return 2
    bad = []
    work = tempfile.mkdtemp(prefix='policy-rules-')
    try:
        for i, (label, text, sev, sub) in enumerate(CASES):
            d = os.path.join(work, 'c%d' % i, '.github', 'workflows')
            os.makedirs(d)
            io.open(os.path.join(d, 'w.yml'), 'w', encoding='utf-8').write(text)
            rc, out = run_policy(pstep, script, d, os.path.join(work, 'c%d' % i))
            ok = finding(out, sev, sub) and (rc != 0 if sev == 'ERROR' else True)
            print('  %-36s rc=%s %s' % (label, rc, 'ok' if ok else 'WRONG'))
            if not ok:
                bad.append('%s: no %s naming %r (rc=%s)' % (label, sev, sub, rc))
        d = os.path.join(work, 'clean', '.github', 'workflows')
        os.makedirs(d)
        io.open(os.path.join(d, 'w.yml'), 'w', encoding='utf-8').write(CLEAN)
        rc, out = run_policy(pstep, script, d, os.path.join(work, 'clean'))
        print('  %-36s rc=%s' % ('CONTROL clean workflow', rc))
        if rc != 0 or 'ERROR' in ''.join(ln for ln in out.splitlines() if ln.startswith('|')):
            bad.append('CONTROL a clean workflow was refused (rc=%s): %s' % (rc, out[-500:]))

        # ZERO: the whole shipped step, under bash, against a path that matches nothing.
        import _step_harness as H
        bash, why = H.usable_bash()
        if not bash:
            print('UNKNOWN: no usable bash for the shipped steps (%s)' % why)
            return 2
        ctx = {'inputs.workflows_path': '.github/workflows',
               'inputs.trusted_orgs': 'actions,github,azure,docker,hashicorp',
               'inputs.require_sha_pinning': 'true', 'inputs.allow_deploy_on_push': 'false',
               'inputs.soft_fail': 'false', 'inputs.weakening_reason': '',
               'inputs.weakening_authority': '', 'inputs.weakening_exception_ref': '',
               'inputs.weakening_expires': ''}
        zws = os.path.join(work, 'zero')
        os.makedirs(os.path.join(zws, '.github', 'workflows'))
        step = dict(H.step(WF, 'policy-check', 'policy'))
        # ONE RELOCATION, declared: /tmp -> this probe's workspace.
        step['run'] = step['run'].replace('/tmp/', zws.replace('\\', '/') + '/')
        r = H.run(bash, step, ctx, zws, extra_env={'PYTHON': sys.executable})
        files_scanned = r['outputs'].get('files_scanned')
        print('  %-36s rc=%s files_scanned=%r' % ('ZERO no workflow files (step)', r['rc'], files_scanned))
        if r['rc'] == 0:
            bad.append('ZERO a workflows_path matching no file exited 0: a green gate over nothing')
        if files_scanned != '0':
            bad.append('ZERO files_scanned=0 was not emitted for the posture step (%r)' % files_scanned)
        post = H.step(WF, 'policy-check', 'posture')
        for label, outcome, count, want in (('ZERO posture', 'failure', '0', 'EVIDENCE_UNTRUSTED'),
                                            ('count absent', 'success', '', 'EVIDENCE_UNTRUSTED'),
                                            ('CONTROL 3 files, clean', 'success', '3', 'PROCEED')):
            ws = os.path.join(work, 'posture-' + label.split()[0])
            os.makedirs(ws, exist_ok=True)
            pc = dict(ctx, **{'steps.policy.outcome': outcome,
                              'steps.policy.outputs.files_scanned': count})
            route = H.run(bash, post, pc, ws)['outputs'].get('routing_result')
            print('  %-36s routing=%s' % (label, route))
            if route != want:
                bad.append('%s: the posture step routed %r, want %s' % (label, route, want))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print(('FAIL ' + b).encode('ascii', 'replace').decode('ascii'))
    if bad:
        return 1
    print('PASS: every policy rule refuses its seeded violation, including a reusable-workflow call,')
    print('      container, service and docker:// images, and inputs.* in run; zero files is not green.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
