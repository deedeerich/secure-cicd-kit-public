#!/usr/bin/env python3
"""Every value a deploy step reads must arrive through `env:`, never through `${{ }}` in `run:`.

WHY THIS EXISTS (L100 / L38, brief N35)

    The two deploy reusables open with a guard that refuses anything but a full sha256 digest --
    and the guard itself read its input as

        d='${{ inputs.image_digest }}'

    GitHub substitutes that into the SCRIPT TEXT before bash runs. The validation therefore
    happens after the value has already been parsed as shell: a digest containing a quote ends
    the assignment early and the remainder runs as code, in the job that holds the deploy
    identity. The check that exists to refuse a malformed input is the first thing a malformed
    input reaches. `docs/architecture/SINGLE_PIPELINE_TARGET.md` section 6.2 names the hazard
    and the registered fix, SAFE_ENV_TRANSPORT.

    `tests/lint_injection.py` counts these sites (CALLER_CONTROLLED_INPUT_INTERPOLATION) but
    reports them without failing, because the flagship still carries dozens. The deploy surface
    is the one place where being wrong mutates a live target, so this file holds it to the
    stricter rule and FAILS.

THE RULE HERE IS STRICTER THAN lint_injection.py
    No `${{ }}` of ANY kind inside a `run:` body of a deploy workflow -- inputs, step outputs,
    secrets, everything. A step output on this surface is usually a string read back from the
    cloud (a revision name, a host name), which is data the workflow did not write, so it gets
    the same treatment as an input. `${{ }}` stays legal where it is data: `env:`, `with:`,
    `if:`, `concurrency:`.

THE FOUR CASES (docs/PROOF_RULE.md)
    allowed           a step that reads its value from env: is not flagged
    attack            a step that interpolates an input into run: is flagged
    missing-evidence  a deploy workflow that cannot be found or parsed is UNKNOWN, never PASS
    recovery          the shipped workflows, after the fix, carry zero sites

EXIT
    0  no deploy step interpolates anything into a script body
    1  at least one site interpolates
    2  could not be checked -- UNKNOWN, never PASS
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEPLOY_WORKFLOWS = [
    os.path.join(ROOT, '.github', 'workflows', 'reusable-deploy-appservice.yml'),
    os.path.join(ROOT, '.github', 'workflows', 'reusable-deploy-containerapp.yml'),
    os.path.join(ROOT, '.github', 'workflows', 'reusable-deploy-staticwebapp.yml'),
]
EXPR = re.compile(r'\$\{\{(.*?)\}\}')


def sites(doc):
    """-> [(job, step, expression)] for every ${{ }} inside a run: body."""
    out = []
    for jname, job in ((doc or {}).get('jobs') or {}).items():
        if not isinstance(job, dict):
            continue
        for i, step in enumerate(job.get('steps') or []):
            if not isinstance(step, dict) or not isinstance(step.get('run'), str):
                continue
            for m in EXPR.finditer(step['run']):
                out.append((jname, step.get('name') or '#%d' % (i + 1), m.group(1).strip()))
    return out


ATTACK = """
on: {workflow_call: {inputs: {image_digest: {type: string, required: true}}}}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Validate digest
        run: |
          d='${{ inputs.image_digest }}'
"""

ALLOWED = """
on: {workflow_call: {inputs: {image_digest: {type: string, required: true}}}}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Validate digest
        if: inputs.image_digest != ''
        env:
          IMAGE_DIGEST: ${{ inputs.image_digest }}
        run: |
          d="$IMAGE_DIGEST"
"""


def self_test(yaml):
    bad = sites(yaml.safe_load(ATTACK))
    good = sites(yaml.safe_load(ALLOWED))
    ok = True
    if len(bad) != 1 or 'inputs.image_digest' not in bad[0][2]:
        print('SELF-TEST FAILED: an input interpolated into run: was not flagged (got %r).' % bad)
        ok = False
    if good:
        print('SELF-TEST FAILED: a value passed through env: was flagged (%r). A check that '
              'flags the remedy teaches people to ignore it.' % good)
        ok = False
    if ok:
        print('self-test ok: run: interpolation flagged; env:/if: transport not flagged')
    return ok


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable. Failure to observe is not an observation.')
        return 2
    if not self_test(yaml):
        return 2
    total = []
    for wf in DEPLOY_WORKFLOWS:
        if not os.path.isfile(wf):
            print('UNKNOWN: %s is missing. Nothing inspected is not nothing wrong.' % wf)
            return 2
        try:
            doc = yaml.safe_load(io.open(wf, encoding='utf-8'))
        except Exception as e:  # noqa: BLE001
            print('UNKNOWN: %s does not parse (%s).' % (wf, e))
            return 2
        found = sites(doc)
        print('  %-36s %3d site(s)' % (os.path.basename(wf), len(found)))
        for job, step, expr in found:
            total.append('%s :: %s :: %s :: ${{ %s }}' % (os.path.basename(wf), job, step, expr))
    if total:
        for t in total:
            print('FAIL: ' + t)
        print('\n%d value(s) reach a deploy script as CODE rather than DATA. Move each to the '
              "step's env: and read it as a shell variable (SAFE_ENV_TRANSPORT)." % len(total))
        return 1
    print('PASS: every deploy step reads its inputs and step outputs through env:. The digest '
          'guard validates a value bash has not yet parsed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
