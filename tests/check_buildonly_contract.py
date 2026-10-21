#!/usr/bin/env python3
"""A workflow that documents a credential-free path must not authenticate on it.

WHY THIS EXISTS
    `reusable-build-docker.yml` advertised, in its own input descriptions:

        "Leave empty for build-only runs (no registry, no Azure auth) -- useful on feature
         branches."

    The implementation contradicted it on every point. `acr_login_server` was `required: true`.
    All three AZURE_* secrets were `required: true`. Azure login ran unconditionally. ACR login
    ran unconditionally. The image reference was registry-shaped, so with an empty registry it
    resolved to `/repo:sha` -- a leading slash and an invalid reference. Only the push and the
    registry round trip were conditional.

    So the documented feature-branch path could not be called without naming a registry it would
    never contact and supplying credentials it would never use, and if it were called it would
    attempt federated login anyway.

    NOT UNTESTED -- UNIMPLEMENTABLE. Static inspection was enough to see it, and nothing had
    looked. That is the difference this check exists to hold: a contract nobody exercises drifts
    from its implementation silently, and the DOCUMENTATION is what a consumer plans against.

WHAT THIS CHECKS
    SHAPE. That the credential-bearing steps are conditioned, that the registry inputs are not
    mandatory, and that the image reference degrades to a local name. Whether a build-only run
    actually succeeds is a RUN, and that is the job in consumer-path-test.yml.

EXIT
    0  the build-only contract is implementable as documented
    1  the workflow contradicts its own contract
    2  could not be checked -- reported as UNKNOWN, never as PASS
"""
import io
import re
import sys

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML not available.')
    print('Failure to observe is not an observation.')
    sys.exit(2)

WF = '.github/workflows/reusable-build-docker.yml'

# Steps that reach a credentialed service. Matched broadly on purpose: the failure mode is a NEW
# authenticating step added later without a condition, and a narrow matcher would miss it.
AUTH_USES = re.compile(r'azure/login|docker/login-action|aws-actions/configure-aws|'
                       r'google-github-actions/auth')
AUTH_RUN = re.compile(r'\baz\s+login\b|\baz\s+acr\s+login\b|\bdocker\s+login\b|'
                      r'\baz\s+account\s+set\b')

REGISTRY_INPUTS = {'acr_login_server'}
PUSH_SECRETS = {'AZURE_TENANT_ID', 'AZURE_SUBSCRIPTION_ID', 'AZURE_CLIENT_ID'}


def guarded_by_push(step):
    """A step is safe on the build-only path only if its condition mentions the push input."""
    cond = str(step.get('if', ''))
    return 'inputs.push' in cond


def main():
    try:
        doc = yaml.safe_load(io.open(WF, encoding='utf-8', errors='replace'))
    except Exception as e:
        print('UNKNOWN: %s could not be read (%s).' % (WF, e))
        return 2
    if not isinstance(doc, dict):
        print('UNKNOWN: %s did not parse to a mapping.' % WF)
        return 2

    trigger = doc.get('on', doc.get(True)) or {}
    call = (trigger.get('workflow_call') or {}) if isinstance(trigger, dict) else {}
    inputs = call.get('inputs') or {}
    secrets = call.get('secrets') or {}

    fails = []

    # 1 -- the contract must still be claimed. If the description stops promising a
    # credential-free path, this check should be deleted along with the promise, not kept as
    # decoration over a feature nobody offers.
    blob = ' '.join(str(v.get('description', '')) for v in inputs.values() if isinstance(v, dict))
    claims_buildonly = bool(re.search(r'build-only', blob, re.I))
    if not claims_buildonly:
        print('UNKNOWN: %s no longer documents a build-only path. This check asserts an '
              'implementation matches a promise; with the promise gone there is nothing to '
              'compare. Remove both, or restore the contract.' % WF)
        return 2

    # 2 -- registry inputs must not be mandatory on a path that uses no registry.
    for name in REGISTRY_INPUTS:
        spec = inputs.get(name)
        if isinstance(spec, dict) and spec.get('required') is True:
            fails.append('input `%s` is required:true, so the documented build-only path cannot '
                         'be called without naming a registry the run will never contact' % name)

    # 3 -- same for the push credentials.
    for name in sorted(PUSH_SECRETS):
        spec = secrets.get(name)
        if isinstance(spec, dict) and spec.get('required') is True:
            fails.append('secret `%s` is required:true, so a build-only caller must supply a '
                         'credential it will never use' % name)

    # 4 -- nothing that authenticates may run unconditionally.
    for job_name, job in (doc.get('jobs') or {}).items():
        if not isinstance(job, dict):
            continue
        for step in (job.get('steps') or []):
            if not isinstance(step, dict):
                continue
            uses, run = str(step.get('uses', '')), str(step.get('run', ''))
            if AUTH_USES.search(uses) or AUTH_RUN.search(run):
                if not guarded_by_push(step):
                    fails.append('job %s: step %r authenticates and is not conditioned on '
                                 'inputs.push, so the credential-free path is not credential-free'
                                 % (job_name, step.get('name') or uses or '(unnamed)'))

    # 5 -- the image reference must degrade to a local name. A registry-shaped reference with an
    # empty registry yields `/repo:tag`, which docker refuses -- after the build.
    env = ((doc.get('jobs') or {}).get('build') or {}).get('env') or {}
    image = str(env.get('IMAGE', ''))
    if image and 'local/' not in image:
        fails.append("job build: IMAGE has no local fallback. With acr_login_server empty this "
                     "resolves to a leading-slash reference, and the run fails AFTER doing all "
                     "the build work: %r" % image[:90])

    print('=== build-only contract ===')
    print('  documented          : yes')
    print('  registry input      : %s' % ('optional' if not any('acr_login_server' in f for f in fails) else 'REQUIRED'))
    print('  push credentials    : %s' % ('optional' if not any('secret `' in f for f in fails) else 'REQUIRED'))
    print('  authenticating steps: %s' % ('all conditioned on inputs.push'
                                          if not any('authenticates' in f for f in fails) else 'UNCONDITIONAL'))
    print('  image reference     : %s' % ('degrades to a local name'
                                          if not any('IMAGE has no local' in f for f in fails) else 'REGISTRY-SHAPED'))

    print('\n' + '=' * 72)
    if fails:
        for f in fails:
            print('FAIL: %s' % f)
        print('\nA workflow that documents a credential-free path must not authenticate on it.')
        print('This is SHAPE. Whether a build-only run succeeds is a run, and that is the')
        print('credential-free job in consumer-path-test.yml.')
        return 1
    print('PASS: the build-only path is implementable as documented.')
    print('      SHAPE ONLY -- that it RUNS is proven by the credential-free consumer job,')
    print('      not by this file. Implementable is not proven.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
