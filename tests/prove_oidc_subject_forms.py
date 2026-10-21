#!/usr/bin/env python3
"""The claims step must accept BOTH subject forms GitHub issues, and refuse every near-miss.

WHY THIS EXISTS

    verify-azure-oidc.yml's step `claims` reads the OIDC token's own `sub` and compares it with
    `repo:<owner>/<name>:environment:<env>` built from the declared expectation. GitHub also issues
    the IMMUTABLE-ID form, `repo:<owner>@<owner_id>/<name>@<repo_id>:environment:<env>`, and did so
    for a genuine caller on hosted runs 38824385082 and 38824392100 (2026-10-15): the step refused
    the caller BEFORE login, on a subject the login itself had accepted in September (run
    35757818464 printed the same form). The step was added after that September run and had never
    run hosted until the refusal. The kit's own adoption docs (docs/adoption/SETUP.md) already say
    both forms exist in the wild and neither is a rendering artefact.

WHAT THE STEP MUST DO

    Accept the plain form exactly as before. Accept the ID-qualified form ONLY when the owner and
    repository names equal the expectation (compared exactly as presented -- case-sensitively, the
    comparison the plain form has always had; no offline GitHub document states a different rule),
    `<owner_id>` equals the token's own `repository_owner_id` claim, `<repo_id>` equals its
    `repository_id` claim (both present and numeric), and the environment equals the expectation.
    Anything else is the existing "Subject mismatch" hard failure. The run must record WHICH form
    it verified (output `subject_form`), so a reader can tell a plain acceptance from an ID one.

WHAT THIS PROVES, LOCALLY

    The shipped step is EXTRACTED from the workflow (never re-implemented) and run under bash with
    a shim `curl` that answers the token endpoint with a crafted, unsigned JWT whose payload is
    the scenario's claim set. `jq`, `base64`, `sed` and `cut` are real. Rows:

      P1  plain subject                                   -> exit 0, subject_form=PLAIN
      P2  ID-qualified, ids equal the token's own claims  -> exit 0, subject_form=ID_QUALIFIED
      N1  ID-qualified, wrong owner id in the subject     -> exit 1, Subject mismatch
      N2  ID-qualified, wrong repository id               -> exit 1
      N3  ID-qualified, the two ids swapped               -> exit 1
      N4  ID-qualified, repository_id claim absent        -> exit 1
      N5  ID-qualified, repository_owner_id claim absent  -> exit 1
      N6  ID-qualified, ids present but not numeric       -> exit 1
      N7  ID-qualified, wrong environment in the subject  -> exit 1
      N8  ID-qualified, wrong repository name             -> exit 1
      N9  ID-qualified, a different owner                 -> exit 1
      N10 ID-qualified, owner case differs                -> exit 1 (case-sensitive, by design)
      N11 plain, owner case differs                       -> exit 1 (unchanged behaviour)
      N12 a ref-scoped subject (no environment)           -> exit 1
      N13 a plain subject for a different environment     -> exit 1
    Every N row keeps the repository and environment CLAIMS correct, so the only assertion that
    can refuse is the subject one -- and the row checks that it is the one that did. No N row
    may record subject_form as PLAIN or ID_QUALIFIED. The minted token appears in no log line
    other than the runner's own `::add-mask::` command.

WHAT IT CANNOT ESTABLISH
    That GitHub issues either form to a given repository, that azure/login accepts it, or that
    the job's conclusion is `failure` -- only a hosted run can. Run 35757818464 established the
    login accepts the ID-qualified form; runs 38824385082 and 38824392100 established the shipped
    step refused it.

EXIT  0 every row holds   1 a row failed   2 the step could not be run (UNKNOWN, never PASS)
"""
import base64
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

WF = '.github/workflows/verify-azure-oidc.yml'
JOB = 'verify'
STEP = 'claims'

# Shapes only: an invented owner, repository and ids. Nothing denotes a real account.
OWNER = 'example-owner'
NAME = 'example-kit'
REPO = OWNER + '/' + NAME
OWNER_ID = '1001'
REPO_ID = '2002'
ENV = 'test'
AUD = 'api://AzureADTokenExchange'

PLAIN_SUB = 'repo:%s:environment:%s' % (REPO, ENV)


def id_sub(owner=OWNER, oid=OWNER_ID, name=NAME, rid=REPO_ID, env=ENV):
    return 'repo:%s@%s/%s@%s:environment:%s' % (owner, oid, name, rid, env)


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def jwt(claims):
    """An UNSIGNED token of the right shape. The step decodes the payload; it never verifies."""
    header = b64url(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode('utf-8'))
    payload = b64url(json.dumps(claims, separators=(',', ':')).encode('utf-8'))
    signature = b64url(b'not-a-signature-' * 4)
    return header + '.' + payload + '.' + signature


def claims(sub, **override):
    c = {'sub': sub, 'repository': REPO, 'environment': ENV, 'ref': 'refs/heads/main',
         'job_workflow_ref': REPO + '/.github/workflows/verify-azure-oidc.yml@refs/heads/main',
         'workflow_ref': REPO + '/.github/workflows/caller.yml@refs/heads/main',
         'repository_id': REPO_ID, 'repository_owner_id': OWNER_ID,
         'aud': AUD, 'iss': 'https://token.actions.githubusercontent.com'}
    for k, v in override.items():
        if v is None:
            c.pop(k, None)
        else:
            c[k] = v
    return c


# The shim answers the token endpoint from env, whatever the URL. curl is the ONLY tool shimmed:
# the step's jq, base64, sed and cut are the real ones.
CURL_SHIM = 'printf \'{"value":"%s"}\' "$STUB_TOKEN"'

# Git for Windows' bash wrapper puts /mingw64/bin ahead of anything the parent prefixed on PATH,
# so the shim directory is prepended INSIDE the script, in the form bash uses on this host --
# the same prelude tests/prove_context_integrity_refuses.py uses. It is the only text added to
# the shipped step, and it changes PATH, nothing else.
PRELUDE = ('if command -v cygpath >/dev/null 2>&1; then _d=$(cygpath -u "$STUB_DIR"); '
           'else _d="$STUB_DIR"; fi\nexport PATH="$_d:$PATH"\n')


def run_case(H, bash, step, token, ws):
    shim_dir = os.path.join(ws, 'shim')
    H.shim(shim_dir, 'curl', CURL_SHIM)
    ctx = {'inputs.token_audience': AUD,
           'steps.preflight.outputs.expect_repository': REPO,
           'inputs.environment': ENV,
           'inputs.expect_job_workflow_ref_prefix': ''}
    extra = {'ACTIONS_ID_TOKEN_REQUEST_URL': 'http://token.invalid/request?api-version=stub',
             'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'stub-request-token',
             'STUB_DIR': shim_dir, 'STUB_TOKEN': token}
    s = dict(step)
    s['run'] = PRELUDE + (step.get('run') or '')
    return H.run(bash, s, ctx, ws, extra_env=extra)


def main():
    import _step_harness as H
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s); the step was not run.' % why)
        return 2
    if not shutil.which('jq'):
        print('UNKNOWN: jq is not on PATH; the step decodes claims with it and was not run.')
        return 2
    try:
        step = H.step(WF, JOB, STEP)
    except Exception as e:  # noqa: BLE001
        print('UNKNOWN: could not read %s: %s' % (WF, e))
        return 2
    if step is None:
        print('FAIL: job %r has no step with id %r in %s -- the claims step is not addressable, '
              'so nothing shipped can be run here.' % (JOB, STEP, WF))
        return 1

    fails = []

    def row(name, ok, detail=''):
        print('  %s  %s%s' % ('ok  ' if ok else 'FAIL', name, ('  -- ' + detail) if detail else ''))
        if not ok:
            fails.append(name)

    env = step.get('env') or {}
    row('step env EXPECT_REPO carries steps.preflight.outputs.expect_repository',
        'steps.preflight.outputs.expect_repository' in str(env.get('EXPECT_REPO', '')))
    row('step env EXPECT_ENVIRONMENT carries inputs.environment',
        'inputs.environment' in str(env.get('EXPECT_ENVIRONMENT', '')))
    row('no expression inside the step body (data arrives through env:)',
        '${{' not in (step.get('run') or ''))

    ws = tempfile.mkdtemp(prefix='oidc-sub-')
    try:
        def go(name, token, expect_pass, form=None):
            r = run_case(H, bash, step, token, ws)
            rc, log, outs = r['rc'], r['log'], r['outputs']
            got_form = outs.get('subject_form', '')
            if expect_pass:
                row('%s -> exit 0' % name, rc == 0, 'rc=%s' % rc)
                row('   records subject_form=%s' % form, got_form == form,
                    'subject_form=%r' % got_form)
                row('   says the claims matched',
                    'Subject, repository and environment claims all match' in log)
            else:
                row('%s -> exit 1' % name, rc != 0, 'rc=%s' % rc)
                row('   refused by the SUBJECT assertion, not another one',
                    'Subject mismatch' in log and 'Repository claim mismatch' not in log
                    and 'Environment claim mismatch' not in log)
                row('   never records an accepted form', got_form not in ('PLAIN', 'ID_QUALIFIED'),
                    'subject_form=%r' % got_form)
            leaked = [l for l in log.splitlines() if token in l and '::add-mask::' not in l]
            row('   token appears in no log line but the mask command', not leaked,
                '%d line(s)' % len(leaked))
            return r

        # P1, P2
        go('P1 plain subject', jwt(claims(PLAIN_SUB)), True, 'PLAIN')
        r = go('P2 ID-qualified subject, ids equal the token claims', jwt(claims(id_sub())),
               True, 'ID_QUALIFIED')
        row('P2 still prints the id claims it compared against',
            'repository_id=' + REPO_ID in r['log'] and 'repository_owner_id=' + OWNER_ID in r['log'])

        # N rows: the subject varies; the repository and environment CLAIMS stay correct.
        for name, c in (
            ('N1 wrong owner id in the subject', claims(id_sub(oid='9999'))),
            ('N2 wrong repository id in the subject', claims(id_sub(rid='9999'))),
            ('N3 the two ids swapped', claims(id_sub(oid=REPO_ID, rid=OWNER_ID))),
            ('N4 repository_id claim absent', claims(id_sub(), repository_id=None)),
            ('N5 repository_owner_id claim absent', claims(id_sub(), repository_owner_id=None)),
            ('N6 ids present but not numeric', claims(id_sub(oid='abc', rid='def'),
                                                      repository_id='def',
                                                      repository_owner_id='abc')),
            ('N7 wrong environment in the subject', claims(id_sub(env='prod'))),
            ('N8 wrong repository name', claims(id_sub(name='other-kit'))),
            ('N9 a different owner', claims(id_sub(owner='other-owner'))),
            ('N10 owner case differs, ID-qualified (case-sensitive by design)',
             claims(id_sub(owner=OWNER.upper()))),
            ('N11 owner case differs, plain (unchanged behaviour)',
             claims('repo:%s/%s:environment:%s' % (OWNER.upper(), NAME, ENV))),
            ('N12 a ref-scoped subject', claims('repo:%s:ref:refs/heads/main' % REPO)),
            ('N13 plain subject for a different environment',
             claims('repo:%s:environment:prod' % REPO)),
        ):
            go(name, jwt(c), False)
    finally:
        shutil.rmtree(ws, ignore_errors=True)

    if fails:
        print('\nFAIL: %d row(s): %s' % (len(fails), '; '.join(fails)))
        return 1
    print('\nPASS: the shipped claims step accepts the plain subject and the ID-qualified subject '
          'whose ids equal the token\'s own repository_owner_id and repository_id, records which '
          'form it verified, and hard-fails every near-miss on the subject assertion alone. '
          'Whether GitHub issues either form to a given caller is a hosted fact, not a local one.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
