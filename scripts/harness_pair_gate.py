#!/usr/bin/env python3
"""Decide whether the hosted kit-harness pair may run, and run it -- or say, by name, why it did not.

WHY THIS EXISTS (KDEC-052 item 9, KDEC-058)

    tests/prove_kit_harness_pair.py (KREQ-302) runs the kit's export leg and the evidence harness's import
    leg on one fixture, and fails HARNESS_LEG_NOT_RUN without the harness. It ran only on a workstation:
    no workflow could read the harness repository. The owner accepted a hosted gate, read-only and narrowly
    scoped (a GitHub App installation token), at a PINNED harness commit; she creates the credential.

    Three things must never happen, and this script is where each is refused:

      the token beside code a pull request controls   the token is minted only on a push to the default
                                                      branch or a dispatch from it. Any other
                                                      event is EVENT_NOT_TRUSTED, and the mint step never runs.
                                                      (The workflow itself has no pull_request trigger, and its
                                                      environment admits only the default branch: the event
                                                      rule here is the third layer, the one a proof can drive.)
      the harness at a moving ref                     .github/harness-pair.json names one full 40-hex commit.
                                                      A branch, a tag, a short SHA or HEAD is PIN_NOT_A_COMMIT;
                                                      the checked-out HEAD must equal it (HARNESS_PIN_MISMATCH).
      an absent credential read as a pass             with no App key, no client id, no repository or no pin,
                                                      the outcome is HARNESS_LEG_NOT_RUN with every reason
                                                      named, an ::error annotation, a step-summary line, and
                                                      exit 1. Never exit 0.

    The pair proof's own UNWIRED entry (tests/check_selftest_coverage.py) stays until a hosted run shows the
    pair passing: this script invokes the proof through a subprocess, so the census does not count the
    workflow as running it, which is the truth while the credential is absent.

USAGE
    harness_pair_gate.py plan                      decide; write run/state/reason/commit/owner/repo to
                                                   $GITHUB_OUTPUT (when set) and print the decision
    harness_pair_gate.py run --harness-root PATH   re-decide from the same inputs; when the pair may run,
                                                   check the checkout's HEAD is the pin and run the proof

    Inputs (environment; the workflow maps them, never the secret itself):
      EVENT, REF, DEFAULT_BRANCH        github.event_name, github.ref, the repository's default branch
      HAS_APP_KEY                        'true' when the App private-key secret is non-empty
      APP_CLIENT_ID                      the App's client id (a variable, not a secret)
      HARNESS_REPOSITORY                 OWNER/REPO of the harness ON THE RUN HOST (KDEC-027: no host part;
                                         the token and the checkout go only to the run's own server)
      HARNESS_PIN_FILE                   default .github/harness-pair.json

EXIT  plan: 0 always (the decision is an output)   run: 0 the pair proof passed   1 not run, or it failed
      2 could not be checked (the pin file unreadable)
"""
import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIN_FILE = os.path.join(ROOT, '.github', 'harness-pair.json')
PAIR_PROOF = os.path.join(ROOT, 'tests', 'prove_kit_harness_pair.py')
TRUSTED_EVENTS = ('push', 'workflow_dispatch')
COMMIT_RX = re.compile(r'^[0-9a-f]{40}$')
REPO_RX = re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$')
RUN, NOT_RUN = 'HARNESS_PAIR_RUN', 'HARNESS_LEG_NOT_RUN'


def read_pin(path=PIN_FILE):
    """-> the pinned commit value as written (None when unset). Raises ValueError when unreadable."""
    try:
        doc = json.load(io.open(path, encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise ValueError('the pin file %s cannot be read: %s' % (path, e))
    if not isinstance(doc, dict) or doc.get('schema') != 'kit-harness-pair-pin/1':
        raise ValueError('the pin file %s is not kit-harness-pair-pin/1' % path)
    return doc.get('commit')


def decide(env, pin):
    """-> dict(state, reasons, commit, owner, repo). Pure: every input is an argument."""
    reasons = []
    event = (env.get('EVENT') or '').strip()
    ref = (env.get('REF') or '').strip()
    default = (env.get('DEFAULT_BRANCH') or '').strip()
    if event not in TRUSTED_EVENTS:
        reasons.append('EVENT_NOT_TRUSTED: event %r may run code a pull request controls; the token is minted '
                       'only on %s' % (event, ', '.join(TRUSTED_EVENTS)))
    elif not default or ref != 'refs/heads/' + default:
        reasons.append('EVENT_NOT_TRUSTED: ref %r is not the default branch %r' % (ref, default))
    if (env.get('HAS_APP_KEY') or '').strip().lower() != 'true' or not (env.get('APP_CLIENT_ID') or '').strip():
        reasons.append('CREDENTIAL_ABSENT: the read-only GitHub App (client id variable and private-key secret '
                       'in the kit-harness-pair environment) is not configured; see '
                       'docs/operations/HARNESS_PAIR_HOSTED.md')
    repo = (env.get('HARNESS_REPOSITORY') or '').strip()
    if not REPO_RX.match(repo):
        reasons.append('HARNESS_REPOSITORY_NOT_SET: %r is not OWNER/REPO on the run host' % repo)
    commit = pin.strip() if isinstance(pin, str) else pin
    if commit is None or commit == '':
        reasons.append('PIN_NOT_SET: .github/harness-pair.json names no harness commit')
    elif not isinstance(commit, str) or not COMMIT_RX.match(commit):
        reasons.append('PIN_NOT_A_COMMIT: %r is not a full 40-hex commit (a branch, tag, short SHA or HEAD '
                       'moves; the pair runs at one reviewed commit)' % (commit,))
    owner, _, name = repo.partition('/')
    return {'state': NOT_RUN if reasons else RUN, 'reasons': reasons,
            'commit': commit if not reasons else '', 'owner': owner if not reasons else '',
            'repo': name if not reasons else ''}


def write_outputs(d):
    out = os.environ.get('GITHUB_OUTPUT')
    if not out:
        return
    with io.open(out, 'a', encoding='utf-8') as f:
        f.write('run=%s\n' % ('true' if d['state'] == RUN else 'false'))
        f.write('state=%s\n' % d['state'])
        f.write('commit=%s\nowner=%s\nrepo=%s\n' % (d['commit'], d['owner'], d['repo']))


def summary(line):
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        with io.open(path, 'a', encoding='utf-8') as f:
            f.write(line + '\n')


def not_run(reasons):
    codes = ', '.join(sorted(set(r.split(':')[0] for r in reasons)))
    print('::error title=%s (not established)::the kit-harness pair did not run: %s' % (NOT_RUN, codes))
    for r in reasons:
        print('  ' + r)
    summary('**Kit-harness pair: %s** (not established; this is not a pass). Reasons: %s' % (NOT_RUN, codes))
    return 1


def head_of(root):
    p = subprocess.run(['git', '-C', root, 'rev-parse', 'HEAD'], capture_output=True, text=True)
    return (p.stdout or '').strip() if p.returncode == 0 else ''


def run(env, pin, harness_root, head=head_of, proof=None):
    """-> exit code. `head` and `proof` are seams for the offline proof."""
    d = decide(env, pin)
    if d['state'] != RUN:
        return not_run(d['reasons'])
    if not harness_root or not os.path.isdir(harness_root):
        return not_run(['HARNESS_CHECKOUT_MISSING: no harness checkout at %r (the mint or checkout step failed)'
                        % harness_root])
    got = head(harness_root)
    if got != d['commit']:
        return not_run(['HARNESS_PIN_MISMATCH: the checkout is at %r, the pin is %s' % (got, d['commit'])])
    if proof is None:
        rc = subprocess.call([sys.executable, PAIR_PROOF, '--harness-root', harness_root])
    else:
        rc = proof(harness_root)
    summary('**Kit-harness pair** at harness %s: %s' % (d['commit'], 'PASS' if rc == 0 else 'FAIL (rc %d)' % rc))
    return 0 if rc == 0 else 1


def main(argv):
    if not argv or argv[0] not in ('plan', 'run'):
        print(__doc__.split('USAGE')[1].split('EXIT')[0])
        return 2
    env = dict(os.environ)
    try:
        pin = read_pin(env.get('HARNESS_PIN_FILE') or PIN_FILE)
    except ValueError as e:
        print('UNKNOWN: %s' % e)
        return 2 if argv[0] == 'plan' else not_run(['PIN_NOT_SET: %s' % e])
    if argv[0] == 'plan':
        d = decide(env, pin)
        write_outputs(d)
        print('plan: %s%s' % (d['state'], ''.join('\n  ' + r for r in d['reasons'])))
        return 0
    root = argv[argv.index('--harness-root') + 1] if '--harness-root' in argv else ''
    return run(env, pin, root)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
