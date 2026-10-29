#!/usr/bin/env python3
"""The release preconditions the landing zone's design is stronger on, enforced by the kit before
login (OF-5, the LZ-vs-kit deployment review, 2026-10-28; KDEC-034 PROPOSED).

WHY THIS EXISTS

    The landing zone (LZ) and the kit were reviewed against each other step by step and the
    stronger mechanism taken on each side. Three of the LZ's were missing from the kit's releases:

      K-3  STOP. The LZ halts its own pipeline (ops/halt.json) and blocks applies on a budget cap or
           a TTL (apply_block). A release refused only on verdict, protection and policy, so a halted
           or capped platform still took releases. The vend now writes the block into every kit
           environment as KIT_RELEASE_BLOCK; anything but `none` refuses the release before login,
           at every tier (RELEASE_BLOCKED_BY_PLATFORM). Unset: no landing zone writes one; recorded.
      K-2  READINESS. The LZ's eight behavioural readiness gates decide whether the ZONE may take
           anything beyond dev; UNKNOWN is never a pass. The vend writes the zone's readiness into
           every kit environment as KIT_ZONE_READINESS. At uat and prod only READY and
           READY_WITH_EXCEPTIONS release; NOT_READY, UNKNOWN, unset or an unregistered value refuses
           before login (RELEASE_REFUSED_ZONE_NOT_READY). Below uat it is recorded, never refused.
      K-1  CONSENT BOUND TO THE CHANGE. The LZ's owner confirms the exact plan digest, and the
           approver, the confirmer and the requester are three people. GitHub's environment
           reviewers with self-review prevented exclude only the run's trigger: the author of the
           commit being released may approve it, and nothing ties the approval to the digest. So at
           uat and prod the kit reads the run's own approvals (GET .../actions/runs/{id}/approvals)
           and refuses before login unless an approval for THIS environment exists
           (RELEASE_APPROVAL_ABSENT -- an administrator bypass leaves none), no approving reviewer is
           the requester (the triggering actor or the actor) or the release's author (the author of
           the released commit, and of a merge commit's second parent) (SELF_DEPLOYMENT_APPROVAL,
           the LZ's own name for it), and an independent approval's comment names the digest being
           released -- the full digest or at least its first 12 hex characters
           (RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST). The approving reviewer who names the digest is
           the CONFIRMER: approver/confirmer, requester and author are distinct people. A second,
           separate confirmer is not possible inside one job (an environment admits on ONE
           approval). Anything that cannot be read is RELEASE_APPROVAL_NOT_ESTABLISHED, a refusal.
           Below uat it is recorded (RELEASE_APPROVAL_NOT_REQUIRED) unless the policy register's
           deploy_approval for the tier sets `confirm_digest: required`, which can only tighten.

    Vocabulary: assurance-taxonomy.yaml :: release_block, zone_readiness, zone_readiness_gate,
    release_approval. Proven by tests/prove_release_gates.py. Inlined into the deploy reusables by
    scripts/inline_deploy_scripts.py (a reusable workflow called cross-repo has no scripts/).

USAGE (one subcommand per workflow step; inputs arrive through env:, as data -- the names below are
       the job's environment variables, written lower-case here and upper-cased on lookup)
    release_gates.py zone                       kit_release_block, kit_zone_readiness, environment_tier
    release_gates.py approval --digest D [--source-commit SHA]
                                                environment_tier, deploy_environment, deploy_approval,
                                                github_run_id, github_sha, github_triggering_actor,
                                                github_actor, github_repository, github_api_url, gh_token
    release_gates.py --self-test

EXIT 0 permitted   1 refused (by name)   2 usage
"""
import argparse
import io
import json
import os
import re
import sys
import urllib.parse
import urllib.request

PRODUCTION_TIERS = ('uat', 'prod')
TIERS = ('sandbox', 'dev', 'test', 'uat', 'prod')

# release_block (K-3). The LZ's values of KIT_RELEASE_BLOCK; `none` is the only permitting one.
BLOCK_VALUES = ('none', 'platform_halted', 'ttl_expired', 'budget_cap_reached')
NOT_BLOCKED = 'RELEASE_NOT_BLOCKED'
BLOCK_NOT_VENDED = 'RELEASE_BLOCK_NOT_VENDED'
BLOCKED = 'RELEASE_BLOCKED_BY_PLATFORM'

# zone_readiness (the LZ's register vocabulary, as vended) and zone_readiness_gate (K-2).
READINESS = ('READY', 'READY_WITH_EXCEPTIONS', 'NOT_READY', 'UNKNOWN')
READINESS_PERMITS = ('READY', 'READY_WITH_EXCEPTIONS')
ZONE_PERMITTED = 'ZONE_READINESS_PERMITTED'
ZONE_NOT_REQUIRED = 'ZONE_READINESS_NOT_REQUIRED'
ZONE_REFUSED = 'RELEASE_REFUSED_ZONE_NOT_READY'

# release_approval (K-1)
APPROVAL_VERIFIED = 'RELEASE_APPROVAL_VERIFIED'
APPROVAL_NOT_REQUIRED = 'RELEASE_APPROVAL_NOT_REQUIRED'
APPROVAL_ABSENT = 'RELEASE_APPROVAL_ABSENT'
SELF_APPROVAL = 'SELF_DEPLOYMENT_APPROVAL'
NOT_BOUND = 'RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST'
NOT_ESTABLISHED = 'RELEASE_APPROVAL_NOT_ESTABLISHED'
APPROVAL_PERMITS = (APPROVAL_VERIFIED, APPROVAL_NOT_REQUIRED)
MIN_DIGEST_PREFIX = 12          # hex characters an approval comment must quote, at least
DIGEST_RE = re.compile(r'^(?:sha256:)?([0-9a-f]{64})$')


def env(name, default=''):
    """Lower-case names, upper-cased on lookup: they are settings, not vocabulary."""
    return os.environ.get(name.upper(), default)


def output(**values):
    """One line per value to $GITHUB_OUTPUT (a newline in a value would end the file command early)."""
    path = os.environ.get('GITHUB_OUTPUT')
    lines = ['%s=%s' % (k, ' '.join(str('' if v is None else v).split())) for k, v in values.items()]
    print('\n'.join(lines))
    if path:
        with io.open(path, 'a', encoding='utf-8') as fh:
            fh.write('\n'.join(lines) + '\n')


def summary(text):
    path = env('github_step_summary')
    if path:
        with io.open(path, 'a', encoding='utf-8') as fh:
            fh.write(text + '\n')


def plain(v):
    """A value is shown only when it is a plain token (vended or caller text could carry `::`)."""
    return bool(re.match(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$', v or ''))


def shown(v):
    if not v:
        return '(unset)'
    return "'%s'" % v if plain(v) else '(a value that is not a plain token, not shown)'


# ----------------------------------------------------------------------------- K-2, K-3
def decide_block(value):
    """-> (release_block, permits, why)."""
    v = (value or '').strip()
    if not v:
        return BLOCK_NOT_VENDED, True, ('this environment carries no KIT_RELEASE_BLOCK: no landing zone '
                                        'writes one here, so no platform stop is in force (recorded)')
    if v == 'none':
        return NOT_BLOCKED, True, 'the landing zone reports no halt, TTL or budget block on this workload'
    if v in BLOCK_VALUES:
        return BLOCKED, False, ('the landing zone has stopped releases into this workload: KIT_RELEASE_BLOCK '
                                'is %s. Releases resume when the platform clears it to none' % shown(v))
    return BLOCKED, False, ('KIT_RELEASE_BLOCK is %s, which is not none: anything but none refuses, and an '
                            'unregistered value is not read as a clearance' % shown(v))


def decide_zone(tier, value):
    """-> (zone_readiness, zone_readiness_gate, permits, why)."""
    v = (value or '').strip()
    readiness = v if v in READINESS else 'UNKNOWN'
    what = ('KIT_ZONE_READINESS is unset' if not v else
            'KIT_ZONE_READINESS is %s' % shown(v) + ('' if v in READINESS else ', not a registered readiness value'))
    if tier not in TIERS:
        return readiness, ZONE_REFUSED, False, ('environment_tier %s is not a registered tier, so it cannot be '
                                                'shown to be below production' % shown(tier))
    if tier not in PRODUCTION_TIERS:
        return readiness, ZONE_NOT_REQUIRED, True, '%s; below uat the zone\'s readiness is recorded, not required' % what
    if readiness in READINESS_PERMITS:
        return readiness, ZONE_PERMITTED, True, '%s: the zone may take a %s release' % (what, tier)
    return readiness, ZONE_REFUSED, False, ('%s, and %s is a production tier. The landing zone\'s readiness '
                                            'gates decide whether the zone may take anything beyond dev; only '
                                            'READY or READY_WITH_EXCEPTIONS releases at uat and prod, and '
                                            'UNKNOWN is never a pass' % (what, tier))


def cmd_zone(_a):
    tier = env('environment_tier').strip()
    block, block_ok, block_why = decide_block(env('kit_release_block'))
    readiness, gate, zone_ok, zone_why = decide_zone(tier, env('kit_zone_readiness'))
    output(release_block=block, zone_readiness=readiness, zone_readiness_gate=gate)
    summary('### Platform stop and zone readiness (before login)\n\n| check | outcome | why |\n|---|---|---|\n'
            '| release block (K-3) | `%s` | %s |\n| zone readiness (K-2) | `%s` / `%s` | %s |'
            % (block, block_why, readiness, gate, zone_why))
    refused = []
    if not block_ok:
        refused.append('%s: %s' % (BLOCKED, block_why))
    if not zone_ok:
        refused.append('%s: %s' % (ZONE_REFUSED, zone_why))
    if refused:
        for r in refused:
            print('::error title=Release refused before login::%s. Nothing was deployed.' % r)
        return 1
    if readiness == 'READY_WITH_EXCEPTIONS' and tier in PRODUCTION_TIERS:
        print('::warning title=Zone ready with exceptions::the landing zone is READY_WITH_EXCEPTIONS; this %s '
              'release proceeds and the exceptions are the landing zone\'s record.' % tier)
    print('release block %s; zone readiness %s (%s)' % (block, readiness, gate))
    return 0


# ----------------------------------------------------------------------------- K-1
class Unreadable(Exception):
    pass


def api(path):
    """GET /repos/<repository>/<path> (a file:// base is the local stand-in). Unreadable on any failure."""
    base = env('GITHUB_API_URL', 'https://api.github.com').rstrip('/')  # unset means github.com
    repo = env('github_repository')
    if not repo:
        raise Unreadable('no repository is named')
    url = '%s/repos/%s/%s' % (base, repo, path)
    req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json',
                                               'X-GitHub-Api-Version': '2022-11-28'})
    token = env('gh_token')
    if token and url.startswith('https://'):
        req.add_unredirected_header('Authorization', 'Bearer %s' % token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as exc:  # noqa: BLE001 -- any failure is "could not read", never a pass
        raise Unreadable('GET %s failed: %s' % (url.split('?')[0], type(exc).__name__))


def digest_bound(comment, digest):
    """True when the comment quotes the digest: the full value, or at least its first 12 hex."""
    m = DIGEST_RE.match((digest or '').strip().lower())
    if not m:
        return False
    hexd = m.group(1)
    for tok in re.findall(r'(?:sha256:)?[0-9a-f]{%d,64}' % MIN_DIGEST_PREFIX, (comment or '').lower()):
        tok = tok.split(':', 1)[-1]
        if hexd.startswith(tok):
            return True
    return False


def confirm_demand(tier, demand_json):
    """-> 'required' | 'not_required', or None when the demand cannot be read. The kit default
    requires the digest at uat and prod; a passed demand can only tighten that."""
    base = 'required' if tier in PRODUCTION_TIERS else 'not_required'
    if not (demand_json or '').strip():
        return base
    try:
        doc = json.loads(demand_json)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    sup = doc.get(tier, {}) if any(k in TIERS for k in doc) else doc
    if not isinstance(sup, dict):
        return None
    return 'required' if 'required' in (base, sup.get('confirm_digest')) else 'not_required'


def authors_of(sha):
    """-> the logins that authored the released commit (and a merge commit's second parent)."""
    out = set()
    doc = api('commits/%s' % sha)
    if not isinstance(doc, dict):
        raise Unreadable('commit %s answered no object' % sha[:12])
    login = ((doc.get('author') or {}).get('login') or '').strip()
    if not login:
        raise Unreadable('commit %s has no GitHub author login (its author email is not linked to an '
                         'account), so the approver cannot be shown not to be its author' % sha[:12])
    out.add(login.lower())
    parents = doc.get('parents') or []
    if len(parents) > 1 and isinstance(parents[1], dict) and parents[1].get('sha'):
        p = api('commits/%s' % parents[1]['sha'])
        plog = (((p or {}).get('author') or {}).get('login') or '').strip()
        if not plog:
            raise Unreadable('the merged branch head %s has no GitHub author login' % parents[1]['sha'][:12])
        out.add(plog.lower())
    return out


def decide_approval(tier, environment, digest, approvals, requesters, authors, confirm):
    """Pure. -> (outcome, why, approvers). `approvals`/`authors` None = could not be read."""
    if confirm is None:
        return NOT_ESTABLISHED, 'the policy\'s deploy_approval could not be read', []
    production = tier in PRODUCTION_TIERS
    if not production and confirm != 'required':
        return APPROVAL_NOT_REQUIRED, 'below uat the run\'s approval is recorded, not required', []
    if approvals is None:
        return NOT_ESTABLISHED, 'the run\'s environment approvals could not be read', []
    mine = [a for a in approvals if isinstance(a, dict) and a.get('state') == 'approved' and
            any(str((e or {}).get('name') or '').lower() == (environment or '').lower()
                for e in a.get('environments') or [])]
    who = sorted(set(((a.get('user') or {}).get('login') or '').lower() for a in mine) - {''})
    if not mine or not who:
        return APPROVAL_ABSENT, ('no reviewer approved this run\'s deployment to %s (an administrator bypass, '
                                 'or an environment without required reviewers, leaves no approval)'
                                 % shown(environment)), who
    req = set(r.lower() for r in requesters if r)
    if not req:
        return NOT_ESTABLISHED, 'the run names no requester (triggering actor), so independence cannot be shown', who
    if authors is None:
        return NOT_ESTABLISHED, 'the released commit\'s author could not be read', who
    selfies = [(w, 'the requester') for w in who if w in req] + \
              [(w, 'the release\'s author') for w in who if w in authors and w not in req]
    if selfies:
        return SELF_APPROVAL, \
            'approved by %s: the approver must be neither the requester nor the release\'s author' % ', '.join(
                '%s (%s)' % (shown(w), role) for w, role in selfies), who
    if confirm == 'required':
        bound = [((a.get('user') or {}).get('login') or '').lower() for a in mine
                 if digest_bound(a.get('comment'), digest)]
        if not bound:
            return NOT_BOUND, ('no approval comment names the digest being released. The approving reviewer '
                               'confirms the exact artefact by quoting it (at least sha256:%s): approve with '
                               'the digest in the comment' % ((digest or '').split(':', 1)[-1][:MIN_DIGEST_PREFIX]
                                                            or '<digest>')), who
        return APPROVAL_VERIFIED, ('approved by %s, who is neither the requester nor the author, and the approval '
                                   'names the digest (confirmer %s)' % (', '.join(who), ', '.join(sorted(set(bound))))), who
    return APPROVAL_VERIFIED, 'approved by %s, neither the requester nor the author' % ', '.join(who), who


def cmd_approval(a):
    tier = env('environment_tier').strip()
    environment = env('deploy_environment').strip()
    confirm = confirm_demand(tier, env('deploy_approval'))
    approvals = authors = None
    notes = []
    needed = tier in PRODUCTION_TIERS or confirm == 'required'
    if tier not in TIERS:
        outcome, why, who = NOT_ESTABLISHED, 'environment_tier %s is not a registered tier' % shown(tier), []
    else:
        if needed and confirm is not None:
            try:
                if not env('github_run_id').strip():
                    raise Unreadable('no run id is named, so the run\'s approvals cannot be read')
                doc = api('actions/runs/%s/approvals' % env('github_run_id').strip())
                approvals = doc if isinstance(doc, list) else None
                if approvals is None:
                    notes.append('the approvals answer is not a list')
            except Unreadable as exc:
                notes.append(str(exc))
            try:
                authors = set()
                for sha in [s for s in (env('github_sha'), a.source_commit) if s]:
                    authors |= authors_of(sha)
            except Unreadable as exc:
                authors = None
                notes.append(str(exc))
        requesters = [env('github_triggering_actor'), env('github_actor')]
        outcome, why, who = decide_approval(tier, environment, a.digest, approvals, requesters, authors, confirm)
    if notes:
        why = '%s (%s)' % (why, '; '.join(notes))
    refused = outcome not in APPROVAL_PERMITS
    output(release_approval=outcome, release_approval_by=','.join(who))
    summary('### Release approval (K-1, before login)\n\n`%s` at tier `%s`: %s' % (outcome, tier or 'none', why))
    if refused:
        print('::error title=Release refused before login (approval)::%s: %s. Nothing was deployed.' % (outcome, why))
        return 1
    print('release approval %s: %s' % (outcome, why))
    return 0


# ----------------------------------------------------------------------------- self-test
def self_test():
    fails = []
    d = 'sha256:' + 'ab' * 32

    def appr(login, comment='', env_name='prod', state='approved'):
        return {'state': state, 'user': {'login': login}, 'comment': comment, 'environments': [{'name': env_name}]}
    cases = [
        (decide_block(''), BLOCK_NOT_VENDED), (decide_block('none'), NOT_BLOCKED),
        (decide_block('ttl_expired'), BLOCKED), (decide_block('NONE'), BLOCKED),
        (decide_zone('prod', 'READY')[1], ZONE_PERMITTED), (decide_zone('prod', '')[1], ZONE_REFUSED),
        (decide_zone('dev', 'NOT_READY')[1], ZONE_NOT_REQUIRED),
        (decide_approval('prod', 'prod', d, [appr('rev', d[:19])], ['dev1'], {'dev2'}, 'required')[0],
         APPROVAL_VERIFIED),
        (decide_approval('prod', 'prod', d, [appr('dev2', d)], ['dev1'], {'dev2'}, 'required')[0], SELF_APPROVAL),
        (decide_approval('prod', 'prod', d, [appr('rev', 'lgtm')], ['dev1'], {'dev2'}, 'required')[0], NOT_BOUND),
        (decide_approval('prod', 'prod', d, [], ['dev1'], {'dev2'}, 'required')[0], APPROVAL_ABSENT),
    ]
    for i, (got, want) in enumerate(cases):
        got = got[0] if isinstance(got, tuple) else got
        if got != want:
            fails.append('case %d: %s, wanted %s' % (i, got, want))
    if confirm_demand('prod', json.dumps({'prod': {'confirm_digest': 'not_required'}})) != 'required':
        fails.append('a passed demand relaxed the digest confirmation at prod')
    if fails:
        print('release_gates self-test FAILED: ' + '; '.join(fails))
        return 2
    print('release_gates self-test ok. The full proof is tests/prove_release_gates.py.')
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['--self-test']:
        return self_test()
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('zone')
    p = sub.add_parser('approval')
    p.add_argument('--digest', default='')
    p.add_argument('--source-commit', default='')
    a = ap.parse_args(argv)
    return {'zone': cmd_zone, 'approval': cmd_approval}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
