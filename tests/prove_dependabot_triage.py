#!/usr/bin/env python3
"""Dependabot triage, run as shipped: auto-merge only what cannot change behaviour; a human for the rest.

WHY THIS EXISTS

    The owner (2026-10-22): Dependabot pull requests should merge themselves, and a human should be
    asked only for the ones that "materially change something that could change functionality or is
    critically important to runtime". The kit is consumed privately across several repositories, so
    this ships as a REUSABLE workflow (.github/workflows/reusable-dependabot-triage.yml) with every
    policy value supplied by the caller (templates/dependabot-triage.yml), and the merge itself is
    `gh pr merge --auto --squash`: GitHub merges only when branch protection and the required checks
    say so. The workflow never merges past them.

    This proof extracts the workflow's OWN steps -- the evidence step, the decision step and the
    three action steps -- and runs them under bash with the env: block a runner would substitute and
    a `gh` shim answering from fixtures. What runs here is what the runner runs. No step is re-typed.

WHAT IT PROVES
    D1  structure: callable only; no permissions at the top; each job holds only what it needs
        (classify reads, auto-merge may merge, human-review may label and comment, close may close);
        the classify job is guarded on the PR AUTHOR being dependabot[bot]; nothing checks out any
        code; dependabot/fetch-metadata is pinned by full SHA with a version comment and its
        Dependabot-commit verification is left on; no expression inside any run: block; the merge
        is `--auto --squash` and nothing passes `--admin`
    D2  the template caller uses pull_request_target, checks nothing out, and grants exactly the
        union of what the reusable's jobs request
    D3  the owner's eight cases, each through the shipped evidence and decision steps:
          patch dev dependency                       -> auto_merge
          major                                      -> human_review (major_update)
          critical package, minor                    -> human_review (critical_package)
          production lockfile churn over threshold   -> human_review (lockfile_churn)
          github-actions SHA bump within a major     -> auto_merge
          github-actions across a major              -> human_review
          security update on a critical package      -> human_review + the urgent label
          a change under an excluded path            -> close
    D4  FUTURE_WORK section 6's remaining criteria and every fail-closed path: no required checks on
        the base branch, the scan gate unnamed or not required, the protection APIs unreadable, a
        network package, a source file or a non-pin workflow line changed, a breaking-change or
        maintainer-change signal (and "no breaking changes" NOT read as one), a lockfile moving a
        package the PR does not name or returning no diff, fetch-metadata failed (an unverified
        commit), an unknown update type, an action moved onto a tag, the triage chain itself
        updated, a docker base image, a misconfigured policy, a narrower update-type policy, a
        compatibility floor with no score -- every one human_review, by its own rule
    D5  the trigger: pull_request is refused loudly (it runs the PR's own copy of the caller), and a
        PR not authored by dependabot[bot] is not acted on
    D6  every decision is recorded: package, from -> to, update type, rule, action -- in the step
        summary and in decision.json
    D7  the action steps issue exactly the gh commands the decision names: --auto --squash for a
        merge (and a failed enable is explained, not swallowed); labels created when absent, added,
        one comment upserted by marker, a review team requested; close with an explanation
    D8  PR-derived text is data: a dependency name shaped as shell does not execute

WHAT IT CANNOT PROVE
    That GitHub substitutes the expressions as written, that fetch-metadata emits what its source
    says, that branch protection then holds the merge, or that the token's scopes suffice for each
    gh call. Those need a hosted run on a real repository: docs/adoption/DEPENDABOT_TRIAGE.md holds
    the plan, and nothing here claims it.

USAGE  python3 tests/prove_dependabot_triage.py
EXIT   0 every case behaved, 1 otherwise, 2 could not run
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML not available. Failure to observe is not an observation.')
    sys.exit(2)

WF_REL = '.github/workflows/reusable-dependabot-triage.yml'
TPL_REL = 'templates/dependabot-triage.yml'
WF = os.path.join(ROOT, WF_REL)
TPL = os.path.join(ROOT, TPL_REL)
REPO = 'example-org/example-app'
PR_URL = 'https://github.com/%s/pull/42' % REPO
CALLER = '%s/.github/workflows/dependabot-triage.yml@refs/heads/main' % REPO
SHA_A = '1' * 40
SHA_B = '2' * 40

GH_SHIM = r'''
printf '%s\n' "$*" >> "$GH_LOG"
case "$*" in
  "api --paginate repos/"*"/pulls/"*"/files"*)
    [ "${FILES_RC:-0}" = 0 ] || { echo "HTTP 500" >&2; exit 1; }
    cat "$FIX/files.jsonl" ;;
  "api repos/"*"/rules/branches/"*)
    [ -f "$FIX/rules.json" ] || { echo "HTTP 404" >&2; exit 1; }
    cat "$FIX/rules.json" ;;
  "api repos/"*"/branches/"*)
    [ -f "$FIX/branch.json" ] || { echo "HTTP 404" >&2; exit 1; }
    cat "$FIX/branch.json" ;;
  "api repos/"*"/labels/"*)
    [ "${LABEL_EXISTS:-no}" = yes ] || { echo "HTTP 404" >&2; exit 1; }
    echo '{}' ;;
  "api --paginate repos/"*"/issues/"*"/comments"*)
    [ -n "${EXISTING_COMMENT:-}" ] && echo "$EXISTING_COMMENT"
    exit 0 ;;
  "pr view"*)
    echo "${AUTO_MERGE_ON:-false}" ;;
  "pr merge --auto"*)
    [ "${MERGE_RC:-0}" = 0 ] || echo "auto-merge is not allowed for this repository" >&2
    exit "${MERGE_RC:-0}" ;;
  *) exit 0 ;;
esac
'''


def load(path):
    return yaml.safe_load(io.open(path, encoding='utf-8'))


def on_of(doc):
    return doc.get('on', doc.get(True)) or {}


def find_step(job, key):
    for s in job.get('steps') or []:
        if isinstance(s, dict) and (s.get('id') == key or s.get('name') == key):
            return s
    return None


# ------------------------------------------------------------------------------- structure (D1, D2)

CLASSIFY_PERMS = {'contents': 'read', 'pull-requests': 'read'}
JOB_PERMS = {
    'classify': CLASSIFY_PERMS,
    'auto-merge': {'contents': 'write', 'pull-requests': 'write'},
    'human-review': {'pull-requests': 'write', 'issues': 'write'},
    'close': {'pull-requests': 'write'},
}
DEFAULTS = {
    'critical_packages': '',
    'critical_ecosystems': '',
    'auto_merge_update_types': 'patch,minor',
    'lockfile_line_threshold': '400',
    'excluded_paths': 'tests/consumer-fixture/**',
    'required_checks': '',
    'min_compatibility_score': '',
    'review_team': '',
    'review_label': 'needs-human-review',
    'urgent_label': 'urgent-security-review',
}


def structure(doc, raw):
    p = []
    on = on_of(doc)
    if not isinstance(on, dict) or set(on) != {'workflow_call'}:
        p.append('the workflow must be callable only (on: workflow_call), got %r' % (on,))
    wc = (on or {}).get('workflow_call') or {}
    ins = wc.get('inputs') or {}
    for name, want in DEFAULTS.items():
        if name not in ins:
            p.append('input %s is not declared' % name)
        elif str((ins[name] or {}).get('default', '')) != want:
            p.append('input %s defaults to %r, want %r' % (name, ins[name].get('default'), want))
    if 'METADATA_TOKEN' not in (wc.get('secrets') or {}):
        p.append('secret METADATA_TOKEN (optional alert/compatibility lookup) is not declared')
    if doc.get('permissions') != {}:
        p.append('top-level permissions must be {} so no job inherits a scope; got %r'
                 % (doc.get('permissions'),))
    jobs = doc.get('jobs') or {}
    if set(jobs) != set(JOB_PERMS):
        p.append('jobs must be exactly %s, got %s' % (sorted(JOB_PERMS), sorted(jobs)))
    for name, want in JOB_PERMS.items():
        job = jobs.get(name) or {}
        if job.get('permissions') != want:
            p.append('job %s permissions must be %r, got %r' % (name, want, job.get('permissions')))
        if not job.get('timeout-minutes'):
            p.append('job %s has no timeout-minutes' % name)
        for s in job.get('steps') or []:
            uses = str(s.get('uses') or '')
            if uses.startswith('actions/checkout'):
                p.append('job %s checks out code -- this workflow must never check anything out' % name)
            run = str(s.get('run') or '')
            if '${{' in run:
                p.append('job %s step %r has an expression inside run: -- data would become code'
                         % (name, s.get('name')))
            if '--admin' in run:
                p.append('job %s step %r passes --admin: that bypasses branch protection' % (name, s.get('name')))
            if re.search(r'gh pr merge(?! --auto --squash| --disable-auto)', run):
                p.append('job %s merges without --auto --squash' % name)
    cl = jobs.get('classify') or {}
    if "github.event.pull_request.user.login == 'dependabot[bot]'" not in str(cl.get('if', '')):
        p.append('the classify job is not guarded on the PR author being dependabot[bot]')
    for name in ('auto-merge', 'human-review', 'close'):
        if 'needs.classify.outputs.action' not in str((jobs.get(name) or {}).get('if', '')):
            p.append('job %s is not gated on the classify decision' % name)
    meta = find_step(cl, 'metadata') or {}
    m = re.match(r'^dependabot/fetch-metadata@([0-9a-f]{40})$', str(meta.get('uses', '')))
    if not m:
        p.append('dependabot/fetch-metadata is not pinned by a full 40-hex SHA: %r' % meta.get('uses'))
    elif not re.search(r'dependabot/fetch-metadata@%s # v\d+\.\d+\.\d+' % m.group(1), raw):
        p.append('the fetch-metadata pin carries no `# vX.Y.Z` version comment')
    w = meta.get('with') or {}
    for k in ('skip-verification', 'skip-commit-verification'):
        if str(w.get(k, 'false')).lower() not in ('false', ''):
            p.append('fetch-metadata %s is set: an unverified commit would be classified' % k)
    if not meta.get('continue-on-error'):
        p.append('fetch-metadata must continue-on-error so a refusal is routed to a human, not lost')
    allowed = ('dependabot/fetch-metadata@', 'actions/upload-artifact@')
    for jn, job in jobs.items():
        for s in job.get('steps') or []:
            u = str(s.get('uses') or '')
            if u and not u.startswith(allowed):
                p.append('job %s uses %s -- only fetch-metadata and upload-artifact are expected' % (jn, u))
    auto = find_step(jobs.get('auto-merge') or {}, 'merge') or {}
    if 'gh pr merge --auto --squash' not in str(auto.get('run', '')):
        p.append('the auto-merge step does not call `gh pr merge --auto --squash`')
    return p


def template_structure(tpl, doc):
    p = []
    on = on_of(tpl)
    if not isinstance(on, dict) or set(on) != {'pull_request_target'}:
        p.append('the template must trigger on pull_request_target only, got %r' % (on,))
    jobs = tpl.get('jobs') or {}
    union = {}
    for perms in JOB_PERMS.values():
        for k, v in perms.items():
            if union.get(k) != 'write':
                union[k] = v
    callers = [j for j in jobs.values() if 'reusable-dependabot-triage.yml@' in str(j.get('uses', ''))]
    if len(callers) != 1:
        p.append('the template must call the reusable exactly once, found %d' % len(callers))
    for j in callers:
        if j.get('permissions') != union:
            p.append('the template grants %r; the reusable\'s jobs need exactly %r'
                     % (j.get('permissions'), union))
        if "github.event.pull_request.user.login == 'dependabot[bot]'" not in str(j.get('if', '')):
            p.append('the template call is not guarded on the PR author')
    if tpl.get('permissions') != {}:
        p.append('the template must set top-level permissions: {}')
    for j in jobs.values():
        for s in j.get('steps') or []:
            if str(s.get('uses', '')).startswith('actions/checkout'):
                p.append('the template checks out code under pull_request_target')
    return p


# ----------------------------------------------------------------------------------- fixtures

def dep(name, utype, frm, to, dtype='direct:development', eco='npm_and_yarn', ghsa='', alert=''):
    return {'dependencyName': name, 'dependencyType': dtype,
            'updateType': ('version-update:semver-' + utype) if utype else None,
            'directory': '/', 'packageEcosystem': eco, 'targetBranch': '', 'prevVersion': frm,
            'newVersion': to, 'compatScore': 0, 'maintainerChanges': False, 'dependencyGroup': '',
            'alertState': alert, 'ghsaId': ghsa, 'cvss': 0}


def f(name, changes=4, patch=None):
    d = {'filename': name, 'status': 'modified', 'additions': changes // 2,
         'deletions': changes - changes // 2, 'changes': changes}
    if patch is not None:
        d['patch'] = patch
    return d


PROTECTED = {'protected': True, 'protection': {'enabled': True, 'required_status_checks': {
    'enforcement_level': 'everyone', 'contexts': ['test'], 'checks': [{'context': 'test'}]}}}
UNPROTECTED = {'protected': False, 'protection': {'enabled': False, 'required_status_checks': {
    'enforcement_level': 'off', 'contexts': [], 'checks': []}}}
RULES_WITH_CHECKS = [{'type': 'required_status_checks', 'parameters': {
    'required_status_checks': [{'context': 'build'}]}}]
AUTO = object()   # a lockfile patch built from the case's own dependencies
NPM = [f('package.json'), f('package-lock.json', 40, AUTO)]


def npm_lock_patch(deps, extra=()):
    out = []
    for d in list(deps or []) + list(extra):
        n, a, b = d['dependencyName'], d['prevVersion'], d['newVersion']
        out += ['@@ -10,7 +10,7 @@', '     "node_modules/%s": {' % n,
                '-      "version": "%s",' % a, '+      "version": "%s",' % b,
                '-      "resolved": "https://registry.example/%s-%s.tgz",' % (n, a),
                '+      "resolved": "https://registry.example/%s-%s.tgz",' % (n, b)]
    return '\n'.join(out) + '\n'
ACTIONS_PATCH = ('@@ -10,7 +10,7 @@\n-      - uses: actions/setup-node@%s # v4.1.0\n'
                 '+      - uses: actions/setup-node@%s # v4.2.0\n' % (SHA_A, SHA_B))
ACTIONS_TAG_PATCH = ('@@ -10,7 +10,7 @@\n-      - uses: actions/setup-node@%s # v4.1.0\n'
                     '+      - uses: actions/setup-node@v4.2.0\n' % SHA_A)


def case(label, deps, files=None, want='auto_merge', rule=None, **kw):
    c = {'label': label, 'deps': deps, 'files': NPM if files is None else files,
         'want': want, 'rule': rule}
    c.update(kw)
    return c


CASES = [
    # --- D3: the owner's eight
    case('D3 patch dev dependency -> auto', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         rule='all_conditions_met'),
    case('D3 major -> human', [dep('left-pad', 'major', '1.3.0', '2.0.0')],
         want='human_review', rule='major_update'),
    case('D3 critical package minor -> human',
         [dep('express', 'minor', '4.18.0', '4.19.0', dtype='direct:production')],
         want='human_review', rule='critical_package'),
    case('D3 production lockfile churn over threshold -> human',
         [dep('lodash.merge', 'minor', '4.6.1', '4.7.0', dtype='direct:production')],
         files=[f('package.json'), f('package-lock.json', 1200, AUTO)],
         want='human_review', rule='lockfile_churn'),
    case('D3 github-actions SHA bump same major -> auto',
         [dep('actions/setup-node', 'minor', 'v4.1.0', 'v4.2.0', dtype='direct:production',
              eco='github_actions')],
         files=[f('.github/workflows/build.yml', 2, ACTIONS_PATCH)], rule='all_conditions_met'),
    case('D3 github-actions across a major -> human',
         [dep('actions/setup-node', 'major', 'v4.2.0', 'v5.0.0', dtype='direct:production',
              eco='github_actions')],
         files=[f('.github/workflows/build.yml', 2, ACTIONS_PATCH)],
         want='human_review', rule='major_update'),
    case('D3 security update on a critical package -> human + urgent',
         [dep('jsonwebtoken', 'patch', '9.0.0', '9.0.1', dtype='direct:production',
              ghsa='GHSA-aaaa-bbbb-cccc', alert='OPEN')],
         want='human_review', rule='security_critical', urgent=True, lookup='true'),
    case('D3 excluded fixture path -> close', [dep('requests', 'minor', '2.19.1', '2.33.0', eco='pip')],
         files=[f('tests/consumer-fixture/python/requirements.txt')], want='close',
         rule='excluded_path'),
    # --- D3 controls: the rule is the one named, not a blanket refusal
    case('D3 same churn on a dev-only update -> auto',
         [dep('jest', 'minor', '29.6.0', '29.7.0')],
         files=[f('package.json'), f('package-lock.json', 1200, AUTO)], rule='all_conditions_met'),
    case('D3 security update on a non-critical package -> auto, linkage recorded',
         [dep('minimist', 'patch', '1.2.5', '1.2.8', ghsa='GHSA-xvch-5gv4-984h', alert='OPEN')],
         rule='all_conditions_met', lookup='true', needle='GHSA-xvch-5gv4-984h'),
    case('D3 caller glob adds a critical package', [dep('@acme/billing-client', 'patch', '1.0.0', '1.0.1')],
         want='human_review', rule='critical_package', inputs={'critical_packages': '@acme/*'}),
    case('D3 caller exclusion list closes', [dep('requests', 'patch', '2.31.0', '2.31.1', eco='pip')],
         files=[f('samples/vulnerable/requirements.txt')], want='close', rule='excluded_path',
         inputs={'excluded_paths': 'samples/vulnerable/**'}),
    # --- D4: fail closed
    case('D4 no required checks on the base -> human', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='human_review', rule='no_required_checks', branch=UNPROTECTED, rules=[]),
    case('D4 required checks from a ruleset count', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         rule='all_conditions_met', branch=UNPROTECTED, rules=RULES_WITH_CHECKS,
         inputs={'required_checks': 'build'}),
    case('D4 no scan gate named -> human', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='human_review', rule='scan_gate_unnamed', inputs={'required_checks': ''}),
    case('D4 named scan gate not required on the base -> human',
         [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='human_review', rule='scan_gate_not_required',
         inputs={'required_checks': 'test,security / Security gate'}),
    case('D4 a network package is protected',
         [dep('axios', 'patch', '1.6.0', '1.6.1', dtype='direct:production')],
         want='human_review', rule='critical_package'),
    case('D4 a source file changed -> human', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         files=NPM + [f('src/index.js')], want='human_review', rule='non_dependency_file'),
    case('D4 a workflow line that is not a pin -> human',
         [dep('actions/setup-node', 'minor', 'v4.1.0', 'v4.2.0', dtype='direct:production',
              eco='github_actions')],
         files=[f('.github/workflows/build.yml', 4,
                  ACTIONS_PATCH + '-        run: make\n+        run: curl x | sh\n')],
         want='human_review', rule='non_dependency_change'),
    case('D4 release notes say feat!: -> human', [dep('eslint-plugin-foo', 'minor', '1.2.3', '1.3.0')],
         want='human_review', rule='breaking_change_signal',
         body='<li>feat!: drop support for Node 16</li>'),
    case('D4 release notes say BREAKING -> human', [dep('eslint-plugin-foo', 'minor', '1.2.3', '1.3.0')],
         want='human_review', rule='breaking_change_signal', body='BREAKING: the default changed'),
    case('D4 "no breaking changes" is not a signal', [dep('eslint-plugin-foo', 'minor', '1.2.3', '1.3.0')],
         rule='all_conditions_met', body='Release 1.3.0: no breaking changes, a non-breaking fix.'),
    case('D4 maintainers changed -> human',
         [dict(dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4'), maintainerChanges=True)],
         want='human_review', rule='maintainer_changed'),
    case('D4 lockfile moves an unrelated package -> human', [dep('jest', 'minor', '29.6.0', '29.7.0')],
         files=[f('package.json'), f('package-lock.json', 40, 'UNRELATED')],
         want='human_review', rule='lockfile_unrelated_moves', needle='left-pad'),
    case('D4 lockfile without a diff -> human', [dep('jest', 'minor', '29.6.0', '29.7.0')],
         files=[f('package.json'), f('package-lock.json', 40)],
         want='human_review', rule='lockfile_unparsed'),
    case('D4 protection unreadable -> human', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='human_review', rule='required_checks_unknown', branch=None, rules=None),
    case('D4 PR files unreadable -> human', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='human_review', rule='files_unknown', files_rc='1'),
    case('D4 fetch-metadata refused -> human', None, want='human_review', rule='metadata_unverified',
         meta_outcome='failure'),
    case('D4 update type unknown -> human', [dep('some-lib', None, '1.0.0', '1.0.1')],
         want='human_review', rule='update_type_unknown'),
    case('D4 action moved onto a tag -> human',
         [dep('actions/setup-node', 'minor', 'v4.1.0', 'v4.2.0', dtype='direct:production',
              eco='github_actions')],
         files=[f('.github/workflows/build.yml', 2, ACTIONS_TAG_PATCH)],
         want='human_review', rule='actions_pin_not_sha'),
    case('D4 action versions unreadable -> human',
         [dep('actions/setup-node', 'minor', SHA_A, SHA_B, dtype='direct:production',
              eco='github_actions')],
         files=[f('.github/workflows/build.yml', 2, ACTIONS_PATCH)],
         want='human_review', rule='actions_major_unknown'),
    case('D4 the triage action itself -> human',
         [dep('dependabot/fetch-metadata', 'minor', 'v3.1.0', 'v3.2.0', dtype='direct:production',
              eco='github_actions')],
         files=[f('.github/workflows/build.yml', 2, ACTIONS_PATCH)],
         want='human_review', rule='triage_chain'),
    case('D4 PR edits the caller workflow -> human',
         [dep('actions/setup-node', 'minor', 'v4.1.0', 'v4.2.0', dtype='direct:production',
              eco='github_actions')],
         files=[f('.github/workflows/dependabot-triage.yml', 2, ACTIONS_PATCH)],
         want='human_review', rule='triage_chain'),
    case('D4 docker base image -> human', [dep('node', 'patch', '20.11.0', '20.11.1', eco='docker',
                                               dtype='direct:production')],
         files=[f('Dockerfile')], want='human_review', rule='critical_ecosystem'),
    case('D4 policy names a major as auto -> human', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='human_review', rule='policy_misconfigured',
         inputs={'auto_merge_update_types': 'patch,minor,major'}),
    case('D4 threshold above the ceiling -> human', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='human_review', rule='policy_misconfigured', inputs={'lockfile_line_threshold': '5000'}),
    case('D4 narrower policy (patch only) sends a minor to a human',
         [dep('eslint-plugin-foo', 'minor', '1.2.3', '1.3.0')],
         want='human_review', rule='update_type_not_allowed', inputs={'auto_merge_update_types': 'patch'}),
    case('D4 grouped PR with one major -> human',
         [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4'), dep('left-pad', 'major', '1.3.0', '2.0.0')],
         want='human_review', rule='major_update'),
    case('D4 compatibility floor and no score -> human', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='human_review', rule='compatibility_unknown', inputs={'min_compatibility_score': '80'}),
    case('D4 caller adds terraform as critical', [dep('hashicorp/azurerm', 'minor', '3.1.0', '3.2.0',
                                                      eco='terraform', dtype='direct:production')],
         files=[f('infra/main.tf')], want='human_review', rule='critical_ecosystem',
         inputs={'critical_ecosystems': 'terraform'}),
    # --- D5: the trigger
    case('D5 pull_request is refused loudly', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='none', rule='wrong_trigger', event='pull_request', rc=1),
    case('D5 a human-authored PR is not acted on', [dep('eslint-plugin-foo', 'patch', '1.2.3', '1.2.4')],
         want='none', rule='not_dependabot', author='someone'),
]


def ctx_for(c, inputs):
    deps = c['deps']
    ctx = {
        'github.event_name': c.get('event', 'pull_request_target'),
        'github.event.pull_request.user.login': c.get('author', 'dependabot[bot]'),
        'github.event.pull_request.number': '42',
        'github.event.pull_request.html_url': PR_URL,
        'github.event.pull_request.head.sha': SHA_B,
        'github.event.pull_request.base.ref': 'main',
        'github.repository': REPO,
        'github.workflow_ref': CALLER,
        'github.token': 'ghs_fixture',
        'github.event.pull_request.body': c.get('body', 'Bumps a dependency.'),
        'steps.metadata.outcome': c.get('meta_outcome', 'success'),
        'steps.metadata.outputs.updated-dependencies-json': '' if deps is None else json.dumps(deps),
        "secrets.METADATA_TOKEN != ''": c.get('lookup', 'false'),
        'runner.temp': '',
    }
    for k, v in DEFAULTS.items():
        ctx['inputs.%s' % k] = v
    # The fixture base branch requires `test`; every case names it unless it says otherwise.
    ctx['inputs.required_checks'] = 'test'
    for k, v in inputs.items():
        ctx['inputs.%s' % k] = v
    return ctx


def setup_fixture(work, c):
    fix = os.path.join(work, 'fix')
    os.makedirs(fix)
    with io.open(os.path.join(fix, 'files.jsonl'), 'w', encoding='utf-8', newline='\n') as h:
        for x in c['files']:
            x = dict(x)
            if x.get('patch') is AUTO:
                x['patch'] = npm_lock_patch(c['deps'])
            elif x.get('patch') == 'UNRELATED':
                x['patch'] = npm_lock_patch(c['deps'], [dep('left-pad', 'patch', '1.3.0', '1.3.1')])
            h.write(json.dumps(x) + '\n')
    branch = c.get('branch', PROTECTED)
    if branch is not None:
        json.dump(branch, io.open(os.path.join(fix, 'branch.json'), 'w', encoding='utf-8'))
    rules = c.get('rules', [])
    if rules is not None:
        json.dump(rules, io.open(os.path.join(fix, 'rules.json'), 'w', encoding='utf-8'))
    return fix


def main():
    import _step_harness as H
    if not os.path.exists(WF):
        print('FAIL: %s does not exist -- the kit has no Dependabot triage workflow' % WF_REL)
        return 1
    if not os.path.exists(TPL):
        print('FAIL: %s does not exist -- consumers have no caller to copy' % TPL_REL)
        return 1
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s). Failure to observe is not an observation.' % why)
        return 2
    raw = io.open(WF, encoding='utf-8').read()
    doc = load(WF)
    fails = ['D1 %s' % x for x in structure(doc, raw)]
    fails += ['D2 %s' % x for x in template_structure(load(TPL), doc)]
    if fails:
        for x in fails:
            print('FAIL: %s' % x)
        return 1

    jobs = doc['jobs']
    ev_step = dict(find_step(jobs['classify'], 'evidence'))
    de_step = dict(find_step(jobs['classify'], 'decide'))
    root_work = tempfile.mkdtemp(prefix='dbt-proof-')
    decisions = {}
    try:
        print('%-62s %-13s %s' % ('case', 'action', 'verdict'))
        print('-' * 96)
        for c in CASES:
            work = tempfile.mkdtemp(dir=root_work)
            ws = os.path.join(work, 'ws')
            os.makedirs(ws)
            fix = setup_fixture(work, c)
            shims = os.path.join(work, 'bin')
            H.shim(shims, 'gh', GH_SHIM)
            log = os.path.join(work, 'gh.log')
            env = {'RUNNER_TEMP': ws, 'FIX': fix, 'GH_LOG': log, 'FILES_RC': c.get('files_rc', '0')}
            ctx = ctx_for(c, c.get('inputs') or {})
            ctx['runner.temp'] = ws
            r1 = H.run(bash, ev_step, ctx, ws, shim_dir=shims, extra_env=env)
            r2 = H.run(bash, de_step, ctx, ws, shim_dir=shims, extra_env=env)
            out = r2['outputs']
            problems = []
            if r1['rc'] != 0:
                problems.append('evidence step rc=%s: %s' % (r1['rc'], r1['log'][-400:]))
            if r2['rc'] != c.get('rc', 0):
                problems.append('decide rc=%s want %s: %s' % (r2['rc'], c.get('rc', 0), r2['log'][-600:]))
            if out.get('action', '') != c['want']:
                problems.append('action=%r want %r' % (out.get('action'), c['want']))
            if out.get('rule', '') != c['rule']:
                problems.append('rule=%r want %r' % (out.get('rule'), c['rule']))
            want_urgent = 'true' if c.get('urgent') else 'false'
            if c['want'] != 'none' and out.get('urgent') != want_urgent:
                problems.append('urgent=%r want %r' % (out.get('urgent'), want_urgent))
            labels = out.get('labels', '')
            if c['want'] == 'human_review':
                if 'needs-human-review' not in labels.split(','):
                    problems.append('human_review without the review label: %r' % labels)
                if c.get('urgent') and 'urgent-security-review' not in labels.split(','):
                    problems.append('urgent without the urgent label: %r' % labels)
                if not c.get('urgent') and 'urgent-security-review' in labels.split(','):
                    problems.append('urgent label on a non-urgent decision')
            # D6: the record
            rec_path = os.path.join(ws, 'dependabot-triage', 'decision.json')
            if c['want'] != 'none' or c['rule'] == 'wrong_trigger':
                if not os.path.exists(rec_path):
                    problems.append('no decision.json')
                else:
                    rec = json.load(io.open(rec_path, encoding='utf-8'))
                    decisions[c['label']] = rec
                    if rec.get('action') != c['want'] or rec.get('rule') != c['rule']:
                        problems.append('decision.json disagrees with the outputs: %r/%r'
                                        % (rec.get('action'), rec.get('rule')))
                    for d in (c['deps'] or []):
                        hit = [x for x in rec.get('dependencies', [])
                               if x.get('name') == d['dependencyName']]
                        if not hit:
                            problems.append('decision.json does not record %s' % d['dependencyName'])
                            continue
                        x = hit[0]
                        for k, v in (('from', d['prevVersion']), ('to', d['newVersion'])):
                            if x.get(k) != v:
                                problems.append('%s %s=%r want %r' % (d['dependencyName'], k, x.get(k), v))
                        for k in ('update_type', 'rules', 'verdict', 'ecosystem', 'dependency_type'):
                            if k not in x:
                                problems.append('%s record lacks %s' % (d['dependencyName'], k))
                    summ = r2['summary']
                    for d in (c['deps'] or []):
                        if d['dependencyName'] not in summ:
                            problems.append('summary does not name %s' % d['dependencyName'])
                        if '%s -> %s' % (d['prevVersion'], d['newVersion']) not in summ:
                            problems.append('summary does not show %s -> %s'
                                            % (d['prevVersion'], d['newVersion']))
                    if c['rule'] not in summ or c['want'] not in summ:
                        problems.append('summary does not name the rule and action')
                    if c.get('needle') and c['needle'] not in summ:
                        problems.append('summary does not show %s' % c['needle'])
            if c['want'] in ('human_review', 'close'):
                body = out.get('comment', '')
                if '<!-- kit-dependabot-triage -->' not in body or len(body) < 80:
                    problems.append('no plain-words comment for a %s decision' % c['want'])
            ok = not problems
            print('%-62s %-13s %s' % (c['label'][:62], out.get('action', '-'),
                                      'ok' if ok else 'FAIL'))
            for x in problems:
                print('      %s' % x)
                fails.append('%s: %s' % (c['label'], x))

        fails += act_steps(H, bash, jobs, root_work)
        fails += injection(H, bash, ev_step, de_step, root_work)
    finally:
        shutil.rmtree(root_work, ignore_errors=True)

    print('')
    if fails:
        print('FAILURES (%d):' % len(fails))
        for x in fails:
            print('  - %s' % x)
        return 1
    print('PASS: %d decisions through the shipped evidence and decision steps; the action steps' % len(CASES))
    print('      issue exactly the gh commands named; the merge is --auto --squash, so branch')
    print('      protection and the required checks still decide; PR-derived text stayed data.')
    return 0


def gh_calls(path):
    if not os.path.exists(path):
        return []
    return [x for x in io.open(path, encoding='utf-8').read().split('\n') if x]


def act_steps(H, bash, jobs, root_work):
    """D7: the action steps, run as shipped against a gh shim."""
    fails = []
    comment = '<!-- kit-dependabot-triage -->\nThis update needs a human: it is a major version.'

    def go(job, key, outputs, **env_extra):
        work = tempfile.mkdtemp(dir=root_work)
        ws = os.path.join(work, 'ws')
        os.makedirs(ws)
        fix = os.path.join(work, 'fix')
        os.makedirs(fix)
        shims = os.path.join(work, 'bin')
        H.shim(shims, 'gh', GH_SHIM)
        log = os.path.join(work, 'gh.log')
        ctx = {'github.event.pull_request.html_url': PR_URL,
               'github.event.pull_request.number': '42', 'github.repository': REPO,
               'github.token': 'ghs_fixture', 'runner.temp': ws}
        for k, v in outputs.items():
            ctx['needs.classify.outputs.%s' % k] = v
        for k, v in DEFAULTS.items():
            ctx['inputs.%s' % k] = v
        ctx.update(env_extra.pop('ctx', {}))
        env = {'RUNNER_TEMP': ws, 'FIX': fix, 'GH_LOG': log}
        env.update(env_extra)
        s = find_step(jobs[job], key)
        if s is None:
            return None, ['job %s has no step %s' % (job, key)]
        r = H.run(bash, dict(s), ctx, ws, shim_dir=shims, extra_env=env)
        return r, gh_calls(log)

    r, calls = go('auto-merge', 'merge', {'action': 'auto_merge', 'rule': 'all_conditions_met'})
    merges = [x for x in calls if x.startswith('pr merge')]
    if r is None or r['rc'] != 0 or merges != ['pr merge --auto --squash %s' % PR_URL]:
        fails.append('D7 auto-merge issued %r (rc=%s), want exactly one `pr merge --auto --squash`'
                     % (merges, r and r['rc']))
    else:
        print('%-62s %-13s %s' % ('D7 auto-merge: one `gh pr merge --auto --squash`', 'auto_merge', 'ok'))

    r, calls = go('auto-merge', 'merge', {'action': 'auto_merge', 'rule': 'all_conditions_met'},
                  MERGE_RC='1')
    said = [x for x in calls if x.startswith('pr comment')]
    if r is None or r['rc'] == 0 or not said:
        fails.append('D7 a refused auto-merge must fail the job AND explain on the PR (rc=%s, %r)'
                     % (r and r['rc'], calls))
    else:
        print('%-62s %-13s %s' % ('D7 auto-merge refused: explained on the PR, job fails', 'auto_merge', 'ok'))

    hr = {'action': 'human_review', 'rule': 'major_update', 'urgent': 'false',
          'labels': 'needs-human-review', 'comment': comment}
    r, calls = go('human-review', 'request', hr)
    want = ['label create needs-human-review', 'pr edit %s --add-label needs-human-review' % PR_URL,
            'pr comment %s --body-file' % PR_URL]
    miss = [w for w in want if not any(x.startswith(w) for x in calls)]
    if r is None or r['rc'] != 0 or miss or any(x.startswith('pr merge --auto') for x in calls):
        fails.append('D7 human-review (labels absent, no comment yet): missing %r; calls %r; rc=%s'
                     % (miss, calls, r and r['rc']))
    else:
        print('%-62s %-13s %s' % ('D7 human-review: label created + added, comment posted', 'human_review', 'ok'))

    r, calls = go('human-review', 'request', dict(hr, labels='needs-human-review,urgent-security-review',
                                                  urgent='true'),
                  LABEL_EXISTS='yes', EXISTING_COMMENT='9876', AUTO_MERGE_ON='true',
                  ctx={'inputs.review_team': 'example-org/platform'})
    want = ['pr edit %s --add-label needs-human-review' % PR_URL,
            'pr edit %s --add-label urgent-security-review' % PR_URL,
            'api -X PATCH repos/%s/issues/comments/9876' % REPO,
            'pr merge --disable-auto %s' % PR_URL,
            'pr edit %s --add-reviewer example-org/platform' % PR_URL]
    miss = [w for w in want if not any(x.startswith(w) for x in calls)]
    extra = [x for x in calls if x.startswith('label create') or x.startswith('pr comment')]
    if r is None or r['rc'] != 0 or miss or extra:
        fails.append('D7 human-review (labels exist, comment exists, auto-merge on, team): missing %r, '
                     'unexpected %r; rc=%s' % (miss, extra, r and r['rc']))
    else:
        print('%-62s %-13s %s' % ('D7 human-review: upsert, urgent, auto-merge off, team asked', 'human_review', 'ok'))

    r, calls = go('close', 'close', {'action': 'close', 'rule': 'excluded_path',
                                     'comment': comment.replace('major version', 'fixture path')})
    closes = [x for x in calls if x.startswith('pr close %s --comment' % PR_URL)]
    if r is None or r['rc'] != 0 or len(closes) != 1:
        fails.append('D7 close issued %r (rc=%s)' % (calls, r and r['rc']))
    else:
        print('%-62s %-13s %s' % ('D7 close: one `gh pr close --comment`', 'close', 'ok'))
    return fails


def injection(H, bash, ev_step, de_step, root_work):
    """D8: a dependency name shaped as shell is data in every step that reads it."""
    fails = []
    canary = os.path.join(root_work, 'pwned').replace('\\', '/')
    for shape in ('$(touch %s)' % canary, '`touch %s`' % canary, '"; touch %s; "' % canary):
        c = case('inj', [dep('evil%s' % shape, 'major', '1.0.0', '2.0.0')])
        work = tempfile.mkdtemp(dir=root_work)
        ws = os.path.join(work, 'ws')
        os.makedirs(ws)
        fix = setup_fixture(work, c)
        shims = os.path.join(work, 'bin')
        H.shim(shims, 'gh', GH_SHIM)
        env = {'RUNNER_TEMP': ws, 'FIX': fix, 'GH_LOG': os.path.join(work, 'gh.log')}
        ctx = ctx_for(c, {})
        ctx['runner.temp'] = ws
        H.run(bash, ev_step, ctx, ws, shim_dir=shims, extra_env=env)
        r = H.run(bash, de_step, ctx, ws, shim_dir=shims, extra_env=env)
        if os.path.exists(canary):
            fails.append('D8 INJECTION: a dependency name executed via %s' % shape[:12])
            os.unlink(canary)
        elif r['outputs'].get('action') != 'human_review':
            fails.append('D8 the shell-shaped name was not classified (action=%r)'
                         % r['outputs'].get('action'))
    if not fails:
        print('%-62s %-13s %s' % ('D8 shell-shaped dependency names stay data (3 shapes)', '-', 'ok'))
    return fails


if __name__ == '__main__':
    sys.exit(main())
