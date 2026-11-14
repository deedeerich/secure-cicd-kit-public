#!/usr/bin/env python3
"""`kit org init`: the one-time organisation setup, CHECKED read-only, with a dry-run plan a person carries out.

WHY THIS EXISTS (owner, 2026-11-07)
    A one-time org setup that "sets up what it can and then instructs people on what they need to fill out,
    how to do it, and why it's important." Every consumer repository depends on a handful of organisation
    settings nobody sees until they are wrong: a private kit repository whose reusable workflows are invisible
    to the org (the caller says "workflow not found", which reads as a typo), an Actions allow-list that
    refuses the kit's pinned third-party actions, approver teams that do not exist, a variable set at the
    wrong level. This reads each one and says, per item, PASS / ACTION_NEEDED / NOT_ESTABLISHED, and for
    ACTION_NEEDED: WHAT to change, HOW (the exact gh command, and the GUI path), and WHY it matters.

WHAT IT NEVER DOES
    It never performs a change. Its client sends GET and nothing else (scripts/kit_survey.py ReadOnlyClient;
    tests/prove_kit_org_init.py runs it against a stand-in that answers any other method 405 and records it).
    The "dry-run plan" is the ordered list of commands for a person to run, after reading them.

THE CHECKS
    O1  the kit repository exists and is private or internal (a public copy is the mirror's job)
    O2  other repositories may call its reusable workflows (Actions access level organization / user)
    O3  the org overlay overlays/<name>/ is present in the kit repository
    O4  the approver teams exist (platform and AppSec pools: KDEC-042's uat/prod reviewers)
    O5  KIT_APPROVER_POOLS is set as an org variable, and no per-repository or per-environment variable is set
        at the org level (KIT_APP_TEAM, AZURE_CLIENT_ID, ...: one identity per deployment, not per org)
    O6  Actions permissions allow the kit's reusable workflows and every action owner they pin
    O7  the default workflow token is read-only and cannot approve pull requests
    O8  the OIDC issuer for this host, and the org's subject-claim template (the federated credentials match it)
    O9  the environments template (kit init and its .kit/environments.json spec) is in the kit copy
    O10 Dependabot alerts and security updates on for new repositories (free on every plan)
    O11 secret scanning / GHAS: what is on, and with GHAS off, what still works (the kit does not need GHAS)
    A user account has no organisation settings: O4, O5, O7, O10 and O11 are NOT_ESTABLISHED there, by name,
    and O2 / O6 are read from the kit repository's own settings.

USAGE
    python3 scripts/kit_org_init.py --owner ORG [--host github.com|<tenant>.ghe.com] [--api-url URL]
        [--kit-repo secure-cicd-kit] [--overlay NAME] [--platform-team SLUG] [--appsec-team SLUG] --out DIR
    The token is GH_TOKEN, else GITHUB_TOKEN; read:org (and admin:org read for the Actions settings).
    python3 scripts/kit_org_init.py --self-test

OUTPUT  DIR/ORG_INIT_CHECKLIST.md and DIR/org-init.json
EXIT 0 every item checked (some may be ACTION_NEEDED or NOT_ESTABLISHED)   1 refused (host, token, owner)   2 bad arguments
"""
import argparse
import datetime
import io
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import kit_survey as ks  # noqa: E402

PASS, ACTION_NEEDED, NOT_ESTABLISHED = 'PASS', 'ACTION_NEEDED', 'NOT_ESTABLISHED'

ORG_LEVEL_REQUIRED = ('KIT_APPROVER_POOLS',)
# Set per repository or per environment; at the org level one value would apply to every repository.
WRONG_AT_ORG = ('KIT_APP_TEAM', 'KIT_APP_NAME', 'KIT_RESOURCE_GROUP', 'KIT_ENVIRONMENT_TIER', 'KIT_CLOUD',
                'AZURE_CLIENT_ID', 'AZURE_SUBSCRIPTION_ID', 'KIT_IMAGE_REPOSITORY', 'KIT_ACR_LOGIN_SERVER')
DEFAULT_SUB_CLAIMS = (['repo', 'context'], ['repo', 'context', 'job_workflow_ref'])


def issuer_for(host):
    if host == 'github.com':
        return 'https://token.actions.githubusercontent.com'
    m = re.match(r'^([a-z0-9-]+)\.ghe\.com$', host or '')
    return 'https://token.actions.%s.ghe.com' % m.group(1) if m else None


def kit_action_owners(root=ROOT):
    """The non-GitHub action owners the kit's own workflows and composites pin (an allow-list must cover them)."""
    owners = set()
    for d in (os.path.join(root, '.github', 'workflows'), os.path.join(root, '.github', 'actions')):
        for dirpath, _, files in os.walk(d):
            for fn in files:
                if not fn.endswith(('.yml', '.yaml')):
                    continue
                try:
                    text = io.open(os.path.join(dirpath, fn), encoding='utf-8').read()
                except OSError:
                    continue
                for m in re.finditer(r'uses:\s*["\']?([A-Za-z0-9_.-]+)/[A-Za-z0-9_.-]+[^@\s]*@[0-9a-f]{40}', text):
                    o = m.group(1).lower()
                    if o not in ('actions', 'github'):
                        owners.add(o)
    return sorted(owners)


def item(oid, title, result, what='', how='', why='', detail='', gui=''):
    return {'id': oid, 'title': title, 'result': result, 'what': what, 'how': how, 'why': why, 'detail': detail,
            'gui': gui}


def run_checks(owner, host=None, api_url=None, token=None, kit_repo='secure-cicd-kit', overlay=None,
               platform_team=None, appsec_team=None, env=None, root=ROOT):
    host, api_url = ks.resolve_host(host, api_url, env)
    c = ks.ReadOnlyClient(api_url, token)
    kind = ks.owner_kind(c, owner)
    is_org = kind == 'org'
    overlay = overlay or owner.lower()
    K = '%s/%s' % (owner, kit_repo)
    gh = 'GH_HOST=%s gh' % host if host != 'github.com' else 'gh'
    items = []
    user_note = ('a user account has no organisation setting for this; it is NOT_ESTABLISHED by design. Move the kit '
                 'to an organisation to have it, or set the equivalent on each repository.')

    # O1
    st, repo, _ = c.get('/repos/%s' % K)
    vis = (repo or {}).get('visibility') or ('private' if (repo or {}).get('private') else 'public') if st == 200 else ''
    if st == 200 and not ks.repo_host_matches(repo, host):
        raise ks.Refusal(ks.SURVEY_HOST_MISMATCH, 'the kit repository answered on %s, not %s.'
                         % (ks.host_of(repo.get('html_url')), host))
    if st == 200 and vis in ('private', 'internal'):
        items.append(item('O1', 'The kit repository exists and is %s' % vis, PASS, detail=K))
    elif st == 200:
        items.append(item('O1', 'The kit repository is PUBLIC', ACTION_NEEDED,
                          what='Make the organisation\'s kit copy %s.' % ('internal' if is_org else 'private'),
                          how='%s repo edit %s --visibility %s --accept-visibility-change-consequences'
                              % (gh, K, 'internal' if is_org else 'private'),
                          gui='Kit repository -> Settings -> General -> Danger Zone -> Change visibility',
                          why='The org copy carries the org overlay (its tools, its settings). A public copy publishes '
                              'them; the public mirror exists for the hosted self-tests only.'))
    elif st == 404:
        items.append(item('O1', 'The kit repository does not exist', ACTION_NEEDED,
                          what='Create %s (private) and push the kit\'s neutral export into it.' % K,
                          how='%s repo create %s --%s\n# then, from a kit checkout: python3 scripts/export_for_adoption.py '
                              '(see docs/adoption/SETUP.md) and push the result' % (gh, K, 'internal' if is_org else 'private'),
                          gui='github.com (or your tenant) -> New repository -> owner %s, name %s, Private' % (owner, kit_repo),
                          why='Every consumer pins this repository by commit SHA. Without it nothing can call the kit.'))
    else:
        items.append(item('O1', 'The kit repository could not be read', NOT_ESTABLISHED,
                          detail='HTTP %s: the token needs metadata read on %s' % (st, K)))
    kit_ok = st == 200

    # O2
    if kit_ok and vis == 'public':
        items.append(item('O2', 'Other repositories may call the kit (public: anyone may)', PASS))
    elif kit_ok:
        s2, acc, _ = c.get('/repos/%s/actions/permissions/access' % K)
        level = (acc or {}).get('access_level') if s2 == 200 else None
        want = 'organization' if is_org else 'user'
        if level in (want, 'enterprise', 'organization') or (not is_org and level == 'user'):
            items.append(item('O2', 'Other repositories may call the kit\'s reusable workflows (%s)' % level, PASS))
        elif level is not None:
            items.append(item('O2', 'Other repositories cannot call the kit (access level %s)' % level, ACTION_NEEDED,
                              what='Let repositories owned by %s use the kit\'s workflows.' % owner,
                              how="%s api -X PUT repos/%s/actions/permissions/access -f access_level='%s'" % (gh, K, want),
                              gui='Kit repository -> Settings -> Actions -> General -> Access -> "Accessible from '
                                  'repositories owned by the %s"' % ('organization' if is_org else 'user'),
                              why='A private repository\'s reusable workflows are invisible until this is set, and the '
                                  'caller\'s error says "workflow not found", which reads as a typo in the path '
                                  '(docs/adoption/SETUP.md section 1.5).'))
        else:
            items.append(item('O2', 'The kit\'s Actions access level could not be read', NOT_ESTABLISHED,
                              detail='HTTP %s: needs administration read on the kit repository' % s2))
    else:
        items.append(item('O2', 'Actions access level', NOT_ESTABLISHED, detail='the kit repository was not read (O1)'))

    # O3
    if kit_ok:
        s3, _, _ = c.get('/repos/%s/contents/overlays/%s' % (K, urllib.parse.quote(overlay)))
        if s3 == 200:
            items.append(item('O3', 'The org overlay overlays/%s/ is present' % overlay, PASS))
        elif s3 == 404:
            items.append(item('O3', 'The org overlay overlays/%s/ is missing' % overlay, ACTION_NEEDED,
                              what='Create overlays/%s/ in the kit repository (docs/, workflows/, templates/).' % overlay,
                              how='git switch -c overlay-%s\nmkdir -p overlays/%s/docs overlays/%s/workflows\n'
                                  'printf "# %s overlay\\n" > overlays/%s/README.md\ngit add overlays && git commit -m '
                                  '"Org overlay: %s"\n%s pr create --fill' % (overlay, overlay, overlay, overlay, overlay,
                                                                          overlay, gh),
                              why='Everything the org does that the neutral kit does not (its vendor tools, its '
                                  'settings, practice adopted from the survey) lives here, so a kit upgrade never '
                                  'overwrites it and the neutral kit stays neutral.'))
        else:
            items.append(item('O3', 'The org overlay could not be read', NOT_ESTABLISHED, detail='HTTP %s' % s3))
    else:
        items.append(item('O3', 'The org overlay', NOT_ESTABLISHED, detail='the kit repository was not read (O1)'))

    # O4
    for role, slug in (('platform', platform_team), ('AppSec', appsec_team)):
        if not is_org:
            items.append(item('O4', 'The %s approver team' % role, NOT_ESTABLISHED, detail=user_note +
                              ' Name approvers by login in KIT_APPROVER_POOLS instead.'))
            continue
        if not slug:
            items.append(item('O4', 'The %s approver team is not named' % role, ACTION_NEEDED,
                              what='Decide which team approves uat and prod deployments for %s, and re-run with '
                                   '--%s-team <slug>.' % (role, 'platform' if role == 'platform' else 'appsec'),
                              how='%s api orgs/%s/teams --jq ".[].slug"    # list the teams, then re-run' % (gh, owner),
                              why='KDEC-042: a uat or prod deployment needs a human approval from outside the app '
                                  'team. The pool is that team.'))
            continue
        s4, _, _ = c.get('/orgs/%s/teams/%s' % (owner, urllib.parse.quote(slug.lstrip('@').split('/')[-1])))
        if s4 == 200:
            items.append(item('O4', 'The %s approver team %s exists' % (role, slug), PASS))
        elif s4 == 404:
            items.append(item('O4', 'The %s approver team %s does not exist' % (role, slug), ACTION_NEEDED,
                              what='Create the team and add its members (people outside the app teams).',
                              how="%s api -X POST orgs/%s/teams -f name='%s' -f privacy=closed\n%s api -X PUT "
                                  "orgs/%s/teams/%s/memberships/<login>    # once per member"
                                  % (gh, owner, slug, gh, owner, slug),
                              gui='Organisation -> Teams -> New team',
                              why='uat and prod environments name this team as required reviewers; a missing team '
                                  'leaves the rule naming nobody, and the deploy refuses (ENVIRONMENT_REVIEWERS_EMPTY).'))
        else:
            items.append(item('O4', 'The %s approver team could not be read' % role, NOT_ESTABLISHED,
                              detail='HTTP %s: needs read:org' % s4))

    # O5
    if is_org:
        s5, vitems, _ = c.pages('/orgs/%s/actions/variables' % owner, key='variables')
        names = set(ks.names_only(vitems)) if s5 == ks.READ else None
        if names is None:
            items.append(item('O5', 'Organisation variables could not be read', NOT_ESTABLISHED,
                              detail='needs the organisation variables read permission (admin:org read)'))
        else:
            for v in ORG_LEVEL_REQUIRED:
                if v in names:
                    items.append(item('O5', '%s is set at the organisation level' % v, PASS))
                else:
                    pools = json.dumps({'platform': ['@%s/%s' % (owner, (platform_team or '<platform-team>').lstrip('@').split('/')[-1])],
                                        'security': ['@%s/%s' % (owner, (appsec_team or '<appsec-team>').lstrip('@').split('/')[-1])]},
                                       separators=(',', ':'))
                    items.append(item('O5', '%s is not set at the organisation level' % v, ACTION_NEEDED,
                                      what='Name the approver pools once for every repository.',
                                      how="%s variable set %s --org %s --visibility all --body '%s'" % (gh, v, owner, pools),
                                      gui='Organisation -> Settings -> Secrets and variables -> Actions -> Variables',
                                      why='The deploy reads it at uat and prod to check the reviewers come from the '
                                          'platform or security pool (KDEC-042). A repository may still override it.'))
            wrong = sorted(names & set(WRONG_AT_ORG))
            if wrong:
                items.append(item('O5', 'Set at the organisation level but belongs to a repository or environment: %s'
                                  % ', '.join(wrong), ACTION_NEEDED,
                                  what='Move each to the repository (or its environment) it describes.',
                                  how='\n'.join('%s variable set %s --repo %s/<repo> --env <environment> --body <value>\n'
                                                '%s variable delete %s --org %s    # after every repository has its own'
                                                % (gh, w, owner, gh, w, owner) for w in wrong),
                                  why='One org-wide value means every repository deploys as the same identity or to the '
                                      'same app: OIDC is one identity per deployment per subscription.'))
            else:
                items.append(item('O5', 'No per-repository variable is set at the organisation level', PASS))
    else:
        items.append(item('O5', 'Organisation variables', NOT_ESTABLISHED, detail=user_note))

    # O6
    owners = kit_action_owners(root)
    path = '/orgs/%s/actions/permissions' % owner if is_org else '/repos/%s/actions/permissions' % K
    s6, perm, _ = c.get(path)
    if s6 != 200 or not isinstance(perm, dict):
        items.append(item('O6', 'Actions permissions could not be read', NOT_ESTABLISHED,
                          detail='HTTP %s on %s: needs administration read' % (s6, path)))
    else:
        allowed = perm.get('allowed_actions')
        enabled = perm.get('enabled_repositories', perm.get('enabled'))
        if enabled in ('none', False):
            items.append(item('O6', 'GitHub Actions is turned off', ACTION_NEEDED,
                              what='Allow Actions for the repositories that will use the kit.',
                              how='%s api -X PUT %s -f enabled_repositories=all -f allowed_actions=selected'
                                  % (gh, path.lstrip('/')) if is_org else '%s api -X PUT %s -F enabled=true' % (gh, path.lstrip('/')),
                              why='Every kit control runs as a workflow.'))
        elif allowed == 'all':
            items.append(item('O6', 'Actions permissions allow every action (the kit\'s included)', PASS,
                              detail='The kit pins every action by SHA. Consider "selected" with the owners below: %s'
                                     % ', '.join(owners)))
        elif allowed == 'local_only':
            items.append(item('O6', 'Actions permissions allow local actions only', ACTION_NEEDED,
                              what='Allow GitHub-owned actions and the action owners the kit pins.',
                              how=_selected_how(gh, path, owners),
                              why='The kit\'s workflows pin third-party actions (%s); with local-only every scanner '
                                  'job fails before its first step.' % ', '.join(owners)))
        else:
            s6b, sel, _ = c.get(path + '/selected-actions')
            if s6b != 200 or not isinstance(sel, dict):
                items.append(item('O6', 'The selected-actions list could not be read', NOT_ESTABLISHED, detail='HTTP %s' % s6b))
            else:
                pats = [p.lower() for p in sel.get('patterns_allowed') or []]
                missing = [o for o in owners if not any(p.startswith(o + '/') for p in pats)]
                gh_owned = sel.get('github_owned_allowed')
                if missing or not gh_owned:
                    items.append(item('O6', 'The Actions allow-list misses what the kit uses', ACTION_NEEDED,
                                      what='Add %s%s.' % ('GitHub-owned actions and ' if not gh_owned else '',
                                                          ', '.join('%s/*' % o for o in missing) or 'nothing else'),
                                      how=_selected_how(gh, path, owners, pats),
                                      why='A refused action fails the job with "not allowed", before any scan runs.'))
                else:
                    items.append(item('O6', 'The Actions allow-list covers every action owner the kit pins', PASS))
        if perm.get('sha_pinning_required') is True:
            items.append(item('O6', 'The organisation requires actions pinned by SHA (the kit already is)', PASS))

    # O7
    if is_org:
        s7, wp, _ = c.get('/orgs/%s/actions/permissions/workflow' % owner)
        if s7 != 200 or not isinstance(wp, dict):
            items.append(item('O7', 'The default workflow token could not be read', NOT_ESTABLISHED, detail='HTTP %s' % s7))
        elif wp.get('default_workflow_permissions') == 'read' and not wp.get('can_approve_pull_request_reviews'):
            items.append(item('O7', 'The default workflow token is read-only and cannot approve pull requests', PASS))
        else:
            items.append(item('O7', 'The default workflow token is %s%s' % (
                wp.get('default_workflow_permissions'), ' and may approve pull requests'
                if wp.get('can_approve_pull_request_reviews') else ''), ACTION_NEEDED,
                what='Make the default token read-only and stop it approving pull requests.',
                how='%s api -X PUT orgs/%s/actions/permissions/workflow -f default_workflow_permissions=read '
                    '-F can_approve_pull_request_reviews=false' % (gh, owner),
                gui='Organisation -> Settings -> Actions -> General -> Workflow permissions',
                why='The kit grants each job exactly what it needs; a write default hands every other workflow more. '
                    'A token that may approve pull requests can satisfy a review rule without a person.'))
    else:
        items.append(item('O7', 'The default workflow token', NOT_ESTABLISHED, detail=user_note))

    # O8
    iss = issuer_for(host)
    items.append(item('O8', 'The OIDC issuer for %s is %s' % (host, iss), PASS,
                      detail='Every Azure federated credential uses this issuer (KDEC-027). A GHE.com tenant has its '
                             'own; github.com\'s is never right there.'))
    if is_org:
        s8, sub, _ = c.get('/orgs/%s/actions/oidc/customization/sub' % owner)
        keys = (sub or {}).get('include_claim_keys') if s8 == 200 and isinstance(sub, dict) else None
        if s8 == 404 or (s8 == 200 and (not keys or keys in DEFAULT_SUB_CLAIMS)):
            items.append(item('O8', 'The OIDC subject claim is the default (repo:<org>/<repo>:environment:<env>)', PASS))
        elif s8 == 200:
            items.append(item('O8', 'The OIDC subject claim is customised (%s)' % ', '.join(keys), ACTION_NEEDED,
                              what='Write each federated credential\'s subject in this template, or reset it.',
                              how='%s api orgs/%s/actions/oidc/customization/sub    # read the template, then match it in '
                                  'every `az ad app federated-credential create --parameters` subject' % (gh, owner),
                              why='docs/adoption/SETUP.md writes subjects in the default form; a customised template '
                                  'makes every Azure login fail with AADSTS700213 (no matching federated identity).'))
        else:
            items.append(item('O8', 'The OIDC subject template could not be read', NOT_ESTABLISHED, detail='HTTP %s' % s8))

    # O9
    if kit_ok:
        s9, _, _ = c.get('/repos/%s/contents/scripts/kit_init.py' % K)
        s9b, _, _ = c.get('/repos/%s/contents/templates/kit-init.yml' % K)
        if s9 == 200 and s9b == 200:
            items.append(item('O9', 'The environments template (kit init and its .kit/environments.json spec) is in '
                              'the kit copy', PASS, detail='Each repository\'s dev/test/uat/prod spec is written by kit '
                              'init; a person applies it with the commands in its .kit/ADOPTION_CHECKLIST.md.'))
        elif 404 in (s9, s9b):
            items.append(item('O9', 'The kit copy lacks kit init or its template', ACTION_NEEDED,
                              what='Refresh the kit copy from the current neutral export.',
                              how='python3 scripts/export_for_adoption.py    # from a current kit checkout; then push to %s' % K,
                              why='kit init writes the environments spec, the callers and the checklist; without it '
                                  'every repository is wired by hand.'))
        else:
            items.append(item('O9', 'The environments template could not be read', NOT_ESTABLISHED,
                              detail='HTTP %s / %s' % (s9, s9b)))

    # O10, O11
    if is_org:
        s10, org, _ = c.get('/orgs/%s' % owner)
        org = org if s10 == 200 and isinstance(org, dict) else {}
        da = org.get('dependabot_alerts_enabled_for_new_repositories')
        du = org.get('dependabot_security_updates_enabled_for_new_repositories')
        if da is None:
            items.append(item('O10', 'Dependabot defaults for new repositories', NOT_ESTABLISHED,
                              detail='the organisation\'s security defaults are visible to an org owner only'))
        elif da and du:
            items.append(item('O10', 'Dependabot alerts and security updates are on for new repositories', PASS))
        else:
            items.append(item('O10', 'Dependabot is not on for new repositories', ACTION_NEEDED,
                              what='Turn on Dependabot alerts and security updates for new (and existing) repositories.',
                              how='%s api -X PATCH orgs/%s -F dependabot_alerts_enabled_for_new_repositories=true '
                                  '-F dependabot_security_updates_enabled_for_new_repositories=true' % (gh, owner),
                              gui='Organisation -> Settings -> Code security -> Configurations (apply to all)',
                              why='Free on every plan, with or without GHAS. The kit\'s Dependabot triage and config '
                                  'check work on what it opens.'))
        ghas = org.get('advanced_security_enabled_for_new_repositories')
        ss = org.get('secret_scanning_enabled_for_new_repositories')
        still = ('With GHAS off the kit still runs in full: its gitleaks secret scan blocks in every mode, its gate reads '
                 'the scanners\' SARIF itself (no Security tab needed), Dependabot alerts and updates are free. Not '
                 'available without it on private repositories: GitHub secret scanning and push protection (Secret '
                 'Protection) and the code-scanning Security tab (Code Security).')
        if ghas is None and ss is None:
            items.append(item('O11', 'Secret scanning / GHAS state', NOT_ESTABLISHED,
                              detail='visible to an org owner only. ' + still))
        else:
            items.append(item('O11', 'The kit does not need GHAS (GHAS %s, GitHub secret scanning %s)' % (
                'on' if ghas else 'off', 'on' if ss else 'off'), PASS, detail=still))
    else:
        items.append(item('O10', 'Dependabot defaults', NOT_ESTABLISHED, detail=user_note + ' Turn on Dependabot alerts '
                          'per repository: Settings -> Code security.'))
        items.append(item('O11', 'Secret scanning / GHAS', NOT_ESTABLISHED, detail=user_note))

    return {'schema': 'kit-org-init/1', 'owner': owner, 'owner_kind': kind, 'host': host, 'kit_repo': K,
            'overlay': overlay, 'generated': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'requests': c.calls, 'items': items,
            'counts': dict((r, sum(1 for i in items if i['result'] == r)) for r in (PASS, ACTION_NEEDED, NOT_ESTABLISHED))}


def _selected_how(gh, path, owners, have=()):
    pats = sorted(set(list(have) + ['%s/*' % o for o in owners]))
    body = json.dumps({'github_owned_allowed': True, 'verified_allowed': False, 'patterns_allowed': pats})
    return ("%s api -X PUT %s -f allowed_actions=selected\n%s api -X PUT %s/selected-actions --input - <<'JSON'\n%s\nJSON"
            % (gh, path.lstrip('/'), gh, path.lstrip('/'), body))


def checklist_md(res):
    c = res['counts']
    L = ['# Organisation setup checklist: %s (%s, %s)' % (res['owner'], res['owner_kind'], res['host']), '',
         'Generated %s by scripts/kit_org_init.py. **Nothing was changed**: every item was read, and each '
         'ACTION_NEEDED item says what to change, how (the exact command; run it yourself after reading it) and why.'
         % res['generated'], '',
         'PASS %d, ACTION_NEEDED %d, NOT_ESTABLISHED %d (could not be read: a permission, or not an organisation).'
         % (c[PASS], c[ACTION_NEEDED], c[NOT_ESTABLISHED]), '',
         '## What you need to fill out', '',
         '- The kit repository name (`%s`) and the overlay name (`overlays/%s/`).' % (res['kit_repo'], res['overlay']),
         '- The platform and AppSec approver team slugs (people outside the app teams).',
         '- Which clouds you deploy to, and per repository its environments (kit init asks; `.kit/environments.json`).',
         '- A read-only token for the survey and this check (see docs/adoption/ORG_SURVEY_AND_ORG_INIT.md).', '',
         '| id | item | result |', '|---|---|---|']
    for i in res['items']:
        L.append('| %s | %s | **%s** |' % (i['id'], i['title'], i['result']))
    for i in res['items']:
        L += ['', '## %s %s: %s' % (i['id'], i['title'], i['result'])]
        if i['detail']:
            L += ['', i['detail']]
        if i['result'] == ACTION_NEEDED:
            L += ['', '**What:** %s' % i['what'], '', '**Why it matters:** %s' % i['why'], '', '**How:**', '', '```bash',
                  i['how'], '```']
            if i['gui']:
                L += ['', 'Or in the browser: %s.' % i['gui']]
    L += ['', '## Dry-run plan (in order; nothing here has been run)', '']
    n = 0
    for i in res['items']:
        if i['result'] == ACTION_NEEDED:
            n += 1
            L += ['%d. %s %s' % (n, i['id'], i['what']), '', '   ```bash'] + ['   ' + ln for ln in i['how'].splitlines()] + \
                 ['   ```', '']
    if not n:
        L.append('Nothing to do.')
    return L


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--owner')
    ap.add_argument('--host')
    ap.add_argument('--api-url')
    ap.add_argument('--kit-repo', default='secure-cicd-kit')
    ap.add_argument('--overlay')
    ap.add_argument('--platform-team')
    ap.add_argument('--appsec-team')
    ap.add_argument('--out')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.owner or not a.out:
        ap.error('--owner and --out are required')
    try:
        if ks._inside_kit(a.out):
            raise ks.Refusal(ks.SURVEY_OUT_IN_KIT, 'refusing to write inside the kit (%s): the checklist names the '
                             'organisation\'s settings. Choose a directory outside the repository.' % os.path.normpath(a.out))
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN') or None
        res = run_checks(a.owner, a.host, a.api_url, token, a.kit_repo, a.overlay, a.platform_team, a.appsec_team)
    except ks.Refusal as e:
        print('%s\n  %s' % (e.state, e.detail))
        return 1
    os.makedirs(a.out, exist_ok=True)
    with io.open(os.path.join(a.out, 'ORG_INIT_CHECKLIST.md'), 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(checklist_md(res)) + '\n')
    with io.open(os.path.join(a.out, 'org-init.json'), 'w', encoding='utf-8') as fh:
        json.dump(res, fh, indent=1, sort_keys=True)
    c = res['counts']
    print('org init check for %s: PASS %d, ACTION_NEEDED %d, NOT_ESTABLISHED %d (nothing changed). %s'
          % (a.owner, c[PASS], c[ACTION_NEEDED], c[NOT_ESTABLISHED], os.path.join(os.path.normpath(a.out), 'ORG_INIT_CHECKLIST.md')))
    return 0


def self_test():
    bad = []
    if issuer_for('acme.ghe.com') != 'https://token.actions.acme.ghe.com':
        bad.append('ghe issuer')
    if issuer_for('github.com') != 'https://token.actions.githubusercontent.com' or issuer_for('ghes.example.com'):
        bad.append('github.com issuer')
    owners = kit_action_owners()
    if not owners or 'actions' in owners:
        bad.append('kit action owners %r' % owners)
    if not hasattr(ks.ReadOnlyClient, 'get') or any(hasattr(ks.ReadOnlyClient, m) for m in ('post', 'put', 'patch', 'delete')):
        bad.append('the client has a write method')
    print('kit_org_init self-test: %s' % ('PASS' if not bad else 'FAIL ' + '; '.join(bad)))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
