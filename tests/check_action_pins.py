#!/usr/bin/env python3
"""Every remote `uses:` in the kit is a full commit SHA naming its exact release (ledger L82, O-23).

WHY THIS EXISTS

    The kit ships a policy gate whose threat model names one control first: pin a third-party action
    to a full 40-character commit SHA, because a tag can be repointed at different code (the
    tj-actions/changed-files pattern). On 2cd078e the kit's OWN tree carried 161 remote `uses:`
    references by tag and one by SHA, and the self-test ran that gate against itself with
    `require_sha_pinning: false` under a weakening dated to expire 2026-10-31. The owner's ruling
    (O-23) was to run the sweep, not to re-date the exception.

    The policy gate cannot hold this alone. It exempts `trusted_orgs` (actions, github, azure,
    docker, hashicorp) by default -- a consumer's risk acceptance, not this kit's -- it does not read
    `templates/`, and a bare SHA is a NOTE there, not an ERROR. A SHA is only reviewable if the
    comment beside it names the release it is, and only honest if that release really is that SHA.

WHAT IT REQUIRES, over `.github/workflows/*`, `.github/actions/**/action.y*ml` and `templates/*`
    (every job-level `uses:` calling a reusable workflow, every step `uses:`, every composite step)

      P1  a remote reference is pinned by a full 40-hex commit SHA -- not a tag, not a branch
      P2  the line carries a trailing `# vX.Y.Z` comment: the EXACT release, never a moving major
      P3  where the (action, SHA) pair is in the recorded table below, the comment names the version
          recorded for it; and a comment naming a recorded version must carry that version's SHA
      P4  `--online`: every pin is checked against github.com -- the tag the comment names, peeled
          through annotated tags, is that commit. By `git ls-remote` (no token); the REST API only
          as a fallback with a token api.github.com issued, never a ghe.com run's (KDEC-027).
          Rate limit or no network is UNKNOWN (2), and the UNKNOWN names its cause (D-11).
      P5  .github/dependabot.yml's github-actions entry reads `/` and every composite directory
          (so the pins stay current everywhere they are), and still excludes
          tests/consumer-fixture/**. On 2cd078e it read `/` only: every composite unread.
          And it does NOT read `overlays/`: an overlay's workflows ship to that consumer's own copy
          (scripts/export-profiles) and are maintained there, with the consumer's own Dependabot.
          A kit-side bump PR against an overlay would change a file whose owner is not here.
      P6  every manifest directory under tests/consumer-fixture/ has its own dependabot.yml entry
          (its ecosystem, that exact `directory`) that ignores every dependency (`dependency-name:
          "*"`) and opens no version-update PR (`open-pull-requests-limit: 0`). `exclude-paths`
          (P5) binds version updates only: an ALERT-DRIVEN security update ignores it, and opened
          #2, #4, #7 (pip) and #9 (log4j-core 2.14.1 -> 2.25.4 in full/java) against the
          fixture. Security updates do apply the `ignore` of the entry matching their ecosystem
          and directory, so the fixture's pins stay the hand-kept acceptance signals.
      P7  every other dependabot.yml entry names a directory holding a manifest of its ecosystem.
          An entry at `/` for an ecosystem the kit's root does not have fails Dependabot's own
          update job (`dependency_file_not_found`) every week (2026-11-02, the owner's work copy).
      P8  the converse of P7, and how a bump stays mergeable (owner, 2026-11-04): every directory
          OUTSIDE tests/consumer-fixture/ (and outside overlays/, .git) that holds a manifest is
          read by an entry of its ecosystem, so a REAL dependency is kept current; and every entry
          that may open pull requests says `rebase-strategy: auto`, so a Dependabot PR that falls
          into conflict with main is rebased by Dependabot instead of sitting red.

    OVERLAYS ARE IN SCOPE for P1-P4 (`overlays/*/workflows/*`): they ship, by the consumer export
    profile, into a consumer's repository, and a tag there is the same repointable code with that
    consumer's secrets. On 4dfd858 the one overlay carried 5 remote refs by tag.

    Not remote, and out of scope: `./` and `$/` (this repository at the running commit), and
    `docker://` (an image; tests/check_pinned_artifacts.py and the policy gate read images).
    Two placeholder forms are accepted, each in its own tree only: in `templates/`,
    `YOUR_ORG/secure-cicd-kit/...@` forty zeros `# pin a commit SHA`; in `overlays/`,
    `KIT_OWNER/KIT_REPO/...@` forty zeros (tests/check_custody.py owns that call's shape). A copy
    must pin THEIR fork's commit; forty zeros cannot resolve, so an unedited copy fails closed
    rather than running a tag.

THE RECORDED TABLE
    Resolved 2026-10-22 through the GitHub REST API (`git/ref/tags/<tag>`, annotated tags peeled to
    the commit), each commit confirmed either on the action's default-branch history (compare API:
    the default branch is identical to or ahead of it) or the target of a published release tag
    (azure/login v3.1.0 is cut from a release branch; actions/setup-java v6.1.0 resolved 2026-11-06). Dependabot's
    github-actions ecosystem updates a SHA and its version comment together; a pin it moves leaves
    this table and P3 no longer spot-checks it, so P4 (`--online`, run by the self-test) is what
    checks every pin. A row is evidence of one resolution, not a list of allowed
    versions.

SELF-TEST
    Before the real tree is read, a sandbox tree seeds each defect in each location -- a tag in a
    workflow step, in a job-level reusable call, in a composite step and in a template; a SHA with no
    comment; a comment naming a moving major; a comment the table contradicts; a recorded version on
    the wrong SHA; the zero placeholder outside templates -- and each must be refused. A control
    tree (pinned, `./`, `$/`, `docker://`, a template placeholder, a commented-out line) must pass.

EXIT  0 every remote reference is pinned and named   1 a reference is not   2 could not be checked
"""
import glob
import io
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _github_refs  # noqa: E402 - after the path insert

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SCOPE = ['.github/workflows/*.yml', '.github/workflows/*.yaml',
         '.github/actions/**/action.yml', '.github/actions/**/action.yaml',
         'templates/*.yml', 'templates/*.yaml',
         'overlays/*/workflows/*.yml', 'overlays/*/workflows/*.yaml',
         # KDEC-028: an overlay's composite actions and its consumer template ship the same way.
         'overlays/*/actions/**/action.yml', 'overlays/*/templates/*.yml']
SHA40 = re.compile(r'^[0-9a-f]{40}$')
EXACT = re.compile(r'^v\d+\.\d+\.\d+$')
ZERO = '0' * 40
PLACEHOLDER = re.compile(r'^YOUR_ORG/secure-cicd-kit/[A-Za-z0-9_./-]+@' + ZERO + '$')
PLACEHOLDER_COMMENT = '# pin a commit SHA'
OVERLAY_PLACEHOLDER = re.compile(r'^KIT_OWNER/KIT_REPO/[A-Za-z0-9_./-]+@' + ZERO + '$')

# (owner/repo) -> {commit SHA: exact release}. See THE RECORDED TABLE above.
RECORDED = {
    'actions/attest': {'1e69f48acb82d1966a394da916b4c1698aa569d6': 'v4.2.2'},
    'actions/cache': {'55cc8345863c7cc4c66a329aec7e433d2d1c52a9': 'v6.1.0'},
    'actions/checkout': {'3d3c42e5aac5ba805825da76410c181273ba90b1': 'v7.0.1'},
    'actions/download-artifact': {'9000827ccba6bdab643e8b6fd33ac0654aef8333': 'v8.0.2'},
    'actions/setup-dotnet': {'a98b56852c35b8e3190ac28c8c2271da59106c68': 'v6.0.0'},
    'actions/setup-go': {'b7ad1dad31e06c5925ef5d2fc7ad053ef454303e': 'v7.0.0'},
    'actions/setup-java': {'b843ebf9b913146b38da2eaa7aeddf76074ae1ad': 'v6.1.0'},
    'actions/setup-node': {'949feb2413d6458794dcd2491c4babbbce0c15c1': 'v7.1.0'},
    'actions/setup-python': {'6d4fd22b20465ccc0f7354476588e8df7c9ca0e0': 'v7.1.0'},
    'actions/upload-artifact': {'cf430e030ddbb5b0abf93d22962f4752f3646cd9': 'v7.0.2'},
    'aquasecurity/trivy-action': {'ed142fd0673e97e23eac54620cfb913e5ce36c25': 'v0.36.0'},
    'azure/login': {'a641126d1b8aa4d1fa005f4f92df94a3a4c4c906': 'v3.1.0'},
    'bridgecrewio/checkov-action': {'c3e106d5f8f4253a6de5110efb41a080f83db294': 'v12.3135.0'},
    'docker/build-push-action': {'c3c9e263c25d99ce0380d002d59b67737d91b0dc': 'v7.4.0'},
    'docker/setup-buildx-action': {'f87e5991a6d7451dcb8d9637bfbc97413f497069': 'v4.4.1'},
    'dorny/paths-filter': {'ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d': 'v4.0.3'},
    'github/codeql-action': {'9b3254085494b55a0f7c4c2b3d2d52cc712ce370': 'v4.39.1'},
    'hashicorp/setup-terraform': {'dfe3c3f87815947d99a8997f908cb6525fc44e9e': 'v4.0.1'},
    # Overlay-only (the one consumer overlay under overlays/), resolved the same way the same day.
    'SonarSource/sonarqube-scan-action': {'fd88b7d7ccbaefd23d8f36f73b59db7a3d246602': 'v6.0.0'},
    'zaproxy/action-baseline': {'7c4deb10e6261301961c86d65d54a516394f9aed': 'v0.14.0'},
}


def parsed_uses(doc):
    """-> [(where, uses)] for every job-level, step and composite-step `uses:` string."""
    out = []
    if not isinstance(doc, dict):
        return out
    jobs = doc.get('jobs')
    if isinstance(jobs, dict):
        for name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if isinstance(job.get('uses'), str):
                out.append(('%s (reusable workflow)' % name, job['uses']))
            for i, s in enumerate(job.get('steps') or []):
                if isinstance(s, dict) and isinstance(s.get('uses'), str):
                    out.append(('%s step %d' % (name, i + 1), s['uses']))
    runs = doc.get('runs')
    if isinstance(runs, dict):
        for i, s in enumerate(runs.get('steps') or []):
            if isinstance(s, dict) and isinstance(s.get('uses'), str):
                out.append(('composite step %d' % (i + 1), s['uses']))
    return out


def remote(uses):
    return not uses.startswith(('./', '$/', 'docker://'))


def line_comments(raw, uses):
    """-> [comment text or ''] for each uncommented `uses:` line carrying exactly this value."""
    rx = re.compile(r'^\s*(?:-\s+)?uses:\s*["\']?' + re.escape(uses) + r'["\']?\s*(#.*)?$')
    return [(m.group(1) or '').strip() for m in (rx.match(ln) for ln in raw.split('\n')) if m]


def check_file(rel, raw, problems, pins):
    import yaml
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        problems.append('%s: unparseable YAML (%s)' % (rel, str(e).splitlines()[0]))
        return
    refs = [(w, u) for w, u in parsed_uses(doc) if remote(u)]
    seen = {}
    in_templates = rel.replace('\\', '/').startswith('templates/')
    in_overlays = rel.replace('\\', '/').startswith('overlays/')
    for where, uses in refs:
        k = seen.get(uses, 0)
        seen[uses] = k + 1
        comments = line_comments(raw, uses)
        comment = comments[k] if k < len(comments) else None
        at = '%s: %s `%s`' % (rel, where, uses)
        if comment is None:
            problems.append('%s: no source line carries this reference; cannot read its comment' % at)
            continue
        if PLACEHOLDER.match(uses):
            if not in_templates:
                problems.append('%s: the forty-zero placeholder belongs in templates/ only' % at)
            elif comment != PLACEHOLDER_COMMENT:
                problems.append('%s: a template placeholder must say `%s`' % (at, PLACEHOLDER_COMMENT))
            continue
        if OVERLAY_PLACEHOLDER.match(uses):
            if not in_overlays:
                problems.append('%s: the KIT_OWNER/KIT_REPO placeholder belongs in overlays/ only' % at)
            continue
        if '@' not in uses:
            problems.append('%s: no ref at all (P1)' % at)
            continue
        path, ref = uses.rsplit('@', 1)
        repo = '/'.join(path.split('/')[:2])
        if not SHA40.match(ref):
            problems.append('%s: pinned by `%s`, not a 40-hex commit SHA (P1)' % (at, ref))
            continue
        m = re.match(r'^#\s*(\S+)', comment)
        version = m.group(1) if m else None
        if not version:
            problems.append('%s: SHA with no trailing `# vX.Y.Z` comment (P2)' % at)
            continue
        if not EXACT.match(version):
            problems.append('%s: comment `%s` is not an exact release vX.Y.Z (P2)' % (at, version))
            continue
        table = RECORDED.get(repo, {})
        if ref in table and table[ref] != version:
            problems.append('%s: comment says %s, the recorded table says this SHA is %s (P3)'
                            % (at, version, table[ref]))
            continue
        wrong = [s for s, v in table.items() if v == version and s != ref]
        if wrong:
            problems.append('%s: %s is recorded as %s, not this SHA (P3)' % (at, version, wrong[0]))
            continue
        pins.append((repo, ref, version, at))


def scan(root):
    """-> (problems, pins, files_read)."""
    problems, pins, files = [], [], 0
    for pat in SCOPE:
        for f in sorted(glob.glob(os.path.join(root, pat), recursive=True)):
            if not os.path.isfile(f):
                continue
            files += 1
            rel = os.path.relpath(f, root).replace('\\', '/')
            check_file(rel, io.open(f, encoding='utf-8').read(), problems, pins)
    return problems, pins, files


def dependabot_problems(root):
    """P5: Dependabot's github-actions ecosystem reads the workflows AND every composite, and still
    leaves the deliberately vulnerable consumer fixture alone."""
    import fnmatch
    import yaml
    p = os.path.join(root, '.github', 'dependabot.yml')
    if not os.path.isfile(p):
        return ['.github/dependabot.yml is missing: nothing keeps the pins current (P5)']
    doc = yaml.safe_load(io.open(p, encoding='utf-8')) or {}
    ga = [u for u in doc.get('updates') or [] if u.get('package-ecosystem') == 'github-actions']
    if len(ga) != 1:
        return ['dependabot.yml has %d github-actions entries, want 1 (P5)' % len(ga)]
    u = ga[0]
    dirs = list(u.get('directories') or []) + ([u['directory']] if u.get('directory') else [])
    out = []
    if '/' not in dirs:
        out.append('dependabot github-actions does not read `/` (the workflows) (P5)')
    for d in sorted(glob.glob(os.path.join(root, '.github', 'actions', '*', 'action.y*ml'))):
        rel = '/' + os.path.relpath(os.path.dirname(d), root).replace('\\', '/')
        if not any(fnmatch.fnmatchcase(rel, pat) for pat in dirs):
            out.append('dependabot github-actions does not read the composite %s (P5)' % rel)
    for pat in dirs:
        if str(pat).lstrip('/').startswith('overlays') or fnmatch.fnmatchcase('/overlays/x/workflows', pat):
            out.append('dependabot github-actions reads overlays (%s): an overlay is maintained with '
                       'its consumer, not bumped from here (P5)' % pat)
    if 'tests/consumer-fixture/**' not in (u.get('exclude-paths') or []):
        out.append('dependabot github-actions no longer excludes tests/consumer-fixture/** (P5)')
    return out


# Manifest file name -> Dependabot ecosystem (P6). Only names the fixture tree uses or plausibly
# will; an unmapped manifest is not silently fine -- FIXTURE_UNMAPPED below refuses it.
FIXTURE_MANIFESTS = {
    'requirements.txt': 'pip', 'pyproject.toml': 'pip', 'Pipfile': 'pip',
    'package.json': 'npm', 'pom.xml': 'maven', 'go.mod': 'gomod', 'composer.json': 'composer',
    'Dockerfile': 'docker', 'Gemfile': 'bundler', 'Cargo.toml': 'cargo',
    'build.gradle': 'gradle', 'build.gradle.kts': 'gradle',
}
FIXTURE_UNMAPPED = ('packages.config', 'Package.swift', 'pubspec.yaml', 'mix.exs')


def fixture_problems(root):
    """P6: no Dependabot update -- version or alert-driven security -- may "fix" the deliberately
    vulnerable consumer fixture."""
    import yaml
    p = os.path.join(root, '.github', 'dependabot.yml')
    if not os.path.isfile(p):
        return []  # P5 already refuses a missing file
    doc = yaml.safe_load(io.open(p, encoding='utf-8')) or {}
    entries = doc.get('updates') or []
    fx = os.path.join(root, 'tests', 'consumer-fixture')
    want = set()
    out = []
    for d, _, names in os.walk(fx):
        rel = '/' + os.path.relpath(d, root).replace(os.sep, '/')
        for n in names:
            eco = FIXTURE_MANIFESTS.get(n)
            if n.endswith('.csproj') or n.endswith('.fsproj'):
                eco = 'nuget'
            elif n.endswith('.tf'):
                eco = 'terraform'
            elif n in FIXTURE_UNMAPPED:
                out.append('fixture manifest %s/%s has no P6 ecosystem mapping (P6)' % (rel, n))
            if eco:
                want.add((eco, rel))
    for eco, rel in sorted(want):
        hit = [u for u in entries if u.get('package-ecosystem') == eco and u.get('directory') == rel]
        if not hit:
            out.append('dependabot.yml has no %s entry for the fixture directory %s: an alert-driven '
                       'security update would bump its deliberately vulnerable pins (P6)' % (eco, rel))
            continue
        u = hit[0]
        names = [str((i or {}).get('dependency-name')) for i in (u.get('ignore') or [])]
        if '*' not in names:
            out.append('dependabot %s %s does not ignore every dependency (`dependency-name: "*"`) (P6)'
                       % (eco, rel))
        if u.get('open-pull-requests-limit') != 0:
            out.append('dependabot %s %s may open version-update PRs (open-pull-requests-limit is not 0) (P6)'
                       % (eco, rel))
    if not want and os.path.isdir(fx):
        out.append('no manifest found under tests/consumer-fixture: P6 read nothing (P6)')
    return out


def _ecosystems_in(directory):
    """The Dependabot ecosystems whose manifest sits IN this directory (not below it)."""
    found = set()
    try:
        names = os.listdir(directory)
    except OSError:
        return found
    for n in names:
        if not os.path.isfile(os.path.join(directory, n)):
            continue
        eco = FIXTURE_MANIFESTS.get(n)
        if n.endswith('.csproj') or n.endswith('.fsproj') or n in ('packages.config', 'Directory.Packages.props'):
            eco = 'nuget'
        elif n.endswith('.tf') or n.endswith('.tf.json'):
            eco = 'terraform'
        elif n.startswith('Dockerfile') or n.endswith('.Dockerfile'):
            eco = 'docker'
        elif n in ('requirements.in', 'setup.py', 'setup.cfg') or (n.startswith('requirements') and n.endswith('.txt')):
            eco = 'pip'
        if eco:
            found.add(eco)
    return found


def entry_manifest_problems(root):
    """P7: every dependabot.yml entry (github-actions aside) names a directory that holds a manifest
    of its ecosystem. Dependabot does not skip an empty directory: it fails the update job with
    `dependency_file_not_found` ("No Dockerfiles nor Kubernetes YAML found", file-path /Dockerfile),
    every week, on every copy of the kit -- the owner's work copy's Dependabot Updates were red on
    pip, npm, nuget, gomod, maven, docker and terraform for exactly this (2026-11-02)."""
    import yaml
    p = os.path.join(root, '.github', 'dependabot.yml')
    if not os.path.isfile(p):
        return []
    doc = yaml.safe_load(io.open(p, encoding='utf-8')) or {}
    out = []
    for u in doc.get('updates') or []:
        eco = u.get('package-ecosystem')
        if eco == 'github-actions':
            continue
        dirs = list(u.get('directories') or []) + ([u['directory']] if u.get('directory') else [])
        for d in dirs:
            if any(c in str(d) for c in '*?['):
                continue  # a glob is matched by Dependabot itself; nothing to stat here
            full = os.path.join(root, *[x for x in str(d).split('/') if x])
            if eco not in _ecosystems_in(full):
                out.append('dependabot %s entry reads %s, where there is no %s manifest: Dependabot fails '
                           'that update job with dependency_file_not_found (P7)' % (eco, d, eco))
    return out


P8_SKIP = ('tests/consumer-fixture', 'overlays', '.git', 'node_modules')


def coverage_problems(root):
    """P8: every real manifest directory is read by an entry of its ecosystem; every entry that may
    open pull requests rebases automatically."""
    import fnmatch
    import yaml
    p = os.path.join(root, '.github', 'dependabot.yml')
    if not os.path.isfile(p):
        return []
    doc = yaml.safe_load(io.open(p, encoding='utf-8')) or {}
    entries = doc.get('updates') or []
    out = []
    for u in entries:
        if u.get('open-pull-requests-limit') == 0:
            continue
        if u.get('rebase-strategy') != 'auto':
            out.append('dependabot %s entry %s does not say `rebase-strategy: auto`: a PR in conflict '
                       'with main would sit red (P8)' % (u.get('package-ecosystem'),
                                                         u.get('directory') or u.get('directories')))
    for d, dirs, _names in os.walk(root):
        rel = os.path.relpath(d, root).replace(os.sep, '/')
        if rel != '.' and any(rel == x or rel.startswith(x + '/') for x in P8_SKIP):
            dirs[:] = []
            continue
        if rel.startswith('.github'):
            continue  # github-actions is P5's
        rel = '/' if rel == '.' else '/' + rel
        for eco in sorted(_ecosystems_in(d)):
            hit = False
            for u in entries:
                if u.get('package-ecosystem') != eco:
                    continue
                ds = list(u.get('directories') or []) + ([u['directory']] if u.get('directory') else [])
                if any(fnmatch.fnmatchcase(rel, str(x).rstrip('/') or '/') for x in ds):
                    hit = True
            if not hit:
                out.append('%s holds a %s manifest that no dependabot.yml entry reads: that dependency is '
                           'never kept current (P8)' % (rel, eco))
    return out


def _fixture_self_test(work):
    """-> None, or what got past P6."""
    import yaml
    root = os.path.join(work, 'p6')
    os.makedirs(os.path.join(root, '.github'))
    os.makedirs(os.path.join(root, 'tests', 'consumer-fixture', 'full', 'java'))
    io.open(os.path.join(root, 'tests', 'consumer-fixture', 'full', 'java', 'pom.xml'), 'w').write('<project/>')
    dep = os.path.join(root, '.github', 'dependabot.yml')
    base = {'package-ecosystem': 'maven', 'directory': '/', 'exclude-paths': ['tests/consumer-fixture/**']}
    good = {'package-ecosystem': 'maven', 'directory': '/tests/consumer-fixture/full/java',
            'open-pull-requests-limit': 0, 'ignore': [{'dependency-name': '*'}]}
    for label, entries in (('exclude-paths alone (the #9 shape)', [base]),
                           ('an entry with no ignore', [base, dict(good, ignore=[])]),
                           ('an entry still opening version PRs', [base, dict(good, **{'open-pull-requests-limit': 5})])):
        io.open(dep, 'w').write(yaml.safe_dump({'version': 2, 'updates': entries}))
        if not fixture_problems(root):
            return 'P6 did not refuse %s' % label
    io.open(dep, 'w').write(yaml.safe_dump({'version': 2, 'updates': [base, good]}))
    got = fixture_problems(root)
    if got:
        return 'P6 refused its control: %s' % got
    # P7: a root entry with no root manifest (the work copy's `docker` at `/`) is refused; the same
    # entry beside a real Dockerfile, and a fixture entry beside its pom.xml, pass.
    root_docker = {'package-ecosystem': 'docker', 'directory': '/'}
    io.open(dep, 'w').write(yaml.safe_dump({'version': 2, 'updates': [good, root_docker]}))
    if not any('(P7)' in x and 'docker' in x for x in entry_manifest_problems(root)):
        return 'P7 did not refuse a docker entry at / with no Dockerfile there'
    io.open(os.path.join(root, 'Dockerfile'), 'w').write('FROM scratch\n')
    got = entry_manifest_problems(root)
    if got:
        return 'P7 refused its control: %s' % got
    return None


def _github(path, timeout=15):
    """REST, secondary: only with a token api.github.com issued (KDEC-027), else (None, None)."""
    return _github_refs.api_get(path, 'secure-cicd-kit-action-pins', timeout)


def _tag_commit_api(repo, tag):
    status, body = _github('/repos/%s/git/ref/tags/%s' % (repo, tag))
    if status == 404:
        return False
    if status != 200 or not isinstance(body, dict) or body.get('ref') != 'refs/tags/' + tag:
        return None
    obj = body.get('object') or {}
    for _ in range(5):
        if obj.get('type') == 'commit':
            return obj.get('sha')
        if obj.get('type') != 'tag':
            return None
        status, body = _github('/repos/%s/git/tags/%s' % (repo, obj.get('sha')))
        if status != 200 or not isinstance(body, dict):
            return None
        obj = body.get('object') or {}
    return None


def tag_commit(repo, tag):
    """-> commit SHA the tag names (annotated tags peeled), False if no such tag, None if unknown.
    Git first (`git ls-remote`, no token, no REST limit); the REST API only when git could not see
    and the run holds a token api.github.com issued (tests/_github_refs.py)."""
    if not _github_refs.valid(repo, tag):
        return None
    got = _github_refs.tag_commit(repo, tag)
    if got is not None:
        return got
    return _tag_commit_api(repo, tag)


def online(pins):
    """-> (problems, unknown). One lookup per distinct (repo, version)."""
    problems, unknown, cache = [], [], {}
    for repo, sha, version, at in pins:
        key = (repo, version)
        if key not in cache:
            cache[key] = tag_commit(repo, version)
        got = cache[key]
        if got is None:
            unknown.append('%s: %s@%s could not be resolved' % (at, repo, version))
        elif got is False:
            problems.append('%s: %s has no tag %s (P4)' % (at, repo, version))
        elif got != sha:
            problems.append('%s: %s %s is commit %s, not %s (P4)' % (at, repo, version, got, sha))
    return problems, unknown


def self_test():
    """-> None, or what a seeded defect got past."""
    good = {'actions/checkout': '3d3c42e5aac5ba805825da76410c181273ba90b1'}
    co = 'actions/checkout@' + good['actions/checkout']
    other = 'f' * 40
    head = 'name: t\non: push\npermissions:\n  contents: read\njobs:\n'
    step = head + '  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n'
    comp = 'name: c\ndescription: d\nruns:\n  using: composite\n  steps:\n    - uses: %s\n'
    tpl = head + '  a:\n    uses: %s\n'
    cases = [
        # (label, location, text, the reason it must be refused for)
        ('a tag in a workflow step', 'w', step % 'actions/checkout@v7', '(P1)'),
        ('a tag in a job-level reusable call', 'w',
         head + '  a:\n    uses: someone/kit/.github/workflows/x.yml@v1\n', '(P1)'),
        ('a tag in a composite step', 'c', comp % 'dorny/paths-filter@v4', '(P1)'),
        ('a tag in a template', 't', tpl % 'someone/kit/.github/workflows/x.yml@v1', '(P1)'),
        ('a branch ref', 'w', step % 'someone/tool@main', '(P1)'),
        ('a SHA with no version comment', 'w', step % co, '(P2)'),
        ('a comment naming a moving major', 'w', step % (co + ' # v7'), '(P2)'),
        ('a comment the table contradicts', 'w', step % (co + ' # v6.0.0'), '(P3)'),
        ('a recorded version on the wrong SHA', 'w',
         step % ('actions/checkout@' + other + ' # v7.0.1'), '(P3)'),
        ('the zero placeholder outside templates', 'w',
         step % ('YOUR_ORG/secure-cicd-kit/.github/actions/x@' + ZERO + '   ' + PLACEHOLDER_COMMENT),
         'templates/ only'),
        ('a placeholder that does not say so', 't',
         tpl % ('YOUR_ORG/secure-cicd-kit/.github/workflows/x.yml@' + ZERO), 'must say'),
        ('a tag in an overlay workflow', 'o', step % 'zaproxy/action-baseline@v0.14.0', '(P1)'),
        ('the overlay placeholder outside overlays', 'w',
         tpl % ('KIT_OWNER/KIT_REPO/.github/workflows/x.yml@' + ZERO), 'overlays/ only'),
    ]
    control = {
        'w': head + '  a:\n    runs-on: ubuntu-latest\n    steps:\n'
                    '      - uses: %s # v7.0.1\n'
                    '      - uses: ./.github/actions/local\n'
                    '      - uses: $/.github/actions/self\n'
                    '      - uses: docker://alpine@sha256:%s\n'
                    '      # - uses: commented/out@v1\n'
                    '      - uses: someone/tool@%s  # v1.2.3\n' % (co, 'b' * 64, other),
        'c': comp % (co + ' # v7.0.1'),
        't': tpl % ('YOUR_ORG/secure-cicd-kit/.github/workflows/x.yml@' + ZERO + '   ' + PLACEHOLDER_COMMENT),
        'o': head + '  a:\n    uses: KIT_OWNER/KIT_REPO/.github/workflows/x.yml@' + ZERO + '\n'
                    '  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s # v7.0.1\n' % co,
    }
    where = {'w': '.github/workflows/w.yml', 'c': '.github/actions/x/action.yml', 't': 'templates/t.yml',
             'o': 'overlays/o/workflows/o.yml'}
    work = tempfile.mkdtemp(prefix='action-pins-')
    try:
        def tree(name, files):
            root = os.path.join(work, name)
            for kind, text in files.items():
                p = os.path.join(root, *where[kind].split('/'))
                os.makedirs(os.path.dirname(p), exist_ok=True)
                io.open(p, 'w', encoding='utf-8', newline='\n').write(text)
            return root
        err = _fixture_self_test(work)
        if err:
            return err
        problems, pins, files = scan(tree('control', control))
        if problems or files != 4 or len(pins) != 4:
            return 'the control tree was refused or under-read: %s (files=%d pins=%d)' % (
                problems, files, len(pins))
        for i, (label, kind, text, why) in enumerate(cases):
            problems, _, _ = scan(tree('c%d' % i, {kind: text}))
            if not any(why in p for p in problems):
                return 'did not refuse %s for the reason %s: %s' % (label, why, problems)
        return None
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv):
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    err = self_test()
    if err:
        print('SELF-TEST FAILED: %s' % err)
        return 1
    print('self-test ok: 13 seeded defects across workflow, job-level, composite, template and '
          'overlay locations refused, 3 fixture-ignore defects (P6), a manifest-less entry (P7), an unread manifest and a non-rebasing entry (P8); '
          'the controls pass')
    problems, pins, files = scan(ROOT)
    if not files:
        print('UNKNOWN: no file in scope was found; nothing read is not nothing wrong.')
        return 2
    problems += dependabot_problems(ROOT)
    problems += fixture_problems(ROOT)
    problems += entry_manifest_problems(ROOT)
    problems += coverage_problems(ROOT)
    unknown = []
    if '--online' in argv and not problems:
        p, unknown = online(pins)
        problems += p
    for p in problems:
        print(('FAIL ' + p).encode('ascii', 'replace').decode('ascii'))
    distinct = sorted({(r, s, v) for r, s, v, _ in pins})
    print('%d file(s) read; %d remote reference(s) pinned and named (%d distinct pins); %d refused.'
          % (files, len(pins), len(distinct), len(problems)))
    if problems:
        unpinned = sum(1 for p in problems if '(P1)' in p)
        fixture = sum(1 for p in problems if '(P6)' in p or '(P7)' in p or '(P8)' in p)
        print('FAIL: %d reference(s) are not pinned by a commit SHA, %d pinned but unnamed or '
              'misnamed; %d Dependabot entry gap(s) (P6/P7/P8).'
              % (unpinned, len(problems) - unpinned - fixture, fixture))
        return 1
    if unknown:
        for u in unknown:
            print('UNKNOWN ' + u)
        # The cause, named (D-11): a 401 is not a rate limit, and no token is neither.
        print('Cause: %s.' % _github_refs.explain())
        print('Reported as UNKNOWN. Failure to observe is not an observation.')
        return 2
    unrecorded = [(r, s, v) for r, s, v in distinct if s not in RECORDED.get(r, {})]
    for r, s, v in unrecorded:
        print('  not in the recorded table (checked by --online only): %s@%s # %s' % (r, s, v))
    print('PASS: every remote `uses:` is a full commit SHA with its exact release named%s.'
          % (', each verified against github.com' if '--online' in argv else
             '; the table spot-checks %d' % (len(distinct) - len(unrecorded))))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
