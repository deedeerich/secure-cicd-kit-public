#!/usr/bin/env python3
"""The artifact a control inspected must be the artifact that gets published.

WHY THIS EXISTS
    `reusable-build-docker.yml` shipped for weeks in this shape:

        6.  Build (load locally for scan)   build #1, no id, digest never captured
        7.  Trivy image scan                 scanned build #1, by mutable tag
        8.  SBOM (Syft)                      SBOM of build #1
        9.  Push (digest-pinned)             build #2 -> steps.push.outputs.digest
        10. Upload SBOM                      shipped build #1's SBOM

    Two `docker/build-push-action` invocations means two images. The gate cleared one and the
    registry received the other, and `image_digest` -- the value every downstream consumer treats
    as the identity of the deployed artifact -- named the one nothing had scanned.

    They are the same image only if the Dockerfile is bit-reproducible. An unpinned apt index, a
    floating base tag, a dependency install without a lockfile, an embedded timestamp: any one of
    them is enough. Nothing in a green run would say so. The SBOM stamped as deployment provenance
    would describe an artifact that was never pushed.

    That is the whole invariant chain failing at its first link. BUILT != SCANNED != PUSHED !=
    DEPLOYED unless each arrow is proven, and an arrow nobody checks is an assumption wearing a
    digest.

WHAT THIS CHECKS, AND WHAT IT DOES NOT
    SHAPE, not behaviour. It reads the workflow graph and refuses the structures that make the
    defect possible. It cannot prove the assertion step's comparison is correct -- only a run can,
    and that is the acceptance work, not this. A structural check that claimed otherwise would be
    the same overstatement it exists to catch.

    R1  One build per job.            Two invocations, two artifacts.
    R2  No scan before a pushing      The original shape exactly: gate the first, ship the second.
        build in the same job.
    R3  A published image_digest      A digest returned without a stated identity class invites
        needs a published                every consumer to assume the strongest reading.
        artifact_identity.
    R4  A job that pushes must        Everything before it is one machine agreeing with itself.
        round-trip the registry.

EXIT
    0  every image-building job keeps its artifact identity intact
    1  a structure that permits a scanned-vs-pushed divergence is present
    2  the self-test could not run -- reported as UNKNOWN, never as PASS
"""
import glob
import io
import os
import re
import sys


def write_if_changed(path, content):
    """Write a tracked fixture only when its CONTENT differs (N51).

    These fixtures are committed so a reviewer can read them, and regenerated from the constants in
    this file so they cannot drift. Rewriting them unconditionally touched tracked files on every
    run -- on a CRLF checkout, every file showed modified -- and a test must leave the tree as it
    found it (tests/prove_tests_leave_tree_clean.py). Compared with line endings normalised, so a
    checkout's EOL convention is not mistaken for drift.
    """
    try:
        current = io.open(path, encoding='utf-8', newline='').read().replace('\r\n', '\n')
    except OSError:
        current = None
    if current != content.replace('\r\n', '\n'):
        io.open(path, 'w', encoding='utf-8', newline='\n').write(content)

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML not available; cannot read the workflow graph.')
    print('Failure to observe is not an observation.')
    sys.exit(2)

WORKFLOWS = '.github/workflows/*.yml'
# COMPOSITES ARE BUILD PATHS TOO (ledger L85, review G3-5). This checker read workflows only, so
# `.github/actions/docker-build-push` kept the exact two-build shape the workflow was rewritten to
# remove -- a consumer who builds inside its own workflow got the defect the kit had fixed.
COMPOSITES = '.github/actions/*/action.yml'
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')

BUILD_ACTION = re.compile(r'docker/build-push-action')
# Scanners that take an IMAGE as input. A source scanner in the same job is irrelevant here --
# it is not reading the artifact, so it cannot be reading the wrong one.
IMAGE_SCAN_ACTION = re.compile(r'aquasecurity/trivy-action|anchore/sbom-action|anchore/scan-action')
IMAGE_SCAN_RUN = re.compile(r'\bsyft\b|\btrivy\s+image\b|\bgrype\b')
PUSH_RUN = re.compile(r'\bdocker\s+push\b|\bbuildx\b[^\n]*--push\b')
# Reading the registry back. Any of these asks something other than the local daemon.
REGISTRY_READ = re.compile(
    r'imagetools\s+inspect|docker\s+manifest\s+inspect|az\s+acr\s+(?:manifest|repository)|crane\s+(?:manifest|digest)')


def truthy(v):
    """GitHub treats the string 'true' and the boolean as the same thing. So must this."""
    return v is True or (isinstance(v, str) and v.strip().lower() == 'true')


def step_text(step):
    """Everything a step might carry a command in, as one string."""
    parts = [str(step.get('run', '')), str(step.get('uses', ''))]
    with_ = step.get('with') or {}
    if isinstance(with_, dict):
        parts.extend(str(x) for x in with_.values())
    return '\n'.join(parts)


def classify(steps):
    """-> list of (index, name, set-of-roles). A step may hold more than one role."""
    out = []
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        uses = str(step.get('uses', ''))
        run = str(step.get('run', ''))
        with_ = step.get('with') or {}
        roles = set()
        if BUILD_ACTION.search(uses):
            roles.add('build')
            # `push: true` on the build action means this step also publishes.
            if isinstance(with_, dict) and truthy(with_.get('push')):
                roles.add('push')
        if IMAGE_SCAN_ACTION.search(uses) or IMAGE_SCAN_RUN.search(run):
            roles.add('scan')
        if PUSH_RUN.search(run):
            roles.add('push')
        if REGISTRY_READ.search(run):
            roles.add('registry_read')
        out.append((i, step.get('name') or uses or '(unnamed)', roles))
    return out


def check_job(wf_path, job_name, job, declared_outputs):
    """-> list of failure strings."""
    steps = job.get('steps') or []
    if not isinstance(steps, list):
        return []
    roles = classify(steps)
    builds = [r for r in roles if 'build' in r[2]]
    scans = [r for r in roles if 'scan' in r[2]]
    pushes = [r for r in roles if 'push' in r[2]]
    reads = [r for r in roles if 'registry_read' in r[2]]

    if not builds:
        return []

    where = '%s :: job %s' % (wf_path, job_name)
    fails = []

    # R1 -- one build per job.
    if len(builds) > 1:
        fails.append(
            'R1 %s: %d build invocations in one job (%s).\n'
            '     Two builds are two artifacts. Whatever the first one was scanned against, the\n'
            '     second one is what reaches the registry, and nothing compares them.'
            % (where, len(builds), ', '.join(b[1] for b in builds)))

    # R2 -- the original shape: scan, then build-and-push.
    for s_i, s_name, _ in scans:
        later_pushing_builds = [b for b in builds if b[0] > s_i and 'push' in b[2]]
        if later_pushing_builds:
            fails.append(
                'R2 %s: image scan %r precedes a BUILDING push step %r.\n'
                '     This is the defect verbatim: the gate reads one image, the registry receives\n'
                '     another. Push the bytes that were scanned -- `docker push` of the loaded image\n'
                '     cannot produce a different artifact; a second build can.'
                % (where, s_name, later_pushing_builds[0][1]))

    # R4 -- a job that pushes must ask the registry what it is holding.
    if pushes and scans and not reads:
        fails.append(
            'R4 %s: the job builds, scans and pushes, and never reads the registry back.\n'
            '     Every check before the push is one machine agreeing with itself. The link between\n'
            '     the scanned image and the published digest is asserted, not established.'
            % where)

    # R3 -- a digest published without an identity class.
    if pushes and 'image_digest' in declared_outputs and 'artifact_identity' not in declared_outputs:
        fails.append(
            'R3 %s: workflow_call publishes image_digest with no artifact_identity output.\n'
            '     A bare digest reads as proven to every consumer. PROVEN, LOCAL_BUILD_ONLY and\n'
            '     IDENTITY_UNVERIFIED are three different answers and must not collapse into one.'
            % where)

    return fails


def scan_composite(path, doc):
    """A composite action is one job: its steps run in sequence on one runner."""
    steps = ((doc.get('runs') or {}).get('steps')) or []
    declared = set((doc.get('outputs') or {}).keys())
    # A composite's outputs are hyphenated by convention; the rule is about the meaning.
    declared |= {k.replace('-', '_') for k in declared}
    return check_job(path, '(composite)', {'steps': steps}, declared)


def scan_file(path):
    try:
        doc = yaml.safe_load(io.open(path, encoding='utf-8', errors='replace'))
    except Exception as e:
        return ['UNREADABLE %s: %s' % (path, e)]
    if not isinstance(doc, dict):
        return []
    if isinstance(doc.get('runs'), dict):
        return scan_composite(path, doc)
    # `on:` parses as the boolean True in YAML 1.1. Look for both spellings.
    trigger = doc.get('on', doc.get(True)) or {}
    declared = set()
    if isinstance(trigger, dict):
        call = trigger.get('workflow_call') or {}
        if isinstance(call, dict) and isinstance(call.get('outputs'), dict):
            declared = set(call['outputs'])
    fails = []
    for job_name, job in (doc.get('jobs') or {}).items():
        if isinstance(job, dict):
            fails.extend(check_job(path, job_name, job, declared))
    return fails


DOUBLE_BUILD_FIXTURE = """\
# Fixture: the shape reusable-build-docker.yml actually shipped in, before 2026-09-18.
# It must FAIL. A guard nobody has watched fail is not a guard -- this repository has already
# shipped five checks whose patterns matched nothing while reporting CLEAN.
name: fixture double build
on:
  workflow_call:
    outputs:
      image_digest:
        value: ${{ jobs.build.outputs.image_digest }}
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image_digest: ${{ steps.push.outputs.digest }}
    steps:
      - name: Build (load locally for scan)
        uses: docker/build-push-action@v7
        with:
          load: true
          tags: reg.example/app:t
      - name: Trivy image scan
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          image-ref: reg.example/app:t
      - name: SBOM
        run: syft reg.example/app:t -o spdx-json=sbom.json
      - name: Push
        id: push
        uses: docker/build-push-action@v7
        with:
          push: true
          tags: reg.example/app:t
"""

SINGLE_BUILD_FIXTURE = """\
# Fixture: the corrected shape. It must PASS. Without this half the self-test cannot tell
# "the rules work" from "the rules reject everything".
name: fixture single build
on:
  workflow_call:
    outputs:
      image_digest:
        value: ${{ jobs.build.outputs.image_digest }}
      artifact_identity:
        value: ${{ jobs.build.outputs.artifact_identity }}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build (once)
        id: build
        uses: docker/build-push-action@v7
        with:
          load: true
          tags: reg.example/app:t
      - name: Trivy image scan
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          image-ref: reg.example/app:t
      - name: SBOM
        run: syft docker:reg.example/app:t -o spdx-json=sbom.json
      - name: Push the scanned bytes
        id: push
        run: docker push reg.example/app:t
      - name: Assert artifact identity
        run: docker buildx imagetools inspect --raw reg.example/app@$DIGEST
"""

DOUBLE_BUILD_COMPOSITE_FIXTURE = """\
# Fixture: the shape .github/actions/docker-build-push shipped in. A composite is a build path
# too, and this must FAIL exactly as the workflow shape does.
name: fixture composite double build
description: fixture
outputs:
  image-digest:
    value: ${{ steps.push.outputs.digest }}
runs:
  using: composite
  steps:
    - name: Build (load locally for scan)
      uses: docker/build-push-action@v7
      with:
        load: true
        tags: reg.example/app:t
    - name: Trivy image scan
      uses: aquasecurity/trivy-action@v0.36.0
      with:
        image-ref: reg.example/app:t
    - name: Push
      id: push
      uses: docker/build-push-action@v7
      with:
        push: true
        tags: reg.example/app:t
"""

EXPECTED_BAD = ('R1', 'R2')


def self_test():
    """Both directions. A checker only proven on its passing case proves nothing."""
    if not os.path.isdir(FIXTURES):
        print('UNKNOWN: %s missing; cannot run the self-test.' % FIXTURES)
        return 2
    bad = os.path.join(FIXTURES, 'double_build_workflow.sample')
    good = os.path.join(FIXTURES, 'single_build_workflow.sample')
    write_if_changed(bad, DOUBLE_BUILD_FIXTURE)
    write_if_changed(good, SINGLE_BUILD_FIXTURE)

    bad_c = os.path.join(FIXTURES, 'double_build_composite.sample')
    write_if_changed(bad_c, DOUBLE_BUILD_COMPOSITE_FIXTURE)

    bad_fails = scan_file(bad)
    good_fails = scan_file(good)
    codes = set(f.split()[0] for f in bad_fails)
    c_codes = set(f.split()[0] for f in scan_file(bad_c))
    for want in EXPECTED_BAD + ('R3',):
        if want not in c_codes:
            print('SELF-TEST FAILED: the known-bad COMPOSITE fixture did not trip %s.' % want)
            return 1

    ok = True
    for want in EXPECTED_BAD:
        if want not in codes:
            print('SELF-TEST FAILED: the known-bad fixture did not trip %s.' % want)
            ok = False
    if good_fails:
        print('SELF-TEST FAILED: the corrected fixture was rejected:')
        for f in good_fails:
            print('  ' + f.split('\n')[0])
        ok = False
    if not ok:
        return 1
    print('self-test ok: known-bad fixture trips %s; corrected fixture passes'
          % ', '.join(sorted(codes)))
    return 0


def main():
    st = self_test()
    if st:
        return st

    files = sorted(f for f in glob.glob(WORKFLOWS) if os.path.isfile(f))
    composites = sorted(f for f in glob.glob(COMPOSITES) if os.path.isfile(f))
    if not files:
        print('UNKNOWN: no workflows found at %s. Nothing inspected is not nothing wrong.' % WORKFLOWS)
        return 2

    print('\n=== image-building jobs ===')
    fails, building = [], 0
    for f in files + composites:
        doc = None
        try:
            doc = yaml.safe_load(io.open(f, encoding='utf-8', errors='replace'))
        except Exception:
            pass
        if isinstance(doc, dict):
            jobs = ((doc.get('jobs') or {}).items() if f in files
                    else [('(composite)', doc.get('runs') or {})])
            for job_name, job in jobs:
                if isinstance(job, dict) and any(
                        'build' in r[2] for r in classify(job.get('steps') or [])):
                    building += 1
                    print('  %s :: %s' % (f, job_name))
        fails.extend(scan_file(f))

    if not building:
        print('  none')

    print('\n' + '=' * 72)
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        print('\nThe artifact a control inspected must be the artifact that gets published.')
        return 1
    print('PASS: %d image-building job(s); each keeps one build, scans what it pushes,'
          % building)
    print('      and reads the registry back before publishing a digest.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
