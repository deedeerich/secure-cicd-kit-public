#!/usr/bin/env python3
"""Which subject is this finding ABOUT? The question `identify()` cannot answer for itself.

WHY THIS FILE EXISTS, AND WHY IT IS SEPARATE

    `finding_identity.py` is correct and is called by nothing. It computes a durable identity that
    survives a scanner upgrade, and it refuses to compute one without a declared `finding_subject` --
    because the subject decides which locus applies, and a default would silently apply one
    subject's identity rule to another subject's finding.

    Meanwhile `scan_report.py` computes `fingerprint(scanner, rule_id, uri, message)` and keys
    APPROVED EXCEPTIONS on it. All four of those inputs are on the forbidden list in the file that
    was supposed to replace it:

        scanner   a Trivy upgrade orphans every disposition ever approved against Trivy
        rule_id   a rule rename or split does the same, silently, at a minor version
        message   the scanner's PROSE. A vendor rewording invalidates the baseline.

    So the correct implementation sat unused while the incorrect one held the approvals. The gap
    between them was exactly this: nothing could say what a SARIF result is about.

    It is a separate file rather than a function inside either, because it is the one part that is
    genuinely a JUDGEMENT about scanner semantics. `finding_identity` should stay a pure function of
    a declared subject; `scan_report` should stay about reporting. A mapping that will need editing
    every time a scanner is added belongs where it can be read and argued with.

THE RULE THIS KEEPS

    An unmappable result is `UNKNOWN`, never a guess.

    `identify()` already refuses an undeclared subject and routes it to EVIDENCE_UNTRUSTED. That is
    the correct outcome and this file does not work around it: a scanner nobody has classified
    produces a finding whose identity is unestablished, which is visible and fixable. Guessing
    SOURCE because most findings are source findings would attach a source locus to a container
    layer and silently mismatch every disposition for it.

USAGE
    from finding_subject import subject_for
    subject_for(scanner='trivy', rule_id='CVE-2024-1', uri='alpine:3.19', tool='Trivy')
    python3 finding_subject.py --self-test

EXIT
    0  self-test passed      2  self-test failed
"""
import argparse
import os
import re
import sys

UNKNOWN = 'UNKNOWN'

# The registered subjects a JOB may declare with `mode=`. Retyped here rather than imported
# because this module must work when `finding_identity.py` is not importable -- but the
# self-test asserts the two lists agree, so a subject added to one and not the other is a
# failure rather than a near-miss that reads as blank.
DECLARABLE = (
    'IMAGE', 'SOURCE', 'SOURCE_DEPENDENCY', 'IAC_PLAN', 'RESOURCE',
    'IDENTITY_ASSIGNMENT', 'RUNTIME_OBSERVATION', 'POLICY', 'RELEASE',
)

# ── the mapping, by the scanner that produced the result ─────────────────────────────
#
# Keyed on the SARIF driver name, lower-cased, because that is what a report actually carries.
# The value is the subject the scanner's findings are ABOUT -- which is not the same as what it
# reads. Checkov reads a template file; its finding is about the resource the template declares.
# Trivy reads a filesystem; in image mode its finding is about the image.
#
# `None` means the scanner is multi-modal and the subject must be decided per result, below.
BY_SCANNER = {
    # source code, analysed statically
    'semgrep': 'SOURCE',
    'bandit': 'SOURCE',
    'gosec': 'SOURCE',
    'flawfinder': 'SOURCE',
    'codeql': 'SOURCE',
    'sonarqube': 'SOURCE',
    'sonar': 'SOURCE',
    'eslint': 'SOURCE',
    'ruff': 'SOURCE',
    'pylint': 'SOURCE',

    # secrets live in source, but the LOCUS is the secret, not the line
    'gitleaks': 'SOURCE',
    'detect-secrets': 'SOURCE',

    # dependencies: the finding is about the PACKAGE COORDINATE, not about the manifest that
    # happens to list it. SOURCE_DEPENDENCY rather than SOURCE -- see finding_identity.py's D-3
    # decision block. Under SOURCE these four produced a locus built from `requirements.txt` or
    # `package-lock.json`, which is the same string for every dependency finding in the
    # repository, and were then refused outright for having no matched construct.
    #
    # `osv-scanner` stays multi-modal: it reads lockfiles and container images, and the locator
    # is what settles which. `dependency-check` does not -- reading dependency archives is its
    # only mode, so the subject is a property of the scanner rather than of the locator.
    'osv-scanner': None,
    'dependency-check': 'SOURCE_DEPENDENCY',
    'dotnet-vuln': 'SOURCE_DEPENDENCY',
    'npm-audit': 'SOURCE_DEPENDENCY',
    'pip-audit': 'SOURCE_DEPENDENCY',

    # infrastructure as code: the finding is about the RESOURCE the template declares
    'checkov': 'IAC_PLAN',
    'terrascan': 'IAC_PLAN',
    'tfsec': 'IAC_PLAN',

    # container images
    'grype': 'IMAGE',
    'syft': 'IMAGE',

    # multi-modal
    'trivy': None,

    # the pipeline looking at itself
    'actionlint': 'SOURCE',
    'zizmor': 'SOURCE',
    # Scripts and Dockerfiles, linted since lane L-SCAN-A (KDEC-025): shell and PowerShell are
    # source; a Dockerfile is a build template, the subject Checkov and Trivy config give it too.
    'shellcheck': 'SOURCE',
    'psscriptanalyzer': 'SOURCE',
    'hadolint': 'IAC_PLAN',

    # dynamic analysis reaches a RUNNING thing
    'zap': 'RUNTIME_OBSERVATION',
    'owasp zap': 'RUNTIME_OBSERVATION',
    'nuclei': 'RUNTIME_OBSERVATION',

    # SARIF driver names that differ from the tool's short name.
    'semgrep oss': 'SOURCE',
    'cppcheck': 'SOURCE',

    # ── THE REPORT'S ROSTER NAMES (L42, G3-3) ─────────────────────────────────────────
    #
    # `scan_report.parse_sarif` passes the STATE-FILE name as `scanner`, and the scanner wins over
    # the SARIF driver. Those names are the report job's roster (`expect:` in reusable-security.yml),
    # not tool names, and twelve of them were missing here -- so every finding from Java, C#, C/C++,
    # Trivy-IaC, OSV, the container image and all six CodeQL languages was SUBJECT_NOT_ESTABLISHED
    # and could never hold a durable identity. tests/prove_subject_covers_roster.py reads the roster
    # from the workflow and fails if any name here goes missing again.
    #
    # Each entry is the subject of what THAT JOB scans, which is a property of the job's invocation
    # and so stronger than inference from a locator:
    'code-quality': 'SOURCE',         # ruff / mypy over source
    'java-sast': 'SOURCE',            # semgrep, java rules
    'semgrep-csharp': 'SOURCE',       # semgrep, c# rules
    # sast-mobile (lane L-SCAN-B, KDEC-026): source, manifests, network security configs, plists
    # and Gradle scripts in the repository -- the locus is the file and line, as for Semgrep.
    'mobsfscan': 'SOURCE',            # mobsfscan, Android/iOS source and configuration
    'mobile-config': 'SOURCE',        # semgrep, the kit's Android configuration rules
    'trivy-iac': 'IAC_PLAN',          # trivy config mode over templates
    'trivy-image': 'IMAGE',           # trivy image mode
    'trivy-image-secret': 'IMAGE',    # trivy image mode, secrets scanner: the locus is a layer
    # osv-scanner `scan source` over lockfiles: the finding is a (malicious) PACKAGE COORDINATE.
    'malicious-deps': 'SOURCE_DEPENDENCY',
    # syft `dir:` over the source tree, licences judged per component: a package coordinate.
    # NOT IMAGE, which the bare `syft` entry above assumes -- the kit runs syft on a directory.
    'sbom': 'SOURCE_DEPENDENCY',
    'codeql-python': 'SOURCE',
    'codeql-javascript-typescript': 'SOURCE',
    'codeql-go': 'SOURCE',
    'codeql-csharp': 'SOURCE',
    'codeql-java-kotlin': 'SOURCE',
    'codeql-c-cpp': 'SOURCE',
}


def mapped_names():
    """Every name the map answers for. Read by tests/prove_subject_covers_roster.py."""
    return frozenset(BY_SCANNER)


def _normalise_name(value):
    name = (value or '').strip().lower()
    return re.sub(r'\s*\(.*\)$', '', name)

# Trivy and the dependency scanners change subject by what they were pointed at. The SARIF
# does not say so in a single field, so it is inferred from the artifact locator -- and when the
# locator does not settle it, the answer is UNKNOWN rather than a default.
_IMAGE_URI = re.compile(
    r'(^|/)([a-z0-9][a-z0-9._-]*(\.[a-z]{2,}|:\d+)/)?[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+$'
    r'|@sha256:[0-9a-f]{64}')
_IAC_EXT = ('.tf', '.tfvars', '.bicep', '.json.arm', '.yaml', '.yml', '.template')
_IAC_HINT = re.compile(r'(?i)(^|/)(terraform|bicep|arm|infra|iac|deploy)(/|$)')
_MANIFEST = (
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt', 'poetry.lock',
    'pipfile.lock', 'go.sum', 'go.mod', 'gemfile.lock', 'composer.lock', 'cargo.lock',
    'packages.lock.json', 'pom.xml', 'build.gradle', 'gradle.lockfile',
)


def _looks_like_image(uri):
    if not uri:
        return False
    u = uri.strip()
    if u.startswith(('http://', 'https://')):
        return False
    if '@sha256:' in u:
        return True
    # A tag reference has a colon in the last path segment and no filesystem extension.
    last = u.rsplit('/', 1)[-1]
    if ':' not in last:
        return False
    if os.path.splitext(last.split(':', 1)[0])[1]:
        return False
    return bool(_IMAGE_URI.search(u))


def _looks_like_iac(uri):
    if not uri:
        return False
    low = uri.lower()
    if low.endswith(('.tf', '.tfvars', '.bicep')):
        return True
    if _IAC_HINT.search(low) and low.endswith(('.yaml', '.yml', '.json')):
        return True
    return False


def _looks_like_manifest(uri):
    return bool(uri) and os.path.basename(uri).lower() in _MANIFEST


def subject_for(scanner='', rule_id='', uri='', tool='', mode=''):
    """-> (subject, basis). UNKNOWN when nothing establishes it.

    `mode` is an optional explicit declaration from the job that ran the scanner -- a workflow
    knows whether it invoked Trivy in image or filesystem mode, and a declaration always beats an
    inference. When it is given it wins, and the basis says so.
    """
    name = _normalise_name(scanner or tool)

    if mode:
        m = mode.strip().upper()
        if m in DECLARABLE:
            return m, 'declared by the invoking job as mode=%s' % m
        return UNKNOWN, 'invoking job declared an unregistered mode %r' % mode

    via = ''
    if name not in BY_SCANNER:
        # THE DRIVER, WHEN THE JOB NAME IS UNMAPPED. The SARIF driver name is a fact the scanner
        # wrote about itself, not a guess -- but it is weaker than the job's own name, which says how
        # the tool was invoked, so it is consulted only when the job name answers nothing, and the
        # basis says it was the driver. A driver nobody mapped still ends in UNKNOWN below.
        driver = _normalise_name(tool)
        if driver and driver != name and driver in BY_SCANNER:
            via = ' (job name %r is unmapped; answered by the SARIF driver name)' % name
            name = driver
        else:
            return UNKNOWN, ('scanner %r is not in the subject map. Add it there rather than '
                             'guessing -- an unmapped scanner must not inherit another scanner\'s '
                             'locus' % name)

    fixed = BY_SCANNER[name]
    if fixed:
        return fixed, 'scanner %r produces %s findings by construction%s' % (name, fixed, via)

    # Multi-modal: decide from the artifact locator.
    if _looks_like_image(uri):
        return 'IMAGE', 'locator %r is an image reference (tag or digest)%s' % (uri, via)
    if _looks_like_iac(uri):
        return 'IAC_PLAN', 'locator %r is an infrastructure template%s' % (uri, via)
    if _looks_like_manifest(uri):
        # A MANIFEST IS NOT THE SUBJECT, THE PACKAGE IS. The locator names the file that listed
        # the package; the finding is about the coordinate. Returning SOURCE here is what sent
        # every dependency finding to the one subject that cannot represent one (D-3).
        return ('SOURCE_DEPENDENCY',
                'locator %r is a dependency manifest, so the finding is about a package '
                'coordinate rather than about a construct in the file%s' % (uri, via))
    if uri and ('/' in uri or os.path.splitext(uri)[1]):
        return 'SOURCE', 'locator %r is a path in the source tree%s' % (uri, via)
    return UNKNOWN, ('scanner %r is multi-modal and locator %r does not establish which mode. '
                     'Have the invoking job declare mode=' % (name, uri))


def self_test():
    fails = []

    cases = [
        (dict(scanner='semgrep', uri='app/main.py'), 'SOURCE'),
        (dict(scanner='checkov', uri='infra/main.tf'), 'IAC_PLAN'),
        (dict(scanner='zap', uri='https://example.test/'), 'RUNTIME_OBSERVATION'),
        (dict(scanner='trivy', uri='registry.example.io/app/api:1.4.2'), 'IMAGE'),
        (dict(scanner='trivy', uri='app@sha256:' + 'a' * 64), 'IMAGE'),
        (dict(scanner='trivy', uri='infra/network.tf'), 'IAC_PLAN'),
        (dict(scanner='trivy', uri='package-lock.json'), 'SOURCE_DEPENDENCY'),
        (dict(scanner='pip-audit', uri='requirements.txt'), 'SOURCE_DEPENDENCY'),
        (dict(scanner='trivy', uri='src/server/app.go'), 'SOURCE'),
        (dict(scanner='trivy', uri=''), UNKNOWN),
        (dict(scanner='a-scanner-nobody-mapped', uri='x.py'), UNKNOWN),
    ]
    for kw, want in cases:
        got, basis = subject_for(**kw)
        if got != want:
            fails.append('%r -> %s, expected %s (%s)' % (kw, got, want, basis))
        if not basis:
            fails.append('%r produced no basis' % (kw,))

    # A declaration beats an inference, and an unregistered declaration is refused.
    got, basis = subject_for(scanner='trivy', uri='src/app.go', mode='IMAGE')
    if got != 'IMAGE' or 'declared' not in basis:
        fails.append('an explicit mode did not win over the locator inference')
    got, _ = subject_for(scanner='trivy', uri='x', mode='NONSENSE')
    if got != UNKNOWN:
        fails.append('an unregistered declared mode was accepted')

    # The whole point: UNKNOWN must flow through identify() as unfingerprintable, not as a guess.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from finding_identity import identify, SUBJECTS
        for s in set(v for v in BY_SCANNER.values() if v):
            if s not in SUBJECTS:
                fails.append('mapped subject %r is not a registered finding_subject' % s)
        # DECLARABLE is retyped from SUBJECTS, so it is checked rather than trusted. A subject
        # added to the identity model and not here would be refused as "unregistered mode" at the
        # one point a job is trying to be explicit about it.
        if set(DECLARABLE) != set(SUBJECTS):
            fails.append('DECLARABLE and finding_identity.SUBJECTS disagree: %r'
                         % (set(DECLARABLE).symmetric_difference(set(SUBJECTS)),))
        r = identify({'scanner': 'x', 'rule_id': 'y', 'uri': 'z', 'message': 'm'})
        if r.get('state') != 'UNFINGERPRINTABLE':
            fails.append('identify() accepted a record with no subject')
    except ImportError as e:
        fails.append('could not import finding_identity: %s' % e)

    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('self-test ok: a single-mode scanner maps by construction; a multi-modal one is decided '
          'from the locator and distinguishes an image tag, a digest reference, a template, a '
          'dependency manifest and a source path; an unmapped scanner and an unsettled locator are '
          'UNKNOWN rather than a guess; an explicit mode declared by the invoking job beats the '
          'inference and an unregistered mode is refused; every mapped subject is a registered '
          'finding_subject; and a record with no subject stays UNFINGERPRINTABLE in identify()')
    return 0


def main():
    ap = argparse.ArgumentParser(description='Which subject is a finding about?')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--scanner', default='')
    ap.add_argument('--uri', default='')
    ap.add_argument('--mode', default='')
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    s, b = subject_for(scanner=a.scanner, uri=a.uri, mode=a.mode)
    print('%s\n  %s' % (s, b))
    return 0


if __name__ == '__main__':
    sys.exit(main())
