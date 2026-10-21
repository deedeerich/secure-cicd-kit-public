#!/usr/bin/env python3
"""A tool the kit installs must be a version somebody chose, and the bytes must be checked.

WHY THIS EXISTS (ledger L84; review "PIN": osv-scanner from releases/latest, syft via curl from
`main`, trivy's install script from `main` with `latest`)

    `curl .../main/install.sh | sh -s -- latest` installs whatever upstream published this morning,
    through a script that is itself whatever is on a branch this morning. A scanner proven on Monday
    and installed on Tuesday is a different scanner; a compromised release is installed without a
    question. A pin names the version; a checksum makes the pin mean something.

WHAT THIS CHECKS (static), per `run:` step, in the files listed in SCOPE:
    P1  no install script fetched from a branch (`raw.githubusercontent.com/.../main/` or `master`)
    P2  no `releases/latest`, no `install.sh ... latest`, no `go install ...@latest`
    P3  `pip install <pkg>` names an exact version (`pkg==x.y.z`)
    P4  a step that downloads a release artifact verifies it with `sha256sum -c`

SCOPE IS DECLARED, NOT IMPLIED. It starts with the NVD workflow and the scanner probes, plus the two
build paths (ledger L84 order). reusable-security.yml joins it ONE JOB AT A TIME, as each job's
installs are pinned: a whole-file entry would be a claim about jobs nobody has pinned yet. The
jobs still outside are named in NOT_YET_IN_SCOPE (ledger L15, coordinator) -- say so rather than
pass by omission.

EXIT 0 every in-scope step is pinned and verified; 1 a violation; 2 could not be checked.
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# A path (every job), or (path, {job, ...}) for the jobs of that file that are in scope.
SCOPE = ['.github/workflows/reusable-nvd-cve.yml', '.github/workflows/validate-scanners.yml',
         '.github/workflows/reusable-build-docker.yml', '.github/actions/docker-build-push/action.yml',
         # syft from a release asset with sha256 (was install.sh from `main`); semgrep pinned to
         # the version tests/prove_semgrep_rulesets.py measured.
         ('.github/workflows/reusable-security.yml', {'sbom', 'sast-dotnet', 'sast-java'})]
NOT_YET_IN_SCOPE = ['.github/workflows/reusable-security.yml jobs other than sbom, sast-dotnet and '
                    'sast-java (ledger L15, coordinator): secret-scan installs detect-secrets and '
                    'code-quality installs ruff/mypy without a version']

RULES = [
    ('P1', re.compile(r'raw\.githubusercontent\.com/[^\s/]+/[^\s/]+/(?:main|master)/'),
     'install script fetched from a BRANCH: whatever is on it today is what runs'),
    ('P2', re.compile(r'releases/latest|install\.sh[^\n]*\blatest\b|go install \S+@latest'),
     'installs "latest": a version nobody chose'),
    ('P3', re.compile(r'pip3? install (?:--?[\w-]+ )*(?![\w.-]*==)([A-Za-z][\w.-]*)(?=\s|$)'),
     'pip package without an exact version'),
]
DOWNLOAD = re.compile(r'releases/download/')


def steps(doc):
    if isinstance(doc.get('runs'), dict):
        yield '(composite)', doc['runs'].get('steps') or []
    for jn, j in (doc.get('jobs') or {}).items():
        if isinstance(j, dict):
            yield jn, j.get('steps') or []


def check_text(where, run, out):
    for code, rx, why in RULES:
        for m in rx.finditer(run):
            out.append('%s %s: %s -- `%s`' % (code, where, why, m.group(0)[:90]))
    if DOWNLOAD.search(run) and 'sha256sum -c' not in run:
        out.append('P4 %s: downloads a release artifact and never verifies it with sha256sum -c'
                   % where)


def self_test():
    bad = ('curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b x\n'
           'curl -o o https://github.com/google/osv-scanner/releases/latest/download/osv\n'
           'pip install --quiet checkov\n'
           'go install github.com/securego/gosec/v2/cmd/gosec@latest\n'
           'wget https://github.com/a/b/releases/download/v1/t.zip\n')
    good = ('curl -sSfLO https://github.com/a/b/releases/download/v1.2.3/t.tar.gz\n'
            'echo "abc  t.tar.gz" | sha256sum -c -\n'
            'pip install --quiet checkov==3.2.1\n'
            'go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0\n')
    b, g = [], []
    check_text('bad', bad, b)
    check_text('good', good, g)
    codes = {x.split()[0] for x in b}
    if codes != {'P1', 'P2', 'P3', 'P4'} or g:
        print('SELF-TEST FAILED: bad sample tripped %s (want P1-P4); good sample tripped %s'
              % (sorted(codes), g))
        return 1
    return 0


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if self_test():
        return 1
    out = []
    checked = 0
    for entry in SCOPE:
        rel, jobs = (entry, None) if isinstance(entry, str) else entry
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            print('UNKNOWN: %s missing; an absent file is not a pinned one.' % rel)
            return 2
        doc = yaml.safe_load(io.open(p, encoding='utf-8')) or {}
        seen = set()
        for jn, ss in steps(doc):
            if jobs is not None and jn not in jobs:
                continue
            seen.add(jn)
            for s in ss:
                if isinstance(s, dict) and s.get('run'):
                    checked += 1
                    check_text('%s :: %s :: %s' % (os.path.basename(rel), jn, s.get('name', '?')),
                               str(s['run']), out)
        if jobs is not None and jobs - seen:
            # A job named in scope that is not in the file would pass by never being read.
            print('UNKNOWN: %s has no job %s; a scope entry nothing matches is not a pass.'
                  % (rel, ', '.join(sorted(jobs - seen))))
            return 2
    if out:
        for o in out:
            print('FAIL: ' + o)
        return 1
    print('PASS: every install in %d scope entr%s (%d run steps) names its version and verifies '
          'what it downloaded.' % (len(SCOPE), 'y' if len(SCOPE) == 1 else 'ies', checked))
    print('      NOT YET IN SCOPE: %s.' % '; '.join(NOT_YET_IN_SCOPE))
    return 0


if __name__ == '__main__':
    sys.exit(main())
