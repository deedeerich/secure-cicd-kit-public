#!/usr/bin/env python3
"""Every SARIF a job publishes must be WRITTEN by an earlier step in the same job (W4C-001).

WHY THIS EXISTS

    Three SAST jobs once published a SARIF that nothing wrote. sast-dotnet installed .NET, audited
    NuGet, then uploaded `dotnet-semgrep.sarif` -- no step produced it. sast-cpp uploaded
    `flawfinder.sarif` and never ran flawfinder. The uploads were guarded by "is there anything to
    publish?", so the absent file read as "no applicable source" and every run went green with ZERO
    static analysis (fixed in c483d6d, "three SAST jobs never ran a scanner at all"). Nothing in
    this repository would have caught it, because every check READ that an upload step existed.

WHAT IT CHECKS, STATICALLY

    For each job in each workflow, each publishing step -- `github/codeql-action/upload-sarif`
    (`sarif_file:`) and `actions/upload-artifact` whose `path:` names a `.sarif` -- must be
    preceded, in the SAME job, by a step that WRITES that file. "Writes" means one of:
      * a `run:` that names the file as the target of an output flag (`-o`, `--output`,
        `--output-file`, `-out`, `--sarif-output`), a shell redirect (`>`), or a Python
        `open("<file>", "w")`;
      * a `with:` key `output` / `output-file` / `sarif_file` / `output_file_path` on an ACTION
        step (not an upload) equal to the file -- trivy-action and codeql analyze write there;
      * either of the above naming a DIRECTORY the file sits in (checkov-action's
        `output_file_path` and Dependency-Check's `--out` are directories).
    A step that only TESTS the file (`[ -s x.sarif ]`) or uploads it is not a producer. A glob
    (`*.sarif`) is accepted only when an earlier step writes some `.sarif`.

    A negative control runs first: a synthetic job that uploads a SARIF nothing wrote MUST be
    reported, or this check proves nothing and exits 2.

EXIT
    0  every published SARIF has a producer
    1  a published SARIF has no producer in its job
    2  could not be checked -- UNKNOWN, never PASS
"""
import argparse
import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

OUT_FLAG = r'(?:-o|--out|--output|--output-file|-out|--sarif-output|--sarif-output-file)'


def writes(step, name):
    """True when `step` writes the file `name` (a basename or relative path)."""
    base = re.escape(name)
    pre = r'["\']?(?:[^\s"\'>]*/)?'
    run = str(step.get('run') or '')
    pats = [
        OUT_FLAG + r'(?:\s+|=)' + pre + base + r'\b',
        r'>{1,2}\s*' + pre + base + r'\b',
        r'open\(\s*["\']' + base + r'["\']\s*,\s*["\'][wa]',
        r'\bmv\s+\S+\s+' + pre + base + r'\b',
        r'\bcp\s+\S+\s+' + pre + base + r'\b',
        r'normalize_sarif\.py\s+\S+\s+' + pre + base + r'\b',
    ]
    if any(re.search(p, run) for p in pats):
        return True
    uses = str(step.get('uses') or '')
    if uses and 'upload-sarif' not in uses and 'upload-artifact' not in uses:
        w = step.get('with') or {}
        for k in ('output', 'output-file', 'sarif_file', 'output_file_path'):
            if str(w.get(k, '')).strip() == name:
                return True
    return False


def writes_path(step, name):
    """`name` itself, or a directory it sits in that the step names as its output target --
    checkov-action's `output_file_path` and Dependency-Check's `--out` are directories."""
    parts = name.split('/')
    for i in range(len(parts), 0, -1):
        if writes(step, '/'.join(parts[:i])):
            return True
    return writes(step, os.path.basename(name))


def writes_any_sarif(step):
    run = str(step.get('run') or '')
    if re.search(OUT_FLAG + r'(?:\s+|=)\S*\.sarif|>\s*\S*\.sarif|open\(\s*["\'][^"\']*\.sarif["\']\s*,'
                 r'\s*["\'][wa]', run):
        return True
    w = step.get('with') or {}
    uses = str(step.get('uses') or '')
    return bool(uses) and 'upload' not in uses and any(
        str(w.get(k, '')).endswith('.sarif') for k in ('output', 'output-file'))


def published(step):
    """-> list of SARIF names this step publishes."""
    uses = str(step.get('uses') or '')
    w = step.get('with') or {}
    if 'upload-sarif' in uses:
        f = str(w.get('sarif_file', '')).strip()
        return [f] if f else []
    if 'upload-artifact' in uses:
        return [ln.strip() for ln in str(w.get('path', '')).splitlines()
                if ln.strip().endswith('.sarif') or ln.strip().endswith('/*.sarif')]
    return []


def check_doc(doc, where):
    bad = []
    for jname, job in ((doc or {}).get('jobs') or {}).items():
        steps = (job or {}).get('steps') or []
        for i, s in enumerate(steps):
            for name in published(s):
                if '${{' in name:
                    continue
                earlier = steps[:i]
                if '*' in name:
                    ok = any(writes_any_sarif(e) for e in earlier)
                else:
                    ok = any(writes_path(e, name) for e in earlier)
                if not ok:
                    bad.append('%s: job `%s`, step %r publishes `%s`, which no earlier step in '
                               'the job writes' % (where, jname, s.get('name') or s.get('uses'),
                                                   name))
    return bad


NEGATIVE = {'jobs': {'ghost': {'steps': [
    {'name': 'Install', 'run': 'pip install semgrep'},
    {'name': 'Anything to publish?', 'run': '[ -s ghost.sarif ] && echo exists=true'},
    {'name': 'Publish', 'uses': 'github/codeql-action/upload-sarif@v4',
     'with': {'sarif_file': 'ghost.sarif'}}]}}}
POSITIVE = {'jobs': {'real': {'steps': [
    {'name': 'Scan', 'run': 'semgrep scan --sarif --output real.sarif .'},
    {'name': 'Publish', 'uses': 'github/codeql-action/upload-sarif@v4',
     'with': {'sarif_file': 'real.sarif'}}]}}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('workflows', nargs='*', help='default: .github/workflows/*.yml and overlays')
    args = ap.parse_args()
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if not check_doc(NEGATIVE, 'control') or check_doc(POSITIVE, 'control'):
        print('UNKNOWN: the negative control was not reported (or the positive one was). This '
              'check cannot distinguish a producer from its absence, so it proves nothing.')
        return 2
    files = args.workflows or sorted(
        glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml'))
        + glob.glob(os.path.join(ROOT, 'overlays', '*', 'workflows', '*.yml')))
    if not files:
        print('UNKNOWN: no workflow files found.')
        return 2
    bad, n = [], 0
    for f in files:
        doc = yaml.safe_load(io.open(f, encoding='utf-8'))
        for job in ((doc or {}).get('jobs') or {}).values():
            for s in (job or {}).get('steps') or []:
                n += len(published(s))
        try:
            where = os.path.relpath(f, ROOT).replace(os.sep, '/')
        except ValueError:
            where = f
        bad += check_doc(doc, where)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        print('A PUBLISHED FILE NOTHING WROTE IS A SCANNER THAT NEVER RAN, wearing a green job.')
        return 1
    print('PASS: %d SARIF publication(s) across %d workflow(s); each has a producing step earlier '
          'in its job (negative control detected).' % (n, len(files)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
