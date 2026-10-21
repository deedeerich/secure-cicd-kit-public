#!/usr/bin/env python3
"""A branch-protection profile may require only status checks the kit's workflows actually emit.

WHY THIS EXISTS (completion ledger L104)

    developer-safety/branch-protection/*.json required `lint`, `test`, `sast`, `sca`, `policy`,
    `provenance` -- names no job in this kit emits. Applied as shipped, GitHub waits for checks that
    never arrive, so every pull request blocks forever, and the adopter's first fix is to delete the
    required checks. Either way the profile protects nothing: configured is not enforced.

    A required status check is the NAME of a check run. When a caller job `uses:` a reusable
    workflow, each called job reports as "<caller job name> / <called job name>" (the caller's
    `name:`, else its job id; the same for the called job). That name is DERIVED here from the
    shipped starter templates and the reusables they call, so it cannot drift from the code.

WHAT IT CHECKS
    B1  every context every profile requires is a check name the shipped templates emit
    B2  every profile requires the security gate's check (the one job that decides the verdict)
    B3  PROFILES.md names each profile's required checks exactly as its JSON does

WHAT IT CANNOT CHECK
    That the profile is APPLIED to any repository, or that GitHub accepted it. That is a setting on a
    real repository, read back with `gh api .../branches/<b>/protection` (PROFILES.md shows how).
    The naming rule above is GitHub's documented behaviour for reusable workflows, applied here --
    not observed by this script.

EXIT  0 every profile requires only emitted checks   1 a profile requires a check nothing emits
      2 could not be checked
"""
import argparse
import glob
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GATE_JOB = 'security-gate'
EXPR = re.compile(r'\$\{\{')


def load_yaml(path):
    import yaml
    with io.open(path, encoding='utf-8') as fh:
        return yaml.safe_load(fh) or {}


def label(job_id, job):
    n = job.get('name') if isinstance(job, dict) else None
    return str(n) if n else job_id


def emitted(root):
    """-> ({check name}, gate check name or None) from templates/*.yml and the reusables they call."""
    names, gate = set(), None
    for t in sorted(glob.glob(os.path.join(root, 'templates', '*.yml'))):
        doc = load_yaml(t)
        for jid, job in (doc.get('jobs') or {}).items():
            if not isinstance(job, dict):
                continue
            caller = label(jid, job)
            uses = job.get('uses')
            m = re.search(r'/\.github/workflows/([A-Za-z0-9._-]+\.ya?ml)@', str(uses or ''))
            if not m:
                if not EXPR.search(caller):
                    names.add(caller)
                continue
            callee = os.path.join(root, '.github', 'workflows', m.group(1))
            if not os.path.exists(callee):
                continue
            for cid, cjob in (load_yaml(callee).get('jobs') or {}).items():
                called = label(cid, cjob)
                if EXPR.search(called) or EXPR.search(caller):
                    continue          # a matrix-expanded name cannot be required by a fixed string
                full = '%s / %s' % (caller, called)
                names.add(full)
                if cid == GATE_JOB and m.group(1) == 'reusable-security.yml':
                    gate = gate or full
    return names, gate


def doc_contexts(md_text, profile):
    """The backticked check names on the profile's 'Required status checks' row in PROFILES.md."""
    sec = re.search(r'## Profile: %s.*?(?=\n## |\Z)' % re.escape(profile), md_text, re.S | re.I)
    if not sec:
        return None
    row = re.search(r'\|\s*Required status checks\s*\|([^\n]*)\|', sec.group(0))
    return None if not row else re.findall(r'`([^`]+)`', row.group(1))


DOC_SECTION = {'solo': 'solo', 'small-team': 'small team', 'critical-service': 'critical service'}


def check(root):
    fails = []
    names, gate = emitted(root)
    if not names or not gate:
        return ['UNKNOWN: could not derive the emitted check names (or the security gate\'s) from '
                'templates/*.yml'], names, gate
    pdir = os.path.join(root, 'developer-safety', 'branch-protection')
    profiles = sorted(glob.glob(os.path.join(pdir, '*.json')))
    if not profiles:
        return ['UNKNOWN: no profiles under developer-safety/branch-protection'], names, gate
    md_path = os.path.join(pdir, 'PROFILES.md')
    md = io.open(md_path, encoding='utf-8').read() if os.path.exists(md_path) else ''
    for p in profiles:
        prof = os.path.splitext(os.path.basename(p))[0]
        ctx = ((json.load(io.open(p, encoding='utf-8')).get('required_status_checks') or {})
               .get('contexts') or [])
        for c in ctx:
            if c not in names:
                fails.append('B1 %s requires `%s`, which no shipped workflow emits -- GitHub would '
                             'wait for it forever' % (os.path.basename(p), c))
        if gate not in ctx:
            fails.append('B2 %s does not require the security gate (`%s`)' % (os.path.basename(p), gate))
        sect = DOC_SECTION.get(prof)
        dc = doc_contexts(md, sect) if sect else None
        if dc is None:
            fails.append('B3 PROFILES.md has no "Required status checks" row for profile %s' % prof)
        elif sorted(dc) != sorted(ctx):
            fails.append('B3 PROFILES.md lists %s for %s; the JSON requires %s' % (dc, prof, ctx))
    return fails, names, gate


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--root', default=ROOT)
    a = ap.parse_args()
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    fails, names, gate = check(a.root)
    print('=== status checks the shipped templates emit (%d) ===' % len(names))
    for n in sorted(names):
        print('  %s%s' % (n, '   <- the security gate' if n == gate else ''))
    if any(f.startswith('UNKNOWN') for f in fails):
        print(fails[0])
        return 2
    print('')
    if fails:
        for f in fails:
            print('FAIL: %s' % f)
        return 1
    print('PASS: every branch-protection profile requires only checks the kit emits, every one')
    print('      requires the security gate, and PROFILES.md says the same as the JSON.')
    print('      NOT CHECKED: that any repository has a profile applied -- read it back with gh api.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
