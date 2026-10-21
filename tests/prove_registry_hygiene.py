#!/usr/bin/env python3
"""The debt registers refuse the entries nothing consults (completion ledger G-01, G-02, L70).

WHY THIS EXISTS

    A deferral is read only when its capability is asked about. Three ways an entry escaped that:

      G-01  `version-metadata` was a deferral whose capability had been split in two and renamed.
            No artifact registered the old name, so reconcile_validation never consulted it, and
            its 2026-09-30 expiry passed in silence for three weeks. An expired deferral that
            nothing reaches is the one state the expiry mechanism cannot see.
      L70   check_selftest_coverage.py counted a capability whose VALIDATION_REGISTRY state was
            `requires-integration-environment` as ACCOUNTED FOR, with no dated deferral behind it.
            "Needs infrastructure" is a reason to defer, never an exemption (the registry's own
            rule 4). Latent while no capability had that state; one entry would have hidden an
            unexercised workflow forever.
      EXEMPT  check_weakening_record.py's `verify-azure-oidc.yml` exemption said it closes when two
            named deferrals close. Both closed on 2026-10-15; the exemption stayed, its reason still
            saying the probe "HAS NEVER BEEN DISPATCHED". A closing condition that is met and an
            entry that is not closed is the same silence by another route.

WHAT IT PROVES
    H1  the shipped DEFERRALS hold no orphan (a key no artifact registers) and no stale entry (a key
        whose capability is observed); and reconcile_validation itself turns each into BLOCKING when
        one is seeded -- an orphan, and a stale one, each refused by name, rc 1
    H2  G-02 stays closed: `ticket-reconciliation` is registered at level `tool`, because its probe
        runs the reconciler, never reusable-ticket-reconcile.yml
    H3  check_selftest_coverage refuses an unexercised workflow whose only account is a
        `requires-integration-environment` state with no deferral (rc 1, named), and refuses one
        whose deferral has EXPIRED; CONTROL: an unexpired, complete deferral accounts for it (rc 0)
    H4  every check_weakening_record EXEMPT entry whose `closes` names deferral keys names keys that
        are still deferred; and every EXEMPT entry has an expiry that has not passed

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import contextlib
import datetime
import importlib
import io
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)


def fresh(name):
    if name in sys.modules:
        del sys.modules[name]
    return importlib.import_module(name)


def run_main(fn, argv):
    out = io.StringIO()
    saved = sys.argv
    sys.argv = argv
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = fn()
    finally:
        sys.argv = saved
    return rc, out.getvalue()


def h1(bad):
    R = fresh('reconcile_validation')
    registered = {c for caps in R.CAPABILITY_REGISTRY.values() for c in caps}
    synthetic = getattr(R, 'synthetic_deferral_keys', {'azure-oidc-auth-e2e'})
    for key in sorted(R.DEFERRALS):
        if key in synthetic:
            continue
        if key not in registered:
            bad.append('H1 shipped deferral `%s` is an orphan: no artifact registers it' % key)
        elif R.VALIDATION_REGISTRY.get(key, {}).get('state') == 'observed':
            bad.append('H1 shipped deferral `%s` is stale: the capability is observed' % key)
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        for label, key, extra in (
                ('orphan', 'seeded-orphan-capability', None),
                ('stale', 'sast-semgrep', None)):
            R = fresh('reconcile_validation')
            R.DEFERRALS[key] = {'reason': 'seeded', 'owner': 'kit-maintainer',
                                'proves': 'seeded', 'expires': '2099-01-01'}
            R.MAX_ACCEPTED_DEBT += 1
            rc, out = run_main(R.main, ['reconcile_validation.py', '--today', '2026-10-21'])
            named = re.search(r'`%s`[^\n]*(ORPHAN|STALE)' % re.escape(key), out)
            print('  H1 seeded %-7s deferral `%s`: rc=%s named=%s' % (label, key, rc, bool(named)))
            if rc != 1 or not named:
                bad.append('H1 a seeded %s deferral `%s` was not refused by name (rc=%s)'
                           % (label, key, rc))
    finally:
        os.chdir(cwd)
        fresh('reconcile_validation')


def h2(bad):
    R = fresh('reconcile_validation')
    lvl = R.VALIDATION_REGISTRY.get('ticket-reconciliation', {}).get('level')
    print('  H2 ticket-reconciliation level=%r' % lvl)
    if lvl != 'tool':
        bad.append('H2 ticket-reconciliation is registered at level %r; its probe never runs the '
                   'workflow, so it is `tool`' % lvl)


def h3(bad):
    work = tempfile.mkdtemp(prefix='coverage-l70-')
    try:
        wf = os.path.join(work, '.github', 'workflows')
        os.makedirs(wf)
        with open(os.path.join(wf, 'orphan-integration.yml'), 'w', encoding='utf-8') as fh:
            fh.write('name: x\non:\n  workflow_call: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n'
                     '    steps:\n      - run: echo\n')
        cases = [
            ('no deferral, requires-integration-environment', None, 1),
            ('expired deferral', '2026-01-01', 1),
            ('CONTROL unexpired deferral', '2099-01-01', 0),
        ]
        for label, expires, want in cases:
            R = fresh('reconcile_validation')
            C = fresh('check_selftest_coverage')
            R.CAPABILITY_REGISTRY = {'orphan-integration.yml': ['seeded-integration-cap']}
            R.VALIDATION_REGISTRY = {'seeded-integration-cap':
                                     {'probe': '-', 'state': 'requires-integration-environment'}}
            R.DEFERRALS = {}
            if expires:
                R.DEFERRALS['seeded-integration-cap'] = {
                    'reason': 'seeded', 'owner': 'kit-maintainer', 'proves': 'seeded',
                    'expires': expires}
            C.WORKFLOWS = os.path.join(wf, '*.yml')
            if hasattr(C, 'ROOT'):
                C.ROOT = work
            argv = ['check_selftest_coverage.py', '--today', '2026-10-21', '--workflows-only']
            rc, out = run_main(C.main, argv)
            print('  H3 %-48s rc=%s' % (label, rc))
            if rc != want:
                bad.append('H3 %s: check_selftest_coverage rc=%s, want %s' % (label, rc, want))
            elif want == 1 and 'orphan-integration.yml' not in out:
                bad.append('H3 %s: refused without naming the workflow' % label)
    finally:
        shutil.rmtree(work, ignore_errors=True)
        fresh('reconcile_validation')
        fresh('check_selftest_coverage')


def h4(bad, today):
    R = fresh('reconcile_validation')
    W = fresh('check_weakening_record')
    for wf, e in sorted(W.EXEMPT.items()):
        named = set(re.findall(r'`([a-z0-9][a-z0-9-]+)`', str(e.get('closes', ''))))
        caps = {c for caps in R.CAPABILITY_REGISTRY.values() for c in caps}
        gone = sorted(k for k in named if k in caps and k not in R.DEFERRALS)
        print('  H4 exemption %-26s expires %s; deferrals named in closes: %s'
              % (wf, e.get('expires'), ', '.join(sorted(named & caps)) or '-'))
        if gone:
            bad.append('H4 exemption %s closes when %s close, and they have closed (no deferral '
                       'left): the exemption is stale' % (wf, ', '.join(gone)))
        try:
            exp = datetime.date.fromisoformat(str(e.get('expires')))
        except ValueError:
            bad.append('H4 exemption %s has an unreadable expiry %r' % (wf, e.get('expires')))
            continue
        if exp < today:
            bad.append('H4 exemption %s expired %s' % (wf, exp))


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    today = datetime.date.today()
    bad = []
    h1(bad)
    h2(bad)
    h3(bad)
    h4(bad, today)
    for b in bad:
        print('FAIL ' + b)
    if bad:
        return 1
    print('PASS: no deferral is orphaned or stale, and a seeded one of each is refused by name;')
    print('      ticket-reconciliation is tool level; "needs infrastructure" and an expired deferral')
    print('      no longer account for an unexercised workflow; no exemption outlives its condition.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
