#!/usr/bin/env python3
"""Two deploys that can mutate the same app must queue behind each other, and never cancel.

WHY THIS EXISTS (L99; ROLLBACK_CONTRACT.md "Cancellation is a failure mode")

    Concurrency on a mutating workflow is a SAFETY setting: serialised per target, never
    cancelled in flight, because a run killed between its change and its verification strands a
    half-applied change with no completed manifest. The contract keys the group on
    "environment + target resource".

    The App Service reusable keyed its group on the SLOT as well as the app. Every slot path ends
    in a swap INTO PRODUCTION, so two runs staging into two different slots of one app were put in
    two different groups -- and could both swap into the same production at the same time. The
    target of a slot deploy is the app, not the slot; a key that includes the slot serialises the
    staging write and leaves the production write unserialised.

THE CASES
    attack     same environment, same app, DIFFERENT slots -> the resolved groups must be EQUAL
    allowed    a different app (or resource group, or environment) -> groups must DIFFER, so
               unrelated targets still deploy in parallel. A key that serialised everything would
               pass the attack case and fail this one.
    structure  cancel-in-progress is false on both deploy reusables, and the deploy job carries no
               timeout-minutes (ROLLBACK_CONTRACT.md: a timeout is a cancellation nobody chose).

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _deploy_steps as D  # noqa: E402


def group(doc, values):
    conc = doc.get('concurrency') or {}
    return D.resolve(str(conc.get('group', '')), values)


def base(app_key):
    return {'inputs.github_environment': 'prod-env', 'inputs.resource_group': 'rg-a',
            app_key: 'app-a', 'inputs.slot': 'staging'}


def check(path, app_key, has_slot):
    doc = D.load(path)
    name = os.path.basename(path)
    fails = []
    conc = doc.get('concurrency') or {}
    if conc.get('cancel-in-progress') is not False:
        fails.append('%s: cancel-in-progress is %r, not false. A deploy cancelled mid-mutation '
                     'strands a change with no manifest.' % (name, conc.get('cancel-in-progress')))
    if 'timeout-minutes' in D.job(doc):
        fails.append('%s: the deploy job carries timeout-minutes -- a cancellation nobody chose.'
                     % name)
    b = base(app_key)
    g = group(doc, b)
    if has_slot:
        other_slot = dict(b, **{'inputs.slot': 'canary'})
        direct = dict(b, **{'inputs.slot': ''})
        for label, v in (('slot canary', other_slot), ('direct to production', direct)):
            if group(doc, v) != g:
                fails.append('%s: same app, %s resolves to a different group (%r vs %r). Both '
                             'runs end by writing production, and they no longer queue.'
                             % (name, label, group(doc, v), g))
    for label, key, val in (('another app', app_key, 'app-b'),
                            ('another resource group', 'inputs.resource_group', 'rg-b'),
                            ('another environment', 'inputs.github_environment', 'dev-env')):
        if group(doc, dict(b, **{key: val})) == g:
            fails.append('%s: %s resolves to the SAME group. Unrelated targets would serialise '
                         'behind each other.' % (name, label))
    print('  %-36s group=%s' % (name, g))
    return fails


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    fails = check(D.APPSERVICE, 'inputs.webapp_name', True)
    fails += check(D.CONTAINERAPP, 'inputs.containerapp_name', False)
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: deploys to one app serialise whatever slot they stage into; unrelated targets '
          'stay parallel; nothing cancels in flight and no mutating job is time-bounded.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
