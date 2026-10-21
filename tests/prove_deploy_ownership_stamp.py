#!/usr/bin/env python3
"""An App Service swap stamps PRODUCTION with this release's ownership, and the reversal reads it there.

WHY THIS EXISTS (ledger DCR-OWN; DEPLOYMENT_CONTRACT_RECONCILIATION.md 8.3 "the stamp travels with
the mutation"; section 8.1 P1)

    The App Service mutation stamped the SLOT it wrote (a resource tag, set before the image).
    Tags do not move with a swap, so after the swap production carried no stamp of this release --
    or the previous release's -- while serving this release's image. And the reversal read every
    entry's stamp from the TARGET slot, so the swap entry (whose object is production) was judged
    by the slot's stamp: a production another release had claimed since was still "ours", and the
    reversal swapped it back over that release.

WHAT IS BUILT
    The swap writes this release's RELEASE_OWNERSHIP_STAMP onto production BEFORE swapping, and
    records production's previous stamp in the manifest entry. The reversal reads each entry's
    stamp from the object it names (production for the swap, the slot for the slot's image), and a
    swap-back it performs restores production's previous stamp.

WHAT IS RUN
    The App Service deploy job as shipped against the stub cloud, through the same delegating az
    stand-in as tests/prove_deploy_now_serving.py, with production's public name made to fail after
    the swap (the serving check fails, the reversal runs) and, in the attack, another release's
    stamp written onto production right after the swap.

CASES (docs/PROOF_RULE.md)
    allowed           a healthy swap -> production's stamp names this release
    attack            serving fails after the swap, and another release has claimed production ->
                      the swap is NOT reversed (REVERSAL_REFUSED_CONFLICT, OWNED_BY_ANOTHER_RELEASE),
                      ROLLBACK_PARTIAL, production keeps the other release's claim
    recovery          serving fails after the swap, nobody else touched it -> swapped back,
                      ROLLBACK_VERIFIED, production's previous stamp restored

EXIT 0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _workflow_runner as W  # noqa: E402
import prove_deploy_now_serving as N  # noqa: E402

OTHER_STAMP = 'release_id=run-someone-else-1;run=elsewhere;post=x'
PRIOR_STAMP = 'release_id=run-earlier-1;run=earlier;post=y'


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bad = []
    swap = 'webapp deployment slot swap'
    for name, hook, fail_serving in (
            ('allowed', None, False),
            ('attack', {'after': swap, 'do': 'retag', 'stamp': OTHER_STAMP, 'host': ''}, True),
            ('recovery', None, True)):
        st = W.appservice_state()
        st['webapp']['slots']['production']['tags'] = {'release_ownership_stamp': PRIOR_STAMP}
        if hook:
            st['post_hook'] = hook
        if fail_serving:
            st['unhealthy_hosts'] = ['web.site.example']
        try:
            res, final = N.world(N.inputs(), st)
        except W.Unmodelled as e:
            print('UNKNOWN: %s' % e)
            return 2
        ev = res['evidence']
        release = (ev.get('manifest.json') or {}).get('release_id', '')
        prod_stamp = (final['webapp']['slots']['production'].get('tags') or {}).get(
            'release_ownership_stamp', '')
        o = ev.get('outcome.json') or {}
        rv = ev.get('reversal.json') or {}
        swap_entry = [e for e in rv.get('entries') or [] if e.get('action') == 'REDIRECTED']
        print('  %-9s outcome=%-18s production stamp=%-40s swap reversal=%s'
              % (name, o.get('deployment_outcome'), prod_stamp[:40],
                 [(e.get('reversal_disposition'), e.get('performed')) for e in swap_entry]))
        if name == 'allowed':
            if o.get('deployment_outcome') != 'DEPLOY_HEALTHY' or \
                    'release_id=%s;' % release not in prod_stamp + ';':
                bad.append('allowed: after a healthy swap production\'s stamp is %r, not this '
                           'release (%s)\n%s' % (prod_stamp, release, res['log'][-800:]))
        elif name == 'attack':
            if not swap_entry or swap_entry[0].get('performed') or \
                    swap_entry[0].get('release_ownership') != 'OWNED_BY_ANOTHER_RELEASE':
                bad.append('attack: the swap was reversed over another release\'s claim on '
                           'production (%r)' % swap_entry)
            if o.get('deployment_outcome') != 'ROLLBACK_PARTIAL' or prod_stamp != OTHER_STAMP:
                bad.append('attack: outcome %r, production stamp %r; want ROLLBACK_PARTIAL and the '
                           'other release\'s claim left standing'
                           % (o.get('deployment_outcome'), prod_stamp))
        else:
            if not swap_entry or not swap_entry[0].get('performed') or \
                    o.get('deployment_outcome') != 'ROLLBACK_VERIFIED':
                bad.append('recovery: the swap was not reversed and verified (%r, %r)\n%s'
                           % (o.get('deployment_outcome'), swap_entry, res['log'][-800:]))
            if prod_stamp != PRIOR_STAMP:
                bad.append('recovery: after the swap-back production\'s stamp is %r, not the '
                           'previous release\'s %r' % (prod_stamp, PRIOR_STAMP))
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the swap stamps production with this release before swapping; the reversal judges '
          'the swap by production\'s own stamp, refuses it when another release has claimed '
          'production, and a swap-back restores the previous stamp.')
    print('      STUB CLOUD. That a resource tag does not move with a real swap is INFERRED (ledger '
          'DCR-OWN); a live slot run is owed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
