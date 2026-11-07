#!/usr/bin/env python3
"""App Service `slot: ''` may not mutate a production tier, and an unhealthy direct deploy says so.

WHY THIS EXISTS (DCR section 5 gap 1, the first and worst-misleading item)

    `slot: ''` is documented as "deploys straight to production". On that path the workflow set
    the image on production, restarted production and probed production -- with no reversal step
    anywhere in the file, so a failed probe ended with production serving the failed digest.

    Worse, the step that prints "no swap performed. Production is untouched." was gated on
    `inputs.slot != ''`. It did not run on the one path where production WAS touched, and it was
    the only message about production the run ever printed. The guard reassured exactly when it
    should not and stayed silent exactly when it should warn -- the defect class DCR names: a
    conditional step whose condition excludes the case it exists to handle.

THE MINIMUM FIX, IN DCR'S ORDER
    (a) the direct path refuses to run at a production tier (uat, prod -- environment_tier, where
        both are production) until a reversal path exists; refused BEFORE login
    (b) the unhealthy path always reports, with different text for slot-staged and direct
    (c) pre-change capture and reversal for the direct path -- later gaps (4-7), not this file

    environment_tier is a REQUIRED input taking the five registered values. An unregistered tier
    is refused: a near-miss ("production") must not be read as "not uat or prod".

THE CASES, run as a whole job against a stubbed cloud (tests/_workflow_runner.py)
    attack     prod and uat with slot '' -> refused before ANY az call, for the stated reason
    missing    environment_tier '' or 'production' -> refused before any az call
    allowed    dev with slot '' and a healthy image -> deploys
    the guard  dev with slot '' and an UNHEALTHY image -> the run says production was modified
               by the failed digest, names what live state holds now (read back, never echoed),
               and never says "untouched"
    recovery   prod with a slot and an unhealthy image -> "untouched" is printed AND is true:
               production's image in the stub is byte-identical to before

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _workflow_runner as W  # noqa: E402


def inputs(tier, slot, digest=W.NEW):
    return dict(github_environment='env', routing_result='PROCEED', environment_tier=tier,
                resource_group='rg-a', webapp_name='web', acr_login_server=W.REG,
                image_repository=W.REPO, image_digest=digest, cloud='commercial', slot=slot,
                swap_on_healthy=True, health_path='/health', health_retries=2,
                health_interval_seconds=0, version_metadata='', rollback_on_failure=True)


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if not W.D.bash()[0]:
        print('UNKNOWN: no usable bash.')
        return 2
    fails = []

    for tier in ('prod', 'uat'):
        res, _final, calls = W.run_world(W.D.APPSERVICE, inputs(tier, ''), W.appservice_state())
        az = [c for c in calls if c[0] == 'az']
        print('  attack   %-5s slot=\'\'        az calls=%d failed=%s' % (tier, len(az), res['failed']))
        if az or not res['failed']:
            fails.append('%s, slot \'\': the direct-to-production path ran (%d az call(s)).'
                         % (tier, len(az)))
        elif 'direct' not in res['log'].lower():
            fails.append('%s, slot \'\': refused, but not for the direct-path reason.' % tier)

    for tier in ('', 'production'):
        res, _final, calls = W.run_world(W.D.APPSERVICE, inputs(tier, 'staging'),
                                         W.appservice_state())
        az = [c for c in calls if c[0] == 'az']
        print('  missing  %-12r          az calls=%d failed=%s' % (tier, len(az), res['failed']))
        if az or not res['failed']:
            fails.append('environment_tier %r was not refused before login.' % tier)
        elif 'environment_tier' not in res['log']:
            fails.append('environment_tier %r refused for an unrelated reason.' % tier)

    res, final, _ = W.run_world(W.D.APPSERVICE, inputs('dev', ''), W.appservice_state())
    prod = final['webapp']['slots']['production']['linuxFxVersion']
    print('  allowed  dev   slot=\'\'        failed=%s production=%s' % (res['failed'], prod[-8:]))
    if res['failed'] or not prod.endswith(W.NEW):
        fails.append('dev, slot \'\', healthy: the deploy did not complete (a guard that refuses '
                     'everything is a broken pipeline).')

    st = W.appservice_state(unhealthy_images=[W.ref(W.NEW)])
    res, final, _ = W.run_world(W.D.APPSERVICE, inputs('dev', ''), st)
    text = (res['log'] + res['summary']).lower()
    print('  guard    dev   slot=\'\' unhealthy  failed=%s' % res['failed'])
    if 'untouched' in text:
        fails.append('direct path, unhealthy: the run claimed production was untouched while '
                     'production serves the failed digest.')
    said = [ln for ln in (res['log'] + '\n' + res['summary']).splitlines()
            if ln.startswith(('::error', '::warning')) and 'production' in ln.lower()
            and 'unhealthy' in ln.lower() and W.NEW in ln]
    if not said:
        fails.append('direct path, unhealthy: no step reported that PRODUCTION was modified and '
                     'is unhealthy, naming the digest this run set. The message the slot path '
                     'gets must not be the only message there is.')
    # What production holds NOW is read back, not echoed: the reversal has restored the prior
    # image by the time this message is written (live run 38879879589 echoed the inputs).
    live_now = final['webapp']['slots']['production']['linuxFxVersion'].split('@')[-1]
    if said and (live_now not in said[0] or 'now serves' in said[0].lower()):
        fails.append('direct path, unhealthy: the production message does not report the image '
                     'live state holds now (%s): %s' % (live_now[:15], said[0][:300]))
    if not res['failed']:
        fails.append('direct path, unhealthy: the job did not fail.')

    st = W.appservice_state(unhealthy_images=[W.ref(W.NEW)])
    before = st['webapp']['slots']['production']['linuxFxVersion']
    res, final, _ = W.run_world(W.D.APPSERVICE, W.break_glass(inputs('prod', 'staging')), st)
    after = final['webapp']['slots']['production']['linuxFxVersion']
    text = res['log'] + res['summary']
    print('  recovery prod  slot=staging unhealthy  production unchanged=%s' % (before == after))
    if before != after:
        fails.append('slot path, unhealthy: production changed although no swap should run.')
    if 'untouched' not in text:
        fails.append('slot path, unhealthy: the held-back report did not run.')

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: slot \'\' refuses at uat and prod before login; an unregistered tier refuses;')
    print('      dev may deploy direct; an unhealthy direct deploy is reported as production')
    print('      modified and unhealthy; "untouched" appears only where it is true.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
