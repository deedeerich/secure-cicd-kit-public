#!/usr/bin/env python3
"""The deploy outcome is reconciled reality, not the run's intent -- proven against a stub cloud.

WHY THIS EXISTS (DCR sections 3 and 5; L95 gaps 2-9 and 11, L96, L97, L101)

    Both deploy reusables ended with an `if: always()` summary that printed the digest the run
    TRIED to deploy beside a Health cell that might read `failure`, with nothing read back from
    the target. A reader concluded their change shipped when it had been rolled back -- the
    reporting defect that motivated the whole reconciliation. Each section below is one gap of
    DCR section 5 (or the ledger row named), added in its own commit, and each runs the WHOLE job
    as shipped (tests/_workflow_runner.py) against a stateful stand-in for the cloud
    (tests/_fake_az.py). Assertions read the stand-in's FINAL STATE as well as the report, so
    "the report says X" is always checked against "X is what the cloud holds".

    The scenarios are DCR section 7.8's acceptance matrix, stubbed:
        A  healthy deployment
        B  partial mutation / execution failure
        C  complete deployment, unhealthy workload
        D  mutation occurred, reconciliation lost            -> status untrusted
        E  technically healthy release withdrawn by the business   (owed: needs a release graph)
    crossed with a prior release and an empty target as the rollback point.

    STUBBED, NOT LIVE. Every answer here is what the workflow does with what the stand-in says.
    Whether Azure says the same is the hosted acceptance run, which is owed and is not claimed.

USAGE   python3 tests/prove_deploy_outcome.py [--section NAME ...]
EXIT    0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _workflow_runner as W  # noqa: E402

SECTIONS = []


def section(fn):
    SECTIONS.append(fn)
    return fn


def ca_inputs(**over):
    i = dict(github_environment='env', routing_result='PROCEED', environment_tier='dev',
             resource_group='rg-a', containerapp_name='web', acr_login_server=W.REG,
             image_repository=W.REPO, image_digest=W.NEW, cloud='commercial',
             health_path='/health', health_retries=2, health_interval_seconds=0,
             rollback_on_failure=True, version_metadata='')
    i.update(over)
    return i


def as_inputs(**over):
    i = dict(github_environment='env', routing_result='PROCEED', environment_tier='dev',
             resource_group='rg-a', webapp_name='web', acr_login_server=W.REG,
             image_repository=W.REPO, image_digest=W.NEW, cloud='commercial', slot='staging',
             swap_on_healthy=True, health_path='/health', health_retries=2,
             health_interval_seconds=0, version_metadata='', rollback_on_failure=True)
    i.update(over)
    return i


def outcome(res):
    o = res['evidence'].get('outcome.json')
    return o if isinstance(o, dict) else {}


def report_rows(summary):
    """-> [(claim, field, value)] from the outcome table."""
    rows = []
    for line in summary.splitlines():
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) == 3 and cells[0] in ('ATTEMPTED', 'NOW SERVING'):
            rows.append(tuple(cells))
    return rows


def ca_live_images(final):
    a = final['containerapp']
    out = []
    for t in a['traffic']:
        if t.get('weight', 0) > 0:
            n = a['latestRevisionName'] if t.get('latestRevision') else t['revisionName']
            out.append(a['revisions'][n]['image'])
    return out


# ------------------------------------------------------------------------------ gap 2
@section
def gap2_attempted_vs_now_serving(fails):
    """Every identifier is labelled ATTEMPTED or NOW SERVING; NOW SERVING is read back."""
    unhealthy = {'unhealthy_images': [W.ref(W.NEW)]}
    cases = [
        ('containerapp C unhealthy', W.D.CONTAINERAPP, ca_inputs(),
         W.containerapp_state(**unhealthy), lambda f: ca_live_images(f)),
        ('appservice C held on slot', W.D.APPSERVICE, as_inputs(),
         W.appservice_state(**unhealthy),
         lambda f: [f['webapp']['slots']['production']['linuxFxVersion'].split('|', 1)[1]]),
        ('containerapp D reads lost', W.D.CONTAINERAPP, ca_inputs(),
         W.containerapp_state(fail_after_mutation=['containerapp show',
                                                   'containerapp revision list']), None),
    ]
    for label, wf, inp, st, live in cases:
        res, final, _ = W.run_world(wf, inp, st)
        rows = report_rows(res['summary'])
        now = [r for r in rows if r[0] == 'NOW SERVING']
        att = [r for r in rows if r[0] == 'ATTEMPTED']
        print('  gap2  %-28s rows: %d attempted, %d now-serving' % (label, len(att), len(now)))
        if not now or not att:
            fails.append('gap2 %s: the report has no ATTEMPTED/NOW SERVING labelled rows '
                         '(summary was:\n%s)' % (label, res['summary'][-600:]))
            continue
        if not any(W.NEW in r[2] for r in att):
            fails.append('gap2 %s: the attempted digest is not reported as ATTEMPTED.' % label)
        now_text = ' '.join(r[2] for r in now)
        if W.NEW in now_text:
            fails.append('gap2 %s: the attempted digest appears under NOW SERVING, but the '
                         'stub cloud is not serving it.' % label)
        if live is None:
            if 'unknown' not in now_text.lower():
                fails.append('gap2 %s: live state was unreadable and NOW SERVING did not say '
                             'unknown.' % label)
        else:
            for img in live(final):
                if img.split('@')[-1] not in now_text:
                    fails.append('gap2 %s: NOW SERVING does not show what the cloud serves '
                                 '(%s).' % (label, img))


# ------------------------------------------------------------------------------ gap 3
META = '{"version":"1.2.3","source":"git:abc"}'


def provenance_marks(final):
    """Every place in the stub cloud that carries a provenance claim, as (where, text)."""
    out = []
    a = final.get('containerapp')
    if a:
        for n, r in a['revisions'].items():
            for k, v in r['env'].items():
                if 'provenance' in k.lower():
                    out.append(('revision %s env' % n, v))
        for k, v in (a.get('tags') or {}).items():
            if 'provenance' in k.lower():
                out.append(('app tag %s' % k, v))
    w = final.get('webapp')
    if w:
        for sn, sl in w['slots'].items():
            for k, v in list((sl.get('appsettings') or {}).items()) + list((sl.get('tags') or {}).items()):
                if 'provenance' in k.lower():
                    out.append(('slot %s %s' % (sn, k), v))
    return out


@section
def gap3_provenance_after_health(fails):
    """Provenance is stamped only once health and live reconciliation hold, on what serves."""
    unhealthy = {'unhealthy_images': [W.ref(W.NEW)]}
    for label, wf, inp, st in (
            ('containerapp C', W.D.CONTAINERAPP, ca_inputs(version_metadata=META),
             W.containerapp_state(mode='Single', **unhealthy)),
            ('appservice C slot', W.D.APPSERVICE, as_inputs(version_metadata=META),
             W.appservice_state(**unhealthy))):
        res, final, _ = W.run_world(wf, inp, st)
        marks = provenance_marks(final)
        print('  gap3  %-28s provenance marks after a FAILED deploy: %d' % (label, len(marks)))
        if marks:
            fails.append('gap3 %s: the target carries provenance for a deploy that never passed '
                         'health: %s' % (label, marks))
    for label, wf, inp, st, where in (
            ('containerapp A', W.D.CONTAINERAPP, ca_inputs(version_metadata=META),
             W.containerapp_state(mode='Single'), 'app tag'),
            ('appservice A swapped', W.D.APPSERVICE, as_inputs(version_metadata=META),
             W.appservice_state(), 'slot production')):
        res, final, _ = W.run_world(wf, inp, st)
        marks = provenance_marks(final)
        hit = [m for m in marks if m[0].startswith(where) and W.NEW in m[1]]
        print('  gap3  %-28s provenance on the serving object naming the digest: %s'
              % (label, bool(hit)))
        if not hit:
            fails.append('gap3 %s: a healthy deploy did not stamp provenance naming %s on the '
                         'object now serving (%s); marks were %s' % (label, W.NEW[:15], where, marks))
        if label.startswith('containerapp') and len(final['containerapp']['revisions']) != 2:
            fails.append('gap3 %s: stamping provenance created another revision (%d revisions); '
                         'the stamp mutated the thing it describes after it was verified.'
                         % (label, len(final['containerapp']['revisions'])))


# ------------------------------------------------------------------------------ L93 record
@section
def l93_controls_unavailable_recorded(fails):
    """The verdict's controls_unavailable list reaches the deploy's outcome report."""
    for label, wf, inp, st in (
            ('containerapp A', W.D.CONTAINERAPP,
             ca_inputs(routing_result='PROCEED_WITH_ADVISORY', controls_unavailable='codeql,image-scan'),
             W.containerapp_state(mode='Single')),
            ('appservice A', W.D.APPSERVICE,
             as_inputs(routing_result='PROCEED_WITH_ADVISORY', controls_unavailable='codeql,image-scan'),
             W.appservice_state())):
        res, _final, _ = W.run_world(wf, inp, st)
        o = outcome(res)
        got = o.get('gate', {}).get('controls_unavailable')
        print('  l93   %-28s controls_unavailable recorded: %r' % (label, got))
        if got != ['codeql', 'image-scan'] or 'image-scan' not in res['summary']:
            fails.append('l93 %s: the outcome report does not record the gate\'s '
                         'controls_unavailable (got %r).' % (label, got))
        if o.get('gate', {}).get('routing_result') != 'PROCEED_WITH_ADVISORY':
            fails.append('l93 %s: the outcome report does not record the verdict it proceeded on.'
                         % label)


# ------------------------------------------------------------------------------ gap 4 / L97
def mutating_calls(calls):
    verbs = ('update', 'set', 'swap', 'activate', 'deactivate', 'restart')
    return [c for c in calls if c[0] == 'az' and any(v in c[1:5] for v in verbs)]


@section
def gap4_read_failure_is_not_empty(fails):
    """previous_state has three values; a capture read error fails loudly before any mutation."""
    for label, wf, inp, st in (
            ('containerapp read error', W.D.CONTAINERAPP, ca_inputs(),
             W.containerapp_state(fail=['containerapp revision list'])),
            ('appservice read error', W.D.APPSERVICE, as_inputs(),
             W.appservice_state(fail=['webapp config show']))):
        res, _final, calls = W.run_world(wf, inp, st)
        muts = mutating_calls(calls)
        print('  gap4  %-28s mutations=%d failed=%s' % (label, len(muts), res['failed']))
        if muts:
            fails.append('gap4 %s: the capture could not read the target and the run MUTATED it '
                         'anyway (%s). A read failure became an empty previous state.'
                         % (label, muts[0][:4]))
        if not res['failed']:
            fails.append('gap4 %s: the job did not fail.' % label)
        snap = res['evidence'].get('snapshot.json') or {}
        if snap.get('previous_state') != 'UNKNOWN' or 'UNKNOWN' not in res['log']:
            fails.append('gap4 %s: previous_state was not recorded as UNKNOWN (snapshot: %r).'
                         % (label, snap.get('previous_state')))
    for label, wf, inp, st, want in (
            ('containerapp existing', W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(),
             'EXISTING_DEPLOYMENT'),
            ('containerapp empty', W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(empty=True),
             'EMPTY'),
            ('appservice existing', W.D.APPSERVICE, as_inputs(), W.appservice_state(),
             'EXISTING_DEPLOYMENT'),
            ('appservice empty', W.D.APPSERVICE, as_inputs(), W.appservice_state(prior=None),
             'EMPTY')):
        res, _final, _calls = W.run_world(wf, inp, st)
        got = (res['evidence'].get('snapshot.json') or {}).get('previous_state')
        print('  gap4  %-28s previous_state=%s' % (label, got))
        if got != want:
            fails.append('gap4 %s: previous_state %r, wanted %s (measured, not assumed).'
                         % (label, got, want))
    for wf in W.D.deploy_workflows:
        for s in W.D.steps(W.D.load(wf)):
            if 'capture' in str(s.get('name', '')).lower() and re.search(
                    r'\|\|\s*true|2>\s*/dev/null', str(s.get('run', ''))):
                fails.append('gap4 %s: the capture step suppresses its own errors.'
                             % os.path.basename(wf))


# ------------------------------------------------------------------------------ gap 6
@section
def gap6_snapshot_and_manifest(fails):
    """A change manifest records what THIS run did, written before the mutation begins."""
    # Another actor creates a revision right after ours: "newest by creation time" is then theirs.
    st = W.containerapp_state(mode='Multiple',
                              second_actor={'after': 'containerapp update',
                                            'do': 'new_revision_by_other'})
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), st)
    man = res['evidence'].get('manifest.json') or {}
    ours = [n for n, r in final['containerapp']['revisions'].items() if r['image'] == W.ref(W.NEW)]
    created = [e for e in man.get('entries', []) if e.get('action') == 'CREATED']
    print('  gap6  containerapp second actor     manifest CREATED=%s ours=%s'
          % ([e.get('object') for e in created], ours))
    if not created or [e['object'] for e in created] != ours:
        fails.append('gap6 containerapp: the manifest does not record exactly the revision this '
                     'run created (%s); recorded %s. Ownership was guessed, not recorded.'
                     % (ours, [e.get('object') for e in created]))
    if (res['evidence'].get('snapshot.json') or {}).get('previous_state') != 'EXISTING_DEPLOYMENT':
        fails.append('gap6 containerapp: no pre-change snapshot beside the manifest.')

    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(), W.appservice_state())
    man = res['evidence'].get('manifest.json') or {}
    acts = sorted((e.get('action'), e.get('object')) for e in man.get('entries', []))
    print('  gap6  appservice swap               manifest=%s' % acts)
    mod = [e for e in man.get('entries', []) if e.get('action') == 'MODIFIED']
    if not mod or mod[0].get('prior') != 'DOCKER|' + W.ref(W.GOOD) or \
            mod[0].get('post') != 'DOCKER|' + W.ref(W.NEW):
        fails.append('gap6 appservice: no MODIFIED entry carrying the captured prior and the '
                     'post-state for the staged slot (%r).' % mod)
    if not any(e.get('action') == 'REDIRECTED' for e in man.get('entries', [])):
        fails.append('gap6 appservice: the swap into production is not recorded as REDIRECTED.')

    st = W.containerapp_state(fail=['containerapp update'])
    res, _final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), st)
    man = res['evidence'].get('manifest.json') or {}
    print('  gap6  containerapp update refused   manifest status=%s' % man.get('status'))
    if man.get('status') != 'planned' or not man.get('entries'):
        fails.append('gap6 containerapp: when the mutation call itself fails, the manifest must '
                     'already exist as planned -- it is written BEFORE mutation, so a run that '
                     'dies mid-change still says what it was about to do (got %r).' % man)


# ------------------------------------------------------------------------------ L101
@section
def l101_health_proves_the_intended_digest_serves(fails):
    """Health establishes that the INTENDED digest is what serves, read back from live state."""
    bad = {'unhealthy_images': [W.ref(W.NEW)]}
    # Multiple-revision mode: the old probe hit the app FQDN, which still routed to the OLD
    # revision, so an unhealthy new revision passed -- and a healthy one never received traffic.
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(**bad))
    h = res['steps'].get('health', {}).get('outcome')
    print('  l101  containerapp multi, bad image   health=%s' % h)
    if h == 'success':
        fails.append('l101 containerapp: the health step passed while the new revision answers '
                     '503 -- the 200 came from the previous revision.')
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state())
    live = ca_live_images(final)
    print('  l101  containerapp multi, good image  serving=%s failed=%s'
          % ([i[-6:] for i in live], res['failed']))
    if live != [W.ref(W.NEW)] or res['failed']:
        fails.append('l101 containerapp: a healthy deploy in multiple-revision mode ended with '
                     'traffic on %s, not on the revision it verified.' % live)
    res, _f, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(
        fail_after_mutation=['containerapp revision show']))
    h = res['steps'].get('health', {}).get('outcome')
    print('  l101  containerapp readback lost      health=%s' % h)
    if h == 'success':
        fails.append('l101 containerapp: the running image could not be read back and health '
                     'still passed. A 200 is not a digest.')
    # App Service: someone else's image lands on the slot after our write; it answers 200.
    st = W.appservice_state(second_actor={'after': 'webapp restart', 'do': 'modify_slot_image',
                                          'slot': 'staging'})
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(), st)
    h = res['steps'].get('health', {}).get('outcome')
    prod = final['webapp']['slots']['production']['linuxFxVersion']
    print('  l101  appservice slot overwritten     health=%s production=%s' % (h, prod[-6:]))
    if h == 'success' or not prod.endswith(W.GOOD):
        fails.append('l101 appservice: the slot answered 200 with a digest this run did not set, '
                     'and the run treated that as its own healthy deploy (production now %s).'
                     % prod[-12:])
    v = res['evidence'].get('verification.json') or {}
    if v.get('runtime_deployed') is not False:
        fails.append('l101 appservice: verification.json does not record runtime_deployed=false '
                     'for the overwritten slot (%r).' % v)


# ------------------------------------------------------------------------------ gap 5
@section
def gap5_rollback_to_empty(fails):
    """A first deployment has a rollback point: the measured empty state."""
    bad = {'unhealthy_images': [W.ref(W.NEW)]}
    # C on an empty Container App: the run created the only revision; reversal removes (here:
    # deactivates) exactly that, after the section 8 preconditions hold.
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(empty=True, **bad))
    rv = res['evidence'].get('reversal.json') or {}
    active = [n for n, r in final['containerapp']['revisions'].items() if r['active']]
    print('  gap5  containerapp empty, C        path=%s active after=%s'
          % (rv.get('reversal_path'), active))
    if rv.get('reversal_path') != 'ROLLBACK_TO_EMPTY' or active:
        fails.append('gap5 containerapp: a failed FIRST deploy was not reversed to the measured '
                     'empty state (path %r, still active %s). "No previous revision" skipped '
                     'recovery on exactly the population that orphans the most.'
                     % (rv.get('reversal_path'), active))
    ents = rv.get('entries') or []
    if not ents or ents[0].get('reversal_disposition') != 'REVERSAL_REMOVE':
        fails.append('gap5 containerapp: the removal was not derived as REVERSAL_REMOVE from live '
                     'preconditions (%r).' % ents)
    # Same, but a second actor took a dependency on the new revision before the reversal.
    st = W.containerapp_state(empty=True, second_actor={'after': 'curl',
                                                        'do': 'modify_new_revision_traffic'}, **bad)
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), st)
    rv = res['evidence'].get('reversal.json') or {}
    ents = rv.get('entries') or []
    still = [n for n, r in final['containerapp']['revisions'].items() if r['active']]
    print('  gap5  containerapp empty, dependent  disposition=%s active after=%s'
          % ([e.get('reversal_disposition') for e in ents], still))
    if not ents or ents[0].get('reversal_disposition') != 'REVERSAL_WITHHELD_DEPENDENCY' or not still:
        fails.append('gap5 containerapp: something took a dependency on the revision this run '
                     'created, and the reversal removed it anyway or did not say why it kept it '
                     '(%r).' % ents)
    # App Service, direct path at dev, target measured empty: restore the empty configuration.
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(slot=''),
                                W.appservice_state(prior=None, **bad))
    rv = res['evidence'].get('reversal.json') or {}
    prod = final['webapp']['slots']['production']['linuxFxVersion']
    print('  gap5  appservice empty, direct C   path=%s production=%r'
          % (rv.get('reversal_path'), prod[-8:]))
    if rv.get('reversal_path') != 'ROLLBACK_TO_EMPTY' or prod:
        fails.append('gap5 appservice: the empty production was left serving the failed digest '
                     '(%r).' % prod)


# ------------------------------------------------------------------------------ gap 7
@section
def gap7_reversal_verified_against_live_state(fails):
    """A reversal is verified by reading live state back against the snapshot, never by exit."""
    bad = {'unhealthy_images': [W.ref(W.NEW)]}
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(**bad))
    rv = res['evidence'].get('reversal.json') or {}
    print('  gap7  containerapp prior, C          result=%s' % rv.get('result'))
    if rv.get('result') != 'ROLLBACK_VERIFIED' or ca_live_images(final) != [W.ref(W.GOOD)]:
        fails.append('gap7 containerapp: a complete reversal was not verified against live state '
                     '(result %r, serving %s).' % (rv.get('result'), ca_live_images(final)))
    if 'web--r2' not in json.dumps(rv.get('verification') or {}):
        fails.append('gap7 containerapp: verification does not assert the NEGATIVE space -- that '
                     'the revision this run created is no longer active.')
    # The removal call fails: the restored traffic is right, but our revision is still active.
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(
        fail=['containerapp revision deactivate'], **bad))
    rv = res['evidence'].get('reversal.json') or {}
    print('  gap7  containerapp removal fails     result=%s' % rv.get('result'))
    if rv.get('result') != 'ROLLBACK_PARTIAL':
        fails.append('gap7 containerapp: a reversal that left the created revision active was '
                     'reported as %r, not ROLLBACK_PARTIAL.' % rv.get('result'))
    # The removal applies and then reports an error: exit status says failed, reality says done.
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(
        apply_then_fail=['containerapp revision deactivate'], **bad))
    rv = res['evidence'].get('reversal.json') or {}
    print('  gap7  containerapp exit lies         result=%s' % rv.get('result'))
    if rv.get('result') != 'ROLLBACK_VERIFIED':
        fails.append('gap7 containerapp: live state matched the snapshot but the reversal '
                     'reported %r -- the command exit decided, not the reconciliation.'
                     % rv.get('result'))
    # Single-revision mode: the traffic-weight mechanism is not valid there.
    res, final, calls = W.run_world(W.D.CONTAINERAPP, ca_inputs(),
                                    W.containerapp_state(mode='Single', **bad))
    rv = res['evidence'].get('reversal.json') or {}
    traffic_calls = [c for c in calls if c[1:4] == ['containerapp', 'ingress', 'traffic']]
    print('  gap7  containerapp single mode       result=%s traffic calls=%d'
          % (rv.get('result'), len(traffic_calls)))
    if traffic_calls or rv.get('result') == 'ROLLBACK_VERIFIED' or \
            'single' not in json.dumps(rv).lower():
        fails.append('gap7 containerapp single mode: the reversal used a mechanism that is not '
                     'valid for the observed configuration, or claimed verification, or did not '
                     'say why it could not reverse (%r).' % rv.get('result'))
    # App Service: the staged slot fails health; restoring it is verified by reading it back.
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(), W.appservice_state(**bad))
    rv = res['evidence'].get('reversal.json') or {}
    print('  gap7  appservice slot C              result=%s' % rv.get('result'))
    if rv.get('result') != 'ROLLBACK_VERIFIED':
        fails.append('gap7 appservice: restoring the staged slot was not verified (%r).'
                     % rv.get('result'))


# ------------------------------------------------------------------------------ gap 8
@section
def gap8_partial_apply_and_lost_visibility(fails):
    """A run that mutated and then lost track says so; it never reads as 'failed, nothing changed'."""
    bad = {'unhealthy_images': [W.ref(W.NEW)]}
    cases = [
        ('A healthy', W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(), None, 'DEPLOY_HEALTHY'),
        ('B update applied, then errored', W.D.CONTAINERAPP, ca_inputs(),
         W.containerapp_state(apply_then_fail=['containerapp update']), None, 'PARTIAL_APPLY'),
        ('C unhealthy, reversed', W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(**bad), None,
         'ROLLBACK_VERIFIED'),
        ('D reads lost after mutation', W.D.CONTAINERAPP, ca_inputs(),
         W.containerapp_state(fail_after_mutation=['containerapp revision show',
                                                   'containerapp show',
                                                   'containerapp revision list']), None,
         'STATUS_UNTRUSTED'),
        ('cancelled after the mutation', W.D.CONTAINERAPP, ca_inputs(), W.containerapp_state(),
         'Deploy by digest', 'STATUS_UNTRUSTED'),
        ('refused at the gate', W.D.CONTAINERAPP, ca_inputs(routing_result='BLOCKED'),
         W.containerapp_state(), None, 'DEPLOY_REFUSED'),
        ('appservice B container set errored', W.D.APPSERVICE, as_inputs(),
         W.appservice_state(apply_then_fail=['webapp config container']), None, 'PARTIAL_APPLY'),
        ('appservice A slot swapped', W.D.APPSERVICE, as_inputs(), W.appservice_state(), None,
         'DEPLOY_HEALTHY'),
    ]
    for label, wf, inp, st, cancel, want in cases:
        res, _final, _ = W.run_world(wf, inp, st, cancel_after=cancel)
        got = outcome(res).get('deployment_outcome')
        print('  gap8  %-36s outcome=%s' % (label, got))
        if got != want:
            fails.append('gap8 %s: outcome %r, wanted %s.' % (label, got, want))
        if want != 'DEPLOY_HEALTHY' and not res['failed']:
            fails.append('gap8 %s: the job succeeded with outcome %s.' % (label, got))
        if want == 'DEPLOY_HEALTHY' and res['failed']:
            fails.append('gap8 %s: a healthy deploy failed the job.' % label)


# ------------------------------------------------------------------------------ gap 9
@section
def gap9_rollback_capability_before_the_point_of_no_return(fails):
    """rollback_capability is established before the first mutation; production tiers block
    on UNAVAILABLE, lower tiers proceed with the risk recorded."""
    cases = [
        ('containerapp single, prod', W.D.CONTAINERAPP, ca_inputs(environment_tier='prod'),
         W.containerapp_state(mode='Single'), 'UNAVAILABLE', False),
        ('containerapp single, dev', W.D.CONTAINERAPP, ca_inputs(environment_tier='dev'),
         W.containerapp_state(mode='Single'), 'UNAVAILABLE', True),
        ('containerapp multi, prod', W.D.CONTAINERAPP, ca_inputs(environment_tier='prod'),
         W.containerapp_state(), 'AVAILABLE', True),
        ('containerapp empty, uat', W.D.CONTAINERAPP, ca_inputs(environment_tier='uat'),
         W.containerapp_state(empty=True), 'NO_PRIOR_STATE', True),
        ('appservice no rollback, prod', W.D.APPSERVICE,
         as_inputs(environment_tier='prod', rollback_on_failure=False),
         W.appservice_state(), 'UNAVAILABLE', False),
        ('appservice slot, prod', W.D.APPSERVICE, as_inputs(environment_tier='prod'),
         W.appservice_state(), 'AVAILABLE', True),
    ]
    for label, wf, inp, st, want, proceeds in cases:
        res, _final, calls = W.run_world(wf, inp, st)
        cap = (res['evidence'].get('capability.json') or {}).get('rollback_capability')
        muts = mutating_calls(calls)
        print('  gap9  %-32s capability=%s mutations=%d' % (label, cap, len(muts)))
        if cap != want:
            fails.append('gap9 %s: rollback_capability %r, wanted %s -- established before the '
                         'mutation or not at all.' % (label, cap, want))
        if not proceeds and muts:
            fails.append('gap9 %s: a production tier mutated with rollback UNAVAILABLE; governance '
                         'arrived after the point of no return.' % label)
        if proceeds and not muts:
            fails.append('gap9 %s: refused although the capability permits it.' % label)
        if not proceeds and outcome(res).get('deployment_outcome') != 'DEPLOY_REFUSED':
            fails.append('gap9 %s: the refusal is not reported as DEPLOY_REFUSED.' % label)


# ------------------------------------------------------------------------------ L96
SIX = ('progression_blocked', 'why', 'resolution_owner', 'remediation_known',
       'automated_actor_may_proceed', 'next_action')
ESCALATION = ('resolution_owner', 'request_channel', 'request_type', 'required_artefacts',
              'service_level', 'permitted_agent_action')


@section
def l96_six_question_report(fails):
    """The outcome report answers six questions, and a non-autonomous blocker carries an
    escalation contract whose MAY NOT list forbids mutation."""
    bad = {'unhealthy_images': [W.ref(W.NEW)]}
    cases = [
        ('A', ca_inputs(), W.containerapp_state(), False),
        ('C', ca_inputs(), W.containerapp_state(**bad), True),
        ('C partial', ca_inputs(), W.containerapp_state(fail=['containerapp revision deactivate'], **bad), True),
        ('B', ca_inputs(), W.containerapp_state(apply_then_fail=['containerapp update']), True),
        ('refused', ca_inputs(routing_result='DECISION_REQUIRED'), W.containerapp_state(), True),
    ]
    for label, inp, st, blocked in cases:
        res, _f, _ = W.run_world(W.D.CONTAINERAPP, inp, st)
        o = outcome(res)
        q = o.get('six_questions') or {}
        print('  l96   %-10s %-24s blocked=%s owner=%s' % (
            label, o.get('deployment_outcome'), q.get('progression_blocked'),
            q.get('resolution_owner')))
        missing = [k for k in SIX if k not in q or q[k] in (None, '')]
        if missing:
            fails.append('l96 %s: the report does not answer %s.' % (label, missing))
            continue
        if q['progression_blocked'] is not blocked:
            fails.append('l96 %s: progression_blocked=%r, wanted %r.'
                         % (label, q['progression_blocked'], blocked))
        if blocked and q['automated_actor_may_proceed'] is not False:
            fails.append('l96 %s: a blocking outcome lets an automated actor proceed.' % label)
        if 'Is progression blocked?' not in res['summary']:
            fails.append('l96 %s: the six questions are not in the step summary.' % label)
        if blocked and q['automated_actor_may_proceed'] is False:
            esc = o.get('escalation') or {}
            gone = [k for k in ESCALATION if not esc.get(k)]
            may_not = ' '.join((esc.get('permitted_agent_action') or {}).get('may_not') or [])
            if gone or 'mutate' not in may_not or 'approval' not in may_not:
                fails.append('l96 %s: a blocking state no automated actor may resolve has no '
                             'complete escalation contract (missing %s; may_not=%r). Without '
                             'one it is a dead end.' % (label, gone, may_not))


# ------------------------------------------------------------------------------ gap 11
@section
def gap11_deployed_is_not_promoted(fails):
    """Deployment success is not trust progression: a healthy deploy records promotion as a
    separate, evidence-gated claim and names what is missing."""
    res, _f, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(routing_result='PROCEED',
                                                         version_metadata=META),
                             W.containerapp_state())
    o = outcome(res)
    p = o.get('promotion') or {}
    print('  gap11 containerapp A             outcome=%s promotion=%s missing=%d'
          % (o.get('deployment_outcome'), p.get('state'), len(p.get('missing') or [])))
    if o.get('deployment_outcome') != 'DEPLOY_HEALTHY':
        fails.append('gap11: the healthy case did not deploy (%r).' % o.get('deployment_outcome'))
    if not p or p.get('state') != 'not-verified' or not p.get('missing'):
        fails.append('gap11: a healthy deploy did not keep promotion separate, or claimed it '
                     'without the DCR 7.7 conjunction (%r).' % p)
    held = set(p.get('established') or [])
    for need in ('expected artefact observed running', 'intended traffic observed',
                 'state reconciliation complete'):
        if need not in held:
            fails.append('gap11: %r is established by this run and not credited.' % need)
    if 'promotion' not in json.dumps(o.get('six_questions') or {}).lower():
        fails.append('gap11: the next action does not say promotion needs more evidence.')


# ------------------------------------------------------------------------------ live finding
@section
def live_traffic_following_latest_is_pinned(fails):
    """Traffic that FOLLOWS THE LATEST REVISION must be pinned before the update, or the update
    itself moves production to an unverified revision.

    Observed live 2026-10-15 on a sandbox Container App left in the shape `az containerapp
    create` produces ({latestRevision: true, weight: 100}): `az containerapp update --image` --
    the call this workflow's mutate step makes -- routed all public traffic to the new revision
    at once, and the public health path went from 200 to 404 on an unverified image. "Verify the
    intended digest is loaded and healthy (before traffic moves)" did not hold in that shape.
    """
    follow = [{'latestRevision': True, 'weight': 100}]
    bad = {'unhealthy_images': [W.ref(W.NEW)]}
    # C: unhealthy. Production must never have followed the new revision, and the reversal
    # must end where it started without inventing a conflict out of its own pin.
    st = W.containerapp_state(**bad)
    st['containerapp']['traffic'] = list(follow)
    res, final, calls = W.run_world(W.D.CONTAINERAPP, ca_inputs(), st)
    rv = res['evidence'].get('reversal.json') or {}
    disp = [e.get('reversal_disposition') for e in rv.get('entries') or []]
    print('  live  follow-latest, C   exposed=%s result=%s dispositions=%s serving=%s'
          % (final.get('exposed_on_update', False), rv.get('result'), disp,
             [i[-6:] for i in ca_live_images(final)]))
    if final.get('exposed_on_update'):
        fails.append('live follow-latest C: the update ran while traffic followed the latest '
                     'revision, so production served the unverified revision before health.')
    if rv.get('result') != 'ROLLBACK_VERIFIED' or ca_live_images(final) != [W.ref(W.GOOD)]:
        fails.append('live follow-latest C: the reversal did not end verified on the prior image '
                     '(%r, serving %s).' % (rv.get('result'), ca_live_images(final)))
    if 'REVERSAL_REFUSED_CONFLICT' in disp:
        fails.append('live follow-latest C: the run reported a conflict with its own change (%r).'
                     % disp)
    # Live run 38856714492: after the created revision was deactivated, the pin's entry read its
    # ownership stamp from a revision list that no longer showed it, and withheld the restore as
    # UNTRUSTED -- the run's own pin left in place.
    if 'REVERSAL_WITHHELD_UNTRUSTED' in disp:
        fails.append('live follow-latest C: the reversal could not read its own stamp after '
                     'deactivating its revision, and withheld its own pin (%r).' % disp)
    # A: healthy. The pin must not stop the verified revision receiving the traffic.
    st = W.containerapp_state()
    st['containerapp']['traffic'] = list(follow)
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), st)
    out = outcome(res).get('deployment_outcome')
    print('  live  follow-latest, A   exposed=%s outcome=%s serving=%s'
          % (final.get('exposed_on_update', False), out, [i[-6:] for i in ca_live_images(final)]))
    if final.get('exposed_on_update') or out != 'DEPLOY_HEALTHY' or \
            ca_live_images(final) != [W.ref(W.NEW)]:
        fails.append('live follow-latest A: a healthy deploy did not end DEPLOY_HEALTHY on the new '
                     'revision without exposure (%r, %s).' % (out, ca_live_images(final)))
    # Serving fails AFTER the traffic move: two redirections of this run's own are reversed in
    # order, each judged against live state as it stands when its turn comes -- not against a
    # read taken before the first one was undone.
    st = W.containerapp_state(unhealthy_hosts=['web.app.example'])
    st['containerapp']['traffic'] = list(follow)
    res, final, _ = W.run_world(W.D.CONTAINERAPP, ca_inputs(), st)
    rv = res['evidence'].get('reversal.json') or {}
    disp = [e.get('reversal_disposition') for e in rv.get('entries') or []]
    print('  live  follow-latest, serving fails   result=%s dispositions=%s serving=%s'
          % (rv.get('result'), disp, [i[-6:] for i in ca_live_images(final)]))
    if rv.get('result') != 'ROLLBACK_VERIFIED' or 'REVERSAL_REFUSED_CONFLICT' in disp or \
            ca_live_images(final) != [W.ref(W.GOOD)]:
        fails.append('live follow-latest serving-fails: expected a verified reversal with no '
                     'self-conflict, got %r %r serving %s.'
                     % (rv.get('result'), disp, ca_live_images(final)))


@section
def live_appservice_health_is_the_new_container(fails):
    """App Service: a 200 after `config container set` + `restart` can come from the PREVIOUS
    container, which keeps answering until the platform has started the new one.

    Observed live 2026-10-15 (run 38857408542): an image with no /health was deployed direct to
    production; the configured image read back as intended, the probe answered 200 twice, the run
    reported DEPLOY_HEALTHY -- and the platform's own container log shows the new container's site
    starting ~20 s AFTER those probes. Production then served 404. The configured image is not the
    running one, so health must wait for the platform to report a site started from the intended
    image, and must not pass when it never does.
    """
    st = W.appservice_state(container_never_starts=True)
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(slot=''), st)
    h = res['steps'].get('health', {}).get('outcome')
    out = outcome(res).get('deployment_outcome')
    v = res['evidence'].get('verification.json') or {}
    print('  live  appservice, container never starts   health=%s outcome=%s runtime_deployed=%r'
          % (h, out, v.get('runtime_deployed')))
    if h == 'success' or out == 'DEPLOY_HEALTHY':
        fails.append('live appservice: health passed while the platform never started a container '
                     'from the intended image -- the 200 came from the previous container.')
    if v.get('runtime_deployed') is True:
        fails.append('live appservice: runtime_deployed recorded True with no started container.')
    # Live run 38862154970: the deploy identity could not read the container log, and the run
    # said only "log unreadable". Unreadable must stay unknown (never a pass) AND name its reason,
    # or nobody can restore the ability to observe.
    st = W.appservice_state(fail=['rest'])
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(slot=''), st)
    v = res['evidence'].get('verification.json') or {}
    named = 'injected failure' in str(v.get('reason', '')) and 'injected failure' in res['log']
    print('  live  appservice, container log unreadable  runtime_deployed=%r reason named=%s'
          % (v.get('runtime_deployed'), named))
    if v.get('runtime_deployed') is not None or not named:
        fails.append('live appservice: an unreadable container log must record runtime_deployed '
                     'unknown and name the read error (%r).' % v)
    # Live run 38867771912 (F1 plan): an idle site starts its container only when a request
    # arrives, and the gate waited for a start it never provoked -- a healthy deploy to an idle
    # site could never pass. The gate may wake the site; the wake-up answer is not evidence.
    st = W.appservice_state(start_on_request=True)
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(slot=''), st)
    out = outcome(res).get('deployment_outcome')
    print('  live  appservice, idle site starts on request  outcome=%s' % out)
    if out != 'DEPLOY_HEALTHY':
        fails.append('live appservice: a healthy image on an idle site never started because the '
                     'gate never sent it a request (%r).' % out)
    # The ordinary healthy path still ends healthy: the platform reports the start.
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(slot=''), W.appservice_state())
    out = outcome(res).get('deployment_outcome')
    print('  live  appservice, container starts         outcome=%s' % out)
    if out != 'DEPLOY_HEALTHY':
        fails.append('live appservice: a started healthy container did not end DEPLOY_HEALTHY (%r).'
                     % out)


OTHER = 'registry.example/other@sha256:' + 'f' * 64


def digest_of(image):
    return image.split('@')[-1]


@section
def live_appservice_refused_reversal_is_not_verified(fails):
    """A reversal that was REFUSED is never summarised as verified, and "now serves" is read live.

    Observed live 2026-10-16 (run 38879879589, direct path, slot ''): the run set production to
    an unhealthy image; while it probed, a second actor set production to another image. The
    reversal rightly refused (REVERSAL_REFUSED_CONFLICT, performed=False, MODIFIED_BY_EXTERNAL_
    ACTOR) -- and the run then printed "ROLLBACK_TO_PRIOR, verified: live state matches the
    pre-change snapshot", reported ROLLBACK_VERIFIED, and said production "now serves" the image
    THIS RUN set, echoed from its inputs. There the second actor's image happened to equal the
    prior one, so the snapshot comparison was coincidentally true; a refused reversal is not a
    verified rollback whatever live state happens to equal. Both shapes are run: the actor's
    image differs from the prior, and the actor's image IS the prior.
    """
    for label, actor in (('actor image is not the prior', OTHER),
                         ('actor image equals the prior', W.ref(W.GOOD))):
        st = W.appservice_state(unhealthy_images=[W.ref(W.NEW)],
                                second_actor={'after': 'curl', 'do': 'modify_slot_image',
                                              'slot': 'production', 'image': actor,
                                              'restart': True})
        res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(slot='', health_retries=1), st)
        rv = res['evidence'].get('reversal.json') or {}
        ents = rv.get('entries') or []
        o = outcome(res)
        prod = final['webapp']['slots']['production']['linuxFxVersion']
        print('  live  appservice, %-30s dispositions=%s result=%s outcome=%s'
              % (label, [(e.get('reversal_disposition'), e.get('performed')) for e in ents],
                 rv.get('result'), o.get('deployment_outcome')))
        refused = [e for e in ents if e.get('reversal_disposition') == 'REVERSAL_REFUSED_CONFLICT'
                   and e.get('performed') is False]
        if not refused or prod != 'DOCKER|' + actor:
            fails.append('live refused (%s): the scenario was not reproduced -- no refused entry, or '
                         'the reversal overwrote the other actor (production %s).'
                         % (label, prod[-12:]))
            continue
        if rv.get('result') == 'ROLLBACK_VERIFIED' or o.get('deployment_outcome') == 'ROLLBACK_VERIFIED':
            fails.append('live refused (%s): a reversal that was REFUSED (performed=False) was '
                         'reported ROLLBACK_VERIFIED (reversal %r, outcome %r).'
                         % (label, rv.get('result'), o.get('deployment_outcome')))
        if o.get('deployment_outcome') != 'ROLLBACK_PARTIAL':
            fails.append('live refused (%s): DCR 8.2 -- a refused conflict is ROLLBACK_PARTIAL at '
                         'minimum; got %r.' % (label, o.get('deployment_outcome')))
        if 'ROLLBACK_VERIFIED' in str(o.get('why')) or re.search(
                r'verified: live state matches', res['log']):
            fails.append('live refused (%s): the run still SAYS the rollback was verified '
                         '(why %r).' % (label, o.get('why')))
        if 'production' not in str(o.get('why')) or 'REFUSED' not in str(o.get('why')):
            fails.append('live refused (%s): the outcome does not name the refused object and its '
                         'disposition (why %r).' % (label, o.get('why')))
        # (b) Every line that tells the reader what production serves names what LIVE state
        # holds -- the other actor's image -- and never presents this run's image as serving.
        said = [ln for ln in (res['log'] + '\n' + res['summary']).splitlines()
                if ln.startswith(('::error', '::warning')) and 'production' in ln.lower()
                and 'unhealthy' in ln.lower()]
        if not said:
            fails.append('live refused (%s): the direct path printed no production message.' % label)
        for ln in said:
            if digest_of(actor) not in ln or re.search(r'now serves \S*' + re.escape(W.NEW), ln):
                fails.append('live refused (%s): the production message does not report what live '
                             'state holds (%s); it said: %s' % (label, digest_of(actor)[:15], ln[:300]))
        now = ' '.join(r[2] for r in report_rows(res['summary']) if r[0] == 'NOW SERVING')
        if digest_of(actor) not in now or W.NEW in now:
            fails.append('live refused (%s): NOW SERVING (%s) is not the other actor\'s image.'
                         % (label, now[:200]))


def appservice_now_rows(res):
    return [(r[1], r[2].strip('`')) for r in report_rows(res['summary']) if r[0] == 'NOW SERVING']


@section
def live_appservice_configured_is_not_running(fails):
    """App Service: the configured image (linuxFxVersion) is not the running container.

    The report's NOW SERVING row and the reversal's verification both read the CONFIGURED image
    and presented it unqualified. The kit already reads the platform's own record of which
    container it started (the started-container gate); every App Service NOW SERVING row must
    name which of the two it is, the start-record row must come from that record, and a
    reversal verified on configuration must say it compared configuration.
    """
    # The restored container is configured and never reports a start.
    st = W.appservice_state(unhealthy_images=[W.ref(W.NEW)], container_never_starts=True)
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(slot=''), st)
    rows = appservice_now_rows(res)
    rv = res['evidence'].get('reversal.json') or {}
    print('  live  appservice, restored, never started  rows=%s result=%s'
          % ([(f, v[-12:]) for f, v in rows], rv.get('result')))
    unlabelled = [f for f, _v in rows if 'configured' not in f and 'start' not in f]
    if not rows or unlabelled:
        fails.append('live configured: NOW SERVING row(s) %s do not say whether they read the '
                     'CONFIGURED image or the platform\'s container start record.' % unlabelled)
    conf = [v for f, v in rows if 'configured' in f]
    start = [v for f, v in rows if 'start' in f]
    if conf != [W.ref(W.GOOD)]:
        fails.append('live configured: the configured row does not show the restored image (%s).'
                     % conf)
    if not start:
        fails.append('live configured: no NOW SERVING row reads the platform\'s container start '
                     'record, which the kit already reads for its health gate.')
    elif start[0].startswith(W.ref(W.GOOD)) or start[0].startswith(W.ref(W.NEW)):
        fails.append('live configured: the start-record row claims %s started, but the platform '
                     'never reported a start.' % start[0][:80])
    ver = rv.get('verification') or {}
    said = [ln for ln in res['log'].splitlines() if 'verified:' in ln]
    if 'configured' not in str(ver.get('compared', '')) or any('configured' not in ln for ln in said):
        fails.append('live configured: the reversal verification does not say it compared the '
                     'CONFIGURED image (compared=%r; said %s).' % (ver.get('compared'), said))
    # Healthy: the start record shows the intended image started, labelled as such.
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(slot=''), W.appservice_state())
    rows = appservice_now_rows(res)
    start = [v for f, v in rows if 'start' in f]
    print('  live  appservice, healthy                  rows=%s' % [(f, v[-12:]) for f, v in rows])
    if not start or not start[0].startswith(W.ref(W.NEW)):
        fails.append('live configured: on a healthy deploy the start-record row does not show the '
                     'intended image started (%s).' % start)


@section
def live_appservice_reversal_reads_each_entry_fresh(fails):
    """App Service: each reversal entry is judged against live state AS IT STANDS WHEN ITS TURN
    COMES. One read taken before acting on any entry judged the slot entry against the state
    before the swap-back -- after a swap whose consumer check fails, the slot holds the PRIOR
    image (swapped out of production) until the swap-back returns ours to it, so the run called
    its own slot change a conflict with an external actor and left it in place. The Container
    Apps reversal already re-reads per entry; this mirrors it.
    """
    st = W.appservice_state(unhealthy_hosts=['web.site.example'])
    res, final, _ = W.run_world(W.D.APPSERVICE, as_inputs(), st)
    rv = res['evidence'].get('reversal.json') or {}
    disp = [(e.get('object'), e.get('reversal_disposition')) for e in rv.get('entries') or []]
    slots = final['webapp']['slots']
    images = {n: s['linuxFxVersion'][-6:] for n, s in slots.items()}
    print('  live  appservice, swap then serving fails  dispositions=%s result=%s slots=%s'
          % (disp, rv.get('result'), images))
    if not disp:
        fails.append('live fresh-read: no reversal ran after the consumer check failed.')
    if any(d == 'REVERSAL_REFUSED_CONFLICT' for _o, d in disp):
        fails.append('live fresh-read: the run judged an entry against a read taken before its own '
                     'swap-back and reported a conflict with itself (%r).' % disp)
    if rv.get('result') != 'ROLLBACK_VERIFIED' or any(
            s['linuxFxVersion'] != 'DOCKER|' + W.ref(W.GOOD) for s in slots.values()):
        fails.append('live fresh-read: expected a verified reversal with both slots back on the '
                     'prior image, got %r with %s.' % (rv.get('result'), images))


# ------------------------------------------------------------------------------ run record
@section
def record_evidence_survives_the_run(fails):
    """The manifest and snapshot ARE the run record; they must outlive the runner."""
    for wf in W.D.deploy_workflows:
        steps = W.D.steps(W.D.load(wf))
        ups = [s for s in steps if 'actions/upload-artifact' in str(s.get('uses', ''))]
        ok = any('always()' in str(s.get('if', '')) and
                 'deploy-evidence' in str((s.get('with') or {}).get('path', '')) for s in ups)
        rep = [i for i, s in enumerate(steps) if s.get('name') == 'Reconcile and report outcome']
        after = ups and rep and steps.index(ups[-1]) > rep[0]
        print('  record %-34s evidence uploaded always, after the report: %s'
              % (os.path.basename(wf), bool(ok and after)))
        if not (ok and after):
            fails.append('record %s: deploy-evidence (manifest, snapshot, reversal, outcome) is '
                         'not uploaded on every path after the report; it dies with the runner.'
                         % os.path.basename(wf))


def main(argv):
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if not W.D.bash()[0]:
        print('UNKNOWN: no usable bash.')
        return 2
    want = [a for a in argv if not a.startswith('-')]
    fails = []
    for fn in SECTIONS:
        if want and not any(fn.__name__.startswith(w) for w in want):
            continue
        fn(fails)
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: %d section(s). STUBBED CLOUD: the live acceptance run (DCR 7.8) is owed.'
          % len([f for f in SECTIONS if not want or any(f.__name__.startswith(w) for w in want)]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
