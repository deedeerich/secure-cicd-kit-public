#!/usr/bin/env python3
"""TICKET NUMBERS, FIX AVAILABILITY, THEIR SOURCES, AND THE PROD ESCALATION ROUTE (KREQ-590, 676, 674, 706).

Owner 2026-11-13 (KDEC-052 item 7) accepted the neutral defaults: deadlines 7/30/180/365, grace 0/7/14/14,
stall 90, no-fix re-check 30, instance threshold 25, creation ceiling 25 -- governed, overridable by the org,
the repository and the environment, never silently exceeded -- and an escalation that is refused at prod when
its target is a placeholder.

    S1  the register template carries exactly the kit defaults (one table, not two)
    S2  no register: every number is the kit default, recorded as level kit_default
    S3  org < repo < environment < variable: each value used is recorded with its level and source
    S4  NEGATIVE: a narrower level that RAISES a governed number is refused (TICKET_SETTING_ABOVE_GOVERNED), an
        invalid one TICKET_SETTING_INVALID; the governed value stands
    S5  the reconciler's run record carries ticket_settings (every value, level, source, refusal) -- through the CLI
    S6  the creation ceiling: past it, obligations are carried and the overflow is NAMED and ESCALATED
        (TICKET_CEILING_OVERFLOW in needs_decision, exit 1); under it, nothing is
    S7  the instance threshold: past it, the overflow is named (count kept), not escalated
    S8  the fix-availability writer: FIX_AVAILABLE from a scanner's fixed-in version, dated; none reported is
        FIX_AVAILABILITY_NOT_ESTABLISHED, never NO_FIX_AVAILABLE; a person's value is never overwritten;
        scan_report reads the fixed-in version from SARIF properties and Trivy's message
    S9  the SLA deadline uses the default table (HIGH +30 days)
    S10 KREQ-706: at prod a missing or placeholder escalation channel/service level is REFUSED (no stand-in);
        configured is used; below prod the placeholder is used and named; the org overlay validates the shape
    Mutants MT1-MT5, each caught at its own claim.

USAGE: python3 tests/prove_ticket_defaults.py   (no network; exit 0 PASS, 1 FAIL)
"""
import inspect
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import deploy_contract as DC     # noqa: E402
import org_settings as OS        # noqa: E402
import reconcile_tickets as RT   # noqa: E402
import remediation_sla as RS     # noqa: E402
import scan_report as SR         # noqa: E402
import ticket_settings as TS     # noqa: E402

OWNER_TABLE = {'sla_period_days': {'CRITICAL': 7, 'HIGH': 30, 'MEDIUM': 180, 'LOW': 365},
               'breach_grace_days': {'CRITICAL': 0, 'HIGH': 7, 'MEDIUM': 14, 'LOW': 14},
               'track_stall_period_days': 90, 'no_fix_recheck_days': 30,
               'ticket_instance_threshold': 25, 'ticket_create_ceiling': 25}


def _rec(name, line=1, sev='high', fixed=None, scanner='trivy'):
    r = RT._rec(scanner, 'CVE-%s' % name, '%s/go.mod' % name, 'id-%s' % name, aliases=['cve-%s' % name.lower()],
                severity=sev, line=line)
    if fixed is not None:
        r['fixed_version'] = fixed
    return r


def _quiet(fn, *a, **k):
    import contextlib
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **k)


def lvl(settings, name):
    return [(r['value'], r['level']) for r in settings['record'] if r['setting'] == name]


def claims(work):
    out = []

    def c(label, ok, detail=''):
        out.append((label, bool(ok), detail))

    # S1
    tpl = json.load(io.open(os.path.join(ROOT, 'templates', 'policy-register.central.example.json'), encoding='utf-8'))
    c('S1 the register template numbers are the owner table and the kit defaults',
      tpl.get('numbers') == OWNER_TABLE == TS.kit_defaults, tpl.get('numbers'))

    # S2
    s = TS.resolve(None, None, '', {})
    c('S2 no register: every number is the kit default, recorded kit_default (12 values)',
      s['numbers'] == OWNER_TABLE and len(s['record']) == 12 and {r['level'] for r in s['record']} == {'kit_default'}
      and not s['refused'], s['record'][:2])

    # S3
    central = {'numbers': {'ticket_create_ceiling': 40, 'sla_period_days': {'HIGH': 20}},
               'environment_numbers': {'prod-tickets': {'ticket_create_ceiling': 12}}}
    repo = {'numbers': {'ticket_create_ceiling': 30, 'sla_period_days': {'HIGH': 14}},
            'environment_numbers': {'prod-tickets': {'sla_period_days': {'HIGH': 10}}}}
    s = TS.resolve(central, repo, 'prod-tickets', {'TICKET_INSTANCE_THRESHOLD': '9'})
    c('S3 each value carries its level: ceiling 12 environment, HIGH 10 environment, threshold 9 variable, '
      'CRITICAL 7 kit_default',
      lvl(s, 'ticket_create_ceiling') == [(12, 'environment')] and lvl(s, 'sla_period_days.HIGH') == [(10, 'environment')]
      and lvl(s, 'ticket_instance_threshold') == [(9, 'variable')] and
      lvl(s, 'sla_period_days.CRITICAL') == [(7, 'kit_default')] and not s['refused'], s['record'])
    s = TS.resolve(central, repo, '', {})
    c('S3 without the environment: ceiling 30 from the repo, HIGH 14 from the repo, governed 40 / 20 by the org',
      lvl(s, 'ticket_create_ceiling') == [(30, 'repo')] and lvl(s, 'sla_period_days.HIGH') == [(14, 'repo')] and
      [r['governed'] for r in s['record'] if r['setting'] == 'ticket_create_ceiling'] == [40], s['record'])

    # S4
    s = TS.resolve({'numbers': {'sla_period_days': {'HIGH': 30}}}, {'numbers': {'sla_period_days': {'HIGH': 60}}}, '',
                   {'TICKET_CREATE_CEILING': '100'})
    ref = {(r['setting'], r['level'], r['state']) for r in s['refused']}
    c('S4 a repository that LOOSENS the HIGH deadline and a variable that raises the ceiling are refused by name; the '
      'governed values stand',
      ('sla_period_days.HIGH', 'repo', TS.TICKET_SETTING_ABOVE_GOVERNED) in ref and
      ('ticket_create_ceiling', 'variable', TS.TICKET_SETTING_ABOVE_GOVERNED) in ref and
      s['numbers']['sla_period_days']['HIGH'] == 30 and s['numbers']['ticket_create_ceiling'] == 25 and
      lvl(s, 'sla_period_days.HIGH') == [(30, 'org')], s['refused'])
    s = TS.resolve(None, {'numbers': {'ticket_create_ceiling': 0, 'no_fix_recheck_days': 'abc'}}, '', {})
    c('S4 an invalid value (ceiling 0, a word) is TICKET_SETTING_INVALID; the default stands',
      {(r['setting'], r['state']) for r in s['refused']} == {('ticket_create_ceiling', TS.TICKET_SETTING_INVALID),
                                                           ('no_fix_recheck_days', TS.TICKET_SETTING_INVALID)}
      and s['numbers']['ticket_create_ceiling'] == 25, s['refused'])

    # S5 the run record, through the CLI
    cpath, rpath = os.path.join(work, 'central.json'), os.path.join(work, 'repo.json')
    io.open(cpath, 'w', encoding='utf-8').write(json.dumps({'numbers': {'ticket_create_ceiling': 20}}))
    io.open(rpath, 'w', encoding='utf-8').write(json.dumps({'numbers': {'ticket_create_ceiling': 50},
                                                            'environment_numbers': {'tix': {'track_stall_period_days': 60}}}))
    fpath, record = os.path.join(work, 'findings.json'), os.path.join(work, 'record.json')
    io.open(fpath, 'w', encoding='utf-8').write(json.dumps([_rec('S5')]))
    env = dict((k, v) for k, v in os.environ.items() if not k.startswith(('TICKET_', 'JIRA_', 'AZDO_', 'GH_', 'GITHUB_',
                                                                           'FRESHSERVICE_')))
    env.update(TICKET_SETTINGS_ENVIRONMENT='tix', TICKET_INSTANCE_THRESHOLD='4')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'reconcile_tickets.py'), '--findings', fpath,
                        '--ledger', os.path.join(work, 'ledger.json'), '--registration', rpath,
                        '--central-registration', cpath, '--record', record, '--out', os.path.join(work, 'sum.md'),
                        '--today', '2026-11-13'], env=env, capture_output=True, text=True, cwd=work)
    rec = json.load(io.open(record, encoding='utf-8')) if os.path.exists(record) else {}
    ts = rec.get('ticket_settings') or {}
    got = dict((r['setting'], (r['value'], r['level'])) for r in ts.get('record') or [])
    c('S5 the run record names each value and its level: ceiling 20 org (the repo raise refused), stall 60 '
      'environment, threshold 4 variable, LOW 365 kit_default',
      got.get('ticket_create_ceiling') == (20, 'org') and got.get('track_stall_period_days') == (60, 'environment')
      and got.get('ticket_instance_threshold') == (4, 'variable') and got.get('sla_period_days.LOW') == (365, 'kit_default')
      and ts.get('environment') == 'tix' and
      [(r['setting'], r['state']) for r in ts.get('refused') or []] == [('ticket_create_ceiling',
                                                                         TS.TICKET_SETTING_ABOVE_GOVERNED)],
      (p.returncode, p.stderr[-400:], ts))
    summ = io.open(os.path.join(work, 'sum.md'), encoding='utf-8').read() if os.path.exists(os.path.join(work, 'sum.md')) else ''
    c('S5 the summary shows the refusal by name', TS.TICKET_SETTING_ABOVE_GOVERNED in summ, summ[-600:])

    # S6 creation ceiling overflow
    def run_cap(n):
        be = RT.RecordingBackend()
        be.create_ceiling = TS.resolve(None, {'numbers': {'ticket_create_ceiling': 2}}, '', {})['numbers']['ticket_create_ceiling']
        appr = RT.tm.Approval(actor='platform-security', reason='proof')
        recs = [_rec('C%d' % i, sev=('critical', 'high', 'low')[i % 3]) for i in range(n)]
        return _quiet(RT.reconcile, *_quiet(RT.build_clusters, recs), backend=be, ledger={}, apply_changes=True,
                      approval=appr, today='2026-11-13')
    r = run_cap(3)
    nd = [d for d in r.get('needs_decision') or [] if d.get('outcome') == RT.TICKET_CEILING_OVERFLOW]
    c('S6 past the ceiling (2 of 3): one carried, the overflow NAMED (%s) and ESCALATED (needs_decision, exit 1)'
      % RT.TICKET_CEILING_OVERFLOW,
      len(r.get('carried') or []) == 1 and [o['state'] for o in r.get('ceiling_overflow') or []] ==
      [RT.TICKET_CEILING_OVERFLOW] and len(nd) == 1 and RT.exit_code(r) == 1 and
      RT.TICKET_CEILING_OVERFLOW in RT.render_summary(r), (r.get('carried'), r.get('ceiling_overflow'), nd))
    r = run_cap(2)
    c('S6 at the ceiling (2 of 2): nothing carried, no overflow, nothing escalated',
      not r.get('carried') and not r.get('ceiling_overflow') and
      not [d for d in r.get('needs_decision') or [] if d.get('outcome') == RT.TICKET_CEILING_OVERFLOW],
      r.get('ceiling_overflow'))

    # S7 instance threshold overflow: named, not escalated
    be = RT.RecordingBackend()
    be.instance_threshold = 2
    be.create_instance = lambda parent, m, body, title: ('i-%s' % m['identity'], 'ok')
    recs = [RT._rec(sc, 'CVE-I7', 'go.mod', 'id-i7%s' % sc[0], aliases=['cve-i7']) for sc in ('trivy', 'grype', 'osv')]
    led = {}
    r = _quiet(RT.reconcile, *_quiet(RT.build_clusters, recs), backend=be, ledger=led, apply_changes=True,
               approval=RT.tm.Approval(actor='platform-security', reason='proof'), today='2026-11-13')
    ov = r.get('ceiling_overflow') or []
    c('S7 three instances over a threshold of 2: the overflow is named (over by 1), the count kept, not escalated',
      [(o['setting'], o['over_by']) for o in ov] == [('ticket_instance_threshold', 1)] and
      not [d for d in r.get('needs_decision') or [] if d.get('outcome') == RT.TICKET_CEILING_OVERFLOW] and
      any((e.get('instances_not_itemised') == 1) for e in led.values()), (ov, led))

    # S8 fix availability
    cl = _quiet(RT.build_clusters, [_rec('F1', fixed='1.4.2'), _rec('F1', fixed='', scanner='grype')])[0][0]
    e = RT.write_fix_availability({}, cl, '2026-11-13')
    c('S8 a scanner fixed-in version establishes FIX_AVAILABLE, dated, with the basis',
      e.get('fix_availability') == RS.FIX_AVAILABLE and e.get('fix_availability_established_on') == '2026-11-13' and
      '1.4.2' in e.get('fix_availability_basis', ''), e)
    ts_ = RS.track_state(dict(e, effective_severity='HIGH', sla_deadline='2026-12-13'), [], OWNER_TABLE, '2026-11-20', 'walk')
    c('S8 remediation_sla admits the track on the written value', ts_['state'] == RS.ON_TRACK, ts_)
    cl0 = _quiet(RT.build_clusters, [_rec('F2', fixed='')])[0][0]
    e0 = RT.write_fix_availability({}, cl0, '2026-11-13')
    c('S8 no fixed-in version reported: FIX_AVAILABILITY_NOT_ESTABLISHED, never NO_FIX_AVAILABLE',
      e0.get('fix_availability') == RS.FIX_AVAILABILITY_NOT_ESTABLISHED and 'fix_availability_established_on' not in e0, e0)
    person = {'fix_availability': RS.NO_FIX_AVAILABLE, 'fix_availability_established_on': '2026-11-01'}
    RT.write_fix_availability(person, cl, '2026-11-13')
    c('S8 a value a person established is never overwritten by the writer',
      person == {'fix_availability': RS.NO_FIX_AVAILABLE, 'fix_availability_established_on': '2026-11-01'}, person)
    c('S8 scan_report reads the fixed-in version from properties and from Trivy\'s message; none is empty',
      SR.fixed_version_of({'properties': {'fixedVersion': '2.0.1'}}) == '2.0.1' and
      SR.fixed_version_of({'message': {'text': 'Package: x\nInstalled Version: 1.0\nFixed Version: 1.0.9\nLink: y'}}) == '1.0.9'
      and SR.fixed_version_of({'message': {'text': 'no fix line'}}) == '', '')
    led8 = {}
    _quiet(RT.reconcile, *_quiet(RT.build_clusters, [_rec('F3', fixed='3.3.3')]), backend=RT.RecordingBackend(),
           ledger=led8, apply_changes=True, approval=RT.tm.Approval(actor='platform-security', reason='proof'),
           today='2026-11-13')
    c('S8 the reconciler writes it into the ticket ledger on creation',
      [(v.get('fix_availability'), v.get('fix_availability_established_on')) for v in led8.values()] ==
      [(RS.FIX_AVAILABLE, '2026-11-13')], led8)

    # S9 SLA from the default table
    sla = RT.sla_for('high', OWNER_TABLE, '2026-11-13', None, '2026-11-13')
    c('S9 a HIGH finding first seen 2026-11-13 is due 2026-12-13 under the default table',
      (sla or {}).get('deadline') == '2026-12-13', sla)

    # S10 escalation (KREQ-706)
    conf = {'escalation': {'owner_role': 'platform on-call', 'channel': 'SEC queue, highest priority',
                           'service_level': 'same business day'}}
    _q, esc = DC.six_questions('MANUAL_RECOVERY_REQUIRED', 'x', {}, 'prod')
    c('S10 prod with no escalation route: REFUSED, no stand-in channel or service level',
      esc['route_state'] == DC.ESCALATION_ROUTE_REFUSED and esc['request_channel'] is None and esc['service_level'] is None,
      esc)
    ph = {'escalation': {'channel': DC.escalation_placeholder_channel, 'service_level': '<set me>'}}
    _q, esc = DC.six_questions('PARTIAL_APPLY', 'x', ph, 'prod')
    c('S10 prod with placeholder strings: REFUSED', esc['route_state'] == DC.ESCALATION_ROUTE_REFUSED, esc)
    _q, esc = DC.six_questions('PARTIAL_APPLY', 'x', conf, 'prod')
    c('S10 prod with a configured route: used', esc['route_state'] == DC.ESCALATION_ROUTE_CONFIGURED and
      esc['request_channel'] == 'SEC queue, highest priority' and esc['service_level'] == 'same business day', esc)
    _q, esc = DC.six_questions('PARTIAL_APPLY', 'x', {}, 'uat')
    c('S10 below prod the placeholder is used and NAMED', esc['route_state'] == DC.ESCALATION_ROUTE_PLACEHOLDER and
      esc['service_level'] == DC.escalation_placeholder_service_level, esc)
    base = {'schema': OS.SCHEMA, 'github_orgs': ['example-org']}
    bad = OS.problems(dict(base, escalation={'channel': 3}))
    good = OS.problems(dict(base, escalation=conf['escalation']))
    c('S10 the org overlay accepts the escalation route and refuses a malformed one',
      any('escalation' in x for x in bad) and not good, (bad, good))
    return out


def failing(work, prefix):
    return [x for x in claims(work) if x[0].startswith(prefix) and not x[1]]


def swap_function(mod, name, old, new):
    """Recompile ONE function of `mod` with one change, in the module's own namespace. -> undo."""
    fn = getattr(mod, name)
    src = inspect.getsource(fn)
    if src.count(old) != 1:
        raise SystemExit('mutant anchor not in %s.%s exactly once: %r' % (mod.__name__, name, old))
    ns = {}
    exec(compile(src.replace(old, new), mod.__file__ + ' (mutant)', 'exec'), mod.__dict__, ns)
    setattr(mod, name, ns[name])
    return lambda: setattr(mod, name, fn)


MUTANTS = [
    ('MT1 a narrower level may raise a governed number', 'S4 ',
     lambda: swap_function(TS, 'resolve', 'elif v > governed:', 'elif False:')),
    ('MT2 the record loses the level a value came from', 'S3 ',
     lambda: swap_function(TS, 'resolve', "'value': value, 'level': level,", "'value': value, 'level': 'kit_default',")),
    ('MT3 the creation-ceiling overflow is not escalated', 'S6 ',
     lambda: swap_function(RT, 'ceiling_overflow', 'if escalate and', 'if False and')),
    ('MT4 no fixed-in version is written as NO_FIX_AVAILABLE', 'S8 ',
     lambda: swap_function(RT, 'write_fix_availability', "entry['fix_availability'] = FIX_AVAILABILITY_NOT_ESTABLISHED",
                           "entry['fix_availability'] = 'NO_FIX_AVAILABLE'")),
    ('MT5 prod uses the placeholder escalation route', 'S10 ',
     lambda: swap_function(DC, 'escalation_route', "if tier == 'prod':", "if tier == 'never':")),
]


def main():
    fails = []
    work = tempfile.mkdtemp(prefix='kit-ticket-defaults-')
    try:
        for label, ok, detail in claims(work):
            print('  %s %s' % ('ok  ' if ok else 'FAIL', label))
            if not ok:
                fails.append('%s -- %s' % (label, json.dumps(detail, default=str)[:700]))
        for label, prefix, apply in MUTANTS:
            undo = apply()
            try:
                got = failing(work, prefix)
            except Exception as exc:                   # noqa: BLE001 - a crash is not a catch
                got = []
                print('  mutant %s crashed: %s: %s' % (label, type(exc).__name__, exc))
            finally:
                undo()
            print('  mutant %-52s %s' % (label, ('caught at %s' % got[0][0][:70]) if got else 'NOT CAUGHT'))
            if not got:
                fails.append('mutant %s was not caught at %s' % (label, prefix))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if fails:
        for f in fails:
            print('FAIL: %s' % f)
        print('::error title=Ticket defaults unproven::%d failure(s)' % len(fails))
        return 1
    print('PASS: the owner\'s defaults are the template and the kit default; every value used is recorded with its '
          'level; a raise below the org is refused; overflow is named and escalated; fix availability is written '
          'from scanner data; prod refuses a placeholder escalation route; every mutant is caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
