#!/usr/bin/env python3
"""THE TICKETING NUMBERS, THEIR DEFAULTS, AND WHERE EACH ONE CAME FROM (KREQ-590, 676, 674; KDEC-052 item 7).

    The owner accepted neutral defaults on 2026-11-13 (KDEC-052 item 7): fix deadlines 7/30/180/365 days
    (critical/high/medium/low), breach grace 0/7/14/14 days, a track stalls after 90 days without a verified
    closure, "no fix exists" is re-established every 30 days, at most 25 instances are itemised under one
    ticket, and at most 25 tickets are created per run. Every one stays configuration.

PRECEDENCE AND GOVERNANCE (owner ruling 2026-11-07: governed values come from the org; a repository may only
tighten them; GitHub's own order is environment > repository > organization)

    kit_default  <  org (the central register's `numbers`)  <  repo (the repository register's `numbers`)
                 <  environment (`environment_numbers.<environment>` in the central, then the repository register)
                 <  variable (TICKET_INSTANCE_THRESHOLD / TICKET_CREATE_CEILING; GitHub has already resolved its
                    own environment > repository > organization order, so the run names the variable, not a level)

    The GOVERNED value is the org's when it sets one, else the kit default. Any narrower level may LOWER a
    number (a shorter deadline, a smaller ceiling) and may never raise it above the governed value: a raise is
    refused by name (TICKET_SETTING_ABOVE_GOVERNED) and the governed value stands -- never silently exceeded.
    A value that is not a whole number in range is refused (TICKET_SETTING_INVALID) the same way.

THE RECORD (KREQ-674's condition): `resolve()` returns, for every number the run used, its value, the level it
came from and the file or variable that supplied it, plus every refusal. The reconciler writes it into the run
record (`ticket_settings`) and the summary, so a shadowed or refused value is visible, never inferred.

USAGE
    import ticket_settings as ts; ts.resolve(central_doc, repo_doc, environment, os.environ)
    python3 scripts/ticket_settings.py --self-test
"""
import copy
import sys

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

# KDEC-052 item 7 (owner, 2026-11-13). templates/policy-register.central.example.json carries the same block;
# tests/prove_ticket_defaults.py fails when the two differ.
kit_defaults = {
    'sla_period_days': {'CRITICAL': 7, 'HIGH': 30, 'MEDIUM': 180, 'LOW': 365},
    'breach_grace_days': {'CRITICAL': 0, 'HIGH': 7, 'MEDIUM': 14, 'LOW': 14},
    'track_stall_period_days': 90,
    'no_fix_recheck_days': 30,
    'ticket_instance_threshold': 25,
    'ticket_create_ceiling': 25,
}
# The smallest value each number may take: a creation ceiling of 0 would carry every obligation forever.
MINIMUM = {'ticket_create_ceiling': 1}
VARIABLES = {'ticket_instance_threshold': 'TICKET_INSTANCE_THRESHOLD', 'ticket_create_ceiling': 'TICKET_CREATE_CEILING'}

TICKET_SETTING_ABOVE_GOVERNED = 'TICKET_SETTING_ABOVE_GOVERNED'
TICKET_SETTING_INVALID = 'TICKET_SETTING_INVALID'

LEVELS = ('kit_default', 'org', 'repo', 'environment', 'variable')


def _paths():
    for k, v in kit_defaults.items():
        if isinstance(v, dict):
            for s in SEVERITIES:
                yield (k, s)
        else:
            yield (k,)


def _get(doc, path):
    cur = doc
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return None, False
        cur = cur[p]
    return cur, True


def _as_number(v, minimum):
    if isinstance(v, bool):
        return None
    if isinstance(v, str) and v.strip().isdigit():
        v = int(v.strip())
    if isinstance(v, int) and v >= minimum:
        return v
    return None


def layers(central, repo, environment, env):
    """-> [(level, source, numbers-dict)] in precedence order, lowest first."""
    out = [('kit_default', 'scripts/ticket_settings.py kit_defaults', kit_defaults)]
    c, r = (central or {}), (repo or {})
    if isinstance(c.get('numbers'), dict):
        out.append(('org', 'central register numbers', c['numbers']))
    if isinstance(r.get('numbers'), dict):
        out.append(('repo', 'repository register numbers', r['numbers']))
    if environment:
        for label, doc in (('central', c), ('repository', r)):
            en = (doc.get('environment_numbers') or {}) if isinstance(doc.get('environment_numbers'), dict) else {}
            if isinstance(en.get(environment), dict):
                out.append(('environment', '%s register environment_numbers.%s' % (label, environment),
                            en[environment]))
    var = {}
    for key, name in VARIABLES.items():
        raw = ((env or {}).get(name) or '').strip()
        if raw:
            var[key] = raw
    if var:
        out.append(('variable', 'GitHub variable(s) %s (GitHub resolved environment > repository > organization '
                                'before the run; the run cannot see which)' %
                    ', '.join(VARIABLES[k] for k in sorted(var)), var))
    return out


def resolve(central, repo, environment='', env=None):
    """-> {'numbers': the numbers the run uses, 'record': [{setting, value, level, source, governed}],
    'refused': [{setting, level, source, value, state, governed, why}], 'environment': environment}."""
    numbers = copy.deepcopy(kit_defaults)
    record, refused = [], []
    lays = layers(central, repo, environment, env)
    for path in _paths():
        name = '.'.join(path)
        minimum = MINIMUM.get(path[0], 0)
        value, level, source = _get(kit_defaults, path)[0], 'kit_default', lays[0][1]
        governed = value
        for lv, src, doc in lays[1:]:
            raw, present = _get(doc, path)
            if not present:
                continue
            v = _as_number(raw, minimum)
            if v is None:
                refused.append({'setting': name, 'level': lv, 'source': src, 'value': raw,
                                'state': TICKET_SETTING_INVALID, 'governed': governed,
                                'why': '%r is not a whole number >= %d; the value from the level below stands'
                                       % (raw, minimum)})
                continue
            if lv == 'org':
                governed = v
            elif v > governed:
                refused.append({'setting': name, 'level': lv, 'source': src, 'value': v,
                                'state': TICKET_SETTING_ABOVE_GOVERNED, 'governed': governed,
                                'why': '%s may only tighten %s; %d is above the governed %d, which stands. Raise it '
                                       'in the central register (the org) if that is the decision' % (lv, name, v, governed)})
                continue
            value, level, source = v, lv, src
        cur = numbers
        for p in path[:-1]:
            cur = cur[p]
        cur[path[-1]] = value
        record.append({'setting': name, 'value': value, 'level': level, 'source': source, 'governed': governed})
    return {'numbers': numbers, 'record': record, 'refused': refused, 'environment': environment or ''}


def summary_rows(settings):
    """-> markdown rows for the run summary: every value used and its level; every refusal by name."""
    rows = ['| ticket setting | value | level | source |', '|---|---|---|---|']
    for r in (settings or {}).get('record') or []:
        rows.append('| %s | %s | %s | %s |' % (r['setting'], r['value'], r['level'], r['source']))
    for r in (settings or {}).get('refused') or []:
        rows.append('| %s | REFUSED %s (%s) | %s | %s |' % (r['setting'], r['value'], r['state'], r['level'], r['why']))
    return rows


def _selftest():
    fails = []
    s = resolve(None, None, '', {})
    if s['numbers'] != kit_defaults or {r['level'] for r in s['record']} != {'kit_default'}:
        fails.append('no register: the kit defaults are not used and recorded as kit_default')
    s = resolve({'numbers': {'ticket_create_ceiling': 40}}, {'numbers': {'ticket_create_ceiling': 60}}, '', {})
    if s['numbers']['ticket_create_ceiling'] != 40 or not s['refused']:
        fails.append('a repository raised the org ceiling')
    if fails:
        for f in fails:
            sys.stderr.write('FAIL: %s\n' % f)
        return 2
    print('ticket_settings selftest ok: kit defaults recorded; a narrower level never raises the governed value. '
          'The full proof is tests/prove_ticket_defaults.py.')
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ('--self-test', '--selftest'):
        sys.exit(_selftest())
    print('usage: ticket_settings.py --self-test', file=sys.stderr)
    sys.exit(2)
