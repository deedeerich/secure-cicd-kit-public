#!/usr/bin/env python3
"""TICKET ROUTING: which tracker project a finding's ticket is CREATED in. (KDEC-028, lane L-AM)

WHY THIS EXISTS

    One JIRA_PROJECT per repository put every finding on one board. Owners route by the kind of
    finding: IaC and cloud findings to the team that runs the cloud, everything else to the
    security board or to the product's own board (owner, 2026-10-23). So the policy register carries
    `ticket_routing`, an ordered list of rules plus a default, on any entry of any scope.

THE SHAPE (on a policy register entry, beside rung/controls; the entry still carries a decision)

    "ticket_routing": {
        "inherit": true,                       optional; false drops the RULES of broader scopes
                                               (their default still applies if this has none)
        "rules": [                             first match wins, most specific scope first
            {"id": "cloud",                    optional, named in the run record
             "match": {"scanner_family": ["iac"], "category": ["IAC_PLAN", "RESOURCE"]},
             "project": "AZSEC",               a project key, or "none" (no ticket)
             "issue_type": "Bug",              optional; else JIRA_TYPE_CLUSTER
             "epic": "10123",                  optional numeric id IN THAT PROJECT; else none
             "components": ["Azure"],          optional
             "labels": ["cloud-security"]}],   optional, added beside the kit's own
        "default": {"project": "SEC", ...}     optional; same target fields as a rule
    }

    match keys (all given must hold; a list means any of):
        class           secret | kev | malicious | finding
        scanner_family  secrets | sca | sast | iac | container | dast
        scanner         a scanner name the cluster's members carry
        category        the finding_subject (SOURCE, SOURCE_DEPENDENCY, IAC_PLAN, RESOURCE, IMAGE,
                        POLICY, IDENTITY_ASSIGNMENT, RUNTIME_OBSERVATION)
        severity        critical | high | medium | low | ...   (the cluster's effective severity)
        min_severity    one severity: that one or worse
        repository      owner/name globs (fnmatch, case-insensitive)

PRECEDENCE: repository > org+team+product > org+product > org+team > org > enterprise > kit default

    The kit default is JIRA_PROJECT (and so, for the simple case, GitHub's own variable precedence:
    a repository-level JIRA_PROJECT overrides the organisation's). ROUTING IS NOT A SECURITY FLOOR:
    a narrower scope overrides a broader one freely -- unlike the rung, where a narrower entry may
    only tighten. Rules are evaluated most specific scope first; a scope's rules are followed by
    its parent's unless it says `inherit: false`. The default is the most specific scope's default.

THE ONE EXCEPTION, REFUSED BY NAME: TICKET_ROUTING_BELOW_FLOOR

    Routing may send a secret, a KEV-listed vulnerability or a known-malicious package to any
    project; it may never send one to "none". A register that does (a "none" rule whose match
    names such a class) is refused as TICKET_ROUTING_BELOW_FLOOR, which routes BLOCKED like every
    other below-floor register. At run time the same rule holds for anything
    the register could not see coming: a none-rule or a none-default that MATCHES a floor-class
    finding is skipped for it, the note names TICKET_ROUTING_BELOW_FLOOR, and the finding is
    ticketed by the next rule, the default, or the kit default -- never dropped.

A RULE CHANGE NEVER MOVES OR DUPLICATES A TICKET

    Routing is consulted only when a ticket is CREATED. A cluster already bound to a ticket stays
    where its ticket is: the reconciler's sweep covers JIRA_PROJECT, every project the routing
    names and every project the ledger records a ticket in, so the next run finds it, comments once
    that routing now names another project, and creates nothing.
"""
import fnmatch
import re

TICKET_ROUTING_BELOW_FLOOR = 'TICKET_ROUTING_BELOW_FLOOR'
NONE = 'none'
FLOOR_CLASSES = ('secret', 'kev', 'malicious')
CLASSES = FLOOR_CLASSES + ('finding',)
FAMILIES = ('secrets', 'sca', 'sast', 'iac', 'container', 'dast')
SUBJECTS = ('SOURCE', 'SOURCE_DEPENDENCY', 'IAC_PLAN', 'RESOURCE', 'IMAGE', 'POLICY',
            'IDENTITY_ASSIGNMENT', 'RUNTIME_OBSERVATION', 'RELEASE')
SEVERITY_ORDER = ('critical', 'high', 'medium', 'moderate', 'low', 'info', 'informational', 'note',
                  'none')
ROUTING_KEYS = ('inherit', 'rules', 'default', 'notes')
TARGET_KEYS = ('project', 'issue_type', 'epic', 'components', 'labels')
RULE_KEYS = ('id', 'match', 'notes') + TARGET_KEYS
MATCH_KEYS = ('class', 'scanner_family', 'scanner', 'category', 'severity', 'min_severity',
              'repository')
# A Jira project key: an upper-case letter, then upper-case letters, digits or underscores.
PROJECT_RE = re.compile(r'^[A-Z][A-Z0-9_]{1,254}$')
LABEL_RE = re.compile(r'^\S+$')


def _list(v):
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _target_problems(t, where, bad):
    proj = t.get('project')
    if proj is not None and proj != NONE and not (isinstance(proj, str) and PROJECT_RE.match(proj)):
        bad('%s project %r is not a Jira project key (upper-case letters, digits, _) or "none"'
            % (where, proj))
    if 'issue_type' in t and not (isinstance(t['issue_type'], str) and t['issue_type'].strip()):
        bad('%s issue_type must be a non-empty issue type name' % where)
    if 'epic' in t and not str(t['epic']).strip().isdigit():
        bad('%s epic must be the NUMERIC id of an epic in that project (the key moves)' % where)
    for k in ('components', 'labels'):
        if k in t and (not isinstance(t[k], list) or
                       any(not isinstance(x, str) or not x.strip() for x in t[k])):
            bad('%s %s must be a list of names' % (where, k))
    for x in t.get('labels') or []:
        if isinstance(x, str) and not LABEL_RE.match(x):
            bad('%s label %r contains whitespace; a Jira label is one token' % (where, x))


def check_routing(obj, where, unreadable_code):
    """-> [(code, message)]. Structure faults carry `unreadable_code` (the register's
    REGISTRATION_UNAVAILABLE); a floor class routed to none is TICKET_ROUTING_BELOW_FLOOR."""
    p = []
    bad = lambda m: p.append((unreadable_code, m))  # noqa: E731
    where = '%s ticket_routing' % where
    if not isinstance(obj, dict):
        return [(unreadable_code, '%s is not an object' % where)]
    for k in obj:
        if k not in ROUTING_KEYS:
            bad('%s carries unknown field %r (inherit, rules, default, notes)' % (where, k))
    if 'inherit' in obj and not isinstance(obj['inherit'], bool):
        bad('%s inherit must be true or false' % where)
    rules = obj.get('rules', [])
    if not isinstance(rules, list):
        bad('%s rules is not a list' % where)
        rules = []
    for i, rule in enumerate(rules):
        w = '%s rules[%d]' % (where, i)
        if not isinstance(rule, dict):
            bad('%s is not an object' % w)
            continue
        for k in rule:
            if k not in RULE_KEYS:
                bad('%s carries unknown field %r' % (w, k))
        if 'project' not in rule:
            bad('%s names no project (a project key, or "none")' % w)
        _target_problems(rule, w, bad)
        m = rule.get('match', {})
        if not isinstance(m, dict):
            bad('%s match is not an object' % w)
            m = {}
        for k, v in m.items():
            if k not in MATCH_KEYS:
                bad('%s match names %r, which is not a routing fact (%s)' % (w, k, ', '.join(MATCH_KEYS)))
                continue
            vals = _list(v)
            if not vals or any(not isinstance(x, str) or not x.strip() for x in vals):
                bad('%s match.%s must be a name or a list of names' % (w, k))
            elif k == 'class' and any(x not in CLASSES for x in vals):
                bad('%s match.class %r: the classes are %s' % (w, v, ', '.join(CLASSES)))
            elif k == 'scanner_family' and any(x not in FAMILIES for x in vals):
                bad('%s match.scanner_family %r: the families are %s' % (w, v, ', '.join(FAMILIES)))
            elif k == 'category' and any(x not in SUBJECTS for x in vals):
                bad('%s match.category %r is not a finding_subject' % (w, v))
            elif k in ('severity', 'min_severity') and any(x.lower() not in SEVERITY_ORDER for x in vals):
                bad('%s match.%s %r is not a severity' % (w, k, v))
            elif k == 'min_severity' and len(vals) != 1:
                bad('%s match.min_severity is one severity' % w)
        # THE FLOOR: a rule that names a floor class may not send it to none.
        if rule.get('project') == NONE:
            named = [c for c in _list(m.get('class')) if c in FLOOR_CLASSES]
            if named:
                p.append((TICKET_ROUTING_BELOW_FLOOR,
                          '%s routes %s to "none": a secret, a KEV-listed vulnerability or a '
                          'known-malicious package is always ticketed; route it to a project'
                          % (w, '/'.join(named))))
    if 'default' in obj:
        d = obj['default']
        if not isinstance(d, dict):
            bad('%s default is not an object' % where)
        else:
            for k in d:
                if k not in TARGET_KEYS + ('notes',):
                    bad('%s default carries unknown field %r' % (where, k))
            if 'project' not in d:
                bad('%s default names no project' % where)
            _target_problems(d, '%s default' % where, bad)
    return p


# ── resolution: the chain of scopes ──────────────────────────────────────────────────────

def resolve_routing(central, repo_doc, repository):
    """-> {'rules': [rule + source], 'default': target or None, 'chain': [entry ids], 'notes': []}.
    Pure over the parsed registers. Entries are matched by the policy register's own scope rules
    (environment_tier-qualified entries are not routing scopes and are skipped)."""
    import policy_registration as pr  # here, not at the top: policy_registration imports this module
    out = {'rules': [], 'default': None, 'chain': [], 'notes': []}
    if not central and not repo_doc:
        return out
    ident = pr._identity(central, repository)
    if not ident.get('enterprise') and pr.enterprise_defined(central):
        ents = sorted(set(pr._s(v) for v in central['orgs'].values() if pr._s(v)))
        if len(ents) == 1:
            ident = dict(ident, enterprise=ents[0])
        else:
            out['notes'].append('org %r is not in the orgs map and %d enterprises are defined, so no '
                                'enterprise routing applies to it' % (ident['org'], len(ents)))
    chain = [(key, origin, e) for key, origin, e in pr._chain(central, repo_doc, ident, None)
             if isinstance(e.get('ticket_routing'), dict)]
    # Most specific first. `inherit: false` stops the RULES of broader scopes; the default is still
    # the most specific one any scope sets.
    inheriting = True
    for key, origin, e in reversed(chain):
        tr = e['ticket_routing']
        src = '%s:%s' % (origin, e.get('id') or '?')
        out['chain'].append(src)
        if inheriting:
            for rule in tr.get('rules') or []:
                out['rules'].append(dict(rule, source=src))
        if out['default'] is None and isinstance(tr.get('default'), dict):
            out['default'] = dict(tr['default'], source=src)
        if inheriting and tr.get('inherit') is False:
            out['notes'].append('%s does not inherit routing rules from broader scopes' % src)
            inheriting = False
    return out


def projects_named(routing):
    """Every project key the routing could create a ticket in (never "none")."""
    seen = []
    for t in list((routing or {}).get('rules') or []) + [(routing or {}).get('default') or {}]:
        p = t.get('project')
        if p and p != NONE and p not in seen:
            seen.append(p)
    return seen


# ── matching ─────────────────────────────────────────────────────────────────────────────

def _sev_rank(s):
    s = str(s or '').lower()
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER)


def matches(match, facts):
    for k, v in (match or {}).items():
        vals = [str(x) for x in _list(v)]
        if k == 'class':
            if facts.get('class') not in vals:
                return False
        elif k == 'scanner_family':
            if facts.get('scanner_family') not in vals:
                return False
        elif k == 'scanner':
            have = set(str(s).lower() for s in facts.get('scanners') or [])
            if not have & set(x.lower() for x in vals):
                return False
        elif k == 'category':
            if str(facts.get('category') or '').upper() not in [x.upper() for x in vals]:
                return False
        elif k == 'severity':
            if str(facts.get('severity') or '').lower() not in [x.lower() for x in vals]:
                return False
        elif k == 'min_severity':
            if _sev_rank(facts.get('severity')) > _sev_rank(vals[0]):
                return False
        elif k == 'repository':
            repo = str(facts.get('repository') or '').lower()
            if not any(fnmatch.fnmatchcase(repo, x.lower()) for x in vals):
                return False
        else:
            return False
    return True


def _target(t, rule_id, source):
    return {'project': t.get('project'), 'issue_type': t.get('issue_type') or None,
            'epic': str(t['epic']).strip() if t.get('epic') else None,
            'components': list(t.get('components') or []), 'labels': list(t.get('labels') or []),
            'rule': rule_id, 'source': source, 'notes': []}


def route(facts, routing, kit_default_project):
    """-> the target for one cluster: {project (None = not ticketed), issue_type, epic, components,
    labels, rule, source, notes}. A floor-class finding is never routed to none."""
    notes = []
    floor = bool(facts.get('floor')) or facts.get('class') in FLOOR_CLASSES
    candidates = [(r, r.get('id') or 'rules[%d]' % i, r.get('source') or '')
                  for i, r in enumerate((routing or {}).get('rules') or [])
                  if matches(r.get('match'), facts)]
    d = (routing or {}).get('default')
    if d:
        candidates.append((d, 'default', d.get('source') or ''))
    for t, rid, src in candidates:
        if t.get('project') == NONE and floor:
            notes.append('%s: %s (%s) routes this %s finding to "none"; a floor-class finding is '
                         'always ticketed, so the rule is skipped for it'
                         % (TICKET_ROUTING_BELOW_FLOOR, rid, src, facts.get('class')))
            continue
        out = _target(t, rid, src)
        if out['project'] == NONE:
            out['project'] = None
        out['notes'] = notes
        return out
    out = _target({'project': kit_default_project}, 'kit-default', 'JIRA_PROJECT')
    out['notes'] = notes
    return out
