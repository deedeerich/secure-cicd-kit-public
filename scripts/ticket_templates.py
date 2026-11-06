#!/usr/bin/env python3
"""Ticket templates: findings the kit's scan did not produce, compliance requests, extensions,
no-fix re-checks, closures and triage decisions -- each with a fixed set of required fields, checked,
routed and written through the kit's own reconciler. (KDEC-037, amending KDEC-035 O-35f and O-35g;
template_version 2 carries the owner's rulings of 2026-11-04.)

WHY THIS EXISTS

    The owner, 2026-11-03: Tines "might be helping run USR reviews and things and will need to be
    able to write tickets when the review has been finalized and approved ... it truly needs to look
    at all even the manually created tickets ... it all must be tracked and processed and governed
    and worked on and managed." And 2026-11-04, on the first build: separation of duties, the whole
    security team as approvers, a fixer's close that is only ever pending, exact duplicates closed as
    duplicates, near matches created for triage, nothing ever lost, trust beside confidence, and her
    own taxonomy of requests.

THE TEMPLATES (api/v1/tickets/<template>.schema.json, template_version 2)

    finding               a finding from a USR review, a cloud tool, a pentest, an audit, a review, a tool
    false-positive        "the scanner is wrong": evidence, a reviewer confirms, NO expiry, re-checked on a
                          rule / tool-version / code change        -> FALSE_POSITIVE_REQUEST
    exception             at most 90 days, a SPECIFIC scope, compensating controls -> EXCEPTION_REQUEST
    exemption             the accepted-risk family "there to stay", a review cadence -> EXEMPTION_REQUEST
    accepted-risk         its own type: owner, rationale, review date, risk register -> ACCEPTED_RISK_REQUEST
    compliance-exception  the stricter standard: framework, control, requirement, scope, compensating
                          controls, expiry, a named authority      -> COMPLIANCE_EXCEPTION_REQUEST
    mitigation            a compensating control in force           -> MITIGATED_REQUEST
    extension             a new expiry, 30 days by default; capped while a fix exists, continuing (with an
                          advisory) while the vendor has none
    nofix-recheck         NO_FIX_AVAILABLE: a short exemption, a re-check every 30 days, a review every 90,
                          the advisory at 180 (severity-dependent)
    closure               resolve (the fixer: pending verification) / verify (a rescan on the mapped branch,
                          or a reviewer who is not the fixer) / reject (reopens)
    triage                a person's merge / separate on a possible duplicate
    (intake is a READ: scripts/ticket_intake.py and tickets.search tracker_query; proposed types are
    stubs under api/v1/tickets/proposed/, DISABLED -- docs/ticketing/TICKET-TYPES.md)

    A REQUEST IS NOT A DISPOSITION. Nothing stops blocking until an exact, unexpired, approved
    disposition is merged to the protected default branch (API_DISPOSITION_NOT_VIA_API stands).

THE ASSET IDENTITY SCHEME, CONFIDENCE AND TRUST

    The durable identity is sha256 over (asset key, identifier) -- nothing about the source -- so two
    tools agreeing are one identity. CONFIDENCE (finding_correlation.corroboration_score) is how
    likely the finding is real; TRUST (trust_score below) is how much we trust its source and its
    handling. Both are deterministic 0..100 with their derivation; neither replaces the tier.

USAGE
    python3 scripts/ticket_templates.py validate --template finding --item @payload.json
    python3 scripts/ticket_templates.py normalize --template finding --items @items.json --out f.json
    python3 scripts/ticket_templates.py evidence-hash --params @params.json
    python3 scripts/ticket_templates.py --self-test
EXIT  0 ok   1 refused (named)   2 usage
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

TEMPLATE_VERSION = 2
COMPLIANCE_TEMPLATES = ('false-positive', 'exception', 'exemption', 'accepted-risk', 'compliance-exception',
                        'mitigation')
WRITE_TEMPLATES = ('finding',) + COMPLIANCE_TEMPLATES + ('extension', 'nofix-recheck', 'closure', 'triage')
# Templates whose items carry a whole finding (and so become, or touch, a finding ticket).
FINDING_BEARING = ('finding', 'nofix-recheck') + COMPLIANCE_TEMPLATES
# The owner picks which to enable (docs/ticketing/TICKET-TYPES.md); until then TEMPLATE_NOT_ENABLED.
PROPOSED_TEMPLATES = ('vendor-dependency', 'remediation-subtask', 'review-finding', 'pentest-finding',
                      'audit-finding', 'cloud-misconfiguration', 'exposed-secret', 'licence', 'end-of-life',
                      'architecture-risk', 'access-review-finding', 'incident-follow-up', 'policy-deviation',
                      'control-gap')

# ── NAMED REFUSALS (assurance-taxonomy.yaml :: ticket_template_refusal) ─────────────────────
TEMPLATE_UNKNOWN = 'TEMPLATE_UNKNOWN'
TEMPLATE_NOT_ENABLED = 'TEMPLATE_NOT_ENABLED'
TEMPLATE_VERSION_UNSUPPORTED = 'TEMPLATE_VERSION_UNSUPPORTED'
TEMPLATE_FIELD_INVALID = 'TEMPLATE_FIELD_INVALID'
TEMPLATE_ASSET_IDENTITY_INVALID = 'TEMPLATE_ASSET_IDENTITY_INVALID'
NOFIX_EXEMPTION_TOO_LONG = 'NOFIX_EXEMPTION_TOO_LONG'
EXCEPTION_TOO_LONG = 'EXCEPTION_TOO_LONG'
LINK_DECISION_INVALID = 'LINK_DECISION_INVALID'
TICKET_NOT_KIT_LINKED = 'TICKET_NOT_KIT_LINKED'
SOD_SELF_APPROVAL = 'SOD_SELF_APPROVAL'
EXTENSION_LIMIT_REACHED = 'EXTENSION_LIMIT_REACHED'
EXTENSION_CEILING_EXCEEDED = 'EXTENSION_CEILING_EXCEEDED'
EXTENSION_COUNT_MISMATCH = 'EXTENSION_COUNT_MISMATCH'
CLOSURE_NOT_VERIFIED = 'CLOSURE_NOT_VERIFIED'

# ── WHAT HAPPENED TO EACH ITEM (assurance-taxonomy.yaml :: ticket_template_outcome) ─────────
TEMPLATE_TICKET_CREATED = 'TEMPLATE_TICKET_CREATED'
TEMPLATE_TICKET_PLANNED = 'TEMPLATE_TICKET_PLANNED'
TEMPLATE_TICKET_BOUND = 'TEMPLATE_TICKET_BOUND'
TEMPLATE_LINKED_EXACT = 'TEMPLATE_LINKED_EXACT'
TEMPLATE_CLOSED_DUPLICATE = 'TEMPLATE_CLOSED_DUPLICATE'
TEMPLATE_REGRESSION = 'TEMPLATE_REGRESSION'
TEMPLATE_POSSIBLE_DUPLICATE = 'TEMPLATE_POSSIBLE_DUPLICATE'
TEMPLATE_DEDUPE_PENDING = 'TEMPLATE_DEDUPE_PENDING'
TEMPLATE_OUTBOX = 'TEMPLATE_OUTBOX'
TEMPLATE_SENT_BACK = 'TEMPLATE_SENT_BACK'
TEMPLATE_TICKET_UPDATED = 'TEMPLATE_TICKET_UPDATED'
TEMPLATE_TICKET_CLOSED = 'TEMPLATE_TICKET_CLOSED'
TEMPLATE_PENDING_VERIFICATION = 'TEMPLATE_PENDING_VERIFICATION'
TEMPLATE_VERIFICATION_REJECTED = 'TEMPLATE_VERIFICATION_REJECTED'
TEMPLATE_FIX_OBSERVED = 'TEMPLATE_FIX_OBSERVED'
TEMPLATE_REOPENED_AS_REMEDIATION = 'TEMPLATE_REOPENED_AS_REMEDIATION'
TEMPLATE_TRIAGED_SEPARATE = 'TEMPLATE_TRIAGED_SEPARATE'
# EVERY ACCEPTED ITEM ENDS IN ONE OF THESE (owner, 2026-11-04: "not just lost to the bits").
TERMINAL_OUTCOMES = (TEMPLATE_TICKET_CREATED, TEMPLATE_TICKET_PLANNED, TEMPLATE_TICKET_BOUND, TEMPLATE_LINKED_EXACT,
                     TEMPLATE_CLOSED_DUPLICATE, TEMPLATE_REGRESSION, TEMPLATE_POSSIBLE_DUPLICATE,
                     TEMPLATE_DEDUPE_PENDING, TEMPLATE_OUTBOX, TEMPLATE_SENT_BACK, TEMPLATE_TICKET_UPDATED,
                     TEMPLATE_TICKET_CLOSED, TEMPLATE_PENDING_VERIFICATION, TEMPLATE_VERIFICATION_REJECTED,
                     TEMPLATE_FIX_OBSERVED, TEMPLATE_REOPENED_AS_REMEDIATION, TEMPLATE_TRIAGED_SEPARATE)

# compliance template -> (the requested_disposition word reconcile_tickets reads, the ticket class)
COMPLIANCE_MAP = {'false-positive': ('false_positive', 'FALSE_POSITIVE_REQUEST'),
                  'exception': ('exception', 'EXCEPTION_REQUEST'),
                  'exemption': ('exemption', 'EXEMPTION_REQUEST'),
                  'accepted-risk': ('risk_acceptance', 'ACCEPTED_RISK_REQUEST'),
                  'compliance-exception': ('compliance_exception', 'COMPLIANCE_EXCEPTION_REQUEST'),
                  'mitigation': ('mitigation', 'MITIGATED_REQUEST')}

# THE OWNER'S NUMBERS (KDEC-037, answered 2026-11-04), each a repository/organisation variable read by
# the API's jobs; an invalid value is a configuration refusal, never a silent default.
SETTING_DEFAULTS = {
    'extension_default_days': (30, 1, 90),      # O-37c: an extension with no new_expiry
    'extension_max': (2, 0, 5),                 # O-37c: while a fix is available
    'extension_ceiling_days': (90, 1, 365),     # O-37c: how far one extension may reach
    'vendor_advisory_extensions': (2, 1, 10),   # O-37c: waiting on the vendor: the advisory at this extension
    'vendor_advisory_days': (180, 30, 730),     # O-37c: ... or this many days after the first extension
    'nofix_exemption_days': (30, 1, 90),        # O-37d
    'nofix_exemption_ceiling_days': (90, 1, 365),
    'nofix_recheck_days': (30, 1, 180),         # O-37d: every 30 days (unless numbers.no_fix_recheck_days)
    'nofix_review_days': (90, 7, 365),          # O-37d: every 90 days
    'exception_max_days': (90, 1, 365),         # O-37f: an exception is at most 90 days
    'review_max_age_days': (30, 1, 365),        # O-37b: a concurrence older than this is stale
    'verification_reminder_days': (7, 1, 60),   # closure: remind at N days, escalate at 2N
    'fuzzy_title_percent': (85, 50, 100),       # O-37e: a possible duplicate at or above it
}
# O-37d: the no-fix advisory by severity (days; None: none). Register numbers.no_fix_advisory_days may
# override any of them; critical and high are escalated (the priority raised) when it is posted.
NOFIX_ADVISORY_DAYS = {'critical': 90, 'high': 90, 'medium': 180, 'low': None, 'info': None}
NOFIX_ESCALATE = ('critical', 'high')
DEFAULT_REVIEW_APPROVER_LIST = 'review-concurrence'
DEFAULT_APPROVER_SOURCE = 'list:review-concurrence'

# TRUST (owner, 2026-11-04: "there's confidence and trust ... we should probably show both").
TRUST_SOURCE_CLASS = {'kit-scan': 40, 'integrated-tool': 30, 'contracted-assessment': 25,
                      'internal-review': 20, 'manual-unknown': 5}

_SUBJECT_BY_SCHEME = {'repo-path': 'SOURCE', 'azure-resource': 'RESOURCE', 'aws-resource': 'RESOURCE',
                      'github-repo': 'POLICY', 'engagement': 'RUNTIME_OBSERVATION'}
_SCHEME_FIELDS = {'repo-path': ('repository', 'path'),
                  'azure-resource': ('cloud', 'tenant_id', 'subscription_id', 'resource_id'),
                  'aws-resource': ('account_id', 'region', 'arn'),
                  'github-repo': ('host', 'org', 'repo'),
                  'engagement': ('engagement_id', 'kind', 'target')}


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def refusal(code, detail, item=None):
    out = {'code': code, 'detail': str(detail)[:1500]}
    if item is not None:
        out['item'] = item
    return out


def template_dir():
    for cand in (os.path.join(HERE, '..', 'api', 'v1', 'tickets'), os.path.join(HERE, 'api', 'v1', 'tickets'),
                 os.path.join(HERE, 'v1', 'tickets')):
        if os.path.isfile(os.path.join(cand, 'finding.schema.json')):
            return os.path.normpath(cand)
    return os.path.normpath(os.path.join(HERE, '..', 'api', 'v1', 'tickets'))


_CACHE = {}


def load_template(name):
    """-> the template's schema. A template nobody can read is not a template anyone is held to."""
    if name not in _CACHE:
        sub = 'proposed' if name in PROPOSED_TEMPLATES else ''
        _CACHE[name] = json.load(io.open(os.path.join(template_dir(), sub, '%s.schema.json' % name),
                                         encoding='utf-8'))
    return _CACHE[name]


def settings_from(values):
    """-> ({setting: int}, problem). `values` maps a setting to its configured text ('' = default)."""
    out = {}
    for k, (default, lo, hi) in SETTING_DEFAULTS.items():
        raw = _s(str((values or {}).get(k) or ''))
        if not raw:
            out[k] = default
            continue
        if not raw.isdigit() or not lo <= int(raw) <= hi:
            return None, 'the setting %s is %r; it must be an integer from %d to %d (unset: the default %d)' % (
                k, raw, lo, hi, default)
        out[k] = int(raw)
    if out['nofix_exemption_days'] > out['nofix_exemption_ceiling_days']:
        return None, 'nofix_exemption_days %d is above nofix_exemption_ceiling_days %d' % (
            out['nofix_exemption_days'], out['nofix_exemption_ceiling_days'])
    return out, ''


def _date(v):
    try:
        return datetime.date.fromisoformat(v) if isinstance(v, str) and len(v) == 10 else None
    except ValueError:
        return None


def branch_environment(branch, mapping, default_branch):
    """-> the environment a branch is mapped to, or None. `mapping` is configuration
    ("main=prod,dev=dev,test=test"); with none, the default branch is prod. A feature branch maps to
    nothing: a fix there is OBSERVED, never closed (docs/ticketing/BRANCH-SCAN-AND-CLOSURE-PROPOSAL.md)."""
    pairs = [[x.strip() for x in p.split('=', 1)] for p in str(mapping or '').split(',') if '=' in p]
    if not pairs and default_branch:
        pairs = [(default_branch, 'prod')]
    for pat, env in pairs:
        # A trailing * matches a prefix (release/*); the first match wins. The environment is compared with
        # the ticket's `<stamp>-env-<environment>` label, so it is slugged the same way.
        if (pat.endswith('*') and str(branch or '').startswith(pat[:-1])) or pat == branch:
            return _slug(env) or None
    return None


# ═════════════════════════════════════════════════════════════════════════════════════
# THE ASSET IDENTITY SCHEME
# ═════════════════════════════════════════════════════════════════════════════════════

def asset_key(asset):
    """-> (key, display, needle, problem). `needle` is the text a manually written ticket would
    carry for this asset (what dedupe looks for); `problem` names why the asset is not an identity."""
    if not isinstance(asset, dict):
        return None, None, None, 'the asset is not an object'
    scheme = asset.get('scheme')
    need = _SCHEME_FIELDS.get(scheme)
    if need is None:
        return None, None, None, 'asset scheme %r is not one of %s' % (scheme, ', '.join(sorted(_SCHEME_FIELDS)))
    missing = [k for k in need if not _s(str(asset.get(k) or ''))]
    if missing:
        return None, None, None, 'a %s asset needs %s (missing: %s)' % (scheme, ', '.join(need), ', '.join(missing))
    extra = [k for k in asset if k not in need + ('scheme', 'line')]
    if extra:
        return None, None, None, 'a %s asset does not carry %s' % (scheme, ', '.join(sorted(extra)))
    if scheme == 'repo-path':
        path = _s(asset['path']).replace('\\', '/').lstrip('/')
        if not path or '..' in path.split('/'):
            return None, None, None, 'the path %r is not a repository-relative path' % asset['path']
        repo = _s(asset['repository']).lower()
        key = 'repo:%s:%s' % (repo, path)
        disp = '%s:%s%s' % (asset['repository'], path, (':%d' % asset['line']) if asset.get('line') else '')
        return key, disp, path.lower(), ''
    if scheme == 'azure-resource':
        rid = _s(asset['resource_id']).lower().rstrip('/')
        sub = _s(asset['subscription_id']).lower()
        if not rid.startswith('/subscriptions/%s/' % sub) and rid != '/subscriptions/%s' % sub:
            return None, None, None, ('the resource id %r does not name the subscription %s: one asset, '
                                      'two subscriptions is not an identity' % (asset['resource_id'], sub))
        key = 'azure:%s:%s:%s' % (asset['cloud'], _s(asset['tenant_id']).lower(), rid)
        return key, '%s (%s)' % (asset['resource_id'], asset['cloud']), rid, ''
    if scheme == 'aws-resource':
        arn = _s(asset['arn'])
        parts = arn.split(':', 5)
        if len(parts) < 6:
            return None, None, None, 'the ARN %r is not arn:partition:service:region:account:resource' % arn
        if parts[4] and parts[4] != asset['account_id']:
            return None, None, None, ('the ARN names account %s and the asset says %s: one asset, two '
                                      'accounts is not an identity' % (parts[4], asset['account_id']))
        if parts[3] and parts[3] != asset['region']:
            return None, None, None, 'the ARN names region %s and the asset says %s' % (parts[3], asset['region'])
        key = 'aws:%s:%s:%s' % (asset['account_id'], asset['region'], arn)
        return key, arn, arn.lower(), ''
    if scheme == 'github-repo':
        key = 'github:%s/%s/%s' % (_s(asset['host']).lower(), _s(asset['org']).lower(), _s(asset['repo']).lower())
        return key, '%s/%s/%s' % (asset['host'], asset['org'], asset['repo']), \
            ('%s/%s' % (asset['org'], asset['repo'])).lower(), ''
    key = 'engagement:%s:%s:%s' % (asset['kind'], _s(asset['engagement_id']).lower(), _s(asset['target']).lower())
    return key, '%s %s: %s' % (asset['kind'], asset['engagement_id'], asset['target']), \
        _s(asset['engagement_id']).lower(), ''


def identity_of(akey, identifier):
    """THE DURABLE IDENTITY of an external finding: the asset and the identifier, nothing about who
    reported it -- so two sources agreeing are one identity (anchored, automatically)."""
    return hashlib.sha256(('kit-external-finding/1|%s|%s' % (akey, identifier.lower())).encode('utf-8')) \
        .hexdigest()[:32]



# ═════════════════════════════════════════════════════════════════════════════════════
# VALIDATION
# ═════════════════════════════════════════════════════════════════════════════════════

def _validate_finding(f, where):
    import kit_api as ka
    errs = ka.validate(f, load_template('finding'), where)
    if errs:
        return refusal(TEMPLATE_FIELD_INVALID, '%s %s' % errs[0])
    _k, _d, _n, bad = asset_key(f.get('asset'))
    if bad:
        return refusal(TEMPLATE_ASSET_IDENTITY_INVALID, '%s.asset: %s' % (where, bad))
    return None


def _future(item, field, where, td, index, required=True):
    v = item.get(field)
    if v is None and not required:
        return None, None
    d = _date(v)
    if d is None:
        return None, refusal(TEMPLATE_FIELD_INVALID, '%s.%s %r is not a calendar date' % (where, field, v), index)
    if td and d <= td:
        return None, refusal(TEMPLATE_FIELD_INVALID, '%s.%s %s is not after today (%s): a date already passed '
                             'decides nothing' % (where, field, v, td), index)
    return d, None


def validate_item(template, item, index=0, settings=None, today=None):
    """-> None, or the FIRST problem named (code, detail, item index). Pure; reads no tracker."""
    import kit_api as ka
    settings = settings or settings_from({})[0]
    where = '$.items[%d]' % index
    if template in PROPOSED_TEMPLATES:
        return refusal(TEMPLATE_NOT_ENABLED, 'template %r is PROPOSED and not enabled: the owner chooses which '
                       'proposed types to enable (docs/ticketing/TICKET-TYPES.md)' % template, index)
    if template not in WRITE_TEMPLATES:
        return refusal(TEMPLATE_UNKNOWN, 'template %r is not one of %s' % (template, ', '.join(WRITE_TEMPLATES)), index)
    if not isinstance(item, dict):
        return refusal(TEMPLATE_FIELD_INVALID, '%s is not an object' % where, index)
    errs = ka.validate(item, load_template(template), where)
    if errs:
        return refusal(TEMPLATE_FIELD_INVALID, '%s %s' % errs[0], index)
    if template == 'finding':
        r = _validate_finding(item, where)
    elif template in FINDING_BEARING:
        r = _validate_finding(item['finding'], where + '.finding')
    else:
        r = None
    if r:
        r['item'] = index
        return r
    f = item if template == 'finding' else item.get('finding')
    if isinstance(f, dict) and f.get('correlation_key'):
        rec = normalize('finding', f, {}, index)
        if rec['correlation_key'] != f['correlation_key']:
            return refusal(TEMPLATE_FIELD_INVALID, '%s correlation_key %s is not the kit\'s %s for this asset and '
                           'identifier; the kit\'s key is authoritative' % (where, f['correlation_key'],
                                                                            rec['correlation_key']), index)
    td = _date(today) if today else datetime.date.today()
    if template in ('exception', 'compliance-exception', 'mitigation'):
        exp, bad = _future(item, 'expires', where, td, index)
        if bad:
            return bad
        if template == 'exception' and (exp - td).days > settings['exception_max_days']:
            return refusal(EXCEPTION_TOO_LONG, '%s.expires %s is %d day(s) away; an exception is ALWAYS time-limited to '
                           'at most %d days (owner, 2026-11-04) -- anything longer is an exemption or an accepted '
                           'risk' % (where, exp, (exp - td).days, settings['exception_max_days']), index)
    if template == 'exemption':
        _e, bad = _future(item, 'expires', where, td, index, required=False)
        if bad:
            return bad
    if template == 'accepted-risk':
        _e, bad = _future(item, 'review_date', where, td, index)
        if bad:
            return bad
    if template == 'nofix-recheck':
        if item['finding'].get('fix_status') != 'NO_FIX_AVAILABLE':
            return refusal(TEMPLATE_FIELD_INVALID, '%s.finding.fix_status is %r; a no-fix re-check is for '
                           'NO_FIX_AVAILABLE only' % (where, item['finding'].get('fix_status')), index)
        days = item.get('exemption_days') or settings['nofix_exemption_days']
        if days > settings['nofix_exemption_ceiling_days']:
            return refusal(NOFIX_EXEMPTION_TOO_LONG, '%s.exemption_days %d is past the ceiling of %d day(s): the '
                           'automatic exemption is SHORT by design' % (where, days,
                                                                       settings['nofix_exemption_ceiling_days']), index)
    if template == 'extension' and item.get('new_expiry') is not None:
        exp, bad = _future(item, 'new_expiry', where, td, index)
        if bad:
            return bad
        if (exp - td).days > settings['extension_ceiling_days']:
            return refusal(EXTENSION_CEILING_EXCEEDED, '%s.new_expiry %s is %d day(s) away; one extension reaches at '
                           'most %d day(s)' % (where, exp, (exp - td).days, settings['extension_ceiling_days']), index)
    if template == 'closure':
        v = item['verification']
        if item['action'] == 'verify' and v['kind'] == 'scan' and not v.get('run_id'):
            return refusal(TEMPLATE_FIELD_INVALID, '%s.verification: a scan verification names the run (run_id)'
                           % where, index)
        if item['action'] == 'reject' and not _s(item.get('reason')):
            return refusal(TEMPLATE_FIELD_INVALID, '%s.reason: a rejection says why' % where, index)
    return None


def validate_submit(params, settings=None, today=None):
    """-> None or the first refusal, for a whole tickets.submit params object (already schema-valid)."""
    if params.get('template_version') != TEMPLATE_VERSION:
        return refusal(TEMPLATE_VERSION_UNSUPPORTED, 'template_version %r is not served; this kit serves %d (version 1 '
                       'was superseded on 2026-11-04 by the owner\'s rulings, before any consumer used it)'
                       % (params.get('template_version'), TEMPLATE_VERSION))
    for i, item in enumerate(params.get('items') or []):
        r = validate_item(params['template'], item, i, settings, today)
        if r:
            return r
    keys = set()
    if params['template'] in FINDING_BEARING:
        keys = set(normalize(params['template'], it, {}, i)['correlation_key']
                   for i, it in enumerate(params['items']))
    for j, d in enumerate(params.get('link_decisions') or []):
        if d['correlation_key'] not in keys:
            return refusal(LINK_DECISION_INVALID, 'link_decisions[%d] names %s, which no item in this call has'
                           % (j, d['correlation_key']))
        if d['decision'] == 'link' and not d.get('ref'):
            return refusal(LINK_DECISION_INVALID, 'link_decisions[%d] is a link and names no ticket (ref)' % j)
    return None


def needs_review(params):
    """Every template needs a finalized review, except closure items that are the FIXER's own resolve
    (pending, never final) or a verification by the kit's own rescan (the scanner is the verifier)."""
    if params.get('template') == 'closure':
        return not all(it.get('action') == 'resolve' or
                       (it.get('action') == 'verify' and (it.get('verification') or {}).get('kind') == 'scan')
                       for it in params.get('items') or [])
    return True


def evidence_set_sha256(params):
    """THE EVIDENCE SET a review concurs with: exactly what will be written. sha256 over the
    canonical JSON of the template, its version, the review id, the items and the link decisions."""
    doc = {'template': params.get('template'), 'template_version': params.get('template_version'),
           'review_id': params.get('review_id') or '', 'items': params.get('items') or [],
           'link_decisions': params.get('link_decisions') or []}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
                          .encode('utf-8')).hexdigest()


# ═════════════════════════════════════════════════════════════════════════════════════
# NORMALISATION INTO THE KIT'S FINDING MODEL
# ═════════════════════════════════════════════════════════════════════════════════════

def _slug(v):
    return re.sub(r'[^a-z0-9._-]+', '-', str(v or '').lower()).strip('-')[:60] or 'unknown'


def tag_labels(stamp_label, template, finding, ck, review_id='', kev=False):
    """THE TAGGING BASELINE (docs/ticketing/TAGGING-STRATEGY-PROPOSAL.md: the neutral baseline for an
    environment-specific scheme to be designed at the adopting organisation). -> sorted list."""
    p = stamp_label or 'secure-cicd-kit'
    out = ['%s-tpl-%s' % (p, template), '%s-ck-%s' % (p, ck)]
    if isinstance(finding, dict):
        out += ['%s-src-%s' % (p, _slug(finding.get('source_type'))),
                '%s-tool-%s' % (p, _slug(finding.get('source_tool'))),
                '%s-env-%s' % (p, _slug(finding.get('environment'))),
                '%s-asset-%s' % (p, _slug((finding.get('asset') or {}).get('scheme'))),
                '%s-sev-%s' % (p, _slug(finding.get('severity')))]
        sha = ((finding.get('evidence') or {}).get('sha256') or '')[:16]
        if sha:
            out.append('%s-ev-%s' % (p, sha))
        if finding.get('kev') or kev:
            out.append('%s-kev' % p)
    if review_id:
        out.append('%s-review-%s' % (p, _slug(review_id)))
    return sorted(set(out))


def _facts_for_request(template, item):
    rows = []
    if template == 'false-positive':
        rows += [('rule', item.get('rule_id')), ('tool version', item.get('tool_version')),
                 ('code ref', item.get('code_ref') or 'not given'),
                 ('re-check', 'no expiry; re-checked when the rule, the tool version or the code changes')]
    if item.get('scope'):
        s = item['scope']
        rows.append(('scope', 'from %s to %s, %s' % (s['from'], s['to'], s['condition'])))
    if item.get('compensating_controls'):
        rows.append(('compensating controls', '; '.join(item['compensating_controls'])))
    for k, label in (('expires', 'request expires'), ('review_every_days', 'review every (days)'),
                     ('owner', 'risk owner'), ('review_date', 'review date'), ('risk_register_ref', 'risk register'),
                     ('framework', 'framework'), ('control_id', 'control'), ('requirement_text', 'requirement'),
                     ('approving_authority', 'approving authority'), ('compensating_control', 'compensating control'),
                     ('register_scope', 'register scope')):
        if item.get(k) is not None:
            rows.append((label, item[k]))
    return rows


def normalize(template, item, provenance, index=0, stamp_label='', settings=None, today=None, numbers=None):
    """-> one kit-shaped finding record (scripts/reconcile_tickets.py reads it; finding_correlation
    clusters it), with its provenance. Pure."""
    import finding_correlation as fc
    settings = settings or settings_from({})[0]
    f = item if template == 'finding' else item.get('finding') or {}
    akey, disp, needle, _bad = asset_key(f.get('asset'))
    ident_f = identity_of(akey or '', f.get('identifier') or '')
    subject = f.get('finding_subject') or _SUBJECT_BY_SCHEME.get((f.get('asset') or {}).get('scheme'), 'SOURCE')
    # THE ANCHOR IS THE IDENTIFIER, alone (two submissions with different alias lists are one finding).
    aliases = [str(f.get('identifier') or '').lower()]
    finding_ck = fc.cluster_key(subject, akey or '', aliases[0] or ident_f)
    ev = item.get('evidence') or f.get('evidence') or {}
    rec = {
        'identity': ident_f, 'state': 'FINGERPRINTED', 'identity_state': 'FINGERPRINTED',
        'finding_subject': subject, 'where': akey or '', 'uri': disp or '', 'canonical_path': disp or '',
        'line': (f.get('asset') or {}).get('line'), 'rule': f.get('identifier'), 'rule_id': f.get('identifier'),
        'scanner': _slug(f.get('source_tool')), 'tool': f.get('source_tool'),
        'scanner_version': f.get('source_tool_version') or '', 'severity': f.get('severity'),
        'what_aliases': aliases, 'aliases': sorted(set(str(a).lower() for a in f.get('aliases') or [])),
        'cwe': f.get('cwe') or '', 'job': 'external', 'fp': '', 'kev': bool(f.get('kev')), 'title': f.get('title'),
        'template': template, 'source_type': f.get('source_type'), 'environment': f.get('environment'),
        'fix_status': f.get('fix_status'), 'asset_scheme': (f.get('asset') or {}).get('scheme'),
        'asset_needle': needle or '', 'finding_correlation_key': finding_ck, 'correlation_key': finding_ck,
        'item': index, 'code_ref': item.get('code_ref') or f.get('code_ref') or '',
        'provenance': {'source_type': f.get('source_type'), 'tool': f.get('source_tool'),
                       'tool_version': f.get('source_tool_version') or '',
                       'submitted_by': (provenance or {}).get('submitted_by') or '',
                       'on_behalf_of': (provenance or {}).get('on_behalf_of') or '',
                       'on_behalf_of_verified': False,
                       'requested_by': item.get('requested_by') or f.get('requested_by') or '',
                       'review_id': (provenance or {}).get('review_id') or '',
                       'evidence_ref': ev.get('ref'), 'evidence_sha256': ev.get('sha256'),
                       'evidence_receipt': ev.get('receipt') or '',
                       'asset_key': akey, 'correlation_call': (provenance or {}).get('correlation_id') or ''},
    }
    if f.get('kev'):
        rec['kit_class'] = 'kev'
    facts = [('template', '%s (version %d)' % (template, TEMPLATE_VERSION)),
             ('source', '%s via %s%s' % (f.get('source_type'), f.get('source_tool'),
                                         (' ' + f['source_tool_version']) if f.get('source_tool_version') else '')),
             ('environment', f.get('environment')), ('asset', '%s (`%s`)' % (disp, akey)),
             ('identifier', f.get('identifier')), ('fix status', f.get('fix_status')),
             ('evidence', '%s (sha256 `%s`)%s' % (ev.get('ref'), ev.get('sha256'),
                                                  (', receipt %s' % ev['receipt']) if ev.get('receipt') else '')),
             ('submitted by', '%s%s' % (rec['provenance']['submitted_by'] or 'unknown',
                                        ('; on behalf of %s, as declared -- not verified' % rec['provenance']['on_behalf_of'])
                                        if rec['provenance']['on_behalf_of'] else '')),
             ('requested by', rec['provenance']['requested_by'] or 'not stated')]
    if rec['provenance']['review_id']:
        facts.append(('review', '%s (finalized, human-concurred)' % rec['provenance']['review_id']))
    labels = tag_labels(stamp_label, template, f, finding_ck, rec['provenance']['review_id'])
    if template in COMPLIANCE_TEMPLATES:
        word, cls = COMPLIANCE_MAP[template]
        # A REQUEST IS ITS OWN OBLIGATION beside the finding's: its own identity and locus.
        rec.update(identity=hashlib.sha256(('kit-request/1|%s|%s' % (template, ident_f)).encode()).hexdigest()[:32],
                   where='request:%s:%s' % (template, akey),
                   what_aliases=['request:%s:%s' % (template, aliases[0] if aliases else '')],
                   requested_disposition=word, request_class=cls)
        facts += [('requested', '%s -> %s (a REQUEST: nothing stops blocking until an approved disposition is '
                                'merged to the protected default branch)' % (template, cls)),
                  ('finding correlation key', '`%s`' % finding_ck), ('justification', item['justification'])]
        facts += _facts_for_request(template, item)
    if template == 'nofix-recheck':
        td = _date(today) or datetime.date.today()
        ex_days = item.get('exemption_days') or settings['nofix_exemption_days']
        rc_days = item.get('recheck_days') or (numbers or {}).get('no_fix_recheck_days') or settings['nofix_recheck_days']
        rec['nofix'] = {'since': td.isoformat(),
                        'exempt_until': (td + datetime.timedelta(days=int(ex_days))).isoformat(),
                        'recheck_due': (td + datetime.timedelta(days=int(rc_days))).isoformat(),
                        'vendor': item['vendor']}
        facts += [('no fix', 'upstream has no fix (%s, vendor %s%s)' % (
            'NO_FIX_AVAILABLE', item['vendor'], (', advisory %s' % item['vendor_advisory_ref'])
            if item.get('vendor_advisory_ref') else '')),
            ('no-fix since', rec['nofix']['since']),
            ('exempt until', '%s (an automatic, ticket-level pause of the SLA clock -- never a gate exception)'
             % rec['nofix']['exempt_until']),
            ('re-check due', '%s -- check with the vendor again, every %s days; a review every %d days; when a fix '
             'ships this ticket reopens as remediation' % (rec['nofix']['recheck_due'], rc_days,
                                                           settings['nofix_review_days']))]
        labels.append('%s-nofix' % (stamp_label or 'secure-cicd-kit'))
    rec['template_facts'] = facts
    rec['template_labels'] = sorted(set(labels))
    rec['correlation_key'] = fc.cluster_key(subject, rec['where'], rec['what_aliases'][0] or rec['identity'])
    return rec


# ═════════════════════════════════════════════════════════════════════════════════════
# TRUST BESIDE CONFIDENCE
# ═════════════════════════════════════════════════════════════════════════════════════
#
# CONFIDENCE (finding_correlation.corroboration_score) is how likely the finding is real. TRUST is how much we
# trust its SOURCE AND ITS HANDLING. Deterministic, integers, 0..100, the derivation attached:
#
#     source class   the kit's own scan 40 | an approved integrated tool 30 | a contracted pentest or audit 25
#                    | an internal reviewer (review, USR) 20 | manual / unknown 5
#     evidence       +10 a sha256 is present; +10 the kit verified it (its own artifact); +5 a custody receipt
#     identity       +10 the submitter is a verified identity (GitHub's actor; a declared on_behalf_of is not)
#     review         +20 a finalized, human concurrence
#     custody        +5 the evidence reference is in an approved evidence store
#
# It is not exploitability, severity or priority, and it replaces neither the tier nor confidence.

def source_class(record, approved_tools=()):
    if _s(record.get('job')) and record.get('job') != 'external':
        return 'kit-scan'
    tool = _slug(record.get('tool') or record.get('scanner'))
    if tool in set(_slug(t) for t in approved_tools or ()):
        return 'integrated-tool'
    st = record.get('source_type')
    if st in ('pentest', 'audit'):
        return 'contracted-assessment'
    if st in ('review', 'usr'):
        return 'internal-review'
    return 'manual-unknown'


def trust_score(record, ctx):
    """-> (score, basis). `ctx`: approved_tools, evidence_stores, review_finalized, submitter_verified,
    evidence_verified."""
    ctx = ctx or {}
    prov = record.get('provenance') or {}
    cls = source_class(record, ctx.get('approved_tools'))
    terms = [('source %s' % cls, TRUST_SOURCE_CLASS[cls])]
    has_hash = bool(_s(str(prov.get('evidence_sha256') or '')))
    terms.append(('evidence hash', 10 if has_hash else 0))
    terms.append(('evidence verified by the kit', 10 if (has_hash and ctx.get('evidence_verified')) else 0))
    terms.append(('custody receipt', 5 if _s(str(prov.get('evidence_receipt') or '')) else 0))
    terms.append(('submitter identity verified', 10 if ctx.get('submitter_verified') else 0))
    terms.append(('review concurrence', 20 if ctx.get('review_finalized') else 0))
    ref = _s(str(prov.get('evidence_ref') or ''))
    terms.append(('chain of custody (an approved evidence store)',
                  5 if ref and any(ref.startswith(s) for s in ctx.get('evidence_stores') or () if s) else 0))
    score = max(0, min(100, sum(v for _k, v in terms)))
    return score, '; '.join('%s +%d' % (k, v) for k, v in terms) + ' = %d' % score


# ═════════════════════════════════════════════════════════════════════════════════════
# THE RULES THAT NEED THE TRACKER'S STATE (pure: the caller reads the state and hands it in)
# ═════════════════════════════════════════════════════════════════════════════════════

def extensions_observed(labels, stamp_label):
    """-> the number of extensions the ticket's own labels record (the tracker is the record)."""
    n = 0
    p = (stamp_label or 'secure-cicd-kit') + '-extension-'
    for lb in labels or []:
        if str(lb).startswith(p) and str(lb)[len(p):].isdigit():
            n = max(n, int(str(lb)[len(p):]))
    return n


def label_dates(labels, stamp_label, word):
    """-> the dates (YYYY-MM-DD) carried by labels `<p>-<word>-YYYYMMDD`, sorted."""
    p = '%s-%s-' % (stamp_label or 'secure-cicd-kit', word)
    out = []
    for lb in labels or []:
        tail = str(lb)[len(p):] if str(lb).startswith(p) else ''
        if len(tail) == 8 and tail.isdigit():
            out.append('%s-%s-%s' % (tail[:4], tail[4:6], tail[6:]))
    return sorted(out)


def date_label(stamp_label, word, day):
    return '%s-%s-%s' % (stamp_label or 'secure-cicd-kit', word, str(day).replace('-', ''))


def check_extension(item, index, observed, approver, settings):
    """-> None or the refusal. The requester never approves; the count is the tracker's; capped while a fix
    exists, continuing while the vendor has none."""
    import separation_of_duties as sod
    viol = sod.violations({'requester': item['requested_by']}, approver) if approver else []
    if viol:
        return refusal(SOD_SELF_APPROVAL, 'item %d: %s -- nobody approves their own extension' % (index, sod.describe(viol)),
                       index)
    if item['extensions_used'] != observed:
        return refusal(EXTENSION_COUNT_MISMATCH, 'item %d: the request says %d extension(s) were used and the ticket '
                       '%s records %d -- a history shorter than the tracker shows is refused'
                       % (index, item['extensions_used'], item['ref'], observed), index)
    if item.get('waiting_on', 'fix') == 'fix' and observed + 1 > settings['extension_max']:
        return refusal(EXTENSION_LIMIT_REACHED, 'item %d: ticket %s has had %d extension(s) and, with a fix available, '
                       'the maximum is %d: fix it, or the owner raises the maximum'
                       % (index, item['ref'], observed, settings['extension_max']), index)
    return None


def nofix_state(since, today, severity, numbers, settings, recheck_every=None):
    """-> {'recheck': k (cycles of the re-check period completed), 'review': k (review periods),
    'advisory': bool, 'escalate': bool, 'days': n}. The CLOCK's arithmetic, pure."""
    d0, td = _date(since), _date(today)
    if not d0 or not td or td < d0:
        return {'recheck': 0, 'review': 0, 'advisory': False, 'escalate': False, 'days': 0}
    nums = numbers or {}
    days = (td - d0).days
    # The ticket's own interval (what it was raised with, written on it) wins over the register's default.
    rc = int(recheck_every or nums.get('no_fix_recheck_days') or settings['nofix_recheck_days'])
    rv = int(nums.get('no_fix_review_days') or settings['nofix_review_days'])
    sev = str(severity or '').lower()
    adv_tab = dict(NOFIX_ADVISORY_DAYS, **dict((str(k).lower(), v) for k, v in
                                              (nums.get('no_fix_advisory_days') or {}).items()))
    adv = adv_tab.get(sev)
    return {'recheck': days // rc, 'review': days // rv, 'advisory': bool(adv) and days >= int(adv),
            'escalate': bool(adv) and days >= int(adv) and sev in NOFIX_ESCALATE, 'days': days}


def fp_recheck_reason(fp_facts, record):
    """-> why a false positive must be re-checked against a newer observation, or ''."""
    out = []
    tv = _s(record.get('scanner_version'))
    if tv and fp_facts.get('tool version') and tv != fp_facts['tool version']:
        out.append('the tool version changed %s -> %s' % (fp_facts['tool version'], tv))
    cr = _s(record.get('code_ref'))
    if cr and fp_facts.get('code ref') not in (None, '', 'not given') and cr != fp_facts['code ref']:
        out.append('the code changed %s -> %s' % (fp_facts['code ref'], cr))
    rid = _s(record.get('rule'))
    if rid and fp_facts.get('rule') and rid.lower() != str(fp_facts['rule']).lower():
        out.append('the rule changed %s -> %s' % (fp_facts['rule'], rid))
    return '; '.join(out)


# ═════════════════════════════════════════════════════════════════════════════════════
# SELF-TEST AND CLI
# ═════════════════════════════════════════════════════════════════════════════════════

def example_finding(**over):
    f = {'source_type': 'cloud-tool', 'source_tool': 'defender', 'environment': 'azure-commercial-prod',
         'asset': {'scheme': 'azure-resource', 'cloud': 'azure-commercial',
                   'tenant_id': '11111111-2222-3333-4444-555555555555',
                   'subscription_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                   'resource_id': '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg/providers/'
                                  'Microsoft.Storage/storageAccounts/acct1'},
         'identifier': 'AZURE-STORAGE-TLS-1-0', 'severity': 'high', 'fix_status': 'FIX_AVAILABLE',
         'evidence': {'ref': 'review-pack/item-1', 'sha256': 'e' * 64}, 'title': 'Storage account allows TLS 1.0'}
    f.update(over)
    return f


def _selftest():
    fails = []
    if validate_item('finding', example_finding()) is not None:
        fails.append('a well-formed finding was refused: %r' % validate_item('finding', example_finding()))
    bad = example_finding(asset=dict(example_finding()['asset'], resource_id='/subscriptions/ffffffff-bbbb-cccc-dddd-'
                                                                             'eeeeeeeeeeee/x'))
    if (validate_item('finding', bad) or {}).get('code') != TEMPLATE_ASSET_IDENTITY_INVALID:
        fails.append('a resource id naming another subscription was not refused by name')
    a = normalize('finding', example_finding(source_tool='defender'), {})
    b = normalize('finding', example_finding(source_tool='usr-review'), {})
    if a['identity'] != b['identity'] or a['correlation_key'] != b['correlation_key'] or not a['identity']:
        fails.append('two sources on one asset and identifier are not one identity')
    if evidence_set_sha256({'template': 'finding', 'template_version': 2, 'items': [example_finding()]}) == \
            evidence_set_sha256({'template': 'finding', 'template_version': 2, 'items': [example_finding(severity='low')]}):
        fails.append('the evidence-set hash does not change when an item does')
    if (validate_item('control-gap', {}) or {}).get('code') != TEMPLATE_NOT_ENABLED:
        fails.append('a proposed type was not refused TEMPLATE_NOT_ENABLED')
    if trust_score(a, {'review_finalized': True})[0] <= trust_score(a, {})[0]:
        fails.append('a review concurrence did not raise trust')
    for f in fails:
        sys.stderr.write('FAIL: %s\n' % f)
    if fails:
        return 2
    print('ticket_templates selftest ok: a finding validates; an asset naming another subscription is refused by name; '
          'two sources on one asset are one identity; the evidence set binds every byte; proposed types are disabled; '
          'trust counts the review. The cases run in tests/prove_ticket_templates.py and prove_ticket_intake_v2.py.')
    return 0


def _load_arg(text):
    if text.startswith('@'):
        return json.load(io.open(text[1:], encoding='utf-8'))
    return json.loads(text)


def main(argv=None):
    ap = argparse.ArgumentParser(description='Ticket templates (KDEC-037).')
    ap.add_argument('--self-test', action='store_true')
    sub = ap.add_subparsers(dest='cmd')
    v = sub.add_parser('validate')
    v.add_argument('--template', required=True)
    v.add_argument('--item', required=True)
    n = sub.add_parser('normalize')
    n.add_argument('--template', required=True)
    n.add_argument('--items', required=True)
    n.add_argument('--out', required=True)
    h = sub.add_parser('evidence-hash')
    h.add_argument('--params', required=True)
    a = ap.parse_args(argv)
    if a.self_test:
        return _selftest()
    if a.cmd == 'validate':
        r = validate_item(a.template, _load_arg(a.item))
        print(json.dumps({'valid': r is None, 'refusal': r}, indent=2))
        return 0 if r is None else 1
    if a.cmd == 'normalize':
        items = _load_arg(a.items)
        items = items if isinstance(items, list) else [items]
        out = []
        for i, it in enumerate(items):
            r = validate_item(a.template, it, i)
            if r:
                print(json.dumps({'refusal': r}, indent=2))
                return 1
            if a.template in FINDING_BEARING:
                out.append(normalize(a.template, it, {}, i))
        io.open(a.out, 'w', encoding='utf-8').write(json.dumps(out, indent=2, sort_keys=True) + '\n')
        print('%d record(s) written to %s' % (len(out), a.out))
        return 0
    if a.cmd == 'evidence-hash':
        print(evidence_set_sha256(_load_arg(a.params)))
        return 0
    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
