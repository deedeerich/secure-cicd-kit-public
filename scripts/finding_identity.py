#!/usr/bin/env python3
"""CANONICAL finding identity. Does this finding already exist, across runs and across upgrades?

THIS FILE IS THE SINGLE SOURCE OF TRUTH for the IDENTITY side of finding matching.

IDENTITY IS NOT CORRELATION, AND MERGING THEM BREAKS IDENTITY
-------------------------------------------------------------
Two different questions, asked at two different timescales, and the kit has been answering the
second with a function named for the first.

    CORRELATION  did these two TOOLS see the same thing, in THIS run?
                 `scanner` and `rule_id` are the right inputs -- they are what distinguishes the
                 tools you are comparing. A correlation key is valid for one moment.

    IDENTITY     is this the same finding I saw BEFORE -- last week, before the refactor, before
                 the scanner upgrade?
                 `scanner` and `rule_id` are FATAL inputs. A rule rename resets the baseline; a
                 second scanner reads corroboration as duplication.

They STACK: correlate within a run, then match the correlated finding against the ledger by
identity. Nothing here computes a correlation key, and nothing here may be handed one.

WHAT THIS REPLACES, AND WHY IT IS URGENT
----------------------------------------
`reusable-security.yml` carries `fingerprint(scanner, rule_id, uri, message)`, and that hash is
what `load_dispositions()` keys every approved exception by -- every false-positive approval,
every risk acceptance, every mitigation, with their approvers and expiry dates.

Its docstring correctly explains why it excludes the LINE NUMBER. It then includes four things
section 5.2 of ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md names as fatal:

    scanner    a Trivy upgrade orphans every disposition ever approved against Trivy
    rule_id    a rule rename or split does the same, silently, at a minor version
    uri        as a STRONG component: a directory move produces N new criticals and N
               silent disappearances. The design carries the path WEAKLY, beside a symbol path.
    message    the scanner's PROSE. A vendor rewording a message invalidates the baseline.
               The design hashes the matched CONSTRUCT, which is a property of the code.

So the disposition ledger is keyed by a correlation-shaped hash. It is not wrong today; it goes
wrong on the next `trivy` bump, and the failure is silent -- approvals do not error, they stop
matching, and a gate that was green goes red with no change to the code it is gating.

THE THREE COMPONENTS, CARRIED SEPARATELY
----------------------------------------
Not one hash. One hash forces a single answer to three questions that fail in different ways
and would make "moved" indistinguishable from "new" (section 5.3's cascade needs the components apart).

    WHAT     the defect's class identity
    WHERE    a subject-scaled locus, never an offset
    CONTENT  the matched construct, normalised

A composite is computed for convenience. It is carried BESIDE the three, never instead of them.

REFUSE, NEVER DEGRADE
---------------------
If a component cannot be derived, this returns UNFINGERPRINTABLE with a reason. It does NOT hash
whatever happened to be present.

    Hashing a partial record manufactures a STABLE-LOOKING identity out of an incomplete one.
    That is the same defect family as FILE_MTIME provenance in the evidence harness: not merely
    wrong, but systematically wrong in the direction that makes a weak claim look like a strong
    one. A hash is opaque -- nobody downstream can tell a full identity from a shrug.

An uncomputable identity is neither a match nor a NEW finding. It is EVIDENCE_UNTRUSTED (the
registered term), which stops the run. The permissive side is never the default.

EXCLUDED FIELDS CANNOT INFLUENCE OUTPUT BY CONSTRUCTION
-------------------------------------------------------
Every component reads through an explicit per-subject ALLOWLIST of keys. An excluded field is not
filtered out after the fact -- it is never read. `--self-test` additionally mutates each excluded
field and asserts the identity is unchanged, because a construction argument nobody exercises is
an argument, not a test.

USAGE
    python3 finding_identity.py --self-test
    python3 finding_identity.py <records.json>    # a list of records, or one record

    from finding_identity import identify
    result = identify(record)
    if result['state'] == 'FINGERPRINTED':
        key = result['identity']
    else:
        # result['reason'], result['detail'] -- route to EVIDENCE_UNTRUSTED
"""

import hashlib
import io
import json
import re
import sys

# ─────────────────────────────────────────────────────────────────────────────
# The nine registered `finding_subject` values, verbatim from assurance-taxonomy.yaml.
# Retyped nowhere else: a near-miss spelling reads as blank to every consumer, and blank
# renders as unqualified.
SUBJECTS = (
    'IMAGE',
    'SOURCE',
    'SOURCE_DEPENDENCY',
    'IAC_PLAN',
    'RESOURCE',
    'IDENTITY_ASSIGNMENT',
    'RUNTIME_OBSERVATION',
    'POLICY',
    'RELEASE',
)

# Fields that may NEVER reach a fingerprint, with what breaks each one. This table is
# DOCUMENTATION plus the selftest's input -- it is not a filter, because nothing reads these
# keys in the first place.
EXCLUDED = {
    'scanner': 'a scanner upgrade, or adding a second scanner, resets the whole baseline',
    'scanner_version': 'same, at every patch release',
    'tool': 'the SARIF driver name is the scanner under another name',
    'rule_id': 'a rule rename or split at a minor version resets the baseline',
    'line': 'one import added at the top of a file and every finding in it is NEW',
    'start_line': 'same',
    'end_line': 'same',
    'column': 'same, horizontally',
    'start_column': 'same',
    'severity': 'a CVSS re-score would retire the old finding AND create a new one -- two lies in one event',
    'commit': 'changes every run, so nothing ever matches anything',
    'commit_sha': 'same',
    'run_id': 'same',
    'build_number': 'same',
    'timestamp': 'same',
    'observed_at': 'same -- this belongs in first_seen provenance, not in identity',
    'image_digest': 'changes on every build, so every rebuild re-baselines the entire image',
    'partial_fingerprints': (
        'scanner-specific by construction, and for a secret scanner it can be a hash OF THE '
        'SECRET. The kit strips these before SARIF upload for exactly that reason; a ledger '
        'that reintroduced them would commit an offline-crackable oracle to a readable branch'
    ),
    'snippet': 'matched material. See secrets_rule -- the baseline never needs to hold one',
    'message': (
        "the scanner's PROSE. A vendor rewording a message is not a change to the code, and a "
        'fingerprint that moved because of it manufactures a NEW finding out of an edit to a '
        'string table'
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# IDENTITY SCOPE -- a second axis, and it does not rank against the states below.
#
# Seven subjects name something that outlives the run that observed it. RELEASE does not:
# `finding_subject`'s own registered rule says a finding whose subject is a running resource
# OUTLIVES EVERY RELEASE THAT TOUCHED IT, and naming it by release loses it at the next deploy.
#
# So a RELEASE fingerprint is computable and is NOT durable. It is valid for comparisons inside
# one release and must never be used as a baseline ledger key. Saying so is the point: the
# alternative is a key that works in testing and quietly loses every finding at the next deploy.
DURABLE = 'DURABLE_ACROSS_RUNS_AND_UPGRADES'
SINGLE_RELEASE = 'VALID_WITHIN_ONE_RELEASE_ONLY'

# CONTENT normalisation policy, per subject. TWO policies, because a literal value is noise in
# one place and the entire finding in another.
#
#   LITERALS_PLACEHOLDERED   source constructs. `if (x == 41)` and `if (x == 42)` are the same
#                            defect; a reformat or a constant tweak must not manufacture a NEW
#                            finding.
#
#   VALUES_VERBATIM          declarative state -- IaC, resources, policy, RBAC. Here the value
#                            IS the finding. `publicNetworkAccess = Enabled` and
#                            `= Disabled` are an open finding and a FIXED one. Placeholdering
#                            them collapses the two, which means a remediated finding keeps
#                            matching its ledger entry and reads as still open -- or an
#                            introduced one matches a closed entry and gets grandfathered.
#                            That error is in the PERMISSIVE direction, which is the one
#                            direction this kit does not accept.
LITERALS_PLACEHOLDERED = 'LITERALS_PLACEHOLDERED'
VALUES_VERBATIM = 'VALUES_VERBATIM'

# A declared structural absence, which is NOT a missing field. A package vulnerability has no
# matched construct -- the package coordinate in WHERE is the whole finding. Collapsing
# "not applicable here" into "could not be derived" is the four-state collapse the kit refuses
# everywhere else (NOT_APPLICABLE / CLEAN / COVERAGE_GAP / turned-off never collapse).
CONTENT_NOT_APPLICABLE = 'CONTENT_NOT_APPLICABLE_FOR_SUBJECT'

# ─────────────────────────────────────────────────────────────────────────────
# D-3, DECIDED: A DEPENDENCY FINDING IS A DIFFERENT SUBJECT, NOT A LOOSER `SOURCE`.
#
# The defect (docs/KNOWN_DEFECTS.md D-3): `SPEC['SOURCE']['content']` was mandatory, so a
# dependency vulnerability carrying a perfect CVE *and* a perfect purl was refused with
# CONTENT_UNDERIVABLE -- while the identical vulnerability in the identical package was
# FINGERPRINTED under IMAGE, where `content` is declared None. The same fact was
# representable in a container and unrepresentable in a lockfile.
#
# THE REJECTED FIX, AND WHY IT IS REJECTED
#   `content: '?construct'` on SOURCE would have let the dependency finding through in one
#   character. It also weakens every SAST finding in the estate, permanently and invisibly:
#   `_derive_content` returns the NOT_APPLICABLE sentinel for an absent OPTIONAL key, so a
#   Semgrep finding whose scanner merely FAILED to carry its construct -- or whose construct
#   the kit's own pre-upload redactor stripped -- would hash as though no construct had ever
#   existed. Two different injections in one function would then share one identity, and the
#   second would inherit the first's risk acceptance. That is an error in the PERMISSIVE
#   direction, and a security gate does not get to make those.
#
#   The deeper objection is the four-state rule. "This subject has no matched construct"
#   (a fact about dependency findings) and "this finding has a construct and we could not read
#   it" (a fact about this record) are two states. An optional key answers both with one
#   sentinel and the operator cannot tell them apart.
#
# THE DECISION
#   A ninth registered subject, SOURCE_DEPENDENCY, whose locus is the PACKAGE COORDINATE and
#   whose `content` is declared None -- the same shape as IMAGE, for the same reason, because it
#   is the same kind of fact about a different artifact. `SOURCE` keeps `content: 'construct'`
#   MANDATORY and unchanged, so a code finding that cannot produce its construct still REFUSES
#   with CONTENT_UNDERIVABLE and says so.
#
#   This is also the fix SPEC['SOURCE']['why_stable'] already PROMISED and the table did not
#   implement: "When the finding is a dependency, the PURL replaces the path entirely." Under
#   SOURCE that sentence was false -- `?purl` was optional and `canonical_path` was required, so
#   the lockfile path went into every dependency locus, and every dependency finding in a
#   repository shared most of its WHERE with every other.
#
#   `--self-test` asserts BOTH halves, because the cheap fix is one character away forever:
#   that SOURCE_DEPENDENCY fingerprints the D-3 reproduction record, and that
#   SPEC['SOURCE']['content'] is still spelled without a '?'.


# ─────────────────────────────────────────────────────────────────────────────
# Per-subject specification.
#
# `where` is the ordered list of keys composing the locus. A key prefixed '?' is optional and
# contributes when present. A key prefixed '=' may be legitimately EMPTY STRING and is still
# present -- the root module of a Terraform plan has an empty module path, and treating that as
# missing would refuse every root-level resource in the estate. None is missing; '' is root.
#
# `content` is the key holding the matched construct, or None where the subject has no construct.
# `why_stable` is not a comment. It is printed by --explain and is the reason the field set can be
# defended in a review, which is the only thing that stops the set being quietly widened later.
SPEC = {
    'SOURCE': {
        'where': ['?purl', '?dependency_scope', '?manifest_role', 'canonical_path', '?symbol_path'],
        'content': 'construct',
        'content_policy': LITERALS_PLACEHOLDERED,
        'scope': DURABLE,
        'why_stable': (
            'A source finding survives rescans because neither the path nor the symbol moves when '
            'a scanner is upgraded, and survives refactors because the SYMBOL is the strong half: '
            'a function keeps its name when its file is moved. The path is carried beside it and '
            'weighted weakly by the section 5.3 cascade, which treats a WHERE-only difference as MOVED '
            'rather than NEW. A dependency finding is NOT a SOURCE finding: it is '
            'SOURCE_DEPENDENCY, whose locus is the purl alone (D-3).'
        ),
    },
    'SOURCE_DEPENDENCY': {
        # THE PACKAGE COORDINATE IS THE LOCUS, and `purl` is REQUIRED rather than optional.
        #
        # Not the manifest path: `requirements.txt` is identical for every dependency finding in
        # the repository, so including it adds nothing to the locus and loses the finding when
        # the manifest moves or a monorepo splits. Not the manifest LINE: it moves on every
        # unrelated upgrade. The ecosystem/name/version triple is assigned by the registry, is
        # identical across every scanner that reads the same lockfile, and is the thing the
        # advisory is actually about.
        #
        # A dependency finding with NO purl therefore refuses with WHERE_UNDERIVABLE. That is
        # deliberate and it is the whole difference between this and `content: '?construct'`:
        # the refusal names the missing field, so a scanner that reports packages without
        # coordinates is a visible extraction gap rather than an invisible collision.
        'where': ['purl', '?dependency_scope', '?manifest_role'],
        'content': None,
        'content_policy': None,
        'scope': DURABLE,
        'why_stable': (
            'A purl is ecosystem/name/version, assigned by the package registry and not by the '
            'scanner, so two tools reading one lockfile agree and a tool upgrade cannot move it. '
            'There is NO matched construct: a package vulnerability is not a line of code that '
            'matched a pattern, it is a coordinate that appears in an advisory, so CONTENT is a '
            'declared NOT_APPLICABLE read from this table rather than a hash of whatever the '
            'record happened to carry. An upgrade of the package IS a different finding, which '
            'is correct -- the version is part of the coordinate, and 2.19.1 being vulnerable is '
            'not a statement about 2.31.0.'
        ),
    },
    'IMAGE': {
        # NEVER the image digest. It is the one field an image finding obviously "has", and it
        # changes on every build -- including a rebuild that changed nothing but a base-layer
        # timestamp.
        'where': ['package_name', 'package_version', '?package_source'],
        'content': None,
        'content_policy': None,
        'scope': DURABLE,
        'why_stable': (
            "The image's own package database reports the same package name and version on every "
            'rescan of the same image, and on a rebuild that did not change that package. The '
            'digest changes on both. There is no matched construct: the installed package '
            'coordinate IS the finding, so CONTENT is a declared NOT_APPLICABLE rather than a '
            'hash of empty string -- which would be indistinguishable from a real one.'
        ),
    },
    'IAC_PLAN': {
        # The plan's resource ADDRESS, never the file offset. An address survives the file being
        # reformatted, split, or having a resource inserted above it.
        'where': ['=module_path', 'resource_type', 'resource_name'],
        'content': 'attribute_path',
        'content_policy': VALUES_VERBATIM,
        'scope': DURABLE,
        'why_stable': (
            'A resource address is assigned by the configuration, not by the scanner, so it is '
            'identical across tools and across tool versions. The attribute path plus its '
            'proposed value is hashed VERBATIM: for declarative state the value is the finding, '
            'and placeholdering it would make a remediation indistinguishable from the defect.'
        ),
    },
    'RESOURCE': {
        'where': ['resource_id', '?property_path'],
        'content': 'observed_value',
        'content_policy': VALUES_VERBATIM,
        'scope': DURABLE,
        'why_stable': (
            'A cloud resource id is assigned by the platform and outlives every release that '
            'touched the resource, which is exactly what `finding_subject` warns about: name '
            'this by release and it is lost at the next deploy. It is also identical across '
            'every tool that reads the same resource.'
        ),
    },
    'IDENTITY_ASSIGNMENT': {
        # The unit is the GRANT: who, what, where. Principal OBJECT ID, never display name --
        # a person changing their name must not create a new finding.
        'where': ['principal_id', 'role_definition_id', 'assignment_scope'],
        'content': '?condition_expression',
        'content_policy': VALUES_VERBATIM,
        'scope': DURABLE,
        'why_stable': (
            'The grant triple is the assignment. Object ids and role definition ids are platform '
            'identifiers and do not move; display names do, and a rename must not manufacture a '
            'finding. The condition expression is the CONTENT because a constrained grant and an '
            'unconstrained one at the same triple are two different findings -- and hashing the '
            'condition verbatim is what makes ADDING a constraint read as a fix rather than as a '
            'new finding at the same locus.'
        ),
    },
    'RUNTIME_OBSERVATION': {
        # The live-target class. Registered the whole time and emitted by nothing, so this locus
        # is derived here rather than inherited -- and that is stated, not hidden.
        #
        # NOT the IP address: it rotates behind a load balancer and a scaling event would
        # manufacture findings. NOT the observation time: every run would be new.
        'where': ['target_host', '=target_path', '?observed_port'],
        'content': 'observed_condition',
        'content_policy': VALUES_VERBATIM,
        'scope': DURABLE,
        'why_stable': (
            'A canonical host and request path are properties of the service, not of the probe, '
            'so two authorized scans a month apart agree. Deliberately NOT the resolved IP, '
            'which rotates behind a load balancer -- a scaling event would otherwise close every '
            'finding and open an identical set. Deliberately NOT the observation time. This '
            'locus is DERIVED here: section 5.1 of the design specifies loci for five subjects and this '
            'is not one of them, so it is the weakest-defended entry in this table and should be '
            'the first reviewed against a real active-scan output.'
        ),
    },
    'POLICY': {
        'where': ['policy_definition_id', '=assignment_scope'],
        'content': '?parameter_path',
        'content_policy': VALUES_VERBATIM,
        'scope': DURABLE,
        'why_stable': (
            'A policy definition id is stable by contract -- it is what assignments reference. '
            'The subject here is the CONTROL ITSELF rather than anything it evaluated, so no '
            'scanner field appears in the locus at all.'
        ),
    },
    'RELEASE': {
        'where': ['release_id', '?aggregate_dimension'],
        'content': None,
        'content_policy': None,
        # The one non-durable subject. See the DURABLE/SINGLE_RELEASE note above.
        'scope': SINGLE_RELEASE,
        'why_stable': (
            'Stable WITHIN one release and worthless across releases, which is why it carries '
            'VALID_WITHIN_ONE_RELEASE_ONLY. `finding_subject` registers RELEASE for the case '
            'where no narrower subject is the real one; using it as a baseline key is the exact '
            'error its registered rule warns about, so the scope field exists to make that '
            'misuse visible to a reader rather than discoverable at the next deploy.'
        ),
    },
}

# Refusal reasons. Each one names the field, so the refusal is actionable rather than a shrug.
R_SUBJECT_MISSING = 'SUBJECT_NOT_DECLARED'
R_SUBJECT_UNREGISTERED = 'SUBJECT_NOT_REGISTERED'
R_WHAT_UNDERIVABLE = 'WHAT_UNDERIVABLE'
R_WHERE_UNDERIVABLE = 'WHERE_UNDERIVABLE'
R_CONTENT_UNDERIVABLE = 'CONTENT_UNDERIVABLE'
R_SYMBOL_REQUIRED = 'SYMBOL_REQUIRED_FOR_COARSE_WHAT'
R_SECRET_NOT_BASELINEABLE = 'SECRET_SUBJECT_NOT_BASELINEABLE'

UNFINGERPRINTABLE = 'UNFINGERPRINTABLE'
FINGERPRINTED = 'FINGERPRINTED'

# The registered disposition for a finding whose identity could not be computed. Not a match,
# and not a NEW finding.
ROUTES_TO = 'EVIDENCE_UNTRUSTED'


def _h(label, parts):
    """Hash with a domain label, so a WHAT can never collide with a WHERE that happens to agree.

    Components are joined with a unit separator rather than a printable character: a path
    containing '|' must not be able to impersonate a two-field locus.
    """
    raw = label + '\x1f' + '\x1f'.join(parts)
    return hashlib.sha256(raw.encode('utf-8', 'replace')).hexdigest()


def _norm_ws(text):
    r"""Normalise whitespace so a reformat is not a new finding.

    TWO passes, and the second is the one that matters. Collapsing runs of whitespace alone leaves
    `run( cmd, shell=True )` different from `run(cmd, shell=True)` -- which is precisely what a
    formatter rollout changes, so the first draft of this function was reformat-fragile in exactly
    the case it existed to cover. The selftest caught it.

    So whitespace ADJACENT TO PUNCTUATION is dropped as well. This also buys tool-independence:
    two scanners quoting the same IaC attribute as `a = b` and `a=b` must produce one identity,
    and without this pass they produce two.

    RESIDUAL: a value whose meaning depends on whitespace beside a punctuation mark normalises
    the same as one without it. Whitespace between two word characters is preserved, so ordinary
    prose in an observed condition survives intact.
    """
    out = re.sub(r'\s+', ' ', (text or '')).strip()
    return re.sub(r'\s*([^\w\s])\s*', r'\1', out)


_COMMENT_MARKERS = {'c_like': '//', 'hash': '#', 'sql': '--'}


def _quote_chars(family):
    # A backtick delimits a literal in the c_like family (JS/TS template strings, Go raw strings).
    # In the hash family it is shell command substitution -- CODE, not a literal -- so it is a
    # quote only where the family says so.
    return ('"', "'", '`') if family == 'c_like' else ('"', "'")


def _segments(text, family, marker):
    """Split `text` into ('code' | 'string' | 'comment', chunk) segments, left to right.

    STRING-AWARE, which is the whole point (L40). The first draft of this module cut every line at
    the first comment marker, before literals were placeholdered: `password = "hunter#2"` became
    `password = "hunter`, an unterminated string the placeholder could not match, so a FRAGMENT OF
    THE LITERAL reached the hash. That broke the one argument that makes hashing a construct safe
    at all (D-8: a literal destroyed before hashing cannot be recovered), and under VALUES_VERBATIM
    it collided `"team#1"` with `"team#2"`.

    A string runs to its closing quote, honouring backslash escapes, and may cross a newline. A
    string with NO closing quote runs to the end of the text and is still a string: a snippet cut
    mid-literal must not hand the rest of the literal to the hash as code. A comment runs from a
    marker OUTSIDE any string to the end of its line.
    """
    text = text or ''
    quotes = _quote_chars(family)
    out, buf, i, n = [], [], 0, len(text)

    def flush():
        if buf:
            out.append(('code', ''.join(buf)))
            del buf[:]

    while i < n:
        ch = text[i]
        if ch in quotes:
            flush()
            j = i + 1
            while j < n:
                if text[j] == '\\':
                    j += 2
                    continue
                if text[j] == ch:
                    break
                j += 1
            end = min(j + 1, n)
            out.append(('string' if j < n else 'open_string', text[i:end]))
            i = end
            continue
        if marker and text.startswith(marker, i):
            flush()
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(('comment', text[i:j]))
            i = j
            continue
        buf.append(ch)
        i += 1
    flush()
    return out


def _placeholder_literals(text, family=None):
    r"""Replace string and numeric literals so a constant tweak is not a new finding.

    Strings first, then numbers -- the other order would rewrite digits INSIDE a string and then
    fail to match the string, leaving a half-normalised construct that looks normalised.

    Strings are found by the same scanner that strips comments, so the two can never disagree
    about where a literal ends. A string whose closing quote is missing is placeholdered to the end
    of the construct rather than left as a fragment (L40).

    RESIDUAL, stated rather than hidden: a finding whose only distinguishing feature IS a literal
    collapses with its sibling -- two `chmod` calls in one function differing only in mode. WHERE
    separates them when they sit in different symbols and does not when they do not. The section 5.3
    cardinality rule is what keeps that honest: the group is matched by count, not by pretending
    to know which is which.
    """
    parts = []
    for kind, chunk in _segments(text, family, None):
        if kind in ('string', 'open_string'):
            quote = chunk[0]
            parts.append(quote + 'S' + (quote if kind == 'string' else ''))
        else:
            parts.append(chunk)
    return re.sub(r'\b\d+(?:\.\d+)?\b', 'N', ''.join(parts))


def _strip_line_comments(text, family):
    """Strip line comments, and ONLY for a DECLARED language family -- and never inside a string.

    Guessing the comment syntax is how '#' inside a shell string becomes a truncated construct.
    An undeclared family means comments stay in, and the normalisation id below records that --
    so two records normalised differently produce different hashes that SAY WHY, instead of
    matching by luck or differing without explanation.

    A marker inside a string literal is part of the literal (L40, see `_segments`).
    """
    marker = _COMMENT_MARKERS.get(family)
    if not marker:
        return text
    return ''.join(chunk for kind, chunk in _segments(text, family, marker) if kind != 'comment')


def _content_normalisation_id(policy, family):
    """Which normalisation ran. Goes INTO the content hash.

    If it did not, the same construct normalised two ways would produce two hashes with nothing
    recording the difference -- a silent duplicate-finding generator.
    """
    return '%s+comments:%s' % (policy, family or 'NOT_DECLARED')


def _get(record, key):
    """Read one key. The ONLY reader. Nothing in this module reaches into `record` elsewhere,
    which is what makes the exclusion list structural rather than a filter someone can forget."""
    value = record.get(key)
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if not isinstance(value, str):
        return None
    return value


def _derive_what(record):
    """-> (hash, described, aliases) or (None, reason_detail, None).

    An externally anchored id is preferred because it is the one component two unrelated tools
    agree on. CWE plus a rule-family alias is the fallback; a bare rule id is not a fallback at
    all, which is the whole point.
    """
    aliases = []
    for key in ('cve', 'ghsa', 'osv', 'advisory_id'):
        value = _get(record, key)
        if value:
            aliases.append(value.strip().upper())
    if aliases:
        # Sorted so the same alias set in a different order is the same WHAT. Carried as a SET
        # because advisories re-alias -- section 5.6 matches on intersection, which needs the members.
        aliases = sorted(set(aliases))
        return (_h('WHAT/ADVISORY', aliases), 'advisory:' + ','.join(aliases), aliases)

    purl = _get(record, 'purl')
    if purl:
        # A PURL identifies the vulnerable package even where no advisory id was reported.
        return (_h('WHAT/PURL', [purl.strip()]), 'purl:' + purl.strip(), [purl.strip()])

    cwe = _get(record, 'cwe')
    family = _get(record, 'rule_family')
    if cwe and family:
        pair = [cwe.strip().upper(), family.strip()]
        return (_h('WHAT/FAMILY', pair), 'cwe+family:' + '/'.join(pair), None)

    missing = []
    if not cwe:
        missing.append('cwe')
    if not family:
        missing.append('rule_family')
    return (
        None,
        'no advisory id (cve/ghsa/osv/advisory_id), no purl, and %s absent. A bare rule_id is '
        'NOT an acceptable substitute -- it is the field a scanner upgrade renames, which is why '
        'the alias table exists and why this refuses instead of reaching for it'
        % ' and '.join(missing),
        None,
    )


def _what_is_coarse(described):
    """CWE-only WHAT is coarse enough to collide across genuinely different findings (section 5.6, last
    row), so it requires a symbol-level WHERE. An advisory id or PURL does not."""
    return described.startswith('cwe+family:')


def _derive_where(record, subject):
    """-> (hash, described) or (None, reason_detail).

    Reads ONLY the keys this subject's spec names. A line number is not in any spec, so it cannot
    reach a hash even if a caller passes one.
    """
    parts = []
    described = []
    missing = []
    for key in SPEC[subject]['where']:
        optional = key.startswith('?')
        may_be_empty = key.startswith('=')
        name = key.lstrip('?=')
        value = _get(record, name)
        if value is None:
            if optional:
                continue
            missing.append(name)
            continue
        if not may_be_empty and not value.strip():
            # Empty where empty is not meaningful. A resource_type of '' is a missing field
            # wearing a present field's clothes, and hashing it would produce a locus shared by
            # every incomplete record in the estate -- a collision that looks like a match.
            missing.append(name + ' (present but empty)')
            continue
        # Field NAME is part of the hash, so an optional field being absent can never produce the
        # same locus as a different field being present with that value.
        parts.append(name + '=' + value.strip())
        described.append(name + '=' + value.strip())
    if missing:
        return (
            None,
            'subject %s requires %s; missing: %s'
            % (
                subject,
                ', '.join(k.lstrip('?=') for k in SPEC[subject]['where'] if not k.startswith('?')),
                ', '.join(missing),
            ),
        )
    return (_h('WHERE/' + subject, parts), ' '.join(described))


def _derive_content(record, subject):
    """-> (hash, normalisation_id) or (None, reason_detail).

    A subject with no construct returns the DECLARED not-applicable sentinel. That is not a
    refusal, and it must not be reachable by accident -- it is read from the spec, never from
    the absence of data.
    """
    spec = SPEC[subject]
    key = spec['content']
    if key is None:
        return (CONTENT_NOT_APPLICABLE, CONTENT_NOT_APPLICABLE)

    optional = key.startswith('?')
    name = key.lstrip('?')
    raw = _get(record, name)
    if raw is None or not raw.strip():
        if optional:
            # Optional CONTENT absent is a legitimate state: an RBAC grant with no condition is
            # unconstrained, which is a fact about the grant rather than a gap in the record.
            return (CONTENT_NOT_APPLICABLE, CONTENT_NOT_APPLICABLE)
        return (None, 'subject %s requires `%s` and it is absent or empty' % (subject, name))

    policy = spec['content_policy']
    family = _get(record, 'language_family')
    text = _strip_line_comments(raw, family)
    text = _norm_ws(text)
    if policy == LITERALS_PLACEHOLDERED:
        text = _placeholder_literals(text, family)
    norm_id = _content_normalisation_id(policy, family)
    return (_h('CONTENT/' + norm_id, [text]), norm_id)


def _refuse(subject, reason, detail):
    return {
        'state': UNFINGERPRINTABLE,
        'reason': reason,
        'detail': detail,
        'finding_subject': subject,
        'routes_to': ROUTES_TO,
        # No hash. Not a truncated one, not a partial one, not a hash of the fields that WERE
        # present. The absence is the signal.
        'identity': None,
    }


def identify(record):
    """Compute the identity of one finding. -> dict, state FINGERPRINTED or UNFINGERPRINTABLE.

    `record` is a flat mapping. Unknown keys are ignored; excluded keys are never read.
    """
    if not isinstance(record, dict):
        return _refuse(None, R_SUBJECT_MISSING, 'record is not a mapping')

    subject = _get(record, 'finding_subject')
    if not subject:
        return _refuse(
            None,
            R_SUBJECT_MISSING,
            'no `finding_subject`. The subject decides which locus applies, so there is no '
            'default to fall back to -- a default would silently apply one subject\'s identity '
            'to another subject\'s finding',
        )
    subject = subject.strip()
    if subject not in SUBJECTS:
        return _refuse(
            subject,
            R_SUBJECT_UNREGISTERED,
            '`%s` is not one of the %d registered finding_subject values (%s). A near-miss '
            'spelling is worse than a wild one: consumers read it as blank'
            % (subject, len(SUBJECTS), ', '.join(SUBJECTS)),
        )

    # section 5.7: the baseline has NO AUTHORITY over secrets. Secret findings block at every rung and
    # are never grandfathered, so a secret finding has no baseline identity to compute -- and
    # refusing here means nothing in the ledger ever needs to hold secret-derived material.
    # Computing one "just in case" is how an offline-crackable oracle reaches a readable branch.
    if str(record.get('is_secret_finding', '')).strip().lower() in ('1', 'true', 'yes'):
        return _refuse(
            subject,
            R_SECRET_NOT_BASELINEABLE,
            'a secret finding is never grandfathered, so it has no baseline identity. The remedy '
            'is rotation, and "it was already in production" is the reason to rotate rather than '
            'a reason to schedule. Route to the secrets path, not to the ledger',
        )

    what, what_described, aliases = _derive_what(record)
    if what is None:
        return _refuse(subject, R_WHAT_UNDERIVABLE, what_described)

    where, where_described = _derive_where(record, subject)
    if where is None:
        return _refuse(subject, R_WHERE_UNDERIVABLE, where_described)

    # A coarse WHAT plus a repetitive CONTENT collides across genuinely different findings, and a
    # collision in identity is a finding that inherits another finding's approvals. The symbol
    # path is what separates them, so for a CWE-only WHAT it stops being optional.
    #
    # SOURCE_DEPENDENCY is deliberately NOT subject to this rule, and that is not a carve-out: it
    # has no symbol path to require, and it cannot reach here with a coarse WHAT in the first
    # place. Its locus REQUIRES a purl, and `_derive_what` prefers an advisory id and then the
    # purl ahead of cwe+family -- so a record that satisfies its WHERE has already answered its
    # WHAT with an externally anchored id. Requiring a symbol here would refuse every dependency
    # finding on a field no dependency finding has.
    if subject == 'SOURCE' and _what_is_coarse(what_described) and not _get(record, 'symbol_path'):
        return _refuse(
            subject,
            R_SYMBOL_REQUIRED,
            'WHAT is CWE-only (no advisory id, no purl), which is coarse enough that two '
            'different findings can share it. A symbol-level WHERE is what separates them, so '
            '`symbol_path` is required here. Without it two findings could share one identity, '
            'and the second would silently inherit the first\'s risk acceptance',
        )

    content, norm_id = _derive_content(record, subject)
    if content is None:
        return _refuse(subject, R_CONTENT_UNDERIVABLE, norm_id)

    spec = SPEC[subject]
    return {
        'state': FINGERPRINTED,
        'finding_subject': subject,
        # The three, carried separately. The cascade in section 5.3 needs them apart to tell MOVED from
        # NEW; a consumer that only ever reads `identity` gets exact-match and nothing else.
        'what': what,
        'where': where,
        'content': content,
        'identity': _h('IDENTITY/' + subject, [what, where, content]),
        'identity_scope': spec['scope'],
        'content_normalisation': norm_id,
        # Alias SET, not a single id: advisories split and merge, and section 5.6 matches on set
        # intersection rather than equality.
        'what_aliases': aliases,
        'what_described': what_described,
        'where_described': where_described,
    }


# ─────────────────────────────────────────────────────────────────────────────
def _selftest():
    """Exercises the SUCCESS path and the refusal path.

    A self-test that only exercises refusals proves the guard fires and proves nothing about the
    thing being guarded. This kit has shipped that mistake: a promotion routine printed
    "Promoted." while writing nothing, because only the blocked path was ever run.
    """
    fails = []

    def check(condition, message):
        if not condition:
            fails.append(message)

    # ── 1. SUCCESS: a source finding is fingerprintable ──────────────────────
    src = {
        'finding_subject': 'SOURCE',
        'cve': 'CVE-2024-1111',
        'canonical_path': 'services/worker/app.py',
        'symbol_path': 'worker.handler.process',
        'construct': 'subprocess.run(cmd, shell=True)',
        'language_family': 'hash',
        # Excluded fields, present and populated, to prove they do not participate.
        'scanner': 'trivy',
        'scanner_version': '0.52.0',
        'rule_id': 'PY-SEC-0042',
        'line': 41,
        'severity': 'HIGH',
        'commit_sha': 'aaaaaaaa',
        'run_id': '900001',
        'message': 'Found a subprocess call with shell=True at line 41',
    }
    a = identify(src)
    check(a['state'] == FINGERPRINTED, 'a complete SOURCE record was not fingerprinted: %r' % a)
    check(bool(a.get('identity')), 'FINGERPRINTED result carried no identity')
    check(
        a.get('identity_scope') == DURABLE,
        'SOURCE identity should be durable, got %r' % a.get('identity_scope'),
    )
    check(
        a['what'] != a['where'] and a['where'] != a['content'],
        'two components collided, so the domain labels are not separating them',
    )

    # ── 2. RESCAN: identical input, identical identity ───────────────────────
    check(identify(dict(src))['identity'] == a['identity'], 'a rescan of the same finding changed identity')

    # ── 3. UPGRADE IMMUNITY: mutate every excluded field, identity unchanged ──
    for key, why in EXCLUDED.items():
        mutated = dict(src)
        mutated[key] = 'MUTATED-VALUE-9999'
        result = identify(mutated)
        check(
            result['state'] == FINGERPRINTED and result['identity'] == a['identity'],
            'identity changed when `%s` changed -- that field is excluded because %s' % (key, why),
        )
    # The two headline cases, named explicitly so a failure reads as the defect it is.
    renamed = dict(src, rule_id='PY-SEC-0042-RENAMED-IN-0.53')
    check(
        identify(renamed)['identity'] == a['identity'],
        'a rule_id rename changed identity -- the baseline would reset at the next minor version',
    )
    swapped = dict(src, scanner='semgrep', scanner_version='1.90.0', tool='Semgrep OSS')
    check(
        identify(swapped)['identity'] == a['identity'],
        'a different scanner produced a different identity -- corroboration would read as duplication',
    )
    moved = dict(src, line=987, start_line=987, column=12)
    check(identify(moved)['identity'] == a['identity'], 'line movement changed identity')

    # ── 4. REAL CHANGE: a genuinely different finding differs ────────────────
    other_what = dict(src, cve='CVE-2024-2222')
    check(identify(other_what)['identity'] != a['identity'], 'a different advisory produced the same identity')
    other_where = dict(src, symbol_path='worker.handler.validate')
    check(identify(other_where)['identity'] != a['identity'], 'a different symbol produced the same identity')
    other_content = dict(src, construct='os.system(cmd)')
    check(identify(other_content)['identity'] != a['identity'], 'a different construct produced the same identity')

    # ── 5. CONTENT normalisation: reformat immune, constant-tweak immune ─────
    reformatted = dict(src, construct='subprocess.run(  cmd,\n    shell=True )   # noqa')
    check(
        identify(reformatted)['identity'] == a['identity'],
        'whitespace and a trailing comment changed identity -- a formatter rollout would '
        'manufacture NEW findings across the repository',
    )
    literal = {
        'finding_subject': 'SOURCE',
        'cwe': 'CWE-798',
        'rule_family': 'hardcoded-credential',
        'canonical_path': 'a.py',
        'symbol_path': 'm.f',
        'construct': 'connect(timeout=30, retries=3)',
    }
    literal_b = dict(literal, construct='connect(timeout=60, retries=5)')
    check(
        identify(literal)['identity'] == identify(literal_b)['identity'],
        'a numeric constant change produced a new identity in a source construct',
    )

    # ── 5b. A COMMENT MARKER INSIDE A STRING IS NOT A COMMENT (L40) ──────────
    #
    # Comment stripping used to cut at the first marker on the line, before placeholdering. For
    # the hash family `password = "hunter#2"` became `password = "hunter` -- an unterminated string
    # the placeholder could not match -- so a FRAGMENT OF THE LITERAL reached the hash. That breaks
    # the argument D-8 relies on to carry construct hashes past redaction: a literal destroyed
    # before hashing cannot be recovered. Under VALUES_VERBATIM it also collides two different
    # values that share a prefix before the marker, which is the permissive direction.
    def _ident_of(construct, family, subject='SOURCE'):
        base = dict(literal, construct=construct, language_family=family)
        if subject == 'IAC_PLAN':
            base = dict(iac_open_for_5b, attribute_path=construct, language_family=family)
        result = identify(base)
        check(result['state'] == FINGERPRINTED and bool(result.get('identity')),
              '5b: %r did not fingerprint, so nothing below can be compared: %r' % (construct, result))
        return result.get('identity') or ''

    iac_open_for_5b = {
        'finding_subject': 'IAC_PLAN', 'cwe': 'CWE-284', 'rule_family': 'f', 'module_path': '',
        'resource_type': 'r', 'resource_name': 'n',
    }
    # Literal-only differences must be erased in full. If ANY character of either literal reached
    # the hash input, these would differ -- that is the "no fragment reaches the hash" assertion,
    # stated over the public function rather than over a private helper.
    for family, marker in (('hash', '#'), ('c_like', '//'), ('sql', '--')):
        one = _ident_of('password = "hunter%s2"' % marker, family)
        two = _ident_of('password = "zz%s9 other"' % marker, family)
        plain = _ident_of('password = "x"', family)
        check(one and one == two == plain,
              '5b: family %s -- a %r inside a string literal truncated the construct, so a fragment '
              'of the literal reached the hash' % (family, marker))
    single = _ident_of("key = 'ab#cd'", 'hash')
    check(single and single == _ident_of("key = 'q'", 'hash'),
          '5b: a marker inside a SINGLE-quoted literal truncated the construct')
    escaped = _ident_of(r'v = "a\"#b"', 'hash')
    check(escaped and escaped == _ident_of('v = "x"', 'hash'),
          '5b: an escaped quote before the marker ended the string early')
    # A REAL comment after a string must still go -- or a reworded comment is a NEW finding.
    check(_ident_of('run("a#b")  # first wording', 'hash') == _ident_of('run("c")  # changed', 'hash'),
          '5b: a genuine comment after a string literal was not stripped')
    check(_ident_of('run("a")', 'hash') == _ident_of('run("a") # trailing', 'hash'),
          '5b: a trailing comment changed identity')
    # VALUES_VERBATIM: the value IS the finding, so two values sharing a prefix up to the marker
    # must NOT collide.
    # A snippet cut mid-literal: the open string's tail is placeholdered, never hashed as code.
    check(_ident_of('token = "abc#def', 'hash') == _ident_of('token = "zzz', 'hash'),
          '5b: an unterminated string handed the rest of its literal to the hash')
    check(_ident_of('p = "a\\\\"', 'hash') == _ident_of('p = "b"', 'hash'),
          '5b: a string ending in an escaped backslash was read as unterminated')
    v1 = _ident_of('tags = "team#1"', 'hash', subject='IAC_PLAN')
    v2 = _ident_of('tags = "team#2"', 'hash', subject='IAC_PLAN')
    check(v1 and v2 and v1 != v2,
          '5b: VALUES_VERBATIM -- "team#1" and "team#2" produced one identity, because the marker '
          'inside the string cut both values to the same prefix')

    # ── 6. VALUES_VERBATIM: the opposite, and it must be the opposite ────────
    # An IaC remediation MUST change identity. If it did not, a fixed finding would keep matching
    # its ledger entry and read as still open -- or worse, an introduced one would match a closed
    # entry and be grandfathered.
    iac_open = {
        'finding_subject': 'IAC_PLAN',
        'cwe': 'CWE-284',
        'rule_family': 'public-network-access',
        'module_path': '',  # root module -- present and empty, NOT missing
        'resource_type': 'azurerm_storage_account',
        'resource_name': 'artifacts',
        'attribute_path': 'public_network_access_enabled = true',
    }
    iac_fixed = dict(iac_open, attribute_path='public_network_access_enabled = false')
    ro = identify(iac_open)
    rf = identify(iac_fixed)
    check(ro['state'] == FINGERPRINTED, 'an IaC record with a ROOT module path was refused: %r' % ro)
    check(
        ro['identity'] != rf['identity'],
        'an IaC value change did not change identity -- a remediated finding would keep matching '
        'its ledger entry, and an introduced one could inherit a closed entry',
    )
    check(
        ro['content_normalisation'].startswith(VALUES_VERBATIM),
        'IaC content was not hashed verbatim: %r' % ro['content_normalisation'],
    )
    # The root-module empty string must not be interchangeable with a real module path.
    iac_module = dict(iac_open, module_path='module.platform')
    check(
        identify(iac_module)['identity'] != ro['identity'],
        'the root module and a named module produced the same locus',
    )

    # ── 7. Every subject has a working success path ──────────────────────────
    # Without this the table below is eight untested claims.
    samples = {
        'IMAGE': {
            'finding_subject': 'IMAGE',
            'cve': 'CVE-2024-3333',
            'package_name': 'openssl',
            'package_version': '3.0.11-r0',
            'image_digest': 'sha256:' + 'b' * 64,
        },
        'SOURCE_DEPENDENCY': {
            'finding_subject': 'SOURCE_DEPENDENCY',
            'cve': 'CVE-2018-18074',
            'purl': 'pkg:pypi/requests@2.19.1',
        },
        'RESOURCE': {
            'finding_subject': 'RESOURCE',
            'cwe': 'CWE-306',
            'rule_family': 'unauthenticated-endpoint',
            'resource_id': '/subscriptions/S/resourceGroups/G/providers/Microsoft.Web/sites/app',
            'property_path': 'properties.httpsOnly',
            'observed_value': 'false',
        },
        'IDENTITY_ASSIGNMENT': {
            'finding_subject': 'IDENTITY_ASSIGNMENT',
            'cwe': 'CWE-269',
            'rule_family': 'overbroad-grant',
            'principal_id': '00000000-0000-0000-0000-000000000001',
            'role_definition_id': 'b24988ac-6180-42a0-ab88-20f7382dd24c',
            'assignment_scope': '/subscriptions/S/resourceGroups/G',
        },
        'RUNTIME_OBSERVATION': {
            'finding_subject': 'RUNTIME_OBSERVATION',
            'cwe': 'CWE-693',
            'rule_family': 'missing-security-header',
            'target_host': 'app.example.test',
            'target_path': '/',
            'observed_condition': 'strict-transport-security absent',
        },
        'POLICY': {
            'finding_subject': 'POLICY',
            'cwe': 'CWE-1188',
            'rule_family': 'policy-effect-audit-only',
            'policy_definition_id': '/providers/Microsoft.Authorization/policyDefinitions/abc',
            'assignment_scope': '/providers/Microsoft.Management/managementGroups/root',
            'parameter_path': 'effect=Audit',
        },
        'RELEASE': {
            'finding_subject': 'RELEASE',
            'cwe': 'CWE-1104',
            'rule_family': 'unmaintained-component-aggregate',
            'release_id': 'r-2026-09-28-01',
        },
    }
    for subject, record in samples.items():
        result = identify(record)
        check(
            result['state'] == FINGERPRINTED,
            'subject %s has no working success path: %r' % (subject, result),
        )
        if result['state'] == FINGERPRINTED:
            expected = SPEC[subject]['scope']
            check(
                result['identity_scope'] == expected,
                'subject %s reported scope %r, spec says %r'
                % (subject, result['identity_scope'], expected),
            )
    # RELEASE is the one subject that must NOT claim durability.
    check(
        identify(samples['RELEASE'])['identity_scope'] == SINGLE_RELEASE,
        'RELEASE claimed durability across releases, which loses the finding at the next deploy',
    )
    # IMAGE identity must ignore the digest -- the field it most obviously "has".
    img = identify(samples['IMAGE'])
    check(
        identify(dict(samples['IMAGE'], image_digest='sha256:' + 'c' * 64))['identity'] == img['identity'],
        'the image digest reached the identity, so every rebuild would re-baseline the image',
    )
    check(
        img['content'] == CONTENT_NOT_APPLICABLE,
        'an IMAGE package finding produced a CONTENT hash where there is no construct to hash',
    )
    # A package upgrade IS a different finding.
    check(
        identify(dict(samples['IMAGE'], package_version='3.0.12-r0'))['identity'] != img['identity'],
        'an image package version change did not change identity',
    )
    # An optional CONTENT absent is a declared state, not a refusal.
    unconstrained = identify(samples['IDENTITY_ASSIGNMENT'])
    check(
        unconstrained['content'] == CONTENT_NOT_APPLICABLE,
        'an RBAC grant with no condition should carry a declared NOT_APPLICABLE content',
    )
    constrained = identify(dict(samples['IDENTITY_ASSIGNMENT'], condition_expression='@Resource[tag] StringEquals "x"'))
    check(
        constrained['identity'] != unconstrained['identity'],
        'adding a condition to a grant did not change identity, so a constrained grant and an '
        'unconstrained one would share one identity',
    )

    # ── 7b. D-3, BOTH HALVES. See the decision block above CONTENT_NOT_APPLICABLE ────
    #
    # These are regression guards on a JUDGEMENT, not on an implementation detail. The
    # permissive shortcut -- `content: '?construct'` on SOURCE -- is one character away forever
    # and it would make the first of these pass while silently disarming the second.
    d3 = identify({'finding_subject': 'SOURCE_DEPENDENCY', 'cve': 'CVE-2018-18074',
                   'purl': 'pkg:pypi/requests@2.19.1', 'canonical_path': 'requirements.txt'})
    check(
        d3['state'] == FINGERPRINTED,
        'D-3: the exact reproduction record -- a real advisory id and a real purl -- is still '
        'refused (%r / %r). A dependency finding carrying the two strongest inputs the model '
        'accepts must be fingerprintable.' % (d3.get('reason'), d3.get('detail')),
    )
    check(
        d3.get('content') == CONTENT_NOT_APPLICABLE,
        'D-3: a dependency finding produced a CONTENT hash. There is no matched construct to '
        'hash, and hashing one anyway is how "not applicable here" becomes indistinguishable '
        'from a real construct: got %r' % d3.get('content'),
    )
    # The manifest path must NOT reach the locus. If it does, every dependency finding in the
    # repository shares most of its WHERE, and a monorepo re-layout orphans all of them at once.
    dep = {'finding_subject': 'SOURCE_DEPENDENCY', 'cve': 'CVE-2018-18074',
           'purl': 'pkg:pypi/requests@2.19.1'}
    check(
        identify(dict(dep, canonical_path='services/api/requirements.txt'))['identity']
        == identify(dep)['identity'],
        'D-3: the manifest path reached the dependency locus, so moving a lockfile would orphan '
        'every disposition approved against the packages in it',
    )
    # A package UPGRADE is a different finding. The version is part of the coordinate.
    check(
        identify(dict(dep, purl='pkg:pypi/requests@2.31.0'))['identity']
        != identify(dep)['identity'],
        'D-3: two different package versions produced one identity, so an upgrade would inherit '
        'the vulnerable version\'s risk acceptance',
    )
    # THE OTHER HALF, AND THE ONE THAT ACTUALLY PROTECTS ANYTHING. SOURCE keeps its construct
    # mandatory: a code finding with no construct REFUSES rather than borrowing the sentinel.
    check(
        SPEC['SOURCE']['content'] == 'construct',
        'D-3: SPEC[SOURCE][content] is %r. It must stay mandatory -- spelled `?construct` it '
        'returns CONTENT_NOT_APPLICABLE_FOR_SUBJECT for a SAST finding whose construct was '
        'merely absent, which collapses "this subject has no construct" into "we could not read '
        'this one" and lets two injections in one function share one approval.'
        % SPEC['SOURCE']['content'],
    )
    no_construct = identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-89',
                             'rule_family': 'python.lang.security.audit.sqli',
                             'canonical_path': 'app/db/queries.py',
                             'symbol_path': 'app.db.queries.fetch_user'})
    check(
        no_construct['state'] == UNFINGERPRINTABLE
        and no_construct.get('reason') == R_CONTENT_UNDERIVABLE,
        'D-3: a SAST finding with no construct was NOT refused with %s (%r). Fixing the '
        'dependency case must not have made the code case permissive.'
        % (R_CONTENT_UNDERIVABLE, no_construct.get('reason')),
    )
    check(
        no_construct.get('identity') is None,
        'D-3: a SAST finding with no construct was refused and still carried a hash',
    )

    # ── 8. REFUSALS: each one refuses, names why, and carries NO hash ────────
    refusals = [
        ({}, R_SUBJECT_MISSING, 'no subject'),
        ({'finding_subject': 'ARTIFACT'}, R_SUBJECT_UNREGISTERED, 'unregistered subject'),
        (
            {
                'finding_subject': 'SOURCE',
                'canonical_path': 'a.py',
                'symbol_path': 'm.f',
                'construct': 'x',
                'rule_id': 'ONLY-A-RULE-ID',
            },
            R_WHAT_UNDERIVABLE,
            'a bare rule_id offered as WHAT',
        ),
        (
            {'finding_subject': 'SOURCE', 'cve': 'CVE-1', 'construct': 'x'},
            R_WHERE_UNDERIVABLE,
            'no canonical_path',
        ),
        (
            {'finding_subject': 'SOURCE', 'cve': 'CVE-1', 'canonical_path': 'a.py'},
            R_CONTENT_UNDERIVABLE,
            'no construct',
        ),
        (
            {
                'finding_subject': 'SOURCE',
                'cwe': 'CWE-89',
                'rule_family': 'sqli',
                'canonical_path': 'a.py',
                'construct': 'q = "SELECT " + v',
            },
            R_SYMBOL_REQUIRED,
            'CWE-only WHAT with no symbol path',
        ),
        (
            {
                'finding_subject': 'IAC_PLAN',
                'cwe': 'CWE-284',
                'rule_family': 'f',
                'module_path': '',
                'resource_type': '   ',
                'resource_name': 'n',
                'attribute_path': 'a = b',
            },
            R_WHERE_UNDERIVABLE,
            'a required locus field present but whitespace-only',
        ),
        (
            {
                'finding_subject': 'SOURCE',
                'cve': 'CVE-1',
                'canonical_path': 'a.py',
                'symbol_path': 'm.f',
                'construct': 'x',
                'is_secret_finding': 'true',
            },
            R_SECRET_NOT_BASELINEABLE,
            'a secret finding',
        ),
    ]
    for record, expected_reason, label in refusals:
        result = identify(record)
        check(
            result['state'] == UNFINGERPRINTABLE,
            '%s was fingerprinted and should have been refused: %r' % (label, result),
        )
        check(
            result.get('reason') == expected_reason,
            '%s refused with %r, expected %r' % (label, result.get('reason'), expected_reason),
        )
        check(result.get('identity') is None, '%s refused but still carried a hash' % label)
        check(
            result.get('routes_to') == ROUTES_TO,
            '%s refused without routing to %s' % (label, ROUTES_TO),
        )
        check(
            bool((result.get('detail') or '').strip()),
            '%s refused with an empty detail, which is a shrug rather than a refusal' % label,
        )

    # ── 9. The spec table is complete and self-consistent ───────────────────
    check(
        set(SPEC) == set(SUBJECTS),
        'SPEC and SUBJECTS disagree: %r' % (set(SPEC).symmetric_difference(set(SUBJECTS)),),
    )
    for subject, spec in SPEC.items():
        check(bool(spec.get('why_stable')), 'subject %s has no stated stability argument' % subject)
        # An excluded field must not appear in any locus. This is the structural guarantee stated
        # as an assertion, so widening a spec later cannot quietly reintroduce one.
        for key in spec['where']:
            check(
                key.lstrip('?=') not in EXCLUDED,
                'subject %s names excluded field `%s` in its locus' % (subject, key),
            )
        if spec['content']:
            check(
                spec['content'].lstrip('?') not in EXCLUDED,
                'subject %s names excluded field `%s` as content' % (subject, spec['content']),
            )

    if fails:
        print('finding_identity selftest FAILED (%d):' % len(fails))
        for f in fails:
            print('  - ' + f)
        return 1
    print(
        'finding_identity selftest ok: %d subjects each fingerprint; identity survives rule '
        'rename, scanner swap, version bump, line movement, reformat and image rebuild; '
        'IaC/RBAC value changes DO change it; %d excluded fields proven inert; %d refusal paths '
        'each name a reason and carry no hash'
        % (len(SUBJECTS), len(EXCLUDED), len(refusals))
    )
    return 0


def _explain():
    print('finding identity -- per-subject loci and why each field survives a rescan and an upgrade')
    print('')
    for subject in SUBJECTS:
        spec = SPEC[subject]
        required = [k for k in spec['where'] if not k.startswith('?')]
        optional = [k.lstrip('?') for k in spec['where'] if k.startswith('?')]
        print('%s  [%s]' % (subject, spec['scope']))
        print('  WHERE required : ' + ', '.join(k.lstrip('=') for k in required))
        if optional:
            print('  WHERE optional : ' + ', '.join(optional))
        print('  CONTENT        : %s (%s)' % (spec['content'] or CONTENT_NOT_APPLICABLE, spec['content_policy'] or 'n/a'))
        print('  WHY STABLE     : ' + re.sub(r'\s+', ' ', spec['why_stable']))
        print('')
    print('NEVER READ, and what each one breaks:')
    for key in sorted(EXCLUDED):
        print('  %-22s %s' % (key, EXCLUDED[key]))
    return 0


def main(argv):
    # `--self-test` is the kit's convention (14 other call sites). The unhyphenated spelling is
    # accepted because a near-miss flag would exit 2 from a workflow step, and a caller guessing
    # the wrong one should get the test rather than a usage error.
    if len(argv) == 2 and argv[1] in ('--self-test', '--selftest'):
        return _selftest()
    if len(argv) == 2 and argv[1] == '--explain':
        return _explain()
    if len(argv) != 2 or argv[1].startswith('-'):
        # An unrecognised flag is MISUSE, and it must not fall through to being opened as a
        # filename -- that produced a FileNotFoundError traceback, which in a workflow log reads
        # as the tool crashing rather than as the caller mistyping.
        print('usage: finding_identity.py <records.json> | --self-test | --explain', file=sys.stderr)
        return 2
    try:
        doc = json.load(io.open(argv[1], encoding='utf-8'))
    except IOError as exc:
        print('cannot read %s: %s' % (argv[1], exc), file=sys.stderr)
        return 2
    except ValueError as exc:
        # Unparseable input is a collection failure wearing a report's clothes. It is NOT zero
        # findings, and exiting 0 here would let a broken handoff read as "nothing to baseline".
        print('%s is not valid JSON: %s' % (argv[1], exc), file=sys.stderr)
        return 2
    records = doc if isinstance(doc, list) else [doc]
    out = [identify(r) for r in records]
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    print('')
    refused = sum(1 for r in out if r['state'] == UNFINGERPRINTABLE)
    print(
        '%d fingerprinted, %d UNFINGERPRINTABLE -> %s' % (len(out) - refused, refused, ROUTES_TO),
        file=sys.stderr,
    )
    # A refusal is not a tool failure. Exit 0 and let the caller route on the state -- exiting
    # non-zero here would make a correctly-refused finding indistinguishable from a broken run.
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
