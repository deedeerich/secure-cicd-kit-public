#!/usr/bin/env python3
"""The deterministic identity of a CODE finding (SAST) and of a SECRET finding. (KDEC-038)

WHY THIS EXISTS

    The Release 4 end-to-end (public runs 41945270732, 41946786208) ticketed no SAST finding at all:
    bandit had no rule family (its B-codes are not namespaced, so the prefix tier found nothing),
    semgrep and CodeQL had no symbol (neither emits logicalLocations), and beneath both lay
    KNOWN_DEFECTS D-8 -- the redactor strips the SARIF snippet before the report reads it, so the
    construct could not be derived either. Secret findings were never ticketed: the baseline refuses
    them by design (it has no authority over secrets) and the ticket path had no other key.

    The owner, 2026-11-06: "close the gap for bandit, semgrep and codeql, basically SAST and secrets
    tickets."

THREE PARTS

    1  THE RULE-FAMILY ALIAS TABLE (sast_families, sast_aliases, CWE_FAMILY). A family is a CWE group
       with ONE canonical CWE. A tool's rule resolves to a family by, in order:
         a  the curated alias (tool, rule id) -> family. Authoritative: it is how a rule whose SARIF
            CWE is misleading (bandit tags exec and eval CWE-78; they are code injection) is placed;
         b  the rule's own CWE, through CWE_FAMILY;
         c  nothing: RULE_FAMILY_UNKNOWN, naming the tool, the rule and the CWE it carried. Never the
            bare rule id, never the rule's namespace prefix -- a guess that looks like an identity.
       Two tools reporting one weakness on one line therefore produce ONE WHAT (cwe + family), and
       that is what makes a bandit and a semgrep finding on the same code one identity.

       SOURCES, as recorded when the table was written (2026-11-06); re-verify on a tool upgrade:
         bandit   https://bandit.readthedocs.io/en/latest/plugins/index.html (test ids) and
                  bandit/core/issue.py (the CWE each test reports)
         semgrep  the `metadata.cwe` of each rule in https://github.com/semgrep/semgrep-rules
                  (the SARIF ruleId is the rule's registry path; its last segment is the rule id)
         CodeQL   https://codeql.github.com/codeql-query-help/ (each query's id and its
                  `external/cwe/cwe-NNN` tags)
         CWE      https://cwe.mitre.org/data/definitions/<n>.html (the grouping: a family is a
                  base weakness and the variants MITRE lists as its children, e.g. CWE-78 under
                  CWE-77, CWE-259 under CWE-798)

    2  THE CODE LOCATION, from the CHECKED-OUT SOURCE (the security-gate job checks out the scanned
       commit). The SARIF snippet is gone by then (D-8) and was never the same text across tools, so
       the line is read from the file itself:
         symbol      the enclosing def/class chain (Python, from the syntax tree); else the SARIF's
                     logicalLocations; else FILE SCOPE, said in the basis
         anchor      sha256 over the NORMALISED line (comments stripped, whitespace collapsed,
                     literals placeholdered -- finding_identity's own normalisation) and its ORDINAL
                     among identical normalised lines in the same scope. Never the line number: a
                     line shift keeps the anchor; the ordinal keeps two identical statements apart.
         construct   the line itself, so finding_identity's CONTENT exists again (D-8 closed for
                     every finding whose file is in the checkout). Literals are placeholdered
                     before hashing, so a credential on the line never reaches a hash.
         ticket key  sha256 over (repository, path, symbol, anchor, family, CWE) -- the ticket
                     anchor. The repository is in it, so the same code in two repositories is two
                     tickets; the family is in it, so two weaknesses on one line are two tickets.

    3  THE SECRET KEY: detector family + path + a NON-REVERSIBLE fingerprint of the matched material.
       The value is never stored, logged or hashed plainly: PBKDF2-HMAC-SHA256, 200,000 iterations,
       salted with the repository, truncated to 128 bits ('sfp1:<32 hex>'). It is computed in the
       secret-scan job BEFORE the redactor runs (gitleaks itself runs --redact, so the material is
       read from the file -- at the commit gitleaks named when it scanned history) and carried in the
       result's properties, which the redactor keeps. A rotated credential is a new fingerprint and
       so a new ticket, which is correct: a new credential leaked is a new incident.
       Secret tickets are URGENT and instruct ROTATION: removing a credential from the code does not
       un-leak it.

USAGE
    python3 code_finding_key.py --self-test
    python3 code_finding_key.py annotate-secrets --sarif F [--repo-root .] [--repository OWNER/REPO]
    from code_finding_key import resolve_sast_family, code_location, annotate_secrets, secret_ticket_key

EXIT  0 ok   1 refused   2 usage or self-test failure
"""
import ast
import functools
import hashlib
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SCHEMA = 'kit-code-finding-key/1'

# Refusals and states (assurance-taxonomy.yaml :: code_finding_key_state).
RULE_FAMILY_UNKNOWN = 'RULE_FAMILY_UNKNOWN'
SOURCE_NOT_AVAILABLE = 'SOURCE_NOT_AVAILABLE'
SOURCE_PATH_REFUSED = 'SOURCE_PATH_REFUSED'
SOURCE_LINE_OUT_OF_RANGE = 'SOURCE_LINE_OUT_OF_RANGE'
SOURCE_LINE_EMPTY = 'SOURCE_LINE_EMPTY'
SECRET_KEYED = 'SECRET_KEYED'
SECRET_FINGERPRINT_NOT_ESTABLISHED = 'SECRET_FINGERPRINT_NOT_ESTABLISHED'
secret_fp_property = 'kit_secret_fingerprint'
secret_fp_basis_property = 'kit_secret_fingerprint_basis'

# Mutation switches for tests/prove_sast_secret_tickets.py. The shipped values are the only correct ones.
anchor_ordinal = True
anchor_on_line_number = False
unknown_falls_back_to_rule_id = False

MAX_SOURCE_BYTES = 4 * 1024 * 1024
PBKDF2_ITERATIONS = 200000

# ─────────────────────────────────────────────────────────────────────────────────────────────
# 1  THE FAMILIES. family -> (canonical CWE, the CWEs that are this family, a sentence).
sast_families = {
    'os-command-injection': ('CWE-78', (77, 78, 88), 'a command assembled from input reaches a shell or exec'),
    'sql-injection': ('CWE-89', (89, 564, 943), 'a query assembled from input'),
    'code-injection': ('CWE-94', (94, 95, 96, 1336), 'input evaluated as code or as a template'),
    'cross-site-scripting': ('CWE-79', (79, 80, 83, 116), 'output not escaped for its context'),
    'path-traversal': ('CWE-22', (22, 23, 35, 36, 73), 'a path built from input escapes its directory'),
    'unsafe-deserialization': ('CWE-502', (502,), 'untrusted data deserialised into objects'),
    'xml-external-entity': ('CWE-611', (611, 776, 827), 'an XML parser that resolves external entities'),
    'server-side-request-forgery': ('CWE-918', (918,), 'a request target taken from input'),
    'hardcoded-credential': ('CWE-798', (798, 259, 321, 547), 'a credential written into the code'),
    'weak-cryptography': ('CWE-327', (327, 328, 326, 916, 1240), 'a broken or weak algorithm, mode or key'),
    'weak-randomness': ('CWE-330', (330, 331, 338), 'a non-cryptographic random source for a secret'),
    'certificate-validation-disabled': ('CWE-295', (295, 297), 'TLS or host verification turned off'),
    'cleartext-transmission': ('CWE-319', (319,), 'a protocol that sends data in clear'),
    'insecure-temporary-file': ('CWE-377', (377, 379), 'a predictable or shared temporary file'),
    'debug-enabled': ('CWE-489', (489, 215), 'a debug mode left on'),
    'bind-all-interfaces': ('CWE-605', (605, 1327), 'a listener bound to every interface'),
    'permissive-file-permissions': ('CWE-732', (732, 276), 'a file or directory made writable to all'),
    'open-redirect': ('CWE-601', (601,), 'a redirect target taken from input'),
    'missing-timeout': ('CWE-400', (400, 1088), 'a network call that can wait for ever'),
    'swallowed-exception': ('CWE-703', (703, 390, 754), 'an error silently passed over'),
    'assert-used': ('CWE-617', (617,), 'an assert that optimisation removes'),
    'cleartext-logging': ('CWE-532', (532, 312), 'sensitive data written to a log or in clear'),
    'cross-site-request-forgery': ('CWE-352', (352,), 'a state change without a request token'),
    'insecure-cookie': ('CWE-614', (614, 1004), 'a cookie without Secure or HttpOnly'),
    'regex-denial-of-service': ('CWE-1333', (1333, 730), 'a regular expression with catastrophic backtracking'),
    'ldap-injection': ('CWE-90', (90,), 'an LDAP filter assembled from input'),
    'xpath-injection': ('CWE-643', (643,), 'an XPath expression assembled from input'),
}
CWE_FAMILY = {}
for _fam, (_canon, _cwes, _why) in sast_families.items():
    for _n in _cwes:
        CWE_FAMILY[_n] = _fam

# The curated aliases: tool -> {rule id -> family}. bandit: the test id. semgrep: the LAST segment of
# the registry path (the rule's own `id:`), or a full path. CodeQL: the query id.
sast_aliases = {
    'bandit': {
        'B101': 'assert-used', 'B102': 'code-injection', 'B103': 'permissive-file-permissions',
        'B104': 'bind-all-interfaces', 'B105': 'hardcoded-credential', 'B106': 'hardcoded-credential',
        'B107': 'hardcoded-credential', 'B108': 'insecure-temporary-file', 'B110': 'swallowed-exception',
        'B112': 'swallowed-exception', 'B113': 'missing-timeout', 'B201': 'debug-enabled',
        'B202': 'path-traversal', 'B301': 'unsafe-deserialization', 'B302': 'unsafe-deserialization',
        'B303': 'weak-cryptography', 'B304': 'weak-cryptography', 'B305': 'weak-cryptography',
        'B306': 'insecure-temporary-file', 'B307': 'code-injection', 'B308': 'cross-site-scripting',
        'B311': 'weak-randomness', 'B312': 'cleartext-transmission', 'B313': 'xml-external-entity',
        'B314': 'xml-external-entity', 'B315': 'xml-external-entity', 'B316': 'xml-external-entity',
        'B317': 'xml-external-entity', 'B318': 'xml-external-entity', 'B319': 'xml-external-entity',
        'B320': 'xml-external-entity', 'B321': 'cleartext-transmission', 'B323': 'certificate-validation-disabled',
        'B324': 'weak-cryptography', 'B501': 'certificate-validation-disabled', 'B502': 'weak-cryptography',
        'B503': 'weak-cryptography', 'B504': 'weak-cryptography', 'B505': 'weak-cryptography',
        'B506': 'unsafe-deserialization', 'B507': 'certificate-validation-disabled',
        'B601': 'os-command-injection', 'B602': 'os-command-injection', 'B603': 'os-command-injection',
        'B604': 'os-command-injection', 'B605': 'os-command-injection', 'B606': 'os-command-injection',
        'B607': 'os-command-injection', 'B608': 'sql-injection', 'B609': 'os-command-injection',
        'B610': 'sql-injection', 'B611': 'sql-injection', 'B612': 'code-injection', 'B614': 'unsafe-deserialization',
        'B701': 'cross-site-scripting', 'B702': 'cross-site-scripting', 'B703': 'cross-site-scripting',
    },
    'semgrep': {
        'subprocess-shell-true': 'os-command-injection', 'dangerous-subprocess-use': 'os-command-injection',
        'dangerous-system-call': 'os-command-injection', 'dangerous-spawn-process': 'os-command-injection',
        'formatted-sql-query': 'sql-injection', 'sqlalchemy-execute-raw-query': 'sql-injection',
        'avoid-sqlalchemy-text': 'sql-injection', 'tainted-sql-string': 'sql-injection',
        'eval-detected': 'code-injection', 'exec-detected': 'code-injection',
        'avoid-pickle': 'unsafe-deserialization', 'avoid-pyyaml-load': 'unsafe-deserialization',
        'avoid-unsafe-ruamel': 'unsafe-deserialization', 'insecure-hash-algorithm-md5': 'weak-cryptography',
        'insecure-hash-algorithm-sha1': 'weak-cryptography', 'insecure-cipher-algorithm-des': 'weak-cryptography',
        'disabled-cert-validation': 'certificate-validation-disabled', 'debug-enabled': 'debug-enabled',
        'avoid-bind-to-all-interfaces': 'bind-all-interfaces', 'insecure-file-permissions': 'permissive-file-permissions',
        'detected-jinja2-autoescape-false': 'cross-site-scripting', 'direct-use-of-jinja2': 'cross-site-scripting',
        'open-redirect': 'open-redirect', 'ssrf-requests': 'server-side-request-forgery',
        'use-defused-xml': 'xml-external-entity', 'request-session-with-http': 'cleartext-transmission',
        'tempfile-insecure': 'insecure-temporary-file', 'no-auth-over-http': 'cleartext-transmission',
    },
    'codeql': {
        'py/command-line-injection': 'os-command-injection', 'js/command-line-injection': 'os-command-injection',
        'java/command-line-injection': 'os-command-injection', 'cs/command-line-injection': 'os-command-injection',
        'go/command-injection': 'os-command-injection', 'rb/command-line-injection': 'os-command-injection',
        'py/shell-command-constructed-from-input': 'os-command-injection',
        'py/sql-injection': 'sql-injection', 'js/sql-injection': 'sql-injection', 'java/sql-injection': 'sql-injection',
        'cs/sql-injection': 'sql-injection', 'go/sql-injection': 'sql-injection', 'rb/sql-injection': 'sql-injection',
        'py/code-injection': 'code-injection', 'js/code-injection': 'code-injection', 'rb/code-injection': 'code-injection',
        'py/reflective-xss': 'cross-site-scripting', 'js/reflected-xss': 'cross-site-scripting',
        'js/xss': 'cross-site-scripting', 'java/xss': 'cross-site-scripting', 'cs/web/xss': 'cross-site-scripting',
        'py/path-injection': 'path-traversal', 'js/path-injection': 'path-traversal', 'java/path-injection': 'path-traversal',
        'go/path-injection': 'path-traversal', 'py/tarslip': 'path-traversal', 'js/zipslip': 'path-traversal',
        'py/unsafe-deserialization': 'unsafe-deserialization', 'js/unsafe-deserialization': 'unsafe-deserialization',
        'java/unsafe-deserialization': 'unsafe-deserialization',
        'py/xxe': 'xml-external-entity', 'js/xxe': 'xml-external-entity', 'java/xxe': 'xml-external-entity',
        'py/full-ssrf': 'server-side-request-forgery', 'py/partial-ssrf': 'server-side-request-forgery',
        'js/request-forgery': 'server-side-request-forgery', 'go/request-forgery': 'server-side-request-forgery',
        'py/weak-sensitive-data-hashing': 'weak-cryptography', 'py/weak-cryptographic-algorithm': 'weak-cryptography',
        'js/weak-cryptographic-algorithm': 'weak-cryptography', 'js/insufficient-password-hash': 'weak-cryptography',
        'py/request-without-cert-validation': 'certificate-validation-disabled',
        'js/disabling-certificate-validation': 'certificate-validation-disabled',
        'py/flask-debug': 'debug-enabled', 'py/bind-socket-all-network-interfaces': 'bind-all-interfaces',
        'py/url-redirection': 'open-redirect', 'js/server-side-unvalidated-url-redirection': 'open-redirect',
        'py/clear-text-logging-sensitive-data': 'cleartext-logging', 'js/clear-text-logging': 'cleartext-logging',
        'py/clear-text-storage-sensitive-data': 'cleartext-logging', 'py/hardcoded-credentials': 'hardcoded-credential',
        'js/hardcoded-credentials': 'hardcoded-credential', 'java/hardcoded-credential-api-call': 'hardcoded-credential',
        'py/polynomial-redos': 'regex-denial-of-service', 'js/polynomial-redos': 'regex-denial-of-service',
        'py/redos': 'regex-denial-of-service', 'js/redos': 'regex-denial-of-service',
        'py/insecure-temporary-file': 'insecure-temporary-file', 'js/insecure-temporary-file': 'insecure-temporary-file',
        'py/overly-permissive-file': 'permissive-file-permissions', 'js/missing-token-validation': 'cross-site-request-forgery',
        'py/ldap-injection': 'ldap-injection', 'py/xpath-injection': 'xpath-injection',
        'py/insecure-cookie': 'insecure-cookie', 'js/clear-text-cookie': 'insecure-cookie',
    },
}
CURATED_TOOLS = tuple(sorted(sast_aliases))
# The secret scanners (scan_report names the same three).
SECRET_TOOLS = ('gitleaks', 'detect-secrets', 'trufflehog')

# Secret detector families: detector (rule id / plugin / detector name, lower-case) -> family.
secret_families = {
    'aws-access-token': 'aws-access-key', 'aws-access-key': 'aws-access-key', 'awskeydetector': 'aws-access-key',
    'aws': 'aws-access-key', 'aws-secret-key': 'aws-secret-key',
    'github-pat': 'github-token', 'github-fine-grained-pat': 'github-token', 'github-oauth': 'github-token',
    'github-app-token': 'github-token', 'github-refresh-token': 'github-token', 'githubtokendetector': 'github-token',
    'github': 'github-token',
    'private-key': 'private-key', 'privatekeydetector': 'private-key', 'privatekey': 'private-key',
    'slack-bot-token': 'slack-token', 'slack-user-token': 'slack-token', 'slack-webhook-url': 'slack-token',
    'slackdetector': 'slack-token', 'slack': 'slack-token',
    'jwt': 'jwt', 'jwttokendetector': 'jwt',
    'azure-storage-connection-string': 'azure-storage-key', 'azure-storage-account-key': 'azure-storage-key',
    'azurestoragekeydetector': 'azure-storage-key', 'azurestorage': 'azure-storage-key',
    'azure-sas-token': 'azure-sas-token', 'azure-shared-access-key': 'azure-shared-access-key',
    'azure-iothub-connection-string': 'azure-shared-access-key', 'azure-cosmos-key': 'azure-cosmos-key',
    'azure-sql-connection-string': 'database-credential', 'azure-redis-key': 'azure-redis-key',
    'entra-client-secret-value': 'entra-client-secret', 'entra-client-secret-assignment': 'entra-client-secret',
    'azure-ad-client-secret': 'entra-client-secret', 'azure-service-principal-password-cli': 'entra-client-secret',
    'azure-devops-pat': 'azure-devops-pat', 'azure-subscription-key': 'azure-subscription-key',
    'azure-publish-settings': 'azure-publish-profile',
    'generic-api-key': 'generic-secret', 'keyworddetector': 'generic-secret',
    'base64highentropystring': 'generic-secret', 'hexhighentropystring': 'generic-secret',
}

secret_remedy = (
    'ROTATE the credential now: revoke or regenerate it at its issuer, and update every system that uses it. '
    'Removing it from the code does not un-leak it -- it is in the history, in every clone and fork, and in '
    'every log or artifact that held it. Then remove it from the code and the history, and confirm the old '
    'value is dead (an authentication attempt with it fails). This ticket closes on a person confirming the '
    'rotation, never on the scanner no longer seeing it.')


def _s(v):
    return v.strip() if isinstance(v, str) else ''


def _h(label, parts):
    return hashlib.sha256((label + '\x1f' + '\x1f'.join(parts)).encode('utf-8', 'replace')).hexdigest()


def tool_of(scanner, tool=''):
    """-> 'bandit' | 'semgrep' | 'codeql' | '' (a tool outside the curated table)."""
    for name in (_s(scanner).lower(), _s(tool).lower()):
        for t in CURATED_TOOLS:
            if t in name:
                return t
    return ''


def is_secret_tool(name):
    n = _s(name).lower()
    return any(t in n for t in SECRET_TOOLS)


def cwe_number(cwe):
    """The CWE's number through THE shared normaliser (scripts/finding_ids.py, owner 2026-11-06): every
    tool's spelling (CWE-79, cwe-079, external/cwe/cwe-079, cwe:79, Bandit's {"id": 79}) is one CWE, and a
    form it does not know is no CWE at all -- never the first digits found in the text."""
    import finding_ids
    vals = cwe if isinstance(cwe, (list, tuple)) else [cwe]
    for v in vals:
        c, _why = finding_ids.normalize_cwe(v, numeric_ok=True)
        if c:
            return int(c[4:])
    return None


@functools.lru_cache(maxsize=1)
def reviewed_rule_mappings():
    """The rule-family mappings people made for unknown rules (id-mappings.json at the kit root)."""
    import unknown_ids
    applied, _refused = unknown_ids.load_mappings(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return tuple(m for m in applied if m.get('kind') == 'rule-family')


def resolve_sast_family(scanner, tool, rule_id, cwe=''):
    """-> (family, canonical_cwe, basis) or (None, None, refusal detail naming RULE_FAMILY_UNKNOWN)."""
    t = tool_of(scanner, tool)
    rid = _s(rule_id)
    aliases = sast_aliases.get(t) or {}
    fam = aliases.get(rid)
    how = 'curated alias %s %r' % (t, rid)
    if not fam and t == 'semgrep' and '.' in rid:
        fam = aliases.get(rid.rsplit('.', 1)[-1])
        how = 'curated alias semgrep %r (the rule id at the end of its registry path)' % rid.rsplit('.', 1)[-1]
    if not fam:
        # A MAPPING A PERSON MADE, as a reviewed change (id-mappings.json: author, date, review_ref;
        # scripts/unknown_ids.py). Only reviewed entries apply; nothing is ever guessed here.
        for m in reviewed_rule_mappings():
            if str(m.get('tool')).lower() == t and str(m.get('rule')) == rid and m.get('family') in sast_families:
                fam = m['family']
                how = 'reviewed mapping by %s on %s (%s)' % (m.get('author'), m.get('date'), m.get('review_ref'))
                break
    n = cwe_number(cwe)
    if not fam and n is not None and n in CWE_FAMILY:
        fam = CWE_FAMILY[n]
        how = 'the rule\'s own CWE-%d, through the family table' % n
    if fam:
        return fam, sast_families[fam][0], 'rule family %s (%s; canonical %s)' % (fam, how, sast_families[fam][0])
    if unknown_falls_back_to_rule_id and rid:      # mutant M5 only
        return rid, 'CWE-%s' % (n or 0), 'MUTANT: the bare rule id'
    return None, None, ('%s: %s rule %r (%s) is in neither the curated alias table nor, by its CWE, the family '
                        'table. Add an alias (scripts/code_finding_key.py sast_aliases, with its source): a bare '
                        'rule id or its namespace prefix is never a substitute' % (
                            RULE_FAMILY_UNKNOWN, t or (_s(scanner) or _s(tool) or 'unknown tool'), rid,
                            ('CWE-%d' % n) if n is not None else 'none'))


# ─────────────────────────────────────────────────────────────────────────────────────────────
# 2  THE CODE LOCATION
def _safe_path(root, rel):
    """-> (absolute path, '') or ('', refusal). Inside the checkout only: no absolute path, no '..',
    no symlink out."""
    rel = _s(rel)
    if rel.startswith('file://'):
        rel = rel[len('file://'):]
    if not rel:
        return '', '%s: no path' % SOURCE_PATH_REFUSED
    rroot = os.path.realpath(root)
    cand = rel.replace('\\', '/')
    if os.path.isabs(cand) or re.match(r'^[A-Za-z]:', cand):
        absn = os.path.realpath(cand)
        if not (absn == rroot or absn.startswith(rroot + os.sep)):
            return '', '%s: %r is not inside the checkout' % (SOURCE_PATH_REFUSED, rel)
        return absn, ''
    if '..' in cand.split('/'):
        return '', '%s: %r climbs out of the checkout' % (SOURCE_PATH_REFUSED, rel)
    absn = os.path.realpath(os.path.join(rroot, *[p for p in cand.split('/') if p and p != '.']))
    if not (absn == rroot or absn.startswith(rroot + os.sep)):
        return '', '%s: %r resolves outside the checkout' % (SOURCE_PATH_REFUSED, rel)
    return absn, ''


def read_lines(root, rel):
    """-> (lines, '') or (None, why). A file with many findings is read once (cached on its path, size and
    modification time, so a rewritten file is read again)."""
    if not root or not os.path.isdir(root):
        return None, '%s: no checkout to read' % SOURCE_NOT_AVAILABLE
    p, bad = _safe_path(root, rel)
    if bad:
        return None, bad
    if not os.path.isfile(p):
        return None, '%s: %s is not in the checkout' % (SOURCE_NOT_AVAILABLE, rel)
    st = os.stat(p)
    if st.st_size > MAX_SOURCE_BYTES:
        return None, '%s: %s is larger than %d bytes' % (SOURCE_NOT_AVAILABLE, rel, MAX_SOURCE_BYTES)
    return list(_read_file(p, st.st_size, st.st_mtime_ns)), ''


@functools.lru_cache(maxsize=64)
def _read_file(path, _size, _mtime_ns):
    with io.open(path, 'rb') as fh:
        return tuple(fh.read().decode('utf-8', 'replace').split('\n'))


def normalised(line, family):
    import finding_identity as fi
    t = fi._strip_line_comments(line, family)
    t = fi._norm_ws(t)
    return fi._placeholder_literals(t, family)


@functools.lru_cache(maxsize=64)
def python_scopes(text):
    """-> ((start, end, qualified name), ...) for every def and class. None when unparseable."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    out = []

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = '%s.%s' % (prefix, ch.name) if prefix else ch.name
                start = min([ch.lineno] + [d.lineno for d in getattr(ch, 'decorator_list', [])])
                out.append((start, getattr(ch, 'end_lineno', None) or ch.lineno, name))
                walk(ch, name)
            else:
                walk(ch, prefix)
    walk(tree, '')
    return tuple(out)


def code_location(source_root, path, line, sarif_symbol='', family=''):
    """-> dict {symbol_path, code_anchor, construct, scope, basis} or {refused: why}.

    `family` is the declared comment family (scan_report.language_family_of)."""
    try:
        n = int(line or 0)
    except (TypeError, ValueError):
        n = 0
    lines, why = read_lines(source_root, path)
    if lines is None:
        return {'refused': why}
    if n < 1 or n > len(lines):
        return {'refused': '%s: line %s of %s (%d lines) -- the checkout is not the scanned commit, or the '
                           'scanner named no line' % (SOURCE_LINE_OUT_OF_RANGE, line, path, len(lines))}
    raw = lines[n - 1].rstrip('\r')
    norm = normalised(raw, family)
    if not norm.strip():
        return {'refused': '%s: line %d of %s is blank or a comment once normalised' % (SOURCE_LINE_EMPTY, n, path)}
    symbol, scope, basis = '', (1, len(lines)), ''
    if path.lower().endswith('.py'):
        scopes = python_scopes('\n'.join(lines))
        if scopes:
            inner = [s for s in scopes if s[0] <= n <= s[1]]
            if inner:
                best = max(inner, key=lambda s: (s[0], -s[1]))
                symbol, scope = best[2], (best[0], best[1])
                basis = 'symbol %s from the Python syntax tree' % symbol
            else:
                symbol, basis = '<module>', 'module level (Python syntax tree)'
        elif scopes is None:
            basis = 'the Python file does not parse'
    if not symbol and _s(sarif_symbol):
        symbol, basis = _s(sarif_symbol), 'symbol %s from the SARIF logicalLocations' % _s(sarif_symbol)
    if not symbol:
        basis = (basis + '; ' if basis else '') + 'file scope: no symbol derivable for this language, so the anchor ' \
            'is the normalised line and its ordinal in the file'
    ordinal = 0
    for i in range(scope[0], min(scope[1], len(lines)) + 1):
        if normalised(lines[i - 1].rstrip('\r'), family) == norm:
            ordinal += 1
        if i == n:
            break
    parts = [symbol or '<file>', norm, str(ordinal) if anchor_ordinal else '-']
    if anchor_on_line_number:          # mutant M2 only
        parts = [symbol or '<file>', str(n)]
    anchor = _h('code-anchor/1', parts)[:32]
    return {'symbol_path': symbol, 'code_anchor': anchor, 'construct': raw, 'ordinal': ordinal,
            'scope': 'symbol' if symbol else 'file',
            'basis': '%s; anchor = normalised line + ordinal %d in its %s (never the line number)'
                     % (basis, ordinal, 'symbol' if symbol else 'file')}


def code_ticket_key(repository, path, symbol, anchor, family, cwe):
    """THE TICKET ANCHOR of a code finding: repository + path + symbol + anchor + family + CWE."""
    return _h('code-finding-key/1', [_s(repository).lower(), _s(path), _s(symbol) or '<file>', _s(anchor),
                                     _s(family), _s(cwe).upper()])[:32]


# ─────────────────────────────────────────────────────────────────────────────────────────────
# 3  SECRETS
def secret_family(detector):
    d = re.sub(r'\s+', '', _s(detector).lower())
    fam = secret_families.get(d)
    if fam:
        return fam, 'detector %r is the %s family' % (_s(detector), fam)
    return (d or 'unnamed-detector'), ('detector %r is not in the secret family table: keyed on its own name, so a '
                                       'second tool naming it differently is a second ticket' % _s(detector))


def secret_fingerprint(material, repository):
    """NON-REVERSIBLE: PBKDF2-HMAC-SHA256, salted with the repository, 200,000 iterations, 128 bits."""
    dk = hashlib.pbkdf2_hmac('sha256', material.encode('utf-8', 'replace'),
                             ('kit-secret-fp/1\x1f%s' % _s(repository).lower()).encode('utf-8'),
                             PBKDF2_ITERATIONS, 16)
    return 'sfp1:' + dk.hex()


def secret_ticket_key(detector, path, fingerprint):
    fam, _why = secret_family(detector)
    return _h('secret-key/1', [fam, _s(path), _s(fingerprint)])[:32]


def _git_show(root, sha, path):
    if not re.match(r'^[0-9a-f]{7,64}$', _s(sha)):
        return None
    try:
        p = subprocess.run(['git', '-C', root, 'show', '%s:%s' % (sha, path.replace('\\', '/'))],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    return p.stdout.decode('utf-8', 'replace').split('\n')


def _region_text(lines, region):
    """The matched region's text. Columns are SARIF's (1-based, end exclusive); absent columns take the
    whole line. -> '' when the region is not in the lines."""
    try:
        sl = int(region.get('startLine') or 0)
        el = int(region.get('endLine') or sl)
    except (TypeError, ValueError):
        return ''
    if sl < 1 or sl > len(lines) or el < sl:
        return ''
    chunk = [lines[i - 1].rstrip('\r') for i in range(sl, min(el, len(lines)) + 1)]
    sc, ec = region.get('startColumn'), region.get('endColumn')
    if isinstance(ec, int) and ec > 0:
        chunk[-1] = chunk[-1][:ec - 1]
    if isinstance(sc, int) and sc > 0:
        chunk[0] = chunk[0][sc - 1:]
    return '\n'.join(chunk).strip()


def annotate_secrets(doc, repo_root, repository):
    """Fingerprint every secret result IN PLACE, before redaction. -> counts. The material is read from
    the commit the scanner named (history mode), else the working tree; it is never written anywhere."""
    stats = {'results': 0, 'fingerprinted': 0, 'not_established': 0}
    for run in (doc.get('runs') or []):
        for res in (run.get('results') or []):
            stats['results'] += 1
            props = res.setdefault('properties', {}) if isinstance(res.get('properties', {}), dict) else {}
            loc = ((res.get('locations') or [{}])[0].get('physicalLocation') or {})
            path = _s((loc.get('artifactLocation') or {}).get('uri'))
            region = loc.get('region') or {}
            sha = _s(((res.get('partialFingerprints') or {}).get('commitSha')))
            lines, basis = None, ''
            if sha:
                lines = _git_show(repo_root, sha, path)
                basis = 'the file at commit %s (history mode)' % sha[:12]
            if lines is None and not sha:
                lines, why = read_lines(repo_root, path)
                basis = 'the working tree' if lines is not None else why
            material = _region_text(lines, region) if lines is not None else ''
            if material:
                props[secret_fp_property] = secret_fingerprint(material, repository)
                props[secret_fp_basis_property] = 'pbkdf2-sha256/%d, read from %s' % (PBKDF2_ITERATIONS, basis)
                stats['fingerprinted'] += 1
            else:
                props[secret_fp_basis_property] = '%s: the matched region could not be read (%s)' % (
                    SECRET_FINGERPRINT_NOT_ESTABLISHED, basis or 'no path or region')
                stats['not_established'] += 1
            material = ''
    return stats


# ─────────────────────────────────────────────────────────────────────────────────────────────
def _selftest():
    fails = []
    f, c, _b = resolve_sast_family('bandit', 'Bandit', 'B602', 'CWE-78')
    g, d, _b = resolve_sast_family('semgrep', 'Semgrep OSS', 'python.lang.security.audit.subprocess-shell-true.'
                                   'subprocess-shell-true', 'CWE-78')
    h, e, _b = resolve_sast_family('codeql', 'CodeQL', 'py/command-line-injection', 'CWE-078')
    if not (f == g == h == 'os-command-injection' and c == d == e == 'CWE-78'):
        fails.append('three tools on one weakness do not share a family: %r' % ((f, g, h),))
    if resolve_sast_family('bandit', '', 'B999', '')[0] is not None:
        fails.append('an unknown rule resolved')
    if resolve_sast_family('bandit', '', 'B102', 'CWE-78')[0] != 'code-injection':
        fails.append('the curated alias did not outrank the misleading CWE')
    for fam, (canon, cwes, _w) in sast_families.items():
        if cwe_number(canon) not in cwes:
            fails.append('family %s: its canonical %s is not one of its CWEs' % (fam, canon))
    for t, table in sast_aliases.items():
        for rid, fam in table.items():
            if fam not in sast_families:
                fails.append('alias %s %s names an unknown family %s' % (t, rid, fam))
    fp = secret_fingerprint('x' * 20, 'o/r')
    if not fp.startswith('sfp1:') or fp == secret_fingerprint('x' * 20, 'o/other') or len(fp) != 37:
        fails.append('the secret fingerprint is not salted by repository or has the wrong shape')
    if fails:
        for x in fails:
            sys.stderr.write('FAIL: %s\n' % x)
        return 2
    print('code_finding_key selftest ok: %d families, %d curated aliases across %s; three tools on one weakness '
          'share a family; an unknown rule refuses; the secret fingerprint is salted and slow. The end-to-end cases '
          'run in tests/prove_sast_secret_tickets.py.' % (len(sast_families), sum(len(t) for t in sast_aliases.values()),
                                                         ', '.join(CURATED_TOOLS)))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (['--self-test'], ['--selftest']):
        return _selftest()
    if argv and argv[0] == 'annotate-secrets':
        import argparse
        ap = argparse.ArgumentParser(prog='code_finding_key.py annotate-secrets')
        ap.add_argument('--sarif', required=True)
        ap.add_argument('--repo-root', default='.')
        ap.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', ''))
        a = ap.parse_args(argv[1:])
        if not os.path.isfile(a.sarif) or os.path.getsize(a.sarif) == 0:
            print('no SARIF at %s: nothing to fingerprint' % a.sarif)
            return 0
        try:
            doc = json.load(io.open(a.sarif, encoding='utf-8'))
        except ValueError:
            print('::warning title=%s::%s is not JSON; no secret was fingerprinted (the findings still block)'
                  % (SECRET_FINGERPRINT_NOT_ESTABLISHED, a.sarif))
            return 0
        stats = annotate_secrets(doc, a.repo_root, a.repository)
        tmp = a.sarif + '.kit-tmp'
        with io.open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(doc, fh)
        os.replace(tmp, a.sarif)
        print('secret fingerprints: %(fingerprinted)d of %(results)d result(s); %(not_established)d not established '
              '(each still blocks, and still tickets once its region can be read)' % stats)
        return 0
    print('usage: code_finding_key.py --self-test | annotate-secrets --sarif F [--repo-root D] [--repository O/R]',
          file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
