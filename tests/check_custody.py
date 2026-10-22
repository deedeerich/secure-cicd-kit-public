#!/usr/bin/env python3
"""Custody manifest vs reality, and the one-way dependency the overlay must respect.

WHY A CHECK AND NOT A DOCUMENT

    A custody claim written down and never verified is the same shape as an invariant written down
    and never enforced -- which this estate has already proven gets violated anyway. The manifest
    says one capability is neutral and another belongs to an overlay. Nothing stops someone
    adding a third overlay-specific integration into the neutral core next month, and by then the
    provenance answer is "it has always been in there", which is exactly the answer with no defence.

THE ONE-WAY RULE

    the overlay  ──depends on──>  neutral core
    neutral core         ──MUST NOT──>    the overlay

    The neutral kit has to keep working standalone. If it ever needs the overlay to run, the
    overlay has stopped being an overlay and has become the product, and the custody line drawn in
    DEC-2026-09-14-001 stops being true regardless of what the manifest says.

WHAT IT CANNOT ESTABLISH
    Static, and manifest-driven. It proves the declared capabilities are present or absent as
    declared and that the core does not reference the overlay. It cannot decide whether a NEW
    capability was consumer-originated -- a person classifies that once, here, while it is still cheap.

EVERY OVERLAY, AND NONE (ledger L107)
    It read the FIRST ledger and the FIRST overlay directory only, so a second overlay that
    copied the pipeline, or a second ledger, was never looked at; and with no overlay at all it
    crashed on `os.path.exists(None)` -- the neutral kit could not run its own custody check.
    Every overlay and every ledger is now checked, and a tree with none passes.

THE CALL SHAPE (KDEC-008 OD-10)
    An overlay calls the kit cross-repository: `owner/repo/.github/workflows/reusable-security.yml
    @<40-hex sha>`. A `./` path resolves against the CALLER's checkout, so it works only inside
    the kit repository; a branch or tag is a moving pointer. Both are refused.
    tests/prove_custody_overlays.py runs this checker against constructed trees.

USAGE  python3 tests/check_custody.py [--root DIR]
EXIT   0 consistent      1 drift      2 self-test failed
"""
import csv
import io
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# THE LEDGER BELONGS TO WHOEVER IT DESCRIBES, NOT TO THE NEUTRAL KIT.
#
# This file used to live at docs/assurance/ inside the neutral core. It names an employer's
# entire declared toolchain -- build, test, design, AI tooling, their ticket-id digit range --
# and the neutral kit is intended to be shared. Publishing it would disclose one organisation's
# internals to every future consumer of the kit, which is a custody failure committed inside the
# custody checker.
#
# So the checker is generic and the ledger is the overlay's. Neutral enforces the SHAPE of the
# boundary -- core must never reference an overlay. WHO the overlay is, and what they declared,
# is theirs to state and theirs to keep.
def _find_manifests():
    """Every overlay's own custody ledger, discovered. None is not an error -- a neutral kit
    with no overlay has nothing to declare and must still pass."""
    out = []
    for d in sorted(glob.glob(os.path.join(ROOT, 'overlays', '*', 'docs'))):
        p = os.path.join(d, 'CAPABILITY_CUSTODY.csv')
        if os.path.exists(p):
            out.append(p)
    legacy = os.path.join(ROOT, 'docs', 'assurance', 'CAPABILITY_CUSTODY.csv')
    if os.path.exists(legacy):
        # Loud, not silent: its reappearance in neutral is the defect this move fixed.
        print('::error title=Custody ledger in neutral core::%s names an overlay owner and must '
              'live under overlays/<name>/docs/.' % legacy)
        out.append(legacy)
    return out


MANIFESTS = []
WF = ''

# Capability -> how to recognise it actually being invoked in a workflow.
# Deliberately the same shape as tests/capability_inventory.py: a NAME is not an invocation.
MARKERS = {
    'SonarCloud / SonarQube': [r'sonarsource/sonar', r'sonar-scanner'],
    'OWASP ZAP': [r'zaproxy/action-', r'zap-baseline', r'zap-full-scan'],
    'the work-item system reference validation': [r'/browse/\$\{|TICKET_PROJECT|TICKET_HOST'],
    'CodeQL': [r'codeql-action/(init|analyze|autobuild)'],
    'gitleaks': [r'gitleaks\s+(detect|dir|git)', r'zricethezav/gitleaks'],
    'Trivy': [r'trivy\s+(fs|image|config|repo)', r'aquasecurity/trivy'],
    # ADDED AFTER A FALSE CLAIM SHIPPED. A patch to add `p/xss` to the semgrep default silently
    # matched nothing -- the anchor had the wrong quote style -- and the manifest was updated to
    # say the capability existed anyway. Declared present, actually absent, committed.
    #
    # The check could not catch it because it only knew about capabilities listed in MARKERS, so
    # a capability with no marker was unverifiable BY CONSTRUCTION and silently skipped. A
    # manifest row nothing can check is a claim, not a control.
    'CodeQL taint tracking (security-extended)': [r'security-extended', r'security-and-quality'],
    'XSS ruleset (semgrep p/xss)': [r'p/xss'],
    'Trivy (filesystem: vuln + secret + licence)': [r'scanners:\s*vuln,secret,license'],
    'Trivy (container image)': [r'scan-type:\s*image'],
    'SBOM licence inventory': [r'sbom_licenses\.py'],
}

OVERLAY_ROOT = ''
# DISCOVERED, NEVER NAMED. An overlay identity hardcoded in the neutral core would be published
# to every future consumer of this kit. Direction of knowledge: overlay knows neutral; neutral
# knows only that an extension point exists.
OVERLAY_DIRS, OVERLAY_NAMES = [], []
# The one call shape an overlay may use to reach the core (KDEC-008 OD-10).
CORE_CALL = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/'
                       r'reusable-security\.yml@[0-9a-f]{40}$')


def configure(root):
    """Point every path at `root`. Module globals so the existing functions read them as before."""
    global ROOT, MANIFESTS, WF, OVERLAY_ROOT, OVERLAY_DIRS, OVERLAY_NAMES
    ROOT = os.path.abspath(root)
    WF = os.path.join(ROOT, '.github', 'workflows')
    OVERLAY_ROOT = os.path.join(ROOT, 'overlays')
    OVERLAY_DIRS = sorted(d for d in glob.glob(os.path.join(OVERLAY_ROOT, '*'))
                          if os.path.isdir(d))
    OVERLAY_NAMES = [os.path.basename(d) for d in OVERLAY_DIRS]
    MANIFESTS = _find_manifests()


def load():
    """Every ledger's rows, each tagged with the ledger it came from."""
    rows = []
    for m in MANIFESTS:
        with io.open(m, encoding='utf-8-sig', newline='') as fh:
            for r in csv.DictReader(fh):
                r['_ledger'] = os.path.relpath(m, ROOT).replace(os.sep, '/')
                rows.append(r)
    return rows


def workflow_text():
    """-> {path: text} for BOTH layers, keyed by a path that says which layer it is.

    Scanning only .github/workflows was fine while everything lived in one place. The moment the
    AM capabilities moved to overlays/, that check reported them as "declared implemented and
    invoked nowhere" -- a true statement about the wrong search scope. A checker that cannot see
    half the tree reports absence and means "I did not look there", which is the failure this
    estate keeps finding in other forms.
    """
    blobs = {}
    # The core's composites are core too: a scanner job's body lives in .github/actions/<scanner>/
    # since ledger L64, so detect-secrets, for one, is invoked nowhere else.
    actions = os.path.join(ROOT, '.github', 'actions')
    for base, tag in ((WF, 'core'), (actions, 'core'), (OVERLAY_ROOT, 'overlay')):
        if not os.path.isdir(base):
            continue
        for dp, _dn, fns in os.walk(base):
            for f in sorted(fns):
                if not f.endswith(('.yml', '.yaml')):
                    continue
                p = os.path.join(dp, f)
                key = '%s:%s' % (tag, os.path.relpath(p, ROOT).replace(os.sep, '/'))
                blobs[key] = io.open(p, encoding='utf-8', errors='replace').read()
    return blobs


def self_test():
    fails = []
    if not MANIFESTS:
        # NO OVERLAY IS NOT AN ERROR. A neutral kit with no overlay has nothing to declare.
        print('self-test ok: no overlay ledger present -- nothing is declared, nothing to check')
        return True
    for m in MANIFESTS:
        with io.open(m, encoding='utf-8-sig', newline='') as fh:
            rows = list(csv.DictReader(fh))
        where = os.path.relpath(m, ROOT).replace(os.sep, '/')
        if not rows:
            # A manifest that lists nothing would let this check pass while asserting nothing.
            fails.append('%s is empty; a custody check with no rows is not a pass' % where)
            continue
        need = {'Capability', 'Origin', 'Custody'}
        if not need <= set(rows[0].keys()):
            fails.append('%s is missing columns: %s' % (where, ', '.join(sorted(need - set(rows[0])))))
            continue
        cust = set(r['Custody'] for r in rows)
        known = {'neutral'} | set(OVERLAY_NAMES)
        if not cust <= known:
            fails.append('%s: unknown custody value(s): %s -- expected neutral or a directory '
                         'under overlays/ (%s)' % (where, ', '.join(sorted(cust - known)),
                                                   ', '.join(OVERLAY_NAMES) or 'none present'))
    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: manifest present, non-empty, and every custody value is known')
    return True


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    root = ROOT
    if '--root' in argv:
        root = argv[argv.index('--root') + 1]
    configure(root)
    if not self_test():
        return 2
    rows = load()
    blobs = workflow_text()
    problems, notes, unverifiable = [], [], []

    # 1. Declared-vs-present. A capability the manifest says is HERE must be invoked somewhere;
    #    one it says is absent must not have quietly appeared.
    for r in rows:
        cap = r['Capability']
        pats = MARKERS.get(cap)
        if not pats:
            # UNVERIFIABLE IS ITS OWN STATE. Skipping silently means the manifest can carry any
            # number of unchecked claims and still report "manifest and workflows agree".
            unverifiable.append(cap)
            continue
        found = sorted(f for f, t in blobs.items()
                       if any(re.search(p, t, re.I) for p in pats))
        in_core = [f for f in found if f.startswith('core:')]
        in_overlay = [f for f in found if f.startswith('overlay:')]
        declared_here = (r.get('Implemented before AM') == 'yes'
                         or r.get('Completed during AM') == 'yes')
        if declared_here and not found:
            problems.append('%s is declared implemented and is invoked nowhere' % cap)
        if not declared_here and found:
            problems.append('%s is declared NOT implemented but appears in %s -- classify its '
                            'origin before it becomes "it was always there"'
                            % (cap, ', '.join(found)))

        # PLACEMENT IS THE ENFORCEMENT. A manifest saying a capability is employer-originated
        # while the file sits in the neutral core is a declared boundary the tree does not
        # honour, and that is the state that becomes archaeology.
        if r['Custody'] in OVERLAY_NAMES and in_core:
            problems.append('%s is employer-custody and lives in the NEUTRAL CORE: %s -- move it '
                            'to overlays/, or reclassify it deliberately'
                            % (cap, ', '.join(in_core)))
        if r['Custody'] == 'neutral' and in_overlay and not in_core:
            problems.append('%s is neutral-custody and lives ONLY in an overlay: %s -- the core '
                            'cannot depend on an overlay, so this capability is unreachable to it'
                            % (cap, ', '.join(in_overlay)))

    # 2. THE ONE-WAY RULE. The neutral core must never reference the overlay.
    if OVERLAY_DIRS:
        for f, t in blobs.items():
            # THE KIT'S OWN CI IS EXEMPT, AND THE EXEMPTION IS NARROW.
            #
            # self-test.yml must see both layers -- testing that the core stands alone AND that
            # core-plus-overlay works is the entire point of the two-layer check. It is not a
            # consumer workflow and never runs in a consumer's repository.
            #
            # Named explicitly rather than pattern-matched: an exemption that grows by accident
            # is how a one-way rule quietly becomes a suggestion.
            if f == 'core:.github/workflows/self-test.yml':
                continue
            if f.startswith('core:') and re.search(r'overlays/', t):
                problems.append('neutral workflow %s references an overlay -- the dependency is '
                                'one-way and this reverses it' % f)
        # EVERY overlay with workflows must compose the core, by the one call shape (OD-10).
        for od in OVERLAY_DIRS:
            name = os.path.basename(od)
            wfs = sorted(glob.glob(os.path.join(od, 'workflows', '*.yml'))
                         + glob.glob(os.path.join(od, 'workflows', '*.yaml')))
            if not wfs:
                continue
            calls = []
            for w in wfs:
                txt = io.open(w, encoding='utf-8', errors='replace').read()
                for m in re.finditer(r'(?m)^\s*(?:-\s*)?uses:\s*["\']?([^\s"\'#]*reusable-security\.yml[^\s"\'#]*)',
                                     txt):
                    calls.append((os.path.relpath(w, ROOT).replace(os.sep, '/'), m.group(1)))
            if not calls:
                problems.append('overlay %s does not call the neutral core -- if it has copied the '
                                'pipeline instead of composing it, it is a fork' % name)
                continue
            for where, ref in calls:
                if not CORE_CALL.match(ref):
                    problems.append('%s calls the core as `%s` -- an overlay calls the kit '
                                    'cross-repository as owner/repo/.github/workflows/'
                                    'reusable-security.yml@<40-hex sha> (KDEC-008 OD-10); a ./ '
                                    'path resolves against the caller and a branch or tag moves'
                                    % (where, ref))
            notes.append('overlay %s composes the neutral core (%d call(s))' % (name, len(calls)))
    else:
        notes.append('no overlays/ directory; nothing has been separated yet')

    counts = {}
    for r in rows:
        counts[r['Origin']] = counts.get(r['Origin'], 0) + 1
    print('')
    print('CAPABILITY CUSTODY -- %d capability/capabilities' % len(rows))
    print('-' * 88)
    for k in sorted(counts):
        n_neutral = len([r for r in rows if r['Origin'] == k and r['Custody'] == 'neutral'])
        print('  %-32s %3d   (%d neutral / %d overlay)'
              % (k, counts[k], n_neutral, counts[k] - n_neutral))

    print('')
    print('ORIGIN IS NOT THE DATE IT BECAME REAL. Three capabilities are recorded as')
    print('PREEXISTING_NEUTRAL_INTENT with "annotated only" before the engagement -- CodeQL,')
    print('Dependabot and native secret scanning. CodeQL had twelve upload-sarif references and')
    print('zero init calls: a DEFECT in the neutral kit, found while working somewhere else.')
    print('Where a defect is discovered is not where the capability came from.')

    if unverifiable:
        print('')
        print('  %d manifest row(s) have no marker and were NOT checked:' % len(unverifiable))
        print('    %s' % ', '.join(sorted(unverifiable)[:8]))
        print('    These are claims, not controls. Agreement below covers only the rest.')
    if notes:
        print('')
        for n in notes:
            print('  NOTE: %s' % n)
    if problems:
        print('')
        print('DRIFT:')
        for p in problems:
            print('  - %s' % p)
        return 1
    print('')
    print('manifest and workflows agree; no neutral->overlay dependency')
    return 0


configure(ROOT)

if __name__ == '__main__':
    sys.exit(main())
