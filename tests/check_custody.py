#!/usr/bin/env python3
"""Custody manifest vs reality, and the one-way dependency the overlay must respect.

WHY A CHECK AND NOT A DOCUMENT

    A custody claim written down and never verified is the same shape as an invariant written down
    and never enforced -- which this estate has already proven gets violated anyway. The manifest
    says one capability is neutral and another belongs to an overlay. Nothing stops someone
    adding a third AM-specific integration into the neutral core next month, and by then the
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
    capability was AM-originated -- a person classifies that once, here, while it is still cheap.

USAGE  python3 tests/check_custody.py
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


MANIFESTS = _find_manifests()
MANIFEST = MANIFESTS[0] if MANIFESTS else None
WF = os.path.join(ROOT, '.github', 'workflows')

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

OVERLAY_ROOT = os.path.join(ROOT, 'overlays')
# DISCOVERED, NEVER NAMED. An overlay identity hardcoded in the neutral core would be published
# to every future consumer of this kit. Direction of knowledge: overlay knows neutral; neutral
# knows only that an extension point exists.
OVERLAY_DIRS = sorted(d for d in glob.glob(os.path.join(OVERLAY_ROOT, '*')) if os.path.isdir(d))
OVERLAY_NAMES = [os.path.basename(d) for d in OVERLAY_DIRS]
OVERLAY_DIR = OVERLAY_DIRS[0] if OVERLAY_DIRS else os.path.join(OVERLAY_ROOT, '_none')


def load():
    with io.open(MANIFEST, encoding='utf-8-sig', newline='') as fh:
        return list(csv.DictReader(fh))


def workflow_text():
    """-> {path: text} for BOTH layers, keyed by a path that says which layer it is.

    Scanning only .github/workflows was fine while everything lived in one place. The moment the
    AM capabilities moved to overlays/, that check reported them as "declared implemented and
    invoked nowhere" -- a true statement about the wrong search scope. A checker that cannot see
    half the tree reports absence and means "I did not look there", which is the failure this
    estate keeps finding in other forms.
    """
    blobs = {}
    for base, tag in ((WF, 'core'), (OVERLAY_ROOT, 'overlay')):
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
    if not os.path.exists(MANIFEST):
        fails.append('no manifest at %s -- nothing to check' % MANIFEST)
    else:
        rows = load()
        if not rows:
            # A manifest that lists nothing would let this check pass while asserting nothing.
            fails.append('manifest is empty; a custody check with no rows is not a pass')
        need = {'Capability', 'Origin', 'Custody'}
        if rows and not need <= set(rows[0].keys()):
            fails.append('manifest is missing columns: %s' % ', '.join(sorted(need - set(rows[0]))))
        cust = set(r['Custody'] for r in rows) if rows else set()
        known = {'neutral'} | set(OVERLAY_NAMES)
        if rows and not cust <= known:
            fails.append('unknown custody value(s): %s -- expected neutral or a directory under '
                         'overlays/ (%s)' % (', '.join(sorted(cust - known)),
                                             ', '.join(OVERLAY_NAMES) or 'none present'))
    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: manifest present, non-empty, and every custody value is known')
    return True


def main():
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
    if os.path.isdir(OVERLAY_DIR):
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
        # And the overlay must actually compose the core rather than duplicate it.
        am = os.path.join(OVERLAY_DIR, 'workflows', 'security-am.yml')
        if os.path.exists(am):
            txt = io.open(am, encoding='utf-8').read()
            if 'reusable-security.yml' not in txt:
                problems.append('the overlay does not call the neutral core -- if it has copied '
                                'the pipeline instead of composing it, it is a fork')
            else:
                notes.append('overlay composes the neutral core (calls reusable-security.yml)')
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


if __name__ == '__main__':
    sys.exit(main())
