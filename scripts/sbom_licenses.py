#!/usr/bin/env python3
"""Read the licences the SBOM already recorded. Free, local, no network.

WHY THIS EXISTS
    syft emits CycloneDX and SPDX, and BOTH carry per-component licence data. The kit generated
    them, uploaded them, and read neither. "We produce an SBOM" was true and answered nothing:
    the licence question, the one an SBOM is most often asked to answer, went to an artifact
    nobody opened.

    That is the producer-with-no-consumer shape, three times in one day -- collection time with
    no requirement consumer, worksheet dataset identity with no family consumer, and this.
    Generating an artifact is not a capability. Reading it is.

WHAT IT ESTABLISHES, AND WHAT IT DOES NOT
    It reports what the SBOM SAYS. It does not audit licence compliance, it cannot tell you
    whether a declared licence is correct, and it has no opinion about which licences are
    acceptable -- that is a policy decision belonging to the consumer, supplied as a denylist.

    NO LICENCE DECLARED is reported separately and deliberately. It is not "permissive by
    default"; it is unestablished, and in most jurisdictions an unlicensed dependency is the
    MORE restrictive case rather than the less.

USAGE
    python3 sbom_licenses.py sbom.cyclonedx.json [--deny GPL-3.0,AGPL-3.0] [--out licences.json]
    python3 sbom_licenses.py --self-test

EXIT
    0  inventory written      1  denied licence present      2  self-test failed
    3  NO readable SBOM, or one supplied SBOM unreadable -- licence state NOT ESTABLISHED, which
       is not an empty licence set (ledger L16: this used to exit 0, so a syft failure read as
       "nothing denied")

THE VERDICT BELONGS TO THE GATE (ledger L16). `--out` writes it as JSON -- `state` (FINDINGS |
PASS | NOT_APPLICABLE when no denylist was supplied), the deduplicated component count, the
inventory, the undeclared and the denied -- and the sbom job publishes `state` and the denied
count as job outputs the gate reads.
"""
import argparse
import io
import json
import os
import re
import sys


def described_roots(doc):
    """SPDX ids the DOCUMENT describes -- the scan root (syft: a `.` package of purpose FILE),
    not a dependency. Measured on syft 1.52.0; counting it reported the directory itself as an
    unlicensed component."""
    roots = set(doc.get('documentDescribes') or [])
    for r in (doc.get('relationships') or []):
        if (r.get('relationshipType') == 'DESCRIBES'
                and r.get('spdxElementId') == 'SPDXRef-DOCUMENT'):
            roots.add(r.get('relatedSpdxElement'))
    return roots


def components(doc):
    """CycloneDX and SPDX carry the same facts under different names. Handle both rather than
    silently reading one and reporting a total that means 'the half I understood'."""
    out = []
    roots = described_roots(doc)
    for c in (doc.get('components') or []):                      # CycloneDX
        if c.get('type') == 'file':
            # A manifest syft read, not a dependency (see the self-test).
            continue
        lic = []
        for entry in (c.get('licenses') or []):
            node = entry.get('license') or {}
            v = node.get('id') or node.get('name') or entry.get('expression')
            if v:
                lic.append(str(v))
        out.append({'name': c.get('name') or '?', 'version': c.get('version') or '',
                    'licenses': sorted(set(lic)), 'purl': c.get('purl') or ''})
    for p in (doc.get('packages') or []):                        # SPDX
        if p.get('SPDXID') in roots:
            continue
        lic = []
        for k in ('licenseConcluded', 'licenseDeclared'):
            v = p.get(k)
            if v and v not in ('NOASSERTION', 'NONE'):
                lic.append(str(v))
        out.append({'name': p.get('name') or '?',
                    'version': p.get('versionInfo') or '',
                    'licenses': sorted(set(lic)),
                    'purl': ''})
    return out


def dedupe(comps):
    """ONE COMPONENT, ONE ROW. The job reads CycloneDX AND SPDX, which describe the same packages;
    counting both counted every component twice. Merge on (name, version), uniting licences."""
    merged, order = {}, []
    for c in comps:
        k = (c['name'], c['version'])
        if k not in merged:
            merged[k] = dict(c, licenses=list(c['licenses']))
            order.append(k)
        else:
            merged[k]['licenses'] = sorted(set(merged[k]['licenses']) | set(c['licenses']))
            merged[k]['purl'] = merged[k]['purl'] or c['purl']
    return [merged[k] for k in order]


TOKEN = re.compile(r'[A-Za-z0-9.+\-:]+')
OPERATORS = {'AND', 'OR', 'WITH'}


def tokens(expr):
    """The licence identifiers in an SPDX expression: `(MIT OR GPL-3.0-only)` -> MIT, GPL-3.0-only."""
    return [t for t in TOKEN.findall(expr) if t.upper() not in OPERATORS]


def denies(entry, token):
    """TOKEN-LEVEL, NOT SUBSTRING (ledger L16). `GPL-3.0` must catch `GPL-3.0-only`,
    `GPL-3.0-or-later` and `GPL-3.0+`, and must NOT catch `LGPL-3.0-only` -- which the substring
    match did, reporting an LGPL library as a GPL denial."""
    t, d = token.upper(), entry.upper()
    return t == d or t == d + '+' or t.startswith(d + '-')


def assess(comps, deny):
    denied, undeclared, inventory = [], [], {}
    dl = [d.strip() for d in deny if d.strip()]
    for c in comps:
        if not c['licenses']:
            undeclared.append(c)
            continue
        hit = None
        for lic in c['licenses']:
            inventory[lic] = inventory.get(lic, 0) + 1
            if hit is None and any(denies(d, t) for d in dl for t in tokens(lic)):
                hit = lic
        # One denial per component, whichever of its licences carried it.
        if hit is not None:
            denied.append((c, hit))
    return denied, undeclared, inventory


def self_test():
    fails = []
    cdx = {'components': [
        {'name': 'a', 'version': '1.0', 'licenses': [{'license': {'id': 'MIT'}}]},
        {'name': 'b', 'version': '2.0', 'licenses': [{'license': {'name': 'GPL-3.0-only'}}]},
        {'name': 'c', 'version': '3.0'},
    ]}
    spdx = {'packages': [
        {'name': 'd', 'versionInfo': '1', 'licenseDeclared': 'Apache-2.0'},
        {'name': 'e', 'versionInfo': '2', 'licenseDeclared': 'NOASSERTION'},
    ]}
    c1 = components(cdx)
    if len(c1) != 3:
        fails.append('CycloneDX components lost (%d of 3)' % len(c1))
    c2 = components(spdx)
    if len(c2) != 2:
        fails.append('SPDX packages lost (%d of 2)' % len(c2))
    # NOASSERTION is not a licence. Treating it as one would report a component as licensed.
    if [c for c in c2 if c['name'] == 'e'][0]['licenses']:
        fails.append('NOASSERTION was read as a declared licence')

    denied, undeclared, inv = assess(c1, ['GPL-3.0'])
    if len(denied) != 1:
        fails.append('denylist did not match GPL-3.0-only from a GPL-3.0 entry')
    if len(undeclared) != 1:
        fails.append('a component with no licence was not reported separately')
    if inv.get('MIT') != 1:
        fails.append('inventory count wrong')
    # An empty denylist must deny nothing -- and must NOT match everything via empty substring.
    d2, _u, _i = assess(c1, [''])
    if d2:
        fails.append('an empty denylist denied something -- empty substring matches everything')
    # TOKEN-LEVEL: LGPL is not GPL; an expression is read per identifier; `+` is a GPL spelling.
    lg = [{'name': 'l', 'version': '1', 'licenses': ['LGPL-3.0-only'], 'purl': ''},
          {'name': 'x', 'version': '1', 'licenses': ['MIT OR GPL-3.0-only'], 'purl': ''},
          {'name': 'p', 'version': '1', 'licenses': ['GPL-3.0+'], 'purl': ''}]
    d3, _u, _i = assess(lg, ['GPL-3.0'])
    if sorted(c['name'] for c, _l in d3) != ['p', 'x']:
        fails.append('token match wrong: denied %s, expected p and x (never the LGPL one)'
                     % sorted(c['name'] for c, _l in d3))
    # DEDUPE: the same package from CycloneDX and SPDX is one component.
    both = dedupe(components({'components': [{'name': 'd', 'version': '1',
                                              'licenses': [{'license': {'id': 'Apache-2.0'}}]}]})
                  + components(spdx))
    if len([c for c in both if c['name'] == 'd']) != 1:
        fails.append('a package present in CycloneDX and SPDX was counted twice')
    # THE DESCRIBED ROOT IS NOT A DEPENDENCY.
    rooted = {'packages': [{'SPDXID': 'SPDXRef-Root', 'name': '.'},
                           {'SPDXID': 'SPDXRef-P', 'name': 'q', 'versionInfo': '1'}],
              'relationships': [{'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType':
                                 'DESCRIBES', 'relatedSpdxElement': 'SPDXRef-Root'}]}
    if [c['name'] for c in components(rooted)] != ['q']:
        fails.append('the SPDX document root was counted as a component')
    # A FILE IS NOT A PACKAGE. syft on Linux lists every manifest it read as a CycloneDX
    # component of type `file`, named by absolute path (measured: syft 1.52.0 and 1.54.1 on a
    # hosted runner; Windows emitted none). Counting them reported each lockfile as an
    # unlicensed dependency, and the component count depended on the host.
    filed = {'components': [{'type': 'library', 'name': 'r', 'version': '1'},
                            {'type': 'file', 'name': '/w/src/package-lock.json'}]}
    if [c['name'] for c in components(filed)] != ['r']:
        fails.append('a CycloneDX `file` component was counted as a package')
    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: reads CycloneDX and SPDX, NOASSERTION is not a licence, undeclared is '
          'its own state, empty denylist denies nothing')
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('sbom', nargs='*')
    ap.add_argument('--deny', default='')
    ap.add_argument('--out', default='')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.self_test:
        return 0 if self_test() else 2
    if not self_test():
        return 2

    comps = []
    read, unreadable = [], []
    for p in a.sbom:
        if not os.path.exists(p) or os.path.getsize(p) == 0:
            unreadable.append(p)
            continue
        try:
            comps += components(json.load(io.open(p, encoding='utf-8', errors='replace')))
            read.append(os.path.basename(p))
        except (ValueError, IOError, AttributeError) as e:
            unreadable.append(p)
            print('::warning title=Unreadable SBOM::%s (%s) -- its components are NOT included '
                  'in the counts below.' % (p, type(e).__name__))
    if not read or unreadable:
        # NOT ESTABLISHED IS NOT EMPTY. Exit 3, so the caller cannot read it as "nothing denied".
        print('::error title=Licence state NOT ESTABLISHED::%s' % (
            'no readable SBOM supplied' if not read else
            'SBOM(s) absent or unreadable: %s' % ', '.join(unreadable)))
        if a.out:
            json.dump({'state': 'COLLECTION_FAILED', 'read': read, 'unreadable': unreadable},
                      io.open(a.out, 'w', encoding='utf-8'), indent=1)
        return 3

    comps = dedupe(comps)
    denied, undeclared, inv = assess(comps, a.deny.split(','))
    out = os.environ.get('GITHUB_STEP_SUMMARY', '')
    L = ['### Dependency licences', '',
         'Read from: %s' % ', '.join(read), '',
         '| | |', '|---|---|',
         '| Components | %d |' % len(comps),
         '| Distinct licences | %d |' % len(inv),
         '| No licence declared | %d |' % len(undeclared),
         '| Denied by policy | %d |' % len(denied), '']
    if inv:
        L += ['| Licence | Components |', '|---|---|']
        for k in sorted(inv, key=lambda x: -inv[x])[:15]:
            L.append('| %s | %d |' % (k, inv[k]))
        L.append('')
    if denied:
        L += ['**DENIED BY POLICY**', '']
        for c, lic in denied[:20]:
            L.append('- `%s@%s` — %s' % (c['name'], c['version'], lic))
        L.append('')
    if undeclared:
        L += ['**NO LICENCE DECLARED — %d component(s)**' % len(undeclared), '',
              'Not "permissive by default". The licence is UNESTABLISHED, and an unlicensed',
              'dependency is usually the more restrictive case rather than the less.', '']
        for c in undeclared[:15]:
            L.append('- `%s@%s`' % (c['name'], c['version']))
        L.append('')
    L += ['This reports what the SBOM SAYS. It does not audit compliance and cannot tell you',
          'whether a declared licence is correct.']
    text = '\n'.join(L)
    print(text)
    if out:
        with io.open(out, 'a', encoding='utf-8') as fh:
            fh.write(text + '\n\n')
    if a.out:
        policy = any(d.strip() for d in a.deny.split(','))
        json.dump({'state': 'FINDINGS' if denied else ('PASS' if policy else 'NOT_APPLICABLE'),
                   'components': len(comps), 'inventory': inv,
                   'undeclared': [c['name'] for c in undeclared],
                   'denied': [{'name': c['name'], 'version': c['version'], 'licence': l}
                              for c, l in denied]},
                  io.open(a.out, 'w', encoding='utf-8'), indent=1)
    return 1 if denied else 0


if __name__ == '__main__':
    sys.exit(main())
