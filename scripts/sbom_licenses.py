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
"""
import argparse
import io
import json
import os
import sys


def components(doc):
    """CycloneDX and SPDX carry the same facts under different names. Handle both rather than
    silently reading one and reporting a total that means 'the half I understood'."""
    out = []
    for c in (doc.get('components') or []):                      # CycloneDX
        lic = []
        for entry in (c.get('licenses') or []):
            node = entry.get('license') or {}
            v = node.get('id') or node.get('name') or entry.get('expression')
            if v:
                lic.append(str(v))
        out.append({'name': c.get('name') or '?', 'version': c.get('version') or '',
                    'licenses': sorted(set(lic)), 'purl': c.get('purl') or ''})
    for p in (doc.get('packages') or []):                        # SPDX
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


def assess(comps, deny):
    denied, undeclared, inventory = [], [], {}
    dl = [d.strip().upper() for d in deny if d.strip()]
    for c in comps:
        if not c['licenses']:
            undeclared.append(c)
            continue
        for lic in c['licenses']:
            inventory[lic] = inventory.get(lic, 0) + 1
            # Substring match, deliberately: a denylist entry of GPL-3.0 should catch
            # "GPL-3.0-only" and "GPL-3.0-or-later" rather than requiring every spelling.
            if any(d in lic.upper() for d in dl):
                denied.append((c, lic))
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
    read = []
    for p in a.sbom:
        if not os.path.exists(p) or os.path.getsize(p) == 0:
            continue
        try:
            comps += components(json.load(io.open(p, encoding='utf-8', errors='replace')))
            read.append(os.path.basename(p))
        except (ValueError, IOError) as e:
            print('::warning title=Unreadable SBOM::%s (%s) -- its components are NOT included '
                  'in the counts below.' % (p, type(e).__name__))
    if not read:
        print('no readable SBOM supplied; licence state NOT ESTABLISHED')
        return 0

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
        json.dump({'components': len(comps), 'inventory': inv,
                   'undeclared': [c['name'] for c in undeclared],
                   'denied': [{'name': c['name'], 'licence': l} for c, l in denied]},
                  io.open(a.out, 'w', encoding='utf-8'), indent=1)
    return 1 if denied else 0


if __name__ == '__main__':
    sys.exit(main())
