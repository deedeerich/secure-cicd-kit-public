#!/usr/bin/env python3
"""Azure Government sign-in asks for the Government audience at EVERY azure/login site. NO NETWORK.

WHY (owner, 2026-11-04)
    The estate includes an Azure Government tenant. Microsoft documents that for Azure Government
    the federated credential's audience is `api://AzureADTokenExchangeUSGov`, with
    `environment: AzureUSGovernment`. The kit's azure/login steps set the environment for
    `cloud == 'gov'` but passed no `audience`, so in Government they asked for the GLOBAL audience
    (`api://AzureADTokenExchange`), which a Government credential does not accept.

THE RULE
    Every `uses: azure/login@` step that serves the Government cloud (its `environment` names
    AzureUSGovernment) passes `audience`, evaluating to:
        cloud gov, no override              api://AzureADTokenExchangeUSGov
        cloud gov, vars.KIT_AZURE_OIDC_AUDIENCE set   that value (a tenant whose credential uses
                                            the global audience)
        cloud commercial (any override)     api://AzureADTokenExchange (azure/login's default:
                                            commercial behaviour unchanged)
    In the composite action (no `vars` there) the override is the `audience` input, applied to gov
    only. A step that serves only the commercial cloud (no `environment`) passes no audience, or
    the global one.

WHAT IT PROVES
    G1  every azure/login site found (workflows and composite actions), each classified; at least
        the known count.
    G2  each gov-capable site's `audience` evaluates as the table above, for all four contexts.
    G3  each commercial-only site sets no audience, or the global default.
    G4  mutants: a gov site with the audience removed fails G2; one with the two audiences swapped
        fails G2; one whose override also applies to commercial fails G2.

UNVERIFIED: a LIVE Government sign-in. This proves what the steps ASK FOR; that a Government
tenant's credential accepts it is owed to a Government sandbox run.

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GOV = 'api://AzureADTokenExchangeUSGov'
GLOBAL = 'api://AzureADTokenExchange'
OVERRIDE = 'api://AzureADTokenExchange'   # a gov tenant whose credential uses the global audience
FAILS = []
MIN_SITES = 10


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)


def evaluate(expr, ctx):
    """A GitHub expression of literals, inputs.X / vars.X, ==, !=, &&, ||, ! and parentheses.
    && and || return an operand, as GitHub's do; '' and None are falsy."""
    s = str(expr).strip()
    m = re.match(r'^\$\{\{(.*)\}\}$', s, re.S)
    if not m:
        return s
    body = m.group(1)
    toks = re.findall(r"'(?:[^']|'')*'|&&|\|\||==|!=|!|\(|\)|[A-Za-z_][A-Za-z0-9_.-]*", body)
    py = []
    for t in toks:
        if t == '&&':
            py.append(' and ')
        elif t == '||':
            py.append(' or ')
        elif t == '!':
            py.append(' not ')
        elif t in ('==', '!=', '(', ')'):
            py.append(t)
        elif t.startswith("'"):
            py.append(repr(t[1:-1].replace("''", "'")))
        elif t in ('true', 'false'):
            py.append('True' if t == 'true' else 'False')
        else:
            py.append(repr(ctx.get(t, '') or ''))
    return eval(''.join(py), {'__builtins__': {}}, {})   # noqa: S307 - tokens above only


def sites(root=ROOT):
    import yaml
    out = []
    files = sorted(glob.glob(os.path.join(root, '.github', 'workflows', '*.yml')) +
                   glob.glob(os.path.join(root, '.github', 'actions', '*', 'action.yml')))
    for p in files:
        doc = yaml.safe_load(io.open(p, encoding='utf-8').read()) or {}
        composite = p.endswith('action.yml')
        steps = []
        if composite:
            steps = [('runs', s) for s in ((doc.get('runs') or {}).get('steps') or [])]
        else:
            for jn, j in (doc.get('jobs') or {}).items():
                steps += [(jn, s) for s in (j.get('steps') or [])]
        for jn, st in steps:
            if str(st.get('uses') or '').startswith('azure/login@'):
                out.append((os.path.relpath(p, root).replace(os.sep, '/'), jn, st, composite))
    return out


def contexts(composite):
    """(label, ctx, expected) for the four cases."""
    o = 'inputs.audience' if composite else 'vars.KIT_AZURE_OIDC_AUDIENCE'
    return [('gov, no override', {'inputs.cloud': 'gov'}, GOV),
            ('gov, override', {'inputs.cloud': 'gov', o: OVERRIDE}, OVERRIDE),
            ('commercial, no override', {'inputs.cloud': 'commercial'}, GLOBAL),
            ('commercial, override set', {'inputs.cloud': 'commercial', o: 'api://something-else'}, GLOBAL)]


def site_problems(rel, jn, st, composite):
    w = st.get('with') or {}
    envx = w.get('environment')
    aud = w.get('audience')
    probs = []
    if envx is None or 'AzureUSGovernment' not in str(envx):
        if aud not in (None, '', GLOBAL):
            probs.append('%s %s: a commercial-only site sets audience %r' % (rel, jn, aud))
        return 'commercial-only', probs
    if aud is None:
        return 'gov-capable', ['%s %s: serves AzureUSGovernment but passes no audience' % (rel, jn)]
    for label, ctx, want in contexts(composite):
        try:
            got = evaluate(aud, ctx)
        except Exception as exc:                  # noqa: BLE001
            probs.append('%s %s: the audience expression cannot be read (%s)' % (rel, jn, exc))
            break
        if got != want:
            probs.append('%s %s: %s gives audience %r, wanted %r' % (rel, jn, label, got, want))
    return 'gov-capable', probs


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    found = sites()
    check(len(found) >= MIN_SITES, 'G1 %d azure/login site(s) found (at least %d known)' % (len(found), MIN_SITES))
    for rel, jn, st, comp in found:
        kind, probs = site_problems(rel, jn, st, comp)
        for p in probs:
            check(False, ('G2 ' if kind == 'gov-capable' else 'G3 ') + p)
        if not probs:
            check(True, '%s %s %s (%s)' % ('G2' if kind == 'gov-capable' else 'G3', rel, jn, kind))
    # G4 mutants, on the first gov-capable workflow site and the composite.
    import copy
    gov = [(r, j, s, c) for (r, j, s, c) in found if 'AzureUSGovernment' in str((s.get('with') or {}).get('environment'))]
    for r, j, s, c in [x for x in gov if not x[3]][:1] + [x for x in gov if x[3]][:1]:
        m1 = copy.deepcopy(s); m1['with'].pop('audience', None)
        check(bool(site_problems(r, j, m1, c)[1]), 'G4 mutant %s: audience removed is caught' % r)
        m2 = copy.deepcopy(s)
        a = str(m2['with'].get('audience', ''))
        m2['with']['audience'] = a.replace(GOV, '@@').replace("'%s'" % GLOBAL, "'%s'" % GOV).replace('@@', GLOBAL)
        check(bool(site_problems(r, j, m2, c)[1]), 'G4 mutant %s: the audiences swapped is caught' % r)
        o = 'inputs.audience' if c else 'vars.KIT_AZURE_OIDC_AUDIENCE'
        m3 = copy.deepcopy(s)
        m3['with']['audience'] = "${{ %s || (inputs.cloud == 'gov' && '%s' || '%s') }}" % (o, GOV, GLOBAL)
        check(bool(site_problems(r, j, m3, c)[1]), 'G4 mutant %s: an override that reaches commercial is caught' % r)
    print()
    if FAILS:
        print('FAIL: %d check(s): an Azure Government sign-in would ask for the wrong audience.' % len(FAILS))
        return 1
    print('PASS: every Government-capable azure/login site asks for %s (overridable for gov only);' % GOV)
    print('      commercial sites are unchanged. UNVERIFIED: a live Government sign-in (owed to a Gov sandbox).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
