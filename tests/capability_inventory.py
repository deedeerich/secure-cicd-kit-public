#!/usr/bin/env python3
"""Prove every claimed capability actually runs. Static census across all workflows. No network.

WHY THIS EXISTS
    `github/codeql-action` appeared twelve times in reusable-security.yml. Every one was
    upload-sarif -- the transport for OTHER scanners' output. init, autobuild and analyze appeared
    zero times. The capability was named, wrapped in graceful-degradation handling, referenced in
    the architecture material, and never ran.

    Nobody lied. A vendor action name appeared often enough to read as a capability. This walks the
    chain instead of the name.

THE CHAIN, AND WHY EACH LINK IS SEPARATE
    Every one of these has failed independently in this kit at least once:

      IDENTIFIED   the capability is named somewhere
      SPECIFIED    expected behaviour is defined
      CONFIGURED   an implementation exists in a workflow
      INVOKED      a step actually calls the tool
      COMPLETED    the step can finish and its outcome is captured
      SURFACED     a human sees the result in the run, not only inside an artifact
      CONSUMED     a downstream gate reads the outcome
      ENFORCED     the outcome can actually fail the build

    and then, only from a LIVE RUN and never from this file:

      EXECUTED            the job actually ran on a runner and completed
      DETECTION_PROVEN    it found the planted defect it was supposed to find
      ENFORCEMENT_PROVEN  a real finding actually blocked a real promotion
      REVALIDATED         proven again after the code stopped changing and the feed moved

    A capability that stops at IDENTIFIED looks identical, in a YAML skim, to one that reaches
    the top. That is the entire problem.

    EXECUTED IS NOT DETECTION_PROVEN, AND THE FIRST LIVE RUN IS WHY THAT SPLIT EXISTS.
    On 2026-09-15 this kit ran against a corpus of deliberately planted defects. CodeQL executed,
    uploaded its analysis, and reported ZERO results over a file containing three XSS sinks.
    Gitleaks executed and reported zero over a planted credential. Both jobs were green; both
    would have been recorded EFFECTIVE under a single post-run state, and that record would have
    been worse than no record -- a green job is the most persuasive possible evidence for a
    control that did nothing.

        A GREEN WORKFLOW IS NOT EVIDENCE THAT THE INTENDED CONTROLS EXECUTED,
        AND AN EXECUTED CONTROL IS NOT EVIDENCE THAT IT DETECTS ANYTHING.

    So detection is proven per capability against a fixture mapped to a query documented to catch
    that exact pattern -- not against "something vulnerable-looking is in the repo".

WHAT THIS CANNOT ESTABLISH
    It is static. It proves a step EXISTS that would invoke a tool; it cannot prove the tool
    installed, ran, or detected anything on a real runner. EFFECTIVE is never awarded here -- that
    needs a live seeded run. Reporting otherwise would be this defect class committed inside the
    tool built to catch it.

USAGE
    python tests/capability_inventory.py [--workflows .github/workflows] [--wishlist a,b,c]

EXIT
    0  census written      1  no workflows found      2  self-test failed
"""
import argparse
import csv
import io
import os
import re
import sys

# capability -> (regexes that prove INVOCATION, not merely mention)
INVOCATION = {
    'gitleaks':            [r'gitleaks\s+(detect|dir|git)', r'zricethezav/gitleaks'],
    'detect-secrets':      [r'detect-secrets\s+scan'],
    'semgrep':             [r'semgrep\s+(ci|scan)', r'returntocorp/semgrep', r'semgrep/semgrep'],
    'bandit':              [r'bandit\s+-'],
    'gosec':               [r'gosec\s+', r'securego/gosec'],
    'flawfinder':          [r'flawfinder\s+'],
    'checkov':             [r'checkov\s+-', r'bridgecrewio/checkov'],
    'trivy':               [r'trivy\s+(fs|image|config|repo)', r'aquasecurity/trivy'],
    'syft':                [r'syft\s+', r'anchore/sbom-action'],
    'osv-scanner':         [r'osv-scanner\s+', r'google/osv-scanner'],
    'dependency-check':    [r'dependency-check', r'dependency-check\.sh'],
    'dotnet-vuln':         [r'dotnet\s+list\s+package\s+--vulnerable'],
    'codeql':              [r'codeql-action/init', r'codeql-action/analyze',
                            r'codeql-action/autobuild'],
    'sonarcloud':          [r'sonarsource/sonarcloud-github-action',
                            r'sonarsource/sonarqube-scan-action', r'sonar-scanner'],
    'owasp-zap':           [r'zaproxy/action-', r'zap-baseline', r'zap-full-scan',
                            r'owasp/zap2docker'],
    'sarif-upload':        [r'codeql-action/upload-sarif'],
}

# Things that indicate a capability is merely NAMED
MENTION = dict((k, [k.replace('-', '[-_ ]?')]) for k in INVOCATION)


GENERATED = re.compile(r'(?s)# BEGIN (?:NORMALIZE_SARIF|SCAN_REPORT|SCAN_STATUS).*?'
                       r'# END (?:NORMALIZE_SARIF|SCAN_REPORT|SCAN_STATUS)')


def strip_generated(text):
    """Remove inlined Python from the census input.

    A reusable workflow cannot reach the kit's own scripts/ at consumer runtime, so two canonical
    Python files are GENERATED into the workflow as heredocs. Their source names scanners
    constantly -- in docstrings, in severity tables, in the comment explaining why upload-sarif is
    not CodeQL. Left in, the census credited the reporting job with invoking gosec, flawfinder and
    trivy, none of which it runs.

    That is precisely this file's own defect class -- a name read as a capability -- committed
    inside the tool written to catch it, and it appeared the moment the reporter was inlined. The
    inlined regions are Python, not workflow steps. They are not evidence of invocation.
    """
    return GENERATED.sub('', text)


def scan(text, pats):
    return [p for p in pats if re.search(p, text, re.I)]


def job_of(text, idx):
    """Which job a character offset falls in, by walking back to the last 2-space job header."""
    best = ''
    for m in re.finditer(r'(?m)^  ([a-z][\w-]*):\s*$', text):
        if m.start() > idx:
            break
        best = m.group(1)
    return best


def self_test():
    """A census that credits a name is the defect. Prove invocation and mention differ."""
    upload_only = 'uses: github/codeql-action/upload-sarif@v4'
    real = 'uses: github/codeql-action/init@v4'
    ok_no_credit = not scan(upload_only, INVOCATION['codeql'])
    ok_credit = bool(scan(real, INVOCATION['codeql']))
    ok_mention = bool(scan(upload_only, MENTION['codeql']))
    ok_sarif = bool(scan(upload_only, INVOCATION['sarif-upload']))
    ok_job = job_of('  discover:\n    x\n  secret-scan:\n    y\n', 40) == 'secret-scan'
    # Inlined Python that merely NAMES scanners must not be read as invoking them. This exact
    # false positive appeared the moment the reporter was inlined: the census credited the
    # reporting job with running gosec, flawfinder and trivy on the strength of its docstrings.
    gen = ('  report:\n    run: |\n'
           '      # BEGIN SCAN_REPORT - x\n'
           '      gosec  is mentioned here in a docstring\n'
           '      trivy fs would look like an invocation\n'
           '      # END SCAN_REPORT\n')
    ok_strip = (not scan(strip_generated(gen), INVOCATION['gosec'])
                and not scan(strip_generated(gen), INVOCATION['trivy'])
                and bool(scan(gen, INVOCATION['trivy'])))
    if not all((ok_no_credit, ok_credit, ok_mention, ok_sarif, ok_job, ok_strip)):
        print('SELF-TEST FAILED: upload-not-credited=%s init-credited=%s mention=%s sarif=%s '
              'job=%s generated-stripped=%s'
              % (ok_no_credit, ok_credit, ok_mention, ok_sarif, ok_job, ok_strip))
        return False
    print('self-test ok: upload-sarif does NOT count as CodeQL invocation; init does; a mention is '
          'tracked separately from an invocation')
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--workflows', default='.github/workflows')
    # NO DEFAULT. A wishlist is a CONSUMER's belief about their own pipeline, and baking one in
    # made the neutral kit ship with an opinion about which capabilities it ought to have -- so
    # its own census reported another organisation's tooling as missing from THIS kit. That both
    # misstates the neutral contract and discloses, to every future consumer, what a previous
    # consumer used. ABSENT BY DESIGN IS NOT A MISSING CAPABILITY.
    ap.add_argument('--wishlist', default='',
                    help='comma-separated capabilities the CALLER believes are running. Supply '
                         'your own; this kit ships without one.')
    ap.add_argument('--out', default='docs/assurance/CAPABILITY_INVENTORY_GENERATED.csv')
    a = ap.parse_args()
    if not self_test():
        print('ABORTING -- a census that cannot tell a name from a call proves nothing.')
        return 2

    wdir = os.path.abspath(a.workflows)
    if not os.path.isdir(wdir):
        print('no workflow directory at %s' % wdir)
        return 1
    files = sorted(f for f in os.listdir(wdir) if f.endswith(('.yml', '.yaml')))
    if not files:
        print('no workflow files in %s' % wdir)
        return 1

    blobs = {}
    for f in files:
        blobs[f] = strip_generated(
            io.open(os.path.join(wdir, f), encoding='utf-8', errors='replace').read())

    rows = []
    for cap in sorted(INVOCATION):
        inv_where, men_where, jobs = [], [], set()
        surfaced = consumed = enforced = False
        for f, t in blobs.items():
            for p in INVOCATION[cap]:
                for m in re.finditer(p, t, re.I):
                    inv_where.append(f)
                    jobs.add(job_of(t, m.start()))
            if scan(t, MENTION[cap]):
                men_where.append(f)
        inv_where = sorted(set(inv_where))
        men_where = sorted(set(men_where))

        # SURFACED: does any job that invokes it write a human-visible summary or notice?
        for f in inv_where:
            t = blobs[f]
            for j in jobs:
                if not j:
                    continue
                seg = re.search(r'(?ms)^  %s:.*?(?=^  [a-z][\w-]*:\s*$|\Z)' % re.escape(j), t)
                if not seg:
                    continue
                s = seg.group(0)
                if 'GITHUB_STEP_SUMMARY' in s or '::notice' in s or '::warning' in s:
                    surfaced = True
                if re.search(r'(?i)outputs?:|>>\s*"?\$GITHUB_OUTPUT', s):
                    consumed = True
        # A job need not publish its own outputs to be consumed. The gate reading
        # needs.<job>.result IS consumption -- that is how every scanner here contributes its
        # verdict. Requiring job-level outputs undercounted zap, which reports through its job
        # conclusion like the rest of them.
        for f, t in blobs.items():
            for j in jobs:
                if j and re.search(r'needs\.%s\.result' % re.escape(j), t):
                    consumed = True
        # ENFORCED: is this capability's JOB actually wired into the gate?
        #
        # The first version of this check searched every FILE that contained 'security-gate' --
        # which is the whole workflow -- so any capability mentioned anywhere scored ENFORCED. It
        # awarded that to three capabilities on the same day those three jobs were added
        # WITHOUT being wired into the gate at all. A census that credits a name is the defect it
        # was written to catch, committed inside itself. Third occurrence of that shape.
        #
        # Now: extract the gate job body, and require the capability's job to appear in its
        # needs: list. A job the gate does not depend on cannot fail the build, whatever the
        # rest of the file says.
        for f, t in blobs.items():
            g = re.search(r'(?ms)^  security-gate:.*?(?=^  [a-z][\w-]*:\s*$|\Z)', t)
            if not g:
                continue
            body = g.group(0)
            needs = re.search(r'(?ms)^\s{4}needs:\s*(\[.*?\]|(?:\n\s{6}-\s*\S+)+)', body)
            needs_txt = needs.group(1) if needs else ''
            for j in jobs:
                if j and re.search(r'\b%s\b' % re.escape(j), needs_txt):
                    enforced = True

        if inv_where:
            state = 'INVOKED'
            if surfaced:
                state = 'SURFACED'
            if surfaced and consumed:
                state = 'CONSUMED'
            if surfaced and consumed and enforced:
                state = 'ENFORCED (static)'
        elif men_where:
            state = 'IDENTIFIED ONLY -- named, never invoked'
        else:
            state = 'ABSENT'

        rows.append([cap, state,
                     ';'.join(inv_where) or '-', ';'.join(sorted(j for j in jobs if j)) or '-',
                     ';'.join(men_where) or '-',
                     'yes' if surfaced else 'no', 'yes' if consumed else 'no',
                     'yes' if enforced else 'no', 'NOT ESTABLISHED HERE'])

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with io.open(a.out, 'w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['Capability', 'Static state', 'Invoked in', 'Jobs', 'Merely mentioned in',
                    'Result surfaced in run', 'Outcome captured', 'Referenced by gate',
                    'EFFECTIVE (needs live seeded run)'])
        w.writerows(rows)

    print('')
    print('%-18s %-34s %-7s %-8s %s' % ('capability', 'static state', 'surfaced', 'captured',
                                        'jobs'))
    print('-' * 104)
    for cap, state, inv, jobs, men, surf, cons, enf, eff in rows:
        print('%-18s %-34s %-7s %-8s %s' % (cap, state, surf, cons, jobs[:34]))

    absent = [r[0] for r in rows if r[1] == 'ABSENT']
    named = [r[0] for r in rows if r[1].startswith('IDENTIFIED ONLY')]
    unsurfaced = [r[0] for r in rows if r[5] == 'no' and r[1] not in ('ABSENT',)
                  and not r[1].startswith('IDENTIFIED')]

    print('')
    if named:
        print('NAMED BUT NEVER INVOKED: %s' % ', '.join(named))
        print('  This is the CodeQL shape. The word appears; no step calls the tool.')
    if absent:
        print('ABSENT: %s' % ', '.join(absent))
    if unsurfaced:
        print('')
        print('INVOKED BUT NOT SURFACED: %s' % ', '.join(unsurfaced))
        print('  The scan runs and a human reading the run cannot see what it found. A result')
        print('  that lives only inside an artifact is a result nobody reads.')

    wish = [w.strip().lower() for w in a.wishlist.split(',') if w.strip()]
    if wish:
        print('')
        print('WISHLIST CHECK -- what someone believes is running')
        print('-' * 104)
        for w in wish:
            hit = [r for r in rows if r[0] == w]
            if hit:
                print('  %-16s %s' % (w, hit[0][1]))
            elif w == 'dependabot':
                dep = os.path.exists(os.path.join(os.path.dirname(wdir), 'dependabot.yml'))
                print('  %-16s %s' % (w, 'config file present -- platform enablement NOT proven'
                                      if dep else 'ABSENT -- no .github/dependabot.yml'))
            else:
                print('  %-16s ABSENT -- not a capability this census knows, and not in any workflow'
                      % w)

    print('')
    print('EFFECTIVE is deliberately blank for every row. This census is static: it proves a step')
    print('EXISTS that would call the tool. It cannot prove the tool installed, ran, or detected')
    print('anything. Only a live seeded run establishes that, and awarding it here would be this')
    print('exact defect class committed inside the tool built to catch it.')
    print('')
    print('wrote %s' % a.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
