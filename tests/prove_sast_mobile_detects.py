#!/usr/bin/env python3
"""The sast-mobile job finds every planted Android and iOS condition, stays silent on clean trees,
and never reads a hollow scan as clean (lane L-SCAN-B, KDEC-026).

WHY THIS EXISTS (docs/roadmap/FUTURE_WORK.md section 5)

    "Swift / Objective-C: no scanner at all." "Kotlin / Android: Java coverage does not imply
    Android -- manifests, exported components, permissions, signing/config." Tool choice, with
    evidence (measured 2026-10-23, python:3.12-slim, mobsfscan 1.0.1 pinning semgrep 1.172.0):

      * mobsfscan reports the planted manifest (debuggable, allowBackup, usesCleartextTraffic,
        minSdk 16), network_security_config (cleartext, user trust anchors), Kotlin (ECB, MD5,
        WebView), Info.plist ATS (arbitrary loads, insecure HTTP exception, TLS 1.0 exception),
        Swift (kSecAttrAccessibleAlways, UIWebView) and Objective-C (MD5, strcpy) -- and nothing
        at error on the clean trees;
      * it reports NONE of: exported components with no permission, hard-coded Gradle signing
        passwords, Gradle minSdk, debuggable release build types. Those are kit-authored Semgrep
        rules (.github/actions/sast-mobile/mobile-config.semgrep.yml), run here and graded too;
      * pointed at a path that does not exist it exits 0 with an empty, "successful" SARIF -- so the
        job scans a planted canary first and refuses to trust a tool that cannot see it.

WHAT IT PROVES (the composite's steps, extracted AS SHIPPED, run in a Linux container)
    M1  the install step installs mobsfscan 1.0.1 and Semgrep 1.172.0 against their pinned digests
    M2  planted Android tree: mobsfscan COMPLETE; every mobsfscan row of PLATFORM_SIGNALS is reported
        by that rule on that file, with a repository-relative path; enforce hands FINDINGS to the gate
    M3  planted Android tree: the configuration rules COMPLETE; every mobile-config row reported on
        its file; enforce hands FINDINGS
    M4  planted iOS tree (Swift, Objective-C, Info.plist): every iOS row reported; the configuration
        rules are NOT_APPLICABLE (no manifest, no Gradle)
    M5  clean Android and clean iOS: zero error-level results from either scanner, nothing handed
    M6  no mobile sources: both steps NOT_APPLICABLE, exit 0 -- discovery skipping the job is
        proven by tests/prove_platform_discovery.py D7
    M7  HOLLOW: a mobsfscan that writes an empty, successful SARIF and sees nothing -> the positive
        control refuses it: COLLECTION_FAILED, exit 1, and enforce fails
    M8  the kit's rule file missing -> COLLECTION_FAILED, never a clean zero
    M9  a wrong pinned digest installs nothing: DEPENDENCY_ACQUISITION_UNAVAILABLE, exit 1
        (fault injection: one character of the shipped hash is changed)
    M10 a mobsfscan with no `semgrep` on its PATH (measured: it then skips every Kotlin, Java and
        Swift rule without a word and still reports the manifest) -> the Kotlin half of the
        positive control refuses it: COLLECTION_FAILED

    FAILS ON c7e1ea9: there is no sast-mobile job (M1-M9 have no steps to run).

EXIT  0 all hold   1 any does not   2 could not be checked (no docker, no network, no PyYAML)
"""
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

JOB = 'sast-mobile'
INSTALL, MOBSF, MOBSF_ENFORCE_STEP = 'Install mobsfscan', 'mobsfscan', 'mobsfscan — enforce'
RULES, RULES_ENFORCE_STEP = 'Mobile configuration rules (Semgrep)', 'Mobile configuration rules — enforce'
ACTION_DIR = os.path.join(ROOT, '.github', 'actions', 'sast-mobile')
# The runner image the job runs on is ubuntu-latest (Python 3.12); this is the closest local
# stand-in, by digest, plus jq (which ubuntu-latest carries).
IMAGE = 'kitproof-mobile:1'
DOCKERFILE = ('FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1\n'
              'RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends jq >/dev/null '
              '&& rm -rf /var/lib/apt/lists/*\n')
HOLLOW = ('#!/usr/bin/env bash\n# a mobsfscan that sees nothing and says it succeeded\n'
          'out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; esac; shift; done\n'
          'printf \'{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"mobsfscan"}},'
          '"invocations":[{"executionSuccessful":true}],"results":[]}]}\' > "$out"\n'
          'case "$out" in *.json) printf \'{"results":{},"errors":[]}\' > "$out" ;; esac\nexit 0\n')


def results_by_file(sarif_path):
    doc = json.load(io.open(sarif_path, encoding='utf-8'))
    got = {}
    for run in doc.get('runs') or []:
        for r in run.get('results') or []:
            for loc in r.get('locations') or []:
                uri = ((loc.get('physicalLocation') or {}).get('artifactLocation') or {}).get('uri', '')
                got.setdefault(uri, []).append((r.get('ruleId', ''), r.get('level', '')))
    return got


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    import _docker_step_runner as d
    import _scan_step_harness as h
    import _platform_fixtures as pf
    if not d.docker_ok():
        print('UNKNOWN: docker is not available, so the steps cannot be run on Linux here.')
        return 2
    steps = h.steps_by_name(JOB)
    need = [INSTALL, MOBSF, MOBSF_ENFORCE_STEP, RULES, RULES_ENFORCE_STEP]
    if any(n not in steps for n in need):
        print('FAIL: job %r lacks step(s) %s -- Android and iOS have no scanner.'
              % (JOB, [n for n in need if n not in steps]))
        return 1
    ok, log = d.build_image(IMAGE, DOCKERFILE)
    if not ok:
        print('UNKNOWN: the proof image could not be built (network?):\n%s' % log[-600:])
        return 2
    c = d.Container(IMAGE, action_dir=ACTION_DIR, prefix='mobile-proof-')
    bad = []
    base = {'inputs.paths': '.', 'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false'}
    try:
        rc, out, _o, unk = c.run(steps[INSTALL], base)
        if rc != 0:
            if 'Could not find' in out or 'ConnectionError' in out or 'Temporary failure' in out:
                print('UNKNOWN: PyPI unreachable:\n%s' % out[-400:])
                return 2
            bad.append('M1 install failed (exit %d):\n%s' % (rc, out[-800:]))
            raise StopIteration
        print('  M1 install: %s' % ' | '.join(l for l in out.splitlines() if 'mobsfscan' in l.lower() or 'semgrep' in l.lower())[:200])

        def scan(name, tree_files):
            c.reset_workspace(tree_files)
            rc1, l1, o1, u1 = c.run(steps[MOBSF], base)
            e1 = dict(base, **{'steps.mobsfscan.outputs.%s' % k: o1.get(k, '') for k in ('count', 'collection')})
            erc1, el1, eo1, _ = c.run(steps[MOBSF_ENFORCE_STEP], e1)
            rc2, l2, o2, u2 = c.run(steps[RULES], base)
            e2 = dict(base, **{'steps.mobile_rules.outputs.%s' % k: o2.get(k, '') for k in ('count', 'collection')})
            erc2, el2, eo2, _ = c.run(steps[RULES_ENFORCE_STEP], e2)
            for u in (u1, u2):
                if u:
                    bad.append('%s: unmodelled expressions %s' % (name, u))
            r1 = results_by_file(os.path.join(c.ws, 'mobsfscan.sarif')) if os.path.exists(os.path.join(c.ws, 'mobsfscan.sarif')) else {}
            r2 = results_by_file(os.path.join(c.ws, 'mobile-config.sarif')) if os.path.exists(os.path.join(c.ws, 'mobile-config.sarif')) else {}
            print('  %-14s mobsfscan rc=%d %s count=%s handed=%r | rules rc=%d %s count=%s handed=%r'
                  % (name, rc1, o1.get('collection'), o1.get('count'), eo1.get('findings_state', ''),
                     rc2, o2.get('collection'), o2.get('count'), eo2.get('findings_state', '')))
            return dict(rc1=rc1, l1=l1, o1=o1, erc1=erc1, eo1=eo1, rc2=rc2, l2=l2, o2=o2, erc2=erc2,
                        eo2=eo2, r1=r1, r2=r2)

        def graded(tree, res):
            for t, path, tool, rule in pf.SIGNALS:
                if t != tree or tool not in ('mobsfscan', 'mobile-config'):
                    continue
                got = (res['r1'] if tool == 'mobsfscan' else res['r2']).get(path, [])
                if not any(rule in rid for rid, _lv in got):
                    bad.append('%s: %s did not report %s on %s (it reported there: %s)'
                               % (tree, tool, rule, path, sorted({r for r, _ in got})))
            for r in (res['r1'], res['r2']):
                for uri in r:
                    if uri.startswith('/') or uri.startswith('./') or uri in ('.', ''):
                        bad.append('%s: a result location is not repository-relative: %r' % (tree, uri))

        a = scan('android', pf.TREES['android'])
        if a['o1'].get('collection') != 'COMPLETE' or a['o2'].get('collection') != 'COMPLETE':
            bad.append('M2/M3 android: collections %r / %r\n%s\n%s' % (a['o1'].get('collection'),
                       a['o2'].get('collection'), a['l1'][-900:], a['l2'][-900:]))
        graded('android', a)
        if a['eo1'].get('findings_state') != 'FINDINGS' or a['eo2'].get('findings_state') != 'FINDINGS':
            bad.append('M2/M3 android: planted error-level findings were not handed to the gate')

        i = scan('ios', pf.TREES['ios'])
        if i['o1'].get('collection') != 'COMPLETE':
            bad.append('M4 ios: mobsfscan %r\n%s' % (i['o1'].get('collection'), i['l1'][-900:]))
        if i['o2'].get('collection') != 'NOT_APPLICABLE' or i['rc2'] != 0:
            bad.append('M4 ios: the configuration rules must be NOT_APPLICABLE (got %r, exit %d)'
                       % (i['o2'].get('collection'), i['rc2']))
        graded('ios', i)

        for name in ('android-clean', 'ios-clean'):
            cl = scan(name, pf.TREES[name])
            if cl['rc1'] != 0 or cl['o1'].get('count') != '0' or cl['eo1'].get('findings_state'):
                bad.append('M5 %s: mobsfscan error-level results on a clean tree: %s' % (name, cl['r1']))
            errs = [x for v in cl['r2'].values() for x in v]
            if cl['eo2'].get('findings_state') or errs:
                bad.append('M5 %s: configuration-rule results on a clean tree: %s' % (name, cl['r2']))

        n = scan('no-mobile', {'app/main.py': 'print(1)\n'})
        if (n['o1'].get('collection'), n['o2'].get('collection')) != ('NOT_APPLICABLE', 'NOT_APPLICABLE') \
                or n['rc1'] or n['rc2'] or n['erc1'] or n['erc2']:
            bad.append('M6 no mobile sources: %r / %r (exits %d %d %d %d)' % (
                n['o1'].get('collection'), n['o2'].get('collection'), n['rc1'], n['rc2'], n['erc1'], n['erc2']))

        # M7: the hollow scanner, first on PATH.
        c.sh('mkdir -p /hollow && cat > /hollow/mobsfscan <<\'EOF\'\n%sEOF\nchmod +x /hollow/mobsfscan' % HOLLOW)
        c.path_extra.insert(0, '/hollow')
        c.reset_workspace(pf.TREES['android'])
        rc, lg, o, _ = c.run(steps[MOBSF], base)
        erc, elg, eo, _ = c.run(steps[MOBSF_ENFORCE_STEP], dict(base, **{'steps.mobsfscan.outputs.%s' % k: o.get(k, '')
                                                              for k in ('count', 'collection')}))
        print('  %-14s mobsfscan rc=%d %s enforce rc=%d' % ('hollow', rc, o.get('collection'), erc))
        if rc == 0 or o.get('collection') != 'COLLECTION_FAILED' or 'positive control' not in lg or erc == 0:
            bad.append('M7 hollow mobsfscan was not refused (rc=%d, %r, enforce rc=%d):\n%s'
                       % (rc, o.get('collection'), erc, lg[-600:]))
        c.path_extra.remove('/hollow')

        # M10: a mobsfscan with no `semgrep` on its PATH -- it skips every code rule silently and
        # still reports the manifest. The positive control's Kotlin canary must refuse it.
        c.sh('mkdir -p /nosg && printf \'#!/usr/bin/env bash\\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin exec /rt/mobsf-venv/bin/mobsfscan "$@"\\n\' > /nosg/mobsfscan && chmod +x /nosg/mobsfscan')
        c.path_extra.insert(0, '/nosg')
        c.reset_workspace(pf.TREES['android'])
        rc, lg, o, _ = c.run(steps[MOBSF], base)
        print('  %-14s mobsfscan rc=%d %s' % ('no-semgrep', rc, o.get('collection')))
        if rc == 0 or o.get('collection') != 'COLLECTION_FAILED':
            bad.append('M10 a mobsfscan that silently skipped its code rules was trusted (rc=%d, %r):\n%s'
                       % (rc, o.get('collection'), lg[-500:]))
        c.path_extra.remove('/nosg')

        # M8: the rule file absent.
        c.reset_workspace(pf.TREES['android'])
        rc, lg, o, _ = c.run(steps[RULES], base, env={'GITHUB_ACTION_PATH': '/nonexistent'})
        print('  %-14s rules rc=%d %s' % ('no-rule-file', rc, o.get('collection')))
        if rc == 0 or o.get('collection') != 'COLLECTION_FAILED':
            bad.append('M8 a missing rule file read as %r (rc=%d)' % (o.get('collection'), rc))

        # M9: one character of the shipped digest changed.
        def corrupt(body):
            return body.replace('--hash=sha256:4d755d4b', '--hash=sha256:0d755d4b', 1)
        c.sh('rm -rf /rt/mobsf-venv')
        rc, lg, o, _ = c.run(steps[INSTALL], base, body_edit=corrupt)
        print('  %-14s install rc=%d' % ('bad-digest', rc))
        if rc == 0 or 'DEPENDENCY_ACQUISITION_UNAVAILABLE' not in lg:
            bad.append('M9 a wrong digest installed anyway (rc=%d):\n%s' % (rc, lg[-500:]))
    except StopIteration:
        pass
    finally:
        c.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: sast-mobile, run as shipped on Linux, reports every planted Android and iOS condition '
          '(mobsfscan 1.0.1 by digest + the kit rules), is silent on clean trees, skips cleanly with no '
          'mobile sources, and refuses a hollow scanner, a missing rule file and a wrong digest.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
