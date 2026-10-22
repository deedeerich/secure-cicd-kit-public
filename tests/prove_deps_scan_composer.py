#!/usr/bin/env python3
"""PHP dependencies: the deps-scan job reports a vulnerable Composer package from composer.lock and
blocks on it, and a composer.json with no lock is a NAMED gap, never a quiet pass (lane L-PHP).

WHY THIS EXISTS

    Trivy fs runs on every repository and reads composer.lock -- incidentally: nothing proved a
    Composer advisory came back through the job's own count and enforce steps. And Trivy reads ONLY
    the lock. Measured locally with trivy 0.71.2 on 2026-10-21:

      * composer.lock pinning phpmailer/phpmailer v5.2.18 -> CVE-2016-10045 CRITICAL, four HIGH
        (CVE-2018-19296, CVE-2020-13625, CVE-2021-34551, CVE-2021-3603) and two MEDIUM;
      * the same package named in a composer.json with no lock beside it -> no result at all.

    A manifest is a set of constraints; the lock is the versions. So a repository that commits
    composer.json without composer.lock gets a dependency scan that passes over PHP it never read.
    Discovery now declares that as COVERAGE_GAP `PHPDependenciesUnlocked`, counted and named, the
    way it declares every other class nothing here can read.

WHAT IT PROVES (deps-scan's Trivy step reproduced as trivy-action@v0.36.0 runs it -- the
reproduction tests/prove_trivy_threshold.py established -- and the count and enforce steps as
shipped; the discovery survey as shipped)
    C1  composer.lock with phpmailer/phpmailer v5.2.18 -> a result on composer.lock at CRITICAL or
        HIGH, a count >= 1 at the default threshold, and the job hands it to the security gate
        (findings_state=FINDINGS; the job succeeds -- lane L-S, O-24: the gate enforces)
    C2  CONTROL: composer.lock with a package carrying no advisory -> count 0, the job PASSES
    C3  composer.json alone (the same vulnerable package) -> Trivy reports nothing for it (the
        measured limit, re-measured every run so a Trivy that learns to read manifests is seen)
    C4  ...and the discovery survey over that tree declares PHPDependenciesUnlocked: named in
        coverage_gaps, counted, warned, with the lock it needs -- never silence
    C5  the seeds stay seeds: .github/dependabot.yml lists composer, and EVERY ecosystem in it
        excludes tests/consumer-fixture/** (a Dependabot PR "fixing" the fixture's pins makes the
        detection proofs pass for the wrong reason -- the public mirror received such PRs)

    FAILS ON 75d935c at C4 (no php ecosystem; the unlocked manifest is not declared) and C5 (no
    composer entry). C1-C3 hold there too: Trivy always read composer.lock; what was missing was
    the proof, and the gap.

EXIT  0 all hold, 1 any does not, 2 could not be checked (no bash, no trivy, no database)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402
import prove_trivy_threshold as ptt  # noqa: E402
import test_discovery as td  # noqa: E402

JOB = 'deps-scan'
CFG = ptt.JOBS[JOB]
# The vulnerable pin: phpmailer/phpmailer v5.2.18 (CVE-2016-10033 / CVE-2016-10045, remote code
# execution through the mail() sender). Identical to the seed tests/make_fixture.py writes.
VULN_PKG = ('phpmailer/phpmailer', 'v5.2.18')
CLEAN_PKG = ('psr/log', '3.0.2')


def lock(pkg):
    return json.dumps({
        "_readme": ["Test-only seed (tests/prove_deps_scan_composer.py)."],
        "content-hash": "0" * 32,
        "packages": [{"name": pkg[0], "version": pkg[1], "type": "library"}],
        "packages-dev": [], "aliases": [], "minimum-stability": "stable",
        "stability-flags": [], "prefer-stable": False, "prefer-lowest": False,
        "platform": {"php": ">=7.4"}, "platform-dev": [], "plugin-api-version": "2.6.0"},
        indent=4) + "\n"


def manifest(pkg):
    return json.dumps({"name": "seed/php-app",
                       "require": {"php": ">=7.4", pkg[0]: pkg[1].lstrip('v')}}, indent=4) + "\n"


def results_on(sarif, name):
    """-> severities of results whose location names `name`."""
    doc = json.load(open(sarif, encoding='utf-8'))
    out = []
    for run_ in doc.get('runs', []):
        rules = {r['id']: r for r in run_.get('tool', {}).get('driver', {}).get('rules', [])}
        for r in run_.get('results', []):
            uris = [l['physicalLocation']['artifactLocation']['uri'] for l in r.get('locations', [])]
            if any(u.replace('\\', '/').endswith(name) for u in uris):
                tags = rules.get(r.get('ruleId'), {}).get('properties', {}).get('tags', [])
                out += [t for t in tags if t in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')] or ['?']
    return out


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    steps = h.steps_by_name(JOB)
    prod = [s for s in h.job(JOB).get('steps', []) if 'trivy-action' in str(s.get('uses'))
            and str((s.get('with') or {}).get('output')) == CFG['producer_output']]
    if not prod or CFG['count'] not in steps or CFG['enforce'] not in steps:
        print('UNKNOWN: deps-scan does not carry the Trivy, count and enforce steps this reproduces.')
        return 2
    bad = []
    sb = h.Sandbox('deps-composer-').with_bundle()
    try:
        if not h.have(bash, 'trivy', ''):
            print('UNKNOWN: trivy is required.')
            return 2
        inputs = {'fail_on_severity': 'CRITICAL,HIGH', 'advisory_mode': 'false', 'paths': '.'}
        vals = {'inputs.%s' % k: v for k, v in inputs.items()}
        scen = [('C1 vulnerable lock', {'web/composer.json': manifest(VULN_PKG),
                                        'web/composer.lock': lock(VULN_PKG)}, 'fail'),
                ('C2 clean lock', {'web/composer.json': manifest(CLEAN_PKG),
                                   'web/composer.lock': lock(CLEAN_PKG)}, 'pass'),
                ('C3 manifest alone', {'web/composer.json': manifest(VULN_PKG)}, 'pass')]
        for name, files, expect in scen:
            ws = sb.workspace(name.split()[0], files)
            trc, err = ptt.run_action(prod[0], inputs, '.', ws)
            if 'failed to download' in err.lower() or 'db error' in err.lower():
                print('UNKNOWN: Trivy could not obtain its vulnerability database.')
                return 2
            sarif = os.path.join(ws, CFG['producer_output'])
            on_lock = results_on(sarif, 'composer.lock') if os.path.isfile(sarif) else []
            on_json = results_on(sarif, 'composer.json') if os.path.isfile(sarif) else []
            crc, clog, cout, unk = sb.run(bash, steps[CFG['count']], vals, ws)
            v2 = dict(vals, **{'steps.%s.outputs.%s' % (CFG['count_id'], k): cout.get(k, '')
                               for k in ('count', 'collection')})
            erc, elog, eout, _u = sb.run(bash, steps[CFG['enforce']], v2, ws)
            failed = trc != 0 or erc != 0
            handed = eout.get('findings_state', '')
            print('  %-20s trivy=%d lock=%s json=%s count=%s job %s%s'
                  % (name, trc, ','.join(on_lock) or '-', ','.join(on_json) or '-',
                     cout.get('count', '-'), 'FAILS' if failed else 'passes',
                     ', hands the gate %s' % handed if handed else ''))
            if name.startswith('C1'):
                if not ({'CRITICAL', 'HIGH'} & set(on_lock)):
                    bad.append('C1 no CRITICAL/HIGH result on composer.lock for %s %s'
                               % VULN_PKG)
                # Handed to the security gate, the single enforcement point (lane L-S, O-24):
                # the job succeeds and the gate enforces it by the resolved policy.
                if failed or handed != 'FINDINGS':
                    bad.append('C1 the vulnerable Composer package was not handed to the gate '
                               '(job %s, findings_state %r)'
                               % ('failed' if failed else 'passed', handed))
            if name.startswith('C2') and (failed or handed):
                bad.append('C2 CONTROL: a lock with no advisory failed the job or was handed to '
                           'the gate (count %s)' % cout.get('count'))
            if name.startswith('C3') and on_json:
                bad.append('C3 Trivy now reports composer.json alone (%s): the measured limit has '
                           'changed -- re-examine PHPDependenciesUnlocked' % on_json)
        shell = td.extract_discovery_shell()
        got = td.run_case(shell, ['web/index.php', 'web/composer.json'])
        gaps = got.get('coverage_gaps', '').split(',')
        print('  C4 discovery: php=%s coverage_gaps=%r count=%s'
              % (got.get('php'), got.get('coverage_gaps'), got.get('coverage_gap_count')))
        if 'PHPDependenciesUnlocked' not in gaps:
            bad.append('C4 a composer.json with no lock is not declared: coverage_gaps=%r'
                       % got.get('coverage_gaps'))
        elif 'composer.lock' not in got.get('__summary__', '') or \
                '::warning title=COVERAGE_GAP: PHPDependenciesUnlocked::' not in got.get('__log__', ''):
            bad.append('C4 the unlocked-manifest gap is declared but not warned and named in the summary')
        import yaml
        dep = yaml.safe_load(open(os.path.join(h.ROOT, '.github', 'dependabot.yml'),
                                  encoding='utf-8')) or {}
        ups = dep.get('updates') or []
        ecos = [u.get('package-ecosystem') for u in ups]
        unguarded = [u.get('package-ecosystem') for u in ups
                     if 'tests/consumer-fixture/**' not in (u.get('exclude-paths') or [])]
        print('  C5 dependabot ecosystems: %s; without the fixture exclusion: %s'
              % (', '.join(str(e) for e in ecos), unguarded or 'none'))
        if 'composer' not in ecos:
            bad.append('C5 .github/dependabot.yml lists no composer ecosystem')
        if unguarded:
            bad.append('C5 ecosystem(s) %s do not exclude tests/consumer-fixture/**' % unguarded)
    finally:
        sb.close()
    for b in bad:
        print('FAIL %s' % b)
    if bad:
        return 1
    print('PASS: a vulnerable Composer package in composer.lock blocks deps-scan; a clean lock passes;')
    print('      composer.json alone is read by nothing and discovery declares it PHPDependenciesUnlocked.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
