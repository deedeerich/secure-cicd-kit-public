#!/usr/bin/env python3
"""C/C++ is analysed THROUGH ITS BUILD when the build can be read without inventing one, and a
source-only analysis says CPP_ANALYSIS_PARTIAL instead of reading like a complete one (lane
L-SCAN-B, KDEC-026).

WHY THIS EXISTS (docs/roadmap/FUTURE_WORK.md section 5, "Build-aware C/C++")

    "Source-only analysis is proven. Compilation database, resolved includes/macros ... are not.
    Report CPP_ANALYSIS_PARTIAL when source exists without build metadata -- and never synthesise a
    build system." CPP_ANALYSIS_PARTIAL was never emitted. MEASURED 2026-10-23 (Ubuntu 24.04,
    cppcheck 2.13.0, cmake 3.28.3, bear 3.1.3) on the planted tree tests/_platform_fixtures.py
    cpp-build/: BUF_LEN is defined in include/config.h, reached only through the include
    directory CMake passes. Source-only, cppcheck reports NOTHING; with the compilation database
    CMake exports it reports arrayIndexOutOfBounds at src/main.c:5. A source-only scan of that
    tree is a false clean, which is exactly why it must be PARTIAL.

WHAT IT PROVES (the sast-cpp composite's steps, extracted AS SHIPPED, run in Ubuntu 24.04)
    B1  CMake tree -> the database comes from `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`, configured
        OUTSIDE the checkout; cppcheck --project finds the planted out-of-bounds write on
        cmake/src/main.c (repository-relative); scan_state COMPLETE; enforce hands FINDINGS
    B2  Makefile tree where `make -n` works -> bear records the build; the planted write on
        make/src/app.c is found
    B3  CONTROL, the gap itself: the same cmake tree source-only (no database) -> nothing found
    B4  no build system -> scan_state PARTIAL, scan_reason CPP_ANALYSIS_PARTIAL, the summary says
        source-only; and NOTHING is written into the source tree (no build system synthesised)
    B5  a committed compile_commands.json whose files do not exist here -> not trusted: PARTIAL
    B6  a CMakeLists.txt whose configure fails -> PARTIAL naming the failure; no invented build
    B7  a CMake root plus a loose .c outside it -> the database is used for its files, the loose
        file is scanned source-only, and the scan is PARTIAL (one file had no build metadata)
    B8  no C/C++ source at all -> NOT_APPLICABLE (unchanged)
    B9  the job publishes scan_state / scan_reason, the gate reads them (PARTIAL, never PASS), and
        assurance-taxonomy.yaml registers CPP_ANALYSIS_PARTIAL as a scan_partial_reason

    FAILS ON c7e1ea9: there is no build-metadata step (B1, B2, B4-B7 fail), scan_state is not
    published (B9), and CPP_ANALYSIS_PARTIAL is not a taxonomy term.

EXIT  0 all hold   1 any does not   2 could not be checked (no docker, no network, no PyYAML)
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

JOB = 'sast-cpp'
INSTALL, BUILD, SCAN, ENFORCE = 'Install analyzers', 'C/C++ build metadata', 'cppcheck', 'cppcheck — enforce'
IMAGE = 'kitproof-cpp:1'
DOCKERFILE = ('FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac\n'
              'RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq '
              '--no-install-recommends cppcheck flawfinder cmake make bear gcc libc6-dev python3 jq '
              '>/dev/null && rm -rf /var/lib/apt/lists/*\n')


def cpp_results(c):
    p = os.path.join(c.ws, 'cppcheck.sarif')
    if not os.path.exists(p):
        return {}
    got = {}
    for run in json.load(io.open(p, encoding='utf-8')).get('runs') or []:
        for r in run.get('results') or []:
            uri = r['locations'][0]['physicalLocation']['artifactLocation']['uri']
            got.setdefault(uri, set()).add(r.get('ruleId', ''))
    return got


def tree_files(c):
    out = set()
    for dp, _dn, fn in os.walk(c.ws):
        for f in fn:
            out.add(os.path.relpath(os.path.join(dp, f), c.ws).replace(os.sep, '/'))
    return out


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    import _docker_step_runner as d
    import _scan_step_harness as h
    import _platform_fixtures as pf
    bad = []

    # B9 (static): the job publishes the state, the gate reads it, the taxonomy registers it.
    doc = h.load()
    jobs = doc.get('jobs') or {}
    outs = (jobs.get(JOB) or {}).get('outputs') or {}
    if 'scan_state' not in outs or 'scan_reason' not in outs:
        bad.append('B9 sast-cpp publishes no scan_state / scan_reason (outputs: %s)' % sorted(outs))
    gate = [s for s in (jobs.get('security-gate') or {}).get('steps') or [] if s.get('id') == 'gate']
    genv = (gate[0].get('env') or {}) if gate else {}
    if 'needs.sast-cpp.outputs.scan_state' not in json.dumps(genv):
        bad.append('B9 the gate does not read sast-cpp\'s scan_state')
    tax = yaml.safe_load(io.open(os.path.join(ROOT, 'assurance-taxonomy.yaml'), encoding='utf-8'))
    def find_key(node, key):
        if isinstance(node, dict):
            if key in node:
                return node[key]
            for v in node.values():
                r = find_key(v, key)
                if r is not None:
                    return r
        return None
    if 'CPP_ANALYSIS_PARTIAL' not in json.dumps((find_key(tax, 'scan_partial_reason') or {}).get('values') or {}):
        bad.append('B9 CPP_ANALYSIS_PARTIAL is not a registered scan_partial_reason in assurance-taxonomy.yaml')

    steps = h.steps_by_name(JOB)
    missing = [n for n in (INSTALL, BUILD, SCAN, ENFORCE) if n not in steps]
    if missing:
        bad.append('B1-B7 the sast-cpp job has no %s step: C/C++ is analysed source-only and never says so'
                   % missing)
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    if not d.docker_ok():
        print('UNKNOWN: docker is not available, so the steps cannot be run on Linux here.')
        return 2
    ok, log = d.build_image(IMAGE, DOCKERFILE)
    if not ok:
        print('UNKNOWN: the proof image could not be built (network?):\n%s' % log[-600:])
        return 2
    c = d.Container(IMAGE, prefix='cpp-proof-')
    base = {'inputs.paths': '.', 'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false'}
    T = pf.TREES['cpp-build']

    def sub(prefix):
        return {k: v for k, v in T.items() if k.startswith(prefix + '/')}

    try:
        rc, lg, _o, _u = c.run(steps[INSTALL], base)
        if rc != 0:
            bad.append('install step failed (rc %d):\n%s' % (rc, lg[-500:]))
            raise StopIteration

        def scan(name, files, paths='.'):
            c.reset_workspace(files)
            before = tree_files(c)
            v = dict(base, **{'inputs.paths': paths})
            rb, lb, ob, ub = c.run(steps[BUILD], v)
            v2 = dict(v, **{'steps.cpp_build.outputs.%s' % k: ob.get(k, '') for k in
                            ('compile_dbs', 'scan_state', 'scan_reason', 'uncovered')})
            rs, ls, os_, us = c.run(steps[SCAN], v2)
            ve = dict(v2, **{'steps.cppcheck.outputs.%s' % k: os_.get(k, '') for k in ('count', 'collection')})
            re_, le, oe, ue = c.run(steps[ENFORCE], ve)
            after = tree_files(c)
            for u in (ub, us, ue):
                if u:
                    bad.append('%s: unmodelled expressions %s' % (name, u))
            res = cpp_results(c)
            print('  %-11s build rc=%d state=%-8s reason=%-21s dbs=%s | cppcheck rc=%d %s count=%s | handed=%r'
                  % (name, rb, ob.get('scan_state'), ob.get('scan_reason', '-'), ob.get('compile_dbs', '')[:40],
                     rs, os_.get('collection'), os_.get('count'), oe.get('findings_state', '')))
            return dict(rb=rb, lb=lb, ob=ob, rs=rs, ls=ls, os=os_, re=re_, oe=oe, res=res,
                        new=sorted(after - before), summary=c.summary())

        def found(res, path, rule):
            return any(rule in r for r in res.get(path, set()))

        r = scan('B1 cmake', sub('cmake'))
        if not found(r['res'], 'cmake/src/main.c', 'arrayIndexOutOfBounds') or r['ob'].get('scan_state') != 'COMPLETE':
            bad.append('B1 cmake: planted write not found build-aware, or state %r\n%s\n%s'
                       % (r['ob'].get('scan_state'), r['lb'][-700:], r['ls'][-700:]))
        if r['oe'].get('findings_state') != 'FINDINGS':
            bad.append('B1 cmake: the build-aware finding was not handed to the gate')
        if any(n.startswith('cmake/') and not n.startswith('cmake/src') and not n.startswith('cmake/include')
               and n != 'cmake/CMakeLists.txt' for n in r['new']):
            bad.append('B1 cmake: configure wrote into the checkout: %s' % r['new'])

        r = scan('B2 make', sub('make'))
        if not found(r['res'], 'make/src/app.c', 'arrayIndexOutOfBounds') or r['ob'].get('scan_state') != 'COMPLETE':
            bad.append('B2 make: planted write not found through bear, or state %r\n%s\n%s'
                       % (r['ob'].get('scan_state'), r['lb'][-700:], r['ls'][-700:]))

        # B3: the gap, measured by the same cppcheck invocation shape, source-only.
        c.reset_workspace(sub('cmake'))
        rc, lg = c.sh('cppcheck --enable=warning,style,performance,portability --inline-suppr --template=gcc cmake 2>&1')
        print('  B3 source-only control: %s' % ('silent' if 'arrayIndexOutOfBounds' not in lg else 'FOUND IT'))
        if 'arrayIndexOutOfBounds' in lg:
            bad.append('B3 the control no longer shows the gap: source-only cppcheck found the planted write')

        r = scan('B4 nobuild', sub('nobuild'))
        if r['ob'].get('scan_state') != 'PARTIAL' or r['ob'].get('scan_reason') != 'CPP_ANALYSIS_PARTIAL':
            bad.append('B4 no build system: state %r reason %r, want PARTIAL / CPP_ANALYSIS_PARTIAL'
                       % (r['ob'].get('scan_state'), r['ob'].get('scan_reason')))
        if 'CPP_ANALYSIS_PARTIAL' not in r['summary']:
            bad.append('B4 the summary does not say CPP_ANALYSIS_PARTIAL')
        synth = [n for n in r['new'] if n.startswith('nobuild/')]
        if synth:
            bad.append('B4 files were written into a tree with no build system: %s' % synth)
        if r['os'].get('collection') != 'COMPLETE':
            bad.append('B4 the source-only scan itself must still run (got %r)' % r['os'].get('collection'))

        stale = dict(sub('nobuild'), **{'compile_commands.json': json.dumps(
            [{'directory': '/home/dev/proj', 'file': '/home/dev/proj/src/loose.c', 'command': 'cc -c src/loose.c'}])})
        r = scan('B5 stale', stale)
        if r['ob'].get('scan_state') != 'PARTIAL':
            bad.append('B5 a compile_commands.json naming files that are not here was trusted (state %r)'
                       % r['ob'].get('scan_state'))

        broken = {'bad/CMakeLists.txt': 'cmake_minimum_required(VERSION 3.10)\nproject(b C)\n'
                                        'message(FATAL_ERROR "needs a dependency this runner lacks")\n',
                  'bad/src/b.c': 'int b(void) { return 0; }\n'}
        r = scan('B6 cfgfail', broken)
        if r['ob'].get('scan_state') != 'PARTIAL' or 'configure' not in r['summary'].lower():
            bad.append('B6 a failed configure: state %r, summary does not name the failure'
                       % r['ob'].get('scan_state'))
        if [n for n in r['new'] if n.startswith('bad/')]:
            bad.append('B6 files were written into the source tree: %s' % r['new'])

        mixed = dict(sub('cmake'), **{'tools/loose.c': '#include <string.h>\nvoid f(const char *s)'
                                      ' { char b[2]; strcpy(b, s); b[3] = 0; }\n'})
        r = scan('B7 mixed', mixed)
        if not found(r['res'], 'cmake/src/main.c', 'arrayIndexOutOfBounds'):
            bad.append('B7 mixed: the build-aware finding was lost')
        if r['ob'].get('scan_state') != 'PARTIAL' or r['ob'].get('uncovered') != '1':
            bad.append('B7 mixed: state %r uncovered %r, want PARTIAL / 1'
                       % (r['ob'].get('scan_state'), r['ob'].get('uncovered')))
        if not r['res'].get('tools/loose.c'):
            bad.append('B7 mixed: the file outside every database was not scanned source-only')

        r = scan('B8 none', {'README.md': 'nothing\n'})
        if r['os'].get('collection') != 'NOT_APPLICABLE' or r['rs'] != 0:
            bad.append('B8 no C/C++: %r (rc %d)' % (r['os'].get('collection'), r['rs']))
    except StopIteration:
        pass
    finally:
        c.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: sast-cpp reads the build when CMake or make can describe it (cppcheck --project finds '
          'what source-only misses), never invents a build system, and says CPP_ANALYSIS_PARTIAL -- a '
          'visible partial, read by the gate -- whenever any source had no build metadata.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
