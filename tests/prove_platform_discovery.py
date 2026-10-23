#!/usr/bin/env python3
"""Kotlin, Swift, Objective-C and Android/iOS configuration are DISCOVERED and ROUTED to scanners,
never declared a COVERAGE_GAP and never left unprobed (lane L-SCAN-B, KDEC-026).

WHY THIS EXISTS (docs/roadmap/FUTURE_WORK.md section 5, the two mobile rows)

    * "A Kotlin-only repository gets no scanner": discovery named `.kt` a COVERAGE_GAP, the java
      probe read only pom.xml / build.gradle, so CodeQL's java-kotlin leg never started for Kotlin
      without a Java build file, and nothing guaranteed the Kotlin rules a caller's
      `semgrep_config` could narrow away (measured 2026-10-23: the shipped default, p/default,
      happens to carry 18 Kotlin rules -- incidental, unwitnessed coverage).
    * "Objective-C is not even probed": no `.m` or `.mm` anywhere in discovery, so an ObjC-only
      repository reported no gap at all; Swift was a declared COVERAGE_GAP.
    * Android manifests, network security configs and Info.plist ATS settings had no scanner.

WHAT IT PROVES (the survey run AS SHIPPED, from the discover composite, via tests/test_discovery.py)
    D1  Kotlin only (no Gradle, no Maven)  -> kotlin=true, java=false; Kotlin is NOT a coverage gap
    D2  Objective-C only (.m)              -> mobile=true; nothing reads it as NOT_APPLICABLE
    D3  Objective-C++ only (.mm)           -> mobile=true
    D4  Swift                              -> swift=true, mobile=true; Swift is NOT a coverage gap
    D5  AndroidManifest.xml alone          -> mobile=true
    D6  Info.plist alone                   -> mobile=true
    D7  ABSENT: Python only                -> kotlin, swift, mobile all false (NOT_APPLICABLE rows)
    D8  the Kotlin probe fails             -> kotlin=true (UNDETERMINED -> RUN), state PARTIAL
    D9  discovery itself fails             -> kotlin, swift and mobile force-enabled
    D10 the selector names kotlin / swift / mobile without being refused as unrecognised
WIRING (static, from the flagship as shipped)
    W1  the discover job publishes kotlin, swift and mobile from the survey step
    W2  CodeQL starts on Kotlin, and its java-kotlin leg is gated on java OR kotlin
    W3  sast-semgrep reads discover's kotlin answer as data and adds the p/kotlin floor
    W4  a sast-mobile job runs on discover's mobile answer, through its composite
    W5  resolve receives discover's kotlin and swift answers

    FAILS ON c7e1ea9: D1 (kotlin unset, `Kotlin` in coverage_gaps), D2/D3 (mobile unset), D4
    (Swift a coverage gap), D5/D6, W1-W5.

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

WF = os.path.join(os.path.dirname(HERE), '.github', 'workflows', 'reusable-security.yml')


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    import test_discovery as td
    shell = td.extract_discovery_shell()
    ok = True
    run, check, check_text = td.run_case, td.check, td.check_text

    k = run(shell, ['src/Main.kt', 'src/util/Strings.kt'])
    ok &= check('D1 kotlin only -> kotlin RUN', k, {'kotlin': 'true', 'java': 'false', 'state': 'COMPLETE'})
    ok &= check_text('D1 kotlin is not a coverage gap', k, '__summary__',
                     must=['| kotlin | RUN |'], must_not=['| Kotlin | COVERAGE_GAP |'])
    ok &= td.check_bool('D1 coverage_gaps carries no Kotlin', 'Kotlin' not in k.get('coverage_gaps', 'Kotlin'),
                        'coverage_gaps=%r' % k.get('coverage_gaps'))

    m = run(shell, ['App/Legacy.m'])
    ok &= check('D2 objective-c only -> mobile RUN', m, {'mobile': 'true', 'swift': 'false', 'state': 'COMPLETE'})
    ok &= check_text('D2 objective-c is a RUN row', m, '__summary__', must=['| mobile | RUN |'],
                     must_not=['| mobile | NOT_APPLICABLE |'])
    ok &= check('D3 objective-c++ only -> mobile RUN', run(shell, ['App/Bridge.mm']), {'mobile': 'true'})

    s = run(shell, ['ios/App/AppDelegate.swift'])
    ok &= check('D4 swift -> swift + mobile RUN', s, {'swift': 'true', 'mobile': 'true'})
    ok &= td.check_bool('D4 coverage_gaps carries no Swift', 'Swift' not in s.get('coverage_gaps', 'Swift'),
                        'coverage_gaps=%r' % s.get('coverage_gaps'))
    ok &= check('D5 AndroidManifest.xml -> mobile RUN',
                run(shell, ['app/src/main/AndroidManifest.xml']), {'mobile': 'true', 'kotlin': 'false'})
    ok &= check('D6 Info.plist -> mobile RUN', run(shell, ['App/Info.plist']), {'mobile': 'true'})

    a = run(shell, ['app/main.py'])
    ok &= check('D7 absent -> not applicable', a, {'kotlin': 'false', 'swift': 'false', 'mobile': 'false'})
    ok &= check_text('D7 absence is a NOT_APPLICABLE row', a, '__summary__',
                     must=['| kotlin | NOT_APPLICABLE |', '| swift | NOT_APPLICABLE |',
                           '| mobile | NOT_APPLICABLE |'])

    ok &= check('D8 kotlin probe failed -> UNDETERMINED -> RUN',
                run(shell, ['app/main.py'], break_probes=['*.kt']),
                {'kotlin': 'true', 'python': 'true', 'state': 'DISCOVERY_PARTIAL'})
    ok &= check('D9 discovery failure -> mobile classes ON',
                run(shell, ['app/main.py'], break_find=True),
                {'state': 'DISCOVERY_UNAVAILABLE', 'kotlin': 'true', 'swift': 'true', 'mobile': 'true'})
    sel = run(shell, ['src/Main.kt', 'App/Legacy.m'], language='kotlin,mobile,swift')
    ok &= check('D10 selector names the new classes', sel, {'kotlin': 'true', 'mobile': 'true'})

    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    jobs = doc.get('jobs') or {}
    outs = (jobs.get('discover') or {}).get('outputs') or {}
    ok &= td.check_bool('W1 discover publishes kotlin/swift/mobile',
                        all(str(outs.get(n, '')).strip() == '${{ steps.d.outputs.%s }}' % n
                            for n in ('kotlin', 'swift', 'mobile')), 'outputs=%s' % sorted(outs))
    cq = jobs.get('codeql') or {}
    legs = {i.get('lang'): str(i.get('gate')) for i in
            (((cq.get('strategy') or {}).get('matrix') or {}).get('include') or [])}
    ok &= td.check_bool('W2 codeql starts on kotlin; java-kotlin gated java OR kotlin',
                        'needs.discover.outputs.kotlin' in str(cq.get('if', ''))
                        and 'outputs.kotlin' in legs.get('java-kotlin', '')
                        and 'outputs.java' in legs.get('java-kotlin', ''),
                        'if=%r java-kotlin gate=%r' % (cq.get('if'), legs.get('java-kotlin')))
    sg = [s for s in (jobs.get('sast-semgrep') or {}).get('steps') or [] if s.get('id') == 'semgrep']
    sg = sg[0] if sg else {}
    ok &= td.check_bool('W3 semgrep reads kotlin as data, adds p/kotlin',
                        str((sg.get('env') or {}).get('IN_DISCOVERED_KOTLIN', '')).strip()
                        == '${{ needs.discover.outputs.kotlin }}'
                        and re.search(r'--config p/kotlin', str(sg.get('run', ''))) is not None
                        and '${{' not in re.sub(r'\$\{\{ steps\.[^}]*\}\}', '', str(sg.get('run', ''))),
                        'env=%s' % sorted((sg.get('env') or {})))
    mob = jobs.get('sast-mobile') or {}
    uses = [s.get('uses') for s in mob.get('steps') or []]
    ok &= td.check_bool('W4 sast-mobile runs on discover mobile',
                        str(mob.get('if', '')).replace('"', "'").strip() == "needs.discover.outputs.mobile == 'true'"
                        and '$/.github/actions/sast-mobile' in uses,
                        'if=%r uses=%r' % (mob.get('if'), uses))
    rs = [s for s in (jobs.get('resolve') or {}).get('steps') or [] if s.get('uses') == '$/.github/actions/resolve']
    w = (rs[0].get('with') or {}) if rs else {}
    ok &= td.check_bool('W5 resolve receives kotlin and swift',
                        str(w.get('discovered-kotlin', '')).strip() == '${{ needs.discover.outputs.kotlin }}'
                        and str(w.get('discovered-swift', '')).strip() == '${{ needs.discover.outputs.swift }}',
                        'with=%s' % sorted(w))
    print()
    if not ok:
        print('FAIL: Kotlin / Swift / Objective-C / mobile configuration discovery or routing is not as KDEC-026 requires.')
        return 1
    print('PASS: Kotlin, Swift, Objective-C and Android/iOS configuration are discovered, routed to scanners '
          'and never read as a coverage gap or NOT_APPLICABLE when present.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
