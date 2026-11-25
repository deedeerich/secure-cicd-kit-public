#!/usr/bin/env python3
"""Java4Shell (CVE-2026-114938) exposure check: scripts/java4shell_check.py classifies every
runtime it finds, and "could not establish" never reads as "not affected" (owner 2026-11-19:
"we need to be able to check for this in our environment immediately").

WHAT IT PROVES -- fixtures only, no network, no docker

    J1  version classification against the advisory table, for every numbering the vendors use
        (OpenJDK/Oracle, Corretto 4+1, Zulu/Temurin +build, Microsoft .0.2, Debian -1, Java 8
        1.8.0_x and 8u, EOL lines, 17.0.0-17.0.5, a bare line, OpenJ9, an unreadable string)
    J2  CPU: /proc/cpuinfo with all four flags is VULNERABLE, one missing is NOT_VULNERABLE, ARM is
        NOT_VULNERABLE, no flags line is UNKNOWN; the JVM's own os+cpu log likewise (a real line
        captured from a 12th-gen Core i9 with no AVX-512), and no CPU line is UNKNOWN
    J3  the combined verdict: affected + vulnerable CPU + no workaround = AFFECTED; the workaround
        seen in the running JVM = AFFECTED_MITIGATED; no CPU = AFFECTED_CPU_UNKNOWN (never
        NOT_AFFECTED); CPU without VBMI = AFFECTED_CPU_NOT_VULNERABLE; ARM = NOT_AFFECTED;
        JAVA_TOOL_OPTIONS alone is NOT proof the running JVM is mitigated
    J4  `java -version`, a JDK `release` file, PrintFlagsFinal and jcmd VM.flags are parsed
    J5  repo mode: Dockerfile bases (pinned build, floating tag, product image, build arg,
        build vs final stage, digest), setup-java, App Service linuxFxVersion; a declared line
        without a build is UNKNOWN; a non-Java repo reports nothing
    J6  host mode with --no-exec over a planted JDK home finds it, reads its release file and,
        with the CPU not read, says AFFECTED_CPU_UNKNOWN -- never NOT_AFFECTED
    J7  exit codes: 2 for any AFFECTED*, 1 for UNKNOWN only, 0 for clean; --json is written
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'scripts'))
import java4shell_check as j  # noqa: E402

FAILS = []


def check(cond, label):
    print(('  ok   ' if cond else '  FAIL ') + label)
    if not cond:
        FAILS.append(label)


VULN_CPU = 'processor\t: 0\nflags\t\t: fpu sse2 avx2 avx512f avx512bw avx512vbmi bmi2 aes\n'
NOVBMI_CPU = 'processor\t: 0\nflags\t\t: fpu sse2 avx2 avx512f avx512bw bmi2 aes\n'
ARM_CPU = 'processor\t: 0\nBogoMIPS\t: 50.00\nFeatures\t: fp asimd aes\nCPU implementer\t: 0x41\n'
# Captured 2026-11-19 from this repo's development machine (12th Gen Core i9-12900HK, no AVX-512).
REAL_JVM_CPU = ('[0.009s][info][os,cpu] CPU: total 20 (initial active 20) (10 cores per cpu, 2 threads '
                'per core) family 6 model 154 stepping 3 microcode 0x43b, cx8, cmov, fxsr, ht, mmx, sse, '
                'sse2, sse3, ssse3, sse4.1, sse4.2, popcnt, lzcnt, tsc, avx, avx2, aes, erms, clmul, bmi1, '
                'bmi2, adx, sha, fma, vzeroupper, clflush, clflushopt, clwb, hv, serialize\n'
                'java version "18" 2022-03-22\n')
REAL_JAVA18 = ('java version "18" 2022-03-22\nJava(TM) SE Runtime Environment (build 18+36-2087)\n'
               'Java HotSpot(TM) 64-Bit Server VM (build 18+36-2087, mixed mode, sharing)\n')
CORRETTO_FIXED = ('openjdk version "21.0.13" 2026-11-17 LTS\nOpenJDK Runtime Environment '
                  'Corretto-21.0.13.1.2 (build 21.0.13.1+2-LTS)\nOpenJDK 64-Bit Server VM Corretto-21.0.13.1.2 '
                  '(build 21.0.13.1+2-LTS, mixed mode, sharing)\n')
TEMURIN_OLD = ('openjdk version "17.0.21" 2026-10-20\nOpenJDK Runtime Environment Temurin-17.0.21+9 '
               '(build 17.0.21+9)\nOpenJDK 64-Bit Server VM Temurin-17.0.21+9 (build 17.0.21+9, mixed mode)\n')
SEMERU = ('openjdk version "21.0.13" 2026-10-20\nIBM Semeru Runtime Open Edition 21.0.13.0 (build '
          '21.0.13+9)\nEclipse OpenJ9 VM 21.0.13.0 (build openj9-0.50.0, JRE 21 Linux amd64-64-Bit)\n')
FLAGS_ON = ('     intx UseAVX                                   = 3                {ARCH product} {default}\n'
            '     bool UseBASE64Intrinsics                      = true             {product} {default}\n')
FLAGS_REAL = ('     intx UseAVX                                   = 2                {ARCH product} {default}\n'
              '     bool UseBASE64Intrinsics                      = false            {product} {default}\n')
JCMD_MITIGATED = '-XX:CICompilerCount=4 -XX:-UseBASE64Intrinsics -XX:+UseG1GC\n'


def j1():
    print('J1 version classification')
    cases = [
        ('17.0.5', 'NOT_AFFECTED'), ('17.0.6', 'AFFECTED_VERSION'), ('17.0.21+9', 'AFFECTED_VERSION'),
        ('17.0.21.0.3', 'AFFECTED_VERSION'), ('17.0.21.1', 'FIXED'), ('17.0.21.1.2', 'FIXED'),
        ('17.0.22', 'FIXED'), ('21.0.13.0.2', 'AFFECTED_VERSION'), ('21.0.13.1+2-LTS', 'FIXED'),
        ('21.0.13.1+2-1', 'FIXED'), ('21.0.12', 'AFFECTED_VERSION'), ('25.0.5.0.3', 'AFFECTED_VERSION'),
        ('25.0.5.1', 'FIXED'), ('27.0.1', 'AFFECTED_VERSION'), ('27.0.1.1+4', 'FIXED'),
        ('18+36-2087', 'AFFECTED_VERSION'), ('26.0.2', 'AFFECTED_VERSION'), ('11.0.25', 'NOT_AFFECTED'),
        ('1.8.0_402', 'NOT_AFFECTED'), ('8u402', 'NOT_AFFECTED'), ('1.8.0_511-perf', 'UNKNOWN'),
        ('21', 'UNKNOWN'), ('16.0.2', 'UNKNOWN'), ('garbage', 'UNKNOWN'), (None, 'UNKNOWN'),
    ]
    for v, want in cases:
        got = j.classify_version(v)[0]
        check(got == want, '%-18s -> %s (got %s)' % (v, want, got))
    check(j.classify_version('21.0.13', 'Eclipse OpenJ9 VM 21.0.13.0')[0] == 'UNKNOWN',
          'OpenJ9 is UNKNOWN (vendor to confirm), not NOT_AFFECTED')
    # Azul Platform Prime lists affected 8 and 11 builds; standard OpenJDK 8/11 are not affected.
    for v, vm in (('11.0.25', 'Zing 64-Bit Tiered VM (build 11.0.25-zing_25.10.0.0-b3-product-linux-x86_64)'),
                  ('1.8.0_452', 'Zing 64-Bit Tiered VM'), ('21.0.13.1', 'Zing 64-Bit Tiered VM')):
        check(j.classify_version(v, vm)[0] == 'UNKNOWN', 'Azul Prime/Zing %s -> UNKNOWN, never NOT_AFFECTED or FIXED' % v)
    check(j.classify_version('11.0.25', '', 'Azul Platform Prime')[0] == 'UNKNOWN', 'vendor "Azul Platform Prime" -> UNKNOWN')
    check(j.classify_version('11.0.25', 'OpenJDK 64-Bit Server VM Zulu11.76+21-CA', 'Azul Zulu')[0] == 'NOT_AFFECTED',
          'Azul Zulu (HotSpot) 11 stays NOT_AFFECTED')


def j2():
    print('J2 CPU')
    check(j.cpu_from_cpuinfo(VULN_CPU)[0] == 'VULNERABLE', 'all four flags -> VULNERABLE')
    check(j.cpu_from_cpuinfo(NOVBMI_CPU)[0] == 'NOT_VULNERABLE', 'no avx512vbmi -> NOT_VULNERABLE')
    check(j.cpu_from_cpuinfo(ARM_CPU)[0] == 'NOT_VULNERABLE' and 'ARM' in j.cpu_from_cpuinfo(ARM_CPU)[1],
          'ARM -> NOT_VULNERABLE (ARM)')
    check(j.cpu_from_cpuinfo('processor : 0\n')[0] == 'UNKNOWN', 'no flags line -> UNKNOWN')
    check(j.cpu_from_cpuinfo('')[0] == 'UNKNOWN', 'empty -> UNKNOWN')
    check(j.cpu_from_jvm_log(REAL_JVM_CPU)[0] == 'NOT_VULNERABLE', 'real JVM log, Core i9 no AVX-512 -> NOT_VULNERABLE')
    vuln_log = REAL_JVM_CPU.replace('avx2,', 'avx2, avx512f, avx512bw, avx512_vbmi,')
    check(j.cpu_from_jvm_log(vuln_log)[0] == 'VULNERABLE', 'JVM log with avx512_vbmi -> VULNERABLE')
    check(j.cpu_from_jvm_log(REAL_JAVA18)[0] == 'UNKNOWN', 'no CPU line in JVM output -> UNKNOWN')
    check(j.cpu_from_jvm_log('probe failed: x')[0] == 'UNKNOWN', 'failed probe -> UNKNOWN')


def j3():
    print('J3 combined verdict')
    V, N, A, U = (('VULNERABLE', 'x'), ('NOT_VULNERABLE', 'CPU lacks avx512vbmi'),
                  ('NOT_VULNERABLE', 'ARM CPU (not affected)'), ('UNKNOWN', 'not read'))
    off, on, unk = (False, 'on'), (True, 'flag off'), (None, 'not read')
    check(j.verdict('21.0.12', cpu=V, mitigated=off)[0] == 'AFFECTED', 'affected + vuln CPU + intrinsic on -> AFFECTED')
    check(j.verdict('21.0.12', cpu=V, mitigated=unk)[0] == 'AFFECTED', 'affected + vuln CPU + flags unread -> AFFECTED')
    check(j.verdict('21.0.12', cpu=V, mitigated=on)[0] == 'AFFECTED_MITIGATED', 'workaround in the JVM -> AFFECTED_MITIGATED')
    check(j.verdict('21.0.12', cpu=U, mitigated=unk)[0] == 'AFFECTED_CPU_UNKNOWN', 'CPU unread -> AFFECTED_CPU_UNKNOWN')
    check(j.verdict('21.0.12', cpu=N, mitigated=unk)[0] == 'AFFECTED_CPU_NOT_VULNERABLE', 'no VBMI -> AFFECTED_CPU_NOT_VULNERABLE')
    check(j.verdict('21.0.12', cpu=A, mitigated=unk)[0] == 'NOT_AFFECTED', 'ARM -> NOT_AFFECTED')
    check(j.verdict('21.0.13.1', cpu=V)[0] == 'FIXED', 'fixed build -> FIXED')
    check(j.verdict('21', cpu=V)[0] == 'UNKNOWN', 'bare line, x86 VBMI -> UNKNOWN, not NOT_AFFECTED')
    check(j.verdict(None, cpu=U)[0] == 'UNKNOWN', 'nothing known -> UNKNOWN')
    m = j.mitigation_from_flags({}, '-XX:-UseBASE64Intrinsics')
    check(m[0] is None, 'JAVA_TOOL_OPTIONS alone does not prove the running JVM is mitigated')
    check(j.mitigation_from_flags(j.parse_flags_final(FLAGS_ON))[0] is False, 'flags on -> not mitigated')
    check(j.mitigation_from_flags(j.parse_flags_final(FLAGS_REAL))[0] is True, 'UseAVX=2/Base64 off -> mitigated')
    check(j.mitigation_from_flags(j.parse_flags_final(JCMD_MITIGATED))[0] is True, 'jcmd -XX:-UseBASE64Intrinsics -> mitigated')
    check(j.mitigation_from_flags({})[0] is None, 'no flags -> None, never False')


def j4():
    print('J4 parsing')
    p = j.parse_java_version_output(REAL_JAVA18)
    check(p['version'] == '18+36-2087' and 'HotSpot' in p['vm'], 'real java 18 -version: %s / %s' % (p['version'], p['vm']))
    p = j.parse_java_version_output(CORRETTO_FIXED)
    check(j.classify_version(p['version'])[0] == 'FIXED', 'Corretto 21.0.13.1.2 -> FIXED (%s)' % p['version'])
    p = j.parse_java_version_output(TEMURIN_OLD)
    check(j.classify_version(p['version'])[0] == 'AFFECTED_VERSION', 'Temurin 17.0.21+9 -> affected (%s)' % p['version'])
    p = j.parse_java_version_output(SEMERU)
    check(j.classify_version(p['version'], p['vm'])[0] == 'UNKNOWN', 'Semeru/OpenJ9 -> UNKNOWN (%s)' % p['vm'])
    rel = 'IMPLEMENTOR="Eclipse Adoptium"\nJAVA_RUNTIME_VERSION="21.0.13+11-LTS"\nJAVA_VERSION="21.0.13"\nJVM_VARIANT="Hotspot"\n'
    p = j.parse_java_version_output(rel)
    check(p['version'] == '21.0.13+11-LTS' and p['vendor'] == 'Eclipse Adoptium', 'release file read: %s' % p)
    f = j.parse_flags_final(FLAGS_ON)
    check(f == {'UseBASE64Intrinsics': 'true', 'UseAVX': '3'}, 'PrintFlagsFinal parsed: %s' % f)


def write(root, rel, text):
    p = os.path.join(root, *rel.split('/'))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w', encoding='utf-8') as fh:
        fh.write(text)


def j5(tmp):
    print('J5 repo mode')
    r = os.path.join(tmp, 'repo')
    write(r, 'svc/Dockerfile', 'FROM maven:3.9-eclipse-temurin-21 AS build\nRUN mvn package\n'
          'FROM eclipse-temurin:21.0.13_11-jre\nCOPY --from=build /app.jar /app.jar\n')
    write(r, 'pinned/Dockerfile', 'FROM eclipse-temurin:21.0.13.1_2-jre@sha256:' + 'a' * 64 + '\n')
    write(r, 'floating/Dockerfile', 'FROM amazoncorretto:21-al2023\n')
    write(r, 'ubi/Dockerfile', 'FROM registry.access.redhat.com/ubi9/openjdk-21:1.20\n')
    write(r, 'arg/Dockerfile', 'ARG BASE=eclipse-temurin:21\nFROM ${BASE}\nCOPY app.jar /\n')
    write(r, 'kc/Dockerfile', 'FROM quay.io/keycloak/keycloak:26.0\n')
    write(r, 'node/Dockerfile', 'FROM node:22-alpine\n')
    write(r, '.github/workflows/ci.yml', 'jobs:\n  b:\n    steps:\n      - uses: actions/setup-java@v4\n'
          '        with:\n          java-version: "17.0.20"\n')
    write(r, 'infra/app.bicep', "  siteConfig: {\n    linuxFxVersion: 'JAVA|21-java21'\n  }\n")
    res = j.check_repo(r)
    by = {x['where']: x for x in res}
    get = lambda w: by.get(w, {}).get('verdict')
    check(get('svc/Dockerfile:3') == 'AFFECTED_CPU_UNKNOWN', 'final stage temurin 21.0.13_11 -> AFFECTED_CPU_UNKNOWN (%s)' % get('svc/Dockerfile:3'))
    check('final stage' in by.get('svc/Dockerfile:3', {}).get('kind', ''), 'final stage labelled')
    check('build stage' in by.get('svc/Dockerfile:1', {}).get('kind', '') and get('svc/Dockerfile:1') == 'UNKNOWN',
          'maven build stage -> UNKNOWN, labelled build stage')
    check(get('pinned/Dockerfile:1') == 'FIXED' and by['pinned/Dockerfile:1'].get('digest_pinned') is True,
          'digest-pinned 21.0.13.1 -> FIXED, digest noted')
    check(get('floating/Dockerfile:1') == 'UNKNOWN', 'floating corretto:21 -> UNKNOWN (resolve the image)')
    check(get('ubi/Dockerfile:1') == 'UNKNOWN', 'ubi9/openjdk-21:1.20 -> UNKNOWN by line, not "Java 1"')
    check(get('arg/Dockerfile:2') == 'UNKNOWN', 'FROM ${BASE} in a Java Dockerfile -> UNKNOWN')
    check(get('kc/Dockerfile:1') == 'UNKNOWN', 'keycloak product image -> UNKNOWN (bundled JDK, inspect image)')
    check(not any(w.startswith('node/') for w in by), 'node base reports nothing')
    check(get('.github/workflows/ci.yml:6') == 'AFFECTED_CPU_UNKNOWN', 'setup-java 17.0.20 -> AFFECTED_CPU_UNKNOWN')
    check(get('infra/app.bicep:2') == 'UNKNOWN', 'App Service JAVA|21 -> UNKNOWN (platform build)')
    empty = os.path.join(tmp, 'empty')
    write(empty, 'README.md', 'hello\n')
    check(j.check_repo(empty) == [], 'non-Java repo -> no rows')
    return r


def j6(tmp):
    print('J6 host mode, --no-exec, planted JDK home')
    root = os.path.join(tmp, 'opt')
    home = os.path.join(root, 'product', 'jre')
    write(home, 'release', 'IMPLEMENTOR="Eclipse Adoptium"\nJAVA_VERSION="21.0.12"\n')
    write(home, 'bin/java', '')
    write(home, 'bin/java.exe', '')
    res = [x for x in j.check_host([root], 'internet', no_exec=True) if x['where'] == os.path.realpath(home)]
    check(len(res) == 1, 'planted home found under --root')
    if res:
        v = res[0]['verdict']
        if os.path.isfile('/proc/cpuinfo') or j.machine_arch() == 'arm':
            check(v.startswith('AFFECTED') or v == 'NOT_AFFECTED', 'verdict uses this host CPU: %s' % v)
        else:
            check(v == 'AFFECTED_CPU_UNKNOWN', 'CPU not read under --no-exec -> AFFECTED_CPU_UNKNOWN (%s)' % v)
        check(res[0]['exposure'] == 'internet', 'exposure carried')
    return root


def j7(tmp, repo):
    print('J7 exit codes and --json')
    out = os.path.join(tmp, 'r.json')
    check(j.main(['repo', repo, '--json', out]) == 2, 'repo with an affected build -> exit 2')
    data = json.load(open(out, encoding='utf-8'))
    check(data['cve'] == 'CVE-2026-114938' and data['counts'].get('FIXED') == 1, 'json written with counts')
    only_unknown = os.path.join(tmp, 'u')
    write(only_unknown, 'Dockerfile', 'FROM openjdk:17-jdk-slim\n')
    check(j.main(['repo', only_unknown]) == 1, 'UNKNOWN only -> exit 1')
    clean = os.path.join(tmp, 'c')
    write(clean, 'Dockerfile', 'FROM eclipse-temurin:11.0.25_9-jre\n')
    check(j.main(['repo', clean]) == 0, 'Java 11 only -> exit 0')
    saved = os.path.join(tmp, 'v.txt')
    write(tmp, 'v.txt', REAL_JAVA18 + FLAGS_REAL)
    write(tmp, 'cpu.txt', NOVBMI_CPU)
    rc = j.main(['java-version-text', saved, '--cpuinfo', os.path.join(tmp, 'cpu.txt'), '--json', out])
    v = json.load(open(out, encoding='utf-8'))['results'][0]['verdict']
    check(rc == 2 and v in ('AFFECTED_MITIGATED', 'AFFECTED_CPU_NOT_VULNERABLE'),
          'saved java 18 output -> affected class, exit 2 (%s)' % v)


def main():
    tmp = tempfile.mkdtemp(prefix='j4s-')
    try:
        j1(); j2(); j3(); j4()
        repo = j5(tmp)
        j6(tmp)
        j7(tmp, repo)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('%d FAILED' % len(FAILS) if FAILS else 'ALL PASS')
    return 1 if FAILS else 0


if __name__ == '__main__':
    sys.exit(main())
