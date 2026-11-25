#!/usr/bin/env python3
"""Java4Shell (CVE-2026-114938) exposure check -- read-only, standard library only.

WHAT THE VULNERABILITY NEEDS (all three, per the OpenJDK, Oracle, Tenable, Cycode and ThreatDefence
advisories of 2026-11-17/18 -- sources at the bottom of this docstring)

    1  an affected HotSpot runtime: Java 17.0.6 and later below 17.0.21.1, 21 below 21.0.13.1,
       25 below 25.0.5.1, 27 below 27.0.1.1; the end-of-life lines 18-20, 22-24 and 26 have the
       code and get no fix. Standard Java 8 and 11, and 17.0.0-17.0.5, are not affected.
    2  an x86-64 CPU with AVX-512 VBMI (flags avx512f, avx512bw, avx512vbmi, bmi2 all present).
       ARM (Graviton, Ampere, Apple silicon) is not affected.
    3  the Base64 intrinsic active in the running JVM (UseBASE64Intrinsics true, UseAVX 3). The
       interim workarounds -XX:-UseBASE64Intrinsics or -XX:UseAVX=2 switch it off.

    Reachability: attacker-controlled data reaching java.util.Base64's basic or URL decoder --
    Basic auth headers, bearer tokens / JWTs, uploads. Products reported exploitable before login
    in default configurations: Keycloak, Jira, Confluence, Artifactory, Jenkins, PingFederate.

WHAT THIS CHECK DOES -- and does not do

    It READS: files on disk (a JDK's `release` file, Dockerfiles, workflow and IaC files,
    /proc/cpuinfo) and runs `java -version` style probes of runtimes it finds (`--no-exec` turns
    the probes off). It never changes a runtime, a flag, a service or a file outside --out. It
    sends nothing anywhere.

    Every runtime gets ONE verdict, and "could not establish" is never reported as "not
    affected":

      AFFECTED                 affected version, vulnerable CPU confirmed, no workaround seen
      AFFECTED_CPU_UNKNOWN     affected version; the CPU could not be read (treat as AFFECTED
                               until shown otherwise -- an image's deployment host is unknown)
      AFFECTED_MITIGATED       affected version, but the running JVM shows the workaround flag.
                               Still patch: the flag goes away on the next restart without it.
      AFFECTED_CPU_NOT_VULNERABLE  affected version on a CPU without AVX-512 VBMI. Patch anyway:
                               a VM resize or host move to a newer CPU makes it exploitable.
      FIXED                    at or above the fixed build for its line (confirm against the
                               vendor's own advisory -- distributions number their own builds)
      NOT_AFFECTED             a line or CPU the advisories rule out (with the reason)
      UNKNOWN                  the version, line or VM could not be established (with the cause)

    Exit code: 2 if anything is AFFECTED*, else 1 if anything is UNKNOWN, else 0.

USE

    python3 java4shell_check.py host [--exposure internet|internal|unknown] [--no-exec]
    python3 java4shell_check.py image IMAGE_REF [IMAGE_REF ...] [--exposure ...]
    python3 java4shell_check.py repo PATH [PATH ...]
    python3 java4shell_check.py java-version-text FILE   (classify saved `java -version` output)
    add --json OUT.json to any of them for the machine-readable result.

SOURCES (read 2026-11-19)
    https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability
    https://cycode.com/blog/java4shell-cve-2026-114938/
    https://threatdefence.com/article/java4shell-cve-2026-114938-openjdk-rce-patching-hunting
    https://www.sophos.com/en-us/security-advisories/sophos-sa-20261118-java4shell
    https://calif.io/java4shell
"""
import argparse
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys

CVE = 'CVE-2026-114938'
DATA_AS_OF = '2026-11-19'

# Fixed build per supported line (OpenJDK / Oracle numbering; Corretto, Zulu, Temurin and Debian
# use the same first four numbers: 21.0.13.1+2, 21.0.13.1.2, ...). The first affected build of the
# line is the lower bound.
FIXED = {17: (17, 0, 21, 1), 21: (21, 0, 13, 1), 25: (25, 0, 5, 1), 27: (27, 0, 1, 1)}
FIRST_AFFECTED = {17: (17, 0, 6)}
EOL_AFFECTED = {18, 19, 20, 22, 23, 24, 26}
NOT_AFFECTED_LINES = {8, 11}

CPU_FLAGS = ('avx512f', 'avx512bw', 'avx512vbmi', 'bmi2')

VERDICTS = ('AFFECTED', 'AFFECTED_CPU_UNKNOWN', 'AFFECTED_MITIGATED', 'AFFECTED_CPU_NOT_VULNERABLE',
            'FIXED', 'NOT_AFFECTED', 'UNKNOWN')

NEXT_STEP = {
    'AFFECTED': 'Patch to the fixed build for this line and restart the JVM. Until then set '
                'JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics and restart.',
    'AFFECTED_CPU_UNKNOWN': 'Treat as AFFECTED: patch, or apply -XX:-UseBASE64Intrinsics, and '
                            'confirm the CPU of the host it actually runs on.',
    'AFFECTED_MITIGATED': 'Workaround is active in this JVM. Patch, then remove the flag; make sure '
                          'the flag is in the service definition so a restart keeps it.',
    'AFFECTED_CPU_NOT_VULNERABLE': 'Not exploitable on this CPU today. Patch in the normal cycle; '
                                   'a move to a newer x86-64 CPU makes it exploitable.',
    'FIXED': 'Confirm the build against the vendor advisory and that the running JVM was restarted.',
    'NOT_AFFECTED': 'No action for this CVE.',
    'UNKNOWN': 'Establish the runtime by hand (see the cause), then re-run the check.',
}


# ---------------------------------------------------------------------------------------- version

def parse_version(text):
    """`17.0.21.1.2`, `21.0.13.1+2`, `17.0.21+9`, `1.8.0_402`, `11.0.25`, `25.0.5.0.2-LTS`, `21`
    -> (line, tuple of numbers) or (None, None). Java 8's `1.8.0_402` is line 8."""
    if not text:
        return None, None
    t = str(text).strip().strip('"')
    m = re.match(r'^1\.(\d+)\.(\d+)(?:_(\d+))?', t)
    if m:
        line = int(m.group(1))
        return line, (line, 0, int(m.group(3) or 0))
    m = re.match(r'^(\d+)(?:u(\d+))?((?:\.\d+)*)', t)
    if not m:
        return None, None
    line = int(m.group(1))
    if m.group(2):  # 8u511
        return line, (line, 0, int(m.group(2)))
    rest = [int(x) for x in m.group(3).split('.') if x != ''] if m.group(3) else []
    return line, tuple([line] + rest)


def _pad(v, n=4):
    return tuple(list(v) + [0] * (n - len(v)))[:max(n, len(v))]


def classify_version(version_text, vm_name='', vendor=''):
    """-> (state, reason). state: AFFECTED_VERSION, FIXED, NOT_AFFECTED, UNKNOWN."""
    vm = (vm_name or '').lower()
    if 'openj9' in vm or 'j9' == vm.strip():
        return 'UNKNOWN', ('Eclipse OpenJ9 VM: the advisories name the HotSpot intrinsic; confirm '
                           'with the vendor (IBM Semeru) before calling it unaffected')
    who = ('%s %s' % (vm_name or '', vendor or '')).lower()
    if 'zing' in who or 'platform prime' in who or re.search(r'\bprime\b', who):
        return 'UNKNOWN', ('Azul Platform Prime (Zing VM): its own JVM and build numbering, and Azul lists '
                           'affected Prime builds on lines (8, 11) that are safe in standard OpenJDK -- '
                           'confirm against the Azul advisory')
    perf = '-perf' in (version_text or '').lower() or 'performance pack' in (vendor or '').lower()
    line, v = parse_version(version_text)
    if line is None:
        return 'UNKNOWN', 'version could not be read: %r' % (version_text,)
    if line == 8 and perf:
        return 'UNKNOWN', ('Java 8 Enterprise Performance Pack is affected up to 8u511b33-perf; '
                           'fixed in 8u513-perf -- confirm the exact build by hand')
    if line in NOT_AFFECTED_LINES:
        return 'NOT_AFFECTED', 'Java %d (standard builds) is not affected' % line
    if line in EOL_AFFECTED:
        return 'AFFECTED_VERSION', ('Java %d is end-of-life, shares the vulnerable code and gets no '
                                    'fix: move to a fixed 21, 25 or 27' % line)
    if line in FIXED:
        if len(v) == 1:
            return 'UNKNOWN', ('only the line (%d) is known, not the build -- a floating tag or '
                               'setting; resolve the exact build' % line)
        lo = FIRST_AFFECTED.get(line)
        if lo and _pad(v) < _pad(lo):
            return 'NOT_AFFECTED', '%s is below the first affected build %s' % (
                version_text, '.'.join(map(str, lo)))
        if _pad(v) >= _pad(FIXED[line]):
            return 'FIXED', 'at or above the fixed build %s' % '.'.join(map(str, FIXED[line]))
        return 'AFFECTED_VERSION', 'below the fixed build %s' % '.'.join(map(str, FIXED[line]))
    return 'UNKNOWN', ('Java %d is not covered by the advisories (%s); treat any line below 17 '
                       'other than 8/11 as unsupported and upgrade' % (line, DATA_AS_OF))


# -------------------------------------------------------------------------------------------- cpu

def cpu_from_cpuinfo(text):
    """/proc/cpuinfo text -> ('VULNERABLE'|'NOT_VULNERABLE'|'UNKNOWN', reason)."""
    if not text:
        return 'UNKNOWN', 'no /proc/cpuinfo'
    if re.search(r'^(CPU implementer|Features)\s*:', text, re.M) and not re.search(r'^flags\s*:', text, re.M):
        return 'NOT_VULNERABLE', 'ARM CPU (not affected)'
    m = re.search(r'^flags\s*:(.*)$', text, re.M)
    if not m:
        return 'UNKNOWN', 'no flags line in /proc/cpuinfo'
    flags = set(m.group(1).split())
    missing = [f for f in CPU_FLAGS if f not in flags]
    if missing:
        return 'NOT_VULNERABLE', 'CPU lacks %s' % ', '.join(missing)
    return 'VULNERABLE', 'CPU has %s' % ', '.join(CPU_FLAGS)


def cpu_from_jvm_log(text):
    """Output of `java -Xlog:os+cpu -version` -> state, reason. HotSpot names the feature
    `avx512_vbmi` in its CPU features line; absence of the CPU line is UNKNOWN, not negative."""
    if not text:
        return 'UNKNOWN', 'no JVM CPU log'
    low = text.lower()
    if 'aarch64' in low or 'arm64' in low:
        return 'NOT_VULNERABLE', 'ARM CPU (from the JVM)'
    if not re.search(r'cpu:\s*total', low):
        return 'UNKNOWN', 'the JVM did not print its CPU features line'
    if 'avx512_vbmi' in low and 'avx512bw' in low and 'bmi2' in low:
        return 'VULNERABLE', 'JVM reports avx512_vbmi, avx512bw, bmi2'
    return 'NOT_VULNERABLE', 'JVM CPU features line has no avx512_vbmi'


def machine_arch():
    m = platform.machine().lower()
    if m in ('aarch64', 'arm64') or m.startswith('arm'):
        return 'arm'
    if m in ('x86_64', 'amd64', 'x64'):
        return 'x86_64'
    return m or 'unknown'


# ------------------------------------------------------------------------------- java -version etc

def parse_java_version_output(text):
    """`java -version` (stderr) -> dict(version, vm, vendor). Accepts the `release` file too."""
    out = {'version': None, 'vm': '', 'vendor': ''}
    if not text:
        return out
    m = re.search(r'^JAVA_VERSION="?([^"\n]+)"?', text, re.M)
    if m:  # a JDK `release` file
        out['version'] = m.group(1).strip()
        mr = re.search(r'^JAVA_RUNTIME_VERSION="?([^"\n]+)"?', text, re.M)
        if mr:
            out['version'] = mr.group(1).strip()
        mi = re.search(r'^IMPLEMENTOR="?([^"\n]+)"?', text, re.M)
        out['vendor'] = mi.group(1).strip() if mi else ''
        mv = re.search(r'^JVM_VARIANT="?([^"\n]+)"?', text, re.M)
        out['vm'] = mv.group(1).strip() if mv else ''
        if re.search(r'openj9', text, re.I):
            out['vm'] = 'OpenJ9'
        return out
    # the runtime line carries the full build: "OpenJDK Runtime Environment Corretto-21.0.13.1.2 (build 21.0.13.1+2-LTS)"
    mb = re.search(r'Runtime Environment[^\n]*\(build ([^)\s]+)', text)
    mq = re.search(r'version "([^"]+)"', text)
    out['version'] = (mb.group(1) if mb else None) or (mq.group(1) if mq else None)
    if mb and mq:  # prefer the longer, more exact one
        out['version'] = max([mb.group(1), mq.group(1)], key=lambda s: len(re.findall(r'\d+', s)))
    mvm = re.search(r'^(.*(?:VM|Server VM|OpenJ9)[^\n]*)$', text, re.M)
    out['vm'] = mvm.group(1).strip() if mvm else ''
    mre = re.search(r'Runtime Environment\s+([^\n(]*)', text)
    out['vendor'] = mre.group(1).strip() if mre else ''
    return out


def parse_flags_final(text):
    """`java -XX:+PrintFlagsFinal -version` or `jcmd PID VM.flags -all` -> dict of the two flags."""
    flags = {}
    for name in ('UseBASE64Intrinsics', 'UseAVX'):
        m = re.search(r'\b%s\s+(?::?=)\s*(\S+)' % name, text or '')
        if m:
            flags[name] = m.group(1)
        else:  # jcmd VM.flags short form: -XX:-UseBASE64Intrinsics / -XX:UseAVX=2
            m2 = re.search(r'-XX:([+-])%s\b' % name, text or '')
            m3 = re.search(r'-XX:%s=(\d+)' % name, text or '')
            if m2:
                flags[name] = 'true' if m2.group(1) == '+' else 'false'
            elif m3:
                flags[name] = m3.group(1)
    return flags


def mitigation_from_flags(flags, env_opts=''):
    """-> (True|False|None, reason). None = could not tell (never reads as 'not mitigated')."""
    b64 = str(flags.get('UseBASE64Intrinsics', '')).lower()
    avx = str(flags.get('UseAVX', ''))
    if b64 == 'false':
        return True, 'UseBASE64Intrinsics is false in this JVM'
    if avx.isdigit() and int(avx) < 3:
        return True, 'UseAVX=%s in this JVM' % avx
    if b64 == 'true' and avx == '3':
        return False, 'UseBASE64Intrinsics true and UseAVX 3'
    if b64 == 'true' and avx.isdigit():
        return False, 'UseBASE64Intrinsics true, UseAVX %s' % avx
    if env_opts and re.search(r'-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2]\b', env_opts):
        return None, 'JAVA_TOOL_OPTIONS sets a workaround, but the running JVM was not read'
    return None, 'JVM flags not read'


# ------------------------------------------------------------------------------------- verdict

def verdict(version_text, vm='', vendor='', cpu=('UNKNOWN', ''), mitigated=(None, '')):
    vstate, vreason = classify_version(version_text, vm, vendor)
    cstate, creason = cpu
    mstate, mreason = mitigated
    if vstate == 'FIXED':
        return 'FIXED', vreason
    if vstate == 'NOT_AFFECTED':
        return 'NOT_AFFECTED', vreason
    if vstate == 'UNKNOWN':
        if cstate == 'NOT_VULNERABLE' and 'ARM' in creason:
            return 'NOT_AFFECTED', creason + '; runtime: ' + vreason
        return 'UNKNOWN', vreason
    # affected version
    if cstate == 'NOT_VULNERABLE' and 'ARM' in creason:
        return 'NOT_AFFECTED', '%s, but %s' % (vreason, creason)
    if mstate is True:
        return 'AFFECTED_MITIGATED', '%s; %s' % (vreason, mreason)
    if cstate == 'NOT_VULNERABLE':
        return 'AFFECTED_CPU_NOT_VULNERABLE', '%s; %s' % (vreason, creason)
    if cstate == 'VULNERABLE':
        return 'AFFECTED', '%s; %s; %s' % (vreason, creason, mreason)
    return 'AFFECTED_CPU_UNKNOWN', '%s; CPU: %s' % (vreason, creason or 'not read')


def record(kind, where, version_text, vm='', vendor='', cpu=('UNKNOWN', ''), mitigated=(None, ''),
           exposure='unknown', extra=None):
    v, reason = verdict(version_text, vm, vendor, cpu, mitigated)
    r = {'cve': CVE, 'kind': kind, 'where': where, 'version': version_text, 'vm': vm,
         'vendor': vendor, 'cpu': cpu[0], 'mitigation': mitigated[0], 'exposure': exposure,
         'verdict': v, 'reason': reason, 'next_step': NEXT_STEP[v]}
    if extra:
        r.update(extra)
    return r


# ------------------------------------------------------------------------------------------- host

def _run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or '') + (p.stderr or '')
    except (OSError, subprocess.SubprocessError) as e:
        return 'probe failed: %s' % e


def _java_exe(home):
    for n in ('bin/java', 'bin/java.exe', 'jre/bin/java', 'jre/bin/java.exe'):
        p = os.path.join(home, n)
        if os.path.isfile(p):
            return p
    return None


def find_java_homes(extra_roots=()):
    """Every directory that looks like a JDK/JRE home: a `release` file next to bin/java, from
    JAVA_HOME, PATH, the usual install roots, and any --root. Bundled runtimes inside products
    (Jira, Jenkins, Keycloak...) are found when their install root is under a searched root."""
    homes = {}
    roots = list(extra_roots)
    if os.environ.get('JAVA_HOME'):
        roots.append(os.environ['JAVA_HOME'])
    for exe in ('java', 'java.exe'):
        w = shutil.which(exe)
        if w:
            real = os.path.realpath(w)
            homes.setdefault(os.path.dirname(os.path.dirname(real)), real)
    if os.name == 'nt':
        for env in ('ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432'):
            if os.environ.get(env):
                roots.append(os.environ[env])
    else:
        roots += ['/usr/lib/jvm', '/usr/java', '/opt', '/usr/local', '/Library/Java/JavaVirtualMachines',
                  '/srv', '/var/lib']
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth > 6:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in ('node_modules', '.git', 'proc', 'sys')]
            if 'release' in filenames and _java_exe(dirpath):
                homes[os.path.realpath(dirpath)] = _java_exe(dirpath)
                dirnames[:] = []
    return sorted(homes.items())


def running_jvms():
    """-> list of (pid, exe path or ''). Linux: /proc; Windows: CIM via PowerShell; else []."""
    out = []
    if os.path.isdir('/proc'):
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                exe = os.readlink('/proc/%s/exe' % pid)
            except OSError:
                continue
            if os.path.basename(exe) == 'java':
                out.append((int(pid), exe))
    elif os.name == 'nt':
        txt = _run(['powershell', '-NoProfile', '-Command',
                    "Get-CimInstance Win32_Process -Filter \"Name='java.exe' or Name='javaw.exe'\" | "
                    "ForEach-Object { \"$($_.ProcessId)`t$($_.ExecutablePath)\" }"])
        for line in txt.splitlines():
            parts = line.strip().split('\t')
            if len(parts) == 2 and parts[0].isdigit():
                out.append((int(parts[0]), parts[1]))
    return out


def host_cpu(probe_exe=None, no_exec=False):
    if machine_arch() == 'arm':
        return 'NOT_VULNERABLE', 'ARM CPU (not affected)'
    if os.path.isfile('/proc/cpuinfo'):
        try:
            return cpu_from_cpuinfo(open('/proc/cpuinfo', encoding='utf-8', errors='replace').read())
        except OSError:
            pass
    if probe_exe and not no_exec:
        return cpu_from_jvm_log(_run([probe_exe, '-Xlog:os+cpu=info', '-version']))
    return 'UNKNOWN', 'CPU flags not readable on this OS without running a JVM'


def check_host(roots=(), exposure='unknown', no_exec=False):
    results = []
    homes = find_java_homes(roots)
    jcmd = shutil.which('jcmd')
    cpu = host_cpu(homes[0][1] if homes else None, no_exec)
    env_opts = os.environ.get('JAVA_TOOL_OPTIONS', '') + ' ' + os.environ.get('_JAVA_OPTIONS', '')
    for home, exe in homes:
        info = {'version': None, 'vm': '', 'vendor': ''}
        relf = os.path.join(home, 'release')
        if os.path.isfile(relf):  # a PATH shim (Oracle's javapath) has none: the probe must say
            info = parse_java_version_output(open(relf, encoding='utf-8', errors='replace').read())
        flags = {}
        if exe and not no_exec:
            jv = parse_java_version_output(_run([exe, '-version']))
            if jv['version']:
                info.update({k: v for k, v in jv.items() if v})
            flags = parse_flags_final(_run([exe, '-XX:+PrintFlagsFinal', '-version']))
        # a home on disk is not a running JVM: its defaults say whether the intrinsic WOULD be on
        mit = mitigation_from_flags({}, env_opts)
        results.append(record('installed-runtime', home, info['version'], info['vm'], info['vendor'],
                              cpu, mit, exposure,
                              {'default_flags': flags,
                               'note': 'installed on disk; see running-jvm rows for live processes'}))
    for pid, exe in running_jvms():
        home = os.path.dirname(os.path.dirname(exe)) if exe else ''
        info = {'version': None, 'vm': '', 'vendor': ''}
        if home and os.path.isfile(os.path.join(home, 'release')):
            info = parse_java_version_output(open(os.path.join(home, 'release'), encoding='utf-8',
                                                  errors='replace').read())
        flags, mit = {}, (None, 'jcmd not available or not run')
        if jcmd and not no_exec:
            vtxt = _run([jcmd, str(pid), 'VM.version'])
            got = re.search(r'JDK\s+([\d][^\s]*)', vtxt)
            if got:
                info['version'] = info['version'] or got.group(1)
            flags = parse_flags_final(_run([jcmd, str(pid), 'VM.flags', '-all']))
            mit = mitigation_from_flags(flags, '')
        results.append(record('running-jvm', 'pid %d %s' % (pid, exe), info['version'], info['vm'],
                              info['vendor'], cpu, mit, exposure, {'flags': flags}))
    if not results:
        results.append({'cve': CVE, 'kind': 'host', 'where': platform.node(), 'verdict': 'UNKNOWN',
                        'reason': 'no Java runtime found under the searched roots -- a runtime '
                                  'elsewhere (a product install dir) is not ruled out; add --root',
                        'exposure': exposure, 'next_step': NEXT_STEP['UNKNOWN']})
    return results


# ------------------------------------------------------------------------------------------ image

def check_image(ref, exposure='unknown', engine='docker'):
    """Runs the image's own java with networking off, to read its build and default flags. The
    CPU of the DEPLOYMENT host is not knowable from here, so the best verdict is
    AFFECTED_CPU_UNKNOWN for an affected build."""
    if not shutil.which(engine):
        return [record('image', ref, None, exposure=exposure,
                       extra={'reason_detail': '%s not on PATH' % engine})]
    base = [engine, 'run', '--rm', '--network', 'none', '--entrypoint', 'java', ref]
    txt = _run(base + ['-version'], timeout=180)
    info = parse_java_version_output(txt)
    if not info['version']:
        rel = _run([engine, 'run', '--rm', '--network', 'none', '--entrypoint', 'sh', ref, '-c',
                    'cat "$JAVA_HOME/release" 2>/dev/null || cat /opt/java/openjdk/release 2>/dev/null'],
                   timeout=180)
        info = parse_java_version_output(rel)
    flags = parse_flags_final(_run(base + ['-XX:+PrintFlagsFinal', '-version'], timeout=180))
    return [record('image', ref, info['version'], info['vm'], info['vendor'],
                   ('UNKNOWN', 'deployment host CPU not known from the image'),
                   (None, 'image defaults only; the runtime flags come from the deployment'),
                   exposure, {'default_flags': flags,
                              'probe_output': '' if info['version'] else txt.strip()[:300]})]


# ------------------------------------------------------------------------------------------- repo

JAVA_IMAGE = re.compile(
    r'^(?:[\w.-]+(?::\d+)?/)*'
    r'(eclipse-temurin|openjdk|amazoncorretto|zulu-openjdk[\w-]*|sapmachine|liberica[\w-]*|'
    r'ibm-semeru-runtimes|ibmjava|graalvm[\w-]*|jdk|jre|openjdk-\d+[\w-]*|ubi\d*-openjdk-\d+[\w-]*|'
    r'tomcat|jetty|keycloak|jenkins|jira[\w-]*|confluence[\w-]*|artifactory[\w-]*|maven|gradle|'
    r'jboss[\w-]*|wildfly|elasticsearch|solr|kafka)'
    r'(?::([^\s@]+))?(?:@(sha256:[0-9a-f]{64}))?$', re.I)


def _tag_version(image, tag):
    """A tag's exact Java build when it carries one (`21.0.13_11-jre`, `17.0.21.1`, `21.0.13.1-al2`),
    else the line only (`21-jre`, `17`), else None. Product images (tomcat, jenkins...) carry the
    PRODUCT version in the tag, so only `-jdkNN`/`-jreNN` suffixes give a line."""
    name = image.lower()
    named = re.search(r'openjdk-?(\d+)', name.split('/')[-1])
    if named:  # ubi9/openjdk-21:1.20 -- the tag is the image's own version, the name has the line
        return named.group(1)
    if not tag:
        return None
    if re.match(r'^(tomcat|jetty|keycloak|jenkins|jira|confluence|artifactory|maven|gradle|jboss|'
                r'wildfly|elasticsearch|solr|kafka)', name.split('/')[-1]):
        m = re.search(r'(?:jdk|jre|temurin-|corretto-)(\d+)', tag, re.I)
        return m.group(1) if m else None
    m = re.match(r'^(\d+(?:\.\d+){0,4})(?:[_+](\d+))?', tag)
    if not m:
        m2 = re.search(r'(?:jdk|jre|java)-?(\d+)', tag, re.I)
        return m2.group(1) if m2 else None
    return m.group(1)


def _repo_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('.git', 'node_modules', 'target', 'build',
                                                         '.gradle', 'vendor')]
        for f in filenames:
            yield os.path.join(dirpath, f)


def check_repo(root, exposure='unknown'):
    """Static: where the repository DECLARES a Java runtime it builds or deploys with. A declared
    line without a build is UNKNOWN (resolve the built image), never 'not affected'."""
    results = []
    rel = lambda p: os.path.relpath(p, root).replace('\\', '/')
    for path in _repo_files(root):
        base = os.path.basename(path)
        low = base.lower()
        try:
            if os.path.getsize(path) > 2_000_000:
                continue
            text = open(path, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        hits = []
        if low == 'dockerfile' or low.startswith('dockerfile.') or low.endswith('.dockerfile') \
                or low.startswith('containerfile'):
            froms = [(n, line) for n, line in enumerate(text.splitlines(), 1)
                     if re.match(r'^\s*FROM\s', line, re.I)]
            javaish = re.search(r'java|jdk|jre|\.jar\b', text, re.I)
            for i, (n, line) in enumerate(froms):
                m = re.match(r'^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)', line, re.I)
                if not m:
                    continue
                ref = m.group(1)
                stage = 'final stage (ships)' if i == len(froms) - 1 else 'build stage (may not ship)'
                if '$' in ref and javaish:
                    hits.append((n, 'dockerfile-base, %s' % stage, ref, None, False))
                    continue
                mi = JAVA_IMAGE.match(ref)
                if mi:
                    image = re.sub(r'[:@].*$', '', ref.split('/')[-1])
                    hits.append((n, 'dockerfile-base, %s' % stage, ref, _tag_version(image, mi.group(2)),
                                 '@sha256:' in ref))
        elif path.replace('\\', '/').find('.github/workflows/') >= 0 and low.endswith(('.yml', '.yaml')):
            if 'setup-java' in text:
                for n, line in enumerate(text.splitlines(), 1):
                    m = re.search(r'java-version:\s*[\'"]?([\w.+-]+)', line)
                    if m:
                        hits.append((n, 'setup-java (build/test runtime)', m.group(1), m.group(1), False))
        elif low in ('.java-version', '.sdkmanrc', '.tool-versions', 'system.properties'):
            for n, line in enumerate(text.splitlines(), 1):
                m = re.search(r'(?:^java\s*[= ]\s*|^java\.runtime\.version\s*=\s*|^)(\d[\w.+-]*)', line.strip())
                if m and (low != '.tool-versions' or line.strip().startswith('java')):
                    v = re.search(r'(\d+(?:\.\d+)*)', m.group(1))
                    hits.append((n, low, line.strip(), v.group(1) if v else None, False))
        elif low.endswith(('.bicep', '.tf', '.json', '.yml', '.yaml')):
            for n, line in enumerate(text.splitlines(), 1):
                m = re.search(r'(?:linuxFxVersion|linux_fx_version|windowsFxVersion)\W+[\'"]?'
                              r'(?:JAVA|TOMCAT|JBOSSEAP)\|([^\'"\s,]+)', line, re.I) \
                    or re.search(r'(?:javaVersion|java_version)\W+[\'"]?(\d[\w.]*)', line)
                if m:
                    val = m.group(1)
                    lm = re.search(r'java(\d+)', val, re.I) or re.match(r'(\d+(?:\.\d+)*)', val)
                    hits.append((n, 'azure app service runtime (platform-managed JDK)', val,
                                 lm.group(1) if lm else None, False))
        for n, kind, raw, ver, pinned in hits:
            if ver is None:
                r = {'cve': CVE, 'kind': 'repo:' + kind, 'where': '%s:%d' % (rel(path), n),
                     'declared': raw, 'version': None, 'verdict': 'UNKNOWN',
                     'reason': 'Java runtime declared, build not stated in the reference -- '
                               'inspect the built image (image mode)', 'exposure': exposure,
                     'next_step': NEXT_STEP['UNKNOWN']}
            else:
                r = record('repo:' + kind, '%s:%d' % (rel(path), n), ver,
                           cpu=('UNKNOWN', 'deployment host CPU not known from the repository'),
                           mitigated=(None, 'static declaration'), exposure=exposure,
                           extra={'declared': raw, 'digest_pinned': pinned})
                if 'platform-managed' in kind and r['verdict'] in ('UNKNOWN',):
                    r['reason'] += '; App Service patches its own JDK -- check the platform build'
            results.append(r)
    return results


# ------------------------------------------------------------------------------------------- main

def summarise(results):
    order = {v: i for i, v in enumerate(VERDICTS)}
    exp_rank = {'internet': 0, 'unknown': 1, 'internal': 2}
    results.sort(key=lambda r: (order.get(r['verdict'], 9), exp_rank.get(r.get('exposure'), 1),
                                r.get('where', '')))
    counts = {}
    for r in results:
        counts[r['verdict']] = counts.get(r['verdict'], 0) + 1
    return counts


def main(argv=None):
    ap = argparse.ArgumentParser(description='Java4Shell (%s) read-only exposure check' % CVE)
    sub = ap.add_subparsers(dest='mode', required=True)
    for name in ('host', 'image', 'repo', 'java-version-text'):
        p = sub.add_parser(name)
        p.add_argument('--exposure', choices=('internet', 'internal', 'unknown'), default='unknown')
        p.add_argument('--json', help='write the results here')
        if name == 'host':
            p.add_argument('--root', action='append', default=[],
                           help='also search here (e.g. a product install dir)')
            p.add_argument('--no-exec', action='store_true', help='read files only; run no java')
        if name == 'image':
            p.add_argument('refs', nargs='+')
            p.add_argument('--engine', default='docker')
        if name == 'repo':
            p.add_argument('paths', nargs='+')
        if name == 'java-version-text':
            p.add_argument('files', nargs='+')
            p.add_argument('--cpuinfo', help='a saved /proc/cpuinfo from the same host')
    a = ap.parse_args(argv)
    if a.mode == 'host':
        results = check_host(a.root, a.exposure, a.no_exec)
    elif a.mode == 'image':
        results = [r for ref in a.refs for r in check_image(ref, a.exposure, a.engine)]
    elif a.mode == 'repo':
        results = [r for p in a.paths for r in check_repo(p, a.exposure)]
    else:
        cpu = ('UNKNOWN', 'no --cpuinfo given')
        if a.cpuinfo:
            cpu = cpu_from_cpuinfo(open(a.cpuinfo, encoding='utf-8', errors='replace').read())
        results = []
        for f in a.files:
            txt = open(f, encoding='utf-8', errors='replace').read()
            info = parse_java_version_output(txt)
            results.append(record('saved-output', f, info['version'], info['vm'], info['vendor'], cpu,
                                  mitigation_from_flags(parse_flags_final(txt)), a.exposure))
    counts = summarise(results)
    print('%s exposure check (%s mode, advisory data as of %s)' % (CVE, a.mode, DATA_AS_OF))
    for r in results:
        print('  %-28s %-9s %s  [%s]' % (r['verdict'], r.get('exposure', ''), r.get('where', ''),
                                         r.get('version') or r.get('declared') or '-'))
        print('      %s' % r['reason'])
    print('TOTALS ' + ', '.join('%s=%d' % (k, counts[k]) for k in VERDICTS if k in counts))
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as fh:
            json.dump({'cve': CVE, 'data_as_of': DATA_AS_OF, 'mode': a.mode, 'counts': counts,
                       'results': results}, fh, indent=2)
    if any(r['verdict'].startswith('AFFECTED') for r in results):
        return 2
    if any(r['verdict'] == 'UNKNOWN' for r in results):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
