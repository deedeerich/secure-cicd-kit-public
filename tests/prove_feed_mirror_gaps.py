#!/usr/bin/env python3
"""The feed-mirror gaps closed (KDEC-032, coordinator 2026-10-27): the tag-pinned scanner images, Trivy's
misconfiguration checks bundle and the OSV database are mirrored too, and each refuses by name and FAILS
CLOSED exactly as the NVD datafeed, KEV and the Trivy database do (tests/prove_feed_mirror.py).

WHY THIS EXISTS

    The first cut of the mirrors left three public pulls behind it and said so: gosec and gitleaks were
    pulled BY TAG (a mirror of a moving pointer is not a mirror), `trivy config` fetched its checks bundle
    from Trivy's public registry, and the malicious-package scan asked the public OSV API. A private
    runner that reaches only the mirror would have lost all three -- and two of them would not have said
    so: Trivy with no checks bundle and `--skip-check-update` FALLS BACK TO ITS EMBEDDED CHECKS (measured,
    Trivy 0.71.2: "Falling back to embedded checks"), which reads as a current scan.

WHAT IT PROVES (scripts/feed_mirror.py, scripts/feed_mirror_step.sh, the composites and workflows as
shipped) -- file:// fixtures; the real Trivy and osv-scanner when they are on PATH

    G1  IMAGES BY DIGEST: gosec and gitleaks are pinned `name:tag@sha256:<64 hex>` at every code site
        (the flagship's sast-go, the secret-scan composite, validate-scanners), one digest per image; the
        pin readers still see the tag (check_pinned_artifacts resolves it, prove_validate_scanners
        compares the probe), and each is redirectable to vars.KIT_SCANNER_IMAGE_REGISTRY by the SAME
        digest; the refresh's default image list carries all three digests
    G2  image-target maps a source to its mirror path (tag dropped, digest kept, docker.io/ stripped) and
        REFUSES a tag-only source
    G3  THE CHECKS BUNDLE: a current mirror is unpacked to <cache>/policy with the update off; a refused
        one empties it and points TRIVY_CONFIG_CHECK at a path that does not exist, so `trivy config`
        is FATAL instead of falling back to embedded checks; the refresh packs Trivy's own download
    G4  OSV: a current mirror places each ecosystem's all.zip where osv-scanner 2.6 reads it
        (<dir>/osv-scalibr/<Ecosystem>/all.zip -- measured; the docs' `osv-scanner/` path is not what
        2.6 reads) and switches the scan offline; an ecosystem the scan needs that the manifest lacks is
        MIRROR_INTEGRITY_FAILED; a refused mirror switches the scan offline against an EMPTY directory,
        so osv-scanner exits non-zero and the job's own count step says COLLECTION_FAILED; the refresh
        refuses an all.zip that is not a zip
    G5  WIRING: iac-scan and the NVD path's Dockerfile scan read the checks mirror; malicious-deps reads
        the OSV mirror for the ecosystems discovery found and adds --offline-vulnerabilities only when
        the mirror says so; sast-go, secret-scan, iac-scan and malicious-deps can run on the private
        runner; the refresh publishes trivy-checks and osv and mirrors images through the composite
    G6  REAL TOOLS (when on PATH): Trivy refuses `trivy config` under the refused environment, and
        osv-scanner fails offline with an empty database
    G7  the taxonomy registers every term the gaps use
    G8  REAL TOOLS, THE POSITIVE HALVES (once measured by hand only): the refresh's own fetcher and packer
        -> a published mirror -> consume -> the scanner under the environment consume wrote.
        osv-scanner v2.6.0 (sha256-verified release asset) offline against the placed database finds a
        seeded vulnerable package (KIT-OSV-0001, an advisory only the mirror has); Trivy v0.71.2 `trivy
        config` with the check update off reads the placed checks bundle and finds a seeded
        misconfiguration through a check only that bundle has (KIT-MIRROR-0001 -- an embedded-checks fall
        back cannot produce it). Either tool absent or not the pinned release: UNKNOWN (exit 2), never PASS

EXIT  0 proven   1 a rule failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import prove_feed_mirror as P  # noqa: E402  (fixture helpers: publish, consume, file_url, ago, write)

FM = os.path.join(ROOT, 'scripts', 'feed_mirror.py')
WF = os.path.join(ROOT, '.github', 'workflows')
ACT = os.path.join(ROOT, '.github', 'actions')
GOSEC_D = 'sha256:2cf71ea78210c496c65e3a987576a9c8317b68e20f2960520b3f6f8f9f539be5'
GITLEAKS_D = 'sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46'
SEMGREP_D = 'sha256:32e459968daabe7ab86968184a29109b9564aa00392401156f9788452b42786b'
GOSEC = 'securego/gosec:2.24.6@' + GOSEC_D
GITLEAKS = 'zricethezav/gitleaks:v8.21.2@' + GITLEAKS_D


# osv-scanner v2.6.0, the release the workflow and self-test pin, from its osv-scanner_SHA256SUMS. The positive
# OSV case runs only a binary whose bytes are one of these; anything else is UNKNOWN, never a pass.
OSV_260_SHA256 = {
    'ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108',  # linux_amd64 (self-test installs this)
    '2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4',  # linux_arm64
    '60c5296637e977b28eeda5c7f13573e447659a632922737f94d11fa7e30ad6ca',  # darwin_amd64
    '98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4',  # darwin_arm64
    'e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6',  # windows_amd64.exe
    'ca1379da0e408279ef2c85cde0846a903495738a91c7b065a208048437c1686c',  # windows_arm64.exe
}
# A check that exists only in the mirror's bundle: Trivy's embedded checks cannot produce this id.
MARKER_REGO = b'''# METADATA
# title: Kit feed-mirror marker
# description: Present only in the organisation mirror's checks bundle (tests/prove_feed_mirror_gaps.py G8).
# scope: package
# schemas:
# - input: schema["dockerfile"]
# custom:
#   id: KIT-MIRROR-0001
#   long_id: kit-feed-mirror-marker
#   severity: HIGH
#   recommended_action: none
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.KITMIRROR0001

import rego.v1

deny contains res if {
\tsome instr in input.Stages[_].Commands
\tinstr.Cmd == "user"
\tinstr.Value[0] == "root"
\tres := result.new("USER root", instr)
}
'''


def osv_scanner_260():
    """osv-scanner on PATH -- only when its sha256 is a v2.6.0 release asset."""
    b = shutil.which('osv-scanner')
    if not b or not os.path.isfile(b):
        return None, 'osv-scanner v2.6.0 is not on PATH'
    with io.open(b, 'rb') as fh:
        h = hashlib.sha256(fh.read()).hexdigest()
    if h not in OSV_260_SHA256:
        return None, '%s (sha256 %s) is not a checksum-verified osv-scanner v2.6.0 release asset' % (b, h)
    return b, ''


def trivy_0712():
    """trivy on PATH, only at the v0.71.2 the kit pins (the release the bundle layout was measured against)."""
    b = shutil.which('trivy')
    if not b:
        return None, 'trivy is not on PATH'
    try:
        v = subprocess.run([b, '--version'], capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return None, 'trivy --version failed: %s' % exc
    if not re.search(r'^Version:\s*0\.71\.2\s*$', v, re.M):
        return None, 'trivy is not the pinned v0.71.2: %r' % v.splitlines()[:1]
    return b, ''


def text(*parts):
    return io.open(os.path.join(ROOT, *parts), encoding='utf-8').read()


def run(*args):
    p = subprocess.run([sys.executable, FM] + list(args), capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def tgz(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def zipped(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if not os.path.isfile(FM):
        print('UNKNOWN: scripts/feed_mirror.py is absent')
        return 2
    fails = []
    unknowns = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)
        return cond

    work = tempfile.mkdtemp(prefix='feed-mirror-gaps-')
    try:
        # ---- G1 images pinned by digest at every code site -------------------------------------------
        sec = text('.github', 'workflows', 'reusable-security.yml')
        ss = text('.github', 'actions', 'secret-scan', 'action.yml')
        vs = text('.github', 'workflows', 'validate-scanners.yml')
        check("GOSEC_IMAGE='%s'" % GOSEC in sec, 'G1: sast-go does not pin gosec by digest (%s)' % GOSEC)
        check(GOSEC in vs, 'G1: validate-scanners does not probe gosec at the same digest')
        check(('IMG=' + GITLEAKS) in ss and ('IMG=' + GITLEAKS) in vs,
              'G1: gitleaks is not pinned by digest in the secret-scan composite and validate-scanners')
        code = '\n'.join(io.open(os.path.join(dp, f), encoding='utf-8').read()
                         for d in (WF, ACT) for dp, _, fs in os.walk(d) for f in fs if f.endswith('.yml'))
        for img, d in (('securego/gosec', GOSEC_D), ('zricethezav/gitleaks', GITLEAKS_D)):
            refs = [l for l in code.splitlines() if img in l and not l.lstrip().startswith('#')]
            bare = [l.strip() for l in refs if re.search(re.escape(img) + r':v?[0-9][^@\s\'"]*(?!@)(\s|$|\'|")', l)
                    and '@sha256:' not in l]
            check(not bare, 'G1: %s still pulled by tag only: %r' % (img, bare[:3]))
            digests = set(re.findall(re.escape(img) + r'(?::[^@\s\'"]+)?@(sha256:[0-9a-f]{64})', code))
            check(digests == {d}, 'G1: %s is pinned to %r, not one digest %s' % (img, sorted(digests), d))
        check('W_IMAGE_REGISTRY' in sec and 'vars.KIT_SCANNER_IMAGE_REGISTRY' in sec
              and '/securego/gosec@${GOSEC_IMAGE##*@}' in sec,
              'G1: sast-go cannot pull gosec from the mirror registry by the same digest')
        check('image-registry' in (yaml.safe_load(ss).get('inputs') or {})
              and '/zricethezav/gitleaks@${IMG##*@}' in ss,
              'G1: the secret-scan composite cannot pull gitleaks from the mirror registry by the same digest')
        sdoc = yaml.safe_load(sec)
        for job in ('sast-go', 'secret-scan'):
            check('vars.KIT_FEED_MIRROR_RUNNER' in str((sdoc['jobs'].get(job) or {}).get('runs-on', '')),
                  'G1: %s cannot run on the private runner that reaches the mirror registry' % job)
        ref = yaml.safe_load(text('.github', 'workflows', 'reusable-feed-mirror-refresh.yml'))
        dflt = str(((ref.get(True) or ref.get('on'))['workflow_call']['inputs']['images'] or {}).get('default', ''))
        for d in (SEMGREP_D, GOSEC_D, GITLEAKS_D):
            check(d in dflt, 'G1: the refresh does not mirror %s by default' % d)
        # The pin readers still see the tag: check_pinned_artifacts' image pattern, prove_validate_scanners' read.
        import check_pinned_artifacts as cpa
        seen = set()
        for line in code.splitlines():
            seen.update(cpa.IMAGE.findall(line))
        check(('securego/gosec', '2.24.6') in seen and ('zricethezav/gitleaks', 'v8.21.2') in seen,
              'G1: check_pinned_artifacts no longer sees the gosec / gitleaks tags it resolves')

        # ---- G2 image-target ----------------------------------------------------------------------
        rc, out, err = run('image-target', '--registry', 'reg.example.io', '--source', GOSEC)
        check(rc == 0 and out.split() == ['reg.example.io/securego/gosec', GOSEC_D],
              'G2: image-target mapped %s to %r (rc %d %s)' % (GOSEC, out, rc, err[-200:]))
        rc, out, _ = run('image-target', '--registry', 'reg.example.io', '--source',
                         'docker.io/semgrep/semgrep@' + SEMGREP_D)
        check(rc == 0 and out.split() == ['reg.example.io/semgrep/semgrep', SEMGREP_D],
              'G2: docker.io/ was not stripped: %r' % out)
        rc, out, err = run('image-target', '--registry', 'reg.example.io', '--source', 'securego/gosec:2.24.6')
        check(rc != 0 and 'digest' in (out + err).lower(), 'G2: a tag-only source was not refused (rc %d)' % rc)

        # ---- G3 the checks bundle -------------------------------------------------------------------
        bundle = tgz([('content/policies/x.rego', b'package x'),
                      ('metadata.json', json.dumps({'Digest': 'sha256:' + 'b' * 64, 'DownloadedAt':
                                                    '2026-10-27T04:20:00Z', 'MajorVersion': 2}).encode())])
        croot = os.path.join(work, 'cmirror')
        P.publish(croot, 'trivy-checks', {'checks.tar.gz': bundle}, P.ago(2))
        cache = os.path.join(work, 'tcache')
        P.write(os.path.join(cache, 'policy', 'content', 'stale.rego'), b'OLD')
        rc, o, env, summ, ev, log = P.consume(work, 'trivy-checks', P.file_url(croot), '--trivy-cache-dir', cache,
                                              tag='g3a')
        print('  G3 checks current: state=%s env=%s' % (o.get('mirror_state'), sorted(env)))
        check(o.get('mirror_state') == 'MIRROR_CURRENT'
              and os.path.isfile(os.path.join(cache, 'policy', 'content', 'policies', 'x.rego'))
              and not os.path.exists(os.path.join(cache, 'policy', 'content', 'stale.rego'))
              and env.get('TRIVY_SKIP_CHECK_UPDATE') == 'true' and env.get('TRIVY_CACHE_DIR') == cache
              and 'TRIVY_CONFIG_CHECK' not in env,
              'G3: a current checks mirror was not unpacked over the cache with the update off: %r %r\n%s'
              % (o, env, log[-400:]))
        cstale = os.path.join(work, 'cstale')
        P.publish(cstale, 'trivy-checks', {'checks.tar.gz': bundle}, P.ago(60))
        rc, o, env, summ, ev, log = P.consume(work, 'trivy-checks', P.file_url(cstale), '--trivy-cache-dir', cache,
                                              tag='g3b')
        print('  G3 checks stale: state=%s config_check=%s' % (o.get('mirror_state'), env.get('TRIVY_CONFIG_CHECK')))
        check(o.get('mirror_state') == 'MIRROR_STALE' and not os.path.exists(os.path.join(cache, 'policy'))
              and env.get('TRIVY_SKIP_CHECK_UPDATE') == 'true' and env.get('TRIVY_CONFIG_CHECK')
              and not os.path.exists(env.get('TRIVY_CONFIG_CHECK', '')) and 'MIRROR_STALE' in env.get('TRIVY_CONFIG_CHECK', ''),
              'G3: a refused checks mirror did not make `trivy config` fatal (it would fall back to embedded '
              'checks): %r %r' % (o, env))
        tc = os.path.join(work, 'trivy-src')
        P.write(os.path.join(tc, 'policy', 'content', 'policies', 'y.rego'), b'package y')
        P.write(os.path.join(tc, 'policy', 'metadata.json'),
                json.dumps({'Digest': 'sha256:' + 'c' * 64, 'DownloadedAt': '2026-10-27T05:00:00.1-06:00'}))
        rc, out, err = run('pack-trivy-checks', '--cache-dir', tc, '--out', os.path.join(work, 'cpack'))
        try:
            info = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            info = {}
        check(rc == 0 and info.get('upstream_version') == 'sha256:' + 'c' * 64
              and os.listdir(os.path.join(work, 'cpack')) == ['checks.tar.gz'],
              'G3: the refresh did not pack Trivy\'s checks bundle with its digest: rc %d %r %s' % (rc, info, err[-300:]))
        rc, out, err = run('pack-trivy-checks', '--cache-dir', os.path.join(work, 'no-cache'), '--out',
                           os.path.join(work, 'cpack2'))
        check(rc != 0 and 'MIRROR_UPSTREAM_UNREACHABLE' in out + err, 'G3: a missing bundle was packed (rc %d)' % rc)

        # ---- G4 OSV -------------------------------------------------------------------------------
        osv_files = {'PyPI/all.zip': zipped([('PYSEC-1.json', b'{"id":"PYSEC-1"}')]),
                     'npm/all.zip': zipped([('MAL-1.json', b'{"id":"MAL-1"}')])}
        oroot = os.path.join(work, 'omirror')
        P.publish(oroot, 'osv', osv_files, P.ago(5), upstream_version='2 ecosystems')
        odir = os.path.join(work, 'osvdb')
        rc, o, env, summ, ev, log = P.consume(work, 'osv', P.file_url(oroot), '--osv-dir', odir, '--osv-ecosystems',
                                              'PyPI npm', tag='g4a')
        placed = os.path.join(odir, 'osv-scalibr', 'npm', 'all.zip')
        print('  G4 osv current: state=%s env=%s' % (o.get('mirror_state'), sorted(env)))
        check(o.get('mirror_state') == 'MIRROR_CURRENT' and os.path.isfile(placed)
              and os.path.isfile(os.path.join(odir, 'osv-scalibr', 'PyPI', 'all.zip'))
              and env.get('KIT_OSV_OFFLINE') == 'true' and env.get('OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY') == odir,
              'G4: a current OSV mirror was not placed where osv-scanner 2.6 reads it: %r %r\n%s' % (o, env, log[-400:]))
        rc, o, env, _, _, _ = P.consume(work, 'osv', P.file_url(oroot), '--osv-dir', os.path.join(work, 'osvdb2'),
                                        '--osv-ecosystems', 'PyPI Go', tag='g4b')
        check(o.get('mirror_state') == 'MIRROR_INTEGRITY_FAILED' and 'Go' in o.get('mirror_why', ''),
              'G4: an ecosystem the scan needs and the mirror lacks was not refused by name: %r' % o)
        ostale = os.path.join(work, 'ostale')
        P.publish(ostale, 'osv', osv_files, P.ago(50))
        odir3 = os.path.join(work, 'osvdb3')
        P.write(os.path.join(odir3, 'osv-scalibr', 'npm', 'all.zip'), b'OLD')
        rc, o, env, _, _, _ = P.consume(work, 'osv', P.file_url(ostale), '--osv-dir', odir3, '--osv-ecosystems',
                                        'npm', tag='g4c')
        print('  G4 osv stale: state=%s offline=%s placed=%s' % (o.get('mirror_state'), env.get('KIT_OSV_OFFLINE'),
                                                                 os.path.exists(os.path.join(odir3, 'osv-scalibr'))))
        check(o.get('mirror_state') == 'MIRROR_STALE' and env.get('KIT_OSV_OFFLINE') == 'true'
              and not os.path.exists(os.path.join(odir3, 'osv-scalibr')),
              'G4: a refused OSV mirror did not leave osv-scanner offline against an EMPTY database: %r %r' % (o, env))
        _, o, env, _, _, _ = P.consume(work, 'osv', P.file_url(ostale), '--osv-dir', os.path.join(work, 'osvdb4'),
                                       '--osv-ecosystems', 'npm', '--fallback', 'upstream', tag='g4d')
        check(o.get('mirror_state') == 'MIRROR_FALLBACK_UPSTREAM' and 'KIT_OSV_OFFLINE' not in env,
              'G4: an explicit fallback did not let osv-scanner use its public API: %r %r' % (o, env))
        up = os.path.join(work, 'osv-up')
        P.write(os.path.join(up, 'PyPI', 'all.zip'), osv_files['PyPI/all.zip'])
        P.write(os.path.join(up, 'npm', 'all.zip'), b'not a zip')
        rc, out, err = run('fetch-osv', '--upstream', P.file_url(up) + '/', '--ecosystems', 'PyPI', '--out',
                           os.path.join(work, 'osv-out'))
        check(rc == 0 and os.path.isfile(os.path.join(work, 'osv-out', 'PyPI', 'all.zip')),
              'G4: the refresh did not fetch the PyPI database: rc %d %s' % (rc, (out + err)[-300:]))
        rc, out, err = run('fetch-osv', '--upstream', P.file_url(up) + '/', '--ecosystems', 'PyPI npm', '--out',
                           os.path.join(work, 'osv-out2'))
        check(rc != 0 and 'MIRROR_UPSTREAM_INTEGRITY_FAILED' in out + err,
              'G4: an all.zip that is not a zip was published (rc %d)' % rc)

        # ---- G5 wiring ----------------------------------------------------------------------------
        iac = text('.github', 'actions', 'iac-scan', 'action.yml')
        iacd = yaml.safe_load(iac)
        check(all(k in (iacd.get('inputs') or {}) for k in ('feed-mirror-url', 'feed-mirror-max-age-hours',
                                                            'feed-mirror-fallback'))
              and 'M_FEED: trivy-checks' in iac and 'scripts/feed_mirror_step.sh' in iac,
              'G5: the iac-scan composite does not read the checks mirror')
        steps = [s.get('name') for s in (iacd.get('runs') or {}).get('steps') or []]
        mi = next((i for i, n in enumerate(steps) if n and 'checks bundle from the organisation mirror' in n), None)
        ti = next((i for i, n in enumerate(steps) if n and n.startswith('Trivy') and 'config' in n.lower()), None)
        check(mi is not None and (ti is None or mi < ti), 'G5: the checks mirror is read after the Trivy config scan')
        nvd = yaml.safe_load(text('.github', 'workflows', 'reusable-nvd-cve.yml'))
        ns = nvd['jobs']['nvd-cve-scan']['steps']
        ids = [s.get('id') for s in ns]
        cm = [s for s in ns if str(s.get('uses', '')).endswith('feed-mirror') and (s.get('with') or {}).get('feed') == 'trivy-checks']
        check(cm and ids.index(cm[0].get('id')) < ids.index('dockerfile'),
              'G5: the NVD path\'s Dockerfile scan does not read the checks mirror first')
        md = sdoc['jobs']['malicious-deps']
        mdt = json.dumps(md)
        check('vars.KIT_FEED_MIRROR_RUNNER' in str(md.get('runs-on', '')), 'G5: malicious-deps cannot run on the private runner')
        om = [s for s in md['steps'] if str(s.get('uses', '')).endswith('feed-mirror') and (s.get('with') or {}).get('feed') == 'osv']
        check(om and 'needs.discover.outputs' in json.dumps(om[0].get('with') or {}),
              'G5: malicious-deps does not read the OSV mirror for the ecosystems discovery found')
        scan = next((s for s in md['steps'] if s.get('id') == 'osv_scan'), {})
        check('KIT_OSV_OFFLINE' in scan.get('run', '') and '--offline-vulnerabilities' in scan.get('run', ''),
              'G5: the OSV scan does not go offline when the mirror says so')
        check('vars.KIT_FEED_MIRROR_RUNNER' in str((sdoc['jobs'].get('iac-scan') or {}).get('runs-on', '')),
              'G5: iac-scan cannot run on the private runner')
        rtext = text('.github', 'workflows', 'reusable-feed-mirror-refresh.yml') + text(
            '.github', 'actions', 'feed-mirror-refresh', 'action.yml')
        for k in ('trivy-checks', 'osv'):
            check('"%s"' % k in dflt + str(((ref.get(True) or ref.get('on'))['workflow_call']['inputs']['feeds'] or {}).get('default', '')),
                  'G5: the refresh does not publish %s by default' % k)
        for k in ('pack-trivy-checks', 'fetch-osv', 'image-target'):
            check(('"$fm" %s' % k) in rtext, 'G5: the refresh never runs feed_mirror.py %s' % k)

        # ---- G6 real tools --------------------------------------------------------------------------
        trivy = shutil.which('trivy')
        if trivy:
            cfg = os.path.join(work, 'cfg')
            P.write(os.path.join(cfg, 'main.tf'), b'resource "aws_s3_bucket" "b" {}\n')
            e = dict(os.environ, TRIVY_SKIP_CHECK_UPDATE='true',
                     TRIVY_CONFIG_CHECK=os.path.join(work, 'policy-refused-MIRROR_STALE'))
            p = subprocess.run([trivy, 'config', '--quiet', '--cache-dir', os.path.join(work, 'tc-empty'), cfg],
                               capture_output=True, text=True, env=e, timeout=600)
            print('  G6 trivy config under the refused environment: rc=%d' % p.returncode)
            check(p.returncode != 0, 'G6: trivy config scanned under the refused environment (it fell back to '
                                     'embedded checks): %s' % (p.stdout + p.stderr)[-300:])
        else:
            print('  G6 trivy not on PATH: the real-tool half is not run here (G3 holds by construction)')
        osv = shutil.which('osv-scanner')
        if osv:
            proj = os.path.join(work, 'proj')
            P.write(os.path.join(proj, 'requirements.txt'), b'requests==2.0.0\n')
            e = dict(os.environ, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=os.path.join(work, 'osv-empty'))
            p = subprocess.run([osv, 'scan', 'source', '--offline-vulnerabilities', '--recursive', proj],
                               capture_output=True, text=True, env=e, timeout=600)
            print('  G6 osv-scanner offline with an empty database: rc=%d' % p.returncode)
            check(p.returncode not in (0, 1), 'G6: osv-scanner reported a result offline with NO database')
        else:
            print('  G6 osv-scanner not on PATH: the real-tool half is not run here')

        # ---- G8 real tools, the POSITIVE halves: a placed mirror is what the scan reads ----------------
        # Each goes the whole way a run goes: the refresh's own packer/fetcher -> a published mirror ->
        # consume -> the scanner under the environment consume wrote. The seeds exist ONLY in the mirror
        # (an advisory for a package no public database has; a check id no embedded bundle has), so a
        # finding cannot have come from the public API or from Trivy's embedded checks.
        osv_bin, why = osv_scanner_260()
        if not osv_bin:
            unknowns.append('G8 osv: ' + why)
            print('  G8 osv-scanner offline from a placed mirror: UNKNOWN (%s)' % why)
        else:
            adv = {'schema_version': '1.6.0', 'id': 'KIT-OSV-0001', 'modified': '2026-10-27T00:00:00Z',
                   'summary': 'seeded: present only in the organisation mirror',
                   'affected': [{'package': {'ecosystem': 'Packagist', 'name': 'kit-seed/vulnerable'},
                                 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '1.0.1'}]}]}]}
            up8 = os.path.join(work, 'osv-up8')
            P.write(os.path.join(up8, 'Packagist', 'all.zip'), zipped([('KIT-OSV-0001.json', json.dumps(adv).encode())]))
            rc, out, err = run('fetch-osv', '--upstream', P.file_url(up8) + '/', '--ecosystems', 'Packagist', '--out',
                               os.path.join(work, 'osv-out8'))
            check(rc == 0, 'G8: the refresh did not fetch the seeded Packagist database: rc %d %s' % (rc, (out + err)[-300:]))
            m8 = os.path.join(work, 'omirror8')
            with io.open(os.path.join(work, 'osv-out8', 'Packagist', 'all.zip'), 'rb') as fh:
                P.publish(m8, 'osv', {'Packagist/all.zip': fh.read()}, P.ago(3), upstream_version='1 ecosystem')
            db8 = os.path.join(work, 'osvdb8')
            rc, o, env, _, _, log = P.consume(work, 'osv', P.file_url(m8), '--osv-dir', db8, '--osv-ecosystems',
                                              'Packagist', tag='g8osv')
            proj = os.path.join(work, 'proj8')
            P.write(os.path.join(proj, 'composer.lock'), json.dumps(
                {'packages': [{'name': 'kit-seed/vulnerable', 'version': '1.0.0'}], 'packages-dev': []}).encode())
            e = dict(os.environ, **{k: v for k, v in env.items() if k.startswith('OSV_')})
            cmd = [osv_bin, 'scan', 'source', '--format', 'json', '--recursive', proj]
            if env.get('KIT_OSV_OFFLINE') == 'true':
                cmd[3:3] = ['--offline-vulnerabilities']
            p = subprocess.run(cmd, capture_output=True, text=True, env=e, timeout=600)
            try:
                ids = [v.get('id') for r in json.loads(p.stdout).get('results') or [] for pk in r.get('packages') or []
                       for v in pk.get('vulnerabilities') or []]
            except ValueError:
                ids = []
            print('  G8 osv-scanner 2.6.0 offline from a placed mirror: state=%s offline=%s rc=%d found=%s'
                  % (o.get('mirror_state'), env.get('KIT_OSV_OFFLINE'), p.returncode, ids))
            check(o.get('mirror_state') == 'MIRROR_CURRENT' and env.get('KIT_OSV_OFFLINE') == 'true'
                  and '--offline-vulnerabilities' in cmd and p.returncode == 1 and 'KIT-OSV-0001' in ids,
                  'G8: an offline osv-scanner scan against the placed mirror did not find the seeded vulnerable '
                  'package: state=%r rc=%d ids=%r\n%s\n%s' % (o.get('mirror_state'), p.returncode, ids,
                                                             p.stderr[-400:], log[-300:]))
        trivy_bin, why = trivy_0712()
        if not trivy_bin:
            unknowns.append('G8 trivy: ' + why)
            print('  G8 trivy config from a placed checks bundle: UNKNOWN (%s)' % why)
        else:
            src = os.path.join(work, 'trivy-src8')
            P.write(os.path.join(src, 'policy', 'content', 'policies', 'kit', 'marker.rego'), MARKER_REGO)
            P.write(os.path.join(src, 'policy', 'metadata.json'), json.dumps(
                {'Digest': 'sha256:' + 'd' * 64, 'DownloadedAt': '2026-10-27T04:20:00Z', 'MajorVersion': 2}).encode())
            rc, out, err = run('pack-trivy-checks', '--cache-dir', src, '--out', os.path.join(work, 'cpack8'))
            check(rc == 0, 'G8: the refresh did not pack the seeded checks bundle: rc %d %s' % (rc, (out + err)[-300:]))
            m8 = os.path.join(work, 'cmirror8')
            with io.open(os.path.join(work, 'cpack8', 'checks.tar.gz'), 'rb') as fh:
                P.publish(m8, 'trivy-checks', {'checks.tar.gz': fh.read()}, P.ago(2))
            cache8 = os.path.join(work, 'tcache8')
            rc, o, env, _, _, log = P.consume(work, 'trivy-checks', P.file_url(m8), '--trivy-cache-dir', cache8,
                                              tag='g8trivy')
            cfg = os.path.join(work, 'cfg8')
            P.write(os.path.join(cfg, 'Dockerfile'), b'FROM alpine:3.20\nUSER root\n')
            e = dict(os.environ, **{k: v for k, v in env.items() if k.startswith('TRIVY_')})
            p = subprocess.run([trivy_bin, 'config', '--skip-version-check', '--format', 'json', cfg],
                               capture_output=True, text=True, env=e, timeout=600)
            try:
                found = [(m.get('ID'), m.get('Status')) for r in json.loads(p.stdout).get('Results') or []
                         for m in r.get('Misconfigurations') or []]
            except ValueError:
                found = []
            print('  G8 trivy 0.71.2 config from a placed checks bundle, update off: state=%s rc=%d found=%s'
                  % (o.get('mirror_state'), p.returncode, found))
            check(o.get('mirror_state') == 'MIRROR_CURRENT' and env.get('TRIVY_SKIP_CHECK_UPDATE') == 'true'
                  and env.get('TRIVY_CACHE_DIR') == cache8 and p.returncode == 0
                  and ('KIT-MIRROR-0001', 'FAIL') in found and 'embedded' not in p.stderr.lower(),
                  'G8: trivy config did not read the placed checks bundle with the update off (a fall back to '
                  'embedded checks cannot find KIT-MIRROR-0001): state=%r rc=%d found=%r\n%s\n%s'
                  % (o.get('mirror_state'), p.returncode, found, p.stderr[-400:], log[-300:]))

        # ---- G7 taxonomy ----------------------------------------------------------------------------
        import subprocess as sp
        r = sp.run([sys.executable, os.path.join(ROOT, 'scripts', 'reconcile_taxonomy.py')], capture_output=True,
                   text=True, env=dict(os.environ, PYTHONIOENCODING='utf-8'))
        check(r.returncode == 0, 'G7: taxonomy drift: %s' % r.stdout[-400:])
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    if unknowns:
        for u in unknowns:
            print('UNKNOWN: ' + u)
        print('UNKNOWN: every other rule held; the positive real-tool halves above could not be checked here '
              '(never PASS).')
        return 2
    print('PASS: gosec and gitleaks are pinned by digest and mirrored like Semgrep; Trivy\'s checks bundle and the '
          'OSV database are mirrored with sha256 manifests; a refused checks mirror makes `trivy config` fatal '
          '(never a silent fall back to embedded checks) and a refused OSV mirror leaves osv-scanner offline '
          'against an empty database (COLLECTION_FAILED), never clean; a placed mirror is what the real '
          'osv-scanner 2.6.0 and Trivy 0.71.2 read offline (the seeded vulnerable package and misconfiguration found).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
