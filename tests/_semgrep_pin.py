"""The Semgrep the flagship's sast-semgrep job runs: its container image, pinned by digest, and the
version that digest is (lane L-SG, completion ledger L03 "one Semgrep version").

Not a test: the leading underscore keeps tests/prove_tests_leave_tree_clean.py from running it.

WHY THIS EXISTS

    Until lane L-SG the job ran `semgrep/semgrep:1.90.0` (a tag, which can move) while the C# and
    Java jobs, the weekly probe and every local proof ran pip Semgrep 1.178.0. Each proof then
    carried a "NOT PROVEN HERE: the job runs 1.90.0" caveat, and 1.90.0 reads PHP only to 7.2
    (tests/corpora/php_corpus.py), so a real PHP 8.x repository was COLLECTION_FAILED.

    One rule, read once: the job's `container.image` is `semgrep/semgrep@sha256:<64 hex>`, and the
    same line carries a `# <version>` comment naming the release that digest is. A digest alone
    says nothing a reader can compare; a version alone can move. The proofs that run Semgrep
    locally (prove_semgrep_php, prove_semgrep_strict) hold the Semgrep on PATH to that version, and
    the probes (validate-scanners, probe-scanner-corpora) to that exact image.
"""
import io
import os
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FLAGSHIP = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
JOB = 'sast-semgrep'
DIGEST_IMAGE = re.compile(r'^semgrep/semgrep@sha256:[0-9a-f]{64}$')


def flagship(path=None):
    """-> (image, version, problem). `problem` is None when the job's image is a digest pin whose
    line names its version; otherwise it says what is wrong and version may be None."""
    import yaml
    path = path or os.environ.get('KIT_PROOF_WORKFLOW') or FLAGSHIP
    text = io.open(path, encoding='utf-8').read()
    doc = yaml.safe_load(text) or {}
    cont = ((doc.get('jobs') or {}).get(JOB) or {}).get('container')
    image = str((cont.get('image') if isinstance(cont, dict) else cont) or '')
    # THE MIRROR FORM (Release 4, KDEC-032): `${{ vars.KIT_SCANNER_IMAGE_REGISTRY != '' && format('{0}/
    # semgrep/semgrep@sha256:<d>', ...) || 'semgrep/semgrep@sha256:<d>' }}`. Accepted only when BOTH
    # branches name the same digest: the mirror may change where the bytes come from, never which bytes.
    if image.startswith('${{'):
        pins = set(re.findall(r'semgrep/semgrep@sha256:[0-9a-f]{64}', image))
        if len(pins) != 1 or "'semgrep/semgrep@sha256:" not in image or "/semgrep/semgrep@sha256:" not in image:
            return image, None, ('the %s image expression does not name ONE digest in both its mirror and its '
                                 'public branch: %r' % (JOB, image))
        line = re.search(r'^\s*image:\s*\$\{\{.*\}\}\s*#\s*(\d+\.\d+\.\d+)\s*$', text, re.M)
        image = pins.pop()
        if not line:
            return image, None, ('the %s image line does not name the version its digest is '
                                 '(`# X.Y.Z`)' % JOB)
        return image, line.group(1), None
    if not DIGEST_IMAGE.match(image):
        m = re.match(r'^semgrep/semgrep:(\d+\.\d+\.\d+)$', image)
        return image, (m.group(1) if m else None), (
            'the %s job runs %r, which is not pinned by digest (a tag can move)' % (JOB, image))
    m = re.search(r'^\s*image:\s*%s\s*#\s*(\d+\.\d+\.\d+)\s*$' % re.escape(image), text, re.M)
    if not m:
        return image, None, ('the %s image line does not name the version its digest is '
                             '(`# X.Y.Z`)' % JOB)
    return image, m.group(1), None


def path_version(bash, path_prefix=''):
    """-> the version of the `semgrep` a bash on this PATH runs, or None."""
    env = dict(os.environ)
    if path_prefix:
        env['PATH'] = path_prefix + os.pathsep + env.get('PATH', '')
    try:
        p = subprocess.run([bash, '-c', 'semgrep --version 2>/dev/null'], capture_output=True,
                           text=True, env=env, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r'^(\d+\.\d+\.\d+)\s*$', p.stdout or '', re.M)
    return m.group(1) if m else None
