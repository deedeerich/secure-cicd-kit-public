#!/usr/bin/env python3
"""Run the self-test's own yamllint, with the self-test's own config, before anything is pushed.

WHY THIS EXISTS
    Release 3's candidate went red on the hosted `yamllint` job with 27 errors of one kind:

        32:32 [colons] too many spaces after colon

    in `.github/actions/resolve-policy/action.yml` and `.github/actions/run-record/action.yml`,
    whose `outputs:`/`inputs:` maps were padded into aligned columns. Every local gate was green.
    Not one of them ran yamllint: the config lived only inside the self-test's `run:` block (a
    heredoc), so the only place the rule existed was the hosted runner, and the local battery had
    no way to find a defect the hosted job was certain to find.

WHAT THIS DOES
    It reads the config OUT OF `.github/workflows/self-test.yml` -- the heredoc the hosted step
    writes to `.yamllint.kit.yml` -- so there is one config and it cannot drift. It then lints the
    same paths the hosted step lints (`.github/` and `profiles/`), and fails on any ERROR. Warnings
    are reported by count only; the hosted step does not fail on them either.

    Line endings: a hosted checkout is LF; a Windows checkout with autocrlf is CRLF, and yamllint's
    `new-lines` rule then fires once on every file -- a defect of the disk, not of the commit. The
    files are linted from a copy with line endings normalised to LF, which is what the runner sees
    (the same normalisation tests/check_workflow_size.py applies to its measurement).

    Before trusting a clean result it proves it can fail: a padded-colon sample (the exact Release 3
    defect) must be reported as an error under the extracted config.

EXIT
    0  zero yamllint errors under the self-test's config
    1  one or more errors (each printed as path:line:col)
    2  could not be checked -- yamllint absent, or the config could not be extracted (UNKNOWN)
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SELF_TEST = os.path.join(ROOT, '.github', 'workflows', 'self-test.yml')
PATHS = ('.github', 'profiles')
HEREDOC_RX = re.compile(r"cat > \.yamllint\.kit\.yml <<'EOF'\r?\n(.*?)\r?\n[ \t]*EOF\r?\n", re.S)
SEEDED = 'outputs:\n  a:          {description: padded, value: x}\n'


def extract_config(text):
    m = HEREDOC_RX.search(text)
    if not m:
        return None
    lines = m.group(1).replace('\r\n', '\n').split('\n')
    indent = min(len(ln) - len(ln.lstrip()) for ln in lines if ln.strip())
    return '\n'.join(ln[indent:] for ln in lines) + '\n'


def lint(config_path, target, cwd):
    p = subprocess.run([sys.executable, '-m', 'yamllint', '-f', 'parsable', '-c', config_path] +
                       list(target), cwd=cwd, capture_output=True, text=True, encoding='utf-8',
                       errors='replace')
    out = p.stdout.splitlines()
    return ([ln for ln in out if '[error]' in ln], [ln for ln in out if '[warning]' in ln],
            p.returncode, p.stderr)


def copy_lf(src_root, dst_root):
    for top in PATHS:
        for dirpath, _dirs, files in os.walk(os.path.join(src_root, top)):
            for f in files:
                if not f.endswith(('.yml', '.yaml')):
                    continue
                src = os.path.join(dirpath, f)
                dst = os.path.join(dst_root, os.path.relpath(src, src_root))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(src, 'rb') as fh:
                    data = fh.read()
                with open(dst, 'wb') as fh:
                    fh.write(data.replace(b'\r\n', b'\n'))


def main():
    try:
        import yamllint  # noqa: F401
    except ImportError:
        print('UNKNOWN: yamllint is not installed (python -m pip install yamllint); nothing was linted.')
        return 2
    try:
        with open(SELF_TEST, encoding='utf-8') as fh:
            config = extract_config(fh.read())
    except OSError as e:
        print('UNKNOWN: cannot read %s: %s' % (SELF_TEST, e))
        return 2
    if not config:
        print('UNKNOWN: the yamllint config heredoc was not found in self-test.yml; '
              'this check and the hosted step have come apart.')
        return 2
    work = tempfile.mkdtemp(prefix='yamllint-kit-')
    try:
        cfg = os.path.join(work, 'yamllint.kit.yml')
        with open(cfg, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(config)
        # Prove it can fail before believing a pass.
        probe = os.path.join(work, 'probe')
        os.makedirs(probe)
        with open(os.path.join(probe, 'seeded.yml'), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(SEEDED)
        errs, _w, _rc, stderr = lint(cfg, ['seeded.yml'], probe)
        if not any('(colons)' in e for e in errs):
            print('UNKNOWN: the seeded padded-colon sample was NOT reported -- the extracted config '
                  'or the yamllint run is not doing what the hosted step does. %s' % stderr[:300])
            return 2
        tree = os.path.join(work, 'tree')
        copy_lf(ROOT, tree)
        errs, warns, rc, stderr = lint(cfg, list(PATHS), tree)
        if rc not in (0, 1) and not errs:
            print('UNKNOWN: yamllint exited %s: %s' % (rc, stderr[:300]))
            return 2
        for e in errs:
            print('  ' + e.replace('\\', '/'))
        if errs:
            print('FAIL: %d yamllint error(s) under the self-test config (%d warning(s)). The hosted '
                  '`yamllint` job fails on exactly these.' % (len(errs), len(warns)))
            return 1
        print('PASS: zero yamllint errors in %s under the self-test config (%d warning(s), '
              'non-failing there too); the seeded padded-colon control was caught.'
              % (' '.join(PATHS), len(warns)))
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
