#!/usr/bin/env python3
"""No step writes external text into $GITHUB_OUTPUT or $GITHUB_ENV unsanitised (KDEC-027).

WHY THIS EXISTS

    On a GHE.com tenant, `.github/actions/resolve` step "Consume the platform-probe values" ran
    `gh api .../dependabot/alerts` against the wrong host, got a multi-line JSON error body, and
    wrote `dependabot_basis=... ${body:0:160}` into $GITHUB_OUTPUT. The runner refused the file:
    `Unable to process file command 'output' successfully` / `Invalid format '  "message": "Bad
    credentials",'`. A step whose own contract was "cannot fail the job: an error is UNAVAILABLE"
    crashed the consumer path instead of degrading.

    It is also output injection. A file-command line is `name=value`; a value carrying a newline
    and `other=...` sets an output -- or, in $GITHUB_ENV, an environment variable such as
    LD_PRELOAD or NODE_OPTIONS -- that the step never meant to set. The text came from a server.

THE RULE

    A value written to $GITHUB_OUTPUT / $GITHUB_ENV that derives from EXTERNAL text -- the output
    of gh, curl, wget, az, docker, git, cat/head/tail of a file, or anything captured with 2>&1 --
    must pass through a single-line sanitiser first (`kit_one_line`, `tr -d '\\r\\n'`, `tr '\\r\\n'
    ' '`, `head -n 1`, a `^[0-9]+$` / `^[A-Za-z0-9_.-]+$` guard), or be written with the
    multi-line form `name<<DELIM` where DELIM is random per write (contains $RANDOM, uuidgen,
    openssl rand, /proc/sys/kernel/random/uuid or mktemp).

    Taint is tracked through plain assignments inside one step: `b=$(gh api ...)`, then
    `basis="... ${b:0:160}"`, then `echo "basis=$basis" >> "$GITHUB_OUTPUT"` is caught at the write.
    This is a static, line-level analysis of shell, not a proof: it catches the class that crashed
    and every simple propagation of it. A finding is cleared by sanitising, never by an allowlist.

EXIT  0 no unsanitised write   1 at least one
"""
import glob
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIPPED = ['.github/workflows/*.yml', '.github/actions/**/action.yml', 'templates/**/*.yml',
           'overlays/**/*.yml']

# In COMMAND position only (`echo npm` is not running npm).
EXTERNAL = re.compile(r'(?:^|\$\(|`|[|;&]|\bthen|\bdo|\belse)\s*(gh|curl|wget|az|docker|git|cat|head|tail|trivy|osv-scanner|'
                      r'semgrep|gitleaks|syft|grype|checkov|kubectl|helm|terraform|npm|pip|dotnet|'
                      r'mvn|gradle)\s|2>&1')
# `${v//[$'\r\n']/ }` is the in-place form the kit's writes use: CR and LF become spaces.
INLINE_CLEAN = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*//\[\$'\\r\\n'\]/ \}")
SANITISER = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*//\[\$'\\r\\n'\]/ \}|kit_one_line|tr -d ['\"]?\\r\\n|tr -d ['\"]?\\n|tr ['\"]\\r\\n['\"] |"
                       r"tr ['\"]\\n['\"] |head -n ?1\b|head -1\b|\$\{[A-Za-z_]+//\$'\\n'/|"
                       r"tr -cd ")
ASSIGN = re.compile(r'^\s*(?:local\s+|export\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
IF_ASSIGN = re.compile(r'(?:if|while|&&|\|\|)\s*!?\s*([A-Za-z_][A-Za-z0-9_]*)=(\$\(.*)$')
GUARD = re.compile(r'\[\[\s*"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?\s*=~\s*\^\[[^\]]*\]\+\$\s*\]\]')
VAR = re.compile(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)')
WRITE = re.compile(r'>>\s*"?\$\{?(GITHUB_OUTPUT|GITHUB_ENV)\}?"?')
RANDOM_DELIM = re.compile(r'RANDOM|uuidgen|openssl rand|random/uuid|mktemp|urandom')


def scan_script(text):
    """-> [(lineno, line, reason)] for every unsanitised write of external text."""
    lines = text.split('\n')
    tainted, guarded = set(), set()
    out = []
    group_start = None    # index of the line that opened a `{ ... } >> $GITHUB_OUTPUT` group
    for i, line in enumerate(lines):
        code = line.split(' #', 1)[0] if not line.lstrip().startswith('#') else ''
        if not code.strip():
            continue
        for g in GUARD.findall(code):
            guarded.add(g)
        for m in (ASSIGN.match(code), IF_ASSIGN.search(code)):
            if not m:
                continue
            name, rhs = m.group(1), m.group(2)
            ext = ('$(' in rhs or '`' in rhs) and EXTERNAL.search(rhs)
            prop = any(v in tainted and v not in guarded for v in VAR.findall(rhs))
            if (ext or prop) and not SANITISER.search(rhs):
                tainted.add(name)
                guarded.discard(name)
            elif SANITISER.search(rhs) or not (ext or prop):
                tainted.discard(name)
        if re.match(r'^\s*read\b', code):
            for v in re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\b', code.split('read', 1)[1]):
                if not v.startswith('-'):
                    tainted.add(v)
        if code.strip() == '{':
            group_start = i
        if WRITE.search(code):
            body = [code]
            if code.strip().startswith('}') and group_start is not None:
                body = lines[group_start:i + 1]
            joined = '\n'.join(body)
            if '<<' in joined and re.search(r'=?<<\s*["\']?\$?\{?[A-Za-z_]', joined):
                # name<<DELIM multi-line form: the delimiter must be random per write.
                if not RANDOM_DELIM.search(joined):
                    m = re.search(r'<<\s*["\']?\$?\{?([A-Za-z_][A-Za-z0-9_]*)', joined)
                    d = m.group(1) if m else ''
                    if not any(RANDOM_DELIM.search(l) for l in lines[:i] if d and d in l):
                        out.append((i + 1, code.strip(), 'multi-line write with a fixed delimiter'))
                continue
            for b in body:
                bcode = INLINE_CLEAN.sub('', b.split(' #', 1)[0])
                if ('$(' in bcode or '`' in bcode) and EXTERNAL.search(bcode) and \
                        not SANITISER.search(bcode):
                    out.append((i + 1, b.strip(), 'command output written directly'))
                    break
                bad = [v for v in VAR.findall(bcode) if v in tainted and v not in guarded]
                if bad:
                    out.append((i + 1, b.strip(), 'external text via $%s' % bad[0]))
                    break
            group_start = None
    return out


def scan_file(path):
    import yaml
    try:
        doc = yaml.safe_load(io.open(path, encoding='utf-8').read()) or {}
    except Exception:  # noqa: BLE001 - another check owns parse errors
        return []
    steps = []
    if isinstance(doc, dict):
        for job in (doc.get('jobs') or {}).values():
            if isinstance(job, dict):
                steps += job.get('steps') or []
        if isinstance(doc.get('runs'), dict):
            steps += doc['runs'].get('steps') or []
    found = []
    for st in steps:
        if isinstance(st, dict) and isinstance(st.get('run'), str):
            for n, line, why in scan_script(st['run']):
                found.append((st.get('name') or st.get('id') or '?', n, line, why))
    return found


SEEDS = [
    ('crash shape', 'if body=$(gh api x 2>&1); then :; else\n  basis="refused: ${body:0:160}"\nfi\n'
                    '{\n  echo "basis=$basis"\n} >> "$GITHUB_OUTPUT"\n', True),
    ('direct', 'echo "v=$(curl -s https://x)" >> "$GITHUB_OUTPUT"\n', True),
    ('fixed delimiter', 'r=$(cat f)\n{ echo "x<<EOF"; echo "$r"; echo "EOF"; } >> "$GITHUB_OUTPUT"\n', True),
    ('sanitised', 'b=$(gh api x 2>&1)\nb=$(printf %s "$b" | kit_one_line)\n'
                  'echo "b=$b" >> "$GITHUB_OUTPUT"\n', False),
    ('random delimiter', 'r=$(cat f)\nd="EOF_$RANDOM$RANDOM"\n'
                         '{ echo "x<<$d"; echo "$r"; echo "$d"; } >> "$GITHUB_OUTPUT"\n', False),
    ('guarded number', 'n=$(gh api x | jq length)\n[[ "$n" =~ ^[0-9]+$ ]] || n=""\n'
                       'echo "n=$n" >> "$GITHUB_OUTPUT"\n', False),
    ('inline clean', 'n=$(cat f)\necho "n=${n//[$\'\\r\\n\']/ }" >> "$GITHUB_OUTPUT"\n', False),
    ('inline clean, other var raw', 'n=$(cat f)\nm=$(cat g)\n'
                                    'echo "n=${n//[$\'\\r\\n\']/ } $m" >> "$GITHUB_OUTPUT"\n', True),
    ('literal', 'state=PASS\necho "state=$state" >> "$GITHUB_OUTPUT"\n', False),
]


def self_test():
    bad = []
    for name, script, want in SEEDS:
        got = bool(scan_script(script))
        if got != want:
            bad.append('%s: flagged=%s, want %s' % (name, got, want))
    return bad


def main():
    st = self_test()
    if st:
        for b in st:
            print('SELF-TEST FAILED: ' + b)
        return 1
    print('self-test ok: %d seeds (the crash shape, direct, fixed delimiter flagged; sanitised, '
          'random delimiter, guarded, literal not)' % len(SEEDS))
    total = []
    for pat in SHIPPED:
        for f in sorted(glob.glob(os.path.join(ROOT, pat), recursive=True)):
            for step, n, line, why in scan_file(f):
                rel = os.path.relpath(f, ROOT).replace('\\', '/')
                total.append('%s: step "%s" run line %d: %s\n      %s' % (rel, step, n, why, line[:150]))
    for t in total:
        print('  ' + t)
    if total:
        print('FAIL: %d write(s) of external text into $GITHUB_OUTPUT/$GITHUB_ENV without a '
              'single-line sanitiser or a random delimiter (output injection; KDEC-027).' % len(total))
        return 1
    print('PASS: every $GITHUB_OUTPUT/$GITHUB_ENV write of external text is sanitised.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
