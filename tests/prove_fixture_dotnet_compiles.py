#!/usr/bin/env python3
"""The six-language fixture's C# must compile, or CodeQL cannot analyse it and says so.

WHY THIS EXISTS

    Hosted run 40808064559 (public mirror, throwaway branch of integrate/r8, 2026-10-28) was the first
    on which the csharp CodeQL leg ran buildless (`build-mode: none`) over
    tests/consumer-fixture/full/dotnet/. It analysed, and its SARIF carried two error-level
    `cs/diagnostics/extraction-errors` notifications ("Compiler error: "). Validity row 5 reads an
    error-level tool notification as a failed run, so the leg was COLLECTION_FAILED and its row
    FAILED -- correctly. The cause was the fixture, not the kit: Vuln.cs uses
    System.Data.SqlClient, which .NET 8 does not ship, and Fixture.csproj did not reference it
    (`dotnet build`: CS1069, SqlConnection and SqlCommand forwarded to an unreferenced assembly). A
    fixture that does not compile can never show that CodeQL analyses C#.

WHAT IT PROVES
    D1  the committed fixture's dotnet/ files are exactly what tests/make_fixture.py generates
        (newlines aside), so fixing one cannot drift from the other
    D2  `dotnet build` of a copy of that project succeeds with no compiler error -- as the library the
        SDK builds by default AND as an executable, because CodeQL's buildless C# extraction compiled
        it as one: the second hosted run (40808972273) still carried an error-level extraction
        notification, CS5001 "Program does not contain a static 'Main' method"
    D3  the package added for the compile, System.Data.SqlClient, is at a version
        `dotnet list package --vulnerable` does not flag, so the fixture's seeded dependency signal
        (deps:dotnet-vulnerable: Newtonsoft.Json 9.0.1, System.Text.Encodings.Web 4.5.0) is unchanged

EXIT  0 all hold   1 a violation   2 could not be checked (no dotnet, or the NuGet feed unreachable)
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
FIXTURE = os.path.join(ROOT, 'tests', 'consumer-fixture', 'full', 'dotnet')
ADDED = 'System.Data.SqlClient'


def norm(text):
    return text.replace('\r\n', '\n').strip('\n')


def main():
    import make_fixture as mf
    bad = []
    gen = {rel: body for rel, body, _sig, _tool in mf.FILES if rel.startswith('dotnet/')}
    if not gen:
        print('UNKNOWN: make_fixture.py generates no dotnet/ files.')
        return 2
    for rel, body in sorted(gen.items()):
        p = os.path.join(FIXTURE, os.path.basename(rel))
        have = io.open(p, encoding='utf-8').read() if os.path.isfile(p) else None
        if have is None or norm(have) != norm(body):
            bad.append('D1 %s differs from what make_fixture.py generates' % rel)
    if ADDED not in gen.get('dotnet/Fixture.csproj', ''):
        bad.append('D2 Fixture.csproj does not reference %s, which Vuln.cs uses' % ADDED)
    dotnet = shutil.which('dotnet')
    if not dotnet:
        for b in bad:
            print('VIOLATION: ' + b)
        print('UNKNOWN: no dotnet on this host; D2 and D3 not run.')
        return 1 if bad else 2
    work = tempfile.mkdtemp(prefix='fixture-dotnet-')
    try:
        for rel, body in gen.items():
            io.open(os.path.join(work, os.path.basename(rel)), 'w', encoding='utf-8',
                    newline='\n').write(body)
        env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1')
        for kind, extra in (('library', []), ('exe', ['-p:OutputType=Exe'])):
            b = subprocess.run([dotnet, 'build', '-nologo'] + extra, cwd=work, capture_output=True,
                               text=True, encoding='utf-8', errors='replace', env=env, timeout=600)
            log = (b.stdout or '') + (b.stderr or '')
            if 'NU1301' in log:
                print('UNKNOWN: the NuGet feed was unreachable; the build could not be attempted.')
                return 2
            errors = sorted({ln.strip() for ln in log.splitlines() if ': error ' in ln})
            print('D2 dotnet build (%s) -> exit %d, %d compiler error(s)' % (kind, b.returncode, len(errors)))
            if b.returncode != 0 or errors:
                bad.append('D2 the fixture does not compile as %s: %s' % (kind, errors[:3] or log[-400:]))
            shutil.rmtree(os.path.join(work, 'obj'), ignore_errors=True)
            shutil.rmtree(os.path.join(work, 'bin'), ignore_errors=True)
        v = subprocess.run([dotnet, 'list', 'package', '--vulnerable', '--include-transitive'],
                           cwd=work, capture_output=True, text=True, encoding='utf-8',
                           errors='replace', env=env, timeout=300)
        vlog = v.stdout or ''
        flagged = [ln.strip() for ln in vlog.splitlines() if ln.strip().startswith('>')]
        print('D3 vulnerable packages: %s' % ([f.split()[1] for f in flagged] or 'none'))
        if any(ADDED in f for f in flagged):
            bad.append('D3 %s is itself flagged vulnerable: %s' % (ADDED, flagged))
        for want in ('Newtonsoft.Json', 'System.Text.Encodings.Web'):
            if not any(want in f for f in flagged):
                bad.append('D3 the seeded vulnerable package %s is no longer flagged' % want)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print('VIOLATION: ' + b)
    if bad:
        print('FAIL: %d violation(s)' % len(bad))
        return 1
    print('PASS: the fixture C# is what the generator writes, compiles, and keeps its seeded '
          'vulnerable packages and only those.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
