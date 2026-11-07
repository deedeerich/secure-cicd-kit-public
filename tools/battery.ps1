# The local battery (CP-018), PowerShell twin of tools/battery.sh. All logic is in tools/battery.py,
# which reads .github/workflows/self-test.yml. Arguments pass through (--fast, --list, --only, --strict).
#
# WHY THE PATH CHANGE: under PowerShell, `bash` resolves to the WSL stub, and the proofs that shell
# out to bash then report UNKNOWN (continuation.md). Git for Windows' bash goes first on PATH for
# this process only, and BATTERY_BASH names it for tools/battery.py.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$gitBin = 'C:\Program Files\Git\bin'
if (Test-Path (Join-Path $gitBin 'bash.exe')) {
    $env:PATH = "$gitBin;C:\Program Files\Git\usr\bin;$env:PATH"
    $env:BATTERY_BASH = (Join-Path $gitBin 'bash.exe')
}
$py = $env:BATTERY_PYTHON
if (-not $py) {
    foreach ($c in @('python', 'python3', 'py')) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($null -ne $cmd) { $py = $cmd.Source; break }
    }
}
if (-not $py) { Write-Error 'UNKNOWN: no Python found (set BATTERY_PYTHON).'; exit 2 }
Push-Location $root
try {
    & $py tools/battery.py @args
    $rc = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $rc
