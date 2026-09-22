[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$venvPython = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    throw 'Virtual environment not found. Run ./scripts/setup.ps1 first.'
}
if ($PSVersionTable.PSVersion -lt [version]'7.4') {
    throw "PowerShell 7.4 or later is required; found $($PSVersionTable.PSVersion)."
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git is required but was not found on PATH.'
}

& $venvPython -c "import sys; from importlib.metadata import version; assert (3, 12) <= sys.version_info[:2] < (3, 15), sys.version; import frx_portal; print('Python', sys.version.split()[0]); print('Flask', version('Flask')); print('cryptography', version('cryptography')); print('pytest', version('pytest')); print('frx_portal import OK')"
if ($LASTEXITCODE -ne 0) { throw 'Python environment verification failed.' }

Write-Host "PowerShell $($PSVersionTable.PSVersion)"
Write-Host "Git $((git --version) -replace '^git version ', '')"
Write-Host 'Environment verification passed.'
