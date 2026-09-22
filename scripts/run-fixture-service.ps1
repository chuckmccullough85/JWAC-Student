[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 5101
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$venvPython = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    throw 'Virtual environment not found. Run ./scripts/setup.ps1 first.'
}
& $venvPython -m frx_portal.fixture_service --host 127.0.0.1 --port $Port
