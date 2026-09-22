[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$packageRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$venvPython = Join-Path $packageRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) { throw 'Run ./scripts/setup.ps1 first.' }
& $venvPython -m frx_portal.database --state vulnerable
if ($LASTEXITCODE -ne 0) { throw 'Learner-state reset failed.' }
