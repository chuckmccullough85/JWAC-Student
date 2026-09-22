[CmdletBinding()]
param([ValidateRange(1024, 65535)][int]$Port = 5100)

$ErrorActionPreference = 'Stop'
$packageRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$venvPython = Join-Path $packageRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) { throw 'Run ./scripts/setup.ps1 first.' }
& $venvPython -m frx_portal.cli --state vulnerable --host 127.0.0.1 --port $Port
