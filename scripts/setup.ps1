[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$packageRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$venvPath = Join-Path $packageRoot '.venv'
$venvPython = Join-Path $venvPath 'Scripts/python.exe'
$frxProject = Join-Path $packageRoot 'frx-project'
$requirements = Join-Path $packageRoot 'requirements.txt'

if (-not (Test-Path -LiteralPath $venvPython)) {
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) { & $launcher.Source -3.12 -m venv $venvPath }
    else { python -m venv $venvPath }
}

& $venvPython -m pip install -r $requirements
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
& $venvPython -m pip install --no-build-isolation --no-deps -e $frxProject
if ($LASTEXITCODE -ne 0) { throw 'FRX project installation failed.' }
& $venvPython -m frx_portal.database --state vulnerable
if ($LASTEXITCODE -ne 0) { throw 'Learner-state initialization failed.' }
Write-Host 'FRX learner setup complete.'
