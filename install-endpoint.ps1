param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("OASIS-PAVILION-01", "OASIS-THINKBOOK-01")]
  [string]$NodeId,
  [string]$InstallRoot = "$env:LOCALAPPDATA\JGA\UniversalBraid"
)
$ErrorActionPreference = "Stop"
if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw "Python launcher 'py' is required." }
if (Test-Path "$InstallRoot\identity.pem") { throw "Identity already exists. Refusing to replace it." }
py -3 -m venv "$InstallRoot\venv"
& "$InstallRoot\venv\Scripts\python.exe" -m pip install --upgrade pip
& "$InstallRoot\venv\Scripts\python.exe" -m pip install $PSScriptRoot
& "$InstallRoot\venv\Scripts\oasis-braid.exe" --root $InstallRoot init --node $NodeId
& "$InstallRoot\venv\Scripts\oasis-braid.exe" --root $InstallRoot status
Write-Host "Endpoint initialized OFFLINE. Exchange identity.json only; never copy identity.pem."
Write-Host "CERTIFICATION: NOT_GRANTED"
