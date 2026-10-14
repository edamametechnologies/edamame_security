<#
.SYNOPSIS
  Build a self-contained Windows bundle of the EDAMAME Attack Simulator.

.DESCRIPTION
  Embeds its own standalone CPython (fetched with uv) plus the EDAMAME trigger
  scripts, their catalog.json, and a tiny GUI launcher .exe built from
  launcher_windows.c. Recipients do not need Python installed.

  The embedded Python version is EDAMAME_EMBED_PYTHON_VERSION (default 3.11).
  The asset version is read from .\VERSION. When the AZURE_SIGN_* env vars are
  present the launcher is Authenticode signed with AzureSignTool before the zip
  is sealed.

.PARAMETER DistDir
  Output directory. Defaults to <script dir>\dist.

.NOTES
  Required env var EDAMAME_TRIGGERS_DIR: the edamame_posture trigger scripts
  (tests\security\triggers), which carry catalog.json. CI builds this app from
  the edamame_security checkout with the triggers from the edamame_posture
  checkout.

.OUTPUTS
  Prints "ARTIFACT=<path>" with the produced .zip path as its last line.
#>
[CmdletBinding()]
param(
  [string]$DistDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$PanelDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $DistDir) { $DistDir = Join-Path $PanelDir 'dist' }

$PythonVersion = if ($env:EDAMAME_EMBED_PYTHON_VERSION) { $env:EDAMAME_EMBED_PYTHON_VERSION } else { '3.11' }

$VersionFile = Join-Path $PanelDir 'VERSION'
if (Test-Path $VersionFile) {
  $Version = (Get-Content -Raw $VersionFile).Trim()
} elseif ($env:EDAMAME_SIMULATOR_VERSION) {
  $Version = $env:EDAMAME_SIMULATOR_VERSION
} else {
  $Version = 'dev'
}
if (-not $Version) { $Version = 'dev' }

# Required triggers directory (no local fallback: the triggers live in a
# different repository).
$TriggersSrc = $env:EDAMAME_TRIGGERS_DIR
if (-not $TriggersSrc) {
  throw 'EDAMAME_TRIGGERS_DIR is required (path to edamame_posture\tests\security\triggers).'
}
if (-not (Test-Path -PathType Container $TriggersSrc)) {
  throw "EDAMAME_TRIGGERS_DIR is not a directory: $TriggersSrc"
}
if (-not (Get-ChildItem -Path $TriggersSrc -Filter 'trigger_*.py' -ErrorAction SilentlyContinue)) {
  throw "No trigger_*.py scripts found in $TriggersSrc"
}
if (-not (Test-Path (Join-Path $TriggersSrc 'catalog.json'))) {
  throw "catalog.json not found in $TriggersSrc (the simulator catalog ships with the triggers)."
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  throw 'uv is required to fetch a relocatable CPython (https://github.com/astral-sh/uv)'
}

$AppName = 'EDAMAME Attack Simulator'
$BundleDir = Join-Path $DistDir $AppName
if (Test-Path $BundleDir) { Remove-Item -Recurse -Force $BundleDir }
New-Item -ItemType Directory -Force -Path $BundleDir | Out-Null

# --- Fetch a standalone (managed) CPython ----------------------------------
$env:UV_PYTHON_PREFERENCE = 'only-managed'
Write-Host "Installing relocatable CPython $PythonVersion (x64)..."
uv python install $PythonVersion
if ($LASTEXITCODE -ne 0) { throw "uv python install $PythonVersion failed" }

$PyExe = (uv python find $PythonVersion).Trim()
if (-not $PyExe -or -not (Test-Path $PyExe)) { throw "Could not resolve CPython $PythonVersion via uv" }
$PyHome = Split-Path -Parent $PyExe
Write-Host "Using Python home: $PyHome"

if (-not (Test-Path (Join-Path $PyHome 'pythonw.exe'))) {
  throw "Embedded Python at $PyHome has no pythonw.exe"
}
& (Join-Path $PyHome 'python.exe') -c 'import tkinter' 2>$null
if ($LASTEXITCODE -ne 0) { throw "Embedded Python at $PyHome has no tkinter; pick another version." }

# --- Assemble the bundle ----------------------------------------------------
$PyDest = Join-Path $BundleDir 'python'
Write-Host "Copying runtime into $PyDest"
Copy-Item -Recurse -Force $PyHome $PyDest
foreach ($junk in @('Lib\test', 'Lib\idlelib', 'Lib\turtledemo', 'Lib\ensurepip')) {
  $p = Join-Path $PyDest $junk
  if (Test-Path $p) { Remove-Item -Recurse -Force $p }
}
Get-ChildItem -Path $PyDest -Recurse -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue |
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Copy-Item -Force (Join-Path $PanelDir 'app.py') (Join-Path $BundleDir 'app.py')
Copy-Item -Force (Join-Path $PanelDir 'app_texts.json') (Join-Path $BundleDir 'app_texts.json')
$TriggersDest = Join-Path $BundleDir 'triggers'
New-Item -ItemType Directory -Force -Path $TriggersDest | Out-Null
Copy-Item -Recurse -Force (Join-Path $TriggersSrc '*') $TriggersDest
Get-ChildItem -Path $TriggersDest -Recurse -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue |
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
if (-not (Test-Path (Join-Path $TriggersDest 'catalog.json'))) {
  throw 'catalog.json did not make it into the bundle.'
}

# --- Compile the launcher with MSVC ----------------------------------------
$LauncherExe = Join-Path $BundleDir "$AppName.exe"
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "vswhere not found at $vswhere (Visual Studio C++ tools required)" }
$vsPath = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if (-not $vsPath) { throw 'No Visual Studio installation with the C++ toolset was found' }
Import-Module (Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -no_logo'

# Compile to a space-free name, then rename, to avoid native-arg quoting of
# the display name with spaces.
Push-Location $BundleDir
try {
  cl /nologo /O2 /MD (Join-Path $PanelDir 'launcher_windows.c') `
    /Fe:simulator_launcher.exe `
    /link /SUBSYSTEM:WINDOWS shell32.lib shlwapi.lib user32.lib
  if ($LASTEXITCODE -ne 0) { throw "cl failed to build the launcher ($LASTEXITCODE)" }
  Remove-Item -Force 'launcher_windows.obj' -ErrorAction SilentlyContinue
} finally {
  Pop-Location
}
$BuiltExe = Join-Path $BundleDir 'simulator_launcher.exe'
if (-not (Test-Path $BuiltExe)) { throw "Launcher not produced: $BuiltExe" }
Move-Item -Force $BuiltExe $LauncherExe
if (-not (Test-Path $LauncherExe)) { throw "Launcher not produced: $LauncherExe" }

# Exercise the embedded runtime before sealing.
& (Join-Path $PyDest 'python.exe') -c 'import tkinter, sys; print("embedded python ok:", sys.version.split()[0], "tk", tkinter.TkVersion)'
if ($LASTEXITCODE -ne 0) { throw 'Embedded runtime failed its tkinter self-check' }

# --- Authenticode-sign the launcher ----------------------------------------
# CI (GitHub Actions) MUST produce a signed, verified bundle: an unsigned
# launcher must never be uploaded or published. A local developer build with
# no signing secrets is allowed and prints that it is unsigned.
$IsCI = ($env:GITHUB_ACTIONS -eq 'true') -or ($env:CI -eq 'true')
$HasSigningSecrets = [bool]$env:AZURE_SIGN_KEY_VAULT_URI -and [bool]$env:AZURE_SIGN_CLIENT_ID
if ($HasSigningSecrets) {
  Write-Host 'Signing the launcher with AzureSignTool...'
  AzureSignTool sign `
    -kvt $env:AZURE_SIGN_TENANT_ID `
    -kvu $env:AZURE_SIGN_KEY_VAULT_URI `
    -kvi $env:AZURE_SIGN_CLIENT_ID `
    -kvs $env:AZURE_SIGN_CLIENT_SECRET `
    -kvc $env:AZURE_SIGN_CERT_NAME `
    -tr http://timestamp.digicert.com -v "$LauncherExe"
  if ($LASTEXITCODE -ne 0) { throw "AzureSignTool failed ($LASTEXITCODE)" }
  # Require a valid signature before the bundle is sealed/uploaded.
  $sig = Get-AuthenticodeSignature -FilePath $LauncherExe
  if ($sig.Status -ne 'Valid') {
    throw "Launcher Authenticode signature is not Valid after signing (Status=$($sig.Status): $($sig.StatusMessage)); refusing to seal an unverified bundle."
  }
  Write-Host "Launcher signature verified: $($sig.Status)"
} elseif ($IsCI) {
  throw 'AZURE_SIGN_* signing secrets are not set; refusing to build an unsigned bundle in CI. Configure the AzureSignTool secrets, or run this script locally for an explicitly-unsigned developer build.'
} else {
  Write-Host 'AZURE_SIGN_* not set and not running in CI; launcher left unsigned (local developer build).'
}

# --- Zip --------------------------------------------------------------------
$ZipName = "edamame-attack-simulator-windows-x64-$Version.zip"
$ZipPath = Join-Path $DistDir $ZipName
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path $BundleDir -DestinationPath $ZipPath

$AbsZip = (Resolve-Path $ZipPath).Path
Write-Host "Built: $BundleDir"
Write-Host "Zip:   $AbsZip"
# Emit the marker on the success stream so a caller capturing output sees it.
Write-Output "ARTIFACT=$AbsZip"
