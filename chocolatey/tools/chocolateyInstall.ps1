$ErrorActionPreference = 'Stop'
$packageName = 'edamame'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
# The release workflow (edamame_app release_windows_standalone.yml) sets the
# URL of the release's MSIX and its SHA256 below before `choco pack`.
$url64 = 'https://github.com/edamametechnologies/edamame_security/releases/download/v2.0.3/edamame-windows-2.0.3.msix'
$checksum64 = '0000000000000000000000000000000000000000000000000000000000000000'

# install_msix.ps1 is the WiX Burn bundle's MSIX driver
# (windows_bundle/install_msix.ps1), copied into the package by the release
# workflow before `choco pack`. It provisions the MSIX machine-wide
# (Add-AppxProvisionedPackage), so every user gets the app -- including when
# choco runs as SYSTEM from an MDM, where a per-user Add-AppxPackage would
# register it for SYSTEM only -- and registers it for the signed-in user.
$driver = Join-Path $toolsDir 'install_msix.ps1'
if (-not (Test-Path -LiteralPath $driver)) {
    throw "install_msix.ps1 is missing from the package"
}

# The driver expects the payload next to it, named edamame.msix.
$msixPath = Join-Path $toolsDir 'edamame.msix'
Get-ChocolateyWebFile -PackageName $packageName `
                      -FileFullPath $msixPath `
                      -Url64bit $url64 `
                      -Checksum64 $checksum64 `
                      -ChecksumType64 'sha256'

try {
    & $driver -Action install
    if ($LASTEXITCODE -ne 0) {
        throw "install_msix.ps1 failed with exit code $LASTEXITCODE"
    }
} finally {
    Remove-Item -LiteralPath $msixPath -Force -ErrorAction SilentlyContinue
}
