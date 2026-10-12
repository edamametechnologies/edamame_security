$ErrorActionPreference = 'Stop'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Removes the provisioned package and the per-user registrations of every
# user (see chocolateyInstall.ps1).
$driver = Join-Path $toolsDir 'install_msix.ps1'
if (Test-Path -LiteralPath $driver) {
    & $driver -Action uninstall
    if ($LASTEXITCODE -ne 0) {
        throw "install_msix.ps1 failed with exit code $LASTEXITCODE"
    }
} else {
    # Packages built before the driver was bundled.
    Get-AppxPackage -AllUsers -Name 'EDAMAMETechnologies.EDAMAMESecurity' |
        ForEach-Object { Remove-AppxPackage -AllUsers -Package $_.PackageFullName -ErrorAction SilentlyContinue }
}

Write-Host "EDAMAME Security has been uninstalled."
