# -----------------------------------------------------------------------
# EDAMAME Security MSIX install/uninstall driver for the WiX Burn bundle.
#
# Invoked by install_msix.cmd from the Burn ExePackage cache directory. The
# cmd wrapper passes -Action install / -Action uninstall (RepairArguments
# in bundle.wxs reuse install) plus -BundleProviderKey [WixBundleProviderKey].
#
# Install path:
#   * Add-AppxProvisionedPackage -- machine-wide provisioning so new user
#     logins on the same machine get the app. Bundle is already elevated
#     because the helper MSI is perMachine, so this is allowed.
#   * Add-AppxPackage -- install for the current user immediately so the
#     app shows up in Start menu / shortcuts without re-login.
#   * Set HKLM:\SOFTWARE\EDAMAME\EdamameMsixInstalledVersion to the MSIX
#     payload version -- this is the version-specific Burn DetectCondition
#     lever (see util:RegistrySearch in bundle.wxs).
#   * Set HKLM:\SOFTWARE\EDAMAME\EdamameMsixInstalledByBundle to the parent
#     bundle's WixBundleProviderKey GUID -- so the uninstall path can tell
#     "I am being uninstalled by the bundle that owns me" from "a sibling
#     bundle is being cleaned up by Burn after a same-version reinstall
#     while my installed MSIX should stay put". See uninstall path below.
#   * Relaunch the just-installed app for the interactive console user via
#     a one-shot scheduled task. Mirrors the macOS .pkg postinstall which
#     does `su "$USER" -c "open .../EDAMAME Security.app"` so an upgrade
#     leaves the user with a running app instead of a dead tray icon.
#     Burn ExePackage runs elevated, so we cannot Start-Process the AUMID
#     directly (it would activate as Admin in session 0); the scheduled
#     task with LogonType Interactive + RunLevel Limited is the standard
#     installer trick to spawn into the user's interactive session.
#
# Uninstall path: reverse the install steps, with TWO self-protection
# clauses to survive Burn related-bundle cascades. See full discussion in
# the uninstall block below.
#
# Identity: the MSIX Identity Name MUST be
# 'EDAMAMETechnologies.EDAMAMESecurity'. This is the value declared in
# pubspec.yaml's msix_config.identity_name AND hard-coded as
# WindowsInitializationSettings.appUserModelId in
# lib/notification_service_flutter.dart. They MUST match -- the AUMID
# under which the running app registers with the Windows Toast notifier
# only resolves to a real notification target when an MSIX package with
# the same Name is provisioned for the user. If they drift apart,
# notifications silently fail to register.
#
# We match by package Name (stable, controlled by pubspec.yaml) rather
# than by the full PackageFamilyName, because the publisher hash suffix
# in PFN changes if the signing cert is reissued, which would break this
# script across cert rotations.
# -----------------------------------------------------------------------

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('install', 'uninstall')]
    [string]$Action,
    # Optional: the WixBundleProviderKey GUID of the parent bundle. Burn
    # passes this in via [WixBundleProviderKey] in the bundle.wxs Arguments
    # strings. Used for bundle-id self-protection on uninstall (see below).
    # Empty string is tolerated so old bundles that don't pass it still work.
    [Parameter(Mandatory = $false)]
    [string]$BundleProviderKey = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here              = Split-Path -Parent $MyInvocation.MyCommand.Path
$msixPath          = Join-Path $here 'edamame.msix'
$packageNameFilter = 'EDAMAMETechnologies.EDAMAMESecurity'
$displayNameLike   = 'EDAMAMETechnologies.EDAMAMESecurity*'
$detectKeyPath     = 'HKLM:\SOFTWARE\EDAMAME'
$detectValueName   = 'EdamameMsixInstalledVersion'
$legacyDetectValueName = 'EdamameMsixInstalled'
$bundleKeyValueName = 'EdamameMsixInstalledByBundle'
$helperServiceName = 'edamame_helper'

function Set-DetectKey {
    param(
        [AllowNull()][version]$Version,
        [string]$BundleKey = ''
    )
    if (-not (Test-Path $detectKeyPath)) {
        New-Item -Path $detectKeyPath -Force | Out-Null
    }
    if ($null -eq $Version) {
        Remove-ItemProperty -Path $detectKeyPath -Name $detectValueName -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $detectKeyPath -Name $legacyDetectValueName -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $detectKeyPath -Name $bundleKeyValueName -ErrorAction SilentlyContinue
    } else {
        New-ItemProperty -Path $detectKeyPath -Name $detectValueName -Value $Version.ToString() -PropertyType String -Force | Out-Null
        Remove-ItemProperty -Path $detectKeyPath -Name $legacyDetectValueName -ErrorAction SilentlyContinue
        if ($BundleKey) {
            New-ItemProperty -Path $detectKeyPath -Name $bundleKeyValueName -Value $BundleKey -PropertyType String -Force | Out-Null
        } else {
            Remove-ItemProperty -Path $detectKeyPath -Name $bundleKeyValueName -ErrorAction SilentlyContinue
        }
    }
}

function Get-RegisteredBundleProviderKey {
    try {
        $val = (Get-ItemProperty -Path $detectKeyPath -Name $bundleKeyValueName -ErrorAction SilentlyContinue).$bundleKeyValueName
        if ($val) { return [string]$val }
    } catch { }
    return ''
}

function Invoke-EdamameCliBestEffort {
    param([string[]]$Arguments)
    $candidates = @()
    $cmd = Get-Command 'edamame_cli.exe' -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        $candidates += $cmd.Source
    }
    $commonPaths = @(
        (Join-Path $env:ProgramFiles 'edamame_cli\edamame_cli.exe'),
        (Join-Path $env:ProgramFiles 'edamame_cli\bin\edamame_cli.exe'),
        (Join-Path $env:ProgramData 'chocolatey\bin\edamame_cli.exe')
    )
    foreach ($path in $commonPaths) {
        if (Test-Path -LiteralPath $path) {
            $candidates += $path
        }
    }

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        try {
            Write-Host "Running best-effort EDAMAME RPC: $candidate $($Arguments -join ' ')"
            & $candidate @Arguments | Write-Host
            return $true
        } catch {
            Write-Warning "Best-effort EDAMAME RPC failed via ${candidate}: $_"
        }
    }
    return $false
}

function Stop-EdamameRuntimeForMsixChange {
    Write-Host "Quiescing EDAMAME runtime before MSIX package change..."

    # Prefer a graceful FIM stop when edamame_cli is available. This covers
    # dogfood and CI hosts; consumer installs may not have the CLI package.
    Invoke-EdamameCliBestEffort -Arguments @('rpc', 'stop_file_monitor') | Out-Null

    # Stop the app before touching AppX state. The running 1.3.4 app can
    # otherwise observe helper restart, re-enable the vulnerability loop, and
    # ask the helper to start FIM again during the MSIX replacement.
    Get-Process -Name 'edamame' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Write-Host "Stopping running EDAMAME app process PID $($_.Id)..."
            Stop-Process -Id $_.Id -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to stop EDAMAME app process PID $($_.Id): $_"
        }
    }

    # On non-standalone Windows, FIM is hosted by edamame_helper. Stop the
    # service while Windows replaces the MSIX so no old-version watcher can
    # hold package files open. The service is restarted after the AppX change.
    $svc = Get-Service -Name $helperServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        try {
            if ($svc.Status -ne 'Stopped') {
                Write-Host "Stopping EDAMAME helper service..."
                Stop-Service -Name $helperServiceName -Force -ErrorAction Stop
                $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            }
        } catch {
            Write-Warning "Failed to stop EDAMAME helper service cleanly: $_"
        }
    }

    Get-Process -Name 'edamame_helper' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Write-Host "Stopping leftover EDAMAME helper process PID $($_.Id)..."
            Stop-Process -Id $_.Id -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to stop EDAMAME helper process PID $($_.Id): $_"
        }
    }

    Start-Sleep -Seconds 2
}

function Start-EdamameHelperServiceBestEffort {
    $svc = Get-Service -Name $helperServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    try {
        Write-Host "Starting EDAMAME helper service after MSIX package change..."
        Start-Service -Name $helperServiceName -ErrorAction Stop
    } catch {
        Write-Warning "Failed to start EDAMAME helper service: $_"
    }
}

function Get-MsixPayloadVersion {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $resolved = (Resolve-Path -LiteralPath $Path).Path
        $zip = [System.IO.Compression.ZipFile]::OpenRead($resolved)
        try {
            $entry = $zip.Entries | Where-Object { $_.FullName -ieq 'AppxManifest.xml' } | Select-Object -First 1
            if (-not $entry) { return $null }
            $reader = New-Object System.IO.StreamReader($entry.Open())
            try {
                $xmlText = $reader.ReadToEnd()
            } finally {
                $reader.Close()
            }
            $manifest = [xml]$xmlText
            $ns = New-Object System.Xml.XmlNamespaceManager($manifest.NameTable)
            $ns.AddNamespace('m', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
            $identity = $manifest.SelectSingleNode('//m:Package/m:Identity', $ns)
            if ($identity -and $identity.Version) {
                return [version]$identity.Version
            }
            return $null
        } finally {
            $zip.Dispose()
        }
    } catch {
        Write-Warning "Could not read AppxManifest version from ${Path}: $_"
        return $null
    }
}

function Get-MsixAppId {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $resolved = (Resolve-Path -LiteralPath $Path).Path
        $zip = [System.IO.Compression.ZipFile]::OpenRead($resolved)
        try {
            $entry = $zip.Entries | Where-Object { $_.FullName -ieq 'AppxManifest.xml' } | Select-Object -First 1
            if (-not $entry) { return $null }
            $reader = New-Object System.IO.StreamReader($entry.Open())
            try {
                $xmlText = $reader.ReadToEnd()
            } finally {
                $reader.Close()
            }
            $manifest = [xml]$xmlText
            $ns = New-Object System.Xml.XmlNamespaceManager($manifest.NameTable)
            $ns.AddNamespace('m', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
            $appNode = $manifest.SelectSingleNode('//m:Package/m:Applications/m:Application', $ns)
            if ($appNode -and $appNode.Id) {
                return [string]$appNode.Id
            }
            return $null
        } finally {
            $zip.Dispose()
        }
    } catch {
        Write-Warning "Could not read AppxManifest App Id from ${Path}: $_"
        return $null
    }
}

function Get-InteractiveConsoleUser {
    # Win32_ComputerSystem.UserName returns DOMAIN\User of the user logged in
    # to the interactive console session. This is the moral equivalent of the
    # macOS pkg infra setting $USER to the user who launched installer.app.
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs -and $cs.UserName) { return [string]$cs.UserName }
    } catch { }

    # Fallback: take the owner of the first running explorer.exe. Explorer
    # always runs as the interactive user in their session and never as
    # SYSTEM, so its owner is a reliable proxy when Win32_ComputerSystem
    # returns $null (e.g. RDP-only console disconnected).
    try {
        $explorer = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop |
            Select-Object -First 1
        if ($explorer) {
            $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($owner -and $owner.Domain -and $owner.User) {
                return "$($owner.Domain)\$($owner.User)"
            }
        }
    } catch { }

    return $null
}

function Start-EdamameAppForInteractiveUser {
    param(
        [Parameter(Mandatory=$true)][string]$PackageNameFilter,
        [Parameter(Mandatory=$true)][string]$MsixPath
    )

    # Look up the just-installed package to recover the publisher-hashed
    # PackageFamilyName. We cannot derive this from the bare AppxManifest
    # because the publisher hash depends on the signing certificate.
    $pkg = $null
    try {
        $pkg = Get-AppxPackage -AllUsers -Name $PackageNameFilter -ErrorAction Stop |
            Sort-Object -Property Version -Descending |
            Select-Object -First 1
    } catch {
        Write-Warning "Get-AppxPackage failed during post-install relaunch: $_"
        return
    }
    if (-not $pkg -or -not $pkg.PackageFamilyName) {
        Write-Warning "Skipping post-install relaunch: package $PackageNameFilter not found."
        return
    }

    $appId = Get-MsixAppId -Path $MsixPath
    if (-not $appId) {
        Write-Warning "Skipping post-install relaunch: could not determine App Id from $MsixPath."
        return
    }

    $userName = Get-InteractiveConsoleUser
    if (-not $userName) {
        Write-Warning "Skipping post-install relaunch: no interactive console user detected (silent / unattended install?)."
        return
    }

    $aumid    = "$($pkg.PackageFamilyName)!$appId"
    $taskName = 'EdamameLaunchAfterInstall'

    try {
        Write-Host "Scheduling EDAMAME app relaunch as $userName via $aumid..."
        $action    = New-ScheduledTaskAction -Execute 'explorer.exe' -Argument "shell:AppsFolder\$aumid"
        $trigger   = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(2))
        $principal = New-ScheduledTaskPrincipal -UserId $userName -LogonType Interactive -RunLevel Limited
        # Do NOT pass -DeleteExpiredTaskAfter here. With a -Once trigger that has no
        # EndBoundary, that combination makes Register-ScheduledTask throw
        # HRESULT 0x80041319 (SCHED_E_TASK_ATTRIBUTE_NOT_FOUND, "EndBoundary missing"),
        # which we previously swallowed in the catch and the relaunch silently
        # never fired. The finally block below already unregisters the task.
        $settings  = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit ([TimeSpan]::FromMinutes(2)) `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries
        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Start-Sleep -Seconds 5
        $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        if ($info) {
            Write-Host "Relaunch task LastRunTime=$($info.LastRunTime) LastTaskResult=0x$([Convert]::ToString($info.LastTaskResult,16))"
        }
    } catch {
        Write-Warning "Failed to schedule post-install relaunch: $_"
    } finally {
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        } catch { }
    }
}

function Test-RunningAsLocalSystem {
    try {
        return ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
    } catch {
        return $false
    }
}

function Register-EdamameForInteractiveUser {
    # Running as LocalSystem (an MDM, ConfigMgr or `choco install` from a
    # SYSTEM context) there is no user to Add-AppxPackage for: the AppX
    # deployment APIs do not register packages for LocalSystem. The
    # provisioned package reaches every user at their next sign-in; the user
    # signed in right now gets it registered (and started) through a one-shot
    # task in their session, the same mechanism as the post-install relaunch.
    param(
        [Parameter(Mandatory=$true)][string]$PackageNameFilter,
        [Parameter(Mandatory=$true)][string]$MsixPath
    )

    $prov = Get-AppxProvisionedPackage -Online |
        Where-Object { $_.DisplayName -eq $PackageNameFilter } |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1
    if (-not $prov) {
        Write-Warning "Provisioned package $PackageNameFilter not found; users get the app at their next sign-in."
        return
    }
    # PackageName is Name_Version_Arch_ResourceId_PublisherId; the family
    # name is Name_PublisherId.
    $pfn = "$($prov.DisplayName)_$(($prov.PackageName -split '_')[-1])"
    $appId = Get-MsixAppId -Path $MsixPath

    $userName = Get-InteractiveConsoleUser
    if (-not $userName) {
        Write-Host "No interactive user signed in; $pfn is provisioned and registers at the next sign-in."
        return
    }

    $command = "Add-AppxPackage -RegisterByFamilyName -MainPackage '$pfn'"
    if ($appId) {
        $command += "; Start-Process explorer.exe -ArgumentList 'shell:AppsFolder\$pfn!$appId'"
    }
    $taskName = 'EdamameRegisterAfterInstall'
    try {
        Write-Host "Registering $pfn for $userName through a one-shot task..."
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$command`""
        $trigger   = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(2))
        $principal = New-ScheduledTaskPrincipal -UserId $userName -LogonType Interactive -RunLevel Limited
        # No -DeleteExpiredTaskAfter: see Start-EdamameAppForInteractiveUser.
        $settings  = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5)) `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries
        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        # Registration takes a few seconds; wait for it before unregistering.
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 2
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if (-not $task -or $task.State -ne 'Running') { break }
        }
        $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        if ($info) {
            Write-Host "Registration task LastRunTime=$($info.LastRunTime) LastTaskResult=0x$([Convert]::ToString($info.LastTaskResult,16))"
        }
    } catch {
        Write-Warning "Failed to register $pfn for ${userName}: $_ (it registers at the next sign-in)"
    } finally {
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        } catch { }
    }
}

if ($Action -eq 'install') {
    if (-not (Test-Path -LiteralPath $msixPath)) {
        Write-Error "MSIX payload not found at $msixPath"
        exit 1
    }
    $payloadVersion = Get-MsixPayloadVersion -Path $msixPath
    if (-not $payloadVersion) {
        Write-Error "Could not determine MSIX payload version from $msixPath"
        exit 1
    }

    Stop-EdamameRuntimeForMsixChange

    $asSystem = Test-RunningAsLocalSystem
    try {
        Write-Host "Provisioning $msixPath machine-wide..."
        Add-AppxProvisionedPackage -Online -PackagePath $msixPath -SkipLicense | Out-Null

        if (-not $asSystem) {
            Write-Host "Installing $msixPath for current user..."
            Add-AppxPackage -Path $msixPath
        }
    } finally {
        Start-EdamameHelperServiceBestEffort
    }

    Set-DetectKey -Version $payloadVersion -BundleKey $BundleProviderKey
    Write-Host "EDAMAME MSIX $payloadVersion installed (bundle: $BundleProviderKey)."

    # Relaunch the app for the interactive user so an upgrade does not leave
    # the user staring at a closed window. Best-effort -- a failure here
    # never fails the install. As LocalSystem the signed-in user first needs
    # the package registered; that task starts the app as well.
    if ($asSystem) {
        Register-EdamameForInteractiveUser -PackageNameFilter $packageNameFilter -MsixPath $msixPath
    } else {
        Start-EdamameAppForInteractiveUser -PackageNameFilter $packageNameFilter -MsixPath $msixPath
    }

    exit 0
}

if ($Action -eq 'uninstall') {
    # Self-protection against the Burn MajorUpgrade related-bundle cascade.
    # Two distinct shapes hit the same cleanup path:
    #
    #   1. Newer-version supersession (the original case). User installs
    #      bundle 1.3.5 over 1.3.4. Burn plans "install new packages, then
    #      uninstall the old related bundle's packages". The MSIX ExePackage
    #      is version-detected, but the OLD cached bundle still gets invoked
    #      and would Remove-AppxPackage the freshly-installed newer MSIX
    #      because the package Name matches (only version differs). We
    #      detect this via installedVersion -gt payloadVersion below and
    #      exit early, leaving the registry pointing at the newer version.
    #
    #   2. Same-version reinstall (added 2026-05-14). User installs the
    #      same 1.3.8 bundle a second time (e.g. CI workflow build_bins=
    #      false rebuild, or a corrupt-install recovery attempt). Burn's
    #      DetectCondition (EdamameMsixInstalledVersion = X) evaluates true,
    #      so the NEW bundle's MSIX install is SKIPPED entirely; only the
    #      cascade uninstall of the OLD related bundle runs. Version-based
    #      self-protection does not fire (versions are equal, not -gt), and
    #      the OLD uninstall happily wipes the MSIX. We detect this by
    #      stamping the parent bundle's WixBundleProviderKey GUID into the
    #      registry on install (-BundleKey) and comparing it to the GUID
    #      passed to this uninstall. If they differ, a different bundle
    #      now owns the MSIX -- skip the uninstall.
    #
    # NOTE: Case #2 protection only kicks in once both bundles in a
    # cascade carry this logic; OLD bundles deployed before 2026-05-14
    # will still uninstall the MSIX on a same-version cascade. The fix
    # buys us protection going forward.
    $payloadVersion = Get-MsixPayloadVersion -Path $msixPath
    $installedPkg = $null
    try {
        $installedPkg = Get-AppxPackage -AllUsers -Name $packageNameFilter -ErrorAction SilentlyContinue |
            Sort-Object -Property Version -Descending |
            Select-Object -First 1
    } catch {
        Write-Warning "Could not enumerate installed AppxPackage for self-protection check: $_"
    }

    # Case 1: newer version installed.
    if ($payloadVersion -and $installedPkg -and $installedPkg.Version) {
        try {
            $installedVersion = [version]$installedPkg.Version
            if ($installedVersion -gt $payloadVersion) {
                Write-Host "A newer EDAMAME MSIX ($installedVersion) is already installed; skipping uninstall of older payload ($payloadVersion)."
                Write-Host "This is the Burn MajorUpgrade related-bundle cleanup path. The newer bundle's MSIX is the system of record."
                Set-DetectKey -Version $installedVersion -BundleKey (Get-RegisteredBundleProviderKey)
                exit 0
            }
        } catch {
            Write-Warning "Could not parse installed MSIX version '$($installedPkg.Version)': $_"
        }
    }

    # Case 2: same version, different bundle owner.
    $registeredBundleKey = Get-RegisteredBundleProviderKey
    if ($BundleProviderKey -and $registeredBundleKey -and ($registeredBundleKey -ne $BundleProviderKey) -and $installedPkg) {
        Write-Host "EDAMAME MSIX is currently owned by bundle $registeredBundleKey; this script belongs to bundle $BundleProviderKey."
        Write-Host "Skipping uninstall (Burn related-bundle cascade for a same-version reinstall)."
        # Leave the registry alone -- it correctly points at the bundle that owns the MSIX.
        exit 0
    }

    Stop-EdamameRuntimeForMsixChange

    Write-Host "Removing provisioned EDAMAME MSIX (machine-wide)..."
    $provisioned = Get-AppxProvisionedPackage -Online | Where-Object {
        $_.DisplayName -like $displayNameLike
    }
    if ($provisioned) {
        foreach ($p in $provisioned) {
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName | Out-Null
            } catch {
                Write-Warning "Remove-AppxProvisionedPackage failed for $($p.PackageName): $_"
            }
        }
    }

    Write-Host "Removing EDAMAME MSIX for all users..."
    $userPkgs = Get-AppxPackage -AllUsers -Name $packageNameFilter -ErrorAction SilentlyContinue
    if ($userPkgs) {
        foreach ($u in $userPkgs) {
            try {
                Remove-AppxPackage -AllUsers -Package $u.PackageFullName -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Remove-AppxPackage failed for $($u.PackageFullName): $_"
            }
        }
    }

    Set-DetectKey -Version $null
    Write-Host "EDAMAME MSIX uninstalled."
    exit 0
}
