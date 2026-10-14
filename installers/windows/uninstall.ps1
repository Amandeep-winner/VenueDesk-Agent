<#
.SYNOPSIS
    VenueDesk Agent Windows Uninstaller Script
.DESCRIPTION
    Stops and removes the VenueDesk Agent service, optionally purges configuration,
    state, and log files from C:\ProgramData\VenueDesk.
.PARAMETER Purge
    Remove all state, keys, and configuration files.
#>
param(
    [switch]$Purge = $false
)

$ErrorActionPreference = "Stop"

# Ensure script is running with administrative privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "This uninstallation script must be run as Administrator."
    exit 1
}

$ServiceName = "VenueDeskAgent"
Write-Host ">>> Stopping service $ServiceName..."
$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Service) {
    if ($Service.Status -eq 'Running') {
        Stop-Service -Name $ServiceName -Force
    }
    Write-Host ">>> Removing service registration..."
    sc.exe delete $ServiceName | Out-Null
}

$InstallDir = "C:\ProgramData\VenueDesk"
if ($Purge) {
    Write-Host ">>> Purging state directory at $InstallDir..."
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force
    }
    Write-Host ">>> Full purge complete. All device keys, config, and state deleted."
} else {
    Write-Host ">>> Preserving state and configuration in $InstallDir (pass -Purge to delete)."
}

Write-Host ">>> VenueDesk Agent successfully uninstalled."
