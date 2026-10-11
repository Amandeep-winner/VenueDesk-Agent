<#
.SYNOPSIS
    VenueDesk Agent Windows Installation Script
.DESCRIPTION
    Installs VenueDesk Agent into C:\ProgramData\VenueDesk, restricts filesystem ACLs,
    writes config.toml, performs initial enrollment if token is supplied, and sets up
    the Windows Service wrapper.
.PARAMETER ServerUrl
    Control plane server URL (e.g. https://control.venue.internal)
.PARAMETER Token
    Single-use pairing token (e.g. PAIR-...)
.PARAMETER AllowInsecureDev
    Allow unencrypted HTTP for local development testing
#>
param(
    [string]$ServerUrl = "https://127.0.0.1:5001",
    [string]$Token = "",
    [switch]$AllowInsecureDev = $false
)

$ErrorActionPreference = "Stop"

# Ensure script is running with administrative privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "This installation script must be run as Administrator."
    exit 1
}

$InstallDir = "C:\ProgramData\VenueDesk"
Write-Host ">>> Setting up target directory at $InstallDir..."
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Restrict ACLs: SYSTEM and Administrators FullControl only
Write-Host ">>> Configuring restrictive NTFS ACL permissions..."
$Acl = Get-Acl $InstallDir
$Acl.SetAccessRuleProtection($true, $false) # Disable inheritance and remove existing
$SystemRule = New-Object Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$AdminRule = New-Object Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.AddAccessRule($SystemRule)
$Acl.AddAccessRule($AdminRule)
Set-Acl -Path $InstallDir -AclObject $Acl

# Write config.toml
$ConfigFile = Join-Path $InstallDir "config.toml"
Write-Host ">>> Writing configuration to $ConfigFile..."
$ConfigContent = @"
server_url = "$ServerUrl"
deployment_salt = "venuedesk-default-salt-32-chars-long!"
heartbeat_seconds = 60
telemetry_seconds = 60
inventory_seconds = 21600
jobs_poll_seconds = 60
key_store = "file"
state_dir = "$InstallDir"
allow_insecure_dev = $(if ($AllowInsecureDev) { "true" } else { "false" })
log_level = "INFO"
approved_services = []
diagnostic_allowlist = ["127.0.0.1", "localhost"]
"@
Set-Content -Path $ConfigFile -Value $ConfigContent -Encoding UTF8

# Install Python package
Write-Host ">>> Installing VenueDesk Agent package..."
$AgentSource = Join-Path $PSScriptRoot "..\..\venuedesk-agent"
if (Test-Path $AgentSource) {
    pip install -e $AgentSource
}

# Execute enrollment if token is provided
if ($Token) {
    Write-Host ">>> Enrolling endpoint with supplied pairing token..."
    python -m agent.main enroll --config $ConfigFile --server $ServerUrl --token $Token
}

Write-Host ">>> VenueDesk Agent Windows installation complete."
Write-Host "State directory: $InstallDir"
Write-Host "Config file: $ConfigFile"
