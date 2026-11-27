<#
.SYNOPSIS
  Install Root Justice as a least-privilege Windows Service.

.DESCRIPTION
  Creates an isolated Python venv under %ProgramData%\RootJustice, installs the
  package, and registers a Windows Service that runs the edge shield.

  SAFE BY DEFAULT: the service starts in LOG-ONLY mode, bound to 127.0.0.1.
  It runs under the per-service Virtual Account "NT SERVICE\RootJustice"
  (not SYSTEM, not your user) with only the privileges a listener needs.

  Admin is required ONLY to register the service. The service itself is
  unprivileged. This is defensive software for a machine you own/administer.

.PARAMETER Enforce
  Start in enforce mode (serve the warning banner + block) instead of log-only.

.PARAMETER ListenHost
  Interface to bind. Default 127.0.0.1. Use a real interface only in front of
  the app you protect, behind your own TLS.

.PARAMETER Port
  Port to bind. Default 8080.

.EXAMPLE
  # From an elevated PowerShell, in the repo root:
  .\deploy\windows\Install-RootJustice.ps1
#>
[CmdletBinding()]
param(
    [switch]$Enforce,
    [string]$ListenHost = "127.0.0.1",
    [int]$Port = 8080,
    [string[]]$TrustedProxy = @(),
    # Passthrough for any other serve flags, e.g.:
    #   -ExtraArgs '--db C:\ProgramData\RootJustice\state.sqlite3 --allowlist C:\...\allow.txt --upstream http://127.0.0.1:9000'
    [string]$ExtraArgs = ""
)

$ErrorActionPreference = "Stop"
$ServiceName = "RootJustice"
$Base = Join-Path $env:ProgramData "RootJustice"
$Venv = Join-Path $Base "venv"
$Evidence = Join-Path $Base "evidence\evidence_ledger.jsonl"
$SrcDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# --- Admin check (needed only to register the service) ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { throw "Run this installer from an elevated (Administrator) PowerShell." }

$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { throw "Python 3.10+ is required on PATH." }

Write-Host "[root-justice] installing from $SrcDir"
New-Item -ItemType Directory -Force -Path $Base, (Split-Path $Evidence) | Out-Null

& $python -m venv $Venv
& (Join-Path $Venv "Scripts\pip.exe") install --upgrade pip | Out-Null
& (Join-Path $Venv "Scripts\pip.exe") install $SrcDir | Out-Null

$exe = Join-Path $Venv "Scripts\root-justice.exe"
if (-not (Test-Path $exe)) { throw "Install did not produce $exe" }

# Build the service command line. Default is log-only; --enforce opts in.
$args = @("serve", "--host", $ListenHost, "--port", $Port, "--evidence", "`"$Evidence`"")
if ($Enforce) { $args += "--enforce" }
foreach ($tp in $TrustedProxy) { $args += @("--trusted-proxy", $tp) }
$binPath = "`"$exe`" " + ($args -join " ")
if ($ExtraArgs.Trim()) { $binPath += " " + $ExtraArgs.Trim() }

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "[root-justice] service exists; stopping and reconfiguring"
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# Create the service. Run as the per-service Virtual Account (least privilege).
New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName "Root Justice Edge Shield" `
    -Description "Defensive blue-team edge shield, origin attribution, and evidence (log-only unless configured to enforce)." `
    -StartupType Automatic | Out-Null
sc.exe config $ServiceName obj= "NT SERVICE\$ServiceName" | Out-Null
# Restart on failure.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

# Grant the virtual account write access to its evidence dir only.
$acct = "NT SERVICE\$ServiceName"
icacls (Split-Path $Evidence) /grant "${acct}:(OI)(CI)M" | Out-Null

Start-Service $ServiceName
$mode = if ($Enforce) { "ENFORCE" } else { "LOG-ONLY" }
Write-Host ""
Write-Host "[root-justice] installed and started ($mode) on http://${ListenHost}:$Port"
Write-Host "  status : Get-Service $ServiceName"
Write-Host "  logs   : Get-Content '$Base\evidence\evidence_ledger.jsonl' -Wait"
Write-Host "  report : & '$exe' export-report --evidence '$Evidence' --reviewed-by '<your name>'"
Write-Host "  remove : .\deploy\windows\Uninstall-RootJustice.ps1"
