<#
.SYNOPSIS
  Remove the Root Justice Windows Service and program files.
.DESCRIPTION
  Keeps the evidence ledger (chain-of-custody) unless -PurgeEvidence is passed.
  Run from an elevated PowerShell.
#>
[CmdletBinding()]
param([switch]$PurgeEvidence)

$ErrorActionPreference = "Stop"
$ServiceName = "RootJustice"
$Base = Join-Path $env:ProgramData "RootJustice"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { throw "Run from an elevated (Administrator) PowerShell." }

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Write-Host "[root-justice] service removed."
}

$venv = Join-Path $Base "venv"
if (Test-Path $venv) { Remove-Item -Recurse -Force $venv }

if ($PurgeEvidence) {
    if (Test-Path $Base) { Remove-Item -Recurse -Force $Base }
    Write-Host "[root-justice] removed, including evidence ledger."
} else {
    Write-Host "[root-justice] removed. Evidence kept under $Base\evidence (use -PurgeEvidence to delete)."
}
