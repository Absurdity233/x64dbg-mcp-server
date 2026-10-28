# install-elevated-task.ps1 - one-time, passwordless elevated launch for x64dbg.
#
# Why a scheduled task: a non-elevated MCP server can only start an elevated
# x64dbg through Start-Process -Verb RunAs, which shows a UAC prompt (on the
# secure desktop, where UI automation cannot click it). A task registered with
# RunLevel Highest and an interactive logon type starts the same GUI in the
# user's session with no prompt, and `schtasks /run` can trigger it from a
# medium-integrity process.
#
# Security: this is a persistent auto-elevation path for the given executable.
# Only register the x64dbg copy you intend to run as administrator. Remove it
# with -Remove when done.
#
# Run ONCE from an elevated PowerShell.

[CmdletBinding()]
param(
  [string]$Id = 'default',
  [string]$X64dbgPath = '',
  [string]$TaskName = '',
  [switch]$Remove
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  throw 'Run this script from an elevated PowerShell (right-click > Run as administrator).'
}

if (-not $TaskName) { $TaskName = "x64dbg-mcp-$Id" }

if ($Remove) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
  Write-Output "Removed scheduled task '$TaskName'."
  exit 0
}

if (-not $X64dbgPath) { $X64dbgPath = $env:X64DBG_PATH }
if (-not $X64dbgPath) {
  throw 'Pass -X64dbgPath <path to x64dbg.exe>, or set X64DBG_PATH first.'
}
if (-not (Test-Path -LiteralPath $X64dbgPath -PathType Leaf)) {
  throw "x64dbg.exe not found: $X64dbgPath"
}

$exe = (Resolve-Path -LiteralPath $X64dbgPath).Path
$workDir = Split-Path -Parent $exe
$user = "$env:USERDOMAIN\$env:USERNAME"

$action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $workDir
# Interactive = "run only when the user is logged on", so the GUI appears on
# this desktop. Highest = elevated token, no UAC prompt when triggered.
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $taskPrincipal `
  -Description 'Started by x64dbg MCP (elevated, no UAC prompt)' -Force | Out-Null

Write-Output "Registered scheduled task '$TaskName' -> $exe"
Write-Output ''
Write-Output 'Wire it into the MCP server:'
Write-Output "  single instance:  set X64DBG_MCP_ELEVATED_TASK=$TaskName and X64DBG_MCP_ELEVATED=1"
Write-Output "  per instance:     add \"elevated\": true and \"elevatedTask\": \"$TaskName\" to that manifest entry"
Write-Output ''
Write-Output 'Then x64dbg_instances action=start elevated=true starts it with no prompt.'
Write-Output "Remove later with: .\install-elevated-task.ps1 -TaskName $TaskName -Remove"
