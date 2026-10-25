<#
.SYNOPSIS
    Clone an x64dbg install into N independent instances, each on its own MCP port.

.DESCRIPTION
    The MCP plugin reads [MCP] Port from the x64dbg.ini that sits next to
    x64dbg.exe, so two windows cannot share one install directory. This script
    copies the release (minus x32, which x64dbg.exe does not need), gives every
    copy a unique port and the same auth token, and emits the JSON to paste into
    the MCP server's X64DBG_MCP_INSTANCES environment variable.

    Ports are written in HEX because the plugin stores the value through
    BridgeSetting, which parses integers as hexadecimal. Writing decimal is
    silently interpreted as a different port.

.EXAMPLE
    .\provision-instances.ps1 -Count 3 -BasePort 27042 -Dest F:\reverse1\.tools\x64dbg-instances

.EXAMPLE
    # Add one more instance, numbered inst4, without touching the existing ones
    .\provision-instances.ps1 -Count 1 -StartIndex 4 -BasePort 27042
#>
[CmdletBinding()]
param(
    [int]$Count = 2,
    [int]$StartIndex = 1,
    [int]$BasePort = 27042,
    [string]$Source = '',
    [string]$Dest = 'F:\reverse1\.tools\x64dbg-instances',
    [string]$Token = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Find-Source {
    if ($Source) {
        if (-not (Test-Path -LiteralPath $Source)) { throw "Source not found: $Source" }
        return (Resolve-Path -LiteralPath $Source).Path
    }
    $candidates = @(
        @(
            $env:X64DBG_PATH,
            'D:\Program Files\snapshot_2026-05-27_12-11\release',
            'C:\x64dbg\release',
            'D:\x64dbg\release',
            'F:\x64dbg\release'
        ) | Where-Object { $_ -and (Test-Path -LiteralPath (Join-Path $_ 'x64\x64dbg.exe')) }
    )

    if (-not $candidates) {
        throw 'Could not locate an x64dbg release directory. Pass -Source <release folder>.'
    }
    return (Resolve-Path -LiteralPath $candidates[0]).Path
}

function Read-IniLines([string]$Path) {
    return @(Get-Content -LiteralPath $Path -Encoding UTF8)
}

function Set-IniValue {
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [string]$Section,
        [string]$Key,
        [string]$Value
    )
    $sectionStart = -1
    $sectionEnd = $Lines.Count
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^\s*\[(.+?)\]\s*$') {
            if ($sectionStart -ge 0) { $sectionEnd = $i; break }
            if ($Matches[1] -ieq $Section) { $sectionStart = $i }
        }
    }

    if ($sectionStart -lt 0) {
        $Lines.Add("[$Section]")
        $Lines.Add("$Key=$Value")
        return
    }

    for ($i = $sectionStart + 1; $i -lt $sectionEnd; $i++) {
        if ($Lines[$i] -match "^\s*$([regex]::Escape($Key))\s*=") {
            $Lines[$i] = "$Key=$Value"
            return
        }
    }
    $Lines.Insert($sectionStart + 1, "$Key=$Value")
}

$src = Find-Source
$srcIni = Join-Path $src 'x64\x64dbg.ini'
if (-not (Test-Path -LiteralPath $srcIni)) {
    throw "Source has no x64\x64dbg.ini: $srcIni"
}

if (-not $Token) {
    $m = Select-String -LiteralPath $srcIni -Pattern '^\s*AuthToken\s*=\s*(.+)$' | Select-Object -First 1
    if ($m) { $Token = $m.Matches[0].Groups[1].Value.Trim() }
}
if (-not $Token) {
    $Token = [guid]::NewGuid().ToString('N')
    Write-Host "No token in the source ini; generated a new one."
}

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$entries = @()

for ($n = $StartIndex; $n -lt ($StartIndex + $Count); $n++) {
    $id = "inst$n"
    $port = $BasePort + ($n - 1)
    if ($port -gt 65535) { throw "Port $port is out of range; lower -BasePort." }
    $hexPort = [Convert]::ToString($port, 16).ToUpperInvariant()

    $dir = Join-Path $Dest $id
    $exe = Join-Path $dir 'x64\x64dbg.exe'

    if (Test-Path -LiteralPath $exe) {
        if (-not $Force) {
            Write-Host "[$id] exists, reusing $dir (use -Force to recopy)"
        }
    } else {
        Write-Host "[$id] copying $src -> $dir"
        # /XD x32: x64dbg.exe needs only x64/ plus the shared data files.
        $rc = Start-Process robocopy -ArgumentList @(
            "`"$src`"", "`"$dir`"", '/E', '/XD', 'x32',
            '/NFL', '/NDL', '/NJH', '/NJS', '/NP'
        ) -Wait -PassThru -NoNewWindow
        if ($rc.ExitCode -ge 8) { throw "robocopy failed with exit code $($rc.ExitCode)" }
    }

    $ini = Join-Path $dir 'x64\x64dbg.ini'
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($l in (Read-IniLines $ini)) { $lines.Add($l) }

    Set-IniValue -Lines $lines -Section 'MCP' -Key 'Host' -Value '127.0.0.1'
    Set-IniValue -Lines $lines -Section 'MCP' -Key 'Port' -Value $hexPort
    Set-IniValue -Lines $lines -Section 'MCP' -Key 'AuthToken' -Value $Token
    Set-IniValue -Lines $lines -Section 'MCP' -Key 'AutoStart' -Value '1'

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ini, ($lines -join "`r`n") + "`r`n", $utf8)

    Write-Host "[$id] port $port (0x$hexPort)  exe $exe"

    $entries += [ordered]@{
        id         = $id
        host       = '127.0.0.1'
        port       = $port
        token      = $Token
        x64dbgPath = $exe
        label      = "provisioned instance $id"
    }
}

$utf8 = New-Object System.Text.UTF8Encoding($false)

$manifest = Join-Path $Dest 'instances.json'
$json = $entries | ConvertTo-Json -Depth 5
# ConvertTo-Json emits an object instead of an array for a single element.
if ($entries.Count -eq 1) { $json = "[$json]" }
[System.IO.File]::WriteAllText($manifest, $json, $utf8)

# Stable manifest that the MCP server reads on its own when
# X64DBG_MCP_INSTANCES is not set, so provisioning needs no .claude.json edit.
# Merged by id: running with -StartIndex 4 must not drop instances 1..3.
$stableDir = Join-Path $env:USERPROFILE '.x64dbg-mcp'
$stable = Join-Path $stableDir 'instances.json'
$all = @()
if (Test-Path -LiteralPath $stable) {
    try {
        $all = @(Get-Content -LiteralPath $stable -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        Write-Host "warning: existing $stable is not valid JSON; replacing it"
        $all = @()
    }
}
$newIds = @($entries | ForEach-Object { $_.id })
$all = @($all | Where-Object { $_.id -notin $newIds }) + $entries
$allJson = $all | ConvertTo-Json -Depth 5
if (@($all).Count -eq 1) { $allJson = "[$allJson]" }
New-Item -ItemType Directory -Force -Path $stableDir | Out-Null
[System.IO.File]::WriteAllText($stable, $allJson, $utf8)

Write-Host ''
Write-Host "Manifest: $manifest"
Write-Host "Auto-loaded manifest: $stable"
Write-Host 'The MCP server reads that file when X64DBG_MCP_INSTANCES is unset -'
Write-Host 'no .claude.json edit needed. Explicit env vars still take precedence.'
Write-Host ''
Write-Host 'Launch each instance (x64dbg.exe reads the ini next to it):'
foreach ($e in $entries) { Write-Host ("  Start-Process `"{0}`"" -f $e.x64dbgPath) }
