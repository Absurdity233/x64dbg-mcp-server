<#
.SYNOPSIS
    Clone a target folder so two debuggers can run the same binary without
    sharing its Config/ Logs/ save files.

.DESCRIPTION
    Most Windows programs resolve their data directory from the module path, not
    the working directory, so a second instance of the same exe writes to the
    same Config/ and Logs/ as the first. For before/after comparisons (patch
    applied vs not, licence accepted vs rejected) that corrupts both runs.

    Copying the folder gives each run its own private copy. The copy is
    byte-identical, so self-integrity checks still pass.

    -HardLinkBig replaces files >= 16 MB with hard links to save space. Only use
    it for files the target never writes to - a self-patching binary or a
    config file must be a real copy. Requires source and destination on the
    same volume.

.EXAMPLE
    .\provision-target.ps1 -Source "C:\Users\Absurdity\Desktop\逆向靶场\crackme" -Name xxoo-a
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Dest = 'F:\reverse1\.tools\targets',
    [switch]$HardLinkBig,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Source)) { throw "Source not found: $Source" }
$src = (Resolve-Path -LiteralPath $Source).Path
$dst = Join-Path $Dest $Name

if (Test-Path -LiteralPath $dst) {
    if (-not $Force) { throw "$dst already exists (use -Force to overwrite)" }
    Remove-Item -LiteralPath $dst -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $dst | Out-Null

if ($HardLinkBig) {
    $srcRoot = (Resolve-Path -LiteralPath $src).Path
    $dstRoot = (Resolve-Path -LiteralPath $dst).Path
    if ((Split-Path $srcRoot -Qualifier) -ne (Split-Path $dstRoot -Qualifier)) {
        throw '-HardLinkBig needs source and destination on the same volume'
    }
    $copied = 0; $linked = 0
    Get-ChildItem -LiteralPath $src -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($srcRoot.Length).TrimStart('\')
        $target = Join-Path $dstRoot $rel
        $dir = Split-Path $target -Parent
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        if ($_.Length -ge 16MB) {
            New-Item -ItemType HardLink -Path $target -Target $_.FullName | Out-Null
            $linked++
        } else {
            Copy-Item -LiteralPath $_.FullName -Destination $target -Force
            $copied++
        }
    }
    Write-Host "linked $linked large file(s), copied $copied file(s)"
} else {
    $rc = Start-Process robocopy -ArgumentList @(
        "`"$src`"", "`"$dst`"", '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NP'
    ) -Wait -PassThru -NoNewWindow
    if ($rc.ExitCode -ge 8) { throw "robocopy failed with exit code $($rc.ExitCode)" }
}

$exe = Get-ChildItem -LiteralPath $dst -Filter *.exe -File |
    Sort-Object Length -Descending | Select-Object -First 1

$manifest = Join-Path $Dest 'targets.json'
$entries = @()
if (Test-Path -LiteralPath $manifest) {
    $entries = @(Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json)
}
$entries = @($entries | Where-Object { $_.name -ne $Name })
$entries += [ordered]@{
    name        = $Name
    source      = $src
    clone       = $dst
    exe         = if ($exe) { $exe.FullName } else { $null }
    sha256      = if ($exe) { (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash } else { $null }
    hardLinked  = [bool]$HardLinkBig
}
$json = $entries | ConvertTo-Json -Depth 5
if ($entries.Count -eq 1) { $json = "[$json]" }
[System.IO.File]::WriteAllText($manifest, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ''
Write-Host "Clone: $dst"
if ($exe) { Write-Host "Exe:   $($exe.FullName)" }
Write-Host "Manifest: $manifest"
Write-Host ''
Write-Host 'Load it in the instance you want:'
if ($exe) { Write-Host ("  x64dbg_debug {{ action: `"load`", path: `"{0}`", instance: `"beta`" }}" -f $exe.FullName) }
