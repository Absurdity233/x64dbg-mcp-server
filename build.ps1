# build.ps1 - One-shot build for the x64dbg MCP plugin (+ optional server).
#
# Ensures the plugin SDK is present (fetch-sdk.ps1), then configures and builds
# the plugin with CMake/Ninja/MSVC. Pass -Server to also build the TypeScript
# server, -Install to copy the built plugins into your x64dbg.
#
# Usage:
#   .\build.ps1                       # build both x64 + x32 plugins
#   .\build.ps1 -Arch x64             # x64 only
#   .\build.ps1 -Server               # also build the TS server
#   .\build.ps1 -Install              # build, then install into x64dbg
#   .\build.ps1 -ForceSdk             # re-download the SDK even if up to date

[CmdletBinding()]
param(
    [ValidateSet('x64', 'x32', 'both')] [string]$Arch = 'both',
    [switch]$Server,
    [switch]$Install,
    [switch]$ForceSdk
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

# Import the MSVC environment into this process. Without this, `cl` is not on
# PATH and CMake cannot find a compiler - a plain PowerShell window is not a
# developer prompt.
function Import-MsvcEnvironment {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }
    if (-not $install) {
        foreach ($candidate in @(
            "$env:ProgramFiles\Microsoft Visual Studio\18\Community",
            "$env:ProgramFiles\Microsoft Visual Studio\2022\Community",
            "$env:ProgramFiles\Microsoft Visual Studio\2022\Professional"
        )) {
            if (Test-Path $candidate) { $install = $candidate; break }
        }
    }
    if (-not $install) { throw "Visual Studio with the C++ workload was not found. Install 'Desktop development with C++'." }

    $vcvars = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found under $install" }

    # vcvars writes 'set' output we can replay into this session.
    $lines = & cmd /c "`"$vcvars`" >nul 2>&1 && set"
    foreach ($line in $lines) {
        if ($line -match '^([^=]+)=(.*)$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] -ErrorAction SilentlyContinue
        }
    }
    Write-Host "[build] MSVC environment imported from $install" -ForegroundColor DarkGray
}

Import-MsvcEnvironment

# 1. SDK (headers + import libs) - offline-tolerant once cached.
& "$Root\plugin\fetch-sdk.ps1" -Force:$ForceSdk

# 2. Plugin(s).
Push-Location "$Root\plugin"
try {
    if ($Arch -in 'x64', 'both') {
        cmake --preset x64-release
        if ($LASTEXITCODE) { throw "x64 configure failed ($LASTEXITCODE)" }
        cmake --build --preset x64-release
        if ($LASTEXITCODE) { throw "x64 plugin build failed ($LASTEXITCODE)" }
    }
    if ($Arch -in 'x32', 'both') {
        # x32 needs the 32-bit compiler, which lives in a different bin dir than
        # the x64 one vcvars64 put on PATH. Re-run configure+build inside a
        # vcvars32 environment so `cl` resolves to the x86 host tool.
        $vcvars32 = Join-Path $env:VCToolsInstallDir '..\..\..\Auxiliary\Build\vcvars32.bat'
        $vcvars32 = [IO.Path]::GetFullPath($vcvars32)
        if (-not (Test-Path $vcvars32)) { throw "vcvars32.bat not found at $vcvars32" }

        $pluginDir = (Get-Location).Path
        & cmd /c "`"$vcvars32`" >nul 2>&1 && cd /d `"$pluginDir`" && cmake --preset x32-release && cmake --build --preset x32-release"
        if ($LASTEXITCODE) { throw "x32 plugin build failed ($LASTEXITCODE)" }
    }
} finally { Pop-Location }

# 3. Server (optional).
if ($Server) {
    Push-Location "$Root\server"
    try {
        if (-not (Test-Path node_modules)) { npm install }
        npm run build
        if ($LASTEXITCODE) { throw "server build failed ($LASTEXITCODE)" }
    } finally { Pop-Location }
}

# 4. Install (optional).
if ($Install) { & "$Root\install.ps1" -Arch $Arch }

Write-Host "`nBuild complete." -ForegroundColor Cyan
