# build-driver.ps1 - compile x64dbg_mcp_hide.sys with the WDK.
#
# This script does NOT pretend to build. If the WDK kernel headers are missing
# it prints exactly what to install and exits with code 2.
#
# Usage:
#   .\build-driver.ps1                 # build x64dbg_mcp_hide.sys
#   .\build-driver.ps1 -Clean          # remove build artefacts first
#   .\build-driver.ps1 -TestSign       # sign with a self-signed cert after build
#   .\build-driver.ps1 -Load           # build, then sc create + sc start
#   .\build-driver.ps1 -Unload         # stop + delete the service
#
# Targets: WDK 10.0.26100 + MSVC v143, x64 only.

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$TestSign,
    [switch]$Load,
    [switch]$Unload
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$SysName = 'x64dbg_mcp_hide.sys'
$ServiceName = 'x64dbg_mcp_hide'

Write-Host "=== x64dbg_mcp_hide build ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 0. Unload-only shortcut
# ---------------------------------------------------------------------------
if ($Unload) {
    if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName")) {
        Write-Host "[unload] service '$ServiceName' is not installed." -ForegroundColor Yellow
        exit 0
    }
    & sc.exe stop $ServiceName | Out-Host
    & sc.exe delete $ServiceName | Out-Host
    Write-Host "[unload] stop/delete issued." -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------------------
# 1. Locate the WDK
#    Kernel headers live at:
#      ${env:ProgramFiles(x86)}\Windows Kits\10\Include\<ver>\km
#    Kernel libs live at:
#      ${env:ProgramFiles(x86)}\Windows Kits\10\Lib\<ver>\km\x64
#    A version is usable only when BOTH exist.
# ---------------------------------------------------------------------------
$KitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$IncludeRoot = Join-Path $KitsRoot 'Include'
$LibRoot = Join-Path $KitsRoot 'Lib'

function Show-WdkInstallInstructions {
    param([string]$Why)

    Write-Host ""
    Write-Host "WDK NOT FOUND - nothing was built." -ForegroundColor Red
    Write-Host "  reason: $Why" -ForegroundColor Red
    Write-Host ""
    Write-Host "Install the Windows Driver Kit, then re-run this script." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Option A - Visual Studio Installer (recommended)" -ForegroundColor White
    Write-Host "    1. Open 'Visual Studio Installer' -> Modify your VS 2022 install."
    Write-Host "    2. Workloads tab: check 'Desktop development with C++'."
    Write-Host "    3. Individual components tab: search 'Windows Driver Kit'"
    Write-Host "       and check 'Windows Driver Kit' (the WDK for the current SDK)."
    Write-Host "    4. Modify, wait for the install, reboot if prompted."
    Write-Host ""
    Write-Host "  Option B - standalone MSI" -ForegroundColor White
    Write-Host "    1. Install the matching Windows SDK first (e.g. 10.0.26100)."
    Write-Host "    2. Download and run 'Windows Driver Kit' (wdksetup.exe) from"
    Write-Host "       https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk"
    Write-Host "    3. Select the 'Windows Driver Kit' feature (not just the SDK)."
    Write-Host ""
    Write-Host "  Verify afterwards, these must both exist:" -ForegroundColor White
    Write-Host "    $IncludeRoot\<ver>\km\ntddk.h"
    Write-Host "    $LibRoot\<ver>\km\x64\ntoskrnl.lib"
    Write-Host ""
    Write-Host "Note: a plain 'Windows SDK' install is NOT enough - the SDK ships the" -ForegroundColor DarkGray
    Write-Host "user-mode headers only. The 'km' directories come from the WDK." -ForegroundColor DarkGray
    Write-Host ""
    exit 2
}

if (-not (Test-Path $IncludeRoot)) {
    Show-WdkInstallInstructions "no Windows Kits\10\Include directory at $IncludeRoot"
}

# Newest version that has km headers AND km x64 libs.
$candidates = @()
foreach ($dir in Get-ChildItem $IncludeRoot -Directory -ErrorAction SilentlyContinue) {
    $kmInclude = Join-Path $dir.FullName 'km'
    $kmLib = Join-Path $LibRoot "$($dir.Name)\km\x64"
    if ((Test-Path $kmInclude) -and (Test-Path $kmLib)) {
        $candidates += [pscustomobject]@{
            Version    = $dir.Name
            KmInclude  = $kmInclude
            KmLib      = $kmLib
            Score      = try { [version]$dir.Name } catch { [version]'0.0.0.0' }
        }
    }
}

if ($candidates.Count -eq 0) {
    $found = (Get-ChildItem $IncludeRoot -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ', '
    Show-WdkInstallInstructions "no SDK version under Include has a complete 'km' tree (found: $found)"
}

$sdk = $candidates | Sort-Object Score -Descending | Select-Object -First 1
$KmInclude = $sdk.KmInclude
$KmLib = $sdk.KmLib

Write-Host "[wdk] version  : $($sdk.Version)" -ForegroundColor DarkGray
Write-Host "[wdk] km include: $KmInclude" -ForegroundColor DarkGray
Write-Host "[wdk] km lib    : $KmLib" -ForegroundColor DarkGray

# The user-mode headers are needed too: wdmsec.h pulls in nothing from um, but
# ntddk.h includes um/winnt.h and friends through the shared tree.
$UmInclude = Join-Path $IncludeRoot "$($sdk.Version)\um"
$SharedInclude = Join-Path $IncludeRoot "$($sdk.Version)\shared"
$UcrtInclude = Join-Path $IncludeRoot "$($sdk.Version)\ucrt"

foreach ($p in @($UmInclude, $SharedInclude, $UcrtInclude)) {
    if (-not (Test-Path $p)) {
        Write-Host "[wdk] warning: expected include dir missing: $p" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. Import the MSVC environment
#    Same vswhere-first discovery the repo's own build.ps1 uses, so a plain
#    PowerShell window works without a developer prompt.
# ---------------------------------------------------------------------------
function Import-MsvcEnvironment {
    $install = $null

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $install = & $vswhere -latest -products * `
                    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                    -property installationPath
    }
    if (-not $install) {
        foreach ($candidate in @(
            "$env:ProgramFiles\Microsoft Visual Studio\18\Community",
            "$env:ProgramFiles\Microsoft Visual Studio\2022\Community",
            "$env:ProgramFiles\Microsoft Visual Studio\2022\Professional",
            "$env:ProgramFiles\Microsoft Visual Studio\2022\Enterprise",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community"
        )) {
            if (Test-Path $candidate) { $install = $candidate; break }
        }
    }
    if (-not $install) {
        throw "Visual Studio with the C++ workload was not found. Install 'Desktop development with C++'."
    }

    $vcvars = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found under $install" }

    # vcvars writes 'set' output we replay into this session.
    $lines = & cmd /c "`"$vcvars`" >nul 2>&1 && set"
    foreach ($line in $lines) {
        if ($line -match '^([^=]+)=(.*)$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] -ErrorAction SilentlyContinue
        }
    }
    Write-Host "[msvc] environment imported from $install" -ForegroundColor DarkGray
}

Import-MsvcEnvironment

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    throw "cl.exe is still not on PATH after importing the MSVC environment."
}

# ---------------------------------------------------------------------------
# 3. Clean
# ---------------------------------------------------------------------------
$OutDir = Join-Path $Root 'build'
if ($Clean -and (Test-Path $OutDir)) {
    Remove-Item $OutDir -Recurse -Force
    Write-Host "[clean] removed $OutDir" -ForegroundColor DarkGray
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# ---------------------------------------------------------------------------
# 4. Compile
#
#    Flags worth explaining:
#      /kernel              tells the compiler this is kernel code (no CRT,
#                           no user-mode intrinsics, correct ABI assumptions)
#      /GS- /Gs9999999      no stack-cookie probing: the kernel has no
#                           __security_cookie initialiser here, and a huge
#                           probe threshold stops the compiler inserting
#                           failed stack probes into a driver with no CRT
#      /D_WIN64 /DAMD64     pick the x64 paths in the DDK headers
#      /D_NT_TARGET_VERSION the WDK headers gate newer APIs on this; without it
#                           some declarations land in a compatibility branch
#      /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry
#                           produce a native driver image, not a console app
#      /INTEGRITYCHECK      only with -TestSign, see below
#
#    /INTEGRITYCHECK forces a PE checksum + IMAGE_DLLCHARACTERISTICS_FORCE_
#    INTEGRITY, which is what HVCI and CI check. A test-signed driver does NOT
#    need it, and adding it to an unsigned/test-signed binary makes CI reject
#    the image in some configurations, so it is opt-in and tied to -TestSign
#    rather than always on.
# ---------------------------------------------------------------------------
$TargetVersion = '0x0A000000'
# NT_TARGET_VERSION for Windows 11: the headers define the numeric form; using
# the symbolic ABI constant avoids pinning to one SDK servicing branch.
$NTargetDefine = '/D_NT_TARGET_VERSION=0x0A00000A'

$clArgs = @(
    '/nologo'
    '/c'
    '/kernel'
    '/GS-'
    '/Gs9999999'
    '/W4'
    '/O2'
    '/Zi'
    '/Zc:wchar_t-'
    '/Zc:forScope'
    '/D_WIN64'
    '/DAMD64'
    '/DWIN32=100'
    '/D_UNICODE'
    '/DUNICODE'
    $NTargetDefine
    '/I' + $KmInclude
    '/I' + $UmInclude
    '/I' + $SharedInclude
    '/I' + $UcrtInclude
    '/I' + $Root
    '/Fo' + (Join-Path $OutDir 'x64dbg_mcp_hide.obj')
    '/Fd' + (Join-Path $OutDir 'x64dbg_mcp_hide.pdb')
    (Join-Path $Root 'x64dbg_mcp_hide.c')
)

if ($TestSign) {
    $clArgs += '/INTEGRITYCHECK'
}

$SysPath = Join-Path $OutDir $SysName

$linkArgs = @(
    '/nologo'
    '/DRIVER'
    '/SUBSYSTEM:NATIVE'
    '/ENTRY:DriverEntry'
    '/MACHINE:X64'
    '/OUT:' + $SysPath
    '/DEBUG'
    '/OPT:REF'
    '/OPT:ICF'
    '/LIBPATH:' + $KmLib
    'ntoskrnl.lib'
    'hal.lib'
    'wdm.lib'
    'BufferOverflowK.lib'
    'ntstrsafe.lib'
    'wdmsec.lib'
)

Write-Host "[cl] compiling x64dbg_mcp_hide.c" -ForegroundColor DarkGray
& cl.exe @clArgs
if ($LASTEXITCODE -ne 0) {
    throw "compile failed (cl exit $LASTEXITCODE)"
}

Write-Host "[link] linking $SysName" -ForegroundColor DarkGray
& link.exe @linkArgs (Join-Path $OutDir 'x64dbg_mcp_hide.obj')
if ($LASTEXITCODE -ne 0) {
    throw "link failed (link exit $LASTEXITCODE)"
}

if (-not (Test-Path $SysPath)) {
    throw "link reported success but $SysPath does not exist"
}

$info = Get-Item $SysPath
Write-Host ""
Write-Host "Built: $($info.FullName)" -ForegroundColor Green
Write-Host "Size : $([math]::Round($info.Length / 1KB, 1)) KB" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Optional test signing
# ---------------------------------------------------------------------------
if ($TestSign) {
    Write-Host ""
    Write-Host "=== test signing ===" -ForegroundColor Cyan

    # testsigning must be ON or the loader refuses the image outright.
    $ts = & bcdedit.exe /enum '{current}' 2>$null | Select-String -Pattern 'testsigning\s+(\S+)'
    if ($ts -and $ts -match 'testsigning\s+Yes') {
        Write-Host "[sign] test signing is already ON" -ForegroundColor DarkGray
    } else {
        Write-Host "[sign] enabling test signing (requires reboot, admin)" -ForegroundColor Yellow
        Write-Host "       bcdedit /set testsigning on" -ForegroundColor DarkGray
        try {
            & bcdedit.exe /set testsigning on | Out-Host
        } catch {
            Write-Host "[sign] could not enable test signing automatically; run as admin:" -ForegroundColor Yellow
            Write-Host "       bcdedit /set testsigning on" -ForegroundColor Yellow
        }
        Write-Host "[sign] A REBOOT IS REQUIRED before the driver will load." -ForegroundColor Yellow
    }

    $certSubject = 'CN=x64dbg-mcp-hide-test'
    $cert = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Subject -eq $certSubject } |
            Select-Object -First 1

    if (-not $cert) {
        Write-Host "[sign] creating self-signed cert $certSubject" -ForegroundColor DarkGray
        $cert = New-SelfSignedCertificate `
                    -Type CodeSigningCert `
                    -Subject $certSubject `
                    -CertStoreLocation 'Cert:\LocalMachine\My' `
                    -NotAfter (Get-Date).AddYears(3)
        Write-Host "[sign] exporting + trusting the cert (needed for the loader)" -ForegroundColor DarkGray
        $cerPath = Join-Path $OutDir 'x64dbg-mcp-hide-test.cer'
        Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
        Import-Certificate -FilePath $cerPath `
            -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
        Import-Certificate -FilePath $cerPath `
            -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
    }

    Write-Host "[sign] signtool sign /fd SHA256 /s My /n `"$certSubject`"" -ForegroundColor DarkGray
    & signtool.exe sign /fd SHA256 /s My /n $certSubject $SysPath
    if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }

    & signtool.exe verify /v /pa $SysPath | Out-Host
}

# ---------------------------------------------------------------------------
# 6. Load / unload instructions
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== load ===" -ForegroundColor Cyan
Write-Host "Run these in an ELEVATED prompt. '$ServiceName' must not already exist." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  sc.exe create $ServiceName type= kernel binPath= `"$SysPath`"" -ForegroundColor White
Write-Host "  sc.exe start  $ServiceName" -ForegroundColor White
Write-Host ""

if ($Load) {
    Write-Host "[load] creating and starting the service" -ForegroundColor Yellow
    & sc.exe create $ServiceName type= kernel binPath= "$SysPath" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[load] sc create failed ($LASTEXITCODE) - already installed?" -ForegroundColor Red
    } else {
        & sc.exe start $ServiceName | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[load] sc start failed ($LASTEXITCODE)" -ForegroundColor Red
            Write-Host "[load] usual causes: driver not signed, test signing off," -ForegroundColor Yellow
            Write-Host "       or HVCI/memory integrity enabled (see README)." -ForegroundColor Yellow
        } else {
            Write-Host "[load] started. Check DbgView for '[$([char]0x78)64mcp-hide] loaded'." -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "=== verify / remove ===" -ForegroundColor Cyan
Write-Host "  sc.exe query $ServiceName" -ForegroundColor White
Write-Host "  sc.exe stop   $ServiceName" -ForegroundColor White
Write-Host "  sc.exe delete $ServiceName" -ForegroundColor White
Write-Host ""
Write-Host "  .\build-driver.ps1 -Unload     # does stop + delete for you" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Test signing reminder: if you enabled it, the machine needs a reboot" -ForegroundColor Yellow
Write-Host "before the driver will load, and a permanently enabled test signing" -ForegroundColor Yellow
Write-Host "mode puts a watermark on the desktop. Turn it off with:" -ForegroundColor Yellow
Write-Host "  bcdedit /set testsigning off" -ForegroundColor DarkGray
