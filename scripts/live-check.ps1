# live-check.ps1 - drive one x64dbg session and report the facts, no quoting games.
#
#   .\live-check.ps1 -Target <exe> [-Report <txt>] [-Arms cpuid,rdtsc] [-HookNtdll] [-Harden]
#
# Prints, in order: hook install result, dispatcher bytes as the target will see
# them, then the target's own verdict file.

param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$Report,
    [string]$Arms = 'cpuid,rdtsc',
    [switch]$HookNtdll,
    [switch]$Harden,
    [switch]$KeepRunning,
    [switch]$Inspect
)

$ErrorActionPreference = 'Continue'
$port  = 27042
$token = 'e317318976298f9c154e1a961c1552c1'
$h     = @{ 'Authorization' = "Bearer $token" }
$x64dbg = 'D:\Program Files\snapshot_2026-05-27_12-11\release\x64\x64dbg.exe'

function Api {
    param([string]$Path, $Body, [string]$Method = 'Get')
    try {
        if ($null -ne $Body) {
            return (Invoke-RestMethod -Uri "http://127.0.0.1:$port$Path" -Method $Method `
                    -Body ($Body | ConvertTo-Json -Depth 8) -ContentType 'application/json' `
                    -Headers $h -TimeoutSec 40)
        }
        return (Invoke-RestMethod -Uri "http://127.0.0.1:$port$Path" -Method $Method `
                -Headers $h -TimeoutSec 40)
    } catch {
        return $null
    }
}

function Wait-Server {
    for ($i = 0; $i -lt 40; $i++) {
        $r = Api '/api/health'
        if ($r) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# --- fresh session ----------------------------------------------------------
Get-Process x64dbg -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
if ($Report) {
    Remove-Item $Report -ErrorAction SilentlyContinue
    $env:ADTEST_REPORT = $Report
}

Start-Process -FilePath $x64dbg -ArgumentList "`"$Target`"" -WorkingDirectory (Split-Path $x64dbg)
if (-not (Wait-Server)) { Write-Host "SERVER DID NOT START"; exit 1 }

# Wait for the initial breakpoint. A target that reaches its own code before the
# debugger settles would either be gone (nothing to hook) or already have called
# the function we are about to hook, so this gate is not cosmetic: it is what
# makes the install happen before the first call.
for ($i = 0; $i -lt 40; $i++) {
    $st = (Api '/api/debug/state').data
    if ($st -and $st.state -eq 'paused') { break }
    Start-Sleep -Milliseconds 500
}
$st = (Api '/api/debug/state').data
Write-Host "state=$($st.state) cip=$($st.cip)"

# --- optional protections ---------------------------------------------------
if ($Arms) {
    $armList = $Arms -split ','
    $av = Api '/api/antidebug/anti_vm' @{ module = ''; arms = $armList; max_hits = 100 } 'Post'
    if ($av) {
        Write-Host "anti_vm armed=$($av.data.count) skipped=$($av.data.skipped.Count)"
        foreach ($s in $av.data.skipped) { Write-Host "  skip: $($s.probe) $($s.reason)" }
    }
}

if ($HookNtdll) {
    $hk = Api '/api/antidebug/hook_ntdll' @{ functions = @('NtQueryInformationProcess') } 'Post'
    if ($hk) {
        Write-Host "ntdll ok=$($hk.data.ok)"
        if ($hk.data.hooked) {
            $disp = $hk.data.hooked[0].dispatcher
            Write-Host "ntdll layout=$($hk.data.hooked[0].layout) dispatcher=$disp"
            # Print the bytes the CPU will actually execute. This is the single
            # most useful fact: a hook that installs but cannot dispatch shows up
            # here as a wrong comparison or a wrong store target.
            $d = Api "/api/disasm/at?address=$disp&count=18"
            if ($d) { $d.data.instructions | ForEach-Object { Write-Host "   $($_.address)  $($_.instruction)" } }
        }
        foreach ($s in $hk.data.skipped) { Write-Host "  skip: $($s.function) $($s.reason)" }
    }
}

if ($Harden) {
    $hd = Api '/api/antidebug/harden' @{ level = 'deep'; threads = $true } 'Post'
    if ($hd) { Write-Host "harden ok=$($hd.data.ok) failed=$($hd.data.failed.Count)" }
}

# --- optionally stop before running ----------------------------------------
if ($Inspect) {
    Write-Host "`n=== armed sites (target still paused) ==="
    $av = Api '/api/antidebug/anti_vm/list'
    if ($av) {
        foreach ($s in $av.data.stubs) {
            $site = Api "/api/memory/read?address=$($s.address)&size=8"
            $body = Api "/api/memory/read?address=$($s.stub)&size=24"
            $pr   = Api "/api/memmap/at?address=$($s.address)"
            Write-Host ("  {0,-8} site={1} stub={2}" -f $s.probe, $s.address, $s.stub)
            Write-Host ("     site bytes: {0}" -f ($(if ($site) { $site.data.hex } else { '<unreadable>' })))
            Write-Host ("     stub bytes: {0}" -f ($(if ($body) { $body.data.hex } else { '<unreadable>' })))
            if ($pr) { Write-Host ("     protect   : {0}" -f $pr.data.protect) }
        }
    }
    Write-Host "`n(inspect only, target not run)"
    return
}

# --- run the target ---------------------------------------------------------
for ($i = 0; $i -lt 12; $i++) {
    Api '/api/debug/run' @{} 'Post' | Out-Null
    Start-Sleep -Milliseconds 900
    if ($Report -and (Test-Path $Report)) { break }
    $s = (Api '/api/debug/state').data
    if ($s -and $s.state -eq 'stopped') { break }
}

if ($Report) {
    Write-Host "`n=== target verdict ==="
    if (Test-Path $Report) { Get-Content $Report } else { Write-Host "(no report written)" }
}
if (-not $KeepRunning) { Write-Host "`n(dbg left as-is)" }
