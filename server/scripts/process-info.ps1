# process-info.ps1 - list x64dbg processes with the two facts the launcher needs.
#
# Get-CimInstance Win32_Process cannot read ExecutablePath of an elevated
# process from a non-elevated caller (it comes back empty), so the old launcher
# concluded "x64dbg is not running" and started a second window. QueryFullProcess-
# ImageName with PROCESS_QUERY_LIMITED_INFORMATION works across integrity levels.
#
# Output, one process per line: <pid>|<exe path>|<true|false|unknown>
# `elevated` is the token's TokenElevation, i.e. whether UAC/UIPI treats this
# process as high integrity.

param(
  [string]$Name = 'x64dbg',
  [int]$TargetPid = 0
)

$ErrorActionPreference = 'Stop'

Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool QueryFullProcessImageName(IntPtr h, int flags, System.Text.StringBuilder sb, ref int size);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
[DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(IntPtr p, int access, out IntPtr token);
[DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetTokenInformation(IntPtr token, int cls, out int info, int len, out int ret);
'@ -Name Native -Namespace MCPProc

function Get-ProcInfo([int]$ProcessId) {
  # PROCESS_QUERY_LIMITED_INFORMATION works on elevated processes from a
  # medium-integrity caller; PROCESS_QUERY_INFORMATION does not.
  $h = [MCPProc.Native]::OpenProcess(0x1000, $false, $ProcessId)
  if ($h -eq [IntPtr]::Zero) { return $null }

  try {
    $sb = New-Object System.Text.StringBuilder 2048
    $size = 2048
    $path = ''
    if ([MCPProc.Native]::QueryFullProcessImageName($h, 0, $sb, [ref]$size)) {
      $path = $sb.ToString()
    }

    $elevated = 'unknown'
    $token = [IntPtr]::Zero
    if ([MCPProc.Native]::OpenProcessToken($h, 0x8, [ref]$token)) {
      try {
        $value = 0
        $returned = 0
        # TokenElevation = 20; one DWORD: nonzero means elevated.
        if ([MCPProc.Native]::GetTokenInformation($token, 20, [ref]$value, 4, [ref]$returned)) {
          if ($value -eq 1) { $elevated = 'true' } else { $elevated = 'false' }
        }
      } finally {
        [void][MCPProc.Native]::CloseHandle($token)
      }
    }

    return [pscustomobject]@{ pid = $ProcessId; path = $path; elevated = $elevated }
  } finally {
    [void][MCPProc.Native]::CloseHandle($h)
  }
}

if ($TargetPid -gt 0) {
  $p = Get-ProcInfo $TargetPid
  if ($p) { Write-Output ("{0}|{1}|{2}" -f $p.pid, $p.path, $p.elevated) }
  exit 0
}

Get-Process -Name $Name -ErrorAction SilentlyContinue | ForEach-Object {
  $p = Get-ProcInfo $_.Id
  if ($p -and $p.path) { Write-Output ("{0}|{1}|{2}" -f $p.pid, $p.path, $p.elevated) }
}
