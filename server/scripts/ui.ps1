# ui.ps1 - window automation for a debuggee driven over MCP.
#
# x64dbg can inspect a process but cannot interact with its UI. Many targets
# require a click or a typed value before they exercise the code you want to
# observe, so this script provides the missing half: capture the window, click
# it, and type into it.
#
# Two click paths exist on purpose:
#   -click        PostMessage(WM_LBUTTONDOWN) - does not move the real cursor,
#                 but many Direct2D/custom-drawn UIs ignore posted input.
#   -realclick    SetCursorPos + SendInput - actually moves the mouse; works on
#                 custom-drawn UIs, which is the common case for protected apps.
#
# Typing uses PostMessage(WM_CHAR), which reaches the focused control without
# stealing focus from whatever the user is doing.

param(
  [Parameter(Mandatory = $true)][long]$Hwnd,
  [ValidateSet('info', 'shot', 'click', 'realclick', 'type', 'key', 'windows')]
  [string]$Action = 'info',
  [int]$X = 0,
  [int]$Y = 0,
  [string]$Text = '',
  [string]$Out = '',
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

Add-Type -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
[DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
[DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
[DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
[DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
[DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll", EntryPoint = "GetWindowThreadProcessId")] public static extern uint GetWindowThreadProcessId(IntPtr h, IntPtr pid);
[DllImport("user32.dll", EntryPoint = "GetWindowThreadProcessId")] public static extern uint GetWindowThreadProcessIdOut(IntPtr h, out uint pid);
[DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool attach);
[DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
[DllImport("user32.dll")] public static extern void mouse_event(uint f, int dx, int dy, uint d, IntPtr e);
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumWindowsProc cb, IntPtr l);
[DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
public struct RECT { public int Left, Top, Right, Bottom; }
public struct POINT { public int X, Y; }
'@ -Name U -Namespace MCPUI

$script:h = [IntPtr]$Hwnd

function Get-ClientOrigin {
  $p = New-Object MCPUI.U+POINT
  [MCPUI.U]::ClientToScreen($script:h, [ref]$p) | Out-Null
  return $p
}

function Focus-Target {
  # Windows refuses SetForegroundWindow from a background process, so a plain
  # call silently does nothing and the subsequent SendInput click lands on
  # whatever window happens to be in front. Minimise+restore forces activation.
  for ($attempt = 0; $attempt -lt 4; $attempt++) {
    if ([MCPUI.U]::GetForegroundWindow() -eq $script:h) { return }

    $fg = [MCPUI.U]::GetForegroundWindow()
    $t1 = [MCPUI.U]::GetWindowThreadProcessId($fg, [IntPtr]::Zero)
    $t2 = [MCPUI.U]::GetWindowThreadProcessId($script:h, [IntPtr]::Zero)
    [MCPUI.U]::AttachThreadInput($t1, $t2, $true) | Out-Null
    $null = [MCPUI.U]::SetForegroundWindow($script:h)
    $null = [MCPUI.U]::BringWindowToTop($script:h)
    # HWND_TOP=0, SWP_NOMOVE|SWP_NOSIZE|SWP_SHOWWINDOW = 0x0001|0x0002|0x0040
    $null = [MCPUI.U]::SetWindowPos($script:h, [IntPtr]::Zero, 0, 0, 0, 0, 0x0043)
    [MCPUI.U]::AttachThreadInput($t1, $t2, $false) | Out-Null

    if ([MCPUI.U]::GetForegroundWindow() -ne $script:h) {
      # Fall back to minimise + restore, which the shell honours.
      $null = [MCPUI.U]::ShowWindow($script:h, 6)   # SW_MINIMIZE
      Start-Sleep -Milliseconds 120
      $null = [MCPUI.U]::ShowWindow($script:h, 9)   # SW_RESTORE
      $null = [MCPUI.U]::SetForegroundWindow($script:h)
    }
    Start-Sleep -Milliseconds 180
    if ([MCPUI.U]::GetForegroundWindow() -eq $script:h) { return }
  }
  Write-Output "warning: could not bring the target window to the foreground"
}

function Invoke-Shot([string]$path) {
  if (-not $path) { throw "-Out is required for -Action shot" }
  $r = New-Object MCPUI.U+RECT
  [MCPUI.U]::GetWindowRect($script:h, [ref]$r) | Out-Null
  $w = $r.Right - $r.Left
  $hh = $r.Bottom - $r.Top
  if ($w -le 0 -or $hh -le 0) { throw "window has no size" }

  $bmp = New-Object System.Drawing.Bitmap $w, $hh
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $hdc = $g.GetHdc()
  # PW_RENDERFULLCONTENT (2) is required for DirectComposition / Direct2D
  # windows, otherwise the bitmap comes back black.
  $ok = [MCPUI.U]::PrintWindow($script:h, $hdc, 2)
  $g.ReleaseHdc($hdc)
  $g.Dispose()
  $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
  $bmp.Dispose()
  Write-Output "shot ok=$ok ${w}x${hh} -> $path"
}

switch ($Action) {
  'info' {
    $wr = New-Object MCPUI.U+RECT; [MCPUI.U]::GetWindowRect($script:h, [ref]$wr) | Out-Null
    $cr = New-Object MCPUI.U+RECT; [MCPUI.U]::GetClientRect($script:h, [ref]$cr) | Out-Null
    $o = Get-ClientOrigin
    Write-Output ("window={0},{1} {2}x{3} client={4}x{5} client_origin={6},{7}" -f `
      $wr.Left, $wr.Top, ($wr.Right - $wr.Left), ($wr.Bottom - $wr.Top), `
      ($cr.Right - $cr.Left), ($cr.Bottom - $cr.Top), $o.X, $o.Y)
  }

  'windows' {
    # Enumerate every top-level window of the process that owns $Hwnd.
    # Results are collected into a list because output written inside an
    # EnumWindows delegate callback does not reach the pipeline.
    [uint32]$procid = 0
    $null = [MCPUI.U]::GetWindowThreadProcessIdOut($script:h, [ref]$procid)
    $global:found = New-Object System.Collections.ArrayList
    $cb = [MCPUI.U+EnumWindowsProc] {
      param($w, $l)
      [uint32]$p = 0
      $null = [MCPUI.U]::GetWindowThreadProcessIdOut($w, [ref]$p)
      if ($p -eq $procid) {
        $t = New-Object System.Text.StringBuilder 256
        $c = New-Object System.Text.StringBuilder 256
        $null = [MCPUI.U]::GetWindowText($w, $t, 256)
        $null = [MCPUI.U]::GetClassName($w, $c, 256)
        if ($t.Length -gt 0) {
          [void]$global:found.Add(("hwnd={0} class='{1}' title='{2}' visible={3}" -f `
            $w.ToInt64(), $c.ToString(), $t.ToString(), [MCPUI.U]::IsWindowVisible($w)))
        }
      }
      return $true
    }
    [MCPUI.U]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
    if ($global:found.Count -eq 0) { Write-Output "no titled windows" }
    else { $global:found | ForEach-Object { Write-Output $_ } }
  }

  'shot' { Invoke-Shot $Out }

  'click' {
    $lp = [IntPtr](($Y -shl 16) -bor ($X -band 0xFFFF))
    $null = [MCPUI.U]::PostMessage($script:h, 0x0200, [IntPtr]1, $lp)
    $null = [MCPUI.U]::PostMessage($script:h, 0x0201, [IntPtr]1, $lp)
    Start-Sleep -Milliseconds 60
    $null = [MCPUI.U]::PostMessage($script:h, 0x0202, [IntPtr]0, $lp)
    Write-Output "posted click at client($X,$Y)"
  }

  'realclick' {
    Focus-Target
    $o = Get-ClientOrigin
    $sx = $o.X + $X
    $sy = $o.Y + $Y
    [MCPUI.U]::SetCursorPos($sx, $sy) | Out-Null
    Start-Sleep -Milliseconds 120
    [MCPUI.U]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 60
    [MCPUI.U]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
    Write-Output "real click at screen($sx,$sy) from client($X,$Y)"
  }

  'type' {
    Focus-Target
    foreach ($ch in $Text.ToCharArray()) {
      $code = [int][char]$ch
      $null = [MCPUI.U]::PostMessage($script:h, 0x0102, [IntPtr]$code, [IntPtr]1)
      Start-Sleep -Milliseconds 20
    }
    Write-Output "typed $($Text.Length) chars"
  }

  'key' {
    Focus-Target
    $vk = [int]$X
    $null = [MCPUI.U]::PostMessage($script:h, 0x0100, [IntPtr]$vk, [IntPtr]1)
    Start-Sleep -Milliseconds 40
    $null = [MCPUI.U]::PostMessage($script:h, 0x0101, [IntPtr]$vk, [IntPtr]0xC0000001)
    Write-Output "key vk=$vk"
  }
}
