# ui.ps1 - window automation + OCR for a debuggee driven over MCP.
#
# x64dbg can inspect a process but cannot touch its UI. Many targets require a
# click or a typed value before they exercise the code you want to observe, so
# this script supplies the missing half.
#
# Coordinates: -X/-Y are CLIENT coordinates. OCR results are in IMAGE
# coordinates, which include the non-client area; every OCR-derived coordinate
# is converted back to client space before it is reported or clicked.
#
# OCR uses the built-in Windows.Media.Ocr engine, so there is no extra
# dependency and no network access.

param(
  [Parameter(Mandatory = $true)][long]$Hwnd,
  [ValidateSet('info', 'shot', 'ocr', 'findtext', 'clicktext', 'typeinto',
               'click', 'realclick', 'type', 'key', 'windows', 'findwindow', 'serve')]
  [string]$Action = 'info',
  [int]$X = 0,
  [int]$Y = 0,
  [string]$Text = '',
  [string]$Match = '',
  [string]$Out = '',
  [int]$Scale = 300,
  [string]$Lang = '',
  [switch]$Enhance,
  [switch]$Regex,
  [switch]$All,
  [int]$WaitStable = 0,
  [string]$Region = '',
  [int]$StableTimeout = 8000,
  [int]$TargetPid = 0
)

$ErrorActionPreference = 'Stop'
# The MCP transport is UTF-8; without this every non-ASCII glyph OCR returns
# would be mangled by the console code page.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Runtime.WindowsRuntime

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
[DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
[DllImport("user32.dll", SetLastError = true)] public static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, IntPtr w, IntPtr l, uint flags, uint timeout, out IntPtr result);
public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
public struct RECT { public int Left, Top, Right, Bottom; }
public struct POINT { public int X, Y; }
'@ -Name U -Namespace MCPUI

$script:h = [IntPtr]$Hwnd

# ---------------------------------------------------------------------------
# WinRT await helper (PowerShell has no native await for IAsyncOperation)
# ---------------------------------------------------------------------------
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
  $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Await($winRtTask, $resultType) {
  $asTask = $asTaskGeneric.MakeGenericMethod($resultType)
  $netTask = $asTask.Invoke($null, @($winRtTask))
  $netTask.Wait(-1) | Out-Null
  $netTask.Result
}

[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.StorageFile, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Globalization.Language, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null

function New-OcrEngine {
  # Explicit language wins; otherwise try the user profile, then fall back to
  # Chinese since most targets here are localised. Windows OCR only reports
  # what its installed models support.
  if ($Lang) {
    $l = New-Object Windows.Globalization.Language($Lang)
    $e = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($l)
    if ($e) { return $e }
  }
  $e = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
  if ($e) { return $e }
  foreach ($tag in @('zh-Hans-CN', 'en-US')) {
    $l = New-Object Windows.Globalization.Language($tag)
    $e = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($l)
    if ($e) { return $e }
  }
  throw "no OCR engine available"
}

function Get-ClientOrigin {
  $p = New-Object MCPUI.U+POINT
  [MCPUI.U]::ClientToScreen($script:h, [ref]$p) | Out-Null
  return $p
}

function Get-ImageOffset {
  # Offset of the client area inside the PrintWindow image.
  $wr = New-Object MCPUI.U+RECT
  [MCPUI.U]::GetWindowRect($script:h, [ref]$wr) | Out-Null
  $o = Get-ClientOrigin
  return @{ X = $o.X - $wr.Left; Y = $o.Y - $wr.Top }
}

function Test-TargetHung {
  # A debuggee paused at a breakpoint cannot pump its message loop, so every
  # foreground/activation call that waits on it blocks until the timeout.
  # SendMessageTimeout with SMTO_ABORTIFHUNG is the standard probe.
  $result = [IntPtr]::Zero
  $ok = [MCPUI.U]::SendMessageTimeout($script:h, 0x0000 <# WM_NULL #>, [IntPtr]::Zero, [IntPtr]::Zero,
                                     0x0002 <# SMTO_ABORTIFHUNG #>, 600, [ref]$result)
  return ($ok -eq [IntPtr]::Zero)
}

function Focus-Target {
  # Windows refuses SetForegroundWindow from a background process, so a plain
  # call silently does nothing and the following SendInput click lands on
  # whatever window happens to be in front.
  if (Test-TargetHung) {
    Write-Output "warning: target is not responding (paused in the debugger?) - skipping focus change"
    return $false
  }

  for ($attempt = 0; $attempt -lt 3; $attempt++) {
    if ([MCPUI.U]::GetForegroundWindow() -eq $script:h) { return $true }

    $fg = [MCPUI.U]::GetForegroundWindow()
    $t1 = [MCPUI.U]::GetWindowThreadProcessId($fg, [IntPtr]::Zero)
    $t2 = [MCPUI.U]::GetWindowThreadProcessId($script:h, [IntPtr]::Zero)
    [MCPUI.U]::AttachThreadInput($t1, $t2, $true) | Out-Null
    $null = [MCPUI.U]::SetForegroundWindow($script:h)
    $null = [MCPUI.U]::BringWindowToTop($script:h)
    $null = [MCPUI.U]::SetWindowPos($script:h, [IntPtr]::Zero, 0, 0, 0, 0, 0x0043)
    [MCPUI.U]::AttachThreadInput($t1, $t2, $false) | Out-Null

    if ([MCPUI.U]::GetForegroundWindow() -ne $script:h) {
      $null = [MCPUI.U]::ShowWindow($script:h, 6)   # SW_MINIMIZE
      Start-Sleep -Milliseconds 120
      $null = [MCPUI.U]::ShowWindow($script:h, 9)   # SW_RESTORE
      $null = [MCPUI.U]::SetForegroundWindow($script:h)
    }
    Start-Sleep -Milliseconds 150
    if ([MCPUI.U]::GetForegroundWindow() -eq $script:h) { return $true }
  }
  Write-Output "warning: could not bring the target window to the foreground"
  return $false
}

function Scale-Bitmap($bmp, [double]$factor) {
  # Windows OCR misses small glyphs; upscaling with high-quality interpolation
  # raises recognition accuracy a lot, at the cost of a coordinate divide.
  if ($factor -le 1.0) { return $bmp }
  $w = [int]($bmp.Width * $factor)
  $h = [int]($bmp.Height * $factor)
  $scaled = New-Object System.Drawing.Bitmap $w, $h
  $g = [System.Drawing.Graphics]::FromImage($scaled)
  $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
  $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
  $g.DrawImage($bmp, 0, 0, $w, $h)
  $g.Dispose()
  return $scaled
}

function Enhance-ForOcr($bmp) {
  # The targets here use dark themes with dim text; Windows OCR is tuned for
  # document scans. A contrast stretch + greyscale gives it something usable
  # without changing the geometry (so coordinates stay valid).
  $out = New-Object System.Drawing.Bitmap $bmp.Width, $bmp.Height
  $g = [System.Drawing.Graphics]::FromImage($out)
  $ia = New-Object System.Drawing.Imaging.ImageAttributes
  # Luminance-to-alpha-free greyscale, then a strong contrast curve.
  $cm = New-Object System.Drawing.Imaging.ColorMatrix
  $cm.Matrix00 = 0.9; $cm.Matrix01 = 0.9; $cm.Matrix02 = 0.9
  $cm.Matrix10 = 0.9; $cm.Matrix11 = 0.9; $cm.Matrix12 = 0.9
  $cm.Matrix20 = 0.9; $cm.Matrix21 = 0.9; $cm.Matrix22 = 0.9
  $cm.Matrix33 = 1.0
  $cm.Matrix40 = -0.35; $cm.Matrix41 = -0.35; $cm.Matrix42 = -0.35
  $ia.SetColorMatrix($cm)
  $rect = New-Object System.Drawing.Rectangle 0, 0, $bmp.Width, $bmp.Height
  $g.DrawImage($bmp, $rect, 0, 0, $bmp.Width, $bmp.Height, [System.Drawing.GraphicsUnit]::Pixel, $ia)
  $g.Dispose()
  $ia.Dispose()
  return $out
}

function Capture-Bitmap {
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
  return @{ Bitmap = $bmp; Ok = $ok; Width = $w; Height = $hh }
}

function Save-Bitmap($bmp, [string]$path) {
  $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
}

function Get-BitmapHash($bmp) {
  # Cheap perceptual fingerprint: sample a grid of pixels and hash the values.
  # Full byte comparison is unnecessary and slow for large windows.
  $sb = New-Object System.Text.StringBuilder
  $stepX = [Math]::Max(1, [int]($bmp.Width / 40))
  $stepY = [Math]::Max(1, [int]($bmp.Height / 40))
  for ($y = 0; $y -lt $bmp.Height; $y += $stepY) {
    for ($x = 0; $x -lt $bmp.Width; $x += $stepX) {
      [void]$sb.Append($bmp.GetPixel($x, $y).ToArgb())
    }
  }
  return $sb.ToString().GetHashCode()
}

function Wait-StableFrame {
  # A window that is mid-animation (spinner, fade, layout) yields screenshots
  # that differ frame to frame, and OCR on one of them reports half the UI.
  # Poll until two consecutive captures match, or give up.
  $deadline = (Get-Date).AddMilliseconds($StableTimeout)
  $prev = $null
  while ((Get-Date) -lt $deadline) {
    $cap = Capture-Bitmap
    $hash = Get-BitmapHash $cap.Bitmap
    $cap.Bitmap.Dispose()
    if ($null -ne $prev -and $hash -eq $prev) { return $true }
    $prev = $hash
    Start-Sleep -Milliseconds $WaitStable
  }
  return $false
}

function Invoke-Shot([string]$path) {
  if (-not $path) { throw "-Out is required for -Action shot" }
  $cap = Capture-Bitmap
  Save-Bitmap $cap.Bitmap $path
  $cap.Bitmap.Dispose()
  Write-Output "shot ok=$($cap.Ok) $($cap.Width)x$($cap.Height) -> $path"
}

# ---------------------------------------------------------------------------
# OCR
# ---------------------------------------------------------------------------

function Crop-Bitmap($bmp, [int]$cx, [int]$cy, [int]$cw, [int]$ch) {
  $off = Get-ImageOffset
  $x = [Math]::Max(0, [Math]::Min($bmp.Width - 1, $cx + $off.X))
  $y = [Math]::Max(0, [Math]::Min($bmp.Height - 1, $cy + $off.Y))
  $w = [Math]::Min($cw, $bmp.Width - $x)
  $h = [Math]::Min($ch, $bmp.Height - $y)
  if ($w -le 0 -or $h -le 0) { throw "crop region is empty" }
  $rect = New-Object System.Drawing.Rectangle $x, $y, $w, $h
  return $bmp.Clone($rect, $bmp.PixelFormat)
}

function Invoke-Ocr {
  # Returns @{ Text; Words } where each word carries its center in CLIENT coords.
  if ($WaitStable -gt 0) { $null = Wait-StableFrame }
  $cap = Capture-Bitmap
  $base = $cap.Bitmap
  $regionOffset = @{ X = 0; Y = 0 }
  if ($Region) {
    $parts = $Region -split ','
    if ($parts.Count -ne 4) { throw "-Region must be 'x,y,w,h'" }
    $rx = [int]$parts[0]; $ry = [int]$parts[1]; $rw = [int]$parts[2]; $rh = [int]$parts[3]
    $cropped = Crop-Bitmap $base $rx $ry $rw $rh
    $regionOffset = @{ X = $rx; Y = $ry }
    $base = $cropped
  }
  $enhanced = if ($Enhance) { Enhance-ForOcr $base } else { $base }
  $factor = [Math]::Max(1.0, $Scale / 100.0)
  $scaled = Scale-Bitmap $enhanced $factor
  try {
    $tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), "mcp-ocr-$PID-$([guid]::NewGuid().ToString('N')).png")
    Save-Bitmap $scaled $tmp

    try {
      $file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($tmp)) ([Windows.Storage.StorageFile])
      $stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
      $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
      $soft = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])

      $engine = New-OcrEngine
      $result = Await ($engine.RecognizeAsync($soft)) ([Windows.Media.Ocr.OcrResult])

      $stream.Dispose()
    } finally {
      Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }

    $off = Get-ImageOffset
    $words = New-Object System.Collections.ArrayList
    $lines = New-Object System.Collections.ArrayList

    foreach ($line in $result.Lines) {
      [void]$lines.Add($line.Text)
      foreach ($w in $line.Words) {
        $b = $w.BoundingRect
        # OCR ran on the upscaled image, so divide back into client space.
        [void]$words.Add([pscustomobject]@{
          Text   = $w.Text
          X      = [int](($b.X / $factor) - $off.X + $regionOffset.X)
          Y      = [int](($b.Y / $factor) - $off.Y + $regionOffset.Y)
          Width  = [int]($b.Width / $factor)
          Height = [int]($b.Height / $factor)
          CX     = [int](($b.X + $b.Width / 2) / $factor - $off.X + $regionOffset.X)
          CY     = [int](($b.Y + $b.Height / 2) / $factor - $off.Y + $regionOffset.Y)
        })
      }
    }

    return @{
      Text  = ($lines -join "`n")
      Lines = $lines
      Words = $words
      Width = $cap.Width
      Height = $cap.Height
    }
  } finally {
    if ($scaled -ne $enhanced) { $scaled.Dispose() }
    if ($enhanced -ne $base) { $enhanced.Dispose() }
    if ($base -ne $cap.Bitmap) { $base.Dispose() }
    $cap.Bitmap.Dispose()
  }
}

function Find-Text($ocr, [string]$needle, [switch]$UseRegex) {
  if (-not $needle) { throw "-Match is required for this action" }

  # Windows OCR splits CJK text into one word per glyph ("正 在 检 查"), so a
  # substring search over Words never matches a multi-character label. Compare
  # against whitespace-stripped lines instead, then map the hit back to the
  # individual words that compose it.
  $normalize = { param($t) ($t -replace '\s+', '') }
  $target = & $normalize $needle

  $hits = New-Object System.Collections.ArrayList
  foreach ($line in $ocr.Lines) {
    $flat = & $normalize $line
    $isHit = if ($UseRegex) { $flat -match $target } else { $flat.Contains($target) }
    if ($isHit) { [void]$hits.Add(@{ Line = $line; Flat = $flat }) }
  }

  $targets = New-Object System.Collections.ArrayList
  if ($hits.Count -gt 0) {
    # Collect the words whose flattened text participates in the matched line,
    # restricted to the slice that covers the needle when possible.
    foreach ($hit in $hits) {
      $pos = if ($UseRegex) { -1 } else { $hit.Flat.IndexOf($target) }
      $cursor = 0
      foreach ($word in $ocr.Words) {
        if (-not $hit.Flat.Contains(($word.Text -replace '\s+', ''))) { continue }
        # Only words belonging to this line: rely on ordering + proximity.
        $wflat = $word.Text -replace '\s+', ''
        $idx = $hit.Flat.IndexOf($wflat, [Math]::Min($cursor, [Math]::Max(0, $hit.Flat.Length - 1)))
        if ($idx -lt 0) { continue }
        $cursor = $idx + $wflat.Length
        if ($pos -ge 0 -and ($cursor -le $pos -or $idx -ge ($pos + $target.Length))) { continue }
        [void]$targets.Add($word)
        if ($pos -ge 0) { break }   # first glyph of the label is enough to click
      }
      if ($targets.Count -gt 0 -and $pos -ge 0) { break }
    }
  }

  if ($targets.Count -eq 0) {
    foreach ($word in $ocr.Words) {
      $flat = & $normalize $word.Text
      $isHit = if ($UseRegex) { $flat -match $target } else { $flat.Contains($target) }
      if ($isHit) { [void]$targets.Add($word) }
    }
  }

  return @{ Lines = @($hits | ForEach-Object { $_.Line }); Words = $targets }
}

function Invoke-RealClick([int]$cx, [int]$cy) {
  $focused = Focus-Target
  if (-not $focused -and [MCPUI.U]::GetForegroundWindow() -ne $script:h) {
    throw "cannot click: the target window is not in the foreground and cannot be activated"
  }
  $o = Get-ClientOrigin
  $sx = $o.X + $cx
  $sy = $o.Y + $cy
  [MCPUI.U]::SetCursorPos($sx, $sy) | Out-Null
  Start-Sleep -Milliseconds 120
  [MCPUI.U]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 60
  [MCPUI.U]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
  return "real click at screen($sx,$sy) from client($cx,$cy)"
}

function Invoke-Type([string]$s) {
  $focused = Focus-Target
  if (-not $focused -and [MCPUI.U]::GetForegroundWindow() -ne $script:h) {
    throw "cannot type: the target window is not in the foreground"
  }
  foreach ($ch in $s.ToCharArray()) {
    $code = [int][char]$ch
    $null = [MCPUI.U]::PostMessage($script:h, 0x0102, [IntPtr]$code, [IntPtr]1)
    Start-Sleep -Milliseconds 20
  }
  return "typed $($s.Length) chars"
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

function Invoke-UiAction {
  param([string]$Action)
  switch ($Action) {

  'findwindow' {
    # Resolve a process's largest visible top-level window. Lives here so the
    # caller does not pay another PowerShell launch just to find a handle.
    if ($TargetPid -le 0) { throw "-Pid is required for findwindow" }
    $global:bestHwnd = 0; $global:bestArea = 0
    $cb = [MCPUI.U+EnumWindowsProc] {
      param($w, $l)
      [uint32]$p = 0
      $null = [MCPUI.U]::GetWindowThreadProcessIdOut($w, [ref]$p)
      if ($p -eq $TargetPid -and [MCPUI.U]::IsWindowVisible($w)) {
        $r = New-Object MCPUI.U+RECT
        $null = [MCPUI.U]::GetWindowRect($w, [ref]$r)
        $area = ($r.Right - $r.Left) * ($r.Bottom - $r.Top)
        if ($area -gt $global:bestArea) { $global:bestArea = $area; $global:bestHwnd = $w.ToInt64() }
      }
      return $true
    }
    [MCPUI.U]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
    Write-Output $global:bestHwnd
  }

  'info' {
    $wr = New-Object MCPUI.U+RECT; [MCPUI.U]::GetWindowRect($script:h, [ref]$wr) | Out-Null
    $cr = New-Object MCPUI.U+RECT; [MCPUI.U]::GetClientRect($script:h, [ref]$cr) | Out-Null
    $o = Get-ClientOrigin
    $off = Get-ImageOffset
    Write-Output ("window={0},{1} {2}x{3} client={4}x{5} client_origin={6},{7} image_offset={8},{9}" -f `
      $wr.Left, $wr.Top, ($wr.Right - $wr.Left), ($wr.Bottom - $wr.Top), `
      ($cr.Right - $cr.Left), ($cr.Bottom - $cr.Top), $o.X, $o.Y, $off.X, $off.Y)
  }

  'windows' {
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

  'ocr' {
    $ocr = Invoke-Ocr
    if ($Out) {
      # Re-render exactly what OCR saw (region crop + scale) for inspection.
      $cap = Capture-Bitmap
      $view = $cap.Bitmap
      if ($Region) {
        $p4 = $Region -split ','
        $cropped = Crop-Bitmap $view ([int]$p4[0]) ([int]$p4[1]) ([int]$p4[2]) ([int]$p4[3])
        $view = $cropped
      }
      $scaled = Scale-Bitmap $view ([Math]::Max(1.0, $Scale / 100.0))
      Save-Bitmap $scaled $Out
      if ($scaled -ne $view) { $scaled.Dispose() }
      if ($view -ne $cap.Bitmap) { $view.Dispose() }
      $cap.Bitmap.Dispose()
    }
    Write-Output "TEXT:"
    foreach ($l in $ocr.Lines) { Write-Output "  $l" }
    Write-Output "WORDS:"
    foreach ($w in $ocr.Words) {
      Write-Output ("  '{0}' client=({1},{2}) size={3}x{4}" -f $w.Text, $w.X, $w.Y, $w.Width, $w.Height)
    }
  }

  'findtext' {
    $ocr = Invoke-Ocr
    $found = Find-Text $ocr $Match -UseRegex:$Regex
    if ($found.Words.Count -eq 0) {
      Write-Output "NOTFOUND '$Match'"
      Write-Output "available text:"
      foreach ($l in $ocr.Lines) { Write-Output "  $l" }
      exit 2
    }
    foreach ($w in $found.Words) {
      Write-Output ("MATCH '{0}' client=({1},{2}) center=({3},{4})" -f $w.Text, $w.X, $w.Y, $w.CX, $w.CY)
    }
  }

  'clicktext' {
    $ocr = Invoke-Ocr
    $found = Find-Text $ocr $Match -UseRegex:$Regex
    if ($found.Words.Count -eq 0) {
      Write-Output "NOTFOUND '$Match'"
      Write-Output "available text:"
      foreach ($l in $ocr.Lines) { Write-Output "  $l" }
      exit 2
    }
    $w = $found.Words[0]
    Write-Output ("matched '{0}' center=({1},{2})" -f $w.Text, $w.CX, $w.CY)
    Write-Output (Invoke-RealClick $w.CX $w.CY)
  }

  'typeinto' {
    # Click the element carrying -Match (by OCR), then type -Text into it.
    #
    # Two-step is not enough for inputs with a placeholder: clicking the label
    # opens the dialog, and the actual edit box sits elsewhere. When -X/-Y are
    # supplied they take over as the click target after the label is used to
    # confirm the expected screen; otherwise the click lands on the label.
    $ocr = Invoke-Ocr
    $found = Find-Text $ocr $Match -UseRegex:$Regex
    if ($found.Words.Count -eq 0) {
      Write-Output "NOTFOUND '$Match'"
      Write-Output "available text:"
      foreach ($l in $ocr.Lines) { Write-Output "  $l" }
      exit 2
    }

    $w = $found.Words[0]
    $clickX = if ($PSBoundParameters.ContainsKey('X') -and ($X -ne 0 -or $Y -ne 0)) { $X } else { $w.CX }
    $clickY = if ($PSBoundParameters.ContainsKey('X') -and ($X -ne 0 -or $Y -ne 0)) { $Y } else { $w.CY }

    Write-Output ("matched '{0}' label_center=({1},{2}) click=({3},{4})" -f $w.Text, $w.CX, $w.CY, $clickX, $clickY)
    Write-Output (Invoke-RealClick $clickX $clickY)
    Start-Sleep -Milliseconds 250
    Write-Output (Invoke-Type $Text)
  }

  'click' {
    $lp = [IntPtr](($Y -shl 16) -bor ($X -band 0xFFFF))
    $null = [MCPUI.U]::PostMessage($script:h, 0x0200, [IntPtr]1, $lp)
    $null = [MCPUI.U]::PostMessage($script:h, 0x0201, [IntPtr]1, $lp)
    Start-Sleep -Milliseconds 60
    $null = [MCPUI.U]::PostMessage($script:h, 0x0202, [IntPtr]0, $lp)
    Write-Output "posted click at client($X,$Y)"
  }

  'realclick' { Write-Output (Invoke-RealClick $X $Y) }

  'type' { Write-Output (Invoke-Type $Text) }

  'key' {
    Focus-Target | Out-Null
    $vk = [int]$X
    $null = [MCPUI.U]::PostMessage($script:h, 0x0100, [IntPtr]$vk, [IntPtr]1)
    Start-Sleep -Milliseconds 40
    $null = [MCPUI.U]::PostMessage($script:h, 0x0101, [IntPtr]$vk, [IntPtr]0xC0000001)
    Write-Output "key vk=$vk"
  }
}

}

# ---------------------------------------------------------------------------
# Entry point
#
# One-shot mode (default) runs a single action and exits. `-Action serve` keeps
# the process alive and reads one JSON command per line from stdin, which is
# what the MCP tool uses: loading .NET, WinRT and the P/Invoke types costs ~3s,
# and paying that per click makes an otherwise instant UI interaction useless.
# ---------------------------------------------------------------------------

if ($Action -ne 'serve') {
  Invoke-UiAction -Action $Action
  exit 0
}

$stdin = [Console]::In
while ($true) {
  $line = $stdin.ReadLine()
  if ($null -eq $line) { break }
  $line = $line.Trim()
  if (-not $line) { continue }

  $resp = @{ id = $null; ok = $false; output = ''; error = '' }
  try {
    $cmd = $line | ConvertFrom-Json
    $resp.id = $cmd.id

    # Apply per-command state. Everything is script-scoped because the helper
    # functions resolve these names up the scope chain.
    if ($cmd.hwnd) { $script:h = [IntPtr][long]$cmd.hwnd }
    $script:TargetPid = if ($cmd.pid) { [int]$cmd.pid } else { 0 }
    $script:X = if ($null -ne $cmd.x) { [int]$cmd.x } else { 0 }
    $script:Y = if ($null -ne $cmd.y) { [int]$cmd.y } else { 0 }
    $script:Text = if ($cmd.text) { [string]$cmd.text } else { '' }
    $script:Match = if ($cmd.match) { [string]$cmd.match } else { '' }
    $script:Out = if ($cmd.file) { [string]$cmd.file } else { '' }
    $script:Scale = if ($cmd.scale) { [int]$cmd.scale } else { 300 }
    $script:Lang = if ($cmd.lang) { [string]$cmd.lang } else { '' }
    $script:Region = if ($cmd.region) { [string]$cmd.region } else { '' }
    $script:WaitStable = if ($cmd.wait_stable_ms) { [int]$cmd.wait_stable_ms } else { 0 }
    $script:StableTimeout = if ($cmd.stable_timeout_ms) { [int]$cmd.stable_timeout_ms } else { 8000 }
    $script:Enhance = [bool]$cmd.enhance
    $script:Regex = [bool]$cmd.regex
    $script:All = $false

    $out = & { Invoke-UiAction -Action $cmd.action } *>&1 | Out-String
    $resp.ok = $true
    $resp.output = $out.Trim()
  } catch {
    $resp.ok = $false
    $resp.error = $_.Exception.Message
    $resp.output = ($_ | Out-String)
  }

  $json = $resp | ConvertTo-Json -Compress -Depth 4
  [Console]::Out.WriteLine($json)
  [Console]::Out.Flush()
}
