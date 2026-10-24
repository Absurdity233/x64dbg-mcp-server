"""Drive Snarl to the activation dialog, then find who reads the activation code.

Strategy notes
--------------
* Hardware breakpoints are avoided: Dr0-Dr3 are a classic anti-debug check and
  the target died the first time one was armed.
* A memory breakpoint is page based, so UI text rendering (dwrite/textshaping)
  trips it too. Every stop is classified by its call stack and rendering frames
  are skipped automatically.
* Every UI step is verified with OCR before moving on - an unverified click
  silently lands on the wrong control and the rest of the run is wasted.
"""

import json
import re
import subprocess
import sys
import time
import urllib.request

TOKEN = "e317318976298f9c154e1a961c1552c1"
BASE = "http://127.0.0.1:27042"
UI = r"F:\reverse1\.tools\x64dbg_mcp-src\server\scripts\ui.ps1"
TARGET = r"F:\reverse1\Snarl-3.1.0-offline.exe"
SHOT_DIR = r"F:\reverse1\.tools"
CODE = "AAAA-BBBB-CCCC"


def api(path, body=None, timeout=240):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + TOKEN},
        method="POST" if data is not None else "GET",
    )
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def cmd(c, timeout=60):
    return api("/api/command/exec", {"command": c}, timeout)


def state():
    return api("/api/debug/state")["data"]


def stack(depth=18):
    return api("/api/stack/trace?max_depth=%d" % depth)["data"]


def wait_state(want, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        s = state()["state"]
        if want == "paused" and s == "paused":
            return True
        if want == "running" and s == "running":
            return True
        if want == "active" and s != "stopped":
            return True
        if want == "stopped" and s == "stopped":
            return True
        time.sleep(0.2)
    return False


class Ui:
    def __init__(self):
        self.p = subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", UI,
             "-Hwnd", "0", "-Action", "serve"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=1,
        )
        self.n = 0

    def call(self, **kw):
        self.n += 1
        d = {"id": self.n}
        d.update(kw)
        self.p.stdin.write((json.dumps(d) + "\n").encode())
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            return {"ok": False, "output": "", "error": "daemon closed"}
        return json.loads(line.decode("utf-8"))

    def hwnd_for(self, pid):
        r = self.call(action="findwindow", pid=pid)
        return int((r.get("output") or "0").strip() or 0)


def pid_of(name):
    out = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq " + name, "/FO", "CSV", "/NH"],
        capture_output=True, text=True, encoding="mbcs", errors="replace",
    ).stdout
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == name.lower():
            try:
                return int(parts[1])
            except ValueError:
                pass
    return 0


# Only modules that exist purely to draw the UI. Generic layers (ntdll,
# kernelbase, ucrtbase) are NOT filtered: a snarl -> ntdll -> ... chain is a
# perfectly good candidate for the code that consumes the string.
RENDER_MODULES = {
    "dwrite", "textshaping", "d2d1", "d3d11", "dxgi", "dcomp",
    "coreuicomponents", "coremessaging", "msctf", "imm32", "nvwgf2umx",
    "gdi32", "gdi32full", "win32u",
}


def classify(st):
    frames = st.get("frames") or []
    mods = [(f.get("module") or "").lower() for f in frames]
    top = mods[0] if mods else ""
    snarl = [f for f in frames if "snarl" in (f.get("module") or "").lower()]
    return top, snarl, mods


def main():
    print("== reset ==")
    try:
        cmd("stop")
    except Exception:
        pass
    time.sleep(1)

    print("== load ==")
    print(cmd('init "%s"' % TARGET)["data"])
    if not wait_state("paused", 90):
        print("load did not reach a pause")
        return 1
    # `bc` clears software breakpoints only; hardware (bphwc) and memory (bpmc)
    # ones survive and will stop the new process before it even creates a window.
    for clear in ("bc", "bphwc", "bpmc"):
        try:
            cmd(clear)
        except Exception:
            pass

    print("== exception preset ==")
    for code in ["C0000005", "C000001D", "C0000094", "C0000095", "C0000096",
                 "C000008E", "C000001E", "80000003", "E06D7363", "E0434352"]:
        try:
            api("/api/exceptions/set_bp", {"code": code, "chance": "second"})
        except Exception:
            pass

    print("== run to UI ==")
    cmd("run")
    wait_state("running", 30)
    time.sleep(14)

    pid = pid_of("Snarl-3.1.0-offline.exe")
    if not pid:
        print("target not running")
        return 1
    ui = Ui()
    h = ui.hwnd_for(pid)
    print("pid", pid, "hwnd", h)
    if not h:
        print("no window")
        return 1

    def ocr_text():
        r = ui.call(action="ocr", hwnd=h, lang="zh-Hans-CN", scale=400, wait_stable_ms=150)
        return (r.get("output") or "").replace("\r", "")

    def ocr_flat():
        # Windows OCR puts a space between every CJK glyph, so substring tests
        # have to run on whitespace-stripped text.
        return re.sub(r"\s+", "", ocr_text())

    def ocr_settled(tries=6):
        # A single capture can land on a partially drawn frame and report an
        # empty screen, which then reads as "the dialog is gone". Require two
        # consecutive identical results before trusting the text.
        prev = None
        for _ in range(tries):
            cur = ocr_flat()
            if cur and cur == prev:
                return cur
            prev = cur
            time.sleep(0.7)
        return prev or ""

    print("== wait for the UI to actually render ==")
    for _ in range(30):
        if ocr_flat():
            break
        time.sleep(1)
    else:
        print("  window never produced text; aborting")
        return 1
    print("  UI is rendering")

    print("== wait for the migration dialog to appear ==")
    # The app shows a progress line first and only then pops the dialog, so an
    # early OCR legitimately has neither - wait for either state.
    seen = ""
    for _ in range(30):
        seen = ocr_settled(tries=2)
        if "迁移完毕" in seen or "新的激活码" in seen:
            break
        time.sleep(1)
    print("  state:", "dialog" if "迁移完毕" in seen else ("main" if "新的激活码" in seen else "unknown"))

    if "迁移完毕" in seen:
        print("== dismiss migration dialog ==")
        for attempt in range(6):
            ui.call(action="realclick", hwnd=h, x=603, y=327)
            time.sleep(1.4)
            if "迁移完毕" not in ocr_settled(tries=2):
                print("  dismissed (attempt %d)" % attempt)
                break
        else:
            print("  could not dismiss; screen:")
            print(ocr_text()[:400])
            return 1

    print("== open activation dialog ==")
    opened = False
    for attempt in range(4):
        txt = ocr_flat()
        if "输入您的激活密钥" in txt or "激活密钥" in txt:
            opened = True
            break
        ui.call(action="realclick", hwnd=h, x=390, y=478)
        time.sleep(1.2)
    if not opened:
        print("  dialog did not open; screen:")
        print(ocr_text()[:400])
        return 1
    print("  activation input is visible")

    print("== focus input and type ==")
    ui.call(action="realclick", hwnd=h, x=470, y=476)
    time.sleep(0.6)
    print(" ", ui.call(action="type", hwnd=h, text=CODE)["output"])
    time.sleep(0.8)
    ui.call(action="shot", hwnd=h, file=SHOT_DIR + r"\r_typed.png")

    print("== search memory for the code (utf-16le) ==")
    pat = " ".join("%02X" % b for b in CODE.encode("utf-16le"))
    res = api("/api/search/memory",
              {"pattern": pat, "max_results": 20, "max_bytes": 2_000_000_000})["data"]
    print("matches:", res["matches"], "scanned MB:", round(res["bytes_scanned"] / 1e6))
    if not res["matches"]:
        print("code not found - the typed text did not reach the widget")
        return 1
    addr = int(res["matches"][0], 16)

    print("== arm memory read bp at %s ==" % hex(addr))
    print(cmd("bpm %s, r" % hex(addr))["data"])
    time.sleep(0.5)

    print("== submit ==")
    ui.call(action="realclick", hwnd=h, x=600, y=476)

    hits = 0
    for i in range(60):
        if not wait_state("paused", 25):
            print("[%d] no pause within 25s; state=%s" % (i, state()["state"]))
            break
        hits += 1
        # A memory breakpoint is page based, so most hits are unrelated data
        # sharing the page. Only accept a hit whose registers actually point at
        # the code buffer.
        regs = api("/api/registers/all")["data"]
        ptrs = {}
        for k in ("rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"):
            try:
                v = int(str(regs.get(k, "0")), 16)
            except ValueError:
                continue
            if addr <= v < addr + 0x40:
                ptrs[k] = hex(v)
        st = stack()
        top, snarl, mods = classify(st)
        if not ptrs:
            print("[%d] top=%-14s (no register points at the code, skipping)" % (i, top or "?"))
            cmd("run")
            time.sleep(0.25)
            continue
        print("[%d] *** register(s) point at the code: %s ***" % (i, ptrs))
        print("[%d] top=%-16s frames=%d snarl=%d" % (i, top or "?", len(mods), len(snarl)))
        for f in snarl[:6]:
            print("      %s  %s %s" % (f.get("from"), f.get("module"), f.get("comment", "")))
        if snarl and top not in RENDER_MODULES:
            print("  *** candidate reader ***")
            for f in snarl[:10]:
                print("    from=%s %s %s" % (f.get("from"), f.get("module"), f.get("comment", "")))
            print(json.dumps(st, indent=1)[:2500])
            break
        cmd("run")
        time.sleep(0.3)
    else:
        print("no non-rendering reader found")

    print("hits:", hits)
    ui.p.stdin.close()
    ui.p.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
