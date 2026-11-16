#include "util/host_artifacts.h"

#include <windows.h>
#include <winreg.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace host_artifacts {

namespace {

enum class sev {
    // A check with this artifact present fires. This is "the target knows".
    hit,
    // Present but ambiguous: the check may or may not treat it as a VM.
    weak,
};

struct finding_sink {
    nlohmann::json items = nlohmann::json::array();
    void add(sev s, const char* category, const std::string& item,
             const std::string& value, const std::string& why) {
        items.push_back({
            {"category", category},
            {"item",     item},
            {"value",    value},
            {"severity", s == sev::hit ? "hit" : "weak"},
            {"why",      why}
        });
    }
};

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Read a REG_SZ / REG_EXPAND_SZ value. Returns empty on any failure - an absent
// key is the normal case for half this list, not an error.
std::string read_reg_sz(HKEY root, const wchar_t* subkey, const wchar_t* name,
                        REGSAM view = 0) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | view, &key) != ERROR_SUCCESS) return {};

    wchar_t buf[1024] = {};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    const LONG rc = RegQueryValueExW(key, name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS) return {};
    if (type != REG_SZ && type != REG_EXPAND_SZ) return {};

    // A non-NUL-terminated value is legal; the API gives us the byte count.
    buf[(sizeof(buf) / sizeof(buf[0])) - 1] = L'\0';

    // Narrow it. The system code page is what the target's ANSI APIs will see,
    // which is the whole point of reporting the value.
    char narrow[2048] = {};
    if (WideCharToMultiByte(CP_ACP, 0, buf, -1, narrow, sizeof(narrow) - 1, nullptr, nullptr) == 0) {
        return {};
    }
    return narrow;
}

// Read a REG_DWORD value.
//
// This exists because the most important artifact on a modern host is a DWORD:
// DeviceGuard\...\HypervisorEnforcedCodeIntegrity\Enabled is 0 or 1 as a DWORD,
// and a string-only reader reports "not present" for it. That is not a cosmetic
// gap - HVCI/VBS sets the CPUID hypervisor bit, so a target fails its VM check on
// a perfectly physical machine and the survey has to be able to say why.
bool read_reg_dword(HKEY root, const wchar_t* subkey, const wchar_t* name, DWORD* out) {
    HKEY key = nullptr;
    REGSAM view = 0;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | view, &key) != ERROR_SUCCESS) {
        return false;
    }
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    const LONG rc = RegQueryValueExW(key, name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(&value), &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return false;
    *out = value;
    return true;
}

// Does a registry key exist at all?
bool reg_key_exists(HKEY root, const wchar_t* subkey, REGSAM view = 0) {
    HKEY key = nullptr;
    const LONG rc = RegOpenKeyExW(root, subkey, 0, KEY_READ | view, &key);
    if (key) RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

void check_registry(finding_sink& out) {
    const HKEY hklm = HKEY_LOCAL_MACHINE;

    // --- Guest-tools / hypervisor services ---------------------------------
    struct key_probe {
        const wchar_t* subkey;
        const char* item;
        const char* why;
    };
    const key_probe keys[] = {
        {L"SOFTWARE\\VMware, Inc.\\VMware Tools", "VMware Tools",
         "installed guest tools; VMDetect/IsVMware checks read this key directly"},
        {L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VirtualBox Guest Additions",
         "installed guest tools"},
        {L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "Hyper-V integration services",
         "KVP/guest services; present on every Hyper-V guest"},
        {L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", "VBoxGuest service",
         "VirtualBox guest driver service"},
        {L"SYSTEM\\CurrentControlSet\\Services\\vmtools", "vmtools service",
         "VMware Tools service"},
        {L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", "vmhgfs service",
         "VMware shared folders"},
        {L"SYSTEM\\CurrentControlSet\\Services\\vmmouse", "vmmouse service",
         "VMware mouse driver"},
        {L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", "VBoxMouse service",
         "VirtualBox mouse driver"},
        {L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF", "VBoxSF service",
         "VirtualBox shared folders"},
        {L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo", "VBoxVideo service",
         "VirtualBox video driver"},
        {L"HARDWARE\\ACPI\\DSDT\\VBOX__", "ACPI DSDT: VBOX__",
         "VirtualBox DSDT signature - a check that reads the DSDT sees it"},
        {L"HARDWARE\\ACPI\\FADT\\VBOX__", "ACPI FADT: VBOX__",
         "VirtualBox FADT signature"},
        {L"HARDWARE\\ACPI\\DSDT\\VMWARE", "ACPI DSDT: VMWARE",
         "VMware DSDT signature"},
        {L"HARDWARE\\ACPI\\DSDT\\PTLTD", "ACPI DSDT: PTLTD",
         "some hypervisors ship the reference ACPI tables"},
        {L"SOFTWARE\\Wine", "Wine prefix",
         "not a VM but the same class of check: a non-Windows host"},
    };
    for (const auto& k : keys) {
        if (reg_key_exists(hklm, k.subkey)) {
            out.add(sev::hit, "registry", k.item, "present", k.why);
        }
    }

    // --- System identity strings the BIOS/disk model checks read -----------
    const std::string bios_vendor =
        read_reg_sz(hklm, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer");
    const std::string bios_product =
        read_reg_sz(hklm, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
    const std::string bios_version =
        read_reg_sz(hklm, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion");

    auto vendor_hit = [&](const std::string& v, const char* needle, const char* what) {
        if (!v.empty() && lower(v).find(needle) != std::string::npos) {
            out.add(sev::hit, "firmware", what, v,
                    "the string itself is the detection: checks substring-match these");
        }
    };
    vendor_hit(bios_vendor, "vmware", "SystemManufacturer = VMware");
    vendor_hit(bios_vendor, "innotek", "SystemManufacturer = innotek (VirtualBox)");
    vendor_hit(bios_vendor, "virtualbox", "SystemManufacturer = VirtualBox");
    vendor_hit(bios_vendor, "qemu", "SystemManufacturer = QEMU");
    vendor_hit(bios_vendor, "xen", "SystemManufacturer = Xen");
    vendor_hit(bios_vendor, "microsoft corporation", "SystemManufacturer = Microsoft (Hyper-V)");
    vendor_hit(bios_product, "virtualbox", "SystemProductName = VirtualBox");
    vendor_hit(bios_product, "vmware", "SystemProductName = VMware");
    vendor_hit(bios_product, "virtual machine", "SystemProductName = Virtual Machine");
    vendor_hit(bios_version, "vbox", "BIOSVersion contains VBOX");

    if (!bios_vendor.empty() && !bios_product.empty() &&
        lower(bios_vendor) == lower(bios_product)) {
        out.add(sev::weak, "firmware",
                "SystemManufacturer == SystemProductName",
                bios_vendor + " / " + bios_product,
                "generic hypervisor default; a physical machine rarely has them equal");
    }

    // --- Disk model --------------------------------------------------------
    const std::string disk =
        read_reg_sz(hklm, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\"
                          L"Target Id 0\\Logical Unit Id 0", L"Identifier");
    for (const char* needle : {"vbox", "vmware", "qemu", "virtual hd", "msft virtual"}) {
        if (!disk.empty() && lower(disk).find(needle) != std::string::npos) {
            out.add(sev::hit, "storage", std::string("disk model contains '") + needle + "'",
                    disk, "GetVolumeInformation / IOCTL_STORAGE_QUERY_PROPERTY exposes this");
            break;
        }
    }

    // --- Hyper-V / VBS: a hypervisor is present even on bare metal ----------
    // The CPUID hypervisor bit is set whenever Hyper-V or VBS is enabled, so a
    // target that only checks that bit fails on a perfectly normal host. This is
    // a separate category from the guest-tools artifacts because the fix is
    // different: this is not a VM fingerprint to hide, it is a real hypervisor
    // the host is legitimately running, and the only way to make the bit clear is
    // to boot without it (bcdedit /set hypervisorlaunchtype off) or to stub the
    // cpuid in the debuggee.
    DWORD hvci = 0;
    if (read_reg_dword(hklm, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
                            L"HypervisorEnforcedCodeIntegrity", L"Enabled", &hvci)) {
        if (hvci != 0) {
            out.add(sev::hit, "hypervisor",
                    "HypervisorEnforcedCodeIntegrity = 1", "enabled",
                    "VBS/HVCI is running a hypervisor: the CPUID hypervisor bit is set and "
                    "CPUID leaf 0x40000000 answers with a vendor string. A target checking "
                    "that bit sees a VM on this physical machine. Also blocks unsigned "
                    "kernel drivers, including this tool's kernel component.");
        }
    }

    DWORD vbs_running = 0;
    if (read_reg_dword(hklm, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
                            L"SystemGuard", L"Enabled", &vbs_running)) {
        if (vbs_running != 0) {
            out.add(sev::weak, "hypervisor", "SystemGuard (VBS) = 1", "enabled",
                    "part of the same hypervisor-backed security stack as HVCI");
        }
    }
}

void check_devices(finding_sink& out) {
    // Device interface paths are what DeviceIoControl-based checks open. The
    // \Device\ names below are the classic ones (the PnP manager exposes them
    // under \GLOBAL??).
    const wchar_t* devices[] = {
        L"\\\\.\\pipe\\VBoxTrayIPC",
        L"\\\\.\\VBoxMiniRdrDN",
        L"\\\\.\\VBoxGuest",
        L"\\\\.\\HGFS",
        L"\\\\.\\vmci",
        L"\\\\.\\vmhgfs",
    };
    for (const wchar_t* d : devices) {
        HANDLE h = CreateFileW(d, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            char narrow[256] = {};
            WideCharToMultiByte(CP_ACP, 0, d, -1, narrow, sizeof(narrow) - 1, nullptr, nullptr);
            out.add(sev::hit, "device", std::string("openable: ") + narrow, "present",
                    "the target's CreateFile on this path succeeds under a VM and fails on metal");
        } else if (GetLastError() == ERROR_ACCESS_DENIED) {
            char narrow[256] = {};
            WideCharToMultiByte(CP_ACP, 0, d, -1, narrow, sizeof(narrow) - 1, nullptr, nullptr);
            out.add(sev::weak, "device", std::string("exists (access denied): ") + narrow,
                    "present",
                    "ERROR_ACCESS_DENIED still proves the device object exists");
        }
    }
}

void check_processes(finding_sink& out) {
    // Guest-tool processes. A check that enumerates processes and looks for
    // these names is the cheapest VM detection there is, and one of the most
    // common in game anti-cheats and packers.
    static const char* names[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "vmacthlp.exe",
        "vboxservice.exe", "vboxtray.exe", "vboxsdl.exe",
        "qemu-ga.exe", "prl_tools.exe", "prl_cc.exe",
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::vector<std::string> found;
    if (Process32FirstW(snap, &pe)) {
        do {
            char narrow[MAX_PATH] = {};
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, narrow, sizeof(narrow) - 1,
                                nullptr, nullptr);
            const std::string name = lower(narrow);
            for (const char* needle : names) {
                if (name == needle) { found.push_back(narrow); break; }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    for (const auto& n : found) {
        out.add(sev::hit, "process", n, "running",
                "process-name enumeration finds it; this fires even when every other check passes");
    }
}

void check_mac(finding_sink& out) {
    // MAC OUI prefixes assigned to hypervisor vendors. A target reading
    // GetAdaptersAddresses and matching the first three octets is the classic
    // check that survives every registry and file cleanup.
    struct oui { const char* prefix; const char* vendor; };
    static const oui prefixes[] = {
        {"00:05:69", "VMware"}, {"00:0C:29", "VMware"}, {"00:1C:14", "VMware"},
        {"00:50:56", "VMware"},
        {"08:00:27", "VirtualBox (innotek)"},
        {"00:15:5D", "Microsoft Hyper-V"}, {"00:03:FF", "Microsoft Virtual PC"},
        {"52:54:00", "QEMU / KVM"},
        {"00:16:3E", "Xen"},
        {"00:1C:42", "Parallels"},
    };

    // Walk the adapter list through the registry rather than IP Helper: one
    // RegEnumKeyEx loop, no allocation, and it cannot be confused by a
    // virtual adapter that has no address yet.
    HKEY adapters = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
                      L"{4d36e972-e325-11ce-bfc1-08002be10318}",
                      0, KEY_READ, &adapters) != ERROR_SUCCESS) {
        return;
    }

    for (DWORD i = 0; ; ++i) {
        wchar_t sub[64] = {};
        DWORD len = static_cast<DWORD>(std::size(sub));
        if (RegEnumKeyExW(adapters, i, sub, &len, nullptr, nullptr, nullptr, nullptr)
            != ERROR_SUCCESS) {
            break;
        }
        HKEY inst = nullptr;
        if (RegOpenKeyExW(adapters, sub, 0, KEY_READ, &inst) != ERROR_SUCCESS) continue;

        BYTE mac[16] = {};
        DWORD size = sizeof(mac);
        DWORD type = 0;
        if (RegQueryValueExW(inst, L"NetworkAddress", nullptr, &type, mac, &size)
            == ERROR_SUCCESS && type == REG_SZ) {
            // Only a configured override is stored here; the hardware address
            // is not, which is why the real check uses the driver. Report the
            // override as a weak artifact and say so.
            const std::string s = lower(reinterpret_cast<const char*>(mac));
            for (const auto& p : prefixes) {
                if (s.find(p.prefix) != std::string::npos) {
                    out.add(sev::weak, "network",
                            std::string("NetworkAddress override = ") + p.vendor, s,
                            "adapter override matches a hypervisor OUI");
                }
            }
        }
        RegCloseKey(inst);
    }
    RegCloseKey(adapters);
}

void check_window_classes(finding_sink& out) {
    // Guest-tool windows. A target can FindWindow these classes without any
    // privilege and without loading a driver.
    static const char* classes[] = {
        "VBoxTrayToolWndClass", "VBoxSharedClipboardClass", "VBoxGuestHLPWindow",
        "VMwareTrayIcon", "VMwareUserProcessWindowClass",
    };
    for (const char* c : classes) {
        wchar_t wide[128] = {};
        MultiByteToWideChar(CP_ACP, 0, c, -1, wide, static_cast<int>(std::size(wide)) - 1);
        if (FindWindowW(wide, nullptr) != nullptr) {
            out.add(sev::hit, "window", std::string("window class: ") + c, "exists",
                    "FindWindow by class succeeds under a VM and fails on metal");
        }
    }
}

// Runs inside the anonymous namespace so the finding_sink helper above is
// visible; the public entry point is the thin wrapper below it.
nlohmann::json survey_impl() {
    finding_sink sink;

    check_registry(sink);
    check_devices(sink);
    check_processes(sink);
    check_mac(sink);
    check_window_classes(sink);

    // Count by severity so the caller can decide whether to bother.
    size_t hits = 0, weak = 0;
    for (const auto& it : sink.items) {
        (it["severity"] == "hit" ? hits : weak) += 1;
    }

    // Report the raw identity even when nothing matched. Without it, "0
    // findings" is indistinguishable from "the registry reads all failed", and
    // the caller has no way to tell a clean physical host from a broken scan.
    // These are the values the checks actually substring-match, so seeing them
    // is also what tells you which string to spoof next.
    nlohmann::json identity = {
        {"SystemManufacturer", read_reg_sz(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer")},
        {"SystemProductName", read_reg_sz(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName")},
        {"BIOSVersion", read_reg_sz(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion")},
        {"DiskIdentifier", read_reg_sz(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\"
            L"Target Id 0\\Logical Unit Id 0", L"Identifier")}
    };

    // An empty identity means the reads themselves failed, which is a different
    // problem from a machine with no fingerprints.
    const bool identity_readable =
        !identity["SystemManufacturer"].get<std::string>().empty() ||
        !identity["BIOSVersion"].get<std::string>().empty();

    return nlohmann::json{
        {"findings", sink.items},
        {"count",    sink.items.size()},
        {"hits",     hits},
        {"weak",     weak},
        {"host_identity", identity},
        {"identity_readable", identity_readable},
        {"verdict", !identity_readable
            ? "registry reads failed - the survey could not see this host, so the "
              "empty result means nothing"
            : (hits == 0 ? "no VM fingerprint found: this looks like physical hardware"
                         : "VM fingerprints present - a detection check would fire")},
        {"note", "Read-only survey of this host: what a VM-detection check will see. "
                 "Nothing was modified. To beat a specific check, stub the check's input "
                 "in the debuggee (anti_vm), not the host: a host-wide change is also "
                 "visible to the tooling doing the analysis."}
    };
}

} // namespace

nlohmann::json survey() { return survey_impl(); }

} // namespace host_artifacts
