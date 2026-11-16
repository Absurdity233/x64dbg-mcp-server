#include "util/kernel_driver.h"

#include <windows.h>
#include <winioctl.h>

#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "x64dbg_mcp_hide.h"

namespace kernel_driver {

namespace {

// The driver's device object is exclusive and single-instance, so one cached
// handle is correct. It is opened lazily and reopened if the driver was
// unloaded and reloaded underneath us.
HANDLE open_device() {
    HANDLE h = CreateFileW(X64MCP_HIDE_USER_PATH,
                           GENERIC_READ | GENERIC_WRITE,
                           0,          // no sharing: the device is exclusive
                           nullptr,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    return (h == INVALID_HANDLE_VALUE) ? nullptr : h;
}

// Every IOCTL in this driver is synchronous and tiny, so a blocking
// DeviceIoControl is right; the timeout is covered by the fact that the driver
// never queues work.
struct ioctl_result {
    bool ok = false;
    DWORD bytes = 0;
    DWORD error = 0;
};

template <typename TIn, typename TOut>
ioctl_result do_ioctl(HANDLE device, DWORD code, const TIn* in, TOut* out) {
    ioctl_result r{};
    DWORD in_size = in ? static_cast<DWORD>(sizeof(TIn)) : 0;
    DWORD out_size = out ? static_cast<DWORD>(sizeof(TOut)) : 0;
    BOOL ok = DeviceIoControl(device, code, const_cast<TIn*>(in), in_size,
                              out, out_size, &r.bytes, nullptr);
    r.ok = ok != FALSE;
    if (!r.ok) r.error = GetLastError();
    return r;
}

std::string win_error(DWORD code) {
    switch (code) {
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
            return "driver not loaded (device object absent)";
        case ERROR_ACCESS_DENIED:
            return "access denied - x64dbg must run elevated to open the device";
        case ERROR_INVALID_PARAMETER:
            return "driver rejected the request (ABI mismatch or bad buffer size)";
        case ERROR_NOT_SUPPORTED:
            return "driver present but this IOCTL is not implemented (older build)";
        case ERROR_BAD_DEVICE:
            return "wrong device (another driver owns that symlink)";
        case ERROR_INVALID_FUNCTION:
            return "IOCTL not recognised by the driver (ABI mismatch)";
        case ERROR_OPERATION_ABORTED:
            return "the request was cancelled";
        default: {
            char buf[64];
            snprintf(buf, sizeof(buf), "error %lu", static_cast<unsigned long>(code));
            return buf;
        }
    }
}

// Read the version block once per call. Cheap (one IRP) and it is what tells us
// whether the driver is usable at all.
nlohmann::json read_version(HANDLE device) {
    X64MCP_VERSION ver{};
    auto r = do_ioctl<X64MCP_VERSION, X64MCP_VERSION>(device, IOCTL_X64MCP_GET_VERSION,
                                                      nullptr, &ver);
    if (!r.ok) {
        return nlohmann::json{{"ok", false}, {"error", win_error(r.error)},
                             {"win32_error", r.error}};
    }
    if (ver.abi != X64MCP_HIDE_ABI) {
        return nlohmann::json{
            {"ok", false},
            {"abi_mismatch", true},
            {"driver_abi", ver.abi},
            {"plugin_abi", static_cast<unsigned long>(X64MCP_HIDE_ABI)},
            {"error", "driver ABI differs from the plugin's; rebuild both from the "
                      "same driver/x64dbg_mcp_hide.h"}
        };
    }

    const char* source = "unresolved";
    switch (ver.flags_source) {
        case X64MCP_OFFSET_SOURCE_AUTO:       source = "resolved by export + disassembly"; break;
        case X64MCP_OFFSET_SOURCE_SUPPLIED:   source = "supplied by caller"; break;
        case X64MCP_OFFSET_SOURCE_UNRESOLVED: source = "unresolved"; break;
        default: break;
    }

    return nlohmann::json{
        {"ok", true},
        {"abi", ver.abi},
        {"build", ver.build},
        {"os_build", ver.os_build},
        {"ep_debugport_offset", format_utils::format_hex(ver.ep_debugport_offset)},
        {"ep_flags_offset", format_utils::format_hex(ver.ep_flags_offset)},
        {"flags_source", source},
        {"offsets_resolved", ver.flags_source != X64MCP_OFFSET_SOURCE_UNRESOLVED}
    };
}

// Current debuggee pid, 0 when there is no session.
unsigned long current_pid() {
    auto& bridge = get_bridge();
    if (!bridge.is_debugging()) return 0;
    return static_cast<unsigned long>(bridge.eval_expression("$pid"));
}

} // namespace

std::wstring device_path() { return X64MCP_HIDE_USER_PATH; }

nlohmann::json status() {
    HANDLE device = open_device();
    if (!device) {
        const DWORD err = GetLastError();
        return nlohmann::json{
            {"driver_present", false},
            {"user_path", "\\\\.\\x64dbg_mcp_hide"},
            {"error", win_error(err)},
            {"win32_error", err},
            {"next_step", "load driver/x64dbg_mcp_hide.sys (see driver/README.md). "
                          "Everything else in this tool works without it; only "
                          "ProcessDebugPort/ObjectHandle/Flags need the kernel."}
        };
    }

    auto version = read_version(device);
    X64MCP_STATUS st{};
    auto q = do_ioctl<X64MCP_STATUS, X64MCP_STATUS>(device, IOCTL_X64MCP_QUERY, nullptr, &st);
    CloseHandle(device);

    nlohmann::json out = {
        {"driver_present", true},
        {"user_path", "\\\\.\\x64dbg_mcp_hide"},
        {"version", version}
    };

    if (q.ok) {
        out["attached_pid"] = st.pid;
        out["applied_mask"] = format_utils::format_hex(static_cast<duint>(st.applied));
        out["failed_mask"] = format_utils::format_hex(static_cast<duint>(st.failed));
        if (st.errors != 0) out["last_ntstatus"] = format_utils::format_address(st.errors);
    } else {
        out["query_error"] = win_error(q.error);
    }

    const unsigned long pid = current_pid();
    if (pid != 0) {
        out["debuggee_pid"] = pid;
        out["attached_to_debuggee"] = q.ok && st.pid == pid;
    }

    return out;
}

nlohmann::json attach(unsigned long pid) {
    if (pid == 0) pid = current_pid();
    if (pid == 0) {
        return nlohmann::json{{"ok", false}, {"error", "no debuggee and no 'pid' given"}};
    }
    if (pid == 4 || pid == 0) {
        return nlohmann::json{{"ok", false}, {"error", "refusing pid " + std::to_string(pid)}};
    }

    HANDLE device = open_device();
    if (!device) {
        return nlohmann::json{{"ok", false}, {"error", win_error(GetLastError())}};
    }

    X64MCP_ATTACH_REQ req{};
    req.pid = pid;
    auto r = do_ioctl<X64MCP_ATTACH_REQ, X64MCP_ATTACH_REQ>(device, IOCTL_X64MCP_ATTACH,
                                                            &req, nullptr);
    CloseHandle(device);

    if (!r.ok) {
        return nlohmann::json{{"ok", false}, {"pid", pid}, {"error", win_error(r.error)},
                              {"win32_error", r.error}};
    }
    return nlohmann::json{{"ok", true}, {"pid", pid},
                          {"message", "driver pinned to pid " + std::to_string(pid)}};
}

nlohmann::json detach() {
    HANDLE device = open_device();
    if (!device) {
        return nlohmann::json{{"ok", false}, {"error", win_error(GetLastError())}};
    }
    auto r = do_ioctl<X64MCP_ATTACH_REQ, X64MCP_ATTACH_REQ>(device, IOCTL_X64MCP_DETACH,
                                                            nullptr, nullptr);
    CloseHandle(device);

    if (!r.ok) return nlohmann::json{{"ok", false}, {"error", win_error(r.error)}};
    return nlohmann::json{{"ok", true}, {"message", "driver detached; nothing is applied"}};
}

nlohmann::json apply(uint64_t mask,
                     unsigned long debugport_offset,
                     unsigned long flags_offset,
                     unsigned long cross_session_offset) {
    HANDLE device = open_device();
    if (!device) {
        return nlohmann::json{{"ok", false}, {"error", win_error(GetLastError())},
                              {"hint", "call kernel_status for the reason"}};
    }

    auto version = read_version(device);
    if (!version.value("ok", false)) {
        CloseHandle(device);
        return nlohmann::json{{"ok", false}, {"error", version.value("error", "")},
                              {"version", version}};
    }

    // The driver must be pinned to something before it can clear fields for it.
    X64MCP_STATUS before{};
    auto q = do_ioctl<X64MCP_STATUS, X64MCP_STATUS>(device, IOCTL_X64MCP_QUERY, nullptr, &before);
    if (!q.ok || before.pid == 0) {
        CloseHandle(device);
        return nlohmann::json{
            {"ok", false},
            {"error", "driver has no attached process; call kernel_attach first"},
            {"version", version}
        };
    }

    X64MCP_APPLY_REQ req{};
    req.mask = mask;
    req.ep_flags_offset = flags_offset;
    req.ep_crosssession_offset = cross_session_offset;
    // The DebugPort offset is not per-request: the driver resolves it once at
    // load (it is the same field for every process on that kernel build) and
    // refuses to apply DEBUGPORT when it could not. Passing it here would let a
    // caller write a wrong offset into a live EPROCESS.
    (void)debugport_offset;

    X64MCP_STATUS st{};
    auto r = do_ioctl<X64MCP_APPLY_REQ, X64MCP_STATUS>(device, IOCTL_X64MCP_APPLY, &req, &st);
    CloseHandle(device);

    if (!r.ok) {
        return nlohmann::json{{"ok", false}, {"error", win_error(r.error)},
                              {"win32_error", r.error},
                              {"requested_mask", format_utils::format_hex(static_cast<duint>(mask))}};
    }

    nlohmann::json out = {
        {"ok", st.failed == 0},
        {"pid", st.pid},
        {"requested_mask", format_utils::format_hex(static_cast<duint>(mask))},
        {"applied_mask", format_utils::format_hex(static_cast<duint>(st.applied))},
        {"failed_mask", format_utils::format_hex(static_cast<duint>(st.failed))},
        {"ep_debugport_offset", format_utils::format_hex(st.ep_debugport_offset)},
        {"ep_flags_offset", format_utils::format_hex(st.ep_flags_offset)},
        {"version", version}
    };
    if (st.errors != 0) out["first_ntstatus"] = format_utils::format_address(st.errors);

    // Say plainly what a partially applied mask means, because "some bits
    // failed" is the difference between "this check is now invisible" and
    // "this check still sees the debugger".
    if (st.failed != 0) {
        out["message"] = "some fields could not be cleared - see failed_mask; the "
                         "target will still detect the debugger through those";
    } else {
        out["message"] = "EPROCESS debug fields cleared and verified";
    }
    return out;
}

nlohmann::json query() {
    HANDLE device = open_device();
    if (!device) {
        return nlohmann::json{{"ok", false}, {"error", win_error(GetLastError())}};
    }
    X64MCP_STATUS st{};
    auto r = do_ioctl<X64MCP_STATUS, X64MCP_STATUS>(device, IOCTL_X64MCP_QUERY, nullptr, &st);
    CloseHandle(device);

    if (!r.ok) return nlohmann::json{{"ok", false}, {"error", win_error(r.error)}};
    return nlohmann::json{
        {"ok", true},
        {"pid", st.pid},
        {"applied_mask", format_utils::format_hex(static_cast<duint>(st.applied))},
        {"failed_mask", format_utils::format_hex(static_cast<duint>(st.failed))},
        {"ep_debugport_offset", format_utils::format_hex(st.ep_debugport_offset)},
        {"ep_flags_offset", format_utils::format_hex(st.ep_flags_offset)},
        {"os_build", st.os_build},
        {"last_ntstatus", format_utils::format_address(st.errors)}
    };
}

std::string describe() {
    auto st = status();
    if (!st.value("driver_present", false)) {
        return "kernel driver: not loaded (" + st.value("error", std::string("unknown")) + ")";
    }
    const auto& ver = st["version"];
    if (!ver.value("ok", false)) {
        return "kernel driver: loaded but unusable (" + ver.value("error", std::string("unknown")) + ")";
    }
    return "kernel driver: loaded, os_build " +
           std::to_string(ver.value("os_build", 0u)) +
           ", debugport offset " + ver.value("ep_debugport_offset", std::string("?")) +
           " via " + ver.value("flags_source", std::string("?"));
}

} // namespace kernel_driver
