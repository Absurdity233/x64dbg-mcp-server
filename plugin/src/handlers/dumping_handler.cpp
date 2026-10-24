#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"
#include "_scriptapi_module.h"

namespace handlers {

namespace {

// Small helpers for reading PE structures out of a loaded module's memory.
// For a loaded image, an RVA maps directly to base + rva.

bool mem_u16(c_bridge_executor& bridge, duint addr, uint16_t& out) {
    auto r = bridge.read_memory(addr, sizeof(uint16_t));
    if (!r.has_value() || r->size() < sizeof(uint16_t)) return false;
    std::memcpy(&out, r->data(), sizeof(uint16_t));
    return true;
}

std::string mem_cstr(c_bridge_executor& bridge, duint addr, size_t max_len = 512) {
    auto r = bridge.read_memory(addr, max_len);
    if (!r.has_value()) return "";
    std::string s;
    for (auto c : *r) {
        if (c == 0) break;
        s += static_cast<char>(c);
    }
    return s;
}

// Locate the PE optional header and return whether it is PE32+, plus the RVA/size
// of a given data directory index. Returns false on any malformed read.
bool get_data_directory(c_bridge_executor& bridge, duint base, int index,
                        bool& is_pe32plus, uint32_t& dir_rva, uint32_t& dir_size) {
    auto dos = bridge.read_memory(base, 64);
    if (!dos.has_value() || dos->size() < 64 || (*dos)[0] != 'M' || (*dos)[1] != 'Z') {
        return false;
    }
    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, dos->data() + 0x3C, 4);

    // PE sig (4) + COFF header (20) + optional header. Read enough to cover the
    // optional header magic and the data directory array.
    auto pe = bridge.read_memory(base + e_lfanew, 264);
    if (!pe.has_value() || pe->size() < 28 || (*pe)[0] != 'P' || (*pe)[1] != 'E') {
        return false;
    }
    uint16_t magic = 0;
    std::memcpy(&magic, pe->data() + 24, 2); // optional header starts at +24
    is_pe32plus = (magic == 0x20B);

    // Data directory array offset within the optional header.
    size_t dd_off = 24 + (is_pe32plus ? 112 : 96) + static_cast<size_t>(index) * 8;
    if (pe->size() < dd_off + 8) {
        return false;
    }
    std::memcpy(&dir_rva, pe->data() + dd_off, 4);
    std::memcpy(&dir_size, pe->data() + dd_off + 4, 4);
    return true;
}

// ---------------------------------------------------------------------------
// IAT reconstruction without Scylla
//
// A packed target's IAT is populated at runtime: every slot holds the address of
// an export in some other loaded module. Rebuilding the table therefore means
// answering, for each candidate pointer, "which module owns this address, and
// which export is it?" - which every loaded module can answer from its own
// export directory.
//
// Three sources are combined, in decreasing order of reliability:
//   1. the import descriptors already in memory (a packer usually keeps them);
//   2. a scan of the candidate IAT range for pointers into other modules'
//      export ranges (recovers entries a packer stripped from the descriptors);
//   3. for anything unresolved, a direct exported-name lookup by address.
// ---------------------------------------------------------------------------

struct export_entry {
    duint address;
    std::string name;
    bool by_ordinal;
    uint32_t ordinal;
};

struct module_exports {
    std::string name;      // module file name, e.g. kernel32.dll
    duint base;
    duint size;
    std::vector<export_entry> entries;   // sorted by address
};

// Parse one loaded module's export directory into a sorted address table.
module_exports collect_exports(c_bridge_executor& bridge, const Script::Module::ModuleInfo& mod) {
    module_exports out;
    out.name = mod.name;
    out.base = mod.base;
    out.size = mod.size;
    if (mod.base == 0 || mod.size == 0) return out;

    bool pe32plus = false;
    uint32_t exp_rva = 0, exp_size = 0;
    if (!get_data_directory(bridge, mod.base, 0, pe32plus, exp_rva, exp_size) || exp_rva == 0) {
        return out;
    }

    auto ed = bridge.read_memory(mod.base + exp_rva, 40);
    if (!ed.has_value() || ed->size() < 40) return out;

    uint32_t ordinal_base = 0, num_funcs = 0, num_names = 0;
    uint32_t addr_funcs = 0, addr_names = 0, addr_ords = 0;
    std::memcpy(&ordinal_base, ed->data() + 16, 4);
    std::memcpy(&num_funcs,    ed->data() + 20, 4);
    std::memcpy(&num_names,    ed->data() + 24, 4);
    std::memcpy(&addr_funcs,   ed->data() + 28, 4);
    std::memcpy(&addr_names,   ed->data() + 32, 4);
    std::memcpy(&addr_ords,    ed->data() + 36, 4);

    constexpr uint32_t kMax = 100000;
    if (num_funcs > kMax || num_names > kMax) return out;
    if (num_funcs == 0) return out;

    auto funcs = bridge.read_memory(mod.base + addr_funcs, static_cast<size_t>(num_funcs) * 4);
    if (!funcs.has_value() || funcs->size() < static_cast<size_t>(num_funcs) * 4) return out;

    // Address -> name. Ordinal-only exports get a synthetic name later.
    std::unordered_map<uint32_t, std::string> name_by_index;

    if (num_names > 0) {
        auto names = bridge.read_memory(mod.base + addr_names, static_cast<size_t>(num_names) * 4);
        auto ords  = bridge.read_memory(mod.base + addr_ords,  static_cast<size_t>(num_names) * 2);
        if (names.has_value() && ords.has_value() &&
            names->size() >= static_cast<size_t>(num_names) * 4 &&
            ords->size()  >= static_cast<size_t>(num_names) * 2) {
            for (uint32_t i = 0; i < num_names; ++i) {
                uint32_t name_rva = 0;
                uint16_t ord_index = 0;
                std::memcpy(&name_rva,  names->data() + i * 4, 4);
                std::memcpy(&ord_index, ords->data()  + i * 2, 2);
                if (name_rva == 0 || ord_index >= num_funcs) continue;
                name_by_index[ord_index] = mem_cstr(bridge, mod.base + name_rva, 512);
            }
        }
    }

    out.entries.reserve(num_funcs);
    for (uint32_t i = 0; i < num_funcs; ++i) {
        uint32_t fn_rva = 0;
        std::memcpy(&fn_rva, funcs->data() + i * 4, 4);
        if (fn_rva == 0) continue;

        // A forwarder (RVA inside the export directory) is not a real address.
        if (fn_rva >= exp_rva && fn_rva < exp_rva + exp_size) continue;

        export_entry e{};
        e.address = mod.base + fn_rva;
        e.ordinal = ordinal_base + i;
        const auto it = name_by_index.find(i);
        if (it != name_by_index.end() && !it->second.empty()) {
            e.name = it->second;
            e.by_ordinal = false;
        } else {
            e.by_ordinal = true;
        }
        out.entries.push_back(std::move(e));
    }

    std::sort(out.entries.begin(), out.entries.end(),
              [](const export_entry& a, const export_entry& b) { return a.address < b.address; });
    return out;
}

// Which module owns `address`, and which export is it?
const export_entry* resolve_pointer(const std::vector<module_exports>& mods,
                                    duint address, const module_exports** owner) {
    for (const auto& m : mods) {
        if (address < m.base || address >= m.base + m.size) continue;
        // Binary search the sorted export table.
        auto lo = std::lower_bound(
            m.entries.begin(), m.entries.end(), address,
            [](const export_entry& e, duint a) { return e.address < a; });
        if (lo != m.entries.end() && lo->address == address) {
            if (owner) *owner = &m;
            return &*lo;
        }
        if (owner) *owner = &m;
        return nullptr;
    }
    return nullptr;
}

// Is the Scylla plugin installed next to x64dbg?
//
// Checked on disk rather than through the command table because
// DbgCmdExecDirect's return value is unreliable for commands that do not exist
// (a garbage command returns true on x32dbg). Scylla ships as Scylla_x64.dp64 /
// Scylla_x86.dp32; a bare Scylla.exe next to the debugger is also treated as
// present so a portable install is not misreported.
bool scylla_plugin_present() {
    char path[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, path, MAX_PATH) == 0) return false;

    std::string dir(path);
    const auto slash = dir.find_last_of("\\/");
    if (slash == std::string::npos) return false;
    dir.resize(slash);

    const char* candidates[] = {
        "\\plugins\\Scylla_x64.dp64",
        "\\plugins\\Scylla_x86.dp32",
        "\\plugins\\Scylla_x64.dll",
        "\\plugins\\Scylla_x86.dll",
        "\\Scylla_x64.exe",
        "\\Scylla.exe",
    };
    for (const auto* rel : candidates) {
        const DWORD attr = GetFileAttributesA((dir + rel).c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            return true;
        }
    }
    return false;
}

} // namespace

void register_dumping_routes(c_http_router& router) {
    // POST /api/dump/module - Dump module to file
    router.post("/api/dump/module", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("module")) {
            return s_http_response::bad_request("Missing 'module' field");
        }

        auto module_name = body["module"].get<std::string>();
        auto file_path = body.value("file", "");

        auto base = bridge.get_module_base(module_name);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module_name);
        }

        // Use x64dbg's savedata command
        auto size = bridge.eval_expression("mod.size(" + module_name + ")");
        std::string cmd;
        if (!file_path.empty()) {
            cmd = "savedata " + file_path + ", " + format_utils::format_address(base) + ", " + format_utils::format_hex(size);
        } else {
            cmd = "savedata :memdump:, " + format_utils::format_address(base) + ", " + format_utils::format_hex(size);
        }

        auto success = bridge.exec_command(cmd);

        return s_http_response::ok({
            {"success", success},
            {"module", module_name},
            {"base", format_utils::format_address(base)},
            {"size", size},
            {"file", file_path.empty() ? "(prompted)" : file_path}
        });
    });

    // GET /api/dump/pe_header?address= - Parse PE header from memory
    router.get("/api/dump/pe_header", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address", "");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto base = bridge.eval_expression(address_str);

        // Read DOS header (first 64 bytes)
        auto dos_header = bridge.read_memory(base, 64);
        if (!dos_header.has_value()) {
            return s_http_response::internal_error("Failed to read DOS header");
        }

        const auto& dos = dos_header.value();
        if (dos.size() < 64 || dos[0] != 'M' || dos[1] != 'Z') {
            return s_http_response::bad_request("Not a valid PE file (no MZ signature)");
        }

        // e_lfanew at offset 0x3C
        DWORD e_lfanew = 0;
        memcpy(&e_lfanew, dos.data() + 0x3C, 4);

        // Read PE signature + headers (enough for COFF + optional header)
        auto pe_header = bridge.read_memory(base + e_lfanew, 264);
        if (!pe_header.has_value()) {
            return s_http_response::internal_error("Failed to read PE header");
        }

        const auto& pe = pe_header.value();
        if (pe.size() < 4 || pe[0] != 'P' || pe[1] != 'E') {
            return s_http_response::bad_request("Invalid PE signature");
        }

        // COFF header starts at offset 4 in PE signature block
        WORD machine = 0;
        memcpy(&machine, pe.data() + 4, 2);

        WORD num_sections = 0;
        memcpy(&num_sections, pe.data() + 6, 2);

        DWORD timestamp = 0;
        memcpy(&timestamp, pe.data() + 8, 4);

        WORD size_of_optional = 0;
        memcpy(&size_of_optional, pe.data() + 20, 2);

        WORD characteristics = 0;
        memcpy(&characteristics, pe.data() + 22, 2);

        nlohmann::json data = {
            {"base",              format_utils::format_address(base)},
            {"e_lfanew",          format_utils::format_address(e_lfanew)},
            {"machine",           format_utils::format_address(machine)},
            {"number_of_sections", num_sections},
            {"timestamp",         timestamp},
            {"characteristics",   format_utils::format_address(characteristics)},
            {"size_of_optional_header", size_of_optional}
        };

        // Optional header starts at offset 24
        if (pe.size() >= 28) {
            WORD magic = 0;
            memcpy(&magic, pe.data() + 24, 2);
            data["magic"] = format_utils::format_address(magic);
            data["is_pe32plus"] = (magic == 0x20B);

            if (magic == 0x10B && pe.size() >= 64) {
                // PE32
                DWORD entry_point = 0;
                memcpy(&entry_point, pe.data() + 40, 4);
                data["address_of_entry_point"] = format_utils::format_address(entry_point);

                DWORD image_base_32 = 0;
                memcpy(&image_base_32, pe.data() + 52, 4);
                data["image_base"] = format_utils::format_address(image_base_32);

                DWORD size_of_image = 0;
                memcpy(&size_of_image, pe.data() + 80, 4);
                data["size_of_image"] = size_of_image;
            } else if (magic == 0x20B && pe.size() >= 88) {
                // PE32+
                DWORD entry_point = 0;
                memcpy(&entry_point, pe.data() + 40, 4);
                data["address_of_entry_point"] = format_utils::format_address(entry_point);

                uint64_t image_base_64 = 0;
                memcpy(&image_base_64, pe.data() + 48, 8);
                data["image_base"] = format_utils::format_address(static_cast<duint>(image_base_64));

                DWORD size_of_image = 0;
                memcpy(&size_of_image, pe.data() + 80, 4);
                data["size_of_image"] = size_of_image;
            }
        }

        return s_http_response::ok(data);
    });

    // GET /api/dump/sections?module= - Get PE sections
    router.get("/api/dump/sections", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module", "");
        if (module_name.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        auto base = bridge.get_module_base(module_name);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module_name);
        }

        // Read DOS header to get e_lfanew
        auto dos = bridge.read_memory(base, 64);
        if (!dos.has_value() || dos.value().size() < 64) {
            return s_http_response::internal_error("Failed to read DOS header");
        }

        DWORD e_lfanew = 0;
        memcpy(&e_lfanew, dos.value().data() + 0x3C, 4);

        // Read PE header to get number of sections and optional header size
        auto pe = bridge.read_memory(base + e_lfanew, 24);
        if (!pe.has_value() || pe.value().size() < 24) {
            return s_http_response::internal_error("Failed to read PE header");
        }

        WORD num_sections = 0;
        memcpy(&num_sections, pe.value().data() + 6, 2);

        WORD optional_size = 0;
        memcpy(&optional_size, pe.value().data() + 20, 2);

        // Section headers start after optional header
        auto section_offset = e_lfanew + 24 + optional_size;
        auto section_data = bridge.read_memory(base + section_offset, num_sections * 40); // IMAGE_SECTION_HEADER is 40 bytes
        if (!section_data.has_value()) {
            return s_http_response::internal_error("Failed to read section headers");
        }

        auto sections = nlohmann::json::array();
        for (WORD i = 0; i < num_sections; ++i) {
            auto* sec = section_data.value().data() + (i * 40);

            char name[9] = {};
            memcpy(name, sec, 8);

            DWORD virtual_size = 0, virtual_addr = 0, raw_size = 0, raw_ptr = 0, chars = 0;
            memcpy(&virtual_size, sec + 8, 4);
            memcpy(&virtual_addr, sec + 12, 4);
            memcpy(&raw_size, sec + 16, 4);
            memcpy(&raw_ptr, sec + 20, 4);
            memcpy(&chars, sec + 36, 4);

            sections.push_back({
                {"name",           std::string(name)},
                {"virtual_address", format_utils::format_address(virtual_addr)},
                {"virtual_size",   virtual_size},
                {"raw_size",       raw_size},
                {"raw_offset",     format_utils::format_address(raw_ptr)},
                {"characteristics", format_utils::format_address(chars)}
            });
        }

        return s_http_response::ok({
            {"module", module_name},
            {"base", format_utils::format_address(base)},
            {"sections", sections},
            {"count", sections.size()}
        });
    });

    // GET /api/dump/imports?module= - Get import table
    router.get("/api/dump/imports", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module", "");
        if (module_name.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        auto base = bridge.get_module_base(module_name);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module_name);
        }

        bool is_pe32plus = false;
        uint32_t imp_rva = 0, imp_size = 0;
        if (!get_data_directory(bridge, base, 1 /*IMAGE_DIRECTORY_ENTRY_IMPORT*/,
                                is_pe32plus, imp_rva, imp_size)) {
            return s_http_response::internal_error("Failed to read PE headers");
        }

        const size_t ptr_size = is_pe32plus ? 8 : 4;
        const uint64_t ord_flag = is_pe32plus ? 0x8000000000000000ULL : 0x80000000ULL;

        auto modules = nlohmann::json::array();
        size_t total_imports = 0;
        constexpr size_t kMaxImports = 50000;

        // Walk the IMAGE_IMPORT_DESCRIPTOR array (20 bytes each), null-terminated.
        for (uint32_t d = 0; imp_rva != 0 && d < 4096; ++d) {
            auto desc = bridge.read_memory(base + imp_rva + static_cast<duint>(d) * 20, 20);
            if (!desc.has_value() || desc->size() < 20) break;

            uint32_t oft = 0, name_rva = 0, ft = 0;
            std::memcpy(&oft,      desc->data() + 0, 4);
            std::memcpy(&name_rva, desc->data() + 12, 4);
            std::memcpy(&ft,       desc->data() + 16, 4);
            if (oft == 0 && name_rva == 0 && ft == 0) break; // terminator

            auto dll = mem_cstr(bridge, base + name_rva, 256);
            auto funcs = nlohmann::json::array();

            uint32_t thunk_array = oft ? oft : ft; // INT preferred, else IAT
            for (uint32_t t = 0; thunk_array != 0 && t < kMaxImports; ++t) {
                duint thunk_addr = base + thunk_array + static_cast<duint>(t) * ptr_size;
                auto raw = bridge.read_memory(thunk_addr, ptr_size);
                if (!raw.has_value() || raw->size() < ptr_size) break;

                uint64_t value = 0;
                std::memcpy(&value, raw->data(), ptr_size);
                if (value == 0) break; // end of this DLL's thunks

                duint iat_addr = base + ft + static_cast<duint>(t) * ptr_size;
                if (value & ord_flag) {
                    funcs.push_back({
                        {"by_ordinal", true},
                        {"ordinal",    static_cast<uint32_t>(value & 0xFFFF)},
                        {"iat",        format_utils::format_address(iat_addr)}
                    });
                } else {
                    uint32_t hint_name_rva = static_cast<uint32_t>(value);
                    uint16_t hint = 0;
                    mem_u16(bridge, base + hint_name_rva, hint);
                    funcs.push_back({
                        {"by_ordinal", false},
                        {"hint",       hint},
                        {"name",       mem_cstr(bridge, base + hint_name_rva + 2)},
                        {"iat",        format_utils::format_address(iat_addr)}
                    });
                }
                if (++total_imports >= kMaxImports) break;
            }

            modules.push_back({
                {"dll",       dll},
                {"functions", funcs},
                {"count",     funcs.size()}
            });
            if (total_imports >= kMaxImports) break;
        }

        return s_http_response::ok({
            {"module",       module_name},
            {"base",         format_utils::format_address(base)},
            {"imports",      modules},
            {"module_count", modules.size()},
            {"import_count", total_imports}
        });
    });

    // GET /api/dump/exports?module= - Get export table
    router.get("/api/dump/exports", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module", "");
        if (module_name.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        auto base = bridge.get_module_base(module_name);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module_name);
        }

        bool is_pe32plus = false;
        uint32_t exp_rva = 0, exp_size = 0;
        if (!get_data_directory(bridge, base, 0 /*IMAGE_DIRECTORY_ENTRY_EXPORT*/,
                                is_pe32plus, exp_rva, exp_size)) {
            return s_http_response::internal_error("Failed to read PE headers");
        }

        auto exports = nlohmann::json::array();
        if (exp_rva != 0) {
            // IMAGE_EXPORT_DIRECTORY (40 bytes)
            auto ed = bridge.read_memory(base + exp_rva, 40);
            if (ed.has_value() && ed->size() >= 40) {
                uint32_t ordinal_base = 0, num_funcs = 0, num_names = 0;
                uint32_t addr_funcs = 0, addr_names = 0, addr_ords = 0;
                std::memcpy(&ordinal_base, ed->data() + 16, 4);
                std::memcpy(&num_funcs,    ed->data() + 20, 4);
                std::memcpy(&num_names,    ed->data() + 24, 4);
                std::memcpy(&addr_funcs,   ed->data() + 28, 4);
                std::memcpy(&addr_names,   ed->data() + 32, 4);
                std::memcpy(&addr_ords,    ed->data() + 36, 4);

                constexpr uint32_t kMax = 50000;
                if (num_names > kMax) num_names = kMax;
                if (num_funcs > kMax) num_funcs = kMax;

                auto names = bridge.read_memory(base + addr_names, static_cast<size_t>(num_names) * 4);
                auto ords  = bridge.read_memory(base + addr_ords,  static_cast<size_t>(num_names) * 2);
                auto funcs = bridge.read_memory(base + addr_funcs, static_cast<size_t>(num_funcs) * 4);

                if (names.has_value() && ords.has_value() && funcs.has_value()) {
                    for (uint32_t i = 0; i < num_names; ++i) {
                        uint32_t name_rva = 0;
                        uint16_t ord_idx = 0;
                        std::memcpy(&name_rva, names->data() + i * 4, 4);
                        std::memcpy(&ord_idx,  ords->data()  + i * 2, 2);
                        if (ord_idx >= num_funcs) continue;

                        uint32_t func_rva = 0;
                        std::memcpy(&func_rva, funcs->data() + ord_idx * 4, 4);

                        bool forwarded = (func_rva >= exp_rva && func_rva < exp_rva + exp_size);
                        nlohmann::json entry = {
                            {"name",      mem_cstr(bridge, base + name_rva)},
                            {"ordinal",   ordinal_base + ord_idx},
                            {"rva",       format_utils::format_address(func_rva)},
                            {"address",   format_utils::format_address(base + func_rva)},
                            {"forwarded", forwarded}
                        };
                        if (forwarded) {
                            entry["forwarder"] = mem_cstr(bridge, base + func_rva);
                        }
                        exports.push_back(std::move(entry));
                    }
                }
            }
        }

        return s_http_response::ok({
            {"module",  module_name},
            {"base",    format_utils::format_address(base)},
            {"exports", exports},
            {"count",   exports.size()}
        });
    });

    // POST /api/dump/fix_iat - IAT reconstruction via the Scylla plugin
    //
    // Scylla is a separate plugin and is often not installed. Two traps here:
    // the old version ignored the command result and always reported success,
    // and DbgCmdExecDirect's return value is not trustworthy for unknown
    // commands either (verified: a garbage command returned true on x32dbg).
    // So the plugin is detected by looking for its module in the plugin
    // directory rather than by probing the command table.
    router.post("/api/dump/fix_iat", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto oep = body.value("oep", "");

        if (oep.empty()) {
            return s_http_response::bad_request("Missing 'oep' (original entry point) field");
        }

        const bool scylla_loaded = scylla_plugin_present();
        if (!scylla_loaded) {
            return s_http_response::conflict(
                "The Scylla plugin is not loaded, so IAT reconstruction is unavailable. "
                "Install Scylla (Scylla_x64.dp64 / Scylla_x86.dp32) into the x64dbg "
                "plugins directory and restart x64dbg. Note that ScyllaHide is a "
                "different plugin - it hides the debugger, it does not rebuild the IAT.");
        }

        const auto cmd = "scylla iatAutoFix " + oep;
        if (!bridge.exec_command(cmd)) {
            return s_http_response::internal_error(
                "Scylla is loaded but rejected 'iatAutoFix " + oep +
                "'. Check that the OEP is inside the main module and that the "
                "process is paused.");
        }

        return s_http_response::ok({
            {"success", true},
            {"oep", oep},
            {"verified", false},
            {"message", "Scylla accepted the IAT fix request. That confirms the command "
                        "ran, not that the IAT is correct - dump the module and validate "
                        "the result before relying on it."}
        });
    });

    // GET /api/dump/relocations?address= - Get relocations for module
    router.get("/api/dump/relocations", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address", "");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);

        BridgeList<DBGRELOCATIONINFO> relocs;
        auto success = DbgFunctions()->ModRelocationsFromAddr(address, &relocs);

        if (!success) {
            return s_http_response::ok({
                {"address", format_utils::format_address(address)},
                {"relocations", nlohmann::json::array()},
                {"count", 0},
                {"message", "No relocations found or relocation data unavailable"}
            });
        }

        auto result = nlohmann::json::array();
        for (int i = 0; i < relocs.Count(); ++i) {
            result.push_back({
                {"rva",  format_utils::format_address(relocs[i].rva)},
                {"type", relocs[i].type},
                {"size", relocs[i].size}
            });
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(address)},
            {"relocations", result},
            {"count", result.size()}
        });
    });

    // POST /api/patches/export_file - Export patches to file
    router.post("/api/patches/export_file", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("filename")) {
            return s_http_response::bad_request("Missing 'filename' field");
        }

        auto filename = body["filename"].get<std::string>();

        // Get all patches
        size_t patch_count = 0;
        DbgFunctions()->PatchEnum(nullptr, &patch_count);

        if (patch_count == 0) {
            return s_http_response::ok({
                {"success", false},
                {"message", "No patches to export"}
            });
        }

        std::vector<DBGPATCHINFO> patches(patch_count);
        DbgFunctions()->PatchEnum(patches.data(), &patch_count);

        char error[MAX_ERROR_SIZE] = {};
        auto result = DbgFunctions()->PatchFile(patches.data(), static_cast<int>(patch_count), filename.c_str(), error);

        return s_http_response::ok({
            {"success",     result > 0},
            {"patch_count", patch_count},
            {"filename",    filename},
            {"error",       std::string(error)}
        });
    });

    // POST /api/dump/rebuild - Rebuild a runnable PE image from the live process
    //
    // `dump/module` is a flat copy of the mapped image: section headers still
    // carry their in-memory VirtualAddress layout, SizeOfRawData does not match
    // what is on disk, and AddressOfEntryPoint still points at the packer stub.
    // A loader will not map that, and tools that parse it (IDA, pefile) read
    // garbage. This route walks the mapped image, copies each section's real
    // bytes to a file-aligned offset, rewrites the headers, and optionally
    // patches in the OEP.
    //
    // Body: { "module": "target.exe", "file": "out.exe", "oep": "0x140001000",
    //         "fix_section_flags": true }
    router.post("/api/dump/rebuild", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) return s_http_response::bad_request("Invalid JSON body");

        const auto module_name = body.value("module", "");
        const auto file_path = body.value("file", "");
        const auto oep_expr = body.value("oep", "");
        const bool fix_flags = body.value("fix_section_flags", true);

        if (module_name.empty()) return s_http_response::bad_request("Missing 'module'");
        if (file_path.empty()) return s_http_response::bad_request("Missing 'file'");

        const auto base = bridge.get_module_base(module_name);
        if (base == 0) return s_http_response::not_found("Module not found: " + module_name);

        // The on-disk path is needed to recover the linker's ImageBase: the
        // live header carries the ASLR address instead.
        std::string module_path;
        {
            BridgeList<Script::Module::ModuleInfo> mods;
            if (Script::Module::GetList(&mods)) {
                for (int i = 0; i < mods.Count(); ++i) {
                    if (mods[i].base != base) continue;
                    if (mods[i].path[0]) module_path = mods[i].path;
                    break;
                }
            }
        }

        // ---- headers -------------------------------------------------------
        auto dos = bridge.read_memory(base, 0x40);
        if (!dos.has_value() || dos->size() < 0x40 || (*dos)[0] != 'M' || (*dos)[1] != 'Z') {
            return s_http_response::internal_error("Not a PE image at module base");
        }
        uint32_t e_lfanew = 0;
        std::memcpy(&e_lfanew, dos->data() + 0x3C, 4);

        // PE sig + COFF + optional header (large enough for PE32 and PE32+).
        auto headers = bridge.read_memory(base + e_lfanew, 24 + 240);
        if (!headers.has_value() || headers->size() < 24 + 112) {
            return s_http_response::internal_error("Cannot read PE headers");
        }
        const uint8_t* pe = headers->data();
        if (pe[0] != 'P' || pe[1] != 'E') {
            return s_http_response::internal_error("Bad PE signature");
        }

        uint16_t num_sections = 0;
        std::memcpy(&num_sections, headers->data() + 6, 2);
        uint16_t opt_size = 0;
        std::memcpy(&opt_size, headers->data() + 20, 2);
        if (num_sections == 0 || num_sections > 96) {
            return s_http_response::internal_error("Implausible section count");
        }

        const size_t opt_off = 24;
        uint16_t magic = 0;
        std::memcpy(&magic, headers->data() + opt_off, 2);
        const bool pe32plus = (magic == 0x20B);

        uint32_t file_align = 0, sect_align = 0, size_of_image = 0;
        uint32_t size_of_headers = 0, entry_rva = 0;
        std::memcpy(&entry_rva, headers->data() + opt_off + 16, 4);
        std::memcpy(&sect_align, headers->data() + opt_off + 32, 4);
        std::memcpy(&file_align, headers->data() + opt_off + 36, 4);
        std::memcpy(&size_of_image, headers->data() + opt_off + 56, 4);
        std::memcpy(&size_of_headers, headers->data() + opt_off + 60, 4);

        // ImageBase in the live image is wherever ASLR put it, not the value the
        // linker recorded. Writing that address into the dump makes the loader
        // believe the file prefers a base the relocation table knows nothing
        // about: if it cannot map there it rebases using deltas computed from
        // the *original* base, so every absolute address in .text ends up wrong
        // and the process dies at start with STATUS_INVALID_IMAGE_FORMAT.
        //
        // Prefer the on-disk value. When the file cannot be read (packed
        // targets are often gone from disk), keep the live value and strip the
        // relocations instead, which is correct for an image whose pointers are
        // already final.
        uint64_t image_base = 0;
        std::memcpy(&image_base, headers->data() + opt_off + 24, pe32plus ? 8 : 4);

        uint64_t original_base = 0;
        if (!module_path.empty()) {
            std::ifstream disk(module_path, std::ios::binary);
            if (disk) {
                std::vector<uint8_t> head(0x400);
                disk.read(reinterpret_cast<char*>(head.data()),
                          static_cast<std::streamsize>(head.size()));
                const auto got = static_cast<size_t>(disk.gcount());
                if (got >= 0x40 && head[0] == 'M' && head[1] == 'Z') {
                    uint32_t pe_off = 0;
                    std::memcpy(&pe_off, head.data() + 0x3C, 4);
                    if (pe_off + 24 + 88 <= got && head[pe_off] == 'P' && head[pe_off + 1] == 'E') {
                        const size_t o = pe_off + 24;
                        uint16_t m = 0;
                        std::memcpy(&m, head.data() + o, 2);
                        const bool dplus = (m == 0x20B);
                        std::memcpy(&original_base, head.data() + o + 24, dplus ? 8 : 4);
                    }
                }
            }
        }

        if (file_align == 0 || file_align > 0x10000 || (file_align & (file_align - 1))) {
            // Packers sometimes leave this bogus. 0x200 is the universal default
            // for x86/x64 images and is what every loader accepts.
            file_align = 0x200;
        }
        if (sect_align == 0) sect_align = 0x1000;

        // The output buffer starts at the module base, so every offset into it is
        // an RVA. The PE header is not at RVA 0 - it starts at e_lfanew, which is
        // why the section table is e_lfanew + 24 + SizeOfOptionalHeader.
        const size_t section_table_off = e_lfanew + opt_off + opt_size;
        const size_t headers_size = section_table_off + static_cast<size_t>(num_sections) * 40;
        const size_t header_bytes = headers_size > size_of_headers ? headers_size : size_of_headers;
        std::vector<uint8_t> out(header_bytes, 0);

        auto img = bridge.read_memory(base, out.size());
        if (!img.has_value()) {
            return s_http_response::internal_error("Cannot read image headers from process");
        }
        std::memcpy(out.data(), img->data(), out.size());

        // ---- sections ------------------------------------------------------
        struct sec_info {
            std::string name;
            uint32_t va, vsize, raw_ptr, raw_size;
            uint32_t characteristics;
        };
        std::vector<sec_info> secs;
        secs.reserve(num_sections);

        for (uint16_t i = 0; i < num_sections; ++i) {
            const size_t off = section_table_off + static_cast<size_t>(i) * 40;
            if (off + 40 > out.size()) break;

            sec_info s{};
            char name[9] = {};
            std::memcpy(name, out.data() + off, 8);
            s.name = name;

            std::memcpy(&s.vsize,   out.data() + off + 8,  4);
            std::memcpy(&s.va,      out.data() + off + 12, 4);
            std::memcpy(&s.raw_size, out.data() + off + 16, 4);
            std::memcpy(&s.raw_ptr,  out.data() + off + 20, 4);
            std::memcpy(&s.characteristics, out.data() + off + 36, 4);

            // A zero VirtualSize means "same as raw size"; a zero raw size means
            // the section occupies only virtual space (e.g. .bss).
            const uint32_t span = s.vsize ? s.vsize : s.raw_size;
            if (span == 0 || s.va == 0) continue;

            // Round the on-disk size up to FileAlignment.
            uint32_t disk_size = (span + file_align - 1) & ~(file_align - 1);
            s.raw_size = disk_size;

            // Skip sections that point outside the mapped image.
            if (static_cast<uint64_t>(s.va) + span > size_of_image + sect_align) {
                s.raw_size = 0;
            }
            secs.push_back(s);
        }
        if (secs.empty()) return s_http_response::internal_error("No usable sections");

        // Assign file offsets in VA order, starting after the headers.
        std::sort(secs.begin(), secs.end(),
                  [](const sec_info& a, const sec_info& b) { return a.va < b.va; });

        size_t raw_cursor = (out.size() + file_align - 1) & ~(static_cast<size_t>(file_align) - 1);
        for (auto& s : secs) {
            if (s.raw_size == 0) { s.raw_ptr = 0; continue; }
            s.raw_ptr = static_cast<uint32_t>(raw_cursor);
            raw_cursor += s.raw_size;
        }

        out.resize(raw_cursor, 0);

        // Copy each section's bytes out of the mapped image.
        nlohmann::json section_report = nlohmann::json::array();
        size_t copied = 0, unreadable = 0;

        for (const auto& s : secs) {
            if (s.raw_size == 0) continue;

            const uint32_t span = s.vsize ? s.vsize : s.raw_size;
            const uint32_t copy_len = std::min<uint32_t>(span, s.raw_size);

            auto data = bridge.read_memory(base + s.va, copy_len);
            if (data.has_value() && data->size() == copy_len) {
                std::memcpy(out.data() + s.raw_ptr, data->data(), copy_len);
                copied++;
            } else {
                // Leave zeros rather than aborting: a partially dumped image is
                // still useful, as long as the caller knows which parts are junk.
                unreadable++;
            }

            section_report.push_back({
                {"name",   s.name},
                {"va",     format_utils::format_address(s.va)},
                {"vsize",  s.vsize},
                {"raw_ptr", format_utils::format_address(s.raw_ptr)},
                {"raw_size", s.raw_size},
                {"readable", data.has_value() && data->size() == copy_len}
            });
        }

        // ---- rewrite the section table -------------------------------------
        // Each header entry is matched back to its layout record by VA+name, so
        // the table keeps its original order. Reordering it would break the
        // section indices that data directories (resources, relocations, TLS)
        // refer to.
        for (uint16_t i = 0; i < num_sections; ++i) {
            const size_t off = section_table_off + static_cast<size_t>(i) * 40;
            if (off + 40 > out.size()) break;

            char name[9] = {};
            std::memcpy(name, out.data() + off, 8);
            uint32_t va = 0;
            std::memcpy(&va, out.data() + off + 12, 4);

            for (const auto& s : secs) {
                if (s.va != va || s.name != name) continue;

                std::memcpy(out.data() + off + 16, &s.raw_size, 4);
                std::memcpy(out.data() + off + 20, &s.raw_ptr, 4);

                if (fix_flags) {
                    // Memory-only permissions must not survive into the file:
                    // a section marked MEM_WRITE|MEM_EXECUTE on disk makes some
                    // scanners and loaders reject the image, and IMAGE_SCN_MEM_WRITE
                    // on .text is a strong packed-file tell.
                    uint32_t chars = s.characteristics;
                    chars &= ~IMAGE_SCN_MEM_WRITE;
                    if (chars & IMAGE_SCN_MEM_EXECUTE) chars |= IMAGE_SCN_MEM_READ;
                    std::memcpy(out.data() + off + 36, &chars, 4);
                }
                break;
            }
        }

        // SizeOfImage must cover the highest section end, page-aligned.
        uint32_t max_end = 0;
        for (const auto& s : secs) {
            const uint32_t end = s.va + ((s.vsize ? s.vsize : s.raw_size) );
            if (end > max_end) max_end = end;
        }
        uint32_t new_image_size = (max_end + sect_align - 1) & ~(sect_align - 1);
        std::memcpy(out.data() + e_lfanew + opt_off + 56, &new_image_size, 4);

        // SizeOfHeaders must cover the whole header region, padded to FileAlignment.
        uint32_t new_headers = static_cast<uint32_t>(
            (headers_size + file_align - 1) & ~(static_cast<size_t>(file_align) - 1));
        std::memcpy(out.data() + e_lfanew + opt_off + 60, &new_headers, 4);

        // ---- ImageBase and relocations -------------------------------------
        //
        // Two cases, and mixing them up is what makes a dump fail to start:
        //   * disk header readable -> restore the linker's ImageBase. The
        //     relocation table in the image still describes that base, so the
        //     loader can rebase correctly.
        //   * no disk file -> keep the live base and strip relocations, because
        //     the pointers in .text are already absolute for that base and
        //     rebasing them again would double-apply the delta.
        nlohmann::json base_report = nlohmann::json::object();

        // Restoring the on-disk base and keeping the relocations was measured to
        // be wrong: the loader then rebases every absolute address that the dump
        // already captured post-relocation, and LoadLibraryEx fails with
        // ERROR_NOACCESS (998). Keep the live base and strip the relocation
        // directory - the pointers in .text are final for that base, and a
        // stripped image is never rebased.
        {
            const size_t dd_reloc = e_lfanew + opt_off + (pe32plus ? 112 : 96) + 5 * 8;
            uint32_t zero[2] = {0, 0};
            std::memcpy(out.data() + dd_reloc, zero, sizeof(zero));

            uint16_t coff = 0;
            std::memcpy(&coff, out.data() + e_lfanew + 22, 2);
            coff |= 0x0001;                       // IMAGE_FILE_RELOCS_STRIPPED
            std::memcpy(out.data() + e_lfanew + 22, &coff, 2);

            base_report = {
                {"image_base",  format_utils::format_address(image_base)},
                {"source",      "live image"},
                {"on_disk_base", original_base ? format_utils::format_address(original_base)
                                               : std::string("(no disk copy)")},
                {"relocations", "stripped - pointers are already absolute for this base"}
            };
        }

        // ---- OEP -----------------------------------------------------------
        nlohmann::json oep_report = nlohmann::json::object();
        bool oep_applied = false;

        if (!oep_expr.empty()) {
            const duint oep_va = bridge.eval_expression(oep_expr);
            if (oep_va > base) {
                uint32_t oep_rva = static_cast<uint32_t>(oep_va - base);
                std::memcpy(out.data() + e_lfanew + opt_off + 16, &oep_rva, 4);
                oep_report = {{"address", format_utils::format_address(oep_va)},
                              {"rva", format_utils::format_address(oep_rva)}};
                oep_applied = true;
            } else {
                oep_report = {{"error", "OEP expression did not resolve inside the module"},
                              {"expression", oep_expr}};
            }
        } else {
            oep_report = {{"value", format_utils::format_address(entry_rva)},
                          {"note", "unchanged - original entry still points at the "
                                   "packer stub. Pass 'oep' to set the real one."}};
        }

        // ---- write ---------------------------------------------------------
        std::ofstream f(file_path, std::ios::binary | std::ios::trunc);
        if (!f) return s_http_response::internal_error("Cannot open output file: " + file_path);
        f.write(reinterpret_cast<const char*>(out.data()),
                static_cast<std::streamsize>(out.size()));
        const bool wrote = f.good();
        f.close();

        if (!wrote) return s_http_response::internal_error("Failed writing " + file_path);

        return s_http_response::ok({
            {"success",        true},
            {"module",         module_name},
            {"file",           file_path},
            {"bytes",          out.size()},
            {"pe32plus",       pe32plus},
            {"file_alignment", file_align},
            {"section_alignment", sect_align},
            {"size_of_image",  new_image_size},
            {"size_of_headers", new_headers},
            {"sections",       section_report},
            {"sections_copied", copied},
            {"sections_unreadable", unreadable},
            {"oep",            oep_report},
            {"oep_applied",    oep_applied},
            {"image_base",     base_report},
            {"note", unreadable
                ? "Some sections could not be read; they were zero-filled."
                : "All sections copied. The IAT is NOT rebuilt by this route - "
                  "use 'rebuild_iats' to write a new import table, or fix_iat "
                  "(requires Scylla)."}
        });
    });

    // POST /api/dump/rebuild_iats - Rebuild the import table from live memory
    //
    // The missing half of a dump: dump/rebuild produces a structurally valid PE
    // whose import directory still describes the *packed* state (usually empty
    // or pointing at the packer's stub), so the image cannot load. This walks
    // the loaded modules' export tables and rewrites a real import directory.
    //
    // Unlike the Scylla path this needs no external plugin, and it works on a
    // running (not paused-at-OEP) process because it reads what the loader
    // already resolved.
    //
    // Body: { "module": "target.exe", "file": "out.exe",
    //         "scan_hint": "0x..." (optional IAT range start),
    //         "scan_size": 4096 (optional, default 64 KB) }
    router.post("/api/dump/rebuild_iats", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) return s_http_response::bad_request("Invalid JSON body");

        const auto module_name = body.value("module", "");
        const auto file_path   = body.value("file", "");
        if (module_name.empty()) return s_http_response::bad_request("Missing 'module'");
        if (file_path.empty())   return s_http_response::bad_request("Missing 'file'");

        const auto base = bridge.get_module_base(module_name);
        if (base == 0) return s_http_response::not_found("Module not found: " + module_name);

        // -------- gather every loaded module's exports ----------------------
        BridgeList<Script::Module::ModuleInfo> mods;
        if (!Script::Module::GetList(&mods)) {
            return s_http_response::internal_error("Cannot enumerate loaded modules");
        }

        std::vector<module_exports> exports;
        exports.reserve(mods.Count());
        for (int i = 0; i < mods.Count(); ++i) {
            auto parsed = collect_exports(bridge, mods[i]);
            if (!parsed.entries.empty()) exports.push_back(std::move(parsed));
        }

        // -------- collect the IAT entries we need to describe ---------------
        // module name -> ordered list of (name, ordinal) for that module.
        struct import_ref {
            std::string module;
            std::string name;       // empty when by ordinal
            uint32_t ordinal = 0;
            bool by_ordinal = false;
        };

        std::vector<import_ref> imports;
        std::unordered_map<std::string, size_t> seen;   // dedupe "mod!name"
        size_t unresolved = 0;

        // `force_module` overrides the module name taken from the owner of the
        // pointer. The descriptor's own DLL name wins when it is known, because
        // that string is what the loader resolves; the owning module is only
        // used to find the export name.
        auto add_pointer = [&](duint slot_value, duint slot_address,
                               const std::string* force_module = nullptr) {
            const module_exports* owner = nullptr;
            const export_entry* hit = resolve_pointer(exports, slot_value, &owner);
            if (!hit) {
                if (slot_value != 0) ++unresolved;
                return;
            }
            import_ref r;
            r.module = force_module && !force_module->empty() ? *force_module : owner->name;
            if (hit->by_ordinal || hit->name.empty()) {
                r.by_ordinal = true;
                r.ordinal = hit->ordinal;
            } else {
                r.name = hit->name;
            }
            const auto key = r.module + "!" +
                             (r.by_ordinal ? ("#" + std::to_string(r.ordinal)) : r.name);
            if (seen.emplace(key, imports.size()).second) {
                imports.push_back(std::move(r));
            }
            (void)slot_address;
        };

        // Source 1: the import descriptors still present in memory. These give
        // the intended DLL grouping and ordering, which keeps the rebuilt table
        // close to what the linker produced.
        bool pe32plus = false;
        uint32_t imp_rva = 0, imp_size = 0;
        const bool have_descriptors =
            get_data_directory(bridge, base, 1, pe32plus, imp_rva, imp_size) && imp_rva != 0;

        if (have_descriptors) {
            for (uint32_t d = 0; d < 4096; ++d) {
                auto desc = bridge.read_memory(base + imp_rva + static_cast<duint>(d) * 20, 20);
                if (!desc.has_value() || desc->size() < 20) break;

                uint32_t oft = 0, name_rva = 0, ft = 0;
                std::memcpy(&oft,      desc->data() + 0,  4);
                std::memcpy(&name_rva, desc->data() + 12, 4);
                std::memcpy(&ft,       desc->data() + 16, 4);
                if (oft == 0 && name_rva == 0 && ft == 0) break;

                const auto dll = mem_cstr(bridge, base + name_rva, 256);
                if (dll.empty() || ft == 0) continue;

                const size_t ptr = pe32plus ? 8 : 4;
                if (d == 0) (void)ptr;

                for (uint32_t t = 0; t < 65536; ++t) {
                    auto raw = bridge.read_memory(base + ft + static_cast<duint>(t) * ptr, ptr);
                    if (!raw.has_value() || raw->size() < ptr) break;
                    uint64_t value = 0;
                    std::memcpy(&value, raw->data(), ptr);
                    if (value == 0) break;

                    // Keep the descriptor's own DLL name. A loader import is
                    // resolved by the name written here, and API-set names
                    // ("api-ms-win-core-...") must stay as they are: replacing
                    // them with the resolved host module (kernelbase, ntdll)
                    // produces a table the loader rejects at process start.
                    add_pointer(static_cast<duint>(value),
                                base + ft + static_cast<duint>(t) * ptr, &dll);
                }
            }
        }

        // Source 2: scan a range of the image for pointers into other modules.
        // Recovers entries a packer removed from the descriptors.
        duint scan_start = base;
        size_t scan_size = 0;
        if (body.contains("scan_hint")) {
            scan_start = bridge.eval_expression(body["scan_hint"].get<std::string>());
            scan_size = body.value("scan_size", static_cast<size_t>(64 * 1024));
        } else if (body.contains("scan_size")) {
            scan_size = body.value("scan_size", static_cast<size_t>(64 * 1024));
        }
        if (scan_start == 0) scan_start = base;
        if (scan_size > 16u * 1024 * 1024) scan_size = 16u * 1024 * 1024;
        scan_size &= ~static_cast<size_t>(7);

        size_t scanned_slots = 0;
        if (scan_size >= 8) {
            auto blob = bridge.read_memory(scan_start, scan_size);
            if (blob.has_value()) {
                const auto& b = *blob;
                for (size_t off = 0; off + 8 <= b.size(); off += 8) {
                    uint64_t value = 0;
                    std::memcpy(&value, b.data() + off, 8);
                    ++scanned_slots;
                    add_pointer(static_cast<duint>(value), scan_start + off);
                }
            }
        }

        if (imports.empty()) {
            return s_http_response::internal_error(
                "No importable entries found. The imports in this process are resolved "
                "through a private table that does not point at any loaded module's "
                "exports - pass scan_hint pointing at the real IAT to search there.");
        }

        // -------- pack the import directory --------------------------------
        // Layout: descriptor array, then per-DLL name strings, then the ILT
        // (thunk) arrays, then the IAT arrays, then hint/name entries.
        const size_t ptr = pe32plus ? 8 : 4;
        const uint64_t ord_flag = pe32plus ? 0x8000000000000000ULL : 0x80000000ULL;

        std::vector<std::pair<std::string, std::vector<const import_ref*>>> by_module;
        for (const auto& r : imports) {
            auto it = std::find_if(by_module.begin(), by_module.end(),
                                   [&](const auto& p) { return p.first == r.module; });
            if (it == by_module.end()) by_module.push_back({r.module, {&r}});
            else it->second.push_back(&r);
        }

        std::vector<uint8_t> idata;
        auto align_up = [](std::vector<uint8_t>& v, size_t a) {
            while (v.size() % a) v.push_back(0);
        };
        auto put32 = [](std::vector<uint8_t>& v, uint32_t x) {
            const size_t o = v.size(); v.resize(o + 4);
            std::memcpy(v.data() + o, &x, 4);
        };
        auto put64 = [](std::vector<uint8_t>& v, uint64_t x) {
            const size_t o = v.size(); v.resize(o + 8);
            std::memcpy(v.data() + o, &x, 8);
        };

        const size_t desc_bytes = (by_module.size() + 1) * 20;
        idata.resize(desc_bytes, 0);

        align_up(idata, 2);
        std::vector<uint32_t> dll_name_rva;
        for (const auto& [name, _] : by_module) {
            dll_name_rva.push_back(static_cast<uint32_t>(idata.size()));
            idata.insert(idata.end(), name.begin(), name.end());
            idata.push_back(0);
        }

        // Every thunk slot is pointer-sized on both tables: the loader reads the
        // ILT and the IAT with the same width, so reserving 4 bytes for a
        // name-based entry on x64 shifts every following entry and corrupts the
        // whole section. Reserve ptr bytes for every slot, terminator included.
        auto put_slot = [&](uint64_t v) {
            if (ptr == 8) put64(idata, v);
            else          put32(idata, static_cast<uint32_t>(v));
        };

        align_up(idata, ptr);
        std::vector<uint32_t> ilt_rva, iat_rva;
        for (const auto& [name, list] : by_module) {
            ilt_rva.push_back(static_cast<uint32_t>(idata.size()));
            for (const auto* r : list) {
                // Values are filled in below, once hint/name RVAs are known.
                put_slot(r->by_ordinal ? (ord_flag | r->ordinal) : 0);
            }
            put_slot(0);            // terminator
        }
        align_up(idata, ptr);
        for (const auto& [name, list] : by_module) {
            iat_rva.push_back(static_cast<uint32_t>(idata.size()));
            for (size_t i = 0; i < list.size(); ++i) put_slot(0);
            put_slot(0);
        }

        // Hint/name records, then backfill both the ILT and the IAT with the
        // address of each record (the loader replaces the IAT at load time).
        std::unordered_map<std::string, uint32_t> hint_rva;
        for (const auto& [name, list] : by_module) {
            for (const auto* r : list) {
                if (r->by_ordinal) continue;
                const auto key = r->module + "!" + r->name;
                if (hint_rva.count(key)) continue;
                align_up(idata, 2);
                hint_rva[key] = static_cast<uint32_t>(idata.size());
                const size_t o = idata.size();
                idata.resize(o + 2 + r->name.size() + 1);
                idata[o] = 0; idata[o + 1] = 0;          // hint
                std::memcpy(idata.data() + o + 2, r->name.data(), r->name.size());
                idata[o + 2 + r->name.size()] = 0;
            }
        }

        for (size_t m = 0; m < by_module.size(); ++m) {
            const auto& list = by_module[m].second;
            for (size_t k = 0; k < list.size(); ++k) {
                const auto* r = list[k];
                if (r->by_ordinal) continue;   // already written at reserve time

                const auto key = r->module + "!" + r->name;
                const uint64_t rva = hint_rva[key];
                const size_t off = k * ptr;
                if (ptr == 8) {
                    std::memcpy(idata.data() + ilt_rva[m] + off, &rva, 8);
                    std::memcpy(idata.data() + iat_rva[m] + off, &rva, 8);
                } else {
                    const uint32_t rva32 = static_cast<uint32_t>(rva);
                    std::memcpy(idata.data() + ilt_rva[m] + off, &rva32, 4);
                    std::memcpy(idata.data() + iat_rva[m] + off, &rva32, 4);
                }
            }
        }

        // Descriptors.
        //
        // Everything packed above is written relative to the start of .idata,
        // but PE fields are RVAs. The section's VirtualAddress is not known yet
        // (it is computed below from the image layout), so the base is patched
        // in afterwards rather than guessed here.
        for (size_t m = 0; m < by_module.size(); ++m) {
            const size_t off = m * 20;
            const uint32_t oft = ilt_rva[m];
            const uint32_t name_rva = dll_name_rva[m];
            const uint32_t ft = iat_rva[m];
            std::memcpy(idata.data() + off +  0, &oft, 4);
            std::memcpy(idata.data() + off + 12, &name_rva, 4);
            std::memcpy(idata.data() + off + 16, &ft, 4);
        }

        // -------- write the .idata section into a copy of the image ---------
        std::error_code ec;
        std::ifstream in(file_path, std::ios::binary);
        if (!in) {
            return s_http_response::internal_error(
                "Cannot open '" + file_path + "' - run dump/rebuild first to produce "
                "the base image, then rebuild the IAT into it.");
        }
        std::vector<uint8_t> out((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
        in.close();

        if (out.size() < 0x40 || out[0] != 'M' || out[1] != 'Z') {
            return s_http_response::internal_error("Output file is not a PE image");
        }
        uint32_t e_lfanew = 0;
        std::memcpy(&e_lfanew, out.data() + 0x3C, 4);
        if (e_lfanew + 24 > out.size()) return s_http_response::internal_error("Bad e_lfanew");

        uint16_t nsec = 0, optsz = 0;
        std::memcpy(&nsec,  out.data() + e_lfanew + 6,  2);
        std::memcpy(&optsz, out.data() + e_lfanew + 20, 2);

        const size_t opt = e_lfanew + 24;
        uint16_t magic = 0;
        std::memcpy(&magic, out.data() + opt, 2);
        const bool file_pe32plus = (magic == 0x20B);
        if (file_pe32plus != pe32plus) {
            return s_http_response::internal_error(
                "File architecture differs from the running process");
        }

        uint32_t sect_align = 0, file_align = 0, size_of_image = 0, size_of_headers = 0;
        std::memcpy(&sect_align,     out.data() + opt + 32, 4);
        std::memcpy(&file_align,     out.data() + opt + 36, 4);
        std::memcpy(&size_of_image,  out.data() + opt + 56, 4);
        std::memcpy(&size_of_headers, out.data() + opt + 60, 4);
        if (sect_align == 0) sect_align = 0x1000;
        if (file_align == 0) file_align = 0x200;

        const size_t sect_table = opt + optsz;
        if (sect_table + static_cast<size_t>(nsec) * 40 > out.size()) {
            return s_http_response::internal_error("Section table out of bounds");
        }

        // Find the highest VA currently in use.
        uint32_t max_va_end = 0;
        for (uint16_t i = 0; i < nsec; ++i) {
            const size_t o = sect_table + static_cast<size_t>(i) * 40;
            uint32_t vsize = 0, va = 0;
            std::memcpy(&vsize, out.data() + o + 8,  4);
            std::memcpy(&va,    out.data() + o + 12, 4);
            const uint32_t end = va + vsize;
            if (end > max_va_end) max_va_end = end;
        }
        const uint32_t new_va = (max_va_end + sect_align - 1) & ~(sect_align - 1);

        // ---- where does the IAT have to live? ------------------------------
        // Code in .text calls through the IAT by absolute address
        // (`call [rip+disp]`), so the thunk array has to sit at the RVA the
        // code already uses. Those addresses came from the original import
        // directory, so reuse that directory's FirstThunk when it is inside a
        // section we can write into. Building a fresh IAT elsewhere produces a
        // file that parses correctly and then fails at process start with
        // STATUS_INVALID_IMAGE_FORMAT, because every call still goes to the old
        // slots.
        uint32_t old_first_thunk = 0;
        if (have_descriptors) {
            auto first = bridge.read_memory(base + imp_rva, 20);
            if (first.has_value() && first->size() >= 20) {
                std::memcpy(&old_first_thunk, first->data() + 16, 4);
            }
        }

        bool patch_in_place = false;
        if (old_first_thunk != 0) {
            for (uint16_t i = 0; i < nsec; ++i) {
                const size_t o = sect_table + static_cast<size_t>(i) * 40;
                uint32_t vsize = 0, va = 0, raw_size = 0, raw_ptr = 0, chars = 0;
                std::memcpy(&vsize,   out.data() + o + 8,  4);
                std::memcpy(&va,      out.data() + o + 12, 4);
                std::memcpy(&raw_size, out.data() + o + 16, 4);
                std::memcpy(&raw_ptr,  out.data() + o + 20, 4);
                std::memcpy(&chars,    out.data() + o + 36, 4);

                const uint32_t span = vsize ? vsize : raw_size;
                if (old_first_thunk < va || old_first_thunk >= va + span) continue;

                // Make the section writable on disk so the loader can fill the
                // thunks; .rdata is read-only in the original image.
                chars |= 0x80000000u;            // IMAGE_SCN_MEM_WRITE
                std::memcpy(out.data() + o + 36, &chars, 4);
                patch_in_place = true;
                break;
            }
        }

        // Now that the section's RVA is known, convert every packed offset into
        // a real RVA. Descriptor fields, ILT entries and IAT entries all hold
        // these; the hint/name records are addressed the same way.
        auto add_base32 = [new_va](std::vector<uint8_t>& buf, size_t off) {
            uint32_t v = 0;
            std::memcpy(&v, buf.data() + off, 4);
            if (v == 0) return;
            v += new_va;
            std::memcpy(buf.data() + off, &v, 4);
        };
        auto add_base_thunk = [&](std::vector<uint8_t>& buf, size_t off) {
            if (pe32plus) {
                uint64_t v = 0;
                std::memcpy(&v, buf.data() + off, 8);
                if (v == 0 || (v & ord_flag)) return;   // terminator / ordinal
                v += new_va;
                std::memcpy(buf.data() + off, &v, 8);
            } else {
                add_base32(buf, off);
            }
        };

        for (size_t m = 0; m < by_module.size(); ++m) {
            const size_t desc = m * 20;
            add_base32(idata, desc + 0);    // OriginalFirstThunk
            add_base32(idata, desc + 12);   // Name
            add_base32(idata, desc + 16);   // FirstThunk

            const auto& list = by_module[m].second;
            for (size_t k = 0; k < list.size(); ++k) {
                add_base_thunk(idata, ilt_rva[m] + k * ptr);
                add_base_thunk(idata, iat_rva[m] + k * ptr);
            }
        }

        // In-place mode: every descriptor's FirstThunk is rewritten to point at
        // a slice of the *original* IAT, so the addresses .text already calls
        // through become the loader's fill targets.
        if (patch_in_place) {
            uint32_t cursor = old_first_thunk;
            for (size_t m = 0; m < by_module.size(); ++m) {
                const size_t desc = m * 20;
                std::memcpy(idata.data() + desc + 16, &cursor, 4);   // FirstThunk (RVA)
                cursor += static_cast<uint32_t>((by_module[m].second.size() + 1) * ptr);
                if (cursor != old_first_thunk && (cursor - old_first_thunk) > 0x10000) {
                    // The original table is smaller than what we need to write.
                    // Fall back to the private array rather than corrupt memory
                    // past the end of the old IAT.
                    patch_in_place = false;
                    break;
                }
            }
        }

        const uint32_t idata_vsize = static_cast<uint32_t>(idata.size());
        const uint32_t idata_raw_size = (idata_vsize + file_align - 1) & ~(file_align - 1);
        const uint32_t idata_raw_ptr = static_cast<uint32_t>(
            (out.size() + file_align - 1) & ~(static_cast<size_t>(file_align) - 1));

        const size_t new_sect_off = sect_table + static_cast<size_t>(nsec) * 40;
        const size_t needed = new_sect_off + 40;
        if (needed > size_of_headers) {
            // Header growth must stay inside the first raw section's offset.
            const uint32_t new_hdr = static_cast<uint32_t>(
                (needed + file_align - 1) & ~(static_cast<size_t>(file_align) - 1));
            if (new_hdr > file_align * 4) {
                return s_http_response::internal_error(
                    "No room for another section header next to the existing ones");
            }
            out.resize(std::max<size_t>(out.size(), new_hdr), 0);
            std::memcpy(out.data() + opt + 60, &new_hdr, 4);
            size_of_headers = new_hdr;
        }
        if (out.size() < needed) out.resize(needed, 0);

        uint8_t* sh = out.data() + new_sect_off;
        std::memset(sh, 0, 40);
        std::memcpy(sh, ".idata", 6);
        std::memcpy(sh + 8,  &idata_vsize,    4);   // VirtualSize
        std::memcpy(sh + 12, &new_va,         4);   // VirtualAddress
        std::memcpy(sh + 16, &idata_raw_size, 4);   // SizeOfRawData
        std::memcpy(sh + 20, &idata_raw_ptr,  4);   // PointerToRawData
        // IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE. Spelled out
        // because the minimal SDK does not define these macros.
        constexpr uint32_t SCN_CNT_INITIALIZED_DATA = 0x00000040;
        constexpr uint32_t SCN_MEM_READ             = 0x40000000;
        constexpr uint32_t SCN_MEM_WRITE            = 0x80000000;
        const uint32_t chars =
            SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE;
        std::memcpy(sh + 36, &chars, 4);

        std::memcpy(out.data() + e_lfanew + 6, &++nsec, 2);

        // Data directories: [1] import table, [12] IAT.
        //
        // The IAT directory still pointed into .rdata at the old table's size.
        // That entry is not merely cosmetic: the loader validates it (it must
        // describe a writable region), and leaving it stale made the image fail
        // with STATUS_INVALID_IMAGE_FORMAT at start despite a valid import
        // directory.
        const size_t dd_base = opt + (file_pe32plus ? 112 : 96);

        std::memcpy(out.data() + dd_base + 1 * 8,     &new_va,      4);
        std::memcpy(out.data() + dd_base + 1 * 8 + 4, &idata_vsize, 4);

        // The IAT directory must describe the array the descriptors actually
        // point at. In in-place mode that is the original table inside .rdata,
        // not the private copy in .idata - a mismatch here is rejected by the
        // loader even when both arrays are individually valid.
        uint32_t iat_va = 0, iat_size = 0;
        if (patch_in_place) {
            uint32_t end_exclusive = old_first_thunk;
            for (size_t m = 0; m < by_module.size(); ++m) {
                uint32_t ft = 0;
                std::memcpy(&ft, idata.data() + m * 20 + 16, 4);
                const uint32_t stop =
                    ft + static_cast<uint32_t>((by_module[m].second.size() + 1) * ptr);
                if (stop > end_exclusive) end_exclusive = stop;
            }
            iat_va = old_first_thunk;
            iat_size = end_exclusive - old_first_thunk;
        } else {
            uint32_t iat_begin = 0, iat_end = 0;
            for (size_t m = 0; m < by_module.size(); ++m) {
                const uint32_t start = iat_rva[m];
                const uint32_t stop  = start +
                    static_cast<uint32_t>((by_module[m].second.size() + 1) * ptr);
                if (iat_begin == 0 || start < iat_begin) iat_begin = start;
                if (stop > iat_end) iat_end = stop;
            }
            iat_va = new_va + iat_begin;
            iat_size = iat_end - iat_begin;
        }
        std::memcpy(out.data() + dd_base + 12 * 8,     &iat_va,   4);
        std::memcpy(out.data() + dd_base + 12 * 8 + 4, &iat_size, 4);

        const uint32_t new_image = (new_va + idata_vsize + sect_align - 1) & ~(sect_align - 1);
        std::memcpy(out.data() + opt + 56, &new_image, 4);

        out.resize(idata_raw_ptr);
        out.insert(out.end(), idata.begin(), idata.end());
        out.resize(idata_raw_ptr + idata_raw_size, 0);

        std::ofstream f(file_path, std::ios::binary | std::ios::trunc);
        if (!f) return s_http_response::internal_error("Cannot write " + file_path);
        f.write(reinterpret_cast<const char*>(out.data()),
                static_cast<std::streamsize>(out.size()));
        const bool wrote = f.good();
        f.close();
        if (!wrote) return s_http_response::internal_error("Failed writing " + file_path);

        nlohmann::json dlls = nlohmann::json::array();
        for (const auto& [name, list] : by_module) {
            dlls.push_back({{"dll", name}, {"functions", list.size()}});
        }

        return s_http_response::ok({
            {"success",       true},
            {"file",          file_path},
            {"modules",       dlls},
            {"module_count",  by_module.size()},
            {"import_count",  imports.size()},
            {"unresolved",    unresolved},
            {"scanned_slots", scanned_slots},
            {"used_descriptors", have_descriptors},
            {"idata_rva",     format_utils::format_hex(new_va)},
            {"idata_size",    idata_vsize},
            {"size_of_image", new_image},
            {"note", unresolved
                ? "Some pointers did not resolve to a loaded module's export and were "
                  "left out; the image may still need manual fixes."
                : "Every resolved pointer mapped to a real export."}
        });
    });

    // GET /api/dump/entry_point?module= - Get entry point of module
    router.get("/api/dump/entry_point", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module", "");
        if (module_name.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        auto base = bridge.get_module_base(module_name);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module_name);
        }

        auto entry = bridge.eval_expression("mod.entry(" + module_name + ")");

        return s_http_response::ok({
            {"module", module_name},
            {"base", format_utils::format_address(base)},
            {"entry_point", format_utils::format_address(entry)},
            {"rva", format_utils::format_address(entry - base)}
        });
    });

    // GET /api/dump/detect_oep - Heuristic original-entry-point search
    //
    // Packers leave the PE entry pointing at the unpacking stub. The real OEP
    // usually starts with a standard compiler prologue and sits just after a
    // run of padding (CC / 00 / 90). This scans the main module's executable
    // sections for those patterns and ranks them. It is a heuristic, not proof:
    // confirm the candidate by breakpointing it and letting the target run.
    router.get("/api/dump/detect_oep", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        BridgeList<Script::Module::ModuleSectionInfo> sections;
        if (!Script::Module::GetMainModuleSectionList(&sections)) {
            return s_http_response::internal_error("Cannot enumerate main module sections");
        }

        const duint entry = Script::Module::GetMainModuleEntry();
        char module_name[MAX_MODULE_SIZE] = {};
        Script::Module::GetMainModuleName(module_name);

        // Common prologues. 32-bit: push ebp; mov ebp,esp / mov edi,edi; push ebp...
        // 64-bit: sub rsp,imm8 / mov [rsp+x],rbx / push rbx / mov rax,rsp.
        struct prologue { const uint8_t* bytes; size_t len; };
        static const uint8_t p32a[] = {0x55, 0x8B, 0xEC};
        static const uint8_t p32b[] = {0x55, 0x89, 0xE5};
        static const uint8_t p32c[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};
        static const uint8_t p64a[] = {0x48, 0x83, 0xEC};
        static const uint8_t p64b[] = {0x48, 0x89, 0x5C, 0x24};
        static const uint8_t p64c[] = {0x48, 0x81, 0xEC};
        static const uint8_t p64d[] = {0x40, 0x53};
        static const prologue prologues[] = {
            {p32a, sizeof(p32a)}, {p32b, sizeof(p32b)}, {p32c, sizeof(p32c)},
            {p64a, sizeof(p64a)}, {p64b, sizeof(p64b)}, {p64c, sizeof(p64c)},
            {p64d, sizeof(p64d)}
        };

        struct candidate {
            duint addr;
            std::string section;
            int score;
            size_t offset;
        };
        std::vector<candidate> found;

        for (int s = 0; s < sections.Count(); ++s) {
            const auto& sec = sections[s];
            // Only executable sections matter, and skip tiny ones.
            if (sec.size < 64) continue;
            if (!DbgFunctions()->MemIsCodePage(sec.addr, false)) continue;

            // Cap the scan per section so a huge .text cannot stall the plugin.
            const size_t scan = std::min<size_t>(sec.size, 8 * 1024 * 1024);
            auto bytes = bridge.read_memory(sec.addr, scan);
            if (!bytes.has_value()) continue;

            for (size_t i = 0; i + 8 < bytes->size(); ++i) {
                for (const auto& p : prologues) {
                    if (i + p.len > bytes->size()) continue;
                    if (std::memcmp(bytes->data() + i, p.bytes, p.len) != 0) continue;

                    int score = 0;
                    // Padding immediately before the prologue is a strong hint.
                    const uint8_t prev = i > 0 ? (*bytes)[i - 1] : 0;
                    if (prev == 0xCC || prev == 0x00 || prev == 0x90) score += 3;
                    // Candidates far from the current entry are more interesting
                    // for a packed binary (the stub is at the entry).
                    const duint addr = sec.addr + i;
                    if (addr > entry + 0x100) score += 1;
                    // Section-start candidates are usually the packer stub.
                    if (i < 0x200) score -= 2;

                    found.push_back({addr, sec.name, score, i});
                    i += p.len - 1;
                    break;
                }
            }
        }

        std::sort(found.begin(), found.end(), [](const candidate& a, const candidate& b) {
            return a.score != b.score ? a.score > b.score : a.addr < b.addr;
        });

        auto candidates = nlohmann::json::array();
        for (size_t i = 0; i < found.size() && i < 16; ++i) {
            candidates.push_back({
                {"address", format_utils::format_address(found[i].addr)},
                {"section", found[i].section},
                {"score",   found[i].score},
                {"offset",  found[i].offset}
            });
        }

        return s_http_response::ok({
            {"module",            module_name},
            {"current_entry",     format_utils::format_address(entry)},
            {"candidate_count",   found.size()},
            {"candidates",        candidates},
            {"note",              "heuristic only - breakpoint a candidate and let the target run to confirm"}
        });
    });
}

} // namespace handlers
