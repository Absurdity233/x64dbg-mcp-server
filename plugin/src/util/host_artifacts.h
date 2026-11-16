#pragma once

// What a virtualisation check actually reads on this host.
//
// This is the "what will the target see" side of anti-VM work. Every published
// VM-detection check reduces to one of a few dozen host-observable facts:
// registry keys installed by the guest tools, service names, a MAC OUI, a disk
// model string, an ACPI table signature, a device path, a window class, a
// process name. Listing them turns "the target behaves differently in the VM"
// into "the target reads this key, and here is its value".
//
// Nothing here modifies the host: it is a read-only survey. That is deliberate.
// The bypass that follows from it is per-check and belongs in the target's own
// view (the anti_vm stubs in the debugger), not in a machine-wide change that
// would also hide the VM from the tooling you are using to analyse it.

#include <nlohmann/json.hpp>

namespace host_artifacts {

// A full survey grouped by category. Cheap enough to run on demand: registry
// reads against a fixed key list, one WMI-free device enumeration, one process
// list. No network, no service control, no writes.
nlohmann::json survey();

} // namespace host_artifacts
