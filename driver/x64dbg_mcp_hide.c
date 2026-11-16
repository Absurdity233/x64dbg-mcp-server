/*++
    x64dbg_mcp_hide.c - kernel-mode anti-anti-debug helper for the x64dbg MCP
    plugin.

    Plain WDM, x64 only, C. No KMDF, no WDF headers, no C++.

    WHAT THIS DRIVER DOES
    ---------------------
    A user-mode debugger (x64dbg) holds a debug object and a handle to the
    debuggee. The parts of the debug relation that user mode cannot reach live
    in EPROCESS:

        EPROCESS.DebugPort        - what NtQueryInformationProcess(
                                    ProcessDebugPort = 7) reports, and what
                                    PsIsProcessBeingDebugged() tests.
        EPROCESS.Flags            - the dword containing NoDebugInherit, which
                                    is what NtQueryInformationProcess(
                                    ProcessDebugFlags = 0x1F) inverts.

    Clearing DebugPort does not disturb the debugger: the debug object handle
    belongs to the debugger process, and debug-event delivery is driven by that
    object, not by a fresh read of the debuggee's EPROCESS.DebugPort.

    THE OFFSETS ARE RESOLVED AT RUNTIME
    -----------------------------------
    PsGetProcessDebugPort is an exported one-line accessor. We find it with
    MmGetSystemRoutineAddress and decode its prologue. Verified encodings on
    x64 (WDK 10.0.26100 / Win11 26100 and 26200):

        48 8B 81 <disp32>   mov rax,[rcx+disp32]   <- 26100 / 26200
        48 8B 89 <disp32>   mov rcx,[rcx+disp32]
        8B 81   <disp32>    mov eax,[rcx+disp32]
        8B 41   <disp8>     mov eax,[rcx+disp8]

    The decoded offset is then validated against the current process: the
    driver runs in the System process, whose DebugPort is always NULL, so a
    correct offset reads 0 and a misdecoded instruction almost certainly does
    not.

    EPROCESS.Flags has no exported accessor, so its offset can only be
    supplied by user mode. When it is not supplied, X64MCP_HIDE_FLAGS is
    reported as FAILED rather than written to a guessed address.

    No WDK was installed on the machine this was authored on, so the file could
    not be compiled there. Everything below was written against
    WDK 10.0.26100 + MSVC v143 and self-reviewed; see README.md for the
    checklist and for the assumptions that need a compile to confirm.
--*/

#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
/* Needed for CTL_CODE, which the shared header uses for the IOCTL numbers. */
#include <devioctl.h>

/* The shared ABI header keys its kernel-only sections off _KERNEL_MODE. */
#ifndef _KERNEL_MODE
#define _KERNEL_MODE 1
#endif

#include "x64dbg_mcp_hide.h"

/* ------------------------------------------------------------------------- */
/* Constants                                                                 */
/* ------------------------------------------------------------------------- */

#define X64MCP_BUILD_NUMBER   1

/* Device class GUID for IoCreateDeviceSecure. A private GUID is correct here:
   this is not a device class with an installer, and reusing a system GUID risks
   colliding with a real class key. */
static const GUID X64MCP_DEVICE_CLASS_GUID =
    { 0x6f1c2a44, 0x8d19, 0x4b7e, { 0x9a, 0x31, 0x5c, 0x0e, 0x77, 0xb2, 0x4d, 0x18 } };

/* Bit inside EPROCESS.Flags that NtQueryInformationProcess(ProcessDebugFlags)
   inverts. Taken from the kernel's own code path on 26100/26200:

       mov  eax, [rcx+1F4h]     ; EPROCESS.Flags
       shr  eax, 1              ; -> NoDebugInherit is bit 1
       not  eax
       and  eax, 1              ; DebugFlags = !NoDebugInherit

   Cross-checked against a live measurement on Win11 26200:

       clean process                DebugFlags = 1  -> NoDebugInherit = 0
       process under DebugActiveProcess  DebugFlags = 0  -> NoDebugInherit = 1

   So a DEBUGBEE has NoDebugInherit = 1, and looking clean means CLEARING the
   bit. The name reads backwards ("no debug inherit" is set while being
   debugged) because it records the inherit setting, not the debug state; the
   measurement above is what settles the direction. */
#define X64MCP_FLAGS_NODEBUGINHERIT_MASK   0x00000002UL

/* Offset sanity bounds. A real EPROCESS.DebugPort sits at 0x308 on every
   recent x64 build; the window leaves room for layout drift without letting a
   wild value through. */
#define X64MCP_MIN_EP_OFFSET   0x100UL
#define X64MCP_MAX_EP_OFFSET   0x1000UL

/* Reject these PIDs outright: they are not debuggable, and poking them is how
   a lab tool bug becomes a bugcheck. */
#define X64MCP_PID_IDLE        0UL
#define X64MCP_PID_SYSTEM      4UL

/* ------------------------------------------------------------------------- */
/* Per-target record                                                         */
/* ------------------------------------------------------------------------- */

typedef struct _X64MCP_STATE {
    ULONG   pid;                   /* 0 = nothing attached */
    ULONG64 applied;               /* flags currently applied */
    ULONG64 saved_debugport;       /* original EPROCESS.DebugPort value */
    ULONG   saved_flags;           /* original EPROCESS.Flags dword */
    ULONG   saved_crosssession;    /* original cross-session dword */
    ULONG   ep_debugport_offset;   /* offsets in effect for the applied set */
    ULONG   ep_flags_offset;
    ULONG   ep_crosssession_offset;
    ULONG   last_offset_source;    /* X64MCP_OFFSET_SOURCE_* of the last apply */
    ULONG   os_build;
    ULONG   errors;                /* cumulative failed-operation count */
} X64MCP_STATE, *PX64MCP_STATE;

/* One global record, guarded by an ERESOURCE.

   An ERESOURCE is the right primitive here: every path that touches this
   record (IOCTL dispatch, IRP_MJ_CLEANUP, DriverUnload) runs at PASSIVE_LEVEL,
   so the lock may block, and the critical sections are short and contain no
   blocking calls. A spin lock or a bare global IRQL would be wrong: the lock
   is acquired in one function and released in another, so carrying the
   previous IRQL in a global would corrupt the release on a multi-core box. */
static X64MCP_STATE g_State;
static ERESOURCE    g_StateLock;
static BOOLEAN      g_StateLockInitialized = FALSE;

static PDEVICE_OBJECT g_DeviceObject = NULL;
static BOOLEAN        g_SymlinkCreated = FALSE;

/* Resolved once in DriverEntry (single-threaded) and read-only afterwards, so
   these need no lock. */
static ULONG g_EpDebugPortOffset = 0;
static ULONG g_EpFlagsOffset = 0;
static ULONG g_FlagsSource = X64MCP_OFFSET_SOURCE_UNRESOLVED;
static ULONG g_OsBuild = 0;

/* Cached at load: the accessor we decoded, used to type-safely read the
   target's DebugPort without trusting a hand-rolled pointer arithmetic path
   for every probe. */
typedef ULONG64 (*X64MCP_PFN_GET_DEBUG_PORT)(_In_ PEPROCESS Process);
static X64MCP_PFN_GET_DEBUG_PORT g_PsGetProcessDebugPort = NULL;

/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */

static VOID
X64McpLock(VOID)
{
    if (g_StateLockInitialized) {
        ExAcquireResourceExclusiveLite(&g_StateLock, TRUE);
    }
}

static VOID
X64McpUnlock(VOID)
{
    if (g_StateLockInitialized) {
        ExReleaseResourceLite(&g_StateLock);
    }
}

static VOID
X64McpLog(
    _In_ PCSTR Format,
    ...
    )
{
    va_list args;

    /* Every message carries the tag so the output is greppable in DbgView. */
    DbgPrint("[%s] ", X64MCP_HIDE_TAG);

    va_start(args, Format);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, args);
    va_end(args);
}

/* Resolve the running OS build number once. Failure is not fatal. */
static ULONG
X64McpQueryOsBuild(VOID)
{
    RTL_OSVERSIONINFOW vi;
    NTSTATUS status;

    RtlZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);

    status = RtlGetVersion(&vi);
    if (!NT_SUCCESS(status)) {
        return 0;
    }
    return vi.dwBuildNumber;
}

/* ------------------------------------------------------------------------- */
/* Offset resolution                                                         */
/* ------------------------------------------------------------------------- */

/*
  Decode a "load from [rcx+disp]" prologue and return the displacement.

  Handles the four encodings the x64 compiler emits for a trivial accessor:

      48 8B 81 <disp32>   mov rax,[rcx+disp32]
      48 8B 89 <disp32>   mov rcx,[rcx+disp32]
      8B 81   <disp32>    mov eax,[rcx+disp32]
      8B 41   <disp8>     mov eax,[rcx+disp8]

  Returns TRUE and sets *Offset on a recognised prologue.
*/
static BOOLEAN
X64McpDecodeAccessor(
    _In_ const UCHAR *Code,
    _Out_ PULONG Offset
    )
{
    ULONG value = 0;
    BOOLEAN found = FALSE;

    /* 48 8B 81 / 48 8B 89 : REX.W + mov r64, [rcx+disp32] */
    if (Code[0] == 0x48 && Code[1] == 0x8B && (Code[2] == 0x81 || Code[2] == 0x89)) {
        value = (ULONG)Code[3] |
                ((ULONG)Code[4] << 8) |
                ((ULONG)Code[5] << 16) |
                ((ULONG)Code[6] << 24);
        found = TRUE;
    }
    /* 8B 81 : mov eax,[rcx+disp32] */
    else if (Code[0] == 0x8B && Code[1] == 0x81) {
        value = (ULONG)Code[2] |
                ((ULONG)Code[3] << 8) |
                ((ULONG)Code[4] << 16) |
                ((ULONG)Code[5] << 24);
        found = TRUE;
    }
    /* 8B 41 : mov eax,[rcx+disp8] */
    else if (Code[0] == 0x8B && Code[1] == 0x41) {
        value = (ULONG)Code[2];
        found = TRUE;
    }

    if (!found) {
        return FALSE;
    }

    *Offset = value;
    return TRUE;
}

/*
  Validate a candidate EPROCESS.DebugPort offset against the one process whose
  DebugPort is guaranteed NULL: the System process, which the driver runs in
  and which is never debugged.

  Also requires 4-byte alignment and a sane range, so a misdecoded instruction
  cannot become an arbitrary kernel write later.
*/
static BOOLEAN
X64McpValidateDebugPortOffset(
    _In_ ULONG Offset
    )
{
    PEPROCESS self;
    ULONG64 value = 0;

    if (Offset == 0) {
        return FALSE;
    }
    if ((Offset & 0x3) != 0) {
        return FALSE;
    }
    if (Offset < X64MCP_MIN_EP_OFFSET || Offset > X64MCP_MAX_EP_OFFSET) {
        return FALSE;
    }

    self = PsGetCurrentProcess();
    if (self == NULL) {
        return FALSE;
    }

    __try {
        value = *(volatile ULONG64 *)((PUCHAR)self + Offset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return (value == 0);
}

/*
  Resolve EPROCESS.DebugPort from the PsGetProcessDebugPort export, decode it,
  validate it, and keep a typed pointer to the accessor.
*/
static BOOLEAN
X64McpResolveDebugPortOffset(VOID)
{
    UNICODE_STRING name;
    PVOID routine;
    ULONG candidate = 0;

    RtlInitUnicodeString(&name, L"PsGetProcessDebugPort");

    routine = MmGetSystemRoutineAddress(&name);
    if (routine == NULL) {
        X64McpLog("PsGetProcessDebugPort not exported on this build\n");
        return FALSE;
    }

    if (!X64McpDecodeAccessor((const UCHAR *)routine, &candidate)) {
        X64McpLog("PsGetProcessDebugPort prologue not recognised\n");
        return FALSE;
    }

    if (!X64McpValidateDebugPortOffset(candidate)) {
        X64McpLog("candidate DebugPort offset 0x%X failed validation\n", candidate);
        return FALSE;
    }

    g_PsGetProcessDebugPort = (X64MCP_PFN_GET_DEBUG_PORT)routine;
    g_EpDebugPortOffset = candidate;
    return TRUE;
}

/*
  EPROCESS.Flags has no exported getter, so this offset cannot be derived the
  way DebugPort can. It is only ever taken from the caller, validated, and
  otherwise left at zero so the corresponding flag fails loudly instead of
  writing somewhere arbitrary.
*/
static BOOLEAN
X64McpResolveFlagsOffset(
    _In_ ULONG Supplied,
    _Out_ PULONG Offset,
    _Out_ PULONG Source
    )
{
    *Offset = 0;
    *Source = X64MCP_OFFSET_SOURCE_UNRESOLVED;

    if (Supplied == 0) {
        return FALSE;
    }
    if ((Supplied & 0x3) != 0 ||
        Supplied < X64MCP_MIN_EP_OFFSET ||
        Supplied > X64MCP_MAX_EP_OFFSET) {
        X64McpLog("supplied flags offset 0x%X out of range\n", Supplied);
        return FALSE;
    }

    *Offset = Supplied;
    *Source = X64MCP_OFFSET_SOURCE_SUPPLIED;
    return TRUE;
}

/* ------------------------------------------------------------------------- */
/* Apply / revert                                                            */
/* ------------------------------------------------------------------------- */

/*
  Put every field we changed back to its original value.

  Runs from IRP_MJ_CLEANUP (last close) and from DriverUnload. Idempotent: a
  second call finds nothing recorded and does nothing.

  Reference discipline: PsLookupProcessByProcessId on every path is paired with
  exactly one ObDereferenceObject, including the early-exit paths.
*/
static VOID
X64McpRevertAll(
    _In_ PCSTR Reason
    )
{
    X64MCP_STATE snapshot;
    PEPROCESS process = NULL;
    NTSTATUS status;

    X64McpLock();
    snapshot = g_State;
    RtlZeroMemory(&g_State, sizeof(g_State));
    X64McpUnlock();

    if (snapshot.pid == 0 || snapshot.applied == 0) {
        return;
    }
    if (snapshot.pid == X64MCP_PID_IDLE || snapshot.pid == X64MCP_PID_SYSTEM) {
        return;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(snapshot.pid), &process);
    if (!NT_SUCCESS(status)) {
        /* The target is gone; its address space went with it. Nothing to
           restore, so this is a normal outcome, not an error. */
        X64McpLog("revert(%s): pid %u gone (0x%08X), nothing to restore\n",
                  Reason, snapshot.pid, status);
        return;
    }

    if ((snapshot.applied & X64MCP_HIDE_DEBUGPORT) != 0 &&
        snapshot.ep_debugport_offset != 0) {
        __try {
            *(volatile ULONG64 *)((PUCHAR)process + snapshot.ep_debugport_offset) =
                snapshot.saved_debugport;
            X64McpLog("revert(%s): DebugPort restored to 0x%I64x\n",
                      Reason, snapshot.saved_debugport);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            X64McpLog("revert(%s): DebugPort write faulted\n", Reason);
        }
    }

    if ((snapshot.applied & X64MCP_HIDE_FLAGS) != 0 &&
        snapshot.ep_flags_offset != 0) {
        __try {
            *(volatile ULONG *)((PUCHAR)process + snapshot.ep_flags_offset) =
                snapshot.saved_flags;
            X64McpLog("revert(%s): Flags restored to 0x%08x\n",
                      Reason, snapshot.saved_flags);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            X64McpLog("revert(%s): Flags write faulted\n", Reason);
        }
    }

    if ((snapshot.applied & X64MCP_HIDE_CROSSSESSION) != 0 &&
        snapshot.ep_crosssession_offset != 0) {
        __try {
            *(volatile ULONG *)((PUCHAR)process + snapshot.ep_crosssession_offset) =
                snapshot.saved_crosssession;
            X64McpLog("revert(%s): cross-session dword restored\n", Reason);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            X64McpLog("revert(%s): cross-session write faulted\n", Reason);
        }
    }

    ObDereferenceObject(process);
}

/*
  Clear/normalise the requested fields on a referenced process, remembering the
  original values so revert can put them back.
*/
static NTSTATUS
X64McpApplyToProcess(
    _In_ PEPROCESS Process,
    _In_ ULONG Pid,
    _In_ const X64MCP_APPLY_REQ *Request,
    _Out_ PX64MCP_STATUS StatusOut
    )
{
    ULONG64 mask = Request->mask;
    ULONG64 applied = 0;
    ULONG64 failed = 0;
    ULONG flagsOffset = 0;
    ULONG flagsSource = X64MCP_OFFSET_SOURCE_UNRESOLVED;
    ULONG crossOffset = 0;
    ULONG savedFlags = 0;
    ULONG newFlags = 0;
    ULONG crossSaved = 0;
    ULONG64 oldDebugPort = 0;

    RtlZeroMemory(StatusOut, sizeof(*StatusOut));

    /* --- EPROCESS.DebugPort ------------------------------------------- */
    if ((mask & X64MCP_HIDE_DEBUGPORT) != 0) {
        if (g_EpDebugPortOffset == 0) {
            failed |= X64MCP_HIDE_DEBUGPORT;
            X64McpLog("apply: DebugPort offset unresolved, bit not applied\n");
        }
        else {
            BOOLEAN faulted = FALSE;

            __try {
                oldDebugPort = *(volatile ULONG64 *)((PUCHAR)Process + g_EpDebugPortOffset);
                *(volatile ULONG64 *)((PUCHAR)Process + g_EpDebugPortOffset) = 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                faulted = TRUE;
            }

            if (faulted) {
                failed |= X64MCP_HIDE_DEBUGPORT;
            }
            else {
                applied |= X64MCP_HIDE_DEBUGPORT;
                X64McpLog("apply: pid %u DebugPort 0x%I64x -> 0\n",
                          Pid, oldDebugPort);
            }
        }
    }

    /* --- EPROCESS.Flags : NoDebugInherit ------------------------------- */
    if ((mask & X64MCP_HIDE_FLAGS) != 0) {
        if (!X64McpResolveFlagsOffset(Request->ep_flags_offset,
                                      &flagsOffset, &flagsSource)) {
            failed |= X64MCP_HIDE_FLAGS;
            X64McpLog("apply: flags offset not supplied/valid, bit not applied\n");
        }
        else {
            BOOLEAN faulted = FALSE;

            __try {
                savedFlags = *(volatile ULONG *)((PUCHAR)Process + flagsOffset);
                /* A debuggee has NoDebugInherit = 1; clear it so
                   ProcessDebugFlags reads back 1 ("not being debugged"). */
                newFlags = savedFlags & ~X64MCP_FLAGS_NODEBUGINHERIT_MASK;
                *(volatile ULONG *)((PUCHAR)Process + flagsOffset) = newFlags;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                faulted = TRUE;
            }

            if (faulted) {
                failed |= X64MCP_HIDE_FLAGS;
                savedFlags = 0;
                newFlags = 0;
            }
            else {
                applied |= X64MCP_HIDE_FLAGS;
                X64McpLog("apply: pid %u Flags 0x%08x -> 0x%08x (NoDebugInherit cleared)\n",
                          Pid, savedFlags, newFlags);
            }
        }
    }

    /* --- cross-session dword ------------------------------------------ */
    if ((mask & X64MCP_HIDE_CROSSSESSION) != 0) {
        if (Request->ep_crosssession_offset == 0 ||
            (Request->ep_crosssession_offset & 0x3) != 0 ||
            Request->ep_crosssession_offset < X64MCP_MIN_EP_OFFSET ||
            Request->ep_crosssession_offset > X64MCP_MAX_EP_OFFSET) {
            failed |= X64MCP_HIDE_CROSSSESSION;
            X64McpLog("apply: cross-session offset not supplied/valid, bit not applied\n");
        }
        else {
            BOOLEAN faulted = FALSE;

            crossOffset = Request->ep_crosssession_offset;
            __try {
                crossSaved = *(volatile ULONG *)((PUCHAR)Process + crossOffset);
                *(volatile ULONG *)((PUCHAR)Process + crossOffset) = 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                faulted = TRUE;
            }

            if (faulted) {
                failed |= X64MCP_HIDE_CROSSSESSION;
                crossSaved = 0;
            }
            else {
                applied |= X64MCP_HIDE_CROSSSESSION;
                X64McpLog("apply: pid %u cross-session 0x%08x -> 0\n",
                          Pid, crossSaved);
            }
        }
    }

    /* --- KPROCESS.DebugActive ----------------------------------------- */
    /* Deliberately not attempted. KPROCESS is kernel-private with no stable
       layout, no exported accessor, and writing it is a PatchGuard hazard for
       no benefit - no ring-3 reader consults DebugActive. Reported as failed
       so user mode can see the bit was not honoured. */
    if ((mask & X64MCP_HIDE_KDPRINT) != 0) {
        failed |= X64MCP_HIDE_KDPRINT;
        X64McpLog("apply: KDPRINT not supported on this driver\n");
    }

    /* --- publish ------------------------------------------------------ */
    X64McpLock();
    g_State.pid = Pid;
    g_State.applied = applied;
    g_State.saved_debugport = oldDebugPort;
    g_State.saved_flags = savedFlags;
    g_State.saved_crosssession = crossSaved;
    g_State.ep_debugport_offset = g_EpDebugPortOffset;
    g_State.ep_flags_offset = flagsOffset;
    g_State.ep_crosssession_offset = crossOffset;
    g_State.last_offset_source = flagsSource;
    g_State.os_build = g_OsBuild;
    if (failed != 0) {
        g_State.errors++;
    }
    X64McpUnlock();

    StatusOut->pid = Pid;
    StatusOut->applied = applied;
    StatusOut->failed = failed;
    StatusOut->ep_debugport_offset = g_EpDebugPortOffset;
    StatusOut->ep_flags_offset = flagsOffset;
    StatusOut->os_build = g_OsBuild;
    StatusOut->errors = (failed != 0) ? 1 : 0;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* IRP handlers                                                              */
/* ------------------------------------------------------------------------- */

static NTSTATUS
X64McpCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
X64McpClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
  Last close: restore everything. This is the safety net that keeps the
  debuggee from being left modified when the plugin exits or crashes without
  sending DETACH.
*/
static NTSTATUS
X64McpCleanup(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    X64McpRevertAll("cleanup");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* GET_VERSION */
static NTSTATUS
X64McpGetVersion(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    PX64MCP_VERSION out;

    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(X64MCP_VERSION)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    out = (PX64MCP_VERSION)Irp->AssociatedIrp.SystemBuffer;
    if (out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(out, sizeof(*out));
    out->abi = X64MCP_HIDE_ABI;
    out->build = X64MCP_BUILD_NUMBER;
    out->os_build = g_OsBuild;
    out->ep_debugport_offset = g_EpDebugPortOffset;
    out->ep_flags_offset = g_EpFlagsOffset;
    out->flags_source = g_FlagsSource;

    /* Bounded copy: never overruns the fixed 32-byte array. */
    (VOID)RtlStringCchCopyA(out->tag, RTL_NUMBER_OF(out->tag), X64MCP_HIDE_TAG);

    Irp->IoStatus.Information = sizeof(X64MCP_VERSION);
    return STATUS_SUCCESS;
}

/* ATTACH: prove the pid is live, then record it. */
static NTSTATUS
X64McpAttach(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    PX64MCP_ATTACH_REQ req;
    PEPROCESS process = NULL;
    NTSTATUS status;
    ULONG pid;

    if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(X64MCP_ATTACH_REQ)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    req = (PX64MCP_ATTACH_REQ)Irp->AssociatedIrp.SystemBuffer;
    if (req == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    pid = req->pid;
    if (pid == X64MCP_PID_IDLE || pid == X64MCP_PID_SYSTEM) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* The returned reference proves the EPROCESS is a live process object and
       keeps it alive across the check; it is released exactly once here. */
    if (g_PsGetProcessDebugPort != NULL) {
        (VOID)g_PsGetProcessDebugPort(process);
    }
    ObDereferenceObject(process);

    X64McpLock();
    g_State.pid = pid;
    g_State.os_build = g_OsBuild;
    X64McpUnlock();

    X64McpLog("attach pid %u\n", pid);

    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/* DETACH: revert and forget. */
static NTSTATUS
X64McpDetach(
    _In_ PIRP Irp
    )
{
    X64McpRevertAll("detach");
    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/* APPLY */
static NTSTATUS
X64McpApply(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    PX64MCP_APPLY_REQ req;
    PX64MCP_STATUS statusOut;
    X64MCP_APPLY_REQ local;
    PEPROCESS process = NULL;
    NTSTATUS status;
    ULONG pid;

    if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(X64MCP_APPLY_REQ)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(X64MCP_STATUS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    req = (PX64MCP_APPLY_REQ)Irp->AssociatedIrp.SystemBuffer;
    if (req == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* METHOD_BUFFERED shares one system buffer between input and output, and
       X64MCP_STATUS is larger than X64MCP_APPLY_REQ, so the request is copied
       out before anything writes the response back over it. */
    RtlCopyMemory(&local, req, sizeof(local));

    if (local.mask == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((local.mask & ~X64MCP_HIDE_ALL_KNOWN) != 0) {
        X64McpLog("apply: unknown mask bits 0x%I64x ignored\n",
                  local.mask & ~X64MCP_HIDE_ALL_KNOWN);
    }

    X64McpLock();
    pid = g_State.pid;
    X64McpUnlock();

    if (pid == 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (pid == X64MCP_PID_IDLE || pid == X64MCP_PID_SYSTEM) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
    if (!NT_SUCCESS(status)) {
        X64McpLog("apply: cannot reference pid %u (0x%08X)\n", pid, status);
        return status;
    }

    statusOut = (PX64MCP_STATUS)Irp->AssociatedIrp.SystemBuffer;
    status = X64McpApplyToProcess(process, pid, &local, statusOut);

    /* Single dereference, matching the single reference above, on both the
       success path and the failure path. */
    ObDereferenceObject(process);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    Irp->IoStatus.Information = sizeof(X64MCP_STATUS);
    return STATUS_SUCCESS;
}

/* QUERY */
static NTSTATUS
X64McpQuery(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack
    )
{
    PX64MCP_STATUS out;

    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(X64MCP_STATUS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    out = (PX64MCP_STATUS)Irp->AssociatedIrp.SystemBuffer;
    if (out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    X64McpLock();
    RtlZeroMemory(out, sizeof(*out));
    out->pid = g_State.pid;
    out->applied = g_State.applied;
    out->failed = 0;
    out->ep_debugport_offset = g_State.ep_debugport_offset;
    out->ep_flags_offset = g_State.ep_flags_offset;
    out->os_build = g_State.os_build;
    out->errors = g_State.errors;
    X64McpUnlock();

    Irp->IoStatus.Information = sizeof(X64MCP_STATUS);
    return STATUS_SUCCESS;
}

static NTSTATUS
X64McpDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    NTSTATUS status;
    ULONG controlCode;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
    case IOCTL_X64MCP_GET_VERSION:
        status = X64McpGetVersion(Irp, stack);
        break;

    case IOCTL_X64MCP_ATTACH:
        status = X64McpAttach(Irp, stack);
        break;

    case IOCTL_X64MCP_DETACH:
        status = X64McpDetach(Irp);
        break;

    case IOCTL_X64MCP_APPLY:
        status = X64McpApply(Irp, stack);
        break;

    case IOCTL_X64MCP_QUERY:
        status = X64McpQuery(Irp, stack);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    /* Exactly one IoCompleteRequest per IRP, and a status on every path. A
       failure must not claim bytes were returned, so Information is cleared
       here rather than trusted from the handler. */
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Information = 0;
    }
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

/* ------------------------------------------------------------------------- */
/* Unload                                                                    */
/* ------------------------------------------------------------------------- */

static VOID
X64McpUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symlink;

    UNREFERENCED_PARAMETER(DriverObject);

    /* Revert before tearing down, so the debuggee is never left modified. */
    X64McpRevertAll("unload");

    if (g_SymlinkCreated) {
        RtlInitUnicodeString(&symlink, X64MCP_HIDE_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlink);
        g_SymlinkCreated = FALSE;
    }

    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    if (g_StateLockInitialized) {
        ExDeleteResourceLite(&g_StateLock);
        g_StateLockInitialized = FALSE;
    }

    X64McpLog("unloaded\n");
}

/* ------------------------------------------------------------------------- */
/* DriverEntry                                                               */
/* ------------------------------------------------------------------------- */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_State, sizeof(g_State));
    g_SymlinkCreated = FALSE;
    g_DeviceObject = NULL;
    g_StateLockInitialized = FALSE;

    status = ExInitializeResourceLite(&g_StateLock);
    if (!NT_SUCCESS(status)) {
        X64McpLog("ExInitializeResourceLite failed 0x%08X\n", status);
        return status;
    }
    g_StateLockInitialized = TRUE;

    g_OsBuild = X64McpQueryOsBuild();

    /* --- resolve offsets ---------------------------------------------- */
    if (X64McpResolveDebugPortOffset()) {
        g_FlagsSource = X64MCP_OFFSET_SOURCE_AUTO;
        X64McpLog("resolved DebugPort offset 0x%X (build %u)\n",
                  g_EpDebugPortOffset, g_OsBuild);
    }
    else {
        g_EpDebugPortOffset = 0;
        g_FlagsSource = X64MCP_OFFSET_SOURCE_UNRESOLVED;
        X64McpLog("WARNING: DebugPort offset unresolved on build %u; "
                  "X64MCP_HIDE_DEBUGPORT will report failure\n", g_OsBuild);
    }

    /* No exported accessor exists for EPROCESS.Flags, so it starts unresolved
       and is supplied per-apply by user mode. */
    g_EpFlagsOffset = 0;

    /* --- device ------------------------------------------------------- */

    /* The device is created with IoCreateDeviceSecure and an SDDL descriptor.

       WHY THIS AND NOT RtlCreateSecurityDescriptor BY HAND: SDDL is the
       documented way to express exactly this DACL, and IoCreateDeviceSecure
       installs it atomically at creation, so the device is never briefly
       reachable under the default descriptor. Hand-building the same DACL with
       RtlCreateAcl/RtlAddAccessAllowedAceEx/RtlSetDaclSecurityDescriptor means
       sizing three SIDs and two ACEs by hand and then attaching the result to
       an existing object with an undocumented helper - more code, more ways to
       get the size arithmetic wrong, and no upside. SDDL_DEVOBJ_SYS_ALL_ADM_ALL
       grants SYSTEM and Administrators full access and denies everyone else,
       which is precisely the intended policy. */
    RtlInitUnicodeString(&deviceName, X64MCP_HIDE_DEVICE_NAME);

    status = IoCreateDeviceSecure(
                DriverObject,
                0,
                &deviceName,
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_SECURE_OPEN,
                TRUE,                       /* exclusive */
                SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                &X64MCP_DEVICE_CLASS_GUID,
                &g_DeviceObject);

    if (!NT_SUCCESS(status)) {
        X64McpLog("IoCreateDeviceSecure failed 0x%08X\n", status);
        ExDeleteResourceLite(&g_StateLock);
        g_StateLockInitialized = FALSE;
        return status;
    }

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&symlinkName, X64MCP_HIDE_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        X64McpLog("IoCreateSymbolicLink failed 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        ExDeleteResourceLite(&g_StateLock);
        g_StateLockInitialized = FALSE;
        return status;
    }
    g_SymlinkCreated = TRUE;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = X64McpCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = X64McpClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = X64McpCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = X64McpDeviceControl;
    DriverObject->DriverUnload = X64McpUnload;

    X64McpLog("loaded (abi %u, build %u)\n", X64MCP_HIDE_ABI, X64MCP_BUILD_NUMBER);

    return STATUS_SUCCESS;
}
