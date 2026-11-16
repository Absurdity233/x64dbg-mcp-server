/*++
    x64dbg_mcp_hide.h - shared ABI between the x64dbg MCP plugin (user mode)
    and the x64dbg_mcp_hide kernel driver.

    This header is included by BOTH sides. Kernel-only material is guarded by
    _KERNEL_MODE so the same file can be dropped into a user-mode project that
    only needs the IOCTL codes and the request/response structs.

    ABI version is carried in X64MCP_VERSION.abi and must match on both sides;
    bump X64MCP_HIDE_ABI whenever a struct layout changes.
--*/

#ifndef X64DBG_MCP_HIDE_H
#define X64DBG_MCP_HIDE_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

/* ------------------------------------------------------------------------- */
/* Device naming                                                             */
/* ------------------------------------------------------------------------- */

#define X64MCP_HIDE_DEVICE_NAME      L"\\Device\\x64dbg_mcp_hide"
#define X64MCP_HIDE_SYMLINK_NAME     L"\\??\\x64dbg_mcp_hide"
#define X64MCP_HIDE_USER_PATH        L"\\\\.\\x64dbg_mcp_hide"

#define X64MCP_HIDE_ABI              1
#define X64MCP_HIDE_TAG              "x64mcp-hide"

/* ------------------------------------------------------------------------- */
/* IOCTL codes                                                               */
/* ------------------------------------------------------------------------- */

#define X64MCP_IOCTL(idx)  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + (idx), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_X64MCP_GET_VERSION   X64MCP_IOCTL(0)   /* out: X64MCP_VERSION */
#define IOCTL_X64MCP_ATTACH        X64MCP_IOCTL(1)   /* in:  X64MCP_ATTACH_REQ */
#define IOCTL_X64MCP_DETACH        X64MCP_IOCTL(2)   /* none */
#define IOCTL_X64MCP_APPLY         X64MCP_IOCTL(3)   /* in:  X64MCP_APPLY_REQ -> out: X64MCP_STATUS */
#define IOCTL_X64MCP_QUERY         X64MCP_IOCTL(4)   /* out: X64MCP_STATUS */

/* ------------------------------------------------------------------------- */
/* Flags                                                                     */
/* ------------------------------------------------------------------------- */

/* clear EPROCESS.DebugPort (the read that NtQueryInformationProcess class 7
   and PsIsProcessBeingDebugged both perform) */
#define X64MCP_HIDE_DEBUGPORT       0x00000001ULL
/* normalise the no-debug-inherit debug bit (NtQueryInformationProcess class
   0x1F, ProcessDebugFlags). NOTE: this bit is inverted relative to its name -
   1 means "not being debugged" - so the driver SETS it rather than clearing
   it. See README "What it does and does not do". */
#define X64MCP_HIDE_FLAGS           0x00000002ULL
/* clear the cross-session debug flags dword, when the running build has one
   at a caller-supplied offset */
#define X64MCP_HIDE_CROSSSESSION    0x00000004ULL
/* clear KPROCESS.DebugActive ("kernel debugger is active for me") */
#define X64MCP_HIDE_KDPRINT         0x00000008ULL

#define X64MCP_HIDE_ALL_KNOWN       (X64MCP_HIDE_DEBUGPORT | X64MCP_HIDE_FLAGS | \
                                     X64MCP_HIDE_CROSSSESSION | X64MCP_HIDE_KDPRINT)

/* ------------------------------------------------------------------------- */
/* Offset provenance - reported in X64MCP_VERSION.flags_source              */
/* ------------------------------------------------------------------------- */

#define X64MCP_OFFSET_SOURCE_AUTO        0   /* resolved by export + disassembly */
#define X64MCP_OFFSET_SOURCE_SUPPLIED    1   /* taken from the request struct */
#define X64MCP_OFFSET_SOURCE_UNRESOLVED  2   /* not known on this build */

/* ------------------------------------------------------------------------- */
/* Structures - user mode and kernel must agree byte-for-byte               */
/* ------------------------------------------------------------------------- */

#pragma pack(push, 8)

typedef struct _X64MCP_VERSION {
    ULONG abi;                    /* X64MCP_HIDE_ABI the driver was built with */
    ULONG build;                  /* driver build counter, bumped by hand */
    ULONG os_build;               /* RtlGetVersion().dwBuildNumber */
    ULONG ep_debugport_offset;    /* resolved EPROCESS.DebugPort offset, 0 = unknown */
    ULONG ep_flags_offset;        /* resolved flags/debug-bit offset, 0 = unknown */
    ULONG flags_source;           /* X64MCP_OFFSET_SOURCE_* */
    CHAR  tag[32];                /* NUL-terminated "x64mcp-hide" */
} X64MCP_VERSION, *PX64MCP_VERSION;

typedef struct _X64MCP_ATTACH_REQ {
    ULONG pid;
    ULONG reserved;
} X64MCP_ATTACH_REQ, *PX64MCP_ATTACH_REQ;

typedef struct _X64MCP_APPLY_REQ {
    ULONG64 mask;                  /* X64MCP_HIDE_* bits to apply */
    ULONG   ep_flags_offset;       /* 0 = auto / not used for this apply */
    ULONG   ep_crosssession_offset;/* 0 = auto / not used for this apply */
    ULONG   reserved;
} X64MCP_APPLY_REQ, *PX64MCP_APPLY_REQ;

typedef struct _X64MCP_STATUS {
    ULONG   pid;                   /* target pid, 0 = nothing attached */
    ULONG64 applied;               /* flags currently applied */
    ULONG64 failed;                /* flags requested but not applied */
    ULONG   ep_debugport_offset;   /* offset in effect for this apply, 0 = unknown */
    ULONG   ep_flags_offset;       /* offset in effect for this apply, 0 = unknown */
    ULONG   os_build;              /* RtlGetVersion().dwBuildNumber */
    ULONG   errors;                /* count of failed operations since load */
} X64MCP_STATUS, *PX64MCP_STATUS;

#pragma pack(pop)

/* ------------------------------------------------------------------------- */
/* Compile-time ABI agreement checks                                         */
/* ------------------------------------------------------------------------- */

/* Layout under x64, pack(8):
     X64MCP_VERSION     6 * ULONG + CHAR[32]              = 24 + 32 = 56
     X64MCP_ATTACH_REQ  2 * ULONG                                  =  8
     X64MCP_APPLY_REQ   ULONG64 + 3 * ULONG (4 bytes tail pad)     = 24
     X64MCP_STATUS      ULONG + pad + ULONG64 + ULONG64 + 4*ULONG  = 40

   The STATUS padding after `pid` is what makes the two ULONG64s land on an
   8-byte boundary; a user-mode build with a different pack setting would
   disagree here, which is exactly what these asserts exist to catch. */
#ifdef _KERNEL_MODE
C_ASSERT(sizeof(X64MCP_VERSION) == 56);
C_ASSERT(sizeof(X64MCP_ATTACH_REQ) == 8);
C_ASSERT(sizeof(X64MCP_APPLY_REQ) == 24);
C_ASSERT(sizeof(X64MCP_STATUS) == 40);
#endif

#endif /* X64DBG_MCP_HIDE_H */
