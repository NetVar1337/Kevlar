#pragma once
// Consumes the PDB-generated layout (tools\pdb_layout) for the synthetic kernel
// structures the harness populates at fixed offsets. Regenerate
// generated\kernel_layout.h after refreshing the target ntoskrnl PDB; the
// constants below follow automatically. The static_asserts below fail the build
// if a hardcoded struct in ntoskrnl_struct.h drifts from the generated offsets
// for a field the harness writes or reads.

#include <cstdint>
#include "ntoskrnl_struct.h"
#include "../../generated/kernel_layout.h"

// ---------------------------------------------------------------------------
// Fixed-offset accesses (replaces magic literals)
// ---------------------------------------------------------------------------

// KTHREAD.KernelApcDisable == ETHREAD+0x1E4 (KeLeaveCriticalRegion counter).
static constexpr uint64_t ETHREAD_APC_DISABLE = GEN__KTHREAD_KernelApcDisable;

// KPRCB.CurrentThread, reachable as KPCR.Prcb then +CurrentThread (== +0x188).
static constexpr uint64_t KPCR_PRCB_OFFSET = GEN__KPCR_Prcb;                    // 0x180
static constexpr uint64_t KPRCB_CURRENT_THREAD = GEN__KPRCB_CurrentThread;      // 0x8

// EPROCESS.RundownProtect (PsAcquire/ReleaseProcessExitSynchronization).
static constexpr uint64_t EPROCESS_RUNDOWN_PROTECT = GEN__EPROCESS_RundownProtect;

// ETHREAD -> KTHREAD back-pointers (Tcb is at ETHREAD+0).
static constexpr uint64_t ETHREAD_Tcb_Process = GEN__KTHREAD_Process;                    // 0x220
static constexpr uint64_t ETHREAD_Tcb_ApcState_Process =
    GEN__KTHREAD_ApcState + offsetof(_KAPC_STATE, Process);                              // 0xB8

// ---------------------------------------------------------------------------
// Typed accessors for synthetic ETHREAD / EPROCESS fields. These track the
// generated offsets so a driver probing the real build sees consistent data.
// ---------------------------------------------------------------------------

inline struct _CLIENT_ID* EthreadCid(_ETHREAD* E) { return (struct _CLIENT_ID*)((uint8_t*)E + GEN__ETHREAD_Cid); }
inline void** EprocUniqueProcessId(_EPROCESS* P) { return (void**)((uint8_t*)P + GEN__EPROCESS_UniqueProcessId); }
inline ULONG* EprocProtection(_EPROCESS* P) { return (ULONG*)((uint8_t*)P + GEN__EPROCESS_Protection); }
inline void** EprocWow64Process(_EPROCESS* P) { return (void**)((uint8_t*)P + GEN__EPROCESS_WoW64Process); }
inline LARGE_INTEGER* EprocCreateTime(_EPROCESS* P) { return (LARGE_INTEGER*)((uint8_t*)P + GEN__EPROCESS_CreateTime); }
inline char* EprocImageFileName(_EPROCESS* P) { return (char*)((uint8_t*)P + GEN__EPROCESS_ImageFileName); }

// ---------------------------------------------------------------------------
// Drift gates: the harness populates these via struct member access, so the
// hardcoded layouts must agree with the generated offsets.
// ---------------------------------------------------------------------------

static_assert(sizeof(_KTHREAD) == GEN__KTHREAD_StructSize, "_KTHREAD size drifted from PDB");
// The synthetic _ETHREAD is a superset of the target build: its tail carries fields from
// the older hardcoded layout past the PDB end. Populated fields (Cid, CreateTime, Tcb)
// are asserted individually to land at the generated offsets, so a superset size is fine.
static_assert(sizeof(_ETHREAD) >= GEN__ETHREAD_StructSize, "_ETHREAD smaller than target PDB");
static_assert(offsetof(_ETHREAD, Tcb) == GEN__ETHREAD_Tcb, "_ETHREAD.Tcb drifted");
static_assert(offsetof(_ETHREAD, Cid) == GEN__ETHREAD_Cid, "_ETHREAD.Cid drifted");
static_assert(offsetof(_ETHREAD, CreateTime) == GEN__ETHREAD_CreateTime, "_ETHREAD.CreateTime drifted");
static_assert(offsetof(_KTHREAD, Process) == GEN__KTHREAD_Process, "_KTHREAD.Process drifted");
static_assert(offsetof(_KTHREAD, ApcState) == GEN__KTHREAD_ApcState, "_KTHREAD.ApcState drifted");
static_assert(offsetof(_KTHREAD, KernelApcDisable) == GEN__KTHREAD_KernelApcDisable, "_KTHREAD.KernelApcDisable drifted");
static_assert(offsetof(_KPCR, Self) == GEN__KPCR_Self, "_KPCR.Self drifted");
static_assert(offsetof(_KPCR, CurrentPrcb) == GEN__KPCR_CurrentPrcb, "_KPCR.CurrentPrcb drifted");
static_assert(offsetof(_KPCR, Irql) == GEN__KPCR_Irql, "_KPCR.Irql drifted");
