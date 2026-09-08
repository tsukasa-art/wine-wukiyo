/*
 * x86-64 emulation on ARM64 Unix interface
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_XTAJIT64_UNIXLIB_H
#define __WINE_XTAJIT64_UNIXLIB_H

#include "windef.h"
#include "winnt.h"
#include "wine/low_va.h"
#include "wine/unixlib.h"
#include "flight_recorder.h"

#define XTAJIT64_GUEST_PAGE_SIZE      0x1000
#define XTAJIT64_MAX_HOST_PAGE_SIZE   0x10000
#define XTAJIT64_GUEST_KUSER          WINE_USER_SHARED_DATA_ADDRESS
#define XTAJIT64_X64_USER_ADDRESS_MAX 0x00007fffffffffffull
#define XTAJIT64_X64_SYSCALL_NT_READ_VIRTUAL_MEMORY 0x003fu
#define XTAJIT64_PROCESS_ABI_VERSION          11u
#define XTAJIT64_PROCESS_INIT_PARAMS_SIZE     96u
#define XTAJIT64_BEGIN_PARAMS_SIZE            472u
#define XTAJIT64_PROVIDER_ABI_IDENTITY \
    "switchyard-xtajit64-provider-abi-v11-normal-fault-process-init-96-begin-472-doorbell"

#define XTAJIT64_CAP_GS_NATIVE_DOMAIN 0x00000001u
#define XTAJIT64_CAP_ADDRESS_CODEC    0x00000002u
#define XTAJIT64_CAP_MUTATION_CODEC   0x00000004u
#define XTAJIT64_CAP_SUSPEND_DOORBELL 0x00000008u
#define XTAJIT64_CAPABILITIES         (XTAJIT64_CAP_GS_NATIVE_DOMAIN | \
                                       XTAJIT64_CAP_ADDRESS_CODEC | \
                                       XTAJIT64_CAP_MUTATION_CODEC | \
                                       XTAJIT64_CAP_SUSPEND_DOORBELL)

#define XTAJIT64_MEMORY_VALID_FLAGS   0u

#define XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST 0x00000001u
#define XTAJIT64_MEMORY_TRANSLATE_HOST_TO_GUEST 0x00000002u
#define XTAJIT64_MEMORY_TRANSLATE_DIRECTION_MASK \
    (XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST | XTAJIT64_MEMORY_TRANSLATE_HOST_TO_GUEST)
#define XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ    0x00000004u
#define XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE   0x00000008u
#define XTAJIT64_MEMORY_TRANSLATE_REQUIRE_EXECUTE 0x00000010u
#define XTAJIT64_MEMORY_TRANSLATE_VALID_FLAGS \
    (XTAJIT64_MEMORY_TRANSLATE_DIRECTION_MASK | \
     XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ | \
     XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE | \
     XTAJIT64_MEMORY_TRANSLATE_REQUIRE_EXECUTE)

/* Returned translation domains are part of the PE/Unix validation contract.
 * PE fast paths may dereference an address only when the provider explicitly
 * authenticates the identity lane. */
enum xtajit64_memory_domain
{
    XTAJIT64_MEMORY_ADDRESS_INVALID,
    XTAJIT64_MEMORY_ADDRESS_IDENTITY,
    XTAJIT64_MEMORY_ADDRESS_AMD64_LOW,
};

static inline BOOL xtajit64_process_term_notification_may_cleanup(
    UINT_PTR handle, BOOL is_post, NTSTATUS status )
{
    (void)handle;
    (void)is_post;
    (void)status;

    /* Wine sends both callbacks around a soft NtTerminateProcess(NULL) that
     * must return for guest LdrShutdownProcess.  Neither notification is a
     * quiescent teardown boundary; the OS reclaims this process-lifetime
     * provider after the terminal process exit. */
    return FALSE;
}

enum xtajit64_unix_funcs
{
    unix_process_init,
    unix_process_term,
    unix_thread_init,
    unix_thread_term,
    unix_memory_map,
    unix_memory_unmap,
    unix_memory_protect,
    unix_memory_resync,
    unix_flush_instruction_cache,
    unix_poison,
    unix_begin_simulation,
    unix_memory_resync_begin,
    unix_memory_translate,
    unix_flight_bind,
    unix_resolve_memory_fault,
    unix_memory_snapshot_lock,
    unix_memory_snapshot_unlock,
    unix_thread_exit_ready,
    unix_funcs_count
};

struct xtajit64_fault_params
{
    UINT64 address;
    UINT32 access;
    UINT32 reserved;
    struct wine_wow64_memory_fault_result_v1 result;
};

enum xtajit64_stop_reason
{
    XTAJIT64_STOP_NONE,
    XTAJIT64_STOP_EC_TRANSITION,
    XTAJIT64_STOP_SYSCALL,
    XTAJIT64_STOP_MEMORY_FAULT,
    XTAJIT64_STOP_MAPPING_MISS,
    XTAJIT64_STOP_INVALID_INSTRUCTION,
    XTAJIT64_STOP_UNSUPPORTED_TRANSITION,
    XTAJIT64_STOP_INTERNAL_ERROR,
    XTAJIT64_STOP_SUSPEND,
    XTAJIT64_STOP_SINGLE_STEP
};

struct xtajit64_x64_context
{
    UINT64 rax, rbx, rcx, rdx;
    UINT64 rsi, rdi, rbp, rsp;
    UINT64 r8, r9, r10, r11;
    UINT64 r12, r13, r14, r15;
    UINT64 rip, eflags;
    UINT32 mxcsr;
    UINT32 reserved;
    UINT64 xmm[16][2];
};

struct xtajit64_process_init_params
{
    UINT64 ec_bitmap;
    UINT64 highest_user_address;
    UINT64 guest_kuser;
    UINT64 host_kuser;
    UINT64 kuser_size;
    UINT64 rtl_exit_user_thread;
    UINT32 abi_version;
    UINT32 abi_size;
    UINT32 required_capabilities;
    UINT32 enabled_capabilities;
    UINT64 x64_syscall_dispatcher;
    UINT32 x64_syscall_count;
    UINT32 reserved;
    /* This native target is resolved by the PE-side ARM64EC metadata parser.
     * It lets the Unix provider distinguish Wine's RtlQueryPerformanceCounter
     * from an arbitrary EC function with a superficially similar body. */
    UINT64 rtl_query_performance_counter;
    /* The raw x64 export authenticates the final branch of an ARM64X
     * hybrid-patch thunk.  It is intentionally not redirected through the
     * ARM64EC metadata table. */
    UINT64 nt_query_performance_counter;
};

struct xtajit64_memory_params
{
    UINT64 guest;
    UINT64 host;
    UINT64 size;
    UINT64 allocation_base;
    UINT32 protect;
    UINT32 flags;
};

struct xtajit64_memory_resync_params
{
    UINT64 ranges;
    UINT64 generation;
    UINT32 count;
    UINT32 reserved;
};

struct xtajit64_memory_resync_begin_params
{
    UINT64 generation;
};

struct xtajit64_memory_translate_params
{
    UINT64 address;
    UINT64 size;
    UINT64 guest;
    UINT64 host;
    UINT64 allocation_base;
    UINT32 flags;
    UINT32 domain;
    UINT64 exception_stack_limit;
    UINT64 exception_stack_base;
};

struct xtajit64_begin_params
{
    struct xtajit64_x64_context context;
    UINT64 gs_base;
    UINT64 stack_limit;
    UINT64 stack_base;
    UINT64 transition_target;
    UINT64 fault_address;
    UINT32 fault_access;
    UINT32 stop_reason;
    UINT32 unicorn_error;
    UINT32 reserved;
    UINT64 suspend_doorbell;
};

/* Optional, diagnostic-only association.  Kept separate from begin_params so
 * operational provider ABI additions (for example suspend signaling) do not
 * need to share a hot-path diagnostic layout. */
struct xtajit64_flight_bind_params
{
    UINT64 recorder;
    UINT64 causal_boundary_id;
    UINT64 context_generation;
    UINT64 transition_generation;
    /* Stable PE-side x18 claim captured before this Unix dispatcher entry.
     * unix_flight_bind authenticates it against WINE_UNIX_LIB NtCurrentTeb(). */
    UINT64 claimed_teb;
    UINT64 guest_rip;
    UINT64 guest_rsp;
    UINT64 guest_stack_limit;
    UINT64 guest_stack_base;
    UINT64 control_stack_limit;
    UINT64 control_stack_top;
};

struct xtajit64_poison_params
{
    UINT32 status;
    UINT32 reserved;
};

C_ASSERT( sizeof(struct xtajit64_x64_context) == 408 );
C_ASSERT( offsetof(struct xtajit64_process_init_params, abi_version) == 48 );
C_ASSERT( offsetof(struct xtajit64_process_init_params, abi_size) == 52 );
C_ASSERT( offsetof(struct xtajit64_process_init_params, required_capabilities) == 56 );
C_ASSERT( offsetof(struct xtajit64_process_init_params, enabled_capabilities) == 60 );
C_ASSERT( offsetof(struct xtajit64_process_init_params, x64_syscall_dispatcher) == 64 );
C_ASSERT( offsetof(struct xtajit64_process_init_params, x64_syscall_count) == 72 );
C_ASSERT( offsetof(struct xtajit64_process_init_params, reserved) == 76 );
C_ASSERT( offsetof(struct xtajit64_process_init_params, rtl_query_performance_counter) == 80 );
C_ASSERT( offsetof(struct xtajit64_process_init_params, nt_query_performance_counter) == 88 );
C_ASSERT( sizeof(struct xtajit64_process_init_params) ==
          XTAJIT64_PROCESS_INIT_PARAMS_SIZE );
/* The new handshake intentionally cannot satisfy the legacy tail validation. */
C_ASSERT( (((UINT64)sizeof(struct xtajit64_process_init_params) << 32) |
           XTAJIT64_PROCESS_ABI_VERSION) != WINE_LOW_VA_SHADOW_BASE );
C_ASSERT( (UINT64)XTAJIT64_CAP_GS_NATIVE_DOMAIN != WINE_LOW_VA_SHADOW_SIZE );
C_ASSERT( sizeof(struct xtajit64_memory_params) == 40 );
C_ASSERT( sizeof(struct xtajit64_memory_resync_params) == 24 );
C_ASSERT( sizeof(struct xtajit64_memory_resync_begin_params) == 8 );
C_ASSERT( offsetof(struct xtajit64_memory_translate_params, flags) == 40 );
C_ASSERT( sizeof(struct xtajit64_memory_translate_params) == 64 );
C_ASSERT( sizeof(((struct xtajit64_begin_params *)0)->gs_base) == 8 );
C_ASSERT( offsetof(struct xtajit64_begin_params, gs_base) == 408 );
C_ASSERT( offsetof(struct xtajit64_begin_params, stack_limit) == 416 );
C_ASSERT( offsetof(struct xtajit64_begin_params, stack_base) == 424 );
C_ASSERT( offsetof(struct xtajit64_begin_params, transition_target) == 432 );
C_ASSERT( offsetof(struct xtajit64_begin_params, fault_address) == 440 );
C_ASSERT( offsetof(struct xtajit64_begin_params, fault_access) == 448 );
C_ASSERT( offsetof(struct xtajit64_begin_params, stop_reason) == 452 );
C_ASSERT( offsetof(struct xtajit64_begin_params, unicorn_error) == 456 );
C_ASSERT( offsetof(struct xtajit64_begin_params, reserved) == 460 );
C_ASSERT( offsetof(struct xtajit64_begin_params, suspend_doorbell) == 464 );
C_ASSERT( sizeof(struct xtajit64_begin_params) == XTAJIT64_BEGIN_PARAMS_SIZE );
C_ASSERT( sizeof(struct xtajit64_flight_bind_params) == 88 );
C_ASSERT( sizeof(struct xtajit64_poison_params) == 8 );
C_ASSERT( !(XTAJIT64_GUEST_KUSER & (XTAJIT64_MAX_HOST_PAGE_SIZE - 1)) );

#endif /* __WINE_XTAJIT64_UNIXLIB_H */
