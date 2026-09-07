/*
 * i386 emulation on ARM64 Unix interface
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_XTAJIT_UNIXLIB_H
#define __WINE_XTAJIT_UNIXLIB_H

#include "windef.h"
#include "winnt.h"
#include "wine/low_va.h"
#include "wine/unixlib.h"

#define XTAJIT_GUEST_PAGE_SIZE     0x1000
#define XTAJIT_MAX_HOST_PAGE_SIZE  0x10000
#define XTAJIT_GUEST_KUSER         0x7ffe0000

/* These pages are outside Wine's i386 user range and exist only in Unicorn. */
#define XTAJIT_GUEST_BOP_PAGE      0xffff0000
#define XTAJIT_GUEST_GDT_PAGE      0xffff1000
#define XTAJIT_GUEST_SYSCALL_BOP   (XTAJIT_GUEST_BOP_PAGE + 0x000)
#define XTAJIT_GUEST_UNIX_BOP      (XTAJIT_GUEST_BOP_PAGE + 0x010)
#define XTAJIT_RECENT_EIP_COUNT     8

#define XTAJIT_PROCESS_ABI_VERSION                 1
#define XTAJIT_PROCESS_CAP_MEMORY_OBSERVER  0x0000000000000001ull
#define XTAJIT_PROCESS_CAP_LOGICAL_WRITE_FAULT 0x0000000000000002ull
#define XTAJIT_PROCESS_REQUIRED_CAPABILITIES \
    (XTAJIT_PROCESS_CAP_MEMORY_OBSERVER | XTAJIT_PROCESS_CAP_LOGICAL_WRITE_FAULT)

static inline BOOL xtajit_guest_unixlib_handle_is_allowed( UINT64 handle )
{
    return wine_unixlib_decode_dispatch_handle( handle, NULL, NULL );
}

enum xtajit_unix_funcs
{
    unix_process_init,
    unix_process_term,
    unix_thread_init,
    unix_thread_term,
    unix_memory_map,
    unix_memory_unmap,
    unix_memory_protect,
    unix_flush_instruction_cache,
    unix_poison,
    unix_begin_simulation,
    unix_resolve_memory_fault,
    unix_funcs_count
};

enum xtajit_stop_reason
{
    XTAJIT_STOP_NONE,
    XTAJIT_STOP_SYSCALL,
    XTAJIT_STOP_UNIX_CALL,
    XTAJIT_STOP_UNMAPPED_MEMORY,
    XTAJIT_STOP_MEMORY_FAULT,
    XTAJIT_STOP_INVALID_INSTRUCTION,
    XTAJIT_STOP_UNSUPPORTED_INTERRUPT,
    XTAJIT_STOP_INTERNAL_ERROR
};

struct xtajit_i386_context
{
    UINT32 eax, ebx, ecx, edx;
    UINT32 esi, edi, ebp, esp;
    UINT32 eip, eflags;
    UINT32 seg_cs, seg_ss, seg_ds, seg_es, seg_fs, seg_gs;
    UINT32 mxcsr;
    UINT16 fp_control;
    UINT16 fp_status;
    UINT16 fp_tag;
    UINT8 fp_valid;
    UINT8 reserved;
    UINT8 st[8][10];
    UINT64 xmm[8][2];
};

struct xtajit_process_init_params
{
    UINT32 version;
    UINT32 size;
    UINT64 required_capabilities;
    UINT64 enabled_capabilities;
    UINT64 highest_user_address;
    UINT64 guest_kuser;
    UINT64 host_kuser;
    UINT64 kuser_size;
    UINT64 low_va_shadow_base;
    UINT64 low_va_shadow_size;
};

struct xtajit_memory_params
{
    UINT64 guest;
    UINT64 host;
    UINT64 size;
    UINT64 allocation_base;
    UINT32 protect;
    UINT32 reserved;
};

struct xtajit_begin_params
{
    struct xtajit_i386_context context;
    UINT32 teb_guest;
    UINT32 stop_reason;
    UINT64 fault_address;
    UINT32 fault_type;
    UINT32 unicorn_error;
    UINT64 execution_slice_count;
    UINT32 recent_eip_count;
    UINT32 reserved;
    UINT32 recent_eip[XTAJIT_RECENT_EIP_COUNT];
};

struct xtajit_poison_params
{
    UINT32 status;
    UINT32 reserved;
};

struct xtajit_fault_params
{
    UINT64 guest;
    UINT32 unicorn_type;
    UINT32 reserved;
    struct wine_wow64_memory_fault_result_v1 result;
};

C_ASSERT( sizeof(struct xtajit_i386_context) == 288 );
C_ASSERT( sizeof(struct xtajit_process_init_params) == 72 );
C_ASSERT( sizeof(struct xtajit_memory_params) == 40 );
C_ASSERT( sizeof(struct xtajit_begin_params) == 360 );
C_ASSERT( sizeof(struct xtajit_poison_params) == 8 );
C_ASSERT( sizeof(struct wine_wow64_memory_observer_v1) == 40 );
C_ASSERT( sizeof(struct wine_wow64_memory_fault_result_v1) == 48 );
C_ASSERT( sizeof(struct xtajit_fault_params) == 64 );
C_ASSERT( !(XTAJIT_GUEST_KUSER & (XTAJIT_MAX_HOST_PAGE_SIZE - 1)) );
C_ASSERT( !(WINE_LOW_VA_SHADOW_BASE & (XTAJIT_MAX_HOST_PAGE_SIZE - 1)) );
C_ASSERT( WINE_LOW_VA_SHADOW_SIZE == 0x100000000ull );
C_ASSERT( XTAJIT_GUEST_BOP_PAGE >= WINE_LOW_VA_SHADOW_SIZE - 0x10000 );
C_ASSERT( XTAJIT_GUEST_GDT_PAGE == XTAJIT_GUEST_BOP_PAGE + XTAJIT_GUEST_PAGE_SIZE );

static inline void xtajit_context_segments_to_unix( struct xtajit_i386_context *dst,
                                                      const I386_CONTEXT *src )
{
    /* Windows stores selectors in DWORD context fields but defines only their
     * low 16 bits.  Exception dispatch is allowed to leave the upper bits
     * unspecified, and Unicorn rejects those non-selector bits. */
    dst->seg_cs = LOWORD( src->SegCs );
    dst->seg_ss = LOWORD( src->SegSs );
    dst->seg_ds = LOWORD( src->SegDs );
    dst->seg_es = LOWORD( src->SegEs );
    dst->seg_fs = LOWORD( src->SegFs );
    dst->seg_gs = LOWORD( src->SegGs );
}

static inline void xtajit_context_segments_from_unix( I386_CONTEXT *dst,
                                                        const struct xtajit_i386_context *src )
{
    dst->SegCs = LOWORD( src->seg_cs );
    dst->SegSs = LOWORD( src->seg_ss );
    dst->SegDs = LOWORD( src->seg_ds );
    dst->SegEs = LOWORD( src->seg_es );
    dst->SegFs = LOWORD( src->seg_fs );
    dst->SegGs = LOWORD( src->seg_gs );
}

static inline BOOL xtajit_normalize_shadow_address( UINT64 address, BOOL allow_end,
                                                     UINT64 *guest )
{
    UINT64 offset;

    if (!guest) return FALSE;
    if (address < WINE_LOW_VA_SHADOW_BASE)
    {
        *guest = address;
        return TRUE;
    }
    offset = address - WINE_LOW_VA_SHADOW_BASE;
    if (offset < WINE_LOW_VA_SHADOW_SIZE ||
        (allow_end && offset == WINE_LOW_VA_SHADOW_SIZE))
        *guest = offset;
    else
        *guest = address;
    return TRUE;
}

static inline BOOL xtajit_normalize_shadow_range( UINT64 address, UINT64 size,
                                                   UINT64 *guest )
{
    UINT64 end;

    if (!size || address > ~(UINT64)0 - size ||
        !xtajit_normalize_shadow_address( address, FALSE, guest ))
        return FALSE;
    end = address + size;
    if (*guest != address)
        return size <= WINE_LOW_VA_SHADOW_SIZE - *guest;
    if (address < WINE_LOW_VA_SHADOW_BASE && end > WINE_LOW_VA_SHADOW_BASE)
        return FALSE;
    return TRUE;
}

static inline BOOL xtajit_bounded_region_run( UINT64 cursor, UINT64 limit,
                                               UINT64 region_base, UINT64 region_size,
                                               UINT64 *run_end )
{
    UINT64 region_end;

    if (!run_end || cursor >= limit || !region_size ||
        region_base > ~(UINT64)0 - region_size)
        return FALSE;
    region_end = region_base + region_size;
    if (cursor < region_base || cursor >= region_end) return FALSE;
    *run_end = min( region_end, limit );
    return *run_end > cursor &&
           !((cursor | *run_end) & (XTAJIT_GUEST_PAGE_SIZE - 1));
}

#endif /* __WINE_XTAJIT_UNIXLIB_H */
