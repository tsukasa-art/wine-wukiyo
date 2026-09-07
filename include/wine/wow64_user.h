/*
 * WoW64 guest-memory access helpers
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_WOW64_USER_H
#define __WINE_WOW64_USER_H

#include <stdint.h>
#include "wine/low_va.h"

enum wow64_user_copy_operation
{
    WOW64_USER_COPY_READ,
    WOW64_USER_COPY_WRITE,
    WOW64_USER_COPY_PROBE_READ,
    WOW64_USER_COPY_PROBE_WRITE,
    WOW64_USER_COPY_FAULTING_WRITE,
    WOW64_USER_COPY_STORE_RELEASE_LONG,
    WOW64_USER_COPY_PUBLISH_IOSB,
    WOW64_USER_COPY_PUBLISH_HANDLE_PAIR,
    WOW64_USER_COPY_ATOMIC_WRITE,
};

/* Fixed-width because this crosses the PE/native Unix-call boundary. */
struct wow64_user_copy_params
{
    uint64_t dst;
    uint64_t src;
    uint64_t size;
    uint64_t value;
    uint32_t operation;
    int32_t status;
    uint32_t reserved[2];
};

#define WINE_WOW64_CREATE_USER_PROCESS_VERSION 1u
#define WINE_WOW64_CREATE_USER_THREAD_VERSION 1u
#define WINE_THREAD_CREATE_TRANSACTION 0x00000001u

enum wine_wow64_create_user_process_result
{
    WINE_WOW64_CREATE_USER_PROCESS_NONE,
    WINE_WOW64_CREATE_USER_PROCESS_PE_TRANSACTION,
    WINE_WOW64_CREATE_USER_PROCESS_NON_MZ_COMMITTED,
};

/* Private WoW64/native process-creation transaction.  The process_handle and
 * thread_handle fields return native HANDLE values.  All pointer fields except
 * the three guest_* outputs name native 64-bit staging storage owned by
 * wow64.dll; guest_* must use the current process's authoritative WoW64 address
 * model.  The native side retains transaction until the PE output publication
 * either commits it or cancels it. */
struct wine_wow64_create_user_process_params
{
    uint32_t version;
    uint32_t size;
    uint64_t process_handle;
    uint64_t thread_handle;
    uint64_t process_attributes;
    uint64_t thread_attributes;
    uint64_t process_parameters;
    uint64_t create_info;
    uint64_t attribute_list;
    uint64_t guest_process_handle;
    uint64_t guest_thread_handle;
    uint64_t guest_create_info;
    uint64_t non_mz_create_info;
    uint64_t transaction;
    uint32_t process_access;
    uint32_t thread_access;
    uint32_t process_flags;
    uint32_t thread_flags;
    uint32_t non_mz_create_info_size;
    uint32_t result;
    uint64_t reserved[2];
};

struct wine_wow64_complete_user_process_params
{
    uint64_t transaction;
    int32_t status;
    uint32_t commit;
    uint64_t reserved;
};

/* Native staged inputs for a WoW64 thread-creation transaction.  process is
 * the SAME_ACCESS-pinned operation handle from process_address_codec;
 * start/param are already decoded against that codec's target model.  The
 * native side keeps one private server suspension until the caller publishes
 * every guest output and commits, or cancels independently of thread-handle
 * access on any publication failure. */
struct wine_wow64_create_user_thread_params
{
    uint32_t version;
    uint32_t size;
    uint64_t handle;
    uint64_t transaction;
    uint64_t process;
    uint64_t object_attributes;
    uint64_t attribute_list;
    uint64_t start;
    uint64_t param;
    uint64_t zero_bits;
    uint64_t stack_commit;
    uint64_t stack_reserve;
    uint32_t access;
    uint32_t flags;
    uint64_t reserved[2];
};

struct wine_wow64_complete_user_thread_params
{
    uint64_t transaction;
    int32_t status;
    uint32_t commit;
    uint64_t reserved;
};

#ifndef WINE_UNIX_LIB

NTSTATUS CDECL __wine_wow64_user_copy( void *dst, const void *src, SIZE_T size,
                                       ULONG operation );
NTSTATUS CDECL __wine_wow64_store_release_long( LONG *dst, LONG value );
NTSTATUS CDECL __wine_wow64_publish_iosb( void *dst, NTSTATUS status,
                                          ULONG information );
NTSTATUS CDECL __wine_wow64_publish_handle_pair( ULONG *dst1, ULONG value1,
                                                  ULONG *dst2, ULONG value2 );
NTSTATUS CDECL __wine_wow64_create_user_process(
    struct wine_wow64_create_user_process_params *params );
NTSTATUS CDECL __wine_wow64_complete_user_process( HANDLE transaction,
                                                    BOOL commit, NTSTATUS status );
NTSTATUS CDECL __wine_wow64_create_user_thread(
    struct wine_wow64_create_user_thread_params *params );
NTSTATUS CDECL __wine_wow64_complete_user_thread( HANDLE transaction,
                                                   BOOL commit, NTSTATUS status );

/* The paired 32-bit TEB is native ntdll-owned process state.  Its host address
 * identifies the high-shadow model without consulting writable guest PEB/TEB
 * fields.  Callers that run before the paired TEB exists must use the explicit
 * variant with their process-init state. */
static inline BOOL wine_wow64_current_process_uses_low_va_shadow(void)
{
#ifdef _WIN64
    const TEB *teb = NtCurrentTeb();
    ULONG_PTR teb32;

    if (!teb->WowTebOffset) return FALSE;
    teb32 = (ULONG_PTR)teb + teb->WowTebOffset;
    return teb32 >= WINE_LOW_VA_SHADOW_BASE &&
           teb32 - WINE_LOW_VA_SHADOW_BASE < WINE_LOW_VA_SHADOW_SIZE;
#else
    return FALSE;
#endif
}

static inline void *wine_wow64_guest_memory_ptr_for_shadow( BOOL shadow, ULONG address )
{
    if (!address) return NULL;
    if (shadow) return (void *)(ULONG_PTR)(WINE_LOW_VA_SHADOW_BASE + address);
    return ULongToPtr( address );
}

static inline void *wine_wow64_guest_memory_ptr( ULONG address )
{
    return wine_wow64_guest_memory_ptr_for_shadow(
        wine_wow64_current_process_uses_low_va_shadow(), address );
}

static inline ULONG wine_wow64_guest_memory_addr_for_shadow( BOOL shadow,
                                                              const void *address )
{
#ifdef _WIN64
    ULONG_PTR value = (ULONG_PTR)address;

    if (shadow && value >= WINE_LOW_VA_SHADOW_BASE &&
        value - WINE_LOW_VA_SHADOW_BASE < WINE_LOW_VA_SHADOW_SIZE)
        return value - WINE_LOW_VA_SHADOW_BASE;
#else
    (void)shadow;
#endif
    return PtrToUlong( address );
}

static inline ULONG wine_wow64_guest_memory_addr( const void *address )
{
    return wine_wow64_guest_memory_addr_for_shadow(
        wine_wow64_current_process_uses_low_va_shadow(), address );
}

static inline NTSTATUS wine_wow64_copy_from_user( void *dst, const void *src, SIZE_T size )
{
    return __wine_wow64_user_copy( dst, src, size, WOW64_USER_COPY_READ );
}

static inline NTSTATUS wine_wow64_copy_to_user( void *dst, const void *src, SIZE_T size )
{
    return __wine_wow64_user_copy( dst, src, size, WOW64_USER_COPY_FAULTING_WRITE );
}

/* Use for outputs whose native ownership must be rolled back on failure.  The
 * complete range is validated and written while the native virtual lock is
 * held, so a returned error guarantees that no output byte was stored. */
static inline NTSTATUS wine_wow64_try_copy_to_user( void *dst, const void *src,
                                                     SIZE_T size )
{
    return __wine_wow64_user_copy( dst, src, size, WOW64_USER_COPY_ATOMIC_WRITE );
}

static inline NTSTATUS wine_wow64_probe_user_read( const void *src, SIZE_T size )
{
    return __wine_wow64_user_copy( NULL, src, size, WOW64_USER_COPY_PROBE_READ );
}

static inline NTSTATUS wine_wow64_probe_user_write( void *dst, SIZE_T size )
{
    return __wine_wow64_user_copy( dst, NULL, size, WOW64_USER_COPY_PROBE_WRITE );
}

static inline NTSTATUS wine_wow64_faulting_copy_to_user( void *dst, const void *src,
                                                          SIZE_T size )
{
    return __wine_wow64_user_copy( dst, src, size, WOW64_USER_COPY_FAULTING_WRITE );
}

static inline NTSTATUS wine_wow64_publish_handle_pair( ULONG *dst1, ULONG value1,
                                                        ULONG *dst2, ULONG value2 )
{
    return __wine_wow64_publish_handle_pair( dst1, value1, dst2, value2 );
}

#endif /* !WINE_UNIX_LIB */

#endif /* __WINE_WOW64_USER_H */
