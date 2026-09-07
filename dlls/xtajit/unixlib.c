/*
 * Unicorn-backed i386 emulation on ARM64
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef XTAJIT_UNIXLIB_TEST
# include <stdatomic.h>
#endif

#ifdef HAVE_UNICORN
# include <pthread.h>
# include <unicorn/unicorn.h>
# include <unicorn/x86.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "wine/debug.h"
#include "unixlib.h"

#ifdef HAVE_UNICORN

#if !defined(UC_SWITCHYARD_INSTRUCTION_BOUNDARY_STOP) || \
    !defined(UC_SWITCHYARD_SHARED_MEMORY_ATOMICS) || \
    !defined(UC_SWITCHYARD_SHARED_CODE_COHERENCE)
# error Switchyard Unicorn instruction-boundary stop, shared-memory atomics, and shared-code coherence are required
#endif

WINE_DEFAULT_DEBUG_CHANNEL(xtajit);

struct mapped_range
{
    uint64_t guest;
    uint64_t host;
    uint64_t size;
    uint64_t allocation_base;
    unsigned int perms;
    BOOL permanent;
};

struct range_array
{
    struct mapped_range *data;
    size_t count;
    size_t capacity;
};

struct xtajit_segment_state
{
    uint32_t cs;
    uint32_t ss;
    uint32_t ds;
    uint32_t es;
    uint32_t fs;
    uint32_t gs;
    uint32_t teb_guest;
};

struct xtajit_engine
{
    struct xtajit_engine *next;
    uc_engine *uc;
    pthread_t owner;
    BOOL linked;
    BOOL running;
    BOOL start_acknowledged;
    BOOL pause_requested;
    uc_hook start_hook;
    uint64_t fault_address;
    uint64_t execution_slice_count;
    uint32_t fault_type;
    uint32_t recent_eip[XTAJIT_RECENT_EIP_COUNT];
    uint32_t recent_eip_count;
    uint32_t recent_eip_next;
    enum xtajit_stop_reason stop_reason;
    struct xtajit_segment_state segment_state;
    BOOL segment_state_valid;
};

struct provider_process
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    BOOL initialized;
    BOOL mutating;
    BOOL shutting_down;
    BOOL observer_active;
    BOOL observer_transaction;
    pthread_t mutation_owner;
    uint64_t mutation_token;
    uint64_t next_mutation_token;
    uint64_t mutation_start;
    uint64_t mutation_end;
    uint64_t mutation_allocation_base;
    uint32_t mutation_operation;
    BOOL mutation_resync;
    BOOL mutation_flush_all;
    uint64_t mutation_flush_start;
    uint64_t mutation_flush_end;
    uint64_t low_va_shadow_base;
    uint64_t low_va_shadow_size;
    uint64_t guest_kuser;
    uint64_t host_kuser;
    uint64_t kuser_size;
    NTSTATUS poison_status;
    struct range_array ranges;
    struct xtajit_engine *engines;
};

static struct provider_process provider =
{
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};
static pthread_key_t engine_key;
static pthread_once_t engine_key_once = PTHREAD_ONCE_INIT;
static int engine_key_error;

#ifdef XTAJIT_UNIXLIB_TEST
static int test_fail_engine_mutation = -1;
static int test_engine_mutation_count;
static unsigned int test_segment_descriptor_write_count;
static atomic_int test_hold_progress_hook;
static atomic_int test_progress_hook_entered;
static atomic_int test_release_progress_hook;
#ifndef UC_SWITCHYARD_SHARED_MEMORY_ATOMICS
static atomic_uint test_hold_write_address;
static atomic_int test_write_hook_entered;
static atomic_int test_release_write_hook;
#endif
static atomic_int test_pause_request_count;
static int32_t (*test_memory_fault_resolver)(
    uint64_t, uint32_t, struct wine_wow64_memory_fault_result_v1 * );
#endif

static const int integer_regs[] =
{
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EIP, UC_X86_REG_EFLAGS,
};

static const int segment_regs[] =
{
    UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS,
    UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS,
};

static const int xmm_regs[] =
{
    UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
    UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7,
};

static const int st_regs[] =
{
    UC_X86_REG_ST0, UC_X86_REG_ST1, UC_X86_REG_ST2, UC_X86_REG_ST3,
    UC_X86_REG_ST4, UC_X86_REG_ST5, UC_X86_REG_ST6, UC_X86_REG_ST7,
};

#define XTAJIT_CPL3_IRET_OFFSET     0x20
#define XTAJIT_CPL3_LANDING_OFFSET  0x21
static void poison_provider_locked( NTSTATUS status )
{
    if (!provider.poison_status)
        provider.poison_status = status ? status : STATUS_UNSUCCESSFUL;
}

static uint64_t align_down( uint64_t value )
{
    return value & ~(uint64_t)(XTAJIT_GUEST_PAGE_SIZE - 1);
}

static uint64_t align_up( uint64_t value )
{
    return (value + XTAJIT_GUEST_PAGE_SIZE - 1) &
           ~(uint64_t)(XTAJIT_GUEST_PAGE_SIZE - 1);
}

static BOOL align_range( uint64_t address, uint64_t size, uint64_t *start, uint64_t *end )
{
    uint64_t limit;

    if (!size || address > UINT64_MAX - size) return FALSE;
    limit = address + size;
    if (limit > UINT64_MAX - (XTAJIT_GUEST_PAGE_SIZE - 1)) return FALSE;
    *start = align_down( address );
    *end = align_up( limit );
    return *start < *end;
}

static BOOL ranges_overlap( uint64_t first, uint64_t last, uint64_t other, uint64_t size )
{
    return first < other + size && other < last;
}

static BOOL overlaps_provider_pages( uint64_t start, uint64_t end )
{
    return ranges_overlap( start, end, XTAJIT_GUEST_GDT_PAGE, XTAJIT_GUEST_PAGE_SIZE ) ||
           ranges_overlap( start, end, XTAJIT_GUEST_BOP_PAGE, XTAJIT_GUEST_PAGE_SIZE );
}

static unsigned int protection_to_unicorn( unsigned int protect )
{
    /* Wine implements guard pages through the normal-context fault resolver.
     * Keep them inaccessible until its authoritative snapshot publishes the
     * final protection; never let Unicorn access inaccessible host backing. */
    if (protect & PAGE_GUARD) return UC_PROT_NONE;

    switch (protect & 0xff)
    {
    case PAGE_READONLY:
        return UC_PROT_READ;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        return UC_PROT_READ | UC_PROT_WRITE;
    case PAGE_EXECUTE:
        /* Windows permits data reads from execute-only pages. */
        return UC_PROT_READ | UC_PROT_EXEC;
    case PAGE_EXECUTE_READ:
        return UC_PROT_READ | UC_PROT_EXEC;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC;
    default:
        return UC_PROT_NONE;
    }
}

static BOOL range_array_reserve( struct range_array *array, size_t capacity )
{
    struct mapped_range *data;

    if (capacity <= array->capacity) return TRUE;
    if (capacity > SIZE_MAX / sizeof(*data)) return FALSE;
    if (!(data = realloc( array->data, capacity * sizeof(*data) ))) return FALSE;
    array->data = data;
    array->capacity = capacity;
    return TRUE;
}

static BOOL ranges_can_merge( const struct mapped_range *left,
                              const struct mapped_range *right )
{
    return !left->permanent && !right->permanent &&
           left->guest + left->size == right->guest &&
           left->host + left->size == right->host &&
           left->allocation_base == right->allocation_base &&
           left->perms == right->perms;
}

static BOOL range_array_append( struct range_array *array, const struct mapped_range *range )
{
    struct mapped_range *last;

    if (!range->size) return TRUE;
    if (array->count)
    {
        last = &array->data[array->count - 1];
        if (last->guest + last->size > range->guest) return FALSE;
        if (ranges_can_merge( last, range ))
        {
            if (last->size > UINT64_MAX - range->size) return FALSE;
            last->size += range->size;
            return TRUE;
        }
    }
    if (array->count == SIZE_MAX || !range_array_reserve( array, array->count + 1 ))
        return FALSE;
    array->data[array->count++] = *range;
    return TRUE;
}

static struct mapped_range range_slice( const struct mapped_range *range,
                                        uint64_t start, uint64_t end )
{
    struct mapped_range result = *range;

    result.host += start - range->guest;
    result.guest = start;
    result.size = end - start;
    return result;
}

static BOOL range_overlaps( const struct mapped_range *range, uint64_t start, uint64_t end )
{
    return range->guest < end && start < range->guest + range->size;
}

static void range_array_free( struct range_array *array )
{
    free( array->data );
    memset( array, 0, sizeof(*array) );
}

static NTSTATUS build_mapped_registry( const struct range_array *old,
                                       const struct mapped_range *mapping,
                                       struct range_array *result )
{
    size_t i;
    BOOL inserted = FALSE;
    uint64_t start = mapping->guest, end = start + mapping->size;

    if (old->count > SIZE_MAX - 3 || !range_array_reserve( result, old->count + 3 ))
        return STATUS_NO_MEMORY;
    for (i = 0; i < old->count; ++i)
    {
        const struct mapped_range *range = &old->data[i];
        uint64_t range_end = range->guest + range->size;
        struct mapped_range slice;

        if (range_end <= start)
        {
            if (!range_array_append( result, range )) return STATUS_INVALID_ADDRESS;
            continue;
        }
        if (range->guest >= end)
        {
            if (!inserted)
            {
                if (!range_array_append( result, mapping )) return STATUS_INVALID_ADDRESS;
                inserted = TRUE;
            }
            if (!range_array_append( result, range )) return STATUS_INVALID_ADDRESS;
            continue;
        }
        if (range->permanent) return STATUS_ACCESS_DENIED;
        if (range->guest < start)
        {
            slice = range_slice( range, range->guest, start );
            if (!range_array_append( result, &slice )) return STATUS_INVALID_ADDRESS;
        }
        if (!inserted)
        {
            if (!range_array_append( result, mapping )) return STATUS_INVALID_ADDRESS;
            inserted = TRUE;
        }
        if (range_end > end)
        {
            slice = range_slice( range, end, range_end );
            if (!range_array_append( result, &slice )) return STATUS_INVALID_ADDRESS;
        }
    }
    if (!inserted && !range_array_append( result, mapping )) return STATUS_INVALID_ADDRESS;
    return STATUS_SUCCESS;
}

static NTSTATUS build_unmapped_registry( const struct range_array *old, uint64_t start,
                                         uint64_t size, uint64_t allocation_base,
                                         struct range_array *result )
{
    size_t i;
    uint64_t end = size ? start + size : 0;

    if (old->count == SIZE_MAX || !range_array_reserve( result, old->count + 1 ))
        return STATUS_NO_MEMORY;
    for (i = 0; i < old->count; ++i)
    {
        const struct mapped_range *range = &old->data[i];
        uint64_t range_end = range->guest + range->size;
        struct mapped_range slice;
        BOOL remove = size ? range_overlaps( range, start, end ) :
                             range->allocation_base == allocation_base;

        if (!remove)
        {
            if (!range_array_append( result, range )) return STATUS_INVALID_ADDRESS;
            continue;
        }
        if (range->permanent) return STATUS_ACCESS_DENIED;
        if (!size) continue;
        if (range->guest < start)
        {
            slice = range_slice( range, range->guest, start );
            if (!range_array_append( result, &slice )) return STATUS_INVALID_ADDRESS;
        }
        if (range_end > end)
        {
            slice = range_slice( range, end, range_end );
            if (!range_array_append( result, &slice )) return STATUS_INVALID_ADDRESS;
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS build_protected_registry( const struct range_array *old, uint64_t start,
                                          uint64_t end, unsigned int perms,
                                          struct range_array *result )
{
    size_t i;

    if (old->count > (SIZE_MAX - 1) / 3 ||
        !range_array_reserve( result, old->count * 3 + 1 ))
        return STATUS_NO_MEMORY;
    for (i = 0; i < old->count; ++i)
    {
        const struct mapped_range *range = &old->data[i];
        uint64_t range_end = range->guest + range->size;
        uint64_t overlap_start, overlap_end;
        struct mapped_range slice;

        if (!range_overlaps( range, start, end ))
        {
            if (!range_array_append( result, range )) return STATUS_INVALID_ADDRESS;
            continue;
        }
        if (range->permanent) return STATUS_ACCESS_DENIED;
        overlap_start = max( range->guest, start );
        overlap_end = min( range_end, end );
        if (range->guest < overlap_start)
        {
            slice = range_slice( range, range->guest, overlap_start );
            if (!range_array_append( result, &slice )) return STATUS_INVALID_ADDRESS;
        }
        slice = range_slice( range, overlap_start, overlap_end );
        slice.perms = perms;
        if (!range_array_append( result, &slice )) return STATUS_INVALID_ADDRESS;
        if (overlap_end < range_end)
        {
            slice = range_slice( range, overlap_end, range_end );
            if (!range_array_append( result, &slice )) return STATUS_INVALID_ADDRESS;
        }
    }
    return STATUS_SUCCESS;
}

static BOOL registry_covers_range( const struct range_array *ranges,
                                   uint64_t start, uint64_t end )
{
    uint64_t cursor = start;
    size_t i;

    for (i = 0; i < ranges->count && cursor < end; ++i)
    {
        const struct mapped_range *range = &ranges->data[i];
        uint64_t range_end = range->guest + range->size;

        if (range_end <= cursor) continue;
        if (range->guest > cursor) return FALSE;
        cursor = min( range_end, end );
    }
    return cursor == end;
}

static BOOL guest_to_host_address( uint64_t guest, uint64_t *host )
{
    if (!host || guest >= provider.low_va_shadow_size) return FALSE;
    if (provider.low_va_shadow_base)
    {
        if (guest > UINT64_MAX - provider.low_va_shadow_base) return FALSE;
        *host = provider.low_va_shadow_base + guest;
    }
    else *host = guest;
    return TRUE;
}

static BOOL host_range_matches_guest( uint64_t guest, uint64_t host, uint64_t size )
{
    uint64_t expected;

    if (!size || guest >= provider.low_va_shadow_size ||
        size > provider.low_va_shadow_size - guest ||
        !guest_to_host_address( guest, &expected ))
        return FALSE;
    return host == expected;
}

static uc_err map_host_range( struct xtajit_engine *engine, uint64_t guest, uint64_t host,
                              uint64_t size, unsigned int perms )
{
    uint64_t guest_page, guest_end, host_page, host_end;

    if (!size) return UC_ERR_OK;
    if (((guest ^ host) & (XTAJIT_GUEST_PAGE_SIZE - 1))) return UC_ERR_ARG;
    if (!align_range( guest, size, &guest_page, &guest_end ) ||
        !align_range( host, size, &host_page, &host_end ) ||
        guest_end > WINE_LOW_VA_SHADOW_SIZE ||
        guest_end - guest_page != host_end - host_page)
        return UC_ERR_ARG;
    return uc_mem_map_ptr( engine->uc, guest_page, guest_end - guest_page, perms,
                           (void *)(uintptr_t)host_page );
}

static uc_err unmap_range( struct xtajit_engine *engine, uint64_t guest, uint64_t size )
{
    if (!size) return UC_ERR_OK;
    return uc_mem_unmap( engine->uc, guest, size );
}

static uc_err unmap_registry_intersections( struct xtajit_engine *engine,
                                            const struct range_array *ranges,
                                            uint64_t start, uint64_t end )
{
    size_t i;
    uc_err err;

    for (i = 0; i < ranges->count; ++i)
    {
        const struct mapped_range *range = &ranges->data[i];
        uint64_t range_end = range->guest + range->size;
        uint64_t overlap_start, overlap_end;

        if (!range_overlaps( range, start, end ) || range->permanent) continue;
        overlap_start = max( range->guest, start );
        overlap_end = min( range_end, end );
        if ((err = unmap_range( engine, overlap_start, overlap_end - overlap_start )) != UC_ERR_OK)
            return err;
    }
    return UC_ERR_OK;
}

static uc_err unmap_allocation_ranges( struct xtajit_engine *engine,
                                       const struct range_array *ranges,
                                       uint64_t allocation_base )
{
    size_t i;
    uc_err err;

    for (i = 0; i < ranges->count; ++i)
    {
        const struct mapped_range *range = &ranges->data[i];

        if (range->permanent || range->allocation_base != allocation_base) continue;
        if ((err = unmap_range( engine, range->guest, range->size )) != UC_ERR_OK) return err;
    }
    return UC_ERR_OK;
}

static uc_err map_registry( struct xtajit_engine *engine, const struct range_array *ranges )
{
    size_t i;
    uc_err err;

    for (i = 0; i < ranges->count; ++i)
    {
        const struct mapped_range *range = &ranges->data[i];

        if ((err = map_host_range( engine, range->guest, range->host, range->size,
                                   range->perms )) != UC_ERR_OK)
            return err;
    }
    return UC_ERR_OK;
}

static BOOL any_engine_running_locked(void)
{
    struct xtajit_engine *engine;

    for (engine = provider.engines; engine; engine = engine->next)
        if (engine->running) return TRUE;
    return FALSE;
}

static void request_engine_pause_locked( struct xtajit_engine *engine )
{
    uc_err err;

    if (!engine->running) return;
    __atomic_store_n( &engine->pause_requested, TRUE, __ATOMIC_RELEASE );
#ifdef XTAJIT_UNIXLIB_TEST
    atomic_fetch_add_explicit( &test_pause_request_count, 1,
                               memory_order_release );
#endif
    /* A non-owner stop must reach a guest-instruction boundary; an immediate
     * stop can commit a guest memory side effect while restoring the PC to the
     * beginning of that instruction.  A request published before the first-
     * block acknowledgement is instead consumed by that hook, after
     * uc_emu_start() has cleared Unicorn's internal stop flag. */
    if (engine->start_acknowledged &&
        (err = uc_emu_stop_at_instruction_boundary( engine->uc )) != UC_ERR_OK)
        poison_provider_locked( STATUS_UNSUCCESSFUL );
}

static NTSTATUS begin_mutation_locked(void)
{
    struct xtajit_engine *engine;

    while (provider.mutating && provider.initialized)
    {
        if (provider.observer_transaction &&
            pthread_equal( provider.mutation_owner, pthread_self() ))
        {
            poison_provider_locked( STATUS_INVALID_DEVICE_STATE );
            return provider.poison_status;
        }
        pthread_cond_wait( &provider.cond, &provider.mutex );
    }
    if (!provider.initialized || provider.shutting_down) return STATUS_INVALID_HANDLE;
    if (provider.poison_status) return provider.poison_status;

    provider.mutating = TRUE;
    provider.observer_transaction = FALSE;
    for (engine = provider.engines; engine; engine = engine->next)
        request_engine_pause_locked( engine );
    while (any_engine_running_locked()) pthread_cond_wait( &provider.cond, &provider.mutex );
    return provider.poison_status;
}

static void finish_mutation_locked(void)
{
    provider.mutating = FALSE;
    provider.observer_transaction = FALSE;
    provider.mutation_token = 0;
    provider.mutation_start = 0;
    provider.mutation_end = 0;
    provider.mutation_allocation_base = 0;
    provider.mutation_operation = 0;
    provider.mutation_resync = FALSE;
    provider.mutation_flush_all = FALSE;
    provider.mutation_flush_start = 0;
    provider.mutation_flush_end = 0;
    pthread_cond_broadcast( &provider.cond );
}

static void record_recent_eip( struct xtajit_engine *engine, uint64_t address )
{
    engine->recent_eip[engine->recent_eip_next] = address;
    engine->recent_eip_next = (engine->recent_eip_next + 1) % XTAJIT_RECENT_EIP_COUNT;
    if (engine->recent_eip_count < XTAJIT_RECENT_EIP_COUNT) ++engine->recent_eip_count;
}

static void bop_hook( uc_engine *uc, uint64_t address, uint32_t size, void *user )
{
    struct xtajit_engine *engine = user;

    (void)size;

    record_recent_eip( engine, address );
    if (address == XTAJIT_GUEST_SYSCALL_BOP) engine->stop_reason = XTAJIT_STOP_SYSCALL;
    else if (address == XTAJIT_GUEST_UNIX_BOP) engine->stop_reason = XTAJIT_STOP_UNIX_CALL;
    else engine->stop_reason = XTAJIT_STOP_INVALID_INSTRUCTION;
    uc_emu_stop( uc );
}

static void engine_start_hook( uc_engine *uc, uint64_t address,
                               uint32_t size, void *user )
{
    struct xtajit_engine *engine = user;
    uc_hook hook;
    uc_err err = UC_ERR_OK;
    BOOL stop;

    (void)size;

#ifdef XTAJIT_UNIXLIB_TEST
    if (atomic_load_explicit( &test_hold_progress_hook, memory_order_acquire ))
    {
        atomic_store_explicit( &test_progress_hook_entered, 1, memory_order_release );
        while (!atomic_load_explicit( &test_release_progress_hook, memory_order_acquire ));
    }
#endif
    pthread_mutex_lock( &provider.mutex );
    hook = engine->start_hook;
    if (hook)
    {
        err = uc_hook_del( uc, hook );
        engine->start_hook = 0;
        if (err != UC_ERR_OK) poison_provider_locked( STATUS_UNSUCCESSFUL );
    }
    else poison_provider_locked( STATUS_INVALID_DEVICE_STATE );
    record_recent_eip( engine, address );
    engine->start_acknowledged = TRUE;
    stop = provider.mutating ||
           __atomic_load_n( &engine->pause_requested, __ATOMIC_ACQUIRE ) ||
           provider.poison_status;
    pthread_cond_broadcast( &provider.cond );
    pthread_mutex_unlock( &provider.mutex );
    if (stop) uc_emu_stop( uc );
}

static void interrupt_hook( uc_engine *uc, uint32_t interrupt, void *user )
{
    struct xtajit_engine *engine = user;

    engine->fault_type = interrupt;
    engine->stop_reason = XTAJIT_STOP_UNSUPPORTED_INTERRUPT;
    uc_emu_stop( uc );
}

static uint32_t privileged_in_hook( uc_engine *uc, uint32_t port, int size, void *user )
{
    struct xtajit_engine *engine = user;

    (void)port;
    (void)size;
    engine->fault_type = 13;  /* #GP */
    engine->stop_reason = XTAJIT_STOP_UNSUPPORTED_INTERRUPT;
    uc_emu_stop( uc );
    return 0;
}

static void privileged_out_hook( uc_engine *uc, uint32_t port, int size,
                                 uint32_t value, void *user )
{
    struct xtajit_engine *engine = user;

    (void)port;
    (void)size;
    (void)value;
    engine->fault_type = 13;  /* #GP */
    engine->stop_reason = XTAJIT_STOP_UNSUPPORTED_INTERRUPT;
    uc_emu_stop( uc );
}

static bool invalid_instruction_hook( uc_engine *uc, void *user )
{
    struct xtajit_engine *engine = user;

    engine->stop_reason = XTAJIT_STOP_INVALID_INSTRUCTION;
    uc_emu_stop( uc );
    return false;
}

static uc_err arm_engine_start_hook_locked( struct xtajit_engine *engine,
                                            uint64_t address )
{
    uc_hook hook = 0;
    uc_err err;

    if (engine->start_hook) return UC_ERR_HOOK;
    if ((err = uc_hook_add( engine->uc, &hook, UC_HOOK_BLOCK,
                            engine_start_hook, engine, 1, 0 )) != UC_ERR_OK)
        return err;
    engine->start_hook = hook;

    /* Hook installation does not retrofit Unicorn's cached translation
     * blocks.  Invalidate only the entry TB so its first-block callback is
     * guaranteed to acknowledge this emulation slice.  Deleting the hook from
     * that callback invalidates the same instrumented TB again, leaving the
     * steady-state path free of block hooks. */
    if ((err = uc_ctl_remove_cache( engine->uc, address, address + 1 )) != UC_ERR_OK)
    {
        uc_hook_del( engine->uc, hook );
        engine->start_hook = 0;
    }
    return err;
}

static uc_err disarm_engine_start_hook_locked( struct xtajit_engine *engine )
{
    uc_err err;

    if (!engine->start_hook) return UC_ERR_OK;
    err = uc_hook_del( engine->uc, engine->start_hook );
    engine->start_hook = 0;
    return err;
}

static bool invalid_memory_hook( uc_engine *uc, uc_mem_type type, uint64_t address,
                                 int size, int64_t value, void *user )
{
    struct xtajit_engine *engine = user;

    (void)size;
    (void)value;
    record_recent_eip( engine, address );
    engine->fault_address = address;
    engine->fault_type = type;
    switch (type)
    {
    case UC_MEM_READ_UNMAPPED:
    case UC_MEM_WRITE_UNMAPPED:
    case UC_MEM_FETCH_UNMAPPED:
        engine->stop_reason = XTAJIT_STOP_UNMAPPED_MEMORY;
        break;
    default:
        engine->stop_reason = XTAJIT_STOP_MEMORY_FAULT;
        break;
    }
    uc_emu_stop( uc );
    return false;
}

#if defined(XTAJIT_UNIXLIB_TEST) && !defined(UC_SWITCHYARD_SHARED_MEMORY_ATOMICS)
static void test_memory_write_hook( uc_engine *uc, uc_mem_type type,
                                    uint64_t address, int size, int64_t value,
                                    void *user )
{
    uint32_t hold_address;

    (void)uc;
    (void)type;
    (void)size;
    (void)value;
    (void)user;
    hold_address = atomic_load_explicit( &test_hold_write_address,
                                         memory_order_acquire );
    if (address != hold_address ||
        atomic_exchange_explicit( &test_write_hook_entered, 1,
                                  memory_order_acq_rel ))
        return;
    while (!atomic_load_explicit( &test_release_write_hook,
                                  memory_order_acquire ));
}
#endif

static uint64_t make_segment_descriptor( uint32_t base, uint32_t limit,
                                         uint8_t access, uint8_t flags )
{
    return ((uint64_t)(limit & 0xffff)) |
           ((uint64_t)(base & 0xffff) << 16) |
           ((uint64_t)((base >> 16) & 0xff) << 32) |
           ((uint64_t)access << 40) |
           ((uint64_t)((limit >> 16) & 0x0f) << 48) |
           ((uint64_t)(flags & 0x0f) << 52) |
           ((uint64_t)((base >> 24) & 0xff) << 56);
}

static uc_err write_segment_descriptor( struct xtajit_engine *engine, uint32_t selector,
                                        uint32_t base, uint8_t access )
{
    uint64_t descriptor;
    uint32_t offset;

    if (!selector) return UC_ERR_ARG;
    if ((selector & 4) || (offset = selector & ~7u) < 8 ||
        offset > XTAJIT_GUEST_PAGE_SIZE - sizeof(descriptor))
        return UC_ERR_ARG;
    descriptor = make_segment_descriptor( base, 0xfffff, access, 0x0c );
#ifdef XTAJIT_UNIXLIB_TEST
    ++test_segment_descriptor_write_count;
#endif
    return uc_mem_write( engine->uc, XTAJIT_GUEST_GDT_PAGE + offset,
                         &descriptor, sizeof(descriptor) );
}

static uc_err load_segment( struct xtajit_engine *engine, int reg, uint32_t selector )
{
    uint16_t sel = selector;

    return uc_reg_write( engine->uc, reg, &sel );
}

static uc_err bootstrap_cpl3( struct xtajit_engine *engine )
{
    const uint16_t ring0_ss = 0x08, ring0_cs = 0x10;
    const uint16_t ring3_cs = 0x23, ring3_ss = 0x2b;
    const uint32_t frame_address = XTAJIT_GUEST_GDT_PAGE + 0xf00;
    const uint32_t user_esp = XTAJIT_GUEST_GDT_PAGE + 0xe00;
    const uint32_t landing = XTAJIT_GUEST_BOP_PAGE + XTAJIT_CPL3_LANDING_OFFSET;
    const uint32_t frame[] = { landing, ring3_cs, 0x202, user_esp, ring3_ss };
    uc_x86_mmr gdtr = {0};
    uint32_t esp, eip;
    uint16_t cs, ss;
    uc_err err;

    gdtr.base = XTAJIT_GUEST_GDT_PAGE;
    gdtr.limit = XTAJIT_GUEST_PAGE_SIZE - 1;
    if ((err = uc_reg_write( engine->uc, UC_X86_REG_GDTR, &gdtr )) != UC_ERR_OK) return err;
    if ((err = write_segment_descriptor( engine, ring0_ss, 0, 0x93 )) != UC_ERR_OK) return err;
    if ((err = write_segment_descriptor( engine, ring0_cs, 0, 0x9b )) != UC_ERR_OK) return err;
    if ((err = write_segment_descriptor( engine, ring3_cs, 0, 0xfb )) != UC_ERR_OK) return err;
    if ((err = write_segment_descriptor( engine, ring3_ss, 0, 0xf3 )) != UC_ERR_OK) return err;
    if ((err = uc_mem_write( engine->uc, frame_address, frame, sizeof(frame) )) != UC_ERR_OK)
        return err;
    if ((err = load_segment( engine, UC_X86_REG_SS, ring0_ss )) != UC_ERR_OK) return err;
    if ((err = load_segment( engine, UC_X86_REG_CS, ring0_cs )) != UC_ERR_OK) return err;
    esp = frame_address;
    if ((err = uc_reg_write( engine->uc, UC_X86_REG_ESP, &esp )) != UC_ERR_OK) return err;

    /* The protected-mode IRET is the only public Unicorn operation which also
     * updates its hidden CPL.  Stopping after exactly that instruction leaves
     * subsequent guest execution at CPL3 without relying on private QEMU APIs. */
    if ((err = uc_emu_start( engine->uc,
                             XTAJIT_GUEST_BOP_PAGE + XTAJIT_CPL3_IRET_OFFSET,
                             landing, 0, 1 )) != UC_ERR_OK)
        return err;
    if ((err = uc_reg_read( engine->uc, UC_X86_REG_CS, &cs )) != UC_ERR_OK) return err;
    if ((err = uc_reg_read( engine->uc, UC_X86_REG_SS, &ss )) != UC_ERR_OK) return err;
    if ((err = uc_reg_read( engine->uc, UC_X86_REG_EIP, &eip )) != UC_ERR_OK) return err;
    if ((err = uc_reg_read( engine->uc, UC_X86_REG_ESP, &esp )) != UC_ERR_OK) return err;
    if (cs != ring3_cs || ss != ring3_ss || eip != landing || esp != user_esp)
        return UC_ERR_EXCEPTION;
    return UC_ERR_OK;
}

static uc_err write_segments( struct xtajit_engine *engine,
                              const struct xtajit_i386_context *context,
                              uint32_t teb_guest )
{
    const uint32_t cs = context->seg_cs ? context->seg_cs : 0x23;
    const uint32_t ss = context->seg_ss ? context->seg_ss : 0x2b;
    const uint32_t ds = context->seg_ds ? context->seg_ds : 0x2b;
    const uint32_t es = context->seg_es ? context->seg_es : 0x2b;
    const uint32_t fs = context->seg_fs ? context->seg_fs : 0x53;
    const uint32_t gs = context->seg_gs ? context->seg_gs : 0x2b;
    uc_x86_mmr gdtr = {0};
    BOOL descriptors_unchanged;
    uc_err err;

    /* Unicorn retains each segment's hidden descriptor cache independently of
     * its visible selector.  Initializing only FS leaves SS (and potentially
     * the other flat Windows segments) with an engine-default base, so an
     * implicit stack access can land somewhere other than ESP.  Materialize
     * every changed selector in our private GDT; only FS is non-flat.  Guest
     * code may still load a different visible selector, so descriptor caching
     * must never suppress the register loads below. */
    if ((cs & 7) != 3 || (ss & 7) != 3 || (ds & 7) != 3 ||
        (es & 7) != 3 || (fs & 7) != 3 || (gs & 7) != 3 ||
        (cs & ~7u) == (ss & ~7u) || (cs & ~7u) == (ds & ~7u) ||
        (cs & ~7u) == (es & ~7u) || (cs & ~7u) == (fs & ~7u) ||
        (cs & ~7u) == (gs & ~7u) || (ss & ~7u) == (fs & ~7u) ||
        (ds & ~7u) == (fs & ~7u) || (es & ~7u) == (fs & ~7u) ||
        (gs & ~7u) == (fs & ~7u))
        return UC_ERR_ARG;

    descriptors_unchanged = engine->segment_state_valid &&
                            engine->segment_state.cs == cs &&
                            engine->segment_state.ss == ss &&
                            engine->segment_state.ds == ds &&
                            engine->segment_state.es == es &&
                            engine->segment_state.fs == fs &&
                            engine->segment_state.gs == gs &&
                            engine->segment_state.teb_guest == teb_guest;
    if (!descriptors_unchanged)
    {
        /* The engine and its GDT are thread-owned.  Invalidate before the
         * first Unicorn mutation so a partial failure can never make a later
         * caller trust the previously programmed descriptor state. */
        engine->segment_state_valid = FALSE;
        gdtr.base = XTAJIT_GUEST_GDT_PAGE;
        gdtr.limit = XTAJIT_GUEST_PAGE_SIZE - 1;
        if ((err = uc_reg_write( engine->uc, UC_X86_REG_GDTR, &gdtr )) != UC_ERR_OK) return err;
        if ((err = write_segment_descriptor( engine, cs, 0, 0xfb )) != UC_ERR_OK) return err;
        if ((err = write_segment_descriptor( engine, ss, 0, 0xf3 )) != UC_ERR_OK) return err;
        if ((err = write_segment_descriptor( engine, ds, 0, 0xf3 )) != UC_ERR_OK) return err;
        if ((err = write_segment_descriptor( engine, es, 0, 0xf3 )) != UC_ERR_OK) return err;
        if ((err = write_segment_descriptor( engine, gs, 0, 0xf3 )) != UC_ERR_OK) return err;
        if ((err = write_segment_descriptor( engine, fs, teb_guest, 0xf3 )) != UC_ERR_OK) return err;
    }

#define LOAD_SEGMENT(reg, selector, name) \
    do \
    { \
        if ((err = load_segment( engine, (reg), (selector) )) != UC_ERR_OK) \
        { \
            ERR( "cannot load " name " selector %#x: %s\n", \
                 (selector), uc_strerror( err ) ); \
            return err; \
        } \
    } while (0)
    LOAD_SEGMENT( UC_X86_REG_CS, cs, "CS" );
    LOAD_SEGMENT( UC_X86_REG_SS, ss, "SS" );
    LOAD_SEGMENT( UC_X86_REG_DS, ds, "DS" );
    LOAD_SEGMENT( UC_X86_REG_ES, es, "ES" );
    LOAD_SEGMENT( UC_X86_REG_GS, gs, "GS" );
    LOAD_SEGMENT( UC_X86_REG_FS, fs, "FS" );
#undef LOAD_SEGMENT
    engine->segment_state.cs = cs;
    engine->segment_state.ss = ss;
    engine->segment_state.ds = ds;
    engine->segment_state.es = es;
    engine->segment_state.fs = fs;
    engine->segment_state.gs = gs;
    engine->segment_state.teb_guest = teb_guest;
    engine->segment_state_valid = TRUE;
    return UC_ERR_OK;
}

static uc_err write_context( struct xtajit_engine *engine,
                             const struct xtajit_i386_context *context,
                             uint32_t teb_guest )
{
    const UINT32 *values = &context->eax;
    uc_err err;
    unsigned int i;

    if ((err = write_segments( engine, context, teb_guest )) != UC_ERR_OK) return err;
    for (i = 0; i < ARRAY_SIZE(integer_regs); ++i)
        if ((err = uc_reg_write( engine->uc, integer_regs[i], &values[i] )) != UC_ERR_OK) return err;
    if ((err = uc_reg_write( engine->uc, UC_X86_REG_MXCSR, &context->mxcsr )) != UC_ERR_OK) return err;
    for (i = 0; i < ARRAY_SIZE(xmm_regs); ++i)
        if ((err = uc_reg_write( engine->uc, xmm_regs[i], context->xmm[i] )) != UC_ERR_OK) return err;
    if (!context->fp_valid) return UC_ERR_OK;
    if ((err = uc_reg_write( engine->uc, UC_X86_REG_FPCW, &context->fp_control )) != UC_ERR_OK) return err;
    if ((err = uc_reg_write( engine->uc, UC_X86_REG_FPSW, &context->fp_status )) != UC_ERR_OK) return err;
    if ((err = uc_reg_write( engine->uc, UC_X86_REG_FPTAG, &context->fp_tag )) != UC_ERR_OK) return err;
    for (i = 0; i < ARRAY_SIZE(st_regs); ++i)
        if ((err = uc_reg_write( engine->uc, st_regs[i], context->st[i] )) != UC_ERR_OK) return err;
    return UC_ERR_OK;
}

static uc_err read_context( struct xtajit_engine *engine, struct xtajit_i386_context *context )
{
    UINT32 *values = &context->eax;
    UINT32 *segments[] =
    {
        &context->seg_cs, &context->seg_ss, &context->seg_ds,
        &context->seg_es, &context->seg_fs, &context->seg_gs,
    };
    uint16_t selector;
    uc_err err;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(integer_regs); ++i)
        if ((err = uc_reg_read( engine->uc, integer_regs[i], &values[i] )) != UC_ERR_OK) return err;
    for (i = 0; i < ARRAY_SIZE(segment_regs); ++i)
    {
        if ((err = uc_reg_read( engine->uc, segment_regs[i], &selector )) != UC_ERR_OK) return err;
        *segments[i] = selector;
    }
    if ((err = uc_reg_read( engine->uc, UC_X86_REG_MXCSR, &context->mxcsr )) != UC_ERR_OK) return err;
    for (i = 0; i < ARRAY_SIZE(xmm_regs); ++i)
        if ((err = uc_reg_read( engine->uc, xmm_regs[i], context->xmm[i] )) != UC_ERR_OK) return err;
    if (!context->fp_valid) return UC_ERR_OK;
    if ((err = uc_reg_read( engine->uc, UC_X86_REG_FPCW, &context->fp_control )) != UC_ERR_OK) return err;
    if ((err = uc_reg_read( engine->uc, UC_X86_REG_FPSW, &context->fp_status )) != UC_ERR_OK) return err;
    if ((err = uc_reg_read( engine->uc, UC_X86_REG_FPTAG, &context->fp_tag )) != UC_ERR_OK) return err;
    for (i = 0; i < ARRAY_SIZE(st_regs); ++i)
        if ((err = uc_reg_read( engine->uc, st_regs[i], context->st[i] )) != UC_ERR_OK) return err;
    return UC_ERR_OK;
}

static const unsigned char bop_page[XTAJIT_CPL3_LANDING_OFFSET + 1] =
{
    [0] = 0xcc,
    [0x10] = 0xcc,
    [XTAJIT_CPL3_IRET_OFFSET] = 0xcf,
    [XTAJIT_CPL3_LANDING_OFFSET] = 0x90,
};

#define XTAJIT_MAX_OBSERVER_RANGES (1u << 20)

static uc_err install_engine( struct xtajit_engine *engine )
{
    uc_hook hook;
    uc_err err;

    if ((err = uc_open( UC_ARCH_X86, UC_MODE_32, &engine->uc )) != UC_ERR_OK) return err;
    if ((err = uc_enable_shared_memory_atomics( engine->uc )) != UC_ERR_OK)
    {
        uc_close( engine->uc );
        engine->uc = NULL;
        return err;
    }
    if ((err = uc_mem_map( engine->uc, XTAJIT_GUEST_GDT_PAGE, XTAJIT_GUEST_PAGE_SIZE,
                           UC_PROT_READ | UC_PROT_WRITE )) != UC_ERR_OK ||
        (err = uc_mem_map( engine->uc, XTAJIT_GUEST_BOP_PAGE, XTAJIT_GUEST_PAGE_SIZE,
                           UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC )) != UC_ERR_OK ||
        (err = uc_mem_write( engine->uc, XTAJIT_GUEST_BOP_PAGE,
                             bop_page, sizeof(bop_page) )) != UC_ERR_OK ||
        (err = bootstrap_cpl3( engine )) != UC_ERR_OK ||
        (err = uc_mem_protect( engine->uc, XTAJIT_GUEST_BOP_PAGE, XTAJIT_GUEST_PAGE_SIZE,
                               UC_PROT_READ | UC_PROT_EXEC )) != UC_ERR_OK ||
        (err = uc_mem_protect( engine->uc, XTAJIT_GUEST_GDT_PAGE, XTAJIT_GUEST_PAGE_SIZE,
                               UC_PROT_READ )) != UC_ERR_OK ||
        (err = uc_hook_add( engine->uc, &hook, UC_HOOK_CODE, bop_hook, engine,
                            XTAJIT_GUEST_BOP_PAGE,
                            XTAJIT_GUEST_BOP_PAGE + XTAJIT_GUEST_PAGE_SIZE - 1 )) != UC_ERR_OK ||
        (err = uc_hook_add( engine->uc, &hook, UC_HOOK_INTR,
                            interrupt_hook, engine, 1, 0 )) != UC_ERR_OK ||
        (err = uc_hook_add( engine->uc, &hook, UC_HOOK_INSN,
                            privileged_in_hook, engine, 1, 0, UC_X86_INS_IN )) != UC_ERR_OK ||
        (err = uc_hook_add( engine->uc, &hook, UC_HOOK_INSN,
                            privileged_out_hook, engine, 1, 0, UC_X86_INS_OUT )) != UC_ERR_OK ||
        (err = uc_hook_add( engine->uc, &hook, UC_HOOK_INSN_INVALID,
                            invalid_instruction_hook, engine, 1, 0 )) != UC_ERR_OK ||
        (err = uc_hook_add( engine->uc, &hook, UC_HOOK_MEM_INVALID,
                            invalid_memory_hook, engine, 1, 0 )) != UC_ERR_OK ||
#if defined(XTAJIT_UNIXLIB_TEST) && !defined(UC_SWITCHYARD_SHARED_MEMORY_ATOMICS)
        (err = uc_hook_add( engine->uc, &hook, UC_HOOK_MEM_WRITE,
                            test_memory_write_hook, engine, 1, 0 )) != UC_ERR_OK ||
#endif
        (err = map_registry( engine, &provider.ranges )) != UC_ERR_OK)
    {
        uc_close( engine->uc );
        engine->uc = NULL;
    }
    return err;
}

static void unlink_engine_locked( struct xtajit_engine *engine )
{
    struct xtajit_engine **cursor;

    if (!engine->linked) return;
    for (cursor = &provider.engines; *cursor && *cursor != engine; cursor = &(*cursor)->next);
    if (*cursor == engine) *cursor = engine->next;
    engine->next = NULL;
    engine->linked = FALSE;
}

static void destroy_thread_engine( void *value )
{
    struct xtajit_engine *engine = value;
    uc_engine *uc;

    if (!engine) return;
    pthread_mutex_lock( &provider.mutex );
    while (provider.mutating && provider.initialized)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (engine->running)
    {
        poison_provider_locked( STATUS_UNSUCCESSFUL );
        request_engine_pause_locked( engine );
        while (engine->running) pthread_cond_wait( &provider.cond, &provider.mutex );
    }
    unlink_engine_locked( engine );
    uc = engine->uc;
    engine->uc = NULL;
    pthread_mutex_unlock( &provider.mutex );
    if (uc) uc_close( uc );
    free( engine );
}

static void make_engine_key(void)
{
    engine_key_error = pthread_key_create( &engine_key, destroy_thread_engine );
}

static BOOL host_to_guest_range( uint64_t address, uint64_t size,
                                 uint64_t *guest, uint64_t *end )
{
    uint64_t offset;

    if (!guest || !end || !size || address > UINT64_MAX - size) return FALSE;
    if (provider.low_va_shadow_base)
    {
        if (address < provider.low_va_shadow_base) return FALSE;
        offset = address - provider.low_va_shadow_base;
    }
    else offset = address;
    if (offset >= provider.low_va_shadow_size || size > provider.low_va_shadow_size - offset)
        return FALSE;
    *guest = offset;
    *end = offset + size;
    return TRUE;
}

static BOOL host_to_guest_allocation( uint64_t address, uint64_t *guest )
{
    uint64_t end;

    if (!address || !host_to_guest_range( address, XTAJIT_GUEST_PAGE_SIZE, guest, &end ))
        return FALSE;
    return !(*guest & (XTAJIT_GUEST_PAGE_SIZE - 1));
}

static BOOL event_has_kuser( uint64_t start, uint64_t end )
{
    return start <= provider.guest_kuser &&
           end >= provider.guest_kuser + provider.kuser_size;
}

static BOOL observer_event_header_is_valid( const struct wine_wow64_memory_event_v1 *event )
{
    return event && event->version == WINE_WOW64_MEMORY_OBSERVER_VERSION &&
           event->size >= sizeof(*event) && !event->reserved[0] && !event->reserved[1] &&
           !(event->flags & ~WINE_WOW64_MEMORY_EVENT_FULL_SNAPSHOT) &&
           event->range_count <= XTAJIT_MAX_OBSERVER_RANGES &&
           event->range_count <= SIZE_MAX / sizeof(*event->ranges) &&
           (!event->range_count || event->ranges);
}

static NTSTATUS append_snapshot_mapping( struct range_array *result,
                                         const struct mapped_range *mapping,
                                         uint64_t coverage_start, uint64_t coverage_end,
                                         BOOL *inserted_kuser )
{
    struct mapped_range kuser, slice;
    uint64_t mapping_end = mapping->guest + mapping->size;
    uint64_t kuser_end = provider.guest_kuser + provider.kuser_size;

    kuser.guest = provider.guest_kuser;
    kuser.host = provider.host_kuser;
    kuser.size = provider.kuser_size;
    kuser.allocation_base = provider.guest_kuser;
    kuser.perms = UC_PROT_READ;
    kuser.permanent = TRUE;

    if (!*inserted_kuser && event_has_kuser( coverage_start, coverage_end ) &&
        mapping->guest >= kuser_end)
    {
        if (!range_array_append( result, &kuser )) return STATUS_NO_MEMORY;
        *inserted_kuser = TRUE;
    }
    if (mapping_end <= provider.guest_kuser || mapping->guest >= kuser_end)
        return range_array_append( result, mapping ) ? STATUS_SUCCESS : STATUS_NO_MEMORY;

    if (mapping->guest < provider.guest_kuser)
    {
        slice = range_slice( mapping, mapping->guest, provider.guest_kuser );
        if (!range_array_append( result, &slice )) return STATUS_NO_MEMORY;
    }
    if (!*inserted_kuser)
    {
        if (!range_array_append( result, &kuser )) return STATUS_NO_MEMORY;
        *inserted_kuser = TRUE;
    }
    if (mapping_end > kuser_end)
    {
        slice = range_slice( mapping, kuser_end, mapping_end );
        if (!range_array_append( result, &slice )) return STATUS_NO_MEMORY;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS build_event_registry( const struct wine_wow64_memory_event_v1 *event,
                                      uint64_t *coverage_start, uint64_t *coverage_end,
                                      struct range_array *result )
{
    const struct wine_wow64_memory_range_v1 *ranges;
    struct wine_wow64_memory_range_v1 *copy = NULL;
    struct mapped_range mapping, kuser;
    uint64_t host_cursor, host_end, guest, end, allocation_base;
    size_t count, i;
    BOOL inserted_kuser = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (!observer_event_header_is_valid( event ) || !event->size_covered ||
        !host_to_guest_range( event->address, event->size_covered,
                              coverage_start, coverage_end ) ||
        ((*coverage_start | *coverage_end) & (XTAJIT_GUEST_PAGE_SIZE - 1)))
        return STATUS_INVALID_PARAMETER;

    count = event->range_count;
    ranges = event->ranges;
    if (count)
    {
        if (!(copy = malloc( count * sizeof(*copy) ))) return STATUS_NO_MEMORY;
        memcpy( copy, ranges, count * sizeof(*copy) );
    }
    if (!range_array_reserve( result, count + 1 ))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    host_cursor = event->address;
    for (i = 0; i < count; ++i)
    {
        if (copy[i].reserved ||
            copy[i].flags & ~(WINE_WOW64_MEMORY_RANGE_TRANSLATED |
                              WINE_WOW64_MEMORY_RANGE_LOGICAL_WRITE_FAULT) ||
            copy[i].address != host_cursor || !copy[i].size ||
            copy[i].address > UINT64_MAX - copy[i].size ||
            ((copy[i].address | copy[i].size) & (XTAJIT_GUEST_PAGE_SIZE - 1)) ||
            !host_to_guest_range( copy[i].address, copy[i].size, &guest, &end ))
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
        host_end = copy[i].address + copy[i].size;
        if (host_end > event->address + event->size_covered ||
            (copy[i].state != MEM_FREE && copy[i].state != MEM_RESERVE &&
             copy[i].state != MEM_COMMIT))
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }

        if (copy[i].state == MEM_FREE)
        {
            if (copy[i].flags || copy[i].allocation_base ||
                copy[i].protect != PAGE_NOACCESS)
            {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }
        }
        else
        {
            if (!host_to_guest_allocation( copy[i].allocation_base, &allocation_base ) ||
                !(copy[i].flags & WINE_WOW64_MEMORY_RANGE_TRANSLATED) ||
                (copy[i].state != MEM_COMMIT &&
                 (copy[i].flags & WINE_WOW64_MEMORY_RANGE_LOGICAL_WRITE_FAULT)) ||
                allocation_base > guest ||
                (copy[i].state == MEM_RESERVE && copy[i].protect) ||
                overlaps_provider_pages( guest, end ))
            {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }
        }

        if (copy[i].state == MEM_COMMIT)
        {
            mapping.guest = guest;
            mapping.host = copy[i].address;
            mapping.size = copy[i].size;
            mapping.allocation_base = allocation_base;
            mapping.perms = protection_to_unicorn( copy[i].protect );
            if (copy[i].flags & WINE_WOW64_MEMORY_RANGE_LOGICAL_WRITE_FAULT)
                mapping.perms &= ~UC_PROT_WRITE;
            mapping.permanent = FALSE;
            if ((status = append_snapshot_mapping( result, &mapping, *coverage_start,
                                                   *coverage_end, &inserted_kuser )))
                goto done;
        }
        else if (!inserted_kuser && event_has_kuser( *coverage_start, *coverage_end ) &&
                 guest <= provider.guest_kuser && end >= provider.guest_kuser + provider.kuser_size)
        {
            kuser.guest = provider.guest_kuser;
            kuser.host = provider.host_kuser;
            kuser.size = provider.kuser_size;
            kuser.allocation_base = provider.guest_kuser;
            kuser.perms = UC_PROT_READ;
            kuser.permanent = TRUE;
            if (!range_array_append( result, &kuser ))
            {
                status = STATUS_NO_MEMORY;
                goto done;
            }
            inserted_kuser = TRUE;
        }
        host_cursor = host_end;
    }
    if (host_cursor != event->address + event->size_covered)
    {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    if (!inserted_kuser && event_has_kuser( *coverage_start, *coverage_end ))
    {
        kuser.guest = provider.guest_kuser;
        kuser.host = provider.host_kuser;
        kuser.size = provider.kuser_size;
        kuser.allocation_base = provider.guest_kuser;
        kuser.perms = UC_PROT_READ;
        kuser.permanent = TRUE;
        if (!range_array_append( result, &kuser )) status = STATUS_NO_MEMORY;
    }

done:
    free( copy );
    return status;
}

static NTSTATUS build_replaced_registry( const struct range_array *old,
                                         const struct range_array *snapshot,
                                         uint64_t start, uint64_t end,
                                         struct range_array *result )
{
    size_t i;

    if (old->count > SIZE_MAX - snapshot->count - 2 ||
        !range_array_reserve( result, old->count + snapshot->count + 2 ))
        return STATUS_NO_MEMORY;
    for (i = 0; i < old->count; ++i)
    {
        const struct mapped_range *range = &old->data[i];
        uint64_t range_end = range->guest + range->size;
        struct mapped_range slice;

        if (range_end <= start)
        {
            if (!range_array_append( result, range )) return STATUS_INVALID_ADDRESS;
        }
        else if (range->guest < start)
        {
            slice = range_slice( range, range->guest, start );
            if (!range_array_append( result, &slice )) return STATUS_INVALID_ADDRESS;
        }
    }
    for (i = 0; i < snapshot->count; ++i)
        if (!range_array_append( result, &snapshot->data[i] )) return STATUS_INVALID_ADDRESS;
    for (i = 0; i < old->count; ++i)
    {
        const struct mapped_range *range = &old->data[i];
        uint64_t range_end = range->guest + range->size;
        struct mapped_range slice;

        if (range->guest >= end)
        {
            if (!range_array_append( result, range )) return STATUS_INVALID_ADDRESS;
        }
        else if (range_end > end)
        {
            slice = range_slice( range, end, range_end );
            if (!range_array_append( result, &slice )) return STATUS_INVALID_ADDRESS;
        }
    }
    return STATUS_SUCCESS;
}

static uc_err map_registry_intersections( struct xtajit_engine *engine,
                                          const struct range_array *ranges,
                                          uint64_t start, uint64_t end )
{
    size_t i;
    uc_err err;

    for (i = 0; i < ranges->count; ++i)
    {
        const struct mapped_range *range = &ranges->data[i];

        if (range->permanent || !range_overlaps( range, start, end )) continue;
        if ((err = map_host_range( engine, range->guest, range->host, range->size,
                                   range->perms )) != UC_ERR_OK)
            return err;
    }
    return UC_ERR_OK;
}

static BOOL fail_test_engine_mutation(void)
{
#ifdef XTAJIT_UNIXLIB_TEST
    return test_fail_engine_mutation >= 0 &&
           test_engine_mutation_count++ == test_fail_engine_mutation;
#else
    return FALSE;
#endif
}

static int32_t observer_begin_callback( void *context, uint32_t operation, uint64_t address,
                                        uint64_t size, uint64_t allocation_base,
                                        void **transaction )
{
    uint64_t start = 0, end = 0, allocation_guest = 0, token;
    NTSTATUS status;

    if (context != &provider || !transaction ||
        operation < WINE_WOW64_MEMORY_RESYNC || operation > WINE_WOW64_MEMORY_UNMAP)
        return STATUS_INVALID_PARAMETER;
    *transaction = NULL;
    if (!address && size && operation != WINE_WOW64_MEMORY_ALLOCATE &&
        operation != WINE_WOW64_MEMORY_COMMIT && operation != WINE_WOW64_MEMORY_MAP)
        return STATUS_INVALID_PARAMETER;
    /* Automatic allocations and mappings have no address until after the
     * mutation.  Their successful complete event supplies the authoritative
     * coverage while this transaction still excludes every engine. */
    if (address && size && !host_to_guest_range( address, size, &start, &end ))
        return STATUS_INVALID_PARAMETER;
    if (operation == WINE_WOW64_MEMORY_RESYNC &&
        (!address || !size || start || end != provider.low_va_shadow_size))
        return STATUS_INVALID_PARAMETER;
    if (allocation_base && !host_to_guest_allocation( allocation_base, &allocation_guest ))
        return STATUS_INVALID_PARAMETER;

    pthread_mutex_lock( &provider.mutex );
    status = begin_mutation_locked();
    if (!status)
    {
        if (!(token = ++provider.next_mutation_token)) token = ++provider.next_mutation_token;
        provider.observer_transaction = TRUE;
        provider.mutation_owner = pthread_self();
        provider.mutation_token = token;
        provider.mutation_start = start;
        provider.mutation_end = end;
        provider.mutation_allocation_base = allocation_guest;
        provider.mutation_operation = operation;
        provider.mutation_resync = operation == WINE_WOW64_MEMORY_RESYNC;
        *transaction = (void *)(uintptr_t)token;
    }
    pthread_mutex_unlock( &provider.mutex );
    return status;
}

static void observer_complete_callback( void *context, void *transaction,
                                        const struct wine_wow64_memory_event_v1 *event )
{
    struct range_array snapshot = {0}, replacement = {0};
    struct xtajit_engine *engine;
    uint64_t expected_allocation = 0, start = 0, end = 0;
    uint64_t token = (uintptr_t)transaction;
    NTSTATUS status = STATUS_SUCCESS;
    uc_err err = UC_ERR_OK;
    BOOL no_snapshot_change = FALSE, owns_transaction;

    pthread_mutex_lock( &provider.mutex );
    owns_transaction = context == &provider && provider.mutating &&
                       provider.observer_transaction && token &&
                       token == provider.mutation_token &&
                       pthread_equal( provider.mutation_owner, pthread_self() );
    if (!owns_transaction)
        status = STATUS_INVALID_DEVICE_STATE;
    else if (!observer_event_header_is_valid( event ) || event->snapshot_status ||
             event->operation != provider.mutation_operation)
        status = event && event->snapshot_status ? event->snapshot_status :
                 STATUS_INVALID_PARAMETER;
    else
    {
        if (!event->size_covered)
        {
            /* A failed address-selected allocation can leave no range to
             * snapshot.  It is an exact no-op only when ntdll reports failure
             * and no coverage; successful mutations must always describe
             * their final state. */
            if (event->status >= 0 || event->address || event->range_count ||
                provider.mutation_end)
                status = STATUS_INVALID_PARAMETER;
            else
                no_snapshot_change = TRUE;
        }
        else
            status = build_event_registry( event, &start, &end, &snapshot );

        if (!status && provider.mutation_resync !=
            !!(event->flags & WINE_WOW64_MEMORY_EVENT_FULL_SNAPSHOT))
            status = STATUS_INVALID_PARAMETER;
        else if (!status && provider.mutation_resync &&
                 (start || end != provider.low_va_shadow_size))
            status = STATUS_INVALID_PARAMETER;
        else if (!status && provider.mutation_end &&
                 (start > provider.mutation_start || end < provider.mutation_end))
            status = STATUS_INVALID_PARAMETER;
        else if (!status && provider.mutation_allocation_base &&
                 (!guest_to_host_address( provider.mutation_allocation_base,
                                          &expected_allocation ) ||
                  event->allocation_base != expected_allocation))
            status = STATUS_INVALID_PARAMETER;
        else if (!status && !no_snapshot_change)
            status = build_replaced_registry( &provider.ranges, &snapshot,
                                              start, end, &replacement );
    }

    if (!status)
    {
#ifdef XTAJIT_UNIXLIB_TEST
        test_engine_mutation_count = 0;
#endif
        for (engine = provider.engines; engine; engine = engine->next)
        {
            if (fail_test_engine_mutation() || (!no_snapshot_change &&
                ((err = unmap_registry_intersections( engine, &provider.ranges,
                                                       start, end )) != UC_ERR_OK ||
                 (err = map_registry_intersections( engine, &snapshot,
                                                    start, end )) != UC_ERR_OK ||
                 (provider.mutation_resync ? uc_ctl_flush_tb( engine->uc ) :
                  uc_ctl_remove_cache( engine->uc, start, end )) != UC_ERR_OK)) ||
                (provider.mutation_flush_all && uc_ctl_flush_tb( engine->uc ) != UC_ERR_OK) ||
                (!provider.mutation_flush_all && provider.mutation_flush_end &&
                 uc_ctl_remove_cache( engine->uc, provider.mutation_flush_start,
                                      provider.mutation_flush_end ) != UC_ERR_OK))
            {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    if (!status)
    {
        if (!no_snapshot_change)
        {
            struct range_array old = provider.ranges;

            provider.ranges = replacement;
            memset( &replacement, 0, sizeof(replacement) );
            range_array_free( &old );
            if (provider.mutation_resync) provider.observer_active = TRUE;
        }
    }
    else
    {
        WARN( "cannot publish i386 memory observer operation %u status %#x: %s\n",
              event ? event->operation : 0, (unsigned int)status, uc_strerror( err ) );
        poison_provider_locked( status );
    }
    if (owns_transaction) finish_mutation_locked();
    pthread_mutex_unlock( &provider.mutex );
    range_array_free( &snapshot );
    range_array_free( &replacement );
}

static const struct wine_wow64_memory_observer_v1 memory_observer =
{
    WINE_WOW64_MEMORY_OBSERVER_VERSION,
    sizeof(memory_observer),
    &provider,
    observer_begin_callback,
    observer_complete_callback,
    WINE_WOW64_MEMORY_OBSERVER_CAP_LOGICAL_WRITE_FAULT,
};

static int32_t register_memory_observer(void)
{
#ifdef XTAJIT_UNIXLIB_TEST
    struct wine_wow64_memory_range_v1 range = {0};
    struct wine_wow64_memory_event_v1 event = {0};
    void *transaction;
    int32_t status;

    range.address = provider.low_va_shadow_base;
    range.size = provider.low_va_shadow_size;
    range.state = MEM_FREE;
    range.protect = PAGE_NOACCESS;
    event.version = WINE_WOW64_MEMORY_OBSERVER_VERSION;
    event.size = sizeof(event);
    event.operation = WINE_WOW64_MEMORY_RESYNC;
    event.flags = WINE_WOW64_MEMORY_EVENT_FULL_SNAPSHOT;
    event.address = range.address;
    event.size_covered = range.size;
    event.ranges = &range;
    event.range_count = 1;
    status = memory_observer.begin( memory_observer.context, event.operation,
                                    event.address, event.size_covered, 0, &transaction );
    if (!status) memory_observer.complete( memory_observer.context, transaction, &event );
    return status;
#else
    return __wine_register_wow64_memory_observer( &memory_observer );
#endif
}

static NTSTATUS process_init( void *args )
{
    struct xtajit_process_init_params *params = args;
    struct mapped_range kuser;
    NTSTATUS status;
    unsigned int major, minor;

    if (!params || params->version != XTAJIT_PROCESS_ABI_VERSION ||
        params->size < sizeof(*params) ||
        (params->required_capabilities & XTAJIT_PROCESS_REQUIRED_CAPABILITIES) !=
            XTAJIT_PROCESS_REQUIRED_CAPABILITIES ||
        params->required_capabilities & ~XTAJIT_PROCESS_REQUIRED_CAPABILITIES ||
        !params->highest_user_address ||
        params->highest_user_address >= XTAJIT_GUEST_BOP_PAGE ||
        params->guest_kuser != XTAJIT_GUEST_KUSER || !params->host_kuser ||
        params->kuser_size != XTAJIT_GUEST_PAGE_SIZE ||
        (params->guest_kuser & (params->kuser_size - 1)) ||
        (params->host_kuser & (params->kuser_size - 1)) ||
        params->low_va_shadow_base > UINT64_MAX - params->low_va_shadow_size ||
        params->low_va_shadow_base > UINT64_MAX - params->guest_kuser ||
        params->host_kuser != params->low_va_shadow_base + params->guest_kuser ||
#ifdef XTAJIT_UNIXLIB_TEST
        !params->low_va_shadow_base ||
        (params->low_va_shadow_base & (XTAJIT_GUEST_PAGE_SIZE - 1)) ||
        params->low_va_shadow_size != WINE_LOW_VA_SHADOW_SIZE)
#else
        !((!params->low_va_shadow_base &&
           params->low_va_shadow_size == WINE_LOW_VA_SHADOW_SIZE) ||
          (params->low_va_shadow_base == WINE_LOW_VA_SHADOW_BASE &&
           params->low_va_shadow_size == WINE_LOW_VA_SHADOW_SIZE)))
#endif
        return STATUS_INVALID_PARAMETER;
    params->enabled_capabilities = 0;

    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error) return STATUS_NO_MEMORY;
    uc_version( &major, &minor );
    if (major != UC_API_MAJOR || (major == 2 && minor < 1))
        return STATUS_REVISION_MISMATCH;

    pthread_mutex_lock( &provider.mutex );
    if (provider.initialized)
    {
        pthread_mutex_unlock( &provider.mutex );
        return STATUS_ALREADY_INITIALIZED;
    }
    provider.low_va_shadow_base = params->low_va_shadow_base;
    provider.low_va_shadow_size = params->low_va_shadow_size;
    provider.guest_kuser = params->guest_kuser;
    provider.host_kuser = params->host_kuser;
    provider.kuser_size = params->kuser_size;
    provider.poison_status = STATUS_SUCCESS;
    provider.shutting_down = FALSE;
    provider.observer_active = FALSE;
    provider.next_mutation_token = 0;

    kuser.guest = params->guest_kuser;
    kuser.host = params->host_kuser;
    kuser.size = params->kuser_size;
    kuser.allocation_base = params->guest_kuser;
    kuser.perms = UC_PROT_READ;
    kuser.permanent = TRUE;
    if (!range_array_append( &provider.ranges, &kuser ))
    {
        pthread_mutex_unlock( &provider.mutex );
        return STATUS_NO_MEMORY;
    }
    provider.initialized = TRUE;
    pthread_mutex_unlock( &provider.mutex );

    status = register_memory_observer();
    pthread_mutex_lock( &provider.mutex );
    if (!status && !provider.observer_active) status = STATUS_INVALID_DEVICE_STATE;
    if (!status && provider.poison_status) status = provider.poison_status;
    if (status) poison_provider_locked( status );
    pthread_mutex_unlock( &provider.mutex );
    if (status) return status;
    params->enabled_capabilities = XTAJIT_PROCESS_REQUIRED_CAPABILITIES;

    TRACE( "initialized Unicorn %u.%u i386 provider registry, KUSER guest %p host %p, "
           "shadow %p-%p, syscall BOP %p unix BOP %p\n", major, minor,
           (void *)(uintptr_t)params->guest_kuser, (void *)(uintptr_t)params->host_kuser,
           (void *)(uintptr_t)params->low_va_shadow_base,
           (void *)(uintptr_t)(params->low_va_shadow_base + params->low_va_shadow_size),
           (void *)(uintptr_t)XTAJIT_GUEST_SYSCALL_BOP,
           (void *)(uintptr_t)XTAJIT_GUEST_UNIX_BOP );
    return STATUS_SUCCESS;
}

static NTSTATUS process_term( void *args )
{
#ifndef XTAJIT_UNIXLIB_TEST
    NTSTATUS status;
#endif

    (void)args;
#ifdef XTAJIT_UNIXLIB_TEST
    pthread_mutex_lock( &provider.mutex );
    if (provider.engines || provider.mutating)
    {
        pthread_mutex_unlock( &provider.mutex );
        return STATUS_INVALID_DEVICE_STATE;
    }
    range_array_free( &provider.ranges );
    provider.initialized = FALSE;
    provider.shutting_down = FALSE;
    provider.observer_active = FALSE;
    provider.observer_transaction = FALSE;
    provider.mutation_token = 0;
    provider.next_mutation_token = 0;
    provider.mutation_start = 0;
    provider.mutation_end = 0;
    provider.mutation_allocation_base = 0;
    provider.mutation_operation = 0;
    provider.mutation_resync = FALSE;
    provider.mutation_flush_all = FALSE;
    provider.mutation_flush_start = 0;
    provider.mutation_flush_end = 0;
    provider.low_va_shadow_base = 0;
    provider.low_va_shadow_size = 0;
    provider.guest_kuser = 0;
    provider.host_kuser = 0;
    provider.kuser_size = 0;
    provider.poison_status = STATUS_SUCCESS;
    pthread_mutex_unlock( &provider.mutex );
    return STATUS_SUCCESS;
#else
    pthread_mutex_lock( &provider.mutex );
    status = provider.initialized ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
    pthread_mutex_unlock( &provider.mutex );
    return status;
#endif
}

static NTSTATUS thread_init( void *args )
{
    struct xtajit_engine *engine;
    uc_err err;
    int ret;

    (void)args;
    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error) return STATUS_NO_MEMORY;
    if ((engine = pthread_getspecific( engine_key )))
    {
        if (engine->uc && engine->linked) return STATUS_SUCCESS;
        if ((ret = pthread_setspecific( engine_key, NULL )))
            return ret == ENOMEM ? STATUS_NO_MEMORY : STATUS_UNSUCCESSFUL;
        destroy_thread_engine( engine );
    }
    if (!(engine = calloc( 1, sizeof(*engine) ))) return STATUS_NO_MEMORY;
    engine->owner = pthread_self();

    pthread_mutex_lock( &provider.mutex );
    while (provider.mutating && provider.initialized)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (!provider.initialized || provider.shutting_down) ret = STATUS_INVALID_HANDLE;
    else if (provider.poison_status) ret = provider.poison_status;
    else
    {
        /* bootstrap_cpl3 executes guest code and may acquire Unicorn's global
         * code-coherence exclusion.  An existing engine's start hook may need
         * provider.mutex while counted as running by that exclusion.  Quiesce
         * existing engines before installing this one to avoid lock inversion. */
        ret = begin_mutation_locked();
        if (!ret)
        {
            if ((err = install_engine( engine )) != UC_ERR_OK)
            {
                WARN( "cannot initialize thread-owned i386 engine: %s\n", uc_strerror( err ) );
                ret = STATUS_NOT_SUPPORTED;
            }
            else
            {
                engine->next = provider.engines;
                provider.engines = engine;
                engine->linked = TRUE;
                if ((ret = pthread_setspecific( engine_key, engine )))
                {
                    unlink_engine_locked( engine );
                    uc_close( engine->uc );
                    engine->uc = NULL;
                    ret = ret == ENOMEM ? STATUS_NO_MEMORY : STATUS_UNSUCCESSFUL;
                }
            }
        }
        finish_mutation_locked();
    }
    pthread_mutex_unlock( &provider.mutex );
    if (ret) free( engine );
    return ret;
}

static NTSTATUS thread_term( void *args )
{
    struct xtajit_engine *engine;
    int ret;

    (void)args;
    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error) return STATUS_UNSUCCESSFUL;
    if (!(engine = pthread_getspecific( engine_key ))) return STATUS_SUCCESS;
    if ((ret = pthread_setspecific( engine_key, NULL )))
        return ret == ENOMEM ? STATUS_NO_MEMORY : STATUS_UNSUCCESSFUL;
    destroy_thread_engine( engine );
    return STATUS_SUCCESS;
}

static NTSTATUS memory_map( void *args )
{
    const struct xtajit_memory_params *params = args;
    struct mapped_range mapping;
    struct range_array replacement = {0};
    struct xtajit_engine *engine;
    uint64_t start, end;
    NTSTATUS status;
    uc_err err = UC_ERR_OK;

    if (!params || !params->guest || !params->host || !params->size ||
        !params->allocation_base || params->reserved ||
        !host_range_matches_guest( params->guest, params->host, params->size ) ||
        !align_range( params->guest, params->size, &start, &end ) ||
        end > WINE_LOW_VA_SHADOW_SIZE || overlaps_provider_pages( start, end ) ||
        (params->allocation_base & (XTAJIT_GUEST_PAGE_SIZE - 1)) ||
        params->allocation_base > start)
        return STATUS_INVALID_PARAMETER;
    mapping.guest = start;
    mapping.host = params->host - (params->guest - start);
    mapping.size = end - start;
    mapping.allocation_base = params->allocation_base;
    mapping.perms = protection_to_unicorn( params->protect );
    mapping.permanent = FALSE;

    pthread_mutex_lock( &provider.mutex );
    if (provider.observer_active)
    {
        status = provider.poison_status;
        pthread_mutex_unlock( &provider.mutex );
        return status;
    }
    if (!(status = begin_mutation_locked()))
        status = build_mapped_registry( &provider.ranges, &mapping, &replacement );
    if (!status)
    {
#ifdef XTAJIT_UNIXLIB_TEST
        test_engine_mutation_count = 0;
#endif
        for (engine = provider.engines; engine; engine = engine->next)
        {
            if (fail_test_engine_mutation() ||
                (err = unmap_registry_intersections( engine, &provider.ranges,
                                                      start, end )) != UC_ERR_OK ||
                (err = map_host_range( engine, mapping.guest, mapping.host,
                                       mapping.size, mapping.perms )) != UC_ERR_OK ||
                (err = uc_ctl_remove_cache( engine->uc, start, end )) != UC_ERR_OK)
            {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    if (!status)
    {
        struct range_array old = provider.ranges;

        provider.ranges = replacement;
        memset( &replacement, 0, sizeof(replacement) );
        range_array_free( &old );
    }
    else if (provider.initialized) poison_provider_locked( status );
    if (provider.mutating) finish_mutation_locked();
    pthread_mutex_unlock( &provider.mutex );
    range_array_free( &replacement );
    return status;
}

static NTSTATUS memory_unmap( void *args )
{
    const struct xtajit_memory_params *params = args;
    struct range_array replacement = {0};
    struct xtajit_engine *engine;
    uint64_t guest, size, end;
    NTSTATUS status;
    uc_err err = UC_ERR_OK;

    if (!params || !params->guest || params->reserved) return STATUS_INVALID_PARAMETER;
    if (params->size)
    {
        if (!align_range( params->guest, params->size, &guest, &end ) ||
            end > WINE_LOW_VA_SHADOW_SIZE || overlaps_provider_pages( guest, end ))
            return STATUS_INVALID_PARAMETER;
        size = end - guest;
    }
    else
    {
        guest = align_down( params->guest );
        size = 0;
        if (guest >= XTAJIT_GUEST_BOP_PAGE) return STATUS_INVALID_PARAMETER;
    }

    pthread_mutex_lock( &provider.mutex );
    if (provider.observer_active)
    {
        status = provider.poison_status;
        pthread_mutex_unlock( &provider.mutex );
        return status;
    }
    if (!(status = begin_mutation_locked()))
        status = build_unmapped_registry( &provider.ranges, guest, size, guest, &replacement );
    if (!status)
    {
#ifdef XTAJIT_UNIXLIB_TEST
        test_engine_mutation_count = 0;
#endif
        for (engine = provider.engines; engine; engine = engine->next)
        {
            if (fail_test_engine_mutation()) err = UC_ERR_RESOURCE;
            else if (size)
                err = unmap_registry_intersections( engine, &provider.ranges,
                                                    guest, guest + size );
            else err = unmap_allocation_ranges( engine, &provider.ranges, guest );
            if (err != UC_ERR_OK)
            {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    if (!status)
    {
        struct range_array old = provider.ranges;

        provider.ranges = replacement;
        memset( &replacement, 0, sizeof(replacement) );
        range_array_free( &old );
    }
    else if (provider.initialized) poison_provider_locked( status );
    if (provider.mutating) finish_mutation_locked();
    pthread_mutex_unlock( &provider.mutex );
    range_array_free( &replacement );
    return status;
}

static NTSTATUS memory_protect( void *args )
{
    const struct xtajit_memory_params *params = args;
    struct range_array replacement = {0};
    struct xtajit_engine *engine;
    uint64_t start, end;
    unsigned int perms;
    NTSTATUS status;
    uc_err err = UC_ERR_OK;
    size_t i;

    if (!params || !params->guest || !params->size || params->reserved ||
        !align_range( params->guest, params->size, &start, &end ) ||
        end > WINE_LOW_VA_SHADOW_SIZE || overlaps_provider_pages( start, end ))
        return STATUS_INVALID_PARAMETER;
    perms = protection_to_unicorn( params->protect );

    pthread_mutex_lock( &provider.mutex );
    if (provider.observer_active)
    {
        status = provider.poison_status;
        pthread_mutex_unlock( &provider.mutex );
        return status;
    }
    if (!(status = begin_mutation_locked()) &&
        !registry_covers_range( &provider.ranges, start, end ))
        status = STATUS_INVALID_ADDRESS;
    if (!status)
        status = build_protected_registry( &provider.ranges, start, end, perms, &replacement );
    if (!status)
    {
#ifdef XTAJIT_UNIXLIB_TEST
        test_engine_mutation_count = 0;
#endif
        for (engine = provider.engines; engine; engine = engine->next)
        {
            if (fail_test_engine_mutation())
            {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            for (i = 0; i < provider.ranges.count; ++i)
            {
                const struct mapped_range *range = &provider.ranges.data[i];
                uint64_t overlap_start, overlap_end;

                if (!range_overlaps( range, start, end ) || range->permanent) continue;
                overlap_start = max( range->guest, start );
                overlap_end = min( range->guest + range->size, end );
                if ((err = uc_mem_protect( engine->uc, overlap_start,
                                           overlap_end - overlap_start, perms )) != UC_ERR_OK)
                    break;
            }
            if (err == UC_ERR_OK) err = uc_ctl_remove_cache( engine->uc, start, end );
            if (err != UC_ERR_OK)
            {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    if (!status)
    {
        struct range_array old = provider.ranges;

        provider.ranges = replacement;
        memset( &replacement, 0, sizeof(replacement) );
        range_array_free( &old );
    }
    else if (provider.initialized) poison_provider_locked( status );
    if (provider.mutating) finish_mutation_locked();
    pthread_mutex_unlock( &provider.mutex );
    range_array_free( &replacement );
    return status;
}

static NTSTATUS flush_instruction_cache( void *args )
{
    const struct xtajit_memory_params *params = args;
    struct xtajit_engine *engine;
    uint64_t start = 0, end = 0;
    NTSTATUS status;
    uc_err err = UC_ERR_OK;

    if (params && params->guest && params->size &&
        (!align_range( params->guest, params->size, &start, &end ) ||
         end > WINE_LOW_VA_SHADOW_SIZE || overlaps_provider_pages( start, end )))
        return STATUS_INVALID_PARAMETER;
    pthread_mutex_lock( &provider.mutex );
    if (provider.observer_transaction &&
        pthread_equal( provider.mutation_owner, pthread_self() ))
    {
        if (!start || !end) provider.mutation_flush_all = TRUE;
        else if (!provider.mutation_flush_all)
        {
            if (!provider.mutation_flush_end)
            {
                provider.mutation_flush_start = start;
                provider.mutation_flush_end = end;
            }
            else
            {
                provider.mutation_flush_start = min( provider.mutation_flush_start, start );
                provider.mutation_flush_end = max( provider.mutation_flush_end, end );
            }
        }
        status = provider.poison_status;
        pthread_mutex_unlock( &provider.mutex );
        return status;
    }
    status = begin_mutation_locked();
    if (!status)
    {
        for (engine = provider.engines; engine; engine = engine->next)
        {
            if (!start || !end) err = uc_ctl_flush_tb( engine->uc );
            else err = uc_ctl_remove_cache( engine->uc, start, end );
            if (err != UC_ERR_OK)
            {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    if (status && provider.initialized) poison_provider_locked( status );
    if (provider.mutating) finish_mutation_locked();
    pthread_mutex_unlock( &provider.mutex );
    return status;
}

static NTSTATUS poison( void *args )
{
    const struct xtajit_poison_params *params = args;
    struct xtajit_engine *engine;
    NTSTATUS status = params && params->status ? params->status : STATUS_UNSUCCESSFUL;

    pthread_mutex_lock( &provider.mutex );
    if (!provider.initialized) status = STATUS_INVALID_HANDLE;
    else
    {
        poison_provider_locked( status );
        for (engine = provider.engines; engine; engine = engine->next)
            request_engine_pause_locked( engine );
        status = provider.poison_status;
        pthread_cond_broadcast( &provider.cond );
    }
    pthread_mutex_unlock( &provider.mutex );
    return status;
}

static NTSTATUS begin_simulation( void *args )
{
    struct xtajit_begin_params *params = args;
    struct xtajit_engine *engine;
    NTSTATUS status = STATUS_SUCCESS;
    uc_err err = UC_ERR_OK, hook_err = UC_ERR_OK, read_err = UC_ERR_OK, stop_err = UC_ERR_OK;
    unsigned int i, first;
    BOOL restore_context = TRUE, resume;

    if (!params) return STATUS_INVALID_PARAMETER;
    if (!params->context.eip || !params->context.esp ||
        !params->teb_guest || params->teb_guest >= XTAJIT_GUEST_BOP_PAGE)
        return STATUS_INVALID_PARAMETER;
    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error || !(engine = pthread_getspecific( engine_key )))
        return STATUS_INVALID_HANDLE;

    engine->fault_address = 0;
    engine->fault_type = 0;
    engine->execution_slice_count = 0;
    engine->recent_eip_count = 0;
    engine->recent_eip_next = 0;
    memset( engine->recent_eip, 0, sizeof(engine->recent_eip) );
    engine->stop_reason = XTAJIT_STOP_NONE;

    for (;;)
    {
        resume = FALSE;
        pthread_mutex_lock( &provider.mutex );
        while (provider.mutating && provider.initialized)
            pthread_cond_wait( &provider.cond, &provider.mutex );
        if (!provider.initialized || provider.shutting_down ||
            !engine->uc || !engine->linked)
            status = STATUS_INVALID_HANDLE;
        else if (provider.poison_status) status = provider.poison_status;
        else if (engine->running) status = STATUS_INVALID_DEVICE_STATE;
        else if (restore_context)
        {
            if ((err = write_context( engine, &params->context,
                                      params->teb_guest )) != UC_ERR_OK)
            {
                status = STATUS_UNSUCCESSFUL;
                poison_provider_locked( status );
            }
        }
        if (!status)
        {
            engine->start_acknowledged = FALSE;
            if ((err = arm_engine_start_hook_locked( engine,
                                                      params->context.eip )) != UC_ERR_OK)
            {
                status = STATUS_UNSUCCESSFUL;
                poison_provider_locked( status );
            }
        }
        if (status)
        {
            params->stop_reason = XTAJIT_STOP_INTERNAL_ERROR;
            params->unicorn_error = err;
            pthread_mutex_unlock( &provider.mutex );
            return status;
        }

        __atomic_store_n( &engine->pause_requested, FALSE, __ATOMIC_RELEASE );
        engine->running = TRUE;
        ++engine->execution_slice_count;
        pthread_mutex_unlock( &provider.mutex );

        err = uc_emu_start( engine->uc, params->context.eip, UINT64_MAX, 0, 0 );
        pthread_mutex_lock( &provider.mutex );
        hook_err = disarm_engine_start_hook_locked( engine );
        read_err = read_context( engine, &params->context );
        /* A mutator may post a boundary stop after uc_emu_start returns but
         * before this mutex is reacquired.  Discard that run's request while
         * requesters are excluded, before publishing the engine as idle. */
        stop_err = uc_clear_instruction_boundary_stop( engine->uc );
        engine->running = FALSE;
        pthread_cond_broadcast( &provider.cond );
        if (hook_err != UC_ERR_OK || read_err != UC_ERR_OK || stop_err != UC_ERR_OK)
            poison_provider_locked( STATUS_UNSUCCESSFUL );
        if (provider.poison_status) status = provider.poison_status;
        else if (!provider.initialized || provider.shutting_down ||
                 !engine->uc || !engine->linked)
            status = STATUS_INVALID_HANDLE;
        else if (err == UC_ERR_OK && read_err == UC_ERR_OK)
        {
            if (__atomic_load_n( &engine->pause_requested, __ATOMIC_ACQUIRE ) &&
                engine->stop_reason == XTAJIT_STOP_NONE)
                resume = TRUE;
        }
        pthread_mutex_unlock( &provider.mutex );
        if (!resume) break;
        restore_context = FALSE;
    }

    params->fault_address = engine->fault_address;
    params->fault_type = engine->fault_type;
    params->stop_reason = status ? XTAJIT_STOP_INTERNAL_ERROR : engine->stop_reason;
    params->unicorn_error = err != UC_ERR_OK ? err :
                            hook_err != UC_ERR_OK ? hook_err :
                            read_err != UC_ERR_OK ? read_err : stop_err;
    params->execution_slice_count = engine->execution_slice_count;
    params->recent_eip_count = engine->recent_eip_count;
    first = (engine->recent_eip_next + XTAJIT_RECENT_EIP_COUNT -
             engine->recent_eip_count) % XTAJIT_RECENT_EIP_COUNT;
    for (i = 0; i < engine->recent_eip_count; ++i)
        params->recent_eip[i] = engine->recent_eip[(first + i) % XTAJIT_RECENT_EIP_COUNT];
    if (!status && params->stop_reason == XTAJIT_STOP_NONE)
        params->stop_reason = err == UC_ERR_INSN_INVALID ? XTAJIT_STOP_INVALID_INSTRUCTION :
                              XTAJIT_STOP_INTERNAL_ERROR;
    if (status) return status;

    switch (params->stop_reason)
    {
    case XTAJIT_STOP_SYSCALL:
    case XTAJIT_STOP_UNIX_CALL:
        return STATUS_SUCCESS;
    case XTAJIT_STOP_UNMAPPED_MEMORY:
    case XTAJIT_STOP_MEMORY_FAULT:
        return STATUS_ACCESS_VIOLATION;
    default:
        return STATUS_NOT_SUPPORTED;
    }
}

static NTSTATUS resolve_memory_fault( void *args )
{
    struct xtajit_fault_params *params = args;
    struct xtajit_engine *engine;
    uint64_t host;
    uint32_t access;
    NTSTATUS status;

    if (!params || params->reserved ||
        params->result.version != WINE_WOW64_MEMORY_FAULT_VERSION ||
        params->result.size < sizeof(params->result))
        return STATUS_INVALID_PARAMETER;

    switch (params->unicorn_type)
    {
    case UC_MEM_READ_UNMAPPED:
    case UC_MEM_READ_PROT:
        access = WINE_WOW64_MEMORY_FAULT_READ;
        break;
    case UC_MEM_WRITE_UNMAPPED:
    case UC_MEM_WRITE_PROT:
        access = WINE_WOW64_MEMORY_FAULT_WRITE;
        break;
    case UC_MEM_FETCH_UNMAPPED:
    case UC_MEM_FETCH_PROT:
        access = WINE_WOW64_MEMORY_FAULT_EXECUTE;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error || !(engine = pthread_getspecific( engine_key )))
        return STATUS_INVALID_HANDLE;
    pthread_mutex_lock( &provider.mutex );
    if (!provider.initialized || !provider.observer_active || !engine->uc ||
        !engine->linked || !pthread_equal( engine->owner, pthread_self() ))
        status = STATUS_INVALID_HANDLE;
    else if (params->guest >= provider.low_va_shadow_size ||
             params->guest > UINT64_MAX - provider.low_va_shadow_base)
        status = STATUS_INVALID_PARAMETER;
    else if (provider.poison_status)
        status = provider.poison_status;
    else if (engine->running)
        status = STATUS_INVALID_DEVICE_STATE;
    else
        status = STATUS_SUCCESS;
    host = provider.low_va_shadow_base + params->guest;
    pthread_mutex_unlock( &provider.mutex );
    if (status) return status;

#ifdef XTAJIT_UNIXLIB_TEST
    if (!test_memory_fault_resolver) status = STATUS_NOT_SUPPORTED;
    else status = test_memory_fault_resolver( host, access, &params->result );
#else
    status = __wine_resolve_wow64_memory_fault_v1( host, access, &params->result );
#endif

    pthread_mutex_lock( &provider.mutex );
    if (!provider.initialized || !provider.observer_active)
        status = STATUS_INVALID_HANDLE;
    if (provider.poison_status) status = provider.poison_status;
    if (!status &&
        (params->result.version != WINE_WOW64_MEMORY_FAULT_VERSION ||
         params->result.size < sizeof(params->result) || params->result.reserved ||
         (params->result.action != WINE_WOW64_MEMORY_FAULT_RETRY &&
          params->result.action != WINE_WOW64_MEMORY_FAULT_RAISE) ||
         params->result.parameter_count > ARRAY_SIZE(params->result.information)))
        status = STATUS_INVALID_PARAMETER;
    if (!status && params->result.action == WINE_WOW64_MEMORY_FAULT_RETRY &&
        (params->result.status || params->result.parameter_count))
        status = STATUS_INVALID_PARAMETER;
    if (!status && params->result.action == WINE_WOW64_MEMORY_FAULT_RAISE)
    {
        switch (params->result.status)
        {
        case STATUS_ACCESS_VIOLATION:
        case STATUS_GUARD_PAGE_VIOLATION:
            if (params->result.parameter_count != 2 ||
                params->result.information[0] != access ||
                params->result.information[1] != host)
                status = STATUS_INVALID_PARAMETER;
            break;
        case STATUS_IN_PAGE_ERROR:
            if (params->result.parameter_count != 3 ||
                params->result.information[0] != access ||
                params->result.information[1] != host ||
                (params->result.information[2] !=
                 (uint64_t)(uint32_t)STATUS_EXECUTABLE_MEMORY_WRITE &&
                 params->result.information[2] !=
                 (uint64_t)(int64_t)STATUS_EXECUTABLE_MEMORY_WRITE))
                status = STATUS_INVALID_PARAMETER;
            break;
        case STATUS_STACK_OVERFLOW:
            if (params->result.parameter_count)
                status = STATUS_INVALID_PARAMETER;
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }
    if (status)
    {
        struct xtajit_engine *other;

        poison_provider_locked( status );
        for (other = provider.engines; other; other = other->next)
            request_engine_pause_locked( other );
        status = provider.poison_status;
        pthread_cond_broadcast( &provider.cond );
    }
    pthread_mutex_unlock( &provider.mutex );
    return status;
}

#else /* HAVE_UNICORN */

static NTSTATUS unicorn_not_supported( void *args )
{
    (void)args;
    return STATUS_NOT_SUPPORTED;
}

#define process_init             unicorn_not_supported
#define process_term             unicorn_not_supported
#define thread_init              unicorn_not_supported
#define thread_term              unicorn_not_supported
#define memory_map               unicorn_not_supported
#define memory_unmap             unicorn_not_supported
#define memory_protect           unicorn_not_supported
#define flush_instruction_cache  unicorn_not_supported
#define poison                   unicorn_not_supported
#define begin_simulation         unicorn_not_supported
#define resolve_memory_fault     unicorn_not_supported

#endif /* HAVE_UNICORN */

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    process_init,
    process_term,
    thread_init,
    thread_term,
    memory_map,
    memory_unmap,
    memory_protect,
    flush_instruction_cache,
    poison,
    begin_simulation,
    resolve_memory_fault,
};

C_ASSERT( ARRAY_SIZE(__wine_unix_call_funcs) == unix_funcs_count );
