/*
 * Native xtajit64 identity, trap, hook, and concurrency tests
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#if 0
#pragma makedep standalone
#endif

#include <setjmp.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#undef WIN32_NO_STATUS

#define CACHE_RECORD_LIMIT 16

struct cache_remove_record
{
    uc_engine *engine;
    uint64_t start;
    uint64_t end;
};

static struct cache_remove_record cache_remove_records[CACHE_RECORD_LIMIT];
static uc_engine *cache_flush_engines[CACHE_RECORD_LIMIT];
static uc_engine *tlb_flush_engines[CACHE_RECORD_LIMIT];
static uint64_t cache_remove_start;
static uint64_t cache_remove_end;
static unsigned int cache_remove_calls;
static unsigned int cache_flush_calls;
static unsigned int tlb_flush_calls;
static int cache_remove_fail_call = -1;
static int tlb_flush_fail_call = -1;
static unsigned int memory_map_calls;
static unsigned int memory_unmap_calls;
static int memory_map_fail_call = -1;
static int memory_unmap_fail_call = -1;
static unsigned int reg_write_batch_calls;
static int reg_write_batch_fail_call = -1;

static uc_err record_memory_map( uc_engine *uc, uint64_t address, size_t size,
                                 uint32_t perms, void *pointer )
{
    unsigned int call = memory_map_calls++;

    if ((int)call == memory_map_fail_call) return UC_ERR_RESOURCE;
    return uc_mem_map_ptr( uc, address, size, perms, pointer );
}

static uc_err record_memory_unmap( uc_engine *uc, uint64_t address, size_t size )
{
    unsigned int call = memory_unmap_calls++;

    if ((int)call == memory_unmap_fail_call) return UC_ERR_RESOURCE;
    return uc_mem_unmap( uc, address, size );
}

static uc_err record_reg_write_batch( uc_engine *uc, int const *regs,
                                      void *const *values, int count )
{
    unsigned int call = reg_write_batch_calls++;

    if ((int)call == reg_write_batch_fail_call) return UC_ERR_RESOURCE;
    return uc_reg_write_batch( uc, regs, values, count );
}

static uc_err record_cache_remove( uc_engine *uc, uint64_t start, uint64_t end )
{
    unsigned int call = cache_remove_calls++;

    cache_remove_start = start;
    cache_remove_end = end;
    if (call < CACHE_RECORD_LIMIT)
    {
        cache_remove_records[call].engine = uc;
        cache_remove_records[call].start = start;
        cache_remove_records[call].end = end;
    }
    if ((int)call == cache_remove_fail_call) return UC_ERR_RESOURCE;
    return uc_ctl_remove_cache( uc, start, end );
}

static uc_err record_cache_flush( uc_engine *uc )
{
    unsigned int call = cache_flush_calls++;

    if (call < CACHE_RECORD_LIMIT) cache_flush_engines[call] = uc;
    return uc_ctl_flush_tb( uc );
}

static uc_err record_tlb_flush( uc_engine *uc )
{
    unsigned int call = tlb_flush_calls++;

    if (call < CACHE_RECORD_LIMIT) tlb_flush_engines[call] = uc;
    if ((int)call == tlb_flush_fail_call) return UC_ERR_RESOURCE;
    return uc_ctl_flush_tlb( uc );
}

static void reset_cache_recorders(void)
{
    memset( cache_remove_records, 0, sizeof(cache_remove_records) );
    memset( cache_flush_engines, 0, sizeof(cache_flush_engines) );
    memset( tlb_flush_engines, 0, sizeof(tlb_flush_engines) );
    cache_remove_start = cache_remove_end = 0;
    cache_remove_calls = cache_flush_calls = tlb_flush_calls = 0;
    cache_remove_fail_call = -1;
    tlb_flush_fail_call = -1;
}

#undef uc_ctl_remove_cache
#define uc_ctl_remove_cache record_cache_remove
#undef uc_ctl_flush_tb
#define uc_ctl_flush_tb record_cache_flush
#undef uc_ctl_flush_tlb
#define uc_ctl_flush_tlb record_tlb_flush
#undef uc_mem_map_ptr
#define uc_mem_map_ptr record_memory_map
#undef uc_mem_unmap
#define uc_mem_unmap record_memory_unmap
#undef uc_reg_write_batch
#define uc_reg_write_batch record_reg_write_batch

static _Thread_local void *test_exception_jmp_buf;
void test_ntdll_set_exception_jmp_buf( jmp_buf jmp );
static void test_raise_mutation_exception(void);

#define ntdll_set_exception_jmp_buf test_ntdll_set_exception_jmp_buf
#define XTAJIT64_TEST_RAISE_EXCEPTION() test_raise_mutation_exception()

/* Include the implementation so the regression can inspect deterministic
 * test hooks without adding a production control opcode to the provider ABI. */
#include "../unixlib.c"

C_ASSERT( XTAJIT64_PROCESS_ABI_VERSION == 11 );

#undef XTAJIT64_TEST_RAISE_EXCEPTION
#undef ntdll_set_exception_jmp_buf
#undef uc_ctl_remove_cache
#undef uc_ctl_flush_tb
#undef uc_ctl_flush_tlb
#undef uc_mem_map_ptr
#undef uc_mem_unmap
#undef uc_reg_write_batch

void test_ntdll_set_exception_jmp_buf( jmp_buf jmp )
{
    test_exception_jmp_buf = jmp;
}

static void test_raise_mutation_exception(void)
{
    jmp_buf *jmp = test_exception_jmp_buf;

    if (!jmp) abort();
    test_exception_jmp_buf = NULL;
    longjmp( *jmp, 1 );
}

#define TEST_PAGE             0x4000u
#define TEST_PAGE_COUNT       15u
#define TEST_PREFERRED_KUSER  (WINE_LOW_VA_SHADOW_BASE + 0x04000000ull)
#define TEST_PREFERRED_BASE   (WINE_LOW_VA_SHADOW_BASE + 0x06000000ull)
#define TEST_LOW_HOST_BASE    (WINE_LOW_VA_SHADOW_BASE + 0x08000000ull)
#define TEST_LOW_GUEST_BASE   0x08000000ull
#define TEST_FALLBACK_KUSER   0x0000001004000000ull
#define TEST_FALLBACK_BASE    0x0000001006000000ull
#define TEST_ASAN_KUSER       0x0000000404000000ull
#define TEST_ASAN_BASE        0x0000000406000000ull
#define TEST_SYSCALL_COUNT    (XTAJIT64_X64_SYSCALL_NT_READ_VIRTUAL_MEMORY + 1u)
#define TEST_LOW_PAGE_COUNT   8u

static unsigned int failures;
static struct xtajit64_process_init_params process_params;
static unsigned char *test_pages;
static unsigned char *test_kuser;
static unsigned char *test_low_pages;
static uint64_t test_base;
static uint64_t test_ec_target;
static uint64_t test_syscall_dispatcher;
static uint64_t test_teb;
static struct xtajit64_flight_recorder flight_test_recorder;
static struct xtajit64_flight_snapshot flight_test_snapshot;

static volatile uint32_t *test_suspend_doorbell(void)
{
    return (volatile uint32_t *)(uintptr_t)(test_teb + 0x100);
}

#define check(condition, ...) \
    do { if (!(condition)) { fprintf( stderr, "not ok: " __VA_ARGS__ ); ++failures; } } while (0)

static void test_unicorn_perf_counter_api(void)
{
#if defined(__APPLE__) && defined(RTLD_NOLOAD)
    Dl_info unicorn_info, enable_info, get_info;
    unicorn_enable_perf_counters_fn enable = NULL, expected_enable = NULL;
    unicorn_get_perf_counters_fn get = NULL, expected_get = NULL;
    enum unicorn_perf_counter_api_resolution resolution;
    void *handle, *enable_address, *get_address;
    BOOL expected = FALSE;

    if (!dladdr( (const void *)uc_version, &unicorn_info ) || !unicorn_info.dli_fbase ||
        !unicorn_info.dli_fname)
    {
        check( FALSE, "cannot identify linked Unicorn image\n" );
        return;
    }
    handle = dlopen( unicorn_info.dli_fname, RTLD_NOW | RTLD_NOLOAD );
    check( handle != NULL, "cannot retain linked Unicorn image\n" );
    if (!handle) return;

    enable_address = dlsym( handle, "uc_switchyard_enable_perf_counters" );
    get_address = dlsym( handle, "uc_switchyard_get_perf_counters" );
    if (enable_address && get_address &&
        dladdr( enable_address, &enable_info ) && dladdr( get_address, &get_info ) &&
        enable_info.dli_fbase == unicorn_info.dli_fbase &&
        get_info.dli_fbase == unicorn_info.dli_fbase)
    {
        memcpy( &expected_enable, &enable_address, sizeof(expected_enable) );
        memcpy( &expected_get, &get_address, sizeof(expected_get) );
        expected = TRUE;
    }
    resolution = resolve_unicorn_perf_counter_api( &enable, &get );
    check( (resolution == UNICORN_PERF_COUNTER_API_RESOLVED) == expected,
           "Unicorn performance-counter resolver did not match the linked image\n" );
    if (expected)
        check( enable == expected_enable && get == expected_get,
               "Unicorn performance-counter resolver returned foreign symbols\n" );
    else
        check( !enable && !get,
               "failed Unicorn performance-counter resolution altered outputs\n" );
    dlclose( handle );
#endif
}

static void test_ec_target_stats_initial_report_parser(void)
{
    uint64_t initial_report = 0;

    check( parse_ec_target_stats_initial_report( "4096", &initial_report ) &&
           initial_report == XTAJIT64_EC_TARGET_STATS_MIN_INITIAL_REPORT,
           "EC target stats minimum initial report was rejected\n" );
    check( parse_ec_target_stats_initial_report( "1048576", &initial_report ) &&
           initial_report == XTAJIT64_EC_TARGET_STATS_DEFAULT_INITIAL_REPORT,
           "EC target stats maximum initial report was rejected\n" );
    initial_report = 0xfeedface;
    check( !parse_ec_target_stats_initial_report( "4095", &initial_report ) &&
           initial_report == 0xfeedface,
           "EC target stats lower-bound rejection changed output\n" );
    check( !parse_ec_target_stats_initial_report( "1048577", &initial_report ) &&
           initial_report == 0xfeedface,
           "EC target stats upper-bound rejection changed output\n" );
    check( !parse_ec_target_stats_initial_report( "4096x", &initial_report ) &&
           !parse_ec_target_stats_initial_report( "-4096", &initial_report ) &&
           !parse_ec_target_stats_initial_report( "+4096", &initial_report ) &&
           !parse_ec_target_stats_initial_report( " 4096", &initial_report ) &&
           !parse_ec_target_stats_initial_report( "4096 ", &initial_report ) &&
           !parse_ec_target_stats_initial_report( "", &initial_report ) &&
           !parse_ec_target_stats_initial_report( NULL, &initial_report ) &&
           !parse_ec_target_stats_initial_report( "4096", NULL ),
           "EC target stats malformed initial report was accepted\n" );
    check( ec_target_stats_initial_sample_count(
               XTAJIT64_EC_TARGET_STATS_MIN_INITIAL_REPORT ) == 1 &&
           ec_target_stats_initial_sample_count(
               XTAJIT64_EC_TARGET_STATS_SAMPLE_STRIDE ) == 1 &&
           ec_target_stats_initial_sample_count(
               XTAJIT64_EC_TARGET_STATS_SAMPLE_STRIDE + 1 ) == 2 &&
           ec_target_stats_initial_sample_count(
               XTAJIT64_EC_TARGET_STATS_DEFAULT_INITIAL_REPORT ) == 65,
           "EC target stats sample threshold conversion is incorrect\n" );
}

struct code_buffer
{
    unsigned char *data;
    size_t offset;
};

struct simulation
{
    struct xtajit64_begin_params params;
    atomic_int ready;
    atomic_int done;
    NTSTATUS init_status;
    NTSTATUS status;
};

struct protect_worker
{
    struct xtajit64_memory_params params;
    atomic_int done;
    NTSTATUS status;
};

struct flush_worker
{
    struct xtajit64_memory_params params;
    atomic_int done;
    NTSTATUS status;
};

struct process_term_worker
{
    atomic_int done;
    NTSTATUS status;
};

struct low_observer_worker
{
    struct wine_arm64ec_low_memory_range_v1 range;
    struct wine_arm64ec_low_memory_event_v1 event;
    atomic_int begun;
    atomic_int done;
    NTSTATUS status;
};

struct code_observer_worker
{
    struct wine_arm64ec_code_range_v1 range;
    struct wine_arm64ec_code_event_v1 event;
    uint64_t *bitmap_word;
    uint64_t bitmap_mask;
    BOOL set_ec;
    atomic_int begun;
    atomic_int done;
    NTSTATUS status;
};

struct low_begin_worker
{
    struct wine_arm64ec_low_memory_event_v1 event;
    atomic_int done;
    NTSTATUS status;
    void *transaction;
};

struct engine_holder
{
    struct xtajit64_begin_params params;
    atomic_int ready;
    atomic_int execute;
    atomic_int executed;
    atomic_int release;
    atomic_int done;
    NTSTATUS status;
    NTSTATUS simulation_status;
};

static void *alloc_pages_at( uint64_t address, size_t count )
{
    size_t size;
    void *ret;

    if (!count || count > SIZE_MAX / TEST_PAGE) return NULL;
    size = count * TEST_PAGE;
    ret = mmap( (void *)(uintptr_t)address, size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON, -1, 0 );
    if (ret == MAP_FAILED) return NULL;
    if ((uintptr_t)ret == address) return ret;
    munmap( ret, size );
    return NULL;
}

static void *alloc_preferred_pages( uint64_t preferred, uint64_t fallback,
                                    size_t count )
{
    void *ret;

    if ((ret = alloc_pages_at( preferred, count ))) return ret;
    return alloc_pages_at( fallback, count );
}

static void emit_u8( struct code_buffer *code, unsigned int value )
{
    code->data[code->offset++] = value;
}

static void emit_u32( struct code_buffer *code, uint32_t value )
{
    memcpy( code->data + code->offset, &value, sizeof(value) );
    code->offset += sizeof(value);
}

static void emit_u64( struct code_buffer *code, uint64_t value )
{
    memcpy( code->data + code->offset, &value, sizeof(value) );
    code->offset += sizeof(value);
}

static void emit_movabs_rax( struct code_buffer *code, uint64_t value )
{
    emit_u8( code, 0x48 ); emit_u8( code, 0xb8 ); emit_u64( code, value );
}

static void emit_movabs_rbx( struct code_buffer *code, uint64_t value )
{
    emit_u8( code, 0x48 ); emit_u8( code, 0xbb ); emit_u64( code, value );
}

static void emit_movabs_rcx( struct code_buffer *code, uint64_t value )
{
    emit_u8( code, 0x48 ); emit_u8( code, 0xb9 ); emit_u64( code, value );
}

static void emit_movabs_rdx( struct code_buffer *code, uint64_t value )
{
    emit_u8( code, 0x48 ); emit_u8( code, 0xba ); emit_u64( code, value );
}

static void emit_call_rax( struct code_buffer *code )
{
    emit_u8( code, 0xff ); emit_u8( code, 0xd0 );
}

static void emit_jump_rax( struct code_buffer *code )
{
    emit_u8( code, 0xff ); emit_u8( code, 0xe0 );
}

static void emit_jump_rdx( struct code_buffer *code )
{
    emit_u8( code, 0xff ); emit_u8( code, 0xe2 );
}

static void patch_rel8( struct code_buffer *code, size_t displacement, size_t target )
{
    intptr_t value = (intptr_t)target - (intptr_t)(displacement + 1);

    check( value >= INT8_MIN && value <= INT8_MAX,
           "relative branch is out of range\n" );
    code->data[displacement] = (unsigned char)(int8_t)value;
}

static NTSTATUS register_identity_page( void *page, unsigned int protect )
{
    struct xtajit64_memory_params params =
    {
        .guest = (uintptr_t)page,
        .host = (uintptr_t)page,
        .size = TEST_PAGE,
        .allocation_base = (uintptr_t)page,
        .protect = protect,
    };

    return memory_map( &params );
}

static NTSTATUS register_identity_range( void *base, size_t size, unsigned int protect )
{
    struct xtajit64_memory_params params =
    {
        .guest = (uintptr_t)base,
        .host = (uintptr_t)base,
        .size = size,
        .allocation_base = (uintptr_t)base,
        .protect = protect,
    };

    return memory_map( &params );
}

static NTSTATUS unregister_identity_page( void *page )
{
    struct xtajit64_memory_params params =
    {
        .guest = (uintptr_t)page,
        .size = TEST_PAGE,
    };

    return memory_unmap( &params );
}

static NTSTATUS unregister_identity_range( void *base, size_t size )
{
    struct xtajit64_memory_params params =
    {
        .guest = (uintptr_t)base,
        .size = size,
    };

    return memory_unmap( &params );
}

static NTSTATUS observer_provider_status(void)
{
    NTSTATUS status;

    pthread_mutex_lock( &provider.mutex );
    status = provider.poison_status;
    pthread_mutex_unlock( &provider.mutex );
    return status;
}

static uint64_t observer_generation(void)
{
    uint64_t generation;

    pthread_mutex_lock( &provider.mutex );
    generation = provider.generation;
    pthread_mutex_unlock( &provider.mutex );
    return generation;
}

static struct thread_engine *first_provider_engine(void)
{
    struct thread_engine *engine;

    pthread_mutex_lock( &provider.mutex );
    engine = provider.engines;
    pthread_mutex_unlock( &provider.mutex );
    return engine;
}

static size_t provider_engine_count(void)
{
    struct thread_engine *engine;
    size_t count = 0;

    pthread_mutex_lock( &provider.mutex );
    for (engine = provider.engines; engine; engine = engine->next) ++count;
    pthread_mutex_unlock( &provider.mutex );
    return count;
}

static uint64_t provider_direct_self_read_completions(void)
{
    struct thread_engine *engine;
    uint64_t count = 0;

    pthread_mutex_lock( &provider.mutex );
    for (engine = provider.engines; engine; engine = engine->next)
        count += engine->direct_self_read_completions;
    pthread_mutex_unlock( &provider.mutex );
    return count;
}

static uint64_t provider_direct_self_read_rejections(
    enum direct_self_read_rejection reason )
{
    struct thread_engine *engine;
    uint64_t count = 0;

    pthread_mutex_lock( &provider.mutex );
    for (engine = provider.engines; engine; engine = engine->next)
        count += engine->direct_self_read_diagnostics.rejections[reason];
    pthread_mutex_unlock( &provider.mutex );
    return count;
}

static uint64_t provider_direct_self_read_size_bucket(
    enum direct_self_read_size_bucket bucket )
{
    struct thread_engine *engine;
    uint64_t count = 0;

    pthread_mutex_lock( &provider.mutex );
    for (engine = provider.engines; engine; engine = engine->next)
        count += engine->direct_self_read_diagnostics.size_buckets[bucket];
    pthread_mutex_unlock( &provider.mutex );
    return count;
}

static BOOL engine_mappings_match_registry( const struct thread_engine *engine )
{
    const struct mapped_range *mapped, *canonical;
    uint64_t offset;
    size_t i;
    BOOL match = TRUE;

    pthread_mutex_lock( &provider.mutex );
    for (i = 0; i < engine->mapped_ranges.count; ++i)
    {
        mapped = &engine->mapped_ranges.data[i];
        canonical = find_canonical_mapping( mapped->guest, mapped->size,
                                            mapped->perms );
        if (!canonical || (offset = mapped->guest - canonical->guest) >
                          UINT64_MAX - canonical->host ||
            canonical->host + offset != mapped->host ||
            canonical->allocation_base != mapped->allocation_base ||
            canonical->state != mapped->state || canonical->domain != mapped->domain ||
            canonical->flags != mapped->flags ||
            canonical->permanent != mapped->permanent || mapped->stale)
        {
            match = FALSE;
            break;
        }
    }
    pthread_mutex_unlock( &provider.mutex );
    return match;
}

static BOOL canonical_range_matches( uint64_t guest, uint64_t host,
                                     unsigned int state, unsigned int perms,
                                     unsigned int domain, BOOL permanent )
{
    const struct mapped_range *range;
    BOOL found = FALSE;
    size_t i;

    pthread_mutex_lock( &provider.mutex );
    for (i = 0; i < provider.ranges.count; ++i)
    {
        range = &provider.ranges.data[i];
        if (guest < range->guest || guest >= range->guest + range->size) continue;
        found = range->host + guest - range->guest == host &&
                range->state == state && range->perms == perms &&
                range->domain == domain && range->permanent == permanent;
        break;
    }
    pthread_mutex_unlock( &provider.mutex );
    return found;
}

static void initialize_low_range( struct wine_arm64ec_low_memory_range_v1 *range,
                                  uint64_t guest, uint64_t size,
                                  uint64_t allocation_base, uint32_t state,
                                  uint32_t protect )
{
    memset( range, 0, sizeof(*range) );
    range->host_address = WINE_LOW_VA_SHADOW_BASE + guest;
    range->size = size;
    range->state = state;
    range->protect = protect;
    if (state != MEM_FREE)
        range->host_allocation_base = WINE_LOW_VA_SHADOW_BASE + allocation_base;
}

static void initialize_low_event( struct wine_arm64ec_low_memory_event_v1 *event,
                                  uint32_t operation, uint32_t flags,
                                  uint64_t guest, uint64_t size,
                                  uint64_t allocation_base,
                                  const struct wine_arm64ec_low_memory_range_v1 *ranges,
                                  size_t range_count, NTSTATUS mutation_status,
                                  NTSTATUS snapshot_status )
{
    memset( event, 0, sizeof(*event) );
    event->version = WINE_ARM64EC_LOW_MEMORY_OBSERVER_VERSION;
    event->size = sizeof(*event);
    event->operation = operation;
    event->flags = flags;
    event->status = mutation_status;
    event->snapshot_status = snapshot_status;
    event->host_address = WINE_LOW_VA_SHADOW_BASE + guest;
    event->size_covered = size;
    if (allocation_base)
        event->host_allocation_base = WINE_LOW_VA_SHADOW_BASE + allocation_base;
    event->ranges = ranges;
    event->range_count = range_count;
}

static NTSTATUS publish_low_event(
    uint32_t operation, uint32_t flags, uint64_t guest, uint64_t size,
    uint64_t allocation_base,
    const struct wine_arm64ec_low_memory_range_v1 *ranges, size_t range_count,
    NTSTATUS mutation_status, NTSTATUS snapshot_status )
{
    struct wine_arm64ec_low_memory_event_v1 event;
    void *transaction = NULL;
    NTSTATUS status;

    initialize_low_event( &event, operation, flags, guest, size, allocation_base,
                          ranges, range_count, mutation_status, snapshot_status );
    status = arm64ec_low_memory_observer.begin( arm64ec_low_memory_observer.context,
                                                operation, event.host_address,
                                                event.size_covered,
                                                event.host_allocation_base,
                                                &transaction );
    if (!status)
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              transaction, &event );
    if (!status) status = observer_provider_status();
    return status;
}

static void initialize_code_event(
    struct wine_arm64ec_code_event_v1 *event, uint32_t operation,
    uint32_t flags, const struct wine_arm64ec_code_range_v1 *ranges,
    size_t range_count, NTSTATUS mutation_status )
{
    memset( event, 0, sizeof(*event) );
    event->version = WINE_ARM64EC_CODE_OBSERVER_VERSION;
    event->size = sizeof(*event);
    event->operation = operation;
    event->flags = flags;
    event->status = mutation_status;
    event->ranges = ranges;
    event->range_count = range_count;
}

static NTSTATUS publish_code_event(
    uint32_t operation, uint32_t flags,
    const struct wine_arm64ec_code_range_v1 *ranges, size_t range_count,
    NTSTATUS mutation_status )
{
    struct wine_arm64ec_code_event_v1 event;
    void *transaction = NULL;
    NTSTATUS status;

    initialize_code_event( &event, operation, flags, ranges, range_count,
                           mutation_status );
    status = arm64ec_code_observer.begin( arm64ec_code_observer.context,
                                          operation, &transaction );
    if (!status)
        arm64ec_code_observer.complete( arm64ec_code_observer.context,
                                        transaction, &event );
    if (!status) status = observer_provider_status();
    return status;
}

static NTSTATUS reset_test_provider(void)
{
    NTSTATUS status;

    if ((status = process_term( NULL ))) return status;
    process_params.enabled_capabilities = 0;
    return process_init( &process_params );
}

static void test_incremental_resync(void)
{
    unsigned char *existing_low = test_pages + 9 * TEST_PAGE;
    unsigned char *added = test_pages + 10 * TEST_PAGE;
    unsigned char *existing_high = test_pages + 11 * TEST_PAGE;
    struct xtajit64_memory_resync_begin_params begin;
    struct xtajit64_memory_resync_params resync = {0};
    struct xtajit64_memory_params ranges[3] = {0};
    struct thread_engine *engine;
    unsigned int starting_failures = failures;
    BOOL found, mapped;
    NTSTATUS status;
    uc_err err;

    status = thread_init( NULL );
    check( !status, "additions-only resync engine init returned %#x\n",
           (unsigned int)status );
    if (status) return;
    status = register_identity_page( existing_low, PAGE_READONLY );
    if (!status) status = register_identity_page( existing_high, PAGE_READONLY );
    check( !status, "additions-only resync setup maps returned %#x\n",
           (unsigned int)status );
    if (status) goto done;

    ranges[0].guest = ranges[0].host = (uintptr_t)existing_low;
    ranges[0].size = TEST_PAGE;
    ranges[0].allocation_base = (uintptr_t)existing_low;
    ranges[0].protect = PAGE_READONLY;
    ranges[1].guest = ranges[1].host = (uintptr_t)added;
    ranges[1].size = TEST_PAGE;
    ranges[1].allocation_base = (uintptr_t)added;
    ranges[1].protect = PAGE_READONLY;
    ranges[2].guest = ranges[2].host = (uintptr_t)existing_high;
    ranges[2].size = TEST_PAGE;
    ranges[2].allocation_base = (uintptr_t)existing_high;
    ranges[2].protect = PAGE_READONLY;
    resync.ranges = (uintptr_t)ranges;
    resync.count = ARRAY_SIZE(ranges);

    status = memory_resync_begin( &begin );
    resync.generation = begin.generation;
    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    if (!status) status = memory_resync( &resync );
    check( !status && !memory_map_calls && !memory_unmap_calls &&
           !cache_flush_calls && canonical_range_matches(
               (uintptr_t)existing_low, (uintptr_t)existing_low, MEM_COMMIT,
               UC_PROT_READ,
               XTAJIT64_MEMORY_ADDRESS_IDENTITY, FALSE ) &&
           canonical_range_matches(
               (uintptr_t)added, (uintptr_t)added, MEM_COMMIT,
               UC_PROT_READ,
               XTAJIT64_MEMORY_ADDRESS_IDENTITY, FALSE ) &&
           canonical_range_matches(
               (uintptr_t)existing_high, (uintptr_t)existing_high, MEM_COMMIT,
               UC_PROT_READ,
               XTAJIT64_MEMORY_ADDRESS_IDENTITY, FALSE ),
           "additions-only resync returned %#x with map/unmap/flush %u/%u/%u\n",
           (unsigned int)status, memory_map_calls, memory_unmap_calls,
           cache_flush_calls );
    if (status) goto done;

    engine = first_provider_engine();
    pthread_mutex_lock( &provider.mutex );
    err = synchronize_engine_registry_locked( engine );
    pthread_mutex_unlock( &provider.mutex );
    check( err == UC_ERR_OK && !memory_map_calls && !memory_unmap_calls &&
           !cache_flush_calls && !engine->mapped_ranges.count,
           "untouched additions synchronized with map/unmap/flush %u/%u/%u: %s\n",
           memory_map_calls, memory_unmap_calls, cache_flush_calls,
           uc_strerror( err ) );
    found = mapped = FALSE;
    err = demand_map_canonical_range( engine, (uintptr_t)added, 1,
                                      UC_PROT_READ, &found, &mapped );
    check( err == UC_ERR_OK && found && mapped && memory_map_calls == 1 &&
           !memory_unmap_calls && !cache_flush_calls &&
           engine->mapped_ranges.count == 1,
           "first-use addition map returned %s found %u calls %u/%u/%u ranges %zu\n",
           uc_strerror( err ), found, memory_map_calls, memory_unmap_calls,
           cache_flush_calls, engine->mapped_ranges.count );

    ranges[1].protect = PAGE_EXECUTE_READ;
    resync.count = 2;
    status = memory_resync_begin( &begin );
    resync.generation = begin.generation;
    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    if (!status) status = memory_resync( &resync );
    check( !status && !memory_map_calls && !memory_unmap_calls &&
           !cache_flush_calls && canonical_range_matches(
               (uintptr_t)existing_low, (uintptr_t)existing_low, MEM_COMMIT,
               UC_PROT_READ,
               XTAJIT64_MEMORY_ADDRESS_IDENTITY, FALSE ) &&
           canonical_range_matches(
               (uintptr_t)added, (uintptr_t)added, MEM_COMMIT,
               UC_PROT_READ | UC_PROT_EXEC,
               XTAJIT64_MEMORY_ADDRESS_IDENTITY, FALSE ) &&
           !canonical_range_matches(
               (uintptr_t)existing_high, (uintptr_t)existing_high, MEM_COMMIT,
               UC_PROT_READ,
               XTAJIT64_MEMORY_ADDRESS_IDENTITY, FALSE ),
           "changed resync returned %#x with map/unmap/flush %u/%u/%u\n",
           (unsigned int)status, memory_map_calls, memory_unmap_calls,
           cache_flush_calls );
    if (status) goto done;

    pthread_mutex_lock( &provider.mutex );
    err = synchronize_engine_registry_locked( engine );
    pthread_mutex_unlock( &provider.mutex );
    check( err == UC_ERR_OK && !memory_map_calls && memory_unmap_calls == 1 &&
           !cache_flush_calls,
           "changed demand-mapped range synchronized with map/unmap/flush %u/%u/%u: %s\n",
           memory_map_calls, memory_unmap_calls, cache_flush_calls,
           uc_strerror( err ) );
    found = mapped = FALSE;
    err = demand_map_canonical_range( engine, (uintptr_t)added, 1,
                                      UC_PROT_READ, &found, &mapped );
    check( err == UC_ERR_OK && found && mapped && memory_map_calls == 1 &&
           memory_unmap_calls == 1 && !cache_flush_calls &&
           engine->mapped_ranges.count == 1,
           "changed range first-use remap returned %s found %u calls %u/%u/%u ranges %zu\n",
           uc_strerror( err ), found, memory_map_calls, memory_unmap_calls,
           cache_flush_calls, engine->mapped_ranges.count );
    found = mapped = TRUE;
    err = demand_map_canonical_range( engine, (uintptr_t)existing_high, 1,
                                      UC_PROT_READ, &found, &mapped );
    check( err == UC_ERR_MAP && !found && !mapped && memory_map_calls == 1 &&
           engine->mapped_ranges.count == 1,
           "removed untouched range demand map returned %s found %u calls %u ranges %zu\n",
           uc_strerror( err ), found, memory_map_calls,
           engine->mapped_ranges.count );

done:
    unregister_identity_page( added );
    unregister_identity_page( existing_high );
    unregister_identity_page( existing_low );
    thread_term( NULL );
    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    if (failures == starting_failures)
        printf( "XTAJIT64_INCREMENTAL_RESYNC_PASS\n" );
}

static void test_coalesced_demand_mapping(void)
{
    unsigned char *base = test_pages + 9 * TEST_PAGE;
    struct xtajit64_memory_params first =
    {
        .guest = (uintptr_t)base,
        .host = (uintptr_t)base,
        .size = XTAJIT64_GUEST_PAGE_SIZE,
        .allocation_base = (uintptr_t)base,
        .protect = PAGE_READWRITE,
    };
    struct xtajit64_memory_params second = first;
    struct xtajit64_memory_params cleanup =
    {
        .guest = (uintptr_t)base,
        .size = 2 * XTAJIT64_GUEST_PAGE_SIZE,
    };
    struct thread_engine *engine;
    unsigned int starting_failures = failures;
    BOOL found = FALSE, mapped = FALSE;
    BOOL thread_initialized = FALSE;
    NTSTATUS status;
    uc_err err;

    status = reset_test_provider();
    check( !status, "coalesced demand-map reset returned %#x\n",
           (unsigned int)status );
    if (status) return;

    second.guest += XTAJIT64_GUEST_PAGE_SIZE;
    second.host += XTAJIT64_GUEST_PAGE_SIZE;
    status = memory_map( &first );
    if (!status) status = thread_init( NULL );
    check( !status, "coalesced demand-map setup returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    thread_initialized = TRUE;
    engine = first_provider_engine();

    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    err = demand_map_canonical_range( engine, first.guest, 1,
                                      UC_PROT_WRITE, &found, &mapped );
    check( err == UC_ERR_OK && found && mapped && memory_map_calls == 1 &&
           !memory_unmap_calls && engine->mapped_ranges.count == 1 &&
           engine->mapped_ranges.data[0].size == XTAJIT64_GUEST_PAGE_SIZE,
           "first coalesced demand map returned %s found %u calls %u/%u ranges %zu\n",
           uc_strerror( err ), found, memory_map_calls, memory_unmap_calls,
           engine->mapped_ranges.count );

    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    status = memory_map( &second );
    check( !status && !memory_map_calls && !memory_unmap_calls &&
           !cache_flush_calls && canonical_range_matches(
               first.guest, first.host, MEM_COMMIT,
               UC_PROT_READ | UC_PROT_WRITE,
               XTAJIT64_MEMORY_ADDRESS_IDENTITY, FALSE ),
           "adjacent canonical map returned %#x calls %u/%u/%u\n",
           (unsigned int)status, memory_map_calls, memory_unmap_calls,
           cache_flush_calls );
    if (status) goto done;

    pthread_mutex_lock( &provider.mutex );
    err = synchronize_engine_registry_locked( engine );
    pthread_mutex_unlock( &provider.mutex );
    check( err == UC_ERR_OK && !memory_map_calls && !memory_unmap_calls &&
           !cache_flush_calls && engine->mapped_ranges.count == 1 &&
           engine->mapped_ranges.data[0].guest == first.guest &&
           engine->mapped_ranges.data[0].size == XTAJIT64_GUEST_PAGE_SIZE,
           "lazy coalesced writable sync returned %s calls %u/%u/%u ranges %zu\n",
           uc_strerror( err ), memory_map_calls, memory_unmap_calls,
           cache_flush_calls, engine->mapped_ranges.count );
    found = mapped = FALSE;
    err = demand_map_canonical_range(
        engine, second.guest - sizeof(uint32_t), 2 * sizeof(uint32_t),
                                      UC_PROT_WRITE, &found, &mapped );
    check( err == UC_ERR_OK && found && mapped && memory_map_calls == 1 &&
           !memory_unmap_calls && !cache_flush_calls &&
           engine->mapped_ranges.count == 1 &&
           engine->mapped_ranges.data[0].guest == first.guest &&
           engine->mapped_ranges.data[0].size == 2 * XTAJIT64_GUEST_PAGE_SIZE,
           "coalesced writable cross-page touch returned %s found %u calls %u/%u/%u ranges %zu\n",
           uc_strerror( err ), found, memory_map_calls, memory_unmap_calls,
           cache_flush_calls, engine->mapped_ranges.count );

done:
    if (thread_initialized) thread_term( NULL );
    memory_unmap( &cleanup );
    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    if (failures == starting_failures)
        printf( "XTAJIT64_COALESCED_DEMAND_MAPPING_PASS\n" );
}

static uint64_t elapsed_milliseconds( const struct timespec *start,
                                      const struct timespec *now )
{
    time_t seconds = now->tv_sec - start->tv_sec;
    long nanoseconds = now->tv_nsec - start->tv_nsec;

    if (nanoseconds < 0)
    {
        --seconds;
        nanoseconds += 1000000000l;
    }
    return (uint64_t)seconds * 1000 + nanoseconds / 1000000;
}

static BOOL wait_atomic_int_at_least( atomic_int *value, int expected,
                                      unsigned int timeout_ms )
{
    struct timespec start, now;

    clock_gettime( CLOCK_MONOTONIC, &start );
    do
    {
        if (atomic_load_explicit( value, memory_order_acquire ) >= expected) return TRUE;
        sched_yield();
        clock_gettime( CLOCK_MONOTONIC, &now );
    } while (elapsed_milliseconds( &start, &now ) < timeout_ms);
    return FALSE;
}

static BOOL wait_atomic_int_equal( atomic_int *value, int expected,
                                   unsigned int timeout_ms )
{
    struct timespec start, now;

    clock_gettime( CLOCK_MONOTONIC, &start );
    do
    {
        if (atomic_load_explicit( value, memory_order_acquire ) == expected) return TRUE;
        sched_yield();
        clock_gettime( CLOCK_MONOTONIC, &now );
    } while (elapsed_milliseconds( &start, &now ) < timeout_ms);
    return FALSE;
}

static BOOL wait_mutation_stage( enum mutation_stage expected,
                                 unsigned int timeout_ms )
{
    struct timespec start, now;
    enum mutation_stage stage;

    clock_gettime( CLOCK_MONOTONIC, &start );
    do
    {
        pthread_mutex_lock( &provider.mutex );
        stage = provider.mutation_stage;
        pthread_mutex_unlock( &provider.mutex );
        if (stage == expected) return TRUE;
        sched_yield();
        clock_gettime( CLOCK_MONOTONIC, &now );
    } while (elapsed_milliseconds( &start, &now ) < timeout_ms);
    return FALSE;
}

static BOOL wait_provider_shutdown_started( unsigned int timeout_ms )
{
    struct timespec start, now;
    BOOL shutting_down;

    clock_gettime( CLOCK_MONOTONIC, &start );
    do
    {
        pthread_mutex_lock( &provider.mutex );
        shutting_down = provider.shutting_down;
        pthread_mutex_unlock( &provider.mutex );
        if (shutting_down) return TRUE;
        sched_yield();
        clock_gettime( CLOCK_MONOTONIC, &now );
    } while (elapsed_milliseconds( &start, &now ) < timeout_ms);
    return FALSE;
}

static void initialize_begin_parameters( struct xtajit64_begin_params *params,
                                         uint64_t code, uint64_t stack )
{
    memset( params, 0, sizeof(*params) );
    params->context.rip = code;
    params->context.rsp = stack + TEST_PAGE - 16;
    params->context.eflags = 0x202;
    params->context.mxcsr = 0x1f80;
    params->gs_base = test_teb;
    params->stack_limit = stack;
    params->stack_base = stack + TEST_PAGE;
    params->suspend_doorbell = (uintptr_t)test_suspend_doorbell();
}

static void initialize_begin_params( struct simulation *simulation,
                                     uint64_t code, uint64_t stack )
{
    initialize_begin_parameters( &simulation->params, code, stack );
}

static void *run_simulation( void *arg )
{
    struct simulation *simulation = arg;

    simulation->init_status = thread_init( NULL );
    atomic_store_explicit( &simulation->ready, 1, memory_order_release );
    if (!simulation->init_status)
        simulation->status = begin_simulation( &simulation->params );
    thread_term( NULL );
    atomic_store_explicit( &simulation->done, 1, memory_order_release );
    return NULL;
}

static BOOL join_simulation( pthread_t thread, struct simulation *simulation )
{
    BOOL done = wait_atomic_int_at_least( &simulation->done, 1, 5000 );

    if (!done)
    {
        struct xtajit64_poison_params params = { .status = STATUS_TIMEOUT };

        poison( &params );
    }
    pthread_join( thread, NULL );
    return done;
}

static const struct xtajit64_flight_event *find_flight_event( UINT32 type,
                                                               UINT64 causal_boundary_id )
{
    UINT32 i;

    for (i = 0; i < XTAJIT64_FLIGHT_CAPACITY; ++i)
        if (flight_test_snapshot.states[i] == XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED &&
            flight_test_snapshot.events[i].event_type == type &&
            (!causal_boundary_id ||
             flight_test_snapshot.events[i].causal_boundary_id == causal_boundary_id))
            return &flight_test_snapshot.events[i];
    return NULL;
}

#define FLIGHT_STRESS_WRITERS 4u
#define FLIGHT_STRESS_RECORDS 2048u

struct flight_stress_context
{
    struct xtajit64_flight_recorder recorder;
    atomic_int start;
    atomic_int writers_done;
    atomic_uint_fast64_t accepted;
    atomic_uint failures;
};

struct flight_stress_writer
{
    struct flight_stress_context *context;
    UINT32 writer;
};

static struct flight_stress_context flight_stress;

static void *flight_stress_writer_main( void *arg )
{
    struct flight_stress_writer *writer = arg;
    struct xtajit64_flight_event event;
    UINT32 i;

    while (!atomic_load_explicit( &writer->context->start, memory_order_acquire )) sched_yield();
    for (i = 0; i < FLIGHT_STRESS_RECORDS; ++i)
    {
        UINT64 value = (UINT64)writer->writer << 32 | i;

        xtajit64_flight_event_init( &event, XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN,
                                     XTAJIT64_FLIGHT_SOURCE_UNIX_PROVIDER );
        event.detail0 = value;
        event.detail1 = ~value;
        if (xtajit64_flight_record( &writer->context->recorder, &event ))
            atomic_fetch_add_explicit( &writer->context->accepted, 1, memory_order_relaxed );
        if (!(i & 63)) sched_yield();
    }
    atomic_fetch_add_explicit( &writer->context->writers_done, 1, memory_order_release );
    return NULL;
}

static void *flight_stress_snapshot_main( void *arg )
{
    struct flight_stress_context *context = arg;
    struct xtajit64_flight_snapshot_metadata metadata;
    struct xtajit64_flight_event event;
    UINT64 sequence;

    while (!atomic_load_explicit( &context->start, memory_order_acquire )) sched_yield();
    do
    {
        if (!xtajit64_flight_snapshot_metadata( &context->recorder, &metadata ))
        {
            atomic_fetch_add_explicit( &context->failures, 1, memory_order_relaxed );
            break;
        }
        for (sequence = metadata.first_sequence;
             sequence && sequence <= metadata.last_sequence; ++sequence)
        {
            if (xtajit64_flight_snapshot_event( &context->recorder, sequence, &event ) ==
                XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED &&
                (event.sequence != sequence || event.event_type !=
                 XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN || event.detail1 != ~event.detail0))
                atomic_fetch_add_explicit( &context->failures, 1, memory_order_relaxed );
        }
        sched_yield();
    } while (atomic_load_explicit( &context->writers_done, memory_order_acquire ) <
             FLIGHT_STRESS_WRITERS);
    return NULL;
}

static void test_flight_recorder_stress(void)
{
    struct flight_stress_writer writers[FLIGHT_STRESS_WRITERS];
    struct xtajit64_flight_snapshot_metadata metadata;
    struct xtajit64_flight_event event;
    pthread_t writer_threads[FLIGHT_STRESS_WRITERS], snapshot_thread;
    BOOL writer_created[FLIGHT_STRESS_WRITERS] = {0};
    BOOL snapshot_created = FALSE, threads_ready = TRUE;
    UINT64 accepted, attempts = (UINT64)FLIGHT_STRESS_WRITERS * FLIGHT_STRESS_RECORDS;
    UINT64 sequence;
    unsigned int starting_failures = failures;
    UINT32 i;

    memset( &flight_stress, 0, sizeof(flight_stress) );
    xtajit64_flight_recorder_init( &flight_stress.recorder );
    for (i = 0; i < FLIGHT_STRESS_WRITERS; ++i)
    {
        writers[i].context = &flight_stress;
        writers[i].writer = i + 1;
        if (!(writer_created[i] = !pthread_create( &writer_threads[i], NULL,
                                                    flight_stress_writer_main, &writers[i] )))
        {
            check( FALSE, "flight stress writer %u creation failed\n", i );
            threads_ready = FALSE;
            break;
        }
    }
    if (threads_ready &&
        !(snapshot_created = !pthread_create( &snapshot_thread, NULL,
                                              flight_stress_snapshot_main, &flight_stress )))
    {
        check( FALSE, "flight stress snapshot creation failed\n" );
        threads_ready = FALSE;
    }
    atomic_store_explicit( &flight_stress.start, 1, memory_order_release );
    for (i = 0; i < FLIGHT_STRESS_WRITERS; ++i)
        if (writer_created[i]) pthread_join( writer_threads[i], NULL );
    if (snapshot_created) pthread_join( snapshot_thread, NULL );
    if (!threads_ready) return;

    accepted = atomic_load_explicit( &flight_stress.accepted, memory_order_relaxed );
    check( !atomic_load_explicit( &flight_stress.failures, memory_order_relaxed ) &&
           !__atomic_load_n( &flight_stress.recorder.freeze_state, __ATOMIC_ACQUIRE ) &&
           accepted &&
           accepted + __atomic_load_n( &flight_stress.recorder.contention_loss_count,
                                       __ATOMIC_RELAXED ) == attempts &&
           __atomic_load_n( &flight_stress.recorder.next_sequence, __ATOMIC_ACQUIRE ) ==
           accepted + 1,
           "flight MPMC snapshot/ownership stress failed accepted %llu contention %llu failures %u\n",
           (unsigned long long)accepted,
           (unsigned long long)__atomic_load_n( &flight_stress.recorder.contention_loss_count,
                                                __ATOMIC_RELAXED ),
           atomic_load_explicit( &flight_stress.failures, memory_order_relaxed ) );
    check( xtajit64_flight_snapshot_metadata( &flight_stress.recorder, &metadata ),
           "flight stress metadata failed\n" );
    for (sequence = metadata.first_sequence;
         sequence && sequence <= metadata.last_sequence; ++sequence)
        check( xtajit64_flight_snapshot_event( &flight_stress.recorder, sequence, &event ) ==
               XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED && event.sequence == sequence &&
               event.detail1 == ~event.detail0,
               "flight MPMC final snapshot failed at sequence %llu\n",
               (unsigned long long)sequence );
    if (failures == starting_failures) printf( "XTAJIT64_FLIGHT_MPMC_PASS\n" );
}

static void test_flight_recorder_core(void)
{
    struct xtajit64_flight_event event;
    struct xtajit64_flight_snapshot_metadata metadata;
    struct thread_engine engine = {0};
    struct xtajit64_begin_params params = {0};
    struct timespec timestamp;
    ULONG_PTR layout_base, recorder_address;
    UINT64 before, sequence;
    UINT32 reason;
    unsigned int starting_failures = failures;
    unsigned int i;

    timestamp.tv_sec = 1;
    timestamp.tv_nsec = 17;
    check( flight_timestamp_from_timespec( &timestamp ) == UINT64_C(1000000017),
           "flight monotonic timestamp conversion failed\n" );
    timestamp.tv_sec = UINT64_MAX / UINT64_C(1000000000);
    timestamp.tv_nsec = UINT64_MAX % UINT64_C(1000000000);
    check( flight_timestamp_from_timespec( &timestamp ) == XTAJIT64_FLIGHT_UNKNOWN_U64,
           "flight monotonic timestamp accepted the unavailable sentinel\n" );
    timestamp.tv_sec = UINT64_MAX / UINT64_C(1000000000);
    timestamp.tv_nsec = 999999999;
    check( flight_timestamp_from_timespec( &timestamp ) == XTAJIT64_FLIGHT_UNKNOWN_U64,
           "flight monotonic timestamp final-add overflow was not rejected\n" );
    timestamp.tv_sec = 0;
    timestamp.tv_nsec = 1000000000;
    check( flight_timestamp_from_timespec( &timestamp ) == XTAJIT64_FLIGHT_UNKNOWN_U64,
           "flight monotonic timestamp accepted invalid nanoseconds\n" );

    xtajit64_flight_event_init( &event, XTAJIT64_FLIGHT_EVENT_TRANSITION_BEGIN,
                                 XTAJIT64_FLIGHT_SOURCE_ARM64EC_PE );
    check( event.ownership_flags == XTAJIT64_FLIGHT_UNKNOWN_U32,
           "flight event initialized ownership as known\n" );
    event.causal_boundary_id = 0x41;
    before = __atomic_load_n( &flight_test_recorder.next_sequence, __ATOMIC_RELAXED );
    check( !xtajit64_flight_record( NULL, &event ) &&
           __atomic_load_n( &flight_test_recorder.next_sequence, __ATOMIC_RELAXED ) == before,
           "disabled flight recorder changed state\n" );
    check( !xtajit64_flight_record( &flight_test_recorder, &event ) &&
           __atomic_load_n( &flight_test_recorder.next_sequence, __ATOMIC_RELAXED ) == before,
           "uninitialized flight recorder changed state\n" );

    xtajit64_flight_recorder_init( &flight_test_recorder );
    __atomic_store_n( &flight_test_recorder.next_causal_boundary_id,
                      XTAJIT64_FLIGHT_UNKNOWN_U64 - 1, __ATOMIC_RELAXED );
    check( xtajit64_flight_next_causal_boundary_id( &flight_test_recorder ) ==
           XTAJIT64_FLIGHT_UNKNOWN_U64 - 1 &&
           xtajit64_flight_next_causal_boundary_id( &flight_test_recorder ) ==
           XTAJIT64_FLIGHT_UNKNOWN_U64 &&
           __atomic_load_n( &flight_test_recorder.freeze_reason, __ATOMIC_ACQUIRE ) ==
           XTAJIT64_FLIGHT_REASON_RECORDER_WRAP,
           "flight causal ID wrap reused a reserved or prior identity\n" );
    xtajit64_flight_recorder_init( &flight_test_recorder );
    __atomic_store_n( &flight_test_recorder.next_causal_boundary_id, 0, __ATOMIC_RELAXED );
    check( xtajit64_flight_next_causal_boundary_id( &flight_test_recorder ) ==
           XTAJIT64_FLIGHT_UNKNOWN_U64 &&
           __atomic_load_n( &flight_test_recorder.freeze_reason, __ATOMIC_ACQUIRE ) ==
           XTAJIT64_FLIGHT_REASON_RECORDER_WRAP,
           "flight causal ID zero sentinel did not fail closed\n" );
    xtajit64_flight_recorder_init( &flight_test_recorder );
    check( xtajit64_flight_publish_boundary( &flight_test_recorder, 0x41 ) == 0x41 &&
           xtajit64_flight_current_boundary( &flight_test_recorder ) == 0x41 &&
           xtajit64_flight_publish_boundary( &flight_test_recorder, 0x40 ) == 0x41 &&
           xtajit64_flight_current_boundary( &flight_test_recorder ) == 0x41,
           "flight shared boundary publication regressed\n" );
    xtajit64_flight_recorder_init( &flight_test_recorder );
    check( xtajit64_flight_publish_boundary( &flight_test_recorder,
                                             XTAJIT64_FLIGHT_UNKNOWN_U64 ) ==
           XTAJIT64_FLIGHT_UNKNOWN_U64 &&
           __atomic_load_n( &flight_test_recorder.freeze_reason, __ATOMIC_ACQUIRE ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_STALE_PUBLICATION,
           "flight invalid shared boundary did not fail closed\n" );
    xtajit64_flight_recorder_init( &flight_test_recorder );
    recorder_address = (ULONG_PTR)&flight_test_recorder;
    layout_base = recorder_address - 0x10000;
    check( xtajit64_flight_validate_layout( layout_base,
                                            0x10000 + sizeof(flight_test_recorder),
                                            recorder_address, &flight_test_recorder ) &&
           xtajit64_flight_validate_layout( layout_base,
                                            0x10000 + sizeof(flight_test_recorder), 0,
                                            NULL ) &&
           !xtajit64_flight_validate_layout( layout_base,
                                             0x10000 + sizeof(flight_test_recorder),
                                             recorder_address + 64, &flight_test_recorder ) &&
           !xtajit64_flight_validate_layout( layout_base,
                                             0x10001 + sizeof(flight_test_recorder),
                                             recorder_address, &flight_test_recorder ) &&
           !xtajit64_flight_validate_layout( layout_base,
                                             0x10000 + sizeof(flight_test_recorder),
                                             recorder_address + 1,
                                             (const struct xtajit64_flight_recorder *)
                                             (recorder_address + 1) ),
           "flight recorder layout validation accepted an unsafe placement\n" );
    for (i = 0; i < XTAJIT64_FLIGHT_CAPACITY + 3; ++i)
    {
        event.detail0 = i;
        sequence = xtajit64_flight_record( &flight_test_recorder, &event );
        check( sequence == i + 1, "flight sequence %llu was expected %u\n",
               (unsigned long long)sequence, i + 1 );
    }
    xtajit64_flight_snapshot( &flight_test_recorder, &flight_test_snapshot );
    check( flight_test_snapshot.first_sequence == 4 &&
           flight_test_snapshot.last_sequence == XTAJIT64_FLIGHT_CAPACITY + 3 &&
           flight_test_snapshot.count == XTAJIT64_FLIGHT_CAPACITY &&
           flight_test_snapshot.lost_count == 3,
           "flight wrap snapshot %#llx-%#llx count %u lost %llu\n",
           (unsigned long long)flight_test_snapshot.first_sequence,
           (unsigned long long)flight_test_snapshot.last_sequence,
           flight_test_snapshot.count,
           (unsigned long long)flight_test_snapshot.lost_count );
    for (i = 0; i < XTAJIT64_FLIGHT_CAPACITY; ++i)
        check( flight_test_snapshot.states[i] == XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED &&
               flight_test_snapshot.events[i].sequence == i + 4 &&
               flight_test_snapshot.events[i].detail0 == i + 3,
               "flight snapshot ordering failed at slot %u\n", i );

    check( xtajit64_flight_snapshot_metadata( &flight_test_recorder, &metadata ) &&
           metadata.first_sequence == 4 &&
           metadata.historical_loss_count == 3,
           "flight metadata did not expose wrap loss\n" );
    __atomic_store_n( &flight_test_recorder.events[
                          metadata.last_sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)].publication_sequence,
                      0, __ATOMIC_RELEASE );
    check( xtajit64_flight_snapshot_event( &flight_test_recorder, metadata.last_sequence,
                                           &event ) ==
           XTAJIT64_FLIGHT_SNAPSHOT_UNCOMMITTED,
           "flight snapshot did not detect invalidated writer slot\n" );
    __atomic_store_n( &flight_test_recorder.events[
                          metadata.last_sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)].publication_sequence,
                      metadata.last_sequence + XTAJIT64_FLIGHT_CAPACITY, __ATOMIC_RELEASE );
    check( xtajit64_flight_snapshot_event( &flight_test_recorder, metadata.last_sequence,
                                           &event ) ==
           XTAJIT64_FLIGHT_SNAPSHOT_OVERWRITTEN,
           "flight snapshot did not detect overwritten writer slot\n" );
    __atomic_store_n( &flight_test_recorder.events[
                          metadata.last_sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)].publication_sequence,
                      metadata.last_sequence, __ATOMIC_RELEASE );
    __atomic_store_n( &flight_test_recorder.slot_owners[
                          metadata.last_sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)],
                      metadata.last_sequence + XTAJIT64_FLIGHT_CAPACITY |
                      XTAJIT64_FLIGHT_OWNER_BUSY, __ATOMIC_RELEASE );
    check( xtajit64_flight_snapshot_event( &flight_test_recorder, metadata.last_sequence,
                                           &event ) ==
           XTAJIT64_FLIGHT_SNAPSHOT_OVERWRITTEN,
           "flight snapshot accepted an old publication during next-generation claim\n" );
    __atomic_store_n( &flight_test_recorder.slot_owners[
                          metadata.last_sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)],
                      metadata.last_sequence + XTAJIT64_FLIGHT_CAPACITY, __ATOMIC_RELEASE );
    __atomic_store_n( &flight_test_recorder.contention_loss_count, ~(UINT64)0,
                      __ATOMIC_RELAXED );
    xtajit64_flight_snapshot( &flight_test_recorder, &flight_test_snapshot );
    check( flight_test_snapshot.lost_count == ~(UINT64)0,
           "flight loss counter did not saturate\n" );
    xtajit64_flight_recorder_init( &flight_test_recorder );

    reason = xtajit64_flight_validate_context( CONTEXT_AMD64_CONTROL |
                                                CONTEXT_AMD64_INTEGER,
                                                CONTEXT_AMD64_FULL |
                                                CONTEXT_AMD64_FLOATING_POINT,
                                                0x1f80, 0x1f80, 0x1000, 0x2000,
                                                XTAJIT64_X64_USER_ADDRESS_MAX,
                                                0x1000, 0x3000,
                                                XTAJIT64_FLIGHT_UNKNOWN_U64,
                                                XTAJIT64_FLIGHT_UNKNOWN_U64,
                                                XTAJIT64_FLIGHT_UNKNOWN_U64 );
    check( reason == XTAJIT64_FLIGHT_REASON_CONTEXT_FLAGS,
           "flight context flags watchdog returned %u\n", reason );
    reason = xtajit64_flight_validate_context( 0,
                                                CONTEXT_AMD64_FULL |
                                                CONTEXT_AMD64_FLOATING_POINT,
                                                0x1f80, 0x1f80, 0x1000, 0x2000,
                                                XTAJIT64_X64_USER_ADDRESS_MAX,
                                                0x1000, 0x3000,
                                                XTAJIT64_FLIGHT_UNKNOWN_U64,
                                                XTAJIT64_FLIGHT_UNKNOWN_U64,
                                                XTAJIT64_FLIGHT_UNKNOWN_U64 );
    check( reason == XTAJIT64_FLIGHT_REASON_CONTEXT_FLAGS,
           "flight known zero context flags passed required bits\n" );
    reason = xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                                0x1f80, 0x1234, 0x1000, 0x2000,
                                                XTAJIT64_X64_USER_ADDRESS_MAX,
                                                0x1000, 0x3000,
                                                XTAJIT64_FLIGHT_UNKNOWN_U64,
                                                XTAJIT64_FLIGHT_UNKNOWN_U64,
                                                XTAJIT64_FLIGHT_UNKNOWN_U64 );
    check( reason == XTAJIT64_FLIGHT_REASON_CONTEXT_MXCSR,
           "flight MXCSR watchdog returned %u\n", reason );
    reason = xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                                0x1f80, 0x1f80, 0x1000, 0x1000,
                                                XTAJIT64_X64_USER_ADDRESS_MAX,
                                                0x1000, 0x3000, 0x5000, 0x5000,
                                                0x2000 );
    check( reason == XTAJIT64_FLIGHT_REASON_CONTINUATION_PAIR,
           "flight continuation watchdog returned %u\n", reason );
    check( xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                              0x1f80, 0x1f80, 0, 0x2000,
                                              XTAJIT64_X64_USER_ADDRESS_MAX,
                                              0x1000, 0x3000,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64 ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_RIP &&
           xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                              0x1f80, 0x1f80,
                                              XTAJIT64_X64_USER_ADDRESS_MAX + 1, 0x2000,
                                              XTAJIT64_X64_USER_ADDRESS_MAX,
                                              0x1000, 0x3000,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64 ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_RIP,
           "flight RIP address bounds watchdog failed\n" );
    check( xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                              0x1f80, 0x1f80, 0x1000, 0,
                                              XTAJIT64_X64_USER_ADDRESS_MAX,
                                              0x1000, 0x3000,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64 ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_RSP &&
           xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                              0x1f80, 0x1f80, 0x1000,
                                              XTAJIT64_X64_USER_ADDRESS_MAX + 1,
                                              XTAJIT64_X64_USER_ADDRESS_MAX,
                                              0x1000, 0x3000,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64 ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_RSP,
           "flight RSP address bounds watchdog failed\n" );
    check( xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                              0x1f80, 0x1f80, 0x1000, 0x2000,
                                              XTAJIT64_X64_USER_ADDRESS_MAX,
                                              0x3000, 0x1000,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64 ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_STACK &&
           xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                              0x1f80, 0x1f80, 0x1000, 0x0fff,
                                              XTAJIT64_X64_USER_ADDRESS_MAX,
                                              0x1000, 0x3000,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64 ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_STACK &&
           xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                              0x1f80, 0x1f80, 0x1000, 0x3000,
                                              XTAJIT64_X64_USER_ADDRESS_MAX,
                                              0x1000, 0x3000,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64 ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_STACK &&
           xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                              0x1f80, 0x1f80, 0x1000, 0x2000,
                                              XTAJIT64_X64_USER_ADDRESS_MAX,
                                              0x1000, 0x3000,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64,
                                              XTAJIT64_FLIGHT_UNKNOWN_U64 ) ==
           XTAJIT64_FLIGHT_REASON_NONE,
           "flight stack-range watchdog failed\n" );
    check( xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_UNKNOWN,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
                                         0x1111, 0x1111 ) ==
           XTAJIT64_FLIGHT_REASON_NONE &&
           xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_UNKNOWN,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
                                         0x1111, 0x2222 ) ==
           XTAJIT64_FLIGHT_REASON_X18_VALUE,
           "flight x18 UNKNOWN semantics inferred a mode\n" );
    check( xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_ENABLED,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM,
                                         0, 0x1111 ) == XTAJIT64_FLIGHT_REASON_X18_MODE &&
           xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_DISABLED,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM,
                                         0, 0x1111 ) == XTAJIT64_FLIGHT_REASON_NONE &&
           xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_DISABLED,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM,
                                         0x9999, 0x1111 ) == XTAJIT64_FLIGHT_REASON_NONE &&
           xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_UNKNOWN,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM,
                                         0x9999, 0x1111 ) == XTAJIT64_FLIGHT_REASON_NONE,
           "flight native-system x18 mode/value separation failed\n" );
    check( xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_ENABLED,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
                                         0x1111, 0x1111 ) == XTAJIT64_FLIGHT_REASON_NONE &&
           xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_ENABLED,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
                                         0x2222, 0x1111 ) == XTAJIT64_FLIGHT_REASON_X18_VALUE &&
           xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_DISABLED,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
                                         0x1111, 0x1111 ) == XTAJIT64_FLIGHT_REASON_X18_MODE &&
           xtajit64_flight_validate_x18( XTAJIT64_FLIGHT_X18_MODE_UNKNOWN,
                                         XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
                                         0x2222, 0x1111 ) == XTAJIT64_FLIGHT_REASON_X18_VALUE,
           "flight PE x18 mode/value separation failed\n" );
    check( xtajit64_flight_validate_pe_x18_claim( 0x1111, 0x1111 ) ==
           XTAJIT64_FLIGHT_REASON_NONE &&
           xtajit64_flight_validate_pe_x18_claim( 0x2222, 0x1111 ) ==
           XTAJIT64_FLIGHT_REASON_X18_VALUE &&
           xtajit64_flight_validate_pe_x18_claim( 0, 0x1111 ) ==
           XTAJIT64_FLIGHT_REASON_X18_VALUE &&
           xtajit64_flight_validate_pe_x18_claim( XTAJIT64_FLIGHT_UNKNOWN_U64, 0x1111 ) ==
           XTAJIT64_FLIGHT_REASON_X18_VALUE,
           "flight PE x18 claim authentication accepted an invalid value\n" );
    check( xtajit64_flight_validate_private_control_stack( 0x1800, 0x1000, 0x2000,
                                                            0x3000, 0x4000 ) ==
           XTAJIT64_FLIGHT_REASON_NONE &&
           xtajit64_flight_validate_private_control_stack( 0x1800, 0x2000, 0x1000,
                                                            0x3000, 0x4000 ) ==
           XTAJIT64_FLIGHT_REASON_TRANSITION_STACK &&
           xtajit64_flight_validate_private_control_stack( 0x2000, 0x1000, 0x2000,
                                                            0x3000, 0x4000 ) ==
           XTAJIT64_FLIGHT_REASON_TRANSITION_STACK &&
           xtajit64_flight_validate_private_control_stack( 0x1800, 0x1000, 0x3000,
                                                            0x2000, 0x4000 ) ==
           XTAJIT64_FLIGHT_REASON_TRANSITION_STACK,
           "flight private-control-stack watchdog failed\n" );
    check( !xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0x4000, TRUE, 0, 0x2000,
               XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR, 2 ) &&
           xtajit64_flight_classify_transition_stack(
               0, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0x4000, TRUE, 0, 0x2000,
               XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_RIP_RANGE &&
           xtajit64_flight_classify_transition_stack(
               0x1000, XTAJIT64_X64_USER_ADDRESS_MAX + 1, 0x3000,
               XTAJIT64_X64_USER_ADDRESS_MAX, 0x3000, 0x3000, 0x4000, 0x4000,
               TRUE, 0, XTAJIT64_X64_USER_ADDRESS_MAX + 1,
               XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_RSP_RANGE &&
           xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0x4000, TRUE, 0, 0x2000,
               XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_GS_RANGE &&
           xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3008, 0x4000, 0x4000, TRUE, 0, 0x2000,
               XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_TEB_IDENTITY &&
           xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0, TRUE, 0, 0x2000,
               XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_CPU_MISSING &&
           xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0x4008, TRUE, 0, 0x2000,
               XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_CPU_IDENTITY &&
           xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0x4000, TRUE, STATUS_INVALID_ADDRESS,
               XTAJIT64_FLIGHT_UNKNOWN_U64, 0, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_TRANSLATE_STATUS &&
           xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0x4000, TRUE, 0, 0x2008,
               XTAJIT64_FLIGHT_STACK_MATCH_TEB, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_TRANSLATED_GUEST &&
           xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0x4000, TRUE, 0, 0x2000, 0, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_STACK_RANGE &&
           xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0x4000, FALSE,
               XTAJIT64_FLIGHT_UNKNOWN_U32, XTAJIT64_FLIGHT_UNKNOWN_U64, 0, 2 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_PROBE_NOT_RUN &&
           xtajit64_flight_classify_transition_stack(
               0x1000, 0x2000, 0x3000, XTAJIT64_X64_USER_ADDRESS_MAX,
               0x3000, 0x3000, 0x4000, 0x4000, TRUE, 0, 0x2000,
               XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR,
               XTAJIT64_FLIGHT_MAX_TRANSITION_FRAMES + 1 ) ==
               XTAJIT64_FLIGHT_STACK_REJECT_FRAME_DEPTH,
           "flight transition-stack classifier did not isolate each predicate\n" );
    /* Simulate the next MAPPING_MISS retry reusing begin_params.  IMPORT is
     * input-side evidence, so it must not inherit that prior output reason. */
    xtajit64_flight_recorder_init( &flight_test_recorder );
    engine.flight_recorder = &flight_test_recorder;
    params.context.rip = 0x1000;
    params.context.rsp = 0x2000;
    params.context.mxcsr = 0x1f80;
    params.stack_limit = 0x1000;
    params.stack_base = 0x3000;
    params.stop_reason = XTAJIT64_STOP_MAPPING_MISS;
    flight_record_context_event( &engine, XTAJIT64_FLIGHT_EVENT_CONTEXT_IMPORT,
                                 &params, XTAJIT64_FLIGHT_REASON_NONE );
    check( xtajit64_flight_snapshot_event( &flight_test_recorder, 1, &event ) ==
           XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED &&
           event.event_type == XTAJIT64_FLIGHT_EVENT_CONTEXT_IMPORT &&
           event.stop_reason == XTAJIT64_FLIGHT_UNKNOWN_U32,
           "flight retry import inherited terminal stop reason %u\n", event.stop_reason );
    xtajit64_flight_recorder_init( &flight_test_recorder );
    check( xtajit64_flight_freeze( &flight_test_recorder,
                                   XTAJIT64_FLIGHT_REASON_CONTEXT_MXCSR ) &&
           !xtajit64_flight_freeze( &flight_test_recorder,
                                    XTAJIT64_FLIGHT_REASON_X18_VALUE ) &&
           !xtajit64_flight_recorder_is_active( &flight_test_recorder ) &&
           __atomic_load_n( &flight_test_recorder.freeze_reason, __ATOMIC_ACQUIRE ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_MXCSR,
           "flight first-violation freeze was not stable\n" );
    if (failures == starting_failures) printf( "XTAJIT64_FLIGHT_CORE_PASS\n" );
}

static void test_flight_atomic_trace(void)
{
    struct xtajit64_flight_event exit_event, reentry_event;
    struct thread_engine engine = {0};
    uc_engine *uc = NULL;
    uint64_t rip = UINT64_C(0x1234567812345678);
    uint64_t rsp = UINT64_C(0x0000001020004000);
    uc_err err;
    unsigned int starting_failures = failures;

    xtajit64_flight_recorder_init( &flight_test_recorder );
    engine.flight_recorder = &flight_test_recorder;
    engine.flight_binding_id = 0x51;
    engine.flight_causal_boundary_id = 0x61;
    engine.flight_guest_rip = 0x71;
    engine.flight_guest_rsp = 0x81;
    engine.diagnostic_id = 0x91;
    engine.execution_generation = 0xa1;

    err = uc_open( UC_ARCH_X86, UC_MODE_64, &uc );
    check( err == UC_ERR_OK, "flight atomic trace engine open failed: %s\n",
           uc_strerror( err ) );
    if (err != UC_ERR_OK) goto done;
    err = uc_reg_write( uc, UC_X86_REG_RIP, &rip );
    if (err == UC_ERR_OK) err = uc_reg_write( uc, UC_X86_REG_RSP, &rsp );
    check( err == UC_ERR_OK, "flight atomic trace register setup failed: %s\n",
           uc_strerror( err ) );
    if (err != UC_ERR_OK) goto done;

    shared_memory_atomic_hook( uc, (uc_shared_memory_atomic_phase)0, &engine );
    shared_memory_atomic_hook( uc, UC_SHARED_MEMORY_ATOMIC_EXIT, &engine );
    shared_memory_atomic_hook( uc, UC_SHARED_MEMORY_ATOMIC_REENTRY, &engine );
    check( xtajit64_flight_snapshot_event( &flight_test_recorder, 1, &exit_event ) ==
               XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED &&
           xtajit64_flight_snapshot_event( &flight_test_recorder, 2, &reentry_event ) ==
               XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED &&
           exit_event.event_type == XTAJIT64_FLIGHT_EVENT_ATOMIC_EXIT &&
           reentry_event.event_type == XTAJIT64_FLIGHT_EVENT_ATOMIC_REENTRY &&
           exit_event.guest_rip == rip && exit_event.guest_rsp == rsp &&
           reentry_event.guest_rip == rip && reentry_event.guest_rsp == rsp &&
           exit_event.binding_id == engine.flight_binding_id &&
           reentry_event.causal_boundary_id == engine.flight_causal_boundary_id,
           "flight serial-atomic events lost phase or exact RIP/RSP evidence\n" );

done:
    if (uc) uc_close( uc );
    if (failures == starting_failures) printf( "XTAJIT64_FLIGHT_ATOMIC_TRACE_PASS\n" );
}

static void test_flight_recorder_contracts(void)
{
    struct xtajit64_flight_event event, first;
    struct xtajit64_flight_transition_stack_violation violation, violation_copy;
    struct xtajit64_flight_scratch *scratch[XTAJIT64_FLIGHT_SCRATCH_SLOTS];
    struct xtajit64_flight_scratch *exhausted_scratch;
    struct xtajit64_flight_event *held_slot;
    struct xtajit64_flight_snapshot_metadata metadata;
    UINT64 held_sequence, sequence;
    unsigned int starting_failures = failures;
    UINT32 i;

    xtajit64_flight_recorder_init( &flight_test_recorder );
    xtajit64_flight_event_init( &event, XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN,
                                 XTAJIT64_FLIGHT_SOURCE_UNIX_PROVIDER );
    check( xtajit64_flight_claim_slot( &flight_test_recorder, &held_sequence, &held_slot ) &&
           held_sequence == 1,
           "flight deterministic owner claim failed\n" );
    for (i = 2; i <= XTAJIT64_FLIGHT_CAPACITY; ++i)
        check( xtajit64_flight_record( &flight_test_recorder, &event ) == i,
               "flight deterministic fill failed at sequence %u\n", i );
    check( !xtajit64_flight_record( &flight_test_recorder, &event ) &&
           __atomic_load_n( &flight_test_recorder.next_sequence, __ATOMIC_ACQUIRE ) ==
           XTAJIT64_FLIGHT_CAPACITY + 1 &&
           __atomic_load_n( &flight_test_recorder.contention_loss_count,
                            __ATOMIC_RELAXED ) == 1,
           "flight blocked next-generation slot advanced or lost accounting\n" );
    xtajit64_flight_release_slot( &flight_test_recorder, held_slot, held_sequence );
    sequence = xtajit64_flight_record( &flight_test_recorder, &event );
    check( sequence == XTAJIT64_FLIGHT_CAPACITY + 1,
           "flight released next-generation slot did not recover\n" );

    xtajit64_flight_recorder_init( &flight_test_recorder );
    for (i = 0; i < XTAJIT64_FLIGHT_SCRATCH_SLOTS; ++i)
        check( xtajit64_flight_acquire_scratch( &flight_test_recorder, &scratch[i] ),
               "flight scratch slot %u was unavailable\n", i );
    exhausted_scratch = (void *)(ULONG_PTR)0x1;
    check( !xtajit64_flight_acquire_scratch( &flight_test_recorder, &exhausted_scratch ) &&
           !exhausted_scratch &&
           __atomic_load_n( &flight_test_recorder.scratch_loss_count, __ATOMIC_RELAXED ) == 1,
           "flight scratch exhaustion was not reported\n" );
    for (i = 0; i < XTAJIT64_FLIGHT_SCRATCH_SLOTS; ++i)
        xtajit64_flight_release_scratch( scratch[i] );
    check( xtajit64_flight_acquire_scratch( &flight_test_recorder, &scratch[0] ),
           "flight scratch slot did not recover after release\n" );
    xtajit64_flight_release_scratch( scratch[0] );

    xtajit64_flight_recorder_init( &flight_test_recorder );
    check( xtajit64_flight_record( &flight_test_recorder, &event ) == 1 &&
           xtajit64_flight_freeze( &flight_test_recorder,
                                   XTAJIT64_FLIGHT_REASON_TERMINAL_ABORT ),
           "flight frozen-window setup failed\n" );
    /* Model the only remaining freeze-gate race deterministically: a writer
     * sampled ACTIVE, then reserves ticket 2 after the freezer captured its
     * cut-off.  Snapshot metadata must retain sequence 1 as the end of causal
     * history even though next_sequence subsequently advances. */
    sequence = 2;
    check( __atomic_compare_exchange_n( &flight_test_recorder.next_sequence, &sequence, 3,
                                        FALSE, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE ) &&
           xtajit64_flight_snapshot_metadata( &flight_test_recorder, &metadata ) &&
           metadata.frozen_sequence == 1 && metadata.last_sequence == 1,
           "flight frozen-window metadata did not cap a late ticket\n" );
    xtajit64_flight_snapshot( &flight_test_recorder, &flight_test_snapshot );
    check( flight_test_snapshot.first_sequence == 1 && flight_test_snapshot.last_sequence == 1 &&
           flight_test_snapshot.count == 1 &&
           flight_test_snapshot.events[0].sequence == 1,
           "flight late ticket was rendered as frozen causal history\n" );

    xtajit64_flight_recorder_init( &flight_test_recorder );
    xtajit64_flight_event_init( &event, XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION,
                                 XTAJIT64_FLIGHT_SOURCE_ARM64EC_PE );
    event.reason = XTAJIT64_FLIGHT_REASON_NONE;
    event.detail0 = 0xfeed;
    check( xtajit64_flight_record_and_freeze( &flight_test_recorder, &event,
                                               XTAJIT64_FLIGHT_REASON_CONTEXT_FLAGS ) &&
           !xtajit64_flight_record_and_freeze( &flight_test_recorder, &event,
                                                XTAJIT64_FLIGHT_REASON_X18_VALUE ) &&
           xtajit64_flight_snapshot_metadata( &flight_test_recorder, &metadata ) &&
           metadata.first_violation_available &&
           xtajit64_flight_snapshot_first_violation( &flight_test_recorder, &first ) &&
           first.reason == XTAJIT64_FLIGHT_REASON_CONTEXT_FLAGS && first.sequence == 1 &&
           first.detail0 == 0xfeed,
           "flight first watchdog winner was not atomically preserved\n" );

    xtajit64_flight_recorder_init( &flight_test_recorder );
    xtajit64_flight_event_init( &event,
                               XTAJIT64_FLIGHT_EVENT_TRANSITION_STACK_CLASSIFY,
                               XTAJIT64_FLIGHT_SOURCE_ARM64EC_PE );
    memset( &violation, 0, sizeof(violation) );
    violation.reject_mask = XTAJIT64_FLIGHT_STACK_REJECT_STACK_RANGE;
    violation.depth = violation.frame_count = 2;
    violation.frames[0].depth = 1;
    violation.frames[0].guest_rsp = 0x8000;
    violation.frames[1].depth = 2;
    violation.frames[1].guest_rsp = 0x7ff0;
    check( xtajit64_flight_record_transition_stack_violation_and_freeze(
               &flight_test_recorder, &event, &violation ) &&
           xtajit64_flight_snapshot_metadata( &flight_test_recorder, &metadata ) &&
           metadata.freeze_reason == XTAJIT64_FLIGHT_REASON_TRANSITION_STACK &&
           xtajit64_flight_snapshot_first_violation( &flight_test_recorder, &first ) &&
           first.event_type == XTAJIT64_FLIGHT_EVENT_TRANSITION_STACK_CLASSIFY &&
           first.reason == XTAJIT64_FLIGHT_REASON_TRANSITION_STACK &&
           xtajit64_flight_snapshot_transition_stack_violation(
               &flight_test_recorder, &violation_copy ) &&
           violation_copy.reject_mask == XTAJIT64_FLIGHT_STACK_REJECT_STACK_RANGE &&
           violation_copy.depth == 2 && violation_copy.frame_count == 2 &&
           violation_copy.frames[0].guest_rsp == 0x8000 &&
           violation_copy.frames[1].guest_rsp == 0x7ff0,
           "flight transition-stack side payload was not atomically preserved\n" );

    xtajit64_flight_recorder_init( &flight_test_recorder );
    xtajit64_flight_event_init( &event, XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_PUSH,
                                 XTAJIT64_FLIGHT_SOURCE_ARM64EC_PE );
    event.transition_frame_kind = XTAJIT64_FLIGHT_FRAME_ENTRY;
    event.transition_depth_before = 0;
    event.transition_depth_after = 1;
    event.ownership_flags = XTAJIT64_FLIGHT_OWNERSHIP_SIMULATION_ACTIVE |
                            XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_PRESENT |
                            XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_OWNED;
    event.guest_rsp = 0x8000;
    event.detail0 = 0x1800;
    event.detail1 = 0x5000;
    xtajit64_flight_record( &flight_test_recorder, &event );
    event.transition_frame_kind = XTAJIT64_FLIGHT_FRAME_EXIT;
    event.transition_depth_before = 1;
    event.transition_depth_after = 2;
    event.guest_rsp = 0x7ff0;
    event.detail0 = 0x1810;
    event.detail1 = 0x5010;
    xtajit64_flight_record( &flight_test_recorder, &event );
    event.event_type = XTAJIT64_FLIGHT_EVENT_TRANSITION_UNWIND;
    event.transition_depth_before = 2;
    event.transition_depth_after = 1;
    xtajit64_flight_record( &flight_test_recorder, &event );
    event.event_type = XTAJIT64_FLIGHT_EVENT_TRANSITION_RECONCILE;
    event.transition_frame_kind = XTAJIT64_FLIGHT_FRAME_ENTRY;
    event.transition_depth_before = 1;
    event.transition_depth_after = 0;
    event.guest_rsp = 0x8000;
    event.detail0 = 0x1800;
    event.detail1 = 0x5000;
    xtajit64_flight_record( &flight_test_recorder, &event );
    xtajit64_flight_snapshot( &flight_test_recorder, &flight_test_snapshot );
    check( flight_test_snapshot.count == 4 &&
           flight_test_snapshot.events[0].event_type ==
           XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_PUSH &&
           flight_test_snapshot.events[0].transition_frame_kind == XTAJIT64_FLIGHT_FRAME_ENTRY &&
           flight_test_snapshot.events[0].transition_depth_before == 0 &&
           flight_test_snapshot.events[0].transition_depth_after == 1 &&
           flight_test_snapshot.events[0].ownership_flags ==
               (XTAJIT64_FLIGHT_OWNERSHIP_SIMULATION_ACTIVE |
                XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_PRESENT |
                XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_OWNED) &&
           flight_test_snapshot.events[1].transition_frame_kind == XTAJIT64_FLIGHT_FRAME_EXIT &&
           flight_test_snapshot.events[1].transition_depth_before == 1 &&
           flight_test_snapshot.events[1].transition_depth_after == 2 &&
           flight_test_snapshot.events[2].event_type ==
           XTAJIT64_FLIGHT_EVENT_TRANSITION_UNWIND &&
           flight_test_snapshot.events[2].transition_depth_before == 2 &&
           flight_test_snapshot.events[2].transition_depth_after == 1 &&
           flight_test_snapshot.events[3].event_type ==
           XTAJIT64_FLIGHT_EVENT_TRANSITION_RECONCILE &&
           flight_test_snapshot.events[3].transition_depth_before == 1 &&
           flight_test_snapshot.events[3].transition_depth_after == 0 &&
           flight_test_snapshot.events[2].detail0 == 0x1810 &&
           flight_test_snapshot.events[2].detail1 == 0x5010,
           "flight nested/non-local transition-frame sequence was not preserved\n" );
    if (failures == starting_failures) printf( "XTAJIT64_FLIGHT_CONTRACTS_PASS\n" );
}

static void publish_test_flight_boundary( struct xtajit64_flight_recorder *recorder,
                                          struct xtajit64_flight_bind_params *binding,
                                          UINT64 boundary_id )
{
    binding->causal_boundary_id = boundary_id;
    binding->context_generation = boundary_id;
    binding->transition_generation = boundary_id;
    check( xtajit64_flight_publish_boundary( recorder, boundary_id ) == boundary_id,
           "flight test boundary %#llx was not published\n",
           (unsigned long long)boundary_id );
}

static void test_flight_provider_boundary(void)
{
    unsigned char *recorder_pages = test_pages + 12 * TEST_PAGE;
    unsigned char *stack_page = test_pages + 14 * TEST_PAGE;
    unsigned char *invalid_code_page = test_pages + 11 * TEST_PAGE;
    void *recorder2_pages = MAP_FAILED;
    struct xtajit64_flight_recorder *recorder =
        (struct xtajit64_flight_recorder *)recorder_pages;
    struct xtajit64_flight_recorder *recorder2;
    struct xtajit64_flight_bind_params binding = {0};
    struct xtajit64_begin_params params;
    struct xtajit64_memory_params flush =
    {
        .guest = (uintptr_t)invalid_code_page,
        .size = TEST_PAGE,
    };
    const struct xtajit64_flight_event *bind, *acquire, *import, *begin;
    const struct xtajit64_flight_event *stop, *export, *release;
    const struct xtajit64_flight_event *invalid_stop, *invalid_export;
    const struct xtajit64_flight_event *interrupt_stop;
    struct xtajit64_flight_event first_violation;
    UINT64 binding_id, causal_boundary_id, unix_teb, wrong_teb;
    NTSTATUS status;
    unsigned int starting_failures = failures;
    BOOL recorder_mapped = FALSE, recorder2_mapped = FALSE, stack_mapped = FALSE, ec_mapped = FALSE;
    BOOL invalid_code_mapped = FALSE;
    BOOL teb_mapped = FALSE, thread_initialized = FALSE;

    check( sizeof(*recorder) <= 2 * TEST_PAGE,
           "flight recorder %lu exceeds test mapping\n", (unsigned long)sizeof(*recorder) );
    status = reset_test_provider();
    if (!status) status = register_identity_page( (void *)(uintptr_t)test_ec_target,
                                                   PAGE_EXECUTE_READ );
    if (!status) ec_mapped = TRUE;
    if (!status) status = register_identity_page( (void *)(uintptr_t)test_teb, PAGE_READWRITE );
    if (!status) teb_mapped = TRUE;
    if (!status)
        status = register_identity_range( recorder_pages, 2 * TEST_PAGE, PAGE_READWRITE );
    if (!status) recorder_mapped = TRUE;
    if (!status)
    {
        recorder2_pages = mmap( NULL, 2 * TEST_PAGE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANON, -1, 0 );
        if (recorder2_pages == MAP_FAILED ||
            (uintptr_t)recorder2_pages > XTAJIT64_X64_USER_ADDRESS_MAX)
            status = STATUS_NO_MEMORY;
        else status = register_identity_range( recorder2_pages, 2 * TEST_PAGE, PAGE_READWRITE );
    }
    if (!status) recorder2_mapped = TRUE;
    if (!status) status = register_identity_page( stack_page, PAGE_READWRITE );
    if (!status) stack_mapped = TRUE;
    if (!status)
    {
        memset( invalid_code_page, 0x90, TEST_PAGE );
        invalid_code_page[0] = 0x0f;  /* UD2: route through the invalid-insn path. */
        invalid_code_page[1] = 0x0b;
        status = register_identity_page( invalid_code_page, PAGE_EXECUTE_READ );
    }
    if (!status) invalid_code_mapped = TRUE;
    if (!status) status = thread_init( NULL );
    if (!status) thread_initialized = TRUE;
    check( !status, "flight provider setup returned %#x\n", (unsigned int)status );
    if (status) goto done;

    xtajit64_flight_recorder_init( recorder );
    recorder2 = recorder2_pages;
    xtajit64_flight_recorder_init( recorder2 );
    unix_teb = (UINT64)(ULONG_PTR)NtCurrentTeb();
    check( unix_teb && unix_teb != XTAJIT64_FLIGHT_UNKNOWN_U64,
           "flight Unix TEB authority was unavailable\n" );
    if (!unix_teb || unix_teb == XTAJIT64_FLIGHT_UNKNOWN_U64) goto done;
    initialize_begin_parameters( &params, test_ec_target, (uintptr_t)stack_page );
    binding.recorder = (uintptr_t)recorder;
    publish_test_flight_boundary( recorder, &binding, 0x9a17 );
    binding.claimed_teb = unix_teb;
    binding.guest_rip = params.context.rip;
    binding.guest_rsp = params.context.rsp;
    binding.guest_stack_limit = params.stack_limit;
    binding.guest_stack_base = params.stack_base;
    binding.control_stack_limit = (uintptr_t)recorder_pages;
    binding.control_stack_top = (uintptr_t)recorder_pages + 2 * TEST_PAGE;
    status = flight_bind( &binding );
    check( !status, "flight binding returned %#x\n", (unsigned int)status );
    if (status) goto done;

    status = begin_simulation( &params );
    check( !status && params.stop_reason == XTAJIT64_STOP_EC_TRANSITION,
           "flight provider simulation returned %#x stop %u\n",
           (unsigned int)status, params.stop_reason );
    xtajit64_flight_snapshot( recorder, &flight_test_snapshot );
    bind = find_flight_event( XTAJIT64_FLIGHT_EVENT_BINDING, binding.causal_boundary_id );
    acquire = find_flight_event( XTAJIT64_FLIGHT_EVENT_ENGINE_ACQUIRE,
                                 binding.causal_boundary_id );
    import = find_flight_event( XTAJIT64_FLIGHT_EVENT_CONTEXT_IMPORT,
                                binding.causal_boundary_id );
    begin = find_flight_event( XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN,
                               binding.causal_boundary_id );
    stop = find_flight_event( XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP,
                              binding.causal_boundary_id );
    export = find_flight_event( XTAJIT64_FLIGHT_EVENT_CONTEXT_EXPORT,
                                binding.causal_boundary_id );
    release = find_flight_event( XTAJIT64_FLIGHT_EVENT_ENGINE_RELEASE,
                                 binding.causal_boundary_id );
    check( bind && acquire && import && begin && stop && export && release,
           "flight provider boundary events missing bind %p acquire %p import %p begin %p "
           "stop %p export %p release %p\n", bind, acquire, import, begin, stop,
           export, release );
    if (bind && acquire && import && begin && stop && export && release)
    {
        binding_id = bind->binding_id;
        causal_boundary_id = bind->causal_boundary_id;
        check( binding_id && acquire->binding_id == binding_id &&
               import->binding_id == binding_id && begin->binding_id == binding_id &&
               stop->binding_id == binding_id && export->binding_id == binding_id &&
               release->binding_id == binding_id &&
               causal_boundary_id == binding.causal_boundary_id &&
               acquire->context_generation == causal_boundary_id &&
               acquire->transition_generation == causal_boundary_id &&
               bind->guest_rsp == binding.guest_rsp &&
               begin->guest_stack_limit == binding.guest_stack_limit &&
               begin->guest_stack_base == binding.guest_stack_base &&
               begin->control_stack_limit == binding.control_stack_limit &&
               begin->control_stack_top == binding.control_stack_top &&
               bind->expected_teb == unix_teb && bind->saved_x18_value == unix_teb &&
               (__atomic_load_n( &recorder->authenticated_teb, __ATOMIC_ACQUIRE ) == unix_teb) &&
               stop->guest_rsp == params.context.rsp,
               "flight provider identity/stack data was not preserved\n" );
    }

    /* The terminal recorder events must see the ordinary stop-reason
     * normalization, not the pre-normalization NONE left by uc_emu_start(). */
    initialize_begin_parameters( &params, (uintptr_t)invalid_code_page,
                                 (uintptr_t)stack_page );
    publish_test_flight_boundary( recorder, &binding, 0x9a19 );
    status = begin_simulation( &params );
    check( status == STATUS_NOT_SUPPORTED &&
           params.stop_reason == XTAJIT64_STOP_INVALID_INSTRUCTION,
           "flight invalid instruction returned %#x stop %u\n",
           (unsigned int)status, params.stop_reason );
    xtajit64_flight_snapshot( recorder, &flight_test_snapshot );
    invalid_stop = find_flight_event( XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP,
                                      binding.causal_boundary_id );
    invalid_export = find_flight_event( XTAJIT64_FLIGHT_EVENT_CONTEXT_EXPORT,
                                        binding.causal_boundary_id );
    check( !find_flight_event( XTAJIT64_FLIGHT_EVENT_BINDING,
                               binding.causal_boundary_id ) &&
           invalid_stop && invalid_export &&
           invalid_stop->context_generation == binding.causal_boundary_id &&
           invalid_stop->transition_generation == binding.causal_boundary_id &&
           invalid_stop->stop_reason == XTAJIT64_STOP_INVALID_INSTRUCTION &&
           invalid_export->stop_reason == XTAJIT64_STOP_INVALID_INSTRUCTION,
           "flight shared-boundary refresh or terminal stop was lost stop %p/%u export %p/%u\n",
           invalid_stop, invalid_stop ? invalid_stop->stop_reason : XTAJIT64_FLIGHT_UNKNOWN_U32,
           invalid_export, invalid_export ? invalid_export->stop_reason : XTAJIT64_FLIGHT_UNKNOWN_U32 );

    /* UC_HOOK_INTR distinguishes INT 2e (syscall bridge) from every other
     * interrupt.  Preserve the latter's exact number rather than only its
     * normalized INVALID_INSTRUCTION terminal reason. */
    memset( invalid_code_page, 0x90, TEST_PAGE );
    invalid_code_page[0] = 0xcd;  /* INT 80 */
    invalid_code_page[1] = 0x80;
    check( !flush_instruction_cache( &flush ),
           "flight interrupt code flush failed\n" );
    initialize_begin_parameters( &params, (uintptr_t)invalid_code_page,
                                 (uintptr_t)stack_page );
    publish_test_flight_boundary( recorder, &binding, 0x9a1a );
    status = begin_simulation( &params );
    check( status == STATUS_NOT_SUPPORTED &&
           params.stop_reason == XTAJIT64_STOP_INVALID_INSTRUCTION,
           "flight interrupt returned %#x stop %u\n", (unsigned int)status,
           params.stop_reason );
    xtajit64_flight_snapshot( recorder, &flight_test_snapshot );
    interrupt_stop = find_flight_event( XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP,
                                        binding.causal_boundary_id );
    check( interrupt_stop && interrupt_stop->detail0 == 0x80 &&
           interrupt_stop->stop_reason == XTAJIT64_STOP_INVALID_INSTRUCTION &&
           interrupt_stop->guest_rip == (uintptr_t)invalid_code_page + 2 &&
           interrupt_stop->guest_rsp == params.context.rsp,
           "flight interrupt evidence missing event %p int %#llx stop %u rip %#llx rsp %#llx\n",
           interrupt_stop, (unsigned long long)(interrupt_stop ? interrupt_stop->detail0 : 0),
           interrupt_stop ? interrupt_stop->stop_reason : XTAJIT64_FLIGHT_UNKNOWN_U32,
           (unsigned long long)(interrupt_stop ? interrupt_stop->guest_rip : 0),
           (unsigned long long)(interrupt_stop ? interrupt_stop->guest_rsp : 0) );

    binding.recorder = 0;
    status = flight_bind( &binding );
    check( !status, "flight unbind returned %#x\n", (unsigned int)status );
    if (status) goto done;
    binding.recorder = (uintptr_t)recorder2;
    publish_test_flight_boundary( recorder2, &binding, 0x9a18 );
    binding.control_stack_limit = (uintptr_t)recorder2_pages;
    binding.control_stack_top = (uintptr_t)recorder2_pages + 2 * TEST_PAGE;
    status = flight_bind( &binding );
    check( !status && !__atomic_load_n( &recorder2->freeze_state, __ATOMIC_ACQUIRE ),
           "flight rebind to new recorder rejected generation one %#x/%u\n",
           (unsigned int)status,
           __atomic_load_n( &recorder2->freeze_state, __ATOMIC_ACQUIRE ) );
    if (status) goto done;
    /* A redundant standalone bind is a stale publication even though a
     * BeginSimulation retry may legitimately reuse the current boundary. */
    status = flight_bind( &binding );
    check( !status && __atomic_load_n( &recorder2->freeze_state, __ATOMIC_ACQUIRE ) == 1 &&
           __atomic_load_n( &recorder2->freeze_reason, __ATOMIC_ACQUIRE ) ==
           XTAJIT64_FLIGHT_REASON_CONTEXT_STALE_PUBLICATION,
           "flight stale binding generation was not frozen %#x/%u\n",
           (unsigned int)status,
           __atomic_load_n( &recorder2->freeze_reason, __ATOMIC_ACQUIRE ) );

    binding.recorder = 0;
    status = flight_bind( &binding );
    check( !status, "flight unbind before TEB mismatch returned %#x\n", (unsigned int)status );
    if (status) goto done;
    xtajit64_flight_recorder_init( recorder2 );
    binding.recorder = (uintptr_t)recorder2;
    publish_test_flight_boundary( recorder2, &binding, 0x9a18 );
    wrong_teb = unix_teb ^ UINT64_C(0x10);
    binding.claimed_teb = wrong_teb;
    status = flight_bind( &binding );
    check( !status && __atomic_load_n( &recorder2->freeze_state, __ATOMIC_ACQUIRE ) == 1 &&
           __atomic_load_n( &recorder2->freeze_reason, __ATOMIC_ACQUIRE ) ==
           XTAJIT64_FLIGHT_REASON_X18_VALUE,
           "flight wrong PE TEB claim was not frozen %#x/%u\n", (unsigned int)status,
           __atomic_load_n( &recorder2->freeze_reason, __ATOMIC_ACQUIRE ) );
    check( xtajit64_flight_snapshot_first_violation( recorder2, &first_violation ) &&
           first_violation.event_type == XTAJIT64_FLIGHT_EVENT_BINDING &&
           first_violation.reason == XTAJIT64_FLIGHT_REASON_X18_VALUE &&
           first_violation.saved_x18_value == wrong_teb &&
           first_violation.expected_teb == unix_teb &&
           __atomic_load_n( &recorder2->authenticated_teb, __ATOMIC_ACQUIRE ) == unix_teb,
           "flight TEB claim and Unix authority were not independently recorded\n" );

    binding.recorder = 0;
    status = flight_bind( &binding );
    check( !status, "flight unbind before NULL TEB claim returned %#x\n", (unsigned int)status );
    if (status) goto done;
    xtajit64_flight_recorder_init( recorder2 );
    binding.recorder = (uintptr_t)recorder2;
    publish_test_flight_boundary( recorder2, &binding, 0x9a18 );
    binding.claimed_teb = 0;
    status = flight_bind( &binding );
    check( !status && __atomic_load_n( &recorder2->freeze_state, __ATOMIC_ACQUIRE ) == 1 &&
           __atomic_load_n( &recorder2->freeze_reason, __ATOMIC_ACQUIRE ) ==
           XTAJIT64_FLIGHT_REASON_X18_VALUE,
           "flight NULL PE TEB claim was not frozen %#x/%u\n", (unsigned int)status,
           __atomic_load_n( &recorder2->freeze_reason, __ATOMIC_ACQUIRE ) );

done:
    if (thread_initialized) thread_term( NULL );
    if (stack_mapped)
        check( !unregister_identity_page( stack_page ), "flight stack unmap failed\n" );
    if (invalid_code_mapped)
        check( !unregister_identity_page( invalid_code_page ),
               "flight invalid-instruction code unmap failed\n" );
    if (recorder_mapped)
        check( !unregister_identity_range( recorder_pages, 2 * TEST_PAGE ),
               "flight recorder unmap failed\n" );
    if (recorder2_mapped)
        check( !unregister_identity_range( recorder2_pages, 2 * TEST_PAGE ),
               "flight second-recorder unmap failed\n" );
    if (recorder2_pages != MAP_FAILED) munmap( recorder2_pages, 2 * TEST_PAGE );
    if (teb_mapped)
        check( !unregister_identity_page( (void *)(uintptr_t)test_teb ),
               "flight TEB unmap failed\n" );
    if (ec_mapped)
        check( !unregister_identity_page( (void *)(uintptr_t)test_ec_target ),
               "flight EC target unmap failed\n" );
    if (failures == starting_failures) printf( "XTAJIT64_FLIGHT_PROVIDER_BOUNDARY_PASS\n" );
}

static void test_process_init_abi(void)
{
    struct xtajit64_process_init_params invalid = process_params;
    NTSTATUS status;

    check( process_init( NULL ) == STATUS_INVALID_PARAMETER,
           "NULL process init was accepted\n" );
    invalid.abi_version = XTAJIT64_PROCESS_ABI_VERSION - 1;
    status = process_init( &invalid );
    check( status == STATUS_REVISION_MISMATCH,
           "previous ABI version returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.abi_version++;
    status = process_init( &invalid );
    check( status == STATUS_REVISION_MISMATCH,
           "future ABI version returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.abi_size--;
    status = process_init( &invalid );
    check( status == STATUS_REVISION_MISMATCH,
           "wrong ABI size returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.enabled_capabilities = 1;
    status = process_init( &invalid );
    check( status == STATUS_REVISION_MISMATCH,
           "pre-enabled capabilities returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.x64_syscall_count = (1u << 16) + 1;
    status = process_init( &invalid );
    check( status == STATUS_INVALID_PARAMETER,
           "oversized syscall table returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.ec_bitmap++;
    status = process_init( &invalid );
    check( status == STATUS_INVALID_PARAMETER,
           "misaligned EC bitmap returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.highest_user_address = XTAJIT64_X64_USER_ADDRESS_MAX + 1;
    status = process_init( &invalid );
    check( status == STATUS_INVALID_PARAMETER,
           "oversized x64 address space returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.rtl_exit_user_thread = invalid.highest_user_address + 1;
    status = process_init( &invalid );
    check( status == STATUS_INVALID_PARAMETER,
           "out-of-range exit thunk returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.rtl_query_performance_counter = invalid.highest_user_address + 1;
    status = process_init( &invalid );
    check( status == STATUS_INVALID_PARAMETER,
           "out-of-range QPC target returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.nt_query_performance_counter = invalid.highest_user_address + 1;
    status = process_init( &invalid );
    check( status == STATUS_INVALID_PARAMETER,
           "out-of-range raw x64 QPC target returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.x64_syscall_dispatcher = invalid.highest_user_address + 1;
    status = process_init( &invalid );
    check( status == STATUS_INVALID_PARAMETER,
           "out-of-range syscall dispatcher returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.highest_user_address = XTAJIT64_GUEST_KUSER - 1;
    invalid.rtl_exit_user_thread = 1;
    invalid.x64_syscall_dispatcher = 1;
    status = process_init( &invalid );
    check( status == STATUS_INVALID_PARAMETER,
           "out-of-range guest KUSER mapping returned %#x\n", (unsigned int)status );
    invalid = process_params;
    invalid.host_kuser = UINT64_MAX - TEST_PAGE + 1;
    status = process_init( &invalid );
    check( status == STATUS_INVALID_PARAMETER,
           "overflowing host KUSER mapping returned %#x\n", (unsigned int)status );
}

static void test_ec_bitmap_lookup(void)
{
    check( provider.ec_page_shift == 14,
           "EC bitmap page shift is %u instead of 14\n",
           provider.ec_page_shift );
    check( is_ec_code( test_ec_target ),
           "marked EC page start was not recognized\n" );
    check( is_ec_code( test_ec_target + TEST_PAGE - 1 ),
           "marked EC page end was not recognized\n" );
    check( !is_ec_code( test_ec_target + TEST_PAGE ),
           "adjacent non-EC page was recognized as EC code\n" );
    check( !is_ec_code( provider.highest_user_address + 1 ),
           "address above the EC bitmap bound was accepted\n" );
}

static void *run_low_begin_only( void *arg )
{
    struct low_begin_worker *worker = arg;

    worker->status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, worker->event.operation,
        worker->event.host_address, worker->event.size_covered,
        worker->event.host_allocation_base, &worker->transaction );
    atomic_store_explicit( &worker->done, 1, memory_order_release );
    return NULL;
}

static void *run_engine_holder( void *arg )
{
    struct engine_holder *holder = arg;

    holder->status = thread_init( NULL );
    atomic_store_explicit( &holder->ready, 1, memory_order_release );
    while (!atomic_load_explicit( &holder->release, memory_order_acquire ))
    {
        if (!holder->status &&
            atomic_load_explicit( &holder->execute, memory_order_acquire ) &&
            !atomic_load_explicit( &holder->executed, memory_order_relaxed ))
        {
            holder->simulation_status = begin_simulation( &holder->params );
            atomic_store_explicit( &holder->executed, 1, memory_order_release );
            while (atomic_load_explicit( &holder->execute, memory_order_acquire ) &&
                   !atomic_load_explicit( &holder->release, memory_order_relaxed ))
                sched_yield();
            atomic_store_explicit( &holder->executed, 0, memory_order_release );
        }
        sched_yield();
    }
    if (!holder->status) thread_term( NULL );
    atomic_store_explicit( &holder->done, 1, memory_order_release );
    return NULL;
}

static void test_low_observer_validation(void)
{
    struct wine_arm64ec_low_memory_range_v1 range;
    struct wine_arm64ec_low_memory_event_v1 event;
    struct low_begin_worker worker = {0};
    void *transaction, *duplicate, *stale;
    uint64_t generation;
    unsigned int starting_failures = failures;
    pthread_t non_owner;
    BOOL non_owner_created = FALSE, non_owner_done = FALSE;
    int ret;
    NTSTATUS status;

    check( arm64ec_low_memory_observer.version ==
               WINE_ARM64EC_LOW_MEMORY_OBSERVER_VERSION &&
           arm64ec_low_memory_observer.size == sizeof(arm64ec_low_memory_observer) &&
           arm64ec_low_memory_observer.capabilities ==
               WINE_ARM64EC_LOW_MEMORY_OBSERVER_CAP_EXACT_POST_SNAPSHOT,
           "LOW observer descriptor does not advertise the exact v1 ABI\n" );

    transaction = (void *)(uintptr_t)1;
    status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, WINE_WOW64_MEMORY_UNMAP,
        TEST_LOW_HOST_BASE, 0, 0, &transaction );
    check( status == STATUS_INVALID_PARAMETER && !transaction,
           "zero-length LOW begin returned %#x/%p\n",
           (unsigned int)status, transaction );
    transaction = (void *)(uintptr_t)1;
    status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, WINE_WOW64_MEMORY_UNMAP,
        TEST_LOW_HOST_BASE + 1, TEST_PAGE, 0, &transaction );
    check( status == STATUS_INVALID_PARAMETER && !transaction,
           "unaligned LOW begin returned %#x/%p\n",
           (unsigned int)status, transaction );
    transaction = (void *)(uintptr_t)1;
    status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, 0, TEST_LOW_HOST_BASE,
        TEST_PAGE, 0, &transaction );
    check( status == STATUS_INVALID_PARAMETER && !transaction,
           "unknown LOW operation returned %#x/%p\n",
           (unsigned int)status, transaction );

    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE, 0,
                          MEM_FREE, PAGE_NOACCESS );
    initialize_low_event( &event, WINE_WOW64_MEMORY_UNMAP, 0,
                          TEST_LOW_GUEST_BASE, TEST_PAGE, 0, &range, 1,
                          STATUS_SUCCESS, STATUS_SUCCESS );
    transaction = NULL;
    status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, event.operation, event.host_address,
        event.size_covered, event.host_allocation_base, &transaction );
    check( !status && transaction, "LOW bad-size begin failed %#x\n",
           (unsigned int)status );
    event.size--;
    if (!status)
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              transaction, &event );
    check( observer_provider_status() == STATUS_INVALID_PARAMETER,
           "short LOW event did not poison the provider %#x\n",
           (unsigned int)observer_provider_status() );
    check( !reset_test_provider(), "LOW reset after bad size failed\n" );

    initialize_low_event( &event, WINE_WOW64_MEMORY_UNMAP, 0x80000000u,
                          TEST_LOW_GUEST_BASE, TEST_PAGE, 0, &range, 1,
                          STATUS_SUCCESS, STATUS_SUCCESS );
    status = publish_low_event( event.operation, event.flags,
                                TEST_LOW_GUEST_BASE, TEST_PAGE, 0,
                                &range, 1, STATUS_SUCCESS, STATUS_SUCCESS );
    check( status == STATUS_INVALID_PARAMETER,
           "unknown LOW event flags returned %#x\n", (unsigned int)status );
    check( !reset_test_provider(), "LOW reset after bad event flags failed\n" );

    range.flags = 1;
    status = publish_low_event( WINE_WOW64_MEMORY_UNMAP, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE, 0,
                                &range, 1, STATUS_SUCCESS, STATUS_SUCCESS );
    check( status == STATUS_INVALID_PARAMETER,
           "unknown LOW range flags returned %#x\n", (unsigned int)status );
    check( !reset_test_provider(), "LOW reset after bad range flags failed\n" );
    range.flags = 0;

    initialize_low_range( &range, 0, WINE_LOW_VA_SHADOW_SIZE - TEST_PAGE,
                          0, MEM_FREE, PAGE_NOACCESS );
    status = publish_low_event( WINE_WOW64_MEMORY_RESYNC,
                                WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT,
                                0, WINE_LOW_VA_SHADOW_SIZE, 0, &range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( status == STATUS_INVALID_PARAMETER,
           "gapped LOW full snapshot returned %#x\n", (unsigned int)status );
    check( !reset_test_provider(), "LOW reset after gapped snapshot failed\n" );

    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE, 0,
                          MEM_FREE, PAGE_NOACCESS );
    initialize_low_event( &event, WINE_WOW64_MEMORY_UNMAP, 0,
                          TEST_LOW_GUEST_BASE, TEST_PAGE, 0, NULL, 0,
                          STATUS_SUCCESS, STATUS_NO_MEMORY );
    transaction = NULL;
    status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, event.operation, event.host_address,
        event.size_covered, event.host_allocation_base, &transaction );
    if (!status)
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              transaction, &event );
    check( observer_provider_status() == STATUS_NO_MEMORY,
           "failed LOW snapshot did not poison once %#x\n",
           (unsigned int)observer_provider_status() );
    check( !reset_test_provider(), "LOW reset after snapshot failure failed\n" );

    initialize_low_event( &event, WINE_WOW64_MEMORY_UNMAP, 0,
                          TEST_LOW_GUEST_BASE, TEST_PAGE, 0, &range, 1,
                          STATUS_UNSUCCESSFUL, STATUS_SUCCESS );
    transaction = NULL;
    status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, event.operation, event.host_address,
        event.size_covered, event.host_allocation_base, &transaction );
    duplicate = (void *)(uintptr_t)1;
    if (!status)
        status = arm64ec_low_memory_observer.begin(
            arm64ec_low_memory_observer.context, event.operation,
            event.host_address, event.size_covered, event.host_allocation_base,
            &duplicate );
    check( status == STATUS_INVALID_DEVICE_STATE && !duplicate,
           "duplicate LOW mutation owner returned %#x/%p\n",
           (unsigned int)status, duplicate );
    worker.event = event;
    ret = pthread_create( &non_owner, NULL, run_low_begin_only, &worker );
    check( !ret, "non-owner duplicate LOW begin thread creation failed %d\n", ret );
    if (!ret)
    {
        non_owner_created = TRUE;
        non_owner_done = wait_atomic_int_at_least( &worker.done, 1, 2000 );
        check( non_owner_done,
               "non-owner duplicate LOW begin blocked behind the live transaction\n" );
    }
    if (non_owner_created && !non_owner_done)
    {
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              transaction, &event );
        transaction = NULL;
    }
    if (non_owner_created) pthread_join( non_owner, NULL );
    check( !non_owner_created ||
           (worker.status == STATUS_INVALID_DEVICE_STATE && !worker.transaction),
           "non-owner duplicate LOW begin returned %#x/%p\n",
           (unsigned int)worker.status, worker.transaction );
    pthread_mutex_lock( &provider.mutex );
    check( !non_owner_done ||
           (provider.observer_transaction == transaction && provider.mutating),
           "non-owner duplicate LOW begin consumed the live transaction\n" );
    pthread_mutex_unlock( &provider.mutex );
    if (worker.transaction)
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              worker.transaction, &event );
    generation = observer_generation();
    if (transaction)
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              transaction, &event );
    check( !observer_provider_status() && observer_generation() == generation + 1,
           "failed mutation post-snapshot was not completed once %#x\n",
           (unsigned int)observer_provider_status() );

    transaction = NULL;
    status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, event.operation, event.host_address,
        event.size_covered, event.host_allocation_base, &transaction );
    if (!status)
        arm64ec_low_memory_observer.complete(
            arm64ec_low_memory_observer.context, (void *)(uintptr_t)1, &event );
    pthread_mutex_lock( &provider.mutex );
    check( !status && provider.observer_transaction == transaction &&
           provider.mutating,
           "forged LOW completion consumed the active transaction\n" );
    pthread_mutex_unlock( &provider.mutex );
    if (!status)
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              transaction, &event );
    pthread_mutex_lock( &provider.mutex );
    check( provider.poison_status == STATUS_INVALID_DEVICE_STATE &&
           !provider.observer_transaction && !provider.mutating,
           "valid LOW completion did not clean up after forged rejection\n" );
    pthread_mutex_unlock( &provider.mutex );
    check( !reset_test_provider(), "LOW reset after forged completion failed\n" );

    transaction = NULL;
    status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, event.operation, event.host_address,
        event.size_covered, event.host_allocation_base, &transaction );
    stale = transaction;
    if (!status)
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              transaction, &event );
    check( !observer_provider_status(), "valid LOW completion poisoned provider\n" );
    arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                          stale, &event );
    check( observer_provider_status() == STATUS_INVALID_DEVICE_STATE,
           "stale LOW token was not rejected without dereference %#x\n",
           (unsigned int)observer_provider_status() );
    check( !reset_test_provider(), "LOW reset after stale token failed\n" );
    if (failures == starting_failures)
        printf( "XTAJIT64_LOW_OBSERVER_VALIDATION_PASS\n" );
}

static void test_low_observer_interval_replacement(void)
{
    struct wine_arm64ec_low_memory_range_v1 full[3], range;
    struct xtajit64_memory_translate_params translate;
    struct xtajit64_memory_resync_begin_params begin;
    struct xtajit64_memory_resync_params resync;
    struct xtajit64_memory_params legacy;
    uint64_t generation;
    unsigned int starting_failures = failures;
    NTSTATUS status;

    check( (uintptr_t)test_low_pages == TEST_LOW_HOST_BASE,
           "LOW observer host pages are unavailable at the authoritative shadow\n" );
    if ((uintptr_t)test_low_pages != TEST_LOW_HOST_BASE) return;

    initialize_low_range( &full[0], 0, TEST_LOW_GUEST_BASE, 0,
                          MEM_FREE, PAGE_NOACCESS );
    initialize_low_range( &full[1], TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READWRITE );
    initialize_low_range( &full[2], TEST_LOW_GUEST_BASE + TEST_PAGE,
                          WINE_LOW_VA_SHADOW_SIZE - TEST_LOW_GUEST_BASE - TEST_PAGE,
                          0, MEM_FREE, PAGE_NOACCESS );
    status = publish_low_event( WINE_WOW64_MEMORY_RESYNC,
                                WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT,
                                0, WINE_LOW_VA_SHADOW_SIZE, 0, full, 3,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT,
               UC_PROT_READ | UC_PROT_WRITE,
               XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ) &&
           canonical_range_matches( XTAJIT64_GUEST_KUSER,
                                    (uintptr_t)test_kuser, MEM_COMMIT,
                                    UC_PROT_READ,
                                    XTAJIT64_MEMORY_ADDRESS_INVALID, TRUE ),
           "initial LOW full snapshot lost mapping or non-LOW KUSER %#x\n",
           (unsigned int)status );

    memset( &translate, 0, sizeof(translate) );
    translate.address = TEST_LOW_GUEST_BASE + 37;
    translate.size = 32;
    translate.flags = XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST |
                      XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE;
    status = memory_translate( &translate );
    check( !status && translate.host == TEST_LOW_HOST_BASE + 37 &&
           translate.allocation_base == TEST_LOW_GUEST_BASE &&
           translate.domain == XTAJIT64_MEMORY_ADDRESS_AMD64_LOW,
           "LOW address codec returned %#x %#llx/%#llx/%u\n",
           (unsigned int)status, (unsigned long long)translate.host,
           (unsigned long long)translate.allocation_base, translate.domain );

    memset( &legacy, 0, sizeof(legacy) );
    legacy.guest = TEST_LOW_GUEST_BASE;
    legacy.size = TEST_PAGE;
    legacy.protect = PAGE_READONLY;
    check( memory_protect( &legacy ) == STATUS_ACCESS_DENIED &&
           memory_unmap( &legacy ) == STATUS_ACCESS_DENIED,
           "legacy mutation changed LOW-owned state\n" );

    memset( &legacy, 0, sizeof(legacy) );
    legacy.guest = TEST_LOW_HOST_BASE;
    legacy.host = TEST_LOW_HOST_BASE;
    legacy.size = TEST_PAGE;
    legacy.allocation_base = TEST_LOW_HOST_BASE;
    legacy.protect = PAGE_READONLY;
    check( memory_map( &legacy ) == STATUS_ACCESS_DENIED &&
           memory_protect( &legacy ) == STATUS_ACCESS_DENIED &&
           memory_unmap( &legacy ) == STATUS_ACCESS_DENIED,
           "host-address legacy mutation changed LOW-owned state\n" );
    legacy.size = 0;
    check( memory_unmap( &legacy ) == STATUS_ACCESS_DENIED,
           "host-allocation legacy unmap changed LOW-owned state\n" );
    puts( "XTAJIT64_LOW_LEGACY_HOST_SKIP_PASS" );

    status = memory_resync_begin( &begin );
    memset( &resync, 0, sizeof(resync) );
    resync.generation = begin.generation;
    if (!status) status = memory_resync( &resync );
    check( !status && canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT,
               UC_PROT_READ | UC_PROT_WRITE,
               XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "identity resync replaced LOW ownership %#x\n", (unsigned int)status );

    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READONLY );
    status = publish_low_event( WINE_WOW64_MEMORY_PROTECT, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE,
                                TEST_LOW_GUEST_BASE, &range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT,
               UC_PROT_READ, XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "LOW protect interval replacement failed %#x\n", (unsigned int)status );

    generation = observer_generation();
    range.protect = PAGE_READWRITE;
    status = publish_low_event( WINE_WOW64_MEMORY_PROTECT, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE,
                                TEST_LOW_GUEST_BASE, &range, 1,
                                STATUS_ACCESS_DENIED, STATUS_SUCCESS );
    check( !status && observer_generation() == generation + 1 &&
           canonical_range_matches( TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE,
                                    MEM_COMMIT, UC_PROT_READ | UC_PROT_WRITE,
                                    XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "failed LOW mutation did not publish exact post-state %#x\n",
           (unsigned int)status );

    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_RESERVE, 0 );
    status = publish_low_event( WINE_WOW64_MEMORY_DECOMMIT, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE,
                                TEST_LOW_GUEST_BASE, &range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_RESERVE,
               UC_PROT_NONE, XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "LOW decommit interval replacement failed %#x\n", (unsigned int)status );

    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_EXECUTE_READ );
    status = publish_low_event( WINE_WOW64_MEMORY_COMMIT, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE,
                                TEST_LOW_GUEST_BASE, &range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT,
               UC_PROT_READ | UC_PROT_EXEC,
               XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "LOW commit interval replacement failed %#x\n", (unsigned int)status );

    initialize_low_range( &full[0], 0, TEST_LOW_GUEST_BASE + TEST_PAGE, 0,
                          MEM_FREE, PAGE_NOACCESS );
    initialize_low_range( &full[1], TEST_LOW_GUEST_BASE + TEST_PAGE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE + TEST_PAGE, MEM_RESERVE, 0 );
    initialize_low_range( &full[2], TEST_LOW_GUEST_BASE + 2 * TEST_PAGE,
                          WINE_LOW_VA_SHADOW_SIZE - TEST_LOW_GUEST_BASE - 2 * TEST_PAGE,
                          0, MEM_FREE, PAGE_NOACCESS );
    status = publish_low_event( WINE_WOW64_MEMORY_PROTECT,
                                WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT,
                                0, WINE_LOW_VA_SHADOW_SIZE, 0, full, 3,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && !canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT,
               UC_PROT_READ | UC_PROT_EXEC,
               XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ) &&
           canonical_range_matches( TEST_LOW_GUEST_BASE + TEST_PAGE,
                                    TEST_LOW_HOST_BASE + TEST_PAGE, MEM_RESERVE,
                                    UC_PROT_NONE,
                                    XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ) &&
           canonical_range_matches( XTAJIT64_GUEST_KUSER,
                                    (uintptr_t)test_kuser, MEM_COMMIT,
                                    UC_PROT_READ,
                                    XTAJIT64_MEMORY_ADDRESS_INVALID, TRUE ),
           "nested LOW full snapshot was not authoritative %#x\n",
           (unsigned int)status );

    initialize_low_range( &range, 0, WINE_LOW_VA_SHADOW_SIZE, 0,
                          MEM_FREE, PAGE_NOACCESS );
    status = publish_low_event( WINE_WOW64_MEMORY_RESYNC,
                                WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT,
                                0, WINE_LOW_VA_SHADOW_SIZE, 0, &range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && !canonical_range_matches(
               TEST_LOW_GUEST_BASE + TEST_PAGE, TEST_LOW_HOST_BASE + TEST_PAGE,
               MEM_RESERVE, UC_PROT_NONE,
               XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "LOW full free snapshot retained stale ownership %#x\n",
           (unsigned int)status );
    if (failures == starting_failures)
        printf( "XTAJIT64_LOW_OBSERVER_INTERVAL_PASS\n" );
}

static void test_low_observer_lazy_engine_sync(void)
{
    unsigned char *code_page = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct code_buffer code = { .data = code_page };
    struct wine_arm64ec_low_memory_range_v1 range;
    struct engine_holder holders[2] = {0};
    struct xtajit64_poison_params timeout = { .status = STATUS_TIMEOUT };
    pthread_t threads[2];
    BOOL created[2] = {FALSE, FALSE};
    unsigned int starting_failures = failures;
    unsigned int emu_start_count;
    NTSTATUS status;
    int i, ret;

    emit_movabs_rax( &code, TEST_LOW_GUEST_BASE );
    emit_u8( &code, 0x48 ); emit_u8( &code, 0x8b ); emit_u8( &code, 0x00 );
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );

    status = register_identity_page( (void *)(uintptr_t)test_ec_target,
                                     PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( code_page, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    if (!status) status = register_identity_page( (void *)(uintptr_t)test_teb,
                                                  PAGE_READWRITE );
    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READWRITE );
    if (!status)
        status = publish_low_event( WINE_WOW64_MEMORY_ALLOCATE, 0,
                                    TEST_LOW_GUEST_BASE, TEST_PAGE,
                                    TEST_LOW_GUEST_BASE, &range, 1,
                                    STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status, "lazy LOW synchronization setup failed %#x\n",
           (unsigned int)status );
    if (status) goto done;

    for (i = 0; i < 2; ++i)
    {
        initialize_begin_parameters( &holders[i].params, (uintptr_t)code_page,
                                     (uintptr_t)stack );
        ret = pthread_create( &threads[i], NULL, run_engine_holder, &holders[i] );
        check( !ret, "lazy LOW holder %d creation failed %d\n", i, ret );
        if (!ret) created[i] = TRUE;
    }
    for (i = 0; i < 2; ++i)
    {
        if (!created[i]) continue;
        check( wait_atomic_int_at_least( &holders[i].ready, 1, 5000 ),
               "lazy LOW holder %d did not initialize\n", i );
        check( !holders[i].status, "lazy LOW holder %d init failed %#x\n", i,
               (unsigned int)holders[i].status );
    }
    if (!created[0] || !created[1] || holders[0].status || holders[1].status)
        goto release;

    /* Exercise two Windows threads sequentially.  They must retain independent
     * CPU contexts while borrowing one idle engine and one mapping topology. */
    for (i = 0; i < 2; ++i)
    {
        atomic_store_explicit( &holders[i].execute, 1, memory_order_release );
        if (!wait_atomic_int_at_least( &holders[i].executed, 1, 5000 ))
        {
            check( FALSE, "initial lazy LOW engine %d did not execute\n", i );
            poison( &timeout );
            goto release;
        }
        check( !holders[i].simulation_status &&
               holders[i].params.stop_reason == XTAJIT64_STOP_EC_TRANSITION,
               "initial lazy LOW engine %d returned %#x reason %u\n", i,
               (unsigned int)holders[i].simulation_status,
               holders[i].params.stop_reason );
        atomic_store_explicit( &holders[i].execute, 0, memory_order_release );
        check( wait_atomic_int_equal( &holders[i].executed, 0, 5000 ),
               "initial lazy LOW engine %d did not rearm\n", i );
        initialize_begin_parameters( &holders[i].params, (uintptr_t)code_page,
                                     (uintptr_t)stack );
    }
    check( provider_engine_count() == 1,
           "sequential LOW holders retained %zu pooled engines\n",
           provider_engine_count() );

    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READONLY );
    status = publish_low_event( WINE_WOW64_MEMORY_PROTECT, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE,
                                TEST_LOW_GUEST_BASE, &range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && !memory_map_calls && !memory_unmap_calls &&
           !cache_flush_calls && canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT, UC_PROT_READ,
               XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "LOW publication eagerly touched engines %#x %u/%u/%u\n",
           (unsigned int)status, memory_map_calls, memory_unmap_calls,
           cache_flush_calls );
    if (status) goto release;

    emu_start_count = atomic_load_explicit( &test_emu_start_count,
                                            memory_order_relaxed );
    atomic_store_explicit( &holders[0].execute, 1, memory_order_release );
    if (!wait_atomic_int_at_least( &holders[0].executed, 1, 5000 ))
    {
        check( FALSE, "first lazy LOW engine did not execute\n" );
        poison( &timeout );
        goto release;
    }
    check( !holders[0].simulation_status &&
           holders[0].params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           memory_map_calls == 1 && memory_unmap_calls == 1 &&
           !cache_flush_calls &&
           atomic_load_explicit( &test_emu_start_count, memory_order_relaxed ) ==
               emu_start_count + 1,
           "first lazy LOW engine returned %#x reason %u map/unmap/flush %u/%u/%u\n",
           (unsigned int)holders[0].simulation_status,
           holders[0].params.stop_reason, memory_map_calls, memory_unmap_calls,
           cache_flush_calls );

    atomic_store_explicit( &holders[1].execute, 1, memory_order_release );
    if (!wait_atomic_int_at_least( &holders[1].executed, 1, 5000 ))
    {
        check( FALSE, "second lazy LOW engine did not execute\n" );
        poison( &timeout );
        goto release;
    }
    check( !holders[1].simulation_status &&
           holders[1].params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           memory_map_calls == 1 && memory_unmap_calls == 1 &&
           !cache_flush_calls && provider_engine_count() == 1 &&
           atomic_load_explicit( &test_emu_start_count, memory_order_relaxed ) ==
               emu_start_count + 2,
           "second sequential LOW borrower returned %#x reason %u map/unmap/flush %u/%u/%u engines %zu\n",
           (unsigned int)holders[1].simulation_status,
           holders[1].params.stop_reason, memory_map_calls, memory_unmap_calls,
           cache_flush_calls, provider_engine_count() );

release:
    for (i = 0; i < 2; ++i)
        atomic_store_explicit( &holders[i].release, 1, memory_order_release );
    for (i = 0; i < 2; ++i)
    {
        if (!created[i]) continue;
        check( wait_atomic_int_at_least( &holders[i].done, 1, 5000 ),
               "lazy LOW holder %d did not terminate\n", i );
        pthread_join( threads[i], NULL );
    }
done:
    memory_map_fail_call = memory_unmap_fail_call = -1;
    check( !reset_test_provider(), "reset after lazy LOW synchronization failed\n" );
    if (failures == starting_failures)
        printf( "XTAJIT64_LOW_OBSERVER_LAZY_SYNC_PASS\n" );
}

static void test_low_observer_lazy_sync_poison(void)
{
    unsigned char *code_page = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct code_buffer code = { .data = code_page };
    struct wine_arm64ec_low_memory_range_v1 range;
    struct engine_holder holder = {0};
    struct xtajit64_poison_params timeout = { .status = STATUS_TIMEOUT };
    pthread_t thread;
    BOOL created = FALSE;
    uint64_t generation;
    unsigned int starting_failures = failures;
    unsigned int emu_start_count;
    NTSTATUS status;
    int ret;

    emit_movabs_rax( &code, TEST_LOW_GUEST_BASE );
    emit_u8( &code, 0x48 ); emit_u8( &code, 0x8b ); emit_u8( &code, 0x00 );
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );

    status = register_identity_page( (void *)(uintptr_t)test_ec_target,
                                     PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( code_page, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    if (!status) status = register_identity_page( (void *)(uintptr_t)test_teb,
                                                  PAGE_READWRITE );
    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READWRITE );
    if (!status)
        status = publish_low_event( WINE_WOW64_MEMORY_ALLOCATE, 0,
                                    TEST_LOW_GUEST_BASE, TEST_PAGE,
                                    TEST_LOW_GUEST_BASE, &range, 1,
                                    STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status, "lazy-sync poison setup failed %#x\n", (unsigned int)status );
    if (status) goto done;

    initialize_begin_parameters( &holder.params, (uintptr_t)code_page,
                                 (uintptr_t)stack );
    ret = pthread_create( &thread, NULL, run_engine_holder, &holder );
    check( !ret, "lazy-sync poison holder creation failed %d\n", ret );
    if (ret) goto done;
    created = TRUE;
    check( wait_atomic_int_at_least( &holder.ready, 1, 5000 ),
           "lazy-sync poison holder did not initialize\n" );
    check( !holder.status, "lazy-sync poison holder init failed %#x\n",
           (unsigned int)holder.status );
    if (holder.status) goto release;

    atomic_store_explicit( &holder.execute, 1, memory_order_release );
    if (!wait_atomic_int_at_least( &holder.executed, 1, 5000 ))
    {
        check( FALSE, "lazy-sync poison holder did not fault in LOW mapping\n" );
        poison( &timeout );
        goto release;
    }
    check( !holder.simulation_status &&
           holder.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION,
           "lazy-sync poison setup execution returned %#x reason %u\n",
           (unsigned int)holder.simulation_status, holder.params.stop_reason );
    atomic_store_explicit( &holder.execute, 0, memory_order_release );
    check( wait_atomic_int_equal( &holder.executed, 0, 5000 ),
           "lazy-sync poison holder did not rearm\n" );
    initialize_begin_parameters( &holder.params, (uintptr_t)code_page,
                                 (uintptr_t)stack );

    generation = observer_generation();
    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READONLY );
    status = publish_low_event( WINE_WOW64_MEMORY_PROTECT, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE,
                                TEST_LOW_GUEST_BASE, &range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && observer_generation() == generation + 1 &&
           !memory_map_calls && !memory_unmap_calls && !cache_flush_calls,
           "lazy-sync poison publication failed %#x generation %llu calls %u/%u/%u\n",
           (unsigned int)status,
           (unsigned long long)observer_generation(), memory_map_calls,
           memory_unmap_calls, cache_flush_calls );
    if (status) goto release;

    memory_map_fail_call = 0;
    emu_start_count = atomic_load_explicit( &test_emu_start_count,
                                            memory_order_relaxed );
    atomic_store_explicit( &holder.execute, 1, memory_order_release );
    if (!wait_atomic_int_at_least( &holder.executed, 1, 5000 ))
    {
        check( FALSE, "failing lazy LOW engine did not return\n" );
        poison( &timeout );
        goto release;
    }
    check( holder.simulation_status == STATUS_UNSUCCESSFUL &&
           holder.params.stop_reason == XTAJIT64_STOP_INTERNAL_ERROR &&
           holder.params.unicorn_error == UC_ERR_RESOURCE &&
           observer_provider_status() == STATUS_UNSUCCESSFUL,
           "lazy LOW sync failure did not poison provider %#x reason %u uc %u/%#x\n",
           (unsigned int)holder.simulation_status, holder.params.stop_reason,
           holder.params.unicorn_error, (unsigned int)observer_provider_status() );
    check( memory_map_calls == 1 && memory_unmap_calls == 1 &&
           !cache_flush_calls &&
           atomic_load_explicit( &test_emu_start_count, memory_order_relaxed ) ==
               emu_start_count + 1,
           "failed demand map had wrong execution or map/unmap/flush calls %u/%u/%u\n",
           memory_map_calls, memory_unmap_calls, cache_flush_calls );
    check( canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT, UC_PROT_READ,
               XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "failed lazy LOW sync corrupted the canonical registry\n" );
    check( thread_init( NULL ) == STATUS_UNSUCCESSFUL,
           "lazy-sync-poisoned provider accepted a future engine\n" );
    thread_term( NULL );

release:
    memory_map_fail_call = memory_unmap_fail_call = -1;
    atomic_store_explicit( &holder.release, 1, memory_order_release );
    if (created)
    {
        check( wait_atomic_int_at_least( &holder.done, 1, 5000 ),
               "lazy-sync poison holder did not terminate\n" );
        pthread_join( thread, NULL );
    }
done:
    memory_map_fail_call = memory_unmap_fail_call = -1;
    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    check( !reset_test_provider(), "reset after lazy-sync poison failed\n" );
    if (failures == starting_failures)
        printf( "XTAJIT64_LOW_OBSERVER_LAZY_POISON_PASS\n" );
}

static void test_low_flush_multi_engine_poison(void)
{
    struct wine_arm64ec_low_memory_range_v1 range;
    struct xtajit64_memory_params targeted =
    {
        .guest = TEST_LOW_GUEST_BASE + 0x40,
        .size = 0x80,
    };
    struct xtajit64_memory_params full = {0};
    struct xtajit64_memory_params empty =
    {
        .guest = TEST_LOW_GUEST_BASE,
    };
    struct xtajit64_memory_params unmapped =
    {
        .guest = TEST_LOW_GUEST_BASE + 2 * TEST_PAGE,
        .size = 0x80,
    };
    struct engine_holder holders[2] = {0};
    pthread_t threads[2];
    BOOL created[2] = {FALSE, FALSE};
    uint64_t generation;
    unsigned int starting_failures = failures;
    NTSTATUS status;
    uc_err engine_err;
    int i, ret;

    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READONLY );
    status = publish_low_event( WINE_WOW64_MEMORY_ALLOCATE, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE,
                                TEST_LOW_GUEST_BASE, &range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT,
               UC_PROT_READ, XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "LOW cache-flush setup failed %#x\n", (unsigned int)status );
    if (status) goto done;

    for (i = 0; i < 2; ++i)
    {
        ret = pthread_create( &threads[i], NULL, run_engine_holder, &holders[i] );
        check( !ret, "LOW cache-flush holder %d creation failed %d\n", i, ret );
        if (!ret) created[i] = TRUE;
    }
    for (i = 0; i < 2; ++i)
    {
        if (!created[i]) continue;
        check( wait_atomic_int_at_least( &holders[i].ready, 1, 5000 ),
               "LOW cache-flush holder %d did not initialize\n", i );
        check( !holders[i].status,
               "LOW cache-flush holder %d init failed %#x\n", i,
               (unsigned int)holders[i].status );
    }
    if (!created[0] || !created[1] || holders[0].status || holders[1].status)
        goto release;

    /* Cache invalidation is process-wide over every pooled topology.  Create a
     * second idle topology explicitly; simultaneous borrowing is covered by
     * test_concurrent_engines(). */
    pthread_mutex_lock( &provider.mutex );
    engine_err = create_pool_engine_locked( NULL );
    pthread_mutex_unlock( &provider.mutex );
    check( engine_err == UC_ERR_OK && provider_engine_count() == 2,
           "LOW cache-flush pool setup returned %s with %zu engines\n",
           uc_strerror( engine_err ), provider_engine_count() );
    if (engine_err != UC_ERR_OK) goto release;

    reset_cache_recorders();
    status = flush_instruction_cache( &targeted );
    check( !status && cache_remove_calls == 2 && !cache_flush_calls,
           "LOW guest cache flush returned %#x remove/full %u/%u\n",
           (unsigned int)status, cache_remove_calls, cache_flush_calls );
    for (i = 0; i < 2 && i < cache_remove_calls; ++i)
        check( cache_remove_records[i].start == targeted.guest &&
               cache_remove_records[i].end == targeted.guest + targeted.size,
               "LOW guest cache interval %d was %#llx-%#llx\n", i,
               (unsigned long long)cache_remove_records[i].start,
               (unsigned long long)cache_remove_records[i].end );
    check( cache_remove_calls < 2 ||
           cache_remove_records[0].engine != cache_remove_records[1].engine,
           "LOW guest cache flush reused one engine\n" );

    reset_cache_recorders();
    targeted.guest = TEST_LOW_HOST_BASE + 0x40;
    status = flush_instruction_cache( &targeted );
    check( !status && cache_remove_calls == 2 && !cache_flush_calls,
           "LOW host cache flush returned %#x remove/full %u/%u\n",
           (unsigned int)status, cache_remove_calls, cache_flush_calls );
    for (i = 0; i < 2 && i < cache_remove_calls; ++i)
        check( cache_remove_records[i].start == TEST_LOW_GUEST_BASE + 0x40 &&
               cache_remove_records[i].end == TEST_LOW_GUEST_BASE + 0xc0,
               "LOW host cache interval %d was %#llx-%#llx\n", i,
               (unsigned long long)cache_remove_records[i].start,
               (unsigned long long)cache_remove_records[i].end );

    reset_cache_recorders();
    status = flush_instruction_cache( &full );
    check( !status && !cache_remove_calls && cache_flush_calls == 2 &&
           cache_flush_engines[0] != cache_flush_engines[1],
           "NULL/zero full flush returned %#x remove/full %u/%u\n",
           (unsigned int)status, cache_remove_calls, cache_flush_calls );

    reset_cache_recorders();
    full.size = 0x1234;
    status = flush_instruction_cache( &full );
    check( !status && !cache_remove_calls && cache_flush_calls == 2 &&
           cache_flush_engines[0] != cache_flush_engines[1],
           "NULL/nonzero full flush returned %#x remove/full %u/%u\n",
           (unsigned int)status, cache_remove_calls, cache_flush_calls );

    reset_cache_recorders();
    status = flush_instruction_cache( &empty );
    check( !status && !cache_remove_calls && !cache_flush_calls,
           "non-NULL/zero empty flush returned %#x remove/full %u/%u\n",
           (unsigned int)status, cache_remove_calls, cache_flush_calls );

    reset_cache_recorders();
    status = flush_instruction_cache( &unmapped );
    check( !status && !cache_remove_calls && !cache_flush_calls,
           "unmapped targeted flush returned %#x remove/full %u/%u\n",
           (unsigned int)status, cache_remove_calls, cache_flush_calls );

    generation = observer_generation();
    reset_cache_recorders();
    targeted.guest = TEST_LOW_GUEST_BASE + 0x40;
    cache_remove_fail_call = 1;
    status = flush_instruction_cache( &targeted );
    cache_remove_fail_call = -1;
    check( status == STATUS_UNSUCCESSFUL && cache_remove_calls == 2 &&
           observer_provider_status() == STATUS_UNSUCCESSFUL,
           "partial LOW cache flush did not poison provider %#x/%#x calls %u\n",
           (unsigned int)status, (unsigned int)observer_provider_status(),
           cache_remove_calls );
    check( observer_generation() == generation && canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT,
               UC_PROT_READ, XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "partial LOW cache flush changed the canonical registry\n" );
    pthread_mutex_lock( &provider.mutex );
    check( !provider.mutating && !provider.mutation_owner_valid &&
           provider.mutation_stage == MUTATION_STAGE_IDLE &&
           !provider.observer_transaction,
           "partial LOW cache flush retained mutation ownership\n" );
    pthread_mutex_unlock( &provider.mutex );
    check( thread_init( NULL ) == STATUS_UNSUCCESSFUL,
           "cache-flush-poisoned provider accepted a future engine\n" );
    thread_term( NULL );

release:
    cache_remove_fail_call = -1;
    for (i = 0; i < 2; ++i)
        atomic_store_explicit( &holders[i].release, 1, memory_order_release );
    for (i = 0; i < 2; ++i)
    {
        if (!created[i]) continue;
        check( wait_atomic_int_at_least( &holders[i].done, 1, 5000 ),
               "LOW cache-flush holder %d did not terminate\n", i );
        pthread_join( threads[i], NULL );
    }
done:
    reset_cache_recorders();
    check( !reset_test_provider(), "LOW reset after cache-flush poison failed\n" );
    if (failures == starting_failures)
        printf( "XTAJIT64_LOW_FLUSH_MULTI_ENGINE_PASS\n" );
}

static void test_code_observer_invalidation(void)
{
    struct wine_arm64ec_code_range_v1 ranges[2] =
    {
        {0, TEST_PAGE},
        {0, TEST_PAGE},
    };
    struct wine_arm64ec_code_event_v1 event;
    void *transaction = NULL, *stale;
    uint64_t generation;
    unsigned int starting_failures = failures;
    uc_err engine_err = UC_ERR_OK;
    NTSTATUS status;
    size_t i;

    ranges[0].address = test_base + 4 * TEST_PAGE;
    ranges[1].address = test_base + 6 * TEST_PAGE;
    check( arm64ec_code_observer.version == WINE_ARM64EC_CODE_OBSERVER_VERSION &&
           arm64ec_code_observer.size == sizeof(arm64ec_code_observer) &&
           arm64ec_code_observer.capabilities ==
               WINE_ARM64EC_CODE_OBSERVER_CAP_EXACT_INVALIDATION_RANGES,
           "code observer descriptor does not advertise the exact v1 ABI\n" );
    check( provider.code_observer_active,
           "code observer was not activated by its registration resync\n" );

    transaction = (void *)(uintptr_t)1;
    status = arm64ec_code_observer.begin( arm64ec_code_observer.context,
                                          UINT32_MAX, &transaction );
    check( status == STATUS_INVALID_PARAMETER && !transaction,
           "unknown code operation returned %#x/%p\n",
           (unsigned int)status, transaction );
    status = arm64ec_code_observer.begin( arm64ec_code_observer.context,
                                          WINE_ARM64EC_CODE_MAP, NULL );
    check( status == STATUS_INVALID_PARAMETER,
           "NULL code transaction output returned %#x\n", (unsigned int)status );

    pthread_mutex_lock( &provider.mutex );
    while (provider.engine_count < 2 && engine_err == UC_ERR_OK)
        engine_err = create_pool_engine_locked( NULL );
    pthread_mutex_unlock( &provider.mutex );
    check( engine_err == UC_ERR_OK && provider_engine_count() == 2,
           "code observer pool setup returned %s with %zu engines\n",
           uc_strerror( engine_err ), provider_engine_count() );
    if (engine_err != UC_ERR_OK || provider_engine_count() != 2) goto done;

    generation = observer_generation();
    reset_cache_recorders();
    status = publish_code_event( WINE_ARM64EC_CODE_ALLOCATE, 0, ranges,
                                 ARRAY_SIZE(ranges), STATUS_UNSUCCESSFUL );
    check( !status && observer_generation() == generation &&
           tlb_flush_calls == 2 && cache_remove_calls == 4 &&
           !cache_flush_calls,
           "exact code invalidation returned %#x generation %#llx/%#llx "
           "TLB/remove/full %u/%u/%u\n", (unsigned int)status,
           (unsigned long long)observer_generation(),
           (unsigned long long)generation, tlb_flush_calls,
           cache_remove_calls, cache_flush_calls );
    for (i = 0; i < cache_remove_calls && i < CACHE_RECORD_LIMIT; ++i)
    {
        const struct wine_arm64ec_code_range_v1 *range = &ranges[i & 1];

        check( cache_remove_records[i].start == range->address &&
               cache_remove_records[i].end == range->address + range->size,
               "exact code interval %zu was %#llx-%#llx\n", i,
               (unsigned long long)cache_remove_records[i].start,
               (unsigned long long)cache_remove_records[i].end );
    }
    check( cache_remove_calls < 4 ||
           cache_remove_records[0].engine != cache_remove_records[2].engine,
           "exact code invalidation reused one engine\n" );
    check( tlb_flush_calls < 2 || tlb_flush_engines[0] != tlb_flush_engines[1],
           "exact code invalidation flushed one engine TLB twice\n" );

    reset_cache_recorders();
    status = publish_code_event( WINE_ARM64EC_CODE_MAP, 0, NULL, 0,
                                 STATUS_SUCCESS );
    check( !status && !tlb_flush_calls && !cache_remove_calls &&
           !cache_flush_calls,
           "empty code event returned %#x with TLB/remove/full %u/%u/%u\n",
           (unsigned int)status, tlb_flush_calls, cache_remove_calls,
           cache_flush_calls );

    reset_cache_recorders();
    status = publish_code_event( WINE_ARM64EC_CODE_RESYNC,
                                 WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION,
                                 NULL, 0, STATUS_UNSUCCESSFUL );
    check( !status && !tlb_flush_calls && !cache_remove_calls &&
           cache_flush_calls == 2 &&
           cache_flush_engines[0] != cache_flush_engines[1],
           "full code invalidation returned %#x with TLB/remove/full %u/%u/%u\n",
           (unsigned int)status, tlb_flush_calls, cache_remove_calls,
           cache_flush_calls );

    status = publish_code_event( WINE_ARM64EC_CODE_MAP,
                                 WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION,
                                 ranges, 1, STATUS_SUCCESS );
    check( status == STATUS_INVALID_PARAMETER,
           "full code event with ranges returned %#x\n", (unsigned int)status );
    check( !reset_test_provider(), "code reset after full/range conflict failed\n" );

    ranges[1].address = ranges[0].address + ranges[0].size;
    status = publish_code_event( WINE_ARM64EC_CODE_MAP, 0, ranges,
                                 ARRAY_SIZE(ranges), STATUS_SUCCESS );
    check( status == STATUS_INVALID_PARAMETER,
           "unmerged adjacent code ranges returned %#x\n", (unsigned int)status );
    check( !reset_test_provider(), "code reset after adjacent ranges failed\n" );
    ranges[1].address = test_base + 6 * TEST_PAGE;

    ranges[0].address++;
    status = publish_code_event( WINE_ARM64EC_CODE_MAP, 0, ranges, 1,
                                 STATUS_SUCCESS );
    check( status == STATUS_INVALID_PARAMETER,
           "misaligned code range returned %#x\n", (unsigned int)status );
    check( !reset_test_provider(), "code reset after misaligned range failed\n" );
    --ranges[0].address;

    initialize_code_event( &event, WINE_ARM64EC_CODE_UNMAP, 0, NULL, 0,
                           STATUS_SUCCESS );
    status = arm64ec_code_observer.begin( arm64ec_code_observer.context,
                                          event.operation, &transaction );
    stale = transaction;
    if (!status)
        arm64ec_code_observer.complete( arm64ec_code_observer.context,
                                        transaction, &event );
    check( !observer_provider_status(), "valid code completion poisoned provider\n" );
    arm64ec_code_observer.complete( arm64ec_code_observer.context, stale, &event );
    check( observer_provider_status() == STATUS_INVALID_DEVICE_STATE,
           "stale code token was not rejected without dereference %#x\n",
           (unsigned int)observer_provider_status() );
    check( !reset_test_provider(), "code reset after stale token failed\n" );

    pthread_mutex_lock( &provider.mutex );
    while (provider.engine_count < 2 && engine_err == UC_ERR_OK)
        engine_err = create_pool_engine_locked( NULL );
    pthread_mutex_unlock( &provider.mutex );
    check( engine_err == UC_ERR_OK && provider_engine_count() == 2,
           "code failure pool setup returned %s with %zu engines\n",
           uc_strerror( engine_err ), provider_engine_count() );
    if (engine_err != UC_ERR_OK || provider_engine_count() != 2) goto done;
    reset_cache_recorders();
    cache_remove_fail_call = 1;
    status = publish_code_event( WINE_ARM64EC_CODE_RELEASE, 0, ranges, 1,
                                 STATUS_SUCCESS );
    cache_remove_fail_call = -1;
    check( status == STATUS_UNSUCCESSFUL && tlb_flush_calls == 2 &&
           cache_remove_calls == 2 &&
           observer_provider_status() == STATUS_UNSUCCESSFUL,
           "partial code invalidation did not poison provider %#x/%#x "
           "TLB/remove %u/%u\n", (unsigned int)status,
           (unsigned int)observer_provider_status(), tlb_flush_calls,
           cache_remove_calls );
    pthread_mutex_lock( &provider.mutex );
    check( !provider.mutating && !provider.mutation_owner_valid &&
           provider.mutation_stage == MUTATION_STAGE_IDLE &&
           !provider.code_observer_transaction,
           "partial code invalidation retained mutation ownership\n" );
    pthread_mutex_unlock( &provider.mutex );

done:
    reset_cache_recorders();
    check( !reset_test_provider(), "code observer final reset failed\n" );
    if (failures == starting_failures)
        printf( "XTAJIT64_CODE_OBSERVER_INVALIDATION_PASS\n" );
}

static void test_identity_codec(void)
{
    unsigned char *page = test_pages + 3 * TEST_PAGE;
    struct xtajit64_memory_translate_params translate;
    struct xtajit64_memory_params protect =
    {
        .guest = (uintptr_t)page,
        .size = TEST_PAGE,
        .protect = PAGE_READONLY,
    };
    const uint8_t owner = 7u << UC_SWITCHYARD_IDENTITY_PAGE_OWNER_SHIFT;
    const size_t page_index = (uintptr_t)page >>
                              UC_SWITCHYARD_IDENTITY_PAGE_SHIFT;
    NTSTATUS status;
    unsigned int starting_failures = failures;

    check( !register_identity_page( page, PAGE_READWRITE ),
           "identity codec map failed\n" );
    check( provider.identity_page_flags &&
           provider.identity_page_flags[(uintptr_t)page >>
               UC_SWITCHYARD_IDENTITY_PAGE_SHIFT] ==
               (UC_SWITCHYARD_IDENTITY_PAGE_READ |
                UC_SWITCHYARD_IDENTITY_PAGE_WRITE),
           "read/write identity page did not publish fast-path permissions\n" );
    provider.identity_page_flags[page_index] |= owner;
    memset( &translate, 0, sizeof(translate) );
    translate.address = (uintptr_t)page + 37;
    translate.size = 64;
    translate.flags = XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST |
                      XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ |
                      XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE;
    status = memory_translate( &translate );
    check( !status && translate.guest == (uintptr_t)page + 37 &&
           translate.host == translate.guest &&
           translate.allocation_base == (uintptr_t)page &&
           translate.domain == XTAJIT64_MEMORY_ADDRESS_IDENTITY,
           "identity guest codec returned %#x %#llx/%#llx/%u\n",
           (unsigned int)status, (unsigned long long)translate.guest,
           (unsigned long long)translate.host, translate.domain );

    memset( &translate, 0, sizeof(translate) );
    translate.address = (uintptr_t)page + 91;
    translate.size = 8;
    translate.flags = XTAJIT64_MEMORY_TRANSLATE_HOST_TO_GUEST |
                      XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE;
    status = memory_translate( &translate );
    check( !status && translate.guest == translate.host &&
           translate.host == (uintptr_t)page + 91,
           "identity host codec returned %#x %#llx/%#llx\n",
           (unsigned int)status, (unsigned long long)translate.guest,
           (unsigned long long)translate.host );

    check( !memory_protect( &protect ), "identity protect failed\n" );
    check( provider.identity_page_flags[page_index] ==
               (owner | UC_SWITCHYARD_IDENTITY_PAGE_READ),
           "read-only identity page lost owner or retained write permission\n" );
    memset( &translate, 0, sizeof(translate) );
    translate.address = (uintptr_t)page;
    translate.size = 1;
    translate.flags = XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST |
                      XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE;
    status = memory_translate( &translate );
    check( status == STATUS_INVALID_ADDRESS,
           "read-only identity mapping remained writable %#x\n",
           (unsigned int)status );

    protect.protect = PAGE_EXECUTE_READWRITE;
    check( !memory_protect( &protect ), "executable identity protect failed\n" );
    check( provider.identity_page_flags[page_index] ==
               (owner | UC_SWITCHYARD_IDENTITY_PAGE_READ),
           "executable identity page lost owner or acquired write permission\n" );

    memset( &translate, 0, sizeof(translate) );
    translate.address = UINT64_MAX - 3;
    translate.size = 8;
    translate.flags = XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST;
    status = memory_translate( &translate );
    check( status == STATUS_INVALID_PARAMETER,
           "overflowing codec request returned %#x\n", (unsigned int)status );
    check( !unregister_identity_page( page ), "identity codec unmap failed\n" );
    check( provider.identity_page_flags[page_index] == owner,
           "unmapped identity page lost owner or retained permissions\n" );
    if (failures == starting_failures)
        printf( "XTAJIT64_IDENTITY_FASTPATH_FLAGS_PASS\n" );
}

static void build_execute_only_code( unsigned char *host_page,
                                     uint64_t guest_page, uint64_t marker )
{
    struct code_buffer code = { host_page, 0 };

    memset( host_page, 0, TEST_PAGE );
    emit_movabs_rax( &code, guest_page + 0x100 );
    emit_u8( &code, 0x48 ); emit_u8( &code, 0x8b ); emit_u8( &code, 0x18 );
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );
    memcpy( host_page + 0x100, &marker, sizeof(marker) );
}

static void test_execute_only_read_and_execute(void)
{
    const uint64_t identity_marker = 0x123456789abcdef0ull;
    const uint64_t low_first = 0xfedcba9876543210ull;
    const uint64_t low_second = 0x0f1e2d3c4b5a6978ull;
    const uint64_t low_third = 0x89abcdef01234567ull;
    unsigned char *identity = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct xtajit64_memory_params flush = { .size = TEST_PAGE };
    struct wine_arm64ec_low_memory_range_v1 low_range;
    struct simulation simulation = {0};
    unsigned int starting_failures = failures;
    BOOL thread_initialized = FALSE;
    NTSTATUS status;

    build_execute_only_code( identity, (uintptr_t)identity, identity_marker );
    build_execute_only_code( test_low_pages, TEST_LOW_GUEST_BASE, low_first );
    check( !register_identity_page( identity, PAGE_EXECUTE ),
           "execute-only identity map failed\n" );
    check( !register_identity_page( stack, PAGE_READWRITE ),
           "execute-only stack map failed\n" );
    initialize_low_range( &low_range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_EXECUTE );
    status = publish_low_event( WINE_WOW64_MEMORY_ALLOCATE, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE,
                                TEST_LOW_GUEST_BASE, &low_range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status && canonical_range_matches(
               TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT,
               UC_PROT_READ | UC_PROT_EXEC,
               XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
           "execute-only LOW map returned %#x\n", (unsigned int)status );
    if (failures != starting_failures) goto done;
    status = thread_init( NULL );
    check( !status, "execute-only engine init failed %#x\n", (unsigned int)status );
    if (status) goto done;
    thread_initialized = TRUE;

    flush.guest = (uintptr_t)identity;
    check( !flush_instruction_cache( &flush ),
           "execute-only identity flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)identity, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.context.rbx == identity_marker,
           "execute-only identity simulation returned %#x reason %u data %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.context.rbx );

    initialize_begin_params( &simulation, TEST_LOW_GUEST_BASE, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.context.rbx == low_first,
           "execute-only LOW first simulation returned %#x reason %u data %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.context.rbx );

    build_execute_only_code( test_low_pages, TEST_LOW_GUEST_BASE, low_second );
    reset_cache_recorders();
    flush.guest = TEST_LOW_GUEST_BASE;
    check( !flush_instruction_cache( &flush ),
           "execute-only LOW guest flush failed\n" );
    check( cache_remove_calls == 1 &&
           cache_remove_start == TEST_LOW_GUEST_BASE &&
           cache_remove_end == TEST_LOW_GUEST_BASE + TEST_PAGE,
           "execute-only LOW guest interval %#llx-%#llx calls %u\n",
           (unsigned long long)cache_remove_start,
           (unsigned long long)cache_remove_end, cache_remove_calls );
    initialize_begin_params( &simulation, TEST_LOW_GUEST_BASE, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.context.rbx == low_second,
           "execute-only LOW guest-flush simulation returned %#x reason %u data %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.context.rbx );

    build_execute_only_code( test_low_pages, TEST_LOW_GUEST_BASE, low_third );
    reset_cache_recorders();
    flush.guest = TEST_LOW_HOST_BASE;
    check( !flush_instruction_cache( &flush ),
           "execute-only LOW host flush failed\n" );
    check( cache_remove_calls == 1 &&
           cache_remove_start == TEST_LOW_GUEST_BASE &&
           cache_remove_end == TEST_LOW_GUEST_BASE + TEST_PAGE,
           "execute-only LOW host interval %#llx-%#llx calls %u\n",
           (unsigned long long)cache_remove_start,
           (unsigned long long)cache_remove_end, cache_remove_calls );
    initialize_begin_params( &simulation, TEST_LOW_GUEST_BASE, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.context.rbx == low_third,
           "execute-only LOW host-flush simulation returned %#x reason %u data %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.context.rbx );
done:
    if (thread_initialized) thread_term( NULL );
    initialize_low_range( &low_range, TEST_LOW_GUEST_BASE, TEST_PAGE, 0,
                          MEM_FREE, PAGE_NOACCESS );
    status = publish_low_event( WINE_WOW64_MEMORY_RELEASE, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE, 0, &low_range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status, "execute-only LOW cleanup returned %#x\n",
           (unsigned int)status );
    check( !unregister_identity_page( stack ),
           "execute-only stack cleanup failed\n" );
    check( !unregister_identity_page( identity ),
           "execute-only identity cleanup failed\n" );
    if (failures == starting_failures)
        printf( "XTAJIT64_EXECUTE_ONLY_PASS\n" );
}

static void test_identity_atomic_avoids_demand_mapping(void)
{
    unsigned char *data = test_pages + 3 * TEST_PAGE;
    unsigned char *code_page = test_pages + 4 * TEST_PAGE;
    unsigned char *stack = test_pages + 5 * TEST_PAGE;
    struct code_buffer code = { .data = code_page };
    struct simulation simulation = {0};
    struct thread_engine *engine;
    unsigned int starting_failures = failures;
    BOOL thread_initialized = FALSE;
    BOOL mappings_match = FALSE;
    BOOL has_ec = FALSE, has_teb = FALSE, has_data = FALSE;
    BOOL has_code = FALSE, has_stack = FALSE;
    NTSTATUS status;
    size_t i;

    memset( data, 0, TEST_PAGE );
    memset( code_page, 0, TEST_PAGE );
    emit_movabs_rax( &code, (uintptr_t)data );
    emit_u8( &code, 0xf0 ); emit_u8( &code, 0x48 );
    emit_u8( &code, 0xff ); emit_u8( &code, 0x00 ); /* lock incq [rax] */
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );

    status = register_identity_page( data, PAGE_READWRITE );
    if (!status) status = register_identity_page( code_page, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    check( !status, "identity atomic mapping setup returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    status = thread_init( NULL );
    check( !status, "identity atomic mapping engine init returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    thread_initialized = TRUE;

    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    initialize_begin_params( &simulation, (uintptr_t)code_page,
                             (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    engine = test_last_acquired_engine;
    for (i = 0; engine && i < engine->mapped_ranges.count; ++i)
    {
        const struct mapped_range *range = &engine->mapped_ranges.data[i];

        if (range->guest == test_ec_target &&
            range->size == TEST_PAGE &&
            range->perms == (UC_PROT_READ | UC_PROT_EXEC))
            has_ec = TRUE;
        else if (range->guest == test_teb &&
                 range->size == TEST_PAGE &&
                 range->perms == (UC_PROT_READ | UC_PROT_WRITE))
            has_teb = TRUE;
        else if (range->guest == (uintptr_t)data &&
                 range->size == TEST_PAGE &&
                 range->perms == (UC_PROT_READ | UC_PROT_WRITE))
            has_data = TRUE;
        else if (range->guest == (uintptr_t)code_page &&
                 range->size == TEST_PAGE &&
                 range->perms == (UC_PROT_READ | UC_PROT_EXEC))
            has_code = TRUE;
        else if (range->guest == (uintptr_t)stack &&
                 range->size == TEST_PAGE &&
                 range->perms == (UC_PROT_READ | UC_PROT_WRITE))
            has_stack = TRUE;
    }
    mappings_match = engine && engine->mapped_ranges.count == 2 &&
                     has_ec && !has_teb && !has_data && has_code && !has_stack &&
                     engine_mappings_match_registry( engine );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           *(uint64_t *)data == 1 && memory_map_calls == 1 &&
           memory_unmap_calls <= 2 && cache_flush_calls <= 1 &&
           mappings_match,
           "identity atomic mapping returned %#x reason %u value %#llx calls %u/%u/%u ranges %zu\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)*(uint64_t *)data, memory_map_calls,
           memory_unmap_calls, cache_flush_calls,
           engine ? engine->mapped_ranges.count : 0 );

done:
    if (thread_initialized) thread_term( NULL );
    unregister_identity_page( stack );
    unregister_identity_page( code_page );
    unregister_identity_page( data );
    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    if (failures == starting_failures)
        printf( "XTAJIT64_IDENTITY_ATOMIC_NO_DEMAND_MAP_PASS\n" );
}

static void test_memory_fault_access_reporting(void)
{
    unsigned char *read_code = test_pages + 6 * TEST_PAGE;
    unsigned char *write_code = test_pages + 7 * TEST_PAGE;
    unsigned char *stack = test_pages + 8 * TEST_PAGE;
    unsigned char *fault = test_pages + 9 * TEST_PAGE;
    struct code_buffer code = {0};
    struct simulation simulation = {0};
    unsigned int starting_failures = failures;
    BOOL fault_registered = FALSE, thread_initialized = FALSE;
    NTSTATUS status;

    memset( read_code, 0, TEST_PAGE );
    code.data = read_code;
    emit_movabs_rax( &code, (uintptr_t)fault );
    emit_u8( &code, 0x48 ); emit_u8( &code, 0x8b );
    emit_u8( &code, 0x18 ); /* mov (%rax),%rbx */

    memset( write_code, 0, TEST_PAGE );
    code.data = write_code;
    code.offset = 0;
    emit_movabs_rax( &code, (uintptr_t)fault );
    emit_u8( &code, 0xc7 ); emit_u8( &code, 0x00 );
    emit_u32( &code, 0x12345678 ); /* movl $0x12345678,(%rax) */

    status = register_identity_page( read_code, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( write_code, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    check( !status, "memory-fault access setup returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    status = thread_init( NULL );
    check( !status, "memory-fault access engine init returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    thread_initialized = TRUE;

    initialize_begin_params( &simulation, (uintptr_t)read_code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( status == STATUS_RETRY &&
           simulation.params.stop_reason == XTAJIT64_STOP_MAPPING_MISS &&
           simulation.params.fault_address == (uintptr_t)fault &&
           simulation.params.fault_access == EXCEPTION_READ_FAULT,
           "read memory fault returned %#x reason %u fault %#llx access %#x\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.fault_address,
           simulation.params.fault_access );

    initialize_begin_params( &simulation, (uintptr_t)write_code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( status == STATUS_RETRY &&
           simulation.params.stop_reason == XTAJIT64_STOP_MAPPING_MISS &&
           simulation.params.fault_address == (uintptr_t)fault &&
           simulation.params.fault_access == EXCEPTION_WRITE_FAULT,
           "write memory fault returned %#x reason %u fault %#llx access %#x\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.fault_address,
           simulation.params.fault_access );

    initialize_begin_params( &simulation, (uintptr_t)fault, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( status == STATUS_RETRY &&
           simulation.params.stop_reason == XTAJIT64_STOP_MAPPING_MISS &&
           simulation.params.fault_address == (uintptr_t)fault &&
           simulation.params.fault_access == EXCEPTION_EXECUTE_FAULT,
           "execute memory fault returned %#x reason %u fault %#llx access %#x\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.fault_address,
           simulation.params.fault_access );

    status = register_identity_page( fault, PAGE_READONLY );
    fault_registered = !status;
    check( !status, "first-touch protection-fault setup returned %#x\n",
           (unsigned int)status );
    if (status) goto done;

    memory_map_calls = 0;
    initialize_begin_params( &simulation, (uintptr_t)write_code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( status == STATUS_ACCESS_VIOLATION &&
           simulation.params.stop_reason == XTAJIT64_STOP_MEMORY_FAULT &&
           simulation.params.fault_address == (uintptr_t)fault &&
           simulation.params.fault_access == EXCEPTION_WRITE_FAULT &&
           !memory_map_calls,
           "first-touch write protection fault returned %#x reason %u fault %#llx "
           "access %#x maps %u\n", (unsigned int)status,
           simulation.params.stop_reason,
           (unsigned long long)simulation.params.fault_address,
           simulation.params.fault_access, memory_map_calls );

    memory_map_calls = 0;
    initialize_begin_params( &simulation, (uintptr_t)fault, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( status == STATUS_ACCESS_VIOLATION &&
           simulation.params.stop_reason == XTAJIT64_STOP_MEMORY_FAULT &&
           simulation.params.fault_address == (uintptr_t)fault &&
           simulation.params.fault_access == EXCEPTION_EXECUTE_FAULT &&
           !memory_map_calls,
           "first-touch execute protection fault returned %#x reason %u fault %#llx "
           "access %#x maps %u\n", (unsigned int)status,
           simulation.params.stop_reason,
           (unsigned long long)simulation.params.fault_address,
           simulation.params.fault_access, memory_map_calls );

done:
    if (thread_initialized) thread_term( NULL );
    if (fault_registered) unregister_identity_page( fault );
    unregister_identity_page( stack );
    unregister_identity_page( write_code );
    unregister_identity_page( read_code );
    if (failures == starting_failures)
        printf( "XTAJIT64_MEMORY_FAULT_ACCESS_PASS\n" );
}

static void test_late_identity_mapping_retry(void)
{
    unsigned char *code_page = test_pages + 6 * TEST_PAGE;
    unsigned char *data = test_pages + 7 * TEST_PAGE;
    unsigned char *stack = test_pages + 8 * TEST_PAGE;
    const uint64_t expected = 0x6c6174656d617070ull;
    struct code_buffer code = { code_page, 0 };
    struct simulation simulation = {0};
    unsigned int starting_failures = failures;
    BOOL data_registered = FALSE, thread_initialized = FALSE;
    NTSTATUS status;

    memset( code_page, 0, TEST_PAGE );
    memset( data, 0, TEST_PAGE );
    *(uint64_t *)data = expected;
    emit_movabs_rax( &code, (uintptr_t)data );
    emit_u8( &code, 0x48 ); emit_u8( &code, 0x8b );
    emit_u8( &code, 0x18 ); /* mov (%rax),%rbx */
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );

    status = register_identity_page( code_page, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    check( !status, "late identity mapping setup returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    status = thread_init( NULL );
    check( !status, "late identity mapping engine init returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    thread_initialized = TRUE;

    initialize_begin_params( &simulation, (uintptr_t)code_page, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( status == STATUS_RETRY &&
           simulation.params.stop_reason == XTAJIT64_STOP_MAPPING_MISS &&
           simulation.params.fault_address == (uintptr_t)data &&
           simulation.params.fault_access == EXCEPTION_READ_FAULT,
           "late identity first access returned %#x reason %u fault %#llx access %#x\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.fault_address,
           simulation.params.fault_access );

    status = register_identity_page( data, PAGE_READWRITE );
    data_registered = !status;
    check( !status, "late identity reconciliation returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    initialize_begin_params( &simulation, (uintptr_t)code_page, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( !status &&
           simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.context.rbx == expected,
           "late identity retry returned %#x reason %u value %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.context.rbx );

done:
    if (thread_initialized) thread_term( NULL );
    if (data_registered) unregister_identity_page( data );
    unregister_identity_page( stack );
    unregister_identity_page( code_page );
    if (failures == starting_failures)
        printf( "XTAJIT64_LATE_IDENTITY_MAPPING_RETRY_PASS\n" );
}

static size_t build_syscall_trap_code( unsigned char *page, BOOL use_int2e,
                                       uint32_t syscall, uint64_t argument )
{
    struct code_buffer code = { page, 0 };
    size_t return_offset;

    emit_movabs_rcx( &code, argument );
    emit_u8( &code, 0x49 ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xca );
    emit_u8( &code, 0xb8 ); emit_u32( &code, syscall );
    emit_u8( &code, use_int2e ? 0xcd : 0x0f );
    emit_u8( &code, use_int2e ? 0x2e : 0x05 );
    return_offset = code.offset;
    emit_u8( &code, 0x49 ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xc0 );
    emit_u8( &code, 0x49 ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xc9 );
    emit_u8( &code, 0x4d ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xd4 );
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );
    return return_offset;
}

static size_t build_direct_self_read_code( unsigned char *page, uint64_t process,
                                           uint64_t source, uint64_t destination,
                                           uint64_t size )
{
    struct code_buffer code = { page, 0 };
    size_t return_offset;

    emit_movabs_rcx( &code, process );
    emit_u8( &code, 0x49 ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xca );
                                               /* mov %rcx,%r10 */
    emit_u8( &code, 0x48 ); emit_u8( &code, 0xba ); emit_u64( &code, source );
                                               /* movabs source,%rdx */
    emit_u8( &code, 0x49 ); emit_u8( &code, 0xb8 ); emit_u64( &code, destination );
                                               /* movabs destination,%r8 */
    emit_u8( &code, 0x49 ); emit_u8( &code, 0xb9 ); emit_u64( &code, size );
                                               /* movabs size,%r9 */
    emit_u8( &code, 0xb8 );
    emit_u32( &code, XTAJIT64_X64_SYSCALL_NT_READ_VIRTUAL_MEMORY );
    emit_u8( &code, 0x0f ); emit_u8( &code, 0x05 ); /* syscall */
    return_offset = code.offset;
    emit_u8( &code, 0x48 ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xc3 );
                                               /* mov %rax,%rbx */
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );
    return return_offset;
}

static void build_syscall_dispatcher_code( unsigned char *page )
{
    struct code_buffer code = { page, 0 };

    emit_u8( &code, 0x48 ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xc3 );
    emit_u8( &code, 0x49 ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xc8 );
    emit_u8( &code, 0x4d ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xd1 );
    emit_u8( &code, 0x49 ); emit_u8( &code, 0x89 ); emit_u8( &code, 0xe5 );
    emit_u8( &code, 0x4c ); emit_u8( &code, 0x8b ); emit_u8( &code, 0x34 );
    emit_u8( &code, 0x24 );
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );
}

static void test_x64_syscall_traps(void)
{
    static const uint64_t arguments[] =
    {
        0x1122334455667788ull,
        0x8877665544332211ull,
    };
    const uint64_t stack_marker = 0xdecafbad12345678ull;
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    unsigned char *source = test_pages + 5 * TEST_PAGE;
    unsigned char *destination = test_pages + 6 * TEST_PAGE;
    const size_t direct_size = 64;
    struct xtajit64_memory_params flush =
    {
        .guest = (uintptr_t)code,
        .size = TEST_PAGE,
    };
    struct simulation simulation = {0};
    struct code_buffer unsupported;
    unsigned int starting_failures = failures;
    unsigned int start_count, write_count, read_count;
    uint64_t *bytes_read;
    uint64_t direct_completions, diagnostic_count;
    size_t i, return_offset;
    BOOL direct_stats_enabled = FALSE;
    NTSTATUS status;
    int ret;

    memset( code, 0, TEST_PAGE );
    memset( stack, 0, TEST_PAGE );
    memset( source, 0, TEST_PAGE );
    memset( destination, 0, TEST_PAGE );
    for (i = 0; i < direct_size; ++i) source[i] = (unsigned char)(i ^ 0xa5);
    check( !register_identity_page( code, PAGE_EXECUTE_READ ),
           "syscall code map failed\n" );
    check( !register_identity_page( stack, PAGE_READWRITE ),
           "syscall stack map failed\n" );
    check( !register_identity_page( source, PAGE_READWRITE ),
           "direct self-read source map failed\n" );
    check( !register_identity_page( destination, PAGE_READWRITE ),
           "direct self-read destination map failed\n" );
    *(uint64_t *)(stack + TEST_PAGE - 16) = stack_marker;
    status = thread_init( NULL );
    check( !status, "syscall engine init failed %#x\n", (unsigned int)status );
    if (status) goto done;

    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    simulation.params.stack_limit = simulation.params.context.rsp + 1;
    status = begin_simulation( &simulation.params );
    check( status == STATUS_INVALID_PARAMETER,
           "out-of-bounds x64 stack returned %#x\n", (unsigned int)status );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    simulation.params.context.rip = XTAJIT64_X64_USER_ADDRESS_MAX + 1;
    status = begin_simulation( &simulation.params );
    check( status == STATUS_INVALID_PARAMETER,
           "non-canonical x64 RIP returned %#x\n", (unsigned int)status );

    return_offset = build_syscall_trap_code( code, TRUE, 0, arguments[0] );
    check( !flush_instruction_cache( &flush ), "INT 2E code flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    start_count = atomic_load_explicit( &test_emu_start_count, memory_order_relaxed );
    write_count = atomic_load_explicit( &test_context_write_count, memory_order_relaxed );
    read_count = atomic_load_explicit( &test_context_read_count, memory_order_relaxed );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION,
           "INT 2E returned %#x reason %u\n", (unsigned int)status,
           simulation.params.stop_reason );
    check( simulation.params.context.rbx == 0 &&
           simulation.params.context.r8 == arguments[0] &&
           simulation.params.context.r9 == (uintptr_t)code + return_offset &&
           simulation.params.context.r13 == (uintptr_t)stack + TEST_PAGE - 16 &&
           simulation.params.context.r14 == stack_marker,
           "INT 2E register bridge mismatch\n" );
    check( atomic_load_explicit( &test_emu_start_count, memory_order_relaxed ) ==
               start_count + 2 &&
           atomic_load_explicit( &test_context_write_count, memory_order_relaxed ) ==
               write_count + 1 &&
           atomic_load_explicit( &test_context_read_count, memory_order_relaxed ) ==
               read_count + 1,
           "INT 2E did not resume with one context transfer\n" );

    return_offset = build_syscall_trap_code( code, FALSE, 1,
                                             arguments[1] );
    check( !flush_instruction_cache( &flush ), "SYSCALL code flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.context.rbx == 1 &&
           simulation.params.context.r8 == arguments[1] &&
           simulation.params.context.r9 == (uintptr_t)code + return_offset,
           "SYSCALL bridge returned %#x reason %u\n", (unsigned int)status,
           simulation.params.stop_reason );

    pthread_mutex_lock( &provider.mutex );
    provider.direct_self_read_stats_enabled = TRUE;
    pthread_mutex_unlock( &provider.mutex );
    direct_stats_enabled = TRUE;
    memset( destination, 0xcc, direct_size );
    return_offset = build_direct_self_read_code( code, ~(uint64_t)0,
                                                 (uintptr_t)source,
                                                 (uintptr_t)destination,
                                                 direct_size );
    check( !flush_instruction_cache( &flush ), "direct self-read code flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    simulation.params.context.rsp = (uintptr_t)stack + TEST_PAGE - 0x80;
    bytes_read = (uint64_t *)(stack + TEST_PAGE - 0x100);
    *bytes_read = UINT64_MAX;
    *(uint64_t *)(uintptr_t)(simulation.params.context.rsp + 0x28) =
        (uintptr_t)bytes_read;
    direct_completions = provider_direct_self_read_completions();
    diagnostic_count = provider_direct_self_read_size_bucket( DIRECT_SELF_READ_SIZE_64 );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.context.rbx == STATUS_SUCCESS &&
           simulation.params.context.rip == test_ec_target &&
           return_offset && !memcmp( source, destination, direct_size ) &&
           *bytes_read == direct_size &&
           provider_direct_self_read_completions() == direct_completions + 1,
           "direct self-read returned %#x reason %u status %#llx bytes %#llx completions %#llx/%#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)*bytes_read,
           (unsigned long long)direct_completions,
           (unsigned long long)provider_direct_self_read_completions() );
    check( provider_direct_self_read_size_bucket( DIRECT_SELF_READ_SIZE_64 ) ==
               diagnostic_count + 1,
           "direct self-read size bucket was not recorded\n" );

    /* Statistics distinguish unsupported argument shapes without logging
     * addresses or adding clocks and locks to the syscall hot path. */
    return_offset = build_direct_self_read_code( code, 0x1234,
                                                 (uintptr_t)source,
                                                 (uintptr_t)destination,
                                                 direct_size );
    check( !flush_instruction_cache( &flush ),
           "non-current self-read code flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    simulation.params.context.rsp = (uintptr_t)stack + TEST_PAGE - 0x80;
    *(uint64_t *)(uintptr_t)(simulation.params.context.rsp + 0x28) =
        (uintptr_t)bytes_read;
    diagnostic_count = provider_direct_self_read_rejections(
        DIRECT_SELF_READ_REJECT_PROCESS );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.context.rbx == XTAJIT64_X64_SYSCALL_NT_READ_VIRTUAL_MEMORY &&
           provider_direct_self_read_rejections( DIRECT_SELF_READ_REJECT_PROCESS ) ==
               diagnostic_count + 1 && return_offset,
           "non-current self-read did not record dispatcher fallback %#x reason %u\n",
           (unsigned int)status, simulation.params.stop_reason );

    return_offset = build_direct_self_read_code(
        code, ~(uint64_t)0, (uintptr_t)source, (uintptr_t)destination,
        XTAJIT64_DIRECT_SELF_READ_MAX_SIZE + 1 );
    check( !flush_instruction_cache( &flush ),
           "oversized self-read code flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    simulation.params.context.rsp = (uintptr_t)stack + TEST_PAGE - 0x80;
    *(uint64_t *)(uintptr_t)(simulation.params.context.rsp + 0x28) =
        (uintptr_t)bytes_read;
    diagnostic_count = provider_direct_self_read_rejections(
        DIRECT_SELF_READ_REJECT_SIZE );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.context.rbx ==
               XTAJIT64_X64_SYSCALL_NT_READ_VIRTUAL_MEMORY &&
           provider_direct_self_read_rejections( DIRECT_SELF_READ_REJECT_SIZE ) ==
               diagnostic_count + 1 && return_offset,
           "oversized self-read did not record dispatcher fallback %#x\n",
           (unsigned int)status );

    return_offset = build_direct_self_read_code( code, ~(uint64_t)0, 1,
                                                 (uintptr_t)destination,
                                                 direct_size );
    check( !flush_instruction_cache( &flush ),
           "unmapped-source self-read code flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    simulation.params.context.rsp = (uintptr_t)stack + TEST_PAGE - 0x80;
    *(uint64_t *)(uintptr_t)(simulation.params.context.rsp + 0x28) =
        (uintptr_t)bytes_read;
    diagnostic_count = provider_direct_self_read_rejections(
        DIRECT_SELF_READ_REJECT_SOURCE_RANGE );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.context.rbx ==
               XTAJIT64_X64_SYSCALL_NT_READ_VIRTUAL_MEMORY &&
           provider_direct_self_read_rejections( DIRECT_SELF_READ_REJECT_SOURCE_RANGE ) ==
               diagnostic_count + 1 && return_offset,
           "unmapped-source self-read did not record dispatcher fallback %#x\n",
           (unsigned int)status );

    return_offset = build_direct_self_read_code( code, ~(uint64_t)0,
                                                 (uintptr_t)source,
                                                 (uintptr_t)source + 1,
                                                 direct_size );
    check( !flush_instruction_cache( &flush ),
           "overlapping self-read code flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    simulation.params.context.rsp = (uintptr_t)stack + TEST_PAGE - 0x80;
    *(uint64_t *)(uintptr_t)(simulation.params.context.rsp + 0x28) =
        (uintptr_t)bytes_read;
    diagnostic_count = provider_direct_self_read_rejections(
        DIRECT_SELF_READ_REJECT_OVERLAP );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.context.rbx ==
               XTAJIT64_X64_SYSCALL_NT_READ_VIRTUAL_MEMORY &&
           provider_direct_self_read_rejections( DIRECT_SELF_READ_REJECT_OVERLAP ) ==
               diagnostic_count + 1 && return_offset,
           "overlapping self-read did not record dispatcher fallback %#x\n",
           (unsigned int)status );

    memset( destination, 0xcc, direct_size );
    return_offset = build_direct_self_read_code( code, ~(uint64_t)0,
                                                 (uintptr_t)source,
                                                 (uintptr_t)destination,
                                                 direct_size );
    check( !flush_instruction_cache( &flush ),
           "null-result self-read code flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    simulation.params.context.rsp = (uintptr_t)stack + TEST_PAGE - 0x80;
    *(uint64_t *)(uintptr_t)(simulation.params.context.rsp + 0x28) = 0;
    direct_completions = provider_direct_self_read_completions();
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.context.rbx == STATUS_SUCCESS &&
           !memcmp( source, destination, direct_size ) &&
           provider_direct_self_read_completions() == direct_completions + 1 &&
           return_offset,
           "null-result self-read did not complete directly %#x\n",
           (unsigned int)status );

    /* A canonical RW entry can temporarily be physically read-only for Wine
     * write-watch handling.  The direct path must leave that case to ntdll. */
    memset( destination, 0xcc, direct_size );
    *bytes_read = UINT64_MAX;
    ret = mprotect( destination, TEST_PAGE, PROT_READ );
    check( !ret, "direct self-read write-watch simulation mprotect failed %d\n", errno );
    if (!ret)
    {
        check( !flush_instruction_cache( &flush ),
               "direct self-read fallback code flush failed\n" );
        initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
        simulation.params.context.rsp = (uintptr_t)stack + TEST_PAGE - 0x80;
        *(uint64_t *)(uintptr_t)(simulation.params.context.rsp + 0x28) =
            (uintptr_t)bytes_read;
        direct_completions = provider_direct_self_read_completions();
        diagnostic_count = provider_direct_self_read_rejections(
            DIRECT_SELF_READ_REJECT_DATA_COPY );
        status = begin_simulation( &simulation.params );
        check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
               simulation.params.context.rbx ==
                   XTAJIT64_X64_SYSCALL_NT_READ_VIRTUAL_MEMORY &&
               destination[0] == 0xcc && *bytes_read == UINT64_MAX &&
               provider_direct_self_read_completions() == direct_completions &&
               provider_direct_self_read_rejections( DIRECT_SELF_READ_REJECT_DATA_COPY ) ==
                   diagnostic_count + 1,
               "physically protected self-read did not fall back %#x reason %u result %#llx bytes %#llx\n",
               (unsigned int)status, simulation.params.stop_reason,
               (unsigned long long)simulation.params.context.rbx,
               (unsigned long long)*bytes_read );
        check( !mprotect( destination, TEST_PAGE, PROT_READ | PROT_WRITE ),
               "direct self-read destination permission restore failed %d\n", errno );
    }

    return_offset = build_syscall_trap_code( code, TRUE, TEST_SYSCALL_COUNT,
                                             arguments[0] );
    check( !flush_instruction_cache( &flush ), "unknown syscall flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.context.r8 ==
               (UINT64)(INT64)STATUS_INVALID_SYSTEM_SERVICE &&
           simulation.params.context.r9 == arguments[0] &&
           simulation.params.context.r12 == arguments[0] && return_offset == 20,
           "unknown syscall did not resume with STATUS_INVALID_SYSTEM_SERVICE\n" );

    memset( code, 0x90, TEST_PAGE );
    unsupported.data = code;
    unsupported.offset = 0;
    emit_u8( &unsupported, 0x9c ); /* pushfq */
    emit_u8( &unsupported, 0x81 ); emit_u8( &unsupported, 0x0c );
    emit_u8( &unsupported, 0x24 ); emit_u32( &unsupported, 0x00010100 );
                                      /* orl $(TF|RF),(%rsp) */
    emit_u8( &unsupported, 0x9d ); /* popfq */
    emit_u8( &unsupported, 0x0f ); emit_u8( &unsupported, 0xa2 ); /* cpuid */
    check( !flush_instruction_cache( &flush ), "single-step code flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( status == STATUS_SINGLE_STEP &&
           simulation.params.stop_reason == XTAJIT64_STOP_SINGLE_STEP &&
           simulation.params.context.rip == (uintptr_t)code + unsupported.offset &&
           !provider.poison_status,
           "single-step trap returned %#x reason %u rip %#llx poison %#x\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.context.rip,
           (unsigned int)provider.poison_status );

    memset( code, 0x90, TEST_PAGE );
    unsupported.data = code;
    unsupported.offset = 0;
    emit_u8( &unsupported, 0xcd ); emit_u8( &unsupported, 0x80 );
    emit_movabs_rax( &unsupported, test_ec_target );
    emit_jump_rax( &unsupported );
    check( !flush_instruction_cache( &flush ), "unsupported interrupt flush failed\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( status == STATUS_NOT_SUPPORTED &&
           simulation.params.stop_reason == XTAJIT64_STOP_INVALID_INSTRUCTION &&
           simulation.params.context.rip == (uintptr_t)code + 2 &&
           !provider.poison_status,
           "unsupported interrupt returned %#x reason %u poison %#x\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned int)provider.poison_status );

    pthread_mutex_lock( &provider.mutex );
    provider.direct_self_read_stats_enabled = FALSE;
    pthread_mutex_unlock( &provider.mutex );
    direct_stats_enabled = FALSE;
    thread_term( NULL );
done:
    if (direct_stats_enabled)
    {
        pthread_mutex_lock( &provider.mutex );
        provider.direct_self_read_stats_enabled = FALSE;
        pthread_mutex_unlock( &provider.mutex );
    }
    mprotect( destination, TEST_PAGE, PROT_READ | PROT_WRITE );
    unregister_identity_page( destination );
    unregister_identity_page( source );
    unregister_identity_page( stack );
    unregister_identity_page( code );
    if (failures == starting_failures)
        printf( "XTAJIT64_DIRECT_SELF_READ_PASS\n" );
}

static void build_x87_control_code( unsigned char *page, uint64_t address,
                                    BOOL load )
{
    struct code_buffer code = { page, 0 };

    emit_movabs_rax( &code, address );
    emit_u8( &code, 0xd9 );
    emit_u8( &code, load ? 0x28 : 0x38 ); /* FLDCW/FNSTCW word ptr [RAX] */
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );
}

static void test_pooled_thread_cpu_context(void)
{
    unsigned char *data = test_pages + 3 * TEST_PAGE;
    unsigned char *code = test_pages + 4 * TEST_PAGE;
    unsigned char *stack = test_pages + 5 * TEST_PAGE;
    uint16_t *control = (uint16_t *)data;
    struct simulation current = {0}, other = {0};
    pthread_t thread;
    unsigned int starting_failures = failures;
    BOOL thread_created = FALSE, thread_initialized = FALSE;
    NTSTATUS status;
    int ret;

    memset( data, 0, TEST_PAGE );
    memset( code, 0, TEST_PAGE );
    control[0] = 0x027f;
    control[1] = 0x037f;
    build_x87_control_code( code, (uintptr_t)&control[0], TRUE );
    build_x87_control_code( code + 64, (uintptr_t)&control[1], TRUE );
    build_x87_control_code( code + 128, (uintptr_t)&control[2], FALSE );

    status = register_identity_page( data, PAGE_READWRITE );
    if (!status) status = register_identity_page( code, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    if (!status) status = thread_init( NULL );
    check( !status, "pooled CPU-context setup returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    thread_initialized = TRUE;

    initialize_begin_params( &current, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &current.params );
    check( !status && current.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           provider_engine_count() == 1,
           "first pooled CPU context returned %#x reason %u engines %zu\n",
           (unsigned int)status, current.params.stop_reason,
           provider_engine_count() );
    if (status) goto done;

    initialize_begin_params( &other, (uintptr_t)code + 64, (uintptr_t)stack );
    ret = pthread_create( &thread, NULL, run_simulation, &other );
    check( !ret, "second pooled CPU-context thread creation failed %d\n", ret );
    if (!ret)
    {
        thread_created = TRUE;
        check( join_simulation( thread, &other ),
               "second pooled CPU-context thread timed out\n" );
        thread_created = FALSE;
        check( !other.init_status && !other.status &&
               other.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
               provider_engine_count() == 1,
               "second pooled CPU context returned %#x/%#x reason %u engines %zu\n",
               (unsigned int)other.init_status, (unsigned int)other.status,
               other.params.stop_reason, provider_engine_count() );
    }

    initialize_begin_params( &current, (uintptr_t)code + 128, (uintptr_t)stack );
    status = begin_simulation( &current.params );
    check( !status && current.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           control[2] == control[0] && control[2] != control[1] &&
           provider_engine_count() == 1,
           "pooled x87 state returned %#x reason %u control %#x/%#x/%#x engines %zu\n",
           (unsigned int)status, current.params.stop_reason, control[0], control[1],
           control[2], provider_engine_count() );

done:
    if (thread_created) pthread_join( thread, NULL );
    if (thread_initialized) thread_term( NULL );
    unregister_identity_page( stack );
    unregister_identity_page( code );
    unregister_identity_page( data );
    if (failures == starting_failures)
        printf( "XTAJIT64_POOLED_CPU_CONTEXT_PASS\n" );
}

static void build_peer_wait_code( unsigned char *page, uint64_t data,
                                  unsigned int self, unsigned int peer )
{
    struct code_buffer code = { page, 0 };
    size_t loop, branch;

    emit_movabs_rax( &code, data );
    emit_u8( &code, 0xc7 );
    emit_u8( &code, self ? 0x40 : 0x00 );
    if (self) emit_u8( &code, self * 4 );
    emit_u32( &code, 1 );
    loop = code.offset;
    emit_u8( &code, 0x83 ); emit_u8( &code, 0x78 );
    emit_u8( &code, peer * 4 ); emit_u8( &code, 1 );
    emit_u8( &code, 0x72 ); branch = code.offset; emit_u8( &code, 0 );
    patch_rel8( &code, branch, loop );
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );
}

static void test_concurrent_engines(void)
{
    unsigned char *data = test_pages + 3 * TEST_PAGE;
    unsigned char *code0 = test_pages + 4 * TEST_PAGE;
    unsigned char *code1 = test_pages + 5 * TEST_PAGE;
    unsigned char *stack0 = test_pages + 6 * TEST_PAGE;
    unsigned char *stack1 = test_pages + 7 * TEST_PAGE;
    struct simulation simulations[2] = {0};
    pthread_t threads[2];
    unsigned int i;

    memset( data, 0, TEST_PAGE );
    memset( code0, 0, TEST_PAGE );
    memset( code1, 0, TEST_PAGE );
    build_peer_wait_code( code0, (uintptr_t)data, 0, 1 );
    build_peer_wait_code( code1, (uintptr_t)data, 1, 0 );
    check( !register_identity_page( data, PAGE_READWRITE ), "peer data map failed\n" );
    check( !register_identity_page( code0, PAGE_EXECUTE_READ ), "peer code0 map failed\n" );
    check( !register_identity_page( code1, PAGE_EXECUTE_READ ), "peer code1 map failed\n" );
    check( !register_identity_page( stack0, PAGE_READWRITE ), "peer stack0 map failed\n" );
    check( !register_identity_page( stack1, PAGE_READWRITE ), "peer stack1 map failed\n" );

    initialize_begin_params( &simulations[0], (uintptr_t)code0, (uintptr_t)stack0 );
    initialize_begin_params( &simulations[1], (uintptr_t)code1, (uintptr_t)stack1 );
    pthread_create( &threads[0], NULL, run_simulation, &simulations[0] );
    pthread_create( &threads[1], NULL, run_simulation, &simulations[1] );
    for (i = 0; i < 2; ++i)
        check( join_simulation( threads[i], &simulations[i] ),
               "peer engine %u timed out\n", i );
    for (i = 0; i < 2; ++i)
        check( !simulations[i].init_status && !simulations[i].status &&
               simulations[i].params.stop_reason == XTAJIT64_STOP_EC_TRANSITION,
               "peer engine %u returned %#x/%#x reason %u\n", i,
               (unsigned int)simulations[i].init_status,
               (unsigned int)simulations[i].status,
               simulations[i].params.stop_reason );
    check( provider_engine_count() == 2,
           "simultaneous peer execution retained %zu pooled engines\n",
           provider_engine_count() );

    unregister_identity_page( stack1 );
    unregister_identity_page( stack0 );
    unregister_identity_page( code1 );
    unregister_identity_page( code0 );
    unregister_identity_page( data );
}

static size_t build_marker_code( unsigned char *page, uint64_t marker )
{
    struct code_buffer code = { page, 0 };

    emit_u8( &code, 0x49 ); emit_u8( &code, 0xba ); emit_u64( &code, marker );
    emit_movabs_rax( &code, test_ec_target );
    emit_jump_rax( &code );
    return code.offset;
}

static void test_executable_cache_invalidation(void)
{
    const uint64_t first = 0x1020304050607080ull;
    const uint64_t second = 0x8070605040302010ull;
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct xtajit64_memory_params flush =
    {
        .guest = (uintptr_t)code,
    };
    struct simulation simulation = {0};
    struct thread_engine *first_engine;
    size_t engine_count;
    NTSTATUS status;

    memset( code, 0, TEST_PAGE );
    flush.size = build_marker_code( code, first );
    check( !register_identity_page( code, PAGE_EXECUTE_READ ), "cache code map failed\n" );
    check( !register_identity_page( stack, PAGE_READWRITE ), "cache stack map failed\n" );
    status = thread_init( NULL );
    check( !status, "cache engine init failed %#x\n", (unsigned int)status );
    if (status) goto done;
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    first_engine = test_last_acquired_engine;
    check( !status && simulation.params.context.r10 == first,
           "first code generation returned %#x/%#llx\n", (unsigned int)status,
           (unsigned long long)simulation.params.context.r10 );

    build_marker_code( code, second );
    reset_cache_recorders();
    check( !flush_instruction_cache( &flush ), "targeted cache flush failed\n" );
    engine_count = provider_engine_count();
    check( cache_remove_calls == engine_count && cache_remove_start == (uintptr_t)code &&
           cache_remove_end == (uintptr_t)code + flush.size,
           "targeted cache interval %#llx-%#llx calls %u/%zu\n",
           (unsigned long long)cache_remove_start,
           (unsigned long long)cache_remove_end, cache_remove_calls, engine_count );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.context.r10 == second &&
           test_last_acquired_engine == first_engine,
           "cache flush retained stale code %#x/%#llx engine %p/%p\n",
           (unsigned int)status, (unsigned long long)simulation.params.context.r10,
           first_engine, test_last_acquired_engine );
    thread_term( NULL );
done:
    unregister_identity_page( stack );
    unregister_identity_page( code );
}

static void test_executable_address_reuse_invalidation(void)
{
    const uint64_t first = 0x1122334455667788ull;
    const uint64_t second = 0x8877665544332211ull;
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct simulation simulation = {0};
    struct thread_engine *first_engine;
    unsigned int starting_failures = failures;
    NTSTATUS status;

    memset( code, 0, TEST_PAGE );
    build_marker_code( code, first );
    check( !register_identity_page( code, PAGE_EXECUTE_READ ),
           "address-reuse code map failed\n" );
    check( !register_identity_page( stack, PAGE_READWRITE ),
           "address-reuse stack map failed\n" );
    status = thread_init( NULL );
    check( !status, "address-reuse engine init failed %#x\n",
           (unsigned int)status );
    if (status) goto done;

    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    first_engine = test_last_acquired_engine;
    check( !status && simulation.params.context.r10 == first,
           "first address-reuse generation returned %#x/%#llx\n",
           (unsigned int)status,
           (unsigned long long)simulation.params.context.r10 );

    reset_cache_recorders();
    memory_map_calls = memory_unmap_calls = 0;
    status = unregister_identity_page( code );
    build_marker_code( code, second );
    if (!status) status = register_identity_page( code, PAGE_EXECUTE_READ );
    check( !status && !memory_map_calls && !memory_unmap_calls &&
           !cache_flush_calls,
           "address reuse publication returned %#x with engine calls %u/%u/%u\n",
           (unsigned int)status, memory_map_calls, memory_unmap_calls,
           cache_flush_calls );
    if (status) goto thread_done;

    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.context.r10 == second &&
           test_last_acquired_engine == first_engine &&
           memory_unmap_calls == 1 && memory_map_calls == 1 &&
           !cache_flush_calls,
           "address reuse retained stale code %#x/%#llx engine %p/%p calls %u/%u/%u\n",
           (unsigned int)status,
           (unsigned long long)simulation.params.context.r10,
           first_engine, test_last_acquired_engine, memory_map_calls,
           memory_unmap_calls, cache_flush_calls );

thread_done:
    thread_term( NULL );
done:
    unregister_identity_page( stack );
    unregister_identity_page( code );
    memory_map_calls = memory_unmap_calls = 0;
    reset_cache_recorders();
    if (failures == starting_failures)
        printf( "XTAJIT64_ADDRESS_REUSE_INVALIDATION_PASS\n" );
}

static void *run_protect( void *arg )
{
    struct protect_worker *worker = arg;

    worker->status = memory_protect( &worker->params );
    atomic_store_explicit( &worker->done, 1, memory_order_release );
    return NULL;
}

static void *run_flush( void *arg )
{
    struct flush_worker *worker = arg;

    worker->status = flush_instruction_cache( &worker->params );
    atomic_store_explicit( &worker->done, 1, memory_order_release );
    return NULL;
}

static void *run_process_term( void *arg )
{
    struct process_term_worker *worker = arg;

    worker->status = process_term( NULL );
    atomic_store_explicit( &worker->done, 1, memory_order_release );
    return NULL;
}

static void test_running_pool_teardown(void)
{
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct code_buffer buffer = { code, 0 };
    struct simulation simulation = {0};
    struct process_term_worker worker = {0};
    pthread_t runner, terminator;
    unsigned int starting_failures = failures;
    BOOL runner_created = FALSE, terminator_created = FALSE;
    BOOL entered, shutting_down;
    NTSTATUS status;
    int ret;

    memset( code, 0, TEST_PAGE );
    emit_movabs_rax( &buffer, test_ec_target );
    emit_jump_rax( &buffer );
    status = register_identity_page( (void *)(uintptr_t)test_ec_target,
                                     PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( code, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    if (!status) status = register_identity_page( (void *)(uintptr_t)test_teb,
                                                  PAGE_READWRITE );
    check( !status, "running pool teardown setup returned %#x\n",
           (unsigned int)status );
    if (status) goto reset;

    atomic_store( &test_hold_ec_hook, 1 );
    atomic_store( &test_ec_hook_entered, 0 );
    atomic_store( &test_release_ec_hook, 0 );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    ret = pthread_create( &runner, NULL, run_simulation, &simulation );
    check( !ret, "running pool teardown simulation creation failed %d\n", ret );
    if (ret) goto release;
    runner_created = TRUE;
    entered = wait_atomic_int_at_least( &test_ec_hook_entered, 1, 2000 );
    check( entered, "running pool teardown did not enter the held engine\n" );
    if (!entered) goto release;

    ret = pthread_create( &terminator, NULL, run_process_term, &worker );
    check( !ret, "running pool terminator creation failed %d\n", ret );
    if (ret) goto release;
    terminator_created = TRUE;
    shutting_down = wait_provider_shutdown_started( 2000 );
    check( shutting_down && !atomic_load_explicit( &worker.done,
                                                   memory_order_acquire ),
           "process teardown did not wait for the borrowed engine\n" );

release:
    atomic_store_explicit( &test_release_ec_hook, 1, memory_order_release );
    if (runner_created)
        check( join_simulation( runner, &simulation ),
               "running pool teardown simulation timed out\n" );
    if (terminator_created) pthread_join( terminator, NULL );
    if (runner_created)
        check( !simulation.init_status && !simulation.status &&
               simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION,
               "running pool teardown simulation returned %#x/%#x reason %u\n",
               (unsigned int)simulation.init_status,
               (unsigned int)simulation.status, simulation.params.stop_reason );
    if (terminator_created)
        check( !worker.status && atomic_load_explicit( &worker.done,
                                                       memory_order_acquire ),
               "running pool teardown returned %#x\n", (unsigned int)worker.status );
    pthread_mutex_lock( &provider.mutex );
    check( !provider.initialized && !provider.engines &&
           !provider.initial_context && !provider.mutating &&
           !provider.shutting_down,
           "running pool teardown retained provider resources\n" );
    pthread_mutex_unlock( &provider.mutex );

reset:
    atomic_store( &test_hold_ec_hook, 0 );
    atomic_store( &test_release_ec_hook, 1 );
    process_term( NULL );
    process_params.enabled_capabilities = 0;
    status = process_init( &process_params );
    check( !status, "provider restart after running pool teardown returned %#x\n",
           (unsigned int)status );
    if (failures == starting_failures)
        printf( "XTAJIT64_RUNNING_POOL_TEARDOWN_PASS\n" );
}

static void *run_low_observer( void *arg )
{
    struct low_observer_worker *worker = arg;
    void *transaction = NULL;

    worker->status = arm64ec_low_memory_observer.begin(
        arm64ec_low_memory_observer.context, worker->event.operation,
        worker->event.host_address, worker->event.size_covered,
        worker->event.host_allocation_base, &transaction );
    if (!worker->status)
    {
        atomic_store_explicit( &worker->begun, 1, memory_order_release );
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              transaction, &worker->event );
        worker->status = observer_provider_status();
    }
    atomic_store_explicit( &worker->done, 1, memory_order_release );
    return NULL;
}

static void *run_code_observer( void *arg )
{
    struct code_observer_worker *worker = arg;
    void *transaction = NULL;

    worker->status = arm64ec_code_observer.begin(
        arm64ec_code_observer.context, worker->event.operation, &transaction );
    if (!worker->status)
    {
        if (worker->set_ec)
            __atomic_fetch_or( worker->bitmap_word, worker->bitmap_mask,
                               __ATOMIC_RELEASE );
        else
            __atomic_fetch_and( worker->bitmap_word, ~worker->bitmap_mask,
                                __ATOMIC_RELEASE );
        atomic_store_explicit( &worker->begun, 1, memory_order_release );
        arm64ec_code_observer.complete( arm64ec_code_observer.context,
                                       transaction, &worker->event );
        worker->status = observer_provider_status();
    }
    atomic_store_explicit( &worker->done, 1, memory_order_release );
    return NULL;
}

static void test_running_mutation_barrier(void)
{
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct code_buffer buffer = { code, 0 };
    struct simulation simulation = {0};
    struct protect_worker worker =
    {
        .params =
        {
            .guest = (uintptr_t)code,
            .size = TEST_PAGE,
            .protect = PAGE_EXECUTE_READWRITE,
        },
    };
    pthread_t runner, mutator;
    BOOL entered;

    memset( code, 0, TEST_PAGE );
    emit_movabs_rax( &buffer, test_ec_target );
    emit_jump_rax( &buffer );
    check( !register_identity_page( code, PAGE_EXECUTE_READ ), "barrier code map failed\n" );
    check( !register_identity_page( stack, PAGE_READWRITE ), "barrier stack map failed\n" );
    atomic_store( &test_hold_ec_hook, 1 );
    atomic_store( &test_ec_hook_entered, 0 );
    atomic_store( &test_release_ec_hook, 0 );
    atomic_store( &test_mutation_waiters, 0 );
    atomic_store( &test_pause_stop_owner_violation, 0 );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    pthread_create( &runner, NULL, run_simulation, &simulation );
    entered = wait_atomic_int_at_least( &test_ec_hook_entered, 1, 2000 );
    check( entered, "simulation did not enter held EC hook\n" );
    if (entered)
    {
        pthread_create( &mutator, NULL, run_protect, &worker );
        check( wait_mutation_stage( MUTATION_STAGE_WAIT, 2000 ),
               "mapping mutation did not wait for running engine\n" );
        check( !atomic_load_explicit( &worker.done, memory_order_acquire ),
               "mapping mutation published while engine hook was active\n" );
        atomic_store_explicit( &test_release_ec_hook, 1, memory_order_release );
        pthread_join( mutator, NULL );
        check( !worker.status, "mapping mutation returned %#x\n",
               (unsigned int)worker.status );
    }
    else atomic_store_explicit( &test_release_ec_hook, 1, memory_order_release );
    check( join_simulation( runner, &simulation ), "barrier simulation timed out\n" );
    check( !simulation.status &&
           simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           !atomic_load_explicit( &test_pause_stop_owner_violation,
                                  memory_order_acquire ),
           "barrier lost EC stop or stopped from foreign thread %#x/%u\n",
           (unsigned int)simulation.status, simulation.params.stop_reason );
    atomic_store( &test_hold_ec_hook, 0 );
    atomic_store( &test_release_ec_hook, 1 );
    unregister_identity_page( stack );
    unregister_identity_page( code );
}

static void test_prestart_mutation_barrier(void)
{
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct simulation simulation = {0};
    struct protect_worker worker =
    {
        .params =
        {
            .guest = (uintptr_t)code,
            .size = TEST_PAGE,
            .protect = PAGE_EXECUTE_READWRITE,
        },
    };
    volatile uint32_t *doorbell = test_suspend_doorbell();
    pthread_t runner, mutator;
    BOOL runner_created = FALSE, mutator_created = FALSE;
    BOOL entered = FALSE, waiting = FALSE, mutation_done = FALSE;
    unsigned int starting_failures = failures;
    unsigned int pause_count;
    int ret;

    memset( code, 0, TEST_PAGE );
    code[0] = 0xf3; code[1] = 0x90; /* pause */
    code[2] = 0xeb; code[3] = 0xfc; /* jmp code */
    check( !register_identity_page( code, PAGE_EXECUTE_READ ),
           "prestart barrier code map failed\n" );
    check( !register_identity_page( stack, PAGE_READWRITE ),
           "prestart barrier stack map failed\n" );
    *doorbell = 0;
    atomic_store( &test_hold_engine_start, 1 );
    atomic_store( &test_engine_start_entered, 0 );
    atomic_store( &test_release_engine_start, 0 );
    atomic_store( &test_disable_pause_hook, 1 );
    atomic_store( &test_pause_stop_owner_violation, 0 );
    pause_count = atomic_load_explicit( &test_pause_stop_count,
                                        memory_order_relaxed );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );

    ret = pthread_create( &runner, NULL, run_simulation, &simulation );
    check( !ret, "prestart barrier runner creation failed %d\n", ret );
    runner_created = !ret;
    if (runner_created)
    {
        entered = wait_atomic_int_at_least( &test_engine_start_entered, 1, 2000 );
        check( entered, "simulation did not enter the prestart publication window\n" );
    }
    if (entered)
    {
        ret = pthread_create( &mutator, NULL, run_protect, &worker );
        check( !ret, "prestart barrier mutator creation failed %d\n", ret );
        mutator_created = !ret;
    }
    if (mutator_created)
    {
        waiting = wait_mutation_stage( MUTATION_STAGE_WAIT, 2000 );
        check( waiting, "prestart mutation did not wait for the published engine\n" );
        check( !atomic_load_explicit( &worker.done, memory_order_acquire ),
               "prestart mutation published before the engine could acknowledge\n" );
    }

    atomic_store_explicit( &test_hold_engine_start, 0, memory_order_release );
    atomic_store_explicit( &test_release_engine_start, 1, memory_order_release );
    if (mutator_created)
    {
        mutation_done = wait_atomic_int_at_least( &worker.done, 1, 2000 );
        if (!mutation_done) *doorbell = 1;
        pthread_join( mutator, NULL );
        check( mutation_done,
               "prestart boundary request was lost after uc_emu_start entry\n" );
        check( !worker.status, "prestart mutation returned %#x\n",
               (unsigned int)worker.status );
    }
    *doorbell = 1;
    if (runner_created)
    {
        check( join_simulation( runner, &simulation ),
               "prestart barrier simulation timed out\n" );
        check( !simulation.status &&
               simulation.params.stop_reason == XTAJIT64_STOP_SUSPEND,
               "prestart barrier returned %#x reason %u\n",
               (unsigned int)simulation.status, simulation.params.stop_reason );
    }
    check( atomic_load_explicit( &test_pause_stop_count,
                                 memory_order_relaxed ) == pause_count &&
           !atomic_load_explicit( &test_pause_stop_owner_violation,
                                  memory_order_acquire ),
           "prestart barrier relied on the diagnostic block-hook pause path\n" );

    *doorbell = 0;
    atomic_store( &test_hold_engine_start, 0 );
    atomic_store( &test_release_engine_start, 1 );
    atomic_store( &test_disable_pause_hook, 0 );
    unregister_identity_page( stack );
    unregister_identity_page( code );
    if (failures == starting_failures)
        printf( "XTAJIT64_PRESTART_MUTATION_BARRIER_PASS\n" );
}

static void test_late_stop_does_not_escape_engine_lease(void)
{
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct code_buffer buffer = { code, 0 };
    struct simulation first = {0}, second = {0};
    struct protect_worker worker =
    {
        .params =
        {
            .guest = (uintptr_t)code,
            .size = TEST_PAGE,
            .protect = PAGE_EXECUTE_READWRITE,
        },
    };
    struct thread_engine *first_engine = NULL;
    pthread_t first_runner, second_runner, mutator;
    BOOL first_created = FALSE, second_created = FALSE, mutator_created = FALSE;
    BOOL entered = FALSE, waiting = FALSE;
    unsigned int starting_failures = failures;
    NTSTATUS status;
    int ret;

    memset( code, 0, TEST_PAGE );
    emit_movabs_rax( &buffer, test_ec_target );
    emit_jump_rax( &buffer );
    status = register_identity_page( (void *)(uintptr_t)test_ec_target,
                                     PAGE_EXECUTE_READ );
    if (!status)
        status = register_identity_page( (void *)(uintptr_t)test_teb,
                                         PAGE_READWRITE );
    if (!status) status = register_identity_page( code, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    check( !status, "late-stop lease setup returned %#x\n", (unsigned int)status );
    if (status) goto done;

    atomic_store( &test_hold_engine_result, 1 );
    atomic_store( &test_engine_result_entered, 0 );
    atomic_store( &test_release_engine_result, 0 );
    atomic_store( &test_disable_pause_hook, 1 );
    initialize_begin_params( &first, (uintptr_t)code, (uintptr_t)stack );
    ret = pthread_create( &first_runner, NULL, run_simulation, &first );
    check( !ret, "late-stop first runner creation failed %d\n", ret );
    first_created = !ret;
    if (first_created)
    {
        entered = wait_atomic_int_at_least( &test_engine_result_entered, 1, 2000 );
        check( entered, "first engine did not enter the post-emulation window\n" );
        first_engine = test_last_acquired_engine;
    }
    if (entered)
    {
        ret = pthread_create( &mutator, NULL, run_protect, &worker );
        check( !ret, "late-stop mutator creation failed %d\n", ret );
        mutator_created = !ret;
    }
    if (mutator_created)
    {
        waiting = wait_mutation_stage( MUTATION_STAGE_WAIT, 2000 );
        check( waiting, "late-stop mutation did not wait for the published engine\n" );
        check( !atomic_load_explicit( &worker.done, memory_order_acquire ),
               "late-stop mutation published before the engine lease ended\n" );
    }

    atomic_store_explicit( &test_hold_engine_result, 0, memory_order_release );
    atomic_store_explicit( &test_release_engine_result, 1, memory_order_release );
    if (first_created)
    {
        check( join_simulation( first_runner, &first ),
               "late-stop first simulation timed out\n" );
        check( !first.status &&
               first.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION,
               "late-stop first simulation returned %#x reason %u\n",
               (unsigned int)first.status, first.params.stop_reason );
    }
    if (mutator_created)
    {
        pthread_join( mutator, NULL );
        check( !worker.status, "late-stop mutation returned %#x\n",
               (unsigned int)worker.status );
    }

    initialize_begin_params( &second, (uintptr_t)code, (uintptr_t)stack );
    ret = pthread_create( &second_runner, NULL, run_simulation, &second );
    check( !ret, "late-stop second runner creation failed %d\n", ret );
    second_created = !ret;
    if (second_created)
    {
        check( join_simulation( second_runner, &second ),
               "late-stop second simulation timed out\n" );
        check( test_last_acquired_engine == first_engine &&
               !second.status &&
               second.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION,
               "late stop escaped into reused engine %p/%p status %#x reason %u\n",
               (void *)first_engine, (void *)test_last_acquired_engine,
               (unsigned int)second.status, second.params.stop_reason );
    }

done:
    atomic_store( &test_hold_engine_result, 0 );
    atomic_store( &test_release_engine_result, 1 );
    atomic_store( &test_disable_pause_hook, 0 );
    /* Reset even after the expected red result so this contract test cannot
     * leave a poisoned provider or stale mappings for process cleanup. */
    check( !reset_test_provider(), "reset after late-stop lease test failed\n" );
    if (failures == starting_failures)
        printf( "XTAJIT64_LATE_STOP_LEASE_PASS\n" );
}

static void test_suspend_doorbell_mutation_barrier(void)
{
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct code_buffer buffer = { code, 0 };
    struct simulation simulation = {0}, resumed = {0};
    struct protect_worker worker =
    {
        .params =
        {
            .guest = (uintptr_t)code,
            .size = TEST_PAGE,
            .protect = PAGE_EXECUTE_READWRITE,
        },
    };
    volatile uint32_t *doorbell = test_suspend_doorbell();
    BOOL runner_created = FALSE, mutator_created = FALSE, entered = FALSE;
    unsigned int starting_failures = failures;
    pthread_t runner, mutator;
    uint64_t initial_rsp;
    NTSTATUS status;
    int ret;

    memset( code, 0, TEST_PAGE );
    emit_movabs_rax( &buffer, test_ec_target );
    emit_u8( &buffer, 0x50 ); /* push %rax */
    emit_jump_rax( &buffer );
    *doorbell = 0;
    status = register_identity_page( code, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    check( !status, "suspend doorbell barrier setup returned %#x\n",
           (unsigned int)status );
    if (status) goto done;

    atomic_store( &test_hold_non_ec_hook, 1 );
    atomic_store( &test_non_ec_hook_entered, 0 );
    atomic_store( &test_release_non_ec_hook, 0 );
    atomic_store( &test_pause_stop_owner_violation, 0 );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    ret = pthread_create( &runner, NULL, run_simulation, &simulation );
    check( !ret, "suspend doorbell runner creation failed %d\n", ret );
    if (ret) goto release;
    runner_created = TRUE;
    entered = wait_atomic_int_at_least( &test_non_ec_hook_entered, 1, 2000 );
    check( entered, "suspend doorbell runner did not enter the held block\n" );
    if (!entered) goto release;

    ret = pthread_create( &mutator, NULL, run_protect, &worker );
    check( !ret, "suspend doorbell mutator creation failed %d\n", ret );
    if (ret) goto release;
    mutator_created = TRUE;
    check( wait_mutation_stage( MUTATION_STAGE_WAIT, 2000 ),
           "suspend doorbell mutation did not wait for the running engine\n" );
    *doorbell = ~0u;

release:
    atomic_store_explicit( &test_release_non_ec_hook, 1, memory_order_release );
    if (runner_created)
        check( join_simulation( runner, &simulation ),
               "suspend doorbell simulation timed out\n" );
    if (mutator_created) pthread_join( mutator, NULL );
    if (runner_created)
        check( !simulation.init_status && !simulation.status &&
               simulation.params.stop_reason == XTAJIT64_STOP_SUSPEND &&
               !atomic_load_explicit( &test_pause_stop_owner_violation,
                                      memory_order_acquire ),
               "suspend doorbell lost the captured stop %#x/%#x reason %u\n",
               (unsigned int)simulation.init_status,
               (unsigned int)simulation.status,
               simulation.params.stop_reason );
    if (runner_created)
        check( (simulation.params.context.rip == (uintptr_t)code &&
                simulation.params.context.rsp == initial_rsp) ||
               (simulation.params.context.rip == test_ec_target &&
                simulation.params.context.rsp == initial_rsp - sizeof(uint64_t) &&
                *(uint64_t *)(uintptr_t)simulation.params.context.rsp ==
                    test_ec_target),
               "suspend doorbell captured a replayable block context rip %#llx "
               "rsp %#llx value %#llx\n",
               (unsigned long long)simulation.params.context.rip,
               (unsigned long long)simulation.params.context.rsp,
               (unsigned long long)*(uint64_t *)(uintptr_t)
                   simulation.params.context.rsp );
    if (mutator_created)
        check( !worker.status &&
               atomic_load_explicit( &worker.done, memory_order_acquire ),
               "suspend doorbell mutation returned %#x\n",
               (unsigned int)worker.status );

    *doorbell = 0;
    status = thread_init( NULL );
    check( !status, "suspend doorbell resume init returned %#x\n",
           (unsigned int)status );
    if (!status)
    {
        resumed.params = simulation.params;
        status = begin_simulation( &resumed.params );
        check( !status &&
               resumed.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
               resumed.params.context.rsp == initial_rsp - sizeof(uint64_t),
               "cleared suspend doorbell did not resume captured context "
               "%#x reason %u rip %#llx rsp %#llx\n",
               (unsigned int)status, resumed.params.stop_reason,
               (unsigned long long)resumed.params.context.rip,
               (unsigned long long)resumed.params.context.rsp );
        thread_term( NULL );
    }

done:
    *doorbell = 0;
    atomic_store( &test_hold_non_ec_hook, 0 );
    atomic_store( &test_release_non_ec_hook, 1 );
    unregister_identity_page( stack );
    unregister_identity_page( code );
    if (failures == starting_failures)
        printf( "XTAJIT64_SUSPEND_DOORBELL_BARRIER_PASS\n" );
}

static void test_running_low_observer_barrier(void)
{
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct wine_arm64ec_low_memory_range_v1 full[3], free_range;
    struct code_buffer buffer = { code, 0 };
    struct simulation simulation = {0};
    struct low_observer_worker worker = {0};
    unsigned int pause_count;
    unsigned int starting_failures = failures;
    pthread_t runner, observer;
    BOOL entered;
    NTSTATUS status;

    initialize_low_range( &full[0], 0, TEST_LOW_GUEST_BASE, 0,
                          MEM_FREE, PAGE_NOACCESS );
    initialize_low_range( &full[1], TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READWRITE );
    initialize_low_range( &full[2], TEST_LOW_GUEST_BASE + TEST_PAGE,
                          WINE_LOW_VA_SHADOW_SIZE - TEST_LOW_GUEST_BASE - TEST_PAGE,
                          0, MEM_FREE, PAGE_NOACCESS );
    status = publish_low_event( WINE_WOW64_MEMORY_RESYNC,
                                WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT,
                                0, WINE_LOW_VA_SHADOW_SIZE, 0, full, 3,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status, "LOW barrier setup snapshot returned %#x\n",
           (unsigned int)status );
    if (status) return;

    memset( code, 0, TEST_PAGE );
    emit_movabs_rax( &buffer, test_ec_target );
    emit_jump_rax( &buffer );
    check( !register_identity_page( code, PAGE_EXECUTE_READ ),
           "LOW barrier code map failed\n" );
    check( !register_identity_page( stack, PAGE_READWRITE ),
           "LOW barrier stack map failed\n" );

    initialize_low_range( &worker.range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READONLY );
    initialize_low_event( &worker.event, WINE_WOW64_MEMORY_PROTECT, 0,
                          TEST_LOW_GUEST_BASE, TEST_PAGE, TEST_LOW_GUEST_BASE,
                          &worker.range, 1, STATUS_SUCCESS, STATUS_SUCCESS );
    atomic_store( &test_hold_non_ec_hook, 1 );
    atomic_store( &test_non_ec_hook_entered, 0 );
    atomic_store( &test_release_non_ec_hook, 0 );
    atomic_store( &test_mutation_waiters, 0 );
    atomic_store( &test_pause_stop_owner_violation, 0 );
    pause_count = atomic_load_explicit( &test_pause_stop_count,
                                        memory_order_relaxed );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    pthread_create( &runner, NULL, run_simulation, &simulation );
    entered = wait_atomic_int_at_least( &test_non_ec_hook_entered, 1, 2000 );
    check( entered, "simulation did not enter held non-EC hook\n" );
    if (entered)
    {
        pthread_create( &observer, NULL, run_low_observer, &worker );
        check( wait_mutation_stage( MUTATION_STAGE_WAIT, 2000 ),
               "LOW observer did not wait for the running engine\n" );
        check( !atomic_load_explicit( &worker.begun, memory_order_acquire ) &&
               !atomic_load_explicit( &worker.done, memory_order_acquire ),
               "LOW observer returned before the running engine quiesced\n" );
        atomic_store_explicit( &test_release_non_ec_hook, 1,
                               memory_order_release );
        pthread_join( observer, NULL );
        check( !worker.status &&
               canonical_range_matches( TEST_LOW_GUEST_BASE,
                                        TEST_LOW_HOST_BASE, MEM_COMMIT,
                                        UC_PROT_READ,
                                        XTAJIT64_MEMORY_ADDRESS_AMD64_LOW,
                                        FALSE ),
               "LOW observer barrier publish returned %#x\n",
               (unsigned int)worker.status );
    }
    else atomic_store_explicit( &test_release_non_ec_hook, 1,
                                memory_order_release );
    check( join_simulation( runner, &simulation ),
           "LOW barrier simulation timed out\n" );
    check( !simulation.status &&
           simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           atomic_load_explicit( &test_pause_stop_count,
                                 memory_order_relaxed ) == pause_count + 1 &&
           !atomic_load_explicit( &test_pause_stop_owner_violation,
                                  memory_order_acquire ),
           "LOW barrier lost owner-thread pause or EC stop %#x/%u\n",
           (unsigned int)simulation.status, simulation.params.stop_reason );
    atomic_store( &test_hold_non_ec_hook, 0 );
    atomic_store( &test_release_non_ec_hook, 1 );
    unregister_identity_page( stack );
    unregister_identity_page( code );

    initialize_low_range( &free_range, 0, WINE_LOW_VA_SHADOW_SIZE, 0,
                          MEM_FREE, PAGE_NOACCESS );
    status = publish_low_event( WINE_WOW64_MEMORY_RESYNC,
                                WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT,
                                0, WINE_LOW_VA_SHADOW_SIZE, 0, &free_range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status, "LOW barrier cleanup snapshot returned %#x\n",
           (unsigned int)status );
    if (failures == starting_failures)
        printf( "XTAJIT64_LOW_OBSERVER_BARRIER_PASS\n" );
}

static void test_running_code_observer_barrier(void)
{
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct code_buffer buffer = { code, 0 };
    struct simulation simulation = {0};
    struct code_observer_worker worker = {0}, cleanup = {0};
    uint64_t page = (uintptr_t)code / TEST_PAGE;
    uint64_t *bitmap = (uint64_t *)(uintptr_t)process_params.ec_bitmap;
    size_t engine_count;
    unsigned int pause_count;
    unsigned int starting_failures = failures;
    pthread_t runner, observer;
    BOOL runner_created = FALSE, observer_created = FALSE, entered = FALSE;
    NTSTATUS status;
    int ret;

    memset( code, 0, TEST_PAGE );
    emit_movabs_rax( &buffer, test_ec_target );
    emit_jump_rax( &buffer );
    status = register_identity_page( code, PAGE_EXECUTE_READ );
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    check( !status, "code observer barrier setup returned %#x\n",
           (unsigned int)status );
    if (status) goto done;
    check( !is_ec_code( (uintptr_t)code ),
           "code observer barrier page started as EC code\n" );

    worker.range.address = (uintptr_t)code;
    worker.range.size = TEST_PAGE;
    worker.bitmap_word = bitmap + page / 64;
    worker.bitmap_mask = 1ull << (page & 63);
    worker.set_ec = TRUE;
    initialize_code_event( &worker.event, WINE_ARM64EC_CODE_MAP, 0,
                           &worker.range, 1, STATUS_SUCCESS );

    atomic_store( &test_hold_non_ec_hook, 1 );
    atomic_store( &test_non_ec_hook_entered, 0 );
    atomic_store( &test_release_non_ec_hook, 0 );
    atomic_store( &test_pause_stop_owner_violation, 0 );
    pause_count = atomic_load_explicit( &test_pause_stop_count,
                                        memory_order_relaxed );
    reset_cache_recorders();
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    ret = pthread_create( &runner, NULL, run_simulation, &simulation );
    check( !ret, "code observer barrier runner creation failed %d\n", ret );
    if (ret) goto release;
    runner_created = TRUE;
    entered = wait_atomic_int_at_least( &test_non_ec_hook_entered, 1, 2000 );
    check( entered, "code observer barrier did not enter the held block\n" );
    if (!entered) goto release;

    engine_count = provider_engine_count();
    ret = pthread_create( &observer, NULL, run_code_observer, &worker );
    check( !ret, "code observer barrier worker creation failed %d\n", ret );
    if (ret) goto release;
    observer_created = TRUE;
    check( wait_mutation_stage( MUTATION_STAGE_WAIT, 2000 ),
           "code observer did not wait for the running engine\n" );
    check( !atomic_load_explicit( &worker.begun, memory_order_acquire ) &&
           !atomic_load_explicit( &worker.done, memory_order_acquire ) &&
           !is_ec_code( (uintptr_t)code ),
           "code observer mutated the bitmap before the engine quiesced\n" );

release:
    atomic_store_explicit( &test_release_non_ec_hook, 1, memory_order_release );
    if (observer_created) pthread_join( observer, NULL );
    if (runner_created)
        check( join_simulation( runner, &simulation ),
               "code observer barrier simulation timed out\n" );
    if (observer_created)
        check( !worker.status && is_ec_code( (uintptr_t)code ) &&
               tlb_flush_calls == engine_count &&
               cache_remove_calls == engine_count && !cache_flush_calls,
               "code observer barrier publish returned %#x with "
               "TLB/remove/full %u/%u/%u for %zu engines\n",
               (unsigned int)worker.status, tlb_flush_calls,
               cache_remove_calls, cache_flush_calls, engine_count );
    if (runner_created)
        check( !simulation.init_status && !simulation.status &&
               simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
               simulation.params.transition_target >= (uintptr_t)code &&
               simulation.params.transition_target <
                   (uintptr_t)code + TEST_PAGE &&
               atomic_load_explicit( &test_pause_stop_count,
                                     memory_order_relaxed ) == pause_count + 1 &&
               !atomic_load_explicit( &test_pause_stop_owner_violation,
                                      memory_order_acquire ),
               "code observer barrier lost reclassification %#x/%#x reason %u "
               "target %#llx\n", (unsigned int)simulation.init_status,
               (unsigned int)simulation.status, simulation.params.stop_reason,
               (unsigned long long)simulation.params.transition_target );

    if (__atomic_load_n( worker.bitmap_word, __ATOMIC_ACQUIRE ) &
        worker.bitmap_mask)
    {
        cleanup.range = worker.range;
        cleanup.bitmap_word = worker.bitmap_word;
        cleanup.bitmap_mask = worker.bitmap_mask;
        initialize_code_event( &cleanup.event, WINE_ARM64EC_CODE_UNMAP, 0,
                               &cleanup.range, 1, STATUS_SUCCESS );
        run_code_observer( &cleanup );
        check( !cleanup.status && !is_ec_code( (uintptr_t)code ),
               "code observer barrier cleanup returned %#x\n",
               (unsigned int)cleanup.status );
    }

done:
    atomic_store( &test_hold_non_ec_hook, 0 );
    atomic_store( &test_release_non_ec_hook, 1 );
    unregister_identity_page( stack );
    unregister_identity_page( code );
    reset_cache_recorders();
    if (failures == starting_failures)
        printf( "XTAJIT64_CODE_OBSERVER_BARRIER_PASS\n" );
}

static void test_running_flush_preflight_failure(void)
{
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    struct wine_arm64ec_low_memory_range_v1 range;
    struct code_buffer buffer = { code, 0 };
    struct simulation simulation = {0};
    struct flush_worker worker =
    {
        .params =
        {
            .guest = TEST_LOW_GUEST_BASE + 0x40,
            .size = 0x80,
        },
    };
    pthread_t runner, flusher;
    BOOL runner_created = FALSE, flusher_created = FALSE;
    BOOL entered = FALSE, prompt = FALSE;
    uint64_t generation = 0;
    size_t range_count = 0;
    unsigned int pause_count = 0;
    unsigned int starting_failures = failures;
    NTSTATUS status;
    int ret;

    initialize_low_range( &range, TEST_LOW_GUEST_BASE, TEST_PAGE,
                          TEST_LOW_GUEST_BASE, MEM_COMMIT, PAGE_READONLY );
    status = publish_low_event( WINE_WOW64_MEMORY_ALLOCATE, 0,
                                TEST_LOW_GUEST_BASE, TEST_PAGE,
                                TEST_LOW_GUEST_BASE, &range, 1,
                                STATUS_SUCCESS, STATUS_SUCCESS );
    check( !status, "flush preflight LOW setup returned %#x\n",
           (unsigned int)status );
    if (status) goto done;

    memset( code, 0, TEST_PAGE );
    emit_movabs_rax( &buffer, test_ec_target );
    emit_jump_rax( &buffer );
    check( !register_identity_page( code, PAGE_EXECUTE_READ ),
           "flush preflight code map failed\n" );
    check( !register_identity_page( stack, PAGE_READWRITE ),
           "flush preflight stack map failed\n" );
    if (failures != starting_failures) goto done;

    atomic_store( &test_hold_ec_hook, 1 );
    atomic_store( &test_ec_hook_entered, 0 );
    atomic_store( &test_release_ec_hook, 0 );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    ret = pthread_create( &runner, NULL, run_simulation, &simulation );
    check( !ret, "flush preflight runner creation failed %d\n", ret );
    if (!ret)
    {
        runner_created = TRUE;
        entered = wait_atomic_int_at_least( &test_ec_hook_entered, 1, 2000 );
        check( entered, "flush preflight runner did not enter the held EC hook\n" );
    }
    if (!entered) goto release;

    generation = observer_generation();
    pthread_mutex_lock( &provider.mutex );
    range_count = provider.ranges.count;
    pthread_mutex_unlock( &provider.mutex );
    pause_count = atomic_load_explicit( &test_pause_stop_count,
                                        memory_order_relaxed );
    reset_cache_recorders();
    test_flush_interval_append_count = 0;
    test_fail_flush_interval_append = 0;
    ret = pthread_create( &flusher, NULL, run_flush, &worker );
    check( !ret, "flush preflight worker creation failed %d\n", ret );
    if (!ret)
    {
        flusher_created = TRUE;
        prompt = wait_atomic_int_at_least( &worker.done, 1, 1000 );
        check( prompt,
               "flush preflight failure waited on an engine that was never paused\n" );
    }

release:
    atomic_store_explicit( &test_release_ec_hook, 1, memory_order_release );
    if (flusher_created) pthread_join( flusher, NULL );
    test_fail_flush_interval_append = -1;
    if (runner_created)
        check( join_simulation( runner, &simulation ),
               "flush preflight simulation timed out\n" );
    atomic_store( &test_hold_ec_hook, 0 );
    atomic_store( &test_release_ec_hook, 1 );

    if (flusher_created)
    {
        check( prompt && worker.status == STATUS_NO_MEMORY &&
               test_flush_interval_append_count == 1,
               "flush preflight failure returned prompt/status/count %u/%#x/%d\n",
               prompt, (unsigned int)worker.status,
               test_flush_interval_append_count );
        check( !cache_remove_calls && !cache_flush_calls,
               "flush preflight failure touched remove/full cache %u/%u\n",
               cache_remove_calls, cache_flush_calls );
        check( !observer_provider_status() &&
               observer_generation() == generation && canonical_range_matches(
                   TEST_LOW_GUEST_BASE, TEST_LOW_HOST_BASE, MEM_COMMIT,
                   UC_PROT_READ, XTAJIT64_MEMORY_ADDRESS_AMD64_LOW, FALSE ),
               "flush preflight failure poisoned or changed the registry %#x\n",
               (unsigned int)observer_provider_status() );
        pthread_mutex_lock( &provider.mutex );
        check( provider.ranges.count == range_count && !provider.mutating &&
               !provider.mutation_owner_valid &&
               provider.mutation_stage == MUTATION_STAGE_IDLE &&
               !provider.observer_transaction,
               "flush preflight failure retained mutation ownership\n" );
        pthread_mutex_unlock( &provider.mutex );
        check( atomic_load_explicit( &test_pause_stop_count,
                                     memory_order_relaxed ) == pause_count,
               "flush preflight failure requested an engine pause\n" );

        status = thread_init( NULL );
        check( !status, "flush preflight retry engine init returned %#x\n",
               (unsigned int)status );
        if (!status)
        {
            size_t engine_count = provider_engine_count();

            reset_cache_recorders();
            status = flush_instruction_cache( &worker.params );
            check( !status && cache_remove_calls == engine_count &&
                   !cache_flush_calls &&
                   cache_remove_start == worker.params.guest &&
                   cache_remove_end == worker.params.guest + worker.params.size,
                   "flush preflight retry returned %#x remove/full %#x-%#x %u/%u engines %zu\n",
                   (unsigned int)status, (unsigned int)cache_remove_start,
                   (unsigned int)cache_remove_end, cache_remove_calls,
                   cache_flush_calls, engine_count );
            thread_term( NULL );
        }
    }

done:
    test_fail_flush_interval_append = -1;
    reset_cache_recorders();
    check( !reset_test_provider(), "reset after flush preflight failure failed\n" );
    if (failures == starting_failures)
        printf( "XTAJIT64_FLUSH_PREFLIGHT_FAILURE_PASS\n" );
}

#if defined(__APPLE__) && defined(XTAJIT64_TEST_EC_LEAF_FASTPATH)
static void test_ec_leaf_fastpath(void)
{
    static const uint32_t thread_id_load = 0xb9404a40;  /* ldr w0,[x18,#0x48] */
    static const uint32_t last_error_load = 0xb9406a40; /* ldr w0,[x18,#0x68] */
    static const uint32_t last_status_load = 0xb9525240; /* ldr w0,[x18,#0x1250] */
    static const uint32_t tls_get_value[] =
    {
        0x7100fc1f, 0xb9006a5f, 0x54000088, 0x8b204e48,
        0xf94a4100, 0xd65f03c0, 0xaa1f03e0, 0xd65f03c0,
    };
    static const uint32_t tls_get_value2[] =
    {
        0x7100fc1f, 0x54000088, 0x8b204e48, 0xf94a4100,
        0xd65f03c0, 0xaa1f03e0, 0xd65f03c0,
    };
    static const uint32_t rtl_query_performance_counter[] =
    {
        0xf81f0ffe, 0xaa1f03e1, 0x9400000e, 0x52800020,
        0xf84107fe, 0xd65f03c0,
    };
    static const uint32_t nt_query_performance_counter[] =
    {
        0xd2800628, 0xaa1e03e9, 0x58000090, 0xf9400210,
        0xd63f0200, 0xd65f03c0,
    };
    static const uint32_t nt_query_performance_counter_hybrid_thunk[] =
    {
        0xf81f0ffe, 0x90000008, 0xb000000b, 0x9102016b,
        0xf940c108, 0x9000000a, 0x9106214a, 0x90000009,
        0x91064129, 0xd63f0100, 0xf84107fe, 0xd61f0160,
    };
    static const uint32_t ret = 0xd65f03c0;
    const uint64_t preserved_rbx = 0x91f0c2d4e6a8b357ull;
    const uint64_t tls_value = 0x8c7b6a5948372615ull;
    const uint32_t tls_index = 7;
    const uint32_t invalid_tls_index = XTAJIT64_TEB_TLS_SLOT_COUNT;
    const uint32_t thread_id = 0x7a35;
    const uint32_t last_error = 0x5319;
    const uint32_t last_status = 0xc0000005;
    unsigned char *code = test_pages + 3 * TEST_PAGE;
    unsigned char *stack = test_pages + 4 * TEST_PAGE;
    unsigned char *counter = test_pages + 5 * TEST_PAGE;
    uint64_t target = test_ec_target;
    uint64_t terminal = target + 0x100;
    uint64_t hybrid_x64_target = target + 0x1000 + 0x80;
    const uint64_t invalid_counter = test_base + 13 * TEST_PAGE;
    const uint64_t counter_sentinel = 0x4a3d6c91e7502bf8ull;
    struct code_buffer buffer = {code, 0};
    struct xtajit64_memory_params flush =
    {
        .guest = target,
        .size = 0x400,
    };
    struct xtajit64_memory_params code_flush = {0};
    struct simulation simulation = {0};
    uint64_t initial_rsp, generation, qpc_before, qpc_after, counter_address;
    size_t tls_index_offset;
    unsigned int i, starting_failures = failures;
    BOOL target_mapped = FALSE, teb_mapped = FALSE;
    BOOL code_mapped = FALSE, stack_mapped = FALSE, counter_mapped = FALSE;
    BOOL thread_initialized = FALSE, fastpath_enabled = FALSE;
    NTSTATUS status;

    memset( code, 0, TEST_PAGE );
    memset( stack, 0, TEST_PAGE );
    memset( counter, 0, TEST_PAGE );
    memset( (void *)(uintptr_t)target, 0, 0x400 );
    *(uint32_t *)(uintptr_t)target = thread_id_load;
    *(uint32_t *)(uintptr_t)(target + sizeof(uint32_t)) = ret;
    *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_THREAD_ID_OFFSET) = thread_id;
    *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET) = last_error;
    *(uint32_t *)(uintptr_t)(test_teb + 0x1250) = last_status;
    *(uint64_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_TLS_SLOTS_OFFSET +
                             tls_index * sizeof(uint64_t)) = tls_value;
    emit_movabs_rbx( &buffer, preserved_rbx );
    tls_index_offset = buffer.offset + 2;
    emit_movabs_rcx( &buffer, tls_index );
    emit_movabs_rax( &buffer, target );
    emit_call_rax( &buffer );
    emit_movabs_rdx( &buffer, terminal );
    emit_jump_rdx( &buffer );
    code_flush.guest = (uintptr_t)code;
    code_flush.size = 0x210;


    status = register_identity_page( (void *)(uintptr_t)target, PAGE_EXECUTE_READ );
    if (!status) target_mapped = TRUE;
    if (!status) status = register_identity_page( (void *)(uintptr_t)test_teb, PAGE_READWRITE );
    if (!status) teb_mapped = TRUE;
    if (!status) status = register_identity_page( code, PAGE_EXECUTE_READ );
    if (!status) code_mapped = TRUE;
    if (!status) status = register_identity_page( stack, PAGE_READWRITE );
    if (!status) stack_mapped = TRUE;
    if (!status) status = register_identity_page( counter, PAGE_READWRITE );
    if (!status) counter_mapped = TRUE;
    if (!status) status = thread_init( NULL );
    check( !status, "EC leaf fastpath setup returned %#x\n", (unsigned int)status );
    if (status) goto done;
    thread_initialized = TRUE;

    pthread_mutex_lock( &provider.mutex );
    provider.ec_leaf_fastpath_enabled = TRUE;
    provider.ec_leaf_fastpath_stats_enabled = TRUE;
    advance_ec_leaf_fastpath_code_generation_locked();
    atomic_store_explicit( &provider.ec_leaf_fastpath_attempts, 0, memory_order_relaxed );
    atomic_store_explicit( &provider.ec_leaf_fastpath_hits, 0, memory_order_relaxed );
    atomic_store_explicit( &provider.ec_leaf_fastpath_unsupported, 0,
                           memory_order_relaxed );
    atomic_store_explicit( &provider.ec_leaf_fastpath_register_failures, 0,
                           memory_order_relaxed );
    atomic_store_explicit( &provider.ec_leaf_fastpath_memory_failures, 0,
                           memory_order_relaxed );
    atomic_store_explicit( &provider.ec_leaf_fastpath_stack_failures, 0,
                           memory_order_relaxed );
    atomic_store_explicit( &provider.ec_leaf_fastpath_write_failures, 0,
                           memory_order_relaxed );
    for (i = 0; i < EC_LEAF_FASTPATH_KIND_COUNT; ++i)
        atomic_store_explicit( &provider.ec_leaf_fastpath_hits_by_kind[i], 0,
                               memory_order_relaxed );
    pthread_mutex_unlock( &provider.mutex );
    fastpath_enabled = TRUE;

    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == terminal &&
           simulation.params.context.rax == thread_id &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp &&
           simulation.params.context.eflags == 0x202,
           "thread-id EC leaf fastpath returned %#x stop %u target %#llx "
           "rax %#llx rbx %#llx rsp %#llx flags %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags );
    check( atomic_load_explicit( &provider.ec_leaf_fastpath_attempts,
                                 memory_order_relaxed ) == 2 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits,
                                 memory_order_relaxed ) == 1 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_unsupported,
                                 memory_order_relaxed ) == 1,
           "thread-id EC leaf fastpath counters are incorrect\n" );

    *(uint32_t *)(uintptr_t)target = last_error_load;
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "EC leaf fastpath code flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == terminal &&
           simulation.params.context.rax == last_error &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp &&
           simulation.params.context.eflags == 0x202,
           "last-error EC leaf fastpath returned %#x stop %u target %#llx "
           "rax %#llx rbx %#llx rsp %#llx flags %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags );
    check( atomic_load_explicit( &provider.ec_leaf_fastpath_attempts,
                                 memory_order_relaxed ) == 4 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits,
                                 memory_order_relaxed ) == 2 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_unsupported,
                                 memory_order_relaxed ) == 2 &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_register_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_memory_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_stack_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_write_failures,
                                  memory_order_relaxed ),
           "last-error EC leaf fastpath counters are incorrect\n" );

    *(uint32_t *)(uintptr_t)target = last_status_load;
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "generic TEB EC leaf code flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == terminal &&
           simulation.params.context.rax == last_status &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp &&
           simulation.params.context.eflags == 0x202,
           "generic TEB EC leaf returned %#x stop %u target %#llx "
           "rax %#llx rbx %#llx rsp %#llx flags %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags );
    check( atomic_load_explicit( &provider.ec_leaf_fastpath_attempts,
                                 memory_order_relaxed ) == 6 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits,
                                 memory_order_relaxed ) == 3 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_unsupported,
                                 memory_order_relaxed ) == 3 &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_register_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_memory_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_stack_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_write_failures,
                                  memory_order_relaxed ),
           "generic TEB EC leaf fastpath counters are incorrect\n" );

    memcpy( (void *)(uintptr_t)target, tls_get_value, sizeof(tls_get_value) );
    *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET) = last_error;
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "TlsGetValue EC leaf code flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == terminal &&
           simulation.params.context.rax == tls_value &&
           *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET) == 0 &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp &&
           simulation.params.context.eflags == 0x202,
           "TlsGetValue EC leaf returned %#x stop %u target %#llx rax %#llx "
           "last_error %#x rbx %#llx rsp %#llx flags %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET),
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags );
    check( atomic_load_explicit( &provider.ec_leaf_fastpath_attempts,
                                 memory_order_relaxed ) == 8 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits,
                                 memory_order_relaxed ) == 4 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_unsupported,
                                 memory_order_relaxed ) == 4,
           "TlsGetValue EC leaf fastpath counters are incorrect\n" );

    memcpy( (void *)(uintptr_t)target, tls_get_value2, sizeof(tls_get_value2) );
    *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET) = last_error;
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "TlsGetValue2 EC leaf code flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == terminal &&
           simulation.params.context.rax == tls_value &&
           *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET) == last_error &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp &&
           simulation.params.context.eflags == 0x202,
           "TlsGetValue2 EC leaf returned %#x stop %u target %#llx rax %#llx "
           "last_error %#x rbx %#llx rsp %#llx flags %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET),
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags );
    check( atomic_load_explicit( &provider.ec_leaf_fastpath_attempts,
                                 memory_order_relaxed ) == 10 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits,
                                 memory_order_relaxed ) == 5 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_unsupported,
                                 memory_order_relaxed ) == 5 &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_register_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_memory_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_stack_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_write_failures,
                                  memory_order_relaxed ),
           "TlsGetValue2 EC leaf fastpath counters are incorrect\n" );

    /* An out-of-range TLS index takes TlsGetValue's native ARM64EC branch.
     * The leaf shortcut must leave every visible state unchanged while it
     * declines that branch; in particular, the preceding LastError clear is
     * not allowed to become a partial emulation. */
    memcpy( code + tls_index_offset, &invalid_tls_index, sizeof(invalid_tls_index) );
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &code_flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "out-of-range TlsGetValue code flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET) = last_error;
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == target &&
           simulation.params.context.rax == target &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp - sizeof(uint64_t) &&
           simulation.params.context.eflags == 0x202 &&
           *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET) == last_error,
           "out-of-range TlsGetValue changed fallback state %#x stop %u target %#llx "
           "rax %#llx rbx %#llx rsp %#llx flags %#llx last_error %#x\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags,
           *(uint32_t *)(uintptr_t)(test_teb + XTAJIT64_TEB_LAST_ERROR_OFFSET) );
    check( atomic_load_explicit( &provider.ec_leaf_fastpath_attempts,
                                 memory_order_relaxed ) == 11 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits,
                                 memory_order_relaxed ) == 5 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_unsupported,
                                 memory_order_relaxed ) == 6 &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_register_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_memory_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_stack_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_write_failures,
                                  memory_order_relaxed ) &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                     EC_LEAF_FASTPATH_TEB_LOAD_W0 ],
                                 memory_order_relaxed ) == 3 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                     EC_LEAF_FASTPATH_TLS_GET_VALUE ],
                                 memory_order_relaxed ) == 1 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                     EC_LEAF_FASTPATH_TLS_GET_VALUE2 ],
                                 memory_order_relaxed ) == 1 &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                      EC_LEAF_FASTPATH_ROTL32 ], memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                      EC_LEAF_FASTPATH_ROTR32 ], memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                      EC_LEAF_FASTPATH_ROTL64 ], memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                      EC_LEAF_FASTPATH_ROTR64 ], memory_order_relaxed ),
           "out-of-range TlsGetValue fastpath counters are incorrect\n" );

    /* The QPC shortcut is target-authenticated through the process-init
     * contract and then validates both Wine ARM64EC wrappers.  It must write
     * the same 100 ns monotonic counter range as native ntdll while preserving
     * the x64 return contract. */
    memcpy( (void *)(uintptr_t)target, rtl_query_performance_counter,
            sizeof(rtl_query_performance_counter) );
    memcpy( (void *)(uintptr_t)(target + 0x40), nt_query_performance_counter,
            sizeof(nt_query_performance_counter) );
    counter_address = (uintptr_t)counter;
    memcpy( code + tls_index_offset, &counter_address, sizeof(counter_address) );
    *(uint64_t *)counter = counter_sentinel;
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "RtlQueryPerformanceCounter target flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &code_flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "RtlQueryPerformanceCounter caller flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    qpc_before = 0;
    check( query_ec_performance_counter( &qpc_before ),
           "cannot read reference RtlQueryPerformanceCounter value\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    qpc_after = 0;
    check( query_ec_performance_counter( &qpc_after ),
           "cannot read trailing RtlQueryPerformanceCounter value\n" );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == terminal &&
           simulation.params.context.rax == TRUE &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp &&
           simulation.params.context.eflags == 0x202 &&
           *(uint64_t *)counter >= qpc_before && *(uint64_t *)counter <= qpc_after,
           "RtlQueryPerformanceCounter EC fastpath returned %#x stop %u target %#llx "
           "rax %#llx rbx %#llx rsp %#llx flags %#llx counter %#llx range %#llx-%#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags,
           (unsigned long long)*(uint64_t *)counter,
           (unsigned long long)qpc_before, (unsigned long long)qpc_after );

    /* ARM64X normally routes this exact wrapper through a generic hybrid
     * patch thunk before branching to the raw x64 NtQueryPerformanceCounter
     * export.  The fast path must accept that checked topology too. */
    check( provider.nt_query_performance_counter == hybrid_x64_target,
           "raw x64 QPC target is %#llx instead of %#llx\n",
           (unsigned long long)provider.nt_query_performance_counter,
           (unsigned long long)hybrid_x64_target );
    memcpy( (void *)(uintptr_t)(target + 0x40),
            nt_query_performance_counter_hybrid_thunk,
            sizeof(nt_query_performance_counter_hybrid_thunk) );
    *(uint64_t *)counter = counter_sentinel;
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "RtlQueryPerformanceCounter hybrid target flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    qpc_before = 0;
    check( query_ec_performance_counter( &qpc_before ),
           "cannot read hybrid RtlQueryPerformanceCounter reference value\n" );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    qpc_after = 0;
    check( query_ec_performance_counter( &qpc_after ),
           "cannot read trailing hybrid RtlQueryPerformanceCounter value\n" );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == terminal &&
           simulation.params.context.rax == TRUE &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp &&
           simulation.params.context.eflags == 0x202 &&
           *(uint64_t *)counter >= qpc_before && *(uint64_t *)counter <= qpc_after,
           "hybrid RtlQueryPerformanceCounter EC fastpath returned %#x stop %u target %#llx "
           "rax %#llx rbx %#llx rsp %#llx flags %#llx counter %#llx range %#llx-%#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags,
           (unsigned long long)*(uint64_t *)counter,
           (unsigned long long)qpc_before, (unsigned long long)qpc_after );

    /* The generic bridge shape is insufficient on its own.  Its terminal
     * x64 branch must be the raw export authenticated in process_init. */
    *(uint32_t *)(uintptr_t)(target + 0x40 + 3 * sizeof(uint32_t)) = 0x9102416b;
    *(uint64_t *)counter = counter_sentinel;
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "mismatched hybrid QPC target flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == target &&
           simulation.params.context.rax == target &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp - sizeof(uint64_t) &&
           simulation.params.context.eflags == 0x202 &&
           *(uint64_t *)counter == counter_sentinel,
           "mismatched hybrid QPC target changed fallback state %#x stop %u target %#llx "
           "rax %#llx rbx %#llx rsp %#llx flags %#llx counter %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags,
           (unsigned long long)*(uint64_t *)counter );

    /* A valid code signature alone is not enough: the output destination is
     * checked before any return-state write.  An unavailable mapping must
     * retain the ordinary transition with no partial counter store. */
    memcpy( (void *)(uintptr_t)(target + 0x40), nt_query_performance_counter,
            sizeof(nt_query_performance_counter) );
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "restored RtlQueryPerformanceCounter target flush returned %#x generation %#llx/%#llx\n",
           (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    memcpy( code + tls_index_offset, &invalid_counter, sizeof(invalid_counter) );
    *(uint64_t *)counter = counter_sentinel;
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &code_flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "invalid RtlQueryPerformanceCounter caller flush returned %#x "
           "generation %#llx/%#llx\n", (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == target &&
           simulation.params.context.rax == target &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp - sizeof(uint64_t) &&
           simulation.params.context.eflags == 0x202 &&
           *(uint64_t *)counter == counter_sentinel,
           "invalid RtlQueryPerformanceCounter destination changed fallback state %#x "
           "stop %u target %#llx rax %#llx rbx %#llx rsp %#llx flags %#llx counter %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags,
           (unsigned long long)*(uint64_t *)counter );

    /* A code-observer generation change must invalidate the cached function
     * classification.  A patched target cannot be treated as Wine QPC merely
     * because its address is still the registered system export. */
    *(uint32_t *)(uintptr_t)target = 0xd503201f; /* nop */
    memcpy( code + tls_index_offset, &counter_address, sizeof(counter_address) );
    *(uint64_t *)counter = counter_sentinel;
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "patched RtlQueryPerformanceCounter target flush returned %#x "
           "generation %#llx/%#llx\n", (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    generation = provider.ec_leaf_fastpath_code_generation;
    status = flush_instruction_cache( &code_flush );
    check( !status && provider.ec_leaf_fastpath_code_generation != generation,
           "patched RtlQueryPerformanceCounter caller flush returned %#x "
           "generation %#llx/%#llx\n", (unsigned int)status,
           (unsigned long long)generation,
           (unsigned long long)provider.ec_leaf_fastpath_code_generation );
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    initial_rsp = simulation.params.context.rsp;
    status = begin_simulation( &simulation.params );
    check( !status && simulation.params.stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
           simulation.params.transition_target == target &&
           simulation.params.context.rax == target &&
           simulation.params.context.rbx == preserved_rbx &&
           simulation.params.context.rsp == initial_rsp - sizeof(uint64_t) &&
           simulation.params.context.eflags == 0x202 &&
           *(uint64_t *)counter == counter_sentinel,
           "patched RtlQueryPerformanceCounter target changed fallback state %#x "
           "stop %u target %#llx rax %#llx rbx %#llx rsp %#llx flags %#llx counter %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned long long)simulation.params.transition_target,
           (unsigned long long)simulation.params.context.rax,
           (unsigned long long)simulation.params.context.rbx,
           (unsigned long long)simulation.params.context.rsp,
           (unsigned long long)simulation.params.context.eflags,
           (unsigned long long)*(uint64_t *)counter );
    check( atomic_load_explicit( &provider.ec_leaf_fastpath_attempts,
                                 memory_order_relaxed ) == 18 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits,
                                 memory_order_relaxed ) == 7 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_unsupported,
                                 memory_order_relaxed ) == 10 &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_register_failures,
                                  memory_order_relaxed ) &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_memory_failures,
                                 memory_order_relaxed ) == 1 &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_stack_failures,
                                  memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_write_failures,
                                  memory_order_relaxed ) &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                     EC_LEAF_FASTPATH_TEB_LOAD_W0 ],
                                 memory_order_relaxed ) == 3 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                     EC_LEAF_FASTPATH_TLS_GET_VALUE ],
                                 memory_order_relaxed ) == 1 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                     EC_LEAF_FASTPATH_TLS_GET_VALUE2 ],
                                 memory_order_relaxed ) == 1 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                     EC_LEAF_FASTPATH_RTL_QUERY_PERFORMANCE_COUNTER ],
                                 memory_order_relaxed ) == 2 &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                      EC_LEAF_FASTPATH_ROTL32 ], memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                      EC_LEAF_FASTPATH_ROTR32 ], memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                      EC_LEAF_FASTPATH_ROTL64 ], memory_order_relaxed ) &&
           !atomic_load_explicit( &provider.ec_leaf_fastpath_hits_by_kind[
                                      EC_LEAF_FASTPATH_ROTR64 ], memory_order_relaxed ),
           "RtlQueryPerformanceCounter fastpath counters are incorrect "
           "attempts %#llx hits %#llx unsupported %#llx memory_fail %#llx qpc_hits %#llx\n",
           (unsigned long long)atomic_load_explicit( &provider.ec_leaf_fastpath_attempts,
                                                      memory_order_relaxed ),
           (unsigned long long)atomic_load_explicit( &provider.ec_leaf_fastpath_hits,
                                                      memory_order_relaxed ),
           (unsigned long long)atomic_load_explicit( &provider.ec_leaf_fastpath_unsupported,
                                                      memory_order_relaxed ),
           (unsigned long long)atomic_load_explicit(
               &provider.ec_leaf_fastpath_memory_failures, memory_order_relaxed ),
           (unsigned long long)atomic_load_explicit(
               &provider.ec_leaf_fastpath_hits_by_kind[
                   EC_LEAF_FASTPATH_RTL_QUERY_PERFORMANCE_COUNTER ], memory_order_relaxed ) );

    /* Once a leaf has stored guest output, a failed return-register commit
     * must poison the engine instead of falling back through the native leaf
     * with partially committed state. */
    memcpy( (void *)(uintptr_t)target, rtl_query_performance_counter,
            sizeof(rtl_query_performance_counter) );
    memcpy( (void *)(uintptr_t)(target + 0x40), nt_query_performance_counter,
            sizeof(nt_query_performance_counter) );
    memcpy( code + tls_index_offset, &counter_address, sizeof(counter_address) );
    *(uint64_t *)counter = counter_sentinel;
    status = flush_instruction_cache( &flush );
    check( !status, "write-failure QPC target flush returned %#x\n",
           (unsigned int)status );
    status = flush_instruction_cache( &code_flush );
    check( !status, "write-failure QPC caller flush returned %#x\n",
           (unsigned int)status );
    qpc_before = 0;
    check( query_ec_performance_counter( &qpc_before ),
           "cannot read write-failure QPC reference value\n" );
    reg_write_batch_fail_call = reg_write_batch_calls;
    initialize_begin_params( &simulation, (uintptr_t)code, (uintptr_t)stack );
    status = begin_simulation( &simulation.params );
    reg_write_batch_fail_call = -1;
    qpc_after = 0;
    check( query_ec_performance_counter( &qpc_after ),
           "cannot read trailing write-failure QPC reference value\n" );
    check( status == STATUS_UNSUCCESSFUL &&
           simulation.params.stop_reason == XTAJIT64_STOP_INTERNAL_ERROR &&
           provider.poison_status == STATUS_UNSUCCESSFUL &&
           *(uint64_t *)counter >= qpc_before && *(uint64_t *)counter <= qpc_after &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_write_failures,
                                 memory_order_relaxed ) == 1 &&
           atomic_load_explicit( &provider.ec_leaf_fastpath_hits,
                                 memory_order_relaxed ) == 7,
           "QPC return-write failure did not fail closed status %#x stop %u "
           "poison %#x counter %#llx range %#llx-%#llx writes %#llx hits %#llx\n",
           (unsigned int)status, simulation.params.stop_reason,
           (unsigned int)provider.poison_status,
           (unsigned long long)*(uint64_t *)counter,
           (unsigned long long)qpc_before, (unsigned long long)qpc_after,
           (unsigned long long)atomic_load_explicit(
               &provider.ec_leaf_fastpath_write_failures, memory_order_relaxed ),
           (unsigned long long)atomic_load_explicit(
               &provider.ec_leaf_fastpath_hits, memory_order_relaxed ) );

done:
    if (fastpath_enabled)
    {
        pthread_mutex_lock( &provider.mutex );
        provider.ec_leaf_fastpath_enabled = FALSE;
        provider.ec_leaf_fastpath_stats_enabled = FALSE;
        pthread_mutex_unlock( &provider.mutex );
    }
    if (thread_initialized) thread_term( NULL );
    if (counter_mapped) unregister_identity_page( counter );
    if (stack_mapped) unregister_identity_page( stack );
    if (code_mapped) unregister_identity_page( code );
    if (teb_mapped) unregister_identity_page( (void *)(uintptr_t)test_teb );
    if (target_mapped) unregister_identity_page( (void *)(uintptr_t)target );
    if (failures == starting_failures)
        printf( "XTAJIT64_EC_LEAF_FASTPATH_PASS\n" );
}
#endif


/* E31: a foreign transaction must serialize; same-owner recursion must fail. */
struct e31_observer_worker { atomic_int entered, done; NTSTATUS status; };
static void *e31_run_observer(void *arg)
{
    struct e31_observer_worker *w = arg;
    atomic_store(&w->entered, 1);
    w->status = publish_code_event(WINE_ARM64EC_CODE_ALLOCATE, 0, NULL, 0, 0);
    atomic_store(&w->done, 1);
    return NULL;
}
static void e31_test_observer_contention(void)
{
    struct e31_observer_worker w = {0};
    struct wine_arm64ec_code_event_v1 event;
    pthread_t thread;
    void *first = NULL, *nested = NULL;
    NTSTATUS status;
    unsigned int before = failures;
    int created;
    status = arm64ec_code_observer.begin(arm64ec_code_observer.context,
                                         WINE_ARM64EC_CODE_ALLOCATE, &first);
    check(!status, "E31 first begin failed %#x\n", status);
    if (status) return;
    status = arm64ec_code_observer.begin(arm64ec_code_observer.context,
                                         WINE_ARM64EC_CODE_ALLOCATE, &nested);
    check(status == STATUS_INVALID_DEVICE_STATE && !nested,
          "E31 same-owner recursion was not rejected %#x\n", status);
    created = !pthread_create(&thread, NULL, e31_run_observer, &w);
    check(created, "E31 could not create waiter\n");
    if (created)
    {
        check(wait_atomic_int_at_least(&w.entered, 1, 5000), "E31 waiter did not enter\n");
        check(!wait_atomic_int_at_least(&w.done, 1, 100),
              "E31 foreign transaction rejected instead of waiting %#x\n", w.status);
    }
    initialize_code_event(&event, WINE_ARM64EC_CODE_ALLOCATE, 0, NULL, 0, 0);
    arm64ec_code_observer.complete(arm64ec_code_observer.context, first, &event);
    if (created)
    {
        check(wait_atomic_int_at_least(&w.done, 1, 5000), "E31 waiter did not finish\n");
        pthread_join(thread, NULL);
        check(!w.status, "E31 foreign begin failed after release %#x\n", w.status);
    }
    if (failures == before) puts("E31_OBSERVER_CONTENTION_PASS");
}

int main(void)
{
    uint64_t highest, page;
    uint64_t *bitmap;
    size_t bitmap_size;
    NTSTATUS status;

    test_pages = alloc_preferred_pages( TEST_PREFERRED_BASE, TEST_FALLBACK_BASE,
                                        TEST_PAGE_COUNT );
    test_kuser = alloc_preferred_pages( TEST_PREFERRED_KUSER, TEST_FALLBACK_KUSER, 1 );
    test_low_pages = alloc_pages_at( TEST_LOW_HOST_BASE, TEST_LOW_PAGE_COUNT );
    if (!test_pages) test_pages = alloc_pages_at( TEST_ASAN_BASE, TEST_PAGE_COUNT );
    if (!test_kuser) test_kuser = alloc_pages_at( TEST_ASAN_KUSER, 1 );
    check( test_pages && test_kuser && test_low_pages,
           "provider test address allocation failed pages %p KUSER %p LOW %p\n",
           test_pages, test_kuser, test_low_pages );
    if (!test_pages || !test_kuser || !test_low_pages) return 1;
    test_base = (uintptr_t)test_pages;
    test_ec_target = test_base;
    test_syscall_dispatcher = test_base + TEST_PAGE;
    test_teb = test_base + 2 * TEST_PAGE;
    highest = max( test_base + TEST_PAGE_COUNT * TEST_PAGE,
                   (uint64_t)(uintptr_t)test_kuser + TEST_PAGE ) - 1;
    highest = max( highest + 1,
                   (uint64_t)(uintptr_t)test_low_pages +
                   TEST_LOW_PAGE_COUNT * TEST_PAGE ) - 1;
    bitmap_size = ((highest / TEST_PAGE + 63) / 64) * sizeof(*bitmap);
    check( bitmap_size && bitmap_size <= 32 * 1024 * 1024,
           "EC bitmap size %lu is outside the test bound\n",
           (unsigned long)bitmap_size );
    bitmap = bitmap_size <= 32 * 1024 * 1024 ? calloc( 1, bitmap_size ) : NULL;
    if (!bitmap) return 1;
    page = test_ec_target / TEST_PAGE;
    bitmap[page / 64] |= 1ull << (page & 63);
    build_syscall_dispatcher_code( (void *)(uintptr_t)test_syscall_dispatcher );

    process_params.ec_bitmap = (uintptr_t)bitmap;
    process_params.highest_user_address = highest;
    process_params.guest_kuser = XTAJIT64_GUEST_KUSER;
    process_params.host_kuser = (uintptr_t)test_kuser;
    process_params.kuser_size = TEST_PAGE;
    process_params.rtl_exit_user_thread = test_ec_target;
    process_params.rtl_query_performance_counter = test_ec_target;
    process_params.nt_query_performance_counter = test_ec_target + 0x1000 + 0x80;
    process_params.abi_version = XTAJIT64_PROCESS_ABI_VERSION;
    process_params.abi_size = sizeof(process_params);
    process_params.required_capabilities = XTAJIT64_CAPABILITIES;
    process_params.x64_syscall_dispatcher = test_syscall_dispatcher;
    process_params.x64_syscall_count = TEST_SYSCALL_COUNT;

    test_unicorn_perf_counter_api();
    test_ec_target_stats_initial_report_parser();
    test_process_init_abi();
    status = process_init( &process_params );
    check( !status && process_params.enabled_capabilities == XTAJIT64_CAPABILITIES,
           "process init returned %#x capabilities %#x\n", (unsigned int)status,
           process_params.enabled_capabilities );
    if (status) return 1;
    check( provider.ranges.count == 1 && !provider.ranges.data[0].flags &&
           provider.ranges.data[0].permanent,
           "KUSER registry metadata was not initialized deterministically\n" );
    check( provider.identity_page_flags && provider.identity_page_flags_size &&
           provider.identity_address_bits >
               UC_SWITCHYARD_IDENTITY_PAGE_SHIFT &&
           !provider.identity_page_flags[process_params.guest_kuser >>
               UC_SWITCHYARD_IDENTITY_PAGE_SHIFT],
           "identity fast-path table was not initialized fail-closed\n" );
    if (getenv("ORRERY_E31_ONLY"))
    {
        e31_test_observer_contention();
        process_term(NULL);
        return failures ? 1 : 0;
    }
    test_ec_bitmap_lookup();
    test_flight_recorder_core();
    test_flight_atomic_trace();
    test_flight_recorder_contracts();
    test_flight_recorder_stress();
    test_incremental_resync();
    test_coalesced_demand_mapping();
    test_low_observer_validation();
    test_low_observer_interval_replacement();
    test_low_observer_lazy_engine_sync();
    test_low_observer_lazy_sync_poison();
    test_low_flush_multi_engine_poison();
    test_code_observer_invalidation();
    test_running_pool_teardown();
    check( !register_identity_page( (void *)(uintptr_t)test_ec_target,
                                    PAGE_EXECUTE_READ ),
           "EC target map failed\n" );
    check( !register_identity_page( (void *)(uintptr_t)test_syscall_dispatcher,
                                    PAGE_EXECUTE_READ ),
           "syscall dispatcher map failed\n" );
    check( !register_identity_page( (void *)(uintptr_t)test_teb, PAGE_READWRITE ),
           "TEB map failed\n" );

    test_identity_codec();
    test_execute_only_read_and_execute();
    test_identity_atomic_avoids_demand_mapping();
    test_memory_fault_access_reporting();
    test_late_identity_mapping_retry();
    test_x64_syscall_traps();
    test_pooled_thread_cpu_context();
    test_concurrent_engines();
    test_executable_cache_invalidation();
    test_executable_address_reuse_invalidation();
    test_running_mutation_barrier();
    test_prestart_mutation_barrier();
    test_suspend_doorbell_mutation_barrier();
    test_running_low_observer_barrier();
    test_running_code_observer_barrier();
    test_running_flush_preflight_failure();
    test_flight_provider_boundary();
    test_late_stop_does_not_escape_engine_lease();
#if defined(__APPLE__) && defined(XTAJIT64_TEST_EC_LEAF_FASTPATH)
    test_ec_leaf_fastpath();
#endif

    unregister_identity_page( (void *)(uintptr_t)test_teb );
    unregister_identity_page( (void *)(uintptr_t)test_syscall_dispatcher );
    unregister_identity_page( (void *)(uintptr_t)test_ec_target );
    check( !process_term( NULL ) && !process_term( NULL ),
           "idempotent process termination failed\n" );
    check( !provider.identity_page_flags &&
           !provider.identity_page_flags_size &&
           !provider.identity_address_bits,
           "process termination retained the identity fast-path table\n" );
    munmap( test_kuser, TEST_PAGE );
    munmap( test_pages, TEST_PAGE_COUNT * TEST_PAGE );
    munmap( test_low_pages, TEST_LOW_PAGE_COUNT * TEST_PAGE );
    free( bitmap );
    if (failures)
    {
        fprintf( stderr, "%u xtajit64 native provider checks failed\n", failures );
        return 1;
    }
    printf( "xtajit64 native provider checks passed\n" );
    return 0;
}
