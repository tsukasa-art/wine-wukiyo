/*
 * Unicorn-backed x86-64 emulation on ARM64
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
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#ifdef XTAJIT64_UNIXLIB_TEST
# include <sched.h>
#endif

#ifdef HAVE_UNICORN
# include <pthread.h>
# include <unistd.h>
# include <unicorn/unicorn.h>
# include <unicorn/x86.h>
# ifdef __APPLE__
#  include <dlfcn.h>
#  include <mach/mach.h>
#  include <mach/mach_time.h>
#  include <mach/mach_vm.h>
#  include <mach-o/dyld.h>
#  if defined(__aarch64__) && defined(HAVE_OS_CUSTOM_X18_ABI)
#   include <os/arch/arm64.h>
#  endif
# endif
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "wine/debug.h"
#include "unixlib.h"
#include "tb_history.h"

#ifdef HAVE_UNICORN

#if !defined(UC_SWITCHYARD_INSTRUCTION_BOUNDARY_STOP) || \
    !defined(UC_SWITCHYARD_INSTRUCTION_BOUNDARY_STOP_CLEAR) || \
    !defined(UC_SWITCHYARD_X64_BOUNDARY_GUARD) || \
    !defined(UC_SWITCHYARD_SHARED_MEMORY_ATOMICS) || \
    !defined(UC_SWITCHYARD_SHARED_MEMORY_ATOMIC_TRACE) || \
    !defined(UC_SWITCHYARD_SHARED_CODE_COHERENCE) || \
    !defined(UC_SWITCHYARD_AARCH64_IDENTITY_MEMORY_FASTPATH) || \
    !defined(UC_SWITCHYARD_X86_64_TRANSITION_CONTEXT)
# error Switchyard Unicorn instruction-boundary stop/clear, x64 boundary guard, atomic trace, shared-memory atomics, shared-code coherence, AArch64 identity-memory fast path, and x86-64 transition context are required
#endif

WINE_DEFAULT_DEBUG_CHANNEL(xtajit);
#ifndef XTAJIT64_UNIXLIB_TEST
WINE_DECLARE_DEBUG_CHANNEL(xtajitmap);
WINE_DECLARE_DEBUG_CHANNEL(xtajittrap);
#endif

#define XTAJIT64_MAX_RESYNC_RANGES (1u << 20)
#define XTAJIT64_MAX_SYSCALL_COUNT  (1u << 16)
#define XTAJIT64_DIRECT_SELF_READ_MAX_SIZE 0x10000u
#define XTAJIT64_TEB_SELF_END 0x38
#define XTAJIT64_TEB_THREAD_ID_OFFSET 0x48
#define XTAJIT64_TEB_LAST_ERROR_OFFSET 0x68
#define XTAJIT64_TEB_TLS_SLOTS_OFFSET 0x1480
#define XTAJIT64_TEB_TLS_SLOT_COUNT 64
#define XTAJIT64_TB_HISTORY_WATCHDOG_SECONDS 5
#define XTAJIT64_TB_HISTORY_HOT_ENGINES      4
#define XTAJIT64_EC_TARGET_STATS_SLOTS       4096
#define XTAJIT64_EC_TARGET_STATS_MAX_PROBE   32
#define XTAJIT64_EC_TARGET_STATS_TOP         16
#define XTAJIT64_EC_TARGET_STATS_ENGINE_SLOTS 64
#define XTAJIT64_EC_TARGET_STATS_SAMPLE_STRIDE 16381u
#define XTAJIT64_EC_TARGET_STATS_DEFAULT_INITIAL_REPORT (1u << 20)
#define XTAJIT64_EC_TARGET_STATS_MIN_INITIAL_REPORT     (1u << 12)
#define XTAJIT64_EC_LEAF_FASTPATH_CACHE_SIZE 64

C_ASSERT( !(XTAJIT64_EC_TARGET_STATS_ENGINE_SLOTS &
            (XTAJIT64_EC_TARGET_STATS_ENGINE_SLOTS - 1)) );
C_ASSERT( !(XTAJIT64_EC_LEAF_FASTPATH_CACHE_SIZE &
            (XTAJIT64_EC_LEAF_FASTPATH_CACHE_SIZE - 1)) );

enum direct_self_read_range_result
{
    DIRECT_SELF_READ_RANGE_OK,
    DIRECT_SELF_READ_RANGE_MISSING,
    DIRECT_SELF_READ_RANGE_PERMISSIONS,
    DIRECT_SELF_READ_RANGE_DOMAIN,
};

enum direct_self_read_rejection
{
    DIRECT_SELF_READ_REJECT_PROCESS,
    DIRECT_SELF_READ_REJECT_REGISTERS,
    DIRECT_SELF_READ_REJECT_SIZE,
    DIRECT_SELF_READ_REJECT_STACK_BOUNDS,
    DIRECT_SELF_READ_REJECT_STACK_RANGE,
    DIRECT_SELF_READ_REJECT_STACK_PERMISSIONS,
    DIRECT_SELF_READ_REJECT_STACK_DOMAIN,
    DIRECT_SELF_READ_REJECT_STACK_PHYSICAL,
    DIRECT_SELF_READ_REJECT_SOURCE_RANGE,
    DIRECT_SELF_READ_REJECT_SOURCE_PERMISSIONS,
    DIRECT_SELF_READ_REJECT_SOURCE_DOMAIN,
    DIRECT_SELF_READ_REJECT_DESTINATION_RANGE,
    DIRECT_SELF_READ_REJECT_DESTINATION_PERMISSIONS,
    DIRECT_SELF_READ_REJECT_DESTINATION_DOMAIN,
    DIRECT_SELF_READ_REJECT_RESULT_RANGE,
    DIRECT_SELF_READ_REJECT_RESULT_PERMISSIONS,
    DIRECT_SELF_READ_REJECT_RESULT_DOMAIN,
    DIRECT_SELF_READ_REJECT_OVERLAP,
    DIRECT_SELF_READ_REJECT_DATA_COPY,
    DIRECT_SELF_READ_REJECT_RESULT_COPY,
    DIRECT_SELF_READ_REJECT_COUNT,
};

enum direct_self_read_size_bucket
{
    DIRECT_SELF_READ_SIZE_ZERO,
    DIRECT_SELF_READ_SIZE_64,
    DIRECT_SELF_READ_SIZE_4K,
    DIRECT_SELF_READ_SIZE_64K,
    DIRECT_SELF_READ_SIZE_1M,
    DIRECT_SELF_READ_SIZE_16M,
    DIRECT_SELF_READ_SIZE_LARGE,
    DIRECT_SELF_READ_SIZE_BUCKET_COUNT,
};

struct direct_self_read_diagnostics
{
    uint64_t syscalls;
    uint64_t current_process;
    uint64_t requested_bytes;
    uint64_t maximum_size;
    uint64_t null_result;
    uint64_t size_buckets[DIRECT_SELF_READ_SIZE_BUCKET_COUNT];
    uint64_t rejections[DIRECT_SELF_READ_REJECT_COUNT];
};

#define XTAJIT64_UNICORN_PERF_COUNTERS_VERSION 5u

struct xtajit64_unicorn_perf_counters
{
    uint32_t version;
    uint32_t size;
    uint64_t tcg_dispatch_entries;
    uint64_t tb_lookup_calls;
    uint64_t tb_jump_cache_hits;
    uint64_t tb_hash_hits;
    uint64_t tb_lookup_misses;
    uint64_t tb_generations;
    uint64_t indirect_tb_lookups;
    uint64_t softmmu_load_helpers;
    uint64_t softmmu_store_helpers;
    uint64_t notdirty_writes;
    uint64_t executable_writes;
    uint64_t invalidate_fast_calls;
    uint64_t invalidate_bitmap_skips;
    uint64_t actual_tb_invalidations;
    uint64_t shared_code_write_begins;
    uint64_t shared_code_engine_scans;
    uint64_t shared_code_peer_invalidations;
    uint64_t shared_code_private_writes;
    uint64_t shared_code_translation_begins;
    uint64_t shared_exclusive_begins;
    uint64_t shared_pause_requests;
    uint64_t indirect_site_first_observations;
    uint64_t indirect_site_reobservations;
    uint64_t indirect_site_target_matches;
    uint64_t indirect_site_target_tb_matches;
    uint64_t indirect_site_target_changes;
    uint64_t indirect_site_collisions;
};

#ifdef UC_SWITCHYARD_PERF_COUNTERS
C_ASSERT( UC_SWITCHYARD_PERF_COUNTERS_VERSION ==
          XTAJIT64_UNICORN_PERF_COUNTERS_VERSION );
C_ASSERT( sizeof(struct xtajit64_unicorn_perf_counters) ==
          sizeof(uc_switchyard_perf_counters) );
#endif

typedef uc_err (*unicorn_enable_perf_counters_fn)( uc_engine *uc );
typedef uc_err (*unicorn_get_perf_counters_fn)(
    uc_engine *uc, struct xtajit64_unicorn_perf_counters *counters );

#ifdef __APPLE__
enum unicorn_perf_counter_api_resolution
{
    UNICORN_PERF_COUNTER_API_RESOLVED,
    UNICORN_PERF_COUNTER_API_BAD_ARGUMENT,
    UNICORN_PERF_COUNTER_API_IMAGE_UNAVAILABLE,
    UNICORN_PERF_COUNTER_API_SYMBOL_UNAVAILABLE,
    UNICORN_PERF_COUNTER_API_IMAGE_UNVERIFIABLE,
};

/* Resolve optional counters from the exact Unicorn image used by this unixlib.
 * RTLD_DEFAULT omits private two-level-namespace dependencies on Darwin. */
static void *open_loaded_unicorn_image(void)
{
#ifdef RTLD_NOLOAD
    Dl_info info;
    uint32_t count, index;
    const char *image, *basename;
    void *handle;

    if (dladdr( (const void *)uc_version, &info ) && info.dli_fname &&
        (handle = dlopen( info.dli_fname, RTLD_NOW | RTLD_NOLOAD )))
    {
        if (dlsym( handle, "uc_version" )) return handle;
        dlclose( handle );
    }

    count = _dyld_image_count();
    for (index = 0; index < count; ++index)
    {
        image = _dyld_get_image_name( index );
        if (!image) continue;
        basename = strrchr( image, '/' );
        if (strcmp( basename ? basename + 1 : image, "libunicorn.2.dylib" )) continue;
        if (!(handle = dlopen( image, RTLD_NOW | RTLD_NOLOAD ))) continue;
        if (dlsym( handle, "uc_version" )) return handle;
        dlclose( handle );
    }
#endif
    return NULL;
}

static enum unicorn_perf_counter_api_resolution resolve_unicorn_perf_counter_api(
    unicorn_enable_perf_counters_fn *enable, unicorn_get_perf_counters_fn *get )
{
#ifdef RTLD_NOLOAD
    Dl_info unicorn_info, enable_info, get_info;
    unicorn_enable_perf_counters_fn resolved_enable;
    unicorn_get_perf_counters_fn resolved_get;
    void *handle, *version_address, *enable_address, *get_address;
    BOOL ret = FALSE;

    if (!enable || !get || sizeof(resolved_enable) != sizeof(enable_address) ||
        sizeof(resolved_get) != sizeof(get_address))
        return UNICORN_PERF_COUNTER_API_BAD_ARGUMENT;
    if (!(handle = open_loaded_unicorn_image()))
        return UNICORN_PERF_COUNTER_API_IMAGE_UNAVAILABLE;

    version_address = dlsym( handle, "uc_version" );
    enable_address = dlsym( handle, "uc_switchyard_enable_perf_counters" );
    get_address = dlsym( handle, "uc_switchyard_get_perf_counters" );
    if (!version_address || !enable_address || !get_address)
    {
        dlclose( handle );
        return UNICORN_PERF_COUNTER_API_SYMBOL_UNAVAILABLE;
    }
    if (!dladdr( version_address, &unicorn_info ) || !unicorn_info.dli_fbase ||
        !dladdr( enable_address, &enable_info ) || !dladdr( get_address, &get_info ) ||
        enable_info.dli_fbase != unicorn_info.dli_fbase ||
        get_info.dli_fbase != unicorn_info.dli_fbase)
    {
        dlclose( handle );
        return UNICORN_PERF_COUNTER_API_IMAGE_UNVERIFIABLE;
    }

    memcpy( &resolved_enable, &enable_address, sizeof(resolved_enable) );
    memcpy( &resolved_get, &get_address, sizeof(resolved_get) );
    *enable = resolved_enable;
    *get = resolved_get;
    ret = TRUE;

    dlclose( handle );
    return ret ? UNICORN_PERF_COUNTER_API_RESOLVED : UNICORN_PERF_COUNTER_API_IMAGE_UNVERIFIABLE;
#else
    return UNICORN_PERF_COUNTER_API_IMAGE_UNAVAILABLE;
#endif
}
#endif

struct mapped_range
{
    uint64_t guest;
    uint64_t host;
    uint64_t size;
    uint64_t allocation_base;
    unsigned int perms;
    unsigned int state;
    unsigned int domain;
    unsigned int flags;
    BOOL permanent;
    /* An engine can miss a complete unmap/remap cycle while it is idle. */
    BOOL stale;
};

struct range_array
{
    struct mapped_range *data;
    size_t count;
    size_t capacity;
};

struct thread_engine;

enum ec_leaf_fastpath_kind
{
    EC_LEAF_FASTPATH_UNCLASSIFIED,
    EC_LEAF_FASTPATH_UNSUPPORTED,
    /* A leaf reads a zero-extended 32-bit TEB field into ARM64 x0.  The
     * ARM64EC entry/return thunks map that result to the emulated x64 RAX.
     * Keep the exact instruction in the cache so the field offset is part of
     * the recognition result rather than an unchecked policy list. */
    EC_LEAF_FASTPATH_TEB_LOAD_W0,
    EC_LEAF_FASTPATH_TLS_GET_VALUE,
    EC_LEAF_FASTPATH_TLS_GET_VALUE2,
    EC_LEAF_FASTPATH_RTL_QUERY_PERFORMANCE_COUNTER,
    EC_LEAF_FASTPATH_ROTL32,
    EC_LEAF_FASTPATH_ROTR32,
    EC_LEAF_FASTPATH_ROTL64,
    EC_LEAF_FASTPATH_ROTR64,
    EC_LEAF_FASTPATH_KIND_COUNT,
};

struct ec_leaf_fastpath_cache_entry
{
    uint64_t address;
    uint64_t mapping_generation;
    uint64_t code_generation;
    uint32_t instruction;
    enum ec_leaf_fastpath_kind kind;
};

struct ec_transition_target_sample
{
    atomic_uint_fast64_t address;
    atomic_uint_fast64_t count;
};

struct thread_binding
{
    uc_context *context;
    struct thread_engine *resident_engine;
    uint64_t process_instance;
    uint64_t id;
    struct xtajit64_flight_recorder *flight_recorder;
    uint64_t flight_causal_boundary_id;
    uint64_t flight_context_generation;
    uint64_t flight_last_context_generation;
    uint64_t flight_transition_generation;
    /* `flight_expected_teb` is the Unix-TLS authenticated value.  The
     * separately retained claim is the PE x18 value supplied at bind. */
    uint64_t flight_expected_teb;
    uint64_t flight_claimed_teb;
    uint64_t flight_guest_rip;
    uint64_t flight_guest_rsp;
    uint64_t flight_guest_stack_limit;
    uint64_t flight_guest_stack_base;
    uint64_t flight_control_stack_limit;
    uint64_t flight_control_stack_top;
    uint64_t flight_pid;
    uint64_t flight_mach_thread_id;
    uint64_t flight_pthread_identity;
    BOOL context_valid;
    BOOL active;
};

struct thread_engine
{
    struct thread_engine *next;
    uc_engine *uc;
    /* Actual Unicorn mappings, not a copy of the canonical process registry.
     * Keeping untouched canonical ranges absent lets each pooled engine fault
     * in only the guest regions reached by concurrent translated execution. */
    struct range_array mapped_ranges;
    uint64_t mapping_generation;
    struct thread_binding *resident_binding;
    uint64_t resident_binding_id;
    uint64_t execution_generation;
    struct xtajit64_tb_history *tb_history;
    uint64_t tb_binding_id;
    uint64_t tb_causal_boundary_id;
    uint32_t tb_history_sample_counter;
    struct xtajit64_flight_recorder *flight_recorder;
    uint64_t flight_binding_id;
    uint64_t flight_causal_boundary_id;
    uint64_t flight_context_generation;
    uint64_t flight_transition_generation;
    uint64_t flight_expected_teb;
    uint64_t flight_claimed_teb;
    uint64_t flight_guest_rip;
    uint64_t flight_guest_rsp;
    uint64_t flight_guest_stack_limit;
    uint64_t flight_guest_stack_base;
    uint64_t flight_control_stack_limit;
    uint64_t flight_control_stack_top;
    uint64_t flight_pid;
    uint64_t flight_mach_thread_id;
    uint64_t flight_pthread_identity;
    /* Terminal interrupt evidence is captured in the owner callback and
     * copied into each PROVIDER_STOP record.  It is diagnostic-only and is
     * never used to drive provider behavior. */
    uint64_t flight_stop_detail0;
    uint64_t diagnostic_id;
    unsigned int diagnostic_pool_size;
    unsigned int diagnostic_pool_in_use;
    unsigned int diagnostic_pool_high_water;
    uint64_t demand_map_calls;
    uint64_t demand_map_bytes;
    uint64_t demand_map_4k_calls;
    uint64_t demand_map_16k_calls;
    uint64_t demand_map_64k_calls;
    uint64_t demand_map_1m_calls;
    uint64_t demand_map_large_calls;
    uint64_t demand_map_max_size;
    uint64_t registry_sync_calls;
    uint64_t resync_unmap_calls;
    uint64_t resync_unmap_bytes;
    uint64_t direct_self_read_attempts;
    uint64_t direct_self_read_completions;
    uint64_t direct_self_read_bytes;
    struct direct_self_read_diagnostics direct_self_read_diagnostics;
    uint64_t direct_self_read_next_report;
    uint64_t perf_sample_count;
    uint64_t perf_next_report;
    uint32_t ec_target_stats_sample_counter;
    atomic_uint_fast64_t ec_target_stats_lost;
    BOOL ec_target_stats_report_pending;
    struct ec_transition_target_sample
        ec_target_stats[XTAJIT64_EC_TARGET_STATS_ENGINE_SLOTS];
    struct ec_leaf_fastpath_cache_entry ec_leaf_fastpath_cache[XTAJIT64_EC_LEAF_FASTPATH_CACHE_SIZE];
    pthread_t owner;
    BOOL linked;
    BOOL in_use;
    BOOL running;
    atomic_bool pause_requested;
    volatile uint32_t *suspend_doorbell;
    volatile uint32_t boundary_idle_doorbell;
    uint64_t stack_limit;
    uint64_t stack_base;
    uint64_t transition_target;
    uint64_t fault_address;
    uint32_t fault_access;
    uc_err mapping_error;
    enum xtajit64_stop_reason stop_reason;
};
C_ASSERT( !(offsetof(struct thread_engine, boundary_idle_doorbell) &
            (sizeof(uint32_t) - 1)) );

enum mutation_kind
{
    MUTATION_NONE,
    MUTATION_MAP,
    MUTATION_UNMAP,
    MUTATION_PROTECT,
    MUTATION_RESYNC,
    MUTATION_FLUSH,
    MUTATION_POISON,
};

enum mutation_stage
{
    MUTATION_STAGE_IDLE,
    MUTATION_STAGE_PAUSE,
    MUTATION_STAGE_WAIT,
    MUTATION_STAGE_PREPARE,
    MUTATION_STAGE_APPLY,
    MUTATION_STAGE_PUBLISH,
};

struct arm64ec_low_observer_transaction
{
    uint64_t generation;
    uint32_t operation;
    uint32_t reserved;
};

struct arm64ec_code_observer_transaction
{
    uint64_t generation;
    uint32_t operation;
    uint32_t reserved;
};

struct ec_transition_target_stat
{
    uint64_t address;
    uint64_t count;
};

struct provider_process
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    BOOL initialized;
    BOOL mutating;
    BOOL mutation_owner_valid;
    BOOL shutting_down;
    BOOL observer_active;
    BOOL code_observer_active;
    uint64_t generation;
    pthread_t mutation_owner;
    enum mutation_kind mutation_kind;
    enum mutation_stage mutation_stage;
    enum mutation_kind last_fault_kind;
    enum mutation_stage last_fault_stage;
    uint64_t last_fault_generation;
    NTSTATUS poison_status;
    const uint64_t *ec_bitmap;
    size_t ec_bitmap_word_count;
    unsigned int ec_page_shift;
    uint64_t highest_user_address;
    uint8_t *identity_page_flags;
    size_t identity_page_flags_size;
    uint32_t identity_address_bits;
    uint64_t rtl_exit_user_thread;
    uint64_t rtl_query_performance_counter;
    uint64_t nt_query_performance_counter;
    uint64_t x64_syscall_dispatcher;
    uint32_t x64_syscall_count;
    uint64_t guest_kuser;
    uint64_t host_kuser;
    uint64_t kuser_size;
    uint64_t instance;
    uint64_t next_binding_id;
    uint64_t next_diagnostic_id;
    unsigned int engine_count;
    unsigned int engines_in_use;
    unsigned int engine_high_water;
    BOOL tb_history_enabled;
    BOOL direct_self_read_stats_enabled;
    BOOL unicorn_perf_stats_enabled;
    BOOL ec_target_stats_enabled;
    BOOL ec_leaf_fastpath_enabled;
    BOOL ec_leaf_fastpath_stats_enabled;
    uint64_t ec_leaf_fastpath_code_generation;
    atomic_uint_fast64_t ec_target_stats_total;
    uint64_t ec_target_stats_lost;
    atomic_uint_fast64_t ec_target_stats_next_report;
    struct ec_transition_target_stat ec_target_stats[XTAJIT64_EC_TARGET_STATS_SLOTS];
    atomic_uint_fast64_t ec_leaf_fastpath_attempts;
    atomic_uint_fast64_t ec_leaf_fastpath_hits;
    atomic_uint_fast64_t ec_leaf_fastpath_unsupported;
    atomic_uint_fast64_t ec_leaf_fastpath_register_failures;
    atomic_uint_fast64_t ec_leaf_fastpath_memory_failures;
    atomic_uint_fast64_t ec_leaf_fastpath_stack_failures;
    atomic_uint_fast64_t ec_leaf_fastpath_write_failures;
    atomic_uint_fast64_t ec_leaf_fastpath_hits_by_kind[EC_LEAF_FASTPATH_KIND_COUNT];
    atomic_uint_fast64_t ec_leaf_fastpath_next_report;
    unicorn_enable_perf_counters_fn unicorn_enable_perf_counters;
    unicorn_get_perf_counters_fn unicorn_get_perf_counters;
#ifndef XTAJIT64_UNIXLIB_TEST
    BOOL tb_history_watchdog_started;
    pthread_t tb_history_watchdog;
    uint64_t tb_history_watchdog_tick;
#endif
    uc_context *initial_context;
    struct range_array ranges;
    struct thread_engine *engines;
    struct arm64ec_low_observer_transaction *observer_transaction;
    struct arm64ec_code_observer_transaction *code_observer_transaction;
};

static struct provider_process provider =
{
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};

/* This cache is only a classification cache, never a code-lifetime claim.
 * Code observers and FlushInstructionCache advance it after Unicorn has
 * invalidated the affected translations.  Keeping it separate from the
 * mapping generation also covers byte changes with unchanged VM mappings. */
static void advance_ec_leaf_fastpath_code_generation_locked(void)
{
    if (!++provider.ec_leaf_fastpath_code_generation)
        ++provider.ec_leaf_fastpath_code_generation;
}

static pthread_key_t engine_key;
static pthread_once_t engine_key_once = PTHREAD_ONCE_INIT;
static int engine_key_error;

#define XTAJIT64_DEMAND_MAP_MAX_SIZE \
    ((uint64_t)4096 * XTAJIT64_GUEST_PAGE_SIZE)

static NTSTATUS memory_map( void *args );
static NTSTATUS memory_map_internal( void *args );
static BOOL legacy_mutation_selects_low_locked( uint64_t guest, uint64_t size );
static NTSTATUS build_resync_mapping_changes( const struct range_array *old,
                                               const struct range_array *replacement,
                                               struct range_array *removals,
                                               struct range_array *additions );
static NTSTATUS process_term( void *args );

static struct xtajit64_tb_history *tb_history_create(void)
{
    struct xtajit64_tb_history *history;

    if (!(history = malloc( sizeof(*history) ))) return NULL;
    xtajit64_tb_history_init( history );
    return history;
}

static void tb_history_record_execution_entry( struct thread_engine *engine,
                                               uint64_t address )
{
    xtajit64_tb_history_record( engine->tb_history, address, 0,
                                engine->tb_binding_id,
                                engine->execution_generation,
                                engine->mapping_generation,
                                engine->tb_causal_boundary_id );
}

#ifndef XTAJIT64_UNIXLIB_TEST
struct tb_history_hot_engine
{
    struct thread_engine *engine;
    uint64_t delta;
    uint64_t diagnostic_id;
};

/* A provider-created POSIX watchdog is not a Wine thread and therefore has no
 * Windows TEB in x18.  Keep its diagnostic output entirely below Wine's debug
 * layer; wine_dbg_log() obtains thread state and is invalid from this thread. */
static void tb_history_native_log( const char *format, ... )
{
    char buffer[768];
    va_list args;
    size_t length, offset = 0;
    int ret;

    va_start( args, format );
    ret = vsnprintf( buffer, sizeof(buffer), format, args );
    va_end( args );
    if (ret <= 0) return;
    length = (size_t)ret < sizeof(buffer) ? (size_t)ret : sizeof(buffer) - 1;
    while (offset < length)
    {
        ssize_t written = write( STDERR_FILENO, buffer + offset, length - offset );

        if (written > 0) offset += written;
        else if (written < 0 && errno == EINTR) continue;
        else break;
    }
}

static unsigned int tb_history_select_hot_engines_locked(
    struct tb_history_hot_engine selected[XTAJIT64_TB_HISTORY_HOT_ENGINES] )
{
    struct thread_engine *engine;
    unsigned int count = 0;

    for (engine = provider.engines; engine; engine = engine->next)
    {
        struct xtajit64_tb_history *history = engine->tb_history;
        uint64_t previous, latest, delta;
        unsigned int position;

        if (!history) continue;
        latest = atomic_load_explicit( &history->writer_sequence,
                                       memory_order_acquire );
        previous = history->watchdog_last_sequence;
        history->watchdog_last_sequence = latest;
        delta = latest >= previous ? latest - previous : latest;
        if (!delta) continue;
        for (position = 0; position < count; ++position)
            if (delta > selected[position].delta) break;
        if (position >= XTAJIT64_TB_HISTORY_HOT_ENGINES) continue;
        if (count < XTAJIT64_TB_HISTORY_HOT_ENGINES) ++count;
        if (position + 1 < count)
            memmove( &selected[position + 1], &selected[position],
                     (count - position - 1) * sizeof(selected[0]) );
        selected[position].engine = engine;
        selected[position].delta = delta;
        selected[position].diagnostic_id = engine->diagnostic_id;
    }
    return count;
}

static void tb_history_trace_engine( const struct tb_history_hot_engine *selected,
                                     uint64_t tick, BOOL include_tail )
{
    struct xtajit64_tb_history_summary summary;
    const struct xtajit64_tb_history_snapshot *latest;
    const char *classification;
    BOOL repeating;
    unsigned int i;

    xtajit64_tb_history_summarize( selected->engine->tb_history, &summary );
    if (!summary.valid) return;
    latest = &summary.tail[summary.tail_count - 1];
    repeating = xtajit64_tb_history_is_repeat_candidate( &summary );
    classification = !repeating ? "advancing" :
                     summary.execution_generation_changes ?
                     "cross-generation-repeat" : "same-generation-repeat";
    tb_history_native_log(
        "xtajittb: pid %ld tick %#llx engine %#llx samples %#llx stride %u "
        "seq %#llx-%#llx "
        "window %u/%u missing %u unique-pc %u execution-generation-changes %u "
        "provenance-changes %u overwritten %#llx "
        "pc %#llx-%#llx map %#llx-%#llx binding %#llx generation %#llx "
        "causal %#llx class %s\n",
        (long)getpid(),
        (unsigned long long)tick,
        (unsigned long long)selected->diagnostic_id,
        (unsigned long long)selected->delta,
        XTAJIT64_TB_HISTORY_SAMPLE_STRIDE,
        (unsigned long long)summary.first_sequence,
        (unsigned long long)summary.last_sequence,
        summary.valid, summary.requested, summary.missing_or_torn,
        summary.unique_pc_count, summary.execution_generation_changes,
        summary.provenance_changes,
        (unsigned long long)summary.overwritten,
        (unsigned long long)summary.first_pc,
        (unsigned long long)summary.last_pc,
        (unsigned long long)summary.minimum_mapping_generation,
        (unsigned long long)summary.maximum_mapping_generation,
        (unsigned long long)latest->binding_id,
        (unsigned long long)latest->execution_generation,
        (unsigned long long)latest->causal_boundary_id,
        classification );
    if (!include_tail && !repeating) return;
    for (i = 0; i < summary.tail_count; ++i)
    {
        const struct xtajit64_tb_history_snapshot *event = &summary.tail[i];

        tb_history_native_log(
            "xtajittb: pid %ld tail engine %#llx seq %#llx pc %#llx size %#x map %#llx "
            "binding %#llx generation %#llx causal %#llx\n",
            (long)getpid(),
            (unsigned long long)selected->diagnostic_id,
            (unsigned long long)event->sequence,
            (unsigned long long)event->guest_pc, event->block_size,
            (unsigned long long)event->mapping_generation,
            (unsigned long long)event->binding_id,
            (unsigned long long)event->execution_generation,
            (unsigned long long)event->causal_boundary_id );
    }
}

static void tb_history_watchdog_deadline( struct timespec *deadline )
{
    if (clock_gettime( CLOCK_REALTIME, deadline ))
    {
        deadline->tv_sec = time( NULL );
        deadline->tv_nsec = 0;
    }
    deadline->tv_sec += XTAJIT64_TB_HISTORY_WATCHDOG_SECONDS;
}

static void *tb_history_watchdog_main( void *arg )
{
    struct tb_history_hot_engine selected[XTAJIT64_TB_HISTORY_HOT_ENGINES];

    (void)arg;
    pthread_mutex_lock( &provider.mutex );
    while (!provider.shutting_down)
    {
        struct timespec deadline;
        unsigned int count, i;
        int ret;

        tb_history_watchdog_deadline( &deadline );
        do
            ret = pthread_cond_timedwait( &provider.cond, &provider.mutex,
                                          &deadline );
        while (!provider.shutting_down && !ret);
        if (provider.shutting_down) break;
        if (ret != ETIMEDOUT)
        {
            tb_history_native_log( "xtajittb: pid %ld watchdog wait failed: %s\n",
                                   (long)getpid(), strerror( ret ) );
            break;
        }
        ++provider.tb_history_watchdog_tick;
        count = tb_history_select_hot_engines_locked( selected );
        pthread_mutex_unlock( &provider.mutex );
        for (i = 0; i < count; ++i)
            tb_history_trace_engine( &selected[i],
                                     provider.tb_history_watchdog_tick, !i );
        pthread_mutex_lock( &provider.mutex );
    }
    pthread_mutex_unlock( &provider.mutex );
    return NULL;
}

static NTSTATUS tb_history_start_watchdog_locked(void)
{
    int ret;

    if (!provider.tb_history_enabled || provider.tb_history_watchdog_started)
        return STATUS_SUCCESS;
    if ((ret = pthread_create( &provider.tb_history_watchdog, NULL,
                               tb_history_watchdog_main, NULL )))
    {
        tb_history_native_log(
            "xtajittb: pid %ld cannot start translated-block history watchdog: %s\n",
            (long)getpid(), strerror( ret ) );
        return ret == ENOMEM ? STATUS_NO_MEMORY : STATUS_UNSUCCESSFUL;
    }
    provider.tb_history_watchdog_started = TRUE;
    tb_history_native_log(
        "xtajittb: pid %ld enabled capacity %u window %u stride %u interval %us\n",
        (long)getpid(), XTAJIT64_TB_HISTORY_CAPACITY,
        XTAJIT64_TB_HISTORY_SUMMARY_WINDOW,
        XTAJIT64_TB_HISTORY_SAMPLE_STRIDE,
        XTAJIT64_TB_HISTORY_WATCHDOG_SECONDS );
    return STATUS_SUCCESS;
}
#endif

C_ASSERT( sizeof(struct wine_arm64ec_low_memory_range_v1) == 40 );
C_ASSERT( sizeof(struct wine_arm64ec_low_memory_event_v1) == 72 );
C_ASSERT( sizeof(struct wine_arm64ec_low_memory_observer_v1) == 40 );
C_ASSERT( sizeof(struct wine_arm64ec_code_range_v1) == 16 );
C_ASSERT( sizeof(struct wine_arm64ec_code_event_v1) == 40 );
C_ASSERT( sizeof(struct wine_arm64ec_code_observer_v1) == 40 );

static uint64_t flight_timestamp_from_timespec( const struct timespec *timestamp )
{
    uint64_t seconds, nanoseconds, base;

    if (!timestamp || timestamp->tv_sec < 0 || timestamp->tv_nsec < 0 ||
        timestamp->tv_nsec >= 1000000000 ||
        (uint64_t)timestamp->tv_sec > UINT64_MAX / UINT64_C(1000000000))
        return XTAJIT64_FLIGHT_UNKNOWN_U64;
    seconds = timestamp->tv_sec;
    nanoseconds = timestamp->tv_nsec;
    base = seconds * UINT64_C(1000000000);
    /* UINT64_MAX is the explicit unavailable sentinel, so reject equality as
     * well as arithmetic overflow rather than returning an ambiguous value. */
    if (base >= UINT64_MAX - nanoseconds) return XTAJIT64_FLIGHT_UNKNOWN_U64;
    return base + nanoseconds;
}

static uint64_t flight_monotonic_timestamp_ns(void)
{
    struct timespec timestamp;

    if (clock_gettime( CLOCK_MONOTONIC, &timestamp )) return XTAJIT64_FLIGHT_UNKNOWN_U64;
    return flight_timestamp_from_timespec( &timestamp );
}

static uint64_t flight_read_live_x18(void)
{
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t value;

    __asm__ volatile( "mov %0, x18" : "=r" (value) : : "memory" );
    return value;
#else
    return XTAJIT64_FLIGHT_UNKNOWN_U64;
#endif
}

static uint64_t flight_read_live_sp(void)
{
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t value;

    __asm__ volatile( "mov %0, sp" : "=r" (value) : : "memory" );
    return value;
#else
    return XTAJIT64_FLIGHT_UNKNOWN_U64;
#endif
}

static uint64_t flight_current_frame_address(void)
{
#if defined(__GNUC__) || defined(__clang__)
    void *frame = __builtin_frame_address( 0 );

    return frame ? (uint64_t)(uintptr_t)frame : XTAJIT64_FLIGHT_UNKNOWN_U64;
#else
    return XTAJIT64_FLIGHT_UNKNOWN_U64;
#endif
}

static uint64_t flight_current_return_address(void)
{
#if defined(__GNUC__) || defined(__clang__)
    void *address = __builtin_return_address( 0 );

    return address ? (uint64_t)(uintptr_t)address : XTAJIT64_FLIGHT_UNKNOWN_U64;
#else
    return XTAJIT64_FLIGHT_UNKNOWN_U64;
#endif
}

static uint64_t flight_current_pthread_identity(void)
{
    pthread_t thread = pthread_self();
    uint64_t identity = XTAJIT64_FLIGHT_UNKNOWN_U64;

    memcpy( &identity, &thread,
            sizeof(identity) < sizeof(thread) ? sizeof(identity) : sizeof(thread) );
    return identity;
}

static uint64_t flight_current_mach_thread_id(void)
{
#ifdef __APPLE__
    return (uint64_t)pthread_mach_thread_np( pthread_self() );
#else
    return XTAJIT64_FLIGHT_UNKNOWN_U64;
#endif
}

/* This must be called only by an ordinary Unixlib entry after the dispatcher
 * has switched ownership of x18 to Darwin.  It describes that Unix/system
 * side alone; it never claims to observe the ARM64EC caller's pre-switch mode. */
static uint32_t flight_query_unix_system_x18_mode( BOOL *safe )
{
    *safe = FALSE;
#if defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__)) && \
    defined(HAVE_OS_CUSTOM_X18_ABI)
    if (__builtin_available( macOS 26.4, * ))
    {
        *safe = TRUE;
        return os_custom_x18_abi_enabled() ? XTAJIT64_FLIGHT_X18_MODE_ENABLED :
                                             XTAJIT64_FLIGHT_X18_MODE_DISABLED;
    }
#endif
    return XTAJIT64_FLIGHT_X18_MODE_UNKNOWN;
}

static void flight_init_binding_event( struct xtajit64_flight_event *event,
                                       const struct thread_binding *binding,
                                       uint32_t type )
{
    uint64_t timestamp;

    /* The Unix dispatcher can be entered while a transition stack is under
     * investigation.  All callers obtain this payload from the recorder's
     * reentrant scratch pool; do not turn it back into a large C stack local. */
    xtajit64_flight_event_init( event, type, XTAJIT64_FLIGHT_SOURCE_UNIX_PROVIDER );
    if (!binding) return;
    event->binding_id = binding->id;
    event->causal_boundary_id = binding->flight_causal_boundary_id;
    event->context_generation = binding->flight_context_generation;
    event->transition_generation = binding->flight_transition_generation;
    event->expected_teb = binding->flight_expected_teb;
    if (binding->flight_expected_teb &&
        binding->flight_expected_teb != XTAJIT64_FLIGHT_UNKNOWN_U64)
        event->flags |= XTAJIT64_FLIGHT_FLAG_EXPECTED_TEB_AUTHENTICATED;
    event->saved_x18_value = binding->flight_claimed_teb;
    if (binding->flight_claimed_teb != XTAJIT64_FLIGHT_UNKNOWN_U64)
        event->flags &= ~XTAJIT64_FLIGHT_FLAG_SAVED_X18_UNKNOWN;
    if (binding->flight_claimed_teb &&
        binding->flight_claimed_teb != XTAJIT64_FLIGHT_UNKNOWN_U64)
        event->flags |= XTAJIT64_FLIGHT_FLAG_PE_X18_CLAIM_PRESENT;
    event->guest_rip = binding->flight_guest_rip;
    event->guest_rsp = binding->flight_guest_rsp;
    event->guest_stack_limit = binding->flight_guest_stack_limit;
    event->guest_stack_base = binding->flight_guest_stack_base;
    event->control_stack_limit = binding->flight_control_stack_limit;
    event->control_stack_top = binding->flight_control_stack_top;
    event->pid = binding->flight_pid;
    event->mach_thread_id = binding->flight_mach_thread_id;
    event->pthread_identity = binding->flight_pthread_identity;
    event->x18_value = flight_read_live_x18();
    event->native_sp = flight_read_live_sp();
    event->native_frame = flight_current_frame_address();
    event->native_pc = flight_current_return_address();
    timestamp = flight_monotonic_timestamp_ns();
    if (timestamp != XTAJIT64_FLIGHT_UNKNOWN_U64)
    {
        event->monotonic_timestamp_ns = timestamp;
        event->flags &= ~XTAJIT64_FLIGHT_FLAG_TIME_UNAVAILABLE;
    }
}

static void flight_init_engine_event( struct xtajit64_flight_event *event,
                                      const struct thread_engine *engine,
                                      uint32_t type )
{
    uint64_t timestamp;

    if (!engine || !engine->flight_recorder) return;
    xtajit64_flight_event_init( event, type, XTAJIT64_FLIGHT_SOURCE_UNIX_PROVIDER );
    event->binding_id = engine->flight_binding_id;
    event->causal_boundary_id = engine->flight_causal_boundary_id;
    event->context_generation = engine->flight_context_generation;
    event->transition_generation = engine->flight_transition_generation;
    event->expected_teb = engine->flight_expected_teb;
    if (engine->flight_expected_teb &&
        engine->flight_expected_teb != XTAJIT64_FLIGHT_UNKNOWN_U64)
        event->flags |= XTAJIT64_FLIGHT_FLAG_EXPECTED_TEB_AUTHENTICATED;
    event->saved_x18_value = engine->flight_claimed_teb;
    if (engine->flight_claimed_teb != XTAJIT64_FLIGHT_UNKNOWN_U64)
        event->flags &= ~XTAJIT64_FLIGHT_FLAG_SAVED_X18_UNKNOWN;
    if (engine->flight_claimed_teb &&
        engine->flight_claimed_teb != XTAJIT64_FLIGHT_UNKNOWN_U64)
        event->flags |= XTAJIT64_FLIGHT_FLAG_PE_X18_CLAIM_PRESENT;
    event->guest_rip = engine->flight_guest_rip;
    event->guest_rsp = engine->flight_guest_rsp;
    event->guest_stack_limit = engine->flight_guest_stack_limit;
    event->guest_stack_base = engine->flight_guest_stack_base;
    event->control_stack_limit = engine->flight_control_stack_limit;
    event->control_stack_top = engine->flight_control_stack_top;
    event->pid = engine->flight_pid;
    event->mach_thread_id = engine->flight_mach_thread_id;
    event->pthread_identity = engine->flight_pthread_identity;
    event->x18_value = flight_read_live_x18();
    event->native_sp = flight_read_live_sp();
    event->native_frame = flight_current_frame_address();
    event->native_pc = flight_current_return_address();
    timestamp = flight_monotonic_timestamp_ns();
    if (timestamp != XTAJIT64_FLIGHT_UNKNOWN_U64)
    {
        event->monotonic_timestamp_ns = timestamp;
        event->flags &= ~XTAJIT64_FLIGHT_FLAG_TIME_UNAVAILABLE;
    }
    event->engine_id = engine->diagnostic_id;
    event->engine_generation = engine->execution_generation;
    event->mapping_generation = engine->mapping_generation;
    event->x18_expectation = XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM;
    if (type == XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP)
        event->detail0 = engine->flight_stop_detail0;
}

static void flight_record_engine_event( struct thread_engine *engine, uint32_t type,
                                        uint32_t reason, uint32_t stop_reason,
                                        uint64_t guest_rip, uint64_t guest_rsp )
{
    struct xtajit64_flight_recorder *recorder;
    struct xtajit64_flight_scratch *scratch;
    struct xtajit64_flight_event *event;

    if (!engine || !(recorder = engine->flight_recorder) ||
        !xtajit64_flight_recorder_is_active( recorder ))
        return;
    if (!(event = xtajit64_flight_acquire_scratch( recorder, &scratch )))
    {
        if (reason && xtajit64_flight_recorder_is_active( recorder ))
            xtajit64_flight_freeze( recorder, reason );
        return;
    }
    flight_init_engine_event( event, engine, type );
    event->reason = reason;
    event->stop_reason = stop_reason;
    if (guest_rip != XTAJIT64_FLIGHT_UNKNOWN_U64) event->guest_rip = guest_rip;
    if (guest_rsp != XTAJIT64_FLIGHT_UNKNOWN_U64) event->guest_rsp = guest_rsp;
    if (type == XTAJIT64_FLIGHT_EVENT_SUSPEND_REQUEST)
    {
        /* A mutator may be requesting a pause for another thread's engine.
         * Keep its causal binding ID, but identify the actual requester. */
        event->mach_thread_id = flight_current_mach_thread_id();
        event->pthread_identity = flight_current_pthread_identity();
    }
    if (reason) xtajit64_flight_record_and_freeze( recorder, event, reason );
    else xtajit64_flight_record( recorder, event );
    xtajit64_flight_release_scratch( scratch );
}

static void flight_record_binding_event( struct thread_binding *binding, uint32_t type,
                                         uint32_t reason )
{
    struct xtajit64_flight_recorder *recorder;
    struct xtajit64_flight_scratch *scratch;
    struct xtajit64_flight_event *event;

    if (!binding || !(recorder = binding->flight_recorder) ||
        !xtajit64_flight_recorder_is_active( recorder ))
        return;
    if (!(event = xtajit64_flight_acquire_scratch( recorder, &scratch )))
    {
        if (reason && xtajit64_flight_recorder_is_active( recorder ))
            xtajit64_flight_freeze( recorder, reason );
        return;
    }
    flight_init_binding_event( event, binding, type );
    event->reason = reason;
    if (reason) xtajit64_flight_record_and_freeze( recorder, event, reason );
    else xtajit64_flight_record( recorder, event );
    xtajit64_flight_release_scratch( scratch );
}

static uint32_t flight_validate_provider_context( const struct xtajit64_begin_params *params )
{
    if (!params) return XTAJIT64_FLIGHT_REASON_CONTEXT_RIP;
    /* The provider ABI carries a normalized x64 context, not AMD64_CONTEXT,
     * so context flags/version and FltSave.MxCsr are explicitly unavailable
     * here.  The PE-side watchdog verifies those source fields. */
    return xtajit64_flight_validate_context( XTAJIT64_FLIGHT_UNKNOWN_U32, 0,
                                             params->context.mxcsr,
                                             XTAJIT64_FLIGHT_UNKNOWN_U32,
                                             params->context.rip,
                                             params->context.rsp,
                                             XTAJIT64_X64_USER_ADDRESS_MAX,
                                             params->stack_limit,
                                             params->stack_base,
                                             XTAJIT64_FLIGHT_UNKNOWN_U64,
                                             XTAJIT64_FLIGHT_UNKNOWN_U64,
                                             XTAJIT64_FLIGHT_UNKNOWN_U64 );
}

static void flight_record_context_event( struct thread_engine *engine, uint32_t type,
                                         const struct xtajit64_begin_params *params,
                                         uint32_t reason )
{
    struct xtajit64_flight_recorder *recorder;
    struct xtajit64_flight_scratch *scratch;
    struct xtajit64_flight_event *event;

    if (!engine || !params || !(recorder = engine->flight_recorder) ||
        !xtajit64_flight_recorder_is_active( recorder ))
        return;
    if (!reason) reason = flight_validate_provider_context( params );
    if (!(event = xtajit64_flight_acquire_scratch( recorder, &scratch )))
    {
        if (reason && xtajit64_flight_recorder_is_active( recorder ))
            xtajit64_flight_freeze( recorder, reason );
        return;
    }
    flight_init_engine_event( event, engine, type );
    event->reason = reason;
    event->guest_rip = params->context.rip;
    event->guest_rsp = params->context.rsp;
    event->guest_stack_limit = params->stack_limit;
    event->guest_stack_base = params->stack_base;
    event->mxcsr = params->context.mxcsr;
    /* CONTEXT_EXPORT carries the normalized terminal provider reason as well
     * as the context.  Do not copy it into IMPORT: CPU intentionally reuses
     * begin_params after a MAPPING_MISS retry, so that field may still contain
     * the preceding output reason rather than an input-side observation. */
    if (type == XTAJIT64_FLIGHT_EVENT_CONTEXT_EXPORT)
        event->stop_reason = params->stop_reason;
    event->flags |= XTAJIT64_FLIGHT_FLAG_CONTEXT_FLAGS_UNKNOWN;
    if (reason) xtajit64_flight_record_and_freeze( recorder, event, reason );
    else xtajit64_flight_record( recorder, event );
    xtajit64_flight_release_scratch( scratch );
}

#ifdef XTAJIT64_UNIXLIB_TEST
static int test_fail_flush_interval_append = -1;
static int test_flush_interval_append_count;
enum test_mutation_fault_point
{
    TEST_MUTATION_FAULT_NONE,
    TEST_MUTATION_FAULT_AFTER_BEGIN,
    TEST_MUTATION_FAULT_ENGINE_PAUSE,
};
static atomic_int test_mutation_fault_point;
static atomic_int test_mutation_fault_entered;
static atomic_int test_mutation_fault_release;
static atomic_int test_mutation_waiters;
static atomic_int test_hold_ec_hook;
static atomic_int test_ec_hook_entered;
static atomic_int test_release_ec_hook;
static atomic_int test_hold_non_ec_hook;
static atomic_int test_non_ec_hook_entered;
static atomic_int test_release_non_ec_hook;
static atomic_int test_pause_stop_count;
static atomic_int test_pause_stop_owner_violation;
static atomic_int test_hold_engine_start;
static atomic_int test_engine_start_entered;
static atomic_int test_release_engine_start;
static atomic_int test_hold_engine_result;
static atomic_int test_engine_result_entered;
static atomic_int test_release_engine_result;
static atomic_int test_disable_pause_hook;
static atomic_int test_emu_start_count;
static atomic_int test_context_write_count;
static atomic_int test_context_read_count;
static struct thread_engine *test_last_acquired_engine;
static atomic_int test_check_context_read_lock;
static atomic_int test_context_read_lock_violation;
#endif

C_ASSERT( sizeof(struct xtajit64_x64_context) ==
          sizeof(uc_switchyard_x86_64_transition_context) );
C_ASSERT( offsetof(struct xtajit64_x64_context, rip) ==
          offsetof(uc_switchyard_x86_64_transition_context, rip) );
C_ASSERT( offsetof(struct xtajit64_x64_context, mxcsr) ==
          offsetof(uc_switchyard_x86_64_transition_context, mxcsr) );
C_ASSERT( offsetof(struct xtajit64_x64_context, xmm) ==
          offsetof(uc_switchyard_x86_64_transition_context, xmm) );

static uint64_t align_down( uint64_t value )
{
    return value & ~(uint64_t)(XTAJIT64_GUEST_PAGE_SIZE - 1);
}

static uint64_t align_up( uint64_t value )
{
    return (value + XTAJIT64_GUEST_PAGE_SIZE - 1) &
           ~(uint64_t)(XTAJIT64_GUEST_PAGE_SIZE - 1);
}

static BOOL align_range( uint64_t address, uint64_t size, uint64_t *start, uint64_t *end )
{
    uint64_t limit;

    if (!size || address > UINT64_MAX - size) return FALSE;
    limit = address + size;
    if (limit > UINT64_MAX - (XTAJIT64_GUEST_PAGE_SIZE - 1)) return FALSE;
    *start = align_down( address );
    *end = align_up( limit );
    return *start < *end;
}

static unsigned int protection_to_unicorn( unsigned int protect )
{
    /* Guest guard handling is not bridged to Wine's one-shot exception path;
     * never turn a guarded logical page into directly accessible backing. */
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

static BOOL identity_page_table_layout( uint64_t highest_address,
                                        uint32_t *address_bits,
                                        size_t *table_size )
{
    uint32_t bits;

    if (!highest_address) return FALSE;
    bits = 64 - __builtin_clzll( highest_address );
    if (bits <= UC_SWITCHYARD_IDENTITY_PAGE_SHIFT || bits >= 64 ||
        bits - UC_SWITCHYARD_IDENTITY_PAGE_SHIFT >= sizeof(size_t) * 8)
        return FALSE;
    *address_bits = bits;
    *table_size = (size_t)1 <<
                  (bits - UC_SWITCHYARD_IDENTITY_PAGE_SHIFT);
    return TRUE;
}

static NTSTATUS allocate_identity_page_table_locked( uint64_t highest_address )
{
    uint32_t address_bits;
    size_t table_size;
    int flags = MAP_PRIVATE;
    void *table;

    if (!identity_page_table_layout( highest_address, &address_bits,
                                     &table_size ))
        return STATUS_INVALID_PARAMETER;
#ifdef MAP_ANONYMOUS
    flags |= MAP_ANONYMOUS;
#else
    flags |= MAP_ANON;
#endif
    table = mmap( NULL, table_size, PROT_READ | PROT_WRITE, flags, -1, 0 );
    if (table == MAP_FAILED) return STATUS_NO_MEMORY;
    provider.identity_page_flags = table;
    provider.identity_page_flags_size = table_size;
    provider.identity_address_bits = address_bits;
    return STATUS_SUCCESS;
}

#define XTAJIT64_RANGE_CPU_ALIAS 0x80000000u
static struct wine_arm64ec_cpu_alias_snapshot_v1 *cpu_alias_snapshot;

static uint8_t identity_page_permissions( const struct mapped_range *range )
{
    uint8_t flags = 0;

    if (range->state != MEM_COMMIT ||
        range->domain != XTAJIT64_MEMORY_ADDRESS_IDENTITY ||
        range->guest != range->host || (range->flags & XTAJIT64_RANGE_CPU_ALIAS))
        return 0;
    if (range->perms & UC_PROT_READ)
        flags |= UC_SWITCHYARD_IDENTITY_PAGE_READ;
    /* Executable mappings must retain Unicorn's shared-code write transaction
     * and translated-block invalidation path even when Windows also marks the
     * page writable. */
    if ((range->perms & (UC_PROT_WRITE | UC_PROT_EXEC)) == UC_PROT_WRITE)
        flags |= UC_SWITCHYARD_IDENTITY_PAGE_WRITE;
    return flags;
}

static BOOL identity_page_flag_span( const struct mapped_range *range,
                                     size_t *first, size_t *count )
{
    uint64_t last;

    if (!range->size ||
        (range->guest & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
        (range->size & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
        range->guest > UINT64_MAX - range->size)
        return FALSE;
    last = range->guest + range->size - 1;
    *first = range->guest >> UC_SWITCHYARD_IDENTITY_PAGE_SHIFT;
    *count = range->size >> UC_SWITCHYARD_IDENTITY_PAGE_SHIFT;
    return last <= provider.highest_user_address &&
           *first <= provider.identity_page_flags_size &&
           *count <= provider.identity_page_flags_size - *first;
}

static void publish_identity_page_permissions( size_t first, size_t count,
                                               uint8_t permissions )
{
    size_t i;

    for (i = 0; i < count; ++i)
    {
        uint8_t old = __atomic_load_n( &provider.identity_page_flags[first + i],
                                       __ATOMIC_RELAXED );
        uint8_t replacement =
            (old & UC_SWITCHYARD_IDENTITY_PAGE_OWNER_MASK) |
            (permissions & UC_SWITCHYARD_IDENTITY_PAGE_PERMISSIONS);

        __atomic_store_n( &provider.identity_page_flags[first + i], replacement,
                          __ATOMIC_RELAXED );
    }
}

/* All engines are quiescent while this runs.  Clear removed permissions first
 * and then publish replacement permissions so a protect or remap cannot leave
 * a stale direct-write grant behind.  Unicorn owns the upper, monotonic
 * executable-page participation bits; retaining them can only select the
 * conservative shared-code path after an unmap or engine teardown. */
static NTSTATUS publish_identity_page_flag_changes_locked(
    const struct range_array *removals, const struct range_array *additions )
{
    size_t i, first, count;

    if (!provider.identity_page_flags) return STATUS_INVALID_DEVICE_STATE;
    for (i = 0; i < removals->count; ++i)
        if (!identity_page_flag_span( &removals->data[i], &first, &count ))
            return STATUS_INVALID_ADDRESS;
    for (i = 0; i < additions->count; ++i)
        if (!identity_page_flag_span( &additions->data[i], &first, &count ))
            return STATUS_INVALID_ADDRESS;

    for (i = 0; i < removals->count; ++i)
    {
        identity_page_flag_span( &removals->data[i], &first, &count );
        publish_identity_page_permissions( first, count, 0 );
    }
    for (i = 0; i < additions->count; ++i)
    {
        uint8_t flags = identity_page_permissions( &additions->data[i] );

        identity_page_flag_span( &additions->data[i], &first, &count );
        publish_identity_page_permissions( first, count, flags );
    }
    return STATUS_SUCCESS;
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
           left->perms == right->perms && left->state == right->state &&
           left->domain == right->domain && left->flags == right->flags &&
           left->stale == right->stale;
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
    if (array->count == SIZE_MAX ||
        !range_array_reserve( array, array->count + 1 )) return FALSE;
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

static BOOL registry_covers_range( const struct range_array *ranges,
                                   uint64_t start, uint64_t end )
{
    uint64_t cursor = start;
    size_t i;

    for (i = 0; i < ranges->count && cursor < end; ++i)
    {
        const struct mapped_range *range = &ranges->data[i];
        uint64_t range_end = range->guest + range->size;

        if (range_end <= cursor || range->state != MEM_COMMIT) continue;
        if (range->guest > cursor) return FALSE;
        cursor = min( range_end, end );
    }
    return cursor == end;
}

static BOOL registry_covers_readable_range( const struct range_array *ranges,
                                            uint64_t start, uint64_t end )
{
    uint64_t cursor = start;
    size_t i, left = 0, right = ranges->count;

    while (left < right)
    {
        size_t mid = left + (right - left) / 2;
        const struct mapped_range *range = &ranges->data[mid];

        if (range->guest + range->size <= start) left = mid + 1;
        else right = mid;
    }

    for (i = left; i < ranges->count && cursor < end; ++i)
    {
        const struct mapped_range *range = &ranges->data[i];
        uint64_t range_end = range->guest + range->size;

        if (range_end <= cursor || range->state != MEM_COMMIT) continue;
        if (range->guest > cursor || !(range->perms & UC_PROT_READ)) return FALSE;
        cursor = min( range_end, end );
    }
    return cursor == end;
}

static unsigned int translation_required_perms( unsigned int flags )
{
    unsigned int perms = 0;

    if (flags & XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ) perms |= UC_PROT_READ;
    if (flags & XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE) perms |= UC_PROT_WRITE;
    if (flags & XTAJIT64_MEMORY_TRANSLATE_REQUIRE_EXECUTE) perms |= UC_PROT_EXEC;
    return perms;
}

static BOOL translate_guest_range_locked( uint64_t guest, uint64_t size,
                                          unsigned int required_perms,
                                          uint64_t *host,
                                          uint64_t *allocation_base,
                                          unsigned int *domain )
{
    const struct mapped_range *range;
    uint64_t cursor, end, host_cursor, host_start, allocation;
    size_t i, left = 0, right = provider.ranges.count;

    if (!guest || !size || guest > UINT64_MAX - size ||
        guest + size - 1 > provider.highest_user_address)
        return FALSE;
    end = guest + size;
    while (left < right)
    {
        size_t mid = left + (right - left) / 2;

        range = &provider.ranges.data[mid];
        if (range->guest + range->size <= guest) left = mid + 1;
        else right = mid;
    }
    if (left == provider.ranges.count) return FALSE;
    range = &provider.ranges.data[left];
    if (range->guest > guest || range->host > UINT64_MAX - (guest - range->guest))
        return FALSE;
    host_start = range->host + guest - range->guest;
    host_cursor = host_start;
    allocation = range->allocation_base;
    cursor = guest;

    for (i = left; i < provider.ranges.count && cursor < end; ++i)
    {
        uint64_t range_end, next, offset, chunk;

        range = &provider.ranges.data[i];
        range_end = range->guest + range->size;
        if (range_end <= cursor) continue;
        if (range->state != MEM_COMMIT || range->guest > cursor ||
            range->allocation_base != allocation ||
            range->domain != provider.ranges.data[left].domain ||
            (range->perms & required_perms) != required_perms)
            return FALSE;
        offset = cursor - range->guest;
        if (range->host > UINT64_MAX - offset || range->host + offset != host_cursor)
            return FALSE;
        next = min( range_end, end );
        chunk = next - cursor;
        if (host_cursor > UINT64_MAX - chunk) return FALSE;
        host_cursor += chunk;
        cursor = next;
    }
    if (cursor != end) return FALSE;
    *host = host_start;
    *allocation_base = allocation;
    if (domain) *domain = provider.ranges.data[left].domain;
    return TRUE;
}

static NTSTATUS translate_host_range_locked( uint64_t address, uint64_t size,
                                              unsigned int required_perms,
                                              uint64_t *guest,
                                              uint64_t *allocation_base,
                                              unsigned int *domain )
{
    NTSTATUS status = STATUS_INVALID_ADDRESS;
    uint64_t found_guest = 0, found_allocation = 0;
    unsigned int found_domain = XTAJIT64_MEMORY_ADDRESS_INVALID;
    size_t i;

    for (i = 0; i < provider.ranges.count; ++i)
    {
        const struct mapped_range *range = &provider.ranges.data[i];
        uint64_t range_end, candidate_guest, candidate_host, candidate_allocation;
        unsigned int candidate_domain;

        if (range->state != MEM_COMMIT || range->host > UINT64_MAX - range->size) continue;
        range_end = range->host + range->size;
        if (address < range->host || address >= range_end) continue;
        if (range->guest > UINT64_MAX - (address - range->host)) continue;
        candidate_guest = range->guest + address - range->host;
        if (!translate_guest_range_locked( candidate_guest, size, required_perms,
                                           &candidate_host, &candidate_allocation,
                                           &candidate_domain ) ||
            candidate_host != address)
            continue;
        if (!status && candidate_guest != found_guest)
            return STATUS_OBJECT_NAME_COLLISION;
        found_guest = candidate_guest;
        found_allocation = candidate_allocation;
        found_domain = candidate_domain;
        status = STATUS_SUCCESS;
    }
    if (!status)
    {
        *guest = found_guest;
        *allocation_base = found_allocation;
        if (domain) *domain = found_domain;
    }
    return status;
}

static NTSTATUS memory_translate( void *args )
{
    struct xtajit64_memory_translate_params *params = args;
    uint64_t address, size, guest = 0, host = 0, allocation_base = 0;
    unsigned int direction, required_perms;
    NTSTATUS status = STATUS_INVALID_ADDRESS;

    if (!params || params->domain ||
        (params->flags & ~XTAJIT64_MEMORY_TRANSLATE_VALID_FLAGS))
        return STATUS_INVALID_PARAMETER;
    direction = params->flags & XTAJIT64_MEMORY_TRANSLATE_DIRECTION_MASK;
    if (direction != XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST &&
        direction != XTAJIT64_MEMORY_TRANSLATE_HOST_TO_GUEST)
        return STATUS_INVALID_PARAMETER;
    address = params->address;
    size = params->size;
    if (!address || !size || address > UINT64_MAX - size)
        return STATUS_INVALID_PARAMETER;
    required_perms = translation_required_perms( params->flags );
    params->guest = params->host = params->allocation_base = 0;
    params->exception_stack_limit = params->exception_stack_base = 0;

    pthread_mutex_lock( &provider.mutex );
    while (provider.mutating && provider.initialized)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (!provider.initialized || provider.shutting_down) status = STATUS_INVALID_HANDLE;
    else if (provider.poison_status) status = provider.poison_status;
    else if (direction == XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST)
    {
        guest = address;
        if (translate_guest_range_locked( guest, size, required_perms,
                                          &host, &allocation_base,
                                          &params->domain ))
            status = STATUS_SUCCESS;
    }
    else if (!(status = translate_host_range_locked( address, size, required_perms,
                                                     &guest, &allocation_base,
                                                     &params->domain )))
        host = address;
    pthread_mutex_unlock( &provider.mutex );

    if (!status)
    {
        params->guest = guest;
        params->host = host;
        params->allocation_base = allocation_base;
        uint64_t limit, base;
        __wine_get_arm64ec_exception_stack_v1( &limit, &base );
        params->exception_stack_limit = limit;
        params->exception_stack_base = base;
    }
    return status;
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

    if (old->count > SIZE_MAX - 3 ||
        !range_array_reserve( result, old->count + 3 )) return STATUS_NO_MEMORY;
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

    if (old->count == SIZE_MAX ||
        !range_array_reserve( result, old->count + 1 )) return STATUS_NO_MEMORY;
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

static void mark_engine_mappings_stale_locked( uint64_t start, uint64_t size,
                                               uint64_t allocation_base )
{
    struct thread_engine *engine;
    uint64_t end = size ? start + size : 0;

    for (engine = provider.engines; engine; engine = engine->next)
    {
        size_t i = 0;

        if (size)
        {
            size_t left = 0, right = engine->mapped_ranges.count;

            while (left < right)
            {
                size_t mid = left + (right - left) / 2;
                const struct mapped_range *range = &engine->mapped_ranges.data[mid];

                if (range->guest + range->size <= start) left = mid + 1;
                else right = mid;
            }
            i = left;
        }
        for (; i < engine->mapped_ranges.count; ++i)
        {
            struct mapped_range *range = &engine->mapped_ranges.data[i];

            if (size)
            {
                if (range->guest >= end) break;
                if (!range_overlaps( range, start, end )) continue;
            }
            else if (range->allocation_base != allocation_base) continue;
            range->stale = TRUE;
        }
    }
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

static uc_err map_host_range( struct thread_engine *engine, uint64_t guest, uint64_t host,
                              uint64_t size, unsigned int perms )
{
    uint64_t guest_page, guest_end, host_page, host_end;

    if (!size) return UC_ERR_OK;
    if (((guest ^ host) & (XTAJIT64_GUEST_PAGE_SIZE - 1))) return UC_ERR_ARG;
    if (!align_range( guest, size, &guest_page, &guest_end ) ||
        !align_range( host, size, &host_page, &host_end ) ||
        guest_end - guest_page != host_end - host_page)
        return UC_ERR_ARG;

    /* A collision here means the engine no longer matches the canonical
     * registry.  Protecting an unknown existing region would silently retain
     * the wrong host backing, so let the caller poison the provider. */
    while (guest_page < guest_end)
    {
        uint64_t backing = host_page, end = guest_end;
        unsigned int i;
        uc_err err;
        if (guest_page == host_page && cpu_alias_snapshot)
            for (i = 0; i < cpu_alias_snapshot->count; ++i)
            {
                const struct wine_arm64ec_cpu_alias_range_v1 *range = &cpu_alias_snapshot->ranges[i];
                if (guest_page >= range->address && guest_page < range->address + 16384)
                {
                    backing = range->backing + guest_page - range->address;
                    end = min( end, range->address + 16384 );
                    break;
                }
                if (range->address > guest_page) end = min( end, range->address );
            }
        err = uc_mem_map_ptr( engine->uc, guest_page, end - guest_page, perms,
                                     (void *)(uintptr_t)backing );
        if (err) return err;
        host_page += end - guest_page;
        guest_page = end;
    }
    return UC_ERR_OK;
}

static uc_err unmap_range( struct thread_engine *engine, uint64_t guest, uint64_t size )
{
    if (!size) return UC_ERR_OK;
    return uc_mem_unmap( engine->uc, guest, size );
}

static void trace_mapping_diagnostic( const struct thread_engine *engine,
                                      const char *event, uint64_t latest_size )
{
#ifdef XTAJIT64_UNIXLIB_TEST
    (void)engine;
    (void)event;
    (void)latest_size;
#else
    TRACE_(xtajitmap)(
        "pid %ld engine %llu pool=%u/%u/%u event %s maps %llu bytes %llu "
        "buckets 4k=%llu 16k=%llu "
        "64k=%llu 1m=%llu large=%llu max=%llu latest=%llu mapped=%zu "
        "syncs=%llu resync-unmaps=%llu/%llu self-reads=%llu/%llu/%llu generation=%llu\n",
        (long)getpid(), (unsigned long long)engine->diagnostic_id,
        engine->diagnostic_pool_in_use, engine->diagnostic_pool_size,
        engine->diagnostic_pool_high_water, event,
        (unsigned long long)engine->demand_map_calls,
        (unsigned long long)engine->demand_map_bytes,
        (unsigned long long)engine->demand_map_4k_calls,
        (unsigned long long)engine->demand_map_16k_calls,
        (unsigned long long)engine->demand_map_64k_calls,
        (unsigned long long)engine->demand_map_1m_calls,
        (unsigned long long)engine->demand_map_large_calls,
        (unsigned long long)engine->demand_map_max_size,
        (unsigned long long)latest_size, engine->mapped_ranges.count,
        (unsigned long long)engine->registry_sync_calls,
        (unsigned long long)engine->resync_unmap_calls,
        (unsigned long long)engine->resync_unmap_bytes,
        (unsigned long long)engine->direct_self_read_attempts,
        (unsigned long long)engine->direct_self_read_completions,
        (unsigned long long)engine->direct_self_read_bytes,
        (unsigned long long)engine->mapping_generation );
#endif
}

static const struct mapped_range *find_canonical_mapping( uint64_t address,
                                                          uint64_t size,
                                                          unsigned int perms )
{
    const struct mapped_range *range;
    size_t left = 0, right = provider.ranges.count;
    uint64_t end;

    if (!size || address > UINT64_MAX - size) return NULL;
    end = address + size;
    while (left < right)
    {
        size_t mid = left + (right - left) / 2;

        if (provider.ranges.data[mid].guest <= address) left = mid + 1;
        else right = mid;
    }
    if (!left) return NULL;
    range = &provider.ranges.data[left - 1];
    if (range->state != MEM_COMMIT || range->size > UINT64_MAX - range->guest ||
        address < range->guest || end > range->guest + range->size ||
        (range->perms & perms) != perms)
        return NULL;
    return range;
}

static const struct mapped_range *find_engine_mapping( const struct thread_engine *engine,
                                                        uint64_t address, uint64_t size )
{
    const struct mapped_range *range;
    size_t left = 0, right;
    uint64_t end;

    if (!engine || !size || address > UINT64_MAX - size) return NULL;
    end = address + size;
    right = engine->mapped_ranges.count;
    while (left < right)
    {
        size_t mid = left + (right - left) / 2;

        if (engine->mapped_ranges.data[mid].guest <= address) left = mid + 1;
        else right = mid;
    }
    if (!left) return NULL;
    range = &engine->mapped_ranges.data[left - 1];
    if (range->size > UINT64_MAX - range->guest || address < range->guest ||
        end > range->guest + range->size)
        return NULL;
    return range;
}

#ifndef XTAJIT64_UNIXLIB_TEST
static void trace_interrupt_diagnostic_locked( struct thread_engine *engine, uint64_t rip )
{
    const struct mapped_range *canonical, *mapped;
    unsigned char bytes[8];
    char hex[2 * sizeof(bytes) + 1] = "-";
    uint64_t start, available;
    size_t count = 0, i;

    if (!TRACE_ON( xtajittrap ) || !engine ||
        engine->flight_stop_detail0 == XTAJIT64_FLIGHT_UNKNOWN_U64)
        return;
    start = rip >= 2 ? rip - 2 : rip;
    canonical = find_canonical_mapping( start, 1, 0 );
    mapped = find_engine_mapping( engine, start, 1 );
    if (canonical && mapped && canonical->size <= UINT64_MAX - canonical->guest)
    {
        available = canonical->guest + canonical->size - start;
        count = available < sizeof(bytes) ? (size_t)available : sizeof(bytes);
        if (!count || uc_mem_read( engine->uc, start, bytes, count ) != UC_ERR_OK)
            count = 0;
    }
    if (count)
    {
        for (i = 0; i < count; ++i)
            snprintf( hex + 2 * i, sizeof(hex) - 2 * i, "%02x", bytes[i] );
    }
    TRACE_(xtajittrap)(
        "pid %ld engine %llu interrupt=%#llx reason=%u rip=%#llx bytes@%#llx=%s/%zu "
        "canonical=%u/%#llx/%#llx/%#llx/%#llx/%#x/%#x/%#x/%#x/%u "
        "mapped=%u/%#llx/%#llx/%#llx/%#x/%u generation=%llu/%llu\n",
        (long)getpid(), (unsigned long long)engine->diagnostic_id,
        (unsigned long long)engine->flight_stop_detail0,
        engine->stop_reason,
        (unsigned long long)rip, (unsigned long long)start, hex, count,
        !!canonical, (unsigned long long)(canonical ? canonical->guest : 0),
        (unsigned long long)(canonical ? canonical->host : 0),
        (unsigned long long)(canonical ? canonical->size : 0),
        (unsigned long long)(canonical ? canonical->allocation_base : 0),
        canonical ? canonical->perms : 0, canonical ? canonical->state : 0,
        canonical ? canonical->domain : 0, canonical ? canonical->flags : 0,
        canonical ? canonical->permanent : 0,
        !!mapped, (unsigned long long)(mapped ? mapped->guest : 0),
        (unsigned long long)(mapped ? mapped->host : 0),
        (unsigned long long)(mapped ? mapped->size : 0),
        mapped ? mapped->perms : 0, mapped ? mapped->stale : 0,
        (unsigned long long)engine->mapping_generation,
        (unsigned long long)provider.generation );
}
#endif

static uc_err demand_map_canonical_range( struct thread_engine *engine,
                                          uint64_t address, uint64_t size,
                                          unsigned int perms, BOOL *found,
                                          BOOL *mapped )
{
    const struct mapped_range *range;
    struct mapped_range mapping;
    struct range_array replacement = {0}, old;
    uint64_t start, end, missing_start, mapping_start, mapping_end, range_end;
    NTSTATUS status;
    uc_err err;
    size_t i;

    *found = FALSE;
    *mapped = FALSE;
    if (!(range = find_canonical_mapping( address, size, 0 ))) return UC_ERR_MAP;
    *found = TRUE;
    /* An engine that has not touched a canonical page reports UNMAPPED even
     * when the requested guest access violates that page's protection.  Keep
     * this as a Windows access violation instead of misclassifying it as a
     * late native mapping that should be registered again. */
    if ((range->perms & perms) != perms) return UC_ERR_OK;

    range_end = range->guest + range->size;
    if (!align_range( address, size, &start, &end ) ||
        start < range->guest || end > range_end)
        return UC_ERR_ARG;

    /* Canonical ranges can split or coalesce between generations.  Map the
     * entire still-unmapped gap containing the first missing part of the
     * access, bounded by retained actual mappings.  A multi-byte access may
     * begin in a retained page and end in an untouched page, so overlap with
     * the requested range is not itself a mapping collision.  Mapping the
     * whole enlarged canonical range would collide with a retained prefix or
     * suffix; mapping one guest page per fault makes Unicorn rebuild its
     * MemoryRegion topology thousands of times during a large application
     * startup. */
    missing_start = start;
    mapping_start = range->guest;
    mapping_end = range_end;
    for (i = 0; i < engine->mapped_ranges.count; ++i)
    {
        const struct mapped_range *mapped = &engine->mapped_ranges.data[i];
        uint64_t mapped_end;

        if (mapped->size > UINT64_MAX - mapped->guest) return UC_ERR_ARG;
        mapped_end = mapped->guest + mapped->size;
        if (mapped_end <= missing_start)
        {
            mapping_start = max( mapping_start, mapped_end );
            continue;
        }
        if (mapped->guest > missing_start)
        {
            mapping_end = min( mapping_end, mapped->guest );
            break;
        }
        mapping_start = max( mapping_start, mapped_end );
        missing_start = mapped_end;
        if (missing_start >= end) return UC_ERR_MAP;
    }
    if (mapping_start > missing_start || mapping_end <= missing_start ||
        mapping_start >= mapping_end)
        return UC_ERR_MAP;
    if (mapping_end - mapping_start > XTAJIT64_DEMAND_MAP_MAX_SIZE)
    {
        /* Keep large image and sparse reservation faults coarse enough to avoid
         * per-page hook churn, but do not force every pooled engine to
         * instantiate hundreds of megabytes after a single code or data touch.
         * The required Unicorn contract invokes invalid-memory hooks for an
         * unmapped atomic read-modify-write target, so writable data can follow
         * this same bounded first-touch path without eager process-wide
         * cloning into every engine. */
        mapping_start = missing_start;
        mapping_end = min( mapping_end,
                           mapping_start + XTAJIT64_DEMAND_MAP_MAX_SIZE );
    }
    mapping = range_slice( range, mapping_start, mapping_end );

    for (i = 0; i < engine->mapped_ranges.count; ++i)
        if (range_overlaps( &engine->mapped_ranges.data[i], mapping.guest,
                            mapping.guest + mapping.size ))
            return UC_ERR_MAP;
    status = build_mapped_registry( &engine->mapped_ranges, &mapping, &replacement );
    if (status) return status == STATUS_NO_MEMORY ? UC_ERR_NOMEM : UC_ERR_ARG;
    if ((err = map_host_range( engine, mapping.guest, mapping.host, mapping.size,
                               mapping.perms )) != UC_ERR_OK)
    {
        range_array_free( &replacement );
        return err;
    }

    old = engine->mapped_ranges;
    engine->mapped_ranges = replacement;
    range_array_free( &old );

    ++engine->demand_map_calls;
    engine->demand_map_bytes += mapping.size;
    if (mapping.size <= XTAJIT64_GUEST_PAGE_SIZE) ++engine->demand_map_4k_calls;
    else if (mapping.size <= 4 * XTAJIT64_GUEST_PAGE_SIZE)
        ++engine->demand_map_16k_calls;
    else if (mapping.size <= 16 * XTAJIT64_GUEST_PAGE_SIZE)
        ++engine->demand_map_64k_calls;
    else if (mapping.size <= 256 * XTAJIT64_GUEST_PAGE_SIZE)
        ++engine->demand_map_1m_calls;
    else ++engine->demand_map_large_calls;
    engine->demand_map_max_size = max( engine->demand_map_max_size, mapping.size );
    if (!(engine->demand_map_calls & (engine->demand_map_calls - 1)))
        trace_mapping_diagnostic( engine, "map", mapping.size );
    *mapped = TRUE;
    return UC_ERR_OK;
}

/* Unicorn can report the full operand at its first byte even when the fault
 * is on a later page. Validate each canonical range before mapping any part,
 * and preserve the first inaccessible byte for exception/reconciliation. */
static BOOL check_canonical_access( uint64_t address, uint64_t size,
                                    unsigned int perms, BOOL *found,
                                    uint64_t *fault_address )
{
    const struct mapped_range *range;
    uint64_t cursor = address, end;

    *found = FALSE;
    *fault_address = address;
    if (!size || address > UINT64_MAX - size) return FALSE;
    end = address + size;
    while (cursor < end)
    {
        *fault_address = cursor;
        if (!(range = find_canonical_mapping( cursor, 1, 0 ))) return FALSE;
        if ((range->perms & perms) != perms)
        {
            *found = TRUE;
            return FALSE;
        }
        cursor = min( end, range->guest + range->size );
    }
    *found = TRUE;
    *fault_address = address;
    return TRUE;
}

static uc_err demand_map_canonical_access( struct thread_engine *engine,
                                           uint64_t address, uint64_t size,
                                           unsigned int perms, BOOL *found,
                                           BOOL *mapped, uint64_t *fault_address )
{
    const struct mapped_range *range;
    uint64_t cursor = address, end;
    BOOL chunk_found, chunk_mapped;
    uc_err err;

    *mapped = FALSE;
    if (!check_canonical_access( address, size, perms, found, fault_address ))
        return *found ? UC_ERR_OK : UC_ERR_MAP;
    end = address + size;
    while (cursor < end)
    {
        /* A previous fault or this loop may already have mapped this prefix.
         * Never ask the single-gap mapper to remap retained engine backing. */
        if ((range = find_engine_mapping( engine, cursor, 1 )))
        {
            if ((range->perms & perms) != perms) return UC_ERR_MAP;
            cursor = min( end, range->guest + range->size );
            continue;
        }
        range = find_canonical_mapping( cursor, 1, perms );
        if (!range) return UC_ERR_MAP;
        err = demand_map_canonical_range( engine, cursor,
                min( end, range->guest + range->size ) - cursor,
                perms, &chunk_found, &chunk_mapped );
        if (err != UC_ERR_OK) return err;
        if (!chunk_found || !chunk_mapped) return UC_ERR_MAP;
        *mapped = TRUE;
        /* Recheck actual coverage: the gap mapper deliberately caps large
         * mappings and can stop at a retained suffix inside this range. */
    }
    /* An UNMAPPED hook with no missing engine mapping is inconsistent; do not
     * report success and retry forever without making progress. */
    return *mapped ? UC_ERR_OK : UC_ERR_MAP;
}

static void poison_provider_locked( NTSTATUS status )
{
    if (!provider.poison_status)
        provider.poison_status = status ? status : STATUS_UNSUCCESSFUL;
}

static const char *mutation_kind_name( enum mutation_kind kind )
{
    switch (kind)
    {
    case MUTATION_MAP: return "map";
    case MUTATION_UNMAP: return "unmap";
    case MUTATION_PROTECT: return "protect";
    case MUTATION_RESYNC: return "resync";
    case MUTATION_FLUSH: return "flush";
    case MUTATION_POISON: return "poison";
    default: return "none";
    }
}

static const char *mutation_stage_name( enum mutation_stage stage )
{
    switch (stage)
    {
    case MUTATION_STAGE_PAUSE: return "pause";
    case MUTATION_STAGE_WAIT: return "wait";
    case MUTATION_STAGE_PREPARE: return "prepare";
    case MUTATION_STAGE_APPLY: return "apply";
    case MUTATION_STAGE_PUBLISH: return "publish";
    default: return "idle";
    }
}

static BOOL current_thread_owns_mutation_locked(void)
{
    return provider.mutating && provider.mutation_owner_valid &&
           pthread_equal( provider.mutation_owner, pthread_self() );
}

static void set_mutation_stage_locked( enum mutation_stage stage )
{
    if (current_thread_owns_mutation_locked()) provider.mutation_stage = stage;
}

#ifdef XTAJIT64_UNIXLIB_TEST
static void test_mutation_fault_checkpoint( enum test_mutation_fault_point point )
{
    if (atomic_load_explicit( &test_mutation_fault_point, memory_order_acquire ) != point)
        return;
    atomic_store_explicit( &test_mutation_fault_entered, 1, memory_order_release );
    while (!atomic_load_explicit( &test_mutation_fault_release, memory_order_acquire ))
        sched_yield();
    XTAJIT64_TEST_RAISE_EXCEPTION();
}
#else
static void test_mutation_fault_checkpoint( int point )
{
    (void)point;
}
# define TEST_MUTATION_FAULT_AFTER_BEGIN 0
# define TEST_MUTATION_FAULT_ENGINE_PAUSE 0
#endif

static BOOL any_engine_running_locked(void)
{
    struct thread_engine *engine;

    for (engine = provider.engines; engine; engine = engine->next)
        if (engine->running) return TRUE;
    return FALSE;
}

static BOOL any_engine_in_use_locked(void)
{
    struct thread_engine *engine;

    for (engine = provider.engines; engine; engine = engine->next)
        if (engine->in_use) return TRUE;
    return FALSE;
}

static void request_engine_pause_locked( struct thread_engine *engine )
{
    uc_err err;

    if (!engine->running) return;
    if (engine->flight_recorder)
        flight_record_engine_event( engine, XTAJIT64_FLIGHT_EVENT_SUSPEND_REQUEST,
                                    XTAJIT64_FLIGHT_REASON_NONE,
                                    XTAJIT64_FLIGHT_UNKNOWN_U32,
                                    XTAJIT64_FLIGHT_UNKNOWN_U64,
                                    XTAJIT64_FLIGHT_UNKNOWN_U64 );
    atomic_store_explicit( &engine->pause_requested, true, memory_order_release );
    /* The ordinary block hook is absent from production hot execution.  Ask
     * Unicorn directly to leave after the current guest instruction; the owner
     * thread will publish running=FALSE only after it has exported the exact
     * architectural context. */
    if ((err = uc_emu_stop_at_instruction_boundary( engine->uc )) != UC_ERR_OK)
    {
        engine->mapping_error = err;
        engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
        poison_provider_locked( STATUS_UNSUCCESSFUL );
        uc_emu_stop( engine->uc );
    }
    test_mutation_fault_checkpoint( TEST_MUTATION_FAULT_ENGINE_PAUSE );
}

static NTSTATUS claim_mutation_locked( enum mutation_kind kind, BOOL advance_generation )
{
    while (provider.mutating && provider.initialized)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (!provider.initialized || provider.shutting_down) return STATUS_INVALID_HANDLE;
    if (provider.poison_status) return provider.poison_status;

    provider.mutating = TRUE;
    provider.mutation_owner = pthread_self();
    provider.mutation_owner_valid = TRUE;
    provider.mutation_kind = kind;
    provider.mutation_stage = MUTATION_STAGE_PAUSE;
    if (advance_generation) ++provider.generation;
    return STATUS_SUCCESS;
}

static void pause_mutation_engines_locked(void)
{
    struct thread_engine *engine;

    for (engine = provider.engines; engine; engine = engine->next)
        request_engine_pause_locked( engine );
}

static NTSTATUS wait_for_mutation_engines_locked(void)
{
    provider.mutation_stage = MUTATION_STAGE_WAIT;
    while (any_engine_running_locked())
        pthread_cond_wait( &provider.cond, &provider.mutex );
    provider.mutation_stage = MUTATION_STAGE_PREPARE;
    return provider.poison_status;
}

static void finish_mutation_locked(void)
{
    provider.mutation_owner_valid = FALSE;
    provider.mutation_kind = MUTATION_NONE;
    provider.mutation_stage = MUTATION_STAGE_IDLE;
    provider.mutating = FALSE;
    pthread_cond_broadcast( &provider.cond );
}

static NTSTATUS record_mutation_access_violation_locked( enum mutation_kind kind,
                                                         enum mutation_stage stage,
                                                         uint64_t generation )
{
    provider.last_fault_kind = kind;
    provider.last_fault_stage = stage;
    provider.last_fault_generation = generation;
    if (provider.initialized) poison_provider_locked( STATUS_ACCESS_VIOLATION );
    if (current_thread_owns_mutation_locked()) finish_mutation_locked();
    return STATUS_ACCESS_VIOLATION;
}

static NTSTATUS recover_mutation_access_violation_locked(void)
{
    return record_mutation_access_violation_locked( provider.mutation_kind,
                                                    provider.mutation_stage,
                                                    provider.generation );
}

static void report_mutation_access_violation( enum mutation_kind kind,
                                              enum mutation_stage stage,
                                              uint64_t generation )
{
    ERR( "access violation during x64 %s mutation stage %s at generation %llu\n",
         mutation_kind_name( kind ), mutation_stage_name( stage ),
         (unsigned long long)generation );
}

static BOOL is_ec_code( uint64_t address )
{
    uint64_t page, word;

    if (!provider.ec_bitmap || address > provider.highest_user_address) return FALSE;
    page = address >> provider.ec_page_shift;
    word = provider.ec_bitmap[page / 64];
    return (word >> (page & 63)) & 1;
}

#ifdef __APPLE__
static BOOL query_host_page( uint64_t address, unsigned int *perms )
{
    vm_region_submap_info_data_64_t info;
    mach_vm_address_t region = address;
    mach_vm_size_t size;
    natural_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    uint32_t depth = 0;
    kern_return_t ret;

    ret = mach_vm_region_recurse( mach_task_self(), &region, &size, &depth,
                                  (vm_region_recurse_info_t)&info, &count );
    if (ret != KERN_SUCCESS || region > address || address - region >= size) return FALSE;

    *perms = 0;
    if (info.protection & VM_PROT_READ) *perms |= UC_PROT_READ;
    if (info.protection & VM_PROT_WRITE) *perms |= UC_PROT_WRITE;
    if (info.protection & VM_PROT_EXECUTE) *perms |= UC_PROT_EXEC;
    return TRUE;
}

#endif

static BOOL unmapped_ec_target_is_executable( uint64_t address )
{
#ifdef __APPLE__
    unsigned int perms;

    return query_host_page( address, &perms ) && (perms & UC_PROT_EXEC);
#else
    return FALSE;
#endif
}

#ifdef __APPLE__
enum direct_self_read_operand
{
    DIRECT_SELF_READ_OPERAND_STACK,
    DIRECT_SELF_READ_OPERAND_SOURCE,
    DIRECT_SELF_READ_OPERAND_DESTINATION,
    DIRECT_SELF_READ_OPERAND_RESULT,
};

static void direct_self_read_increment( uint64_t *value )
{
    if (*value != UINT64_MAX) ++*value;
}

static void direct_self_read_add( uint64_t *value, uint64_t addend )
{
    if (*value > UINT64_MAX - addend) *value = UINT64_MAX;
    else *value += addend;
}

#ifndef XTAJIT64_UNIXLIB_TEST
static void render_direct_self_read_diagnostics(
    const struct direct_self_read_diagnostics *diagnostics, uint64_t engine_id,
    uint64_t attempts, uint64_t completions, uint64_t completed_bytes );

static void direct_self_read_maybe_report( struct thread_engine *engine )
{
    uint64_t next;

    if (!provider.direct_self_read_stats_enabled) return;
    next = engine->direct_self_read_next_report;
    if (!next) next = 1;
    if (engine->direct_self_read_diagnostics.syscalls < next)
    {
        engine->direct_self_read_next_report = next;
        return;
    }
    render_direct_self_read_diagnostics( &engine->direct_self_read_diagnostics,
                                         engine->diagnostic_id,
                                         engine->direct_self_read_attempts,
                                         engine->direct_self_read_completions,
                                         engine->direct_self_read_bytes );
    if (next < 1024) next = 1024;
    else if (next <= UINT64_MAX / 4) next *= 4;
    else next = UINT64_MAX;
    engine->direct_self_read_next_report = next;
}
#else
static void direct_self_read_maybe_report( struct thread_engine *engine )
{
    (void)engine;
}
#endif

static void direct_self_read_record_rejection( struct thread_engine *engine,
                                               enum direct_self_read_rejection reason )
{
    if (provider.direct_self_read_stats_enabled)
    {
        direct_self_read_increment( &engine->direct_self_read_diagnostics.rejections[reason] );
        direct_self_read_maybe_report( engine );
    }
}

static void direct_self_read_record_request( struct thread_engine *engine, uint64_t size )
{
    struct direct_self_read_diagnostics *diagnostics;
    enum direct_self_read_size_bucket bucket;

    if (!provider.direct_self_read_stats_enabled) return;
    diagnostics = &engine->direct_self_read_diagnostics;
    direct_self_read_increment( &diagnostics->current_process );
    direct_self_read_add( &diagnostics->requested_bytes, size );
    if (size > diagnostics->maximum_size) diagnostics->maximum_size = size;
    if (!size) bucket = DIRECT_SELF_READ_SIZE_ZERO;
    else if (size <= 64) bucket = DIRECT_SELF_READ_SIZE_64;
    else if (size <= 0x1000) bucket = DIRECT_SELF_READ_SIZE_4K;
    else if (size <= XTAJIT64_DIRECT_SELF_READ_MAX_SIZE) bucket = DIRECT_SELF_READ_SIZE_64K;
    else if (size <= 0x100000) bucket = DIRECT_SELF_READ_SIZE_1M;
    else if (size <= 0x1000000) bucket = DIRECT_SELF_READ_SIZE_16M;
    else bucket = DIRECT_SELF_READ_SIZE_LARGE;
    direct_self_read_increment( &diagnostics->size_buckets[bucket] );
}

static void direct_self_read_record_range_rejection(
    struct thread_engine *engine, enum direct_self_read_operand operand,
    enum direct_self_read_range_result result )
{
    enum direct_self_read_rejection reason;

    switch (operand)
    {
    case DIRECT_SELF_READ_OPERAND_STACK:
        reason = result == DIRECT_SELF_READ_RANGE_PERMISSIONS ?
                 DIRECT_SELF_READ_REJECT_STACK_PERMISSIONS :
                 result == DIRECT_SELF_READ_RANGE_DOMAIN ?
                 DIRECT_SELF_READ_REJECT_STACK_DOMAIN : DIRECT_SELF_READ_REJECT_STACK_RANGE;
        break;
    case DIRECT_SELF_READ_OPERAND_SOURCE:
        reason = result == DIRECT_SELF_READ_RANGE_PERMISSIONS ?
                 DIRECT_SELF_READ_REJECT_SOURCE_PERMISSIONS :
                 result == DIRECT_SELF_READ_RANGE_DOMAIN ?
                 DIRECT_SELF_READ_REJECT_SOURCE_DOMAIN : DIRECT_SELF_READ_REJECT_SOURCE_RANGE;
        break;
    case DIRECT_SELF_READ_OPERAND_DESTINATION:
        reason = result == DIRECT_SELF_READ_RANGE_PERMISSIONS ?
                 DIRECT_SELF_READ_REJECT_DESTINATION_PERMISSIONS :
                 result == DIRECT_SELF_READ_RANGE_DOMAIN ?
                 DIRECT_SELF_READ_REJECT_DESTINATION_DOMAIN :
                 DIRECT_SELF_READ_REJECT_DESTINATION_RANGE;
        break;
    default:
        reason = result == DIRECT_SELF_READ_RANGE_PERMISSIONS ?
                 DIRECT_SELF_READ_REJECT_RESULT_PERMISSIONS :
                 result == DIRECT_SELF_READ_RANGE_DOMAIN ?
                 DIRECT_SELF_READ_REJECT_RESULT_DOMAIN : DIRECT_SELF_READ_REJECT_RESULT_RANGE;
        break;
    }
    direct_self_read_record_rejection( engine, reason );
}

static enum direct_self_read_range_result translate_direct_identity_range_locked(
    uint64_t guest, uint64_t size, unsigned int required_perms, uint64_t *host )
{
    uint64_t allocation_base;
    unsigned int domain;

    if (translate_guest_range_locked( guest, size, required_perms, host,
                                      &allocation_base, &domain ))
        return domain == XTAJIT64_MEMORY_ADDRESS_IDENTITY ?
               DIRECT_SELF_READ_RANGE_OK : DIRECT_SELF_READ_RANGE_DOMAIN;

    /* Extra classification work is diagnostic-only.  The normal fallback
     * remains one failed registry lookup when statistics are disabled. */
    if (!provider.direct_self_read_stats_enabled ||
        !translate_guest_range_locked( guest, size, 0, host,
                                       &allocation_base, &domain ))
        return DIRECT_SELF_READ_RANGE_MISSING;
    return domain == XTAJIT64_MEMORY_ADDRESS_IDENTITY ?
           DIRECT_SELF_READ_RANGE_PERMISSIONS : DIRECT_SELF_READ_RANGE_DOMAIN;
}

static uc_err try_direct_self_read( struct thread_engine *engine, uint64_t rip,
                                    uint64_t process, uint64_t *next_rip,
                                    BOOL *handled )
{
    static const int read_regs[] =
    {
        UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP,
    };
    uint64_t source, destination, size, rsp, bytes_read = 0;
    uint64_t source_host = 0, destination_host = 0, bytes_read_host = 0;
    void *read_values[] = {&source, &destination, &size, &rsp};
    uint64_t status = STATUS_SUCCESS;
    mach_vm_size_t copied;
    enum direct_self_read_range_result range_result;
    kern_return_t ret;
    uc_err err;

    *handled = FALSE;
    if (provider.direct_self_read_stats_enabled)
        direct_self_read_increment( &engine->direct_self_read_diagnostics.syscalls );
    if (process != ~(uint64_t)0)
    {
        direct_self_read_record_rejection( engine, DIRECT_SELF_READ_REJECT_PROCESS );
        return UC_ERR_OK;
    }
    ++engine->direct_self_read_attempts;
    if ((err = uc_reg_read_batch( engine->uc, read_regs, read_values,
                                  ARRAY_SIZE(read_regs) )) != UC_ERR_OK)
    {
        direct_self_read_record_rejection( engine, DIRECT_SELF_READ_REJECT_REGISTERS );
        return err;
    }
    direct_self_read_record_request( engine, size );
    if (size > XTAJIT64_DIRECT_SELF_READ_MAX_SIZE)
    {
        direct_self_read_record_rejection( engine, DIRECT_SELF_READ_REJECT_SIZE );
        return UC_ERR_OK;
    }
    if (rsp < engine->stack_limit || rsp > engine->stack_base ||
        rsp > UINT64_MAX - 0x30 || rsp + 0x30 > engine->stack_base ||
        rsp + 0x28 < engine->stack_limit)
    {
        direct_self_read_record_rejection( engine, DIRECT_SELF_READ_REJECT_STACK_BOUNDS );
        return UC_ERR_OK;
    }
    range_result = translate_direct_identity_range_locked( rsp + 0x28,
                                                           sizeof(bytes_read),
                                                           UC_PROT_READ,
                                                           &source_host );
    if (range_result != DIRECT_SELF_READ_RANGE_OK)
    {
        direct_self_read_record_range_rejection( engine, DIRECT_SELF_READ_OPERAND_STACK,
                                                 range_result );
        return UC_ERR_OK;
    }
    copied = 0;
    ret = mach_vm_read_overwrite( mach_task_self(), source_host, sizeof(bytes_read),
                                  (mach_vm_address_t)(uintptr_t)&bytes_read, &copied );
    if (ret != KERN_SUCCESS || copied != sizeof(bytes_read))
    {
        direct_self_read_record_rejection( engine, DIRECT_SELF_READ_REJECT_STACK_PHYSICAL );
        return UC_ERR_OK;
    }
    if (!bytes_read && provider.direct_self_read_stats_enabled)
        direct_self_read_increment( &engine->direct_self_read_diagnostics.null_result );

    if (size)
    {
        range_result = translate_direct_identity_range_locked( source, size, UC_PROT_READ,
                                                               &source_host );
        if (range_result != DIRECT_SELF_READ_RANGE_OK)
        {
            direct_self_read_record_range_rejection( engine,
                                                     DIRECT_SELF_READ_OPERAND_SOURCE,
                                                     range_result );
            return UC_ERR_OK;
        }
        range_result = translate_direct_identity_range_locked( destination, size,
                                                               UC_PROT_WRITE,
                                                               &destination_host );
        if (range_result != DIRECT_SELF_READ_RANGE_OK)
        {
            direct_self_read_record_range_rejection(
                engine, DIRECT_SELF_READ_OPERAND_DESTINATION, range_result );
            return UC_ERR_OK;
        }
    }
    if (bytes_read &&
        (range_result = translate_direct_identity_range_locked( bytes_read, sizeof(size),
                                                                UC_PROT_WRITE,
                                                                &bytes_read_host )) !=
            DIRECT_SELF_READ_RANGE_OK)
    {
        direct_self_read_record_range_rejection( engine, DIRECT_SELF_READ_OPERAND_RESULT,
                                                 range_result );
        return UC_ERR_OK;
    }

    if (size)
    {
        /* Mach performs the protection check and copy in one bounded kernel
         * operation.  This cannot fault while provider.mutex is held, and a
         * physically armed write-watch page returns an error to the ordinary
         * ntdll path.  Defer overlapping copies because Mach does not promise
         * memmove ordering for a single task map. */
        if (source != destination && source < destination + size &&
            destination < source + size)
        {
            direct_self_read_record_rejection( engine, DIRECT_SELF_READ_REJECT_OVERLAP );
            return UC_ERR_OK;
        }
        copied = 0;
        ret = mach_vm_read_overwrite( mach_task_self(), source_host, size,
                                      destination_host, &copied );
        if (ret != KERN_SUCCESS || copied != size)
        {
            direct_self_read_record_rejection( engine, DIRECT_SELF_READ_REJECT_DATA_COPY );
            return UC_ERR_OK;
        }
    }
    if (bytes_read)
    {
        copied = 0;
        ret = mach_vm_read_overwrite( mach_task_self(),
                                      (mach_vm_address_t)(uintptr_t)&size,
                                      sizeof(size), bytes_read_host, &copied );
        if (ret != KERN_SUCCESS || copied != sizeof(size))
        {
            direct_self_read_record_rejection( engine, DIRECT_SELF_READ_REJECT_RESULT_COPY );
            return UC_ERR_OK;
        }
    }
    if ((err = uc_reg_write( engine->uc, UC_X86_REG_RAX, &status )) != UC_ERR_OK)
    {
        direct_self_read_record_rejection( engine, DIRECT_SELF_READ_REJECT_REGISTERS );
        return err;
    }
    ++engine->direct_self_read_completions;
    direct_self_read_add( &engine->direct_self_read_bytes, size );
    direct_self_read_maybe_report( engine );
    *next_rip = rip;
    *handled = TRUE;
    return UC_ERR_OK;
}

/* A forced Wine shutdown does not necessarily execute process_term(), so a
 * bounded live capture needs to emit before the normal million-transition
 * checkpoint. This remains opt-in diagnostic configuration, and the lower
 * bound prevents a hostile or accidental environment from turning it into a
 * logging loop. */
static BOOL parse_ec_target_stats_initial_report( const char *value,
                                                  uint64_t *initial_report )
{
    const char *cursor;
    char *end;
    unsigned long long parsed;

    if (!value || !*value || !initial_report) return FALSE;
    for (cursor = value; *cursor; ++cursor)
        if (*cursor < '0' || *cursor > '9') return FALSE;
    errno = 0;
    parsed = strtoull( value, &end, 10 );
    if (errno || *end || parsed < XTAJIT64_EC_TARGET_STATS_MIN_INITIAL_REPORT ||
        parsed > XTAJIT64_EC_TARGET_STATS_DEFAULT_INITIAL_REPORT)
        return FALSE;
    *initial_report = parsed;
    return TRUE;
}

/* The environment remains expressed as an estimated number of transitions,
 * even though the low-distortion collector records only a sparse sample. */
static uint64_t ec_target_stats_initial_sample_count( uint64_t initial_report )
{
    return initial_report / XTAJIT64_EC_TARGET_STATS_SAMPLE_STRIDE +
           !!(initial_report % XTAJIT64_EC_TARGET_STATS_SAMPLE_STRIDE);
}

#if !defined(XTAJIT64_UNIXLIB_TEST) || defined(XTAJIT64_TEST_EC_LEAF_FASTPATH)
static uint64_t ec_transition_target_hash( uint64_t address )
{
    address >>= 4;
    address ^= address >> 33;
    address *= 0xff51afd7ed558ccdull;
    address ^= address >> 33;
    return address;
}
#endif

#ifndef XTAJIT64_UNIXLIB_TEST
static void write_diagnostic_line( const char *buffer, size_t length )
{
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t written = write( STDERR_FILENO, buffer + offset, length - offset );

        if (written > 0) offset += written;
        else if (written < 0 && errno == EINTR) continue;
        else break;
    }
}

static void reset_ec_transition_target_stats( uint64_t initial_report )
{
    unsigned int i;

    memset( provider.ec_target_stats, 0, sizeof(provider.ec_target_stats) );
    atomic_store_explicit( &provider.ec_target_stats_total, 0, memory_order_relaxed );
    provider.ec_target_stats_lost = 0;
    atomic_store_explicit( &provider.ec_target_stats_next_report,
                           ec_target_stats_initial_sample_count( initial_report ),
                           memory_order_relaxed );
    atomic_store_explicit( &provider.ec_leaf_fastpath_attempts, 0, memory_order_relaxed );
    atomic_store_explicit( &provider.ec_leaf_fastpath_hits, 0, memory_order_relaxed );
    atomic_store_explicit( &provider.ec_leaf_fastpath_unsupported, 0, memory_order_relaxed );
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
    atomic_store_explicit( &provider.ec_leaf_fastpath_next_report,
                           initial_report,
                           memory_order_relaxed );
}

/* The Unicorn boundary hook and begin_simulation() can both call this on the
 * engine's owner thread.  Keep the enabled diagnostic out of their hot path:
 * sample a thread-owned direct map rather than bouncing shared atomics and
 * request rendering only at a sparse report interval. */
static void record_ec_transition_target( struct thread_engine *engine,
                                         uint64_t address )
{
    uint64_t index, expected, total, next_report;
    unsigned int probe;

    if (!provider.ec_target_stats_enabled || !address) return;
    if (++engine->ec_target_stats_sample_counter !=
        XTAJIT64_EC_TARGET_STATS_SAMPLE_STRIDE)
        return;
    engine->ec_target_stats_sample_counter = 0;
    index = ec_transition_target_hash( address ) &
            (XTAJIT64_EC_TARGET_STATS_ENGINE_SLOTS - 1);
    for (probe = 0; probe < XTAJIT64_EC_TARGET_STATS_MAX_PROBE; ++probe)
    {
        struct ec_transition_target_sample *slot =
            &engine->ec_target_stats[(index + probe) &
                                     (XTAJIT64_EC_TARGET_STATS_ENGINE_SLOTS - 1)];
        uint64_t current = atomic_load_explicit( &slot->address, memory_order_acquire );

        if (current == address)
        {
            atomic_fetch_add_explicit( &slot->count, 1, memory_order_relaxed );
            goto maybe_report;
        }
        if (current) continue;
        expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &slot->address, &expected, address,
                memory_order_acq_rel, memory_order_acquire ))
        {
            atomic_store_explicit( &slot->count, 1, memory_order_relaxed );
            goto maybe_report;
        }
        if (expected == address)
        {
            atomic_fetch_add_explicit( &slot->count, 1, memory_order_relaxed );
            goto maybe_report;
        }
    }
    atomic_fetch_add_explicit( &engine->ec_target_stats_lost, 1, memory_order_relaxed );

maybe_report:
    total = atomic_fetch_add_explicit( &provider.ec_target_stats_total, 1,
                                       memory_order_relaxed ) + 1;
    next_report = atomic_load_explicit( &provider.ec_target_stats_next_report,
                                        memory_order_relaxed );
    while (total >= next_report && next_report)
    {
        uint64_t replacement = next_report <= UINT64_MAX / 4 ?
                               next_report * 4 : UINT64_MAX;

        if (atomic_compare_exchange_weak_explicit(
                &provider.ec_target_stats_next_report, &next_report,
                replacement, memory_order_acq_rel, memory_order_relaxed ))
        {
            engine->ec_target_stats_report_pending = TRUE;
            break;
        }
    }
}

#if defined(__APPLE__)
/* Leaf statistics already opt into per-transition counters.  Reuse the
 * transition renderer's thread-owned pending bit, but let a leaf-only run
 * request a periodic snapshot independently of target sampling. */
static void record_ec_leaf_fastpath_attempt( struct thread_engine *engine )
{
    uint64_t total, next_report;

    total = atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_attempts, 1,
                                       memory_order_relaxed ) + 1;
    next_report = atomic_load_explicit( &provider.ec_leaf_fastpath_next_report,
                                        memory_order_relaxed );
    while (total >= next_report && next_report)
    {
        uint64_t replacement = next_report <= UINT64_MAX / 4 ?
                               next_report * 4 : UINT64_MAX;

        if (atomic_compare_exchange_weak_explicit(
                &provider.ec_leaf_fastpath_next_report, &next_report,
                replacement, memory_order_acq_rel, memory_order_relaxed ))
        {
            engine->ec_target_stats_report_pending = TRUE;
            break;
        }
    }
}
#endif

/* Caller holds provider.mutex.  The resulting buffer is written only after
 * the lock is released, so a slow stderr consumer cannot perturb transition
 * ownership or the ARM64EC return path. */
static size_t format_ec_transition_target_stats_locked( char *buffer, size_t size )
{
    struct
    {
        uint64_t address;
        uint64_t count;
        uint32_t instruction[3];
    } top[XTAJIT64_EC_TARGET_STATS_TOP] = {0};
    struct thread_engine *engine;
    uint64_t total, lost, estimated_total, host, allocation_base;
    unsigned int domain;
    int length;
    unsigned int i, j;
    size_t offset = 0;

    if ((!provider.ec_target_stats_enabled && !provider.ec_leaf_fastpath_stats_enabled) ||
        !buffer || !size)
        return 0;
    if (!provider.ec_target_stats_enabled) goto leaf_stats;
    memset( provider.ec_target_stats, 0, sizeof(provider.ec_target_stats) );
    provider.ec_target_stats_lost = 0;
    for (engine = provider.engines; engine; engine = engine->next)
    {
        provider.ec_target_stats_lost += atomic_load_explicit(
            &engine->ec_target_stats_lost, memory_order_relaxed );
        for (i = 0; i < XTAJIT64_EC_TARGET_STATS_ENGINE_SLOTS; ++i)
        {
            const struct ec_transition_target_sample *sample = &engine->ec_target_stats[i];
            uint64_t address, count, index;

            address = atomic_load_explicit( &sample->address, memory_order_acquire );
            count = atomic_load_explicit( &sample->count, memory_order_relaxed );
            if (!address || !count) continue;
            index = ec_transition_target_hash( address ) &
                    (XTAJIT64_EC_TARGET_STATS_SLOTS - 1);
            for (j = 0; j < XTAJIT64_EC_TARGET_STATS_MAX_PROBE; ++j)
            {
                struct ec_transition_target_stat *slot =
                    &provider.ec_target_stats[(index + j) &
                                              (XTAJIT64_EC_TARGET_STATS_SLOTS - 1)];

                if (!slot->address)
                {
                    slot->address = address;
                    slot->count = count;
                    break;
                }
                if (slot->address != address) continue;
                slot->count += count;
                break;
            }
            if (j == XTAJIT64_EC_TARGET_STATS_MAX_PROBE)
                ++provider.ec_target_stats_lost;
        }
    }
    total = atomic_load_explicit( &provider.ec_target_stats_total,
                                  memory_order_relaxed );
    lost = provider.ec_target_stats_lost;
    estimated_total = total > UINT64_MAX / XTAJIT64_EC_TARGET_STATS_SAMPLE_STRIDE ?
                      UINT64_MAX : total * XTAJIT64_EC_TARGET_STATS_SAMPLE_STRIDE;
    for (i = 0; i < XTAJIT64_EC_TARGET_STATS_SLOTS; ++i)
    {
        uint64_t count = provider.ec_target_stats[i].count;
        uint64_t address = provider.ec_target_stats[i].address;

        if (!address || !count || count <= top[XTAJIT64_EC_TARGET_STATS_TOP - 1].count)
            continue;
        for (j = 0; j < XTAJIT64_EC_TARGET_STATS_TOP; ++j)
            if (count > top[j].count) break;
        if (j >= XTAJIT64_EC_TARGET_STATS_TOP) continue;
        if (j + 1 < XTAJIT64_EC_TARGET_STATS_TOP)
            memmove( &top[j + 1], &top[j],
                     (XTAJIT64_EC_TARGET_STATS_TOP - j - 1) * sizeof(top[0]) );
        top[j].address = address;
        top[j].count = count;
    }
    for (i = 0; i < XTAJIT64_EC_TARGET_STATS_TOP && top[i].count; ++i)
    {
        if (top[i].address > UINT64_MAX - sizeof(top[i].instruction) ||
            !translate_guest_range_locked( top[i].address, sizeof(top[i].instruction),
                                           UC_PROT_READ, &host, &allocation_base, &domain ) ||
            host > UINT64_MAX - sizeof(top[i].instruction))
            continue;
        memcpy( top[i].instruction, (const void *)(uintptr_t)host,
                sizeof(top[i].instruction) );
    }

    length = snprintf( buffer, size,
                       "XTAJIT64_EC_TARGET_STATS_V3 pid=%ld samples=%llu "
                       "estimated_transitions=%llu lost_samples=%llu top=",
                       (long)getpid(), (unsigned long long)total,
                       (unsigned long long)estimated_total,
                       (unsigned long long)lost );
    if (length <= 0) return 0;
    offset = (size_t)length < size ? (size_t)length : size - 1;
    for (i = 0; i < XTAJIT64_EC_TARGET_STATS_TOP && top[i].count; ++i)
    {
        length = snprintf( buffer + offset, size - offset,
                           "%s%#llx@%08x,%08x,%08x:%llu", i ? "," : "",
                           (unsigned long long)top[i].address,
                           top[i].instruction[0], top[i].instruction[1],
                           top[i].instruction[2],
                           (unsigned long long)top[i].count );
        if (length <= 0) break;
        if ((size_t)length >= size - offset)
        {
            offset = size - 1;
            break;
        }
        offset += (size_t)length;
    }
    if (offset < size - 1) buffer[offset++] = '\n';
leaf_stats:
    if (provider.ec_leaf_fastpath_stats_enabled && offset < size)
    {
        length = snprintf(
            buffer + offset, size - offset,
            "XTAJIT64_EC_LEAF_FASTPATH_STATS_V4 pid=%ld attempts=%llu "
            "hits=%llu unsupported=%llu register_fail=%llu memory_fail=%llu stack_fail=%llu "
            "write_fail=%llu teb_load_w0=%llu tls_get_value=%llu tls_get_value2=%llu "
            "rtl_query_performance_counter=%llu qpc_arm64ec_target=%#llx "
            "qpc_x64_target=%#llx "
            "rotl32=%llu rotr32=%llu rotl64=%llu rotr64=%llu\n",
            (long)getpid(),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_attempts, memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_hits, memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_unsupported, memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_register_failures,
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_memory_failures,
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_stack_failures,
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_write_failures,
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_hits_by_kind[EC_LEAF_FASTPATH_TEB_LOAD_W0],
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_hits_by_kind[EC_LEAF_FASTPATH_TLS_GET_VALUE],
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_hits_by_kind[EC_LEAF_FASTPATH_TLS_GET_VALUE2],
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_hits_by_kind[
                    EC_LEAF_FASTPATH_RTL_QUERY_PERFORMANCE_COUNTER ],
                memory_order_relaxed ),
            (unsigned long long)provider.rtl_query_performance_counter,
            (unsigned long long)provider.nt_query_performance_counter,
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_hits_by_kind[EC_LEAF_FASTPATH_ROTL32],
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_hits_by_kind[EC_LEAF_FASTPATH_ROTR32],
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_hits_by_kind[EC_LEAF_FASTPATH_ROTL64],
                memory_order_relaxed ),
            (unsigned long long)atomic_load_explicit(
                &provider.ec_leaf_fastpath_hits_by_kind[EC_LEAF_FASTPATH_ROTR64],
                memory_order_relaxed ) );
        if (length > 0)
        {
            if ((size_t)length >= size - offset) offset = size - 1;
            else offset += (size_t)length;
        }
    }
    return offset;
}

static void render_ec_transition_target_stats(void)
{
    char buffer[2048];
    size_t length;

    pthread_mutex_lock( &provider.mutex );
    length = format_ec_transition_target_stats_locked( buffer, sizeof(buffer) );
    pthread_mutex_unlock( &provider.mutex );
    if (length) write_diagnostic_line( buffer, length );
}

static void merge_direct_self_read_diagnostics(
    struct direct_self_read_diagnostics *destination,
    const struct direct_self_read_diagnostics *source )
{
    unsigned int i;

    direct_self_read_add( &destination->syscalls, source->syscalls );
    direct_self_read_add( &destination->current_process, source->current_process );
    direct_self_read_add( &destination->requested_bytes, source->requested_bytes );
    if (source->maximum_size > destination->maximum_size)
        destination->maximum_size = source->maximum_size;
    direct_self_read_add( &destination->null_result, source->null_result );
    for (i = 0; i < DIRECT_SELF_READ_SIZE_BUCKET_COUNT; ++i)
        direct_self_read_add( &destination->size_buckets[i], source->size_buckets[i] );
    for (i = 0; i < DIRECT_SELF_READ_REJECT_COUNT; ++i)
        direct_self_read_add( &destination->rejections[i], source->rejections[i] );
}

static void render_direct_self_read_diagnostics(
    const struct direct_self_read_diagnostics *diagnostics,
    uint64_t engine_id, uint64_t attempts, uint64_t completions,
    uint64_t completed_bytes )
{
    char buffer[2048];
    int length;

    if (!diagnostics->syscalls) return;
    length = snprintf(
        buffer, sizeof(buffer),
        "XTAJIT64_DIRECT_READ_STATS_V1 pid=%ld engine=%llu syscalls=%llu current=%llu "
        "attempts=%llu completions=%llu requested_bytes=%llu completed_bytes=%llu "
        "maximum_size=%llu null_result=%llu "
        "sizes=zero:%llu,64:%llu,4k:%llu,64k:%llu,1m:%llu,16m:%llu,large:%llu "
        "reject=process:%llu,registers:%llu,size:%llu,stack_bounds:%llu,"
        "stack_range:%llu,stack_permissions:%llu,stack_domain:%llu,stack_physical:%llu,"
        "source_range:%llu,source_permissions:%llu,source_domain:%llu,"
        "destination_range:%llu,destination_permissions:%llu,destination_domain:%llu,"
        "result_range:%llu,result_permissions:%llu,result_domain:%llu,overlap:%llu,"
        "data_copy:%llu,result_copy:%llu\n",
        (long)getpid(), (unsigned long long)engine_id,
        (unsigned long long)diagnostics->syscalls,
        (unsigned long long)diagnostics->current_process,
        (unsigned long long)attempts, (unsigned long long)completions,
        (unsigned long long)diagnostics->requested_bytes,
        (unsigned long long)completed_bytes,
        (unsigned long long)diagnostics->maximum_size,
        (unsigned long long)diagnostics->null_result,
        (unsigned long long)diagnostics->size_buckets[DIRECT_SELF_READ_SIZE_ZERO],
        (unsigned long long)diagnostics->size_buckets[DIRECT_SELF_READ_SIZE_64],
        (unsigned long long)diagnostics->size_buckets[DIRECT_SELF_READ_SIZE_4K],
        (unsigned long long)diagnostics->size_buckets[DIRECT_SELF_READ_SIZE_64K],
        (unsigned long long)diagnostics->size_buckets[DIRECT_SELF_READ_SIZE_1M],
        (unsigned long long)diagnostics->size_buckets[DIRECT_SELF_READ_SIZE_16M],
        (unsigned long long)diagnostics->size_buckets[DIRECT_SELF_READ_SIZE_LARGE],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_PROCESS],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_REGISTERS],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_SIZE],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_STACK_BOUNDS],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_STACK_RANGE],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_STACK_PERMISSIONS],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_STACK_DOMAIN],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_STACK_PHYSICAL],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_SOURCE_RANGE],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_SOURCE_PERMISSIONS],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_SOURCE_DOMAIN],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_DESTINATION_RANGE],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_DESTINATION_PERMISSIONS],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_DESTINATION_DOMAIN],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_RESULT_RANGE],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_RESULT_PERMISSIONS],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_RESULT_DOMAIN],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_OVERLAP],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_DATA_COPY],
        (unsigned long long)diagnostics->rejections[DIRECT_SELF_READ_REJECT_RESULT_COPY] );
    if (length <= 0) return;
    if ((size_t)length >= sizeof(buffer)) length = sizeof(buffer) - 1;
    write_diagnostic_line( buffer, length );
}
#endif
#else
static uc_err try_direct_self_read( struct thread_engine *engine, uint64_t rip,
                                    uint64_t process, uint64_t *next_rip,
                                    BOOL *handled )
{
    (void)engine;
    (void)rip;
    (void)process;
    (void)next_rip;
    *handled = FALSE;
    return UC_ERR_OK;
}
#endif

#if defined(__APPLE__) && \
    (!defined(XTAJIT64_UNIXLIB_TEST) || defined(XTAJIT64_TEST_EC_LEAF_FASTPATH))
static mach_timebase_info_data_t ec_qpc_timebase;
static pthread_once_t ec_qpc_timebase_once = PTHREAD_ONCE_INIT;

static void initialize_ec_qpc_timebase(void)
{
    if (mach_timebase_info( &ec_qpc_timebase ) != KERN_SUCCESS ||
        !ec_qpc_timebase.numer || !ec_qpc_timebase.denom)
        memset( &ec_qpc_timebase, 0, sizeof(ec_qpc_timebase) );
}

/* Keep the native RtlQueryPerformanceCounter contract bit-for-bit aligned
 * with dlls/ntdll/unix/sync.c: mach_continuous_time converted to 100 ns
 * ticks.  If Darwin cannot provide a valid timebase, decline the shortcut so
 * native ntdll remains authoritative. */
static BOOL query_ec_performance_counter( uint64_t *counter )
{
    if (!counter) return FALSE;
    pthread_once( &ec_qpc_timebase_once, initialize_ec_qpc_timebase );
    if (!ec_qpc_timebase.numer || !ec_qpc_timebase.denom) return FALSE;
    *counter = mach_continuous_time() * ec_qpc_timebase.numer /
               ec_qpc_timebase.denom / 100;
    return TRUE;
}

static BOOL decode_arm64_bl_target( uint64_t address, uint32_t instruction,
                                    uint64_t *target )
{
    uint64_t immediate, displacement;

    if (!target || (instruction & 0xfc000000) != 0x94000000) return FALSE;
    immediate = instruction & 0x03ffffff;
    if (immediate & 0x02000000)
    {
        displacement = (UINT64_C(0x04000000) - immediate) << 2;
        if (address < displacement) return FALSE;
        *target = address - displacement;
    }
    else
    {
        displacement = immediate << 2;
        if (address > UINT64_MAX - displacement) return FALSE;
        *target = address + displacement;
    }
    return TRUE;
}

static BOOL decode_arm64_adrp_target( uint64_t address, uint32_t instruction,
                                      uint64_t *target )
{
    uint64_t immediate, displacement, page;

    if (!target || (instruction & 0x9f000000) != 0x90000000) return FALSE;
    page = address & ~UINT64_C(0xfff);
    immediate = (((uint64_t)instruction >> 5) & 0x7ffff) << 2 |
                ((instruction >> 29) & 3);
    if (immediate & 0x100000)
    {
        displacement = (UINT64_C(0x200000) - immediate) << 12;
        if (page < displacement) return FALSE;
        *target = page - displacement;
    }
    else
    {
        displacement = immediate << 12;
        if (page > UINT64_MAX - displacement) return FALSE;
        *target = page + displacement;
    }
    return TRUE;
}

static BOOL decode_arm64_add_immediate_target( uint64_t base, uint32_t instruction,
                                               unsigned int source, unsigned int destination,
                                               uint64_t *target )
{
    uint64_t immediate;

    if (!target || source > 30 || destination > 30 ||
        (instruction & 0xff000000) != 0x91000000 ||
        ((instruction >> 5) & 0x1f) != source ||
        (instruction & 0x1f) != destination)
        return FALSE;
    immediate = (instruction >> 10) & 0xfff;
    if (instruction & 0x00400000) immediate <<= 12;
    if (base > UINT64_MAX - immediate) return FALSE;
    *target = base + immediate;
    return TRUE;
}

static BOOL is_arm64_adrp_register( uint32_t instruction, unsigned int destination )
{
    return destination <= 30 &&
           (instruction & 0x9f00001f) == (0x90000000 | destination);
}

static BOOL is_arm64_ldr_register_offset( uint32_t instruction, unsigned int base,
                                          unsigned int destination )
{
    return base <= 30 && destination <= 30 &&
           (instruction & 0xffc003ff) ==
           (0xf9400000 | (base << 5) | destination);
}

/* An ARM64X hotpatch thunk bridges an ARM64EC caller to an x64 export.  The
 * registered RtlQueryPerformanceCounter target authenticates the wrapper;
 * this exact structural check and the raw NtQueryPerformanceCounter export
 * authenticate the thunk's final x64 branch before the provider replaces the
 * whole call with the Unix-side monotonic counter. */
static BOOL is_arm64ec_qpc_hybrid_patch_thunk( uc_engine *uc, uint64_t address )
{
    uint32_t instruction[12];
    uint64_t x64_page, x64_target, ignored;

    if (!provider.nt_query_performance_counter ||
        address > provider.highest_user_address ||
        address > UINT64_MAX - sizeof(instruction) ||
        sizeof(instruction) - 1 > provider.highest_user_address - address ||
        uc_mem_read( uc, address, instruction, sizeof(instruction) ) != UC_ERR_OK ||
        instruction[0] != 0xf81f0ffe || /* str x30,[sp,#-16]! */
        !is_arm64_adrp_register( instruction[1], 8 ) ||
        !is_arm64_adrp_register( instruction[2], 11 ) ||
        !decode_arm64_adrp_target( address + 2 * sizeof(instruction[0]), instruction[2],
                                   &x64_page ) ||
        !decode_arm64_add_immediate_target( x64_page, instruction[3], 11, 11,
                                            &x64_target ) ||
        !is_arm64_ldr_register_offset( instruction[4], 8, 8 ) ||
        !is_arm64_adrp_register( instruction[5], 10 ) ||
        !decode_arm64_add_immediate_target( 0, instruction[6], 10, 10, &ignored ) ||
        !is_arm64_adrp_register( instruction[7], 9 ) ||
        !decode_arm64_add_immediate_target( 0, instruction[8], 9, 9, &ignored ) ||
        instruction[9] != 0xd63f0100 || /* blr x8 */
        instruction[10] != 0xf84107fe || /* ldr x30,[sp],#16 */
        instruction[11] != 0xd61f0160 || /* br x11 */
        x64_target != provider.nt_query_performance_counter)
        return FALSE;
    return TRUE;
}

static enum ec_leaf_fastpath_kind classify_ec_leaf_fastpath_target(
    uc_engine *uc, uint64_t address, uint32_t *instruction )
{
    static const uint32_t tls_get_value[] =
    {
        0x7100fc1f, /* cmp w0,#0x3f */
        0xb9006a5f, /* str wzr,[x18,#0x68] */
        0x54000088, /* b.hi +0x10 */
        0x8b204e48, /* add x8,x18,w0,uxtw #3 */
        0xf94a4100, /* ldr x0,[x8,#0x1480] */
        0xd65f03c0, /* ret */
    };
    static const uint32_t tls_get_value2[] =
    {
        0x7100fc1f, /* cmp w0,#0x3f */
        0x54000088, /* b.hi +0x10 */
        0x8b204e48, /* add x8,x18,w0,uxtw #3 */
        0xf94a4100, /* ldr x0,[x8,#0x1480] */
        0xd65f03c0, /* ret */
    };
    static const uint32_t rtl_query_performance_counter[] =
    {
        0xf81f0ffe, /* str x30,[sp,#-16]! */
        0xaa1f03e1, /* mov x1,xzr */
        0,          /* bl NtQueryPerformanceCounter */
        0x52800020, /* mov w0,#1 */
        0xf84107fe, /* ldr x30,[sp],#16 */
        0xd65f03c0, /* ret */
    };
    static const uint32_t nt_query_performance_counter[] =
    {
        0xd2800628, /* mov x8,#0x31 */
        0xaa1e03e9, /* mov x9,x30 */
        0x58000090, /* ldr x16,=unix syscall dispatcher */
        0xf9400210, /* ldr x16,[x16] */
        0xd63f0200, /* blr x16 */
        0xd65f03c0, /* ret */
    };
    uint32_t insn[ARRAY_SIZE(tls_get_value)] = {0};
    uint32_t syscall_insn[ARRAY_SIZE(nt_query_performance_counter)];
    uint64_t syscall_target;

    *instruction = 0;
    if (address > UINT64_MAX - 2 * sizeof(insn[0]) ||
        uc_mem_read( uc, address, insn, 2 * sizeof(insn[0]) ) != UC_ERR_OK)
        return EC_LEAF_FASTPATH_UNSUPPORTED;

    /* ldr w0,[x18,#imm] ; ret.  AArch64 encodes the byte offset as an
     * unsigned, naturally aligned imm12, so extracting it later cannot
     * overflow a 64-bit authenticated guest TEB address. */
    if (insn[1] == 0xd65f03c0 && (insn[0] & 0xffc003ff) == 0xb9400240)
    {
        *instruction = insn[0];
        return EC_LEAF_FASTPATH_TEB_LOAD_W0;
    }
    if (insn[0] == 0x1ac12c00 && insn[1] == 0xd65f03c0)
        return EC_LEAF_FASTPATH_ROTR32;
    if (insn[0] == 0x9ac12c00 && insn[1] == 0xd65f03c0)
        return EC_LEAF_FASTPATH_ROTR64;
    if (address > UINT64_MAX - 3 * sizeof(insn[0]) ||
        uc_mem_read( uc, address + 2 * sizeof(insn[0]), &insn[2],
                     sizeof(insn[2]) ) != UC_ERR_OK)
        return EC_LEAF_FASTPATH_UNSUPPORTED;
    if (insn[0] == 0x4b0103e8 && insn[1] == 0x1ac82c00 &&
        insn[2] == 0xd65f03c0)
        return EC_LEAF_FASTPATH_ROTL32;
    if (insn[0] == 0x4b0103e8 && insn[1] == 0x9ac82c00 &&
        insn[2] == 0xd65f03c0)
        return EC_LEAF_FASTPATH_ROTL64;
    if (address > UINT64_MAX - sizeof(insn) ||
        uc_mem_read( uc, address, insn, sizeof(insn) ) != UC_ERR_OK)
        return EC_LEAF_FASTPATH_UNSUPPORTED;
    if (!memcmp( insn, tls_get_value, sizeof(tls_get_value) ))
        return EC_LEAF_FASTPATH_TLS_GET_VALUE;
    if (!memcmp( insn, tls_get_value2, sizeof(tls_get_value2) ))
        return EC_LEAF_FASTPATH_TLS_GET_VALUE2;

    if (address != provider.rtl_query_performance_counter ||
        memcmp( insn, rtl_query_performance_counter, 2 * sizeof(insn[0])) ||
        insn[3] != rtl_query_performance_counter[3] ||
        insn[4] != rtl_query_performance_counter[4] ||
        insn[5] != rtl_query_performance_counter[5] ||
        !decode_arm64_bl_target( address + 2 * sizeof(insn[0]), insn[2],
                                 &syscall_target ) ||
        !syscall_target || syscall_target > provider.highest_user_address)
        return EC_LEAF_FASTPATH_UNSUPPORTED;
    if (syscall_target <= UINT64_MAX - sizeof(syscall_insn) &&
        sizeof(syscall_insn) - 1 <= provider.highest_user_address - syscall_target &&
        uc_mem_read( uc, syscall_target, syscall_insn, sizeof(syscall_insn) ) == UC_ERR_OK &&
        !memcmp( syscall_insn, nt_query_performance_counter, sizeof(syscall_insn) ))
        return EC_LEAF_FASTPATH_RTL_QUERY_PERFORMANCE_COUNTER;
    if (!is_arm64ec_qpc_hybrid_patch_thunk( uc, syscall_target ))
        return EC_LEAF_FASTPATH_UNSUPPORTED;
    return EC_LEAF_FASTPATH_RTL_QUERY_PERFORMANCE_COUNTER;
}

/* Caller holds provider.mutex.  Code and VM generation checks make this a
 * recognition cache only; no entry survives a published code or mapping
 * change. */
static enum ec_leaf_fastpath_kind get_ec_leaf_fastpath_kind(
    struct thread_engine *engine, uc_engine *uc, uint64_t address,
    uint32_t *instruction )
{
    struct ec_leaf_fastpath_cache_entry *entry;
    unsigned int index;

    index = ec_transition_target_hash( address ) &
            (XTAJIT64_EC_LEAF_FASTPATH_CACHE_SIZE - 1);
    entry = &engine->ec_leaf_fastpath_cache[index];
    if (entry->address == address &&
        entry->mapping_generation == provider.generation &&
        entry->code_generation == provider.ec_leaf_fastpath_code_generation &&
        entry->kind != EC_LEAF_FASTPATH_UNCLASSIFIED)
    {
        *instruction = entry->instruction;
        return entry->kind;
    }

    entry->address = address;
    entry->mapping_generation = provider.generation;
    entry->code_generation = provider.ec_leaf_fastpath_code_generation;
    entry->kind = classify_ec_leaf_fastpath_target( uc, address, &entry->instruction );
    *instruction = entry->instruction;
    return entry->kind;
}

static uint64_t rotate_left64( uint64_t value, unsigned int shift )
{
    shift &= 63;
    return shift ? (value << shift) | (value >> (64 - shift)) : value;
}

static uint64_t rotate_right64( uint64_t value, unsigned int shift )
{
    shift &= 63;
    return shift ? (value >> shift) | (value << (64 - shift)) : value;
}

static uint32_t rotate_left32( uint32_t value, unsigned int shift )
{
    shift &= 31;
    return shift ? (value << shift) | (value >> (32 - shift)) : value;
}

static uint32_t rotate_right32( uint32_t value, unsigned int shift )
{
    shift &= 31;
    return shift ? (value >> shift) | (value << (32 - shift)) : value;
}

static BOOL read_engine_guest( const struct thread_engine *engine,
                               uint64_t guest, void *value, size_t size )
{
    const struct mapped_range *range;
    uint64_t host, allocation_base;
    unsigned int domain;

    if (!engine || !value || !size || guest > UINT64_MAX - size) return FALSE;
    if ((range = find_engine_mapping( engine, guest, size )) &&
        range->state == MEM_COMMIT &&
        (range->perms & UC_PROT_READ) == UC_PROT_READ &&
        range->host <= UINT64_MAX - (guest - range->guest))
        host = range->host + guest - range->guest;
    else if (!translate_guest_range_locked( guest, size, UC_PROT_READ,
                                            &host, &allocation_base, &domain ))
        return FALSE;
    if (host > UINT64_MAX - size) return FALSE;
    memcpy( value, (const void *)(uintptr_t)host, size );
    return TRUE;
}

static BOOL read_engine_guest_u64( const struct thread_engine *engine,
                                   uint64_t guest, uint64_t *value )
{
    return read_engine_guest( engine, guest, value, sizeof(*value) );
}

static BOOL read_engine_guest_u32( const struct thread_engine *engine,
                                   uint64_t guest, uint32_t *value )
{
    return read_engine_guest( engine, guest, value, sizeof(*value) );
}

static BOOL write_engine_guest( const struct thread_engine *engine,
                                uint64_t guest, const void *value, size_t size )
{
    const struct mapped_range *range;
    uint64_t host, allocation_base;
    unsigned int domain;

    if (!engine || !value || !size || guest > UINT64_MAX - size) return FALSE;
    if ((range = find_engine_mapping( engine, guest, size )) &&
        range->state == MEM_COMMIT &&
        (range->perms & UC_PROT_WRITE) == UC_PROT_WRITE &&
        range->host <= UINT64_MAX - (guest - range->guest))
        host = range->host + guest - range->guest;
    else if (!translate_guest_range_locked( guest, size, UC_PROT_WRITE,
                                            &host, &allocation_base, &domain ))
        return FALSE;
    if (host > UINT64_MAX - size) return FALSE;
    memcpy( (void *)(uintptr_t)host, value, size );
    return TRUE;
}

static BOOL write_engine_guest_u32( const struct thread_engine *engine,
                                    uint64_t guest, uint32_t value )
{
    return write_engine_guest( engine, guest, &value, sizeof(value) );
}

#ifndef XTAJIT64_UNIXLIB_TEST
static void report_ec_leaf_fastpath_stack_failure( uint64_t address, uint64_t rsp,
                                                   uint64_t ret_rsp, uint64_t ret,
                                                   const struct thread_engine *engine,
                                                   BOOL stack_in_bounds, BOOL stack_read,
                                                   BOOL ret_valid )
{
    static atomic_bool reported;
    char buffer[384];
    int length;

    if (!provider.ec_leaf_fastpath_stats_enabled ||
        atomic_exchange_explicit( &reported, true, memory_order_relaxed ))
        return;
    length = snprintf(
        buffer, sizeof(buffer),
        "XTAJIT64_EC_LEAF_FASTPATH_STACK_FAIL_V1 pid=%ld target=%#llx "
        "rsp=%#llx ret_rsp=%#llx limit=%#llx base=%#llx in_bounds=%u read=%u "
        "ret=%#llx ret_valid=%u ret_ec=%u\n",
        (long)getpid(), (unsigned long long)address,
        (unsigned long long)rsp, (unsigned long long)ret_rsp,
        (unsigned long long)engine->stack_limit,
        (unsigned long long)engine->stack_base, stack_in_bounds,
        stack_read, (unsigned long long)ret, ret_valid,
        stack_read && ret ? is_ec_code( ret ) : 0 );
    if (length <= 0) return;
    if ((size_t)length >= sizeof(buffer)) length = sizeof(buffer) - 1;
    write_diagnostic_line( buffer, (size_t)length );
}
#endif

static BOOL try_ec_leaf_fastpath( struct thread_engine *engine, uc_engine *uc,
                                  uint64_t address, BOOL pre_call_stack,
                                  uint64_t *next_rip )
{
    enum ec_leaf_fastpath_kind kind;
    uint64_t rcx = 0, rdx = 0, rax = 0, rsp = 0, gs_base = 0;
    uint64_t ret_rsp, final_rsp, ret = 0, teb_offset, tls_slot_offset;
    uint64_t performance_counter;
    uint32_t instruction;
    uint32_t teb_value;
    uc_err write_err;
    BOOL stack_in_bounds, stack_read, ret_valid;
    BOOL stats;
    static const int rotate_read_regs[] =
    {
        UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSP,
    };
    static const int teb_read_regs[] =
    {
        UC_X86_REG_RSP, UC_X86_REG_GS_BASE,
    };
    static const int tls_read_regs[] =
    {
        UC_X86_REG_RCX, UC_X86_REG_RSP, UC_X86_REG_GS_BASE,
    };
    static const int qpc_read_regs[] =
    {
        UC_X86_REG_RCX, UC_X86_REG_RSP,
    };
    static const int write_regs[] =
    {
        UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RIP,
    };
    void *rotate_read_values[] = {&rcx, &rdx, &rsp};
    void *teb_read_values[] = {&rsp, &gs_base};
    void *tls_read_values[] = {&rcx, &rsp, &gs_base};
    void *qpc_read_values[] = {&rcx, &rsp};
    void *write_values[] = {&rax, &rsp, &ret};

    if (!provider.ec_leaf_fastpath_enabled || !engine || !uc || !next_rip) return FALSE;
    stats = provider.ec_leaf_fastpath_stats_enabled;
    if (stats)
#ifndef XTAJIT64_UNIXLIB_TEST
        record_ec_leaf_fastpath_attempt( engine );
#else
        atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_attempts, 1,
                                   memory_order_relaxed );
#endif
    kind = get_ec_leaf_fastpath_kind( engine, uc, address, &instruction );
    if (kind == EC_LEAF_FASTPATH_UNSUPPORTED) goto unsupported;
    if (kind == EC_LEAF_FASTPATH_TEB_LOAD_W0)
    {
        if (uc_reg_read_batch( uc, teb_read_regs, teb_read_values,
                               ARRAY_SIZE(teb_read_regs) ) != UC_ERR_OK)
        {
            if (stats)
                atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_register_failures, 1,
                                           memory_order_relaxed );
            return FALSE;
        }
    }
    else if (kind == EC_LEAF_FASTPATH_TLS_GET_VALUE ||
             kind == EC_LEAF_FASTPATH_TLS_GET_VALUE2)
    {
        if (uc_reg_read_batch( uc, tls_read_regs, tls_read_values,
                               ARRAY_SIZE(tls_read_regs) ) != UC_ERR_OK)
        {
            if (stats)
                atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_register_failures, 1,
                                           memory_order_relaxed );
            return FALSE;
        }
    }
    else if (kind == EC_LEAF_FASTPATH_RTL_QUERY_PERFORMANCE_COUNTER)
    {
        if (uc_reg_read_batch( uc, qpc_read_regs, qpc_read_values,
                               ARRAY_SIZE(qpc_read_regs) ) != UC_ERR_OK)
        {
            if (stats)
                atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_register_failures, 1,
                                           memory_order_relaxed );
            return FALSE;
        }
    }
    else if (uc_reg_read_batch( uc, rotate_read_regs, rotate_read_values,
                                ARRAY_SIZE(rotate_read_regs) ) != UC_ERR_OK)
    {
        if (stats)
            atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_register_failures, 1,
                                       memory_order_relaxed );
        return FALSE;
    }
    if (pre_call_stack)
    {
        if (rsp < sizeof(ret))
        {
            if (stats)
                atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_stack_failures, 1,
                                           memory_order_relaxed );
            return FALSE;
        }
        ret_rsp = rsp - sizeof(ret);
        final_rsp = rsp;
    }
    else
    {
        if (rsp > UINT64_MAX - sizeof(ret))
        {
            if (stats)
                atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_stack_failures, 1,
                                           memory_order_relaxed );
            return FALSE;
        }
        ret_rsp = rsp;
        final_rsp = rsp + sizeof(ret);
    }
    stack_in_bounds = engine->stack_base >= sizeof(ret) &&
                      ret_rsp >= engine->stack_limit &&
                      ret_rsp <= engine->stack_base - sizeof(ret);
    stack_read = stack_in_bounds && read_engine_guest_u64( engine, ret_rsp, &ret );
    ret_valid = stack_read && ret &&
                ret <= XTAJIT64_X64_USER_ADDRESS_MAX && !is_ec_code( ret );
    if (!stack_in_bounds || !ret_valid)
    {
#ifndef XTAJIT64_UNIXLIB_TEST
        report_ec_leaf_fastpath_stack_failure( address, rsp, ret_rsp, ret, engine,
                                               stack_in_bounds, stack_read, ret_valid );
#endif
        if (stats)
            atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_stack_failures, 1,
                                       memory_order_relaxed );
        return FALSE;
    }

    switch (kind)
    {
    case EC_LEAF_FASTPATH_TEB_LOAD_W0:
        teb_offset = ((instruction >> 10) & 0xfff) * sizeof(uint32_t);
        if (gs_base > UINT64_MAX - teb_offset ||
            !read_engine_guest_u32( engine, gs_base + teb_offset, &teb_value ))
            goto memory_failure;
        rax = teb_value;
        break;
    case EC_LEAF_FASTPATH_TLS_GET_VALUE:
        /* The out-of-range branch is intentionally left to native ARM64EC.
         * The accepted prefix's LastError clear precedes that branch, so
         * writing it before discovering an unsupported case would make an
         * otherwise safe fallback a partial emulation. */
        if ((uint32_t)rcx >= XTAJIT64_TEB_TLS_SLOT_COUNT) goto unsupported;
        if (gs_base > UINT64_MAX - XTAJIT64_TEB_LAST_ERROR_OFFSET ||
            !write_engine_guest_u32( engine,
                                     gs_base + XTAJIT64_TEB_LAST_ERROR_OFFSET, 0 ))
            goto memory_failure;
        /* Fall through.  TlsGetValue2 has the same bounded slot lookup but
         * deliberately retains LastError. */
        /* fall through */
    case EC_LEAF_FASTPATH_TLS_GET_VALUE2:
        if ((uint32_t)rcx >= XTAJIT64_TEB_TLS_SLOT_COUNT) goto unsupported;
        tls_slot_offset = XTAJIT64_TEB_TLS_SLOTS_OFFSET +
                          (uint64_t)(uint32_t)rcx * sizeof(rax);
        if (gs_base > UINT64_MAX - tls_slot_offset ||
            !read_engine_guest_u64( engine, gs_base + tls_slot_offset, &rax ))
            goto memory_failure;
        break;
    case EC_LEAF_FASTPATH_RTL_QUERY_PERFORMANCE_COUNTER:
        /* RtlQueryPerformanceCounter always passes x1 = NULL to the ntdll
         * syscall body, so the x64 caller supplies only the counter pointer
         * in RCX.  Compute before the store: any unavailable counter source
         * or invalid guest destination must leave the native fallback wholly
         * responsible for the call. */
        if (!query_ec_performance_counter( &performance_counter )) goto unsupported;
        if (!write_engine_guest( engine, rcx, &performance_counter,
                                 sizeof(performance_counter) ))
            goto memory_failure;
        rax = TRUE;
        break;
    case EC_LEAF_FASTPATH_ROTL32:
        rax = rotate_left32( (uint32_t)rcx, (unsigned int)rdx );
        break;
    case EC_LEAF_FASTPATH_ROTR32:
        rax = rotate_right32( (uint32_t)rcx, (unsigned int)rdx );
        break;
    case EC_LEAF_FASTPATH_ROTL64:
        rax = rotate_left64( rcx, (unsigned int)rdx );
        break;
    case EC_LEAF_FASTPATH_ROTR64:
        rax = rotate_right64( rcx, (unsigned int)rdx );
        break;
    default:
        goto unsupported;
    }
    rsp = final_rsp;
    if ((write_err = uc_reg_write_batch( uc, write_regs, write_values,
                                         ARRAY_SIZE(write_regs) )) != UC_ERR_OK)
    {
        if (stats)
            atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_write_failures, 1,
                                       memory_order_relaxed );
        /* Some leaf implementations have already updated guest memory at
         * this point.  Never fall back to the native implementation with a
         * partially committed call; a valid-register write failure means the
         * engine is no longer trustworthy.  The caller holds provider.mutex. */
        engine->mapping_error = write_err;
        engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
        poison_provider_locked( STATUS_UNSUCCESSFUL );
        return FALSE;
    }
    if (stats)
    {
        atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_hits, 1,
                                   memory_order_relaxed );
        if (kind > EC_LEAF_FASTPATH_UNSUPPORTED && kind < EC_LEAF_FASTPATH_KIND_COUNT)
            atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_hits_by_kind[kind], 1,
                                       memory_order_relaxed );
    }
    *next_rip = ret;
    return TRUE;

memory_failure:
    if (stats)
        atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_memory_failures, 1,
                                   memory_order_relaxed );
    return FALSE;

unsupported:
    if (stats)
        atomic_fetch_add_explicit( &provider.ec_leaf_fastpath_unsupported, 1,
                                   memory_order_relaxed );
    return FALSE;
}
#endif

static void stop_at_ec_target( struct thread_engine *engine, uc_engine *uc,
                               uint64_t address )
{
    uint64_t rsp = XTAJIT64_FLIGHT_UNKNOWN_U64;

#ifndef XTAJIT64_UNIXLIB_TEST
    record_ec_transition_target( engine, address );
#endif
    engine->transition_target = address;
    engine->stop_reason = XTAJIT64_STOP_EC_TRANSITION;
    if (engine->flight_recorder &&
        uc_reg_read( uc, UC_X86_REG_RSP, &rsp ) != UC_ERR_OK)
        rsp = XTAJIT64_FLIGHT_UNKNOWN_U64;
    if (engine->flight_recorder)
        flight_record_engine_event( engine, XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP,
                                    XTAJIT64_FLIGHT_REASON_NONE,
                                    XTAJIT64_STOP_EC_TRANSITION, address, rsp );
    uc_emu_stop( uc );
}

static void stop_at_instruction_boundary( struct thread_engine *engine,
                                          uc_engine *uc )
{
    uc_err err;

    /* An ordinary hook-time stop can commit the current translation block's
     * side effects while restoring RIP to its beginning.  Resuming that
     * context would repeat stores, stack updates, calls, or returns. */
    err = uc_emu_stop_at_instruction_boundary( uc );
    if (err == UC_ERR_OK) return;

    engine->mapping_error = err;
    engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
    uc_emu_stop( uc );
}

#if defined(__APPLE__) && !defined(XTAJIT64_UNIXLIB_TEST)
static void render_unicorn_perf_diagnostics(
    const struct thread_engine *engine,
    const struct xtajit64_unicorn_perf_counters *counters )
{
    char buffer[2048];
    int length;

    length = snprintf(
        buffer, sizeof(buffer),
        "XTAJIT64_UNICORN_PERF_V5 pid=%ld engine=%llu samples=%llu "
        "dispatch=%llu lookups=%llu jump_hits=%llu hash_hits=%llu misses=%llu "
        "generated=%llu indirect=%llu soft_load=%llu soft_store=%llu "
        "notdirty=%llu exec_writes=%llu invalidate_fast=%llu bitmap_skips=%llu "
        "tb_invalidated=%llu code_writes=%llu engine_scans=%llu peer_invalidations=%llu "
        "private_writes=%llu "
        "code_translations=%llu exclusive=%llu pause_requests=%llu "
        "site_first=%llu site_reobserved=%llu site_matches=%llu site_tb_matches=%llu site_changes=%llu "
        "site_collisions=%llu\n",
        (long)getpid(), (unsigned long long)engine->diagnostic_id,
        (unsigned long long)engine->perf_sample_count,
        (unsigned long long)counters->tcg_dispatch_entries,
        (unsigned long long)counters->tb_lookup_calls,
        (unsigned long long)counters->tb_jump_cache_hits,
        (unsigned long long)counters->tb_hash_hits,
        (unsigned long long)counters->tb_lookup_misses,
        (unsigned long long)counters->tb_generations,
        (unsigned long long)counters->indirect_tb_lookups,
        (unsigned long long)counters->softmmu_load_helpers,
        (unsigned long long)counters->softmmu_store_helpers,
        (unsigned long long)counters->notdirty_writes,
        (unsigned long long)counters->executable_writes,
        (unsigned long long)counters->invalidate_fast_calls,
        (unsigned long long)counters->invalidate_bitmap_skips,
        (unsigned long long)counters->actual_tb_invalidations,
        (unsigned long long)counters->shared_code_write_begins,
        (unsigned long long)counters->shared_code_engine_scans,
        (unsigned long long)counters->shared_code_peer_invalidations,
        (unsigned long long)counters->shared_code_private_writes,
        (unsigned long long)counters->shared_code_translation_begins,
        (unsigned long long)counters->shared_exclusive_begins,
        (unsigned long long)counters->shared_pause_requests,
        (unsigned long long)counters->indirect_site_first_observations,
        (unsigned long long)counters->indirect_site_reobservations,
        (unsigned long long)counters->indirect_site_target_matches,
        (unsigned long long)counters->indirect_site_target_tb_matches,
        (unsigned long long)counters->indirect_site_target_changes,
        (unsigned long long)counters->indirect_site_collisions );
    if (length <= 0) return;
    if ((size_t)length >= sizeof(buffer)) length = sizeof(buffer) - 1;
    write_diagnostic_line( buffer, length );
}

static void maybe_report_unicorn_perf_diagnostics( struct thread_engine *engine )
{
    struct xtajit64_unicorn_perf_counters counters =
    {
        .version = XTAJIT64_UNICORN_PERF_COUNTERS_VERSION,
        .size = sizeof(counters),
    };
    uint64_t next;
    uc_err err;

    if (!provider.unicorn_perf_stats_enabled ||
        !provider.unicorn_get_perf_counters)
        return;
    if (engine->perf_sample_count != UINT64_MAX) ++engine->perf_sample_count;
    next = engine->perf_next_report;
    if (!next) next = 1;
    if (engine->perf_sample_count < next)
    {
        engine->perf_next_report = next;
        return;
    }
    err = provider.unicorn_get_perf_counters( engine->uc, &counters );
    if (err != UC_ERR_OK)
    {
        ERR( "engine %llu Unicorn performance counter query failed %u\n",
             (unsigned long long)engine->diagnostic_id, err );
        engine->perf_next_report = UINT64_MAX;
        return;
    }
    render_unicorn_perf_diagnostics( engine, &counters );
    if (next < (1u << 10)) next = 1u << 10;
    else if (next <= UINT64_MAX / 4) next *= 4;
    else next = UINT64_MAX;
    engine->perf_next_report = next;
}
#else
static void maybe_report_unicorn_perf_diagnostics( struct thread_engine *engine )
{
    (void)engine;
}
#endif

static void block_hook( uc_engine *uc, uint64_t address, uint32_t size, void *user )
{
    struct thread_engine *engine = user;

    (void)size;
    if (is_ec_code( address ))
    {
#ifdef XTAJIT64_UNIXLIB_TEST
        if (atomic_load_explicit( &test_hold_ec_hook, memory_order_acquire ))
        {
            atomic_store_explicit( &test_ec_hook_entered, 1, memory_order_release );
            while (!atomic_load_explicit( &test_release_ec_hook, memory_order_acquire ))
                sched_yield();
        }
#endif
        stop_at_ec_target( engine, uc, address );
        return;
    }

#ifdef XTAJIT64_UNIXLIB_TEST
    if (atomic_load_explicit( &test_hold_non_ec_hook, memory_order_acquire ))
    {
        atomic_store_explicit( &test_non_ec_hook_entered, 1, memory_order_release );
        while (!atomic_load_explicit( &test_release_non_ec_hook, memory_order_acquire ))
            sched_yield();
    }
#endif
    if (engine->suspend_doorbell && *engine->suspend_doorbell)
    {
        engine->stop_reason = XTAJIT64_STOP_SUSPEND;
        if (engine->flight_recorder)
            flight_record_engine_event( engine,
                                        XTAJIT64_FLIGHT_EVENT_SUSPEND_ACKNOWLEDGED,
                                        XTAJIT64_FLIGHT_REASON_NONE,
                                        XTAJIT64_STOP_SUSPEND, address,
                                        XTAJIT64_FLIGHT_UNKNOWN_U64 );
        stop_at_instruction_boundary( engine, uc );
        return;
    }
    if (!atomic_load_explicit( &engine->pause_requested, memory_order_acquire )) return;
#ifdef XTAJIT64_UNIXLIB_TEST
    if (atomic_load_explicit( &test_disable_pause_hook, memory_order_acquire )) return;
#endif
    if (engine->flight_recorder)
        flight_record_engine_event( engine, XTAJIT64_FLIGHT_EVENT_SUSPEND_ACKNOWLEDGED,
                                    XTAJIT64_FLIGHT_REASON_NONE,
                                    XTAJIT64_FLIGHT_UNKNOWN_U32,
                                    address, XTAJIT64_FLIGHT_UNKNOWN_U64 );
#ifdef XTAJIT64_UNIXLIB_TEST
    if (!pthread_equal( engine->owner, pthread_self() ))
        atomic_store_explicit( &test_pause_stop_owner_violation, 1, memory_order_relaxed );
    atomic_fetch_add_explicit( &test_pause_stop_count, 1, memory_order_relaxed );
#endif
    stop_at_instruction_boundary( engine, uc );
}

static void syscall_hook( uc_engine *uc, void *user )
{
    struct thread_engine *engine = user;
    uint64_t rip = XTAJIT64_FLIGHT_UNKNOWN_U64;
    uint64_t rsp = XTAJIT64_FLIGHT_UNKNOWN_U64;

    engine->stop_reason = XTAJIT64_STOP_SYSCALL;
    if (engine->flight_recorder)
    {
        if (uc_reg_read( uc, UC_X86_REG_RIP, &rip ) != UC_ERR_OK)
            rip = XTAJIT64_FLIGHT_UNKNOWN_U64;
        if (uc_reg_read( uc, UC_X86_REG_RSP, &rsp ) != UC_ERR_OK)
            rsp = XTAJIT64_FLIGHT_UNKNOWN_U64;
    }
    if (engine->flight_recorder)
        flight_record_engine_event( engine, XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP,
                                    XTAJIT64_FLIGHT_REASON_NONE,
                                    XTAJIT64_STOP_SYSCALL, rip, rsp );
    uc_emu_stop( uc );
}

static void interrupt_hook( uc_engine *uc, uint32_t intno, void *user )
{
    struct thread_engine *engine = user;
    uint64_t eflags = 0;
    uint64_t rip = XTAJIT64_FLIGHT_UNKNOWN_U64;
    uint64_t rsp = XTAJIT64_FLIGHT_UNKNOWN_U64;

    if (intno == 0x2e)
        engine->stop_reason = XTAJIT64_STOP_SYSCALL;
    else if (intno == 1 &&
             uc_reg_read( uc, UC_X86_REG_EFLAGS, &eflags ) == UC_ERR_OK &&
             (eflags & 0x100))
        engine->stop_reason = XTAJIT64_STOP_SINGLE_STEP;
    else
        engine->stop_reason = XTAJIT64_STOP_INVALID_INSTRUCTION;
    engine->flight_stop_detail0 = intno;
    if (engine->flight_recorder &&
        xtajit64_flight_recorder_is_active( engine->flight_recorder ))
    {
        /* UC_HOOK_INTR runs after Unicorn advances RIP past INT.  Preserve
         * both that exact register pair and the interrupt number instead of
         * reducing every non-2e interrupt to the same stop-reason enum. */
        if (uc_reg_read( uc, UC_X86_REG_RIP, &rip ) != UC_ERR_OK)
            rip = XTAJIT64_FLIGHT_UNKNOWN_U64;
        if (uc_reg_read( uc, UC_X86_REG_RSP, &rsp ) != UC_ERR_OK)
            rsp = XTAJIT64_FLIGHT_UNKNOWN_U64;
        flight_record_engine_event( engine, XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP,
                                    XTAJIT64_FLIGHT_REASON_NONE,
                                    engine->stop_reason, rip, rsp );
    }
    uc_emu_stop( uc );
}

static bool invalid_instruction_hook( uc_engine *uc, void *user )
{
    struct thread_engine *engine = user;

    engine->stop_reason = XTAJIT64_STOP_INVALID_INSTRUCTION;
    uc_emu_stop( uc );
    return false;
}

static bool invalid_memory_hook( uc_engine *uc, uc_mem_type type, uint64_t address,
                                 int size, int64_t value, void *user )
{
    struct thread_engine *engine = user;
    unsigned int required_perms = 0, access_perms = 0;
    uint64_t fault_address = address;
    uint32_t fault_access = EXCEPTION_READ_FAULT;
    BOOL found = FALSE, mapped = FALSE;
    uc_err err;

    (void)value;
    if (type == UC_MEM_FETCH_UNMAPPED && is_ec_code( address ) &&
        unmapped_ec_target_is_executable( address ))
    {
        stop_at_ec_target( engine, uc, address );
        return false;
    }

    switch (type)
    {
    case UC_MEM_READ_UNMAPPED:
    case UC_MEM_READ_PROT:
        access_perms = UC_PROT_READ;
        required_perms = type == UC_MEM_READ_UNMAPPED ? UC_PROT_READ : 0;
        fault_access = EXCEPTION_READ_FAULT;
        break;
    case UC_MEM_WRITE_UNMAPPED:
    case UC_MEM_WRITE_PROT:
        access_perms = UC_PROT_WRITE;
        required_perms = type == UC_MEM_WRITE_UNMAPPED ? UC_PROT_WRITE : 0;
        fault_access = EXCEPTION_WRITE_FAULT;
        break;
    case UC_MEM_FETCH_UNMAPPED:
    case UC_MEM_FETCH_PROT:
        access_perms = UC_PROT_EXEC;
        required_perms = type == UC_MEM_FETCH_UNMAPPED ? UC_PROT_EXEC : 0;
        fault_access = EXCEPTION_EXECUTE_FAULT;
        break;
    default: break;
    }
    if (required_perms && size > 0)
    {
        err = demand_map_canonical_access( engine, address, size,
                                           required_perms, &found, &mapped, &fault_address );
        if (err == UC_ERR_OK && mapped) return true;
        if (err == UC_ERR_OK && found)
        {
            engine->fault_address = fault_address;
            engine->fault_access = fault_access;
            engine->stop_reason = XTAJIT64_STOP_MEMORY_FAULT;
            uc_emu_stop( uc );
            return false;
        }
        if (found)
        {
            engine->fault_address = fault_address;
            engine->fault_access = fault_access;
            engine->mapping_error = err;
            engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
            uc_emu_stop( uc );
            return false;
        }
    }

    else if (access_perms && size > 0)
        check_canonical_access( address, size, access_perms, &found, &fault_address );

    engine->fault_address = fault_address;
    engine->fault_access = fault_access;
    /* A committed identity mapping can be created by a native Unixlib through
     * ntdll.so without traversing the ARM64EC PE syscall notification.  Let
     * the PE side query this exact address once before deciding that the guest
     * access is invalid.  Protection faults already have an authoritative
     * engine mapping and remain ordinary Windows access violations. */
    engine->stop_reason = required_perms ? XTAJIT64_STOP_MAPPING_MISS :
                                           XTAJIT64_STOP_MEMORY_FAULT;
    uc_emu_stop( uc );
    return false;
}

static void shared_memory_atomic_hook(
    uc_engine *uc, uc_shared_memory_atomic_phase phase, void *user )
{
    struct thread_engine *engine = user;
    uint64_t rip = XTAJIT64_FLIGHT_UNKNOWN_U64;
    uint64_t rsp = XTAJIT64_FLIGHT_UNKNOWN_U64;
    uint32_t type;

    if (!engine || !engine->flight_recorder) return;
    if (phase == UC_SHARED_MEMORY_ATOMIC_EXIT)
        type = XTAJIT64_FLIGHT_EVENT_ATOMIC_EXIT;
    else if (phase == UC_SHARED_MEMORY_ATOMIC_REENTRY)
        type = XTAJIT64_FLIGHT_EVENT_ATOMIC_REENTRY;
    else return;
    if (uc_reg_read( uc, UC_X86_REG_RIP, &rip ) != UC_ERR_OK)
        rip = XTAJIT64_FLIGHT_UNKNOWN_U64;
    if (uc_reg_read( uc, UC_X86_REG_RSP, &rsp ) != UC_ERR_OK)
        rsp = XTAJIT64_FLIGHT_UNKNOWN_U64;
    flight_record_engine_event( engine, type, XTAJIT64_FLIGHT_REASON_NONE,
                                XTAJIT64_FLIGHT_UNKNOWN_U32, rip, rsp );
}

static uc_err install_engine_hooks( struct thread_engine *engine )
{
    uc_hook hook;
    uc_err err;
    BOOL install_block_hook = FALSE;

#ifdef XTAJIT64_UNIXLIB_TEST
    /* The legacy concurrency harness deliberately holds hook callbacks to
     * exercise owner/mutator races.  Production does not install a block hook:
     * TB history samples uc_emu_start() entries outside generated execution. */
    install_block_hook = TRUE;
#endif
    if (install_block_hook &&
        (err = uc_hook_add( engine->uc, &hook, UC_HOOK_BLOCK, block_hook,
                            engine, 1, 0 )) != UC_ERR_OK)
        return err;
    if ((err = uc_hook_add( engine->uc, &hook, UC_HOOK_INSN, syscall_hook,
                            engine, 1, 0, UC_X86_INS_SYSCALL )) != UC_ERR_OK)
        return err;
    if ((err = uc_hook_add( engine->uc, &hook, UC_HOOK_INTR, interrupt_hook,
                            engine, 1, 0 )) != UC_ERR_OK)
        return err;
    if ((err = uc_hook_add( engine->uc, &hook, UC_HOOK_INSN_INVALID,
                            invalid_instruction_hook, engine, 1, 0 )) != UC_ERR_OK)
        return err;
    return uc_hook_add( engine->uc, &hook, UC_HOOK_MEM_INVALID,
                        invalid_memory_hook, engine, 1, 0 );
}

static uc_err open_thread_engine( struct thread_engine *engine )
{
    uc_err err;

    if ((err = uc_open( UC_ARCH_X86, UC_MODE_64, &engine->uc )) != UC_ERR_OK) return err;
    if ((provider.unicorn_perf_stats_enabled &&
         (err = provider.unicorn_enable_perf_counters( engine->uc )) != UC_ERR_OK) ||
        (err = uc_configure_identity_memory_fastpath(
             engine->uc, provider.identity_page_flags,
             provider.identity_address_bits )) != UC_ERR_OK ||
        (err = uc_configure_x64_boundary_guard(
             engine->uc, provider.ec_bitmap, provider.ec_bitmap_word_count,
             provider.highest_user_address, provider.ec_page_shift,
             &engine->boundary_idle_doorbell, NULL )) != UC_ERR_OK ||
        (err = uc_set_shared_memory_atomic_callback(
             engine->uc, shared_memory_atomic_hook, engine )) != UC_ERR_OK ||
        (err = uc_enable_shared_memory_atomics( engine->uc )) != UC_ERR_OK)
    {
        uc_close( engine->uc );
        engine->uc = NULL;
        return err;
    }
    if ((err = install_engine_hooks( engine )) != UC_ERR_OK)
    {
        range_array_free( &engine->mapped_ranges );
        uc_close( engine->uc );
        engine->uc = NULL;
    }
    else engine->mapping_generation = 0;
    return err;
}

static uc_err write_context( struct thread_engine *engine,
                             struct xtajit64_x64_context *context,
                             uint64_t gs_base )
{
    uc_switchyard_x86_64_transition_context packed;

#ifdef XTAJIT64_UNIXLIB_TEST
    atomic_fetch_add_explicit( &test_context_write_count, 1, memory_order_relaxed );
#endif
    memcpy( &packed, context, sizeof(packed) );
    return uc_switchyard_x86_64_import_transition_context(
        engine->uc, &packed, gs_base,
        UC_SWITCHYARD_X86_64_TRANSITION_CONTEXT_VERSION, sizeof(packed) );
}

static uc_err read_context( struct thread_engine *engine,
                            struct xtajit64_x64_context *context )
{
    uc_switchyard_x86_64_transition_context packed;
    uc_err err;

#ifdef XTAJIT64_UNIXLIB_TEST
    atomic_fetch_add_explicit( &test_context_read_count, 1, memory_order_relaxed );
    if (atomic_load_explicit( &test_check_context_read_lock, memory_order_acquire ))
    {
        int ret = pthread_mutex_trylock( &provider.mutex );

        if (!ret)
        {
            atomic_store_explicit( &test_context_read_lock_violation, 1,
                                   memory_order_release );
            pthread_mutex_unlock( &provider.mutex );
        }
        else if (ret != EBUSY)
            atomic_store_explicit( &test_context_read_lock_violation, 1,
                                   memory_order_release );
    }
#endif
    packed.reserved = context->reserved;
    err = uc_switchyard_x86_64_export_transition_context(
        engine->uc, &packed,
        UC_SWITCHYARD_X86_64_TRANSITION_CONTEXT_VERSION, sizeof(packed) );
    if (err == UC_ERR_OK) memcpy( context, &packed, sizeof(packed) );
    return err;
}

static uc_err prepare_x64_syscall_engine( struct thread_engine *engine,
                                          uint64_t dispatcher, uint32_t count,
                                          uint64_t *next_rip )
{
    uint64_t rax, r10, rip;
    BOOL handled;
    static const int read_regs[] =
    {
        UC_X86_REG_RAX, UC_X86_REG_RIP, UC_X86_REG_R10,
    };
    static const int write_regs[] =
    {
        UC_X86_REG_RCX, UC_X86_REG_R10, UC_X86_REG_RIP,
    };
    void *read_values[] = {&rax, &rip, &r10};
    void *write_values[] = {&r10, &rip, &dispatcher};
    uc_err err;

    if ((err = uc_reg_read_batch( engine->uc, read_regs, read_values,
                                  ARRAY_SIZE(read_regs) )) != UC_ERR_OK)
        return err;
    if (rax >= count)
    {
        rax = (uint64_t)(int64_t)STATUS_INVALID_SYSTEM_SERVICE;
        if ((err = uc_reg_write( engine->uc, UC_X86_REG_RAX, &rax )) != UC_ERR_OK)
            return err;
        *next_rip = rip;
        return UC_ERR_OK;
    }
    if (rax == XTAJIT64_X64_SYSCALL_NT_READ_VIRTUAL_MEMORY)
    {
        if ((err = try_direct_self_read( engine, rip, r10, next_rip,
                                         &handled )) != UC_ERR_OK || handled)
            return err;
    }
    /* Match ntdll's ARM64EC STATUS_EMULATION_SYSCALL conversion.  Unicorn
     * reports RIP after both SYSCALL and INT 2E once the stop hook returns. */
    if ((err = uc_reg_write_batch( engine->uc, write_regs, write_values,
                                   ARRAY_SIZE(write_regs) )) != UC_ERR_OK)
        return err;
    *next_rip = dispatcher;
    return UC_ERR_OK;
}

static uc_err create_pool_engine_locked( struct thread_engine **result )
{
    struct thread_engine *engine;
    uc_context *initial_context = NULL;
    uc_err err;
    unsigned int i;

    if (!(engine = calloc( 1, sizeof(*engine) ))) return UC_ERR_NOMEM;
    atomic_init( &engine->pause_requested, false );
    atomic_init( &engine->ec_target_stats_lost, 0 );
    for (i = 0; i < XTAJIT64_EC_TARGET_STATS_ENGINE_SLOTS; ++i)
    {
        atomic_init( &engine->ec_target_stats[i].address, 0 );
        atomic_init( &engine->ec_target_stats[i].count, 0 );
    }
    if (provider.tb_history_enabled &&
        !(engine->tb_history = tb_history_create()))
    {
        err = UC_ERR_NOMEM;
        goto failed;
    }
    if ((err = open_thread_engine( engine )) != UC_ERR_OK) goto failed;
    if (!provider.initial_context)
    {
        if ((err = uc_context_alloc( engine->uc, &initial_context )) != UC_ERR_OK ||
            (err = uc_context_save( engine->uc, initial_context )) != UC_ERR_OK)
            goto failed;
        provider.initial_context = initial_context;
    }
    engine->diagnostic_id = ++provider.next_diagnostic_id;
    engine->next = provider.engines;
    provider.engines = engine;
    engine->linked = TRUE;
    ++provider.engine_count;
    if (result) *result = engine;
    return UC_ERR_OK;

failed:
    if (initial_context) uc_context_free( initial_context );
    if (engine->uc) uc_close( engine->uc );
    range_array_free( &engine->mapped_ranges );
    free( engine->tb_history );
    free( engine );
    return err;
}

static void clear_engine_residency_locked( struct thread_engine *engine )
{
    struct thread_binding *binding = engine->resident_binding;

    if (binding && binding->resident_engine == engine)
        binding->resident_engine = NULL;
    engine->resident_binding = NULL;
    engine->resident_binding_id = 0;
}

static uc_err evict_engine_residency_locked( struct thread_engine *engine )
{
    struct thread_binding *binding = engine->resident_binding;
    uc_err err;

    if (!binding)
    {
        engine->resident_binding_id = 0;
        return UC_ERR_OK;
    }
    if (binding->resident_engine != engine ||
        engine->resident_binding_id != binding->id || !binding->context)
        return UC_ERR_HANDLE;
    if ((err = uc_context_save( engine->uc, binding->context )) != UC_ERR_OK)
        return err;
    binding->context_valid = TRUE;
    clear_engine_residency_locked( engine );
    return UC_ERR_OK;
}

static uc_err acquire_pool_engine_locked( struct thread_binding *binding,
                                          struct thread_engine **result )
{
    struct thread_engine *engine, *idle = NULL;
    uc_err err;

    while (provider.mutating && provider.initialized)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (!provider.initialized || provider.shutting_down || provider.poison_status)
        return UC_ERR_HANDLE;
    if ((engine = binding->resident_engine))
    {
        if (!engine->linked || engine->in_use ||
            engine->resident_binding != binding ||
            engine->resident_binding_id != binding->id)
            return UC_ERR_HANDLE;
    }
    else
    {
        idle = NULL;
        for (engine = provider.engines; engine; engine = engine->next)
        {
            if (engine->in_use) continue;
            if (!idle) idle = engine;
        }
        engine = idle;
    }
    if (!engine && (err = create_pool_engine_locked( &engine )) != UC_ERR_OK)
        return err;
    if (!binding->context &&
        (err = uc_context_alloc( engine->uc, &binding->context )) != UC_ERR_OK)
        return err;
    if (engine->resident_binding == binding)
        clear_engine_residency_locked( engine );
    else
    {
        if ((err = evict_engine_residency_locked( engine )) != UC_ERR_OK)
            return err;
        if ((err = uc_context_restore( engine->uc, binding->context_valid ?
                                       binding->context : provider.initial_context )) != UC_ERR_OK)
            return err;
    }

    engine->owner = pthread_self();
    engine->in_use = TRUE;
    engine->flight_stop_detail0 = XTAJIT64_FLIGHT_UNKNOWN_U64;
    engine->flight_recorder = binding->flight_recorder;
    if (engine->flight_recorder || engine->tb_history)
    {
        if (!(++engine->execution_generation)) ++engine->execution_generation;
    }
    if (engine->tb_history)
    {
        engine->tb_binding_id = binding->id;
        engine->tb_causal_boundary_id = binding->flight_causal_boundary_id;
    }
    if (engine->flight_recorder)
    {
        engine->flight_binding_id = binding->id;
        engine->flight_causal_boundary_id = binding->flight_causal_boundary_id;
        engine->flight_context_generation = binding->flight_context_generation;
        engine->flight_transition_generation = binding->flight_transition_generation;
        engine->flight_expected_teb = binding->flight_expected_teb;
        engine->flight_claimed_teb = binding->flight_claimed_teb;
        engine->flight_guest_rip = binding->flight_guest_rip;
        engine->flight_guest_rsp = binding->flight_guest_rsp;
        engine->flight_guest_stack_limit = binding->flight_guest_stack_limit;
        engine->flight_guest_stack_base = binding->flight_guest_stack_base;
        engine->flight_control_stack_limit = binding->flight_control_stack_limit;
        engine->flight_control_stack_top = binding->flight_control_stack_top;
        engine->flight_pid = binding->flight_pid;
        engine->flight_mach_thread_id = binding->flight_mach_thread_id;
        engine->flight_pthread_identity = binding->flight_pthread_identity;
    }
    ++provider.engines_in_use;
    provider.engine_high_water = max( provider.engine_high_water,
                                      provider.engines_in_use );
    engine->diagnostic_pool_size = provider.engine_count;
    engine->diagnostic_pool_in_use = provider.engines_in_use;
    engine->diagnostic_pool_high_water = provider.engine_high_water;
    binding->active = TRUE;
    if (engine->flight_recorder)
        flight_record_engine_event( engine, XTAJIT64_FLIGHT_EVENT_ENGINE_ACQUIRE,
                                    XTAJIT64_FLIGHT_REASON_NONE,
                                    XTAJIT64_FLIGHT_UNKNOWN_U32,
                                    XTAJIT64_FLIGHT_UNKNOWN_U64,
                                    XTAJIT64_FLIGHT_UNKNOWN_U64 );
#ifdef XTAJIT64_UNIXLIB_TEST
    test_last_acquired_engine = engine;
#endif
    *result = engine;
    return UC_ERR_OK;
}

static uc_err release_pool_engine_locked( struct thread_binding *binding,
                                          struct thread_engine *engine,
                                          BOOL save_context )
{
    uc_err err = UC_ERR_OK;
    uc_err stop_err;

    if (save_context)
    {
        if ((binding->resident_engine && binding->resident_engine != engine) ||
            (engine->resident_binding && engine->resident_binding != binding))
        {
            err = UC_ERR_HANDLE;
            if (binding->resident_engine)
                clear_engine_residency_locked( binding->resident_engine );
            clear_engine_residency_locked( engine );
        }
        else
        {
            binding->resident_engine = engine;
            engine->resident_binding = binding;
            engine->resident_binding_id = binding->id;
        }
    }
    else clear_engine_residency_locked( engine );
    if (engine->flight_recorder)
    {
        flight_record_engine_event( engine, XTAJIT64_FLIGHT_EVENT_ENGINE_RELEASE,
                                    XTAJIT64_FLIGHT_REASON_NONE,
                                    XTAJIT64_FLIGHT_UNKNOWN_U32,
                                    XTAJIT64_FLIGHT_UNKNOWN_U64,
                                    XTAJIT64_FLIGHT_UNKNOWN_U64 );
        engine->flight_recorder = NULL;
        engine->flight_binding_id = 0;
        engine->flight_causal_boundary_id = 0;
        engine->flight_context_generation = 0;
        engine->flight_transition_generation = 0;
        engine->flight_expected_teb = 0;
        engine->flight_claimed_teb = 0;
        engine->flight_guest_rip = 0;
        engine->flight_guest_rsp = 0;
        engine->flight_guest_stack_limit = 0;
        engine->flight_guest_stack_base = 0;
        engine->flight_control_stack_limit = 0;
        engine->flight_control_stack_top = 0;
        engine->flight_pid = 0;
        engine->flight_mach_thread_id = 0;
        engine->flight_pthread_identity = 0;
    }
    engine->tb_binding_id = 0;
    engine->tb_causal_boundary_id = 0;
    engine->flight_stop_detail0 = XTAJIT64_FLIGHT_UNKNOWN_U64;
    if (engine->running)
    {
        /* A mutator may publish its stop after uc_emu_start() has returned but
         * before the owner can reacquire this mutex.  No further requester can
         * enter while the mutex is held, so discard that lease-scoped request
         * before running=FALSE exposes the engine to the pool. */
        stop_err = uc_clear_instruction_boundary_stop( engine->uc );
        engine->running = FALSE;
        if (stop_err != UC_ERR_OK)
        {
            engine->mapping_error = stop_err;
            engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
            poison_provider_locked( STATUS_UNSUCCESSFUL );
            if (err == UC_ERR_OK) err = stop_err;
        }
    }
    engine->in_use = FALSE;
    {
        uc_err doorbell_err = uc_update_x64_boundary_suspend_doorbell(
            engine->uc, &engine->boundary_idle_doorbell );

        if (doorbell_err != UC_ERR_OK)
        {
            /* Never return an engine to the pool while Unicorn may retain a
             * caller-owned doorbell pointer.  A poisoned provider cannot run
             * the engine again, even if the extension failed before replacing
             * its pointer. */
            engine->mapping_error = doorbell_err;
            engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
            poison_provider_locked( STATUS_UNSUCCESSFUL );
            if (err == UC_ERR_OK) err = doorbell_err;
        }
    }
    engine->suspend_doorbell = NULL;
    --provider.engines_in_use;
    binding->active = FALSE;
    pthread_cond_broadcast( &provider.cond );
    return err;
}

static void destroy_thread_binding( void *value )
{
    struct thread_binding *binding = value;

    if (!binding) return;
    pthread_mutex_lock( &provider.mutex );
    if (binding->resident_engine)
        clear_engine_residency_locked( binding->resident_engine );
    pthread_mutex_unlock( &provider.mutex );
    if (binding->context) uc_context_free( binding->context );
    free( binding );
}

static void make_engine_key(void)
{
    engine_key_error = pthread_key_create( &engine_key, destroy_thread_binding );
}

static NTSTATUS merge_range_arrays( const struct range_array *left,
                                       const struct range_array *right,
                                       struct range_array *result )
{
    size_t i = 0, j = 0;

    if (left->count > SIZE_MAX - right->count ||
        !range_array_reserve( result, left->count + right->count ))
        return STATUS_NO_MEMORY;
    while (i < left->count || j < right->count)
    {
        const struct mapped_range *range;

        if (j == right->count ||
            (i < left->count && left->data[i].guest <= right->data[j].guest))
            range = &left->data[i++];
        else range = &right->data[j++];
        if (!range_array_append( result, range )) return STATUS_INVALID_ADDRESS;
    }
    return STATUS_SUCCESS;
}

static enum mutation_kind observer_mutation_kind( uint32_t operation )
{
    switch (operation)
    {
    case WINE_WOW64_MEMORY_ALLOCATE:
    case WINE_WOW64_MEMORY_COMMIT:
    case WINE_WOW64_MEMORY_MAP:
        return MUTATION_MAP;
    case WINE_WOW64_MEMORY_DECOMMIT:
    case WINE_WOW64_MEMORY_RELEASE:
    case WINE_WOW64_MEMORY_UNMAP:
        return MUTATION_UNMAP;
    case WINE_WOW64_MEMORY_PROTECT:
        return MUTATION_PROTECT;
    default:
        return MUTATION_RESYNC;
    }
}

static BOOL observer_operation_is_valid( uint32_t operation )
{
    return operation >= WINE_WOW64_MEMORY_RESYNC &&
           operation <= WINE_WOW64_MEMORY_UNMAP;
}

static BOOL low_host_interval_to_guest( uint64_t host, uint64_t size,
                                        uint64_t *guest_start, uint64_t *guest_end )
{
    uint64_t guest;

    if (!size || (host & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
        (size & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
        host < WINE_LOW_VA_SHADOW_BASE)
        return FALSE;
    guest = host - WINE_LOW_VA_SHADOW_BASE;
    if (guest >= WINE_LOW_VA_SHADOW_SIZE ||
        size > WINE_LOW_VA_SHADOW_SIZE - guest)
        return FALSE;
    *guest_start = guest;
    *guest_end = guest + size;
    return TRUE;
}

static BOOL low_host_allocation_base_is_valid( uint64_t host_allocation_base )
{
    return !host_allocation_base ||
           (!(host_allocation_base & (XTAJIT64_GUEST_PAGE_SIZE - 1)) &&
            host_allocation_base >= WINE_LOW_VA_SHADOW_BASE &&
            host_allocation_base - WINE_LOW_VA_SHADOW_BASE <
                WINE_LOW_VA_SHADOW_SIZE);
}

static BOOL observer_protection_is_valid( uint32_t protect )
{
    uint32_t base = protect & 0xff;

    if (protect & ~(0xffu | PAGE_GUARD | PAGE_NOCACHE)) return FALSE;
    switch (base)
    {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS validate_observer_event_header(
    const struct wine_arm64ec_low_memory_event_v1 *event,
    const struct arm64ec_low_observer_transaction *transaction,
    uint64_t *guest_start, uint64_t *guest_end, BOOL *full_snapshot )
{
    if (!event || event->version != WINE_ARM64EC_LOW_MEMORY_OBSERVER_VERSION ||
        event->size != sizeof(*event) || event->operation != transaction->operation ||
        !observer_operation_is_valid( event->operation ) ||
        (event->flags & ~WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT) ||
        event->reserved[0] || event->reserved[1] ||
        event->range_count > XTAJIT64_MAX_RESYNC_RANGES ||
        event->range_count > SIZE_MAX ||
        (event->range_count && !event->ranges) ||
        !low_host_interval_to_guest( event->host_address, event->size_covered,
                                     guest_start, guest_end ) ||
        !low_host_allocation_base_is_valid( event->host_allocation_base ))
        return STATUS_INVALID_PARAMETER;

    *full_snapshot = !!(event->flags & WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT);
    if (*full_snapshot)
    {
        if (event->host_address != WINE_LOW_VA_SHADOW_BASE ||
            event->size_covered != WINE_LOW_VA_SHADOW_SIZE ||
            event->host_allocation_base)
            return STATUS_INVALID_PARAMETER;
    }
    else if (!provider.observer_active)
        return STATUS_INVALID_DEVICE_STATE;
    return STATUS_SUCCESS;
}

static NTSTATUS build_observer_ranges(
    const struct wine_arm64ec_low_memory_event_v1 *event,
    uint64_t guest_start, uint64_t guest_end, struct range_array *result )
{
    uint64_t cursor = guest_start;
    size_t i, count = (size_t)event->range_count;

    if (count && !range_array_reserve( result, count )) return STATUS_NO_MEMORY;
    for (i = 0; i < count; ++i)
    {
        const struct wine_arm64ec_low_memory_range_v1 *input = &event->ranges[i];
        struct mapped_range mapping;
        uint64_t input_guest, input_end, allocation_guest = 0;

        if (input->flags & ~WINE_ARM64EC_LOW_MEMORY_RANGE_VALID_FLAGS ||
            input->reserved || !input->size ||
            !low_host_interval_to_guest( input->host_address, input->size,
                                         &input_guest, &input_end ) ||
            input_guest != cursor || input_end > guest_end)
            return STATUS_INVALID_PARAMETER;
        switch (input->state)
        {
        case MEM_FREE:
            if (input->host_allocation_base || input->protect != PAGE_NOACCESS)
                return STATUS_INVALID_PARAMETER;
            break;
        case MEM_RESERVE:
            if (!input->host_allocation_base || input->protect ||
                !low_host_allocation_base_is_valid( input->host_allocation_base ) ||
                input->host_allocation_base > input->host_address)
                return STATUS_INVALID_PARAMETER;
            allocation_guest = input->host_allocation_base - WINE_LOW_VA_SHADOW_BASE;
            break;
        case MEM_COMMIT:
            if (!input->host_allocation_base ||
                !low_host_allocation_base_is_valid( input->host_allocation_base ) ||
                input->host_allocation_base > input->host_address ||
                !observer_protection_is_valid( input->protect ))
                return STATUS_INVALID_PARAMETER;
            allocation_guest = input->host_allocation_base - WINE_LOW_VA_SHADOW_BASE;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
        }

        if (input->state != MEM_FREE)
        {
            memset( &mapping, 0, sizeof(mapping) );
            mapping.guest = input_guest;
            mapping.host = input->host_address;
            mapping.size = input->size;
            mapping.allocation_base = allocation_guest;
            mapping.perms = input->state == MEM_COMMIT ?
                            protection_to_unicorn( input->protect ) : UC_PROT_NONE;
            mapping.state = input->state;
            mapping.domain = XTAJIT64_MEMORY_ADDRESS_AMD64_LOW;
            mapping.stale = FALSE;
            if (!range_array_append( result, &mapping )) return STATUS_INVALID_PARAMETER;
        }
        cursor = input_end;
    }
    return cursor == guest_end ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

static NTSTATUS build_observer_replacement( const struct range_array *old,
                                             const struct range_array *captured,
                                             uint64_t start, uint64_t end,
                                             BOOL full_snapshot,
                                             struct range_array *result )
{
    struct range_array retained = {0};
    NTSTATUS status = STATUS_SUCCESS;
    size_t i;

    if (old->count > (SIZE_MAX - 1) / 2 ||
        !range_array_reserve( &retained, old->count * 2 + 1 ))
        return STATUS_NO_MEMORY;
    for (i = 0; i < old->count; ++i)
    {
        const struct mapped_range *range = &old->data[i];
        uint64_t range_end = range->guest + range->size;
        struct mapped_range slice;

        if (range->domain != XTAJIT64_MEMORY_ADDRESS_AMD64_LOW)
        {
            if (!range_array_append( &retained, range ))
            {
                status = STATUS_INVALID_ADDRESS;
                goto done;
            }
            continue;
        }
        if (range->permanent)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            goto done;
        }
        if (full_snapshot) continue;
        if (!range_overlaps( range, start, end ))
        {
            if (!range_array_append( &retained, range ))
            {
                status = STATUS_INVALID_ADDRESS;
                goto done;
            }
            continue;
        }
        if (range->guest < start)
        {
            slice = range_slice( range, range->guest, start );
            if (!range_array_append( &retained, &slice ))
            {
                status = STATUS_INVALID_ADDRESS;
                goto done;
            }
        }
        if (range_end > end)
        {
            slice = range_slice( range, end, range_end );
            if (!range_array_append( &retained, &slice ))
            {
                status = STATUS_INVALID_ADDRESS;
                goto done;
            }
        }
    }
    status = merge_range_arrays( &retained, captured, result );

done:
    range_array_free( &retained );
    return status;
}

static int32_t arm64ec_low_observer_begin_callback(
    void *context, uint32_t operation, uint64_t host_address, uint64_t size,
    uint64_t host_allocation_base, void **transaction_ret )
{
    struct arm64ec_low_observer_transaction *transaction;
    volatile NTSTATUS status = STATUS_SUCCESS;
    volatile BOOL faulted = FALSE;
    BOOL claimed = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0, guest_start, guest_end;

    if (!transaction_ret) return STATUS_INVALID_PARAMETER;
    *transaction_ret = NULL;
    if (context != &provider || !observer_operation_is_valid( operation ) ||
        !low_host_interval_to_guest( host_address, size, &guest_start, &guest_end ) ||
        !low_host_allocation_base_is_valid( host_allocation_base ))
        return STATUS_INVALID_PARAMETER;
    if (!(transaction = calloc( 1, sizeof(*transaction) ))) return STATUS_NO_MEMORY;

    pthread_mutex_lock( &provider.mutex );
    /* Reject same-owner recursion; a foreign transaction must finish through
     * claim_mutation_locked() before we can publish our own token. */
    if (current_thread_owns_mutation_locked())
        status = STATUS_INVALID_DEVICE_STATE;
    else
    {
        status = claim_mutation_locked( observer_mutation_kind( operation ), FALSE );
        claimed = !status;
    }
    if (!status) __TRY
    {
        pause_mutation_engines_locked();
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted && !status && claimed && current_thread_owns_mutation_locked())
        status = wait_for_mutation_engines_locked();
    if (!faulted && !status)
    {
        transaction->generation = provider.generation;
        transaction->operation = operation;
        provider.observer_transaction = transaction;
        *transaction_ret = transaction;
    }
    else if (!faulted && claimed && current_thread_owns_mutation_locked())
        finish_mutation_locked();
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    pthread_mutex_unlock( &provider.mutex );
    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    if (status) free( transaction );
    return status;
}

static void arm64ec_low_observer_complete_callback(
    void *context, void *token,
    const struct wine_arm64ec_low_memory_event_v1 *event )
{
    struct arm64ec_low_observer_transaction *transaction = NULL;
    struct range_array captured = {0}, replacement = {0};
    volatile NTSTATUS status = STATUS_SUCCESS;
    volatile BOOL faulted = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0, guest_start = 0, guest_end = 0;
    uint64_t free_bytes = 0, reserve_bytes = 0, commit_bytes = 0;
    uint64_t free_ranges = 0, reserve_ranges = 0, commit_ranges = 0;
    BOOL full_snapshot = FALSE;
    size_t i;

    pthread_mutex_lock( &provider.mutex );
    transaction = provider.observer_transaction;
    if (context != &provider || !token || token != transaction ||
        !transaction || !current_thread_owns_mutation_locked() ||
        transaction->generation != provider.generation)
    {
        status = STATUS_INVALID_DEVICE_STATE;
        poison_provider_locked( status );
        pthread_mutex_unlock( &provider.mutex );
        WARN( "rejected non-owning ARM64EC LOW memory completion\n" );
        return;
    }
    if (!status) __TRY
    {
        status = validate_observer_event_header( event, transaction,
                                                 &guest_start, &guest_end,
                                                 &full_snapshot );
        if (!status && event->snapshot_status) status = event->snapshot_status;
        if (!status)
            status = build_observer_ranges( event, guest_start, guest_end, &captured );
        if (!status)
            status = build_observer_replacement( &provider.ranges, &captured,
                                                 guest_start, guest_end,
                                                 full_snapshot, &replacement );
        if (!status) set_mutation_stage_locked( MUTATION_STAGE_APPLY );
        if (!status)
        {
            struct range_array old = provider.ranges;

            set_mutation_stage_locked( MUTATION_STAGE_PUBLISH );
            mark_engine_mappings_stale_locked( guest_start,
                                               guest_end - guest_start, 0 );
            for (i = 0; i < (size_t)event->range_count; ++i)
            {
                switch (event->ranges[i].state)
                {
                case MEM_FREE:
                    ++free_ranges;
                    free_bytes += event->ranges[i].size;
                    break;
                case MEM_RESERVE:
                    ++reserve_ranges;
                    reserve_bytes += event->ranges[i].size;
                    break;
                case MEM_COMMIT:
                    ++commit_ranges;
                    commit_bytes += event->ranges[i].size;
                    break;
                }
            }
            provider.ranges = replacement;
            memset( &replacement, 0, sizeof(replacement) );
            ++provider.generation;
            if (full_snapshot) provider.observer_active = TRUE;
            TRACE( "published ARM64EC LOW event operation %u mutation status %#x, "
                   "full %u covered %#llx ranges %llu, free %llu/%#llx "
                   "reserve %llu/%#llx commit %llu/%#llx generation %llu\n",
                   event->operation,
                   (unsigned int)event->status, full_snapshot,
                   (unsigned long long)event->size_covered,
                   (unsigned long long)event->range_count,
                   (unsigned long long)free_ranges,
                   (unsigned long long)free_bytes,
                   (unsigned long long)reserve_ranges,
                   (unsigned long long)reserve_bytes,
                   (unsigned long long)commit_ranges,
                   (unsigned long long)commit_bytes,
                   (unsigned long long)provider.generation );
            range_array_free( &old );
        }
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted)
    {
        if (status) poison_provider_locked( status );
        if (provider.mutating) finish_mutation_locked();
    }
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    provider.observer_transaction = NULL;
    pthread_mutex_unlock( &provider.mutex );

    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    else if (status)
        WARN( "cannot publish ARM64EC LOW memory event status %#x\n",
              (unsigned int)status );
    range_array_free( &captured );
    range_array_free( &replacement );
    free( transaction );
}

static const struct wine_arm64ec_low_memory_observer_v1 arm64ec_low_memory_observer =
{
    WINE_ARM64EC_LOW_MEMORY_OBSERVER_VERSION,
    sizeof(arm64ec_low_memory_observer),
    &provider,
    arm64ec_low_observer_begin_callback,
    arm64ec_low_observer_complete_callback,
    WINE_ARM64EC_LOW_MEMORY_OBSERVER_CAP_EXACT_POST_SNAPSHOT,
};

static uc_err synchronize_engine_registry_locked( struct thread_engine *engine );

static NTSTATUS overlay_cpu_alias_snapshot( struct range_array *registry,
    const struct wine_arm64ec_cpu_alias_snapshot_v1 *snapshot )
{
    unsigned int i, j;
    NTSTATUS status;
    if (!snapshot) return STATUS_SUCCESS;
    for (i = 0; i < snapshot->count; ++i)
        for (j = 0; j < 4; ++j)
        {
            const struct wine_arm64ec_cpu_alias_range_v1 *input = &snapshot->ranges[i];
            struct mapped_range range = {0};
            struct range_array replacement = {0};
            range.guest = range.host = input->address + j * 4096;
            range.size = 4096;
            range.allocation_base = input->allocation_base;
            range.perms = protection_to_unicorn( input->protect[j] );
            range.state = input->state[j];
            range.domain = XTAJIT64_MEMORY_ADDRESS_IDENTITY;
            range.flags = input->backing != input->address ? XTAJIT64_RANGE_CPU_ALIAS : 0;
            status = build_mapped_registry( registry, &range, &replacement );
            if (status) { range_array_free( &replacement ); return status; }
            range_array_free( registry );
            *registry = replacement;
        }
    return STATUS_SUCCESS;
}

static NTSTATUS replace_cpu_alias_snapshot_locked(
    struct wine_arm64ec_cpu_alias_snapshot_v1 *snapshot )
{
    struct range_array replacement = {0}, removed = {0}, added = {0};
    struct thread_engine *engine;
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int i;
    size_t j;
    if (!snapshot && !cpu_alias_snapshot) return STATUS_SUCCESS;
    if (!current_thread_owns_mutation_locked()) return STATUS_INVALID_DEVICE_STATE;
    if (!range_array_reserve( &replacement, provider.ranges.count )) return STATUS_NO_MEMORY;
    for (j = 0; j < provider.ranges.count; ++j)
        if (!range_array_append( &replacement, &provider.ranges.data[j] )) { status = STATUS_INVALID_ADDRESS; goto done; }
    if (cpu_alias_snapshot)
        for (i = 0; i < cpu_alias_snapshot->count; ++i)
        {
            struct range_array filtered = {0};
            uint64_t address = cpu_alias_snapshot->ranges[i].address;
            if (cpu_alias_snapshot->ranges[i].backing == address) continue;
            status = build_unmapped_registry( &replacement, address, 16384, address, &filtered );
            if (status) { range_array_free( &filtered ); goto done; }
            range_array_free( &replacement );
            replacement = filtered;
            mark_engine_mappings_stale_locked( address, 16384, 0 );
        }
    if ((status = overlay_cpu_alias_snapshot( &replacement, snapshot ))) goto done;
    if ((status = build_resync_mapping_changes( &provider.ranges, &replacement, &removed, &added ))) goto done;
    /* Flags are part of backing identity, even when guest/native addresses match. */
    if ((status = publish_identity_page_flag_changes_locked( &removed, &added ))) goto done;
    if (snapshot)
        for (i = 0; i < snapshot->count; ++i)
        {
            struct mapped_range whole = {0};
            size_t first, count;
            whole.guest = snapshot->ranges[i].address; whole.size = 16384;
            if (!identity_page_flag_span( &whole, &first, &count )) { status = STATUS_INVALID_ADDRESS; goto done; }
            /* Every lane goes through the software TLB until ordinary resync
             * republishes native identity permissions after the alias retires. */
            publish_identity_page_permissions( first, count, 0 );
            mark_engine_mappings_stale_locked( whole.guest, 16384, 0 );
        }
    range_array_free( &provider.ranges );
    provider.ranges = replacement;
    memset( &replacement, 0, sizeof(replacement) );
    for (engine = provider.engines; engine; engine = engine->next)
    {
        engine->mapping_generation = 0;
        if (synchronize_engine_registry_locked( engine ) != UC_ERR_OK)
        { status = STATUS_UNSUCCESSFUL; goto done; }
    }
#ifndef XTAJIT64_UNIXLIB_TEST
    __wine_release_arm64ec_cpu_alias_v1( cpu_alias_snapshot );
#endif
    cpu_alias_snapshot = snapshot;
done:
    range_array_free( &replacement ); range_array_free( &removed ); range_array_free( &added );
    return status;
}

static BOOL arm64ec_code_operation_is_valid( uint32_t operation )
{
    switch (operation)
    {
    case WINE_ARM64EC_CODE_RESYNC:
    case WINE_ARM64EC_CODE_ALLOCATE:
    case WINE_ARM64EC_CODE_RELEASE:
    case WINE_ARM64EC_CODE_MAP:
    case WINE_ARM64EC_CODE_UNMAP:
    case WINE_ARM64EC_CODE_PROTECT:
        return TRUE;
    default:
        return FALSE;
    }
}

static enum mutation_kind arm64ec_code_mutation_kind( uint32_t operation )
{
    switch (operation)
    {
    case WINE_ARM64EC_CODE_RESYNC: return MUTATION_RESYNC;
    case WINE_ARM64EC_CODE_PROTECT: return MUTATION_PROTECT;
    case WINE_ARM64EC_CODE_ALLOCATE:
    case WINE_ARM64EC_CODE_MAP: return MUTATION_MAP;
    case WINE_ARM64EC_CODE_RELEASE:
    case WINE_ARM64EC_CODE_UNMAP: return MUTATION_UNMAP;
    default: return MUTATION_FLUSH;
    }
}

static NTSTATUS validate_arm64ec_code_event(
    const struct wine_arm64ec_code_event_v1 *event,
    const struct arm64ec_code_observer_transaction *transaction,
    BOOL *full_invalidation )
{
    uint64_t page_mask, previous_end = 0;
    size_t i, count;

    if (!event || event->version != WINE_ARM64EC_CODE_OBSERVER_VERSION ||
        event->size != sizeof(*event) || event->operation != transaction->operation ||
        !arm64ec_code_operation_is_valid( event->operation ) ||
        (event->flags & ~WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION) ||
        event->reserved || event->range_count > XTAJIT64_MAX_RESYNC_RANGES ||
        event->range_count > SIZE_MAX || (event->range_count && !event->ranges))
        return STATUS_INVALID_PARAMETER;

    *full_invalidation = !!(event->flags & WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION);
    if (*full_invalidation)
    {
        if (event->range_count) return STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    if (!provider.code_observer_active) return STATUS_INVALID_DEVICE_STATE;

    page_mask = (UINT64_C(1) << provider.ec_page_shift) - 1;
    count = (size_t)event->range_count;
    for (i = 0; i < count; ++i)
    {
        const struct wine_arm64ec_code_range_v1 *range = &event->ranges[i];
        uint64_t end;

        if (!range->size || (range->address & page_mask) ||
            (range->size & page_mask) ||
            range->address > provider.highest_user_address ||
            range->size - 1 > provider.highest_user_address - range->address)
            return STATUS_INVALID_PARAMETER;
        end = range->address + range->size;
        if (i && range->address <= previous_end) return STATUS_INVALID_PARAMETER;
        previous_end = end;
    }
    return STATUS_SUCCESS;
}

static int32_t arm64ec_code_observer_begin_callback(
    void *context, uint32_t operation, void **transaction_ret )
{
    struct arm64ec_code_observer_transaction *transaction;
    volatile NTSTATUS status = STATUS_SUCCESS;
    volatile BOOL faulted = FALSE;
    BOOL claimed = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0;

    if (!transaction_ret) return STATUS_INVALID_PARAMETER;
    *transaction_ret = NULL;
    if (context != &provider || !arm64ec_code_operation_is_valid( operation ))
        return STATUS_INVALID_PARAMETER;
    if (!(transaction = calloc( 1, sizeof(*transaction) ))) return STATUS_NO_MEMORY;

    pthread_mutex_lock( &provider.mutex );
    /* Reject same-owner recursion; a foreign transaction must finish through
     * claim_mutation_locked() before we can publish our own token. */
    if (current_thread_owns_mutation_locked())
        status = STATUS_INVALID_DEVICE_STATE;
    else
    {
        /* Native thread teardown also changes identity views without passing
         * through the PE deferred-VM generation. Invalidate in-flight mapping
         * snapshots at this gate, before any view can disappear. */
        status = claim_mutation_locked( arm64ec_code_mutation_kind( operation ), TRUE );
        claimed = !status;
    }
    if (!status) __TRY
    {
        pause_mutation_engines_locked();
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted && !status && claimed && current_thread_owns_mutation_locked())
        status = wait_for_mutation_engines_locked();
    if (!faulted && !status)
    {
        transaction->generation = provider.generation;
        transaction->operation = operation;
        provider.code_observer_transaction = transaction;
        *transaction_ret = transaction;
    }
    else if (!faulted && claimed && current_thread_owns_mutation_locked())
        finish_mutation_locked();
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    pthread_mutex_unlock( &provider.mutex );
    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    if (status) free( transaction );
    return status;
}

static void arm64ec_code_observer_complete_callback(
    void *context, void *token, const struct wine_arm64ec_code_event_v1 *event )
{
    struct arm64ec_code_observer_transaction *transaction;
    struct thread_engine *engine;
    volatile NTSTATUS status = STATUS_SUCCESS;
    volatile BOOL faulted = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0;
    BOOL full_invalidation = FALSE;
    size_t i;
    struct wine_arm64ec_cpu_alias_snapshot_v1 *snapshot = NULL;
    NTSTATUS snapshot_status = STATUS_SUCCESS;

#ifndef XTAJIT64_UNIXLIB_TEST
    snapshot_status = __wine_acquire_arm64ec_cpu_alias_v1( cpu_alias_snapshot, &snapshot );
#endif
    pthread_mutex_lock( &provider.mutex );
    transaction = provider.code_observer_transaction;
    if (context != &provider || !token || token != transaction || !transaction ||
        !current_thread_owns_mutation_locked() ||
        transaction->generation != provider.generation)
    {
        status = STATUS_INVALID_DEVICE_STATE;
        poison_provider_locked( status );
        pthread_mutex_unlock( &provider.mutex );
        WARN( "rejected non-owning ARM64EC code completion\n" );
#ifndef XTAJIT64_UNIXLIB_TEST
        __wine_release_arm64ec_cpu_alias_v1( snapshot );
#endif
        return;
    }

    __TRY
    {
        status = validate_arm64ec_code_event( event, transaction, &full_invalidation );
        if (!status) status = snapshot_status;
        if (!status) set_mutation_stage_locked( MUTATION_STAGE_APPLY );
        if (!status)
        {
            status = replace_cpu_alias_snapshot_locked( snapshot );
            if (!status) snapshot = NULL;
        }
        if (!status)
        {
            for (engine = provider.engines; engine; engine = engine->next)
            {
                uc_err err = UC_ERR_OK;

                if (full_invalidation) err = uc_ctl_flush_tb( engine->uc );
                else if (event->range_count)
                {
                    err = uc_ctl_flush_tlb( engine->uc );
                    for (i = 0; err == UC_ERR_OK && i < (size_t)event->range_count; ++i)
                        err = uc_ctl_remove_cache(
                            engine->uc, event->ranges[i].address,
                            event->ranges[i].address + event->ranges[i].size );
                }
                if (err != UC_ERR_OK)
                {
                    status = STATUS_UNSUCCESSFUL;
                    break;
                }
            }
        }
        if (!status)
        {
            if (full_invalidation || event->range_count)
                advance_ec_leaf_fastpath_code_generation_locked();
            set_mutation_stage_locked( MUTATION_STAGE_PUBLISH );
            if (full_invalidation) provider.code_observer_active = TRUE;
            TRACE( "published ARM64EC code event operation %u mutation status %#x, "
                   "full %u ranges %llu\n", event->operation,
                   (unsigned int)event->status, full_invalidation,
                   (unsigned long long)event->range_count );
        }
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted)
    {
        if (status) poison_provider_locked( status );
        if (provider.mutating) finish_mutation_locked();
    }
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    provider.code_observer_transaction = NULL;
    pthread_mutex_unlock( &provider.mutex );

    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    else if (status)
        WARN( "cannot publish ARM64EC code event status %#x\n",
              (unsigned int)status );
#ifndef XTAJIT64_UNIXLIB_TEST
    __wine_release_arm64ec_cpu_alias_v1( snapshot );
#endif
    free( transaction );
}

static const struct wine_arm64ec_code_observer_v1 arm64ec_code_observer =
{
    WINE_ARM64EC_CODE_OBSERVER_VERSION,
    sizeof(arm64ec_code_observer),
    &provider,
    arm64ec_code_observer_begin_callback,
    arm64ec_code_observer_complete_callback,
    WINE_ARM64EC_CODE_OBSERVER_CAP_EXACT_INVALIDATION_RANGES | WINE_ARM64EC_CODE_OBSERVER_CAP_DATA_ALIAS,
};

static int32_t register_xtajit64_memory_observer(void)
{
#ifdef XTAJIT64_UNIXLIB_TEST
    struct wine_arm64ec_low_memory_range_v1 range =
    {
        WINE_LOW_VA_SHADOW_BASE,
        WINE_LOW_VA_SHADOW_SIZE,
        0,
        MEM_FREE,
        PAGE_NOACCESS,
        0,
        0,
    };
    struct wine_arm64ec_low_memory_event_v1 event =
    {
        WINE_ARM64EC_LOW_MEMORY_OBSERVER_VERSION,
        sizeof(event),
        WINE_WOW64_MEMORY_RESYNC,
        WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT,
        STATUS_SUCCESS,
        STATUS_SUCCESS,
        {0, 0},
        WINE_LOW_VA_SHADOW_BASE,
        WINE_LOW_VA_SHADOW_SIZE,
        0,
        &range,
        1,
    };
    struct wine_arm64ec_code_event_v1 code_event =
    {
        WINE_ARM64EC_CODE_OBSERVER_VERSION,
        sizeof(code_event),
        WINE_ARM64EC_CODE_RESYNC,
        WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION,
        STATUS_SUCCESS,
        0,
        NULL,
        0,
    };
    void *transaction = NULL, *code_transaction = NULL;
    int32_t status;

    status = arm64ec_low_memory_observer.begin( arm64ec_low_memory_observer.context,
                                                WINE_WOW64_MEMORY_RESYNC,
                                                WINE_LOW_VA_SHADOW_BASE,
                                                WINE_LOW_VA_SHADOW_SIZE, 0,
                                                &transaction );
    if (!status)
        arm64ec_low_memory_observer.complete( arm64ec_low_memory_observer.context,
                                              transaction, &event );
    if (!status)
        status = arm64ec_code_observer.begin( arm64ec_code_observer.context,
                                              WINE_ARM64EC_CODE_RESYNC,
                                              &code_transaction );
    if (!status)
        arm64ec_code_observer.complete( arm64ec_code_observer.context,
                                        code_transaction, &code_event );
    return status;
#else
    int32_t status = __wine_register_arm64ec_low_memory_observer_v1(
        &arm64ec_low_memory_observer );

    if (status) return status;
    return __wine_register_arm64ec_code_observer_v1( &arm64ec_code_observer );
#endif
}

static NTSTATUS process_init( void *args )
{
    struct xtajit64_process_init_params *params = args;
    struct mapped_range kuser;
    NTSTATUS status;
    unsigned int major, minor;
#ifndef XTAJIT64_UNIXLIB_TEST
    const char *tb_history_environment;
    const char *ec_target_stats_environment;
    const char *ec_target_stats_initial_environment;
    const char *ec_leaf_fastpath_environment;
    const char *ec_leaf_fastpath_stats_environment;
    uint64_t ec_target_stats_initial_report =
        XTAJIT64_EC_TARGET_STATS_DEFAULT_INITIAL_REPORT;
#ifdef __APPLE__
    const char *direct_self_read_stats_environment;
    const char *unicorn_perf_stats_environment;
    unicorn_enable_perf_counters_fn unicorn_enable_perf_counters = NULL;
    unicorn_get_perf_counters_fn unicorn_get_perf_counters = NULL;
    enum unicorn_perf_counter_api_resolution unicorn_perf_counter_api_resolution;
#endif
#endif

    TRACE( "CPU provider interface %s\n", XTAJIT64_PROVIDER_ABI_IDENTITY );
    if (!params) return STATUS_INVALID_PARAMETER;
    if (params->abi_version != XTAJIT64_PROCESS_ABI_VERSION ||
        params->abi_size != sizeof(*params) ||
        (params->required_capabilities & XTAJIT64_CAPABILITIES) != XTAJIT64_CAPABILITIES ||
        (params->required_capabilities & ~XTAJIT64_CAPABILITIES) ||
        params->enabled_capabilities)
        return STATUS_REVISION_MISMATCH;
    if (!params->ec_bitmap || (params->ec_bitmap & (sizeof(uint64_t) - 1)) ||
        !params->highest_user_address ||
        params->highest_user_address > XTAJIT64_X64_USER_ADDRESS_MAX ||
        !params->rtl_exit_user_thread ||
        params->rtl_exit_user_thread > XTAJIT64_X64_USER_ADDRESS_MAX ||
        params->rtl_exit_user_thread > params->highest_user_address ||
        (params->rtl_query_performance_counter &&
         (params->rtl_query_performance_counter > XTAJIT64_X64_USER_ADDRESS_MAX ||
          params->rtl_query_performance_counter > params->highest_user_address)) ||
        (params->nt_query_performance_counter &&
         (params->nt_query_performance_counter > XTAJIT64_X64_USER_ADDRESS_MAX ||
          params->nt_query_performance_counter > params->highest_user_address)) ||
        !params->x64_syscall_dispatcher ||
        params->x64_syscall_dispatcher > XTAJIT64_X64_USER_ADDRESS_MAX ||
        params->x64_syscall_dispatcher > params->highest_user_address ||
        !params->x64_syscall_count ||
        params->x64_syscall_count > XTAJIT64_MAX_SYSCALL_COUNT || params->reserved ||
        params->guest_kuser != XTAJIT64_GUEST_KUSER || !params->host_kuser ||
        params->kuser_size < XTAJIT64_GUEST_PAGE_SIZE ||
        params->kuser_size > XTAJIT64_MAX_HOST_PAGE_SIZE ||
        (params->kuser_size & (params->kuser_size - 1)) ||
        (params->guest_kuser & (params->kuser_size - 1)) ||
        (params->host_kuser & (params->kuser_size - 1)) ||
        params->guest_kuser > params->highest_user_address ||
        params->kuser_size - 1 > params->highest_user_address - params->guest_kuser ||
        params->host_kuser > UINT64_MAX - params->kuser_size)
        return STATUS_INVALID_PARAMETER;

    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error) return STATUS_NO_MEMORY;
    uc_version( &major, &minor );
    if (major != UC_API_MAJOR || (major == 2 && minor < 1))
    {
        ERR( "unsupported Unicorn API %u.%u\n", major, minor );
        return STATUS_REVISION_MISMATCH;
    }
#ifndef XTAJIT64_UNIXLIB_TEST
    tb_history_environment = getenv( "WINE_XTAJIT64_TB_HISTORY" );
    ec_target_stats_environment = getenv( "WINE_XTAJIT64_EC_TARGET_STATS" );
    ec_target_stats_initial_environment =
        getenv( "WINE_XTAJIT64_EC_TARGET_STATS_INITIAL" );
    ec_leaf_fastpath_environment = getenv( "WINE_XTAJIT64_EC_LEAF_FASTPATH" );
    ec_leaf_fastpath_stats_environment =
        getenv( "WINE_XTAJIT64_EC_LEAF_FASTPATH_STATS" );
    if (ec_target_stats_environment && !strcmp( ec_target_stats_environment, "1" ) &&
        ec_target_stats_initial_environment &&
        !parse_ec_target_stats_initial_report( ec_target_stats_initial_environment,
                                               &ec_target_stats_initial_report ))
    {
        ERR( "WINE_XTAJIT64_EC_TARGET_STATS_INITIAL must be a decimal value "
             "from %u through %u\n", XTAJIT64_EC_TARGET_STATS_MIN_INITIAL_REPORT,
             XTAJIT64_EC_TARGET_STATS_DEFAULT_INITIAL_REPORT );
        return STATUS_INVALID_PARAMETER;
    }
#ifdef __APPLE__
    direct_self_read_stats_environment =
        getenv( "WINE_XTAJIT64_DIRECT_READ_STATS" );
    unicorn_perf_stats_environment = getenv( "WINE_XTAJIT64_PERF_STATS" );
    if (unicorn_perf_stats_environment &&
        !strcmp( unicorn_perf_stats_environment, "1" ))
    {
        unicorn_perf_counter_api_resolution = resolve_unicorn_perf_counter_api(
            &unicorn_enable_perf_counters, &unicorn_get_perf_counters );
        if (unicorn_perf_counter_api_resolution != UNICORN_PERF_COUNTER_API_RESOLVED)
        {
            ERR( "WINE_XTAJIT64_PERF_STATS requires the Switchyard Unicorn "
                 "performance-counter API (resolver stage %u)\n",
                 unicorn_perf_counter_api_resolution );
            return STATUS_NOT_SUPPORTED;
        }
    }
#endif
#endif

    pthread_mutex_lock( &provider.mutex );
    while (provider.shutting_down)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (provider.initialized)
    {
        pthread_mutex_unlock( &provider.mutex );
        return STATUS_ALREADY_INITIALIZED;
    }
    status = allocate_identity_page_table_locked( params->highest_user_address );
    if (status)
    {
        pthread_mutex_unlock( &provider.mutex );
        return status;
    }
    provider.ec_bitmap = (const uint64_t *)(uintptr_t)params->ec_bitmap;
    /* kuser_size is a validated, nonzero power of two and is also the EC
     * bitmap page size.  Precompute its shift once instead of executing a
     * variable 64-bit division at every translated basic-block boundary. */
    provider.ec_page_shift = __builtin_ctzll( params->kuser_size );
    provider.ec_bitmap_word_count =
        (params->highest_user_address >> provider.ec_page_shift) / 64 + 1;
    provider.highest_user_address = params->highest_user_address;
    provider.rtl_exit_user_thread = params->rtl_exit_user_thread;
    provider.rtl_query_performance_counter = params->rtl_query_performance_counter;
    provider.nt_query_performance_counter = params->nt_query_performance_counter;
    provider.x64_syscall_dispatcher = params->x64_syscall_dispatcher;
    provider.x64_syscall_count = params->x64_syscall_count;
    provider.guest_kuser = params->guest_kuser;
    provider.host_kuser = params->host_kuser;
    provider.kuser_size = params->kuser_size;
    provider.next_diagnostic_id = 0;
    provider.next_binding_id = 0;
    provider.engine_count = 0;
    provider.engines_in_use = 0;
    provider.engine_high_water = 0;
    provider.ec_leaf_fastpath_code_generation = 1;
#ifdef XTAJIT64_UNIXLIB_TEST
    provider.tb_history_enabled = FALSE;
    provider.direct_self_read_stats_enabled = FALSE;
    provider.unicorn_perf_stats_enabled = FALSE;
    provider.ec_target_stats_enabled = FALSE;
    provider.ec_leaf_fastpath_enabled = FALSE;
    provider.ec_leaf_fastpath_stats_enabled = FALSE;
    provider.unicorn_enable_perf_counters = NULL;
    provider.unicorn_get_perf_counters = NULL;
#else
    provider.tb_history_enabled = tb_history_environment &&
                                  !strcmp( tb_history_environment, "1" );
    reset_ec_transition_target_stats( ec_target_stats_initial_report );
    provider.ec_target_stats_enabled = ec_target_stats_environment &&
                                       !strcmp( ec_target_stats_environment, "1" );
    /* The exact-state shortcut is a normal Apple native-runtime path.  Keep
     * a conservative per-process escape hatch for a new application or a
     * field regression; unsupported values also choose that fallback. */
#ifdef __APPLE__
    provider.ec_leaf_fastpath_enabled = !ec_leaf_fastpath_environment ||
                                        !strcmp( ec_leaf_fastpath_environment, "1" );
#else
    provider.ec_leaf_fastpath_enabled = FALSE;
#endif
    provider.ec_leaf_fastpath_stats_enabled = provider.ec_leaf_fastpath_enabled &&
                                              ec_leaf_fastpath_stats_environment &&
                                              !strcmp( ec_leaf_fastpath_stats_environment,
                                                       "1" );
#ifdef __APPLE__
    provider.direct_self_read_stats_enabled = direct_self_read_stats_environment &&
                                              !strcmp( direct_self_read_stats_environment,
                                                       "1" );
    provider.unicorn_perf_stats_enabled = unicorn_enable_perf_counters &&
                                          unicorn_get_perf_counters;
    provider.unicorn_enable_perf_counters = unicorn_enable_perf_counters;
    provider.unicorn_get_perf_counters = unicorn_get_perf_counters;
#else
    provider.direct_self_read_stats_enabled = FALSE;
    provider.unicorn_perf_stats_enabled = FALSE;
    provider.unicorn_enable_perf_counters = NULL;
    provider.unicorn_get_perf_counters = NULL;
#endif
    provider.tb_history_watchdog_started = FALSE;
    provider.tb_history_watchdog_tick = 0;
#endif
    if (!++provider.instance) ++provider.instance;
    provider.poison_status = STATUS_SUCCESS;
    provider.last_fault_kind = MUTATION_NONE;
    provider.last_fault_stage = MUTATION_STAGE_IDLE;
    provider.last_fault_generation = 0;
    provider.shutting_down = FALSE;
    provider.observer_active = FALSE;
    provider.code_observer_active = FALSE;
    provider.observer_transaction = NULL;
    provider.code_observer_transaction = NULL;
    provider.generation = 1;

    kuser.guest = params->guest_kuser;
    kuser.host = params->host_kuser;
    kuser.size = params->kuser_size;
    kuser.allocation_base = params->guest_kuser;
    kuser.perms = UC_PROT_READ;
    kuser.state = MEM_COMMIT;
    kuser.domain = XTAJIT64_MEMORY_ADDRESS_INVALID;
    kuser.flags = 0;
    kuser.permanent = TRUE;
    kuser.stale = FALSE;
    if (!range_array_append( &provider.ranges, &kuser ))
    {
        range_array_free( &provider.ranges );
        munmap( provider.identity_page_flags, provider.identity_page_flags_size );
        provider.identity_page_flags = NULL;
        provider.identity_page_flags_size = 0;
        provider.identity_address_bits = 0;
        pthread_mutex_unlock( &provider.mutex );
        return STATUS_NO_MEMORY;
    }
    provider.initialized = TRUE;
    pthread_mutex_unlock( &provider.mutex );

    status = register_xtajit64_memory_observer();
    if (status)
    {
        process_term( NULL );
        return status;
    }
    pthread_mutex_lock( &provider.mutex );
    if (provider.poison_status) status = provider.poison_status;
    else if (!provider.observer_active || !provider.code_observer_active)
    {
        status = STATUS_INVALID_DEVICE_STATE;
        poison_provider_locked( status );
    }
#ifndef XTAJIT64_UNIXLIB_TEST
    else if ((status = tb_history_start_watchdog_locked()))
    {
        provider.tb_history_enabled = FALSE;
    }
#endif
    else
    {
        params->enabled_capabilities = XTAJIT64_CAPABILITIES;
#ifndef XTAJIT64_UNIXLIB_TEST
        TRACE_(xtajitmap)( "schema 1 initialized\n" );
#endif
        TRACE( "initialized Unicorn %u.%u provider registry, KUSER guest %p host %p, "
               "RtlExitUserThread %p, x64 syscall dispatcher %p count %u\n", major, minor,
               (void *)(uintptr_t)params->guest_kuser,
               (void *)(uintptr_t)params->host_kuser,
               (void *)(uintptr_t)params->rtl_exit_user_thread,
               (void *)(uintptr_t)params->x64_syscall_dispatcher,
               params->x64_syscall_count );
    }
    pthread_mutex_unlock( &provider.mutex );
    if (status)
    {
        process_term( NULL );
        return status;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS process_term( void *args )
{
    struct thread_engine *engine, *next;
#if defined(__APPLE__) && !defined(XTAJIT64_UNIXLIB_TEST)
    struct direct_self_read_diagnostics direct_self_read_diagnostics = {0};
    uint64_t direct_self_read_attempts = 0;
    uint64_t direct_self_read_completions = 0;
    uint64_t direct_self_read_bytes = 0;
    BOOL render_direct_self_read_stats = FALSE;
#endif
#ifndef XTAJIT64_UNIXLIB_TEST
    pthread_t tb_history_watchdog;
    BOOL join_tb_history_watchdog = FALSE;
    char ec_target_stats_report[2048];
    size_t ec_target_stats_report_length = 0;
#endif
    (void)args;
    pthread_mutex_lock( &provider.mutex );
    if (!provider.initialized)
    {
        pthread_mutex_unlock( &provider.mutex );
        return STATUS_SUCCESS;
    }
    while (provider.mutating) pthread_cond_wait( &provider.cond, &provider.mutex );
    provider.mutating = TRUE;
    provider.shutting_down = TRUE;
    ++provider.generation;
    for (engine = provider.engines; engine; engine = engine->next)
        request_engine_pause_locked( engine );
    while (any_engine_running_locked())
        pthread_cond_wait( &provider.cond, &provider.mutex );

    /* A simulation paused for this mutation still owns its engine while it
     * waits to discover the terminal provider state.  Publish that state first,
     * then wait for every borrower to return before closing pooled engines. */
    provider.initialized = FALSE;
    pthread_cond_broadcast( &provider.cond );
    while (any_engine_in_use_locked())
        pthread_cond_wait( &provider.cond, &provider.mutex );

#ifndef XTAJIT64_UNIXLIB_TEST
    if (provider.tb_history_watchdog_started)
    {
        tb_history_watchdog = provider.tb_history_watchdog;
        provider.tb_history_watchdog_started = FALSE;
        join_tb_history_watchdog = TRUE;
    }
    if (join_tb_history_watchdog)
    {
        pthread_mutex_unlock( &provider.mutex );
        pthread_join( tb_history_watchdog, NULL );
        pthread_mutex_lock( &provider.mutex );
    }
    ec_target_stats_report_length = format_ec_transition_target_stats_locked(
        ec_target_stats_report, sizeof(ec_target_stats_report) );
#endif

    for (engine = provider.engines; engine; engine = next)
    {
        next = engine->next;
#if defined(__APPLE__) && !defined(XTAJIT64_UNIXLIB_TEST)
        if (provider.direct_self_read_stats_enabled)
        {
            render_direct_self_read_stats = TRUE;
            merge_direct_self_read_diagnostics( &direct_self_read_diagnostics,
                                                &engine->direct_self_read_diagnostics );
            direct_self_read_add( &direct_self_read_attempts,
                                  engine->direct_self_read_attempts );
            direct_self_read_add( &direct_self_read_completions,
                                  engine->direct_self_read_completions );
            direct_self_read_add( &direct_self_read_bytes,
                                  engine->direct_self_read_bytes );
        }
#endif
        trace_mapping_diagnostic( engine, "final", 0 );
        clear_engine_residency_locked( engine );
        if (engine->uc) uc_close( engine->uc );
        range_array_free( &engine->mapped_ranges );
        free( engine->tb_history );
        free( engine );
    }
#ifndef XTAJIT64_UNIXLIB_TEST
    __wine_release_arm64ec_cpu_alias_v1( cpu_alias_snapshot );
#endif
    cpu_alias_snapshot = NULL;
    provider.engines = NULL;
    provider.engine_count = 0;
    provider.engines_in_use = 0;
    provider.engine_high_water = 0;
    provider.tb_history_enabled = FALSE;
    provider.direct_self_read_stats_enabled = FALSE;
    provider.unicorn_perf_stats_enabled = FALSE;
    provider.ec_target_stats_enabled = FALSE;
    provider.ec_leaf_fastpath_enabled = FALSE;
    provider.ec_leaf_fastpath_stats_enabled = FALSE;
    provider.ec_leaf_fastpath_code_generation = 0;
    provider.unicorn_enable_perf_counters = NULL;
    provider.unicorn_get_perf_counters = NULL;
#ifndef XTAJIT64_UNIXLIB_TEST
    provider.tb_history_watchdog_tick = 0;
#endif
    if (provider.initial_context) uc_context_free( provider.initial_context );
    provider.initial_context = NULL;
    range_array_free( &provider.ranges );
    munmap( provider.identity_page_flags, provider.identity_page_flags_size );
    provider.identity_page_flags = NULL;
    provider.identity_page_flags_size = 0;
    provider.identity_address_bits = 0;
    provider.observer_active = FALSE;
    provider.code_observer_active = FALSE;
    provider.observer_transaction = NULL;
    provider.code_observer_transaction = NULL;
    provider.ec_bitmap = NULL;
    provider.ec_bitmap_word_count = 0;
    provider.ec_page_shift = 0;
    provider.highest_user_address = 0;
    provider.rtl_exit_user_thread = 0;
    provider.rtl_query_performance_counter = 0;
    provider.nt_query_performance_counter = 0;
    provider.x64_syscall_dispatcher = 0;
    provider.x64_syscall_count = 0;
    provider.guest_kuser = 0;
    provider.host_kuser = 0;
    provider.kuser_size = 0;
    provider.poison_status = STATUS_SUCCESS;
    provider.shutting_down = FALSE;
    finish_mutation_locked();
    pthread_mutex_unlock( &provider.mutex );
#ifndef XTAJIT64_UNIXLIB_TEST
    if (ec_target_stats_report_length)
        write_diagnostic_line( ec_target_stats_report, ec_target_stats_report_length );
#endif
#if defined(__APPLE__) && !defined(XTAJIT64_UNIXLIB_TEST)
    if (render_direct_self_read_stats)
        render_direct_self_read_diagnostics( &direct_self_read_diagnostics,
                                             0,
                                             direct_self_read_attempts,
                                             direct_self_read_completions,
                                             direct_self_read_bytes );
#endif
    return STATUS_SUCCESS;
}

static NTSTATUS thread_init( void *args )
{
    struct thread_binding *binding, *current;
    NTSTATUS status = STATUS_SUCCESS;
    uc_err err;
    int ret;

    (void)args;
    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error) return STATUS_NO_MEMORY;
    current = pthread_getspecific( engine_key );
    if (!(binding = calloc( 1, sizeof(*binding) ))) return STATUS_NO_MEMORY;

    pthread_mutex_lock( &provider.mutex );
    while (provider.mutating && provider.initialized)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (!provider.initialized || provider.shutting_down)
        status = STATUS_INVALID_HANDLE;
    else if (provider.poison_status) status = provider.poison_status;
    else if (current && current->process_instance == provider.instance)
        status = STATUS_SUCCESS;
    else if (!provider.engines &&
             (err = create_pool_engine_locked( NULL )) != UC_ERR_OK)
    {
        WARN( "cannot initialize pooled x64 engine: %s\n", uc_strerror( err ) );
        status = STATUS_NOT_SUPPORTED;
    }
    if (!status && (!current || current->process_instance != provider.instance))
    {
        binding->process_instance = provider.instance;
        if (!(binding->id = ++provider.next_binding_id))
            binding->id = ++provider.next_binding_id;
        if ((ret = pthread_setspecific( engine_key, binding )))
            status = ret == ENOMEM ? STATUS_NO_MEMORY : STATUS_UNSUCCESSFUL;
    }
    pthread_mutex_unlock( &provider.mutex );
    if (!status && current && current->process_instance == provider.instance)
        free( binding );
    else if (status) free( binding );
    else if (current) destroy_thread_binding( current );
    return status;
}

static NTSTATUS thread_term( void *args )
{
    struct thread_binding *binding;

    (void)args;
    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error) return STATUS_UNSUCCESSFUL;
    if (!(binding = pthread_getspecific( engine_key ))) return STATUS_SUCCESS;
    if (binding->active) return STATUS_INVALID_DEVICE_STATE;
    pthread_setspecific( engine_key, NULL );
    destroy_thread_binding( binding );
    return STATUS_SUCCESS;
}

static void clear_flight_binding( struct thread_binding *binding )
{
    binding->flight_recorder = NULL;
    binding->flight_causal_boundary_id = 0;
    binding->flight_context_generation = 0;
    binding->flight_transition_generation = 0;
    binding->flight_expected_teb = 0;
    binding->flight_claimed_teb = 0;
    binding->flight_guest_rip = 0;
    binding->flight_guest_rsp = 0;
    binding->flight_guest_stack_limit = 0;
    binding->flight_guest_stack_base = 0;
    binding->flight_control_stack_limit = 0;
    binding->flight_control_stack_top = 0;
    binding->flight_last_context_generation = 0;
    binding->flight_pid = 0;
    binding->flight_mach_thread_id = 0;
    binding->flight_pthread_identity = 0;
}

static NTSTATUS flight_bind( void *args )
{
    const struct xtajit64_flight_bind_params *params = args;
    struct thread_binding *binding;
    const struct mapped_range *range;
    uint64_t offset, published_boundary_id, unix_teb;
    BOOL mode_safe;
    BOOL stale_context_generation = FALSE;
    uint32_t mode, reason, teb_reason = XTAJIT64_FLIGHT_REASON_NONE;
    NTSTATUS status = STATUS_SUCCESS;

    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error || !(binding = pthread_getspecific( engine_key )))
        return STATUS_INVALID_HANDLE;
    if (!params) return STATUS_INVALID_PARAMETER;
    if (!params->recorder)
    {
        /* An unbind also crosses recorder lifetime boundaries.  Keep it under
         * the same lock/instance validation as a non-null bind instead of
         * leaving a stale association visible during provider teardown. */
        pthread_mutex_lock( &provider.mutex );
        while (provider.mutating && provider.initialized)
            pthread_cond_wait( &provider.cond, &provider.mutex );
        if (!provider.initialized || provider.shutting_down ||
            binding->process_instance != provider.instance)
            status = STATUS_INVALID_HANDLE;
        else if (binding->active) status = STATUS_INVALID_DEVICE_STATE;
        else clear_flight_binding( binding );
        pthread_mutex_unlock( &provider.mutex );
        return status;
    }
    if ((params->recorder & 63) || !params->causal_boundary_id ||
        params->recorder > XTAJIT64_X64_USER_ADDRESS_MAX ||
        params->recorder > UINT64_MAX - sizeof(*binding->flight_recorder))
        return STATUS_INVALID_PARAMETER;

    /* This opt-in call validates process lifetime and canonical mapping on
     * every bind.  It deliberately takes the provider mutex rather than
     * relying on a same-pointer fast path across process teardown/reuse. */
    pthread_mutex_lock( &provider.mutex );
    while (provider.mutating && provider.initialized)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (!provider.initialized || provider.shutting_down ||
        binding->process_instance != provider.instance)
        status = STATUS_INVALID_HANDLE;
    else if (binding->active) status = STATUS_INVALID_DEVICE_STATE;
    else if (!(range = find_canonical_mapping( params->recorder,
                                                sizeof(*binding->flight_recorder),
                                                UC_PROT_READ | UC_PROT_WRITE )) ||
             range->domain != XTAJIT64_MEMORY_ADDRESS_IDENTITY ||
             params->recorder < range->guest ||
             (offset = params->recorder - range->guest) > range->size ||
             range->host > UINT64_MAX - offset || range->host + offset != params->recorder)
        status = STATUS_INVALID_ADDRESS;
    else if (!xtajit64_flight_recorder_is_valid(
                 (const struct xtajit64_flight_recorder *)(uintptr_t)params->recorder ))
        status = STATUS_REVISION_MISMATCH;
    else
    {
        if (binding->flight_recorder !=
            (struct xtajit64_flight_recorder *)(uintptr_t)params->recorder)
        {
            binding->flight_last_context_generation = 0;
            /* Diagnostic identity is sampled only after a non-null opt-in
             * binding has passed lifetime/mapping validation. */
            binding->flight_pid = (uint64_t)getpid();
            binding->flight_mach_thread_id = flight_current_mach_thread_id();
            binding->flight_pthread_identity = flight_current_pthread_identity();
        }
        published_boundary_id = xtajit64_flight_current_boundary(
            (const struct xtajit64_flight_recorder *)(uintptr_t)params->recorder );
        stale_context_generation =
            published_boundary_id != params->causal_boundary_id ||
            params->context_generation != params->causal_boundary_id ||
            params->transition_generation != params->causal_boundary_id ||
            (params->context_generation && binding->flight_last_context_generation &&
             params->context_generation <= binding->flight_last_context_generation);
        binding->flight_recorder =
            (struct xtajit64_flight_recorder *)(uintptr_t)params->recorder;
        binding->flight_causal_boundary_id = params->causal_boundary_id;
        binding->flight_context_generation = params->context_generation;
        binding->flight_transition_generation = params->transition_generation;
        /* WINE_UNIX_LIB NtCurrentTeb() is backed by Unix thread data rather
         * than the ARM64EC x18 register.  It is the independent authority for
         * this handshake; never use a fresh PE-side NtCurrentTeb() as both
         * sides of a numeric x18 comparison. */
        unix_teb = (uint64_t)(uintptr_t)NtCurrentTeb();
        teb_reason = xtajit64_flight_validate_pe_x18_claim( params->claimed_teb, unix_teb );
        binding->flight_expected_teb = unix_teb;
        binding->flight_claimed_teb = params->claimed_teb;
        __atomic_store_n( &binding->flight_recorder->authenticated_teb, unix_teb,
                          __ATOMIC_RELEASE );
        binding->flight_guest_rip = params->guest_rip;
        binding->flight_guest_rsp = params->guest_rsp;
        binding->flight_guest_stack_limit = params->guest_stack_limit;
        binding->flight_guest_stack_base = params->guest_stack_base;
        binding->flight_control_stack_limit = params->control_stack_limit;
        binding->flight_control_stack_top = params->control_stack_top;
        if (params->context_generation > binding->flight_last_context_generation)
            binding->flight_last_context_generation = params->context_generation;
    }
    pthread_mutex_unlock( &provider.mutex );
    if (status) return status;

    flight_record_binding_event( binding, XTAJIT64_FLIGHT_EVENT_BINDING,
                                 teb_reason ? teb_reason :
                                 stale_context_generation ?
                                 XTAJIT64_FLIGHT_REASON_CONTEXT_STALE_PUBLICATION :
                                 XTAJIT64_FLIGHT_REASON_NONE );
    if (!xtajit64_flight_recorder_is_active( binding->flight_recorder ))
        return STATUS_SUCCESS;
    /* Native-system validity depends only on the separately queried ABI mode,
     * not on the numeric x18 sample.  Query/validate it before acquiring a
     * payload so scratch exhaustion cannot hide an enabled-mode violation. */
    mode = flight_query_unix_system_x18_mode( &mode_safe );
    reason = xtajit64_flight_validate_x18(
        mode, XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM,
        XTAJIT64_FLIGHT_UNKNOWN_U64, XTAJIT64_FLIGHT_UNKNOWN_U64 );
    {
        struct xtajit64_flight_recorder *recorder = binding->flight_recorder;
        struct xtajit64_flight_scratch *scratch;
        struct xtajit64_flight_event *event;

        if (!(event = xtajit64_flight_acquire_scratch( recorder, &scratch )))
        {
            if (reason && xtajit64_flight_recorder_is_active( recorder ))
                xtajit64_flight_freeze( recorder, reason );
        }
        else
        {
            flight_init_binding_event( event, binding,
                                       XTAJIT64_FLIGHT_EVENT_UNIX_ENTERED_SYSTEM_MODE );
            event->custom_x18_mode = mode;
            event->x18_expectation = XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM;
            if (mode_safe)
                event->flags = (event->flags | XTAJIT64_FLIGHT_FLAG_MODE_QUERY_SAFE) &
                               ~XTAJIT64_FLIGHT_FLAG_EXECUTION_MODE_UNKNOWN;
            event->reason = reason;
            if (reason) xtajit64_flight_record_and_freeze( recorder, event, reason );
            else xtajit64_flight_record( recorder, event );
            xtajit64_flight_release_scratch( scratch );
        }
    }
    return STATUS_SUCCESS;
}

/* Refresh per-transition diagnostic identity from data already crossing the
 * operational BeginSimulation boundary.  flight_bind owns the stable recorder,
 * control-stack, and Unix-authenticated TEB association once per thread; doing
 * another standalone Unix dispatch for every transition is unnecessary and,
 * on the ARM64EC control-stack path, observably perturbs application execution.
 * Must be called with provider.mutex held and an inactive binding. */
static uint32_t refresh_flight_binding_for_begin_locked(
    struct thread_binding *binding, const struct xtajit64_begin_params *params )
{
    struct xtajit64_flight_recorder *recorder;
    const struct mapped_range *range;
    uint64_t address, boundary_id, offset;
    uint32_t reason = XTAJIT64_FLIGHT_REASON_NONE;

    if (!binding || !params || !(recorder = binding->flight_recorder) ||
        !xtajit64_flight_recorder_is_active( recorder ))
        return reason;

    /* The initial bind authenticated this runtime-owned identity mapping.  It
     * may still have crossed a process mapping mutation before this entry, so
     * revalidate it while the provider map is stable before the shared load. */
    address = (uint64_t)(uintptr_t)recorder;
    if ((address & 63) || address > XTAJIT64_X64_USER_ADDRESS_MAX ||
        address > UINT64_MAX - sizeof(*recorder) ||
        !(range = find_canonical_mapping( address, sizeof(*recorder),
                                          UC_PROT_READ | UC_PROT_WRITE )) ||
        range->domain != XTAJIT64_MEMORY_ADDRESS_IDENTITY ||
        address < range->guest || (offset = address - range->guest) > range->size ||
        range->host > UINT64_MAX - offset || range->host + offset != address)
    {
        clear_flight_binding( binding );
        return XTAJIT64_FLIGHT_REASON_RECORDER_INVALID;
    }

    boundary_id = xtajit64_flight_current_boundary( recorder );
    /* Equality is a valid one-transition retry after mapping reconciliation;
     * only a regressing publication violates the monotonic context contract. */
    if (!boundary_id || boundary_id == XTAJIT64_FLIGHT_UNKNOWN_U64 ||
        boundary_id < binding->flight_last_context_generation)
        reason = XTAJIT64_FLIGHT_REASON_CONTEXT_STALE_PUBLICATION;
    else
    {
        binding->flight_causal_boundary_id = boundary_id;
        binding->flight_context_generation = boundary_id;
        binding->flight_transition_generation = boundary_id;
        if (boundary_id > binding->flight_last_context_generation)
            binding->flight_last_context_generation = boundary_id;
    }
    binding->flight_guest_rip = params->context.rip;
    binding->flight_guest_rsp = params->context.rsp;
    binding->flight_guest_stack_limit = params->stack_limit;
    binding->flight_guest_stack_base = params->stack_base;
    return reason;
}

static NTSTATUS memory_map_internal( void *args )
{
    const struct xtajit64_memory_params *params = args;
    struct mapped_range mapping;
    struct range_array replacement = {0}, removals = {0}, additions = {0};
    uint64_t start, end, host_start, host_end;
    volatile NTSTATUS status = STATUS_SUCCESS;
    volatile BOOL faulted = FALSE;
    BOOL report_error = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0;

    if (!params || params->flags || !params->guest || !params->host || !params->size ||
        !params->allocation_base ||
        !align_range( params->guest, params->size, &start, &end ) ||
        !align_range( params->host, params->size, &host_start, &host_end ) ||
        end - start != host_end - host_start ||
        end - 1 > XTAJIT64_X64_USER_ADDRESS_MAX ||
        ((start ^ host_start) & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
        (params->allocation_base & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
        params->allocation_base > start || start != host_start)
        return STATUS_INVALID_PARAMETER;

    mapping.guest = start;
    mapping.host = host_start;
    mapping.size = end - start;
    mapping.allocation_base = params->allocation_base;
    mapping.perms = protection_to_unicorn( params->protect );
    mapping.state = MEM_COMMIT;
    mapping.domain = XTAJIT64_MEMORY_ADDRESS_IDENTITY;
    mapping.flags = 0;
    mapping.permanent = FALSE;
    mapping.stale = FALSE;

    pthread_mutex_lock( &provider.mutex );
    if (legacy_mutation_selects_low_locked( start, end - start ))
        status = STATUS_ACCESS_DENIED;
    else status = claim_mutation_locked( MUTATION_MAP, TRUE );
    if (!status) __TRY
    {
        pause_mutation_engines_locked();
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted && current_thread_owns_mutation_locked())
        status = wait_for_mutation_engines_locked();
    if (!faulted && !status) __TRY
    {
        test_mutation_fault_checkpoint( TEST_MUTATION_FAULT_AFTER_BEGIN );
        if (!status)
            status = build_mapped_registry( &provider.ranges, &mapping, &replacement );
        if (!status) status = overlay_cpu_alias_snapshot( &replacement, cpu_alias_snapshot );
        if (!status)
            status = build_resync_mapping_changes( &provider.ranges, &replacement,
                                                   &removals, &additions );
        if (!status) set_mutation_stage_locked( MUTATION_STAGE_APPLY );
        if (!status)
        {
            struct range_array old = provider.ranges;

            set_mutation_stage_locked( MUTATION_STAGE_PUBLISH );
            status = publish_identity_page_flag_changes_locked( &removals,
                                                                 &additions );
            if (!status)
            {
                provider.ranges = replacement;
                memset( &replacement, 0, sizeof(replacement) );
                range_array_free( &old );
            }
        }
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted)
    {
        report_error = status && status != STATUS_ACCESS_DENIED && provider.initialized;
        if (report_error) poison_provider_locked( status );
        if (current_thread_owns_mutation_locked()) finish_mutation_locked();
    }
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    pthread_mutex_unlock( &provider.mutex );
    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    else
    {
        if (report_error)
            WARN( "cannot map guest %p size %#llx: status %#x\n",
                  (void *)(uintptr_t)start, (unsigned long long)(end - start),
                  (unsigned int)status );
        range_array_free( &removals );
        range_array_free( &additions );
        range_array_free( &replacement );
    }
    return status;
}

static NTSTATUS memory_map( void *args )
{
    return memory_map_internal( args );
}

static BOOL legacy_mutation_selects_low_locked( uint64_t address, uint64_t size )
{
    uint64_t end = size ? address + size : 0;
    size_t i;

    for (i = 0; i < provider.ranges.count; ++i)
    {
        const struct mapped_range *range = &provider.ranges.data[i];
        uint64_t host_end, host_allocation_base;

        if (range->domain != XTAJIT64_MEMORY_ADDRESS_AMD64_LOW) continue;
        if (size)
        {
            if (range_overlaps( range, address, end )) return TRUE;
            host_end = range->host + range->size;
            if (range->host < end && address < host_end) return TRUE;
        }
        else
        {
            host_allocation_base = range->allocation_base + WINE_LOW_VA_SHADOW_BASE;
            if (range->allocation_base == address || host_allocation_base == address)
                return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS memory_unmap( void *args )
{
    const struct xtajit64_memory_params *params = args;
    struct range_array replacement = {0}, removals = {0}, additions = {0};
    uint64_t guest = 0, size = 0;
    volatile NTSTATUS status = STATUS_SUCCESS;
    volatile BOOL faulted = FALSE;
    BOOL report_error = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0;

    if (!params || (params->flags & ~XTAJIT64_MEMORY_VALID_FLAGS) ||
        !params->guest || params->guest > XTAJIT64_X64_USER_ADDRESS_MAX)
        return STATUS_INVALID_PARAMETER;
    if (params->size)
    {
        uint64_t end;

        if (!align_range( params->guest, params->size, &guest, &end ))
            return STATUS_INVALID_PARAMETER;
        if (end - 1 > XTAJIT64_X64_USER_ADDRESS_MAX)
            return STATUS_INVALID_PARAMETER;
        size = end - guest;
    }
    else
    {
        guest = align_down( params->guest );
        size = 0;
    }

    pthread_mutex_lock( &provider.mutex );
    if (legacy_mutation_selects_low_locked( guest, size ))
        status = STATUS_ACCESS_DENIED;
    else status = claim_mutation_locked( MUTATION_UNMAP, TRUE );
    if (!status) __TRY
    {
        pause_mutation_engines_locked();
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted && current_thread_owns_mutation_locked())
        status = wait_for_mutation_engines_locked();
    if (!faulted && !status) __TRY
    {
        test_mutation_fault_checkpoint( TEST_MUTATION_FAULT_AFTER_BEGIN );
        if (!status)
            status = build_unmapped_registry( &provider.ranges, guest, size, guest, &replacement );
        if (!status)
            status = build_resync_mapping_changes( &provider.ranges, &replacement,
                                                   &removals, &additions );
        if (!status) set_mutation_stage_locked( MUTATION_STAGE_APPLY );
        if (!status)
        {
            struct range_array old = provider.ranges;

            set_mutation_stage_locked( MUTATION_STAGE_PUBLISH );
            status = publish_identity_page_flag_changes_locked( &removals,
                                                                 &additions );
            if (!status)
            {
                mark_engine_mappings_stale_locked( guest, size, guest );
                provider.ranges = replacement;
                memset( &replacement, 0, sizeof(replacement) );
                range_array_free( &old );
            }
        }
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted)
    {
        report_error = status && status != STATUS_ACCESS_DENIED && provider.initialized;
        if (report_error) poison_provider_locked( status );
        if (current_thread_owns_mutation_locked()) finish_mutation_locked();
    }
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    pthread_mutex_unlock( &provider.mutex );
    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    else
    {
        if (report_error)
            WARN( "cannot unmap guest %p size %#llx: status %#x\n",
                  (void *)(uintptr_t)guest, (unsigned long long)size,
                  (unsigned int)status );
        range_array_free( &removals );
        range_array_free( &additions );
        range_array_free( &replacement );
    }
    return status;
}

static NTSTATUS memory_protect( void *args )
{
    const struct xtajit64_memory_params *params = args;
    struct range_array replacement = {0}, removals = {0}, additions = {0};
    uint64_t start = 0, end = 0;
    unsigned int perms;
    volatile NTSTATUS status = STATUS_SUCCESS;
    volatile BOOL faulted = FALSE;
    BOOL report_error = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0;

    if (!params || (params->flags & ~XTAJIT64_MEMORY_VALID_FLAGS) ||
        !params->guest || !params->size)
        return STATUS_INVALID_PARAMETER;
    if (!align_range( params->guest, params->size, &start, &end ))
        return STATUS_INVALID_PARAMETER;
    if (end - 1 > XTAJIT64_X64_USER_ADDRESS_MAX)
        return STATUS_INVALID_PARAMETER;
    perms = protection_to_unicorn( params->protect );

    pthread_mutex_lock( &provider.mutex );
    if (legacy_mutation_selects_low_locked( start, end - start ))
        status = STATUS_ACCESS_DENIED;
    else status = claim_mutation_locked( MUTATION_PROTECT, TRUE );
    if (!status) __TRY
    {
        pause_mutation_engines_locked();
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted && current_thread_owns_mutation_locked())
        status = wait_for_mutation_engines_locked();
    if (!faulted && !status) __TRY
    {
        test_mutation_fault_checkpoint( TEST_MUTATION_FAULT_AFTER_BEGIN );
        if (!status && !registry_covers_range( &provider.ranges, start, end ))
            status = STATUS_INVALID_ADDRESS;
        if (!status)
            status = build_protected_registry( &provider.ranges, start, end, perms,
                                               &replacement );
        if (!status)
            status = build_resync_mapping_changes( &provider.ranges, &replacement,
                                                   &removals, &additions );
        if (!status) set_mutation_stage_locked( MUTATION_STAGE_APPLY );
        if (!status)
        {
            struct range_array old = provider.ranges;

            set_mutation_stage_locked( MUTATION_STAGE_PUBLISH );
            status = publish_identity_page_flag_changes_locked( &removals,
                                                                 &additions );
            if (!status)
            {
                provider.ranges = replacement;
                memset( &replacement, 0, sizeof(replacement) );
                range_array_free( &old );
            }
        }
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted)
    {
        report_error = status && status != STATUS_ACCESS_DENIED && provider.initialized;
        if (report_error) poison_provider_locked( status );
        if (current_thread_owns_mutation_locked()) finish_mutation_locked();
    }
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    pthread_mutex_unlock( &provider.mutex );
    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    else
    {
        if (report_error)
            WARN( "cannot protect guest %p-%p: status %#x\n",
                  (void *)(uintptr_t)start, (void *)(uintptr_t)end,
                  (unsigned int)status );
        range_array_free( &removals );
        range_array_free( &additions );
        range_array_free( &replacement );
    }
    return status;
}

static int compare_memory_params( const void *left, const void *right )
{
    const struct xtajit64_memory_params *a = left, *b = right;

    if (a->guest < b->guest) return -1;
    if (a->guest > b->guest) return 1;
    if (a->size < b->size) return -1;
    if (a->size > b->size) return 1;
    return 0;
}

static NTSTATUS memory_snapshot_lock( void *args )
{
#ifdef XTAJIT64_UNIXLIB_TEST
    return STATUS_SUCCESS;
#else
    return __wine_lock_arm64ec_mapping_snapshot_v1();
#endif
}

static NTSTATUS memory_snapshot_unlock( void *args )
{
#ifdef XTAJIT64_UNIXLIB_TEST
    return STATUS_SUCCESS;
#else
    return __wine_unlock_arm64ec_mapping_snapshot_v1();
#endif
}

static NTSTATUS memory_resync_begin( void *args )
{
    struct xtajit64_memory_resync_begin_params *params = args;
    NTSTATUS status = STATUS_SUCCESS;

    /* The PE side must inspect the host address space without holding this
     * mutex.  Its commit is accepted only if no incremental notification has
     * advanced the canonical generation while that snapshot was collected. */
    if (!params) return STATUS_INVALID_PARAMETER;
    pthread_mutex_lock( &provider.mutex );
    while (provider.mutating && provider.initialized)
    {
#ifdef XTAJIT64_UNIXLIB_TEST
        atomic_fetch_add_explicit( &test_mutation_waiters, 1, memory_order_release );
#endif
        pthread_cond_wait( &provider.cond, &provider.mutex );
#ifdef XTAJIT64_UNIXLIB_TEST
        atomic_fetch_sub_explicit( &test_mutation_waiters, 1, memory_order_release );
#endif
    }
    if (!provider.initialized || provider.shutting_down) status = STATUS_INVALID_HANDLE;
    else if (provider.poison_status) status = provider.poison_status;
    else params->generation = provider.generation;
    pthread_mutex_unlock( &provider.mutex );
    return status;
}

static NTSTATUS build_resync_registry( const struct xtajit64_memory_resync_params *params,
                                       struct range_array *result )
{
    const struct xtajit64_memory_params *input;
    struct xtajit64_memory_params *copy = NULL;
    struct mapped_range kuser, range;
    struct range_array retained = {0}, merged = {0};
    uint64_t start, end, host_start, host_end, previous_end = 0;
    size_t i;
    BOOL inserted_kuser = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (!params || params->reserved || params->count > XTAJIT64_MAX_RESYNC_RANGES ||
        (params->count && !params->ranges))
        return STATUS_INVALID_PARAMETER;
    input = (const struct xtajit64_memory_params *)(uintptr_t)params->ranges;
    if (params->count)
    {
        if (!(copy = malloc( params->count * sizeof(*copy) )))
            return STATUS_NO_MEMORY;
        memcpy( copy, input, params->count * sizeof(*copy) );
        qsort( copy, params->count, sizeof(*copy), compare_memory_params );
    }

    kuser.guest = provider.guest_kuser;
    kuser.host = provider.host_kuser;
    kuser.size = provider.kuser_size;
    kuser.allocation_base = provider.guest_kuser;
    kuser.perms = UC_PROT_READ;
    kuser.state = MEM_COMMIT;
    kuser.domain = XTAJIT64_MEMORY_ADDRESS_INVALID;
    kuser.flags = 0;
    kuser.permanent = TRUE;
    kuser.stale = FALSE;
    if (!range_array_reserve( result, params->count + 1 ))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    for (i = 0; i < params->count; ++i)
    {
        if (!copy[i].guest || !copy[i].host || !copy[i].size ||
            !copy[i].allocation_base || copy[i].flags ||
            !align_range( copy[i].guest, copy[i].size, &start, &end ) ||
            !align_range( copy[i].host, copy[i].size, &host_start, &host_end ) ||
            end - start != host_end - host_start ||
            end - 1 > provider.highest_user_address ||
            start != host_start ||
            ((start ^ host_start) & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
            (copy[i].allocation_base & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
            copy[i].allocation_base > start ||
            start < previous_end)
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
        if (start < kuser.guest + kuser.size && kuser.guest < end)
        {
            status = STATUS_ACCESS_DENIED;
            goto done;
        }
        if (!inserted_kuser && start > kuser.guest)
        {
            if (!range_array_append( result, &kuser ))
            {
                status = STATUS_NO_MEMORY;
                goto done;
            }
            inserted_kuser = TRUE;
        }
        range.guest = start;
        range.host = host_start;
        range.size = end - start;
        range.allocation_base = copy[i].allocation_base;
        range.perms = protection_to_unicorn( copy[i].protect );
        range.state = MEM_COMMIT;
        range.domain = XTAJIT64_MEMORY_ADDRESS_IDENTITY;
        range.flags = 0;
        range.permanent = FALSE;
        range.stale = FALSE;
        if (!range_array_append( result, &range ))
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
        previous_end = end;
    }
    if (!inserted_kuser && !range_array_append( result, &kuser )) status = STATUS_NO_MEMORY;
    if (status) goto done;

    if (!range_array_reserve( &retained, provider.ranges.count ))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }
    for (i = 0; i < provider.ranges.count; ++i)
    {
        const struct mapped_range *old = &provider.ranges.data[i];

        if (old->domain != XTAJIT64_MEMORY_ADDRESS_AMD64_LOW) continue;
        if (!range_array_append( &retained, old ))
        {
            status = STATUS_INVALID_ADDRESS;
            goto done;
        }
    }
    if ((status = merge_range_arrays( result, &retained, &merged ))) goto done;
    range_array_free( result );
    *result = merged;
    memset( &merged, 0, sizeof(merged) );

done:
    if (!status) status = overlay_cpu_alias_snapshot( result, cpu_alias_snapshot );
    free( copy );
    range_array_free( &retained );
    range_array_free( &merged );
    return status;
}

static BOOL ranges_have_same_engine_mapping( const struct mapped_range *left,
                                             const struct mapped_range *right,
                                             uint64_t guest )
{
    uint64_t left_offset, right_offset;

    if (guest < left->guest || guest < right->guest) return FALSE;
    left_offset = guest - left->guest;
    right_offset = guest - right->guest;
    return left->state == MEM_COMMIT && right->state == MEM_COMMIT &&
           left->perms == right->perms && left->flags == right->flags &&
           left->host <= UINT64_MAX - left_offset &&
           right->host <= UINT64_MAX - right_offset &&
           left->host + left_offset == right->host + right_offset;
}

static NTSTATUS append_resync_mapping_changes( const struct range_array *source,
                                                const struct range_array *reference,
                                                struct range_array *changes )
{
    size_t i, reference_index = 0;

    if (source->count > SIZE_MAX - reference->count ||
        !range_array_reserve( changes, source->count + reference->count ))
        return STATUS_NO_MEMORY;
    for (i = 0; i < source->count; ++i)
    {
        const struct mapped_range *range = &source->data[i];
        uint64_t cursor, end;
        size_t j;

        if (range->state != MEM_COMMIT) continue;
        cursor = range->guest;
        end = cursor + range->size;
        while (reference_index < reference->count &&
               reference->data[reference_index].guest +
                   reference->data[reference_index].size <= cursor)
            ++reference_index;
        j = reference_index;
        while (cursor < end)
        {
            const struct mapped_range *other;
            struct mapped_range slice;
            uint64_t next;

            while (j < reference->count &&
                   reference->data[j].guest + reference->data[j].size <= cursor)
                ++j;
            if (j == reference->count || reference->data[j].guest >= end)
                next = end;
            else if (reference->data[j].guest > cursor)
                next = min( end, reference->data[j].guest );
            else
            {
                other = &reference->data[j];
                next = min( end, other->guest + other->size );
                if (ranges_have_same_engine_mapping( range, other, cursor ))
                {
                    cursor = next;
                    continue;
                }
            }
            slice = range_slice( range, cursor, next );
            if (!range_array_append( changes, &slice ))
                return STATUS_INVALID_ADDRESS;
            cursor = next;
        }
        reference_index = j;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS build_resync_mapping_changes( const struct range_array *old,
                                               const struct range_array *replacement,
                                               struct range_array *removals,
                                               struct range_array *additions )
{
    NTSTATUS status;

    if ((status = append_resync_mapping_changes( old, replacement, removals )))
        return status;
    return append_resync_mapping_changes( replacement, old, additions );
}

static uc_err synchronize_engine_registry_locked( struct thread_engine *engine )
{
    struct range_array retained = {0}, old;
    size_t i;
    uc_err err = UC_ERR_OK;

    if (engine->mapping_generation == provider.generation) return UC_ERR_OK;
    ++engine->registry_sync_calls;
    if (!range_array_reserve( &retained, engine->mapped_ranges.count ))
        return UC_ERR_NOMEM;

    for (i = 0; i < engine->mapped_ranges.count; ++i)
    {
        const struct mapped_range *mapped = &engine->mapped_ranges.data[i];
        const struct mapped_range *canonical =
            find_canonical_mapping( mapped->guest, mapped->size, mapped->perms );
        uint64_t offset = canonical ? mapped->guest - canonical->guest : 0;

        if (!mapped->stale && canonical &&
            canonical->host <= UINT64_MAX - offset &&
            canonical->host + offset == mapped->host &&
            canonical->allocation_base == mapped->allocation_base &&
            canonical->perms == mapped->perms &&
            canonical->state == mapped->state &&
            canonical->domain == mapped->domain &&
            canonical->flags == mapped->flags &&
            canonical->permanent == mapped->permanent)
        {
            if (!range_array_append( &retained, mapped ))
            {
                err = UC_ERR_ARG;
                goto done;
            }
            continue;
        }
        if ((err = unmap_range( engine, mapped->guest, mapped->size )) != UC_ERR_OK)
            goto done;
        /* uc_mem_unmap() invalidates translated blocks and TLB entries for
         * every affected mapped region.  A full-engine flush here would
         * discard unrelated translations on every generation change. */
        ++engine->resync_unmap_calls;
        engine->resync_unmap_bytes += mapped->size;
    }

    old = engine->mapped_ranges;
    engine->mapped_ranges = retained;
    memset( &retained, 0, sizeof(retained) );
    range_array_free( &old );
    engine->mapping_generation = provider.generation;
    if (engine->flight_recorder)
        flight_record_engine_event( engine, XTAJIT64_FLIGHT_EVENT_MAPPING_GENERATION,
                                    XTAJIT64_FLIGHT_REASON_NONE,
                                    XTAJIT64_FLIGHT_UNKNOWN_U32,
                                    XTAJIT64_FLIGHT_UNKNOWN_U64,
                                    XTAJIT64_FLIGHT_UNKNOWN_U64 );
    if (!(engine->registry_sync_calls & (engine->registry_sync_calls - 1)))
        trace_mapping_diagnostic( engine, "sync", 0 );

done:
    range_array_free( &retained );
    return err;
}

static NTSTATUS memory_resync( void *args )
{
    const struct xtajit64_memory_resync_params *params = args;
    struct range_array replacement = {0}, removals = {0}, additions = {0};
    volatile NTSTATUS status = STATUS_SUCCESS;
    volatile BOOL faulted = FALSE;
    BOOL report_error = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0;
    uint64_t completed_generation = 0;
    size_t completed_range_count = 0;
    size_t completed_removal_count = 0, completed_addition_count = 0;

    pthread_mutex_lock( &provider.mutex );
    while (provider.mutating && provider.initialized)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (!params) status = STATUS_INVALID_PARAMETER;
    else if (!provider.initialized || provider.shutting_down) status = STATUS_INVALID_HANDLE;
    else if (provider.poison_status) status = provider.poison_status;
    else if (params->generation != provider.generation) status = STATUS_RETRY;
    else status = claim_mutation_locked( MUTATION_RESYNC, TRUE );
    if (!status) __TRY
    {
        pause_mutation_engines_locked();
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted && current_thread_owns_mutation_locked())
        status = wait_for_mutation_engines_locked();
    if (!faulted && !status) __TRY
    {
        test_mutation_fault_checkpoint( TEST_MUTATION_FAULT_AFTER_BEGIN );
        if (!status) status = build_resync_registry( params, &replacement );
        if (!status)
            status = build_resync_mapping_changes( &provider.ranges, &replacement,
                                                   &removals, &additions );
        if (!status) set_mutation_stage_locked( MUTATION_STAGE_APPLY );
        if (!status)
        {
            struct range_array old = provider.ranges;
            size_t i;

            set_mutation_stage_locked( MUTATION_STAGE_PUBLISH );
            status = publish_identity_page_flag_changes_locked( &removals,
                                                                 &additions );
            if (!status)
            {
                for (i = 0; i < removals.count; ++i)
                    mark_engine_mappings_stale_locked( removals.data[i].guest,
                                                       removals.data[i].size, 0 );
                provider.ranges = replacement;
                memset( &replacement, 0, sizeof(replacement) );
                range_array_free( &old );
            }
        }
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted)
    {
        report_error = status && provider.initialized && status != STATUS_RETRY;
        if (report_error) poison_provider_locked( status );
        if (!status)
        {
            completed_range_count = provider.ranges.count;
            completed_generation = provider.generation;
            completed_removal_count = removals.count;
            completed_addition_count = additions.count;
        }
        if (current_thread_owns_mutation_locked()) finish_mutation_locked();
    }
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    pthread_mutex_unlock( &provider.mutex );
    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    else
    {
        if (report_error)
            WARN( "cannot authoritatively resynchronize x64 mappings: status %#x\n",
                  (unsigned int)status );
        range_array_free( &removals );
        range_array_free( &additions );
        range_array_free( &replacement );
        if (!status)
            TRACE( "resynchronized %zu canonical x64 mapping ranges with %zu removals and "
                   "%zu additions across generation %llu\n", completed_range_count,
                   completed_removal_count, completed_addition_count,
                   (unsigned long long)completed_generation );
    }
    return status;
}

struct flush_interval
{
    uint64_t start;
    uint64_t end;
};

struct flush_interval_array
{
    struct flush_interval *data;
    size_t count;
    size_t capacity;
};

static int compare_flush_interval( const void *left, const void *right )
{
    const struct flush_interval *a = left, *b = right;

    if (a->start < b->start) return -1;
    if (a->start > b->start) return 1;
    if (a->end < b->end) return -1;
    if (a->end > b->end) return 1;
    return 0;
}

static NTSTATUS normalize_flush_intervals( struct flush_interval_array *array )
{
    size_t i, out = 0;

    if (array->count < 2) return STATUS_SUCCESS;
    qsort( array->data, array->count, sizeof(*array->data), compare_flush_interval );
    for (i = 0; i < array->count; ++i)
    {
        if (out && array->data[i].start <= array->data[out - 1].end)
        {
            if (array->data[i].end > array->data[out - 1].end)
                array->data[out - 1].end = array->data[i].end;
        }
        else array->data[out++] = array->data[i];
    }
    array->count = out;
    return STATUS_SUCCESS;
}

static NTSTATUS append_flush_interval( struct flush_interval_array *array,
                                       uint64_t start, uint64_t end )
{
    struct flush_interval *data;
    size_t capacity;

    if (start >= end) return STATUS_SUCCESS;
#ifdef XTAJIT64_UNIXLIB_TEST
    if (test_fail_flush_interval_append >= 0 &&
        test_flush_interval_append_count++ == test_fail_flush_interval_append)
        return STATUS_NO_MEMORY;
#endif
    if (array->count == array->capacity)
    {
        capacity = array->capacity ? array->capacity * 2 : 16;
        if (capacity < array->capacity || capacity > SIZE_MAX / sizeof(*data))
            return STATUS_NO_MEMORY;
        if (!(data = realloc( array->data, capacity * sizeof(*data) )))
            return STATUS_NO_MEMORY;
        array->data = data;
        array->capacity = capacity;
    }
    array->data[array->count].start = start;
    array->data[array->count].end = end;
    ++array->count;
    return STATUS_SUCCESS;
}

static NTSTATUS collect_flush_intervals_locked(
    uint64_t address, uint64_t size, BOOL host_domain,
    struct flush_interval_array *result )
{
    uint64_t end = address + size;
    size_t i;
    NTSTATUS status;

    for (i = 0; i < provider.ranges.count; ++i)
    {
        const struct mapped_range *range = &provider.ranges.data[i];
        uint64_t range_start, range_end, overlap_start, overlap_end, guest_start;

        if (range->state != MEM_COMMIT) continue;
        range_start = host_domain ? range->host : range->guest;
        if (range_start > UINT64_MAX - range->size) return STATUS_INVALID_ADDRESS;
        range_end = range_start + range->size;
        if (range_end <= address || range_start >= end) continue;
        overlap_start = max( address, range_start );
        overlap_end = min( end, range_end );
        if (range->guest > UINT64_MAX - (overlap_start - range_start))
            return STATUS_INVALID_ADDRESS;
        guest_start = range->guest + overlap_start - range_start;
        status = append_flush_interval( result, guest_start,
                                        guest_start + overlap_end - overlap_start );
        if (status) return status;
    }
    return normalize_flush_intervals( result );
}

static BOOL flush_intervals_equal( const struct flush_interval_array *left,
                                   const struct flush_interval_array *right )
{
    size_t i;

    if (left->count != right->count) return FALSE;
    for (i = 0; i < left->count; ++i)
        if (left->data[i].start != right->data[i].start ||
            left->data[i].end != right->data[i].end)
            return FALSE;
    return TRUE;
}

static NTSTATUS flush_instruction_cache( void *args )
{
    const struct xtajit64_memory_params *params = args;
    struct flush_interval_array guest_intervals = {0}, host_intervals = {0};
    const struct flush_interval_array *intervals = NULL;
    struct thread_engine *engine;
    BOOL full_flush;
    volatile BOOL barrier_started = FALSE;
    volatile NTSTATUS status = STATUS_SUCCESS;
    volatile BOOL faulted = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0;
    uc_err err = UC_ERR_OK;
    size_t i;

    if (params && (params->flags || params->host || params->allocation_base ||
                   params->protect ||
                   (params->guest && params->guest > UINT64_MAX - params->size)))
        return STATUS_INVALID_PARAMETER;
    /* Windows ignores the region size when the base is NULL.  Preserve the
     * original size across the PE callback while treating every NULL-base
     * form as a provider-wide flush. */
    full_flush = !params || !params->guest;

    /* FlushInstructionCache accepts a non-NULL address with a zero length.
     * It is an exact empty interval, not the NULL/zero whole-cache sentinel. */
    if (params && params->guest && !params->size) return STATUS_SUCCESS;

    pthread_mutex_lock( &provider.mutex );
    status = claim_mutation_locked( MUTATION_FLUSH, FALSE );
    if (!status && !full_flush)
    {
#ifdef XTAJIT64_UNIXLIB_TEST
        test_flush_interval_append_count = 0;
#endif
        status = collect_flush_intervals_locked( params->guest, params->size,
                                                  FALSE, &guest_intervals );
        if (!status)
            status = collect_flush_intervals_locked( params->guest, params->size,
                                                      TRUE, &host_intervals );
        if (!status && guest_intervals.count && host_intervals.count &&
            !flush_intervals_equal( &guest_intervals, &host_intervals ))
            full_flush = TRUE;
        else if (!status)
            intervals = guest_intervals.count ? &guest_intervals : &host_intervals;
    }
    if (!status) __TRY
    {
        pause_mutation_engines_locked();
        barrier_started = TRUE;
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted && !status && barrier_started &&
        current_thread_owns_mutation_locked())
        status = wait_for_mutation_engines_locked();
    if (!faulted && !status) __TRY
    {
        test_mutation_fault_checkpoint( TEST_MUTATION_FAULT_AFTER_BEGIN );
        set_mutation_stage_locked( MUTATION_STAGE_APPLY );
        for (engine = provider.engines; engine; engine = engine->next)
        {
            if (full_flush) err = uc_ctl_flush_tb( engine->uc );
            else if (intervals)
            {
                /* Unicorn resolves targeted TB invalidations through the
                 * engine's software TLB.  A pooled engine may retain a TLB
                 * entry across an unmap/remap generation even when the final
                 * canonical host mapping is byte-for-byte identical. */
                err = uc_ctl_flush_tlb( engine->uc );
                for (i = 0; i < intervals->count; ++i)
                {
                    if (err != UC_ERR_OK) break;
                    if ((err = uc_ctl_remove_cache( engine->uc,
                                                    intervals->data[i].start,
                                                    intervals->data[i].end )) != UC_ERR_OK)
                        break;
                }
            }
            if (err != UC_ERR_OK)
            {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
    __EXCEPT
    {
        status = recover_mutation_access_violation_locked();
        faulted = TRUE;
    }
    __ENDTRY
    if (!faulted)
    {
        if (!status) advance_ec_leaf_fastpath_code_generation_locked();
        /* Once engine quiescence has begun, a failed invalidation cannot prove
         * that every engine discarded the requested code.  Preflight failures
         * happen before any pause request or cache operation and are safe for
         * the caller to retry. */
        if (status && barrier_started && provider.initialized)
            poison_provider_locked( status );
        if (current_thread_owns_mutation_locked()) finish_mutation_locked();
    }
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    pthread_mutex_unlock( &provider.mutex );
    free( guest_intervals.data );
    free( host_intervals.data );
    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    return status;
}

static NTSTATUS poison( void *args )
{
    const struct xtajit64_poison_params *params = args;
    struct thread_engine *engine;
    volatile NTSTATUS status = params && params->status ?
                               params->status : STATUS_UNSUCCESSFUL;
    volatile BOOL faulted = FALSE;
    enum mutation_kind fault_kind = MUTATION_NONE;
    enum mutation_stage fault_stage = MUTATION_STAGE_IDLE;
    uint64_t fault_generation = 0;

    pthread_mutex_lock( &provider.mutex );
    if (!provider.initialized) status = STATUS_INVALID_HANDLE;
    else
    {
        poison_provider_locked( status );
        __TRY
        {
            for (engine = provider.engines; engine; engine = engine->next)
                request_engine_pause_locked( engine );
        }
        __EXCEPT
        {
            status = record_mutation_access_violation_locked( MUTATION_POISON,
                                                              MUTATION_STAGE_PAUSE,
                                                              provider.generation );
            faulted = TRUE;
        }
        __ENDTRY
        if (!faulted) status = provider.poison_status;
        pthread_cond_broadcast( &provider.cond );
    }
    if (faulted)
    {
        fault_kind = provider.last_fault_kind;
        fault_stage = provider.last_fault_stage;
        fault_generation = provider.last_fault_generation;
    }
    pthread_mutex_unlock( &provider.mutex );
    if (faulted)
        report_mutation_access_violation( fault_kind, fault_stage, fault_generation );
    return status;
}

static NTSTATUS begin_simulation( void *args )
{
    struct xtajit64_begin_params *params = args;
    struct thread_binding *binding;
    struct thread_engine *engine = NULL;
    volatile uint32_t *suspend_doorbell = NULL;
    uint64_t doorbell_host, doorbell_allocation;
    uint64_t boundary_address = 0;
    unsigned int doorbell_domain;
    uc_err err = UC_ERR_OK, read_err = UC_ERR_OK, context_err = UC_ERR_OK;
    uc_err boundary_err = UC_ERR_OK;
    uc_x64_boundary_stop_reason boundary_reason = UC_X64_BOUNDARY_STOP_NONE;
    NTSTATUS status = STATUS_SUCCESS;
    uint64_t next_rip;
    uint32_t flight_reason;
    BOOL resume, reentering = FALSE;
#ifndef XTAJIT64_UNIXLIB_TEST
    BOOL ec_target_stats_report = FALSE;
#endif

    if (!params || params->reserved || !params->context.rip ||
        params->context.rip > XTAJIT64_X64_USER_ADDRESS_MAX ||
        !params->context.rsp ||
        params->context.rsp < params->stack_limit ||
        params->context.rsp >= params->stack_base ||
        params->stack_base > XTAJIT64_X64_USER_ADDRESS_MAX + 1 ||
        !params->gs_base ||
        params->gs_base > XTAJIT64_X64_USER_ADDRESS_MAX ||
        params->gs_base > UINT64_MAX - XTAJIT64_TEB_SELF_END ||
        !params->suspend_doorbell ||
        (params->suspend_doorbell & (sizeof(uint32_t) - 1)) ||
        params->stack_limit >= params->stack_base)
        return STATUS_INVALID_PARAMETER;
    pthread_once( &engine_key_once, make_engine_key );
    if (engine_key_error || !(binding = pthread_getspecific( engine_key )))
        return STATUS_INVALID_HANDLE;

    pthread_mutex_lock( &provider.mutex );
    while (provider.mutating && provider.initialized)
        pthread_cond_wait( &provider.cond, &provider.mutex );
    if (!provider.initialized || provider.shutting_down ||
        binding->process_instance != provider.instance)
        status = STATUS_INVALID_HANDLE;
    else if (provider.poison_status) status = provider.poison_status;
    else if (binding->active) status = STATUS_INVALID_DEVICE_STATE;
    else if (!translate_guest_range_locked(
                 params->suspend_doorbell, sizeof(uint32_t),
                 UC_PROT_READ | UC_PROT_WRITE, &doorbell_host,
                 &doorbell_allocation, &doorbell_domain ) ||
             doorbell_host != params->suspend_doorbell ||
             doorbell_domain != XTAJIT64_MEMORY_ADDRESS_IDENTITY)
        status = STATUS_INVALID_ADDRESS;
    else if (*(suspend_doorbell =
                   (volatile uint32_t *)(uintptr_t)doorbell_host))
    {
        params->transition_target = 0;
        params->fault_address = 0;
        params->fault_access = EXCEPTION_READ_FAULT;
        params->stop_reason = XTAJIT64_STOP_SUSPEND;
        params->unicorn_error = UC_ERR_OK;
    }
    else
    {
        if (binding->flight_recorder)
        {
            flight_reason = refresh_flight_binding_for_begin_locked( binding, params );
            if (flight_reason)
                flight_record_binding_event( binding,
                                             XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION,
                                             flight_reason );
        }
        if ((err = acquire_pool_engine_locked( binding, &engine )) != UC_ERR_OK)
            status = err == UC_ERR_NOMEM ? STATUS_NO_MEMORY : STATUS_UNSUCCESSFUL;
    }
    if (!status && !engine)
    {
        pthread_mutex_unlock( &provider.mutex );
        return STATUS_SUCCESS;
    }
    if (status)
    {
        params->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
        params->unicorn_error = err;
        pthread_mutex_unlock( &provider.mutex );
        return status;
    }
    pthread_mutex_unlock( &provider.mutex );

    do
    {
        resume = FALSE;
        pthread_mutex_lock( &provider.mutex );
        while (provider.mutating && provider.initialized)
            pthread_cond_wait( &provider.cond, &provider.mutex );
        if (!provider.initialized || !engine->uc || !engine->linked)
            status = STATUS_INVALID_HANDLE;
        else if (provider.poison_status) status = provider.poison_status;
        else if (!engine->in_use || !binding->active)
            status = STATUS_INVALID_DEVICE_STATE;
        else if (!translate_guest_range_locked(
                     params->suspend_doorbell, sizeof(uint32_t),
                     UC_PROT_READ | UC_PROT_WRITE, &doorbell_host,
                     &doorbell_allocation, &doorbell_domain ) ||
                 doorbell_host != params->suspend_doorbell ||
                 doorbell_domain != XTAJIT64_MEMORY_ADDRESS_IDENTITY)
            status = STATUS_INVALID_ADDRESS;
        else if (!registry_covers_readable_range( &provider.ranges, params->gs_base,
                                                   params->gs_base +
                                                   XTAJIT64_TEB_SELF_END ))
            status = STATUS_INVALID_ADDRESS;
        else if ((err = synchronize_engine_registry_locked( engine )) != UC_ERR_OK)
        {
            status = STATUS_UNSUCCESSFUL;
            poison_provider_locked( status );
        }
        else if ((err = write_context( engine, &params->context,
                                       params->gs_base )) != UC_ERR_OK)
        {
            status = STATUS_UNSUCCESSFUL;
            poison_provider_locked( status );
        }
        if (status)
        {
            params->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
            params->unicorn_error = err;
            release_pool_engine_locked( binding, engine, FALSE );
            pthread_mutex_unlock( &provider.mutex );
            return status;
        }

        suspend_doorbell = (volatile uint32_t *)(uintptr_t)doorbell_host;
        if ((err = uc_update_x64_boundary_suspend_doorbell(
                 engine->uc, suspend_doorbell )) != UC_ERR_OK)
        {
            status = STATUS_UNSUCCESSFUL;
            poison_provider_locked( status );
            params->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
            params->unicorn_error = err;
            release_pool_engine_locked( binding, engine, FALSE );
            pthread_mutex_unlock( &provider.mutex );
            return status;
        }
        engine->suspend_doorbell = suspend_doorbell;
        if (*suspend_doorbell)
        {
            params->transition_target = 0;
            params->fault_address = 0;
            params->fault_access = EXCEPTION_READ_FAULT;
            params->stop_reason = XTAJIT64_STOP_SUSPEND;
            params->unicorn_error = UC_ERR_OK;
            if (engine->flight_recorder)
                flight_record_engine_event(
                    engine, XTAJIT64_FLIGHT_EVENT_SUSPEND_ACKNOWLEDGED,
                    XTAJIT64_FLIGHT_REASON_NONE, XTAJIT64_STOP_SUSPEND,
                    params->context.rip, params->context.rsp );
            release_pool_engine_locked( binding, engine, FALSE );
            pthread_mutex_unlock( &provider.mutex );
            return STATUS_SUCCESS;
        }

        engine->stack_limit = params->stack_limit;
        engine->stack_base = params->stack_base;
        engine->transition_target = 0;
        engine->fault_address = 0;
        engine->fault_access = EXCEPTION_READ_FAULT;
        engine->mapping_error = UC_ERR_OK;
        engine->stop_reason = XTAJIT64_STOP_NONE;
        atomic_store_explicit( &engine->pause_requested, false, memory_order_release );
        if (*suspend_doorbell)
        {
            params->transition_target = 0;
            params->fault_address = 0;
            params->fault_access = EXCEPTION_READ_FAULT;
            params->stop_reason = XTAJIT64_STOP_SUSPEND;
            params->unicorn_error = UC_ERR_OK;
            if (engine->flight_recorder)
                flight_record_engine_event(
                    engine, XTAJIT64_FLIGHT_EVENT_SUSPEND_ACKNOWLEDGED,
                    XTAJIT64_FLIGHT_REASON_NONE, XTAJIT64_STOP_SUSPEND,
                    params->context.rip, params->context.rsp );
            release_pool_engine_locked( binding, engine, FALSE );
            pthread_mutex_unlock( &provider.mutex );
            return STATUS_SUCCESS;
        }
        if (engine->flight_recorder)
            flight_record_context_event( engine, XTAJIT64_FLIGHT_EVENT_CONTEXT_IMPORT,
                                         params, XTAJIT64_FLIGHT_REASON_NONE );
        engine->running = TRUE;
        pthread_mutex_unlock( &provider.mutex );

#ifdef XTAJIT64_UNIXLIB_TEST
        if (atomic_load_explicit( &test_hold_engine_start, memory_order_acquire ))
        {
            atomic_store_explicit( &test_engine_start_entered, 1, memory_order_release );
            while (!atomic_load_explicit( &test_release_engine_start,
                                          memory_order_acquire ))
                sched_yield();
        }
#endif

        next_rip = params->context.rip;
        for (;;)
        {
#ifdef XTAJIT64_UNIXLIB_TEST
            atomic_fetch_add_explicit( &test_emu_start_count, 1, memory_order_relaxed );
#endif
            if (engine->tb_history &&
                xtajit64_tb_history_should_sample( &engine->tb_history_sample_counter ))
                tb_history_record_execution_entry( engine, next_rip );
            if (engine->flight_recorder)
                flight_record_engine_event( engine,
                                            reentering ? XTAJIT64_FLIGHT_EVENT_PROVIDER_RESUME :
                                                         XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN,
                                            XTAJIT64_FLIGHT_REASON_NONE,
                                            XTAJIT64_FLIGHT_UNKNOWN_U32, next_rip,
                                            params->context.rsp );
            engine->flight_stop_detail0 = XTAJIT64_FLIGHT_UNKNOWN_U64;
            err = uc_emu_start( engine->uc, next_rip, UINT64_MAX, 0, 0 );
            maybe_report_unicorn_perf_diagnostics( engine );
#ifdef XTAJIT64_UNIXLIB_TEST
            if (atomic_load_explicit( &test_hold_engine_result, memory_order_acquire ))
            {
                atomic_store_explicit( &test_engine_result_entered, 1,
                                       memory_order_release );
                while (!atomic_load_explicit( &test_release_engine_result,
                                              memory_order_acquire ))
                    sched_yield();
            }
#endif
            boundary_reason = UC_X64_BOUNDARY_STOP_NONE;
            boundary_address = 0;
            boundary_err = uc_query_x64_boundary_stop(
                engine->uc, &boundary_reason, &boundary_address );
            pthread_mutex_lock( &provider.mutex );
            if (boundary_err != UC_ERR_OK)
            {
                engine->mapping_error = boundary_err;
                engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
                poison_provider_locked( STATUS_UNSUCCESSFUL );
            }
            else if (boundary_reason == UC_X64_BOUNDARY_STOP_EC_CODE)
            {
                engine->transition_target = boundary_address;
                engine->stop_reason = XTAJIT64_STOP_EC_TRANSITION;
#ifndef XTAJIT64_UNIXLIB_TEST
                record_ec_transition_target( engine, boundary_address );
#endif
            }
            else if (boundary_reason == UC_X64_BOUNDARY_STOP_SUSPEND)
            {
                engine->stop_reason = XTAJIT64_STOP_SUSPEND;
                if (engine->flight_recorder)
                    flight_record_engine_event(
                        engine, XTAJIT64_FLIGHT_EVENT_SUSPEND_ACKNOWLEDGED,
                        XTAJIT64_FLIGHT_REASON_NONE, XTAJIT64_STOP_SUSPEND,
                        boundary_address, XTAJIT64_FLIGHT_UNKNOWN_U64 );
            }
            else if (boundary_reason == UC_X64_BOUNDARY_STOP_PAUSE &&
                     !atomic_load_explicit( &engine->pause_requested,
                                            memory_order_acquire ))
            {
                engine->mapping_error = UC_ERR_EXCEPTION;
                engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
                poison_provider_locked( STATUS_UNSUCCESSFUL );
            }
            else if (boundary_reason != UC_X64_BOUNDARY_STOP_NONE &&
                     boundary_reason != UC_X64_BOUNDARY_STOP_PAUSE)
            {
                engine->mapping_error = UC_ERR_EXCEPTION;
                engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
                poison_provider_locked( STATUS_UNSUCCESSFUL );
            }
            if (engine->stop_reason == XTAJIT64_STOP_INTERNAL_ERROR &&
                engine->mapping_error != UC_ERR_OK)
                err = engine->mapping_error;
            if (!provider.poison_status && provider.initialized && engine->uc &&
                engine->linked && engine->stop_reason == XTAJIT64_STOP_SYSCALL &&
                err == UC_ERR_OK)
            {
                /* Syscalls are a hot path.  Keep the stopped engine's full
                 * register file resident and rewrite only the ARM64EC ABI
                 * registers before resuming in the x64 ntdll helper. */
                uc_err syscall_err = prepare_x64_syscall_engine(
                    engine, provider.x64_syscall_dispatcher,
                    provider.x64_syscall_count, &next_rip );

                if (syscall_err != UC_ERR_OK)
                {
                    err = syscall_err;
                    poison_provider_locked( STATUS_UNSUCCESSFUL );
                }
                else
                {
                    engine->stop_reason = XTAJIT64_STOP_NONE;
                    if (engine->suspend_doorbell && *engine->suspend_doorbell)
                        engine->stop_reason = XTAJIT64_STOP_SUSPEND;
                    if (engine->stop_reason == XTAJIT64_STOP_NONE &&
                        !atomic_load_explicit( &engine->pause_requested,
                                               memory_order_acquire ))
                    {
                        if (engine->flight_recorder)
                            flight_record_engine_event( engine,
                                                        XTAJIT64_FLIGHT_EVENT_PROVIDER_RESUME,
                                                        XTAJIT64_FLIGHT_REASON_NONE,
                                                        XTAJIT64_STOP_SYSCALL, next_rip,
                                                        XTAJIT64_FLIGHT_UNKNOWN_U64 );
                        reentering = TRUE;
                        pthread_mutex_unlock( &provider.mutex );
                        continue;
                    }
                }
            }
#if defined(__APPLE__) && \
    (!defined(XTAJIT64_UNIXLIB_TEST) || defined(XTAJIT64_TEST_EC_LEAF_FASTPATH))
            if (!provider.poison_status && provider.initialized && engine->uc &&
                engine->linked && engine->stop_reason == XTAJIT64_STOP_EC_TRANSITION &&
                err == UC_ERR_OK &&
                try_ec_leaf_fastpath( engine, engine->uc,
                                      engine->transition_target, FALSE,
                                      &next_rip ))
            {
                engine->stop_reason = XTAJIT64_STOP_NONE;
                if (engine->suspend_doorbell && *engine->suspend_doorbell)
                    engine->stop_reason = XTAJIT64_STOP_SUSPEND;
                if (engine->stop_reason == XTAJIT64_STOP_NONE &&
                    !atomic_load_explicit( &engine->pause_requested,
                                           memory_order_acquire ))
                {
                    if (engine->flight_recorder)
                        flight_record_engine_event( engine,
                                                    XTAJIT64_FLIGHT_EVENT_PROVIDER_RESUME,
                                                    XTAJIT64_FLIGHT_REASON_NONE,
                                                    XTAJIT64_STOP_EC_TRANSITION,
                                                    next_rip,
                                                    XTAJIT64_FLIGHT_UNKNOWN_U64 );
                    reentering = TRUE;
                    pthread_mutex_unlock( &provider.mutex );
                    continue;
                }
            }
#endif

            /* Keep the engine logically running until its registers are captured.
             * Mutators only publish a pause request, so the owner callback has
             * already completed uc_emu_stop before this read can begin. */
            read_err = read_context( engine, &params->context );
            if (read_err != UC_ERR_OK) poison_provider_locked( STATUS_UNSUCCESSFUL );
            if (provider.poison_status) status = provider.poison_status;
            else if (!provider.initialized || !engine->uc || !engine->linked)
                status = STATUS_INVALID_HANDLE;
            else if (atomic_load_explicit( &engine->pause_requested,
                                            memory_order_acquire ) &&
                     engine->stop_reason == XTAJIT64_STOP_NONE &&
                     err == UC_ERR_OK && read_err == UC_ERR_OK)
                resume = TRUE;

            if (resume)
            {
                uc_err stop_err = uc_clear_instruction_boundary_stop( engine->uc );

                engine->running = FALSE;
                pthread_cond_broadcast( &provider.cond );
                if (stop_err != UC_ERR_OK)
                {
                    err = stop_err;
                    engine->mapping_error = stop_err;
                    engine->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
                    poison_provider_locked( STATUS_UNSUCCESSFUL );
                    status = provider.poison_status;
                    resume = FALSE;
                }
                else reentering = TRUE;
            }
            if (!resume)
            {
#ifndef XTAJIT64_UNIXLIB_TEST
                ec_target_stats_report = engine->ec_target_stats_report_pending;
                engine->ec_target_stats_report_pending = FALSE;
#endif
                params->transition_target = engine->transition_target;
                params->fault_address = engine->fault_address;
                params->fault_access = engine->fault_access;
                params->stop_reason = status ? XTAJIT64_STOP_INTERNAL_ERROR :
                                               engine->stop_reason;
                params->unicorn_error = err != UC_ERR_OK ? err : read_err;
#ifndef XTAJIT64_UNIXLIB_TEST
                if (status || params->stop_reason != XTAJIT64_STOP_EC_TRANSITION)
                    TRACE_(xtajitmap)(
                        "pid %ld engine %llu result status=%#x reason=%u "
                        "unicorn=%u emu=%u read=%u mapping=%u pause=%u "
                        "doorbell=%u rip=%#llx fault=%#llx access=%u\n",
                        (long)getpid(),
                        (unsigned long long)engine->diagnostic_id,
                        (unsigned int)status, params->stop_reason,
                        params->unicorn_error, err, read_err,
                        engine->mapping_error,
                        atomic_load_explicit( &engine->pause_requested,
                                              memory_order_acquire ),
                        engine->suspend_doorbell ? *engine->suspend_doorbell : 0,
                        (unsigned long long)params->context.rip,
                        (unsigned long long)params->fault_address,
                        params->fault_access );
                trace_interrupt_diagnostic_locked( engine, params->context.rip );
#endif
                if (!status && params->stop_reason == XTAJIT64_STOP_NONE)
                    params->stop_reason = err == UC_ERR_INSN_INVALID ?
                                          XTAJIT64_STOP_INVALID_INSTRUCTION :
                                          XTAJIT64_STOP_INTERNAL_ERROR;
                /* Record only after the ordinary terminal normalization.  In
                 * particular, uc_emu_start() returning UC_ERR_INSN_INVALID
                 * must not be published as an ambiguous STOP_NONE event. */
                if (engine->flight_recorder)
                {
                    flight_record_context_event( engine, XTAJIT64_FLIGHT_EVENT_CONTEXT_EXPORT,
                                                 params, XTAJIT64_FLIGHT_REASON_NONE );
                    flight_record_engine_event( engine, XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP,
                                                XTAJIT64_FLIGHT_REASON_NONE,
                                                params->stop_reason, params->context.rip,
                                                params->context.rsp );
                }
                if (!status && params->stop_reason == XTAJIT64_STOP_INTERNAL_ERROR)
                {
                    poison_provider_locked( STATUS_UNSUCCESSFUL );
                    status = provider.poison_status;
                }
                context_err = release_pool_engine_locked(
                    binding, engine, read_err == UC_ERR_OK );
                if (context_err != UC_ERR_OK)
                {
                    params->unicorn_error = context_err;
                    params->stop_reason = XTAJIT64_STOP_INTERNAL_ERROR;
                    poison_provider_locked( STATUS_UNSUCCESSFUL );
                    status = provider.poison_status;
                }
            }
            pthread_mutex_unlock( &provider.mutex );
#ifndef XTAJIT64_UNIXLIB_TEST
            if (!resume && ec_target_stats_report) render_ec_transition_target_stats();
#endif
            break;
        }
    } while (resume);

    if (status) return status;
    if (params->stop_reason == XTAJIT64_STOP_EC_TRANSITION) return STATUS_SUCCESS;
    if (params->stop_reason == XTAJIT64_STOP_SUSPEND) return STATUS_SUCCESS;
    if (params->stop_reason == XTAJIT64_STOP_MEMORY_FAULT) return STATUS_ACCESS_VIOLATION;
    if (params->stop_reason == XTAJIT64_STOP_MAPPING_MISS) return STATUS_RETRY;
    if (params->stop_reason == XTAJIT64_STOP_SINGLE_STEP) return STATUS_SINGLE_STEP;
    return STATUS_NOT_SUPPORTED;
}

/* Called only by ntdll while its code observer owns the mutation gate and
 * virtual_mutex. Do not call ntdll here: publish exact identity metadata and
 * invalidate retained engine mappings before the observer resumes engines. */
static int32_t publish_fault_range( void *context, uint64_t address, uint64_t size,
                                     uint64_t allocation_base, uint32_t protect )
{
    struct mapped_range mapping = {0};
    struct range_array replacement = {0}, removals = {0}, additions = {0}, old;
    NTSTATUS status = STATUS_SUCCESS;

    pthread_mutex_lock( &provider.mutex );
    if (context != &provider || !current_thread_owns_mutation_locked() ||
        !provider.code_observer_transaction || provider.poison_status ||
        !size || (address & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
        (size & (XTAJIT64_GUEST_PAGE_SIZE - 1)) ||
        address > XTAJIT64_X64_USER_ADDRESS_MAX || size - 1 > XTAJIT64_X64_USER_ADDRESS_MAX - address ||
        legacy_mutation_selects_low_locked( address, size ))
        status = STATUS_INVALID_DEVICE_STATE;
    if (!status)
    {
        mapping.guest = mapping.host = address;
        mapping.size = size;
        mapping.allocation_base = allocation_base;
        mapping.perms = protection_to_unicorn( protect );
        mapping.state = MEM_COMMIT;
        mapping.domain = XTAJIT64_MEMORY_ADDRESS_IDENTITY;
        status = build_mapped_registry( &provider.ranges, &mapping, &replacement );
    }
    if (!status) status = build_resync_mapping_changes( &provider.ranges, &replacement,
                                                        &removals, &additions );
    if (!status) status = publish_identity_page_flag_changes_locked( &removals, &additions );
    if (!status)
    {
        old = provider.ranges;
        provider.ranges = replacement;
        memset( &replacement, 0, sizeof(replacement) );
        mark_engine_mappings_stale_locked( address, size, 0 );
        range_array_free( &old );
        /* This owner publishes metadata inside the code transaction. Advance
         * its token together with the registry so cached readers and engines
         * must resynchronize before reentering guest execution. */
        ++provider.generation;
        provider.code_observer_transaction->generation = provider.generation;
    }
    if (status) poison_provider_locked( status );
    pthread_mutex_unlock( &provider.mutex );
    range_array_free( &replacement );
    range_array_free( &removals );
    range_array_free( &additions );
    return status;
}

static NTSTATUS resolve_memory_fault( void *args )
{
    struct xtajit64_fault_params *params = args;
    NTSTATUS status;

    if (!params || params->reserved) return STATUS_INVALID_PARAMETER;
    pthread_mutex_lock( &provider.mutex );
    status = provider.poison_status;
    if (!status && (!provider.initialized || !provider.code_observer_active))
        status = STATUS_INVALID_HANDLE;
    pthread_mutex_unlock( &provider.mutex );
    if (status) return status;
#ifndef XTAJIT64_UNIXLIB_TEST
    status = __wine_resolve_arm64ec_memory_fault_v1( params->address, params->access,
                                                  &params->result, &provider, publish_fault_range );
#else
    status = STATUS_NOT_SUPPORTED;
    (void)publish_fault_range;
#endif
    pthread_mutex_lock( &provider.mutex );
    if (provider.poison_status) status = provider.poison_status;
    pthread_mutex_unlock( &provider.mutex );
    return status;
}

#else /* HAVE_UNICORN */

static NTSTATUS unicorn_not_supported( void *args )
{
    return STATUS_NOT_SUPPORTED;
}

#define process_init             unicorn_not_supported
#define process_term             unicorn_not_supported
#define thread_init              unicorn_not_supported
#define thread_term              unicorn_not_supported
#define memory_map               unicorn_not_supported
#define memory_unmap             unicorn_not_supported
#define memory_protect           unicorn_not_supported
#define memory_snapshot_lock     unicorn_not_supported
#define memory_snapshot_unlock   unicorn_not_supported
#define memory_resync_begin      unicorn_not_supported
#define memory_resync            unicorn_not_supported
#define memory_translate         unicorn_not_supported
#define flush_instruction_cache  unicorn_not_supported
#define poison                   unicorn_not_supported
#define begin_simulation         unicorn_not_supported
#define flight_bind              unicorn_not_supported
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
    memory_resync,
    flush_instruction_cache,
    poison,
    begin_simulation,
    memory_resync_begin,
    memory_translate,
    flight_bind,
    resolve_memory_fault,
    memory_snapshot_lock,
    memory_snapshot_unlock,
};

C_ASSERT( ARRAY_SIZE(__wine_unix_call_funcs) == unix_funcs_count );
