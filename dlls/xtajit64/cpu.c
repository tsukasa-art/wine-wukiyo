/*
 * x86-64 emulation on ARM64
 *
 * Copyright 2024 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <string.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/exception.h"
#include "unixlib.h"

WINE_DEFAULT_DEBUG_CHANNEL(xtajit);

#ifdef HAVE_UNICORN

#define XTAJIT64_CALL(func,params) WINE_UNIX_CALL( unix_ ## func, params )

static ULONG_PTR rtl_exit_user_thread;
static ULONG host_page_size;
static BOOL flight_recorder_enabled;
static BOOL terminal_diagnostics_enabled;
static LARGE_INTEGER flight_qpc_frequency;
static volatile LONG64 transition_cache_generation = 1;

#define XTAJIT64_CONTROL_STACK_SIZE 0x40000
#define XTAJIT64_MAX_TRANSITION_DEPTH 64
#define XTAJIT64_MAX_RESYNC_ATTEMPTS 8
#define XTAJIT64_EC_ENTRY_CACHE_SIZE 32
#define XTAJIT64_THREAD_STATE_MAGIC 0x363454494a415458ull /* "XTAJIT64" */

C_ASSERT( !(XTAJIT64_EC_ENTRY_CACHE_SIZE & (XTAJIT64_EC_ENTRY_CACHE_SIZE - 1)) );

/* ARM64EC's clang target advertises __arm64ec__ rather than the native
 * aarch64 spelling.  Keep this capability centralized: an UNKNOWN x18 from
 * an accidentally excluded PE build would make the watchdog observationally
 * useless. */
#if defined(__aarch64__) || defined(__arm64__) || defined(__arm64ec__) || defined(_M_ARM64EC)
# define XTAJIT64_HAVE_LIVE_ARM64_REGISTERS 1
#endif
#if (defined(__arm64ec__) || defined(_M_ARM64EC)) && !defined(XTAJIT64_HAVE_LIVE_ARM64_REGISTERS)
# error ARM64EC requires live x18/SP diagnostic capture
#endif

enum xtajit64_native_transition
{
    XTAJIT64_NATIVE_RETURN,
    XTAJIT64_NATIVE_EXIT,
    XTAJIT64_NATIVE_JUMP,
};

enum xtajit64_transition_frame_kind
{
    XTAJIT64_FRAME_ENTRY = XTAJIT64_FLIGHT_FRAME_ENTRY,
    XTAJIT64_FRAME_EXIT = XTAJIT64_FLIGHT_FRAME_EXIT,
};

struct xtajit64_transition_frame
{
    UINT64 guest_rsp;
    UINT64 native_sp;
    UINT64 native_pc;
    UINT32 kind;
    UINT32 reserved;
};

struct xtajit64_ec_entry_cache
{
    UINT64 generation;
    UINT64 guest_target;
    UINT64 native_target;
    UINT64 entry;
};

struct xtajit64_thread_state
{
    UINT64 magic;
    UINT64 allocation_size;
    UINT64 control_stack_top;
    UINT64 capture_sp;
    UINT64 capture_lr;
    UINT64 capture_target;
    UINT64 capture_x10;
    UINT32 capture_kind;
    UINT32 depth;
    struct xtajit64_transition_frame frames[XTAJIT64_MAX_TRANSITION_DEPTH];
    ULONG suspend_doorbell;
    ULONG flight_alignment;
    struct xtajit64_flight_recorder *flight_recorder;
    UINT64 flight_causal_boundary_id;
    UINT64 flight_context_generation;
    UINT64 flight_transition_generation;
    volatile UINT32 flight_dump_state;
    UINT32 flight_reserved;
    /* Captured in the naked ARM64EC wrapper before this code switches to the
     * private control stack.  It is meaningful only on TRANSITION_CAPTURE. */
    UINT64 capture_x18;
    /* A PE-side x18 claim is captured exactly once while ThreadInit has its
     * normal ARM64EC contract.  unix_flight_bind authenticates it against the
     * independently-backed Unix TEB; do not refresh it through NtCurrentTeb,
     * which is itself x18 on this side of the ABI. */
    UINT64 flight_expected_teb;
    BOOL flight_teb_authenticated;
    UINT32 flight_teb_reserved;
    /* Stable identity stack and validated ARM64EC entry metadata are hot
     * transition inputs.  Publish their generation last so a nested signal
     * transition can never consume a partially replaced cache entry. */
    UINT64 stack_cache_generation;
    UINT64 stack_cache_limit;
    UINT64 stack_cache_base;
    struct xtajit64_ec_entry_cache ec_entry_cache[XTAJIT64_EC_ENTRY_CACHE_SIZE];
};

typedef NTSTATUS (WINAPI *arm64x_get_information)( ULONG, void *, void * );
typedef NTSTATUS (WINAPI *arm64x_set_information)( ULONG, ULONG_PTR, void * );

extern void *__os_arm64x_get_x64_information;
extern void *__os_arm64x_set_x64_information;
extern NTSTATUS WINAPI __wine_arm64ec_get_x64_syscall_dispatcher( ULONG_PTR *, ULONG * );
extern NTSTATUS WINAPI __wine_arm64ec_prepare_x64_execution(void);

C_ASSERT( offsetof(TEB, ChpeV2CpuAreaInfo) == 0x1788 );
C_ASSERT( offsetof(CHPE_V2_CPU_AREA_INFO, InSimulation) == 0x00 );
C_ASSERT( offsetof(CHPE_V2_CPU_AREA_INFO, ContextAmd64) == 0x18 );
C_ASSERT( offsetof(CHPE_V2_CPU_AREA_INFO, SuspendDoorbell) == 0x20 );
C_ASSERT( offsetof(CHPE_V2_CPU_AREA_INFO, EmulatorData[0]) == 0x30 );
C_ASSERT( offsetof(struct xtajit64_thread_state, control_stack_top) == 0x10 );
C_ASSERT( offsetof(struct xtajit64_thread_state, capture_sp) == 0x18 );
C_ASSERT( offsetof(struct xtajit64_thread_state, capture_lr) == 0x20 );
C_ASSERT( offsetof(struct xtajit64_thread_state, capture_target) == 0x28 );
C_ASSERT( offsetof(struct xtajit64_thread_state, capture_x10) == 0x30 );
C_ASSERT( offsetof(struct xtajit64_thread_state, capture_kind) == 0x38 );
C_ASSERT( offsetof(struct xtajit64_thread_state, depth) == 0x3c );
C_ASSERT( offsetof(struct xtajit64_thread_state, frames) == 0x40 );
C_ASSERT( offsetof(struct xtajit64_thread_state, suspend_doorbell) == 0x840 );
C_ASSERT( XTAJIT64_STOP_SUSPEND == 8 );
C_ASSERT( offsetof(struct xtajit64_thread_state, flight_alignment) == 0x844 );
C_ASSERT( offsetof(struct xtajit64_thread_state, flight_recorder) == 0x848 );
C_ASSERT( offsetof(struct xtajit64_thread_state, flight_causal_boundary_id) == 0x850 );
C_ASSERT( offsetof(struct xtajit64_thread_state, flight_context_generation) == 0x858 );
C_ASSERT( offsetof(struct xtajit64_thread_state, flight_transition_generation) == 0x860 );
C_ASSERT( offsetof(struct xtajit64_thread_state, flight_dump_state) == 0x868 );
C_ASSERT( offsetof(struct xtajit64_thread_state, capture_x18) == 0x870 );
C_ASSERT( offsetof(struct xtajit64_thread_state, flight_expected_teb) == 0x878 );
C_ASSERT( offsetof(struct xtajit64_thread_state, flight_teb_authenticated) == 0x880 );
C_ASSERT( offsetof(struct xtajit64_thread_state, stack_cache_generation) == 0x888 );
C_ASSERT( offsetof(struct xtajit64_thread_state, stack_cache_limit) == 0x890 );
C_ASSERT( offsetof(struct xtajit64_thread_state, stack_cache_base) == 0x898 );
C_ASSERT( offsetof(struct xtajit64_thread_state, ec_entry_cache) == 0x8a0 );
C_ASSERT( sizeof(struct xtajit64_ec_entry_cache) == 0x20 );
C_ASSERT( sizeof(struct xtajit64_thread_state) == 0xca0 );
C_ASSERT( ((sizeof(struct xtajit64_thread_state) + 15) & ~(SIZE_T)15) == 0xca0 );
C_ASSERT( sizeof(struct xtajit64_transition_frame) == 0x20 );
C_ASSERT( XTAJIT64_CONTROL_STACK_SIZE >= sizeof(struct xtajit64_thread_state) +
          sizeof(struct xtajit64_flight_recorder) + 0x10000 );
C_ASSERT( offsetof(ARM64EC_NT_CONTEXT, X8) == 0x78 );
C_ASSERT( offsetof(ARM64EC_NT_CONTEXT, Sp) == 0x98 );
C_ASSERT( offsetof(ARM64EC_NT_CONTEXT, Pc) == 0xf8 );
C_ASSERT( offsetof(ARM64EC_NT_CONTEXT, Lr) == 0x120 );
C_ASSERT( offsetof(ARM64EC_NT_CONTEXT, X6) == 0x130 );
C_ASSERT( offsetof(ARM64EC_NT_CONTEXT, X9) == 0x150 );
C_ASSERT( offsetof(ARM64EC_NT_CONTEXT, X15) == 0x190 );
C_ASSERT( offsetof(ARM64EC_NT_CONTEXT, V) == 0x1a0 );

static NTSTATUS init_unixlib(void)
{
    if (__wine_unixlib_handle) return STATUS_SUCCESS;
    return __wine_init_unix_call();
}

static UINT64 current_transition_cache_generation(void)
{
    return __atomic_load_n( &transition_cache_generation, __ATOMIC_ACQUIRE );
}

static void invalidate_transition_caches(void)
{
    LONG64 generation = __atomic_add_fetch( &transition_cache_generation, 1,
                                            __ATOMIC_RELEASE );

    /* Zero is reserved for an unpublished cache entry.  Wrapping requires an
     * impossible process lifetime in practice, but preserving the sentinel is
     * free and keeps the publication contract complete. */
    if (!generation)
        __atomic_add_fetch( &transition_cache_generation, 1, __ATOMIC_RELEASE );
}

static NTSTATUS synchronize_transition_state_mapping( struct xtajit64_thread_state *state,
                                                       BOOL *provider_touched );
static NTSTATUS unregister_transition_state_mapping( struct xtajit64_thread_state *state );
static UINT64 flight_read_live_x18(void);

/* State itself is supplied by the current thread's owned allocation.  Before
 * any opt-in producer dereferences its recorder pointer, additionally prove
 * that the pointer is the exact high-end object allocated below.  This is
 * intentionally separate from the recorder magic/schema check: a damaged
 * pointer must never be dereferenced merely to discover that it is damaged. */
static BOOL flight_validate_recorder_layout( const struct xtajit64_thread_state *state )
{
    ULONG_PTR state_address, allocation_end, control_limit, recorder_address;

    if (!state) return FALSE;
    if (state->magic != XTAJIT64_THREAD_STATE_MAGIC ||
        state->allocation_size != XTAJIT64_CONTROL_STACK_SIZE)
        return FALSE;
    state_address = (ULONG_PTR)state;
    /* Prove the whole fixed allocation first.  This also proves the later
     * +15 alignment rounding cannot overflow. */
    if (state_address > ~(ULONG_PTR)0 - state->allocation_size ||
        sizeof(*state) > state->allocation_size - 15)
        return FALSE;
    allocation_end = state_address + state->allocation_size;
    if (!state->flight_recorder)
        return state->control_stack_top == allocation_end &&
               !(state->control_stack_top & 15);
    if ((allocation_end & 63) ||
        sizeof(*state->flight_recorder) > state->allocation_size)
        return FALSE;
    recorder_address = allocation_end - sizeof(*state->flight_recorder);
    if ((ULONG_PTR)state->flight_recorder != recorder_address ||
        state->control_stack_top != recorder_address || (recorder_address & 63))
        return FALSE;
    control_limit = (state_address + sizeof(*state) + 15) & ~(ULONG_PTR)15;
    if (control_limit >= (ULONG_PTR)state->flight_recorder) return FALSE;
    return xtajit64_flight_validate_layout( state_address, state->allocation_size,
                                            state->control_stack_top,
                                            state->flight_recorder );
}

static BOOL flight_has_valid_recorder( const struct xtajit64_thread_state *state )
{
    return state && state->flight_recorder && flight_validate_recorder_layout( state );
}

static BOOL flight_has_active_recorder( const struct xtajit64_thread_state *state )
{
    return flight_has_valid_recorder( state ) &&
           xtajit64_flight_recorder_is_active( state->flight_recorder );
}

static NTSTATUS allocate_transition_state( struct xtajit64_thread_state **ret )
{
    struct xtajit64_thread_state *state;
    SIZE_T size = XTAJIT64_CONTROL_STACK_SIZE;
    void *allocation = NULL;
    ULONG_PTR allocation_end, recorder, stack_limit;
    NTSTATUS status;

    status = NtAllocateVirtualMemory( GetCurrentProcess(), &allocation, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    if (status) return status;
    if (size < sizeof(*state) + 0x10000 ||
        (ULONG_PTR)allocation > ~(ULONG_PTR)0 - size)
    {
        void *free_base = allocation;
        SIZE_T free_size = 0;

        NtFreeVirtualMemory( GetCurrentProcess(), &free_base, &free_size, MEM_RELEASE );
        return STATUS_NO_MEMORY;
    }

    state = allocation;
    memset( state, 0, sizeof(*state) );
    state->magic = XTAJIT64_THREAD_STATE_MAGIC;
    state->allocation_size = size;
    allocation_end = (ULONG_PTR)allocation + size;
    if (allocation_end & 15)
    {
        void *free_base = allocation;
        SIZE_T free_size = 0;

        NtFreeVirtualMemory( GetCurrentProcess(), &free_base, &free_size, MEM_RELEASE );
        return STATUS_NO_MEMORY;
    }
    state->control_stack_top = allocation_end;
    if (flight_recorder_enabled)
    {
        stack_limit = ((ULONG_PTR)state + sizeof(*state) + 15) & ~(ULONG_PTR)15;
        if ((allocation_end & 63) || sizeof(*state->flight_recorder) > size)
            recorder = 0;
        else recorder = allocation_end - sizeof(*state->flight_recorder);
        if (!recorder || (recorder & 63) || recorder < stack_limit ||
            recorder - stack_limit < 0x10000)
        {
            void *free_base = allocation;
            SIZE_T free_size = 0;

            NtFreeVirtualMemory( GetCurrentProcess(), &free_base, &free_size, MEM_RELEASE );
            return STATUS_NO_MEMORY;
        }
        /* The recorder occupies the high end of the existing transition-state
         * allocation.  Lowering the native control-stack top makes the two
         * non-overlapping even as the state structure grows. */
        state->control_stack_top = recorder;
        state->flight_recorder = (struct xtajit64_flight_recorder *)recorder;
        xtajit64_flight_recorder_init( state->flight_recorder );
        state->flight_teb_authenticated = FALSE;
    }
    *ret = state;
    return STATUS_SUCCESS;
}

static NTSTATUS query_current_thread_teb( TEB **ret )
{
    THREAD_BASIC_INFORMATION info;
    TEB *teb;
    NTSTATUS status;

    if (!ret) return STATUS_INVALID_PARAMETER;
    *ret = NULL;
    if ((status = NtQueryInformationThread( NtCurrentThread(), ThreadBasicInformation,
                                             &info, sizeof(info), NULL )))
        return status;
    teb = info.TebBaseAddress;
    if (!teb || teb->Tib.Self != &teb->Tib)
        return STATUS_INVALID_ADDRESS;
    *ret = teb;
    return STATUS_SUCCESS;
}

static NTSTATUS free_transition_state( struct xtajit64_thread_state *state )
{
    void *free_base = state;
    SIZE_T free_size = 0;

    return NtFreeVirtualMemory( GetCurrentProcess(), &free_base, &free_size, MEM_RELEASE );
}

static void *resolve_arm64ec_export( HMODULE module, const char *name )
{
    const IMAGE_ARM64EC_REDIRECTION_ENTRY *map;
    const IMAGE_ARM64EC_METADATA *metadata;
    const IMAGE_LOAD_CONFIG_DIRECTORY *cfg;
    const IMAGE_NT_HEADERS *nt;
    ULONG_PTR base = (ULONG_PTR)module;
    ULONG_PTR metadata_ptr, image_end;
    void *raw;
    ULONG size, rva;
    int min, max;

    if (!(raw = RtlFindExportedRoutineByName( module, name ))) return NULL;
    if (!(nt = RtlImageNtHeader( module )) ||
        nt->OptionalHeader.SizeOfImage < sizeof(*metadata) ||
        nt->OptionalHeader.SizeOfImage > ~(ULONG_PTR)0 - base)
        return NULL;
    image_end = base + nt->OptionalHeader.SizeOfImage;
    if (!(cfg = RtlImageDirectoryEntryToData( module, TRUE,
                                              IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size )))
        return NULL;
    if (size < sizeof(cfg->Size)) return NULL;
    size = min( size, cfg->Size );
    if (size < offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer ) +
               sizeof(cfg->CHPEMetadataPointer))
        return NULL;
    metadata_ptr = cfg->CHPEMetadataPointer;
    if (metadata_ptr < base || metadata_ptr > image_end - sizeof(*metadata)) return NULL;
    metadata = (const IMAGE_ARM64EC_METADATA *)metadata_ptr;
    if (!metadata->RedirectionMetadata || !metadata->RedirectionMetadataCount ||
        metadata->RedirectionMetadata > nt->OptionalHeader.SizeOfImage ||
        metadata->RedirectionMetadataCount > 0x7fffffff ||
        metadata->RedirectionMetadataCount >
            (nt->OptionalHeader.SizeOfImage - metadata->RedirectionMetadata) / sizeof(*map))
        return NULL;
    if ((ULONG_PTR)raw < base || (ULONG_PTR)raw - base > ~(ULONG)0) return NULL;
    rva = (ULONG)((ULONG_PTR)raw - base);
    map = (const IMAGE_ARM64EC_REDIRECTION_ENTRY *)(base + metadata->RedirectionMetadata);

    min = 0;
    max = metadata->RedirectionMetadataCount - 1;
    while (min <= max)
    {
        int pos = min + (max - min) / 2;

        if (map[pos].Source == rva)
        {
            if (map[pos].Destination >= nt->OptionalHeader.SizeOfImage) return NULL;
            return (void *)(base + map[pos].Destination);
        }
        if (map[pos].Source < rva) min = pos + 1;
        else max = pos - 1;
    }
    return NULL;
}

static void context_to_unix( struct xtajit64_x64_context *dst, const AMD64_CONTEXT *src )
{
    dst->rax = src->Rax;
    dst->rbx = src->Rbx;
    dst->rcx = src->Rcx;
    dst->rdx = src->Rdx;
    dst->rsi = src->Rsi;
    dst->rdi = src->Rdi;
    dst->rbp = src->Rbp;
    dst->rsp = src->Rsp;
    dst->r8 = src->R8;
    dst->r9 = src->R9;
    dst->r10 = src->R10;
    dst->r11 = src->R11;
    dst->r12 = src->R12;
    dst->r13 = src->R13;
    dst->r14 = src->R14;
    dst->r15 = src->R15;
    dst->rip = src->Rip;
    dst->eflags = src->EFlags;
    dst->mxcsr = src->MxCsr;
    memcpy( dst->xmm, &src->Xmm0, sizeof(dst->xmm) );
}

static void context_from_unix( AMD64_CONTEXT *dst, const struct xtajit64_x64_context *src )
{
    dst->Rax = src->rax;
    dst->Rbx = src->rbx;
    dst->Rcx = src->rcx;
    dst->Rdx = src->rdx;
    dst->Rsi = src->rsi;
    dst->Rdi = src->rdi;
    dst->Rbp = src->rbp;
    dst->Rsp = src->rsp;
    dst->R8 = src->r8;
    dst->R9 = src->r9;
    dst->R10 = src->r10;
    dst->R11 = src->r11;
    dst->R12 = src->r12;
    dst->R13 = src->r13;
    dst->R14 = src->r14;
    dst->R15 = src->r15;
    dst->Rip = src->rip;
    dst->EFlags = src->eflags;
    dst->MxCsr = dst->FltSave.MxCsr = src->mxcsr;
    memcpy( &dst->Xmm0, src->xmm, sizeof(src->xmm) );
}

static void poison_provider( const char *operation, NTSTATUS status )
{
    struct xtajit64_poison_params params = { .status = status };

    ERR( "%s failed, poisoning x64 provider with status %#lx\n", operation, status );
    if (__wine_unixlib_handle) XTAJIT64_CALL( poison, &params );
}

static NTSTATUS get_allocation_base( const void *addr, ULONG_PTR *base )
{
    MEMORY_BASIC_INFORMATION info;
    NTSTATUS status;

    status = NtQueryVirtualMemory( GetCurrentProcess(), addr, MemoryBasicInformation,
                                   &info, sizeof(info), NULL );
    if (!status && info.AllocationBase) *base = (ULONG_PTR)info.AllocationBase;
    else if (!status) status = STATUS_INVALID_ADDRESS;
    return status;
}

static NTSTATUS describe_host_mapping( ULONG_PTR host, SIZE_T size,
                                       ULONG_PTR allocation_base, ULONG protect,
                                       struct xtajit64_memory_params *params )
{
    WINE_TRANSLATED_VIEW_INFORMATION translated = {0};
    ULONG_PTR guest_base, host_base, offset;
    NTSTATUS status;

    C_ASSERT( sizeof(translated) == 48 );
    if (!params || !host || !size || host > ~(ULONG_PTR)0 - size ||
        !allocation_base)
        return STATUS_INVALID_ADDRESS;
    memset( params, 0, sizeof(*params) );
    status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)host,
                                   MemoryWineTranslatedViewInformation,
                                   &translated, sizeof(translated), NULL );
    if (status) return status;
    if (translated.Version != WINE_TRANSLATED_VIEW_INFORMATION_VERSION ||
        translated.Reserved ||
        (translated.Flags & ~WINE_TRANSLATED_VIEW_AMD64_LOW))
        return STATUS_REVISION_MISMATCH;
    if (translated.Flags & WINE_TRANSLATED_VIEW_AMD64_LOW)
        return STATUS_ACCESS_DENIED;  /* owned by the native LOW observer */

    guest_base = (ULONG_PTR)translated.GuestBase;
    host_base = (ULONG_PTR)translated.HostBase;
    if (!guest_base || guest_base != host_base || !translated.RegionSize ||
        host < host_base || (offset = host - host_base) >= translated.RegionSize ||
        size > translated.RegionSize - offset ||
        (ULONG_PTR)translated.AllocationBase != allocation_base)
        return STATUS_INVALID_ADDRESS;

    params->guest = guest_base + offset;
    params->host = host;
    params->size = size;
    params->allocation_base = allocation_base;
    params->protect = protect;
    return STATUS_SUCCESS;
}

static NTSTATUS synchronize_transition_state_mapping( struct xtajit64_thread_state *state,
                                                       BOOL *provider_touched )
{
    struct xtajit64_memory_params params;
    ULONG_PTR allocation_base;
    NTSTATUS status;

    if (!provider_touched) return STATUS_INVALID_PARAMETER;
    *provider_touched = FALSE;
    if (!state || !state->allocation_size ||
        (ULONG_PTR)state > ~(ULONG_PTR)0 - state->allocation_size)
        return STATUS_INVALID_ADDRESS;
    if ((status = get_allocation_base( state, &allocation_base ))) return status;
    if ((status = describe_host_mapping( (ULONG_PTR)state, state->allocation_size,
                                          allocation_base, PAGE_READWRITE, &params )))
        return status;
    *provider_touched = TRUE;
    return XTAJIT64_CALL( memory_map, &params );
}

static NTSTATUS unregister_transition_state_mapping( struct xtajit64_thread_state *state )
{
    struct xtajit64_memory_params params;

    if (!state || !state->allocation_size ||
        (ULONG_PTR)state > ~(ULONG_PTR)0 - state->allocation_size)
        return STATUS_INVALID_ADDRESS;
    memset( &params, 0, sizeof(params) );
    params.guest = (ULONG_PTR)state;
    params.host = (ULONG_PTR)state;
    params.size = state->allocation_size;
    return XTAJIT64_CALL( memory_unmap, &params );
}

struct mapping_snapshot
{
    struct xtajit64_memory_params *ranges;
    ULONG count;
    ULONG capacity;
};

static RTL_SRWLOCK resync_snapshot_lock = RTL_SRWLOCK_INIT;
static struct mapping_snapshot resync_snapshot;

static void free_mapping_snapshot( struct mapping_snapshot *snapshot )
{
    if (snapshot->ranges)
        RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, snapshot->ranges );
    memset( snapshot, 0, sizeof(*snapshot) );
}

static NTSTATUS append_mapping_snapshot( struct mapping_snapshot *snapshot,
                                         const struct xtajit64_memory_params *params )
{
    struct xtajit64_memory_params *ranges;
    ULONG capacity;
    SIZE_T size;

    if (snapshot->count)
    {
        struct xtajit64_memory_params *last = &snapshot->ranges[snapshot->count - 1];

        if (last->guest + last->size == params->guest &&
            last->host + last->size == params->host &&
            last->allocation_base == params->allocation_base &&
            last->protect == params->protect && last->size <= ~(UINT64)0 - params->size)
        {
            last->size += params->size;
            return STATUS_SUCCESS;
        }
    }
    if (snapshot->count < snapshot->capacity)
    {
        snapshot->ranges[snapshot->count++] = *params;
        return STATUS_SUCCESS;
    }
    if (snapshot->capacity >= (1u << 20)) return STATUS_INSUFFICIENT_RESOURCES;
    capacity = snapshot->capacity ? snapshot->capacity * 2 : 256;
    if (capacity > (1u << 20)) capacity = 1u << 20;
    size = (SIZE_T)capacity * sizeof(*ranges);
    if (snapshot->ranges)
        ranges = RtlReAllocateHeap( NtCurrentTeb()->Peb->ProcessHeap, 0,
                                    snapshot->ranges, size );
    else
        ranges = RtlAllocateHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, size );
    if (!ranges) return STATUS_NO_MEMORY;
    snapshot->ranges = ranges;
    snapshot->capacity = capacity;
    snapshot->ranges[snapshot->count++] = *params;
    return STATUS_SUCCESS;
}

static NTSTATUS collect_existing_mappings( ULONG_PTR lowest, ULONG_PTR highest,
                                           ULONG page_size,
                                           struct mapping_snapshot *snapshot )
{
    ULONG_PTR cursor = max( lowest, (ULONG_PTR)XTAJIT64_GUEST_PAGE_SIZE );
    ULONG_PTR window_end;

    if (!snapshot || highest < cursor || highest == ~(ULONG_PTR)0)
        return STATUS_INVALID_ADDRESS;
    window_end = highest + 1;

    while (cursor < window_end)
    {
        struct xtajit64_memory_params params = {0};
        MEMORY_BASIC_INFORMATION info;
        ULONG_PTR region_base, region_end, start, end;
        NTSTATUS status;

        status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)cursor,
                                       MemoryBasicInformation, &info, sizeof(info), NULL );
        if (status) return status;
        region_base = (ULONG_PTR)info.BaseAddress;
        if (!info.RegionSize || region_base > ~(ULONG_PTR)0 - info.RegionSize)
            return STATUS_INVALID_ADDRESS;
        region_end = region_base + info.RegionSize;
        if (region_end <= cursor) return STATUS_INVALID_ADDRESS;
        start = max( cursor, region_base );
        end = min( region_end, window_end );

        if (info.State == MEM_COMMIT && info.AllocationBase && end > start)
        {
            if ((start | end) & (XTAJIT64_GUEST_PAGE_SIZE - 1))
                return STATUS_INVALID_ADDRESS;
            status = describe_host_mapping( start, end - start,
                                            (ULONG_PTR)info.AllocationBase,
                                            info.Protect, &params );
            /* The capability-negotiated low-memory observer is the sole
             * structural authority for fixed-low AMD64 mappings.  Legacy
             * snapshots retain identity views only and must not replay that
             * translated lane. */
            if (status == STATUS_ACCESS_DENIED)
            {
                cursor = region_end;
                continue;
            }
            if (status) return status;
            if (params.guest < XTAJIT64_GUEST_KUSER + page_size &&
                params.guest + params.size > XTAJIT64_GUEST_KUSER)
            {
                if (params.guest != XTAJIT64_GUEST_KUSER ||
                    params.size != page_size)
                    return STATUS_INVALID_ADDRESS;
                cursor = region_end;
                continue;  /* ProcessInit installed the explicit low mapping. */
            }
            if ((status = append_mapping_snapshot( snapshot, &params ))) return status;
        }
        cursor = region_end;
    }
    return STATUS_SUCCESS;
}

static void finish_mapping_snapshot( BOOL normal )
{
    NTSTATUS status = XTAJIT64_CALL( memory_snapshot_unlock, NULL );
    RtlReleaseSRWLockExclusive( &resync_snapshot_lock );
    if (status) RtlRaiseStatus( status );
}

static NTSTATUS resync_existing_mappings(void)
{
    struct xtajit64_memory_resync_params params = {0};
    struct xtajit64_memory_resync_begin_params begin;
    struct mapping_snapshot *snapshot = &resync_snapshot;
    SYSTEM_BASIC_INFORMATION info;
    NTSTATUS status;
    ULONG attempt;

    status = NtQuerySystemInformation( SystemBasicInformation, &info, sizeof(info), NULL );
    if (status) return status;
    if (info.PageSize < XTAJIT64_GUEST_PAGE_SIZE ||
        info.PageSize > XTAJIT64_MAX_HOST_PAGE_SIZE ||
        (info.PageSize & (info.PageSize - 1)))
        return STATUS_INVALID_PARAMETER;
    /* Keep the bounded snapshot allocation for reuse.  Allocating and freeing
     * it inside every authoritative pass changes the very address space being
     * scanned and can prevent the outer generation retry from converging. */
    RtlAcquireSRWLockExclusive( &resync_snapshot_lock );
    if ((status = XTAJIT64_CALL( memory_snapshot_lock, NULL )))
    {
        RtlReleaseSRWLockExclusive( &resync_snapshot_lock );
        return status;
    }
    __TRY
    {
    snapshot->count = 0;
    for (attempt = 0; attempt < XTAJIT64_MAX_RESYNC_ATTEMPTS; ++attempt)
    {
        /* A concurrent map/protect/unmap after this token makes the commit
         * return STATUS_RETRY instead of republishing a stale snapshot. */
        if ((status = XTAJIT64_CALL( memory_resync_begin, &begin ))) break;
        status = collect_existing_mappings( (ULONG_PTR)info.LowestUserAddress,
                                            (ULONG_PTR)info.HighestUserAddress,
                                            info.PageSize, snapshot );
        if (status)
        {
            struct xtajit64_memory_resync_begin_params after;
            NTSTATUS query_status;

            snapshot->count = 0;
            /* A view can disappear between the basic and translated queries.
             * Retry only when the canonical generation proves concurrent change;
             * stable invalid mappings still fail closed. Never publish this pass. */
            if (status != STATUS_NOT_MAPPED_VIEW && status != STATUS_INVALID_ADDRESS) break;
            query_status = XTAJIT64_CALL( memory_resync_begin, &after );
            if (query_status) { status = query_status; break; }
            if (after.generation == begin.generation) break;
            TRACE( "retrying changed mapping snapshot after status %#lx\n", status );
            status = STATUS_RETRY;
            continue;
        }
        params.ranges = (ULONG_PTR)snapshot->ranges;
        params.generation = begin.generation;
        params.count = snapshot->count;
        status = XTAJIT64_CALL( memory_resync, &params );
        if (!status)
        {
            TRACE( "resynchronized %lu committed x64/native mapping runs through %p\n",
                   snapshot->count, info.HighestUserAddress );
            break;
        }
        snapshot->count = 0;
        if (status != STATUS_RETRY) break;
    }
    snapshot->count = 0;
    }
    __FINALLY( finish_mapping_snapshot );
    return status;
}

static NTSTATUS synchronize_mapping_window( ULONG_PTR lowest, ULONG_PTR highest )
{
    struct mapping_snapshot snapshot = {0};
    NTSTATUS status;
    ULONG i;

    if (!host_page_size || !lowest || highest <= lowest)
        return STATUS_INVALID_ADDRESS;
    status = collect_existing_mappings( lowest, highest - 1, host_page_size, &snapshot );
    for (i = 0; !status && i < snapshot.count; ++i)
        status = XTAJIT64_CALL( memory_map, &snapshot.ranges[i] );
    /* A window containing only a fixed-low view is intentionally absent from
     * the legacy identity snapshot. */
    free_mapping_snapshot( &snapshot );
    return status;
}

/* Reconcile the faulting committed region that may have been created by a native
 * Unixlib through ntdll.so.  Such a call does not cross the ARM64EC PE syscall
 * wrappers, so it cannot use NotifyMemoryAlloc.  A single targeted query keeps
 * this recovery off the normal transition path and distinguishes a real
 * committed mapping from a reserved, free, or otherwise invalid guest address.
 */
static NTSTATUS synchronize_fault_mapping( ULONG_PTR address, BOOL *mapped )
{
    struct xtajit64_memory_params params = {0};
    MEMORY_BASIC_INFORMATION info;
    ULONG_PTR region_start, region_end, start, end;
    NTSTATUS status;

    if (!mapped) return STATUS_INVALID_PARAMETER;
    *mapped = FALSE;
    if (!address || address > XTAJIT64_X64_USER_ADDRESS_MAX ||
        address > ~(ULONG_PTR)0 - XTAJIT64_GUEST_PAGE_SIZE)
        return STATUS_SUCCESS;
    status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)address,
                                   MemoryBasicInformation, &info, sizeof(info), NULL );
    if (status) return status;
    region_start = (ULONG_PTR)info.BaseAddress;
    if (!info.RegionSize || region_start > ~(ULONG_PTR)0 - info.RegionSize)
        return STATUS_INVALID_ADDRESS;
    region_end = region_start + info.RegionSize;
    if (info.State != MEM_COMMIT || !info.AllocationBase ||
        address < region_start || address >= region_end)
        return STATUS_SUCCESS;

    start = region_start;
    end = region_end;
    if (end - 1 > XTAJIT64_X64_USER_ADDRESS_MAX ||
        ((start | end) & (XTAJIT64_GUEST_PAGE_SIZE - 1)))
        return STATUS_INVALID_ADDRESS;
    status = describe_host_mapping( start, end - start,
                                    (ULONG_PTR)info.AllocationBase,
                                    info.Protect, &params );
    if (status == STATUS_ACCESS_DENIED) return STATUS_SUCCESS;
    if (status) return status;
    if (params.guest < XTAJIT64_GUEST_KUSER + host_page_size &&
        params.guest + params.size > XTAJIT64_GUEST_KUSER)
        return STATUS_SUCCESS;
    if ((status = XTAJIT64_CALL( memory_map, &params ))) return status;
    TRACE( "reconciled late x64 mapping fault %p region %p-%p protect %#lx\n",
           (void *)address, (void *)start, (void *)end, info.Protect );
    *mapped = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS get_current_thread_teb_window( ULONG_PTR *lowest, ULONG_PTR *highest,
                                               UINT64 *allocation_base )
{
    MEMORY_BASIC_INFORMATION info;
    ULONG_PTR teb = (ULONG_PTR)NtCurrentTeb();
    ULONG_PTR region_start, region_end, teb_end, start, end;
    NTSTATUS status;

    if (!lowest || !highest || !allocation_base || !host_page_size ||
        teb > ~(ULONG_PTR)0 - sizeof(TEB))
        return STATUS_INVALID_ADDRESS;
    status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)teb,
                                   MemoryBasicInformation, &info, sizeof(info), NULL );
    if (status) return status;
    region_start = (ULONG_PTR)info.BaseAddress;
    if (info.State != MEM_COMMIT || !info.AllocationBase || !info.RegionSize ||
        region_start > ~(ULONG_PTR)0 - info.RegionSize)
        return STATUS_INVALID_ADDRESS;
    region_end = region_start + info.RegionSize;
    teb_end = teb + sizeof(TEB);
    if (teb_end > ~(ULONG_PTR)0 - (host_page_size - 1)) return STATUS_INVALID_ADDRESS;
    start = teb & ~(ULONG_PTR)(host_page_size - 1);
    end = (teb_end + host_page_size - 1) & ~(ULONG_PTR)(host_page_size - 1);
    if (start < region_start || end > region_end || start >= end)
        return STATUS_INVALID_ADDRESS;
    *allocation_base = (ULONG_PTR)info.AllocationBase;
    *lowest = start;
    *highest = end;
    return STATUS_SUCCESS;
}

static NTSTATUS synchronize_current_thread_mappings(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    ULONG_PTR native_limit = (ULONG_PTR)NtCurrentTeb()->Tib.StackLimit;
    ULONG_PTR native_base = (ULONG_PTR)NtCurrentTeb()->Tib.StackBase;
    ULONG_PTR teb_limit, teb_base;
    UINT64 teb_allocation;
    NTSTATUS status;

    if ((status = get_current_thread_teb_window( &teb_limit, &teb_base,
                                                  &teb_allocation )))
        return status;
    if ((status = synchronize_mapping_window( teb_limit, teb_base ))) return status;
    if ((status = synchronize_mapping_window( native_limit, native_base ))) return status;
    if (cpu && cpu->EmulatorStackLimit && cpu->EmulatorStackBase > cpu->EmulatorStackLimit &&
        (cpu->EmulatorStackLimit < native_limit || cpu->EmulatorStackBase > native_base))
        status = synchronize_mapping_window( cpu->EmulatorStackLimit,
                                              cpu->EmulatorStackBase );
    return status;
}

static void unregister_thread_teb_window( ULONG_PTR lowest, ULONG_PTR highest )
{
    struct xtajit64_memory_params params =
    {
        .guest = lowest,
        .size = highest - lowest,
    };
    NTSTATUS status;

    if (!lowest || highest <= lowest || !__wine_unixlib_handle) return;
    if ((status = XTAJIT64_CALL( memory_unmap, &params )))
        poison_provider( "thread-TEB unregister", status );
}

static void unregister_thread_stack_allocation( ULONG_PTR allocation_base )
{
    struct xtajit64_memory_params params = { .guest = allocation_base };
    NTSTATUS status;

    if (!allocation_base || !host_page_size || !__wine_unixlib_handle) return;
    if ((status = XTAJIT64_CALL( memory_unmap, &params )))
        poison_provider( "thread-stack unregister", status );
}

static void flush_unicorn_cache( const void *addr, SIZE_T size )
{
    struct xtajit64_memory_params params =
    {
        .guest = (ULONG_PTR)addr,
        .size = size,
    };
    NTSTATUS status;

    if (addr && size && (ULONG_PTR)addr > ~(ULONG_PTR)0 - size)
    {
        poison_provider( "instruction-cache range", STATUS_INVALID_ADDRESS );
        return;
    }
    if (__wine_unixlib_handle &&
        (status = XTAJIT64_CALL( flush_instruction_cache, &params )))
        poison_provider( "instruction-cache synchronization", status );
}

static struct xtajit64_thread_state *get_thread_state(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    struct xtajit64_thread_state *state;

    if (!cpu || !(state = cpu->EmulatorData[0]) ||
        state->magic != XTAJIT64_THREAD_STATE_MAGIC)
        return NULL;
    return state;
}

static BOOL guest_range_to_host( UINT64 guest, SIZE_T size, ULONG required_access,
                                 ULONG_PTR *host )
{
    struct xtajit64_memory_translate_params params =
    {
        .address = guest,
        .size = size,
        .flags = XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST | required_access,
    };

    if (!host || (required_access & ~(XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ |
                                      XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE |
                                      XTAJIT64_MEMORY_TRANSLATE_REQUIRE_EXECUTE)) ||
        !size || guest > XTAJIT64_X64_USER_ADDRESS_MAX ||
        size - 1 > XTAJIT64_X64_USER_ADDRESS_MAX - guest ||
        !__wine_unixlib_handle || XTAJIT64_CALL( memory_translate, &params ) ||
        params.guest != guest)
        return FALSE;
    *host = (ULONG_PTR)params.host;
    return TRUE;
}

static BOOL cached_identity_stack_range( const struct xtajit64_thread_state *state,
                                         UINT64 guest, SIZE_T size, ULONG_PTR *host,
                                         UINT64 *limit_ret, UINT64 *base_ret )
{
    CHPE_V2_CPU_AREA_INFO *cpu;
    UINT64 generation, limit, base;
    TEB *teb;

    if (!state || state->magic != XTAJIT64_THREAD_STATE_MAGIC || !size ||
        guest > XTAJIT64_X64_USER_ADDRESS_MAX ||
        size - 1 > XTAJIT64_X64_USER_ADDRESS_MAX - guest)
        return FALSE;
    generation = current_transition_cache_generation();
    if (__atomic_load_n( &state->stack_cache_generation, __ATOMIC_ACQUIRE ) !=
        generation)
        return FALSE;
    limit = state->stack_cache_limit;
    base = state->stack_cache_base;
    if (__atomic_load_n( &state->stack_cache_generation, __ATOMIC_ACQUIRE ) !=
            generation || limit >= base || guest < limit || guest >= base ||
        size > base - guest)
        return FALSE;

    teb = NtCurrentTeb();
    if (!teb || !(cpu = teb->ChpeV2CpuAreaInfo) ||
        !((limit == cpu->EmulatorStackLimit && base == cpu->EmulatorStackBase) ||
          (limit == (ULONG_PTR)teb->Tib.StackLimit &&
           base == (ULONG_PTR)teb->Tib.StackBase)))
        return FALSE;
    if (host) *host = (ULONG_PTR)guest;
    if (limit_ret) *limit_ret = limit;
    if (base_ret) *base_ret = base;
    return TRUE;
}

static BOOL transition_guest_range_to_host( const struct xtajit64_thread_state *state,
                                            UINT64 guest, SIZE_T size,
                                            ULONG required_access, ULONG_PTR *host )
{
    if (!(required_access & XTAJIT64_MEMORY_TRANSLATE_REQUIRE_EXECUTE) &&
        cached_identity_stack_range( state, guest, size, host, NULL, NULL ))
        return TRUE;
    return guest_range_to_host( guest, size, required_access, host );
}

static NTSTATUS read_current_process_memory( void *dst, const void *src, SIZE_T size )
{
    volatile NTSTATUS status = STATUS_SUCCESS;

    __TRY
    {
        memcpy( dst, src, size );
    }
    __EXCEPT_PAGE_FAULT
    {
        status = STATUS_ACCESS_VIOLATION;
    }
    __ENDTRY
    return status;
}

static NTSTATUS write_current_process_memory( void *dst, const void *src, SIZE_T size )
{
    volatile NTSTATUS status = STATUS_SUCCESS;

    __TRY
    {
        memcpy( dst, src, size );
    }
    __EXCEPT_PAGE_FAULT
    {
        status = STATUS_ACCESS_VIOLATION;
    }
    __ENDTRY
    return status;
}

static NTSTATUS read_guest_u64( const struct xtajit64_thread_state *state,
                                UINT64 guest, UINT64 *value )
{
    ULONG_PTR host;

    if (!value || !transition_guest_range_to_host(
                      state, guest, sizeof(*value),
                      XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ, &host ))
        return STATUS_ACCESS_VIOLATION;
    return read_current_process_memory( value, (const void *)host, sizeof(*value) );
}

static NTSTATUS write_guest_u64( const struct xtajit64_thread_state *state,
                                 UINT64 guest, UINT64 value )
{
    ULONG_PTR host;

    if (!transition_guest_range_to_host(
            state, guest, sizeof(value),
            XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE, &host ))
    {
        BOOL mapped = FALSE;
        NTSTATUS status = synchronize_fault_mapping( guest, &mapped );
        if (status || !mapped || !transition_guest_range_to_host(
                state, guest, sizeof(value), XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE, &host ))
            return STATUS_ACCESS_VIOLATION;
    }
    return write_current_process_memory( (void *)host, &value, sizeof(value) );
}

struct xtajit64_x64_stack_probe
{
    UINT64 fresh_teb;
    UINT64 fresh_cpu;
    UINT64 translated_guest;
    UINT64 host_rsp;
    UINT64 allocation_base;
    UINT64 emulator_stack_limit;
    UINT64 emulator_stack_base;
    UINT64 teb_stack_limit;
    UINT64 teb_stack_base;
    UINT32 translation_status;
    UINT32 translation_domain;
    UINT32 stack_match_mask;
    BOOL probe_ran;
};

static BOOL get_x64_stack_bounds( struct xtajit64_thread_state *state, UINT64 rsp,
                                  UINT64 *limit, UINT64 *base,
                                  struct xtajit64_x64_stack_probe *result )
{
    struct xtajit64_memory_translate_params params =
    {
        .address = rsp,
        .size = sizeof(UINT64),
        .flags = XTAJIT64_MEMORY_TRANSLATE_GUEST_TO_HOST |
                 XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ,
    };
    TEB *teb;
    CHPE_V2_CPU_AREA_INFO *cpu;
    ULONG_PTR host_rsp;
    NTSTATUS status;
    UINT64 generation;
    UINT32 stack_match_mask = 0;

    /* Keep the recorder-disabled path identical to the production predicate.
     * In particular, do not move the post-Unixlib NtCurrentTeb() reads across
     * memory_translate: x18 preservation at that boundary is one of the
     * invariants this diagnostic exists to observe. */
    if (!result)
    {
        teb = NtCurrentTeb();
        cpu = teb ? teb->ChpeV2CpuAreaInfo : NULL;
        if (!cpu) return FALSE;
        if (cached_identity_stack_range( state, rsp, sizeof(UINT64), &host_rsp,
                                         limit, base ))
            return TRUE;
        if (rsp > XTAJIT64_X64_USER_ADDRESS_MAX ||
            sizeof(UINT64) - 1 > XTAJIT64_X64_USER_ADDRESS_MAX - rsp ||
            !__wine_unixlib_handle)
            return FALSE;
        generation = current_transition_cache_generation();
        if (XTAJIT64_CALL( memory_translate, &params ) || params.guest != rsp)
            return FALSE;
        host_rsp = params.host;
        if (host_rsp >= cpu->EmulatorStackLimit && host_rsp < cpu->EmulatorStackBase)
        {
            *limit = cpu->EmulatorStackLimit;
            *base = cpu->EmulatorStackBase;
        }
        else if (host_rsp >= (ULONG_PTR)teb->Tib.StackLimit &&
                 host_rsp < (ULONG_PTR)teb->Tib.StackBase)
        {
            *limit = (ULONG_PTR)teb->Tib.StackLimit;
            *base = (ULONG_PTR)teb->Tib.StackBase;
        }
        else if (params.exception_stack_limit && host_rsp >= params.exception_stack_limit &&
                 host_rsp < params.exception_stack_base)
        {
            *limit = params.exception_stack_limit;
            *base = params.exception_stack_base;
        }
        else return FALSE;

        /* Only identity-backed stacks can use their guest address directly in
         * later return-address and entry-stack operations.  Mapping callbacks
         * invalidate the generation before a freed or reprotected allocation
         * can be reused. */
        if (state && params.domain == XTAJIT64_MEMORY_ADDRESS_IDENTITY &&
            params.host == rsp &&
            current_transition_cache_generation() == generation)
        {
            __atomic_store_n( &state->stack_cache_generation, 0, __ATOMIC_RELEASE );
            state->stack_cache_limit = *limit;
            state->stack_cache_base = *base;
            __atomic_store_n( &state->stack_cache_generation, generation,
                              __ATOMIC_RELEASE );
        }
        return TRUE;
    }

    memset( result, 0xff, sizeof(*result) );
    result->fresh_cpu = 0;
    result->stack_match_mask = 0;
    result->probe_ran = FALSE;
    teb = NtCurrentTeb();
    result->fresh_teb = (ULONG_PTR)teb;
    if (!teb || !(cpu = teb->ChpeV2CpuAreaInfo)) return FALSE;
    result->fresh_cpu = (ULONG_PTR)cpu;
    result->emulator_stack_limit = cpu->EmulatorStackLimit;
    result->emulator_stack_base = cpu->EmulatorStackBase;
    result->probe_ran = TRUE;
    if (rsp > XTAJIT64_X64_USER_ADDRESS_MAX ||
        sizeof(UINT64) - 1 > XTAJIT64_X64_USER_ADDRESS_MAX - rsp)
        status = STATUS_INVALID_PARAMETER;
    else if (!__wine_unixlib_handle)
        status = STATUS_INVALID_HANDLE;
    else
        status = XTAJIT64_CALL( memory_translate, &params );
    result->translation_status = status;
    result->translated_guest = params.guest;
    result->host_rsp = params.host;
    result->allocation_base = params.allocation_base;
    result->translation_domain = params.domain;
    if (status || params.guest != rsp) return FALSE;

    if (params.host >= cpu->EmulatorStackLimit && params.host < cpu->EmulatorStackBase)
    {
        stack_match_mask |= XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR;
        *limit = cpu->EmulatorStackLimit;
        *base = cpu->EmulatorStackBase;
    }
    /* Sample the live TEB after the Unix call, at the same semantic point as
     * the original TEB-stack predicate.  On a rejected transition this makes
     * an x18 boundary failure distinguishable from a valid translation whose
     * host address simply belongs to neither accepted stack. */
    teb = NtCurrentTeb();
    result->fresh_teb = (ULONG_PTR)teb;
    result->fresh_cpu = teb ? (ULONG_PTR)teb->ChpeV2CpuAreaInfo : 0;
    if (teb)
    {
        result->teb_stack_limit = (ULONG_PTR)teb->Tib.StackLimit;
        result->teb_stack_base = (ULONG_PTR)teb->Tib.StackBase;
        if (params.host >= (ULONG_PTR)teb->Tib.StackLimit &&
            params.host < (ULONG_PTR)teb->Tib.StackBase)
        {
            stack_match_mask |= XTAJIT64_FLIGHT_STACK_MATCH_TEB;
            if (!(stack_match_mask & XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR))
            {
                *limit = (ULONG_PTR)teb->Tib.StackLimit;
                *base = (ULONG_PTR)teb->Tib.StackBase;
            }
        }
    }
    if (!stack_match_mask && params.exception_stack_limit &&
        params.host >= params.exception_stack_limit && params.host < params.exception_stack_base)
    {
        stack_match_mask = 4; /* authenticated thread-owned exception stack */
        *limit = params.exception_stack_limit;
        *base = params.exception_stack_base;
    }
    result->stack_match_mask = stack_match_mask;
    return !!stack_match_mask;
}

/* The opt-in is sampled once during ProcessInit.  Individual transitions only
 * test state->flight_recorder, so disabled execution neither touches the
 * recorder nor makes a Unixlib call, performs an OS query, or takes a lock. */
static void init_flight_recorder_enablement(void)
{
    static const WCHAR nameW[] = L"WINE_XTAJIT64_DIAGNOSTICS";
    static const WCHAR terminal_nameW[] = L"WINE_XTAJIT64_TERMINAL_DIAGNOSTICS";
    UNICODE_STRING name = { sizeof(nameW) - sizeof(*nameW), sizeof(nameW), (WCHAR *)nameW };
    UNICODE_STRING terminal_name =
    {
        sizeof(terminal_nameW) - sizeof(*terminal_nameW),
        sizeof(terminal_nameW), (WCHAR *)terminal_nameW
    };
    WCHAR valueW[2] = {0};
    UNICODE_STRING value = { 0, sizeof(valueW), valueW };

    flight_recorder_enabled = RtlQueryEnvironmentVariable_U( NULL, &name, &value ) ==
                              STATUS_SUCCESS && value.Length == sizeof(WCHAR) &&
                              valueW[0] == '1';
    value.Length = 0;
    valueW[0] = 0;
    terminal_diagnostics_enabled =
        RtlQueryEnvironmentVariable_U( NULL, &terminal_name, &value ) ==
            STATUS_SUCCESS && value.Length == sizeof(WCHAR) && valueW[0] == '1';
    flight_qpc_frequency.QuadPart = 0;
    if (flight_recorder_enabled)
    {
        LARGE_INTEGER counter;

        if (NtQueryPerformanceCounter( &counter, &flight_qpc_frequency ))
            flight_qpc_frequency.QuadPart = 0;
    }
}

static UINT64 flight_monotonic_timestamp_ns(void)
{
    LARGE_INTEGER counter;
    UINT64 frequency, ticks, seconds_ns, remainder_ns;

    if (flight_qpc_frequency.QuadPart <= 0 ||
        NtQueryPerformanceCounter( &counter, NULL ) || counter.QuadPart < 0)
        return XTAJIT64_FLIGHT_UNKNOWN_U64;
    frequency = flight_qpc_frequency.QuadPart;
    ticks = counter.QuadPart;
    /* QPC frequency is provider ABI input, not a host constant.  Check both
     * products before converting to nanoseconds. */
    if (ticks / frequency > ~(UINT64)0 / UINT64_C(1000000000) ||
        ticks % frequency > ~(UINT64)0 / UINT64_C(1000000000))
        return XTAJIT64_FLIGHT_UNKNOWN_U64;
    seconds_ns = ticks / frequency * UINT64_C(1000000000);
    remainder_ns = ticks % frequency * UINT64_C(1000000000) / frequency;
    /* UINT64_MAX is the explicit unavailable sentinel, so reject equality
     * as well as arithmetic overflow rather than returning an ambiguous time. */
    if (seconds_ns >= ~(UINT64)0 - remainder_ns)
        return XTAJIT64_FLIGHT_UNKNOWN_U64;
    return seconds_ns + remainder_ns;
}

static UINT64 flight_read_live_sp(void)
{
#ifdef XTAJIT64_HAVE_LIVE_ARM64_REGISTERS
    UINT64 value;

    __asm__ volatile( "mov %0, sp" : "=r" (value) : : "memory" );
    return value;
#else
    return XTAJIT64_FLIGHT_UNKNOWN_U64;
#endif
}

static UINT64 flight_read_live_x18(void)
{
#ifdef XTAJIT64_HAVE_LIVE_ARM64_REGISTERS
    UINT64 value;

    __asm__ volatile( "mov %0, x18" : "=r" (value) : : "memory" );
    return value;
#else
    return XTAJIT64_FLIGHT_UNKNOWN_U64;
#endif
}

static UINT64 flight_control_stack_limit( const struct xtajit64_thread_state *state )
{
    ULONG_PTR limit;

    /* Account for alignment rounding too: this helper is also used while
     * validating a damaged diagnostic state, before trusting its top field. */
    if (!state || (ULONG_PTR)state > ~(ULONG_PTR)0 - sizeof(*state) - 15)
        return XTAJIT64_FLIGHT_UNKNOWN_U64;
    limit = ((ULONG_PTR)state + sizeof(*state) + 15) & ~(ULONG_PTR)15;
    if (state->control_stack_top <= limit) return XTAJIT64_FLIGHT_UNKNOWN_U64;
    return limit;
}

static UINT32 flight_read_cpu_ownership( const struct xtajit64_thread_state *state,
                                         const TEB *teb )
{
    const CHPE_V2_CPU_AREA_INFO *cpu;
    ULONG *doorbell;
    UINT32 flags = 0;

    if (!state || !teb || !(cpu = teb->ChpeV2CpuAreaInfo))
        return XTAJIT64_FLIGHT_UNKNOWN_U32;
    if (*(const volatile BOOLEAN *)&cpu->InSimulation)
        flags |= XTAJIT64_FLIGHT_OWNERSHIP_SIMULATION_ACTIVE;
    if (*(const volatile BOOLEAN *)&cpu->InSyscallCallback)
        flags |= XTAJIT64_FLIGHT_OWNERSHIP_SYSCALL_CALLBACK;
    if ((doorbell = cpu->SuspendDoorbell))
    {
        flags |= XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_PRESENT;
        if (doorbell == &state->suspend_doorbell)
        {
            flags |= XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_OWNED;
            if (*(const volatile ULONG *)doorbell)
                flags |= XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_SET;
        }
    }
    return flags;
}

static BOOL flight_cpu_event_requires_control_stack( UINT32 type )
{
    switch (type)
    {
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_CAPTURE:
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_BEGIN:
    case XTAJIT64_FLIGHT_EVENT_CONTEXT_IMPORT:
    case XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN:
    case XTAJIT64_FLIGHT_EVENT_PROVIDER_RESUME:
    case XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP:
    case XTAJIT64_FLIGHT_EVENT_CONTEXT_EXPORT:
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_CONTINUE:
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_PUSH:
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_POP:
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_UNWIND:
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_RECONCILE:
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_STACK_CLASSIFY:
        return TRUE;
    default:
        return FALSE;
    }
}

static UINT32 flight_validate_cpu_stack( const struct xtajit64_flight_event *event )
{
    if (!(event->flags & XTAJIT64_FLIGHT_FLAG_EXPECT_PRIVATE_CONTROL_STACK))
        return XTAJIT64_FLIGHT_REASON_NONE;
    return xtajit64_flight_validate_private_control_stack(
        event->native_sp, event->control_stack_limit, event->control_stack_top,
        event->guest_stack_limit, event->guest_stack_base );
}

static UINT32 flight_validate_cpu_stack_values( const struct xtajit64_thread_state *state,
                                                UINT64 native_sp, UINT64 stack_limit,
                                                UINT64 stack_base, UINT32 type )
{
    if (!state || !flight_cpu_event_requires_control_stack( type ))
        return XTAJIT64_FLIGHT_REASON_NONE;
    return xtajit64_flight_validate_private_control_stack(
        native_sp, flight_control_stack_limit( state ), state->control_stack_top,
        stack_limit, stack_base );
}

static struct xtajit64_flight_event *flight_acquire_cpu_event(
    struct xtajit64_thread_state *state, struct xtajit64_flight_recorder **recorder,
    struct xtajit64_flight_scratch **scratch )
{
    if (recorder) *recorder = NULL;
    if (scratch) *scratch = NULL;
    if (!recorder || !flight_has_valid_recorder( state )) return NULL;
    *recorder = state->flight_recorder;
    if (!xtajit64_flight_recorder_is_active( *recorder ))
    {
        *recorder = NULL;
        return NULL;
    }
    return xtajit64_flight_acquire_scratch( *recorder, scratch );
}

static void flight_init_cpu_event( struct xtajit64_flight_event *event,
                                   const struct xtajit64_thread_state *state,
                                   const ARM64EC_NT_CONTEXT *ec_context,
                                   const AMD64_CONTEXT *context,
                                   UINT64 stack_limit, UINT64 stack_base,
                                   UINT32 type )
{
    const TEB *teb = NULL;
    UINT64 timestamp;

    xtajit64_flight_event_init( event, type, XTAJIT64_FLIGHT_SOURCE_ARM64EC_PE );
    event->causal_boundary_id = state->flight_causal_boundary_id;
    event->context_generation = state->flight_context_generation;
    event->transition_generation = state->flight_transition_generation;
    event->guest_stack_limit = stack_limit;
    event->guest_stack_base = stack_base;
    event->control_stack_limit = flight_control_stack_limit( state );
    event->control_stack_top = state->control_stack_top;
    if (state->flight_teb_authenticated && state->flight_expected_teb &&
        state->flight_expected_teb != XTAJIT64_FLIGHT_UNKNOWN_U64)
    {
        event->expected_teb = state->flight_expected_teb;
        event->flags |= XTAJIT64_FLIGHT_FLAG_EXPECTED_TEB_AUTHENTICATED;
    }
    /* Do not dereference a fresh ARM64EC NtCurrentTeb(): it aliases the live
     * x18 value being checked.  The stable initial claim becomes safe identity
     * data only after Unix flight_bind authenticated it independently. */
    if (state->flight_teb_authenticated && state->flight_expected_teb &&
        state->flight_expected_teb != XTAJIT64_FLIGHT_UNKNOWN_U64)
    {
        teb = (const TEB *)(ULONG_PTR)state->flight_expected_teb;
        event->pid = (ULONG_PTR)teb->ClientId.UniqueProcess;
        event->wine_tid = (ULONG_PTR)teb->ClientId.UniqueThread;
        event->ownership_flags = flight_read_cpu_ownership( state, teb );
    }
    event->native_sp = flight_read_live_sp();
    event->native_frame = (UINT64)(ULONG_PTR)__builtin_frame_address( 0 );
    event->native_pc = (UINT64)(ULONG_PTR)__builtin_return_address( 0 );
    event->x18_value = flight_read_live_x18();
    /* There is no supported PE-side mode query at this CPU boundary.  The
     * numeric value is useful evidence, but it never implies an ABI mode. */
    event->custom_x18_mode = XTAJIT64_FLIGHT_X18_MODE_UNKNOWN;
    event->x18_expectation = XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC;
    if (flight_cpu_event_requires_control_stack( type ))
        event->flags |= XTAJIT64_FLIGHT_FLAG_EXPECT_PRIVATE_CONTROL_STACK;
    if (ec_context) event->arm64ec_pc = ec_context->Pc;
    if (context)
    {
        event->guest_rip = context->Rip;
        event->guest_rsp = context->Rsp;
        event->context_flags = context->ContextFlags;
        event->mxcsr = context->MxCsr;
        event->fltsave_mxcsr = context->FltSave.MxCsr;
        event->flags &= ~XTAJIT64_FLIGHT_FLAG_CONTEXT_FLAGS_UNKNOWN;
    }
    timestamp = flight_monotonic_timestamp_ns();
    if (timestamp != XTAJIT64_FLIGHT_UNKNOWN_U64)
    {
        event->monotonic_timestamp_ns = timestamp;
        event->flags &= ~XTAJIT64_FLIGHT_FLAG_TIME_UNAVAILABLE;
    }
}

static BOOL flight_record_cpu_event( struct xtajit64_thread_state *state,
                                     const ARM64EC_NT_CONTEXT *ec_context,
                                     const AMD64_CONTEXT *context,
                                     UINT64 stack_limit, UINT64 stack_base,
                                     UINT64 detail0, UINT64 detail1,
                                     UINT32 type, UINT32 reason )
{
    struct xtajit64_flight_recorder *recorder;
    struct xtajit64_flight_scratch *scratch;
    struct xtajit64_flight_event *event;
    BOOL recorded;

    if (!(event = flight_acquire_cpu_event( state, &recorder, &scratch )))
    {
        if (!recorder || !xtajit64_flight_recorder_is_active( recorder )) return FALSE;
        if (!reason && state && state->flight_teb_authenticated &&
            type == XTAJIT64_FLIGHT_EVENT_TRANSITION_CAPTURE)
            reason = xtajit64_flight_validate_x18(
                XTAJIT64_FLIGHT_X18_MODE_UNKNOWN,
                XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
                state->capture_x18, state->flight_expected_teb );
        if (!reason && state)
            reason = flight_validate_cpu_stack_values( state, flight_read_live_sp(),
                                                        stack_limit, stack_base, type );
        if (reason && xtajit64_flight_recorder_is_active( recorder ))
            xtajit64_flight_freeze( recorder, reason );
        return FALSE;
    }
    flight_init_cpu_event( event, state, ec_context, context, stack_limit, stack_base, type );
    if (!reason && state->flight_teb_authenticated &&
        type == XTAJIT64_FLIGHT_EVENT_TRANSITION_CAPTURE)
        reason = xtajit64_flight_validate_x18(
            XTAJIT64_FLIGHT_X18_MODE_UNKNOWN,
            XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
            state->capture_x18, state->flight_expected_teb );
    if (!reason) reason = flight_validate_cpu_stack( event );
    event->reason = reason;
    event->detail0 = detail0;
    event->detail1 = detail1;
    if (type == XTAJIT64_FLIGHT_EVENT_TRANSITION_CAPTURE)
    {
        event->saved_x18_value = state->capture_x18;
        event->flags &= ~XTAJIT64_FLIGHT_FLAG_SAVED_X18_UNKNOWN;
        event->flags |= XTAJIT64_FLIGHT_FLAG_PE_X18_CLAIM_PRESENT;
    }
    if (reason) recorded = xtajit64_flight_record_and_freeze( recorder, event, reason );
    else recorded = !!xtajit64_flight_record( recorder, event );
    xtajit64_flight_release_scratch( scratch );
    return recorded;
}

static void flight_record_transition_stack_violation(
    struct xtajit64_thread_state *state, const ARM64EC_NT_CONTEXT *ec_context,
    const AMD64_CONTEXT *context, const TEB *expected_teb,
    const CHPE_V2_CPU_AREA_INFO *expected_cpu, UINT64 gs_base,
    const struct xtajit64_x64_stack_probe *probe )
{
    struct xtajit64_flight_transition_stack_violation violation;
    struct xtajit64_flight_recorder *recorder;
    struct xtajit64_flight_scratch *scratch;
    struct xtajit64_flight_event *event;
    UINT32 count, index, reject;

    if (!state || !probe) return;
    if (!(event = flight_acquire_cpu_event( state, &recorder, &scratch )))
    {
        if (recorder && xtajit64_flight_recorder_is_active( recorder ))
            xtajit64_flight_freeze( recorder,
                                   XTAJIT64_FLIGHT_REASON_TRANSITION_STACK );
        return;
    }

    memset( &violation, 0xff, sizeof(violation) );
    violation.guest_rip = context ? context->Rip : XTAJIT64_FLIGHT_UNKNOWN_U64;
    violation.guest_rsp = context ? context->Rsp : XTAJIT64_FLIGHT_UNKNOWN_U64;
    violation.gs_base = gs_base;
    violation.expected_teb = (ULONG_PTR)expected_teb;
    violation.fresh_teb = probe->fresh_teb;
    violation.expected_cpu = (ULONG_PTR)expected_cpu;
    violation.fresh_cpu = probe->fresh_cpu;
    violation.translated_guest = probe->translated_guest;
    violation.host_rsp = probe->host_rsp;
    violation.allocation_base = probe->allocation_base;
    violation.emulator_stack_limit = probe->emulator_stack_limit;
    violation.emulator_stack_base = probe->emulator_stack_base;
    violation.teb_stack_limit = probe->teb_stack_limit;
    violation.teb_stack_base = probe->teb_stack_base;
    violation.causal_boundary_id = state->flight_causal_boundary_id;
    violation.context_generation = state->flight_context_generation;
    violation.transition_generation = state->flight_transition_generation;
    violation.translation_status = probe->probe_ran ? probe->translation_status :
                                                     XTAJIT64_FLIGHT_UNKNOWN_U32;
    violation.translation_domain = probe->probe_ran ? probe->translation_domain :
                                                     XTAJIT64_FLIGHT_UNKNOWN_U32;
    violation.stack_match_mask = probe->stack_match_mask;
    violation.capture_kind = state->capture_kind;
    violation.depth = state->depth;
    count = min( state->depth, XTAJIT64_FLIGHT_MAX_TRANSITION_FRAMES );
    violation.frame_count = count;
    violation.reserved = XTAJIT64_FLIGHT_UNKNOWN_U32;
    for (index = 0; index < count; ++index)
    {
        const struct xtajit64_transition_frame *frame = &state->frames[index];
        struct xtajit64_flight_transition_frame_snapshot *snapshot =
            &violation.frames[index];

        snapshot->guest_rsp = frame->guest_rsp;
        snapshot->native_sp = frame->native_sp;
        snapshot->native_pc = frame->native_pc;
        snapshot->kind = frame->kind;
        snapshot->depth = index + 1;
    }
    reject = xtajit64_flight_classify_transition_stack(
        violation.guest_rip, violation.guest_rsp, violation.gs_base,
        XTAJIT64_X64_USER_ADDRESS_MAX, violation.expected_teb,
        violation.fresh_teb, violation.expected_cpu, violation.fresh_cpu,
        probe->probe_ran, violation.translation_status,
        violation.translated_guest, violation.stack_match_mask, violation.depth );
    violation.reject_mask = reject;

    flight_init_cpu_event( event, state, ec_context, context,
                           XTAJIT64_FLIGHT_UNKNOWN_U64,
                           XTAJIT64_FLIGHT_UNKNOWN_U64,
                           XTAJIT64_FLIGHT_EVENT_TRANSITION_STACK_CLASSIFY );
    event->reason = XTAJIT64_FLIGHT_REASON_TRANSITION_STACK;
    event->detail0 = reject;
    event->detail1 = (UINT64)violation.translation_status |
                     (UINT64)violation.stack_match_mask << 32;
    event->transition_depth_before = state->depth;
    event->transition_depth_after = state->depth;
    xtajit64_flight_record_transition_stack_violation_and_freeze(
        recorder, event, &violation );
    xtajit64_flight_release_scratch( scratch );
}

/* Frame records are a distinct diagnostic contract.  Do not overload a
 * provider stop reason or an implementation-reserved field: non-local
 * re-entry needs the exact frame kind and before/after depth to be readable
 * across a later provider resume. */
static void flight_record_transition_frame_event(
    struct xtajit64_thread_state *state, const ARM64EC_NT_CONTEXT *ec_context,
    const AMD64_CONTEXT *context, UINT64 stack_limit, UINT64 stack_base,
    UINT32 type, UINT32 reason, UINT32 kind, UINT32 depth_before, UINT32 depth_after,
    UINT64 guest_rsp, UINT64 native_sp, UINT64 native_pc )
{
    struct xtajit64_flight_recorder *recorder;
    struct xtajit64_flight_scratch *scratch;
    struct xtajit64_flight_event *event;

    if (!(event = flight_acquire_cpu_event( state, &recorder, &scratch )))
    {
        if (!recorder || !xtajit64_flight_recorder_is_active( recorder )) return;
        if (!reason && state)
            reason = flight_validate_cpu_stack_values( state, flight_read_live_sp(),
                                                        stack_limit, stack_base, type );
        if (reason && xtajit64_flight_recorder_is_active( recorder ))
            xtajit64_flight_freeze( recorder, reason );
        return;
    }
    flight_init_cpu_event( event, state, ec_context, context, stack_limit, stack_base, type );
    if (!reason) reason = flight_validate_cpu_stack( event );
    event->reason = reason;
    event->transition_frame_kind = kind;
    event->transition_depth_before = depth_before;
    event->transition_depth_after = depth_after;
    event->guest_rsp = guest_rsp;
    event->detail0 = native_sp;
    event->detail1 = native_pc;
    if (reason) xtajit64_flight_record_and_freeze( recorder, event, reason );
    else xtajit64_flight_record( recorder, event );
    xtajit64_flight_release_scratch( scratch );
}

static void flight_record_transition_frame_push(
    struct xtajit64_thread_state *state, const ARM64EC_NT_CONTEXT *ec_context,
    const AMD64_CONTEXT *context, UINT64 stack_limit, UINT64 stack_base,
    const struct xtajit64_transition_frame *frame, UINT32 depth_before, UINT32 depth_after,
    UINT64 native_sp, UINT64 native_pc )
{
    if (!frame) return;
    flight_record_transition_frame_event( state, ec_context, context, stack_limit, stack_base,
                                          XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_PUSH,
                                          XTAJIT64_FLIGHT_REASON_NONE, frame->kind,
                                          depth_before, depth_after, frame->guest_rsp,
                                          native_sp, native_pc );
}

/* This is intentionally reusable by the non-local restoration work that is
 * currently outside the clean base.  Its caller owns the actual frame-array
 * mutation and supplies the old/new depth; the recorder only observes it.
 * Rebase hook: call once for every discarded or reconciled frame in the
 * BeginSimulation/NtContinue frame-discard loop. */
static void flight_reconcile_transition_frame(
    struct xtajit64_thread_state *state, const ARM64EC_NT_CONTEXT *ec_context,
    const AMD64_CONTEXT *context, UINT64 stack_limit, UINT64 stack_base,
    const struct xtajit64_transition_frame *frame, UINT32 depth_before, UINT32 depth_after,
    BOOL reconciled )
{
    if (!frame) return;
    flight_record_transition_frame_event(
        state, ec_context, context, stack_limit, stack_base,
        reconciled ? XTAJIT64_FLIGHT_EVENT_TRANSITION_RECONCILE :
                     XTAJIT64_FLIGHT_EVENT_TRANSITION_UNWIND,
        XTAJIT64_FLIGHT_REASON_NONE, frame->kind, depth_before, depth_after,
        frame->guest_rsp, frame->native_sp, frame->native_pc );
}

static void flight_pop_transition_frame(
    struct xtajit64_thread_state *state, const ARM64EC_NT_CONTEXT *ec_context,
    const AMD64_CONTEXT *context, UINT64 stack_limit, UINT64 stack_base )
{
    struct xtajit64_transition_frame *frame;
    UINT32 depth_before;

    if (!state || !state->depth) return;
    depth_before = state->depth;
    frame = &state->frames[depth_before - 1];
    /* Keep the frame owned while the recorder builds its bounded payload.
     * A signal/non-local re-entry can otherwise see the decremented depth and
     * reuse this slot before the helper has copied its evidence.  A normal
     * return still performs exactly the original depth mutation below. */
    flight_record_transition_frame_event( state, ec_context, context, stack_limit, stack_base,
                                          XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_POP,
                                          XTAJIT64_FLIGHT_REASON_NONE, frame->kind,
                                          depth_before, depth_before - 1, frame->guest_rsp,
                                          frame->native_sp, frame->native_pc );
    --state->depth;
}

static UINT32 flight_validate_cpu_context( const AMD64_CONTEXT *context,
                                            UINT64 stack_limit, UINT64 stack_base,
                                            UINT64 continuation_target,
                                            UINT64 continuation_pc,
                                            UINT64 continuation_rsp )
{
    if (!context) return XTAJIT64_FLIGHT_REASON_CONTEXT_RIP;
    return xtajit64_flight_validate_context( context->ContextFlags,
                                             CONTEXT_AMD64_FULL |
                                             CONTEXT_AMD64_FLOATING_POINT,
                                             context->MxCsr, context->FltSave.MxCsr,
                                             context->Rip, context->Rsp,
                                             XTAJIT64_X64_USER_ADDRESS_MAX,
                                             stack_limit, stack_base,
                                             continuation_target, continuation_pc,
                                             continuation_rsp );
}

static void flight_watch_cpu_context( struct xtajit64_thread_state *state,
                                      const ARM64EC_NT_CONTEXT *ec_context,
                                      const AMD64_CONTEXT *context,
                                      UINT64 stack_limit, UINT64 stack_base,
                                      UINT64 continuation_target,
                                      UINT64 continuation_pc,
                                      UINT64 continuation_rsp, UINT32 type )
{
    UINT32 reason;

    if (!flight_has_active_recorder( state )) return;
    reason = flight_validate_cpu_context( context, stack_limit, stack_base,
                                           continuation_target, continuation_pc,
                                           continuation_rsp );
    flight_record_cpu_event( state, ec_context, context, stack_limit, stack_base,
                             continuation_pc, continuation_rsp, type, reason );
}

static void flight_watch_cpu_x18( struct xtajit64_thread_state *state,
                                  const ARM64EC_NT_CONTEXT *ec_context,
                                  const AMD64_CONTEXT *context,
                                  UINT64 stack_limit, UINT64 stack_base,
                                  UINT32 type )
{
    struct xtajit64_flight_recorder *recorder;
    struct xtajit64_flight_scratch *scratch;
    struct xtajit64_flight_event *event;
    UINT32 reason;

    if (!(event = flight_acquire_cpu_event( state, &recorder, &scratch )))
    {
        if (!recorder || !xtajit64_flight_recorder_is_active( recorder )) return;
        reason = state && state->flight_teb_authenticated ?
            xtajit64_flight_validate_x18(
                XTAJIT64_FLIGHT_X18_MODE_UNKNOWN,
                XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
                flight_read_live_x18(), state->flight_expected_teb ) :
            XTAJIT64_FLIGHT_REASON_NONE;
        if (!reason && state)
            reason = flight_validate_cpu_stack_values( state, flight_read_live_sp(),
                                                        stack_limit, stack_base, type );
        if (reason && xtajit64_flight_recorder_is_active( recorder ))
            xtajit64_flight_freeze( recorder, reason );
        return;
    }
    flight_init_cpu_event( event, state, ec_context, context, stack_limit, stack_base, type );
    reason = state->flight_teb_authenticated ?
        xtajit64_flight_validate_x18( event->custom_x18_mode,
                                      event->x18_expectation, event->x18_value,
                                      state->flight_expected_teb ) :
        XTAJIT64_FLIGHT_REASON_NONE;
    if (!reason) reason = flight_validate_cpu_stack( event );
    event->reason = reason;
    if (reason) xtajit64_flight_record_and_freeze( recorder, event, reason );
    else xtajit64_flight_record( recorder, event );
    xtajit64_flight_release_scratch( scratch );
}

/* Rendering is deliberately deferred to ordinary C code after a Unixlib call
 * returns (or a terminal abort path).  Producers and watchdogs only write the
 * binary ring; they never recurse through Wine exception handling or logging. */
static const char *flight_event_type_name( UINT32 type )
{
    switch (type)
    {
    case XTAJIT64_FLIGHT_EVENT_NONE: return "none";
    case XTAJIT64_FLIGHT_EVENT_RECORDER_READY: return "recorder-ready";
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_CAPTURE: return "transition-capture";
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_BEGIN: return "transition-begin";
    case XTAJIT64_FLIGHT_EVENT_CONTEXT_IMPORT: return "context-import";
    case XTAJIT64_FLIGHT_EVENT_UNIX_ENTERED_SYSTEM_MODE: return "unix-system-mode";
    case XTAJIT64_FLIGHT_EVENT_BINDING: return "binding";
    case XTAJIT64_FLIGHT_EVENT_ENGINE_ACQUIRE: return "engine-acquire";
    case XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN: return "provider-begin";
    case XTAJIT64_FLIGHT_EVENT_PROVIDER_RESUME: return "provider-resume";
    case XTAJIT64_FLIGHT_EVENT_ATOMIC_EXIT: return "atomic-exit";
    case XTAJIT64_FLIGHT_EVENT_ATOMIC_REENTRY: return "atomic-reentry";
    case XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP: return "provider-stop";
    case XTAJIT64_FLIGHT_EVENT_CONTEXT_EXPORT: return "context-export";
    case XTAJIT64_FLIGHT_EVENT_ENGINE_RELEASE: return "engine-release";
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_CONTINUE: return "transition-continue";
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_PUSH: return "frame-push";
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_POP: return "frame-pop";
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_UNWIND: return "frame-unwind";
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_RECONCILE: return "frame-reconcile";
    case XTAJIT64_FLIGHT_EVENT_MAPPING_GENERATION: return "mapping-generation";
    case XTAJIT64_FLIGHT_EVENT_SUSPEND_REQUEST: return "suspend-request";
    case XTAJIT64_FLIGHT_EVENT_SUSPEND_ACKNOWLEDGED: return "suspend-ack";
    case XTAJIT64_FLIGHT_EVENT_TRANSITION_STACK_CLASSIFY: return "transition-stack-classify";
    case XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION: return "watchdog";
    default: return "unknown";
    }
}

static const char *flight_reason_name( UINT32 reason )
{
    switch (reason)
    {
    case XTAJIT64_FLIGHT_REASON_NONE: return "none";
    case XTAJIT64_FLIGHT_REASON_CONTEXT_FLAGS: return "context-flags";
    case XTAJIT64_FLIGHT_REASON_CONTEXT_MXCSR: return "context-mxcsr";
    case XTAJIT64_FLIGHT_REASON_CONTEXT_RIP: return "context-rip";
    case XTAJIT64_FLIGHT_REASON_CONTEXT_RSP: return "context-rsp";
    case XTAJIT64_FLIGHT_REASON_CONTEXT_STACK: return "context-stack";
    case XTAJIT64_FLIGHT_REASON_TRANSITION_STACK: return "transition-stack";
    case XTAJIT64_FLIGHT_REASON_CONTINUATION_PAIR: return "continuation-pair";
    case XTAJIT64_FLIGHT_REASON_CONTEXT_STALE_PUBLICATION: return "context-stale";
    case XTAJIT64_FLIGHT_REASON_X18_MODE: return "x18-mode";
    case XTAJIT64_FLIGHT_REASON_X18_VALUE: return "x18-value";
    case XTAJIT64_FLIGHT_REASON_TRANSITION_DEPTH: return "transition-depth";
    case XTAJIT64_FLIGHT_REASON_TERMINAL_ABORT: return "terminal-abort";
    case XTAJIT64_FLIGHT_REASON_RECORDER_WRAP: return "recorder-wrap";
    case XTAJIT64_FLIGHT_REASON_RECORDER_INVALID: return "recorder-invalid";
    case XTAJIT64_FLIGHT_REASON_SIMULATION_OWNERSHIP: return "simulation-ownership";
    default: return "unknown";
    }
}

static const char *flight_ownership_bit_name( UINT32 flags, UINT32 bit )
{
    if (flags == XTAJIT64_FLIGHT_UNKNOWN_U32) return "unknown";
    return flags & bit ? "yes" : "no";
}

static const char *flight_stop_reason_name( UINT32 reason )
{
    switch (reason)
    {
    case XTAJIT64_STOP_NONE: return "none";
    case XTAJIT64_STOP_EC_TRANSITION: return "ec-transition";
    case XTAJIT64_STOP_SYSCALL: return "syscall";
    case XTAJIT64_STOP_MEMORY_FAULT: return "memory-fault";
    case XTAJIT64_STOP_MAPPING_MISS: return "mapping-miss";
    case XTAJIT64_STOP_INVALID_INSTRUCTION: return "invalid-instruction";
    case XTAJIT64_STOP_UNSUPPORTED_TRANSITION: return "unsupported-transition";
    case XTAJIT64_STOP_INTERNAL_ERROR: return "internal-error";
    default: return "unknown";
    }
}

static const char *flight_x18_mode_name( UINT32 mode )
{
    switch (mode)
    {
    case XTAJIT64_FLIGHT_X18_MODE_UNKNOWN: return "unknown";
    case XTAJIT64_FLIGHT_X18_MODE_DISABLED: return "disabled";
    case XTAJIT64_FLIGHT_X18_MODE_ENABLED: return "enabled";
    default: return "invalid";
    }
}

static const char *flight_x18_expectation_name( UINT32 expectation )
{
    switch (expectation)
    {
    case XTAJIT64_FLIGHT_X18_EXPECTATION_UNKNOWN: return "unknown";
    case XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM: return "native-system";
    case XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC: return "pe-arm64ec";
    default: return "invalid";
    }
}

static void flight_dump_event( const char *prefix, const struct xtajit64_flight_event *event )
{
    ERR( "xtajit64 diagnostic %s seq %#llx ts %#llx src %u type %s/%u reason %s/%u "
         "stop %s/%u "
         "causal %#llx binding %#llx engine %#llx/%#llx map %#llx ctx %#llx trans %#llx\n",
         prefix, event->sequence, event->monotonic_timestamp_ns, event->source,
         flight_event_type_name( event->event_type ), event->event_type,
         flight_reason_name( event->reason ), event->reason,
         flight_stop_reason_name( event->stop_reason ), event->stop_reason,
         event->causal_boundary_id, event->binding_id, event->engine_id,
         event->engine_generation, event->mapping_generation,
         event->context_generation, event->transition_generation );
    ERR( "xtajit64 diagnostic %s guest rip %#llx rsp %#llx stack %#llx-%#llx arm-pc %#llx "
         "native pc %#llx sp %#llx frame %#llx control %#llx-%#llx "
         "x18 %#llx saved %#llx teb %#llx mode %s/%u expectation %s/%u detail %#llx/%#llx "
         "frame %u depth %u->%u\n",
         prefix, event->guest_rip, event->guest_rsp, event->guest_stack_limit,
         event->guest_stack_base, event->arm64ec_pc, event->native_pc,
         event->native_sp, event->native_frame, event->control_stack_limit,
         event->control_stack_top, event->x18_value, event->saved_x18_value,
         event->expected_teb, flight_x18_mode_name( event->custom_x18_mode ),
         event->custom_x18_mode, flight_x18_expectation_name( event->x18_expectation ),
         event->x18_expectation,
         event->detail0, event->detail1, event->transition_frame_kind,
         event->transition_depth_before, event->transition_depth_after );
    ERR( "xtajit64 diagnostic %s pid %#llx tid %#llx mach %#llx pthread %#llx "
         "context-flags %#x mxcsr %#x fltsave-mxcsr %#x flags %#x ownership %#x "
         "simulation %s callback %s doorbell present/owned/set %s/%s/%s teb-auth %u\n",
         prefix, event->pid, event->wine_tid, event->mach_thread_id,
         event->pthread_identity, event->context_flags, event->mxcsr,
         event->fltsave_mxcsr, event->flags, event->ownership_flags,
         flight_ownership_bit_name( event->ownership_flags,
                                    XTAJIT64_FLIGHT_OWNERSHIP_SIMULATION_ACTIVE ),
         flight_ownership_bit_name( event->ownership_flags,
                                    XTAJIT64_FLIGHT_OWNERSHIP_SYSCALL_CALLBACK ),
         flight_ownership_bit_name( event->ownership_flags,
                                    XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_PRESENT ),
         flight_ownership_bit_name( event->ownership_flags,
                                    XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_OWNED ),
         flight_ownership_bit_name( event->ownership_flags,
                                    XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_SET ),
         (unsigned int)!!(event->flags & XTAJIT64_FLIGHT_FLAG_EXPECTED_TEB_AUTHENTICATED) );
}

static void flight_dump_transition_stack_violation(
    const struct xtajit64_flight_recorder *recorder )
{
    struct xtajit64_flight_transition_stack_violation violation;
    UINT32 index, reject;

    if (!xtajit64_flight_snapshot_transition_stack_violation( recorder, &violation ))
        return;
    reject = violation.reject_mask;
    ERR( "xtajit64 diagnostic transition-stack-classify reject %#x "
         "rip/rsp/gs %u/%u/%u teb/cpu %u/%u translate %u guest %u stack %u "
         "probe %u depth %u\n",
         reject,
         !!(reject & XTAJIT64_FLIGHT_STACK_REJECT_RIP_RANGE),
         !!(reject & XTAJIT64_FLIGHT_STACK_REJECT_RSP_RANGE),
         !!(reject & XTAJIT64_FLIGHT_STACK_REJECT_GS_RANGE),
         !!(reject & XTAJIT64_FLIGHT_STACK_REJECT_TEB_IDENTITY),
         !!(reject & (XTAJIT64_FLIGHT_STACK_REJECT_CPU_MISSING |
                      XTAJIT64_FLIGHT_STACK_REJECT_CPU_IDENTITY)),
         !!(reject & XTAJIT64_FLIGHT_STACK_REJECT_TRANSLATE_STATUS),
         !!(reject & XTAJIT64_FLIGHT_STACK_REJECT_TRANSLATED_GUEST),
         !!(reject & XTAJIT64_FLIGHT_STACK_REJECT_STACK_RANGE),
         !!(reject & XTAJIT64_FLIGHT_STACK_REJECT_PROBE_NOT_RUN),
         !!(reject & XTAJIT64_FLIGHT_STACK_REJECT_FRAME_DEPTH) );
    ERR( "xtajit64 diagnostic transition-stack-classify guest rip %#llx rsp %#llx "
         "gs %#llx expected/fresh teb %#llx/%#llx expected/fresh cpu %#llx/%#llx\n",
         violation.guest_rip, violation.guest_rsp, violation.gs_base,
         violation.expected_teb, violation.fresh_teb,
         violation.expected_cpu, violation.fresh_cpu );
    ERR( "xtajit64 diagnostic transition-stack-classify translate status %#x "
         "domain %#x guest %#llx host %#llx allocation %#llx match %#x "
         "emulator %#llx-%#llx teb %#llx-%#llx\n",
         violation.translation_status, violation.translation_domain,
         violation.translated_guest, violation.host_rsp, violation.allocation_base,
         violation.stack_match_mask, violation.emulator_stack_limit,
         violation.emulator_stack_base, violation.teb_stack_limit,
         violation.teb_stack_base );
    ERR( "xtajit64 diagnostic transition-stack-classify causal %#llx ctx %#llx "
         "trans %#llx capture %u depth %u frames %u\n",
         violation.causal_boundary_id, violation.context_generation,
         violation.transition_generation, violation.capture_kind,
         violation.depth, violation.frame_count );
    for (index = 0; index < violation.frame_count; ++index)
    {
        const struct xtajit64_flight_transition_frame_snapshot *frame =
            &violation.frames[index];

        ERR( "xtajit64 diagnostic transition-stack-frame depth %u kind %u "
             "guest-rsp %#llx native-sp %#llx native-pc %#llx\n",
             frame->depth, frame->kind, frame->guest_rsp,
             frame->native_sp, frame->native_pc );
    }
}

static void flight_dump_if_frozen( struct xtajit64_thread_state *state, const char *where )
{
    struct xtajit64_flight_snapshot_metadata metadata;
    struct xtajit64_flight_recorder *recorder;
    struct xtajit64_flight_scratch *scratch;
    struct xtajit64_flight_event *event;
    UINT64 sequence;
    UINT64 lost;
    UINT32 expected = 0;
    UINT32 committed = 0, torn = 0, snapshot_state;

    if (!flight_recorder_enabled || !flight_has_valid_recorder( state )) return;
    recorder = state->flight_recorder;
    if (__atomic_load_n( &recorder->freeze_state, __ATOMIC_ACQUIRE ) != 1)
        return;
    /* A previous renderer owns or completed this one-shot dump.  Check before
     * borrowing recorder scratch so later terminal paths remain observationally
     * quiet.  The CAS below stays after acquisition: temporary scratch
     * exhaustion must not suppress the first usable dump forever. */
    if (__atomic_load_n( &state->flight_dump_state, __ATOMIC_ACQUIRE )) return;
    if (!(event = xtajit64_flight_acquire_scratch( recorder, &scratch ))) return;
    if (!__atomic_compare_exchange_n( &state->flight_dump_state, &expected, 1, FALSE,
                                      __ATOMIC_ACQ_REL, __ATOMIC_RELAXED ))
    {
        xtajit64_flight_release_scratch( scratch );
        return;
    }
    if (!xtajit64_flight_snapshot_metadata( recorder, &metadata ))
    {
        xtajit64_flight_release_scratch( scratch );
        return;
    }
    lost = xtajit64_flight_saturating_add( metadata.historical_loss_count,
                                           metadata.contention_loss_count );
    lost = xtajit64_flight_saturating_add( lost, metadata.scratch_loss_count );
    for (sequence = metadata.first_sequence;
         sequence && sequence <= metadata.last_sequence;
         ++sequence)
    {
        snapshot_state = xtajit64_flight_snapshot_event( recorder, sequence, event );
        if (snapshot_state == XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED) ++committed;
        else if (snapshot_state == XTAJIT64_FLIGHT_SNAPSHOT_TORN) ++torn;
        else lost = xtajit64_flight_saturating_add( lost, 1 );
    }
    ERR( "xtajit64 diagnostic recorder frozen at %s reason %s/%u sequences %#llx-%#llx "
         "committed %u lost %#llx torn %u contention-loss %#llx scratch-loss %#llx\n", where,
         flight_reason_name( metadata.freeze_reason ), metadata.freeze_reason,
         metadata.first_sequence, metadata.last_sequence, committed, lost, torn,
         metadata.contention_loss_count, metadata.scratch_loss_count );
    if (metadata.first_violation_available &&
        xtajit64_flight_snapshot_first_violation( recorder, event ))
        flight_dump_event( "first-violation", event );
    flight_dump_transition_stack_violation( recorder );
    for (sequence = metadata.first_sequence;
         sequence && sequence <= metadata.last_sequence;
         ++sequence)
    {
        if (xtajit64_flight_snapshot_event( recorder, sequence, event ) !=
            XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED)
            continue;
        flight_dump_event( "ring", event );
    }
    xtajit64_flight_release_scratch( scratch );
}

static void flight_bind_provider( struct xtajit64_thread_state *state,
                                  const ARM64EC_NT_CONTEXT *ec_context,
                                  const AMD64_CONTEXT *context,
                                  UINT64 stack_limit, UINT64 stack_base )
{
    struct xtajit64_flight_bind_params params;
    struct xtajit64_flight_recorder *recorder;
    UINT64 authenticated_teb;
    NTSTATUS status;

    if (!flight_has_active_recorder( state ) ||
        state->flight_teb_authenticated) return;
    recorder = state->flight_recorder;
    memset( &params, 0, sizeof(params) );
    params.recorder = (ULONG_PTR)recorder;
    params.causal_boundary_id = state->flight_causal_boundary_id;
    params.context_generation = state->flight_context_generation;
    params.transition_generation = state->flight_transition_generation;
    /* Authenticate the wrapper's live pre-dispatch x18 observation.  The
     * stable ThreadBasicInformation value remains the operational TEB and is
     * accepted by the watchdog only after Unix publishes the same value. */
    params.claimed_teb = state->capture_x18;
    params.guest_rip = context ? context->Rip : XTAJIT64_FLIGHT_UNKNOWN_U64;
    params.guest_rsp = context ? context->Rsp : XTAJIT64_FLIGHT_UNKNOWN_U64;
    params.guest_stack_limit = stack_limit;
    params.guest_stack_base = stack_base;
    params.control_stack_limit = flight_control_stack_limit( state );
    params.control_stack_top = state->control_stack_top;
    state->flight_teb_authenticated = FALSE;
    status = XTAJIT64_CALL( flight_bind, &params );
    if (status)
        flight_record_cpu_event( state, ec_context, context, stack_limit, stack_base,
                                 XTAJIT64_FLIGHT_UNKNOWN_U64,
                                 XTAJIT64_FLIGHT_UNKNOWN_U64,
                                 XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION,
                                 XTAJIT64_FLIGHT_REASON_RECORDER_INVALID );
    else if (!flight_has_valid_recorder( state ) || state->flight_recorder != recorder)
        xtajit64_flight_freeze( recorder, XTAJIT64_FLIGHT_REASON_RECORDER_INVALID );
    else
    {
        authenticated_teb = __atomic_load_n( &recorder->authenticated_teb, __ATOMIC_ACQUIRE );
        state->flight_teb_authenticated =
            xtajit64_flight_validate_pe_x18_claim( authenticated_teb,
                                                    params.claimed_teb ) ==
                XTAJIT64_FLIGHT_REASON_NONE &&
            authenticated_teb == state->flight_expected_teb;
        if (state->flight_teb_authenticated)
            state->flight_expected_teb = authenticated_teb;
        if (!state->flight_teb_authenticated)
        {
            /* A successful Unix call without an independently authenticated
             * TEB is itself an x18 contract failure, not a reason to quietly
             * downgrade all later PE observations to untrusted evidence. */
            flight_record_cpu_event( state, ec_context, context, stack_limit, stack_base,
                                     state->flight_expected_teb, authenticated_teb,
                                     XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION,
                                     XTAJIT64_FLIGHT_REASON_X18_VALUE );
        }
    }
}

static BOOL decode_ec_entry_thunk( ULONG_PTR target, UINT32 encoded,
                                   ULONG_PTR *candidate )
{
    INT32 delta = (INT32)(encoded & ~3u);

    if (!candidate || !delta ||
        (delta > 0 && target > ~(ULONG_PTR)0 - (UINT32)delta) ||
        (delta < 0 && target < (ULONG_PTR)-(INT64)delta))
        return FALSE;
    *candidate = target + delta;
    return !(*candidate & 3);
}

static UINT32 ec_entry_cache_index( UINT64 address )
{
    address >>= 4;
    address ^= address >> 33;
    address *= 0xff51afd7ed558ccdull;
    address ^= address >> 33;
    return address & (XTAJIT64_EC_ENTRY_CACHE_SIZE - 1);
}

static NTSTATUS resolve_ec_entry_thunk( struct xtajit64_thread_state *state,
                                        UINT64 guest_target, ULONG_PTR *native_target,
                                        ULONG_PTR *entry )
{
    struct xtajit64_ec_entry_cache *cache;
    MEMORY_BASIC_INFORMATION target_info, entry_info;
    ULONG_PTR target, candidate, cached_target, cached_entry;
    UINT64 generation, cached_generation, cached_guest;
    UINT32 encoded;
    NTSTATUS status;

    if (!native_target || !entry) return STATUS_INVALID_PARAMETER;

    generation = current_transition_cache_generation();
    cache = state ? &state->ec_entry_cache[ec_entry_cache_index( guest_target )] : NULL;
    if (cache &&
        (cached_generation = __atomic_load_n( &cache->generation,
                                               __ATOMIC_ACQUIRE )) == generation)
    {
        cached_guest = cache->guest_target;
        cached_target = cache->native_target;
        cached_entry = cache->entry;
        if (__atomic_load_n( &cache->generation, __ATOMIC_ACQUIRE ) == generation &&
            cached_guest == guest_target && cached_target >= sizeof(encoded) &&
            RtlIsEcCode( cached_target ) && RtlIsEcCode( cached_entry ) &&
            !(status = read_current_process_memory(
                  &encoded, (const void *)(cached_target - sizeof(encoded)),
                  sizeof(encoded) )) &&
            decode_ec_entry_thunk( cached_target, encoded, &candidate ) &&
            candidate == cached_entry)
        {
            *native_target = cached_target;
            *entry = cached_entry;
            return STATUS_SUCCESS;
        }
    }

    if (!state ||
        !guest_range_to_host( guest_target, sizeof(encoded),
                              XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ, &target ) ||
        target < sizeof(encoded) || !RtlIsEcCode( target ))
        return STATUS_INVALID_ADDRESS;
    status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)target,
                                   MemoryBasicInformation, &target_info,
                                   sizeof(target_info), NULL );
    if (status) return status;
    if (target_info.State != MEM_COMMIT || !target_info.AllocationBase ||
        target - sizeof(encoded) < (ULONG_PTR)target_info.AllocationBase)
        return STATUS_INVALID_IMAGE_FORMAT;
    status = read_current_process_memory( &encoded,
                                          (const void *)(target - sizeof(encoded)),
                                          sizeof(encoded) );
    if (status) return status;

    /* Public ARM64EC ABI: the word immediately before an EC function is a
     * signed target-relative entry-thunk offset with two low flag bits. */
    if (!decode_ec_entry_thunk( target, encoded, &candidate ))
        return STATUS_INVALID_IMAGE_FORMAT;
    if (!RtlIsEcCode( candidate )) return STATUS_INVALID_IMAGE_FORMAT;
    status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)candidate,
                                   MemoryBasicInformation, &entry_info,
                                   sizeof(entry_info), NULL );
    if (status) return status;
    if (entry_info.State != MEM_COMMIT ||
        entry_info.AllocationBase != target_info.AllocationBase ||
        !((entry_info.Protect & 0xff) == PAGE_EXECUTE ||
          (entry_info.Protect & 0xff) == PAGE_EXECUTE_READ ||
          (entry_info.Protect & 0xff) == PAGE_EXECUTE_READWRITE ||
          (entry_info.Protect & 0xff) == PAGE_EXECUTE_WRITECOPY))
        return STATUS_INVALID_IMAGE_FORMAT;

    *native_target = target;
    *entry = candidate;
    if (cache && current_transition_cache_generation() == generation)
    {
        __atomic_store_n( &cache->generation, 0, __ATOMIC_RELEASE );
        cache->guest_target = guest_target;
        cache->native_target = target;
        cache->entry = candidate;
        __atomic_store_n( &cache->generation, generation, __ATOMIC_RELEASE );
    }
    return STATUS_SUCCESS;
}

static struct xtajit64_transition_frame *push_transition_frame(
    struct xtajit64_thread_state *state, enum xtajit64_transition_frame_kind kind )
{
    struct xtajit64_transition_frame *frame;

    if (!state) return NULL;
    if (state->depth >= XTAJIT64_MAX_TRANSITION_DEPTH)
    {
        /* A depth limit is the primary signal for leaked non-local frames.
         * Freeze it before abort_transition() so the preceding ring remains
         * available even when no context/x18 invariant fired. */
        if (state->flight_recorder)
            flight_record_transition_frame_event(
                state, NULL, NULL, XTAJIT64_FLIGHT_UNKNOWN_U64,
                XTAJIT64_FLIGHT_UNKNOWN_U64, XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_PUSH,
                XTAJIT64_FLIGHT_REASON_TRANSITION_DEPTH, kind, state->depth, state->depth,
                XTAJIT64_FLIGHT_UNKNOWN_U64, XTAJIT64_FLIGHT_UNKNOWN_U64,
                XTAJIT64_FLIGHT_UNKNOWN_U64 );
        return NULL;
    }
    frame = &state->frames[state->depth++];
    memset( frame, 0, sizeof(*frame) );
    frame->kind = kind;
    return frame;
}

static void discard_unwound_transition_frames( struct xtajit64_thread_state *state,
                                                UINT64 guest_rsp )
{
    UINT old_depth = state->depth;

    /* BeginSimulation is also the re-entry point after NtContinue restores an
     * x64 context.  Such a restore may abandon native callbacks without ever
     * reaching their entry/exit thunks.  Frames whose return stack is at or
     * below the restored RSP are no longer reachable and must not accumulate
     * across repeated exception, APC, or user-callback dispatch. */
    while (state->depth &&
           guest_rsp >= state->frames[state->depth - 1].guest_rsp)
    {
        struct xtajit64_transition_frame *frame =
            &state->frames[state->depth - 1];

        if (state->flight_recorder)
            flight_reconcile_transition_frame(
                state, NULL, NULL, XTAJIT64_FLIGHT_UNKNOWN_U64,
                XTAJIT64_FLIGHT_UNKNOWN_U64, frame, state->depth,
                state->depth - 1, TRUE );
        --state->depth;
    }

    if (state->depth != old_depth)
        TRACE( "discarded %u unwound transition frames at restored x64 rsp %p, depth %u\n",
               old_depth - state->depth, (void *)(ULONG_PTR)guest_rsp,
               state->depth );
}

static NTSTATUS capture_fp_state( AMD64_CONTEXT *context )
{
    arm64x_get_information get_info = (arm64x_get_information)__os_arm64x_get_x64_information;
    UINT mxcsr;
    NTSTATUS status;

    if (!get_info) return STATUS_ENTRYPOINT_NOT_FOUND;
    if ((status = get_info( 0, &mxcsr, NULL ))) return status;
    context->MxCsr = mxcsr;
    context->FltSave.MxCsr = mxcsr;
    return STATUS_SUCCESS;
}

static NTSTATUS restore_fp_state( const AMD64_CONTEXT *context )
{
    arm64x_set_information set_info = (arm64x_set_information)__os_arm64x_set_x64_information;

    if (!set_info) return STATUS_ENTRYPOINT_NOT_FOUND;
    return set_info( 0, context->MxCsr, NULL );
}

static DECLSPEC_NORETURN void xtajit64_restore_native(
    struct xtajit64_thread_state *state, ARM64EC_NT_CONTEXT *context,
    CHPE_V2_CPU_AREA_INFO *cpu, UINT unicorn_error );

static DECLSPEC_NORETURN void terminate_transition( NTSTATUS status )
{
    NtTerminateProcess( GetCurrentProcess(), status ? status : STATUS_NOT_SUPPORTED );
    RtlRaiseStatus( status ? status : STATUS_NOT_SUPPORTED );
}

/* Terminal paths are normally outside the narrow watchdog checks.  In opt-in
 * diagnostic mode freeze the ring before termination so an unsupported stop
 * or a depth-overflow abort does not silently discard its causal history. */
static void flight_freeze_terminal_abort( struct xtajit64_thread_state *state,
                                          NTSTATUS status, UINT stop_reason,
                                          UINT unicorn_error )
{
    struct xtajit64_flight_recorder *recorder;

    if (!flight_has_active_recorder( state )) return;
    recorder = state->flight_recorder;
    if (__atomic_load_n( &recorder->freeze_state, __ATOMIC_ACQUIRE ))
        return;
    if (!flight_record_cpu_event( state, NULL, NULL, XTAJIT64_FLIGHT_UNKNOWN_U64,
                                  XTAJIT64_FLIGHT_UNKNOWN_U64, (UINT64)(ULONG)status,
                                  (UINT64)stop_reason | (UINT64)unicorn_error << 32,
                                  XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION,
                                  XTAJIT64_FLIGHT_REASON_TERMINAL_ABORT ))
        xtajit64_flight_freeze( recorder,
                                 XTAJIT64_FLIGHT_REASON_TERMINAL_ABORT );
}

static DECLSPEC_NORETURN void abort_transition( struct xtajit64_thread_state *state,
                                               NTSTATUS status, const char *reason )
{
    flight_freeze_terminal_abort( state, status, XTAJIT64_STOP_INTERNAL_ERROR, 0 );
    flight_dump_if_frozen( state, "terminal transition abort" );
    ERR( "%s, status %#lx transition %u depth %u\n", reason, status,
         state ? state->capture_kind : ~0u, state ? state->depth : 0 );
    terminate_transition( status );
}

static void require_control_stack_simulation_ownership(
    struct xtajit64_thread_state *state, CHPE_V2_CPU_AREA_INFO *cpu,
    ARM64EC_NT_CONTEXT *context, const char *boundary )
{
    if (*(const volatile BOOLEAN *)&cpu->InSimulation) return;
    if (state->flight_recorder)
    {
        flight_record_cpu_event(
            state, context, &context->AMD64_Context,
            XTAJIT64_FLIGHT_UNKNOWN_U64, XTAJIT64_FLIGHT_UNKNOWN_U64,
            XTAJIT64_FLIGHT_UNKNOWN_U64, XTAJIT64_FLIGHT_UNKNOWN_U64,
            XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION,
            XTAJIT64_FLIGHT_REASON_SIMULATION_OWNERSHIP );
        flight_dump_if_frozen( state, boundary );
    }
    abort_transition( state, STATUS_INVALID_DEVICE_STATE, boundary );
}

static void terminal_diagnostic_address( const char *name, UINT64 address )
{
    MEMORY_BASIC_INFORMATION info;
    NTSTATUS status;

    if (!address)
    {
        ERR( "XTAJIT64_TERMINAL_ADDRESS_V1 %s=0\n", name );
        return;
    }
    status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)(ULONG_PTR)address,
                                   MemoryBasicInformation, &info, sizeof(info), NULL );
    if (status)
    {
        ERR( "XTAJIT64_TERMINAL_ADDRESS_V1 %s=%p query=%#lx ec=%u\n",
             name, (void *)(ULONG_PTR)address, status,
             RtlIsEcCode( (ULONG_PTR)address ) );
        return;
    }
    ERR( "XTAJIT64_TERMINAL_ADDRESS_V1 %s=%p base=%p allocation=%p "
         "size=%#Ix state=%#lx protect=%#lx type=%#lx ec=%u\n",
         name, (void *)(ULONG_PTR)address, info.BaseAddress,
         info.AllocationBase, info.RegionSize, info.State, info.Protect,
         info.Type, RtlIsEcCode( (ULONG_PTR)address ) );
}

static void terminal_simulation_diagnostic(
    const struct xtajit64_thread_state *state, NTSTATUS status,
    UINT stop_reason, UINT unicorn_error,
    const struct xtajit64_begin_params *params,
    const ARM64EC_NT_CONTEXT *context )
{
    const CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    UINT depth = 0, i;

    if (!terminal_diagnostics_enabled) return;
    if (state && state->magic == XTAJIT64_THREAD_STATE_MAGIC &&
        state->allocation_size == XTAJIT64_CONTROL_STACK_SIZE)
        depth = min( state->depth, (UINT)XTAJIT64_MAX_TRANSITION_DEPTH );
    ERR( "XTAJIT64_TERMINAL_V1 status=%#lx reason=%u unicorn=%u state=%p "
         "capture=%u depth=%u control_top=%p capture_sp=%p capture_lr=%p "
         "capture_target=%p capture_x10=%p simulation=%u callback=%u "
         "doorbell=%p\n", status, stop_reason, unicorn_error, state,
         state ? state->capture_kind : ~0u, depth,
         state ? (void *)(ULONG_PTR)state->control_stack_top : NULL,
         state ? (void *)(ULONG_PTR)state->capture_sp : NULL,
         state ? (void *)(ULONG_PTR)state->capture_lr : NULL,
         state ? (void *)(ULONG_PTR)state->capture_target : NULL,
         state ? (void *)(ULONG_PTR)state->capture_x10 : NULL,
         cpu ? *(const volatile BOOLEAN *)&cpu->InSimulation : 0,
         cpu ? *(const volatile BOOLEAN *)&cpu->InSyscallCallback : 0,
         cpu ? cpu->SuspendDoorbell : NULL );
    if (params)
    {
        ERR( "XTAJIT64_TERMINAL_CONTEXT_V1 provider_rip=%p provider_rsp=%p "
             "stack=%p-%p transition=%p fault=%p access=%u\n",
             (void *)(ULONG_PTR)params->context.rip,
             (void *)(ULONG_PTR)params->context.rsp,
             (void *)(ULONG_PTR)params->stack_limit,
             (void *)(ULONG_PTR)params->stack_base,
             (void *)(ULONG_PTR)params->transition_target,
             (void *)(ULONG_PTR)params->fault_address, params->fault_access );
        terminal_diagnostic_address( "provider_rip", params->context.rip );
        terminal_diagnostic_address( "transition", params->transition_target );
        terminal_diagnostic_address( "fault", params->fault_address );
    }
    if (context)
    {
        ERR( "XTAJIT64_TERMINAL_CONTEXT_V1 native_pc=%p native_sp=%p "
             "native_lr=%p amd64_rip=%p amd64_rsp=%p flags=%#lx\n",
             (void *)(ULONG_PTR)context->Pc, (void *)(ULONG_PTR)context->Sp,
             (void *)(ULONG_PTR)context->Lr,
             (void *)(ULONG_PTR)context->AMD64_Context.Rip,
             (void *)(ULONG_PTR)context->AMD64_Context.Rsp,
             context->AMD64_Context.ContextFlags );
        terminal_diagnostic_address( "native_pc", context->Pc );
        terminal_diagnostic_address( "native_lr", context->Lr );
        terminal_diagnostic_address( "amd64_rip", context->AMD64_Context.Rip );
    }
    for (i = 0; i < depth; ++i)
    {
        const struct xtajit64_transition_frame *frame = &state->frames[i];

        ERR( "XTAJIT64_TERMINAL_FRAME_V1 index=%u kind=%u guest_rsp=%p "
             "native_sp=%p native_pc=%p ec=%u\n", i, frame->kind,
             (void *)(ULONG_PTR)frame->guest_rsp,
             (void *)(ULONG_PTR)frame->native_sp,
             (void *)(ULONG_PTR)frame->native_pc,
             RtlIsEcCode( (ULONG_PTR)frame->native_pc ) );
    }
}

static DECLSPEC_NORETURN void abort_simulation( struct xtajit64_thread_state *state,
                                               NTSTATUS status, UINT stop_reason,
                                               UINT unicorn_error,
                                               const struct xtajit64_begin_params *params,
                                               const ARM64EC_NT_CONTEXT *context )
{
    terminal_simulation_diagnostic( state, status, stop_reason, unicorn_error,
                                    params, context );
    flight_freeze_terminal_abort( state, status, stop_reason, unicorn_error );
    flight_dump_if_frozen( state, "terminal provider return" );
    ERR( "unsupported x64 simulation boundary, status %#lx reason %u unicorn %u "
         "transition %u depth %u\n", status, stop_reason, unicorn_error,
         state ? state->capture_kind : ~0u, state ? state->depth : 0 );
    terminate_transition( status );
}

static BOOL suspend_doorbell_is_set( const CHPE_V2_CPU_AREA_INFO *cpu )
{
    return cpu && cpu->SuspendDoorbell &&
           *(const volatile ULONG *)cpu->SuspendDoorbell;
}

static DECLSPEC_NORETURN void __attribute__((used, noinline)) continue_suspended_context(
    struct xtajit64_thread_state *state, ARM64EC_NT_CONTEXT *context,
    UINT stop_reason, UINT unicorn_error )
{
    NTSTATUS status;

    context->AMD64_Context.ContextFlags |= CONTEXT_AMD64_FULL |
                                           CONTEXT_AMD64_FLOATING_POINT;
    status = NtContinue( &context->AMD64_Context, FALSE );
    abort_simulation( state, status ? status : STATUS_UNSUCCESSFUL,
                      stop_reason, unicorn_error, NULL, context );
}

static DECLSPEC_NORETURN void raise_x64_memory_fault( struct xtajit64_thread_state *state,
                                                      const struct xtajit64_begin_params *params,
                                                      ARM64EC_NT_CONTEXT *ec_context )
{
    struct xtajit64_fault_params fault = {0};
    EXCEPTION_RECORD rec;
    unsigned int i;
    NTSTATUS status;

    fault.address = params->fault_address;
    fault.access = params->fault_access;
    fault.result.version = WINE_WOW64_MEMORY_FAULT_VERSION;
    fault.result.size = sizeof(fault.result);
    status = XTAJIT64_CALL( resolve_memory_fault, &fault );
    if (status && status != STATUS_NOT_SUPPORTED)
        abort_simulation( state, status, params->stop_reason, params->unicorn_error, params, ec_context );
    if (!status)
    {
        if (fault.result.version != WINE_WOW64_MEMORY_FAULT_VERSION ||
            fault.result.size != sizeof(fault.result) || fault.result.reserved ||
            fault.result.parameter_count > 3 ||
            (fault.result.action != WINE_WOW64_MEMORY_FAULT_RETRY &&
             fault.result.action != WINE_WOW64_MEMORY_FAULT_RAISE))
            abort_simulation( state, STATUS_INVALID_PARAMETER, params->stop_reason,
                              params->unicorn_error, params, ec_context );
        if (fault.result.action == WINE_WOW64_MEMORY_FAULT_RETRY)
        {
            if (fault.result.status || fault.result.parameter_count)
                abort_simulation( state, STATUS_INVALID_PARAMETER, params->stop_reason,
                                  params->unicorn_error, params, ec_context );
            continue_suspended_context( state, ec_context, params->stop_reason, params->unicorn_error );
        }
    }
    memset( &rec, 0, sizeof(rec) );
    rec.ExceptionCode = STATUS_ACCESS_VIOLATION;
    rec.ExceptionAddress = (void *)(ULONG_PTR)params->context.rip;
    rec.NumberParameters = 2;
    switch (params->fault_access)
    {
    case EXCEPTION_READ_FAULT:
    case EXCEPTION_WRITE_FAULT:
    case EXCEPTION_EXECUTE_FAULT:
        rec.ExceptionInformation[0] = params->fault_access;
        break;
    default:
        rec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;
        break;
    }
    rec.ExceptionInformation[1] = params->fault_address;
    if (!status)
    {
        rec.ExceptionCode = fault.result.status;
        rec.NumberParameters = fault.result.parameter_count;
        memset( rec.ExceptionInformation, 0, sizeof(rec.ExceptionInformation) );
        for (i = 0; i < rec.NumberParameters; ++i) rec.ExceptionInformation[i] = fault.result.information[i];
    }
    ec_context->AMD64_Context.ContextFlags |= CONTEXT_AMD64_FULL |
                                              CONTEXT_AMD64_FLOATING_POINT;
    TRACE( "raise x64 memory exception rip %p fault %p access %#Ix\n",
           rec.ExceptionAddress, (void *)(ULONG_PTR)rec.ExceptionInformation[1],
           rec.ExceptionInformation[0] );
    status = NtRaiseException( &rec, &ec_context->AMD64_Context, TRUE );
    abort_simulation( state, status ? status : STATUS_ACCESS_VIOLATION,
                      params->stop_reason, params->unicorn_error,
                      params, ec_context );
}

static DECLSPEC_NORETURN void raise_x64_single_step(
    struct xtajit64_thread_state *state,
    const struct xtajit64_begin_params *params,
    ARM64EC_NT_CONTEXT *ec_context )
{
    EXCEPTION_RECORD rec;
    NTSTATUS status;

    memset( &rec, 0, sizeof(rec) );
    rec.ExceptionCode = STATUS_SINGLE_STEP;
    rec.ExceptionAddress = (void *)(ULONG_PTR)params->context.rip;
    ec_context->AMD64_Context.ContextFlags |= CONTEXT_AMD64_FULL |
                                              CONTEXT_AMD64_FLOATING_POINT;
    ec_context->AMD64_Context.EFlags &= ~0x100; /* clear the trap flag */
    TRACE( "raise x64 single-step exception rip %p\n", rec.ExceptionAddress );
    status = NtRaiseException( &rec, &ec_context->AMD64_Context, TRUE );
    abort_simulation( state, status ? status : STATUS_SINGLE_STEP,
                      params->stop_reason, params->unicorn_error,
                      params, ec_context );
}

static void flight_start_transition( struct xtajit64_thread_state *state )
{
    struct xtajit64_flight_recorder *recorder;
    UINT64 boundary_id;

    if (!flight_has_active_recorder( state )) return;
    recorder = state->flight_recorder;
    boundary_id = xtajit64_flight_next_causal_boundary_id( recorder );
    if (boundary_id == XTAJIT64_FLIGHT_UNKNOWN_U64) return;
    boundary_id = xtajit64_flight_publish_boundary( recorder, boundary_id );
    if (boundary_id == XTAJIT64_FLIGHT_UNKNOWN_U64) return;
    /* These are separate event fields but one owning transition boundary.
     * Assign them from the release-published ID so an interrupted outer
     * producer cannot regress state after a nested transition published. */
    state->flight_causal_boundary_id = boundary_id;
    state->flight_context_generation = boundary_id;
    state->flight_transition_generation = boundary_id;
}

static DECLSPEC_NORETURN void run_x64_simulation( struct xtajit64_thread_state *state )
{
    CHPE_V2_CPU_AREA_INFO *cpu;
    ARM64EC_NT_CONTEXT *ec_context;
    struct xtajit64_x64_stack_probe stack_probe;
    struct xtajit64_transition_frame *frame, *mismatched_frame = NULL;
    struct xtajit64_begin_params params = {0};
    TEB *teb;
    UINT64 guest_return;
    ULONG_PTR native_target, entry, host_rsp;
    NTSTATUS status;
    UINT frame_index;
    UINT32 depth_before;
    BOOL continuation_target_seen, mapping_reconciled = FALSE, stack_valid = FALSE;

    if (!state || state->magic != XTAJIT64_THREAD_STATE_MAGIC ||
        !(teb = (TEB *)(ULONG_PTR)state->flight_expected_teb) ||
        teb->Tib.Self != &teb->Tib ||
        !(cpu = teb->ChpeV2CpuAreaInfo) ||
        !(ec_context = cpu->ContextAmd64) ||
        cpu->SuspendDoorbell != &state->suspend_doorbell)
        abort_transition( state, STATUS_INVALID_PARAMETER, "missing x64 transition state" );

    /* BeginSimulation and every native return/exit/jump converge here.  Do not
     * expose x64 execution until ntdll has committed any VM/cache resync that a
     * nested provider callback had to defer. */
    if ((status = __wine_arm64ec_prepare_x64_execution()))
        abort_transition( state, status, "cannot prepare deferred x64 mapping state" );

    context_to_unix( &params.context, &ec_context->AMD64_Context );
    /* A Darwin exceptional return can lose live x18 after the direct TEB
     * access above.  A bare NtCurrentTeb() read would then silently produce
     * zero rather than faulting through ntdll's authenticated recovery path.
     * The generation-owned transition state retains the TEB established by
     * ThreadBasicInformation, which is also the Windows x64 GS base. */
    params.gs_base = (ULONG_PTR)teb;
    params.suspend_doorbell = (ULONG_PTR)cpu->SuspendDoorbell;
    if (state->flight_recorder)
    {
        memset( &stack_probe, 0xff, sizeof(stack_probe) );
        stack_probe.fresh_cpu = 0;
        stack_probe.stack_match_mask = 0;
        stack_probe.probe_ran = FALSE;
    }
    if (params.context.rip <= XTAJIT64_X64_USER_ADDRESS_MAX &&
        params.context.rsp <= XTAJIT64_X64_USER_ADDRESS_MAX &&
        params.gs_base <= XTAJIT64_X64_USER_ADDRESS_MAX)
        stack_valid = get_x64_stack_bounds(
            state, params.context.rsp, &params.stack_limit, &params.stack_base,
            state->flight_recorder ? &stack_probe : NULL );
    if (!stack_valid)
    {
        if (state->flight_recorder)
            flight_record_transition_stack_violation(
                state, ec_context, &ec_context->AMD64_Context, teb, cpu,
                params.gs_base, &stack_probe );
        abort_transition( state, STATUS_INVALID_ADDRESS, "invalid semantic x64 stack" );
    }

    /* This outer branch is the complete normal-transition cost when the
     * recorder is disabled.  In particular, it avoids the Unixlib bind and
     * all diagnostic register/time sampling. */
    if (state->flight_recorder)
    {
        flight_watch_cpu_context( state, ec_context, &ec_context->AMD64_Context,
                                  params.stack_limit, params.stack_base,
                                  XTAJIT64_FLIGHT_UNKNOWN_U64,
                                  XTAJIT64_FLIGHT_UNKNOWN_U64,
                                  XTAJIT64_FLIGHT_UNKNOWN_U64,
                                  XTAJIT64_FLIGHT_EVENT_CONTEXT_IMPORT );
        flight_watch_cpu_x18( state, ec_context, &ec_context->AMD64_Context,
                              params.stack_limit, params.stack_base,
                              XTAJIT64_FLIGHT_EVENT_TRANSITION_BEGIN );
        flight_bind_provider( state, ec_context, &ec_context->AMD64_Context,
                              params.stack_limit, params.stack_base );
        /* The first unix_flight_bind() returns through the system-mode
         * dispatcher; later transitions reuse that authenticated association
         * and publish their live boundary through the recorder.  Re-observe
         * the PE numeric x18 contract directly before every provider entry. */
        flight_watch_cpu_x18( state, ec_context, &ec_context->AMD64_Context,
                              params.stack_limit, params.stack_base,
                              XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN );
    }

    for (;;)
    {
        BOOL mapped = FALSE;

        cpu->InSimulation = 1;
        if (state->flight_recorder)
            flight_record_cpu_event( state, ec_context, &ec_context->AMD64_Context,
                                     params.stack_limit, params.stack_base,
                                     XTAJIT64_FLIGHT_UNKNOWN_U64,
                                     XTAJIT64_FLIGHT_UNKNOWN_U64,
                                     mapping_reconciled ?
                                     XTAJIT64_FLIGHT_EVENT_PROVIDER_RESUME :
                                     XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN,
                                     XTAJIT64_FLIGHT_REASON_NONE );
        status = XTAJIT64_CALL( begin_simulation, &params );
        if (state->flight_recorder)
        {
            /* This samples the public PE register contract before ordinary
             * return-side helpers can blur the provider boundary.  The later
             * CONTEXT_EXPORT observation pairs it with imported guest state. */
            flight_watch_cpu_x18( state, ec_context, &ec_context->AMD64_Context,
                                  params.stack_limit, params.stack_base,
                                  XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP );
            flight_dump_if_frozen( state, "provider boundary return" );
        }
        context_from_unix( &ec_context->AMD64_Context, &params.context );
        if (state->flight_recorder)
        {
            flight_watch_cpu_context( state, ec_context, &ec_context->AMD64_Context,
                                      params.stack_limit, params.stack_base,
                                      XTAJIT64_FLIGHT_UNKNOWN_U64,
                                      XTAJIT64_FLIGHT_UNKNOWN_U64,
                                      XTAJIT64_FLIGHT_UNKNOWN_U64,
                                      XTAJIT64_FLIGHT_EVENT_CONTEXT_EXPORT );
            flight_watch_cpu_x18( state, ec_context, &ec_context->AMD64_Context,
                                  params.stack_limit, params.stack_base,
                                  XTAJIT64_FLIGHT_EVENT_CONTEXT_EXPORT );
            flight_dump_if_frozen( state, "context export" );
        }
        if (!status && params.stop_reason == XTAJIT64_STOP_SUSPEND)
        {
            if (!suspend_doorbell_is_set( cpu ))
                abort_simulation( state, STATUS_INVALID_DEVICE_STATE,
                                  params.stop_reason, params.unicorn_error,
                                  &params, ec_context );
            continue_suspended_context( state, ec_context,
                                        params.stop_reason,
                                        params.unicorn_error );
        }
        if (status != STATUS_RETRY ||
            params.stop_reason != XTAJIT64_STOP_MAPPING_MISS ||
            mapping_reconciled)
            break;

        /* begin_simulation has captured the unchanged faulting context and
         * returned its engine to the pool.  Reconcile at most once so a truly
         * invalid pointer cannot turn into an unbounded retry loop. */
        status = synchronize_fault_mapping( params.fault_address, &mapped );
        if (status)
            abort_transition( state, status, "cannot reconcile late x64 mapping" );
        if (!mapped)
        {
            status = STATUS_RETRY;
            break;
        }
        /* Demand-mapping the stack guard does not make the faulting RSP a
         * valid simulation entry yet. Let the normal fault resolver grow the
         * stack or raise overflow before begin_simulation validates it again. */
        if (params.context.rsp < params.stack_limit)
        {
            status = STATUS_RETRY;
            break;
        }
        mapping_reconciled = TRUE;
    }
    if (status || params.stop_reason != XTAJIT64_STOP_EC_TRANSITION)
    {
        TRACE( "x64 simulation stopped fault %p target %p\n",
               (void *)(ULONG_PTR)params.fault_address,
               (void *)(ULONG_PTR)params.transition_target );
        if ((status == STATUS_ACCESS_VIOLATION &&
             params.stop_reason == XTAJIT64_STOP_MEMORY_FAULT) ||
            (status == STATUS_RETRY &&
             params.stop_reason == XTAJIT64_STOP_MAPPING_MISS))
            raise_x64_memory_fault( state, &params, ec_context );
        if (status == STATUS_SINGLE_STEP &&
            params.stop_reason == XTAJIT64_STOP_SINGLE_STEP)
            raise_x64_single_step( state, &params, ec_context );
        abort_simulation( state, status ? status : STATUS_NOT_SUPPORTED,
                          params.stop_reason, params.unicorn_error,
                          &params, ec_context );
    }

    /* A non-local unwind may abandon nested x64/ARM64EC transitions and resume
     * an earlier exit-thunk continuation.  Match both the continuation PC and
     * its post-pop x64 RSP; either value alone can recur in nested calls. */
    frame = NULL;
    continuation_target_seen = FALSE;
    for (frame_index = state->depth; frame_index; )
    {
        struct xtajit64_transition_frame *candidate =
            &state->frames[--frame_index];

        if (candidate->kind != XTAJIT64_FRAME_EXIT ||
            params.transition_target != candidate->native_pc)
            continue;
        continuation_target_seen = TRUE;
        if (!mismatched_frame) mismatched_frame = candidate;
        if (params.context.rsp == candidate->guest_rsp)
        {
            frame = candidate;
            break;
        }
    }
    if (frame)
    {
        /* Remove the matched EXIT frame and every newer frame abandoned by
         * the unwind before restoring the captured native continuation. */
        if (params.context.rsp != frame->guest_rsp)
            abort_transition( state, STATUS_BAD_STACK,
                              "x64 exit-thunk continuation stack mismatch" );
        while (state->depth > frame_index)
        {
            struct xtajit64_transition_frame *discarded =
                &state->frames[state->depth - 1];

            if (state->flight_recorder)
                flight_reconcile_transition_frame(
                    state, ec_context, &ec_context->AMD64_Context,
                    params.stack_limit, params.stack_base, discarded,
                    state->depth, state->depth - 1, TRUE );
            --state->depth;
        }
        ec_context->Sp = frame->native_sp;
        ec_context->Pc = frame->native_pc;
        ec_context->Lr = frame->native_pc;
        if (state->flight_recorder)
        {
            flight_record_cpu_event( state, ec_context, &ec_context->AMD64_Context,
                                     params.stack_limit, params.stack_base,
                                     frame->native_pc, frame->guest_rsp,
                                     XTAJIT64_FLIGHT_EVENT_TRANSITION_CONTINUE,
                                     XTAJIT64_FLIGHT_REASON_NONE );
            flight_dump_if_frozen( state, "EC continuation re-entry" );
        }
        if ((status = restore_fp_state( &ec_context->AMD64_Context )))
            abort_transition( state, status, "cannot restore native FP state" );
        if (suspend_doorbell_is_set( cpu ))
            continue_suspended_context( state, ec_context,
                                        XTAJIT64_STOP_SUSPEND,
                                        params.unicorn_error );
        TRACE( "return x64 target to EC continuation %p native sp %p depth %u\n",
               (void *)(ULONG_PTR)frame->native_pc,
               (void *)(ULONG_PTR)frame->native_sp, state->depth );
        xtajit64_restore_native( state, ec_context, cpu, params.unicorn_error );
    }
    if (continuation_target_seen)
    {
        /* Only the complete frame search owns the continuation-pair
         * invariant.  The top frame can legitimately share a native PC with
         * an older frame that has the exact post-pop guest RSP selected by a
         * non-local unwind.  Freeze only when no candidate matched both. */
        if (state->flight_recorder && mismatched_frame)
        {
            flight_record_cpu_event( state, ec_context, &ec_context->AMD64_Context,
                                     params.stack_limit, params.stack_base,
                                     mismatched_frame->native_pc,
                                     mismatched_frame->guest_rsp,
                                     XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION,
                                     XTAJIT64_FLIGHT_REASON_CONTINUATION_PAIR );
            flight_dump_if_frozen( state, "continuation frame search" );
        }
        abort_transition( state, STATUS_BAD_STACK,
                          "x64 exit-thunk continuation stack mismatch" );
    }

    if (params.context.rsp > ~(UINT64)0 - sizeof(guest_return) ||
        (status = read_guest_u64( state, params.context.rsp, &guest_return )))
        abort_transition( state, status ? status : STATUS_BAD_STACK,
                          "cannot pop x64 return address for EC entry" );
    if (!guest_return)
        abort_transition( state, STATUS_INVALID_IMAGE_FORMAT,
                          "missing x64 return address for ARM64EC entry" );
    if ((status = resolve_ec_entry_thunk( state, params.transition_target,
                                          &native_target, &entry )))
        abort_transition( state, status ? status : STATUS_INVALID_IMAGE_FORMAT,
                          "invalid ARM64EC entry-thunk metadata" );
    if (!transition_guest_range_to_host(
            state, params.context.rsp + sizeof(guest_return), sizeof(guest_return),
            XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ, &host_rsp ))
        abort_transition( state, STATUS_BAD_STACK,
                          "cannot materialize EC entry stack" );
    depth_before = state->depth;
    if (!(frame = push_transition_frame( state, XTAJIT64_FRAME_ENTRY )))
        abort_transition( state, STATUS_STACK_OVERFLOW,
                          "ARM64EC transition nesting limit exceeded" );

    frame->guest_rsp = params.context.rsp + sizeof(guest_return);
    ec_context->X4 = host_rsp;  /* public entry-thunk ABI: original post-pop x64 RSP */
    ec_context->X9 = native_target;
    ec_context->Lr = guest_return;
    ec_context->Sp = host_rsp & ~(ULONG_PTR)15;
    ec_context->Pc = entry;
    if (state->flight_recorder)
    {
        flight_record_transition_frame_push( state, ec_context, &ec_context->AMD64_Context,
                                             params.stack_limit, params.stack_base, frame,
                                             depth_before, state->depth,
                                             host_rsp & ~(ULONG_PTR)15, entry );
        flight_record_cpu_event( state, ec_context, &ec_context->AMD64_Context,
                                 params.stack_limit, params.stack_base,
                                 entry, ec_context->Sp,
                                 XTAJIT64_FLIGHT_EVENT_TRANSITION_CONTINUE,
                                 XTAJIT64_FLIGHT_REASON_NONE );
        flight_dump_if_frozen( state, "EC entry re-entry" );
    }
    if ((status = restore_fp_state( &ec_context->AMD64_Context )))
        abort_transition( state, status, "cannot restore EC entry FP state" );
    if (suspend_doorbell_is_set( cpu ))
        continue_suspended_context( state, ec_context,
                                    XTAJIT64_STOP_SUSPEND,
                                    params.unicorn_error );
    TRACE( "enter EC target %p through compiler thunk %p x64 return %p "
           "guest rsp %p native sp %p depth %u\n",
           (void *)native_target, (void *)entry, (void *)(ULONG_PTR)guest_return,
           (void *)(ULONG_PTR)frame->guest_rsp, (void *)(ULONG_PTR)ec_context->Sp,
           state->depth );
    xtajit64_restore_native( state, ec_context, cpu, params.unicorn_error );
}

static void __attribute__((used, noreturn)) xtajit64_transition_from_native(
    struct xtajit64_thread_state *state )
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    ARM64EC_NT_CONTEXT *ec_context;
    struct xtajit64_transition_frame *frame;
    UINT64 guest_sp, guest_target;
    NTSTATUS status;
    UINT32 depth_before;

    if (!state || state != get_thread_state() || !cpu || !(ec_context = cpu->ContextAmd64))
        abort_transition( state, STATUS_INVALID_PARAMETER, "invalid native capture state" );
    if (state->flight_recorder) flight_start_transition( state );
    require_control_stack_simulation_ownership(
        state, cpu, ec_context,
        "native capture entered its control stack without simulation ownership" );
    if ((status = capture_fp_state( &ec_context->AMD64_Context )))
        abort_transition( state, status, "cannot capture native FP state" );
    /* The assembly capture above materializes every integer and SIMD register,
     * while capture_fp_state() completes the architectural FP metadata.  Mark
     * those groups valid at their owning boundary so consumers, including the
     * diagnostic watchdog, never observe a fully populated context with stale
     * or zero validity flags. */
    ec_context->AMD64_Context.ContextFlags |= CONTEXT_AMD64_FULL |
                                               CONTEXT_AMD64_FLOATING_POINT;
    if (state->flight_recorder)
    {
        UINT64 stack_limit = XTAJIT64_FLIGHT_UNKNOWN_U64;
        UINT64 stack_base = XTAJIT64_FLIGHT_UNKNOWN_U64;

        get_x64_stack_bounds( state, ec_context->AMD64_Context.Rsp,
                              &stack_limit, &stack_base, NULL );
        /* detail0/detail1 preserve the assembly capture's pre-switch native
         * SP/PC; the regular native_sp/native_frame fields describe this live
         * private-control-stack C observation. */
        flight_record_cpu_event( state, ec_context, &ec_context->AMD64_Context,
                                 stack_limit, stack_base, state->capture_sp,
                                 state->capture_lr,
                                 XTAJIT64_FLIGHT_EVENT_TRANSITION_CAPTURE,
                                 XTAJIT64_FLIGHT_REASON_NONE );
    }

    switch (state->capture_kind)
    {
    case XTAJIT64_NATIVE_RETURN:
        if (!state->depth ||
            (frame = &state->frames[state->depth - 1])->kind != XTAJIT64_FRAME_ENTRY ||
            !state->capture_lr || state->capture_lr > XTAJIT64_X64_USER_ADDRESS_MAX)
            abort_transition( state, STATUS_INVALID_UNWIND_TARGET,
                              "unmatched ARM64EC entry return" );
        ec_context->AMD64_Context.Rsp = frame->guest_rsp;
        ec_context->AMD64_Context.Rip = state->capture_lr;
        if (state->flight_recorder)
            flight_pop_transition_frame( state, ec_context, &ec_context->AMD64_Context,
                                         XTAJIT64_FLIGHT_UNKNOWN_U64,
                                         XTAJIT64_FLIGHT_UNKNOWN_U64 );
        else --state->depth;
        cpu->InSimulation = 1;
        TRACE( "return EC entry to x64 rip %p rsp %p depth %u\n",
               (void *)(ULONG_PTR)state->capture_lr,
               (void *)(ULONG_PTR)frame->guest_rsp, state->depth );
        run_x64_simulation( state );

    case XTAJIT64_NATIVE_EXIT:
        if (state->capture_sp < sizeof(UINT64) || !state->capture_lr ||
            !state->capture_target ||
            state->capture_sp > XTAJIT64_X64_USER_ADDRESS_MAX ||
            state->capture_lr > XTAJIT64_X64_USER_ADDRESS_MAX ||
            state->capture_target > XTAJIT64_X64_USER_ADDRESS_MAX)
            abort_transition( state, STATUS_INVALID_ADDRESS,
                              "invalid ARM64EC exit-thunk state" );
        guest_sp = state->capture_sp;
        guest_target = state->capture_target;
        depth_before = state->depth;
        if (!(frame = push_transition_frame( state, XTAJIT64_FRAME_EXIT )))
            abort_transition( state, STATUS_STACK_OVERFLOW,
                              "ARM64EC transition nesting limit exceeded" );
        frame->guest_rsp = guest_sp;
        frame->native_sp = state->capture_sp;
        frame->native_pc = state->capture_lr;
        if (state->flight_recorder)
            flight_record_transition_frame_push(
                state, ec_context, &ec_context->AMD64_Context,
                XTAJIT64_FLIGHT_UNKNOWN_U64, XTAJIT64_FLIGHT_UNKNOWN_U64, frame,
                depth_before, state->depth, frame->native_sp, frame->native_pc );
        if ((status = write_guest_u64( state, guest_sp - sizeof(UINT64),
                                       state->capture_lr )))
            abort_transition( state, status, "cannot push EC exit continuation" );
        ec_context->AMD64_Context.Rsp = guest_sp - sizeof(UINT64);
        ec_context->AMD64_Context.Rip = guest_target;
        cpu->InSimulation = 1;
        TRACE( "exit EC through compiler thunk to x64 target %p continuation %p "
               "guest rsp %p depth %u\n", (void *)(ULONG_PTR)guest_target,
               (void *)(ULONG_PTR)state->capture_lr,
               (void *)(ULONG_PTR)ec_context->AMD64_Context.Rsp, state->depth );
        run_x64_simulation( state );

    case XTAJIT64_NATIVE_JUMP:
        if (!state->depth ||
            (frame = &state->frames[state->depth - 1])->kind != XTAJIT64_FRAME_ENTRY ||
            !state->capture_lr || !state->capture_target ||
            state->capture_lr > XTAJIT64_X64_USER_ADDRESS_MAX ||
            state->capture_target > XTAJIT64_X64_USER_ADDRESS_MAX ||
            frame->guest_rsp < sizeof(UINT64))
            abort_transition( state, STATUS_INVALID_UNWIND_TARGET,
                              "invalid signature-less x64 jump" );
        guest_target = state->capture_target;
        if ((status = write_guest_u64( state, frame->guest_rsp - sizeof(UINT64),
                                       state->capture_lr )))
            abort_transition( state, status, "cannot restore tail-jump return address" );
        ec_context->AMD64_Context.Rsp = frame->guest_rsp - sizeof(UINT64);
        ec_context->AMD64_Context.Rip = guest_target;
        /* The custom entry thunk is tail-forwarding. */
        if (state->flight_recorder)
            flight_pop_transition_frame( state, ec_context, &ec_context->AMD64_Context,
                                         XTAJIT64_FLIGHT_UNKNOWN_U64,
                                         XTAJIT64_FLIGHT_UNKNOWN_U64 );
        else --state->depth;
        cpu->InSimulation = 1;
        TRACE( "tail-forward EC adjustor to x64 target %p return %p depth %u\n",
               (void *)(ULONG_PTR)guest_target, (void *)(ULONG_PTR)state->capture_lr,
               state->depth );
        run_x64_simulation( state );

    default:
        abort_transition( state, STATUS_INVALID_PARAMETER,
                          "unknown ARM64EC native transition" );
    }
}

/* Native ARM64EC entry and exit thunks use the register mapping encoded by
 * ARM64EC_NT_CONTEXT.  Capture every mapped integer/SIMD register before using
 * x16/x17 as scratch.  x13/x14/x23/x24/x28 are reserved by the public ABI and
 * are deliberately never touched here. */
static void __attribute__((used, naked)) xtajit64_capture_native(void)
{
    __asm__(
        "ldr x17, [x18, #0x1788]\n\t"       /* TEB.ChpeV2CpuAreaInfo */
        "cbz x17, 1f\n\t"
        "ldr x9, [x17, #0x30]\n\t"         /* cpu.EmulatorData[0] */
        "cmp x9, x16\n\t"
        "b.ne 1f\n\t"
        "ldr x9, [x17, #0x18]\n\t"         /* cpu.ContextAmd64 */
        "cbz x9, 1f\n\t"
        /* Native ARM64EC execution has released simulation ownership.  Take
         * it again before the private provider stack becomes architectural;
         * x9/x10 are safe scratch because capture_transition saved both. */
        "mov w10, #1\n\t"
        "stlrb w10, [x17]\n\t"             /* cpu.InSimulation, release */
        "mov x17, x9\n\t"                  /* ARM64EC context */
        "stp x8, x0,   [x17, #0x78]\n\t"   /* Rax,Rcx */
        "stp x1, x27,  [x17, #0x88]\n\t"   /* Rdx,Rbx */
        "ldr x9, [x16, #0x18]\n\t"        /* captured native SP */
        "stp x9, x29,  [x17, #0x98]\n\t"   /* Rsp,Rbp */
        "stp x25, x26, [x17, #0xa8]\n\t"   /* Rsi,Rdi */
        "stp x2, x3,   [x17, #0xb8]\n\t"   /* R8,R9 */
        "stp x4, x5,   [x17, #0xc8]\n\t"   /* R10,R11 */
        "stp x19, x20, [x17, #0xd8]\n\t"   /* R12,R13 */
        "stp x21, x22, [x17, #0xe8]\n\t"   /* R14,R15 */
        "ldr x9, [x16, #0x20]\n\t"        /* captured LR */
        "str x9, [x17, #0xf8]\n\t"        /* Rip */
        "str x9, [x17, #0x120]\n\t"       /* hidden LR */
        "str x6, [x17, #0x130]\n\t"
        "str x7, [x17, #0x140]\n\t"
        "ldr x9, [x16, #0x28]\n\t"        /* captured target x9 */
        "str x9, [x17, #0x150]\n\t"
        "ldr x9, [x16, #0x30]\n\t"        /* captured x10 */
        "str x9, [x17, #0x160]\n\t"
        "str x11, [x17, #0x170]\n\t"
        "str x12, [x17, #0x180]\n\t"
        "str x15, [x17, #0x190]\n\t"
        "stp q0, q1,   [x17, #0x1a0]\n\t"
        "stp q2, q3,   [x17, #0x1c0]\n\t"
        "stp q4, q5,   [x17, #0x1e0]\n\t"
        "stp q6, q7,   [x17, #0x200]\n\t"
        "stp q8, q9,   [x17, #0x220]\n\t"
        "stp q10, q11, [x17, #0x240]\n\t"
        "stp q12, q13, [x17, #0x260]\n\t"
        "stp q14, q15, [x17, #0x280]\n\t"
        "ldr x17, [x16, #0x10]\n\t"       /* private control-stack top */
        "mov sp, x17\n\t"
        "mov x0, x16\n\t"
        "adr x30, 2f\n\t"
        "b \"#xtajit64_transition_from_native\"\n\t"
        "1: brk #0xf64\n\t"
        "2: brk #0xf65\n\t" );
}

static DECLSPEC_NORETURN void __attribute__((naked)) xtajit64_restore_native(
    struct xtajit64_thread_state *state, ARM64EC_NT_CONTEXT *context,
    CHPE_V2_CPU_AREA_INFO *cpu, UINT unicorn_error )
{
    __asm__(
        "mov x16, x1\n\t"
        "ldr x17, [x16, #0xf8]\n\t"       /* native PC */
        "ldr x15, [x16, #0x98]\n\t"
        "mov sp, x15\n\t"
        /* Retain simulation ownership across the ARM64EC call dispatcher and
         * release it only after the architectural native SP is live.  A
         * cooperative SIGUSR1 can publish the doorbell between the final C
         * check and this handoff, so recheck it after the release and return
         * to the provider control stack before entering NtContinue. */
        "strb wzr, [x2]\n\t"             /* cpu.InSimulation */
        "dmb ish\n\t"
        "ldr x15, [x2, #0x20]\n\t"       /* cpu.SuspendDoorbell */
        "cbz x15, 2f\n\t"
        "ldr w15, [x15]\n\t"
        "cbnz w15, 1f\n\t"
        "2:\n\t"
        "ldp q0, q1,   [x16, #0x1a0]\n\t"
        "ldp q2, q3,   [x16, #0x1c0]\n\t"
        "ldp q4, q5,   [x16, #0x1e0]\n\t"
        "ldp q6, q7,   [x16, #0x200]\n\t"
        "ldp q8, q9,   [x16, #0x220]\n\t"
        "ldp q10, q11, [x16, #0x240]\n\t"
        "ldp q12, q13, [x16, #0x260]\n\t"
        "ldp q14, q15, [x16, #0x280]\n\t"
        "ldr x30, [x16, #0x120]\n\t"
        "ldr x6,  [x16, #0x130]\n\t"
        "ldr x7,  [x16, #0x140]\n\t"
        "ldr x9,  [x16, #0x150]\n\t"
        "ldr x10, [x16, #0x160]\n\t"
        "ldr x11, [x16, #0x170]\n\t"
        "ldr x12, [x16, #0x180]\n\t"
        "ldr x15, [x16, #0x190]\n\t"
        "ldr x8,  [x16, #0x78]\n\t"
        "ldr x0,  [x16, #0x80]\n\t"
        "ldp x1, x27,  [x16, #0x88]\n\t"
        "ldr x29, [x16, #0xa0]\n\t"
        "ldp x25, x26, [x16, #0xa8]\n\t"
        "ldp x2, x3,   [x16, #0xb8]\n\t"
        "ldp x4, x5,   [x16, #0xc8]\n\t"
        "ldp x19, x20, [x16, #0xd8]\n\t"
        "ldp x21, x22, [x16, #0xe8]\n\t"
        "br x17\n\t"
        "1:\n\t"
        "mov w15, #1\n\t"
        "strb w15, [x2]\n\t"            /* reclaim simulation ownership */
        "ldr x15, [x0, #0x10]\n\t"       /* private control-stack top */
        "mov sp, x15\n\t"
        "mov x1, x16\n\t"               /* ARM64EC context */
        "mov w2, #8\n\t"                /* XTAJIT64_STOP_SUSPEND */
        "b \"#continue_suspended_context\"\n\t" );
}

#endif /* HAVE_UNICORN */


/**********************************************************************
 *           DispatchJump  (xtajit64.@)
 *
 * Implementation of __os_arm64x_x64_jump.
 */
#ifdef HAVE_UNICORN

static void __attribute__((used, naked)) capture_transition(void)
{
    __asm__(
        "sub sp, sp, #16\n\t"
        "stp x16, x17, [sp]\n\t"          /* preserve transition kind */
        "add x16, sp, #16\n\t"            /* original native SP */
        "ldr x17, [x18, #0x1788]\n\t"      /* TEB.ChpeV2CpuAreaInfo */
        "cbz x17, 1f\n\t"
        "ldr x17, [x17, #0x30]\n\t"       /* cpu.EmulatorData[0] */
        "cbz x17, 1f\n\t"
        "str x17, [sp]\n\t"
        "ldr x17, [x17]\n\t"
        "movz x16, #0x5458\n\t"
        "movk x16, #0x4a41, lsl #16\n\t"
        "movk x16, #0x5449, lsl #32\n\t"
        "movk x16, #0x3634, lsl #48\n\t"
        "cmp x17, x16\n\t"
        "b.ne 1f\n\t"
        "ldr x17, [sp]\n\t"
        "add x16, sp, #16\n\t"            /* original native SP */
        "str x16, [x17, #0x18]\n\t"
        "str x30, [x17, #0x20]\n\t"
        "str x9,  [x17, #0x28]\n\t"
        "str x10, [x17, #0x30]\n\t"
        "ldr w16, [sp, #8]\n\t"
        "str w16, [x17, #0x38]\n\t"
        "ldr x16, [x17, #0x848]\n\t"     /* opt-in recorder */
        "cbz x16, 2f\n\t"
        "str x18, [x17, #0x870]\n\t"     /* pre-switch caller x18 */
        "2:\n\t"
        "add sp, sp, #16\n\t"
        "mov x16, x17\n\t"               /* state for capture common */
        "b \"#xtajit64_capture_native\"\n\t"
        "1: brk #0xf66\n\t" );
}

void WINAPI __attribute__((naked)) DispatchJump(void)
{
    __asm__( "mov w17, #2\n\tb \"#capture_transition\"\n\t" );
}


/**********************************************************************
 *           RetToEntryThunk  (xtajit64.@)
 *
 * Implementation of __os_arm64x_dispatch_ret.
 */
void WINAPI __attribute__((naked)) RetToEntryThunk(void)
{
    __asm__( "mov w17, #0\n\tb \"#capture_transition\"\n\t" );
}


/**********************************************************************
 *           ExitToX64  (xtajit64.@)
 *
 * Implementation of __os_arm64x_dispatch_call_no_redirect.
 */
void WINAPI __attribute__((naked)) ExitToX64(void)
{
    __asm__( "mov w17, #1\n\tb \"#capture_transition\"\n\t" );
}

#else

void WINAPI DispatchJump(void)
{
    ERR( "x64 emulation not implemented\n" );
    NtTerminateProcess( GetCurrentProcess(), 1 );
}

void WINAPI RetToEntryThunk(void)
{
    ERR( "x64 emulation not implemented\n" );
    NtTerminateProcess( GetCurrentProcess(), 1 );
}

void WINAPI ExitToX64(void)
{
    ERR( "x64 emulation not implemented\n" );
    NtTerminateProcess( GetCurrentProcess(), 1 );
}

#endif


/**********************************************************************
 *           BeginSimulation  (xtajit64.@)
 */
#ifdef HAVE_UNICORN
static DECLSPEC_NORETURN void __attribute__((used)) begin_simulation_missing_state(void)
{
    RtlRaiseStatus( STATUS_INVALID_PARAMETER );
    __builtin_unreachable();
}

static DECLSPEC_NORETURN void __attribute__((used)) begin_simulation_on_control_stack(
    struct xtajit64_thread_state *state )
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;

    if (state != get_thread_state() || state->magic != XTAJIT64_THREAD_STATE_MAGIC ||
        state->allocation_size != XTAJIT64_CONTROL_STACK_SIZE ||
        !flight_validate_recorder_layout( state ) ||
        !cpu || !cpu->ContextAmd64)
        RtlRaiseStatus( STATUS_INVALID_PARAMETER );
    if (state->flight_recorder) flight_start_transition( state );
    require_control_stack_simulation_ownership(
        state, cpu, cpu->ContextAmd64,
        "BeginSimulation entered its control stack without simulation ownership" );
    discard_unwound_transition_frames( state,
                                       cpu->ContextAmd64->AMD64_Context.Rsp );
    run_x64_simulation( state );
}

/* The Windows x64 stack remains live for the entire emulation interval and
 * may descend arbitrarily before a suspend or context operation re-enters
 * BeginSimulation.  Reset every non-returning entry to the provider-owned
 * control stack so native dispatcher frames can never overlap guest locals.
 * Validate every value that controls SP before leaving the current stack. */
void WINAPI __attribute__((naked)) BeginSimulation(void)
{
    __asm__(
        "ldr x16, [x18, #0x1788]\n\t"      /* TEB.ChpeV2CpuAreaInfo */
        "cbz x16, 1f\n\t"
        "ldr x0, [x16, #0x30]\n\t"        /* cpu.EmulatorData[0] */
        "cbz x0, 1f\n\t"
        "ldr x17, [x0]\n\t"
        "movz x16, #0x5458\n\t"
        "movk x16, #0x4a41, lsl #16\n\t"
        "movk x16, #0x5449, lsl #32\n\t"
        "movk x16, #0x3634, lsl #48\n\t"
        "cmp x17, x16\n\t"               /* state.magic */
        "b.ne 1f\n\t"
        "ldr x16, [x0, #8]\n\t"          /* state.allocation_size */
        "cmp x16, #0x40, lsl #12\n\t"     /* XTAJIT64_CONTROL_STACK_SIZE */
        "b.ne 1f\n\t"
        "adds x17, x0, x16\n\t"
        "b.cs 1f\n\t"
        "ldr x16, [x0, #0x10]\n\t"       /* state.control_stack_top */
        "ldr x15, [x0, #0x848]\n\t"      /* state.flight_recorder */
        "cbnz x15, 3f\n\t"
        "cmp x16, x17\n\t"               /* diagnostics-disabled top */
        "b.ne 1f\n\t"
        "b 4f\n\t"
        "3:\n\t"
        "tst x17, #63\n\t"
        "b.ne 1f\n\t"
        "movz x9, #0x6880\n\t"           /* XTAJIT64_FLIGHT_RECORDER_SIZE */
        "sub x9, x17, x9\n\t"
        "cmp x15, x9\n\t"                /* exact high-end recorder */
        "b.ne 1f\n\t"
        "tst x15, #63\n\t"
        "b.ne 1f\n\t"
        "cmp x16, x15\n\t"               /* recorder owns stack high end */
        "b.ne 1f\n\t"
        "add x9, x0, #0xca0\n\t"         /* rounded state/control low */
        "cmp x15, x9\n\t"
        "b.ls 1f\n\t"
        "sub x9, x15, x9\n\t"
        "cmp x9, #0x10, lsl #12\n\t"     /* at least 64 KiB stack */
        "b.lo 1f\n\t"
        "4:\n\t"
        "tst x16, #15\n\t"
        "b.ne 1f\n\t"
        "str x18, [x0, #0x870]\n\t"      /* state.capture_x18 */
        /* BeginSimulation can be re-entered after the preceding native owner
         * released simulation.  Acquire it before the private control stack
         * becomes the live architectural SP. */
        "ldr x9, [x18, #0x1788]\n\t"      /* TEB.ChpeV2CpuAreaInfo */
        "cbz x9, 1f\n\t"
        "mov w15, #1\n\t"
        "stlrb w15, [x9]\n\t"            /* cpu.InSimulation, release */
        "mov sp, x16\n\t"
        "adr x30, 2f\n\t"
        "b \"#begin_simulation_on_control_stack\"\n\t"
        "1: b \"#begin_simulation_missing_state\"\n\t"
        "2: brk #0xf67\n\t" );
}
#else
void WINAPI BeginSimulation(void)
{
    ERR( "x64 emulation not implemented\n" );
    NtTerminateProcess( GetCurrentProcess(), 1 );
}
#endif


/**********************************************************************
 *           BTCpu64FlushInstructionCache  (xtajit64.@)
 */
void WINAPI BTCpu64FlushInstructionCache( void *addr, SIZE_T size )
{
    TRACE( "%p %Ix\n", addr, size );
#ifdef HAVE_UNICORN
    flush_unicorn_cache( addr, size );
#endif
}


/**********************************************************************
 *           BTCpu64IsProcessorFeaturePresent  (xtajit64.@)
 */
BOOLEAN WINAPI BTCpu64IsProcessorFeaturePresent( UINT feature )
{
    static const ULONGLONG x86_features =
        (1ull << PF_COMPARE_EXCHANGE_DOUBLE) |
        (1ull << PF_MMX_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_XMMI_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_RDTSC_INSTRUCTION_AVAILABLE) |
        (1ull << PF_XMMI64_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_NX_ENABLED) |
        (1ull << PF_SSE3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_COMPARE_EXCHANGE128) |
        (1ull << PF_FASTFAIL_AVAILABLE) |
        (1ull << PF_RDTSCP_INSTRUCTION_AVAILABLE) |
        (1ull << PF_SSSE3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SSE4_1_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SSE4_2_INSTRUCTIONS_AVAILABLE);

    return feature < 64 && (x86_features & (1ull << feature));
}


/**********************************************************************
 *           BTCpu64NotifyMemoryDirty  (xtajit64.@)
 */
void WINAPI BTCpu64NotifyMemoryDirty( void *addr, SIZE_T size )
{
    TRACE( "%p %Ix\n", addr, size );
#ifdef HAVE_UNICORN
    flush_unicorn_cache( addr, size );
#endif
}


/**********************************************************************
 *           BTCpu64NotifyReadFile  (xtajit64.@)
 */
void WINAPI BTCpu64NotifyReadFile( HANDLE handle, void *addr, SIZE_T size, BOOL is_post, NTSTATUS status )
{
    (void)is_post;
    (void)status;
    TRACE( "%p %p %Ix\n", handle, addr, size );
#ifdef HAVE_UNICORN
    if (is_post && !status) flush_unicorn_cache( addr, size );
#endif
}


/**********************************************************************
 *           FlushInstructionCacheHeavy  (xtajit64.@)
 */
void WINAPI FlushInstructionCacheHeavy( void *addr, SIZE_T size )
{
    TRACE( "%p %Ix\n", addr, size );
#ifdef HAVE_UNICORN
    flush_unicorn_cache( addr, size );
#endif
}


/**********************************************************************
 *           ResyncIdentityMemoryMappingsStatus  (xtajit64.@)
 *
 * Status-returning initialization barrier for the target-owned cross-process
 * work list.  Keep this separate from the legacy void callback below so a
 * mismatched older provider cannot be mistaken for a successful resync.
 */
NTSTATUS WINAPI ResyncIdentityMemoryMappingsStatus(void)
{
#ifdef HAVE_UNICORN
    invalidate_transition_caches();
    return resync_existing_mappings();
#else
    return STATUS_SUCCESS;
#endif
}


/**********************************************************************
 *           ResyncIdentityMemoryMappings  (xtajit64.@)
 *
 * Rebuild the legacy identity lane from the target process after an external
 * address-space mutation.  The Unix provider preserves observer-owned LOW
 * ranges while atomically replacing identity state.
 */
void WINAPI ResyncIdentityMemoryMappings(void)
{
#ifdef HAVE_UNICORN
    NTSTATUS status;

    if ((status = ResyncIdentityMemoryMappingsStatus()))
        poison_provider( "authoritative identity mapping resynchronization", status );
#endif
}


/**********************************************************************
 *           NotifyMapViewOfSection  (xtajit64.@)
 */
NTSTATUS WINAPI NotifyMapViewOfSection( void *unk1, void *addr, void *unk2, SIZE_T size,
                                        ULONG alloc_type, ULONG protect )
{
#ifdef HAVE_UNICORN
    ULONG_PTR lowest = (ULONG_PTR)addr;
    NTSTATUS status;

    if (!lowest || !size || lowest > ~(ULONG_PTR)0 - size)
    {
        status = STATUS_INVALID_ADDRESS;
        poison_provider( "mapped-view range validation", status );
    }
    else if ((status = synchronize_mapping_window( lowest, lowest + size )))
    {
        /* The LOW lane is owned by the native observer.  A stale legacy
         * callback that intersects it is a validation-only no-op. */
        if (status == STATUS_ACCESS_DENIED) status = STATUS_SUCCESS;
        else poison_provider( "mapped-view synchronization", status );
    }
#endif

    (void)unk1;
    (void)unk2;
    TRACE( "%p %Ix %lx %lx\n", addr, size, alloc_type, protect );
#ifdef HAVE_UNICORN
    return status;
#else
    return STATUS_SUCCESS;
#endif
}


/**********************************************************************
 *           NotifyMemoryAlloc  (xtajit64.@)
 */
void WINAPI NotifyMemoryAlloc( void *addr, SIZE_T size, ULONG type, ULONG prot, BOOL is_post, NTSTATUS status )
{
    (void)type;
    (void)prot;
    (void)is_post;
    (void)status;
    TRACE( "%p %Ix\n", addr, size );
#ifdef HAVE_UNICORN
    if (is_post && !status && (type & (MEM_RESERVE | MEM_COMMIT)))
    {
        struct xtajit64_memory_params params;
        ULONG_PTR allocation_base;

        if ((status = get_allocation_base( addr, &allocation_base )))
            poison_provider( "allocation-base query", status );
        else if ((status = describe_host_mapping( (ULONG_PTR)addr, size,
                                                   allocation_base,
                                                   (type & MEM_COMMIT) ? prot : PAGE_NOACCESS,
                                                   &params )))
        {
            if (status != STATUS_ACCESS_DENIED)
                poison_provider( "allocation address translation", status );
        }
        else if ((status = XTAJIT64_CALL( memory_map, &params )) &&
                 status != STATUS_ACCESS_DENIED)
            poison_provider( "allocation synchronization", status );
    }
#endif
}


/**********************************************************************
 *           NotifyMemoryFree  (xtajit64.@)
 */
void WINAPI NotifyMemoryFree( void *addr, SIZE_T size, ULONG type, BOOL is_post, NTSTATUS status )
{
    (void)is_post;
    (void)status;
    TRACE( "%p %Ix %lx\n", addr, size, type );
#ifdef HAVE_UNICORN
    if (is_post && !status)
    {
        NTSTATUS sync_status;
        struct xtajit64_memory_params params =
        {
            .guest = (ULONG_PTR)addr,
            .host = (ULONG_PTR)addr,
            .size = size,
            .protect = type,
        };

        invalidate_transition_caches();
        sync_status = XTAJIT64_CALL( memory_unmap, &params );
        if (sync_status && sync_status != STATUS_ACCESS_DENIED)
            poison_provider( "allocation-free synchronization", sync_status );
    }
#endif
}


/**********************************************************************
 *           NotifyMemoryProtect  (xtajit64.@)
 */
void WINAPI NotifyMemoryProtect( void *addr, SIZE_T size, ULONG prot, BOOL is_post, NTSTATUS status )
{
    (void)is_post;
    (void)status;
    TRACE( "%p %Ix %lx\n", addr, size, prot );
#ifdef HAVE_UNICORN
    if (is_post && !status)
    {
        NTSTATUS sync_status;
        struct xtajit64_memory_params params =
        {
            .guest = (ULONG_PTR)addr,
            .host = (ULONG_PTR)addr,
            .size = size,
            .protect = prot,
        };

        invalidate_transition_caches();
        /* Native stack pages below StackLimit were not in the initial CPU
         * window. Reconcile the authoritative post-state before asking the
         * provider to protect a range it may never have registered. */
        if ((ULONG_PTR)addr >= (ULONG_PTR)NtCurrentTeb()->DeallocationStack &&
            (ULONG_PTR)addr < (ULONG_PTR)NtCurrentTeb()->Tib.StackLimit &&
            size && size <= ~(ULONG_PTR)0 - (ULONG_PTR)addr &&
            (ULONG_PTR)addr + size <= (ULONG_PTR)NtCurrentTeb()->Tib.StackBase)
        {
            sync_status = synchronize_mapping_window( (ULONG_PTR)addr, (ULONG_PTR)addr + size );
            if (sync_status)
            {
                poison_provider( "stack protection post-state registration", sync_status );
                return;
            }
        }
        sync_status = XTAJIT64_CALL( memory_protect, &params );
        if (sync_status && sync_status != STATUS_ACCESS_DENIED)
            poison_provider( "memory-protection synchronization", sync_status );
    }
#endif
}


/**********************************************************************
 *           NotifyUnmapViewOfSection  (xtajit64.@)
 */
void WINAPI NotifyUnmapViewOfSection( void *addr, BOOL is_post, NTSTATUS status )
{
    (void)is_post;
    (void)status;
    TRACE( "%p\n", addr );
#ifdef HAVE_UNICORN
    if (is_post && !status)
    {
        NTSTATUS sync_status;
        struct xtajit64_memory_params params =
        {
            .guest = (ULONG_PTR)addr,
            .host = (ULONG_PTR)addr,
        };

        invalidate_transition_caches();
        sync_status = XTAJIT64_CALL( memory_unmap, &params );
        if (sync_status && sync_status != STATUS_ACCESS_DENIED)
            poison_provider( "mapped-view unmap synchronization", sync_status );
    }
#endif
}


/**********************************************************************
 *           ProcessInit  (xtajit64.@)
 */
NTSTATUS WINAPI ProcessInit(void)
{
#ifdef HAVE_UNICORN
    SYSTEM_BASIC_INFORMATION info;
    struct xtajit64_process_init_params params = {0};
    UNICODE_STRING ntdll_name = RTL_CONSTANT_STRING( L"ntdll.dll" );
    HMODULE ntdll;
    ULONG syscall_count;
    ULONG_PTR syscall_dispatcher;
    ULONG_PTR shared_data;
    ULONG_PTR rtl_query_performance_counter;
    ULONG_PTR nt_query_performance_counter;
    NTSTATUS status;

    TRACE( "CPU provider interface %s\n", XTAJIT64_PROVIDER_ABI_IDENTITY );
    init_flight_recorder_enablement();
    if ((status = init_unixlib())) return status;
    status = NtQuerySystemInformation( SystemBasicInformation, &info, sizeof(info), NULL );
    if (status) return status;
    if (info.PageSize < XTAJIT64_GUEST_PAGE_SIZE ||
        info.PageSize > XTAJIT64_MAX_HOST_PAGE_SIZE ||
        (info.PageSize & (info.PageSize - 1)))
        return STATUS_INVALID_PARAMETER;
    shared_data = (ULONG_PTR)NtCurrentTeb()->Peb->SharedData;
    if (!shared_data || (shared_data & (info.PageSize - 1)) ||
        (XTAJIT64_GUEST_KUSER & (info.PageSize - 1)))
        return STATUS_INVALID_ADDRESS;
    if ((status = LdrGetDllHandle( NULL, 0, &ntdll_name, &ntdll ))) return status;
    rtl_exit_user_thread = (ULONG_PTR)resolve_arm64ec_export( ntdll, "RtlExitUserThread" );
    if (!rtl_exit_user_thread) return STATUS_ENTRYPOINT_NOT_FOUND;
    /* This is an optional provider fastpath target.  Keep process startup
     * independent from its availability so a different ntdll build simply
     * takes the ordinary ARM64EC transition path. */
    rtl_query_performance_counter = (ULONG_PTR)resolve_arm64ec_export(
        ntdll, "RtlQueryPerformanceCounter" );
    nt_query_performance_counter = (ULONG_PTR)RtlFindExportedRoutineByName(
        ntdll, "NtQueryPerformanceCounter" );
    if ((status = __wine_arm64ec_get_x64_syscall_dispatcher( &syscall_dispatcher,
                                                             &syscall_count )))
        return status;

    params.ec_bitmap = (ULONG_PTR)NtCurrentTeb()->Peb->EcCodeBitMap;
    params.highest_user_address = (ULONG_PTR)info.HighestUserAddress;
    params.guest_kuser = XTAJIT64_GUEST_KUSER;
    params.host_kuser = shared_data;
    params.kuser_size = info.PageSize;
    params.rtl_exit_user_thread = rtl_exit_user_thread;
    params.abi_version = XTAJIT64_PROCESS_ABI_VERSION;
    params.abi_size = sizeof(params);
    params.required_capabilities = XTAJIT64_CAPABILITIES;
    params.x64_syscall_dispatcher = syscall_dispatcher;
    params.x64_syscall_count = syscall_count;
    params.rtl_query_performance_counter = rtl_query_performance_counter;
    params.nt_query_performance_counter = nt_query_performance_counter;
    if ((status = XTAJIT64_CALL( process_init, &params ))) return status;
    if ((params.enabled_capabilities & params.required_capabilities) !=
            params.required_capabilities ||
        (params.enabled_capabilities & ~XTAJIT64_CAPABILITIES))
    {
        XTAJIT64_CALL( process_term, NULL );
        rtl_exit_user_thread = 0;
        return STATUS_REVISION_MISMATCH;
    }
    host_page_size = info.PageSize;
    status = resync_existing_mappings();
    if (status)
    {
        XTAJIT64_CALL( process_term, NULL );
        rtl_exit_user_thread = 0;
        host_page_size = 0;
    }
    return status;
#else
    return STATUS_SUCCESS;
#endif
}


/**********************************************************************
 *           ProcessTerm  (xtajit64.@)
 */
void WINAPI ProcessTerm( HANDLE handle, BOOL is_post, NTSTATUS status )
{
    (void)xtajit64_process_term_notification_may_cleanup( (UINT_PTR)handle,
                                                          is_post, status );
    TRACE( "soft process termination notification handle %p post %u status %#lx\n",
           handle, is_post, status );
}


/**********************************************************************
 *           ResetToConsistentState  (xtajit64.@)
 */
void WINAPI ResetToConsistentState( EXCEPTION_RECORD *rec, CONTEXT *context, ARM64_NT_CONTEXT *arm_ctx )
{
    TRACE( "%p %p %p\n", rec, context, arm_ctx );
}


/**********************************************************************
 *           ThreadInit  (xtajit64.@)
 */
NTSTATUS WINAPI ThreadInit(void)
{
#ifdef HAVE_UNICORN
    CHPE_V2_CPU_AREA_INFO *cpu;
    struct xtajit64_thread_state *state;
    TEB *teb;
    NTSTATUS cleanup_status, status;
    BOOL provider_touched;

    if ((status = query_current_thread_teb( &teb ))) return status;
    cpu = teb->ChpeV2CpuAreaInfo;
    if (!cpu || !cpu->ContextAmd64) return STATUS_INVALID_PARAMETER;
    if ((state = cpu->EmulatorData[0]))
    {
        if (state->magic != XTAJIT64_THREAD_STATE_MAGIC ||
            !flight_validate_recorder_layout( state ) ||
            state->flight_expected_teb != (ULONG_PTR)teb ||
            (cpu->SuspendDoorbell &&
             cpu->SuspendDoorbell != &state->suspend_doorbell))
            return STATUS_ALREADY_INITIALIZED;
        cpu->SuspendDoorbell = &state->suspend_doorbell;
        return STATUS_SUCCESS;
    }
    if ((status = synchronize_current_thread_mappings()))
    {
        poison_provider( "thread mapping synchronization", status );
        return status;
    }
    if ((status = allocate_transition_state( &state ))) return status;
    state->flight_expected_teb = (ULONG_PTR)teb;
    /* Publish this known uniform allocation directly while ntdll defers its
     * nested VM notification.  Ntdll acknowledges the exact single mutation;
     * any additional or concurrent mutation retains the full-resync fallback. */
    if ((status = synchronize_transition_state_mapping( state, &provider_touched )))
    {
        if (!provider_touched) free_transition_state( state );
        else poison_provider( "transition-state synchronization", status );
        return status;
    }
    if ((status = XTAJIT64_CALL( thread_init, NULL )))
    {
        cleanup_status = unregister_transition_state_mapping( state );
        if (!cleanup_status) cleanup_status = free_transition_state( state );
        if (cleanup_status) poison_provider( "transition-state cleanup", cleanup_status );
        return status;
    }

    cpu->SuspendDoorbell = &state->suspend_doorbell;
    if (state->flight_recorder)
        flight_record_cpu_event( state, NULL, &cpu->ContextAmd64->AMD64_Context,
                                 XTAJIT64_FLIGHT_UNKNOWN_U64,
                                 XTAJIT64_FLIGHT_UNKNOWN_U64,
                                 XTAJIT64_FLIGHT_UNKNOWN_U64,
                                 XTAJIT64_FLIGHT_UNKNOWN_U64,
                                 XTAJIT64_FLIGHT_EVENT_RECORDER_READY,
                                 XTAJIT64_FLIGHT_REASON_NONE );
    cpu->EmulatorData[0] = state;
    return STATUS_SUCCESS;
#else
    return STATUS_SUCCESS;
#endif
}


/**********************************************************************
 *           ThreadTerm  (xtajit64.@)
 */
BOOL WINAPI ThreadExitReady(void)
{
#ifdef HAVE_UNICORN
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    if (!cpu || cpu->EmulatorData[0] || cpu->SuspendDoorbell || !__wine_unixlib_handle) return FALSE;
    return !XTAJIT64_CALL( thread_exit_ready, NULL );
#else
    return FALSE;
#endif
}

void WINAPI ThreadTerm( HANDLE handle, LONG exit_code )
{
#ifdef HAVE_UNICORN
    struct xtajit64_thread_state *state = NULL;
    CHPE_V2_CPU_AREA_INFO *cpu;
    ULONG_PTR native_stack_allocation = 0, emulator_stack_allocation = 0;
    ULONG_PTR teb_limit = 0, teb_base = 0;
    UINT64 teb_allocation = 0;
    NTSTATUS status;
#endif

    TRACE( "%p %lx\n", handle, exit_code );
#ifdef HAVE_UNICORN

    if (!RtlIsCurrentThread( handle )) return;
    if ((cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo) && (state = get_thread_state()) &&
        state->flight_recorder)
        flight_dump_if_frozen( state, "thread termination" );
    get_current_thread_teb_window( &teb_limit, &teb_base, &teb_allocation );
    get_allocation_base( &state, &native_stack_allocation );
    if ((cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo) && cpu->EmulatorStackBase > cpu->EmulatorStackLimit)
        get_allocation_base( (void *)(cpu->EmulatorStackBase - 1),
                             &emulator_stack_allocation );
    if (__wine_unixlib_handle) XTAJIT64_CALL( thread_term, NULL );
    if (teb_allocation != native_stack_allocation &&
        teb_allocation != emulator_stack_allocation)
        unregister_thread_teb_window( teb_limit, teb_base );
    unregister_thread_stack_allocation( native_stack_allocation );
    if (emulator_stack_allocation != native_stack_allocation)
        unregister_thread_stack_allocation( emulator_stack_allocation );
    if (!cpu || !(state = get_thread_state())) return;
    if (cpu->SuspendDoorbell &&
        cpu->SuspendDoorbell != &state->suspend_doorbell)
    {
        poison_provider( "thread doorbell ownership", STATUS_INVALID_DEVICE_STATE );
        return;
    }
    cpu->SuspendDoorbell = NULL;
    if ((status = unregister_transition_state_mapping( state )))
    {
        cpu->SuspendDoorbell = &state->suspend_doorbell;
        poison_provider( "transition-state unregister", status );
        return;
    }
    if (state->allocation_size <= ~(ULONG_PTR)0 - (ULONG_PTR)state &&
        (ULONG_PTR)&state >= (ULONG_PTR)state &&
        (ULONG_PTR)&state < (ULONG_PTR)state + state->allocation_size)
    {
        cpu->EmulatorData[0] = NULL;
        state->magic = 0;
        ERR( "cannot release x64 transition state while running on its control stack\n" );
    }
    else
    {
        cpu->EmulatorData[0] = NULL;
        state->magic = 0;
        if ((status = free_transition_state( state )))
        {
            state->magic = XTAJIT64_THREAD_STATE_MAGIC;
            cpu->EmulatorData[0] = state;
            cpu->SuspendDoorbell = &state->suspend_doorbell;
            poison_provider( "transition-state release", status );
        }
    }
#endif
}


/**********************************************************************
 *           UpdateProcessorInformation  (xtajit64.@)
 */
void WINAPI UpdateProcessorInformation( SYSTEM_CPU_INFORMATION *info )
{
    info->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
    info->ProcessorLevel = 21;
    info->ProcessorRevision = 1;
}


/**********************************************************************
 *           DllMain
 */
BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, void *reserved )
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
    {
        LdrDisableThreadCalloutsForDll( inst );
#ifdef HAVE_UNICORN
        if (init_unixlib()) return FALSE;
#endif
    }
    return TRUE;
}
