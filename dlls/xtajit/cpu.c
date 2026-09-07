/*
 * i386 emulation on ARM64
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <string.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/debug.h"
#include "context_generation.h"
#include "process_lifecycle.h"
#include "unixlib.h"

WINE_DEFAULT_DEBUG_CHANNEL(xtajit);

#ifdef HAVE_UNICORN

#define XTAJIT_CALL(func,params) WINE_UNIX_CALL( unix_ ## func, params )

static NTSTATUS (WINAPI *native_unix_call_dispatcher)( unixlib_handle_t, unsigned int, void * );
static ULONG_PTR low_va_shadow_base;
static ULONG emulated_highest_user_address;
static LONG fatal_termination_started;
static LONG memory_observer_active;

struct xtajit_thread_state
{
    struct xtajit_thread_state *next;
    WOW64_CPURESERVED *cpu;
    struct xtajit_context_generation context_generation;
};

static RTL_SRWLOCK thread_state_lock = RTL_SRWLOCK_INIT;
static struct xtajit_thread_state *thread_states;

static NTSTATUS init_unixlib(void)
{
    if (__wine_unixlib_handle) return STATUS_SUCCESS;
    return __wine_init_unix_call();
}

static BOOL host_to_guest_address( ULONG_PTR host, BOOL allow_end, ULONG *guest )
{
    UINT64 normalized;

    if (!guest || !xtajit_normalize_shadow_address( host, allow_end, &normalized )) return FALSE;
    if (low_va_shadow_base)
    {
        if (host < low_va_shadow_base ||
            host - low_va_shadow_base > WINE_LOW_VA_SHADOW_SIZE ||
            (!allow_end && host - low_va_shadow_base == WINE_LOW_VA_SHADOW_SIZE))
            return FALSE;
    }
    if (normalized > ~(ULONG)0) return FALSE;
    *guest = normalized;
    return TRUE;
}

static BOOL host_to_guest_range( ULONG_PTR host, SIZE_T size, UINT64 *guest )
{
    if (!guest || !xtajit_normalize_shadow_range( host, size, guest )) return FALSE;
    if (low_va_shadow_base &&
        (host < low_va_shadow_base || host - low_va_shadow_base >= WINE_LOW_VA_SHADOW_SIZE ||
         size > WINE_LOW_VA_SHADOW_SIZE - (host - low_va_shadow_base)))
        return FALSE;
    return *guest + size <= WINE_LOW_VA_SHADOW_SIZE;
}

static void *guest_to_host_address( ULONG guest )
{
    if (!guest) return NULL;
    if (low_va_shadow_base) return (void *)(low_va_shadow_base + guest);
    return ULongToPtr( guest );
}

static NTSTATUS read_guest_memory( ULONG guest, void *buffer, SIZE_T size )
{
    SIZE_T read = 0;
    NTSTATUS status;

    if (!guest || guest > ~(ULONG)0 - size) return STATUS_ACCESS_VIOLATION;
    status = NtReadVirtualMemory( GetCurrentProcess(), guest_to_host_address( guest ),
                                  buffer, size, &read );
    if (!status && read != size) status = STATUS_PARTIAL_COPY;
    return status;
}

static void context_to_unix( struct xtajit_i386_context *dst, const I386_CONTEXT *src )
{
    const XSAVE_FORMAT *fpux = (const XSAVE_FORMAT *)src->ExtendedRegisters;
    unsigned int i;

    memset( dst, 0, sizeof(*dst) );
    dst->eax = src->Eax;
    dst->ebx = src->Ebx;
    dst->ecx = src->Ecx;
    dst->edx = src->Edx;
    dst->esi = src->Esi;
    dst->edi = src->Edi;
    dst->ebp = src->Ebp;
    dst->esp = src->Esp;
    dst->eip = src->Eip;
    dst->eflags = src->EFlags ? src->EFlags : 0x202;
    xtajit_context_segments_to_unix( dst, src );

    dst->mxcsr = fpux->MxCsr ? fpux->MxCsr : 0x1f80;
    memcpy( dst->xmm, fpux->XmmRegisters, sizeof(dst->xmm) );
    dst->fp_control = src->FloatSave.ControlWord ? src->FloatSave.ControlWord : 0x037f;
    dst->fp_status = src->FloatSave.StatusWord;
    dst->fp_tag = src->FloatSave.ControlWord ? src->FloatSave.TagWord : 0xffff;
    dst->fp_valid = 1;
    for (i = 0; i < ARRAY_SIZE(dst->st); ++i)
        memcpy( dst->st[i], src->FloatSave.RegisterArea + i * 10, 10 );
}

static UINT8 full_tag_to_abridged( UINT16 tag )
{
    UINT8 abridged = 0;
    unsigned int i;

    for (i = 0; i < 8; ++i)
        if (((tag >> (i * 2)) & 3) != 3) abridged |= 1u << i;
    return abridged;
}

static void context_from_unix( I386_CONTEXT *dst, const struct xtajit_i386_context *src )
{
    XSAVE_FORMAT *fpux = (XSAVE_FORMAT *)dst->ExtendedRegisters;
    unsigned int i;

    dst->Eax = src->eax;
    dst->Ebx = src->ebx;
    dst->Ecx = src->ecx;
    dst->Edx = src->edx;
    dst->Esi = src->esi;
    dst->Edi = src->edi;
    dst->Ebp = src->ebp;
    dst->Esp = src->esp;
    dst->Eip = src->eip;
    dst->EFlags = src->eflags;
    xtajit_context_segments_from_unix( dst, src );

    dst->FloatSave.ControlWord = src->fp_control;
    dst->FloatSave.StatusWord = src->fp_status;
    dst->FloatSave.TagWord = src->fp_tag;
    for (i = 0; i < ARRAY_SIZE(src->st); ++i)
        memcpy( dst->FloatSave.RegisterArea + i * 10, src->st[i], 10 );

    fpux->ControlWord = src->fp_control;
    fpux->StatusWord = src->fp_status;
    fpux->TagWord = full_tag_to_abridged( src->fp_tag );
    fpux->MxCsr = src->mxcsr;
    for (i = 0; i < ARRAY_SIZE(src->st); ++i)
        memcpy( &fpux->FloatRegisters[i], src->st[i], 10 );
    memcpy( fpux->XmmRegisters, src->xmm, sizeof(src->xmm) );
}

static NTSTATUS get_current_cpu_area( WOW64_CPURESERVED **cpu, I386_CONTEXT **context )
{
    WOW64_CPU_AREA_INFO info;
    NTSTATUS status;

    if (!cpu || !context || !NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED])
        return STATUS_INVALID_PARAMETER;
    *cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED];
    if ((status = RtlWow64GetCpuAreaInfo( *cpu, 0, &info ))) return status;
    if (info.Machine != IMAGE_FILE_MACHINE_I386 || !info.Context)
        return STATUS_INVALID_IMAGE_FORMAT;
    *context = info.Context;
    return STATUS_SUCCESS;
}

static struct xtajit_thread_state *find_thread_state( WOW64_CPURESERVED *cpu )
{
    struct xtajit_thread_state *state;

    /* Callers only retain their own current-thread record.  The owning thread
     * removes it after simulation in BTCpuThreadTerm; process exit reclaims
     * any remaining process-lifetime records. */
    RtlAcquireSRWLockShared( &thread_state_lock );
    for (state = thread_states; state; state = state->next)
        if (state->cpu == cpu) break;
    RtlReleaseSRWLockShared( &thread_state_lock );
    return state;
}

static NTSTATUS register_thread_state( WOW64_CPURESERVED *cpu,
                                       struct xtajit_thread_state **result )
{
    struct xtajit_thread_state *state, *allocated;

    if (!cpu || !result) return STATUS_INVALID_PARAMETER;
    if (!(allocated = RtlAllocateHeap( NtCurrentTeb()->Peb->ProcessHeap,
                                       HEAP_ZERO_MEMORY, sizeof(*allocated) )))
        return STATUS_NO_MEMORY;
    allocated->cpu = cpu;

    RtlAcquireSRWLockExclusive( &thread_state_lock );
    for (state = thread_states; state; state = state->next)
        if (state->cpu == cpu) break;
    if (!state)
    {
        state = allocated;
        state->next = thread_states;
        thread_states = state;
        allocated = NULL;
    }
    RtlReleaseSRWLockExclusive( &thread_state_lock );

    if (allocated) RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, allocated );
    *result = state;
    return STATUS_SUCCESS;
}

static void unregister_thread_state( WOW64_CPURESERVED *cpu )
{
    struct xtajit_thread_state **cursor, *state = NULL;

    if (!cpu) return;
    RtlAcquireSRWLockExclusive( &thread_state_lock );
    for (cursor = &thread_states; *cursor; cursor = &(*cursor)->next)
    {
        if ((*cursor)->cpu != cpu) continue;
        state = *cursor;
        *cursor = state->next;
        break;
    }
    RtlReleaseSRWLockExclusive( &thread_state_lock );
    if (state) RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, state );
}

static void poison_provider( const char *operation, NTSTATUS status )
{
    struct xtajit_poison_params params = { .status = status };

    ERR( "%s failed, poisoning i386 provider with status %#lx\n", operation, status );
    if (__wine_unixlib_handle) XTAJIT_CALL( poison, &params );
}

static NTSTATUS get_allocation_base( const void *address, UINT64 *base )
{
    MEMORY_BASIC_INFORMATION info;
    ULONG guest;
    NTSTATUS status;

    status = NtQueryVirtualMemory( GetCurrentProcess(), address, MemoryBasicInformation,
                                   &info, sizeof(info), NULL );
    if (!status && info.AllocationBase &&
        host_to_guest_address( (ULONG_PTR)info.AllocationBase, FALSE, &guest ))
        *base = guest;
    else if (!status) status = STATUS_INVALID_ADDRESS;
    return status;
}

static NTSTATUS query_translated_run_ownership( ULONG_PTR start, ULONG_PTR end,
                                                ULONG *translated )
{
    ULONG first = 1, last = 1;
    NTSTATUS status;

    if (!translated || start >= end) return STATUS_INVALID_PARAMETER;
    if (!low_va_shadow_base)
    {
        *translated = 1;
        return STATUS_SUCCESS;
    }

    status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)start,
                                   MemoryWineWow64TranslatedInformation,
                                   &first, sizeof(first), NULL );
    if (status) return status;
    status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)(end - 1),
                                   MemoryWineWow64TranslatedInformation,
                                   &last, sizeof(last), NULL );
    if (status) return status;
    if (first > 1 || last > 1) return STATUS_INVALID_PARAMETER;
    if (first != last) return STATUS_INVALID_ADDRESS;
    *translated = first;
    return STATUS_SUCCESS;
}

static NTSTATUS recover_translated_fault_page( const struct xtajit_begin_params *begin )
{
    struct xtajit_memory_params params = { .size = XTAJIT_GUEST_PAGE_SIZE };
    ULONG_PTR host_page, region_base, region_end;
    MEMORY_BASIC_INFORMATION info;
    ULONG translated = low_va_shadow_base ? ~0u : 1;
    UINT64 normalized;
    NTSTATUS status;

    if (!begin || begin->stop_reason != XTAJIT_STOP_UNMAPPED_MEMORY ||
        begin->fault_address > emulated_highest_user_address)
        return STATUS_ACCESS_VIOLATION;
    params.guest = begin->fault_address & ~(UINT64)(XTAJIT_GUEST_PAGE_SIZE - 1);
    if (!params.guest || params.guest > ~(ULONG_PTR)0 - low_va_shadow_base)
        return STATUS_ACCESS_VIOLATION;
    host_page = low_va_shadow_base + (ULONG_PTR)params.guest;

    status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)host_page,
                                   MemoryBasicInformation, &info, sizeof(info), NULL );
    if (status) return status;
    region_base = (ULONG_PTR)info.BaseAddress;
    if (info.State != MEM_COMMIT || !info.AllocationBase ||
        info.RegionSize < XTAJIT_GUEST_PAGE_SIZE ||
        region_base > ~(ULONG_PTR)0 - info.RegionSize)
        return STATUS_NOT_MAPPED_VIEW;
    region_end = region_base + info.RegionSize;
    if (host_page < region_base || host_page > region_end - XTAJIT_GUEST_PAGE_SIZE)
        return STATUS_NOT_MAPPED_VIEW;

    if (low_va_shadow_base)
    {
        status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)host_page,
                                       MemoryWineWow64TranslatedInformation,
                                       &translated, sizeof(translated), NULL );
        if (status) return status;
    }
    if (translated != 1)
        return translated ? STATUS_INVALID_PARAMETER : STATUS_NOT_SUPPORTED;

    params.host = host_page;
    params.protect = info.Protect;
    if (!host_to_guest_range( host_page, params.size, &normalized ) ||
        normalized != params.guest)
        return STATUS_INVALID_ADDRESS;
    if ((status = get_allocation_base( (void *)host_page, &params.allocation_base ))) return status;
    if ((status = XTAJIT_CALL( memory_map, &params ))) return status;

    TRACE( "recovered tagged post-init mapping guest %08llx host %p protect %#lx "
           "after Unicorn fault type %u\n", (unsigned long long)params.guest,
           (void *)host_page, info.Protect, begin->fault_type );
    return STATUS_SUCCESS;
}

static NTSTATUS sync_translated_mapping_range( ULONG_PTR address, SIZE_T size )
{
    ULONG_PTR cursor, end;
    UINT64 normalized;
    unsigned int count = 0, runs = 0;

    if (!address || !size || (address | size) & (XTAJIT_GUEST_PAGE_SIZE - 1) ||
        address > ~(ULONG_PTR)0 - size || !host_to_guest_range( address, size, &normalized ))
        return STATUS_INVALID_ADDRESS;
    end = address + size;

    /* NtMapViewOfSection's single Protect argument describes the requested
     * view, not the final per-section protections of an image.  MBI returns a
     * maximal same-state/protection run; map each bounded run rather than
     * issuing two native queries per logical page. */
    for (cursor = address; cursor < end;)
    {
        struct xtajit_memory_params params = {0};
        MEMORY_BASIC_INFORMATION info;
        ULONG_PTR region_base, run_end;
        ULONG allocation_guest, translated;
        NTSTATUS status;

        status = NtQueryVirtualMemory( GetCurrentProcess(), (void *)cursor,
                                       MemoryBasicInformation, &info, sizeof(info), NULL );
        if (status) return status;
        region_base = (ULONG_PTR)info.BaseAddress;
        if (!xtajit_bounded_region_run( cursor, end, region_base,
                                         info.RegionSize, &run_end ))
            return STATUS_INVALID_ADDRESS;
        if (info.State == MEM_FREE || !info.AllocationBase) return STATUS_NOT_MAPPED_VIEW;
        if ((status = query_translated_run_ownership( cursor, run_end, &translated )))
            return status;
        if (translated != 1) return STATUS_NOT_SUPPORTED;
        if (info.State != MEM_COMMIT)
        {
            cursor = run_end;
            continue;
        }
        if (!host_to_guest_address( (ULONG_PTR)info.AllocationBase, FALSE,
                                    &allocation_guest ))
            return STATUS_INVALID_ADDRESS;

        params.host = cursor;
        params.size = run_end - cursor;
        params.protect = info.Protect;
        if (!host_to_guest_range( cursor, params.size, &params.guest ))
            return STATUS_INVALID_ADDRESS;
        params.allocation_base = allocation_guest;
        if ((status = XTAJIT_CALL( memory_map, &params ))) return status;
        count += params.size / XTAJIT_GUEST_PAGE_SIZE;
        ++runs;
        cursor = run_end;
    }
    TRACE( "synchronized %u committed logical pages in %u protection runs for "
           "translated view %p-%p\n", count, runs, (void *)address, (void *)end );
    return STATUS_SUCCESS;
}

static void flush_unicorn_cache( const void *address, SIZE_T size )
{
    struct xtajit_memory_params params = { .size = size };
    NTSTATUS status;

    if (address && size && !host_to_guest_range( (ULONG_PTR)address, size, &params.guest ))
    {
        poison_provider( "instruction-cache address normalization", STATUS_INVALID_ADDRESS );
        return;
    }
    if ((!address || !size) && address)
    {
        ULONG guest;

        if (!host_to_guest_address( (ULONG_PTR)address, FALSE, &guest ))
        {
            poison_provider( "instruction-cache address normalization", STATUS_INVALID_ADDRESS );
            return;
        }
        params.guest = guest;
    }
    if (__wine_unixlib_handle &&
        (status = XTAJIT_CALL( flush_instruction_cache, &params )))
        poison_provider( "instruction-cache synchronization", status );
}

static BOOL observer_owns_structural_memory(void)
{
    return !!InterlockedCompareExchange( &memory_observer_active, 0, 0 );
}

static NTSTATUS validate_structural_memory_range( const void *address, SIZE_T size,
                                                   BOOL allow_zero_size )
{
    UINT64 guest;
    ULONG guest_address;

    if (!address || ((ULONG_PTR)address & (XTAJIT_GUEST_PAGE_SIZE - 1)))
        return STATUS_INVALID_ADDRESS;
    if (!size)
        return allow_zero_size &&
               host_to_guest_address( (ULONG_PTR)address, FALSE, &guest_address ) ?
               STATUS_SUCCESS : STATUS_INVALID_ADDRESS;
    if (size & (XTAJIT_GUEST_PAGE_SIZE - 1) ||
        !host_to_guest_range( (ULONG_PTR)address, size, &guest ))
        return STATUS_INVALID_ADDRESS;
    return STATUS_SUCCESS;
}

static DECLSPEC_NORETURN void fail_simulation( const struct xtajit_begin_params *params,
                                               NTSTATUS status )
{
    status = status ? status : STATUS_NOT_SUPPORTED;
    if (!InterlockedCompareExchange( &fatal_termination_started, 1, 0 ))
    {
        ERR( "i386 simulation stopped status %#lx reason %u unicorn error %u slices %llu fault %#llx "
             "type %u eip %08x esp %08x eax %08x ecx %08x edx %08x ebx %08x "
             "esi %08x edi %08x ebp %08x recent(%u) %08x %08x %08x %08x "
             "%08x %08x %08x %08x\n", status, params->stop_reason,
             params->unicorn_error, (unsigned long long)params->execution_slice_count,
             (unsigned long long)params->fault_address,
             params->fault_type, params->context.eip, params->context.esp,
             params->context.eax, params->context.ecx, params->context.edx,
             params->context.ebx, params->context.esi, params->context.edi,
             params->context.ebp, params->recent_eip_count,
             params->recent_eip[0], params->recent_eip[1],
             params->recent_eip[2], params->recent_eip[3],
             params->recent_eip[4], params->recent_eip[5],
             params->recent_eip[6], params->recent_eip[7] );
        poison_provider( "fatal simulation stop", status );
    }
    NtTerminateProcess( GetCurrentProcess(), status );
    for (;;) RtlRaiseStatus( status );
}

static void clear_reset_state( WOW64_CPURESERVED *cpu )
{
    cpu->Flags &= ~WOW64_CPURESERVED_FLAG_RESET_STATE;
}

static NTSTATUS resolve_translated_memory_fault( const struct xtajit_begin_params *begin,
                                                  const I386_CONTEXT *context )
{
    struct xtajit_fault_params params =
    {
        .guest = begin->fault_address,
        .unicorn_type = begin->fault_type,
        .result.version = WINE_WOW64_MEMORY_FAULT_VERSION,
        .result.size = sizeof(params.result),
    };
    EXCEPTION_RECORD record = {0};
    ULONG guest_fault;
    NTSTATUS status;
    unsigned int i;

    if (begin->stop_reason != XTAJIT_STOP_UNMAPPED_MEMORY &&
        begin->stop_reason != XTAJIT_STOP_MEMORY_FAULT)
        return STATUS_INVALID_PARAMETER;
    if ((status = XTAJIT_CALL( resolve_memory_fault, &params ))) return status;
    if (params.result.version != WINE_WOW64_MEMORY_FAULT_VERSION ||
        params.result.size < sizeof(params.result) || params.result.reserved ||
        params.result.parameter_count > ARRAY_SIZE(params.result.information))
        return STATUS_INVALID_PARAMETER;
    if (params.result.action == WINE_WOW64_MEMORY_FAULT_RETRY)
        return params.result.status || params.result.parameter_count ?
               STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
    if (params.result.action != WINE_WOW64_MEMORY_FAULT_RAISE ||
        params.result.status >= 0)
        return STATUS_INVALID_PARAMETER;

    record.ExceptionCode = params.result.status;
    record.ExceptionAddress = ULongToPtr( context->Eip );
    record.NumberParameters = params.result.parameter_count;
    for (i = 0; i < record.NumberParameters; ++i)
        record.ExceptionInformation[i] = params.result.information[i];
    if (record.NumberParameters >= 2)
    {
        if (!host_to_guest_address( params.result.information[1], FALSE,
                                    &guest_fault ) ||
            guest_fault != begin->fault_address)
            return STATUS_INVALID_ADDRESS;
        record.ExceptionInformation[1] = guest_fault;
    }
    return Wow64RaiseException( -1, &record );
}

static NTSTATUS dispatch_syscall( WOW64_CPURESERVED *cpu, I386_CONTEXT *context,
                                  struct xtajit_thread_state *thread_state )
{
    ULONG return_address;
    ULONG syscall = context->Eax, old_esp = context->Esp;
    UINT64 generation;
    NTSTATUS status;

    if ((status = read_guest_memory( old_esp, &return_address, sizeof(return_address) ))) return status;
    if (old_esp > ~(ULONG)0 - 8) return STATUS_ACCESS_VIOLATION;
    context->Eip = return_address;
    context->Esp = old_esp + 4;
    generation = xtajit_context_generation_snapshot( &thread_state->context_generation );
    status = Wow64SystemServiceEx( syscall,
                                   guest_to_host_address( old_esp + 8 ) );
    if (!xtajit_context_requires_reload( &thread_state->context_generation, generation,
                                         cpu->Flags & WOW64_CPURESERVED_FLAG_RESET_STATE ))
        context->Eax = status;
    else
        TRACE( "syscall %08lx installed a replacement CPU context; preserving Eax %08lx "
               "Eip %08lx Esp %08lx\n", syscall, context->Eax, context->Eip,
               context->Esp );
    clear_reset_state( cpu );
    return STATUS_SUCCESS;
}

static NTSTATUS dispatch_unix_call( WOW64_CPURESERVED *cpu, I386_CONTEXT *context,
                                    struct xtajit_thread_state *thread_state )
{
    ULONG stack[XTAJIT_I386_UNIX_CALL_FRAME_DWORDS];
    UINT64 handle;
    ULONG old_esp = context->Esp;
    UINT64 generation;
    NTSTATUS status;

    C_ASSERT( sizeof(stack) == XTAJIT_I386_UNIX_CALL_FRAME_SIZE );
    if (!native_unix_call_dispatcher) return STATUS_INVALID_HANDLE;
    if ((status = read_guest_memory( old_esp, stack, sizeof(stack) ))) return status;
    handle = stack[1] | ((UINT64)stack[2] << 32);
    /* The i386 stack is guest-controlled.  Only ntdll-issued bounded handles
     * may cross into the native ARM64 dispatcher; a raw function-table pointer
     * is unsafe even when the guest happens to use the direct-map layout. */
    if (!xtajit_guest_unixlib_handle_is_allowed( handle ))
    {
        struct xtajit_i386_unix_call_completion completion =
            xtajit_i386_complete_rejected_unix_call( old_esp, stack[0],
                                                       STATUS_INVALID_PARAMETER );

        /* Match the native dispatcher's bad-handle return without letting the
         * guest-selected value reach its raw-table dereference path.  This is
         * a completed stdcall, not a provider failure.  No native code ran, so
         * this path cannot install a replacement CPU context. */
        context->Eip = completion.eip;
        context->Esp = completion.esp;
        context->Eax = completion.eax;
        clear_reset_state( cpu );
        return STATUS_SUCCESS;
    }

    context->Eip = stack[0];
    context->Esp = old_esp + sizeof(stack);
    generation = xtajit_context_generation_snapshot( &thread_state->context_generation );
    status = native_unix_call_dispatcher( handle, stack[3],
                                          guest_to_host_address( stack[4] ) );
    if (!xtajit_context_requires_reload( &thread_state->context_generation, generation,
                                         cpu->Flags & WOW64_CPURESERVED_FLAG_RESET_STATE ))
        context->Eax = status;
    else
        TRACE( "Unix call installed a replacement CPU context; preserving Eax %08lx "
               "Eip %08lx Esp %08lx\n", context->Eax, context->Eip, context->Esp );
    clear_reset_state( cpu );
    return STATUS_SUCCESS;
}

#endif /* HAVE_UNICORN */


/**********************************************************************
 *           BTCpuGetBopCode  (xtajit.@)
 */
void * WINAPI BTCpuGetBopCode(void)
{
    return ULongToPtr( XTAJIT_GUEST_SYSCALL_BOP );
}


/**********************************************************************
 *           __wine_get_unix_opcode  (xtajit.@)
 */
void * WINAPI __wine_get_unix_opcode(void)
{
    return ULongToPtr( XTAJIT_GUEST_UNIX_BOP );
}


/**********************************************************************
 *           BTCpuGetContext  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuGetContext( HANDLE thread, HANDLE process, void *unknown,
                                 I386_CONTEXT *context )
{
    (void)process;
    (void)unknown;
    return RtlWow64GetThreadContext( thread, context );
}


/**********************************************************************
 *           BTCpuSetContext  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuSetContext( HANDLE thread, HANDLE process, void *unknown,
                                 I386_CONTEXT *context )
{
#ifdef HAVE_UNICORN
    struct xtajit_thread_state *thread_state = NULL;
    WOW64_CPURESERVED *cpu;
    I386_CONTEXT *cpu_context;
    BOOL self = thread == GetCurrentThread();
    NTSTATUS status;
#endif

    (void)process;
    (void)unknown;
#ifdef HAVE_UNICORN
    if (self)
    {
        if ((status = get_current_cpu_area( &cpu, &cpu_context ))) return status;
        if (!(thread_state = find_thread_state( cpu ))) return STATUS_INVALID_HANDLE;
    }
    status = RtlWow64SetThreadContext( thread, context );
    if (!status && thread_state)
        xtajit_context_generation_advance( &thread_state->context_generation );
    return status;
#else
    return RtlWow64SetThreadContext( thread, context );
#endif
}


/**********************************************************************
 *           BTCpuIsProcessorFeaturePresent  (xtajit.@)
 */
BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent( UINT feature )
{
    static const ULONGLONG x86_features =
        (1ull << PF_COMPARE_EXCHANGE_DOUBLE) |
        (1ull << PF_MMX_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_XMMI_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_RDTSC_INSTRUCTION_AVAILABLE) |
        (1ull << PF_XMMI64_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_NX_ENABLED) |
        (1ull << PF_SSE3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_FASTFAIL_AVAILABLE) |
        (1ull << PF_RDTSCP_INSTRUCTION_AVAILABLE) |
        (1ull << PF_SSSE3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SSE4_1_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SSE4_2_INSTRUCTIONS_AVAILABLE);

    return feature < 64 && !!(x86_features & (1ull << feature));
}


/**********************************************************************
 *           BTCpuProcessInit  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuProcessInit(void)
{
#ifdef HAVE_UNICORN
    struct xtajit_process_init_params params =
    {
        .version = XTAJIT_PROCESS_ABI_VERSION,
        .size = sizeof(params),
        .required_capabilities = XTAJIT_PROCESS_REQUIRED_CAPABILITIES,
    };
    SYSTEM_BASIC_INFORMATION host_info, emulation_info;
    WOW64_CPURESERVED *cpu;
    I386_CONTEXT *context;
    WOW64INFO *wow64info;
    UNICODE_STRING ntdll_name = RTL_CONSTANT_STRING( L"ntdll.dll" );
    ULONG_PTR shared_data;
    HMODULE ntdll;
    void **dispatcher;
    NTSTATUS status;
    BOOL unix_initialized = FALSE;

    InterlockedExchange( &fatal_termination_started, 0 );
    InterlockedExchange( &memory_observer_active, 0 );
    if ((status = init_unixlib())) goto failed;
    if ((status = get_current_cpu_area( &cpu, &context ))) goto failed;
    if (!(wow64info = NtCurrentTeb()->TlsSlots[WOW64_TLS_WOW64INFO]) ||
        wow64info->EmulatedMachineType != IMAGE_FILE_MACHINE_I386 ||
        wow64info->NativeMachineType != IMAGE_FILE_MACHINE_ARM64)
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto failed;
    }
    if ((status = NtQuerySystemInformation( SystemBasicInformation,
                                             &host_info, sizeof(host_info), NULL )))
        goto failed;
    if ((status = NtQuerySystemInformation( SystemEmulationBasicInformation,
                                             &emulation_info, sizeof(emulation_info), NULL )))
        goto failed;
    if (host_info.PageSize < XTAJIT_GUEST_PAGE_SIZE ||
        host_info.PageSize > XTAJIT_MAX_HOST_PAGE_SIZE ||
        (host_info.PageSize & (host_info.PageSize - 1)) ||
        (ULONG_PTR)emulation_info.HighestUserAddress >= XTAJIT_GUEST_BOP_PAGE)
    {
        status = STATUS_INVALID_PARAMETER;
        goto failed;
    }

    shared_data = (ULONG_PTR)NtCurrentTeb()->Peb->SharedData;
    if (shared_data == WINE_LOW_VA_SHADOW_BASE + XTAJIT_GUEST_KUSER)
        low_va_shadow_base = WINE_LOW_VA_SHADOW_BASE;
    else if (shared_data == XTAJIT_GUEST_KUSER)
        low_va_shadow_base = 0;
    else
    {
        status = STATUS_INVALID_ADDRESS;
        goto failed;
    }
    if (!shared_data || (shared_data & (host_info.PageSize - 1)) ||
        (XTAJIT_GUEST_KUSER & (host_info.PageSize - 1)))
    {
        status = STATUS_INVALID_ADDRESS;
        goto failed;
    }

    if ((status = LdrGetDllHandle( NULL, 0, &ntdll_name, &ntdll ))) goto failed;
    dispatcher = RtlFindExportedRoutineByName( ntdll, "__wine_unix_call_dispatcher" );
    if (!dispatcher || !*dispatcher)
    {
        status = STATUS_ENTRYPOINT_NOT_FOUND;
        goto failed;
    }
    native_unix_call_dispatcher = *dispatcher;

    params.highest_user_address = (ULONG_PTR)emulation_info.HighestUserAddress;
    params.guest_kuser = XTAJIT_GUEST_KUSER;
    params.host_kuser = shared_data;
    /* KUSER is one logical i386 page even when its Darwin backing page is
     * larger.  Mapping the host page size would expose adjacent guest pages. */
    params.kuser_size = XTAJIT_GUEST_PAGE_SIZE;
    params.low_va_shadow_base = low_va_shadow_base;
    params.low_va_shadow_size = WINE_LOW_VA_SHADOW_SIZE;
    if ((status = XTAJIT_CALL( process_init, &params ))) goto failed;
    unix_initialized = TRUE;
    if (!xtajit_process_capabilities_satisfied( params.required_capabilities,
                                                params.enabled_capabilities ))
    {
        status = STATUS_REVISION_MISMATCH;
        goto failed;
    }
    emulated_highest_user_address = (ULONG_PTR)emulation_info.HighestUserAddress;
    /* Unix process initialization registers the process-lifetime native
     * observer and does not return until its gate-protected full RESYNC has
     * populated the canonical registry.  From this point the official BTCpu
     * structural callbacks remain ABI validators, not a second mutation feed. */
    InterlockedExchange( &memory_observer_active, 1 );

    wow64info->CpuFlags |= WOW64_CPUFLAGS_SOFTWARE;
    TRACE( "initialized i386 provider context %p KUSER guest %p host %p shadow %p\n",
           context, (void *)(ULONG_PTR)XTAJIT_GUEST_KUSER,
           (void *)shared_data, (void *)low_va_shadow_base );
    return STATUS_SUCCESS;

failed:
    /* Native observer registration is process-lifetime and has no unregister
     * operation.  Once Unix initialization succeeds, a later handshake error
     * cannot be rolled back safely; poison that provider before the mandatory
     * process-fatal initialization exception. */
    if (xtajit_process_init_failure_must_poison( unix_initialized ))
        poison_provider( "process capability handshake", status );
    native_unix_call_dispatcher = NULL;
    InterlockedExchange( &memory_observer_active, 0 );
    low_va_shadow_base = 0;
    emulated_highest_user_address = 0;
    ERR( "cannot initialize i386 provider, status %#lx\n", status );
    RtlRaiseStatus( status ? status : STATUS_NOT_SUPPORTED );
#else
    ERR( "i386 emulation requires Unicorn 2.1.4 or newer\n" );
    RtlRaiseStatus( STATUS_NOT_SUPPORTED );
#endif
}


/**********************************************************************
 *           BTCpuThreadInit  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuThreadInit(void)
{
#ifdef HAVE_UNICORN
    struct xtajit_thread_state *thread_state;
    WOW64_CPURESERVED *cpu;
    I386_CONTEXT *context;
    ULONG teb_guest;
    NTSTATUS status;

    if ((status = get_current_cpu_area( &cpu, &context ))) RtlRaiseStatus( status );
    if (!host_to_guest_address( (ULONG_PTR)((char *)NtCurrentTeb() + NtCurrentTeb()->WowTebOffset),
                                 FALSE, &teb_guest ))
        RtlRaiseStatus( STATUS_INVALID_ADDRESS );
    if ((status = XTAJIT_CALL( thread_init, NULL ))) RtlRaiseStatus( status );
    if ((status = register_thread_state( cpu, &thread_state )))
    {
        XTAJIT_CALL( thread_term, NULL );
        RtlRaiseStatus( status );
    }
    TRACE( "initialized i386 thread TEB guest %08lx state %p CPU %p\n",
           teb_guest, thread_state, cpu );
#endif
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           BTCpuSimulate  (xtajit.@)
 */
void WINAPI BTCpuSimulate(void)
{
#ifdef HAVE_UNICORN
    struct xtajit_begin_params params;
    struct xtajit_thread_state *thread_state;
    WOW64_CPURESERVED *cpu;
    I386_CONTEXT *context;
    NTSTATUS status;
    ULONG teb_guest;

    if ((status = get_current_cpu_area( &cpu, &context )))
    {
        memset( &params, 0, sizeof(params) );
        fail_simulation( &params, status );
    }
    if (!(thread_state = find_thread_state( cpu )))
    {
        memset( &params, 0, sizeof(params) );
        fail_simulation( &params, STATUS_INVALID_HANDLE );
    }
    if (!host_to_guest_address( (ULONG_PTR)((char *)NtCurrentTeb() + NtCurrentTeb()->WowTebOffset),
                                 FALSE, &teb_guest ))
    {
        memset( &params, 0, sizeof(params) );
        fail_simulation( &params, STATUS_INVALID_ADDRESS );
    }

    for (;;)
    {
        memset( &params, 0, sizeof(params) );
        context_to_unix( &params.context, context );
        params.teb_guest = teb_guest;
        status = XTAJIT_CALL( begin_simulation, &params );
        context_from_unix( context, &params.context );
        if ((params.stop_reason == XTAJIT_STOP_UNMAPPED_MEMORY ||
             params.stop_reason == XTAJIT_STOP_MEMORY_FAULT) &&
            InterlockedCompareExchange( &memory_observer_active, 0, 0 ))
        {
            status = resolve_translated_memory_fault( &params, context );
            if (!status) continue;
        }
        if (params.stop_reason == XTAJIT_STOP_UNMAPPED_MEMORY &&
            !InterlockedCompareExchange( &memory_observer_active, 0, 0 ))
        {
            status = recover_translated_fault_page( &params );
            if (!status) continue;
        }
        if (status) fail_simulation( &params, status );

        switch (params.stop_reason)
        {
        case XTAJIT_STOP_SYSCALL:
            status = dispatch_syscall( cpu, context, thread_state );
            break;
        case XTAJIT_STOP_UNIX_CALL:
            status = dispatch_unix_call( cpu, context, thread_state );
            break;
        default:
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        if (status) fail_simulation( &params, status );
    }
#else
    RtlRaiseStatus( STATUS_NOT_SUPPORTED );
#endif
}


/**********************************************************************
 *           BTCpuResetToConsistentState  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuResetToConsistentState( EXCEPTION_POINTERS *ptrs )
{
#ifdef HAVE_UNICORN
    WOW64_CPURESERVED *cpu;
    I386_CONTEXT *context;
#endif

    if (!ptrs || !ptrs->ExceptionRecord || !ptrs->ContextRecord)
        return STATUS_INVALID_PARAMETER;
#ifdef HAVE_UNICORN
    if (get_current_cpu_area( &cpu, &context )) return STATUS_NOT_SUPPORTED;
    clear_reset_state( cpu );
#endif
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           BTCpuFlushInstructionCache2  (xtajit.@)
 */
void WINAPI BTCpuFlushInstructionCache2( const void *address, SIZE_T size )
{
    (void)address;
    (void)size;
#ifdef HAVE_UNICORN
    flush_unicorn_cache( address, size );
#endif
}


/**********************************************************************
 *           BTCpuFlushInstructionCacheHeavy  (xtajit.@)
 */
void WINAPI BTCpuFlushInstructionCacheHeavy( const void *address, SIZE_T size )
{
    (void)address;
    (void)size;
#ifdef HAVE_UNICORN
    flush_unicorn_cache( address, size );
#endif
}


/**********************************************************************
 *           BTCpuNotifyMapViewOfSection  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuNotifyMapViewOfSection( void *unknown1, void *address, void *unknown2,
                                             SIZE_T size, ULONG alloc_type, ULONG protect )
{
#ifdef HAVE_UNICORN
    NTSTATUS status;
#endif

    (void)unknown1;
    (void)address;
    (void)unknown2;
    (void)size;
    (void)alloc_type;
    (void)protect;
#ifdef HAVE_UNICORN
    if (observer_owns_structural_memory())
        status = validate_structural_memory_range( address, size, FALSE );
    else status = sync_translated_mapping_range( (ULONG_PTR)address, size );
    return status;
#else
    return STATUS_SUCCESS;
#endif
}


/**********************************************************************
 *           BTCpuNotifyMemoryAlloc  (xtajit.@)
 */
void WINAPI BTCpuNotifyMemoryAlloc( void *address, SIZE_T size, ULONG type, ULONG protect,
                                    BOOL is_post, NTSTATUS status )
{
#ifdef HAVE_UNICORN
    if (is_post && !status && (type & (MEM_RESERVE | MEM_COMMIT)))
    {
        struct xtajit_memory_params params =
        {
            .host = (ULONG_PTR)address,
            .size = size,
            .protect = (type & MEM_COMMIT) ? protect : PAGE_NOACCESS,
        };

        if (observer_owns_structural_memory())
        {
            if ((status = validate_structural_memory_range( address, size, FALSE )))
                poison_provider( "allocation callback validation", status );
        }
        else if (!host_to_guest_range( (ULONG_PTR)address, size, &params.guest ))
            poison_provider( "allocation address normalization", STATUS_INVALID_ADDRESS );
        else if ((status = get_allocation_base( address, &params.allocation_base )))
            poison_provider( "allocation-base query", status );
        else if ((status = XTAJIT_CALL( memory_map, &params )))
            poison_provider( "allocation synchronization", status );
    }
#endif
    (void)address;
    (void)size;
    (void)type;
    (void)protect;
    (void)is_post;
    (void)status;
}


/**********************************************************************
 *           BTCpuNotifyMemoryDirty  (xtajit.@)
 */
void WINAPI BTCpuNotifyMemoryDirty( void *address, SIZE_T size )
{
    (void)address;
    (void)size;
#ifdef HAVE_UNICORN
    flush_unicorn_cache( address, size );
#endif
}


/**********************************************************************
 *           BTCpuNotifyMemoryFree  (xtajit.@)
 */
void WINAPI BTCpuNotifyMemoryFree( void *address, SIZE_T size, ULONG type,
                                   BOOL is_post, NTSTATUS status )
{
#ifdef HAVE_UNICORN
    if (is_post && !status)
    {
        struct xtajit_memory_params params = { .size = size, .protect = type };
        NTSTATUS sync_status;
        ULONG guest;

        if (observer_owns_structural_memory())
        {
            if ((sync_status = validate_structural_memory_range( address, size, TRUE )))
                poison_provider( "allocation-free callback validation", sync_status );
        }
        else if ((size && !host_to_guest_range( (ULONG_PTR)address, size, &params.guest )) ||
            (!size && (!host_to_guest_address( (ULONG_PTR)address, FALSE, &guest ) ||
                       !(params.guest = guest))))
            poison_provider( "allocation-free address normalization", STATUS_INVALID_ADDRESS );
        else if ((sync_status = XTAJIT_CALL( memory_unmap, &params )))
            poison_provider( "allocation-free synchronization", sync_status );
    }
#endif
    (void)address;
    (void)size;
    (void)type;
    (void)is_post;
    (void)status;
}


/**********************************************************************
 *           BTCpuNotifyMemoryProtect  (xtajit.@)
 */
void WINAPI BTCpuNotifyMemoryProtect( void *address, SIZE_T size, ULONG protect,
                                      BOOL is_post, NTSTATUS status )
{
#ifdef HAVE_UNICORN
    if (is_post && !status)
    {
        struct xtajit_memory_params params = { .size = size, .protect = protect };
        NTSTATUS sync_status;

        if (observer_owns_structural_memory())
        {
            if ((sync_status = validate_structural_memory_range( address, size, FALSE )))
                poison_provider( "memory-protection callback validation", sync_status );
        }
        else if (!host_to_guest_range( (ULONG_PTR)address, size, &params.guest ))
            poison_provider( "memory-protection address normalization", STATUS_INVALID_ADDRESS );
        else if ((sync_status = XTAJIT_CALL( memory_protect, &params )))
            poison_provider( "memory-protection synchronization", sync_status );
    }
#endif
    (void)address;
    (void)size;
    (void)protect;
    (void)is_post;
    (void)status;
}


/**********************************************************************
 *           BTCpuNotifyProcessExecuteFlagsChange  (xtajit.@)
 */
void WINAPI BTCpuNotifyProcessExecuteFlagsChange( ULONG flags )
{
    TRACE( "execute flags %#lx\n", flags );
}


/**********************************************************************
 *           BTCpuNotifyReadFile  (xtajit.@)
 */
void WINAPI BTCpuNotifyReadFile( HANDLE handle, void *address, SIZE_T size,
                                 BOOL is_post, NTSTATUS status )
{
    (void)handle;
    (void)address;
    (void)size;
    (void)is_post;
    (void)status;
#ifdef HAVE_UNICORN
    if (is_post && !status) flush_unicorn_cache( address, size );
#endif
}


/**********************************************************************
 *           BTCpuNotifyUnmapViewOfSection  (xtajit.@)
 */
void WINAPI BTCpuNotifyUnmapViewOfSection( void *address, BOOL is_post, NTSTATUS status )
{
#ifdef HAVE_UNICORN
    if (is_post && !status)
    {
        struct xtajit_memory_params params = {0};
        NTSTATUS sync_status;
        ULONG guest;

        if (observer_owns_structural_memory())
        {
            if ((sync_status = validate_structural_memory_range( address, 0, TRUE )))
                poison_provider( "mapped-view unmap callback validation", sync_status );
        }
        else if (!host_to_guest_address( (ULONG_PTR)address, FALSE, &guest ))
            poison_provider( "mapped-view unmap address normalization", STATUS_INVALID_ADDRESS );
        else
        {
            params.guest = guest;
            if ((sync_status = XTAJIT_CALL( memory_unmap, &params )))
                poison_provider( "mapped-view unmap synchronization", sync_status );
        }
    }
#endif
    (void)address;
    (void)is_post;
    (void)status;
}


/**********************************************************************
 *           BTCpuUpdateProcessorInformation  (xtajit.@)
 */
void WINAPI BTCpuUpdateProcessorInformation( SYSTEM_CPU_INFORMATION *info )
{
    info->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
    info->ProcessorLevel = 6;
    info->ProcessorRevision = 0x3a09;
}


/**********************************************************************
 *           BTCpuProcessTerm  (xtajit.@)
 */
void WINAPI BTCpuProcessTerm( HANDLE handle, BOOL is_post, NTSTATUS status )
{
    /* Wine sends these callbacks around the soft NtTerminateProcess(NULL)
     * phase.  That call must return into guest RtlExitUserProcess so it can run
     * LdrShutdownProcess; closing Unicorn here makes the next guest instruction
     * fail with STATUS_INVALID_HANDLE.  There is no provider quiesce callback
     * for the later terminal pseudo-handle call, so OS process reclamation owns
     * teardown.  FreeLibrary is unsupported without a future outside-loader-
     * lock quiesce entrypoint. */
    (void)xtajit_process_term_notification_may_cleanup( (uintptr_t)handle,
                                                         is_post, status );
    TRACE( "soft process termination notification handle %p post %u status %#lx\n",
           handle, is_post, status );
}


/**********************************************************************
 *           BTCpuThreadTerm  (xtajit.@)
 */
void WINAPI BTCpuThreadTerm( HANDLE handle, LONG exit_code )
{
#ifdef HAVE_UNICORN
    WOW64_CPURESERVED *cpu;
    I386_CONTEXT *context;
#endif

    (void)handle;
    (void)exit_code;
#ifdef HAVE_UNICORN
    if (!get_current_cpu_area( &cpu, &context )) unregister_thread_state( cpu );
    if (__wine_unixlib_handle) XTAJIT_CALL( thread_term, NULL );
#endif
}


/**********************************************************************
 *           BTCpuTurboThunkControl  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuTurboThunkControl( ULONG enable )
{
    return enable ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}


/**********************************************************************
 *           DllMain
 */
BOOL WINAPI DllMain( HINSTANCE instance, DWORD reason, void *reserved )
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) LdrDisableThreadCalloutsForDll( instance );
    return TRUE;
}
