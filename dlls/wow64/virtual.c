/*
 * WoW64 virtual memory functions
 *
 * Copyright 2021 Alexandre Julliard
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

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "winioctl.h"
#include "wow64_private.h"
#include "wine/debug.h"
#include "wine/exception.h"

WINE_DEFAULT_DEBUG_CHANNEL(wow);

static void *alloc_temp( SIZE_T size )
{
    void *ret;

    if (!size) size = 1;
    if (!(ret = Wow64AllocateTemp( size ))) RtlRaiseStatus( STATUS_NO_MEMORY );
    return ret;
}

static NTSTATUS publish_local_handle( ULONG *handle_ptr, HANDLE handle, NTSTATUS status )
{
    NTSTATUS publish_status;

    if (!handle) return status;
    if (!(publish_status = try_put_handle( handle_ptr, handle ))) return status;
    NtClose( handle );
    return publish_status;
}

NTSTATUS init_process_address_codec( HANDLE process, struct process_address_codec *codec )
{
    WINE_PROCESS_VM_INFORMATION info;
    NTSTATUS status;

    codec->process = NtCurrentProcess();
    codec->close_process = FALSE;
    codec->is_current = process == NtCurrentProcess();
    codec->translated = FALSE;
    if (codec->is_current)
    {
        codec->translated = wow64_uses_low_va_shadow();
        return STATUS_SUCCESS;
    }

    /* Pin the handle identity across the machine query and target operation. */
    status = NtDuplicateObject( NtCurrentProcess(), process, NtCurrentProcess(), &codec->process,
                                0, 0, DUPLICATE_SAME_ACCESS );
    if (status) return status;
    codec->close_process = TRUE;
    if (RtlIsCurrentProcess( codec->process ))
    {
        codec->is_current = TRUE;
        codec->translated = wow64_uses_low_va_shadow();
        return STATUS_SUCCESS;
    }

    memset( &info, 0, sizeof(info) );
    status = NtQueryVirtualMemory( codec->process, NULL,
                                   MemoryWineProcessVmMachineInformation,
                                   &info, sizeof(info), NULL );
    if (status)
    {
        NtClose( codec->process );
        codec->process = NtCurrentProcess();
        codec->close_process = FALSE;
        return status;
    }

    if (info.Version != WINE_PROCESS_VM_INFORMATION_VERSION ||
        info.Size != sizeof(info) || info.Reserved ||
        (info.Flags & ~WINE_PROCESS_VM_FLAG_WOW64_TRANSLATED) ||
        ((info.Flags & WINE_PROCESS_VM_FLAG_WOW64_TRANSLATED) &&
         info.Machine != IMAGE_FILE_MACHINE_I386))
    {
        NtClose( codec->process );
        codec->process = NtCurrentProcess();
        codec->close_process = FALSE;
        return STATUS_INVALID_PARAMETER;
    }

    /* The server records this address-space property from the target's
     * validated main-image view.  Do not infer it from the caller ABI or PE
     * machine: native and identity-mapped i386 processes may coexist. */
    codec->translated = !!(info.Flags & WINE_PROCESS_VM_FLAG_WOW64_TRANSLATED);
    return STATUS_SUCCESS;
}

void CALLBACK close_process_address_codec( BOOL normal, void *arg )
{
    struct process_address_codec *codec = arg;
    HANDLE process;

    if (!codec->close_process) return;
    process = codec->process;
    codec->process = NtCurrentProcess();
    codec->close_process = FALSE;
    NtClose( process );
}

struct map_view_cleanup
{
    struct process_address_codec *codec;
    void *arbitrary_user_pointer;
    BOOL restore_arbitrary_user_pointer;
};

static void CALLBACK cleanup_map_view( BOOL normal, void *arg )
{
    struct map_view_cleanup *cleanup = arg;

    if (cleanup->restore_arbitrary_user_pointer)
        NtCurrentTeb()->Tib.ArbitraryUserPointer = cleanup->arbitrary_user_pointer;
    close_process_address_codec( normal, cleanup->codec );
}

void *decode_process_address( const struct process_address_codec *codec, ULONG address )
{
    if (!address) return NULL;
    if (codec->translated)
        return (void *)(ULONG_PTR)(WINE_LOW_VA_SHADOW_BASE + address);
    return ULongToPtr( address );
}

NTSTATUS encode_process_address( const struct process_address_codec *codec,
                                 const void *address, ULONG *ret )
{
    ULONG_PTR value = (ULONG_PTR)address;

    if (!address)
    {
        *ret = 0;
        return STATUS_SUCCESS;
    }
    if (codec->translated)
    {
        if (value < WINE_LOW_VA_SHADOW_BASE ||
            value - WINE_LOW_VA_SHADOW_BASE >= WINE_LOW_VA_SHADOW_SIZE)
            return STATUS_INVALID_ADDRESS;
        value -= WINE_LOW_VA_SHADOW_BASE;
    }
    if (value > ~(ULONG)0) return STATUS_INVALID_ADDRESS;
    *ret = value;
    return STATUS_SUCCESS;
}

static BOOL WINAPIV send_cross_process_notification( HANDLE process, UINT id, const void *addr, SIZE_T size,
                                                     int nb_args, ... )
{
    CROSS_PROCESS_WORK_LIST *list;
    CROSS_PROCESS_WORK_ENTRY *entry;
    void *unused;
    HANDLE section;
    va_list args;
    int i;

    RtlOpenCrossProcessEmulatorWorkConnection( process, &section, (void **)&list );
    if (!list) return FALSE;
    if ((entry = RtlWow64PopCrossProcessWorkFromFreeList( &list->free_list )))
    {
        entry->id = id;
        entry->addr = (ULONG_PTR)addr;
        entry->size = size;
        if (nb_args)
        {
            va_start( args, nb_args );
            for (i = 0; i < nb_args; i++) entry->args[i] = va_arg( args, int );
            va_end( args );
        }
        RtlWow64PushCrossProcessWorkOntoWorkList( &list->work_list, entry, &unused );
    }
    NtUnmapViewOfSection( GetCurrentProcess(), list );
    NtClose( section );
    return TRUE;
}


static NTSTATUS memory_range_entry_array_32to64(
    MEMORY_RANGE_ENTRY **ret, const struct process_address_codec *codec,
    const MEMORY_RANGE_ENTRY32 *addresses32, ULONG count )
{
    MEMORY_RANGE_ENTRY *addresses;
    SIZE_T snapshot_size, addresses_size;
    ULONG i;

    if (count > MAXDWORD / sizeof(*addresses32) ||
        count > MAXDWORD / sizeof(*addresses) ||
        (SIZE_T)count > ~(SIZE_T)0 / sizeof(*addresses))
        return STATUS_INTEGER_OVERFLOW;
    snapshot_size = (SIZE_T)count * sizeof(*addresses32);
    addresses_size = (SIZE_T)count * sizeof(*addresses);
    wow64_probe_user_read( addresses32, snapshot_size );
    addresses = alloc_temp( addresses_size );
    wow64_read_user( addresses, addresses32, snapshot_size );

    /* Expand backwards so the native array doubles as the guest snapshot.
     * This avoids a second attacker-sized allocation without overwriting an
     * entry that has not been converted yet. */
    for (i = count; i--;)
    {
        MEMORY_RANGE_ENTRY32 entry32;

        memcpy( &entry32, (char *)addresses + i * sizeof(entry32), sizeof(entry32) );
        addresses[i].VirtualAddress = codec ?
            decode_process_address( codec, entry32.VirtualAddress ) :
            ULongToPtr( entry32.VirtualAddress );
        addresses[i].NumberOfBytes = entry32.NumberOfBytes;
    }

    *ret = addresses;
    return STATUS_SUCCESS;
}

static ULONG_PTR get_guest_zero_bits_limit( ULONG_PTR zero_bits )
{
    unsigned int shift;

    if (!zero_bits) return 0;
    if (zero_bits < 32) shift = 32 + zero_bits;
    else
    {
        shift = 63;
        if (zero_bits >> 32) { shift -= 32; zero_bits >>= 32; }
        if (zero_bits >> 16) { shift -= 16; zero_bits >>= 16; }
        if (zero_bits >> 8) { shift -= 8; zero_bits >>= 8; }
        if (zero_bits >> 4) { shift -= 4; zero_bits >>= 4; }
        if (zero_bits >> 2) { shift -= 2; zero_bits >>= 2; }
        if (zero_bits >> 1) shift--;
    }
    return (~(UINT64)0) >> shift;
}

static NTSTATUS mem_extended_parameters_32to64( MEM_EXTENDED_PARAMETER **ret_params,
                                                const MEM_EXTENDED_PARAMETER32 *params32, ULONG *count,
                                                ULONG_PTR implicit_high )
{
    ULONG i, present = 0;
    SIZE_T alloc_size, snapshot_size;
    MEM_EXTENDED_PARAMETER32 *snapshot = NULL;
    MEM_EXTENDED_PARAMETER *params;
    MEM_ADDRESS_REQUIREMENTS *req;
    MEM_ADDRESS_REQUIREMENTS32 req32;
    BOOL have_req = FALSE;

    if (*count && !params32) return STATUS_INVALID_PARAMETER;
    if (*count > 32 || (SIZE_T)*count + 2 >
        (~(SIZE_T)0 - sizeof(*req)) / sizeof(*params))
        return STATUS_INVALID_PARAMETER;

    alloc_size = ((SIZE_T)*count + 2) * sizeof(*params) + sizeof(*req);
    params = alloc_temp( alloc_size );
    req = (MEM_ADDRESS_REQUIREMENTS *)(params + *count + 2);
    if (*count)
    {
        snapshot_size = (SIZE_T)*count * sizeof(*snapshot);
        snapshot = alloc_temp( snapshot_size );
        wow64_read_user( snapshot, params32, snapshot_size );
    }

    for (i = 0; i < *count; i++)
    {
        params[i].Type = snapshot[i].Type;
        params[i].Reserved = 0;
        params[i].ULong64 = snapshot[i].ULong64;
        if (params[i].Type >= 32 ||
            params[i].Type == WINE_MEM_EXTENDED_PARAMETER_WOW64_TRANSLATED ||
            (present & (1u << params[i].Type)))
            return STATUS_INVALID_PARAMETER;
        present |= 1u << params[i].Type;
        switch (params[i].Type)
        {
        case MemExtendedParameterAddressRequirements:
            have_req = TRUE;
            wow64_read_user( &req32, wow64_guest_memory_ptr( snapshot[i].Pointer ),
                             sizeof(req32) );
            if (req32.HighestEndingAddress > highest_user_address)
                return STATUS_INVALID_PARAMETER;
            req->LowestStartingAddress = ULongToPtr( req32.LowestStartingAddress );
            req->HighestEndingAddress = ULongToPtr( req32.HighestEndingAddress );
            req->Alignment = req32.Alignment;
            params[i].Pointer = req;
            break;
        case MemExtendedParameterAttributeFlags:
        case MemExtendedParameterNumaNode:
        case MemExtendedParameterImageMachine:
            params[i].ULong = snapshot[i].ULong;
            break;
        case MemExtendedParameterPartitionHandle:
        case MemExtendedParameterUserPhysicalHandle:
            params[i].Handle = ULongToHandle( snapshot[i].Handle );
            break;
        }
    }

    if (!have_req && implicit_high)
    {
        req->LowestStartingAddress = NULL;
        req->HighestEndingAddress  = (void *)implicit_high;
        req->Alignment             = 0;

        params[i].Type = MemExtendedParameterAddressRequirements;
        params[i].Reserved = 0;
        params[i].Pointer = req;
        *count = i + 1;
    }
    *ret_params = params;
    return STATUS_SUCCESS;
}

static void finalize_mem_extended_parameters( MEM_EXTENDED_PARAMETER *params, ULONG *count,
                                               const struct process_address_codec *codec,
                                               ULONG translated_commit_size )
{
    ULONG i;

    if (!codec->translated) return;
    for (i = 0; i < *count; i++)
    {
        MEM_ADDRESS_REQUIREMENTS *req;
        ULONG_PTR high;
        ULONG low;

        if (params[i].Type != MemExtendedParameterAddressRequirements) continue;
        req = params[i].Pointer;
        low = max( PtrToUlong( req->LowestStartingAddress ), 0x10000u );
        high = PtrToUlong( req->HighestEndingAddress );
        if (!high) high = highest_user_address;
        req->LowestStartingAddress = decode_process_address( codec, low );
        req->HighestEndingAddress = decode_process_address( codec, high );
    }

    params[*count].Type = WINE_MEM_EXTENDED_PARAMETER_WOW64_TRANSLATED;
    params[*count].Reserved = 0;
    params[*count].ULong64 = translated_commit_size;
    (*count)++;
}

/**********************************************************************
 *           wow64_NtAllocateVirtualMemory
 */
NTSTATUS WINAPI wow64_NtAllocateVirtualMemory( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG *addr32 = get_ptr( &args );
    ULONG_PTR zero_bits = get_ulong( &args );
    ULONG *size32 = get_ptr( &args );
    ULONG type = get_ulong( &args );
    ULONG protect = get_ulong( &args );

    struct process_address_codec codec = {0};
    void *addr, *requested_addr;
    SIZE_T size;
    NTSTATUS status;
    MEM_EXTENDED_PARAMETER *params64;
    ULONG count = 0;
    ULONG guest_addr, guest_size;
    ULONG result_addr = 0;
    ULONG_PTR limit = 0;

    wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
    wow64_read_user( &guest_size, size32, sizeof(guest_size) );
    size = guest_size;
    wow64_probe_user_write( addr32, sizeof(guest_addr) );
    wow64_probe_user_write( size32, sizeof(guest_size) );

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            addr = decode_process_address( &codec, guest_addr );
            requested_addr = addr;
            if (!addr && (type & MEM_COMMIT)) type |= MEM_RESERVE;

            if (!codec.is_current)
                send_cross_process_notification( codec.process, CrossProcessPreVirtualAlloc,
                                                 addr, size, 3, type, protect, 0 );
            else if (pBTCpuNotifyMemoryAlloc)
                pBTCpuNotifyMemoryAlloc( addr, size, type, protect, FALSE, 0 );

            if (codec.translated)
            {
                if (!addr)
                {
                    limit = get_guest_zero_bits_limit( get_zero_bits( zero_bits ) );
                    if (!limit || limit > highest_user_address) limit = highest_user_address;
                }
                status = mem_extended_parameters_32to64( &params64, NULL, &count, limit );
                if (!status)
                {
                    finalize_mem_extended_parameters( params64, &count, &codec, 0 );
                    status = NtAllocateVirtualMemoryEx( codec.process, &addr, &size, type, protect,
                                                        params64, count );
                }
            }
            else
                status = NtAllocateVirtualMemory( codec.process, &addr, get_zero_bits( zero_bits ),
                                                  &size, type, protect );

            if (!status && (status = encode_process_address( &codec, addr, &result_addr )) &&
                !requested_addr)
            {
                SIZE_T free_size = 0;
                void *free_addr = addr;

                NtFreeVirtualMemory( codec.process, &free_addr, &free_size, MEM_RELEASE );
            }

            if (!codec.is_current)
                send_cross_process_notification( codec.process, CrossProcessPostVirtualAlloc,
                                                 addr, size, 3, type, protect, status );
            else if (pBTCpuNotifyMemoryAlloc)
                pBTCpuNotifyMemoryAlloc( addr, size, type, protect, TRUE, status );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )

    if (!status)
    {
        wow64_write_user( addr32, &result_addr, sizeof(result_addr) );
        put_size( size32, size );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtAllocateVirtualMemoryEx
 */
NTSTATUS WINAPI wow64_NtAllocateVirtualMemoryEx( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG *addr32 = get_ptr( &args );
    ULONG *size32 = get_ptr( &args );
    ULONG type = get_ulong( &args );
    ULONG protect = get_ulong( &args );
    MEM_EXTENDED_PARAMETER32 *params32 = get_ptr( &args );
    ULONG count = get_ulong( &args );

    struct process_address_codec codec = {0};
    void *addr, *requested_addr;
    SIZE_T size;
    NTSTATUS status;
    MEM_EXTENDED_PARAMETER *params64;
    ULONG guest_addr, guest_size;
    ULONG result_addr = 0;
    ULONG_PTR implicit_high;

    wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
    wow64_read_user( &guest_size, size32, sizeof(guest_size) );
    size = guest_size;
    implicit_high = !guest_addr ? highest_user_address : 0;

    if ((status = mem_extended_parameters_32to64( &params64, params32, &count, implicit_high )))
        return status;
    wow64_probe_user_write( addr32, sizeof(guest_addr) );
    wow64_probe_user_write( size32, sizeof(guest_size) );

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            addr = decode_process_address( &codec, guest_addr );
            requested_addr = addr;
            if (!addr) type |= MEM_RESERVE;
            finalize_mem_extended_parameters( params64, &count, &codec, 0 );

            if (!codec.is_current)
                send_cross_process_notification( codec.process, CrossProcessPreVirtualAlloc,
                                                 addr, size, 3, type, protect, 0 );
            else if (pBTCpuNotifyMemoryAlloc)
                pBTCpuNotifyMemoryAlloc( addr, size, type, protect, FALSE, 0 );

            status = NtAllocateVirtualMemoryEx( codec.process, &addr, &size, type, protect,
                                                params64, count );
            if (!status && (status = encode_process_address( &codec, addr, &result_addr )) &&
                !requested_addr)
            {
                SIZE_T free_size = 0;
                void *free_addr = addr;

                NtFreeVirtualMemory( codec.process, &free_addr, &free_size, MEM_RELEASE );
            }

            if (!codec.is_current)
                send_cross_process_notification( codec.process, CrossProcessPostVirtualAlloc,
                                                 addr, size, 3, type, protect, status );
            else if (pBTCpuNotifyMemoryAlloc)
                pBTCpuNotifyMemoryAlloc( addr, size, type, protect, TRUE, status );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )

    if (!status)
    {
        wow64_write_user( addr32, &result_addr, sizeof(result_addr) );
        put_size( size32, size );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtAreMappedFilesTheSame
 */
NTSTATUS WINAPI wow64_NtAreMappedFilesTheSame( UINT *args )
{
    void *ptr1 = get_ptr( &args );
    void *ptr2 = get_ptr( &args );

    return NtAreMappedFilesTheSame( ptr1, ptr2 );
}


/**********************************************************************
 *           wow64_NtCreateSectionEx
 */
NTSTATUS WINAPI wow64_NtCreateSectionEx( UINT *args )
{
    ULONG *handle_ptr = get_ptr( &args );
    ACCESS_MASK access = get_ulong( &args );
    OBJECT_ATTRIBUTES32 *attr32 = get_ptr( &args );
    const LARGE_INTEGER *size = get_ptr( &args );
    ULONG protect = get_ulong( &args );
    ULONG flags = get_ulong( &args );
    HANDLE file = get_handle( &args );
    MEM_EXTENDED_PARAMETER32 *params32 = get_ptr( &args );
    ULONG count = get_ulong( &args );

    MEM_EXTENDED_PARAMETER *params64;
    struct object_attr64 attr;
    LARGE_INTEGER size_buf;
    const LARGE_INTEGER *native_size = NULL;
    HANDLE handle = 0;
    NTSTATUS status;

    if ((status = mem_extended_parameters_32to64( &params64, params32, &count, 0 )))
        return status;

    put_handle( handle_ptr, 0 );
    if (size)
    {
        wow64_read_user( &size_buf, size, sizeof(size_buf) );
        native_size = &size_buf;
    }
    status = NtCreateSectionEx( &handle, access, objattr_32to64( &attr, attr32 ),
                                native_size, protect, flags, file, params64, count );
    return publish_local_handle( handle_ptr, handle, status );
}


/**********************************************************************
 *           wow64_NtFlushInstructionCache
 */
NTSTATUS WINAPI wow64_NtFlushInstructionCache( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG addr32 = get_ulong( &args );
    SIZE_T size = get_ulong( &args );
    struct process_address_codec codec = {0};
    const void *addr;
    NTSTATUS status;

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            addr = decode_process_address( &codec, addr32 );
            if (codec.is_current)
            {
                if (pBTCpuFlushInstructionCache2) pBTCpuFlushInstructionCache2( addr, size );
            }
            else send_cross_process_notification( codec.process, CrossProcessFlushCache, addr, size, 0 );

            status = NtFlushInstructionCache( codec.process, addr, size );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )
    return status;
}


/**********************************************************************
 *           wow64_NtFlushVirtualMemory
 */
NTSTATUS WINAPI wow64_NtFlushVirtualMemory( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG *addr32 = get_ptr( &args );
    ULONG *size32 = get_ptr( &args );
    IO_STATUS_BLOCK32 *io32 = get_ptr( &args );
    IO_STATUS_BLOCK io;

    struct process_address_codec codec = {0};
    void *addr = NULL;
    SIZE_T size = 0;
    NTSTATUS status;
    ULONG guest_addr = 0, result_addr = 0;
    ULONG guest_size = 0;
    BOOL called = FALSE;

    memset( &io, 0, sizeof(io) );
    if (addr32)
    {
        wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
        wow64_probe_user_write( addr32, sizeof(guest_addr) );
    }
    if (size32)
    {
        wow64_read_user( &guest_size, size32, sizeof(guest_size) );
        wow64_probe_user_write( size32, sizeof(guest_size) );
        size = guest_size;
    }
    if (io32) wow64_probe_user_write( io32, sizeof(*io32) );
    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            if (addr32) addr = decode_process_address( &codec, guest_addr );
            called = TRUE;
            status = NtFlushVirtualMemory( codec.process, addr32 ? (const void **)&addr : NULL,
                                           size32 ? &size : NULL, iosb_32to64( &io, io32 ) );
            if (!status && addr32)
                status = encode_process_address( &codec, addr, &result_addr );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )
    if (!status)
    {
        if (addr32) wow64_write_user( addr32, &result_addr, sizeof(result_addr) );
        put_size( size32, size );
    }
    if (called) put_iosb( io32, &io );
    return status;
}


/**********************************************************************
 *           wow64_NtFreeVirtualMemory
 */
NTSTATUS WINAPI wow64_NtFreeVirtualMemory( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG *addr32 = get_ptr( &args );
    ULONG *size32 = get_ptr( &args );
    ULONG type = get_ulong( &args );

    struct process_address_codec codec = {0};
    void *addr;
    SIZE_T size;
    NTSTATUS status;
    ULONG guest_addr, guest_size, result_addr = 0;

    wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
    wow64_read_user( &guest_size, size32, sizeof(guest_size) );
    size = guest_size;
    wow64_probe_user_write( addr32, sizeof(guest_addr) );
    wow64_probe_user_write( size32, sizeof(guest_size) );

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            addr = decode_process_address( &codec, guest_addr );
            if (!codec.is_current)
                send_cross_process_notification( codec.process, CrossProcessPreVirtualFree,
                                                 addr, size, 2, type, 0 );
            else if (pBTCpuNotifyMemoryFree)
                pBTCpuNotifyMemoryFree( addr, size, type, FALSE, 0 );

            status = NtFreeVirtualMemory( codec.process, &addr, &size, type );

            if (!codec.is_current)
                send_cross_process_notification( codec.process, CrossProcessPostVirtualFree,
                                                 addr, size, 2, type, status );
            else if (pBTCpuNotifyMemoryFree)
                pBTCpuNotifyMemoryFree( addr, size, type, TRUE, status );
            if (!status) status = encode_process_address( &codec, addr, &result_addr );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )
    if (!status)
    {
        wow64_write_user( addr32, &result_addr, sizeof(result_addr) );
        put_size( size32, size );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtGetNlsSectionPtr
 */
NTSTATUS WINAPI wow64_NtGetNlsSectionPtr( UINT *args )
{
    ULONG type = get_ulong( &args );
    ULONG id = get_ulong( &args );
    void *unknown = get_raw_ptr( &args );
    ULONG *addr32 = get_ptr( &args );
    ULONG *size32 = get_ptr( &args );

    void *addr;
    SIZE_T size;
    NTSTATUS status;
    ULONG guest_addr, guest_size;

    wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
    wow64_read_user( &guest_size, size32, sizeof(guest_size) );
    addr = wow64_guest_memory_ptr( guest_addr );
    size = guest_size;
    wow64_probe_user_write( addr32, sizeof(guest_addr) );
    wow64_probe_user_write( size32, sizeof(guest_size) );
    status = NtGetNlsSectionPtr( type, id, unknown, &addr, &size );
    if (!status)
    {
        put_addr( addr32, addr );
        put_size( size32, size );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtGetWriteWatch
 */
NTSTATUS WINAPI wow64_NtGetWriteWatch( UINT *args )
{
    HANDLE handle = get_handle( &args );
    ULONG flags = get_ulong( &args );
    ULONG base32 = get_ulong( &args );
    SIZE_T size = get_ulong( &args );
    ULONG *addr_ptr = get_ptr( &args );
    ULONG *count_ptr = get_ptr( &args );
    ULONG *granularity = get_ptr( &args );

    struct process_address_codec codec = {0};
    ULONG_PTR i, count, capacity;
    SIZE_T output_size, range_size, max_count;
    const SIZE_T guest_page_size = 0x1000;
    ULONG address32;
    ULONG count32, granularity_value = 0;
    void *base;
    void **addresses;
    NTSTATUS status;

    if (!count_ptr || !granularity) return STATUS_ACCESS_VIOLATION;
    wow64_read_user( &count32, count_ptr, sizeof(count32) );
    count = count32;

    if (!count || !size) return STATUS_INVALID_PARAMETER;
    if (flags & ~WRITE_WATCH_FLAG_RESET) return STATUS_INVALID_PARAMETER;
    if (!addr_ptr) return STATUS_ACCESS_VIOLATION;

    /* NtGetWriteWatch cannot return more than one address per guest page.
     * Clamp the caller's capacity before sizing the native pointer array so a
     * huge capacity cannot amplify a bounded range into a huge temp buffer. */
    range_size = (base32 & (guest_page_size - 1)) + size;
    max_count = (range_size + guest_page_size - 1) / guest_page_size;
    count = min( count, max_count );
    if (count > MAXDWORD / sizeof(*addr_ptr) ||
        count > MAXDWORD / sizeof(*addresses) ||
        count > ~(SIZE_T)0 / sizeof(*addresses))
        return STATUS_INTEGER_OVERFLOW;
    capacity = count;
    output_size = count * sizeof(*addr_ptr);
    wow64_probe_user_write( addr_ptr, output_size );
    wow64_probe_user_write( count_ptr, sizeof(count32) );
    wow64_probe_user_write( granularity, sizeof(granularity_value) );
    __TRY
    {
        status = init_process_address_codec( handle, &codec );
        if (!status)
        {
            base = decode_process_address( &codec, base32 );
            addresses = alloc_temp( count * sizeof(*addresses) );
            status = NtGetWriteWatch( codec.process, flags, base, size,
                                      addresses, &count, &granularity_value );
            if (!status && count > capacity) status = STATUS_INVALID_BUFFER_SIZE;
            if (!status)
            {
                /* Stage all narrowing before touching the caller buffer.  Packed ULONGs
                 * cannot overlap a pointer entry that has not been read yet. */
                C_ASSERT( sizeof(*addresses) >= sizeof(address32) );
                for (i = 0; i < count; i++)
                {
                    status = encode_process_address( &codec, addresses[i], &address32 );
                    if (status) break;
                    memcpy( (char *)addresses + i * sizeof(address32), &address32,
                            sizeof(address32) );
                }
            }
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )
    if (!status)
    {
        count32 = count;
        wow64_write_user( addr_ptr, addresses, count * sizeof(*addr_ptr) );
        wow64_write_user( count_ptr, &count32, sizeof(count32) );
        wow64_write_user( granularity, &granularity_value, sizeof(granularity_value) );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtInitializeNlsFiles
 */
NTSTATUS WINAPI wow64_NtInitializeNlsFiles( UINT *args )
{
    ULONG *addr32 = get_ptr( &args );
    LCID *lcid = get_ptr( &args );
    LARGE_INTEGER *size = get_ptr( &args );

    void *addr;
    void *native_addr;
    LCID lcid_buf = ~0u;
    ULONG guest_addr;
    NTSTATUS status;

    wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
    addr = wow64_guest_memory_ptr( guest_addr );
    native_addr = addr;
    wow64_probe_user_write( addr32, sizeof(guest_addr) );
    wow64_probe_user_write( lcid, sizeof(lcid_buf) );
    /* The native implementation currently treats size as an opaque, unused
     * same-layout argument.  Keep it borrowed so the thunk does not invent an
     * input fault that the underlying call would not take. */
    status = NtInitializeNlsFiles( &native_addr, &lcid_buf, size );
    if (lcid_buf != ~0u) wow64_write_user( lcid, &lcid_buf, sizeof(lcid_buf) );
    if (!status) put_addr( addr32, native_addr );
    return status;
}


/**********************************************************************
 *           wow64_NtLockVirtualMemory
 */
NTSTATUS WINAPI wow64_NtLockVirtualMemory( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG *addr32 = get_ptr( &args );
    ULONG *size32 = get_ptr( &args );
    ULONG unknown = get_ulong( &args );

    struct process_address_codec codec = {0};
    void *addr;
    SIZE_T size = 0;
    NTSTATUS status;
    ULONG guest_addr = 0, result_addr = 0;
    ULONG guest_size = 0;

    if (addr32)
    {
        wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
        wow64_probe_user_write( addr32, sizeof(guest_addr) );
    }
    if (size32)
    {
        wow64_read_user( &guest_size, size32, sizeof(guest_size) );
        wow64_probe_user_write( size32, sizeof(guest_size) );
        size = guest_size;
    }
    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            if (addr32) addr = decode_process_address( &codec, guest_addr );
            status = NtLockVirtualMemory( codec.process, addr32 ? &addr : NULL,
                                          size32 ? &size : NULL, unknown );
            if (!status && addr32)
                status = encode_process_address( &codec, addr, &result_addr );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )
    if (!status)
    {
        if (addr32) wow64_write_user( addr32, &result_addr, sizeof(result_addr) );
        put_size( size32, size );
    }
    return status;
}


static void notify_map_view_of_section( HANDLE handle, void *addr, SIZE_T size, ULONG alloc,
                                        ULONG protect, NTSTATUS *ret_status )
{
    SECTION_IMAGE_INFORMATION info;
    NTSTATUS status;

    if (!NtCurrentTeb()->Tib.ArbitraryUserPointer) return;
    if (NtQuerySection( handle, SectionImageInformation, &info, sizeof(info), NULL )) return;
    if (info.Machine != current_machine) return;
    init_image_mapping( addr );
    if (!pBTCpuNotifyMapViewOfSection) return;
    status = pBTCpuNotifyMapViewOfSection( NULL, addr, NULL, size, alloc, protect );
    if (NT_SUCCESS(status)) return;
    NtUnmapViewOfSection( GetCurrentProcess(), addr );
    *ret_status = status;
}

/**********************************************************************
 *           wow64_NtMapViewOfSection
 */
NTSTATUS WINAPI wow64_NtMapViewOfSection( UINT *args )
{
    HANDLE handle = get_handle( &args );
    HANDLE process = get_handle( &args );
    ULONG *addr32 = get_ptr( &args );
    ULONG_PTR zero_bits = get_ulong( &args );
    SIZE_T commit = get_ulong( &args );
    const LARGE_INTEGER *offset = get_ptr( &args );
    ULONG *size32 = get_ptr( &args );
    SECTION_INHERIT inherit = get_ulong( &args );
    ULONG alloc = get_ulong( &args );
    ULONG protect = get_ulong( &args );

    struct process_address_codec codec = {0};
    struct map_view_cleanup cleanup = {&codec};
    LARGE_INTEGER offset_value;
    const LARGE_INTEGER *native_offset = NULL;
    void *addr = NULL;
    SIZE_T size = 0;
    NTSTATUS status;
    MEM_EXTENDED_PARAMETER *params64;
    ULONG guest_addr = 0, result_addr = 0;
    ULONG guest_arbitrary_user_pointer;
    ULONG count = 0;
    ULONG_PTR limit = 0;
    ULONG guest_size = 0;

    if (addr32) wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
    if (size32)
    {
        wow64_read_user( &guest_size, size32, sizeof(guest_size) );
        size = guest_size;
    }
    if (offset)
    {
        wow64_read_user( &offset_value, offset, sizeof(offset_value) );
        native_offset = &offset_value;
    }
    wow64_read_user( &guest_arbitrary_user_pointer,
                     &NtCurrentTeb32()->Tib.ArbitraryUserPointer,
                     sizeof(guest_arbitrary_user_pointer) );
    cleanup.arbitrary_user_pointer = NtCurrentTeb()->Tib.ArbitraryUserPointer;
    if (addr32) wow64_probe_user_write( addr32, sizeof(guest_addr) );
    if (size32) wow64_probe_user_write( size32, sizeof(guest_size) );

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            if (addr32) addr = decode_process_address( &codec, guest_addr );
            cleanup.restore_arbitrary_user_pointer = TRUE;
            NtCurrentTeb()->Tib.ArbitraryUserPointer =
                wow64_guest_memory_ptr( guest_arbitrary_user_pointer );

            if (codec.translated)
            {
                if (!addr)
                {
                    limit = get_guest_zero_bits_limit( get_zero_bits( zero_bits ) );
                    if (!limit || limit > highest_user_address) limit = highest_user_address;
                }
                status = mem_extended_parameters_32to64( &params64, NULL, &count, limit );
                if (!status)
                {
                    finalize_mem_extended_parameters( params64, &count, &codec, commit );
                    status = NtMapViewOfSectionEx( handle, codec.process,
                                                   addr32 ? &addr : NULL, native_offset,
                                                   size32 ? &size : NULL, alloc, protect,
                                                   params64, count );
                }
            }
            else
                status = NtMapViewOfSection( handle, codec.process, addr32 ? &addr : NULL,
                                             get_zero_bits( zero_bits ), commit, native_offset,
                                             size32 ? &size : NULL, inherit, alloc, protect );

            if (NT_SUCCESS(status))
            {
                NTSTATUS encode_status = addr32 ?
                    encode_process_address( &codec, addr, &result_addr ) : STATUS_SUCCESS;

                if (encode_status)
                {
                    NtUnmapViewOfSection( codec.process, addr );
                    status = encode_status;
                }
                else if (codec.is_current)
                    notify_map_view_of_section( handle, addr, size, alloc, protect, &status );
            }
        }
    }
    __FINALLY_CTX( cleanup_map_view, &cleanup )

    if (NT_SUCCESS(status))
    {
        if (addr32) wow64_write_user( addr32, &result_addr, sizeof(result_addr) );
        put_size( size32, size );
    }
    return status;
}

/**********************************************************************
 *           wow64_NtMapViewOfSectionEx
 */
NTSTATUS WINAPI wow64_NtMapViewOfSectionEx( UINT *args )
{
    HANDLE handle = get_handle( &args );
    HANDLE process = get_handle( &args );
    ULONG *addr32 = get_ptr( &args );
    const LARGE_INTEGER *offset = get_ptr( &args );
    ULONG *size32 = get_ptr( &args );
    ULONG alloc = get_ulong( &args );
    ULONG protect = get_ulong( &args );
    MEM_EXTENDED_PARAMETER32 *params32 = get_ptr( &args );
    ULONG count = get_ulong( &args );

    struct process_address_codec codec = {0};
    struct map_view_cleanup cleanup = {&codec};
    LARGE_INTEGER offset_value;
    const LARGE_INTEGER *native_offset = NULL;
    void *addr = NULL;
    SIZE_T size = 0;
    NTSTATUS status;
    MEM_EXTENDED_PARAMETER *params64;
    ULONG guest_addr = 0, result_addr = 0;
    ULONG guest_arbitrary_user_pointer;
    ULONG_PTR implicit_high;
    ULONG guest_size = 0;

    if (addr32) wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
    if (size32)
    {
        wow64_read_user( &guest_size, size32, sizeof(guest_size) );
        size = guest_size;
    }
    if (offset)
    {
        wow64_read_user( &offset_value, offset, sizeof(offset_value) );
        native_offset = &offset_value;
    }
    wow64_read_user( &guest_arbitrary_user_pointer,
                     &NtCurrentTeb32()->Tib.ArbitraryUserPointer,
                     sizeof(guest_arbitrary_user_pointer) );
    cleanup.arbitrary_user_pointer = NtCurrentTeb()->Tib.ArbitraryUserPointer;
    implicit_high = !guest_addr ? highest_user_address : 0;
    if ((status = mem_extended_parameters_32to64( &params64, params32, &count,
                                                  implicit_high )))
        return status;
    if (addr32) wow64_probe_user_write( addr32, sizeof(guest_addr) );
    if (size32) wow64_probe_user_write( size32, sizeof(guest_size) );

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            if (addr32) addr = decode_process_address( &codec, guest_addr );
            finalize_mem_extended_parameters( params64, &count, &codec, 0 );
            cleanup.restore_arbitrary_user_pointer = TRUE;
            NtCurrentTeb()->Tib.ArbitraryUserPointer =
                wow64_guest_memory_ptr( guest_arbitrary_user_pointer );
            status = NtMapViewOfSectionEx( handle, codec.process, addr32 ? &addr : NULL,
                                           native_offset, size32 ? &size : NULL, alloc,
                                           protect, params64, count );
            if (NT_SUCCESS(status))
            {
                NTSTATUS encode_status = addr32 ?
                    encode_process_address( &codec, addr, &result_addr ) : STATUS_SUCCESS;

                if (encode_status)
                {
                    NtUnmapViewOfSection( codec.process, addr );
                    status = encode_status;
                }
                else if (codec.is_current)
                    notify_map_view_of_section( handle, addr, size, alloc, protect, &status );
            }
        }
    }
    __FINALLY_CTX( cleanup_map_view, &cleanup )

    if (NT_SUCCESS(status))
    {
        if (addr32) wow64_write_user( addr32, &result_addr, sizeof(result_addr) );
        put_size( size32, size );
    }
    return status;
}

/**********************************************************************
 *           wow64_NtProtectVirtualMemory
 */
NTSTATUS WINAPI wow64_NtProtectVirtualMemory( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG *addr32 = get_ptr( &args );
    ULONG *size32 = get_ptr( &args );
    ULONG new_prot = get_ulong( &args );
    ULONG *old_prot = get_ptr( &args );

    struct process_address_codec codec = {0};
    void *addr;
    SIZE_T size;
    NTSTATUS status;
    ULONG guest_addr, guest_size, result_addr = 0;
    ULONG old_prot_buf = ~0u;
    BOOL old_prot_written = FALSE;

    wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
    wow64_read_user( &guest_size, size32, sizeof(guest_size) );
    size = guest_size;
    wow64_probe_user_write( addr32, sizeof(guest_addr) );
    wow64_probe_user_write( size32, sizeof(guest_size) );
    wow64_probe_user_write( old_prot, sizeof(old_prot_buf) );

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            addr = decode_process_address( &codec, guest_addr );
            if (!codec.is_current)
                send_cross_process_notification( codec.process, CrossProcessPreVirtualProtect,
                                                 addr, size, 2, new_prot, 0 );
            else if (pBTCpuNotifyMemoryProtect)
                pBTCpuNotifyMemoryProtect( addr, size, new_prot, FALSE, 0 );

            status = NtProtectVirtualMemory( codec.process, &addr, &size, new_prot,
                                             &old_prot_buf );
            old_prot_written = old_prot_buf != ~0u;

            if (!codec.is_current)
                send_cross_process_notification( codec.process, CrossProcessPostVirtualProtect,
                                                 addr, size, 2, new_prot, status );
            else if (pBTCpuNotifyMemoryProtect)
                pBTCpuNotifyMemoryProtect( addr, size, new_prot, TRUE, status );

            if (!status) status = encode_process_address( &codec, addr, &result_addr );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )

    if (old_prot_written)
        wow64_write_user( old_prot, &old_prot_buf, sizeof(old_prot_buf) );
    if (!status)
    {
        wow64_write_user( addr32, &result_addr, sizeof(result_addr) );
        put_size( size32, size );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtQueryVirtualMemory
 */
NTSTATUS WINAPI wow64_NtQueryVirtualMemory( UINT *args )
{
    HANDLE handle = get_handle( &args );
    ULONG guest_addr = get_ulong( &args );
    MEMORY_INFORMATION_CLASS class = get_ulong( &args );
    void *ptr = get_ptr( &args );
    ULONG len = get_ulong( &args );
    ULONG *retlen = get_ptr( &args );

    struct process_address_codec codec = {0};
    MEMORY_WORKING_SET_EX_INFORMATION *working_set_info = NULL;
    UNICODE_STRING unix_name;
    UNICODE_STRING32 unix_name32;
    WINE_PROCESS_VM_INFORMATION machine_info;
    UINT64 unix_result[2] = {0};
    UINT64 unix_handle = 0;
    void *addr = NULL;
    SIZE_T res_len = 0;
    SIZE_T working_set_snapshot_size = 0, working_set_native_size = 0;
    NTSTATUS status;
    ULONG working_set_count = 0, i;

    /* This process-wide query has no address-sized input or output.  Forward
     * it before initializing the address codec so the native implementation
     * retains ownership of validation order and handle-rights checks. */
    if (class == MemoryWineProcessVmMachineInformation)
    {
        status = NtQueryVirtualMemory( handle, NULL, class, ptr ? &machine_info : NULL,
                                       len, &res_len );
        if (!status)
        {
            wow64_write_user( ptr, &machine_info, sizeof(machine_info) );
            put_size( retlen, res_len );
        }
        return status;
    }

    /* Reject unsupported classes and impossible fixed lengths before pinning
     * the process handle.  Variable-size guest snapshots are captured only
     * after the native class and handle gates that precede their use. */
    switch (class)
    {
    case MemoryBasicInformation:
        if (len < sizeof(MEMORY_BASIC_INFORMATION32))
        {
            res_len = sizeof(MEMORY_BASIC_INFORMATION32);
            status = STATUS_INFO_LENGTH_MISMATCH;
            put_size( retlen, res_len );
            return status;
        }
        if (guest_addr > highest_user_address) return STATUS_INVALID_PARAMETER;
        break;
    case MemoryRegionInformation:
        if (len < sizeof(MEMORY_REGION_INFORMATION32))
        {
            res_len = sizeof(MEMORY_REGION_INFORMATION32);
            status = STATUS_INFO_LENGTH_MISMATCH;
            put_size( retlen, res_len );
            return status;
        }
        if (guest_addr > highest_user_address) return STATUS_INVALID_PARAMETER;
        break;
    case MemoryWorkingSetExInformation:
        if (len < sizeof(MEMORY_WORKING_SET_EX_INFORMATION32))
            return STATUS_INFO_LENGTH_MISMATCH;
        working_set_count = len / sizeof(MEMORY_WORKING_SET_EX_INFORMATION32);
        if (working_set_count > MAXDWORD / sizeof(*working_set_info))
            return STATUS_INTEGER_OVERFLOW;
        working_set_snapshot_size =
            (SIZE_T)working_set_count * sizeof(MEMORY_WORKING_SET_EX_INFORMATION32);
        working_set_native_size = (SIZE_T)working_set_count * sizeof(*working_set_info);
        break;
    case MemoryImageInformation:
        if (len < sizeof(MEMORY_IMAGE_INFORMATION32)) return STATUS_INFO_LENGTH_MISMATCH;
        if (guest_addr > highest_user_address) return STATUS_INVALID_PARAMETER;
        break;
    case MemoryWineLoadUnixLibByName:
    case MemoryWineLoadUnixLib:
    case MemoryWineUnloadUnixLib:
        break;
    case MemoryMappedFilenameInformation:
    case MemoryWineWow64TranslatedInformation:
        break;
    case MemoryWineLoadUnixLibWow64:
    case MemoryWineLoadUnixLibByNameWow64:
        return STATUS_INVALID_INFO_CLASS;
    default:
        FIXME( "unsupported class %u\n", class );
        return STATUS_INVALID_INFO_CLASS;
    }

    __TRY
    {
        status = init_process_address_codec( handle, &codec );
        if (!status)
        {
            switch (class)
            {
            case MemoryWineLoadUnixLib:
            case MemoryWineLoadUnixLibByName:
            case MemoryWineUnloadUnixLib:
                addr = wow64_guest_memory_ptr( guest_addr );
                break;
            default:
                addr = decode_process_address( &codec, guest_addr );
                break;
            }

            switch (class)
            {
            case MemoryBasicInformation:  /* MEMORY_BASIC_INFORMATION */
            {
                MEMORY_BASIC_INFORMATION info;
                MEMORY_BASIC_INFORMATION32 info32;

                if (!(status = NtQueryVirtualMemory( codec.process, addr, class,
                                                     &info, sizeof(info), &res_len )))
                {
                    ULONG base, allocation_base;

                    status = encode_process_address( &codec, info.BaseAddress, &base );
                    if (!status)
                        status = encode_process_address( &codec, info.AllocationBase,
                                                         &allocation_base );
                    if (!status)
                    {
                        info32.BaseAddress = base;
                        info32.AllocationBase = allocation_base;
                        info32.AllocationProtect = info.AllocationProtect;
                        info32.RegionSize = info.RegionSize;
                        info32.State = info.State;
                        info32.Protect = info.Protect;
                        info32.Type = info.Type;
                        if ((ULONG_PTR)base + info.RegionSize > highest_user_address)
                            info32.RegionSize = highest_user_address - base + 1;
                        wow64_write_user( ptr, &info32, sizeof(info32) );
                    }
                }
                res_len = sizeof(MEMORY_BASIC_INFORMATION32);
                break;
            }

            case MemoryMappedFilenameInformation:  /* MEMORY_SECTION_NAME */
            {
                MEMORY_SECTION_NAME *info;
                MEMORY_SECTION_NAME32 info32;
                SIZE_T header_delta = sizeof(*info) - sizeof(info32);
                SIZE_T requested_size = (SIZE_T)len + header_delta;
                SIZE_T size = min( requested_size, sizeof(*info) + 512 );
                SIZE_T copy_size;

                /* The server result is a counted Unicode string.  Start with
                 * a bounded common-case buffer and retry with the exact ABI-
                 * bounded result, rather than allocating the caller's entire
                 * (potentially multi-gigabyte) capacity up front. */
                info = alloc_temp( size );
                status = NtQueryVirtualMemory( codec.process, addr, class,
                                               info, size, &res_len );
                if (status == STATUS_BUFFER_OVERFLOW && res_len > size &&
                    res_len <= requested_size)
                {
                    if (res_len > sizeof(*info) + (SIZE_T)~(USHORT)0 + sizeof(WCHAR))
                        status = STATUS_INVALID_BUFFER_SIZE;
                    else
                    {
                        size = res_len;
                        info = alloc_temp( size );
                        status = NtQueryVirtualMemory( codec.process, addr, class,
                                                       info, size, &res_len );
                    }
                }
                if (!status)
                {
                    if (len < sizeof(info32) ||
                        info->SectionFileName.MaximumLength >
                        len - sizeof(info32) ||
                        info->SectionFileName.MaximumLength > size - sizeof(*info))
                        status = STATUS_INFO_LENGTH_MISMATCH;
                    else
                    {
                        copy_size = sizeof(info32) + info->SectionFileName.MaximumLength;
                        info32.SectionFileName.Length = info->SectionFileName.Length;
                        info32.SectionFileName.MaximumLength =
                            info->SectionFileName.MaximumLength;
                        info32.SectionFileName.Buffer = ptr ?
                            wow64_guest_memory_addr( (char *)ptr + sizeof(info32) ) : 0;
                        memmove( (char *)info + sizeof(info32),
                                 info->SectionFileName.Buffer,
                                 info->SectionFileName.MaximumLength );
                        memcpy( info, &info32, sizeof(info32) );
                        wow64_write_user( ptr, info, copy_size );
                    }
                }
                if (res_len >= header_delta) res_len -= header_delta;
                else res_len = 0;
                break;
            }

            case MemoryRegionInformation: /* MEMORY_REGION_INFORMATION */
            {
                MEMORY_REGION_INFORMATION info;
                MEMORY_REGION_INFORMATION32 info32;

                if (!(status = NtQueryVirtualMemory( codec.process, addr, class,
                                                     &info, sizeof(info), &res_len )))
                {
                    ULONG allocation_base;

                    status = encode_process_address( &codec, info.AllocationBase,
                                                     &allocation_base );
                    if (!status)
                    {
                        info32.AllocationBase = allocation_base;
                        info32.AllocationProtect = info.AllocationProtect;
                        info32.RegionType = info.RegionType;
                        info32.RegionSize = info.RegionSize;
                        info32.CommitSize = info.CommitSize;
                        info32.PartitionId = info.PartitionId;
                        info32.NodePreference = info.NodePreference;
                        if ((ULONG_PTR)allocation_base + info.RegionSize > highest_user_address)
                            info32.RegionSize = highest_user_address - allocation_base + 1;
                        wow64_write_user( ptr, &info32, sizeof(info32) );
                    }
                }
                res_len = sizeof(MEMORY_REGION_INFORMATION32);
                break;
            }

            case MemoryWorkingSetExInformation:  /* MEMORY_WORKING_SET_EX_INFORMATION */
                if (!codec.is_current)
                {
                    /* The native implementation rejects a non-current process
                     * before inspecting its variable-sized in/out buffer. */
                    status = NtQueryVirtualMemory( codec.process, addr, class, NULL, 0,
                                                   &res_len );
                    break;
                }
                if (codec.process != NtCurrentProcess())
                {
                    MEMORY_BASIC_INFORMATION access_info;
                    SIZE_T access_len;

                    /* The local WorkingSet implementation accepts only the
                     * pseudo handle.  First run an ordinary query through the
                     * pinned real handle so the server enforces its original
                     * access mask; substituting the pseudo handle directly
                     * would silently upgrade a restricted duplicate. */
                    status = NtQueryVirtualMemory( codec.process, addr,
                                                   MemoryBasicInformation,
                                                   &access_info, sizeof(access_info),
                                                   &access_len );
                    if (status) break;
                }

                /* Validate the complete guest snapshot before allocating the
                 * widened array.  Expand backwards in that same allocation so
                 * attacker-controlled lengths do not require two temp arrays. */
                wow64_probe_user_read( ptr, working_set_snapshot_size );
                working_set_info = alloc_temp( working_set_native_size );
                wow64_read_user( working_set_info, ptr, working_set_snapshot_size );
                for (i = working_set_count; i--;)
                {
                    MEMORY_WORKING_SET_EX_INFORMATION32 info32;

                    memcpy( &info32,
                            (char *)working_set_info + i * sizeof(info32), sizeof(info32) );
                    working_set_info[i].VirtualAddress =
                        decode_process_address( &codec, info32.VirtualAddress );
                    working_set_info[i].VirtualAttributes.Flags =
                        info32.VirtualAttributes.Flags;
                }

                status = NtQueryVirtualMemory( NtCurrentProcess(), addr, class,
                                               working_set_info, working_set_native_size,
                                               &res_len );
                if (!status)
                {
                    if (res_len > working_set_native_size ||
                        res_len % sizeof(*working_set_info))
                    {
                        status = STATUS_INVALID_BUFFER_SIZE;
                        break;
                    }
                    working_set_count = res_len / sizeof(*working_set_info);
                    for (i = 0; i < working_set_count; i++)
                    {
                        MEMORY_WORKING_SET_EX_INFORMATION32 info32;

                        status = encode_process_address( &codec,
                                                         working_set_info[i].VirtualAddress,
                                                         &info32.VirtualAddress );
                        if (status) break;
                        info32.VirtualAttributes.Flags =
                            working_set_info[i].VirtualAttributes.Flags;
                        memcpy( (char *)working_set_info + i * sizeof(info32),
                                &info32, sizeof(info32) );
                    }
                    if (status) break;
                    res_len = (SIZE_T)working_set_count *
                              sizeof(MEMORY_WORKING_SET_EX_INFORMATION32);
                    wow64_write_user( ptr, working_set_info, res_len );
                }
                break;

            case MemoryImageInformation: /* MEMORY_IMAGE_INFORMATION */
            {
                MEMORY_IMAGE_INFORMATION info;
                MEMORY_IMAGE_INFORMATION32 info32;

                if (!(status = NtQueryVirtualMemory( codec.process, addr, class,
                                                     &info, sizeof(info), &res_len )))
                {
                    ULONG image_base;

                    if (codec.translated)
                    {
                        if ((ULONG_PTR)info.ImageBase > ~(ULONG)0)
                            status = STATUS_INVALID_ADDRESS;
                        else
                            image_base = (ULONG)(ULONG_PTR)info.ImageBase;
                    }
                    else
                        status = encode_process_address( &codec, info.ImageBase, &image_base );
                    if (!status)
                    {
                        info32.ImageBase = image_base;
                        info32.SizeOfImage = info.SizeOfImage;
                        info32.ImageFlags = info.ImageFlags;
                        wow64_write_user( ptr, &info32, sizeof(info32) );
                    }
                }
                res_len = sizeof(MEMORY_IMAGE_INFORMATION32);
                break;
            }

            case MemoryWineWow64TranslatedInformation:
                if (codec.process != NtCurrentProcess()) status = STATUS_INVALID_HANDLE;
                else
                {
                    ULONG translated;

                    status = NtQueryVirtualMemory( NtCurrentProcess(), addr, class,
                                                   ptr ? &translated : NULL, len, &res_len );
                    if (!status) wow64_write_user( ptr, &translated, sizeof(translated) );
                }
                break;

            case MemoryWineLoadUnixLib:
                /* Native validates the exact result size before checking that
                 * the pseudo current-process handle was supplied. */
                if (len != sizeof(unix_result[0]))
                {
                    status = NtQueryVirtualMemory( codec.process, addr,
                                                   MemoryWineLoadUnixLibWow64,
                                                   &unix_result[0], len, &res_len );
                    break;
                }
                if (codec.process != NtCurrentProcess())
                {
                    status = STATUS_INVALID_HANDLE;
                    break;
                }
                if (!ptr)
                {
                    status = STATUS_ACCESS_VIOLATION;
                    break;
                }
                wow64_probe_user_write( ptr, sizeof(unix_result[0]) );
                if (retlen) wow64_probe_user_write( retlen, sizeof(*retlen) );
                status = NtQueryVirtualMemory( codec.process, addr,
                                               MemoryWineLoadUnixLibWow64,
                                               &unix_result[0], len, &res_len );
                if (!status)
                    wow64_write_user( ptr, &unix_result[0], sizeof(unix_result[0]) );
                break;
            case MemoryWineLoadUnixLibByName:
            {
                SIZE_T name_alloc_size;

                /* Native rejects non-pseudo handles before reading the name.
                 * Keep that order before materializing the guest string. */
                if (codec.process != NtCurrentProcess())
                {
                    status = STATUS_INVALID_HANDLE;
                    break;
                }
                if (len != sizeof(unix_result[0]) && len != sizeof(unix_result))
                {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                    break;
                }
                if (!ptr)
                {
                    status = STATUS_ACCESS_VIOLATION;
                    break;
                }
                wow64_read_user( &unix_name32, wow64_guest_memory_ptr( guest_addr ),
                                 sizeof(unix_name32) );
                unix_name.Length = unix_name32.Length;
                unix_name.MaximumLength = unix_name32.MaximumLength;
                if ((SIZE_T)unix_name.Length > ~(SIZE_T)0 - sizeof(*unix_name.Buffer))
                {
                    status = STATUS_INTEGER_OVERFLOW;
                    break;
                }
                name_alloc_size = (SIZE_T)unix_name.Length + sizeof(*unix_name.Buffer);
                unix_name.Buffer = alloc_temp( name_alloc_size );
                if (unix_name.Length)
                    wow64_read_user( unix_name.Buffer,
                                     wow64_guest_memory_ptr( unix_name32.Buffer ),
                                     unix_name.Length );
                memset( (char *)unix_name.Buffer + unix_name.Length, 0,
                        sizeof(*unix_name.Buffer) );
                wow64_probe_user_write( ptr, len );
                if (retlen) wow64_probe_user_write( retlen, sizeof(*retlen) );
                status = NtQueryVirtualMemory( codec.process, &unix_name,
                                               MemoryWineLoadUnixLibByNameWow64,
                                               unix_result, len, &res_len );
                if (!status)
                {
                    NTSTATUS publish_status = wow64_try_write_user(
                        ptr, unix_result, len );

                    if (publish_status)
                    {
                        UINT64 rollback_handle = unix_result[0];

                        NtQueryVirtualMemory( NtCurrentProcess(), &rollback_handle,
                                              MemoryWineUnloadUnixLib, NULL, 0, NULL );
                        status = publish_status;
                    }
                }
                break;
            }
            case MemoryWineUnloadUnixLib:
                if (codec.process != NtCurrentProcess())
                {
                    status = STATUS_INVALID_HANDLE;
                    break;
                }
                wow64_read_user( &unix_handle, wow64_guest_memory_ptr( guest_addr ),
                                 sizeof(unix_handle) );
                if (retlen) wow64_probe_user_write( retlen, sizeof(*retlen) );
                status = NtQueryVirtualMemory( codec.process, &unix_handle, class,
                                               NULL, len, &res_len );
                break;
            default:
                /* All classes were validated before the process handle was pinned. */
                status = STATUS_INVALID_INFO_CLASS;
                break;
            }
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )

    if (!status || status == STATUS_INFO_LENGTH_MISMATCH) put_size( retlen, res_len );
    return status;
}


/**********************************************************************
 *           wow64_NtReadVirtualMemory
 */
NTSTATUS WINAPI wow64_NtReadVirtualMemory( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG addr32 = get_ulong( &args );
    void *buffer = get_ptr( &args );
    SIZE_T size = get_ulong( &args );
    ULONG *retlen = get_ptr( &args );

    struct process_address_codec codec = {0};
    const void *addr;
    SIZE_T ret_size = 0;
    NTSTATUS status;
    BOOL called = FALSE;

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            addr = decode_process_address( &codec, addr32 );
            called = TRUE;
            status = NtReadVirtualMemory( codec.process, addr, buffer, size, &ret_size );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )

    if (called) put_size( retlen, ret_size );
    return status;
}


/**********************************************************************
 *           wow64_NtResetWriteWatch
 */
NTSTATUS WINAPI wow64_NtResetWriteWatch( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG base32 = get_ulong( &args );
    SIZE_T size = get_ulong( &args );
    struct process_address_codec codec = {0};
    NTSTATUS status;

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
            status = NtResetWriteWatch( codec.process,
                                        decode_process_address( &codec, base32 ), size );
    }
    __FINALLY_CTX( close_process_address_codec, &codec )
    return status;
}


/**********************************************************************
 *           wow64_NtSetInformationVirtualMemory
 */
NTSTATUS WINAPI wow64_NtSetInformationVirtualMemory( UINT *args )
{
    HANDLE process = get_handle( &args );
    VIRTUAL_MEMORY_INFORMATION_CLASS info_class = get_ulong( &args );
    ULONG count = get_ulong( &args );
    MEMORY_RANGE_ENTRY32 *addresses32 = get_ptr( &args );
    PVOID ptr = get_ptr( &args );
    ULONG len = get_ulong( &args );

    struct process_address_codec codec = {0};
    MEMORY_RANGE_ENTRY *addresses;
    ULONG value = 0;
    NTSTATUS status;

    switch (info_class)
    {
    case VmPrefetchInformation:
        if (!ptr) return STATUS_INVALID_PARAMETER_5;
        if (len != sizeof(value)) return STATUS_INVALID_PARAMETER_6;
        if (!count) return STATUS_INVALID_PARAMETER_3;
        if (count > MAXDWORD / sizeof(*addresses32) ||
            count > MAXDWORD / sizeof(*addresses))
            return STATUS_INTEGER_OVERFLOW;
        wow64_read_user( &value, ptr, sizeof(value) );
        break;
    default:
        FIXME( "(%p,info_class=%u,%lu,%p,%p,%lu): not implemented\n",
               process, info_class, count, addresses32, ptr, len );
        return STATUS_INVALID_PARAMETER_2;
    }

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            status = memory_range_entry_array_32to64( &addresses, &codec,
                                                       addresses32, count );
            if (!status)
                status = NtSetInformationVirtualMemory( codec.process, info_class, count,
                                                        addresses, &value, len );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )
    return status;
}


/**********************************************************************
 *           wow64_NtSetLdtEntries
 */
NTSTATUS WINAPI wow64_NtSetLdtEntries( UINT *args )
{
    ULONG sel1 = get_ulong( &args );
    ULONG entry1_low = get_ulong( &args );
    ULONG entry1_high = get_ulong( &args );
    ULONG sel2 = get_ulong( &args );
    ULONG entry2_low = get_ulong( &args );
    ULONG entry2_high = get_ulong( &args );

    return NtSetLdtEntries( sel1, entry1_low, entry1_high, sel2, entry2_low, entry2_high );
}


/**********************************************************************
 *           wow64_NtUnlockVirtualMemory
 */
NTSTATUS WINAPI wow64_NtUnlockVirtualMemory( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG *addr32 = get_ptr( &args );
    ULONG *size32 = get_ptr( &args );
    ULONG unknown = get_ulong( &args );

    struct process_address_codec codec = {0};
    void *addr = NULL;
    SIZE_T size = 0;
    NTSTATUS status;
    ULONG guest_addr = 0, result_addr = 0;
    ULONG guest_size = 0;

    if (addr32)
    {
        wow64_read_user( &guest_addr, addr32, sizeof(guest_addr) );
        wow64_probe_user_write( addr32, sizeof(guest_addr) );
    }
    if (size32)
    {
        wow64_read_user( &guest_size, size32, sizeof(guest_size) );
        wow64_probe_user_write( size32, sizeof(guest_size) );
        size = guest_size;
    }
    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            if (addr32) addr = decode_process_address( &codec, guest_addr );
            status = NtUnlockVirtualMemory( codec.process, addr32 ? &addr : NULL,
                                            size32 ? &size : NULL, unknown );
            if (!status && addr32)
                status = encode_process_address( &codec, addr, &result_addr );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )

    if (!status)
    {
        if (addr32) wow64_write_user( addr32, &result_addr, sizeof(result_addr) );
        put_size( size32, size );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtUnmapViewOfSection
 */
NTSTATUS WINAPI wow64_NtUnmapViewOfSection( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG addr32 = get_ulong( &args );

    struct process_address_codec codec = {0};
    void *addr;
    NTSTATUS status;

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            addr = decode_process_address( &codec, addr32 );
            if (codec.is_current && pBTCpuNotifyUnmapViewOfSection)
                pBTCpuNotifyUnmapViewOfSection( addr, FALSE, 0 );
            status = NtUnmapViewOfSection( codec.process, addr );
            if (codec.is_current && pBTCpuNotifyUnmapViewOfSection)
                pBTCpuNotifyUnmapViewOfSection( addr, TRUE, status );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )
    return status;
}


/**********************************************************************
 *           wow64_NtUnmapViewOfSectionEx
 */
NTSTATUS WINAPI wow64_NtUnmapViewOfSectionEx( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG addr32 = get_ulong( &args );
    ULONG flags = get_ulong( &args );

    struct process_address_codec codec = {0};
    void *addr;
    NTSTATUS status;

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            addr = decode_process_address( &codec, addr32 );
            if (codec.is_current && pBTCpuNotifyUnmapViewOfSection)
                pBTCpuNotifyUnmapViewOfSection( addr, FALSE, 0 );
            status = NtUnmapViewOfSectionEx( codec.process, addr, flags );
            if (codec.is_current && pBTCpuNotifyUnmapViewOfSection)
                pBTCpuNotifyUnmapViewOfSection( addr, TRUE, status );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )
    return status;
}


/**********************************************************************
 *           wow64_NtWow64AllocateVirtualMemory64
 */
NTSTATUS WINAPI wow64_NtWow64AllocateVirtualMemory64( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG64 *addr = get_ptr( &args );
    ULONG_PTR zero_bits = get_ulong64( &args );
    ULONG64 *size = get_ptr( &args );
    ULONG type = get_ulong( &args );
    ULONG protect = get_ulong( &args );

    ULONG64 addr64, size64;
    void *native_addr;
    SIZE_T native_size;
    NTSTATUS status;

    wow64_read_user( &addr64, addr, sizeof(addr64) );
    wow64_read_user( &size64, size, sizeof(size64) );
    native_addr = (void *)(ULONG_PTR)addr64;
    native_size = size64;
    if ((ULONG64)native_size != size64) return STATUS_WORKING_SET_LIMIT_RANGE;
    wow64_probe_user_write( addr, sizeof(addr64) );
    wow64_probe_user_write( size, sizeof(size64) );
    status = NtAllocateVirtualMemory( process, &native_addr, zero_bits, &native_size,
                                      type, protect );
    if (!status)
    {
        addr64 = (ULONG_PTR)native_addr;
        size64 = native_size;
        wow64_write_user( addr, &addr64, sizeof(addr64) );
        wow64_write_user( size, &size64, sizeof(size64) );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtWow64ReadVirtualMemory64
 */
NTSTATUS WINAPI wow64_NtWow64ReadVirtualMemory64( UINT *args )
{
    HANDLE process = get_handle( &args );
    void *addr = (void *)(ULONG_PTR)get_ulong64( &args );
    void *buffer = get_ptr( &args );
    SIZE_T size = get_ulong64( &args );
    ULONG64 *ret_size = get_ptr( &args );

    SIZE_T native_ret_size = 0;
    ULONG64 result;
    NTSTATUS status;

    status = NtReadVirtualMemory( process, addr, buffer, size, &native_ret_size );
    if (ret_size)
    {
        result = native_ret_size;
        wow64_write_user( ret_size, &result, sizeof(result) );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtWow64WriteVirtualMemory64
 */
NTSTATUS WINAPI wow64_NtWow64WriteVirtualMemory64( UINT *args )
{
    HANDLE process = get_handle( &args );
    void *addr = (void *)(ULONG_PTR)get_ulong64( &args );
    const void *buffer = get_ptr( &args );
    SIZE_T size = get_ulong64( &args );
    ULONG64 *ret_size = get_ptr( &args );

    SIZE_T native_ret_size = 0;
    ULONG64 result;
    NTSTATUS status;

    if (ret_size) wow64_probe_user_write( ret_size, sizeof(*ret_size) );
    status = NtWriteVirtualMemory( process, addr, buffer, size, &native_ret_size );
    if (ret_size)
    {
        result = native_ret_size;
        wow64_write_user( ret_size, &result, sizeof(result) );
    }
    return status;
}


/**********************************************************************
 *           wow64_NtWriteVirtualMemory
 */
NTSTATUS WINAPI wow64_NtWriteVirtualMemory( UINT *args )
{
    HANDLE process = get_handle( &args );
    ULONG addr32 = get_ulong( &args );
    const void *buffer = get_ptr( &args );
    SIZE_T size = get_ulong( &args );
    ULONG *retlen = get_ptr( &args );

    struct process_address_codec codec = {0};
    void *addr;
    SIZE_T ret_size = 0;
    NTSTATUS status;
    BOOL called = FALSE;

    if (retlen) wow64_probe_user_write( retlen, sizeof(*retlen) );

    __TRY
    {
        status = init_process_address_codec( process, &codec );
        if (!status)
        {
            addr = decode_process_address( &codec, addr32 );
            called = TRUE;
            status = NtWriteVirtualMemory( codec.process, addr, buffer, size, &ret_size );
        }
    }
    __FINALLY_CTX( close_process_address_codec, &codec )

    if (called) put_size( retlen, ret_size );
    return status;
}
