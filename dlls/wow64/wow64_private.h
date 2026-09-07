/*
 * WoW64 private definitions
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

#ifndef __WOW64_PRIVATE_H
#define __WOW64_PRIVATE_H

#include "../ntdll/ntsyscalls.h"
#include "../ntdll/unixlib.h"
#include "struct32.h"
#include "wine/low_va.h"
#include "wine/wow64_user.h"

#define SYSCALL_ENTRY(id,name,_args) extern NTSTATUS WINAPI wow64_ ## name( UINT *args );
ALL_SYSCALLS32
#undef SYSCALL_ENTRY

extern void init_image_mapping( HMODULE module );
extern void init_file_redirects(void);
extern BOOL get_file_redirect( OBJECT_ATTRIBUTES *attr );

extern USHORT native_machine;
extern USHORT current_machine;
extern ULONG_PTR args_alignment;
extern ULONG_PTR highest_user_address;
extern ULONG_PTR default_zero_bits;
extern BOOL wow64_low_va_shadow;
extern SYSTEM_DLL_INIT_BLOCK *pLdrSystemDllInitBlock;

extern void     (WINAPI *pBTCpuFlushInstructionCache2)( const void *, SIZE_T );
extern void     (WINAPI *pBTCpuFlushInstructionCacheHeavy)( const void *, SIZE_T );
extern NTSTATUS (WINAPI *pBTCpuNotifyMapViewOfSection)( void *, void *, void *, SIZE_T, ULONG, ULONG );
extern void     (WINAPI *pBTCpuNotifyMemoryAlloc)( void *, SIZE_T, ULONG, ULONG, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuNotifyMemoryDirty)( void *, SIZE_T );
extern void     (WINAPI *pBTCpuNotifyMemoryFree)( void *, SIZE_T, ULONG, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuNotifyMemoryProtect)( void *, SIZE_T, ULONG, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuNotifyProcessExecuteFlagsChange)(ULONG);
extern void     (WINAPI *pBTCpuNotifyReadFile)( HANDLE, void *, SIZE_T, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuNotifyUnmapViewOfSection)( void *, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuUpdateProcessorInformation)( SYSTEM_CPU_INFORMATION * );
extern void     (WINAPI *pBTCpuProcessTerm)( HANDLE, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuThreadTerm)( HANDLE, LONG );

struct object_attr64
{
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      str;
    SECURITY_DESCRIPTOR sd;
    SECURITY_QUALITY_OF_SERVICE qos;
};

/* Pin a target process handle with its original access mask while resolving
 * the authoritative target address model.  Cross-process thunk callers must
 * perform the native operation through codec.process and keep the codec alive
 * until every target-address input and output has been converted. */
struct process_address_codec
{
    HANDLE process;
    BOOL close_process;
    BOOL is_current;
    BOOL translated;
};

extern NTSTATUS init_process_address_codec( HANDLE process,
                                             struct process_address_codec *codec );
extern void CALLBACK close_process_address_codec( BOOL normal, void *arg );
extern void *decode_process_address( const struct process_address_codec *codec,
                                     ULONG address );
extern NTSTATUS encode_process_address( const struct process_address_codec *codec,
                                        const void *address, ULONG *ret );

/* cf. GetSystemWow64Directory2 */
static inline const WCHAR *get_machine_wow64_dir( USHORT machine )
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_TARGET_HOST: return L"\\??\\C:\\windows\\system32";
    case IMAGE_FILE_MACHINE_I386:        return L"\\??\\C:\\windows\\syswow64";
    case IMAGE_FILE_MACHINE_ARMNT:       return L"\\??\\C:\\windows\\sysarm32";
    default: return NULL;
    }
}

static inline TEB32 *NtCurrentTeb32(void)
{
    return (TEB32 *)((char *)NtCurrentTeb() + NtCurrentTeb()->WowTebOffset);
}

/* Native ARM64 keeps i386 mappings in a fixed high shadow while the guest ABI
 * retains low 32-bit addresses.  This process-init state is captured before
 * guest code runs; do not make the translation boundary depend on writable PEB
 * fields after initialization. */
static inline BOOL wow64_uses_low_va_shadow(void)
{
    return wow64_low_va_shadow;
}

static inline void *wow64_guest_memory_ptr( ULONG address )
{
    return wine_wow64_guest_memory_ptr_for_shadow( wow64_uses_low_va_shadow(), address );
}

static inline ULONG wow64_guest_memory_addr( const void *address )
{
    return wine_wow64_guest_memory_addr_for_shadow( wow64_uses_low_va_shadow(), address );
}

/* Convert pointer-shaped values that the native call treats as opaque data. */
static inline void *wow64_raw_ptr32( ULONG value )
{
    return ULongToPtr( value );
}

static inline void wow64_read_user( void *dst, const void *src, SIZE_T size )
{
    NTSTATUS status = wine_wow64_copy_from_user( dst, src, size );
    if (status) RtlRaiseStatus( status );
}

static inline void wow64_write_user( void *dst, const void *src, SIZE_T size )
{
    NTSTATUS status = wine_wow64_copy_to_user( dst, src, size );
    if (status) RtlRaiseStatus( status );
}

/* Use the status-returning form when the native call creates an object or
 * otherwise acquires ownership that must be rolled back if the guest output
 * is reprotected after its initial probe. */
static inline NTSTATUS wow64_try_write_user( void *dst, const void *src, SIZE_T size )
{
    return wine_wow64_try_copy_to_user( dst, src, size );
}

static inline void wow64_probe_user_read( const void *ptr, SIZE_T size )
{
    NTSTATUS status = wine_wow64_probe_user_read( ptr, size );
    if (status) RtlRaiseStatus( status );
}

static inline void wow64_probe_user_write( void *ptr, SIZE_T size )
{
    NTSTATUS status = wine_wow64_probe_user_write( ptr, size );
    if (status) RtlRaiseStatus( status );
}

static inline void wow64_faulting_write_user( void *dst, const void *src, SIZE_T size )
{
    NTSTATUS status = wine_wow64_faulting_copy_to_user( dst, src, size );
    if (status) RtlRaiseStatus( status );
}

static inline NTSTATUS wow64_store_release_long( LONG *dst, LONG value )
{
    return __wine_wow64_store_release_long( dst, value );
}

static inline NTSTATUS wow64_publish_iosb( IO_STATUS_BLOCK32 *dst, NTSTATUS status,
                                           ULONG information )
{
    return __wine_wow64_publish_iosb( dst, status, information );
}

static inline ULONG get_ulong( UINT **args )
{
    return *(*args)++;
}

static inline HANDLE get_handle( UINT **args ) { return LongToHandle( get_ulong( args ) ); }
static inline void *get_ptr( UINT **args ) { return wow64_guest_memory_ptr( get_ulong( args ) ); }
static inline void *get_raw_ptr( UINT **args ) { return wow64_raw_ptr32( get_ulong( args ) ); }

static inline ULONG64 get_ulong64( UINT **args )
{
    ULONG64 ret;

    *args = (UINT *)(((ULONG_PTR)*args + args_alignment - 1) & ~(args_alignment - 1));
    ret = *(ULONG64 *)*args;
    *args += 2;
    return ret;
}

static inline ULONG_PTR get_zero_bits( ULONG_PTR zero_bits )
{
    return zero_bits ? zero_bits : default_zero_bits;
}

static inline void **addr_32to64( void **addr, ULONG *addr32 )
{
    ULONG value;

    if (!addr32) return NULL;
    wow64_read_user( &value, addr32, sizeof(value) );
    *addr = wow64_guest_memory_ptr( value );
    return addr;
}

static inline SIZE_T *size_32to64( SIZE_T *size, ULONG *size32 )
{
    ULONG value;

    if (!size32) return NULL;
    wow64_read_user( &value, size32, sizeof(value) );
    *size = value;
    return size;
}

static inline void *apc_32to64( ULONG func )
{
    return func ? Wow64ApcRoutine : NULL;
}

static inline void *apc_param_32to64( ULONG func, ULONG context )
{
    if (!func) return wow64_raw_ptr32( context );  /* completion-port value, not an address */
    return (void *)(ULONG_PTR)(((ULONG64)func << 32) | context);
}

static inline IO_STATUS_BLOCK *iosb_32to64( IO_STATUS_BLOCK *io, IO_STATUS_BLOCK32 *io32 )
{
    if (!io32) return NULL;
    io->Pointer = io32;
    return io;
}

static inline UNICODE_STRING *unicode_str_32to64( UNICODE_STRING *str, const UNICODE_STRING32 *str32 )
{
    UNICODE_STRING32 local;

    if (!str32) return NULL;
    wow64_read_user( &local, str32, sizeof(local) );
    str->Length = local.Length;
    str->MaximumLength = local.MaximumLength;
    str->Buffer = wow64_guest_memory_ptr( local.Buffer );
    return str;
}

/* Materialize a guest string for native helpers that inspect the buffer before
 * entering ntdll's common object-attribute capture boundary.  The temporary
 * allocation has syscall lifetime and the terminator is native-only; Windows'
 * Length and MaximumLength values remain unchanged. */
static inline UNICODE_STRING *unicode_str_32to64_temp( UNICODE_STRING *str,
                                                       const UNICODE_STRING32 *str32 )
{
    WCHAR *buffer;

    if (!unicode_str_32to64( str, str32 )) return NULL;
    if (!(buffer = Wow64AllocateTemp( (SIZE_T)str->Length + sizeof(*buffer) )))
        RtlRaiseStatus( STATUS_NO_MEMORY );
    if (str->Length) wow64_read_user( buffer, str->Buffer, str->Length );
    buffer[str->Length / sizeof(*buffer)] = 0;
    str->Buffer = buffer;
    return str;
}

static inline void unicode_str_32to64_materialize( UNICODE_STRING *str )
{
    WCHAR *buffer;

    if (!str || !str->Buffer) return;
    if (!(buffer = Wow64AllocateTemp( (SIZE_T)str->Length + sizeof(*buffer) )))
        RtlRaiseStatus( STATUS_NO_MEMORY );
    if (str->Length) wow64_read_user( buffer, str->Buffer, str->Length );
    buffer[str->Length / sizeof(*buffer)] = 0;
    str->Buffer = buffer;
}

static inline CLIENT_ID *client_id_32to64( CLIENT_ID *id, const CLIENT_ID32 *id32 )
{
    CLIENT_ID32 local;

    if (!id32) return NULL;
    wow64_read_user( &local, id32, sizeof(local) );
    id->UniqueProcess = LongToHandle( local.UniqueProcess );
    id->UniqueThread = LongToHandle( local.UniqueThread );
    return id;
}

static inline SECURITY_DESCRIPTOR *secdesc_32to64( SECURITY_DESCRIPTOR *out, const SECURITY_DESCRIPTOR *in )
{
    /* relative descr has the same layout for 32 and 64 */
    SECURITY_DESCRIPTOR_RELATIVE sd;

    if (!in) return NULL;
    wow64_read_user( &sd, in, sizeof(sd) );
    out->Revision = sd.Revision;
    out->Sbz1     = sd.Sbz1;
    out->Control  = sd.Control & ~SE_SELF_RELATIVE;
    if (sd.Control & SE_SELF_RELATIVE)
    {
        out->Owner = sd.Owner ? (PSID)((BYTE *)in + sd.Owner) : NULL;
        out->Group = sd.Group ? (PSID)((BYTE *)in + sd.Group) : NULL;
        out->Sacl = ((sd.Control & SE_SACL_PRESENT) && sd.Sacl) ? (PSID)((BYTE *)in + sd.Sacl) : NULL;
        out->Dacl = ((sd.Control & SE_DACL_PRESENT) && sd.Dacl) ? (PSID)((BYTE *)in + sd.Dacl) : NULL;
    }
    else
    {
        out->Owner = wow64_guest_memory_ptr( sd.Owner );
        out->Group = wow64_guest_memory_ptr( sd.Group );
        out->Sacl = (sd.Control & SE_SACL_PRESENT) ? wow64_guest_memory_ptr( sd.Sacl ) : NULL;
        out->Dacl = (sd.Control & SE_DACL_PRESENT) ? wow64_guest_memory_ptr( sd.Dacl ) : NULL;
    }
    return out;
}

static inline OBJECT_ATTRIBUTES *objattr_32to64( struct object_attr64 *out, const OBJECT_ATTRIBUTES32 *in )
{
    OBJECT_ATTRIBUTES32 local;

    memset( out, 0, sizeof(*out) );
    if (!in) return NULL;
    wow64_read_user( &local, in, sizeof(local) );
    if (local.Length != sizeof(local)) return &out->attr;

    out->attr.Length = sizeof(out->attr);
    out->attr.RootDirectory = LongToHandle( local.RootDirectory );
    out->attr.Attributes = local.Attributes;
    out->attr.ObjectName = unicode_str_32to64( &out->str, wow64_guest_memory_ptr( local.ObjectName ));
    if (local.SecurityQualityOfService)
    {
        SECURITY_QUALITY_OF_SERVICE32 qos32;

        wow64_read_user( &qos32, wow64_guest_memory_ptr( local.SecurityQualityOfService ), sizeof(qos32) );
        out->qos.Length = qos32.Length;
        out->qos.ImpersonationLevel = qos32.ImpersonationLevel;
        out->qos.ContextTrackingMode = qos32.ContextTrackingMode;
        out->qos.EffectiveOnly = qos32.EffectiveOnly;
        out->attr.SecurityQualityOfService = &out->qos;
    }
    out->attr.SecurityDescriptor = secdesc_32to64( &out->sd,
                                                   wow64_guest_memory_ptr( local.SecurityDescriptor ));
    return &out->attr;
}

static inline OBJECT_ATTRIBUTES *objattr_32to64_redirect( struct object_attr64 *out,
                                                          const OBJECT_ATTRIBUTES32 *in )
{
    OBJECT_ATTRIBUTES *attr = objattr_32to64( out, in );

    if (attr)
    {
        unicode_str_32to64_materialize( attr->ObjectName );
        get_file_redirect( attr );
    }
    return attr;
}

static inline ALPC_PORT_ATTRIBUTES *alpc_port_attributes_32to64( ALPC_PORT_ATTRIBUTES *out,
                                                                 const ALPC_PORT_ATTRIBUTES32 *in )
{
    ALPC_PORT_ATTRIBUTES32 local;

    if (!in) return NULL;
    wow64_read_user( &local, in, sizeof(local) );

    out->Flags = local.Flags;
    out->SecurityQos.Length = local.SecurityQos.Length;
    out->SecurityQos.ImpersonationLevel = local.SecurityQos.ImpersonationLevel;
    out->SecurityQos.ContextTrackingMode = local.SecurityQos.ContextTrackingMode;
    out->SecurityQos.EffectiveOnly = local.SecurityQos.EffectiveOnly;
    out->MaxMessageLength = local.MaxMessageLength + (sizeof(ALPC_PORT_MESSAGE) - sizeof(ALPC_PORT_MESSAGE32));
    out->MemoryBandwidth = local.MemoryBandwidth;
    out->MaxPoolUsage = local.MaxPoolUsage;
    out->MaxSectionSize = local.MaxSectionSize;
    out->MaxViewSize = local.MaxViewSize;
    out->MaxTotalSectionSize = local.MaxTotalSectionSize;
    out->DupObjectTypes = local.DupObjectTypes;
    out->Reserved = 0;
    return out;
}

static inline ALPC_PORT_MESSAGE *alpc_port_message_32to64( ALPC_PORT_MESSAGE **out, SIZE_T out_msg_size,
                                                           const ALPC_PORT_MESSAGE32 *in, BOOL copy_msg )
{
    ALPC_PORT_MESSAGE *msg;

    if (!in || !(msg = Wow64AllocateTemp( out_msg_size )))
    {
        *out = NULL;
        return NULL;
    }

    if (!copy_msg) goto done;

    msg->DataLength = in->DataLength;
    msg->TotalLength = sizeof(*msg) + msg->DataLength;
    msg->Type = in->Type;
    msg->DataInfoOffset = in->DataInfoOffset;
    client_id_32to64( &msg->ClientId, &in->ClientId );
    msg->MessageId = in->MessageId;
    msg->ClientViewSize = in->ClientViewSize;
    memcpy( (unsigned char *)msg + sizeof(*msg), (const unsigned char *)in + sizeof(*in), in->DataLength );
done:
    *out = msg;
    return msg;
}

static inline ALPC_CONTEXT_ATTR *alpc_context_attr_32to64( ALPC_CONTEXT_ATTR *out,
                                                           const ALPC_CONTEXT_ATTR32 *in )
{
    out->PortContext = wow64_raw_ptr32( in->PortContext );
    out->MessageContext = wow64_raw_ptr32( in->MessageContext );
    out->Sequence = in->Sequence;
    out->MessageId = in->MessageId;
    out->CallbackId = in->CallbackId;
    return out;
}

static inline ALPC_MESSAGE_ATTRIBUTES *alpc_port_message_attributes_32to64( ALPC_MESSAGE_ATTRIBUTES **out,
                                                                            const ALPC_MESSAGE_ATTRIBUTES32 *in,
                                                                            BOOL copy_attributes )
{
    ALPC_MESSAGE_ATTRIBUTES *attr;
    const unsigned char *current_from_attr;

    if (!in || !(attr = Wow64AllocateTemp( AlpcGetHeaderSize( in->AllocatedAttributes ) )))
    {
        *out = NULL;
        return NULL;
    }

    attr->AllocatedAttributes = in->AllocatedAttributes;

    if (!copy_attributes)
    {
        attr->ValidAttributes = 0;
        *out = attr;
        return attr;
    }

    attr->ValidAttributes = in->ValidAttributes;
    current_from_attr = (const unsigned char *)in + sizeof(*in);

    if (in->ValidAttributes & ALPC_MESSAGE_SECURITY_ATTRIBUTE)
    {
        const ALPC_SECURITY_ATTR32 *from_attr = (const ALPC_SECURITY_ATTR32 *)current_from_attr;
        ALPC_SECURITY_ATTR *to_attr = AlpcGetMessageAttribute( attr, ALPC_MESSAGE_SECURITY_ATTRIBUTE );

        to_attr->Flags = from_attr->Flags;
        to_attr->ContextHandle = UlongToHandle( from_attr->ContextHandle );
        if (from_attr->QoSPointer)
        {
            SECURITY_QUALITY_OF_SERVICE32 *qos32 = wow64_guest_memory_ptr( from_attr->QoSPointer );
            SECURITY_QUALITY_OF_SERVICE *qos = Wow64AllocateTemp( sizeof(*qos) );

            to_attr->QoS = qos;
            qos->Length = qos32->Length;
            qos->ImpersonationLevel = qos32->ImpersonationLevel;
            qos->ContextTrackingMode = qos32->ContextTrackingMode;
            qos->EffectiveOnly = qos32->EffectiveOnly;
        }
        else
        {
            to_attr->QoS = NULL;
        }
    }
    if (in->AllocatedAttributes & ALPC_MESSAGE_SECURITY_ATTRIBUTE)
        current_from_attr += sizeof(ALPC_SECURITY_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE)
    {
        const ALPC_VIEW_ATTR32 *from_attr = (const ALPC_VIEW_ATTR32 *)current_from_attr;
        ALPC_VIEW_ATTR *to_attr = AlpcGetMessageAttribute( attr, ALPC_MESSAGE_VIEW_ATTRIBUTE );

        to_attr->Flags = from_attr->Flags;
        to_attr->SectionHandle = UlongToHandle( from_attr->SectionHandle );
        to_attr->ViewBase = wow64_guest_memory_ptr( from_attr->ViewBase );
        to_attr->ViewSize = from_attr->ViewSize;
    }
    if (in->AllocatedAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE)
        current_from_attr += sizeof(ALPC_VIEW_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_CONTEXT_ATTRIBUTE)
    {
        const ALPC_CONTEXT_ATTR32 *from_attr = (const ALPC_CONTEXT_ATTR32 *)current_from_attr;
        ALPC_CONTEXT_ATTR *to_attr = AlpcGetMessageAttribute( attr, ALPC_MESSAGE_CONTEXT_ATTRIBUTE );

        alpc_context_attr_32to64( to_attr, from_attr );
    }
    if (in->AllocatedAttributes & ALPC_MESSAGE_CONTEXT_ATTRIBUTE)
        current_from_attr += sizeof(ALPC_CONTEXT_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_HANDLE_ATTRIBUTE)
    {
        const ALPC_HANDLE_ATTR32 *from_attr = (const ALPC_HANDLE_ATTR32 *)current_from_attr;
        ALPC_HANDLE_ATTR *to_attr = AlpcGetMessageAttribute( attr, ALPC_MESSAGE_HANDLE_ATTRIBUTE );

        to_attr->Flags = from_attr->Flags;
        to_attr->Handle = UlongToHandle( from_attr->Handle );
        to_attr->ObjectType = from_attr->ObjectType;
        to_attr->DesiredAccess = from_attr->DesiredAccess;
    }
    if (in->AllocatedAttributes & ALPC_MESSAGE_HANDLE_ATTRIBUTE)
        current_from_attr += sizeof(ALPC_HANDLE_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_TOKEN_ATTRIBUTE)
    {
        const ALPC_TOKEN_ATTR32 *from_attr = (const ALPC_TOKEN_ATTR32 *)current_from_attr;
        ALPC_TOKEN_ATTR *to_attr = AlpcGetMessageAttribute( attr, ALPC_MESSAGE_TOKEN_ATTRIBUTE );

        to_attr->TokenId = from_attr->TokenId;
        to_attr->AuthenticationId = from_attr->AuthenticationId;
        to_attr->ModifiedId = from_attr->ModifiedId;
    }
    if (in->AllocatedAttributes & ALPC_MESSAGE_TOKEN_ATTRIBUTE)
        current_from_attr += sizeof(ALPC_TOKEN_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_DIRECT_ATTRIBUTE)
    {
        const ALPC_DIRECT_ATTR32 *from_attr = (const ALPC_DIRECT_ATTR32 *)current_from_attr;
        ALPC_DIRECT_ATTR *to_attr = AlpcGetMessageAttribute( attr, ALPC_MESSAGE_DIRECT_ATTRIBUTE );

        to_attr->Event = UlongToHandle( from_attr->Event );
    }
    if (in->AllocatedAttributes & ALPC_MESSAGE_DIRECT_ATTRIBUTE)
        current_from_attr += sizeof(ALPC_DIRECT_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE)
    {
        const ALPC_WORK_ON_BEHALF_ATTR32 *from_attr = (const ALPC_WORK_ON_BEHALF_ATTR32 *)current_from_attr;
        ALPC_WORK_ON_BEHALF_ATTR *to_attr = AlpcGetMessageAttribute( attr, ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE );

        to_attr->Ticket = from_attr->Ticket;
    }

    *out = attr;
    return attr;
}

static inline ALPC_PORT_MESSAGE32 *alpc_port_message_64to32( ALPC_PORT_MESSAGE32 *out,
                                                             const ALPC_PORT_MESSAGE *in )
{
    if (!in) return NULL;

    out->DataLength = in->DataLength;
    out->TotalLength = sizeof(*out) + in->DataLength;
    out->Type = in->Type;
    out->DataInfoOffset = in->DataInfoOffset;
    out->ClientId.UniqueProcess = HandleToUlong( in->ClientId.UniqueProcess );
    out->ClientId.UniqueThread = HandleToUlong( in->ClientId.UniqueThread );
    out->MessageId = in->MessageId;
    out->ClientViewSize = in->ClientViewSize;
    memcpy( (unsigned char *)out + sizeof(*out), (const unsigned char *)in + sizeof(*in), in->DataLength );
    return out;
}

static inline ALPC_MESSAGE_ATTRIBUTES32 *alpc_port_message_attributes_64to32( ALPC_MESSAGE_ATTRIBUTES32 *out,
                                                                              ALPC_MESSAGE_ATTRIBUTES *in )
{
    unsigned char *current_to_attr;

    if (!in) return NULL;

    out->AllocatedAttributes = in->AllocatedAttributes;
    out->ValidAttributes = in->ValidAttributes;

    current_to_attr = (unsigned char *)out + sizeof(*out);

    if (in->ValidAttributes & ALPC_MESSAGE_SECURITY_ATTRIBUTE)
    {
        const ALPC_SECURITY_ATTR *from_attr = AlpcGetMessageAttribute( in, ALPC_MESSAGE_SECURITY_ATTRIBUTE );
        ALPC_SECURITY_ATTR32 *to_attr = (ALPC_SECURITY_ATTR32 *)current_to_attr;

        to_attr->Flags = from_attr->Flags;
        to_attr->ContextHandle = HandleToUlong( from_attr->ContextHandle );
        if (to_attr->QoSPointer && from_attr->QoS)
        {
            SECURITY_QUALITY_OF_SERVICE32 *qos32 = wow64_guest_memory_ptr( to_attr->QoSPointer );
            qos32->ImpersonationLevel = from_attr->QoS->ImpersonationLevel;
            qos32->ContextTrackingMode = from_attr->QoS->ContextTrackingMode;
            qos32->EffectiveOnly = from_attr->QoS->EffectiveOnly;
        }
    }
    if (out->AllocatedAttributes & ALPC_MESSAGE_SECURITY_ATTRIBUTE)
        current_to_attr += sizeof(ALPC_SECURITY_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE)
    {
        const ALPC_VIEW_ATTR *from_attr = AlpcGetMessageAttribute( in, ALPC_MESSAGE_VIEW_ATTRIBUTE );
        ALPC_VIEW_ATTR32 *to_attr = (ALPC_VIEW_ATTR32 *)current_to_attr;

        to_attr->Flags = from_attr->Flags;
        to_attr->SectionHandle = HandleToUlong( from_attr->SectionHandle );
        to_attr->ViewBase = wow64_guest_memory_addr( from_attr->ViewBase );
        to_attr->ViewSize = from_attr->ViewSize;
    }
    if (out->AllocatedAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE)
        current_to_attr += sizeof(ALPC_VIEW_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_CONTEXT_ATTRIBUTE)
    {
        const ALPC_CONTEXT_ATTR *from_attr = AlpcGetMessageAttribute( in, ALPC_MESSAGE_CONTEXT_ATTRIBUTE );
        ALPC_CONTEXT_ATTR32 *to_attr = (ALPC_CONTEXT_ATTR32 *)current_to_attr;

        to_attr->PortContext = PtrToUlong( from_attr->PortContext );
        to_attr->MessageContext = PtrToUlong( from_attr->MessageContext );
        to_attr->Sequence = from_attr->Sequence;
        /* Should be from_attr->MessageId. But tests show that it's always 0 on 32-bit */
        to_attr->MessageId = 0;
        to_attr->CallbackId = from_attr->CallbackId;
    }
    if (out->AllocatedAttributes & ALPC_MESSAGE_CONTEXT_ATTRIBUTE)
        current_to_attr += sizeof(ALPC_CONTEXT_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_HANDLE_ATTRIBUTE)
    {
        const ALPC_HANDLE_ATTR *from_attr = AlpcGetMessageAttribute( in, ALPC_MESSAGE_HANDLE_ATTRIBUTE );
        ALPC_HANDLE_ATTR32 *to_attr = (ALPC_HANDLE_ATTR32 *)current_to_attr;

        to_attr->Flags = from_attr->Flags;
        to_attr->Handle = HandleToUlong( from_attr->Handle );
        to_attr->ObjectType = from_attr->ObjectType;
        to_attr->DesiredAccess = from_attr->DesiredAccess;
    }
    if (out->AllocatedAttributes & ALPC_MESSAGE_HANDLE_ATTRIBUTE)
        current_to_attr += sizeof(ALPC_HANDLE_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_TOKEN_ATTRIBUTE)
    {
        const ALPC_TOKEN_ATTR *from_attr = AlpcGetMessageAttribute( in, ALPC_MESSAGE_TOKEN_ATTRIBUTE );
        ALPC_TOKEN_ATTR32 *to_attr = (ALPC_TOKEN_ATTR32 *)current_to_attr;

        to_attr->TokenId = from_attr->TokenId;
        to_attr->AuthenticationId = from_attr->AuthenticationId;
        to_attr->ModifiedId = from_attr->ModifiedId;
    }
    if (out->AllocatedAttributes & ALPC_MESSAGE_TOKEN_ATTRIBUTE)
        current_to_attr += sizeof(ALPC_TOKEN_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_DIRECT_ATTRIBUTE)
    {
        const ALPC_DIRECT_ATTR *from_attr = AlpcGetMessageAttribute( in, ALPC_MESSAGE_DIRECT_ATTRIBUTE );
        ALPC_DIRECT_ATTR32 *to_attr = (ALPC_DIRECT_ATTR32 *)current_to_attr;

        to_attr->Event = HandleToUlong( from_attr->Event );
    }
    if (out->AllocatedAttributes & ALPC_MESSAGE_DIRECT_ATTRIBUTE)
        current_to_attr += sizeof(ALPC_DIRECT_ATTR32);

    if (in->ValidAttributes & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE)
    {
        const ALPC_WORK_ON_BEHALF_ATTR *from_attr = AlpcGetMessageAttribute( in, ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE );
        ALPC_WORK_ON_BEHALF_ATTR32 *to_attr = (ALPC_WORK_ON_BEHALF_ATTR32 *)current_to_attr;

        to_attr->Ticket = from_attr->Ticket;
    }

    return out;
}

static inline TOKEN_USER *token_user_32to64( TOKEN_USER *out, const TOKEN_USER32 *in )
{
    TOKEN_USER32 local;
    wow64_read_user( &local, in, sizeof(local) );
    out->User.Sid = wow64_guest_memory_ptr( local.User.Sid );
    out->User.Attributes = local.User.Attributes;
    return out;
}

static inline TOKEN_OWNER *token_owner_32to64( TOKEN_OWNER *out, const TOKEN_OWNER32 *in )
{
    TOKEN_OWNER32 local;
    wow64_read_user( &local, in, sizeof(local) );
    out->Owner = wow64_guest_memory_ptr( local.Owner );
    return out;
}

static inline TOKEN_PRIMARY_GROUP *token_primary_group_32to64( TOKEN_PRIMARY_GROUP *out, const TOKEN_PRIMARY_GROUP32 *in )
{
    TOKEN_PRIMARY_GROUP32 local;
    wow64_read_user( &local, in, sizeof(local) );
    out->PrimaryGroup = wow64_guest_memory_ptr( local.PrimaryGroup );
    return out;
}

static inline TOKEN_DEFAULT_DACL *token_default_dacl_32to64( TOKEN_DEFAULT_DACL *out, const TOKEN_DEFAULT_DACL32 *in )
{
    TOKEN_DEFAULT_DACL32 local;
    wow64_read_user( &local, in, sizeof(local) );
    out->DefaultDacl = wow64_guest_memory_ptr( local.DefaultDacl );
    return out;
}

static inline void put_handle( ULONG *handle32, HANDLE handle )
{
    ULONG value = HandleToULong( handle );
    wow64_write_user( handle32, &value, sizeof(value) );
}

static inline NTSTATUS try_put_handle( ULONG *handle32, HANDLE handle )
{
    ULONG value = HandleToULong( handle );

    return wow64_try_write_user( handle32, &value, sizeof(value) );
}

static inline NTSTATUS try_put_handle_pair( ULONG *handle1, HANDLE value1,
                                             ULONG *handle2, HANDLE value2 )
{
    return wine_wow64_publish_handle_pair( handle1, HandleToULong(value1),
                                            handle2, HandleToULong(value2) );
}

static inline void put_addr( ULONG *addr32, void *addr )
{
    ULONG value;
    if (!addr32) return;
    value = wow64_guest_memory_addr( addr );
    wow64_write_user( addr32, &value, sizeof(value) );
}

static inline void put_size( ULONG *size32, SIZE_T size )
{
    ULONG value;
    if (!size32) return;
    value = min( size, MAXDWORD );
    wow64_write_user( size32, &value, sizeof(value) );
}

static inline void put_client_id( CLIENT_ID32 *id32, const CLIENT_ID *id )
{
    CLIENT_ID32 local;
    if (!id32) return;
    local.UniqueProcess = HandleToLong( id->UniqueProcess );
    local.UniqueThread = HandleToLong( id->UniqueThread );
    wow64_write_user( id32, &local, sizeof(local) );
}

static inline void put_iosb( IO_STATUS_BLOCK32 *io32, const IO_STATUS_BLOCK *io )
{
    /* sync I/O modifies the 64-bit iosb right away, so in that case we update the 32-bit one */
    /* async I/O leaves the 64-bit one untouched and updates the 32-bit one directly later on */
    if (io32 && io->Pointer != io32)
    {
        IO_STATUS_BLOCK32 local;
        local.Status = io->Status;
        local.Information = io->Information;
        wow64_write_user( io32, &local, sizeof(local) );
    }
}

extern void put_section_image_info( SECTION_IMAGE_INFORMATION32 *info32,
                                    const SECTION_IMAGE_INFORMATION *info );
extern void put_vm_counters( VM_COUNTERS_EX32 *info32, const VM_COUNTERS_EX *info,
                             ULONG size );

#endif /* __WOW64_PRIVATE_H */
