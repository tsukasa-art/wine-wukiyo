/*
 * XTAJIT64 fixed-low AMD64 executable regression
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "psapi.h"
#include "winternl.h"
#undef WIN32_NO_STATUS
#include "wine/exception.h"
#include "wine/low_va.h"

#define FIXED_LOW_IMAGE_BASE 0x00400000ull
#define FIXED_LOW_VALLOC_BASE 0x20000000ull
#define TEST_DATA_ALIGNMENT   0x1000u
#define FIXED_LOW_EXPORT_XOR  0xa5c31f27u
#define FIXED_LOW_EXPORT_ADD  0x013579bdu

__declspec(align(TEST_DATA_ALIGNMENT)) static volatile LONG fixed_low_data = 0x12345678;
__declspec(align(TEST_DATA_ALIGNMENT)) static unsigned int failures;
static volatile LONG spoof_thread_count;

#define check(condition, ...) \
    do { if (!(condition)) { fprintf( stderr, "not ok: " __VA_ARGS__ ); ++failures; } } while (0)

ULONG WINAPI fixed_low_export( ULONG value )
{
    return (value ^ FIXED_LOW_EXPORT_XOR) + FIXED_LOW_EXPORT_ADD;
}

struct code_buffer
{
    BYTE *data;
    SIZE_T offset;
};

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

static void emit_movabs( struct code_buffer *code, unsigned int rex,
                         unsigned int opcode, uint64_t value )
{
    emit_u8( code, rex );
    emit_u8( code, opcode );
    emit_u64( code, value );
}

static void patch_rel8( struct code_buffer *code, SIZE_T displacement,
                        SIZE_T target )
{
    INT_PTR value = target - displacement - 1;

    if (value < -128 || value > 127)
    {
        fprintf( stderr, "not ok: fixed-low stub branch is out of range\n" );
        ++failures;
        value = 0;
    }
    code->data[displacement] = value;
}

static BOOL query_translated_view( const void *address,
                                   WINE_TRANSLATED_VIEW_INFORMATION *info )
{
    SIZE_T result_size = 0;
    NTSTATUS status;

    memset( info, 0, sizeof(*info) );
    status = NtQueryVirtualMemory( GetCurrentProcess(), address,
                                   MemoryWineTranslatedViewInformation,
                                   info, sizeof(*info), &result_size );
    check( !status && result_size == sizeof(*info),
           "translated-view query for %p returned %#lx/%Iu\n",
           address, status, result_size );
    return !status && result_size == sizeof(*info);
}

static NTSTATUS query_translated_view_raw(
    const void *address, WINE_TRANSLATED_VIEW_INFORMATION *info,
    SIZE_T *result_size )
{
    memset( info, 0, sizeof(*info) );
    *result_size = 0;
    return NtQueryVirtualMemory( GetCurrentProcess(), address,
                                 MemoryWineTranslatedViewInformation,
                                 info, sizeof(*info), result_size );
}

static BOOL check_identity_view( const void *address, const char *name )
{
    WINE_TRANSLATED_VIEW_INFORMATION info;
    SIZE_T result_size;
    NTSTATUS status;
    BOOL valid;

    status = query_translated_view_raw( address, &info, &result_size );
    valid = !status && result_size == sizeof(info) &&
            info.Version == WINE_TRANSLATED_VIEW_INFORMATION_VERSION &&
            !info.Flags && !info.Reserved && info.GuestBase == info.HostBase &&
            (ULONG_PTR)address >= (ULONG_PTR)info.GuestBase &&
            (ULONG_PTR)address - (ULONG_PTR)info.GuestBase < info.RegionSize;
    check( valid,
           "%s identity query for %p returned %#lx/%Iu v%lu flags %#lx "
           "guest %p host %p allocation %p size %Iu\n", name, address,
           status, result_size, info.Version, info.Flags, info.GuestBase,
           info.HostBase, info.AllocationBase, info.RegionSize );
    return valid;
}

static BOOL protection_is_writable( ULONG protect )
{
    switch (protect & 0xff)
    {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

__declspec(noinline) static ULONG run_post_mutation_probe(ULONG value)
{
    return (value ^ 0x5a5aa5a5u) + 0x10203u;
}

static void test_process_contract(void)
{
    PROCESS_MACHINE_INFORMATION machine_info;
    char image[MAX_PATH], provider_image[MAX_PATH];
    HMODULE provider_module;
    DWORD length;
    BOOL ret;

    memset( &machine_info, 0, sizeof(machine_info) );
    ret = GetProcessInformation( GetCurrentProcess(), ProcessMachineTypeInfo,
                                 &machine_info, sizeof(machine_info) );
    check( ret && machine_info.ProcessMachine == IMAGE_FILE_MACHINE_AMD64,
           "process machine query returned %u/%#x, error %lu\n", ret,
           machine_info.ProcessMachine, GetLastError() );
    length = GetModuleFileNameA( NULL, image, ARRAY_SIZE(image) );
    check( length && length < ARRAY_SIZE(image),
           "process image query returned %lu, error %lu\n", length,
           GetLastError() );
    provider_module = GetModuleHandleA( "xtajit64.dll" );
    check( !!provider_module, "xtajit64.dll is not loaded, error %lu\n",
           GetLastError() );
    length = provider_module ? GetModuleFileNameA( provider_module,
                                                    provider_image,
                                                    ARRAY_SIZE(provider_image) ) : 0;
    check( length && length < ARRAY_SIZE(provider_image),
           "provider image query returned %lu, error %lu\n", length,
           GetLastError() );
    if (!failures)
    {
        printf( "XTAJIT64_FIXED_LOW_PROCESS pid=%lu image=\"%s\" "
                "process_machine=%#x\n", GetCurrentProcessId(), image,
                machine_info.ProcessMachine );
        printf( "XTAJIT64_FIXED_LOW_PROVIDER pid=%lu module=%p image=\"%s\"\n",
                GetCurrentProcessId(), provider_module, provider_image );
    }
}

static void test_public_module_contract(void)
{
    PEB *peb = NtCurrentTeb()->Peb;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)GetModuleHandleW( NULL );
    IMAGE_NT_HEADERS64 *nt;
    LDR_DATA_TABLE_ENTRY *main_entry = NULL, *found_entry = NULL;
    MODULEINFO module_info;
    void *pc_base = NULL, *pc_result;
    NTSTATUS status;
    BOOL ret;

    check( peb && peb->ImageBaseAddress == (HMODULE)dos &&
           (ULONG_PTR)dos == FIXED_LOW_IMAGE_BASE,
           "public main bases disagree PEB %p GetModuleHandle %p\n",
           peb ? peb->ImageBaseAddress : NULL, dos );
    if (!peb || peb->ImageBaseAddress != (HMODULE)dos ||
        (ULONG_PTR)dos != FIXED_LOW_IMAGE_BASE)
        return;

    nt = (IMAGE_NT_HEADERS64 *)RtlImageNtHeader( (HMODULE)dos );
    check( !!nt && nt->Signature == IMAGE_NT_SIGNATURE,
           "public main header lookup returned %p\n", nt );
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return;

    check( peb->LdrData && peb->LdrData->Initialized &&
           peb->LdrData->InLoadOrderModuleList.Flink !=
               &peb->LdrData->InLoadOrderModuleList,
           "public loader list is unavailable %p/%u\n", peb->LdrData,
           peb->LdrData ? peb->LdrData->Initialized : 0 );
    if (!peb->LdrData || !peb->LdrData->Initialized ||
        peb->LdrData->InLoadOrderModuleList.Flink ==
            &peb->LdrData->InLoadOrderModuleList)
        return;
    main_entry = CONTAINING_RECORD( peb->LdrData->InLoadOrderModuleList.Flink,
                                    LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
    check( main_entry->DllBase == dos &&
           main_entry->EntryPoint ==
               (BYTE *)dos + nt->OptionalHeader.AddressOfEntryPoint &&
           main_entry->SizeOfImage == nt->OptionalHeader.SizeOfImage,
           "public loader main base %p entry %p size %#lx expected %p/%p/%#lx\n",
           main_entry->DllBase, main_entry->EntryPoint, main_entry->SizeOfImage,
           dos, (BYTE *)dos + nt->OptionalHeader.AddressOfEntryPoint,
           nt->OptionalHeader.SizeOfImage );

    status = LdrFindEntryForAddress( (const void *)test_public_module_contract,
                                     &found_entry );
    check( !status && found_entry == main_entry && found_entry->DllBase == dos,
           "LdrFindEntryForAddress returned %#lx/%p base %p expected %p/%p\n",
           status, found_entry, found_entry ? found_entry->DllBase : NULL,
           main_entry, dos );

    pc_result = RtlPcToFileHeader( (void *)test_public_module_contract,
                                  &pc_base );
    check( pc_result == dos && pc_base == dos,
           "RtlPcToFileHeader returned %p/%p expected %p\n",
           pc_result, pc_base, dos );

    memset( &module_info, 0, sizeof(module_info) );
    ret = GetModuleInformation( GetCurrentProcess(), (HMODULE)dos, &module_info,
                                sizeof(module_info) );
    check( ret && module_info.lpBaseOfDll == dos &&
           module_info.EntryPoint ==
               (BYTE *)dos + nt->OptionalHeader.AddressOfEntryPoint &&
           module_info.SizeOfImage == nt->OptionalHeader.SizeOfImage,
           "PSAPI main info returned %u error %lu base %p entry %p size %#lx\n",
           ret, GetLastError(), module_info.lpBaseOfDll, module_info.EntryPoint,
           module_info.SizeOfImage );

    if (!failures)
        printf( "XTAJIT64_FIXED_LOW_PUBLIC_MODULE peb=%p ldr=%p entry=%p "
                "pc_base=%p psapi=%p size=%#lx\n", peb->ImageBaseAddress,
                main_entry->DllBase, main_entry->EntryPoint, pc_base,
                module_info.lpBaseOfDll, module_info.SizeOfImage );
}

typedef ULONG (WINAPI *fixed_low_import_call_func)(ULONG);
typedef const void *(WINAPI *fixed_low_import_target_func)(void);

struct module_name
{
    WCHAR buffer[1024];
    UNICODE_STRING string;
};

struct peb_spoof_scope
{
    PEB *peb;
    HMODULE original;
    HANDLE thread;
};

static NTSTATUS get_full_module_name( HMODULE module, struct module_name *name )
{
    name->buffer[0] = 0;
    name->string.Buffer = name->buffer;
    name->string.Length = 0;
    name->string.MaximumLength = sizeof(name->buffer);
    return LdrGetDllFullName( module, &name->string );
}

static BOOL equal_module_name( const struct module_name *left,
                               const struct module_name *right )
{
    return RtlEqualUnicodeString( &left->string, &right->string, FALSE );
}

static DWORD WINAPI peb_spoof_thread_proc( void *arg )
{
    ULONG value = PtrToUlong( arg );

    InterlockedIncrement( &spoof_thread_count );
    return fixed_low_export( value );
}

static void run_peb_spoof_thread( struct peb_spoof_scope *scope,
                                  ULONG value, const char *name )
{
    DWORD exit_code = STILL_ACTIVE, wait;
    BOOL ret;

    scope->thread = CreateThread( NULL, 0, peb_spoof_thread_proc,
                                  UlongToPtr(value), 0, NULL );
    check( !!scope->thread, "%s spoof thread creation failed, error %lu\n",
           name, GetLastError() );
    if (!scope->thread) return;

    wait = WaitForSingleObject( scope->thread, 10000 );
    check( wait == WAIT_OBJECT_0,
           "%s spoof thread wait returned %#lx, error %lu\n",
           name, wait, GetLastError() );
    if (wait == WAIT_OBJECT_0)
    {
        ret = GetExitCodeThread( scope->thread, &exit_code );
        check( ret && exit_code == fixed_low_export( value ),
               "%s spoof thread exit returned %u/%#lx, expected %#lx\n",
               name, ret, exit_code, fixed_low_export( value ) );
    }
    ret = CloseHandle( scope->thread );
    check( ret, "%s spoof thread close failed, error %lu\n",
           name, GetLastError() );
    scope->thread = NULL;
}

static void CALLBACK restore_peb_image_base( BOOL normal, void *context )
{
    struct peb_spoof_scope *scope = context;

    (void)normal;
    InterlockedExchangePointer( (void *volatile *)&scope->peb->ImageBaseAddress,
                                scope->original );
    if (scope->thread)
    {
        WaitForSingleObject( scope->thread, 5000 );
        CloseHandle( scope->thread );
        scope->thread = NULL;
    }
}

static void check_main_lookups_while_spoofed(
    HMODULE main, const struct module_name *expected_name,
    const char *case_name, struct peb_spoof_scope *scope, ULONG thread_value )
{
    ANSI_STRING export_name = RTL_CONSTANT_STRING( "fixed_low_export" );
    struct module_name explicit_name, implicit_name;
    LDR_DATA_TABLE_ENTRY *entry = NULL;
    IMAGE_NT_HEADERS64 *nt;
    WCHAR filename[1024];
    void *address = NULL, *pc_base = NULL, *pc_result;
    void *exports, *rtl_export;
    DWORD length;
    ULONG export_size = 0;
    NTSTATUS status;

    nt = (IMAGE_NT_HEADERS64 *)RtlImageNtHeader( main );
    check( !!nt && nt->Signature == IMAGE_NT_SIGNATURE,
           "%s spoof canonical RtlImageNtHeader returned %p\n", case_name, nt );

    exports = RtlImageDirectoryEntryToData( main, TRUE,
                                            IMAGE_DIRECTORY_ENTRY_EXPORT,
                                            &export_size );
    check( !!exports && export_size >= sizeof(IMAGE_EXPORT_DIRECTORY) &&
           (ULONG_PTR)exports >= (ULONG_PTR)main && nt &&
           (ULONG_PTR)exports - (ULONG_PTR)main <
               nt->OptionalHeader.SizeOfImage,
           "%s spoof canonical export directory returned %p/%#lx\n",
           case_name, exports, export_size );

    rtl_export = RtlFindExportedRoutineByName( main, "fixed_low_export" );
    check( rtl_export == (void *)fixed_low_export,
           "%s spoof canonical RtlFindExportedRoutineByName returned %p, "
           "expected %p\n", case_name, rtl_export, fixed_low_export );

    status = LdrGetProcedureAddress( main, &export_name, 0, &address );
    check( !status && address == (void *)fixed_low_export,
           "%s spoof canonical LdrGetProcedureAddress returned %#lx/%p, "
           "expected %p\n", case_name, status, address, fixed_low_export );
    check( GetProcAddress( main, "fixed_low_export" ) ==
               (FARPROC)fixed_low_export,
           "%s spoof canonical GetProcAddress failed, error %lu\n",
           case_name, GetLastError() );

    status = get_full_module_name( main, &explicit_name );
    check( !status && equal_module_name( &explicit_name, expected_name ),
           "%s spoof explicit main name returned %#lx length %u, expected %u\n",
           case_name, status, explicit_name.string.Length,
           expected_name->string.Length );
    status = get_full_module_name( NULL, &implicit_name );
    check( !status && equal_module_name( &implicit_name, expected_name ),
           "%s spoof implicit main name returned %#lx length %u, expected %u\n",
           case_name, status, implicit_name.string.Length,
           expected_name->string.Length );

    length = GetModuleFileNameW( NULL, filename, ARRAY_SIZE(filename) );
    check( length == expected_name->string.Length / sizeof(WCHAR) &&
           !memcmp( filename, expected_name->string.Buffer,
                    expected_name->string.Length ),
           "%s spoof GetModuleFileNameW(NULL) returned %lu, error %lu\n",
           case_name, length, GetLastError() );

    status = LdrFindEntryForAddress( (const void *)fixed_low_export, &entry );
    check( !status && entry && entry->DllBase == main,
           "%s spoof canonical LdrFindEntryForAddress returned %#lx/%p base %p\n",
           case_name, status, entry, entry ? entry->DllBase : NULL );
    pc_result = RtlPcToFileHeader( (void *)fixed_low_export, &pc_base );
    check( pc_result == main && pc_base == main,
           "%s spoof canonical RtlPcToFileHeader returned %p/%p\n",
           case_name, pc_result, pc_base );

    run_peb_spoof_thread( scope, thread_value, case_name );
}

static void test_main_export_import(void)
{
    const ULONG input = 0x6d3a91c7;
    fixed_low_import_call_func import_call;
    fixed_low_import_target_func import_target;
    WINE_TRANSLATED_VIEW_INFORMATION info;
    IMAGE_NT_HEADERS64 *nt;
    HMODULE main = GetModuleHandleW( NULL );
    HMODULE companion;
    FARPROC dynamic_export;
    const void *iat_target = NULL;
    ULONG result = 0;

    dynamic_export = GetProcAddress( main, "fixed_low_export" );
    check( dynamic_export == (FARPROC)fixed_low_export,
           "fixed-low main export returned %p, expected %p, error %lu\n",
           dynamic_export, fixed_low_export, GetLastError() );
    nt = (IMAGE_NT_HEADERS64 *)RtlImageNtHeader( main );
    check( !!nt && nt->Signature == IMAGE_NT_SIGNATURE,
           "fixed-low exported main header returned %p\n", nt );

    companion = LoadLibraryA( "fixed_low_import.dll" );
    check( !!companion, "loading fixed-low import companion failed, error %lu\n",
           GetLastError() );
    if (!companion) return;

    import_call = (fixed_low_import_call_func)GetProcAddress(
        companion, "fixed_low_import_call" );
    import_target = (fixed_low_import_target_func)GetProcAddress(
        companion, "fixed_low_import_target" );
    check( !!import_call && !!import_target,
           "fixed-low companion exports returned %p/%p, error %lu\n",
           import_call, import_target, GetLastError() );
    if (import_target) iat_target = import_target();
    if (import_call) result = import_call( input );
    check( iat_target == (const void *)fixed_low_export &&
           iat_target == (const void *)dynamic_export && nt &&
           (ULONG_PTR)iat_target >= (ULONG_PTR)main &&
           (ULONG_PTR)iat_target - (ULONG_PTR)main <
               nt->OptionalHeader.SizeOfImage,
           "fixed-low companion IAT target %p differs from canonical export %p\n",
           iat_target, fixed_low_export );
    check( result == fixed_low_export( input ),
           "fixed-low companion call returned %#lx, expected %#lx\n",
           result, fixed_low_export( input ) );
    if (iat_target && query_translated_view( iat_target, &info ))
        check( info.Flags == WINE_TRANSLATED_VIEW_AMD64_LOW &&
               (ULONG_PTR)info.HostBase ==
                   WINE_LOW_VA_SHADOW_BASE + (ULONG_PTR)info.GuestBase,
               "fixed-low imported target provenance flags %#lx guest %p host %p\n",
               info.Flags, info.GuestBase, info.HostBase );

    check( FreeLibrary( companion ),
           "unloading fixed-low import companion failed, error %lu\n",
           GetLastError() );
    printf( "XTAJIT64_FIXED_LOW_MAIN_IMPORT main=%p dynamic=%p iat=%p "
            "result=%#lx\n", main, dynamic_export, iat_target, result );
}

static void test_peb_image_base_spoof(void)
{
    ANSI_STRING export_name = RTL_CONSTANT_STRING( "fixed_low_export" );
    ANSI_STRING ntdll_export_name = RTL_CONSTANT_STRING( "NtClose" );
    struct module_name main_name, ntdll_name, result_name;
    PEB *peb = NtCurrentTeb()->Peb;
    HMODULE main = GetModuleHandleW( NULL );
    HMODULE ntdll = GetModuleHandleW( L"ntdll.dll" );
    HMODULE private_main;
    WINE_TRANSLATED_VIEW_INFORMATION info;
    struct peb_spoof_scope scope;
    LDR_DATA_TABLE_ENTRY *entry = NULL;
    FARPROC ntdll_export;
    void *address, *pc_base, *pc_result;
    ULONG directory_size;
    DWORD exception, length;
    WCHAR filename[1024];
    NTSTATUS status;

    check( peb && main == (HMODULE)(ULONG_PTR)FIXED_LOW_IMAGE_BASE,
           "PEB spoof setup has invalid PEB/main %p/%p\n", peb, main );
    check( !!ntdll && ntdll != main,
           "PEB spoof setup has invalid ntdll module %p\n", ntdll );
    status = get_full_module_name( main, &main_name );
    check( !status, "PEB spoof main name setup returned %#lx\n", status );
    status = get_full_module_name( ntdll, &ntdll_name );
    check( !status, "PEB spoof ntdll name setup returned %#lx\n", status );
    ntdll_export = GetProcAddress( ntdll, "NtClose" );
    check( !!ntdll_export, "PEB spoof NtClose setup failed, error %lu\n",
           GetLastError() );
    if (!peb || !main || !ntdll || !ntdll_export ||
        !query_translated_view( (const void *)fixed_low_export, &info ))
        return;

    check( info.Flags == WINE_TRANSLATED_VIEW_AMD64_LOW &&
           (ULONG_PTR)info.HostBase >= (ULONG_PTR)info.GuestBase,
           "PEB spoof export provenance flags %#lx guest %p host %p\n",
           info.Flags, info.GuestBase, info.HostBase );
    if (info.Flags != WINE_TRANSLATED_VIEW_AMD64_LOW ||
        (ULONG_PTR)info.HostBase < (ULONG_PTR)info.GuestBase)
        return;
    private_main = (HMODULE)((ULONG_PTR)info.HostBase -
                             (ULONG_PTR)info.GuestBase +
                             (ULONG_PTR)main);
    check( private_main != main &&
           (ULONG_PTR)private_main ==
               WINE_LOW_VA_SHADOW_BASE + (ULONG_PTR)main,
           "PEB spoof derived private main %p from guest/host %p/%p\n",
           private_main, info.GuestBase, info.HostBase );
    if (private_main == main) return;

    memset( &scope, 0, sizeof(scope) );
    scope.peb = peb;
    scope.original = main;
    exception = 0;
    __TRY
    {
        __TRY
        {
            void *previous = InterlockedExchangePointer(
                (void *volatile *)&peb->ImageBaseAddress, private_main );

            check( previous == main && peb->ImageBaseAddress == private_main,
                   "private spoof exchange returned %p/%p, expected %p/%p\n",
                   previous, peb->ImageBaseAddress, main, private_main );
            check_main_lookups_while_spoofed( main, &main_name, "private",
                                              &scope, 0x19a72c4e );

            address = (void *)0xdeadbeef;
            status = LdrGetProcedureAddress( private_main, &export_name, 0,
                                             &address );
            check( status == STATUS_DLL_NOT_FOUND,
                   "private spoof LdrGetProcedureAddress returned %#lx/%p\n",
                   status, address );
            check( !GetProcAddress( private_main, "fixed_low_export" ),
                   "private spoof GetProcAddress exposed the backing\n" );
            check( !RtlFindExportedRoutineByName( private_main,
                                                  "fixed_low_export" ),
                   "private spoof RtlFindExportedRoutineByName exposed the backing\n" );
            check( !RtlImageNtHeader( private_main ),
                   "private spoof RtlImageNtHeader exposed the backing\n" );
            directory_size = 0;
            check( !RtlImageDirectoryEntryToData(
                       private_main, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT,
                       &directory_size ),
                   "private spoof RtlImageDirectoryEntryToData exposed the backing\n" );
            status = get_full_module_name( private_main, &result_name );
            check( status == STATUS_DLL_NOT_FOUND,
                   "private spoof LdrGetDllFullName returned %#lx length %u\n",
                   status, result_name.string.Length );
            length = GetModuleFileNameW( private_main, filename,
                                         ARRAY_SIZE(filename) );
            check( !length,
                   "private spoof GetModuleFileNameW returned %lu, error %lu\n",
                   length, GetLastError() );
            status = LdrFindEntryForAddress(
                (const void *)((ULONG_PTR)private_main +
                    ((ULONG_PTR)fixed_low_export - (ULONG_PTR)main)), &entry );
            check( status == STATUS_NO_MORE_ENTRIES,
                   "private spoof LdrFindEntryForAddress returned %#lx/%p\n",
                   status, entry );
            pc_base = (void *)0xdeadbeef;
            pc_result = RtlPcToFileHeader(
                (void *)((ULONG_PTR)private_main +
                    ((ULONG_PTR)fixed_low_export - (ULONG_PTR)main)), &pc_base );
            check( !pc_result && !pc_base,
                   "private spoof RtlPcToFileHeader returned %p/%p\n",
                   pc_result, pc_base );
        }
        __FINALLY_CTX( restore_peb_image_base, &scope )
    }
    __EXCEPT_ALL
    {
        exception = GetExceptionCode();
    }
    __ENDTRY
    check( !exception, "private PEB spoof raised exception %#lx\n", exception );
    check( peb->ImageBaseAddress == main,
           "private PEB spoof restored %p, expected %p\n",
           peb->ImageBaseAddress, main );
    printf( "XTAJIT64_FIXED_LOW_PEB_PRIVATE canonical=%p private=%p "
            "thread_count=%ld exception=%#lx\n", main, private_main,
            spoof_thread_count, exception );

    memset( &scope, 0, sizeof(scope) );
    scope.peb = peb;
    scope.original = main;
    exception = 0;
    __TRY
    {
        __TRY
        {
            void *previous = InterlockedExchangePointer(
                (void *volatile *)&peb->ImageBaseAddress, ntdll );

            check( previous == main && peb->ImageBaseAddress == ntdll,
                   "module spoof exchange returned %p/%p, expected %p/%p\n",
                   previous, peb->ImageBaseAddress, main, ntdll );
            check_main_lookups_while_spoofed( main, &main_name, "module",
                                              &scope, 0xb62041d3 );

            status = get_full_module_name( ntdll, &result_name );
            check( !status && equal_module_name( &result_name, &ntdll_name ),
                   "module spoof ntdll name returned %#lx length %u, expected %u\n",
                   status, result_name.string.Length,
                   ntdll_name.string.Length );
            address = NULL;
            status = LdrGetProcedureAddress( ntdll, &ntdll_export_name, 0,
                                             &address );
            check( !status && address == (void *)ntdll_export,
                   "module spoof ntdll LdrGetProcedureAddress returned %#lx/%p, "
                   "expected %p\n", status, address, ntdll_export );
            check( GetProcAddress( ntdll, "NtClose" ) == ntdll_export,
                   "module spoof ntdll GetProcAddress failed, error %lu\n",
                   GetLastError() );
            check( RtlFindExportedRoutineByName( ntdll, "NtClose" ) ==
                       (void *)ntdll_export,
                   "module spoof ntdll RtlFindExportedRoutineByName failed\n" );
            status = LdrFindEntryForAddress( (const void *)ntdll_export, &entry );
            check( !status && entry && entry->DllBase == ntdll,
                   "module spoof ntdll LdrFindEntryForAddress returned %#lx/%p "
                   "base %p\n", status, entry,
                   entry ? entry->DllBase : NULL );
            pc_base = NULL;
            pc_result = RtlPcToFileHeader( (void *)ntdll_export, &pc_base );
            check( pc_result == ntdll && pc_base == ntdll,
                   "module spoof ntdll RtlPcToFileHeader returned %p/%p\n",
                   pc_result, pc_base );
        }
        __FINALLY_CTX( restore_peb_image_base, &scope )
    }
    __EXCEPT_ALL
    {
        exception = GetExceptionCode();
    }
    __ENDTRY
    check( !exception, "module PEB spoof raised exception %#lx\n", exception );
    check( peb->ImageBaseAddress == main,
           "module PEB spoof restored %p, expected %p\n",
           peb->ImageBaseAddress, main );
    check( spoof_thread_count == 2,
           "PEB spoof threads completed %ld times, expected 2\n",
           spoof_thread_count );
    printf( "XTAJIT64_FIXED_LOW_PEB_MODULE canonical=%p spoof=%p export=%p "
            "thread_count=%ld exception=%#lx\n", main, ntdll, ntdll_export,
            spoof_thread_count, exception );
}

static void test_fixed_low_main(void)
{
    WINE_TRANSLATED_VIEW_INFORMATION info, restored_info;
    MEMORY_BASIC_INFORMATION basic_info, restored_basic;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)GetModuleHandleW( NULL );
    IMAGE_NT_HEADERS64 *nt;
    void *page;
    SIZE_T size;
    SIZE_T translated_size = 0, basic_size = 0;
    SIZE_T restored_translated_size = 0, restored_basic_size = 0;
    ULONG old_protect = 0, restore_previous = 0;
    NTSTATUS status, translated_status, basic_status, restore_status;
    NTSTATUS restored_translated_status = STATUS_UNSUCCESSFUL;
    NTSTATUS restored_basic_status = STATUS_UNSUCCESSFUL;
    LONG original_data, written_data;
    BOOL readonly_flush = FALSE;
    DWORD readonly_flush_error = ERROR_SUCCESS;
    ULONG probe;

    memset( &restored_info, 0, sizeof(restored_info) );
    memset( &restored_basic, 0, sizeof(restored_basic) );

    check( (ULONG_PTR)dos == FIXED_LOW_IMAGE_BASE,
           "fixed-low image loaded at %p, expected %#llx\n", dos,
           (unsigned long long)FIXED_LOW_IMAGE_BASE );
    if ((ULONG_PTR)dos != FIXED_LOW_IMAGE_BASE) return;
    nt = (IMAGE_NT_HEADERS64 *)((BYTE *)dos + dos->e_lfanew);
    check( nt->Signature == IMAGE_NT_SIGNATURE &&
           nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
           (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) &&
           !(nt->FileHeader.Characteristics & IMAGE_FILE_DLL),
           "fixed-low image header machine %#x characteristics %#x\n",
           nt->FileHeader.Machine, nt->FileHeader.Characteristics );

    if (query_translated_view( (const void *)&fixed_low_data, &info ))
    {
        check( info.Version == WINE_TRANSLATED_VIEW_INFORMATION_VERSION &&
               info.Flags == WINE_TRANSLATED_VIEW_AMD64_LOW &&
               info.AllocationBase == dos &&
               (ULONG_PTR)info.HostBase ==
                   WINE_LOW_VA_SHADOW_BASE + (ULONG_PTR)info.GuestBase &&
               (ULONG_PTR)&fixed_low_data >= (ULONG_PTR)info.GuestBase &&
               (ULONG_PTR)&fixed_low_data - (ULONG_PTR)info.GuestBase <
                   info.RegionSize,
               "main translated view v%lu flags %#lx guest %p host %p alloc %p size %Iu\n",
               info.Version, info.Flags, info.GuestBase, info.HostBase,
               info.AllocationBase, info.RegionSize );
        printf( "XTAJIT64_FIXED_LOW_MAIN flags=%#lx guest=%p host=%p allocation=%p "
                "protect=%#lx image_size=%#lx\n", info.Flags, info.GuestBase,
                info.HostBase, info.AllocationBase, info.Protect,
                nt->OptionalHeader.SizeOfImage );
    }

    page = (void *)((ULONG_PTR)&fixed_low_data & ~(ULONG_PTR)0xfff);
    size = 0x1000;
    status = NtProtectVirtualMemory( GetCurrentProcess(), &page, &size,
                                     PAGE_READONLY, &old_protect );
    check( !status, "fixed-low protect returned %#lx\n", status );
    if (!status)
    {
        translated_status = query_translated_view_raw(
            (const void *)&fixed_low_data, &info, &translated_size );
        memset( &basic_info, 0, sizeof(basic_info) );
        basic_size = 0;
        basic_status = NtQueryVirtualMemory( GetCurrentProcess(),
                                             (const void *)&fixed_low_data,
                                             MemoryBasicInformation,
                                             &basic_info, sizeof(basic_info),
                                             &basic_size );
        readonly_flush = FlushInstructionCache( GetCurrentProcess(),
                                                 (const void *)&fixed_low_data,
                                                 sizeof(fixed_low_data) );
        if (!readonly_flush) readonly_flush_error = GetLastError();
        page = (void *)((ULONG_PTR)&fixed_low_data & ~(ULONG_PTR)0xfff);
        size = 0x1000;
        restore_status = NtProtectVirtualMemory( GetCurrentProcess(), &page,
                                                 &size, old_protect,
                                                 &restore_previous );
        check( !restore_status,
               "restoring fixed-low protection returned %#lx\n",
               restore_status );
        if (!restore_status)
        {
            restored_translated_status = query_translated_view_raw(
                (const void *)&fixed_low_data, &restored_info,
                &restored_translated_size );
            memset( &restored_basic, 0, sizeof(restored_basic) );
            restored_basic_status = NtQueryVirtualMemory(
                GetCurrentProcess(), (const void *)&fixed_low_data,
                MemoryBasicInformation, &restored_basic,
                sizeof(restored_basic), &restored_basic_size );
        }
        check( !translated_status && translated_size == sizeof(info),
               "protected translated query returned %#lx/%Iu\n",
               translated_status, translated_size );
        check( info.Flags == WINE_TRANSLATED_VIEW_AMD64_LOW &&
               (info.Protect & 0xff) == PAGE_READONLY,
               "protected LOW query flags/protect %#lx/%#lx\n",
               info.Flags, info.Protect );
        check( !basic_status && basic_size == sizeof(basic_info),
               "protected basic query returned %#lx/%Iu\n",
               basic_status, basic_size );
        check( basic_info.State == MEM_COMMIT &&
               basic_info.AllocationBase == dos &&
               (ULONG_PTR)basic_info.BaseAddress < WINE_LOW_VA_SHADOW_SIZE &&
               (ULONG_PTR)&fixed_low_data >= (ULONG_PTR)basic_info.BaseAddress &&
               (ULONG_PTR)&fixed_low_data - (ULONG_PTR)basic_info.BaseAddress <
                   basic_info.RegionSize &&
               (basic_info.Protect & 0xff) == PAGE_READONLY,
               "protected basic query base %p allocation %p size %Iu state %#lx "
               "protect %#lx\n", basic_info.BaseAddress,
               basic_info.AllocationBase, basic_info.RegionSize,
               basic_info.State, basic_info.Protect );
        check( readonly_flush,
               "read-only LOW cache flush failed, error %lu\n",
               readonly_flush_error );
        check( !restored_translated_status &&
               restored_translated_size == sizeof(restored_info) &&
               restored_info.Version == WINE_TRANSLATED_VIEW_INFORMATION_VERSION &&
               restored_info.Flags == WINE_TRANSLATED_VIEW_AMD64_LOW &&
               restored_info.AllocationBase == dos &&
               (ULONG_PTR)restored_info.HostBase == WINE_LOW_VA_SHADOW_BASE +
                   (ULONG_PTR)restored_info.GuestBase &&
               (ULONG_PTR)&fixed_low_data >=
                   (ULONG_PTR)restored_info.GuestBase &&
               (ULONG_PTR)&fixed_low_data -
                   (ULONG_PTR)restored_info.GuestBase < restored_info.RegionSize &&
               (restored_info.Protect & 0xff) == (old_protect & 0xff),
               "restored LOW query returned %#lx/%Iu flags %#lx allocation %p "
               "protect %#lx expected %#lx\n", restored_translated_status,
               restored_translated_size, restored_info.Flags,
               restored_info.AllocationBase, restored_info.Protect, old_protect );
        check( !restored_basic_status &&
               restored_basic_size == sizeof(restored_basic) &&
               restored_basic.State == MEM_COMMIT &&
               restored_basic.AllocationBase == dos &&
               (ULONG_PTR)&fixed_low_data >=
                   (ULONG_PTR)restored_basic.BaseAddress &&
               (ULONG_PTR)&fixed_low_data -
                   (ULONG_PTR)restored_basic.BaseAddress <
                   restored_basic.RegionSize &&
               (restored_basic.Protect & 0xff) == (old_protect & 0xff),
               "restored basic query returned %#lx/%Iu allocation %p state %#lx "
               "protect %#lx expected %#lx\n", restored_basic_status,
               restored_basic_size, restored_basic.AllocationBase,
               restored_basic.State, restored_basic.Protect, old_protect );
        if (!restore_status)
        {
            check( (restore_previous & 0xff) == PAGE_READONLY,
                   "fixed-low restore replaced unexpected protection %#lx\n",
                   restore_previous );
            check( protection_is_writable( old_protect ),
                   "fixed-low data page originally nonwritable %#lx\n",
                   old_protect );
            if (protection_is_writable( old_protect ))
            {
                original_data = fixed_low_data;
                fixed_low_data = original_data ^ 0x55aa33cc;
                written_data = fixed_low_data;
                fixed_low_data = original_data;
                check( written_data == (original_data ^ 0x55aa33cc) &&
                       fixed_low_data == original_data,
                       "restored LOW page was not writable %#lx/%#lx\n",
                       (ULONG)written_data, (ULONG)fixed_low_data );
            }
        }
        printf( "XTAJIT64_FIXED_LOW_PROTECT status=%#lx old=%#lx protect=%#lx "
                "basic_base=%p basic_allocation=%p basic_size=%Iu flush=%u\n",
                status, old_protect, info.Protect, basic_info.BaseAddress,
                basic_info.AllocationBase, basic_info.RegionSize,
                readonly_flush );
        printf( "XTAJIT64_FIXED_LOW_PROTECT_RESTORE status=%#lx previous=%#lx "
                "protect=%#lx writable=%u\n", restore_status,
                restore_previous, restored_info.Protect,
                protection_is_writable( restored_info.Protect ) );
    }

    page = (BYTE *)dos + nt->OptionalHeader.SizeOfImage - 0x1000;
    size = 0x2000;
    status = NtProtectVirtualMemory( GetCurrentProcess(), &page, &size,
                                     PAGE_READONLY, &old_protect );
    check( !NT_SUCCESS(status),
           "cross-boundary fixed-low protect unexpectedly returned %#lx\n", status );
    probe = run_post_mutation_probe( 0x13572468 );
    check( probe == ((0x13572468u ^ 0x5a5aa5a5u) + 0x10203u),
           "post-failure x64 probe returned %#lx\n", probe );
    printf( "XTAJIT64_FIXED_LOW_FAILED_PROTECT status=%#lx\n", status );
    printf( "XTAJIT64_FIXED_LOW_RESUME probe=%#lx\n", probe );
}

static void test_execute_only_low_read(void)
{
    WINE_TRANSLATED_VIEW_INFORMATION info;
    LONG expected = fixed_low_data;
    void *page = (void *)((ULONG_PTR)&fixed_low_data & ~(ULONG_PTR)0xfff);
    SIZE_T size = 0x1000, result_size = 0, matched = 0;
    ULONG old_protect = 0, restore_previous = 0;
    NTSTATUS status, query_status, restore_status;

    check( ((ULONG_PTR)&fixed_low_data & ~(ULONG_PTR)0xfff) !=
           ((ULONG_PTR)&failures & ~(ULONG_PTR)0xfff),
           "execute-only LOW data unexpectedly shares the failure-state page\n" );
    if (failures) return;

    status = NtProtectVirtualMemory( GetCurrentProcess(), &page, &size,
                                     PAGE_EXECUTE, &old_protect );
    check( !status, "execute-only LOW protect returned %#lx\n", status );
    if (status) return;

    query_status = query_translated_view_raw(
        (const void *)(ULONG_PTR)&fixed_low_data, &info, &result_size );
    matched = RtlCompareMemory( (const void *)&fixed_low_data, &expected,
                                sizeof(expected) );
    page = (void *)((ULONG_PTR)&fixed_low_data & ~(ULONG_PTR)0xfff);
    size = 0x1000;
    restore_status = NtProtectVirtualMemory( GetCurrentProcess(), &page, &size,
                                             old_protect, &restore_previous );
    check( !restore_status,
           "restoring execute-only LOW protection returned %#lx\n",
           restore_status );
    check( !query_status && result_size == sizeof(info) &&
           info.Version == WINE_TRANSLATED_VIEW_INFORMATION_VERSION &&
           info.Flags == WINE_TRANSLATED_VIEW_AMD64_LOW &&
           (info.Protect & 0xff) == PAGE_EXECUTE,
           "execute-only LOW query returned %#lx/%Iu flags %#lx protect %#lx\n",
           query_status, result_size, info.Flags, info.Protect );
    check( matched == sizeof(expected),
           "native RtlCompareMemory read %Iu/%Iu execute-only LOW bytes\n",
           matched, sizeof(expected) );
    check( !restore_status && (restore_previous & 0xff) == PAGE_EXECUTE,
           "execute-only LOW restore replaced protection %#lx/%#lx\n",
           restore_status, restore_previous );
    if (!failures)
        printf( "XTAJIT64_FIXED_LOW_EXECUTE_ONLY_READ matched=%Iu protect=%#lx "
                "restored=%#lx\n", matched, info.Protect, old_protect );
}

static void test_low_release_normalization(void)
{
    static const BYTE return_code_a[] =
    {
        0xb8, 0x44, 0x33, 0x22, 0x11, /* mov $0x11223344,%eax */
        0xc3,                         /* ret */
    };
    static const BYTE return_code_b[] =
    {
        0xb8, 0x88, 0x77, 0x66, 0x55, /* mov $0x55667788,%eax */
        0xc3,                         /* ret */
    };
    static const BYTE return_code_c[] =
    {
        0xb8, 0xcc, 0xbb, 0xaa, 0x99, /* mov $0x99aabbcc,%eax */
        0xc3,                         /* ret */
    };
    WINE_TRANSLATED_VIEW_INFORMATION info;
    MEMORY_BASIC_INFORMATION basic_info;
    void *requested = (void *)(ULONG_PTR)FIXED_LOW_VALLOC_BASE;
    void *base = requested;
    SIZE_T basic_size, size = 0x10000;
    SIZE_T resolved_size;
    NTSTATUS status, release_status, invalid_release, invalid_unmap;
    HANDLE real_self;
    BOOL flush_ok;
    DWORD flush_error;
    ULONG probe, code_a, code_b, code_c;

    status = NtAllocateVirtualMemory( GetCurrentProcess(), &base, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT,
                                      PAGE_EXECUTE_READWRITE );
    check( !status && base == requested,
           "canonical low valloc returned %#lx base %p size %Iu\n",
           status, base, size );
    if (status || base != requested) return;

    if (query_translated_view( requested, &info ))
        check( info.Flags == WINE_TRANSLATED_VIEW_AMD64_LOW &&
               info.GuestBase == requested &&
               (ULONG_PTR)info.HostBase ==
                   WINE_LOW_VA_SHADOW_BASE + (ULONG_PTR)info.GuestBase &&
               info.AllocationBase == requested &&
               (info.Protect & 0xff) == PAGE_EXECUTE_READWRITE &&
               info.RegionSize >= sizeof(return_code_a),
               "canonical low valloc detailed query flags %#lx guest %p host %p "
               "allocation %p size %Iu protect %#lx\n", info.Flags,
               info.GuestBase, info.HostBase, info.AllocationBase,
               info.RegionSize, info.Protect );
    memset( &basic_info, 0, sizeof(basic_info) );
    basic_size = 0;
    status = NtQueryVirtualMemory( GetCurrentProcess(), requested,
                                   MemoryBasicInformation, &basic_info,
                                   sizeof(basic_info), &basic_size );
    check( !status && basic_size == sizeof(basic_info) &&
           basic_info.State == MEM_COMMIT &&
           basic_info.AllocationBase == requested &&
           basic_info.BaseAddress == requested &&
           (basic_info.Protect & 0xff) == PAGE_EXECUTE_READWRITE &&
           basic_info.RegionSize >= sizeof(return_code_a),
           "canonical low valloc basic query returned %#lx/%Iu base %p "
           "allocation %p size %Iu state %#lx protect %#lx\n", status,
           basic_size, basic_info.BaseAddress, basic_info.AllocationBase,
           basic_info.RegionSize, basic_info.State, basic_info.Protect );
    if (failures) return;
    memcpy( requested, return_code_a, sizeof(return_code_a) );
    flush_ok = FlushInstructionCache( GetCurrentProcess(), requested,
                                      sizeof(return_code_a) );
    flush_error = flush_ok ? ERROR_SUCCESS : GetLastError();
    check( flush_ok,
           "flushing canonical low valloc generation A failed, error %lu\n",
           flush_error );
    if (failures) return;
    code_a = ((ULONG (WINAPI *)(void))requested)();
    check( code_a == 0x11223344,
           "canonical low valloc generation A returned %#lx\n", code_a );
    if (failures) return;

    real_self = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                             FALSE, GetCurrentProcessId() );
    check( !!real_self, "opening a real current-process handle failed, error %lu\n",
           GetLastError() );
    if (!real_self) return;
    memcpy( requested, return_code_b, sizeof(return_code_b) );
    flush_ok = FlushInstructionCache( real_self, requested,
                                      sizeof(return_code_b) );
    flush_error = flush_ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle( real_self );
    check( flush_ok,
           "flushing canonical LOW through a real self handle failed, error %lu\n",
           flush_error );
    if (failures) return;
    code_b = ((ULONG (WINAPI *)(void))requested)();
    check( code_b == 0x55667788,
           "canonical low valloc generation B returned %#lx\n", code_b );
    if (failures) return;

    memcpy( requested, return_code_c, sizeof(return_code_c) );
    flush_ok = FlushInstructionCache( GetCurrentProcess(), NULL,
                                      sizeof(return_code_c) );
    flush_error = flush_ok ? ERROR_SUCCESS : GetLastError();
    check( flush_ok,
           "NULL/nonzero full cache flush failed, error %lu\n",
           flush_error );
    if (failures) return;
    code_c = ((ULONG (WINAPI *)(void))requested)();
    check( code_c == 0x99aabbcc,
           "canonical low valloc generation C returned %#lx\n", code_c );
    printf( "XTAJIT64_FIXED_LOW_VALLOC flags=%#lx guest=%p host=%p "
            "allocation=%p protect=%#lx code=%#lx/%#lx/%#lx real_self=1 "
            "null_full=1\n", info.Flags,
            info.GuestBase, info.HostBase, info.AllocationBase, info.Protect,
            code_a, code_b, code_c );

    size = 0;
    release_status = NtFreeVirtualMemory( GetCurrentProcess(), &base, &size,
                                          MEM_RELEASE );
    resolved_size = size;
    check( !release_status && base == requested && resolved_size,
           "canonical low size-zero release returned %#lx base %p size %Iu\n",
           release_status, base, resolved_size );
    memset( &basic_info, 0, sizeof(basic_info) );
    basic_size = 0;
    status = NtQueryVirtualMemory( GetCurrentProcess(), requested,
                                   MemoryBasicInformation, &basic_info,
                                   sizeof(basic_info), &basic_size );
    check( !status && basic_size == sizeof(basic_info) &&
           basic_info.State == MEM_FREE && !basic_info.AllocationBase &&
           (ULONG_PTR)requested >= (ULONG_PTR)basic_info.BaseAddress &&
           (ULONG_PTR)requested - (ULONG_PTR)basic_info.BaseAddress <
               basic_info.RegionSize,
           "released low basic query returned %#lx/%Iu base %p allocation %p "
           "size %Iu state %#lx\n", status, basic_size,
           basic_info.BaseAddress, basic_info.AllocationBase,
           basic_info.RegionSize, basic_info.State );
    printf( "XTAJIT64_FIXED_LOW_RELEASE status=%#lx base=%p size=%Iu "
            "state=%#lx\n", release_status, requested, resolved_size,
            basic_info.State );

    base = requested;
    size = 0;
    invalid_release = NtFreeVirtualMemory( GetCurrentProcess(), &base, &size,
                                           MEM_RELEASE );
    invalid_unmap = NtUnmapViewOfSection( GetCurrentProcess(),
                                          (BYTE *)requested + 1 );
    check( !NT_SUCCESS(invalid_release) && !NT_SUCCESS(invalid_unmap),
           "invalid released-view operations returned %#lx/%#lx\n",
           invalid_release, invalid_unmap );
    probe = run_post_mutation_probe( 0x24681357 );
    check( probe == ((0x24681357u ^ 0x5a5aa5a5u) + 0x10203u),
           "post-invalid-release x64 probe returned %#lx\n", probe );
    printf( "XTAJIT64_FIXED_LOW_INVALID_RELEASE release=%#lx unmap=%#lx "
            "probe=%#lx\n", invalid_release, invalid_unmap, probe );
}

static void test_public_later_image_map(void)
{
    WINE_TRANSLATED_VIEW_INFORMATION info = {0};
    LARGE_INTEGER offset = {0};
    char path[MAX_PATH];
    HANDLE file, section;
    SIZE_T size = 0;
    NTSTATUS status, unmap_status = STATUS_UNSUCCESSFUL;
    DWORD length;
    void *base = NULL;

    length = GetModuleFileNameA( NULL, path, ARRAY_SIZE(path) );
    check( length && length < ARRAY_SIZE(path),
           "GetModuleFileNameA returned %lu, error %lu\n", length,
           GetLastError() );
    if (!length || length >= ARRAY_SIZE(path)) return;
    file = CreateFileA( path, GENERIC_READ | GENERIC_EXECUTE,
                        FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL );
    check( file != INVALID_HANDLE_VALUE, "opening self returned error %lu\n",
           GetLastError() );
    if (file == INVALID_HANDLE_VALUE) return;
    section = CreateFileMappingA( file, NULL, PAGE_EXECUTE_READ | SEC_IMAGE,
                                  0, 0, NULL );
    check( !!section, "creating self SEC_IMAGE returned error %lu\n",
           GetLastError() );
    if (!section)
    {
        CloseHandle( file );
        return;
    }

    status = NtMapViewOfSection( section, GetCurrentProcess(), &base, 0, 0,
                                 &offset, &size, ViewShare, 0,
                                 PAGE_EXECUTE_READ );
    if (NT_SUCCESS(status))
    {
        BOOL safe_to_unmap = !!base &&
                             base != (void *)(ULONG_PTR)FIXED_LOW_IMAGE_BASE;

        check( safe_to_unmap,
               "later public image reused occupied fixed-low base %p\n", base );
        if (safe_to_unmap && query_translated_view( base, &info ))
            check( info.Version == WINE_TRANSLATED_VIEW_INFORMATION_VERSION &&
                   !info.Flags && !info.Reserved &&
                   info.GuestBase == info.HostBase &&
                   info.AllocationBase == base && info.GuestBase == base &&
                   info.RegionSize,
                   "later public image provenance v%lu flags %#lx guest %p host %p "
                   "allocation %p size %Iu\n", info.Version, info.Flags,
                   info.GuestBase, info.HostBase, info.AllocationBase,
                   info.RegionSize );
        if (safe_to_unmap)
        {
            unmap_status = NtUnmapViewOfSection( GetCurrentProcess(), base );
            check( !unmap_status,
                   "unmapping later public image returned %#lx\n", unmap_status );
        }
        printf( "XTAJIT64_FIXED_LOW_LATER_MAP status=%#lx base=%p flags=%#lx "
                "guest=%p host=%p allocation=%p unmap=%#lx\n", status, base,
                info.Flags, info.GuestBase, info.HostBase,
                info.AllocationBase, unmap_status );
    }
    else
    {
        check( status == STATUS_CONFLICTING_ADDRESSES,
               "later public image failed with unexpected status %#lx\n", status );
        printf( "XTAJIT64_FIXED_LOW_LATER_MAP status=%#lx rejected=1\n",
                status );
    }
    CloseHandle( section );
    CloseHandle( file );
}

static void unmap_main_from_identity_stub(void)
{
    static const char marker[] = "XTAJIT64_FIXED_LOW_UNMAP_OK\r\n";
    struct code_buffer code;
    BYTE *allocation, *data;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)GetModuleHandleW( NULL );
    IMAGE_NT_HEADERS64 *nt;
    SYSTEM_BASIC_INFORMATION system_info;
    WINE_TRANSLATED_VIEW_INFORMATION code_info, data_info;
    MEMORY_BASIC_INFORMATION code_basic, data_basic;
    DWORD old_protect = 0;
    DWORD *written;
    SIZE_T page_size, result_size, unmap_failed, write_failed;
    SIZE_T short_write, exit_call;
    HANDLE output = GetStdHandle( STD_OUTPUT_HANDLE );
    NTSTATUS status, code_status, data_status;

    memset( &system_info, 0, sizeof(system_info) );
    status = NtQuerySystemInformation( SystemBasicInformation, &system_info,
                                       sizeof(system_info), NULL );
    page_size = system_info.PageSize;
    check( !status && system_info.PageSize > 0x104 &&
           !(system_info.PageSize & (system_info.PageSize - 1)),
           "system page-size query returned %#lx/%lu\n", status,
           system_info.PageSize );
    if (status || system_info.PageSize <= 0x104 ||
        (system_info.PageSize & (system_info.PageSize - 1))) return;
    check( dos && dos->e_magic == IMAGE_DOS_SIGNATURE,
           "cannot resolve fixed-low DOS header before unmap\n" );
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS64 *)((BYTE *)dos + dos->e_lfanew);
    check( nt->Signature == IMAGE_NT_SIGNATURE,
           "cannot resolve fixed-low image size before unmap\n" );
    check( output && output != INVALID_HANDLE_VALUE,
           "identity unmap output handle is invalid, error %lu\n",
           GetLastError() );
    if (failures) return;

    allocation = VirtualAlloc( (void *)0x0000000200000000ull,
                               page_size,
                               MEM_RESERVE | MEM_COMMIT,
                               PAGE_EXECUTE_READWRITE );
    if (!allocation)
        allocation = VirtualAlloc( NULL, page_size,
                                   MEM_RESERVE | MEM_COMMIT,
                                   PAGE_EXECUTE_READWRITE );
    check( !!allocation && (ULONG_PTR)allocation >= WINE_LOW_VA_SHADOW_SIZE,
           "identity unmap stub allocation returned %p, error %lu\n",
           allocation, GetLastError() );
    if (!allocation || (ULONG_PTR)allocation < WINE_LOW_VA_SHADOW_SIZE) return;
    data = VirtualAlloc( (void *)0x0000000200010000ull, page_size,
                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    if (!data)
        data = VirtualAlloc( NULL, page_size, MEM_RESERVE | MEM_COMMIT,
                             PAGE_READWRITE );
    check( !!data && (ULONG_PTR)data >= WINE_LOW_VA_SHADOW_SIZE &&
           data != allocation,
           "identity unmap data allocation returned %p after code %p, error %lu\n",
           data, allocation, GetLastError() );
    if (!data || (ULONG_PTR)data < WINE_LOW_VA_SHADOW_SIZE ||
        data == allocation) return;
    memcpy( data, marker, sizeof(marker) );
    written = (DWORD *)(data + 0x100);
    *written = 0;
    code.data = allocation;
    code.offset = 0;

    emit_u8( &code, 0x48 ); emit_u8( &code, 0x83 );
    emit_u8( &code, 0xec ); emit_u8( &code, 0x38 );       /* sub $0x38,%rsp */
    emit_u8( &code, 0x48 ); emit_u8( &code, 0xc7 );
    emit_u8( &code, 0xc1 ); emit_u32( &code, UINT32_MAX ); /* mov $-1,%rcx */
    emit_movabs( &code, 0x48, 0xba,
                 FIXED_LOW_IMAGE_BASE + 1 );               /* movabs interior,%rdx */
    emit_movabs( &code, 0x48, 0xb8,
                 (ULONG_PTR)NtUnmapViewOfSection );
    emit_u8( &code, 0xff ); emit_u8( &code, 0xd0 );       /* call *%rax */
    emit_u8( &code, 0x85 ); emit_u8( &code, 0xc0 );       /* test %eax,%eax */
    emit_u8( &code, 0x75 ); unmap_failed = code.offset; emit_u8( &code, 0 );

    emit_movabs( &code, 0x48, 0xb9, (ULONG_PTR)output );
    emit_movabs( &code, 0x48, 0xba, (ULONG_PTR)data );
    emit_u8( &code, 0x41 ); emit_u8( &code, 0xb8 );
    emit_u32( &code, sizeof(marker) - 1 );                /* mov marker size,%r8d */
    emit_movabs( &code, 0x49, 0xb9, (ULONG_PTR)written );
    emit_u8( &code, 0x48 ); emit_u8( &code, 0xc7 );
    emit_u8( &code, 0x44 ); emit_u8( &code, 0x24 ); emit_u8( &code, 0x20 );
    emit_u32( &code, 0 );                                 /* overlapped = NULL */
    emit_movabs( &code, 0x48, 0xb8, (ULONG_PTR)WriteFile );
    emit_u8( &code, 0xff ); emit_u8( &code, 0xd0 );
    emit_u8( &code, 0x85 ); emit_u8( &code, 0xc0 );
    emit_u8( &code, 0x74 ); write_failed = code.offset; emit_u8( &code, 0 );
    emit_movabs( &code, 0x48, 0xb8, (ULONG_PTR)written );
    emit_u8( &code, 0x81 ); emit_u8( &code, 0x38 );
    emit_u32( &code, sizeof(marker) - 1 );
    emit_u8( &code, 0x75 ); short_write = code.offset; emit_u8( &code, 0 );
    emit_u8( &code, 0x31 ); emit_u8( &code, 0xc9 );       /* xor %ecx,%ecx */
    emit_u8( &code, 0xeb ); exit_call = code.offset; emit_u8( &code, 0 );

    patch_rel8( &code, unmap_failed, code.offset );
    patch_rel8( &code, write_failed, code.offset );
    patch_rel8( &code, short_write, code.offset );
    emit_u8( &code, 0xb9 ); emit_u32( &code, 1 );         /* mov $1,%ecx */
    patch_rel8( &code, exit_call, code.offset );
    emit_movabs( &code, 0x48, 0xb8, (ULONG_PTR)RtlExitUserProcess );
    emit_u8( &code, 0xff ); emit_u8( &code, 0xd0 );
    emit_u8( &code, 0xcc );

    check( code.offset < page_size,
           "identity unmap stub size %Iu exceeds its code page\n", code.offset );
    check_identity_view( allocation, "stub code" );
    check_identity_view( data, "stub marker" );
    check_identity_view( written, "stub write count" );
    check_identity_view( (const void *)(ULONG_PTR)NtUnmapViewOfSection,
                         "NtUnmapViewOfSection" );
    check_identity_view( (const void *)(ULONG_PTR)WriteFile, "WriteFile" );
    check_identity_view( (const void *)(ULONG_PTR)RtlExitUserProcess,
                         "RtlExitUserProcess" );
    if (failures) return;

    /* Darwin executable mappings must be created with their maximum execute
     * permission.  Code and writable data use distinct reservations so the
     * logical split never depends on the host page size. */
    check( VirtualProtect( allocation, page_size, PAGE_EXECUTE_READ,
                           &old_protect ),
           "protecting identity unmap stub failed, error %lu\n",
           GetLastError() );
    check( (old_protect & 0xff) == PAGE_EXECUTE_READWRITE,
           "identity unmap code replaced protection %#lx\n", old_protect );
    if (failures) return;

    result_size = 0;
    code_status = query_translated_view_raw( allocation, &code_info,
                                             &result_size );
    check( !code_status && result_size == sizeof(code_info) &&
           code_info.Version == WINE_TRANSLATED_VIEW_INFORMATION_VERSION &&
           !code_info.Flags && !code_info.Reserved &&
           code_info.GuestBase == allocation &&
           code_info.HostBase == allocation &&
           code_info.AllocationBase == allocation &&
           code_info.RegionSize == page_size &&
           (code_info.Protect & 0xff) == PAGE_EXECUTE_READ,
           "identity unmap code query returned %#lx/%Iu v%lu flags %#lx "
           "guest %p host %p allocation %p protect %#lx\n", code_status,
           result_size, code_info.Version, code_info.Flags,
           code_info.GuestBase, code_info.HostBase, code_info.AllocationBase,
           code_info.Protect );
    result_size = 0;
    data_status = query_translated_view_raw( data, &data_info, &result_size );
    check( !data_status && result_size == sizeof(data_info) &&
           data_info.Version == WINE_TRANSLATED_VIEW_INFORMATION_VERSION &&
           !data_info.Flags && !data_info.Reserved &&
           data_info.GuestBase == data && data_info.HostBase == data &&
           data_info.AllocationBase == data &&
           data_info.RegionSize == page_size &&
           (data_info.Protect & 0xff) == PAGE_READWRITE,
           "identity unmap data query returned %#lx/%Iu v%lu flags %#lx "
           "guest %p host %p allocation %p protect %#lx\n", data_status,
           result_size, data_info.Version, data_info.Flags,
           data_info.GuestBase, data_info.HostBase, data_info.AllocationBase,
           data_info.Protect );

    memset( &code_basic, 0, sizeof(code_basic) );
    result_size = 0;
    code_status = NtQueryVirtualMemory( GetCurrentProcess(), allocation,
                                        MemoryBasicInformation, &code_basic,
                                        sizeof(code_basic), &result_size );
    check( !code_status && result_size == sizeof(code_basic) &&
           code_basic.State == MEM_COMMIT &&
           code_basic.AllocationBase == allocation &&
           code_basic.BaseAddress == allocation &&
           code_basic.RegionSize == page_size &&
           (code_basic.AllocationProtect & 0xff) == PAGE_EXECUTE_READWRITE &&
           (code_basic.Protect & 0xff) == PAGE_EXECUTE_READ,
           "identity unmap code basic query returned %#lx/%Iu base %p "
           "allocation %p size %Iu state %#lx allocation_protect %#lx "
           "protect %#lx\n", code_status,
           result_size, code_basic.BaseAddress, code_basic.AllocationBase,
           code_basic.RegionSize, code_basic.State,
           code_basic.AllocationProtect, code_basic.Protect );
    memset( &data_basic, 0, sizeof(data_basic) );
    result_size = 0;
    data_status = NtQueryVirtualMemory( GetCurrentProcess(), data,
                                        MemoryBasicInformation, &data_basic,
                                        sizeof(data_basic), &result_size );
    check( !data_status && result_size == sizeof(data_basic) &&
           data_basic.State == MEM_COMMIT &&
           data_basic.AllocationBase == data &&
           data_basic.BaseAddress == data &&
           data_basic.RegionSize == page_size &&
           (data_basic.AllocationProtect & 0xff) == PAGE_READWRITE &&
           (data_basic.Protect & 0xff) == PAGE_READWRITE,
           "identity unmap data basic query returned %#lx/%Iu base %p "
           "allocation %p size %Iu state %#lx allocation_protect %#lx "
           "protect %#lx\n", data_status,
           result_size, data_basic.BaseAddress, data_basic.AllocationBase,
           data_basic.RegionSize, data_basic.State,
           data_basic.AllocationProtect, data_basic.Protect );
    if (failures) return;
    check( FlushInstructionCache( GetCurrentProcess(), allocation, code.offset ),
           "flushing identity unmap stub failed, error %lu\n",
           GetLastError() );
    if (failures) return;
    printf( "XTAJIT64_FIXED_LOW_PRE_UNMAP stub=%p data=%p page_size=%Iu "
            "image_size=%#lx\n", allocation, data, page_size,
            nt->OptionalHeader.SizeOfImage );
    fflush( stdout );
    ((void (WINAPI *)(void))allocation)();
    RtlExitUserProcess( 1 );
}

int main(void)
{
    test_process_contract();
    if (!failures) test_public_module_contract();
    if (!failures) test_main_export_import();
    if (!failures) test_peb_image_base_spoof();
    if (!failures) test_fixed_low_main();
    if (!failures) test_execute_only_low_read();
    if (!failures) test_low_release_normalization();
    if (!failures) test_public_later_image_map();
    if (!failures) unmap_main_from_identity_stub();
    fprintf( stderr, "%u fixed-low XTAJIT64 checks failed\n",
             failures ? failures : 1 );
    return 1;
}
