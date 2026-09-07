/*
 * Definitions for Wine Unix libraries
 *
 * Copyright (C) 2021 Alexandre Julliard
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

#if 0
#pragma makedep install
#endif

#ifndef __WINE_WINE_UNIXLIB_H
#define __WINE_WINE_UNIXLIB_H

#include <winternl.h>

typedef UINT64 unixlib_handle_t;
typedef UINT64 unixlib_module_t;

#define WINE_UNIXLIB_DISPATCH_HANDLE_TAG 0x8000000000000000ull
#define WINE_UNIXLIB_DISPATCH_VERSION   1u
#define WINE_UNIXLIB_DISPATCH_MAGIC     0x57494e45554e4958ull
#define WINE_UNIXLIB_DISPATCH_MAX_SLOTS 1025u
#define WINE_UNIXLIB_DISPATCH_MAX_ENTRIES 65536u
#define WINE_UNIXLIB_DISPATCH_SLOT_BITS 11u
#define WINE_UNIXLIB_DISPATCH_SLOT_MASK 0x7ffull
#define WINE_UNIXLIB_DISPATCH_GENERATION_SHIFT WINE_UNIXLIB_DISPATCH_SLOT_BITS
#define WINE_UNIXLIB_DISPATCH_GENERATION_MASK 0xfffffffffffffull
#define WINE_UNIXLIB_DISPATCH_SOURCE_V2_VERSION 2u
#define WINE_UNIXLIB_DISPATCH_MAX_ARGS_SIZE 4096u

#define WINE_UNIXLIB_DISPATCH_ENTRY_REVIEWED        0x00000001u
#define WINE_UNIXLIB_DISPATCH_ENTRY_NESTED          0x00000002u
#define WINE_UNIXLIB_DISPATCH_ENTRY_HAS_OUTPUT      0x00000004u
#define WINE_UNIXLIB_DISPATCH_ENTRY_MAY_CALLBACK    0x00000008u
#define WINE_UNIXLIB_DISPATCH_ENTRY_RETAINS_ADDRESS 0x00000010u
#define WINE_UNIXLIB_DISPATCH_ENTRY_VALID_FLAGS     0x0000001fu

/* Fixed host ABI used by reviewed sibling adapters for Unix libraries whose
 * legacy WoW64 entry table cannot consume high-shadow guest pointers. */
#define WINE_WOW64_UNIXLIB_ALIAS_V2_VERSION          2u
#define WINE_WOW64_UNIXLIB_CODEC_V2_VERSION          2u
#define WINE_WOW64_UNIXLIB_BINDING_V6_VERSION        6u
#define WINE_WOW64_UNIXLIB_COMPANION_V6_VERSION      6u
#define WINE_UNIXLIB_OWNED_BACKING_V2_VERSION        2u
#define WINE_UNIXLIB_OWNED_BACKING_CODEC_V2_VERSION  2u

/* SHA-256 of the canonical winemetal-wow64 abi-schema-v6.txt bytes. */
#define WINE_WOW64_UNIXLIB_COMPANION_V6_ABI_SHA256 \
    { 0x00, 0x51, 0xbd, 0x8c, 0x0b, 0xc3, 0xe3, 0xce, \
      0x26, 0x1e, 0x9d, 0x50, 0x07, 0x66, 0x53, 0x42, \
      0xac, 0x2d, 0x28, 0xa6, 0x43, 0x57, 0x67, 0x44, \
      0xd8, 0xec, 0x71, 0x89, 0x6a, 0xf8, 0x56, 0xf1 }

#define WINE_WOW64_UNIXLIB_CAP_SEPARATE_GUEST_ADDRESS_SPACE 0x0000000000000001ull
#define WINE_WOW64_UNIXLIB_CAP_OWNED_MEMORY_ALIAS           0x0000000000000002ull
#define WINE_UNIXLIB_OWNED_BACKING_CAP_ACQUIRE_RELEASE      0x0000000000000001ull

#define WINE_WOW64_UNIXLIB_ACCESS_READ  0x00000001u
#define WINE_WOW64_UNIXLIB_ACCESS_WRITE 0x00000002u

C_ASSERT( WINE_UNIXLIB_DISPATCH_MAX_SLOTS <= WINE_UNIXLIB_DISPATCH_SLOT_MASK );
C_ASSERT( WINE_UNIXLIB_DISPATCH_SLOT_MASK ==
          ((1ull << WINE_UNIXLIB_DISPATCH_SLOT_BITS) - 1) );
C_ASSERT( WINE_UNIXLIB_DISPATCH_GENERATION_MASK ==
          ((WINE_UNIXLIB_DISPATCH_HANDLE_TAG - 1) >>
           WINE_UNIXLIB_DISPATCH_GENERATION_SHIFT) );

static inline unixlib_handle_t wine_unixlib_dispatch_handle( UINT32 slot, UINT64 generation )
{
    if (slot >= WINE_UNIXLIB_DISPATCH_MAX_SLOTS || !generation ||
        generation > WINE_UNIXLIB_DISPATCH_GENERATION_MASK)
        return 0;
    return WINE_UNIXLIB_DISPATCH_HANDLE_TAG |
           (generation << WINE_UNIXLIB_DISPATCH_GENERATION_SHIFT) | ((UINT64)slot + 1);
}

static inline BOOL wine_unixlib_decode_dispatch_handle( unixlib_handle_t handle,
                                                         UINT32 *slot, UINT64 *generation )
{
    UINT64 payload, encoded_slot, encoded_generation;

    if (!(handle & WINE_UNIXLIB_DISPATCH_HANDLE_TAG)) return FALSE;
    payload = handle & ~WINE_UNIXLIB_DISPATCH_HANDLE_TAG;
    encoded_slot = payload & WINE_UNIXLIB_DISPATCH_SLOT_MASK;
    encoded_generation = payload >> WINE_UNIXLIB_DISPATCH_GENERATION_SHIFT;
    if (!encoded_slot || encoded_slot > WINE_UNIXLIB_DISPATCH_MAX_SLOTS ||
        !encoded_generation || encoded_generation > WINE_UNIXLIB_DISPATCH_GENERATION_MASK)
        return FALSE;
    if (slot) *slot = encoded_slot - 1;
    if (generation) *generation = encoded_generation;
    return TRUE;
}

#ifdef WINE_UNIX_LIB

typedef NTSTATUS (*unixlib_entry_t)( void *args );

struct wine_wow64_unixlib_alias_v2
{
    UINT32 version;
    UINT32 size;
    UINT64 address;
    UINT64 length;
    UINT64 mapped_length;
    UINT64 lease;
    UINT64 generation;
};

struct wine_wow64_unixlib_codec_v2
{
    UINT32 version;
    UINT32 size;
    UINT64 capabilities;
    NTSTATUS (*translate)( UINT64 guest, UINT64 size, UINT32 access, void **host );
    NTSTATUS (*copy_from_guest)( UINT64 guest, void *dst, UINT64 size );
    NTSTATUS (*copy_to_guest)( UINT64 guest, const void *src, UINT64 size );
    NTSTATUS (*acquire_alias)( UINT64 guest, UINT64 size, UINT32 access,
                               struct wine_wow64_unixlib_alias_v2 *alias );
    NTSTATUS (*release_alias)( UINT64 lease );
};

struct wine_unixlib_owned_backing_v2
{
    UINT32 version;
    UINT32 size;
    UINT64 address;
    UINT64 length;
    UINT64 mapped_length;
    UINT64 lease;
    UINT64 generation;
    UINT64 guest_address;
};

struct wine_unixlib_owned_backing_codec_v2
{
    UINT32 version;
    UINT32 size;
    UINT64 capabilities;
    NTSTATUS (*acquire_backing)( UINT64 length, UINT32 access,
                                 struct wine_unixlib_owned_backing_v2 *backing );
    NTSTATUS (*release_backing)( UINT64 lease );
};

/* A companion must test the capability and callbacks before accepting a call
 * that lets a native framework retain caller-owned memory. */
struct wine_wow64_unixlib_binding_v6
{
    UINT32 version;
    UINT32 size;
    UINT32 entry_count;
    UINT32 reserved;
    const unixlib_entry_t *normal_funcs;
    const unixlib_entry_t *legacy_wow64_funcs;
    const struct wine_wow64_unixlib_codec_v2 *codec;
    const struct wine_unixlib_owned_backing_codec_v2 *owned_backing_codec;
};

struct wine_wow64_unixlib_companion_v6
{
    UINT32 version;
    UINT32 size;
    UINT32 entry_count;
    UINT32 flags;
    BYTE abi_sha256[32];
    NTSTATUS (*bind)( const struct wine_wow64_unixlib_binding_v6 *binding );
    NTSTATUS (*quiesce)(void);
    NTSTATUS (*unbind)(void);
};

C_ASSERT( sizeof(struct wine_wow64_unixlib_alias_v2) == 48 );
C_ASSERT( sizeof(struct wine_wow64_unixlib_codec_v2) == 16 + 5 * sizeof(void *) );
C_ASSERT( sizeof(struct wine_unixlib_owned_backing_v2) == 56 );
C_ASSERT( sizeof(struct wine_unixlib_owned_backing_codec_v2) == 16 + 2 * sizeof(void *) );
C_ASSERT( sizeof(struct wine_wow64_unixlib_binding_v6) == 16 + 4 * sizeof(void *) );
C_ASSERT( sizeof(struct wine_wow64_unixlib_companion_v6) == 48 + 3 * sizeof(void *) );

/* Immutable v1 source descriptor used only by ntdll's audited internal WoW64
 * table.  External high-shadow Unix libraries must use v2 metadata; a raw
 * table or a stand-alone count is not a safe dispatch ABI. */
struct wine_unixlib_dispatch_source_v1
{
    UINT32 version;
    UINT32 size;
    UINT32 entry_count;
    UINT32 reserved;
    const unixlib_entry_t *funcs;
};

C_ASSERT( sizeof(struct wine_unixlib_dispatch_source_v1) == 16 + sizeof(void *) );

extern DECLSPEC_EXPORT const struct wine_unixlib_dispatch_source_v1
    __wine_unix_call_wow64_dispatch_v1;

/* Emit this next to ntdll's immutable internal WoW64 entry table.  Keeping the
 * descriptor and table in one translation unit makes the count a compile-time
 * property instead of loader-inferred metadata. */
#define WINE_UNIXLIB_DISPATCH_SOURCE_V1(table) \
    C_ASSERT( sizeof(table) / sizeof((table)[0]) > 0 && \
              sizeof(table) / sizeof((table)[0]) <= WINE_UNIXLIB_DISPATCH_MAX_ENTRIES ); \
    DECLSPEC_EXPORT const struct wine_unixlib_dispatch_source_v1 \
        __wine_unix_call_wow64_dispatch_v1 = \
        { WINE_UNIXLIB_DISPATCH_VERSION, sizeof(struct wine_unixlib_dispatch_source_v1), \
          sizeof(table) / sizeof((table)[0]), 0, table }

/* High-shadow external Unix libraries use v2.  The dispatcher only captures
 * the exact fixed outer block; descriptive flags do not authorize generic
 * nested marshalling or copyback.  A reviewed adapter must use the sanctioned
 * current-process user-memory helpers below for every nested input and output.
 * RETAINS_ADDRESS refers only to an explicitly reviewed canonical guest
 * address.  A callee must never retain the native snapshot pointer. */
struct wine_unixlib_dispatch_entry_v2
{
    UINT32 args_size;
    UINT32 flags;
};

struct wine_unixlib_dispatch_source_v2
{
    UINT32 version;
    UINT32 size;
    UINT32 entry_count;
    UINT32 entry_size;
    const unixlib_entry_t *funcs;
    const struct wine_unixlib_dispatch_entry_v2 *entries;
    UINT32 flags;
    UINT32 reserved;
};

C_ASSERT( sizeof(struct wine_unixlib_dispatch_entry_v2) == 8 );
C_ASSERT( sizeof(struct wine_unixlib_dispatch_source_v2) == 24 + 2 * sizeof(void *) );

extern DECLSPEC_EXPORT const struct wine_unixlib_dispatch_source_v2
    __wine_unix_call_wow64_dispatch_v2;

#define WINE_UNIXLIB_DISPATCH_ARGS_V2(type, extra_flags) \
    { sizeof(type), WINE_UNIXLIB_DISPATCH_ENTRY_REVIEWED | (extra_flags) }
#define WINE_UNIXLIB_DISPATCH_NULL_V2 { 0, 0 }
#define WINE_UNIXLIB_DISPATCH_SOURCE_V2(table, metadata) \
    C_ASSERT( sizeof(table) / sizeof((table)[0]) > 0 && \
              sizeof(table) / sizeof((table)[0]) <= WINE_UNIXLIB_DISPATCH_MAX_ENTRIES ); \
    C_ASSERT( sizeof(metadata) / sizeof((metadata)[0]) == \
              sizeof(table) / sizeof((table)[0]) ); \
    DECLSPEC_EXPORT const struct wine_unixlib_dispatch_source_v2 \
        __wine_unix_call_wow64_dispatch_v2 = \
        { WINE_UNIXLIB_DISPATCH_SOURCE_V2_VERSION, \
          sizeof(struct wine_unixlib_dispatch_source_v2), \
          sizeof(table) / sizeof((table)[0]), \
          sizeof(struct wine_unixlib_dispatch_entry_v2), table, metadata, 0, 0 }

struct wine_unixlib_dispatch_v1
{
    UINT64 magic;
    UINT32 version;
    UINT32 entry_count;
    const unixlib_entry_t *funcs;
    UINT64 self;
};

C_ASSERT( sizeof(struct wine_unixlib_dispatch_v1) == 32 );

extern DECLSPEC_EXPORT NTSTATUS __wine_unix_lib_init(void);
extern DECLSPEC_EXPORT const unixlib_entry_t __wine_unix_call_funcs[];
extern DECLSPEC_EXPORT const unixlib_entry_t __wine_unix_call_wow64_funcs[];

/* some useful private helpers from ntdll */

#ifdef __WINESRC__

NTSYSAPI const WCHAR *ntdll_get_build_dir(void);
NTSYSAPI const WCHAR *ntdll_get_data_dir(void);
NTSYSAPI NTSTATUS ntdll_get_dos_file_name( const char *unix_name, WCHAR **dos, UINT disposition );
NTSYSAPI NTSTATUS ntdll_get_unix_file_name( const WCHAR *dos, char **unix_name, UINT disposition );

/* Current-process WoW64 user-memory access for native Unix libraries.  The
 * range array and every source buffer passed to atomic_writev are native-owned
 * and stable for the duration of the call; destinations are canonical host
 * pointers produced from untrusted 32-bit guest addresses by guest32_to_host.
 * Recoverable atomic-write failures publish no bytes. */
#define NTDLL_WOW64_USER_WRITEV_MAX 64u

struct ntdll_wow64_user_write_range
{
    void *dst;
    const void *src;
    SIZE_T size;
};

C_ASSERT( sizeof(struct ntdll_wow64_user_write_range) == 3 * sizeof(void *) );

struct ntdll_wow64_unixlib_call_context
{
    const void *guest_args;
    UINT32 args_size;
    UINT32 flags;
};

C_ASSERT( sizeof(struct ntdll_wow64_unixlib_call_context) ==
          (sizeof(void *) == 8 ? 16 : 12) );

/* Decode only an untrusted 32-bit guest address; the active paired WoW64 TEB
 * selects identity-low versus translated high-shadow ownership. */
NTSYSAPI NTSTATUS ntdll_wow64_guest32_to_host( ULONG address, void **host );
/* READ preserves direct-load exception status and resolves a readable guard. */
NTSYSAPI NTSTATUS ntdll_wow64_copy_from_user( void *dst, const void *src, SIZE_T size );
/* Ordinary WRITE is a no-touch checked publication for I/O-style callers. */
NTSYSAPI NTSTATUS ntdll_wow64_copy_to_user( void *dst, const void *src, SIZE_T size );
/* FAULTING WRITE preserves direct-store guard/stack-growth behavior. */
NTSYSAPI NTSTATUS ntdll_wow64_faulting_copy_to_user( void *dst, const void *src,
                                                     SIZE_T size );
/* Atomic forms use faulting destination semantics, validate before any store,
 * and fail-stop on an observer publication failure after stores. */
NTSYSAPI NTSTATUS ntdll_wow64_atomic_write_user( void *dst, const void *src, SIZE_T size );
NTSYSAPI NTSTATUS ntdll_wow64_probe_user_writev(
    const struct ntdll_wow64_user_write_range *ranges, ULONG count );
NTSYSAPI NTSTATUS ntdll_wow64_atomic_writev(
    const struct ntdll_wow64_user_write_range *ranges, ULONG count );
NTSYSAPI NTSTATUS ntdll_wow64_probe_user_read( const void *src, SIZE_T size );
NTSYSAPI NTSTATUS ntdll_wow64_probe_user_write( void *dst, SIZE_T size );
/* Valid only while a reviewed v2 entry is running.  The returned guest_args
 * remains canonical guest memory; it is not the native snapshot passed to the
 * entry and must not be retained after the call. */
NTSYSAPI NTSTATUS ntdll_wow64_get_unixlib_call_context(
    struct ntdll_wow64_unixlib_call_context *context );
/* Native-only lifecycle registration for reviewed v2 companion images.  The
 * immutable source, function table, and both callbacks must resolve to the
 * same loaded image; callbacks are invoked outside ntdll's registry lock. */
NTSYSAPI NTSTATUS ntdll_wow64_register_unixlib_dispatch_v2(
    const struct wine_unixlib_dispatch_source_v2 *source, const unixlib_entry_t *funcs,
    NTSTATUS (*quiesce)(void), NTSTATUS (*unbind)(void), unixlib_handle_t *handle );
NTSYSAPI NTSTATUS ntdll_wow64_unregister_unixlib_dispatch( unixlib_handle_t handle );

/* exception handling */

#include <setjmp.h>

NTSYSAPI void ntdll_set_exception_jmp_buf( jmp_buf jmp );

#define __TRY \
    do { jmp_buf __jmp; \
         int __first = 1; \
         for (;;) if (!__first) \
         { \
             do {

#define __EXCEPT \
             } while(0); \
             ntdll_set_exception_jmp_buf( NULL ); \
             break; \
         } else { \
             if (setjmp( __jmp )) { \
                 ntdll_set_exception_jmp_buf( NULL ); \
                 do {

#define __ENDTRY \
                 } while (0); \
                 break; \
             } \
             ntdll_set_exception_jmp_buf( __jmp ); \
             __first = 0; \
         } \
    } while (0);

NTSYSAPI BOOLEAN KeAddSystemServiceTable( ULONG_PTR *funcs, ULONG_PTR *counters, ULONG limit,
                                          BYTE *arguments, ULONG index );
NTSYSAPI void ntdll_add_syscall_debug_info( UINT idx, const char **syscall_names,
                                            const char **usercall_names );

#endif  /* __WINESRC__ */

/* wide char string functions */

static inline int ntdll_iswspace( WCHAR wc )
{
    return ('\t' <= wc && wc <= '\r') || wc == ' ' || wc == 0xa0;
}

static inline size_t ntdll_wcslen( const WCHAR *str )
{
    const WCHAR *s = str;
    while (*s) s++;
    return s - str;
}

static inline WCHAR *ntdll_wcscpy( WCHAR *dst, const WCHAR *src )
{
    WCHAR *p = dst;
    while ((*p++ = *src++));
    return dst;
}

static inline WCHAR *ntdll_wcscat( WCHAR *dst, const WCHAR *src )
{
    ntdll_wcscpy( dst + ntdll_wcslen(dst), src );
    return dst;
}

static inline int ntdll_wcscmp( const WCHAR *str1, const WCHAR *str2 )
{
    while (*str1 && (*str1 == *str2)) { str1++; str2++; }
    return *str1 - *str2;
}

static inline int ntdll_wcsncmp( const WCHAR *str1, const WCHAR *str2, int n )
{
    if (n <= 0) return 0;
    while ((--n > 0) && *str1 && (*str1 == *str2)) { str1++; str2++; }
    return *str1 - *str2;
}

static inline WCHAR *ntdll_wcschr( const WCHAR *str, WCHAR ch )
{
    do { if (*str == ch) return (WCHAR *)(ULONG_PTR)str; } while (*str++);
    return NULL;
}

static inline WCHAR *ntdll_wcsrchr( const WCHAR *str, WCHAR ch )
{
    WCHAR *ret = NULL;
    do { if (*str == ch) ret = (WCHAR *)(ULONG_PTR)str; } while (*str++);
    return ret;
}

static inline WCHAR *ntdll_wcspbrk( const WCHAR *str, const WCHAR *accept )
{
    for ( ; *str; str++) if (ntdll_wcschr( accept, *str )) return (WCHAR *)(ULONG_PTR)str;
    return NULL;
}

static inline SIZE_T ntdll_wcsspn( const WCHAR *str, const WCHAR *accept )
{
    const WCHAR *ptr;
    for (ptr = str; *ptr; ptr++) if (!ntdll_wcschr( accept, *ptr )) break;
    return ptr - str;
}

static inline SIZE_T ntdll_wcscspn( const WCHAR *str, const WCHAR *reject )
{
    const WCHAR *ptr;
    for (ptr = str; *ptr; ptr++) if (ntdll_wcschr( reject, *ptr )) break;
    return ptr - str;
}

static inline LONG ntdll_wcstol( const WCHAR *s, WCHAR **end, int base )
{
    BOOL negative = FALSE, empty = TRUE;
    LONG ret = 0;

    if (base < 0 || base == 1 || base > 36) return 0;
    if (end) *end = (WCHAR *)s;
    while (ntdll_iswspace(*s)) s++;

    if (*s == '-')
    {
        negative = TRUE;
        s++;
    }
    else if (*s == '+') s++;

    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        base = 16;
        s += 2;
    }
    if (base == 0) base = s[0] != '0' ? 10 : 8;

    while (*s)
    {
        int v;

        if ('0' <= *s && *s <= '9') v = *s - '0';
        else if ('A' <= *s && *s <= 'Z') v = *s - 'A' + 10;
        else if ('a' <= *s && *s <= 'z') v = *s - 'a' + 10;
        else break;
        if (v >= base) break;
        if (negative) v = -v;
        s++;
        empty = FALSE;

        if (!negative && (ret > MAXLONG / base || ret * base > MAXLONG - v))
            ret = MAXLONG;
        else if (negative && (ret < (LONG)MINLONG / base || ret * base < (LONG)(MINLONG - v)))
            ret = MINLONG;
        else
            ret = ret * base + v;
    }

    if (end && !empty) *end = (WCHAR *)s;
    return ret;
}

static inline ULONG ntdll_wcstoul( const WCHAR *s, WCHAR **end, int base )
{
    BOOL negative = FALSE, empty = TRUE;
    ULONG ret = 0;

    if (base < 0 || base == 1 || base > 36) return 0;
    if (end) *end = (WCHAR *)s;
    while (ntdll_iswspace(*s)) s++;

    if (*s == '-')
    {
        negative = TRUE;
        s++;
    }
    else if (*s == '+') s++;

    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        base = 16;
        s += 2;
    }
    if (base == 0) base = s[0] != '0' ? 10 : 8;

    while (*s)
    {
        int v;

        if ('0' <= *s && *s <= '9') v = *s - '0';
        else if ('A' <= *s && *s <= 'Z') v = *s - 'A' + 10;
        else if ('a' <= *s && *s <= 'z') v = *s - 'a' + 10;
        else break;
        if (v >= base) break;
        s++;
        empty = FALSE;

        if (ret > MAXDWORD / base || ret * base > MAXDWORD - v)
            ret = MAXDWORD;
        else
            ret = ret * base + v;
    }

    if (end && !empty) *end = (WCHAR *)s;
    return negative ? -ret : ret;
}

NTSYSAPI DWORD ntdll_umbstowcs( const char *src, DWORD srclen, WCHAR *dst, DWORD dstlen );
NTSYSAPI int ntdll_wcstoumbs( const WCHAR *src, DWORD srclen, char *dst, DWORD dstlen, BOOL strict );
NTSYSAPI int ntdll_wcsicmp( const WCHAR *str1, const WCHAR *str2 );
NTSYSAPI int ntdll_wcsnicmp( const WCHAR *str1, const WCHAR *str2, int n );

/* C23 requires these functions to be defined as macros */
#undef wcschr
#undef wcsrchr
#undef wcspbrk

#define iswspace(ch)       ntdll_iswspace(ch)
#define wcslen(str)        ntdll_wcslen(str)
#define wcscpy(dst,src)    ntdll_wcscpy(dst,src)
#define wcscat(dst,src)    ntdll_wcscat(dst,src)
#define wcscmp(s1,s2)      ntdll_wcscmp(s1,s2)
#define wcsncmp(s1,s2,n)   ntdll_wcsncmp(s1,s2,n)
#define wcschr(str,ch)     ntdll_wcschr(str,ch)
#define wcsrchr(str,ch)    ntdll_wcsrchr(str,ch)
#define wcspbrk(str,ac)    ntdll_wcspbrk(str,ac)
#define wcsspn(str,ac)     ntdll_wcsspn(str,ac)
#define wcscspn(str,rej)   ntdll_wcscspn(str,rej)
#define wcsicmp(s1, s2)    ntdll_wcsicmp(s1,s2)
#define wcsnicmp(s1, s2,n) ntdll_wcsnicmp(s1,s2,n)
#define wcstol(str,e,b)    ntdll_wcstol(str,e,b)
#define wcstoul(str,e,b)   ntdll_wcstoul(str,e,b)

#else /* WINE_UNIX_LIB */

extern unixlib_handle_t __wine_unixlib_handle;
extern NTSTATUS (WINAPI *__wine_unix_call_dispatcher)( unixlib_handle_t, unsigned int, void * );
extern NTSTATUS WINAPI __wine_init_unix_call(void);
extern NTSTATUS WINAPI __wine_load_unix_lib( const UNICODE_STRING *name, unixlib_module_t *lib,
                                             unixlib_handle_t *handle );
extern NTSTATUS WINAPI __wine_unload_unix_lib( unixlib_module_t lib );

#ifdef WINE_UNIX_CALL_EXPORT
NTSTATUS WINAPI __wine_unix_call( unixlib_handle_t handle, unsigned int code, void *args );
#elif defined __arm64ec__
NTSTATUS __wine_unix_call_arm64ec( unixlib_handle_t handle, unsigned int code, void *args );
static inline NTSTATUS __wine_unix_call( unixlib_handle_t handle, unsigned int code, void *args )
{
    return __wine_unix_call_arm64ec( handle, code, args );
}
#else
static inline NTSTATUS __wine_unix_call( unixlib_handle_t handle, unsigned int code, void *args )
{
    return __wine_unix_call_dispatcher( handle, code, args );
}
#endif

#define WINE_UNIX_CALL(code,args) __wine_unix_call( __wine_unixlib_handle, (code), (args) )

#endif /* WINE_UNIX_LIB */

#endif  /* __WINE_WINE_UNIXLIB_H */
