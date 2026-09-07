/*
 * Translated WoW64 native-resource backing pool
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
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifdef WINE_WOW64_OWNED_BACKING_NATIVE_TEST
#include <stdio.h>
#include <unistd.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#undef WIN32_NO_STATUS
#include "wine/debug.h"
#include "wine/list.h"
#include "wine/low_va.h"

#ifndef WINE_UNIX_LIB
#define WINE_UNIX_LIB
#define WOW64_OWNED_BACKING_DEFINED_WINE_UNIX_LIB
#endif
#include "unix_private.h"
#ifdef WOW64_OWNED_BACKING_DEFINED_WINE_UNIX_LIB
#undef WINE_UNIX_LIB
#undef WOW64_OWNED_BACKING_DEFINED_WINE_UNIX_LIB
#endif

#ifndef WINE_WOW64_OWNED_BACKING_NATIVE_TEST
WINE_DEFAULT_DEBUG_CHANNEL(virtual);
#else
#undef WARN
#undef ERR
#define WARN(...) fprintf( stderr, __VA_ARGS__ )
#define ERR(...) fprintf( stderr, __VA_ARGS__ )
#endif

#ifdef WINE_WOW64_OWNED_BACKING_NATIVE_TEST
#define WOW64_OWNED_BACKING_MAX_ALLOCATION ((UINT64)64 << 10)
#define WOW64_OWNED_BACKING_MAX_TOTAL       ((UINT64)4 << 16)
#define WOW64_OWNED_BACKING_MAX_BLOCKS      4u
#else
#define WOW64_OWNED_BACKING_MAX_ALLOCATION ((UINT64)1 << 30)
#define WOW64_OWNED_BACKING_MAX_TOTAL       ((UINT64)4 << 30)
#define WOW64_OWNED_BACKING_MAX_BLOCKS      4096u
#endif

enum wow64_owned_backing_state
{
    WOW64_OWNED_BACKING_INACTIVE,
    WOW64_OWNED_BACKING_PREPARING,
    WOW64_OWNED_BACKING_ACTIVE,
    WOW64_OWNED_BACKING_QUARANTINED,
};

struct wow64_owned_backing_block
{
    struct list entry;
    void *address;
    UINT64 guest_address;
    SIZE_T capacity;
    SIZE_T mapped_length;
    UINT64 lease;
    UINT64 generation;
    enum wow64_owned_backing_state state;
};

static struct
{
    pthread_mutex_t mutex;
    struct list blocks;
    UINT64 total_capacity;
    UINT64 active_capacity;
    UINT64 pending_capacity;
    UINT64 next_lease;
    UINT64 next_generation;
    UINT32 block_count;
    UINT32 active_blocks;
    UINT32 pending_blocks;
} pool =
{
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .blocks = LIST_INIT(pool.blocks),
    .next_lease = 1,
    .next_generation = 1,
};

static void discard_block_contents( struct wow64_owned_backing_block *block )
{
    if (!block->address || !block->capacity) return;
    if (madvise( block->address, block->capacity, MADV_DONTNEED ))
        WARN( "failed to discard translated WoW64 owned-backing contents, error %d\n", errno );
}

static struct wow64_owned_backing_block *find_inactive_block( SIZE_T capacity )
{
    struct wow64_owned_backing_block *block, *best = NULL;

    LIST_FOR_EACH_ENTRY( block, &pool.blocks, struct wow64_owned_backing_block, entry )
    {
        if (block->state != WOW64_OWNED_BACKING_INACTIVE || block->capacity < capacity)
            continue;
        if (!best || block->capacity < best->capacity) best = block;
    }
    return best;
}

static BOOL pool_can_activate( SIZE_T mapped_length )
{
    if (pool.active_capacity > WOW64_OWNED_BACKING_MAX_TOTAL) return FALSE;
    if (mapped_length > WOW64_OWNED_BACKING_MAX_TOTAL - pool.active_capacity)
        return FALSE;
    if (pool.active_blocks >= WOW64_OWNED_BACKING_MAX_BLOCKS) return FALSE;
    return TRUE;
}

static void quarantine_block( struct wow64_owned_backing_block *block, void *address,
                              UINT64 guest_address, SIZE_T capacity )
{
    block->address = address;
    block->guest_address = guest_address;
    block->capacity = capacity;
    block->mapped_length = 0;
    block->lease = 0;
    block->generation = 0;
    block->state = WOW64_OWNED_BACKING_QUARANTINED;
    list_add_tail( &pool.blocks, &block->entry );
    if (capacity <= WOW64_OWNED_BACKING_MAX_TOTAL - pool.total_capacity)
        pool.total_capacity += capacity;
    else
        pool.total_capacity = WOW64_OWNED_BACKING_MAX_TOTAL;
    ++pool.block_count;
}

static NTSTATUS acquire_backing( UINT64 length, UINT32 access,
                                 struct wine_unixlib_owned_backing_v2 *backing )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_owned_backing_block *block;
    UINT_PTR page_size = get_host_page_size();
    SIZE_T logical_length = length, mapped_length;
    UINT64 remaining, lease, generation;
    NTSTATUS status;

    if (backing) memset( backing, 0, sizeof(*backing) );
    if (!backing || !is_wow64() || !length ||
        (UINT64)logical_length != length || length > WOW64_OWNED_BACKING_MAX_ALLOCATION ||
        access != (WINE_WOW64_UNIXLIB_ACCESS_READ | WINE_WOW64_UNIXLIB_ACCESS_WRITE))
        return STATUS_INVALID_PARAMETER;
    if (page_size < 0x1000 || (page_size & (page_size - 1)) ||
        logical_length > ~(SIZE_T)0 - (page_size - 1))
        return STATUS_NOT_SUPPORTED;
    mapped_length = (logical_length + page_size - 1) & ~(page_size - 1);
    if (!mapped_length || mapped_length > WOW64_OWNED_BACKING_MAX_ALLOCATION)
        return STATUS_INVALID_PARAMETER;

    pthread_mutex_lock( &pool.mutex );
    if (!pool.next_lease || !pool.next_generation)
    {
        pthread_mutex_unlock( &pool.mutex );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (!pool_can_activate( mapped_length ))
    {
        pthread_mutex_unlock( &pool.mutex );
        return STATUS_QUOTA_EXCEEDED;
    }
    lease = pool.next_lease++;
    generation = pool.next_generation++;
    if ((block = find_inactive_block( mapped_length )))
    {
        block->state = WOW64_OWNED_BACKING_PREPARING;
        block->mapped_length = mapped_length;
        pool.active_capacity += mapped_length;
        ++pool.active_blocks;
    }
    else
    {
        remaining = pool.total_capacity <= WOW64_OWNED_BACKING_MAX_TOTAL ?
                    WOW64_OWNED_BACKING_MAX_TOTAL - pool.total_capacity : 0;
        if (pool.pending_capacity > remaining || mapped_length > remaining - pool.pending_capacity ||
            pool.block_count >= WOW64_OWNED_BACKING_MAX_BLOCKS ||
            pool.pending_blocks >= WOW64_OWNED_BACKING_MAX_BLOCKS - pool.block_count)
        {
            pthread_mutex_unlock( &pool.mutex );
            return STATUS_QUOTA_EXCEEDED;
        }
        pool.pending_capacity += mapped_length;
        ++pool.pending_blocks;
        pool.active_capacity += mapped_length;
        ++pool.active_blocks;
    }
    pthread_mutex_unlock( &pool.mutex );

    if (!block)
    {
        void *address = NULL;
        UINT64 guest_address = 0;
        SIZE_T capacity = mapped_length;

        if (!(block = calloc( 1, sizeof(*block) ))) status = STATUS_NO_MEMORY;
        else status = virtual_alloc_wow64_owned_backing( &address, &guest_address, &capacity );

        pthread_mutex_lock( &pool.mutex );
        --pool.pending_blocks;
        pool.pending_capacity -= mapped_length;
        if (status)
        {
            pool.active_capacity -= mapped_length;
            --pool.active_blocks;
            pthread_mutex_unlock( &pool.mutex );
            free( block );
            return status;
        }
        if (!address || !guest_address || capacity < mapped_length ||
            guest_address >= WINE_LOW_VA_SHADOW_SIZE ||
            capacity > WINE_LOW_VA_SHADOW_SIZE - guest_address ||
            (UINT64)(UINT_PTR)address != WINE_LOW_VA_SHADOW_BASE + guest_address ||
            ((UINT_PTR)address & (page_size - 1)) || (guest_address & (page_size - 1)) ||
            capacity > WOW64_OWNED_BACKING_MAX_TOTAL - pool.total_capacity)
        {
            /* Protected views are process-lifetime allocations.  Quarantine a
             * successfully published but invalid result instead of making it
             * reachable or forgetting that it consumes address space. */
            pool.active_capacity -= mapped_length;
            --pool.active_blocks;
            if (address && capacity)
                quarantine_block( block, address, guest_address, capacity );
            else
                free( block );
            pthread_mutex_unlock( &pool.mutex );
            ERR( "invalid translated WoW64 owned-backing view quarantined\n" );
            return STATUS_INTERNAL_ERROR;
        }
        block->address = address;
        block->guest_address = guest_address;
        block->capacity = capacity;
        block->mapped_length = mapped_length;
        block->state = WOW64_OWNED_BACKING_PREPARING;
        list_add_tail( &pool.blocks, &block->entry );
        pool.total_capacity += capacity;
        ++pool.block_count;
        pthread_mutex_unlock( &pool.mutex );
    }

    memset( block->address, 0, mapped_length );

    pthread_mutex_lock( &pool.mutex );
    if (!is_wow64() || block->state != WOW64_OWNED_BACKING_PREPARING ||
        block->mapped_length != mapped_length)
    {
        pool.active_capacity -= block->mapped_length;
        --pool.active_blocks;
        block->mapped_length = 0;
        block->state = WOW64_OWNED_BACKING_INACTIVE;
        pthread_mutex_unlock( &pool.mutex );
        return STATUS_INVALID_DEVICE_STATE;
    }
    block->lease = lease;
    block->generation = generation;
    block->state = WOW64_OWNED_BACKING_ACTIVE;
    pthread_mutex_unlock( &pool.mutex );

    backing->version = WINE_UNIXLIB_OWNED_BACKING_V2_VERSION;
    backing->size = sizeof(*backing);
    backing->address = (UINT_PTR)block->address;
    backing->length = length;
    backing->mapped_length = mapped_length;
    backing->lease = lease;
    backing->generation = generation;
    backing->guest_address = block->guest_address;
    return STATUS_SUCCESS;
#else
    (void)length;
    (void)access;
    if (backing) memset( backing, 0, sizeof(*backing) );
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS release_backing( UINT64 lease )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_owned_backing_block *block, *found = NULL;
    SIZE_T mapped_length;

    if (!lease) return STATUS_INVALID_HANDLE;
    pthread_mutex_lock( &pool.mutex );
    LIST_FOR_EACH_ENTRY( block, &pool.blocks, struct wow64_owned_backing_block, entry )
    {
        if (block->state == WOW64_OWNED_BACKING_ACTIVE && block->lease == lease)
        {
            found = block;
            break;
        }
    }
    if (!found)
    {
        pthread_mutex_unlock( &pool.mutex );
        return STATUS_INVALID_HANDLE;
    }
    found->state = WOW64_OWNED_BACKING_PREPARING;
    found->lease = 0;
    found->generation = 0;
    mapped_length = found->mapped_length;
    found->mapped_length = 0;
    pool.active_capacity -= mapped_length;
    --pool.active_blocks;
    pthread_mutex_unlock( &pool.mutex );

    discard_block_contents( found );

    pthread_mutex_lock( &pool.mutex );
    found->state = WOW64_OWNED_BACKING_INACTIVE;
    pthread_mutex_unlock( &pool.mutex );
    return STATUS_SUCCESS;
#else
    (void)lease;
    return STATUS_NOT_SUPPORTED;
#endif
}

static void wow64_owned_backing_cleanup(void) __attribute__((destructor));
static void wow64_owned_backing_cleanup(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_owned_backing_block *block, *next;

    pthread_mutex_lock( &pool.mutex );
    LIST_FOR_EACH_ENTRY_SAFE( block, next, &pool.blocks, struct wow64_owned_backing_block, entry )
    {
        list_remove( &block->entry );
        discard_block_contents( block );
        free( block );
    }
    list_init( &pool.blocks );
    pool.total_capacity = 0;
    pool.active_capacity = 0;
    pool.pending_capacity = 0;
    pool.block_count = 0;
    pool.active_blocks = 0;
    pool.pending_blocks = 0;
    pthread_mutex_unlock( &pool.mutex );
#endif
}

static const struct wine_unixlib_owned_backing_codec_v2 codec =
{
    WINE_UNIXLIB_OWNED_BACKING_CODEC_V2_VERSION,
    sizeof(codec),
#if defined(__APPLE__) && defined(__aarch64__)
    WINE_UNIXLIB_OWNED_BACKING_CAP_ACQUIRE_RELEASE,
#else
    0,
#endif
    acquire_backing,
    release_backing,
};

const struct wine_unixlib_owned_backing_codec_v2 *wow64_owned_backing_get_codec(void)
{
    return &codec;
}

#ifdef WINE_WOW64_OWNED_BACKING_NATIVE_TEST

#define TEST_MAX_MAPPINGS (WOW64_OWNED_BACKING_MAX_BLOCKS + 16)

static unsigned int test_failures;
static UINT_PTR test_page_size = 0x1000;
static UINT64 test_next_guest = 0x10000;
static void *test_mappings[TEST_MAX_MAPPINGS];
static SIZE_T test_mapping_sizes[TEST_MAX_MAPPINGS];
static unsigned int test_mapping_count;

WOW_PEB *wow_peb = (WOW_PEB *)1;
WORD native_machine;
ULONG_PTR user_space_wow_limit;
SECTION_IMAGE_INFORMATION main_image_info;

static void test_ok( BOOL condition, const char *message, NTSTATUS status )
{
    if (condition) return;
    fprintf( stderr, "%s", message );
    if (status) fprintf( stderr, " status %#x", (unsigned int)status );
    fputc( '\n', stderr );
    ++test_failures;
}

UINT_PTR get_host_page_size(void)
{
    return test_page_size;
}

NTSTATUS virtual_alloc_wow64_owned_backing( void **host_address, UINT64 *guest_address,
                                             SIZE_T *size )
{
    void *requested, *mapped;
    UINT64 guest;

    if (!host_address || !guest_address || !size || !*size) return STATUS_INVALID_PARAMETER;
    if (test_mapping_count >= TEST_MAX_MAPPINGS) return STATUS_QUOTA_EXCEEDED;

    guest = test_next_guest;
    if (guest >= WINE_LOW_VA_SHADOW_SIZE || *size > WINE_LOW_VA_SHADOW_SIZE - guest)
        return STATUS_QUOTA_EXCEEDED;
    requested = (void *)(UINT_PTR)(WINE_LOW_VA_SHADOW_BASE + guest);
    mapped = mmap( requested, *size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0 );
    if (mapped == MAP_FAILED) return STATUS_NO_MEMORY;
    if (mapped != requested)
    {
        munmap( mapped, *size );
        return STATUS_NO_MEMORY;
    }

    test_next_guest += *size + test_page_size;
    *host_address = mapped;
    *guest_address = guest;
    test_mappings[test_mapping_count] = mapped;
    test_mapping_sizes[test_mapping_count] = *size;
    ++test_mapping_count;
    return STATUS_SUCCESS;
}

static BOOL bytes_are_zero( const void *ptr, SIZE_T size )
{
    const unsigned char *bytes = ptr;
    SIZE_T i;

    for (i = 0; i < size; ++i) if (bytes[i]) return FALSE;
    return TRUE;
}

struct release_thread_params
{
    const struct wine_unixlib_owned_backing_codec_v2 *codec;
    UINT64 lease;
    NTSTATUS status;
};

static void *release_thread_proc( void *arg )
{
    struct release_thread_params *params = arg;

    params->status = params->codec->release_backing( params->lease );
    return NULL;
}

static void test_acquire_release_reuse(
    const struct wine_unixlib_owned_backing_codec_v2 *test_codec )
{
    struct wine_unixlib_owned_backing_v2 first, second;
    UINT64 first_lease, first_generation;
    NTSTATUS status;

    status = test_codec->acquire_backing( 17, WINE_WOW64_UNIXLIB_ACCESS_READ |
                                          WINE_WOW64_UNIXLIB_ACCESS_WRITE, &first );
    test_ok( status == STATUS_SUCCESS, "normal acquire failed", status );
    if (status) return;
    test_ok( first.version == WINE_UNIXLIB_OWNED_BACKING_V2_VERSION &&
             first.size == sizeof(first), "acquire returned malformed header", STATUS_SUCCESS );
    test_ok( first.length == 17 && first.mapped_length == test_page_size,
             "acquire returned wrong lengths", STATUS_SUCCESS );
    test_ok( first.address == WINE_LOW_VA_SHADOW_BASE + first.guest_address,
             "acquire returned mismatched high/guest addresses", STATUS_SUCCESS );
    test_ok( first.lease && first.generation, "acquire returned zero lease/generation",
             STATUS_SUCCESS );
    test_ok( bytes_are_zero( (void *)(UINT_PTR)first.address, first.mapped_length ),
             "acquire did not zero before publication", STATUS_SUCCESS );

    memset( (void *)(UINT_PTR)first.address, 0xa5, first.mapped_length );
    first_lease = first.lease;
    first_generation = first.generation;
    status = test_codec->release_backing( first.lease );
    test_ok( status == STATUS_SUCCESS, "release failed", status );
    status = test_codec->release_backing( first_lease );
    test_ok( status == STATUS_INVALID_HANDLE, "double release did not fail closed", status );

    status = test_codec->acquire_backing( 17, WINE_WOW64_UNIXLIB_ACCESS_READ |
                                          WINE_WOW64_UNIXLIB_ACCESS_WRITE, &second );
    test_ok( status == STATUS_SUCCESS, "reuse acquire failed", status );
    if (status) return;
    test_ok( second.lease && second.lease != first_lease &&
             second.generation && second.generation != first_generation,
             "reuse did not allocate a fresh nonzero lease/generation", STATUS_SUCCESS );
    test_ok( bytes_are_zero( (void *)(UINT_PTR)second.address, second.mapped_length ),
             "reuse did not zero before publication", STATUS_SUCCESS );
    status = test_codec->release_backing( second.lease );
    test_ok( status == STATUS_SUCCESS, "reuse release failed", status );
}

static void test_foreign_thread_exactly_once(
    const struct wine_unixlib_owned_backing_codec_v2 *test_codec )
{
    struct wine_unixlib_owned_backing_v2 backing;
    struct release_thread_params params[2];
    pthread_t threads[2];
    int thread_created[2];
    NTSTATUS status;

    status = test_codec->acquire_backing( test_page_size, WINE_WOW64_UNIXLIB_ACCESS_READ |
                                          WINE_WOW64_UNIXLIB_ACCESS_WRITE, &backing );
    test_ok( status == STATUS_SUCCESS, "foreign-thread acquire failed", status );
    if (status) return;

    params[0].codec = test_codec;
    params[0].lease = backing.lease;
    params[0].status = STATUS_PENDING;
    params[1] = params[0];
    thread_created[0] = !pthread_create( &threads[0], NULL, release_thread_proc, &params[0] );
    test_ok( thread_created[0],
             "first release thread creation failed", STATUS_SUCCESS );
    thread_created[1] = !pthread_create( &threads[1], NULL, release_thread_proc, &params[1] );
    test_ok( thread_created[1],
             "second release thread creation failed", STATUS_SUCCESS );
    if (thread_created[0]) pthread_join( threads[0], NULL );
    if (thread_created[1]) pthread_join( threads[1], NULL );
    if (!thread_created[0] || !thread_created[1])
    {
        if (thread_created[0] && params[0].status != STATUS_SUCCESS)
            test_codec->release_backing( backing.lease );
        else if (thread_created[1] && params[1].status != STATUS_SUCCESS)
            test_codec->release_backing( backing.lease );
        else if (!thread_created[0] && !thread_created[1])
            test_codec->release_backing( backing.lease );
        return;
    }
    test_ok( (params[0].status == STATUS_SUCCESS &&
              params[1].status == STATUS_INVALID_HANDLE) ||
             (params[1].status == STATUS_SUCCESS &&
              params[0].status == STATUS_INVALID_HANDLE),
             "foreign-thread release was not exactly once", STATUS_SUCCESS );
}

static void test_quota( const struct wine_unixlib_owned_backing_codec_v2 *test_codec )
{
    struct wine_unixlib_owned_backing_v2 backings[WOW64_OWNED_BACKING_MAX_BLOCKS];
    NTSTATUS status;
    unsigned int i;

    wow64_owned_backing_cleanup();

    status = test_codec->acquire_backing( WOW64_OWNED_BACKING_MAX_ALLOCATION + 1,
                                          WINE_WOW64_UNIXLIB_ACCESS_READ |
                                          WINE_WOW64_UNIXLIB_ACCESS_WRITE, &backings[0] );
    test_ok( status == STATUS_INVALID_PARAMETER, "oversized acquire did not fail closed", status );

    for (i = 0; i < WOW64_OWNED_BACKING_MAX_BLOCKS; ++i)
    {
        status = test_codec->acquire_backing( test_page_size,
                                              WINE_WOW64_UNIXLIB_ACCESS_READ |
                                              WINE_WOW64_UNIXLIB_ACCESS_WRITE,
                                              &backings[i] );
        if (status)
        {
            fprintf( stderr, "quota setup acquire %u failed status %#x\n",
                     i, (unsigned int)status );
            ++test_failures;
            break;
        }
    }
    if (i == WOW64_OWNED_BACKING_MAX_BLOCKS)
    {
        struct wine_unixlib_owned_backing_v2 extra;

        status = test_codec->acquire_backing( test_page_size,
                                              WINE_WOW64_UNIXLIB_ACCESS_READ |
                                              WINE_WOW64_UNIXLIB_ACCESS_WRITE, &extra );
        test_ok( status == STATUS_QUOTA_EXCEEDED, "block quota did not fail closed", status );
    }
    while (i) test_codec->release_backing( backings[--i].lease );
}

static void unmap_test_mappings(void)
{
    unsigned int i;

    for (i = 0; i < test_mapping_count; ++i)
        munmap( test_mappings[i], test_mapping_sizes[i] );
    test_mapping_count = 0;
}

int main(void)
{
    const struct wine_unixlib_owned_backing_codec_v2 *test_codec =
        wow64_owned_backing_get_codec();

    test_page_size = getpagesize();
    test_next_guest = (test_next_guest + test_page_size - 1) & ~(test_page_size - 1);

    test_ok( test_codec->version == WINE_UNIXLIB_OWNED_BACKING_CODEC_V2_VERSION &&
             test_codec->size == sizeof(*test_codec) &&
             test_codec->capabilities == WINE_UNIXLIB_OWNED_BACKING_CAP_ACQUIRE_RELEASE &&
             test_codec->acquire_backing && test_codec->release_backing,
             "codec header mismatch", STATUS_SUCCESS );
    test_acquire_release_reuse( test_codec );
    test_foreign_thread_exactly_once( test_codec );
    test_quota( test_codec );
    wow64_owned_backing_cleanup();
    unmap_test_mappings();
    return test_failures ? 1 : 0;
}

#endif
