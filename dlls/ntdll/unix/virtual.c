/*
 * Win32 virtual memory functions
 *
 * Copyright 1997, 2002, 2020 Alexandre Julliard
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
#pragma makedep unix
#endif

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SYSINFO_H
# include <sys/sysinfo.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_QUEUE_H
# include <sys/queue.h>
#endif
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#ifdef HAVE_LIBPROCSTAT_H
# include <libprocstat.h>
#endif
#include <unistd.h>
#include <dlfcn.h>
#ifdef HAVE_VALGRIND_VALGRIND_H
# include <valgrind/valgrind.h>
#endif
#if defined(__APPLE__)
#define host_page_size mac_host_page_size
# include <mach/mach_init.h>
# include <mach/mach_vm.h>
# include <mach/task.h>
# include <mach/thread_state.h>
# include <mach/vm_map.h>
#undef host_page_size
#endif

#if defined(HAVE_LINUX_USERFAULTFD_H) && defined(HAVE_LINUX_FS_H) && !defined(__ANDROID__)
# include <linux/userfaultfd.h>
# include <linux/fs.h>
#if defined(UFFD_FEATURE_WP_ASYNC) && defined(PM_SCAN_WP_MATCHING)
#define USE_UFFD_WRITEWATCH
#endif
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/list.h"
#include "wine/low_va.h"
#include "wine/rbtree.h"
#include "unix_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(virtual);
WINE_DECLARE_DEBUG_CHANNEL(module);
WINE_DECLARE_DEBUG_CHANNEL(virtual_ranges);

struct preload_info
{
    void  *addr;
    size_t size;
};

struct reserved_area
{
    struct list entry;
    void       *base;
    size_t      size;
};

static struct list reserved_areas = LIST_INIT(reserved_areas);

struct builtin_module
{
    struct list  entry;
    unsigned int refcount;
    void        *handle;
    void        *module;
    char        *unix_path;
    void        *unix_handle;
    unixlib_handle_t wow64_dispatch;
};

static struct list builtin_modules = LIST_INIT( builtin_modules );

struct file_view
{
    struct wine_rb_entry entry;  /* entry in global view tree */
    void         *base;          /* base address */
    size_t        size;          /* size in bytes */
    BOOL          wine_stack;   /* created by the Wine guarded-stack allocator */
    struct thread_data *stack_owner; /* opt-in E55 enrolled native stack */
    SIZE_T stack_commit_size; /* allocator request, retained for bounded demand-commit setup */
    ULONGLONG     allocation_id; /* never-reused identity for deferred native faults */
    unsigned int  protect;       /* protection for all pages at allocation time and SEC_* flags */
};

/* per-page protection flags */
#define VPROT_READ       0x01
#define VPROT_WRITE      0x02
#define VPROT_EXEC       0x04
#define VPROT_WRITECOPY  0x08
#define VPROT_GUARD      0x10
#define VPROT_COMMITTED  0x20
#define VPROT_WRITEWATCH 0x40
#define VPROT_COPIED     0x80
/* per-mapping protection flags */
#define VPROT_ARM64EC          0x0100  /* view may contain ARM64EC code */
#define VPROT_SYSTEM           0x0200  /* system view (underlying mmap not under our control) */
#define VPROT_PLACEHOLDER      0x0400
#define VPROT_FREE_PLACEHOLDER 0x0800
#define VPROT_WOW64_TRANSLATED 0x1000  /* view contains i386 guest memory in the Darwin shadow */
#define VPROT_AMD64_LOW_TRANSLATED 0x2000 /* fixed-low AMD64 image in the Darwin shadow */
#define VPROT_AMD64_IDENTITY   0x4000  /* identity-mapped AMD64 image fetched by the CPU provider */
#define VPROT_WOW64_OWNED_BACKING 0x8000 /* process-lifetime native resource backing */
#define VPROT_SHADOW_TRANSLATED (VPROT_WOW64_TRANSLATED | VPROT_AMD64_LOW_TRANSLATED)
#define VPROT_CPU_PROVIDER_OWNED (VPROT_SHADOW_TRANSLATED | VPROT_AMD64_IDENTITY)

static inline BOOL is_shadow_translated_vprot( unsigned int vprot )
{
    return !!(vprot & VPROT_SHADOW_TRANSLATED);
}

/* Conversion from VPROT_* to Win32 flags */
static const BYTE VIRTUAL_Win32Flags[16] =
{
    PAGE_NOACCESS,              /* 0 */
    PAGE_READONLY,              /* READ */
    PAGE_READWRITE,             /* WRITE */
    PAGE_READWRITE,             /* READ | WRITE */
    PAGE_EXECUTE,               /* EXEC */
    PAGE_EXECUTE_READ,          /* READ | EXEC */
    PAGE_EXECUTE_READWRITE,     /* WRITE | EXEC */
    PAGE_EXECUTE_READWRITE,     /* READ | WRITE | EXEC */
    PAGE_WRITECOPY,             /* WRITECOPY */
    PAGE_WRITECOPY,             /* READ | WRITECOPY */
    PAGE_WRITECOPY,             /* WRITE | WRITECOPY */
    PAGE_WRITECOPY,             /* READ | WRITE | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* READ | EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* WRITE | EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY      /* READ | WRITE | EXEC | WRITECOPY */
};

static struct wine_rb_tree views_tree;
static pthread_mutex_t virtual_mutex;
pthread_key_t thread_data_key = 0;

static const UINT page_shift = 12;
static const UINT_PTR page_mask = 0xfff;
static const UINT_PTR granularity_mask = 0xffff;

#ifdef __aarch64__
static UINT_PTR host_page_size;
static UINT_PTR host_page_mask;
#else
static const UINT_PTR host_page_size = 0x1000;
static const UINT_PTR host_page_mask = 0xfff;
#endif

/* Note: these are Windows limits, you cannot change them. */
#if defined(__i386__) || defined(__x86_64__)
static void *address_space_start = (void *)0x110000; /* keep DOS area clear */
#else
static void *address_space_start = (void *)0x10000;
#endif
#ifdef _WIN64
static void *address_space_limit = (void *)0x7fffffff0000;  /* top of the total available address space */
static void *user_space_limit    = (void *)0x7fffffff0000;  /* top of the user address space */
static void *working_set_limit   = (void *)0x7fffffff0000;  /* top of the current working set */
#else
static void *address_space_limit = (void *)0xc0000000;
static void *user_space_limit    = (void *)0x7fff0000;
static void *working_set_limit   = (void *)0x7fff0000;
#endif

static void *host_addr_space_limit;  /* top of the host virtual address space */

static struct file_view *arm64ec_view;

ULONG_PTR user_space_wow_limit = 0;
struct _KUSER_SHARED_DATA *user_shared_data = (void *)0x7ffe0000;

/* TEB allocation blocks */
static void *teb_block;
static void **next_free_teb;
static int teb_block_pos;
static struct list teb_list = LIST_INIT( teb_list );
#if defined(__APPLE__) && defined(__aarch64__)
/* Stabilize the selected TEB slot while the LOW observer gate is acquired
 * outside virtual_mutex.  The allocator lock is always outermost. */
static pthread_mutex_t teb_allocator_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#define ROUND_ADDR(addr,mask) ((void *)((UINT_PTR)(addr) & ~(UINT_PTR)(mask)))
#define ROUND_SIZE(addr,size,mask) (((SIZE_T)(size) + ((UINT_PTR)(addr) & (mask)) + (mask)) & ~(UINT_PTR)(mask))

#define VIRTUAL_DEBUG_DUMP_VIEW(view) do { if (TRACE_ON(virtual)) dump_view(view); } while (0)
#define VIRTUAL_DEBUG_DUMP_RANGES() do { if (TRACE_ON(virtual_ranges)) dump_free_ranges(); } while (0)

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

#ifdef _WIN64  /* on 64-bit the page protection bytes use a 2-level table */
static const size_t pages_vprot_shift = 20;
static const size_t pages_vprot_mask = (1 << 20) - 1;
static size_t pages_vprot_size;
static BYTE **pages_vprot;
#else  /* on 32-bit we use a simple array with one byte per page */
static BYTE *pages_vprot;
#endif

static int use_kernel_writewatch;
#ifdef USE_UFFD_WRITEWATCH
static int uffd_fd, pagemap_fd;
#endif

static struct file_view *view_block_start, *view_block_end, *next_free_view;
static ULONGLONG next_view_allocation_id;
static const size_t view_block_size = 0x100000;
static void *preload_reserve_start;
static void *preload_reserve_end;
static BOOL force_exec_prot;  /* whether to force PROT_EXEC on all PROT_READ mmaps */
static BOOL enable_write_exceptions;  /* raise exception on writes to executable memory */

struct range_entry
{
    void *base;
    void *end;
};

static struct range_entry *free_ranges;
static struct range_entry *free_ranges_end;


static inline BOOL is_beyond_limit( const void *addr, size_t size, const void *limit )
{
    return (addr >= limit || (const char *)addr + size > (const char *)limit);
}

static inline BOOL is_vprot_exec_write( BYTE vprot )
{
    return (vprot & VPROT_EXEC) && (vprot & (VPROT_WRITE | VPROT_WRITECOPY));
}

/* mmap() anonymous memory at a fixed address */
void *anon_mmap_fixed( void *start, size_t size, int prot, int flags )
{
    assert( !((UINT_PTR)start & host_page_mask) );
    assert( !(size & host_page_mask) );

    return mmap( start, size, prot, MAP_PRIVATE | MAP_ANON | MAP_FIXED | flags, -1, 0 );
}

/* allocate anonymous mmap() memory at any address */
void *anon_mmap_alloc( size_t size, int prot )
{
    assert( !(size & host_page_mask) );

    return mmap( NULL, size, prot, MAP_PRIVATE | MAP_ANON, -1, 0 );
}

#ifdef USE_UFFD_WRITEWATCH
static void kernel_writewatch_init(void)
{
    struct uffdio_api uffdio_api;

    uffd_fd = syscall( __NR_userfaultfd, O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY );
    if (uffd_fd == -1) return;

    uffdio_api.api = UFFD_API;
    uffdio_api.features = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_UNPOPULATED;
    if (ioctl( uffd_fd, UFFDIO_API, &uffdio_api ) || uffdio_api.api != UFFD_API)
    {
        close( uffd_fd );
        return;
    }
    pagemap_fd = open( "/proc/self/pagemap", O_CLOEXEC | O_RDONLY );
    if (pagemap_fd == -1)
    {
        ERR( "Error opening /proc/self/pagemap.\n" );
        close( uffd_fd );
        return;
    }
    use_kernel_writewatch = 1;
    TRACE( "Using kernel write watches.\n" );
}

static void kernel_writewatch_reset( void *start, SIZE_T len )
{
    struct pm_scan_arg arg = { 0 };

    len = ROUND_SIZE( start, len, host_page_mask );
    start = (char *)ROUND_ADDR( start, host_page_mask );

    arg.size = sizeof(arg);
    arg.start = (UINT_PTR)start;
    arg.end = arg.start + len;
    arg.flags = PM_SCAN_WP_MATCHING;
    arg.category_mask = PAGE_IS_WRITTEN;
    arg.return_mask = PAGE_IS_WRITTEN;
    if (ioctl( pagemap_fd, PAGEMAP_SCAN, &arg ) < 0)
        ERR( "ioctl(PAGEMAP_SCAN) failed, err %s.\n", strerror(errno) );
}

static void kernel_writewatch_register_range( struct file_view *view, void *base, size_t size )
{
    struct uffdio_register uffdio_register;
    struct uffdio_writeprotect wp;

    if (!(view->protect & VPROT_WRITEWATCH) || !use_kernel_writewatch) return;

    size = ROUND_SIZE( base, size, host_page_mask );
    base = (char *)ROUND_ADDR( base, host_page_mask );

    /* Transparent huge pages will result in larger areas reported as dirty. */
    madvise( base, size, MADV_NOHUGEPAGE );

    uffdio_register.range.start = (UINT_PTR)base;
    uffdio_register.range.len = size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;
    if (ioctl( uffd_fd, UFFDIO_REGISTER, &uffdio_register ) == -1)
    {
        ERR( "ioctl( UFFDIO_REGISTER ) failed, %s.\n", strerror(errno) );
        return;
    }

    if (!(uffdio_register.ioctls & UFFDIO_WRITEPROTECT))
    {
        ERR( "uffdio_register.ioctls %s.\n", wine_dbgstr_longlong(uffdio_register.ioctls) );
        return;
    }
    wp.range.start = (UINT_PTR)base;
    wp.range.len = size;
    wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;

    if (ioctl( uffd_fd, UFFDIO_WRITEPROTECT, &wp ) == -1)
        ERR( "ioctl( UFFDIO_WRITEPROTECT ) failed, %s.\n", strerror(errno) );
}

static void kernel_get_write_watches( void *base, SIZE_T size, void **buffer, ULONG_PTR *count, BOOL reset )
{
    struct pm_scan_arg arg = { 0 };
    struct page_region rgns[256];
    SIZE_T buffer_len = *count;
    char *addr, *next_addr;
    int rgn_count, i;
    size_t end, granularity = host_page_size / page_size;

    assert( !(size & page_mask) );

    end = (size_t)((char *)base + size);
    size = ROUND_SIZE( base, size, host_page_mask );
    addr = (char *)ROUND_ADDR( base, host_page_mask );

    arg.size = sizeof(arg);
    arg.vec = (ULONG_PTR)rgns;
    arg.vec_len = ARRAY_SIZE(rgns);
    if (reset) arg.flags |= PM_SCAN_WP_MATCHING;
    arg.category_mask = PAGE_IS_WRITTEN;
    arg.return_mask = PAGE_IS_WRITTEN;

    *count = 0;
    while (1)
    {
        arg.start = (UINT_PTR)addr;
        arg.end = arg.start + size;
        arg.max_pages = (buffer_len + granularity - 1) / granularity;

        if ((rgn_count = ioctl( pagemap_fd, PAGEMAP_SCAN, &arg )) < 0)
        {
            ERR( "ioctl( PAGEMAP_SCAN ) failed, error %s.\n", strerror(errno) );
            return;
        }
        if (!rgn_count) break;

        assert( rgn_count <= ARRAY_SIZE(rgns) );
        for (i = 0; i < rgn_count; ++i)
        {
            size_t c_addr = max( rgns[i].start, (size_t)base );

            rgns[i].end = min( rgns[i].end, end );
            assert( rgns[i].categories == PAGE_IS_WRITTEN );
            while (buffer_len && c_addr < rgns[i].end)
            {
                buffer[(*count)++] = (void *)c_addr;
                --buffer_len;
                c_addr += page_size;
            }
            if (!buffer_len) break;
        }
        if (!buffer_len || rgn_count < arg.vec_len) break;
        next_addr = (char *)(ULONG_PTR)arg.walk_end;
        assert( size >= next_addr - addr );
        if (!(size -= next_addr - addr)) break;
        addr = next_addr;
    }
}
#else
static void kernel_writewatch_init(void)
{
}

static void kernel_writewatch_reset( void *start, SIZE_T len )
{
}

static void kernel_writewatch_register_range( struct file_view *view, void *base, size_t size )
{
}

static void kernel_get_write_watches( void *base, SIZE_T size, void **buffer, ULONG_PTR *count, BOOL reset )
{
    assert( 0 );
}
#endif

static void mmap_add_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr, *next;
    void *end, *area_end;

    assert( !((UINT_PTR)addr & host_page_mask) );
    assert( !(size & host_page_mask) );

    if (!((intptr_t)addr + size)) size--;  /* avoid wrap-around */
    end = (char *)addr + size;

    LIST_FOR_EACH( ptr, &reserved_areas )
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        area_end = (char *)area->base + area->size;

        if (area->base > end) break;
        if (area_end < addr) continue;
        if (area->base > addr)
        {
            area->size += (char *)area->base - (char *)addr;
            area->base = addr;
        }
        if (area_end >= end) return;

        /* try to merge with the following ones */
        while ((next = list_next( &reserved_areas, ptr )))
        {
            struct reserved_area *area_next = LIST_ENTRY( next, struct reserved_area, entry );
            void *next_end = (char *)area_next->base + area_next->size;

            if (area_next->base > end) break;
            list_remove( next );
            free( area_next );
            if (next_end >= end)
            {
                end = next_end;
                break;
            }
        }
        area->size = (char *)end - (char *)area->base;
        return;
    }

    if ((area = malloc( sizeof(*area) )))
    {
        area->base = addr;
        area->size = size;
        list_add_before( ptr, &area->entry );
    }
}

static void mmap_remove_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr;

    assert( !((UINT_PTR)addr & host_page_mask) );
    assert( !(size & host_page_mask) );

    if (!((intptr_t)addr + size)) size--;  /* avoid wrap-around */

    ptr = list_head( &reserved_areas );
    /* find the first area covering address */
    while (ptr)
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        if ((char *)area->base >= (char *)addr + size) break;  /* outside the range */
        if ((char *)area->base + area->size > (char *)addr)  /* overlaps range */
        {
            if (area->base >= addr)
            {
                if ((char *)area->base + area->size > (char *)addr + size)
                {
                    /* range overlaps beginning of area only -> shrink area */
                    area->size -= (char *)addr + size - (char *)area->base;
                    area->base = (char *)addr + size;
                    break;
                }
                else
                {
                    /* range contains the whole area -> remove area completely */
                    ptr = list_next( &reserved_areas, ptr );
                    list_remove( &area->entry );
                    free( area );
                    continue;
                }
            }
            else
            {
                if ((char *)area->base + area->size > (char *)addr + size)
                {
                    /* range is in the middle of area -> split area in two */
                    struct reserved_area *new_area = malloc( sizeof(*new_area) );
                    if (new_area)
                    {
                        new_area->base = (char *)addr + size;
                        new_area->size = (char *)area->base + area->size - (char *)new_area->base;
                        list_add_after( ptr, &new_area->entry );
                    }
                    area->size = (char *)addr - (char *)area->base;
                    break;
                }
                else
                {
                    /* range overlaps end of area only -> shrink area */
                    area->size = (char *)addr - (char *)area->base;
                }
            }
        }
        ptr = list_next( &reserved_areas, ptr );
    }
}

static int mmap_is_in_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        if (area->base > addr) break;
        if ((char *)area->base + area->size <= (char *)addr) continue;
        /* area must contain block completely */
        if ((char *)area->base + area->size < (char *)addr + size) return -1;
        return 1;
    }
    return 0;
}


/***********************************************************************
 *           unmap_area_above_user_limit
 *
 * Unmap memory that's above the user space limit, by replacing it with an empty mapping,
 * and return the remaining size below the limit. virtual_mutex must be held by caller.
 */
static size_t unmap_area_above_user_limit( void *addr, size_t size )
{
    size_t ret = 0;

    if (addr < user_space_limit)
    {
        ret = (char *)user_space_limit - (char *)addr;
        if (ret >= size) return size;  /* nothing is above limit */
        size -= ret;
        addr = user_space_limit;
    }
    anon_mmap_fixed( addr, size, PROT_NONE, MAP_NORESERVE );
    mmap_add_reserved_area( addr, size );
    return ret;
}


static void *anon_mmap_tryfixed( void *start, size_t size, int prot, int flags )
{
    void *ptr;

#ifdef MAP_FIXED_NOREPLACE
    ptr = mmap( start, size, prot, MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#elif defined(MAP_TRYFIXED)
    ptr = mmap( start, size, prot, MAP_TRYFIXED | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
    ptr = mmap( start, size, prot, MAP_FIXED | MAP_EXCL | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
    if (ptr == MAP_FAILED && errno == EINVAL) errno = EEXIST;
#elif defined(__APPLE__)
    mach_vm_address_t result = (mach_vm_address_t)start;
    kern_return_t ret = mach_vm_map( mach_task_self(), &result, size, 0, VM_FLAGS_FIXED,
                                     MEMORY_OBJECT_NULL, 0, 0, prot, VM_PROT_ALL, VM_INHERIT_COPY );

    if (!ret)
    {
        if ((ptr = anon_mmap_fixed( start, size, prot, flags )) == MAP_FAILED)
            mach_vm_deallocate( mach_task_self(), result, size );
    }
    else
    {
        errno = (ret == KERN_NO_SPACE ? EEXIST : ENOMEM);
        ptr = MAP_FAILED;
    }
#else
    ptr = mmap( start, size, prot, MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#endif
    if (ptr != MAP_FAILED && ptr != start)
    {
        size = unmap_area_above_user_limit( ptr, size );
        if (size) munmap( ptr, size );
        ptr = MAP_FAILED;
        errno = EEXIST;
    }
    return ptr;
}

static void reserve_area( void *addr, void *end )
{
#ifdef __APPLE__

#ifdef __i386__
    static const mach_vm_address_t max_address = VM_MAX_ADDRESS;
#else
    static const mach_vm_address_t max_address = MACH_VM_MAX_ADDRESS;
#endif
    mach_vm_address_t address = (mach_vm_address_t)addr;
    mach_vm_address_t end_address = (mach_vm_address_t)end;

    if (!end_address || max_address < end_address)
        end_address = max_address;

    while (address < end_address)
    {
        mach_vm_address_t hole_address = address;
        kern_return_t ret;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t dummy_object_name = MACH_PORT_NULL;

        /* find the mapped region at or above the current address. */
        ret = mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&info, &count, &dummy_object_name);
        if (ret != KERN_SUCCESS)
        {
            address = max_address;
            size = 0;
        }

        if (end_address < address)
            address = end_address;
        if (hole_address < address)
        {
            /* found a hole, attempt to reserve it. */
            size_t hole_size = address - hole_address;
            mach_vm_address_t alloc_address = hole_address;

            ret = mach_vm_map( mach_task_self(), &alloc_address, hole_size, 0, VM_FLAGS_FIXED,
                               MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
            if (!ret) mmap_add_reserved_area( (void*)hole_address, hole_size );
            else if (ret == KERN_NO_SPACE)
            {
                /* something filled (part of) the hole before we could.
                   go back and look again. */
                address = hole_address;
                continue;
            }
        }
        address += size;
    }
#else
    size_t size = (char *)end - (char *)addr;

    if (!size) return;

    if (anon_mmap_tryfixed( addr, size, PROT_NONE, MAP_NORESERVE ) != MAP_FAILED)
    {
        mmap_add_reserved_area( addr, size );
        return;
    }
    size = (size / 2) & ~granularity_mask;
    if (size)
    {
        reserve_area( addr, (char *)addr + size );
        reserve_area( (char *)addr + size, end );
    }
#endif /* __APPLE__ */
}


static void mmap_init( const struct preload_info *preload_info )
{
#ifndef _WIN64
#ifndef __APPLE__
    char stack;
    char * const stack_ptr = &stack;
#endif
    char *user_space_limit = (char *)0x7ffe0000;
    int i;

    if (preload_info)
    {
        /* check for a reserved area starting at the user space limit */
        /* to avoid wasting time trying to allocate it again */
        for (i = 0; preload_info[i].size; i++)
        {
            if ((char *)preload_info[i].addr > user_space_limit) break;
            if ((char *)preload_info[i].addr + preload_info[i].size > user_space_limit)
            {
                user_space_limit = (char *)preload_info[i].addr + preload_info[i].size;
                break;
            }
        }
    }
    else reserve_area( (void *)0x00010000, (void *)0x40000000 );


#ifndef __APPLE__
    if (stack_ptr >= user_space_limit)
    {
        char *end = 0;
        char *base = stack_ptr - ((unsigned int)stack_ptr & granularity_mask) - (granularity_mask + 1);
        if (base > user_space_limit) reserve_area( user_space_limit, base );
        base = stack_ptr - ((unsigned int)stack_ptr & granularity_mask) + (granularity_mask + 1);
#if defined(linux) || defined(__FreeBSD__) || defined (__FreeBSD_kernel__) || defined(__DragonFly__)
        /* Heuristic: assume the stack is near the end of the address */
        /* space, this avoids a lot of futile allocation attempts */
        end = (char *)(((unsigned long)base + 0x0fffffff) & 0xf0000000);
#endif
        reserve_area( base, end );
    }
    else
#endif
        reserve_area( user_space_limit, 0 );

#else

    if (preload_info) return;
    /* if we don't have a preloader, try to reserve the space now */
    reserve_area( (void *)0x000000010000, (void *)0x000068000000 );
    reserve_area( (void *)0x00007f000000, (void *)0x00007fff0000 );
    reserve_area( (void *)0x7ffffe000000, (void *)0x7fffffff0000 );

#endif
}


/***********************************************************************
 *           get_wow_user_space_limit
 */
static ULONG_PTR get_wow_user_space_limit(void)
{
#ifdef _WIN64
    return user_space_wow_limit & ~granularity_mask;
#endif
    return (ULONG_PTR)user_space_limit;
}

#if defined(__APPLE__) && defined(__aarch64__)
#define WOW64_MEMORY_INLINE_RANGES 8
#define ARM64EC_LOW_MEMORY_INLINE_RANGES 8
#define ARM64EC_CODE_INLINE_RANGES 8

C_ASSERT( sizeof(struct wine_wow64_memory_range_v1) == 40 );
C_ASSERT( sizeof(struct wine_wow64_memory_event_v1) == 72 );
C_ASSERT( sizeof(struct wine_wow64_memory_observer_v1) == 40 );
C_ASSERT( sizeof(struct wine_arm64ec_low_memory_range_v1) == 40 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_range_v1, host_address) == 0 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_range_v1, size) == 8 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_range_v1, host_allocation_base) == 16 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_range_v1, state) == 24 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_range_v1, protect) == 28 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_range_v1, flags) == 32 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_range_v1, reserved) == 36 );
C_ASSERT( sizeof(struct wine_arm64ec_low_memory_event_v1) == 72 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, version) == 0 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, size) == 4 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, operation) == 8 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, flags) == 12 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, status) == 16 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, snapshot_status) == 20 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, reserved) == 24 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, host_address) == 32 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, size_covered) == 40 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, host_allocation_base) == 48 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, ranges) == 56 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_event_v1, range_count) == 64 );
C_ASSERT( sizeof(struct wine_arm64ec_low_memory_observer_v1) == 40 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_observer_v1, version) == 0 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_observer_v1, size) == 4 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_observer_v1, context) == 8 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_observer_v1, begin) == 16 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_observer_v1, complete) == 24 );
C_ASSERT( offsetof(struct wine_arm64ec_low_memory_observer_v1, capabilities) == 32 );
C_ASSERT( sizeof(struct wine_arm64ec_code_range_v1) == 16 );
C_ASSERT( offsetof(struct wine_arm64ec_code_range_v1, address) == 0 );
C_ASSERT( offsetof(struct wine_arm64ec_code_range_v1, size) == 8 );
C_ASSERT( sizeof(struct wine_arm64ec_code_event_v1) == 40 );
C_ASSERT( offsetof(struct wine_arm64ec_code_event_v1, version) == 0 );
C_ASSERT( offsetof(struct wine_arm64ec_code_event_v1, size) == 4 );
C_ASSERT( offsetof(struct wine_arm64ec_code_event_v1, operation) == 8 );
C_ASSERT( offsetof(struct wine_arm64ec_code_event_v1, flags) == 12 );
C_ASSERT( offsetof(struct wine_arm64ec_code_event_v1, status) == 16 );
C_ASSERT( offsetof(struct wine_arm64ec_code_event_v1, reserved) == 20 );
C_ASSERT( offsetof(struct wine_arm64ec_code_event_v1, ranges) == 24 );
C_ASSERT( offsetof(struct wine_arm64ec_code_event_v1, range_count) == 32 );
C_ASSERT( sizeof(struct wine_arm64ec_code_observer_v1) == 40 );
C_ASSERT( offsetof(struct wine_arm64ec_code_observer_v1, version) == 0 );
C_ASSERT( offsetof(struct wine_arm64ec_code_observer_v1, size) == 4 );
C_ASSERT( offsetof(struct wine_arm64ec_code_observer_v1, context) == 8 );
C_ASSERT( offsetof(struct wine_arm64ec_code_observer_v1, begin) == 16 );
C_ASSERT( offsetof(struct wine_arm64ec_code_observer_v1, complete) == 24 );
C_ASSERT( offsetof(struct wine_arm64ec_code_observer_v1, capabilities) == 32 );
C_ASSERT( sizeof(struct wine_wow64_memory_fault_result_v1) == 48 );

struct wow64_memory_transaction
{
    struct wine_wow64_memory_event_v1 event;
    struct wine_wow64_memory_range_v1 *ranges;
    struct wine_wow64_memory_range_v1 inline_ranges[WOW64_MEMORY_INLINE_RANGES];
    SIZE_T range_capacity;
    const struct wine_wow64_memory_observer_v1 *observer;
    void *observer_transaction;
    BOOL gate_locked;
    BOOL observer_begun;
    BOOL nested;
};

static pthread_mutex_t wow64_memory_observer_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct wine_wow64_memory_observer_v1 wow64_memory_observer;
static BOOL wow64_memory_observer_registered;
static BOOL wow64_memory_observer_required;
static BOOL wow64_memory_logical_write_fault_delegated;
static __thread struct wow64_memory_transaction *wow64_memory_current_transaction;
static __thread BOOL wow64_memory_observer_callback_active;

struct arm64ec_low_memory_transaction
{
    struct wine_arm64ec_low_memory_event_v1 event;
    struct wine_arm64ec_low_memory_range_v1 *ranges;
    struct wine_arm64ec_low_memory_range_v1 inline_ranges[ARM64EC_LOW_MEMORY_INLINE_RANGES];
    SIZE_T range_capacity;
    const struct wine_arm64ec_low_memory_observer_v1 *observer;
    void *observer_transaction;
    BOOL gate_locked;
    BOOL observer_begun;
    BOOL nested;
    BOOL allow_exact_nested;
};

static pthread_mutex_t arm64ec_low_memory_observer_mutex; /* initialized recursively in virtual_init */
static struct wine_arm64ec_low_memory_observer_v1 arm64ec_low_memory_observer;
static BOOL arm64ec_low_memory_observer_registered;
static BOOL arm64ec_low_memory_observer_required;
static __thread struct arm64ec_low_memory_transaction *arm64ec_low_memory_current_transaction;
static __thread BOOL arm64ec_low_memory_observer_callback_active;

struct arm64ec_code_transaction
{
    struct wine_arm64ec_code_event_v1 event;
    struct wine_arm64ec_code_range_v1 *ranges;
    struct wine_arm64ec_code_range_v1 inline_ranges[ARM64EC_CODE_INLINE_RANGES];
    SIZE_T range_capacity;
    const struct wine_arm64ec_code_observer_v1 *observer;
    void *observer_transaction;
    BOOL gate_locked;
    BOOL observer_begun;
    BOOL nested;
};

static pthread_mutex_t arm64ec_code_observer_mutex; /* initialized recursively in virtual_init */
static struct wine_arm64ec_code_observer_v1 arm64ec_code_observer;
static BOOL arm64ec_code_observer_registered;
static BOOL arm64ec_code_observer_required;
static BOOL arm64ec_cpu_alias_enabled;
static BOOL arm64ec_stack_probe_enabled;
static BOOL arm64ec_stack_auto_enabled;
static __thread BOOL arm64ec_mapping_snapshot_locked;
static BOOL arm64ec_high_data_view( struct file_view *view );
static __thread struct arm64ec_code_transaction *arm64ec_code_current_transaction;
static __thread BOOL arm64ec_code_observer_callback_active;

static inline BOOL is_wow64_shadow_address( const void *address )
{
    ULONG_PTR value = (ULONG_PTR)address;

    return value >= WINE_LOW_VA_SHADOW_BASE &&
           value - WINE_LOW_VA_SHADOW_BASE < WINE_LOW_VA_SHADOW_SIZE;
}

static inline BOOL is_inside_wow64_shadow( const void *address, SIZE_T size )
{
    ULONG_PTR value = (ULONG_PTR)address;

    return is_wow64_shadow_address( address ) &&
           size <= WINE_LOW_VA_SHADOW_SIZE - (value - WINE_LOW_VA_SHADOW_BASE);
}

static inline BOOL overlaps_wow64_shadow( const void *address, SIZE_T size )
{
    ULONG_PTR value = (ULONG_PTR)address;

    if (!size || value >= WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE) return FALSE;
    if (value >= WINE_LOW_VA_SHADOW_BASE) return TRUE;
    return size > WINE_LOW_VA_SHADOW_BASE - value;
}

static inline BOOL limits_are_inside_wow64_shadow( ULONG_PTR limit_low, ULONG_PTR limit_high )
{
    return limit_low >= WINE_LOW_VA_SHADOW_BASE &&
           limit_high >= limit_low &&
           limit_high - WINE_LOW_VA_SHADOW_BASE < WINE_LOW_VA_SHADOW_SIZE;
}

/* Normalize an address supplied by an ARM64EC/x64 VM operation to the host
 * window observed by the AMD64-low provider.  Numeric membership only selects
 * the serialization gate; the VPROT tag remains the ownership authority. */
static BOOL get_arm64ec_low_candidate_range( const void *address, SIZE_T size,
                                              void **host_address )
{
    ULONG_PTR value = (ULONG_PTR)address;

    if (!is_arm64ec() || !address) return FALSE;
    if (value < WINE_LOW_VA_SHADOW_SIZE)
    {
        if (size > WINE_LOW_VA_SHADOW_SIZE - value) return FALSE;
        *host_address = (void *)(WINE_LOW_VA_SHADOW_BASE + value);
        return TRUE;
    }
    if (!is_inside_wow64_shadow( address, size )) return FALSE;
    *host_address = (void *)address;
    return TRUE;
}

static NTSTATUS allocate_wow64_shadow_memory( void **address, SIZE_T *size,
                                              ULONG type, ULONG protect );
static NTSTATUS wow64_memory_set_logical_write_fault_delegation( BOOL enable );

static inline BOOL wow64_memory_observer_is_required(void)
{
    return __atomic_load_n( &wow64_memory_observer_required, __ATOMIC_ACQUIRE );
}

static inline BOOL wow64_memory_logical_write_fault_is_delegated(void)
{
    return __atomic_load_n( &wow64_memory_logical_write_fault_delegated,
                            __ATOMIC_ACQUIRE );
}

static inline void wow64_memory_assert_transaction(void)
{
    assert( !wow64_memory_observer_is_required() || wow64_memory_current_transaction );
}

static NTSTATUS wow64_memory_begin_transaction( struct wow64_memory_transaction *transaction,
                                                 BOOL candidate, ULONG operation,
                                                 const void *address, SIZE_T size,
                                                 const void *allocation_base )
{
    NTSTATUS status = STATUS_SUCCESS;

    memset( transaction, 0, sizeof(*transaction) );
    transaction->ranges = transaction->inline_ranges;
    transaction->range_capacity = ARRAY_SIZE(transaction->inline_ranges);
    if (!candidate) return STATUS_SUCCESS;
    if (wow64_memory_observer_callback_active)
    {
        ERR( "translated memory mutation from observer callback\n" );
        return STATUS_INVALID_PARAMETER;
    }
    if (wow64_memory_current_transaction)
    {
        transaction->nested = TRUE;
        return STATUS_SUCCESS;
    }

    mutex_lock( &wow64_memory_observer_mutex );
    transaction->gate_locked = TRUE;
    transaction->event.version = WINE_WOW64_MEMORY_OBSERVER_VERSION;
    transaction->event.size = sizeof(transaction->event);
    transaction->event.operation = operation;
    transaction->event.address = (ULONG_PTR)address;
    transaction->event.size_covered = size;
    transaction->event.allocation_base = (ULONG_PTR)allocation_base;

    if (wow64_memory_observer_registered)
    {
        transaction->observer = &wow64_memory_observer;
        wow64_memory_observer_callback_active = TRUE;
        status = transaction->observer->begin( transaction->observer->context, operation,
                                               (ULONG_PTR)address, size,
                                               (ULONG_PTR)allocation_base,
                                               &transaction->observer_transaction );
        wow64_memory_observer_callback_active = FALSE;
        if (status)
        {
            transaction->gate_locked = FALSE;
            mutex_unlock( &wow64_memory_observer_mutex );
            return status;
        }
        transaction->observer_begun = TRUE;
    }
    wow64_memory_current_transaction = transaction;
    return STATUS_SUCCESS;
}

static void wow64_memory_complete_transaction( struct wow64_memory_transaction *transaction )
{
    if (transaction->nested || !transaction->gate_locked) return;

    assert( wow64_memory_current_transaction == transaction );
    wow64_memory_current_transaction = NULL;
    if (transaction->observer_begun)
    {
        transaction->event.ranges = transaction->ranges;
        wow64_memory_observer_callback_active = TRUE;
        transaction->observer->complete( transaction->observer->context,
                                         transaction->observer_transaction,
                                         &transaction->event );
        wow64_memory_observer_callback_active = FALSE;
    }
    if (transaction->ranges != transaction->inline_ranges) free( transaction->ranges );
    transaction->gate_locked = FALSE;
    mutex_unlock( &wow64_memory_observer_mutex );
}

static inline BOOL arm64ec_low_memory_observer_is_required(void)
{
    return __atomic_load_n( &arm64ec_low_memory_observer_required, __ATOMIC_ACQUIRE );
}

static inline void arm64ec_low_memory_assert_transaction(void)
{
    assert( !arm64ec_low_memory_observer_is_required() ||
            arm64ec_low_memory_current_transaction );
}

static inline BOOL arm64ec_code_observer_is_required(void)
{
    return __atomic_load_n( &arm64ec_code_observer_required, __ATOMIC_ACQUIRE );
}

static BOOL arm64ec_code_range_is_low_observer_owned( const void *address, SIZE_T size )
{
    ULONG_PTR start = (ULONG_PTR)address;
    const ULONG_PTR shadow_start = WINE_LOW_VA_SHADOW_BASE;
    const ULONG_PTR shadow_end = WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE;

    return arm64ec_low_memory_current_transaction && start >= shadow_start &&
           start < shadow_end && size <= shadow_end - start;
}

static inline void arm64ec_code_assert_transaction( const void *address, SIZE_T size )
{
    assert( !arm64ec_code_observer_is_required() || arm64ec_code_current_transaction ||
            arm64ec_code_range_is_low_observer_owned( address, size ) );
}

static NTSTATUS arm64ec_code_begin_transaction(
    struct arm64ec_code_transaction *transaction, BOOL candidate, ULONG operation )
{
    NTSTATUS status = STATUS_SUCCESS;

    memset( transaction, 0, sizeof(*transaction) );
    transaction->ranges = transaction->inline_ranges;
    transaction->range_capacity = ARRAY_SIZE(transaction->inline_ranges);
    if (!candidate) return STATUS_SUCCESS;
    if (arm64ec_code_observer_callback_active ||
        arm64ec_low_memory_observer_callback_active)
    {
        ERR( "ARM64EC code mutation from observer callback\n" );
        return STATUS_INVALID_PARAMETER;
    }
    if (arm64ec_low_memory_current_transaction)
    {
        ERR( "ARM64EC code mutation overlaps AMD64-low observer transaction\n" );
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (arm64ec_code_current_transaction)
    {
        transaction->nested = TRUE;
        arm64ec_code_current_transaction->event.flags |=
            WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION;
        return STATUS_SUCCESS;
    }

    mutex_lock( &arm64ec_code_observer_mutex );
    transaction->gate_locked = TRUE;
    transaction->event.version = WINE_ARM64EC_CODE_OBSERVER_VERSION;
    transaction->event.size = sizeof(transaction->event);
    transaction->event.operation = operation;

    if (arm64ec_code_observer_registered)
    {
        transaction->observer = &arm64ec_code_observer;
        arm64ec_code_observer_callback_active = TRUE;
        status = transaction->observer->begin( transaction->observer->context,
                                               operation,
                                               &transaction->observer_transaction );
        arm64ec_code_observer_callback_active = FALSE;
        if (status)
        {
            transaction->gate_locked = FALSE;
            mutex_unlock( &arm64ec_code_observer_mutex );
            return status;
        }
        transaction->observer_begun = TRUE;
    }
    arm64ec_code_current_transaction = transaction;
    return STATUS_SUCCESS;
}

static int arm64ec_code_compare_range( const void *left, const void *right )
{
    const struct wine_arm64ec_code_range_v1 *a = left, *b = right;

    if (a->address < b->address) return -1;
    if (a->address > b->address) return 1;
    if (a->size < b->size) return -1;
    if (a->size > b->size) return 1;
    return 0;
}

static void arm64ec_code_normalize_ranges( struct arm64ec_code_transaction *transaction )
{
    SIZE_T i, out = 0, count = transaction->event.range_count;

    if (transaction->event.flags & WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION)
    {
        transaction->event.range_count = 0;
        return;
    }
    qsort( transaction->ranges, count, sizeof(*transaction->ranges),
           arm64ec_code_compare_range );
    for (i = 0; i < count; ++i)
    {
        struct wine_arm64ec_code_range_v1 *range = &transaction->ranges[i];

        if (out)
        {
            struct wine_arm64ec_code_range_v1 *previous = &transaction->ranges[out - 1];
            uint64_t previous_end = previous->address + previous->size;
            uint64_t range_end = range->address + range->size;

            if (range->address <= previous_end)
            {
                if (range_end > previous_end) previous->size = range_end - previous->address;
                continue;
            }
        }
        transaction->ranges[out++] = *range;
    }
    transaction->event.range_count = out;
}

static void arm64ec_code_record_range( const void *address, SIZE_T size )
{
    struct arm64ec_code_transaction *transaction = arm64ec_code_current_transaction;
    struct wine_arm64ec_code_range_v1 *ranges;
    ULONG_PTR start = (ULONG_PTR)address, end;
    SIZE_T count, capacity;

    arm64ec_code_assert_transaction( address, size );
    if (!transaction ||
        (transaction->event.flags & WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION))
        return;
    if (!size || start >= WINE_ARM64EC_CODE_POINTER_LIMIT ||
        size > WINE_ARM64EC_CODE_POINTER_LIMIT - start ||
        size > ~(ULONG_PTR)0 - start)
        goto full_invalidation;
    end = start + size;
    start &= ~page_mask;
    if (end > ~(ULONG_PTR)0 - page_mask) goto full_invalidation;
    end = (end + page_mask) & ~page_mask;
    if (end <= start || end > WINE_ARM64EC_CODE_POINTER_LIMIT)
        goto full_invalidation;

    count = transaction->event.range_count;
    if (count == transaction->range_capacity)
    {
        capacity = transaction->range_capacity ? transaction->range_capacity * 2 : 16;
        if (capacity < transaction->range_capacity ||
            capacity > ~(SIZE_T)0 / sizeof(*ranges))
            goto full_invalidation;
        if (transaction->ranges == transaction->inline_ranges)
        {
            if (!(ranges = malloc( capacity * sizeof(*ranges) )))
                goto full_invalidation;
            memcpy( ranges, transaction->inline_ranges,
                    count * sizeof(*transaction->inline_ranges) );
        }
        else if (!(ranges = realloc( transaction->ranges,
                                     capacity * sizeof(*ranges) )))
            goto full_invalidation;
        transaction->ranges = ranges;
        transaction->range_capacity = capacity;
    }
    transaction->ranges[count].address = start;
    transaction->ranges[count].size = end - start;
    transaction->event.range_count = count + 1;
    return;

full_invalidation:
    transaction->event.flags |= WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION;
    transaction->event.range_count = 0;
}

static void arm64ec_code_capture_transaction(
    struct arm64ec_code_transaction *transaction, NTSTATUS status )
{
    if (!transaction->nested && transaction->gate_locked)
        transaction->event.status = status;
}

static void arm64ec_code_complete_transaction(
    struct arm64ec_code_transaction *transaction )
{
    if (transaction->nested || !transaction->gate_locked) return;

    assert( arm64ec_code_current_transaction == transaction );
    arm64ec_code_current_transaction = NULL;
    arm64ec_code_normalize_ranges( transaction );
    if (transaction->observer_begun)
    {
        transaction->event.ranges = transaction->ranges;
        arm64ec_code_observer_callback_active = TRUE;
        transaction->observer->complete( transaction->observer->context,
                                         transaction->observer_transaction,
                                         &transaction->event );
        arm64ec_code_observer_callback_active = FALSE;
    }
    if (transaction->ranges != transaction->inline_ranges) free( transaction->ranges );
    transaction->gate_locked = FALSE;
    mutex_unlock( &arm64ec_code_observer_mutex );
}

/* The observer begin callback runs before virtual_mutex, so an unmap or
 * MEM_RELEASE request cannot resolve its containing view yet.  Give the
 * provider a conservative, nonempty logical-page interval to quiesce; the
 * completion event is replaced with the exact resolved view interval while
 * virtual_mutex is held. */
static NTSTATUS arm64ec_low_memory_normalize_begin_interval(
    const void *address, SIZE_T size, void **base, SIZE_T *covered )
{
    const ULONG_PTR shadow_start = WINE_LOW_VA_SHADOW_BASE;
    const ULONG_PTR shadow_end = WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE;
    ULONG_PTR start = (ULONG_PTR)address, end;

    if (start < shadow_start || start >= shadow_end) return STATUS_INVALID_ADDRESS;
    if (!size) size = 1;
    if (size > shadow_end - start) return STATUS_INVALID_ADDRESS;
    end = start + size;
    start &= ~page_mask;
    end = (end + page_mask) & ~page_mask;
    if (end <= start || end > shadow_end) return STATUS_INVALID_ADDRESS;
    *base = (void *)start;
    *covered = end - start;
    return STATUS_SUCCESS;
}

static NTSTATUS arm64ec_low_memory_begin_transaction(
    struct arm64ec_low_memory_transaction *transaction, BOOL candidate, ULONG operation,
    const void *address, SIZE_T size, const void *allocation_base )
{
    NTSTATUS status = STATUS_SUCCESS;
    void *begin_address;
    SIZE_T begin_size;

    memset( transaction, 0, sizeof(*transaction) );
    transaction->ranges = transaction->inline_ranges;
    transaction->range_capacity = ARRAY_SIZE(transaction->inline_ranges);
    if (!candidate) return STATUS_SUCCESS;
    if ((status = arm64ec_low_memory_normalize_begin_interval(
             address, size, &begin_address, &begin_size )))
        return status;
    if (arm64ec_low_memory_observer_callback_active ||
        arm64ec_code_observer_callback_active)
    {
        ERR( "AMD64-low memory mutation from observer callback\n" );
        return STATUS_INVALID_PARAMETER;
    }
    if (arm64ec_code_current_transaction)
    {
        ERR( "AMD64-low memory mutation overlaps ARM64EC code observer transaction\n" );
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (arm64ec_low_memory_current_transaction)
    {
        struct arm64ec_low_memory_transaction *parent =
            arm64ec_low_memory_current_transaction;

        transaction->nested = TRUE;
        if (!parent->allow_exact_nested || parent->event.operation != operation ||
            parent->event.host_address != (ULONG_PTR)begin_address ||
            parent->event.size_covered != begin_size)
            parent->event.flags |= WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT;
        return STATUS_SUCCESS;
    }

    mutex_lock( &arm64ec_low_memory_observer_mutex );
    transaction->gate_locked = TRUE;
    transaction->event.version = WINE_ARM64EC_LOW_MEMORY_OBSERVER_VERSION;
    transaction->event.size = sizeof(transaction->event);
    transaction->event.operation = operation;
    transaction->event.host_address = (ULONG_PTR)begin_address;
    transaction->event.size_covered = begin_size;
    transaction->event.host_allocation_base = (ULONG_PTR)allocation_base;

    if (arm64ec_low_memory_observer_registered)
    {
        transaction->observer = &arm64ec_low_memory_observer;
        arm64ec_low_memory_observer_callback_active = TRUE;
        status = transaction->observer->begin(
            transaction->observer->context, operation, (ULONG_PTR)begin_address, begin_size,
            (ULONG_PTR)allocation_base, &transaction->observer_transaction );
        arm64ec_low_memory_observer_callback_active = FALSE;
        if (status)
        {
            transaction->gate_locked = FALSE;
            mutex_unlock( &arm64ec_low_memory_observer_mutex );
            return status;
        }
        transaction->observer_begun = TRUE;
    }
    arm64ec_low_memory_current_transaction = transaction;
    return STATUS_SUCCESS;
}

static void arm64ec_low_memory_complete_transaction(
    struct arm64ec_low_memory_transaction *transaction )
{
    if (transaction->nested || !transaction->gate_locked) return;

    assert( arm64ec_low_memory_current_transaction == transaction );
    arm64ec_low_memory_current_transaction = NULL;
    if (transaction->observer_begun)
    {
        transaction->event.ranges = transaction->ranges;
        arm64ec_low_memory_observer_callback_active = TRUE;
        transaction->observer->complete( transaction->observer->context,
                                         transaction->observer_transaction,
                                         &transaction->event );
        arm64ec_low_memory_observer_callback_active = FALSE;
    }
    if (transaction->ranges != transaction->inline_ranges) free( transaction->ranges );
    transaction->gate_locked = FALSE;
    mutex_unlock( &arm64ec_low_memory_observer_mutex );
}
#endif

#if !defined(__APPLE__) || !defined(__aarch64__)
static inline BOOL wow64_memory_logical_write_fault_is_delegated(void)
{
    return FALSE;
}

static inline BOOL is_inside_wow64_shadow( const void *address, SIZE_T size )
{
    (void)address;
    (void)size;
    return FALSE;
}

static inline BOOL overlaps_wow64_shadow( const void *address, SIZE_T size )
{
    (void)address;
    (void)size;
    return FALSE;
}
#endif


/***********************************************************************
 *           add_builtin_module
 */
static void add_builtin_module( void *module, void *handle )
{
    struct builtin_module *builtin;

    if (!(builtin = malloc( sizeof(*builtin) ))) return;
    builtin->handle      = handle;
    builtin->module      = module;
    builtin->refcount    = 1;
    builtin->unix_path   = NULL;
    builtin->unix_handle = NULL;
    builtin->wow64_dispatch = 0;
    list_add_tail( &builtin_modules, &builtin->entry );
}


/***********************************************************************
 *           get_builtin_module
 */
static struct builtin_module *get_builtin_module( void *module )
{
    struct builtin_module *builtin;

    LIST_FOR_EACH_ENTRY( builtin, &builtin_modules, struct builtin_module, entry )
        if (builtin->module == module) return builtin;

    return NULL;
}


/***********************************************************************
 *           release_builtin_module
 */
static void release_builtin_module( void *module )
{
    struct builtin_module *builtin = get_builtin_module( module );

    if (!builtin) return;
    if (--builtin->refcount) return;
    list_remove( &builtin->entry );
    if (builtin->wow64_dispatch)
        unregister_wow64_unixlib_dispatch( builtin->wow64_dispatch );
    if (builtin->handle) dlclose( builtin->handle );
    if (builtin->unix_handle) dlclose( builtin->unix_handle );
    free( builtin->unix_path );
    free( builtin );
}


/***********************************************************************
 *           get_builtin_so_handle
 */
void *get_builtin_so_handle( void *module )
{
    sigset_t sigset;
    void *ret = NULL;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((builtin = get_builtin_module( module )))
    {
        ret = builtin->handle;
        if (ret) builtin->refcount++;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}

#if defined(__APPLE__) && defined(__aarch64__)
static NTSTATUS wow64_companion_translate( UINT64 guest, UINT64 size, UINT32 access,
                                           void **host )
{
    NTSTATUS status;

    if (!host || guest > UINT32_MAX || size > SIZE_MAX ||
        size > UINT32_MAX + 1ull - guest || !access ||
        (access & ~(WINE_WOW64_UNIXLIB_ACCESS_READ | WINE_WOW64_UNIXLIB_ACCESS_WRITE)))
        return STATUS_INVALID_PARAMETER;
    *host = NULL;
    if ((status = ntdll_wow64_guest32_to_host( guest, host ))) return status;
    if ((access & WINE_WOW64_UNIXLIB_ACCESS_READ) &&
        (status = ntdll_wow64_probe_user_read( *host, size )))
        return status;
    if ((access & WINE_WOW64_UNIXLIB_ACCESS_WRITE) &&
        (status = ntdll_wow64_probe_user_write( *host, size )))
        return status;
    return STATUS_SUCCESS;
}

static NTSTATUS wow64_companion_copy_from_guest( UINT64 guest, void *dst, UINT64 size )
{
    void *host;
    NTSTATUS status;

    if (!dst && size) return STATUS_INVALID_PARAMETER;
    if ((status = wow64_companion_translate( guest, size,
                                             WINE_WOW64_UNIXLIB_ACCESS_READ, &host )))
        return status;
    return ntdll_wow64_copy_from_user( dst, host, size );
}

static NTSTATUS wow64_companion_copy_to_guest( UINT64 guest, const void *src, UINT64 size )
{
    void *host;
    NTSTATUS status;

    if (!src && size) return STATUS_INVALID_PARAMETER;
    if ((status = wow64_companion_translate( guest, size,
                                             WINE_WOW64_UNIXLIB_ACCESS_WRITE, &host )))
        return status;
    return ntdll_wow64_atomic_write_user( host, src, size );
}

static const struct wine_wow64_unixlib_codec_v2 wow64_companion_codec =
{
    WINE_WOW64_UNIXLIB_CODEC_V2_VERSION,
    sizeof(wow64_companion_codec),
    WINE_WOW64_UNIXLIB_CAP_SEPARATE_GUEST_ADDRESS_SPACE,
    wow64_companion_translate,
    wow64_companion_copy_from_guest,
    wow64_companion_copy_to_guest,
    NULL,
    NULL,
};

static char *get_wow64_companion_path( const unixlib_entry_t *funcs )
{
    Dl_info info;
    size_t length;
    char *path;

    if (!funcs || !dladdr( funcs, &info ) || !info.dli_fname) return NULL;
    length = strlen( info.dli_fname );
    if (length < 3 || length > SIZE_MAX - sizeof("-wow64") ||
        strcmp( info.dli_fname + length - 3, ".so" ))
        return NULL;
    if (!(path = malloc( length + sizeof("-wow64") ))) return NULL;
    memcpy( path, info.dli_fname, length - 3 );
    memcpy( path + length - 3, "-wow64.so", sizeof("-wow64.so") );
    return path;
}

static NTSTATUS bind_wow64_companion( void *so_handle, const unixlib_entry_t *legacy_funcs,
                                      unixlib_handle_t *dispatch )
{
    static const BYTE expected_abi_sha256[32] =
        WINE_WOW64_UNIXLIB_COMPANION_V6_ABI_SHA256;
    const struct wine_wow64_unixlib_companion_v6 *descriptor;
    const struct wine_unixlib_dispatch_source_v2 *source;
    const struct wine_unixlib_owned_backing_codec_v2 *owned_codec;
    struct wine_wow64_unixlib_binding_v6 binding;
    const unixlib_entry_t *normal_funcs, *companion_funcs;
    unixlib_entry_t *binding_funcs = NULL;
    Dl_info descriptor_info, bind_info, quiesce_info, unbind_info, source_info, funcs_info;
    SIZE_T table_size;
    char *path;
    void *companion;
    NTSTATUS status;

    if (!(path = get_wow64_companion_path( legacy_funcs )))
    {
        WARN_(module)( "cannot derive WoW64 companion path\n" );
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    companion = dlopen( path, RTLD_NOW | RTLD_LOCAL );
    if (!companion)
        WARN_(module)( "cannot load WoW64 companion %s: %s\n", debugstr_a(path), dlerror() );
    free( path );
    if (!companion) return STATUS_INVALID_IMAGE_FORMAT;

    normal_funcs = dlsym( so_handle, "__wine_unix_call_funcs" );
    companion_funcs = dlsym( companion, "__wine_unix_call_wow64_funcs" );
    source = dlsym( companion, "__wine_unix_call_wow64_dispatch_v2" );
    descriptor = dlsym( companion, "__wine_unix_call_wow64_companion_v6" );
    owned_codec = wow64_owned_backing_get_codec();
    if (!normal_funcs || !companion_funcs || !source || !descriptor ||
        descriptor->version != WINE_WOW64_UNIXLIB_COMPANION_V6_VERSION ||
        descriptor->size != sizeof(*descriptor) || !descriptor->entry_count ||
        descriptor->entry_count > WINE_UNIXLIB_DISPATCH_MAX_ENTRIES ||
        descriptor->flags || !descriptor->bind || !descriptor->quiesce || !descriptor->unbind ||
        memcmp( descriptor->abi_sha256, expected_abi_sha256,
                sizeof(expected_abi_sha256) ) ||
        source->entry_count != descriptor->entry_count || source->funcs != companion_funcs ||
        !dladdr( descriptor, &descriptor_info ) || !dladdr( descriptor->bind, &bind_info ) ||
        !dladdr( descriptor->quiesce, &quiesce_info ) ||
        !dladdr( descriptor->unbind, &unbind_info ) ||
        !dladdr( source, &source_info ) || !dladdr( companion_funcs, &funcs_info ) ||
        descriptor_info.dli_fbase != bind_info.dli_fbase ||
        descriptor_info.dli_fbase != quiesce_info.dli_fbase ||
        descriptor_info.dli_fbase != unbind_info.dli_fbase ||
        descriptor_info.dli_fbase != source_info.dli_fbase ||
        descriptor_info.dli_fbase != funcs_info.dli_fbase ||
        validate_wow64_unixlib_function_table( normal_funcs,
                                                descriptor->entry_count, legacy_funcs ) ||
        validate_wow64_unixlib_function_table( legacy_funcs,
                                                descriptor->entry_count, normal_funcs ) ||
        !owned_codec || owned_codec->version != WINE_UNIXLIB_OWNED_BACKING_CODEC_V2_VERSION ||
        owned_codec->size != sizeof(*owned_codec) ||
        owned_codec->capabilities != WINE_UNIXLIB_OWNED_BACKING_CAP_ACQUIRE_RELEASE ||
        !owned_codec->acquire_backing || !owned_codec->release_backing)
    {
        WARN_(module)( "invalid WoW64 companion v6 contract\n" );
        dlclose( companion );
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    table_size = descriptor->entry_count * sizeof(*binding_funcs);
    if (!(binding_funcs = malloc( 2 * table_size )))
    {
        dlclose( companion );
        return STATUS_NO_MEMORY;
    }
    memcpy( binding_funcs, normal_funcs, table_size );
    memcpy( binding_funcs + descriptor->entry_count, legacy_funcs, table_size );
    if (validate_wow64_unixlib_function_table( normal_funcs,
                                                descriptor->entry_count, legacy_funcs ) ||
        validate_wow64_unixlib_function_table( legacy_funcs,
                                                descriptor->entry_count, normal_funcs ) ||
        memcmp( binding_funcs, normal_funcs, table_size ) ||
        memcmp( binding_funcs + descriptor->entry_count, legacy_funcs, table_size ))
    {
        WARN_(module)( "WoW64 companion source tables changed while binding\n" );
        free( binding_funcs );
        dlclose( companion );
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    binding.version = WINE_WOW64_UNIXLIB_BINDING_V6_VERSION;
    binding.size = sizeof(binding);
    binding.entry_count = descriptor->entry_count;
    binding.reserved = 0;
    binding.normal_funcs = binding_funcs;
    binding.legacy_wow64_funcs = binding_funcs + descriptor->entry_count;
    binding.codec = &wow64_companion_codec;
    binding.owned_backing_codec = owned_codec;
    if (!(status = ntdll_wow64_register_unixlib_dispatch_v2(
              source, companion_funcs, descriptor->quiesce, descriptor->unbind, dispatch )))
    {
        if ((status = descriptor->bind( &binding )))
        {
            NTSTATUS unregister_status = unregister_wow64_unixlib_dispatch( *dispatch );

            *dispatch = 0;
            if (unregister_status) status = unregister_status;
        }
    }
    if (status) WARN_(module)( "failed to bind WoW64 companion, status %#x\n", status );
    free( binding_funcs );
    dlclose( companion ); /* the dispatch registry retains its validated image */
    return status;
}
#endif


/***********************************************************************
 *           get_unixlib_funcs
 */
static NTSTATUS get_unixlib_funcs( void *so_handle, BOOL wow, unixlib_handle_t *dispatch,
                                   NTSTATUS (**entry)(void), BOOL *dispatch_registered )
{
    const unixlib_entry_t *funcs;

    *dispatch = 0;
    *dispatch_registered = FALSE;
    funcs = dlsym( so_handle, wow ? "__wine_unix_call_wow64_funcs" : "__wine_unix_call_funcs" );
#if defined(__APPLE__) && defined(__aarch64__)
    if (wow)
    {
        const struct wine_unixlib_dispatch_source_v2 *source;
        Dl_info funcs_info, source_info;
        NTSTATUS status;

        if (!funcs) return STATUS_ENTRYPOINT_NOT_FOUND;
        source = dlsym( so_handle, "__wine_unix_call_wow64_dispatch_v2" );
        /* dlsym() on a Mach-O handle can find a dependency's export.  Such a
         * descriptor does not describe this library's function table. */
        if (source && (!dladdr( funcs, &funcs_info ) || !dladdr( source, &source_info ) ||
                       funcs_info.dli_fbase != source_info.dli_fbase))
            source = NULL;
        if (!source)
        {
            if ((status = bind_wow64_companion( so_handle, funcs, dispatch ))) return status;
            *dispatch_registered = TRUE;
            return STATUS_SUCCESS;
        }
        if ((status = register_wow64_unixlib_dispatch_v2( source, funcs, dispatch )))
            return status;
        *dispatch_registered = TRUE;
        return STATUS_SUCCESS;
    }
#endif
    if (funcs) *dispatch = (UINT_PTR)funcs;
    else *entry = dlsym( so_handle, "__wine_unix_lib_init" );
    return *dispatch || *entry ? STATUS_SUCCESS : STATUS_ENTRYPOINT_NOT_FOUND;
}


#ifdef __APPLE__
typedef void (*non_native_code_region_registrar)(const void *, size_t);
#define MAX_NON_NATIVE_CODE_REGION_REGISTRARS 16

static pthread_mutex_t non_native_code_region_mutex = PTHREAD_MUTEX_INITIALIZER;
static non_native_code_region_registrar non_native_code_region_registrars[MAX_NON_NATIVE_CODE_REGION_REGISTRARS];
static unsigned int non_native_code_region_registrar_count;

static void add_non_native_code_region_registrar( non_native_code_region_registrar register_region )
{
    unsigned int i;

    if (!register_region) return;

    mutex_lock( &non_native_code_region_mutex );
    for (i = 0; i < non_native_code_region_registrar_count; i++)
    {
        if (non_native_code_region_registrars[i] == register_region)
        {
            mutex_unlock( &non_native_code_region_mutex );
            return;
        }
    }
    if (non_native_code_region_registrar_count < MAX_NON_NATIVE_CODE_REGION_REGISTRARS)
        non_native_code_region_registrars[non_native_code_region_registrar_count++] = register_region;
    else
        WARN_(module)( "too many non-native code region registrars\n" );
    mutex_unlock( &non_native_code_region_mutex );
}

void virtual_register_non_native_code_region( const void *base, SIZE_T size )
{
    non_native_code_region_registrar registrars[MAX_NON_NATIVE_CODE_REGION_REGISTRARS];
    unsigned int i, count;

    if (!base || !size) return;

    mutex_lock( &non_native_code_region_mutex );
    count = non_native_code_region_registrar_count;
    memcpy( registrars, non_native_code_region_registrars, count * sizeof(*registrars) );
    mutex_unlock( &non_native_code_region_mutex );

    for (i = 0; i < count; i++)
    {
        TRACE_(module)( "registering dynamic non-native code region %p-%p\n",
                        base, (const char *)base + size );
        registrars[i]( base, size );
    }
}

static void register_non_native_code_region( void *so_handle, void *module )
{
    int (*supports_regions)(void);
    non_native_code_region_registrar register_region;
    IMAGE_DOS_HEADER *dos = module;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    unsigned int i;

    if (!so_handle || !module) return;

    supports_regions = dlsym( so_handle, "supports_non_native_code_regions" );
    register_region = dlsym( so_handle, "register_non_native_code_region" );
    if (!register_region || (supports_regions && !supports_regions())) return;
    add_non_native_code_region_registrar( register_region );

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS *)((char *)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T size;
        void *base;

        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (!size) continue;

        base = (char *)module + sec[i].VirtualAddress;
        TRACE_(module)( "registering non-native code region %p-%p for %p\n",
                        base, (char *)base + size, module );
        register_region( base, size );
    }
}
#else
void virtual_register_non_native_code_region( const void *base, SIZE_T size )
{
}

static void register_non_native_code_region( void *so_handle, void *module )
{
}
#endif


/***********************************************************************
 *           load_builtin_unixlib
 */
static NTSTATUS load_builtin_unixlib( void *module, BOOL wow, unixlib_handle_t *dispatch )
{
    NTSTATUS (*entry)(void) = NULL;
    void *unix_handle = NULL;
    sigset_t sigset;
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    struct builtin_module *builtin;
    BOOL dispatch_registered = FALSE;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((builtin = get_builtin_module( module )))
    {
        if (builtin->unix_path && !builtin->unix_handle)
        {
            builtin->unix_handle = dlopen( builtin->unix_path, RTLD_NOW );
            if (!builtin->unix_handle)
                WARN_(module)( "failed to load %s: %s\n", debugstr_a(builtin->unix_path), dlerror() );
        }
        if (builtin->unix_handle)
        {
            unix_handle = builtin->unix_handle;
            if (wow && builtin->wow64_dispatch)
            {
                *dispatch = builtin->wow64_dispatch;
                status = STATUS_SUCCESS;
            }
            else
            {
                status = get_unixlib_funcs( builtin->unix_handle, wow, dispatch, &entry,
                                            &dispatch_registered );
                if (!status && dispatch_registered) builtin->wow64_dispatch = *dispatch;
            }
        }
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (!status) register_non_native_code_region( unix_handle, module );
    if (!status && entry) status = entry();
    return status;
}


/***********************************************************************
 *           set_builtin_unixlib_name
 */
NTSTATUS set_builtin_unixlib_name( void *module, const char *name )
{
    sigset_t sigset;
    NTSTATUS status = STATUS_SUCCESS;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((builtin = get_builtin_module( module )))
    {
        if (!builtin->unix_path) builtin->unix_path = strdup( name );
        else status = STATUS_IMAGE_ALREADY_LOADED;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *           free_ranges_lower_bound
 *
 * Returns the first range whose end is not less than addr, or end if there's none.
 */
static struct range_entry *free_ranges_lower_bound( void *addr )
{
    struct range_entry *begin = free_ranges;
    struct range_entry *end = free_ranges_end;
    struct range_entry *mid;

    while (begin < end)
    {
        mid = begin + (end - begin) / 2;
        if (mid->end < addr)
            begin = mid + 1;
        else
            end = mid;
    }

    return begin;
}

static void dump_free_ranges(void)
{
    struct range_entry *r;
    for (r = free_ranges; r != free_ranges_end; ++r)
        TRACE_(virtual_ranges)("%p - %p.\n", r->base, r->end);
}

/***********************************************************************
 *           free_ranges_insert_view
 *
 * Updates the free_ranges after a new view has been created.
 */
static void free_ranges_insert_view( struct file_view *view )
{
    void *view_base = ROUND_ADDR( view->base, granularity_mask );
    void *view_end = ROUND_ADDR( (char *)view->base + view->size + granularity_mask, granularity_mask );
    struct range_entry *range = free_ranges_lower_bound( view_base );
    struct range_entry *next = range + 1;

    /* free_ranges initial value is such that the view is either inside range or before another one. */
    assert( range != free_ranges_end );
    assert( range->end > view_base || next != free_ranges_end );

    /* Free ranges addresses are aligned at granularity_mask while the views may be not. */

    if (range->base > view_base)
        view_base = range->base;
    if (range->end < view_end)
        view_end = range->end;
    if (range->end == view_base && next->base >= view_end)
        view_end = view_base;

    TRACE_(virtual_ranges)( "%p - %p, aligned %p - %p.\n",
                            view->base, (char *)view->base + view->size, view_base, view_end );

    if (view_end <= view_base)
    {
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }

    /* this should never happen */
    if (range->base > view_base || range->end < view_end)
        ERR( "range %p - %p is already partially mapped\n", view_base, view_end );
    assert( range->base <= view_base && range->end >= view_end );

    /* need to split the range in two */
    if (range->base < view_base && range->end > view_end)
    {
        memmove( next + 1, next, (free_ranges_end - next) * sizeof(struct range_entry) );
        free_ranges_end += 1;
        if ((char *)free_ranges_end - (char *)free_ranges > view_block_size)
            ERR( "Free range sequence is full, trouble ahead!\n" );
        assert( (char *)free_ranges_end - (char *)free_ranges <= view_block_size );

        next->base = view_end;
        next->end = range->end;
        range->end = view_base;
    }
    else
    {
        /* otherwise we just have to shrink it */
        if (range->base < view_base)
            range->end = view_base;
        else
            range->base = view_end;

        if (range->base < range->end)
        {
            VIRTUAL_DEBUG_DUMP_RANGES();
            return;
        }
        /* and possibly remove it if it's now empty */
        memmove( range, next, (free_ranges_end - next) * sizeof(struct range_entry) );
        free_ranges_end -= 1;
        assert( free_ranges_end - free_ranges > 0 );
    }
    VIRTUAL_DEBUG_DUMP_RANGES();
}

/***********************************************************************
 *           free_ranges_remove_view
 *
 * Updates the free_ranges after a view has been destroyed.
 */
static void free_ranges_remove_view( struct file_view *view )
{
    void *view_base = ROUND_ADDR( view->base, granularity_mask );
    void *view_end = ROUND_ADDR( (char *)view->base + view->size + granularity_mask, granularity_mask );
    struct range_entry *range = free_ranges_lower_bound( view_base );
    struct range_entry *next = range + 1;

    /* Free ranges addresses are aligned at granularity_mask while the views may be not. */
    struct file_view *prev_view = RB_ENTRY_VALUE( rb_prev( &view->entry ), struct file_view, entry );
    struct file_view *next_view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
    void *prev_view_base = prev_view ? ROUND_ADDR( prev_view->base, granularity_mask ) : NULL;
    void *prev_view_end = prev_view ? ROUND_ADDR( (char *)prev_view->base + prev_view->size + granularity_mask, granularity_mask ) : NULL;
    void *next_view_base = next_view ? ROUND_ADDR( next_view->base, granularity_mask ) : NULL;
    void *next_view_end = next_view ? ROUND_ADDR( (char *)next_view->base + next_view->size + granularity_mask, granularity_mask ) : NULL;

    if (prev_view_end && prev_view_end > view_base && prev_view_base < view_end)
        view_base = prev_view_end;
    if (next_view_base && next_view_base < view_end && next_view_end > view_base)
        view_end = next_view_base;

    TRACE_(virtual_ranges)( "%p - %p, aligned %p - %p.\n",
                            view->base, (char *)view->base + view->size, view_base, view_end );

    if (view_end <= view_base)
    {
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }
    /* free_ranges initial value is such that the view is either inside range or before another one. */
    assert( range != free_ranges_end );
    assert( range->end > view_base || next != free_ranges_end );

    /* this should never happen, but we can safely ignore it */
    if (range->base <= view_base && range->end >= view_end)
    {
        WARN( "range %p - %p is already unmapped\n", view_base, view_end );
        return;
    }

    /* this should never happen */
    if (range->base < view_end && range->end > view_base)
        ERR( "range %p - %p is already partially unmapped\n", view_base, view_end );
    assert( range->end <= view_base || range->base >= view_end );

    /* merge with next if possible */
    if (range->end == view_base && next->base == view_end)
    {
        range->end = next->end;
        memmove( next, next + 1, (free_ranges_end - next - 1) * sizeof(struct range_entry) );
        free_ranges_end -= 1;
        assert( free_ranges_end - free_ranges > 0 );
    }
    /* or try growing the range */
    else if (range->end == view_base)
        range->end = view_end;
    else if (range->base == view_end)
        range->base = view_base;
    /* otherwise create a new one */
    else
    {
        memmove( range + 1, range, (free_ranges_end - range) * sizeof(struct range_entry) );
        free_ranges_end += 1;
        if ((char *)free_ranges_end - (char *)free_ranges > view_block_size)
            ERR( "Free range sequence is full, trouble ahead!\n" );
        assert( (char *)free_ranges_end - (char *)free_ranges <= view_block_size );

        range->base = view_base;
        range->end = view_end;
    }
    VIRTUAL_DEBUG_DUMP_RANGES();
}


static inline int is_view_valloc( const struct file_view *view )
{
    return !(view->protect & (SEC_FILE | SEC_RESERVE | SEC_COMMIT));
}

/***********************************************************************
 *           get_page_vprot
 *
 * Return the page protection byte.
 */
static BYTE get_page_vprot( const void *addr )
{
    size_t idx = (size_t)addr >> page_shift;

#ifdef _WIN64
    if ((idx >> pages_vprot_shift) >= pages_vprot_size) return 0;
    if (!pages_vprot[idx >> pages_vprot_shift]) return 0;
    return pages_vprot[idx >> pages_vprot_shift][idx & pages_vprot_mask];
#else
    return pages_vprot[idx];
#endif
}


/***********************************************************************
 *           get_host_page_vprot
 *
 * Return the union of the page protection bytes of all the pages making up the host page.
 */
static BYTE get_host_page_vprot( const void *addr )
{
    size_t i, idx = (size_t)ROUND_ADDR( addr, host_page_mask ) >> page_shift;
    const BYTE *vprot_ptr;
    BYTE vprot = 0;

#ifdef _WIN64
    if ((idx >> pages_vprot_shift) >= pages_vprot_size) return 0;
    if (!pages_vprot[idx >> pages_vprot_shift]) return 0;
    assert( host_page_mask >> page_shift <= pages_vprot_mask );
    vprot_ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
#else
    vprot_ptr = pages_vprot + idx;
#endif
    for (i = 0; i < host_page_size / page_size; i++) vprot |= vprot_ptr[i];
    return vprot;
}


/***********************************************************************
 *           get_translated_host_page_vprot
 *
 * Return the physical protection required by translated logical pages.
 * The CPU provider enforces 4K guard/no-access state; Darwin can only
 * protect the containing 16K host page, so guarded pages must not suppress
 * access required by an adjacent committed logical page.
 */
static BYTE get_translated_host_page_vprot( const void *addr )
{
    const char *base = ROUND_ADDR( addr, host_page_mask );
    BYTE vprot = 0;
    size_t i;

    for (i = 0; i < host_page_size; i += page_size)
    {
        BYTE page_vprot = get_page_vprot( base + i );

        if (!(page_vprot & VPROT_COMMITTED) || (page_vprot & VPROT_GUARD)) continue;
        if (wow64_memory_logical_write_fault_is_delegated())
            page_vprot &= ~VPROT_WRITEWATCH;
        vprot |= page_vprot;
    }
    return vprot;
}


/***********************************************************************
 *           get_vprot_range_size
 *
 * Return the size of the region with equal masked vprot byte.
 * Also return the protections for the first page.
 * The function assumes that base and size are page aligned,
 * base + size does not wrap around and the range is within view so
 * vprot bytes are allocated for the range. */
static SIZE_T get_vprot_range_size( char *base, SIZE_T size, BYTE mask, BYTE *vprot )
{
    static const UINT_PTR word_from_byte = (UINT_PTR)0x101010101010101;
    static const UINT_PTR index_align_mask = sizeof(UINT_PTR) - 1;
    SIZE_T curr_idx, start_idx, end_idx, aligned_start_idx;
    UINT_PTR vprot_word, mask_word;
    const BYTE *vprot_ptr;

    TRACE("base %p, size %p, mask %#x.\n", base, (void *)size, mask);

    curr_idx = start_idx = (size_t)base >> page_shift;
    end_idx = start_idx + (size >> page_shift);

    aligned_start_idx = ROUND_SIZE( 0, start_idx, index_align_mask );
    if (aligned_start_idx > end_idx) aligned_start_idx = end_idx;

#ifdef _WIN64
    vprot_ptr = pages_vprot[curr_idx >> pages_vprot_shift] + (curr_idx & pages_vprot_mask);
#else
    vprot_ptr = pages_vprot + curr_idx;
#endif
    *vprot = *vprot_ptr;

    /* Page count page table is at least the multiples of sizeof(UINT_PTR)
     * so we don't have to worry about crossing the boundary on unaligned idx values. */

    for (; curr_idx < aligned_start_idx; ++curr_idx, ++vprot_ptr)
        if ((*vprot ^ *vprot_ptr) & mask) return (curr_idx - start_idx) << page_shift;

    vprot_word = word_from_byte * *vprot;
    mask_word = word_from_byte * mask;
    for (; curr_idx < end_idx; curr_idx += sizeof(UINT_PTR), vprot_ptr += sizeof(UINT_PTR))
    {
#ifdef _WIN64
        if (!(curr_idx & pages_vprot_mask)) vprot_ptr = pages_vprot[curr_idx >> pages_vprot_shift];
#endif
        if ((vprot_word ^ *(UINT_PTR *)vprot_ptr) & mask_word)
        {
            for (; curr_idx < end_idx; ++curr_idx, ++vprot_ptr)
                if ((*vprot ^ *vprot_ptr) & mask) break;
            return (curr_idx - start_idx) << page_shift;
        }
    }
    return size;
}

/***********************************************************************
 *           set_page_vprot
 *
 * Set a range of page protection bytes.
 */
static void set_page_vprot( const void *addr, size_t size, BYTE vprot )
{
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;

#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( addr, size )) wow64_memory_assert_transaction();
#endif
#ifdef _WIN64
    while (idx >> pages_vprot_shift != end >> pages_vprot_shift)
    {
        size_t dir_size = pages_vprot_mask + 1 - (idx & pages_vprot_mask);
        memset( pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask), vprot, dir_size );
        idx += dir_size;
    }
    memset( pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask), vprot, end - idx );
#else
    memset( pages_vprot + idx, vprot, end - idx );
#endif
}


/***********************************************************************
 *           set_page_vprot_bits
 *
 * Set or clear bits in a range of page protection bytes.
 */
static void set_page_vprot_bits( const void *addr, size_t size, BYTE set, BYTE clear )
{
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;

#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( addr, size )) wow64_memory_assert_transaction();
#endif
#ifdef _WIN64
    for ( ; idx < end; idx++)
    {
        BYTE *ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
        *ptr = (*ptr & ~clear) | set;
    }
#else
    for ( ; idx < end; idx++) pages_vprot[idx] = (pages_vprot[idx] & ~clear) | set;
#endif
}


/***********************************************************************
 *           set_page_vprot_exec_write_protect
 *
 * Write protect pages that are executable.
 */
static BOOL set_page_vprot_exec_write_protect( const void *addr, size_t size )
{
    BOOL ret = FALSE;
#ifdef _WIN64 /* only supported on 64-bit so assume 2-level table */
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;
#endif
#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( addr, size )) wow64_memory_assert_transaction();
#endif
#ifdef _WIN64 /* only supported on 64-bit so assume 2-level table */
    for ( ; idx < end; idx++)
    {
        BYTE *ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
        if (!is_vprot_exec_write( *ptr )) continue;
        *ptr |= VPROT_WRITEWATCH;
        ret = TRUE;
    }
#endif
    return ret;
}


/***********************************************************************
 *           alloc_pages_vprot
 *
 * Allocate the page protection bytes for a given range.
 */
static BOOL alloc_pages_vprot( const void *addr, size_t size )
{
#ifdef _WIN64
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;
    size_t i;
    void *ptr;

    assert( end <= pages_vprot_size << pages_vprot_shift );
    for (i = idx >> pages_vprot_shift; i < (end + pages_vprot_mask) >> pages_vprot_shift; i++)
    {
        if (pages_vprot[i]) continue;
        if ((ptr = anon_mmap_alloc( pages_vprot_mask + 1, PROT_READ | PROT_WRITE )) == MAP_FAILED)
        {
            ERR( "anon mmap error %s for vprot table, size %08lx\n", strerror(errno), pages_vprot_mask + 1 );
            return FALSE;
        }
        pages_vprot[i] = ptr;
    }
#endif
    return TRUE;
}


static inline UINT64 maskbits( size_t idx )
{
    return ~(UINT64)0 << (idx & 63);
}

/***********************************************************************
 *           set_arm64ec_range
 */
static void set_arm64ec_range( const void *addr, size_t size )
{
    UINT64 *map = arm64ec_view->base;
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;
    size_t pos = idx / 64;
    size_t end_pos = end / 64;

#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_record_range( addr, size );
#endif

    if (end_pos > pos)
    {
        map[pos++] |= maskbits( idx );
        while (pos < end_pos) map[pos++] = ~(UINT64)0;
        if (end & 63) map[pos] |= ~maskbits( end );
    }
    else map[pos] |= maskbits( idx ) & ~maskbits( end );
}


/***********************************************************************
 *           clear_arm64ec_range
 */
static void clear_arm64ec_range( const void *addr, size_t size )
{
    UINT64 *map = arm64ec_view->base;
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;
    size_t pos = idx / 64;
    size_t end_pos = end / 64;

#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_record_range( addr, size );
#endif

    if (end_pos > pos)
    {
        map[pos++] &= ~maskbits( idx );
        while (pos < end_pos) map[pos++] = 0;
        if (end & 63) map[pos] &= maskbits( end );
    }
    else map[pos] &= ~maskbits( idx ) | maskbits( end );
}


/***********************************************************************
 *           compare_view
 *
 * View comparison function used for the rb tree.
 */
static int compare_view( const void *addr, const struct wine_rb_entry *entry )
{
    struct file_view *view = WINE_RB_ENTRY_VALUE( entry, struct file_view, entry );

    if (addr < view->base) return -1;
    if (addr > view->base) return 1;
    return 0;
}


/***********************************************************************
 *           get_prot_str
 */
static const char *get_prot_str( BYTE prot )
{
    static char buffer[6];
    buffer[0] = (prot & VPROT_COMMITTED) ? 'c' : '-';
    buffer[1] = (prot & VPROT_GUARD) ? 'g' : ((prot & VPROT_WRITEWATCH) ? 'H' : '-');
    buffer[2] = (prot & VPROT_READ) ? 'r' : '-';
    buffer[3] = (prot & VPROT_WRITECOPY) ? (prot & VPROT_COPIED ? 'w' : 'W')
            : ((prot & VPROT_WRITE) ? 'w' : '-');
    buffer[4] = (prot & VPROT_EXEC) ? 'x' : '-';
    buffer[5] = 0;
    return buffer;
}


/***********************************************************************
 *           get_unix_prot
 *
 * Convert page protections to protection for mmap/mprotect.
 */
static int get_unix_prot( BYTE vprot )
{
    int prot = 0;
    if ((vprot & VPROT_COMMITTED) && !(vprot & VPROT_GUARD))
    {
        if (vprot & VPROT_READ) prot |= PROT_READ;
        if (vprot & VPROT_WRITE) prot |= PROT_WRITE | PROT_READ;
        if (vprot & VPROT_WRITECOPY) prot |= PROT_WRITE | PROT_READ;
        if (vprot & VPROT_EXEC) prot |= PROT_EXEC | PROT_READ;
        if (vprot & VPROT_WRITEWATCH) prot &= ~PROT_WRITE;
    }
    if (!prot) prot = PROT_NONE;
    return prot;
}


/***********************************************************************
 *           dump_view
 */
static void dump_view( struct file_view *view )
{
    UINT i, count;
    char *addr = view->base;
    BYTE prot = get_page_vprot( addr );

    TRACE( "View: %p - %p %s", addr, addr + view->size - 1, get_prot_str(view->protect) );
    if (view->protect & VPROT_SYSTEM)
        TRACE( " (builtin image)\n" );
    else if (view->protect & VPROT_FREE_PLACEHOLDER)
        TRACE( " (placeholder)\n" );
    else if (view->protect & SEC_IMAGE)
        TRACE( " (image)\n" );
    else if (view->protect & SEC_FILE)
        TRACE( " (file)\n" );
    else if (view->protect & (SEC_RESERVE | SEC_COMMIT))
        TRACE( " (anonymous)\n" );
    else
        TRACE( " (valloc)\n");

    for (count = i = 1; i < view->size >> page_shift; i++, count++)
    {
        BYTE next = get_page_vprot( addr + (count << page_shift) );
        if (next == prot) continue;
        TRACE( "      %p - %p %s\n",
                 addr, addr + (count << page_shift) - 1, get_prot_str(prot) );
        addr += (count << page_shift);
        prot = next;
        count = 0;
    }
    if (count)
        TRACE( "      %p - %p %s\n",
                 addr, addr + (count << page_shift) - 1, get_prot_str(prot) );
}


/***********************************************************************
 *           VIRTUAL_Dump
 */
#ifdef WINE_VM_DEBUG
static void VIRTUAL_Dump(void)
{
    sigset_t sigset;
    struct file_view *view;

    TRACE( "Dump of all virtual memory views:\n" );
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        dump_view( view );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}
#endif


/***********************************************************************
 *           find_view
 *
 * Find the view containing a given address. virtual_mutex must be held by caller.
 *
 * PARAMS
 *      addr  [I] Address
 *
 * RETURNS
 *	View: Success
 *	NULL: Failure
 */
static struct file_view *find_view( const void *addr, size_t size )
{
    struct wine_rb_entry *ptr = views_tree.root;

    if ((const char *)addr + size < (const char *)addr) return NULL; /* overflow */

    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );

        if (view->base > addr) ptr = ptr->left;
        else if ((const char *)view->base + view->size <= (const char *)addr) ptr = ptr->right;
        else if ((const char *)view->base + view->size < (const char *)addr + size) break;  /* size too large */
        else return view;
    }
    return NULL;
}

static SIZE_T get_committed_size( struct file_view *view, void *base, size_t max_size,
                                  BYTE *vprot, BYTE vprot_mask );

#if defined(__APPLE__) && defined(__aarch64__)
struct memory_access_cache
{
    struct file_view *view;
    const char *start;
    const char *end;
    BOOL committed;
};

/* Return the logical protection for a tagged WoW64 page.  The numeric shadow
 * range is only a fast lookup bound; the private type-31 view tag remains the
 * ownership authority.  virtual_mutex must be held by the caller. */
static BYTE get_memory_access_vprot( const void *addr, SIZE_T *available, BOOL *translated,
                                     struct memory_access_cache *cache )
{
    struct file_view *view;

    *available = host_page_size - ((ULONG_PTR)addr & host_page_mask);
    if (translated) *translated = FALSE;
    if (is_wow64_shadow_address( addr ))
    {
        *available = page_size - ((ULONG_PTR)addr & page_mask);
        if ((view = find_view( addr, 0 )) && (view->protect & VPROT_WOW64_TRANSLATED))
        {
            BYTE vprot = get_page_vprot( addr );

            if (translated) *translated = TRUE;
            /* SEC_RESERVE commitment belongs to the shared mapping object in
             * the server.  An alias may not have faulted since another view
             * committed the range, so consult that authority before judging
             * a native copy or I/O buffer.  get_committed_size() preserves
             * the read-only observer-callback rule when no transaction owns
             * this lookup. */
            if ((view->protect & SEC_RESERVE) && !(vprot & VPROT_COMMITTED))
            {
                if (cache && cache->view == view && (const char *)addr >= cache->start &&
                    (const char *)addr < cache->end)
                {
                    if (cache->committed) vprot |= VPROT_COMMITTED;
                }
                else
                {
                    SIZE_T run = get_committed_size( view, (void *)addr,
                                                     (const char *)view->base + view->size -
                                                     (const char *)addr,
                                                     &vprot, VPROT_COMMITTED );
                    if (cache)
                    {
                        cache->view = view;
                        cache->start = addr;
                        cache->end = (const char *)addr + max( run, *available );
                        cache->committed = !!(vprot & VPROT_COMMITTED);
                    }
                }
            }
            return vprot;
        }
        /* Ordinary views are forbidden in the shadow.  A host page may still
         * be physically accessible because it contains an adjacent tagged 4K
         * lane, but that does not grant ownership of this logical address. */
        return 0;
    }
    return get_host_page_vprot( addr );
}

/* Validate only tagged translated pages in a native memory-copy range.
 * Ordinary views retain their existing host access behavior.  virtual_mutex
 * must be held by the caller. */
static BOOL check_wow64_translated_memory_access( const void *base, SIZE_T size, int unix_prot )
{
    struct memory_access_cache cache = {0};
    ULONG_PTR start = (ULONG_PTR)base, end;

    if (!size) return TRUE;
    if (size > ~(ULONG_PTR)0 - start) return FALSE;
    end = start + size;
    if (end <= WINE_LOW_VA_SHADOW_BASE ||
        start >= WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE)
        return TRUE;

    start = max( start, (ULONG_PTR)WINE_LOW_VA_SHADOW_BASE );
    end = min( end, (ULONG_PTR)(WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE) );
    while (start < end)
    {
        SIZE_T available;
        BOOL translated;
        BYTE vprot = get_memory_access_vprot( (void *)start, &available, &translated, &cache );

        if (!translated) return FALSE;
        if (unix_prot & PROT_WRITE) vprot &= ~VPROT_WRITEWATCH;
        if (!(get_unix_prot( vprot ) & unix_prot)) return FALSE;
        start += min( available, end - start );
    }
    return TRUE;
}

static BOOL virtual_check_wow64_translated_memory_access( const void *base, SIZE_T size,
                                                           int unix_prot )
{
    BOOL ret;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    ret = check_wow64_translated_memory_access( base, size, unix_prot );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}
#else
struct memory_access_cache { int unused; };

static BYTE get_memory_access_vprot( const void *addr, SIZE_T *available, BOOL *translated,
                                     struct memory_access_cache *cache )
{
    (void)cache;
    *available = host_page_size - ((ULONG_PTR)addr & host_page_mask);
    if (translated) *translated = FALSE;
    return get_host_page_vprot( addr );
}

static inline BOOL check_wow64_translated_memory_access( const void *base, SIZE_T size,
                                                          int unix_prot )
{
    (void)base;
    (void)size;
    (void)unix_prot;
    return TRUE;
}

static inline BOOL virtual_check_wow64_translated_memory_access( const void *base, SIZE_T size,
                                                                  int unix_prot )
{
    (void)base;
    (void)size;
    (void)unix_prot;
    return TRUE;
}
#endif


/***********************************************************************
 *           is_write_watch_range
 */
static inline BOOL is_write_watch_range( const void *addr, size_t size )
{
    struct file_view *view = find_view( addr, size );
    return view && (view->protect & VPROT_WRITEWATCH);
}


/***********************************************************************
 *           find_view_range
 *
 * Find the first view overlapping at least part of the specified range.
 * virtual_mutex must be held by caller.
 */
static struct file_view *find_view_range( const void *addr, size_t size )
{
    struct wine_rb_entry *ptr = views_tree.root;

    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );

        if ((const char *)view->base >= (const char *)addr + size) ptr = ptr->left;
        else if ((const char *)view->base + view->size <= (const char *)addr) ptr = ptr->right;
        else return view;
    }
    return NULL;
}


/***********************************************************************
 *           find_view_at_or_after
 *
 * Find the view containing addr, or the first view starting after it.
 * virtual_mutex must be held by the caller.
 */
#if defined(__APPLE__) && defined(__aarch64__)
static struct file_view *find_view_at_or_after( const void *addr )
{
    struct wine_rb_entry *candidate = NULL, *ptr = views_tree.root;
    ULONG_PTR address = (ULONG_PTR)addr;

    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        ULONG_PTR start = (ULONG_PTR)view->base;

        if (view->size <= ~(ULONG_PTR)0 - start && start + view->size <= address)
            ptr = ptr->right;
        else
        {
            candidate = ptr;
            ptr = ptr->left;
        }
    }
    return candidate ? WINE_RB_ENTRY_VALUE( candidate, struct file_view, entry ) : NULL;
}
#endif


/***********************************************************************
 *           find_view_inside_range
 *
 * Find first (resp. last, if top_down) view inside a range.
 * virtual_mutex must be held by caller.
 */
static struct wine_rb_entry *find_view_inside_range( void **base_ptr, void **end_ptr, int top_down )
{
    struct wine_rb_entry *first = NULL, *ptr = views_tree.root;
    void *base = *base_ptr, *end = *end_ptr;

    /* find the first (resp. last) view inside the range */
    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        if ((char *)view->base + view->size >= (char *)end)
        {
            end = min( end, view->base );
            ptr = ptr->left;
        }
        else if (view->base <= base)
        {
            base = max( (char *)base, (char *)view->base + view->size );
            ptr = ptr->right;
        }
        else
        {
            first = ptr;
            ptr = top_down ? ptr->right : ptr->left;
        }
    }

    *base_ptr = base;
    *end_ptr = end;
    return first;
}


/***********************************************************************
 *           try_map_free_area
 *
 * Try mmaping some expected free memory region, eventually stepping and
 * retrying inside it, and return where it actually succeeded, or NULL.
 */
static void* try_map_free_area( void *base, void *end, ptrdiff_t step,
                                void *start, size_t size, int unix_prot )
{
    while (start && base <= start && (char*)start + size <= (char*)end)
    {
        if (anon_mmap_tryfixed( start, size, unix_prot, 0 ) != MAP_FAILED) return start;
        TRACE( "Found free area is already mapped, start %p.\n", start );
        if (errno != EEXIST)
        {
            ERR( "mmap() error %s, range %p-%p, unix_prot %#x.\n",
                 strerror(errno), start, (char *)start + size, unix_prot );
            return NULL;
        }
        if ((step > 0 && (char *)end - (char *)start < step) ||
            (step < 0 && (char *)start - (char *)base < -step) ||
            step == 0)
            break;
        start = (char *)start + step;
    }

    return NULL;
}


/***********************************************************************
 *           map_free_area
 *
 * Find a free area between views inside the specified range and map it.
 * virtual_mutex must be held by caller.
 */
static void *map_free_area( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask )
{
    struct wine_rb_entry *first = find_view_inside_range( &base, &end, top_down );
    ptrdiff_t step = top_down ? -(align_mask + 1) : (align_mask + 1);
    void *start;

    if (top_down)
    {
        start = ROUND_ADDR( (char *)end - size, align_mask );
        if (start >= end || start < base) return NULL;

        while (first)
        {
            struct file_view *view = WINE_RB_ENTRY_VALUE( first, struct file_view, entry );
            if ((start = try_map_free_area( (char *)view->base + view->size, (char *)start + size, step,
                                            start, size, unix_prot ))) break;
            start = ROUND_ADDR( (char *)view->base - size, align_mask );
            /* stop if remaining space is not large enough */
            if (!start || start >= end || start < base) return NULL;
            first = rb_prev( first );
        }
    }
    else
    {
        start = ROUND_ADDR( (char *)base + align_mask, align_mask );
        if (!start || start >= end || (char *)end - (char *)start < size) return NULL;

        while (first)
        {
            struct file_view *view = WINE_RB_ENTRY_VALUE( first, struct file_view, entry );
            if ((start = try_map_free_area( start, view->base, step,
                                            start, size, unix_prot ))) break;
            start = ROUND_ADDR( (char *)view->base + view->size + align_mask, align_mask );
            /* stop if remaining space is not large enough */
            if (!start || start >= end || (char *)end - (char *)start < size) return NULL;
            first = rb_next( first );
        }
    }

    if (!first)
        start = try_map_free_area( base, end, step, start, size, unix_prot );

    if (!start)
        ERR( "couldn't map free area in range %p-%p, size %p\n", base, end, (void *)size );

    return start;
}


/***********************************************************************
 *           find_reserved_free_area
 *
 * Find a free area between views inside the specified range.
 * virtual_mutex must be held by caller.
 * The range must be inside a reserved area.
 */
static void *find_reserved_free_area( void *base, void *end, size_t size, int top_down, size_t align_mask )
{
    struct range_entry *range;
    void *start;

    base = ROUND_ADDR( (char *)base + align_mask, align_mask );
    end = (char *)ROUND_ADDR( (char *)end - size, align_mask ) + size;

    if (top_down)
    {
        start = (char *)end - size;
        range = free_ranges_lower_bound( start );
        assert(range != free_ranges_end && range->end >= start);

        if ((char *)range->end - (char *)start < size) start = ROUND_ADDR( (char *)range->end - size, align_mask );
        do
        {
            if (start >= end || start < base || (char *)end - (char *)start < size) return NULL;
            if (start < range->end && start >= range->base && (char *)range->end - (char *)start >= size) break;
            if (--range < free_ranges) return NULL;
            start = ROUND_ADDR( (char *)range->end - size, align_mask );
        }
        while (1);
    }
    else
    {
        start = base;
        range = free_ranges_lower_bound( start );
        assert(range != free_ranges_end && range->end >= start);

        if (start < range->base) start = ROUND_ADDR( (char *)range->base + align_mask, align_mask );
        do
        {
            if (start >= end || start < base || (char *)end - (char *)start < size) return NULL;
            if (start < range->end && start >= range->base && (char *)range->end - (char *)start >= size) break;
            if (++range == free_ranges_end) return NULL;
            start = ROUND_ADDR( (char *)range->base + align_mask, align_mask );
        }
        while (1);
    }
    return start;
}


/***********************************************************************
 *           remove_reserved_area
 *
 * Remove a reserved area from the list maintained by libwine.
 * virtual_mutex must be held by caller.
 */
static void remove_reserved_area( void *addr, size_t size )
{
    struct file_view *view;
    size_t view_size;

    TRACE( "removing %p-%p\n", addr, (char *)addr + size );
    mmap_remove_reserved_area( addr, size );

    /* unmap areas not covered by an existing view */
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        if ((char *)view->base >= (char *)addr + size) break;
        if ((char *)view->base + view->size <= (char *)addr) continue;
        if (view->base > addr) munmap( addr, (char *)view->base - (char *)addr );
        if ((char *)view->base + view->size > (char *)addr + size) return;
        view_size = ROUND_SIZE( view->base, view->size, host_page_mask );
        size = (char *)addr + size - ((char *)view->base + view_size);
        addr = (char *)view->base + view_size;
    }
    munmap( addr, size );
}


/***********************************************************************
 *           unmap_area
 *
 * Unmap an area, or simply replace it by an empty mapping if it is
 * in a reserved area. virtual_mutex must be held by caller.
 */
static void unmap_area( void *start, size_t size )
{
    struct reserved_area *area;
    void *end;

    assert( !((UINT_PTR)start & host_page_mask) );
    size = ROUND_SIZE( 0, size, host_page_mask );

    if (!(size = unmap_area_above_user_limit( start, size ))) return;

    end = (char *)start + size;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        void *area_start = area->base;
        void *area_end = (char *)area_start + area->size;

        if (area_start >= end) break;
        if (area_end <= start) continue;
        if (area_start > start)
        {
            munmap( start, (char *)area_start - (char *)start );
            start = area_start;
        }
        if (area_end >= end)
        {
            anon_mmap_fixed( start, (char *)end - (char *)start, PROT_NONE, MAP_NORESERVE );
            return;
        }
        anon_mmap_fixed( start, (char *)area_end - (char *)start, PROT_NONE, MAP_NORESERVE );
        start = area_end;
    }
    munmap( start, (char *)end - (char *)start );
}


/***********************************************************************
 *           alloc_view
 *
 * Allocate a new view. virtual_mutex must be held by caller.
 */
static struct file_view *alloc_view(void)
{
    struct file_view *ret;
    if (next_view_allocation_id == ~(ULONGLONG)0) return NULL;
    if (next_free_view)
    {
        ret = next_free_view;
        next_free_view = *(struct file_view **)ret;
        ret->wine_stack = FALSE;
        ret->stack_owner = NULL;
    ret->stack_commit_size = 0;
        ret->allocation_id = ++next_view_allocation_id;
        return ret;
    }
    if (view_block_start == view_block_end)
    {
        void *ptr = anon_mmap_alloc( view_block_size, PROT_READ | PROT_WRITE );
        if (ptr == MAP_FAILED) return NULL;
        view_block_start = ptr;
        view_block_end = view_block_start + view_block_size / sizeof(*view_block_start);
    }
    ret = view_block_start++;
    ret->wine_stack = FALSE;
    ret->stack_owner = NULL;
    ret->stack_commit_size = 0;
    ret->allocation_id = ++next_view_allocation_id;
    return ret;
}


/***********************************************************************
 *           free_view
 *
 * Free memory for view structure. virtual_mutex must be held by caller.
 */
static void free_view( struct file_view *view )
{
    *(struct file_view **)view = next_free_view;
    next_free_view = view;
}


/***********************************************************************
 *           unregister_view
 *
 * Remove view from the tree and update free ranges. virtual_mutex must be held by caller.
 */
static void unregister_view( struct file_view *view )
{
    if (mmap_is_in_reserved_area( view->base, view->size ))
        free_ranges_remove_view( view );
    wine_rb_remove( &views_tree, &view->entry );
}


/***********************************************************************
 *           delete_view
 *
 * Deletes a view. virtual_mutex must be held by caller.
 */
static void delete_view( struct file_view *view ) /* [in] View */
{
#if defined(__APPLE__) && defined(__aarch64__)
    if (view->protect & VPROT_WOW64_TRANSLATED) wow64_memory_assert_transaction();
    if (view->protect & VPROT_AMD64_LOW_TRANSLATED)
        arm64ec_low_memory_assert_transaction();
#endif
    if (!(view->protect & VPROT_SYSTEM)) unmap_area( view->base, view->size );
    set_page_vprot( view->base, view->size, 0 );
    if (view->protect & VPROT_ARM64EC) clear_arm64ec_range( view->base, view->size );
    unregister_view( view );
    free_view( view );
}


/***********************************************************************
 *           register_view
 *
 * Add view to the tree and update free ranges. virtual_mutex must be held by caller.
 */
static void register_view( struct file_view *view )
{
    wine_rb_put( &views_tree, view->base, &view->entry );
    if (mmap_is_in_reserved_area( view->base, view->size ))
        free_ranges_insert_view( view );
}


/***********************************************************************
 *           create_view
 *
 * Create a view. virtual_mutex must be held by caller.
 */
static NTSTATUS create_view( struct file_view **view_ret, void *base, size_t size, unsigned int vprot )
{
    struct file_view *view;

#if defined(__APPLE__) && defined(__aarch64__)
    if ((vprot & VPROT_SHADOW_TRANSLATED) == VPROT_SHADOW_TRANSLATED)
        return STATUS_INVALID_PARAMETER;
    if (vprot & VPROT_WOW64_TRANSLATED) wow64_memory_assert_transaction();
    if (vprot & VPROT_AMD64_LOW_TRANSLATED)
        arm64ec_low_memory_assert_transaction();
#endif
    assert( !((UINT_PTR)base & host_page_mask) );
    assert( !(size & page_mask) );

    /* Check for overlapping views. This can happen if the previous view
     * was a system view that got unmapped behind our back. In that case
     * we recover by simply deleting it. */

    while ((view = find_view_range( base, size )))
    {
        TRACE( "overlapping view %p-%p for %p-%p\n",
               view->base, (char *)view->base + view->size, base, (char *)base + size );
        assert( view->protect & VPROT_SYSTEM );
        delete_view( view );
    }

    if (!alloc_pages_vprot( base, size )) return STATUS_NO_MEMORY;

    /* Create the view structure */

    if (!(view = alloc_view()))
    {
        FIXME( "out of memory for %p-%p\n", base, (char *)base + size );
        return STATUS_NO_MEMORY;
    }

    view->base    = base;
    view->size    = size;
    view->protect = vprot;
    if (use_kernel_writewatch) vprot &= ~VPROT_WRITEWATCH;
    set_page_vprot( base, size, vprot );

    register_view( view );
    kernel_writewatch_register_range( view, view->base, view->size );

    *view_ret = view;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           get_win32_prot
 *
 * Convert page protections to Win32 flags.
 */
static DWORD get_win32_prot( BYTE vprot, unsigned int map_prot )
{
    DWORD ret;

    if ((vprot & (VPROT_COPIED | VPROT_WRITECOPY)) == (VPROT_COPIED | VPROT_WRITECOPY))
        vprot = (vprot & ~VPROT_WRITECOPY) | VPROT_WRITE;

    ret = VIRTUAL_Win32Flags[vprot & 0x0f];
    if (vprot & VPROT_GUARD) ret |= PAGE_GUARD;
    if (map_prot & SEC_NOCACHE) ret |= PAGE_NOCACHE;
    return ret;
}

#if defined(__APPLE__) && defined(__aarch64__)
static SIZE_T get_committed_size( struct file_view *view, void *base, size_t max_size,
                                  BYTE *vprot, BYTE vprot_mask );

static NTSTATUS wow64_memory_append_range( struct wow64_memory_transaction *transaction,
                                           ULONG_PTR address, SIZE_T size,
                                           ULONG_PTR allocation_base, ULONG state,
                                           ULONG protect, ULONG flags )
{
    struct wine_wow64_memory_range_v1 *range;
    SIZE_T count = transaction->event.range_count;

    if (!size) return STATUS_SUCCESS;
    if (count)
    {
        range = &transaction->ranges[count - 1];
        if (range->address + range->size == address &&
            range->allocation_base == allocation_base && range->state == state &&
            range->protect == protect && range->flags == flags)
        {
            range->size += size;
            return STATUS_SUCCESS;
        }
    }
    if (count == transaction->range_capacity)
    {
        struct wine_wow64_memory_range_v1 *ranges;
        SIZE_T capacity = transaction->range_capacity ? transaction->range_capacity * 2 : 16;

        if (capacity < transaction->range_capacity ||
            capacity > ~(SIZE_T)0 / sizeof(*ranges)) return STATUS_NO_MEMORY;
        if (transaction->ranges == transaction->inline_ranges)
        {
            if (!(ranges = malloc( capacity * sizeof(*ranges) ))) return STATUS_NO_MEMORY;
            memcpy( ranges, transaction->inline_ranges,
                    count * sizeof(*transaction->inline_ranges) );
        }
        else if (!(ranges = realloc( transaction->ranges, capacity * sizeof(*ranges) )))
            return STATUS_NO_MEMORY;
        transaction->ranges = ranges;
        transaction->range_capacity = capacity;
    }
    range = &transaction->ranges[count];
    range->address = address;
    range->size = size;
    range->allocation_base = allocation_base;
    range->state = state;
    range->protect = protect;
    range->flags = flags;
    range->reserved = 0;
    transaction->event.range_count = count + 1;
    return STATUS_SUCCESS;
}

/* Capture a complete, sorted description of a translated-shadow slice.
 * virtual_mutex must be held by the caller. */
static NTSTATUS wow64_memory_snapshot_range( struct wow64_memory_transaction *transaction,
                                             ULONG_PTR address, SIZE_T size )
{
    const ULONG_PTR shadow_start = WINE_LOW_VA_SHADOW_BASE;
    const ULONG_PTR shadow_end = WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE;
    ULONG_PTR cursor, end;
    struct file_view *view;
    NTSTATUS status;

    transaction->event.range_count = 0;
    if (!size) return STATUS_SUCCESS;
    if ((address & page_mask) || (size & page_mask) || address < shadow_start ||
        size > shadow_end - address) return STATUS_INVALID_ADDRESS;
    end = address + size;
    cursor = address;

    view = find_view_at_or_after( (void *)address );
    while (view)
    {
        struct wine_rb_entry *next = rb_next( &view->entry );
        struct file_view *current = view;
        ULONG_PTR view_start = (ULONG_PTR)current->base;
        ULONG_PTR view_end;

        view = next ? WINE_RB_ENTRY_VALUE( next, struct file_view, entry ) : NULL;

        if (current->size > ~(ULONG_PTR)0 - view_start) return STATUS_INVALID_ADDRESS;
        view_end = view_start + current->size;
        if (view_end <= cursor) continue;
        if (view_start >= end) break;

        if (view_start > cursor)
        {
            SIZE_T gap = min( view_start, end ) - cursor;

            if ((status = wow64_memory_append_range( transaction, cursor, gap, 0,
                                                      MEM_FREE, PAGE_NOACCESS, 0 )))
                return status;
            cursor += gap;
            if (cursor == end) break;
        }

        view_start = max( view_start, cursor );
        view_end = min( view_end, end );
        if (!(current->protect & VPROT_WOW64_TRANSLATED))
        {
            if ((status = wow64_memory_append_range( transaction, view_start,
                                                      view_end - view_start, 0,
                                                      MEM_FREE, PAGE_NOACCESS, 0 )))
                return status;
        }
        else
        {
            ULONG_PTR page;

            for (page = view_start; page < view_end;)
            {
                BYTE vprot;
                SIZE_T run;
                ULONG state, protect, flags = WINE_WOW64_MEMORY_RANGE_TRANSLATED;

                if (current->protect & SEC_RESERVE)
                    run = get_committed_size( current, (void *)page, view_end - page,
                                              &vprot, 0xff );
                else
                    run = get_vprot_range_size( (char *)page, view_end - page,
                                                0xff, &vprot );
                state = (vprot & VPROT_COMMITTED) ? MEM_COMMIT : MEM_RESERVE;
                protect = state == MEM_COMMIT ? get_win32_prot( vprot, current->protect ) : 0;
                if (vprot & VPROT_WRITEWATCH)
                    flags |= WINE_WOW64_MEMORY_RANGE_LOGICAL_WRITE_FAULT;

                if (!run || (run & page_mask) || run > view_end - page)
                    return STATUS_INVALID_ADDRESS;
                if ((status = wow64_memory_append_range(
                         transaction, page, run, (ULONG_PTR)current->base, state, protect,
                         flags )))
                    return status;
                page += run;
            }
        }
        cursor = view_end;
        if (cursor == end) break;
    }
    if (cursor < end)
        return wow64_memory_append_range( transaction, cursor, end - cursor, 0,
                                          MEM_FREE, PAGE_NOACCESS, 0 );
    return STATUS_SUCCESS;
}

static void wow64_memory_capture_transaction( struct wow64_memory_transaction *transaction,
                                               NTSTATUS status, const void *address,
                                               SIZE_T size, const void *allocation_base )
{
    if (transaction->nested || !transaction->gate_locked) return;

    transaction->event.status = status;
    transaction->event.address = (ULONG_PTR)address;
    transaction->event.size_covered = size;
    transaction->event.allocation_base = (ULONG_PTR)allocation_base;
    transaction->event.snapshot_status = STATUS_SUCCESS;
    if (transaction->observer_begun && size)
        transaction->event.snapshot_status = wow64_memory_snapshot_range(
            transaction, (ULONG_PTR)address, size );
}

static NTSTATUS arm64ec_low_memory_append_range(
    struct arm64ec_low_memory_transaction *transaction, ULONG_PTR address, SIZE_T size,
    ULONG_PTR allocation_base, ULONG state, ULONG protect )
{
    struct wine_arm64ec_low_memory_range_v1 *range;
    SIZE_T count = transaction->event.range_count;

    if (!size) return STATUS_SUCCESS;
    if (count)
    {
        range = &transaction->ranges[count - 1];
        if (range->host_address <= UINT64_MAX - range->size &&
            range->host_address + range->size == address &&
            range->host_allocation_base == allocation_base &&
            range->state == state && range->protect == protect && !range->flags)
        {
            if (range->size > UINT64_MAX - size) return STATUS_INTEGER_OVERFLOW;
            range->size += size;
            return STATUS_SUCCESS;
        }
    }
    if (count == transaction->range_capacity)
    {
        struct wine_arm64ec_low_memory_range_v1 *ranges;
        SIZE_T capacity = transaction->range_capacity ? transaction->range_capacity * 2 : 16;

        if (capacity < transaction->range_capacity ||
            capacity > ~(SIZE_T)0 / sizeof(*ranges)) return STATUS_NO_MEMORY;
        if (transaction->ranges == transaction->inline_ranges)
        {
            if (!(ranges = malloc( capacity * sizeof(*ranges) ))) return STATUS_NO_MEMORY;
            memcpy( ranges, transaction->inline_ranges,
                    count * sizeof(*transaction->inline_ranges) );
        }
        else if (!(ranges = realloc( transaction->ranges, capacity * sizeof(*ranges) )))
            return STATUS_NO_MEMORY;
        transaction->ranges = ranges;
        transaction->range_capacity = capacity;
    }
    range = &transaction->ranges[count];
    range->host_address = address;
    range->size = size;
    range->host_allocation_base = allocation_base;
    range->state = state;
    range->protect = protect;
    range->flags = 0;
    range->reserved = 0;
    transaction->event.range_count = count + 1;
    return STATUS_SUCCESS;
}

/* Capture the authoritative post-state of an AMD64-low shadow slice.
 * virtual_mutex must be held.  Untagged ranges are intentionally published as
 * MEM_FREE: numeric location in the shadow never establishes LOW ownership. */
static NTSTATUS arm64ec_low_memory_snapshot_range(
    struct arm64ec_low_memory_transaction *transaction, ULONG_PTR address, SIZE_T size )
{
    const ULONG_PTR shadow_start = WINE_LOW_VA_SHADOW_BASE;
    const ULONG_PTR shadow_end = WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE;
    ULONG_PTR cursor, end;
    struct file_view *view;
    NTSTATUS status;

    transaction->event.range_count = 0;
    if (!size) return STATUS_SUCCESS;
    if ((address & page_mask) || (size & page_mask) || address < shadow_start ||
        size > shadow_end - address) return STATUS_INVALID_ADDRESS;
    end = address + size;
    cursor = address;

    view = find_view_at_or_after( (void *)address );
    while (view)
    {
        struct wine_rb_entry *next = rb_next( &view->entry );
        struct file_view *current = view;
        ULONG_PTR view_start = (ULONG_PTR)current->base;
        ULONG_PTR view_end;

        view = next ? WINE_RB_ENTRY_VALUE( next, struct file_view, entry ) : NULL;
        if (current->size > ~(ULONG_PTR)0 - view_start) return STATUS_INVALID_ADDRESS;
        view_end = view_start + current->size;
        if (view_end <= cursor) continue;
        if (view_start >= end) break;

        if (view_start > cursor)
        {
            SIZE_T gap = min( view_start, end ) - cursor;

            if ((status = arm64ec_low_memory_append_range(
                     transaction, cursor, gap, 0, MEM_FREE, PAGE_NOACCESS )))
                return status;
            cursor += gap;
            if (cursor == end) break;
        }

        view_start = max( view_start, cursor );
        view_end = min( view_end, end );
        if (!(current->protect & VPROT_AMD64_LOW_TRANSLATED))
        {
            if ((status = arm64ec_low_memory_append_range(
                     transaction, view_start, view_end - view_start, 0,
                     MEM_FREE, PAGE_NOACCESS )))
                return status;
        }
        else
        {
            ULONG_PTR page;

            if ((ULONG_PTR)current->base < shadow_start ||
                current->size > shadow_end - (ULONG_PTR)current->base)
                return STATUS_INVALID_ADDRESS;
            for (page = view_start; page < view_end;)
            {
                BYTE vprot;
                SIZE_T run;
                ULONG state, protect;

                if (current->protect & SEC_RESERVE)
                    run = get_committed_size( current, (void *)page, view_end - page,
                                              &vprot, 0xff );
                else
                    run = get_vprot_range_size( (char *)page, view_end - page,
                                                0xff, &vprot );
                if (!run || (run & page_mask) || run > view_end - page)
                    return STATUS_INVALID_ADDRESS;
                state = (vprot & VPROT_COMMITTED) ? MEM_COMMIT : MEM_RESERVE;
                protect = state == MEM_COMMIT ?
                    get_win32_prot( vprot, current->protect ) : 0;
                if ((status = arm64ec_low_memory_append_range(
                         transaction, page, run, (ULONG_PTR)current->base,
                         state, protect )))
                    return status;
                page += run;
            }
        }
        cursor = view_end;
        if (cursor == end) break;
    }
    if (cursor < end)
        return arm64ec_low_memory_append_range( transaction, cursor, end - cursor, 0,
                                                MEM_FREE, PAGE_NOACCESS );
    return STATUS_SUCCESS;
}

static void arm64ec_low_memory_capture_transaction(
    struct arm64ec_low_memory_transaction *transaction, NTSTATUS status,
    const void *address, SIZE_T size, const void *allocation_base )
{
    if (transaction->nested || !transaction->gate_locked) return;

    transaction->event.status = status;
    transaction->event.snapshot_status = STATUS_SUCCESS;
    if (transaction->event.flags & WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT)
    {
        address = (void *)(ULONG_PTR)WINE_LOW_VA_SHADOW_BASE;
        size = WINE_LOW_VA_SHADOW_SIZE;
        allocation_base = NULL;
    }
    else if (!size)
    {
        /* An invalid unmap/release still has to resume a successfully paused
         * provider with an authoritative post-state.  Retain the conservative
         * page used by begin() when no containing view was resolved. */
        address = (void *)(ULONG_PTR)transaction->event.host_address;
        size = transaction->event.size_covered;
        allocation_base = NULL;
    }
    transaction->event.host_address = (ULONG_PTR)address;
    transaction->event.size_covered = size;
    transaction->event.host_allocation_base = (ULONG_PTR)allocation_base;
    if (transaction->observer_begun && size)
        transaction->event.snapshot_status = arm64ec_low_memory_snapshot_range(
            transaction, (ULONG_PTR)address, size );
}

#endif

int32_t __wine_register_wow64_memory_observer(
    const struct wine_wow64_memory_observer_v1 *observer )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction = {0};
    sigset_t sigset;
    NTSTATUS status;

    if (!observer || observer->version != WINE_WOW64_MEMORY_OBSERVER_VERSION ||
        observer->size < sizeof(*observer) || !observer->begin || !observer->complete ||
        !(observer->capabilities & WINE_WOW64_MEMORY_OBSERVER_CAP_LOGICAL_WRITE_FAULT) ||
        (observer->capabilities & ~WINE_WOW64_MEMORY_OBSERVER_CAP_LOGICAL_WRITE_FAULT))
        return STATUS_INVALID_PARAMETER;
    if (wow64_memory_observer_callback_active || wow64_memory_current_transaction)
        return STATUS_INVALID_PARAMETER;

    mutex_lock( &wow64_memory_observer_mutex );
    if (wow64_memory_observer_registered)
    {
        mutex_unlock( &wow64_memory_observer_mutex );
        return STATUS_ALREADY_REGISTERED;
    }
    if (!is_wow64() || !is_wow64_shadow_address( user_shared_data ))
    {
        mutex_unlock( &wow64_memory_observer_mutex );
        return STATUS_NOT_SUPPORTED;
    }

    transaction.observer = observer;
    transaction.gate_locked = TRUE;
    transaction.event.version = WINE_WOW64_MEMORY_OBSERVER_VERSION;
    transaction.event.size = sizeof(transaction.event);
    transaction.event.operation = WINE_WOW64_MEMORY_RESYNC;
    transaction.event.flags = WINE_WOW64_MEMORY_EVENT_FULL_SNAPSHOT;
    transaction.event.address = WINE_LOW_VA_SHADOW_BASE;
    transaction.event.size_covered = WINE_LOW_VA_SHADOW_SIZE;
    transaction.ranges = transaction.inline_ranges;
    transaction.range_capacity = ARRAY_SIZE(transaction.inline_ranges);

    wow64_memory_observer_callback_active = TRUE;
    status = observer->begin( observer->context, WINE_WOW64_MEMORY_RESYNC,
                              WINE_LOW_VA_SHADOW_BASE, WINE_LOW_VA_SHADOW_SIZE,
                              0, &transaction.observer_transaction );
    wow64_memory_observer_callback_active = FALSE;
    if (status)
    {
        __atomic_store_n( &wow64_memory_observer_required, FALSE, __ATOMIC_RELEASE );
        mutex_unlock( &wow64_memory_observer_mutex );
        return status;
    }
    transaction.observer_begun = TRUE;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    /* Observer begin has stopped every guest engine.  Publish the transaction
     * requirement only after excluding native writers too; before this point
     * the physical host-page policy remains authoritative. */
    __atomic_store_n( &wow64_memory_observer_required, TRUE, __ATOMIC_RELEASE );
    status = wow64_memory_snapshot_range( &transaction, WINE_LOW_VA_SHADOW_BASE,
                                          WINE_LOW_VA_SHADOW_SIZE );
    if (!status) status = wow64_memory_set_logical_write_fault_delegation( TRUE );
    /* A failed handoff has already restored the physical write-fault policy.
     * Clear the mutation fence before dropping virtual_mutex so concurrent
     * native writes cannot observe required==TRUE with delegation disabled
     * while the provider's failure completion is still running. */
    if (status)
        __atomic_store_n( &wow64_memory_observer_required, FALSE, __ATOMIC_RELEASE );
    else
    {
        /* Make the observer visible before native writers can enter
         * virtual_mutex under delegated enforcement.  They will then block on
         * the observer gate until this full-snapshot completion returns. */
        wow64_memory_observer = *observer;
        wow64_memory_observer_registered = TRUE;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    transaction.event.status = STATUS_SUCCESS;
    transaction.event.snapshot_status = status;
    transaction.event.ranges = transaction.ranges;
    wow64_memory_observer_callback_active = TRUE;
    observer->complete( observer->context, transaction.observer_transaction,
                        &transaction.event );
    wow64_memory_observer_callback_active = FALSE;
    if (transaction.ranges != transaction.inline_ranges) free( transaction.ranges );
    mutex_unlock( &wow64_memory_observer_mutex );
    return status;
#else
    (void)observer;
    return STATUS_NOT_SUPPORTED;
#endif
}

int32_t __wine_register_arm64ec_low_memory_observer_v1(
    const struct wine_arm64ec_low_memory_observer_v1 *observer )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct arm64ec_low_memory_transaction transaction = {0};
    sigset_t sigset;
    NTSTATUS status;

    if (!observer || observer->version != WINE_ARM64EC_LOW_MEMORY_OBSERVER_VERSION ||
        observer->size != sizeof(*observer) || !observer->begin || !observer->complete ||
        observer->capabilities !=
            WINE_ARM64EC_LOW_MEMORY_OBSERVER_CAP_EXACT_POST_SNAPSHOT)
        return STATUS_INVALID_PARAMETER;
    if (arm64ec_low_memory_observer_callback_active ||
        arm64ec_code_observer_callback_active ||
        arm64ec_low_memory_current_transaction || arm64ec_code_current_transaction)
        return STATUS_INVALID_PARAMETER;

    mutex_lock( &arm64ec_low_memory_observer_mutex );
    if (arm64ec_low_memory_observer_registered)
    {
        mutex_unlock( &arm64ec_low_memory_observer_mutex );
        return STATUS_ALREADY_REGISTERED;
    }
    if (!is_arm64ec())
    {
        mutex_unlock( &arm64ec_low_memory_observer_mutex );
        return STATUS_NOT_SUPPORTED;
    }

    transaction.observer = observer;
    transaction.gate_locked = TRUE;
    transaction.event.version = WINE_ARM64EC_LOW_MEMORY_OBSERVER_VERSION;
    transaction.event.size = sizeof(transaction.event);
    transaction.event.operation = WINE_WOW64_MEMORY_RESYNC;
    transaction.event.flags = WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT;
    transaction.event.host_address = WINE_LOW_VA_SHADOW_BASE;
    transaction.event.size_covered = WINE_LOW_VA_SHADOW_SIZE;
    transaction.ranges = transaction.inline_ranges;
    transaction.range_capacity = ARRAY_SIZE(transaction.inline_ranges);

    arm64ec_low_memory_observer_callback_active = TRUE;
    status = observer->begin( observer->context, WINE_WOW64_MEMORY_RESYNC,
                              WINE_LOW_VA_SHADOW_BASE, WINE_LOW_VA_SHADOW_SIZE,
                              0, &transaction.observer_transaction );
    arm64ec_low_memory_observer_callback_active = FALSE;
    if (status)
    {
        mutex_unlock( &arm64ec_low_memory_observer_mutex );
        return status;
    }
    transaction.observer_begun = TRUE;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    /* begin() has stopped every x64 engine.  Set the mutation fence only
     * after native writers are excluded; this keeps registration and the
     * initial exact snapshot atomic without weakening identity mappings. */
    __atomic_store_n( &arm64ec_low_memory_observer_required, TRUE,
                      __ATOMIC_RELEASE );
    status = arm64ec_low_memory_snapshot_range(
        &transaction, WINE_LOW_VA_SHADOW_BASE, WINE_LOW_VA_SHADOW_SIZE );
    if (status)
        __atomic_store_n( &arm64ec_low_memory_observer_required, FALSE,
                          __ATOMIC_RELEASE );
    else
    {
        arm64ec_low_memory_observer = *observer;
        arm64ec_low_memory_observer_registered = TRUE;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    transaction.event.status = STATUS_SUCCESS;
    transaction.event.snapshot_status = status;
    transaction.event.ranges = transaction.ranges;
    arm64ec_low_memory_observer_callback_active = TRUE;
    observer->complete( observer->context, transaction.observer_transaction,
                        &transaction.event );
    arm64ec_low_memory_observer_callback_active = FALSE;
    if (transaction.ranges != transaction.inline_ranges) free( transaction.ranges );
    mutex_unlock( &arm64ec_low_memory_observer_mutex );
    return status;
#else
    (void)observer;
    return STATUS_NOT_SUPPORTED;
#endif
}

int32_t __wine_register_arm64ec_code_observer_v1(
    const struct wine_arm64ec_code_observer_v1 *observer )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct arm64ec_code_transaction transaction = {0};
    sigset_t sigset;
    NTSTATUS status;

    if (!observer || observer->version != WINE_ARM64EC_CODE_OBSERVER_VERSION ||
        observer->size != sizeof(*observer) || !observer->begin || !observer->complete ||
        (observer->capabilities & ~WINE_ARM64EC_CODE_OBSERVER_CAP_DATA_ALIAS) !=
            WINE_ARM64EC_CODE_OBSERVER_CAP_EXACT_INVALIDATION_RANGES)
        return STATUS_INVALID_PARAMETER;
    if (arm64ec_code_observer_callback_active ||
        arm64ec_low_memory_observer_callback_active ||
        arm64ec_code_current_transaction || arm64ec_low_memory_current_transaction)
        return STATUS_INVALID_PARAMETER;

    mutex_lock( &arm64ec_code_observer_mutex );
    if (arm64ec_code_observer_registered)
    {
        mutex_unlock( &arm64ec_code_observer_mutex );
        return STATUS_ALREADY_REGISTERED;
    }
    if (!is_arm64ec())
    {
        mutex_unlock( &arm64ec_code_observer_mutex );
        return STATUS_NOT_SUPPORTED;
    }

    arm64ec_cpu_alias_enabled =
        (observer->capabilities & WINE_ARM64EC_CODE_OBSERVER_CAP_DATA_ALIAS) &&
        getenv( "ORRERY_ARM64EC_DATA_ALIAS" ) &&
        !strcmp( getenv( "ORRERY_ARM64EC_DATA_ALIAS" ), "1" );

    arm64ec_stack_probe_enabled = arm64ec_cpu_alias_enabled &&
        getenv( "ORRERY_ARM64EC_STACK_PROBE" ) &&
        !strcmp( getenv( "ORRERY_ARM64EC_STACK_PROBE" ), "1" );
    arm64ec_stack_auto_enabled = arm64ec_stack_probe_enabled &&
        getenv( "ORRERY_ARM64EC_STACK_AUTOINIT" ) && !strcmp( getenv( "ORRERY_ARM64EC_STACK_AUTOINIT" ), "1" );

    transaction.observer = observer;
    transaction.gate_locked = TRUE;
    transaction.ranges = transaction.inline_ranges;
    transaction.range_capacity = ARRAY_SIZE(transaction.inline_ranges);
    transaction.event.version = WINE_ARM64EC_CODE_OBSERVER_VERSION;
    transaction.event.size = sizeof(transaction.event);
    transaction.event.operation = WINE_ARM64EC_CODE_RESYNC;
    transaction.event.flags = WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION;
    transaction.event.status = STATUS_SUCCESS;

    arm64ec_code_observer_callback_active = TRUE;
    status = observer->begin( observer->context, WINE_ARM64EC_CODE_RESYNC,
                              &transaction.observer_transaction );
    arm64ec_code_observer_callback_active = FALSE;
    if (status)
    {
        mutex_unlock( &arm64ec_code_observer_mutex );
        return status;
    }
    transaction.observer_begun = TRUE;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    /* begin() has stopped every x64 engine.  Exclude all bitmap writers before
     * making the observer mandatory, then retain that fence for process life. */
    __atomic_store_n( &arm64ec_code_observer_required, TRUE, __ATOMIC_RELEASE );
    arm64ec_code_observer = *observer;
    arm64ec_code_observer_registered = TRUE;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    transaction.event.ranges = transaction.ranges;
    arm64ec_code_observer_callback_active = TRUE;
    observer->complete( observer->context, transaction.observer_transaction,
                        &transaction.event );
    arm64ec_code_observer_callback_active = FALSE;
    mutex_unlock( &arm64ec_code_observer_mutex );
    return STATUS_SUCCESS;
#else
    (void)observer;
    return STATUS_NOT_SUPPORTED;
#endif
}


static DWORD get_virtual_protect_old_prot( BYTE vprot, unsigned int map_prot, ULONG new_prot )
{
    DWORD old = get_win32_prot( vprot, map_prot );

    if (map_prot & SEC_IMAGE)
    {
        switch (new_prot & 0xff)
        {
        case PAGE_READONLY:
        case PAGE_READWRITE:
            if ((old & 0xff) == PAGE_WRITECOPY) old = (old & ~0xff) | PAGE_READWRITE;
            break;
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
            if ((old & 0xff) == PAGE_EXECUTE_WRITECOPY) old = (old & ~0xff) | PAGE_EXECUTE_READWRITE;
            break;
        }
    }
    return old;
}


/***********************************************************************
 *           get_vprot_flags
 *
 * Build page protections from Win32 flags.
 */
static NTSTATUS get_vprot_flags( DWORD protect, unsigned int *vprot, BOOL image )
{
    switch(protect & 0xff)
    {
    case PAGE_READONLY:
        *vprot = VPROT_READ;
        break;
    case PAGE_READWRITE:
        if (image)
            *vprot = VPROT_READ | VPROT_WRITECOPY;
        else
            *vprot = VPROT_READ | VPROT_WRITE;
        break;
    case PAGE_WRITECOPY:
        *vprot = VPROT_READ | VPROT_WRITECOPY;
        break;
    case PAGE_EXECUTE:
        *vprot = VPROT_EXEC;
        break;
    case PAGE_EXECUTE_READ:
        *vprot = VPROT_EXEC | VPROT_READ;
        break;
    case PAGE_EXECUTE_READWRITE:
        if (image)
            *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY;
        else
            *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITE;
        break;
    case PAGE_EXECUTE_WRITECOPY:
        *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY;
        break;
    case PAGE_NOACCESS:
        *vprot = 0;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }
    if (protect & PAGE_GUARD) *vprot |= VPROT_GUARD;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           mprotect_exec
 *
 * Wrapper for mprotect, adds PROT_EXEC if forced by force_exec_prot
 */
static inline int mprotect_exec( void *base, size_t size, int unix_prot, BOOL cpu_provider_owned )
{
#if defined(__APPLE__) && defined(__aarch64__)
    /* Guest code is fetched by the CPU provider and must never become host ARM64 executable code. */
    if (cpu_provider_owned) unix_prot &= ~PROT_EXEC;
#else
    cpu_provider_owned = FALSE;
#endif

    if (!cpu_provider_owned && force_exec_prot && (unix_prot & PROT_READ) && !(unix_prot & PROT_EXEC))
    {
        TRACE( "forcing exec permission on %p-%p\n", base, (char *)base + size - 1 );
        if (!mprotect( base, size, unix_prot | PROT_EXEC )) return 0;
        /* exec + write may legitimately fail, in that case fall back to write only */
        if (!(unix_prot & PROT_WRITE)) return -1;
    }

    return mprotect( base, size, unix_prot );
}


#if defined(__APPLE__) && defined(__aarch64__)
/* Return the exact logical end and the host-page-rounded physical ownership
 * end of a view.  View bases are host-page aligned by the view allocator. */
static BOOL get_mprotect_view_bounds( const struct file_view *view, ULONG_PTR *logical_end,
                                      ULONG_PTR *physical_end )
{
    ULONG_PTR start = (ULONG_PTR)view->base;
    SIZE_T physical_size;

    if ((start & host_page_mask) || !view->size || (view->size & page_mask) ||
        view->size > ~(ULONG_PTR)0 - start || view->size > ~(SIZE_T)0 - host_page_mask)
        return FALSE;
    physical_size = (view->size + host_page_mask) & ~host_page_mask;
    if (!physical_size || physical_size > ~(ULONG_PTR)0 - start) return FALSE;
    *logical_end = start + view->size;
    *physical_end = start + physical_size;
    return TRUE;
}


static struct file_view *next_mprotect_view( struct file_view *view )
{
    struct wine_rb_entry *next = rb_next( &view->entry );

    return next ? WINE_RB_ENTRY_VALUE( next, struct file_view, entry ) : NULL;
}


/* ARM64X images can contain native ARM64EC and translated AMD64 code in the
 * same image view.  The EC bitmap is the validated, page-granular ownership
 * record; use it to decide whether a physical host page needs host EXEC. */
static BOOL arm64ec_host_page_has_native_code( const struct file_view *view,
                                               const void *address )
{
    ULONG_PTR host_start = (ULONG_PTR)address & ~host_page_mask;
    ULONG_PTR start, end, page, end_page, host_end, view_end, physical_end;
    SIZE_T map_word_count;
    const UINT64 *map;

    /* Missing or inconsistent ownership metadata must preserve host EXEC.  It
     * is safer to reject a translated write than to make native EC code NX. */
    if (!(view->protect & VPROT_ARM64EC) || !arm64ec_view ||
        !get_mprotect_view_bounds( view, &view_end, &physical_end ) ||
        host_start >= physical_end || host_page_size > ~(ULONG_PTR)0 - host_start)
        return TRUE;
    host_end = host_start + host_page_size;
    start = max( host_start, (ULONG_PTR)view->base );
    end = min( host_end, view_end );
    if (start >= end) return FALSE;

    page = start >> page_shift;
    end_page = end >> page_shift;
    map = arm64ec_view->base;
    map_word_count = arm64ec_view->size / sizeof(*map);
    while (page < end_page)
    {
        if (page / 64 >= map_word_count) return TRUE;
        if ((map[page / 64] >> (page & 63)) & 1) return TRUE;
        page++;
    }
    return FALSE;
}


static BOOL mprotect_host_page_is_cpu_provider_owned( const struct file_view *view,
                                                       const void *address )
{
    if (!view) return FALSE;
    if (view->protect & VPROT_CPU_PROVIDER_OWNED) return TRUE;
    return (view->protect & VPROT_ARM64EC) &&
           !arm64ec_host_page_has_native_code( view, address );
}


/* Darwin's JIT write-protect state is per-thread and applies to every MAP_JIT
 * mapping, so Wine valloc views must not join the CPU provider's JIT domain.
 * After an RWX mprotect denial, a private valloc may remain logically RWX but
 * physically RW/NX; translated code stays readable to the CPU provider and a
 * native execution attempt raises an access violation.  Never drop host EXEC
 * when a distinct committed RX logical page shares the host-page run. */
static BOOL can_retry_native_writable_exec( const struct file_view *view, const void *base,
                                            size_t size, ULONG_PTR logical_start,
                                            ULONG_PTR logical_end, BYTE set, BYTE clear )
{
    ULONG_PTR start = (ULONG_PTR)base, end, view_start, view_end, physical_end;
    const char *page, *page_end;
    BOOL found_exec = FALSE;

    if (!view || !is_view_valloc( view ) ||
        (view->protect & (VPROT_SYSTEM | VPROT_CPU_PROVIDER_OWNED)) || !size ||
        size > ~(ULONG_PTR)0 - start ||
        !get_mprotect_view_bounds( view, &view_end, &physical_end )) return FALSE;

    end = start + size;
    view_start = (ULONG_PTR)view->base;
    if (start < view_start || end > physical_end) return FALSE;
    page = (const char *)max( start, view_start );
    page_end = (const char *)min( end, view_end );
    if (page >= page_end || ((ULONG_PTR)page & page_mask) ||
        ((ULONG_PTR)page_end & page_mask)) return FALSE;

    while (page < page_end)
    {
        BYTE vprot = get_page_vprot( page );

        if ((ULONG_PTR)page < logical_end &&
            (ULONG_PTR)page + page_size > logical_start)
            vprot = (vprot & ~clear) | set;

        if ((vprot & (VPROT_COMMITTED | VPROT_GUARD | VPROT_EXEC)) ==
            (VPROT_COMMITTED | VPROT_EXEC))
        {
            if (!(vprot & (VPROT_WRITE | VPROT_WRITECOPY))) return FALSE;
            found_exec = TRUE;
        }
        page += page_size;
    }
    return found_exec;
}
#endif


static inline int mprotect_range_run( struct file_view *view, void *base, size_t size, int unix_prot,
                                      BOOL cpu_provider_owned, ULONG_PTR logical_start,
                                      ULONG_PTR logical_end, BYTE set, BYTE clear )
{
    int first_errno;

    if (!mprotect_exec( base, size, unix_prot, cpu_provider_owned )) return 0;
    first_errno = errno;
    TRACE( "mprotect failed for %p-%p, unix_prot %#x, owner %#x, cpu_provider_owned %u, "
           "logical %p-%p, set %#x, clear %#x, errno %d\n",
           base, (char *)base + size, unix_prot, view ? view->protect : 0,
           cpu_provider_owned, (void *)logical_start, (void *)logical_end,
           set, clear, first_errno );

#if defined(__APPLE__) && defined(__aarch64__)
    if (first_errno == EACCES &&
        (unix_prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC) &&
        can_retry_native_writable_exec( view, base, size, logical_start, logical_end,
                                        set, clear ))
        return mprotect( base, size, unix_prot & ~PROT_EXEC );
#endif
    errno = first_errno;
    return -1;
}


/* Project a logical protection delta before filtering translated guard lanes.
 * Applying the delta to the already-filtered union would lose the underlying
 * access of a guarded lane that is being unguarded. */
static BYTE get_mprotect_translated_host_page_vprot( const void *addr,
                                                      ULONG_PTR logical_start,
                                                      ULONG_PTR logical_end,
                                                      BYTE set, BYTE clear )
{
    const char *base = ROUND_ADDR( addr, host_page_mask );
    BOOL delegated = wow64_memory_logical_write_fault_is_delegated();
    BYTE vprot = 0;
    size_t i;

    for (i = 0; i < host_page_size; i += page_size)
    {
        ULONG_PTR page = (ULONG_PTR)base + i;
        BYTE page_vprot = get_page_vprot( (void *)page );

        /* Without 4K provider delegation a write-watch clear is necessarily
         * host-page-wide; otherwise a watched sibling keeps the whole page
         * read-only.  Other deltas retain their exact logical lane scope. */
        if (!delegated && (clear & VPROT_WRITEWATCH))
            page_vprot &= ~VPROT_WRITEWATCH;
        if (page < logical_end && page + page_size > logical_start)
            page_vprot = (page_vprot & ~clear) | set;
        if (!(page_vprot & VPROT_COMMITTED) || (page_vprot & VPROT_GUARD)) continue;
        if (delegated) page_vprot &= ~VPROT_WRITEWATCH;
        vprot |= page_vprot;
    }
    return vprot;
}


/* For experimental high aliases, retain guards outside the exact 4KB
 * delta. Clearing a bit from the host-wide union would silently expose a
 * second guarded operand to native instructions before it can fault. */
static BYTE get_mprotect_native_host_vprot( struct file_view *view, const char *base,
                                            ULONG_PTR start, ULONG_PTR end,
                                            BYTE set, BYTE clear )
{
#if defined(__APPLE__) && defined(__aarch64__)
    BYTE combined = 0, common = VPROT_READ | VPROT_WRITE | VPROT_COMMITTED;
    SIZE_T offset;
    if (arm64ec_high_data_view( view ))
    {
        for (offset = 0; offset < host_page_size; offset += page_size)
        {
            ULONG_PTR page = (ULONG_PTR)base + offset;
            BYTE prot = get_page_vprot( (void *)page );
            if (page < end && page + page_size > start) prot = (prot & ~clear) | set;
            combined |= prot;
            common &= prot;
        }
        /* Native accesses must obey every logical lane. The provider uses
         * a separate alias when the ordinary access permissions differ. */
        if (combined & (VPROT_EXEC | VPROT_WRITEWATCH | VPROT_WRITECOPY)) return combined;
        if (!(common & VPROT_COMMITTED)) return 0;
        return (combined & ~(VPROT_READ | VPROT_WRITE)) | (common & (VPROT_READ | VPROT_WRITE));
    }
#endif
    return (get_host_page_vprot( base ) & ~clear) | set;
}

/* Apply protection to one physical ownership domain.  Runs with identical host
 * protection may be coalesced only inside this domain. */
static int mprotect_range_domain( struct file_view *view, void *base, size_t size,
                                  ULONG_PTR logical_start, ULONG_PTR logical_end,
                                  BYTE set, BYTE clear )
{
    BOOL translated_shadow = view && is_shadow_translated_vprot( view->protect );
    BOOL cpu_provider_owned, next_cpu_provider_owned;
    size_t i, count;
    char *addr = base;
    int prot, next;
    BYTE vprot;

    assert( size && !((ULONG_PTR)base & host_page_mask) && !(size & host_page_mask) );

    vprot = translated_shadow
            ? get_mprotect_translated_host_page_vprot( addr, logical_start, logical_end,
                                                       set, clear )
            : get_mprotect_native_host_vprot( view, addr, logical_start, logical_end, set, clear );
    prot = get_unix_prot( vprot );
    cpu_provider_owned = mprotect_host_page_is_cpu_provider_owned( view, addr );
    for (count = i = 1; i < size / host_page_size; i++, count++)
    {
        vprot = translated_shadow
                ? get_mprotect_translated_host_page_vprot( addr + count * host_page_size,
                                                           logical_start, logical_end,
                                                           set, clear )
                : get_mprotect_native_host_vprot( view, addr + count * host_page_size,
                                                    logical_start, logical_end, set, clear );
        next = get_unix_prot( vprot );
        next_cpu_provider_owned = mprotect_host_page_is_cpu_provider_owned(
            view, addr + count * host_page_size );
        if (next == prot && next_cpu_provider_owned == cpu_provider_owned) continue;
        if (mprotect_range_run( view, addr, count * host_page_size, prot,
                                cpu_provider_owned, logical_start, logical_end,
                                set, clear )) return -1;
        addr += count * host_page_size;
        prot = next;
        cpu_provider_owned = next_cpu_provider_owned;
        count = 0;
    }
    return mprotect_range_run( view, addr, count * host_page_size, prot,
                               cpu_provider_owned, logical_start, logical_end,
                               set, clear );
}


#if defined(__APPLE__) && defined(__aarch64__)
/* Validate the complete physical ownership walk before the first mprotect().
 * The tree is stable under virtual_mutex, so the returned first view can be
 * reused by the apply pass without allocating a domain list. */
static int validate_mprotect_domains( ULONG_PTR start, ULONG_PTR end,
                                      struct file_view **first_ret )
{
    struct file_view *view = find_view_at_or_after( (void *)start );

    *first_ret = view;
    if (view && (ULONG_PTR)view->base < end)
    {
        struct wine_rb_entry *prev_entry = rb_prev( &view->entry );

        if (prev_entry)
        {
            struct file_view *prev = WINE_RB_ENTRY_VALUE( prev_entry, struct file_view, entry );
            ULONG_PTR prev_logical_end, prev_physical_end;

            if (!get_mprotect_view_bounds( prev, &prev_logical_end, &prev_physical_end ) ||
                prev_physical_end > (ULONG_PTR)view->base) goto invalid;
        }
    }

    while (view && (ULONG_PTR)view->base < end)
    {
        struct file_view *next = next_mprotect_view( view );
        ULONG_PTR logical_end, physical_end;

        if (!get_mprotect_view_bounds( view, &logical_end, &physical_end )) goto invalid;
        if ((ULONG_PTR)view->base < start && logical_end <= start) goto invalid;
        if (next && (((ULONG_PTR)next->base & host_page_mask) ||
                     (ULONG_PTR)next->base < physical_end)) goto invalid;
        view = next;
    }
    return 0;

invalid:
    errno = EINVAL;
    return -1;
}
#endif


/***********************************************************************
 *           mprotect_range
 *
 * Call mprotect on a page range, applying the protections from the per-page byte.
 */
static int mprotect_range( void *base, size_t size, BYTE set, BYTE clear )
{
    ULONG_PTR logical_start = (ULONG_PTR)base, logical_end, start, end;

    if (!size) return 0;
    if (size > ~(ULONG_PTR)0 - logical_start) goto invalid;
    logical_end = logical_start + size;
    if (logical_end > ~(ULONG_PTR)0 - host_page_mask) goto invalid;
    start = logical_start & ~host_page_mask;
    end = (logical_end + host_page_mask) & ~host_page_mask;
    if (end <= start) goto invalid;

#if defined(__APPLE__) && defined(__aarch64__)
    {
        struct file_view *view;
        ULONG_PTR address = start;

        if (validate_mprotect_domains( start, end, &view )) return -1;
        while (address < end)
        {
            ULONG_PTR domain_end;

            if (!view || (ULONG_PTR)view->base > address)
            {
                domain_end = view ? min( end, (ULONG_PTR)view->base ) : end;
                assert( domain_end > address );
                if (mprotect_range_domain( NULL, (void *)address, domain_end - address,
                                           logical_start, logical_end,
                                           set, clear )) return -1;
            }
            else
            {
                ULONG_PTR logical_view_end, physical_view_end;
                BOOL valid = get_mprotect_view_bounds( view, &logical_view_end,
                                                       &physical_view_end );

                assert( valid && physical_view_end > address );
                if (!valid || physical_view_end <= address) abort_process( STATUS_ACCESS_DENIED );
                domain_end = min( end, physical_view_end );
                if (mprotect_range_domain( view, (void *)address, domain_end - address,
                                           logical_start, logical_end,
                                           set, clear )) return -1;
                if (domain_end == physical_view_end) view = next_mprotect_view( view );
            }
            address = domain_end;
        }
        return 0;
    }
#else
    return mprotect_range_domain( find_view( base, size ), (void *)start, end - start,
                                  logical_start, logical_end, set, clear );
#endif

invalid:
    errno = EINVAL;
    return -1;
}


#if defined(__APPLE__) && defined(__aarch64__)
/* Switch the physical backing between native write-watch enforcement and the
 * observer's 4K logical enforcement.  The registration caller holds both the
 * observer gate and virtual_mutex, and begin() has stopped every guest engine,
 * so no translated instruction can run between the full snapshot and this
 * reprotection pass. */
static NTSTATUS wow64_memory_set_logical_write_fault_delegation( BOOL enable )
{
    struct file_view *view;
    BOOL rollback_failed = FALSE;
    BOOL previous = wow64_memory_logical_write_fault_is_delegated();
    NTSTATUS status = STATUS_SUCCESS;

    __atomic_store_n( &wow64_memory_logical_write_fault_delegated, enable,
                      __ATOMIC_RELEASE );
    view = find_view_at_or_after( (void *)WINE_LOW_VA_SHADOW_BASE );
    while (view && (ULONG_PTR)view->base < WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE)
    {
        struct wine_rb_entry *next = rb_next( &view->entry );

        if ((view->protect & VPROT_WOW64_TRANSLATED) &&
            mprotect_range( view->base, view->size, 0, 0 ))
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        view = next ? WINE_RB_ENTRY_VALUE( next, struct file_view, entry ) : NULL;
    }
    if (!status) return STATUS_SUCCESS;

    /* Restore the old physical policy before the provider is allowed to
     * resume.  A rollback mprotect failure means host protection can no longer
     * represent the logical state, so fail closed rather than publishing a
     * partially delegated address space. */
    __atomic_store_n( &wow64_memory_logical_write_fault_delegated, previous,
                      __ATOMIC_RELEASE );
    view = find_view_at_or_after( (void *)WINE_LOW_VA_SHADOW_BASE );
    while (view && (ULONG_PTR)view->base < WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE)
    {
        struct wine_rb_entry *next = rb_next( &view->entry );

        if ((view->protect & VPROT_WOW64_TRANSLATED) &&
            mprotect_range( view->base, view->size, 0, 0 ))
        {
            ERR( "failed to restore translated host protection for %p-%p\n",
                 view->base, (char *)view->base + view->size );
            rollback_failed = TRUE;
        }
        view = next ? WINE_RB_ENTRY_VALUE( next, struct file_view, entry ) : NULL;
    }
    if (rollback_failed) abort_process( STATUS_ACCESS_DENIED );
    return status;
}
#endif


/* Validate the complete shadow trust policy before the apply pass can change
 * any ordinary prefix.  Only exact WoW64-translated ownership is accepted;
 * fixed-low AMD64 views, ambiguous owner tags, and gaps are rejected. */
#if defined(__APPLE__) && defined(__aarch64__)
static int validate_mprotect_memory_access_range( const void *base, size_t size )
{
    ULONG_PTR address = (ULONG_PTR)base, end;

    if (!size) return 0;
    if (size > ~(ULONG_PTR)0 - address) goto invalid;
    end = address + size;
    while (address < end)
    {
        struct file_view *view;
        ULONG_PTR logical_end, physical_end;

        if (address < WINE_LOW_VA_SHADOW_BASE)
        {
            address = min( end, (ULONG_PTR)WINE_LOW_VA_SHADOW_BASE );
            continue;
        }
        if (address >= WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE) break;
        if (!(view = find_view( (void *)address, 0 )) ||
            (view->protect & VPROT_CPU_PROVIDER_OWNED) != VPROT_WOW64_TRANSLATED ||
            !get_mprotect_view_bounds( view, &logical_end, &physical_end ) ||
            logical_end <= address)
            goto invalid;
        address = min( end, logical_end );
    }
    return 0;

invalid:
    errno = EINVAL;
    return -1;
}
#endif


/* Apply physical protection without widening ownership across a logical view
 * boundary.  mprotect_range() further splits each validated segment into
 * physical ownership domains, including ordinary views and gaps outside the
 * shadow. */
static int mprotect_memory_access_range( void *base, size_t size, BYTE set, BYTE clear )
{
    if (!overlaps_wow64_shadow( base, size ))
        return mprotect_range( base, size, set, clear );

#if defined(__APPLE__) && defined(__aarch64__)
    if (validate_mprotect_memory_access_range( base, size )) return -1;
    while (size)
    {
        struct file_view *view;
        SIZE_T available = size;
        ULONG_PTR address = (ULONG_PTR)base;

        if (address < WINE_LOW_VA_SHADOW_BASE)
            available = min( available, WINE_LOW_VA_SHADOW_BASE - address );
        else if (address < WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE)
        {
            ULONG_PTR logical_end, physical_end;
            BOOL valid;

            view = find_view( base, 0 );
            valid = view && get_mprotect_view_bounds( view, &logical_end, &physical_end );
            assert( valid && logical_end > address );
            if (!valid || logical_end <= address) abort_process( STATUS_ACCESS_DENIED );
            available = min( available, (SIZE_T)(logical_end - address) );
        }
        if (mprotect_range( base, available, set, clear )) return -1;
        base = (char *)base + available;
        size -= available;
    }
    return 0;
#else
    return mprotect_range( base, size, set, clear );
#endif
}


#define VPROT_STACK_SNAPSHOT_PAGES 64

/* Protection changes normally span only a few logical pages.  Keep those
 * snapshots off the heap; larger ranges use one byte per logical page. */
static BYTE *snapshot_vprot( const void *base, size_t size, BYTE *stack, size_t stack_count )
{
    const char *page = base;
    size_t i, page_count = size >> page_shift;
    BYTE *snapshot = stack;

    if (page_count > stack_count && !(snapshot = malloc( page_count ))) return NULL;
    for (i = 0; i < page_count; i++, page += page_size)
        snapshot[i] = get_page_vprot( page );
    return snapshot;
}


static void restore_vprot_or_abort( void *base, size_t size, const BYTE *snapshot )
{
    size_t i, run_start, page_count = size >> page_shift;
    BYTE run_vprot;

    for (run_start = 0; run_start < page_count; run_start = i)
    {
        run_vprot = snapshot[run_start];
        for (i = run_start + 1; i < page_count && snapshot[i] == run_vprot; i++);
        set_page_vprot( (char *)base + run_start * page_size,
                        (i - run_start) * page_size, run_vprot );
    }
    /* Metadata must be authoritative before any observer capture.  If the host
     * protections cannot be restored too, continuing would publish split state. */
    if (mprotect_range( base, size, 0, 0 ))
    {
        ERR( "failed to restore protection for %p-%p\n", base, (char *)base + size );
        abort_process( STATUS_ACCESS_DENIED );
    }
}


static void restore_uniform_vprot_or_abort( void *base, size_t size, BYTE vprot )
{
    set_page_vprot( base, size, vprot );
    /* Metadata must be authoritative before any observer capture.  If the host
     * protections cannot be restored too, continuing would publish split state. */
    if (mprotect_range( base, size, 0, 0 ))
    {
        ERR( "failed to restore protection for %p-%p\n", base, (char *)base + size );
        abort_process( STATUS_ACCESS_DENIED );
    }
}


/***********************************************************************
 *           set_vprot
 *
 * Change the protection of a range of pages.
 */
static BOOL set_vprot( struct file_view *view, void *base, size_t size, BYTE vprot )
{
#if defined(__APPLE__) && defined(__aarch64__)
    if (view->protect & VPROT_WOW64_TRANSLATED) wow64_memory_assert_transaction();
    if (view->protect & VPROT_AMD64_LOW_TRANSLATED)
        arm64ec_low_memory_assert_transaction();
#endif
    if (!use_kernel_writewatch && view->protect & VPROT_WRITEWATCH)
    {
        /* each page may need different protections depending on write watch flag */
        set_page_vprot_bits( base, size, vprot & ~VPROT_WRITEWATCH, ~vprot & ~VPROT_WRITEWATCH );
    }
    else
    {
        if (enable_write_exceptions && is_vprot_exec_write( vprot )) vprot |= VPROT_WRITEWATCH;
        else if (use_kernel_writewatch && view->protect & VPROT_WRITEWATCH) vprot &= ~VPROT_WRITEWATCH;
        set_page_vprot( base, size, vprot );
    }
    return !mprotect_range( base, size, 0, 0 );
}


/***********************************************************************
 *           set_protection
 *
 * Set page protections on a range of pages
 */
static NTSTATUS set_protection( struct file_view *view, void *base, SIZE_T size, ULONG protect )
{
    BYTE stack_snapshot[VPROT_STACK_SNAPSHOT_PAGES];
    BYTE *old_vprot, current_vprot, compare_mask;
    BOOL preserve_writewatch;
    unsigned int vprot;
    NTSTATUS status;

    if (!size || (size & page_mask) || ((UINT_PTR)base & page_mask))
        return STATUS_INVALID_PARAMETER;
    if ((status = get_vprot_flags( protect, &vprot, view->protect & SEC_IMAGE ))) return status;
#if defined(__APPLE__) && defined(__aarch64__)
    if (view->protect & VPROT_WOW64_OWNED_BACKING) return STATUS_ACCESS_DENIED;
#endif
    if (view->protect & SEC_IMAGE)
    {
        BYTE current = get_host_page_vprot( base );

        switch (protect & 0xff)
        {
        case PAGE_READWRITE:
            if (current & (VPROT_READ | VPROT_WRITECOPY))
                vprot = (vprot & ~VPROT_WRITECOPY) | VPROT_WRITE;
            break;
        case PAGE_EXECUTE_READWRITE:
            if (current & (VPROT_EXEC | VPROT_WRITECOPY))
                vprot = (vprot & ~VPROT_WRITECOPY) | VPROT_WRITE;
            break;
        }
    }
    if (is_view_valloc( view ))
    {
        if (vprot & VPROT_WRITECOPY) return STATUS_INVALID_PAGE_PROTECTION;
    }
    else
    {
        BYTE access = vprot & (VPROT_READ | VPROT_WRITE | VPROT_EXEC);
        unsigned int allowed = view->protect;

        if ((view->protect & VPROT_WRITECOPY) && (access & VPROT_WRITE)) allowed |= VPROT_WRITE;
        if ((allowed & access) != access) return STATUS_INVALID_PAGE_PROTECTION;
    }

    vprot |= VPROT_COMMITTED;
    preserve_writewatch = !use_kernel_writewatch && (view->protect & VPROT_WRITEWATCH);
    if (!preserve_writewatch)
    {
        if (enable_write_exceptions && is_vprot_exec_write( vprot )) vprot |= VPROT_WRITEWATCH;
        else if (use_kernel_writewatch && view->protect & VPROT_WRITEWATCH)
            vprot &= ~VPROT_WRITEWATCH;
    }
    compare_mask = preserve_writewatch ? ~VPROT_WRITEWATCH : ~(BYTE)0;
    if (get_vprot_range_size( base, size, compare_mask, &current_vprot ) == size &&
        (current_vprot & compare_mask) == (vprot & compare_mask))
        return set_vprot( view, base, size, vprot ) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;

    if (!(old_vprot = snapshot_vprot( base, size, stack_snapshot,
                                      ARRAY_SIZE(stack_snapshot) ))) return STATUS_NO_MEMORY;
    if (!set_vprot( view, base, size, vprot ))
    {
        TRACE( "set_vprot failed for %p-%p, protect %#x, vprot %#x, owner %#x, errno %d\n",
               base, (char *)base + size, protect, vprot, view->protect, errno );
        restore_vprot_or_abort( base, size, old_vprot );
        status = STATUS_ACCESS_DENIED;
    }
    else status = STATUS_SUCCESS;
    if (old_vprot != stack_snapshot) free( old_vprot );
    return status;
}


/***********************************************************************
 *           commit_arm64ec_map
 *
 * Make sure that the pages corresponding to the address range of the view
 * are committed in the ARM64EC code map.
 */
static void commit_arm64ec_map( struct file_view *view )
{
    size_t start = ((size_t)view->base >> page_shift) / 8;
    size_t end = (((size_t)view->base + view->size) >> page_shift) / 8;
    size_t size = ROUND_SIZE( start, end + 1 - start, page_mask );
    void *base = ROUND_ADDR( (char *)arm64ec_view->base + start, page_mask );

    view->protect |= VPROT_ARM64EC;
    set_vprot( arm64ec_view, base, size, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED );
}


/***********************************************************************
 *           update_write_watches
 */
static void update_write_watches( void *base, size_t size, size_t accessed_size )
{
    if (!size) return;
    TRACE( "updating watch %p-%p-%p\n", base, (char *)base + accessed_size, (char *)base + size );
    /* clear write watch flag on accessed pages */
    set_page_vprot_bits( base, accessed_size, 0, VPROT_WRITEWATCH );
    /* restore page protections on the entire range */
    if (mprotect_memory_access_range( base, size, 0, 0 ))
        abort_process( STATUS_ACCESS_DENIED );
}


#if defined(__APPLE__) && defined(__aarch64__)
/* Publish native writes after a blocking kernel/server operation.  Until this
 * short transaction completes, stale provider state is conservative: the
 * affected guest lane may fault once more, but it cannot gain write access.
 * The caller must not hold virtual_mutex or the observer gate. */
static void wow64_memory_publish_native_write_or_abort( void *base, SIZE_T size )
{
    struct wow64_memory_transaction transaction;
    void *capture_base;
    SIZE_T capture_size;
    NTSTATUS status, snapshot_status;
    sigset_t sigset;

    if (!size || !wow64_memory_logical_write_fault_is_delegated() ||
        !overlaps_wow64_shadow( base, size )) return;
    capture_base = ROUND_ADDR( base, page_mask );
    capture_size = ROUND_SIZE( base, size, page_mask );
    if (!is_inside_wow64_shadow( capture_base, capture_size ))
        abort_process( STATUS_ACCESS_VIOLATION );

    status = wow64_memory_begin_transaction( &transaction, TRUE,
                                              WINE_WOW64_MEMORY_PROTECT,
                                              capture_base, capture_size, NULL );
    if (status) abort_process( status );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    set_page_vprot_bits( capture_base, capture_size, 0, VPROT_WRITEWATCH );
    if (mprotect_memory_access_range( capture_base, capture_size, 0, 0 ))
        status = STATUS_ACCESS_DENIED;
    wow64_memory_capture_transaction( &transaction, status, capture_base,
                                       capture_size, NULL );
    snapshot_status = transaction.event.snapshot_status;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    wow64_memory_complete_transaction( &transaction );
    if (status || snapshot_status) abort_process( status ? status : snapshot_status );
}
#endif


/***********************************************************************
 *           reset_write_watches
 *
 * Reset write watches in a memory range.
 */
static void reset_write_watches( void *base, SIZE_T size )
{
    if (use_kernel_writewatch)
    {
        kernel_writewatch_reset( base, size );
        if (!enable_write_exceptions) return;
        if (!set_page_vprot_exec_write_protect( base, size )) return;
    }
    else set_page_vprot_bits( base, size, VPROT_WRITEWATCH, 0 );

    mprotect_range( base, size, 0, 0 );
}


/***********************************************************************
 *           unmap_extra_space
 *
 * Release the extra memory while keeping the range starting on the alignment boundary.
 */
static inline void *unmap_extra_space( void *ptr, size_t total_size, size_t wanted_size, size_t align_mask )
{
    if ((ULONG_PTR)ptr & align_mask)
    {
        size_t extra = align_mask + 1 - ((ULONG_PTR)ptr & align_mask);
        munmap( ptr, extra );
        ptr = (char *)ptr + extra;
        total_size -= extra;
    }
    if (total_size > wanted_size)
        munmap( (char *)ptr + wanted_size, total_size - wanted_size );
    return ptr;
}


/***********************************************************************
 *           find_reserved_free_area_outside_preloader
 *
 * Find a free area inside a reserved area, skipping the preloader reserved range.
 * virtual_mutex must be held by caller.
 */
static void *find_reserved_free_area_outside_preloader( void *start, void *end, size_t size,
                                                        int top_down, size_t align_mask )
{
    void *ret;

    if (preload_reserve_end >= end)
    {
        if (preload_reserve_start <= start) return NULL;  /* no space in that area */
        if (preload_reserve_start < end) end = preload_reserve_start;
    }
    else if (preload_reserve_start <= start)
    {
        if (preload_reserve_end > start) start = preload_reserve_end;
    }
    else /* range is split in two by the preloader reservation, try both parts */
    {
        if (top_down)
        {
            ret = find_reserved_free_area( preload_reserve_end, end, size, top_down, align_mask );
            if (ret) return ret;
            end = preload_reserve_start;
        }
        else
        {
            ret = find_reserved_free_area( start, preload_reserve_start, size, top_down, align_mask );
            if (ret) return ret;
            start = preload_reserve_end;
        }
    }
    return find_reserved_free_area( start, end, size, top_down, align_mask );
}

static void *find_reserved_free_area_for_view( void *start, void *end, size_t size,
                                               int top_down, size_t align_mask,
                                               BOOL translated_wow64 )
{
#if defined(__APPLE__) && defined(__aarch64__)
    void *shadow_start = (void *)WINE_LOW_VA_SHADOW_BASE;
    void *shadow_end = (void *)(WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE);
    void *ret;

    if (!translated_wow64 && start < shadow_end && end > shadow_start)
    {
        if (top_down)
        {
            if (end > shadow_end &&
                (ret = find_reserved_free_area_outside_preloader( max( start, shadow_end ), end,
                                                                   size, top_down, align_mask )))
                return ret;
            if (start < shadow_start)
                return find_reserved_free_area_outside_preloader( start, min( end, shadow_start ),
                                                                  size, top_down, align_mask );
        }
        else
        {
            if (start < shadow_start &&
                (ret = find_reserved_free_area_outside_preloader( start, min( end, shadow_start ),
                                                                   size, top_down, align_mask )))
                return ret;
            if (end > shadow_end)
                return find_reserved_free_area_outside_preloader( max( start, shadow_end ), end,
                                                                  size, top_down, align_mask );
        }
        return NULL;
    }
#endif
    return find_reserved_free_area_outside_preloader( start, end, size, top_down, align_mask );
}

/***********************************************************************
 *           map_reserved_area
 *
 * Try to map some space inside a reserved area.
 * virtual_mutex must be held by caller.
 */
static void *map_reserved_area( void *limit_low, void *limit_high, size_t size, int top_down,
                                int unix_prot, size_t align_mask, BOOL translated_wow64 )
{
    void *ptr = NULL;
    struct reserved_area *area;

    if (top_down)
    {
        LIST_FOR_EACH_ENTRY_REV( area, &reserved_areas, struct reserved_area, entry )
        {
            void *start = area->base;
            void *end = (char *)start + area->size;

            if (start >= limit_high) continue;
            if (end <= limit_low) return NULL;
            if (start < limit_low) start = (void *)ROUND_SIZE( 0, limit_low, host_page_mask );
            if (end > limit_high) end = ROUND_ADDR( limit_high, host_page_mask );
            ptr = find_reserved_free_area_for_view( start, end, size, top_down, align_mask,
                                                    translated_wow64 );
            if (ptr) break;
        }
    }
    else
    {
        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            void *start = area->base;
            void *end = (char *)start + area->size;

            if (start >= limit_high) return NULL;
            if (end <= limit_low) continue;
            if (start < limit_low) start = (void *)ROUND_SIZE( 0, limit_low, host_page_mask );
            if (end > limit_high) end = ROUND_ADDR( limit_high, host_page_mask );
            ptr = find_reserved_free_area_for_view( start, end, size, top_down, align_mask,
                                                    translated_wow64 );
            if (ptr) break;
        }
    }
    if (ptr && anon_mmap_fixed( ptr, size, unix_prot, 0 ) != ptr) ptr = NULL;
    return ptr;
}

/***********************************************************************
 *           map_fixed_area
 *
 * Map a memory area at a fixed address.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_fixed_area( void *base, size_t size, int unix_prot )
{
    struct reserved_area *area;
    NTSTATUS status;
    char *start = base, *end = (char *)base + ROUND_SIZE( 0, size, host_page_mask );

    if ((UINT_PTR)base & host_page_mask) return STATUS_CONFLICTING_ADDRESSES;
    if (find_view_range( base, size )) return STATUS_CONFLICTING_ADDRESSES;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        char *area_start = area->base;
        char *area_end = area_start + area->size;

        if (area_start >= end) break;
        if (area_end <= start) continue;
        if (area_start > start)
        {
            if (anon_mmap_tryfixed( start, area_start - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
            start = area_start;
        }
        if (area_end >= end)
        {
            if (anon_mmap_fixed( start, end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
            return STATUS_SUCCESS;
        }
        if (anon_mmap_fixed( start, area_end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
        start = area_end;
    }

    if (anon_mmap_tryfixed( start, end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
    return STATUS_SUCCESS;

failed:
    if (errno == ENOMEM)
    {
        ERR( "out of memory for %p-%p\n", base, (char *)base + size );
        status = STATUS_NO_MEMORY;
    }
    else if (errno == EEXIST) status = STATUS_CONFLICTING_ADDRESSES;
    else
    {
        ERR( "mmap error %s for %p-%p, unix_prot %#x\n",
             strerror(errno), base, (char *)base + size, unix_prot );
        status = STATUS_INVALID_PARAMETER;
    }
    unmap_area( base, start - (char *)base );
    return status;
}

/***********************************************************************
 *           map_view
 *
 * Create a view and mmap the corresponding memory area.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_view( struct file_view **view_ret, void *base, size_t size,
                          unsigned int alloc_type, unsigned int vprot,
                          ULONG_PTR limit_low, ULONG_PTR limit_high, size_t align_mask )
{
    int top_down = alloc_type & MEM_TOP_DOWN;
    void *ptr;
    int unix_prot = get_unix_prot( vprot );
    NTSTATUS status;

    if (!align_mask) align_mask = granularity_mask;
    assert( align_mask >= host_page_mask );

    if (alloc_type & MEM_REPLACE_PLACEHOLDER)
    {
        struct file_view *view;
        unsigned int old_protect;
#if defined(__APPLE__) && defined(__aarch64__)
        unsigned int requested_owner, view_owner;
#endif

        if (!(view = find_view( base, 0 ))) return STATUS_INVALID_PARAMETER;
        if (view->base != base || view->size != size) return STATUS_CONFLICTING_ADDRESSES;
        if (!(view->protect & VPROT_FREE_PLACEHOLDER)) return STATUS_INVALID_PARAMETER;

        TRACE( "found view %p, size %p, protect %#x.\n", view->base, (void *)view->size, view->protect );

#if defined(__APPLE__) && defined(__aarch64__)
        requested_owner = vprot & VPROT_SHADOW_TRANSLATED;
        view_owner = view->protect & VPROT_SHADOW_TRANSLATED;
        if (requested_owner == VPROT_SHADOW_TRANSLATED ||
            view_owner == VPROT_SHADOW_TRANSLATED)
            return STATUS_CONFLICTING_ADDRESSES;
        if ((requested_owner || view_owner) &&
            !is_inside_wow64_shadow( base, size ))
            return STATUS_CONFLICTING_ADDRESSES;
        if (requested_owner && view_owner && requested_owner != view_owner)
            return STATUS_CONFLICTING_ADDRESSES;
        if (view_owner && (vprot & SEC_IMAGE) && !requested_owner)
            return STATUS_CONFLICTING_ADDRESSES;
        vprot |= view_owner;
#endif
        old_protect = view->protect;
        view->protect = vprot | VPROT_PLACEHOLDER;
        if (!set_vprot( view, base, size, vprot ))
        {
            view->protect = old_protect;
            restore_uniform_vprot_or_abort( base, size, 0 );
            return STATUS_ACCESS_DENIED;
        }
        if (vprot & VPROT_WRITEWATCH)
        {
            kernel_writewatch_register_range( view, base, size );
            reset_write_watches( base, size );
        }
        *view_ret = view;
        return STATUS_SUCCESS;
    }

#if defined(__APPLE__) && defined(__aarch64__)
    if ((vprot & VPROT_SHADOW_TRANSLATED) == VPROT_SHADOW_TRANSLATED)
        return STATUS_INVALID_PARAMETER;
    if (base)
    {
        if (is_shadow_translated_vprot( vprot ))
        {
            if (!is_inside_wow64_shadow( base, size )) return STATUS_CONFLICTING_ADDRESSES;
        }
        else if (overlaps_wow64_shadow( base, size )) return STATUS_CONFLICTING_ADDRESSES;
    }
    else
    {
        ULONG_PTR range_low = max( limit_low, (ULONG_PTR)address_space_start );
        ULONG_PTR range_end = (ULONG_PTR)min( user_space_limit, host_addr_space_limit );
        ULONG_PTR range_high = range_end ? range_end - 1 : ~(ULONG_PTR)0;

        if (limit_high && limit_high < range_high) range_high = limit_high;
        if (is_shadow_translated_vprot( vprot ))
        {
            if (!limits_are_inside_wow64_shadow( range_low, range_high ))
                return STATUS_CONFLICTING_ADDRESSES;
        }
        else if ((limit_low || limit_high || top_down) &&
                 range_low < WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE &&
                 range_high >= WINE_LOW_VA_SHADOW_BASE)
        {
            NTSTATUS first = STATUS_NO_MEMORY, second = STATUS_NO_MEMORY;
            ULONG_PTR below_high = WINE_LOW_VA_SHADOW_BASE - 1;
            ULONG_PTR above_low = WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE;

            /* Keep the shadow unavailable to ordinary native allocations while retaining
             * the caller's allocation direction on both sides of the excluded window. */
            if (top_down)
            {
                if (above_low < range_high)
                    first = map_view( view_ret, NULL, size, alloc_type, vprot,
                                      max( range_low, above_low ), range_high, align_mask );
                if (!first) return first;
                if (range_low < below_high)
                    second = map_view( view_ret, NULL, size, alloc_type, vprot,
                                       range_low, min( range_high, below_high ), align_mask );
            }
            else
            {
                if (range_low < below_high)
                    first = map_view( view_ret, NULL, size, alloc_type, vprot,
                                      range_low, min( range_high, below_high ), align_mask );
                if (!first) return first;
                if (above_low < range_high)
                    second = map_view( view_ret, NULL, size, alloc_type, vprot,
                                       max( range_low, above_low ), range_high, align_mask );
            }
            if (!second) return second;
            return first != STATUS_NO_MEMORY ? first : second;
        }
    }
#endif

    if (limit_high && limit_low >= limit_high) return STATUS_INVALID_PARAMETER;

    if (use_kernel_writewatch && vprot & VPROT_WRITEWATCH)
        unix_prot = get_unix_prot( vprot & ~VPROT_WRITEWATCH );

    unix_prot &= ~PROT_EXEC;

    if (base)
    {
        if (is_beyond_limit( base, size, address_space_limit )) return STATUS_WORKING_SET_LIMIT_RANGE;
        if (limit_low && base < (void *)limit_low) return STATUS_CONFLICTING_ADDRESSES;
        if (limit_high && is_beyond_limit( base, size, (void *)limit_high )) return STATUS_CONFLICTING_ADDRESSES;
        if (is_beyond_limit( base, size, host_addr_space_limit )) return STATUS_CONFLICTING_ADDRESSES;
        if ((status = map_fixed_area( base, size, unix_prot ))) return status;
        if (is_beyond_limit( base, size, working_set_limit )) working_set_limit = address_space_limit;
        ptr = base;
    }
    else
    {
        void *start = address_space_start;
        void *end = min( user_space_limit, host_addr_space_limit );
        size_t host_size = ROUND_SIZE( 0, size, host_page_mask );
        size_t unmap_size, view_size = host_size + align_mask + 1;

        if (limit_low && (void *)limit_low > start) start = (void *)limit_low;
        if (limit_high && (void *)limit_high < end) end = (char *)limit_high + 1;

        if ((ptr = map_reserved_area( start, end, host_size, top_down, unix_prot, align_mask,
                                      is_shadow_translated_vprot( vprot ) )))
        {
            TRACE( "got mem in reserved area %p-%p\n", ptr, (char *)ptr + size );
            goto done;
        }

        if (start > address_space_start || end < host_addr_space_limit || top_down)
        {
            if (!(ptr = map_free_area( start, end, host_size, top_down, unix_prot, align_mask )))
                return STATUS_NO_MEMORY;
            TRACE( "got mem with map_free_area %p-%p\n", ptr, (char *)ptr + size );
            goto done;
        }

        for (;;)
        {
            if ((ptr = anon_mmap_alloc( view_size, unix_prot )) == MAP_FAILED)
            {
                status = (errno == ENOMEM) ? STATUS_NO_MEMORY : STATUS_INVALID_PARAMETER;
                ERR( "anon mmap error %s, size %p, unix_prot %#x\n",
                     strerror(errno), (void *)view_size, unix_prot );
                return status;
            }
            TRACE( "got mem with anon mmap %p-%p\n", ptr, (char *)ptr + size );
#if defined(__APPLE__) && defined(__aarch64__)
            /* The unconstrained ASLR path cannot be converted to map_free_area()
             * on Darwin, where arbitrary fixed mappings may be unavailable.
             * Reject an ordinary OS-selected candidate that touches the shadow
             * and retry without changing the allocator's placement policy. */
            if (!is_shadow_translated_vprot( vprot ) &&
                overlaps_wow64_shadow( ptr, view_size ))
            {
                /* Restore reserved areas rather than punching a hole in the
                 * shadow reservation.  Otherwise mmap() can return the same
                 * invalid candidate forever. */
                unmap_area( ptr, view_size );
                continue;
            }
#endif
            /* if we got something beyond the user limit, unmap it and retry */
            if (!is_beyond_limit( ptr, view_size, user_space_limit )) break;
            unmap_size = unmap_area_above_user_limit( ptr, view_size );
            if (unmap_size) munmap( ptr, unmap_size );
        }
        ptr = unmap_extra_space( ptr, view_size, host_size, align_mask );
    }
done:
    status = create_view( view_ret, ptr, size, vprot );
    if (status != STATUS_SUCCESS) unmap_area( ptr, size );
    return status;
}


/***********************************************************************
 *           map_file_into_view
 *
 * Wrapper for mmap() to map a file into a view, falling back to read if mmap fails.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_file_into_view( struct file_view *view, int fd, size_t start, size_t size,
                                    off_t offset, unsigned int vprot, BOOL removable )
{
    char *map_addr, *host_addr;
    size_t map_size, host_size;
    int prot = PROT_READ | PROT_WRITE;
    unsigned int flags = MAP_FIXED;
    BOOL try_mmap;

    assert( start < view->size );
    assert( start + size <= view->size );

    if (vprot & VPROT_WRITE) flags |= MAP_SHARED;
    else if (vprot & VPROT_WRITECOPY) flags |= MAP_PRIVATE;
    else
    {
        /* changes to the file are not guaranteed to be visible in read-only MAP_PRIVATE mappings,
         * but they are on Linux so we take advantage of it */
#ifdef __linux__
        flags |= MAP_PRIVATE;
#else
        flags |= MAP_SHARED;
        prot &= ~PROT_WRITE;
#endif
    }

    map_size = ROUND_SIZE( start, size, page_mask );
    map_addr = ROUND_ADDR( (char *)view->base + start, page_mask );
    host_addr = ROUND_ADDR( (char *)view->base + start, host_page_mask );
    /* last page doesn't need to be a full page */
    if (map_addr + map_size >= (char *)view->base + view->size) host_size = map_size;
    else host_size = ROUND_SIZE( 0, map_size, host_page_mask );

    /* only try mmap if media is not removable (or if we require write access),
       and if alignment is correct */
    try_mmap = (!removable || (flags & MAP_SHARED)) && host_addr == map_addr && host_size == map_size;

#ifdef __APPLE__
    /* Hardened Runtime prevents executable protection on file-backed PE image pages.
     * Keep private image pages in the anonymous view so that the final mprotect(PROT_EXEC)
     * succeeds, but preserve the file backing required by writable shared sections. */
    if ((view->protect & SEC_IMAGE) && !(vprot & VPROT_WRITE)) try_mmap = FALSE;
#endif

    if (try_mmap)
    {
        if (mmap( host_addr, host_size, prot, flags, fd, offset ) != MAP_FAILED)
            return STATUS_SUCCESS;

        switch (errno)
        {
        case EINVAL:  /* file offset is not page-aligned, fall back to read() */
            break;
        case ENOEXEC:
        case ENODEV:  /* filesystem doesn't support mmap(), fall back to read() */
            if (vprot & VPROT_WRITE)
            {
                ERR( "shared writable mmap not supported, broken filesystem?\n" );
                return STATUS_NOT_SUPPORTED;
            }
            break;
        case EACCES:
        case EPERM:  /* access error, fall back to read() */
            if (vprot & VPROT_WRITE) return STATUS_ACCESS_DENIED;
            break;
        default:
            ERR( "mmap error %s, range %p-%p, unix_prot %#x\n",
                 strerror(errno), map_addr, map_addr + map_size, prot );
            return STATUS_NO_MEMORY;
        }
    }

    if (vprot & VPROT_WRITE)
    {
#if defined(__APPLE__) && defined(__aarch64__)
        if (view->protect & SEC_IMAGE)
        {
            size_t physical_size = ROUND_SIZE( host_addr, map_addr + map_size - host_addr,
                                               host_page_mask );
            size_t physical_view_size = ROUND_SIZE( 0, view->size, host_page_mask );
            size_t physical_offset;
            ssize_t ret;

            /* Darwin cannot represent one writable shared 4K Windows image lane
             * inside a larger host page without also sharing the adjacent private
             * image lanes.  Preserve the image contents and per-lane protections
             * with an anonymous copy rather than rejecting the entire image.  Only
             * the cross-process visibility of this physically unrepresentable lane
             * is lost; representable address, size, and offset combinations retain
             * their MAP_SHARED backing.  Remove this fallback if Darwin gains
             * coherent sub-host-page mappings. */
            if (host_addr < (char *)view->base) return STATUS_INVALID_IMAGE_FORMAT;
            physical_offset = host_addr - (char *)view->base;
            if (!physical_size || physical_offset > physical_view_size ||
                physical_size > physical_view_size - physical_offset)
                return STATUS_INVALID_IMAGE_FORMAT;
            if (mprotect( host_addr, physical_size, PROT_READ | PROT_WRITE ))
                return STATUS_ACCESS_DENIED;
            ret = pread( fd, map_addr, size, offset );
            if (ret < 0 || (size_t)ret != size)
            {
                ERR( "failed to copy unaligned shared image mapping %p-%p: %s\n",
                     map_addr, map_addr + size, ret < 0 ? strerror(errno) : "short read" );
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            return STATUS_SUCCESS;
        }
#endif
        ERR( "unaligned shared mapping %p-%p not supported\n", map_addr, map_addr + map_size );
        return STATUS_INVALID_PARAMETER;
    }

    mprotect( map_addr, map_size, PROT_READ | PROT_WRITE );
    pread( fd, map_addr, size, offset );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           get_committed_size
 *
 * Get the size of the committed range with equal masked vprot bytes starting at base.
 * Also return the protections for the first page.
 */
static SIZE_T get_committed_size( struct file_view *view, void *base, size_t max_size, BYTE *vprot, BYTE vprot_mask )
{
    SIZE_T offset, size;
#if defined(__APPLE__) && defined(__aarch64__)
    BOOL translated_read_only = FALSE;
    BOOL server_committed = FALSE;
#endif

    base = ROUND_ADDR( base, page_mask );
    offset = (char *)base - (char *)view->base;

    if (view->protect & SEC_RESERVE)
    {
        size = 0;

        *vprot = get_page_vprot( base );

        SERVER_START_REQ( get_mapping_committed_range )
        {
            req->base   = wine_server_client_ptr( view->base );
            req->offset = offset;
            if (!wine_server_call( req ))
            {
                size = min( reply->size, max_size );
                if (reply->committed)
                {
                    *vprot |= VPROT_COMMITTED;
#if defined(__APPLE__) && defined(__aarch64__)
                    server_committed = TRUE;
                    translated_read_only =
                        ((view->protect & VPROT_WOW64_TRANSLATED) &&
                         wow64_memory_observer_is_required() &&
                         !wow64_memory_current_transaction) ||
                        ((view->protect & VPROT_AMD64_LOW_TRANSLATED) &&
                         arm64ec_low_memory_observer_is_required() &&
                         !arm64ec_low_memory_current_transaction);
                    if (!translated_read_only)
#endif
                        set_page_vprot_bits( base, size, VPROT_COMMITTED, 0 );
                }
            }
        }
        SERVER_END_REQ;

        if (!size || !(vprot_mask & ~VPROT_COMMITTED)) return size;
#if defined(__APPLE__) && defined(__aarch64__)
        if (translated_read_only && server_committed)
        {
            BYTE local_vprot;

            /* A query may run from complete(), after the observer gate has
             * been acquired but outside virtual_mutex.  Preserve its read-only
             * contract: the server response already bounds a uniformly
             * committed run, so combine it with local non-commit protection
             * without changing the structural VPROT cache.  A later provider
             * fault resolves and publishes any newly discovered shared commit
             * from normal context. */
            size = get_vprot_range_size( base, size,
                                         vprot_mask & ~VPROT_COMMITTED,
                                         &local_vprot );
            *vprot = local_vprot | VPROT_COMMITTED;
            return size;
        }
#endif
    }
    else size = min( view->size - offset, max_size );

    return get_vprot_range_size( base, size, vprot_mask, vprot );
}


/***********************************************************************
 *           decommit_pages
 *
 * Decommit some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS decommit_pages( struct file_view *view, char *base, size_t size )
{
    char *host_end, *host_start = (char *)ROUND_SIZE( 0, base, host_page_mask );

#if defined(__APPLE__) && defined(__aarch64__)
    if (view->protect & VPROT_WOW64_TRANSLATED) wow64_memory_assert_transaction();
    if (view->protect & VPROT_AMD64_LOW_TRANSLATED)
        arm64ec_low_memory_assert_transaction();
#endif
    if (!size)
    {
        size = view->size;
        host_end = host_start + view->size;
    }
    else host_end = ROUND_ADDR( base + size, host_page_mask );

    if (host_start < host_end) anon_mmap_fixed( host_start, host_end - host_start, PROT_NONE, 0 );
    set_page_vprot_bits( base, size, 0, VPROT_COMMITTED );
    if (host_start < host_end) kernel_writewatch_register_range( view, host_start, host_end - host_start );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           remove_pages_from_view
 *
 * Remove some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS remove_pages_from_view( struct file_view *view, char *base, size_t size )
{
    assert( size < view->size );

    if (view->base != base && base + size != (char *)view->base + view->size)
    {
        struct file_view *new_view = alloc_view();

        if (!new_view)
        {
            ERR( "out of memory for %p-%p\n", base, base + size );
            return STATUS_NO_MEMORY;
        }
        new_view->base    = base + size;
        new_view->size    = (char *)view->base + view->size - (char *)new_view->base;
        new_view->protect = view->protect;

        unregister_view( view );
        view->size = base - (char *)view->base;
        register_view( view );
        register_view( new_view );

        VIRTUAL_DEBUG_DUMP_VIEW( view );
        VIRTUAL_DEBUG_DUMP_VIEW( new_view );
    }
    else
    {
        unregister_view( view );
        if (view->base == base)
        {
            view->base = base + size;
            view->size -= size;
        }
        else view->size = base - (char *)view->base;

        register_view( view );
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           free_pages_preserve_placeholder
 *
 * Turn pages of a given view into a placeholder.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS free_pages_preserve_placeholder( struct file_view *view, char *base, size_t size )
{
    NTSTATUS status;
    BOOL arm64ec_owned = !!(view->protect & VPROT_ARM64EC);
    /* Only address-translation ownership survives.  An identity image ceases
     * to be CPU-provider-owned when its mapping becomes a free placeholder. */
    unsigned int translated_owner = view->protect & VPROT_SHADOW_TRANSLATED;

#if defined(__APPLE__) && defined(__aarch64__)
    if (translated_owner & VPROT_WOW64_TRANSLATED) wow64_memory_assert_transaction();
    if (translated_owner & VPROT_AMD64_LOW_TRANSLATED)
        arm64ec_low_memory_assert_transaction();
#endif
    if (!size) return STATUS_INVALID_PARAMETER_3;
    if (!(view->protect & VPROT_PLACEHOLDER)) return STATUS_CONFLICTING_ADDRESSES;
    if (view->protect & VPROT_FREE_PLACEHOLDER && size == view->size) return STATUS_CONFLICTING_ADDRESSES;

    if (size < view->size)
    {
        if ((UINT_PTR)base & host_page_mask ||
            ((size & host_page_mask) && base + size != (char *)view->base + view->size))
        {
            ERR( "unaligned partial free %p-%p\n", base, base + size );
            return STATUS_CONFLICTING_ADDRESSES;
        }

        status = remove_pages_from_view( view, base, size );
        if (status) return status;

        if (arm64ec_owned) clear_arm64ec_range( base, size );

        status = create_view( &view, base, size, VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER |
                                                translated_owner );
        if (status) return status;
    }
    else if (arm64ec_owned) clear_arm64ec_range( base, size );

    view->protect = VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER | translated_owner;
    set_page_vprot( view->base, view->size, 0 );
    anon_mmap_fixed( view->base, ROUND_SIZE( 0, view->size, host_page_mask ), PROT_NONE, 0 );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           free_pages
 *
 * Free some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS free_pages( struct file_view *view, char *base, size_t size )
{
    char *host_base = (char *)ROUND_SIZE( 0, base, host_page_mask );
    char *host_end = base + size;
    NTSTATUS status;

#if defined(__APPLE__) && defined(__aarch64__)
    if (view->protect & VPROT_WOW64_TRANSLATED) wow64_memory_assert_transaction();
    if (view->protect & VPROT_AMD64_LOW_TRANSLATED)
        arm64ec_low_memory_assert_transaction();
#endif
    if (size == view->size)
    {
        assert( base == view->base );
        delete_view( view );
        return STATUS_SUCCESS;
    }

    /* new view needs to start on page boundary */

    if (view->base == base)  /* shrink from the start */
    {
        if (size & host_page_mask)
        {
            ERR( "unaligned partial free %p-%p\n", base, base + size );
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else if (base + size < (char *)view->base + view->size)  /* create a hole */
    {
        if ((UINT_PTR)(base + size) & host_page_mask)
        {
            ERR( "unaligned partial free %p-%p\n", base, base + size );
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }

    status = remove_pages_from_view( view, base, size );
    if (!status)
    {
        set_page_vprot( base, size, 0 );
        if (view->protect & VPROT_ARM64EC) clear_arm64ec_range( base, size );
        if (host_base < host_end) unmap_area( host_base, host_end - host_base );
    }
    return status;
}


/***********************************************************************
 *           coalesce_placeholders
 *
 * Coalesce placeholder views.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS coalesce_placeholders( struct file_view *view, char *base, size_t size )
{
    struct rb_entry *next;
    struct file_view *curr_view, *next_view;
    unsigned int i, view_count = 0;
    size_t views_size = 0;

    if (!size) return STATUS_INVALID_PARAMETER_3;
    if (base != view->base) return STATUS_CONFLICTING_ADDRESSES;
#if defined(__APPLE__) && defined(__aarch64__)
    if (view->protect & VPROT_WOW64_TRANSLATED) wow64_memory_assert_transaction();
    if (view->protect & VPROT_AMD64_LOW_TRANSLATED)
        arm64ec_low_memory_assert_transaction();
#endif

    curr_view = view;
    while (curr_view->protect & VPROT_FREE_PLACEHOLDER)
    {
        ++view_count;
        views_size += curr_view->size;
        if (views_size >= size) break;
        if (!(next = rb_next( &curr_view->entry ))) break;
        next_view = RB_ENTRY_VALUE( next, struct file_view, entry );
        if ((char *)curr_view->base + curr_view->size != next_view->base) break;
        if ((view->protect ^ next_view->protect) & VPROT_SHADOW_TRANSLATED)
            return STATUS_CONFLICTING_ADDRESSES;
        curr_view = next_view;
    }

    if (view_count < 2 || size != views_size) return STATUS_CONFLICTING_ADDRESSES;

    for (i = 1; i < view_count; ++i)
    {
        curr_view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
        unregister_view( curr_view );
        free_view( curr_view );
    }

    unregister_view( view );
    view->size = views_size;
    register_view( view );

    VIRTUAL_DEBUG_DUMP_VIEW( view );

    return STATUS_SUCCESS;
}


/***********************************************************************
 *           allocate_dos_memory
 *
 * Allocate the DOS memory range.
 */
static NTSTATUS allocate_dos_memory( struct file_view **view, unsigned int vprot )
{
    size_t size;
    void *addr = NULL;
    void * const low_64k = (void *)0x10000;
    const size_t dosmem_size = 0x110000;
    int unix_prot = get_unix_prot( vprot ) & ~PROT_EXEC;

    /* check for existing view */

    if (find_view_range( 0, dosmem_size )) return STATUS_CONFLICTING_ADDRESSES;

    /* check without the first 64K */

    if (mmap_is_in_reserved_area( low_64k, dosmem_size - 0x10000 ) != 1)
    {
        addr = anon_mmap_tryfixed( low_64k, dosmem_size - 0x10000, unix_prot, 0 );
        if (addr == MAP_FAILED) return map_view( view, NULL, dosmem_size, 0, vprot, 0, 0, 0 );
    }

    /* now try to allocate the low 64K too */

    if (mmap_is_in_reserved_area( NULL, 0x10000 ) != 1)
    {
        addr = anon_mmap_tryfixed( (void *)host_page_size, 0x10000 - host_page_size, unix_prot, 0 );
        if (addr != MAP_FAILED)
        {
            if (!anon_mmap_fixed( NULL, host_page_size, unix_prot, 0 ))
            {
                addr = NULL;
                TRACE( "successfully mapped low 64K range\n" );
            }
            else TRACE( "failed to map page 0\n" );
        }
        else
        {
            addr = low_64k;
            TRACE( "failed to map low 64K range\n" );
        }
    }

    /* now reserve the whole range */

    size = (char *)dosmem_size - (char *)addr;
    anon_mmap_fixed( addr, size, unix_prot, 0 );
    return create_view( view, addr, size, vprot );
}


/***********************************************************************
 *           map_pe_header
 *
 * Map the header of a PE file into memory.
 */
static NTSTATUS map_pe_header( void *ptr, size_t size, size_t map_size, int fd, BOOL *removable )
{
#if defined(__APPLE__) && defined(__aarch64__)
    char *read_ptr = ptr;
    size_t remaining = size;
    off_t offset = 0;
    ssize_t ret;
#endif

    if (!size) return STATUS_INVALID_IMAGE_FORMAT;

#if defined(__APPLE__) && defined(__aarch64__)
    /* A writable handle opened before SEC_IMAGE creation can still change the
     * file.  Keep the header used for the final image classification in the
     * anonymous view instead of exposing a live MAP_PRIVATE file mapping. */
    while (remaining)
    {
        do ret = pread( fd, read_ptr, remaining, offset );
        while (ret < 0 && errno == EINTR);
        if (ret <= 0) return STATUS_INVALID_IMAGE_FORMAT;
        read_ptr += ret;
        remaining -= ret;
        offset += ret;
    }
    return STATUS_SUCCESS;
#endif

    map_size &= ~host_page_mask;

    if (!*removable && map_size)
    {
        if (mmap( ptr, map_size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, 0 ) != MAP_FAILED)
        {
            if (size > map_size) pread( fd, (char *)ptr + map_size, size - map_size, map_size );
            return STATUS_SUCCESS;
        }
        switch (errno)
        {
        case EPERM:
        case EACCES:
            WARN( "noexec file system, falling back to read\n" );
            break;
        case ENOEXEC:
        case ENODEV:
            WARN( "file system doesn't support mmap, falling back to read\n" );
            break;
        default:
            ERR( "mmap error %s, range %p-%p\n", strerror(errno), ptr, (char *)ptr + size );
            return STATUS_NO_MEMORY;
        }
        *removable = TRUE;
    }
    pread( fd, ptr, size, 0 );
    return STATUS_SUCCESS;  /* page protections will be updated later */
}

#ifdef _WIN64

/***********************************************************************
 *           get_host_addr_space_limit
 */
static void *get_host_addr_space_limit(void)
{
    unsigned int flags = MAP_PRIVATE | MAP_ANON;
    UINT_PTR addr = (UINT_PTR)1 << 63;

#ifdef MAP_FIXED_NOREPLACE
    flags |= MAP_FIXED_NOREPLACE;
#endif

    while (addr >> 32)
    {
        void *ret = mmap( (void *)addr, host_page_size, PROT_NONE, flags, -1, 0 );
        if (ret != MAP_FAILED)
        {
            munmap( ret, host_page_size );
            if (ret >= (void *)addr) break;
        }
        else if (errno == EEXIST) break;
        addr >>= 1;
    }
    return (void *)((addr << 1) - (granularity_mask + 1));
}

#endif /* _WIN64 */

#if defined(__aarch64__) || defined(__APPLE__)

#define IMPORT_STRING_CACHE_MIN_LENGTH 64

struct import_string_interval
{
    struct rb_entry entry;
    SIZE_T start;
    SIZE_T end;
};

struct import_string_cache
{
    struct rb_tree tree;
};


static int compare_import_string_interval( const void *key, const struct rb_entry *entry )
{
    const struct import_string_interval *interval =
        RB_ENTRY_VALUE( entry, struct import_string_interval, entry );
    SIZE_T start = *(const SIZE_T *)key;

    if (start < interval->start) return -1;
    if (start > interval->start) return 1;
    return 0;
}


static struct import_string_interval *find_import_string_interval(
    const struct import_string_cache *cache, SIZE_T start,
    struct import_string_interval **next )
{
    struct rb_entry *entry = cache->tree.root;

    *next = NULL;
    while (entry)
    {
        struct import_string_interval *interval =
            RB_ENTRY_VALUE( entry, struct import_string_interval, entry );

        if (start < interval->start)
        {
            *next = interval;
            entry = entry->left;
        }
        else if (start >= interval->end) entry = entry->right;
        else return interval;
    }
    return NULL;
}


static NTSTATUS add_import_string_interval( struct import_string_cache *cache,
                                            SIZE_T start, SIZE_T end )
{
    struct import_string_interval *interval, *next, *previous = NULL;
    struct rb_entry *entry;

    /* Bound interval-node memory by caching only strings whose rescans could be expensive. */
    if (end <= start || end - start < IMPORT_STRING_CACHE_MIN_LENGTH) return STATUS_SUCCESS;
    if (find_import_string_interval( cache, start, &next )) return STATUS_SUCCESS;
    if (next) entry = rb_prev( &next->entry );
    else entry = rb_tail( cache->tree.root );
    if (entry) previous = RB_ENTRY_VALUE( entry, struct import_string_interval, entry );

    if (previous && previous->end >= start)
    {
        interval = previous;
        if (interval->end < end) interval->end = end;
    }
    else
    {
        if (!(interval = malloc( sizeof(*interval) ))) return STATUS_NO_MEMORY;
        interval->start = start;
        interval->end = end;
        if (rb_put( &cache->tree, &interval->start, &interval->entry ) < 0)
        {
            free( interval );
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    entry = rb_next( &interval->entry );
    while (entry)
    {
        struct rb_entry *following = rb_next( entry );
        struct import_string_interval *following_interval =
            RB_ENTRY_VALUE( entry, struct import_string_interval, entry );

        if (following_interval->start > interval->end) break;
        if (interval->end < following_interval->end)
            interval->end = following_interval->end;
        rb_remove( &cache->tree, entry );
        free( following_interval );
        entry = following;
    }
    return STATUS_SUCCESS;
}


static void free_import_string_interval( struct rb_entry *entry, void *context )
{
    (void)context;
    free( RB_ENTRY_VALUE( entry, struct import_string_interval, entry ) );
}


static void init_import_string_cache( struct import_string_cache *cache )
{
    rb_init( &cache->tree, compare_import_string_interval );
}


static void free_import_string_cache( struct import_string_cache *cache )
{
    rb_destroy( &cache->tree, free_import_string_interval, NULL );
}

#endif


#ifdef __aarch64__

/***********************************************************************
 *           alloc_arm64ec_map
 */
static void alloc_arm64ec_map(void)
{
    unsigned int status;
    SIZE_T size = ((ULONG_PTR)address_space_limit + page_size) >> (page_shift + 3);  /* one bit per page */

    size = ROUND_SIZE( 0, size, host_page_mask );
    status = map_view( &arm64ec_view, NULL, size, MEM_TOP_DOWN, VPROT_READ | VPROT_COMMITTED, 0, 0, 0 );
    if (status)
    {
        ERR( "failed to allocate ARM64EC map: %08x\n", status );
        exit(1);
    }
    peb->EcCodeBitMap = arm64ec_view->base;
}


/***********************************************************************
 *           update_arm64ec_ranges
 */
#define IMAGE_RVA_RANGE_FITS(rva, size) \
    (!(size) || (SIZE_T)(size) - 1 <= ~(ULONG)0 - (ULONG)(rva))

C_ASSERT( IMAGE_RVA_RANGE_FITS( 0xfffffffc, 4 ) );
C_ASSERT( !IMAGE_RVA_RANGE_FITS( 0xfffffffc, 8 ) );

static BOOL image_rva_range_valid( SIZE_T total_size, ULONG rva, SIZE_T size )
{
    if (rva > total_size || size > total_size - rva) return FALSE;
    /* Every byte address must remain representable by the 32-bit PE RVA type. */
    return IMAGE_RVA_RANGE_FITS( rva, size );
}
#undef IMAGE_RVA_RANGE_FITS


static BOOL image_rva_array_valid( SIZE_T total_size, ULONG rva, ULONG count,
                                   SIZE_T element_size )
{
    if (!count) return TRUE;
    if (!rva || !element_size || rva > total_size) return FALSE;
    if (count > (total_size - rva) / element_size) return FALSE;
    return (SIZE_T)(count - 1) <= (~(ULONG)0 - rva) / element_size;
}


static BOOL image_rva_offset_valid( SIZE_T total_size, ULONG rva, SIZE_T offset,
                                    SIZE_T size, ULONG *result )
{
    if (offset > ~(ULONG)0 - rva) return FALSE;
    *result = rva + (ULONG)offset;
    return image_rva_range_valid( total_size, *result, size );
}


struct arm64x_patch_chunk
{
    ULONG rva;
    BYTE value[8];
    BYTE mask;
};

struct arm64x_fixup_transaction
{
    struct arm64x_patch_chunk *chunks;
    SIZE_T count;
};

struct arm64x_shared_range
{
    SIZE_T start;
    SIZE_T end;
};

struct arm64ec_mapping
{
    IMAGE_ARM64EC_METADATA metadata;
    UINT entry_point;
    BOOL present;
    BOOL has_native_code;
};


static struct arm64x_patch_chunk *find_arm64x_chunk(
    const struct arm64x_fixup_transaction *transaction, ULONG rva )
{
    SIZE_T low = 0, high = transaction->count;

    rva &= ~7u;
    while (low < high)
    {
        SIZE_T pos = low + (high - low) / 2;

        if (transaction->chunks[pos].rva == rva) return transaction->chunks + pos;
        if (transaction->chunks[pos].rva < rva) low = pos + 1;
        else high = pos;
    }
    return NULL;
}


static void read_arm64x_image( const char *base, const struct arm64x_fixup_transaction *transaction,
                               ULONG rva, void *buffer, SIZE_T size )
{
    BYTE *dst = buffer;
    SIZE_T end = rva + size, current, byte;

    memcpy( dst, base + rva, size );
    if (!transaction || !transaction->count) return;

    for (current = rva & ~7u; current < end; current += 8)
    {
        const struct arm64x_patch_chunk *chunk = find_arm64x_chunk( transaction, current );

        if (!chunk) continue;
        for (byte = 0; byte < 8; byte++)
        {
            SIZE_T address = chunk->rva + byte;

            if (!(chunk->mask & (1u << byte)) || address < rva || address >= end) continue;
            dst[address - rva] = chunk->value[byte];
        }
    }
}


static NTSTATUS write_arm64x_image( struct arm64x_fixup_transaction *transaction, ULONG rva,
                                    const void *buffer, SIZE_T size )
{
    const BYTE *src = buffer;
    SIZE_T i;

    for (i = 0; i < size; i++)
    {
        struct arm64x_patch_chunk *chunk = find_arm64x_chunk( transaction, rva + i );
        BYTE bit = 1u << ((rva + i) & 7);

        if (!chunk) return STATUS_INVALID_IMAGE_FORMAT;
        chunk->mask |= bit;
        chunk->value[(rva + i) & 7] = src[i];
    }
    return STATUS_SUCCESS;
}


static void apply_arm64x_transaction( char *base, struct arm64x_fixup_transaction *transaction )
{
    SIZE_T i, byte;

    for (i = 0; i < transaction->count; i++)
    {
        const struct arm64x_patch_chunk *chunk = transaction->chunks + i;

        for (byte = 0; byte < 8; byte++)
            if (chunk->mask & (1u << byte)) base[chunk->rva + byte] = chunk->value[byte];
    }
}


static void free_arm64x_transaction( struct arm64x_fixup_transaction *transaction )
{
    free( transaction->chunks );
    transaction->chunks = NULL;
    transaction->count = 0;
}


static NTSTATUS get_transformed_nt_headers( const char *base, const IMAGE_NT_HEADERS *nt,
                                            SIZE_T total_size,
                                            const struct arm64x_fixup_transaction *transaction,
                                            IMAGE_NT_HEADERS *transformed )
{
    SIZE_T rva = (const char *)nt - base;

    if (rva > ~(ULONG)0 || !image_rva_range_valid( total_size, rva, sizeof(*transformed) ))
        return STATUS_INVALID_IMAGE_FORMAT;
    read_arm64x_image( base, transaction, rva, transformed, sizeof(*transformed) );

    if (transformed->Signature != nt->Signature ||
        transformed->FileHeader.NumberOfSections != nt->FileHeader.NumberOfSections ||
        transformed->FileHeader.SizeOfOptionalHeader != nt->FileHeader.SizeOfOptionalHeader ||
        transformed->OptionalHeader.Magic != nt->OptionalHeader.Magic ||
        transformed->OptionalHeader.SizeOfImage != nt->OptionalHeader.SizeOfImage ||
        transformed->OptionalHeader.SizeOfHeaders != nt->OptionalHeader.SizeOfHeaders ||
        transformed->OptionalHeader.SectionAlignment != nt->OptionalHeader.SectionAlignment ||
        transformed->OptionalHeader.FileAlignment != nt->OptionalHeader.FileAlignment ||
        transformed->OptionalHeader.ImageBase != nt->OptionalHeader.ImageBase)
        return STATUS_INVALID_IMAGE_FORMAT;
    if (transformed->OptionalHeader.AddressOfEntryPoint &&
        !image_rva_range_valid( total_size,
                                transformed->OptionalHeader.AddressOfEntryPoint, 1 ))
        return STATUS_INVALID_IMAGE_FORMAT;
    return STATUS_SUCCESS;
}


static NTSTATUS get_transformed_data_dir( const IMAGE_NT_HEADERS *nt, SIZE_T total_size,
                                          ULONG index, IMAGE_DATA_DIRECTORY *dir, BOOL *present )
{
    *present = FALSE;
    if (index >= nt->OptionalHeader.NumberOfRvaAndSizes) return STATUS_SUCCESS;
    *dir = nt->OptionalHeader.DataDirectory[index];
    if (!dir->Size || !dir->VirtualAddress) return STATUS_SUCCESS;
    if (!image_rva_range_valid( total_size, dir->VirtualAddress, dir->Size ))
        return STATUS_INVALID_IMAGE_FORMAT;
    *present = TRUE;
    return STATUS_SUCCESS;
}


static NTSTATUS validate_transformed_sections( const char *base, const IMAGE_NT_HEADERS *nt,
                                               const IMAGE_SECTION_HEADER *sections,
                                               SIZE_T total_size,
                                               const struct arm64x_fixup_transaction *transaction )
{
    const IMAGE_SECTION_HEADER *image_sections = IMAGE_FIRST_SECTION( nt );
    IMAGE_SECTION_HEADER transformed;
    SIZE_T rva = (const char *)image_sections - base;
    ULONG i;

    if (rva > total_size ||
        nt->FileHeader.NumberOfSections > (total_size - rva) / sizeof(transformed))
        return STATUS_INVALID_IMAGE_FORMAT;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        read_arm64x_image( base, transaction, rva + i * sizeof(transformed),
                           &transformed, sizeof(transformed) );
        if (memcmp( &transformed, sections + i, sizeof(transformed) ))
            return STATUS_INVALID_IMAGE_FORMAT;
    }
    return STATUS_SUCCESS;
}


static BOOL get_arm64x_shared_section_range( const IMAGE_SECTION_HEADER *section,
                                             SIZE_T align_mask, SIZE_T *start, SIZE_T *end )
{
    SIZE_T map_size;

    if ((section->Characteristics & (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE)) !=
        (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE))
        return FALSE;
    if (section->Misc.VirtualSize)
        map_size = ROUND_SIZE( 0, section->Misc.VirtualSize, align_mask );
    else
        map_size = ROUND_SIZE( 0, section->SizeOfRawData, align_mask );
    if (!map_size) return FALSE;
    *start = section->VirtualAddress & ~host_page_mask;
    *end = (section->VirtualAddress + map_size + host_page_mask) & ~host_page_mask;
    return TRUE;
}


static int compare_arm64x_shared_ranges( const void *left, const void *right )
{
    const struct arm64x_shared_range *a = left, *b = right;

    if (a->start < b->start) return -1;
    if (a->start > b->start) return 1;
    if (a->end < b->end) return -1;
    if (a->end > b->end) return 1;
    return 0;
}


static NTSTATUS get_arm64x_shared_ranges( const IMAGE_SECTION_HEADER *sections,
                                          ULONG section_count, SIZE_T align_mask,
                                          struct arm64x_shared_range **ranges,
                                          SIZE_T *range_count )
{
    SIZE_T count = 0, i;

    *ranges = NULL;
    *range_count = 0;
    if (!section_count) return STATUS_SUCCESS;
    if (!(*ranges = malloc( section_count * sizeof(**ranges) ))) return STATUS_NO_MEMORY;

    for (i = 0; i < section_count; i++)
    {
        SIZE_T start, end;

        if (!get_arm64x_shared_section_range( sections + i, align_mask, &start, &end ))
            continue;
        (*ranges)[count].start = start;
        (*ranges)[count++].end = end;
    }
    qsort( *ranges, count, sizeof(**ranges), compare_arm64x_shared_ranges );
    for (i = 1; i < count; i++)
    {
        if ((*ranges)[*range_count].end >= (*ranges)[i].start)
        {
            if ((*ranges)[*range_count].end < (*ranges)[i].end)
                (*ranges)[*range_count].end = (*ranges)[i].end;
        }
        else (*ranges)[++*range_count] = (*ranges)[i];
    }
    if (count) ++*range_count;
    return STATUS_SUCCESS;
}


static BOOL arm64x_page_overlaps_shared_range( SIZE_T page,
                                               const struct arm64x_shared_range *ranges,
                                               SIZE_T range_count )
{
    SIZE_T low = 0, high = range_count;

    while (low < high)
    {
        SIZE_T pos = low + (high - low) / 2;

        if (page < ranges[pos].start) high = pos;
        else if (page >= ranges[pos].end) low = pos + 1;
        else return TRUE;
    }
    return FALSE;
}


static BOOL arm64x_transaction_contains_page(
    const struct arm64x_fixup_transaction *transaction, SIZE_T page )
{
    SIZE_T low = 0, high = transaction->count;

    while (low < high)
    {
        SIZE_T pos = low + (high - low) / 2;

        if (transaction->chunks[pos].rva < page) low = pos + 1;
        else high = pos;
    }
    while (low < transaction->count &&
           (transaction->chunks[low].rva & ~host_page_mask) == page)
    {
        if (transaction->chunks[low].mask) return TRUE;
        low++;
    }
    return FALSE;
}


static NTSTATUS append_arm64x_range( struct arm64x_shared_range **ranges,
                                     SIZE_T *count, SIZE_T *capacity,
                                     SIZE_T start, SIZE_T end )
{
    struct arm64x_shared_range *new_ranges;
    SIZE_T new_capacity;

    if (start == end) return STATUS_SUCCESS;
    if (*count == *capacity)
    {
        new_capacity = *capacity ? *capacity * 2 : 8;
        if (new_capacity < *capacity ||
            new_capacity > ~(SIZE_T)0 / sizeof(**ranges))
            return STATUS_NO_MEMORY;
        if (!(new_ranges = realloc( *ranges, new_capacity * sizeof(**ranges) )))
            return STATUS_NO_MEMORY;
        *ranges = new_ranges;
        *capacity = new_capacity;
    }
    (*ranges)[*count].start = start;
    (*ranges)[(*count)++].end = end;
    return STATUS_SUCCESS;
}


static NTSTATUS privatize_arm64x_image_range(
    struct file_view *view, SIZE_T start, SIZE_T size,
    const struct arm64x_shared_range *ranges, SIZE_T range_count,
    BYTE *private_pages, SIZE_T private_page_count, void **snapshot );
static NTSTATUS privatize_arm64x_c_string(
    struct file_view *view, const struct arm64x_fixup_transaction *transaction,
    struct import_string_cache *cache, ULONG rva, SIZE_T prefix_size,
    const struct arm64x_shared_range *ranges, SIZE_T range_count,
    BYTE *private_pages, SIZE_T private_page_count, void **snapshot );


static NTSTATUS get_arm64x_import_ranges(
    struct file_view *view, const struct arm64x_fixup_transaction *transaction,
    SIZE_T total_size, const IMAGE_DATA_DIRECTORY *imports, SIZE_T thunk_size,
    const struct arm64x_shared_range *shared_ranges, SIZE_T shared_range_count,
    BYTE *private_pages, SIZE_T private_page_count, void **snapshot,
    struct import_string_cache *string_cache,
    struct arm64x_shared_range **ranges, SIZE_T *range_count )
{
    IMAGE_IMPORT_DESCRIPTOR descriptor;
    SIZE_T capacity = 0, count = 0, offset = 0;
    NTSTATUS status = STATUS_INVALID_IMAGE_FORMAT;
    BOOL terminated = FALSE;
    char *base = view->base;

    while (imports->Size - offset >= sizeof(descriptor))
    {
        ULONG lookup_rva, thunk_rva;
        SIZE_T thunk_offset = 0;
        ULONGLONG thunk;

        if ((status = privatize_arm64x_image_range(
                 view, imports->VirtualAddress + offset, sizeof(descriptor), shared_ranges,
                 shared_range_count, private_pages, private_page_count, snapshot )))
            goto done;
        read_arm64x_image( base, transaction, imports->VirtualAddress + offset,
                           &descriptor, sizeof(descriptor) );
        offset += sizeof(descriptor);
        if (!descriptor.Name || !descriptor.FirstThunk)
        {
            terminated = TRUE;
            break;
        }
        if ((status = privatize_arm64x_c_string(
                 view, transaction, string_cache, descriptor.Name, 0, shared_ranges,
                 shared_range_count, private_pages, private_page_count, snapshot )))
            goto done;

        lookup_rva = descriptor.OriginalFirstThunk ?
                     descriptor.OriginalFirstThunk : descriptor.FirstThunk;
        for (;;)
        {
            if (!image_rva_offset_valid( total_size, lookup_rva, thunk_offset,
                                         thunk_size, &thunk_rva ))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto done;
            }
            if ((status = privatize_arm64x_image_range(
                     view, thunk_rva, thunk_size, shared_ranges, shared_range_count,
                     private_pages, private_page_count, snapshot )))
                goto done;
            thunk = 0;
            read_arm64x_image( base, transaction, thunk_rva, &thunk, thunk_size );
            if (!thunk) break;
            if (!(thunk & (thunk_size == sizeof(IMAGE_THUNK_DATA32) ?
                           IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64)))
            {
                if (thunk > ~(ULONG)0)
                {
                    status = STATUS_INVALID_IMAGE_FORMAT;
                    goto done;
                }
                if ((status = privatize_arm64x_c_string(
                         view, transaction, string_cache, thunk,
                         offsetof(IMAGE_IMPORT_BY_NAME, Name), shared_ranges,
                         shared_range_count, private_pages, private_page_count, snapshot )))
                    goto done;
            }
            if (!image_rva_offset_valid( total_size, descriptor.FirstThunk, thunk_offset,
                                         thunk_size, &thunk_rva ))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto done;
            }
            if ((status = privatize_arm64x_image_range(
                     view, thunk_rva, thunk_size, shared_ranges, shared_range_count,
                     private_pages, private_page_count, snapshot )))
                goto done;
            thunk_offset += thunk_size;
        }
        if (thunk_offset)
        {
            SIZE_T start = descriptor.FirstThunk & ~host_page_mask;
            SIZE_T end = (descriptor.FirstThunk + thunk_offset + host_page_mask) &
                         ~host_page_mask;

            if ((status = append_arm64x_range( ranges, &count, &capacity, start, end )))
                goto done;
        }
    }
    if (!terminated)
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }
    if ((status = append_arm64x_range(
             ranges, &count, &capacity,
             imports->VirtualAddress & ~host_page_mask,
             (imports->VirtualAddress + offset + host_page_mask) & ~host_page_mask )))
        goto done;

    qsort( *ranges, count, sizeof(**ranges), compare_arm64x_shared_ranges );
    *range_count = 0;
    for (offset = 1; offset < count; offset++)
    {
        if ((*ranges)[*range_count].end >= (*ranges)[offset].start)
        {
            if ((*ranges)[*range_count].end < (*ranges)[offset].end)
                (*ranges)[*range_count].end = (*ranges)[offset].end;
        }
        else (*ranges)[++*range_count] = (*ranges)[offset];
    }
    if (count) ++*range_count;
    return STATUS_SUCCESS;

done:
    free( *ranges );
    *ranges = NULL;
    *range_count = 0;
    return status;
}


static NTSTATUS privatize_arm64x_page( struct file_view *view, SIZE_T page,
                                       const struct arm64x_shared_range *ranges,
                                       SIZE_T range_count, void **snapshot )
{
    char *base = view->base;

    if (!arm64x_page_overlaps_shared_range( page, ranges, range_count ))
        return STATUS_SUCCESS;
    if (!*snapshot && !(*snapshot = malloc( host_page_size )))
        return STATUS_NO_MEMORY;
    memcpy( *snapshot, base + page, host_page_size );
    if (anon_mmap_fixed( base + page, host_page_size,
                         PROT_READ | PROT_WRITE, 0 ) == MAP_FAILED)
        return STATUS_NO_MEMORY;
    memcpy( base + page, *snapshot, host_page_size );
    return STATUS_SUCCESS;
}


static NTSTATUS privatize_arm64x_page_once(
    struct file_view *view, SIZE_T page,
    const struct arm64x_shared_range *ranges, SIZE_T range_count,
    BYTE *private_pages, SIZE_T private_page_count, void **snapshot )
{
    SIZE_T page_index = page / host_page_size;
    NTSTATUS status;

    if (!arm64x_page_overlaps_shared_range( page, ranges, range_count ))
        return STATUS_SUCCESS;
    if (page_index >= private_page_count) return STATUS_INVALID_IMAGE_FORMAT;
    if (private_pages[page_index / 8] & (1u << (page_index % 8)))
        return STATUS_SUCCESS;
    if ((status = privatize_arm64x_page( view, page, ranges, range_count, snapshot )))
        return status;
    private_pages[page_index / 8] |= 1u << (page_index % 8);
    return STATUS_SUCCESS;
}


static NTSTATUS privatize_arm64x_image_range(
    struct file_view *view, SIZE_T start, SIZE_T size,
    const struct arm64x_shared_range *ranges, SIZE_T range_count,
    BYTE *private_pages, SIZE_T private_page_count, void **snapshot )
{
    SIZE_T page, end;
    NTSTATUS status;

    if (start > view->size || size > view->size - start)
        return STATUS_INVALID_IMAGE_FORMAT;
    if (!size || !range_count) return STATUS_SUCCESS;
    end = start + size;
    for (page = start & ~host_page_mask; page < end; page += host_page_size)
        if ((status = privatize_arm64x_page_once(
                 view, page, ranges, range_count, private_pages,
                 private_page_count, snapshot )))
            return status;
    return STATUS_SUCCESS;
}


static NTSTATUS privatize_arm64x_c_string(
    struct file_view *view, const struct arm64x_fixup_transaction *transaction,
    struct import_string_cache *cache, ULONG rva, SIZE_T prefix_size,
    const struct arm64x_shared_range *ranges, SIZE_T range_count,
    BYTE *private_pages, SIZE_T private_page_count, void **snapshot )
{
    struct import_string_interval *interval, *next;
    SIZE_T string_start, current, page_end, scan_size;
    NTSTATUS status;
    BYTE *terminator;

    if (rva > view->size || prefix_size >= view->size - rva)
        return STATUS_INVALID_IMAGE_FORMAT;
    if ((status = privatize_arm64x_image_range(
             view, rva, prefix_size + 1, ranges, range_count,
             private_pages, private_page_count, snapshot )))
        return status;
    string_start = current = rva + prefix_size;
    if ((interval = find_import_string_interval( cache, current, &next )))
        return STATUS_SUCCESS;
    while (current < view->size)
    {
        if (next && current >= next->start)
            return add_import_string_interval( cache, string_start, next->end );
        page_end = (current + host_page_size) & ~host_page_mask;
        if (page_end > view->size || page_end < current) page_end = view->size;
        if (next && next->start < page_end) page_end = next->start;
        if ((status = privatize_arm64x_image_range(
                 view, current, page_end - current, ranges, range_count,
                 private_pages, private_page_count, snapshot )))
            return status;
        scan_size = page_end - current;
        if (!*snapshot && !(*snapshot = malloc( host_page_size )))
            return STATUS_NO_MEMORY;
        read_arm64x_image( view->base, transaction, current, *snapshot, scan_size );
        if ((terminator = memchr( *snapshot, 0, scan_size )))
            return add_import_string_interval(
                cache, string_start, current + (terminator - (BYTE *)*snapshot) + 1 );
        current = page_end;
    }
    return STATUS_INVALID_IMAGE_FORMAT;
}


static NTSTATUS privatize_arm64x_pages( struct file_view *view,
                                        const struct arm64x_fixup_transaction *transaction,
                                        const IMAGE_SECTION_HEADER *sections, ULONG section_count,
                                        SIZE_T align_mask,
                                        const IMAGE_DATA_DIRECTORY *effective_import,
                                        SIZE_T import_thunk_size,
                                        const struct arm64ec_mapping *arm64ec_mapping )
{
    struct arm64x_shared_range *ranges, *import_ranges = NULL;
    struct import_string_cache string_cache;
    void *snapshot = NULL;
    BYTE *private_pages = NULL;
    SIZE_T slot_pages[28], slot_page_count = 0;
    SIZE_T i, j, range_count, import_range_count = 0, last_page = ~(SIZE_T)0;
    SIZE_T private_page_count;
    NTSTATUS status;

    init_import_string_cache( &string_cache );

    for (i = 0; i < section_count; i++)
        if ((sections[i].Characteristics & (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE)) ==
            (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE))
            break;
    if (i == section_count) return STATUS_SUCCESS;
    if ((status = get_arm64x_shared_ranges( sections, section_count, align_mask,
                                             &ranges, &range_count )))
        return status;
    if (!range_count)
    {
        free( ranges );
        return STATUS_SUCCESS;
    }
    if (view->size > ~(SIZE_T)0 - host_page_mask)
    {
        free( ranges );
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    private_page_count = ROUND_SIZE( 0, view->size, host_page_mask ) / host_page_size;
    if (!(private_pages = calloc( (private_page_count + 7) / 8, 1 )))
    {
        free( ranges );
        return STATUS_NO_MEMORY;
    }
    if (effective_import)
    {
        if ((status = get_arm64x_import_ranges(
                 view, transaction, view->size, effective_import, import_thunk_size,
                 ranges, range_count, private_pages, private_page_count, &snapshot,
                 &string_cache,
                 &import_ranges, &import_range_count )))
            goto done;
    }
    if (arm64ec_mapping && arm64ec_mapping->present)
    {
        const ULONG slots[] =
        {
            arm64ec_mapping->metadata.__os_arm64x_dispatch_call_no_redirect,
            arm64ec_mapping->metadata.__os_arm64x_dispatch_ret,
            arm64ec_mapping->metadata.__os_arm64x_dispatch_call,
            arm64ec_mapping->metadata.__os_arm64x_dispatch_icall,
            arm64ec_mapping->metadata.__os_arm64x_dispatch_icall_cfg,
            arm64ec_mapping->metadata.GetX64InformationFunctionPointer,
            arm64ec_mapping->metadata.SetX64InformationFunctionPointer,
            arm64ec_mapping->metadata.__os_arm64x_dispatch_fptr,
            arm64ec_mapping->metadata.__os_arm64x_helper3,
            arm64ec_mapping->metadata.__os_arm64x_helper4,
            arm64ec_mapping->metadata.__os_arm64x_helper5,
            arm64ec_mapping->metadata.__os_arm64x_helper6,
            arm64ec_mapping->metadata.__os_arm64x_helper7,
            arm64ec_mapping->metadata.__os_arm64x_helper8,
        };

        for (i = 0; i < ARRAY_SIZE(slots); i++)
        {
            SIZE_T page, end;

            if (!slots[i]) continue;
            page = slots[i] & ~host_page_mask;
            end = (slots[i] + sizeof(void *) + host_page_mask) & ~host_page_mask;
            for (; page < end; page += host_page_size)
            {
                for (j = 0; j < slot_page_count; j++)
                    if (slot_pages[j] == page) break;
                if (j == slot_page_count) slot_pages[slot_page_count++] = page;
            }
        }
    }
    if (!transaction->count && !slot_page_count && !import_range_count)
    {
        status = STATUS_SUCCESS;
        goto done;
    }

    for (i = 0; i < transaction->count; i++)
    {
        const struct arm64x_patch_chunk *chunk = transaction->chunks + i;
        SIZE_T page, end;

        if (!chunk->mask) continue;
        page = chunk->rva & ~host_page_mask;
        end = (chunk->rva + 8 + host_page_mask) & ~host_page_mask;

        for (; page < end; page += host_page_size)
        {
            if (page == last_page) continue;
            last_page = page;
            if ((status = privatize_arm64x_page_once(
                     view, page, ranges, range_count, private_pages,
                     private_page_count, &snapshot )))
                goto done;
        }
    }

    for (i = 0; i < import_range_count; i++)
    {
        SIZE_T page;

        for (page = import_ranges[i].start; page < import_ranges[i].end;
             page += host_page_size)
        {
            if (arm64x_transaction_contains_page( transaction, page )) continue;
            if ((status = privatize_arm64x_page_once(
                     view, page, ranges, range_count, private_pages,
                     private_page_count, &snapshot )))
                goto done;
        }
    }

    for (i = 0; i < slot_page_count; i++)
    {
        SIZE_T page = slot_pages[i];

        if ((status = privatize_arm64x_page_once(
                 view, page, ranges, range_count, private_pages,
                 private_page_count, &snapshot )))
            goto done;
    }
    status = STATUS_SUCCESS;

done:
    free_import_string_cache( &string_cache );
    free( snapshot );
    free( private_pages );
    free( ranges );
    free( import_ranges );
    return status;
}


static NTSTATUS get_load_config_size( const char *base,
                                      const struct arm64x_fixup_transaction *transaction,
                                      const IMAGE_DATA_DIRECTORY *dir,
                                      ULONG *declared_size )
{
    if (dir->Size < sizeof(*declared_size)) return STATUS_INVALID_IMAGE_FORMAT;
    read_arm64x_image( base, transaction, dir->VirtualAddress, declared_size,
                       sizeof(*declared_size) );
    return STATUS_SUCCESS;
}


static NTSTATUS read_load_config_field( const char *base,
                                        const struct arm64x_fixup_transaction *transaction,
                                        const IMAGE_DATA_DIRECTORY *dir,
                                        ULONG declared_size, SIZE_T offset, SIZE_T size,
                                        void *value, BOOL *present )
{
    *present = FALSE;
    if (declared_size <= offset) return STATUS_SUCCESS;
    if (size > ~(SIZE_T)0 - offset || declared_size < offset + size || dir->Size < offset + size)
        return STATUS_INVALID_IMAGE_FORMAT;
    read_arm64x_image( base, transaction, dir->VirtualAddress + offset, value, size );
    *present = TRUE;
    return STATUS_SUCCESS;
}


static BOOL arm64ec_optional_range_valid( SIZE_T total_size, ULONG rva, SIZE_T size )
{
    return !rva || image_rva_range_valid( total_size, rva, size );
}


struct arm64_unwind_info_ext
{
    WORD epilog_count;
    BYTE code_words;
    BYTE reserved;
};


static BOOL arm64ec_metadata_extents_valid( SIZE_T total_size,
                                             const IMAGE_ARM64EC_METADATA *metadata )
{
    return image_rva_array_valid( total_size, metadata->CodeMap,
                                  metadata->CodeMapCount,
                                  sizeof(IMAGE_CHPE_RANGE_ENTRY) ) &&
           image_rva_array_valid( total_size, metadata->CodeRangesToEntryPoints,
                                  metadata->CodeRangesToEntryPointsCount,
                                  sizeof(IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT) ) &&
           image_rva_array_valid( total_size, metadata->RedirectionMetadata,
                                  metadata->RedirectionMetadataCount,
                                  sizeof(IMAGE_ARM64EC_REDIRECTION_ENTRY) ) &&
           (!metadata->ExtraRFETableSize ||
            (!(metadata->ExtraRFETable &
               (TYPE_ALIGNMENT(ARM64_RUNTIME_FUNCTION) - 1)) &&
             !(metadata->ExtraRFETableSize % sizeof(ARM64_RUNTIME_FUNCTION)) &&
             image_rva_array_valid(
                 total_size, metadata->ExtraRFETable,
                 metadata->ExtraRFETableSize / sizeof(ARM64_RUNTIME_FUNCTION),
                 sizeof(ARM64_RUNTIME_FUNCTION) )));
}


static NTSTATUS privatize_arm64ec_unwind_info(
    struct file_view *view, const struct arm64x_fixup_transaction *transaction,
    SIZE_T total_size, ULONG unwind_rva,
    const struct arm64x_shared_range *ranges, SIZE_T range_count,
    BYTE *private_pages, SIZE_T private_page_count, void **snapshot )
{
    IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA xdata;
    struct arm64_unwind_info_ext extended;
    ULONG code_words, epilog_count, field_rva;
    SIZE_T extent;
    NTSTATUS status;

    if (!image_rva_range_valid( total_size, unwind_rva, sizeof(xdata) ))
        return STATUS_INVALID_IMAGE_FORMAT;
    if ((status = privatize_arm64x_image_range(
             view, unwind_rva, sizeof(xdata), ranges, range_count,
             private_pages, private_page_count, snapshot )))
        return status;
    read_arm64x_image( view->base, transaction, unwind_rva, &xdata, sizeof(xdata) );

    extent = sizeof(xdata);
    code_words = xdata.CodeWords;
    epilog_count = xdata.EpilogCount;
    if (!code_words && !epilog_count)
    {
        if (!image_rva_offset_valid( total_size, unwind_rva, extent,
                                     sizeof(extended), &field_rva ))
            return STATUS_INVALID_IMAGE_FORMAT;
        if ((status = privatize_arm64x_image_range(
                 view, field_rva, sizeof(extended), ranges, range_count,
                 private_pages, private_page_count, snapshot )))
            return status;
        read_arm64x_image( view->base, transaction, field_rva, &extended,
                           sizeof(extended) );
        extent += sizeof(extended);
        code_words = extended.code_words;
        epilog_count = extended.epilog_count;
    }
    if (!xdata.EpilogInHeader) extent += (SIZE_T)epilog_count * sizeof(DWORD);
    extent += (SIZE_T)code_words * sizeof(DWORD);
    if (xdata.ExceptionDataPresent) extent += sizeof(ULONG);
    if (!image_rva_range_valid( total_size, unwind_rva, extent ))
        return STATUS_INVALID_IMAGE_FORMAT;
    return privatize_arm64x_image_range( view, unwind_rva, extent, ranges, range_count,
                                         private_pages, private_page_count, snapshot );
}


static NTSTATUS validate_arm64_unwind_info( const char *base,
                                             const struct arm64x_fixup_transaction *transaction,
                                             SIZE_T total_size, ULONG begin_rva, ULONG unwind_rva )
{
    IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA xdata;
    struct arm64_unwind_info_ext extended;
    ULONG code_words, epilog_count, field_rva, handler_rva;
    SIZE_T extent;

    if (!image_rva_range_valid( total_size, unwind_rva, sizeof(xdata) ))
        return STATUS_INVALID_IMAGE_FORMAT;
    read_arm64x_image( base, transaction, unwind_rva, &xdata, sizeof(xdata) );
    if (!image_rva_range_valid( total_size, begin_rva, (SIZE_T)xdata.FunctionLength * 4 ))
        return STATUS_INVALID_IMAGE_FORMAT;

    extent = sizeof(xdata);
    code_words = xdata.CodeWords;
    epilog_count = xdata.EpilogCount;
    if (!code_words && !epilog_count)
    {
        if (!image_rva_offset_valid( total_size, unwind_rva, extent,
                                     sizeof(extended), &field_rva ))
            return STATUS_INVALID_IMAGE_FORMAT;
        read_arm64x_image( base, transaction, field_rva, &extended, sizeof(extended) );
        extent += sizeof(extended);
        code_words = extended.code_words;
        epilog_count = extended.epilog_count;
    }
    if (!xdata.EpilogInHeader) extent += (SIZE_T)epilog_count * sizeof(DWORD);
    extent += (SIZE_T)code_words * sizeof(DWORD);
    if (!image_rva_range_valid( total_size, unwind_rva, extent ))
        return STATUS_INVALID_IMAGE_FORMAT;
    if (xdata.ExceptionDataPresent)
    {
        if (!image_rva_offset_valid( total_size, unwind_rva, extent,
                                     sizeof(handler_rva), &field_rva ))
            return STATUS_INVALID_IMAGE_FORMAT;
        read_arm64x_image( base, transaction, field_rva, &handler_rva, sizeof(handler_rva) );
        if (!image_rva_range_valid( total_size, handler_rva, sizeof(ULONG) ))
            return STATUS_INVALID_IMAGE_FORMAT;
    }
    return STATUS_SUCCESS;
}


static NTSTATUS validate_arm64ec_metadata( const char *base,
                                           const struct arm64x_fixup_transaction *transaction,
                                           SIZE_T total_size, ULONG metadata_rva,
                                           IMAGE_ARM64EC_METADATA *metadata,
                                           BOOL *has_native_code )
{
    ARM64_RUNTIME_FUNCTION function, previous_function;
    IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT code_range;
    IMAGE_ARM64EC_REDIRECTION_ENTRY redirection, previous;
    IMAGE_CHPE_RANGE_ENTRY code;
    ULONG extra_rfe_count, i, start;
    SIZE_T code_map_end = 0;

    if (!metadata_rva || metadata_rva & (TYPE_ALIGNMENT(IMAGE_ARM64EC_METADATA) - 1) ||
        !image_rva_range_valid( total_size, metadata_rva, sizeof(*metadata) ))
        return STATUS_INVALID_IMAGE_FORMAT;
    read_arm64x_image( base, transaction, metadata_rva, metadata, sizeof(*metadata) );

    if (!arm64ec_metadata_extents_valid( total_size, metadata ))
        return STATUS_INVALID_IMAGE_FORMAT;

    for (i = 0; i < metadata->CodeMapCount; i++)
    {
        read_arm64x_image( base, transaction, metadata->CodeMap + i * sizeof(code),
                           &code, sizeof(code) );
        start = code.StartOffset & ~3u;
        if (!code.Length || !image_rva_range_valid( total_size, start, code.Length ) ||
            (i && start < code_map_end))
            return STATUS_INVALID_IMAGE_FORMAT;
        if ((code.StartOffset & 0x3) == 1) *has_native_code = TRUE;
        code_map_end = start + (SIZE_T)code.Length;
    }

    for (i = 0; i < metadata->CodeRangesToEntryPointsCount; i++)
    {
        read_arm64x_image( base, transaction,
                           metadata->CodeRangesToEntryPoints + i * sizeof(code_range),
                           &code_range, sizeof(code_range) );
        if (code_range.StartRva >= code_range.EndRva || code_range.EndRva > total_size ||
            code_range.EntryPoint >= total_size)
            return STATUS_INVALID_IMAGE_FORMAT;
    }

    for (i = 0; i < metadata->RedirectionMetadataCount; i++)
    {
        read_arm64x_image( base, transaction,
                           metadata->RedirectionMetadata + i * sizeof(redirection),
                           &redirection, sizeof(redirection) );
        if (redirection.Source >= total_size || redirection.Destination >= total_size ||
            (i && previous.Source >= redirection.Source))
            return STATUS_INVALID_IMAGE_FORMAT;
        previous = redirection;
    }

    extra_rfe_count = metadata->ExtraRFETableSize / sizeof(function);
    for (i = 0; i < extra_rfe_count; i++)
    {
        read_arm64x_image( base, transaction,
                           metadata->ExtraRFETable + i * sizeof(function),
                           &function, sizeof(function) );
        if (function.BeginAddress >= total_size ||
            (i && (previous_function.BeginAddress > function.BeginAddress ||
                   (function.BeginAddress &&
                    previous_function.BeginAddress == function.BeginAddress))))
            return STATUS_INVALID_IMAGE_FORMAT;
        if (!function.BeginAddress)
        {
            /* Zero-address entries are sorted tombstones, not unwind records. */
            previous_function = function;
            continue;
        }
        if (!function.Flag)
        {
            if (validate_arm64_unwind_info( base, transaction, total_size,
                                             function.BeginAddress, function.UnwindData ))
                return STATUS_INVALID_IMAGE_FORMAT;
        }
        else if (!image_rva_range_valid( total_size, function.BeginAddress,
                                          (SIZE_T)function.FunctionLength * 4 ))
            return STATUS_INVALID_IMAGE_FORMAT;
        previous_function = function;
    }

#define VALIDATE_ARM64EC_SLOT(field) \
    if (!arm64ec_optional_range_valid( total_size, metadata->field, sizeof(void *) )) \
        return STATUS_INVALID_IMAGE_FORMAT
    VALIDATE_ARM64EC_SLOT( __os_arm64x_dispatch_call_no_redirect );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_dispatch_ret );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_dispatch_call );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_dispatch_icall );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_dispatch_icall_cfg );
    VALIDATE_ARM64EC_SLOT( GetX64InformationFunctionPointer );
    VALIDATE_ARM64EC_SLOT( SetX64InformationFunctionPointer );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_dispatch_fptr );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_helper3 );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_helper4 );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_helper5 );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_helper6 );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_helper7 );
    VALIDATE_ARM64EC_SLOT( __os_arm64x_helper8 );
#undef VALIDATE_ARM64EC_SLOT
    return STATUS_SUCCESS;
}


static ULONG redirect_validated_arm64ec_rva( const char *base,
                                              const struct arm64x_fixup_transaction *transaction,
                                              ULONG rva,
                                              const IMAGE_ARM64EC_METADATA *metadata )
{
    IMAGE_ARM64EC_REDIRECTION_ENTRY entry;
    ULONG low = 0, high = metadata->RedirectionMetadataCount;

    while (low < high)
    {
        ULONG pos = low + (high - low) / 2;

        read_arm64x_image( base, transaction,
                           metadata->RedirectionMetadata + pos * sizeof(entry),
                           &entry, sizeof(entry) );
        if (entry.Source == rva) return entry.Destination;
        if (entry.Source < rva) low = pos + 1;
        else high = pos;
    }
    return rva;
}


static NTSTATUS update_arm64ec_ranges( struct file_view *view, IMAGE_NT_HEADERS *nt,
                                       const struct arm64x_fixup_transaction *transaction,
                                       const IMAGE_DATA_DIRECTORY *dir,
                                       const IMAGE_SECTION_HEADER *sections,
                                       ULONG section_count, SIZE_T align_mask,
                                       SIZE_T total_size,
                                       struct arm64ec_mapping *mapping )
{
    struct arm64x_shared_range *ranges = NULL;
    const SIZE_T metadata_offset = offsetof( IMAGE_LOAD_CONFIG_DIRECTORY,
                                             CHPEMetadataPointer );
    ARM64_RUNTIME_FUNCTION function;
    IMAGE_ARM64EC_METADATA metadata;
    ULONGLONG metadata_va, security_cookie_va, image_base, delta;
    void *snapshot = NULL;
    BYTE *private_pages = NULL;
    char *base = view->base;
    ULONG declared_size, metadata_rva, security_cookie_rva, i;
    SIZE_T range_count = 0, private_page_count = 0, load_config_size;
    NTSTATUS status = STATUS_SUCCESS;
    BOOL present, security_cookie_present;

    memset( mapping, 0, sizeof(*mapping) );
    for (i = 0; i < section_count; i++)
    {
        SIZE_T start, end;

        if (get_arm64x_shared_section_range( sections + i, align_mask, &start, &end ))
            break;
    }
    if (i < section_count &&
        (status = get_arm64x_shared_ranges( sections, section_count, align_mask,
                                             &ranges, &range_count )))
        goto done;
    if (range_count)
    {
        if (view->size > ~(SIZE_T)0 - host_page_mask)
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        private_page_count = ROUND_SIZE( 0, view->size, host_page_mask ) / host_page_size;
        if (!(private_pages = calloc( (private_page_count + 7) / 8, 1 )))
        {
            status = STATUS_NO_MEMORY;
            goto done;
        }
    }

    if (!image_rva_range_valid( total_size, dir->VirtualAddress,
                                sizeof(declared_size) ))
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }
    if ((status = privatize_arm64x_image_range(
             view, dir->VirtualAddress, sizeof(declared_size), ranges, range_count,
             private_pages, private_page_count, &snapshot )))
        goto done;
    if ((status = get_load_config_size( base, transaction, dir, &declared_size ))) goto done;
    load_config_size = min( (SIZE_T)declared_size, (SIZE_T)dir->Size );
    load_config_size = min( load_config_size, sizeof(IMAGE_LOAD_CONFIG_DIRECTORY) );
    if ((status = privatize_arm64x_image_range(
             view, dir->VirtualAddress, load_config_size, ranges, range_count,
             private_pages, private_page_count, &snapshot )))
        goto done;
    if ((status = get_load_config_size( base, transaction, dir, &declared_size ))) goto done;
    image_base = nt->OptionalHeader.ImageBase;
    if ((status = read_load_config_field(
             base, transaction, dir, declared_size,
             offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie ),
             sizeof(security_cookie_va), &security_cookie_va,
             &security_cookie_present )))
        goto done;
    if (security_cookie_present && security_cookie_va)
    {
        if (security_cookie_va < image_base ||
            (delta = security_cookie_va - image_base) > ~(ULONG)0)
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        security_cookie_rva = delta;
        if (!image_rva_range_valid( total_size, security_cookie_rva,
                                    sizeof(ULONG_PTR) ))
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        if ((status = privatize_arm64x_image_range(
                 view, security_cookie_rva, sizeof(ULONG_PTR), ranges, range_count,
                 private_pages, private_page_count, &snapshot )))
            goto done;
    }
    if (declared_size <= metadata_offset) goto done;
    if (declared_size < metadata_offset + sizeof(metadata_va) ||
        dir->Size < metadata_offset + sizeof(metadata_va))
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }
    if ((status = read_load_config_field( base, transaction, dir, declared_size,
                                          metadata_offset,
                                          sizeof(metadata_va), &metadata_va, &present )))
        goto done;
    if (!present || !metadata_va) goto done;

    if (metadata_va < image_base || (delta = metadata_va - image_base) > ~(ULONG)0)
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }
    metadata_rva = delta;
    if (!metadata_rva || metadata_rva & (TYPE_ALIGNMENT(IMAGE_ARM64EC_METADATA) - 1) ||
        !image_rva_range_valid( total_size, metadata_rva, sizeof(metadata) ))
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }
    if ((status = privatize_arm64x_image_range(
             view, metadata_rva, sizeof(metadata), ranges, range_count,
             private_pages, private_page_count, &snapshot )))
        goto done;
    read_arm64x_image( base, transaction, metadata_rva, &metadata, sizeof(metadata) );
    if (!arm64ec_metadata_extents_valid( total_size, &metadata ))
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }

#define PRIVATIZE_ARM64EC_ARRAY(field, count, type) \
    if (metadata.count && \
        (status = privatize_arm64x_image_range( \
            view, metadata.field, (SIZE_T)metadata.count * sizeof(type), ranges, \
            range_count, private_pages, private_page_count, &snapshot ))) \
        goto done
    PRIVATIZE_ARM64EC_ARRAY( CodeMap, CodeMapCount, IMAGE_CHPE_RANGE_ENTRY );
    PRIVATIZE_ARM64EC_ARRAY( CodeRangesToEntryPoints, CodeRangesToEntryPointsCount,
                             IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT );
    PRIVATIZE_ARM64EC_ARRAY( RedirectionMetadata, RedirectionMetadataCount,
                             IMAGE_ARM64EC_REDIRECTION_ENTRY );
#undef PRIVATIZE_ARM64EC_ARRAY
    if (metadata.ExtraRFETableSize &&
        (status = privatize_arm64x_image_range(
            view, metadata.ExtraRFETable, metadata.ExtraRFETableSize, ranges,
            range_count, private_pages, private_page_count, &snapshot )))
        goto done;

    for (i = 0; i < metadata.ExtraRFETableSize / sizeof(function); i++)
    {
        read_arm64x_image( base, transaction,
                           metadata.ExtraRFETable + i * sizeof(function),
                           &function, sizeof(function) );
        if (function.BeginAddress && !function.Flag &&
            (status = privatize_arm64ec_unwind_info(
                view, transaction, total_size, function.UnwindData, ranges, range_count,
                private_pages, private_page_count, &snapshot )))
            goto done;
    }

    {
        const ULONG slots[] =
        {
            metadata.__os_arm64x_dispatch_call_no_redirect,
            metadata.__os_arm64x_dispatch_ret,
            metadata.__os_arm64x_dispatch_call,
            metadata.__os_arm64x_dispatch_icall,
            metadata.__os_arm64x_dispatch_icall_cfg,
            metadata.GetX64InformationFunctionPointer,
            metadata.SetX64InformationFunctionPointer,
            metadata.__os_arm64x_dispatch_fptr,
            metadata.__os_arm64x_helper3,
            metadata.__os_arm64x_helper4,
            metadata.__os_arm64x_helper5,
            metadata.__os_arm64x_helper6,
            metadata.__os_arm64x_helper7,
            metadata.__os_arm64x_helper8,
        };

        for (i = 0; i < ARRAY_SIZE(slots); i++)
        {
            if (!arm64ec_optional_range_valid( total_size, slots[i], sizeof(void *) ))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto done;
            }
            if (slots[i] &&
                (status = privatize_arm64x_image_range(
                    view, slots[i], sizeof(void *), ranges, range_count,
                    private_pages, private_page_count, &snapshot )))
                goto done;
        }
    }

    if ((status = validate_arm64ec_metadata( base, transaction, total_size, metadata_rva,
                                             &mapping->metadata,
                                             &mapping->has_native_code )))
        goto done;

    mapping->entry_point = redirect_validated_arm64ec_rva(
        base, transaction, nt->OptionalHeader.AddressOfEntryPoint, &mapping->metadata );
    mapping->present = TRUE;

done:
    free( snapshot );
    free( private_pages );
    free( ranges );
    return status;
}


static void commit_arm64ec_mapping( struct file_view *view,
                                    const struct arm64x_fixup_transaction *transaction,
                                    const struct arm64ec_mapping *mapping )
{
    IMAGE_CHPE_RANGE_ENTRY code;
    char *base = view->base;
    ULONG i;

    if (!mapping->present) return;
    if (!arm64ec_view) alloc_arm64ec_map();
    commit_arm64ec_map( view );

    for (i = 0; i < mapping->metadata.CodeMapCount; i++)
    {
        read_arm64x_image( base, transaction, mapping->metadata.CodeMap + i * sizeof(code),
                           &code, sizeof(code) );
        if ((code.StartOffset & 0x3) != 1 /* arm64ec */) continue;
        set_arm64ec_range( base + (code.StartOffset & ~3u), code.Length );
    }
}


static BOOL memory_is_zero( const BYTE *ptr, SIZE_T size )
{
    while (size--) if (*ptr++) return FALSE;
    return TRUE;
}


enum arm64x_parse_mode
{
    ARM64X_VALIDATE_FIXUPS,
    ARM64X_COLLECT_CHUNKS,
    ARM64X_BUILD_OVERLAY
};


static NTSTATUS parse_arm64x_relocations( const char *base, const BYTE *fixups, SIZE_T size,
                                          SIZE_T total_size,
                                          struct arm64x_fixup_transaction *transaction,
                                          enum arm64x_parse_mode mode, SIZE_T *operation_count,
                                          SIZE_T *chunk_count )
{
    IMAGE_BASE_RELOCATION block;
    SIZE_T chunks = 0, count = 0, pos = 0;
    NTSTATUS status = STATUS_SUCCESS;

    while (pos < size)
    {
        SIZE_T block_end, record_pos;

        if (size - pos < sizeof(block))
        {
            if (!memory_is_zero( fixups + pos, size - pos )) status = STATUS_INVALID_IMAGE_FORMAT;
            break;
        }
        memcpy( &block, fixups + pos, sizeof(block) );
        if (!block.SizeOfBlock)
        {
            if (!memory_is_zero( fixups + pos, size - pos )) status = STATUS_INVALID_IMAGE_FORMAT;
            break;
        }
        if (block.SizeOfBlock < sizeof(block) || block.SizeOfBlock > size - pos ||
            (block.SizeOfBlock - sizeof(block)) % sizeof(USHORT))
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            break;
        }

        block_end = pos + block.SizeOfBlock;
        record_pos = pos + sizeof(block);
        while (record_pos < block_end)
        {
            USHORT record, type, arg, operand;
            SIZE_T width;
            ULONG target;
            BYTE value[8];

            memcpy( &record, fixups + record_pos, sizeof(record) );
            record_pos += sizeof(record);
            if (!record)
            {
                if (!memory_is_zero( fixups + record_pos, block_end - record_pos ))
                    status = STATUS_INVALID_IMAGE_FORMAT;
                break;
            }

            type = (record >> 12) & 3;
            arg = record >> 14;
            if (block.VirtualAddress > ~(ULONG)0 - (record & 0xfff))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                break;
            }
            target = block.VirtualAddress + (record & 0xfff);

            switch (type)
            {
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL:
                if (!arg) return STATUS_INVALID_IMAGE_FORMAT;
                width = (SIZE_T)1 << arg;
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE:
                if (!arg)
                {
                    status = STATUS_INVALID_IMAGE_FORMAT;
                    break;
                }
                width = (SIZE_T)1 << arg;
                if (width > block_end - record_pos)
                {
                    status = STATUS_INVALID_IMAGE_FORMAT;
                    break;
                }
                record_pos += width;
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA:
                width = sizeof(ULONG);
                if (block_end - record_pos < sizeof(operand))
                {
                    status = STATUS_INVALID_IMAGE_FORMAT;
                    break;
                }
                record_pos += sizeof(operand);
                break;
            default:
                status = STATUS_INVALID_IMAGE_FORMAT;
                break;
            }
            if (status) break;
            if (!image_rva_range_valid( total_size, target, width ))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                break;
            }

            if (mode == ARM64X_COLLECT_CHUNKS)
            {
                ULONG first = target & ~7u;
                ULONG last = (target + width - 1) & ~7u;

                transaction->chunks[chunks++].rva = first;
                if (last != first) transaction->chunks[chunks++].rva = last;
            }
            else if (mode == ARM64X_BUILD_OVERLAY)
            {
                read_arm64x_image( base, transaction, target, value, width );
                switch (type)
                {
                case IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL:
                    memset( value, 0, width );
                    break;
                case IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE:
                    memcpy( value, fixups + record_pos - width, width );
                    break;
                case IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA:
                {
                    ULONG current, delta;

                    memcpy( &operand, fixups + record_pos - sizeof(operand), sizeof(operand) );
                    memcpy( &current, value, sizeof(current) );
                    delta = (ULONG)operand * ((arg & 2) ? 8 : 4);
                    if (arg & 1) delta = 0u - delta;
                    current += delta;
                    memcpy( value, &current, sizeof(current) );
                    break;
                }
                }
                if ((status = write_arm64x_image( transaction, target, value, width )))
                    break;
            }
            count++;
        }
        if (status) break;
        pos = block_end;
    }
    *operation_count = count;
    if (chunk_count) *chunk_count = chunks;
    return status;
}


static int compare_arm64x_chunks( const void *left, const void *right )
{
    const struct arm64x_patch_chunk *a = left, *b = right;

    if (a->rva < b->rva) return -1;
    if (a->rva > b->rva) return 1;
    return 0;
}


static NTSTATUS build_arm64x_transaction( const char *base, const BYTE *fixups, SIZE_T size,
                                          SIZE_T total_size,
                                          struct arm64x_fixup_transaction *transaction )
{
    SIZE_T count, parsed_count, chunk_count, max_chunks, unique, i;
    NTSTATUS status;

    if ((status = parse_arm64x_relocations( base, fixups, size, total_size, NULL,
                                            ARM64X_VALIDATE_FIXUPS, &count, NULL )))
        return status;
    if (!count) return STATUS_SUCCESS;
    if (count > ~(SIZE_T)0 / 2) return STATUS_NO_MEMORY;
    max_chunks = count * 2;
    if (max_chunks > ~(SIZE_T)0 / sizeof(*transaction->chunks)) return STATUS_NO_MEMORY;
    if (!(transaction->chunks = calloc( max_chunks, sizeof(*transaction->chunks) )))
        return STATUS_NO_MEMORY;

    status = parse_arm64x_relocations( base, fixups, size, total_size, transaction,
                                       ARM64X_COLLECT_CHUNKS, &parsed_count, &chunk_count );
    if (status || parsed_count != count)
    {
        free_arm64x_transaction( transaction );
        return status ? status : STATUS_INVALID_IMAGE_FORMAT;
    }
    assert( chunk_count <= max_chunks );
    qsort( transaction->chunks, chunk_count, sizeof(*transaction->chunks), compare_arm64x_chunks );

    for (i = unique = 0; i < chunk_count; i++)
    {
        if (unique && transaction->chunks[unique - 1].rva == transaction->chunks[i].rva) continue;
        transaction->chunks[unique++].rva = transaction->chunks[i].rva;
    }
    transaction->count = unique;
    status = parse_arm64x_relocations( base, fixups, size, total_size, transaction,
                                       ARM64X_BUILD_OVERLAY, &parsed_count, NULL );
    if (status || parsed_count != count)
    {
        free_arm64x_transaction( transaction );
        return status ? status : STATUS_INVALID_IMAGE_FORMAT;
    }
    return STATUS_SUCCESS;
}


static NTSTATUS find_arm64x_fixups( const BYTE *entries, SIZE_T size, ULONG version,
                                    const BYTE **fixups, SIZE_T *fixup_size )
{
    SIZE_T pos = 0;

    *fixups = NULL;
    *fixup_size = 0;
    switch (version)
    {
    case 1:
        while (pos < size)
        {
            IMAGE_DYNAMIC_RELOCATION64 dyn;
            SIZE_T step;

            if (size - pos < sizeof(dyn)) return STATUS_INVALID_IMAGE_FORMAT;
            memcpy( &dyn, entries + pos, sizeof(dyn) );
            if (dyn.BaseRelocSize > size - pos - sizeof(dyn))
                return STATUS_INVALID_IMAGE_FORMAT;
            step = sizeof(dyn) + dyn.BaseRelocSize;
            if (dyn.Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X && !*fixups)
            {
                *fixups = entries + pos + sizeof(dyn);
                *fixup_size = dyn.BaseRelocSize;
            }
            pos += step;
        }
        return STATUS_SUCCESS;

    case 2:
        while (pos < size)
        {
            IMAGE_DYNAMIC_RELOCATION64_V2 dyn;
            SIZE_T step;

            if (size - pos < sizeof(dyn)) return STATUS_INVALID_IMAGE_FORMAT;
            memcpy( &dyn, entries + pos, sizeof(dyn) );
            if (dyn.HeaderSize < sizeof(dyn) || dyn.HeaderSize > size - pos ||
                dyn.FixupInfoSize > size - pos - dyn.HeaderSize)
                return STATUS_INVALID_IMAGE_FORMAT;
            step = dyn.HeaderSize + dyn.FixupInfoSize;
            if (dyn.Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X && !*fixups)
            {
                *fixups = entries + pos + dyn.HeaderSize;
                *fixup_size = dyn.FixupInfoSize;
            }
            pos += step;
        }
        return STATUS_SUCCESS;

    default:
        FIXME( "unsupported version %u\n", version );
        return STATUS_SUCCESS;
    }
}


/***********************************************************************
 *           update_arm64x_mapping
 */
static NTSTATUS update_arm64x_mapping( struct file_view *view, IMAGE_NT_HEADERS *nt,
                                       const IMAGE_DATA_DIRECTORY *dir,
                                       IMAGE_SECTION_HEADER *sections, SIZE_T total_size,
                                       struct arm64x_fixup_transaction *transaction )
{
    IMAGE_DYNAMIC_RELOCATION_TABLE table;
    const BYTE *entries, *fixups;
    IMAGE_SECTION_HEADER section;
    BYTE *snapshot = NULL;
    char *base = view->base;
    ULONG declared_size, offset, table_rva;
    SIZE_T section_size, section_remaining, fixup_size;
    USHORT section_index;
    NTSTATUS status;
    BOOL present;

    if ((status = get_load_config_size( base, NULL, dir, &declared_size ))) return status;
    if ((status = read_load_config_field( base, NULL, dir, declared_size,
                                          offsetof( IMAGE_LOAD_CONFIG_DIRECTORY,
                                                    DynamicValueRelocTableOffset ),
                                          sizeof(offset), &offset, &present )))
        return status;
    if (!present) return STATUS_SUCCESS;
    if ((status = read_load_config_field( base, NULL, dir, declared_size,
                                          offsetof( IMAGE_LOAD_CONFIG_DIRECTORY,
                                                    DynamicValueRelocTableSection ),
                                          sizeof(section_index), &section_index, &present )))
        return status;
    if (!present) return STATUS_INVALID_IMAGE_FORMAT;
    if (!section_index) return STATUS_SUCCESS;
    if (section_index > nt->FileHeader.NumberOfSections) return STATUS_INVALID_IMAGE_FORMAT;

    memcpy( &section, sections + section_index - 1, sizeof(section) );
    section_size = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
    if (!image_rva_range_valid( total_size, section.VirtualAddress, section_size ) ||
        offset > section_size || section_size - offset < sizeof(table) ||
        section.VirtualAddress > ~(ULONG)0 - offset)
        return STATUS_INVALID_IMAGE_FORMAT;
    section_remaining = section_size - offset;
    table_rva = section.VirtualAddress + offset;
    memcpy( &table, base + table_rva, sizeof(table) );
    if (table.Size > section_remaining - sizeof(table) ||
        !image_rva_range_valid( total_size, table_rva + sizeof(table), table.Size ))
        return STATUS_INVALID_IMAGE_FORMAT;

    entries = (const BYTE *)base + table_rva + sizeof(table);
    if ((status = find_arm64x_fixups( entries, table.Size, table.Version,
                                      &fixups, &fixup_size )))
        return status;
    if (!fixups) return STATUS_SUCCESS;
    if (fixup_size)
    {
        if (!(snapshot = malloc( fixup_size ))) return STATUS_NO_MEMORY;
        memcpy( snapshot, fixups, fixup_size );
    }
    status = build_arm64x_transaction( base, snapshot, fixup_size, total_size, transaction );
    free( snapshot );
    return status;
}

#endif  /* __aarch64__ */

/***********************************************************************
 *           get_data_dir
 */
static IMAGE_DATA_DIRECTORY *get_data_dir( IMAGE_NT_HEADERS *nt, SIZE_T total_size, ULONG dir )
{
    IMAGE_DATA_DIRECTORY *data;

    switch (nt->OptionalHeader.Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        if (dir >= ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        data = &((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.DataDirectory[dir];
        break;
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        if (dir >= ((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        data = &((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.DataDirectory[dir];
        break;
    default:
        return NULL;
    }
    if (!data->Size) return NULL;
    if (!data->VirtualAddress) return NULL;
    if (data->VirtualAddress >= total_size) return NULL;
    if (data->Size > total_size - data->VirtualAddress) return NULL;
    return data;
}


#if defined(__APPLE__) && !defined(__aarch64__)

struct apple_import_range
{
    SIZE_T start;
    SIZE_T end;
};


static BOOL apple_image_rva_offset_valid( SIZE_T total_size, ULONG rva,
                                           SIZE_T offset, SIZE_T size, ULONG *result )
{
    if (offset > ~(ULONG)0 - rva) return FALSE;
    *result = rva + (ULONG)offset;
    if (*result > total_size || size > total_size - *result) return FALSE;
    return !size || size - 1 <= ~(ULONG)0 - *result;
}


static NTSTATUS append_apple_import_range( struct apple_import_range **ranges,
                                           SIZE_T *count, SIZE_T *capacity,
                                           SIZE_T start, SIZE_T end )
{
    struct apple_import_range *new_ranges;
    SIZE_T new_capacity;

    if (start == end) return STATUS_SUCCESS;
    if (*count == *capacity)
    {
        new_capacity = *capacity ? *capacity * 2 : 8;
        if (new_capacity < *capacity ||
            new_capacity > ~(SIZE_T)0 / sizeof(**ranges))
            return STATUS_NO_MEMORY;
        if (!(new_ranges = realloc( *ranges, new_capacity * sizeof(**ranges) )))
            return STATUS_NO_MEMORY;
        *ranges = new_ranges;
        *capacity = new_capacity;
    }
    (*ranges)[*count].start = start;
    (*ranges)[(*count)++].end = end;
    return STATUS_SUCCESS;
}


static int compare_apple_import_ranges( const void *left, const void *right )
{
    const struct apple_import_range *a = left, *b = right;

    if (a->start < b->start) return -1;
    if (a->start > b->start) return 1;
    if (a->end < b->end) return -1;
    if (a->end > b->end) return 1;
    return 0;
}


static NTSTATUS get_apple_shared_ranges( const IMAGE_SECTION_HEADER *sections,
                                         ULONG section_count, SIZE_T align_mask,
                                         struct apple_import_range **ranges,
                                         SIZE_T *range_count )
{
    SIZE_T count = 0, i, offset;

    *ranges = NULL;
    *range_count = 0;
    if (!section_count) return STATUS_SUCCESS;
    if (!(*ranges = malloc( section_count * sizeof(**ranges) ))) return STATUS_NO_MEMORY;
    for (i = 0; i < section_count; i++)
    {
        SIZE_T map_size, start, end;

        if ((sections[i].Characteristics & (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE)) !=
            (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE))
            continue;
        map_size = ROUND_SIZE( 0, sections[i].Misc.VirtualSize ?
                              sections[i].Misc.VirtualSize : sections[i].SizeOfRawData,
                              align_mask );
        if (!map_size) continue;
        start = sections[i].VirtualAddress & ~host_page_mask;
        end = (sections[i].VirtualAddress + map_size + host_page_mask) & ~host_page_mask;
        (*ranges)[count].start = start;
        (*ranges)[count++].end = end;
    }
    qsort( *ranges, count, sizeof(**ranges), compare_apple_import_ranges );
    for (i = 1, offset = 0; i < count; i++)
    {
        if ((*ranges)[offset].end >= (*ranges)[i].start)
        {
            if ((*ranges)[offset].end < (*ranges)[i].end)
                (*ranges)[offset].end = (*ranges)[i].end;
        }
        else (*ranges)[++offset] = (*ranges)[i];
    }
    if (count) *range_count = offset + 1;
    return STATUS_SUCCESS;
}


static BOOL apple_page_overlaps_ranges( SIZE_T page,
                                         const struct apple_import_range *ranges,
                                         SIZE_T range_count )
{
    SIZE_T low = 0, high = range_count;

    while (low < high)
    {
        SIZE_T pos = low + (high - low) / 2;

        if (page < ranges[pos].start) high = pos;
        else if (page >= ranges[pos].end) low = pos + 1;
        else return TRUE;
    }
    return FALSE;
}


static NTSTATUS privatize_apple_page( struct file_view *view, SIZE_T page,
                                      const struct apple_import_range *shared_ranges,
                                      SIZE_T shared_range_count, BYTE *private_pages,
                                      SIZE_T private_page_count, void **snapshot )
{
    SIZE_T page_index = page / host_page_size;
    char *base = view->base;

    if (!apple_page_overlaps_ranges( page, shared_ranges, shared_range_count ))
        return STATUS_SUCCESS;
    if (page_index >= private_page_count) return STATUS_INVALID_IMAGE_FORMAT;
    if (private_pages[page_index / 8] & (1u << (page_index % 8)))
        return STATUS_SUCCESS;
    if (!*snapshot && !(*snapshot = malloc( host_page_size )))
        return STATUS_NO_MEMORY;
    memcpy( *snapshot, base + page, host_page_size );
    if (anon_mmap_fixed( base + page, host_page_size,
                         PROT_READ | PROT_WRITE, 0 ) == MAP_FAILED)
        return STATUS_NO_MEMORY;
    memcpy( base + page, *snapshot, host_page_size );
    private_pages[page_index / 8] |= 1u << (page_index % 8);
    return STATUS_SUCCESS;
}


static NTSTATUS privatize_apple_image_range(
    struct file_view *view, SIZE_T start, SIZE_T size,
    const struct apple_import_range *shared_ranges, SIZE_T shared_range_count,
    BYTE *private_pages, SIZE_T private_page_count, void **snapshot )
{
    SIZE_T page, end;
    NTSTATUS status;

    if (start > view->size || size > view->size - start)
        return STATUS_INVALID_IMAGE_FORMAT;
    if (!size || !shared_range_count) return STATUS_SUCCESS;
    end = start + size;
    for (page = start & ~host_page_mask; page < end; page += host_page_size)
        if ((status = privatize_apple_page(
                 view, page, shared_ranges, shared_range_count,
                 private_pages, private_page_count, snapshot )))
            return status;
    return STATUS_SUCCESS;
}


static NTSTATUS privatize_apple_c_string(
    struct file_view *view, struct import_string_cache *cache,
    ULONG rva, SIZE_T prefix_size,
    const struct apple_import_range *shared_ranges, SIZE_T shared_range_count,
    BYTE *private_pages, SIZE_T private_page_count, void **snapshot )
{
    struct import_string_interval *interval, *next;
    SIZE_T string_start, current, page_end;
    NTSTATUS status;
    const char *terminator;

    if (rva > view->size || prefix_size >= view->size - rva)
        return STATUS_INVALID_IMAGE_FORMAT;
    if ((status = privatize_apple_image_range(
             view, rva, prefix_size + 1, shared_ranges, shared_range_count,
             private_pages, private_page_count, snapshot )))
        return status;
    string_start = current = rva + prefix_size;
    if ((interval = find_import_string_interval( cache, current, &next )))
        return STATUS_SUCCESS;
    while (current < view->size)
    {
        if (next && current >= next->start)
            return add_import_string_interval( cache, string_start, next->end );
        page_end = (current + host_page_size) & ~host_page_mask;
        if (page_end > view->size || page_end < current) page_end = view->size;
        if (next && next->start < page_end) page_end = next->start;
        if ((status = privatize_apple_image_range(
                 view, current, page_end - current, shared_ranges, shared_range_count,
                 private_pages, private_page_count, snapshot )))
            return status;
        if ((terminator = memchr( (char *)view->base + current, 0,
                                  page_end - current )))
            return add_import_string_interval(
                cache, string_start, terminator - (char *)view->base + 1 );
        current = page_end;
    }
    return STATUS_INVALID_IMAGE_FORMAT;
}


static NTSTATUS privatize_apple_import_pages( struct file_view *view,
                                              const IMAGE_DATA_DIRECTORY *imports,
                                              SIZE_T thunk_size,
                                              const IMAGE_SECTION_HEADER *sections,
                                              ULONG section_count, SIZE_T align_mask )
{
    struct apple_import_range *ranges = NULL, *shared_ranges = NULL;
    struct import_string_cache string_cache;
    IMAGE_IMPORT_DESCRIPTOR descriptor;
    SIZE_T capacity = 0, count = 0, shared_range_count = 0, offset = 0, i;
    void *snapshot = NULL;
    BYTE *private_pages = NULL;
    SIZE_T private_page_count;
    NTSTATUS status = STATUS_INVALID_IMAGE_FORMAT;
    BOOL terminated = FALSE;
    char *base = view->base;

    init_import_string_cache( &string_cache );

    for (i = 0; i < section_count; i++)
        if ((sections[i].Characteristics & (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE)) ==
            (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE))
            break;
    if (i == section_count) return STATUS_SUCCESS;
    if ((status = get_apple_shared_ranges( sections, section_count, align_mask,
                                            &shared_ranges, &shared_range_count )))
        goto done;
    if (!shared_range_count)
    {
        status = STATUS_SUCCESS;
        goto done;
    }
    if (view->size > ~(SIZE_T)0 - host_page_mask)
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }
    private_page_count = ROUND_SIZE( 0, view->size, host_page_mask ) / host_page_size;
    if (!(private_pages = calloc( (private_page_count + 7) / 8, 1 )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }
    while (imports->Size - offset >= sizeof(descriptor))
    {
        ULONG lookup_rva, thunk_rva;
        SIZE_T thunk_offset = 0;
        ULONGLONG thunk;

        if ((status = privatize_apple_image_range(
                 view, imports->VirtualAddress + offset, sizeof(descriptor),
                 shared_ranges, shared_range_count, private_pages,
                 private_page_count, &snapshot )))
            goto done;
        memcpy( &descriptor, base + imports->VirtualAddress + offset, sizeof(descriptor) );
        offset += sizeof(descriptor);
        if (!descriptor.Name || !descriptor.FirstThunk)
        {
            terminated = TRUE;
            break;
        }
        if ((status = privatize_apple_c_string(
                 view, &string_cache, descriptor.Name, 0,
                 shared_ranges, shared_range_count,
                 private_pages, private_page_count, &snapshot )))
            goto done;
        lookup_rva = descriptor.OriginalFirstThunk ?
                     descriptor.OriginalFirstThunk : descriptor.FirstThunk;
        for (;;)
        {
            if (!apple_image_rva_offset_valid( view->size, lookup_rva, thunk_offset,
                                               thunk_size, &thunk_rva ))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto done;
            }
            if ((status = privatize_apple_image_range(
                     view, thunk_rva, thunk_size, shared_ranges, shared_range_count,
                     private_pages, private_page_count, &snapshot )))
                goto done;
            thunk = 0;
            memcpy( &thunk, base + thunk_rva, thunk_size );
            if (!thunk) break;
            if (!(thunk & (thunk_size == sizeof(IMAGE_THUNK_DATA32) ?
                           IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64)))
            {
                if (thunk > ~(ULONG)0)
                {
                    status = STATUS_INVALID_IMAGE_FORMAT;
                    goto done;
                }
                if ((status = privatize_apple_c_string(
                         view, &string_cache, thunk,
                         offsetof(IMAGE_IMPORT_BY_NAME, Name),
                         shared_ranges, shared_range_count, private_pages,
                         private_page_count, &snapshot )))
                    goto done;
            }
            if (!apple_image_rva_offset_valid( view->size, descriptor.FirstThunk,
                                               thunk_offset, thunk_size, &thunk_rva ))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto done;
            }
            if ((status = privatize_apple_image_range(
                     view, thunk_rva, thunk_size, shared_ranges, shared_range_count,
                     private_pages, private_page_count, &snapshot )))
                goto done;
            thunk_offset += thunk_size;
        }
        if (thunk_offset)
        {
            SIZE_T start = descriptor.FirstThunk & ~host_page_mask;
            SIZE_T end = (descriptor.FirstThunk + thunk_offset + host_page_mask) &
                         ~host_page_mask;

            if ((status = append_apple_import_range( &ranges, &count, &capacity,
                                                       start, end )))
                goto done;
        }
    }
    if (!terminated)
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }
    if ((status = append_apple_import_range(
             &ranges, &count, &capacity,
             imports->VirtualAddress & ~host_page_mask,
             (imports->VirtualAddress + offset + host_page_mask) & ~host_page_mask )))
        goto done;

    qsort( ranges, count, sizeof(*ranges), compare_apple_import_ranges );
    for (i = 1, offset = 0; i < count; i++)
    {
        if (ranges[offset].end >= ranges[i].start)
        {
            if (ranges[offset].end < ranges[i].end) ranges[offset].end = ranges[i].end;
        }
        else ranges[++offset] = ranges[i];
    }
    if (count) count = offset + 1;
    for (i = 0; i < count; i++)
    {
        SIZE_T page;

        for (page = ranges[i].start; page < ranges[i].end; page += host_page_size)
        {
            if ((status = privatize_apple_page(
                     view, page, shared_ranges, shared_range_count,
                     private_pages, private_page_count, &snapshot )))
                goto done;
        }
    }
    status = STATUS_SUCCESS;

done:
    free_import_string_cache( &string_cache );
    free( snapshot );
    free( private_pages );
    free( shared_ranges );
    free( ranges );
    return status;
}

#endif  /* __APPLE__ && !__aarch64__ */


/***********************************************************************
 *           process_relocation_block
 *
 * Reimplementation of LdrProcessRelocationBlock.
 */
static IMAGE_BASE_RELOCATION *process_relocation_block( char *page, IMAGE_BASE_RELOCATION *rel,
                                                        INT_PTR delta )
{
    USHORT *reloc = (USHORT *)(rel + 1);
    unsigned int count;

    for (count = (rel->SizeOfBlock - sizeof(*rel)) / sizeof(USHORT); count; count--, reloc++)
    {
        USHORT offset = *reloc & 0xfff;
        switch (*reloc >> 12)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGH:
            *(short *)(page + offset) += HIWORD(delta);
            break;
        case IMAGE_REL_BASED_LOW:
            *(short *)(page + offset) += LOWORD(delta);
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            *(int *)(page + offset) += delta;
            break;
        case IMAGE_REL_BASED_DIR64:
            *(INT64 *)(page + offset) += delta;
            break;
        case IMAGE_REL_BASED_THUMB_MOV32:
        {
            DWORD *inst = (DWORD *)(page + offset);
            WORD lo = ((inst[0] << 1) & 0x0800) + ((inst[0] << 12) & 0xf000) +
                      ((inst[0] >> 20) & 0x0700) + ((inst[0] >> 16) & 0x00ff);
            WORD hi = ((inst[1] << 1) & 0x0800) + ((inst[1] << 12) & 0xf000) +
                      ((inst[1] >> 20) & 0x0700) + ((inst[1] >> 16) & 0x00ff);
            DWORD imm = MAKELONG( lo, hi ) + delta;

            lo = LOWORD( imm );
            hi = HIWORD( imm );
            inst[0] = (inst[0] & 0x8f00fbf0) + ((lo >> 1) & 0x0400) + ((lo >> 12) & 0x000f) +
                                               ((lo << 20) & 0x70000000) + ((lo << 16) & 0xff0000);
            inst[1] = (inst[1] & 0x8f00fbf0) + ((hi >> 1) & 0x0400) + ((hi >> 12) & 0x000f) +
                                               ((hi << 20) & 0x70000000) + ((hi << 16) & 0xff0000);
            break;
        }
        default:
            FIXME( "Unknown/unsupported relocation %x\n", *reloc );
            return NULL;
        }
    }
    return (IMAGE_BASE_RELOCATION *)reloc;  /* return address of next block */
}


/***********************************************************************
 *           virtual_alloc_wow64_owned_backing
 *
 * Allocate a private, process-lifetime translated view.  The owning native
 * resource pool may recycle its contents, but guest memory APIs must never
 * invalidate the address retained by a native framework.
 */
NTSTATUS virtual_alloc_wow64_owned_backing( void **host_address, UINT64 *guest_address,
                                             SIZE_T *size )
{
#if defined(__APPLE__) && defined(__aarch64__)
    unsigned int vprot = VPROT_READ | VPROT_WRITE | VPROT_COMMITTED |
                         VPROT_WOW64_TRANSLATED | VPROT_WOW64_OWNED_BACKING;
    struct wow64_memory_transaction transaction;
    struct file_view *view;
    ULONG_PTR wow_limit, limit_low, limit_high;
    sigset_t sigset;
    NTSTATUS status;

    if (!host_address || !guest_address || !size) return STATUS_INVALID_PARAMETER;
    *host_address = NULL;
    *guest_address = 0;
    if (!is_wow64() || !*size || (*size & host_page_mask) ||
        is_beyond_limit( 0, *size, working_set_limit ))
        return STATUS_INVALID_PARAMETER;
    wow_limit = get_wow_user_space_limit();
    if (!wow_limit) wow_limit = limit_2g;
    if (wow_limit <= 0x10000) return STATUS_NO_MEMORY;
    limit_low = WINE_LOW_VA_SHADOW_BASE + 0x10000;
    limit_high = WINE_LOW_VA_SHADOW_BASE + wow_limit - 1;

    status = wow64_memory_begin_transaction( &transaction, TRUE,
                                              WINE_WOW64_MEMORY_ALLOCATE,
                                              NULL, *size, NULL );
    if (status) return status;
    if (!transaction.observer_begun || transaction.nested)
    {
        transaction.event.status = STATUS_INVALID_DEVICE_STATE;
        wow64_memory_complete_transaction( &transaction );
        return STATUS_INVALID_DEVICE_STATE;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    status = map_view( &view, NULL, *size, 0, vprot, limit_low, limit_high,
                       granularity_mask );
    if (!status)
    {
        *host_address = view->base;
        *guest_address = wow64_native_to_guest_addr( view->base );
        *size = view->size;
        wow64_memory_capture_transaction( &transaction, status, view->base,
                                           view->size, view->base );
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    else wow64_memory_capture_transaction( &transaction, status, NULL, 0, NULL );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    wow64_memory_complete_transaction( &transaction );
    return status;
#else
    if (host_address) *host_address = NULL;
    if (guest_address) *guest_address = 0;
    (void)size;
    return STATUS_NOT_SUPPORTED;
#endif
}


/***********************************************************************
 *           map_image_into_view
 *
 * Map an executable (PE format) image into an existing view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_image_into_view( struct file_view *view, const UNICODE_STRING *nt_name, int fd,
                                     struct pe_image_info *image_info, USHORT machine,
                                     int shared_fd, BOOL removable )
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sections = NULL, *sec;
    IMAGE_DATA_DIRECTORY *imports, *dir;
    NTSTATUS status = STATUS_CONFLICTING_ADDRESSES;
    int i;
    off_t pos;
    struct stat st;
    char *header_end;
    char *ptr = view->base;
    SIZE_T header_size, header_map_size, header_span, nt_offset, section_offset, section_end;
    SIZE_T total_size = view->size;
    SIZE_T align_mask = max( image_info->alignment - 1, page_mask );
    INT_PTR delta;
#ifdef __aarch64__
    USHORT source_machine;
    USHORT mapped_machine = image_info->machine;
    UINT mapped_entry_point = image_info->entry_point;
    struct arm64x_fixup_transaction arm64x_transaction = {0};
    struct arm64ec_mapping arm64ec_mapping = {0};
    IMAGE_NT_HEADERS transformed_nt;
    IMAGE_DATA_DIRECTORY transformed_load_config, transformed_import, effective_import;
    SIZE_T effective_import_thunk_size = 0;
    BOOL transformed_load_config_present, transformed_import_present;
    BOOL hybrid_metadata_processed = FALSE, effective_import_present = FALSE;
#if defined(__APPLE__)
    BOOL initialize_native_arm64ec_protections = FALSE;
#endif
#endif

    TRACE_(module)( "mapping PE file %s at %p-%p\n", debugstr_us(nt_name), ptr, ptr + total_size );

    /* map the header */

    fstat( fd, &st );
    header_size = min( image_info->header_size, st.st_size );
    header_map_size = min( image_info->header_map_size, ROUND_SIZE( 0, st.st_size, host_page_mask ));
    if ((status = map_pe_header( view->base, header_size, header_map_size, fd, &removable )))
        return status;

    status = STATUS_INVALID_IMAGE_FORMAT;  /* generic error */
    if (header_size < sizeof(*dos)) return status;
    header_span = ROUND_SIZE( 0, header_size, align_mask );
    if (header_span < header_size || header_span > total_size) return status;
    header_end = ptr + header_span;
    memset( ptr + header_size, 0, header_end - (ptr + header_size) );
    dos = (IMAGE_DOS_HEADER *)ptr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return status;
    nt_offset = dos->e_lfanew;
    if (nt_offset > header_span || sizeof(*nt) > header_span - nt_offset)
        return status;
    nt = (IMAGE_NT_HEADERS *)(ptr + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return status;
    section_offset = nt_offset + offsetof( IMAGE_NT_HEADERS, OptionalHeader );
    if (nt->FileHeader.SizeOfOptionalHeader > header_span - section_offset)
        return status;
    section_offset += nt->FileHeader.SizeOfOptionalHeader;
    if (nt->FileHeader.NumberOfSections > (header_span - section_offset) / sizeof(*sec))
        return status;
    section_end = section_offset + nt->FileHeader.NumberOfSections * sizeof(*sec);
    sec = (IMAGE_SECTION_HEADER *)(ptr + section_offset);
    if (section_end > image_info->header_map_size)
    {
        /* copy section data since it will get overwritten by a section mapping */
        if (!(sections = malloc( sizeof(*sections) * nt->FileHeader.NumberOfSections )))
            return STATUS_NO_MEMORY;
        memcpy( sections, sec, sizeof(*sections) * nt->FileHeader.NumberOfSections );
        sec = sections;
    }
    imports = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_IMPORT );

#ifdef __aarch64__
    source_machine = nt->FileHeader.Machine;
    if (source_machine != image_info->machine) goto done;
#endif

    /* check for non page-aligned binary */

    if (image_info->image_flags & IMAGE_FLAGS_ImageMappedFlat)
    {
        /* unaligned sections, this happens for native subsystem binaries */
        /* in that case Windows simply maps in the whole file */

        total_size = min( total_size, ROUND_SIZE( 0, st.st_size, page_mask ));
        if (map_file_into_view( view, fd, 0, total_size, 0, VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                                removable ) != STATUS_SUCCESS) goto done;

        /* check that all sections are loaded at the right offset */
        if (nt->OptionalHeader.FileAlignment != nt->OptionalHeader.SectionAlignment) goto done;
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (sec[i].VirtualAddress != sec[i].PointerToRawData)
                goto done;  /* Windows refuses to load in that case too */
        }

        /* set the image protections */
#if defined(__APPLE__) && defined(__aarch64__)
        if (!(view->protect & VPROT_SHADOW_TRANSLATED) &&
            source_machine == IMAGE_FILE_MACHINE_AMD64)
            view->protect |= VPROT_AMD64_IDENTITY;
        else
            view->protect &= ~VPROT_AMD64_IDENTITY;
#endif
        if (!set_vprot( view, ptr, total_size,
                        VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC ))
        {
            status = STATUS_ACCESS_DENIED;
            goto done;
        }

        /* no relocations are performed on non page-aligned binaries */
        status = STATUS_SUCCESS;
        goto done;
    }


    /* map all the sections */

    for (i = pos = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        static const SIZE_T sector_align = 0x1ff;
        SIZE_T map_size, file_start, file_size, end;

        if (!sec[i].Misc.VirtualSize)
            map_size = ROUND_SIZE( 0, sec[i].SizeOfRawData, align_mask );
        else
            map_size = ROUND_SIZE( 0, sec[i].Misc.VirtualSize, align_mask );

        /* file positions are rounded to sector boundaries regardless of OptionalHeader.FileAlignment */
        file_start = sec[i].PointerToRawData & ~sector_align;
        file_size = ROUND_SIZE( sec[i].PointerToRawData, sec[i].SizeOfRawData, sector_align );
        if (file_size > map_size) file_size = map_size;

        /* a few sanity checks */
        end = sec[i].VirtualAddress + ROUND_SIZE( sec[i].VirtualAddress, map_size, align_mask );
        if (sec[i].VirtualAddress > total_size || end > total_size || end < sec[i].VirtualAddress)
        {
            WARN_(module)( "%s section %.8s too large (%x+%lx/%lx)\n",
                           debugstr_us(nt_name), sec[i].Name, sec[i].VirtualAddress, map_size, total_size );
            goto done;
        }

        if ((sec[i].Characteristics & IMAGE_SCN_MEM_SHARED) &&
            (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            TRACE_(module)( "%s mapping shared section %.8s at %p off %x (%x) size %lx (%lx) flags %x\n",
                            debugstr_us(nt_name), sec[i].Name, ptr + sec[i].VirtualAddress,
                            sec[i].PointerToRawData, (int)pos, file_size, map_size,
                            sec[i].Characteristics );
            if (map_file_into_view( view, shared_fd, sec[i].VirtualAddress, map_size, pos,
                                    VPROT_COMMITTED | VPROT_READ | VPROT_WRITE, FALSE ) != STATUS_SUCCESS)
            {
                ERR_(module)( "Could not map %s shared section %.8s\n", debugstr_us(nt_name), sec[i].Name );
                goto done;
            }

#ifndef __APPLE__
            /* check if the import directory falls inside this section */
            if (imports && imports->VirtualAddress >= sec[i].VirtualAddress &&
                imports->VirtualAddress < sec[i].VirtualAddress + map_size)
            {
                UINT_PTR base = imports->VirtualAddress & ~host_page_mask;
                UINT_PTR end = base + ROUND_SIZE( imports->VirtualAddress, imports->Size, host_page_mask );
                if (end > sec[i].VirtualAddress + map_size) end = sec[i].VirtualAddress + map_size;
                if (end > base)
                    map_file_into_view( view, shared_fd, base, end - base,
                                        pos + (base - sec[i].VirtualAddress),
                                        VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY, FALSE );
            }
#else
            /* Apple SEC_IMAGE falls back to pread() here, which would write through
             * the MAP_SHARED backing.  Privatize validated descriptor and IAT pages
             * explicitly after all sections have been mapped instead. */
#endif
            pos += map_size;
            continue;
        }

        TRACE_(module)( "mapping %s section %.8s at %p off %x size %x virt %x flags %x\n",
                        debugstr_us(nt_name), sec[i].Name, ptr + sec[i].VirtualAddress,
                        sec[i].PointerToRawData, sec[i].SizeOfRawData,
                        sec[i].Misc.VirtualSize, sec[i].Characteristics );

        if (!sec[i].PointerToRawData || !file_size) continue;

        /* Note: if the section is not aligned properly map_file_into_view will magically
         *       fall back to read(), so we don't need to check anything here.
         */
        end = file_start + file_size;
        if (sec[i].PointerToRawData >= st.st_size ||
            end > ((st.st_size + sector_align) & ~sector_align) ||
            end < file_start ||
            map_file_into_view( view, fd, sec[i].VirtualAddress, file_size, file_start,
                                VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                                removable ) != STATUS_SUCCESS)
        {
            ERR_(module)( "Could not map %s section %.8s, file probably truncated\n",
                          debugstr_us(nt_name), sec[i].Name );
            goto done;
        }

        if (file_size & align_mask)
        {
            end = ROUND_SIZE( 0, file_size, align_mask );
            if (end > map_size) end = map_size;
            TRACE_(module)("clearing %p - %p\n",
                           ptr + sec[i].VirtualAddress + file_size,
                           ptr + sec[i].VirtualAddress + end );
            memset( ptr + sec[i].VirtualAddress + file_size, 0, end - file_size );
        }
    }

#ifdef __aarch64__
#ifdef __APPLE__
    if (imports)
    {
        effective_import = *imports;
        effective_import_present = TRUE;
        effective_import_thunk_size = nt->OptionalHeader.Magic ==
                                      IMAGE_NT_OPTIONAL_HDR32_MAGIC ?
                                      sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64);
    }
#endif
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        (mapped_machine == IMAGE_FILE_MACHINE_AMD64 ||
         (mapped_machine == IMAGE_FILE_MACHINE_ARM64 &&
          (machine == IMAGE_FILE_MACHINE_AMD64 ||
           (!machine && main_image_info.Machine == IMAGE_FILE_MACHINE_AMD64)))))
    {
        hybrid_metadata_processed = TRUE;
        if ((dir = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG )) &&
            mapped_machine == IMAGE_FILE_MACHINE_ARM64)
        {
            status = update_arm64x_mapping( view, nt, dir, sec, total_size,
                                             &arm64x_transaction );
            if (status) goto done;
        }
        if ((status = get_transformed_nt_headers( ptr, nt, total_size, &arm64x_transaction,
                                                   &transformed_nt )))
            goto done;
        if ((status = validate_transformed_sections( ptr, nt, sec, total_size,
                                                      &arm64x_transaction )))
            goto done;
        mapped_machine = transformed_nt.FileHeader.Machine;
        if (mapped_machine != IMAGE_FILE_MACHINE_AMD64)
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        mapped_entry_point = transformed_nt.OptionalHeader.AddressOfEntryPoint;
        if ((status = get_transformed_data_dir( &transformed_nt, total_size,
                                                 IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
                                                 &transformed_load_config,
                                                 &transformed_load_config_present )))
            goto done;
        if (mapped_machine == IMAGE_FILE_MACHINE_AMD64 && transformed_load_config_present)
        {
            status = update_arm64ec_ranges( view, &transformed_nt, &arm64x_transaction,
                                            &transformed_load_config, sec,
                                            nt->FileHeader.NumberOfSections, align_mask,
                                            total_size,
                                            &arm64ec_mapping );
            if (status) goto done;
        }
        if ((status = get_transformed_data_dir( &transformed_nt, total_size,
                                                 IMAGE_DIRECTORY_ENTRY_IMPORT,
                                                 &transformed_import,
                                                 &transformed_import_present )))
            goto done;
#ifdef __APPLE__
        effective_import_present = transformed_import_present;
#else
        effective_import_present = transformed_import_present &&
            (!imports || imports->VirtualAddress != transformed_import.VirtualAddress ||
             imports->Size != transformed_import.Size);
#endif
        if (effective_import_present)
        {
            effective_import = transformed_import;
            effective_import_thunk_size = sizeof(IMAGE_THUNK_DATA64);
        }
    }
    if (source_machine == IMAGE_FILE_MACHINE_AMD64 &&
        !!image_info->is_hybrid != arm64ec_mapping.present)
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }
    if (machine && machine != (hybrid_metadata_processed ? mapped_machine : nt->FileHeader.Machine))
    {
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }
    if ((status = privatize_arm64x_pages( view, &arm64x_transaction, sec,
                                          nt->FileHeader.NumberOfSections, align_mask,
                                          effective_import_present ? &effective_import : NULL,
                                          effective_import_thunk_size,
                                          &arm64ec_mapping )))
        goto done;
    apply_arm64x_transaction( ptr, &arm64x_transaction );
    commit_arm64ec_mapping( view, NULL, &arm64ec_mapping );
    if (arm64ec_mapping.present) mapped_entry_point = arm64ec_mapping.entry_point;
#else
    if (machine && machine != nt->FileHeader.Machine)
    {
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }
#ifdef __APPLE__
    if (imports &&
        (status = privatize_apple_import_pages(
             view, imports,
             nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ?
                 sizeof(IMAGE_THUNK_DATA32) : sizeof(IMAGE_THUNK_DATA64),
             sec, nt->FileHeader.NumberOfSections, align_mask )))
        goto done;
#endif
#endif

    /* relocate to dynamic base */

    if (image_info->map_addr && (delta = image_info->map_addr - image_info->base))
    {
        TRACE_(module)( "relocating %s dynamic base %lx -> %lx mapped at %p\n", debugstr_us(nt_name),
                        (ULONG_PTR)image_info->base, (ULONG_PTR)image_info->map_addr, ptr );

        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase = image_info->map_addr;
        else
            ((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.ImageBase = image_info->map_addr;

        if ((dir = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_BASERELOC )))
        {
            IMAGE_BASE_RELOCATION *rel = (IMAGE_BASE_RELOCATION *)(ptr + dir->VirtualAddress);
            IMAGE_BASE_RELOCATION *end = (IMAGE_BASE_RELOCATION *)((char *)rel + dir->Size);

            while (rel && rel < end - 1 && rel->SizeOfBlock && rel->VirtualAddress < total_size)
                rel = process_relocation_block( ptr + rel->VirtualAddress, rel, delta );
        }
    }

    /* set the image protections */

#if defined(__APPLE__) && defined(__aarch64__)
    initialize_native_arm64ec_protections =
        !(view->protect & VPROT_SHADOW_TRANSLATED) &&
        mapped_machine == IMAGE_FILE_MACHINE_AMD64 && arm64ec_mapping.has_native_code &&
        align_mask < host_page_mask;

    /* A sub-host-page native image must not expose the initial image-wide
     * WRITECOPY|EXEC logical protection while its final per-section protections
     * are being installed.  Initialize every logical lane to no-access, then
     * project each final protection normally. */
    if (initialize_native_arm64ec_protections)
    {
        if (!set_vprot( view, ptr, total_size, VPROT_COMMITTED ))
        {
            status = STATUS_ACCESS_DENIED;
            goto done;
        }
    }
    if (!(view->protect & VPROT_SHADOW_TRANSLATED) &&
        mapped_machine == IMAGE_FILE_MACHINE_AMD64 && !arm64ec_mapping.has_native_code)
        view->protect |= VPROT_AMD64_IDENTITY;
    else
        view->protect &= ~VPROT_AMD64_IDENTITY;
#endif

    if (!set_vprot( view, ptr, ROUND_SIZE( 0, header_size, align_mask ),
                    VPROT_COMMITTED | VPROT_READ ))
    {
        status = STATUS_ACCESS_DENIED;
        goto done;
    }

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T size;
        BYTE vprot = VPROT_COMMITTED;

        if (!sec[i].Misc.VirtualSize && !sec[i].SizeOfRawData) continue;
        if (sec[i].Misc.VirtualSize)
            size = ROUND_SIZE( sec[i].VirtualAddress, sec[i].Misc.VirtualSize, align_mask );
        else
            size = ROUND_SIZE( sec[i].VirtualAddress, sec[i].SizeOfRawData, align_mask );

        if (sec[i].Characteristics & IMAGE_SCN_MEM_READ)    vprot |= VPROT_READ;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)   vprot |= VPROT_WRITECOPY;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) vprot |= VPROT_EXEC;

        if (!set_vprot( view, ptr + sec[i].VirtualAddress, size, vprot ))
        {
            ERR( "failed to set %08x protection on %s section %.8s\n",
                 sec[i].Characteristics, debugstr_us(nt_name), sec[i].Name );
            status = STATUS_ACCESS_DENIED;
            goto done;
        }
    }

#ifdef VALGRIND_LOAD_PDB_DEBUGINFO
    VALGRIND_LOAD_PDB_DEBUGINFO(fd, ptr, total_size, ptr - (char *)wine_server_get_ptr( image_info->base ));
#endif
#ifdef __aarch64__
    image_info->machine = mapped_machine;
    image_info->entry_point = mapped_entry_point;
#endif
    status = STATUS_SUCCESS;

done:
#ifdef __aarch64__
    free_arm64x_transaction( &arm64x_transaction );
#endif
    free( sections );
    return status;
}


/***********************************************************************
 *             free_pe_mapping_info
 */
static void free_pe_mapping_info( struct pe_mapping_info *info )
{
    if (info->shared_file) NtClose( info->shared_file );
    free( info );
}


/***********************************************************************
 *             get_mapping_info
 */
static unsigned int get_mapping_info( HANDLE handle, ACCESS_MASK access, unsigned int *sec_flags,
                                      mem_size_t *full_size, struct pe_mapping_info **info_ret )
{
    struct pe_mapping_info *info;
    SIZE_T total, size = 2048;
    unsigned int status;

    *info_ret = NULL;
    for (;;)
    {
        if (!(info = malloc( offsetof(struct pe_mapping_info, image) + size ))) return STATUS_NO_MEMORY;

        SERVER_START_REQ( get_mapping_info )
        {
            req->handle = wine_server_obj_handle( handle );
            req->access = access;
            wine_server_set_reply( req, &info->image, size );
            status = wine_server_call( req );
            *sec_flags   = reply->flags;
            *full_size   = reply->size;
            total        = reply->total;
            info->shared_file = wine_server_ptr_handle( reply->shared_file );
            info->version_len = reply->ver_len;
            info->nt_name.Length = info->nt_name.MaximumLength = reply->name_len;
        }
        SERVER_END_REQ;
        if (!status && total <= size) break;
        free_pe_mapping_info( info );
        if (status) return status;
        size = total;
    }

    if (total)
    {
        info->version_res     = info->data;
        info->nt_name.Buffer  = (WCHAR *)(info->data + info->version_len);
        info->exp_name.Buffer = info->data + info->version_len + info->nt_name.Length;
        info->exp_name.Length = total - sizeof(info->image) - info->version_len - info->nt_name.Length;
        info->exp_name.MaximumLength = info->exp_name.Length;
        *info_ret = info;
    }
    else free_pe_mapping_info( info );

    return STATUS_SUCCESS;
}


/***********************************************************************
 *             map_image_view
 *
 * Map a view for a PE image at an appropriate address.
 */
static NTSTATUS map_image_view( struct file_view **view_ret, struct pe_image_info *image_info, SIZE_T size,
                                ULONG_PTR limit_low, ULONG_PTR limit_high, ULONG alloc_type,
                                ULONG_PTR address_bias, unsigned int translated_vprot )
{
    unsigned int vprot = SEC_IMAGE | SEC_FILE | VPROT_COMMITTED | VPROT_READ | VPROT_EXEC | VPROT_WRITECOPY;
    void *base;
    NTSTATUS status;
    ULONG_PTR start, end;
    BOOL top_down = (image_info->image_charact & IMAGE_FILE_DLL) &&
                    (image_info->image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated);

    if (address_bias)
    {
        ULONG_PTR wow_limit = get_wow_user_space_limit();
        ULONG_PTR guest_limit;

        vprot |= translated_vprot;
        /* WoW64 thunks pass translated address requirements in native host form.
         * Convert those limits back to guest form before applying the image bias;
         * bootstrap mappings made before the provider starts still pass zero limits. */
        if (limit_low >= address_bias && limit_low - address_bias < WINE_LOW_VA_SHADOW_SIZE)
            limit_low -= address_bias;
        if (limit_high >= address_bias && limit_high - address_bias < WINE_LOW_VA_SHADOW_SIZE)
            limit_high -= address_bias;
        /* The main image is mapped before virtual_set_large_address_space(). */
        if (!wow_limit) wow_limit = WINE_LOW_VA_SHADOW_SIZE - (granularity_mask + 1);
        /* get_wow_user_space_limit() is exclusive; map_view() takes an inclusive high bound. */
        guest_limit = limit_high ? min( limit_high, wow_limit - 1 ) : wow_limit - 1;

        limit_low = address_bias + max( limit_low, (ULONG_PTR)address_space_start );
        limit_high = address_bias + guest_limit;
    }
    else
    {
        /* make sure the DOS area remains free */
        limit_low = max( limit_low, (ULONG_PTR)address_space_start );
        if (!limit_high) limit_high = (ULONG_PTR)user_space_limit;
    }

    /* first try the specified base */

    if (image_info->map_addr)
    {
        ULONG_PTR preferred = address_bias + image_info->map_addr;

        base = wine_server_get_ptr( preferred );
        if ((ULONG_PTR)base != preferred) base = NULL;
    }
    else
    {
        ULONG_PTR preferred = address_bias + image_info->base;

        base = wine_server_get_ptr( preferred );
        if ((ULONG_PTR)base != preferred) base = NULL;
    }
    if (base)
    {
        status = map_view( view_ret, base, size, alloc_type, vprot, limit_low, limit_high, 0 );
        if (!status) return status;
    }

    /* A fixed-low AMD64 image cannot be relocated within the guest address
     * domain. Its authoritative backing must land at the exact biased base. */
    if (translated_vprot & VPROT_AMD64_LOW_TRANSLATED)
        return STATUS_CONFLICTING_ADDRESSES;

    /* A translated 32-bit image must never escape its owned shadow window. */
    if (address_bias)
        return map_view( view_ret, NULL, size, top_down ? MEM_TOP_DOWN : 0,
                         vprot, limit_low, limit_high, 0 );

    /* then some appropriate address range */

    if (image_info->base >= limit_4g)
    {
        start = max( limit_low, limit_4g );
        end = limit_high;
    }
    else
    {
        start = limit_low;
        end = min( limit_high, get_wow_user_space_limit() );
    }
    if (start < end && (start != limit_low || end != limit_high))
    {
        status = map_view( view_ret, NULL, size, top_down ? MEM_TOP_DOWN : 0, vprot, start, end, 0 );
        if (!status) return status;
    }

    /* then any suitable address */

    return map_view( view_ret, NULL, size, top_down ? MEM_TOP_DOWN : 0, vprot, limit_low, limit_high, 0 );
}


/***********************************************************************
 *             virtual_map_image
 *
 * Map a PE image section into memory.
 */
static NTSTATUS virtual_map_image( HANDLE mapping, void **addr_ptr, SIZE_T *size_ptr,
                                   ULONG_PTR limit_low, ULONG_PTR limit_high, ULONG alloc_type,
                                   struct pe_mapping_info *pe_mapping, USHORT machine,
                                   BOOL translated_wow64, BOOL translated_amd64_low,
                                   BOOL is_builtin, off_t offset)
{
    int unix_fd = -1, needs_close;
    int shared_fd = -1, shared_needs_close = 0;
    SIZE_T size = pe_mapping->image.map_size;
    ULONG_PTR address_bias = 0;
    unsigned int translated_vprot = 0;
    struct file_view *view;
    unsigned int status;
    sigset_t sigset;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    struct arm64ec_low_memory_transaction low_transaction;
    struct arm64ec_code_transaction code_transaction;
    void *capture_base;
    void *allocation_base = NULL;
    SIZE_T capture_size;
#endif

    if (offset >= size)
        return STATUS_INVALID_PARAMETER;

#if defined(__APPLE__) && defined(__aarch64__)
    if (translated_wow64)
    {
        if (pe_mapping->image.machine != IMAGE_FILE_MACHINE_I386)
            return STATUS_INVALID_IMAGE_FORMAT;
        address_bias = WINE_LOW_VA_SHADOW_BASE;
        translated_vprot = VPROT_WOW64_TRANSLATED;
    }
    else if (translated_amd64_low && !offset &&
             pe_mapping->image.machine == IMAGE_FILE_MACHINE_AMD64 &&
             !(pe_mapping->image.image_charact & IMAGE_FILE_DLL) &&
             (pe_mapping->image.image_charact & IMAGE_FILE_RELOCS_STRIPPED) &&
             pe_mapping->image.base < limit_4g &&
             size <= limit_4g - pe_mapping->image.base)
    {
        address_bias = WINE_LOW_VA_SHADOW_BASE;
        translated_vprot = VPROT_AMD64_LOW_TRANSLATED;
    }
#else
    (void)translated_wow64;
#endif

    if ((status = server_get_unix_fd( mapping, 0, &unix_fd, &needs_close, NULL, NULL )))
        return status;

    if (pe_mapping->shared_file &&
        ((status = server_get_unix_fd( pe_mapping->shared_file, FILE_READ_DATA|FILE_WRITE_DATA,
                                       &shared_fd, &shared_needs_close, NULL, NULL ))))
    {
        if (needs_close) close( unix_fd );
        return status;
    }

#if defined(__APPLE__) && defined(__aarch64__)
    status = wow64_memory_begin_transaction(
                                              &transaction,
                                              !!(translated_vprot & VPROT_WOW64_TRANSLATED),
                                              WINE_WOW64_MEMORY_MAP,
                                              *addr_ptr, size, NULL );
    if (status)
    {
        if (needs_close) close( unix_fd );
        if (shared_needs_close) close( shared_fd );
        return status;
    }
    status = arm64ec_low_memory_begin_transaction(
        &low_transaction, !!(translated_vprot & VPROT_AMD64_LOW_TRANSLATED),
        WINE_WOW64_MEMORY_MAP,
        translated_vprot & VPROT_AMD64_LOW_TRANSLATED ?
            (void *)(WINE_LOW_VA_SHADOW_BASE + pe_mapping->image.base) : *addr_ptr,
        size, NULL );
    if (status)
    {
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        if (needs_close) close( unix_fd );
        if (shared_needs_close) close( shared_fd );
        return status;
    }
    status = arm64ec_code_begin_transaction(
        &code_transaction,
        is_arm64ec() && !(translated_vprot & VPROT_AMD64_LOW_TRANSLATED),
        WINE_ARM64EC_CODE_MAP );
    if (status)
    {
        low_transaction.event.status = status;
        arm64ec_low_memory_complete_transaction( &low_transaction );
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        if (needs_close) close( unix_fd );
        if (shared_needs_close) close( shared_fd );
        return status;
    }
    capture_base = translated_vprot & VPROT_AMD64_LOW_TRANSLATED ?
                   (void *)(WINE_LOW_VA_SHADOW_BASE + pe_mapping->image.base) : *addr_ptr;
    capture_size = size;
#endif

    if (!pe_mapping->image.map_addr &&
        (pe_mapping->image.image_charact & IMAGE_FILE_DLL) &&
        (pe_mapping->image.image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated))
    {
        SERVER_START_REQ( get_image_map_address )
        {
            req->handle = wine_server_obj_handle( mapping );
            if (!wine_server_call( req )) pe_mapping->image.map_addr = reply->addr;
        }
        SERVER_END_REQ;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    status = map_image_view( &view, &pe_mapping->image, size, limit_low, limit_high,
                             alloc_type, address_bias, translated_vprot );
    if (status) goto done;
#if defined(__APPLE__) && defined(__aarch64__)
    capture_base = view->base;
    allocation_base = view->base;
#endif

    status = map_image_into_view( view, &pe_mapping->nt_name, unix_fd, &pe_mapping->image,
                                  machine, shared_fd, needs_close );
    if (status == STATUS_SUCCESS)
    {
        if (offset)
        {
            free_pages( view, view->base, offset );
            size -= offset;
#if defined(__APPLE__) && defined(__aarch64__)
            capture_base = view->base;
            allocation_base = view->base;
            capture_size = size;
#endif
        }

        pe_mapping->image.base = wine_server_client_ptr(
            translated_vprot ? (char *)view->base - address_bias : view->base );
        SERVER_START_REQ( map_image_view )
        {
            req->mapping = wine_server_obj_handle( mapping );
            req->base    = wine_server_client_ptr( view->base );
            req->guest_base = pe_mapping->image.base;
            req->size    = size;
            req->entry   = pe_mapping->image.entry_point;
            req->machine = pe_mapping->image.machine;
            req->flags   = translated_vprot & VPROT_AMD64_LOW_TRANSLATED ?
                           IMAGE_VIEW_TRANSLATED_AMD64_LOW :
                           translated_vprot & VPROT_WOW64_TRANSLATED ?
                           IMAGE_VIEW_TRANSLATED_WOW64 : 0;
            req->offset  = offset;
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
    }
    if (NT_SUCCESS(status))
    {
        if (is_builtin && !offset) add_builtin_module( view->base, NULL );
        *addr_ptr = view->base;
        *size_ptr = size;
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    else delete_view( view );

done:
#if defined(__APPLE__) && defined(__aarch64__)
    if (translated_vprot & VPROT_AMD64_LOW_TRANSLATED)
    {
        void *low_base = capture_base;
        SIZE_T low_size = capture_size;

        arm64ec_low_memory_capture_transaction( &low_transaction, status,
                                                 low_base, low_size,
                                                 allocation_base );
    }
    if (capture_base && is_inside_wow64_shadow( capture_base, capture_size ))
        wow64_memory_capture_transaction( &transaction, status, capture_base,
                                           capture_size, allocation_base );
    else
        wow64_memory_capture_transaction( &transaction, status, NULL, 0, NULL );
    arm64ec_code_capture_transaction( &code_transaction, status );
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_complete_transaction( &code_transaction );
    wow64_memory_complete_transaction( &transaction );
    arm64ec_low_memory_complete_transaction( &low_transaction );
#endif
    if (needs_close) close( unix_fd );
    if (shared_needs_close) close( shared_fd );
    return status;
}


/***********************************************************************
 *             virtual_map_section
 *
 * Map a file section into memory.
 */
static unsigned int virtual_map_section( HANDLE handle, PVOID *addr_ptr, ULONG_PTR limit_low,
                                         ULONG_PTR limit_high, SIZE_T commit_size,
                                         const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                         ULONG alloc_type, ULONG protect, USHORT machine,
                                         BOOL translated_wow64 )
{
    unsigned int res;
    mem_size_t full_size;
    ACCESS_MASK access;
    SIZE_T size;
    struct pe_mapping_info *pe_mapping;
    void *base;
    int unix_handle = -1, needs_close;
    unsigned int vprot, sec_flags;
    struct file_view *view;
    LARGE_INTEGER offset;
    sigset_t sigset;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    struct arm64ec_code_transaction code_transaction;
    BOOL transaction_candidate;
    void *capture_base;
    void *allocation_base = NULL;
#endif

    switch(protect)
    {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_WRITECOPY:
        access = SECTION_MAP_READ;
        break;
    case PAGE_READWRITE:
        access = SECTION_MAP_WRITE;
        break;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_WRITECOPY:
        access = SECTION_MAP_READ | SECTION_MAP_EXECUTE;
        break;
    case PAGE_EXECUTE_READWRITE:
        access = SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    res = get_mapping_info( handle, access, &sec_flags, &full_size, &pe_mapping );
    if (res) return res;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    if (pe_mapping)
    {
        SECTION_IMAGE_INFORMATION info;
        ULONG64 prev = 0;
        struct thread_data *data = get_thread_data();
        TEB64 *teb64 = get_teb64( data->teb );

        if (teb64)
        {
            prev = teb64->Tib.ArbitraryUserPointer;
            teb64->Tib.ArbitraryUserPointer =
                wow64_native_to_guest_addr( data->teb->Tib.ArbitraryUserPointer );
        }
        /* check if we can replace that mapping with the builtin */
        res = load_builtin( pe_mapping, machine, &info, addr_ptr, size_ptr,
                            limit_low, limit_high, offset.QuadPart,
                            translated_wow64, FALSE );
        if (res == STATUS_IMAGE_ALREADY_LOADED)
            res = virtual_map_image( handle, addr_ptr, size_ptr, limit_low, limit_high,
                                     alloc_type, pe_mapping, machine, translated_wow64,
                                     FALSE, FALSE, offset.QuadPart );
        free_pe_mapping_info( pe_mapping );
        if (teb64) teb64->Tib.ArbitraryUserPointer = prev;
        return res;
    }

    base = *addr_ptr;
    if (offset.QuadPart >= full_size) return STATUS_INVALID_PARAMETER;
    if (*size_ptr)
    {
        size = *size_ptr;
        if (size > full_size - offset.QuadPart) return STATUS_INVALID_VIEW_SIZE;
    }
    else
    {
        size = full_size - offset.QuadPart;
        if (size != full_size - offset.QuadPart)  /* truncated */
        {
            WARN( "Files larger than 4Gb (%s) not supported on this platform\n",
                  wine_dbgstr_longlong(full_size) );
            return STATUS_INVALID_PARAMETER;
        }
    }
    if (!(size = ROUND_SIZE( 0, size, page_mask ))) return STATUS_INVALID_PARAMETER;  /* wrap-around */

    if (!(sec_flags & SEC_RESERVE)) commit_size = 0;
    else if (commit_size)
    {
        commit_size = ROUND_SIZE( 0, commit_size, page_mask );
        if (!commit_size || commit_size > size) return STATUS_INVALID_PARAMETER;
    }

    get_vprot_flags( protect, &vprot, FALSE );
    vprot |= sec_flags;
    if (!(sec_flags & SEC_RESERVE)) vprot |= VPROT_COMMITTED;
#if defined(__APPLE__) && defined(__aarch64__)
    if (translated_wow64) vprot |= VPROT_WOW64_TRANSLATED;
#else
    (void)translated_wow64;
#endif

    if ((res = server_get_unix_fd( handle, 0, &unix_handle, &needs_close, NULL, NULL ))) return res;

#if defined(__APPLE__) && defined(__aarch64__)
    transaction_candidate = translated_wow64 ||
                            ((alloc_type & MEM_REPLACE_PLACEHOLDER) && base &&
                             is_inside_wow64_shadow( base, size ));
    res = wow64_memory_begin_transaction( &transaction, transaction_candidate,
                                           WINE_WOW64_MEMORY_MAP, base, size, NULL );
    if (res)
    {
        if (needs_close) close( unix_handle );
        return res;
    }
    res = arm64ec_code_begin_transaction( &code_transaction, is_arm64ec(),
                                          WINE_ARM64EC_CODE_MAP );
    if (res)
    {
        transaction.event.status = res;
        wow64_memory_complete_transaction( &transaction );
        if (needs_close) close( unix_handle );
        return res;
    }
    capture_base = base;
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    res = map_view( &view, base, size, alloc_type, vprot, limit_low, limit_high, 0 );
    if (res) goto done;
#if defined(__APPLE__) && defined(__aarch64__)
    capture_base = view->base;
    allocation_base = view->base;
#endif

    TRACE( "handle=%p size=%lx offset=%s\n", handle, size, wine_dbgstr_longlong(offset.QuadPart) );
    res = map_file_into_view( view, unix_handle, 0, size, offset.QuadPart, vprot, needs_close );
    if (res == STATUS_SUCCESS)
    {
        if (commit_size)
            set_page_vprot_bits( view->base, commit_size, VPROT_COMMITTED, 0 );

        /* file mappings must always be accessible */
        mprotect_range( view->base, view->size, VPROT_COMMITTED, 0 );

        SERVER_START_REQ( map_view )
        {
            req->mapping     = wine_server_obj_handle( handle );
            req->access      = access;
            req->base        = wine_server_client_ptr( view->base );
            req->size        = size;
            req->commit_size = commit_size;
            req->start       = offset.QuadPart;
            res = wine_server_call( req );
        }
        SERVER_END_REQ;
    }
    else ERR( "mapping %p %lx %s failed\n", view->base, size, wine_dbgstr_longlong(offset.QuadPart) );

    if (NT_SUCCESS(res))
    {
        *addr_ptr = view->base;
        *size_ptr = size;
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    else delete_view( view );

done:
#if defined(__APPLE__) && defined(__aarch64__)
    if (capture_base && is_inside_wow64_shadow( capture_base, size ))
        wow64_memory_capture_transaction( &transaction, res, capture_base, size,
                                           allocation_base );
    else
        wow64_memory_capture_transaction( &transaction, res, NULL, 0, NULL );
    arm64ec_code_capture_transaction( &code_transaction, res );
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_complete_transaction( &code_transaction );
    wow64_memory_complete_transaction( &transaction );
#endif
    if (needs_close) close( unix_handle );
    return res;
}


/* allocate some space for the virtual heap, if possible from a reserved area */
static void *alloc_virtual_heap( SIZE_T size )
{
    struct reserved_area *area;
    void *ret;

    size = ROUND_SIZE( 0, size, host_page_mask );

    LIST_FOR_EACH_ENTRY_REV( area, &reserved_areas, struct reserved_area, entry )
    {
        void *base = area->base;
        void *end = (char *)base + area->size;

        if (is_beyond_limit( base, area->size, address_space_limit ))
            address_space_limit = host_addr_space_limit = end;
        if (is_win64 && base < (void *)0x80000000) break;
#if defined(__APPLE__) && defined(__aarch64__)
        if (base < (void *)(WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE) &&
            end > (void *)WINE_LOW_VA_SHADOW_BASE)
        {
            if (end > (void *)(WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE) &&
                (char *)end - (char *)(WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE) >= size)
                base = (void *)(WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE);
            else if (base < (void *)WINE_LOW_VA_SHADOW_BASE &&
                     (char *)WINE_LOW_VA_SHADOW_BASE - (char *)base >= size)
                end = (void *)WINE_LOW_VA_SHADOW_BASE;
            else continue;
        }
#endif
        if (preload_reserve_end >= end)
        {
            if (preload_reserve_start <= base) continue;  /* no space in that area */
            if (preload_reserve_start < end) end = preload_reserve_start;
        }
        else if (preload_reserve_end > base)
        {
            if (preload_reserve_start <= base) base = preload_reserve_end;
            else if ((char *)end - (char *)preload_reserve_end >= size) base = preload_reserve_end;
            else end = preload_reserve_start;
        }
        if ((char *)end - (char *)base < size) continue;
        ret = anon_mmap_fixed( (char *)end - size, size, PROT_READ | PROT_WRITE, 0 );
        if (ret == MAP_FAILED) continue;
        mmap_remove_reserved_area( ret, size );
        return ret;
    }
    return anon_mmap_alloc( size, PROT_READ | PROT_WRITE );
}

/***********************************************************************
 *           virtual_init
 */
void virtual_init(void)
{
    const struct preload_info **preload_info = dlsym( RTLD_DEFAULT, "wine_main_preload_info" );
    const char *preload;
    size_t size;
    int i;
    pthread_mutexattr_t attr;

    pthread_mutexattr_init( &attr );
    pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_RECURSIVE );
    pthread_mutex_init( &virtual_mutex, &attr );
#if defined(__APPLE__) && defined(__aarch64__)
    pthread_mutex_init( &arm64ec_low_memory_observer_mutex, &attr );
    pthread_mutex_init( &arm64ec_code_observer_mutex, &attr );
#endif
    pthread_mutexattr_destroy( &attr );

#ifdef __aarch64__
    host_page_size = sysconf( _SC_PAGESIZE );
    host_page_mask = host_page_size - 1;
    TRACE( "host page size: %uk\n", (UINT)host_page_size / 1024 );
#endif

#ifdef _WIN64
    host_addr_space_limit = get_host_addr_space_limit();
    TRACE( "host addr space limit: %p\n", host_addr_space_limit );
#else
    host_addr_space_limit = address_space_limit;
#endif

    kernel_writewatch_init();

    if (preload_info && *preload_info)
        for (i = 0; (*preload_info)[i].size; i++)
            mmap_add_reserved_area( (*preload_info)[i].addr, (*preload_info)[i].size );

    mmap_init( preload_info ? *preload_info : NULL );

    if ((preload = getenv("WINEPRELOADRESERVE")))
    {
        unsigned long start, end;
        if (sscanf( preload, "%lx-%lx", &start, &end ) == 2)
        {
            preload_reserve_start = ROUND_ADDR( start, host_page_mask );
            preload_reserve_end = (void *)ROUND_SIZE( 0, end, host_page_mask );
            /* some apps start inside the DOS area */
            if (preload_reserve_start)
                address_space_start = min( address_space_start, preload_reserve_start );
        }
        unsetenv( "WINEPRELOADRESERVE" );
    }

#if defined(__APPLE__) && defined(__aarch64__)
    /* Own the translated window before any internal anonymous allocation can
     * consume it.  reserve_area() uses non-overwriting Mach mappings on Darwin
     * and records only holes that this process successfully acquired. */
    reserve_area( (void *)WINE_LOW_VA_SHADOW_BASE,
                  (void *)(WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE) );
    if (mmap_is_in_reserved_area( (void *)WINE_LOW_VA_SHADOW_BASE,
                                  WINE_LOW_VA_SHADOW_SIZE ) != 1)
    {
        ERR( "failed to reserve the translated low-address window %p-%p\n",
             (void *)WINE_LOW_VA_SHADOW_BASE,
             (void *)(WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE) );
        exit(1);
    }
#endif

    /* try to find space in a reserved area for the views and pages protection table */
#ifdef _WIN64
    pages_vprot_size = ((size_t)host_addr_space_limit >> page_shift >> pages_vprot_shift) + 1;
    size = 2 * view_block_size + pages_vprot_size * sizeof(*pages_vprot);
#else
    size = 2 * view_block_size + (1U << (32 - page_shift));
#endif
    view_block_start = alloc_virtual_heap( size );
    assert( view_block_start != MAP_FAILED );
    view_block_end = view_block_start + view_block_size / sizeof(*view_block_start);
    free_ranges = (void *)((char *)view_block_start + view_block_size);
    pages_vprot = (void *)((char *)view_block_start + 2 * view_block_size);
    wine_rb_init( &views_tree, compare_view );

    free_ranges[0].base = (void *)0;
    free_ranges[0].end = (void *)~0;
    free_ranges_end = free_ranges + 1;

    /* make the DOS area accessible (except the low 64K) to hide bugs in broken apps like Excel 2003 */
    size = (char *)address_space_start - (char *)0x10000;
    if (size && mmap_is_in_reserved_area( (void*)0x10000, size ) == 1)
        anon_mmap_fixed( (void *)0x10000, size, PROT_READ | PROT_WRITE, 0 );
}


/***********************************************************************
 *           get_system_affinity_mask
 */
ULONG_PTR get_system_affinity_mask(void)
{
    ULONG num_cpus = peb->NumberOfProcessors;
    if (num_cpus >= sizeof(ULONG_PTR) * 8) return ~(ULONG_PTR)0;
    return ((ULONG_PTR)1 << num_cpus) - 1;
}

/***********************************************************************
 *           get_host_page_size
 */
UINT_PTR get_host_page_size(void)
{
    return host_page_size;
}


/***********************************************************************
 *           virtual_get_system_info
 */
void virtual_get_system_info( SYSTEM_BASIC_INFORMATION *info, BOOL wow64 )
{
#if defined(HAVE_SYSINFO) \
    && defined(HAVE_STRUCT_SYSINFO_TOTALRAM) && defined(HAVE_STRUCT_SYSINFO_MEM_UNIT)
    struct sysinfo sinfo;

    if (!sysinfo(&sinfo))
    {
        ULONG64 total = (ULONG64)sinfo.totalram * sinfo.mem_unit;
        info->MmHighestPhysicalPage = max(1, total / page_size);
    }
#elif defined(__APPLE__)
    /* sysconf(_SC_PHYS_PAGES) is buggy on macOS: in a 32-bit process, it
     * returns an error on Macs with >4GB of RAM.
     */
    INT64 memsize;
    size_t len = sizeof(memsize);

    if (!sysctlbyname( "hw.memsize", &memsize, &len, NULL, 0 ))
        info->MmHighestPhysicalPage = max(1, memsize / page_size);
#elif defined(_SC_PHYS_PAGES)
    LONG64 phys_pages = sysconf( _SC_PHYS_PAGES );

    info->MmHighestPhysicalPage = max(1, phys_pages);
#else
    info->MmHighestPhysicalPage = 0x7fffffff / page_size;
#endif

    info->unknown                 = 0;
    info->KeMaximumIncrement      = 0;  /* FIXME */
    info->PageSize                = page_size;
    info->MmLowestPhysicalPage    = 1;
    info->MmNumberOfPhysicalPages = info->MmHighestPhysicalPage - info->MmLowestPhysicalPage;
    info->AllocationGranularity   = granularity_mask + 1;
    info->LowestUserAddress       = (void *)0x10000;
    info->ActiveProcessorsAffinityMask = get_system_affinity_mask();
    info->NumberOfProcessors      = peb->NumberOfProcessors;
    if (wow64) info->HighestUserAddress = (char *)get_wow_user_space_limit() - 1;
    else info->HighestUserAddress = (char *)user_space_limit - 1;
}


/***********************************************************************
 *           virtual_map_builtin_module
 */
NTSTATUS virtual_map_builtin_module( HANDLE mapping, void **module, SIZE_T *size,
                                     SECTION_IMAGE_INFORMATION *info, ULONG_PTR limit_low,
                                     ULONG_PTR limit_high, WORD machine, BOOL prefer_native,
                                     off_t offset, BOOL translated_wow64,
                                     BOOL translated_amd64_low )
{
    mem_size_t full_size;
    unsigned int sec_flags;
    struct pe_mapping_info *pe_mapping;
    NTSTATUS status;

    if ((status = get_mapping_info( mapping, SECTION_MAP_READ, &sec_flags, &full_size, &pe_mapping )))
        return status;

    if (!pe_mapping) return STATUS_INVALID_PARAMETER;

    *module = NULL;
    *size = 0;

    if (!pe_mapping->image.wine_builtin) /* ignore non-builtins */
    {
        if (!pe_mapping->image.wine_fakedll)
            WARN_(module)( "%s found in WINEDLLPATH but not a builtin, ignoring\n",
                           debugstr_us(&pe_mapping->nt_name) );
        status = STATUS_DLL_NOT_FOUND;
    }
    else if (prefer_native && (pe_mapping->image.dll_charact & IMAGE_DLLCHARACTERISTICS_PREFER_NATIVE))
    {
        TRACE_(module)( "%s has prefer-native flag, ignoring builtin\n",
                        debugstr_us(&pe_mapping->nt_name) );
        status = STATUS_IMAGE_ALREADY_LOADED;
    }
    else
    {
        if (pe_mapping->image.image_flags & IMAGE_FLAGS_ComPlusNativeReady)
            translated_wow64 = FALSE;
        status = virtual_map_image( mapping, module, size, limit_low, limit_high, 0,
                                    pe_mapping, machine, translated_wow64,
                                    translated_amd64_low, TRUE, offset );
        virtual_fill_image_information( &pe_mapping->image, info );
    }

    free_pe_mapping_info( pe_mapping );
    return status;
}


/***********************************************************************
 *           virtual_map_module
 */
NTSTATUS virtual_map_module( HANDLE mapping, void **module, SIZE_T *size, SECTION_IMAGE_INFORMATION *info,
                             ULONG_PTR limit_low, ULONG_PTR limit_high, USHORT machine )
{
    unsigned int status;
    mem_size_t full_size;
    unsigned int sec_flags;
    struct pe_mapping_info *pe_mapping;

    if ((status = get_mapping_info( mapping, SECTION_MAP_READ, &sec_flags, &full_size, &pe_mapping )))
        return status;

    if (!pe_mapping) return STATUS_INVALID_PARAMETER;

    *module = NULL;
    *size = 0;

    /* check if we can replace that mapping with the builtin */
    {
        BOOL translated_wow64 = FALSE;
        BOOL translated_amd64_low = FALSE;

#if defined(__APPLE__) && defined(__aarch64__)
        /* This entry point owns the one pre-PEB main-image bootstrap.  Carry
         * that provenance through builtin replacement rather than inferring
         * translation from the PE machine in the generic image mapper. */
        translated_wow64 = pe_mapping->image.machine == IMAGE_FILE_MACHINE_I386 &&
                            !(pe_mapping->image.image_flags & IMAGE_FLAGS_ComPlusNativeReady);
        translated_amd64_low = current_machine == IMAGE_FILE_MACHINE_ARM64 &&
                               pe_mapping->image.machine == IMAGE_FILE_MACHINE_AMD64;
#endif
        status = load_builtin( pe_mapping, machine, info, module, size, limit_low,
                               limit_high, 0, translated_wow64,
                               translated_amd64_low );
    }
    if (status == STATUS_IMAGE_ALREADY_LOADED)
    {
        BOOL translated_wow64 = FALSE;
        BOOL translated_amd64_low = FALSE;

#if defined(__APPLE__) && defined(__aarch64__)
        /* The main i386 image is mapped before wow_peb exists.  This is the
         * single bootstrap owner; later image mappings require either an
         * established WoW64 process or the private type-31 parameter. */
        translated_wow64 = pe_mapping->image.machine == IMAGE_FILE_MACHINE_I386 &&
                            !(pe_mapping->image.image_flags & IMAGE_FLAGS_ComPlusNativeReady);
        translated_amd64_low = current_machine == IMAGE_FILE_MACHINE_ARM64 &&
                               pe_mapping->image.machine == IMAGE_FILE_MACHINE_AMD64;
#endif
        status = virtual_map_image( mapping, module, size, limit_low, limit_high, 0,
                                    pe_mapping, machine, translated_wow64,
                                    translated_amd64_low, FALSE, 0 );
        virtual_fill_image_information( &pe_mapping->image, info );
    }
    free_pe_mapping_info( pe_mapping );
    return status;
}


/***********************************************************************
 *           virtual_create_builtin_view
 */
NTSTATUS virtual_create_builtin_view( void *module, const UNICODE_STRING *nt_name,
                                      struct pe_image_info *info, void *so_handle )
{
    NTSTATUS status;
    sigset_t sigset;
    IMAGE_DOS_HEADER *dos = module;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)dos + dos->e_lfanew);
    SIZE_T size = info->map_size;
    IMAGE_SECTION_HEADER *sec;
    struct file_view *view;
    void *base = wine_server_get_ptr( info->base );
    int i;
#if defined(__APPLE__) && defined(__aarch64__)
    struct arm64ec_code_transaction code_transaction;

    status = arm64ec_code_begin_transaction( &code_transaction, is_arm64ec(),
                                              WINE_ARM64EC_CODE_MAP );
    if (status) return status;
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    status = create_view( &view, base, size, SEC_IMAGE | SEC_FILE | VPROT_SYSTEM |
                          VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC );
    if (!status)
    {
        TRACE( "created %p-%p for %s\n", base, (char *)base + size, debugstr_us(nt_name) );

        /* The PE header is always read-only, no write, no execute. */
        set_page_vprot( base, page_size, VPROT_COMMITTED | VPROT_READ );

        sec = IMAGE_FIRST_SECTION( nt );
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            BYTE flags = VPROT_COMMITTED;

            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) flags |= VPROT_EXEC;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_READ) flags |= VPROT_READ;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) flags |= VPROT_WRITE;
            set_page_vprot( (char *)base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, flags );
        }

        SERVER_START_REQ( map_builtin_view )
        {
            wine_server_add_data( req, info, sizeof(*info) );
            wine_server_add_data( req, nt_name->Buffer, nt_name->Length );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;

        if (!status)
        {
            add_builtin_module( view->base, so_handle );
            VIRTUAL_DEBUG_DUMP_VIEW( view );
            if (is_beyond_limit( base, size, working_set_limit )) working_set_limit = address_space_limit;
        }
        else delete_view( view );
    }
#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_capture_transaction( &code_transaction, status );
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_complete_transaction( &code_transaction );
#endif

    return status;
}


/***********************************************************************
 *           virtual_relocate_module
 */
NTSTATUS virtual_relocate_module( void *module )
{
    char *ptr = module;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(ptr + ((IMAGE_DOS_HEADER *)module)->e_lfanew);
    IMAGE_DATA_DIRECTORY *relocs;
    IMAGE_BASE_RELOCATION *rel, *end;
    IMAGE_SECTION_HEADER *sec;
    ULONG total_size = ROUND_SIZE( 0, nt->OptionalHeader.SizeOfImage, page_mask );
    ULONG *protect_old, i;
    ULONG_PTR image_base;
    INT_PTR delta;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        image_base = ((const IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase;
    else
        image_base = ((const IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.ImageBase;


    if (!(delta = (ULONG_PTR)module - image_base)) return STATUS_SUCCESS;

    if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    {
        ERR( "Need to relocate module from %p to %p, but relocation records are stripped\n",
             (void *)image_base, module );
        return STATUS_CONFLICTING_ADDRESSES;
    }

    TRACE( "%p -> %p\n", (void *)image_base, module );

    if (!(relocs = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_BASERELOC ))) return STATUS_SUCCESS;

    if (!(protect_old = malloc( nt->FileHeader.NumberOfSections * sizeof(*protect_old ))))
        return STATUS_NO_MEMORY;

    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = (char *)module + sec[i].VirtualAddress;
        SIZE_T size = sec[i].SizeOfRawData;
        NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, PAGE_READWRITE, &protect_old[i] );
    }


    rel = (IMAGE_BASE_RELOCATION *)((char *)module + relocs->VirtualAddress);
    end = (IMAGE_BASE_RELOCATION *)((char *)rel + relocs->Size);

    while (rel && rel < end - 1 && rel->SizeOfBlock && rel->VirtualAddress < total_size)
        rel = process_relocation_block( (char *)module + rel->VirtualAddress, rel, delta );

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = (char *)module + sec[i].VirtualAddress;
        SIZE_T size = sec[i].SizeOfRawData;
        NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, protect_old[i], &protect_old[i] );
    }
    free( protect_old );
    return STATUS_SUCCESS;
}


/* set some initial values in a new TEB */
static TEB *init_teb( void *ptr, BOOL is_wow )
{
    TEB *teb;
    TEB64 *teb64 = ptr;
    TEB32 *teb32 = (TEB32 *)((char *)ptr + teb_offset);

#ifdef _WIN64
    teb = (TEB *)teb64;
    teb32->Peb = wow64_native_to_guest_addr( (char *)peb + page_size );
    teb32->Tib.Self = wow64_native_to_guest_addr( teb32 );
    teb32->Tib.ExceptionList = ~0u;
    teb32->Tib.FiberData = 0x1e00;
    teb32->ActivationContextStackPointer =
        wow64_native_to_guest_addr( &teb32->ActivationContextStack );
    teb32->ActivationContextStack.FrameListCache.Flink =
        teb32->ActivationContextStack.FrameListCache.Blink =
            wow64_native_to_guest_addr( &teb32->ActivationContextStack.FrameListCache );
    teb32->StaticUnicodeString.Buffer = wow64_native_to_guest_addr( teb32->StaticUnicodeBuffer );
    teb32->StaticUnicodeString.MaximumLength = sizeof( teb32->StaticUnicodeBuffer );
    teb32->GdiBatchCount = wow64_native_to_guest_addr( teb64 );
    teb32->WowTebOffset  = -teb_offset;
    if (is_wow) teb64->WowTebOffset = teb_offset;
#else
    teb = (TEB *)teb32;
    teb32->Tib.ExceptionList = ~0u;
    teb32->Tib.FiberData = 0x1e00;
    teb64->Peb = PtrToUlong( (char *)peb - page_size );
    teb64->Tib.Self = PtrToUlong( teb64 );
    teb64->Tib.ExceptionList = PtrToUlong( teb32 );
    teb64->Tib.FiberData = 0x1e00;
    teb64->ActivationContextStackPointer = PtrToUlong( &teb64->ActivationContextStack );
    teb64->ActivationContextStack.FrameListCache.Flink =
        teb64->ActivationContextStack.FrameListCache.Blink =
            PtrToUlong( &teb64->ActivationContextStack.FrameListCache );
    teb64->StaticUnicodeString.Buffer = PtrToUlong( teb64->StaticUnicodeBuffer );
    teb64->StaticUnicodeString.MaximumLength = sizeof( teb64->StaticUnicodeBuffer );
    teb64->WowTebOffset = teb_offset;
    if (is_wow)
    {
        teb32->GdiBatchCount = PtrToUlong( teb64 );
        teb32->WowTebOffset  = -teb_offset;
    }
#endif
    teb->Peb = peb;
    teb->Tib.Self = &teb->Tib;
    teb->Tib.StackBase = (void *)~0ul;
    teb->Tib.FiberData = (void *)0x1e00;
    teb->ActivationContextStackPointer = &teb->ActivationContextStack;
    InitializeListHead( &teb->ActivationContextStack.FrameListCache );
    teb->StaticUnicodeString.Buffer = teb->StaticUnicodeBuffer;
    teb->StaticUnicodeString.MaximumLength = sizeof(teb->StaticUnicodeBuffer);
    return teb;
}


/***********************************************************************
 *           virtual_alloc_first_teb
 */
TEB *virtual_alloc_first_teb(void)
{
    void *ptr;
    TEB *teb;
    unsigned int status;
    SIZE_T data_size = page_size;
    SIZE_T block_size = 4 * page_size;
    SIZE_T total = 32 * block_size;
    struct thread_data *thread_data;

    /*
     * Darwin reserves the low 4 GiB in native arm64 processes.  Keep the
     * Windows-visible KUSER_SHARED_DATA address in the CPU provider, but map
     * the native backing wherever the host can represent it.  PEB.SharedData
     * publishes that backing address to native PE code.
     */
#if defined(__APPLE__) && defined(__aarch64__)
    user_shared_data = (void *)(WINE_LOW_VA_SHADOW_BASE + WINE_USER_SHARED_DATA_ADDRESS);
#endif

    /* reserve space for shared user data */
#if defined(__APPLE__) && defined(__aarch64__)
    status = allocate_wow64_shadow_memory( (void **)&user_shared_data, &data_size,
                                           MEM_RESERVE | MEM_COMMIT, PAGE_READONLY );
#else
    status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&user_shared_data, 0, &data_size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READONLY );
#endif
    if (status)
    {
        ERR( "wine: failed to map the shared user data: %08x\n", status );
        exit(1);
    }

#if defined(__APPLE__) && defined(__aarch64__)
    teb_block = (void *)(WINE_LOW_VA_SHADOW_BASE + 0x70000000);
    status = allocate_wow64_shadow_memory( &teb_block, &total, MEM_RESERVE, PAGE_READWRITE );
#else
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &teb_block, is_win64 ? limit_2g - 1 : 0,
                                      &total, MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
#endif
    if (status)
    {
        ERR( "wine: failed to reserve the initial TEB block: %08x\n", status );
        exit(1);
    }
    teb_block_pos = 30;
    ptr = (char *)teb_block + 30 * block_size;
    data_size = 2 * block_size;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&ptr, 0, &data_size,
                                      MEM_COMMIT, PAGE_READWRITE );
    if (status)
    {
        ERR( "wine: failed to commit the initial TEB block: %08x\n", status );
        exit(1);
    }
    peb = (PEB *)((char *)teb_block + 31 * block_size + (is_win64 ? 0 : page_size));
    peb->SharedData = user_shared_data;
    teb = init_teb( ptr, FALSE );

    thread_data = virtual_alloc_thread_data();
    thread_data->teb = teb;
    list_add_head( &teb_list, &thread_data->entry );
    pthread_key_create( &thread_data_key, NULL );
    pthread_setspecific( thread_data_key, thread_data );
    return teb;
}


/***********************************************************************
 *           virtual_alloc_teb
 */
NTSTATUS virtual_alloc_teb( struct thread_data *data )
{
    sigset_t sigset;
    void *ptr = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T block_size = 4 * page_size;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    struct arm64ec_low_memory_transaction low_transaction;
    sigset_t preview_sigset;
    void *teb_candidate = NULL, *low_begin_address = NULL;
    BOOL exact_low_candidate;
    BOOL new_teb_block = FALSE;
#endif

#if defined(__APPLE__) && defined(__aarch64__)
    /* virtual_alloc_teb() recursively commits its selected slot through
     * NtAllocateVirtualMemory while virtual_mutex is held.  Preview that slot
     * and acquire the LOW observer gate first; otherwise a concurrent LOW/code
     * mutation can own the provider gate while waiting for virtual_mutex and
     * this thread can hold virtual_mutex while waiting for the provider gate.
     * teb_allocator_mutex keeps the preview stable until the slot is consumed,
     * so an exactly matching nested commit can use the outer post-state instead
     * of incorrectly reconciling the complete 4-GiB LOW domain. */
    pthread_mutex_lock( &teb_allocator_mutex );
    server_enter_uninterrupted_section( &virtual_mutex, &preview_sigset );
    if (next_free_teb) teb_candidate = next_free_teb;
    else if (teb_block && teb_block_pos > 0)
        teb_candidate = (char *)teb_block + (teb_block_pos - 1) * block_size;
    server_leave_uninterrupted_section( &virtual_mutex, &preview_sigset );
    exact_low_candidate = get_arm64ec_low_candidate_range(
        teb_candidate, block_size, &low_begin_address );

    status = wow64_memory_begin_transaction( &transaction, is_wow64(),
                                              WINE_WOW64_MEMORY_COMMIT,
                                              NULL, block_size, NULL );
    if (status)
    {
        pthread_mutex_unlock( &teb_allocator_mutex );
        return status;
    }
    status = arm64ec_low_memory_begin_transaction(
        &low_transaction, exact_low_candidate, WINE_WOW64_MEMORY_COMMIT,
        low_begin_address, block_size, NULL );
    if (status)
    {
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        pthread_mutex_unlock( &teb_allocator_mutex );
        return status;
    }
    low_transaction.allow_exact_nested = exact_low_candidate;
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (next_free_teb)
    {
        ptr = next_free_teb;
        next_free_teb = *(void **)ptr;
        memset( ptr, 0, block_size );
    }
    else
    {
        if (!teb_block_pos)
        {
            SIZE_T total = 32 * block_size;

#if defined(__APPLE__) && defined(__aarch64__)
            if (is_wow64())
                status = allocate_wow64_shadow_memory( &ptr, &total, MEM_RESERVE, PAGE_READWRITE );
            else
                status = NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, 0, &total,
                                                  MEM_RESERVE, PAGE_READWRITE );
#else
            status = NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, user_space_wow_limit,
                                              &total, MEM_RESERVE, PAGE_READWRITE );
#endif
            if (status)
            {
                goto done;
            }
            teb_block = ptr;
            teb_block_pos = 32;
#if defined(__APPLE__) && defined(__aarch64__)
            new_teb_block = is_inside_wow64_shadow( ptr, total );
#endif
        }
        ptr = ((char *)teb_block + --teb_block_pos * block_size);
        status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&ptr, 0, &block_size,
                                          MEM_COMMIT, PAGE_READWRITE );
        if (status) goto done;
    }
    data->teb = init_teb( ptr, is_wow64() );
    list_add_head( &teb_list, &data->entry );

    if ((status = signal_alloc_thread( data->teb )))
    {
        *(void **)ptr = next_free_teb;
        next_free_teb = ptr;
    }
done:
#if defined(__APPLE__) && defined(__aarch64__)
    if (ptr)
    {
        struct file_view *view = NULL, *low_view = NULL;
        void *low_capture_address = NULL;
        BOOL low_capture_candidate = get_arm64ec_low_candidate_range(
            ptr, block_size, &low_capture_address );

        if (is_inside_wow64_shadow( ptr, block_size ))
            view = find_view( ptr, block_size );
        if (low_capture_candidate)
            low_view = find_view( low_capture_address, block_size );

        /* Reserving a fresh TEB arena is nested under this transaction.  The
         * committed TEB is only one slice of that mutation, so publish the
         * complete tagged allocation rather than leaving the remaining arena
         * falsely described as free. */
        if (view && (view->protect & VPROT_WOW64_TRANSLATED))
            wow64_memory_capture_transaction( &transaction, status,
                                               new_teb_block ? view->base : ptr,
                                               new_teb_block ? view->size : block_size,
                                               view->base );
        else
            wow64_memory_capture_transaction( &transaction, status, NULL, 0, NULL );
        if (low_capture_candidate &&
            low_view && (low_view->protect & VPROT_AMD64_LOW_TRANSLATED))
            arm64ec_low_memory_capture_transaction(
                &low_transaction, status,
                low_capture_address, block_size, low_view->base );
        else if (low_capture_candidate)
            arm64ec_low_memory_capture_transaction(
                &low_transaction, status, low_capture_address, block_size, NULL );
        else
            arm64ec_low_memory_capture_transaction( &low_transaction, status, NULL, 0, NULL );
    }
    else
    {
        wow64_memory_capture_transaction( &transaction, status, NULL, 0, NULL );
        arm64ec_low_memory_capture_transaction(
            &low_transaction, status, NULL, 0, NULL );
    }
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_low_memory_complete_transaction( &low_transaction );
    wow64_memory_complete_transaction( &transaction );
    pthread_mutex_unlock( &teb_allocator_mutex );
#endif
    return status;
}


/***********************************************************************
 *           virtual_alloc_thread_data
 */
struct thread_data *virtual_alloc_thread_data(void)
{
    NTSTATUS status;
    sigset_t sigset;
    struct file_view *view;
    struct thread_data *data = NULL;
    SIZE_T size = signal_stack_mask + 1 + kernel_stack_size;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    status = map_view( &view, NULL, size, 0, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED,
                       WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE, 0, 0 );
#else
    status = map_view( &view, NULL, size, 0, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED,
                       limit_4g, 0, 0 );
#endif
    if (!status)
    {
        data = view->base;
        data->request_fd = -1;
        data->reply_fd   = -1;
        data->wait_fd[0] = -1;
        data->wait_fd[1] = -1;
        data->alert_fd   = -1;
#ifdef VALGRIND_STACK_REGISTER
        VALGRIND_STACK_REGISTER( (char *)data + signal_stack_mask + 1, (char *)data + view->size );
#endif
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return data;
}


/***********************************************************************
 *           virtual_free_thread_data
 */
void virtual_free_thread_data( struct thread_data *data )
{
    TEB *teb;
    void *ptr;
    SIZE_T size;
    sigset_t sigset;
    WOW_TEB *wow_teb;

    if (!(teb = data->teb)) goto done;

    if (teb->DeallocationStack)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &teb->DeallocationStack, &size, MEM_RELEASE );
    }
#ifdef __aarch64__
    if (teb->ChpeV2CpuAreaInfo)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), (void **)&teb->ChpeV2CpuAreaInfo, &size, MEM_RELEASE );
    }
#endif
    if ((wow_teb = get_wow_teb( teb )) &&
        (ptr = wow64_guest_to_native_ptr( wow_teb->DeallocationStack )))
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &ptr, &size, MEM_RELEASE );
    }

#if defined(__APPLE__) && defined(__aarch64__)
    pthread_mutex_lock( &teb_allocator_mutex );
#endif
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    signal_free_thread( teb );
    list_remove( &data->entry );
    ptr = teb;
    if (!is_win64) ptr = (char *)ptr - teb_offset;
    *(void **)ptr = next_free_teb;
    next_free_teb = ptr;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    pthread_mutex_unlock( &teb_allocator_mutex );
#endif

 done:
    if (data->native_guard_stack)
    {
        size = 0;
        ptr = data->native_guard_stack;
        NtFreeVirtualMemory( GetCurrentProcess(), &ptr, &size, MEM_RELEASE );
        data->native_guard_stack = NULL;
    }
    size = 0;
    ptr = data;
    NtFreeVirtualMemory( GetCurrentProcess(), &ptr, &size, MEM_RELEASE );
}


/* LDT support */

#if defined(__i386__) || defined(__x86_64__)

struct ldt_copy
{
    unsigned int    base[LDT_SIZE];
    struct ldt_bits bits[LDT_SIZE];
};
C_ASSERT( sizeof(struct ldt_copy) == 8 * LDT_SIZE );

static struct ldt_copy *ldt_copy;

UINT ldt_bitmap[LDT_SIZE / 32] = { ~0u };

/***********************************************************************
 *           ldt_update_entry
 */
WORD ldt_update_entry( WORD sel, LDT_ENTRY entry )
{
    unsigned int index = sel >> 3;

    if (!ldt_copy)
    {
        struct file_view *view;

        if (map_view( &view, NULL, sizeof(*ldt_copy), MEM_TOP_DOWN,
                      VPROT_COMMITTED | VPROT_READ | VPROT_WRITE,
                      is_win64 ? limit_2g : 0, limit_4g, 0 )) return 0;
        ldt_copy = view->base;
        if (is_win64) wow_peb->SpareUlongs[0] = PtrToUlong( ldt_copy );
        else peb->SpareUlongs[0] = PtrToUlong( ldt_copy );
    }

    ldt_set_entry( sel, entry );
    ldt_copy->base[index]             = ldt_get_base( entry );
    ldt_copy->bits[index].limit       = entry.LimitLow | (entry.HighWord.Bits.LimitHi << 16);
    ldt_copy->bits[index].type        = entry.HighWord.Bits.Type;
    ldt_copy->bits[index].granularity = entry.HighWord.Bits.Granularity;
    ldt_copy->bits[index].default_big = entry.HighWord.Bits.Default_Big;
    ldt_bitmap[index / 32] |= 1u << (index & 31);
    return sel;
}

/***********************************************************************
 *           ldt_get_entry
 */
NTSTATUS ldt_get_entry( WORD sel, CLIENT_ID client_id, LDT_ENTRY *entry )
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int base = 0;
    struct ldt_bits bits = { 0 };
    unsigned int idx = sel >> 3;

    if (HandleToULong(client_id.UniqueProcess) == pid)
    {
        if (ldt_copy)
        {
            base = ldt_copy->base[idx];
            bits = ldt_copy->bits[idx];
        }
    }
    else
    {
        HANDLE process;
        ULONG ptr = 0;
        PEB32 *peb32 = NULL;

        if ((status = NtOpenProcess( &process, PROCESS_ALL_ACCESS, NULL, &client_id ))) return status;

        if (!is_win64)
        {
            PROCESS_BASIC_INFORMATION pbi;

            NtQueryInformationProcess( process, ProcessBasicInformation, &pbi, sizeof(pbi), NULL );
            peb32 = (PEB32 *)pbi.PebBaseAddress;
        }
        else NtQueryInformationProcess( process, ProcessWow64Information, &peb32, sizeof(peb32), NULL );

        if (!NtReadVirtualMemory( process, &peb32->SpareUlongs[0], &ptr, sizeof(ptr), NULL ) && ptr)
        {
            struct ldt_copy *ldt = ULongToPtr( ptr );
            NtReadVirtualMemory( process, &ldt->base[idx], &base, sizeof(base), NULL );
            NtReadVirtualMemory( process, &ldt->bits[idx], &bits, sizeof(bits), NULL );
        }
        NtClose( process );
    }

    if (base || bits.limit || bits.type) *entry = ldt_make_entry( base, bits );
    else status = STATUS_UNSUCCESSFUL;

    return status;
}

/******************************************************************************
 *           NtSetLdtEntries   (NTDLL.@)
 *           ZwSetLdtEntries   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetLdtEntries( ULONG sel1, ULONG entry1_low, ULONG entry1_high, ULONG sel2, ULONG entry2_low, ULONG entry2_high )
{
    sigset_t sigset;
    union { LDT_ENTRY entry; ULONG ul[2]; } entry;

    if (is_win64 && !is_wow64()) return STATUS_NOT_IMPLEMENTED;
    if (sel1 >> 16 || sel2 >> 16) return STATUS_INVALID_LDT_DESCRIPTOR;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (sel1)
    {
        entry.ul[0] = entry1_low;
        entry.ul[1] = entry1_high;
        ldt_update_entry( sel1, entry.entry );
    }
    if (sel2)
    {
        entry.ul[0] = entry2_low;
        entry.ul[1] = entry2_high;
        ldt_update_entry( sel2, entry.entry );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return STATUS_SUCCESS;
}

#else /* defined(__i386__) || defined(__x86_64__) */

/******************************************************************************
 *           NtSetLdtEntries   (NTDLL.@)
 *           ZwSetLdtEntries   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetLdtEntries( ULONG sel1, ULONG entry1_low, ULONG entry1_high, ULONG sel2, ULONG entry2_low, ULONG entry2_high )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif /* defined(__i386__) || defined(__x86_64__) */


/***********************************************************************
 *           virtual_clear_tls_index
 */
NTSTATUS virtual_clear_tls_index( ULONG index )
{
    struct thread_data *data;
    sigset_t sigset;

    if (index < TLS_MINIMUM_AVAILABLE)
    {
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        LIST_FOR_EACH_ENTRY( data, &teb_list, struct thread_data, entry )
        {
            TEB *teb = data->teb;
#ifdef _WIN64
            WOW_TEB *wow_teb = get_wow_teb( teb );
            if (wow_teb) wow_teb->TlsSlots[index] = 0;
            else
#endif
            teb->TlsSlots[index] = 0;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    }
    else
    {
        index -= TLS_MINIMUM_AVAILABLE;
        if (index >= 8 * sizeof(peb->TlsExpansionBitmapBits)) return STATUS_INVALID_PARAMETER;

        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        LIST_FOR_EACH_ENTRY( data, &teb_list, struct thread_data, entry )
        {
            TEB *teb = data->teb;
#ifdef _WIN64
            WOW_TEB *wow_teb = get_wow_teb( teb );
            if (wow_teb)
            {
                if (wow_teb->TlsExpansionSlots)
                    ((ULONG *)wow64_guest_to_native_ptr( wow_teb->TlsExpansionSlots ))[index] = 0;
            }
            else
#endif
            if (teb->TlsExpansionSlots) teb->TlsExpansionSlots[index] = 0;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           virtual_alloc_thread_stack
 */
NTSTATUS virtual_alloc_thread_stack( INITIAL_TEB *stack, ULONG_PTR limit_low, ULONG_PTR limit_high,
                                     SIZE_T reserve_size, SIZE_T commit_size, BOOL guard_page )
{
    struct file_view *view;
    NTSTATUS status;
    sigset_t sigset;
    SIZE_T size;
    SIZE_T stack_page_size = host_page_size;
    unsigned int vprot = VPROT_READ | VPROT_WRITE | VPROT_COMMITTED;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    void *capture_base = NULL;
#endif

    if (!reserve_size) reserve_size = main_image_info.MaximumStackSize;
    if (!commit_size) commit_size = main_image_info.CommittedStackSize;

    size = max( reserve_size, commit_size );
    if (size < 1024 * 1024) size = 1024 * 1024;  /* Xlib needs a large stack */
    size = ROUND_SIZE( 0, size, granularity_mask );

#if defined(__APPLE__) && defined(__aarch64__)
    if (limits_are_inside_wow64_shadow( limit_low, limit_high ))
    {
        vprot |= VPROT_WOW64_TRANSLATED;
        stack_page_size = page_size;
    }
    status = wow64_memory_begin_transaction(
        &transaction, !!(vprot & VPROT_WOW64_TRANSLATED),
        WINE_WOW64_MEMORY_ALLOCATE, NULL, size, NULL );
    if (status) return status;
#endif
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    status = map_view( &view, NULL, size, 0, vprot, limit_low, limit_high, 0 );
    if (status != STATUS_SUCCESS) goto done;
#if defined(__APPLE__) && defined(__aarch64__)
    view->wine_stack = guard_page && !(vprot & VPROT_WOW64_TRANSLATED);
    view->stack_commit_size = commit_size;
    capture_base = view->base;
#endif

#ifdef VALGRIND_STACK_REGISTER
    VALGRIND_STACK_REGISTER( view->base, (char *)view->base + view->size );
#endif

    /* setup no access guard page */
    if (guard_page)
    {
        set_page_vprot( view->base, stack_page_size, 0 );
        set_page_vprot( (char *)view->base + stack_page_size, stack_page_size,
                        VPROT_READ | VPROT_WRITE | VPROT_COMMITTED | VPROT_GUARD );
        mprotect_range( view->base, 2 * stack_page_size, 0, 0 );
    }
    VIRTUAL_DEBUG_DUMP_VIEW( view );

    /* note: limit is lower than base since the stack grows down */
    stack->OldStackBase = 0;
    stack->OldStackLimit = 0;
    stack->DeallocationStack = view->base;
    stack->StackBase = (char *)view->base + view->size;
    stack->StackLimit = (char *)view->base + (guard_page ? 2 * stack_page_size : 0);
done:
#if defined(__APPLE__) && defined(__aarch64__)
    if (capture_base)
        wow64_memory_capture_transaction( &transaction, status, capture_base, size,
                                           capture_base );
    else
        wow64_memory_capture_transaction( &transaction, status, NULL, 0, NULL );
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    wow64_memory_complete_transaction( &transaction );
#endif
    return status;
}


static const WCHAR shared_data_nameW[] = {'\\','K','e','r','n','e','l','O','b','j','e','c','t','s',
                                          '\\','_','_','w','i','n','e','_','u','s','e','r','_','s','h','a','r','e','d','_','d','a','t','a',0};

/***********************************************************************
 *           virtual_map_user_shared_data
 */
void virtual_map_user_shared_data(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    unsigned int status;
    HANDLE section;
    int res, fd, needs_close;

    if ((status = NtOpenSection( &section, SECTION_ALL_ACCESS, &attr )))
    {
        ERR( "failed to open the USD section: %08x\n", status );
        exit(1);
    }
    if ((res = server_get_unix_fd( section, 0, &fd, &needs_close, NULL, NULL )) ||
        (user_shared_data != mmap( user_shared_data, page_size, PROT_READ, MAP_SHARED|MAP_FIXED, fd, 0 )))
    {
        ERR( "failed to remap the process USD: %d\n", res );
        exit(1);
    }
    if (needs_close) close( fd );
    NtClose( section );
}


/******************************************************************
 *		virtual_init_user_shared_data
 *
 * Initialize user shared data before running wineboot.
 */
void virtual_init_user_shared_data(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    SYSTEM_BASIC_INFORMATION info;
    KUSER_SHARED_DATA *data;
    unsigned int status;
    HANDLE section;
    int res, fd, needs_close;

    if ((status = NtOpenSection( &section, SECTION_ALL_ACCESS, &attr )))
    {
        ERR( "failed to open the USD section: %08x\n", status );
        exit(1);
    }
    if ((res = server_get_unix_fd( section, 0, &fd, &needs_close, NULL, NULL )) ||
        (data = mmap( NULL, sizeof(*data), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 )) == MAP_FAILED)
    {
        ERR( "failed to remap the process USD: %d\n", res );
        exit(1);
    }
    if (needs_close) close( fd );
    NtClose( section );

    virtual_get_system_info( &info, FALSE );

    data->TickCountMultiplier   = 1 << 24;
    data->LargePageMinimum      = 2 * 1024 * 1024;
    data->SystemCall            = 1;
    data->NumberOfPhysicalPages = info.MmNumberOfPhysicalPages;
    data->NXSupportPolicy       = NX_SUPPORT_POLICY_OPTIN;
    data->ActiveProcessorCount  = peb->NumberOfProcessors;
    data->ActiveGroupCount      = 1;

    switch (native_machine)
    {
    case IMAGE_FILE_MACHINE_I386:  data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL; break;
    case IMAGE_FILE_MACHINE_AMD64: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64; break;
    case IMAGE_FILE_MACHINE_ARMNT: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM; break;
    case IMAGE_FILE_MACHINE_ARM64: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64; break;
    }

    init_shared_data_cpuinfo( data );
    munmap( data, sizeof(*data) );
}


struct thread_stack_info
{
    char  *start;
    char  *limit;
    char  *end;
    SIZE_T guaranteed;
    BOOL   is_wow;
};

/***********************************************************************
 *           is_inside_thread_stack
 */
static BOOL is_inside_thread_stack( struct thread_data *data, void *ptr, struct thread_stack_info *stack )
{
    TEB *teb;
    WOW_TEB *wow_teb;
    size_t min_guaranteed;

    if (!(teb = data->teb)) return FALSE;
    min_guaranteed = max( page_size * (is_win64 ? 2 : 1), host_page_size );
    stack->start = teb->DeallocationStack;
    stack->limit = teb->Tib.StackLimit;
    stack->end   = teb->Tib.StackBase;
    stack->guaranteed = max( teb->GuaranteedStackBytes, min_guaranteed );
    stack->is_wow = FALSE;
    if ((char *)ptr > stack->start && (char *)ptr <= stack->end) return TRUE;

    if (!(wow_teb = get_wow_teb( teb ))) return FALSE;
    stack->start = wow64_guest_to_native_ptr( wow_teb->DeallocationStack );
    stack->limit = wow64_guest_to_native_ptr( wow_teb->Tib.StackLimit );
    stack->end   = wow64_guest_to_native_ptr( wow_teb->Tib.StackBase );
    /* The paired WoW TEB describes an i386 stack even though native ntdll is
     * 64-bit.  Its Windows minimum guarantee is therefore one guest page. */
    min_guaranteed = page_size;
    stack->guaranteed = max( wow_teb->GuaranteedStackBytes, min_guaranteed );
    stack->is_wow = TRUE;
    return ((char *)ptr > stack->start && (char *)ptr <= stack->end);
}


/***********************************************************************
 *           grow_thread_stack
 */
static NTSTATUS grow_thread_stack( struct thread_data *data, char *page,
                                   struct thread_stack_info *stack_info )
{
    BYTE old_vprot[VPROT_STACK_SNAPSHOT_PAGES];
    SIZE_T stack_page_size = stack_info->is_wow ? page_size : host_page_size;
    SIZE_T guaranteed;
    char *lower_page;
    size_t i, snapshot_size, snapshot_pages;
    BOOL overflow = FALSE;
#if defined(__APPLE__) && defined(__aarch64__)
    struct file_view *stack_view = find_view( stack_info->start, 1 );
    if (arm64ec_stack_probe_enabled && stack_view && stack_view->stack_owner == data)
        stack_page_size = page_size;
#endif
    guaranteed = ROUND_SIZE( 0, stack_info->guaranteed, stack_page_size - 1 );

    if (page >= stack_info->start + stack_page_size + guaranteed)
    {
        lower_page = page - stack_page_size;
        snapshot_size = 2 * stack_page_size;
        snapshot_pages = snapshot_size >> page_shift;
        if (snapshot_pages > ARRAY_SIZE(old_vprot)) return STATUS_ACCESS_DENIED;
        for (i = 0; i < snapshot_pages; i++)
            old_vprot[i] = get_page_vprot( lower_page + i * page_size );

        /* Establish the new guard physically before publishing it.  This is
         * particularly important for two 4K WoW lanes sharing one 16K host
         * page: the second projection must see the staged lower-lane guard. */
        if (mprotect_range( lower_page, stack_page_size,
                            VPROT_COMMITTED | VPROT_GUARD, 0 ))
        {
            restore_vprot_or_abort( lower_page, snapshot_size, old_vprot );
            return STATUS_ACCESS_DENIED;
        }
        set_page_vprot_bits( lower_page, stack_page_size,
                             VPROT_COMMITTED | VPROT_GUARD, 0 );

        if (mprotect_range( page, stack_page_size,
                            VPROT_COMMITTED, VPROT_GUARD ))
        {
            restore_vprot_or_abort( lower_page, snapshot_size, old_vprot );
            return STATUS_ACCESS_DENIED;
        }
        set_page_vprot_bits( page, stack_page_size, VPROT_COMMITTED, VPROT_GUARD );
    }
    else  /* inside guaranteed space -> overflow exception */
    {
        overflow = TRUE;
        page = stack_info->start + stack_page_size;
        if (mprotect_range( page, guaranteed, VPROT_COMMITTED, VPROT_GUARD ))
        {
            /* The failed domain walk may already have changed earlier host
             * pages.  Logical metadata is still exact, so re-project it. */
            if (mprotect_range( page, guaranteed, 0, 0 ))
                abort_process( STATUS_ACCESS_DENIED );
            return STATUS_ACCESS_DENIED;
        }
        set_page_vprot_bits( page, guaranteed, VPROT_COMMITTED, VPROT_GUARD );
    }
    if (stack_info->is_wow)
    {
        WOW_TEB *wow_teb = get_wow_teb( data->teb );
        wow_teb->Tib.StackLimit = wow64_native_to_guest_addr( page );
    }
    else data->teb->Tib.StackLimit = page;
    return overflow ? STATUS_STACK_OVERFLOW : STATUS_SUCCESS;
}


int32_t __wine_resolve_wow64_memory_fault_v1(
    uint64_t host_address, uint32_t access_type,
    struct wine_wow64_memory_fault_result_v1 *result )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    struct thread_stack_info stack_info;
    struct thread_data *data = get_thread_data();
    struct file_view *view;
    char *logical_page, *host_page;
    void *allocation_base = NULL;
    NTSTATUS bridge_status = STATUS_SUCCESS;
    NTSTATUS status, snapshot_status;
    BYTE vprot, host_vprot;
    sigset_t sigset;

    if (!result || result->version != WINE_WOW64_MEMORY_FAULT_VERSION ||
        result->size < sizeof(*result))
        return STATUS_INVALID_PARAMETER;
    memset( result, 0, sizeof(*result) );
    result->version = WINE_WOW64_MEMORY_FAULT_VERSION;
    result->size = sizeof(*result);
    result->action = WINE_WOW64_MEMORY_FAULT_RAISE;
    result->status = STATUS_ACCESS_VIOLATION;
    result->parameter_count = 2;
    result->information[0] = access_type;
    result->information[1] = host_address;

    if (!data || !is_wow64() || !wow64_memory_observer_is_required() ||
        (access_type != WINE_WOW64_MEMORY_FAULT_READ &&
         access_type != WINE_WOW64_MEMORY_FAULT_WRITE &&
         access_type != WINE_WOW64_MEMORY_FAULT_EXECUTE) ||
        !is_wow64_shadow_address( (void *)(ULONG_PTR)host_address ))
        return STATUS_INVALID_PARAMETER;

    logical_page = ROUND_ADDR( (void *)(ULONG_PTR)host_address, page_mask );
    host_page = ROUND_ADDR( logical_page, host_page_mask );
    status = wow64_memory_begin_transaction( &transaction, TRUE,
                                              WINE_WOW64_MEMORY_PROTECT,
                                              logical_page, page_size, NULL );
    if (status) return status;
    if (!transaction.observer_begun || transaction.nested)
    {
        wow64_memory_complete_transaction( &transaction );
        return STATUS_INVALID_DEVICE_STATE;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = find_view( logical_page, page_size );
    if (!view || !(view->protect & VPROT_WOW64_TRANSLATED))
    {
        /* The fixed begin coverage must still be reconciled when the fault is
         * genuinely free or belongs to an untagged view.  The snapshot emits
         * MEM_FREE without the translated flag; address alone never proves
         * provider ownership. */
        wow64_memory_capture_transaction( &transaction, result->status,
                                           logical_page, page_size, NULL );
        goto done;
    }
    allocation_base = view->base;

    /* A shared SEC_RESERVE view may have been committed through another view
     * since its local VPROT cache was populated.  This normal-context fault is
     * the synchronization point: refresh the logical page while a transaction
     * is active so the observer sees the authoritative committed state. */
    vprot = get_page_vprot( logical_page );
    if (view->protect & SEC_RESERVE)
    {
        BYTE committed_vprot;

        if (get_committed_size( view, logical_page, page_size,
                                &committed_vprot, VPROT_COMMITTED ))
            vprot = get_page_vprot( logical_page );
    }

    if ((vprot & (VPROT_COMMITTED | VPROT_GUARD)) ==
        (VPROT_COMMITTED | VPROT_GUARD))
    {
        if (is_inside_thread_stack( data, logical_page, &stack_info ) && stack_info.is_wow)
        {
            ULONG_PTR view_start = (ULONG_PTR)view->base;
            ULONG_PTR view_end;
            ULONG_PTR stack_start = (ULONG_PTR)stack_info.start;
            ULONG_PTR stack_end = (ULONG_PTR)stack_info.end;
            ULONG_PTR page_start = (ULONG_PTR)logical_page;
            ULONG_PTR capture_start, capture_end;
            SIZE_T guaranteed_size;

            if (view->size > ~(ULONG_PTR)0 - view_start)
            {
                bridge_status = STATUS_INVALID_ADDRESS;
                wow64_memory_capture_transaction( &transaction, bridge_status,
                                                   logical_page, page_size,
                                                   allocation_base );
                goto done;
            }
            view_end = view_start + view->size;
            guaranteed_size = ROUND_SIZE( 0, stack_info.guaranteed, page_mask );
            if (!guaranteed_size || stack_start != view_start || stack_end <= stack_start ||
                stack_end > view_end || stack_end - stack_start < page_size ||
                page_start < stack_start + page_size ||
                page_start > stack_end - page_size ||
                guaranteed_size > stack_end - stack_start - page_size ||
                (ULONG_PTR)stack_info.limit < stack_start + page_size ||
                (ULONG_PTR)stack_info.limit > stack_end)
            {
                bridge_status = STATUS_INVALID_ADDRESS;
                wow64_memory_capture_transaction( &transaction, bridge_status,
                                                   logical_page, page_size,
                                                   allocation_base );
                goto done;
            }

            if (page_start >= stack_start + page_size + guaranteed_size)
            {
                capture_start = page_start - page_size;
                capture_end = page_start + page_size;
            }
            else
            {
                capture_start = stack_start + page_size;
                capture_end = capture_start + guaranteed_size;
                if (capture_end < page_start + page_size)
                    capture_end = page_start + page_size;
            }
            status = grow_thread_stack( data, logical_page, &stack_info );
            if (status == STATUS_STACK_OVERFLOW)
            {
                result->status = status;
                result->parameter_count = 0;
                memset( result->information, 0, sizeof(result->information) );
            }
            else if (status == STATUS_SUCCESS)
            {
                result->action = WINE_WOW64_MEMORY_FAULT_RETRY;
                result->status = STATUS_SUCCESS;
                result->parameter_count = 0;
                memset( result->information, 0, sizeof(result->information) );
            }
            else if (status == STATUS_ACCESS_DENIED)
            {
                result->status = STATUS_ACCESS_DENIED;
                bridge_status = STATUS_ACCESS_DENIED;
            }
            else bridge_status = status;
            wow64_memory_capture_transaction( &transaction, status,
                                               (void *)capture_start,
                                               capture_end - capture_start,
                                               allocation_base );
            goto done;
        }

        if (mprotect_range( logical_page, page_size, 0, VPROT_GUARD ))
            bridge_status = STATUS_ACCESS_DENIED;
        else
            set_page_vprot_bits( logical_page, page_size, 0, VPROT_GUARD );
        result->status = STATUS_GUARD_PAGE_VIOLATION;
        wow64_memory_capture_transaction( &transaction, result->status,
                                           logical_page, page_size, allocation_base );
        goto done;
    }

    host_vprot = get_translated_host_page_vprot( host_page );
    if (access_type == WINE_WOW64_MEMORY_FAULT_WRITE &&
        (vprot & VPROT_COMMITTED) && (vprot & (VPROT_WRITE | VPROT_WRITECOPY)) &&
        ((wow64_memory_logical_write_fault_is_delegated() && (vprot & VPROT_WRITEWATCH)) ||
         (!wow64_memory_logical_write_fault_is_delegated() &&
          (host_vprot & VPROT_WRITEWATCH))))
    {
        if (enable_write_exceptions && (vprot & (VPROT_EXEC | VPROT_WRITEWATCH)) ==
            (VPROT_EXEC | VPROT_WRITEWATCH) && !data->allow_writes)
        {
            result->status = STATUS_IN_PAGE_ERROR;
            result->parameter_count = 3;
            result->information[2] = STATUS_EXECUTABLE_MEMORY_WRITE;
        }
        else
        {
            void *clear_base = host_page;
            SIZE_T clear_size = host_page_size;

            /* A capability-negotiated provider enforces this private bit at
             * guest 4K granularity, so disarm only the faulting lane.  The
             * pre-registration fallback retains physical host-page behavior. */
            if (wow64_memory_logical_write_fault_is_delegated())
            {
                clear_base = logical_page;
                clear_size = page_size;
            }
            /* Match the projected physical delta to the metadata clear range;
             * the domain walk preserves a short translated tail's owner. */
            if (mprotect_range( clear_base, clear_size, 0, VPROT_WRITEWATCH ))
                bridge_status = STATUS_ACCESS_DENIED;
            else
                set_page_vprot_bits( clear_base, clear_size, 0, VPROT_WRITEWATCH );
            result->action = WINE_WOW64_MEMORY_FAULT_RETRY;
            result->status = STATUS_SUCCESS;
            result->parameter_count = 0;
            memset( result->information, 0, sizeof(result->information) );

            wow64_memory_capture_transaction( &transaction, result->status,
                                               clear_base, clear_size,
                                               allocation_base );
            goto done;
        }
    }
    else if ((vprot & VPROT_COMMITTED) &&
             ((access_type == WINE_WOW64_MEMORY_FAULT_READ &&
               (get_unix_prot( vprot ) & PROT_READ)) ||
              (access_type == WINE_WOW64_MEMORY_FAULT_WRITE &&
               (get_unix_prot( vprot & ~VPROT_WRITEWATCH ) & PROT_WRITE)) ||
              (access_type == WINE_WOW64_MEMORY_FAULT_EXECUTE && (vprot & VPROT_EXEC))))
    {
        result->action = WINE_WOW64_MEMORY_FAULT_RETRY;
        result->status = STATUS_SUCCESS;
        result->parameter_count = 0;
        memset( result->information, 0, sizeof(result->information) );
    }
    wow64_memory_capture_transaction( &transaction, result->status,
                                       logical_page, page_size, allocation_base );

done:
    snapshot_status = transaction.event.snapshot_status;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    wow64_memory_complete_transaction( &transaction );
    if (bridge_status) return bridge_status;
    return snapshot_status;
#else
    (void)host_address;
    (void)access_type;
    (void)result;
    return STATUS_NOT_SUPPORTED;
#endif
}


#if defined(__APPLE__) && defined(__aarch64__)
/* A low AMD64 operand belongs to the low-memory observer, not to the identity
 * code observer. Consume only the faulting logical guard and publish its new
 * state before resuming engines. Keep the exception address in guest space. */
static NTSTATUS resolve_arm64ec_low_guard( ULONG_PTR address,
                                           struct wine_wow64_memory_fault_result_v1 *result )
{
    struct arm64ec_low_memory_transaction transaction;
    struct file_view *view;
    void *page = (void *)(WINE_LOW_VA_SHADOW_BASE + (address & ~page_mask));
    void *allocation_base = NULL;
    BYTE vprot;
    NTSTATUS status;
    sigset_t sigset;

    if (!address || !arm64ec_low_memory_observer_is_required()) return STATUS_NOT_SUPPORTED;
    status = arm64ec_low_memory_begin_transaction( &transaction, TRUE,
                                                  WINE_WOW64_MEMORY_PROTECT,
                                                  page, page_size, NULL );
    if (status) return status;
    if (!transaction.observer_begun || transaction.nested)
    {
        arm64ec_low_memory_complete_transaction( &transaction );
        return STATUS_INVALID_DEVICE_STATE;
    }
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = find_view( page, page_size );
    if (!view || !(view->protect & VPROT_AMD64_LOW_TRANSLATED) ||
        (view->protect & VPROT_SYSTEM)) goto done;
    allocation_base = view->base;
    vprot = get_page_vprot( page );
    if ((vprot & (VPROT_COMMITTED | VPROT_GUARD)) != (VPROT_COMMITTED | VPROT_GUARD))
        goto done;
    if (mprotect_range( page, page_size, 0, VPROT_GUARD ))
    {
        status = STATUS_ACCESS_DENIED;
        goto done;
    }
    set_page_vprot_bits( page, page_size, 0, VPROT_GUARD );
    result->status = STATUS_GUARD_PAGE_VIOLATION;
 done:
    arm64ec_low_memory_capture_transaction( &transaction, status, page, page_size, allocation_base );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    arm64ec_low_memory_complete_transaction( &transaction );
    return status;
}
#endif


/* Resolve an emulated AMD64 identity fault outside signal context. Reuse the
 * native VM ownership and stack growth policy while the registered code
 * observer excludes every guest engine. Publication completes before that
 * observer releases its mutation gate. The WoW64 shadow contract is separate. */
int32_t __wine_resolve_arm64ec_memory_fault_v1(
    uint64_t address, uint32_t access_type,
    struct wine_wow64_memory_fault_result_v1 *result, void *context,
    int32_t (*publish)( void *, uint64_t, uint64_t, uint64_t, uint32_t ) )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct arm64ec_code_transaction transaction;
    struct thread_data *data = get_thread_data();
    struct thread_stack_info stack_info;
    struct file_view *view;
    char *page, *capture_start = NULL, *capture_end = NULL, *cursor;
    SIZE_T size;
    BYTE vprot;
    NTSTATUS status;
    sigset_t sigset;

    if (!result || result->version != WINE_WOW64_MEMORY_FAULT_VERSION ||
        result->size < sizeof(*result) || !publish || !data || !is_arm64ec() ||
        !arm64ec_code_observer_is_required() ||
        address >= (uint64_t)(ULONG_PTR)host_addr_space_limit ||
        is_wow64_shadow_address( (void *)(ULONG_PTR)address ) ||
        (access_type != EXCEPTION_READ_FAULT && access_type != EXCEPTION_WRITE_FAULT &&
         access_type != EXCEPTION_EXECUTE_FAULT))
        return STATUS_NOT_SUPPORTED;
    memset( result, 0, sizeof(*result) );
    result->version = WINE_WOW64_MEMORY_FAULT_VERSION;
    result->size = sizeof(*result);
    result->action = WINE_WOW64_MEMORY_FAULT_RAISE;
    result->status = STATUS_ACCESS_VIOLATION;
    result->parameter_count = 2;
    result->information[0] = access_type;
    result->information[1] = address;
    if (address < limit_4g) return resolve_arm64ec_low_guard( address, result );
    page = ROUND_ADDR( (void *)(ULONG_PTR)address, page_mask );

    status = arm64ec_code_begin_transaction( &transaction, TRUE, WINE_ARM64EC_CODE_RESYNC );
    if (status) return status;
    if (!transaction.observer_begun || transaction.nested)
    {
        arm64ec_code_complete_transaction( &transaction );
        return STATUS_INVALID_DEVICE_STATE;
    }
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = find_view( page, page_size );
    if (!view || is_shadow_translated_vprot( view->protect )) goto done;
    vprot = get_page_vprot( page );
    if ((vprot & (VPROT_COMMITTED | VPROT_GUARD)) != (VPROT_COMMITTED | VPROT_GUARD))
        goto done;

    if (is_inside_thread_stack( data, page, &stack_info ) && !stack_info.is_wow)
    {
        SIZE_T stack_granule = view->stack_owner == data ? page_size : host_page_size;
        SIZE_T guaranteed = ROUND_SIZE( 0, stack_info.guaranteed, (stack_granule - 1) );
        char *view_end = (char *)view->base + view->size;

        if (view->stack_owner && (view->stack_owner != data || page < stack_info.limit - page_size))
        { status = STATUS_NOT_SUPPORTED; goto done; }
        page = ROUND_ADDR( page, (stack_granule - 1) );
        if (stack_info.start != view->base || stack_info.end > view_end ||
            stack_info.end <= stack_info.start ||
            stack_info.end - stack_info.start < stack_granule ||
            guaranteed > stack_info.end - stack_info.start - stack_granule ||
            page < stack_info.start + stack_granule ||
            page > stack_info.end - stack_granule)
        {
            status = STATUS_INVALID_ADDRESS;
            goto done;
        }
        if (page >= stack_info.start + stack_granule + guaranteed)
        {
            capture_start = page - stack_granule;
            capture_end = page + stack_granule;
        }
        else
        {
            capture_start = stack_info.start + stack_granule;
            capture_end = max( capture_start + guaranteed, page + stack_granule );
        }
        status = grow_thread_stack( data, page, &stack_info );
        if (status == STATUS_ACCESS_DENIED && view->stack_owner == data)
        {
            /* grow_thread_stack either restored the original protection or
             * terminated the process. The completed rollback leaves no new
             * mappings to publish. Report this owned-stack OS failure to the
             * guest, while retaining fail-stop for other resolver failures. */
            result->status = status;
            status = STATUS_SUCCESS;
            goto done;
        }
        if (status != STATUS_SUCCESS && status != STATUS_STACK_OVERFLOW) goto done;
        result->status = status;
        result->action = status ? WINE_WOW64_MEMORY_FAULT_RAISE : WINE_WOW64_MEMORY_FAULT_RETRY;
        result->parameter_count = 0;
        memset( result->information, 0, sizeof(result->information) );
        status = STATUS_SUCCESS;
    }
    else
    {
        if (mprotect_range( page, page_size, 0, VPROT_GUARD ))
        {
            status = STATUS_ACCESS_DENIED;
            goto done;
        }
        set_page_vprot_bits( page, page_size, 0, VPROT_GUARD );
        capture_start = page;
        capture_end = page + page_size;
        result->status = STATUS_GUARD_PAGE_VIOLATION;
    }
    /* Snapshot the actual logical protection, including the newly established
     * stack guard. No guest engine runs between the mutation and this publish. */
    for (cursor = capture_start; cursor < capture_end; cursor += size)
    {
        size = get_vprot_range_size( cursor, capture_end - cursor, 0xff, &vprot );
        if (!size || !(vprot & VPROT_COMMITTED))
        {
            status = STATUS_INVALID_ADDRESS;
            break;
        }
        status = publish( context, (ULONG_PTR)cursor, size, (ULONG_PTR)view->base,
                          get_win32_prot( vprot, view->protect ) );
        if (status) break;
    }
    arm64ec_code_record_range( capture_start, capture_end - capture_start );

done:
    arm64ec_code_capture_transaction( &transaction, status );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    arm64ec_code_complete_transaction( &transaction );
    return status;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}


/* Caller owns the code-observer gate, not the provider mutex. Every alias
 * is freshly acquired from the current view; an old address is never itself
 * evidence that the old allocation or backing survived. */
void __wine_release_arm64ec_cpu_alias_v1( struct wine_arm64ec_cpu_alias_snapshot_v1 *snapshot )
{
#if defined(__APPLE__) && defined(__aarch64__)
    unsigned int i;
    if (!snapshot) return;
    for (i = 0; i < snapshot->count; ++i)
        if (snapshot->ranges[i].backing != snapshot->ranges[i].address)
            mach_vm_deallocate( mach_task_self(), snapshot->ranges[i].backing, 16384 );
    free( snapshot );
#endif
}

int32_t __wine_acquire_arm64ec_cpu_alias_v1(
    const struct wine_arm64ec_cpu_alias_snapshot_v1 *previous,
    struct wine_arm64ec_cpu_alias_snapshot_v1 **result )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct wine_arm64ec_cpu_alias_snapshot_v1 *snapshot;
    struct file_view *view;
    NTSTATUS status = STATUS_SUCCESS;
    sigset_t sigset;
    unsigned int i, j;

    if (!result) return STATUS_INVALID_PARAMETER;
    *result = NULL;
    if (!arm64ec_cpu_alias_enabled) return STATUS_SUCCESS;
    if (!arm64ec_code_observer_callback_active || host_page_size != 16384 ||
        (previous && (previous->version != WINE_ARM64EC_CPU_ALIAS_VERSION ||
                      previous->size != sizeof(*previous) || previous->count > WINE_ARM64EC_CPU_ALIAS_MAX)))
        return STATUS_INVALID_DEVICE_STATE;
    if (!(snapshot = calloc( 1, sizeof(*snapshot) ))) return STATUS_NO_MEMORY;
    snapshot->version = WINE_ARM64EC_CPU_ALIAS_VERSION;
    snapshot->size = sizeof(*snapshot);
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        SIZE_T chunk;
        if (!arm64ec_high_data_view( view )) continue;
        for (chunk = 0; chunk < view->size; chunk += 16384)
        {
            struct wine_arm64ec_cpu_alias_range_v1 range = {0};
            BOOL needs_alias = FALSE, supported = TRUE, retained = FALSE;
            BYTE first_access = get_page_vprot( (char *)view->base + chunk ) &
                                (VPROT_READ | VPROT_WRITE | VPROT_COMMITTED);
            range.address = range.backing = (ULONG_PTR)view->base + chunk;
            range.allocation_base = (ULONG_PTR)view->base;
            for (j = 0; j < 4; ++j)
            {
                BYTE prot = get_page_vprot( (char *)view->base + chunk + j * 4096 );
                range.protect[j] = get_win32_prot( prot, view->protect );
                range.state[j] = (prot & VPROT_COMMITTED) ? MEM_COMMIT : MEM_RESERVE;
                if ((prot & (VPROT_COMMITTED | VPROT_GUARD)) == (VPROT_COMMITTED | VPROT_GUARD)) needs_alias = TRUE;
                if ((prot & (VPROT_READ | VPROT_WRITE | VPROT_COMMITTED)) != first_access)
                    needs_alias = TRUE;
                if (prot & (VPROT_EXEC | VPROT_WRITEWATCH | VPROT_WRITECOPY))
                    supported = FALSE;
            }
            if (previous)
                for (i = 0; i < previous->count; ++i)
                    if (previous->ranges[i].backing != previous->ranges[i].address &&
                        previous->ranges[i].address == range.address) retained = TRUE;
            if (!(needs_alias && supported) && !retained) continue;
            if (needs_alias && !supported)
            {
                status = STATUS_NOT_SUPPORTED;
                break;
            }
            if (snapshot->count == WINE_ARM64EC_CPU_ALIAS_MAX)
            {
                status = STATUS_NO_MEMORY;
                break;
            }
            if (needs_alias)
            {
                mach_vm_address_t alias = 0;
                vm_prot_t current = 0, maximum = 0;
                kern_return_t kr = mach_vm_remap( mach_task_self(), &alias, 16384, 0,
                    VM_FLAGS_ANYWHERE, mach_task_self(), range.address, FALSE,
                    &current, &maximum, VM_INHERIT_NONE );
                if (kr != KERN_SUCCESS)
                {
                    status = STATUS_ACCESS_DENIED;
                    break;
                }
                if ((maximum & (VM_PROT_READ | VM_PROT_WRITE)) != (VM_PROT_READ | VM_PROT_WRITE) ||
                    mach_vm_protect( mach_task_self(), alias, 16384, FALSE,
                                      VM_PROT_READ | VM_PROT_WRITE ) != KERN_SUCCESS)
                {
                    mach_vm_deallocate( mach_task_self(), alias, 16384 );
                    status = STATUS_ACCESS_DENIED;
                    break;
                }
                range.backing = alias;
            }
            snapshot->ranges[snapshot->count++] = range;
        }
        if (status) break;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (status || !snapshot->count) __wine_release_arm64ec_cpu_alias_v1( snapshot );
    else *result = snapshot;
    return status;
#else
    if (result) *result = NULL;
    return STATUS_NOT_SUPPORTED;
#endif
}

/* The bounded high data bridge and CPU alias lease share eligibility.
 * Each lease describes one host page inside its original allocation. Caller holds virtual_mutex. */
#if defined(__APPLE__) && defined(__aarch64__)
static BOOL arm64ec_high_data_view( struct file_view *view )
{
    return arm64ec_cpu_alias_enabled && view && (view->size == 16384 || view->size == 65536 ||
            (arm64ec_stack_probe_enabled && view->wine_stack && view->stack_owner && view->size == 1048576)) &&
           !((ULONG_PTR)view->base & 16383) &&
           (ULONG_PTR)view->base >= 0x100000000ull && is_view_valloc( view ) &&
           !(view->protect & (VPROT_SYSTEM | VPROT_CPU_PROVIDER_OWNED |
                              VPROT_WOW64_OWNED_BACKING));
}
#endif

/***********************************************************************
 *           virtual_handle_fault
 */
NTSTATUS virtual_handle_fault( struct thread_data *data, EXCEPTION_RECORD *rec, void *stack )
{
    NTSTATUS ret = STATUS_ACCESS_VIOLATION;
    ULONG_PTR err = rec->ExceptionInformation[0];
    void *addr = (void *)rec->ExceptionInformation[1];
    char *page = ROUND_ADDR( addr, host_page_mask );
    BYTE vprot;

    mutex_lock( &virtual_mutex );  /* no need for signal masking inside signal handler */
    vprot = get_host_page_vprot( page );

#if defined(__APPLE__) && defined(__aarch64__)
    /* Unknown native instructions and actual guard operands must not consume
     * unrelated 4KB guards through the legacy host-wide fallback. Guard
     * delivery needs a normal-context observer transaction, still separate. */
    if (is_arm64ec() && (vprot & VPROT_GUARD) &&
        arm64ec_high_data_view( find_view( addr, 1 ) ))
    {
        mutex_unlock( &virtual_mutex );
        rec->ExceptionCode = ret;
        return ret;
    }
#endif

#ifdef __APPLE__
    /* Rosetta on Apple Silicon misreports certain write faults as read faults. */
    if (err == EXCEPTION_READ_FAULT && (get_unix_prot( vprot ) & PROT_READ))
    {
        WARN( "treating read fault in a readable page as a write fault, addr %p\n", addr );
        err = EXCEPTION_WRITE_FAULT;
    }
#endif

    if (!is_inside_signal_stack( data, stack ) && (vprot & VPROT_GUARD))
    {
        struct thread_stack_info stack_info;
        if (!is_inside_thread_stack( data, page, &stack_info ))
        {
            /* Change the physical page before publishing the logical clear.
             * A failed mprotect therefore leaves the exact old vprot intact. */
            if (!mprotect_range( page, host_page_size, 0, VPROT_GUARD ))
            {
                set_page_vprot_bits( page, host_page_size, 0, VPROT_GUARD );
                ret = STATUS_GUARD_PAGE_VIOLATION;
            }
        }
        else ret = grow_thread_stack( data, page, &stack_info );
    }
    else if (err == EXCEPTION_WRITE_FAULT)
    {
        if (vprot & VPROT_WRITEWATCH)
        {
            if (enable_write_exceptions && is_vprot_exec_write( vprot ) && !data->allow_writes)
            {
                rec->NumberParameters = 3;
                rec->ExceptionInformation[2] = STATUS_EXECUTABLE_MEMORY_WRITE;
                ret = STATUS_IN_PAGE_ERROR;
            }
            else
            {
                /* The domain walk retains a short image tail's owner while
                 * applying this legacy host-page-wide metadata change. */
                if (!mprotect_range( page, host_page_size, 0, VPROT_WRITEWATCH ))
                    set_page_vprot_bits( page, host_page_size, 0, VPROT_WRITEWATCH );
            }
        }
        /* ignore fault if page is writable now */
        if (get_unix_prot( get_host_page_vprot( page )) & PROT_WRITE)
        {
            if ((vprot & VPROT_WRITEWATCH) || is_write_watch_range( page, 1 ))
                ret = STATUS_SUCCESS;
        }
    }
    mutex_unlock( &virtual_mutex );
    rec->ExceptionCode = ret;
    return ret;
}


/***********************************************************************
 *           arm64ec_scalar_load
 */
#if defined(__APPLE__) && defined(__aarch64__)
static inline void arm64ec_scalar_load( const void *addr, SIZE_T size, ULONG64 *value )
{
    ULONG tmp32;
    USHORT tmp16;

    switch (size)
    {
    case sizeof(BYTE):
        __asm__ volatile( "ldrb %w0, [%1]" : "=r" (tmp32) : "r" (addr) : "memory" );
        *value = (BYTE)tmp32;
        break;
    case sizeof(USHORT):
        __asm__ volatile( "ldrh %w0, [%1]" : "=r" (tmp32) : "r" (addr) : "memory" );
        tmp16 = tmp32;
        *value = tmp16;
        break;
    case sizeof(ULONG):
        __asm__ volatile( "ldr %w0, [%1]" : "=r" (tmp32) : "r" (addr) : "memory" );
        *value = tmp32;
        break;
    case sizeof(ULONG64):
        __asm__ volatile( "ldr %0, [%1]" : "=r" (*value) : "r" (addr) : "memory" );
        break;
    default:
        assert(0);
    }
}


/***********************************************************************
 *           arm64ec_scalar_store
 */
static inline void arm64ec_scalar_store( void *addr, SIZE_T size, ULONG64 value )
{
    ULONG tmp32;

    switch (size)
    {
    case sizeof(BYTE):
        tmp32 = value;
        __asm__ volatile( "strb %w0, [%1]" :: "r" (tmp32), "r" (addr) : "memory" );
        break;
    case sizeof(USHORT):
        tmp32 = value;
        __asm__ volatile( "strh %w0, [%1]" :: "r" (tmp32), "r" (addr) : "memory" );
        break;
    case sizeof(ULONG):
        tmp32 = value;
        __asm__ volatile( "str %w0, [%1]" :: "r" (tmp32), "r" (addr) : "memory" );
        break;
    case sizeof(ULONG64):
        __asm__ volatile( "str %0, [%1]" :: "r" (value), "r" (addr) : "memory" );
        break;
    default:
        assert(0);
    }
}


/***********************************************************************
 *           arm64ec_q_load
 */
static inline void arm64ec_q_load( const void *addr,
                                   struct arm64ec_low_guest_value *value )
{
    __asm__ volatile( "ldr q0, [%0]\n\t"
                      "str q0, [%1]"
                      :: "r" (addr), "r" (value) : "v0", "memory" );
}


/***********************************************************************
 *           arm64ec_q_store
 */
static inline void arm64ec_q_store( void *addr,
                                    const struct arm64ec_low_guest_value *value )
{
    __asm__ volatile( "ldr q0, [%0]\n\t"
                      "str q0, [%1]"
                      :: "r" (value), "r" (addr) : "v0", "memory" );
}


/***********************************************************************
 *           arm64ec_qpair_load
 */
static inline void arm64ec_qpair_load( const void *addr,
                                       struct arm64ec_low_guest_value *value )
{
    __asm__ volatile( "ldp q0, q1, [%0]\n\t"
                      "stp q0, q1, [%1]"
                      :: "r" (addr), "r" (value) : "v0", "v1", "memory" );
}


/***********************************************************************
 *           arm64ec_qpair_store
 */
static inline void arm64ec_qpair_store( void *addr,
                                        const struct arm64ec_low_guest_value *value )
{
    __asm__ volatile( "ldp q0, q1, [%0]\n\t"
                      "stp q0, q1, [%1]"
                      :: "r" (value), "r" (addr) : "v0", "v1", "memory" );
}


/***********************************************************************
 *           arm64ec_gpr_pair_load
 */
static inline void arm64ec_gpr_pair_load( const void *addr,
                                          struct arm64ec_low_guest_value *value,
                                          SIZE_T element_size )
{
    if (element_size == sizeof(ULONG))
    {
        ULONG first, second;

        __asm__ volatile( "ldp %w0, %w1, [%2]"
                          : "=&r" (first), "=&r" (second) : "r" (addr) : "memory" );
        value->word[0] = first;
        value->word[1] = second;
    }
    else
    {
        ULONG64 first, second;

        __asm__ volatile( "ldp %x0, %x1, [%2]"
                          : "=&r" (first), "=&r" (second) : "r" (addr) : "memory" );
        value->word[0] = first;
        value->word[1] = second;
    }
}


/***********************************************************************
 *           arm64ec_gpr_pair_store
 */
static inline void arm64ec_gpr_pair_store( void *addr,
                                           const struct arm64ec_low_guest_value *value,
                                           SIZE_T element_size )
{
    if (element_size == sizeof(ULONG))
    {
        ULONG first = value->word[0], second = value->word[1];

        __asm__ volatile( "stp %w0, %w1, [%2]"
                          :: "r" (first), "r" (second), "r" (addr) : "memory" );
    }
    else
    {
        ULONG64 first = value->word[0], second = value->word[1];

        __asm__ volatile( "stp %x0, %x1, [%2]"
                          :: "r" (first), "r" (second), "r" (addr) : "memory" );
    }
}
#endif


/***********************************************************************
 *           virtual_arm64ec_fetch_low_guest_instr
 *
 * Fetch one instruction from Wine-owned ARM64EC code while holding the
 * virtual memory lock.  This avoids trusting the guest-visible PEB EC bitmap
 * directly from the signal handler and avoids a validate-then-deref race on PC.
 */
BOOL virtual_arm64ec_fetch_low_guest_instr( const void *pc, ULONG *instr )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct file_view *view;
    ULONG_PTR page;
    ULONG64 value;
    UINT64 *map;
    BOOL ret = FALSE;
    BYTE vprot;

    if (!instr || ((ULONG_PTR)pc & 3)) return FALSE;

    mutex_lock( &virtual_mutex );  /* no need for signal masking inside signal handler */
    if (!(view = find_view( pc, sizeof(*instr) )) ||
        !(view->protect & VPROT_ARM64EC) || (view->protect & VPROT_SYSTEM) ||
        !arm64ec_view)
        goto done;

    page = (ULONG_PTR)pc >> page_shift;
    if ((page / 8) >= arm64ec_view->size) goto done;
    map = arm64ec_view->base;
    if (!((map[page / 64] >> (page & 63)) & 1)) goto done;

    vprot = get_page_vprot( pc );
    if ((vprot & (VPROT_COMMITTED | VPROT_EXEC | VPROT_GUARD)) !=
        (VPROT_COMMITTED | VPROT_EXEC))
        goto done;

    arm64ec_scalar_load( pc, sizeof(*instr), &value );
    *instr = value;
    ret = TRUE;

done:
    mutex_unlock( &virtual_mutex );
    return ret;
#else
    (void)pc;
    (void)instr;
    return FALSE;
#endif
}


/***********************************************************************
 *           check_translated_write_access
 *
 * Validate the physical Darwin pages backing one already-validated LOW
 * operand.  This signal path is read-only with respect to virtual-memory
 * metadata: write-watch disarming belongs to a normal-context V1 transaction.
 */
#if defined(__APPLE__) && defined(__aarch64__)
static NTSTATUS check_translated_write_access( void *base, SIZE_T size,
                                                BOOL *has_write_watch )
{
    ULONG_PTR start = (ULONG_PTR)base, end, page;

    if (!has_write_watch || !size || size > ~(ULONG_PTR)0 - start)
        return STATUS_INVALID_PARAMETER;
    *has_write_watch = FALSE;
    end = start + size;
    page = start & ~host_page_mask;
    while (page < end)
    {
        BYTE physical_vprot = get_host_page_vprot( (void *)page );
        BYTE translated_vprot = get_translated_host_page_vprot( (void *)page );

        if (physical_vprot & VPROT_WRITEWATCH)
        {
            *has_write_watch = TRUE;
            return STATUS_ACCESS_VIOLATION;
        }
        if (!(get_unix_prot( translated_vprot ) & PROT_WRITE))
            return STATUS_ACCESS_VIOLATION;
        if (host_page_size > ~(ULONG_PTR)0 - page) return STATUS_INVALID_PARAMETER;
        page += host_page_size;
    }
    return STATUS_SUCCESS;
}
#endif


/* Emulate one decoded ordinary high native operand without changing the
 * original mapping's protection or any logical VM state. The temporary Mach
 * alias is never published to guest registers or the CPU provider. Ownership,
 * full operand permissions and the actual memory access stay under VM lock. */
#if defined(__APPLE__) && defined(__aarch64__)
static NTSTATUS arm64ec_high_data_access( ULONG_PTR guest,
                                         struct arm64ec_low_guest_value *value,
                                         SIZE_T size, SIZE_T pair_element_size, BOOL write,
                                         ULONG_PTR *allocation_id )
{
    struct file_view *view;
    mach_vm_address_t alias = 0;
    vm_prot_t current = 0, maximum = 0, needed = write ? (VM_PROT_READ | VM_PROT_WRITE) : VM_PROT_READ;
    ULONG_PTR page, host;
    SIZE_T offset, alias_size = 0;
    BOOL guarded = FALSE;
    NTSTATUS status = STATUS_ACCESS_VIOLATION;

    mutex_lock( &virtual_mutex );
    view = find_view( (void *)guest, size );
    if (!arm64ec_high_data_view( view )) goto done;
    /* Keep executable/write-watch/COW domains out, including untouched siblings. */
    for (offset = 0; offset < view->size; offset += page_size)
        if (get_page_vprot( (char *)view->base + offset ) &
            (VPROT_EXEC | VPROT_WRITEWATCH | VPROT_WRITECOPY)) goto done;
    for (offset = 0; offset < size; offset += min( size - offset,
                                                  page_size - ((guest + offset) & page_mask) ))
    {
        BYTE prot = get_page_vprot( (void *)(guest + offset) );
        if (!(prot & VPROT_COMMITTED)) goto done;
        /* Guard is a one-shot access alarm even when the underlying page is
         * read-only. Enforce its ordinary permissions on the retry. */
        if (prot & VPROT_GUARD) { guarded = TRUE; break; }
        if (!(get_unix_prot( prot ) & (write ? PROT_WRITE : PROT_READ))) goto done;
    }
    if (guarded)
    {
        if (!allocation_id) goto done;
        *allocation_id = view->allocation_id;
        status = STATUS_WINE_NATIVE_GUARD;
        goto done;
    }
    page = guest & ~host_page_mask;
    alias_size = ROUND_SIZE( guest, size, host_page_mask );
    if (mach_vm_remap( mach_task_self(), &alias, alias_size, 0, VM_FLAGS_ANYWHERE,
                      mach_task_self(), page, FALSE, &current, &maximum,
                      VM_INHERIT_NONE ) != KERN_SUCCESS) goto done;
    if ((maximum & needed) != needed ||
        mach_vm_protect( mach_task_self(), alias, alias_size, FALSE, needed ) != KERN_SUCCESS)
        goto done;
    host = alias + guest - page;
    if (write)
    {
        if (!pair_element_size && size == 16) arm64ec_q_store( (void *)host, value );
        else if (pair_element_size == 16) arm64ec_qpair_store( (void *)host, value );
        else if (pair_element_size) arm64ec_gpr_pair_store( (void *)host, value, pair_element_size );
        else arm64ec_scalar_store( (void *)host, size, value->word[0] );
    }
    else
    {
        if (!pair_element_size && size == 16) arm64ec_q_load( (const void *)host, value );
        else if (pair_element_size == 16) arm64ec_qpair_load( (const void *)host, value );
        else if (pair_element_size) arm64ec_gpr_pair_load( (const void *)host, value, pair_element_size );
        else arm64ec_scalar_load( (const void *)host, size, &value->word[0] );
    }
    status = STATUS_SUCCESS;
done:
    if (alias) mach_vm_deallocate( mach_task_self(), alias, alias_size );
    mutex_unlock( &virtual_mutex );
    return status;
}
#endif


#if defined(__APPLE__) && defined(__aarch64__)
/* Caller has authenticated the Wine allocation and holds both observer and VM gates. */
static NTSTATUS enroll_shared_stack( struct thread_data *owner, struct file_view *view, BOOL *created )
{
    struct file_view *guard_view;
    NTSTATUS status;
    *created = FALSE;
    if (!owner->native_guard_stack)
    {
        status = map_view( &guard_view, NULL, NATIVE_GUARD_STACK_SIZE, 0,
                           VPROT_COMMITTED | VPROT_READ | VPROT_WRITE, limit_4g, 0, 0 );
        if (status) return status;
        set_page_vprot( guard_view->base, 16384, 0 );
        if (mprotect_range( guard_view->base, 16384, 0, 0 ))
        {
            delete_view( guard_view );
            return STATUS_ACCESS_DENIED;
        }
        owner->native_guard_stack = guard_view->base;
        *created = TRUE;
        arm64ec_code_record_range( guard_view->base, guard_view->size );
    }
    view->stack_owner = owner;
    return STATUS_SUCCESS;
}
#endif

/* Start only authenticated 1MiB Wine stacks with a bounded committed window.
 * This runs after provider ThreadInit, before user entry, in normal context. */
NTSTATUS virtual_prepare_shared_stack( void *args )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct shared_stack_init_params *params = args;
    struct thread_data *data = get_thread_data();
    struct arm64ec_code_transaction transaction;
    struct file_view *view;
    BYTE old_vprot[1048576 / 4096];
    char *base, *end, *limit;
    SIZE_T commit, i;
    BOOL created = FALSE;
    NTSTATUS status;
    sigset_t sigset;
    if (!arm64ec_stack_auto_enabled || !is_arm64ec()) return STATUS_SUCCESS;
    status = arm64ec_code_begin_transaction( &transaction, TRUE, WINE_ARM64EC_CODE_RESYNC );
    if (status) return status;
    if (!transaction.observer_begun || transaction.nested)
    {
        arm64ec_code_complete_transaction( &transaction );
        return STATUS_INVALID_DEVICE_STATE;
    }
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    base = data->teb->DeallocationStack;
    end = data->teb->Tib.StackBase;
    view = find_view( base, 1 );
    /* A different stack size remains outside this bounded prototype. */
    if (!view || !view->wine_stack || view->size != 1048576 || base != view->base ||
        end != base + view->size || view->stack_owner) goto done;
    if (!params || params->sp <= (ULONG_PTR)base || params->sp >= (ULONG_PTR)end)
    { status = STATUS_INVALID_ADDRESS; goto done; }
    commit = ROUND_SIZE( 0, max( max( (SIZE_T)131072, view->stack_commit_size ),
                                  (ULONG_PTR)end - params->sp + 16384 ), 16383 );
    if (commit > view->size - 32768) goto done; /* preserve explicit near-full commit requests */
    limit = end - commit;
    for (i = 0; i < ARRAY_SIZE(old_vprot); i++) old_vprot[i] = get_page_vprot( base + i * page_size );
    if ((status = enroll_shared_stack( data, view, &created ))) goto done;
    set_page_vprot( base, limit - base, VPROT_READ | VPROT_WRITE );
    set_page_vprot( base, page_size, 0 );
    set_page_vprot( limit - page_size, page_size, VPROT_COMMITTED | VPROT_READ | VPROT_WRITE | VPROT_GUARD );
    if (mprotect_range( base, limit - base, 0, 0 ))
    {
        restore_vprot_or_abort( base, view->size, old_vprot );
        view->stack_owner = NULL;
        if (created)
        {
            delete_view( find_view( data->native_guard_stack, 1 ) );
            data->native_guard_stack = NULL;
        }
        status = STATUS_ACCESS_DENIED;
        goto done;
    }
    data->teb->Tib.StackLimit = limit;
    arm64ec_code_record_range( base, view->size );
done:
    arm64ec_code_capture_transaction( &transaction, status );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    arm64ec_code_complete_transaction( &transaction );
    return status;
#else
    return STATUS_SUCCESS;
#endif
}

/* Freeze VM writers across the PE mapping walk and its generation-checked
 * provider commit. Never hold provider.mutex while querying Wine views.
 * Recursive mutexes permit this thread's snapshot-buffer allocation; its
 * generation change still forces a fresh pass before anything is published.
 * Existing transactions reject cross-domain nesting, so lock low before code. */
int32_t __wine_lock_arm64ec_mapping_snapshot_v1(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    if (!arm64ec_stack_probe_enabled) return STATUS_SUCCESS;
    if (arm64ec_mapping_snapshot_locked || arm64ec_code_current_transaction ||
        arm64ec_low_memory_current_transaction || arm64ec_code_observer_callback_active ||
        arm64ec_low_memory_observer_callback_active) return STATUS_INVALID_DEVICE_STATE;
    mutex_lock( &arm64ec_low_memory_observer_mutex );
    mutex_lock( &arm64ec_code_observer_mutex );
    arm64ec_mapping_snapshot_locked = TRUE;
#endif
    return STATUS_SUCCESS;
}

int32_t __wine_unlock_arm64ec_mapping_snapshot_v1(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    if (!arm64ec_stack_probe_enabled) return STATUS_SUCCESS;
    if (!arm64ec_mapping_snapshot_locked || arm64ec_code_current_transaction ||
        arm64ec_low_memory_current_transaction) return STATUS_INVALID_DEVICE_STATE;
    arm64ec_mapping_snapshot_locked = FALSE;
    mutex_unlock( &arm64ec_code_observer_mutex );
    mutex_unlock( &arm64ec_low_memory_observer_mutex );
#endif
    return STATUS_SUCCESS;
}

/* Private current-thread bounds, never a caller-supplied stack registration. */
int32_t __wine_get_arm64ec_exception_stack_v1( uint64_t *limit, uint64_t *base )
{
    struct thread_data *data = get_thread_data();
    *limit = *base = 0;
#if defined(__APPLE__) && defined(__aarch64__)
    if (arm64ec_stack_probe_enabled && data && data->native_guard_stack)
    {
        *limit = (ULONG_PTR)data->native_guard_stack + 16384;
        *base = (ULONG_PTR)data->native_guard_stack + NATIVE_GUARD_STACK_SIZE;
        return STATUS_SUCCESS;
    }
#endif
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS virtual_get_exception_stack( void *args )
{
    struct exception_stack_params *params = args;
    uint64_t limit, base;
    NTSTATUS status = __wine_get_arm64ec_exception_stack_v1( &limit, &base );
    params->limit = limit;
    params->base = base;
    return status;
}

/* Called after leaving signal context, before any guest exception handler.
 * Only a signal-owned pending operand may request a guard mutation. */
NTSTATUS virtual_resolve_native_guard( void *args )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct native_guard_params *params = args, pending;
    struct thread_data *data = get_thread_data();
    struct arm64ec_code_transaction transaction;
    struct file_view *view;
    char *guard = NULL;
    SIZE_T offset;
    NTSTATUS status, result = STATUS_ACCESS_VIOLATION;
    sigset_t sigset;

    if (!data || !is_arm64ec() || !arm64ec_cpu_alias_enabled || !params)
        return STATUS_NOT_SUPPORTED;
    pending = data->native_guard;
    memset( &data->native_guard, 0, sizeof(data->native_guard) );
    if (!pending.size || pending.pc != params->pc || pending.size > 32 ||
        pending.size > ~(ULONG_PTR)0 - pending.address) return STATUS_ACCESS_VIOLATION;
    params->address = pending.address;
    params->write = pending.write;
    params->size = pending.size;
    status = arm64ec_code_begin_transaction( &transaction, TRUE, WINE_ARM64EC_CODE_RESYNC );
    if (status) return status;
    if (!transaction.observer_begun || transaction.nested)
    {
        arm64ec_code_complete_transaction( &transaction );
        return STATUS_INVALID_DEVICE_STATE;
    }
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = find_view( (void *)(ULONG_PTR)pending.address, pending.size );
    if (!arm64ec_high_data_view( view ) ||
        !pending.allocation_id || view->allocation_id != pending.allocation_id) goto done;
    for (offset = 0; offset < view->size; offset += page_size)
        if (get_page_vprot( (char *)view->base + offset ) &
            (VPROT_EXEC | VPROT_WRITEWATCH | VPROT_WRITECOPY)) goto done;
    for (offset = 0; offset < pending.size; offset += min( pending.size - offset,
                                  page_size - ((pending.address + offset) & page_mask) ))
    {
        char *ptr = (void *)(ULONG_PTR)(pending.address + offset);
        BYTE prot = get_page_vprot( ptr );
        if (!(prot & VPROT_COMMITTED)) goto done;
        if (prot & VPROT_GUARD)
        {
            guard = ROUND_ADDR( ptr, page_mask );
            params->address = (ULONG_PTR)ptr;
            break;
        }
        if (!(get_unix_prot( prot ) & (pending.write ? PROT_WRITE : PROT_READ))) goto done;
    }
    result = STATUS_SUCCESS; /* Another thread may already have consumed it. */
    if (guard && view->stack_owner)
    {
        struct thread_stack_info info;
        SIZE_T guaranteed;
        char *capture_start, *capture_end;
        if (view->stack_owner != data || !is_inside_thread_stack( data, guard, &info ) ||
            info.is_wow || info.start != view->base ||
            data->native_guard_limit != (ULONG_PTR)info.limit ||
            data->native_guard_base != (ULONG_PTR)info.end)
        { result = STATUS_ACCESS_VIOLATION; goto done; }
        guaranteed = ROUND_SIZE( 0, info.guaranteed, page_mask );
        /* Also accept a rearmed guard above StackLimit (_resetstkoflw).
         * Foreign stacks and skipped uncommitted growth remain rejected. */
        if (guard < info.limit - page_size || guard < info.start + page_size ||
            guaranteed > info.end - info.start - page_size)
        { result = STATUS_NOT_SUPPORTED; goto done; }
        capture_start = guard >= info.start + page_size + guaranteed ? guard - page_size :
                        info.start + page_size;
        capture_end = guard >= info.start + page_size + guaranteed ? guard + page_size :
                      max( capture_start + guaranteed, guard + page_size );
        result = grow_thread_stack( data, guard, &info );
        status = result == STATUS_STACK_OVERFLOW ? STATUS_SUCCESS : result;
        if (!status) arm64ec_code_record_range( capture_start, capture_end - capture_start );
    }
    else if (guard)
    {
        if (mprotect_range( guard, page_size, 0, VPROT_GUARD ))
        {
            status = STATUS_ACCESS_DENIED;
            result = status;
            goto done;
        }
        set_page_vprot_bits( guard, page_size, 0, VPROT_GUARD );
        arm64ec_code_record_range( guard, page_size );
        result = STATUS_GUARD_PAGE_VIOLATION;
    }
 done:
    arm64ec_code_capture_transaction( &transaction, status );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    arm64ec_code_complete_transaction( &transaction );
    return result;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

/***********************************************************************
 *           virtual_arm64ec_low_guest_access
 *
 * Validate and perform one bounded native ARM64EC access to an AMD64 fixed-low
 * guest operand.  The interrupted register remains a guest pointer; only this
 * operand is redirected to its tagged high-shadow backing while virtual_mutex
 * prevents remap and reprotection races.
 */
NTSTATUS virtual_arm64ec_low_guest_access( struct thread_data *data, ULONG_PTR guest,
                                           struct arm64ec_low_guest_value *value,
                                           SIZE_T size, SIZE_T pair_element_size,
                                           BOOL write, ULONG_PTR *extra_status )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct file_view *view;
    BOOL has_write_watch = FALSE;
    ULONG_PTR host, page, end;
    SIZE_T offset;
    NTSTATUS status = STATUS_ACCESS_VIOLATION;

    (void)data;
    if (!value ||
        ((!pair_element_size && size != sizeof(BYTE) && size != sizeof(USHORT) &&
          size != sizeof(ULONG) && size != sizeof(ULONG64) && size != 16) ||
         (pair_element_size &&
          ((pair_element_size != sizeof(ULONG) &&
            pair_element_size != sizeof(ULONG64) && pair_element_size != 16) ||
           size != pair_element_size * 2))) ||
        size > ~(ULONG_PTR)0 - guest)
        return STATUS_INVALID_PARAMETER;
    if (extra_status) *extra_status = 0;
    if (guest >= WINE_LOW_VA_SHADOW_SIZE)
        return arm64ec_high_data_access( guest, value, size, pair_element_size, write, extra_status );
    if (size > WINE_LOW_VA_SHADOW_SIZE - guest) return STATUS_INVALID_PARAMETER;
    host = WINE_LOW_VA_SHADOW_BASE + guest;

    mutex_lock( &virtual_mutex );  /* signal handler already masks nested VM mutation */
    for (offset = 0; offset < size; )
    {
        SIZE_T span = min( size - offset, page_size - ((host + offset) & page_mask) );
        BYTE vprot = get_page_vprot( (void *)(host + offset) );

        if (!(view = find_view( (void *)(host + offset), span )) ||
            !(view->protect & VPROT_AMD64_LOW_TRANSLATED) ||
            (view->protect & VPROT_SYSTEM) ||
            !(vprot & VPROT_COMMITTED) || (vprot & VPROT_GUARD))
            goto done;
        if (write)
        {
            /* Executable writes and all write-watch state need observer-visible
             * normal-context transitions; this first signal bridge stays closed. */
            if (!(vprot & (VPROT_WRITE | VPROT_WRITECOPY)) ||
                (vprot & (VPROT_EXEC | VPROT_WRITEWATCH)))
                goto done;
        }
        else if (!(get_unix_prot( vprot ) & PROT_READ)) goto done;
        offset += span;
    }

    end = host + size;
    page = host & ~host_page_mask;
    if (write)
    {
        if ((status = check_translated_write_access( (void *)host, size,
                                                     &has_write_watch )) ||
            has_write_watch)
            goto done;
        if (!pair_element_size && size == 16) arm64ec_q_store( (void *)host, value );
        else if (pair_element_size == 16) arm64ec_qpair_store( (void *)host, value );
        else if (pair_element_size)
            arm64ec_gpr_pair_store( (void *)host, value, pair_element_size );
        else arm64ec_scalar_store( (void *)host, size, value->word[0] );
    }
    else
    {
        while (page < end)
        {
            if (!(get_unix_prot( get_translated_host_page_vprot( (void *)page )) &
                  PROT_READ))
                goto done;
            if (host_page_size > ~(ULONG_PTR)0 - page) goto done;
            page += host_page_size;
        }
        if (!pair_element_size && size == 16) arm64ec_q_load( (const void *)host, value );
        else if (pair_element_size == 16) arm64ec_qpair_load( (const void *)host, value );
        else if (pair_element_size)
            arm64ec_gpr_pair_load( (const void *)host, value, pair_element_size );
        else arm64ec_scalar_load( (const void *)host, size, &value->word[0] );
    }
    status = STATUS_SUCCESS;

done:
    mutex_unlock( &virtual_mutex );
    return status;
#else
    (void)data;
    (void)guest;
    (void)value;
    (void)size;
    (void)pair_element_size;
    (void)write;
    (void)extra_status;
    return STATUS_NOT_SUPPORTED;
#endif
}


/***********************************************************************
 *           virtual_setup_exception
 */
void *virtual_setup_exception( struct thread_data *data, void *stack_ptr, size_t size, EXCEPTION_RECORD *rec )
{
    char *stack = stack_ptr;
    struct thread_stack_info stack_info;
    SIZE_T stack_page_size;

    if (!is_inside_thread_stack( data, stack, &stack_info ))
    {
        if (is_inside_signal_stack( data, stack ))
        {
            ERR( "nested exception on signal stack addr %p stack %p\n", rec->ExceptionAddress, stack );
            abort_thread(1);
        }
        WARN( "exception outside of stack limits addr %p stack %p (%p-%p-%p)\n",
              rec->ExceptionAddress, stack, data->teb->DeallocationStack,
              data->teb->Tib.StackLimit, data->teb->Tib.StackBase );
        return stack - size;
    }

    stack -= size;
    stack_page_size = stack_info.is_wow ? page_size : host_page_size;

    if (stack < stack_info.start + stack_page_size)
    {
        /* stack overflow on last page, unrecoverable */
        UINT diff = stack_info.start + stack_page_size - stack;
        ERR( "stack overflow %u bytes addr %p stack %p (%p-%p-%p)\n",
             diff, rec->ExceptionAddress, stack, stack_info.start, stack_info.limit, stack_info.end );
        abort_thread(1);
    }
    else if (stack < stack_info.limit)
    {
        char *page = ROUND_ADDR( stack, stack_page_size - 1 );
        mutex_lock( &virtual_mutex );  /* no need for signal masking inside signal handler */
        if ((stack_info.is_wow ? get_page_vprot( page ) : get_host_page_vprot( page )) & VPROT_GUARD)
        {
            NTSTATUS status = grow_thread_stack( data, page, &stack_info );

            if (status == STATUS_STACK_OVERFLOW)
            {
                rec->ExceptionCode = STATUS_STACK_OVERFLOW;
                rec->NumberParameters = 0;
            }
            else if (status)
            {
                mutex_unlock( &virtual_mutex );
                if (status == STATUS_ACCESS_DENIED)
                    ERR( "failed to update stack protection, status %08x\n", status );
                abort_thread(1);
            }
        }
        mutex_unlock( &virtual_mutex );
    }
#if defined(VALGRIND_MAKE_MEM_UNDEFINED)
    VALGRIND_MAKE_MEM_UNDEFINED( stack, size );
#elif defined(VALGRIND_MAKE_WRITABLE)
    VALGRIND_MAKE_WRITABLE( stack, size );
#endif
    return stack;
}


/***********************************************************************
 *           check_write_access
 *
 * Check if the memory range is writable, temporarily disabling write watches if necessary.
 */
static NTSTATUS validate_write_access( void *base, size_t size, BOOL *has_write_watch )
{
    char *addr = base;
    size_t remaining = size;
    struct memory_access_cache cache = {0};

    while (remaining)
    {
        SIZE_T available;
        BOOL translated;
        BYTE vprot = get_memory_access_vprot( addr, &available, &translated, &cache );

        if ((vprot & VPROT_WRITEWATCH) ||
            (translated && (get_translated_host_page_vprot( addr ) & VPROT_WRITEWATCH)))
            *has_write_watch = TRUE;
        if (!(get_unix_prot( vprot & ~VPROT_WRITEWATCH ) & PROT_WRITE))
            return STATUS_INVALID_USER_BUFFER;
        available = min( available, remaining );
        addr += available;
        remaining -= available;
    }

    return STATUS_SUCCESS;
}


static NTSTATUS check_write_access( void *base, size_t size, BOOL *has_write_watch )
{
    NTSTATUS status;

    if ((status = validate_write_access( base, size, has_write_watch ))) return status;

    /* Keep the logical range intact so mprotect_range() can identify a tagged
     * view even when it ends inside a 16K host page.  Apply one logical/host
     * lane at a time so adjacent views retain their own ownership tag. */
    if (*has_write_watch &&
#if defined(__APPLE__) && defined(__aarch64__)
        !wow64_memory_logical_write_fault_is_delegated() &&
#endif
        mprotect_memory_access_range( base, size, 0, VPROT_WRITEWATCH ))
    {
        if (mprotect_memory_access_range( base, size, 0, 0 ))
            abort_process( STATUS_ACCESS_DENIED );
        return STATUS_INVALID_USER_BUFFER;
    }
    return STATUS_SUCCESS;
}


static unsigned int virtual_server_call( void *req_ptr, BOOL lock_native_reply,
                                         void *fixed_reply, SIZE_T fixed_reply_size )
{
    struct __server_request_info * const req = req_ptr;
    sigset_t sigset;
    void *addr = req->reply_data;
    data_size_t size = req->u.req.request_header.reply_size;
    data_size_t reply_size = 0;
    BOOL has_write_watch = FALSE;
    BOOL fixed_has_write_watch = FALSE;
    BOOL reply_received = FALSE;
    BOOL delegated_write_fault = FALSE;
    unsigned int i, ret = STATUS_SUCCESS;
    size_t payload_size = 0;
    BOOL lock_required = (lock_native_reply && !!size) || !!fixed_reply_size;

    if (fixed_reply_size > sizeof(req->u.reply)) return STATUS_INVALID_PARAMETER;
    if (req->data_count > __SERVER_MAX_DATA) goto malformed;
    for (i = 0; i < req->data_count; i++)
    {
        if (req->data[i].size > ~(data_size_t)0 - payload_size) goto malformed;
        payload_size += req->data[i].size;
    }
    if (payload_size != req->u.req.request_header.request_size ||
        payload_size > ~(data_size_t)0 - sizeof(req->u.req) ||
        payload_size > SSIZE_MAX - sizeof(req->u.req))
        goto malformed;

    for (i = 0; i < req->data_count; i++)
    {
        if (req->data[i].size &&
            (!req->data[i].ptr ||
             (overlaps_wow64_shadow( req->data[i].ptr, req->data[i].size ) &&
              !is_inside_wow64_shadow( req->data[i].ptr, req->data[i].size ))))
        {
            memset( &req->u.reply, 0, sizeof(req->u.reply) );
            return STATUS_ACCESS_VIOLATION;
        }
        if (overlaps_wow64_shadow( req->data[i].ptr, req->data[i].size ))
            lock_required = TRUE;
    }
    if (size && (!addr || (overlaps_wow64_shadow( addr, size ) &&
                           !is_inside_wow64_shadow( addr, size ))))
    {
        memset( &req->u.reply, 0, sizeof(req->u.reply) );
        return STATUS_ACCESS_VIOLATION;
    }
    if (overlaps_wow64_shadow( addr, size )) lock_required = TRUE;
    if (fixed_reply_size &&
        (!fixed_reply ||
         (overlaps_wow64_shadow( fixed_reply, fixed_reply_size ) &&
          !is_inside_wow64_shadow( fixed_reply, fixed_reply_size ))))
    {
        memset( &req->u.reply, 0, sizeof(req->u.reply) );
        return STATUS_ACCESS_VIOLATION;
    }
    if (overlaps_wow64_shadow( fixed_reply, fixed_reply_size )) lock_required = TRUE;
    if (!lock_required) return wine_server_call_unchecked( req_ptr );

#if defined(__APPLE__) && defined(__aarch64__)
    delegated_write_fault = wow64_memory_logical_write_fault_is_delegated();
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < req->data_count; i++)
    {
        if (overlaps_wow64_shadow( req->data[i].ptr, req->data[i].size ) &&
            !check_wow64_translated_memory_access( req->data[i].ptr,
                                                    req->data[i].size, PROT_READ ))
        {
            ret = STATUS_ACCESS_VIOLATION;
            break;
        }
    }
    if (!ret && size)
    {
        if (check_write_access( addr, size, &has_write_watch ))
            ret = STATUS_ACCESS_VIOLATION;
    }
    if (!ret && fixed_reply_size)
    {
        if (check_write_access( fixed_reply, fixed_reply_size, &fixed_has_write_watch ))
            ret = STATUS_ACCESS_VIOLATION;
    }
    if (!ret)
    {
        ret = server_call_unlocked_with_reply_size( req, &reply_size, &reply_received );
        if (fixed_reply_size && reply_received)
            memcpy( fixed_reply, &req->u.reply, fixed_reply_size );
    }
    else
        memset( &req->u.reply, 0, sizeof(req->u.reply) );
    if (has_write_watch && !delegated_write_fault)
        update_write_watches( addr, size, min( size, reply_size ));
    if (fixed_has_write_watch && !delegated_write_fault)
        update_write_watches( fixed_reply, fixed_reply_size,
                              reply_received ? fixed_reply_size : 0 );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    if (has_write_watch && delegated_write_fault && reply_size)
    {
        wow64_memory_publish_native_write_or_abort( addr, min( size, reply_size ) );
    }
    if (fixed_has_write_watch && reply_received && delegated_write_fault && fixed_reply_size)
    {
        wow64_memory_publish_native_write_or_abort( fixed_reply, fixed_reply_size );
    }
#endif
    return ret;

malformed:
    memset( &req->u.reply, 0, sizeof(req->u.reply) );
    return STATUS_INVALID_PARAMETER;
}


/***********************************************************************
 *           virtual_locked_server_call
 */
unsigned int virtual_locked_server_call( void *req_ptr )
{
    return virtual_server_call( req_ptr, TRUE, NULL, 0 );
}


/***********************************************************************
 *           virtual_locked_wow64_server_call
 */
unsigned int virtual_locked_wow64_server_call( void *req_ptr )
{
    return virtual_server_call( req_ptr, FALSE, NULL, 0 );
}


/***********************************************************************
 *           virtual_locked_wow64_server_call_with_reply
 *
 * Validate and publish the fixed WoW64 reply descriptor while the virtual
 * address space is locked.  This prevents a protection race from turning a
 * successful server-side operation into an unpublishable reply.
 */
unsigned int virtual_locked_wow64_server_call_with_reply( void *req_ptr,
                                                          void *reply, SIZE_T reply_size )
{
    return virtual_server_call( req_ptr, FALSE, reply, reply_size );
}


/* Classification only; the locked I/O helper validates actual mapping ownership. */
BOOL virtual_is_arm64ec_low_buffer( const void *addr, size_t size )
{
#if defined(__APPLE__) && defined(__aarch64__)
    return is_arm64ec() && size && (ULONG_PTR)addr < WINE_LOW_VA_SHADOW_SIZE;
#else
    return FALSE;
#endif
}


/* Regular synchronous file I/O may carry an AMD64 fixed-low image buffer.
 * Retain guest addresses outside this operation. Validate all logical pages
 * and keep the same VM lock used by virtual_locked_read while the kernel
 * accesses the tagged backing, so reprotection/remapping cannot widen access.
 * Code and write-watch destinations still need observer publication and are
 * deliberately rejected here; this path supports ordinary data buffers. */
ssize_t virtual_locked_arm64ec_file_io( int fd, void *addr, size_t size, off_t offset,
                                       BOOL positioned, BOOL write_to_file )
{
#if defined(__APPLE__) && defined(__aarch64__)
    if (virtual_is_arm64ec_low_buffer( addr, size ))
    {
        ULONG_PTR guest = (ULONG_PTR)addr, host = WINE_LOW_VA_SHADOW_BASE + guest;
        struct file_view *view;
        SIZE_T cursor;
        sigset_t sigset;
        ssize_t ret = -1;
        int saved_errno = EFAULT;
        BOOL write_watch = FALSE;

        if (!guest || size > WINE_LOW_VA_SHADOW_SIZE - guest)
        {
            errno = EFAULT;
            return -1;
        }
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        for (cursor = 0; cursor < size; )
        {
            SIZE_T span = min( size - cursor, page_size - ((host + cursor) & page_mask) );
            BYTE vprot = get_page_vprot( (void *)(host + cursor) );

            if (!(view = find_view( (void *)(host + cursor), span )) ||
                !(view->protect & VPROT_AMD64_LOW_TRANSLATED) ||
                (view->protect & VPROT_SYSTEM) || !(vprot & VPROT_COMMITTED) ||
                (vprot & VPROT_GUARD)) goto done;
            if (write_to_file)
            {
                if (!(get_unix_prot( vprot ) & PROT_READ) ||
                    !(get_unix_prot( get_translated_host_page_vprot(
                        (void *)((host + cursor) & ~host_page_mask) )) & PROT_READ)) goto done;
            }
            else if (!(vprot & (VPROT_WRITE | VPROT_WRITECOPY)) ||
                     (vprot & (VPROT_EXEC | VPROT_WRITEWATCH))) goto done;
            cursor += span;
        }
        if (!write_to_file && check_translated_write_access( (void *)host, size, &write_watch ))
            goto done;
        if (write_to_file)
            ret = positioned ? pwrite( fd, (void *)host, size, offset ) : write( fd, (void *)host, size );
        else
            ret = positioned ? pread( fd, (void *)host, size, offset ) : read( fd, (void *)host, size );
        saved_errno = errno;
    done:
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        errno = saved_errno;
        return ret;
    }
    if (is_arm64ec() && size && host_page_size > page_size && !overlaps_wow64_shadow( addr, size ))
    {
        ULONG_PTR start = (ULONG_PTR)addr;
        SIZE_T cursor;
        sigset_t sigset;
        ssize_t ret = -1;
        int saved_errno = EFAULT;
        BOOL has_write_watch = FALSE;
        BOOL delegated = wow64_memory_logical_write_fault_is_delegated();

        if (!start || size > ~(ULONG_PTR)0 - start)
        {
            errno = EFAULT;
            return -1;
        }
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        /* The kernel sees the union of permissions for a 16K host page.
         * Check each Wine-owned 4K lane before the first byte is transferred.
         * Native/system allocations retain the existing kernel access check. */
        for (cursor = 0; cursor < size; )
        {
            void *page = (void *)(start + cursor);
            SIZE_T span = min( size - cursor, page_size - ((start + cursor) & page_mask) );
            struct file_view *view = find_view( page, span );

            if (view && !(view->protect & VPROT_SYSTEM))
            {
                BYTE vprot = get_page_vprot( page );
                int required = write_to_file ? PROT_READ : PROT_WRITE;

                /* SEC_RESERVE aliases share commitment through the server. */
                if ((view->protect & SEC_RESERVE) && !(vprot & VPROT_COMMITTED))
                    get_committed_size( view, page, span, &vprot, VPROT_COMMITTED );
                if (!(get_unix_prot( vprot & ~VPROT_WRITEWATCH ) & required)) goto high_done;
            }
            cursor += span;
        }
        if (write_to_file)
            ret = positioned ? pwrite( fd, addr, size, offset ) : write( fd, addr, size );
        else
        {
            /* Preserve virtual_locked_read/pread's native write-watch fallback.
             * Do not reacquire virtual_mutex or drop it between check and I/O. */
            ret = positioned ? pread( fd, addr, size, offset ) : read( fd, addr, size );
            if (ret == -1 && !use_kernel_writewatch && errno == EFAULT &&
                !check_write_access( addr, size, &has_write_watch ))
            {
                ret = positioned ? pread( fd, addr, size, offset ) : read( fd, addr, size );
                if (has_write_watch && !delegated)
                    update_write_watches( addr, size, max( 0, ret ));
            }
        }
        saved_errno = errno;
    high_done:
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        if (!write_to_file && has_write_watch && delegated && ret > 0)
            wow64_memory_publish_native_write_or_abort( addr, ret );
        errno = saved_errno;
        return ret;
    }
#endif
    if (write_to_file) return positioned ? pwrite( fd, addr, size, offset ) : write( fd, addr, size );
    return positioned ? virtual_locked_pread( fd, addr, size, offset ) : virtual_locked_read( fd, addr, size );
}


/***********************************************************************
 *           virtual_locked_read
 */
ssize_t virtual_locked_read( int fd, void *addr, size_t size )
{
    sigset_t sigset;
    BOOL has_write_watch = FALSE;
    BOOL delegated_write_fault = FALSE;
    int err = EFAULT;
    ssize_t ret;

    /* A translated 4K lane can be logically inaccessible while an adjacent
     * lane keeps the shared 16K host page writable.  Validate the logical
     * protections before letting the kernel copy into any shadow range. */
    if (!overlaps_wow64_shadow( addr, size ))
    {
        ret = read( fd, addr, size );
        if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;
    }
    else ret = -1;

#if defined(__APPLE__) && defined(__aarch64__)
    delegated_write_fault = wow64_memory_logical_write_fault_is_delegated();
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!check_write_access( addr, size, &has_write_watch ))
    {
        ret = read( fd, addr, size );
        err = errno;
        if (has_write_watch && !delegated_write_fault)
            update_write_watches( addr, size, max( 0, ret ));
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    if (has_write_watch && delegated_write_fault && ret > 0)
        wow64_memory_publish_native_write_or_abort( addr, ret );
#endif
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_pread
 */
ssize_t virtual_locked_pread( int fd, void *addr, size_t size, off_t offset )
{
    sigset_t sigset;
    BOOL has_write_watch = FALSE;
    BOOL delegated_write_fault = FALSE;
    int err = EFAULT;
    ssize_t ret;

    if (!overlaps_wow64_shadow( addr, size ))
    {
        ret = pread( fd, addr, size, offset );
        if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;
    }
    else ret = -1;

#if defined(__APPLE__) && defined(__aarch64__)
    delegated_write_fault = wow64_memory_logical_write_fault_is_delegated();
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!check_write_access( addr, size, &has_write_watch ))
    {
        ret = pread( fd, addr, size, offset );
        err = errno;
        if (has_write_watch && !delegated_write_fault)
            update_write_watches( addr, size, max( 0, ret ));
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    if (has_write_watch && delegated_write_fault && ret > 0)
        wow64_memory_publish_native_write_or_abort( addr, ret );
#endif
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_recvmsg
 */
ssize_t virtual_locked_recvmsg( int fd, struct msghdr *hdr, int flags )
{
    sigset_t sigset;
    size_t accessed, i, j, remaining;
    BOOL has_write_watch = FALSE;
    BOOL delegated_write_fault = FALSE;
    BOOL shadow = FALSE;
    int err = EFAULT;
    ssize_t ret;

    for (i = 0; i < hdr->msg_iovlen; i++)
        if (overlaps_wow64_shadow( hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len ))
        {
            shadow = TRUE;
            break;
        }
    if (!shadow)
    {
        ret = recvmsg( fd, hdr, flags );
        if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;
    }
    else ret = -1;

#if defined(__APPLE__) && defined(__aarch64__)
    delegated_write_fault = wow64_memory_logical_write_fault_is_delegated();
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < hdr->msg_iovlen; i++)
        if (check_write_access( hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len, &has_write_watch ))
            break;
    if (i == hdr->msg_iovlen)
    {
        ret = recvmsg( fd, hdr, flags );
        err = errno;
    }
    if (has_write_watch && !delegated_write_fault)
    {
        remaining = ret > 0 ? ret : 0;
        for (j = 0; j < i; j++)
        {
            accessed = min( hdr->msg_iov[j].iov_len, remaining );
            update_write_watches( hdr->msg_iov[j].iov_base, hdr->msg_iov[j].iov_len, accessed );
            remaining -= accessed;
        }
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    if (has_write_watch && delegated_write_fault && ret > 0)
    {
        remaining = ret;
        for (j = 0; j < i && remaining; j++)
        {
            accessed = min( hdr->msg_iov[j].iov_len, remaining );
            if (accessed)
                wow64_memory_publish_native_write_or_abort( hdr->msg_iov[j].iov_base,
                                                             accessed );
            remaining -= accessed;
        }
    }
#endif
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_sendmsg
 */
ssize_t virtual_locked_sendmsg( int fd, const struct msghdr *hdr, int flags )
{
    sigset_t sigset;
    BOOL shadow = FALSE;
    size_t i;
    int err = EFAULT;
    ssize_t ret = -1;

    for (i = 0; i < hdr->msg_iovlen; i++)
        if (overlaps_wow64_shadow( hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len ))
        {
            shadow = TRUE;
            break;
        }
    if (!shadow) return sendmsg( fd, hdr, flags );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < hdr->msg_iovlen; i++)
        if (!check_wow64_translated_memory_access( hdr->msg_iov[i].iov_base,
                                                   hdr->msg_iov[i].iov_len, PROT_READ ))
            break;
    if (i == hdr->msg_iovlen)
    {
        ret = sendmsg( fd, hdr, flags );
        err = errno;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_send
 */
ssize_t virtual_locked_send( int fd, const void *buffer, size_t size, int flags )
{
    struct iovec iov = {(void *)buffer, size};
    struct msghdr hdr = {0};

    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    return virtual_locked_sendmsg( fd, &hdr, flags );
}


/***********************************************************************
 *           virtual_locked_ioctl
 *
 * Keep a kernel ioctl from observing the physical 16K permission of a
 * logically inaccessible translated 4K input or output lane.  This avoids
 * eager bounce allocations for direct-I/O controls while serializing guest
 * reprotection for the duration of the kernel access.
 */
int virtual_locked_ioctl( int fd, unsigned long request, void *arg,
                          const void *read_buffer, SIZE_T read_size,
                          void *write_buffer, SIZE_T write_size )
{
    BOOL has_write_watch = FALSE, delegated = FALSE;
#if defined(__APPLE__) && defined(__aarch64__)
    BOOL accessed = FALSE;
#endif
    BOOL shadow_read = overlaps_wow64_shadow( read_buffer, read_size );
    BOOL shadow_write = overlaps_wow64_shadow( write_buffer, write_size );
    sigset_t sigset;
    int err = EFAULT, ret = -1;

    if (!shadow_read && !shadow_write) return ioctl( fd, request, arg );
#if defined(__APPLE__) && defined(__aarch64__)
    delegated = wow64_memory_logical_write_fault_is_delegated();
#endif
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((!shadow_read || check_wow64_translated_memory_access( read_buffer, read_size,
                                                               PROT_READ )) &&
        (!shadow_write || !check_write_access( write_buffer, write_size,
                                                &has_write_watch )))
    {
#if defined(__APPLE__) && defined(__aarch64__)
        accessed = TRUE;
#endif
        ret = ioctl( fd, request, arg );
        err = errno;
        /* An ioctl may publish partial output even when it reports failure.
         * Conservatively dirty the requested output range. */
        if (has_write_watch && !delegated)
            update_write_watches( write_buffer, write_size, write_size );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    if (accessed && has_write_watch && delegated)
        wow64_memory_publish_native_write_or_abort( write_buffer, write_size );
#endif
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_is_valid_code_address
 */
BOOL virtual_is_valid_code_address( const void *addr, SIZE_T size )
{
    struct file_view *view;
    BOOL ret = FALSE;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((view = find_view( addr, size )))
        ret = !(view->protect & VPROT_SYSTEM);  /* system views are not visible to the app */
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_check_buffer_for_read
 *
 * Check if a memory buffer can be read, triggering page faults if needed for DIB section access.
 */
BOOL virtual_check_buffer_for_read( const void *ptr, SIZE_T size )
{
    if (!size) return TRUE;
    if (!ptr) return FALSE;
    if (!virtual_check_wow64_translated_memory_access( ptr, size, PROT_READ )) return FALSE;

    __TRY
    {
        volatile const char *p = ptr;
        char dummy __attribute__((unused));
        SIZE_T count = size;

        while (count > host_page_size)
        {
            dummy = *p;
            p += host_page_size;
            count -= host_page_size;
        }
        dummy = p[0];
        dummy = p[count - 1];
    }
    __EXCEPT
    {
        return FALSE;
    }
    __ENDTRY
    return TRUE;
}


/***********************************************************************
 *           virtual_check_buffer_for_write
 *
 * Check if a memory buffer can be written to, triggering page faults if needed for write watches.
 */
BOOL virtual_check_buffer_for_write( void *ptr, SIZE_T size )
{
    if (!size) return TRUE;
    if (!ptr) return FALSE;
    if (!virtual_check_wow64_translated_memory_access( ptr, size, PROT_WRITE )) return FALSE;

    __TRY
    {
        volatile char *p = ptr;
        SIZE_T count = size;

        while (count > host_page_size)
        {
            *p |= 0;
            p += host_page_size;
            count -= host_page_size;
        }
        p[0] |= 0;
        p[count - 1] |= 0;
    }
    __EXCEPT
    {
        return FALSE;
    }
    __ENDTRY
    return TRUE;
}


/***********************************************************************
 *           virtual_check_buffer_for_write_no_touch
 *
 * Validate a completion output without changing its contents or consuming
 * logical guard/write-watch state.
 */
BOOL virtual_check_buffer_for_write_no_touch( void *ptr, SIZE_T size )
{
    BOOL has_write_watch = FALSE;
    sigset_t sigset;
    NTSTATUS status;

    if (!size) return TRUE;
    if (!ptr) return FALSE;
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    status = check_write_access( ptr, size, &has_write_watch );
    if (has_write_watch) update_write_watches( ptr, size, 0 );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return !status;
}


/***********************************************************************
 *           virtual_uninterrupted_read_memory
 *
 * Similar to NtReadVirtualMemory, but without wineserver calls. Moreover
 * permissions are checked before accessing each page, to ensure that no
 * exceptions can happen.
 */
SIZE_T virtual_uninterrupted_read_memory( const void *addr, void *buffer, SIZE_T size )
{
    struct file_view *view;
    sigset_t sigset;
    SIZE_T bytes_read = 0;
    struct memory_access_cache cache = {0};

    if (!size) return 0;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((view = find_view( addr, size )))
    {
        if (!(view->protect & VPROT_SYSTEM))
        {
            while (bytes_read < size)
            {
                SIZE_T available;
                BYTE vprot = get_memory_access_vprot( addr, &available, NULL, &cache );
                SIZE_T block_size = min( size - bytes_read, available );

                if (!(get_unix_prot( vprot ) & PROT_READ)) break;
                memcpy( buffer, addr, block_size );

                addr   = (const void *)((const char *)addr + block_size);
                buffer = (void *)((char *)buffer + block_size);
                bytes_read += block_size;
            }
        }
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return bytes_read;
}


/***********************************************************************
 *           virtual_uninterrupted_write_memory
 *
 * Similar to NtWriteVirtualMemory, but without wineserver calls. Moreover
 * permissions are checked before accessing each page, to ensure that no
 * exceptions can happen.
 */
NTSTATUS virtual_uninterrupted_write_memory( void *addr, const void *buffer, SIZE_T size )
{
    BOOL has_write_watch = FALSE;
    sigset_t sigset;
    NTSTATUS ret;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    void *capture_base;
    SIZE_T capture_size;
    NTSTATUS snapshot_status;
    BOOL delegated_range;
    BOOL stored;
#endif

    if (!size) return STATUS_SUCCESS;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    ret = check_write_access( addr, size, &has_write_watch );
#if defined(__APPLE__) && defined(__aarch64__)
    delegated_range = wow64_memory_logical_write_fault_is_delegated() &&
                      overlaps_wow64_shadow( addr, size );
    if (!ret && has_write_watch && delegated_range)
    {
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        capture_base = ROUND_ADDR( addr, page_mask );
        capture_size = ROUND_SIZE( addr, size, page_mask );
        if (!is_inside_wow64_shadow( capture_base, capture_size ))
            return STATUS_ACCESS_VIOLATION;
        ret = wow64_memory_begin_transaction( &transaction, TRUE,
                                               WINE_WOW64_MEMORY_PROTECT,
                                               capture_base, capture_size, NULL );
        if (ret) return ret;

        has_write_watch = FALSE;
        stored = FALSE;
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        if (!(ret = check_write_access( addr, size, &has_write_watch )))
        {
            memcpy( addr, buffer, size );
            stored = TRUE;
            if (has_write_watch)
            {
                set_page_vprot_bits( capture_base, capture_size, 0, VPROT_WRITEWATCH );
                if (mprotect_memory_access_range( capture_base, capture_size, 0, 0 ))
                    ret = STATUS_ACCESS_DENIED;
            }
        }
        wow64_memory_capture_transaction( &transaction, ret, capture_base,
                                           capture_size, NULL );
        snapshot_status = transaction.event.snapshot_status;
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        wow64_memory_complete_transaction( &transaction );
        if (stored && (ret || snapshot_status))
            abort_process( ret ? ret : snapshot_status );
        return ret ? ret : snapshot_status;
    }
#endif
    if (!ret)
    {
        memcpy( addr, buffer, size );
        if (has_write_watch)
            update_write_watches( addr, size, size );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_copy_from_user
 *
 * Copy from a current-process WoW64 user buffer without letting Darwin's
 * 16K host protection widen a translated 4K guest page.  Ordinary address
 * spaces keep the established fault behavior and avoid the virtual lock.
 */
NTSTATUS virtual_copy_from_user( void *dst, const void *src, SIZE_T size )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!size) return STATUS_SUCCESS;
    if (!dst || !src) return STATUS_ACCESS_VIOLATION;
#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( src, size ))
    {
        struct memory_access_cache cache = {0};
        const char *addr = src;
        char *buffer = dst;
        SIZE_T remaining = size;
        sigset_t sigset;

        if (!is_inside_wow64_shadow( src, size )) return STATUS_ACCESS_VIOLATION;
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        while (remaining)
        {
            SIZE_T available;
            BYTE vprot = get_memory_access_vprot( addr, &available, NULL, &cache );

            if (vprot & VPROT_GUARD)
            {
                struct wine_wow64_memory_fault_result_v1 result =
                {
                    .version = WINE_WOW64_MEMORY_FAULT_VERSION,
                    .size = sizeof(result),
                };

                server_leave_uninterrupted_section( &virtual_mutex, &sigset );
                status = __wine_resolve_wow64_memory_fault_v1( (ULONG_PTR)addr,
                            WINE_WOW64_MEMORY_FAULT_READ, &result );
                if (status) return status;
                if (result.action != WINE_WOW64_MEMORY_FAULT_RETRY) return result.status;
                memset( &cache, 0, sizeof(cache) );
                server_enter_uninterrupted_section( &virtual_mutex, &sigset );
                continue;
            }
            if (!(get_unix_prot( vprot ) & PROT_READ))
            {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }
            available = min( available, remaining );
            memcpy( buffer, addr, available );
            addr += available;
            buffer += available;
            remaining -= available;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        return status;
    }
#endif
    __TRY
    {
        memcpy( dst, src, size );
    }
    __EXCEPT
    {
        status = get_thread_data()->jmp_status;
    }
    __ENDTRY
    return status;
}


/***********************************************************************
 *           virtual_copy_string_from_user
 *
 * Snapshot a NUL-terminated current-process user string without reading
 * beyond the logical page containing its terminator.  The caller supplies
 * the resource bound and owns the returned allocation.
 */
NTSTATUS virtual_copy_string_from_user( char **dst, const char *src, SIZE_T max_size )
{
    SIZE_T capacity = 0, length = 0;
    char *buffer = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!dst) return STATUS_INVALID_PARAMETER;
    *dst = NULL;
    if (!src) return STATUS_ACCESS_VIOLATION;
    if (!max_size) return STATUS_NAME_TOO_LONG;

    while (length < max_size)
    {
        ULONG_PTR address = (ULONG_PTR)src + length;
        SIZE_T chunk, required;
        char *terminator, *new_buffer;

        if (address < (ULONG_PTR)src) { status = STATUS_ACCESS_VIOLATION; break; }
        chunk = min( max_size - length, page_size - (address & page_mask) );
        required = length + chunk;
        if (required > capacity)
        {
            SIZE_T new_capacity = min( max_size, max( required, capacity ? 2 * capacity : 256 ));

            if (new_capacity < required || (capacity && new_capacity < capacity))
            {
                status = STATUS_NO_MEMORY;
                break;
            }
            if (!(new_buffer = realloc( buffer, new_capacity )))
            {
                status = STATUS_NO_MEMORY;
                break;
            }
            buffer = new_buffer;
            capacity = new_capacity;
        }
        if ((status = virtual_copy_from_user( buffer + length, (const void *)address, chunk )))
            break;
        if ((terminator = memchr( buffer + length, 0, chunk )))
        {
            *dst = buffer;
            return STATUS_SUCCESS;
        }
        length += chunk;
    }
    free( buffer );
    return status ? status : STATUS_NAME_TOO_LONG;
}


/***********************************************************************
 *           virtual_copy_to_user
 */
NTSTATUS virtual_copy_to_user( void *dst, const void *src, SIZE_T size )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!size) return STATUS_SUCCESS;
    if (!dst || !src) return STATUS_ACCESS_VIOLATION;
#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( dst, size ))
    {
        if (!is_inside_wow64_shadow( dst, size )) return STATUS_ACCESS_VIOLATION;
        status = virtual_uninterrupted_write_memory( dst, src, size );
        return status ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    }
#endif
    __TRY
    {
        memcpy( dst, src, size );
    }
    __EXCEPT
    {
        status = get_thread_data()->jmp_status;
    }
    __ENDTRY
    return status;
}


/***********************************************************************
 *           wow64_probe_user_read
 */
NTSTATUS wow64_probe_user_read( const void *ptr, SIZE_T size )
{
    BYTE value;
    SIZE_T offset = 0;
    NTSTATUS status;

    if (!size) return STATUS_SUCCESS;
    if (!ptr) return STATUS_ACCESS_VIOLATION;
#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( ptr, size ))
    {
        if (!is_inside_wow64_shadow( ptr, size ) ||
            !virtual_check_wow64_translated_memory_access( ptr, size, PROT_READ ))
            return STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }
#endif
    while (offset < size)
    {
        status = virtual_copy_from_user( &value, (const char *)ptr + offset, 1 );
        if (status) return status;
        offset += min( host_page_size - (((ULONG_PTR)ptr + offset) & host_page_mask),
                       size - offset );
    }
    return virtual_copy_from_user( &value, (const char *)ptr + size - 1, 1 );
}


/***********************************************************************
 *           wow64_probe_user_write
 */
NTSTATUS wow64_probe_user_write( void *ptr, SIZE_T size )
{
    if (!size) return STATUS_SUCCESS;
    if (!ptr) return STATUS_ACCESS_VIOLATION;
#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( ptr, size ))
    {
        if (!is_inside_wow64_shadow( ptr, size ) ||
            !virtual_check_buffer_for_write_no_touch( ptr, size ))
            return STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }
#endif
    return virtual_check_buffer_for_write( ptr, size ) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
}


static NTSTATUS wow64_prepare_faulting_write_user( void *dst, SIZE_T size )
{
    if (!size) return STATUS_SUCCESS;
    if (!dst) return STATUS_ACCESS_VIOLATION;
#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( dst, size ))
    {
        ULONG_PTR start = (ULONG_PTR)dst, cursor;

        if (!is_inside_wow64_shadow( dst, size )) return STATUS_ACCESS_VIOLATION;
        cursor = start + size;

        /* Walk high to low before publishing any byte.  Stack frames extend
         * down from the old SP, so this reaches and resolves each guard page
         * in order instead of rejecting a large frame at an uncommitted page
         * below the current guard. */
        while (cursor > start)
        {
            struct wine_wow64_memory_fault_result_v1 result =
            {
                .version = WINE_WOW64_MEMORY_FAULT_VERSION,
                .size = sizeof(result),
            };
            struct memory_access_cache cache = {0};
            ULONG_PTR page = (cursor - 1) & ~page_mask;
            SIZE_T available;
            BYTE vprot;
            NTSTATUS status;
            sigset_t sigset;

            server_enter_uninterrupted_section( &virtual_mutex, &sigset );
            vprot = get_memory_access_vprot( (void *)(cursor - 1), &available, NULL, &cache );
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            /* Resolve guards to preserve direct-store stack growth and guard
             * exceptions.  Ordinary write-watch state is consumed only by
             * the final copy; clearing it during preflight would mark an
             * earlier page dirty even if a later page rejects the frame. */
            if ((vprot & VPROT_GUARD) ||
                (enable_write_exceptions && (vprot & VPROT_WRITEWATCH) &&
                 is_vprot_exec_write( vprot )))
            {
                status = __wine_resolve_wow64_memory_fault_v1( cursor - 1,
                            WINE_WOW64_MEMORY_FAULT_WRITE, &result );
                if (status) return status;
                if (result.action != WINE_WOW64_MEMORY_FAULT_RETRY) return result.status;
                continue;
            }
            if (!(get_unix_prot( vprot & ~VPROT_WRITEWATCH ) & PROT_WRITE))
                return STATUS_ACCESS_VIOLATION;
            cursor = max( page, start );
        }

        return STATUS_SUCCESS;
    }
#endif
    {
        ULONG_PTR start = (ULONG_PTR)dst, cursor = start + size;

        /* Low-identity WoW64 can rely on native host-page faults, but the pair
         * and ownership-returning publishers still have to resolve guards
         * before their all-or-nothing validation/store interval.  Touch only
         * guard pages; ordinary write-watch pages must remain armed until the
         * final store succeeds. */
        while (cursor > start)
        {
            struct memory_access_cache cache = {0};
            ULONG_PTR page = (cursor - 1) & ~host_page_mask;
            NTSTATUS status = STATUS_SUCCESS;
            SIZE_T available;
            BYTE vprot;
            sigset_t sigset;

            server_enter_uninterrupted_section( &virtual_mutex, &sigset );
            vprot = get_memory_access_vprot( (void *)(cursor - 1), &available, NULL, &cache );
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            if (vprot & VPROT_GUARD)
            {
                EXCEPTION_RECORD rec = {0};

                rec.NumberParameters = 2;
                rec.ExceptionInformation[0] = EXCEPTION_WRITE_FAULT;
                rec.ExceptionInformation[1] = cursor - 1;
                status = virtual_handle_fault( get_thread_data(), &rec,
                                                __builtin_frame_address(0) );
                if (status) return status;
                continue;
            }
            if (enable_write_exceptions && (vprot & VPROT_WRITEWATCH) &&
                is_vprot_exec_write( vprot ) && !get_thread_data()->allow_writes)
                return STATUS_IN_PAGE_ERROR;
            if (!(get_unix_prot( vprot & ~VPROT_WRITEWATCH ) & PROT_WRITE))
                return STATUS_ACCESS_VIOLATION;
            cursor = max( page, start );
        }
    }
    return STATUS_SUCCESS;
}


static NTSTATUS wow64_faulting_write_user( void *dst, const void *src, SIZE_T size )
{
    NTSTATUS status;

    if (!size) return STATUS_SUCCESS;
    if (!dst || !src) return STATUS_ACCESS_VIOLATION;
    if ((status = wow64_prepare_faulting_write_user( dst, size ))) return status;

    /* The checked copy takes virtual_mutex once and only publishes after the
     * complete frame has passed logical protection validation. */
    return virtual_copy_to_user( dst, src, size );
}


/***********************************************************************
 *           virtual_faulting_copy_to_user
 *
 * Preserve the fault behavior of a direct current-process user store.
 * Native I/O preflight paths use virtual_copy_to_user() instead; this
 * variant is for fixed Unix-call outputs that the old code dereferenced.
 */
NTSTATUS virtual_faulting_copy_to_user( void *dst, const void *src, SIZE_T size )
{
    return wow64_faulting_write_user( dst, src, size );
}


static NTSTATUS wow64_atomic_write_user( void *dst, const void *src, SIZE_T size )
{
    NTSTATUS status;

    if (!size) return STATUS_SUCCESS;
    if (!dst || !src) return STATUS_ACCESS_VIOLATION;
    if ((status = wow64_prepare_faulting_write_user( dst, size ))) return status;

    /* Unlike an ordinary direct thunk copy, callers of this operation own a
     * newly-created handle/object that must be rolled back on failure.  The
     * uninterrupted helper validates the complete range and stores it under a
     * single virtual-lock interval on both high-shadow and low-identity paths. */
    status = virtual_uninterrupted_write_memory( dst, src, size );
    return status ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}


/***********************************************************************
 *           ntdll_wow64_guest32_to_host  (ntdll.so)
 */
static BOOL get_current_wow64_user_model( BOOL *shadow )
{
#ifdef _WIN64
    WOW_TEB *wow_teb = get_wow_teb( NtCurrentTeb() );
    ULONG_PTR address = (ULONG_PTR)wow_teb;

    if (!wow_teb) return FALSE;
    *shadow = address >= WINE_LOW_VA_SHADOW_BASE &&
              address - WINE_LOW_VA_SHADOW_BASE < WINE_LOW_VA_SHADOW_SIZE;
#else
    *shadow = FALSE;
#endif
    return TRUE;
}


static BOOL is_current_wow64_user_range( const void *ptr, SIZE_T size, BOOL shadow )
{
    ULONG_PTR address = (ULONG_PTR)ptr;

    if (!size) return TRUE;
    if (!ptr) return FALSE;
    if (shadow)
        return size <= WINE_LOW_VA_SHADOW_SIZE &&
               address >= WINE_LOW_VA_SHADOW_BASE &&
               address - WINE_LOW_VA_SHADOW_BASE <= WINE_LOW_VA_SHADOW_SIZE - size;
    return address <= MAXDWORD && size <= 0x100000000ull - address;
}


NTSTATUS ntdll_wow64_guest32_to_host( ULONG address, void **host )
{
    BOOL shadow;

    if (!host) return STATUS_INVALID_PARAMETER;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    *host = !address ? NULL : shadow ?
            (void *)(ULONG_PTR)(WINE_LOW_VA_SHADOW_BASE + address) :
            (void *)(ULONG_PTR)address;
    return STATUS_SUCCESS;
}


/* Convert a current-process WoW64 host pointer back to its canonical 32-bit
 * address.  The active paired TEB is authoritative: identity callers may not
 * smuggle shadow pointers and translated callers may not smuggle low host
 * pointers into a native Unix-library call context. */
NTSTATUS virtual_wow64_host_to_guest32( const void *host, SIZE_T size, ULONG *guest )
{
    ULONG_PTR address = (ULONG_PTR)host;
    BOOL shadow;

    if (!guest) return STATUS_INVALID_PARAMETER;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    if (!size)
    {
        *guest = 0;
        return STATUS_SUCCESS;
    }
    if (!is_current_wow64_user_range( host, size, shadow ))
        return STATUS_ACCESS_VIOLATION;
    if (shadow) address -= WINE_LOW_VA_SHADOW_BASE;
    if (!address) return STATUS_ACCESS_VIOLATION;
    *guest = address;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           ntdll_wow64_copy_from_user  (ntdll.so)
 */
NTSTATUS ntdll_wow64_copy_from_user( void *dst, const void *src, SIZE_T size )
{
    BOOL shadow;

    if (!size) return STATUS_SUCCESS;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    if (!is_current_wow64_user_range( src, size, shadow ))
        return STATUS_ACCESS_VIOLATION;
    return virtual_copy_from_user( dst, src, size );
}


/***********************************************************************
 *           ntdll_wow64_copy_to_user  (ntdll.so)
 */
NTSTATUS ntdll_wow64_copy_to_user( void *dst, const void *src, SIZE_T size )
{
    BOOL shadow;

    if (!size) return STATUS_SUCCESS;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    if (!is_current_wow64_user_range( dst, size, shadow ))
        return STATUS_ACCESS_VIOLATION;
    return virtual_copy_to_user( dst, src, size );
}


/***********************************************************************
 *           ntdll_wow64_faulting_copy_to_user  (ntdll.so)
 */
NTSTATUS ntdll_wow64_faulting_copy_to_user( void *dst, const void *src, SIZE_T size )
{
    BOOL shadow;

    if (!size) return STATUS_SUCCESS;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    if (!is_current_wow64_user_range( dst, size, shadow ))
        return STATUS_ACCESS_VIOLATION;
    return wow64_faulting_write_user( dst, src, size );
}


/***********************************************************************
 *           ntdll_wow64_atomic_write_user  (ntdll.so)
 */
NTSTATUS ntdll_wow64_atomic_write_user( void *dst, const void *src, SIZE_T size )
{
    BOOL shadow;

    if (!size) return STATUS_SUCCESS;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    if (!is_current_wow64_user_range( dst, size, shadow ))
        return STATUS_ACCESS_VIOLATION;
    return wow64_atomic_write_user( dst, src, size );
}


/***********************************************************************
 *           ntdll_wow64_probe_user_writev  (ntdll.so)
 */
NTSTATUS ntdll_wow64_probe_user_writev(
    const struct ntdll_wow64_user_write_range *ranges, ULONG count )
{
    struct ntdll_wow64_user_write_range local[NTDLL_WOW64_USER_WRITEV_MAX];
    BOOL has_write_watch = FALSE;
    BOOL shadow;
    sigset_t sigset;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;

    if (!count) return STATUS_SUCCESS;
    if (!ranges || count > ARRAY_SIZE(local)) return STATUS_INVALID_PARAMETER;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    memcpy( local, ranges, count * sizeof(*local) );

    for (i = 0; i < count; i++)
    {
        if (!local[i].size) continue;
        if (!is_current_wow64_user_range( local[i].dst, local[i].size, shadow ))
            return STATUS_ACCESS_VIOLATION;
        if ((status = wow64_prepare_faulting_write_user( local[i].dst,
                                                          local[i].size )))
            return status;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < count && !status; i++)
    {
        if (!local[i].size) continue;
        has_write_watch = FALSE;
        status = validate_write_access( local[i].dst, local[i].size,
                                        &has_write_watch );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}


/***********************************************************************
 *           ntdll_wow64_atomic_writev  (ntdll.so)
 *
 * Validate every destination before opening write-watch backing or storing a
 * byte.  All stores then run under one virtual_mutex interval, so a concurrent
 * protection change cannot split ownership publication.  Later overlapping
 * ranges win, matching native-order scalar publication.
 */
NTSTATUS ntdll_wow64_atomic_writev(
    const struct ntdll_wow64_user_write_range *ranges, ULONG count )
{
    struct ntdll_wow64_user_write_range local[NTDLL_WOW64_USER_WRITEV_MAX];
    BOOL watches[NTDLL_WOW64_USER_WRITEV_MAX] = {0};
    BOOL delegated = FALSE;
    BOOL shadow;
    sigset_t sigset;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;

    if (!count) return STATUS_SUCCESS;
    if (!ranges || count > ARRAY_SIZE(local)) return STATUS_INVALID_PARAMETER;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    memcpy( local, ranges, count * sizeof(*local) );

    for (i = 0; i < count; i++)
    {
        if (!local[i].size) continue;
        if (!local[i].src ||
            !is_current_wow64_user_range( local[i].dst, local[i].size, shadow ))
            return STATUS_ACCESS_VIOLATION;
        if ((status = wow64_prepare_faulting_write_user( local[i].dst,
                                                          local[i].size )))
            return status;
    }

#if defined(__APPLE__) && defined(__aarch64__)
    delegated = wow64_memory_logical_write_fault_is_delegated();
#endif
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < count && !status; i++)
    {
        if (!local[i].size) continue;
        status = validate_write_access( local[i].dst, local[i].size,
                                        &watches[i] );
    }
    for (i = 0; i < count && !status; i++)
    {
        if (!local[i].size) continue;
        status = check_write_access( local[i].dst, local[i].size, &watches[i] );
    }
    if (!status)
    {
        for (i = 0; i < count; i++)
            if (local[i].size) memcpy( local[i].dst, local[i].src, local[i].size );
    }
    if (!delegated)
    {
        for (i = 0; i < count; i++)
            if (watches[i])
                update_write_watches( local[i].dst, local[i].size,
                                      status ? 0 : local[i].size );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (status) return STATUS_ACCESS_VIOLATION;

#if defined(__APPLE__) && defined(__aarch64__)
    if (delegated)
    {
        for (i = 0; i < count; i++)
            if (watches[i])
                wow64_memory_publish_native_write_or_abort( local[i].dst,
                                                             local[i].size );
    }
#endif
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           ntdll_wow64_probe_user_read  (ntdll.so)
 */
NTSTATUS ntdll_wow64_probe_user_read( const void *src, SIZE_T size )
{
    BOOL shadow;

    if (!size) return STATUS_SUCCESS;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    if (!is_current_wow64_user_range( src, size, shadow ))
        return STATUS_ACCESS_VIOLATION;
    return wow64_probe_user_read( src, size );
}


/***********************************************************************
 *           ntdll_wow64_probe_user_write  (ntdll.so)
 */
NTSTATUS ntdll_wow64_probe_user_write( void *dst, SIZE_T size )
{
    BOOL shadow;

    if (!size) return STATUS_SUCCESS;
    if (!get_current_wow64_user_model( &shadow )) return STATUS_INVALID_PARAMETER;
    if (!is_current_wow64_user_range( dst, size, shadow ))
        return STATUS_ACCESS_VIOLATION;
    return wow64_probe_user_write( dst, size );
}


NTSTATUS virtual_publish_wow64_ulong_pair( ULONG *dst1, ULONG value1,
                                           ULONG *dst2, ULONG value2 )
{
    BOOL watch1 = FALSE, watch2 = FALSE;
    BOOL delegated = FALSE;
    sigset_t sigset;
    NTSTATUS status;

    if (!dst1 || !dst2) return STATUS_ACCESS_VIOLATION;
    if ((status = wow64_prepare_faulting_write_user( dst1, sizeof(*dst1) ))) return status;
    if ((status = wow64_prepare_faulting_write_user( dst2, sizeof(*dst2) ))) return status;

#if defined(__APPLE__) && defined(__aarch64__)
    if ((overlaps_wow64_shadow( dst1, sizeof(*dst1) ) &&
         !is_inside_wow64_shadow( dst1, sizeof(*dst1) )) ||
        (overlaps_wow64_shadow( dst2, sizeof(*dst2) ) &&
         !is_inside_wow64_shadow( dst2, sizeof(*dst2) )))
        return STATUS_ACCESS_VIOLATION;
    delegated = wow64_memory_logical_write_fault_is_delegated();
#endif

    /* Validate both cells before either store on every host.  This is a cold
     * ownership-publication path; taking virtual_mutex also prevents a second
     * thread from reprotecting one cell between validation and publication. */
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    status = check_write_access( dst1, sizeof(*dst1), &watch1 );
    if (!status) status = check_write_access( dst2, sizeof(*dst2), &watch2 );
    if (!status)
    {
        memcpy( dst1, &value1, sizeof(value1) );
        memcpy( dst2, &value2, sizeof(value2) );
    }
    if (watch1 && !delegated)
        update_write_watches( dst1, sizeof(*dst1), status ? 0 : sizeof(*dst1) );
    if (watch2 && !delegated)
        update_write_watches( dst2, sizeof(*dst2), status ? 0 : sizeof(*dst2) );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (status) return STATUS_ACCESS_VIOLATION;

#if defined(__APPLE__) && defined(__aarch64__)
    /* Provider write-fault state may remain conservatively armed between the
     * native stores and these short publications; it never widens guest access. */
    if (watch1 && delegated)
        wow64_memory_publish_native_write_or_abort( dst1, sizeof(*dst1) );
    if (watch2 && delegated && dst2 != dst1)
        wow64_memory_publish_native_write_or_abort( dst2, sizeof(*dst2) );
#endif
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           virtual_run_wow64_non_mz_create_process
 *
 * A successful Unix-image launch cannot be rolled back after the detached
 * grandchild has exec'd.  Keep the three deterministic WoW64 outputs stable
 * under virtual_mutex, run the native launch, and publish them only if the
 * launch succeeds.  This is deliberately a cold, process-creation-only path;
 * holding the VM lock avoids a preflight/reprotect race without weakening the
 * ordinary syscall fast paths.
 */
NTSTATUS virtual_run_wow64_non_mz_create_process(
    const struct wine_wow64_create_user_process_params *params,
    NTSTATUS (*operation)(void *context), void *context )
{
    ULONG *process_handle = (void *)(ULONG_PTR)params->guest_process_handle;
    ULONG *thread_handle = (void *)(ULONG_PTR)params->guest_thread_handle;
    void *create_info = (void *)(ULONG_PTR)params->guest_create_info;
    const void *create_info_src = (const void *)(ULONG_PTR)params->non_mz_create_info;
    SIZE_T create_info_size = params->non_mz_create_info_size;
    BYTE create_info_copy[256];
    BOOL process_watch = FALSE, thread_watch = FALSE, info_watch = FALSE;
    BOOL delegated = FALSE;
    ULONG zero = 0;
    sigset_t sigset;
    NTSTATUS status;

    if (!operation || !process_handle || !thread_handle || !create_info ||
        !create_info_src || !create_info_size || create_info_size > sizeof(create_info_copy))
        return STATUS_INVALID_PARAMETER;
    if ((status = virtual_copy_from_user( create_info_copy, create_info_src,
                                          create_info_size )))
        return status;
    if ((status = wow64_prepare_faulting_write_user( create_info, create_info_size )))
        return status;
    if ((status = wow64_prepare_faulting_write_user( process_handle,
                                                      sizeof(*process_handle) )))
        return status;
    if ((status = wow64_prepare_faulting_write_user( thread_handle,
                                                      sizeof(*thread_handle) )))
        return status;

#if defined(__APPLE__) && defined(__aarch64__)
    if ((overlaps_wow64_shadow( create_info, create_info_size ) &&
         !is_inside_wow64_shadow( create_info, create_info_size )) ||
        (overlaps_wow64_shadow( process_handle, sizeof(*process_handle) ) &&
         !is_inside_wow64_shadow( process_handle, sizeof(*process_handle) )) ||
        (overlaps_wow64_shadow( thread_handle, sizeof(*thread_handle) ) &&
         !is_inside_wow64_shadow( thread_handle, sizeof(*thread_handle) )))
        return STATUS_ACCESS_VIOLATION;
    delegated = wow64_memory_logical_write_fault_is_delegated();
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    status = validate_write_access( create_info, create_info_size, &info_watch );
    if (!status)
        status = validate_write_access( process_handle, sizeof(*process_handle),
                                        &process_watch );
    if (!status)
        status = validate_write_access( thread_handle, sizeof(*thread_handle),
                                        &thread_watch );
    if (status)
    {
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        return STATUS_ACCESS_VIOLATION;
    }

    status = operation( context );
    if (!status)
    {
        /* Protection cannot change while virtual_mutex is held.  A failure to
         * expose a previously validated write-watch page after the process has
         * launched is an unrecoverable host/provider invariant violation. */
        if (check_write_access( create_info, create_info_size, &info_watch ) ||
            check_write_access( process_handle, sizeof(*process_handle),
                                &process_watch ) ||
            check_write_access( thread_handle, sizeof(*thread_handle),
                                &thread_watch ))
            abort_process( STATUS_ACCESS_DENIED );
        memcpy( create_info, create_info_copy, create_info_size );
        memcpy( process_handle, &zero, sizeof(zero) );
        memcpy( thread_handle, &zero, sizeof(zero) );
    }
    if (info_watch && !delegated)
        update_write_watches( create_info, create_info_size,
                              status ? 0 : create_info_size );
    if (process_watch && !delegated)
        update_write_watches( process_handle, sizeof(*process_handle),
                              status ? 0 : sizeof(*process_handle) );
    if (thread_watch && !delegated)
        update_write_watches( thread_handle, sizeof(*thread_handle),
                              status ? 0 : sizeof(*thread_handle) );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

#if defined(__APPLE__) && defined(__aarch64__)
    if (!status && delegated)
    {
        if (info_watch)
            wow64_memory_publish_native_write_or_abort( create_info,
                                                        create_info_size );
        if (process_watch)
            wow64_memory_publish_native_write_or_abort( process_handle,
                                                        sizeof(*process_handle) );
        if (thread_watch && thread_handle != process_handle)
            wow64_memory_publish_native_write_or_abort( thread_handle,
                                                        sizeof(*thread_handle) );
    }
#endif
    return status;
}


static NTSTATUS wow64_store_release_long( LONG *dst, LONG value )
{
#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( dst, sizeof(*dst) ))
    {
        struct wow64_memory_transaction transaction;
        BOOL has_write_watch = FALSE;
        sigset_t sigset;
        NTSTATUS status, snapshot_status;
        void *capture_base;
        SIZE_T capture_size;
        BOOL delegated;
        BOOL stored = FALSE;

        if (!is_inside_wow64_shadow( dst, sizeof(*dst) ) ||
            ((ULONG_PTR)dst & (__alignof__(*dst) - 1)))
            return STATUS_ACCESS_VIOLATION;
        capture_base = ROUND_ADDR( dst, page_mask );
        capture_size = ROUND_SIZE( dst, sizeof(*dst), page_mask );
        delegated = wow64_memory_logical_write_fault_is_delegated();
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        status = check_write_access( dst, sizeof(*dst), &has_write_watch );
        if (status || !has_write_watch || !delegated)
        {
            if (!status)
            {
                __atomic_store_n( dst, value, __ATOMIC_RELEASE );
                if (has_write_watch)
                    update_write_watches( dst, sizeof(*dst), sizeof(*dst) );
            }
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            return status ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );

        status = wow64_memory_begin_transaction( &transaction, TRUE,
                    WINE_WOW64_MEMORY_PROTECT, capture_base, capture_size, NULL );
        if (status) return status;
        has_write_watch = FALSE;
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        status = check_write_access( dst, sizeof(*dst), &has_write_watch );
        if (!status)
        {
            __atomic_store_n( dst, value, __ATOMIC_RELEASE );
            stored = TRUE;
        }
        if (!status && has_write_watch)
        {
            set_page_vprot_bits( capture_base, capture_size, 0, VPROT_WRITEWATCH );
            if (mprotect_memory_access_range( capture_base, capture_size, 0, 0 ))
                status = STATUS_ACCESS_DENIED;
        }
        wow64_memory_capture_transaction( &transaction, status, capture_base,
                                           capture_size, NULL );
        snapshot_status = transaction.event.snapshot_status;
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        wow64_memory_complete_transaction( &transaction );
        if (stored && (status || snapshot_status))
            abort_process( status ? status : snapshot_status );
        if (!status) status = snapshot_status;
        return status ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    }
#endif
    {
        NTSTATUS status = STATUS_SUCCESS;

        __TRY
        {
            __atomic_store_n( dst, value, __ATOMIC_RELEASE );
        }
        __EXCEPT
        {
            status = STATUS_ACCESS_VIOLATION;
        }
        __ENDTRY
        return status;
    }
}


/***********************************************************************
 *           virtual_publish_wow64_iosb
 *
 * Publish Information and then Status with release ordering as one checked
 * logical write.  This prevents a 16K host mapping from bypassing a protected
 * 4K translated lane and prevents a protection race between the two fields.
 */
NTSTATUS virtual_publish_wow64_iosb( IO_STATUS_BLOCK32 *dst, NTSTATUS status,
                                     ULONG information )
{
    NTSTATUS ret = STATUS_SUCCESS;

    if (!dst) return STATUS_ACCESS_VIOLATION;
#if defined(__APPLE__) && defined(__aarch64__)
    if (overlaps_wow64_shadow( dst, sizeof(*dst) ))
    {
        struct wow64_memory_transaction transaction;
        BOOL has_write_watch = FALSE;
        sigset_t sigset;
        NTSTATUS snapshot_status;
        void *capture_base;
        SIZE_T capture_size;
        BOOL delegated;
        BOOL stored = FALSE;

        if (!is_inside_wow64_shadow( dst, sizeof(*dst) ) ||
            ((ULONG_PTR)dst & (__alignof__(*dst) - 1)))
            return STATUS_ACCESS_VIOLATION;
        capture_base = ROUND_ADDR( dst, page_mask );
        capture_size = ROUND_SIZE( dst, sizeof(*dst), page_mask );
        delegated = wow64_memory_logical_write_fault_is_delegated();
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        ret = check_write_access( dst, sizeof(*dst), &has_write_watch );
        if (ret || !has_write_watch || !delegated)
        {
            if (!ret)
            {
                dst->Information = information;
                __atomic_store_n( &dst->Status, status, __ATOMIC_RELEASE );
                if (has_write_watch)
                    update_write_watches( dst, sizeof(*dst), sizeof(*dst) );
            }
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            return ret ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );

        ret = wow64_memory_begin_transaction( &transaction, TRUE,
                  WINE_WOW64_MEMORY_PROTECT, capture_base, capture_size, NULL );
        if (ret) return ret;
        has_write_watch = FALSE;
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        ret = check_write_access( dst, sizeof(*dst), &has_write_watch );
        if (!ret)
        {
            dst->Information = information;
            __atomic_store_n( &dst->Status, status, __ATOMIC_RELEASE );
            stored = TRUE;
        }
        if (!ret && has_write_watch)
        {
            set_page_vprot_bits( capture_base, capture_size, 0, VPROT_WRITEWATCH );
            if (mprotect_memory_access_range( capture_base, capture_size, 0, 0 ))
                ret = STATUS_ACCESS_DENIED;
        }
        wow64_memory_capture_transaction( &transaction, ret, capture_base,
                                           capture_size, NULL );
        snapshot_status = transaction.event.snapshot_status;
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        wow64_memory_complete_transaction( &transaction );
        if (stored && (ret || snapshot_status))
            abort_process( ret ? ret : snapshot_status );
        if (!ret) ret = snapshot_status;
        return ret ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    }
#endif
    __TRY
    {
        dst->Information = information;
        __atomic_store_n( &dst->Status, status, __ATOMIC_RELEASE );
    }
    __EXCEPT
    {
        ret = STATUS_ACCESS_VIOLATION;
    }
    __ENDTRY
    return ret;
}


/***********************************************************************
 *           unixcall_wow64_user_copy
 */
C_ASSERT( sizeof(struct wow64_user_copy_params) == 48 );
C_ASSERT( offsetof(struct wow64_user_copy_params, dst) == 0 );
C_ASSERT( offsetof(struct wow64_user_copy_params, src) == 8 );
C_ASSERT( offsetof(struct wow64_user_copy_params, size) == 16 );
C_ASSERT( offsetof(struct wow64_user_copy_params, value) == 24 );
C_ASSERT( offsetof(struct wow64_user_copy_params, operation) == 32 );
C_ASSERT( offsetof(struct wow64_user_copy_params, status) == 36 );
C_ASSERT( offsetof(struct wow64_user_copy_params, reserved) == 40 );

NTSTATUS unixcall_wow64_user_copy( void *args )
{
    const struct wow64_user_copy_params *params = args;
    void *dst;
    const void *src;
    SIZE_T size;

    if (params->reserved[0] || params->reserved[1]) return STATUS_INVALID_PARAMETER;
    size = params->size;
    if ((unsigned long long)size != params->size) return STATUS_INVALID_PARAMETER;
    dst = (void *)(ULONG_PTR)params->dst;
    src = (const void *)(ULONG_PTR)params->src;

    switch (params->operation)
    {
    case WOW64_USER_COPY_READ:
        return virtual_copy_from_user( dst, src, size );
    case WOW64_USER_COPY_WRITE:
        return virtual_copy_to_user( dst, src, size );
    case WOW64_USER_COPY_PROBE_READ:
        if (params->dst) return STATUS_INVALID_PARAMETER;
        return wow64_probe_user_read( src, size );
    case WOW64_USER_COPY_PROBE_WRITE:
        if (params->src) return STATUS_INVALID_PARAMETER;
        return wow64_probe_user_write( dst, size );
    case WOW64_USER_COPY_FAULTING_WRITE:
        return wow64_faulting_write_user( dst, src, size );
    case WOW64_USER_COPY_STORE_RELEASE_LONG:
        if (params->size != sizeof(LONG)) return STATUS_INVALID_PARAMETER;
        return wow64_store_release_long( dst, params->value );
    case WOW64_USER_COPY_PUBLISH_IOSB:
        if (params->src || params->size != sizeof(IO_STATUS_BLOCK32) ||
            params->value > MAXDWORD)
            return STATUS_INVALID_PARAMETER;
        return virtual_publish_wow64_iosb( dst, params->status, params->value );
    case WOW64_USER_COPY_PUBLISH_HANDLE_PAIR:
        if (params->size != 2 * sizeof(ULONG)) return STATUS_INVALID_PARAMETER;
        return virtual_publish_wow64_ulong_pair( dst, (ULONG)params->value,
                                                  (void *)(ULONG_PTR)params->src,
                                                  (ULONG)(params->value >> 32) );
    case WOW64_USER_COPY_ATOMIC_WRITE:
        return wow64_atomic_write_user( dst, src, size );
    default:
        return STATUS_INVALID_PARAMETER;
    }
}


/***********************************************************************
 *           virtual_set_force_exec
 *
 * Whether to force exec prot on all views.
 */
void virtual_set_force_exec( BOOL enable )
{
    struct file_view *view;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!force_exec_prot != !enable)  /* change all existing views */
    {
        force_exec_prot = enable;

        WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
        {
            /* file mappings are always accessible */
            BYTE commit = is_view_valloc( view ) ? 0 : VPROT_COMMITTED;

#if defined(__APPLE__) && defined(__aarch64__)
            if (view->protect & VPROT_WOW64_OWNED_BACKING) continue;
#endif
            mprotect_range( view->base, view->size, commit, 0 );
        }
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/***********************************************************************
 *           virtual_manage_exec_writes
 */
void virtual_enable_write_exceptions( BOOL enable )
{
    struct file_view *view;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!enable_write_exceptions && enable)  /* change all existing views */
    {
        WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
        {
#if defined(__APPLE__) && defined(__aarch64__)
            if (view->protect & VPROT_WOW64_OWNED_BACKING) continue;
#endif
            if (set_page_vprot_exec_write_protect( view->base, view->size ))
                mprotect_range( view->base, view->size, 0, 0 );
        }
    }
    enable_write_exceptions = enable;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/* free reserved areas within a given range */
static void free_reserved_memory( char *base, char *limit )
{
    struct reserved_area *area;

    for (;;)
    {
        int removed = 0;

        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            char *area_base = area->base;
            char *area_end = area_base + area->size;

            if (area_end <= base) continue;
            if (area_base >= limit) return;
            if (area_base < base) area_base = base;
            if (area_end > limit) area_end = limit;
            remove_reserved_area( area_base, area_end - area_base );
            removed = 1;
            break;
        }
        if (!removed) return;
    }
}

#ifndef _WIN64

/***********************************************************************
 *           virtual_release_address_space
 *
 * Release some address space once we have loaded and initialized the app.
 */
static void virtual_release_address_space(void)
{
#ifndef __APPLE__  /* On macOS, we still want to free some of low memory, for OpenGL resources */
    if (user_space_limit > (void *)limit_2g) return;
#endif
    free_reserved_memory( (char *)0x20000000, (char *)0x7f000000 );
}

#endif  /* _WIN64 */


static int needs_override_large_address_aware(void)
{
    static int needs_override = -1;

    if (needs_override == -1)
    {
        const char *value = getenv( "WINE_LARGE_ADDRESS_AWARE" );

        /* Keep the compatibility override enabled when the variable is absent. */
        needs_override = !value || atoi( value ) == 1;
    }
    return needs_override;
}

static BOOL is_large_address_aware(void)
{
    return (main_image_info.ImageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ||
           needs_override_large_address_aware();
}


/***********************************************************************
 *           virtual_set_large_address_space
 *
 * Enable use of a large address space when allowed by the application.
 */
void virtual_set_large_address_space(void)
{
    if (is_win64)
    {
        if (!is_wow64())
        {
            address_space_start = (void *)0x10000;
#ifndef __APPLE__  /* don't free the zerofill section on macOS */
            if ((main_image_info.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) &&
                (main_image_info.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
                free_reserved_memory( 0, (char *)0x7ffe0000 );
#endif
        }
        else user_space_wow_limit = (is_large_address_aware() ? limit_4g : limit_2g) - 1;
    }
    else
    {
        if (!is_large_address_aware()) return;
        free_reserved_memory( (char *)0x80000000, address_space_limit );
    }
    user_space_limit = working_set_limit = address_space_limit;
}


/***********************************************************************
 *             allocate_virtual_memory
 *
 * NtAllocateVirtualMemory[Ex] implementation.
 */
static NTSTATUS allocate_virtual_memory( void **ret, SIZE_T *size_ptr, ULONG type, ULONG protect,
                                         ULONG_PTR limit_low, ULONG_PTR limit_high,
                                         ULONG_PTR align, ULONG attributes, BOOL translated_wow64 )
{
    void *base;
    unsigned int vprot;
    BOOL is_dos_memory = FALSE;
    struct file_view *view;
    sigset_t sigset;
    SIZE_T size = *size_ptr;
    NTSTATUS status = STATUS_SUCCESS;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    struct arm64ec_low_memory_transaction low_transaction;
    struct arm64ec_code_transaction code_transaction;
    void *allocation_base = NULL;
    void *low_capture_base = NULL;
    BOOL low_candidate = FALSE, low_input = FALSE, low_new_reserve = FALSE, low_view = FALSE;
    ULONG operation;
#endif

    /* Round parameters to a page boundary */

    if (is_beyond_limit( 0, size, working_set_limit )) return STATUS_WORKING_SET_LIMIT_RANGE;

    if (*ret)
    {
        if (type & MEM_RESERVE && !(type & MEM_REPLACE_PLACEHOLDER)) /* Round down to 64k boundary */
            base = ROUND_ADDR( *ret, granularity_mask );
        else
            base = ROUND_ADDR( *ret, page_mask );
        size = (((UINT_PTR)*ret + size + page_mask) & ~page_mask) - (UINT_PTR)base;

        /* disallow low 64k, wrap-around and kernel space */
        if (((char *)base < (char *)0x10000) ||
            ((char *)base + size < (char *)base) ||
            is_beyond_limit( base, size, address_space_limit ))
        {
            /* address 1 is magic to mean DOS area */
            if (!base && *ret == (void *)1 && size == 0x110000) is_dos_memory = TRUE;
            else return STATUS_INVALID_PARAMETER;
        }
    }
    else
    {
        base = NULL;
        size = ROUND_SIZE( 0, size, page_mask );
    }

    /* Compute the alloc type flags */

    if (!(type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET))
        || (type & MEM_REPLACE_PLACEHOLDER && !(type & MEM_RESERVE)))
    {
        WARN("called with wrong alloc type flags (%08x) !\n", type);
        return STATUS_INVALID_PARAMETER;
    }

    if (type & MEM_RESERVE_PLACEHOLDER && (protect != PAGE_NOACCESS)) return STATUS_INVALID_PARAMETER;
    if (!arm64ec_view && (attributes & MEM_EXTENDED_PARAMETER_EC_CODE)) return STATUS_INVALID_PARAMETER;

    /* Reserve the memory */

#if defined(__APPLE__) && defined(__aarch64__)
    operation = (type & MEM_RESERVE) ? WINE_WOW64_MEMORY_ALLOCATE :
                (type & MEM_COMMIT) ? WINE_WOW64_MEMORY_COMMIT :
                WINE_WOW64_MEMORY_PROTECT;
    low_candidate = get_arm64ec_low_candidate_range( base, size, &low_capture_base );
    low_input = low_candidate && (ULONG_PTR)base < WINE_LOW_VA_SHADOW_SIZE;
    low_new_reserve = low_input && (type & MEM_RESERVE) &&
                      !(type & MEM_REPLACE_PLACEHOLDER);
    status = wow64_memory_begin_transaction( &transaction,
                                              translated_wow64 ||
                                              (base && is_wow64_shadow_address( base )),
                                              operation, base, size, NULL );
    if (status) return status;
    status = arm64ec_low_memory_begin_transaction(
        &low_transaction, low_candidate, operation, low_capture_base, size, NULL );
    if (status)
    {
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        return status;
    }
    status = arm64ec_code_begin_transaction( &code_transaction,
                                              is_arm64ec() && !low_candidate &&
                                              ((type & MEM_RESERVE) ||
                                               (attributes & MEM_EXTENDED_PARAMETER_EC_CODE)),
                                              WINE_ARM64EC_CODE_ALLOCATE );
    if (status)
    {
        low_transaction.event.status = status;
        arm64ec_low_memory_complete_transaction( &low_transaction );
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        return status;
    }
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

#if defined(__APPLE__) && defined(__aarch64__)
    if (!status && low_input && (view = find_view( low_capture_base, size )) &&
        (view->protect & VPROT_AMD64_LOW_TRANSLATED))
    {
        low_view = TRUE;
        allocation_base = view->base;
        if ((type & MEM_RESERVE) || !base) status = STATUS_CONFLICTING_ADDRESSES;
        else base = low_capture_base;
    }
#endif

    if (!status && ((type & MEM_RESERVE) || !base))
    {
        if (!(status = get_vprot_flags( protect, &vprot, FALSE )))
        {
            if (type & MEM_COMMIT) vprot |= VPROT_COMMITTED;
            if (type & MEM_WRITE_WATCH) vprot |= VPROT_WRITEWATCH;
            if (type & MEM_RESERVE_PLACEHOLDER) vprot |= VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER;
            if (protect & PAGE_NOCACHE) vprot |= SEC_NOCACHE;
            if (translated_wow64) vprot |= VPROT_WOW64_TRANSLATED;

            if (vprot & VPROT_WRITECOPY) status = STATUS_INVALID_PAGE_PROTECTION;
#if defined(__APPLE__) && defined(__aarch64__)
            /* A fresh canonical-low ARM64EC reservation has no usable native
             * backing on Darwin.  Only establish it in the high shadow after
             * a provider has synchronously accepted authoritative LOW
             * ownership; otherwise fail closed instead of returning an
             * inaccessible low host mapping. */
            else if (low_new_reserve && !arm64ec_low_memory_observer_is_required())
                status = STATUS_NOT_SUPPORTED;
#endif
            else if (is_dos_memory) status = allocate_dos_memory( &view, vprot );
            else
            {
#if defined(__APPLE__) && defined(__aarch64__)
                if (low_new_reserve)
                {
                    base = low_capture_base;
                    vprot |= VPROT_AMD64_LOW_TRANSLATED;
                }
#endif
                status = map_view( &view, base, size, type, vprot, limit_low, limit_high,
                                   align ? align - 1 : granularity_mask );
            }

            if (status == STATUS_SUCCESS)
            {
                base = view->base;
#if defined(__APPLE__) && defined(__aarch64__)
                if (view->protect & VPROT_WOW64_TRANSLATED) allocation_base = view->base;
                if (view->protect & VPROT_AMD64_LOW_TRANSLATED)
                {
                    low_view = TRUE;
                    allocation_base = view->base;
                }
#endif
                if (!(type & MEM_REPLACE_PLACEHOLDER) &&
                    (vprot & VPROT_EXEC || force_exec_prot) &&
                    mprotect_range( base, size, 0, 0 ))
                {
                    delete_view( view );
                    view = NULL;
                    status = STATUS_ACCESS_DENIED;
                }
            }
        }
    }
    else if (!status && (type & MEM_RESET))
    {
        if (!(view = find_view( base, size ))) status = STATUS_NOT_MAPPED_VIEW;
        else
        {
#if defined(__APPLE__) && defined(__aarch64__)
            if (view->protect & VPROT_AMD64_LOW_TRANSLATED)
            {
                low_view = TRUE;
                allocation_base = view->base;
            }
            if (view->protect & VPROT_WOW64_TRANSLATED) allocation_base = view->base;
#endif
#if defined(__APPLE__) && defined(__aarch64__)
            if (view->protect & VPROT_WOW64_OWNED_BACKING) status = STATUS_ACCESS_DENIED;
            else
#endif
                madvise( base, size, MADV_DONTNEED );
        }
    }
    else if (!status)  /* commit the pages */
    {
        if (!(view = find_view( base, size ))) status = STATUS_NOT_MAPPED_VIEW;
        else
        {
#if defined(__APPLE__) && defined(__aarch64__)
            if (view->protect & VPROT_AMD64_LOW_TRANSLATED)
            {
                low_view = TRUE;
                allocation_base = view->base;
            }
            if (view->protect & VPROT_WOW64_TRANSLATED) allocation_base = view->base;
#endif
            if (view->protect & SEC_FILE) status = STATUS_ALREADY_COMMITTED;
            else if (view->protect & VPROT_FREE_PLACEHOLDER) status = STATUS_CONFLICTING_ADDRESSES;
            else if (view->protect & SEC_RESERVE)
            {
                BYTE stack_snapshot[VPROT_STACK_SNAPSHOT_PAGES];
                BYTE *old_vprot;
                BOOL protection_set = FALSE;

                if (!(old_vprot = snapshot_vprot( base, size, stack_snapshot,
                                                  ARRAY_SIZE(stack_snapshot) )))
                    status = STATUS_NO_MEMORY;
                else
                {
                    if (!(status = set_protection( view, base, size, protect )))
                    {
                        protection_set = TRUE;
                        SERVER_START_REQ( add_mapping_committed_range )
                        {
                            req->base   = wine_server_client_ptr( view->base );
                            req->offset = (char *)base - (char *)view->base;
                            req->size   = size;
                            status = wine_server_call( req );
                        }
                        SERVER_END_REQ;
                    }
                    if (status && protection_set)
                        restore_vprot_or_abort( base, size, old_vprot );
                    if (old_vprot != stack_snapshot) free( old_vprot );
                }
            }
            else status = set_protection( view, base, size, protect );
        }
    }

    if (!status && (attributes & MEM_EXTENDED_PARAMETER_EC_CODE))
    {
        commit_arm64ec_map( view );
        set_arm64ec_range( base, size );
    }

    if (!status) VIRTUAL_DEBUG_DUMP_VIEW( view );

#if defined(__APPLE__) && defined(__aarch64__)
    if (low_candidate)
        arm64ec_low_memory_capture_transaction(
            &low_transaction, status, low_capture_base, size,
            low_view ? allocation_base : NULL );
    if (!allocation_base && status == STATUS_SUCCESS && translated_wow64 &&
        operation == WINE_WOW64_MEMORY_ALLOCATE)
        allocation_base = base;
    if (base && is_inside_wow64_shadow( base, size ))
        wow64_memory_capture_transaction( &transaction, status, base, size, allocation_base );
    else
        wow64_memory_capture_transaction( &transaction, status, NULL, 0, allocation_base );
    arm64ec_code_capture_transaction( &code_transaction, status );
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_complete_transaction( &code_transaction );
    wow64_memory_complete_transaction( &transaction );
    arm64ec_low_memory_complete_transaction( &low_transaction );
#endif

    if (status == STATUS_SUCCESS)
    {
        *ret =
#if defined(__APPLE__) && defined(__aarch64__)
            low_input && low_view ? (char *)base - WINE_LOW_VA_SHADOW_BASE :
#endif
            base;
        *size_ptr = size;
    }
    else if (status == STATUS_NO_MEMORY)
        ERR( "out of memory for allocation, base %p size %08lx\n", base, size );

    return status;
}

#if defined(__APPLE__) && defined(__aarch64__)
static NTSTATUS allocate_wow64_shadow_memory( void **address, SIZE_T *size,
                                              ULONG type, ULONG protect )
{
    ULONG_PTR limit_low = 0, limit_high = 0;

    if (!*address)
    {
        ULONG_PTR wow_limit = get_wow_user_space_limit();

        if (!wow_limit) wow_limit = limit_2g;
        limit_low = WINE_LOW_VA_SHADOW_BASE + 0x10000;
        limit_high = WINE_LOW_VA_SHADOW_BASE + wow_limit - 1;
    }
    return allocate_virtual_memory( address, size, type, protect, limit_low, limit_high,
                                    0, 0, TRUE );
}
#endif


/***********************************************************************
 *             NtAllocateVirtualMemory   (NTDLL.@)
 *             ZwAllocateVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtAllocateVirtualMemory( HANDLE process, PVOID *ret, ULONG_PTR zero_bits,
                                         SIZE_T *size_ptr, ULONG type, ULONG protect )
{
    static const ULONG type_mask = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_RESET;
    ULONG_PTR limit;

    TRACE("%p %p %08lx %x %08x\n", process, *ret, *size_ptr, type, protect );

    if (!*size_ptr) return STATUS_INVALID_PARAMETER;
    if (zero_bits > 21 && zero_bits < 32) return STATUS_INVALID_PARAMETER_3;
    if (zero_bits > 32 && zero_bits < granularity_mask) return STATUS_INVALID_PARAMETER_3;
#ifndef _WIN64
    if (!is_old_wow64() && zero_bits >= 32) return STATUS_INVALID_PARAMETER_3;
#endif
    if (type & ~type_mask) return STATUS_INVALID_PARAMETER;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;
        unsigned int status;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc.type         = APC_VIRTUAL_ALLOC;
        call.virtual_alloc.addr         = wine_server_client_ptr( *ret );
        call.virtual_alloc.size         = *size_ptr;
        call.virtual_alloc.zero_bits    = zero_bits;
        call.virtual_alloc.op_type      = type;
        call.virtual_alloc.prot         = protect;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc.status == STATUS_SUCCESS)
        {
            *ret      = wine_server_get_ptr( result.virtual_alloc.addr );
            *size_ptr = result.virtual_alloc.size;
        }
        else
        {
            WARN( "cross-process allocation failed, process=%p base=%p size=%08lx status=%08x",
                  process, *ret, *size_ptr, result.virtual_alloc.status );
        }
        return result.virtual_alloc.status;
    }

    if (!*ret)
        limit = get_zero_bits_limit( zero_bits );
    else
        limit = 0;

    return allocate_virtual_memory( ret, size_ptr, type, protect, 0, limit, 0, 0, FALSE );
}


static NTSTATUS get_extended_params( const MEM_EXTENDED_PARAMETER *parameters, ULONG count,
                                     ULONG_PTR *limit_low, ULONG_PTR *limit_high, ULONG_PTR *align,
                                     ULONG *attributes, USHORT *machine, BOOL *translated_wow64,
                                     SIZE_T *map_commit_size )
{
    ULONG i, present = 0;

    if (count && !parameters) return STATUS_INVALID_PARAMETER;

    for (i = 0; i < count; ++i)
    {
        if (parameters[i].Type >= 32) return STATUS_INVALID_PARAMETER;
        if (present & (1u << parameters[i].Type)) return STATUS_INVALID_PARAMETER;
        present |= 1u << parameters[i].Type;

        switch (parameters[i].Type)
        {
#if defined(__APPLE__) && defined(__aarch64__)
        case WINE_MEM_EXTENDED_PARAMETER_WOW64_TRANSLATED:
            if (!is_wow64()) return STATUS_INVALID_PARAMETER;
            if (parameters[i].ULong64)
            {
                if (!map_commit_size || parameters[i].ULong64 > ~(ULONG)0)
                    return STATUS_INVALID_PARAMETER;
                *map_commit_size = parameters[i].ULong64;
            }
            *translated_wow64 = TRUE;
            break;
#endif

        case MemExtendedParameterAddressRequirements:
        {
            MEM_ADDRESS_REQUIREMENTS *r = parameters[i].Pointer;
            ULONG_PTR limit;

            if (is_wow64())
            {
                limit = get_wow_user_space_limit();
#if defined(__APPLE__) && defined(__aarch64__)
                if ((ULONG_PTR)r->LowestStartingAddress >= WINE_LOW_VA_SHADOW_BASE &&
                    (ULONG_PTR)r->LowestStartingAddress <
                        WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE)
                    limit += WINE_LOW_VA_SHADOW_BASE;
#endif
            }
            else limit = (ULONG_PTR)user_space_limit;

            if (r->Alignment)
            {
                if ((r->Alignment & (r->Alignment - 1)) || r->Alignment - 1 < granularity_mask)
                {
                    WARN( "Invalid alignment %lu.\n", r->Alignment );
                    return STATUS_INVALID_PARAMETER;
                }
                *align = r->Alignment;
            }
            if (r->LowestStartingAddress)
            {
                *limit_low = (ULONG_PTR)r->LowestStartingAddress;
                if (*limit_low >= limit || (*limit_low & granularity_mask))
                {
                    WARN( "Invalid limit %p.\n", r->LowestStartingAddress );
                    return STATUS_INVALID_PARAMETER;
                }
            }
            if (r->HighestEndingAddress)
            {
                *limit_high = (ULONG_PTR)r->HighestEndingAddress;
                if (*limit_high > limit ||
                    *limit_high <= *limit_low ||
                    ((*limit_high + 1) & (page_mask - 1)))
                {
                    WARN( "Invalid limit %p.\n", r->HighestEndingAddress );
                    return STATUS_INVALID_PARAMETER;
                }
            }
            break;
        }

        case MemExtendedParameterAttributeFlags:
            *attributes = parameters[i].ULong;
            break;

        case MemExtendedParameterImageMachine:
            *machine = parameters[i].ULong;
            break;

        case MemExtendedParameterNumaNode:
        case MemExtendedParameterPartitionHandle:
        case MemExtendedParameterUserPhysicalHandle:
            FIXME( "Parameter type %d is not supported.\n", parameters[i].Type );
            break;

        default:
            WARN( "Invalid parameter type %u\n", parameters[i].Type );
            return STATUS_INVALID_PARAMETER;
        }
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *             NtAllocateVirtualMemoryEx   (NTDLL.@)
 *             ZwAllocateVirtualMemoryEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtAllocateVirtualMemoryEx( HANDLE process, PVOID *ret, SIZE_T *size_ptr, ULONG type,
                                           ULONG protect, MEM_EXTENDED_PARAMETER *parameters,
                                           ULONG count )
{
    static const ULONG type_mask = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH
                                   | MEM_RESET | MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER;
    ULONG_PTR limit_low = 0;
    ULONG_PTR limit_high = 0;
    ULONG_PTR align = 0;
    ULONG attributes = 0;
    USHORT machine = 0;
    unsigned int status;
    BOOL translated_wow64 = FALSE;

    TRACE( "%p %p %08lx %x %08x %p %u\n",
          process, *ret, *size_ptr, type, protect, parameters, count );

    status = get_extended_params( parameters, count, &limit_low, &limit_high,
                                  &align, &attributes, &machine, &translated_wow64, NULL );
    if (status) return status;

#if defined(__APPLE__) && defined(__aarch64__)
    if (translated_wow64)
    {
        if (*ret)
        {
            if (!is_wow64_shadow_address( *ret )) return STATUS_INVALID_PARAMETER;
        }
        else if (!limits_are_inside_wow64_shadow( limit_low, limit_high ))
            return STATUS_INVALID_PARAMETER;
    }
#endif

    if (type & ~type_mask) return STATUS_INVALID_PARAMETER;
    if (*ret && (align || limit_low || limit_high)) return STATUS_INVALID_PARAMETER;
    if (!*size_ptr) return STATUS_INVALID_PARAMETER;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc_ex.type         = APC_VIRTUAL_ALLOC_EX;
        call.virtual_alloc_ex.addr         = wine_server_client_ptr( *ret );
        call.virtual_alloc_ex.size         = *size_ptr;
        call.virtual_alloc_ex.limit_low    = limit_low;
        call.virtual_alloc_ex.limit_high   = limit_high;
        call.virtual_alloc_ex.align        = align;
        call.virtual_alloc_ex.op_type      = type;
        call.virtual_alloc_ex.prot         = protect;
        call.virtual_alloc_ex.attributes   = attributes;
#if defined(__APPLE__) && defined(__aarch64__)
        if (translated_wow64)
            call.virtual_alloc_ex.wine_flags |= WINE_APC_MEMORY_WOW64_TRANSLATED;
#endif
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc_ex.status == STATUS_SUCCESS)
        {
            *ret      = wine_server_get_ptr( result.virtual_alloc_ex.addr );
            *size_ptr = result.virtual_alloc_ex.size;
        }
        return result.virtual_alloc_ex.status;
    }

    return allocate_virtual_memory( ret, size_ptr, type, protect,
                                    limit_low, limit_high, align, attributes, translated_wow64 );
}


/***********************************************************************
 *             NtFreeVirtualMemory   (NTDLL.@)
 *             ZwFreeVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtFreeVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG type )
{
    struct file_view *view = NULL;
    char *base;
    sigset_t sigset;
    unsigned int status = STATUS_SUCCESS;
    LPVOID addr = *addr_ptr;
    SIZE_T size = *size_ptr;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    struct arm64ec_low_memory_transaction low_transaction;
    struct arm64ec_code_transaction code_transaction;
    void *allocation_base = NULL;
    char *capture_base;
    SIZE_T capture_size;
    void *low_capture_base = NULL;
    SIZE_T low_capture_size;
    BOOL low_candidate, low_input, low_view = FALSE;
#endif

    TRACE("%p %p %08lx %x\n", process, addr, size, type );

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_free.type      = APC_VIRTUAL_FREE;
        call.virtual_free.addr      = wine_server_client_ptr( addr );
        call.virtual_free.size      = size;
        call.virtual_free.op_type   = type;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_free.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_free.addr );
            *size_ptr = result.virtual_free.size;
        }
        return result.virtual_free.status;
    }

    /* Fix the parameters */

    if (size) size = ROUND_SIZE( addr, size, page_mask );
    base = ROUND_ADDR( addr, page_mask );

#if defined(__APPLE__) && defined(__aarch64__)
    low_candidate = get_arm64ec_low_candidate_range( base, size, &low_capture_base );
    low_input = low_candidate && (ULONG_PTR)base < WINE_LOW_VA_SHADOW_SIZE;
    low_capture_size = size;
    if ((type & MEM_COALESCE_PLACEHOLDERS) && overlaps_wow64_shadow( base, size ))
    {
        ULONG_PTR request_start = (ULONG_PTR)base;
        ULONG_PTR shadow_end = WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE;
        ULONG_PTR start = max( request_start, (ULONG_PTR)WINE_LOW_VA_SHADOW_BASE );
        ULONG_PTR end = size > ~(ULONG_PTR)0 - request_start
                        ? shadow_end : min( request_start + size, shadow_end );

        capture_base = (char *)start;
        capture_size = end - start;
    }
    else
    {
        capture_base = base;
        capture_size = size;
    }
    status = wow64_memory_begin_transaction(
        &transaction, base && (is_wow64_shadow_address( base ) ||
                               ((type & MEM_COALESCE_PLACEHOLDERS) &&
                                overlaps_wow64_shadow( base, size ))),
        type == MEM_DECOMMIT ? WINE_WOW64_MEMORY_DECOMMIT : WINE_WOW64_MEMORY_RELEASE,
        capture_base, capture_size, NULL );
    if (status) return status;
    status = arm64ec_low_memory_begin_transaction(
        &low_transaction, low_candidate,
        type == MEM_DECOMMIT ? WINE_WOW64_MEMORY_DECOMMIT : WINE_WOW64_MEMORY_RELEASE,
        low_capture_base, low_capture_size, NULL );
    if (status)
    {
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        return status;
    }
    status = arm64ec_code_begin_transaction( &code_transaction,
                                              is_arm64ec() && !low_candidate &&
                                              (type & MEM_RELEASE),
                                              WINE_ARM64EC_CODE_RELEASE );
    if (status)
    {
        low_transaction.event.status = status;
        arm64ec_low_memory_complete_transaction( &low_transaction );
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        return status;
    }
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    /* avoid freeing the DOS area when a broken app passes a NULL pointer */
    if (!base)
    {
#ifndef _WIN64
        /* address 1 is magic to mean release reserved space */
        if (addr == (void *)1 && !size && type == MEM_RELEASE) virtual_release_address_space();
        else
#endif
        status = STATUS_INVALID_PARAMETER;
    }
    else
    {
#if defined(__APPLE__) && defined(__aarch64__)
        if (low_input && (view = find_view( low_capture_base, 0 )) &&
            (view->protect & VPROT_AMD64_LOW_TRANSLATED))
        {
            base = low_capture_base;
            low_view = TRUE;
        }
        else view = find_view( base, 0 );
#else
        view = find_view( base, 0 );
#endif
        if (!view) status = STATUS_MEMORY_NOT_ALLOCATED;
    }
    if (view)
    {
#if defined(__APPLE__) && defined(__aarch64__)
        if (low_view || (view->protect & VPROT_AMD64_LOW_TRANSLATED))
        {
            low_view = TRUE;
            allocation_base = view->base;
            if (!low_capture_size)
            {
                low_capture_base = view->base;
                low_capture_size = view->size;
            }
        }
        if (view->protect & VPROT_WOW64_TRANSLATED)
        {
            allocation_base = view->base;
            if (!capture_size)
            {
                capture_base = view->base;
                capture_size = view->size;
            }
        }
#endif
#if defined(__APPLE__) && defined(__aarch64__)
        if (view->protect & VPROT_WOW64_OWNED_BACKING) status = STATUS_ACCESS_DENIED;
        else
#endif
        if (!is_view_valloc( view )) status = STATUS_INVALID_PARAMETER;
        else if (!size && base != view->base) status = STATUS_FREE_VM_NOT_AT_BASE;
        else if ((char *)view->base + view->size - base < size &&
                 !(type & MEM_COALESCE_PLACEHOLDERS))
            status = STATUS_UNABLE_TO_FREE_VM;
        else switch (type)
        {
        case MEM_DECOMMIT:
            status = decommit_pages( view, base, size );
            break;
        case MEM_RELEASE:
            if (!size) size = view->size;
            status = free_pages( view, base, size );
            break;
        case MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER:
            status = free_pages_preserve_placeholder( view, base, size );
            break;
        case MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS:
            status = coalesce_placeholders( view, base, size );
            break;
        case MEM_COALESCE_PLACEHOLDERS:
            status = STATUS_INVALID_PARAMETER_4;
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    if (status == STATUS_SUCCESS)
    {
        *addr_ptr =
#if defined(__APPLE__) && defined(__aarch64__)
            low_input && low_view ? (char *)base - WINE_LOW_VA_SHADOW_BASE :
#endif
            base;
        *size_ptr = size;
    }
#if defined(__APPLE__) && defined(__aarch64__)
    if (low_candidate)
        arm64ec_low_memory_capture_transaction(
            &low_transaction, status, low_capture_base,
            low_view ? low_capture_size : 0,
            low_view ? allocation_base : NULL );
    if (capture_base && capture_size && is_inside_wow64_shadow( capture_base, capture_size ))
        wow64_memory_capture_transaction( &transaction, status, capture_base,
                                           capture_size, allocation_base );
    else
        wow64_memory_capture_transaction( &transaction, status, NULL, 0, allocation_base );
    arm64ec_code_capture_transaction( &code_transaction, status );
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_complete_transaction( &code_transaction );
    wow64_memory_complete_transaction( &transaction );
    arm64ec_low_memory_complete_transaction( &low_transaction );
#endif
    return status;
}


/***********************************************************************
 *             NtProtectVirtualMemory   (NTDLL.@)
 *             ZwProtectVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtProtectVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr,
                                        ULONG new_prot, ULONG *old_prot )
{
    struct file_view *view;
    sigset_t sigset;
    unsigned int status = STATUS_SUCCESS;
    char *base;
    BYTE vprot;
    SIZE_T size = *size_ptr;
    LPVOID addr = *addr_ptr;
    DWORD old;
#if defined(__APPLE__) && defined(__aarch64__)
    struct arm64ec_code_transaction code_transaction = {0};
    struct wow64_memory_transaction transaction;
    struct arm64ec_low_memory_transaction low_transaction;
    void *allocation_base = NULL;
    void *low_capture_base = NULL;
    BOOL low_candidate, low_input, low_view = FALSE;
#endif

    TRACE("%p %p %08lx %08x\n", process, addr, size, new_prot );

    if (!old_prot)
        return STATUS_ACCESS_VIOLATION;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_protect.type = APC_VIRTUAL_PROTECT;
        call.virtual_protect.addr = wine_server_client_ptr( addr );
        call.virtual_protect.size = size;
        call.virtual_protect.prot = new_prot;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_protect.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_protect.addr );
            *size_ptr = result.virtual_protect.size;
            *old_prot = result.virtual_protect.prot;
        }
        else *old_prot = PAGE_NOACCESS;
        return result.virtual_protect.status;
    }

    /* Fix the parameters */

    size = ROUND_SIZE( addr, size, page_mask );
    base = ROUND_ADDR( addr, page_mask );

#if defined(__APPLE__) && defined(__aarch64__)
    low_candidate = get_arm64ec_low_candidate_range( base, size, &low_capture_base );
    low_input = low_candidate && (ULONG_PTR)base < WINE_LOW_VA_SHADOW_SIZE;
    status = wow64_memory_begin_transaction( &transaction,
                                              base && is_wow64_shadow_address( base ),
                                              WINE_WOW64_MEMORY_PROTECT,
                                              base, size, NULL );
    if (status)
    {
        *old_prot = PAGE_NOACCESS;
        return status;
    }
    status = arm64ec_low_memory_begin_transaction(
        &low_transaction, low_candidate, WINE_WOW64_MEMORY_PROTECT,
        low_capture_base, size, NULL );
    if (status)
    {
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        *old_prot = PAGE_NOACCESS;
        return status;
    }
    if (!low_candidate && arm64ec_cpu_alias_enabled)
    {
        status = arm64ec_code_begin_transaction( &code_transaction, TRUE, WINE_ARM64EC_CODE_PROTECT );
        if (status)
        {
            transaction.event.status = status;
            wow64_memory_complete_transaction( &transaction );
            arm64ec_low_memory_complete_transaction( &low_transaction );
            *old_prot = PAGE_NOACCESS;
            return status;
        }
    }
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

#if defined(__APPLE__) && defined(__aarch64__)
    if (low_input && (view = find_view( low_capture_base, size )) &&
        (view->protect & VPROT_AMD64_LOW_TRANSLATED))
    {
        base = low_capture_base;
        low_view = TRUE;
        allocation_base = view->base;
    }
    else view = find_view( base, size );
#else
    view = find_view( base, size );
#endif
    if (view)
    {
#if defined(__APPLE__) && defined(__aarch64__)
        low_view = low_view || !!(view->protect & VPROT_AMD64_LOW_TRANSLATED);
        if (low_view)
        {
            low_capture_base = base;
            allocation_base = view->base;
        }
        if (view->protect & VPROT_WOW64_TRANSLATED) allocation_base = view->base;
#endif
        /* Make sure all the pages are committed */
        if (get_committed_size( view, base, size, &vprot, VPROT_COMMITTED ) >= size && (vprot & VPROT_COMMITTED))
        {
            DWORD old_raw = get_win32_prot( vprot, view->protect );
            BOOL enrolled_stack = FALSE, created_guard_stack = FALSE;

            old = get_virtual_protect_old_prot( vprot, view->protect, new_prot );
#if defined(__APPLE__) && defined(__aarch64__)
            /* E55 is an explicit probe mode, not automatic enrollment of all
             * 1MiB allocations. Authenticate allocator provenance and owner. */
            if (arm64ec_stack_probe_enabled && view->wine_stack && view->size == 1048576 &&
                !view->stack_owner && get_thread_data()->teb->DeallocationStack == view->base &&
                get_thread_data()->teb->Tib.StackBase == (char *)view->base + view->size)
            {
                struct thread_data *owner = get_thread_data();
                status = enroll_shared_stack( owner, view, &created_guard_stack );
                if (status) goto protect_done;
                enrolled_stack = TRUE;
            }
#endif
            status = set_protection( view, base, size, new_prot );
            if (status && enrolled_stack)
            {
                view->stack_owner = NULL;
                if (created_guard_stack)
                {
                    struct thread_data *owner = get_thread_data();
                    delete_view( find_view( owner->native_guard_stack, 1 ) );
                    owner->native_guard_stack = NULL;
                }
            }
            if (status == STATUS_SUCCESS
                    && ((old_raw & 0xff) == PAGE_WRITECOPY || (old_raw & 0xff) == PAGE_EXECUTE_WRITECOPY))
            {
                TRACE( "marking %p-%p as copied writecopy\n", base, base + size );
                set_page_vprot_bits( base, size, VPROT_COPIED, 0 );
            }
        }
        else status = STATUS_NOT_COMMITTED;
    }
    else status = STATUS_INVALID_PARAMETER;

protect_done:
    if (!status) VIRTUAL_DEBUG_DUMP_VIEW( view );

#if defined(__APPLE__) && defined(__aarch64__)
    if (low_candidate)
        arm64ec_low_memory_capture_transaction( &low_transaction, status,
                                                 low_capture_base, size,
                                                 low_view ? allocation_base : NULL );
    if (base && size && is_inside_wow64_shadow( base, size ))
        wow64_memory_capture_transaction( &transaction, status, base, size, allocation_base );
    else
        wow64_memory_capture_transaction( &transaction, status, NULL, 0, allocation_base );
#endif
#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_capture_transaction( &code_transaction, status );
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_complete_transaction( &code_transaction );
    wow64_memory_complete_transaction( &transaction );
    arm64ec_low_memory_complete_transaction( &low_transaction );
#endif

    if (status == STATUS_SUCCESS)
    {
        *addr_ptr =
#if defined(__APPLE__) && defined(__aarch64__)
            low_input && low_view ? (char *)base - WINE_LOW_VA_SHADOW_BASE :
#endif
            base;
        *size_ptr = size;
        *old_prot = old;
    }
    else *old_prot = PAGE_NOACCESS;
    return status;
}


static struct file_view *get_memory_region_size( char *base, char **region_start, char **region_end,
                                                 BOOL *fake_reserved )
{
    struct wine_rb_entry *ptr;
    struct file_view *view;

    *fake_reserved = FALSE;
    *region_start = NULL;
    *region_end = working_set_limit;

    ptr = views_tree.root;
    while (ptr)
    {
        view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        if ((char *)view->base > base)
        {
            *region_end = view->base;
            ptr = ptr->left;
        }
        else if ((char *)view->base + view->size <= base)
        {
            *region_start = (char *)view->base + view->size;
            ptr = ptr->right;
        }
        else
        {
            *region_start = view->base;
            *region_end = (char *)view->base + view->size;
            return view;
        }
    }
#ifdef __i386__
    {
        struct reserved_area *area;

        /* on i386, pretend that space outside of a reserved area is allocated,
         * so that the app doesn't believe it's fully available */
        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            char *area_start = area->base;
            char *area_end = area_start + area->size;

            if (area_end <= base)
            {
                if (*region_start < area_end) *region_start = area_end;
                continue;
            }
            if (area_start <= base || area_start <= (char *)address_space_start)
            {
                if (area_end < *region_end) *region_end = area_end;
                return NULL;
            }
            /* report the remaining part of the 64K after the view as free */
            if ((UINT_PTR)*region_start & granularity_mask)
            {
                char *next = (char *)ROUND_ADDR( *region_start, granularity_mask ) + granularity_mask + 1;

                if (base < next)
                {
                    *region_end = min( next, *region_end );
                    return NULL;
                }
                else *region_start = base;
            }
            /* pretend it's allocated */
            if (area_start < *region_end) *region_end = area_start;
            break;
        }
        *fake_reserved = TRUE;
    }
#endif
    return NULL;
}


static unsigned int fill_basic_memory_info( const void *addr, MEMORY_BASIC_INFORMATION *info )
{
    char *base, *alloc_base, *alloc_end;
    struct file_view *view;
    BOOL fake_reserved;
#if defined(__APPLE__) && defined(__aarch64__)
    BOOL translated_amd64_low = FALSE;
#endif
    sigset_t sigset;

    base = ROUND_ADDR( addr, page_mask );

    if (is_beyond_limit( base, 1, working_set_limit )) return STATUS_INVALID_PARAMETER;

    /* Find the view containing the address */

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    if ((ULONG_PTR)base < WINE_LOW_VA_SHADOW_SIZE)
    {
        char *shadow = base + WINE_LOW_VA_SHADOW_BASE;
        struct file_view *shadow_view = find_view( shadow, 0 );

        if (shadow_view && (shadow_view->protect & VPROT_AMD64_LOW_TRANSLATED))
        {
            base = shadow;
            translated_amd64_low = TRUE;
        }
    }
#endif
    view = get_memory_region_size( base, &alloc_base, &alloc_end, &fake_reserved );

    /* Fill the info structure */

    info->BaseAddress = base;
    info->RegionSize  = alloc_end - base;

    if (!view)
    {
        if (fake_reserved)
        {
            info->State             = MEM_RESERVE;
            info->Protect           = PAGE_NOACCESS;
            info->AllocationBase    = alloc_base;
            info->AllocationProtect = PAGE_NOACCESS;
            info->Type              = MEM_PRIVATE;
        }
        else
        {
            info->State             = MEM_FREE;
            info->Protect           = PAGE_NOACCESS;
            info->AllocationBase    = 0;
            info->AllocationProtect = 0;
            info->Type              = 0;
        }
    }
    else
    {
        BYTE vprot;

        info->AllocationBase = alloc_base;
        info->RegionSize = get_committed_size( view, base, ~(size_t)0, &vprot, ~VPROT_WRITEWATCH );
        info->State = (vprot & VPROT_COMMITTED) ? MEM_COMMIT : MEM_RESERVE;
        info->Protect = (vprot & VPROT_COMMITTED) ? get_win32_prot( vprot, view->protect ) : 0;
        info->AllocationProtect = get_win32_prot( view->protect, view->protect );
        if (view->protect & SEC_IMAGE) info->Type = MEM_IMAGE;
        else if (view->protect & (SEC_FILE | SEC_RESERVE | SEC_COMMIT)) info->Type = MEM_MAPPED;
        else info->Type = MEM_PRIVATE;
    }
#if defined(__APPLE__) && defined(__aarch64__)
    if (translated_amd64_low)
    {
        info->BaseAddress = (char *)info->BaseAddress - WINE_LOW_VA_SHADOW_BASE;
        if (info->AllocationBase)
            info->AllocationBase = (char *)info->AllocationBase - WINE_LOW_VA_SHADOW_BASE;
    }
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    return STATUS_SUCCESS;
}

/* get basic information about a memory block */
static unsigned int get_basic_memory_info( HANDLE process, LPCVOID addr,
                                           MEMORY_BASIC_INFORMATION *info,
                                           SIZE_T len, SIZE_T *res_len )
{
    unsigned int status;

    if (len < sizeof(*info))
        return STATUS_INFO_LENGTH_MISMATCH;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_query.type = APC_VIRTUAL_QUERY;
        call.virtual_query.addr = wine_server_client_ptr( addr );
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_query.status == STATUS_SUCCESS)
        {
            info->BaseAddress       = wine_server_get_ptr( result.virtual_query.base );
            info->AllocationBase    = wine_server_get_ptr( result.virtual_query.alloc_base );
            info->RegionSize        = result.virtual_query.size;
            info->Protect           = result.virtual_query.prot;
            info->AllocationProtect = result.virtual_query.alloc_prot;
            info->State             = (DWORD)result.virtual_query.state << 12;
            info->Type              = (DWORD)result.virtual_query.alloc_type << 16;
            if (info->RegionSize != result.virtual_query.size)  /* truncated */
                return STATUS_INVALID_PARAMETER;  /* FIXME */
            if (res_len) *res_len = sizeof(*info);
        }
        return result.virtual_query.status;
    }

    if ((status = fill_basic_memory_info( addr, info ))) return status;

    if (res_len) *res_len = sizeof(*info);
    return STATUS_SUCCESS;
}

static unsigned int get_memory_region_info( HANDLE process, LPCVOID addr, MEMORY_REGION_INFORMATION *info,
                                            SIZE_T len, SIZE_T *res_len )
{
    char *base, *region_start, *region_end;
    struct file_view *view;
    BYTE vprot, vprot_mask;
    BOOL fake_reserved;
    sigset_t sigset;
    SIZE_T size;

    if (len < FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
        return STATUS_INFO_LENGTH_MISMATCH;

    if (process != NtCurrentProcess())
    {
        FIXME("Unimplemented for other processes.\n");
        return STATUS_NOT_IMPLEMENTED;
    }

    base = ROUND_ADDR( addr, page_mask );

    if (is_beyond_limit( base, 1, working_set_limit )) return STATUS_INVALID_PARAMETER;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if ((view = get_memory_region_size( base, &region_start, &region_end, &fake_reserved )))
    {
        info->AllocationBase = view->base;
        info->AllocationProtect = get_win32_prot( view->protect, view->protect );
        info->RegionType = 0; /* FIXME */
        if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
            info->RegionSize = view->size;
        if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, PartitionId))
        {
            base = region_start;
            info->CommitSize = 0;
            vprot_mask = VPROT_COMMITTED;
            if (!is_view_valloc( view )) vprot_mask |= PAGE_WRITECOPY;
            while (base != region_end &&
                   (size = get_committed_size( view, base, ~(size_t)0, &vprot, vprot_mask )))
            {
                if ((vprot & vprot_mask) == vprot_mask) info->CommitSize += size;
                base += size;
            }
        }
    }
    else
    {
        if (!fake_reserved)
        {
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            return STATUS_INVALID_ADDRESS;
        }
        info->AllocationBase = region_start;
        info->AllocationProtect = PAGE_NOACCESS;
        info->RegionType = 0; /* FIXME */
        info->RegionSize = region_end - region_start;
        info->CommitSize = 0;
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (res_len) *res_len = sizeof(*info);
    return STATUS_SUCCESS;
}

struct working_set_info_ref
{
    char *addr;
    SIZE_T orig_index;
};

#if defined(HAVE_LIBPROCSTAT)
struct fill_working_set_info_data
{
    struct procstat *pstat;
    struct kinfo_proc *kip;
    unsigned int vmentry_count;
    struct kinfo_vmentry *vmentries;
};

static void init_fill_working_set_info_data( struct fill_working_set_info_data *d, char *end )
{
    unsigned int proc_count;

    d->kip = NULL;
    d->vmentry_count = 0;
    d->vmentries = NULL;

    if ((d->pstat = procstat_open_sysctl()))
        d->kip = procstat_getprocs( d->pstat, KERN_PROC_PID, getpid(), &proc_count );
    if (d->kip)
        d->vmentries = procstat_getvmmap( d->pstat, d->kip, &d->vmentry_count );
    if (!d->vmentries)
        WARN( "couldn't get process vmmap, errno %d\n", errno );
}

static void free_fill_working_set_info_data( struct fill_working_set_info_data *d )
{
    if (d->vmentries)
        procstat_freevmmap( d->pstat, d->vmentries );
    if (d->kip)
        procstat_freeprocs( d->pstat, d->kip );
    if (d->pstat)
        procstat_close( d->pstat );
}

static void fill_working_set_info( struct fill_working_set_info_data *d, struct file_view *view, BYTE vprot,
                                   struct working_set_info_ref *ref, SIZE_T count,
                                   MEMORY_WORKING_SET_EX_INFORMATION *info )
{
    SIZE_T i;
    int j;

    for (i = 0; i < count; ++i)
    {
        MEMORY_WORKING_SET_EX_INFORMATION *p = &info[ref[i].orig_index];
        struct kinfo_vmentry *entry = NULL;

        for (j = 0; j < d->vmentry_count; j++)
        {
            if (d->vmentries[j].kve_start <= (ULONG_PTR)p->VirtualAddress && (ULONG_PTR)p->VirtualAddress <= d->vmentries[j].kve_end)
            {
                entry = &d->vmentries[j];
                break;
            }
        }

        p->VirtualAttributes.Valid = !(vprot & VPROT_GUARD) && (vprot & 0x0f) && entry && entry->kve_type != KVME_TYPE_SWAP;
        p->VirtualAttributes.Shared = !is_view_valloc( view );
        if (p->VirtualAttributes.Shared && p->VirtualAttributes.Valid)
            p->VirtualAttributes.ShareCount = 1; /* FIXME */
        if (p->VirtualAttributes.Valid)
            p->VirtualAttributes.Win32Protection = get_win32_prot( vprot, view->protect );
    }
}
#else
static int pagemap_fd = -2;

struct fill_working_set_info_data
{
    UINT64 pm_buffer[256];
    SIZE_T buffer_start;
    ssize_t buffer_len;
    SIZE_T end_page;
};

static void init_fill_working_set_info_data( struct fill_working_set_info_data *d, char *end )
{
    d->buffer_start = 0;
    d->buffer_len = 0;
    d->end_page = (UINT_PTR)end / host_page_size;
    memset( d->pm_buffer, 0, sizeof(d->pm_buffer) );

    if (pagemap_fd != -2) return;

#ifdef O_CLOEXEC
    if ((pagemap_fd = open( "/proc/self/pagemap", O_RDONLY | O_CLOEXEC, 0 )) == -1 && errno == EINVAL)
#endif
        pagemap_fd = open( "/proc/self/pagemap", O_RDONLY, 0 );

    if (pagemap_fd == -1) WARN( "unable to open /proc/self/pagemap\n" );
    else fcntl(pagemap_fd, F_SETFD, FD_CLOEXEC);  /* in case O_CLOEXEC isn't supported */
}

static void free_fill_working_set_info_data( struct fill_working_set_info_data *d )
{
}

static void fill_working_set_info( struct fill_working_set_info_data *d, struct file_view *view, BYTE vprot,
                                   struct working_set_info_ref *ref, SIZE_T count,
                                   MEMORY_WORKING_SET_EX_INFORMATION *info )
{
    MEMORY_WORKING_SET_EX_INFORMATION *p;
    UINT64 pagemap;
    SIZE_T i, page;
    ssize_t len;

    for (i = 0; i < count; ++i)
    {
        page = (UINT_PTR)ref[i].addr / host_page_size;
        p = &info[ref[i].orig_index];

        assert(page >= d->buffer_start);
        if (page >= d->buffer_start + d->buffer_len)
        {
            d->buffer_start = page;
            len = min( sizeof(d->pm_buffer), (d->end_page - page) * sizeof(pagemap) );
            if (pagemap_fd != -1)
            {
                d->buffer_len = pread( pagemap_fd, d->pm_buffer, len, page * sizeof(pagemap) );
                if (d->buffer_len != len)
                {
                    d->buffer_len = max( d->buffer_len, 0 );
                    memset( d->pm_buffer + d->buffer_len / sizeof(pagemap), 0, len - d->buffer_len );
                }
            }
            d->buffer_len = len / sizeof(pagemap);
        }
        pagemap = d->pm_buffer[page - d->buffer_start];

        p->VirtualAttributes.Valid = !(vprot & VPROT_GUARD) && (vprot & 0x0f) && (pagemap >> 63);
        p->VirtualAttributes.Shared = !is_view_valloc( view ) && ((pagemap >> 61) & 1);
        if (p->VirtualAttributes.Shared && p->VirtualAttributes.Valid)
            p->VirtualAttributes.ShareCount = 1; /* FIXME */
        if (p->VirtualAttributes.Valid)
            p->VirtualAttributes.Win32Protection = get_win32_prot( vprot, view->protect );
    }
}
#endif

static int compare_working_set_info_ref( const void *a, const void *b )
{
    const struct working_set_info_ref *r1 = a, *r2 = b;

    if (r1->addr < r2->addr) return -1;
    return r1->addr > r2->addr;
}

static NTSTATUS get_working_set_ex( HANDLE process, LPCVOID addr,
                                    MEMORY_WORKING_SET_EX_INFORMATION *info,
                                    SIZE_T len, SIZE_T *res_len )
{
    struct working_set_info_ref ref_buffer[256], *ref = ref_buffer, *r;
    struct fill_working_set_info_data data;
    char *start, *end;
    SIZE_T i, count;
    struct file_view *view, *prev_view;
    sigset_t sigset;
    BYTE vprot;

    if (process != NtCurrentProcess())
    {
        FIXME( "(process=%p,addr=%p) Unimplemented information class: MemoryWorkingSetExInformation\n", process, addr );
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len < sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;

    count = len / sizeof(*info);

    if (count > ARRAY_SIZE(ref_buffer)) ref = malloc( count * sizeof(*ref) );
    for (i = 0; i < count; ++i)
    {
        ref[i].orig_index = i;
        ref[i].addr = ROUND_ADDR( info[i].VirtualAddress, page_mask );
        info[i].VirtualAttributes.Flags = 0;
    }
    qsort( ref, count, sizeof(*ref), compare_working_set_info_ref );
    start = ref[0].addr;
    end = ref[count - 1].addr + page_size;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    init_fill_working_set_info_data( &data, end );

    view = find_view_range( start, end - start );
    while (view && (char *)view->base > start)
    {
        prev_view = RB_ENTRY_VALUE( rb_prev( &view->entry ), struct file_view, entry );
        if (!prev_view || (char *)prev_view->base + prev_view->size <= start) break;
        view = prev_view;
    }

    r = ref;
    while (view && (char *)view->base < end)
    {
        if (start < (char *)view->base) start = view->base;
        while (r != ref + count && r->addr < start) ++r;
        while (start != (char *)view->base + view->size && r != ref + count
               && r->addr < (char *)view->base + view->size)
        {
            start += get_committed_size( view, start, end - start, &vprot, ~VPROT_WRITEWATCH );
            i = 0;
            while (r + i != ref + count && r[i].addr < start) ++i;
            if (vprot & VPROT_COMMITTED) fill_working_set_info( &data, view, vprot, r, i, info );
            r += i;
        }
        if (r == ref + count) break;
        view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
    }

    free_fill_working_set_info_data( &data );
    if (ref != ref_buffer) free( ref );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (res_len)
        *res_len = len;
    return STATUS_SUCCESS;
}

static unsigned int get_memory_section_name( HANDLE process, LPCVOID addr,
                                             MEMORY_SECTION_NAME *info, SIZE_T len, SIZE_T *ret_len )
{
    unsigned int status;

    if (!info) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( get_mapping_filename )
    {
        req->process = wine_server_obj_handle( process );
        req->addr = wine_server_client_ptr( addr );
        if (len > sizeof(*info) + sizeof(WCHAR))
            wine_server_set_reply( req, info + 1, len - sizeof(*info) - sizeof(WCHAR) );
        status = wine_server_call( req );
        if (!status || status == STATUS_BUFFER_OVERFLOW)
        {
            if (ret_len) *ret_len = sizeof(*info) + reply->len + sizeof(WCHAR);
            if (len < sizeof(*info)) status = STATUS_INFO_LENGTH_MISMATCH;
            if (!status)
            {
                info->SectionFileName.Buffer = (WCHAR *)(info + 1);
                info->SectionFileName.Length = reply->len;
                info->SectionFileName.MaximumLength = reply->len + sizeof(WCHAR);
                info->SectionFileName.Buffer[reply->len / sizeof(WCHAR)] = 0;
            }
        }
    }
    SERVER_END_REQ;
    return status;
}

static unsigned int get_memory_image_info( HANDLE process, LPCVOID addr, MEMORY_IMAGE_INFORMATION *info,
                                           SIZE_T len, SIZE_T *res_len )
{
    unsigned int status;

    if (len < sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;
    memset( info, 0, sizeof(*info) );

    SERVER_START_REQ( get_image_view_info )
    {
        req->process = wine_server_obj_handle( process );
        req->addr = wine_server_client_ptr( addr );
        status = wine_server_call( req );
        if (!status && reply->base)
        {
            info->ImageBase = wine_server_get_ptr( reply->base );
            info->SizeOfImage = reply->size;
            info->ImageSigningLevel = 12;
        }
    }
    SERVER_END_REQ;

    if (status == STATUS_NOT_MAPPED_VIEW)
    {
        MEMORY_BASIC_INFORMATION basic_info;

        status = get_basic_memory_info( process, addr, &basic_info, sizeof(basic_info), NULL );
        if (status || basic_info.State == MEM_FREE) status = STATUS_INVALID_ADDRESS;
    }

    if (!status && res_len) *res_len = sizeof(*info);
    return status;
}

/* Return the canonical Windows address for a host mapping.  Numeric shadow
 * membership is not sufficient; only the explicit AMD64-low ownership tag
 * changes the address domain. */
void *virtual_get_guest_address( const void *host )
{
#if defined(__APPLE__) && defined(__aarch64__)
    struct file_view *view;
    void *guest = (void *)host;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((view = find_view( host, 0 )) &&
        (view->protect & VPROT_AMD64_LOW_TRANSLATED))
        guest = (char *)host - WINE_LOW_VA_SHADOW_BASE;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return guest;
#else
    return (void *)host;
#endif
}

static NTSTATUS query_translated_view_information( HANDLE process, LPCVOID addr,
                                                   WINE_TRANSLATED_VIEW_INFORMATION *info,
                                                   SIZE_T len, SIZE_T *res_len )
{
    WINE_TRANSLATED_VIEW_INFORMATION local =
    {
        .Version = WINE_TRANSLATED_VIEW_INFORMATION_VERSION,
    };
    struct file_view *view;
    void *host = (void *)addr, *region;
    BYTE vprot;
    sigset_t sigset;

    if (len != sizeof(local)) return STATUS_INFO_LENGTH_MISMATCH;
    if (!info) return STATUS_ACCESS_VIOLATION;
    if (process != NtCurrentProcess()) return STATUS_INVALID_HANDLE;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    if ((ULONG_PTR)addr < WINE_LOW_VA_SHADOW_SIZE)
    {
        void *shadow = (char *)addr + WINE_LOW_VA_SHADOW_BASE;
        struct file_view *shadow_view = find_view( shadow, 0 );

        if (shadow_view && (shadow_view->protect & VPROT_AMD64_LOW_TRANSLATED))
            host = shadow;
    }
#endif
    if (!(view = find_view( host, 0 )))
    {
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        return STATUS_NOT_MAPPED_VIEW;
    }

    region = ROUND_ADDR( host, page_mask );
    local.GuestBase = region;
    local.HostBase = region;
    local.AllocationBase = view->base;
    local.RegionSize = get_committed_size( view, region,
                                           (char *)view->base + view->size - (char *)region,
                                           &vprot, ~VPROT_WRITEWATCH );
    if (vprot & VPROT_COMMITTED)
        local.Protect = get_win32_prot( vprot, view->protect );
#if defined(__APPLE__) && defined(__aarch64__)
    if (view->protect & VPROT_AMD64_LOW_TRANSLATED)
    {
        local.Flags = WINE_TRANSLATED_VIEW_AMD64_LOW;
        local.GuestBase = (char *)region - WINE_LOW_VA_SHADOW_BASE;
        local.AllocationBase = (char *)view->base - WINE_LOW_VA_SHADOW_BASE;
    }
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    *info = local;
    if (res_len) *res_len = sizeof(local);
    return STATUS_SUCCESS;
}


/***********************************************************************
 *             NtQueryVirtualMemory   (NTDLL.@)
 *             ZwQueryVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryVirtualMemory( HANDLE process, LPCVOID addr,
                                      MEMORY_INFORMATION_CLASS info_class,
                                      PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    NTSTATUS status;

    TRACE("(%p, %p, info_class=%d, %p, %ld, %p)\n",
          process, addr, info_class, buffer, len, res_len);

    switch(info_class)
    {
        case MemoryBasicInformation:
            return get_basic_memory_info( process, addr, buffer, len, res_len );

        case MemoryWorkingSetExInformation:
            return get_working_set_ex( process, addr, buffer, len, res_len );

        case MemoryMappedFilenameInformation:
            return get_memory_section_name( process, addr, buffer, len, res_len );

        case MemoryRegionInformation:
            return get_memory_region_info( process, addr, buffer, len, res_len );

        case MemoryImageInformation:
            return get_memory_image_info( process, addr, buffer, len, res_len );

        case MemoryWineLoadUnixLib:
        case MemoryWineLoadUnixLibWow64:
            if (len != sizeof(unixlib_handle_t)) return STATUS_INFO_LENGTH_MISMATCH;
            if (process == GetCurrentProcess())
            {
                void *module = (void *)addr;
                unixlib_handle_t dispatch;

                status = load_builtin_unixlib( module, info_class == MemoryWineLoadUnixLibWow64, &dispatch );
                if (!status) *(unixlib_handle_t *)buffer = dispatch;
                return status;
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineLoadUnixLibByName:
        case MemoryWineLoadUnixLibByNameWow64:
            if (process == GetCurrentProcess())
            {
                UINT64 res[2];
                const UNICODE_STRING *name = addr;
                NTSTATUS (*entry)(void) = NULL;
                unixlib_handle_t dispatch;
                unixlib_module_t token;
                BOOL dispatch_registered = FALSE;
                void *handle;

                if (len != sizeof(res[0]) && len != sizeof(res))
                    return STATUS_INFO_LENGTH_MISMATCH;
                if (!buffer) return STATUS_ACCESS_VIOLATION;
                if ((status = load_unixlib_by_name( name, &handle ))) return status;
                if (!(status = get_unixlib_funcs( handle, info_class == MemoryWineLoadUnixLibByNameWow64,
                                                  &dispatch, &entry, &dispatch_registered )))
                {
                    res[1] = dispatch;
                    if (entry) status = entry();
                }
                if (!status)
                    status = create_unixlib_module_token( handle, dispatch,
                                                          dispatch_registered, &token );
                if (status)
                {
                    if (dispatch_registered) unregister_wow64_unixlib_dispatch( dispatch );
                    dlclose( handle );
                    return status;
                }
                res[0] = token;
                status = virtual_copy_to_user( buffer, res, len );
                if (status) unload_unixlib_module_token( token );
                return status;
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineUnloadUnixLib:
            if (process == GetCurrentProcess())
            {
                unixlib_module_t token;

                if ((status = virtual_copy_from_user( &token, addr, sizeof(token) )))
                    return status;
                return unload_unixlib_module_token( token );
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineWow64TranslatedInformation:
            if (len != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            if (process == GetCurrentProcess())
            {
                struct file_view *view;
                sigset_t sigset;

                if (!buffer) return STATUS_ACCESS_VIOLATION;
                server_enter_uninterrupted_section( &virtual_mutex, &sigset );
                if (!(view = find_view( addr, 0 ))) status = STATUS_NOT_MAPPED_VIEW;
                else
                {
                    *(ULONG *)buffer = !!(view->protect & VPROT_WOW64_TRANSLATED);
                    if (res_len) *res_len = sizeof(ULONG);
                    status = STATUS_SUCCESS;
                }
                server_leave_uninterrupted_section( &virtual_mutex, &sigset );
                return status;
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineProcessVmMachineInformation:
            if (len != sizeof(WINE_PROCESS_VM_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
            if (!buffer) return STATUS_ACCESS_VIOLATION;
            SERVER_START_REQ( get_process_vm_machine )
            {
                req->handle = wine_server_obj_handle( process );
                status = wine_server_call( req );
                if (!status)
                {
                    WINE_PROCESS_VM_INFORMATION info =
                    {
                        WINE_PROCESS_VM_INFORMATION_VERSION,
                        sizeof(info),
                        reply->machine,
                        reply->flags,
                        0,
                    };

                    if ((info.Flags & ~WINE_PROCESS_VM_FLAG_WOW64_TRANSLATED) ||
                        ((info.Flags & WINE_PROCESS_VM_FLAG_WOW64_TRANSLATED) &&
                         info.Machine != IMAGE_FILE_MACHINE_I386))
                        status = STATUS_INVALID_PARAMETER;
                    else
                    {
                        *(WINE_PROCESS_VM_INFORMATION *)buffer = info;
                        if (res_len) *res_len = sizeof(info);
                    }
                }
            }
            SERVER_END_REQ;
            return status;

        case MemoryWineTranslatedViewInformation:
            return query_translated_view_information( process, addr, buffer, len, res_len );

        default:
            FIXME("(%p,%p,info_class=%d,%p,%ld,%p) Unknown information class\n",
                  process, addr, info_class, buffer, len, res_len);
            return STATUS_INVALID_INFO_CLASS;
    }
}


/***********************************************************************
 *             NtLockVirtualMemory   (NTDLL.@)
 *             ZwLockVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtLockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    unsigned int status = STATUS_SUCCESS;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_lock.type = APC_VIRTUAL_LOCK;
        call.virtual_lock.addr = wine_server_client_ptr( *addr );
        call.virtual_lock.size = *size;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_lock.status == STATUS_SUCCESS)
        {
            *addr = wine_server_get_ptr( result.virtual_lock.addr );
            *size = result.virtual_lock.size;
        }
        return result.virtual_lock.status;
    }

    *size = ROUND_SIZE( *addr, *size, page_mask );
    *addr = ROUND_ADDR( *addr, page_mask );

    if (mlock( ROUND_ADDR( *addr, host_page_mask ), ROUND_SIZE( *addr, *size, host_page_mask ) ))
        status = STATUS_ACCESS_DENIED;
    return status;
}


/***********************************************************************
 *             NtUnlockVirtualMemory   (NTDLL.@)
 *             ZwUnlockVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnlockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    unsigned int status = STATUS_SUCCESS;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_unlock.type = APC_VIRTUAL_UNLOCK;
        call.virtual_unlock.addr = wine_server_client_ptr( *addr );
        call.virtual_unlock.size = *size;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_unlock.status == STATUS_SUCCESS)
        {
            *addr = wine_server_get_ptr( result.virtual_unlock.addr );
            *size = result.virtual_unlock.size;
        }
        return result.virtual_unlock.status;
    }

    *size = ROUND_SIZE( *addr, *size, page_mask );
    *addr = ROUND_ADDR( *addr, page_mask );

    if (munlock( ROUND_ADDR( *addr, host_page_mask ), ROUND_SIZE( *addr, *size, host_page_mask ) ))
        status = STATUS_ACCESS_DENIED;
    return status;
}


/***********************************************************************
 *             NtMapViewOfSection   (NTDLL.@)
 *             ZwMapViewOfSection   (NTDLL.@)
 */
NTSTATUS WINAPI NtMapViewOfSection( HANDLE handle, HANDLE process, PVOID *addr_ptr, ULONG_PTR zero_bits,
                                    SIZE_T commit_size, const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                    SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect )
{
    unsigned int res;
    ULONG_PTR limit_high;
    SIZE_T mask = granularity_mask;
    LARGE_INTEGER offset;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    TRACE("handle=%p process=%p addr=%p off=%s size=0x%lx alloc_type=0x%x access=0x%x\n",
          handle, process, *addr_ptr, wine_dbgstr_longlong(offset.QuadPart), *size_ptr, alloc_type, protect );

    /* Check parameters */
    if (zero_bits > 21 && zero_bits < 32)
        return STATUS_INVALID_PARAMETER_4;

    /* If both addr_ptr and zero_bits are passed, they have match */
    if (zero_bits && zero_bits < 32 && ((UINT_PTR)*addr_ptr >> (32 - zero_bits)))
        return STATUS_INVALID_PARAMETER_4;
    if (zero_bits >= 32 && ((UINT_PTR)*addr_ptr & ~zero_bits))
        return STATUS_INVALID_PARAMETER_4;

    if (!is_win64 && !is_wow64())
    {
        if (zero_bits >= 32) return STATUS_INVALID_PARAMETER_4;
        if (alloc_type & AT_ROUND_TO_PAGE)
        {
            *addr_ptr = ROUND_ADDR( *addr_ptr, page_mask );
            mask = page_mask;
        }
    }
    else if (alloc_type & AT_ROUND_TO_PAGE) return STATUS_INVALID_PARAMETER_9;

    if (alloc_type & MEM_REPLACE_PLACEHOLDER) mask = page_mask;
    if (offset.u.LowPart & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & host_page_mask)
    {
        ERR( "unaligned placeholder at %p\n", *addr_ptr );
        return STATUS_MAPPED_ALIGNMENT;
    }

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.map_view.type         = APC_MAP_VIEW;
        call.map_view.handle       = wine_server_obj_handle( handle );
        call.map_view.addr         = wine_server_client_ptr( *addr_ptr );
        call.map_view.size         = *size_ptr;
        call.map_view.offset       = offset.QuadPart;
        call.map_view.zero_bits    = zero_bits;
        call.map_view.commit_size  = commit_size;
        call.map_view.alloc_type   = alloc_type;
        call.map_view.prot         = protect;
        res = server_queue_process_apc( process, &call, &result );
        if (res != STATUS_SUCCESS) return res;

        if (NT_SUCCESS(result.map_view.status))
        {
            *addr_ptr = wine_server_get_ptr( result.map_view.addr );
            *size_ptr = result.map_view.size;
        }
        return result.map_view.status;
    }

    limit_high = get_zero_bits_limit( zero_bits );
    return virtual_map_section( handle, addr_ptr, 0, limit_high, commit_size,
                                offset_ptr, size_ptr, alloc_type, protect, 0, FALSE );
}

/***********************************************************************
 *             NtMapViewOfSectionEx   (NTDLL.@)
 *             ZwMapViewOfSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtMapViewOfSectionEx( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                      const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                      ULONG alloc_type, ULONG protect,
                                      MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    ULONG_PTR limit_low = 0, limit_high = 0, align = 0;
    ULONG attributes = 0;
    USHORT machine = 0;
    unsigned int status;
    SIZE_T commit_size = 0;
    SIZE_T mask = granularity_mask;
    LARGE_INTEGER offset;
    BOOL translated_wow64 = FALSE;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    TRACE( "handle=%p process=%p addr=%p off=%s size=0x%lx alloc_type=0x%x access=0x%x\n",
           handle, process, *addr_ptr, wine_dbgstr_longlong(offset.QuadPart), *size_ptr, alloc_type, protect );

    status = get_extended_params( parameters, count, &limit_low, &limit_high,
                                  &align, &attributes, &machine, &translated_wow64, &commit_size );
    if (status) return status;
    if (commit_size && attributes) return STATUS_INVALID_PARAMETER;

#if defined(__APPLE__) && defined(__aarch64__)
    if (translated_wow64)
    {
        if (*addr_ptr)
        {
            if (!is_wow64_shadow_address( *addr_ptr )) return STATUS_INVALID_PARAMETER;
        }
        else if (!limits_are_inside_wow64_shadow( limit_low, limit_high ))
            return STATUS_INVALID_PARAMETER;
    }
#endif

    if (align) return STATUS_INVALID_PARAMETER;
    if (*addr_ptr && (limit_low || limit_high)) return STATUS_INVALID_PARAMETER;

    if (alloc_type & AT_ROUND_TO_PAGE)
    {
        if (is_win64 || is_wow64()) return STATUS_INVALID_PARAMETER;
        *addr_ptr = ROUND_ADDR( *addr_ptr, page_mask );
        mask = page_mask;
    }

    if (alloc_type & MEM_REPLACE_PLACEHOLDER) mask = page_mask;
    if (offset.u.LowPart & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & host_page_mask)
    {
        ERR( "unaligned placeholder at %p\n", *addr_ptr );
        return STATUS_MAPPED_ALIGNMENT;
    }

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.map_view_ex.type         = APC_MAP_VIEW_EX;
        call.map_view_ex.handle       = wine_server_obj_handle( handle );
        call.map_view_ex.addr         = wine_server_client_ptr( *addr_ptr );
        call.map_view_ex.size         = *size_ptr;
        call.map_view_ex.offset       = offset.QuadPart;
        call.map_view_ex.limit_low    = limit_low;
        call.map_view_ex.limit_high   = limit_high;
        call.map_view_ex.alloc_type   = alloc_type;
        call.map_view_ex.prot         = protect;
        call.map_view_ex.machine      = machine;
        call.map_view_ex.attributes   = commit_size ? (ULONG)commit_size : attributes;
#if defined(__APPLE__) && defined(__aarch64__)
        if (translated_wow64)
            call.map_view_ex.wine_flags |= WINE_APC_MEMORY_WOW64_TRANSLATED;
        if (commit_size)
            call.map_view_ex.wine_flags |= WINE_APC_MEMORY_MAP_COMMIT_SIZE;
#endif
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (NT_SUCCESS(result.map_view_ex.status))
        {
            *addr_ptr = wine_server_get_ptr( result.map_view_ex.addr );
            *size_ptr = result.map_view_ex.size;
        }
        return result.map_view_ex.status;
    }

    return virtual_map_section( handle, addr_ptr, limit_low, limit_high, commit_size,
                                offset_ptr, size_ptr, alloc_type, protect, machine, translated_wow64 );
}


/***********************************************************************
 *             unmap_view_of_section
 *
 * NtUnmapViewOfSection[Ex] implementation.
 */
static NTSTATUS unmap_view_of_section( HANDLE process, PVOID addr, ULONG flags )
{
    struct file_view *view;
    unsigned int status = STATUS_NOT_MAPPED_VIEW;
    sigset_t sigset;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    struct arm64ec_low_memory_transaction low_transaction;
    struct arm64ec_code_transaction code_transaction;
    void *capture_base = NULL;
    void *allocation_base = NULL;
    void *low_capture_base = NULL;
    SIZE_T capture_size = 0;
    SIZE_T low_capture_size = 0;
    BOOL low_candidate, low_input, low_view = FALSE;
#endif

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.unmap_view.type = APC_UNMAP_VIEW;
        call.unmap_view.addr = wine_server_client_ptr( addr );
        call.unmap_view.flags = flags;
        status = server_queue_process_apc( process, &call, &result );
        if (status == STATUS_SUCCESS) status = result.unmap_view.status;
        return status;
    }

#if defined(__APPLE__) && defined(__aarch64__)
    low_candidate = get_arm64ec_low_candidate_range( addr, 0, &low_capture_base );
    low_input = low_candidate && (ULONG_PTR)addr < WINE_LOW_VA_SHADOW_SIZE;
    status = wow64_memory_begin_transaction( &transaction,
                                              addr && is_wow64_shadow_address( addr ),
                                              WINE_WOW64_MEMORY_UNMAP,
                                              addr, 0, NULL );
    if (status) return status;
    status = arm64ec_low_memory_begin_transaction(
        &low_transaction, low_candidate, WINE_WOW64_MEMORY_UNMAP,
        low_capture_base, 0, NULL );
    if (status)
    {
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        return status;
    }
    status = arm64ec_code_begin_transaction( &code_transaction,
                                              is_arm64ec() && !low_candidate,
                                              WINE_ARM64EC_CODE_UNMAP );
    if (status)
    {
        low_transaction.event.status = status;
        arm64ec_low_memory_complete_transaction( &low_transaction );
        transaction.event.status = status;
        wow64_memory_complete_transaction( &transaction );
        return status;
    }
    status = STATUS_NOT_MAPPED_VIEW;
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    if (low_input && (view = find_view( low_capture_base, 0 )) &&
        (view->protect & VPROT_AMD64_LOW_TRANSLATED))
    {
        addr = low_capture_base;
        low_view = TRUE;
    }
    else view = find_view( addr, 0 );
#else
    view = find_view( addr, 0 );
#endif
    if (!view) goto done;
#if defined(__APPLE__) && defined(__aarch64__)
    if (view->protect & VPROT_WOW64_OWNED_BACKING)
    {
        status = STATUS_ACCESS_DENIED;
        goto done;
    }
#endif
    if (is_view_valloc( view )) goto done;

#if defined(__APPLE__) && defined(__aarch64__)
    if (low_view || (view->protect & VPROT_AMD64_LOW_TRANSLATED))
    {
        low_view = TRUE;
        low_capture_base = view->base;
        low_capture_size = view->size;
        allocation_base = view->base;
    }
    if (view->protect & VPROT_WOW64_TRANSLATED)
    {
        capture_base = view->base;
        capture_size = view->size;
        allocation_base = view->base;
    }
#endif

    if (flags & MEM_PRESERVE_PLACEHOLDER && !(view->protect & VPROT_PLACEHOLDER))
    {
        status = STATUS_CONFLICTING_ADDRESSES;
        goto done;
    }
    if (view->protect & VPROT_SYSTEM)
    {
        struct builtin_module *builtin = get_builtin_module( view->base );

        if (builtin && builtin->refcount > 1)
        {
            TRACE( "not freeing in-use builtin %p\n", view->base );
            builtin->refcount--;
            status = STATUS_SUCCESS;
            goto done;
        }
    }

    SERVER_START_REQ( unmap_view )
    {
        req->base = wine_server_client_ptr( view->base );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (!status)
    {
        if (view->protect & SEC_IMAGE) release_builtin_module( view->base );
        if (flags & MEM_PRESERVE_PLACEHOLDER) free_pages_preserve_placeholder( view, view->base, view->size );
        else delete_view( view );
    }
    else FIXME( "failed to unmap %p %x\n", view->base, status );
done:
#if defined(__APPLE__) && defined(__aarch64__)
    if (low_candidate)
        arm64ec_low_memory_capture_transaction(
            &low_transaction, status, low_capture_base,
            low_view ? low_capture_size : 0,
            low_view ? allocation_base : NULL );
    if (capture_base && capture_size)
        wow64_memory_capture_transaction( &transaction, status, capture_base,
                                           capture_size, allocation_base );
    else
        wow64_memory_capture_transaction( &transaction, status, NULL, 0, allocation_base );
    arm64ec_code_capture_transaction( &code_transaction, status );
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    arm64ec_code_complete_transaction( &code_transaction );
    wow64_memory_complete_transaction( &transaction );
    arm64ec_low_memory_complete_transaction( &low_transaction );
#endif
    return status;
}


/***********************************************************************
 *             NtUnmapViewOfSection   (NTDLL.@)
 *             ZwUnmapViewOfSection   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnmapViewOfSection( HANDLE process, PVOID addr )
{
    return unmap_view_of_section( process, addr, 0 );
}

/***********************************************************************
 *             NtUnmapViewOfSectionEx   (NTDLL.@)
 *             ZwUnmapViewOfSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnmapViewOfSectionEx( HANDLE process, PVOID addr, ULONG flags )
{
    static const ULONG type_mask = MEM_UNMAP_WITH_TRANSIENT_BOOST | MEM_PRESERVE_PLACEHOLDER;

    if (flags & ~type_mask)
    {
        WARN( "Unsupported flags %#x.\n", flags );
        return STATUS_INVALID_PARAMETER;
    }
    if (flags & MEM_UNMAP_WITH_TRANSIENT_BOOST) FIXME( "Ignoring MEM_UNMAP_WITH_TRANSIENT_BOOST.\n" );
    return unmap_view_of_section( process, addr, flags );
}

/******************************************************************************
 *             virtual_fill_image_information
 *
 * Helper for NtQuerySection.
 */
void virtual_fill_image_information( const struct pe_image_info *pe_info, SECTION_IMAGE_INFORMATION *info )
{
    info->TransferAddress             = wine_server_get_ptr( pe_info->base + pe_info->entry_point );
    info->ZeroBits                    = pe_info->zerobits;
    info->MaximumStackSize            = pe_info->stack_size;
    info->CommittedStackSize          = pe_info->stack_commit;
    info->SubSystemType               = pe_info->subsystem;
    info->MinorSubsystemVersion       = pe_info->subsystem_minor;
    info->MajorSubsystemVersion       = pe_info->subsystem_major;
    info->MajorOperatingSystemVersion = pe_info->osversion_major;
    info->MinorOperatingSystemVersion = pe_info->osversion_minor;
    info->ImageCharacteristics        = pe_info->image_charact;
    info->DllCharacteristics          = pe_info->dll_charact;
    info->Machine                     = pe_info->machine;
    info->ImageContainsCode           = pe_info->contains_code;
    info->ImageFlags                  = pe_info->image_flags;
    info->LoaderFlags                 = pe_info->loader_flags;
    info->ImageFileSize               = pe_info->file_size;
    info->CheckSum                    = pe_info->checksum;
#ifndef _WIN64 /* don't return 64-bit values to 32-bit processes */
    if (is_machine_64bit( pe_info->machine ))
    {
        info->TransferAddress = (void *)0x81231234;  /* sic */
        info->MaximumStackSize = 0x100000;
        info->CommittedStackSize = 0x10000;
    }
#endif
}

/******************************************************************************
 *             NtQuerySection   (NTDLL.@)
 *             ZwQuerySection   (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySection( HANDLE handle, SECTION_INFORMATION_CLASS class, void *ptr,
                                SIZE_T size, SIZE_T *ret_size )
{
    unsigned int status;
    struct pe_image_info image_info;

    switch (class)
    {
    case SectionBasicInformation:
        if (size < sizeof(SECTION_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        break;
    case SectionImageInformation:
        if (size < sizeof(SECTION_IMAGE_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        break;
    default:
	FIXME( "class %u not implemented\n", class );
	return STATUS_NOT_IMPLEMENTED;
    }
    if (!ptr) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( get_mapping_info )
    {
        req->handle = wine_server_obj_handle( handle );
        req->access = SECTION_QUERY;
        wine_server_set_reply( req, &image_info, sizeof(image_info) );
        if (!(status = wine_server_call( req )))
        {
            if (class == SectionBasicInformation)
            {
                SECTION_BASIC_INFORMATION *info = ptr;
                info->Attributes    = reply->flags;
                info->BaseAddress   = NULL;
                info->Size.QuadPart = reply->size;
                if (ret_size) *ret_size = sizeof(*info);
            }
            else if (reply->flags & SEC_IMAGE)
            {
                SECTION_IMAGE_INFORMATION *info = ptr;
                virtual_fill_image_information( &image_info, info );
                if (ret_size) *ret_size = sizeof(*info);
            }
            else status = STATUS_SECTION_NOT_IMAGE;
        }
    }
    SERVER_END_REQ;

    return status;
}


/***********************************************************************
 *             NtFlushVirtualMemory   (NTDLL.@)
 *             ZwFlushVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushVirtualMemory( HANDLE process, LPCVOID *addr_ptr,
                                      SIZE_T *size_ptr, IO_STATUS_BLOCK *io )
{
    struct file_view *view;
    unsigned int status = STATUS_SUCCESS;
    sigset_t sigset;
    void *addr = ROUND_ADDR( *addr_ptr, page_mask );

    if (io)
        FIXME("Currently output io values not set.\n");

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_flush.type = APC_VIRTUAL_FLUSH;
        call.virtual_flush.addr = wine_server_client_ptr( addr );
        call.virtual_flush.size = *size_ptr;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_flush.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_flush.addr );
            *size_ptr = result.virtual_flush.size;
        }
        return result.virtual_flush.status;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(view = find_view( addr, *size_ptr ))) status = STATUS_INVALID_PARAMETER;
    else
    {
        if (!*size_ptr) *size_ptr = view->size;
        *addr_ptr = addr;
#ifdef MS_ASYNC
        if (msync( ROUND_ADDR( addr, host_page_mask ), ROUND_SIZE( addr, *size_ptr, host_page_mask ), MS_ASYNC ))
            status = STATUS_NOT_MAPPED_DATA;
#endif
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtGetWriteWatch   (NTDLL.@)
 *             ZwGetWriteWatch   (NTDLL.@)
 */
NTSTATUS WINAPI NtGetWriteWatch( HANDLE process, ULONG flags, PVOID base, SIZE_T size, PVOID *addresses,
                                 ULONG_PTR *count, ULONG *granularity )
{
    NTSTATUS status = STATUS_SUCCESS;
    sigset_t sigset;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    struct file_view *view;
    NTSTATUS snapshot_status = STATUS_SUCCESS;
    BOOL candidate;
#endif

    size = ROUND_SIZE( base, size, page_mask );
    base = ROUND_ADDR( base, page_mask );

    if (!count || !granularity) return STATUS_ACCESS_VIOLATION;
    if (!*count || !size) return STATUS_INVALID_PARAMETER;
    if (flags & ~WRITE_WATCH_FLAG_RESET) return STATUS_INVALID_PARAMETER;

    if (!addresses) return STATUS_ACCESS_VIOLATION;

    TRACE( "%p %x %p-%p %p %lu\n", process, flags, base, (char *)base + size,
           addresses, *count );

#if defined(__APPLE__) && defined(__aarch64__)
    candidate = (flags & WRITE_WATCH_FLAG_RESET) && overlaps_wow64_shadow( base, size );
    status = wow64_memory_begin_transaction( &transaction, candidate,
                                              WINE_WOW64_MEMORY_PROTECT,
                                              base, size, base );
    if (status) return status;
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

#if defined(__APPLE__) && defined(__aarch64__)
    if ((flags & WRITE_WATCH_FLAG_RESET) && (view = find_view( base, size )) &&
        (view->protect & VPROT_WOW64_OWNED_BACKING))
        status = STATUS_ACCESS_DENIED;
    else
#endif
    if (is_write_watch_range( base, size ))
    {
        ULONG_PTR pos = 0;
        char *addr = base;
        char *end = addr + size;

        if (use_kernel_writewatch)
            kernel_get_write_watches( base, size, addresses, count, flags & WRITE_WATCH_FLAG_RESET );
        else
        {
            while (pos < *count && addr < end)
            {
                if (!(get_page_vprot( addr ) & VPROT_WRITEWATCH)) addresses[pos++] = addr;
                addr += page_size;
            }
            size = addr - (char *)base;
            *count = pos;
        }
        if (flags & WRITE_WATCH_FLAG_RESET && (enable_write_exceptions || !use_kernel_writewatch))
        {
            if (use_kernel_writewatch)
                set_page_vprot_exec_write_protect( base, size );
            else
                set_page_vprot_bits( base, size, VPROT_WRITEWATCH, 0 );
            mprotect_range( base, size, 0, 0 );
        }
        *granularity = page_size;
    }
    else status = STATUS_INVALID_PARAMETER;

#if defined(__APPLE__) && defined(__aarch64__)
    if (candidate)
    {
        wow64_memory_capture_transaction( &transaction, status, base, size, base );
        snapshot_status = transaction.event.snapshot_status;
    }
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    wow64_memory_complete_transaction( &transaction );
    if (!status) status = snapshot_status;
#endif
    return status;
}


/***********************************************************************
 *             NtResetWriteWatch   (NTDLL.@)
 *             ZwResetWriteWatch   (NTDLL.@)
 */
NTSTATUS WINAPI NtResetWriteWatch( HANDLE process, PVOID base, SIZE_T size )
{
    NTSTATUS status = STATUS_SUCCESS;
    sigset_t sigset;
#if defined(__APPLE__) && defined(__aarch64__)
    struct wow64_memory_transaction transaction;
    struct file_view *view;
    NTSTATUS snapshot_status = STATUS_SUCCESS;
    BOOL candidate;
#endif

    size = ROUND_SIZE( base, size, page_mask );
    base = ROUND_ADDR( base, page_mask );

    TRACE( "%p %p-%p\n", process, base, (char *)base + size );

    if (!size) return STATUS_INVALID_PARAMETER;

#if defined(__APPLE__) && defined(__aarch64__)
    candidate = overlaps_wow64_shadow( base, size );
    status = wow64_memory_begin_transaction( &transaction, candidate,
                                              WINE_WOW64_MEMORY_PROTECT,
                                              base, size, base );
    if (status) return status;
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

#if defined(__APPLE__) && defined(__aarch64__)
    if ((view = find_view( base, size )) && (view->protect & VPROT_WOW64_OWNED_BACKING))
        status = STATUS_ACCESS_DENIED;
    else
#endif
    if (is_write_watch_range( base, size ))
        reset_write_watches( base, size );
    else
        status = STATUS_INVALID_PARAMETER;

#if defined(__APPLE__) && defined(__aarch64__)
    if (candidate)
    {
        wow64_memory_capture_transaction( &transaction, status, base, size, base );
        snapshot_status = transaction.event.snapshot_status;
    }
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#if defined(__APPLE__) && defined(__aarch64__)
    wow64_memory_complete_transaction( &transaction );
    if (!status) status = snapshot_status;
#endif
    return status;
}


/***********************************************************************
 *           read_current_process_memory
 *
 * Complete small, fully tracked self reads under one virtual-memory
 * transaction.  This avoids separate signal-masked destination and source
 * probes followed by another exception frame for the copy.  Larger reads stay
 * on the established exception path so a user-controlled copy cannot hold the
 * global virtual-memory lock for an unbounded interval.
 */
enum current_process_read_result
{
    CURRENT_PROCESS_READ_FALLBACK,
    CURRENT_PROCESS_READ_SUCCESS,
    CURRENT_PROCESS_READ_INVALID_SOURCE,
    CURRENT_PROCESS_READ_INVALID_DESTINATION,
};

static enum current_process_read_result read_current_process_memory( const void *addr,
                                                                     void *buffer, SIZE_T size )
{
    enum current_process_read_result result = CURRENT_PROCESS_READ_FALLBACK;
    struct memory_access_cache cache = {0};
    struct file_view *source_view, *destination_view;
    const char *cursor = addr;
    SIZE_T remaining = size;
    BOOL has_write_watch = FALSE;
    sigset_t sigset;

    if (!size) return CURRENT_PROCESS_READ_SUCCESS;
    if (size > granularity_mask + 1) return CURRENT_PROCESS_READ_FALLBACK;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    source_view = find_view( addr, size );
    destination_view = find_view( buffer, size );
    if (!source_view || !destination_view ||
        (source_view->protect & VPROT_SYSTEM) ||
        (destination_view->protect & VPROT_SYSTEM))
        goto done;

    /* Preserve the established destination-first error precedence without
     * changing write-watch state until the source has also been validated. */
    if (validate_write_access( buffer, size, &has_write_watch ))
    {
        result = CURRENT_PROCESS_READ_INVALID_DESTINATION;
        goto done;
    }
#if defined(__APPLE__) && defined(__aarch64__)
    /* Delegated translated write watches require the observer transaction in
     * the normal fault path; do not create a second publication mechanism. */
    if (has_write_watch && wow64_memory_logical_write_fault_is_delegated() &&
        overlaps_wow64_shadow( buffer, size ))
        goto done;
#endif

    while (remaining)
    {
        SIZE_T available;
        BYTE vprot = get_memory_access_vprot( cursor, &available, NULL, &cache );

        if (!(get_unix_prot( vprot ) & PROT_READ))
        {
            result = CURRENT_PROCESS_READ_INVALID_SOURCE;
            goto done;
        }
        available = min( available, remaining );
        cursor += available;
        remaining -= available;
    }

    /* Revalidation is cheap while the lock is held and owns the established
     * write-watch enable/restore behavior. */
    has_write_watch = FALSE;
    if (check_write_access( buffer, size, &has_write_watch ))
    {
        result = CURRENT_PROCESS_READ_INVALID_DESTINATION;
        goto done;
    }
    memmove( buffer, addr, size );
    if (has_write_watch) update_write_watches( buffer, size, size );
    result = CURRENT_PROCESS_READ_SUCCESS;

done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return result;
}


/***********************************************************************
 *             NtReadVirtualMemory   (NTDLL.@)
 *             ZwReadVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtReadVirtualMemory( HANDLE process, const void *addr, void *buffer,
                                     SIZE_T size, SIZE_T *bytes_read )
{
    enum current_process_read_result result = CURRENT_PROCESS_READ_FALLBACK;
    unsigned int status;

    if (process == GetCurrentProcess())
        result = read_current_process_memory( addr, buffer, size );

    if (result == CURRENT_PROCESS_READ_SUCCESS)
        status = STATUS_SUCCESS;
    else if (result == CURRENT_PROCESS_READ_INVALID_SOURCE)
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    else if (result == CURRENT_PROCESS_READ_INVALID_DESTINATION)
    {
        status = STATUS_ACCESS_VIOLATION;
        size = 0;
    }
    else if (!virtual_check_buffer_for_write( buffer, size ))
    {
        status = STATUS_ACCESS_VIOLATION;
        size = 0;
    }
    else if (process == GetCurrentProcess() &&
             !virtual_check_wow64_translated_memory_access( addr, size, PROT_READ ))
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    else if (process == GetCurrentProcess())
    {
        __TRY
        {
            memmove( buffer, addr, size );
            status = STATUS_SUCCESS;
        }
        __EXCEPT
        {
            status = STATUS_PARTIAL_COPY;
            size = 0;
        }
        __ENDTRY
    }
    else
    {
        SERVER_START_REQ( read_process_memory )
        {
            req->handle = wine_server_obj_handle( process );
            req->addr   = wine_server_client_ptr( addr );
            wine_server_set_reply( req, buffer, size );
            if ((status = wine_server_call( req ))) size = 0;
        }
        SERVER_END_REQ;
    }
    if (bytes_read) *bytes_read = size;
    return status;
}


/***********************************************************************
 *             NtWriteVirtualMemory   (NTDLL.@)
 *             ZwWriteVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtWriteVirtualMemory( HANDLE process, void *addr, const void *buffer,
                                      SIZE_T size, SIZE_T *bytes_written )
{
    unsigned int status;

    if (!virtual_check_buffer_for_read( buffer, size ))
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    else if (process == GetCurrentProcess() &&
             !virtual_check_wow64_translated_memory_access( addr, size, PROT_WRITE ))
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    else
    {
        SERVER_START_REQ( write_process_memory )
        {
            req->handle     = wine_server_obj_handle( process );
            req->addr       = wine_server_client_ptr( addr );
            wine_server_add_data( req, buffer, size );
            status = wine_server_call( req );
            size = reply->written;
        }
        SERVER_END_REQ;
    }
    if (bytes_written) *bytes_written = size;
    return status;
}


/***********************************************************************
 *             NtAreMappedFilesTheSame   (NTDLL.@)
 *             ZwAreMappedFilesTheSame   (NTDLL.@)
 */
NTSTATUS WINAPI NtAreMappedFilesTheSame(PVOID addr1, PVOID addr2)
{
    struct file_view *view1, *view2;
    unsigned int status;
    sigset_t sigset;

    TRACE("%p %p\n", addr1, addr2);

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    view1 = find_view( addr1, 0 );
    view2 = find_view( addr2, 0 );

    if (!view1 || !view2)
        status = STATUS_INVALID_ADDRESS;
    else if (is_view_valloc( view1 ) || is_view_valloc( view2 ))
        status = STATUS_CONFLICTING_ADDRESSES;
    else if (view1 == view2)
        status = STATUS_SUCCESS;
    else if ((view1->protect & VPROT_SYSTEM) || (view2->protect & VPROT_SYSTEM))
        status = STATUS_NOT_SAME_DEVICE;
    else
    {
        SERVER_START_REQ( is_same_mapping )
        {
            req->base1 = wine_server_client_ptr( view1->base );
            req->base2 = wine_server_client_ptr( view2->base );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


static NTSTATUS prefetch_memory( HANDLE process, ULONG_PTR count,
                                 PMEMORY_RANGE_ENTRY addresses, ULONG flags )
{
    ULONG_PTR i;
    PVOID base;
    SIZE_T size;

    for (i = 0; i < count; i++)
    {
        if (!addresses[i].NumberOfBytes) return STATUS_INVALID_PARAMETER_4;
    }

    if (process != NtCurrentProcess())
    {
        static unsigned int once;

        if (!once++) FIXME( "prefetching another process %p is not supported\n", process );
        return STATUS_SUCCESS;
    }

    for (i = 0; i < count; i++)
    {
        base = ROUND_ADDR( addresses[i].VirtualAddress, host_page_mask );
        size = ROUND_SIZE( addresses[i].VirtualAddress, addresses[i].NumberOfBytes, host_page_mask );
        madvise( base, size, MADV_WILLNEED );
    }

    return STATUS_SUCCESS;
}

static NTSTATUS set_dirty_state_information( ULONG_PTR count, MEMORY_RANGE_ENTRY *addresses )
{
    ULONG_PTR i;
    sigset_t sigset;
    NTSTATUS ret = STATUS_SUCCESS;

#if defined(__APPLE__) && defined(__aarch64__)
    for (i = 0; i < count; i++)
    {
        void *base = ROUND_ADDR( addresses[i].VirtualAddress, page_mask );
        SIZE_T size = ROUND_SIZE( addresses[i].VirtualAddress,
                                  addresses[i].NumberOfBytes, page_mask );

        if (overlaps_wow64_shadow( base, size )) break;
    }
    if (i < count)
    {
        for (i = 0; i < count; i++)
        {
            struct wow64_memory_transaction transaction;
            void *base = ROUND_ADDR( addresses[i].VirtualAddress, page_mask );
            SIZE_T size = ROUND_SIZE( addresses[i].VirtualAddress,
                                      addresses[i].NumberOfBytes, page_mask );
            struct file_view *view;
            NTSTATUS snapshot_status = STATUS_SUCCESS;
            BOOL candidate = overlaps_wow64_shadow( base, size );

            ret = wow64_memory_begin_transaction( &transaction, candidate,
                                                   WINE_WOW64_MEMORY_PROTECT,
                                                   base, size, base );
            if (ret) break;
            server_enter_uninterrupted_section( &virtual_mutex, &sigset );
            if (!(view = find_view( base, size ))) ret = STATUS_MEMORY_NOT_ALLOCATED;
            else if (view->protect & VPROT_WOW64_OWNED_BACKING) ret = STATUS_ACCESS_DENIED;
            else if (use_kernel_writewatch) reset_write_watches( base, size );
            else if (set_page_vprot_exec_write_protect( base, size ))
                mprotect_range( base, size, 0, 0 );
            if (candidate)
            {
                wow64_memory_capture_transaction( &transaction, ret, base, size, base );
                snapshot_status = transaction.event.snapshot_status;
            }
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            wow64_memory_complete_transaction( &transaction );
            if (!ret) ret = snapshot_status;
            if (ret) break;
        }
        return ret;
    }
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < count; i++)
    {
        void *base = ROUND_ADDR( addresses[i].VirtualAddress, page_mask );
        SIZE_T size = ROUND_SIZE( addresses[i].VirtualAddress, addresses[i].NumberOfBytes, page_mask );
        struct file_view *view = find_view( base, size );

        if (!view)
        {
            ret = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }
#if defined(__APPLE__) && defined(__aarch64__)
        if (view->protect & VPROT_WOW64_OWNED_BACKING)
        {
            ret = STATUS_ACCESS_DENIED;
            break;
        }
#endif
        if (use_kernel_writewatch) reset_write_watches( base, size );
        else if (set_page_vprot_exec_write_protect( base, size ))
            mprotect_range( base, size, 0, 0 );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}

/***********************************************************************
 *           NtSetInformationVirtualMemory   (NTDLL.@)
 *           ZwSetInformationVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationVirtualMemory( HANDLE process,
                                               VIRTUAL_MEMORY_INFORMATION_CLASS info_class,
                                               ULONG_PTR count, PMEMORY_RANGE_ENTRY addresses,
                                               PVOID ptr, ULONG size )
{
    TRACE("(%p, info_class=%d, %lu, %p, %p, %u)\n",
          process, info_class, count, addresses, ptr, size);

    switch (info_class)
    {
    case VmPrefetchInformation:
        if (!ptr) return STATUS_INVALID_PARAMETER_5;
        if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER_6;
        if (!count) return STATUS_INVALID_PARAMETER_3;
        return prefetch_memory( process, count, addresses, *(ULONG *)ptr );

    case VmPageDirtyStateInformation:
        if (process != GetCurrentProcess()) return STATUS_NOT_SUPPORTED;
        if (!enable_write_exceptions) return STATUS_NOT_SUPPORTED;
        if (!ptr) return STATUS_INVALID_PARAMETER_5;
        if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER_6;
        if (*(ULONG *)ptr) return STATUS_INVALID_PARAMETER_5;
        if (!count) return STATUS_INVALID_PARAMETER_3;
        return set_dirty_state_information( count, addresses );

    default:
        FIXME("(%p,info_class=%d,%lu,%p,%p,%u) Unknown information class\n",
              process, info_class, count, addresses, ptr, size);
        return STATUS_INVALID_PARAMETER_2;
    }
}


/**********************************************************************
 *           NtFlushInstructionCache  (NTDLL.@)
 */
#if defined(__APPLE__) && defined(__aarch64__) && defined(HAVE___CLEAR_CACHE)
/* Flush only physically accessible host-page runs.  Darwin's cache primitive
 * can signal on PROT_NONE even though a Windows page is logically committed.
 * virtual_mutex must be held by the caller. */
static void flush_instruction_cache_accessible_runs( ULONG_PTR start, ULONG_PTR end,
                                                     BOOL translated )
{
    ULONG_PTR page = start & ~host_page_mask;
    ULONG_PTR run_start = 0, run_end = 0;

    while (page < end)
    {
        ULONG_PTR segment_start = max( page, start );
        ULONG_PTR segment_end = min( page + host_page_size, end );
        BYTE vprot = translated ? get_translated_host_page_vprot( (void *)page )
                                : get_host_page_vprot( (void *)page );

        if (get_unix_prot( vprot ) != PROT_NONE)
        {
            if (!run_start) run_start = segment_start;
            run_end = segment_end;
        }
        else if (run_start)
        {
            __clear_cache( (char *)run_start, (char *)run_end );
            run_start = run_end = 0;
        }
        page += host_page_size;
    }
    if (run_start) __clear_cache( (char *)run_start, (char *)run_end );
}

/* Check one logical page, caching the server's uniform SEC_RESERVE run so a
 * large flush does not issue one mapping query per 4K page.  virtual_mutex
 * must be held by the caller. */
static BOOL is_instruction_cache_page_committed( struct file_view *view, ULONG_PTR page,
                                                 ULONG_PTR end, ULONG_PTR *cached_end,
                                                 BOOL *cached_committed )
{
    BYTE vprot;
    SIZE_T run;

    if (!(view->protect & SEC_RESERVE))
        return !!(get_page_vprot( (void *)page ) & VPROT_COMMITTED);
    if (page >= *cached_end)
    {
        run = get_committed_size( view, (void *)page, end - page,
                                  &vprot, VPROT_COMMITTED );
        if (run < page_size || (run & page_mask) || run > end - page)
        {
            *cached_end = page;
            *cached_committed = FALSE;
            return FALSE;
        }
        *cached_end = page + run;
        *cached_committed = !!(vprot & VPROT_COMMITTED);
    }
    return *cached_committed;
}

static NTSTATUS flush_arm64ec_low_instruction_cache( const void *addr, SIZE_T size )
{
    ULONG_PTR guest = (ULONG_PTR)addr;
    ULONG_PTR host, host_end, guest_end, page, last_page;
    ULONG_PTR committed_end = 0;
    struct file_view *view = NULL;
    sigset_t sigset;
    NTSTATUS status = STATUS_SUCCESS;
    BOOL any_low = FALSE, other_translated = FALSE;
    BOOL translated_valid = TRUE, committed = FALSE;

    /* The caller has already excluded the NULL/zero-length forms. */
    if (guest >= WINE_LOW_VA_SHADOW_SIZE || size > WINE_LOW_VA_SHADOW_SIZE - guest)
        return STATUS_ACCESS_VIOLATION;
    host = WINE_LOW_VA_SHADOW_BASE + guest;
    host_end = host + size;
    guest_end = guest + size;
    page = host & ~page_mask;
    last_page = (host_end - 1) & ~page_mask;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    /* Scan the entire shadow interval before deciding its address model.  If
     * any page has LOW ownership, partial translated coverage is an error and
     * must never fall back to an ordinary mapping at the same guest address. */
    for (;;)
    {
        unsigned int translated_owner;

        if ((!view || page < (ULONG_PTR)view->base ||
             page + page_size > (ULONG_PTR)view->base + view->size) &&
            !(view = find_view( (void *)page, page_size )))
            translated_valid = FALSE;
        else if ((translated_owner = view->protect & VPROT_SHADOW_TRANSLATED) ==
                 VPROT_AMD64_LOW_TRANSLATED)
        {
            ULONG_PTR view_end = (ULONG_PTR)view->base + view->size;

            any_low = TRUE;
            if (view->protect & VPROT_SYSTEM)
                translated_valid = FALSE;
            else if (translated_valid &&
                !is_instruction_cache_page_committed(
                    view, page, min( view_end, last_page + page_size ),
                    &committed_end, &committed ))
                translated_valid = FALSE;
        }
        else
        {
            translated_valid = FALSE;
            if (translated_owner) other_translated = TRUE;
        }
        if (page == last_page) break;
        page += page_size;
    }

    if (any_low || other_translated)
    {
        if (!any_low || other_translated || !translated_valid)
            status = STATUS_ACCESS_VIOLATION;
        else flush_instruction_cache_accessible_runs( host, host_end, TRUE );
    }
    else
    {
        /* With no translated owner, preserve a genuine low identity mapping.
         * Numeric low addresses alone never authorize cache maintenance. */
        view = NULL;
        committed_end = 0;
        page = guest & ~page_mask;
        last_page = (guest_end - 1) & ~page_mask;
        for (;;)
        {
            if (((!view || page < (ULONG_PTR)view->base ||
                  page + page_size > (ULONG_PTR)view->base + view->size) &&
                 !(view = find_view( (void *)page, page_size ))) ||
                (view->protect & (VPROT_SHADOW_TRANSLATED | VPROT_SYSTEM)))
            {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }
            if (!is_instruction_cache_page_committed(
                    view, page,
                    min( (ULONG_PTR)view->base + view->size,
                         last_page + page_size ),
                    &committed_end, &committed ))
            {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }
            if (page == last_page) break;
            page += page_size;
        }
        if (!status) flush_instruction_cache_accessible_runs( guest, guest_end, FALSE );
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}
#endif

NTSTATUS WINAPI NtFlushInstructionCache( HANDLE handle, const void *addr, SIZE_T size )
{
#if defined(__x86_64__) || defined(__i386__)
    /* no-op */
#elif defined(HAVE___CLEAR_CACHE)
    BOOL current_process = handle == NtCurrentProcess();

    /* A duplicated self handle names the same process as the pseudo handle.
     * Resolve that identity before deciding whether local cache maintenance is
     * required; comparison failures retain the historical remote no-op path. */
    if (!current_process)
        current_process = !NtCompareObjects( handle, NtCurrentProcess() );
    if (current_process)
    {
        /* NULL means the whole process cache.  There is no host byte range to
         * clear; the ARM64EC wrapper performs the provider-wide TB flush after
         * this successful syscall. */
        if (!addr) return STATUS_SUCCESS;
#if defined(__APPLE__) && defined(__aarch64__)
        /* The ARM64EC syscall receives a canonical AMD64 address.  Translate
         * only provider-owned fixed-low ranges here; the PE callback still
         * observes the original guest address after this syscall returns. */
        if (is_arm64ec() && addr && size && (ULONG_PTR)addr < WINE_LOW_VA_SHADOW_SIZE)
            return flush_arm64ec_low_instruction_cache( addr, size );
#endif
        __clear_cache( (char *)addr, (char *)addr + size );
    }
    else
    {
        static int once;
        if (!once++) FIXME( "%p %p %ld other process not supported\n", handle, addr, size );
    }
#else
    static int once;
    if (!once++) FIXME( "%p %p %ld\n", handle, addr, size );
#endif
    return STATUS_SUCCESS;
}


#ifdef __APPLE__

static kern_return_t (*p_thread_get_register_pointer_values)( thread_t, uintptr_t*, size_t*, uintptr_t* );
static pthread_once_t tgrpvs_init_once = PTHREAD_ONCE_INIT;

static void tgrpvs_init(void)
{
    p_thread_get_register_pointer_values = dlsym( RTLD_DEFAULT, "thread_get_register_pointer_values" );
    if (!p_thread_get_register_pointer_values)
        FIXME( "thread_get_register_pointer_values not supported for NtFlushProcessWriteBuffers\n" );
}

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    /* Taken from https://github.com/dotnet/runtime/blob/7be37908e5a1cbb83b1062768c1649827eeaceaa/src/coreclr/pal/src/thread/process.cpp#L2799 */
    mach_msg_type_number_t count, i;
    thread_act_array_t threads;

    pthread_once( &tgrpvs_init_once, tgrpvs_init );
    if (!p_thread_get_register_pointer_values) return STATUS_SUCCESS;

    /* Get references to all threads of this process */
    if (task_threads( mach_task_self(), &threads, &count )) return STATUS_SUCCESS;

    for (i = 0; i < count; i++)
    {
        uintptr_t reg_values[128];
        size_t reg_count = ARRAY_SIZE( reg_values );
        uintptr_t sp;

        /* Request the thread's register pointer values to force the thread to go through a memory barrier */
        p_thread_get_register_pointer_values( threads[i], &sp, &reg_count, reg_values );
        mach_port_deallocate( mach_task_self(), threads[i] );
    }
    vm_deallocate( mach_task_self(), (vm_address_t)threads, count * sizeof(threads[0]) );
    return STATUS_SUCCESS;
}

#elif defined(__linux__) && defined(__NR_membarrier)

#define MEMBARRIER_CMD_PRIVATE_EXPEDITED            0x08
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED   0x10

static pthread_once_t membarrier_init_once = PTHREAD_ONCE_INIT;

static int membarrier( int cmd, unsigned int flags, int cpu_id )
{
    return syscall( __NR_membarrier, cmd, flags, cpu_id );
}

static void membarrier_init(void)
{
    if (membarrier( MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0 ))
        FIXME( "membarrier not supported for NtFlushProcessWriteBuffers\n" );
}

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    pthread_once( &membarrier_init_once, membarrier_init );
    membarrier( MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0 );
    return STATUS_SUCCESS;
}

#else /* __linux__ */

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    static int once = 0;
    if (!once++) FIXME( "stub\n" );
    return STATUS_SUCCESS;
}

#endif

/**********************************************************************
 *           NtCreatePagingFile  (NTDLL.@)
 */
NTSTATUS WINAPI NtCreatePagingFile( UNICODE_STRING *name, LARGE_INTEGER *min_size,
                                    LARGE_INTEGER *max_size, LARGE_INTEGER *actual_size )
{
    FIXME( "(%s %p %p %p) stub\n", debugstr_us(name), min_size, max_size, actual_size );
    return STATUS_SUCCESS;
}

#ifndef _WIN64

/***********************************************************************
 *             NtWow64AllocateVirtualMemory64   (NTDLL.@)
 *             ZwWow64AllocateVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64AllocateVirtualMemory64( HANDLE process, ULONG64 *ret, ULONG64 zero_bits,
                                                ULONG64 *size_ptr, ULONG type, ULONG protect )
{
    void *base;
    SIZE_T size;
    unsigned int status;

    TRACE("%p %s %s %x %08x\n", process,
          wine_dbgstr_longlong(*ret), wine_dbgstr_longlong(*size_ptr), type, protect );

    if (!*size_ptr) return STATUS_INVALID_PARAMETER_4;
    if (zero_bits > 21 && zero_bits < 32) return STATUS_INVALID_PARAMETER_3;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc.type         = APC_VIRTUAL_ALLOC;
        call.virtual_alloc.addr         = *ret;
        call.virtual_alloc.size         = *size_ptr;
        call.virtual_alloc.zero_bits    = zero_bits;
        call.virtual_alloc.op_type      = type;
        call.virtual_alloc.prot         = protect;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc.status == STATUS_SUCCESS)
        {
            *ret      = result.virtual_alloc.addr;
            *size_ptr = result.virtual_alloc.size;
        }
        return result.virtual_alloc.status;
    }

    base = (void *)(ULONG_PTR)*ret;
    size = *size_ptr;
    if ((ULONG_PTR)base != *ret) return STATUS_CONFLICTING_ADDRESSES;
    if (size != *size_ptr) return STATUS_WORKING_SET_LIMIT_RANGE;

    status = NtAllocateVirtualMemory( process, &base, zero_bits, &size, type, protect );
    if (!status)
    {
        *ret = (ULONG_PTR)base;
        *size_ptr = size;
    }
    return status;
}


/***********************************************************************
 *             NtWow64ReadVirtualMemory64   (NTDLL.@)
 *             ZwWow64ReadVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64ReadVirtualMemory64( HANDLE process, ULONG64 addr, void *buffer,
                                            ULONG64 size, ULONG64 *bytes_read )
{
    unsigned int status;

    if (size > MAXLONG) size = MAXLONG;

    if (virtual_check_buffer_for_write( buffer, size ))
    {
        SERVER_START_REQ( read_process_memory )
        {
            req->handle = wine_server_obj_handle( process );
            req->addr   = addr;
            wine_server_set_reply( req, buffer, size );
            if ((status = wine_server_call( req ))) size = 0;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_ACCESS_VIOLATION;
        size = 0;
    }
    if (bytes_read) *bytes_read = size;
    return status;
}


/***********************************************************************
 *             NtWow64WriteVirtualMemory64   (NTDLL.@)
 *             ZwWow64WriteVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64WriteVirtualMemory64( HANDLE process, ULONG64 addr, const void *buffer,
                                             ULONG64 size, ULONG64 *bytes_written )
{
    unsigned int status;

    if (size > MAXLONG) size = MAXLONG;

    if (virtual_check_buffer_for_read( buffer, size ))
    {
        SERVER_START_REQ( write_process_memory )
        {
            req->handle     = wine_server_obj_handle( process );
            req->addr       = addr;
            wine_server_add_data( req, buffer, size );
            if ((status = wine_server_call( req ))) size = 0;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    if (bytes_written) *bytes_written = size;
    return status;
}


/***********************************************************************
 *             NtWow64GetNativeSystemInformation   (NTDLL.@)
 *             ZwWow64GetNativeSystemInformation   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64GetNativeSystemInformation( SYSTEM_INFORMATION_CLASS class, void *info,
                                                   ULONG len, ULONG *retlen )
{
    NTSTATUS status;

    switch (class)
    {
    case SystemCpuInformation:
        status = NtQuerySystemInformation( class, info, len, retlen );
        if (!status && is_old_wow64())
        {
            SYSTEM_CPU_INFORMATION *cpu = info;

            if (cpu->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
                cpu->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
        }
        return status;
    case SystemBasicInformation:
    case SystemEmulationBasicInformation:
    case SystemEmulationProcessorInformation:
        return NtQuerySystemInformation( class, info, len, retlen );
    case SystemNativeBasicInformation:
        return NtQuerySystemInformation( SystemBasicInformation, info, len, retlen );
    default:
        if (is_old_wow64()) return STATUS_INVALID_INFO_CLASS;
        return NtQuerySystemInformation( class, info, len, retlen );
    }
}

/***********************************************************************
 *             NtWow64IsProcessorFeaturePresent   (NTDLL.@)
 *             ZwWow64IsProcessorFeaturePresent   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64IsProcessorFeaturePresent( UINT feature )
{
    return feature < PROCESSOR_FEATURE_MAX && user_shared_data->ProcessorFeatures[feature];
}

#endif  /* _WIN64 */
