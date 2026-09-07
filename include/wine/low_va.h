/*
 * Wine low virtual-address translation helpers
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_LOW_VA_H
#define __WINE_LOW_VA_H

#include <stdint.h>

/* Keep the shadow outside the normal PE image range and preserve low 32 bits. */
#define WINE_LOW_VA_SHADOW_BASE       0x0000010000000000ull
#define WINE_LOW_VA_SHADOW_SIZE       0x0000000100000000ull
#define WINE_USER_SHARED_DATA_ADDRESS 0x000000007ffe0000ull

/* The ARM64EC EC-code bitmap describes the 47-bit x64 user address domain.
 * Keep this semantic limit shared by the PE and Unix-side readers; pointers at
 * or above the exclusive limit must never be used to index EcCodeBitMap. */
#define WINE_ARM64EC_CODE_POINTER_BITS  47
#define WINE_ARM64EC_CODE_POINTER_LIMIT (1ull << WINE_ARM64EC_CODE_POINTER_BITS)

#if WINE_ARM64EC_CODE_POINTER_LIMIT != 0x0000800000000000ull
# error WINE_ARM64EC_CODE_POINTER_LIMIT must describe the 47-bit x64 user domain
#endif
#if WINE_ARM64EC_CODE_POINTER_LIMIT <= WINE_LOW_VA_SHADOW_BASE + WINE_LOW_VA_SHADOW_SIZE
# error WINE_ARM64EC_CODE_POINTER_LIMIT must contain the complete low-VA shadow
#endif

static inline int wine_arm64ec_code_pointer_in_range( uint64_t ptr )
{
    return ptr < WINE_ARM64EC_CODE_POINTER_LIMIT;
}

/* Wine-private MEM_EXTENDED_PARAMETER type used only across the WoW64/native
 * boundary.  Keep it out of the public Windows enum namespace.  For translated
 * legacy NtMapViewOfSection calls, ULong64 carries the 32-bit CommitSize. */
#define WINE_MEM_EXTENDED_PARAMETER_WOW64_TRANSLATED 31

/* Internal APC transport flag, stored separately from public attributes. */
#define WINE_APC_MEMORY_WOW64_TRANSLATED 0x00000001u
/* map_view_ex.attributes carries the 32-bit CommitSize while this is set. */
#define WINE_APC_MEMORY_MAP_COMMIT_SIZE   0x00000002u

/* Native ntdll.so / CPU-provider memory synchronization contract.  This is a
 * process-lifetime host-C ABI, not a PE export.  Address fields are in the
 * native process address space; providers normalize the translated shadow to
 * their guest address space.  VPROT_WOW64_TRANSLATED is the authoritative
 * ownership tag and is established only by explicit translated provenance:
 * public ongoing mappings use private parameter type 31, while ntdll owns the
 * initial i386 image bootstrap and internal KUSER/TEB/stack mappings.  A
 * numeric shadow address or PE machine never establishes ownership. */
#define WINE_WOW64_MEMORY_OBSERVER_VERSION 1u

enum wine_wow64_memory_operation
{
    WINE_WOW64_MEMORY_RESYNC = 1,
    WINE_WOW64_MEMORY_ALLOCATE,
    WINE_WOW64_MEMORY_COMMIT,
    WINE_WOW64_MEMORY_PROTECT,
    WINE_WOW64_MEMORY_DECOMMIT,
    WINE_WOW64_MEMORY_RELEASE,
    WINE_WOW64_MEMORY_MAP,
    WINE_WOW64_MEMORY_UNMAP,
};

#define WINE_WOW64_MEMORY_RANGE_TRANSLATED 0x00000001u
/* The provider must remove guest write permission for this logical 4K range
 * even when an adjacent lane keeps the containing host page writable. */
#define WINE_WOW64_MEMORY_RANGE_LOGICAL_WRITE_FAULT 0x00000002u

/* Registration is capability-negotiated.  Providers that do not understand
 * per-logical-page write-fault arming must fail registration instead of
 * silently accepting protections they cannot enforce. */
#define WINE_WOW64_MEMORY_OBSERVER_CAP_LOGICAL_WRITE_FAULT 0x0000000000000001ull

struct wine_wow64_memory_range_v1
{
    uint64_t address;
    uint64_t size;
    uint64_t allocation_base;
    uint32_t state;
    uint32_t protect;
    uint32_t flags;
    uint32_t reserved;
};

#define WINE_WOW64_MEMORY_EVENT_FULL_SNAPSHOT 0x00000001u

struct wine_wow64_memory_event_v1
{
    uint32_t version;
    uint32_t size;
    uint32_t operation;
    uint32_t flags;
    int32_t status;
    int32_t snapshot_status;
    uint32_t reserved[2];
    uint64_t address;
    uint64_t size_covered;
    uint64_t allocation_base;
    const struct wine_wow64_memory_range_v1 *ranges;
    uint64_t range_count;
};

/* begin() runs before ntdll's virtual-memory lock and must stop provider
 * execution until complete() returns.  On a successful begin(), complete() is
 * called exactly once outside that lock, including when the requested mutation
 * fails.  Observer callbacks may issue read-only virtual-memory queries but
 * must not reenter a translated mutation.  The event ranges are sorted,
 * non-overlapping, and cover [address, address + size_covered) exactly in 4K
 * logical-page units.  They describe actual post-operation state, so consumers
 * apply a successful snapshot even when event.status reports mutation failure;
 * a failing snapshot_status must poison/fail closed.  Range storage is borrowed
 * and remains valid only for the duration of complete(). */
struct wine_wow64_memory_observer_v1
{
    uint32_t version;
    uint32_t size;
    void *context;
    int32_t (*begin)( void *context, uint32_t operation, uint64_t address,
                      uint64_t size, uint64_t allocation_base, void **transaction );
    void (*complete)( void *context, void *transaction,
                      const struct wine_wow64_memory_event_v1 *event );
    uint64_t capabilities;
};

/* Native ARM64EC / x64 CPU-provider synchronization for relocation-stripped
 * AMD64 images whose authoritative backing lives in the high shadow.  This is
 * deliberately independent of the i386 observer above: it publishes only
 * explicitly tagged AMD64-low views, and the provider derives canonical guest
 * addresses by checked subtraction of WINE_LOW_VA_SHADOW_BASE.  Identity
 * mappings remain outside this observer's ownership.  Relocation-stripped
 * main-image bootstrap is explicit loader provenance.  After registration,
 * an ARM64EC process may also establish a tagged anonymous view by explicitly
 * reserving a nonzero canonical-low address; ordinary NULL-base allocations
 * and later public SEC_IMAGE mappings never acquire LOW ownership. */
#define WINE_ARM64EC_LOW_MEMORY_OBSERVER_VERSION 1u
#define WINE_ARM64EC_LOW_MEMORY_OBSERVER_CAP_EXACT_POST_SNAPSHOT 0x0000000000000001ull

#define WINE_ARM64EC_LOW_MEMORY_RANGE_VALID_FLAGS 0u

struct wine_arm64ec_low_memory_range_v1
{
    uint64_t host_address;
    uint64_t size;
    uint64_t host_allocation_base;
    uint32_t state;
    uint32_t protect;
    uint32_t flags;
    uint32_t reserved;
};

#define WINE_ARM64EC_LOW_MEMORY_EVENT_FULL_SNAPSHOT 0x00000001u

struct wine_arm64ec_low_memory_event_v1
{
    uint32_t version;
    uint32_t size;
    uint32_t operation;
    uint32_t flags;
    int32_t status;
    int32_t snapshot_status;
    uint32_t reserved[2];
    uint64_t host_address;
    uint64_t size_covered;
    uint64_t host_allocation_base;
    const struct wine_arm64ec_low_memory_range_v1 *ranges;
    uint64_t range_count;
};

/* begin() quiesces all x64 engines before ntdll takes its virtual-memory lock.
 * Its interval is a nonempty, page-aligned conservative hint; operations such
 * as unmap and MEM_RELEASE may resolve a larger exact view only after the lock
 * is held.  Every successful begin() receives exactly one complete() outside
 * that lock, including when the mutation fails.  The post-state ranges are
 * sorted, non-overlapping, and exactly cover the completion event interval,
 * including MEM_FREE gaps.  A nested mutation is normally reconciled with a
 * FULL_SNAPSHOT covering the complete 4-GiB shadow.  Ntdll may coalesce an
 * exactly matching nested operation into an outer transaction only when it
 * owns stable serialization for that interval and its completion captures the
 * authoritative post-state.  Range storage is borrowed for complete() only. */
struct wine_arm64ec_low_memory_observer_v1
{
    uint32_t version;
    uint32_t size;
    void *context;
    int32_t (*begin)( void *context, uint32_t operation, uint64_t host_address,
                      uint64_t size, uint64_t host_allocation_base,
                      void **transaction );
    void (*complete)( void *context, void *transaction,
                      const struct wine_arm64ec_low_memory_event_v1 *event );
    uint64_t capabilities;
};

/* Native ARM64EC code-ownership synchronization.  The EcCodeBitMap is read by
 * x64 CPU providers when translating a block.  Once a provider caches that
 * classification in generated code, every bitmap writer must first quiesce
 * guest execution and then invalidate all translated blocks whose page
 * classification may have changed.  This observer is intentionally separate
 * from the AMD64-low mapping observer: it owns code classification only and
 * publishes native guest addresses rather than shadow-host mappings. */
#define WINE_ARM64EC_CODE_OBSERVER_VERSION 1u
#define WINE_ARM64EC_CODE_OBSERVER_CAP_EXACT_INVALIDATION_RANGES \
    0x0000000000000001ull

enum wine_arm64ec_code_operation
{
    WINE_ARM64EC_CODE_RESYNC = 1,
    WINE_ARM64EC_CODE_ALLOCATE,
    WINE_ARM64EC_CODE_RELEASE,
    WINE_ARM64EC_CODE_MAP,
    WINE_ARM64EC_CODE_UNMAP,
    WINE_ARM64EC_CODE_PROTECT,
};

struct wine_arm64ec_code_range_v1
{
    uint64_t address;
    uint64_t size;
};

#define WINE_ARM64EC_CODE_EVENT_FULL_INVALIDATION 0x00000001u

struct wine_arm64ec_code_event_v1
{
    uint32_t version;
    uint32_t size;
    uint32_t operation;
    uint32_t flags;
    int32_t status;
    uint32_t reserved;
    const struct wine_arm64ec_code_range_v1 *ranges;
    uint64_t range_count;
};

/* begin() runs before ntdll takes its virtual-memory lock and must keep every
 * x64 engine quiescent until complete() returns.  Each successful begin()
 * receives exactly one complete(), including when the Windows mutation fails.
 * Successful events contain the sorted, merged union of page-aligned bitmap
 * writes.  FULL_INVALIDATION is the fail-closed fallback for registration,
 * nested mutation, or range-capture exhaustion.  Range storage is borrowed
 * for complete() only. */
struct wine_arm64ec_code_observer_v1
{
    uint32_t version;
    uint32_t size;
    void *context;
    int32_t (*begin)( void *context, uint32_t operation, void **transaction );
    void (*complete)( void *context, void *transaction,
                      const struct wine_arm64ec_code_event_v1 *event );
    uint64_t capabilities;
};

/* Normal-context fault resolution between the i386 CPU provider and ntdll.so.
 * The provider must stop the faulting engine and publish it as not running
 * before calling this entry point.  WoW64 thunk copies may also call it while
 * servicing a system call or native callback, where guest execution is already
 * stopped.  Observer callbacks are not async-signal-safe. */
#define WINE_WOW64_MEMORY_FAULT_VERSION 1u

enum wine_wow64_memory_fault_action
{
    WINE_WOW64_MEMORY_FAULT_RETRY = 1,
    WINE_WOW64_MEMORY_FAULT_RAISE,
};

enum wine_wow64_memory_fault_access
{
    WINE_WOW64_MEMORY_FAULT_READ = 0,
    WINE_WOW64_MEMORY_FAULT_WRITE = 1,
    WINE_WOW64_MEMORY_FAULT_EXECUTE = 8,
};

struct wine_wow64_memory_fault_result_v1
{
    uint32_t version;
    uint32_t size;
    uint32_t action;
    uint32_t reserved;
    int32_t status;
    uint32_t parameter_count;
    uint64_t information[3];
};

#if !defined(_WIN32)
# if defined(__GNUC__)
#  define WINE_LOW_VA_EXPORT __attribute__((visibility("default")))
# else
#  define WINE_LOW_VA_EXPORT
# endif
/* Registration is process-lifetime and succeeds once.  The observer must
 * advertise WINE_WOW64_MEMORY_OBSERVER_CAP_LOGICAL_WRITE_FAULT.  Registration
 * synchronously calls
 * begin()/complete() with a full RESYNC while memory mutations are excluded;
 * STATUS_SUCCESS is not returned until that complete() callback has returned. */
WINE_LOW_VA_EXPORT int32_t __wine_register_wow64_memory_observer(
    const struct wine_wow64_memory_observer_v1 *observer );
/* Experimental CPU-only backing lease. Acquired only from the code observer
 * complete callback, with engines stopped and without the provider lock.
 * Native ABI pointers never change. release requires every engine to have
 * revoked mappings referring to this snapshot. Limited to 16KB private data. */
#define WINE_ARM64EC_CODE_OBSERVER_CAP_DATA_ALIAS 0x0000000000000002ull
#define WINE_ARM64EC_CPU_ALIAS_VERSION 1u
#define WINE_ARM64EC_CPU_ALIAS_MAX 64u
struct wine_arm64ec_cpu_alias_range_v1
{
    uint64_t address, backing, allocation_base;
    uint32_t protect[4], state[4];
};
struct wine_arm64ec_cpu_alias_snapshot_v1
{
    uint32_t version, size, count, reserved;
    struct wine_arm64ec_cpu_alias_range_v1 ranges[WINE_ARM64EC_CPU_ALIAS_MAX];
};
WINE_LOW_VA_EXPORT int32_t __wine_acquire_arm64ec_cpu_alias_v1(
    const struct wine_arm64ec_cpu_alias_snapshot_v1 *previous,
    struct wine_arm64ec_cpu_alias_snapshot_v1 **result );
WINE_LOW_VA_EXPORT void __wine_release_arm64ec_cpu_alias_v1(
    struct wine_arm64ec_cpu_alias_snapshot_v1 *snapshot );
/* Registration is process-lifetime and ARM64EC-only.  It synchronously
 * completes an exact full post-state snapshot before returning success. */
WINE_LOW_VA_EXPORT int32_t __wine_register_arm64ec_low_memory_observer_v1(
    const struct wine_arm64ec_low_memory_observer_v1 *observer );
/* Registration is process-lifetime and ARM64EC-only.  It synchronously
 * completes a full invalidation while native bitmap writers are excluded. */
WINE_LOW_VA_EXPORT int32_t __wine_register_arm64ec_code_observer_v1(
    const struct wine_arm64ec_code_observer_v1 *observer );
WINE_LOW_VA_EXPORT int32_t __wine_resolve_wow64_memory_fault_v1(
    uint64_t host_address, uint32_t access_type,
    struct wine_wow64_memory_fault_result_v1 *result );
/* Normal-context identity fault resolution. The code observer quiesces all
 * engines before virtual_mutex; publish runs under both gates with exact
 * post-state ranges. It must not call back into ntdll VM operations. */
WINE_LOW_VA_EXPORT int32_t __wine_resolve_arm64ec_memory_fault_v1(
    uint64_t address, uint32_t access_type,
    struct wine_wow64_memory_fault_result_v1 *result, void *context,
    int32_t (*publish)( void *, uint64_t, uint64_t, uint64_t, uint32_t ) );
WINE_LOW_VA_EXPORT int32_t __wine_lock_arm64ec_mapping_snapshot_v1(void);
WINE_LOW_VA_EXPORT int32_t __wine_unlock_arm64ec_mapping_snapshot_v1(void);
WINE_LOW_VA_EXPORT int32_t __wine_get_arm64ec_exception_stack_v1( uint64_t *limit, uint64_t *base );
# undef WINE_LOW_VA_EXPORT
#endif

#endif /* __WINE_LOW_VA_H */
