/*
 * ARM64EC/x64 provider transition flight recorder
 *
 * Copyright 2026 Switchyard contributors
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
 */

#ifndef __WINE_XTAJIT64_FLIGHT_RECORDER_H
#define __WINE_XTAJIT64_FLIGHT_RECORDER_H

#include <string.h>

#include "windef.h"

/* This is an in-process diagnostic ABI shared by ARM64EC PE code and the
 * native Unix provider.  It intentionally has no pointers or host-dependent
 * types in records.  Raw addresses are retained only while the caller has
 * explicitly enabled the engineering diagnostic. */
#define XTAJIT64_FLIGHT_MAGIC          0x3154474c46545858ull /* "XXFTLGT1" */
#define XTAJIT64_FLIGHT_SCHEMA_VERSION 6u
#define XTAJIT64_FLIGHT_CAPACITY       64u
#define XTAJIT64_FLIGHT_SCRATCH_SLOTS  8u
#define XTAJIT64_FLIGHT_RECORDER_SIZE  0x6880u
#define XTAJIT64_FLIGHT_UNKNOWN_U64    (~(UINT64)0)
#define XTAJIT64_FLIGHT_UNKNOWN_U32    (~(UINT32)0)
#define XTAJIT64_FLIGHT_OWNER_BUSY     0x8000000000000000ull
#define XTAJIT64_FLIGHT_SPIN_LIMIT     256u

enum xtajit64_flight_event_type
{
    XTAJIT64_FLIGHT_EVENT_NONE,
    XTAJIT64_FLIGHT_EVENT_RECORDER_READY,
    XTAJIT64_FLIGHT_EVENT_TRANSITION_CAPTURE,
    XTAJIT64_FLIGHT_EVENT_TRANSITION_BEGIN,
    XTAJIT64_FLIGHT_EVENT_CONTEXT_IMPORT,
    XTAJIT64_FLIGHT_EVENT_UNIX_ENTERED_SYSTEM_MODE,
    XTAJIT64_FLIGHT_EVENT_BINDING,
    XTAJIT64_FLIGHT_EVENT_ENGINE_ACQUIRE,
    XTAJIT64_FLIGHT_EVENT_PROVIDER_BEGIN,
    XTAJIT64_FLIGHT_EVENT_PROVIDER_RESUME,
    XTAJIT64_FLIGHT_EVENT_ATOMIC_EXIT,
    XTAJIT64_FLIGHT_EVENT_ATOMIC_REENTRY,
    XTAJIT64_FLIGHT_EVENT_PROVIDER_STOP,
    XTAJIT64_FLIGHT_EVENT_CONTEXT_EXPORT,
    XTAJIT64_FLIGHT_EVENT_ENGINE_RELEASE,
    XTAJIT64_FLIGHT_EVENT_TRANSITION_CONTINUE,
    XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_PUSH,
    XTAJIT64_FLIGHT_EVENT_TRANSITION_FRAME_POP,
    XTAJIT64_FLIGHT_EVENT_TRANSITION_UNWIND,
    XTAJIT64_FLIGHT_EVENT_TRANSITION_RECONCILE,
    XTAJIT64_FLIGHT_EVENT_MAPPING_GENERATION,
    XTAJIT64_FLIGHT_EVENT_SUSPEND_REQUEST,
    XTAJIT64_FLIGHT_EVENT_SUSPEND_ACKNOWLEDGED,
    XTAJIT64_FLIGHT_EVENT_TRANSITION_STACK_CLASSIFY,
    XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION,
};

enum xtajit64_flight_reason
{
    XTAJIT64_FLIGHT_REASON_NONE,
    XTAJIT64_FLIGHT_REASON_CONTEXT_FLAGS,
    XTAJIT64_FLIGHT_REASON_CONTEXT_MXCSR,
    XTAJIT64_FLIGHT_REASON_CONTEXT_RIP,
    XTAJIT64_FLIGHT_REASON_CONTEXT_RSP,
    XTAJIT64_FLIGHT_REASON_CONTEXT_STACK,
    XTAJIT64_FLIGHT_REASON_TRANSITION_STACK,
    XTAJIT64_FLIGHT_REASON_CONTINUATION_PAIR,
    XTAJIT64_FLIGHT_REASON_CONTEXT_STALE_PUBLICATION,
    XTAJIT64_FLIGHT_REASON_X18_MODE,
    XTAJIT64_FLIGHT_REASON_X18_VALUE,
    XTAJIT64_FLIGHT_REASON_TRANSITION_DEPTH,
    XTAJIT64_FLIGHT_REASON_TERMINAL_ABORT,
    XTAJIT64_FLIGHT_REASON_RECORDER_WRAP,
    XTAJIT64_FLIGHT_REASON_RECORDER_INVALID,
    XTAJIT64_FLIGHT_REASON_SIMULATION_OWNERSHIP,
};

enum xtajit64_flight_custom_x18_mode
{
    XTAJIT64_FLIGHT_X18_MODE_UNKNOWN,
    XTAJIT64_FLIGHT_X18_MODE_DISABLED,
    XTAJIT64_FLIGHT_X18_MODE_ENABLED,
};

enum xtajit64_flight_x18_expectation
{
    XTAJIT64_FLIGHT_X18_EXPECTATION_UNKNOWN,
    XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM,
    XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC,
};

enum xtajit64_flight_source
{
    XTAJIT64_FLIGHT_SOURCE_UNKNOWN,
    XTAJIT64_FLIGHT_SOURCE_ARM64EC_PE,
    XTAJIT64_FLIGHT_SOURCE_UNIX_PROVIDER,
};

enum xtajit64_flight_transition_frame_kind
{
    XTAJIT64_FLIGHT_FRAME_UNKNOWN,
    XTAJIT64_FLIGHT_FRAME_ENTRY,
    XTAJIT64_FLIGHT_FRAME_EXIT,
};

#define XTAJIT64_FLIGHT_MAX_TRANSITION_FRAMES 64u

#define XTAJIT64_FLIGHT_STACK_REJECT_RIP_RANGE        0x00000001u
#define XTAJIT64_FLIGHT_STACK_REJECT_RSP_RANGE        0x00000002u
#define XTAJIT64_FLIGHT_STACK_REJECT_GS_RANGE         0x00000004u
#define XTAJIT64_FLIGHT_STACK_REJECT_TEB_IDENTITY     0x00000008u
#define XTAJIT64_FLIGHT_STACK_REJECT_CPU_MISSING      0x00000010u
#define XTAJIT64_FLIGHT_STACK_REJECT_CPU_IDENTITY     0x00000020u
#define XTAJIT64_FLIGHT_STACK_REJECT_TRANSLATE_STATUS 0x00000040u
#define XTAJIT64_FLIGHT_STACK_REJECT_TRANSLATED_GUEST 0x00000080u
#define XTAJIT64_FLIGHT_STACK_REJECT_STACK_RANGE      0x00000100u
#define XTAJIT64_FLIGHT_STACK_REJECT_PROBE_NOT_RUN    0x00000200u
#define XTAJIT64_FLIGHT_STACK_REJECT_FRAME_DEPTH      0x00000400u

#define XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR 0x00000001u
#define XTAJIT64_FLIGHT_STACK_MATCH_TEB      0x00000002u

#define XTAJIT64_FLIGHT_FLAG_RAW_DIAGNOSTIC          0x00000001u
#define XTAJIT64_FLIGHT_FLAG_TIME_UNAVAILABLE        0x00000002u
#define XTAJIT64_FLIGHT_FLAG_CONTEXT_VERSION_UNKNOWN 0x00000004u
#define XTAJIT64_FLIGHT_FLAG_CONTEXT_FLAGS_UNKNOWN   0x00000008u
#define XTAJIT64_FLIGHT_FLAG_SAVED_X18_UNKNOWN       0x00000010u
#define XTAJIT64_FLIGHT_FLAG_MODE_QUERY_SAFE         0x00000020u
#define XTAJIT64_FLIGHT_FLAG_EXECUTION_MODE_UNKNOWN  0x00000040u
#define XTAJIT64_FLIGHT_FLAG_EXPECT_PRIVATE_CONTROL_STACK 0x00000080u
#define XTAJIT64_FLIGHT_FLAG_EXPECTED_TEB_AUTHENTICATED 0x00000100u
#define XTAJIT64_FLIGHT_FLAG_PE_X18_CLAIM_PRESENT    0x00000200u

/* Same-thread provider ownership sampled at the event boundary.  UNKNOWN is
 * retained until the PE-side TEB has been independently authenticated; an
 * untrusted doorbell pointer is never dereferenced unless it is the exact
 * provider-owned word in the transition state. */
#define XTAJIT64_FLIGHT_OWNERSHIP_SIMULATION_ACTIVE  0x00000001u
#define XTAJIT64_FLIGHT_OWNERSHIP_SYSCALL_CALLBACK   0x00000002u
#define XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_PRESENT   0x00000004u
#define XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_OWNED     0x00000008u
#define XTAJIT64_FLIGHT_OWNERSHIP_DOORBELL_SET       0x00000010u

/* A writer first invalidates publication_sequence, fills the payload, then
 * release-publishes the matching sequence.  A reader checks it before and
 * after copying.  Invalidation is essential: without it a reader could accept
 * an old sequence while a wrapping writer overwrites the payload. */
struct DECLSPEC_ALIGN(64) xtajit64_flight_event
{
    volatile UINT64 publication_sequence;
    UINT64 sequence;
    UINT64 monotonic_timestamp_ns;
    UINT64 causal_boundary_id;
    UINT64 binding_id;
    UINT64 engine_id;
    UINT64 engine_generation;
    UINT64 mapping_generation;
    UINT64 context_generation;
    UINT64 transition_generation;
    UINT64 guest_rip;
    UINT64 guest_rsp;
    /* Declared Windows x64 stack range; guest_rsp is checked against it. */
    UINT64 guest_stack_limit;
    UINT64 guest_stack_base;
    UINT64 arm64ec_pc;
    /* Live native observation at this event's source, never a guest register. */
    UINT64 native_pc;
    UINT64 native_sp;
    UINT64 native_frame;
    /* Declared private native transition/control stack range, when present. */
    UINT64 control_stack_limit;
    UINT64 control_stack_top;
    UINT64 x18_value;
    UINT64 saved_x18_value;
    UINT64 expected_teb;
    UINT64 pid;
    UINT64 wine_tid;
    UINT64 mach_thread_id;
    UINT64 pthread_identity;
    /* Event-specific raw diagnostic values.  Context validation uses these
     * for continuation PC/RSP; TRANSITION_CAPTURE uses saved pre-switch
     * native SP/PC; a Unix PROVIDER_STOP produced by UC_HOOK_INTR uses
     * detail0 for the exact INT number (for example 0x2e or 0x80). */
    UINT64 detail0;
    UINT64 detail1;
    UINT32 event_type;
    UINT32 reason;
    UINT32 stop_reason;
    UINT32 custom_x18_mode;
    UINT32 x18_expectation;
    UINT32 context_flags;
    UINT32 mxcsr;
    UINT32 fltsave_mxcsr;
    UINT32 flags;
    UINT32 source;
    /* Transition-frame events deliberately keep this separate from provider
     * stop_reason.  For all other event types these fields are UNKNOWN. */
    UINT32 transition_frame_kind;
    UINT32 transition_depth_before;
    UINT32 transition_depth_after;
    UINT32 ownership_flags;
};

struct xtajit64_flight_transition_frame_snapshot
{
    UINT64 guest_rsp;
    UINT64 native_sp;
    UINT64 native_pc;
    UINT32 kind;
    UINT32 depth;
};

/* This side payload exists only for the first transition-stack violation.  It
 * keeps predicate-specific evidence and the complete bounded frame stack out
 * of the general 320-byte event ABI, while remaining allocation-free. */
struct DECLSPEC_ALIGN(64) xtajit64_flight_transition_stack_violation
{
    UINT64 guest_rip;
    UINT64 guest_rsp;
    UINT64 gs_base;
    UINT64 expected_teb;
    UINT64 fresh_teb;
    UINT64 expected_cpu;
    UINT64 fresh_cpu;
    UINT64 translated_guest;
    UINT64 host_rsp;
    UINT64 allocation_base;
    UINT64 emulator_stack_limit;
    UINT64 emulator_stack_base;
    UINT64 teb_stack_limit;
    UINT64 teb_stack_base;
    UINT64 causal_boundary_id;
    UINT64 context_generation;
    UINT64 transition_generation;
    UINT32 translation_status;
    UINT32 translation_domain;
    UINT32 reject_mask;
    UINT32 stack_match_mask;
    UINT32 capture_kind;
    UINT32 depth;
    UINT32 frame_count;
    UINT32 reserved;
    struct xtajit64_flight_transition_frame_snapshot
        frames[XTAJIT64_FLIGHT_MAX_TRANSITION_FRAMES];
};

/* Event construction must not use a possibly shared guest stack, and a
 * signal/non-local re-entry may interrupt a producer on the same thread.  A
 * recorder-owned bounded pool supplies exclusive construction storage without
 * allocating or serializing the common ring path. */
struct DECLSPEC_ALIGN(64) xtajit64_flight_scratch
{
    volatile UINT32 in_use;
    UINT32 reserved[15];
    struct xtajit64_flight_event event;
};

struct DECLSPEC_ALIGN(64) xtajit64_flight_recorder
{
    UINT64 magic;
    UINT32 schema_version;
    UINT32 capacity;
    volatile UINT64 next_sequence;
    volatile UINT64 next_causal_boundary_id;
    /* Unix flight_bind authenticates the stable PE x18 claim against its
     * independently-backed TEB and release-publishes the authoritative value
     * here.  PE producers must not replace it with a fresh NtCurrentTeb()
     * read, since ARM64EC implements that macro through x18 itself. */
    volatile UINT64 authenticated_teb;
    volatile UINT64 frozen_sequence;
    volatile UINT32 freeze_state; /* 0 active, 2 being frozen, 1 frozen */
    volatile UINT32 freeze_reason;
    /* Producers report bounded pre-ticket contention loss.  A loss after a
     * ticket was issued is represented by that ticket's missing ring slot. */
    volatile UINT64 contention_loss_count;
    /* A bounded construction-pool exhaustion is separately visible. */
    volatile UINT64 scratch_loss_count;
    /* The first watchdog winner has a separate atomically-published payload,
     * so choosing the freeze reason never races with ring-slot ownership. */
    volatile UINT64 first_violation_publication;
    /* The PE transition owner release-publishes the newest boundary before
     * entering Unix.  Context and transition generations deliberately share
     * this boundary clock, so the hot BeginSimulation call can refresh all
     * three identities without a second diagnostic-only Unix dispatch. */
    volatile UINT64 published_boundary_id;
    volatile UINT64 transition_stack_violation_publication;
    struct xtajit64_flight_event first_violation;
    struct xtajit64_flight_transition_stack_violation transition_stack_violation;
    struct xtajit64_flight_scratch scratch[XTAJIT64_FLIGHT_SCRATCH_SLOTS];
    /* A slot belongs only to the writer holding its exact generation.  The
     * busy bit prevents an old stalled writer from publishing after a newer
     * generation has reused the same slot. */
    volatile UINT64 slot_owners[XTAJIT64_FLIGHT_CAPACITY];
    struct xtajit64_flight_event events[XTAJIT64_FLIGHT_CAPACITY];
};

enum xtajit64_flight_snapshot_state
{
    XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED,
    XTAJIT64_FLIGHT_SNAPSHOT_UNCOMMITTED,
    XTAJIT64_FLIGHT_SNAPSHOT_OVERWRITTEN,
    XTAJIT64_FLIGHT_SNAPSHOT_TORN,
};

struct xtajit64_flight_snapshot
{
    UINT64 first_sequence;
    UINT64 last_sequence;
    UINT64 frozen_sequence;
    UINT64 lost_count;
    UINT64 contention_loss_count;
    UINT64 scratch_loss_count;
    UINT32 freeze_reason;
    UINT32 count;
    UINT32 torn_count;
    UINT32 states[XTAJIT64_FLIGHT_CAPACITY];
    struct xtajit64_flight_event events[XTAJIT64_FLIGHT_CAPACITY];
};

struct xtajit64_flight_snapshot_metadata
{
    UINT64 first_sequence;
    UINT64 last_sequence;
    UINT64 frozen_sequence;
    UINT64 historical_loss_count;
    UINT64 contention_loss_count;
    UINT64 scratch_loss_count;
    UINT32 freeze_reason;
    UINT32 freeze_state;
    BOOL first_violation_available;
};

C_ASSERT( !(XTAJIT64_FLIGHT_CAPACITY & (XTAJIT64_FLIGHT_CAPACITY - 1)) );
C_ASSERT( sizeof(struct xtajit64_flight_event) == 320 );
C_ASSERT( sizeof(struct xtajit64_flight_transition_frame_snapshot) == 32 );
C_ASSERT( sizeof(struct xtajit64_flight_transition_stack_violation) == 0x8c0 );
C_ASSERT( sizeof(struct xtajit64_flight_scratch) % 64 == 0 );
C_ASSERT( offsetof(struct xtajit64_flight_scratch, event) % 64 == 0 );
C_ASSERT( !(XTAJIT64_FLIGHT_SCRATCH_SLOTS & (XTAJIT64_FLIGHT_SCRATCH_SLOTS - 1)) );
C_ASSERT( offsetof(struct xtajit64_flight_recorder, first_violation) % 64 == 0 );
C_ASSERT( offsetof(struct xtajit64_flight_recorder, transition_stack_violation) % 64 == 0 );
C_ASSERT( offsetof(struct xtajit64_flight_recorder, scratch) % 64 == 0 );
C_ASSERT( offsetof(struct xtajit64_flight_recorder, slot_owners) % sizeof(UINT64) == 0 );
C_ASSERT( offsetof(struct xtajit64_flight_recorder, events) % 64 == 0 );
C_ASSERT( sizeof(struct xtajit64_flight_recorder) == XTAJIT64_FLIGHT_RECORDER_SIZE );
C_ASSERT( sizeof(struct xtajit64_flight_recorder) % 64 == 0 );

/* Every slot payload access is atomic.  The publication word is still the
 * commit protocol, but using atomics for the payload as well avoids relying on
 * a C-level data race being benign when a wrapping writer invalidates a slot
 * while a diagnostic reader is taking a best-effort snapshot. */
#define XTAJIT64_FLIGHT_EVENT_U64_FIELDS(_) \
    _(sequence) _(monotonic_timestamp_ns) _(causal_boundary_id) _(binding_id) \
    _(engine_id) _(engine_generation) _(mapping_generation) _(context_generation) \
    _(transition_generation) _(guest_rip) _(guest_rsp) _(arm64ec_pc) \
    _(guest_stack_limit) _(guest_stack_base) _(native_pc) _(native_sp) \
    _(native_frame) _(control_stack_limit) _(control_stack_top) _(x18_value) \
    _(saved_x18_value) _(expected_teb) \
    _(pid) _(wine_tid) _(mach_thread_id) _(pthread_identity) _(detail0) _(detail1)
#define XTAJIT64_FLIGHT_EVENT_U32_FIELDS(_) \
    _(event_type) _(reason) _(stop_reason) _(custom_x18_mode) _(x18_expectation) \
    _(context_flags) _(mxcsr) _(fltsave_mxcsr) _(flags) _(source) \
    _(transition_frame_kind) _(transition_depth_before) _(transition_depth_after) _(ownership_flags)

static inline void xtajit64_flight_store_event( struct xtajit64_flight_event *dst,
                                                const struct xtajit64_flight_event *src )
{
#define XTAJIT64_FLIGHT_STORE_U64(field) \
    __atomic_store_n( &dst->field, src->field, __ATOMIC_RELAXED );
#define XTAJIT64_FLIGHT_STORE_U32(field) \
    __atomic_store_n( &dst->field, src->field, __ATOMIC_RELAXED );
    XTAJIT64_FLIGHT_EVENT_U64_FIELDS( XTAJIT64_FLIGHT_STORE_U64 )
    XTAJIT64_FLIGHT_EVENT_U32_FIELDS( XTAJIT64_FLIGHT_STORE_U32 )
#undef XTAJIT64_FLIGHT_STORE_U64
#undef XTAJIT64_FLIGHT_STORE_U32
}

static inline void xtajit64_flight_load_event( struct xtajit64_flight_event *dst,
                                               const struct xtajit64_flight_event *src,
                                               UINT64 publication_sequence )
{
#define XTAJIT64_FLIGHT_LOAD_U64(field) \
    dst->field = __atomic_load_n( &src->field, __ATOMIC_RELAXED );
#define XTAJIT64_FLIGHT_LOAD_U32(field) \
    dst->field = __atomic_load_n( &src->field, __ATOMIC_RELAXED );
    dst->publication_sequence = publication_sequence;
    XTAJIT64_FLIGHT_EVENT_U64_FIELDS( XTAJIT64_FLIGHT_LOAD_U64 )
    XTAJIT64_FLIGHT_EVENT_U32_FIELDS( XTAJIT64_FLIGHT_LOAD_U32 )
#undef XTAJIT64_FLIGHT_LOAD_U64
#undef XTAJIT64_FLIGHT_LOAD_U32
}

#undef XTAJIT64_FLIGHT_EVENT_U64_FIELDS
#undef XTAJIT64_FLIGHT_EVENT_U32_FIELDS

static inline BOOL xtajit64_flight_recorder_is_valid(
    const struct xtajit64_flight_recorder *recorder )
{
    return recorder && recorder->magic == XTAJIT64_FLIGHT_MAGIC &&
           recorder->schema_version == XTAJIT64_FLIGHT_SCHEMA_VERSION &&
           recorder->capacity == XTAJIT64_FLIGHT_CAPACITY;
}

/* Validate placement before looking at the recorder header.  The PE owner
 * supplies its known transition-allocation bounds; a non-null recorder is
 * accepted only at the 64-byte-aligned high end of that allocation, with the
 * private control stack ending exactly at its first byte.  This keeps a
 * damaged state->flight_recorder from turning an opt-in watchdog into an
 * arbitrary/unmapped dereference.  A NULL recorder is the normal disabled
 * layout and is intentionally accepted. */
static inline BOOL xtajit64_flight_validate_layout( ULONG_PTR allocation_base,
                                                    SIZE_T allocation_size,
                                                    ULONG_PTR control_stack_top,
                                                    const struct xtajit64_flight_recorder *recorder )
{
    ULONG_PTR allocation_end, recorder_address, expected, size;

    if (!recorder) return TRUE;
    if (!allocation_size) return FALSE;
    size = (ULONG_PTR)allocation_size;
    if ((SIZE_T)size != allocation_size || allocation_base > ~(ULONG_PTR)0 - size)
        return FALSE;
    allocation_end = allocation_base + size;
    if (size < sizeof(*recorder)) return FALSE;
    recorder_address = (ULONG_PTR)recorder;
    if ((allocation_end & 63) || (recorder_address & 63) ||
        control_stack_top != recorder_address ||
        recorder_address < allocation_base ||
        recorder_address > allocation_end - sizeof(*recorder))
        return FALSE;
    expected = allocation_end - sizeof(*recorder);
    if (recorder_address != expected) return FALSE;
    return xtajit64_flight_recorder_is_valid( recorder );
}

/* Producer paths must stop before acquiring construction storage once a
 * watchdog has frozen the recorder.  Snapshot/dump code deliberately uses
 * xtajit64_flight_acquire_scratch() directly so it can render frozen data. */
static inline BOOL xtajit64_flight_recorder_is_active(
    const struct xtajit64_flight_recorder *recorder )
{
    return xtajit64_flight_recorder_is_valid( recorder ) &&
           !__atomic_load_n( &recorder->freeze_state, __ATOMIC_ACQUIRE );
}

static inline void xtajit64_flight_recorder_init( struct xtajit64_flight_recorder *recorder )
{
    UINT32 index;

    memset( recorder, 0, sizeof(*recorder) );
    recorder->magic = XTAJIT64_FLIGHT_MAGIC;
    recorder->schema_version = XTAJIT64_FLIGHT_SCHEMA_VERSION;
    recorder->capacity = XTAJIT64_FLIGHT_CAPACITY;
    __atomic_store_n( &recorder->next_sequence, 1, __ATOMIC_RELAXED );
    __atomic_store_n( &recorder->next_causal_boundary_id, 1, __ATOMIC_RELAXED );
    __atomic_store_n( &recorder->published_boundary_id, 0, __ATOMIC_RELAXED );
    __atomic_store_n( &recorder->authenticated_teb, XTAJIT64_FLIGHT_UNKNOWN_U64,
                      __ATOMIC_RELAXED );
    /* Sequence 1 maps to slot 1; slot 0 first belongs to sequence 64. */
    for (index = 0; index < XTAJIT64_FLIGHT_CAPACITY; ++index)
        __atomic_store_n( &recorder->slot_owners[index],
                          index ? index : XTAJIT64_FLIGHT_CAPACITY,
                          __ATOMIC_RELAXED );
}

static inline BOOL xtajit64_flight_freeze( struct xtajit64_flight_recorder *recorder,
                                           UINT32 reason );

/* Publish a monotonically increasing transition boundary.  A signal-driven
 * nested transition may publish a newer ID before an interrupted outer
 * producer resumes, so the compare/exchange is a max operation rather than a
 * plain store.  Returning the retained value lets the PE state converge on
 * that non-regressing publication. */
static inline UINT64 xtajit64_flight_publish_boundary(
    struct xtajit64_flight_recorder *recorder, UINT64 boundary_id )
{
    UINT64 current, expected;

    if (!xtajit64_flight_recorder_is_active( recorder ))
        return XTAJIT64_FLIGHT_UNKNOWN_U64;
    if (!boundary_id || boundary_id == XTAJIT64_FLIGHT_UNKNOWN_U64)
    {
        xtajit64_flight_freeze( recorder,
                               XTAJIT64_FLIGHT_REASON_CONTEXT_STALE_PUBLICATION );
        return XTAJIT64_FLIGHT_UNKNOWN_U64;
    }
    for (;;)
    {
        current = __atomic_load_n( &recorder->published_boundary_id,
                                   __ATOMIC_ACQUIRE );
        if (current == XTAJIT64_FLIGHT_UNKNOWN_U64)
        {
            xtajit64_flight_freeze( recorder,
                                   XTAJIT64_FLIGHT_REASON_CONTEXT_STALE_PUBLICATION );
            return XTAJIT64_FLIGHT_UNKNOWN_U64;
        }
        if (current >= boundary_id) return current;
        expected = current;
        if (__atomic_compare_exchange_n( &recorder->published_boundary_id,
                                         &expected, boundary_id, FALSE,
                                         __ATOMIC_RELEASE, __ATOMIC_ACQUIRE ))
            return boundary_id;
    }
}

static inline UINT64 xtajit64_flight_current_boundary(
    const struct xtajit64_flight_recorder *recorder )
{
    if (!xtajit64_flight_recorder_is_valid( recorder ))
        return XTAJIT64_FLIGHT_UNKNOWN_U64;
    return __atomic_load_n( &recorder->published_boundary_id, __ATOMIC_ACQUIRE );
}

static inline UINT64 xtajit64_flight_next_causal_boundary_id(
    struct xtajit64_flight_recorder *recorder )
{
    UINT64 id, expected;

    if (!xtajit64_flight_recorder_is_valid( recorder )) return XTAJIT64_FLIGHT_UNKNOWN_U64;
    for (;;)
    {
        if (__atomic_load_n( &recorder->freeze_state, __ATOMIC_ACQUIRE ))
            return XTAJIT64_FLIGHT_UNKNOWN_U64;
        id = __atomic_load_n( &recorder->next_causal_boundary_id, __ATOMIC_ACQUIRE );
        /* Both zero and UINT64_MAX are reserved sentinels.  Do not let an
         * atomic fetch-add wrap through either one and silently reuse causal
         * ID 1: diagnostic causal identity must fail closed like ring tickets. */
        if (!id || id == XTAJIT64_FLIGHT_UNKNOWN_U64)
        {
            xtajit64_flight_freeze( recorder, XTAJIT64_FLIGHT_REASON_RECORDER_WRAP );
            return XTAJIT64_FLIGHT_UNKNOWN_U64;
        }
        expected = id;
        if (__atomic_compare_exchange_n( &recorder->next_causal_boundary_id, &expected,
                                         id + 1, FALSE, __ATOMIC_ACQ_REL,
                                         __ATOMIC_ACQUIRE ))
            return id;
    }
}

static inline void xtajit64_flight_event_init( struct xtajit64_flight_event *event,
                                                UINT32 type, UINT32 source )
{
    memset( event, 0xff, sizeof(*event) );
    event->event_type = type;
    event->reason = XTAJIT64_FLIGHT_REASON_NONE;
    event->stop_reason = XTAJIT64_FLIGHT_UNKNOWN_U32;
    event->custom_x18_mode = XTAJIT64_FLIGHT_X18_MODE_UNKNOWN;
    event->x18_expectation = XTAJIT64_FLIGHT_X18_EXPECTATION_UNKNOWN;
    event->context_flags = XTAJIT64_FLIGHT_UNKNOWN_U32;
    event->mxcsr = XTAJIT64_FLIGHT_UNKNOWN_U32;
    event->fltsave_mxcsr = XTAJIT64_FLIGHT_UNKNOWN_U32;
    event->ownership_flags = XTAJIT64_FLIGHT_UNKNOWN_U32;
    event->flags = XTAJIT64_FLIGHT_FLAG_RAW_DIAGNOSTIC |
                   XTAJIT64_FLIGHT_FLAG_TIME_UNAVAILABLE |
                   XTAJIT64_FLIGHT_FLAG_CONTEXT_VERSION_UNKNOWN |
                   XTAJIT64_FLIGHT_FLAG_CONTEXT_FLAGS_UNKNOWN |
                   XTAJIT64_FLIGHT_FLAG_SAVED_X18_UNKNOWN |
                   XTAJIT64_FLIGHT_FLAG_EXECUTION_MODE_UNKNOWN;
    event->source = source;
}

static inline struct xtajit64_flight_event *xtajit64_flight_acquire_scratch(
    struct xtajit64_flight_recorder *recorder, struct xtajit64_flight_scratch **scratch )
{
    UINT32 index;

    if (scratch) *scratch = NULL;
    if (!xtajit64_flight_recorder_is_valid( recorder ) || !scratch) return NULL;
    for (index = 0; index < XTAJIT64_FLIGHT_SCRATCH_SLOTS; ++index)
    {
        UINT32 expected = 0;

        if (__atomic_compare_exchange_n( &recorder->scratch[index].in_use, &expected, 1,
                                         FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED ))
        {
            *scratch = &recorder->scratch[index];
            return &(*scratch)->event;
        }
    }
    __atomic_fetch_add( &recorder->scratch_loss_count, 1, __ATOMIC_RELAXED );
    return NULL;
}

static inline void xtajit64_flight_release_scratch(
    struct xtajit64_flight_scratch *scratch )
{
    if (scratch) __atomic_store_n( &scratch->in_use, 0, __ATOMIC_RELEASE );
}

static inline BOOL xtajit64_flight_begin_freeze( struct xtajit64_flight_recorder *recorder )
{
    UINT32 expected = 0;
    UINT64 next;

    if (!xtajit64_flight_recorder_is_valid( recorder )) return FALSE;
    if (!__atomic_compare_exchange_n( &recorder->freeze_state, &expected, 2, FALSE,
                                      __ATOMIC_ACQ_REL, __ATOMIC_RELAXED ))
        return FALSE;
    /* The state change first prevents new claims.  Sample the cut-off after
     * it, retaining all normally committed pre-freeze history.  A writer that
     * sampled ACTIVE before our CAS can still reserve a later ticket; keeping
     * a ticket that appears after this sample outside the frozen window is
     * deliberate.  It prevents a post-freeze missing/publication race from
     * being rendered as causal history. */
    next = __atomic_load_n( &recorder->next_sequence, __ATOMIC_ACQUIRE );
    __atomic_store_n( &recorder->frozen_sequence, next ? next - 1 : 0,
                      __ATOMIC_RELAXED );
    return TRUE;
}

static inline void xtajit64_flight_finish_freeze( struct xtajit64_flight_recorder *recorder,
                                                   UINT32 reason )
{
    __atomic_store_n( &recorder->freeze_reason, reason, __ATOMIC_RELAXED );
    __atomic_store_n( &recorder->freeze_state, 1, __ATOMIC_RELEASE );
}

/* Returns nonzero only for the thread which first freezes the recorder. */
static inline BOOL xtajit64_flight_freeze( struct xtajit64_flight_recorder *recorder,
                                           UINT32 reason )
{
    if (!xtajit64_flight_begin_freeze( recorder )) return FALSE;
    xtajit64_flight_finish_freeze( recorder, reason );
    return TRUE;
}

/* Claims a slot only for its precise generation.  A producer which stalls
 * after reservation holds the slot's busy generation, so a writer one full
 * ring later cannot overwrite it or publish an ABA-stale payload.  Under
 * pathological contention, this drops a diagnostic event after a bounded
 * spin instead of locking or waiting indefinitely in a transition path. */
static inline BOOL xtajit64_flight_claim_slot( struct xtajit64_flight_recorder *recorder,
                                               UINT64 *sequence,
                                               struct xtajit64_flight_event **slot )
{
    UINT64 candidate, owner, expected;
    UINT32 spins = 0;

    for (;;)
    {
        if (__atomic_load_n( &recorder->freeze_state, __ATOMIC_RELAXED )) return FALSE;
        candidate = __atomic_load_n( &recorder->next_sequence, __ATOMIC_ACQUIRE );
        if (!candidate || candidate >= XTAJIT64_FLIGHT_OWNER_BUSY -
                                      XTAJIT64_FLIGHT_CAPACITY)
        {
            xtajit64_flight_freeze( recorder, XTAJIT64_FLIGHT_REASON_RECORDER_WRAP );
            return FALSE;
        }
        *slot = &recorder->events[candidate & (XTAJIT64_FLIGHT_CAPACITY - 1)];
        owner = __atomic_load_n(
            &recorder->slot_owners[candidate & (XTAJIT64_FLIGHT_CAPACITY - 1)],
            __ATOMIC_ACQUIRE );
        if (owner != candidate)
        {
            if (++spins == XTAJIT64_FLIGHT_SPIN_LIMIT)
            {
                __atomic_fetch_add( &recorder->contention_loss_count, 1,
                                    __ATOMIC_RELAXED );
                return FALSE;
            }
            continue;
        }
        expected = candidate;
        if (!__atomic_compare_exchange_n( &recorder->next_sequence, &expected,
                                          candidate + 1, FALSE, __ATOMIC_ACQ_REL,
                                          __ATOMIC_ACQUIRE ))
            continue;

        expected = candidate;
        if (!__atomic_compare_exchange_n(
                &recorder->slot_owners[candidate & (XTAJIT64_FLIGHT_CAPACITY - 1)],
                &expected, candidate | XTAJIT64_FLIGHT_OWNER_BUSY, FALSE,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE ))
        {
            /* This can only indicate memory corruption: the global ticket is
             * already ours, and no other writer can own this generation.  It
             * already occupies a sequence, so the snapshot's missing-slot
             * accounting (not contention_loss_count) reports the loss. */
            xtajit64_flight_freeze( recorder, XTAJIT64_FLIGHT_REASON_RECORDER_INVALID );
            return FALSE;
        }
        *sequence = candidate;
        return TRUE;
    }
}

static inline void xtajit64_flight_release_slot( struct xtajit64_flight_recorder *recorder,
                                                 struct xtajit64_flight_event *slot,
                                                 UINT64 sequence )
{
    __atomic_store_n( &slot->publication_sequence, 0, __ATOMIC_RELEASE );
    __atomic_store_n( &recorder->slot_owners[
                          sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)],
                      sequence + XTAJIT64_FLIGHT_CAPACITY, __ATOMIC_RELEASE );
}

/* The disabled fast path is one null/validity branch in each producer.  It
 * never allocates, locks, logs, queries the OS, or writes shared state. */
static inline UINT64 xtajit64_flight_record( struct xtajit64_flight_recorder *recorder,
                                             const struct xtajit64_flight_event *event )
{
    struct xtajit64_flight_event *slot;
    UINT64 sequence;

    if (!event || !xtajit64_flight_recorder_is_valid( recorder ) ||
        __atomic_load_n( &recorder->freeze_state, __ATOMIC_RELAXED ))
        return 0;
    if (!xtajit64_flight_claim_slot( recorder, &sequence, &slot )) return 0;
    if (__atomic_load_n( &recorder->freeze_state, __ATOMIC_RELAXED ))
    {
        xtajit64_flight_release_slot( recorder, slot, sequence );
        return 0;
    }
    __atomic_store_n( &slot->publication_sequence, 0, __ATOMIC_RELEASE );
    xtajit64_flight_store_event( slot, event );
    __atomic_store_n( &slot->sequence, sequence, __ATOMIC_RELAXED );
    __atomic_store_n( &slot->publication_sequence, sequence, __ATOMIC_RELEASE );
    __atomic_store_n( &recorder->slot_owners[
                          sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)],
                      sequence + XTAJIT64_FLIGHT_CAPACITY, __ATOMIC_RELEASE );
    return sequence;
}

static inline void xtajit64_flight_publish_first_violation(
    struct xtajit64_flight_recorder *recorder, const struct xtajit64_flight_event *event,
    UINT32 reason )
{
    UINT64 sequence;

    __atomic_store_n( &recorder->first_violation_publication, 0, __ATOMIC_RELEASE );
    xtajit64_flight_store_event( &recorder->first_violation, event );
    /* The dedicated payload is outside the ring.  Give it the boundary
     * immediately after the frozen window instead of event_init()'s UNKNOWN
     * value.  This deliberately does not incorporate a stale writer's ticket
     * that raced the freeze gate after we sampled the cut-off. */
    sequence = __atomic_load_n( &recorder->frozen_sequence, __ATOMIC_RELAXED ) + 1;
    __atomic_store_n( &recorder->first_violation.sequence, sequence,
                      __ATOMIC_RELAXED );
    __atomic_store_n( &recorder->first_violation.reason, reason, __ATOMIC_RELAXED );
    __atomic_store_n( &recorder->first_violation.publication_sequence, 1,
                      __ATOMIC_RELAXED );
    __atomic_store_n( &recorder->first_violation_publication, 1, __ATOMIC_RELEASE );
}

/* Selects the first violation before producing any ordinary watchdog event.
 * The winner stores a complete event in dedicated recorder storage, then
 * release-publishes the frozen state.  Later violations cannot replace its
 * reason or payload, and no exception/logging path is involved. */
static inline BOOL xtajit64_flight_record_and_freeze(
    struct xtajit64_flight_recorder *recorder, const struct xtajit64_flight_event *event,
    UINT32 reason )
{
    if (!event) return FALSE;
    if (!xtajit64_flight_begin_freeze( recorder )) return FALSE;
    xtajit64_flight_publish_first_violation( recorder, event, reason );
    xtajit64_flight_finish_freeze( recorder, reason );
    return TRUE;
}

/* Transition-stack rejection needs more evidence than the general event can
 * hold.  The freeze winner copies one complete bounded side payload before the
 * final release store, so readers never observe a partial frame snapshot. */
static inline BOOL xtajit64_flight_record_transition_stack_violation_and_freeze(
    struct xtajit64_flight_recorder *recorder, const struct xtajit64_flight_event *event,
    const struct xtajit64_flight_transition_stack_violation *violation )
{
    if (!event || !violation ||
        violation->frame_count > XTAJIT64_FLIGHT_MAX_TRANSITION_FRAMES)
        return FALSE;
    if (!xtajit64_flight_begin_freeze( recorder )) return FALSE;
    __atomic_store_n( &recorder->transition_stack_violation_publication, 0,
                      __ATOMIC_RELEASE );
    memcpy( &recorder->transition_stack_violation, violation, sizeof(*violation) );
    __atomic_store_n( &recorder->transition_stack_violation_publication, 1,
                      __ATOMIC_RELEASE );
    xtajit64_flight_publish_first_violation(
        recorder, event, XTAJIT64_FLIGHT_REASON_TRANSITION_STACK );
    xtajit64_flight_finish_freeze( recorder,
                                   XTAJIT64_FLIGHT_REASON_TRANSITION_STACK );
    return TRUE;
}

/* Snapshotting is intentionally for non-sensitive code only.  It takes no
 * locks and reports every missing/torn slot instead of manufacturing order.
 * The metadata/one-slot form lets renderers avoid placing a full ring copy on
 * a potentially suspect stack. */
static inline BOOL xtajit64_flight_snapshot_metadata(
    const struct xtajit64_flight_recorder *recorder,
    struct xtajit64_flight_snapshot_metadata *metadata )
{
    UINT64 next, last;
    UINT32 freeze_state;

    memset( metadata, 0, sizeof(*metadata) );
    if (!xtajit64_flight_recorder_is_valid( recorder )) return FALSE;
    /* frozen_sequence/reason are relaxed stores sequenced before this release
     * store.  Acquire the state first; acquiring either field directly would
     * not synchronize with the freezer. */
    freeze_state = __atomic_load_n( &recorder->freeze_state, __ATOMIC_ACQUIRE );
    metadata->freeze_state = freeze_state;
    if (freeze_state == 1)
    {
        metadata->frozen_sequence = __atomic_load_n( &recorder->frozen_sequence,
                                                      __ATOMIC_RELAXED );
        /* Never extend a completed frozen snapshot with a ticket from a
         * producer that raced the freeze gate. */
        last = metadata->frozen_sequence;
        metadata->freeze_reason = __atomic_load_n( &recorder->freeze_reason,
                                                    __ATOMIC_RELAXED );
        metadata->first_violation_available =
            __atomic_load_n( &recorder->first_violation_publication,
                             __ATOMIC_ACQUIRE ) == 1;
    }
    else
    {
        next = __atomic_load_n( &recorder->next_sequence, __ATOMIC_ACQUIRE );
        last = next ? next - 1 : 0;
    }
    metadata->first_sequence = last > XTAJIT64_FLIGHT_CAPACITY ?
                               last - XTAJIT64_FLIGHT_CAPACITY + 1 : 1;
    metadata->last_sequence = last;
    metadata->contention_loss_count = __atomic_load_n( &recorder->contention_loss_count,
                                                        __ATOMIC_RELAXED );
    metadata->scratch_loss_count = __atomic_load_n( &recorder->scratch_loss_count,
                                                     __ATOMIC_RELAXED );
    if (last >= XTAJIT64_FLIGHT_CAPACITY)
        metadata->historical_loss_count = last - XTAJIT64_FLIGHT_CAPACITY;
    return TRUE;
}

static inline BOOL xtajit64_flight_snapshot_first_violation(
    const struct xtajit64_flight_recorder *recorder, struct xtajit64_flight_event *event )
{
    UINT64 before, after;

    if (!recorder || !event) return FALSE;
    before = __atomic_load_n( &recorder->first_violation_publication, __ATOMIC_ACQUIRE );
    if (before != 1) return FALSE;
    xtajit64_flight_load_event( event, &recorder->first_violation, before );
    after = __atomic_load_n( &recorder->first_violation_publication, __ATOMIC_ACQUIRE );
    return before == after;
}

static inline BOOL xtajit64_flight_snapshot_transition_stack_violation(
    const struct xtajit64_flight_recorder *recorder,
    struct xtajit64_flight_transition_stack_violation *violation )
{
    UINT64 before, after;

    if (!recorder || !violation) return FALSE;
    before = __atomic_load_n( &recorder->transition_stack_violation_publication,
                              __ATOMIC_ACQUIRE );
    if (before != 1) return FALSE;
    memcpy( violation, &recorder->transition_stack_violation, sizeof(*violation) );
    after = __atomic_load_n( &recorder->transition_stack_violation_publication,
                             __ATOMIC_ACQUIRE );
    return before == after &&
           violation->frame_count <= XTAJIT64_FLIGHT_MAX_TRANSITION_FRAMES;
}

static inline UINT32 xtajit64_flight_snapshot_event(
    const struct xtajit64_flight_recorder *recorder, UINT64 sequence,
    struct xtajit64_flight_event *event )
{
    const struct xtajit64_flight_event *slot;
    UINT64 before, after, owner_before, owner_after;

    if (!recorder || !event || !sequence) return XTAJIT64_FLIGHT_SNAPSHOT_UNCOMMITTED;
    slot = &recorder->events[sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)];
    owner_before = __atomic_load_n(
        &recorder->slot_owners[sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)], __ATOMIC_ACQUIRE );
    if (owner_before != sequence + XTAJIT64_FLIGHT_CAPACITY)
    {
        UINT64 generation = owner_before & ~XTAJIT64_FLIGHT_OWNER_BUSY;

        if (generation == sequence) return XTAJIT64_FLIGHT_SNAPSHOT_UNCOMMITTED;
        return generation > sequence ? XTAJIT64_FLIGHT_SNAPSHOT_OVERWRITTEN :
                                       XTAJIT64_FLIGHT_SNAPSHOT_TORN;
    }
    before = __atomic_load_n( &slot->publication_sequence, __ATOMIC_ACQUIRE );
    if (before != sequence)
        return before ? XTAJIT64_FLIGHT_SNAPSHOT_OVERWRITTEN :
                        XTAJIT64_FLIGHT_SNAPSHOT_UNCOMMITTED;
    xtajit64_flight_load_event( event, slot, before );
    after = __atomic_load_n( &slot->publication_sequence, __ATOMIC_ACQUIRE );
    owner_after = __atomic_load_n(
        &recorder->slot_owners[sequence & (XTAJIT64_FLIGHT_CAPACITY - 1)], __ATOMIC_ACQUIRE );
    if (after != sequence || before != after || event->sequence != sequence ||
        owner_after != sequence + XTAJIT64_FLIGHT_CAPACITY)
        return XTAJIT64_FLIGHT_SNAPSHOT_TORN;
    return XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED;
}

static inline UINT64 xtajit64_flight_saturating_add( UINT64 left, UINT64 right )
{
    return left > ~(UINT64)0 - right ? ~(UINT64)0 : left + right;
}

static inline void xtajit64_flight_snapshot( const struct xtajit64_flight_recorder *recorder,
                                             struct xtajit64_flight_snapshot *snapshot )
{
    struct xtajit64_flight_snapshot_metadata metadata;
    UINT64 sequence;
    UINT32 index = 0;

    memset( snapshot, 0, sizeof(*snapshot) );
    if (!xtajit64_flight_snapshot_metadata( recorder, &metadata )) return;
    snapshot->first_sequence = metadata.first_sequence;
    snapshot->last_sequence = metadata.last_sequence;
    snapshot->frozen_sequence = metadata.frozen_sequence;
    snapshot->freeze_reason = metadata.freeze_reason;
    snapshot->contention_loss_count = metadata.contention_loss_count;
    snapshot->scratch_loss_count = metadata.scratch_loss_count;
    snapshot->lost_count = xtajit64_flight_saturating_add(
        xtajit64_flight_saturating_add( metadata.historical_loss_count,
                                        metadata.contention_loss_count ),
        metadata.scratch_loss_count );

    for (sequence = metadata.first_sequence;
         sequence && sequence <= metadata.last_sequence &&
         index < XTAJIT64_FLIGHT_CAPACITY; ++sequence, ++index)
    {
        snapshot->states[index] = xtajit64_flight_snapshot_event(
            recorder, sequence, &snapshot->events[index] );
        if (snapshot->states[index] == XTAJIT64_FLIGHT_SNAPSHOT_COMMITTED) ++snapshot->count;
        else if (snapshot->states[index] == XTAJIT64_FLIGHT_SNAPSHOT_TORN)
            ++snapshot->torn_count;
        else snapshot->lost_count = xtajit64_flight_saturating_add(
            snapshot->lost_count, 1 );
    }
}

/* Classify the first invalid transition-stack observation without dereferencing
 * any captured pointer.  The caller supplies explicit probe results so native
 * tests can cover every predicate without a live ARM64EC transition. */
static inline UINT32 xtajit64_flight_classify_transition_stack(
    UINT64 rip, UINT64 rsp, UINT64 gs_base, UINT64 user_address_max,
    UINT64 expected_teb, UINT64 fresh_teb, UINT64 expected_cpu, UINT64 fresh_cpu,
    BOOL probe_ran, UINT32 translation_status, UINT64 translated_guest,
    UINT32 stack_match_mask, UINT32 depth )
{
    UINT32 reject = 0;

    if (!rip || rip > user_address_max) reject |= XTAJIT64_FLIGHT_STACK_REJECT_RIP_RANGE;
    if (!rsp || rsp > user_address_max) reject |= XTAJIT64_FLIGHT_STACK_REJECT_RSP_RANGE;
    if (!gs_base || gs_base > user_address_max) reject |= XTAJIT64_FLIGHT_STACK_REJECT_GS_RANGE;
    if (expected_teb && expected_teb != XTAJIT64_FLIGHT_UNKNOWN_U64 &&
        fresh_teb != XTAJIT64_FLIGHT_UNKNOWN_U64 &&
        fresh_teb != expected_teb)
        reject |= XTAJIT64_FLIGHT_STACK_REJECT_TEB_IDENTITY;
    if (!fresh_cpu || fresh_cpu == XTAJIT64_FLIGHT_UNKNOWN_U64)
        reject |= XTAJIT64_FLIGHT_STACK_REJECT_CPU_MISSING;
    else if (expected_cpu && expected_cpu != XTAJIT64_FLIGHT_UNKNOWN_U64 &&
             fresh_cpu != expected_cpu)
        reject |= XTAJIT64_FLIGHT_STACK_REJECT_CPU_IDENTITY;
    if (!probe_ran)
        reject |= XTAJIT64_FLIGHT_STACK_REJECT_PROBE_NOT_RUN;
    else if (translation_status)
        reject |= XTAJIT64_FLIGHT_STACK_REJECT_TRANSLATE_STATUS;
    else
    {
        if (translated_guest != rsp)
            reject |= XTAJIT64_FLIGHT_STACK_REJECT_TRANSLATED_GUEST;
        if (!(stack_match_mask & (XTAJIT64_FLIGHT_STACK_MATCH_EMULATOR |
                                  XTAJIT64_FLIGHT_STACK_MATCH_TEB)))
            reject |= XTAJIT64_FLIGHT_STACK_REJECT_STACK_RANGE;
    }
    if (depth > XTAJIT64_FLIGHT_MAX_TRANSITION_FRAMES)
        reject |= XTAJIT64_FLIGHT_STACK_REJECT_FRAME_DEPTH;
    return reject;
}

static inline UINT32 xtajit64_flight_validate_context(
    UINT32 flags, UINT32 required_flags, UINT32 mxcsr, UINT32 fltsave_mxcsr,
    UINT64 rip, UINT64 rsp, UINT64 user_address_max, UINT64 stack_limit,
    UINT64 stack_base, UINT64 continuation_target, UINT64 continuation_pc,
    UINT64 continuation_rsp )
{
    if (flags != XTAJIT64_FLIGHT_UNKNOWN_U32 &&
        (flags & required_flags) != required_flags)
        return XTAJIT64_FLIGHT_REASON_CONTEXT_FLAGS;
    if (mxcsr != XTAJIT64_FLIGHT_UNKNOWN_U32 &&
        fltsave_mxcsr != XTAJIT64_FLIGHT_UNKNOWN_U32 && mxcsr != fltsave_mxcsr)
        return XTAJIT64_FLIGHT_REASON_CONTEXT_MXCSR;
    if (!rip || rip > user_address_max) return XTAJIT64_FLIGHT_REASON_CONTEXT_RIP;
    if (!rsp || rsp > user_address_max) return XTAJIT64_FLIGHT_REASON_CONTEXT_RSP;
    if (stack_limit != XTAJIT64_FLIGHT_UNKNOWN_U64 &&
        stack_base != XTAJIT64_FLIGHT_UNKNOWN_U64 &&
        (stack_limit >= stack_base || rsp < stack_limit || rsp >= stack_base))
        return XTAJIT64_FLIGHT_REASON_CONTEXT_STACK;
    if (continuation_target != XTAJIT64_FLIGHT_UNKNOWN_U64 &&
        continuation_pc != XTAJIT64_FLIGHT_UNKNOWN_U64 &&
        continuation_target == continuation_pc && rsp != continuation_rsp)
        return XTAJIT64_FLIGHT_REASON_CONTINUATION_PAIR;
    return XTAJIT64_FLIGHT_REASON_NONE;
}

/* Only invoke this for an event whose C code is contractually executing on
 * the provider-owned transition stack.  Unixlib events run on the Darwin
 * system side and deliberately do not opt in. */
static inline UINT32 xtajit64_flight_validate_private_control_stack(
    UINT64 native_sp, UINT64 control_stack_limit, UINT64 control_stack_top,
    UINT64 guest_stack_limit, UINT64 guest_stack_base )
{
    if (native_sp == XTAJIT64_FLIGHT_UNKNOWN_U64 ||
        control_stack_limit == XTAJIT64_FLIGHT_UNKNOWN_U64 ||
        control_stack_top == XTAJIT64_FLIGHT_UNKNOWN_U64)
        return XTAJIT64_FLIGHT_REASON_NONE;
    if (control_stack_limit >= control_stack_top || native_sp < control_stack_limit ||
        native_sp >= control_stack_top)
        return XTAJIT64_FLIGHT_REASON_TRANSITION_STACK;
    if (guest_stack_limit != XTAJIT64_FLIGHT_UNKNOWN_U64 &&
        guest_stack_base != XTAJIT64_FLIGHT_UNKNOWN_U64 &&
        (guest_stack_limit >= guest_stack_base ||
         !(control_stack_top <= guest_stack_limit ||
           control_stack_limit >= guest_stack_base)))
        return XTAJIT64_FLIGHT_REASON_TRANSITION_STACK;
    return XTAJIT64_FLIGHT_REASON_NONE;
}

static inline UINT32 xtajit64_flight_validate_x18(
    UINT32 mode, UINT32 expectation, UINT64 x18_value, UINT64 expected_teb )
{
    if (expectation == XTAJIT64_FLIGHT_X18_EXPECTATION_NATIVE_SYSTEM)
        return mode == XTAJIT64_FLIGHT_X18_MODE_ENABLED ?
               XTAJIT64_FLIGHT_REASON_X18_MODE : XTAJIT64_FLIGHT_REASON_NONE;
    if (expectation != XTAJIT64_FLIGHT_X18_EXPECTATION_PE_ARM64EC)
        return XTAJIT64_FLIGHT_REASON_NONE;
    if (mode == XTAJIT64_FLIGHT_X18_MODE_DISABLED)
        return XTAJIT64_FLIGHT_REASON_X18_MODE;
    if (x18_value == XTAJIT64_FLIGHT_UNKNOWN_U64 ||
        expected_teb == XTAJIT64_FLIGHT_UNKNOWN_U64)
        return XTAJIT64_FLIGHT_REASON_NONE;
    if (!x18_value || !expected_teb) return XTAJIT64_FLIGHT_REASON_X18_VALUE;
    if (x18_value != expected_teb) return XTAJIT64_FLIGHT_REASON_X18_VALUE;
    return XTAJIT64_FLIGHT_REASON_NONE;
}

/* Bind claims are different from an unavailable CPU observation: the caller
 * supplied a concrete ABI hand-off value, so NULL/sentinel claims (and an
 * unavailable Unix-TLS authority) are diagnostic violations rather than a
 * silent UNKNOWN result. */
static inline UINT32 xtajit64_flight_validate_pe_x18_claim( UINT64 claimed_teb,
                                                            UINT64 authenticated_teb )
{
    if (!claimed_teb || !authenticated_teb ||
        claimed_teb == XTAJIT64_FLIGHT_UNKNOWN_U64 ||
        authenticated_teb == XTAJIT64_FLIGHT_UNKNOWN_U64 ||
        claimed_teb != authenticated_teb)
        return XTAJIT64_FLIGHT_REASON_X18_VALUE;
    return XTAJIT64_FLIGHT_REASON_NONE;
}

#endif /* __WINE_XTAJIT64_FLIGHT_RECORDER_H */
