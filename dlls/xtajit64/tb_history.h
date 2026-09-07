/*
 * x86-64 translated-block execution history
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_XTAJIT64_TB_HISTORY_H
#define __WINE_XTAJIT64_TB_HISTORY_H

#include <stdatomic.h>
#include <stdint.h>

#define XTAJIT64_TB_HISTORY_CAPACITY       256u
#define XTAJIT64_TB_HISTORY_SUMMARY_WINDOW 128u
#define XTAJIT64_TB_HISTORY_TAIL           8u
#define XTAJIT64_TB_HISTORY_SAMPLE_STRIDE   16381u
#define XTAJIT64_TB_HISTORY_REPEAT_SAMPLES 64u
#define XTAJIT64_TB_HISTORY_REPEAT_UNIQUE  16u

/* Sample execution entries, not every translated block.  A UC_HOOK_BLOCK
 * callback would turn a diagnostic into a C round-trip for every dispatch;
 * sampling before selected uc_emu_start() calls leaves generated execution
 * uninstrumented.  A prime stride reduces alignment with short periodic
 * caller sequences.  The counter is engine-thread-owned and deliberately
 * survives binding reuse, so short BeginSimulation calls cannot turn the
 * diagnostic into a per-binding recorder. */
static inline int xtajit64_tb_history_should_sample( uint32_t *block_counter )
{
    uint32_t next;

    if (!block_counter) return 0;
    next = *block_counter + 1;
    if (next < XTAJIT64_TB_HISTORY_SAMPLE_STRIDE)
    {
        *block_counter = next;
        return 0;
    }
    *block_counter = 0;
    return 1;
}

/* One engine thread is the sole producer for a sampled history.  A diagnostic
 * watchdog may snapshot it concurrently.  Every payload field is atomic so a
 * wrapping producer never races with the reader at the C object-model level;
 * publication_sequence is the release-published seqlock generation. */
struct xtajit64_tb_history_event
{
    atomic_uint_least64_t publication_sequence;
    atomic_uint_least64_t sequence;
    atomic_uint_least64_t guest_pc;
    atomic_uint_least64_t binding_id;
    atomic_uint_least64_t execution_generation;
    atomic_uint_least64_t mapping_generation;
    atomic_uint_least64_t causal_boundary_id;
    /* Zero is a sampled uc_emu_start() entry, so no translated-block length
     * was observed.  A nonzero value remains available to focused tests or a
     * future explicitly intrusive block recorder. */
    atomic_uint_least32_t block_size;
};

struct xtajit64_tb_history
{
    atomic_uint_least64_t writer_sequence;
    uint64_t watchdog_last_sequence;
    struct xtajit64_tb_history_event events[XTAJIT64_TB_HISTORY_CAPACITY];
};

struct xtajit64_tb_history_snapshot
{
    uint64_t sequence;
    uint64_t guest_pc;
    uint64_t binding_id;
    uint64_t execution_generation;
    uint64_t mapping_generation;
    uint64_t causal_boundary_id;
    uint32_t block_size;
};

struct xtajit64_tb_history_summary
{
    uint64_t first_sequence;
    uint64_t last_sequence;
    uint64_t overwritten;
    uint64_t first_pc;
    uint64_t last_pc;
    uint64_t minimum_mapping_generation;
    uint64_t maximum_mapping_generation;
    uint64_t binding_id;
    uint64_t execution_generation;
    uint64_t causal_boundary_id;
    uint32_t requested;
    uint32_t valid;
    uint32_t missing_or_torn;
    uint32_t unique_pc_count;
    uint32_t execution_generation_changes;
    uint32_t provenance_changes;
    uint32_t tail_count;
    struct xtajit64_tb_history_snapshot tail[XTAJIT64_TB_HISTORY_TAIL];
};

static inline void xtajit64_tb_history_init( struct xtajit64_tb_history *history )
{
    unsigned int i;

    atomic_init( &history->writer_sequence, 0 );
    history->watchdog_last_sequence = 0;
    for (i = 0; i < XTAJIT64_TB_HISTORY_CAPACITY; ++i)
    {
        struct xtajit64_tb_history_event *event = &history->events[i];

        atomic_init( &event->publication_sequence, 0 );
        atomic_init( &event->sequence, 0 );
        atomic_init( &event->guest_pc, 0 );
        atomic_init( &event->binding_id, 0 );
        atomic_init( &event->execution_generation, 0 );
        atomic_init( &event->mapping_generation, 0 );
        atomic_init( &event->causal_boundary_id, 0 );
        atomic_init( &event->block_size, 0 );
    }
}

static inline uint64_t xtajit64_tb_history_record(
    struct xtajit64_tb_history *history, uint64_t guest_pc, uint32_t block_size,
    uint64_t binding_id, uint64_t execution_generation,
    uint64_t mapping_generation, uint64_t causal_boundary_id )
{
    struct xtajit64_tb_history_event *event;
    uint64_t sequence;

    sequence = atomic_fetch_add_explicit( &history->writer_sequence, 1,
                                          memory_order_relaxed ) + 1;
    /* Sequence zero is reserved for an unpublished slot.  A history has one
     * producer, so a second increment is sufficient after 64-bit wrap. */
    if (!sequence)
        sequence = atomic_fetch_add_explicit( &history->writer_sequence, 1,
                                              memory_order_relaxed ) + 1;
    event = &history->events[(sequence - 1) % XTAJIT64_TB_HISTORY_CAPACITY];
    atomic_store_explicit( &event->publication_sequence, 0, memory_order_release );
    atomic_store_explicit( &event->sequence, sequence, memory_order_relaxed );
    atomic_store_explicit( &event->guest_pc, guest_pc, memory_order_relaxed );
    atomic_store_explicit( &event->binding_id, binding_id, memory_order_relaxed );
    atomic_store_explicit( &event->execution_generation, execution_generation,
                           memory_order_relaxed );
    atomic_store_explicit( &event->mapping_generation, mapping_generation,
                           memory_order_relaxed );
    atomic_store_explicit( &event->causal_boundary_id, causal_boundary_id,
                           memory_order_relaxed );
    atomic_store_explicit( &event->block_size, block_size, memory_order_relaxed );
    atomic_store_explicit( &event->publication_sequence, sequence,
                           memory_order_release );
    return sequence;
}

static inline int xtajit64_tb_history_snapshot(
    const struct xtajit64_tb_history *history, uint64_t sequence,
    struct xtajit64_tb_history_snapshot *snapshot )
{
    const struct xtajit64_tb_history_event *event;
    uint64_t publication;

    if (!sequence || !snapshot) return 0;
    event = &history->events[(sequence - 1) % XTAJIT64_TB_HISTORY_CAPACITY];
    publication = atomic_load_explicit( &event->publication_sequence,
                                        memory_order_acquire );
    if (publication != sequence) return 0;
    snapshot->sequence = atomic_load_explicit( &event->sequence,
                                               memory_order_relaxed );
    snapshot->guest_pc = atomic_load_explicit( &event->guest_pc,
                                               memory_order_relaxed );
    snapshot->binding_id = atomic_load_explicit( &event->binding_id,
                                                 memory_order_relaxed );
    snapshot->execution_generation = atomic_load_explicit(
        &event->execution_generation, memory_order_relaxed );
    snapshot->mapping_generation = atomic_load_explicit(
        &event->mapping_generation, memory_order_relaxed );
    snapshot->causal_boundary_id = atomic_load_explicit(
        &event->causal_boundary_id, memory_order_relaxed );
    snapshot->block_size = atomic_load_explicit( &event->block_size,
                                                 memory_order_relaxed );
    atomic_thread_fence( memory_order_acquire );
    return snapshot->sequence == sequence &&
           atomic_load_explicit( &event->publication_sequence,
                                 memory_order_acquire ) == sequence;
}

static inline void xtajit64_tb_history_summarize(
    const struct xtajit64_tb_history *history,
    struct xtajit64_tb_history_summary *summary )
{
    uint64_t unique_pcs[XTAJIT64_TB_HISTORY_SUMMARY_WINDOW];
    struct xtajit64_tb_history_snapshot snapshot;
    uint64_t previous_binding_id = 0, previous_execution_generation = 0;
    uint64_t previous_causal_boundary_id = 0;
    uint64_t sequence, first, last;
    uint32_t unique_count = 0;
    unsigned int i;

    *summary = (struct xtajit64_tb_history_summary){0};
    last = atomic_load_explicit( &history->writer_sequence, memory_order_acquire );
    if (!last) return;
    first = last > XTAJIT64_TB_HISTORY_SUMMARY_WINDOW ?
            last - XTAJIT64_TB_HISTORY_SUMMARY_WINDOW + 1 : 1;
    summary->first_sequence = first;
    summary->last_sequence = last;
    summary->overwritten = last > XTAJIT64_TB_HISTORY_CAPACITY ?
                           last - XTAJIT64_TB_HISTORY_CAPACITY : 0;
    summary->requested = (uint32_t)(last - first + 1);
    sequence = first;
    for (;;)
    {
        if (!xtajit64_tb_history_snapshot( history, sequence, &snapshot ))
        {
            ++summary->missing_or_torn;
        }
        else
        {
            if (!summary->valid)
            {
                summary->first_pc = snapshot.guest_pc;
                summary->minimum_mapping_generation = snapshot.mapping_generation;
                summary->maximum_mapping_generation = snapshot.mapping_generation;
                summary->binding_id = snapshot.binding_id;
                summary->execution_generation = snapshot.execution_generation;
                summary->causal_boundary_id = snapshot.causal_boundary_id;
            }
            else
            {
                /* BeginSimulation reacquires the same engine for one binding,
                 * so its execution generation is expected to change between
                 * sparse samples.  Report it separately: it rules out a
                 * same-execution conclusion, but not repeated hot PCs across
                 * otherwise stable mapping and binding ownership. */
                if (previous_execution_generation != snapshot.execution_generation)
                    ++summary->execution_generation_changes;
                if (previous_binding_id != snapshot.binding_id ||
                    previous_causal_boundary_id != snapshot.causal_boundary_id)
                    ++summary->provenance_changes;
            }
            summary->last_pc = snapshot.guest_pc;
            if (snapshot.mapping_generation < summary->minimum_mapping_generation)
                summary->minimum_mapping_generation = snapshot.mapping_generation;
            if (snapshot.mapping_generation > summary->maximum_mapping_generation)
                summary->maximum_mapping_generation = snapshot.mapping_generation;
            for (i = 0; i < unique_count; ++i)
                if (unique_pcs[i] == snapshot.guest_pc) break;
            if (i == unique_count && unique_count < XTAJIT64_TB_HISTORY_SUMMARY_WINDOW)
                unique_pcs[unique_count++] = snapshot.guest_pc;
            if (summary->tail_count < XTAJIT64_TB_HISTORY_TAIL)
                summary->tail[summary->tail_count++] = snapshot;
            else
            {
                for (i = 1; i < XTAJIT64_TB_HISTORY_TAIL; ++i)
                    summary->tail[i - 1] = summary->tail[i];
                summary->tail[XTAJIT64_TB_HISTORY_TAIL - 1] = snapshot;
            }
            ++summary->valid;
            previous_binding_id = snapshot.binding_id;
            previous_execution_generation = snapshot.execution_generation;
            previous_causal_boundary_id = snapshot.causal_boundary_id;
        }
        if (sequence == last) break;
        ++sequence;
    }
    summary->unique_pc_count = unique_count;
}

/* A sparse small-PC window establishes only recurrence, never a contiguous
 * execution cycle.  It may span several BeginSimulation executions of one
 * binding; callers must inspect execution_generation_changes before treating
 * it as a same-execution pattern. */
static inline int xtajit64_tb_history_is_repeat_candidate(
    const struct xtajit64_tb_history_summary *summary )
{
    return summary &&
           summary->valid >= XTAJIT64_TB_HISTORY_REPEAT_SAMPLES &&
           summary->unique_pc_count <= XTAJIT64_TB_HISTORY_REPEAT_UNIQUE &&
           !summary->missing_or_torn && !summary->provenance_changes &&
           summary->minimum_mapping_generation ==
               summary->maximum_mapping_generation;
}

#endif /* __WINE_XTAJIT64_TB_HISTORY_H */
