/* Native tests for the translated-block history diagnostic. */

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tb_history.h"

#define CONCURRENT_RECORDS 100000u

static struct xtajit64_tb_history history;
static atomic_bool writer_done;

static void fail( const char *message )
{
    fprintf( stderr, "tb-history: %s\n", message );
    exit( 1 );
}

static void check_snapshot_payload( const struct xtajit64_tb_history_snapshot *snapshot )
{
    uint64_t sequence = snapshot->sequence;

    if (snapshot->guest_pc != UINT64_C(0x100000) + sequence * 16 ||
        snapshot->binding_id != sequence ||
        snapshot->execution_generation != sequence + 1 ||
        snapshot->mapping_generation != sequence + 2 ||
        snapshot->causal_boundary_id != sequence + 3 ||
        snapshot->block_size != (uint32_t)(sequence & 0xff) + 1)
        fail( "accepted a torn payload" );
}

static void *writer_thread( void *arg )
{
    uint64_t sequence;

    (void)arg;
    for (sequence = 1; sequence <= CONCURRENT_RECORDS; ++sequence)
        if (xtajit64_tb_history_record(
                &history, UINT64_C(0x100000) + sequence * 16,
                (uint32_t)(sequence & 0xff) + 1, sequence, sequence + 1,
                sequence + 2, sequence + 3 ) != sequence)
            fail( "writer sequence is not monotonic" );
    atomic_store_explicit( &writer_done, true, memory_order_release );
    return NULL;
}

static void test_concurrent_wrap(void)
{
    struct xtajit64_tb_history_snapshot snapshot;
    struct xtajit64_tb_history_summary summary;
    pthread_t writer;

    xtajit64_tb_history_init( &history );
    atomic_init( &writer_done, false );
    if (pthread_create( &writer, NULL, writer_thread, NULL ))
        fail( "cannot create writer" );
    while (!atomic_load_explicit( &writer_done, memory_order_acquire ))
    {
        uint64_t latest = atomic_load_explicit( &history.writer_sequence,
                                                memory_order_acquire );
        if (latest && xtajit64_tb_history_snapshot( &history, latest, &snapshot ))
            check_snapshot_payload( &snapshot );
    }
    if (pthread_join( writer, NULL )) fail( "cannot join writer" );
    xtajit64_tb_history_summarize( &history, &summary );
    if (summary.last_sequence != CONCURRENT_RECORDS ||
        summary.valid != XTAJIT64_TB_HISTORY_SUMMARY_WINDOW ||
        summary.unique_pc_count != XTAJIT64_TB_HISTORY_SUMMARY_WINDOW ||
        summary.overwritten != CONCURRENT_RECORDS - XTAJIT64_TB_HISTORY_CAPACITY)
        fail( "concurrent wrap summary is incorrect" );
    check_snapshot_payload( &summary.tail[summary.tail_count - 1] );
}

static void test_linear_and_loop_summaries(void)
{
    struct xtajit64_tb_history_summary summary;
    uint64_t sequence;

    xtajit64_tb_history_init( &history );
    xtajit64_tb_history_summarize( &history, &summary );
    if (summary.last_sequence || summary.valid || summary.tail_count)
        fail( "empty history is not empty" );

    for (sequence = 1; sequence <= 10; ++sequence)
        xtajit64_tb_history_record( &history, 0x2000 + sequence * 16, 4,
                                    7, 8, 9, 10 );
    xtajit64_tb_history_summarize( &history, &summary );
    if (summary.first_sequence != 1 || summary.last_sequence != 10 ||
        summary.valid != 10 || summary.unique_pc_count != 10 ||
        summary.tail_count != XTAJIT64_TB_HISTORY_TAIL ||
        summary.first_pc != 0x2010 || summary.last_pc != 0x20a0 ||
        summary.minimum_mapping_generation != 9 ||
        summary.maximum_mapping_generation != 9 ||
        summary.execution_generation_changes ||
        summary.provenance_changes ||
        xtajit64_tb_history_is_repeat_candidate( &summary ))
        fail( "linear summary is incorrect" );

    xtajit64_tb_history_init( &history );
    for (sequence = 1; sequence <= 300; ++sequence)
        xtajit64_tb_history_record( &history, 0x3000 + (sequence & 3) * 16,
                                    5, 11, 12, 13, 14 );
    xtajit64_tb_history_summarize( &history, &summary );
    if (summary.first_sequence != 173 || summary.last_sequence != 300 ||
        summary.valid != XTAJIT64_TB_HISTORY_SUMMARY_WINDOW ||
        summary.unique_pc_count != 4 ||
        summary.overwritten != 44 || summary.execution_generation_changes ||
        summary.provenance_changes ||
        !xtajit64_tb_history_is_repeat_candidate( &summary ))
        fail( "repeating-cycle summary is incorrect" );

    xtajit64_tb_history_record( &history, 0x3010, 5, 99, 12, 13, 14 );
    xtajit64_tb_history_summarize( &history, &summary );
    if (!summary.provenance_changes ||
        xtajit64_tb_history_is_repeat_candidate( &summary ))
        fail( "mixed execution provenance was classified as a cycle" );

    xtajit64_tb_history_init( &history );
    for (sequence = 1; sequence <= 300; ++sequence)
        xtajit64_tb_history_record( &history, 0x5000 + (sequence & 3) * 16,
                                    5, 17, sequence / 8, 19, 20 );
    xtajit64_tb_history_summarize( &history, &summary );
    if (!summary.execution_generation_changes || summary.provenance_changes ||
        !xtajit64_tb_history_is_repeat_candidate( &summary ))
        fail( "cross-generation recurrence was discarded" );
}

static void test_unpublished_slot_rejected(void)
{
    struct xtajit64_tb_history_snapshot snapshot;
    struct xtajit64_tb_history_event *event;
    uint64_t sequence;

    xtajit64_tb_history_init( &history );
    sequence = xtajit64_tb_history_record( &history, 0x4000, 2, 1, 2, 3, 4 );
    event = &history.events[(sequence - 1) % XTAJIT64_TB_HISTORY_CAPACITY];
    atomic_store_explicit( &event->publication_sequence, 0, memory_order_release );
    if (xtajit64_tb_history_snapshot( &history, sequence, &snapshot ))
        fail( "accepted an unpublished slot" );
}

static void test_sampling_stride(void)
{
    uint32_t counter = 0;
    uint32_t block;

    for (block = 0; block + 1 < XTAJIT64_TB_HISTORY_SAMPLE_STRIDE; ++block)
        if (xtajit64_tb_history_should_sample( &counter ))
            fail( "sampling stride fired early" );
    if (!xtajit64_tb_history_should_sample( &counter ) || counter)
        fail( "sampling stride did not fire at its exact boundary" );
    /* Binding release/reacquire must preserve the engine-local phase. */
    for (block = 0; block + 1 < XTAJIT64_TB_HISTORY_SAMPLE_STRIDE; ++block)
        if (xtajit64_tb_history_should_sample( &counter ))
            fail( "binding reuse reset the sampling phase" );
    if (!xtajit64_tb_history_should_sample( &counter ) || counter)
        fail( "binding reuse broke the sampling stride" );
    if (xtajit64_tb_history_should_sample( NULL ))
        fail( "null sampling counter was accepted" );
}

static void test_execution_entry_sample(void)
{
    struct xtajit64_tb_history_snapshot snapshot;
    uint64_t sequence;

    xtajit64_tb_history_init( &history );
    sequence = xtajit64_tb_history_record( &history, 0x12345000, 0,
                                            7, 8, 9, 10 );
    if (!xtajit64_tb_history_snapshot( &history, sequence, &snapshot ) ||
        snapshot.guest_pc != 0x12345000 || snapshot.block_size)
        fail( "execution-entry sample was not preserved" );
}

int main(void)
{
    test_sampling_stride();
    test_execution_entry_sample();
    test_linear_and_loop_summaries();
    test_unpublished_slot_rejected();
    test_concurrent_wrap();
    puts( "xtajit64 translated-block history: ok" );
    return 0;
}
