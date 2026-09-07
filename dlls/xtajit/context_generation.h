/*
 * i386 provider context-transition helpers
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_XTAJIT_CONTEXT_GENERATION_H
#define __WINE_XTAJIT_CONTEXT_GENERATION_H

#include <stdint.h>

struct xtajit_context_generation
{
    /* Owned by the current simulated thread.  Cross-thread SetContext does
     * not retain that thread's provider-private record. */
    uint64_t value;
};

#define XTAJIT_I386_UNIX_CALL_FRAME_DWORDS 5u
#define XTAJIT_I386_UNIX_CALL_FRAME_SIZE \
    (XTAJIT_I386_UNIX_CALL_FRAME_DWORDS * sizeof(uint32_t))

struct xtajit_i386_unix_call_completion
{
    uint32_t eax, esp, eip;
};

static inline struct xtajit_i386_unix_call_completion
xtajit_i386_complete_rejected_unix_call( uint32_t old_esp,
                                          uint32_t return_address,
                                          uint32_t status )
{
    struct xtajit_i386_unix_call_completion completion;

    /* The caller has already validated and read the complete stdcall frame,
     * so advancing by its fixed size cannot wrap. */
    completion.eax = status;
    completion.esp = old_esp + XTAJIT_I386_UNIX_CALL_FRAME_SIZE;
    completion.eip = return_address;
    return completion;
}

static inline uint64_t xtajit_context_generation_snapshot(
    const struct xtajit_context_generation *generation )
{
    return generation->value;
}

static inline void xtajit_context_generation_advance(
    struct xtajit_context_generation *generation )
{
    uint64_t next = generation->value + 1;

    /* Reserve zero for a newly initialized thread while retaining a change
     * across the only wrap that can occur in a dispatch snapshot. */
    generation->value = next ? next : 1;
}

static inline int xtajit_context_generation_changed(
    const struct xtajit_context_generation *generation, uint64_t snapshot )
{
    return generation->value != snapshot;
}

static inline int xtajit_context_requires_reload(
    const struct xtajit_context_generation *generation, uint64_t snapshot,
    int reset_state )
{
    /* SetContext is also used in balanced pairs around returning WoW64 user
     * callbacks.  Only RESET_STATE surviving the native call distinguishes a
     * non-returning context install from such a temporary generation change.
     * Conversely, a stale RESET_STATE without a new install must not discard
     * the current call's return value. */
    return reset_state && xtajit_context_generation_changed( generation, snapshot );
}

#endif /* __WINE_XTAJIT_CONTEXT_GENERATION_H */
