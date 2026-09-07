/*
 * ARM64EC signal-return ownership policy
 *
 * Copyright 2026 Switchyard Wine project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_ARM64EC_EMULATION_DISPATCH_H
#define __WINE_ARM64EC_EMULATION_DISPATCH_H

#include <stdbool.h>

/* RESTORE_FLAGS_EMULATION is a one-shot request owned by the signal-return
 * consumer.  Consume only that request after the producer has published it;
 * clearing the reusable syscall frame at regular entry could race a context
 * update delivered after entry but before service dispatch. */
static inline bool arm64ec_consume_emulation_dispatch_request(
    volatile unsigned int *restore_flags, unsigned int request_flag )
{
    unsigned int flags;

    if (!restore_flags || !request_flag) return false;
    flags = *restore_flags;
    *restore_flags = flags & ~request_flag;
    return !!(flags & request_flag);
}

/* Produce a return request while the context's owner is still known.  An
 * explicit PE guest return remains authoritative during simulation; a Unix
 * context written outside simulation is also returning to guest execution.
 * A non-EC PC alone is not provenance because a CPU provider may execute
 * generated AArch64 code at such an address on its private control stack. */
static inline bool arm64ec_emulation_dispatch_required( bool arm64ec,
                                                         bool guest_return_requested,
                                                         bool simulation_active,
                                                         bool target_is_ec_code )
{
    return arm64ec && !target_is_ec_code &&
           (guest_return_requested || !simulation_active);
}

/* The signal consumer must use the producer's decision, not sample mode again.
 * In particular, a live SIGUSR1 AArch64 ucontext has no such request and a
 * non-EC PC alone must remain a native return. */
static inline bool arm64ec_emulation_dispatch_pending( bool arm64ec,
                                                        bool emulation_requested,
                                                        bool target_is_ec_code )
{
    return arm64ec && emulation_requested && !target_is_ec_code;
}

/* A cooperative suspend normally transfers the saved context only after
 * simulation has ended.  An explicitly marked ARM64EC guest return also lets
 * ntdll quiesce a provider while server signals are blocked.  The handoff may
 * resume either x64 guest execution or an EC syscall callback, so ntdll must
 * reclaim simulation ownership before restoring SIGUSR1; only the provider's
 * actual native-stack return owns the final InSimulation clear. */
static inline bool arm64ec_suspend_handoff_ready( bool arm64ec,
                                                   bool suspend_pending,
                                                   bool syscall_callback_active,
                                                   bool simulation_active,
                                                   bool guest_return_requested )
{
    if (!suspend_pending || syscall_callback_active) return false;
    if (!simulation_active) return true;
    return arm64ec && guest_return_requested;
}

#endif /* __WINE_ARM64EC_EMULATION_DISPATCH_H */
