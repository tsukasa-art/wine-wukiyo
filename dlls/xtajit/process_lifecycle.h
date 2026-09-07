/*
 * i386 provider process lifecycle tracking
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_XTAJIT_PROCESS_LIFECYCLE_H
#define __WINE_XTAJIT_PROCESS_LIFECYCLE_H

#include <stdint.h>

static inline int xtajit_process_capabilities_satisfied(
    uint64_t required, uint64_t enabled )
{
    return (enabled & required) == required;
}

static inline int xtajit_process_init_failure_must_poison( int unix_initialized )
{
    /* Observer registration has process lifetime and cannot be rolled back.
     * A failure after native initialization must make that registered provider
     * permanently unusable before the PE side raises its fatal exception. */
    return !!unix_initialized;
}

static inline int xtajit_process_term_notification_may_cleanup(
    uintptr_t handle, int is_post, int32_t status )
{
    (void)handle;
    (void)is_post;
    (void)status;

    /* Wine sends both callbacks around a soft NtTerminateProcess(NULL) that
     * must return for LdrShutdownProcess.  The provider is process-lifetime:
     * neither callback is a quiescent teardown boundary, and the OS reclaims
     * it at process exit. */
    return 0;
}

#endif /* __WINE_XTAJIT_PROCESS_LIFECYCLE_H */
