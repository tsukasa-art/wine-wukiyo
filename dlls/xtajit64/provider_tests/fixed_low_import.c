/*
 * XTAJIT64 fixed-low main-image import regression helper
 *
 * Copyright 2026 Switchyard contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#if 0
#pragma makedep standalone
#endif

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"

__declspec(dllimport) ULONG WINAPI fixed_low_export( ULONG value );

ULONG WINAPI fixed_low_import_call( ULONG value )
{
    return fixed_low_export( value );
}

const void * WINAPI fixed_low_import_target(void)
{
    return (const void *)fixed_low_export;
}

BOOL WINAPI DllMain( HINSTANCE instance, DWORD reason, void *reserved )
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
