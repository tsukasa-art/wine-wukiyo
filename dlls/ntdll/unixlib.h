/*
 * Ntdll Unix interface
 *
 * Copyright (C) 2020 Alexandre Julliard
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

#ifndef __NTDLL_UNIXLIB_H
#define __NTDLL_UNIXLIB_H

#include "wine/unixlib.h"
#include "wine/wow64_user.h"

struct _DISPATCHER_CONTEXT;

struct wine_dbg_write_params
{
    const char  *str;
    unsigned int len;
};

struct current_teb_params
{
    void *teb;
};

struct native_callback_context_params
{
    void *teb;
    void *pthread_teb;
    void *native_callback_depth;
    void *get_teb_from_pthread;
};

struct wine_server_fd_to_handle_params
{
    int          fd;
    unsigned int access;
    unsigned int attributes;
    HANDLE      *handle;
};

struct wine_server_handle_to_fd_params
{
    HANDLE        handle;
    unsigned int  access;
    int          *unix_fd;
    unsigned int *options;
};

struct wine_spawnvp_params
{
    char       **argv;
    int          wait;
};

struct native_thread_func_params
{
    void *func;
    void *arg;
};

struct native_callback_params
{
    void      *func;
    ULONG_PTR args[4];
    ULONG_PTR ret;
};

struct native_callback_args_params
{
    void      *func;
    ULONG      argc;
    ULONG_PTR args[12];
    ULONG_PTR ret;
    void      *native_tsd_base;
};

struct native_code_region_params
{
    const void *base;
    SIZE_T      size;
};

struct load_so_dll_params
{
    UNICODE_STRING              nt_name;
    void                      **module;
};

struct unwind_builtin_dll_params
{
    ULONG                       type;
    struct _DISPATCHER_CONTEXT *dispatch;
    CONTEXT                    *context;
};

struct wine_get_unix_env_params
{
    const char   *name;
    char         *value;
    unsigned int  value_size;
};

#define WINE_PROCESS_PACKAGE_GRAPH_LIMIT_2G 0x00000001u

/*
 * Keep this argument block pointer-free so the native and WOW64 Unix-call
 * tables use exactly the same layout.  graph and size are outputs.
 */
struct wine_get_process_package_graph_params
{
    unsigned long long process;
    unsigned long long graph;
    unsigned int size;
    unsigned int flags;
};

/* Internal signal-to-normal-context handoff, never delivered to guest VEH. */
#define STATUS_WINE_NATIVE_GUARD ((NTSTATUS)0xe0570051)
struct native_guard_params
{
    ULONGLONG pc, address, allocation_id;
    ULONG size, write;
};

enum ntdll_unix_funcs
{
    unix_load_so_dll,
    unix_unwind_builtin_dll,
    unix_wine_dbg_write,
    unix_get_current_teb,
    unix_get_native_callback_context,
    unix_wine_server_call,
    unix_wine_server_fd_to_handle,
    unix_wine_server_handle_to_fd,
    unix_wine_spawnvp,
    unix_call_native_thread_func,
    unix_call_native_callback3,
    unix_call_native_callback4,
    unix_register_non_native_code_region,
    unix_system_time_precise,
    unix_call_native_callback_args,
    unix_get_unix_env,
    unix_wow64_user_copy,
    unix_resolve_native_guard,
    unix_get_exception_stack,
    unix_prepare_shared_stack,
};

extern unixlib_handle_t __wine_unixlib_handle;

struct exception_stack_params { UINT64 limit, base; };
struct shared_stack_init_params { UINT64 sp; };

#endif /* __NTDLL_UNIXLIB_H */
