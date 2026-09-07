/*
 * ARM64 signal handling routines
 *
 * Copyright 2010-2013 André Hentschel
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

#ifdef __aarch64__

#include "config.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYSCALL_H
# include <syscall.h>
#else
# ifdef HAVE_SYS_SYSCALL_H
#  include <sys/syscall.h>
# endif
#endif
#ifdef HAVE_SYS_SIGNAL_H
# include <sys/signal.h>
#endif
#ifdef HAVE_SYS_UCONTEXT_H
# include <sys/ucontext.h>
#endif
#ifdef HAVE_OS_CUSTOM_X18_ABI
# include <os/arch/arm64.h>
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/asm.h"
#include "unix_private.h"
#include "wine/debug.h"
#include "arm64ec_emulation_dispatch.h"
#ifdef __APPLE__
# include "arm64ec_low_guest_decode.h"
#endif

WINE_DEFAULT_DEBUG_CHANNEL(seh);
WINE_DECLARE_DEBUG_CHANNEL(arm64ec_return);
WINE_DECLARE_DEBUG_CHANNEL(arm64ec_susp);

#ifdef __APPLE__

#if defined(HAVE_OS_CUSTOM_X18_ABI) && \
    defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && \
    __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 260400
# define CUSTOM_X18_ABI_ALWAYS_AVAILABLE
#endif

#if defined(HAVE_OS_CUSTOM_X18_ABI) && !defined(CUSTOM_X18_ABI_ALWAYS_AVAILABLE)
static bool (*custom_x18_abi_enabled_func)(void);
static void (*set_custom_x18_abi_enabled_func)(bool enabled);
#endif

/* libsystem_kernel uses this exported commpage entry to commit TPIDR_EL0 after
 * checking the public strict-toggle contract.  The kernel can reinstall its
 * system TPIDR value asynchronously, so a query followed by the strict setter
 * has an unavoidable check/use race.  Use the same update entry when present;
 * init_custom_x18_abi() exercises both directions before PE code can rely on
 * it, and older systems retain the public-API fallback. */
#ifdef HAVE_OS_CUSTOM_X18_ABI
extern void *update_tpidr __attribute__((weak_import));
static BOOL use_idempotent_x18_transition;

extern void set_custom_x18_abi_enabled_idempotent( BOOL enabled );
__ASM_GLOBAL_FUNC( set_custom_x18_abi_enabled_idempotent,
                   "mrs x9, TPIDR_EL0\n\t"
                   "and x8, x9, #0xfffffffffff00000\n\t"
                   "and x8, x8, #0xfffeffffffffffff\n\t"
                   "cmp w0, #0\n\t"
                   "mov x9, #0x1000000000000\n\t"
                   "csel x9, x9, xzr, ne\n\t"
                   "orr x0, x8, x9\n\t"
                   "adrp x10, _update_tpidr@GOTPAGE\n\t"
                   "ldr x10, [x10, _update_tpidr@GOTPAGEOFF]\n\t"
                   "ldr x1, [x10]\n\t"
                   "braaz x1" )
#endif

static void set_custom_x18_abi_enabled( BOOL enabled );

static BOOL custom_x18_abi_enabled(void)
{
#ifdef HAVE_OS_CUSTOM_X18_ABI
    if (use_idempotent_x18_transition)
    {
        ULONG_PTR tpidr;

        __asm__ volatile( "mrs %0, TPIDR_EL0" : "=r" (tpidr) );
        return !!(tpidr & 0x1000000000000ULL);
    }
#endif
#ifdef CUSTOM_X18_ABI_ALWAYS_AVAILABLE
    return os_custom_x18_abi_enabled();
#elif defined(HAVE_OS_CUSTOM_X18_ABI)
    return custom_x18_abi_enabled_func && custom_x18_abi_enabled_func();
#else
    return FALSE;
#endif
}

static BOOL init_custom_x18_abi(void)
{
#if defined(HAVE_OS_CUSTOM_X18_ABI) && !defined(CUSTOM_X18_ABI_ALWAYS_AVAILABLE)
    if (__builtin_available(macOS 26.4, *))
    {
        custom_x18_abi_enabled_func = os_custom_x18_abi_enabled;
        set_custom_x18_abi_enabled_func = os_set_custom_x18_abi_enabled;
    }
    if (!custom_x18_abi_enabled_func || !set_custom_x18_abi_enabled_func) return FALSE;
#elif !defined(CUSTOM_X18_ABI_ALWAYS_AVAILABLE)
    return FALSE;
#endif

#ifdef HAVE_OS_CUSTOM_X18_ABI
    use_idempotent_x18_transition = &update_tpidr && update_tpidr;
#endif

    /* Symbol availability does not prove that this task carries the required
     * entitlement. Exercise both states while x18 still belongs to Darwin. */
    if (!custom_x18_abi_enabled())
    {
        set_custom_x18_abi_enabled( TRUE );
        if (!custom_x18_abi_enabled()) return FALSE;
    }
    set_custom_x18_abi_enabled( FALSE );
    return !custom_x18_abi_enabled();
}

static void set_custom_x18_abi_enabled( BOOL enabled )
{
#ifdef HAVE_OS_CUSTOM_X18_ABI
    if (use_idempotent_x18_transition)
    {
        set_custom_x18_abi_enabled_idempotent( enabled );
        return;
    }
#endif
#ifdef CUSTOM_X18_ABI_ALWAYS_AVAILABLE
    os_set_custom_x18_abi_enabled( enabled );
#elif defined(HAVE_OS_CUSTOM_X18_ABI)
    if (set_custom_x18_abi_enabled_func) set_custom_x18_abi_enabled_func( enabled );
#else
    (void)enabled;
#endif
}

/* Windows owns x18 as its TEB pointer. Darwin APIs may only run while the
 * thread is in the system x18 ABI, so every PE/Unix transition switches the
 * ownership mode before crossing the boundary. */
static void __attribute__((used,noinline)) enter_system_x18_abi(void)
{
#ifdef HAVE_OS_CUSTOM_X18_ABI
    if (use_idempotent_x18_transition)
    {
        set_custom_x18_abi_enabled( FALSE );
        return;
    }
#endif
    if (custom_x18_abi_enabled()) set_custom_x18_abi_enabled( FALSE );
}

static void __attribute__((used,noinline)) enter_windows_x18_abi(void)
{
#ifdef HAVE_OS_CUSTOM_X18_ABI
    if (use_idempotent_x18_transition)
    {
        set_custom_x18_abi_enabled( TRUE );
        return;
    }
#endif
    if (!custom_x18_abi_enabled()) set_custom_x18_abi_enabled( TRUE );
}

#endif

#define NTDLL_DWARF_H_NO_UNWINDER
#include "dwarf.h"

struct arm64_thread_data
{
    BOOL suspend_pending;
};

C_ASSERT( sizeof(struct arm64_thread_data) <= sizeof(((struct teb_data *)0)->cpu_data) );

static inline struct arm64_thread_data *arm64_thread_data( struct thread_data *data )
{
    return (struct arm64_thread_data *)get_teb_data(data)->cpu_data;
}

/***********************************************************************
 * signal context platform-specific definitions
 */
#ifdef linux

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext.reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext.regs[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(pstate, context) /* Current State Register */
# define FP_sig(context)            REGn_sig(29, context)    /* Frame pointer */
# define LR_sig(context)            REGn_sig(30, context)    /* Link Register */

static struct _aarch64_ctx *get_extended_sigcontext( const ucontext_t *sigcontext, unsigned int magic )
{
    struct _aarch64_ctx *ctx = (struct _aarch64_ctx *)sigcontext->uc_mcontext.__reserved;
    while ((char *)ctx < (char *)(&sigcontext->uc_mcontext + 1) && ctx->magic && ctx->size)
    {
        if (ctx->magic == magic) return ctx;
        ctx = (struct _aarch64_ctx *)((char *)ctx + ctx->size);
    }
    return NULL;
}

static struct fpsimd_context *get_fpsimd_context( const ucontext_t *sigcontext )
{
    return (struct fpsimd_context *)get_extended_sigcontext( sigcontext, FPSIMD_MAGIC );
}

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
#ifdef ESR_MAGIC
    struct esr_context *esr = (struct esr_context *)get_extended_sigcontext( sigcontext, ESR_MAGIC );
    if (esr) return esr->esr;
#endif
    return 0;
}

#elif defined(__APPLE__)

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext->__ss.__ ## reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext->__ss.__x[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(cpsr, context)  /* Current State Register */
# define FP_sig(context)            REG_sig(fp, context)    /* Frame pointer */
# define LR_sig(context)            REG_sig(lr, context)    /* Link Register */

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
    return sigcontext->uc_mcontext->__es.__esr;
}

#endif /* linux */

/* stack layout when calling KiUserExceptionDispatcher */
struct exc_stack_layout
{
    CONTEXT              context;        /* 000 */
    CONTEXT_EX           context_ex;     /* 390 */
    EXCEPTION_RECORD     rec;            /* 3b0 */
    ULONG64              align;          /* 448 */
    ULONG64              redzone[2];     /* 450 */
};
C_ASSERT( offsetof(struct exc_stack_layout, rec) == 0x3b0 );
C_ASSERT( sizeof(struct exc_stack_layout) == 0x460 );

/* stack layout when calling KiUserApcDispatcher */
struct apc_stack_layout
{
    void                *func;           /* 000 APC to call*/
    ULONG64              args[3];        /* 008 function arguments */
    ULONG64              alertable;      /* 020 */
    ULONG64              align;          /* 028 */
    CONTEXT              context;        /* 030 */
    ULONG64              redzone[2];     /* 3c0 */
};
C_ASSERT( offsetof(struct apc_stack_layout, context) == 0x30 );
C_ASSERT( sizeof(struct apc_stack_layout) == 0x3d0 );

/* stack layout when calling KiUserCallbackDispatcher */
struct callback_stack_layout
{
    void                *args;           /* 000 arguments */
    ULONG                len;            /* 008 arguments len */
    ULONG                id;             /* 00c function id */
    ULONG64              unknown;        /* 010 */
    ULONG64              lr;             /* 018 */
    ULONG64              sp;             /* 020 sp+pc (machine frame) */
    ULONG64              pc;             /* 028 */
    BYTE                 args_data[0];   /* 030 copied argument data*/
};
C_ASSERT( offsetof(struct callback_stack_layout, sp) == 0x20 );
C_ASSERT( sizeof(struct callback_stack_layout) == 0x30 );

#define RESTORE_FLAGS_EMULATION  0x00010000

struct syscall_frame
{
    ULONG64               x[29];          /* 000 */
    ULONG64               fp;             /* 0e8 */
    ULONG64               lr;             /* 0f0 */
    ULONG64               sp;             /* 0f8 */
    ULONG64               pc;             /* 100 */
    ULONG                 cpsr;           /* 108 */
    ULONG                 restore_flags;  /* 10c */
    struct syscall_frame *prev_frame;     /* 110 */
    void                 *syscall_cfa;    /* 118 */
    ULONG                 syscall_id;     /* 120 */
    ULONG                 dispatcher_flags; /* 124 */
    ULONG                 fpcr;           /* 128 */
    ULONG                 fpsr;           /* 12c */
    NEON128               v[32];          /* 130 */
};

static BOOL arm64ec_signal_return_requires_emulation_dispatch(
    struct thread_data *data, struct syscall_frame *frame )
{
    const CHPE_V2_CPU_AREA_INFO *cpu =
        data && data->teb ? data->teb->ChpeV2CpuAreaInfo : NULL;
    ULONG restore_flags = frame->restore_flags;
    BOOL arm64ec = is_arm64ec();
    BOOL emulation_requested = arm64ec_consume_emulation_dispatch_request(
        &frame->restore_flags, RESTORE_FLAGS_EMULATION );
    BOOL target_is_ec_code = is_ec_code( frame->pc );
    BOOL dispatch = arm64ec_emulation_dispatch_pending(
        arm64ec, emulation_requested, target_is_ec_code );

    TRACE_(arm64ec_return)(
        "flags %#x->%#x dispatcher %#x syscall %#x pc %p sp %p "
        "x16 %p x17 %p arm64ec %u requested %u simulation %u "
        "callback %u ec %u dispatch %u\n",
        restore_flags, frame->restore_flags, frame->dispatcher_flags,
        frame->syscall_id,
        (void *)(ULONG_PTR)frame->pc, (void *)(ULONG_PTR)frame->sp,
        (void *)(ULONG_PTR)frame->x[16], (void *)(ULONG_PTR)frame->x[17],
        arm64ec, emulation_requested,
        cpu ? *(const volatile BOOLEAN *)&cpu->InSimulation : 0,
        cpu ? *(const volatile BOOLEAN *)&cpu->InSyscallCallback : 0,
        target_is_ec_code, dispatch );
    return dispatch;
}

C_ASSERT( sizeof( struct syscall_frame ) == 0x330 );

#define DISPATCHER_FLAG_UNIX_CALL         0x01
#define DISPATCHER_FLAG_RETURN_CUSTOM_X18 0x02
#define DISPATCHER_FLAG_SYSCALL_TRACE     0x04

#ifdef __APPLE__

struct unix_dispatcher_entry
{
    struct syscall_frame *frame;
    TEB *teb;
    ULONG_PTR saved_x18;
    BOOL custom_x18;
};

C_ASSERT( offsetof( struct unix_dispatcher_entry, frame ) == 0x00 );
C_ASSERT( offsetof( struct unix_dispatcher_entry, teb ) == 0x08 );
C_ASSERT( offsetof( struct unix_dispatcher_entry, saved_x18 ) == 0x10 );
C_ASSERT( offsetof( struct unix_dispatcher_entry, custom_x18 ) == 0x18 );
C_ASSERT( sizeof( struct unix_dispatcher_entry ) == 0x20 );

/* A nested Darwin callback may enter the Unix dispatcher while x18 is
 * system-owned. Recover the TEB from pthread state, and preserve an existing
 * custom-x18 value only as opaque PE register state. */
static void __attribute__((used,noinline)) prepare_unix_dispatcher_entry(
    struct unix_dispatcher_entry *entry )
{
    struct thread_data *data;

    entry->custom_x18 = custom_x18_abi_enabled();
    entry->saved_x18 = 0;
    if (entry->custom_x18)
    {
        __asm__ volatile( "mov %0, x18" : "=r" (entry->saved_x18) );
        set_custom_x18_abi_enabled( FALSE );
    }

    data = get_thread_data();
    entry->teb = data ? data->teb : NULL;
    entry->frame = data ? get_syscall_frame( data ) : NULL;
}

#endif


#define ESR_ELx_EC(esr)                 (((DWORD64)(esr) >> 26) & 0x3f)
#define ESR_ELx_EC_IABT_LOW             0x20
#define ESR_ELx_EC_IABT_CUR             0x21
#define ESR_ELx_EC_PC_ALIGN             0x22
#define ESR_ELx_EC_DABT_LOW             0x24
#define ESR_ELx_EC_DABT_CUR             0x25
#define ESR_ELx_EC_SOFTSTP_LOW          0x32
#define ESR_ELx_EC_SOFTSTP_CUR          0x33
#define ESR_ELx_EC_BRK64                0x3c
#define ESR_ELx_ISS_DABT_WNR(esr)       (((esr) >> 6) & 0x01)
#define ESR_ELx_ISS_BRK_COMMENT(esr)    ((esr) & 0xffff)
#define ESR_ELx_ISS_DFSC(esr)           ((esr) & 0x3f)
#define ESR_ELx_ISS_DFSC_ALIGN_FAULT    0x21

#ifdef linux
static DWORD64 make_esr( ULONG ec, ULONG info )
{
    return ((DWORD64)ec << 26) | (info & 0xffff);
}
#endif

/***********************************************************************
 *           context_init_empty_xstate
 *
 * Initializes a context's CONTEXT_EX structure to point to an empty xstate buffer
 */
static inline void context_init_empty_xstate( CONTEXT *context, void *xstate_buffer )
{
    CONTEXT_EX *xctx;

    xctx = (CONTEXT_EX *)(context + 1);
    xctx->Legacy.Length = sizeof(CONTEXT);
    xctx->Legacy.Offset = -(LONG)sizeof(CONTEXT);
    xctx->XState.Length = 0;
    xctx->XState.Offset = (BYTE *)xstate_buffer - (BYTE *)xctx;
    xctx->All.Length = sizeof(CONTEXT) + xctx->XState.Offset + xctx->XState.Length;
    xctx->All.Offset = -(LONG)sizeof(CONTEXT);
}

void set_process_instrumentation_callback( void *callback )
{
    if (callback) FIXME( "Not supported.\n" );
}


/***********************************************************************
 *           syscall_frame_fixup_for_fastpath
 *
 * Fixes up the given syscall frame such that the syscall dispatcher
 * can return via the fast path if CONTEXT_INTEGER is set in
 * restore_flags.
 *
 * Clobbers the frame's X16 and X17 register values.
 */
static void syscall_frame_fixup_for_fastpath( struct syscall_frame *frame )
{
    frame->x[16] = frame->pc;
    frame->x[17] = frame->sp;
}

/***********************************************************************
 *           save_fpu
 *
 * Set the FPU context from a sigcontext.
 */
static void save_fpu( CONTEXT *context, const ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = fp->fpcr;
    context->Fpsr = fp->fpsr;
    memcpy( context->V, fp->vregs, sizeof(context->V) );
#elif defined(__APPLE__)
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = sigcontext->uc_mcontext->__ns.__fpcr;
    context->Fpsr = sigcontext->uc_mcontext->__ns.__fpsr;
    memcpy( context->V, sigcontext->uc_mcontext->__ns.__v, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           restore_fpu
 *
 * Restore the FPU context to a sigcontext.
 */
static void restore_fpu( const CONTEXT *context, ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    fp->fpcr = context->Fpcr;
    fp->fpsr = context->Fpsr;
    memcpy( fp->vregs, context->V, sizeof(fp->vregs) );
#elif defined(__APPLE__)
    sigcontext->uc_mcontext->__ns.__fpcr = context->Fpcr;
    sigcontext->uc_mcontext->__ns.__fpsr = context->Fpsr;
    memcpy( sigcontext->uc_mcontext->__ns.__v, context->V, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           save_context
 *
 * Set the register values from a sigcontext.
 */
static void save_context( CONTEXT *context, const ucontext_t *sigcontext )
{
    DWORD i;

    context->ContextFlags = CONTEXT_FULL;
    context->Fp   = FP_sig(sigcontext);     /* Frame pointer */
    context->Lr   = LR_sig(sigcontext);     /* Link register */
    context->Sp   = SP_sig(sigcontext);     /* Stack pointer */
    context->Pc   = PC_sig(sigcontext);     /* Program Counter */
    context->Cpsr = PSTATE_sig(sigcontext); /* Current State Register */
    for (i = 0; i <= 28; i++) context->X[i] = REGn_sig( i, sigcontext );
    save_fpu( context, sigcontext );
}


/***********************************************************************
 *           restore_context
 *
 * Build a sigcontext from the register values.
 */
static void restore_context( const CONTEXT *context, ucontext_t *sigcontext )
{
    DWORD i;

    FP_sig(sigcontext)     = context->Fp;   /* Frame pointer */
    LR_sig(sigcontext)     = context->Lr;   /* Link register */
    SP_sig(sigcontext)     = context->Sp;   /* Stack pointer */
    PC_sig(sigcontext)     = context->Pc;   /* Program Counter */
    PSTATE_sig(sigcontext) = context->Cpsr; /* Current State Register */
    for (i = 0; i <= 28; i++) REGn_sig( i, sigcontext ) = context->X[i];
    restore_fpu( context, sigcontext );
}


/***********************************************************************
 *           signal_set_full_context
 */
NTSTATUS signal_set_full_context( CONTEXT *context )
{
    struct thread_data *data = get_thread_data();
    struct syscall_frame *frame = get_syscall_frame( data );
    struct arm64_thread_data *arm64_data = arm64_thread_data( data );
    CHPE_V2_CPU_AREA_INFO *cpu_area = data->teb->ChpeV2CpuAreaInfo;
    BOOL arm64ec = is_arm64ec();
    BOOL guest_return_requested =
        !!(context->ContextFlags & CONTEXT_ARM64_RET_TO_GUEST);
    BOOL handoff_ready = cpu_area && cpu_area->SuspendDoorbell &&
        arm64ec_suspend_handoff_ready(
            arm64ec, arm64_data->suspend_pending,
            *(const volatile BOOLEAN *)&cpu_area->InSyscallCallback,
            *(const volatile BOOLEAN *)&cpu_area->InSimulation,
            guest_return_requested );
    NTSTATUS status;

    if (handoff_ready)
    {
        sigset_t old_set;

        pthread_sigmask( SIG_BLOCK, &server_block_set, &old_set );
        handoff_ready = cpu_area->SuspendDoorbell &&
            arm64ec_suspend_handoff_ready(
                arm64ec, arm64_data->suspend_pending,
                *(const volatile BOOLEAN *)&cpu_area->InSyscallCallback,
                *(const volatile BOOLEAN *)&cpu_area->InSimulation,
                guest_return_requested );
        if (handoff_ready)
        {
            BOOL simulation_active =
                *(const volatile BOOLEAN *)&cpu_area->InSimulation;
            BOOL simulation_quiesced;
            BOOL suspend_pending = arm64_data->suspend_pending;
            ULONG doorbell_value =
                *(const volatile ULONG *)cpu_area->SuspendDoorbell;

            /* Publish quiescence only while server signals are blocked.  This
             * NtContinue handoff resumes a provider context rather than ending
             * simulation, so reclaim ownership before restoring SIGUSR1.  The
             * provider's actual native-stack return owns the final clear. */
            if (simulation_active) cpu_area->InSimulation = 0;
            simulation_quiesced =
                *(const volatile BOOLEAN *)&cpu_area->InSimulation;
            *cpu_area->SuspendDoorbell = 0;
            arm64_data->suspend_pending = FALSE;
            wait_suspend( context );
            status = NtSetContextThread( GetCurrentThread(), context );
            if (simulation_active) cpu_area->InSimulation = 1;
            TRACE_(arm64ec_susp)(
                "suspend return handoff pc %p sp %p simulation %u->%u->%u "
                "callback %u doorbell %p value %#x pending %u guest %u "
                "status %#x\n",
                (void *)(ULONG_PTR)context->Pc,
                (void *)(ULONG_PTR)context->Sp, simulation_active,
                simulation_quiesced,
                *(const volatile BOOLEAN *)&cpu_area->InSimulation,
                *(const volatile BOOLEAN *)&cpu_area->InSyscallCallback,
                cpu_area->SuspendDoorbell, doorbell_value, suspend_pending,
                guest_return_requested, status );
        }
        else status = NtSetContextThread( GetCurrentThread(), context );
        pthread_sigmask( SIG_SETMASK, &old_set, NULL );
    }
    else status = NtSetContextThread( GetCurrentThread(), context );

    if (!status && (context->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
        frame->restore_flags |= CONTEXT_INTEGER;

    return status;
}


/***********************************************************************
 *              get_native_context
 */
void *get_native_context( CONTEXT *context )
{
    return context;
}


/***********************************************************************
 *              get_wow_context
 */
void *get_wow_context( CONTEXT *context )
{
    return get_cpu_area( get_thread_data(), main_image_info.Machine );
}


/***********************************************************************
 *              NtSetContextThread  (NTDLL.@)
 *              ZwSetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetContextThread( HANDLE handle, const CONTEXT *context )
{
    struct thread_data *data = get_thread_data();
    struct syscall_frame *frame = get_syscall_frame( data );
    const CHPE_V2_CPU_AREA_INFO *cpu =
        data && data->teb ? data->teb->ChpeV2CpuAreaInfo : NULL;
    NTSTATUS ret = STATUS_SUCCESS;
    BOOL self = (handle == GetCurrentThread());
    DWORD flags = context->ContextFlags & ~CONTEXT_ARM64;
    BOOL guest_return_requested = flags & CONTEXT_ARM64_RET_TO_GUEST;
    BOOL simulation_active = cpu &&
        *(const volatile BOOLEAN *)&cpu->InSimulation;

    flags &= ~CONTEXT_ARM64_RET_TO_GUEST;

    if (self && !frame) return STATUS_ACCESS_DENIED;
    if (self && (flags & CONTEXT_DEBUG_REGISTERS)) self = FALSE;

    if (!self)
    {
        ret = set_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (ret || !self) return ret;
    }

    if (flags & CONTEXT_INTEGER)
    {
        memcpy( frame->x, context->X, sizeof(context->X[0]) * 18 );
        /* skip x18 */
        memcpy( frame->x + 19, context->X + 19, sizeof(context->X[0]) * 10 );
    }
    if (flags & CONTEXT_CONTROL)
    {
        frame->fp    = context->Fp;
        frame->lr    = context->Lr;
        frame->sp    = context->Sp;
        frame->pc    = context->Pc;
        frame->cpsr  = context->Cpsr;
        if (is_arm64ec())
        {
            if (arm64ec_emulation_dispatch_required(
                    TRUE, guest_return_requested, simulation_active,
                    is_ec_code( frame->pc )))
                flags |= RESTORE_FLAGS_EMULATION;
            else frame->restore_flags &= ~RESTORE_FLAGS_EMULATION;
        }
    }
    if (flags & CONTEXT_FLOATING_POINT)
    {
        frame->fpcr = context->Fpcr;
        frame->fpsr = context->Fpsr;
        memcpy( frame->v, context->V, sizeof(frame->v) );
    }
    if (flags & CONTEXT_ARM64_X18)
    {
        frame->x[18] = context->X[18];
    }
    if (flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    frame->restore_flags |= flags & ~CONTEXT_INTEGER;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtGetContextThread  (NTDLL.@)
 *              ZwGetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtGetContextThread( HANDLE handle, CONTEXT *context )
{
    struct thread_data *data = get_thread_data();
    struct syscall_frame *frame = get_syscall_frame( data );
    DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM64;
    BOOL self = (handle == GetCurrentThread());

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (ret || !self) return ret;
    }
    else if (!frame) return STATUS_ACCESS_DENIED;

    if (needed_flags & CONTEXT_INTEGER)
    {
        memcpy( context->X, frame->x, sizeof(context->X[0]) * 29 );
        context->ContextFlags |= CONTEXT_INTEGER;
    }
    if (needed_flags & CONTEXT_CONTROL)
    {
        context->Fp   = frame->fp;
        context->Lr   = frame->lr;
        context->Sp   = frame->sp;
        context->Pc   = frame->pc;
        context->Cpsr = frame->cpsr;
        context->ContextFlags |= CONTEXT_CONTROL;
    }
    if (needed_flags & CONTEXT_FLOATING_POINT)
    {
        context->Fpcr = frame->fpcr;
        context->Fpsr = frame->fpsr;
        memcpy( context->V, frame->v, sizeof(context->V) );
        context->ContextFlags |= CONTEXT_FLOATING_POINT;
    }
    if (needed_flags & CONTEXT_ARM64_X18)
    {
        context->X[18] = frame->x[18];
        context->ContextFlags |= CONTEXT_ARM64_X18;
    }
    if (needed_flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              set_thread_wow64_context
 */
NTSTATUS set_thread_wow64_context( HANDLE handle, const void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    struct thread_data *data = get_thread_data();
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = set_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( data, machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame;
        const I386_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_i386;

        if (flags & CONTEXT_I386_INTEGER)
        {
            wow_frame->Eax = context->Eax;
            wow_frame->Ebx = context->Ebx;
            wow_frame->Ecx = context->Ecx;
            wow_frame->Edx = context->Edx;
            wow_frame->Esi = context->Esi;
            wow_frame->Edi = context->Edi;
        }
        if (flags & CONTEXT_I386_CONTROL)
        {
            WOW64_CPURESERVED *cpu = data->teb->TlsSlots[WOW64_TLS_CPURESERVED];

            wow_frame->Esp    = context->Esp;
            wow_frame->Ebp    = context->Ebp;
            wow_frame->Eip    = context->Eip;
            wow_frame->EFlags = context->EFlags;
            wow_frame->SegCs  = context->SegCs;
            wow_frame->SegSs  = context->SegSs;
            cpu->Flags |= WOW64_CPURESERVED_FLAG_RESET_STATE;
        }
        if (flags & CONTEXT_I386_SEGMENTS)
        {
            wow_frame->SegDs = context->SegDs;
            wow_frame->SegEs = context->SegEs;
            wow_frame->SegFs = context->SegFs;
            wow_frame->SegGs = context->SegGs;
        }
        if (flags & CONTEXT_I386_DEBUG_REGISTERS)
        {
            wow_frame->Dr0 = context->Dr0;
            wow_frame->Dr1 = context->Dr1;
            wow_frame->Dr2 = context->Dr2;
            wow_frame->Dr3 = context->Dr3;
            wow_frame->Dr6 = context->Dr6;
            wow_frame->Dr7 = context->Dr7;
        }
        if (flags & CONTEXT_I386_EXTENDED_REGISTERS)
        {
            memcpy( &wow_frame->ExtendedRegisters, context->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
        }
        if (flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &wow_frame->FloatSave, &context->FloatSave, sizeof(context->FloatSave) );
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame;
        const ARM_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_ARM;

        if (flags & CONTEXT_INTEGER)
        {
            wow_frame->R0  = context->R0;
            wow_frame->R1  = context->R1;
            wow_frame->R2  = context->R2;
            wow_frame->R3  = context->R3;
            wow_frame->R4  = context->R4;
            wow_frame->R5  = context->R5;
            wow_frame->R6  = context->R6;
            wow_frame->R7  = context->R7;
            wow_frame->R8  = context->R8;
            wow_frame->R9  = context->R9;
            wow_frame->R10 = context->R10;
            wow_frame->R11 = context->R11;
            wow_frame->R12 = context->R12;
        }
        if (flags & CONTEXT_CONTROL)
        {
            wow_frame->Sp = context->Sp;
            wow_frame->Lr = context->Lr;
            wow_frame->Pc = context->Pc & ~1;
            wow_frame->Cpsr = context->Cpsr;
            if (context->Cpsr & 0x20) wow_frame->Pc |= 1; /* thumb */
        }
        if (flags & CONTEXT_FLOATING_POINT)
        {
            wow_frame->Fpscr = context->Fpscr;
            memcpy( wow_frame->D, context->D, sizeof(context->D) );
        }
        break;
    }

    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              get_thread_wow64_context
 */
NTSTATUS get_thread_wow64_context( HANDLE handle, void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    struct thread_data *data = get_thread_data();
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( data, machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_i386;

        if (needed_flags & CONTEXT_I386_INTEGER)
        {
            context->Eax = wow_frame->Eax;
            context->Ebx = wow_frame->Ebx;
            context->Ecx = wow_frame->Ecx;
            context->Edx = wow_frame->Edx;
            context->Esi = wow_frame->Esi;
            context->Edi = wow_frame->Edi;
            context->ContextFlags |= CONTEXT_I386_INTEGER;
        }
        if (needed_flags & CONTEXT_I386_CONTROL)
        {
            context->Esp    = wow_frame->Esp;
            context->Ebp    = wow_frame->Ebp;
            context->Eip    = wow_frame->Eip;
            context->EFlags = wow_frame->EFlags;
            context->SegCs  = wow_frame->SegCs;
            context->SegSs  = wow_frame->SegSs;
            context->ContextFlags |= CONTEXT_I386_CONTROL;
        }
        if (needed_flags & CONTEXT_I386_SEGMENTS)
        {
            context->SegDs = wow_frame->SegDs;
            context->SegEs = wow_frame->SegEs;
            context->SegFs = wow_frame->SegFs;
            context->SegGs = wow_frame->SegGs;
            context->ContextFlags |= CONTEXT_I386_SEGMENTS;
        }
        if (needed_flags & CONTEXT_I386_EXTENDED_REGISTERS)
        {
            memcpy( context->ExtendedRegisters, &wow_frame->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
            context->ContextFlags |= CONTEXT_I386_EXTENDED_REGISTERS;
        }
        if (needed_flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &context->FloatSave, &wow_frame->FloatSave, sizeof(context->FloatSave) );
            context->ContextFlags |= CONTEXT_I386_FLOATING_POINT;
        }
        if (needed_flags & CONTEXT_I386_DEBUG_REGISTERS)
        {
            context->Dr0 = wow_frame->Dr0;
            context->Dr1 = wow_frame->Dr1;
            context->Dr2 = wow_frame->Dr2;
            context->Dr3 = wow_frame->Dr3;
            context->Dr6 = wow_frame->Dr6;
            context->Dr7 = wow_frame->Dr7;
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM;

        if (needed_flags & CONTEXT_INTEGER)
        {
            context->R0  = wow_frame->R0;
            context->R1  = wow_frame->R1;
            context->R2  = wow_frame->R2;
            context->R3  = wow_frame->R3;
            context->R4  = wow_frame->R4;
            context->R5  = wow_frame->R5;
            context->R6  = wow_frame->R6;
            context->R7  = wow_frame->R7;
            context->R8  = wow_frame->R8;
            context->R9  = wow_frame->R9;
            context->R10 = wow_frame->R10;
            context->R11 = wow_frame->R11;
            context->R12 = wow_frame->R12;
            context->ContextFlags |= CONTEXT_INTEGER;
        }
        if (needed_flags & CONTEXT_CONTROL)
        {
            context->Sp   = wow_frame->Sp;
            context->Lr   = wow_frame->Lr;
            context->Pc   = wow_frame->Pc;
            context->Cpsr = wow_frame->Cpsr;
            context->ContextFlags |= CONTEXT_CONTROL;
        }
        if (needed_flags & CONTEXT_FLOATING_POINT)
        {
            context->Fpscr = wow_frame->Fpscr;
            memcpy( context->D, wow_frame->D, sizeof(wow_frame->D) );
            context->ContextFlags |= CONTEXT_FLOATING_POINT;
        }
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           setup_raise_exception
 */
static void setup_raise_exception( struct thread_data *data, ucontext_t *sigcontext,
                                   EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct exc_stack_layout *stack;
    void *stack_ptr = (void *)(SP_sig(sigcontext) & ~15);
    NTSTATUS status;

    status = rec->ExceptionCode == STATUS_WINE_NATIVE_GUARD ? 0 :
             send_debug_event( data, rec, context, TRUE, TRUE );
    if (status == DBG_CONTINUE || status == DBG_EXCEPTION_HANDLED)
    {
        restore_context( context, sigcontext );
        return;
    }

    /* fix up instruction pointer in context for EXCEPTION_BREAKPOINT */
    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) context->Pc -= 4;

    if (rec->ExceptionCode == STATUS_WINE_NATIVE_GUARD && data->native_guard_stack)
    {
        ULONG_PTR bottom = (ULONG_PTR)data->native_guard_stack;
        if ((ULONG_PTR)stack_ptr >= bottom && (ULONG_PTR)stack_ptr < bottom + NATIVE_GUARD_STACK_SIZE)
            abort_thread(1); /* Do not overwrite a live nested dispatcher frame. */
        stack = (struct exc_stack_layout *)(bottom + NATIVE_GUARD_STACK_SIZE) - 1;
        TRACE( "E55 native guard dispatcher original_sp %p emergency %p\n", stack_ptr, stack );
    }
    else stack = virtual_setup_exception( data, stack_ptr, sizeof(*stack), rec );
    stack->rec = *rec;
    stack->context = *context;
    context_init_empty_xstate( &stack->context, stack->redzone );

    SP_sig(sigcontext) = (ULONG_PTR)stack;
    PC_sig(sigcontext) = (ULONG_PTR)pKiUserExceptionDispatcher;
    REGn_sig(18, sigcontext) = (ULONG_PTR)data->teb;
}


/***********************************************************************
 *           call_user_apc_dispatcher
 */
NTSTATUS call_user_apc_dispatcher( CONTEXT *context, unsigned int flags, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3,
                                   PNTAPCFUNC func, NTSTATUS status )
{
    struct thread_data *data = get_thread_data();
    struct syscall_frame *frame = get_syscall_frame( data );
    ULONG64 sp = context ? context->Sp : frame->sp;
    struct apc_stack_layout *stack;

    if (flags) FIXME( "flags %#x are not supported.\n", flags );

    sp &= ~15;
    stack = (struct apc_stack_layout *)sp - 1;
    if (context)
    {
        memmove( &stack->context, context, sizeof(stack->context) );
        NtSetContextThread( GetCurrentThread(), &stack->context );
    }
    else
    {
        stack->context.ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), &stack->context );
        stack->context.X0 = status;
    }
    stack->func      = func;
    stack->args[0]   = arg1;
    stack->args[1]   = arg2;
    stack->args[2]   = arg3;
    stack->alertable = TRUE;

    frame->sp = (ULONG64)stack;
    frame->pc = (ULONG64)pKiUserApcDispatcher;
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_raise_user_exception_dispatcher
 */
void call_raise_user_exception_dispatcher( struct thread_data *data )
{
    get_syscall_frame(data)->pc = (UINT64)pKiRaiseUserExceptionDispatcher;
}


/***********************************************************************
 *           call_user_exception_dispatcher
 */
NTSTATUS call_user_exception_dispatcher( struct thread_data *data, EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame( data );
    struct exc_stack_layout *stack;
    NTSTATUS status = NtSetContextThread( GetCurrentThread(), context );

    if (status) return status;
    stack = (struct exc_stack_layout *)(context->Sp & ~15) - 1;
#if defined(__APPLE__)
    /* The exhausted shared stack must not carry its own exception dispatcher.
     * Preserve the original context for SEH unwinding, while first-chance
     * delivery runs on the thread-owned normal-context emergency area. */
    if (data->native_guard_stack &&
        (rec->ExceptionCode == STATUS_STACK_OVERFLOW ||
         (context->Sp >= (ULONG_PTR)data->teb->DeallocationStack &&
          context->Sp < (ULONG_PTR)data->teb->Tib.StackLimit + get_host_page_size())))
        stack = (struct exc_stack_layout *)((char *)data->native_guard_stack + NATIVE_GUARD_STACK_SIZE) - 1;
#endif
    memmove( &stack->context, context, sizeof(*context) );
    memmove( &stack->rec, rec, sizeof(*rec) );
    context_init_empty_xstate( &stack->context, stack->redzone );

    frame->pc = (ULONG64)pKiUserExceptionDispatcher;
    frame->sp = (ULONG64)stack;
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_user_mode_callback
 */
extern NTSTATUS call_user_mode_callback( ULONG64 user_sp, void **ret_ptr, ULONG *ret_len,
                                         void *func, TEB *teb );
__ASM_GLOBAL_FUNC( call_user_mode_callback,
                   "stp x29, x30, [sp,#-0xd0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xd0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xd0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xc8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   "stp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   "stp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   "stp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   "stp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "stp d8,  d9,  [x29, #0x60]\n\t"
                   "stp d10, d11, [x29, #0x70]\n\t"
                   "stp d12, d13, [x29, #0x80]\n\t"
                   "stp d14, d15, [x29, #0x90]\n\t"
                   "stp x1, x2, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "mov x19, x4\n\t"              /* teb, keep system x18 untouched */
                   "mrs x1, fpcr\n\t"
                   "mrs x2, fpsr\n\t"
                   "bfi x1, x2, #0, #32\n\t"
                   "ldr x2, [x19]\n\t"            /* teb->Tib.ExceptionList */
                   "stp x1, x2, [x29, #0xb0]\n\t"

                   "ldr x7, [x19, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "sub x1, sp, #0x330\n\t"       /* sizeof(struct syscall_frame) */
                   "str x1, [x19, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "add x8, x29, #0xd0\n\t"
                   "stp x7, x8, [x1, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   "ldr w11, [x19, #0x380]\n\t"   /* thread_data->syscall_trace */
                   "cbnz x11, 1f\n\t"
                   /* switch to user stack */
#ifdef __APPLE__
                   "mov x21, x19\n\t"             /* teb */
                   "mov x19, x0\n\t"              /* user_sp */
                   "mov x20, x3\n\t"              /* func */
                   "bl " __ASM_NAME("enter_windows_x18_abi") "\n\t"
                   "mov x18, x21\n\t"
                   "mov sp, x19\n\t"
                   "br x20\n"
#else
                   "mov x18, x19\n\t"             /* teb */
                   "mov sp, x0\n\t"               /* user_sp */
                   "br x3\n"
#endif
                   "1:\tmov x20, x0\n\t"          /* user_sp */
                   "mov x21, x3\n\t"              /* func */
                   "mov sp, x1\n\t"
                   "ldr x1, [x20]\n\t"            /* args */
                   "ldp w2, w0, [x20, #8]\n\t"    /* len, id */
                   "str x0, [x29, #0xc0]\n\t"     /* id */
                   "bl " __ASM_NAME("trace_usercall") "\n\t"
#ifdef __APPLE__
                   "bl " __ASM_NAME("enter_windows_x18_abi") "\n\t"
#endif
                   "mov x18, x19\n\t"             /* teb */
                   "mov sp, x20\n\t"              /* user_sp */
                   "br x21" )


/***********************************************************************
 *           user_mode_callback_return
 */
extern void DECLSPEC_NORETURN user_mode_callback_return( void *ret_ptr, ULONG ret_len,
                                                         NTSTATUS status, TEB *teb );
__ASM_GLOBAL_FUNC( user_mode_callback_return,
                   "ldr x4, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "ldp x5, x29, [x4,#0x110]\n\t" /* prev_frame,syscall_cfa */
                   "str x5, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "sub x29, x29, #0xd0\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   __ASM_CFI(".cfi_rel_offset 29,0x00\n\t")
                   __ASM_CFI(".cfi_rel_offset 30,0x08\n\t")
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "ldp x5, x6, [x29, #0xb0]\n\t"
                   "str x6, [x3]\n\t"             /* teb->Tib.ExceptionList */
                   "msr fpcr, x5\n\t"
                   "lsr x5, x5, #32\n\t"
                   "msr fpsr, x5\n\t"
                   "ldp x5, x6, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "str x0, [x5]\n\t"             /* ret_ptr */
                   "str w1, [x6]\n\t"             /* ret_len */
                   "ldr w11, [x3, #0x380]\n\t"    /* thread_data->syscall_trace */
                   "cbz x11, 1f\n\t"
                   "ldr w3, [x29, #0xc0]\n\t"     /* id */
                   "mov x19, x2\n\t"
                   "bl " __ASM_NAME("trace_userret") "\n\t"
                   "mov x2, x19\n"                /* status */
                   "1:\tldp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_same_value 19\n\t")
                   __ASM_CFI(".cfi_same_value 20\n\t")
                   "ldp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_same_value 21\n\t")
                   __ASM_CFI(".cfi_same_value 22\n\t")
                   "ldp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_same_value 23\n\t")
                   __ASM_CFI(".cfi_same_value 24\n\t")
                   "ldp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_same_value 25\n\t")
                   __ASM_CFI(".cfi_same_value 26\n\t")
                   "ldp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_same_value 27\n\t")
                   __ASM_CFI(".cfi_same_value 28\n\t")
                   "ldp d8,  d9,  [x29, #0x60]\n\t"
                   "ldp d10, d11, [x29, #0x70]\n\t"
                   "ldp d12, d13, [x29, #0x80]\n\t"
                   "ldp d14, d15, [x29, #0x90]\n\t"
                   "mov x0, x2\n\t"               /* status */
                   "mov sp, x29\n\t"
                   "ldp x29, x30, [sp], #0xd0\n\t"
                   "ret" )


/***********************************************************************
 *           user_mode_abort_thread
 */
extern void DECLSPEC_NORETURN user_mode_abort_thread( NTSTATUS status, struct syscall_frame *frame );
__ASM_GLOBAL_FUNC( user_mode_abort_thread,
                   "ldr x1, [x1, #0x118]\n\t"    /* frame->syscall_cfa */
                   "sub x29, x1, #0xc0\n\t"
                   /* switch to kernel stack */
                   "mov sp, x29\n\t"
                   __ASM_CFI(".cfi_def_cfa 29,0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19,-0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20,-0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21,-0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22,-0x98\n\t")
                   __ASM_CFI(".cfi_offset 23,-0x90\n\t")
                   __ASM_CFI(".cfi_offset 24,-0x88\n\t")
                   __ASM_CFI(".cfi_offset 25,-0x80\n\t")
                   __ASM_CFI(".cfi_offset 26,-0x78\n\t")
                   __ASM_CFI(".cfi_offset 27,-0x70\n\t")
                   __ASM_CFI(".cfi_offset 28,-0x68\n\t")
                   "bl " __ASM_NAME("abort_thread") )


/***********************************************************************
 *           KeUserModeCallback
 */
NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    struct thread_data *data = get_thread_data();
    struct syscall_frame *frame = get_syscall_frame( data );
    ULONG64 sp = (frame->sp - offsetof( struct callback_stack_layout, args_data[len] ) - 16) & ~15;
    struct callback_stack_layout *stack = (struct callback_stack_layout *)sp;

    if ((char *)get_kernel_stack( data ) + min_kernel_stack > (char *)&frame) return STATUS_STACK_OVERFLOW;

    stack->args = stack->args_data;
    stack->len  = len;
    stack->id   = id;
    stack->lr   = frame->lr;
    stack->sp   = frame->sp;
    stack->pc   = frame->pc;
    memcpy( stack->args_data, args, len );
    return call_user_mode_callback( sp, ret_ptr, ret_len, pKiUserCallbackDispatcher, data->teb );
}


/***********************************************************************
 *           NtCallbackReturn  (NTDLL.@)
 */
NTSTATUS WINAPI NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status )
{
    struct thread_data *data = get_thread_data();
    struct syscall_frame *frame = get_syscall_frame( data );

    if (!frame->prev_frame) return STATUS_NO_CALLBACK_ACTIVE;
    user_mode_callback_return( ret_ptr, ret_len, status, data->teb );
}


/***********************************************************************
 *           handle_syscall_fault
 *
 * Handle a page fault happening during a system call.
 */
static BOOL handle_syscall_fault( struct thread_data *data, ucontext_t *context, EXCEPTION_RECORD *rec )
{
    struct syscall_frame *frame;
    DWORD i;

    if (!is_inside_syscall( data, SP_sig(context) )) return FALSE;

    TRACE( "code=%x flags=%x addr=%p pc=%p\n",
           rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress, (void *)PC_sig(context) );
    for (i = 0; i < rec->NumberParameters; i++)
        TRACE( " info[%d]=%016lx\n", i, rec->ExceptionInformation[i] );

    TRACE("  x0=%016lx  x1=%016lx  x2=%016lx  x3=%016lx\n",
          (DWORD64)REGn_sig(0, context), (DWORD64)REGn_sig(1, context),
          (DWORD64)REGn_sig(2, context), (DWORD64)REGn_sig(3, context) );
    TRACE("  x4=%016lx  x5=%016lx  x6=%016lx  x7=%016lx\n",
          (DWORD64)REGn_sig(4, context), (DWORD64)REGn_sig(5, context),
          (DWORD64)REGn_sig(6, context), (DWORD64)REGn_sig(7, context) );
    TRACE("  x8=%016lx  x9=%016lx x10=%016lx x11=%016lx\n",
          (DWORD64)REGn_sig(8, context), (DWORD64)REGn_sig(9, context),
          (DWORD64)REGn_sig(10, context), (DWORD64)REGn_sig(11, context) );
    TRACE(" x12=%016lx x13=%016lx x14=%016lx x15=%016lx\n",
          (DWORD64)REGn_sig(12, context), (DWORD64)REGn_sig(13, context),
          (DWORD64)REGn_sig(14, context), (DWORD64)REGn_sig(15, context) );
    TRACE(" x16=%016lx x17=%016lx x18=%016lx x19=%016lx\n",
          (DWORD64)REGn_sig(16, context), (DWORD64)REGn_sig(17, context),
          (DWORD64)REGn_sig(18, context), (DWORD64)REGn_sig(19, context) );
    TRACE(" x20=%016lx x21=%016lx x22=%016lx x23=%016lx\n",
          (DWORD64)REGn_sig(20, context), (DWORD64)REGn_sig(21, context),
          (DWORD64)REGn_sig(22, context), (DWORD64)REGn_sig(23, context) );
    TRACE(" x24=%016lx x25=%016lx x26=%016lx x27=%016lx\n",
          (DWORD64)REGn_sig(24, context), (DWORD64)REGn_sig(25, context),
          (DWORD64)REGn_sig(26, context), (DWORD64)REGn_sig(27, context) );
    TRACE(" x28=%016lx  fp=%016lx  lr=%016lx  sp=%016lx\n",
          (DWORD64)REGn_sig(28, context), (DWORD64)FP_sig(context),
          (DWORD64)LR_sig(context), (DWORD64)SP_sig(context) );

    if (data->jmp_buf)
    {
        data->jmp_status = rec->ExceptionCode;
        unwind_wow64_unixlib_call_context( data->jmp_unixlib_context );
        TRACE( "returning to handler\n" );
        REGn_sig(0, context) = (ULONG_PTR)data->jmp_buf;
        REGn_sig(1, context) = 1;
        PC_sig(context)      = (ULONG_PTR)longjmp;
        data->jmp_buf = NULL;
        return TRUE;
    }
    if ((frame = get_syscall_frame( data )))
    {
        /* A fault escaping a tagged Unixlib call bypasses its C epilogue.
         * Drop the native snapshot context before returning to user mode; a
         * fault handled by an inner checked-copy jump buffer does not reach
         * this branch and keeps the enclosing context intact. */
        reset_wow64_unixlib_call_context();
        TRACE( "returning to user mode ip=%p ret=%08x\n", (void *)frame->pc, rec->ExceptionCode );
        REGn_sig(0, context)  = rec->ExceptionCode;
#ifndef __APPLE__
        REGn_sig(18, context) = (ULONG_PTR)data->teb;
#endif
        SP_sig(context)       = (ULONG_PTR)frame;
        PC_sig(context)       = (ULONG_PTR)__wine_syscall_dispatcher_return;
        return TRUE;
    }
    return FALSE;
}

#if defined(__APPLE__) && defined(__aarch64__)

static BOOL get_arm64_signal_reg( ucontext_t *context, unsigned int reg, ULONG_PTR *value )
{
    switch (reg)
    {
    case 0 ... 28:
        *value = REGn_sig( reg, context );
        return TRUE;
    case 29:
        *value = FP_sig( context );
        return TRUE;
    case 30:
        *value = LR_sig( context );
        return TRUE;
    case 31:
        *value = SP_sig( context );
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL set_arm64_signal_reg( ucontext_t *context, unsigned int reg, ULONG_PTR value )
{
    switch (reg)
    {
    case 0 ... 28:
        REGn_sig( reg, context ) = value;
        return TRUE;
    case 29:
        FP_sig( context ) = value;
        return TRUE;
    case 30:
        LR_sig( context ) = value;
        return TRUE;
    case 31:
        SP_sig( context ) = value;
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL get_arm64_signal_q( const ucontext_t *context, unsigned int reg, ULONG64 value[2] )
{
    __uint128_t q;

    if (reg >= 32) return FALSE;
    q = context->uc_mcontext->__ns.__v[reg];
    value[0] = (ULONG64)q;
    value[1] = (ULONG64)(q >> 64);
    return TRUE;
}

static BOOL set_arm64_signal_q( ucontext_t *context, unsigned int reg, const ULONG64 value[2] )
{
    __uint128_t q;

    if (reg >= 32) return FALSE;
    q = (__uint128_t)value[0] | ((__uint128_t)value[1] << 64);
    context->uc_mcontext->__ns.__v[reg] = q;
    return TRUE;
}

static BOOL get_arm64_signal_d( const ucontext_t *context, unsigned int reg, ULONG64 *value )
{
    if (!value || reg >= 32) return FALSE;
    *value = (ULONG64)context->uc_mcontext->__ns.__v[reg];
    return TRUE;
}

static BOOL set_arm64_signal_d( ucontext_t *context, unsigned int reg, ULONG64 value )
{
    if (reg >= 32) return FALSE;
    context->uc_mcontext->__ns.__v[reg] = (__uint128_t)value;
    return TRUE;
}

/* macOS may lose the Windows x18 value on an exceptional return after custom
 * x18 was enabled.  The TPIDR custom-mode bit is not a reliable discriminator:
 * observed failures have left it either clear or set while saved x18 was zero.
 * Recover only an authenticated ARM64EC or Wine syscall-entry TEB access;
 * remove this bridge when Darwin preserves custom x18 across every kernel
 * return path supported by the runtime. */
extern void __wine_syscall_dispatcher(void);

#define SYSCALL_DISPATCHER_FRAME_X18_OFFSET 4
#define SYSCALL_DISPATCHER_TRACE_X18_OFFSET 52

static BOOL fetch_lost_custom_x18_instr( ULONG_PTR pc, ULONG *instr )
{
    if (pc == (ULONG_PTR)__wine_syscall_dispatcher + SYSCALL_DISPATCHER_FRAME_X18_OFFSET ||
        pc == (ULONG_PTR)__wine_syscall_dispatcher + SYSCALL_DISPATCHER_TRACE_X18_OFFSET)
    {
        *instr = *(const ULONG *)pc;
        return TRUE;
    }
    return virtual_arm64ec_fetch_low_guest_instr( (const void *)pc, instr );
}

static BOOL recover_lost_custom_x18_fault( struct thread_data *data,
                                           ucontext_t *sigcontext,
                                           siginfo_t *siginfo )
{
    struct arm64ec_low_guest_access access;
    DWORD64 esr = get_fault_esr( sigcontext );
    ULONG_PTR pc = PC_sig( sigcontext );
    ULONG_PTR lost_x18 = REGn_sig( 18, sigcontext );
    ULONG_PTR base, offset_register = 0, producer_offset_register = 0;
    ULONG instr, producer_instr;
    unsigned int rn, rm, producer_rm;
    BOOL derived = FALSE;

    if (!data || !data->teb || !siginfo || !is_arm64ec() ||
        is_inside_syscall( data, SP_sig( sigcontext )) ||
        !arm64ec_low_guest_is_translation_fault( esr ) ||
        !fetch_lost_custom_x18_instr( pc, &instr ))
        return FALSE;
    rn = arm64ec_low_guest_base_register( instr );
    if (arm64ec_low_guest_offset_register( instr, &rm ) && rm != 31)
    {
        if (rm == 18 || !get_arm64_signal_reg( sigcontext, rm, &offset_register ))
            return FALSE;
    }
    if (arm64ec_decode_lost_x18_access( instr, lost_x18, offset_register,
                                        (ULONG_PTR)siginfo->si_addr,
                                        ESR_ELx_ISS_DABT_WNR(esr),
                                        WINE_LOW_VA_SHADOW_SIZE, &access ))
        goto recover;

    /* A compiler may first derive an indexed TEB address in a temporary and
     * fault on the following memory instruction.  Authenticate the complete
     * two-instruction dependency, then replay only the side-effect-free ADD. */
    if (pc < sizeof(ULONG) || rn == 18 || rn == 31 ||
        !virtual_arm64ec_fetch_low_guest_instr( (const void *)(pc - sizeof(ULONG)),
                                                &producer_instr ) ||
        !get_arm64_signal_reg( sigcontext, rn, &base ))
        return FALSE;
    producer_rm = (producer_instr >> 16) & 0x1f;
    if (producer_rm != 31 &&
        !get_arm64_signal_reg( sigcontext, producer_rm, &producer_offset_register ))
        return FALSE;
    if (!arm64ec_decode_lost_x18_derived_access(
            producer_instr, instr, lost_x18, producer_offset_register,
            base, offset_register, (ULONG_PTR)siginfo->si_addr,
            ESR_ELx_ISS_DABT_WNR(esr), WINE_LOW_VA_SHADOW_SIZE, &access ))
        return FALSE;
    derived = TRUE;

recover:
    REGn_sig( 18, sigcontext ) = (ULONG_PTR)data->teb;
    if (derived) PC_sig( sigcontext ) = pc - sizeof(ULONG);
    return TRUE;
}

static BOOL handle_arm64ec_low_guest_access( struct thread_data *data, ucontext_t *sigcontext,
                                             siginfo_t *siginfo, DWORD64 esr,
                                             EXCEPTION_RECORD *rec, BOOL *raise_exception )
{
    struct arm64ec_low_guest_access access;
    struct arm64ec_low_guest_value value = {{0}};
    ULONG_PTR pc = PC_sig( sigcontext );
    ULONG_PTR extra_status = 0;
    NTSTATUS status;
    ULONG instr;
    ULONG_PTR base, offset_register = 0;
    unsigned int rn, rm;

    *raise_exception = FALSE;
    if (!data || !siginfo || !is_arm64ec() ||
        is_inside_syscall( data, SP_sig( sigcontext )) ||
        (!arm64ec_low_guest_is_translation_fault( esr ) &&
         !((ULONG_PTR)siginfo->si_addr >= WINE_LOW_VA_SHADOW_SIZE &&
           (ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW || ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_CUR) &&
           !(esr & ((1ull << 10) | (1ull << 7))) && (ESR_ELx_ISS_DFSC(esr) & ~3u) == 0x0c)) ||
        !virtual_arm64ec_fetch_low_guest_instr( (const void *)pc, &instr ))
        return FALSE;

    rn = arm64ec_low_guest_base_register( instr );
    if (!get_arm64_signal_reg( sigcontext, rn, &base )) return FALSE;
    if (arm64ec_low_guest_offset_register( instr, &rm ) && rm != 31 &&
        !get_arm64_signal_reg( sigcontext, rm, &offset_register ))
        return FALSE;
    if (!arm64ec_decode_low_guest_access( instr, base, offset_register,
                                          (ULONG_PTR)siginfo->si_addr,
                                          ESR_ELx_ISS_DABT_WNR(esr),
                                          (ULONG_PTR)siginfo->si_addr < WINE_LOW_VA_SHADOW_SIZE ?
                                              WINE_LOW_VA_SHADOW_SIZE : UINT64_MAX, &access ))
        return FALSE;

    if (access.write)
    {
        if (access.simd_scalar_size == 16)
        {
            if (!get_arm64_signal_q( sigcontext, access.rt, &value.word[0] )) return FALSE;
        }
        else if (access.simd_scalar_size == 8)
        {
            if (!get_arm64_signal_d( sigcontext, access.rt, &value.word[0] )) return FALSE;
        }
        else if (access.pair_element_size == 16)
        {
            if (!get_arm64_signal_q( sigcontext, access.rt, &value.word[0] ) ||
                !get_arm64_signal_q( sigcontext, access.rt2, &value.word[2] ))
                return FALSE;
        }
        else if (access.pair_element_size)
        {
            ULONG_PTR reg_value;

            if (access.rt != 31)
            {
                if (!get_arm64_signal_reg( sigcontext, access.rt, &reg_value )) return FALSE;
                value.word[0] = reg_value;
            }
            if (access.rt2 != 31)
            {
                if (!get_arm64_signal_reg( sigcontext, access.rt2, &reg_value )) return FALSE;
                value.word[1] = reg_value;
            }
        }
        else if (access.rt != 31)
        {
            ULONG_PTR reg_value;

            if (!get_arm64_signal_reg( sigcontext, access.rt, &reg_value )) return FALSE;
            value.word[0] = reg_value;
        }
        status = virtual_arm64ec_low_guest_access( data, access.address, &value,
                                                   access.size, access.pair_element_size,
                                                   TRUE, &extra_status );
    }
    else
    {
        status = virtual_arm64ec_low_guest_access( data, access.address, &value,
                                                   access.size, access.pair_element_size,
                                                   FALSE, &extra_status );
        if (!status && access.simd_scalar_size == 16)
        {
            if (!set_arm64_signal_q( sigcontext, access.rt, &value.word[0] )) return FALSE;
        }
        else if (!status && access.simd_scalar_size == 8)
        {
            if (!set_arm64_signal_d( sigcontext, access.rt, value.word[0] )) return FALSE;
        }
        else if (!status && access.pair_element_size == 16)
        {
            if (!set_arm64_signal_q( sigcontext, access.rt, &value.word[0] ) ||
                !set_arm64_signal_q( sigcontext, access.rt2, &value.word[2] ))
                return FALSE;
        }
        else if (!status && access.pair_element_size)
        {
            if (access.rt != 31 &&
                !set_arm64_signal_reg( sigcontext, access.rt, value.word[0] ))
                return FALSE;
            if (access.rt2 != 31 &&
                !set_arm64_signal_reg( sigcontext, access.rt2, value.word[1] ))
                return FALSE;
        }
        else if (!status && access.rt != 31)
        {
            if (access.sign_extend_size)
            {
                uint64_t extended;

                if (!arm64ec_low_guest_extend_signed_load( value.word[0], access.size,
                                                            access.sign_extend_size,
                                                            &extended ))
                    return FALSE;
                value.word[0] = extended;
            }
            else if (access.load_32) value.word[0] = (ULONG)value.word[0];
            if (!set_arm64_signal_reg( sigcontext, access.rt, value.word[0] )) return FALSE;
        }
    }
    if (status == STATUS_WINE_NATIVE_GUARD)
    {
        if (data->native_guard.size) return FALSE;
        data->native_guard_limit = (ULONG_PTR)data->teb->Tib.StackLimit;
        data->native_guard_base = (ULONG_PTR)data->teb->Tib.StackBase;
        data->native_guard.pc = pc;
        data->native_guard.address = access.address;
        data->native_guard.allocation_id = extra_status;
        data->native_guard.size = access.size;
        data->native_guard.write = access.write;
        rec->ExceptionCode = status;
        rec->NumberParameters = 0;
        *raise_exception = TRUE;
        return TRUE;
    }
    if (status)
    {
        if (status != STATUS_GUARD_PAGE_VIOLATION &&
            status != STATUS_IN_PAGE_ERROR)
            return FALSE;
        rec->ExceptionCode = status;
        rec->ExceptionInformation[0] = access.write ? EXCEPTION_WRITE_FAULT :
                                                      EXCEPTION_READ_FAULT;
        rec->ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
        rec->NumberParameters = 2;
        if (status == STATUS_IN_PAGE_ERROR && extra_status)
        {
            rec->ExceptionInformation[2] = extra_status;
            rec->NumberParameters = 3;
        }
        *raise_exception = TRUE;
        return TRUE;
    }
    if (access.writeback_valid &&
        !set_arm64_signal_reg( sigcontext, access.rn, access.writeback ))
        return FALSE;
    PC_sig( sigcontext ) = pc + 4;
    return TRUE;
}

#endif


/**********************************************************************
 *		segv_handler
 *
 * Handler for SIGSEGV and related errors.
 */
static void segv_handler( int signal, siginfo_t *siginfo, void *_sigcontext )
{
    ucontext_t *sigcontext = _sigcontext;
    struct thread_data *data = get_thread_data();
    CONTEXT context;
    EXCEPTION_RECORD rec = { .ExceptionAddress = (void *)PC_sig(sigcontext) };
    DWORD64 esr = get_fault_esr( sigcontext );

    switch (ESR_ELx_EC(esr))
    {
    case ESR_ELx_EC_IABT_LOW:
    case ESR_ELx_EC_IABT_CUR:
    case ESR_ELx_EC_PC_ALIGN:
        rec.ExceptionInformation[0] = EXCEPTION_EXECUTE_FAULT;
        break;
    case ESR_ELx_EC_DABT_LOW:
    case ESR_ELx_EC_DABT_CUR:
        if (ESR_ELx_ISS_DFSC(esr) == ESR_ELx_ISS_DFSC_ALIGN_FAULT)
        {
            rec.ExceptionCode = EXCEPTION_DATATYPE_MISALIGNMENT;
            save_context( &context, sigcontext );
            setup_raise_exception( data, sigcontext, &rec, &context );
            return;
        }

        if (ESR_ELx_ISS_DABT_WNR(esr))
            rec.ExceptionInformation[0] = EXCEPTION_WRITE_FAULT;
        else
            rec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;
#if defined(__APPLE__) && defined(__aarch64__)
        {
            BOOL raise_exception;

            if (handle_arm64ec_low_guest_access( data, sigcontext, siginfo, esr,
                                                 &rec, &raise_exception ))
            {
                if (raise_exception)
                {
                    save_context( &context, sigcontext );
                    setup_raise_exception( data, sigcontext, &rec, &context );
                }
                return;
            }
        }
#endif
        break;
    default:
        rec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;
        break;
    }
    rec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
    rec.NumberParameters = 2;

    if (!virtual_handle_fault( data, &rec, (void *)SP_sig(sigcontext) )) return;
    if (handle_syscall_fault( data, sigcontext, &rec )) return;

    save_context( &context, sigcontext );
    setup_raise_exception( data, sigcontext, &rec, &context );
}


/**********************************************************************
 *		ill_handler
 *
 * Handler for SIGILL.
 */
static void ill_handler( int signal, siginfo_t *siginfo, void *_sigcontext )
{
    ucontext_t *sigcontext = _sigcontext;
    struct thread_data *data = get_thread_data();
    CONTEXT context;
    EXCEPTION_RECORD rec = { .ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION,
                             .ExceptionAddress = (void *)PC_sig(sigcontext) };

    if (!(PSTATE_sig( sigcontext ) & 0x10) && /* AArch64 (not WoW) */
        !(PC_sig( sigcontext ) & 3))
    {
        ULONG instr = *(ULONG *)PC_sig( sigcontext );
        /* emulate mrs xN, CurrentEL */
        if ((instr & ~0x1f) == 0xd5384240) {
            ULONG reg = instr & 0x1f;
            /* ignore writes to xzr */
            if (reg != 31) REGn_sig(reg, sigcontext) = 0;
            PC_sig(sigcontext) += 4;
            return;
        }
    }

    if (handle_syscall_fault( data, sigcontext, &rec )) return;

    save_context( &context, sigcontext );
    setup_raise_exception( data, sigcontext, &rec, &context );
}


/**********************************************************************
 *		trap_handler
 *
 * Handler for SIGTRAP.
 */
static void trap_handler( int signal, siginfo_t *siginfo, void *_sigcontext )
{
    ucontext_t *sigcontext = _sigcontext;
    struct thread_data *data = get_thread_data();
    CONTEXT context;
    EXCEPTION_RECORD rec = { .ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION,
                             .ExceptionAddress = (void *)PC_sig(sigcontext) };
    DWORD64 esr = 0;

    save_context( &context, sigcontext );

#ifdef linux
    /* Only SIGSEGV/SIGBUS expose ESR, synthesize it instead. */
    switch (siginfo->si_code)
    {
    case TRAP_TRACE:
        esr = make_esr( ESR_ELx_EC_SOFTSTP_CUR, 0 );
        break;
    case TRAP_BRKPT:
        if (!(PSTATE_sig( sigcontext ) & 0x10) && /* AArch64 (not WoW) */
            !(PC_sig( sigcontext ) & 3))
            esr = make_esr( ESR_ELx_EC_BRK64, *(ULONG *)PC_sig( sigcontext ) >> 5 );
        break;
    }
#else
    esr = get_fault_esr( sigcontext );
#endif

    switch (ESR_ELx_EC(esr))
    {
    case ESR_ELx_EC_SOFTSTP_LOW:
    case ESR_ELx_EC_SOFTSTP_CUR:
        rec.ExceptionCode = EXCEPTION_SINGLE_STEP;
        break;
    case ESR_ELx_EC_BRK64: /* bkpt */
        switch (ESR_ELx_ISS_BRK_COMMENT(esr))
        {
        case 0xf000:
            context.Pc += 4;  /* skip the brk instruction */
            rec.ExceptionCode = EXCEPTION_BREAKPOINT;
            rec.NumberParameters = 1;
            break;
        case 0xf001:
            rec.ExceptionCode = STATUS_ASSERTION_FAILURE;
            break;
        case 0xf003:
            rec.ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
            rec.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
            rec.NumberParameters = 1;
            rec.ExceptionInformation[0] = context.X[0];
            NtRaiseException( &rec, &context, FALSE );
            break;
        case 0xf004:
            rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
            break;
        }
        break;
    }

    setup_raise_exception( data, sigcontext, &rec, &context );
}

/**********************************************************************
 *		fpe_handler
 *
 * Handler for SIGFPE.
 */
static void fpe_handler( int signal, siginfo_t *siginfo, void *_sigcontext )
{
    ucontext_t *sigcontext = _sigcontext;
    struct thread_data *data = get_thread_data();
    CONTEXT context;
    EXCEPTION_RECORD rec = { .ExceptionAddress = (void *)PC_sig(sigcontext) };

    switch (siginfo->si_code & 0xffff )
    {
#ifdef FPE_FLTSUB
    case FPE_FLTSUB:
        rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
        break;
#endif
#ifdef FPE_INTDIV
    case FPE_INTDIV:
        rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_INTOVF
    case FPE_INTOVF:
        rec.ExceptionCode = EXCEPTION_INT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTDIV
    case FPE_FLTDIV:
        rec.ExceptionCode = EXCEPTION_FLT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_FLTOVF
    case FPE_FLTOVF:
        rec.ExceptionCode = EXCEPTION_FLT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTUND
    case FPE_FLTUND:
        rec.ExceptionCode = EXCEPTION_FLT_UNDERFLOW;
        break;
#endif
#ifdef FPE_FLTRES
    case FPE_FLTRES:
        rec.ExceptionCode = EXCEPTION_FLT_INEXACT_RESULT;
        break;
#endif
#ifdef FPE_FLTINV
    case FPE_FLTINV:
#endif
    default:
        rec.ExceptionCode = EXCEPTION_FLT_INVALID_OPERATION;
        break;
    }
    save_context( &context, sigcontext );
    setup_raise_exception( data, sigcontext, &rec, &context );
}


/**********************************************************************
 *		int_handler
 *
 * Handler for SIGINT.
 */
static void int_handler( int signal, siginfo_t *siginfo, void *_sigcontext )
{
    HANDLE handle;

    if (!p__wine_ctrl_routine) return;
    if (!NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
                           p__wine_ctrl_routine, 0 /* CTRL_C_EVENT */, 0, 0, 0, 0, NULL ))
        NtClose( handle );
}


/**********************************************************************
 *		abrt_handler
 *
 * Handler for SIGABRT.
 */
static void abrt_handler( int signal, siginfo_t *siginfo, void *_sigcontext )
{
    ucontext_t *sigcontext = _sigcontext;
    struct thread_data *data = get_thread_data();
    CONTEXT context;
    EXCEPTION_RECORD rec = { .ExceptionCode = EXCEPTION_WINE_ASSERTION,
                             .ExceptionFlags = EXCEPTION_NONCONTINUABLE,
                             .ExceptionAddress = (void *)PC_sig(sigcontext) };

    save_context( &context, sigcontext );
    setup_raise_exception( data, sigcontext, &rec, &context );
}


/**********************************************************************
 *		quit_handler
 *
 * Handler for SIGQUIT.
 */
static void quit_handler( int signal, siginfo_t *siginfo, void *_sigcontext )
{
    ucontext_t *sigcontext = _sigcontext;
    struct thread_data *data = get_thread_data();

    if (is_inside_syscall( data, SP_sig(sigcontext) )) abort_thread(0);
    user_mode_abort_thread( 0, get_syscall_frame( data ));
}


/**********************************************************************
 *		usr1_handler
 *
 * Handler for SIGUSR1, used to signal a thread that it got suspended.
 */
static void usr1_handler( int signal, siginfo_t *siginfo, void *_sigcontext )
{
    ucontext_t *sigcontext = _sigcontext;
    struct thread_data *data = get_thread_data();
    CHPE_V2_CPU_AREA_INFO *chpe;
    CONTEXT context;

    if (!data->teb)
    {
        server_select( NULL, 0, SELECT_INTERRUPTIBLE, 0, NULL, NULL );
    }
    else if ((chpe = data->teb->ChpeV2CpuAreaInfo) && chpe->SuspendDoorbell &&
             (chpe->InSimulation || chpe->InSyscallCallback))
    {
        NTSTATUS status = server_select( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_COOPERATIVE_SUSPEND,
                                         0, NULL, NULL );
        if (status == STATUS_THREAD_WAS_SUSPENDED)
        {
            *chpe->SuspendDoorbell = -1;
            arm64_thread_data( data )->suspend_pending = TRUE;
        }
    }
    else if (is_inside_syscall( data, SP_sig(sigcontext) ))
    {
        context.ContextFlags = CONTEXT_FULL | CONTEXT_EXCEPTION_REQUEST;
        NtGetContextThread( GetCurrentThread(), &context );
        wait_suspend( &context );
        NtSetContextThread( GetCurrentThread(), &context );
    }
    else
    {
        save_context( &context, sigcontext );
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING;
        wait_suspend( &context );
        /* This ucontext was captured directly from live AArch64 execution.
         * Provider-owned x64 execution and syscall callbacks are handled by
         * the cooperative branch above, while an explicit x64 context return
         * is published through RESTORE_FLAGS_EMULATION and consumed by
         * usr2_handler.  A non-EC live PC can therefore be Wine's native
         * Mach-O dispatcher; the EC bitmap alone is not guest provenance. */
        TRACE_(arm64ec_susp)(
            "sigusr1 native route pc %p sp %p simulation %u callback %u "
            "doorbell %p value %#x pending %u\n",
            (void *)(ULONG_PTR)context.Pc, (void *)(ULONG_PTR)context.Sp,
            chpe ? *(const volatile BOOLEAN *)&chpe->InSimulation : 0,
            chpe ? *(const volatile BOOLEAN *)&chpe->InSyscallCallback : 0,
            chpe ? chpe->SuspendDoorbell : NULL,
            chpe && chpe->SuspendDoorbell ?
                *(const volatile ULONG *)chpe->SuspendDoorbell : 0,
            arm64_thread_data( data )->suspend_pending );
        restore_context( &context, sigcontext );
    }
}


/**********************************************************************
 *		usr2_handler
 *
 * Handler for SIGUSR2, used to set a thread context.
 */
static void usr2_handler( int signal, siginfo_t *siginfo, void *_sigcontext )
{
    ucontext_t *sigcontext = _sigcontext;
    struct thread_data *data = get_thread_data();
    struct syscall_frame *frame = get_syscall_frame( data );
    DWORD i;

    if (!is_inside_syscall( data, SP_sig(sigcontext) )) return;
    if (!frame) return;

    if (arm64ec_signal_return_requires_emulation_dispatch( data, frame ))
    {
        CONTEXT *user_context = (CONTEXT *)((frame->sp - sizeof(CONTEXT)) & ~15);
#if defined(__APPLE__)
        /* A valid x64 RSP may share a host page with a lower 4KB guard.
         * Do not write native dispatcher scratch below that RSP in signal
         * context. Keep the saved guest SP unchanged in the CONTEXT. */
        if (data->native_guard_stack &&
            (frame->sp < (ULONG_PTR)data->native_guard_stack ||
             frame->sp >= (ULONG_PTR)data->native_guard_stack + NATIVE_GUARD_STACK_SIZE))
            user_context = (CONTEXT *)((char *)data->native_guard_stack + NATIVE_GUARD_STACK_SIZE) - 1;
#endif

        data->teb->ChpeV2CpuAreaInfo->InSimulation = 1;
        user_context->ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), user_context );
        SP_sig(sigcontext) = (ULONG_PTR)user_context;
        PC_sig(sigcontext) = (ULONG_PTR)pKiUserEmulationDispatcher;
    }
    else
    {
        SP_sig(sigcontext) = frame->sp;
        PC_sig(sigcontext) = frame->pc;
    }
    FP_sig(sigcontext)     = frame->fp;
    LR_sig(sigcontext)     = frame->lr;
    PSTATE_sig(sigcontext) = frame->cpsr;
    for (i = 0; i <= 28; i++) REGn_sig( i, sigcontext ) = frame->x[i];

#ifdef linux
    {
        struct fpsimd_context *fp = get_fpsimd_context( sigcontext );
        if (fp)
        {
            fp->fpcr = frame->fpcr;
            fp->fpsr = frame->fpsr;
            memcpy( fp->vregs, frame->v, sizeof(fp->vregs) );
        }
    }
#elif defined(__APPLE__)
    sigcontext->uc_mcontext->__ns.__fpcr = frame->fpcr;
    sigcontext->uc_mcontext->__ns.__fpsr = frame->fpsr;
    memcpy( sigcontext->uc_mcontext->__ns.__v, frame->v, sizeof(frame->v) );
#endif
}

#ifdef __APPLE__

typedef void (*signal_handler_func)( int signal, siginfo_t *siginfo, void *sigcontext );

/* Signal handlers call Darwin APIs, so they must run in the system x18 ABI.
 * The kernel ucontext remains the authoritative saved Windows x18 value. */
static void dispatch_signal_with_system_x18( signal_handler_func handler, int signal,
                                             siginfo_t *siginfo, void *_sigcontext )
{
    ucontext_t *sigcontext = _sigcontext;
    BOOL custom = custom_x18_abi_enabled();
    BOOL resume_custom = custom;

    if (custom) set_custom_x18_abi_enabled( FALSE );
    if ((signal == SIGSEGV || signal == SIGBUS) &&
        recover_lost_custom_x18_fault( get_thread_data(), sigcontext, siginfo ))
        resume_custom = TRUE;
    else
        handler( signal, siginfo, sigcontext );

    /* A system-ABI fault may have been redirected to a Windows dispatcher.
     * The SIGUSR2 slow path likewise resumes the saved Windows frame. */
    if (!resume_custom)
    {
        struct thread_data *data = get_thread_data();
        struct syscall_frame *frame = data ? get_syscall_frame( data ) : NULL;

        resume_custom = data && REGn_sig( 18, sigcontext ) == (ULONG_PTR)data->teb &&
                        PC_sig( sigcontext ) == (ULONG_PTR)pKiUserExceptionDispatcher;
        if (!resume_custom && handler == usr2_handler)
            resume_custom = frame && SP_sig( sigcontext ) == frame->sp &&
                            PC_sig( sigcontext ) == frame->pc &&
                            REGn_sig( 18, sigcontext ) == frame->x[18];
        if (!resume_custom && handler == usr2_handler)
            resume_custom = frame &&
                            PC_sig( sigcontext ) == (ULONG_PTR)pKiUserEmulationDispatcher &&
                            REGn_sig( 18, sigcontext ) == frame->x[18];
    }

    if (resume_custom)
    {
        ULONG_PTR custom_x18 = REGn_sig( 18, sigcontext );

        set_custom_x18_abi_enabled( TRUE );
        __asm__ volatile( "mov x18, %0" :: "r" (custom_x18) );
    }
}

#define DEFINE_SYSTEM_X18_SIGNAL_WRAPPER(name) \
    static void name##_system_x18( int signal, siginfo_t *siginfo, void *sigcontext ) \
    { \
        dispatch_signal_with_system_x18( name, signal, siginfo, sigcontext ); \
    }

DEFINE_SYSTEM_X18_SIGNAL_WRAPPER( int_handler )
DEFINE_SYSTEM_X18_SIGNAL_WRAPPER( fpe_handler )
DEFINE_SYSTEM_X18_SIGNAL_WRAPPER( abrt_handler )
DEFINE_SYSTEM_X18_SIGNAL_WRAPPER( quit_handler )
DEFINE_SYSTEM_X18_SIGNAL_WRAPPER( usr1_handler )
DEFINE_SYSTEM_X18_SIGNAL_WRAPPER( usr2_handler )
DEFINE_SYSTEM_X18_SIGNAL_WRAPPER( trap_handler )
DEFINE_SYSTEM_X18_SIGNAL_WRAPPER( segv_handler )
DEFINE_SYSTEM_X18_SIGNAL_WRAPPER( ill_handler )

#endif


/**********************************************************************
 *           get_thread_ldt_entry
 */
NTSTATUS get_thread_ldt_entry( HANDLE handle, THREAD_DESCRIPTOR_INFORMATION *info, ULONG len )
{
    return STATUS_NOT_IMPLEMENTED;
}


/**********************************************************************
 *             signal_alloc_thread
 */
NTSTATUS signal_alloc_thread( TEB *teb )
{
    return STATUS_SUCCESS;
}


/**********************************************************************
 *             signal_free_thread
 */
void signal_free_thread( TEB *teb )
{
}


/**********************************************************************
 *		signal_init_process
 */
BOOL signal_init_process( TEB *teb )
{
    struct sigaction sig_act;

#ifdef __APPLE__
    if (!init_custom_x18_abi()) return FALSE;
#endif
    alloc_syscall_frame( sizeof(struct syscall_frame) );
    signal_alloc_thread( teb );

    sig_act.sa_mask = server_block_set;
    sig_act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;

    sig_act.sa_sigaction =
#ifdef __APPLE__
        int_handler_system_x18;
#else
        int_handler;
#endif
    if (sigaction( SIGINT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction =
#ifdef __APPLE__
        fpe_handler_system_x18;
#else
        fpe_handler;
#endif
    if (sigaction( SIGFPE, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction =
#ifdef __APPLE__
        abrt_handler_system_x18;
#else
        abrt_handler;
#endif
    if (sigaction( SIGABRT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction =
#ifdef __APPLE__
        quit_handler_system_x18;
#else
        quit_handler;
#endif
    if (sigaction( SIGQUIT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction =
#ifdef __APPLE__
        usr1_handler_system_x18;
#else
        usr1_handler;
#endif
    if (sigaction( SIGUSR1, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction =
#ifdef __APPLE__
        usr2_handler_system_x18;
#else
        usr2_handler;
#endif
    if (sigaction( SIGUSR2, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction =
#ifdef __APPLE__
        trap_handler_system_x18;
#else
        trap_handler;
#endif
    if (sigaction( SIGTRAP, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction =
#ifdef __APPLE__
        segv_handler_system_x18;
#else
        segv_handler;
#endif
    if (sigaction( SIGBUS, &sig_act, NULL ) == -1) goto error;
    if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction =
#ifdef __APPLE__
        ill_handler_system_x18;
#else
        ill_handler;
#endif
    if (sigaction( SIGILL, &sig_act, NULL ) == -1) goto error;
    return TRUE;

 error:
    perror("sigaction");
    exit(1);
}


/***********************************************************************
 *           syscall_dispatcher_return_slowpath
 */
void syscall_dispatcher_return_slowpath(void)
{
    raise( SIGUSR2 );
}

/***********************************************************************
 *           init_syscall_frame
 */
void init_syscall_frame( LPTHREAD_START_ROUTINE entry, void *arg, TEB *teb )
{
    struct thread_data *data = get_thread_data();
    struct syscall_frame *frame = get_syscall_frame( data );
    CONTEXT *ctx, context = { CONTEXT_ALL };
    I386_CONTEXT *i386_context;
    ARM_CONTEXT *arm_context;

    context.X0  = (DWORD64)entry;
    context.X1  = (DWORD64)arg;
    context.X18 = (DWORD64)teb;
    context.Sp  = (DWORD64)teb->Tib.StackBase;
    context.Pc  = (DWORD64)pRtlUserThreadStart;

    if ((i386_context = get_cpu_area( data, IMAGE_FILE_MACHINE_I386 )))
    {
        XMM_SAVE_AREA32 *fpu = (XMM_SAVE_AREA32 *)i386_context->ExtendedRegisters;
        i386_context->ContextFlags = CONTEXT_I386_ALL;
        i386_context->Eax = wow64_native_to_guest_addr( entry );
        i386_context->Ebx = wow64_native_to_guest_addr( arg == peb ? wow_peb : arg );
        i386_context->Esp = get_wow_teb( teb )->Tib.StackBase - 16;
        i386_context->Eip = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        i386_context->SegCs = 0x23;
        i386_context->SegDs = 0x2b;
        i386_context->SegEs = 0x2b;
        i386_context->SegFs = 0x53;
        i386_context->SegGs = 0x2b;
        i386_context->SegSs = 0x2b;
        i386_context->EFlags = 0x202;
        fpu->ControlWord = 0x27f;
        fpu->MxCsr = 0x1f80;
        fpux_to_fpu( &i386_context->FloatSave, fpu );
    }
    else if ((arm_context = get_cpu_area( data, IMAGE_FILE_MACHINE_ARMNT )))
    {
        arm_context->ContextFlags = CONTEXT_ARM_ALL;
        arm_context->R0 = (ULONG_PTR)entry;
        arm_context->R1 = (arg == peb ? (ULONG_PTR)wow_peb : (ULONG_PTR)arg);
        arm_context->Sp = get_wow_teb( teb )->Tib.StackBase;
        arm_context->Pc = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        if (arm_context->Pc & 1) arm_context->Cpsr |= 0x20; /* thumb mode */
    }

    if (data->suspend)
    {
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING | CONTEXT_EXCEPTION_ACTIVE;
        wait_suspend( &context );
    }

    ctx = (CONTEXT *)((ULONG_PTR)context.Sp & ~15) - 1;
    *ctx = context;
    ctx->ContextFlags = CONTEXT_FULL | CONTEXT_ARM64_X18;
    signal_set_full_context( ctx );

    frame->sp    = (ULONG64)ctx;
    frame->pc    = (ULONG64)pLdrInitializeThunk;
    frame->x[0]  = (ULONG64)ctx;
    frame->x[18] = (ULONG64)teb;
    syscall_frame_fixup_for_fastpath( frame );

    pthread_sigmask( SIG_UNBLOCK, &server_block_set, NULL );
}


/***********************************************************************
 *           signal_start_thread
 */
__ASM_GLOBAL_FUNC( signal_start_thread,
                   "stp x29, x30, [sp,#-0xc0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   "stp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   "stp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   "stp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   "stp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "add x5, x29, #0xc0\n\t"     /* syscall_cfa */
                   /* set syscall frame */
                   "ldr x4, [x2, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "cbnz x4, 1f\n\t"
                   "sub x4, sp, #0x330\n\t"     /* sizeof(struct syscall_frame) */
                   "str x4, [x2, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "1:\tstr wzr, [x4, #0x10c]\n\t" /* frame->restore_flags */
                   "str wzr, [x4, #0x124]\n\t"   /* frame->dispatcher_flags */
                   "stp xzr, x5, [x4, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   /* switch to kernel stack */
                   "mov sp, x4\n\t"
                   "bl " __ASM_NAME("init_syscall_frame") "\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )


/***********************************************************************
 *           __wine_syscall_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                   "hint 34\n\t" /* bti c */
                   "ldr x10, [x18, #0x378]\n\t" /* thread_data->syscall_frame */
                   "stp x18, x19, [x10, #0x90]\n\t"
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "mov x19, sp\n\t"
                   "stp x9, x19, [x10, #0xf0]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "str w8, [x10, #0x120]\n\t"
#ifdef __APPLE__
                   "ldr w9, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cmp w9, #0\n\t"
                   "cset w9, ne\n\t"
                   "lsl w9, w9, #2\n\t"
                   "str w9, [x10, #0x124]\n\t" /* frame->dispatcher_flags */
#else
                   "str wzr, [x10, #0x124]\n\t"
#endif
                   "mrs x9, FPCR\n\t"
                   "str w9, [x10, #0x128]\n\t"
                   "mrs x9, FPSR\n\t"
                   "str w9, [x10, #0x12c]\n\t"
                   "stp q0,  q1,  [x10, #0x130]\n\t"
                   "stp q2,  q3,  [x10, #0x150]\n\t"
                   "stp q4,  q5,  [x10, #0x170]\n\t"
                   "stp q6,  q7,  [x10, #0x190]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "stp q16, q17, [x10, #0x230]\n\t"
                   "stp q18, q19, [x10, #0x250]\n\t"
                   "stp q20, q21, [x10, #0x270]\n\t"
                   "stp q22, q23, [x10, #0x290]\n\t"
                   "stp q24, q25, [x10, #0x2b0]\n\t"
                   "stp q26, q27, [x10, #0x2d0]\n\t"
                   "stp q28, q29, [x10, #0x2f0]\n\t"
                   "stp q30, q31, [x10, #0x310]\n\t"
                   "mov x22, x10\n\t"
                   /* switch to kernel stack */
                   "mov sp, x10\n\t"
#ifdef __APPLE__
                   /* The ABI toggle may clobber all caller-saved registers. */
                   "stp x0,  x1,  [x22, #0x00]\n\t"
                   "stp x2,  x3,  [x22, #0x10]\n\t"
                   "stp x4,  x5,  [x22, #0x20]\n\t"
                   "stp x6,  x7,  [x22, #0x30]\n\t"
                   "stp x8,  x9,  [x22, #0x40]\n\t"
                   "stp x10, x11, [x22, #0x50]\n\t"
                   "stp x12, x13, [x22, #0x60]\n\t"
                   "stp x14, x15, [x22, #0x70]\n\t"
                   "stp x16, x17, [x22, #0x80]\n\t"
                   "bl " __ASM_NAME("enter_system_x18_abi") "\n\t"
                   "ldp x0,  x1,  [x22, #0x00]\n\t"
                   "ldp x2,  x3,  [x22, #0x10]\n\t"
                   "ldp x4,  x5,  [x22, #0x20]\n\t"
                   "ldp x6,  x7,  [x22, #0x30]\n\t"
                   "ldp x8,  x9,  [x22, #0x40]\n\t"
                   "ldp x10, x11, [x22, #0x50]\n\t"
                   "ldp x12, x13, [x22, #0x60]\n\t"
                   "ldp x14, x15, [x22, #0x70]\n\t"
                   "ldp x16, x17, [x22, #0x80]\n\t"
#endif
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x22, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   "and x20, x8, #0xfff\n\t"    /* syscall number */
                   "ubfx x21, x8, #12, #2\n\t"  /* syscall table number */
#ifdef __APPLE__
                   "ldr x16, [x22, #0x90]\n\t"  /* saved teb */
                   "ldr x16, [x16, #0x370]\n\t"  /* thread_data->syscall_table */
#else
                   "ldr x16, [x18, #0x370]\n\t" /* thread_data->syscall_table */
#endif
                   "add x21, x16, x21, lsl #5\n\t"
                   "ldr x16, [x21, #16]\n\t"    /* table->ServiceLimit */
                   "cmp x20, x16\n\t"
                   "bcs " __ASM_LOCAL_LABEL("bad_syscall") "\n\t"
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w9, [x16, x20]\n\t"
                   "subs x9, x9, #64\n\t"
                   "bls 2f\n\t"
                   "sub sp, sp, x9\n\t"
                   "tbz x9, #3, 1f\n\t"
                   "sub sp, sp, #8\n"
                   "1:\tsub x9, x9, #8\n\t"
                   "ldr x10, [x19, x9]\n\t"
                   "str x10, [sp, x9]\n\t"
                   "cbnz x9, 1b\n"
                   "2:\tldr x16, [x21]\n\t"     /* table->ServiceTable */
                   "ldr x23, [x16, x20, lsl 3]\n\t"
#ifdef __APPLE__
                   "ldr w11, [x22, #0x124]\n\t" /* frame->dispatcher_flags */
                   "tbnz w11, #2, " __ASM_LOCAL_LABEL("trace_syscall") "\n\t"
#else
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall") "\n\t"
#endif
                   "blr x23\n\t"
                   "mov sp, x22\n"
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") ":\n\t"
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "tbz x16, #16, 1f\n\t"       /* RESTORE_FLAGS_EMULATION */
                   "bl " __ASM_NAME("syscall_dispatcher_return_slowpath") "\n"
                   "1:\ttbz x16, #1, 2f\n"      /* CONTEXT_INTEGER */
                   "ldp x12, x13, [sp, #0x80]\n\t" /* frame->x[16..17] */
                   "ldp x14, x15, [sp, #0xf8]\n\t" /* frame->sp, frame->pc */
                   "cmp x12, x15\n\t"              /* frame->x16 == frame->pc? */
                   "ccmp x13, x14, #0, eq\n\t"     /* frame->x17 == frame->sp? */
                   "beq 2f\n\t"                    /* take slowpath if unequal */
                   "bl " __ASM_NAME("syscall_dispatcher_return_slowpath") "\n"
                   "2:\n\t"
#ifdef __APPLE__
                   /* Every successful dispatcher return resumes PE code. */
                   "mov x20, x0\n\t"
                   "bl " __ASM_NAME("enter_windows_x18_abi") "\n\t"
                   "ldr w16, [sp, #0x10c]\n\t"
#endif
                   "tbz x16, #1, 3f\n\t"        /* CONTEXT_INTEGER */
                   "ldp x0, x1, [sp, #0x00]\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x8, x9, [sp, #0x40]\n\t"
                   "ldp x10, x11, [sp, #0x50]\n\t"
                   "ldp x12, x13, [sp, #0x60]\n\t"
                   "ldp x14, x15, [sp, #0x70]\n\t"
                   "b 4f\n"
                   "3:\n\t"
#ifdef __APPLE__
                   "mov x0, x20\n\t"
#endif
                   "4:\n\t"
#ifdef __APPLE__
                   "ldr x18, [sp, #0x90]\n\t"
                   "ldr x19, [sp, #0x98]\n\t"
#else
                   "ldp x18, x19, [sp, #0x90]\n\t"
#endif
                   "ldp x20, x21, [sp, #0xa0]\n\t"
                   "ldp x22, x23, [sp, #0xb0]\n\t"
                   "ldp x24, x25, [sp, #0xc0]\n\t"
                   "ldp x26, x27, [sp, #0xd0]\n\t"
                   "ldp x28, x29, [sp, #0xe0]\n\t"
                   "tbz x16, #2, 1f\n\t"        /* CONTEXT_FLOATING_POINT */
                   "ldp q0,  q1,  [sp, #0x130]\n\t"
                   "ldp q2,  q3,  [sp, #0x150]\n\t"
                   "ldp q4,  q5,  [sp, #0x170]\n\t"
                   "ldp q6,  q7,  [sp, #0x190]\n\t"
                   "ldp q8,  q9,  [sp, #0x1b0]\n\t"
                   "ldp q10, q11, [sp, #0x1d0]\n\t"
                   "ldp q12, q13, [sp, #0x1f0]\n\t"
                   "ldp q14, q15, [sp, #0x210]\n\t"
                   "ldp q16, q17, [sp, #0x230]\n\t"
                   "ldp q18, q19, [sp, #0x250]\n\t"
                   "ldp q20, q21, [sp, #0x270]\n\t"
                   "ldp q22, q23, [sp, #0x290]\n\t"
                   "ldp q24, q25, [sp, #0x2b0]\n\t"
                   "ldp q26, q27, [sp, #0x2d0]\n\t"
                   "ldp q28, q29, [sp, #0x2f0]\n\t"
                   "ldp q30, q31, [sp, #0x310]\n\t"
                   "ldr w17, [sp, #0x128]\n\t"
                   "msr FPCR, x17\n\t"
                   "ldr w17, [sp, #0x12c]\n\t"
                   "msr FPSR, x17\n"
                   "1:\tldp x16, x17, [sp, #0x100]\n\t"
                   "msr NZCV, x17\n\t"
                   "ldp x30, x17, [sp, #0xf0]\n\t"
                   /* switch to user stack */
                   "mov sp, x17\n\t"
                   "ret x16\n"

                   __ASM_LOCAL_LABEL("trace_syscall") ":\n\t"
                   "stp x0, x1, [sp, #-0x40]!\n\t"
                   "stp x2, x3, [sp, #0x10]\n\t"
                   "stp x4, x5, [sp, #0x20]\n\t"
                   "stp x6, x7, [sp, #0x30]\n\t"
                   "mov x0, x8\n\t"             /* id */
                   "mov x1, sp\n\t"             /* args */
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w2, [x16, x20]\n\t"    /* len */
                   "bl " __ASM_NAME("trace_syscall") "\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x0, x1, [sp], #0x40\n\t"
                   "blr x23\n"
                   "mov sp, x22\n"

                   __ASM_LOCAL_LABEL("trace_syscall_ret") ":\n\t"
                   "mov x21, x0\n\t"            /* retval */
                   "ldr w0, [sp, #0x120]\n\t"   /* frame->syscall_id */
                   "mov x1, x21\n\t"            /* retval */
                   "bl " __ASM_NAME("trace_sysret") "\n\t"
                   "mov x0, x21\n\t"            /* retval */
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n"

                   __ASM_LOCAL_LABEL("bad_syscall") ":\n\t"
                   "mov x0, #0xc0000000\n\t"    /* STATUS_INVALID_SYSTEM_SERVICE */
                   "movk x0, #0x001c\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )

__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher_return,
#ifdef __APPLE__
                   "ldr w11, [sp, #0x124]\n\t" /* frame->dispatcher_flags */
                   "tbnz w11, #2, " __ASM_LOCAL_LABEL("trace_syscall_ret") "\n\t"
#else
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall_ret") "\n\t"
#endif
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )


/***********************************************************************
 *           __wine_unix_call_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                   "hint 34\n\t" /* bti c */
#ifdef __APPLE__
                   /* x18 is OS-owned while a nested Darwin callback is active.
                    * Preserve the arguments and recover the TEB from pthread
                    * state without interpreting system x18. */
                   "sub sp, sp, #0x50\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0x50\n\t")
                   "stp x0, x1, [sp, #0x00]\n\t"
                   "stp x2, x30, [sp, #0x10]\n\t"
                   __ASM_CFI(".cfi_offset 30, -0x38\n\t")
                   "mrs x9, NZCV\n\t"
                   "str x9, [sp, #0x20]\n\t"
                   "add x0, sp, #0x28\n\t"
                   "bl " __ASM_NAME("prepare_unix_dispatcher_entry") "\n\t"
                   "ldr x10, [sp, #0x28]\n\t" /* entry.frame */
                   "ldr x9, [sp, #0x30]\n\t"  /* entry.teb */
                   "ldr x12, [sp, #0x38]\n\t" /* entry.saved_x18 */
                   "ldr w11, [sp, #0x40]\n\t" /* entry.custom_x18 */
                   "cbz x10, " __ASM_LOCAL_LABEL("unix_call_no_frame") "\n\t"
                   "ldp x0, x1, [sp, #0x00]\n\t"
                   "ldp x2, x30, [sp, #0x10]\n\t"
                   "ldr x13, [sp, #0x20]\n\t"
                   "msr NZCV, x13\n\t"
                   "add sp, sp, #0x50\n\t"
                   __ASM_CFI(".cfi_restore 30\n\t")
                   __ASM_CFI(".cfi_def_cfa sp, 0\n\t")
#else
                   "ldr x10, [x18, #0x378]\n\t" /* thread_data->syscall_frame */
#endif
#ifdef __APPLE__
                   "cmp w11, #0\n\t"
                   "csel x12, x12, x9, ne\n\t" /* opaque custom x18 or recovered teb */
                   "stp x12, x19, [x10, #0x90]\n\t"
#else
                   "stp x18, x19, [x10, #0x90]\n\t"
#endif
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "mov x9, sp\n\t"
                   "stp x30, x9, [x10, #0xf0]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "mov x19, x10\n\t"
#ifdef __APPLE__
                   "mov w11, #3\n\t" /* UNIX_CALL | RETURN_CUSTOM_X18 */
                   "str w11, [x10, #0x124]\n\t"
#endif
                   "str wzr, [x10, #0x10c]\n\t" /* consume prior restore_flags */
                   /* switch to kernel stack */
                   "mov sp, x10\n\t"
#ifdef __APPLE__
                   "stp x0, x1, [x19, #0x00]\n\t"
                   "str x2, [x19, #0x10]\n\t"
#endif
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x19, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   "tbnz x0, #63, " __ASM_LOCAL_LABEL("unix_call_tagged") "\n\t"
                   "ldr x16, [x0, x1, lsl 3]\n\t"
                   "mov x0, x2\n\t"             /* args */
                   "blr x16\n\t"
                   "b " __ASM_LOCAL_LABEL("unix_call_done") "\n"
                   __ASM_LOCAL_LABEL("unix_call_tagged") ":\n\t"
                   "bl " __ASM_NAME("__wine_unix_call_dispatcher_tagged") "\n"
                   __ASM_LOCAL_LABEL("unix_call_done") ":\n\t"
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "cbnz w16, " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n\t"
#ifdef __APPLE__
                   /* A successful Unix call always returns to PE code. */
                   "str x0, [sp, #0x00]\n\t"
                   "bl " __ASM_NAME("enter_windows_x18_abi") "\n\t"
                   "ldr x0, [sp, #0x00]\n\t"
#endif
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
#ifdef __APPLE__
                   "ldr x18, [sp, #0x90]\n\t"
                   "ldr x19, [sp, #0x98]\n\t"
#else
                   "ldp x18, x19, [sp, #0x90]\n\t"
#endif
                   "ldp x16, x17, [sp, #0xf8]\n\t"
                   /* switch to user stack */
                   "mov sp, x16\n\t"
                   "ret x17\n"
#ifdef __APPLE__
                   __ASM_LOCAL_LABEL("unix_call_no_frame") ":\n\t"
                   __ASM_CFI(".cfi_def_cfa sp, 0x50\n\t")
                   __ASM_CFI(".cfi_offset 30, -0x38\n\t")
                   /* prepare_unix_dispatcher_entry() already left custom mode. */
                   "cbz w11, " __ASM_LOCAL_LABEL("unix_call_no_frame_system") "\n\t"
                   "bl " __ASM_NAME("enter_windows_x18_abi") "\n\t"
                   "ldr x18, [sp, #0x38]\n\t"
                   __ASM_LOCAL_LABEL("unix_call_no_frame_system") ":\n\t"
                   "ldr x30, [sp, #0x18]\n\t"
                   "add sp, sp, #0x50\n\t"
                   __ASM_CFI(".cfi_restore 30\n\t")
                   __ASM_CFI(".cfi_def_cfa sp, 0\n\t")
                   "movz w0, #0x0008\n\t"       /* STATUS_INVALID_HANDLE */
                   "movk w0, #0xc000, lsl #16\n\t"
                   "ret"
#endif
                   )

#endif  /* __aarch64__ */
