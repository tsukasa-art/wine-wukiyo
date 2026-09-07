#!/usr/bin/env python3
"""Verify the translated-block history hot-path and lifetime contracts."""

from pathlib import Path
import sys


def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing function {signature}")
    start = source.find("{", start + len(signature))
    if start < 0:
        raise AssertionError(f"missing body for {signature}")
    depth = 0
    for offset in range(start, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if not depth:
                return source[start : offset + 1]
    raise AssertionError(f"unterminated function {signature}")


def require_order(source: str, tokens: tuple[str, ...], description: str) -> None:
    position = -1
    for token in tokens:
        position = source.find(token, position + 1)
        if position < 0:
            raise AssertionError(f"{description} lost required token: {token}")


def verify(source: str) -> None:
    if source.count('#include "tb_history.h"') != 1:
        raise AssertionError("provider must include the history contract exactly once")

    record = function_body(source, "static void tb_history_record_execution_entry")
    if record.count("xtajit64_tb_history_record(") != 1:
        raise AssertionError("entry recorder must publish exactly one compact event")
    for forbidden in (
        "malloc(", "calloc(", "realloc(", "clock_gettime(", "uc_reg_read(",
        "TRACE", "WARN", "ERR", "pthread_mutex_",
    ):
        if forbidden in record:
            raise AssertionError(f"entry recorder contains hot-path operation {forbidden}")

    hook = function_body(source, "static void block_hook")
    if "tb_history" in hook:
        raise AssertionError("block hook must not carry production history instrumentation")

    install = function_body(source, "static uc_err install_engine_hooks")
    if "BOOL install_block_hook = provider.tb_history_enabled" in install:
        raise AssertionError("history must not install a production UC_HOOK_BLOCK callback")
    require_order(
        install,
        (
            "BOOL install_block_hook = FALSE",
            "#ifdef XTAJIT64_UNIXLIB_TEST",
            "install_block_hook = TRUE",
        ),
        "test-only block hook",
    )

    trace = function_body(source, "static void tb_history_trace_engine")
    require_order(
        trace,
        (
            "xtajit64_tb_history_summarize(",
            "xtajit64_tb_history_is_repeat_candidate( &summary )",
            "summary.execution_generation_changes",
            '"cross-generation-repeat"',
            '"same-generation-repeat"',
        ),
        "provenance-safe cycle classification",
    )

    create = function_body(source, "static uc_err create_pool_engine_locked")
    require_order(
        create,
        (
            "provider.tb_history_enabled",
            "engine->tb_history = tb_history_create()",
            "open_thread_engine( engine )",
            "free( engine->tb_history )",
        ),
        "diagnostic-only allocation",
    )

    acquire = function_body(source, "static uc_err acquire_pool_engine_locked")
    require_order(
        acquire,
        (
            "if (engine->tb_history)",
            "engine->tb_binding_id = binding->id",
        ),
        "per-binding provenance refresh",
    )
    if "tb_history_sample_counter =" in acquire:
        raise AssertionError("acquire must preserve the engine-local sampling phase")

    release = function_body(source, "static uc_err release_pool_engine_locked")
    if "tb_history_sample_counter =" in release:
        raise AssertionError("release must preserve the engine-local sampling phase")

    begin = function_body(source, "static NTSTATUS begin_simulation")
    require_order(
        begin,
        (
            "next_rip = params->context.rip",
            "if (engine->tb_history &&",
            "xtajit64_tb_history_should_sample( &engine->tb_history_sample_counter )",
            "tb_history_record_execution_entry( engine, next_rip )",
            "err = uc_emu_start( engine->uc, next_rip, UINT64_MAX, 0, 0 )",
        ),
        "low-distortion execution-entry capture",
    )

    process_init = function_body(source, "static NTSTATUS process_init")
    require_order(
        process_init,
        (
            'getenv( "WINE_XTAJIT64_TB_HISTORY" )',
            '!strcmp( tb_history_environment, "1" )',
            "tb_history_start_watchdog_locked()",
        ),
        "opt-in watchdog startup",
    )

    native_log = function_body(source, "static void tb_history_native_log")
    if "write( STDERR_FILENO" not in native_log or "wine_dbg" in native_log:
        raise AssertionError("POSIX watchdog output must bypass Wine thread state")
    for signature in (
        "static void tb_history_trace_engine",
        "static void *tb_history_watchdog_main",
    ):
        watchdog = function_body(source, signature)
        for forbidden in ("TRACE", "WARN", "ERR", "wine_dbg"):
            if forbidden in watchdog:
                raise AssertionError(
                    f"non-Wine watchdog path contains {forbidden} logging"
                )

    process_term = function_body(source, "static NTSTATUS process_term( void *args )\n")
    require_order(
        process_term,
        (
            "provider.tb_history_watchdog_started",
            "pthread_join( tb_history_watchdog, NULL )",
            "free( engine->tb_history )",
        ),
        "watchdog and history teardown",
    )


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} UNIXLIB_C", file=sys.stderr)
        return 2
    verify(Path(sys.argv[1]).read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"xtajit64 tb-history source check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
