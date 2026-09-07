#!/usr/bin/env python3
"""Verify that exact trap evidence stays separate from high-volume map tracing."""

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
    if source.count("WINE_DECLARE_DEBUG_CHANNEL(xtajitmap)") != 1:
        raise AssertionError("mapping diagnostics must declare one xtajitmap channel")
    if source.count("WINE_DECLARE_DEBUG_CHANNEL(xtajittrap)") != 1:
        raise AssertionError("trap diagnostics must declare one xtajittrap channel")

    mapping = function_body(source, "static void trace_mapping_diagnostic")
    if "TRACE_(xtajitmap)(" not in mapping or "xtajittrap" in mapping:
        raise AssertionError("mapping summaries must remain on xtajitmap only")

    trap = function_body(source, "static void trace_interrupt_diagnostic_locked")
    for required in (
        "TRACE_ON( xtajittrap )",
        "TRACE_(xtajittrap)(",
        "interrupt=%#llx",
        "reason=%u",
        "rip=%#llx",
        "bytes@%#llx",
        "canonical=%u",
        "mapped=%u",
        "generation=%llu/%llu",
    ):
        if required not in trap:
            raise AssertionError(f"trap evidence lost required field: {required}")
    if "xtajitmap" in trap:
        raise AssertionError("low-volume trap evidence must not enable map tracing")

    interrupt = function_body(source, "static void interrupt_hook")
    require_order(
        interrupt,
        (
            "engine->stop_reason = XTAJIT64_STOP_INVALID_INSTRUCTION",
            "engine->flight_stop_detail0 = intno",
            "uc_emu_stop( uc )",
        ),
        "interrupt provenance publication",
    )

    begin = function_body(source, "static NTSTATUS begin_simulation")
    require_order(
        begin,
        (
            "params->stop_reason = status ? XTAJIT64_STOP_INTERNAL_ERROR",
            "trace_interrupt_diagnostic_locked( engine, params->context.rip )",
            "params->stop_reason == XTAJIT64_STOP_NONE",
        ),
        "terminal trap rendering",
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
        print(f"xtajit64 trap-diagnostic source check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
