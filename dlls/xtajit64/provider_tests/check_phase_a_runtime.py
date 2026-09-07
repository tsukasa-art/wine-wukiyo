#!/usr/bin/env python3
"""Validate the native ARM64 parent to AMD64 child provider runtime evidence."""

from pathlib import Path
import re
import sys


def one_match(text: str, pattern: str, name: str) -> re.Match[str]:
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    if len(matches) != 1:
        raise AssertionError(f"{name} count is {len(matches)}, expected 1")
    return matches[0]


def parse_number(value: str) -> int:
    return int(value, 0)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} RUNTIME_LOG", file=sys.stderr)
        return 2

    log = Path(sys.argv[1])
    text = log.read_bytes().decode("utf-8", errors="replace")

    parent = one_match(
        text,
        r'XTAJIT64_PARENT pid=(\d+) image="([^"\r\n]+)" '
        r'process_machine=(0x[0-9a-fA-F]+)',
        "ARM64 parent",
    )
    child_create = one_match(
        text,
        r'XTAJIT64_CHILD_CREATE parent_pid=(\d+) child_pid=(\d+) '
        r'requested_machine=(0x[0-9a-fA-F]+) image="([^"\r\n]+)"',
        "AMD64 child creation",
    )
    child = one_match(
        text,
        r'XTAJIT64_CHILD pid=(\d+) image="([^"\r\n]+)" '
        r'process_machine=(0x[0-9a-fA-F]+)',
        "AMD64 child",
    )
    provider = one_match(
        text,
        r'XTAJIT64_PROVIDER child_pid=(\d+) module=(\S+) '
        r'image="([^"\r\n]+)"',
        "provider load",
    )
    child_exit = one_match(
        text,
        r'XTAJIT64_CHILD_EXIT child_pid=(\d+) exit_code=(0x[0-9a-fA-F]+|\d+)',
        "AMD64 child exit",
    )
    runtime_exit = one_match(text, r'^RUNTIME_EXIT=(\d+)$', "runtime exit")

    parent_pid = parse_number(parent.group(1))
    child_pid = parse_number(child.group(1))
    if parse_number(parent.group(3)) != 0xAA64:
        raise AssertionError(f"parent ProcessMachine is {parent.group(3)}, expected 0xaa64")
    if parse_number(child_create.group(1)) != parent_pid:
        raise AssertionError("child creation parent PID does not match the parent record")
    if parse_number(child_create.group(3)) != 0x8664:
        raise AssertionError(
            f"requested child machine is {child_create.group(3)}, expected 0x8664"
        )
    created_child_pid = parse_number(child_create.group(2))
    if created_child_pid == parent_pid:
        raise AssertionError("AMD64 child reused the parent PID")
    if child_pid != created_child_pid:
        raise AssertionError("child PID does not match the child creation record")
    if parse_number(child.group(3)) != 0x8664:
        raise AssertionError(f"child ProcessMachine is {child.group(3)}, expected 0x8664")
    if parse_number(provider.group(1)) != child_pid:
        raise AssertionError("provider load PID does not match the AMD64 child")
    if parse_number(child_exit.group(1)) != child_pid:
        raise AssertionError("child exit PID does not match the AMD64 child")
    if parse_number(child_exit.group(2)) != 0:
        raise AssertionError(f"AMD64 child exit is {child_exit.group(2)}, expected 0")
    if parse_number(runtime_exit.group(1)) != 0:
        raise AssertionError(f"runtime exit is {runtime_exit.group(1)}, expected 0")

    markers = re.findall(r"SWITCHYARD_X64_OK\r?\n", text)
    if len(markers) != 1:
        raise AssertionError(f"success marker count is {len(markers)}, expected 1")

    print(
        "xtajit64 Phase-A runtime verified: "
        f"parent={parent_pid} child={child_pid} machine=0x8664 provider={provider.group(3)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError) as error:
        print(f"xtajit64 Phase-A runtime check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
