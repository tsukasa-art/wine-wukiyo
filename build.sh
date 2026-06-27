#!/bin/bash
# Canonical swingby-wine build wrapper — ALWAYS builds x86_64 (Rosetta 2).
#
# Why this exists: macOS clang defaults its target to the architecture of the
# process running it. A bare `make` from a native arm64 shell (e.g. the
# Claude Code Bash tool, proc_translated=0) produces arm64 objects and
# contaminates this x86_64 build tree (ntdll.so / win32u.so / winegstreamer.so
# etc.) -> "Undefined symbols for architecture arm64" link failures.
# 2026-06-27: this bit us for real (104 native .o went arm64, winegstreamer.so
# was deleted by a failed relink). `arch -x86_64` below forces x86_64 no matter
# which shell invokes this.
#
# Full procedure (build -> consistent mirror -> bundle):
#   Melammu/docs/wine-build-and-bundle.md
#
# Usage:
#   ./build.sh                 # clean-ish incremental build of all modules
#   ./build.sh <make targets>  # e.g. ./build.sh dlls/winegstreamer/winegstreamer.so
#
# Recovery from arm64 contamination: delete the offending .o (make only checks
# mtime, not arch, so a stale arm64 .o is treated as up-to-date), then re-run
# this script. Identify with `lipo -info <obj>`.
set -euo pipefail

cd "$(dirname "$0")/build"

# -k: dwrite_test.exe fails to link (truncf undefined) but that's test-only;
# -k lets every real module (.so / PE .dll / .exe) finish building.
exec arch -x86_64 make -k -j"$(sysctl -n hw.activecpu)" "$@"
