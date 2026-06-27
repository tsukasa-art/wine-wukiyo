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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/build"

# -k: dwrite_test.exe fails to link (truncf undefined) but that's test-only;
# -k lets every real module (.so / PE .dll / .exe) finish building. That known
# test-only failure makes `make -k` exit non-zero on otherwise-good builds, so we
# do NOT gate on make's exit code here — we capture it and pass it through
# unchanged, preserving the old `exec make` exit semantics. The real pass/fail
# judgement happens later in the publish gate (arch / guards / codesign) against
# the bundled .app, not here.
set +e
arch -x86_64 make -k -j"$(sysctl -n hw.activecpu)" "$@"
make_rc=$?
set -e

# Provenance stamp (設計 D2 #1: 「ビルドは build.sh 経由」を publish ゲートが実検証
# できるようにする). build.sh は arch -x86_64 固定ラッパーなので、ここへ到達した
# 時点で「この build/ は wrapper 経由で swingby-wine <commit> から作られた」が確定。
# mirror.py がこのスタンプを Melammu/wine-support/ へ運び、melammu_release.py の
# run_gate が読んで built_via_wrapper と build 時 swingby commit を確定する。
# スタンプは由来の証拠であり、ビルド成否ではない（成否はゲートが .app で判定）。
swingby_commit="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
cat > "$SCRIPT_DIR/build/.build-provenance" <<EOF
built_via_wrapper=true
swingby_commit=${swingby_commit}
built_at=$(date +%Y-%m-%dT%H:%M:%S%z)
EOF

exit "$make_rc"
