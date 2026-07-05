#!/bin/bash
# Canonical swingby-wine build wrapper — ALWAYS builds x86_64 (Rosetta 2).
#
# Why this exists: macOS clang defaults its target to its own native
# architecture. A bare `make` from a native arm64 shell produces arm64 objects
# and contaminates this x86_64 build tree (ntdll.so / win32u.so /
# winegstreamer.so etc.) -> "Undefined symbols for architecture arm64" link
# failures. 2026-06-27: this bit us for real (104 native .o went arm64,
# winegstreamer.so was deleted by a failed relink).
#
# 2026-07-05: `arch -x86_64 make` is NO LONGER SUFFICIENT. On macOS 26.4
# (Darwin 25.4) the /usr/bin/cc shim re-execs the toolchain clang natively and
# the arch preference is lost — even `arch -x86_64 cc` emits arm64 objects
# (verified). The one thing that still works is an explicit compiler target,
# so we override CC on the make command line with --target. That day 196
# stale-dependency .o (incl. ntdll/unix + server = the msync binaries) silently
# recompiled as arm64 and ntdll.so/wineserver linked as arm64.
#
# Full procedure (build -> consistent mirror -> bundle):
#   Melammu/docs/wine-build-and-bundle.md
#
# Usage:
#   ./build.sh                 # clean-ish incremental build of all modules
#   ./build.sh <make targets>  # e.g. ./build.sh dlls/winegstreamer/winegstreamer.so
#
# Recovery from arm64 contamination: delete the offending .o AND any arm64
# linked .so/executable (make only checks mtime, not arch, so a stale arm64
# artifact is treated as up-to-date), then re-run this script. Identify with:
#   find build \( -name '*.o' -o -name '*.so' \) -print0 | xargs -0 file | grep 'Mach-O.*arm64'
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/build"

# configure baked CC="gcc -m64"; -m64 does not imply x86_64 when clang runs
# natively on arm64, so the explicit --target is load-bearing (see header).
X86_CC="gcc -m64 --target=x86_64-apple-macos"

# -k: dwrite_test.exe fails to link (truncf undefined) but that's test-only;
# -k lets every real module (.so / PE .dll / .exe) finish building. That known
# test-only failure makes `make -k` exit non-zero on otherwise-good builds, so we
# do NOT gate on make's exit code here — we capture it and pass it through
# unchanged. The real pass/fail judgement happens later in the publish gate
# (arch / guards / codesign) against the bundled .app, not here.
set +e
arch -x86_64 make -k -j"$(sysctl -n hw.activecpu)" CC="$X86_CC" "$@"
make_rc=$?
set -e

# Arch canary (mechanical, not vibes): if anything Mach-O linked today came out
# arm64, fail loudly no matter what make said. A silent arm64 tree wastes whole
# sessions downstream (2026-07-05 実害).
arm64_hits="$(find . \( -name '*.so' -o -name 'wineserver' -o -path './loader/wine64' \) -print0 2>/dev/null \
    | xargs -0 file 2>/dev/null | grep 'Mach-O.*arm64' || true)"
if [ -n "$arm64_hits" ]; then
    echo "!! ARM64 CONTAMINATION DETECTED (build is NOT usable):" >&2
    echo "$arm64_hits" >&2
    exit 70
fi

# Provenance stamp (設計 D2 #1: 「ビルドは build.sh 経由」を publish ゲートが実検証
# できるようにする). build.sh は x86_64 固定ラッパーなので、ここへ到達した
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
