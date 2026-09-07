#!/bin/bash
# Build and run the native xtajit64 Unixlib concurrency regression.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 WINE_BUILD_DIR" >&2
    exit 2
fi

build_dir=$(cd "$1" && pwd)
makefile="$build_dir/Makefile"
if [[ ! -f "$makefile" || ! -f "$build_dir/include/config.h" ]]; then
    echo "not a configured Wine build directory: $build_dir" >&2
    exit 2
fi

source_dir=$(sed -n 's/^srcdir = //p' "$makefile" | head -n 1)
cc_line=${CC:-$(sed -n 's/^CC = //p' "$makefile" | head -n 1)}
cflags_line=$(sed -n 's/^CFLAGS = //p' "$makefile" | head -n 1)
unicorn_cflags=$(sed -n 's/^UNICORN_CFLAGS = //p' "$makefile" | head -n 1)
unicorn_libs=$(sed -n 's/^UNICORN_LIBS = //p' "$makefile" | head -n 1)
if [[ -z "$source_dir" || -z "$cc_line" || -z "$unicorn_libs" ]]; then
    echo "configured build is missing source, compiler, or Unicorn library settings" >&2
    exit 2
fi
if [[ "$source_dir" != /* ]]; then
    source_dir=$(cd "$build_dir/$source_dir" && pwd)
else
    source_dir=$(cd "$source_dir" && pwd)
fi
if [[ -n ${XTAJIT64_EXPECTED_SOURCE_DIR:-} ]]; then
    expected_source_dir=$(cd "$XTAJIT64_EXPECTED_SOURCE_DIR" && pwd)
    if [[ "$source_dir" != "$expected_source_dir" ]]; then
        echo "configured build source $source_dir does not match $expected_source_dir" >&2
        exit 2
    fi
fi
if [[ -n ${XTAJIT64_UNICORN_ROOT:-} ]]; then
    if [[ $XTAJIT64_UNICORN_ROOT != /* || ! -d $XTAJIT64_UNICORN_ROOT ||
          -L $XTAJIT64_UNICORN_ROOT ]]; then
        echo "XTAJIT64_UNICORN_ROOT must name an absolute, real directory" >&2
        exit 2
    fi
    unicorn_root=$(cd "$XTAJIT64_UNICORN_ROOT" && pwd -P)
    if [[ ! -f $unicorn_root/include/unicorn/unicorn.h ||
          ! -f $unicorn_root/lib/libunicorn.2.dylib ]]; then
        echo "XTAJIT64_UNICORN_ROOT is missing the development header or dylib" >&2
        exit 2
    fi
    unicorn_cflags="-I$unicorn_root/include"
    unicorn_libs="-L$unicorn_root/lib -lunicorn"
fi
if [[ -n ${XTAJIT64_UNICORN_INCLUDE_DIR:-} || -n ${XTAJIT64_UNICORN_LIBRARY_DIR:-} ]]; then
    if [[ -n ${XTAJIT64_UNICORN_ROOT:-} || -z ${XTAJIT64_UNICORN_INCLUDE_DIR:-} ||
          -z ${XTAJIT64_UNICORN_LIBRARY_DIR:-} || $XTAJIT64_UNICORN_INCLUDE_DIR != /* ||
          $XTAJIT64_UNICORN_LIBRARY_DIR != /* ||
          ! -d $XTAJIT64_UNICORN_INCLUDE_DIR || ! -d $XTAJIT64_UNICORN_LIBRARY_DIR ||
          -L $XTAJIT64_UNICORN_INCLUDE_DIR || -L $XTAJIT64_UNICORN_LIBRARY_DIR ]]; then
        echo "XTAJIT64_UNICORN_INCLUDE_DIR and XTAJIT64_UNICORN_LIBRARY_DIR must name separate absolute, real directories" >&2
        exit 2
    fi
    unicorn_include_dir=$(cd "$XTAJIT64_UNICORN_INCLUDE_DIR" && pwd -P)
    unicorn_library_dir=$(cd "$XTAJIT64_UNICORN_LIBRARY_DIR" && pwd -P)
    if [[ ! -f $unicorn_include_dir/unicorn/unicorn.h ||
          ! -f $unicorn_library_dir/libunicorn.2.dylib ]]; then
        echo "separate Unicorn directories are missing the development header or dylib" >&2
        exit 2
    fi
    unicorn_cflags="-I$unicorn_include_dir"
    unicorn_libs="-L$unicorn_library_dir -lunicorn"
fi

/usr/bin/python3 \
    "$source_dir/dlls/xtajit64/provider_tests/check_x64_entry_gate.py" \
    "$source_dir/dlls/xtajit64/cpu.c"

read -r -a cc_words <<<"$cc_line"
read -r -a cflag_words <<<"$cflags_line"
read -r -a unicorn_cflag_words <<<"$unicorn_cflags"
read -r -a unicorn_lib_words <<<"$unicorn_libs"
native_provider="$build_dir/dlls/xtajit64/xtajit64.so"
pe_provider="$build_dir/dlls/xtajit64/aarch64-windows/xtajit64.dll"
if [[ ! -f $native_provider || ! -f $pe_provider ]]; then
    echo "xtajit64 native or PE provider has not been built" >&2
    exit 2
fi
native_imports=$(/usr/bin/nm -u "$native_provider") || exit 1
for symbol in uc_open uc_emu_start uc_hook_add uc_mem_map_ptr \
              uc_context_alloc uc_context_save uc_context_restore uc_context_free \
              uc_emu_stop_at_instruction_boundary \
              uc_clear_instruction_boundary_stop uc_enable_shared_memory_atomics \
              uc_set_shared_memory_atomic_callback \
              uc_configure_identity_memory_fastpath \
              uc_configure_x64_boundary_guard \
              uc_update_x64_boundary_suspend_doorbell \
              uc_query_x64_boundary_stop \
              uc_switchyard_x86_64_import_transition_context \
              uc_switchyard_x86_64_export_transition_context; do
    if ! grep -Eq "(^|[[:space:]])_?${symbol}$" <<<"$native_imports"; then
        echo "production xtajit64 Unixlib is missing Unicorn symbol $symbol" >&2
        exit 1
    fi
done
if [[ $(uname -s) == Darwin ]]; then
    native_libraries=$(/usr/bin/otool -L "$native_provider") || exit 1
    if ! grep -Eq '/libunicorn\.2\.dylib([[:space:]]|$)' <<<"$native_libraries"; then
        echo "production xtajit64 Unixlib is not linked to Unicorn 2" >&2
        exit 1
    fi
fi
pe_strings=$(/usr/bin/strings "$pe_provider") || exit 1
if ! grep -Fxq '__wine_arm64ec_prepare_x64_execution' <<<"$pe_strings" ||
   ! grep -Fxq '__wine_arm64ec_get_x64_syscall_dispatcher' <<<"$pe_strings"; then
    echo "production xtajit64 PE image does not contain the Phase-A provider path" >&2
    exit 1
fi
echo "xtajit64 production native and PE provider linkage verified"
unicorn_lib_dir=
for word in "${unicorn_lib_words[@]}"; do
    if [[ "$word" == -L* ]]; then unicorn_lib_dir=${word#-L}; fi
done

if [[ -z ${MACOSX_DEPLOYMENT_TARGET:-} && $(uname -s) == Darwin ]]; then
    deployment_target=$(/usr/bin/otool -l "$build_dir/dlls/ntdll/ntdll.so" |
        awk '$1 == "minos" { print $2; exit }')
    if [[ -n $deployment_target ]]; then export MACOSX_DEPLOYMENT_TARGET=$deployment_target; fi
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/xtajit64-concurrency.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT
test_binary="$tmp_dir/unixlib_concurrency"
sanitizer_flags=()
sanitize_mode=${SANITIZE:-0}
test_asan_options=${ASAN_OPTIONS:-}
case $sanitize_mode in
0)
    ;;
1|address|address,undefined)
    sanitizer_flags=("-fsanitize=address,undefined" -fno-omit-frame-pointer)
    ;;
undefined)
    sanitizer_flags=("-fsanitize=undefined" -fno-omit-frame-pointer)
    ;;
*)
    echo "SANITIZE must be 0, 1, address, address,undefined, or undefined" >&2
    exit 2
    ;;
esac
if [[ $sanitize_mode == 1 || $sanitize_mode == address ||
      $sanitize_mode == address,undefined ]]; then
    if [[ -n $test_asan_options ]]; then test_asan_options+=:; fi
    test_asan_options+=protect_shadow_gap=0
fi
iterations=${ITERATIONS:-1}
if [[ ! $iterations =~ ^[1-9][0-9]*$ || $iterations -gt 1000 ]]; then
    echo "ITERATIONS must be an integer from 1 through 1000" >&2
    exit 2
fi

"${cc_words[@]}" \
    ${cflag_words[@]+"${cflag_words[@]}"} \
    -o "$test_binary" \
    "$source_dir/dlls/xtajit64/provider_tests/unixlib_concurrency.c" \
    -I"$build_dir/dlls/xtajit64" \
    -I"$source_dir/dlls/xtajit64" \
    -I"$build_dir/include" \
    -I"$source_dir/include" \
    -D__WINESRC__ -D_CRTIMP= -DHAVE_UNICORN -DWINE_UNIX_LIB \
    -DXTAJIT64_UNIXLIB_TEST -DXTAJIT64_TEST_EC_LEAF_FASTPATH \
    -Wall -Werror -Wdeclaration-after-statement -Wempty-body \
    -Wignored-qualifiers -Winit-self -Wpointer-arith -Wstrict-prototypes \
    -Wtype-limits -Wunused-but-set-parameter -Wvla -Wwrite-strings \
    -fno-strict-aliasing -fno-stack-protector \
    ${sanitizer_flags[@]+"${sanitizer_flags[@]}"} \
    ${unicorn_cflag_words[@]+"${unicorn_cflag_words[@]}"} \
    "$build_dir/dlls/ntdll/ntdll.so" \
    "${unicorn_lib_words[@]}"

for ((iteration = 1; iteration <= iterations; ++iteration)); do
    ASAN_OPTIONS="$test_asan_options" \
    DYLD_LIBRARY_PATH="$build_dir/dlls/ntdll${unicorn_lib_dir:+:$unicorn_lib_dir}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
        "$test_binary"
done
