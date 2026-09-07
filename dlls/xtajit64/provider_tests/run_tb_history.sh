#!/bin/bash
# Build and run the allocation-free translated-block history regression.

set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
compiler_line=${CC:-cc}
read -r -a compiler_words <<<"$compiler_line"
test_tmp=$(/usr/bin/mktemp -d /tmp/xtajit64-tb-history.XXXXXX)
sanitizer_flags=()

if [[ ${SANITIZE:-0} == 1 ]]; then
    sanitizer_flags=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi

cleanup()
{
    case "$test_tmp" in
        /tmp/xtajit64-tb-history.??????)
            if [[ -e "$test_tmp/tb_history" || -L "$test_tmp/tb_history" ]]; then
                /bin/rm -- "$test_tmp/tb_history"
            fi
            /bin/rmdir -- "$test_tmp"
            ;;
        *)
            echo "refusing to remove unexpected test path: $test_tmp" >&2
            ;;
    esac
}
trap cleanup EXIT HUP INT TERM

"${compiler_words[@]}" -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic \
    -Wconversion -Wsign-conversion -pthread \
    ${sanitizer_flags[@]+"${sanitizer_flags[@]}"} \
    -I"$root_dir/dlls/xtajit64" \
    "$root_dir/dlls/xtajit64/provider_tests/tb_history.c" \
    -o "$test_tmp/tb_history"

"$test_tmp/tb_history"
