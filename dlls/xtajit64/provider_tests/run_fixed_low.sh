#!/bin/bash
# Build and optionally run the pure-AMD64 fixed-low XTAJIT64 regression.

set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo "usage: $0 WINE_BUILD_DIR [INITIALIZED_PREFIX [LOG_FILE]]" >&2
    exit 2
fi

build_dir=$(cd "$1" && pwd)
makefile="$build_dir/Makefile"
if [[ ! -f $makefile || ! -f "$build_dir/include/config.h" ]]; then
    echo "not a configured Wine build directory: $build_dir" >&2
    exit 2
fi

make_var()
{
    sed -n "s/^$1 = //p" "$makefile" | head -n 1
}

source_dir=$(make_var srcdir)
x86_cc=$(make_var x86_64_CC)
x86_cflags=$(make_var x86_64_CFLAGS)
x86_extra_cflags=$(make_var x86_64_EXTRACFLAGS)
x86_ldflags=$(make_var x86_64_LDFLAGS)
x86_target=$(make_var x86_64_TARGET)
unicorn_libs=$(make_var UNICORN_LIBS)
if [[ -z $source_dir || -z $x86_cc || -z $x86_extra_cflags ||
      -z $x86_target || $x86_target != x86_64-windows ]]; then
    echo "configured build has no usable x86_64-windows compiler path" >&2
    exit 2
fi
if [[ $source_dir != /* ]]; then
    source_dir=$(cd "$build_dir/$source_dir" && pwd)
else
    source_dir=$(cd "$source_dir" && pwd)
fi
if [[ -n ${XTAJIT64_EXPECTED_SOURCE_DIR:-} ]]; then
    expected_source_dir=$(cd "$XTAJIT64_EXPECTED_SOURCE_DIR" && pwd)
    if [[ $source_dir != "$expected_source_dir" ]]; then
        echo "configured source $source_dir does not match $expected_source_dir" >&2
        exit 2
    fi
fi

source_file="$source_dir/dlls/xtajit64/provider_tests/fixed_low.c"
source_spec="$source_dir/dlls/xtajit64/provider_tests/fixed_low.spec"
companion_source="$source_dir/dlls/xtajit64/provider_tests/fixed_low_import.c"
companion_spec="$source_dir/dlls/xtajit64/provider_tests/fixed_low_import.spec"
winegcc="$build_dir/tools/winegcc/winegcc"
winebuild="$build_dir/tools/winebuild/winebuild"
output_dir="$build_dir/dlls/xtajit64/provider_tests/x86_64-windows"
object_file="$output_dir/fixed_low.o"
companion_object="$output_dir/fixed_low_import.o"
test_exe="$output_dir/fixed_low.exe"
test_import_library="$output_dir/libfixed_low_export.a"
companion_dll="$output_dir/fixed_low_import.dll"
required_files=(
    "$source_file"
    "$source_spec"
    "$companion_source"
    "$companion_spec"
    "$winegcc"
    "$winebuild"
    "$build_dir/libs/winecrt0/x86_64-windows/libwinecrt0.a"
    "$build_dir/libs/compiler-rt/x86_64-windows/libcompiler-rt.a"
    "$build_dir/dlls/msvcrt/x86_64-windows/libmsvcrt.a"
    "$build_dir/dlls/kernel32/x86_64-windows/libkernel32.a"
    "$build_dir/dlls/ntdll/x86_64-windows/libntdll.a"
)
for file in "${required_files[@]}"; do
    if [[ ! -f $file ]]; then
        echo "missing fixed-low build dependency: $file" >&2
        exit 2
    fi
done
if [[ ! -x $winegcc || ! -x $winebuild ]]; then
    echo "configured Wine build tools are not executable: $winegcc / $winebuild" >&2
    exit 2
fi

read -r -a cc_words <<<"$x86_cc"
read -r -a cflag_words <<<"$x86_cflags"
read -r -a extra_cflag_words <<<"$x86_extra_cflags"
read -r -a ldflag_words <<<"$x86_ldflags"
if [[ ${#cc_words[@]} -eq 0 ]]; then
    echo "configured x86_64 compiler is not executable: $x86_cc" >&2
    exit 2
fi
if [[ ${cc_words[0]} == */* ]]; then
    cc_binary=${cc_words[0]}
else
    cc_binary=$(command -v -- "${cc_words[0]}" || true)
fi
if [[ -z $cc_binary || ! -x $cc_binary ]]; then
    echo "configured x86_64 compiler is not executable: $x86_cc" >&2
    exit 2
fi
winebuild_cc=$x86_cc
if [[ " $winebuild_cc " != *" -target "* &&
      " $winebuild_cc " != *" --target="* ]]; then
    winebuild_cc+=" -target $x86_target"
fi
llvm_bindir=$(cd "$(dirname "$cc_binary")" && pwd)
llvm_readobj=${XTAJIT64_LLVM_READOBJ:-"$llvm_bindir/llvm-readobj"}
if [[ ! -x $llvm_readobj ]]; then
    echo "llvm-readobj is unavailable beside the configured compiler" >&2
    exit 2
fi

mkdir -p "$output_dir"
"${cc_words[@]}" \
    ${cflag_words[@]+"${cflag_words[@]}"} \
    ${extra_cflag_words[@]+"${extra_cflag_words[@]}"} \
    -D__WINESRC__ -D_MSVCR_VER=0 \
    -I"$build_dir/include" -I"$source_dir/include" \
    -I"$source_dir/include/msvcrt" \
    -c "$source_file" -o "$object_file"

"${cc_words[@]}" \
    ${cflag_words[@]+"${cflag_words[@]}"} \
    ${extra_cflag_words[@]+"${extra_cflag_words[@]}"} \
    -D__WINESRC__ -D_MSVCR_VER=0 \
    -I"$build_dir/include" -I"$source_dir/include" \
    -I"$source_dir/include/msvcrt" \
    -c "$companion_source" -o "$companion_object"

"$winegcc" -o "$test_exe" --wine-objdir="$build_dir" \
    "--cc-cmd=$x86_cc" -b "$x86_target" -mconsole \
    -Wl,--image-base,0x400000 -Wl,/fixed \
    "$source_spec" "$object_file" \
    "$build_dir/libs/winecrt0/x86_64-windows/libwinecrt0.a" \
    "$build_dir/libs/compiler-rt/x86_64-windows/libcompiler-rt.a" \
    "$build_dir/dlls/msvcrt/x86_64-windows/libmsvcrt.a" \
    "$build_dir/dlls/kernel32/x86_64-windows/libkernel32.a" \
    "$build_dir/dlls/ntdll/x86_64-windows/libntdll.a" \
    ${ldflag_words[@]+"${ldflag_words[@]}"}

"$winebuild" -w --implib -o "$test_import_library" \
    "--cc-cmd=$winebuild_cc" --without-dlltool -b "$x86_target" \
    -F fixed_low.exe --export "$source_spec"

"$winegcc" -o "$companion_dll" --wine-objdir="$build_dir" \
    "--cc-cmd=$x86_cc" -b "$x86_target" -shared \
    "$companion_spec" "$companion_object" "$test_import_library" \
    "$build_dir/libs/winecrt0/x86_64-windows/libwinecrt0.a" \
    "$build_dir/libs/compiler-rt/x86_64-windows/libcompiler-rt.a" \
    "$build_dir/dlls/msvcrt/x86_64-windows/libmsvcrt.a" \
    "$build_dir/dlls/kernel32/x86_64-windows/libkernel32.a" \
    "$build_dir/dlls/ntdll/x86_64-windows/libntdll.a" \
    ${ldflag_words[@]+"${ldflag_words[@]}"}

header_dump=$(mktemp "${TMPDIR:-/tmp}/xtajit64-fixed-low-header.XXXXXX")
companion_dump=$(mktemp "${TMPDIR:-/tmp}/xtajit64-fixed-low-import.XXXXXX")
cleanup()
{
    rm -f -- "$header_dump" "$companion_dump"
    if [[ -n ${prefix:-} && -x "$build_dir/server/wineserver" ]]; then
        WINEPREFIX="$prefix" "$build_dir/server/wineserver" -k >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
"$llvm_readobj" --file-headers --coff-basereloc --coff-exports \
    "$test_exe" >"$header_dump"
"$llvm_readobj" --file-headers --coff-imports --coff-exports \
    "$companion_dll" >"$companion_dump"
for invariant in \
    'Format: COFF-x86-64' \
    'Machine: IMAGE_FILE_MACHINE_AMD64' \
    'IMAGE_FILE_RELOCS_STRIPPED' \
    'ImageBase: 0x400000' \
    'BaseRelocationTableRVA: 0x0' \
    'BaseRelocationTableSize: 0x0'; do
    if ! grep -Fq "$invariant" "$header_dump"; then
        echo "fixed-low PE invariant is missing: $invariant" >&2
        exit 1
    fi
done
if grep -Fq 'IMAGE_FILE_DLL' "$header_dump" ||
   grep -Fq 'IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE' "$header_dump"; then
    echo "fixed-low PE is a DLL or remains dynamically relocatable" >&2
    exit 1
fi
if ! awk '/^BaseReloc \[/ { inside = 1; next }
         inside && /^]/ { exit entries != 0 }
         inside && NF { entries++ }
         END { if (!inside) exit 1 }' "$header_dump"; then
    echo "fixed-low PE contains base relocation records" >&2
    exit 1
fi
if ! grep -Fq 'Name: fixed_low_export' "$header_dump"; then
    echo "fixed-low PE does not export fixed_low_export" >&2
    exit 1
fi
for invariant in \
    'Format: COFF-x86-64' \
    'Machine: IMAGE_FILE_MACHINE_AMD64' \
    'IMAGE_FILE_DLL' \
    'Name: fixed_low.exe' \
    'Symbol: fixed_low_export' \
    'Name: fixed_low_import_call' \
    'Name: fixed_low_import_target'; do
    if ! grep -Fq "$invariant" "$companion_dump"; then
        echo "fixed-low import companion invariant is missing: $invariant" >&2
        exit 1
    fi
done
echo "XTAJIT64_FIXED_LOW_PE_OK machine=AMD64 image_base=0x400000 relocs_stripped=1 reloc_directory=empty export=fixed_low_export companion_import=1"
shasum -a 256 "$source_file" "$source_spec" "$object_file" "$test_exe" \
    "$test_import_library" "$companion_source" "$companion_spec" \
    "$companion_object" "$companion_dll"

if [[ $# -eq 1 ]]; then
    exit 0
fi

prefix=$(cd "$2" && pwd)
if [[ ! -f "$prefix/system.reg" || ! -f "$prefix/user.reg" ]]; then
    echo "fixed-low runtime requires an initialized Wine prefix: $prefix" >&2
    exit 2
fi
if [[ $# -eq 3 ]]; then
    log_file=$3
else
    log_file="$prefix/xtajit64-fixed-low.log"
fi
if [[ $log_file != /* ]]; then log_file="$PWD/$log_file"; fi
mkdir -p "$(dirname "$log_file")"
for evidence in "$log_file" "$log_file.runner" "$log_file.manifest.pre" \
                "$log_file.manifest.post" "$log_file.tools-wine.codesign" \
                "$log_file.loader-wine.codesign"; do
    if [[ -e $evidence ]]; then
        echo "refusing to overwrite fixed-low evidence: $evidence" >&2
        exit 2
    fi
done

verify_entry_signature()
{
    local entry=$1 output=$2 key key_count

    codesign --verify --strict "$entry"
    codesign -dvvv --entitlements :- "$entry" >"$output" 2>&1
    if ! grep -Fq 'flags=0x2(adhoc)' "$output"; then
        echo "runtime entry is not non-hardened ad-hoc signed: $entry" >&2
        exit 1
    fi
    for key in com.apple.security.cs.allow-dyld-environment-variables \
               com.apple.security.cs.allow-jit \
               com.apple.security.cs.allow-unsigned-executable-memory \
               com.apple.security.custom-x18-abi-toggle; do
        if ! grep -Fq "<key>$key</key><true/>" "$output"; then
            echo "runtime entry is missing entitlement $key: $entry" >&2
            exit 1
        fi
    done
    key_count=$(grep -o '<key>[^<]*</key>' "$output" | wc -l | tr -d ' ')
    if [[ $key_count != 4 ]]; then
        echo "runtime entry has $key_count entitlements instead of four: $entry" >&2
        exit 1
    fi
}

verify_entry_signature "$build_dir/tools/wine/wine" \
                       "$log_file.tools-wine.codesign"
verify_entry_signature "$build_dir/loader/wine" \
                       "$log_file.loader-wine.codesign"

unicorn_lib_dir=
read -r -a unicorn_lib_words <<<"$unicorn_libs"
for word in "${unicorn_lib_words[@]}"; do
    if [[ $word == -L* ]]; then unicorn_lib_dir=${word#-L}; fi
done
if [[ -z $unicorn_lib_dir || ! -d $unicorn_lib_dir ]]; then
    echo "configured Unicorn library directory is unavailable: $unicorn_libs" >&2
    exit 2
fi
native_provider="$build_dir/dlls/xtajit64/xtajit64.so"
unicorn_install_name=$(/usr/bin/otool -L "$native_provider" |
    awk '$1 ~ /libunicorn.*[.]dylib/ { print $1; exit }')
if [[ -z $unicorn_install_name ]]; then
    echo "xtajit64.so has no dynamic Unicorn dependency" >&2
    exit 2
fi
if [[ -n ${XTAJIT64_UNICORN_DYLIB:-} ]]; then
    unicorn_dylib=$XTAJIT64_UNICORN_DYLIB
    unicorn_lib_dir=$(cd "$(dirname "$unicorn_dylib")" && pwd -P)
    unicorn_dylib="$unicorn_lib_dir/$(basename "$unicorn_dylib")"
elif [[ $unicorn_install_name = /* ]]; then
    unicorn_dylib=$unicorn_install_name
else
    unicorn_dylib="$unicorn_lib_dir/${unicorn_install_name##*/}"
fi
if [[ ! -f $unicorn_dylib ]]; then
    echo "configured Unicorn runtime is missing: $unicorn_dylib" >&2
    exit 2
fi
if [[ $unicorn_install_name = @rpath/* ]]; then
    provider_dir=$(cd "$(dirname "$native_provider")" && pwd -P)
    unicorn_leaf=${unicorn_install_name#@rpath/}
    unicorn_reachable=0
    while IFS= read -r provider_rpath; do
        case $provider_rpath in
        @loader_path)
            resolved_rpath=$provider_dir
            ;;
        @loader_path/*)
            resolved_rpath="$provider_dir/${provider_rpath#@loader_path/}"
            ;;
        /*)
            resolved_rpath=$provider_rpath
            ;;
        *)
            continue
            ;;
        esac
        candidate="$resolved_rpath/$unicorn_leaf"
        if [[ -f $candidate ]] && cmp -s "$candidate" "$unicorn_dylib"; then
            unicorn_reachable=1
            break
        fi
    done < <(/usr/bin/otool -l "$native_provider" |
             awk '$1 == "cmd" && $2 == "LC_RPATH" { found = 1; next }
                  found && $1 == "path" { print $2; found = 0 }')
    if [[ $unicorn_reachable -ne 1 ]]; then
        echo "xtajit64.so has no LC_RPATH to the pinned Unicorn runtime: $unicorn_dylib" >&2
        exit 2
    fi
elif [[ $unicorn_install_name = /* ]]; then
    if [[ ! -f $unicorn_install_name ]] ||
       ! cmp -s "$unicorn_install_name" "$unicorn_dylib"; then
        echo "xtajit64.so does not reference the pinned Unicorn runtime: $unicorn_dylib" >&2
        exit 2
    fi
else
    echo "unsupported Unicorn install name in xtajit64.so: $unicorn_install_name" >&2
    exit 2
fi

mandatory_manifest_entries=(
    tools/wine/wine
    loader/wine
    server/wineserver
    dlls/ntdll/ntdll.so
    dlls/ntdll/aarch64-windows/ntdll.dll
    dlls/xtajit64/xtajit64.so
    dlls/xtajit64/aarch64-windows/xtajit64.dll
    dlls/kernel32/aarch64-windows/kernel32.dll
    dlls/kernelbase/aarch64-windows/kernelbase.dll
    dlls/win32u/win32u.so
    dlls/win32u/aarch64-windows/win32u.dll
    programs/start/aarch64-windows/start.exe
    "$source_file"
    "$source_spec"
    "$object_file"
    dlls/xtajit64/provider_tests/x86_64-windows/fixed_low.exe
    "$test_import_library"
    "$companion_source"
    "$companion_spec"
    "$companion_object"
    dlls/xtajit64/provider_tests/x86_64-windows/fixed_low_import.dll
    "$unicorn_dylib"
)
if [[ -z ${XTAJIT64_RUNTIME_MANIFEST:-} ||
      ! -f $XTAJIT64_RUNTIME_MANIFEST ]]; then
    echo "runtime execution requires a nonempty authoritative manifest list" >&2
    exit 2
fi
if ! grep -Fxq '# XTAJIT64_AUTHORITATIVE_RUNTIME_MANIFEST=1' \
        "$XTAJIT64_RUNTIME_MANIFEST" &&
   [[ ${XTAJIT64_RUNTIME_MANIFEST_AUTHORITATIVE:-0} != 1 ]]; then
    echo "runtime manifest lacks its authoritative-format marker" >&2
    exit 2
fi
manifest_entries=()
while IFS= read -r entry; do
    [[ -z $entry || $entry == \#* ]] && continue
    manifest_entries+=("$entry")
done <"$XTAJIT64_RUNTIME_MANIFEST"
if [[ ${#manifest_entries[@]} -eq 0 ]]; then
    echo "runtime manifest contains no artifacts" >&2
    exit 2
fi

manifest_path()
{
    local entry=$1 path directory

    if [[ $entry = /* ]]; then path=$entry; else path="$build_dir/$entry"; fi
    directory=$(cd "$(dirname "$path")" 2>/dev/null && pwd -P) || return 1
    printf '%s/%s\n' "$directory" "$(basename "$path")"
}

for mandatory in "${mandatory_manifest_entries[@]}"; do
    mandatory_path=$(manifest_path "$mandatory") || {
        echo "mandatory runtime artifact is unavailable: $mandatory" >&2
        exit 2
    }
    found=0
    for entry in "${manifest_entries[@]}"; do
        entry_path=$(manifest_path "$entry") || continue
        if [[ $entry_path == "$mandatory_path" ]]; then
            found=1
            break
        fi
    done
    if [[ $found -ne 1 ]]; then manifest_entries+=("$mandatory"); fi
done

write_manifest()
{
    local output=$1 entry path

    : >"$output"
    for entry in "${manifest_entries[@]}"; do
        if [[ $entry = /* ]]; then path=$entry; else path="$build_dir/$entry"; fi
        if [[ ! -f $path ]]; then
            echo "runtime manifest artifact is missing: $path" >&2
            return 1
        fi
        shasum -a 256 "$path" >>"$output"
    done
}

write_manifest "$log_file.manifest.pre"

if [[ -n ${XTAJIT64_TIMEOUT_COMMAND:-} ]]; then
    read -r -a timeout_words <<<"$XTAJIT64_TIMEOUT_COMMAND"
    if [[ ${#timeout_words[@]} -eq 0 || ! -x ${timeout_words[0]} ]]; then
        echo "bounded runtime timeout command is unavailable: $XTAJIT64_TIMEOUT_COMMAND" >&2
        exit 2
    fi
elif [[ -x /opt/homebrew/bin/gtimeout ]]; then
    timeout_words=(/opt/homebrew/bin/gtimeout)
elif [[ -x /usr/bin/perl ]]; then
    timeout_words=(/usr/bin/perl -e 'alarm shift; exec @ARGV')
else
    echo "no bounded runtime timeout implementation is available" >&2
    exit 2
fi
runtime_timeout=${XTAJIT64_RUNTIME_TIMEOUT:-120}
if [[ ! $runtime_timeout =~ ^[1-9][0-9]*$ || $runtime_timeout -gt 600 ]]; then
    echo "XTAJIT64_RUNTIME_TIMEOUT must be an integer from 1 through 600" >&2
    exit 2
fi

{
    echo "XTAJIT64_FIXED_LOW_RUN build=$build_dir prefix=$prefix exe=$test_exe"
    echo "XTAJIT64_FIXED_LOW_SOURCE sha256=$(shasum -a 256 "$source_file" | awk '{print $1}')"
    echo "XTAJIT64_FIXED_LOW_IMAGE sha256=$(shasum -a 256 "$test_exe" | awk '{print $1}')"
    echo "XTAJIT64_FIXED_LOW_IMPORT_SOURCE sha256=$(shasum -a 256 "$companion_source" | awk '{print $1}')"
    echo "XTAJIT64_FIXED_LOW_IMPORT_IMAGE sha256=$(shasum -a 256 "$companion_dll" | awk '{print $1}')"
} >"$log_file.runner"

server_kill_status=0
PATH="$build_dir/server:$PATH" WINEBUILDDIR="$build_dir" WINEPREFIX="$prefix" \
    "$build_dir/server/wineserver" -k || server_kill_status=$?
if [[ $server_kill_status -gt 1 ]]; then
    echo "pre-run wineserver stop failed with $server_kill_status" >&2
    exit 1
fi
PATH="$build_dir/server:$PATH" WINEBUILDDIR="$build_dir" WINEPREFIX="$prefix" \
    "$build_dir/server/wineserver" -w
echo "XTAJIT64_FIXED_LOW_SERVER_STOPPED=1 kill_status=$server_kill_status" \
    >>"$log_file.runner"

set +e
PATH="$build_dir/server:$PATH" \
WINEBUILDDIR="$build_dir" \
WINEPREFIX="$prefix" \
WINEDEBUG=${XTAJIT64_WINEDEBUG:-+xtajit,+process,+loaddll} \
DYLD_LIBRARY_PATH="$build_dir/dlls/ntdll${unicorn_lib_dir:+:$unicorn_lib_dir}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
"${timeout_words[@]}" "$runtime_timeout" "$build_dir/tools/wine/wine" \
    start.exe /wait /b /machine amd64 /unix "$test_exe" >"$log_file" 2>&1
runtime_status=$?
set -e
echo "XTAJIT64_FIXED_LOW_EXIT=$runtime_status" >>"$log_file.runner"

write_manifest "$log_file.manifest.post"
if ! cmp -s "$log_file.manifest.pre" "$log_file.manifest.post"; then
    echo "fixed-low runtime mutated a manifested artifact" >&2
    diff -u "$log_file.manifest.pre" "$log_file.manifest.post" >&2 || true
    exit 1
fi
if [[ $runtime_status -ne 0 ]]; then
    echo "fixed-low runtime exited $runtime_status; log: $log_file" >&2
    exit 1
fi

markers=(
    XTAJIT64_FIXED_LOW_PROCESS
    XTAJIT64_FIXED_LOW_PROVIDER
    XTAJIT64_FIXED_LOW_PUBLIC_MODULE
    XTAJIT64_FIXED_LOW_MAIN_IMPORT
    XTAJIT64_FIXED_LOW_PEB_PRIVATE
    XTAJIT64_FIXED_LOW_PEB_MODULE
    XTAJIT64_FIXED_LOW_MAIN
    XTAJIT64_FIXED_LOW_PROTECT
    XTAJIT64_FIXED_LOW_PROTECT_RESTORE
    XTAJIT64_FIXED_LOW_FAILED_PROTECT
    XTAJIT64_FIXED_LOW_RESUME
    XTAJIT64_FIXED_LOW_EXECUTE_ONLY_READ
    XTAJIT64_FIXED_LOW_VALLOC
    XTAJIT64_FIXED_LOW_RELEASE
    XTAJIT64_FIXED_LOW_INVALID_RELEASE
    XTAJIT64_FIXED_LOW_LATER_MAP
    XTAJIT64_FIXED_LOW_PRE_UNMAP
    XTAJIT64_FIXED_LOW_UNMAP_OK
)
for marker in "${markers[@]}"; do
    count=$(grep -Ec "^${marker}([[:space:]]|$)" "$log_file" || true)
    if [[ $count -ne 1 ]]; then
        echo "fixed-low marker $marker occurred $count times, expected once" >&2
        exit 1
    fi
done
if grep -Fq 'not ok:' "$log_file"; then
    echo "fixed-low runtime reported a failed assertion" >&2
    exit 1
fi
if ! grep -Eq 'published ARM64EC LOW event operation 1 mutation status 0, full 1 covered 0x100000000 ranges [1-9][0-9]*, free [1-9][0-9]*/0x[1-9a-fA-F][0-9a-fA-F]* ' "$log_file"; then
    echo "fixed-low log has no exact 4-GiB initial FULL publication with FREE coverage" >&2
    exit 1
fi
image_size=$(sed -n 's/^XTAJIT64_FIXED_LOW_PRE_UNMAP .* image_size=\(0x[0-9a-fA-F][0-9a-fA-F]*\).*/\1/p' "$log_file")
if [[ -z $image_size ]] ||
   ! grep -Eq "published ARM64EC LOW event operation 8 mutation status 0, full 0 covered ${image_size} ranges 1, free 1/${image_size} " "$log_file"; then
    echo "fixed-low log has no exact whole-main FREE publication after interior unmap" >&2
    exit 1
fi

echo "XTAJIT64_FIXED_LOW_RUNTIME_OK log=$log_file manifest_equal=1 manifest_count=${#manifest_entries[@]}"
