# ARM64 migration inputs (experimental)

This directory keeps the CPU dependency inputs with the ARM64 Wine branch.
The stable product remains on `master`. This is a source checkpoint, not a
ready-to-install runtime or a promise of general x86/x64 game compatibility.

## Unicorn

`unicorn.lock.json` records the upstream archive checksum and patch order.
Verify the archive checksum, unpack it into a new working directory, and apply
each listed patch with `patch --batch --fuzz=0 -p1 -i <absolute-patch-path>`.
Verify every patch checksum before applying it. Never reuse a live runtime's
source or build directory for a clean reconstruction.

The first patch is from Switchyard Wine at the revision linked in the lock.
The remaining three changes handle split reads, code-hook stopping and atomic
XCHG. The original Unicorn license text is preserved in `COPYING.unicorn`;
upstream file notices remain in the source archive. The Wine source keeps its
own existing licensing and attribution.

Configure Unicorn with the options in the lock and build the `unicorn` target.
These inputs have been checked against the modified source used by the local
x64 candidate. This does not establish a clean full-runtime rebuild.

## Remaining build work

The Wine configure/link/signing recipe, SDK/compiler versions, MoltenVK and
other native dependencies still need a portable input lock. The tested macOS
DXVK comparison binary identifies itself as `v1.10.3-20230507-async`; its exact
source rebuild is not yet established. Do not substitute a different DXVK
build and assume the previous acceptance results apply.

No game data, saves, binaries, private test logs or developer provisioning
profiles belong in this directory. Runtime integration and release packaging
remain separate work.
