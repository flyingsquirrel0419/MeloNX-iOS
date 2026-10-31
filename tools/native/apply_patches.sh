#!/bin/sh
# Applies MeloNX's patches to the nxnative submodule before the native host is built (CI, or by hand); a patch already applied is left as it is.
#   0001-loader-jit-region.patch   the loader maps rewritten modules from files into a JIT region (DM_JIT_LOADER), as MeloNX's own JIT gets its memory
#   0002-runtime-game-profile.patch the few compile-time uses of the game profile read the profile chosen at run time (tools/native/gen_profiles.py)
#   0003-chain-foreign-faults.patch  a fault in MeloNX's .NET runtime goes back to its own handler, not the host's crash handler
set -e
root=$(cd "$(dirname "$0")/../.." && pwd)
for p in "$root"/src/MeloNX.NativeHost/patches/*.patch; do
    if git -C "$root/src/nxnative" apply --reverse --check "$p" 2>/dev/null; then echo "already applied: $(basename "$p")"
    else git -C "$root/src/nxnative" apply "$p"; echo "applied: $(basename "$p")"; fi
done
