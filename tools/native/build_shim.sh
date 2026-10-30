#!/bin/sh
# Builds libcs_shim (Capstone 5 behind a flat C API, src/MeloNX.Native.Prep/Native/cs_shim.c) next to nxrewrite, for running the C# rewriter on Linux or macOS.
# Capstone comes from the Python package the identity test needs anyway (python3 -m pip install "capstone>=5,<6"): its headers and its shared library are used as they are,
# so both rewriters decode with the same Capstone build.
# Usage: tools/native/build_shim.sh <nxrewrite output dir>
set -e
out=${1:?usage: build_shim.sh <nxrewrite output dir>}
here=$(cd "$(dirname "$0")" && pwd)
cap=$(python3 -c 'import capstone, os; print(os.path.dirname(capstone.__file__))')
major=$(python3 -c 'import capstone; print(capstone.cs_version()[0])')
[ "$major" = 5 ] || { echo "[RED] Capstone $major: the rewriter needs Capstone 5 (python3 -m pip install \"capstone>=5,<6\")"; exit 1; }
case $(uname) in
  Darwin) lib=libcapstone.dylib; shim=libcs_shim.dylib; cp "$cap/lib/$lib" "$out/$lib"
          cc -O2 -dynamiclib -I"$cap/include" "$here/../../src/MeloNX.Native.Prep/Native/cs_shim.c" "$out/$lib" -Wl,-rpath,@loader_path -o "$out/$shim" ;;
  *)      cp "$cap/lib/libcapstone.so" "$out/libcapstone.so.5"   # the soname the library was linked with
          cc -O2 -shared -fPIC -I"$cap/include" "$here/../../src/MeloNX.Native.Prep/Native/cs_shim.c" "$out/libcapstone.so.5" -Wl,-rpath,'$ORIGIN' -o "$out/libcs_shim.so" ;;
esac
echo "$out: cs_shim built against Capstone $(python3 -c 'import capstone; print(capstone.__version__)')"
