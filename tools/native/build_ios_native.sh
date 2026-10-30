#!/bin/sh
# Builds the native libraries MeloNX.Native.Prep needs inside the app, for iOS arm64, as static libraries that the NativeAOT publish of Ryujinx.Library links in
# (DirectPInvoke cs_shim, see Ryujinx.Library.csproj):
#   libcapstone.a   Capstone 5.0.7, AArch64 only: the release the rewriter port was checked against (identity_test.py uses the Python package of the same version)
#   libcs_shim.a    src/MeloNX.Native.Prep/Native/cs_shim.c
# Runs on a Mac with Xcode (the CI runner). Usage: tools/native/build_ios_native.sh <out dir>
set -eu
out=${1:?usage: build_ios_native.sh <out dir>}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"; out=$(cd "$out" && pwd)
work="$out/capstone-src"
CAPSTONE_TAG=5.0.7
MIN_IOS=15.0

if [ ! -d "$work" ]; then
  git clone -q --depth 1 --branch "$CAPSTONE_TAG" https://github.com/capstone-engine/capstone.git "$work"
fi
# CMAKE_SYSTEM_PROCESSOR: Capstone's CPackConfig.txt compares it unquoted, and it is empty for iOS.
# CAPSTONE_BUILD_MACOS_THIN: otherwise Capstone forces x86_64;arm64 on every Apple target.
cmake -S "$work" -B "$work/build-ios" -G "Unix Makefiles" \
  -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_SYSTEM_PROCESSOR=arm64 -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=$MIN_IOS -DCMAKE_BUILD_TYPE=Release \
  -DCAPSTONE_BUILD_MACOS_THIN=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DCAPSTONE_INSTALL=OFF \
  -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF -DCAPSTONE_BUILD_DIET=OFF \
  -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_ARM64_SUPPORT=ON >/dev/null
cmake --build "$work/build-ios" --config Release -j "$(sysctl -n hw.ncpu 2>/dev/null || echo 4)" >/dev/null
cp "$work/build-ios/libcapstone.a" "$out/libcapstone.a"

sdk=$(xcrun --sdk iphoneos --show-sdk-path)
xcrun --sdk iphoneos clang -c -O2 -arch arm64 -isysroot "$sdk" -miphoneos-version-min=$MIN_IOS -I"$work/include" \
  "$here/../../src/MeloNX.Native.Prep/Native/cs_shim.c" -o "$out/cs_shim.o"
rm -f "$out/libcs_shim.a"
xcrun --sdk iphoneos ar rcs "$out/libcs_shim.a" "$out/cs_shim.o"
rm -f "$out/cs_shim.o"
echo "$out: libcapstone.a (Capstone $CAPSTONE_TAG, AArch64) and libcs_shim.a for iOS arm64"
