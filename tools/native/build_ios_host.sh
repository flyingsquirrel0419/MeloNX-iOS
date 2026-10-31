#!/bin/bash
# Builds nxnative's host (dm/host, dm/gfx, the iOS front end dm/ios/Sources without its main.m) for MeloNX's native mode, as static libraries the app executable links:
#   libdmhost.a   the host, its graphics layers and front end, src/MeloNX.NativeHost (the launch glue native_boot.m, dm_jit.c) and the runtime profile table
#   libvpx.a      third_party/libvpx (movie decoding)
#   ldflags.txt   what the app's link needs (Xcode: DM_NATIVE_HOST_LDFLAGS, which the MeloNX target adds to OTHER_LDFLAGS)
# The host goes into the executable rather than a dylib: it finds its takeover tables in the main image's sections (_mh_execute_header).
# The source list follows dm/host/Makefile (the same wildcards); the iOS flags follow dm/ios/project.yml. The patches (tools/native/apply_patches.sh) must be applied first.
# Runs on a Mac with Xcode (the CI runner). Usage: tools/native/build_ios_host.sh <out dir> <dir with game_profile.h and dm_profiles.gen.c (gen_app_tables.sh)>
set -euo pipefail
out=${1:?usage: build_ios_host.sh <out dir> <host profile dir>}
prof=${2:?usage: build_ios_host.sh <out dir> <host profile dir>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
dm="$root/src/nxnative/dm"
glue="$root/src/MeloNX.NativeHost"
mkdir -p "$out"; out=$(cd "$out" && pwd); prof=$(cd "$prof" && pwd)
obj="$out/obj"; rm -rf "$obj"; mkdir -p "$obj"
MIN_IOS=15.0   # the app's deployment target: the Metal 4 classes are weakly linked, and the launch checks iOS 26 (native_boot.m)
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
cc=$(xcrun --sdk iphoneos -f clang)
# -mcpu=apple-a17: the host's assembly uses LSE atomics (nxnative builds for apple-a18); native mode needs an A17 Pro or later anyway (BC textures)
common=(-arch arm64 -isysroot "$sdk" -miphoneos-version-min=$MIN_IOS -mcpu=apple-a17 -O2 -g0 -w -fobjc-arc -std=gnu11 -DDM_JIT_LOADER=1)
inc=(-I"$prof" -I"$dm/host" -I"$dm/gfx" -I"$dm/gfx/nvn" -I"$dm/gfx/nvn/include" -I"$dm/gfx/tex" -I"$dm/third_party/vulkan-headers/include"
     -I"$dm/third_party/libvpx" -I"$dm/third_party/stb_vorbis" -I"$dm/ios/Sources")

# The host's sources (dm/host/Makefile SRC and GFX, without the Mac front end) and the iOS front end without main.m
srcs=()
for f in loader.c hle.c crash.c probe.c thread.c save_sync.c memstat.m haptics_apple.m entry.S; do srcs+=("$dm/host/$f"); done
while IFS= read -r f; do srcs+=("$f"); done < <(ls "$dm"/host/hle_*.c | sort)
while IFS= read -r f; do srcs+=("$f"); done < <(ls "$dm"/gfx/*.c "$dm"/gfx/nvn/*.c "$dm"/gfx/nvn/*.m "$dm"/gfx/nvn/*.S "$dm"/gfx/tex/*.c "$dm"/gfx/tex/*.m "$dm"/gfx/vk/*.m "$dm"/gfx/gl/*.m 2>/dev/null | grep -v '_mac\.' | sort)
for f in front_ios.m DmGamepad.m CloudSaves.m SaveSync.m; do srcs+=("$dm/ios/Sources/$f"); done
srcs+=("$glue/native_boot.m" "$glue/dm_jit.c" "$prof/dm_profiles.gen.c")

compile() {   # <source> <object> [extra flags]
    local src=$1 o=$2; shift 2
    case "$src" in *.m) lang=(-x objective-c) ;; *.S) lang=(-x assembler-with-cpp) ;; *) lang=(-x c) ;; esac
    "$cc" "${common[@]}" "${inc[@]}" "$@" "${lang[@]}" -c "$src" -o "$o"
}

fail=0
compile "$dm/host/main.c" "$obj/main.o" -Dmain=dm_main || fail=1
n=0
for f in "${srcs[@]}"; do
    n=$((n + 1)); o="$obj/$(printf %04d $n)_$(basename "${f%.*}").o"
    compile "$f" "$o" &
    if (( n % 8 == 0 )); then wait || fail=1; fi
done
wait || fail=1
# a failed compile in a background job shows only in its own output: check every object is there
n=0; for f in "${srcs[@]}"; do n=$((n + 1)); o="$obj/$(printf %04d $n)_$(basename "${f%.*}").o"; [ -f "$o" ] || { echo "[RED] not compiled: $f"; fail=1; }; done
[ $fail = 0 ] || exit 1
rm -f "$out/libdmhost.a"; xcrun --sdk iphoneos ar rcs "$out/libdmhost.a" "$obj"/*.o

# libvpx, as dm/host/Makefile builds it
vobj="$out/vpx"; rm -rf "$vobj"; mkdir -p "$vobj"; n=0
while IFS= read -r f; do
    n=$((n + 1))
    "$cc" -arch arm64 -isysroot "$sdk" -miphoneos-version-min=$MIN_IOS -O2 -g0 -w -I"$dm/third_party/libvpx" -I"$dm/third_party/libvpx/config" -c "$f" -o "$vobj/$(printf %04d $n)_$(basename "${f%.c}").o" &
    if (( n % 8 == 0 )); then wait; fi
done < <(find "$dm/third_party/libvpx" -name '*.c' | sort)
wait
rm -f "$out/libvpx.a"; xcrun --sdk iphoneos ar rcs "$out/libvpx.a" "$vobj"/*.o

# Frameworks: dm/host/Makefile's, with UIKit for Cocoa; BreakpointJIT (dm_jit.c) is already linked by the app
frameworks="QuartzCore Metal MetalFX GameController CoreHaptics IOKit AudioToolbox AVFAudio VideoToolbox CoreMedia CoreVideo ImageIO UniformTypeIdentifiers UIKit"
{
    printf -- '-Wl,-force_load,%s %s' "$out/libdmhost.a" "$out/libvpx.a"
    for f in $frameworks; do printf -- ' -framework %s' "$f"; done
    printf -- ' -lc++\n'
} > "$out/ldflags.txt"
echo "$out: libdmhost.a ($(ls "$obj" | wc -l | tr -d ' ') objects), libvpx.a; link with: $(cat "$out/ldflags.txt")"
