#!/bin/sh
# Writes the native mode tables the app bundles, from the nxnative submodule (Python's standard library is enough):
#   patch_tables.json      the rewriter's registered patches (convert_patches.py)
#   native_profiles.json   the game profiles' title IDs, names and code modules (gen_profiles.py, which also writes the host's runtime profile table)
# Usage: tools/native/gen_app_tables.sh <out dir for the JSON files> [<out dir for game_profile.h / dm_profiles.gen.c>]
set -eu
out=${1:?usage: gen_app_tables.sh <json out dir> [host profile out dir]}
here=$(cd "$(dirname "$0")" && pwd)
repo="$here/../../src/nxnative"
host=${2:-$(mktemp -d)}
mkdir -p "$out" "$host"
python3 -I "$here/convert_patches.py" "$repo" "$out/patch_tables.json"
python3 -I "$here/gen_profiles.py" "$repo" "$host"
cp "$host/native_profiles.json" "$out/native_profiles.json"
