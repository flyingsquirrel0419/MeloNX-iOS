# Native mode tools (nxnative inside MeloNX)

MeloNX's native mode runs a supported game the way [nxnative](https://github.com/seedds/nxnative) does: the game's own AArch64 code, rewritten where Apple's kernel requires it, on nxnative's Horizon host with NVN on Metal. nxnative prepares a game on a Mac with Python tools. MeloNX does that preparation on the iPhone, so the game files never leave the phone. This folder holds the build-time tools and the checks for that port.

nxnative is the `src/nxnative` submodule. The C# port is `src/MeloNX.Native.Prep`.

## What is ported

| nxnative (Python) | MeloNX.Native.Prep (C#) | Checked by |
|---|---|---|
| `dm/tools/patch_nso.py`, the NSO rewriter | `Rewriter/PatchNso*.cs` | `identity_test.py`: byte-identical outputs |
| `nso.py`, `nso_asm.py`, `nso_code.py`, `nso_match.py`, `ue_malloc.py`, `ue_cvar.py`, `nso_syms.defined`, `loader_census.got_values` | `Rewriter/Nso.cs`, `NsoAsm.cs`, `NsoCode.cs`, `NsoMatch.cs`, `UnrealScan.cs` | the same |
| `sdk_patches.py`, `dm/games/*/patches.py` (CUTS, OBS, MATCH_CUTS, CAPABILITIES) | `patch_tables.json`, written by `convert_patches.py` at app build time | the same |
| FRAME_STEP stubs, which are Python functions | `Rewriter/FrameSteps.Generated.cs`, written by `gen_frame_steps.py` | `frame_step_test.py` |

Capstone 5 does the disassembly on both sides. The C# side reaches it through `Native/cs_shim.c`, which copies each instruction into a struct whose layout the shim fixes. The same Capstone build therefore gives both rewriters the same `op_str`, operands and register lists.

## In the app

The game list's menu shows **Native Mode** for a game that has a profile. That sheet runs the preparation and shows its log, which can be shared.

| Step | Where |
|---|---|
| Swift sheet and the `native_prepare` call | `src/MeloNX/MeloNX/Native/NativePrep*.swift` |
| `native_prepare` / `native_rewrite` exports, with progress through the `native_prep` callback | `src/Ryujinx.Library/NativeMode.cs` |
| Profile lookup, extraction, then the rewrite of each module the profile lists | `src/MeloNX.Native.Prep/NativePrep.cs` |
| nx_extract on MeloNX's LibHac: ExeFS, `romfs.img` (DMROMFS1), control data | `src/MeloNX.Native.Prep/Extract/GameExtractor.cs` |

The output goes to `Documents/NativeGames/<title ID>/`:

- `ExeFS/`
- `romfs.img`
- `patched/` (the host's module directory)
- `control.nacp`
- `icon.jpg`
- `native.json`, written last

CI builds the native parts on the Mac runner:

- `build_ios_native.sh` builds Capstone 5.0.7 and cs_shim as static libraries. The NativeAOT publish links them through `DirectPInvoke`, with `-p:NativePrepLibDir`.
- `gen_app_tables.sh` writes `patch_tables.json` and `native_profiles.json` into `src/MeloNX/MeloNX/Native/Generated/`, which the app bundles.

`nxrewrite --prepared <game dir> <title ID> --tables … --profiles …` runs the app's rewrite step on an extracted game. That step is checked against `patch_nso.py` the same way.

## Running the checks (Linux or macOS)

You need the .NET 10 SDK, clang (used as an AArch64 assembler) and `python3 -m pip install "capstone>=5,<6" lz4`.

```
dotnet build -c Release src/MeloNX.Native.Prep.Cli
tools/native/build_shim.sh src/MeloNX.Native.Prep.Cli/bin/Release/net10.0
python3 tools/native/identity_test.py --nxrewrite src/MeloNX.Native.Prep.Cli/bin/Release/net10.0/nxrewrite --seeds 150 --far 6 --profiles 8 --big 3
python3 tools/native/frame_step_test.py --nxrewrite src/MeloNX.Native.Prep.Cli/bin/Release/net10.0/nxrewrite
```

`identity_test.py` builds synthetic modules with `synth_nso.py`. Each module is AArch64 assembly laid out as an LZ4-compressed NSO, with MOD0, an eh_frame with one FDE per function, an eh_frame_hdr, a dynamic section and a symbol table. Its functions use every kind of rewrite site the rewriter knows: x18 uses, system registers, SVCs, exclusive windows, retry blocks, jump tables, tail calls, spin waits, and the SDK symbols that observation gates attach to. Each module is rewritten twice, once as `main` and once as `sdk`.

The test also covers these cases:

- `--far`: modules whose patch area goes before the base.
- `--big`: 400 KB functions with no unwind entry, which the rewriter analyses in pieces.
- `--profiles`: an outside profile (`DM_GAMES_DIR`) holding CUTS, OBS and CAPABILITIES for the module's build, or a function-matched cut for a build that is not registered.
- One module with Paper Mario: The Thousand-Year Door 1.0.1's build ID, so its FRAME_STEP stub runs inside a whole rewrite.

Every output file is compared byte for byte, `build_src.sha256` excepted. Real modules can be checked too, on a machine that has them: `--nso <ExeFS>/main --name main`.

## After an nxnative update

1. Run `python3 tools/native/gen_frame_steps.py src/nxnative src/MeloNX.Native.Prep/Rewriter/FrameSteps.Generated.cs`.
   - It stops if a stub uses Python the translator does not cover.
   - It also stops if ASTRAL CHAIN's helpers (`signed`, `width`, `relocate`) changed. Those are ported by hand in `FrameSteps.cs`.
2. Run both checks above.
3. If `identity_test.py` reports a difference, the rewriter changed upstream: port the change into `Rewriter/`.

The app bundles `patch_tables.json` (`convert_patches.py src/nxnative patch_tables.json`). At run time, `FrameSteps.Run` compares each stub's source hash with the one in the tables. A stub that is stale therefore stops the rewrite instead of emitting old code.

## Not covered yet

- ZBIC (Nintendo's zstd variant, in system 22.0.0+ modules) and compressed NROs: `Nso.Load` names them as unsupported.
- The synthetic modules do not exercise:
  - the Unreal scans (`UnrealScan.cs`)
  - NROs
  - the two-area layout of text longer than 128 MB (`TWO`)

  Check those on real modules with `--nso`.
