#!/usr/bin/env python3
"""Writes patch_tables.json for MeloNX.Native.Prep (the C# port of nxnative's NSO rewriter), at app build time.
It reads nxnative's patch files exactly as dm/tools/patch_nso.py's load_patches() does: dm/tools/sdk_patches.py, dm/games/*/patches.py, then the profiles of
DM_GAMES_DIR (folders separated by os.pathsep), a build ID claimed twice stopping it. The repository profiles' game.tsv "build" rows go in too (MATCH_CUTS reports use them).
FRAME_STEP stubs are Python functions: the JSON names each build and the SHA-256 of its function's source, which the C# port checks (Rewriter/FrameSteps.cs).
No game data is involved: these are nxnative's own tables.
Usage: convert_patches.py <nxnative checkout> <out.json>"""
import glob, hashlib, importlib.util, inspect, json, os, sys


def main():
    repo, out = sys.argv[1], sys.argv[2]
    tools = os.path.join(repo, 'dm', 'tools')
    sys.path.insert(0, tools)   # the patch files import nso_asm
    games = os.path.join(repo, 'dm', 'games')
    extra = [d for d in os.environ.get('DM_GAMES_DIR', '').split(os.pathsep) if d]
    files = [os.path.join(tools, 'sdk_patches.py')] + sorted(glob.glob(os.path.join(games, '*', 'patches.py')))
    files += [p for d in extra for p in sorted(glob.glob(os.path.join(glob.escape(d), '*', 'patches.py')))]
    seen = {}
    for p in files: seen.setdefault(os.path.realpath(p), p)
    files = list(seen.values())

    tables = {'cuts': {}, 'obs': {}, 'frame_step': {}, 'match_cuts': {}, 'sdk_match_cuts': {}, 'capabilities': {}, 'build_rows': {}}
    where = {}
    for n, path in enumerate(files):
        spec = importlib.util.spec_from_file_location(f'patches_{n}', path); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        if os.path.basename(path) == 'sdk_patches.py':
            tables['sdk_match_cuts'] = {k: [rule_json(r) for r in v] for k, v in getattr(m, 'MATCH_CUTS', {}).items()}
        else:
            profile = os.path.basename(os.path.dirname(path))
            roots = [games] + extra
            profile_dir = next((os.path.join(root, profile) for root in roots if os.path.isdir(os.path.join(root, profile))), None)
            if not (profile_dir and os.path.realpath(os.path.dirname(path)) != os.path.realpath(profile_dir)) and getattr(m, 'MATCH_CUTS', {}):
                tables['match_cuts'][profile] = {k: [rule_json(r) for r in v] for k, v in m.MATCH_CUTS.items()}
        for kind, key in (('CUTS', 'cuts'), ('OBS', 'obs'), ('FRAME_STEP', 'frame_step'), ('CAPABILITIES', 'capabilities')):
            for bid, v in getattr(m, kind, {}).items():
                assert (kind, bid) not in where, f'{kind} of build {bid} in both {where[kind, bid]} and {path}'
                where[kind, bid] = path
                if kind == 'CUTS': tables[key][bid] = [[off, ob, nb, why] for off, ob, nb, why in v]
                elif kind == 'OBS': tables[key][bid] = [[off, oid, ow, why] for off, oid, ow, why in v]
                elif kind == 'FRAME_STEP': tables[key][bid] = hashlib.sha256(inspect.getsource(v).encode()).hexdigest()
                else: tables[key][bid] = list(v)

    for tsv in sorted(glob.glob(os.path.join(glob.escape(games), '*', 'game.tsv'))):   # the repository's only: patch_nso.py reads dm/games/<profile>/game.tsv
        profile = os.path.basename(os.path.dirname(tsv))
        with open(tsv, encoding='utf-8') as f:
            rows = [[x.strip() for x in row.split('\t')] for row in f.read().splitlines()]
        tables['build_rows'][profile] = [c for c in rows if c[0] == 'build' and len(c) > 3]

    with open(out, 'w', encoding='utf-8') as f: json.dump(tables, f, indent=1, sort_keys=True)
    print(f'{out}: {len(tables["cuts"])} builds with cuts, {len(tables["obs"])} with observation gates, {len(tables["frame_step"])} with frame steps, '
          f'{sum(len(v) for v in tables["match_cuts"].values())} profile modules with function patches')


def rule_json(r):
    if 'functions' in r: return {'name': r['name'], 'functions': [{k: fn_json(k, v) for k, v in fn.items()} for fn in r['functions']]}
    return {k: fn_json(k, v) for k, v in r.items()}


def fn_json(k, v):
    return [[a, b, c, d] for a, b, c, d in v] if k == 'cuts' else list(v) if k == 'fingerprints' else v


if __name__ == '__main__':
    main()
