#!/usr/bin/env python3
"""Checks that MeloNX.Native.Prep's C# rewriter (nxrewrite) writes byte-identical outputs to nxnative's dm/tools/patch_nso.py.
Synthetic modules (synth_nso.py) by default; --nso <module>... checks real ones too (a game's ExeFS on a machine with game files).
Every output file is compared: <name>.patched.bin, .fixups.tsv, .gates.tsv, .sites.tsv, .cuts.tsv, .obs.tsv and .match.tsv (build_src.sha256 names Python files and is left out).
Usage: identity_test.py --nxrewrite <path to nxrewrite> [--seeds N] [--far N] [--nso module ...] [--name main]
Needs: clang (AArch64 assembler), Python capstone 5 and lz4, an nxnative checkout at src/nxnative."""
import argparse, filecmp, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
NX = os.path.join(REPO, 'src', 'nxnative')
sys.path.insert(0, HERE)
import synth_nso


def run_both(nso, name, nxrewrite, tables, work, env):
    py, cs = os.path.join(work, 'py'), os.path.join(work, 'cs')
    p = subprocess.run([sys.executable, os.path.join(NX, 'dm', 'tools', 'patch_nso.py'), nso, py, name], capture_output=True, text=True, env=env)
    c = subprocess.run([nxrewrite, nso, cs, name, '--tables', tables], capture_output=True, text=True, env=env)
    if p.returncode or c.returncode:
        if p.returncode and c.returncode: return 'both failed', p.stderr.strip().splitlines()[-1:] + c.stderr.strip().splitlines()[-1:]
        return 'one failed', [f'python {p.returncode}: ' + ' | '.join(p.stderr.strip().splitlines()[-2:]), f'c# {c.returncode}: ' + ' | '.join(c.stderr.strip().splitlines()[-3:])]
    files = sorted(f for f in os.listdir(py) if f != 'build_src.sha256')
    diffs = [f for f in files if not os.path.exists(os.path.join(cs, f)) or not filecmp.cmp(os.path.join(py, f), os.path.join(cs, f), shallow=False)]
    extra = sorted(set(os.listdir(cs)) - set(files))
    return ('ok' if not diffs and not extra else 'differ'), diffs + [f'only in c#: {x}' for x in extra]


def profile_cases(seed, t):
    """A synthetic module and an outside profile (DM_GAMES_DIR) with patches for it: registered CUTS, OBS and CAPABILITIES (case 'registered'), or a function-matched
    cut for a build that is not registered, beside another build's CUTS (case 'matched'). Yields (label, nso path, env overrides)"""
    sys.path.insert(0, os.path.join(NX, 'dm', 'tools'))
    import nso as nsomod, nso_code, nso_match
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    data, bid = synth_nso.build(seed)
    path = os.path.join(t, f'p{seed}.nso'); open(path, 'wb').write(data)
    m = nsomod.load(data); img = bytes(m.image)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
    # functions with no rewrite site at all, whose first instruction an observation gate can relocate
    quiet = []
    for s, e in nso_code.fde_ranges(img):
        ins = list(md.disasm(img[s:e], s))
        if len(ins) * 4 != e - s or len(ins) < 3: continue
        if any('18' in x.op_str or x.mnemonic in ('svc', 'mrs', 'msr', 'ldxr', 'ldaxr', 'stxr', 'stlxr') or x.mnemonic.startswith('b') or x.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz') for x in ins): continue
        if ins[0].mnemonic in ('adr', 'adrp', 'ldr') and '[' not in ins[0].op_str: continue
        quiet.append((s, e))
    if len(quiet) < 2: return
    (a, _), (b, be) = quiet[0], quiet[1]
    w = lambda o: img[o:o + 4].hex()
    for case in ('registered', 'matched'):
        root = os.path.join(t, f'profiles{seed}{case}'); os.makedirs(os.path.join(root, 'SYNTH'), exist_ok=True)
        if case == 'registered':
            body = (f"CUTS = {{'{bid}': [({b + 4:#x}, '{w(b + 4)}', '1f2003d5', 'synthetic cut')]}}\n"
                    f"OBS = {{'{bid}': [({a:#x}, 3, '{img[a:a + 4][::-1].hex()}', 'synthetic gate')]}}\n"
                    f"CAPABILITIES = {{'{bid}': ('SYNTH_CAP',)}}\n")
        else:
            rule = nso_match.Image(img, m.text_end).recipe(b + 4, w(b + 4), '1f2003d5', 'synthetic matched cut')
            body = f"CUTS = {{'{'0' * 31}1': [(0, '00000000', '00000000', 'another build')]}}\nMATCH_CUTS = {{'main': [{rule!r}]}}\n"
        open(os.path.join(root, 'SYNTH', 'patches.py'), 'w').write(body)
        yield f'profile {case} {seed}', path, {'DM_GAMES_DIR': root, 'DM_GAME': 'SYNTH'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nxrewrite', required=True)
    ap.add_argument('--seeds', type=int, default=40)
    ap.add_argument('--far', type=int, default=3, help='synthetic modules whose bss puts the patch area before the base')
    ap.add_argument('--big', type=int, default=2, help='synthetic modules with 400 KB of code and no unwind entry (analysed in pieces)')
    ap.add_argument('--profiles', type=int, default=6, help='synthetic modules with patches of their own in an outside profile (CUTS, OBS, MATCH_CUTS)')
    ap.add_argument('--nso', nargs='*', default=[])
    ap.add_argument('--name', default=None, help='module name for --nso (default: the file name)')
    a = ap.parse_args()
    env = dict(os.environ)
    bad = 0
    with tempfile.TemporaryDirectory() as t:
        tables = os.path.join(t, 'patch_tables.json')
        subprocess.run([sys.executable, os.path.join(HERE, 'convert_patches.py'), NX, tables], check=True, capture_output=True, env=env)
        cases = [(f'synth {s}', s, False) for s in range(a.seeds)] + [(f'synth far {s}', 1000 + s, True) for s in range(a.far)]
        for label, seed, far in cases:
            nso = os.path.join(t, f'{seed}.nso')
            data, _ = synth_nso.build(seed, far=far)
            open(nso, 'wb').write(data)
            for name in ('main', 'sdk'):
                with tempfile.TemporaryDirectory() as w:
                    verdict, info = run_both(nso, name, a.nxrewrite, tables, w, env)
                print(f'{label} {name}: {verdict}' + (f' {info}' if info else ''))
                bad += verdict not in ('ok', 'both failed')
        # Paper Mario: The Thousand-Year Door 1.0.1's main build ID with the word its FRAME_STEP stub replaces: the stub runs inside a whole rewrite
        nso = os.path.join(t, 'fs.nso')
        import json
        fs_bid = '0effe4af1dec3a7966b934d4a7c3d2bf'
        want = {0x2e77f8: '604600bd'}   # the stub's own site, then the build's registered cuts: the original bytes where each one expects them
        for off, old, _, _ in json.load(open(tables))['cuts'].get(fs_bid, []): want[off] = old
        tail = '.balign 4\n' + ''.join(f'.org {off:#x}\n.byte ' + ', '.join(f'0x{old[i:i + 2]}' for i in range(0, len(old), 2)) + '\n' for off, old in sorted(want.items())) + ' ret\n'
        data, _ = synth_nso.build(7, tail_asm=tail, build_id=fs_bid, room_after_key_page=True)
        open(nso, 'wb').write(data)
        with tempfile.TemporaryDirectory() as w:
            verdict, info = run_both(nso, 'main', a.nxrewrite, tables, w, env)
        print(f'frame step main: {verdict}' + (f' {info}' if info else ''))
        bad += verdict != 'ok'
        for seed in range(a.big):
            nso = os.path.join(t, f'big{seed}.nso')
            data, _ = synth_nso.build(3000 + seed, big=True)
            open(nso, 'wb').write(data)
            with tempfile.TemporaryDirectory() as w:
                verdict, info = run_both(nso, 'main', a.nxrewrite, tables, w, env)
            print(f'big function {seed} main: {verdict}' + (f' {info}' if info else ''))
            bad += verdict not in ('ok', 'both failed')
        for seed in range(a.profiles):
            for label, nso, extra in profile_cases(5000 + seed, t):
                e = dict(env, **extra)
                ptables = os.path.join(t, 'ptables.json')
                subprocess.run([sys.executable, os.path.join(HERE, 'convert_patches.py'), NX, ptables], check=True, capture_output=True, env=e)
                with tempfile.TemporaryDirectory() as w:
                    verdict, info = run_both(nso, 'main', a.nxrewrite, ptables, w, e)
                print(f'{label} main: {verdict}' + (f' {info}' if info else ''))
                bad += verdict not in ('ok', 'both failed')
        for path in a.nso:
            name = a.name or os.path.basename(path).split('.')[0]
            with tempfile.TemporaryDirectory() as w:
                verdict, info = run_both(path, name, a.nxrewrite, tables, w, env)
            print(f'{path} {name}: {verdict}' + (f' {info}' if info else ''))
            bad += verdict not in ('ok', 'both failed')
    print('identical' if not bad else f'[RED] {bad} cases differ')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
