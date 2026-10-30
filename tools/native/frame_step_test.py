#!/usr/bin/env python3
"""Checks every C# FRAME_STEP stub (FrameSteps.Generated.cs, through nxrewrite --frame-step) against nxnative's Python one, on recording contexts at several patch
positions and state pages: the same words emitted, the same sites asserted and the same words put, in the same order.
Usage: frame_step_test.py --nxrewrite <path>"""
import argparse, glob, importlib.util, os, subprocess, sys, types

HERE = os.path.dirname(os.path.abspath(__file__))
NX = os.path.normpath(os.path.join(HERE, '..', '..', 'src', 'nxnative'))
sys.path.insert(0, os.path.join(NX, 'dm', 'tools'))


def python_events(fn, base, state):
    ev, n = [], [0]
    def emit(w): ev.append(f'emit {w & 0xffffffff:08x}'); n[0] += 1
    ctx = types.SimpleNamespace(here=lambda: base + 4 * n[0], emit=emit, site=lambda off, orig: ev.append(f'site {off:x} {orig}'),
                                put=lambda off, words, why: ev.append(f'put {off:x} {",".join(f"{w & 0xffffffff:08x}" for w in words)} {why}'), state=state, render_scale=0)
    fn(ctx)
    return ev + [f'render_scale {ctx.render_scale}']


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--nxrewrite', required=True); a = ap.parse_args()
    bad = 0
    # patch positions: right after a small image, an unaligned one, a FAR front area (negative), one near the ±128 MB reach; state pages after the key page
    spots = [(0x2a00000, 0x2a10000), (0x2a00004, 0x29fc000), (-0x1000000, 0x7208000), (0x7ff0000, 0x2000000)]
    for path in sorted(glob.glob(os.path.join(NX, 'dm', 'games', '*', 'patches.py'))):
        spec = importlib.util.spec_from_file_location('p', path); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        for bid, fn in getattr(m, 'FRAME_STEP', {}).items():
            for base, state in spots:
                try: want = python_events(fn, base, state)
                except AssertionError as e: want = [f'assert {e}']
                r = subprocess.run([a.nxrewrite, '--frame-step', bid, f'{base & 0xffffffffffffffff:x}' if base >= 0 else f'-{-base:x}', f'{state:x}'], capture_output=True, text=True)
                got = r.stdout.splitlines() if r.returncode == 0 else [f'failed {r.stderr.strip().splitlines()[:1]}']
                ok = got == want
                bad += not ok
                print(f'{os.path.basename(os.path.dirname(path))} {bid} base {base:#x}: {"ok" if ok else "DIFFER"} ({len(want)} events)')
                if not ok:
                    for i, (x, y) in enumerate(zip(want, got)):
                        if x != y: print(f'  first difference at {i}: python {x!r} c# {y!r}'); break
                    else: print(f'  lengths {len(want)} / {len(got)}')
    print('identical' if not bad else f'[RED] {bad} differ')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
