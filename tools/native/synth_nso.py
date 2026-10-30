#!/usr/bin/env python3
"""Synthetic Switch code modules for checking MeloNX.Native.Prep's rewriter against nxnative's patch_nso.py without game files.
A module is AArch64 assembly (clang --target=aarch64-linux-gnu, one .text section) laid out as an NSO: text, ro and data at page-aligned labels, MOD0, an eh_frame
with one FDE per function, an eh_frame_hdr, a dynamic section and a symbol table. Its functions are drawn at random from templates of every rewrite site patch_nso.py
knows (x18 uses, system registers, SVCs, exclusive windows, jump tables of several forms, tail calls, spin waits, observation gate symbols).
Usage: synth_nso.py <seed> <out.nso> [--far]   (prints the build ID)"""
import hashlib, os, random, struct, subprocess, sys, tempfile

R_ADR_PREL_PG_HI21, R_ADD_ABS_LO12_NC, R_LDST64_ABS_LO12_NC, R_LDST32_ABS_LO12_NC, R_ABS64 = 275, 277, 286, 285, 257


def assemble(src):
    """flat image of the .text section, relocations applied as if it were loaded at 0"""
    with tempfile.TemporaryDirectory() as t:
        s, o = os.path.join(t, 'm.s'), os.path.join(t, 'm.o')
        open(s, 'w').write(src)
        subprocess.run(['clang', '--target=aarch64-linux-gnu', '-c', s, '-o', o], check=True)
        d = open(o, 'rb').read()
    shoff = struct.unpack_from('<Q', d, 0x28)[0]; shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x3a)
    secs = [struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * shentsize) for i in range(shnum)]
    name = lambda off: d[secs[shstrndx][4] + off:d.index(b'\0', secs[shstrndx][4] + off)].decode()
    by = {name(s[0]): s for s in secs}
    text = bytearray(d[by['.text'][4]:by['.text'][4] + by['.text'][5]])
    symtab = by['.symtab']; syms = [struct.unpack_from('<IBBHQQ', d, symtab[4] + i * 24) for i in range(symtab[5] // 24)]
    if '.rela.text' in by:
        r = by['.rela.text']
        for i in range(r[5] // 24):
            off, info, add = struct.unpack_from('<QQq', d, r[4] + i * 24)
            typ, si = info & 0xffffffff, info >> 32
            S = syms[si][4] + add
            w = struct.unpack_from('<I', text, off)[0]
            if typ == R_ADR_PREL_PG_HI21:
                imm = ((S & ~0xfff) - (off & ~0xfff)) >> 12
                w = (w & 0x9f00001f) | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5)
            elif typ == R_ADD_ABS_LO12_NC: w = (w & ~(0xfff << 10)) | ((S & 0xfff) << 10)
            elif typ == R_LDST64_ABS_LO12_NC: w = (w & ~(0xfff << 10)) | (((S & 0xfff) >> 3) << 10)
            elif typ == R_LDST32_ABS_LO12_NC: w = (w & ~(0xfff << 10)) | (((S & 0xfff) >> 2) << 10)
            elif typ == R_ABS64: struct.pack_into('<Q', text, off, S); continue
            else: raise SystemExit(f'relocation type {typ}')
            struct.pack_into('<I', text, off, w)
    labels = {}
    strt = by['.strtab']
    for nm, info, other, shndx, value, size in syms:
        if nm: labels[d[strt[4] + nm:d.index(b'\0', strt[4] + nm)].decode()] = value
    return text, labels


# ---- function templates: each returns assembly for one function named f ----
def plain(r, f):
    ops = ['add x18, x0, x1', 'ldr x0, [x18, #8]', 'str x18, [x1, #16]', 'mov x18, x2', 'adds w18, w18, #8', 'ldp x18, x19, [sp, #16]', 'stp x17, x18, [x0]',
           'eor x3, x18, x4', 'ldr w5, [x18, x6, lsl #2]', 'str x18, [sp, #-16]!', 'ldr x18, [sp], #16', 'stp x18, x19, [sp, #-32]!', 'ldp x18, x19, [sp], #32',
           'csel x18, x0, x1, eq', 'ubfx x18, x0, #4, #8', 'lsl x18, x18, #3', 'ldrb w18, [x0, #1]', 'fmov d0, x18', 'madd x18, x0, x1, x18']
    body = '\n'.join(r.choice(ops) for _ in range(r.randint(1, 6)))
    return f'{f}:\n{body}\n ret\n'

def sysregs(r, f):
    ops = ['mrs x0, tpidr_el0', 'msr tpidr_el0, x1', 'mrs x2, tpidrro_el0', 'mrs x16, tpidrro_el0', 'svc #0x7', 'svc #0x1', 'mrs x3, cntpct_el0', 'mrs x4, cntvct_el0',
           'mrs x5, ctr_el0', 'sub sp, sp, x3', 'msr tpidr_el0, x16', 'mrs x17, tpidr_el0']
    return f'{f}:\n' + '\n'.join(r.choice(ops) for _ in range(r.randint(1, 5))) + '\n add sp, sp, #0\n ret\n'

def sp_site(r, f):
    return f'{f}:\n mov x18, sp\n sub x18, x18, x0\n mov sp, x18\n ret\n'

def cond(r, f):
    c = r.choice(['cbz x18, 1f', 'cbnz w18, 1f', 'tbnz w18, #3, 1f', 'tbz x18, #40, 1f'])
    return f'{f}:\n {c}\n add x0, x0, #1\n1: ret\n'

def pcrel(r, f):
    return f'{f}:\n adr x18, 1f\n adrp x18, {f}\n1: blr x18\n ret\n'

def window(r, f):
    k = r.randint(0, 2)
    if k == 0: return f'{f}:\n1: ldaxr w18, [x0]\n add w18, w18, #1\n stlxr w3, w18, [x0]\n cbnz w3, 1b\n ret\n'
    if k == 1: return f'{f}:\n1: ldaxr w18, [x0]\n cmp w18, w1\n b.ne 2f\n stlxr w3, w2, [x0]\n cbnz w3, 1b\n2: ret\n'
    return f'{f}:\n1: ldxr x9, [x0]\n mov x18, x9\n stxr w3, x18, [x0]\n cbnz w3, 1b\n ret\n'

def lock(r, f):
    return f'{f}:\n1: ldxr w8, [x0]\n cbnz w8, 1b\n stxr w9, w10, [x0]\n cbnz w9, 1b\n ret\n'

def byte_table(r, f):
    n = r.randint(2, 6)
    cases = '\n'.join(f'{f}_c{i}: mov x0, #{i}\n b {f}_end' for i in range(n))
    entries = ', '.join(str(2 * i) for i in range(n))   # cases are two instructions each: target = base + 4 × entry
    return (f'{f}:\n cmp w0, #{n - 1}\n b.hi {f}_end\n adrp x16, {f}_tbl\n add x16, x16, :lo12:{f}_tbl\n adr x18, {f}_c0\n ldrb w17, [x16, w0, uxtw]\n'
            f' add x18, x18, x17, lsl #2\n br x18\n{cases}\n{f}_end: ret\n'), f'{f}_tbl: .byte {entries}\n .balign 4\n'

def offset_table(r, f):
    n = r.randint(2, 6)
    cases = '\n'.join(f'{f}_c{i}: mov x0, #{i}\n b {f}_end' for i in range(n))
    entries = '\n'.join(f' .word {f}_c{i} - {f}_tbl' for i in range(n))
    idx = r.choice(['w18', 'w0'])
    pre = ' mov w18, w0\n' if idx == 'w18' else ''
    ld = f' ldrsw x18, [x17, x18, lsl #2]\n' if idx == 'w18' else f' ldrsw x18, [x17, x0, lsl #2]\n'
    return (f'{f}:\n{pre} cmp {idx}, #{n - 1}\n b.hi {f}_end\n adrp x17, {f}_tbl\n add x17, x17, :lo12:{f}_tbl\n{ld} add x18, x18, x17\n br x18\n{cases}\n{f}_end: ret\n'), \
           f'{f}_tbl:\n{entries}\n'

def tail(r, f):
    return f'{f}:\n ldr x16, [sp]\n ldr x18, [x0, #0x18]\n br x18\n'

def spin(r, f):
    k = r.randint(0, 3)
    if k == 0: return f'{f}:\n1: ldr w8, [x0]\n cbz w8, 1b\n ret\n'
    if k == 1: return f'{f}:\n1: ldrb w8, [x0, #4]\n cmp w8, #1\n b.eq 1b\n ret\n'
    if k == 2: return f'{f}:\n mov x1, #0\n1: add x1, x1, #1\n cmp x1, #10\n b.ne 1b\n ret\n'
    return f'{f}:\n1: ldr w8, [x0]\n str wzr, [x1]\n cbz w8, 1b\n ret\n'

def filler(r, f):
    ops = ['add x0, x0, #1', 'mov x1, x2', 'ldr x3, [x4]', 'str x5, [x6, #8]', 'nop', 'bl ' + f, 'cmp x0, #3', 'csinc x2, x3, x4, ne']
    return f'{f}:\n' + '\n'.join(r.choice(ops) for _ in range(r.randint(2, 12))) + '\n ret\n'

TEMPLATES = [plain, plain, plain, sysregs, sp_site, cond, pcrel, window, lock, byte_table, offset_table, tail, spin, spin, filler]

VAMM = '''_ZN2nn2os6detail11VammManager21AllocateAddressRegionEPmm:
 stp x29, x30, [sp, #-32]!
 mov x29, sp
 mov x19, x1
 add x0, x2, #0x1000
 str x0, [x19]
 ldp x29, x30, [sp], #32
 ret
_ZN2nn2os6detail11VammManager17FreeAddressRegionEm:
 mov x0, x1
 ret
_ZN2nn3mem17StandardAllocator10InitializeEPvm:
 stp x29, x30, [sp, #-16]!
 ldp x29, x30, [sp], #16
 ret
'''


def build(seed, far=False, nfunc=None, tail_asm='', build_id=None, room_after_key_page=False, big=False):
    r = random.Random(seed)
    nfunc = nfunc or r.randint(20, 120)
    funcs, ro = [], []
    for i in range(nfunc):
        out = r.choice(TEMPLATES)(r, f'f{i}')
        if isinstance(out, tuple): funcs.append(out[0]); ro.append(out[1])
        else: funcs.append(out)
    funcs.append(f'f{nfunc}:\n ret\n'); nfunc += 1   # the last function runs into the page padding (udf words); keep a plain one there
    with_vamm = r.random() < 0.5
    names = [f'f{i}' for i in range(nfunc)]
    if with_vamm: names += ['_ZN2nn2os6detail11VammManager21AllocateAddressRegionEPmm', '_ZN2nn2os6detail11VammManager17FreeAddressRegionEm', '_ZN2nn3mem17StandardAllocator10InitializeEPvm']
    data_block = r.random() < 0.3
    unwound_gap = r.random() < 0.3   # code before the first FDE: one function to func_of
    src = ['.text', '_start: b f0', ' .word mod0 - _start']
    if unwound_gap: src += ['nofde:', ' add x18, x0, x1', ' mov x18, x2', ' ret']
    if big:   # 400 KB of code before the first FDE: one function to func_of, analysed in pieces (patch_nso.py BIG_FN)
        for k in range(2000):
            body = r.choice([t for t in TEMPLATES if t is not tail])(r, f'big{k}')   # a br x18 tail call is only one at a function's end
            src.append(body[0] if isinstance(body, tuple) else body)
            if isinstance(body, tuple): ro.append(body[1])
            src.append(' .fill 40, 4, 0xd503201f')
    if data_block: src += ['datablk:'] + [' .word 0xffffffff, 0xd2800012, 0xffffffff, 0x8b010012'] * 0x400
    src += funcs
    if with_vamm: src.append(VAMM)
    src.append(tail_asm)
    src.append('text_end:')
    src += ['.balign 0x1000', 'ro_start:'] + ro
    # eh_frame: one CIE, one FDE per function (pc-relative begin, absolute range)
    src += ['.balign 8', 'eh_frame:', 'cie: .word cie_end - cie - 4', ' .word 0', ' .byte 1', ' .asciz "zR"', ' .byte 1', ' .byte 0x78', ' .byte 30', ' .byte 1', ' .byte 0x1b', ' .balign 4', 'cie_end:']
    nxt_of = {n: (names[i + 1] if i + 1 < len(names) else 'text_end') for i, n in enumerate(names)}
    for i, n in enumerate(names):
        nxt = nxt_of[n]
        src += [f'fde{i}: .word fde{i}_end - fde{i} - 4', f' .word fde{i} + 4 - cie', f' .word {n} - .', f' .word {nxt} - {n}', ' .byte 0', ' .balign 4', f'fde{i}_end:']
    src += [' .word 0', '.balign 4', 'eh_hdr:', ' .byte 1, 0x1b, 0x03, 0x3b', ' .word eh_frame - .', f' .word {len(names)}']
    for i, n in enumerate(names): src += [f' .word {n} - eh_hdr', f' .word fde{i} - eh_hdr']
    src += ['eh_hdr_end:']
    # symbol names and table
    src += ['.balign 8', 'symtab:', ' .xword 0, 0, 0']
    for i, n in enumerate(names): src += [f' .word str_{i} - strtab', ' .byte 0x12, 0', ' .hword 1', f' .xword {n}', f' .xword {nxt_of[n]} - {n}']
    src += ['strtab:', ' .byte 0'] + [f'str_{i}: .asciz "{n}"' for i, n in enumerate(names)] + ['strtab_end:']
    src += ['.balign 0x1000', 'data_start:', 'mod0:', ' .ascii "MOD0"', ' .word dynamic - mod0', ' .word bss_start - mod0', ' .word bss_start - mod0',
            ' .word eh_hdr - mod0', ' .word eh_hdr_end - mod0', '.balign 8', 'dynamic:', ' .xword 6, symtab', ' .xword 5, strtab', ' .xword 10, strtab_end - strtab', ' .xword 0, 0',
            ' .balign 0x1000', 'bss_start:']
    text, L = assemble('\n'.join(src) + '\n')
    text_size, ro_size, data_size = L['ro_start'], L['data_start'] - L['ro_start'], len(text) - L['data_start']
    data_size = (data_size + 0xfff) & ~0xfff
    text += bytes(L['data_start'] + data_size - len(text))
    bss = r.choice([0x1000, 0x10000]) if not far else 0x7200000
    if room_after_key_page:   # the image + bss end 16 KB past a 64 KB boundary: the page after the key page (FRAME_STEP's state page) comes before the patch area
        bss = (0x4000 - len(text)) % 0x10000 or 0x10000
    return nso(text, (0, text_size), (L['ro_start'], ro_size), (L['data_start'], data_size), bss, seed, build_id)


def nso(img, t, ro, d, bss, seed, build_id=None):
    import lz4.block
    build_id = (bytes.fromhex(build_id) + bytes(0x20))[:0x20] if build_id else hashlib.sha256(f'synth{seed}'.encode()).digest()[:0x20]
    segs, blobs, off = [], [], 0x100
    for mo, sz in (t, ro, d):
        raw = bytes(img[mo:mo + sz]); comp = lz4.block.compress(raw, store_size=False)
        if len(comp) >= sz: comp = raw   # stored as is (its compression flag cleared below)
        segs.append((off, mo, sz, len(comp), hashlib.sha256(raw).digest())); blobs.append(comp); off += len(comp)
    h = bytearray(0x100)
    flags = 0b111000 | sum(1 << i for i, (_, _, sz, c, _) in enumerate(segs) if c < sz)
    h[0:4] = b'NSO0'; struct.pack_into('<I', h, 0xc, flags)
    for i, (fo, mo, sz, c, _) in enumerate(segs): struct.pack_into('<III', h, 0x10 + i * 0x10, fo, mo, sz)
    struct.pack_into('<I', h, 0x3c, bss); h[0x40:0x60] = build_id
    for i, (_, _, _, c, _) in enumerate(segs): struct.pack_into('<I', h, 0x60 + 4 * i, c)
    for i, (*_, dg) in enumerate(segs): h[0xa0 + 0x20 * i:0xc0 + 0x20 * i] = dg
    return bytes(h) + b''.join(blobs), build_id[:0x10].hex()


if __name__ == '__main__':
    data, bid = build(int(sys.argv[1]), far='--far' in sys.argv)
    open(sys.argv[2], 'wb').write(data)
    print(bid)
