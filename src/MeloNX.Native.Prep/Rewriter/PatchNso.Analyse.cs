using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static MeloNX.Native.Prep.Rewriter.NsoAsm;

namespace MeloNX.Native.Prep.Rewriter
{
    // patch_nso.py from "Function boundaries" on: the scan for rewrite sites, the per-function analysis, emitting every site, observation gates, frame steps and the output files
    public sealed partial class PatchNso
    {
        private const long BIG_FN = 0x40000, PIECE = 0x40000, PIECE_B = 0x10000;
        private const int OBS_UE_MALLOC = 21, OBS_REGION_ASK = 22, OBS_REGION_GOT = 23, OBS_REGION_FREE = 24, OBS_STDALLOC_INIT = 25;

        private long Rd(long o, int enc, long ehs, out int sz)
        {
            int fmt = enc & 0xF, app = enc & 0x70;
            long v;
            switch (fmt)
            {
                case 0x3: v = NsoCode.U32(IMG, o); sz = 4; break;
                case 0xB: v = NsoCode.I32(IMG, o); sz = 4; break;
                case 0x4: v = (long)NsoCode.U64(IMG, o); sz = 8; break;
                default: throw new KeyNotFoundException($"pointer encoding {fmt}");
            }
            if (app == 0x10) v += o;
            if (app == 0x30) v += ehs;
            return v;
        }

        private void Analyse()
        {
            patchFront = new List<byte>(); patchBack = new List<byte>();
            patch = patchFront; PATCH_BASE = PATCH_OFF;

            // ---- Function boundaries (eh_frame_hdr) ----
            long m0 = W(4);
            RewriteAssertion.Check(NsoCode.IsMod0(IMG, m0));
            long ehs = m0 + NsoCode.I32(IMG, m0 + 16);
            int penc = IMG[ehs + 1], cenc = IMG[ehs + 2], tenc = IMG[ehs + 3];
            long o = ehs + 4;
            Rd(o, penc, ehs, out int s0); o += s0;
            long nfde = Rd(o, cenc, ehs, out int s1); o += s1;
            var st = new HashSet<long>();
            for (long i = 0; i < nfde; i++)
            {
                long a = Rd(o, tenc, ehs, out int sa); o += sa;
                Rd(o, tenc, ehs, out int sb); o += sb;
                st.Add(a);
            }
            starts = st.Where(x => x < TEXT_END).OrderBy(x => x).ToList();

            // ---- Linear scan to find all rewrite points ----
            DATA_BLOCKS = NsoCode.DataBlocks(IMG.AsSpan(0, IMGLen).ToArray(), TEXT_END, md);
            CODE_RANGES = new List<(long, long)>();
            var los = new[] { 0L }.Concat(DATA_BLOCKS.Select(b => b.E)).ToList();
            var his = DATA_BLOCKS.Select(b => b.S).Concat(new[] { TEXT_END }).ToList();
            for (int i = 0; i < los.Count; i++) CODE_RANGES.Add((los[i], his[i]));
            foreach (long a in AcquireLockSites())
            {
                PutW(a, W(a) | 0x8000);
                Stat("acquire_lock");
            }
            x18 = new HashSet<long>();
            long scanned = 0, toScan = Math.Max(1, CODE_RANGES.Sum(r => r.E - r.S));
            foreach (var (s, e) in CODE_RANGES) { x18.UnionWith(X18Words(s, e, scanned, toScan)); scanned += e - s; }
            var SPIN_TOPS = new HashSet<uint> { 0x16, 0x17, 0x54, 0x34, 0x35, 0xB4, 0xB5, 0x36, 0x37, 0xB6, 0xB7 };
            foreach (var (s, e) in CODE_RANGES)
            {
                for (long a = s; a < e; a += 4)
                {
                    uint w = W(a);
                    if (SPIN_TOPS.Contains(w >> 24))
                    {
                        uint t = w >> 24; long d;
                        if (t is 0x16 or 0x17) d = ((long)(w & 0x3FFFFFF) - (1L << 26)) * 4;
                        else if ((t & 0x7E) == 0x36) d = (w & 0x40000) != 0 ? ((long)((w >> 5) & 0x3FFF) - (1L << 14)) * 4 : 4;
                        else if (t == 0x54) d = (w & 0x800000) != 0 && (w & 0x10) == 0 ? ((long)((w >> 5) & 0x7FFFF) - (1L << 19)) * 4 : 4;
                        else d = (w & 0x800000) != 0 ? ((long)((w >> 5) & 0x7FFFF) - (1L << 19)) * 4 : 4;
                        if (-SPIN_WIN <= d && d <= 0)
                        {
                            if (!spin_cand.TryGetValue(a + d, out var l)) spin_cand[a + d] = l = new List<long>();
                            l.Add(a);
                        }
                    }
                    if ((w & 0xFFE0001F) == 0xD4000001) { kinds[a] = ("svc", (w >> 5) & 0xFFFF); continue; }
                    if ((w & 0xFFFFFFE0) == 0xD53BD040) { kinds[a] = ("tpidr_r", 0); continue; }
                    if ((w & 0xFFFFFFE0) == 0xD51BD040) { kinds[a] = ("tpidr_w", 0); continue; }
                    if ((w & 0xFFFFFFE0) == 0xD53BD060) { kinds[a] = ("tpidrro_r", 0); continue; }
                    if ((w & 0xFFFFFFE0) == 0xD53BE020) { kinds[a] = ("cntpct", w & 31); continue; }
                    if ((w & 0xFFFFFFE0) == 0xD53BE040) { kinds[a] = ("cntvct", w & 31); continue; }
                    if ((w & 0xFFFFFFE0) == 0xD53B0020) { kinds[a] = ("ctr", w & 31); continue; }
                    if ((w & 0xFFE0FFFF) == 0xCB2063FF && ((w >> 16) & 31) != 18) { kinds[a] = ("sp_align", (w >> 16) & 31); continue; }
                    if (x18.Contains(a)) kinds[a] = ("x18", 0);
                }
            }

            // ---- Per function: windows and jump tables ----
            var funcs = kinds.Where(kv => kv.Value.Kind == "x18").Select(kv => FuncOf(kv.Key)).Distinct().OrderBy(f => f).ToList();
            var farInto = new List<(long At, long To)>(); var rmidAll = new HashSet<long>();
            if (funcs.Any(f => f.E - f.S > BIG_FN))
            {
                var sites18 = kinds.Where(kv => kv.Value.Kind == "x18").Select(kv => kv.Key).OrderBy(x => x).ToList();
                var split = new List<(long, long)>();
                foreach (var (fa, fb) in funcs)
                {
                    if (fb - fa <= BIG_FN) { split.Add((fa, fb)); continue; }
                    var (ps, far) = Pieces(fa, fb); farInto.AddRange(far);
                    split.AddRange(ps.Where(pq => BisectLeft(sites18, pq.S) < BisectLeft(sites18, pq.E)));
                    Log($"function {Hx(fa)}..{Hx(fb)} ({(fb - fa) / 1048576.0:F2} MB, no unwind entries) analysed in {ps.Count} pieces");
                }
                funcs = split;
            }
            for (int i = 0; i < funcs.Count; i++)
            {
                if ((i & 255) == 0) Opt.Progress?.Invoke(0.4 + 0.5 * i / funcs.Count);
                AnalyseFunction(funcs[i].S, funcs[i].E, rmidAll);
            }
            Opt.Progress?.Invoke(0.9);
            if (farInto.Count > 0)
            {
                var winMid = windows.SelectMany(w => w.Skip(1)).Select(x => x.Address).ToHashSet();
                foreach (var (at, to) in farInto) RewriteAssertion.Check(!winMid.Contains(to) && !rmidAll.Contains(to), $"far branch into a window or retry block {at:x}");
                foreach (var (at, tgt) in tabjumps) RewriteAssertion.Check(!tgt.Any(t => winMid.Contains(t) || rmidAll.Contains(t)), $"jump table target into a window or retry block {at:x}");
            }

            // ---- Emit every site ----
            foreach (var wseg in windows)
            {
                UseArea(wseg[0].Address); var (s, lo, _) = SiteWindow(wseg); Stat("window"); PutBranch(lo, s);
            }
            foreach (var parts in retries)
            {
                UseArea(parts[0].Seg[0].Address); long s = SiteRetryWindow(parts); Stat("retry_window"); PutBranch(parts[0].Seg[0].Address, s);
            }
            foreach (var (a, (k, arg)) in kinds)
            {
                if (done.Contains(a)) continue;
                UseArea(a);
                var ins = Dis(W(a), a);
                long s;
                if (k == "x18")
                {
                    string m = ins.Mnemonic;
                    if (m == "br" && tailcalls.Contains(a)) { s = SiteBrCall(ins); Stat("br_call"); }
                    else if (m == "br") { s = tabjumps.TryGetValue(a, out var tj) ? SiteBrTab(ins, tj) : SiteBr(ins, jumps[a].Base, jumps[a].Width); Stat("br"); }
                    else if (m is "cbz" or "cbnz" or "tbz" or "tbnz") { s = SiteCond(ins); Stat("cond"); }
                    else if (m is "adr" or "adrp") { s = SitePcrel(ins); Stat("pcrel"); }
                    else if (m == "blr") { s = SiteBlr(ins); Stat("blr"); }
                    else if (Rx(@"\A(sp|wsp),").IsMatch(ins.OpStr)) { s = SiteSp(ins); Stat("sp"); }
                    else if (m is "ret" or "b" or "bl" || (m == "ldr" && !ins.OpStr.Contains('['))) throw new InvalidOperationException($"{a:x} {m} {ins.OpStr}");
                    else { s = SitePlain(ins); Stat("plain"); }
                }
                else if (k == "tpidr_r") { s = SiteSysregRead(ins, "KTLS"); Stat(k); }
                else if (k == "tpidrro_r") { s = SiteSysregRead(ins, "KTLR"); Stat(k); }
                else if (k == "tpidr_w") { s = SiteTpidrWrite(ins); Stat(k); }
                else if (k == "svc") { s = SiteGate(ins, "svc", arg); Stat(k); }
                else if (k is "cntpct" or "cntvct") { s = SiteGate(ins, k, arg); Stat(k); }
                else if (k == "sp_align") { s = SiteSpAlign(ins, (int)arg); Stat(k); }
                else if (k == "ctr")
                {
                    RewriteAssertion.Check(arg != 18, $"{a:x} mrs x18, ctr_el0");
                    PutW(a, 0xD2A00080u | (uint)arg); Stat(k); continue;
                }
                else throw new InvalidOperationException(k);
                PutBranch(a, s);
            }

            // ---- Observation gates ----
            obs = new List<ObsEntry>(PATCHES.Obs.GetValueOrDefault(BUILD_ID) ?? new List<ObsEntry>());
            var startSet = starts.ToHashSet();
            foreach (var ob in obs)
            {
                long off = ob.Offset;
                uint w = W(off);
                RewriteAssertion.Check($"{w:x8}" == ob.Word, $"observation gate original instruction mismatch {Hx(off)}: {w:x8}");
                bool afterBl = off >= 4 && W(off - 4) >> 26 == 0x25;
                RewriteAssertion.Check(startSet.Contains(off) || afterBl || ScratchDead(off), $"observation gate neither at a function entry, after a bl nor before a call with x9–x17 unread {Hx(off)}");
                RewriteAssertion.Check(off < TEXT_END && !kinds.ContainsKey(off) && !InWindow(off), $"observation gate conflicts with a rewrite site {Hx(off)}");
                UseArea(off); PutBranch(off, SiteObs(off, ob.Id, w)); Stat("obs");
            }
            var (regionObs, whyNot) = RegionGates(startSet);
            if (whyNot != null) Log($"{NAME}: no address region gates: {whyNot}");
            regionObs.AddRange(StdallocGates());
            if (UE_CALL != null)
            {
                RewriteAssertion.Check(!kinds.ContainsKey(UE_CALL.Value) && !InWindow(UE_CALL.Value), $"FMallocBinned3 gate conflicts with a rewrite site {Hx(UE_CALL.Value)}");
                regionObs.Add(new ObsEntry(UE_CALL.Value, OBS_UE_MALLOC, $"{NOP:x8}", "FMallocBinned3 constructor call (cut): the object in x0; the host puts its allocator's vtable in (hle_uemalloc.c)"));
            }
            foreach (var ob in regionObs) { UseArea(ob.Offset); PutBranch(ob.Offset, SiteObs(ob.Offset, ob.Id, Convert.ToUInt32(ob.Word, 16))); Stat("obs"); }
            obs.AddRange(regionObs);

            // ---- Frame step in whole vsyncs ----
            FS_STATE_OFF = 0; RENDER_SCALE = 0;
            if (PATCHES.FrameStep.Contains(BUILD_ID) && NAME == "main")
            {
                FS_STATE_OFF = KEY_PAGE_OFF + 0x4000;
                if (FAR) IMAGE_SIZE = FS_STATE_OFF + 0x4000;
                bool zero = FS_STATE_OFF >= IMGLen || IMG.AsSpan((int)FS_STATE_OFF, IMGLen - (int)FS_STATE_OFF).IndexOfAnyExcept((byte)0) < 0;
                RewriteAssertion.Check(FS_STATE_OFF % 0x1000 == 0 && (FAR || FS_STATE_OFF + 0x40 <= PATCH_OFF) && zero, "frame step state page");
            }
            if (FS_STATE_OFF != 0)
            {
                UseArea(0);
                var ctx = new FrameStepContext(this);
                FrameSteps.Run(BUILD_ID, PATCHES.FrameStepSources.GetValueOrDefault(BUILD_ID), ctx);
                RENDER_SCALE = ctx.RenderScale;
            }

            // ---- Spin waits ----
            SpinWaits();
        }

        // The context a FRAME_STEP stub gets (patch_nso.py: here, emit, site, put, state, render_scale)
        public sealed class FrameStepContext : IFrameStepContext
        {
            private readonly PatchNso _p;
            internal FrameStepContext(PatchNso p) { _p = p; }
            public int RenderScale { get; set; }
            public long State => _p.FS_STATE_OFF;
            public long Here() => _p.Here();
            public void Emit(long w) => _p.Emit((uint)w);
            public void Site(long off, string orig)
            {
                byte[] ob = Convert.FromHexString(orig);
                RewriteAssertion.Check(_p.ImgEq(off, ob), $"frame step original bytes mismatch {Hx(off)}: {_p.ImgHex(off, ob.Length)}");
                for (long o = off; o < off + ob.Length; o += 4)
                    RewriteAssertion.Check(!_p.kinds.ContainsKey(o) && !_p.windows.Any(seg => seg[0].Address <= o && o < seg[^1].Address + 4), $"frame step site is a rewrite site {Hx(o)}");
            }
            public void Put(long off, IReadOnlyList<long> words, string why)
            {
                string old = _p.ImgHex(off, 4 * words.Count);
                for (int i = 0; i < words.Count; i++) _p.PutW(off + 4 * i, (uint)words[i]);
                _p.cuts.Add(new Cut(off, old, _p.ImgHex(off, 4 * words.Count), why)); _p.Stat("frame_step");
            }
        }

        private bool InWindow(long off) => windows.Any(seg => seg[0].Address <= off && off < seg[^1].Address + 4);

        private void PutBranch(long at, long to) => PutW(at, B(at, to));

        private static int BisectLeft(List<long> l, long x) { int i = l.BinarySearch(x); if (i < 0) return ~i; while (i > 0 && l[i - 1] == x) i--; return i; }
        private static int BisectRight(List<long> l, long x) { int i = l.BinarySearch(x); if (i < 0) return ~i; while (i < l.Count && l[i] == x) i++; return i; }

        private List<long> AcquireLockSites()
        {
            var out_ = new List<long>();
            foreach (var (s, e) in CODE_RANGES)
            {
                for (long o = s; o < e - 12; o += 4)
                {
                    uint w = W(o);
                    if ((w & 0xBFFFFC00) != 0x885F7C00) continue;
                    uint c1 = W(o + 4), stx = W(o + 8), c2 = W(o + 12);
                    uint rt = w & 31, rn = (w >> 5) & 31, rs = (stx >> 16) & 31, rk = stx & 31;
                    static bool Cbnz(uint x, uint r, uint back) => (x & 0x7F00001F) == (0x35000000 | r) && ((x >> 5) & 0x7FFFF) == 0x80000 - back;
                    bool fenced = o + 20 <= e && (W(o + 16) is 0xD5033BBF or 0xD50339BF);
                    if (Cbnz(c1, rt, 1) && Cbnz(c2, rs, 3) && (stx & 0xBFE0FC00) == 0x88007C00 && ((stx >> 5) & 31) == rn && rk != 31 && rs != rn && rs != rk && !fenced)
                        out_.Add(o);
                }
            }
            return out_;
        }

        private HashSet<long> X18Words(long lo, long hi, long before = 0, long total = 0)
        {
            var out_ = new HashSet<long>(); long a = lo;
            var r18 = Rx(@"\b[xw]18\b");
            for (int chunk = 0; a < hi; chunk++)
            {
                if (total > 0 && (chunk & 63) == 0) Opt.Progress?.Invoke(0.4 * (before + a - lo) / total);
                long end = Math.Min(hi, a + 0x4000), last = a - 4;
                foreach (var ins in mdLite.Disasm(IMG.AsSpan((int)a, (int)(end - a)), a))
                {
                    last = ins.Address;
                    if (r18.IsMatch(ins.OpStr)) out_.Add(ins.Address);
                }
                a = last + 4 >= end ? last + 4 : last + 8;
            }
            return out_;
        }

        private (long S, long E) FuncOf(long a)
        {
            int i = BisectRight(starts, a) - 1;
            if (i >= 0) return (starts[i], i + 1 < starts.Count ? starts[i + 1] : TEXT_END);
            if (starts.Count > 0)
            {
                long m = 0;
                foreach (var (s, e) in DATA_BLOCKS) if (e <= a && e > m) m = e;
                return (m, starts[0]);
            }
            return (a, a + 4);
        }

        private List<Insn> DisasmFn(long fa, long fb)
        {
            var out_ = new List<Insn>(); long a = fa;
            while (a < fb)
            {
                var l = md.Disasm(IMG.AsSpan((int)a, (int)(fb - a)), a);
                out_.AddRange(l);
                a = (l.Count > 0 ? l[^1].Address + 4 : a) + 4;
            }
            return out_;
        }

        private (List<(long S, long E)> Pieces, List<(long, long)> Far) Pieces(long fa, long fb)
        {
            int n = (int)((fb - fa) / 4);
            var cross = new int[n + 2]; var far = new List<(long, long)>();
            for (int i = 0; i < n; i++)
            {
                uint x = W(fa + 4L * i), t = x >> 24; long d;
                if ((t == 0x54 && (x & 0x10) == 0) || (t & 0x7E) == 0x34) { d = (x >> 5) & 0x7FFFF; d -= (d & 0x40000) << 1; }
                else if ((t & 0x7E) == 0x36) { d = (x >> 5) & 0x3FFF; d -= (d & 0x2000) << 1; }
                else if ((t & 0x7C) == 0x14)
                {
                    d = x & 0x3FFFFFF; d -= (d & 0x2000000) << 1;
                    if ((t & 0x80) != 0 || 4 * Math.Abs(d) > PIECE_B) { far.Add((fa + 4L * i, fa + 4 * (i + d))); continue; }
                }
                else continue;
                long lo = Math.Max(Math.Min(i, i + d), -1), hi = Math.Min(Math.Max(i, i + d), n);
                cross[lo + 1] += 1; cross[hi + 1] -= 1;
            }
            var cand = new List<long>(); int c = 0;
            for (int k = 0; k < n; k++)
            {
                c += cross[k];
                uint x = k > 0 ? W(fa + 4L * (k - 1)) : 0;
                if (k > 0 && c == 0 && ((x & 0xFFFFFC1F) is 0xD65F0000 or 0xD61F0000 || x >> 26 == 0x05)) cand.Add(k);
            }
            var cutsK = new List<long>(); long sk = 0;
            while (sk + PIECE / 4 < n)
            {
                int j = BisectRight(cand, sk + PIECE / 4) - 1;
                if (j < 0 || cand[j] <= sk) j = BisectRight(cand, sk + PIECE / 4);
                if (j >= cand.Count) break;
                sk = cand[j]; cutsK.Add(sk);
            }
            var b = new List<long> { 0 }; b.AddRange(cutsK); b.Add(n);
            var ps = new List<(long, long)>();
            for (int i = 0; i + 1 < b.Count; i++) ps.Add((fa + 4 * b[i], fa + 4 * b[i + 1]));
            return (ps, far);
        }

        private void AnalyseFunction(long fa, long fb, HashSet<long> rmidAll)
        {
            var insl = DisasmFn(fa, fb);
            var ws = FindWindows(insl);
            foreach (var wseg in ws) { windows.Add(wseg); foreach (var x in wseg) done.Add(x.Address); }
            for (int j = 0; j < insl.Count; j++)
            {
                var ins = insl[j];
                if (!(ins.Mnemonic == "br" && ins.OpStr == "x18")) continue;
                long? @base = null; long width = 0;
                var ctx = Slice(insl, j - 16, j);
                foreach (var p in Enumerable.Reverse(ctx))
                    if (p.Mnemonic == "adr" && p.OpStr.StartsWith("x18,")) { @base = p.Operands[1].Imm; break; }
                foreach (var p in Enumerable.Reverse(ctx))
                {
                    if (p.Mnemonic == "add" && p.OpStr.StartsWith("x18, x18,") && p.OpStr.Contains("lsl #2"))
                    {
                        string rn = p.RegName(p.Operands[2].Reg); int? idx = rn == "lr" ? 30 : rn == "fp" ? 29 : Num(rn);
                        foreach (var q in Enumerable.Reverse(ctx))
                        {
                            if (q.Mnemonic is "ldrb" or "ldrsb" && Num(q.RegName(q.Operands[0].Reg)) == idx) width = 256;
                            if (q.Mnemonic is "ldrh" or "ldrsh" && Num(q.RegName(q.Operands[0].Reg)) == idx)
                                width = @base is long bb && bb != 0 ? (HalfCount(insl, q, bb) is long h && h != 0 ? h : 65536) : 65536;
                            if (width != 0) break;
                        }
                        break;
                    }
                }
                if (!(@base is long b0 && b0 != 0 && width != 0))
                {
                    var tgt = JumpOffsets(insl, j) ?? JumpAdrOffsets(insl, j);
                    if (tgt == null && TailCall(insl, j)) { tailcalls.Add(ins.Address); continue; }
                    if (tgt == null && JumpBytesFar(insl, j) is { } far) { jumps[ins.Address] = far; continue; }
                    tgt ??= JumpOffsets(insl, j, copyFirst: true, farBase: true);
                    tgt ??= JumpMaskedPred(insl, j);
                    tgt ??= JumpMaskedNot(insl, j);
                    tgt ??= JumpOffsets(insl, j, copyFirst: true, farBase: true, forwardBase: true);
                    RewriteAssertion.Check(tgt != null && tgt.Count > 0, $"jump table {ins.Address:x}");
                    tabjumps[ins.Address] = tgt; continue;
                }
                jumps[ins.Address] = (@base.Value, width);
            }
            var inwin = ws.SelectMany(w => w).Select(x => x.Address).ToHashSet();
            var heads = ws.Select(w => w[0].Address).ToHashSet();
            var rmid = new HashSet<long>();
            for (int k = 0; k < insl.Count; k++)
            {
                var x = insl[k];
                if (!IsDirectBranch(x.Mnemonic)) continue;
                long t = x.Operands[^1].Imm;
                if (inwin.Contains(t) && !heads.Contains(t))
                {
                    var wseg = ws.First(w => w.Any(y => y.Address == t));
                    var rb = x.Mnemonic is not ("b" or "bl") ? RetryBlock(insl, k, wseg) : null;
                    RewriteAssertion.Check(rb != null, $"branch into window {x.Address:x}");
                    var (retry, tail) = rb.Value;
                    RewriteAssertion.Check(!retry.Any(y => done.Contains(y.Address)), $"retry block overlaps a window {retry[0].Address:x}");
                    retries.Add(new List<(List<Insn>, long)> { (retry, x.Address + 4), (tail, wseg[^1].Address + 4) });
                    foreach (var y in retry) done.Add(y.Address);
                    foreach (var y in retry.Skip(1)) rmid.Add(y.Address);
                }
            }
            foreach (var x in insl)
                if (IsDirectBranch(x.Mnemonic)) RewriteAssertion.Check(!rmid.Contains(x.Operands[^1].Imm), $"branch into retry block {x.Address:x}");
            foreach (var (a_, tgt) in tabjumps)
                if (fa <= a_ && a_ < fb) RewriteAssertion.Check(!tgt.Any(t => inwin.Contains(t) && !heads.Contains(t)), $"jump table target into window {a_:x}");
            rmidAll.UnionWith(rmid);
        }

        private bool ScratchDead(long off)
        {
            var written = new HashSet<int?>(); long a = off;
            for (int i = 0; i < 16; i++)
            {
                if (!(0 <= a && a < TEXT_END)) return false;
                var ins = Dis(W(a), a);
                if (ins.Mnemonic is "bl" or "ret") return true;
                if (ins.Mnemonic == "b") { a = ins.Operands[0].Imm; continue; }
                if (ins.Mnemonic is "br" or "blr" or "cbz" or "cbnz" or "tbz" or "tbnz" || ins.Mnemonic.StartsWith("b.")) return false;
                var (rd, wr) = Regset(ins);
                if (rd.Any(r => { int v = Num(r) ?? -1; return 9 <= v && v <= 17 && !written.Contains(Num(r)); })) return false;
                foreach (var r in wr) written.Add(Num(r));
                a += 4;
            }
            return false;
        }

        private (List<ObsEntry> Obs, string WhyNot) RegionGates(HashSet<long> startSet)
        {
            var sym = NsoCode.Defined(IMG.AsSpan(0, IMGLen).ToArray());
            if (!sym.TryGetValue("_ZN2nn2os6detail11VammManager21AllocateAddressRegionEPmm", out var ask) || !sym.TryGetValue("_ZN2nn2os6detail11VammManager17FreeAddressRegionEm", out var free))
                return (new List<ObsEntry>(), null);
            long got; int reg;
            try { (got, reg) = NsoCode.OutStore(IMG, ask.Value, ask.Size, md); }
            catch (ArgumentException e) { return (new List<ObsEntry>(), e.Message); }
            var sites = new List<(long Off, int Id, string Why)>
            {
                (ask.Value, OBS_REGION_ASK, "VammManager::AllocateAddressRegion entry: the size in x2"),
                (got, OBS_REGION_GOT | reg << 8, $"VammManager::AllocateAddressRegion: the new region's address in x{reg}, stored through the out pointer"),
                (free.Value, OBS_REGION_FREE, "VammManager::FreeAddressRegion entry: the address in x1"),
            };
            foreach (var (off, _, _) in sites)
            {
                bool afterBl = off >= 4 && W(off - 4) >> 26 == 0x25;
                if (!(startSet.Contains(off) || afterBl || ScratchDead(off)) || off >= TEXT_END || kinds.ContainsKey(off) || InWindow(off))
                    return (new List<ObsEntry>(), $"no observation gate possible at {Hx(off)}");
            }
            return (sites.Select(x => new ObsEntry(x.Off, x.Id, $"{W(x.Off):x8}", x.Why)).ToList(), null);
        }

        private List<ObsEntry> StdallocGates()
        {
            var sym = NsoCode.Defined(IMG.AsSpan(0, IMGLen).ToArray());
            var out_ = new List<ObsEntry>();
            foreach (var name in new[] { "_ZN2nn3mem17StandardAllocator10InitializeEPvm", "_ZN2nn3mem17StandardAllocator10InitializeEPvmb" })
            {
                if (!sym.TryGetValue(name, out var v)) continue;
                long off = v.Value;
                if (off >= TEXT_END || kinds.ContainsKey(off) || InWindow(off)) { Log($"{NAME}: no StandardAllocator gate at {Hx(off)}: a rewrite site"); continue; }
                out_.Add(new ObsEntry(off, OBS_STDALLOC_INIT, $"{W(off):x8}", $"StandardAllocator::Initialize(void *, size_t{(name.EndsWith("b") ? ", bool" : "")}) entry: the size in x2, capped when the address in x1 is null"));
            }
            return out_;
        }

        // ---- Output ----
        private RewriteResult Output()
        {
            patch = patchFront;
            long BACK_LEN = (patchBack.Count + 0x3FFF) & ~0x3FFFL;
            byte[] bin;
            if (FAR)
            {
                if (BIG_TEXT && patch.Count > FRONT - 0x4000 && Opt.PatchFront == null)
                {
                    long need = (patch.Count + 0x4000 + 0xFFFF) & ~0xFFFFL;
                    Log($"{NAME}: patch area of {Hx(patch.Count)} bytes does not fit in {Hx(FRONT)} before the base; rewriting again with {Hx(need)}");
                    throw new RerunWithFront(need);
                }
                RewriteAssertion.Check(patch.Count <= FRONT - 0x4000, $"patch area of {Hx(patch.Count)} bytes does not fit in the {Hx(FRONT)} before the base");
                var p = new List<byte>(patch);
                if (TWO)
                {
                    RewriteAssertion.Check(IMAGE_SIZE <= BACK_OFF, "back patch area overlaps the key page or the frame step page");
                    IMAGE_SIZE = BACK_OFF + BACK_LEN;
                    p.AddRange(new byte[(int)((-p.Count) & 0x3FFF)]);
                    p.AddRange(patchBack);
                    p.AddRange(new byte[BACK_LEN - patchBack.Count]);
                }
                bin = new byte[FILE_IMAGE_LEN + p.Count];
                Array.Copy(IMG, bin, IMGLen);
                p.CopyTo(bin, (int)FILE_IMAGE_LEN);
            }
            else
            {
                bin = new byte[PATCH_OFF + patch.Count];
                Array.Copy(IMG, bin, IMGLen);
                patch.CopyTo(bin, (int)PATCH_OFF);
            }
            Res.PatchedBin = bin;

            var f = new StringBuilder();
            f.Append($"# PATCH_OFF\t{Hx(PATCH_OFF)}\n# KEY_PAGE_OFF\t{Hx(KEY_PAGE_OFF)}\n# KEY_PAGE_SIZE\t0x4000\n# TEXT_END\t{Hx(TEXT_END)}\n# RO_OFF\t{Hx(RO_OFF)}\n# DATA_OFF\t{Hx(DATA_OFF)}\n");
            if (FAR) f.Append($"# IMAGE_SIZE\t{Hx(IMAGE_SIZE)}\n# FILE_IMAGE_LEN\t{Hx(FILE_IMAGE_LEN)}\n");
            if (TWO) f.Append($"# BACK_OFF\t{Hx(BACK_OFF)}\n# BACK_LEN\t{Hx(BACK_LEN)}\n");
            foreach (var k in KEY_INDEX) f.Append($"# KEY_{k.Key}_IDX\t{k.Value}\n");
            if (FS_STATE_OFF != 0) f.Append($"# FPS_STATE_OFF\t{Hx(FS_STATE_OFF)}\n");
            if (UE_CALL != null) f.Append($"# UE_MALLOC_VT\t{Hx(UE_VT.Value)}\n# UE_MALLOC_SLOT\t{Hx(UE_SLOT.Value)}\n");
            foreach (var (n, o) in UE_CVARS) f.Append($"# UE_CVAR:{n}\t{Hx(o)}\n");
            if (RENDER_SCALE != 0) f.Append("# RENDER_SCALE\t1\n");
            if (NAME == "main")
                foreach (var capability in PATCHES.Capabilities.GetValueOrDefault(BUILD_ID) ?? new List<string>())
                {
                    RewriteAssertion.Check(FM(@"[A-Z][A-Z0-9_]*", capability) != null, $"invalid capability {capability}");
                    f.Append($"# {capability}\t1\n");
                }
            f.Append($"# BUILD_ID\t{BUILD_ID}\n");
            Res.Files[NAME + ".fixups.tsv"] = f.ToString();

            var g = new StringBuilder();
            foreach (var (ret, k, arg, orig) in gates) g.Append($"{Hx(ret)}\t{k}\t{arg}\t{Hx(orig)}\n");
            Res.Files[NAME + ".gates.tsv"] = g.ToString();

            var s = new StringBuilder();
            foreach (var (a, (k, _)) in kinds) if (!done.Contains(a)) s.Append($"{Hx(a)}\t{k}\n");
            foreach (var wseg in windows) s.Append($"{Hx(wseg[0].Address)}\tW\t{Hx(wseg[^1].Address + 4)}\n");
            foreach (var (a, (b, c)) in jumps) s.Append($"{Hx(a)}\tJ\t{Hx(b)}\t{c}\n");
            foreach (var (a, tgt) in tabjumps) s.Append($"{Hx(a)}\tT\t" + string.Join(" ", tgt.Select(Hx)) + "\n");
            foreach (var (t, bes, _) in spinSites) s.Append($"{Hx(t)}\tS\t" + string.Join(" ", bes.Select(Hx)) + "\n");
            Res.Files[NAME + ".sites.tsv"] = s.ToString();

            var c2 = new StringBuilder($"# BUILD_ID\t{BUILD_ID}\n");
            foreach (var c in cuts) c2.Append($"{Hx(c.Offset)}\t{c.Old}\t{c.New}\t{c.Reason}\n");
            Res.Files[NAME + ".cuts.tsv"] = c2.ToString();

            var o2 = new StringBuilder($"# BUILD_ID\t{BUILD_ID}\n");
            foreach (var ob in obs) o2.Append($"{Hx(ob.Offset)}\t{ob.Id}\t{ob.Word}\t{ob.Reason}\n");
            Res.Files[NAME + ".obs.tsv"] = o2.ToString();

            Log($"{NAME} {{{string.Join(", ", stats.Select(kv => $"'{kv.Key}': {kv.Value}"))}}} cuts {cuts.Count} obs {obs.Count} patch {patchFront.Count + patchBack.Count} PATCH_OFF {Hx(PATCH_OFF)}"
                + (TWO ? $" BACK_OFF {Hx(BACK_OFF)} back {patchBack.Count}" : "") + $" slot_refs {fix.Count} gates {gates.Count}");
            if (DATA_BLOCKS.Count > 0) Log($"{NAME} data blocks left alone: " + string.Join(", ", DATA_BLOCKS.Select(b => $"{Hx(b.S)}..{Hx(b.E)}")));
            return Res;
        }
    }
}
