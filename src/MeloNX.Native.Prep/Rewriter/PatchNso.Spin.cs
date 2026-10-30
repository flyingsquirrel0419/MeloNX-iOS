using System;
using System.Collections.Generic;
using System.Linq;
using static MeloNX.Native.Prep.Rewriter.NsoAsm;

namespace MeloNX.Native.Prep.Rewriter
{
    // patch_nso.py "Spin waits": loops that only another thread can end get a copy whose back-edges pass a spin gate (the host yields there)
    public sealed partial class PatchNso
    {
        private const long SPIN_WIN = 512;
        private const int SPIN_PATHS = 256, SPIN_STEPS = 4096, SPIN_STORES = 4;
        private static readonly string[] SPIN_LSE = { "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin" };
        private static readonly HashSet<string> SPIN_BAD = new() { "bl", "blr", "br", "ret", "eret", "svc", "hvc", "smc", "brk", "hlt", "udf", "mrs", "msr", "sys", "sysl", "wfe", "wfi", "sev", "sevl", "clrex", "dc", "ic", "at",
            "tlbi", "drps", "dcps1", "dcps2", "dcps3", "blraa", "blrab", "blraaz", "blrabz", "braa", "brab", "braaz", "brabz", "retaa", "retab", "eretaa", "eretab" };
        private static readonly (uint M, uint V)[] SPIN_STOP = { (0xFC000000, 0x94000000), (0xFE000000, 0xD6000000), (0xFF000000, 0xD4000000), (0x3FC00000, 0x39000000), (0x3FC00000, 0x3D000000), (0x3FC00000, 0x3D800000),
            (0x3FE00000, 0x38000000), (0x3FE00C00, 0x38200800), (0x3FE00000, 0x3C000000), (0x3FE00000, 0x3C800000), (0x3A400000, 0x28000000), (0x3F200C00, 0x38200000) };

        private readonly Dictionary<long, Insn> spinDec = new();
        private HashSet<long> spinTouched;
        private List<(long T, List<long> Bes, int N)> spinSites = new();

        private sealed class SpinNode
        {
            public string Kind;
            public string Base;
            public long K;
            public List<Insn> Ins;
            public int Pre;
            public HashSet<string> Uses, Defs;
            public List<long> Succ;
            public (string Value, string Base) St;
        }

        private sealed class SpinRegion
        {
            public long T;
            public List<long> R;
            public Dictionary<long, SpinNode> Nodes;
            public HashSet<long> Valid;
        }

        private sealed class SpinNo : Exception { }

        private Insn SpinIns(long a)
        {
            if (!spinDec.TryGetValue(a, out var x))
            {
                var l = a >= 0 && a + 4 <= IMGLen ? md.Disasm(IMG.AsSpan((int)a, 4), a) : new List<Insn>();
                spinDec[a] = x = l.Count > 0 ? l[0] : null;
            }
            return x;
        }

        private static string SpinNorm(string n)
        {
            n = n switch { "fp" => "x29", "lr" => "x30", "wsp" => "sp", _ => n };
            if (n is "wzr" or "xzr") return null;
            var m = FM(@"[wx](\d+)", n);
            if (m != null) return "x" + m.Groups[1].Value;
            m = FM(@"[bhsdqv](\d+)", n);
            return m != null ? "v" + m.Groups[1].Value : n;
        }

        private static HashSet<string> NoNull(IEnumerable<string> s) => s.Where(x => x != null).ToHashSet();

        private static (HashSet<string> R, HashSet<string> W) SpinRw(Insn ins)
        {
            string m = ins.Mnemonic;
            var regs = ins.Operands.Where(o => o.Type == Arm64Op.Reg).Select(o => SpinNorm(ins.RegName(o.Reg))).ToList();
            var ops = NoNull(regs);
            if (m is "cbz" or "cbnz" or "tbz" or "tbnz") return (ops, new HashSet<string>());
            if (m.StartsWith("b.")) return (new HashSet<string> { "nzcv" }, new HashSet<string>());
            if (m == "b") return (new HashSet<string>(), new HashSet<string>());
            if (m is "cmp" or "cmn" or "tst" or "fcmp" or "fcmpe") return (ops, new HashSet<string> { "nzcv" });
            if (m is "ccmp" or "ccmn" or "fccmp" or "fccmpe") { ops.Add("nzcv"); return (ops, new HashSet<string> { "nzcv" }); }
            var (r0, w0) = ins.RegsAccess();
            var r = NoNull(r0.Select(x => SpinNorm(ins.RegName(x))));
            var w = NoNull(w0.Select(x => SpinNorm(ins.RegName(x))));
            if (m.StartsWith("ld") || m.StartsWith("prfm") || m.StartsWith("prfum")) { w.UnionWith(ops); return (r, w); }
            r.UnionWith(NoNull(regs.Skip(1))); w.UnionWith(NoNull(regs.Take(1)));
            return (r, w);
        }

        private static string SpinKind(Insn ins)
        {
            if (ins == null) return null;
            string m = ins.Mnemonic;
            if (m is "b" or "cbz" or "cbnz" or "tbz" or "tbnz" || m.StartsWith("b.")) return "br";
            if (m is "adr" or "adrp") return "pc";
            if (SPIN_BAD.Contains(m) || m.StartsWith("st") || m.StartsWith("cas") || m.StartsWith("swp") || SPIN_LSE.Any(m.StartsWith)) return null;
            bool mem = ins.Operands.Any(o => o.Type == Arm64Op.Mem);
            if (m.StartsWith("ld") || m.StartsWith("prfm") || m.StartsWith("prfum")) return mem ? "ok" : null;
            return mem ? null : "ok";
        }

        private (string Base, long K, HashSet<string> Defs, List<Insn> L)? SpinRmw(long a)
        {
            var l = Enumerable.Range(0, 4).Select(i => SpinIns(a + 4 * i)).ToList();
            if (l.Contains(null) || !(l[0].Mnemonic is "ldxr" or "ldaxr") || !(l[1].Mnemonic is "add" or "sub") || !(l[2].Mnemonic is "stxr" or "stlxr") || l[3].Mnemonic != "cbnz") return null;
            static string R(Insn x, int i) => x.RegName(x.Operands[i].Reg);
            if (l[1].Operands.Length != 3 || l[1].Operands[2].Type != Arm64Op.Imm || l[1].OpStr.Contains("lsl")) return null;
            var @base = l[0].Operands[1].Mem;
            if (@base.Disp != 0 || @base.Index != 0 || l[2].Operands[2].Mem.Base != @base.Base || l[2].Operands[2].Mem.Disp != 0) return null;
            if (R(l[1], 1) != R(l[0], 0) || R(l[2], 1) != R(l[1], 0) || R(l[3], 0) != R(l[2], 0) || l[3].Operands[1].Imm != a) return null;
            long k = l[1].Operands[2].Imm * (l[1].Mnemonic == "add" ? 1 : -1);
            return (SpinNorm(l[0].RegName(@base.Base)), k, NoNull(new[] { SpinNorm(R(l[0], 0)), SpinNorm(R(l[1], 0)), SpinNorm(R(l[2], 0)) }), l);
        }

        private (string Kind, string Base, List<Insn> L, int Pre, int N, HashSet<string> Uses, HashSet<string> Defs)? SpinLock(long a)
        {
            var l = Enumerable.Range(0, 6).Select(i => SpinIns(a + 4 * i)).ToList();
            if (l[0] == null) return null;
            static string R(Insn x, int i) => x.RegName(x.Operands[i].Reg);
            static bool Plain(Insn x, int i) => x.Operands[i].Type == Arm64Op.Mem && x.Operands[i].Mem.Index == 0 && x.Operands[i].Mem.Disp == 0;
            string m0 = l[0].Mnemonic;
            if (m0 is "ldxr" or "ldaxr" && !l.Contains(null) && R(l[0], 0).StartsWith("w") && Plain(l[0], 1))
            {
                int @base = l[0].Operands[1].Mem.Base; string bn = SpinNorm(l[0].RegName(@base));
                if (l[1].Mnemonic == "cbz" && R(l[1], 0) == R(l[0], 0) && l[1].Operands[1].Imm == a + 16 && l[2].Mnemonic == "clrex" && l[3].Mnemonic == "b" && l[3].Operands[0].Imm == a
                    && l[4].Mnemonic is "stxr" or "stlxr" && Plain(l[4], 2) && l[4].Operands[2].Mem.Base == @base && !(R(l[4], 1) is "wzr" or "xzr")
                    && l[5].Mnemonic == "cbnz" && R(l[5], 0) == R(l[4], 0) && l[5].Operands[1].Imm == a)
                    return ("acq", bn, l, 0, 6, NoNull(new[] { bn, SpinNorm(R(l[4], 1)) }), NoNull(new[] { SpinNorm(R(l[0], 0)), SpinNorm(R(l[4], 0)) }));
                var p = SpinIns(a - 4);
                if (p != null && p.Mnemonic == "clrex" && l[1].Mnemonic == "cmp" && R(l[1], 0) == R(l[0], 0) && l[1].Operands[1].Type == Arm64Op.Imm
                    && l[2].Mnemonic == "b.ne" && l[2].Operands[0].Imm == a - 4 && l[3].Mnemonic is "stxr" or "stlxr" && R(l[3], 1) == "wzr"
                    && Plain(l[3], 2) && l[3].Operands[2].Mem.Base == @base && l[4].Mnemonic == "cbnz" && R(l[4], 0) == R(l[3], 0) && l[4].Operands[1].Imm == a)
                    return ("rel", bn, new[] { p }.Concat(l.Take(5)).ToList(), 1, 5, NoNull(new[] { bn }), NoNull(new[] { SpinNorm(R(l[0], 0)), SpinNorm(R(l[3], 0)), "nzcv" }));
            }
            if (m0 == "stlr" && l[0].Operands.Length == 2 && R(l[0], 0) is "wzr" or "xzr" && Plain(l[0], 1))
            {
                string bn = SpinNorm(l[0].RegName(l[0].Operands[1].Mem.Base));
                return ("rel", bn, l.Take(1).ToList(), 0, 1, NoNull(new[] { bn }), new HashSet<string>());
            }
            if (m0 is "ldr" or "ldrb" or "ldrh" && !l.Take(3).Contains(null) && l[0].Operands.Length == 2 && R(l[0], 0).StartsWith("w") && l[0].Operands[1].Type == Arm64Op.Mem
                && l[0].Operands[1].Mem.Index == 0 && !l[0].Writeback && l[1].Mnemonic == "cmp" && R(l[1], 0) == R(l[0], 0) && l[1].Operands[1].Type == Arm64Op.Imm
                && l[2].Mnemonic is "b.eq" or "b.ne" && l[2].Operands[0].Imm == a)
            {
                string bn = SpinNorm(l[0].RegName(l[0].Operands[1].Mem.Base));
                return ("tst", bn, l.Take(3).ToList(), 0, 3, NoNull(new[] { bn }), NoNull(new[] { SpinNorm(R(l[0], 0)), "nzcv" }));
            }
            return null;
        }

        private static (string Value, string Base)? SpinStore(Insn ins)
        {
            if (ins == null || !(ins.Mnemonic is "str" or "strb" or "strh" or "stur" or "sturb" or "sturh") || ins.Writeback || ins.Operands.Length != 2) return null;
            var v = ins.Operands[0]; var o = ins.Operands[1];
            if (v.Type != Arm64Op.Reg || o.Type != Arm64Op.Mem || o.Mem.Index != 0) return null;
            string vn = ins.RegName(v.Reg);
            if (!(vn.StartsWith("w") || vn == "xzr")) return null;
            return (SpinNorm(vn), SpinNorm(ins.RegName(o.Mem.Base)));
        }

        private static uint SpinRebranch(Insn ins, long pc, long tgt)
        {
            uint w = ins.Word; long off = tgt - pc;
            if (ins.Mnemonic == "b") return B(pc, tgt);
            if (ins.Mnemonic is "tbz" or "tbnz")
            {
                RewriteAssertion.Check(-(1L << 15) <= off && off < (1L << 15) && off % 4 == 0, $"spin wait tbz out of range {Hx(pc)}");
                return (w & ~(0x3FFFu << 5)) | (uint)(((off >> 2) & 0x3FFF) << 5);
            }
            RewriteAssertion.Check(-(1L << 20) <= off && off < (1L << 20) && off % 4 == 0, $"spin wait branch out of range {Hx(pc)}");
            return (w & ~(0x7FFFFu << 5)) | (uint)(((off >> 2) & 0x7FFFF) << 5);
        }

        private bool SpinQuick(long T, long hi)
        {
            var seen = new HashSet<long>(); var todo = new Stack<long>(); todo.Push(T);
            while (todo.Count > 0)
            {
                long a = todo.Pop();
                if (seen.Contains(a) || !(T <= a && a <= hi)) continue;
                seen.Add(a); uint w = W(a), t = w >> 24;
                long[] succ;
                if (0x14 <= t && t <= 0x17) succ = new[] { a + (((long)(w & 0x3FFFFFF) ^ 0x2000000) - 0x2000000) * 4 };
                else if (t == 0x54 || (t & 0x7E) == 0x34) succ = new[] { a + ((((long)(w >> 5) & 0x7FFFF) ^ 0x40000) - 0x40000) * 4, a + 4 };
                else if ((t & 0x7E) == 0x36) succ = new[] { a + ((((long)(w >> 5) & 0x3FFF) ^ 0x2000) - 0x2000) * 4, a + 4 };
                else if (SPIN_STOP.Any(sv => (w & sv.M) == sv.V) && !((w & 0xBFC00000) is 0xB9000000 or 0x39000000 or 0x79000000 || (w & 0xBFE00C00) is 0xB8000000 or 0x38000000 or 0x78000000)) continue;
                else succ = new[] { a + 4 };
                if (succ.Contains(T)) return true;
                foreach (var x in succ) todo.Push(x);
            }
            return false;
        }

        // spin_region: a dict, or null
        private SpinRegion SpinRegionOf(long T, List<long> bes)
        {
            var ban = new HashSet<long>();
            object g = null;
            for (int i = 0; i < 8; i++)
            {
                g = SpinRegion1(T, bes, ban, true);
                if (g is not HashSet<long> gs) break;
                ban.UnionWith(gs);
            }
            var old = SpinRegion1(T, bes, new HashSet<long>(), false) as SpinRegion;
            return g is SpinRegion gr && (old == null || old.Valid.IsSubsetOf(gr.Valid)) ? gr : old;
        }

        // A SpinRegion, the set of stores to ban (HashSet<long>), or null
        private object SpinRegion1(long T, List<long> bes, HashSet<long> ban, bool stores)
        {
            long hi = bes.Max();
            if (DATA_BLOCKS.Any(b => b.S < hi + 4 && T < b.E) || !SpinQuick(T, hi)) return null;
            var nodes = new Dictionary<long, SpinNode>(); var back = new HashSet<long>(); var bad = new HashSet<long>(); var inner = new HashSet<long>();
            var todo = new Stack<long>(); todo.Push(T);
            while (todo.Count > 0)
            {
                long a = todo.Pop();
                if (nodes.ContainsKey(a) || bad.Contains(a)) continue;
                if (ban.Contains(a)) { bad.Add(a); continue; }
                var rmw = a + 12 <= hi && (W(a) & 0x3FE00000) == 0x08400000 ? SpinRmw(a) : null;
                var lk = rmw != null ? null : SpinLock(a);
                if (lk != null && lk.Value.Kind == "tst" && a == T) lk = null;
                SpinNode n;
                if (rmw != null)
                    n = new SpinNode { Kind = "rmw", Base = rmw.Value.Base, K = rmw.Value.K, Ins = rmw.Value.L, Uses = new HashSet<string> { rmw.Value.Base }, Defs = rmw.Value.Defs, Succ = new List<long> { a + 16 } };
                else if (lk != null)
                {
                    var v = lk.Value;
                    n = new SpinNode { Kind = v.Kind, Base = v.Base, K = v.Kind == "acq" ? 1 : v.Kind == "rel" ? -1 : 0, Ins = v.L, Pre = v.Pre, Uses = v.Uses, Defs = v.Defs, Succ = new List<long> { a + 4L * v.N } };
                }
                else if (stores && SpinStore(SpinIns(a)) is { } sst)
                {
                    var x = SpinIns(a);
                    var uses = new HashSet<string> { sst.Base };
                    if (sst.Value != null) uses.Add(sst.Value);
                    n = new SpinNode { Kind = "stc", St = sst, Ins = new List<Insn> { x }, Uses = uses, Defs = new HashSet<string>(), Succ = new List<long> { a + 4 } };
                }
                else
                {
                    var x = SpinIns(a); string k = SpinKind(x);
                    if (k == null) { bad.Add(a); continue; }
                    List<long> succ;
                    if (k == "br")
                    {
                        long t = x.Operands[^1].Imm;
                        succ = x.Mnemonic == "b" ? new List<long> { t } : new List<long> { t, a + 4 };
                    }
                    else succ = new List<long> { a + 4 };
                    n = new SpinNode { Kind = k, Ins = new List<Insn> { x }, Succ = succ };
                }
                int pre = n.Pre;
                if (Enumerable.Range(0, n.Ins.Count).Any(i => spinTouched.Contains(a + 4L * (i - pre)))) { bad.Add(a); continue; }
                nodes[a] = n;
                if (n.Kind == "rmw") inner.UnionWith(new[] { a + 4, a + 8, a + 12 });
                if (n.Kind is "acq" or "rel" or "tst") { foreach (int i in Enumerable.Range(0, n.Ins.Count)) if (a + 4L * (i - pre) != a) inner.Add(a + 4L * (i - pre)); }
                foreach (long s in n.Succ)
                {
                    if (s == T) back.Add(a);
                    else if (T < s && s <= hi) todo.Push(s);
                }
            }
            if (back.Count == 0 || inner.Overlaps(nodes.Keys) || nodes.Values.Any(n => n.Succ.Any(inner.Contains))) return null;
            HashSet<long> Prune(IEnumerable<long> ends)
            {
                var keep = new HashSet<long>(ends); bool more = true;
                while (more)
                {
                    more = false;
                    foreach (var (a, n) in nodes)
                        if (!keep.Contains(a) && n.Succ.Any(s => keep.Contains(s) && s != T)) { keep.Add(a); more = true; }
                }
                return keep;
            }
            var R = Prune(back);
            foreach (long a in R)
                if (nodes[a].Uses == null) { var (u, d) = SpinRw(nodes[a].Ins[0]); nodes[a].Uses = u; nodes[a].Defs = d; }
            var badBack = new HashSet<long>(); int cntPaths = 0, cntSteps = 0;
            void Walk(long a, HashSet<long> onpath, Dictionary<string, int> ver, Dictionary<(bool, string, int), long> delta)
            {
                cntSteps++;
                if (cntSteps > SPIN_STEPS) throw new SpinNo();
                var n = nodes[a];
                if (n.Kind is "rmw" or "acq" or "rel")
                {
                    var key = (n.Kind != "rmw", n.Base, ver.GetValueOrDefault(n.Base));
                    delta = new Dictionary<(bool, string, int), long>(delta);
                    delta[key] = delta.GetValueOrDefault(key) + n.K;
                    if (n.Kind != "rmw" && !(0 <= delta[key] && delta[key] <= 1)) throw new SpinNo();
                }
                if (n.Defs.Count > 0)
                {
                    ver = new Dictionary<string, int>(ver);
                    foreach (var r in n.Defs) ver[r] = ver.GetValueOrDefault(r) + 1;
                }
                foreach (long s in n.Succ)
                {
                    if (s == T)
                    {
                        cntPaths++;
                        if (cntPaths > SPIN_PATHS) throw new SpinNo();
                        if (delta.Values.Any(v => v != 0)) badBack.Add(a);
                    }
                    else if (R.Contains(s))
                    {
                        if (onpath.Contains(s)) throw new SpinNo();
                        Walk(s, new HashSet<long>(onpath) { s }, ver, delta);
                    }
                }
            }
            try { Walk(T, new HashSet<long> { T }, new Dictionary<string, int>(), new Dictionary<(bool, string, int), long>()); }
            catch (SpinNo) { return null; }
            var valid = new HashSet<long>(back.Except(badBack));
            if (valid.Count == 0) return null;
            R = Prune(valid);
            var live = R.ToDictionary(a => a, _ => new HashSet<string>()); bool changed = true;
            while (changed)
            {
                changed = false;
                foreach (long a in R.OrderByDescending(x => x))
                {
                    var n = nodes[a]; var o = new HashSet<string>();
                    foreach (long s in n.Succ)
                    {
                        if (s == T) { if (valid.Contains(a)) o.UnionWith(live[T]); }
                        else if (R.Contains(s)) o.UnionWith(live[s]);
                    }
                    var nw = new HashSet<string>(n.Uses); nw.UnionWith(o.Except(n.Defs));
                    if (!nw.SetEquals(live[a])) { live[a] = nw; changed = true; }
                }
            }
            var defs = new HashSet<string>(R.SelectMany(a => nodes[a].Defs));
            if (R.Any(a => nodes[a].Kind == "stc") && !R.Any(a => nodes[a].Kind is "rmw" or "acq" or "rel" or "tst" || nodes[a].Ins[0].Mnemonic.StartsWith("ld"))) return null;
            var vary = R.Where(a => nodes[a].Kind == "stc" && nodes[a].Uses.Overlaps(defs)).ToHashSet();
            if (vary.Count > 0) return vary;
            if (R.Count(a => nodes[a].Kind == "stc") > SPIN_STORES) return null;
            if (live[T].Overlaps(defs)) return null;
            return new SpinRegion { T = T, R = R.OrderBy(x => x).ToList(), Nodes = nodes, Valid = valid };
        }

        private void SpinEmit(SpinRegion g)
        {
            long T = g.T; var R = g.R; var nodes = g.Nodes; var valid = g.Valid;
            UseArea(T);
            var cpy = new Dictionary<long, long>(); var fixes = new List<(int Idx, Insn X, object Info)>(); var tramp = new Dictionary<long, long>();
            for (int i = 0; i < R.Count; i++)
            {
                long a = R[i]; var n = nodes[a]; cpy[a] = Here(); var x = n.Ins[0];
                if (n.Kind == "rmw")
                {
                    foreach (var y in n.Ins.Take(3)) Emit(y.Word);
                    fixes.Add((patch.Count, n.Ins[3], a)); Emit(0);
                }
                else if (n.Kind is "acq" or "rel")
                {
                    cpy[a] = Here() + 4L * n.Pre;
                    foreach (var y in n.Ins) Emit(y.Word);
                }
                else if (n.Kind == "tst")
                {
                    foreach (var y in n.Ins.Take(2)) Emit(y.Word);
                    fixes.Add((patch.Count, n.Ins[2], ("orig", a))); Emit(0);
                }
                else if (n.Kind == "pc")
                {
                    int rd = Num(SpinNorm(x.RegName(x.Operands[0].Reg))).Value; long tgt = x.Operands[1].Imm;
                    Emit(ADRP(rd, Here(), tgt));
                    if (x.Mnemonic == "adr") Emit(ADDI(rd, rd, tgt & 0xFFF));
                }
                else if (n.Kind == "br") { fixes.Add((patch.Count, x, null)); Emit(0); }
                else Emit(x.Word);
                if (!(n.Kind == "br" && x.Mnemonic == "b"))
                {
                    long ft = a + 4L * (n.Ins.Count - n.Pre);
                    if (!(i + 1 < R.Count && R[i + 1] == ft)) { fixes.Add((patch.Count, null, ft)); Emit(0); }
                }
            }
            long pause = Here();
            Emit(STP_PRE(29, 30, 31, -16)); EmitGateCall(); Emit(BLR(30)); long ret = Here(); Emit(LDP_POST(29, 30, 31, 16));
            gates.Add((ret, "spin", 0, T)); Emit(B(Here(), cpy[T]));
            long Out(long t)
            {
                if (!tramp.ContainsKey(t)) { tramp[t] = Here(); Emit(B(Here(), t)); }
                return tramp[t];
            }
            foreach (var (idx, x, info) in fixes)
            {
                long pc = PATCH_BASE + idx; uint w;
                if (x == null) { long ft = (long)info; w = B(pc, cpy.TryGetValue(ft, out long cv) ? cv : ft); }
                else if (info is ValueTuple<string, long> orig) w = SpinRebranch(x, pc, Out(orig.Item2));
                else if (info != null) w = SpinRebranch(x, pc, cpy[(long)info]);
                else
                {
                    long t = x.Operands[^1].Imm; bool cond = x.Mnemonic != "b";
                    long d = t == T && valid.Contains(x.Address) ? pause : cpy.ContainsKey(t) && t != T ? cpy[t] : cond ? Out(t) : t;
                    w = SpinRebranch(x, pc, d);
                }
                SetPatchWord(idx, w);
            }
            foreach (long b in valid.OrderBy(v => v))
            {
                var x = nodes[b].Ins[0];
                if (x.Mnemonic == "b") PutBranch(b, cpy[T]);
                else { long st = Here(); Emit(SpinRebranch(x, Here(), cpy[T])); Emit(B(Here(), b + 4)); PutBranch(b, st); }
            }
            Stat("spin");
        }

        private void SpinWaits()
        {
            spinTouched = new HashSet<long>(kinds.Keys);
            spinTouched.UnionWith(done);
            foreach (var ob in obs) spinTouched.Add(ob.Offset);
            foreach (var c in cuts) for (long o = c.Offset; o < c.Offset + c.Old.Length / 2; o += 4) spinTouched.Add(o);
            var regions = spin_cand.Keys.OrderBy(x => x).Select(T => SpinRegionOf(T, spin_cand[T])).Where(g => g != null).ToList();
            spinSites = regions.Select(g => (g.T, g.Valid.OrderBy(v => v).ToList(), g.R.Sum(a => g.Nodes[a].Ins.Count))).ToList();
            foreach (var g in regions) SpinEmit(g);
            if (Opt.SpinList)
                foreach (var (T, bes, n) in spinSites) Log($"{NAME} spin wait {Hx(T)} ({n} instructions), back-edges " + string.Join(" ", bes.Select(Hx)));
        }
    }
}
