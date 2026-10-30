using System;
using System.Collections.Generic;
using System.Linq;
using static MeloNX.Native.Prep.Rewriter.NsoAsm;

namespace MeloNX.Native.Prep.Rewriter
{
    // patch_nso.py's br x18 recognizers: jump tables of every form it knows, tail calls, and the helpers that find a table's base
    public sealed partial class PatchNso
    {
        private static string Wname(string r) => "w" + r[1..];
        private static int Idx(List<Insn> l, Insn x) { int i = l.IndexOf(x); if (i < 0) throw new InvalidOperationException("not in list"); return i; }
        private static List<Insn> Slice(List<Insn> l, int a, int b)
        {
            a = Math.Clamp(a, 0, l.Count); b = Math.Clamp(b, 0, l.Count);
            return b > a ? l.GetRange(a, b - a) : new List<Insn>();
        }
        private static IEnumerable<string> WrittenNames(Insn p) => p.RegsAccess().Written.Select(r => p.RegName(r));

        private Insn CheckBeforeCopy(List<Insn> insl, List<Insn> ctx, Insn ld, HashSet<string> idx)
        {
            int k = Idx(ctx, ld);
            if (k < 2 || ctx[k - 1].Mnemonic != "b.hi" || ctx[k - 2].Mnemonic != "cmp") return null;
            var m = FM(@"(w\d+), #(0x[0-9a-f]+|\d+)", ctx[k - 2].OpStr);
            if (m == null) return null;
            string src = m.Groups[1].Value; int kl = Idx(insl, ld);
            HashSet<string> Writes(Insn p) => p.Mnemonic is "cmp" or "cmn" or "tst" ? new HashSet<string>() : WrittenNames(p).Select(n => "w" + n[1..]).ToHashSet();
            var all = new HashSet<string>(idx) { src };
            bool broke = false;
            for (int q = kl - 3; q >= 0; q--)
            {
                var p = insl[q];
                if (p.Address + 4 != insl[q + 1].Address) return null;
                if (p.Mnemonic is "bl" or "blr" && all.Any(r => int.Parse(r[1..]) <= 18)) return null;
                var mm = p.Mnemonic == "mov" ? FM(@"(w\d+), (w\d+)", p.OpStr) : null;
                if (mm != null && idx.Contains(mm.Groups[1].Value) && mm.Groups[2].Value == src) { broke = true; break; }
                if (Writes(p).Overlaps(all)) return null;
            }
            if (!broke) return null;
            return ctx[k - 2];
        }

        private List<long> TableTargets(long tb, long n) => Enumerable.Range(0, (int)n).Select(i => tb + NsoCode.I32(IMG, tb + 4 * i)).ToList();

        private List<long> JumpOffsets(List<Insn> insl, int j, bool copyFirst = false, bool farBase = false, bool forwardBase = false)
        {
            var ctx = Slice(insl, j - 16, j);
            var add = Enumerable.Reverse(ctx).FirstOrDefault(p => p.Mnemonic == "add" && FM(@"x18, x\d+, x\d+", p.OpStr) != null);
            if (add == null) return null;
            var parts = add.OpStr.Split(", ");
            string t = parts[1], rb = parts[2];
            var ld = Enumerable.Reverse(ctx).FirstOrDefault(p => p.Mnemonic == "ldrsw" && FM($@"{t}, \[{rb}, x(\d+), lsl #2\]", p.OpStr) != null);
            if (ld == null) return null;
            var idx = new HashSet<string> { "w" + FM($@"{t}, \[{rb}, x(\d+), lsl #2\]", ld.OpStr).Groups[1].Value };
            (string Src, long Mask, int Pos)? masked = null;
            int k0 = Idx(ctx, ld); Insn cmp = null;
            for (int i = k0 - 1; i >= 0; i--)
            {
                var p = ctx[i];
                var m = p.Mnemonic == "mov" ? FM(@"(w\d+), (w\d+)", p.OpStr) : null;
                if (m != null && idx.Contains(m.Groups[1].Value)) { idx.Add(m.Groups[2].Value); continue; }
                m = p.Mnemonic == "and" ? FM(@"([wx]\d+), ([wx]\d+), #(0x[0-9a-f]+|\d+)", p.OpStr) : null;
                if (m != null && idx.Contains(Wname(m.Groups[1].Value)) && masked == null) { masked = (Wname(m.Groups[2].Value), PyInt(m.Groups[3].Value), i); continue; }
                m = p.Mnemonic == "cmp" ? FM(farBase ? @"([wx]\d+), #(0x[0-9a-f]+|\d+)" : @"(w\d+), #(0x[0-9a-f]+|\d+)", p.OpStr) : null;
                if (m == null) continue;
                if (idx.Contains(Wname(m.Groups[1].Value))) { cmp = p; break; }
                if (masked != null)
                {
                    var (msrc, mmask, mpos) = masked.Value;
                    for (int q = i - 1; q >= 0; q--)
                    {
                        var w = WrittenNames(ctx[q]).Select(Wname).ToList();
                        if (!w.Contains(Wname(m.Groups[1].Value))) continue;
                        var mm = ctx[q].Mnemonic == "and" ? FM(@"([wx]\d+), ([wx]\d+), #(0x[0-9a-f]+|\d+)", ctx[q].OpStr) : null;
                        if (mm != null && Wname(mm.Groups[2].Value) == msrc && PyInt(mm.Groups[3].Value) == mmask &&
                            !Enumerable.Range(q + 1, Math.Max(0, mpos - q - 1)).Any(z => WrittenNames(ctx[z]).Select(Wname).Contains(msrc)))
                            cmp = p;
                        break;
                    }
                    if (cmp != null) break;
                }
            }
            if (cmp == null && copyFirst) cmp = CheckBeforeCopy(insl, ctx, ld, idx);
            if (cmp == null) return null;
            long n = PyInt(cmp.OpStr.Split('#')[1]) + 1;
            int k = Idx(insl, ld); long? lo = null, page = null;
            bool brokeLoop = false;
            foreach (var p in Enumerable.Reverse(Slice(insl, k - 256, k)))
            {
                if (!WrittenNames(p).Any(r => r == rb)) continue;
                if (lo == null && p.Mnemonic == "add" && FM($@"{rb}, {rb}, #(0x[0-9a-f]+|\d+)", p.OpStr) != null) { lo = PyInt(p.OpStr.Split('#')[1]); continue; }
                if (lo != null && p.Mnemonic == "adrp" && p.OpStr.StartsWith(rb + ",")) page = p.Operands[1].Imm;
                brokeLoop = true;
                break;
            }
            long fa = insl[0].Address, fb = insl[^1].Address + 4;
            if (!brokeLoop && lo == null && farBase)
            {
                long? tb = TableBase(insl, k, rb, far: true);
                tb ??= CopiedBase(insl, k, rb);
                if (tb == null && forwardBase) tb = ForwardTableBase(insl, k, rb, n);
                if (tb == null || tb + 4 * n > IMGLen) return null;
                var t1 = TableTargets(tb.Value, n);
                return t1.All(x => fa <= x && x < fb && x % 4 == 0) ? t1 : null;
            }
            if (page == null && farBase)
            {
                long? tb = CopiedBase(insl, k, rb);
                if (tb == null || tb + 4 * n > IMGLen) return null;
                var t2 = TableTargets(tb.Value, n);
                return t2.All(x => fa <= x && x < fb && x % 4 == 0) ? t2 : null;
            }
            if (page == null) return null;
            return TableTargets(page.Value + lo.Value, n);
        }

        private long? ForwardTableBase(List<Insn> insl, int k, string rb, long n)
        {
            if (k < 2 || k + 2 >= insl.Count) return null;
            Insn guard = insl[k - 2], branch = insl[k - 1], load = insl[k], add = insl[k + 1], jump = insl[k + 2];
            var m = FM($@"(x\d+), \[{rb}, x(\d+), lsl #2\]", load.OpStr);
            if (load.Mnemonic != "ldrsw" || m == null || guard.Mnemonic != "cmp") return null;
            var bound = FM($@"w{m.Groups[2].Value}, #(0x[0-9a-f]+|\d+)", guard.OpStr);
            if (bound == null || PyInt(bound.Groups[1].Value) != n - 1) return null;
            if (branch.Mnemonic != "b.hi" || add.Mnemonic != "add" || add.OpStr != $"x18, {m.Groups[1].Value}, {rb}" || jump.Mnemonic != "br" || jump.OpStr != "x18") return null;
            for (int q = k - 2; q < k + 2; q++) if (insl[q + 1].Address != insl[q].Address + 4) return null;
            var @protected = Slice(insl, k - 1, k + 3).Select(p => p.Address).ToHashSet();
            if (insl.Any(p => p.Mnemonic is "bl" or "blr") && int.Parse(rb[1..]) <= 18) return null;
            var baseNames = new HashSet<string> { rb, "w" + rb[1..] };
            if (rb == "x30") baseNames.Add("lr");
            if (rb == "x29") baseNames.Add("fp");
            var writers = insl.Select((p, i) => (i, p)).Where(x => !(x.p.Mnemonic is "cmp" or "cmn" or "tst") && WrittenNames(x.p).Any(baseNames.Contains)).ToList();
            if (writers.Count != 2) return null;
            var (wi, wp) = writers[0]; var (_, wq) = writers[1];
            if (wi <= k || wq.Address != wp.Address + 4 || wp.Mnemonic != "adrp" || !wp.OpStr.StartsWith(rb + ",")) return null;
            var mq = wq.Mnemonic == "add" ? FM($@"{rb}, {rb}, #(0x[0-9a-f]+|\d+)", wq.OpStr) : null;
            if (mq == null) return null;
            @protected.Add(wq.Address);
            foreach (var x in insl)
                if (x.Mnemonic is "b" or "bl" or "cbz" or "cbnz" or "tbz" or "tbnz" || x.Mnemonic.StartsWith("b."))
                    if (@protected.Contains(x.Operands[^1].Imm)) return null;
            if (tabjumps.Values.Any(targets => @protected.Overlaps(targets))) return null;
            if (jumps.Values.Any(j => @protected.Any(x => j.Base <= x && x < j.Base + 4 * j.Width))) return null;
            long tb = wp.Operands[1].Imm + PyInt(mq.Groups[1].Value);
            if (!(0 <= tb && tb <= IMGLen - 4 * n)) return null;
            var targets2 = Enumerable.Range(0, (int)n).Select(z => tb + NsoCode.I32(IMG, tb + 4 * z)).ToHashSet();
            var addrs = insl.Select(x => x.Address).ToHashSet();
            return !@protected.Overlaps(targets2) && targets2.IsSubsetOf(addrs) ? tb : null;
        }

        private long? TableBase(List<Insn> insl, int k, string rb, bool far = false)
        {
            long? lo = null;
            foreach (var p in Enumerable.Reverse(Slice(insl, far ? 0 : k - 256, k)))
            {
                if (far && p.Mnemonic is "bl" or "blr" && Num(rb) <= 18) return null;
                if (!WrittenNames(p).Any(r => r == rb)) continue;
                if (lo == null && p.Mnemonic == "add" && FM($@"{rb}, {rb}, #(0x[0-9a-f]+|\d+)", p.OpStr) != null) { lo = PyInt(p.OpStr.Split('#')[1]); continue; }
                if (lo != null && p.Mnemonic == "adrp" && p.OpStr.StartsWith(rb + ",")) return p.Operands[1].Imm + lo;
                return null;
            }
            return null;
        }

        private static string Canon(string n) => n == "lr" ? "x30" : n == "fp" ? "x29" : n;

        private long? CopiedBase(List<Insn> insl, int k, string rb)
        {
            long? lo = null; string r = Canon(rb);
            foreach (var p in Enumerable.Reverse(Slice(insl, 0, k)))
            {
                if (p.Mnemonic is "bl" or "blr" && Num(r) <= 18) return null;
                if (!WrittenNames(p).Any(x => ReplaceFirst(Canon(x), 'w', 'x') == r)) continue;
                var ops = p.OpStr.Split(", ").Select(Canon).ToList();
                if (lo == null && p.Mnemonic == "mov" && ops.Count == 2 && ops[0] == r && FM(@"x\d+", ops[1]) != null) { r = ops[1]; continue; }
                if (lo == null && p.Mnemonic == "add" && ops.Count == 3 && ops[0] == r && ops[1] == r && FM(@"#(0x[0-9a-f]+|\d+)", ops[2]) != null) { lo = PyInt(ops[2][1..]); continue; }
                if (lo != null && p.Mnemonic == "adrp" && ops[0] == r) return p.Operands[1].Imm + lo;
                return null;
            }
            return null;
        }

        // str.replace(old, new, 1)
        private static string ReplaceFirst(string s, char a, char b)
        {
            int i = s.IndexOf(a);
            return i < 0 ? s : s[..i] + b + s[(i + 1)..];
        }

        private List<long> JumpMaskedNot(List<Insn> insl, int j)
        {
            var ctx = Slice(insl, j - 16, j + 1);
            var add = Enumerable.Reverse(ctx.Take(ctx.Count - 1)).FirstOrDefault(p => p.Mnemonic == "add" && FM(@"x18, x\d+, x\d+", p.OpStr) != null);
            if (add == null) return null;
            var ap = add.OpStr.Split(", "); string ent = ap[1], @base = ap[2]; int ka = Idx(ctx, add);
            var ld = Enumerable.Reverse(ctx.Take(ka)).FirstOrDefault(p => p.Mnemonic == "ldrsw" && FM($@"{ent}, \[{@base}, x\d+, lsl #2\]", p.OpStr) != null);
            if (ld == null) return null;
            int kl = Idx(ctx, ld); string idx = ld.OpStr.Split(", ")[2];
            if (@base == ent || @base == idx) return null;
            var mask = Enumerable.Reverse(ctx.Take(kl)).FirstOrDefault(p => p.Mnemonic == "and" && FM($@"{idx}, x\d+, #(0x[0-9a-f]+|\d+)", p.OpStr) != null);
            if (mask == null) return null;
            int km = Idx(ctx, mask);
            if (km < 3) return null;
            var mp = mask.OpStr.Split(", "); string src = mp[1], imm = mp[2]; long n = PyInt(imm[1..]);
            if (n == 0 || (n & (n + 1)) != 0 || n > 0xffffffffL) return null;
            Insn test = ctx[km - 3], branch = ctx[km - 2], invert = ctx[km - 1];
            if (test.Mnemonic != "tst" || test.OpStr != $"w{src[1..]}, {imm}" || branch.Mnemonic != "b.eq" ||
                invert.Mnemonic != "mvn" || invert.OpStr != $"w{src[1..]}, w{src[1..]}") return null;
            var run = ctx.Skip(km - 3).ToList();
            for (int q = 0; q + 1 < run.Count; q++) if (run[q + 1].Address != run[q].Address + 4) return null;
            long head = test.Address, end = insl[j].Address;
            if (head <= branch.Operands[0].Imm && branch.Operands[0].Imm <= end) return null;
            bool Writes(Insn p, string reg)
            {
                if (p.Mnemonic is "cmp" or "cmn" or "tst") return false;
                if (p.Mnemonic is "bl" or "blr" && int.Parse(reg[1..]) <= 18) return true;
                return WrittenNames(p).Any(r => ReplaceFirst(r, 'w', 'x') == reg);
            }
            if (Slice(ctx, km + 1, kl).Any(p => Writes(p, idx)) || Slice(ctx, kl + 1, ka).Any(p => Writes(p, ent)) ||
                Slice(ctx, kl + 1, ka + 1).Any(p => Writes(p, @base)) || Slice(ctx, ka + 1, ctx.Count - 1).Any(p => Writes(p, "x18"))) return null;
            if (Slice(ctx, km + 1, ctx.Count - 1).Any(p => p.Mnemonic is "b" or "bl" or "br" or "blr" or "ret" or "cbz" or "cbnz" or "tbz" or "tbnz" || p.Mnemonic.StartsWith("b."))) return null;
            foreach (var p in insl)
                if (IsDirectBranch(p.Mnemonic) && head < p.Operands[^1].Imm && p.Operands[^1].Imm <= end) return null;
            if (tabjumps.Values.Any(ts => ts.Any(t => head < t && t <= end))) return null;
            if (jumps.Values.Any(jw => jw.Base <= end && jw.Base + 4 * jw.Width > head + 4)) return null;
            long? tb = CopiedBase(insl, Idx(insl, ld), @base);
            if (tb == null || tb < 0 || tb + 4 * n > IMGLen) return null;
            var targets = TableTargets(tb.Value, n);
            var addresses = insl.Select(p => p.Address).ToHashSet();
            return targets.All(t => addresses.Contains(t) && !(head < t && t <= end)) ? targets : null;
        }

        private List<long> JumpAdrOffsets(List<Insn> insl, int j)
        {
            var ctx = Slice(insl, j - 16, j);
            var add = Enumerable.Reverse(ctx).FirstOrDefault(p => p.Mnemonic == "add" && FM(@"x18, x\d+, x\d+", p.OpStr) != null);
            if (add == null) return null;
            int ka = Idx(ctx, add); var ops = add.OpStr.Split(", ").Skip(1).ToArray();
            foreach (var (e, a) in new[] { (ops[0], ops[1]), (ops[1], ops[0]) })
            {
                var ld = Enumerable.Reverse(ctx.Take(ka)).FirstOrDefault(p => p.Mnemonic == "ldrsw" && FM($@"{e}, \[x\d+, x\d+, lsl #2\]", p.OpStr) != null);
                var wa = Enumerable.Reverse(ctx.Take(ka)).FirstOrDefault(p => WrittenNames(p).Any(r => r == a));
                if (ld == null || wa == null || wa.Mnemonic != "adr") continue;
                var g = FM($@"{e}, \[(x\d+), x(\d+), lsl #2\]", ld.OpStr);
                string tbReg = g.Groups[1].Value, ix = g.Groups[2].Value;
                var idx = new HashSet<string> { "w" + ix }; Insn cmp = null;
                foreach (var p in Enumerable.Reverse(ctx.Take(Idx(ctx, ld))))
                {
                    var m = p.Mnemonic == "mov" ? FM(@"(w\d+), (w\d+)", p.OpStr) : null;
                    if (m != null && idx.Contains(m.Groups[1].Value)) { idx.Add(m.Groups[2].Value); continue; }
                    m = p.Mnemonic == "cmp" ? FM(@"(w\d+), #(0x[0-9a-f]+|\d+)", p.OpStr) : null;
                    if (m != null && idx.Contains(m.Groups[1].Value)) { cmp = p; break; }
                    if (WrittenNames(p).Any(r => idx.Contains("w" + r[1..]))) return null;
                }
                if (cmp == null) return null;
                long n = PyInt(cmp.OpStr.Split('#')[1]) + 1, at = wa.Operands[1].Imm;
                List<long> Targets(long tb) => 0 <= tb && tb + 4 * n <= IMGLen ? Enumerable.Range(0, (int)n).Select(i => at + NsoCode.I32(IMG, tb + 4 * i)).ToList() : null;
                long? tb0 = TableBase(insl, Idx(insl, ld), tbReg);
                if (tb0 != null) return Targets(tb0.Value);
                long fa = insl[0].Address, fb = insl[^1].Address + 4;
                var ok = TableCands(insl, tbReg).Where(tb => { var t = Targets(tb); return t != null && t.All(x => fa <= x && x < fb && x % 4 == 0); }).ToList();
                return ok.Count == 1 ? Targets(ok[0]) : null;
            }
            return null;
        }

        private static List<long> TableCands(List<Insn> insl, string rb)
        {
            var cands = new HashSet<long>();
            for (int k = 0; k < insl.Count; k++)
            {
                var p = insl[k];
                if (p.Mnemonic != "adrp" || !p.OpStr.StartsWith(rb + ",")) continue;
                var q = Slice(insl, k + 1, k + 9).FirstOrDefault(x => WrittenNames(x).Any(r => r == rb));
                var m = q != null && q.Mnemonic == "add" ? FM($@"{rb}, {rb}, #(0x[0-9a-f]+|\d+)", q.OpStr) : null;
                if (m != null) cands.Add(p.Operands[1].Imm + PyInt(m.Groups[1].Value));
            }
            return cands.OrderBy(x => x).ToList();
        }

        private List<long> JumpMaskedPred(List<Insn> insl, int j)
        {
            static bool IsBranch(Insn p) => p.Mnemonic is "b" or "cbz" or "cbnz" or "tbz" or "tbnz" || p.Mnemonic.StartsWith("b.");
            static bool IsCf(Insn p) => IsBranch(p) || p.Mnemonic is "br" or "blr" or "bl" or "ret";
            static HashSet<int?> Writes(Insn p) => p.Mnemonic is "cmp" or "cmn" or "tst" ? new HashSet<int?>() : WrittenNames(p).Select(n => Num(Canon(n))).ToHashSet();
            int? kh = null;
            for (int q = j - 1; q > Math.Max(0, j - 32) - 1; q--) if (IsCf(insl[q])) { kh = q; break; }
            if (kh == null || kh < 3 || insl[kh.Value].Mnemonic != "b.hi") return null;
            int k = kh.Value - 2; Insn a_ = insl[k], c_ = insl[kh.Value - 1];
            var ma = a_.Mnemonic == "and" ? FM(@"(w\d+), (w\d+), #(0x[0-9a-f]+|\d+)", a_.OpStr) : null;
            var mc = c_.Mnemonic == "cmp" ? FM(@"(w\d+), #(0x[0-9a-f]+|\d+)", c_.OpStr) : null;
            if (!(ma != null && mc != null && ma.Groups[1].Value == mc.Groups[1].Value)) return null;
            for (int q = k - 1; q < j; q++) if (insl[q + 1].Address != insl[q].Address + 4) return null;
            int? kl = null;
            for (int q = kh.Value + 1; q < j; q++) if (insl[q].Mnemonic == "ldrsw" && insl[q].OpStr.StartsWith("x18, ")) { kl = q; break; }
            var ml = kl != null ? FM(@"x18, \[(x\d+), x(\d+), lsl #2\]", insl[kl.Value].OpStr) : null;
            if (ml == null) return null;
            string rb = ml.Groups[1].Value; int ix = int.Parse(ml.Groups[2].Value);
            int? src = Num(ma.Groups[2].Value); long mask = PyInt(ma.Groups[3].Value), n = PyInt(mc.Groups[2].Value) + 1;
            if (ix == src || ix == Num(ma.Groups[1].Value) || ix == 18 || Num(rb) == ix || Num(rb) == 18 || (mask >> 32) != 0) return null;
            if (Slice(insl, kh.Value + 1, kl.Value).Any(p => Writes(p).Contains(ix))) return null;
            int? ka = null;
            for (int q = kl.Value + 1; q < j; q++) if (Writes(insl[q]).Contains(18)) { ka = q; break; }
            if (ka == null || insl[ka.Value].Mnemonic != "add" || insl[ka.Value].OpStr != $"x18, x18, {rb}") return null;
            if (Slice(insl, kl.Value + 1, ka.Value).Any(p => Writes(p).Contains(Num(rb))) || Slice(insl, ka.Value + 1, j).Any(p => Writes(p).Contains(18))) return null;
            if (!(insl[k - 1].Mnemonic is "b" or "br" or "ret")) return null;
            var brs = Enumerable.Range(0, insl.Count).Where(q => (IsBranch(insl[q]) || insl[q].Mnemonic == "bl") && insl[q].Operands[^1].Type == Arm64Op.Imm).ToList();
            var into = brs.Select(q => insl[q].Operands[^1].Imm).ToHashSet();
            if (Slice(insl, k + 1, j + 1).Any(p => into.Contains(p.Address))) return null;
            var tabs = tabjumps.Values.SelectMany(t => t).ToHashSet();
            bool TableTarget(long a) => tabs.Contains(a) || jumps.Values.Any(jw => jw.Base <= a && a < jw.Base + 4 * jw.Width);
            if (Slice(insl, k, j + 1).Any(p => TableTarget(p.Address))) return null;
            var preds = brs.Where(q => insl[q].Operands[^1].Imm == a_.Address).ToList();
            if (preds.Count == 0 || preds.Any(q => insl[q].Mnemonic == "bl")) return null;
            foreach (int q in preds)
            {
                bool broke = false;
                for (int i = q - 1; i > Math.Max(0, q - 16) - 1; i--)
                {
                    var p = insl[i];
                    var m = p.Mnemonic == "and" ? FM(@"([xw]\d+), ([xw]\d+), #(0x[0-9a-f]+|\d+)", p.OpStr) : null;
                    if (m != null && Num(m.Groups[1].Value) == ix)
                    {
                        if (Num(m.Groups[2].Value) != src || PyInt(m.Groups[3].Value) != mask) return null;
                        if (Slice(insl, i + 1, q + 1).Any(x => into.Contains(x.Address) || TableTarget(x.Address))) return null;
                        for (int z = i; z < q; z++) if (insl[z + 1].Address != insl[z].Address + 4) return null;
                        broke = true;
                        break;
                    }
                    var wr = Writes(p);
                    if (IsCf(p) || wr.Contains(ix) || wr.Contains(src)) return null;
                }
                if (!broke) return null;
            }
            long? tb = CopiedBase(insl, kl.Value, rb);
            if (tb == null || tb < 0 || tb + 4 * n > IMGLen) return null;
            var t2 = TableTargets(tb.Value, n);
            var addresses = insl.Select(p => p.Address).ToHashSet();
            return t2.All(addresses.Contains) ? t2 : null;
        }

        private static bool TailCallAtEnd(List<Insn> insl, int j)
        {
            if (j + 1 != insl.Count) return false;
            foreach (var p in Enumerable.Reverse(Slice(insl, 0, j)))
            {
                if (!WrittenNames(p).Contains("x18")) continue;
                return p.Mnemonic == "ldr" && FM(@"x18, \[(x\d+|sp)(, #(0x[0-9a-f]+|\d+))?\]", p.OpStr) != null;
            }
            return false;
        }

        private static bool TailCall(List<Insn> insl, int j)
        {
            if (j + 1 == insl.Count) return TailCallAtEnd(insl, j);
            if (j < 4) return false;
            for (int q = 0; q + 1 < insl.Count; q++) if (insl[q + 1].Address != insl[q].Address + 4) return false;
            var suffix = Slice(insl, j + 1, insl.Count);
            if (suffix[0].Mnemonic != "bl" || suffix.Skip(1).Any(p => p.Mnemonic != "udf")) return false;
            if (insl[0].Address <= suffix[0].Operands[^1].Imm && suffix[0].Operands[^1].Imm <= insl[^1].Address) return false;
            if (insl[0].Mnemonic != "stp" || insl[0].OpStr != "x29, x30, [sp, #-0x10]!") return false;
            if (insl[1].Mnemonic != "mov" || insl[1].OpStr != "x29, sp") return false;
            if (insl[j - 1].Mnemonic != "ldp" || insl[j - 1].OpStr != "x29, x30, [sp], #0x10") return false;
            var guard = insl[2];
            if (guard.Mnemonic != "cbz" || guard.Operands[^1].Imm != suffix[0].Address) return false;
            Insn load = null;
            for (int k = 3; k < j - 1; k++)
            {
                var p = insl[k];
                if (!(p.Mnemonic is "mov" or "ldr" or "ldur" or "ldp" or "str" or "stur" or "stp")) return false;
                var writes = WrittenNames(p).ToHashSet();
                if (writes.Overlaps(new[] { "sp", "wsp", "fp", "lr", "x29", "w29", "x30", "w30" })) return false;
                if (p.Mnemonic is "str" or "stur" or "stp")
                {
                    if (p.Writeback) return false;
                    var mem = p.Operands[^1].Mem;
                    string bn = p.RegName(mem.Base);
                    if (!(bn is "sp" or "fp" or "x29") || mem.Index != 0 || mem.Disp < 16) return false;
                }
                if (writes.Contains("x18") || writes.Contains("w18"))
                {
                    if (load != null || p.Mnemonic != "ldr" || FM(@"x18, \[(x\d+|sp)(, #(0x[0-9a-f]+|\d+))?\]", p.OpStr) == null) return false;
                    load = p;
                }
            }
            return load != null;
        }

        private (long Base, long Width)? JumpBytesFar(List<Insn> insl, int j)
        {
            var ctx = Slice(insl, j - 32, j);
            int k; Insn p = null;
            for (k = ctx.Count - 1; k >= 0; k--)
            {
                p = ctx[k];
                if (p.Mnemonic == "add" && p.OpStr.StartsWith("x18, x18,") && p.OpStr.Contains("lsl #2")) break;
                if (WrittenNames(p).Any(r => r == "x18")) return null;
            }
            if (k < 0) return null;
            string rn = p.RegName(p.Operands[2].Reg); int? idx = rn == "lr" ? 30 : rn == "fp" ? 29 : Num(rn);
            long? @base = Enumerable.Reverse(ctx.Take(k)).Where(q => q.Mnemonic == "adr" && q.OpStr.StartsWith("x18,")).Select(q => (long?)q.Operands[1].Imm).FirstOrDefault();
            var ld = Enumerable.Reverse(ctx.Take(k)).FirstOrDefault(q => q.Mnemonic is "ldrb" or "ldrsb" or "ldrh" or "ldrsh" && Num(q.RegName(q.Operands[0].Reg)) == idx);
            if (@base == null || ld == null) return null;
            if (ld.Mnemonic is "ldrb" or "ldrsb") return (@base.Value, 256);
            long? hc = HalfCount(insl, ld, @base.Value);
            return (@base.Value, hc is long h && h != 0 ? h : 65536);
        }

        private long? HalfCount(List<Insn> insl, Insn ld, long @base)
        {
            var m = ld.Mnemonic == "ldrh" ? FM(@"w\d+, \[(x\d+), [wx](\d+), (?:lsl|uxtw) #1\]", ld.OpStr) : null;
            if (m == null) return null;
            string tbReg = m.Groups[1].Value; int k = Idx(insl, ld);
            var idx = new HashSet<string> { "w" + m.Groups[2].Value }; Insn cmp = null;
            foreach (var p in Enumerable.Reverse(Slice(insl, k - 32, k)))
            {
                var mm = p.Mnemonic == "mov" ? FM(@"(w\d+), (w\d+)", p.OpStr) : null;
                if (mm != null && idx.Contains(mm.Groups[1].Value)) { idx.Add(mm.Groups[2].Value); continue; }
                mm = p.Mnemonic == "cmp" ? FM(@"(w\d+), #(0x[0-9a-f]+|\d+)", p.OpStr) : null;
                if (mm != null && idx.Contains(mm.Groups[1].Value)) { cmp = p; break; }
                if (WrittenNames(p).Any(r => idx.Contains("w" + r[1..]))) return null;
            }
            int kc = cmp != null ? Idx(insl, cmp) : -1;
            if (kc < 0 || !(insl[kc + 1].Mnemonic is "b.hi" or "b.hs" or "b.cs")) return null;
            long n = PyInt(cmp.OpStr.Split('#')[1]) + 1;
            long fa = insl[0].Address, fb = insl[^1].Address + 4;
            List<long> Entries(long tb) => 0 <= tb && tb + 2 * n <= IMGLen ? Enumerable.Range(0, (int)n).Select(i => (long)NsoCode.U16(IMG, tb + 2 * i)).ToList() : null;
            bool Fits(List<long> e) => e != null && e.All(x => fa <= @base + 4 * x && @base + 4 * x < fb);
            long? tb = TableBase(insl, k, tbReg);
            if (tb == null)
            {
                var ok = TableCands(insl, tbReg).Where(c => Fits(Entries(c))).ToList();
                tb = ok.Count == 1 ? ok[0] : null;
            }
            var e2 = tb != null ? Entries(tb.Value) : null;
            return Fits(e2) ? e2.Max() + 1 : null;
        }
    }
}
