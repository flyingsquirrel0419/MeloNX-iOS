using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MeloNX.Native.Prep.Rewriter
{
    // Ports of dm/tools/ue_malloc.py (Unreal's FMallocBinned3, found by its own name string, getter and vtable) and dm/tools/ue_cvar.py (Unreal console variables found by their registered names)
    public static class UnrealScan
    {
        private const uint RET = 0xD65F03C0;

        private static long AdrpPage(uint w, long pc)
        {
            long imm = (long)((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)) << 12;
            if ((imm & (1L << 32)) != 0) imm -= 1L << 33;
            return (pc & ~0xFFFL) + imm;
        }

        private static bool IsAdrp(uint w, int rd = -1) => (w & 0x9F000000) == 0x90000000 && (rd < 0 || (w & 31) == rd);

        // bytes.find(pattern, start, end)
        private static long Find(byte[] img, byte[] pat, long start, long end)
        {
            if (start < 0) start = Math.Max(0, img.Length + start);
            end = Math.Min(end, img.Length);
            if (start > end) return -1;
            int i = img.AsSpan((int)start, (int)(end - start)).IndexOf(pat);
            return i < 0 ? -1 : start + i;
        }

        private static readonly Dictionary<int, string> Layouts = new() { [19] = "Unreal Engine 4.26 / 4.27", [22] = "Unreal Engine 5", [26] = "Unreal Engine 5.6" };

        public static (long? Call, long? Vt, long? Slot, string Why) FindMalloc(byte[] img, long textEnd, long roOff, long dataOff)
        {
            uint Word(long a) => NsoCode.U32(img, a);
            byte[] name = Encoding.Unicode.GetBytes("Binned3").Concat(new byte[2]).ToArray();
            var names = new List<long>();
            long s = -1;
            while (true)
            {
                s = Find(img, name, s + 1, dataOff);
                if (s < 0) break;
                if (s >= roOff && s % 2 == 0 && (s == roOff || (img[s - 2] == 0 && img[s - 1] == 0))) names.Add(s);
            }
            if (names.Count == 0) return (null, null, null, "no FMallocBinned3 name");
            if (names.Count > 1) return (null, null, null, $"[RED] {names.Count} FMallocBinned3 names: " + string.Join(", ", names.Select(x => $"0x{x:x}")));
            s = names[0];
            byte[] tail = BitConverter.GetBytes(0x91000000u | (uint)((s & 0xFFF) << 10)).Concat(BitConverter.GetBytes(RET)).ToArray();
            var getters = new List<long>();
            long a = -1;
            while (true)
            {
                a = Find(img, tail, a + 1, textEnd);
                if (a < 0) break;
                if (a % 4 == 0 && a >= 4 && IsAdrp(Word(a - 4), 0) && AdrpPage(Word(a - 4), a - 4) == (s & ~0xFFFL)) getters.Add(a - 4);
            }
            if (getters.Count != 1) return (null, null, null, $"[RED] FMallocBinned3 name at 0x{s:x}: {getters.Count} getters");
            long g = getters[0];
            var rel = NsoCode.GotValues(img);
            long Value(long x) => rel.TryGetValue(x, out long v) ? v : (long)NsoCode.U64(img, x);
            var slots = rel.Where(kv => kv.Value == g && kv.Key >= dataOff).Select(kv => kv.Key).ToList();
            byte[] gb = BitConverter.GetBytes(g);
            a = dataOff - 8;
            while (true)
            {
                a = Find(img, gb, a + 8, img.Length);
                if (a < 0) break;
                if (a % 8 == 0 && !slots.Contains(a)) slots.Add(a);
            }
            if (slots.Count != 1) return (null, null, null, $"[RED] FMallocBinned3 getter at 0x{g:x}: {slots.Count} vtable slots");
            bool IsCode(long v) => 0 < v && v < textEnd && v % 4 == 0;
            long vt = slots[0];
            while (vt - 8 >= dataOff && IsCode(Value(vt - 8))) vt -= 8;
            long slot = (slots[0] - vt) / 8;
            if (Value(vt - 16) != 0 || Value(vt - 8) != 0) return (null, null, null, $"[RED] FMallocBinned3 vtable at 0x{vt:x}: no offset to top and RTTI words of 0 before it");
            if (!Layouts.ContainsKey((int)slot)) return (null, null, null, $"[RED] FMallocBinned3 vtable at 0x{vt:x}: the name getter is slot {slot}, a slot layout the host does not know");
            var dtors = new HashSet<long> { Value(vt), Value(vt + 8) };
            var bl = new Dictionary<long, List<long>>(); var b = new Dictionary<long, List<long>>();
            for (long m = 0; m < textEnd; m++)
            {
                byte c = img[m];
                if (!((c >= 0x94 && c <= 0x97) || (c >= 0x14 && c <= 0x17))) continue;
                long at = m - 3;
                if (at % 4 != 0) continue;
                uint w = Word(at); long t = at + ((((long)(w & 0x3FFFFFF)) ^ 0x2000000) - 0x2000000) * 4;
                var d = w >> 26 == 0x25 ? bl : b;
                if (!d.TryGetValue(t, out var l)) d[t] = l = new List<long>();
                l.Add(at);
            }
            long lo = vt & 0xFFF;
            var ctors = new HashSet<long>();
            for (long at = 0; at + 4 <= textEnd; at += 4)
            {
                if (img[at + 2] != (byte)(lo >> 6) || img[at + 3] != 0x91) continue;
                uint w = Word(at);
                if (((w >> 10) & 0xFFF) != lo) continue;
                int n = (int)((w >> 5) & 31), dreg = (int)(w & 31);
                bool adrp = false;
                for (long p = Math.Max(0, at - 32); p < at; p += 4) if (IsAdrp(Word(p), n) && AdrpPage(Word(p), p) == (vt & ~0xFFFL)) { adrp = true; break; }
                if (!adrp) continue;
                bool st = false;
                for (long q = at + 4; q < Math.Min(textEnd, at + 48); q += 4) if ((Word(q) & 0xFFFFFC1F) == (0xF9000000 | (uint)dreg)) { st = true; break; }
                if (!st) continue;
                long? start = null;
                foreach (long t in bl.Keys.Concat(b.Keys).Concat(dtors)) if (t <= at && (start == null || t > start)) start = t;
                bool ret = false;
                if (start != null) for (long q = start.Value; q < at; q += 4) if (Word(q) == RET) { ret = true; break; }
                if (start == null || ret) return (null, null, null, $"[RED] FMallocBinned3 vtable at 0x{vt:x}: no function start for its store at 0x{at:x}");
                if (!dtors.Contains(start.Value)) ctors.Add(start.Value);
            }
            if (ctors.Count != 1) return (null, null, null, $"[RED] FMallocBinned3 vtable at 0x{vt:x}: {ctors.Count} constructors (" + string.Join(", ", ctors.OrderBy(x => x).Select(x => $"0x{x:x}")) + ")");
            long ctor = ctors.First();
            int nbl = bl.GetValueOrDefault(ctor)?.Count ?? 0, nb = b.GetValueOrDefault(ctor)?.Count ?? 0;
            if (nbl != 1 || nb > 0) return (null, null, null, $"[RED] FMallocBinned3 constructor at 0x{ctor:x}: {nbl} calls and {nb} jumps, not one call");
            return (bl[ctor][0], vt, slot, $"FMallocBinned3 ({Layouts[(int)slot]}): its constructor at 0x{ctor:x}, called at 0x{bl[ctor][0]:x}; its vtable 0x{vt:x}, the name getter slot {slot}");
        }

        public static readonly string[] CvarNames = { "t.MaxFPS", "rhi.SyncInterval", "nvn.SyncInterval", "r.Streaming.PoolSize", "Project.FrameRateLimit" };

        private static (int D, int N, long Imm)? AddImm(uint w)
        {
            if ((w & 0xFF800000) != 0x91000000) return null;
            return ((int)(w & 31), (int)((w >> 5) & 31), (long)((w >> 10) & 0xFFF) << (int)(12 * ((w >> 22) & 1)));
        }

        private static long? RegisteredAt(Func<long, uint> word, long textEnd, long j)
        {
            var nameAdd = AddImm(word(j));
            if (nameAdd == null || nameAdd.Value.D != 1) return null;
            var val = new Dictionary<int, long>(); bool name = false, registered = false;
            for (long t = Math.Max(0, j - 64); t < Math.Min(textEnd, j + 192); t += 4)
            {
                uint u = word(t);
                bool call = (u & 0xFC000000) == 0x94000000 || (u & 0xFFFFFC1F) == 0xD63F0000;
                if (t < j && (call || (u & 0xFC000000) == 0x14000000 || u == RET)) { val.Clear(); continue; }
                if (call)
                {
                    if (!registered)
                    {
                        if (!name) return null;
                        if (u >> 26 == 0x25) return val.TryGetValue(0, out long v0) ? v0 : null;
                        registered = true;
                    }
                    for (int r = 0; r < 19; r++) val.Remove(r);
                    name = false; continue;
                }
                if ((u & 0xFC000000) == 0x14000000 || u == RET) break;
                if (registered && (u & 0xFFC0001F) == 0xF9000000 && ((u >> 10) & 0xFFF) == 2 && val.ContainsKey((int)((u >> 5) & 31))) return val[(int)((u >> 5) & 31)];
                var a = AddImm(u); int d = (int)(u & 31); long? v = null;
                if (IsAdrp(u))
                {
                    if (registered && d == 1) break;
                    v = AdrpPage(u, t);
                }
                else if (a != null) v = val.TryGetValue(a.Value.N, out long b0) ? b0 + a.Value.Imm : null;
                else if ((u & 0xFFE0FFE0) == 0xAA0003E0) v = val.TryGetValue((int)((u >> 16) & 31), out long b1) ? b1 : null;
                else if ((u & 0x0A000000) == 0x08000000)
                {
                    if (((u >> 22) & 1) == 0) continue;
                    if ((u & 0x3A000000) == 0x28000000) val.Remove((int)((u >> 10) & 31));
                }
                else if ((u & 0x1C000000) == 0x14000000) continue;
                if (d == 1) name = t == j;
                if (v == null) val.Remove(d);
                else val[d] = v.Value;
            }
            return null;
        }

        public static (long? Offset, string Why) FindCvar(byte[] img, long textEnd, long roOff, long dataOff, string name)
        {
            uint Word(long a) => NsoCode.U32(img, a);
            var objs = new HashSet<long>();
            foreach (int z in new[] { 2, 4 })
            {
                byte[] pat = (z == 2 ? Encoding.Unicode : new UTF32Encoding(false, false)).GetBytes(name).Concat(new byte[z]).ToArray();
                long s = Find(img, pat, roOff, dataOff);
                while (s >= 0)
                {
                    if (s % z == 0)
                    {
                        long lo = s & 0xFFF;
                        for (long m = 1; m < textEnd; m++)
                        {
                            // (?=[b1]<lo>>6>\x91) at m, with the add word starting at m - 1
                            byte c0 = img[m];
                            if ((c0 >> 2) != (lo & 0x3F) || m + 2 >= textEnd || img[m + 1] != (byte)(lo >> 6) || img[m + 2] != 0x91) continue;
                            long j = m - 1;
                            if (j % 4 != 0) continue;
                            var a = AddImm(Word(j));
                            if (a == null || a.Value.Imm != lo) continue;
                            bool adrp = false;
                            for (long i = Math.Max(0, j - 20); i < j; i += 4)
                                if (IsAdrp(Word(i)) && (Word(i) & 31) == a.Value.N && AdrpPage(Word(i), i) == (s & ~0xFFFL)) { adrp = true; break; }
                            if (!adrp) continue;
                            long? o = RegisteredAt(Word, textEnd, j);
                            if (o != null) objs.Add(o.Value);
                        }
                    }
                    s = Find(img, pat, s + z, dataOff);
                }
            }
            if (objs.Count == 0) return (null, $"{name}: not registered");
            if (objs.Count > 1) return (null, $"[RED] {name}: registered at {objs.Count} objects (" + string.Join(", ", objs.OrderBy(x => x).Select(x => $"0x{x:x}")) + ")");
            long obj = objs.First();
            return (obj, $"{name} at 0x{obj:x}");
        }

        public static (Dictionary<string, long> Found, List<string> Why) FindAllCvars(byte[] img, long textEnd, long roOff, long dataOff)
        {
            var found = new Dictionary<string, long>(); var why = new List<string>();
            foreach (var n in CvarNames)
            {
                var (o, r) = FindCvar(img, textEnd, roOff, dataOff, n);
                if (o != null) found[n] = o.Value;
                else why.Add(r);
            }
            return (found, why.OrderBy(r => !r.StartsWith("[RED] ")).ToList());
        }
    }
}
