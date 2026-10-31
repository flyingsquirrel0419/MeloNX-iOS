using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using static MeloNX.Native.Prep.Rewriter.NsoAsm;

namespace MeloNX.Native.Prep.Rewriter
{
    // Port of nxnative's dm/tools/patch_nso.py, the generic NSO rewriter: a Switch aarch64 module → an image that executes natively on Apple systems.
    // The comments of the Python tool explain every rule; this port keeps its structure and names so the two can be compared side by side, and its outputs byte-identical
    // (tools/native/identity_test.py checks that on synthetic modules, and on real ones when game files are at hand).
    public sealed class RewriteOptions
    {
        public string Profile = "";          // DM_GAME's base name: the profile whose MATCH_CUTS and build rows apply
        public long? PatchFront;             // DM_PATCH_FRONT, set only by the rewriter's own second pass
        public bool SpinList;                // DM_SPIN_LIST
        public Action<double> Progress;      // the analysis's progress (0..1) on a big module, for the app's preparation sheet; no effect on the outputs
    }

    public sealed class RewriteResult
    {
        public byte[] PatchedBin;
        public Dictionary<string, string> Files = new();   // file name → contents (fixups.tsv, gates.tsv, sites.tsv, cuts.tsv, obs.tsv, and match.tsv when there is one)
        public List<string> Log = new();
    }

    internal sealed class RerunWithFront : Exception
    {
        public readonly long Need;
        public RerunWithFront(long need) : base("rerun") { Need = need; }
    }

    public sealed partial class PatchNso
    {
        public static RewriteResult Rewrite(NsoModule mod, string name, PatchTables tables, RewriteOptions options)
        {
            options ??= new RewriteOptions();
            try { return new PatchNso(mod, name, tables, options).Run(); }
            catch (RerunWithFront r)
            {
                var again = new RewriteOptions { Profile = options.Profile, PatchFront = r.Need, SpinList = options.SpinList, Progress = options.Progress };
                return new PatchNso(mod, name, tables, again).Run();   // the module's own image is never changed: each pass copies it
            }
        }

        // ---- Python helpers ----
        private static readonly Dictionary<string, Regex> RxCache = new();
        private static Regex Rx(string pattern)
        {
            lock (RxCache)
            {
                if (!RxCache.TryGetValue(pattern, out var r)) RxCache[pattern] = r = new Regex(pattern, RegexOptions.CultureInvariant);
                return r;
            }
        }
        private static Match FM(string pattern, string s)
        {
            var m = Rx(@"\A(?:" + pattern + @")\z").Match(s ?? "");
            return m.Success ? m : null;
        }
        private static long PyInt(string s)
        {
            s = s.Trim();
            bool neg = s.StartsWith('-');
            if (neg || s.StartsWith('+')) s = s[1..];
            long v = s.StartsWith("0x") || s.StartsWith("0X") ? long.Parse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture) : long.Parse(s, CultureInfo.InvariantCulture);
            return neg ? -v : v;
        }
        private static string Hx(long v) => v < 0 ? $"-0x{-v:x}" : $"0x{v:x}";   // Python's f'{v:#x}'
        private static bool IsCondBranch(string m) => m is "cbz" or "cbnz" or "tbz" or "tbnz" || m.StartsWith("b.");
        private static bool IsDirectBranch(string m) => m is "b" or "bl" or "cbz" or "cbnz" or "tbz" or "tbnz" || m.StartsWith("b.");

        // ---- State (the Python tool's globals) ----
        private readonly NsoModule MOD;
        private readonly string NAME;
        private readonly PatchTables PATCHES;
        private readonly RewriteOptions Opt;
        private readonly RewriteResult Res = new();
        private byte[] IMG;
        private int IMGLen;          // the image's length (IMG may be longer: the key page is appended in place)
        private readonly long bss, TEXT_END, RO_OFF, DATA_OFF;
        private readonly bool FAR, BIG_TEXT, TWO;
        private readonly long FRONT, NEAR_PATCH_OFF;
        private readonly long? SPLIT;
        private long FILE_IMAGE_LEN, KEY_PAGE_OFF, IMAGE_SIZE, PATCH_OFF, BACK_OFF;
        private string BUILD_ID;
        private List<Cut> cuts;

        private static readonly Dictionary<string, int> KEY_INDEX = new() { ["K18"] = 0, ["KTLS"] = 1, ["KTLR"] = 2, ["KGATE"] = 3 };

        private Cs md, mdLite;
        private List<byte> patch, patchFront, patchBack;
        private long PATCH_BASE;
        private readonly List<(int Pos, string Kind)> fix = new();
        private readonly List<(long Ret, string Kind, long Arg, long Orig)> gates = new();
        private readonly Dictionary<string, int> stats = new();

        private Dictionary<string, long> UE_CVARS = new();
        private long? UE_CALL, UE_VT, UE_SLOT;

        private List<long> starts;
        private List<(long S, long E)> DATA_BLOCKS, CODE_RANGES;
        private HashSet<long> x18;
        private readonly SortedDictionary<long, (string Kind, long Arg)> kinds = new();
        private readonly Dictionary<long, List<long>> spin_cand = new();
        private readonly HashSet<long> done = new();
        private readonly List<List<Insn>> windows = new();
        private readonly Dictionary<long, (long Base, long Width)> jumps = new();
        private readonly Dictionary<long, List<long>> tabjumps = new();
        private readonly HashSet<long> tailcalls = new();
        private readonly List<List<(List<Insn> Seg, long Ft)>> retries = new();
        private List<ObsEntry> obs;
        private long FS_STATE_OFF;
        private int RENDER_SCALE;

        private PatchNso(NsoModule mod, string name, PatchTables tables, RewriteOptions options)
        {
            MOD = mod; NAME = name; PATCHES = tables; Opt = options;
            bss = mod.Bss;
            int imgLen = mod.Image.Length;
            NEAR_PATCH_OFF = ((((imgLen + bss + 0x3FFF) & ~0x3FFFL) + 0x4000 + 0xFFFF) & ~0xFFFFL);
            FAR = NEAR_PATCH_OFF > 0x7000000; FRONT = 0x2000000;
            BIG_TEXT = FAR && mod.TextEnd + FRONT > 0x8000000 - 0x10000;
            TWO = BIG_TEXT && mod.TextEnd > 0x8000000 - 0x10000;
            long pf = options.PatchFront ?? 0;
            if (TWO) FRONT = pf != 0 ? pf : 0x1000000;
            else if (BIG_TEXT) FRONT = pf != 0 ? pf : (0x8000000 - 0x10000 - mod.TextEnd) & ~0xFFFFL;
            SPLIT = TWO ? 0x8000000 - FRONT - 0x100000 : null;
            // IMG: the image, bss appended unless FAR, then the key page; room for both is allocated up front
            long len = imgLen;
            if (!FAR) len += bss;
            TEXT_END = mod.TextEnd;
            RO_OFF = mod.Segments[1].Offset; DATA_OFF = mod.Segments[2].Offset;
            if (FAR)
            {
                FILE_IMAGE_LEN = (len + 0x3FFF) & ~0x3FFFL;
                KEY_PAGE_OFF = (len + bss + 0x3FFF) & ~0x3FFFL;
                IMAGE_SIZE = KEY_PAGE_OFF + 0x4000; PATCH_OFF = -FRONT;
                BACK_OFF = TWO ? (KEY_PAGE_OFF + 0x8000 + 0xFFFF) & ~0xFFFFL : 0;
                IMG = new byte[len]; IMGLen = (int)len;
            }
            else
            {
                KEY_PAGE_OFF = (len + 0x3FFF) & ~0x3FFFL;
                IMGLen = (int)(len + 0x4000);   // IMG.extend(bytes(0x4000)): from the unpadded end, as the Python tool does
                PATCH_OFF = (IMGLen + 0xFFFF) & ~0xFFFFL;
                IMAGE_SIZE = BACK_OFF = 0;
                IMG = new byte[IMGLen];
            }
            Array.Copy(mod.Image, IMG, imgLen);
        }

        private void Log(string s) => Res.Log.Add(s);
        private void Stat(string k) => stats[k] = stats.GetValueOrDefault(k) + 1;

        private uint W(long o) => NsoCode.U32(IMG, o);
        private void PutW(long o, uint w) => BitConverter.TryWriteBytes(IMG.AsSpan((int)o), w);
        private bool ImgEq(long off, byte[] b) => off >= 0 && off + b.Length <= IMGLen && IMG.AsSpan((int)off, b.Length).SequenceEqual(b);
        private string ImgHex(long off, int n) => Convert.ToHexStringLower(IMG.AsSpan((int)off, (int)Math.Max(0, Math.Min(n, IMGLen - off))));

        private RewriteResult Run()
        {
            md = new Cs(true); mdLite = new Cs(false);
            try
            {
                LoadCuts();
                Analyse();
                return Output();
            }
            finally { md.Dispose(); mdLite.Dispose(); }
        }

        // ---- Registered patches ----
        private void LoadCuts()
        {
            BUILD_ID = Convert.ToHexStringLower(MOD.BuildId.AsSpan(0, 0x10));
            cuts = new List<Cut>(PATCHES.Cuts.GetValueOrDefault(BUILD_ID) ?? new List<Cut>());
            if (!PATCHES.Cuts.ContainsKey(BUILD_ID))
            {
                string profile = Opt.Profile.TrimEnd('/');
                profile = profile.Contains('/') ? profile[(profile.LastIndexOf('/') + 1)..] : profile;
                var known = new List<(string Bid, string Disp, int N)>(); var own = new HashSet<string>();
                var rows = profile.Length > 0 ? PATCHES.BuildRows.GetValueOrDefault(profile) ?? new List<string[]>() : new List<string[]>();
                foreach (var c in rows)
                {
                    if (c[0] == "build" && c.Length > 3)
                    {
                        var d = new Dictionary<string, string>();
                        foreach (var x in c.Skip(3)) if (x.Contains('=')) { int i = x.IndexOf('='); d[x[..i]] = x[(i + 1)..]; }
                        string bid = d.GetValueOrDefault(NAME);
                        if (!string.IsNullOrEmpty(bid)) own.Add(bid);
                        if (!string.IsNullOrEmpty(bid) && bid != BUILD_ID && PATCHES.Cuts.TryGetValue(bid, out var bc) && bc.Count > 0) known.Add((bid, c[2], bc.Count));
                    }
                }
                var outcomes = new List<(string, List<long>, string)>(); var sdkOutcomes = new List<(string, List<long>, string)>();
                var img = IMG.AsSpan(0, IMGLen).ToArray();
                var profRules = PATCHES.MatchCuts.GetValueOrDefault(profile)?.GetValueOrDefault(NAME) ?? new List<MatchRule>();
                cuts.AddRange(MatchImage.Resolve(img, TEXT_END, md, profRules, Log, outcomes));
                cuts.AddRange(MatchImage.Resolve(img, TEXT_END, md, PATCHES.SdkMatchCuts.GetValueOrDefault(NAME) ?? new List<MatchRule>(), Log, sdkOutcomes, red: false));
                if (!own.Contains(BUILD_ID) && (known.Count > 0 || outcomes.Count > 0 || sdkOutcomes.Count > 0))
                {
                    var sb = new StringBuilder();
                    sb.Append($"# {NAME} {BUILD_ID}: not a registered build. registered: build ID, display version, cuts; patch (the game profile's) or sdk (SDK-wide): name, cut offsets or -, implementation or why not\n");
                    foreach (var (bid, disp, n) in known) sb.Append($"registered\t{bid}\t{disp}\t{n}\n");
                    foreach (var (kind, got) in new[] { ("patch", outcomes), ("sdk", sdkOutcomes) })
                        foreach (var (nm, offs, why) in got) sb.Append($"{kind}\t{nm}\t{(offs != null && offs.Count > 0 ? string.Join(",", offs.Select(Hx)) : "-")}\t{why}\n");
                    Res.Files[NAME + ".match.tsv"] = sb.ToString();
                }
            }
            foreach (var c in cuts)
            {
                byte[] ob = Convert.FromHexString(c.Old), nb = Convert.FromHexString(c.New);
                RewriteAssertion.Check(ob.Length == nb.Length && ImgEq(c.Offset, ob), $"cut original bytes mismatch {Hx(c.Offset)}: {ImgHex(c.Offset, ob.Length)}");
                nb.CopyTo(IMG, c.Offset);
            }

            // Unreal console variables in main, and Unreal's FMallocBinned3 in any module
            var snapshot = IMG.AsSpan(0, IMGLen).ToArray();
            List<string> cvarWhy;
            if (NAME == "main") (UE_CVARS, cvarWhy) = UnrealScan.FindAllCvars(snapshot, TEXT_END, RO_OFF, DATA_OFF);
            else cvarWhy = new List<string>();
            if (UE_CVARS.Count > 0) Log($"{NAME}: Unreal console variables (ue_cvar.py): " + string.Join(", ", UE_CVARS.Select(kv => $"{kv.Key} at {Hx(kv.Value)}")));
            foreach (var w in cvarWhy) if (w.StartsWith("[RED] ")) Log($"[RED] {NAME}: Unreal console variable {w[6..]}: the host cannot write it");
            var (call, vt, slot, ueWhy) = UnrealScan.FindMalloc(snapshot, TEXT_END, RO_OFF, DATA_OFF);
            UE_CALL = call; UE_VT = vt; UE_SLOT = slot;
            if (UE_CALL != null)
            {
                long uc = UE_CALL.Value;
                cuts.Add(new Cut(uc, ImgHex(uc, 4), Convert.ToHexStringLower(BitConverter.GetBytes(NOP)), $"{ueWhy}: the constructor call → nop, gate OBS_UE_MALLOC on it (ue_malloc.py)"));
                PutW(uc, NOP);
                Log($"{NAME}: {ueWhy}");
            }
            else if (ueWhy.StartsWith("[RED] ")) Log($"[RED] {NAME}: {ueWhy[6..]}: Unreal's own allocator runs");
        }

        // ---- Patch area ----
        private void UseArea(long a)
        {
            if (TWO && a >= SPLIT) { patch = patchBack; PATCH_BASE = BACK_OFF; }
            else { patch = patchFront; PATCH_BASE = PATCH_OFF; }
        }
        private long Here() => PATCH_BASE + patch.Count;
        private void Emit(uint w, string kind = null)
        {
            if (kind != null) fix.Add((patch.Count, kind));
            patch.Add((byte)w); patch.Add((byte)(w >> 8)); patch.Add((byte)(w >> 16)); patch.Add((byte)(w >> 24));
        }
        private void SetPatchWord(int idx, uint w) { patch[idx] = (byte)w; patch[idx + 1] = (byte)(w >> 8); patch[idx + 2] = (byte)(w >> 16); patch[idx + 3] = (byte)(w >> 24); }
        private void EmitKeyAddr(int reg, string kind)
        {
            fix.Add((patch.Count, kind)); Emit(ADRP(reg, Here(), KEY_PAGE_OFF)); Emit(LDRX(reg, reg, KEY_INDEX[kind]));
        }
        private void EmitSlotAddr(int @base, int keyReg, string kind)
        {
            EmitKeyAddr(keyReg, kind); Emit(ADDR(@base, @base, keyReg));
        }

        // ---- Disassembly helpers ----
        private Insn Dis(uint w, long addr)
        {
            var l = md.Disasm(BitConverter.GetBytes(w), addr);
            RewriteAssertion.Check(l.Count == 1, $"0x{w:x}");
            return l[0];
        }
        private static (HashSet<string> R, HashSet<string> W) Regset(Insn ins)
        {
            var (r, w) = ins.RegsAccess();
            return (r.Select(x => ins.RegName(x)).ToHashSet(), w.Select(x => ins.RegName(x)).ToHashSet());
        }
        private static int? Num(string name)
        {
            var m = FM(@"[xw](\d+)", name ?? "");
            return m != null ? int.Parse(m.Groups[1].Value) : null;
        }
        private static bool Has18(Insn ins) => Rx(@"\b[xw]18\b").IsMatch(ins.OpStr);
        private static HashSet<int> RegsIn(Insn ins)
        {
            var s = Rx(@"\b[xw](\d+)\b").Matches(ins.OpStr).Select(m => int.Parse(m.Groups[1].Value)).ToHashSet();
            try
            {
                var (rd, wr) = Regset(ins);
                foreach (var n in rd.Concat(wr)) { var v = Num(n); if (v != null) s.Add(v.Value); }
            }
            catch (Exception) { }
            return s;
        }
        private static int[] Pick(ICollection<int> avoid, int n = 2)
        {
            var o = Enumerable.Range(0, 16).Where(r => !avoid.Contains(r) && r != 18).Take(n).ToArray();
            RewriteAssertion.Check(o.Length == n);
            return o;
        }

        private static IEnumerable<int[]> Combinations(int[] pool, int k)
        {
            int n = pool.Length;
            if (k > n) yield break;
            var idx = Enumerable.Range(0, k).ToArray();
            while (true)
            {
                yield return idx.Select(i => pool[i]).ToArray();
                int j = k - 1;
                while (j >= 0 && idx[j] == j + n - k) j--;
                if (j < 0) yield break;
                idx[j]++;
                for (int q = j + 1; q < k; q++) idx[q] = idx[q - 1] + 1;
            }
        }

        // x18/w18 → xS/wS: only the 4 register field positions are changed, verified against the disassembly text
        private uint Subst(Insn ins, int S)
        {
            uint w = ins.Word;
            string want = Rx(@"\b([xw])18\b").Replace(ins.OpStr, m => $"{m.Groups[1].Value}{S}");
            var pos = new[] { 0, 5, 10, 16 }.Where(p => ((w >> p) & 31) == 18).ToArray();
            for (int k = pos.Length; k > 0; k--)
            {
                foreach (var c in Combinations(pos, k))
                {
                    uint nw = w;
                    foreach (int p in c) nw = (nw & ~(31u << p)) | ((uint)S << p);
                    Insn dd;
                    try { dd = Dis(nw, ins.Address); }
                    catch (RewriteAssertion) { continue; }
                    if (dd.Mnemonic == ins.Mnemonic && dd.OpStr == want) return nw;
                }
            }
            throw new InvalidOperationException($"subst fail {ins.Address:x} {ins.Mnemonic} {ins.OpStr}");
        }

        // ---- Rewrite blocks of each kind ----
        private static long SpDelta(Insn ins)
        {
            var m = Rx(@"\[sp, #(-?(?:0x)?[0-9a-f]+)\]!").Match(ins.OpStr);
            if (m.Success) return PyInt(m.Groups[1].Value);
            m = Rx(@"\[sp\], #(-?(?:0x)?[0-9a-f]+)\z").Match(ins.OpStr);
            if (m.Success) return PyInt(m.Groups[1].Value);
            RewriteAssertion.Check(!Rx(@"\A(sp|wsp),").IsMatch(ins.OpStr), $"writes sp: {ins.Address:x} {ins.OpStr}");
            return 0;
        }

        private long SitePlain(Insn ins)
        {
            var st = Pick(RegsIn(ins)); int S = st[0], T = st[1];
            long dlt = SpDelta(ins);
            long save = dlt == 0 ? -16 : -112;
            RewriteAssertion.Check(dlt == 0 || dlt >= -96, $"sp delta {dlt} at {ins.Address:x}");
            long start = Here();
            Emit(STP(S, T, 31, save)); Emit(MRS_TPIDRRO(T)); EmitSlotAddr(T, S, "K18"); Emit(LDRX(S, T));
            Emit(Subst(ins, S));
            Emit(STRX(S, T));
            Emit(LDP(S, T, 31, save - dlt)); Emit(B(Here(), ins.Address + 4));
            return start;
        }

        private long SiteSp(Insn ins)
        {
            var st = Pick(RegsIn(ins)); int S = st[0], T = st[1];
            long start = Here();
            Emit(STP(S, T, 31, -16)); Emit(MRS_TPIDRRO(T)); EmitSlotAddr(T, S, "K18"); Emit(LDRX(S, T));
            Emit(ADDI(T, 31, 0));
            Emit(Subst(ins, S));
            Emit(LDP(S, T, T, -16)); Emit(B(Here(), ins.Address + 4));
            return start;
        }

        private long SiteSpAlign(Insn ins, int n)
        {
            long start = Here();
            Emit(ADDI(n, n, 15)); Emit(0x927CEC00u | (uint)(n << 5) | (uint)n);
            Emit(ins.Word); Emit(B(Here(), ins.Address + 4));
            return start;
        }

        private long SiteCond(Insn ins)
        {
            uint w = ins.Word;
            var st = Pick(RegsIn(ins)); int S = st[0], T = st[1];
            long tgt = ins.Operands[^1].Imm;
            long start = Here();
            Emit(STP(S, T, 31, -16)); Emit(MRS_TPIDRRO(T)); EmitSlotAddr(T, S, "K18"); Emit(LDRX(S, T));
            string m = ins.Mnemonic;
            long taken = Here() + 4 * 3;
            long off = (taken - Here()) >> 2;
            uint nw = m is "cbz" or "cbnz" ? (w & 0xFF000000) | (uint)((off & 0x7FFFF) << 5) | (uint)S : (w & 0xFFF80000) | (uint)((off & 0x3FFF) << 5) | (uint)S;
            long pc = Here(); Emit(nw);
            var dd = Dis(nw, pc); RewriteAssertion.Check(dd.Mnemonic == m && dd.Operands[^1].Imm == taken);
            Emit(LDP(S, T, 31, -16)); Emit(B(Here(), ins.Address + 4));
            RewriteAssertion.Check(Here() == taken);
            Emit(LDP(S, T, 31, -16)); Emit(B(Here(), tgt));
            return start;
        }

        private long SitePcrel(Insn ins)
        {
            long tgt = ins.Operands[1].Imm;
            var st = Pick(new HashSet<int>()); int S = st[0], T = st[1];
            long start = Here();
            Emit(STP(S, T, 31, -16)); Emit(MRS_TPIDRRO(T)); EmitSlotAddr(T, S, "K18");
            long pc = Here(); Emit(ADRP(S, pc, tgt));
            if (ins.Mnemonic == "adr") Emit(ADDI(S, S, tgt & 0xFFF));
            Emit(STRX(S, T));
            Emit(LDP(S, T, 31, -16)); Emit(B(Here(), ins.Address + 4));
            return start;
        }

        private long SiteBr(Insn ins, long @base, long count)
        {
            long start = Here();
            Emit(STUR(16, 31, -16)); Emit(STUR(17, 31, -24));
            Emit(MRS_TPIDRRO(16)); EmitSlotAddr(16, 17, "K18"); Emit(LDRX(16, 16)); Emit(LDUR(17, 31, -24));
            long padbase = start + 4 * 24;
            long delta = padbase - @base;
            Func<int, int, long, int, uint> op = delta >= 0 ? (d, n, i, sh) => ADDI(d, n, i, sh) : (d, n, i, sh) => SUBI(d, n, i, sh);
            long dl = Math.Abs(delta);
            var ops = new List<uint>(); long hi = dl >> 12, lo = dl & 0xFFF;
            while (hi != 0) { long h = Math.Min(hi, 0xFFF); ops.Add(op(16, 16, h, 1)); hi -= h; }
            if (lo != 0) ops.Add(op(16, 16, lo, 0));
            RewriteAssertion.Check(ops.Count <= 12);
            foreach (var o in ops) Emit(o);
            Emit(BR(16));
            while (Here() < padbase) Emit(NOP);
            long tails = padbase + 4 * count;
            for (long i = 0; i < count; i++) Emit(B(Here(), tails + 8 * i));
            for (long i = 0; i < count; i++)
            {
                Emit(0xF85F0000u | (31 << 5) | 16);
                Emit(B(Here(), @base + 4 * i));
            }
            return start;
        }

        private long SiteBrTab(Insn ins, List<long> targets)
        {
            long start = Here();
            Emit(STUR(16, 31, -16)); Emit(STUR(17, 31, -24));
            Emit(MRS_TPIDRRO(16)); EmitSlotAddr(16, 17, "K18"); Emit(LDRX(16, 16));
            var uniq = targets.Distinct().OrderBy(x => x).ToList();
            long pads = Here() + 4 * (4 * uniq.Count + 1);
            for (int k = 0; k < uniq.Count; k++)
            {
                long t = uniq[k];
                Emit(ADRP(17, Here(), t)); Emit(ADDI(17, 17, t & 0xFFF)); Emit(CMPR(16, 17)); Emit(BEQ(Here(), pads + 12 * k));
            }
            Emit(BRK(0x18));
            foreach (long t in uniq) { Emit(LDUR(16, 31, -16)); Emit(LDUR(17, 31, -24)); Emit(B(Here(), t)); }
            return start;
        }

        private long SiteBlr(Insn ins)
        {
            long start = Here();
            Emit(MRS_TPIDRRO(16)); EmitSlotAddr(16, 17, "K18"); Emit(LDRX(16, 16));
            long ret = ins.Address + 4;
            Emit(ADRP(30, Here(), ret)); Emit(ADDI(30, 30, ret & 0xFFF)); Emit(BR(16));
            return start;
        }

        private long SiteBrCall(Insn ins)
        {
            long start = Here();
            Emit(MRS_TPIDRRO(16)); EmitSlotAddr(16, 17, "K18"); Emit(LDRX(16, 16)); Emit(BR(16));
            return start;
        }

        private long SiteSysregRead(Insn ins, string kind)
        {
            int N = (int)(ins.Word & 31);
            int tmp = N != 16 ? 16 : 17;
            long start = Here();
            Emit(STUR(tmp, 31, -16)); Emit(MRS_TPIDRRO(N)); EmitSlotAddr(N, tmp, kind); Emit(LDRX(N, N)); Emit(LDUR(tmp, 31, -16));
            Emit(B(Here(), ins.Address + 4));
            return start;
        }

        private long SiteTpidrWrite(Insn ins)
        {
            int N = (int)(ins.Word & 31);
            int T = Pick(new HashSet<int> { N }, 1)[0];
            long start = Here();
            Emit(0xF81F0000u | (31 << 5) | (uint)T);
            int tmp = new[] { 16, 17 }.First(x => x != N && x != T);
            Emit(STUR(tmp, 31, -24)); Emit(MRS_TPIDRRO(T)); EmitSlotAddr(T, tmp, "KTLS"); Emit(STRX(N, T)); Emit(LDUR(tmp, 31, -24));
            Emit(0xF85F0000u | (31 << 5) | (uint)T);
            Emit(B(Here(), ins.Address + 4));
            return start;
        }

        private void EmitGateCall()
        {
            Emit(MRS_TPIDRRO(30)); EmitSlotAddr(30, 29, "KGATE"); Emit(LDRX(30, 30)); Emit(LDRX(29, 31));
        }

        private long SiteGate(Insn ins, string kind, long arg)
        {
            long start = Here();
            Emit(STP_PRE(29, 30, 31, -16));
            EmitGateCall();
            Emit(BLR(30));
            long ret = Here();
            Emit(LDP_POST(29, 30, 31, 16));
            Emit(B(Here(), ins.Address + 4));
            gates.Add((ret, kind, arg, ins.Address));
            return start;
        }

        private long SiteObs(long off, long oid, uint word)
        {
            var ins = Dis(word, off);
            RewriteAssertion.Check(!(ins.Mnemonic is "adr" or "adrp" or "b" or "bl" or "br" or "blr" or "ret" or "cbz" or "cbnz" or "tbz" or "tbnz") && !ins.Mnemonic.StartsWith("b.")
                && !(ins.Mnemonic.StartsWith("ldr") && !ins.OpStr.Contains('[')) && !Has18(ins), $"observation gate original instruction cannot be relocated {Hx(off)} {ins.Mnemonic} {ins.OpStr}");
            long start = Here();
            Emit(STP_PRE(29, 30, 31, -16));
            EmitGateCall();
            Emit(BLR(30));
            long ret = Here();
            Emit(LDP_POST(29, 30, 31, 16));
            Emit(word);
            Emit(B(Here(), off + 4));
            gates.Add((ret, "obs", oid, off));
            return start;
        }

        // ---- Exclusive windows ----
        private static readonly string[] EXCL_LD = { "ldxr", "ldaxr", "ldxp", "ldaxp", "ldxrb", "ldaxrb", "ldxrh", "ldaxrh" };
        private static readonly string[] EXCL_ST = { "stxr", "stlxr", "stxp", "stlxp", "stxrb", "stlxrb", "stxrh", "stlxrh" };

        private static List<List<Insn>> FindWindows(List<Insn> insl)
        {
            var out_ = new List<List<Insn>>();
            for (int i = 0; i < insl.Count; i++)
            {
                if (!EXCL_LD.Contains(insl[i].Mnemonic)) continue;
                int j = i;
                while (j < insl.Count && !EXCL_ST.Contains(insl[j].Mnemonic)) j++;
                if (j >= insl.Count || j - i >= 16) continue;
                bool other = false;
                for (int k = i + 1; k < j; k++) if (EXCL_LD.Contains(insl[k].Mnemonic)) { other = true; break; }
                if (other) continue;
                if (j + 1 < insl.Count && insl[j + 1].Mnemonic is "cbz" or "cbnz") j++;
                var seg = insl.GetRange(i, j + 1 - i);
                if (seg.Any(Has18)) out_.Add(seg);
            }
            return out_;
        }

        private static uint WindowAdrp(Insn x, int S, long pc)
        {
            int rd = Num(x.RegName(x.Operands[0].Reg)) ?? -1;
            return ADRP(rd == 18 ? S : rd, pc, x.Operands[1].Imm);
        }

        private uint RebranchInWindow(Insn x, uint w, long pc, long newt)
        {
            long off = (newt - pc) >> 2;
            if (x.Mnemonic is "tbz" or "tbnz") w = (w & 0xFFF8001F) | (uint)((off & 0x3FFF) << 5);
            else w = (w & 0xFF00001F) | (uint)((off & 0x7FFFF) << 5);
            var dd = Dis(w, pc); RewriteAssertion.Check(dd.Operands[^1].Imm == newt && dd.Mnemonic == x.Mnemonic);
            return w;
        }

        private static void CheckCopyable(Insn x)
        {
            string m = x.Mnemonic;
            RewriteAssertion.Check(!(m is "adr" or "adrp" or "b" or "bl" or "br" or "blr" or "ret") && !(m == "ldr" && !x.OpStr.Contains('[')), $"0x{x.Address:x}");
        }

        private (long Start, long Lo, long Hi) SiteWindow(List<Insn> seg)
        {
            var used = new HashSet<int>();
            foreach (var x in seg) used.UnionWith(RegsIn(x));
            var st = Pick(used); int S = st[0], T = st[1];
            long lo = seg[0].Address, hi = seg[^1].Address + 4;
            long start = Here();
            Emit(STP(S, T, 31, -16)); Emit(MRS_TPIDRRO(T)); EmitSlotAddr(T, S, "K18"); Emit(LDRX(S, T));
            long copy0 = Here(); int n = seg.Count;
            long exits = copy0 + 4 * n + 16;
            var exTargets = new List<long>(); var words = new List<uint>();
            for (int k = 0; k < seg.Count; k++)
            {
                var x = seg[k];
                uint w = x.Word;
                if (Has18(x)) w = Subst(x, S);
                string m = x.Mnemonic;
                if (IsCondBranch(m))
                {
                    long tgt = x.Operands[^1].Imm, newt;
                    if (lo <= tgt && tgt < hi) newt = copy0 + (tgt - lo);
                    else { exTargets.Add(tgt); newt = exits + 16 * (exTargets.Count - 1); }
                    w = RebranchInWindow(x, w, copy0 + 4 * k, newt);
                }
                else if (m == "adrp") w = WindowAdrp(x, S, copy0 + 4 * k);
                else CheckCopyable(x);
                words.Add(w);
            }
            foreach (var w in words) Emit(w);
            foreach (long t in new[] { hi }.Concat(exTargets))
            {
                Emit(STRX(S, T)); Emit(LDP(S, T, 31, -16)); Emit(B(Here(), t)); Emit(NOP);
            }
            return (start, lo, hi);
        }

        private static (List<Insn> Retry, List<Insn> Tail)? RetryBlock(List<Insn> insl, int k, List<Insn> wseg)
        {
            long t = insl[k].Operands[^1].Imm;
            var tail = wseg.Where(y => y.Address >= t).ToList();
            if (tail.Count == 0 || !EXCL_ST.Contains(tail[0].Mnemonic)) return null;
            for (int p = k - 1; p > Math.Max(-1, k - 8); p--)
            {
                var q = insl[p];
                if (EXCL_LD.Contains(q.Mnemonic)) return (insl.GetRange(p, k + 1 - p), tail);
                if (q.Mnemonic is "b" or "bl" or "br" or "blr" or "ret" or "cbz" or "cbnz" or "tbz" or "tbnz" || q.Mnemonic.StartsWith("b.") || EXCL_ST.Contains(q.Mnemonic)) return null;
            }
            return null;
        }

        private long SiteRetryWindow(List<(List<Insn> Seg, long Ft)> parts)
        {
            var used = new HashSet<int>();
            foreach (var (seg, _) in parts) foreach (var x in seg) used.UnionWith(RegsIn(x));
            var st = Pick(used); int S = st[0], T = st[1];
            long start = Here();
            Emit(STP(S, T, 31, -16)); Emit(MRS_TPIDRRO(T)); EmitSlotAddr(T, S, "K18"); Emit(LDRX(S, T));
            var pos = new Dictionary<long, long>(); long at = Here();
            foreach (var (seg, _) in parts)
            {
                foreach (var x in seg) { pos[x.Address] = at; at += 4; }
                at += 16;
            }
            long exits = at; var exTargets = new List<long>();
            foreach (var (seg, ft) in parts)
            {
                foreach (var x in seg)
                {
                    uint w = x.Word;
                    if (Has18(x)) w = Subst(x, S);
                    string m = x.Mnemonic; long pc = Here();
                    if (IsCondBranch(m))
                    {
                        long tgt = x.Operands[^1].Imm;
                        if (!pos.ContainsKey(tgt) && !exTargets.Contains(tgt)) exTargets.Add(tgt);
                        long newt = pos.TryGetValue(tgt, out long pp) ? pp : exits + 16 * exTargets.IndexOf(tgt);
                        w = RebranchInWindow(x, w, pc, newt);
                    }
                    else if (m == "adrp") w = WindowAdrp(x, S, pc);
                    else CheckCopyable(x);
                    Emit(w);
                }
                Emit(STRX(S, T)); Emit(LDP(S, T, 31, -16)); Emit(B(Here(), ft)); Emit(NOP);
            }
            foreach (long t in exTargets) { Emit(STRX(S, T)); Emit(LDP(S, T, 31, -16)); Emit(B(Here(), t)); Emit(NOP); }
            return start;
        }
    }
}
