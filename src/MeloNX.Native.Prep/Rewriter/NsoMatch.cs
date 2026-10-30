using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MeloNX.Native.Prep.Rewriter
{
    // Port of dm/tools/nso_match.py: conservative function matching for opt-in patches across game updates (MATCH_CUTS)
    public sealed class MatchError : Exception
    {
        public MatchError(string message) : base(message) { }
    }

    public sealed record Cut(long Offset, string Old, string New, string Reason);

    // A rule: {name, size, fingerprints, cuts} (cut offsets function-relative), or {name, functions: [{size, fingerprints, cuts}, ...]}
    public sealed class MatchRule
    {
        public string Name;
        public long Size;
        public List<string> Fingerprints;
        public List<Cut> Cuts;
        public List<MatchRule> Functions;
    }

    public sealed class MatchImage
    {
        private readonly byte[] _image;
        private readonly long _textEnd;
        private readonly Cs _md;
        private readonly Dictionary<long, (string Digest, List<(long Off, long Target)> Branches)> _bodies = new();
        private readonly Dictionary<long, string> _fingerprints = new();
        private Dictionary<long, string> _imports;
        public readonly Dictionary<long, long> Functions = new();   // insertion order as in Python's dict

        private static long Signed(long n, int bits) => (n & (1L << (bits - 1))) != 0 ? n - (1L << bits) : n;

        private static (uint Mask, long Delta)? Relative(uint w)
        {
            if ((w & 0x7c000000) == 0x14000000) return (0x03ffffff, Signed(w & 0x3ffffff, 26) * 4);
            if ((w & 0xff000010) == 0x54000000 || (w & 0x7e000000) == 0x34000000) return (0x00ffffe0, Signed((w >> 5) & 0x7ffff, 19) * 4);
            if ((w & 0x7e000000) == 0x36000000) return (0x0007ffe0, Signed((w >> 5) & 0x3fff, 14) * 4);
            return null;
        }

        private static bool PcRelative(uint w) => Relative(w) != null || (w & 0x1f000000) == 0x10000000 || (w & 0x3b000000) == 0x18000000;

        public MatchImage(byte[] image, long textEnd, Cs md)
        {
            _image = image; _textEnd = textEnd; _md = md;
            List<(long Start, long End)> ranges;
            try { ranges = NsoCode.FdeRanges(image); }
            catch (Exception e) when (e is RewriteAssertion or ArgumentException or IndexOutOfRangeException) { throw new MatchError($"cannot read function boundaries: {e.Message}"); }
            foreach (var (start, end) in ranges)
            {
                if (!(0 <= start && start < end && end <= Math.Min(textEnd, image.Length)) || start % 4 != 0 || end % 4 != 0) continue;
                if (Functions.TryGetValue(start, out long e0) && e0 != end) throw new MatchError($"conflicting function boundaries at {start:x}");
                Functions[start] = end;
            }
        }

        private (string Digest, List<(long Off, long Target)> Branches) Body(long start)
        {
            if (_bodies.TryGetValue(start, out var cached)) return cached;
            long end = Functions[start];
            var code = _image.AsSpan((int)start, (int)(end - start));
            var ins = _md.Disasm(code, start);
            if (ins.Count * 4 != code.Length) throw new MatchError($"undecodable function at {start:x}");
            var words = new uint[ins.Count];
            for (int i = 0; i < words.Length; i++) words[i] = NsoCode.U32(_image, start + 4 * i);
            var normalized = (uint[])words.Clone();
            var branches = new List<(long, long)>();
            for (int i = 0; i < words.Length; i++)
            {
                uint w = words[i]; var op = ins[i];
                var branch = Relative(w);
                if (branch != null)
                {
                    var (mask, delta) = branch.Value; long target = op.Address + delta;
                    if (!(start <= target && target < end)) { normalized[i] &= ~mask; branches.Add((i * 4, target)); }
                }
                else if ((w & 0x1f000000) == 0x10000000)
                {
                    long delta = Signed(((w >> 29) & 3) | ((w >> 5) & 0x7ffff) << 2, 21);
                    if ((w & 0x80000000) != 0 || !(start <= op.Address + delta && op.Address + delta < end)) normalized[i] &= 0x9f00001f;
                }
                else if ((w & 0x3b000000) == 0x18000000)
                {
                    long target = op.Address + Signed((w >> 5) & 0x7ffff, 19) * 4;
                    if (!(start <= target && target < end)) normalized[i] &= 0xff00001f;
                }
                if ((w & 0x9f000000) != 0x90000000) continue;
                int rd = (int)(w & 31);
                for (int j = i + 1; j < Math.Min(i + 9, words.Length); j++)
                {
                    uint u = words[j];
                    if (((u & 0xffc00000) == 0x91000000 || (u & 0x3b000000) == 0x39000000) && ((u >> 5) & 31) == rd)
                    {
                        normalized[j] &= ~0x3ffc00u;
                        break;
                    }
                    if (Relative(u) != null || ins[j].Mnemonic is "br" or "blr" or "ret") break;
                    var (_, writes) = ins[j].RegsAccess();
                    string alias = rd == 29 ? "fp" : rd == 30 ? "lr" : "";
                    if (writes.Any(r => { string n = ins[j].RegName(r); return n == $"x{rd}" || n == $"w{rd}" || n == alias; })) break;
                }
            }
            var bytes = new byte[normalized.Length * 4];
            for (int i = 0; i < normalized.Length; i++) BitConverter.TryWriteBytes(bytes.AsSpan(4 * i), normalized[i]);
            string digest = Convert.ToHexStringLower(SHA256.HashData(bytes));
            var r = (digest, branches);
            _bodies[start] = r;
            return r;
        }

        private Dictionary<long, string> ImportSlots()
        {
            if (_imports != null) return _imports;
            _imports = new();
            var img = _image;
            try
            {
                long mod = NsoCode.U32(img, 4);
                long dyn = mod + NsoCode.I32(img, mod + 4);
                var tags = new Dictionary<long, long>();
                for (long pos = dyn; pos < Math.Min(img.Length - 15, dyn + 4096 * 16); pos += 16)
                {
                    long tag = NsoCode.I64(img, pos), value = (long)NsoCode.U64(img, pos + 8);
                    if (tag == 0) break;
                    tags[tag] = value;
                }
                if (tags.GetValueOrDefault(20, -1) != 7) return _imports;
                for (long pos = tags[23]; pos < tags[23] + tags[2]; pos += 24)
                {
                    long slot = (long)NsoCode.U64(img, pos); ulong info = NsoCode.U64(img, pos + 8);
                    if ((info & 0xffffffff) != 1026) continue;
                    long name = NsoCode.U32(img, tags[6] + (long)(info >> 32) * 24) + tags[5];
                    int z = Array.IndexOf(img, (byte)0, (int)name);
                    if (z < 0) throw new ArgumentException();
                    _imports[slot] = new UTF8Encoding(false, true).GetString(img, (int)name, (int)(z - name));
                }
            }
            catch (Exception e) when (e is KeyNotFoundException or ArgumentException or IndexOutOfRangeException or DecoderFallbackException) { _imports = new(); }
            return _imports;
        }

        // ('import', name) | ('svc', n) | ('function', size, digest), as JSON
        private string Callee(long target)
        {
            if (0 <= target && target <= Math.Min(_textEnd, _image.Length) - 16)
            {
                uint a = NsoCode.U32(_image, target), b = NsoCode.U32(_image, target + 4), c = NsoCode.U32(_image, target + 8), d = NsoCode.U32(_image, target + 12);
                if ((a & 0x9f00001f) == 0x90000010 && (b & 0xffc003ff) == 0xf9400211 && (c & 0xffc003ff) == 0x91000210 && d == 0xd61f0220)
                {
                    long page = (target & ~0xfffL) + (Signed(((a >> 29) & 3) | ((a >> 5) & 0x7ffff) << 2, 21) << 12);
                    long lo = ((b >> 10) & 0xfff) * 8;
                    if (((c >> 10) & 0xfff) == lo && ImportSlots().TryGetValue(page + lo, out string name) && !string.IsNullOrEmpty(name))
                        return $"[\"import\",{PyJson.Str(name)}]";
                }
                if ((a & 0xffe0001f) == 0xd4000001 && b == 0xd65f03c0 && !Functions.ContainsKey(target)) return $"[\"svc\",{(a >> 5) & 0xffff}]";
            }
            if (!Functions.ContainsKey(target)) throw new MatchError($"callee has no verified boundary or import at {target:x}");
            return $"[\"function\",{Functions[target] - target},\"{Body(target).Digest}\"]";
        }

        public string Fingerprint(long start)
        {
            if (_fingerprints.TryGetValue(start, out string f)) return f;
            var (body, branches) = Body(start);
            var sb = new StringBuilder();
            sb.Append("[\"").Append(body).Append("\",[");
            for (int i = 0; i < branches.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append('[').Append(branches[i].Off).Append(',').Append(Callee(branches[i].Target)).Append(']');
            }
            sb.Append("]]");
            f = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
            _fingerprints[start] = f;
            return f;
        }

        public List<Cut> Match(MatchRule rule)
        {
            Validate(rule);
            var matches = new List<long>();
            foreach (var (start, end) in Functions)
            {
                if (end - start != rule.Size) continue;
                string digest;
                try { digest = Fingerprint(start); }
                catch (MatchError) { continue; }
                if (rule.Fingerprints.Contains(digest)) matches.Add(start);
            }
            if (matches.Count != 1) throw new MatchError($"{matches.Count} matching functions (need exactly one)");
            long s = matches[0];
            var cuts = new List<Cut>();
            foreach (var c in rule.Cuts)
            {
                long off = s + c.Offset;
                byte[] old = Convert.FromHexString(c.Old);
                if (off < 0 || off + old.Length > _image.Length || !_image.AsSpan((int)off, old.Length).SequenceEqual(old)) throw new MatchError($"original bytes differ at {off:x}");
                cuts.Add(new Cut(off, c.Old, c.New, c.Reason + " [function match]"));
            }
            return cuts;
        }

        public List<Cut> MatchPatch(MatchRule rule)
        {
            Validate(rule);
            if (rule.Functions == null) return Match(rule);
            var cuts = new List<Cut>(); var starts = new HashSet<long>(); var misses = new List<string>(); int n = rule.Functions.Count;
            for (int i = 1; i <= n; i++)
            {
                var fn = rule.Functions[i - 1];
                List<Cut> got;
                try { got = Match(new MatchRule { Name = rule.Name, Size = fn.Size, Fingerprints = fn.Fingerprints, Cuts = fn.Cuts }); }
                catch (MatchError e) { misses.Add($"function {i} of {n} ({fn.Size} bytes): {e.Message}"); continue; }
                long start = got[0].Offset - fn.Cuts[0].Offset;
                if (starts.Contains(start)) misses.Add($"function {i} of {n} matched a function another one did");
                starts.Add(start); cuts.AddRange(got);
            }
            if (misses.Count > 0) throw new MatchError(string.Join("; ", misses) + (misses.Count < n ? $"; the other {n - misses.Count} matched" : ""));
            return cuts;
        }

        public static void Validate(MatchRule rule)
        {
            if (rule.Functions != null)
            {
                if (rule.Fingerprints != null || rule.Cuts != null) throw new ArgumentException("a patch of several functions needs only name and functions");
                if (rule.Functions.Count < 2) throw new ArgumentException("a patch of several functions needs at least two");
                foreach (var fn in rule.Functions)
                {
                    if (fn.Name != null || fn.Functions != null) throw new ArgumentException("a function of a patch has size, fingerprints and cuts only");
                    Validate(new MatchRule { Name = rule.Name, Size = fn.Size, Fingerprints = fn.Fingerprints, Cuts = fn.Cuts });
                }
                return;
            }
            if (rule.Fingerprints == null || rule.Cuts == null) throw new ArgumentException("function patch needs name, size, fingerprints and cuts");
            if (string.IsNullOrEmpty(rule.Name) || rule.Size <= 0 || rule.Size % 4 != 0) throw new ArgumentException("invalid function size/name");
            if (rule.Fingerprints.Count == 0) throw new ArgumentException("missing function fingerprints");
            foreach (var digest in rule.Fingerprints)
                if (digest.Length != 64 || digest.Any(c => !"0123456789abcdef".Contains(c))) throw new ArgumentException("invalid function fingerprint");
            if (rule.Cuts.Count == 0) throw new ArgumentException("function patch has no cuts");
            var used = new HashSet<long>();
            foreach (var c in rule.Cuts)
            {
                byte[] ob = Convert.FromHexString(c.Old), nb = Convert.FromHexString(c.New);
                if (string.IsNullOrEmpty(c.Reason) || ob.Length != nb.Length || ob.Length == 0 || ob.Length % 4 != 0 || c.Offset % 4 != 0 || !(0 <= c.Offset && c.Offset <= rule.Size - ob.Length))
                    throw new ArgumentException("invalid function-relative cut");
                for (long k = c.Offset; k < c.Offset + ob.Length; k++)
                    if (!used.Add(k)) throw new ArgumentException("overlapping cuts");
                for (int k = 0; k < nb.Length; k += 4)
                    if (PcRelative(BitConverter.ToUInt32(nb, k))) throw new ArgumentException("replacement must not contain PC-relative instructions");
            }
        }

        // resolve(): verified cuts without mutating the image; outcomes gets (patch name, cut offsets or null, why) for each patch
        public static List<Cut> Resolve(byte[] image, long textEnd, Cs md, List<MatchRule> rules, Action<string> report, List<(string Name, List<long> Offsets, string Why)> outcomes = null, bool red = true)
        {
            if (rules == null || rules.Count == 0) return new();
            var groups = new List<(string Name, List<MatchRule> Rules)>();
            foreach (var rule in rules)
            {
                int k = groups.FindIndex(g => g.Name == rule.Name);
                if (k < 0) groups.Add((rule.Name, new List<MatchRule> { rule }));
                else groups[k].Rules.Add(rule);
            }
            void Missed(string name, string why)
            {
                report($"{(red ? "[RED] " : "")}function patch {PyJson.Repr(name)} skipped: {why}");
                outcomes?.Add((name, null, why));
            }
            MatchImage module;
            try { module = new MatchImage(image, textEnd, md); }
            catch (MatchError e)
            {
                foreach (var g in groups) Missed(g.Name, e.Message);
                return new();
            }
            var cuts = new List<Cut>();
            foreach (var (name, alternatives) in groups)
            {
                var found = new List<(int I, List<Cut> Got)>(); var misses = new List<string>();
                for (int i = 1; i <= alternatives.Count; i++)
                {
                    try { found.Add((i, module.MatchPatch(alternatives[i - 1]))); }
                    catch (MatchError e) { misses.Add(e.Message); }
                }
                if (found.Count != 1)
                {
                    Missed(name, found.Count > 0 ? $"{found.Count} implementations match (need exactly one)" : string.Join("; ", misses));
                    continue;
                }
                var (idx, got) = found[0];
                cuts.AddRange(got);
                report($"function patch {PyJson.Repr(name)}: matched at {string.Join(", ", got.Select(c => $"0x{c.Offset:x}"))}" + (alternatives.Count > 1 ? $" (implementation {idx} of {alternatives.Count})" : ""));
                outcomes?.Add((name, got.Select(c => c.Offset).ToList(), $"implementation {idx} of {alternatives.Count}"));
            }
            var occupied = new HashSet<long>();
            foreach (var c in cuts)
                for (long k = c.Offset; k < c.Offset + c.Old.Length / 2; k++)
                    if (!occupied.Add(k)) throw new MatchError("function patches overlap");
            return cuts;
        }
    }

    // The bits of Python's json.dumps / repr the rewriter's outputs depend on
    public static class PyJson
    {
        public static string Str(string s)
        {
            var sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20 || c > 0x7f) sb.Append($"\\u{(int)c:x4}");
                        else sb.Append(c);
                        break;
                }
            }
            return sb.Append('"').ToString();
        }

        public static string Repr(string s) => s.Contains('\'') && !s.Contains('"') ? $"\"{s}\"" : $"'{s.Replace("\\", "\\\\").Replace("'", "\\'")}'";
    }
}
