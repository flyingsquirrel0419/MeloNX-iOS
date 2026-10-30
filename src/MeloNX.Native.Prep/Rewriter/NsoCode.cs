using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace MeloNX.Native.Prep.Rewriter
{
    // Port of dm/tools/nso_code.py (function ranges from .eh_frame, data blocks in the text), nso_syms.defined and loader_census.got_values
    public static class NsoCode
    {
        public const int DataMin = 0x1000;

        internal static uint U32(byte[] img, long o) => BinaryPrimitives.ReadUInt32LittleEndian(img.AsSpan((int)o));
        internal static int I32(byte[] img, long o) => BinaryPrimitives.ReadInt32LittleEndian(img.AsSpan((int)o));
        internal static ulong U64(byte[] img, long o) => BinaryPrimitives.ReadUInt64LittleEndian(img.AsSpan((int)o));
        internal static long I64(byte[] img, long o) => BinaryPrimitives.ReadInt64LittleEndian(img.AsSpan((int)o));
        internal static ushort U16(byte[] img, long o) => BinaryPrimitives.ReadUInt16LittleEndian(img.AsSpan((int)o));

        internal static bool IsMod0(byte[] img, long m0) => m0 + 4 <= img.Length && img[m0] == 'M' && img[m0 + 1] == 'O' && img[m0 + 2] == 'D' && img[m0 + 3] == '0';

        public static (long Start, long End) EhFrameHdr(byte[] img)
        {
            long m0 = U32(img, 4);
            RewriteAssertion.Check(IsMod0(img, m0), "no MOD0");
            return (m0 + I32(img, m0 + 16), m0 + I32(img, m0 + 20));
        }

        private static (long V, int Size) ReadPtr(byte[] img, long o, int enc, long ehs)
        {
            int fmt = enc & 0xF, app = enc & 0x70;
            long v; int sz;
            if (fmt == 0x3) { v = U32(img, o); sz = 4; }
            else if (fmt == 0xB) { v = I32(img, o); sz = 4; }
            else if (fmt == 0x0 || fmt == 0x4) { v = (long)U64(img, o); sz = 8; }
            else if (fmt == 0xC) { v = I64(img, o); sz = 8; }
            else throw new ArgumentException($"pointer encoding {enc:x} at {o:x}");
            if (app == 0x10) v += o;
            else if (app == 0x30) v += ehs;
            return (v, sz);
        }

        private static (long V, long O) Uleb(byte[] img, long o)
        {
            long r = 0; int sh = 0;
            while (true)
            {
                byte b = img[o++]; r |= (long)(b & 0x7F) << sh; sh += 7;
                if ((b & 0x80) == 0) return (r, o);
            }
        }

        public static List<(long Start, long Fde)> FdeTable(byte[] img)
        {
            var (ehs, ehe) = EhFrameHdr(img);
            var out_ = new List<(long, long)>();
            if (ehe - ehs < 12 || img[ehs] != 1 || img[ehs + 3] == 0xFF || img[ehs + 3] == 0) return out_;
            int penc = img[ehs + 1], cenc = img[ehs + 2], tenc = img[ehs + 3];
            long o = ehs + 4;
            o += ReadPtr(img, o, penc, ehs).Size;
            var (n, s) = ReadPtr(img, o, cenc, ehs); o += s;
            for (long i = 0; i < n; i++)
            {
                var (a, s1) = ReadPtr(img, o, tenc, ehs); o += s1;
                var (f, s2) = ReadPtr(img, o, tenc, ehs); o += s2;
                out_.Add((a, f));
            }
            return out_;
        }

        public static List<(long Start, long End)> FdeRanges(byte[] img)
        {
            var (ehs, _) = EhFrameHdr(img);
            var cies = new Dictionary<long, int>();
            int CieEncoding(long cie)
            {
                if (cies.TryGetValue(cie, out int e)) return e;
                long p = cie + 8; int ver = img[p]; p += 1;
                int z = Array.IndexOf(img, (byte)0, (int)p);
                if (z < 0) throw new ArgumentException("unterminated augmentation");
                byte[] aug = img[(int)p..z]; p += aug.Length + 1;
                p = Uleb(img, p).O;
                while ((img[p] & 0x80) != 0) p++;
                p++;
                p = ver == 1 ? p + 1 : Uleb(img, p).O;
                int enc = 0;
                if (aug.Length > 0 && aug[0] == 'z')
                {
                    p = Uleb(img, p).O;
                    foreach (byte ch in aug.Skip(1))
                    {
                        if (ch == 'R') { enc = img[p]; p += 1; }
                        else if (ch == 'P') { int pe = img[p]; p += 1; p += ReadPtr(img, p, pe, ehs).Size; }
                        else if (ch == 'L') p += 1;
                    }
                }
                cies[cie] = enc;
                return enc;
            }
            var out_ = new List<(long, long)>();
            foreach (var (_, f) in FdeTable(img))
            {
                long cptr = f + 4;
                int enc = CieEncoding(cptr - U32(img, cptr));
                var (st, s) = ReadPtr(img, f + 8, enc, ehs);
                var (ln, _) = ReadPtr(img, f + 8 + s, enc & 0xF, ehs);
                out_.Add((st, st + ln));
            }
            out_.Sort();
            return out_;
        }

        public static List<(long Start, long End)> DataBlocks(byte[] img, long textEnd, Cs md)
        {
            bool nro = img.Length >= 0x14 && img[0x10] == 'N' && img[0x11] == 'R' && img[0x12] == 'O' && img[0x13] == '0';
            var gaps = new List<(long, long)>();
            long last = nro ? 0x80 : 0;
            foreach (var (s, e) in FdeRanges(img))
            {
                if (s >= textEnd) break;
                if (s > last) gaps.Add((last, s));
                last = Math.Max(last, e);
            }
            if (last < textEnd) gaps.Add((last, textEnd));
            var out_ = new List<(long, long)>();
            if (nro) out_.Add((8, 0x80));
            foreach (var (s0, e0) in gaps)
            {
                long s = (s0 + 3) & ~3L, e = e0 & ~3L;
                if (e - s < DataMin) continue;
                long undecodable = 0;
                for (long a = s; a < e; a += 4)
                    if (md.Disasm(img.AsSpan((int)a, 4), a, 1).Count == 0) undecodable++;
                if (undecodable * 4 > (e - s) / 4) out_.Add((s, e));
            }
            return out_;
        }

        public static (long Offset, int Reg) OutStore(byte[] img, long start, long size, Cs md)
        {
            var ins = md.Disasm(img.AsSpan((int)start, (int)Math.Min(size, img.Length - start)), start);
            var outs = ins.Take(16).Where(i => i.Mnemonic == "mov" && Regex.IsMatch(i.OpStr, @"\Ax\d+, x1\z")).ToList();
            if (outs.Count != 1) throw new ArgumentException("no single copy of the out pointer in the prologue");
            string xb = outs[0].OpStr.Split(',')[0];
            var st = ins.Where(i => i.Mnemonic == "str" && Regex.IsMatch(i.OpStr, $@"\Ax\d+, \[{Regex.Escape(xb)}\]\z")).ToList();
            if (st.Count != 1) throw new ArgumentException($"{st.Count} stores through the out pointer");
            return (st[0].Address, int.Parse(st[0].OpStr.Split(',')[0][1..]));
        }

        // nso_syms.defined: {name: (offset, size)} of the module's defined dynamic symbols; empty without a symbol table it can read
        public static Dictionary<string, (long Value, long Size)> Defined(byte[] img)
        {
            try
            {
                long mod0 = U32(img, 4);
                if (!IsMod0(img, mod0)) return new();
                long dyn = mod0 + I32(img, mod0 + 4);
                var tags = new Dictionary<long, long>();
                for (int i = 0; i < 4096; i++)
                {
                    long t = I64(img, dyn + i * 16), v = (long)U64(img, dyn + i * 16 + 8);
                    if (t == 0) break;
                    tags.TryAdd(t, v);
                }
                long symtab = tags[6], strtab = tags[5];
                long n = tags.ContainsKey(4) ? U32(img, tags[4] + 4) : (strtab - symtab) / 24;
                var out_ = new Dictionary<string, (long, long)>();
                for (long i = 1; i < n; i++)
                {
                    long e = symtab + i * 24;
                    uint name = U32(img, e); ushort shndx = U16(img, e + 6); long value = (long)U64(img, e + 8), size = (long)U64(img, e + 16);
                    if (shndx != 0)
                    {
                        long z = Array.IndexOf(img, (byte)0, (int)(strtab + name));
                        if (z < 0) throw new ArgumentException();
                        out_[System.Text.Encoding.Latin1.GetString(img, (int)(strtab + name), (int)(z - strtab - name))] = (value, size);
                    }
                }
                return out_;
            }
            catch (Exception e) when (e is KeyNotFoundException or ArgumentException or IndexOutOfRangeException) { return new(); }
        }

        // loader_census.got_values: {address: the address it holds once relocated} for the image's relative relocations
        public static Dictionary<long, long> GotValues(byte[] img)
        {
            var out_ = new Dictionary<long, long>();
            long mod0 = U32(img, 4);
            if (!IsMod0(img, mod0)) return out_;
            long dyn = mod0 + I32(img, mod0 + 4);
            var tags = new Dictionary<long, long>();
            for (int k = 0; k < 4096; k++)
            {
                long t = I64(img, dyn + k * 16), v = (long)U64(img, dyn + k * 16 + 8);
                if (t == 0) break;
                tags.TryAdd(t, v);
            }
            long relasz = tags.GetValueOrDefault(8, 0);
            for (long k = 0; k < relasz / 24; k++)
            {
                long e = tags[7] + k * 24;
                long off = (long)U64(img, e); ulong info = U64(img, e + 8); long add = I64(img, e + 16);
                uint type = (uint)(info & 0xffffffff);
                if (type == 1027) out_[off] = add;
                else if ((type == 257 || type == 1025) && tags.ContainsKey(6))
                {
                    long sym = tags[6] + (long)(info >> 32) * 24;
                    ushort shndx = U16(img, sym + 6); long value = (long)U64(img, sym + 8);
                    if (shndx != 0) out_[off] = value + add;
                }
            }
            long where = 0;
            long relrsz = tags.GetValueOrDefault(35, 0);
            for (long k = 0; k < relrsz / 8; k++)
            {
                ulong e = U64(img, tags[36] + k * 8);
                if ((e & 1) == 0) { where = (long)e; out_[where] = (long)U64(img, where); where += 8; }
                else
                {
                    for (int b = 0; b < 63; b++)
                        if (((e >> (b + 1)) & 1) != 0) { long a = where + b * 8; out_[a] = (long)U64(img, a); }
                    where += 63 * 8;
                }
            }
            return out_;
        }
    }
}
