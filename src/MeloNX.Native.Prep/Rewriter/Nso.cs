using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace MeloNX.Native.Prep.Rewriter
{
    // Port of dm/tools/nso.py: an NSO (ExeFS) or an NRO → its memory image of text + ro + data, checked as Horizon checks it
    public sealed class NsoError : Exception
    {
        public NsoError(string message) : base(message) { }
    }

    public sealed class NsoModule
    {
        public byte[] Image;                 // text + ro + data at their memory offsets
        public (long Offset, long Size)[] Segments;
        public long Bss;
        public byte[] BuildId;               // 0x20 bytes
        public long TextEnd => Segments[0].Size;
    }

    public static class Nso
    {
        private const int Page = 0x1000, Lz4MaxRatio = 255;
        private const long SizeMax = 0x7FFFFFFF;
        private const uint NsoZstd = 1 << 7, NroCompressed = 1 << 1;
        private static readonly string[] Names = { "text", "ro", "data" };

        private static uint U32(byte[] d, int o) => BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(o));

        public static NsoModule Load(byte[] d, string name = "module")
        {
            uint flags;
            var stored = new (long Fo, long Mo, long Sz)[3];
            var csz = new long[3];
            long bss;
            byte[] buildId;
            if (d.Length >= 4 && d[0] == 'N' && d[1] == 'S' && d[2] == 'O' && d[3] == '0')
            {
                if (d.Length < 0x100) throw new NsoError($"{name}: the NSO header is cut short ({d.Length} bytes)");
                flags = U32(d, 0xc);
                for (int i = 0; i < 3; i++)
                {
                    stored[i] = (U32(d, 0x10 + i * 0x10), U32(d, 0x14 + i * 0x10), U32(d, 0x18 + i * 0x10));
                    csz[i] = ((flags >> i) & 1) != 0 ? U32(d, 0x60 + i * 4) : stored[i].Sz;
                }
                bss = U32(d, 0x3c); buildId = d[0x40..0x60];
                for (int i = 0; i < 3; i++)
                {
                    var (fo, mo, sz) = stored[i]; long c = csz[i];
                    string what = $"{name}: {Names[i]} segment";
                    if (mo % Page != 0) throw new NsoError($"{what} is at {mo:x}, not on a page");
                    if (sz > SizeMax) throw new NsoError($"{what} claims {sz:x} bytes, more than Horizon loads");
                    if (fo + c > d.Length) throw new NsoError($"{what} is stored past the end of the file: the file is cut short or damaged");
                    if (((flags >> i) & 1) != 0 && c > sz) throw new NsoError($"{what} is stored compressed in {c:x} bytes, more than its {sz:x}");
                    if (((flags >> i) & 1) != 0 && (flags & NsoZstd) == 0 && sz > c * Lz4MaxRatio) throw new NsoError($"{what} claims {sz:x} bytes from {c:x} stored, more than LZ4 can produce");
                }
                if (stored[0].Mo != 0) throw new NsoError($"{name}: text segment is at {stored[0].Mo:x}, not at 0");
                for (int i = 1; i < 3; i++)
                    if (stored[i].Mo < stored[i - 1].Mo + stored[i - 1].Sz) throw new NsoError($"{name}: {Names[i]} segment overlaps the {Names[i - 1]} segment before it");
            }
            else if (d.Length >= 0x14 && d[0x10] == 'N' && d[0x11] == 'R' && d[0x12] == 'O' && d[0x13] == '0')
            {
                if (d.Length < 0x80) throw new NsoError($"{name}: the NRO header is cut short ({d.Length} bytes)");
                uint size = U32(d, 0x18), nflags = U32(d, 0x1c);
                if ((nflags & NroCompressed) != 0) throw new NsoError($"{name}: a compressed NRO (system 23.0.0+), which this loader does not decode yet");
                flags = 0;
                for (int i = 0; i < 3; i++) { long o = U32(d, 0x20 + 8 * i), sz = U32(d, 0x24 + 8 * i); stored[i] = (o, o, sz); csz[i] = sz; }
                bss = U32(d, 0x38); buildId = d[0x40..0x60];
                long at = 0;
                for (int i = 0; i < 3; i++)
                {
                    var (o, _, sz) = stored[i];
                    if (sz % Page != 0 || o != at) throw new NsoError($"{name}: {Names[i]} segment is not whole pages right after the one before it");
                    at += sz;
                }
                if (at != size) throw new NsoError($"{name}: the segments end at {at:x}, not at the module's size {size:x}");
                if (size > d.Length) throw new NsoError($"{name}: the module is {size:x} bytes, the file {d.Length:x}: the file is cut short or damaged");
            }
            else throw new NsoError($"{name}: not an NSO or NRO");

            long end = stored[2].Mo + stored[2].Sz;
            if (end > (long)d.Length * Lz4MaxRatio) throw new NsoError($"{name}: the segments span {end:x} bytes, more than a file of {d.Length:x} bytes can fill");
            var img = new byte[end];
            for (int i = 0; i < 3; i++)
            {
                var (fo, mo, sz) = stored[i];
                byte[] raw = d.AsSpan((int)fo, (int)csz[i]).ToArray();
                if (((flags >> i) & 1) != 0)
                {
                    if ((flags & NsoZstd) != 0)
                        throw new NsoError($"{name}: {Names[i]} segment: ZBIC (zstd) segments are not supported yet");   // TODO: Nintendo's zstd variant (system 22.0.0+ modules), the zbic package's decoder
                    raw = Lz4.DecompressBlock(raw, (int)sz) ?? throw new NsoError($"{name}: {Names[i]} segment does not decompress");
                }
                if (raw.Length != sz) throw new NsoError($"{name}: {Names[i]} segment decompresses to {raw.Length:x} bytes, not the {sz:x} of the header: the file is damaged");
                if (((flags >> (3 + i)) & 1) != 0 && !SHA256.HashData(raw).AsSpan().SequenceEqual(d.AsSpan(0xa0 + 0x20 * i, 0x20)))
                    throw new NsoError($"{name}: {Names[i]} segment does not match its SHA-256 in the header: the file is damaged");
                raw.CopyTo(img, mo);
            }
            return new NsoModule { Image = img, Segments = stored.Select(s => (s.Mo, s.Sz)).ToArray(), Bss = bss, BuildId = buildId };
        }

        public static NsoModule Read(string path) => Load(File.ReadAllBytes(path), path);
    }

    // An LZ4 block (no frame), decompressed to exactly size bytes, as lz4.block.decompress(raw, uncompressed_size=size); null on a damaged stream
    public static class Lz4
    {
        public static byte[] DecompressBlock(ReadOnlySpan<byte> src, int size)
        {
            var dst = new byte[size];
            int s = 0, o = 0;
            while (s < src.Length)
            {
                int token = src[s++];
                int lit = token >> 4;
                if (lit == 15)
                {
                    int b;
                    do { if (s >= src.Length) return null; b = src[s++]; lit += b; } while (b == 255);
                }
                if (s + lit > src.Length || o + lit > size) return null;
                src.Slice(s, lit).CopyTo(dst.AsSpan(o));
                s += lit; o += lit;
                if (s >= src.Length) break;   // the last sequence has literals only
                if (s + 2 > src.Length) return null;
                int off = src[s] | src[s + 1] << 8; s += 2;
                if (off == 0 || off > o) return null;
                int ml = token & 15;
                if (ml == 15)
                {
                    int b;
                    do { if (s >= src.Length) return null; b = src[s++]; ml += b; } while (b == 255);
                }
                ml += 4;
                if (o + ml > size) return null;
                for (int k = 0; k < ml; k++) dst[o + k] = dst[o - off + k];
                o += ml;
            }
            return o == size ? dst : dst.AsSpan(0, o).ToArray();
        }
    }
}
