using System;
using System.Collections.Generic;
using static MeloNX.Native.Prep.Rewriter.NsoAsm;

namespace MeloNX.Native.Prep.Rewriter
{
    // What a FRAME_STEP stub gets (patch_nso.py: ctx.here, ctx.emit, ctx.site, ctx.put, ctx.state, ctx.render_scale)
    public interface IFrameStepContext
    {
        long State { get; }
        int RenderScale { get; set; }
        long Here();
        void Emit(long w);
        void Site(long off, string orig);
        void Put(long off, IReadOnlyList<long> words, string why);
    }

    // The FRAME_STEP stubs of dm/games/<id>/patches.py. They are Python functions: tools/native/gen_frame_steps.py translates them into FrameSteps.Generated.cs, each
    // with the SHA-256 of the Python function's source it was made from, which must match the one in patch_tables.json (an upstream change to a stub stops the rewrite
    // until the file is generated again, instead of emitting stale code). The module-level helpers a stub calls are ported by hand below.
    public static partial class FrameSteps
    {
        private sealed record Port(string SourceSha256, Action<IFrameStepContext> Run);

        private static readonly Dictionary<string, Port> Ports = new();

        static FrameSteps() => Register(Ports);

        static partial void Register(Dictionary<string, Port> ports);

        public static bool Has(string buildId) => Ports.ContainsKey(buildId);

        public static void Run(string buildId, string sourceSha256, IFrameStepContext ctx)
        {
            if (!Ports.TryGetValue(buildId, out var port)) throw new NotSupportedException($"FRAME_STEP of build {buildId} is not translated to C#: run tools/native/gen_frame_steps.py");
            if (sourceSha256 != null && port.SourceSha256 != sourceSha256)
                throw new NotSupportedException($"FRAME_STEP of build {buildId} changed upstream (source {sourceSha256}); FrameSteps.Generated.cs is of {port.SourceSha256}: run tools/native/gen_frame_steps.py");
            port.Run(ctx);
        }

        // struct.pack('<I', w).hex()
        private static string Hex32(long w) => Convert.ToHexStringLower(BitConverter.GetBytes((uint)w));

        // int.from_bytes(bytes.fromhex(s), 'little')
        private static long FromHexLE(string s)
        {
            byte[] b = Convert.FromHexString(s);
            long v = 0;
            for (int i = b.Length - 1; i >= 0; i--) v = v << 8 | b[i];
            return v;
        }

        // ---- ASTRAL CHAIN's helpers (dm/games/01007300020FA000/patches.py: signed, width, relocate), by hand; gen_frame_steps.py checks their source is still this one ----
        private static long Signed(long n, long bits) => (n & (1L << (int)(bits - 1))) != 0 ? n - (1L << (int)bits) : n;

        // ADR and short conditional branches expand; the other instructions stay one word
        private static long Width(long w) =>
            (w & 0x9f000000) == 0x10000000 || (w & 0xff000010) == 0x54000000 || (w & 0x7e000000) is 0x34000000 or 0x36000000 ? 2 : 1;

        private static List<long> Relocate(long w, long old, long @new, Dictionary<long, long> targets)
        {
            long Dest(long a) => targets.TryGetValue(a, out long t) ? t : a;
            if ((w & 0x7c000000) == 0x14000000)
                return new List<long> { B(@new, Dest(old + Signed(w & 0x3ffffff, 26) * 4)) | (w & 0x80000000) };
            if ((w & 0x9f000000) is 0x10000000 or 0x90000000)
            {
                long imm = Signed(((w >> 5 & 0x7ffff) << 2) | (w >> 29 & 3), 21);
                if ((w & 0x80000000) != 0) return new List<long> { ADRP((int)(w & 31), @new, (old & ~0xfffL) + (imm << 12)) };
                long a = Dest(old + imm);
                return new List<long> { ADRP((int)(w & 31), @new, a), ADDI((int)(w & 31), (int)(w & 31), a & 0xfff) };
            }
            if ((w & 0xff000010) == 0x54000000 || (w & 0x7e000000) is 0x34000000 or 0x36000000)
            {
                int bits = (w & 0x7e000000) == 0x36000000 ? 14 : 19;
                long mask = ((1L << bits) - 1) << 5;
                long a = Dest(old + Signed(w >> 5 & ((1L << bits) - 1), bits) * 4);
                long invert = (w & 0xff000010) == 0x54000000 ? 1 : 0x01000000;
                return new List<long> { ((w ^ invert) & ~mask) | (2 << 5), B(@new + 4, a) };
            }
            RewriteAssertion.Check((w & 0x3b000000) != 0x18000000, "unexpected literal load in timing helper");
            return new List<long> { w };
        }
    }
}
