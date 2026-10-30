using System;

namespace MeloNX.Native.Prep.Rewriter
{
    // A failed check of the rewriter: Python's AssertionError (the rewrite stops; subst catches the one dis raises)
    public sealed class RewriteAssertion : Exception
    {
        public RewriteAssertion(string message) : base(message) { }

        public static void Check(bool ok, string message = "assertion failed")
        {
            if (!ok) throw new RewriteAssertion(message);
        }
    }

    // Port of dm/tools/nso_asm.py: the AArch64 encoders of the rewriter and of the per-build patch files. Each returns the instruction word; a branch asserts its reach
    public static class NsoAsm
    {
        public const uint NOP = 0xD503201F;

        public static uint B(long frm, long to)
        {
            long off = to - frm;
            RewriteAssertion.Check(-(1L << 27) <= off && off < (1L << 27) && off % 4 == 0, $"B {frm:x} -> {to:x}");
            return 0x14000000u | (uint)((off >> 2) & 0x3FFFFFF);
        }

        public static uint STP(int t, int t2, int n, long off) => 0xA9000000u | (uint)((FloorDiv(off, 8) & 0x7F) << 15) | (uint)(t2 << 10) | (uint)(n << 5) | (uint)t;
        public static uint LDP(int t, int t2, int n, long off) => 0xA9400000u | (uint)((FloorDiv(off, 8) & 0x7F) << 15) | (uint)(t2 << 10) | (uint)(n << 5) | (uint)t;
        public static uint STP_PRE(int t, int t2, int n, long off) => 0xA9800000u | (uint)((FloorDiv(off, 8) & 0x7F) << 15) | (uint)(t2 << 10) | (uint)(n << 5) | (uint)t;
        public static uint LDP_POST(int t, int t2, int n, long off) => 0xA8C00000u | (uint)((FloorDiv(off, 8) & 0x7F) << 15) | (uint)(t2 << 10) | (uint)(n << 5) | (uint)t;
        public static uint STUR(int t, int n, long off) => 0xF8000000u | (uint)((off & 0x1FF) << 12) | (uint)(n << 5) | (uint)t;
        public static uint LDUR(int t, int n, long off) => 0xF8400000u | (uint)((off & 0x1FF) << 12) | (uint)(n << 5) | (uint)t;
        public static uint LDRX(int t, int n, long imm12 = 0) => 0xF9400000u | (uint)(imm12 << 10) | (uint)(n << 5) | (uint)t;
        public static uint STRX(int t, int n, long imm12 = 0) => 0xF9000000u | (uint)(imm12 << 10) | (uint)(n << 5) | (uint)t;
        public static uint MRS_TPIDRRO(int t) => 0xD53BD060u | (uint)t;

        public static uint ADRP(int dd, long pc, long target)
        {
            long imm = ((target & ~0xFFFL) - (pc & ~0xFFFL)) >> 12;
            RewriteAssertion.Check(-(1L << 20) <= imm && imm < (1L << 20), $"ADRP {pc:x} -> {target:x}");
            return 0x90000000u | (uint)((imm & 3) << 29) | (uint)(((imm >> 2) & 0x7FFFF) << 5) | (uint)dd;
        }

        public static uint ADDI(int dd, int n, long imm12, int sh = 0) => (uint)(0x91000000L | ((long)sh << 22) | (imm12 << 10) | ((long)n << 5) | (long)dd);
        public static uint ADDR(int dd, int n, int m) => 0x8B000000u | (uint)(m << 16) | (uint)(n << 5) | (uint)dd;
        public static uint SUBI(int dd, int n, long imm12, int sh = 0) => (uint)(0xD1000000L | ((long)sh << 22) | (imm12 << 10) | ((long)n << 5) | (long)dd);
        public static uint BR(int n) => 0xD61F0000u | (uint)(n << 5);
        public static uint CMPR(int n, int m) => 0xEB00001Fu | (uint)(m << 16) | (uint)(n << 5);

        public static uint BEQ(long frm, long to)
        {
            long off = to - frm;
            RewriteAssertion.Check(-(1L << 20) <= off && off < (1L << 20) && off % 4 == 0, $"BEQ {frm:x} -> {to:x}");
            return 0x54000000u | (uint)(((off >> 2) & 0x7FFFF) << 5);
        }

        public static uint BRK(int imm) => 0xD4200000u | (uint)((imm & 0xFFFF) << 5);
        public static uint BLR(int n) => 0xD63F0000u | (uint)(n << 5);

        // Python's // (floor division), which the pair encoders use on negative offsets
        public static long FloorDiv(long a, long b) => a / b - (a % b != 0 && (a < 0) != (b < 0) ? 1 : 0);
    }
}
