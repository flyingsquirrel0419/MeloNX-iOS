using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace MeloNX.Native.Prep.Rewriter
{
    // Capstone 5's AArch64 decoder through Native/cs_shim.c, shaped like the Python binding patch_nso.py uses: Cs.Disasm / DisasmLite, Insn.Mnemonic / OpStr / Operands / RegsAccess / RegName
    public static unsafe partial class CsNative
    {
        public const string Lib = "cs_shim";

        [StructLayout(LayoutKind.Sequential)]
        public struct ShimOp
        {
            public int Type, Reg;
            public long Imm;
            public int MemBase, MemIndex, MemDisp, Pad;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ShimInsn
        {
            public ulong Address;
            public uint Word;
            public uint Id;
            public fixed byte Mnemonic[32];
            public fixed byte OpStr[160];
            public byte OpCount, Writeback, RegsStatus, RegsReadCount, RegsWriteCount, Pad0, Pad1, Pad2;
            public fixed ushort RegsRead[64];
            public fixed ushort RegsWrite[64];
            public ShimOp Op0, Op1, Op2, Op3, Op4, Op5, Op6, Op7;
        }

        [LibraryImport(Lib, EntryPoint = "cs_shim_open")] public static partial IntPtr Open(int detail);
        [LibraryImport(Lib, EntryPoint = "cs_shim_close")] public static partial void Close(IntPtr h);
        [LibraryImport(Lib, EntryPoint = "cs_shim_version")] public static partial int Version();
        [LibraryImport(Lib, EntryPoint = "cs_shim_reg_name")] public static partial IntPtr RegName(IntPtr h, int reg);
        [LibraryImport(Lib, EntryPoint = "cs_shim_disasm")] public static partial nuint Disasm(IntPtr h, byte* code, nuint size, ulong address, nuint count, out ShimInsn* insn);
        [LibraryImport(Lib, EntryPoint = "cs_shim_free")] public static partial void Free(ShimInsn* p);
        [LibraryImport(Lib, EntryPoint = "cs_shim_insn_size")] public static partial nuint InsnSize();
    }

    public static class Arm64Op
    {
        public const int Reg = 1, Imm = 2, Mem = 3;   // ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
    }

    public readonly struct MemOp
    {
        public readonly int Base, Index, Disp;
        public MemOp(int b, int i, int d) { Base = b; Index = i; Disp = d; }
    }

    public sealed class Operand
    {
        public int Type;
        public int Reg;
        public long Imm;
        public MemOp Mem;
    }

    public sealed class Insn
    {
        public long Address;
        public uint Word;
        public string Mnemonic;
        public string OpStr;
        public Operand[] Operands;
        public bool Writeback;
        internal ushort[] Read, Written;
        internal bool RegsOk;
        internal Cs Owner;

        public (ushort[] Read, ushort[] Written) RegsAccess()
        {
            if (!RegsOk) throw new CsException($"regs_access failed at {Address:x}");
            return (Read, Written);
        }

        public string RegName(int reg) => Owner.RegName(reg);
    }

    public sealed class CsException : Exception
    {
        public CsException(string message) : base(message) { }
    }

    public sealed unsafe class Cs : IDisposable
    {
        private IntPtr _h;
        private readonly bool _detail;
        private readonly Dictionary<int, string> _names = new();

        public Cs(bool detail)
        {
            if (CsNative.InsnSize() != (nuint)sizeof(CsNative.ShimInsn)) throw new InvalidOperationException("cs_shim layout mismatch");
            _h = CsNative.Open(detail ? 1 : 0);
            if (_h == IntPtr.Zero) throw new InvalidOperationException("cs_open failed");
            _detail = detail;
        }

        public static int Version => CsNative.Version();

        public string RegName(int reg)
        {
            if (_names.TryGetValue(reg, out string n)) return n;
            IntPtr p = CsNative.RegName(_h, reg);
            n = p == IntPtr.Zero ? null : Marshal.PtrToStringAnsi(p);
            _names[reg] = n;
            return n;
        }

        // md.disasm(code, address): every instruction up to the first word Capstone cannot decode
        public List<Insn> Disasm(ReadOnlySpan<byte> code, long address, int count = 0)
        {
            var list = new List<Insn>();
            if (code.IsEmpty) return list;
            CsNative.ShimInsn* p;
            nuint n;
            fixed (byte* c = code) n = CsNative.Disasm(_h, c, (nuint)code.Length, (ulong)address, (nuint)count, out p);
            try
            {
                list.Capacity = (int)n;
                for (nuint i = 0; i < n; i++) list.Add(Convert(&p[i]));
            }
            finally { if (p != null) CsNative.Free(p); }
            return list;
        }

        private static string Str(byte* s, int max)
        {
            int len = 0;
            while (len < max && s[len] != 0) len++;
            return Encoding.ASCII.GetString(s, len);
        }

        private Insn Convert(CsNative.ShimInsn* s)
        {
            var ins = new Insn
            {
                Address = (long)s->Address,
                Word = s->Word,
                Mnemonic = Str(s->Mnemonic, 32),
                OpStr = Str(s->OpStr, 160),
                Owner = this,
            };
            if (!_detail) return ins;
            ins.Writeback = s->Writeback != 0;
            ins.Operands = new Operand[s->OpCount];
            CsNative.ShimOp* ops = &s->Op0;
            for (int k = 0; k < s->OpCount; k++)
            {
                ins.Operands[k] = new Operand { Type = ops[k].Type, Reg = ops[k].Reg, Imm = ops[k].Imm, Mem = new MemOp(ops[k].MemBase, ops[k].MemIndex, ops[k].MemDisp) };
            }
            ins.RegsOk = s->RegsStatus == 0;
            if (ins.RegsOk)
            {
                ins.Read = new ushort[s->RegsReadCount];
                ins.Written = new ushort[s->RegsWriteCount];
                for (int k = 0; k < ins.Read.Length; k++) ins.Read[k] = s->RegsRead[k];
                for (int k = 0; k < ins.Written.Length; k++) ins.Written[k] = s->RegsWrite[k];
            }
            return ins;
        }

        public void Dispose()
        {
            if (_h != IntPtr.Zero) { CsNative.Close(_h); _h = IntPtr.Zero; }
        }
    }
}
