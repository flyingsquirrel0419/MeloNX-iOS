// A flat view of Capstone 5's AArch64 decoder for MeloNX.Native.Prep (the C# port of nxnative's dm/tools/patch_nso.py).
// The C# side never depends on Capstone's own struct layouts: every instruction is copied into a cs_shim_insn, whose layout is fixed here and mirrored in Capstone.cs.
// The rewriter reads exactly what the Python binding gives it (mnemonic, op_str, operands, writeback, regs_access, reg_name), so outputs stay byte-identical with the Python tool.
#include <capstone/capstone.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int32_t type;      // arm64_op_type
    int32_t reg;       // the union's first 32 bits (arm64_reg for a register operand)
    int64_t imm;       // the union's first 64 bits (the immediate for an immediate operand)
    int32_t mem_base;
    int32_t mem_index;
    int32_t mem_disp;
    int32_t pad;
} cs_shim_op;

typedef struct {
    uint64_t address;
    uint32_t word;
    uint32_t id;
    char mnemonic[32];
    char op_str[160];
    uint8_t op_count;
    uint8_t writeback;
    uint8_t regs_status;   // 0: regs_access succeeded
    uint8_t regs_read_count;
    uint8_t regs_write_count;
    uint8_t pad[3];
    uint16_t regs_read[64];
    uint16_t regs_write[64];
    cs_shim_op ops[8];
} cs_shim_insn;

// detail != 0 gives operands and register lists (Python's md.detail = True); 0 is disasm_lite
void *cs_shim_open(int detail) {
    csh h;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h) != CS_ERR_OK) return NULL;
    if (detail) cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    return (void *)(uintptr_t)h;
}

void cs_shim_close(void *handle) {
    csh h = (csh)(uintptr_t)handle;
    cs_close(&h);
}

int cs_shim_version(void) {
    int major = 0, minor = 0;
    cs_version(&major, &minor);
    return major * 100 + minor;
}

const char *cs_shim_reg_name(void *handle, int reg) {
    return cs_reg_name((csh)(uintptr_t)handle, (unsigned)reg);
}

// Decodes code (size bytes at address) as cs_disasm does, stopping at the first word it cannot decode, and returns how many instructions *out holds (free it with cs_shim_free)
size_t cs_shim_disasm(void *handle, const uint8_t *code, size_t size, uint64_t address, size_t count, cs_shim_insn **out) {
    csh h = (csh)(uintptr_t)handle;
    cs_insn *insn = NULL;
    size_t n = cs_disasm(h, code, size, address, count, &insn);
    *out = NULL;
    if (!n) return 0;
    cs_shim_insn *r = calloc(n, sizeof *r);
    if (!r) { cs_free(insn, n); return 0; }
    for (size_t i = 0; i < n; i++) {
        cs_insn *s = &insn[i]; cs_shim_insn *d = &r[i];
        d->address = s->address; d->id = s->id;
        memcpy(&d->word, s->bytes, 4);
        strncpy(d->mnemonic, s->mnemonic, sizeof d->mnemonic - 1);
        strncpy(d->op_str, s->op_str, sizeof d->op_str - 1);
        if (!s->detail) continue;
        cs_arm64 *a = &s->detail->arm64;
        d->writeback = a->writeback;
        d->op_count = a->op_count > 8 ? 8 : a->op_count;
        for (int k = 0; k < d->op_count; k++) {
            cs_arm64_op *o = &a->operands[k];
            d->ops[k].type = o->type;
            memcpy(&d->ops[k].imm, &o->imm, sizeof(int64_t));
            memcpy(&d->ops[k].reg, &o->imm, sizeof(int32_t));
            d->ops[k].mem_base = o->mem.base; d->ops[k].mem_index = o->mem.index; d->ops[k].mem_disp = o->mem.disp;
        }
        cs_regs rr, ww; uint8_t nr = 0, nw = 0;
        d->regs_status = (uint8_t)cs_regs_access(h, s, rr, &nr, ww, &nw);
        if (!d->regs_status) {
            d->regs_read_count = nr; d->regs_write_count = nw;
            memcpy(d->regs_read, rr, nr * sizeof(uint16_t)); memcpy(d->regs_write, ww, nw * sizeof(uint16_t));
        }
    }
    cs_free(insn, n);
    *out = r;
    return n;
}

void cs_shim_free(cs_shim_insn *p) { free(p); }

size_t cs_shim_insn_size(void) { return sizeof(cs_shim_insn); }
