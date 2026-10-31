// dm_jit_alloc for nxnative's loader in MeloNX native mode (patches/0001-loader-jit-region.patch, DM_JIT_LOADER): executable memory for the rewritten game code,
// and a writable view of the same pages.
// - First choice, DM_JIT_POOL=<rx>:<rw>:<size> (hex; set by the app, NativePrep.swift): the JIT region MeloNX's emulator got when the app started
//   (Ryujinx.Cpu DualMappedMemory.SharedJitRegion), already executable at rx and writable at rw. With TXM (iOS 26+ on A15 and later) only the debugger can grant such a
//   region, and the JIT script grants it while the app starts, not later: a BreakGetJITMapping at launch time ends in an unhandled breakpoint (SIGTRAP). The emulator does
//   not run in a process that runs native mode, so the region is carved here, front to back.
// - Otherwise as MeloNX's own JIT does (src/Ryujinx.Memory/DualMappedJitAllocator.cs): with TXM (HAS_TXM=1, set by MeloNXApp.swift) a mapping the debugger grants
//   through BreakpointJIT, else r-x anonymous memory, which a debugged process may remap; the writable view comes from vm_remap.
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void *BreakGetJITMapping(void *addr, size_t len);   // BreakpointJIT.framework

static int pool_alloc(size_t size, void **rx, void **rw) {
    static uintptr_t prx, prw, psize, used; static int parsed;
    if (!parsed) {
        parsed = 1;
        const char *e = getenv("DM_JIT_POOL");
        unsigned long long a = 0, b = 0, n = 0;
        if (e && sscanf(e, "%llx:%llx:%llx", &a, &b, &n) == 3 && a && b && n) { prx = a; prw = b; psize = n; }
        if (prx) fprintf(stderr, "[dm] JIT: the app's region, %#llx bytes at %#llx\n", n, a);
    }
    if (!prx || used + size > psize) return 0;
    *rx = (void *)(prx + used); *rw = (void *)(prw + used); used += size;
    return 1;
}

void *dm_jit_alloc(size_t size, void **rw) {
    *rw = NULL;
    size = (size + 0x3FFF) & ~(size_t)0x3FFF;
    void *rx;
    if (pool_alloc(size, &rx, rw)) return rx;
    const char *txm = getenv("HAS_TXM");
    if (txm && !strcmp(txm, "1")) {
        if (getenv("DM_JIT_POOL")) { fprintf(stderr, "[RED] JIT: the app's region has no %#zx bytes left\n", size); return NULL; }
        rx = BreakGetJITMapping(NULL, size);
        if (!rx || rx == (void *)-1) return NULL;
    } else {
        rx = mmap(NULL, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (rx == MAP_FAILED) return NULL;
    }
    vm_address_t view = 0; vm_prot_t cur = 0, max = 0;
    if (vm_remap(mach_task_self(), &view, size, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (vm_address_t)rx, FALSE, &cur, &max, VM_INHERIT_NONE) != KERN_SUCCESS) return NULL;
    if (vm_protect(mach_task_self(), view, size, FALSE, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) return NULL;
    *rw = (void *)view;
    return rx;
}
