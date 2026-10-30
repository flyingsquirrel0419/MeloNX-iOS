// dm_jit_alloc for nxnative's loader in MeloNX native mode (patches/0001-loader-jit-region.patch, DM_JIT_LOADER): executable memory for the rewritten game code,
// and a writable view of the same pages. It gets the memory the way MeloNX's own JIT does (src/Ryujinx.Memory/DualMappedJitAllocator.cs):
// - with TXM (iOS 26+ on A15 and later; HAS_TXM=1, set by MeloNXApp.swift), a mapping the attached debugger grants through BreakpointJIT;
// - otherwise, r-x anonymous memory, which a debugged process may remap.
// In both cases the writable view comes from vm_remap.
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void *BreakGetJITMapping(void *addr, size_t len);   // BreakpointJIT.framework

void *dm_jit_alloc(size_t size, void **rw) {
    *rw = NULL;
    size = (size + 0x3FFF) & ~(size_t)0x3FFF;
    const char *txm = getenv("HAS_TXM");
    void *rx;
    if (txm && !strcmp(txm, "1")) {
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
