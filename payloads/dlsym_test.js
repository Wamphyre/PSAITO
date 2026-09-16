// 2026-09-16 — ported from the original loader-side dlsym_test (Y2JB runtime).
// The bridge has no check_jailbroken() and no LIBKERNEL_HANDLE global: dlsym
// on Orbis is syscall 0x24F with handle 0x2001 (SYSTEM) / 0x2002 (WEBKIT).
// [sim: hang-expected] final yield loop keeps the notification readable.
(async function() {
    const HANDLE = 0x2001n; // libkernel (SYSTEM module) — read-only probe
    await log("Test 1 : Direct dlsym syscall (0x24F, handle 0x2001)");
    let sym_addr = alloc_string("sceKernelAllocateMainDirectMemory");
    let addr_out = malloc(0x10);
    write64(addr_out, 0n);

    let result = syscall(SYSCALL.dlsym, HANDLE, sym_addr, addr_out);
    // bridge convention: error => -1n (signed) + errno in get_error_string()
    if (result < 0n) {
        await log("dlsym error: " + get_error_string());
    } else {
        await log("dlsym ok: ret=0x" + BigInt.asUintN(64, result).toString(16));
    }

    await log("sceKernelAllocateMainDirectMemory : " +  toHex(read64(addr_out)));
    for (let i = 0; i < 10; ++i) { try { syscall(SYSCALL.sched_yield); } catch (e) {} }
})();
