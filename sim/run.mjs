// sim/run.mjs — ejecuta la simulacion: bridge + payloads reales de DEMO/
// sobre el entorno fake (ver fakeps5.mjs). Uso: node sim/run.mjs
import vm from "node:vm";
import { bootSim, runPayload, setAioAlive, out } from "./fakeps5.mjs";

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

// ---------- resumen ----------
const fails = results.filter((r) => !r.pass);
console.log("\n=== RESULTADO: " + (results.length - fails.length) + "/" + results.length + " OK ===");
process.exit(fails.length ? 1 : 0);
