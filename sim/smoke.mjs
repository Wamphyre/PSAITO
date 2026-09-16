// 2026-09-11 smoke.mjs — pasa TODOS los payloads de DEMO/payloads por el
// entorno simulado (bridge real + kernel fake) con watchdog por payload.
// No valida logica del payload: caza crashes de compatibilidad API del
// bridge (TypeError/not-defined), hangs y errores de sintaxis.
// Uso: node sim/smoke.mjs [--timeout=ms] [--only=a,b] [--quiet] [--strict]
//
// Marcador en el payload: una cabecera con "// sim: hang-expected" marca los
// payloads cuyo bucle de notificacion final se cuelga a proposito (necesario
// en consola para leer el veredicto). Esos HANG cuentan como HANG* y NO
// rompen el exit code; el resto de HANG si. Con --strict, HANG* tambien falla.
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import * as F from "./fakeps5.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.resolve(HERE, "../payloads");
const ARGV = process.argv.slice(2);
const TO = Number((ARGV.find((a) => a.startsWith("--timeout=")) || "").split("=")[1]) || 4000;
const QUIET = ARGV.includes("--quiet");
const STRICT = ARGV.includes("--strict");
const ONLY = (ARGV.find((a) => a.startsWith("--only=")) || "").slice(7)
    .split(",").map((s) => s.trim()).filter(Boolean);
const HANG_EXPECTED = /\/\/\s*sim:\s*hang-expected/i;
// --quiet silencia el ruido del sim (console.log de bridge/payloads) pero NO
// el reporte del smoke: se escribe por process.stdout.write.
const out = (s) => process.stdout.write(s + "\n");
if (QUIET) console.log = () => {};

let files = fs.readdirSync(DIR).filter((f) => f.endsWith(".js")).sort();
if (ONLY.length) files = files.filter((f) => ONLY.some((o) => f.includes(o)));
const tally = {};
const rows = [];
// Los payloads con IIFE async rechazan la promesa FUERA de runInContext: sin
// esta captura un ReferenceError tardio (p.ej. dlsym_test check_jailbroken)
// se contaria como OK.
let pendingRejects = [];
process.on("unhandledRejection", (e) => {
    const m = String((e && e.message) || e).split("\n")[0];
    pendingRejects.push(m);
});
for (const f of files) {
    const src = fs.readFileSync(path.join(DIR, f), "utf8");
    const hangExpected = HANG_EXPECTED.test(src);
    let st, info = "";
    const t0 = Date.now();
    let logs = 0, tcp = 0, last = "";
    pendingRejects.length = 0;
    let sb = null;
    try {
        F.resetOut();
        sb = F.bootSim();
        vm.runInContext(src, sb, { filename: f, timeout: TO });
        // microtask flush: las IIFE async encolan su cuerpo; un await
        // posterior puede seguir colgando (HANG) y eso ya lo cubre el timeout
        // del vm solo para el tramo sincrono.
        await new Promise((r) => setTimeout(r, 20));
        if (pendingRejects.length) {
            const m = pendingRejects[0];
            st = /is not a function|is not defined|Cannot read propert.*undefined/.test(m) ? "APIGAP" : "CRASH";
            info = m.slice(0, 78);
        } else st = "OK";
    } catch (e) {
        const m = String((e && e.message) || e).split("\n")[0];
        if (/timed out/i.test(m)) st = hangExpected ? "HANG*" : "HANG";
        else if (/is not a function|is not defined|Cannot read propert.*undefined/.test(m)) st = "APIGAP";
        else st = "CRASH";
        info = m.slice(0, 78);
    }
    // Aislamiento: cancelar timers pendientes del payload y purgar rechazos
    // tardios para que el siguiente payload empiece limpio.
    try { if (sb && typeof sb.__clearTimers === "function") sb.__clearTimers(); } catch (e) {}
    pendingRejects.length = 0;
    logs = F.out.pclog.length; tcp = F.out.tcp.length;
    last = F.out.pclog.length ? String(F.out.pclog[F.out.pclog.length - 1]).slice(0, 60) : "";
    tally[st] = (tally[st] || 0) + 1;
    rows.push([st, f, Date.now() - t0, logs, tcp, info || last]);
}
const W = { OK: "#", HANG: "H", "HANG*": "h", APIGAP: "A", CRASH: "C" };
for (const [st, f, ms, logs, tcp, info] of rows)
    out(`${W[st] || "?"} ${st.padEnd(6)} ${f.padEnd(28)} ${String(ms).padStart(5)}ms log=${String(logs).padStart(3)} tcp=${String(tcp).padStart(3)}  ${info}`);
out("---");
out(Object.entries(tally).map(([k, v]) => `${k}=${v}`).join("  ") + "  total=" + files.length);
const hardFails = (tally.CRASH || 0) + (tally.APIGAP || 0) + (STRICT ? (tally["HANG*"] || 0) : 0);
process.exit(hardFails ? 1 : 0);
