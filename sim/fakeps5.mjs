// sim/fakeps5.mjs — simulador Node del entorno post-exploit del userland
// mansoor0x + bridge.js. NO simula el bug de WebKit: simula desde el HANDOFF
// (window.__PS5_CTX) hacia abajo: memoria, trampolines del UCollator falso,
// CPU mini-x86 que ejecuta de verdad las cadenas ROP del bridge (bytecode),
// y un kernel fake con tabla de syscalls ORBIS configurable (AIO viva/muerta).
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import vm from "node:vm";

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const PAYLOADS = path.resolve(HERE, "../payloads");
const BRIDGE = path.resolve(HERE, "../modules/bridge.js");
const MENU = path.resolve(HERE, "../modules/menu.js");

// ---------- memoria paginada 4K ----------
const PAGES = new Map();
function pageOf(a) {
    a = BigInt(a);
    const key = a >> 12n;
    let p = PAGES.get(key);
    if (!p) { p = new Uint8Array(4096); PAGES.set(key, p); }
    return [p, Number(a & 0xfffn)];
}
const M = {
    read8(a) { const [p, o] = pageOf(a); return p[o]; },
    write8(a, v) { const [p, o] = pageOf(a); p[o] = v & 0xff; },
    read64(a) { let v = 0n; for (let i = 7; i >= 0; --i) v = (v << 8n) | BigInt(this.read8(BigInt(a) + BigInt(i))); return v; },
    write64(a, v) { v = BigInt.asUintN(64, BigInt(v)); for (let i = 0; i < 8; ++i) this.write8(BigInt(a) + BigInt(i), Number((v >> BigInt(8 * i)) & 0xffn)); },
    writeBytes(a, u8) { for (let i = 0; i < u8.length; ++i) this.write8(BigInt(a) + BigInt(i), u8[i]); },
    readBytes(a, n) { const o = new Uint8Array(n); for (let i = 0; i < n; ++i) o[i] = this.read8(BigInt(a) + BigInt(i)); return o; },
    read32(a) { let v = 0; for (let i = 3; i >= 0; --i) v = v * 256 + this.read8(BigInt(a) + BigInt(i)); return v >>> 0; },
    write32(a, v) { v = v >>> 0; for (let i = 0; i < 4; ++i) this.write8(BigInt(a) + BigInt(i), (v >>> (8 * i)) & 0xff); },
};

// ---------- layout de módulos ----------
const LIBK = 0x810000000n;    // base libkernel (texto 0x44000)
const ARENA = 0x8012340000n;
const COLLCELL = 0x8011000240n;
const ICU_RET = LIBK + 0x21abcn;          // "reingreso ICU" tras la cadena
const R0STK = 0x7ffffffdff40n;            // rsp real de ICU (pila)
const NOTIFY_ENTRY = LIBK + 0x48b0n;
let strCursor = 0x8020000000n;

// ---------- libkernel fake con gadgets reales ----------
function put(off, bytes) { M.writeBytes(LIBK + BigInt(off), Uint8Array.from(bytes)); }
put(0x10c0, [0xc3]);                          // ret
put(0x10d0, [0x58, 0xc3]);                    // pop rax; ret
put(0x10d8, [0x5f, 0xc3]);                    // pop rdi; ret
put(0x10e0, [0x5e, 0xc3]);                    // pop rsi; ret
put(0x10e8, [0x5a, 0xc3]);                    // pop rdx; ret
put(0x10f0, [0x59, 0xc3]);                    // pop rcx; ret
put(0x10f8, [0x41, 0x5a, 0xc3]);              // pop r10; ret
put(0x1100, [0x41, 0x58, 0xc3]);              // pop r8; ret
put(0x1108, [0x41, 0x59, 0xc3]);              // pop r9; ret
put(0x1110, [0x5c, 0xc3]);                    // pop rsp; ret
put(0x1118, [0x0f, 0x05, 0xc3]);              // syscall; ret
put(0x1120, [0x48, 0x89, 0x07, 0xc3]);        // mov [rdi],rax; ret
put(0x1128, [0x48, 0x89, 0x27, 0xc3]);        // mov [rdi],rsp; ret
put(0x1130, [0x48, 0x8b, 0xe7, 0xc3]);        // mov rsp,rdi; ret
put(0x1140, [0x49, 0x89, 0xca, 0x48, 0x89, 0xf8, 0x0f, 0x05]); // syscall() wrapper
M.write64(R0STK, ICU_RET);
// UCollator real: m_collator original en COLLCELL+0x18
M.write64(COLLCELL + 0x18n, 0x8011050a00n);
// centinela arena "ROP1" en +0xf00 (el exploit lo deja puesto)
M.writeBytes(ARENA + 0xf00n, Uint8Array.from([0x52, 0x4f, 0x50, 0x31]));

// ---------- kernel fake ----------
let AIO_ALIVE = true;
let PID = 4242, nextFd = 23, mmapCur = 0x7000000000n;
const openFds = new Set();
let tcpConnected = false;
// [bagagwa] fake-kernel state: AIO requests, osem (zone 128) and UAF.
const aioReqs = new Map();   // id -> {fd, woken, dangling}
let aioSeq = 0x100;
const OSEMS = new Map();     // id -> {name, value, reclaimed, corrupted}
let osemSeq = 0x61ab;
const pairPeer = new Map();  // fd <-> fd (socketpair): wake por el extremo B
let uafArmed = false;        // aio_multi_wait mode0 num>=2 -> array liberado
let UAF_EFFECT = true;       // si false, el waker corre pero no altera nada
export function setUafEffect(v) { UAF_EFFECT = !!v; }

// ===== [conversión] laboratorio zona-128 a nivel de bytes (paste BAGAGWA §1+§4) =====
// Modela el bloque liberado (array de waiters num=2 -> 0x70, zona 128), su
// reclaim por osem_create (malloc(0x60, M_osem)) o por un primitivo externo
// (hook de test), y los efectos EXACTOS del waker sobre los campos del nodo:
//   write32 [node+0x20], mtx_lock [node+0x10]+0x18,
//   dec dword [[node+0]]  (sin null-check -> panic si apunta a nada mapeado)
//   dec dword [[node+8]]  (skip si 0: mode 0 lo deja M_ZERO - paste §1)
// osem (paste §4): flag byte [obj+0x45]&1 (clear -> free sin leer refcount),
// refcount dword [obj+0x54] (mismo ancho que el dec del waker). El nombre se
// strlcpy'a DENTRO del struct a OSEM_NAME_OFF (layout real desconocido: el
// payload osem_conv lo descubre en consola; los hooks lo mueven para probar
// ambos mundos). Refcount inicial del modelo = 2 (handle id + ref interna:
// osem_open hace inc, close dec — paste §4).
const osemHeap = new Map();  // addr -> {id, bytes: Uint8Array(0x60)}
const osemMeta = new Map();  // id  -> {addr, tomb}
let osemAddrSeq = 0;
const OSEM_ADDR_BASE = 0xffff860200000000n;  // banda de structs osem del modelo
const ANON_A = 0xffff860300000000n;           // puntero "kernel" del head (+0)
const ANON_MTX = 0xffff860300001000n;         // mtx interna del head (+0x10)
const Z128_BASE = 0xffff860400000000n;        // banda del bloque liberado
let zseq = 0;
let z128Addr = null;         // direccion del bloque liberado (nodo colgante)
let z128Free = false;        // ¿esta libre (reclamable) o ya lo tomó alguien?
let z128Owner = "none";      // "stale" | "osem" | "inject" | "none"
let z128Stale = null;        // Uint8Array(0x70): bytes del nodo tras mode 0
let z128Inject = null;       // bytes inyectados por el hook de test
let OSEM_NAME_OFF = 0x28;    // offset del nombre dentro del struct (modelo)
let OSEM_FLAG = 1;           // valor del flag [0x45] al crear (ruta refcount)
export function setOsemNameOff(v) { OSEM_NAME_OFF = Number(v) & 0x3f; }
export function setOsemFlagMode(v) { OSEM_FLAG = v ? 1 : 0; }
export function osemAddrOf(id) { const m = osemMeta.get(Number(id)); return m ? m.addr : null; }
export function simReclaimInject(bytes) {
    if (!uafArmed || !z128Free) return false;   // sin UAF armado no hay bloque
    z128Inject = new Uint8Array(0x70); z128Inject.set(bytes.subarray(0, 0x70));
    z128Free = false; z128Owner = "inject";
    return true;
}
function write64Bytes(b, off, v) {
    let x = BigInt(v);
    for (let i = 0; i < 8; ++i) { b[off + i] = Number(x & 0xffn); x >>= 8n; }
}
function read64Bytes(b, off) {
    let x = 0n;
    for (let i = 7; i >= 0; --i) x = (x << 8n) | BigInt(b[off + i]);
    return x;
}
function dec32At(addr, tag) {
    addr = BigInt(addr);
    for (const [base, st] of osemHeap) {          // ¿dentro de un osem?
        if (addr >= base && addr < base + 0x60n) {
            const off = Number(addr - base);
            let v = (st.bytes[off] | (st.bytes[off + 1] << 8)
                | (st.bytes[off + 2] << 16) | (st.bytes[off + 3] << 24)) >>> 0;
            v = (v - 1) >>> 0;
            st.bytes[off] = v & 255; st.bytes[off + 1] = (v >>> 8) & 255;
            st.bytes[off + 2] = (v >>> 16) & 255; st.bytes[off + 3] = (v >>> 24) & 255;
            out.conv.push(tag + "-REFCNT osem id=" + st.id + " @" + off.toString(16)
                + " -> " + v + (off === 0x54 ? " *** DEC EN REFCOUNT (paste §4) ***" : ""));
            return;
        }
    }
    if (addr >= ANON_A && addr < ANON_MTX + 0x10000n) {
        out.conv.push(tag + "-ANON @0x" + addr.toString(16) + " (struct kernel ajeno)");
        return;
    }
    out.panic = "KERNEL PANIC: " + tag + " @0x" + addr.toString(16)
        + " apunta a memoria NO mapeada (nodo colgante con contenido basura)";
    out.conv.push("PANIC " + tag);
}
function wakerApply() {
    const bytes = z128Owner === "inject" ? z128Inject
        : (z128Owner === "osem" ? osemHeap.get(z128Addr)?.bytes : z128Stale);
    if (!bytes) { out.conv.push("WAKER: bloque sin contenido (stale vacio)"); return; }
    out.conv.push("WAKER sobre nodo @0x" + z128Addr.toString(16)
        + " owner=" + z128Owner);
    // 1) write32 [node+0x20], eax (estado de completado; modelo 0)
    for (let i = 0; i < 4; ++i) bytes[0x20 + i] = 0;
    out.conv.push("W-WRITE32 [node+0x20] <- eax(0)");
    // 2) mtx_lock([node+0x10] + 0x18)
    const mtx = read64Bytes(bytes, 0x10);
    if (mtx === 0n || !(mtx >= ANON_A && mtx < ANON_MTX + 0x10000n)) {
        out.panic = "KERNEL PANIC: mtx_lock @0x" + mtx.toString(16)
            + " (campo [node+0x10] del bloque reclaimado no mapeado)";
        out.conv.push("PANIC mtx_lock");
    } else out.conv.push("W-MTXLOCK ok @0x" + mtx.toString(16));
    // 3) dec dword [[node+0]]  (sin null-check en el waker real)
    const t1 = read64Bytes(bytes, 0x00);
    if (t1 === 0n) { out.panic = "KERNEL PANIC: dec1 [NULL] (campo [node+0] a cero)"; out.conv.push("PANIC dec1-NULL"); }
    else dec32At(t1, "W-DEC1");
    // 4) dec dword [[node+8]]  (mode 0 lo deja M_ZERO -> skip)
    const t2 = read64Bytes(bytes, 0x08);
    if (t2 === 0n) out.conv.push("W-DEC2 skip ([node+8]==0, M_ZERO de mode 0)");
    else dec32At(t2, "W-DEC2");
}
export function resetKernel() {
    aioReqs.clear(); OSEMS.clear(); pairPeer.clear();
    uafArmed = false;
    osemHeap.clear(); osemMeta.clear(); osemAddrSeq = 0; zseq = 0;
    z128Addr = null; z128Free = false; z128Owner = "none";
    z128Stale = null; z128Inject = null;
}
export const out = { notifs: [], tcp: [], pclog: [], conv: [], panic: null };
export function resetOut() {
    out.notifs.length = out.tcp.length = out.pclog.length = out.conv.length = 0;
    out.panic = null;
}
function kernel(rax, rdi, rsi, rdx, r10, r8, r9) {
    rax = Number(BigInt.asIntN(64, rax));
    const A = (i) => BigInt.asUintN(64, [rdi, rsi, rdx, r10, r8, r9][i]);
    const neg = (e) => -BigInt(e);
    switch (rax) {
        case 20: return BigInt(PID);                       // getpid
        case 331: return 0n;                               // sched_yield
        case 97: {                                         // socket
            if (A(0) === 2n && A(1) === 1n) { openFds.add(nextFd); return BigInt(nextFd++); }
            return neg(22);                                // EINVAL
        }
        case 98: {                                         // connect
            const fd = Number(A(0));
            if (!openFds.has(fd)) return neg(9);
            const b = M.readBytes(A(1), 16);
            const port = (b[2] << 8) | b[3];
            const ip = `${b[4]}.${b[5]}.${b[6]}.${b[7]}`;
            tcpConnected = true;
            out.tcp.push(`CONNECT ${ip}:${port}`);
            return 0n;
        }
        case 53: {                                         // socketpair
            const a = A(3);
            if (a < 0x100000000n || a > 0x8fffffffffn) return neg(14);
            pairPeer.set(nextFd, nextFd + 1);
            pairPeer.set(nextFd + 1, nextFd);
            openFds.add(nextFd); openFds.add(nextFd + 1);
            M.write32(a, nextFd); M.write32(a + 4n, nextFd + 1);
            nextFd += 2;
            return 0n;
        }
        case 4: {                                          // write
            const fd = Number(A(0)), n = Number(A(2));
            if (!openFds.has(fd)) return neg(9);
            // socketpair wake: writing to end B completes the pending reads
            // of end A -> the kernel WAKER runs over the dangling waiters
            // (UAF) and alters the osems that reclaimed the zone.
            const peer = pairPeer.get(fd);
            if (peer !== undefined) {
                for (const rq of aioReqs.values())
                    if (rq.fd === peer) rq.woken = true;
                if (uafArmed) {
                    uafArmed = false;
                    if (UAF_EFFECT) {
                        // [conversión] primitivas del waker a nivel de bytes
                        // (paste §1) contra el bloque liberado/reclaimado:
                        wakerApply();
                        // y la corruptcion observable por las sondas osem:
                        for (const o of OSEMS.values())
                            if (o.reclaimed) { o.corrupted = true; o.value = 0; }
                    }
                }
                return BigInt(n);
            }
            const s = Buffer.from(M.readBytes(A(1), Math.min(n, 1024))).toString("latin1").trimEnd();
            out.tcp.push(s);
            console.log("  [PS5→PC:8081] " + s);
            return BigInt(n);
        }
        case 6: openFds.delete(Number(A(0))); return 0n;   // close
        case 3:                                            // read
            if (openFds.has(Number(A(0)))) return 0n;      // EOF
            return neg(9);
        case 5: return neg(2);                              // open ENOENT
        case 33: return neg(2);                             // access ENOENT
        case 99: return 0n;                                 // lseek
        case 9: {                                           // mmap: region propia
            const sz = Math.max(0x1000, (Number(BigInt.asUintN(64, rsi)) + 0xfff) & ~0xfff);
            const a = mmapCur; mmapCur += BigInt(sz); return a;
        }
        case 73: return 0n;                                 // munmap
        case 74: return 0n;                                 // mprotect
        case 54: return openFds.has(Number(A(0))) ? 0n : neg(9); // listen
        case 5: return neg(35);                             // accept EAGAIN
        case 105: return 0n;                                // setsockopt
        case 118: {                                         // getsockopt: valor 0, len 4
            if (A(3)) M.write32(A(3), 0);
            if (A(4)) M.write32(A(4), 4);
            return 0n;
        }
        case 240: return 0n;                                // nanosleep (no-op)
        case 455: return 0n;                                // orbis user_usleep
        case 0x295: case 0x296: case 0x297: case 0x298: case 0x299:
        case 0x29A: case 0x29C: case 0x29D: case 0x29E: case 0x2B0:
        case 0x13B: {
            if (!AIO_ALIVE) return neg(78);                // ENOSYS
            if (rax === 0x29E) return 0n;                  // init
            if (rax === 0x29C) return 0x11n;               // create
            if (rax === 0x29D) {                           // aio_submit_cmd
                if (A(0) !== 0x1001n) return neg(22);      // solo MULTI_READ
                const num = Number(A(2)), rq = A(1), idsP = A(4);
                if (!(rq >= 0x100000000n && rq < 0x8ffffffffffn)
                    || !(idsP >= 0x100000000n && idsP < 0x8ffffffffffn)
                    || num < 1 || num > 64) return neg(22);
                for (let i = 0; i < num; ++i) {
                    const fd = M.read32(rq + BigInt(i * 0x28 + 0x20));
                    if (!openFds.has(fd)) return neg(9);
                    const id = aioSeq++;
                    aioReqs.set(id, { fd, woken: false, dangling: false });
                    M.write32(idsP + BigInt(i * 4), id);
                }
                return BigInt(num);
            }
            if (rax === 0x297) {                           // aio_multi_wait
                // mode 0 + num>=2 -> BUG: el MISMO nodo se enlaza N veces, el
                // cleanup desenlaza solo del ultimo: requests 0..N-2 quedan con
                // waiters colgando del array liberado (UAF armado).
                const num = Number(A(1));
                if (A(3) === 0n && num >= 2 && num <= 64
                    && A(0) >= 0x100000000n && A(0) < 0x8ffffffffffn) {
                    for (let i = 0; i < num - 1; ++i) {
                        const rq = aioReqs.get(M.read32(A(0) + BigInt(i * 4)));
                        if (rq) rq.dangling = true;
                    }
                    // [conversión] el array (num*0x38; num=2 -> 0x70, zona 128)
                    // se libera: sus bytes quedan como los dejó mode 0 (el +8
                    // del nodo M_ZERO — paste §1). num=3/4 daría 0xA8/0xE0
                    // (zona 256): osem_create NO podría reclamarlo.
                    if (num === 2) {
                        z128Addr = Z128_BASE + BigInt(zseq++ * 0x80);
                        z128Free = true; z128Owner = "stale";
                        z128Inject = null;
                        z128Stale = new Uint8Array(0x70);
                        write64Bytes(z128Stale, 0x00, ANON_A);      // req ptr stale
                        write64Bytes(z128Stale, 0x08, 0n);          // M_ZERO (paste §1)
                        write64Bytes(z128Stale, 0x10, ANON_MTX);    // mtx stale
                    }
                    uafArmed = true;
                    return 0n;
                }
                return neg(35);                            // resto: EAGAIN
            }
            return neg(22);                                // resto EINVAL
        }
        case 0x225: {                                      // osem_create(name,attr,val,max,opt)
            const np = A(0);
            if (!(np >= 0x100000000n && np < 0x8ffffffffffn)) return neg(14);
            let s = "";
            for (let i = 0n; i < 32n; ++i) { const c = M.read8(np + i); if (!c) break; s += String.fromCharCode(c); }
            if (!s) return neg(22);
            const id = osemSeq++;
            // [conversión] malloc(0x60, M_osem) = zona 128: si el array de
            // waiters esta liberado, el osem RECLAMA ese bloque (el struct
            // pisa el nodo colgante). Solo el PRIMERO lo toma (los demas son
            // alocaciones inocentes fuera del bloque).
            let addr = OSEM_ADDR_BASE + BigInt(osemAddrSeq++ * 0x80);
            let tookFreed = false;
            if (uafArmed && z128Free) {
                addr = z128Addr; z128Free = false; tookFreed = true; z128Owner = "osem";
            }
            // struct del modelo (M_ZERO + init): head con punteros "kernel"
            // (+0/+0x10, +8 queda a 0 = slot libre M_ZERO del paste §1),
            // flag [0x45], refcount [0x54] (dword, paste §4), nombre strlcpy.
            const bytes = new Uint8Array(0x60);
            write64Bytes(bytes, 0x00, ANON_A);
            write64Bytes(bytes, 0x08, 0n);
            write64Bytes(bytes, 0x10, ANON_MTX);
            bytes[0x45] = OSEM_FLAG;
            bytes[0x54] = 2;                                 // refcount: id + ref interna
            const ncap = Math.min(0x45 - OSEM_NAME_OFF, s.length);
            for (let i = 0; i < ncap; ++i) bytes[OSEM_NAME_OFF + i] = s.charCodeAt(i) & 0x7f;
            osemHeap.set(addr, { id, bytes });
            osemMeta.set(id, { addr, tomb: false });
            OSEMS.set(id, { name: s, value: Math.max(1, Number(A(2) & 0xffffffffn)),
                reclaimed: tookFreed, corrupted: false });
            return BigInt(id);
        }
        case 0x226: {                                      // osem_delete(id)
            const id = Number(BigInt.asUintN(32, A(0)));
            const meta = osemMeta.get(id);
            // [conversión] paste §4: osem_delete hace test [rbx+0x45],1:
            //  - flag CLARO -> free inmediato SIN leer el refcount
            //  - flag SET   -> dec dword [rbx+0x54]; jne return (vive);
            //                   a 0 -> free(r14); free(rbx)
            // Un delete sobre un osem ya liberado = DOUBLE-FREE: en kernel
            // real toma el path UAF (corrupcion); aqui queda registrado.
            if (meta && meta.tomb) {
                out.conv.push("DOUBLE-FREE id=" + id
                    + " (delete sobre osem ya liberado -> el kernel toma el path UAF)");
                out.panic = "DOUBLE-FREE on osem id=" + id;
                OSEMS.delete(id);
                return 0n;
            }
            if (!OSEMS.has(id)) return neg(22);
            const st = osemHeap.get(meta.addr);
            if (st && !(st.bytes[0x45] & 1)) {
                out.conv.push("FLAG-CLEAR-FREE id=" + id
                    + " (flag +0x45 claro -> free sin leer refcount — paste §4)");
            } else if (st) {
                let rc = (st.bytes[0x54] | (st.bytes[0x55] << 8)
                    | (st.bytes[0x56] << 16) | (st.bytes[0x57] << 24)) >>> 0;
                rc = (rc - 1) >>> 0;
                st.bytes[0x54] = rc & 255; st.bytes[0x55] = (rc >>> 8) & 255;
                st.bytes[0x56] = (rc >>> 16) & 255; st.bytes[0x57] = (rc >>> 24) & 255;
                if (rc !== 0) {
                    out.conv.push("REFCNT-DEC id=" + id + " -> " + rc + " (vive)");
                    return 0n;
                }
                out.conv.push("REFCNT-ZERO-FREE id=" + id
                    + " (refcount a 0 -> free prematuro si quedaban refs)");
            }
            meta.tomb = true;
            osemHeap.delete(meta.addr);
            // el bloque vuelve al pool libre conservando los bytes del struct
            // (memoria liberada no se pone a cero):
            if (z128Addr === meta.addr) {
                z128Free = true; z128Owner = "stale"; z128Inject = null;
                if (st) z128Stale = st.bytes;
            }
            OSEMS.delete(id);
            return 0n;
        }
        case 0x22A: {                                      // osem_trywait(id)
            const o = OSEMS.get(Number(BigInt.asUintN(32, A(0))));
            if (!o) return neg(22);
            if (o.corrupted || o.value <= 0) return neg(35); // EBUSY
            o.value -= 1;
            return 0n;
        }
        case 0x22B: {                                      // osem_post(id)
            const o = OSEMS.get(Number(BigInt.asUintN(32, A(0))));
            if (!o) return neg(22);
            if (o.corrupted) return neg(22);               // struct alterado
            o.value += 1;
            return 0n;
        }
        case 0x2D7: {                                      // GET_AIO_DEBUG_REQUEST_INFO
            if (!AIO_ALIVE) return neg(78);
            const id = Number(BigInt.asUintN(64, rdi));
            const dstv = A(1);
            if (dstv < 0x100000000n || dstv > 0x8fffffffffn) return neg(14); // EFAULT
            // spec (paste): count bounded [1, table->0x228]. count=0/garbage
            // esta fuera del rango -> EINVAL en kernel real.
            const cnt = Number(A(2));
            if (!(cnt >= 1 && cnt <= 0x228)) return neg(22);
            const rq = aioReqs.get(id);
            if (rq) {
                // fired UAF: the request waiters dangle in the freed/reclaimed
                // zone -> 727 copies DIFFERENT pointers.
                const freed = rq.dangling && rq.woken && UAF_EFFECT;
                const base = freed ? 0x000000dead000000n : 0xffff860000000000n;
                for (let i = 0; i < 3; ++i) M.write64(dstv + BigInt(i * 8), base + BigInt(i) * 0x40n + BigInt(id));
                return 0n;
            }
            // [leakmap] paste §3: el source index es (req_id>>16)+edx usado
            // como sesgo DENTRO de otra array -> leak legítimo de punteros
            // kernel por slot. Elemento = 0x18 bytes: ptr1, ptr2, dword.
            const slot = Number(BigInt.asUintN(64, rdi) >> 16n);
            if (slot < 0x80) {
                const nel = Math.min(Number(A(2)), 16);
                for (let edx = 0; edx < nel; ++edx) {
                    const e = dstv + BigInt(edx * 0x18), s = slot + edx;
                    M.write64(e, 0xffff860000000000n + BigInt(s) * 0x100n);
                    M.write64(e + 8n, 0xffff860000001000n + BigInt(s) * 0x40n);
                    M.write32(e + 0x10n, (s & 0xffff) | 0x10000);
                }
                return 0n;                                 // leak sesgado por slot
            }
            return neg(22);
        }
        default: return neg(78);                           // ENOSYS
    }
}

// ---------- mini-CPU x86 (solo los gadgets del bridge) ----------
// Semantica real: la pila al entrar al gadget apunta a la dir. de retorno.
// Cada gadget termina en ret: pc = [rsp]; rsp += 8 DESPUES de ejecutar el
// cuerpo. "pop X; ret" consume 2 qwords (valor + siguiente pc).
function cpu(entryPc, st, maxSteps = 200000) {
    let pc = entryPc;
    for (let step = 0; step < maxSteps; ++step) {
        if (pc === ICU_RET) return;             // reingreso a ICU
        const b0 = M.read8(pc), b1 = M.read8(pc + 1n);
        let next = null;                         // pc-advance (multi-byte ins)
        if (b0 === 0xb8) {                       // mov eax, imm32 (stub prologue)
            st.rax = BigInt(M.read32(pc + 1n));
            next = pc + 5n;
        }
        else if (b0 === 0x58 || b0 === 0x5f || b0 === 0x5e || b0 === 0x5a || b0 === 0x59) {
            const v = M.read64(st.rsp); st.rsp += 8n;
            if (b0 === 0x58) st.rax = v; else if (b0 === 0x5f) st.rdi = v;
            else if (b0 === 0x5e) st.rsi = v; else if (b0 === 0x5a) st.rdx = v;
            else st.rcx = v;
        }
        else if (b0 === 0x41 && (b1 === 0x5a || b1 === 0x58 || b1 === 0x59)) {
            const v = M.read64(st.rsp); st.rsp += 8n;
            if (b1 === 0x5a) st.r10 = v; else if (b1 === 0x58) st.r8 = v;
            else st.r9 = v;
        }
        else if (b0 === 0x5c) {                 // pop rsp
            st.rsp = M.read64(st.rsp);
        }
        else if (b0 === 0x0f && b1 === 0x05) {
            st.rax = kernel(st.rax, st.rdi, st.rsi, st.rdx, st.r10, st.r8, st.r9);
        }
        else if (b0 === 0x48 && b1 === 0x89) {
            const modrm = M.read8(pc + 2n);
            if (modrm === 0x07) M.write64(st.rdi, st.rax);          // [rdi]=rax
            else if (modrm === 0x27) M.write64(st.rdi, st.rsp);     // [rdi]=rsp
            else if (modrm === 0x47) M.write64(st.rdi + BigInt(M.read8(pc + 3n)), st.rax);
            else throw new Error("BADGADGET4889:" + modrm.toString(16) + "@" + pc.toString(16));
        }
        else if (b0 === 0x48 && b1 === 0x8b && M.read8(pc + 2n) === 0xe7) {
            st.rsp = st.rdi;                    // mov rsp,rdi
        }
        else if (b0 === 0xc3) { /* ret puro */ }
        else throw new Error("BADGADGET " + b0.toString(16) + "@" + pc.toString(16));
        if (next !== null) { pc = next; continue; }
        pc = M.read64(st.rsp); st.rsp += 8n;    // ret del gadget
    }
    throw new Error("ROP-RUNAWAY");
}

// ---------- ctx tipo handoff (lo que publicaría exploit.js) ----------
function viewProxy() {
    let cur = 0n;
    const proxy = new Proxy(new Array(256), {
        get: (t, i) => (typeof i === "string" && /^\d+$/.test(i)) ? M.read8(cur + BigInt(i)) : t[i],
        set: (t, i, v) => { if (/^\d+$/.test(i)) M.write8(cur + BigInt(i), v); else t[i] = v; return true; },
    });
    const arenaProxy = new Proxy(new Array(0x10000), {
        get: (t, i) => (typeof i === "string" && /^\d+$/.test(i)) ? M.read8(ARENA + BigInt(i)) : (i === "length" ? 0x10000 : t[i]),
        set: (t, i, v) => { if (/^\d+$/.test(i)) M.write8(ARENA + BigInt(i), v); else t[i] = v; return true; },
    });
    return {
        aim(a) { cur = BigInt(a); return proxy; },
        proxy, arenaProxy,
    };
}
function makeCtx() {
    const vp = viewProxy();
    const collatorSaved = M.readBytes(COLLCELL + 0x18n, 0x20);
    return {
        aim: vp.aim,
        view: () => vp.proxy,
        arena: vp.arenaProxy,
        arenaBacking: Number(ARENA),
        arenaBytes: 0x10000,
        fakeCollator: Number(ARENA + 0x100n),
        fakeVtable: Number(ARENA + 0x300n),
        collatorCell: Number(COLLCELL),
        collatorSaved,
        compare(req) {
            const B0 = ARENA + 0x100n;
            const target = M.read64(B0 + 0xe0n);
            const rdi = M.read64(B0 + 0x48n);
            const rcx = M.read64(B0 + 0x60n);
            if (M.read64(COLLCELL + 0x18n) !== ARENA + 0x100n)
                throw new Error("COLLATOR-NOT-ARMED");
            const strA = strCursor; strCursor += 0x2000n;
            M.writeBytes(strA, Buffer.from(String(req), "latin1"));
            if (target === NOTIFY_ENTRY) {
                const msg = Buffer.from(M.readBytes(strA, 0xc30)).toString("latin1")
                    .slice(0x2d).replace(/\x00+$/, "");
                out.notifs.push(msg);
                return 0;
            }
            const st = { rax: 0n, rdi, rsi: strA, rdx: BigInt(String(req).length),
                rcx, r10: 0n, r8: 0n, r9: 0n, rsp: R0STK };
            cpu(target, st);
            return Number(BigInt.asIntN(32, st.rax));
        },
        requestPadded(message) {
            const off = 0x2d, cap = 0xc30;
            let m = String(message), cut = cap - off - 1;
            if (m.length > cut) m = m.slice(0, cut);
            let s = "";
            for (let i = 0; i < cap; ++i) {
                const c = i < off ? 0 : (i < off + m.length ? (m.charCodeAt(i - off) & 0x7f) : 0);
                s += String.fromCharCode(c);
            }
            return s;
        },
        webkitBase: Number(0x8200000000n),
        libkernelBase: Number(LIBK),
        notifyEntry: Number(NOTIFY_ENTRY),
        trampoline: Number(LIBK + 0x1d6fan),
        fw: "13.20",
    };
}

// ---------- sandbox navegador mínimo + carga del bridge ----------
// opts.search: querystring del "location" (default auto=0: sin auto-arranque
//   de menu.js, para que los tests controlen que corre y cuando).
// opts.chainDelayMs / opts.chainStepMs: aceleran la cadena gated del menu en
//   sim (la consola usa 1500/4000 ms).
export function bootSim(opts) {
    opts = opts || {};
    const sandbox = {};
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    sandbox.console = console;
    // Los timers se registran para poder cancelarlos al cerrar el sandbox:
    // un vm con timeout mata el script pero NO cancela los setTimeout que
    // quedaron pendientes, y esos siguen escribiendo en out/ctx del sim
    // (contaminaba el smoke: payloads posteriores heredaban el log y los
    // efectos del anterior).
    const timers = new Set();
    sandbox.setTimeout = (f, ms) => {
        const t = setTimeout(() => { timers.delete(t); f(); }, ms);
        timers.add(t);
        if (t.unref) t.unref(); // timers de UI no mantienen viva la sim
        return t;
    };
    sandbox.clearTimeout = (t) => { timers.delete(t); clearTimeout(t); };
    sandbox.__clearTimers = () => { for (const t of timers) clearTimeout(t); timers.clear(); };
    sandbox.URLSearchParams = URLSearchParams;
    sandbox.location = { search: opts.search || "?go=1&pb=payloads/&auto=0" };
    if (typeof opts.chainDelayMs === "number")
        sandbox.__CHAIN_DELAY_MS = opts.chainDelayMs;
    if (typeof opts.chainStepMs === "number")
        sandbox.__CHAIN_STEP_MS = opts.chainStepMs;
    sandbox.navigator = { userAgent: "Mozilla/5.0 (PlayStation; PlayStation 5/2.26) AppleWebKit/605.1.15 Version/13.20 PlayStation 5/13.20" };
    sandbox.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
    const lsStore = {};
    sandbox.localStorage = {
        getItem: (k) => (k in lsStore ? lsStore[k] : null),
        setItem: (k, v) => { lsStore[k] = String(v); },
        removeItem: (k) => { delete lsStore[k]; },
    };
    sandbox.__lsStore = lsStore;
    sandbox.__write8 = (a, v) => M.write8(a, v);
    sandbox.setInterval = () => 0;
    sandbox.clearInterval = () => {};
    sandbox.Blob = class { constructor(parts) { this.parts = parts; } };
    sandbox.MutationObserver = class { observe() {} disconnect() {} };
    sandbox.URL = { createObjectURL: () => "blob:sim", revokeObjectURL: () => {} };
    const elems = {};
    const mkEl = (id) => elems[id] || (elems[id] = {
        id, textContent: "", value: "", className: "", innerHTML: "",
        style: {}, scrollTop: 0, scrollHeight: 0, options: [],
        classList: { remove() {} }, appendChild() {},
        querySelector: (s) => mkEl(id + "::" + s),
        addEventListener() {},
    });
    sandbox.__elems = elems;
    sandbox.document = {
        getElementById: mkEl, createElement: () => mkEl("el" + Math.random()),
        querySelector: mkEl("qs"), head: mkEl("head"), body: mkEl("body"),
    };
    sandbox.XMLHttpRequest = class {
        open(m, u) { this.m = m; this.u = u; }
        setRequestHeader() {}
        send(body) {
            const u = this.u;
            // log remoto unificado: POST a http://<host>:8080/log o ruta log/
            if (/\/log\/?$/.test(u) || u.startsWith("log/")) {
                const line = body !== undefined ? String(body) : decodeURIComponent(u.slice(4));
                out.pclog.push(line);
                console.log("  [PS5→PC-LOG] " + line);
                this.status = 200; this.responseText = "";
            } else if (u.startsWith("payloads/") || /\/payloads\//.test(u)) {
                const rel = u.startsWith("payloads/") ? u.slice("payloads/".length)
                    : u.slice(u.indexOf("/payloads/") + "/payloads/".length);
                const f = path.join(PAYLOADS, rel);
                this.status = fs.existsSync(f) ? 200 : 404;
                this.responseText = this.status === 200 ? fs.readFileSync(f, "utf8") : "";
            } else { this.status = 404; this.responseText = ""; }
            if (this.onload) this.onload();
        }
    };
    const ctx = vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(BRIDGE, "utf8"), ctx, { filename: "bridge.js" });
    vm.runInContext(fs.readFileSync(MENU, "utf8"), ctx, { filename: "menu.js" });
    sandbox.__PS5_CTX = makeCtx();
    sandbox.onUserland();
    return sandbox;
}

export function runPayload(name) {
    const src = fs.readFileSync(path.join(PAYLOADS, name), "utf8");
    return src;
}
export function setAioAlive(v) { AIO_ALIVE = !!v; }
export { M };
