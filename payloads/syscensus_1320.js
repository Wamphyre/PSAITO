// syscensus_1320.js — censo de syscalls del sandbox (SAR map).
// Plan-B generator: si AIO sale MUERTA en el fw objetivo, la siguiente
// superficie de ataque sale de este mapa, no de la improvisacion. No
// destructivo por construccion: args nulos -> EFAULT/EINVAL en el kernel
// sano; lista VETO para numeros fatales de proceso/hilo/sistema.
// Un hang significaria un syscall bloqueante: la ultima linea de progreso
// delata el numero -> reanudar con ?cenfrom=<n+1>.
// Clases: RET (devolvio valor), ANS (errno), CAP (ENOTCAPABLE=93: existe
// pero vetado por SAR — dato de oro), CAPMODE (94), ENOSYS (78: no existe),
// EX (excepcion JS). Tabla cruzada contra los 331 stubs X1NON 13.60: si
// hay stub pero responde ENOSYS/CAP -> existe en libkernel y el veto es
// del SAR; responde sin stub -> vivo no documentado (interesante).
// NO invoca nada de BAGAGWA: el modo-0 valido exige puntero+num>=2 y aqui
// todo va con ceros (aio_multi_wait(0,0,0,0,0) -> error temprano).
(() => {
    const B = (x) => BigInt(x);
    const I = (x) => BigInt.asIntN(64, x);
    const say = (s) => { try { log("[census] " + s); } catch (e) {} };

    say("begin - syscall census pid=" + I(syscall(SYSCALL.getpid))
        + " fw=" + (PS5.fw || "?") + " mode=" + (PS5.mode || "?"));

    // rango + reanudacion: ?cenfrom/?cento (hooks __CENSUS_* para sim)
    let from = 1, to = 0x3ff;
    const ipar = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) && n > 0 ? n : d; };
    try {
        const q = new URLSearchParams(location.search);
        from = ipar(q.get("cenfrom"), 1); to = ipar(q.get("cento"), 0x3ff);
    } catch (e) {
        try { from = globalThis.__CENSUS_FROM || from; to = globalThis.__CENSUS_TO || to; } catch (e2) {}
    }
    if (to > 0x3ff) to = 0x3ff;

    // VETO: fatales con riesgo aunque sea con args nulos (numeracion FreeBSD-
    // heredada de Orbis: 3=read/4=write confirmados -> 1=exit, 2=fork).
    const VETO = new Set([1, 2, 37, 431, 455]);
    const VETO_WHY = "1=exit? 2=fork? 37=kill 431=thr_exit 455=thr_new";
    say("rango " + from + ".." + to + " | VETO no sondeados: " + VETO_WHY);

    // etiquetas conocidas (mapa SYSN del bridge + familias probeadas)
    const NM = { 3:"read",4:"write",5:"open",6:"close",10:"unlink",15:"chmod",
        20:"getpid",29:"recvfrom",30:"accept",32:"getsockname",37:"kill",
        42:"pipe",54:"ioctl",73:"munmap",74:"mprotect",90:"dup2",92:"fcntl",
        93:"select",95:"fsync",97:"socket",98:"connect",104:"bind",
        105:"setsockopt",106:"listen",118:"getsockopt",125:"netgetiflist",
        128:"rename",133:"sendto",136:"mkdir",137:"rmdir",188:"stat",
        189:"fstat",202:"sysctl",240:"nanosleep",272:"getdents",315:"aio_suspend",
        331:"sched_yield",416:"sigaction",431:"thr_exit",432:"thr_self",
        454:"umtx_op",455:"thr_new",466:"rtprio_thread",477:"mmap",478:"lseek",
        480:"ftruncate",487:"cpuset_getaff",488:"cpuset_setaff",
        533:"jitshm_create",534:"jitshm_alias",549:"osem_create",
        550:"osem_delete",551:"osem_open",552:"osem_close",554:"osem_trywait",
        555:"osem_post",585:"is_in_sandbox",591:"dlsym",594:"dynlib_load_prx",
        595:"dynlib_unload_prx",602:"randomized_path",
        655:"aio_init?",661:"aio_submit",662:"aio_multi_delete",
        663:"aio_multi_wait",664:"aio_multi_poll",665:"aio_get_data",
        666:"aio_multi_cancel",668:"aio_create?",669:"aio_submit_cmd",
        670:"aio_init",688:"aio_multi_lock",727:"aio_debug_req_info" };

    // stubs X1NON 13.60 (referencia: existe wrapper en libkernel_web)
    const STUB = new Set([1,2,3,4,5,6,7,10,12,15,20,23,24,25,27,28,29,30,31,32,33,34,35,36,37,39,41,42,43,44,47,49,50,53,54,55,56,59,65,73,74,75,78,79,80,83,86,89,90,92,93,95,96,97,98,99,100,101,102,104,105,106,113,114,116,117,118,120,121,122,124,125,126,127,128,131,133,134,135,136,137,138,140,141,147,165,182,183,188,189,190,191,192,194,195,196,202,203,204,206,209,232,233,234,235,236,237,238,239,240,241,242,243,247,251,253,272,289,290,310,315,324,325,327,328,329,330,331,332,333,334,340,341,343,345,346,362,363,379,392,393,397,400,401,402,403,404,405,406,407,408,416,417,421,422,423,429,430,431,432,433,441,442,443,444,454,455,456,464,466,475,476,477,478,479,480,481,482,483,486,487,488,499,515,522,532,533,534,535,536,538,539,540,541,542,543,544,545,546,547,548,549,550,551,552,553,554,555,556,557,558,559,560,563,564,565,566,567,572,585,586,587,588,591,592,593,594,595,596,597,598,599,600,601,602,603,604,605,606,607,608,610,611,612,613,615,616,617,618,619,620,622,623,624,625,626,627,628,629,630,632,633,634,635,636,637,638,639,640,641,642,643,646,647,648,649,652,653,654,655,656,657,658,659,660,661,662,663,664,665,666,667,668,669,670,671,672,673,674,675,676,677,678,679,680,681,682,683,684,685,686,687,688,689,690,691,692,693,694,705,713,716,717,718,719,720,721,722,725,732,733]);
    // en stub mode preferir los stubs VIVOS del bridge (incluye el fw real)
    try {
        if (typeof SYSCALL_STUBS !== "undefined" && SYSCALL_STUBS)
            for (const k of Object.keys(SYSCALL_STUBS)) STUB.add(Number(k));
    } catch (e) {}

    const EN = () => { try { const m = /^(\d+)/.exec(get_error_string()); return m ? parseInt(m[1], 10) : -1; } catch (e) { return -1; } };
    const cls = (r, e) => r >= 0n ? "RET" : (e === 78 ? "ENOSYS" : e === 93 ? "CAP" : e === 94 ? "CAPMODE" : "ANS");
    const rows = [];
    let counts = { RET: 0, ANS: 0, CAP: 0, CAPMODE: 0, ENOSYS: 0, EX: 0 };
    let lastLogged = from - 1;
    for (let n = from; n <= to; n++) {
        if (VETO.has(n)) continue;
        let r, e = -1, ex = false;
        try { r = I(syscall(n, 0n, 0n, 0n, 0n, 0n)); if (r < 0n) e = EN(); }
        catch (err) { ex = true; }
        const c = ex ? "EX" : cls(r, e);
        counts[c] = (counts[c] || 0) + 1;
        rows.push({ n, c, e, r: ex ? null : r, stub: STUB.has(n) });
        if (n - lastLogged >= 64) { lastLogged = n; say("progreso: hasta " + n + "/" + to); }
    }

    // tabla cruzada stub x clase (la evidencia SAR vive aqui)
    let xsStubEnosys = 0, xsStubCap = 0, xsStubAns = 0, xsNoStubAns = 0, xsNoStubRet = 0;
    for (const w of rows) {
        if (w.stub && w.c === "ENOSYS") xsStubEnosys++;
        else if (w.stub && (w.c === "CAP" || w.c === "CAPMODE")) xsStubCap++;
        else if (w.stub && (w.c === "ANS" || w.c === "RET")) xsStubAns++;
        else if (!w.stub && w.c === "ANS") xsNoStubAns++;
        else if (!w.stub && w.c === "RET") xsNoStubRet++;
    }
    say("TOTAL probed=" + rows.length + " RET=" + counts.RET + " ANS=" + counts.ANS
        + " CAP=" + counts.CAP + " CAPMODE=" + counts.CAPMODE + " ENOSYS=" + counts.ENOSYS
        + " EX=" + counts.EX);
    say("CROSS stub&ENOSYS=" + xsStubEnosys + " (existe en libkernel, VETO del kernel/SAR — dato de oro)"
        + " | stub&CAP=" + xsStubCap
        + " | stub&ANS/RET=" + xsStubAns + " (documentado y alcanzable)"
        + " | nostub&ANS=" + xsNoStubAns + " + nostub&RET=" + xsNoStubRet + " (vivo no documentado)");

    // los interesantes: todo lo que NO es ENOSYS
    const interesting = rows.filter((w) => w.c !== "ENOSYS");
    say("INTERESANTES (" + interesting.length + "):");
    for (let i = 0; i < interesting.length; i++) {
        const w = interesting[i];
        say("  " + ("" + w.n).padStart(3) + (NM[w.n] ? " " + NM[w.n] : "")
            + " [" + w.c + (w.e > 0 ? " e" + w.e : "") + (w.r !== null && w.c === "RET" ? " ret=0x" + w.r.toString(16) : "")
            + "]" + (w.stub ? " stub" : ""));
    }
    // rangos ENOSYS compactos
    const ranges = [];
    let rs = null, re = null;
    const flush = () => { if (rs !== null) { ranges.push(rs === re ? String(rs) : rs + "-" + re); rs = re = null; } };
    for (const w of rows) {
        if (w.c !== "ENOSYS") { flush(); continue; }
        if (rs === null) rs = re = w.n;
        else if (w.n === re + 1) re = w.n;
        else { flush(); rs = re = w.n; }
    }
    flush();
    say("ENOSYS ranges: " + (ranges.join(",") || "(ninguno)"));
    say("CENSUS VERDICT: superficie viva (no-ENOSYS) = " + interesting.length
        + "/" + rows.length + " | vetados por capacidad (CAP) = " + (counts.CAP + counts.CAPMODE)
        + " | con stub pero vetados = " + xsStubEnosys
        + " -> SI la familia AIO muere, los candidatos plan-B son los ANS/RET sin explorar de esta tabla");
    say("PAYLOAD DONE");
})();
