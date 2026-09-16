// 2026-09-16 — setlogserver: apunta el log remoto del bridge al PC.
// El runtime Y2JB exponia version_string/NETWORK_LOGGING/checkLogServer como
// globales; el bridge NO (son del loader). Se sustituyen por sus equivalentes:
// LOG_SERVER es el global del bridge y checkLogServer se sondea con un XHR
// directo al endpoint configurado.
// [sim: hang-expected] bucle final de yield para leer el resultado en consola.
(async () => {
    // Cambia esto por tu servidor
    const url = "http://192.168.1.67:8080/log";
    // bridge.js evalua LOG_SERVER una sola vez al arrancar: asignar
    // window.LOG_SERVER despues NO tiene efecto. La API setLogServer()
    // ( añadida al bridge) es la via real de redireccion en runtime.
    try { if (typeof setLogServer === "function") { setLogServer(url); } } catch (e) {}
    try { window.LOG_SERVER = url; } catch (e) {}
    await log("[setlog] log server url = " + url);

    // Sonda del endpoint (equivalente a checkLogServer del runtime Y2JB).
    let reachable = "unknown";
    try {
        const x = new XMLHttpRequest();
        x.open("POST", url, true);
        x.setRequestHeader("Content-Type", "text/plain");
        x.onload = () => { reachable = x.status === 200 ? "ok" : "http" + x.status; };
        x.onerror = () => { reachable = "network"; };
        x.send("psaito-setlog-probe");
    } catch (e) { reachable = "throw:" + e; }

    for (let i = 0; i < 10; ++i) { try { syscall(SYSCALL.sched_yield); } catch (e) {} }
    await log("[setlog] endpoint reachable = " + reachable
        + (reachable === "ok" ? " (logs will arrive)" : " (check firewall/IP)"));
})();