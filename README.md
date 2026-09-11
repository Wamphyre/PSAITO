# PSAITO — PS5 WebKit userland + puente de payloads

by **wamphyre** · GUI y puente payload-bridge PSAITO · exploit WebKit base: POC publico de **mansoor0x** (ver `NOTICE.md`).
Repo: https://github.com/Wamphyre/PSAITO

Userland para PS5 09.00–13.60. Sobre el POC original de mansoor0x anadimos: **conservar las primitivas
tras el SUCCESS**, un **bridge** que expone la misma API que el loader de Y2JB
y un **menu de payloads** servido por HTTP — los `.js` de `DEMO/payloads/`
corren sin pasarlos por el puerto TCP remoto.

```
exploit.js (bug WebKit, sin tocar la logica)
   |  SUCCESS -> handoff (RW + llamada nativa natural + arena + bases)
bridge.js  -> malloc/syscall/read*/write*/notify/get_error_string/log
menu.js    -> lista + URL + RUN (fetch same-origin, eval en el mismo realm)
   |
payloads/x.js  (aio_reach_1320.js, osem_*, ...) SIN reescribir
```

## Servir

Todo usa rutas relativas: vale servir la carpeta raiz en LAN o subirla como raíz de un repo GitHub Pages (https://wamphyre.github.io/PSAITO/). Sirve por HTTP desde el PC (misma red que la PS5). `payloads/`
es una carpeta REAL con copia de `DEMO/payloads/` (sin symlinks: funciona
tambien en GitHub Pages). Si editas los .js, mantén la copia sincronizada.

PS5 (FW soportado, navegador): `http://PC_IP:PUERTO/` → boton Launch. En
firmwares interpolados (p.ej. **13.60**) la UI lanza el exploit rotando
automaticamente los perfiles de offsets de la familia (GOT `0x334e2xx` ↔
`0x33522xx` en la serie 13.x, un perfil por intento; el log marca
`PROFILE idx=i/N`). Se puede forzar uno: `exploit.html?go=1&fw=13.60&gps=...&gpe=...`
con listas comas si se pasa a mano (offsets en `modules/offsets.mjs`).

Parametros: `go=1` armar; `pb=BASE` base de payloads (def. `payloads/`);
`auto=ARCHIVO.js` payload auto-ejecutado al estar el bridge listo (def.
`aio_reach_1320.js`; `auto=0` desactiva; RESET lo cancela si pulsas antes);
`log=0/1` XHR `log/<linea>` (tu `log_server.py` lo recoge igual que antes);
`cap/gap/rd/n/...` igual que upstream.

## Bridge: que da cada primitiva

- `syscall(n, a1..a6)`: ROP dentro del renderer — pivote `mov rsp,rdi` a la
  arena + `pop rax/rdi/rsi/rdx/r10/r8/r9` + `syscall;ret` + store del rax +
  `pop rsp` al rsp real de ICU (guardado con `mov [rdi],rsp` en una primera
  llamada) + `ret` → **reentra al motor sin corromper nada**. Convencion
  identica a Y2JB: error = `-1n` + errno en `get_error_string()`.
- Gadget-finder en runtime: escanea libkernel .text (`base+0..0x44000`)
  buscando los patrones exactos; si falta alguno, el menu marca modo DIRECT y
  `syscall()` lanza excepcion clara (el payload la reporta como EX).
- `malloc/free`: bump allocator en la arena del exploit (0x2000..0x8000,
  ~24 KB). `free` es no-op.
- `send_notification`: reutiliza la prueba notify original re-arma
  ndo el UCollator falso en cada llamada (retorna booleano).
- `log(msg)`: consola + XHR `log/` + panel.

## Limitaciones conocidas (v1)

- La **estabilidad del grooming** depende del fw: el POC upstream estaba
  verificado por su autor sobre todo en 11.xx/12.xx; en 13.20 el bucle
  auto-retry hace el trabajo (el registro `log/` lo muestra).
- `syscall` ROP asume que dos llamadas `compareFn` consecutivas ocurren al
  misma profundidad de pila (el rsp lo guarda el save-gadget en cada llamada).
- Modo DIRECT no puede ejecutar syscalls con args numericos: sin gadgets no
  hay forma de fijar rax. Notificar sigue operativa.
- `ARENA_BYTES=0x10000` (era 0x1000): si bajase la tasa de exito del grooming
  en tu firmware, vuelve a 0x1000 y reduce `heapEnd`.

## Simulacion local (sin consola)

```
node sim/run.mjs
```

Simula **desde el handoff hacia abajo** (el bug de WebKit no se simula):
memoria paginada, libkernel fake con gadgets reales, mini-CPU x86 que ejecuta
bytecode de las cadenas ROP del bridge, kernel fake ORBIS (socket/connect/
write/close/getpid + familia AIO 0x29x y DEBUG 0x2D7 con conmutador
vivo/muerto) y el canal `log/`+TCP impreso. Carga `modules/bridge.js` real y
los payloads reales de `DEMO/payloads/`. Estado actual: **10/10 OK** y sirvio
para cazar 3 bugs reales (pack 64-bit, TypeError en `aio_reach` PASO 5, y
convencion -1+errno vs -errno crudo).

## Estatus en consola

PENDIENTE de revalidar en la PS5: el POC base ya funcionaba (notify); tras
nuestras mods lo critico es que el handoff conserve la ventana RW. Si ves
`NOTIFY-NATIVE-CALL-PASS` seguido de `BRIDGE-BOOT ... mode=ROP` en tu
`log_server.py`, la cadena esta viva; si el menu sale en `mode=DIRECT`, copia
la linea `rop-missing:` del log para ajustar patrones al libkernel de 13.20.
