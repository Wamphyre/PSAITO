# NOTICE — procedencia del userland base

Este proyecto se publica como **PSAITO** por **wamphyre**. La GUI muestra la
marca PSAITO; la autoria del exploit WebKit subyacente se conserva en
creditos (GUI y este aviso).

Directorio `USERLAND/` basado en el POC publico de **mansoor0x**:
<https://github.com/mansoor0x/POC> (commit `c38fc5670dda8a750381091c4ad808fe9ad60480`, main, 2026).

- El repositorio upstream **no declara licencia** (solo README). Copia para
  **investigacion privada en consola propia**; no redistribuir como propio ni
  empaquetar para terceros.
- Autoria del exploit WebKit (WebKit SSV/type-confusion + primitiva notify):
  mansoor0x. Los unicos offsets/constantes verificados en consola por el autor
  upstream parecen ser los de la familia 11.xx/12.xx (ver notas
  `offline-verified-fw=11.60` en el codigo); el resto es interpolacion.

## Modificaciones nuestras (Jailbreak)

Sobre el baseline anterior (marcadas en el codigo con `Mods Jailbreak` /
fechas 2026-09-11):

- `modules/exploit.js`: arena 0x1000 -> 0x10000; conservar la ventana RW
  (carrier `candidate`, `rwView`) tras el SUCCESS en vez de destruirla;
  handoff `window.__PS5_CTX` + callback `globalThis.onUserland()`.
- `modules/bridge.js` (nuevo): API compatible con el loader Y2JB sobre las
  primitivas del POC — `malloc/free`, `read8/16/32/64`, `write8/16/32/64`,
  `syscall` (ROP propio con gadgets escaneados en libkernel .text), `notify`,
  `get_error_string`, `log`, `SYSCALL`.
- `modules/menu.js` (nuevo): panel de payloads (HTTP same-origin + URL
  arbitraria, `?pb=` configurable), log en pantalla.
- Rebranding GUI a PSAITO (marca wamphyre, credito mansoor0x visible); sw.js de
  rutas relativas para GitHub Pages.
- `exploit.html` / `index.html` / `sw.js`: carga bridge+menu, `pb` param,
  no-cache de `/payloads/` y `/log/`.
- `sim/`: simulador Node del entorno post-handoff (mini-CPU x86 + kernel
  fake ORBIS) para probar bridge y payloads sin consola.
- `payloads/`: copia real de `../DEMO/payloads` (sin symlinks, compatible
  con GitHub Pages).
- Rotacion de perfiles de offsets (`offsets.mjs:profilesFor` + listas
  `gps/cls/ers/gpe/cle/ere/gd/notify` en `exploit.js`): un perfil por
  intento para firmwares interpolados (13.60 prueba `0x334e2xx` y
  `0x33522xx`); la consistencia 3-via del libkernel base rechaza el errado.
