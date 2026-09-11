# PSAITO

PS5 WebKit userland entry point with an integrated payload bridge and menu,
by **Wamphyre**. Firmware support: **09.00 → 13.60** (offsets auto-selected;
on interpolated firmware the exploit auto-rotates offset profiles until the
3-way libkernel-base check validates).

Once the exploit lands, the bridge exposes a Y2JB-loader-compatible API
(`malloc`, `read/write`, `syscall`, `notify`, ...) and the payload panel runs
`.js` payloads straight from GitHub — no TCP loader, no PC needed.
`aio_reach_1320.js` (AIO gating probe) is auto-executed by default; pick any
other payload from the on-screen menu.

## Usage (PS5)

1. On the PS5, set the Internet connection to **manual DNS**:
   - Primary DNS: `62.210.38.117`
   - Secondary DNS: `0.0.0.0`
2. Open the PS5 web browser (guide entry point).
3. Visit: **<https://wamphyre.github.io/PSAITO/>**
4. Press **Launch Userland** — the exploit runs, then the menu appears and
   `aio_reach` starts automatically.

URL params (optional): `?auto=<file.js>` default payload (`auto=0` disables),
`?pb=<base>` payload base URL.

## Credits

- WebKit userland POC: **[mansoor0x](https://github.com/mansoor0x/POC)** — see `NOTICE.md`
- PSAITO (bridge, payload menu, UI, tooling): **Wamphyre**
