# PSAITO

> **Experimental research project for educational and research purposes
> only.** Use exclusively on hardware you own and control. No warranty of
> any kind; you are responsible for how you use it. This project does not
> enable piracy or access to content you are not entitled to.

PSAITO is an experimental WebKit research toolkit for PlayStation 5 system
software **09.00 → 13.60**, created by **Wamphyre** as a study of browser
engine memory management. It demonstrates how far a purely web-based
runtime environment can be characterized and instrumented for analysis.

After the demonstration completes, PSAITO provides a small JavaScript
runtime API (`malloc`, `read/write`, `syscall`, notifications) plus an
on-screen payload panel, so analysis routines (`.js` probes) can be loaded
and executed directly from GitHub — no PC, cables or extra tooling needed.
The default routine is `aio_reach_1320.js`, a kernel-interface availability
probe; other probes can be selected from the panel.

## Usage (PS5)

1. On the PS5, set the Internet connection to **manual DNS**:
   - Primary DNS: `62.210.38.117`
   - Secondary DNS: `0.0.0.0`
2. Open the PS5 web browser (guide entry point).
3. Visit: **<https://wamphyre.github.io/PSAITO/>**
4. Press **Launch** — wait for the runtime panel; the default probe starts
   automatically and prints its results.

Optional URL params: `?auto=<file.js>` default routine (`auto=0` disables),
`?pb=<base>` payload base URL.

## Notes

- Firmware 13.x offsets are interpolated; the toolkit automatically tries
  compatible offset combinations until one validates. A single attempt may
  restart the browser tab — that is expected during testing.

## Credits

- WebKit research baseline: **[mansoor0x](https://github.com/mansoor0x/POC)** — see `NOTICE.md`
- PSAITO (runtime bridge, panel, UI, probes): **Wamphyre**
