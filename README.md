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
3. Visit the toolkit URL (own GitHub Pages deployment, e.g.
   `<https://<user>.github.io/<repo>/`).
4. Press **Launch** — wait for the runtime panel; the default probe starts
   automatically and prints its results.

Optional URL params:
- `?auto=<file.js>` — auto-run routine (`auto=0` disables; default
  `aio_reach_1320.js`)
- `?pb=<base>` — payload base URL (default same-origin `payloads/`)
- `?logserver=<url>` — remote log endpoint (see **Console log** below)
- `?rop=0` — force bridge **DIRECT** mode (skip libkernel .text gadget scan)
- `?log=0` / `?log=1` — force disable/enable remote log

## Console execution (13.20) — procedure

This section is the operational checklist for a real console run. Two pieces
matter beyond the toolkit itself: a **remote log endpoint** on your PC and the
**offset profile** the exploit will try.

### 0. Publish

The toolkit is a static site; serve the contents of this directory from the
**root** of your GitHub Pages deployment. No PC server is needed for the site
itself (the PS5 loads it over the system browser).

### 1. Remote log (recommended; the on-screen log is lossy)

The exploit and the bridge POST each log line to a `log_server.py` on your PC.
Run it before launching:

```
python DEMO/log_server.py       # listens on 0.0.0.0:8080, prints lines
```

The default endpoint is `http://<page-host>:8080/log`, which resolves to the
PC only if the PC is the DNS/page host. **With GitHub Pages the page host is
`*.github.io`, so you MUST pass your PC IP explicitly**:

```
?logserver=http://<PC-IP>:8080/log
```

The setting propagates from `index.html` to `runtime.html`, or can be set
directly on the runtime URL. Without it, logs still go to screen (`#scr`) and
notifications, but the XHR just 404s silently.

### 2. First run: validate the exploit before payloads

Launch with the canary as the auto-run to confirm the WebKit exploit completes
and the bridge boots:

```
https://<user>.github.io/<repo>/?logserver=http://<PC-IP>:8080/log&auto=hello_1320.js
```

Expected: `runtime.html` shows `*** SUCCESS ***`, the panel appears with
`fw 13.20 · modo ROP` (or `DIRECT`), and the PC log receives
`BRIDGE-BOOT fw=13.20 ...`. `hello_1320.js` then logs `getpid ok = 0x...`.

### 3. Second run: the real payload

Once the canary passes, run with the default (`aio_reach_1320.js`), which
gates the BAGAGWA AIO chain (`RESEARCH/bagagwa-aio-multi-wait-uaf-2026-09-06.md`):

```
https://<user>.github.io/<repo>/?logserver=http://<PC-IP>:8080/log
```

`aio_reach` prints `PASO` lines and a final `VEREDICTO: AIO VIVA` /
`AIO MUERTA (todas ENOSYS/EX)`. **Do not expect an exploit result yet** — this
is the reachability gate; if `AIO MUERTA`, the chain is dead from the Y2JB
sandbox.

### 4. Offset profiles (13.20)

`offsets.mjs` marks 13.20 exact and rotates **two** GOT profiles per attempt:

| profile | gps (getpid slot) | cls (close slot) |
|---|---|---|
| 0 (13.00/13.20 family) | `0x3352238` | `0x3352228` |
| 1 (13.40/13.60 family) | `0x334e238` | `0x334e228` |

The exploit tries profile `(attempt-1) % 2`; the 3-way consistency check of the
libkernel base (getpid/close/error pointing to the same page-aligned base)
rejects the wrong one. If it never passes, watch `KERNEL-BASE` /
`VALIDATION-MISMATCH` lines in the log to see which profile validated.

### 5. ROP vs DIRECT mode

`bridge.js` needs gadgets in libkernel `.text` to run arbitrary `syscall()`.
Two safety nets were added for console:
- A **1-byte probe** of `libkernelBase` before scanning. If the region faults
  (protected post-init), the bridge falls back to **DIRECT** instead of killing
  the process. `PS5.notes` will show `rop-probe-threw:...`.
- `?rop=0` forces DIRECT unconditionally.

With GitHub Pages the page origin is `github.io`, and `exploit.js` disables
remote logging by default in that case. **Always pass `?log=1` together with
`?logserver=...`** so the exploit's own `mark()` lines reach the PC:

```
?log=1&logserver=http://<PC-IP>:8080/log
```

(Bridge/menu logs use `httpLog`, which does not check the origin, so they are
sent regardless.)

## Notes

- Firmware 13.x offsets are interpolated; the toolkit automatically tries
  compatible offset combinations until one validates. A single attempt may
  restart the browser tab — that is expected during testing.
- The Y2JB/exploit startup is flaky: if `SOMETHING WENT WRONG` or a hang
  occurs, close and reopen the app. A hard reset is safe (it does not touch the
  installed backup).
- The on-screen exploit log (`#scr`) is the source of truth in-console; the PC
  log is for offline analysis and survives a crash.

## Credits

- WebKit research baseline: **[mansoor0x](https://github.com/mansoor0x/POC)** — see `NOTICE.md`
- PSAITO (runtime bridge, panel, UI, probes): **Wamphyre**
