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
By default a **gated chain** runs automatically once the bridge boots:
`hello_1320.js` (canary) → `aio_reach_1320.js` (AIO gate) →
`bagagwa_uaf_1320.js` (the BAGAGWA `aio_multi_wait` mode 0 UAF shot) — each
step only runs if the previous one passed, and the run ends with a
`PSAITO CHAIN RESULT` summary.

## Usage (PS5)

1. On the PS5, set the Internet connection to **manual DNS**:
   - Primary DNS: `62.210.38.117`
   - Secondary DNS: `0.0.0.0`
2. Open the PS5 web browser (guide entry point).
3. Visit the toolkit URL: **<https://wamphyre.github.io/PSAITO/>**
4. Press **Launch** — the panel appears and the **gated chain** runs
   automatically: `hello_1320.js` (canary) → `aio_reach_1320.js` (AIO gate)
   → `bagagwa_uaf_1320.js` (BAGAGWA shot), stopping at the first closed gate
   and ending with a `PSAITO CHAIN RESULT` summary on the panel and the
   remote log.

> **Warning**: the chain's last step **fires the kernel UAF** and can
> hang/panic the console — it only runs if the canary and the AIO gate pass.
> For a non-destructive first check use `?auto=hello_1320.js` (canary only)
> or `?auto=aio_reach_1320.js`. To skip the gates and shoot directly:
> `?auto=bagagwa_uaf_1320.js` (destructive).

Optional URL params (all of them propagate from `index.html` to `runtime.html`):
append them to <https://wamphyre.github.io/PSAITO/>, e.g.
`https://wamphyre.github.io/PSAITO/?max=3&rd=3000&auto=hello_1320.js`.
- `?auto=<file.js>` — auto-run a single routine; **default (no param) is
  `chain`**: the gated sequence canary → AIO gate → BAGAGWA shot that stops
  at the first closed gate and prints a `PSAITO CHAIN RESULT` summary;
  `?auto=0` disables all auto-run
- `?pb=<base>` — payload base URL (default same-origin `payloads/`)
- `?logserver=<url>` — remote log endpoint (see **Console log** below)
- `?rop=0` — force bridge **DIRECT** mode (skip libkernel .text gadget scan)
- `?notify=0` — disable **all** notifications (bridge boot + payloads). If
  the `nt` offset is wrong on your firmware the native call can kill the
  process; with this flag the bridge, panel and remote log keep working.
- `?log=0` / `?log=1` — force disable/enable remote log
- `?max=<n>` — attempt ceiling (**default 5**; `0` = endless). The exploit
  retries on failure; each attempt reallocates ~100-200 MB, so an endless loop
  saturates WebKit's process memory and the system shows a repeated
  "not enough memory" dialog that hides the on-screen log. Keep the default
  (or lower) while testing.
- `?rd=<ms>` — delay between attempts (default 50 ms)
- `?n=<count>` — drain allocations per attempt (default 512, min 64)
- `?cap=<ms>` / `?gap=<ms>` — capture/compose delays (default 50 ms + gap)
- `?lines=<n>` — `#scr` history kept on screen (default 200)

### On-console log & USB

The bridge **and** the payloads write to the on-screen panel (`#plg`), to the
main runtime log (`#scr`) and to a full in-memory buffer that is not truncated.
The panel is **visible from the start** (state `waiting for bridge…`) and does
not depend on the exploit succeeding, so the log controls stay reachable even
if the exploit loops on memory failures. It exposes `RUN`, `RESET`, `STOP`,
`DOWNLOAD LOG` and `CLEAR`; plus a fixed **DOWNLOAD LOG** button at the bottom
right of the screen (independent of the panel). `STOP` halts the retry loop
and the gated chain without reloading.

- **DOWNLOAD LOG** — downloads the whole buffer as `psaito_log_<timestamp>.txt`
  (via `Blob` + `a[download]`); lands in the console's download area.
- **CLEAR** — clears the buffer.

The buffer is also mirrored to `localStorage`, so it survives a page/app restart
(Y2JB startup may reload the tab). On reopen the previous log is replayed at the
top of the panel. The exploit's own log (`#scr`) is captured into the same
buffer via a MutationObserver.

Both `#scr` and the panel `#plg` keep a long history and scroll independently
(200+ and 1000 lines kept on screen). Scrolling uses **sticky auto-follow**: new
lines only snap to the bottom if you are already at the bottom, so you can
scroll up and read earlier output while the exploit keeps logging.

Writing the log to a **USB drive** is not possible from the browser sandbox:
`payloads/usb_probe_1320.js` probes 24 USB/mount paths (`/mnt/usb*`, `/media`,
`/external`, …) and, without a kernel escape (which this toolkit does not
attempt), the sandbox never exposes them. Run it to confirm on your firmware;
the verdict is printed to the panel.

## Console execution (13.00 → 13.60) — procedure

This section is the operational checklist for a real console run. Two pieces
matter beyond the toolkit itself: a **remote log endpoint** on your PC and
the **offset profile** the exploit will try — check the per-offset
**evidence audit** in section 4 before trusting any offset on a given
firmware.

### 0. Publish

The toolkit is a static site; serve the contents of this directory from the
**root** of your GitHub Pages deployment. No PC server is needed for the site
itself (the PS5 loads it over the system browser).

### 1. Remote log (recommended; the on-screen log is lossy)

The exploit and the bridge POST each log line to a `log_server.py` on your PC.
Run it before launching (no dependencies, Python 3 stdlib only):

```
python3 DEMO/log_server.py      # listens on 0.0.0.0:8080, prints timestamped lines
python3 DEMO/log_server.py 9000 # optional: alternate port
```

Allow inbound TCP 8080 through your PC firewall, and make sure the PC and the
PS5 are on the same LAN.

The default endpoint is `http://<page-host>:8080/log`, which resolves to the
PC only if the PC is the DNS/page host. **With GitHub Pages the page host is
`*.github.io`, so you MUST pass your PC IP explicitly**:

```
?logserver=http://<PC-IP>:8080/log
```

The setting propagates from `index.html` to `runtime.html`, or can be set
directly on the runtime URL. Without it, logs still go to screen (`#scr`) and
notifications, but the XHR just 404s silently. To change the endpoint **after
the bridge booted**, run the `setlogserver.js` payload (it calls the bridge's
`setLogServer()` API — assigning `window.LOG_SERVER` from a payload has no
effect, the bridge reads it once at boot).

### 2. First run: validate the exploit before payloads

The default gated chain already runs the canary as its first step; this URL
runs the canary **alone** (non-destructive) to confirm the WebKit exploit
completes and the bridge boots:

```
https://wamphyre.github.io/PSAITO/?log=1&logserver=http://<PC-IP>:8080/log&auto=hello_1320.js&max=3&rd=3000
```

Expected: `runtime.html` shows `*** SUCCESS ***`, the panel appears with
`fw 13.xx · mode ROP` (or `ROP (X1NON stubs)` / `DIRECT`), and the PC log
receives `BRIDGE-BOOT fw=13.xx ...`. `hello_1320.js` then logs
`getpid ok = 0x...`.

### 3. Second run: the real payload

PSAITO is **two sequential stages**: (1) the WebKit exploit in `exploit.js`
gets the browser-process RW primitive and publishes `window.__PS5_CTX` +
`onUserland()`; (2) the payload runs inside that runtime and uses `syscall()`.
A payload **cannot run before stage 1 succeeds** — `onBridgeReady` (and the
auto-run 1.5 s later) only fires after `*** SUCCESS ***`.

Once the canary passes, the chain proceeds to `bagagwa_uaf_1320.js`, which
fires the BAGAGWA `aio_multi_wait` mode 0 UAF (see 3b). A lighter
alternative to confirm AIO reachability alone is `aio_reach_1320.js`:

```
https://wamphyre.github.io/PSAITO/?log=1&logserver=http://<PC-IP>:8080/log&max=3&rd=3000&auto=aio_reach_1320.js
```

`aio_reach` prints `PASO` lines and a final `VEREDICTO: AIO VIVA` /
`AIO MUERTA (todas ENOSYS/EX)`. If `AIO MUERTA`, the BAGAGWA chain is dead from
the Y2JB sandbox and only the reachability result matters.

### 3b. BAGAGWA UAF (`bagagwa_uaf_1320.js`)

Once AIO is reachable, `bagagwa_uaf_1320.js` **fires** the deterministic
`aio_multi_wait` **mode 0** UAF (`syscall 0x297` / 663): with `num >= 2` it links
the same waiter node onto N request lists, overwriting `node->owner`; cleanup
unlinks it only from the last, so the others keep `req->waiters` pointing to
freed memory. The waker is the write primitive (`[r15+0x20]` 32-bit write,
`[r15]`/`[r15+8]` arbitrary 32-bit decrements, `mtx_lock` on `[r15+0x10]`).

The freed waiter array and the reclaim objects live in the **kernel** zone
128 — userland memory can never observe writes there — so detection is done
exclusively through **kernel-side readback**:

- **727 leak** (`aio_debug_request_info`): the syscall copies kernel pointers
  of each AIO request into a userland buffer (a legitimate kernel read). The
  payload snapshots every request id before the shot and re-reads after the
  wake: changed pointers = the dangling `req->waiters` touched the reclaimed
  zone. In stub mode 727 has no libkernel C stub, so the bridge calls it
  through the **raw path**: `pop rax` + arg pops from the X1NON WebKit gadget
  map plus a `syscall; ret` and `pop r10; ret` scanned in WebKit `.text`
  (badge note `wk-raw-syscall@...`, global `SYSCALL_RAW`). Without raw, the
  payload disables this channel and keeps the osem probe.
- **osem probe**: the `osem_create` x4 reclaim lands kernel structs in the
  freed zone; their semaphore state is readable via `osem_post`/`osem_trywait`
  (0x22B/0x22A). Each reclaimed osem is probed before and after the wake and
  compared against a **control osem created before the shot** (which can
  never overlap the freed zone) — a divergence only in the reclaimed set is
  the effect. The userland blocks (decTargets, arena witnesses, name strings)
  remain as tripwires only; `osem_name` is `strlcpy`'d into the kernel, so
  re-reading it in userland proves nothing.

It still does **not** implement the osem→privilege conversion — that is only
meaningful once the kernel-side witness confirms the effect.

AIO requests are created against a **pending-read fd**: a `socketpair`
(`syscall 53`, stub available) whose empty end is the read target — `fd 0`
does not exist in the browser sandbox, and a completed read would leave no
live waiters. In stub mode the payload pre-checks that every stub it needs
exists and aborts cleanly otherwise.

**Destructive**: phase 3 can hang or panic the console. Run with a single
attempt and read the `VERDICT` line.

```
https://wamphyre.github.io/PSAITO/?log=1&logserver=http://<PC-IP>:8080/log&auto=bagagwa_uaf_1320.js&max=1
```

Possible verdicts: `PRIMITIVE HIT` (a userland tripwire was hit — the
kernel followed a process pointer), `KERNEL EFFECT (osem probe)` (a
reclaimed osem diverged from the control probe after the wake),
`KERNEL EFFECT (727 leak)` (the request's kernel pointers changed across
the wake), `NOISE` (the control osem also drifted — probe unreliable), or
`NO OBSERVABLE EFFECT` (latent/invisible UAF, with per-channel status).

### 3c. Reading the `PSAITO CHAIN RESULT`

The default chain ends with a summary block on the panel and the remote log
(the stage-3 line embeds the payload's own `VERDICT`):

    PSAITO CHAIN RESULT:
      stage 1 userland ..... OK
      stage 2 sandbox AIO ... VIVA
      stage 3 kernel UAF ... [bagagwa] VERDICT: KERNEL EFFECT (osem probe) ...

| summary | meaning | next step |
|---|---|---|
| stage 1 FAILED | bridge did not answer `getpid` (badge `DIRECT` = no syscalls this boot) | read `#scr`: offset profile rejected, or SSV patched on this fw |
| stage 2 … MUERTA (SAR veto) | AIO syscalls unreachable from the browser sandbox | hardware answer: BAGAGWA cannot fire from this entry point |
| stage 3 … KERNEL EFFECT | the waker touched the reclaimed zone — the UAF is real on this kernel | kernel-side witness confirmed; osem→privilege conversion becomes meaningful |
| stage 3 … NO OBSERVABLE EFFECT | the harness fired but no channel moved | reclaim/waker hypothesis wrong — iterate the research notes |
| stage 3 … PRIMITIVE HIT | stronger than expected: the kernel followed a process pointer | re-examine the tripwires before repeating |
| chain stopped at stage N, no verdict | payload hung or panicked the console | read the last visible line + the PC log |

Every outcome is a real answer from the hardware — including the negative
ones: a closed gate means that link of the chain is dead on that firmware,
and no code change can revive it from the browser.

### 4. Offset profiles (13.XX) — evidence audit

Per-offset evidence, audited programmatically against the raw X1NON files
(`offsets/13.XX/`) — do not trust the old blanket "verified" claim:

| group | value | evidence |
|---|---|---|
| `hc` host-ctor candidates | `0x56a58/0x56ca0/0x57ce8` | exact match in all four X1NON files |
| `gpe` getpid export | `0x1b860` | equals X1NON `syscall_map[0x14]` in all four files |
| GOT family split | `0x3352xxx` vs `0x334exxx` | consistent with X1NON `__stack_chk_guard_import` (0x3352198 / 0x334e198) |
| `wk_gadgetmap` + `syscall_map` (331 stubs) | — | identical across 13.00→13.60 |
| `gd` 0x1d6fa, `nt` 0x48b0, `cle` 0x274e0, `ere` 0xf7d0, `gps/cls/ers` 0x334exx | — | documented in the **13.60** X1NON header (the exploit's query-string values); extended to 13.00–13.40 by family identity |
| exact `gps/cls/ers` slots for **13.00/13.20** (`0x33522xx`) | — | family region confirmed only — exact slots interpolated (rejected by the 3-way check if wrong) |

Note on `cle`: X1NON's `syscall_map[0x6] = 0x1C310` is the **raw syscall
stub** (`__sys_close`-style, in the 0x1AE10–0x1D8D0 stub band), while
`cle 0x274e0` is the **exported libc symbol** the WebKit GOT resolves to.
Both are correct; they are different symbols.

Consequences for a real run:
- A wrong exact GOT slot (13.00/13.20) is rejected by the 3-way check — the
  exploit retries and burns attempts; watch `KERNEL-BASE` /
  `VALIDATION-MISMATCH` lines.
- A wrong `nt` only affects the **bridge** notification (the exploit's
  SUCCESS proof uses its own collator call, not `nt`). Telemetry now goes out
  **before** the boot notification and `?notify=0` disables it entirely.

`offsets.mjs` still rotates two GOT profiles per attempt as a safety net:

| profile | gps (getpid slot) | cls (close slot) | firmware family |
|---|---|---|---|
| 0 (13.00/13.20) | `0x3352238` | `0x3352228` | 13.00/13.20 tries this first |
| 1 (13.40/13.60) | `0x334e238` | `0x334e228` | 13.40/13.60 tries this first |

The exploit tries its **own family first** (`profilesFor` puts the firmware's
own entry at index 0), then rotates `(attempt-1) % 2`; the 3-way consistency
check of the libkernel base (getpid/close/error pointing to the same
page-aligned base) rejects the wrong one. If it never passes, watch
`KERNEL-BASE` / `VALIDATION-MISMATCH` lines in the log to see which profile
validated.

### 5. ROP vs DIRECT mode

`bridge.js` needs gadgets in libkernel `.text` to run arbitrary `syscall()`.
Two safety nets were added for console:
- A **1-byte probe** of `libkernelBase` before scanning. If the region faults
  (protected post-init), the bridge falls back to **DIRECT** instead of killing
  the process. `PS5.notes` will show `rop-probe-threw:...`.
- `?rop=0` forces DIRECT unconditionally.

Additionally, if the exploit publishes an out-of-band `libkernelBase` (the
common 13.x symptom when interpolated GOT offsets fail the 3-way check), the
bridge now logs the per-import candidates (`kbase-candidates: getpid=...,close=...`)
and **recovers** from whichever candidate lies in band and is page-aligned
(`kbase-recovered-from:getpid`), so a single wrong offset no longer forces
DIRECT. If none is valid, the panel shows a `DIAG DIRECT MODE` block with the
raw `webkitBase` / `libkernelBase` values and the reason.

**X1NON 13.XX fallback (`modules/offsets13x.js`)**: verified offsets from
[X1NON-PSJB](https://github.com/X1NONs/X1NON-PSJB) (raw files under
`offsets/13.XX/`, generator `sim/gen-offsets13x.mjs`). If the libkernel
gadget scan fails, the bridge switches to **stub mode**: ROP gadgets are taken
from the X1NON `wk_gadgetmap` (validated byte-by-byte inside WebKit, which is
readable), each syscall is executed by jumping to its **libkernel C stub**
(`syscall_map` — execution only, libkernel is never read), and `pivot`/`save`
are located by a targeted scan of WebKit `.text`. The badge then shows
`mode ROP (X1NON stubs)` and `SYSCALL_STUBS` is exposed to payloads. This is
what makes `syscall()` (and therefore BAGAGWA) available even when libkernel
`.text` cannot be read. Syscalls **without** a C stub (e.g. 727/0x2D7, which
has no libkernel wrapper at all) go through the **raw path**: the bridge also
scans WebKit `.text` for `syscall; ret` + `pop r10; ret` and builds the
classic `pop rax`+args+`syscall` chain; when both are found `SYSCALL_RAW` is
exposed (log note `wk-raw-syscall@...`). Without them, stub mode still works
for stubbed syscalls and `syscall(727)` throws a clear `no-stub-in-table`.

When DIRECT, `syscall()` throws and syscall-based payloads (BAGAGWA, AIO) cannot
fire — only `notify`/`nativeCall` probes work.

With GitHub Pages the page origin is `github.io`, and `exploit.js` disables
remote logging by default in that case. **Always pass `?log=1` together with
`?logserver=...`** so the exploit's own `mark()` lines reach the PC:

```
?log=1&logserver=http://<PC-IP>:8080/log
```

(Bridge/menu logs use `httpLog`, which does not check the origin, so they are
sent regardless.)

## Development (simulator & tests)

The `sim/` directory simulates the post-handoff environment (bridge and
payloads — the WebKit exploit itself is not simulated): a mini-x86 CPU
executes the real ROP chains and a fake ORBIS kernel implements the
AIO/osem/727 ABI with configurable behavior (`setAioAlive`, `setUafEffect`).
The gated chain is covered end-to-end: an AIO-alive run reaches the kernel
verdict, an AIO-dead run closes at the gate **without firing the shot**.

```
npm test                          # sim/run.mjs (36 checks) + payload smoke
node sim/run.mjs                  # bridge + chain behavior checks
node sim/smoke.mjs --timeout=1500 --quiet   # API-compat smoke over all payloads
```

- Payloads that intentionally end in a notification/yield loop (console UX
  so the verdict stays readable) carry a `// sim: hang-expected` header;
  the smoke reports them as `HANG*` and they do not fail the run
  (`--strict` makes them fail).
- `sim/fakeps5.mjs` exports `bootSim({ search, chainDelayMs, chainStepMs })`
  so tests can run the chain fast; on console the chain uses 1500/4000 ms.
- The smoke isolates every payload (sandbox timers are tracked and cleared),
  captures async rejections (a late `ReferenceError` is an `APIGAP`, not a
  silent OK), and exits non-zero only on real failures.

## Notes

- 13.XX offsets: see the **evidence audit** in section 4 — `hc`/`gpe`/stub
  tables are dump-verified; `gd`/`nt`/`cle`/`ere` come from the X1NON 13.60
  header extended by family identity; the exact 13.00/13.20 GOT slots remain
  interpolated (the 3-way check rejects them if wrong). What remains
  unverified per-firmware is whether the WebKit SSV bug survived patching and
  whether the sandbox still reaches the AIO syscalls — the payload verdicts
  answer both. A single attempt may restart the browser tab — that is expected
  during testing.
- The site uses a service worker (`psaito-v4`). After a repo update, give
  Pages 1-2 minutes and reload; the SW self-updates on navigation. Payloads
  and logs are never cached.
- The Y2JB/exploit startup is flaky: if `SOMETHING WENT WRONG` or a hang
  occurs, close and reopen the app. A hard reset is safe (it does not touch the
  installed backup).
- The on-screen exploit log (`#scr`) is the source of truth in-console; the PC
  log is for offline analysis and survives a crash.

## Credits

- WebKit research baseline: **[mansoor0x](https://github.com/mansoor0x/POC)** — see `NOTICE.md`
- PSAITO (runtime bridge, panel, UI, probes): **Wamphyre**
- 13.XX offset tables (gadgets + syscall stubs): **[X1NONs/X1NON-PSJB](https://github.com/X1NONs/X1NON-PSJB)**
