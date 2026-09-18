# amon — a read-only Windows change monitor

[中文](README.md)

amon watches an untrusted Windows desktop application from the outside: **read-only, no
injection, no modification of the target**. It turns "what did this program change on my
machine, and where did it connect" into an event stream you can filter by source — and it
states its blind spots instead of implying full coverage.

It started from auditing a third-party desktop program's silent behaviour. Windows keeps
no file-level record of what leaves your machine, so after the fact there is nothing to
inspect. amon's answer: cover as much of the observable surface as possible from now on,
and write down plainly what it cannot see.

## Watched surfaces

Only these sources actually emit events:

| Source | Events | Mechanism |
|---|---|---|
| `file` | `dir_changed` `created` `modified` `deleted` | `ReadDirectoryChangesW` plus a periodic SHA-256 re-scan (missed notifications) |
| `reg` | `key_changed` `added` `modified` `removed` | `RegNotifyChangeKeyValue` (user Run/RunOnce/StartupApproved + the HKLM counterparts) |
| `proc` | `started` `exited` | WMI real-time process creation (`Win32_ProcessStartTrace`) + Toolhelp polling; image path and ppid included |
| `net` | `listen_started` `listen_changed` `listen_stopped` | `GetExtendedTcpTable` (listener table, IPv4) |
| `net` | `conn_opened` `conn_closed` | `GetExtendedTcpTable` (full table, IPv4 + IPv6), grouped per `(pid, peer)` |
| `authdb` | `KEY_CHANGED` `key_appeared` | the target's login store (default: Cursor's `state.vscdb`), read via a copy; only key names plus length/short hash, never the plaintext |
| `device` | `volume_event` | `CM_Register_Notification` (USB volume arrival) |
| `power` | `suspended` `resumed` | power broadcast notifications |
| `meta` | `watch_start` `heartbeat` `baseline_*` `conn_*` | coverage and liveness proof — "is the monitor awake, and what is it actually watching" |

> `task` and `svc` exist in the event model (`event.rs`) but **no code emits them yet**.
> That is a known gap, not "supported".

## The TCP conversation surface

This is what the repo added over its earlier listener-only version: from "a port opened"
to "this process is talking to that peer".

- **Grouped, not one row per socket.** The key is `<pid>|<peer>`, so one browser holding
  21 keep-alive sockets to one peer is **one** event with `sockets: 21` in the detail.
  Per-socket reporting turns the log into a haystack with no needle.
- **Remnants are not conversations.** `LISTEN` (the listener surface's job), `CLOSED`,
  `TIME_WAIT` and `DELETE_TCB` are excluded; `FIN_WAIT1/2` and `CLOSE_WAIT` count (a
  half-closed socket can still send).
- **Filters are explicit.** Loopback peers are hidden by default (`--conn-loopback` shows
  them: a local proxy is loud and says nothing about egress). pid 0 is hidden by default
  (`--conn-pid0`). The monitor never reports its own sockets.
- **Only appearance and disappearance are events.** A change in socket count or state
  string is deliberately not reported — that would fire on every poll. The count is still
  in the detail, carried by the next real transition.
- **A failed table read is not an empty table.** An incomplete sweep is **never** diffed
  (otherwise every group it failed to see would be fabricated as `conn_closed`), and the
  transition is logged once as `meta/conn_fetch_incomplete`. An address family the OS
  reports as absent (IPv6 disabled) is a smaller surface, logged once as
  `meta/conn_surface_partial`.
- **Restarts resume.** `conn-state.json` (a sidecar written on change, throttled to 15s)
  plus the `conn` section of `baseline.json`. The seed is chosen by **recency** — the
  sidecar outranks a possibly ancient baseline — and the resume is logged as
  `meta/conn_state_resumed {groups, source}`.

Example event (one JSON line in `events.jsonl`):

```json
{"ts":"2026-09-18T10:53:34+00:00","local":"2026-09-18 18:53:34","src":"net","action":"conn_opened",
 "target":"chrome.exe -> 127.0.0.1:10808",
 "detail":{"pid":33068,"proc":"chrome.exe","remote":"127.0.0.1:10808","sockets":21,
           "states":["ESTABLISHED"],"locals":["127.0.0.1:10164","127.0.0.1:10266"],"localsOmitted":15}}
```

## Quick start

A Rust toolchain is required (native Windows, or cross-compiled from WSL — see below).

```powershell
cargo build --release          # native Windows (MSVC); cross-compiling from WSL below

# 0) verify the logic first: 12 pure-logic checks, non-zero exit on failure
.\target\release\amon.exe --selftest --root D:\amon-state

# 1) baseline: record what already exists, so the first poll does not report it all
.\target\release\amon.exe --baseline --root D:\amon-state

# 2) watch
.\target\release\amon.exe --watch --root D:\amon-state

# 3) incremental report (only events since the last report)
.\target\release\amon.exe --report --root D:\amon-state
```

`--report` writes a Markdown report (`report.md`) in **Chinese**: coverage, high-signal
events, and every new event.

## Command line

| Mode | Description |
|---|---|
| `--baseline` `-b` | capture current state into `baseline.json` |
| `--watch` `-w` | run continuously, append to `events.jsonl` |
| `--report` `-r` | print/collect events added since the last report |
| `--selftest` | write one synthetic event and run the pure-logic assertions |

| Option | Default | Description |
|---|---|---|
| `--root <DIR>` | `%LOCALAPPDATA%\amon` | state directory (the only place amon writes) |
| `--poll <SEC>` | 5 | listener table / slow-snapshot interval |
| `--proc-sec <S>` | 1 | process-creation poll interval |
| `--conn-sec <S>` | 5 | TCP conversation sample interval (`0` = off); **independent of `--poll`** |
| `--conn-loopback` | off | include loopback peers |
| `--conn-pid0` | off | include pid-0 rows |
| `--file-sec <S>` | 60 | file re-hash safety-net interval |
| `--auth-sec <S>` | 60 | login-store check interval |
| `--heartbeat-sec <S>` | 300 | liveness heartbeat interval |
| `--quiet` `-q` | off | suppress informational chatter |

## State directory

Defaults to `%LOCALAPPDATA%\amon`; override with `--root`:

| File | Content |
|---|---|
| `baseline.json` | baseline snapshot (processes / files / registry / listeners / conversations / login-store keys) |
| `events.jsonl` | append-only event stream; rotates to `events.<timestamp>.jsonl` past 32MB |
| `conn-state.json` | connection-surface sidecar for restart resume (atomic write: temp file + rename) |
| `report-cursor.json` | report cursor (how many lines were already reported) |
| `report.md` | the last `--report` output (Chinese) |

## Pointing it at your own target

The default target lives in three places in `Config::load` (`src/main.rs`):

- `install_dirs` — the watched program's directories (file notifications + re-scan)
- `watched_procs` — process-name fragments (process events and the "high signal" filter)
- `auth_db` / `auth_keys` — the login store path and the key names to watch

The shipped defaults are a third-party companion app for Cursor — this tool's original
purpose. Change those three and everything else is reusable. Exposing them as CLI flags is
**not** implemented yet (see below).

## Known limitations (honest list)

1. **Polling cannot see conversations shorter than the interval.** Anything shorter than
   `--conn-sec` may be missed entirely (no open, no close). That is the inherent cost of
   polling, not a configuration problem.
2. **A local-to-local conversation produces two events** (one per socket side).
3. **Changing filters without re-baselining floods**: a default-filter baseline plus
   `--conn-loopback` produced over a hundred events in one poll. The sidecar reduces it to
   the delta, but a filter switch should still be followed by a fresh `--baseline`.
4. **The first run after an upgrade** reports every conversation that exists at that moment
   once; later restarts resume from the sidecar and do not repeat it.
5. **Pids you cannot open** show `proc: "?"` (running as administrator is more complete).
6. **The listener surface is still IPv4-only**; only the conversation surface is v4+v6.
7. **A hard kill can lose up to 15s of sidecar updates**; those conversations are reported
   once on the next start (the throttle window, `CONN_SIDECAR_MIN_SECS`).
8. **The real table-read failure path is untested**: 20k+ table mutations on this machine
   never triggered a `GetExtendedTcpTable` failure, so that branch has code-level
   guarantees only (watch for `meta/conn_fetch_incomplete`).
9. **Files above 32MB are not content-hashed**: the state string becomes
   `sha256=BIG_<size>`, leaving path, exact byte size and mtime. A few-hundred-MB snapshot
   archive is still conspicuous, but it carries no content fingerprint.
10. **The state directory is trusted**: `conn-state.json` under `--root` is validated for
    *shape*, not for truth. Anything that can write there can seed fabricated groups, which
    produces `conn_closed` for keys that never existed and can keep a future `conn_opened`
    from being reported (the seed already "knows" the key). A same-account attacker could
    equally kill the monitor outright, so this is not solvable with crypto — the answer is
    operational: keep `--root` out of the watched program's reach (separate account or ACLs)
    and watch amon itself. Note the filter signature is **not a secret**: it stops accidents
    like a filter change, not a forgery that copies the format (measured: a forged sidecar
    carrying the correct signature is still trusted and yields one ghost close event).
11. **One root, one watcher at a time**: two processes sharing a root both append to
    `events.jsonl` and fight over `conn-state.json`, producing what look like duplicated
    events (observed during review).
12. **A filter change re-reports what exists, once.** Both the sidecar and the baseline's
    `conn` section record a **filter signature** (`v1|loopback=…|pid0=…|families=…`). On a
    mismatch the seed is not used and `meta/conn_seed_rejected` says so; the cost is one
    re-report of the conversations that exist right now. This replaces the earlier behaviour,
    where a `--conn-loopback` seed plus default filters emitted 58 `conn_closed` — 55 of them
    loopback — for conversations this run could never have opened. **That defect is fixed and
    reproduced in tests.** Pre-signature (legacy) sidecars and baselines are never trusted, at
    the same one-time cost.
13. Reports are in Chinese; `task` / `svc` sources do not emit events yet.
14. **Address-family asymmetry**: an unreadable IPv6 table (rc 50/87) degrades gracefully to
    IPv4 only, but *any* IPv4-table error makes the sweep `complete=false` and that run emits
    no conversation events at all (conservative: silence over invention). An IPv6-only host
    therefore has no conversation surface. Separately, a *transient* "IPv6 unsupported"
    answer is treated as "this host has no IPv6", in which case v6 groups are reported as
    closed (not measured; the error cannot be injected here).
15. **`conn_seed_rejected` says why**: `different surface` (the filters changed) /
    `legacy or corrupt file` (pre-signature or junk, with the real group count) /
    `unreadable or corrupt` (unreadable, or not JSON) / `surface unknown` (the first sweep
    was incomplete). A missing file logs nothing — a fresh root should stay quiet.
16. **No daemon mode is provided.** For long-running use, register a scheduled task, e.g.
    (elevated):
    ```powershell
    $a = New-ScheduledTaskAction -Execute 'D:\tools\amon.exe' -Argument '--watch --root D:\amon-state --quiet'
    Register-ScheduledTask -TaskName amon -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) -RunLevel Highest
    ```

## Read-only guarantee

No path in the code opens a watched resource for writing. The registry is opened with
`KEY_READ`, processes with `PROCESS_QUERY_LIMITED_INFORMATION`, and the login store is
**copied before being queried**. The only writes happen under `--root`.

## Verification

- `amon --selftest`: 12 pure-logic assertions (state classification, group identity, IPv6
  endpoint rendering incl. scope id and v4-mapped peers, loopback classification, port byte
  order swapped exactly once), printed one line each, non-zero exit on failure. Fastest path.
- Probe scripts under `scripts/`, run on real Windows, no internet dependency (the peer is
  this machine's own LAN address):
  - `probe-conn-lifecycle.ps1` — v4 non-loopback open/close on both sides, loopback hidden
    by default, visible with `--conn-loopback`, IPv6 `[::1]` open/ESTABLISHED/close,
    multi-socket grouping, listener surface unregressed
  - `probe-conn-cadence.ps1` — with `--conn-sec 2 --poll 30` events must arrive on the 2s
    cadence (this probe caught a real blocker: the connection poll was nested inside the
    `--poll` branch, making the flag a no-op)
  - `probe-conn-resume.ps1` — two watch sessions on one root; sockets held across both must
    **not** be re-reported in the second session
  - `probe-conn-baseline-compat.ps1` — a pre-`conn` `baseline.json` must still load
- The development process included three rounds of independent adversarial review by
  different model families; every round found real defects, all reproduced, fixed and
  re-measured. Record: [VERIFICATION.md](VERIFICATION.md).

## Building

**Native Windows (MSVC)**: `cargo build --release` (Rust + the VC toolchain).

**Cross-compile from WSL/Linux** (`x86_64-pc-windows-gnu`, needs `mingw-w64`):

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# output: target/x86_64-pc-windows-gnu/release/amon.exe
```

`.cargo/config.toml` maps the gnu target's linker/ar and deliberately sets **no** default
target, so a native Windows checkout builds for its own host with a plain `cargo build`.

**Note**: this crate targets Windows APIs and does **not** compile for Linux
(`--target x86_64-unknown-linux-gnu` fails without the `windows` bindings). That is why the
pure-logic assertions run through `--selftest` on Windows, and why CI runs on
`windows-latest`.

## License

MIT — see [LICENSE](LICENSE).
