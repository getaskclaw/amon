# Changelog

## 0.1.1 — filter signature for persisted connection state

**Fixed.** Persisted connection state could describe a different surface than the run that
loaded it, producing invented events.

Reproduction before the fix: watch with `--conn-loopback` (sidecar records 131 groups, 94 of
them loopback), then restart with the default filters. The loopback groups are "in the seed
but absent from the sweep", so every one of them was reported as closed — measured
`opened=0 closed=58`, 55 of them loopback — for conversations the filtered run could never
have opened.

After the fix, the same scenario measures `closed=2, loopback closed=0`, and the reason is on
record as `meta/conn_seed_rejected {reason: "different or unknown surface"}`.

- `conn-state.json` now stores `{"sig": ..., "rows": {...}}`; the baseline's `conn` section
  gains a `conn_sig` field. `sig` is `v1|loopback=<bool>|pid0=<bool>|families=<sorted list>`.
- A seed is used only when its signature matches the surface this run actually reads. The
  surface is learned from a sweep taken before the seed is considered, because the address
  family set is only knowable that way.
- A mismatch (or an unreadable surface, or a pre-signature file) costs one re-report of what
  currently exists, never a fabricated close.
- Pre-0.1.1 sidecars and baselines are treated as unknown surface: never seeded, same
  one-time cost, and the reason is logged.

Not fixed, and not fixable this way: the signature is not a secret. A file that forges both
the rows *and* the correct signature is still trusted (measured: one ghost `conn_closed`). The
state directory is trusted input — see README limitation 10.

Verified on a real Windows host: the C5 scenario above (before/after), same-surface resume
still suppresses re-reports, legacy sidecar rejected with zero ghost events, legacy baseline
rejected with an explained one-time burst, `--selftest` 12/12, and the lifecycle probe
(v4 non-loopback, loopback, IPv6 `[::1]`) all passing on the new binary.

## 0.1.0 — first public release

Read-only Windows change monitor: file, registry, process, listener and TCP-conversation
surfaces (plus the target's login store, USB volumes and suspend/resume), an append-only
event log with incremental Chinese reports, and pure-logic self-checks runnable from the
shipped binary (`--selftest`).
