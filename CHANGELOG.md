# Changelog

## 0.1.3 — packaging fix (the release tag is the first with a green build)

**No behaviour change.** The `Cargo.lock` in the 0.1.1 and 0.1.2 commits was left at the old
version while `Cargo.toml` moved on, so CI — which builds with `--locked` — failed on those
two commits (`cannot update the lock file ... because --locked was passed`). The lock is
regenerated here; `cargo build --release --locked` passes on Windows and on the cross target.

Lesson recorded in the repo so it does not recur: a version bump must be followed by a
`--locked` build locally, because a warm `cargo build` can satisfy the build cache without
rewriting the lockfile. The workflow now also builds `v*` tags — a tag whose own CI never ran
is how the stale lockfile reached v0.1.1 and v0.1.2 unnoticed.

### v0.1.1 and v0.1.2 are retagged

Both tags now point at commits that build with `--locked` (previously their CI failed on the
lockfile and, because the workflow had no tag trigger, nothing would have caught it):

- content is that release's own source; the only differences from the original commits are
  `Cargo.lock`'s version line and the workflow's `v*` tag trigger (verified: `2 files
  changed, 4 insertions(+), 1 deletion(-)`);
- each was verified locally with `cargo build --release --locked --target
  x86_64-pc-windows-gnu`, and each now has its own green CI run on the tag push;
- procedure, for the record: `scripts/retag-release-lockfix.sh <original-commit> <tag>
  <version>`.

## 0.1.2 — observability cleanups from round 4 (two independent SHIPs)

Three non-blockers that both reviewers found independently, plus two documented trade-offs.
No change to what the tool reports; only to how it explains itself.

- `conn_seed_rejected` now names the sidecar outcome precisely and carries the real group
  count: `different surface` (parseable, wrong surface — was `groups: 0` and merged with the
  legacy case), `legacy or corrupt file` (parseable JSON that is not our shape, e.g. a
  pre-signature map), `unreadable or corrupt` (present but not JSON), and `surface unknown`
  (first sweep incomplete). A *missing* file still logs nothing.
- `--conn-sec 0` no longer runs the pre-seed sweep or writes a resume line: with the surface
  off there is nothing to seed and nothing to diff, so it says nothing instead of announcing
  a surface that never runs. The sidecar is not written (verified).
- README limitations 14/15 record the address-family asymmetry (an IPv6-only host gets no
  conversation coverage; a transient IPv6-unsupported answer is read as "no IPv6", which can
  close v6 groups).

Measured after the change (real Windows host): legacy map with 2 groups → `legacy or corrupt
file, groups: 2`; truncated non-JSON → `unreadable or corrupt`; fresh root → no line;
`--conn-sec 0` → no meta line, no sidecar, zero conversation events; same-surface restart →
`conn_state_resumed source:sidecar` with no re-reports.

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
