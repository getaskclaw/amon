//! amon — read-only change monitor for an untrusted Windows companion app.
//!
//! Why native instead of the PowerShell version: `ReadDirectoryChangesW`,
//! `RegNotifyChangeKeyValue` and `CM_Register_Notification` give *kernel-pushed*
//! events, and `CM_Register_Notification` covers USB volume arrival — something the
//! scripted version could only approximate by polling the PnP tree.
//!
//! Read-only guarantee: nothing in this crate opens a watched resource for writing.
//! The auth database is opened for read, copied, then queried.

mod authdb;
mod connlogic;
mod event;
mod power;
mod report;
mod snapshot;
mod watchers;
mod wmi;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap_lite::{Args, Mode};

use event::{Event, EventLog, Source};
use snapshot::Snap;

/// Tiny hand-rolled arg parsing: one fewer dependency, and the surface is trivial.
mod clap_lite {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Mode {
        Baseline,
        Watch,
        Report,
        SelfTest,
    }

    #[derive(Debug, Clone)]
    pub struct Args {
        pub mode: Mode,
        pub root: std::path::PathBuf,
        pub poll_sec: u64,
        pub proc_sec: u64,
        pub conn_sec: u64,
        pub conn_loopback: bool,
        pub conn_pid0: bool,
        pub file_sec: u64,
        pub auth_sec: u64,
        pub heartbeat_sec: u64,
        pub quiet: bool,
    }

    impl Args {
        pub fn parse() -> anyhow::Result<Args> {
            parse_impl()
        }

        /// The connection-snapshot policy these args describe.
        pub fn conn_filter(&self) -> super::snapshot::ConnFilter {
            super::snapshot::ConnFilter {
                include_loopback: self.conn_loopback,
                include_pid0: self.conn_pid0,
                exclude_pid: std::process::id(),
            }
        }
    }

    fn parse_impl() -> anyhow::Result<Args> {
        let mut mode = None;
        let mut root = super::default_root();
        let mut poll_sec = 5u64;
        let mut proc_sec = 1u64;
        let mut conn_sec = 5u64;
        let mut conn_loopback = false;
        let mut conn_pid0 = false;
        let mut file_sec = 60u64;
        let mut auth_sec = 60u64;
        let mut heartbeat_sec = 300u64;
        let mut quiet = false;

        let mut it = std::env::args().skip(1);
        while let Some(a) = it.next() {
            match a.as_str() {
                "--baseline" | "-b" => mode = Some(Mode::Baseline),
                "--watch" | "-w" => mode = Some(Mode::Watch),
                "--report" | "-r" => mode = Some(Mode::Report),
                "--selftest" => mode = Some(Mode::SelfTest),
                "--quiet" | "-q" => quiet = true,
                "--root" => {
                    let v = it.next().unwrap_or_default();
                    root = std::path::PathBuf::from(v);
                }
                "--poll" => {
                    let v = it.next().unwrap_or_default();
                    poll_sec = v.parse().unwrap_or(5);
                }
                "--proc-sec" => {
                    let v = it.next().unwrap_or_default();
                    proc_sec = v.parse().unwrap_or(1);
                }
                "--conn-sec" => {
                    let v = it.next().unwrap_or_default();
                    conn_sec = v.parse().unwrap_or(5);
                }
                "--conn-loopback" => conn_loopback = true,
                "--conn-pid0" => conn_pid0 = true,
                "--file-sec" => {
                    let v = it.next().unwrap_or_default();
                    file_sec = v.parse().unwrap_or(60);
                }
                "--auth-sec" => {
                    let v = it.next().unwrap_or_default();
                    auth_sec = v.parse().unwrap_or(60);
                }
                "--heartbeat-sec" => {
                    let v = it.next().unwrap_or_default();
                    heartbeat_sec = v.parse().unwrap_or(300);
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => {}
            }
        }

        Ok(Args {
            mode: mode.ok_or_else(|| {
                anyhow::anyhow!("specify --baseline | --watch | --report | --selftest")
            })?,
            root,
            poll_sec,
            proc_sec,
            conn_sec,
            conn_loopback,
            conn_pid0,
            file_sec,
            auth_sec,
            heartbeat_sec,
            quiet,
        })
    }

    fn print_help() {
        println!(
            "amon - read-only change monitor\n\n\
             USAGE:\n  amon <MODE> [OPTIONS]\n\n\
             MODES:\n\
             \x20 --baseline     capture current state to baseline.json\n\
             \x20 --watch        run continuously, append changes to events.jsonl\n\
             \x20 --report       print/collect events added since the last report\n\
             \x20 --selftest     write one synthetic event and exit\n\n\
             OPTIONS:\n\
             \x20 --root <DIR>   state directory (default %LOCALAPPDATA%\\amon)\n\
             \x20 --poll <SEC>   listener/slow-snapshot interval (default 5)\n\
             \x20 --proc-sec <S> process-creation poll interval (default 1)\n\
             \x20 --conn-sec <S> TCP-connection poll interval (default 5; 0 = off)\n\
             \x20 --conn-loopback  include loopback peers (default: hidden)\n\
             \x20 --conn-pid0      include pid 0 rows (default: hidden)\n\
             \x20 --file-sec <S> file re-hash safety net (default 60)\n\
             \x20 --auth-sec <S> auth DB check interval (default 60)\n\
             \x20 --heartbeat-sec <S> liveness heartbeat interval (default 300)\n\
             \x20 --quiet        suppress informational chatter\n"
        );
    }
}

/// Minimum seconds between sidecar rewrites while watching. Smaller means a smaller
/// post-restart blind spot and more disk churn; 15s keeps the window short without
/// rewriting a multi-KB file on every tick.
const CONN_SIDECAR_MIN_SECS: u64 = 15;

/// One line explaining why a persisted seed was not used, so a smaller surface or a
/// filter change is visible in the log instead of looking like a fresh start.
fn conn_seed_rejected(log: &mut EventLog, target: &'static str, reason: &'static str, groups: usize) {
    let _ = log.write(
        &Event::new(Source::Meta, "conn_seed_rejected", target)
            .with_detail(serde_json::json!({ "reason": reason, "groups": groups })),
    );
}

/// Sidecar persistence for the connection snapshot.
///
/// `baseline.json` is written once, at start; the connection set moves fast, so
/// re-writing the whole baseline every tick would be wasteful — but never
/// persisting it means a baseline from before the `conn` section existed keeps
/// reporting every current conversation on **every** restart, not just once.
/// A small sidecar fixes exactly that without changing what `baseline.json`
/// means for the other four surfaces.
mod connstate {
    use std::path::Path;

    use crate::snapshot::Snap;

    const FILE: &str = "conn-state.json";

    /// What the persisted rows were produced by.
    ///
    /// The seed exists to suppress re-reporting groups the monitor already knew about, so
    /// it is only valid for the *same* surface: a sidecar written with `--conn-loopback`
    /// describes loopback groups that a default-filter sweep will never contain, and using
    /// it as a seed would report every one of them as closed — an invented observation.
    /// The baseline's `conn` section has exactly the same requirement, which is why the
    /// signature travels with both.
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone, Debug)]
    pub struct Sig(pub String);

    impl Sig {
        pub fn of(f: &crate::snapshot::ConnFilter, families: &[&'static str]) -> Self {
            let mut fams: Vec<&str> = families.to_vec();
            fams.sort_unstable();
            Sig(format!(
                "v1|loopback={}|pid0={}|families={}",
                f.include_loopback,
                f.include_pid0,
                fams.join("+")
            ))
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct File {
        sig: String,
        rows: Snap,
    }

    /// What a load attempt produced, so the caller can say *why* a seed was skipped
    /// instead of silently behaving differently.
    pub enum Loaded {
        Usable(Snap),
        /// Parseable but written under a different surface, or written by a build that
        /// did not record one.
        OtherSurface,
        /// Missing, truncated, or not the shape we write.
        Unusable,
    }

    /// Atomic-ish write: temp file then rename, so a reader never sees a half file.
    pub fn save(root: &Path, sig: &Sig, rows: &Snap) {
        let f = File {
            sig: sig.0.clone(),
            rows: rows.clone(),
        };
        if let Ok(raw) = serde_json::to_string(&f) {
            let tmp = root.join(format!("{FILE}.tmp"));
            if std::fs::write(&tmp, raw).is_ok() {
                let _ = std::fs::rename(&tmp, root.join(FILE));
            }
        }
    }

    /// Load and validate. Entries that are not the shape we write are dropped, so a
    /// half-written file can never manufacture groups that never existed.
    pub fn load(root: &Path, sig: &Sig) -> Loaded {
        let raw = match std::fs::read_to_string(root.join(FILE)) {
            Ok(r) => r,
            Err(_) => return Loaded::Unusable,
        };
        let f: File = match serde_json::from_str(&raw) {
            Ok(f) => f,
            // A pre-signature sidecar is a plain map of key -> value; parseable JSON,
            // but its surface is unknown. Refusing it costs one re-report; trusting it
            // can cost a fabricated close burst.
            Err(_) => return Loaded::OtherSurface,
        };
        if f.sig != sig.0 {
            return Loaded::OtherSurface;
        }
        Loaded::Usable(
            f.rows
                .into_iter()
                .filter(|(k, v)| {
                    k.contains('|')
                        && serde_json::from_str::<serde_json::Value>(v)
                            .map(|j| j.is_object())
                            .unwrap_or(false)
                })
                .collect(),
        )
    }
}

/// Which notification channels reported themselves healthy at startup.
///
/// Tracked so the heartbeat can prove what is actually being watched. Without this,
/// a channel that failed to open looks exactly like a system where nothing happens.
#[derive(Default, Clone)]
struct ChannelStatus {
    dir: bool,
    reg_user: bool,
    device: bool,
    proc: bool,
    proc_how: String,
    power: bool,
}

/// Everything we watch, resolved once.
struct Config {
    root: PathBuf,
    install_dirs: Vec<PathBuf>,
    watched_procs: Vec<String>,
    auth_db: PathBuf,
    auth_keys: Vec<&'static str>,
}

impl Config {
    /// The resolved profile dir (see `resolve_user_profile`), exposed so the registry
    /// code can locate the matching SID.
    pub fn profile_dir() -> PathBuf {
        resolve_user_profile()
    }

    fn load(root: PathBuf) -> Self {
        // Resolve the *interactive user's* profile explicitly. When amon runs as
        // SYSTEM (which is how a scheduled task should run it), %APPDATA% points at
        // SYSTEM's own profile and the HKCU hive is SYSTEM's, so the two highest-signal
        // surfaces — the user's autostart keys and Cursor's login store — would be
        // silently watched in the wrong place.
        let profile = resolve_user_profile();

        let install_dirs = vec![
            PathBuf::from(r"D:\2609\Apps\Cursor 全能辅助"),
            PathBuf::from(r"D:\2609\Apps\Cursor 全景辅助"),
            PathBuf::from(r"D:\2609\Apps\Cursor 全能辅助\native-menu-icons"),
        ];
        Config {
            root,
            install_dirs,
            watched_procs: vec![
                "cursor-helper".into(),
                "cursor-helper-cliproxy".into(),
                "cursor.exe".into(),
                "cursor-agent".into(),
                "cursorsandbox".into(),
            ],
            auth_db: profile.join(r"AppData\Roaming\Cursor\User\globalStorage\state.vscdb"),
            auth_keys: vec![
                "cursorAuth/accessToken",
                "cursorAuth/refreshToken",
                "cursorAuth/cachedEmail",
                "cursorAuth/cachedSignUpType",
                "cursorAuth/stripeMembershipType",
                "glass.lastSignedInAuthId",
                "adminSettings.cachedAuthId",
            ],
        }
    }
}

/// Default state directory: `%LOCALAPPDATA%\amon`, falling back to a relative
/// `amon-state` when the variable is absent (e.g. a service account with no profile).
/// Override with `--root`; the monitor only ever writes here.
fn default_root() -> std::path::PathBuf {
    match std::env::var("LOCALAPPDATA") {
        Ok(p) if !p.trim().is_empty() => std::path::PathBuf::from(p).join("amon"),
        _ => std::path::PathBuf::from("amon-state"),
    }
}

/// The interactive user's profile path, found without depending on %USERPROFILE%
/// (which is SYSTEM's when running as SYSTEM).
///
/// Preference order:
///   1. an explicit override via `CHMON_USER_PROFILE`
///   2. the profile directory that is not SYSTEM / service-account
///   3. fall back to %USERPROFILE%
fn resolve_user_profile() -> PathBuf {
    if let Ok(p) = std::env::var("CHMON_USER_PROFILE") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }

    // Scan for a loaded, real user profile under C:\Users.
    let users = PathBuf::from(r"C:\Users");
    if let Ok(rd) = std::fs::read_dir(&users) {
        let mut candidates: Vec<PathBuf> = Vec::new();
        for ent in rd.flatten() {
            let p = ent.path();
            if !p.is_dir() {
                continue;
            }
            let name = ent.file_name().to_string_lossy().to_ascii_lowercase();
            // Skip the well-known machine accounts and the public profile.
            if matches!(
                name.as_str(),
                "public" | "default" | "default user" | "all users"
            ) {
                continue;
            }
            // A real profile has an NTUSER.DAT.
            if p.join("NTUSER.DAT").exists() {
                candidates.push(p);
            }
        }
        // If exactly one real profile exists, that is unambiguous.
        if candidates.len() == 1 {
            return candidates.remove(0);
        }
        // Otherwise prefer the one that owns a Cursor install.
        for c in &candidates {
            if c.join(r"AppData\Roaming\Cursor\User\globalStorage\state.vscdb")
                .exists()
            {
                return c.clone();
            }
        }
        if let Some(c) = candidates.into_iter().next() {
            return c;
        }
    }

    PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default())
}

/// Persisted snapshot the watcher diffs against.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Baseline {
    proc: Snap,
    file: Snap,
    reg: Snap,
    listener: Snap,
    /// Added after the first baseline.json files shipped, hence `serde(default)`:
    /// an old baseline must still load, or every upgrade re-baselines and loses the
    /// "what changed before I was watching" line.
    #[serde(default)]
    conn: Snap,
    /// The surface `conn` was captured from. Missing on older baselines, and a baseline
    /// captured with other filters is not a valid seed for this run.
    #[serde(default)]
    conn_sig: Option<String>,
    auth: Snap,
}

impl Baseline {
    fn path(root: &std::path::Path) -> PathBuf {
        root.join("baseline.json")
    }
    fn load(root: &std::path::Path) -> Option<Self> {
        let raw = std::fs::read_to_string(Self::path(root)).ok()?;
        serde_json::from_str(&raw).ok()
    }
    fn save(&self, root: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(root)?;
        let raw = serde_json::to_string_pretty(self)?;
        std::fs::write(Self::path(root), raw)?;
        Ok(())
    }
}

fn capture(cfg: &Config, connf: &snapshot::ConnFilter) -> Baseline {
    let t0 = Instant::now();
    // A baseline must be a complete picture or nothing: seeding it from a partial
    // sweep would make the very first diff compare against a view that never was.
    let sweep = snapshot::snapshot_connections(connf);
    let complete = sweep.complete;
    let families = sweep.families.clone();
    let conn = if complete { sweep.rows } else { Snap::new() };
    // Only a complete sweep may define the surface signature: an incomplete one says
    // nothing about which families this host has.
    let sig = if complete {
        Some(connstate::Sig::of(connf, &families).0)
    } else {
        None
    };
    let b = Baseline {
        proc: snapshot::snapshot_processes(),
        file: snapshot::snapshot_files(&cfg.install_dirs).unwrap_or_default(),
        reg: snapshot::snapshot_run_keys(),
        listener: snapshot::snapshot_listeners(),
        conn,
        conn_sig: sig,
        auth: authdb::snapshot(&cfg.auth_db, &cfg.auth_keys, &cfg.root).unwrap_or_default(),
    };
    let _ = t0;
    b
}

fn main() -> Result<()> {
    let args = Args::parse()?;
    std::fs::create_dir_all(&args.root)?;
    let cfg = Config::load(args.root.clone());

    match args.mode {
        Mode::SelfTest => {
            let mut log = EventLog::open(&cfg.root)?;
            log.write(
                &Event::new(Source::Meta, "selftest", "synthetic")
                    .with_detail(serde_json::json!({ "native": true, "pid": std::process::id() })),
            )?;
            log.flush()?;
            println!("selftest event written");

            // The pure rules (state table, group identity, endpoint rendering,
            // loopback classification) are asserted here so they can be checked on
            // the target platform instead of only by reading the code.
            let checks = connlogic::self_checks();
            let failed = checks.iter().filter(|(_, ok, _)| !ok).count();
            for (name, ok, detail) in &checks {
                let tail = if detail.is_empty() {
                    String::new()
                } else {
                    format!(" ({detail})")
                };
                println!("  [{}] {name}{tail}", if *ok { "ok" } else { "FAIL" });
            }
            println!(
                "pure-logic self-checks: {}/{} passed",
                checks.len() - failed,
                checks.len()
            );
            if failed > 0 {
                anyhow::bail!("{failed} pure-logic self-check(s) failed");
            }
        }
        Mode::Baseline => {
            let mut log = EventLog::open(&cfg.root)?;
            log.write(
                &Event::new(Source::Meta, "baseline_start", hostname()).with_detail(
                    serde_json::json!({ "native": true, "root": cfg.root.to_string_lossy() }),
                ),
            )?;
            let b = capture(&cfg, &args.conn_filter());
            b.save(&cfg.root)?;
            log.write(
                &Event::new(Source::Meta, "baseline_done", "baseline.json").with_detail(
                    serde_json::json!({
                        "procs": b.proc.len(),
                        "files": b.file.len(),
                        "reg": b.reg.len(),
                        "listeners": b.listener.len(),
                        "connections": b.conn.len(),
                        "authKeys": b.auth.len(),
                    }),
                ),
            )?;
            log.flush()?;
            println!("baseline written: {}", Baseline::path(&cfg.root).display());
            println!(
                "  procs={} files={} reg={} listeners={} conns={} authKeys={}",
                b.proc.len(),
                b.file.len(),
                b.reg.len(),
                b.listener.len(),
                b.conn.len(),
                b.auth.len()
            );
        }
        Mode::Watch => run_watch(&args, &cfg)?,
        Mode::Report => {
            let n = report::run(&cfg.root)?;
            if n == 0 {
                println!("NO_NEW_EVENTS");
            }
        }
    }
    Ok(())
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
}

fn run_watch(args: &Args, cfg: &Config) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = channel::<Event>();
    let mut log = EventLog::open(&cfg.root)?;

    let baseline = Baseline::load(&cfg.root).unwrap_or_else(|| capture(cfg, &args.conn_filter()));
    baseline.save(&cfg.root)?;

    // ---- event-driven watchers (the reason this is native) ----
    let mut handles = Vec::new();
    for dir in &cfg.install_dirs {
        if dir.exists() {
            handles.push(watchers::spawn_dir_watcher(
                dir.clone(),
                tx.clone(),
                stop.clone(),
            ));
        }
    }
    handles.push(watchers::spawn_reg_watcher(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU_Run",
        true,
        tx.clone(),
        stop.clone(),
    ));
    handles.push(watchers::spawn_reg_watcher(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM_Run",
        false,
        tx.clone(),
        stop.clone(),
    ));
    handles.push(watchers::spawn_device_watcher(tx.clone(), stop.clone()));

    // Suspend/resume: registered last because it is the only channel that can
    // fire during shutdown, and it must not delay the others' setup.
    let power_ok = power::spawn_power_watcher(tx.clone());
    // Real-time process creation. Beats the Toolhelp poll: a process that starts and
    // exits inside one poll tick never appears in a snapshot.
    handles.push(wmi::spawn_wmi_proc_watcher(tx.clone(), stop.clone()));

    // Resolve the SID once, at startup, and report it. If this is null the user's
    // autostart keys cannot be watched, and that must be visible in the log rather
    // than showing up as "nothing ever changes".
    let sid = crate::snapshot::current_user_sid();

    log.write(
        &Event::new(Source::Meta, "watch_start", hostname()).with_detail(serde_json::json!({
            "native": true,
            "pid": std::process::id(),
            "poll": args.poll_sec,
            "procSec": args.proc_sec,
            "connSec": args.conn_sec,
            "connLoopback": args.conn_loopback,
            "connPid0": args.conn_pid0,
            "fileSec": args.file_sec,
            "authSec": args.auth_sec,
            "sid": sid,
            "sidResolved": sid.is_some(),
            "userProfile": Config::profile_dir().to_string_lossy(),
            "authDbExists": Config::profile_dir()
                .join(r"AppData\Roaming\Cursor\User\globalStorage\state.vscdb")
                .exists(),
            "watchedProcs": cfg.watched_procs,
            "powerChannel": power_ok,
            "sidDiag": crate::snapshot::sid_diagnostics(),
        })),
    )?;
    log.flush()?;

    // Heartbeat: prove liveness on a fixed cadence so that "no events" can be
    // distinguished from "the monitor is wedged or its channels are dead".
    // Carries the channel status, not just a timestamp.
    let mut next_heartbeat = Instant::now() + Duration::from_secs(args.heartbeat_sec);
    let started = Instant::now();
    let mut channel_ok = ChannelStatus::default();

    let mut prev = baseline;

    // Learn this run's surface *before* deciding whether any persisted seed may be
    // trusted. The address-family set is only knowable from a sweep, and a seed written
    // for a different surface is a source of invented closes, not of continuity:
    // a loopback-inclusive seed plus default filters emitted 58 conn_closed — 55 of them
    // loopback — for conversations this run could never have opened (reviewed defect).
    let probe = snapshot::snapshot_connections(&args.conn_filter());
    let surface = if probe.complete {
        Some(connstate::Sig::of(&args.conn_filter(), &probe.families))
    } else {
        None
    };

    let mut base_seed: Option<Snap> = None;
    if !prev.conn.is_empty() {
        let usable = matches!((&surface, &prev.conn_sig), (Some(s), Some(b)) if s.0 == *b);
        if usable {
            base_seed = Some(std::mem::take(&mut prev.conn));
        } else {
            let n = prev.conn.len();
            prev.conn = Snap::new();
            conn_seed_rejected(&mut log, "baseline.json", "different or unknown surface", n);
        }
    }

    let (source, rows) = match &surface {
        None => {
            // Nothing can be validated against an unreadable surface; start clean and say so.
            conn_seed_rejected(
                &mut log,
                "conn-state.json",
                "surface unknown (incomplete first sweep)",
                0,
            );
            ("none", Snap::new())
        }
        Some(sig) => match (connstate::load(&cfg.root, sig), base_seed) {
            (connstate::Loaded::Usable(rows), _) if !rows.is_empty() => ("sidecar", rows),
            (connstate::Loaded::Usable(_), Some(seed)) => ("baseline", seed),
            (connstate::Loaded::Usable(_), None) => ("none", Snap::new()),
            (connstate::Loaded::Unusable, Some(seed)) => ("baseline", seed),
            (connstate::Loaded::Unusable, None) => ("none", Snap::new()),
            (connstate::Loaded::OtherSurface, seed) => {
                conn_seed_rejected(
                    &mut log,
                    "conn-state.json",
                    "unusable or different surface",
                    0,
                );
                match seed {
                    Some(seed) => ("baseline", seed),
                    None => ("none", Snap::new()),
                }
            }
        },
    };
    if !rows.is_empty() {
        let n = rows.len();
        prev.conn = rows;
        let _ = log.write(
            &Event::new(Source::Meta, "conn_state_resumed", "conn-state.json")
                .with_detail(serde_json::json!({ "groups": n, "source": source })),
        );
    }
    let mut next_proc = Instant::now();
    let mut next_poll = Instant::now();
    let mut next_conn = Instant::now();
    let mut next_file = Instant::now() + Duration::from_secs(args.file_sec);
    let mut next_auth = Instant::now() + Duration::from_secs(args.auth_sec);
    // A directory-changed notification means "re-hash soon", but coalesce bursts.
    let mut pending_file_rescan: Option<Instant> = None;
    // Connection-surface bookkeeping: log a partial/unreadable surface once per
    // state change (not per poll), and keep the sidecar near-live, throttled.
    let mut conn_incomplete = false;
    let mut conn_note_logged = false;
    let mut conn_saved: Option<Snap> = None;
    let mut conn_saved_at: Option<Instant> = None;

    loop {
        // 1. drain notifications (non-blocking, short wait so we stay responsive)
        match rx.recv_timeout(Duration::from_millis(700)) {
            Ok(ev) => {
                // A directory notification is a trigger, not a finding: note it and
                // schedule a diff. Log the trigger too, so the reason is on record.
                if ev.action == "dir_changed" {
                    pending_file_rescan = Some(Instant::now() + Duration::from_millis(400));
                    // The concrete created/modified/deleted events come from the diff.
                    let _ = log.write(&ev);
                    continue;
                }
                if ev.src == Source::Reg && ev.action == "key_changed" {
                    let cur = snapshot::snapshot_run_keys();
                    for e in snapshot::diff_reg(&prev.reg, &cur) {
                        let _ = log.write(&e);
                    }
                    prev.reg = cur;
                    continue;
                }
                if ev.src == Source::Device {
                    let _ = log.write(&ev);
                    continue;
                }
                // Track channel health from the meta events the watchers emit. A channel
                // that reports itself unavailable at startup means that surface is dark;
                // the heartbeat must carry that so it is never mistaken for quiet.
                if ev.src == Source::Meta {
                    match ev.action.as_str() {
                        "proc_trace_ok" => {
                            channel_ok.proc = true;
                            channel_ok.proc_how = "wmi".into();
                        }
                        "proc_trace_unavailable" => {
                            channel_ok.proc = false;
                            channel_ok.proc_how = "wmi-failed".into();
                        }
                        "reg_watch_unavailable" => {
                            channel_ok.reg_user = false;
                        }
                        "reg_watch_ok" => {
                            channel_ok.reg_user = true;
                        }
                        "dir_watch_unavailable" => {
                            channel_ok.dir = false;
                        }
                        "dir_watch_ok" => {
                            channel_ok.dir = true;
                        }
                        "device_watch_unavailable" => {
                            channel_ok.device = false;
                        }
                        "device_watch_ok" => {
                            channel_ok.device = true;
                        }
                        "power_watch_unavailable" => {
                            channel_ok.power = false;
                        }
                        "power_watch_ok" => {
                            channel_ok.power = true;
                        }
                        _ => {}
                    }
                }
                let _ = log.write(&ev);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        let now = Instant::now();

        // 1b. heartbeat: liveness proof, independent of whether anything changed.
        if now >= next_heartbeat {
            next_heartbeat = now + Duration::from_secs(args.heartbeat_sec);
            let auth_age = authdb::fingerprint_age(&cfg.auth_db);
            let _ = log.write(
                &Event::new(Source::Meta, "heartbeat", hostname()).with_detail(serde_json::json!({
                    "pid": std::process::id(),
                    "uptimeSec": started.elapsed().as_secs(),
                    "intervalSec": args.heartbeat_sec,
                    "sid": crate::snapshot::current_user_sid(),
                    "authDbMtime": auth_age,
                    "channels": {
                        "dir": channel_ok.dir,
                        "regUser": channel_ok.reg_user,
                        "device": channel_ok.device,
                        "proc": channel_ok.proc,
                        "procHow": channel_ok.proc_how.clone(),
                        "power": channel_ok.power,
                        "conn": args.conn_sec > 0,
                    },
                    "procMode": if channel_ok.proc { "wmi-realtime-plus-poll" } else { "poll-only" },
                })),
            );
            let _ = log.flush();
        }

        // 2. coalesced file rescan after a directory notification
        if let Some(at) = pending_file_rescan {
            if now >= at {
                pending_file_rescan = None;
                let cur = snapshot::snapshot_files(&cfg.install_dirs).unwrap_or_default();
                for e in snapshot::diff_files(&prev.file, &cur) {
                    let _ = log.write(&e);
                }
                prev.file = cur;
            }
        }

        // 3. poll the things Windows will not notify us about.
        //    Process creation is the one that matters for catching a companion app
        //    spawning something, so it gets its own (faster) cadence: a Toolhelp
        //    snapshot costs ~2 ms, versus ~165 ms for the full capture.
        if now >= next_proc {
            next_proc = now + Duration::from_secs(args.proc_sec);
            let cur = snapshot::snapshot_processes();
            for e in snapshot::diff_processes(&prev.proc, &cur, &cfg.watched_procs) {
                // When WMI is live it already reported every start in real time;
                // the poll would duplicate it. Exit events still come only from here,
                // because Win32_ProcessStartTrace has no counterpart.
                if channel_ok.proc && e.action == "started" {
                    continue;
                }
                let _ = log.write(&e);
            }
            prev.proc = cur;
        }

        if now >= next_poll {
            next_poll = now + Duration::from_secs(args.poll_sec);

            let cur = snapshot::snapshot_listeners();
            for e in snapshot::diff_listeners(&prev.listener, &cur) {
                let _ = log.write(&e);
            }
            prev.listener = cur;

            // Slow safety-net re-hash in case a directory notification was missed
            // (network share, delete-then-create inside one tick).
            if now >= next_file {
                next_file = now + Duration::from_secs(args.file_sec);
                let cur = snapshot::snapshot_files(&cfg.install_dirs).unwrap_or_default();
                for e in snapshot::diff_files(&prev.file, &cur) {
                    let _ = log.write(&e);
                }
                prev.file = cur;
            }

            log.flush()?;
        }

        // 3c. TCP conversations, grouped per (pid, peer).
        //
        // This must NOT live inside the `--poll` branch. `--conn-sec` is the knob an
        // operator cranks down to catch short-lived sockets; nesting it under
        // `--poll` silently clamped it to the slower cadence (reviewed defect:
        // `--conn-sec 2 --poll 30` reported a connection 27s late).
        if args.conn_sec > 0 && now >= next_conn {
            next_conn = now + Duration::from_secs(args.conn_sec);
            let sweep = snapshot::snapshot_connections(&args.conn_filter());
            if sweep.complete {
                if conn_incomplete {
                    conn_incomplete = false;
                    let _ = log.write(
                        &Event::new(Source::Meta, "conn_fetch_recovered", "tcp-tables")
                            .with_detail(serde_json::json!({ "families": sweep.families })),
                    );
                }
                if let Some(note) = &sweep.note {
                    if !conn_note_logged {
                        conn_note_logged = true;
                        let _ = log.write(
                            &Event::new(Source::Meta, "conn_surface_partial", "tcp-tables")
                                .with_detail(serde_json::json!({ "note": note })),
                        );
                    }
                }
                for e in snapshot::diff_connections(&prev.conn, &sweep.rows) {
                    let _ = log.write(&e);
                }
                prev.conn = sweep.rows;
                // Persist on change, throttled: a restart must resume from the newest
                // observation, but a 1s cadence must not rewrite the file every tick.
                // Residual gap (documented): a hard kill can lose up to
                // CONN_SIDECAR_MIN_SECS of updates, and those conversations are then
                // reported once on the next start.
                let changed = conn_saved.as_ref() != Some(&prev.conn);
                let due = conn_saved_at
                    .map(|t| now.duration_since(t) >= Duration::from_secs(CONN_SIDECAR_MIN_SECS))
                    .unwrap_or(true);
                if changed && due {
                    // The signature describes the surface these rows came from, so it is
                    // derived from the sweep that produced them — not from startup state.
                    connstate::save(
                        &cfg.root,
                        &connstate::Sig::of(&args.conn_filter(), &sweep.families),
                        &prev.conn,
                    );
                    conn_saved = Some(prev.conn.clone());
                    conn_saved_at = Some(now);
                }
            } else {
                // Never diff an incomplete sweep: every group it failed to see would
                // be reported as `conn_closed`, which is a fabricated observation.
                // Keeping `prev` also means the next good sweep reports the truth.
                if !conn_incomplete {
                    conn_incomplete = true;
                    let _ = log.write(
                        &Event::new(Source::Meta, "conn_fetch_incomplete", "tcp-tables")
                            .with_detail(serde_json::json!({
                                "note": sweep.note,
                                "families": sweep.families,
                            })),
                    );
                }
            }
            log.flush()?;
        }

        // 4. the login store: the highest-signal surface
        if now >= next_auth {
            next_auth = now + Duration::from_secs(args.auth_sec);
            let cur = authdb::snapshot(&cfg.auth_db, &cfg.auth_keys, &cfg.root).unwrap_or_default();
            if !prev.auth.is_empty() {
                for (k, v) in cur.iter() {
                    match prev.auth.get(k) {
                        Some(old) if old != v => {
                            let _ = log.write(
                                &Event::new(Source::AuthDb, "KEY_CHANGED", k)
                                    .with_detail(serde_json::json!({ "old": old, "new": v })),
                            );
                        }
                        None => {
                            let _ = log.write(
                                &Event::new(Source::AuthDb, "key_appeared", k)
                                    .with_detail(serde_json::json!({ "new": v })),
                            );
                        }
                        _ => {}
                    }
                }
            }
            prev.auth = cur;
            log.flush()?;
        }
    }

    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}
