//! Read-only snapshot + diff engines for the things that have no notification API.
//!
//! Design rule: *we only ever read*. No path in this file opens a watched resource
//! for writing. The registry is opened with KEY_READ, the process list with
//! TH32CS_SNAPPROCESS, the auth DB is copied before being parsed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::event::{Event, Source};

/// A single observable thing, reduced to a comparable string.
pub type Snap = BTreeMap<String, String>;

// ---------------------------------------------------------------- processes

#[cfg(windows)]
pub fn snapshot_processes() -> Snap {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut out = Snap::new();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return out,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let name = wide_to_string(&entry.szExeFile);
                let pid = entry.th32ProcessID;
                let ppid = entry.th32ParentProcessID;
                out.insert(format!("P{pid}"), format!("{name}|ppid={ppid}"));
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snap);
    }
    out
}

#[cfg(windows)]
fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Path + command line for a pid, via the WMI-free `NtQuery`-adjacent route:
/// we use `QueryFullProcessImageNameW` through an opened process handle.
#[cfg(windows)]
pub fn process_image_path(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(h);
        if ok {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        } else {
            None
        }
    }
}

/// Diff two process snapshots, emitting only *interesting* transitions.
pub fn diff_processes(prev: &Snap, cur: &Snap, interesting: &[String]) -> Vec<Event> {
    let mut out = Vec::new();

    for (k, v) in cur.iter() {
        if prev.get(k) == Some(v) {
            continue;
        }
        let name = v.split('|').next().unwrap_or("").to_ascii_lowercase();
        let watched = interesting
            .iter()
            .any(|t| name.contains(&t.to_ascii_lowercase()));
        if !watched {
            continue;
        }
        if prev.contains_key(k) {
            continue; // same pid, metadata wobble: not a lifecycle event
        }
        let pid: u32 = k.trim_start_matches('P').parse().unwrap_or(0);
        let mut ev = Event::new(Source::Proc, "started", v.split('|').next().unwrap_or(""));
        let mut d = serde_json::Map::new();
        d.insert("pid".into(), pid.into());
        if let Some(p) = v.split("ppid=").nth(1) {
            d.insert("ppid".into(), p.into());
        }
        if let Some(path) = process_image_path(pid) {
            d.insert("path".into(), path.into());
        }
        ev = ev.with_detail(serde_json::Value::Object(d));
        out.push(ev);
    }

    for (k, v) in prev.iter() {
        if cur.contains_key(k) {
            continue;
        }
        let name = v.split('|').next().unwrap_or("").to_ascii_lowercase();
        let watched = interesting
            .iter()
            .any(|t| name.contains(&t.to_ascii_lowercase()));
        if !watched {
            continue;
        }
        let mut ev = Event::new(Source::Proc, "exited", v.split('|').next().unwrap_or(""));
        ev = ev.with_detail(serde_json::json!({ "pid_key": k }));
        out.push(ev);
    }

    out
}

// ---------------------------------------------------------------- files

/// Recursive file snapshot: size + mtime + SHA-256, so a silently rewritten
/// binary with an identical size still shows up.
pub fn snapshot_files(dirs: &[PathBuf]) -> Result<Snap> {
    let mut out = Snap::new();
    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        walk(dir, &mut out, 0)?;
    }
    Ok(out)
}

fn walk(dir: &Path, out: &mut Snap, depth: usize) -> Result<()> {
    if depth > 12 {
        return Ok(());
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    for ent in rd.flatten() {
        let p = ent.path();
        let md = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.is_dir() {
            walk(&p, out, depth + 1)?;
        } else {
            let size = md.len();
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Hash small files only; huge blobs are not what we are watching for.
            let hash = if size <= 32 * 1024 * 1024 {
                hash_file(&p)
            } else {
                format!("BIG_{size}")
            };
            out.insert(
                p.to_string_lossy().to_string(),
                format!("size={size}|mtime={mtime}|sha256={hash}"),
            );
        }
    }
    Ok(())
}

fn hash_file(p: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    match std::fs::File::open(p) {
        Ok(mut f) => {
            use std::io::Read;
            let mut buf = [0u8; 64 * 1024];
            loop {
                match f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => h.update(&buf[..n]),
                    Err(_) => return "READ_ERR".into(),
                }
            }
            let d = h.finalize();
            d.iter().map(|b| format!("{b:02x}")).collect()
        }
        Err(_) => "OPEN_ERR".into(),
    }
}

pub fn diff_files(prev: &Snap, cur: &Snap) -> Vec<Event> {
    let mut out = Vec::new();
    for (k, v) in cur.iter() {
        match prev.get(k) {
            None => {
                out.push(
                    Event::new(Source::File, "created", k)
                        .with_detail(serde_json::json!({ "state": v })),
                );
            }
            Some(old) if old != v => {
                let old_hash = old.split("sha256=").nth(1).unwrap_or("?");
                let new_hash = v.split("sha256=").nth(1).unwrap_or("?");
                out.push(
                    Event::new(Source::File, "modified", k).with_detail(serde_json::json!({
                        "old_sha256": old_hash,
                        "new_sha256": new_hash,
                        "state": v,
                    })),
                );
            }
            _ => {}
        }
    }
    for k in prev.keys() {
        if !cur.contains_key(k) {
            out.push(Event::new(Source::File, "deleted", k));
        }
    }
    out
}

// ---------------------------------------------------------------- registry

/// Watch the autostart surfaces. Uses `RegNotifyChangeKeyValue` elsewhere to get
/// notified; this is the initial/periodic read used to build and reconcile state.
#[cfg(windows)]
pub fn snapshot_run_keys() -> Snap {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        HKEY_USERS, KEY_READ,
    };

    // Which hive do we use for the *user* autostart keys?
    //
    // `HKEY_CURRENT_USER` is wrong when we run as SYSTEM: it resolves to SYSTEM's own
    // hive, so the interactive user's Run keys become invisible. Prefer the user hive
    // under HKEY_USERS for the profile we are actually watching.
    let user_hive: (HKEY, String) = match user_sid() {
        Some(sid) => (HKEY_USERS, sid),
        None => (HKEY_CURRENT_USER, String::new()),
    };

    // (hive, subkey, label)
    let user_run = join_sub(
        &user_hive.1,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    );
    let user_runonce = join_sub(
        &user_hive.1,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    );
    let user_startupapproved = join_sub(
        &user_hive.1,
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    );

    let targets: [(HKEY, String, &str); 6] = [
        (user_hive.0, user_run, "HKCU_Run"),
        (user_hive.0, user_runonce, "HKCU_RunOnce"),
        (user_hive.0, user_startupapproved, "HKCU_StartupApproved"),
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            "HKLM_Run",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce".to_string(),
            "HKLM_RunOnce",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run".to_string(),
            "HKLM_StartupApproved",
        ),
    ];

    let mut out = Snap::new();
    for (hive, sub, label) in targets.iter() {
        let wide: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let mut hkey = HKEY::default();
            if RegOpenKeyExW(*hive, PCWSTR(wide.as_ptr()), 0, KEY_READ, &mut hkey).is_err() {
                continue;
            }
            let mut idx = 0u32;
            loop {
                let mut name = [0u16; 1024];
                let mut name_len = name.len() as u32;
                let mut data = [0u8; 8192];
                let mut data_len = data.len() as u32;
                let mut ty = 0u32;
                let rc = RegEnumValueW(
                    hkey,
                    idx,
                    windows::core::PWSTR(name.as_mut_ptr()),
                    &mut name_len,
                    None,
                    Some(&mut ty),
                    Some(data.as_mut_ptr()),
                    Some(&mut data_len),
                );
                if rc.is_err() {
                    break;
                }
                idx += 1;
                let key = String::from_utf16_lossy(&name[..name_len as usize]);
                // REG_SZ / REG_EXPAND_SZ are UTF-16LE; everything else is shown as hex.
                let val = if ty == 1 || ty == 2 {
                    let words: Vec<u16> = data[..data_len as usize]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&words)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    format!("<type={ty} len={data_len}>")
                };
                out.insert(format!("{label}\\{key}"), val);
            }
            let _ = RegCloseKey(hkey);
        }
    }

    // Startup folders are just files.
    if let Ok(appdata) = std::env::var("APPDATA") {
        collect_dir(
            &PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
            "STARTUP_USER",
            &mut out,
        );
    }
    if let Ok(pd) = std::env::var("ProgramData") {
        collect_dir(
            &PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
            "STARTUP_MACHINE",
            &mut out,
        );
    }
    out
}

#[cfg(windows)]
pub fn current_user_sid() -> Option<String> {
    user_sid()
}

/// Diagnostic: what the SID resolver actually sees.
///
/// Logged at startup so a failed profile-to-SID mapping shows its own cause instead of
/// surfacing only as `sid: null`.
#[cfg(windows)]
pub fn sid_diagnostics() -> Vec<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_READ, REG_VALUE_TYPE,
    };

    let mut out = Vec::new();
    out.push(format!(
        "profile_dir={}",
        crate::Config::profile_dir().to_string_lossy()
    ));

    let base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    let wide: Vec<u16> = base.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut root = HKEY::default();
        let open = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide.as_ptr()),
            0,
            KEY_READ,
            &mut root,
        );
        // WIN32_ERROR: 0 == ERROR_SUCCESS
        if open != windows::Win32::Foundation::WIN32_ERROR(0) {
            out.push(format!("ProfileList open failed: code {}", open.0));
            return out;
        }
        out.push("ProfileList opened".into());

        let mut idx = 0u32;
        let mut n = 0;
        loop {
            let mut name = [0u16; 512];
            let mut name_len = name.len() as u32;
            let rc = RegEnumKeyExW(
                root,
                idx,
                windows::core::PWSTR(name.as_mut_ptr()),
                &mut name_len,
                None,
                windows::core::PWSTR::null(),
                None,
                None,
            );
            if rc.is_err() {
                break;
            }
            idx += 1;
            n += 1;
            let sid = String::from_utf16_lossy(&name[..name_len as usize]);
            if !sid.starts_with("S-1-5-21-") {
                continue;
            }
            let sub = sid.clone();
            let sw: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sk = HKEY::default();
            if RegOpenKeyExW(root, PCWSTR(sw.as_ptr()), 0, KEY_READ, &mut sk).is_err() {
                out.push(format!("{sid} -> subkey open failed"));
                continue;
            }
            let vname: Vec<u16> = "ProfileImagePath"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut data = [0u8; 2048];
            let mut dlen = data.len() as u32;
            let mut ty = REG_VALUE_TYPE::default();
            let ok = RegQueryValueExW(
                sk,
                PCWSTR(vname.as_ptr()),
                None,
                Some(&mut ty),
                Some(data.as_mut_ptr()),
                Some(&mut dlen),
            )
            .is_ok();
            let _ = RegCloseKey(sk);
            if !ok {
                out.push(format!("{sid} -> ProfileImagePath read failed"));
                continue;
            }
            let words: Vec<u16> = data[..dlen as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let path = String::from_utf16_lossy(&words);
            let path = path.trim_end_matches('\0');
            out.push(format!("{sid} -> [{path}] norm=[{}]", normalize_path(path)));
        }
        out.push(format!("enumerated {n} subkeys"));
        let _ = RegCloseKey(root);
    }
    out
}

/// Resolve the SID of the profile we are watching, as a string usable under
/// `HKEY_USERS`.
///
/// Two routes, in order of reliability:
///
/// 1. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\ProfileImagePath`
///    — this is machine-wide state written at profile creation, so it is present
///    **before anyone logs in**. An `ONSTART` scheduled task runs before logon, which
///    makes this the only route that works at boot.
/// 2. `HKEY_USERS\<SID>\Volatile Environment\USERPROFILE` — only exists while that
///    user has an interactive session, so it fails exactly when route 1 is needed.
///
/// Route 2 was the original implementation and it silently broke every boot. Route 1
/// is now primary.
#[cfg(windows)]
fn user_sid() -> Option<String> {
    let profile = crate::Config::profile_dir();
    if profile.as_os_str().is_empty() {
        return None;
    }

    // Route 1: machine-wide ProfileList.
    if let Some(sid) = sid_from_profile_list(&profile) {
        return Some(sid);
    }

    // Route 2: fall back to the logon-time hive, if there happens to be a session.
    sid_from_volatile_env(&profile)
}

/// Map a profile directory to its SID via `ProfileList`.
///
/// Compares the **full** `ProfileImagePath` against the resolved profile dir, not just
/// the leaf name: comparing leaves is what made the earlier attempt fail, because a
/// non-ASCII username comes back in a different form than the directory scan produced.
#[cfg(windows)]
fn sid_from_profile_list(profile: &Path) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_READ, REG_VALUE_TYPE,
    };

    let wanted = normalize_path(&profile.to_string_lossy());
    if wanted.is_empty() {
        return None;
    }

    let base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    let wide: Vec<u16> = base.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut root = HKEY::default();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide.as_ptr()),
            0,
            KEY_READ,
            &mut root,
        )
        .is_err()
        {
            return None;
        }

        let mut idx = 0u32;
        let mut found: Option<String> = None;
        loop {
            let mut name = [0u16; 512];
            let mut name_len = name.len() as u32;
            let rc = RegEnumKeyExW(
                root,
                idx,
                windows::core::PWSTR(name.as_mut_ptr()),
                &mut name_len,
                None,
                windows::core::PWSTR::null(),
                None,
                None,
            );
            if rc.is_err() {
                break;
            }
            idx += 1;
            let sid = String::from_utf16_lossy(&name[..name_len as usize]);

            // Skip the service and machine accounts; only real users have C:\Users\...
            if !sid.starts_with("S-1-5-21-") {
                continue;
            }

            // Subkey paths are relative to the already-open root key, so only the SID.
            let sub = sid.clone();
            let sw: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sk = HKEY::default();
            if RegOpenKeyExW(root, PCWSTR(sw.as_ptr()), 0, KEY_READ, &mut sk).is_err() {
                continue;
            }

            let vname: Vec<u16> = "ProfileImagePath"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut data = [0u8; 2048];
            let mut dlen = data.len() as u32;
            let mut ty = REG_VALUE_TYPE::default();
            let ok = RegQueryValueExW(
                sk,
                PCWSTR(vname.as_ptr()),
                None,
                Some(&mut ty),
                Some(data.as_mut_ptr()),
                Some(&mut dlen),
            )
            .is_ok();
            let _ = RegCloseKey(sk);
            if !ok {
                continue;
            }

            let words: Vec<u16> = data[..dlen as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let path = String::from_utf16_lossy(&words);
            let path = path.trim_end_matches('\0');
            if normalize_path(&path) == wanted {
                found = Some(sid);
                break;
            }
        }
        let _ = RegCloseKey(root);
        found
    }
}

/// Case- and separator-insensitive path comparison.
#[cfg(windows)]
fn normalize_path(p: &str) -> String {
    p.trim()
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase()
}

/// Logon-time route: `HKEY_USERS\<SID>\Volatile Environment\USERPROFILE`.
#[cfg(windows)]
fn sid_from_volatile_env(profile: &Path) -> Option<String> {
    let wanted = normalize_path(&profile.to_string_lossy());
    if wanted.is_empty() {
        return None;
    }

    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_USERS, KEY_READ,
        REG_VALUE_TYPE,
    };

    unsafe {
        let mut root = HKEY::default();
        if RegOpenKeyExW(
            HKEY_USERS,
            PCWSTR(null_w().as_ptr()),
            0,
            KEY_READ,
            &mut root,
        )
        .is_err()
        {
            return None;
        }
        let mut idx = 0u32;
        let mut found: Option<String> = None;
        loop {
            let mut name = [0u16; 512];
            let mut name_len = name.len() as u32;
            let rc = RegEnumKeyExW(
                root,
                idx,
                windows::core::PWSTR(name.as_mut_ptr()),
                &mut name_len,
                None,
                windows::core::PWSTR::null(),
                None,
                None,
            );
            if rc.is_err() {
                break;
            }
            idx += 1;
            let sid = String::from_utf16_lossy(&name[..name_len as usize]);
            if !sid.starts_with("S-1-5-21-") {
                continue;
            }
            let sub = format!("{sid}\\Volatile Environment");
            let sw: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sk = HKEY::default();
            if RegOpenKeyExW(root, PCWSTR(sw.as_ptr()), 0, KEY_READ, &mut sk).is_err() {
                continue;
            }
            let vname: Vec<u16> = "USERPROFILE"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut data = [0u8; 2048];
            let mut dlen = data.len() as u32;
            let mut ty = REG_VALUE_TYPE::default();
            let ok = RegQueryValueExW(
                sk,
                PCWSTR(vname.as_ptr()),
                None,
                Some(&mut ty),
                Some(data.as_mut_ptr()),
                Some(&mut dlen),
            )
            .is_ok();
            let _ = RegCloseKey(sk);
            if !ok {
                continue;
            }
            let words: Vec<u16> = data[..dlen as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let path = String::from_utf16_lossy(&words);
            if normalize_path(&path) == wanted {
                found = Some(sid);
                break;
            }
        }
        let _ = RegCloseKey(root);
        found
    }
}

#[cfg(windows)]
fn null_w() -> [u16; 1] {
    [0u16]
}

#[cfg(windows)]
fn read_profile_sid(profile_name: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\ProfileImagePath
    let base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    let wide: Vec<u16> = base.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut root = HKEY::default();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide.as_ptr()),
            0,
            KEY_READ,
            &mut root,
        )
        .is_err()
        {
            return None;
        }
        let mut idx = 0u32;
        loop {
            let mut name = [0u16; 512];
            let mut name_len = name.len() as u32;
            let rc = RegEnumKeyExW(
                root,
                idx,
                windows::core::PWSTR(name.as_mut_ptr()),
                &mut name_len,
                None,
                windows::core::PWSTR::null(),
                None,
                None,
            );
            if rc.is_err() {
                break;
            }
            idx += 1;
            let sid = String::from_utf16_lossy(&name[..name_len as usize]);
            // Read ProfileImagePath for this SID.
            let sub = format!("{base}\\{sid}");
            let sw: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sk = HKEY::default();
            if RegOpenKeyExW(root, PCWSTR(sw.as_ptr()), 0, KEY_READ, &mut sk).is_ok() {
                let vname: Vec<u16> = "ProfileImagePath"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let mut data = [0u8; 1024];
                let mut dlen = data.len() as u32;
                let mut ty = windows::Win32::System::Registry::REG_VALUE_TYPE::default();
                if windows::Win32::System::Registry::RegQueryValueExW(
                    sk,
                    PCWSTR(vname.as_ptr()),
                    None,
                    Some(&mut ty),
                    Some(data.as_mut_ptr()),
                    Some(&mut dlen),
                )
                .is_ok()
                {
                    let words: Vec<u16> = data[..dlen as usize]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let path = String::from_utf16_lossy(&words);
                    let path = path.trim_end_matches('\0');
                    if let Some(leaf) = Path::new(path).file_name() {
                        if leaf.to_string_lossy().eq_ignore_ascii_case(profile_name) {
                            let _ = RegCloseKey(sk);
                            let _ = RegCloseKey(root);
                            return Some(sid);
                        }
                    }
                }
                let _ = RegCloseKey(sk);
            }
        }
        let _ = RegCloseKey(root);
    }
    None
}

#[cfg(windows)]
fn join_sub(sid: &str, sub: &str) -> String {
    if sid.is_empty() {
        sub.to_string()
    } else {
        format!("{sid}\\{sub}")
    }
}

#[cfg(windows)]
fn collect_dir(dir: &Path, label: &str, out: &mut Snap) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            out.insert(
                format!("{label}\\{}", ent.file_name().to_string_lossy()),
                p.to_string_lossy().to_string(),
            );
        }
    }
}

pub fn diff_reg(prev: &Snap, cur: &Snap) -> Vec<Event> {
    let mut out = Vec::new();
    for (k, v) in cur.iter() {
        match prev.get(k) {
            None => out.push(
                Event::new(Source::Reg, "added", k).with_detail(serde_json::json!({ "value": v })),
            ),
            Some(old) if old != v => out.push(
                Event::new(Source::Reg, "modified", k)
                    .with_detail(serde_json::json!({ "old": old, "new": v })),
            ),
            _ => {}
        }
    }
    for (k, v) in prev.iter() {
        if !cur.contains_key(k) {
            out.push(
                Event::new(Source::Reg, "removed", k).with_detail(serde_json::json!({ "old": v })),
            );
        }
    }
    out
}

// ---------------------------------------------------------------- tcp tables

/// One `GetExtendedTcpTable` fetch, shared by every TCP surface.
///
/// Returns `Ok(buffer)` — possibly an empty buffer, which is a *fact* ("this table
/// has no entries") — or `Err(rc)` when the table could not be read at all.
///
/// The two must never be conflated: a caller that treats a failed read as an empty
/// table will report "no conversations" while the surface is actually dark, and
/// will also fabricate a close event for every group it failed to see.
///
/// The table can change size between the sizing call and the data call on a busy
/// machine (`ERROR_INSUFFICIENT_BUFFER`); that case is retried a bounded number of
/// times instead of being reported as an empty table.
#[cfg(windows)]
fn fetch_tcp_table(
    family: u32,
    class: windows::Win32::NetworkManagement::IpHelper::TCP_TABLE_CLASS,
) -> Result<Vec<u8>, u32> {
    use windows::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable;

    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    unsafe {
        let mut size = 0u32;
        let rc = GetExtendedTcpTable(None, &mut size, false, family, class, 0);
        if rc != 0 && rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(rc);
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        for _ in 0..3 {
            let mut buf = vec![0u8; size as usize];
            let rc = GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                family,
                class,
                0,
            );
            if rc == 0 {
                return Ok(buf);
            }
            if rc != ERROR_INSUFFICIENT_BUFFER {
                return Err(rc);
            }
            // Grow explicitly: if the API did not raise `size`, retrying with the
            // same buffer would spin three times and give up for no reason.
            if size as usize <= buf.len() {
                size = buf.len() as u32 + 4096;
            }
        }
        Err(ERROR_INSUFFICIENT_BUFFER)
    }
}

/// Listening TCP endpoints (IPv4), attributed to a process name.
#[cfg(windows)]
pub fn snapshot_listeners() -> Snap {
    use std::net::Ipv4Addr;
    use windows::Win32::NetworkManagement::IpHelper::{
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut out = Snap::new();
    // An unreadable table and an empty table are different answers; one of them
    // means "nothing is listening" and the other means "I do not know".
    let buf = match fetch_tcp_table(AF_INET.0 as u32, TCP_TABLE_OWNER_PID_LISTENER) {
        Ok(b) if !b.is_empty() => b,
        _ => return out,
    };
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    unsafe {
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID,
            table.dwNumEntries as usize,
        );
        for r in rows {
            // dwLocalAddr / dwLocalPort are in network byte order.
            let addr = Ipv4Addr::from(u32::from_be(r.dwLocalAddr));
            let port = u16::from_be(r.dwLocalPort as u16);
            let pid = r.dwOwningPid;
            let name = names
                .entry(pid)
                .or_insert_with(|| process_name_for_pid(pid))
                .clone();
            out.insert(format!("{addr}:{port}"), format!("pid={pid}|proc={name}"));
        }
    }
    out
}

pub fn diff_listeners(prev: &Snap, cur: &Snap) -> Vec<Event> {
    let mut out = Vec::new();
    for (k, v) in cur.iter() {
        if prev.get(k) == Some(v) {
            continue;
        }
        let action = if prev.contains_key(k) {
            "listen_changed"
        } else {
            "listen_started"
        };
        out.push(Event::new(Source::Net, action, k).with_detail(serde_json::json!({ "who": v })));
    }
    for k in prev.keys() {
        if !cur.contains_key(k) {
            out.push(Event::new(Source::Net, "listen_stopped", k));
        }
    }
    out
}

/// Which sockets the connection snapshot is willing to ignore.
///
/// Explicit rather than implicit: every entry here is a decision that some
/// traffic will not be reported, so the caller has to say it out loud.
#[derive(Debug, Clone, Copy)]
pub struct ConnFilter {
    /// Loopback peers are dropped by default: a local proxy is loud and tells you
    /// nothing about egress.
    pub include_loopback: bool,
    /// pid 0 rows are closed-socket remnants, not a live owner.
    pub include_pid0: bool,
    /// Our own pid is never interesting to us.
    pub exclude_pid: u32,
}

impl Default for ConnFilter {
    fn default() -> Self {
        ConnFilter {
            include_loopback: false,
            include_pid0: false,
            exclude_pid: 0,
        }
    }
}

/// One sweep of the connection surface.
///
/// `complete == false` means at least one address family could not be read. The
/// caller must **not** diff an incomplete sweep: a partial view would invent
/// `conn_closed` for every group it simply failed to see.
pub struct ConnSweep {
    pub rows: Snap,
    pub complete: bool,
    /// Why the sweep is incomplete, or which family is absent (IPv6 disabled).
    /// Reported once per state change by the caller, never per poll.
    pub note: Option<String>,
    /// Families actually read back, e.g. `["ipv4", "ipv6"]`.
    pub families: Vec<&'static str>,
}

impl ConnSweep {
    fn failed(note: String) -> Self {
        ConnSweep {
            rows: Snap::new(),
            complete: false,
            note: Some(note),
            families: Vec::new(),
        }
    }
}

/// One (pid, peer) group being accumulated across the v4 and v6 tables.
#[cfg(windows)]
#[derive(Default)]
struct ConnGroup {
    pid: u32,
    proc: String,
    remote: String,
    states: std::collections::BTreeSet<String>,
    locals: std::collections::BTreeSet<String>,
}

/// Established/half-open TCP sockets (IPv4 + IPv6), grouped per (pid, peer).
///
/// Grouping — not one row per socket — is the point: a browser holding 20
/// keep-alive sockets to one host is one conversation, and reporting it 20 times
/// per poll would bury everything else. The group carries the socket count so the
/// difference stays visible.
///
/// The group key is (pid, peer) only — see `connlogic::group_key` for why the
/// process *name* is deliberately not part of the identity.
#[cfg(windows)]
pub fn snapshot_connections(f: &ConnFilter) -> ConnSweep {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::NetworkManagement::IpHelper::{
        MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    // An address family the OS reports as absent is a smaller surface, not a
    // failure: report v4 rows and say so once. Any other error means we cannot
    // claim to know the surface at all.
    const ERROR_NOT_SUPPORTED: u32 = 50;
    const ERROR_INVALID_PARAMETER: u32 = 87;

    let mut out = Snap::new();
    let mut groups: BTreeMap<String, ConnGroup> = BTreeMap::new();
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    let mut families: Vec<&'static str> = Vec::new();
    let mut note: Option<String> = None;
    let mut complete = true;

    // Both tables feed one admission test, so a filter can never apply to v4 but
    // silently not to v6. A row is (pid, state, peer, local endpoint); sockets
    // with the same (pid, peer) land in the same group.
    fn add_row(
        groups: &mut BTreeMap<String, ConnGroup>,
        names: &mut BTreeMap<u32, String>,
        f: &ConnFilter,
        pid: u32,
        state: u32,
        remote: String,
        local: String,
    ) {
        if !crate::connlogic::is_live_tcp_state(state) {
            return;
        }
        if pid == f.exclude_pid {
            return;
        }
        if pid == 0 && !f.include_pid0 {
            return;
        }
        let proc = names
            .entry(pid)
            .or_insert_with(|| process_name_for_pid(pid))
            .clone();
        let g = groups
            .entry(crate::connlogic::group_key(pid, &remote))
            .or_insert_with(|| ConnGroup {
                pid,
                proc,
                remote,
                ..Default::default()
            });
        g.states
            .insert(crate::connlogic::tcp_state_name(state).to_string());
        g.locals.insert(local);
    }

    match fetch_tcp_table(AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL) {
        Ok(buf) if buf.is_empty() => families.push("ipv4"),
        Ok(buf) => {
            families.push("ipv4");
            unsafe {
                let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID,
                    table.dwNumEntries as usize,
                );
                for r in rows {
                    let laddr = Ipv4Addr::from(u32::from_be(r.dwLocalAddr));
                    let raddr = Ipv4Addr::from(u32::from_be(r.dwRemoteAddr));
                    let lport = u16::from_be(r.dwLocalPort as u16);
                    let rport = u16::from_be(r.dwRemotePort as u16);
                    if raddr.is_loopback() && !f.include_loopback {
                        continue;
                    }
                    add_row(
                        &mut groups,
                        &mut names,
                        f,
                        r.dwOwningPid,
                        r.dwState,
                        format!("{raddr}:{rport}"),
                        format!("{laddr}:{lport}"),
                    );
                }
            }
        }
        Err(rc) => {
            complete = false;
            note = Some(format!("IPv4 table unreadable (rc={rc})"));
        }
    }

    match fetch_tcp_table(AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL) {
        Ok(buf) if buf.is_empty() => families.push("ipv6"),
        Ok(buf) => {
            families.push("ipv6");
            unsafe {
                let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID,
                    table.dwNumEntries as usize,
                );
                for r in rows {
                    // uc*Addr holds the address in network byte order already.
                    let laddr = Ipv6Addr::from(r.ucLocalAddr);
                    let raddr = Ipv6Addr::from(r.ucRemoteAddr);
                    if crate::connlogic::is_loopback_peer_v6(raddr) && !f.include_loopback {
                        continue;
                    }
                    add_row(
                        &mut groups,
                        &mut names,
                        f,
                        r.dwOwningPid,
                        r.dwState,
                        crate::connlogic::v6_endpoint(raddr, r.dwRemoteScopeId, r.dwRemotePort),
                        crate::connlogic::v6_endpoint(laddr, r.dwLocalScopeId, r.dwLocalPort),
                    );
                }
            }
        }
        Err(rc) if rc == ERROR_NOT_SUPPORTED || rc == ERROR_INVALID_PARAMETER => {
            // IPv6 genuinely absent on this host: a smaller surface, still a fact.
            note = Some(format!("IPv6 table unavailable (rc={rc}); IPv4 only"));
        }
        Err(rc) => {
            complete = false;
            note = Some(format!("IPv6 table unreadable (rc={rc})"));
        }
    }

    for (key, g) in groups {
        let mut locals: Vec<String> = g.locals.iter().cloned().collect();
        let extra = locals.len().saturating_sub(crate::connlogic::LOCAL_SAMPLE);
        locals.truncate(crate::connlogic::LOCAL_SAMPLE);
        out.insert(
            key,
            serde_json::json!({
                "pid": g.pid,
                "proc": g.proc,
                "remote": g.remote,
                "sockets": g.locals.len(),
                "states": g.states.iter().cloned().collect::<Vec<_>>(),
                "locals": locals,
                "localsOmitted": extra,
            })
            .to_string(),
        );
    }

    ConnSweep {
        rows: out,
        complete,
        note,
        families,
    }
}

#[cfg(not(windows))]
pub fn snapshot_connections(_f: &ConnFilter) -> ConnSweep {
    // Nothing to claim about a surface this build cannot read.
    ConnSweep::failed("non-Windows build: connection surface unavailable".into())
}

/// Diff two connection snapshots into conversation-level events.
///
/// Only appearance/disappearance counts as an event. A group whose socket count
/// or state string moved is **not** reported: on a busy machine that fires every
/// poll and turns the log into a haystack with no needle. The count is still in
/// the snapshot, so the next real transition carries it.
pub fn diff_connections(prev: &Snap, cur: &Snap) -> Vec<Event> {
    let mut out = Vec::new();
    for (k, v) in cur.iter() {
        if prev.contains_key(k) {
            continue;
        }
        out.push(conn_event("conn_opened", k, v));
    }
    for (k, v) in prev.iter() {
        if cur.contains_key(k) {
            continue;
        }
        out.push(conn_event("conn_closed", k, v));
    }
    out
}

fn conn_event(action: &str, key: &str, value: &str) -> Event {
    let parsed: serde_json::Value =
        serde_json::from_str(value).unwrap_or_else(|_| serde_json::json!({ "raw": value }));
    let proc = parsed
        .get("proc")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let remote = parsed
        .get("remote")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| key.split('|').nth(1).unwrap_or("?"))
        .to_string();
    Event::new(Source::Net, action, format!("{proc} -> {remote}")).with_detail(parsed)
}

/// Process name from a pid (used for listener attribution).
#[cfg(windows)]
pub fn process_name_for_pid(pid: u32) -> String {
    process_image_path(pid)
        .map(|p| {
            Path::new(&p)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| p.clone())
        })
        .unwrap_or_else(|| "?".into())
}

#[cfg(not(windows))]
pub fn process_name_for_pid(_pid: u32) -> String {
    "?".into()
}
