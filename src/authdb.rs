//! Read-only inspection of Cursor's login store.
//!
//! Values are never logged. For each auth key we record presence, length, and the
//! first 16 hex chars of the value's SHA-256 — enough to detect a rewrite, useless
//! for stealing a session.
//!
//! SQLite parsing: rather than link a C SQLite, we do the small amount we need —
//! locate the `ItemTable` b-tree and read (key, value) rows. That is a fair amount
//! of code for one table, so the pragmatic alternative is used here: if `sqlite3.exe`
//! is available it is invoked read-only against a *copy* of the database; otherwise
//! we fall back to file-level fingerprinting (size/mtime/hash) which still detects
//! that something touched the store.

use std::path::{Path, PathBuf};

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::snapshot::Snap;

/// SHA-256 of a byte slice, first 16 hex chars.
fn sha16(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn sqlite_path() -> Option<PathBuf> {
    for c in [
        r"D:\msys64\mingw64\bin\sqlite3.exe",
        r"C:\msys64\mingw64\bin\sqlite3.exe",
    ] {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Copy the DB plus its WAL/SHM sidecars into our own tmp dir, then read that.
/// Copying is required because the app may hold the store open.
fn stage(db: &Path, root: &Path) -> Option<PathBuf> {
    if !db.exists() {
        return None;
    }
    let tmp = root.join("tmp");
    std::fs::create_dir_all(&tmp).ok()?;
    let dest = tmp.join("auth-copy.vscdb");
    std::fs::copy(db, &dest).ok()?;
    for sidecar in ["-wal", "-shm"] {
        let src = PathBuf::from(format!("{}{sidecar}", db.display()));
        if src.exists() {
            let dst = PathBuf::from(format!("{}{sidecar}", dest.display()));
            let _ = std::fs::copy(&src, &dst);
        }
    }
    Some(dest)
}

/// Age of the auth store's last modification, in seconds, or `None` if unreadable.
///
/// Part of the heartbeat: a store whose mtime never moves is either genuinely idle or
/// being read from the wrong path, and this makes the difference visible.
pub fn fingerprint_age(db: &Path) -> Option<u64> {
    let md = std::fs::metadata(db).ok()?;
    let modified = md.modified().ok()?;
    let age = std::time::SystemTime::now().duration_since(modified).ok()?;
    Some(age.as_secs())
}

/// Read the auth keys out of a database copy.
pub fn snapshot(db: &Path, keys: &[&str], root: &Path) -> Result<Snap> {
    let mut out = Snap::new();

    let staged = match stage(db, root) {
        Some(p) => p,
        None => {
            out.insert("DB".into(), "missing".into());
            return Ok(out);
        }
    };

    let sqlite = match sqlite_path() {
        Some(s) => s,
        None => {
            // No sqlite CLI: degrade to a whole-file fingerprint. Still catches
            // "the store was touched", just not which key.
            match std::fs::read(&staged) {
                Ok(bytes) => {
                    let md = std::fs::metadata(&staged)?;
                    out.insert(
                        "DB".into(),
                        format!("no_sqlite|size={}|sha16={}", md.len(), sha16(&bytes)),
                    );
                }
                Err(_) => {
                    out.insert("DB".into(), "unreadable".into());
                }
            }
            return Ok(out);
        }
    };

    for key in keys {
        let query = format!("select value from ItemTable where key='{key}';");
        let output = std::process::Command::new(&sqlite)
            .arg("-readonly")
            .arg(&staged)
            .arg(&query)
            .output();

        match output {
            Ok(o) if o.status.success() => {
                let raw = String::from_utf8_lossy(&o.stdout);
                let val = raw.trim_end_matches(['\r', '\n']);
                if val.is_empty() {
                    out.insert((*key).into(), "absent".into());
                } else {
                    out.insert(
                        (*key).into(),
                        format!("len={}|sha16={}", val.len(), sha16(val.as_bytes())),
                    );
                }
            }
            _ => {
                out.insert((*key).into(), "query_failed".into());
            }
        }
    }
    Ok(out)
}
