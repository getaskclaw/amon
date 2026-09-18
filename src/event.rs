//! Event model + append-only JSONL sink.
//!
//! Every observation is one `Event`. Nothing here writes to, deletes, or modifies
//! any file belonging to the watched application; the only writes are to our own
//! log under `--root`.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Meta,
    File,
    Reg,
    Proc,
    Net,
    AuthDb,
    Device,
    Task,
    Svc,
    Power,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Meta => "meta",
            Source::File => "file",
            Source::Reg => "reg",
            Source::Proc => "proc",
            Source::Net => "net",
            Source::AuthDb => "authdb",
            Source::Device => "device",
            Source::Task => "task",
            Source::Svc => "svc",
            Source::Power => "power",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// UTC, RFC3339.
    pub ts: String,
    /// Local time, human readable (GMT+8 on this host).
    pub local: String,
    pub src: Source,
    pub action: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl Event {
    pub fn new(src: Source, action: &str, target: impl Into<String>) -> Self {
        let now = chrono::Local::now();
        Event {
            ts: now.with_timezone(&chrono::Utc).to_rfc3339(),
            local: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            src,
            action: action.to_string(),
            target: target.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, v: serde_json::Value) -> Self {
        self.detail = Some(v);
        self
    }

    /// Does this event deserve to be shouted about in a report?
    pub fn is_high_signal(&self) -> bool {
        match (self.src, self.action.as_str()) {
            (Source::AuthDb, "KEY_CHANGED") => true,
            (Source::Reg, "added") | (Source::Reg, "modified") => true,
            (Source::Task, "created") | (Source::Task, "modified") => true,
            (Source::Svc, "created") | (Source::Svc, "changed") => true,
            (Source::Device, _) => true,
            (Source::File, "created") | (Source::File, "modified") | (Source::File, "deleted") => {
                true
            }
            (Source::Proc, "started") => {
                let t = self.target.to_ascii_lowercase();
                t.contains("cursor-helper") || t.contains("cliproxy") || t.contains("cursor.exe")
            }
            // Egress from a watched process is the whole point of watching it.
            // `conn_closed` stays out: a closing socket is not a finding.
            (Source::Net, "conn_opened") => {
                let t = self.target.to_ascii_lowercase();
                t.contains("cursor-helper") || t.contains("cliproxy") || t.contains("cursor.exe")
            }
            // Suspend/resume is environmental context, not a threat signal. It is
            // surfaced in the report's coverage section instead, so it does not
            // compete with real findings for attention in the high-signal list.
            (Source::Power, _) => false,
            _ => false,
        }
    }
}

pub struct EventLog {
    path: PathBuf,
    writer: BufWriter<std::fs::File>,
    written: u64,
    max_bytes: u64,
}

impl EventLog {
    pub fn open(root: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(root)?;
        let path = root.join("events.jsonl");
        let f = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(EventLog {
            path,
            writer: BufWriter::new(f),
            written: 0,
            max_bytes: 32 * 1024 * 1024,
        })
    }

    /// Rotate before the file gets unwieldy, keeping history on disk.
    fn maybe_rotate(&mut self) -> anyhow::Result<()> {
        let len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if len < self.max_bytes {
            return Ok(());
        }
        self.writer.flush()?;
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let rotated = self.path.with_file_name(format!("events.{stamp}.jsonl"));
        std::fs::rename(&self.path, &rotated)?;
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.writer = BufWriter::new(f);
        Ok(())
    }

    pub fn write(&mut self, ev: &Event) -> anyhow::Result<()> {
        if self.written % 64 == 0 {
            self.maybe_rotate()?;
        }
        let line = serde_json::to_string(ev)?;
        writeln!(self.writer, "{line}")?;
        self.written += 1;
        // Flush often: a monitor that loses its last events on kill is useless.
        if self.written % 8 == 0 {
            self.writer.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    pub fn count(&self) -> u64 {
        self.written
    }
}
