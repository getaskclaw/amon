//! Report generation: fold events.jsonl into a human summary + machine line.
//!
//! Incremental by design: a cursor file records how many log lines were already
//! reported, so scheduled runs only surface what is new.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::Result;

use crate::event::{Event, Source};

const CURSOR_FILE: &str = "report-cursor.json";
const REPORT_FILE: &str = "report.md";

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Cursor {
    offset: usize,
    last_report: String,
}

fn read_cursor(root: &Path) -> Cursor {
    std::fs::read_to_string(root.join(CURSOR_FILE))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_cursor(root: &Path, c: &Cursor) -> Result<()> {
    std::fs::write(root.join(CURSOR_FILE), serde_json::to_string_pretty(c)?)?;
    Ok(())
}

/// Returns the number of *new* events. 0 means "nothing to say".
pub fn run(root: &Path) -> Result<usize> {
    let log_path = root.join("events.jsonl");
    if !log_path.exists() {
        write_cursor(
            root,
            &Cursor {
                offset: 0,
                last_report: chrono::Local::now().to_rfc3339(),
            },
        )?;
        return Ok(0);
    }

    let cur = read_cursor(root);
    let file = std::fs::File::open(&log_path)?;
    let reader = BufReader::new(file);

    let mut all: Vec<Event> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<Event>(&line) {
            all.push(ev);
        }
    }

    let total = all.len();
    if cur.offset >= total {
        write_cursor(
            root,
            &Cursor {
                offset: total,
                last_report: chrono::Local::now().to_rfc3339(),
            },
        )?;
        return Ok(0);
    }

    let new_events = &all[cur.offset..total];

    let mut by_src: std::collections::BTreeMap<&str, usize> = Default::default();
    for e in new_events {
        *by_src.entry(e.src.as_str()).or_insert(0) += 1;
    }

    let high: Vec<&Event> = new_events.iter().filter(|e| e.is_high_signal()).collect();

    // Coverage first: "was the monitor even looking?" outranks "what did it see?"
    // A period the monitor slept through cannot be reported as "nothing happened".
    let (gaps, gap_summary) = analyse_gaps(new_events);
    let sleep_min: f64 = gaps
        .iter()
        .filter(|g| g.end.is_some())
        .map(|g| g.minutes)
        .sum();

    let mut md = String::new();
    md.push_str("# amon 监控报告\n\n");
    md.push_str(&format!(
        "- 生成时间: {}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    md.push_str(&format!(
        "- 新增事件: {}（日志累计 {} 行，本次从第 {} 行起）\n",
        new_events.len(),
        total,
        cur.offset + 1
    ));

    md.push_str("\n## 监控覆盖度\n\n");
    md.push_str(&format!("- {gap_summary}\n"));
    if !gaps.is_empty() && sleep_min > 0.0 {
        md.push_str("\n| 睡眠开始 | 唤醒 | 时长 |\n|---|---|---|\n");
        for g in &gaps {
            match &g.end {
                Some(e) => md.push_str(&format!(
                    "| {} | {} | {:.0} 分钟 |\n",
                    g.start, e, g.minutes
                )),
                None => md.push_str(&format!("| {} | （仍在睡眠） | — |\n", g.start)),
            }
        }
        md.push_str(
            "\n**该窗口内：文件改动 / 注册表改动 / 凭据改动仍可通过状态差分回溯发现；             进程启动、端口变化与新建连接不可追溯。**\n",
        );
    }
    let srcs = by_src
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    md.push_str(&format!("- 按来源: {srcs}\n\n"));

    md.push_str(&format!("## 高信号事件 ({})\n\n", high.len()));
    if high.is_empty() {
        md.push_str("（无）\n");
    }
    for e in high.iter().rev().take(200) {
        md.push_str(&format!(
            "- `{}` **{}/{}** `{}`\n",
            e.local,
            e.src.as_str(),
            e.action,
            e.target
        ));
        if let Some(d) = &e.detail {
            md.push_str(&format!("  - `{d}`\n"));
        }
    }

    md.push_str("\n## 全部新增事件\n\n");
    for e in new_events.iter().rev().take(300) {
        let d = e.detail.as_ref().map(|v| v.to_string()).unwrap_or_default();
        md.push_str(&format!(
            "- `{}` {}/{} `{}` {}\n",
            e.local,
            e.src.as_str(),
            e.action,
            e.target,
            d
        ));
    }

    std::fs::write(root.join(REPORT_FILE), md)?;
    write_cursor(
        root,
        &Cursor {
            offset: total,
            last_report: chrono::Local::now().to_rfc3339(),
        },
    )?;

    // Stdout contract for automation.
    println!(
        "NEW_EVENTS={} HIGH={} LOG_LINES={}",
        new_events.len(),
        high.len(),
        total
    );
    if !gaps.is_empty() {
        println!("SLEEP={}", gap_summary);
    }
    for e in high.iter().rev().take(25) {
        println!("  {} {}/{} {}", e.local, e.src.as_str(), e.action, e.target);
    }
    println!("REPORT={}", root.join(REPORT_FILE).display());

    let _ = std::io::stdout().flush();
    Ok(new_events.len())
}

/// Exposed for tests/debugging.
pub fn source_name(s: Source) -> &'static str {
    s.as_str()
}

/// A blind window: the monitor was suspended and could not observe anything.
struct Gap {
    start: String,
    end: Option<String>,
    minutes: f64,
}

/// Analyse suspend/resume pairs in a slice of events.
///
/// Returns (gaps, summary line). An unpaired `suspended` at the end means the
/// machine is asleep right now — reported honestly rather than as a made-up
/// duration.
fn analyse_gaps(events: &[Event]) -> (Vec<Gap>, String) {
    fn parse_ts(s: &str) -> Option<chrono::NaiveDateTime> {
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok()
    }

    let mut gaps: Vec<Gap> = Vec::new();
    let mut pending: Option<&Event> = None;

    for e in events {
        if e.src != Source::Power {
            continue;
        }
        match e.action.as_str() {
            "suspended" => pending = Some(e),
            "resumed" => {
                if let Some(s) = pending.take() {
                    let mins = match (parse_ts(&s.local), parse_ts(&e.local)) {
                        (Some(a), Some(b)) => (b - a).num_seconds() as f64 / 60.0,
                        _ => 0.0,
                    };
                    gaps.push(Gap {
                        start: s.local.clone(),
                        end: Some(e.local.clone()),
                        minutes: mins,
                    });
                }
            }
            _ => {}
        }
    }

    let open = pending.map(|s| Gap {
        start: s.local.clone(),
        end: None,
        minutes: 0.0,
    });

    let total_min: f64 = gaps.iter().map(|g| g.minutes).sum();
    let closed = gaps.len();

    let mut summary = if closed == 0 && open.is_none() {
        "本周期未检测到睡眠".to_string()
    } else {
        format!("睡眠 {} 次，合计 {:.1} 小时", closed, total_min / 60.0)
    };

    if let Some(o) = &open {
        summary.push_str(&format!("；⚠ 自 {} 起处于睡眠中（未统计时长）", o.start));
    }
    if let Some(o) = open {
        gaps.push(o);
    }

    (gaps, summary)
}
