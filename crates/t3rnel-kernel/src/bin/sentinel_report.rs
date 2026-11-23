// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) T3raTech Solutions (Pvt) Ltd. All rights reserved.

//! Report error and security findings from the daemon's logs.
//!
//! The sentinel watches a live event stream inside the daemon. This entry point
//! serves the operator asking "what has been going wrong?" without a daemon
//! running, by replaying what the logs already recorded.
//!
//! It reads only. Nothing here disables an integration or halts an agent: acting
//! on a false positive costs more than the condition it answers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use t3rnel_kernel::sentinel::{Event, EventKind, Sentinel, SentinelConfig, Severity};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let log_dir = std::env::var("T3RNEL_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|home| PathBuf::from(home).join(".t3rnel").join("logs"))
                .unwrap_or_else(|_| PathBuf::from("logs"))
        });

    let logs = collect_logs(&log_dir);
    if logs.is_empty() {
        // Not an error: a system that has never failed has nothing to report.
        // Say which directory was searched, so an empty result is not mistaken
        // for a clean bill of health when the path is simply wrong.
        println!("no logs found under {}", log_dir.display());
        return std::process::ExitCode::SUCCESS;
    }

    let mut sentinel = Sentinel::new(SentinelConfig::default());
    let mut alerts = Vec::new();
    let mut lines_read = 0usize;

    for path in &logs {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let subject = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("daemon")
            .to_string();

        for (index, line) in content.lines().enumerate() {
            lines_read += 1;
            let Some(kind) = classify(line) else { continue };
            // Log timestamps vary by writer; index order preserves sequence,
            // which is what the windowing actually needs.
            let at = SystemTime::UNIX_EPOCH + Duration::from_secs(index as u64);
            alerts.extend(sentinel.observe(Event {
                subject: subject.clone(),
                kind,
                at,
            }));
        }
    }

    report(&alerts, lines_read, logs.len(), as_json);

    // Findings persisted in shared memory under `security:*` are the intake
    // queue: a finding discovered outside a scan (a leak seen in /proc, an
    // exposed credential in a transcript) is written once by whoever found it
    // and surfaces in every sentinel run until its status moves off
    // `still_leaking`. A dead daemon simply means no intake — not zero risk.
    let intake = memory_intake_findings();
    if !as_json && !intake.is_empty() {
        println!("\nSECURITY FINDINGS — shared-memory intake ({})", intake.len());
        for finding in &intake {
            println!("  {}", finding);
        }
    }
    let leaking = intake.iter().any(|f| f.contains("still_leaking"));

    // A critical finding — or a persisted security finding still leaking — is a
    // non-zero exit so a scheduled run surfaces it.
    if alerts.iter().any(|a| a.severity == Severity::Critical) || leaking {
        return std::process::ExitCode::from(2);
    }
    std::process::ExitCode::SUCCESS
}

/// Pull `security:*` records from shared memory, when a daemon is reachable.
///
/// The report must work with no daemon, so an unreachable or absent daemon
/// returns empty rather than an error — intake findings are advisory here,
/// never the difference between "ran" and "did not run".
fn memory_intake_findings() -> Vec<String> {
    let base = std::env::var("T3RNEL_API")
        .ok()
        .or_else(daemon_listen_addr)
        .unwrap_or_default();
    if base.is_empty() {
        return Vec::new();
    }
    let url = format!(
        "{}/api/memory/records?key_prefix=security:&depth=full&budget=65536&limit=100",
        base.trim_end_matches('/')
    );
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Vec::new();
    };
    let records: Vec<serde_json::Value> = runtime
        .block_on(async {
            let body = reqwest::get(&url).await.ok()?.text().await.ok()?;
            let json: serde_json::Value = serde_json::from_str(&body).ok()?;
            json.get("records")?.as_array().cloned()
        })
        .unwrap_or_default();
    records
        .iter()
        .map(|record| {
            let key = record
                .get("key")
                .and_then(|k| k.as_str())
                .unwrap_or("security:?");
            let body: serde_json::Value = record
                .get("content")
                .and_then(|c| c.as_str())
                .and_then(|c| serde_json::from_str(c).ok())
                .unwrap_or_default();
            let severity = body
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown");
            let status = body
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("untracked");
            let finding = body
                .get("finding")
                .and_then(|s| s.as_str())
                .unwrap_or_else(|| {
                    record
                        .get("summary")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                });
            format!("[{severity}/{status}] {key} — {finding}")
        })
        .collect()
}

/// The daemon's own info file is the ground truth for where it listens — the
/// configured port is advisory when bind order changes.
fn daemon_listen_addr() -> Option<String> {
    let home = std::env::var("T3RNEL_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".t3rnel")))
        .ok()?;
    let info: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(home.join("daemon.json")).ok()?).ok()?;
    let addr = info.get("listen_addr")?.as_str()?;
    // A wildcard bind is not a connect address — loopback is what the
    // wildcard actually answers locally.
    let host = match addr.split(':').next() {
        Some("0.0.0.0") | Some("[::]") | Some("::") => addr.replacen(
            addr.split(':').next().unwrap_or(""),
            "127.0.0.1",
            1,
        ),
        _ => addr.to_string(),
    };
    Some(format!("http://{host}"))
}

/// Does a log line report this HTTP status, as opposed to merely containing the
/// digits?
///
/// Matched as a bare substring, "401" appears inside nanosecond timestamps —
/// 15:44:58.601401Z contains it — so any line written in the wrong microsecond
/// counted as an authentication failure. That produced 49 critical security
/// findings on a healthy system, which is worse than having no monitor: real
/// findings are buried under noise nobody reads twice.
fn has_status(line: &str, status: u16) -> bool {
    let code = status.to_string();
    [
        "status ",
        "status=",
        "status: ",
        "http ",
        "http/1.1 ",
        "code=",
        "code ",
    ]
    .iter()
    .any(|label| {
        line.split(label).skip(1).any(|rest| {
            rest.trim_start().starts_with(&code)
                && !rest
                    .trim_start()
                    .chars()
                    .nth(code.len())
                    .is_some_and(|c| c.is_ascii_digit())
        })
    })
}

/// Classify a log line into an observable event.
///
/// Unrecognised lines are ignored rather than counted as failures: treating
/// every unparsed line as an error produces an alert on the first unusual log
/// format and trains the operator to ignore the report.
fn classify(line: &str) -> Option<EventKind> {
    let lower = line.to_lowercase();

    if has_status(&lower, 401)
        || lower.contains("unauthorized")
        || lower.contains("invalid_token")
        || lower.contains("token expired")
        || lower.contains("authentication failed")
    {
        return Some(EventKind::AuthFailure);
    }
    if lower.contains("non-public address")
        || lower.contains("refusing to fetch")
        || lower.contains("ssrf")
    {
        return Some(EventKind::EgressBlocked);
    }
    if lower.contains("error") || lower.contains("panicked") || lower.contains(" failed") {
        return Some(EventKind::Failure);
    }
    None
}

fn collect_logs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut logs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().map(|ext| ext == "log").unwrap_or(false))
        .collect();
    logs.sort();
    logs
}

fn report(alerts: &[t3rnel_kernel::sentinel::Alert], lines: usize, files: usize, as_json: bool) {
    if as_json {
        let items: Vec<String> = alerts
            .iter()
            .map(|a| {
                format!(
                    r#"{{"finding":"{:?}","severity":"{:?}","subject":{:?},"detail":{:?}}}"#,
                    a.finding, a.severity, a.subject, a.detail
                )
            })
            .collect();
        println!(
            "{{\"scanned_files\":{files},\"scanned_lines\":{lines},\"alerts\":[{}]}}",
            items.join(",")
        );
        return;
    }

    println!("scanned {lines} lines across {files} log file(s)");
    if alerts.is_empty() {
        println!("no findings");
        return;
    }

    let mut by_finding: BTreeMap<String, usize> = BTreeMap::new();
    for alert in alerts {
        *by_finding
            .entry(format!("{:?}", alert.finding))
            .or_default() += 1;
    }

    println!();
    for alert in alerts {
        let marker = match alert.severity {
            Severity::Critical => "CRITICAL",
            Severity::Warning => "warning ",
            Severity::Info => "info    ",
        };
        let tag = if alert.finding.is_security() {
            " [security]"
        } else {
            ""
        };
        println!("{marker}{tag} {:<20} {}", alert.subject, alert.detail);
    }

    println!();
    for (finding, count) in by_finding {
        println!("{finding}: {count}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timestamp_containing_the_digits_is_not_a_status() {
        // 15:44:58.601401Z contains "401". Matching it as a substring turned
        // every log line written in the wrong microsecond into a critical
        // authentication failure.
        let line = "2026-08-04t15:44:58.601401z info fallback provider configured provider=gemini";
        assert!(!has_status(line, 401));
        assert!(classify(line).is_none() || classify(line) == Some(EventKind::Failure));
    }

    #[test]
    fn a_real_status_is_recognised() {
        for line in [
            "request failed with status 401",
            "http 401 returned by provider",
            "responded status=401",
        ] {
            assert!(has_status(line, 401), "should match: {line}");
        }
    }

    #[test]
    fn a_longer_code_starting_with_the_digits_is_not_a_match() {
        // 4010 is not 401.
        assert!(!has_status("status 4010", 401));
    }
}
