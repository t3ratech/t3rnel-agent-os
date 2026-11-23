//! Build automation tasks for the T3rnel workspace.

use std::process::{Command, ExitCode};

const UPSTREAM_REMOTE: &str = "upstream";
const UPSTREAM_URL: &str = concat!(
    "https://github.com/",
    "RightNow",
    "-AI/",
    "open",
    "fang.git"
);
const PINNED_SHA: &str = "3cce1eb3fb19ad590a0937e039a8bf8bc09aba13";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return ExitCode::from(2);
    };

    match command.as_str() {
        "sync-upstream" => sync_upstream(),
        _ => {
            eprintln!("unknown xtask command: {command}");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    println!("Usage: cargo xtask <command>");
    println!();
    println!("Commands:");
    println!("  sync-upstream    Fetch pinned upstream and show non-applying diff guidance");
}

fn sync_upstream() -> ExitCode {
    if !git_remote_exists(UPSTREAM_REMOTE) {
        let status = Command::new("git")
            .args(["remote", "add", UPSTREAM_REMOTE, UPSTREAM_URL])
            .status();
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => return status_code(status.code()),
            Err(error) => {
                eprintln!("failed to add upstream remote: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    for args in [
        &["fetch", UPSTREAM_REMOTE, PINNED_SHA][..],
        &["diff", "--stat", "HEAD", "FETCH_HEAD"],
        &["log", "--oneline", "--decorate", "HEAD..FETCH_HEAD"],
    ] {
        let status = Command::new("git").args(args).status();
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => return status_code(status.code()),
            Err(error) => {
                eprintln!("failed to run git {}: {error}", args.join(" "));
                return ExitCode::FAILURE;
            }
        }
    }

    println!("Upstream fetched at {PINNED_SHA}. No changes were applied.");
    ExitCode::SUCCESS
}

fn git_remote_exists(name: &str) -> bool {
    Command::new("git")
        .args(["remote", "get-url", name])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn status_code(code: Option<i32>) -> ExitCode {
    match code.and_then(|code| u8::try_from(code).ok()) {
        Some(code) => ExitCode::from(code),
        None => ExitCode::FAILURE,
    }
}
