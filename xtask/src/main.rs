//! Build automation tasks for the T3rnel workspace.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use t3rnel_runtime::plugin_sign::{package_plugin, ReleaseSigner};

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
    let mut args = std::env::args();
    let _program = args.next();
    let Some(command) = args.next() else {
        print_usage();
        return ExitCode::from(2);
    };

    match command.as_str() {
        "sync-upstream" => sync_upstream(),
        "plugin-keygen" => plugin_keygen(args.collect()),
        "plugin-sign" => plugin_sign(args.collect()),
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
    println!("  plugin-keygen    Generate a release plugin signing keypair");
    println!("  plugin-sign      Build + sign an installable plugin package");
}

/// `plugin-keygen --dir <dir>` — generate `release-signing.key`/`.pub`.
fn plugin_keygen(args: Vec<String>) -> ExitCode {
    let Some(dir) = flag_value(&args, "--dir") else {
        eprintln!("usage: cargo run -p xtask -- plugin-keygen --dir <key-dir>");
        return ExitCode::from(2);
    };
    match ReleaseSigner::generate(&PathBuf::from(&dir)) {
        Ok(signer) => {
            println!("release signing keypair written to {dir}");
            println!("signer pubkey (hex): {}", signer.pubkey_hex());
            println!(
                "add to config.toml: plugin_trusted_signers = [\"{}\"]",
                signer.pubkey_hex()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("plugin-keygen failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `plugin-sign --src <dir> --out <dir> (--key <key-file> | --key-env <VAR>) [--account-home <home>]`
fn plugin_sign(args: Vec<String>) -> ExitCode {
    let (Some(src), Some(out)) = (flag_value(&args, "--src"), flag_value(&args, "--out")) else {
        eprintln!(
            "usage: cargo run -p xtask -- plugin-sign --src <plugin-src-dir> \
             --out <package-out-dir> (--key <release-signing.key> | --key-env <VAR>) \
             [--account-home <t3rnel-home>]"
        );
        return ExitCode::from(2);
    };
    let (key, key_env) = (flag_value(&args, "--key"), flag_value(&args, "--key-env"));
    if key.is_none() == key_env.is_none() {
        eprintln!("plugin-sign: give exactly one of --key <file> or --key-env <VAR>");
        return ExitCode::from(2);
    }
    let account_home = flag_value(&args, "--account-home");
    let result = (|| -> anyhow::Result<()> {
        let signer = match (&key, &key_env) {
            (Some(file), _) => ReleaseSigner::load(std::path::Path::new(file))?,
            (None, Some(var)) => {
                let hex = std::env::var(var)
                    .map_err(|_| anyhow::anyhow!("environment variable {var} is not set"))?;
                ReleaseSigner::from_seed_hex(&hex)?
            }
            (None, None) => unreachable!("checked above"),
        };
        let report = package_plugin(
            std::path::Path::new(&src),
            std::path::Path::new(&out),
            &signer,
            account_home.as_deref().map(std::path::Path::new),
        )?;
        println!("signed package: {} v{}", report.plugin_id, report.version);
        println!("  dir: {}", report.package_dir.display());
        println!("  signer: {}", report.signer_pubkey);
        println!("  account_bound: {}", report.account_bound);
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("plugin-sign failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
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
