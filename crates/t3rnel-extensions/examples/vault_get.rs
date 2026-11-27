//! Diagnostic helper: print a single vault entry value.
//! Usage: vault_get <key>
use std::path::PathBuf;

fn main() {
    let key = std::env::args().nth(1).expect("usage: vault_get <key>");
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let path = PathBuf::from(home).join(".t3rnel").join("vault.enc");
    let mut vault = t3rnel_extensions::vault::CredentialVault::new(path);
    if let Err(e) = vault.unlock() {
        eprintln!("unlock failed: {e}");
        std::process::exit(1);
    }
    match vault.get(&key) {
        Some(v) => println!("{}", v.as_str()),
        None => {
            eprintln!("key not found: {key}");
            std::process::exit(2);
        }
    }
}
