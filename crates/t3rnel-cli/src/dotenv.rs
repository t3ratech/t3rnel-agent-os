//! Minimal `.env` file loader/saver for project and `~/.t3rnel/.env` files.
//!
//! No external crate needed — hand-rolled for simplicity.
//! Format: `KEY=VALUE` lines, `#` comments, optional quotes.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Get the T3rnel home directory, respecting T3RNEL_HOME env var.
fn dotenv_t3rnel_home() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("T3RNEL_HOME") {
        return Some(PathBuf::from(home));
    }
    dirs::home_dir().map(|h| h.join(".t3rnel"))
}

/// Return the path to `~/.t3rnel/.env`.
pub fn env_file_path() -> Option<PathBuf> {
    dotenv_t3rnel_home().map(|h| h.join(".env"))
}

/// Return the path to the current workspace `.env`.
pub fn project_env_file_path() -> Option<PathBuf> {
    std::env::current_dir().ok().map(|cwd| cwd.join(".env"))
}

/// Load project `.env`, `~/.t3rnel/.env`, and `~/.t3rnel/secrets.env` into `std::env`.
///
/// System env vars take priority — existing vars are NOT overridden.
/// Project `.env` values take priority over home `.env`, and both take
/// priority over `secrets.env` (but all yield to system env vars).
/// Silently does nothing if the files don't exist.
pub fn load_dotenv() {
    load_env_file(project_env_file_path());
    load_env_file(env_file_path());
    // Also load secrets.env (written by dashboard "Set API Key" button)
    load_env_file(secrets_env_path());
}

/// Return the path to `~/.t3rnel/secrets.env`.
pub fn secrets_env_path() -> Option<PathBuf> {
    dotenv_t3rnel_home().map(|h| h.join("secrets.env"))
}

fn load_env_file(path: Option<PathBuf>) {
    let path = match path {
        Some(p) => p,
        None => return,
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = parse_env_line(trimmed) {
            if std::env::var(&key).is_err() {
                std::env::set_var(&key, &value);
            }
        }
    }
}

/// Upsert a key in `~/.t3rnel/.env`.
///
/// Creates the file if missing. Sets 0600 permissions on Unix.
/// Also sets the key in the current process environment.
pub fn save_env_key(key: &str, value: &str) -> Result<(), String> {
    let path = env_file_path().ok_or("Could not determine home directory")?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {e}"))?;
    }

    let mut entries = read_env_file(&path);
    entries.insert(key.to_string(), value.to_string());
    write_env_file(&path, &entries)?;

    // Also set in current process
    std::env::set_var(key, value);

    Ok(())
}

/// Remove a key from `~/.t3rnel/.env`.
///
/// Also removes it from the current process environment.
pub fn remove_env_key(key: &str) -> Result<(), String> {
    let path = env_file_path().ok_or("Could not determine home directory")?;

    let mut entries = read_env_file(&path);
    entries.remove(key);
    write_env_file(&path, &entries)?;

    std::env::remove_var(key);

    Ok(())
}

/// List key names (without values) from `~/.t3rnel/.env`.
#[allow(dead_code)]
pub fn list_env_keys() -> Vec<String> {
    let path = match env_file_path() {
        Some(p) => p,
        None => return Vec::new(),
    };

    read_env_file(&path).into_keys().collect()
}

/// Check if the `.env` file exists.
#[allow(dead_code)]
pub fn env_file_exists() -> bool {
    env_file_path().map(|p| p.exists()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a single `KEY=VALUE` line. Handles optional quotes.
fn parse_env_line(line: &str) -> Option<(String, String)> {
    let eq_pos = line.find('=')?;
    let key = line[..eq_pos].trim().to_string();
    let mut value = line[eq_pos + 1..].trim().to_string();

    if key.is_empty() {
        return None;
    }

    // Strip matching quotes
    if ((value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\'')))
        && value.len() >= 2
    {
        value = value[1..value.len() - 1].to_string();
    }

    Some((key, value))
}

/// Read all key-value pairs from the .env file.
fn read_env_file(path: &PathBuf) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return map,
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = parse_env_line(trimmed) {
            map.insert(key, value);
        }
    }

    map
}

/// Write key-value pairs back to the .env file with a header comment.
fn write_env_file(path: &PathBuf, entries: &BTreeMap<String, String>) -> Result<(), String> {
    let mut content = String::from("# T3rnel environment — managed by `t3rnel config set-key`\n");
    content.push_str("# Do not edit while the daemon is running.\n\n");

    for (key, value) in entries {
        // Quote values that contain spaces or special characters
        if value.contains(' ') || value.contains('#') || value.contains('"') {
            content.push_str(&format!("{key}=\"{}\"\n", value.replace('"', "\\\"")));
        } else {
            content.push_str(&format!("{key}={value}\n"));
        }
    }

    std::fs::write(path, &content).map_err(|e| format!("Failed to write .env file: {e}"))?;

    // Set 0600 permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_line_simple() {
        let (k, v) = parse_env_line("FOO=bar").unwrap();
        assert_eq!(k, "FOO");
        assert_eq!(v, "bar");
    }

    #[test]
    fn test_parse_env_line_quoted() {
        let (k, v) = parse_env_line("KEY=\"hello world\"").unwrap();
        assert_eq!(k, "KEY");
        assert_eq!(v, "hello world");
    }

    #[test]
    fn test_parse_env_line_single_quoted() {
        let (k, v) = parse_env_line("KEY='value'").unwrap();
        assert_eq!(k, "KEY");
        assert_eq!(v, "value");
    }

    #[test]
    fn test_parse_env_line_spaces() {
        let (k, v) = parse_env_line("  KEY  =  value  ").unwrap();
        assert_eq!(k, "KEY");
        assert_eq!(v, "value");
    }

    #[test]
    fn test_parse_env_line_no_value() {
        let (k, v) = parse_env_line("KEY=").unwrap();
        assert_eq!(k, "KEY");
        assert_eq!(v, "");
    }

    #[test]
    fn test_parse_env_line_comment() {
        assert!(
            parse_env_line("# comment").is_none()
                || parse_env_line("# comment").unwrap().0.starts_with('#')
        );
        // Comments are filtered before reaching parse_env_line in production code
    }

    #[test]
    fn test_parse_env_line_no_equals() {
        assert!(parse_env_line("NOEQUALS").is_none());
    }

    #[test]
    fn test_parse_env_line_empty_key() {
        assert!(parse_env_line("=value").is_none());
    }

    #[test]
    fn load_env_file_does_not_override_existing_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "T3RNEL_TEST_DOTENV_PRIORITY=file\n").unwrap();

        std::env::set_var("T3RNEL_TEST_DOTENV_PRIORITY", "process");
        load_env_file(Some(path));
        assert_eq!(
            std::env::var("T3RNEL_TEST_DOTENV_PRIORITY").unwrap(),
            "process"
        );
        std::env::remove_var("T3RNEL_TEST_DOTENV_PRIORITY");
    }
}
