//! Skill loader — loads and executes skills from various runtimes.

use crate::{SkillError, SkillManifest, SkillRuntime, SkillToolResult};
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error};

/// Execute a skill tool by spawning the appropriate runtime.
pub async fn execute_skill_tool(
    manifest: &SkillManifest,
    skill_dir: &Path,
    tool_name: &str,
    input: &serde_json::Value,
    meter: Option<&crate::metering::SkillMetering>,
) -> Result<SkillToolResult, SkillError> {
    // Verify the tool exists in the manifest
    let _tool_def = manifest
        .tools
        .provided
        .iter()
        .find(|t| t.name == tool_name)
        .ok_or_else(|| SkillError::NotFound(format!("Tool {tool_name} not in skill manifest")))?;

    let start = std::time::Instant::now();
    let skill_name = manifest.skill.name.clone();

    let result = match manifest.runtime.runtime_type {
        SkillRuntime::Python => {
            execute_python(skill_dir, &manifest.runtime.entry, tool_name, input).await
        }
        SkillRuntime::Node => {
            execute_node(skill_dir, &manifest.runtime.entry, tool_name, input).await
        }
        SkillRuntime::Shell => {
            execute_shell(skill_dir, &manifest.runtime.entry, tool_name, input).await
        }
        SkillRuntime::Wasm => {
            #[cfg(feature = "wasm")]
            {
                execute_wasm(skill_dir, &manifest.runtime.entry, tool_name, input).await
            }
            #[cfg(not(feature = "wasm"))]
            {
                Err(SkillError::RuntimeNotAvailable(
                    "WASM skill runtime not compiled — enable the `wasm` feature".to_string(),
                ))
            }
        }
        SkillRuntime::Builtin => Err(SkillError::RuntimeNotAvailable(
            "Builtin skills are handled by the kernel directly".to_string(),
        )),
        SkillRuntime::PromptOnly => {
            // Prompt-only skills inject context into the system prompt.
            // When a tool call arrives here, guide the LLM to use built-in tools.
            Ok(SkillToolResult {
                output: serde_json::json!({
                    "note": "Prompt-context skill — instructions are in your system prompt. Use built-in tools directly."
                }),
                is_error: false,
            })
        }
    };

    if let Some(m) = meter {
        m.record_invocation(&skill_name, start.elapsed().as_millis() as u64);
    }

    result
}

/// Execute a Python skill script.
async fn execute_python(
    skill_dir: &Path,
    entry: &str,
    tool_name: &str,
    input: &serde_json::Value,
) -> Result<SkillToolResult, SkillError> {
    let script_path = skill_dir.join(entry);
    if !script_path.exists() {
        return Err(SkillError::ExecutionFailed(format!(
            "Python script not found: {}",
            script_path.display()
        )));
    }

    // Build the JSON payload to send via stdin
    let payload = serde_json::json!({
        "tool": tool_name,
        "input": input,
    });

    let python = find_python().ok_or_else(|| {
        SkillError::RuntimeNotAvailable(
            "Python not found. Install Python 3.8+ to run Python skills.".to_string(),
        )
    })?;

    debug!(
        "Executing Python skill: {} {}",
        python,
        script_path.display()
    );

    let mut cmd = tokio::process::Command::new(&python);
    cmd.arg(&script_path)
        .current_dir(skill_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // SECURITY: Isolate environment to prevent secret leakage.
    // Skills are third-party code — they must not inherit API keys,
    // tokens, or credentials from the host environment.
    cmd.env_clear();
    // Preserve PATH for binary resolution and platform essentials
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    #[cfg(windows)]
    {
        if let Ok(sp) = std::env::var("SYSTEMROOT") {
            cmd.env("SYSTEMROOT", sp);
        }
        if let Ok(tmp) = std::env::var("TEMP") {
            cmd.env("TEMP", tmp);
        }
    }
    // Python needs PYTHONIOENCODING for UTF-8 output
    cmd.env("PYTHONIOENCODING", "utf-8");

    let mut child = cmd
        .spawn()
        .map_err(|e| SkillError::ExecutionFailed(format!("Failed to spawn Python: {e}")))?;

    // Write input to stdin
    if let Some(mut stdin) = child.stdin.take() {
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| SkillError::ExecutionFailed(format!("JSON serialize: {e}")))?;
        stdin
            .write_all(&payload_bytes)
            .await
            .map_err(|e| SkillError::ExecutionFailed(format!("Write stdin: {e}")))?;
        drop(stdin);
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| SkillError::ExecutionFailed(format!("Wait for Python: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Python skill failed: {stderr}");
        return Ok(SkillToolResult {
            output: serde_json::json!({ "error": stderr.to_string() }),
            is_error: true,
        });
    }

    // Parse stdout as JSON
    let stdout = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<serde_json::Value>(&stdout) {
        Ok(value) => Ok(SkillToolResult {
            output: value,
            is_error: false,
        }),
        Err(_) => Ok(SkillToolResult {
            output: serde_json::json!({ "result": stdout.trim() }),
            is_error: false,
        }),
    }
}

/// Execute a Node.js skill script.
async fn execute_node(
    skill_dir: &Path,
    entry: &str,
    tool_name: &str,
    input: &serde_json::Value,
) -> Result<SkillToolResult, SkillError> {
    let script_path = skill_dir.join(entry);
    if !script_path.exists() {
        return Err(SkillError::ExecutionFailed(format!(
            "Node.js script not found: {}",
            script_path.display()
        )));
    }

    let node = find_node().ok_or_else(|| {
        SkillError::RuntimeNotAvailable(
            "Node.js not found. Install Node.js 18+ to run Node skills.".to_string(),
        )
    })?;

    let payload = serde_json::json!({
        "tool": tool_name,
        "input": input,
    });

    debug!(
        "Executing Node.js skill: {} {}",
        node,
        script_path.display()
    );

    let mut cmd = tokio::process::Command::new(&node);
    cmd.arg(&script_path)
        .current_dir(skill_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // SECURITY: Isolate environment (same as Python — prevent secret leakage)
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    #[cfg(windows)]
    {
        if let Ok(sp) = std::env::var("SYSTEMROOT") {
            cmd.env("SYSTEMROOT", sp);
        }
        if let Ok(tmp) = std::env::var("TEMP") {
            cmd.env("TEMP", tmp);
        }
    }
    // Node needs NODE_PATH sometimes
    cmd.env("NODE_NO_WARNINGS", "1");

    let mut child = cmd
        .spawn()
        .map_err(|e| SkillError::ExecutionFailed(format!("Failed to spawn Node.js: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| SkillError::ExecutionFailed(format!("JSON serialize: {e}")))?;
        stdin
            .write_all(&payload_bytes)
            .await
            .map_err(|e| SkillError::ExecutionFailed(format!("Write stdin: {e}")))?;
        drop(stdin);
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| SkillError::ExecutionFailed(format!("Wait for Node.js: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(SkillToolResult {
            output: serde_json::json!({ "error": stderr.to_string() }),
            is_error: true,
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<serde_json::Value>(&stdout) {
        Ok(value) => Ok(SkillToolResult {
            output: value,
            is_error: false,
        }),
        Err(_) => Ok(SkillToolResult {
            output: serde_json::json!({ "result": stdout.trim() }),
            is_error: false,
        }),
    }
}

/// Find Python 3 binary.
fn find_python() -> Option<String> {
    for name in &["python3", "python"] {
        if std::process::Command::new(name)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            return Some(name.to_string());
        }
    }
    None
}

/// Find Node.js binary.
fn find_node() -> Option<String> {
    if std::process::Command::new("node")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
    {
        return Some("node".to_string());
    }
    None
}

/// Find Shell/Bash binary.
fn find_shell() -> Option<String> {
    // Try bash first, then sh as fallback
    for name in &["bash", "sh"] {
        if std::process::Command::new(name)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            return Some(name.to_string());
        }
    }
    None
}

/// Execute a Shell/Bash skill script.
async fn execute_shell(
    skill_dir: &Path,
    entry: &str,
    tool_name: &str,
    input: &serde_json::Value,
) -> Result<SkillToolResult, SkillError> {
    let script_path = skill_dir.join(entry);
    if !script_path.exists() {
        return Err(SkillError::ExecutionFailed(format!(
            "Shell script not found: {}",
            script_path.display()
        )));
    }

    // Build the JSON payload to send via stdin
    let payload = serde_json::json!({
        "tool": tool_name,
        "input": input,
    });

    let shell = find_shell().ok_or_else(|| {
        SkillError::RuntimeNotAvailable(
            "Shell/Bash not found. Install bash or sh to run Shell skills.".to_string(),
        )
    })?;

    debug!("Executing Shell skill: {} {}", shell, script_path.display());

    // Use -s to read from stdin, -c to execute command
    let mut cmd = tokio::process::Command::new(&shell);
    cmd.arg("-s")
        .arg(&script_path)
        .current_dir(skill_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // SECURITY: Isolate environment to prevent secret leakage.
    // Same as Python/Node — skills are third-party code.
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    #[cfg(windows)]
    {
        if let Ok(sp) = std::env::var("SYSTEMROOT") {
            cmd.env("SYSTEMROOT", sp);
        }
        if let Ok(tmp) = std::env::var("TEMP") {
            cmd.env("TEMP", tmp);
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| SkillError::ExecutionFailed(format!("Failed to spawn shell: {e}")))?;

    // Write input to stdin
    if let Some(mut stdin) = child.stdin.take() {
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| SkillError::ExecutionFailed(format!("JSON serialize: {e}")))?;
        stdin
            .write_all(&payload_bytes)
            .await
            .map_err(|e| SkillError::ExecutionFailed(format!("Write stdin: {e}")))?;
        drop(stdin);
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| SkillError::ExecutionFailed(format!("Wait for shell: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Shell skill failed: {stderr}");
        return Ok(SkillToolResult {
            output: serde_json::json!({ "error": stderr.to_string() }),
            is_error: true,
        });
    }

    // Parse stdout as JSON
    let stdout = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<serde_json::Value>(&stdout) {
        Ok(value) => Ok(SkillToolResult {
            output: value,
            is_error: false,
        }),
        Err(_) => Ok(SkillToolResult {
            output: serde_json::json!({ "result": stdout.trim() }),
            is_error: false,
        }),
    }
}

/// Execute a WASM skill tool using wasmtime (requires `wasm` feature).
///
/// The module is a WASI preview1 *command*: it receives the tool name in
/// `T3RNEL_TOOL_NAME` and the input JSON in `T3RNEL_TOOL_INPUT`, with the same
/// values as argv[1]/argv[2]. Its stdout is the tool result — parsed as JSON
/// when it is JSON and returned as text otherwise, the same contract the shell
/// runtime honours. stderr is captured for the error path.
///
/// The guest gets no host environment — `inherit_env` would hand a sandboxed
/// module every secret the daemon carries. stdout/stderr are bounded pipes and
/// the store runs on a fuel budget, so a guest can neither spray output nor
/// spin the host. Memory is WASI's own cap, not an explicit store limit: the
/// p1 store type does not accept a `ResourceLimiter`.
#[cfg(feature = "wasm")]
async fn execute_wasm(
    skill_dir: &Path,
    entry: &str,
    tool_name: &str,
    input: &serde_json::Value,
) -> Result<SkillToolResult, SkillError> {
    use std::time::Instant;
    use tokio::io::AsyncWrite;
    use wasmtime_wasi::cli::{IsTerminal, StdoutStream};
    use wasmtime_wasi::p1;
    use wasmtime_wasi::p2::pipe::MemoryOutputPipe;

    const STDOUT_CAP: usize = 4 * 1024 * 1024;
    const STDERR_CAP: usize = 256 * 1024;
    /// Fuel is an instruction budget, not wall time: generous enough for real
    /// work, hard enough that an infinite loop dies on its own.
    const FUEL: u64 = 2_000_000_000;

    /// WASI stdout/stderr backed by a bounded in-memory pipe.
    #[derive(Clone)]
    struct CapturedPipe(MemoryOutputPipe);
    impl IsTerminal for CapturedPipe {
        fn is_terminal(&self) -> bool {
            false
        }
    }
    impl StdoutStream for CapturedPipe {
        fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
            Box::new(self.0.clone())
        }
    }

    let wasm_path = skill_dir.join(entry);
    if !wasm_path.exists() {
        return Err(SkillError::NotFound(format!(
            "WASM module not found: {}",
            wasm_path.display()
        )));
    }

    let input_text = input.to_string();
    let start = Instant::now();

    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    let engine = wasmtime::Engine::new(&config)
        .map_err(|e| SkillError::ExecutionFailed(format!("wasmtime engine failed: {e}")))?;

    let mut linker = wasmtime::Linker::<p1::WasiP1Ctx>::new(&engine);
    p1::add_to_linker_sync(&mut linker, |t| t)
        .map_err(|e| SkillError::ExecutionFailed(format!("WASI linker failed: {e}")))?;

    let stdout_pipe = MemoryOutputPipe::new(STDOUT_CAP);
    let stderr_pipe = MemoryOutputPipe::new(STDERR_CAP);
    let wasi = wasmtime_wasi::WasiCtxBuilder::new()
        .stdout(CapturedPipe(stdout_pipe.clone()))
        .stderr(CapturedPipe(stderr_pipe.clone()))
        .env("T3RNEL_TOOL_NAME", tool_name)
        .env("T3RNEL_TOOL_INPUT", &input_text)
        .arg(tool_name)
        .arg(&input_text)
        .build_p1();

    let mut store = wasmtime::Store::new(&engine, wasi);
    store
        .set_fuel(FUEL)
        .map_err(|e| SkillError::ExecutionFailed(format!("wasm fuel budget failed: {e}")))?;

    let module = wasmtime::Module::from_file(&engine, &wasm_path)
        .map_err(|e| SkillError::ExecutionFailed(format!("WASM module load failed: {e}")))?;
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| SkillError::ExecutionFailed(format!("WASM instantiate failed: {e}")))?;
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .map_err(|_| {
            SkillError::ExecutionFailed(
                "WASM module exports no `_start` — skills ship WASI command modules".to_string(),
            )
        })?;

    let outcome = run.call(&mut store, ());
    let stdout = String::from_utf8_lossy(&stdout_pipe.contents()).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_pipe.contents()).into_owned();
    let elapsed = start.elapsed();
    debug!(tool = tool_name, elapsed_ms = elapsed.as_millis(), "wasm skill finished");

    let exit_code = match outcome {
        Ok(()) => 0,
        Err(trap) => match trap.downcast_ref::<wasmtime_wasi::I32Exit>() {
            // A WASI command exits through proc_exit, which surfaces as I32Exit —
            // code 0 is a clean exit, not a failure.
            Some(exit) => exit.0,
            None => {
                return Err(SkillError::ExecutionFailed(format!(
                    "WASM tool {tool_name} trapped: {trap}"
                )))
            }
        },
    };

    if exit_code != 0 {
        error!(tool = tool_name, code = exit_code, "wasm skill exited non-zero");
        return Ok(SkillToolResult {
            output: serde_json::json!({
                "error": format!("WASM tool exited with code {exit_code}"),
                "stderr": stderr.trim(),
            }),
            is_error: true,
        });
    }

    match serde_json::from_str::<serde_json::Value>(&stdout) {
        Ok(value) => Ok(SkillToolResult { output: value, is_error: false }),
        Err(_) => Ok(SkillToolResult {
            output: serde_json::json!({ "result": stdout.trim() }),
            is_error: false,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_python() {
        // Just ensure it doesn't panic — result depends on environment
        let _ = find_python();
    }

    #[test]
    fn test_find_node() {
        let _ = find_node();
    }

    /// A WASI command module that writes JSON to stdout — the same contract the
    /// shell runtime honours, so a wasm skill's stdout IS the tool result.
    #[cfg(feature = "wasm")]
    const WAT_JSON_ECHO: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 16) "{\"tool\":\"echo\",\"ok\":true}")
          (func (export "_start")
            (i32.store (i32.const 0) (i32.const 16))
            (i32.store (i32.const 4) (i32.const 25))
            (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 48)))))
    "#;

    /// A command module that exits non-zero — the caller must see a failure,
    /// not a pretend success.
    #[cfg(feature = "wasm")]
    const WAT_EXIT_3: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
          (func (export "_start") (call $proc_exit (i32.const 3))))
    "#;

    /// A command module that traps instead of exiting — a guest fault must
    /// surface as a named execution failure.
    #[cfg(feature = "wasm")]
    const WAT_TRAP: &str = r#"
        (module
          (func (export "_start") unreachable))
    "#;

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn wasm_command_stdout_is_the_tool_result() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tool.wat"), WAT_JSON_ECHO).unwrap();
        let result = execute_wasm(dir.path(), "tool.wat", "echo", &serde_json::json!({"x": 1}))
            .await
            .unwrap();
        assert!(!result.is_error, "clean exit reported an error: {result:?}");
        assert_eq!(result.output["ok"], serde_json::json!(true));
        assert_eq!(result.output["tool"], serde_json::json!("echo"));
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn wasm_nonzero_exit_is_an_error_not_a_scaffold() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tool.wat"), WAT_EXIT_3).unwrap();
        let result = execute_wasm(dir.path(), "tool.wat", "exit", &serde_json::json!({}))
            .await
            .unwrap();
        assert!(result.is_error, "exit code 3 reported success");
        assert!(result.output["error"].as_str().unwrap().contains("code 3"));
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn wasm_trap_fails_by_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tool.wat"), WAT_TRAP).unwrap();
        let err = execute_wasm(dir.path(), "tool.wat", "trap", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, SkillError::ExecutionFailed(_)));
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn wasm_missing_module_fails_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let err = execute_wasm(dir.path(), "absent.wasm", "echo", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, SkillError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_prompt_only_execution() {
        use crate::{
            SkillManifest, SkillMeta, SkillRequirements, SkillRuntimeConfig, SkillToolDef,
            SkillTools,
        };
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let manifest = SkillManifest {
            skill: SkillMeta {
                name: "test-prompt".to_string(),
                version: "0.1.0".to_string(),
                description: "A prompt-only test".to_string(),
                author: String::new(),
                license: String::new(),
                tags: vec![],
            },
            runtime: SkillRuntimeConfig {
                runtime_type: SkillRuntime::PromptOnly,
                entry: String::new(),
            },
            tools: SkillTools {
                provided: vec![SkillToolDef {
                    name: "test_tool".to_string(),
                    description: "Test".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                }],
            },
            requirements: SkillRequirements::default(),
            prompt_context: Some("You are a helpful assistant.".to_string()),
            source: None,
            config: std::collections::HashMap::new(),
        };

        let result = execute_skill_tool(
            &manifest,
            dir.path(),
            "test_tool",
            &serde_json::json!({}),
            None,
        )
        .await
        .unwrap();
        assert!(!result.is_error);
        let note = result.output["note"].as_str().unwrap();
        assert!(note.contains("system prompt"));
    }
}
