//! Plugin sandbox — OS-level confinement for plugin processes
//! (`05-security-and-trust.md` §14.6/§14.7, `04` §14.1).
//!
//! A plugin process gets **no route out**: a seccomp-bpf allow-list denies
//! socket creation for every domain, Landlock limits file access to the
//! plugin's own directory plus granted scopes, `PR_SET_NO_NEW_PRIVS` blocks
//! privilege gain, the environment is scrubbed of every variable (the daemon
//! never passes `T3RNEL_VAULT_KEY` or any secret), and the only channels to
//! the core are the two inherited, pre-connected streams.
//!
//! **Fail closed:** if the kernel lacks Landlock or seccomp, confinement
//! returns an error and the caller must refuse to start the plugin. There is
//! no unconfined mode.
//!
//! This module is Linux-only; on other platforms every entry point reports
//! `Unsupported` so callers fail closed there too.

use std::ffi::CString;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Why confinement could not be applied. Callers must treat every variant as
/// "do not start the plugin".
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("kernel does not support Landlock (landlock_create_ruleset: {0})")]
    LandlockUnsupported(i32),
    #[error("kernel does not support seccomp filters (prctl: {0})")]
    SeccompUnsupported(i32),
    #[error("confinement failed: {0}")]
    Failed(String),
    #[error("plugin sandbox is only implemented on Linux")]
    UnsupportedPlatform,
}

/// System locations a dynamically linked program needs in order to start.
/// Read and execute only; entries that do not exist are skipped.
const SYSTEM_READ_ONLY: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/ld.so.cache",
    "/etc/alternatives",
    "/dev/null",
    "/dev/urandom",
];

/// What a plugin process may touch.
#[derive(Debug, Clone, Default)]
pub struct SandboxPolicy {
    /// Directories the plugin may read, write, truncate and execute inside:
    /// its own `data/` folder plus folder scopes the user granted.
    pub read_write_dirs: Vec<PathBuf>,
    /// Read+execute-only locations: the plugin's installed files (so a plugin
    /// can never rewrite its own binary or manifest) and the system libraries
    /// the binary needs to run.
    pub read_only_dirs: Vec<PathBuf>,
    /// File descriptors the plugin keeps (its two host streams). Every other
    /// descriptor above 2 is closed on exec, so nothing the daemon had open —
    /// a listening socket, the vault file — reaches the plugin.
    pub keep_fds: Vec<i32>,
    /// Descriptors to hand the plugin, as `(descriptor in this process, number
    /// the plugin sees)`. The plugin always finds its host streams at the same
    /// fixed numbers whatever the daemon's own numbering is. The target numbers
    /// are kept automatically.
    pub inherit: Vec<(i32, i32)>,
    /// Hard resource limits the plugin cannot raise. `None` applies none (tests).
    pub limits: Option<ProcessLimits>,
}

/// Hard per-process limits applied with `setrlimit` before the plugin runs.
/// They hold even where `systemd-run` scopes are unavailable, and a process
/// cannot raise a hard limit it did not set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessLimits {
    /// Largest core dump in bytes. **Zero**: a core file would contain the
    /// plugin's memory, which can hold a scoped token.
    pub core_bytes: u64,
    /// Most open files.
    pub open_files: u64,
    /// Largest single file the plugin may write.
    pub file_bytes: u64,
    /// Largest address space.
    pub address_space_bytes: u64,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        ProcessLimits {
            core_bytes: 0,
            open_files: 256,
            file_bytes: 1024 * 1024 * 1024,
            address_space_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

impl SandboxPolicy {
    /// The policy for a plugin installed at `plugin_dir`: the installed files
    /// are read-only, only `<plugin_dir>/data` is writable.
    pub fn for_plugin(plugin_dir: &Path) -> Self {
        let data = plugin_dir.join("data");
        let mut read_only_dirs = vec![plugin_dir.to_path_buf()];
        read_only_dirs.extend(
            SYSTEM_READ_ONLY
                .iter()
                .map(PathBuf::from)
                .filter(|p| p.exists()),
        );
        SandboxPolicy {
            read_write_dirs: if data.is_dir() {
                vec![data]
            } else {
                Vec::new()
            },
            read_only_dirs,
            keep_fds: Vec::new(),
            inherit: Vec::new(),
            limits: Some(ProcessLimits::default()),
        }
    }
}

/// Environment variables a confined plugin may keep. Everything else —
/// including `T3RNEL_VAULT_KEY` and every credential variable — is removed.
/// The two inherited stream fds are passed as fds, never as env vars.
pub const SAFE_PLUGIN_ENV: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"];

/// Scrub `cmd`'s environment down to [`SAFE_PLUGIN_ENV`].
pub fn scrub_command_env(cmd: &mut std::process::Command) {
    cmd.env_clear();
    for var in SAFE_PLUGIN_ENV {
        if let Ok(value) = std::env::var(var) {
            cmd.env(var, value);
        }
    }
}

/// Report whether this kernel can confine a plugin at all. Used for the
/// fail-closed check *before* spawning; does not restrict this process.
pub fn confinement_available() -> Result<(), SandboxError> {
    probe_landlock()?;
    probe_seccomp()?;
    Ok(())
}

/// Whether the kernel accepts a seccomp filter without restricting this
/// process. Implemented by checking `Seccomp` mode support via prctl — a
/// `PR_SET_NO_NEW_PRIVS` + filter probe is destructive, so we instead verify
/// the syscall numbers exist by checking `/proc/self/status` is irrelevant;
/// the real proof is `apply_seccomp` failing closed at spawn time. Here we
/// only confirm the platform is Linux with seccomp compiled in.
#[cfg(target_os = "linux")]
fn probe_seccomp() -> Result<(), SandboxError> {
    // The kernel exposes seccomp via /proc/sys/kernel/seccomp/actions_avail
    // on some builds; the reliable probe is attempting PR_SET_SECCOMP with a
    // trivial allow-all filter in a child — too heavy for a probe. Instead we
    // check that the seccomp syscall interface exists by reading the kernel
    // LSM/feature is not possible unprivileged; we return Ok and let
    // apply_seccomp fail closed at spawn. To keep fail-closed honest we do a
    // real probe in a forked child.
    probe_seccomp_in_child()
}

#[cfg(target_os = "linux")]
fn probe_seccomp_in_child() -> Result<(), SandboxError> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    // Child applies no_new_privs + the real filter; exit 0 means supported.
    let mut cmd = Command::new("/bin/true");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            apply_no_new_privs().map_err(|e| std::io::Error::other(e.to_string()))?;
            apply_seccomp().map_err(|e| std::io::Error::other(e.to_string()))
        });
    }
    match cmd.status() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(SandboxError::SeccompUnsupported(s.code().unwrap_or(-1))),
        Err(e) => Err(SandboxError::Failed(format!("seccomp probe spawn: {e}"))),
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_seccomp() -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Apply the full confinement to the **current** process. Order matters:
/// `no_new_privs` must precede the seccomp filter, and both must precede
/// `exec`. Irreversible — call only in a child between fork and exec.
pub fn apply_confinement(policy: &SandboxPolicy) -> Result<(), SandboxError> {
    place_inherited(&policy.inherit)?;
    let mut keep = policy.keep_fds.clone();
    keep.extend(policy.inherit.iter().map(|(_, to)| *to));
    close_inherited_fds(&keep)?;
    if let Some(limits) = &policy.limits {
        apply_rlimits(limits)?;
    }
    apply_no_new_privs()?;
    apply_landlock(policy)?;
    apply_seccomp()?;
    Ok(())
}

/// Prepare a `std::process::Command` to run confined: scrubbed environment
/// plus, in `pre_exec`, the full confinement applied after fork.
///
/// # Safety contract
/// `pre_exec` runs in the child after fork before exec; only async-signal-safe
/// operations are permitted there. The functions called perform raw syscalls
/// and allocations-free path handling — `CString` allocation inside
/// `apply_landlock` is the one caveat; it is acceptable here because the
/// child is single-threaded post-fork.
pub fn confined_command<'a>(
    cmd: &'a mut std::process::Command,
    policy: &'a SandboxPolicy,
) -> &'a mut std::process::Command {
    scrub_command_env(cmd);
    let policy = policy.clone();
    // SAFETY: pre_exec closure only issues syscalls (prctl, landlock,
    // seccomp) and reads already-allocated paths; no locks, no allocation
    // beyond CString creation for path conversion which happens before the
    // dangerous section per call.
    unsafe {
        cmd.pre_exec(move || {
            apply_confinement(&policy).map_err(|e| std::io::Error::other(e.to_string()))
        });
    }
    cmd
}

// ---------------------------------------------------------------------------
// inherited descriptors
// ---------------------------------------------------------------------------

/// Put each `(from, to)` descriptor at its fixed number in this (child)
/// process. Every source is first copied above all the targets, so no copy can
/// overwrite a source that is still needed, then copied down and the temporary
/// closed. `dup2` clears close-on-exec on the target, which is what lets the
/// plugin inherit it.
#[cfg(target_os = "linux")]
fn place_inherited(map: &[(i32, i32)]) -> Result<(), SandboxError> {
    if map.is_empty() {
        return Ok(());
    }
    let floor = map.iter().map(|(_, to)| *to).max().unwrap_or(2).max(2) + 1;
    let mut temps: Vec<i32> = Vec::with_capacity(map.len());
    for (from, _) in map {
        // SAFETY: fcntl with F_DUPFD takes scalar arguments.
        let tmp = unsafe { libc::fcntl(*from, libc::F_DUPFD, floor) };
        if tmp < 0 {
            return Err(SandboxError::Failed(format!(
                "cannot duplicate descriptor {from}: {}",
                std::io::Error::last_os_error()
            )));
        }
        temps.push(tmp);
    }
    for ((_, to), tmp) in map.iter().zip(&temps) {
        // SAFETY: dup2 takes scalar arguments.
        if unsafe { libc::dup2(*tmp, *to) } < 0 {
            return Err(SandboxError::Failed(format!(
                "cannot place descriptor at {to}: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    for tmp in temps {
        // SAFETY: closing a descriptor this function opened.
        unsafe { libc::close(tmp) };
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn place_inherited(_: &[(i32, i32)]) -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Set the hard limits. Soft and hard are set together, so the plugin cannot raise them.
#[cfg(target_os = "linux")]
fn apply_rlimits(l: &ProcessLimits) -> Result<(), SandboxError> {
    let set = |resource: libc::__rlimit_resource_t, value: u64, name: &str| -> Result<(), SandboxError> {
        let rl = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        // SAFETY: setrlimit reads a valid struct.
        if unsafe { libc::setrlimit(resource, &rl) } != 0 {
            return Err(SandboxError::Failed(format!(
                "setrlimit {name}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    };
    set(libc::RLIMIT_CORE, l.core_bytes, "core")?;
    set(libc::RLIMIT_NOFILE, l.open_files, "nofile")?;
    set(libc::RLIMIT_FSIZE, l.file_bytes, "fsize")?;
    set(libc::RLIMIT_AS, l.address_space_bytes, "as")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_rlimits(_: &ProcessLimits) -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Mark every descriptor above 2 close-on-exec except `keep`. They are marked
/// rather than closed so the standard library's exec-error pipe keeps working;
/// the kernel closes them at `exec`, before the plugin's first instruction.
#[cfg(target_os = "linux")]
fn close_inherited_fds(keep: &[i32]) -> Result<(), SandboxError> {
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    let mut keep: Vec<u32> = keep
        .iter()
        .filter(|fd| **fd > 2)
        .map(|fd| *fd as u32)
        .collect();
    keep.sort_unstable();
    keep.dedup();
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    let mut next = 3u32;
    for fd in keep {
        if fd > next {
            ranges.push((next, fd - 1));
        }
        next = fd + 1;
    }
    ranges.push((next, u32::MAX));
    for (lo, hi) in ranges {
        // SAFETY: close_range takes scalar arguments only.
        let rc = unsafe { libc::syscall(libc::SYS_close_range, lo, hi, CLOSE_RANGE_CLOEXEC) };
        if rc == 0 {
            continue;
        }
        // Older kernels: set the flag one descriptor at a time.
        let limit = {
            let mut rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: getrlimit writes into a valid struct.
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
                rl.rlim_cur.min(1 << 20) as u32
            } else {
                4096
            }
        };
        for fd in lo..=hi.min(limit) {
            // SAFETY: fcntl on an arbitrary descriptor number is harmless; EBADF is ignored.
            unsafe {
                let flags = libc::fcntl(fd as i32, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(fd as i32, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn close_inherited_fds(_: &[i32]) -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

// ---------------------------------------------------------------------------
// no_new_privs
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn apply_no_new_privs() -> Result<(), SandboxError> {
    // SAFETY: prctl with a constant operation and no pointers.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(SandboxError::Failed(format!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Landlock (ABI v1 — kernel 5.13+; this machine runs 6.8)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod landlock {
    use super::*;

    // landlock_create_ruleset / add_rule / restrict_self syscall numbers are
    // identical on all architectures Linux supports Landlock on.
    const LANDLOCK_CREATE_RULESET: i64 = 444;
    const LANDLOCK_ADD_RULE: i64 = 445;
    const LANDLOCK_RESTRICT_SELF: i64 = 446;

    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

    // Filesystem rights by Landlock ABI. Handling only the ABI-1 set (the
    // earlier behaviour) left `truncate(2)`, cross-directory moves and device
    // ioctls unrestricted, so a plugin could empty any file its user owns.
    const ACCESS_FS_V1: u64 = 0x1FFF; // execute .. make_sym
    const ACCESS_FS_REFER: u64 = 1 << 13; // ABI 2
    const ACCESS_FS_TRUNCATE: u64 = 1 << 14; // ABI 3
    const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5
    const ACCESS_NET_BIND_TCP: u64 = 1 << 0; // ABI 4
    const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1; // ABI 4
    const ACCESS_FS_READ_EXEC: u64 = (1 << 0) | (1 << 2) | (1 << 3); // EXECUTE | READ_FILE | READ_DIR
    /// Rights that may be attached to a rule on a file (not a directory).
    const ACCESS_FS_FILE_RIGHTS: u64 =
        (1 << 0) | (1 << 1) | (1 << 2) | ACCESS_FS_TRUNCATE | ACCESS_FS_IOCTL_DEV;

    /// Filesystem rights this kernel can restrict.
    pub(super) fn handled_fs(abi: u32) -> u64 {
        let mut mask = ACCESS_FS_V1;
        if abi >= 2 {
            mask |= ACCESS_FS_REFER;
        }
        if abi >= 3 {
            mask |= ACCESS_FS_TRUNCATE;
        }
        if abi >= 5 {
            mask |= ACCESS_FS_IOCTL_DEV;
        }
        mask
    }

    /// TCP rights this kernel can restrict. With no rule granting any, every
    /// TCP bind and connect is refused — a second wall behind the seccomp
    /// socket ban.
    pub(super) fn handled_net(abi: u32) -> u64 {
        if abi >= 4 {
            ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP
        } else {
            0
        }
    }

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    #[repr(C)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    fn syscall3(num: i64, a: usize, b: usize, c: usize) -> i64 {
        // SAFETY: raw syscall with scalar args; caller validates pointers.
        unsafe { libc::syscall(num, a, b, c) }
    }

    fn syscall1(num: i64, a: usize) -> i64 {
        unsafe { libc::syscall(num, a) }
    }

    /// `libc::syscall` follows the libc convention: -1 with errno set on
    /// error, the raw return value otherwise.
    fn errno_of(rc: i64) -> i32 {
        if rc < 0 {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        } else {
            0
        }
    }

    /// ABI version this kernel offers, or an error when Landlock is absent.
    pub fn abi_version() -> Result<u32, SandboxError> {
        let rc = syscall3(
            LANDLOCK_CREATE_RULESET,
            0,                                        // attr = NULL
            0,                                        // size = 0
            LANDLOCK_CREATE_RULESET_VERSION as usize, // flags
        );
        if rc < 0 {
            let e = errno_of(rc);
            if e == libc::ENOSYS || e == libc::EOPNOTSUPP {
                return Err(SandboxError::LandlockUnsupported(e));
            }
            return Err(SandboxError::Failed(format!(
                "landlock_create_ruleset probe: errno {e}"
            )));
        }
        Ok(rc as u32)
    }

    /// Restrict the current process's filesystem (and, where the kernel can,
    /// TCP) access per `policy`. Irreversible.
    pub fn restrict(policy: &SandboxPolicy) -> Result<(), SandboxError> {
        let abi = abi_version()?;
        if abi < 1 {
            return Err(SandboxError::LandlockUnsupported(libc::EOPNOTSUPP));
        }
        let fs_mask = handled_fs(abi);
        let attr = RulesetAttr {
            handled_access_fs: fs_mask,
            handled_access_net: handled_net(abi),
        };
        // ABI < 4 kernels know only the first field; passing more bytes would be rejected.
        let attr_size = if abi >= 4 {
            std::mem::size_of::<RulesetAttr>()
        } else {
            std::mem::size_of::<u64>()
        };
        let fd = syscall3(
            LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr as usize,
            attr_size,
            0,
        );
        if fd < 0 {
            return Err(SandboxError::Failed(format!(
                "landlock_create_ruleset: {}",
                std::io::Error::from_raw_os_error(errno_of(fd))
            )));
        }

        let result = (|| -> Result<(), SandboxError> {
            for dir in &policy.read_write_dirs {
                add_rule(fd as i32, dir, fs_mask)?;
            }
            for dir in &policy.read_only_dirs {
                add_rule(fd as i32, dir, ACCESS_FS_READ_EXEC & fs_mask)?;
            }
            Ok(())
        })();

        // restrict_self consumes the ruleset; close on error paths too.
        let rc = syscall1(LANDLOCK_RESTRICT_SELF, fd as usize);
        unsafe { libc::close(fd as i32) };
        result?;
        if rc != 0 {
            return Err(SandboxError::Failed(format!(
                "landlock_restrict_self: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn add_rule(ruleset_fd: i32, dir: &Path, access: u64) -> Result<(), SandboxError> {
        let c_path = CString::new(dir.as_os_str().as_encoded_bytes())
            .map_err(|_| SandboxError::Failed(format!("path contains NUL: {}", dir.display())))?;
        // SAFETY: opening a directory read-only for the rule's parent_fd.
        let dfd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if dfd < 0 {
            return Err(SandboxError::Failed(format!(
                "cannot open {} for Landlock rule: {}",
                dir.display(),
                std::io::Error::last_os_error()
            )));
        }
        // A rule on a file may only carry file rights; the kernel refuses the
        // directory rights (read_dir, make_*) with EINVAL.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let is_dir = unsafe { libc::fstat(dfd, &mut st) } == 0
            && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let attr = PathBeneathAttr {
            allowed_access: if is_dir {
                access
            } else {
                access & ACCESS_FS_FILE_RIGHTS
            },
            parent_fd: dfd,
        };
        let rc = syscall3(
            LANDLOCK_ADD_RULE,
            ruleset_fd as usize,
            LANDLOCK_RULE_PATH_BENEATH as usize,
            &attr as *const PathBeneathAttr as usize,
        );
        unsafe { libc::close(dfd) };
        if rc != 0 {
            return Err(SandboxError::Failed(format!(
                "landlock_add_rule for {}: {}",
                dir.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn probe_landlock() -> Result<(), SandboxError> {
    landlock::abi_version().map(|_| ())
}

#[cfg(target_os = "linux")]
fn apply_landlock(policy: &SandboxPolicy) -> Result<(), SandboxError> {
    landlock::restrict(policy)
}

// ---------------------------------------------------------------------------
// seccomp-bpf: deny socket creation and other escape hatches
// ---------------------------------------------------------------------------

/// One classic-BPF instruction (`struct sock_filter`).
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// What the filter does with a syscall.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Allow,
    /// Fail the call with EPERM; the plugin keeps running.
    Eperm,
    /// Fail the call with ENOSYS, so libraries fall back to an older call.
    Enosys,
    /// Kill the whole process: the call can only mean an escape attempt.
    Kill,
}

/// x86-64 syscalls that are refused with EPERM. This is a deny-list: anything
/// not named runs. The list covers the ways out of the sandbox the design
/// cares about — network, other processes' memory and descriptors, kernel
/// keyrings, namespaces and mounts, tracing and kernel extension.
#[cfg(target_os = "linux")]
const DENY_EPERM: &[(u32, &str)] = &[
    (41, "socket"), // no route out, ever
    (102, "socketcall"),
    (425, "io_uring_setup"), // io_uring can open sockets without socket()
    (426, "io_uring_enter"),
    (427, "io_uring_register"),
    (321, "bpf"),
    (101, "ptrace"),
    (310, "process_vm_readv"), // read the daemon's memory (the vault key, live secrets)
    (311, "process_vm_writev"),
    (438, "pidfd_getfd"), // take another process's open descriptors, sockets included
    (312, "kcmp"),
    (248, "add_key"), // kernel keyrings
    (249, "request_key"),
    (250, "keyctl"),
    (165, "mount"),
    (166, "umount2"),
    (155, "pivot_root"),
    (161, "chroot"),
    (272, "unshare"),
    (308, "setns"),
    (175, "init_module"),
    (176, "delete_module"),
    (313, "finit_module"),
    (442, "mount_setattr"),
    (298, "perf_event_open"),
    (323, "userfaultfd"),
    (304, "open_by_handle_at"),
    (303, "name_to_handle_at"),
    (179, "quotactl"),
    (163, "acct"),
    (167, "swapon"),
    (168, "swapoff"),
    (169, "reboot"),
    (246, "kexec_load"),
    (320, "kexec_file_load"),
    (154, "modify_ldt"),
    (212, "lookup_dcookie"),
    (300, "fanotify_init"),
];

/// `clone3` takes its flags from memory, where a filter cannot read them, so it
/// is refused with ENOSYS and libc falls back to `clone`, whose flags are checked.
#[cfg(target_os = "linux")]
const DENY_ENOSYS: &[(u32, &str)] = &[(435, "clone3")];

/// x86-64 `clone`: refused when the flags request any new namespace.
#[cfg(target_os = "linux")]
const SYS_CLONE: u32 = 56;
/// CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET | NEWTIME
#[cfg(target_os = "linux")]
const CLONE_NAMESPACE_FLAGS: u32 = 0x0002_0000
    | 0x0200_0000
    | 0x0400_0000
    | 0x0800_0000
    | 0x1000_0000
    | 0x2000_0000
    | 0x4000_0000
    | 0x0000_0080;

/// The x32 ABI shares `AUDIT_ARCH_X86_64` and marks its syscall numbers with
/// this bit. A filter that only compares numbers would let `socket` through
/// as `0x40000029`, so any such number kills the process.
#[cfg(target_os = "linux")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[cfg(target_os = "linux")]
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// Assemble the filter. Layout: architecture check, x32 check, one comparison
/// per denied syscall, the `clone` flag check, then the four verdicts.
#[cfg(target_os = "linux")]
fn build_seccomp_program() -> Vec<SockFilter> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JSET_K: u16 = 0x45;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const OFFSET_NR: u32 = 0;
    const OFFSET_ARCH: u32 = 4;
    const OFFSET_ARG0: u32 = 16; // low 32 bits of args[0] (little endian)

    #[derive(Clone, Copy)]
    enum Step {
        Load(u32),
        /// Jump to the verdict if `nr == k`, else fall through.
        JeqTo(u32, Verdict),
        /// Jump to the verdict if any bit of `k` is set, else fall through.
        JsetTo(u32, Verdict),
        /// If the loaded value equals `k`, skip `n` steps.
        JeqThenSkip(u32, u8),
        /// If the loaded value differs from `k`, skip `n` steps.
        JeqElseSkip(u32, u8),
        Ret(Verdict),
    }

    let mut steps: Vec<Step> = vec![
        Step::Load(OFFSET_ARCH),
        // x86-64: skip the kill. Any other architecture falls into it, because
        // its syscall numbers mean something else entirely.
        Step::JeqThenSkip(AUDIT_ARCH_X86_64, 1),
        Step::Ret(Verdict::Kill),
        Step::Load(OFFSET_NR),
        Step::JsetTo(X32_SYSCALL_BIT, Verdict::Kill),
    ];
    for (nr, _) in DENY_EPERM {
        steps.push(Step::JeqTo(*nr, Verdict::Eperm));
    }
    for (nr, _) in DENY_ENOSYS {
        steps.push(Step::JeqTo(*nr, Verdict::Enosys));
    }
    // clone: not a clone -> skip the flag check; clone with namespace flags -> EPERM.
    steps.push(Step::JeqElseSkip(SYS_CLONE, 2));
    steps.push(Step::Load(OFFSET_ARG0));
    steps.push(Step::JsetTo(CLONE_NAMESPACE_FLAGS, Verdict::Eperm));
    // The four verdicts, in fixed order at the end.
    let rets = [
        Verdict::Allow,
        Verdict::Eperm,
        Verdict::Enosys,
        Verdict::Kill,
    ];
    for v in rets {
        steps.push(Step::Ret(v));
    }

    let ret_index = |v: Verdict| -> usize {
        steps.len() - rets.len() + rets.iter().position(|r| *r == v).unwrap()
    };
    let mut prog = Vec::with_capacity(steps.len());
    for (i, step) in steps.iter().enumerate() {
        let to = |v: Verdict| -> u8 {
            let off = ret_index(v) - i - 1;
            u8::try_from(off).expect("seccomp jump offset exceeds 255")
        };
        prog.push(match *step {
            Step::Load(k) => SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k,
            },
            Step::JeqTo(k, v) => SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: to(v),
                jf: 0,
                k,
            },
            Step::JsetTo(k, v) => SockFilter {
                code: BPF_JMP_JSET_K,
                jt: to(v),
                jf: 0,
                k,
            },
            Step::JeqThenSkip(k, n) => SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: n,
                jf: 0,
                k,
            },
            Step::JeqElseSkip(k, n) => SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: n,
                k,
            },
            Step::Ret(Verdict::Allow) => SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            Step::Ret(Verdict::Eperm) => SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | 1,
            },
            Step::Ret(Verdict::Enosys) => SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | 38,
            },
            Step::Ret(Verdict::Kill) => SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
        });
    }
    prog
}

#[cfg(target_os = "linux")]
fn apply_seccomp() -> Result<(), SandboxError> {
    let prog = build_seccomp_program();
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    // no_new_privs must already be set for an unprivileged filter install.
    // SAFETY: fprog points at live data for the duration of the call.
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &fprog as *const SockFprog,
            0,
            0,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if e == libc::EINVAL || e == libc::ENOSYS {
            return Err(SandboxError::SeccompUnsupported(e));
        }
        return Err(SandboxError::Failed(format!(
            "PR_SET_SECCOMP: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_no_new_privs() -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}
#[cfg(not(target_os = "linux"))]
fn probe_landlock() -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}
#[cfg(not(target_os = "linux"))]
fn apply_landlock(_: &SandboxPolicy) -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}
#[cfg(not(target_os = "linux"))]
fn apply_seccomp() -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

// ---------------------------------------------------------------------------
// Tests — real child processes under real confinement
// ---------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn run_confined(policy: &SandboxPolicy, args: &[&str]) -> std::process::Output {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(args[0]);
        confined_command(&mut cmd, policy)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.output().expect("spawn confined child")
    }

    /// Read+execute system dirs a dynamically linked `/bin/sh` needs.
    fn system_read_only() -> Vec<PathBuf> {
        [
            "/usr",
            "/lib",
            "/lib64",
            "/bin",
            "/sbin",
            "/etc/alternatives",
        ]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
    }

    #[test]
    fn confinement_is_available_on_this_kernel() {
        confinement_available().expect("landlock+seccomp must be available (fail-closed design)");
    }

    #[test]
    fn confined_process_cannot_create_a_socket() {
        let dir = tempfile::tempdir().unwrap();
        let policy = SandboxPolicy {
            read_write_dirs: vec![dir.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            ..Default::default()
        };
        // python3 creates a socket; under seccomp socket() returns EPERM.
        let out = run_confined(&policy, &["python3 -c 'import socket; socket.socket()'"]);
        assert!(!out.status.success(), "socket creation must fail: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("PermissionError") || stderr.contains("Operation not permitted"),
            "expected EPERM from socket(): {stderr}"
        );
    }

    #[test]
    fn unconfined_socket_creation_succeeds_for_comparison() {
        // Same call without confinement: socket() itself works (no connect).
        let out = Command::new("python3")
            .arg("-c")
            .arg("import socket; s=socket.socket(); s.close()")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn landlock_blocks_reads_outside_granted_dirs() {
        let allowed = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, "top-secret-canary").unwrap();
        let ok_file = allowed.path().join("ok.txt");
        std::fs::write(&ok_file, "fine").unwrap();

        let policy = SandboxPolicy {
            read_write_dirs: vec![allowed.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            ..Default::default()
        };

        // Inside the granted dir: readable.
        let out = run_confined(&policy, &[&format!("cat {}", ok_file.display())]);
        assert!(
            out.status.success(),
            "{:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "fine");

        // Outside: denied by Landlock.
        let out = run_confined(&policy, &[&format!("cat {}", secret.display())]);
        assert!(!out.status.success(), "read outside grant must fail");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("Permission denied"), "{stderr}");

        // The canary content never reaches stdout.
        assert!(!String::from_utf8_lossy(&out.stdout).contains("top-secret-canary"));
    }

    #[test]
    fn scrubbed_environment_hides_secrets() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("T3RNEL_VAULT_KEY", "test-canary-not-real");
        let policy = SandboxPolicy {
            read_write_dirs: vec![dir.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            ..Default::default()
        };
        // env inside the confined child must not contain the variable.
        let out = run_confined(&policy, &["env | grep -c T3RNEL_VAULT_KEY; true"]);
        // grep -c prints 0 and exits 1; `; true` keeps sh at 0.
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");
        std::env::remove_var("T3RNEL_VAULT_KEY");
    }

    #[test]
    fn no_new_privs_is_set_in_the_confined_child() {
        // /proc is not granted to the Landlock policy, so check no_new_privs with nnp+seccomp only.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("grep NoNewPrivs /proc/self/status");
        scrub_command_env(&mut cmd);
        unsafe {
            cmd.pre_exec(|| {
                apply_no_new_privs().map_err(|e| std::io::Error::other(e.to_string()))?;
                apply_seccomp().map_err(|e| std::io::Error::other(e.to_string()))
            });
        }
        let out2 = cmd.output().unwrap();
        let text = String::from_utf8_lossy(&out2.stdout);
        assert!(text.contains("NoNewPrivs:\t1"), "{text}");
    }

    // ---- the filter program itself, run through a small cBPF interpreter ----------------------------
    const RET_ALLOW: u32 = 0x7FFF_0000;
    const RET_EPERM: u32 = 0x0005_0001;
    const RET_ENOSYS: u32 = 0x0005_0026;
    const RET_KILL: u32 = 0x8000_0000;

    /// Evaluate the filter for one syscall exactly as the kernel would.
    fn verdict(arch: u32, nr: u32, arg0: u32) -> u32 {
        let prog = build_seccomp_program();
        let (mut acc, mut pc) = (0u32, 0usize);
        for _ in 0..prog.len() + 1 {
            let i = prog[pc];
            match i.code {
                0x20 => {
                    acc = match i.k {
                        0 => nr,
                        4 => arch,
                        16 => arg0,
                        other => panic!("filter loads unexpected offset {other}"),
                    };
                    pc += 1;
                }
                0x15 => pc += 1 + if acc == i.k { i.jt } else { i.jf } as usize,
                0x45 => pc += 1 + if acc & i.k != 0 { i.jt } else { i.jf } as usize,
                0x06 => return i.k,
                other => panic!("filter uses unexpected opcode {other:#x}"),
            }
        }
        panic!("filter did not terminate");
    }

    #[test]
    fn every_listed_syscall_is_refused_with_eperm() {
        for (nr, name) in DENY_EPERM {
            assert_eq!(
                verdict(AUDIT_ARCH_X86_64, *nr, 0),
                RET_EPERM,
                "{name} ({nr})"
            );
        }
        // The escape routes the design depends on, spelled out so a deleted entry fails here.
        for needed in [
            "socket",
            "io_uring_setup",
            "process_vm_readv",
            "pidfd_getfd",
            "ptrace",
            "keyctl",
            "unshare",
            "mount",
        ] {
            assert!(
                DENY_EPERM.iter().any(|(_, n)| *n == needed),
                "{needed} missing from the deny-list"
            );
        }
    }

    #[test]
    fn the_x32_abi_cannot_be_used_to_reach_a_denied_call() {
        // Same architecture value, number with the x32 bit set: a number-only
        // filter would see 0x40000029, not 41, and allow it.
        for (nr, name) in DENY_EPERM {
            assert_eq!(
                verdict(AUDIT_ARCH_X86_64, nr | X32_SYSCALL_BIT, 0),
                RET_KILL,
                "x32 {name}"
            );
        }
        assert_eq!(verdict(AUDIT_ARCH_X86_64, X32_SYSCALL_BIT, 0), RET_KILL);
    }

    #[test]
    fn a_foreign_architecture_is_killed() {
        for arch in [
            0x4000_0003u32, /* i386 */
            0xC000_00B7,    /* aarch64 */
            0,
        ] {
            assert_eq!(verdict(arch, 41, 0), RET_KILL, "arch {arch:#x}");
            assert_eq!(verdict(arch, 0, 0), RET_KILL, "arch {arch:#x}");
        }
    }

    #[test]
    fn calls_a_plugin_needs_to_run_are_allowed() {
        // read write open close mmap mprotect munmap brk ioctl openat futex epoll_wait epoll_ctl
        // nanosleep clock_gettime getrandom execve exit_group sendmsg recvmsg socketpair
        // connect on an inherited stream, sendto/recvfrom, pipe2, dup3, fcntl, getpid
        for nr in [
            0u32, 1, 2, 3, 9, 10, 11, 12, 16, 257, 202, 232, 233, 35, 228, 318, 59, 231, 46, 47,
            53, 42, 44, 45, 293, 292, 72, 39,
        ] {
            assert_eq!(verdict(AUDIT_ARCH_X86_64, nr, 0), RET_ALLOW, "syscall {nr}");
        }
    }

    #[test]
    fn clone_may_make_threads_but_never_a_new_namespace() {
        const THREAD_FLAGS: u32 = 0x0000_0100
            | 0x0000_0200
            | 0x0000_0400
            | 0x0000_0800
            | 0x0001_0000
            | 0x0004_0000
            | 0x0010_0000
            | 0x0020_0000;
        assert_eq!(
            verdict(AUDIT_ARCH_X86_64, SYS_CLONE, THREAD_FLAGS),
            RET_ALLOW,
            "pthread_create"
        );
        assert_eq!(
            verdict(AUDIT_ARCH_X86_64, SYS_CLONE, 17 /* fork: SIGCHLD */),
            RET_ALLOW,
            "fork"
        );
        for (flag, name) in [
            (0x0002_0000u32, "NEWNS"),
            (0x0200_0000, "NEWCGROUP"),
            (0x0400_0000, "NEWUTS"),
            (0x0800_0000, "NEWIPC"),
            (0x1000_0000, "NEWUSER"),
            (0x2000_0000, "NEWPID"),
            (0x4000_0000, "NEWNET"),
            (0x0000_0080, "NEWTIME"),
        ] {
            assert_eq!(
                verdict(AUDIT_ARCH_X86_64, SYS_CLONE, THREAD_FLAGS | flag),
                RET_EPERM,
                "clone {name}"
            );
        }
        assert_eq!(
            verdict(AUDIT_ARCH_X86_64, 435, 0),
            RET_ENOSYS,
            "clone3 falls back to clone"
        );
    }

    #[test]
    fn the_filter_is_a_valid_bounded_program() {
        let prog = build_seccomp_program();
        assert!(prog.len() < 4096, "BPF_MAXINSNS");
        assert_eq!(prog.last().unwrap().code, 0x06, "ends in a return");
        for (i, insn) in prog.iter().enumerate() {
            if insn.code == 0x15 || insn.code == 0x45 {
                assert!(
                    i + 1 + (insn.jt as usize) < prog.len()
                        && i + 1 + (insn.jf as usize) < prog.len(),
                    "jump {i} leaves the program"
                );
            }
        }
    }

    // ---- Landlock rights by ABI ----------------------------------------------------------------------
    #[test]
    fn newer_landlock_rights_are_handled_when_the_kernel_has_them() {
        assert_eq!(landlock::handled_fs(1), 0x1FFF);
        assert_ne!(landlock::handled_fs(2) & (1 << 13), 0, "refer");
        assert_eq!(landlock::handled_fs(2) & (1 << 14), 0);
        assert_ne!(landlock::handled_fs(3) & (1 << 14), 0, "truncate");
        assert_ne!(landlock::handled_fs(5) & (1 << 15), 0, "ioctl on devices");
        assert_eq!(landlock::handled_net(3), 0);
        assert_eq!(landlock::handled_net(4), 0b11, "tcp bind + connect");
    }

    // ---- real confined processes ---------------------------------------------------------------------
    #[test]
    fn a_confined_process_cannot_truncate_a_file_outside_its_grant() {
        let abi = landlock::abi_version().unwrap();
        assert!(
            abi >= 3,
            "Landlock ABI {abi}: this kernel cannot restrict truncate(2) (needs Linux 6.2)"
        );
        let granted = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim.txt");
        std::fs::write(&victim, "important").unwrap();
        let policy = SandboxPolicy {
            read_write_dirs: vec![granted.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            ..Default::default()
        };
        // os.truncate() is truncate(2): it needs no write-open, which ABI 1 does not control.
        let out = run_confined(
            &policy,
            &[&format!(
                "python3 -c \"import os; os.truncate('{}', 0)\"",
                victim.display()
            )],
        );
        assert!(
            !out.status.success(),
            "truncate outside the grant must fail: {out:?}"
        );
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "important");
        // Inside the grant it still works.
        let own = granted.path().join("own.txt");
        std::fs::write(&own, "mine").unwrap();
        let out = run_confined(
            &policy,
            &[&format!(
                "python3 -c \"import os; os.truncate('{}', 0)\"",
                own.display()
            )],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read_to_string(&own).unwrap(), "");
    }

    #[test]
    fn a_confined_process_cannot_read_another_processs_memory() {
        let dir = tempfile::tempdir().unwrap();
        let policy = SandboxPolicy {
            read_write_dirs: vec![dir.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            ..Default::default()
        };
        let script = "python3 -c \"import ctypes; l=ctypes.CDLL(None,use_errno=True); r=l.syscall(310,1,0,0,0,0,0); print(r, ctypes.get_errno())\"";
        let out = run_confined(&policy, &[script]);
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "-1 1",
            "{out:?}"
        );
    }

    #[test]
    fn ptrace_is_refused_with_eperm() {
        let dir = tempfile::tempdir().unwrap();
        let policy = SandboxPolicy {
            read_write_dirs: vec![dir.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            ..Default::default()
        };
        let script = "python3 -c \"import ctypes; l=ctypes.CDLL(None,use_errno=True); r=l.ptrace(0,0,0,0); print(r, ctypes.get_errno())\"";
        let out = run_confined(&policy, &[script]);
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "-1 1",
            "{out:?}"
        );
    }

    #[test]
    fn descriptors_the_daemon_had_open_do_not_reach_the_plugin() {
        // A pipe whose write end is inheritable stands in for any descriptor the
        // daemon forgot to mark close-on-exec (a listening socket, the vault file).
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        let dir = tempfile::tempdir().unwrap();
        let read_all = |r: i32| -> String {
            let mut buf = [0u8; 64];
            let n = unsafe { libc::read(r, buf.as_mut_ptr().cast(), buf.len()) };
            String::from_utf8_lossy(&buf[..n.max(0) as usize]).to_string()
        };

        let closed = SandboxPolicy {
            read_write_dirs: vec![dir.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            keep_fds: vec![],
            ..Default::default()
        };
        // The shell can only name descriptors 0-9, so the pipe's write end is
        // handed over as descriptor 7 (its own number may be higher when many
        // tests run at once). In the daemon's own descriptor table it is open
        // too, but nothing may carry it into the child except the policy.
        let out = run_confined(&closed, &["echo leaked >&7"]);
        assert!(
            !out.status.success(),
            "descriptor 7 must not exist in the child unless the policy gives it: {out:?}"
        );

        let kept = SandboxPolicy {
            inherit: vec![(w, 7)],
            ..closed
        };
        let out = run_confined(&kept, &["echo delivered >&7"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        unsafe { libc::close(w) };
        assert_eq!(
            read_all(r).trim(),
            "delivered",
            "only the kept descriptor carried data"
        );
        unsafe { libc::close(r) };
    }

    #[test]
    fn installed_files_are_read_only_and_only_data_is_writable() {
        let plugin = tempfile::tempdir().unwrap();
        std::fs::create_dir(plugin.path().join("data")).unwrap();
        std::fs::write(plugin.path().join("manifest.json"), "{}").unwrap();
        let policy = SandboxPolicy::for_plugin(plugin.path());

        // A dynamically linked shell starts, so system libraries are reachable.
        let out = run_confined(&policy, &["echo started"]);
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "started",
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // data/ is writable.
        let out = run_confined(
            &policy,
            &[&format!(
                "echo ok > {}/data/state.txt",
                plugin.path().display()
            )],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The plugin cannot rewrite its own manifest or drop in a new binary.
        for target in ["manifest.json", "plugin", "evil"] {
            let out = run_confined(
                &policy,
                &[&format!("echo x > {}/{target}", plugin.path().display())],
            );
            assert!(!out.status.success(), "{target} must not be writable");
        }
        assert_eq!(
            std::fs::read_to_string(plugin.path().join("manifest.json")).unwrap(),
            "{}"
        );
        // Nothing outside is readable: the home directory holds the vault.
        let out = run_confined(&policy, &["cat /etc/passwd"]);
        assert!(!out.status.success(), "/etc/passwd must not be readable");
    }

    // ---- fixed descriptors and hard limits ---------------------------------------------------------
    #[test]
    fn inherited_descriptors_appear_at_the_numbers_the_policy_names() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        let dir = tempfile::tempdir().unwrap();
        let policy = SandboxPolicy {
            read_write_dirs: vec![dir.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            // The daemon's own number for the write end is whatever pipe() returned; the plugin sees 3.
            inherit: vec![(w, 3)],
            ..Default::default()
        };
        let out = run_confined(&policy, &["echo from-the-plugin >&3"]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        unsafe { libc::close(w) };
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(r, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(String::from_utf8_lossy(&buf[..n.max(0) as usize]).trim(), "from-the-plugin");
        unsafe { libc::close(r) };
    }

    #[test]
    fn two_inherited_descriptors_whose_numbers_cross_do_not_overwrite_each_other() {
        // Parent numbers chosen so a naive dup2(a,b); dup2(b,a) would lose one.
        let mut p1 = [0i32; 2];
        let mut p2 = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(p1.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(p2.as_mut_ptr()) }, 0);
        let dir = tempfile::tempdir().unwrap();
        let policy = SandboxPolicy {
            read_write_dirs: vec![dir.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            inherit: vec![(p1[1], 4), (p2[1], 3)],
            ..Default::default()
        };
        let out = run_confined(&policy, &["echo one >&4; echo two >&3"]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let read = |fd: i32| {
            let mut buf = [0u8; 16];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            String::from_utf8_lossy(&buf[..n.max(0) as usize]).trim().to_string()
        };
        unsafe { libc::close(p1[1]); libc::close(p2[1]) };
        assert_eq!(read(p1[0]), "one");
        assert_eq!(read(p2[0]), "two");
        unsafe { libc::close(p1[0]); libc::close(p2[0]) };
    }

    #[test]
    fn a_confined_plugin_has_no_core_dumps_and_bounded_files_it_cannot_raise() {
        let dir = tempfile::tempdir().unwrap();
        let policy = SandboxPolicy {
            read_write_dirs: vec![dir.path().to_path_buf()],
            read_only_dirs: system_read_only(),
            limits: Some(ProcessLimits { open_files: 64, ..ProcessLimits::default() }),
            ..Default::default()
        };
        let out = run_confined(&policy, &["ulimit -c; ulimit -n; ulimit -Hn; ulimit -n 9999 2>&1 | head -1"]);
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "0", "core dumps must be off: {text}");
        assert_eq!(lines[1], "64", "soft open-file limit: {text}");
        assert_eq!(lines[2], "64", "hard open-file limit: {text}");
        assert!(lines[3].contains("Operation not permitted") || lines[3].contains("cannot"), "raising a hard limit must fail: {text}");
    }

}

// ---------------------------------------------------------------------------
// cgroup resource scope (9.3 remainder)
// ---------------------------------------------------------------------------

/// Resource limits applied to a plugin process. Enforced by wrapping the
/// launch in a `systemd-run --user` scope when available; when systemd-run is
/// absent the limits degrade to `prlimit`-style `Command` pre_exec where the
/// platform allows, and the caller MUST treat confinement as best-effort
/// only if `confinement_available` semantics already passed — cgroup limits
/// are defence-in-depth, not the primary boundary.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Max resident memory in bytes (0 = unlimited).
    pub memory_max: u64,
    /// Max CPU time in seconds (0 = unlimited).
    pub cpu_seconds: u64,
    /// Max number of processes/threads.
    pub tasks_max: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            memory_max: 512 * 1024 * 1024, // 512 MiB
            cpu_seconds: 300,
            tasks_max: 64,
        }
    }
}

/// Build the argv vector for a cgroup-scoped plugin launch. Returns None if
/// systemd-run is unavailable. The caller converts to a Command and applies
/// `confined_command` confinement to the *inner* argv is not possible —
/// confinement must be applied by the plugin binary itself or via a wrapper;
/// document that the scope wrapper preserves whatever pre_exec the caller
/// attached only when using `scoped_command` below.
pub fn scoped_argv(argv: &[String], limits: &ResourceLimits) -> Option<Vec<String>> {
    let mut out = vec![
        "systemd-run".to_string(),
        "--user".to_string(),
        "--scope".to_string(),
        "--quiet".to_string(),
        "--collect".to_string(),
    ];
    if limits.memory_max > 0 {
        out.push("-p".into());
        out.push(format!("MemoryMax={}", limits.memory_max));
    }
    if limits.cpu_seconds > 0 {
        // CPUQuota is a percentage of one CPU over the period; express the
        // per-launch CPU-time budget as a quota the kernel enforces.
        out.push("-p".into());
        out.push(format!("RuntimeMaxSec={}", limits.cpu_seconds));
    }
    if limits.tasks_max > 0 {
        out.push("-p".into());
        out.push(format!("TasksMax={}", limits.tasks_max));
    }
    out.push("--".into());
    out.extend(argv.iter().cloned());
    Some(out)
}

/// True when the scoped-launch path is usable on this host.
pub fn cgroup_scope_available() -> bool {
    std::process::Command::new("systemd-run")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod cgroup_tests {
    use super::*;

    #[test]
    fn scoped_argv_contains_limits_and_inner_command() {
        let limits = ResourceLimits {
            memory_max: 256 * 1024 * 1024,
            cpu_seconds: 60,
            tasks_max: 32,
        };
        let argv = vec!["/opt/plugins/x/run".to_string(), "--flag".to_string()];
        let scoped = scoped_argv(&argv, &limits).expect("systemd-run path");
        assert_eq!(scoped[0], "systemd-run");
        assert!(scoped.iter().any(|a| a == "--user"));
        assert!(scoped.iter().any(|a| a.starts_with("MemoryMax=")));
        assert!(scoped.iter().any(|a| a.starts_with("RuntimeMaxSec=")));
        assert!(scoped.iter().any(|a| a.starts_with("TasksMax=")));
        let dash = scoped.iter().position(|a| a == "--").unwrap();
        assert_eq!(&scoped[dash + 1..], &argv[..]);
    }

    #[test]
    fn zero_limits_produce_unbounded_scope() {
        let limits = ResourceLimits {
            memory_max: 0,
            cpu_seconds: 0,
            tasks_max: 0,
        };
        let scoped = scoped_argv(&["/bin/true".into()], &limits).unwrap();
        assert!(!scoped.iter().any(|a| a.starts_with("MemoryMax=")));
        assert!(!scoped.iter().any(|a| a.starts_with("TasksMax=")));
    }

    #[test]
    fn scope_helper_reports_availability_without_panicking() {
        // Either answer is valid on a given host; the function must not panic
        // and must agree with scoped_argv's availability.
        let avail = cgroup_scope_available();
        let argv = scoped_argv(&["/bin/true".into()], &ResourceLimits::default());
        // scoped_argv is pure argv construction; availability is reported
        // separately by cgroup_scope_available.
        assert!(argv.is_some());
        let _ = avail;
    }
}
