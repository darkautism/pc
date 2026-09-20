use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, process::Command};

const EXEC_ARG: &str = "__pc-sandbox-exec";
const SPEC_ENV: &str = "PC_SANDBOX_SPEC";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SandboxSpec {
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
    working_dir: PathBuf,
    namespace_root_base: PathBuf,
    network: bool,
}

#[derive(Debug)]
pub struct SafeSandbox {
    workspace: PathBuf,
    temp_dir: PathBuf,
    home_dir: PathBuf,
    namespace_root_base: PathBuf,
    read_only: Vec<PathBuf>,
    path: OsString,
    rustup_home: Option<PathBuf>,
    network: bool,
}

impl SafeSandbox {
    pub async fn start(
        workspace: &Path,
        temp_root: &Path,
        network: bool,
        protect_secrets: bool,
    ) -> anyhow::Result<Self> {
        let workspace = canonical_dir(workspace).context("canonicalize pc workspace")?;
        tokio::fs::create_dir_all(temp_root).await?;
        let temp_dir = canonical_dir(temp_root).context("canonicalize pc sandbox temp")?;
        let home_dir = temp_dir.join("home");
        let namespace_root_base = temp_dir.join("sandbox-roots");

        if namespace_root_base.exists() {
            tokio::fs::remove_dir_all(&namespace_root_base).await?;
        }
        for dir in [&home_dir, &namespace_root_base] {
            tokio::fs::create_dir_all(dir).await?;
            set_private_dir(dir).await?;
        }

        let host_path = std::env::var_os("PATH")
            .unwrap_or_else(|| OsString::from("/usr/local/bin:/usr/bin:/bin"));
        let mut read_only = BTreeSet::new();

        for path in ["/usr", "/bin", "/sbin", "/lib", "/lib64"] {
            if let Ok(path) = std::fs::canonicalize(path) {
                read_only.insert(path);
            }
        }
        for path in [
            "/etc/ld.so.cache",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/ssl",
            "/etc/ca-certificates",
        ] {
            if let Ok(path) = std::fs::canonicalize(path) {
                read_only.insert(path);
            }
        }

        let host_home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .and_then(|path| std::fs::canonicalize(path).ok());
        for dir in std::env::split_paths(&host_path) {
            if let Ok(dir) = std::fs::canonicalize(dir) {
                let broad_home = host_home
                    .as_ref()
                    .is_some_and(|home| dir == *home || home.starts_with(&dir));
                if !broad_home {
                    read_only.insert(dir);
                }
            }
        }

        let rustup_home = std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
            .filter(|path| path.exists())
            .and_then(|path| std::fs::canonicalize(path).ok());
        if let Some(path) = &rustup_home {
            read_only.insert(path.clone());
        }

        if !protect_secrets {
            if let Some(home) = host_home.as_ref() {
                for relative in [
                    ".ssh",
                    ".aws",
                    ".config/gh",
                    ".config/gcloud",
                    ".git-credentials",
                    ".netrc",
                    ".npmrc",
                    ".docker/config.json",
                    ".kube/config",
                ] {
                    let path = home.join(relative);
                    if path.exists() {
                        if let Ok(path) = std::fs::canonicalize(path) {
                            read_only.insert(path);
                        }
                    }
                }
            }
        }

        let sandbox = Self {
            workspace,
            temp_dir,
            home_dir,
            namespace_root_base,
            read_only: read_only.into_iter().collect(),
            path: host_path,
            rustup_home,
            network,
        };
        sandbox.probe().await?;
        Ok(sandbox)
    }

    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    pub fn visible_path(&self, raw: &str) -> PathBuf {
        let path = PathBuf::from(raw);
        if path.is_absolute() {
            path
        } else {
            self.workspace.join(path)
        }
    }

    pub fn command(&self, program: &str) -> anyhow::Result<Command> {
        let mut read_write = vec![
            self.workspace.clone(),
            self.temp_dir.clone(),
            self.home_dir.clone(),
        ];
        for device in [
            "/dev/null",
            "/dev/zero",
            "/dev/full",
            "/dev/random",
            "/dev/urandom",
        ] {
            if let Ok(path) = std::fs::canonicalize(device) {
                read_write.push(path);
            }
        }

        let spec = SandboxSpec {
            read_only: self.read_only.clone(),
            read_write,
            working_dir: self.workspace.clone(),
            namespace_root_base: self.namespace_root_base.clone(),
            network: self.network,
        };

        let mut command = Command::new(std::env::current_exe().context("resolve pc executable")?);
        command.arg(EXEC_ARG).arg(program);
        command.current_dir(&self.workspace);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.env_clear();
        command.env(SPEC_ENV, serde_json::to_string(&spec)?);
        command.env("PATH", &self.path);
        command.env("HOME", &self.home_dir);
        command.env("TMPDIR", &self.temp_dir);
        command.env("GIT_TERMINAL_PROMPT", "0");
        command.env("GIT_ASKPASS", "/bin/false");
        command.env("SSH_ASKPASS", "/bin/false");
        if let Some(rustup_home) = &self.rustup_home {
            command.env("RUSTUP_HOME", rustup_home);
        }
        for key in [
            "LANG",
            "LC_ALL",
            "TERM",
            "TZ",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_EXTRA_CA_CERTS",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        Ok(command)
    }

    pub fn bash_command(&self, command: &str) -> anyhow::Result<Command> {
        let mut child = self.command("/bin/bash")?;
        child.arg("-lc").arg(command);
        Ok(child)
    }

    pub async fn read_file(&self, raw: &str) -> anyhow::Result<Vec<u8>> {
        let path = self.visible_path(raw);
        let output = self
            .command("/bin/cat")?
            .arg("--")
            .arg(&path)
            .output()
            .await
            .with_context(|| format!("sandbox read {}", path.display()))?;
        if !output.status.success() {
            bail!(
                "sandbox read {}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output.stdout)
    }

    pub async fn write_file(&self, raw: &str, content: &[u8]) -> anyhow::Result<()> {
        let path = self.visible_path(raw);
        let mut child = self.command("/bin/sh")?;
        child
            .args([
                "-c",
                "mkdir -p -- \"$(dirname -- \"$1\")\" && cat > \"$1\"",
                "pc-write",
            ])
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = child
            .spawn()
            .with_context(|| format!("sandbox write {}", path.display()))?;
        child
            .stdin
            .take()
            .context("sandbox write stdin unavailable")?
            .write_all(content)
            .await
            .with_context(|| format!("sandbox write {}", path.display()))?;
        let output = child
            .wait_with_output()
            .await
            .with_context(|| format!("wait for sandbox write {}", path.display()))?;
        if !output.status.success() {
            bail!(
                "sandbox write {}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    async fn probe(&self) -> anyhow::Result<()> {
        let output = self
            .command("/bin/true")?
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("spawn embedded pc sandbox probe")?;
        if !output.status.success() {
            bail!(
                "pc safe sandbox unavailable (fail-closed): {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
}

pub fn maybe_handle_entrypoint() -> Option<anyhow::Result<()>> {
    let mut args = std::env::args_os();
    let _ = args.next();
    let mode = args.next()?;
    if mode == OsStr::new(EXEC_ARG) {
        return Some(sandbox_exec(args.collect()));
    }
    None
}

fn sandbox_exec(mut args: Vec<OsString>) -> anyhow::Result<()> {
    if args.is_empty() {
        bail!("pc sandbox helper missing program");
    }
    let program = args.remove(0);
    let raw = std::env::var(SPEC_ENV).context("pc sandbox helper missing policy")?;
    let spec: SandboxSpec = serde_json::from_str(&raw).context("parse pc sandbox policy")?;

    #[cfg(target_os = "linux")]
    if !spec.network {
        isolate_network()?;
    }

    enable_no_new_privs()?;
    apply_policy(&spec)?;
    drop_capabilities()?;

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(program);
        command.args(args).env_remove(SPEC_ENV);
        let error = command.exec();
        Err(error).context("exec sandboxed pc command")
    }
    #[cfg(not(unix))]
    {
        let _ = (program, args);
        bail!("embedded pc sandbox is only supported on Unix")
    }
}

#[cfg(target_os = "linux")]
fn prepare_gid_mapping(context: &str) -> anyhow::Result<bool> {
    let path = Path::new("/proc/self/setgroups");
    if !path.exists() {
        return Ok(true);
    }
    let current = std::fs::read_to_string(path)
        .with_context(|| format!("read setgroups state for {context}"))?;
    match current.trim() {
        "deny" => Ok(true),
        "allow" => match std::fs::write(path, b"deny\n") {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(false),
            Err(error) => Err(error).with_context(|| format!("disable setgroups for {context}")),
        },
        other => bail!("unexpected setgroups state for {context}: {other}"),
    }
}

#[cfg(target_os = "linux")]
fn root_in_noninitial_user_namespace() -> anyhow::Result<bool> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(false);
    }
    let uid_map = std::fs::read_to_string("/proc/self/uid_map")
        .context("read current user namespace uid_map")?;
    let mut fields = uid_map
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let inside = fields.next().and_then(|value| value.parse::<u64>().ok());
    let outside = fields.next().and_then(|value| value.parse::<u64>().ok());
    let length = fields.next().and_then(|value| value.parse::<u64>().ok());
    Ok(
        matches!((inside, outside, length), (Some(0), Some(host), Some(span)) if host != 0 || span != u32::MAX as u64),
    )
}

#[cfg(target_os = "linux")]
fn enter_rootless_user_namespace(context: &str) -> anyhow::Result<()> {
    use std::fs;

    if root_in_noninitial_user_namespace()? {
        return Ok(());
    }

    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        bail!(
            "unshare {context} user namespace failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let map_gid = prepare_gid_mapping(context)?;
    fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))
        .with_context(|| format!("write {context} uid_map"))?;
    if map_gid {
        fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))
            .with_context(|| format!("write {context} gid_map"))?;
        if unsafe { libc::setresgid(0, 0, 0) } != 0 {
            bail!(
                "setresgid inside {context} failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    if unsafe { libc::setresuid(0, 0, 0) } != 0 {
        bail!(
            "setresuid inside {context} failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn isolate_network() -> anyhow::Result<()> {
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0 {
        return Ok(());
    }
    enter_rootless_user_namespace("network namespace")?;
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        bail!(
            "unshare network namespace failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enable_no_new_privs() -> anyhow::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        bail!(
            "set pc sandbox no_new_privs failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enable_no_new_privs() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn drop_capabilities() -> anyhow::Result<()> {
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) } != 0 {
        bail!(
            "drop pc sandbox capabilities failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINVAL) {
            bail!("clear pc sandbox ambient capabilities failed: {error}");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_capabilities() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_policy(spec: &SandboxSpec) -> anyhow::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, path_beneath_rules,
    };

    let abi = ABI::V3;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(
            &spec.read_only,
            AccessFs::from_read(abi),
        ))?
        .add_rules(path_beneath_rules(
            &spec.read_write,
            AccessFs::from_all(abi),
        ))?
        .set_compatibility(CompatLevel::HardRequirement)
        .restrict_self()
        .context("apply Landlock filesystem policy")?;

    match status.ruleset {
        RulesetStatus::FullyEnforced if status.no_new_privs => {}
        RulesetStatus::NotEnforced => apply_namespace_fs_policy(spec)
            .context("Landlock unavailable and rootless namespace fallback failed")?,
        _ => bail!(
            "Landlock policy was only partially enforced; refusing ambiguous sandbox: {status:?}"
        ),
    }

    install_seccomp_denylist()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_namespace_fs_policy(spec: &SandboxSpec) -> anyhow::Result<()> {
    use std::{ffi::CString, fs, os::unix::ffi::OsStrExt, ptr};

    enter_rootless_user_namespace("filesystem namespace")?;

    let root = spec
        .namespace_root_base
        .join(format!("{}", unsafe { libc::getpid() }));
    if root.exists() {
        fs::remove_dir_all(&root)
            .with_context(|| format!("clear namespace root {}", root.display()))?;
    }
    fs::create_dir_all(&root)
        .with_context(|| format!("create namespace root {}", root.display()))?;

    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        bail!(
            "unshare mount namespace failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let slash = CString::new("/")?;
    if unsafe {
        libc::mount(
            ptr::null(),
            slash.as_ptr(),
            ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            ptr::null(),
        )
    } != 0
    {
        bail!(
            "make mount namespace private failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let root_c = c_path(&root)?;
    let tmpfs = CString::new("tmpfs")?;
    let data = CString::new("mode=0755,size=64m")?;
    if unsafe {
        libc::mount(
            tmpfs.as_ptr(),
            root_c.as_ptr(),
            tmpfs.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
            data.as_ptr().cast(),
        )
    } != 0
    {
        bail!(
            "mount sandbox tmpfs root failed: {}",
            std::io::Error::last_os_error()
        );
    }

    for source in &spec.read_only {
        bind_into_root(&root, source, true)?;
    }
    for source in &spec.read_write {
        bind_into_root(&root, source, false)?;
    }
    mirror_root_symlinks(&root)?;

    let old_root = root.join(".oldroot");
    fs::create_dir_all(&old_root)?;
    std::env::set_current_dir(&root).context("chdir to namespace root")?;
    let dot = CString::new(".")?;
    let old = CString::new(".oldroot")?;
    if unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), old.as_ptr()) } != 0 {
        bail!("pivot_root failed: {}", std::io::Error::last_os_error());
    }
    std::env::set_current_dir("/").context("chdir after pivot_root")?;
    let old_abs = CString::new("/.oldroot")?;
    if unsafe { libc::umount2(old_abs.as_ptr(), libc::MNT_DETACH) } != 0 {
        bail!(
            "detach old root failed: {}",
            std::io::Error::last_os_error()
        );
    }
    fs::remove_dir("/.oldroot").context("remove detached old root mountpoint")?;
    std::env::set_current_dir(&spec.working_dir)
        .with_context(|| format!("enter sandbox workspace {}", spec.working_dir.display()))?;
    return Ok(());

    fn c_path(path: &Path) -> anyhow::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).context("sandbox path contains NUL")
    }

    fn mirror_root_symlinks(root: &Path) -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;
        for name in ["bin", "sbin", "lib", "lib64"] {
            let host = Path::new("/").join(name);
            let metadata = match fs::symlink_metadata(&host) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("stat root alias {}", host.display()));
                }
            };
            if !metadata.file_type().is_symlink() {
                continue;
            }
            let target = fs::read_link(&host)
                .with_context(|| format!("read root alias {}", host.display()))?;
            let destination = root.join(name);
            if destination.exists() || fs::symlink_metadata(&destination).is_ok() {
                fs::remove_file(&destination)
                    .with_context(|| format!("replace root alias {}", destination.display()))?;
            }
            symlink(&target, &destination).with_context(|| {
                format!(
                    "mirror root alias {} -> {}",
                    destination.display(),
                    target.display()
                )
            })?;
        }
        Ok(())
    }

    fn bind_into_root(root: &Path, source: &Path, read_only: bool) -> anyhow::Result<()> {
        let metadata = fs::metadata(source)
            .with_context(|| format!("stat sandbox path {}", source.display()))?;
        let relative = source
            .strip_prefix("/")
            .with_context(|| format!("sandbox path must be absolute: {}", source.display()))?;
        let destination = root.join(relative);
        if metadata.is_dir() {
            fs::create_dir_all(&destination)?;
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            if !destination.exists() {
                fs::File::create(&destination)?;
            }
        }
        let source_c = c_path(source)?;
        let destination_c = c_path(&destination)?;
        let bind_flags = if metadata.is_dir() {
            libc::MS_BIND | libc::MS_REC
        } else {
            libc::MS_BIND
        };
        if unsafe {
            libc::mount(
                source_c.as_ptr(),
                destination_c.as_ptr(),
                std::ptr::null(),
                bind_flags as libc::c_ulong,
                std::ptr::null(),
            )
        } != 0
        {
            bail!(
                "bind mount {} -> {} failed: {}",
                source.display(),
                destination.display(),
                std::io::Error::last_os_error()
            );
        }

        if read_only {
            let remounted = unsafe {
                libc::mount(
                    std::ptr::null(),
                    destination_c.as_ptr(),
                    std::ptr::null(),
                    (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
                    std::ptr::null(),
                )
            } == 0;
            if !remounted {
                let writable = unsafe { libc::access(source_c.as_ptr(), libc::W_OK) } == 0;
                if writable {
                    bail!(
                        "read-only sandbox path is writable by pc: {}",
                        source.display()
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn install_seccomp_denylist() -> anyhow::Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, apply_filter};
    use std::convert::TryInto;

    let denied = [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_pidfd_send_signal,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
    ];
    let rules: BTreeSet<_> = denied.into_iter().collect();
    let rules = rules
        .into_iter()
        .map(|syscall| (syscall, vec![]))
        .collect::<std::collections::BTreeMap<i64, Vec<SeccompRule>>>();
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().map_err(|_| {
            anyhow::anyhow!(
                "unsupported seccomp architecture {}",
                std::env::consts::ARCH
            )
        })?,
    )?
    .try_into()?;
    apply_filter(&filter).context("install seccomp filter")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_policy(_spec: &SandboxSpec) -> anyhow::Result<()> {
    bail!("pc safe sandbox requires Linux; refusing to run unsandboxed")
}

fn canonical_dir(path: &Path) -> anyhow::Result<PathBuf> {
    std::fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))
}

#[cfg(unix)]
async fn set_private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_private_dir(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}
