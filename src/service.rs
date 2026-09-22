use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, bail, ensure};
use clap::Subcommand;

const SYSTEMD_UNIT: &str = "pc.service";
const LAUNCHD_LABEL: &str = "io.github.darkautism.pc";

#[derive(Subcommand, Debug, Clone, Copy)]
pub enum ServiceAction {
    /// Install or update the user service and start it.
    Install,
    /// Start the installed user service.
    Start,
    /// Stop the installed user service.
    Stop,
    /// Restart the installed user service.
    Restart,
    /// Show native service-manager status.
    Status,
    /// Stop and remove the user service.
    Uninstall,
}

#[derive(Debug)]
struct ServiceSpec {
    binary: PathBuf,
    user_home: PathBuf,
    environment: Vec<(String, String)>,
}

pub fn run(action: ServiceAction, explicit_home: Option<&Path>) -> anyhow::Result<()> {
    let spec = ServiceSpec::resolve(explicit_home)?;

    #[cfg(target_os = "linux")]
    {
        return linux::run(action, &spec);
    }

    #[cfg(target_os = "macos")]
    {
        return macos::run(action, &spec);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (action, spec);
        bail!("pc service management currently supports Linux systemd and macOS launchd")
    }
}

impl ServiceSpec {
    fn resolve(explicit_home: Option<&Path>) -> anyhow::Result<Self> {
        let binary = std::env::current_exe().context("resolve current pc executable")?;
        let user_home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .context("HOME is required for user service installation")?;
        let raw_pc_home = explicit_home
            .map(PathBuf::from)
            .unwrap_or(crate::config::default_home()?);
        let pc_home = absolute_path(raw_pc_home)?;
        let environment = service_environment(&pc_home);

        validate_line_value("pc executable", &binary.to_string_lossy())?;
        validate_line_value("PC_HOME", &pc_home.to_string_lossy())?;
        validate_line_value("HOME", &user_home.to_string_lossy())?;
        for (key, value) in &environment {
            validate_line_value(key, value)?;
        }

        Ok(Self {
            binary,
            user_home,
            environment,
        })
    }
}

fn absolute_path(path: PathBuf) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .context("resolve current directory")?
            .join(path))
    }
}

fn service_environment(pc_home: &Path) -> Vec<(String, String)> {
    let mut environment = vec![(
        "PC_HOME".to_string(),
        pc_home.to_string_lossy().into_owned(),
    )];

    let path = std::env::var("PATH").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string()
        } else {
            "/usr/local/bin:/usr/bin:/bin".to_string()
        }
    });
    environment.push(("PATH".to_string(), path));

    // Keep only development-tool path selectors. Do not snapshot the caller's
    // full environment (tokens, credentials, agent sockets, etc.) into a
    // persistent service definition.
    for key in ["RUSTUP_HOME", "CARGO_HOME", "DEVELOPER_DIR"] {
        if let Ok(value) = std::env::var(key)
            && !value.is_empty()
        {
            environment.push((key.to_string(), value));
        }
    }

    environment
}

fn validate_line_value(name: &str, value: &str) -> anyhow::Result<()> {
    ensure!(
        !value.contains('\n') && !value.contains('\r') && !value.contains('\0'),
        "{name} contains unsupported control characters"
    );
    Ok(())
}

fn atomic_write(path: &Path, content: &str) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("service file has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create service directory {}", parent.display()))?;
    let temp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("pc-service"),
        std::process::id()
    ));
    fs::write(&temp, content)
        .with_context(|| format!("write temporary service file {}", temp.display()))?;
    fs::rename(&temp, path)
        .with_context(|| format!("install service file {}", path.display()))?;
    Ok(())
}

fn run_checked(command: &mut Command, description: &str) -> anyhow::Result<()> {
    let status = command
        .status()
        .with_context(|| format!("run {description}"))?;
    ensure!(status.success(), "{description} failed with {status}");
    Ok(())
}

fn run_ignoring_status(command: &mut Command) {
    let _ = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn systemd_escape(value: &str) -> String {
    value
        .replace('\\', r#"\\"#)
        .replace('"', r#"\""#)
        .replace('%', "%%")
}

fn render_systemd_unit(spec: &ServiceSpec) -> String {
    let mut unit = format!(
        "[Unit]\nDescription=pc MCP server\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=\"{}\"\nWorkingDirectory=\"{}\"\nRestart=on-failure\nRestartSec=3\n",
        systemd_escape(&spec.binary.to_string_lossy()),
        systemd_escape(&spec.user_home.to_string_lossy()),
    );
    for (key, value) in &spec.environment {
        unit.push_str(&format!(
            "Environment=\"{}={}\"\n",
            systemd_escape(key),
            systemd_escape(value)
        ));
    }
    unit.push_str("\n[Install]\nWantedBy=default.target\n");
    unit
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn render_launchd_plist(spec: &ServiceSpec) -> String {
    let mut environment = String::new();
    for (key, value) in &spec.environment {
        environment.push_str(&format!(
            "        <key>{}</key>\n        <string>{}</string>\n",
            xml_escape(key),
            xml_escape(value)
        ));
    }

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{working_directory}</string>
    <key>EnvironmentVariables</key>
    <dict>
{environment}    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>3</integer>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        binary = xml_escape(&spec.binary.to_string_lossy()),
        working_directory = xml_escape(&spec.user_home.to_string_lossy()),
    )
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    pub fn run(action: ServiceAction, spec: &ServiceSpec) -> anyhow::Result<()> {
        let unit_path = systemd_user_dir(&spec.user_home).join(SYSTEMD_UNIT);
        match action {
            ServiceAction::Install => {
                atomic_write(&unit_path, &render_systemd_unit(spec))?;
                systemctl(&["daemon-reload"])?;
                systemctl(&["enable", "--now", SYSTEMD_UNIT])?;
                println!("installed and started {}", unit_path.display());
            }
            ServiceAction::Start => systemctl(&["start", SYSTEMD_UNIT])?,
            ServiceAction::Stop => systemctl(&["stop", SYSTEMD_UNIT])?,
            ServiceAction::Restart => systemctl(&["restart", SYSTEMD_UNIT])?,
            ServiceAction::Status => {
                systemctl(&["status", "--no-pager", "--full", SYSTEMD_UNIT])?
            }
            ServiceAction::Uninstall => {
                let mut disable = Command::new("systemctl");
                disable.args(["--user", "disable", "--now", SYSTEMD_UNIT]);
                run_ignoring_status(&mut disable);
                if unit_path.exists() {
                    fs::remove_file(&unit_path)
                        .with_context(|| format!("remove {}", unit_path.display()))?;
                }
                systemctl(&["daemon-reload"])?;
                let mut reset = Command::new("systemctl");
                reset.args(["--user", "reset-failed", SYSTEMD_UNIT]);
                run_ignoring_status(&mut reset);
                println!("uninstalled {}", unit_path.display());
            }
        }
        Ok(())
    }

    fn systemd_user_dir(home: &Path) -> PathBuf {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"))
            .join("systemd")
            .join("user")
    }

    fn systemctl(args: &[&str]) -> anyhow::Result<()> {
        let mut command = Command::new("systemctl");
        command.arg("--user").args(args);
        run_checked(&mut command, &format!("systemctl --user {}", args.join(" ")))
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    pub fn run(action: ServiceAction, spec: &ServiceSpec) -> anyhow::Result<()> {
        let plist = spec
            .user_home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LAUNCHD_LABEL}.plist"));
        let uid = uid()?;
        let domain = format!("gui/{uid}");
        let target = format!("{domain}/{LAUNCHD_LABEL}");

        match action {
            ServiceAction::Install => {
                atomic_write(&plist, &render_launchd_plist(spec))?;
                bootout_if_loaded(&target);
                launchctl(&["bootstrap", &domain], Some(&plist))?;
                launchctl(&["enable", &target], None)?;
                launchctl(&["kickstart", "-k", &target], None)?;
                println!("installed and started {}", plist.display());
            }
            ServiceAction::Start => {
                if !is_loaded(&target) {
                    ensure!(
                        plist.exists(),
                        "pc service is not installed; run 'pc service install'"
                    );
                    launchctl(&["bootstrap", &domain], Some(&plist))?;
                }
                launchctl(&["enable", &target], None)?;
                launchctl(&["kickstart", "-k", &target], None)?;
            }
            ServiceAction::Stop => {
                ensure!(
                    is_loaded(&target),
                    "pc service is not running or loaded"
                );
                launchctl(&["bootout", &target], None)?;
            }
            ServiceAction::Restart => {
                ensure!(
                    plist.exists(),
                    "pc service is not installed; run 'pc service install'"
                );
                bootout_if_loaded(&target);
                launchctl(&["bootstrap", &domain], Some(&plist))?;
                launchctl(&["enable", &target], None)?;
                launchctl(&["kickstart", "-k", &target], None)?;
            }
            ServiceAction::Status => launchctl(&["print", &target], None)?,
            ServiceAction::Uninstall => {
                bootout_if_loaded(&target);
                if plist.exists() {
                    fs::remove_file(&plist)
                        .with_context(|| format!("remove {}", plist.display()))?;
                }
                println!("uninstalled {}", plist.display());
            }
        }
        Ok(())
    }

    fn uid() -> anyhow::Result<String> {
        let output = Command::new("id")
            .arg("-u")
            .output()
            .context("run id -u")?;
        ensure!(output.status.success(), "id -u failed with {}", output.status);
        let uid = String::from_utf8(output.stdout).context("id -u returned non-UTF-8 output")?;
        let uid = uid.trim();
        ensure!(!uid.is_empty(), "id -u returned an empty uid");
        ensure!(
            uid.bytes().all(|byte| byte.is_ascii_digit()),
            "id -u returned invalid uid {uid:?}"
        );
        Ok(uid.to_string())
    }

    fn is_loaded(target: &str) -> bool {
        Command::new("launchctl")
            .args(["print", target])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn bootout_if_loaded(target: &str) {
        if is_loaded(target) {
            let mut command = Command::new("launchctl");
            command.args(["bootout", target]);
            run_ignoring_status(&mut command);
        }
    }

    fn launchctl(args: &[&str], path_arg: Option<&Path>) -> anyhow::Result<()> {
        let mut command = Command::new("launchctl");
        command.args(args);
        if let Some(path) = path_arg {
            command.arg(path);
        }
        let suffix = path_arg
            .map(|path| format!(" {}", path.display()))
            .unwrap_or_default();
        run_checked(
            &mut command,
            &format!("launchctl {}{suffix}", args.join(" ")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            binary: PathBuf::from("/Users/dev/bin/pc"),
            user_home: PathBuf::from("/Users/dev"),
            environment: vec![
                (
                    "PC_HOME".to_string(),
                    "/Users/dev/.config/pc".to_string(),
                ),
                (
                    "PATH".to_string(),
                    "/opt/homebrew/bin:/usr/bin:/bin".to_string(),
                ),
            ],
        }
    }

    #[test]
    fn systemd_unit_is_user_scoped_and_restarts_on_failure() {
        let unit = render_systemd_unit(&spec());
        assert!(unit.contains("ExecStart=\"/Users/dev/bin/pc\""));
        assert!(unit.contains("WorkingDirectory=\"/Users/dev\""));
        assert!(unit.contains("Environment=\"PC_HOME=/Users/dev/.config/pc\""));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(!unit.contains("PC_OAUTH_PASSWORD"));
    }

    #[test]
    fn launchd_plist_uses_modern_user_agent_shape() {
        let plist = render_launchd_plist(&spec());
        assert!(plist.contains("<string>io.github.darkautism.pc</string>"));
        assert!(plist.contains("<string>/Users/dev/bin/pc</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>SuccessfulExit</key>"));
        assert!(plist.contains("<key>PC_HOME</key>"));
        assert!(!plist.contains("PC_OAUTH_PASSWORD"));
    }

    #[test]
    fn launchd_xml_escapes_paths() {
        let mut spec = spec();
        spec.binary = PathBuf::from("/tmp/a&b/pc");
        let plist = render_launchd_plist(&spec);
        assert!(plist.contains("/tmp/a&amp;b/pc"));
    }

    #[test]
    fn systemd_escapes_percent_specifiers() {
        let mut spec = spec();
        spec.binary = PathBuf::from("/tmp/pc%20/bin");
        let unit = render_systemd_unit(&spec);
        assert!(unit.contains("/tmp/pc%%20/bin"));
    }
}
