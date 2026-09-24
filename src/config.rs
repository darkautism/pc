use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PcConfig {
    pub workspace: PathBuf,
    pub oauth_password: Option<String>,
    pub public_url: Option<String>,
    pub production: bool,
    pub allowed_redirect_hosts: Vec<String>,
    pub task_log_retention_secs: u64,
    pub security: SecurityConfig,
}

impl Default for PcConfig {
    fn default() -> Self {
        Self {
            workspace: PathBuf::from("."),
            oauth_password: None,
            public_url: None,
            production: false,
            allowed_redirect_hosts: Vec::new(),
            task_log_retention_secs: 2 * 60 * 60,
            security: SecurityConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum SecurityMode {
    Full,
    Safe,
    Readonly,
}

impl Default for SecurityMode {
    fn default() -> Self {
        Self::Full
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub mode: SecurityMode,
    pub network: bool,
    pub protect_secrets: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            mode: SecurityMode::Full,
            network: true,
            protect_secrets: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct ConfigOverrides {
    pub workspace: Option<PathBuf>,
    pub oauth_password: Option<String>,
    pub public_url: Option<String>,
    pub production: Option<bool>,
    pub allowed_redirect_hosts: Option<Vec<String>>,
    pub task_log_retention_secs: Option<u64>,
    pub security_mode: Option<SecurityMode>,
    pub security_network: Option<bool>,
    pub security_protect_secrets: Option<bool>,
}

pub fn default_home() -> anyhow::Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(home).join(".config").join("pc"));
    }
    if let Some(home) = std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(home).join(".config").join("pc"));
    }
    Err(anyhow::anyhow!(
        "cannot determine pc config directory: set PC_HOME, HOME, or USERPROFILE"
    ))
}

pub async fn load_existing(home: &Path) -> anyhow::Result<PcConfig> {
    let path = home.join("config.yaml");
    let text = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    parse_config(&text, &path)
}

pub async fn load_or_create(home: &Path, overrides: ConfigOverrides) -> anyhow::Result<PcConfig> {
    tokio::fs::create_dir_all(home)
        .await
        .with_context(|| format!("create PC_HOME {}", home.display()))?;
    set_private_dir(home).await?;

    let path = home.join("config.yaml");
    let mut created = false;
    let mut config = match tokio::fs::read_to_string(&path).await {
        Ok(text) => parse_config(&text, &path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            created = true;
            PcConfig::default()
        }
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", path.display()));
        }
    };

    apply_overrides(&mut config, &overrides);
    if config.oauth_password.as_deref().is_none_or(str::is_empty) {
        config.oauth_password = Some(generate_oauth_password());
        created = true;
    }

    if created {
        let text = serde_yaml::to_string(&config).context("serialize pc config")?;
        tokio::fs::write(&path, text)
            .await
            .with_context(|| format!("write {}", path.display()))?;
    }
    set_private_file(&path).await?;
    Ok(config)
}

fn generate_oauth_password() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn parse_config(text: &str, path: &Path) -> anyhow::Result<PcConfig> {
    match serde_yaml::from_str(text) {
        Ok(config) => Ok(config),
        Err(primary) => {
            if let Some(repaired) = repair_windows_workspace_yaml(text)
                && let Ok(config) = serde_yaml::from_str(&repaired)
            {
                return Ok(config);
            }
            Err(primary).with_context(|| format!("parse {}", path.display()))
        }
    }
}

fn repair_windows_workspace_yaml(text: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(text.len());

    for line in text.split_inclusive('\n') {
        let (body, newline) = line
            .strip_suffix('\n')
            .map_or((line, ""), |body| (body, "\n"));
        let trimmed = body.trim_start();
        let indent_len = body.len() - trimmed.len();
        let Some(rest) = trimmed.strip_prefix("workspace:") else {
            out.push_str(line);
            continue;
        };
        let value = rest.trim_start();
        let spacing_len = rest.len() - value.len();
        if !value.starts_with('"') {
            out.push_str(line);
            continue;
        }
        let Some(end_rel) = value[1..].rfind('"') else {
            out.push_str(line);
            continue;
        };
        let end = end_rel + 1;
        let inner = &value[1..end];
        if !looks_like_windows_path(inner) || !inner.contains('\\') {
            out.push_str(line);
            continue;
        }

        changed = true;
        out.push_str(&body[..indent_len]);
        out.push_str("workspace:");
        out.push_str(&rest[..spacing_len]);
        out.push('"');
        out.push_str(&inner.replace('\\', "\\\\"));
        out.push('"');
        out.push_str(&value[end + 1..]);
        out.push_str(newline);
    }

    changed.then_some(out)
}

fn looks_like_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
        || value.starts_with("\\\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_double_quoted_windows_workspace_path() {
        let raw = "workspace: \"E:\\project\"\n";
        let repaired = repair_windows_workspace_yaml(raw).expect("repair");
        let config: PcConfig = serde_yaml::from_str(&repaired).expect("parse repaired config");
        assert_eq!(config.workspace, PathBuf::from(r"E:\project"));
    }

    #[test]
    fn old_config_defaults_task_log_retention_to_two_hours() {
        let config: PcConfig = serde_yaml::from_str("workspace: /tmp\n").expect("parse config");
        assert_eq!(config.task_log_retention_secs, 2 * 60 * 60);
    }

    #[test]
    fn generated_oauth_password_is_self_contained() {
        let password = generate_oauth_password();
        assert_eq!(password.len(), 64);
        assert!(password.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
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

#[cfg(unix)]
async fn set_private_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_private_file(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn apply_overrides(config: &mut PcConfig, overrides: &ConfigOverrides) {
    if let Some(workspace) = overrides.workspace.as_ref() {
        config.workspace = workspace.clone();
    }
    if let Some(oauth_password) = overrides.oauth_password.as_ref() {
        config.oauth_password = Some(oauth_password.clone());
    }
    if let Some(public_url) = overrides.public_url.as_ref() {
        config.public_url = Some(public_url.clone());
    }
    if let Some(production) = overrides.production {
        config.production = production;
    }
    if let Some(allowed_redirect_hosts) = overrides.allowed_redirect_hosts.as_ref() {
        config.allowed_redirect_hosts = allowed_redirect_hosts.clone();
    }
    if let Some(task_log_retention_secs) = overrides.task_log_retention_secs {
        config.task_log_retention_secs = task_log_retention_secs;
    }
    if let Some(mode) = overrides.security_mode {
        config.security.mode = mode;
    }
    if let Some(network) = overrides.security_network {
        config.security.network = network;
    }
    if let Some(protect_secrets) = overrides.security_protect_secrets {
        config.security.protect_secrets = protect_secrets;
    }
}
