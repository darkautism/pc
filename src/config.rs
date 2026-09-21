use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PcConfig {
    pub workspace: PathBuf,
    pub oauth_password: Option<String>,
    pub public_url: Option<String>,
    pub production: bool,
    pub allowed_redirect_hosts: Vec<String>,
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

pub async fn load_or_create(home: &Path, overrides: ConfigOverrides) -> anyhow::Result<PcConfig> {
    tokio::fs::create_dir_all(home)
        .await
        .with_context(|| format!("create PC_HOME {}", home.display()))?;
    set_private_dir(home).await?;

    let path = home.join("config.yaml");
    let mut created = false;
    let mut config = match tokio::fs::read_to_string(&path).await {
        Ok(text) => {
            serde_yaml::from_str(&text).with_context(|| format!("parse {}", path.display()))?
        }
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
        config.oauth_password = Some(generate_oauth_password(&path).await?);
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

async fn generate_oauth_password(config_path: &Path) -> anyhow::Result<String> {
    let output = tokio::process::Command::new("openssl")
        .args(["rand", "-base64", "32"])
        .output()
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "cannot generate oauth_password because OpenSSL is unavailable ({error}). Create {} manually and set oauth_password.",
                config_path.display()
            )
        })?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "cannot generate oauth_password with OpenSSL: {}. Create {} manually and set oauth_password.",
            String::from_utf8_lossy(&output.stderr).trim(),
            config_path.display()
        ));
    }
    let password = String::from_utf8(output.stdout)
        .context("OpenSSL returned a non-UTF-8 oauth password")?
        .trim()
        .to_string();
    if password.is_empty() {
        return Err(anyhow::anyhow!(
            "OpenSSL returned an empty oauth_password. Create {} manually and set oauth_password.",
            config_path.display()
        ));
    }
    Ok(password)
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
