use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PcConfig {
    pub workspace: PathBuf,
    pub security: SecurityConfig,
}

impl Default for PcConfig {
    fn default() -> Self {
        Self {
            workspace: PathBuf::from("."),
            security: SecurityConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

pub async fn load_or_create(
    home: &Path,
    workspace_override: Option<PathBuf>,
) -> anyhow::Result<PcConfig> {
    tokio::fs::create_dir_all(home)
        .await
        .with_context(|| format!("create PC_HOME {}", home.display()))?;

    let path = home.join("config.yaml");
    let mut config = match tokio::fs::read_to_string(&path).await {
        Ok(text) => {
            serde_yaml::from_str(&text).with_context(|| format!("parse {}", path.display()))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut config = PcConfig::default();
            if let Some(workspace) = workspace_override.clone() {
                config.workspace = workspace;
            }
            let text = serde_yaml::to_string(&config).context("serialize default pc config")?;
            tokio::fs::write(&path, text)
                .await
                .with_context(|| format!("write {}", path.display()))?;
            config
        }
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", path.display()));
        }
    };

    if let Some(workspace) = workspace_override {
        config.workspace = workspace;
    }

    Ok(config)
}
