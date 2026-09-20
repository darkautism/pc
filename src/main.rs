use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::{Context, ensure};
use axum::{Router, extract::DefaultBodyLimit, middleware};
use clap::Parser;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tower_http::trace::TraceLayer;
use tracing::info;
use url::Url;

mod config;
mod oauth;
mod sandbox;
mod tools;

use config::{PcConfig, SecurityConfig, SecurityMode};
use sandbox::SafeSandbox;
use tools::{PcMcp, ProcessRegistry};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, env = "PC_LISTEN", default_value = "0.0.0.0:8787")]
    listen: SocketAddr,

    #[arg(
        long,
        env = "PC_DATABASE_URL",
        default_value = "sqlite://data/pc.db?mode=rwc"
    )]
    database_url: String,

    #[arg(long, env = "PC_PUBLIC_URL")]
    public_url: Option<String>,

    #[arg(long, env = "PC_OAUTH_PASSWORD")]
    oauth_password: Option<String>,

    #[arg(long, env = "PC_HOME", default_value = ".")]
    home: PathBuf,

    #[arg(long, env = "PC_WORKSPACE")]
    workspace: Option<PathBuf>,

    #[arg(long, env = "PC_ALLOWED_REDIRECT_HOSTS", default_value = "")]
    allowed_redirect_hosts: String,

    #[arg(long, env = "PC_PRODUCTION", default_value_t = false)]
    production: bool,
}

pub(crate) struct AppState {
    pub db: sqlx::SqlitePool,
    pub public_url: Option<String>,
    pub oauth_password: Option<String>,
    pub workspace: PathBuf,
    pub security: SecurityConfig,
    pub sandbox: Option<Arc<SafeSandbox>>,
    pub allowed_redirect_hosts: Vec<String>,
    pub production: bool,
    pub processes: ProcessRegistry,
}

fn main() -> anyhow::Result<()> {
    // Safe-mode commands re-exec this binary and must enter the rootless sandbox
    // before Tokio creates worker threads, matching LazyTeam's mini-sandbox design.
    if let Some(result) = sandbox::maybe_handle_entrypoint() {
        return result;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let PcConfig {
        workspace,
        security,
    } = config::load_or_create(&args.home, args.workspace.clone()).await?;
    let public_url = args
        .public_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.trim_end_matches('/').to_string());
    let allowed_redirect_hosts = parse_hosts(&args.allowed_redirect_hosts);

    if let Some(public) = public_url.as_deref() {
        validate_public_url(public)?;
    }
    if args.production {
        let public = public_url
            .as_deref()
            .context("PC_PUBLIC_URL is required in production")?;
        let parsed = Url::parse(public).context("parse PC_PUBLIC_URL")?;
        ensure!(
            parsed.scheme() == "https" && parsed.host_str().is_some(),
            "PC_PUBLIC_URL must be an absolute https:// URL in production"
        );
        ensure!(
            args.oauth_password
                .as_deref()
                .is_some_and(|v| v.len() >= 16),
            "PC_OAUTH_PASSWORD must be at least 16 characters in production"
        );
        ensure!(
            !allowed_redirect_hosts.is_empty(),
            "PC_ALLOWED_REDIRECT_HOSTS is required in production"
        );
    }

    if args.database_url.starts_with("sqlite://data/") {
        tokio::fs::create_dir_all("data").await?;
    }

    let home = tokio::fs::canonicalize(&args.home)
        .await
        .with_context(|| format!("canonicalize PC_HOME {}", args.home.display()))?;
    let workspace = tokio::fs::canonicalize(&workspace)
        .await
        .with_context(|| format!("canonicalize workspace {}", workspace.display()))?;
    let sandbox = if security.mode == SecurityMode::Safe {
        Some(Arc::new(
            SafeSandbox::start(
                &workspace,
                &home.join("tmp"),
                security.network,
                security.protect_secrets,
            )
            .await?,
        ))
    } else {
        None
    };

    let connect_options = SqliteConnectOptions::from_str(&args.database_url)
        .context("parse sqlite URL")?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let db = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(connect_options)
        .await
        .context("connect sqlite")?;
    sqlx::migrate!().run(&db).await.context("run migrations")?;

    let state = Arc::new(AppState {
        db,
        public_url,
        oauth_password: args.oauth_password,
        workspace,
        security,
        sandbox,
        allowed_redirect_hosts,
        production: args.production,
        processes: ProcessRegistry::default(),
    });

    let mcp_config = mcp_http_config(state.public_url.as_deref())?;
    let root_mcp_config = mcp_http_config(state.public_url.as_deref())?;

    let mcp_state = state.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(PcMcp::new(mcp_state.clone())),
        LocalSessionManager::default().into(),
        mcp_config,
    );

    let root_state = state.clone();
    let root_mcp_service = StreamableHttpService::new(
        move || Ok(PcMcp::new(root_state.clone())),
        LocalSessionManager::default().into(),
        root_mcp_config,
    );

    let mcp_router = Router::<Arc<AppState>>::new()
        .route_service("/", root_mcp_service)
        .route_service("/mcp", mcp_service)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            oauth::require_mcp_auth,
        ));

    let app = Router::new()
        .merge(oauth::router())
        .merge(mcp_router)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, workspace = %state.workspace.display(), security_mode = ?state.security.mode, "pc listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn parse_hosts(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_ascii_lowercase())
        .collect()
}

fn validate_public_url(raw: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(raw).context("parse PC_PUBLIC_URL")?;
    ensure!(
        parsed.host_str().is_some(),
        "PC_PUBLIC_URL must contain a host"
    );
    ensure!(
        parsed.username().is_empty(),
        "PC_PUBLIC_URL must not contain username"
    );
    ensure!(
        parsed.password().is_none(),
        "PC_PUBLIC_URL must not contain password"
    );
    ensure!(
        parsed.query().is_none(),
        "PC_PUBLIC_URL must not contain query"
    );
    ensure!(
        parsed.fragment().is_none(),
        "PC_PUBLIC_URL must not contain fragment"
    );
    Ok(())
}

fn mcp_http_config(public_url: Option<&str>) -> anyhow::Result<StreamableHttpServerConfig> {
    let mut allowed_hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(public) = public_url {
        let parsed = Url::parse(public).context("parse PC_PUBLIC_URL for MCP host guard")?;
        if let Some(host) = parsed.host_str() {
            let host = host.to_ascii_lowercase();
            if !allowed_hosts.contains(&host) {
                allowed_hosts.push(host);
            }
        }
    }
    Ok(StreamableHttpServerConfig::default()
        .with_allowed_hosts(allowed_hosts)
        .with_legacy_session_mode(true)
        .with_json_response(true))
}
