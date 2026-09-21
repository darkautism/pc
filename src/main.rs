use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc, time::Instant};

use anyhow::{Context, ensure};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request},
    middleware::{self, Next},
    response::Response,
};
use clap::Parser;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tower_http::trace::TraceLayer;
use tracing::info;
use url::Url;

mod config;
mod sandbox;
mod tools;

use config::{ConfigOverrides, PcConfig, SecurityConfig, SecurityMode};
use oauth::{OAuthConfig, OAuthState, RedirectPolicy, TokenPrefixes};
use sandbox::SafeSandbox;
use tools::{PcMcp, ProcessRegistry};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, env = "PC_LISTEN", default_value = "0.0.0.0:8686")]
    listen: SocketAddr,

    #[arg(long, env = "PC_DATABASE_URL")]
    database_url: Option<String>,

    #[arg(long, env = "PC_PUBLIC_URL")]
    public_url: Option<String>,

    #[arg(long, env = "PC_OAUTH_PASSWORD")]
    oauth_password: Option<String>,

    #[arg(long, env = "PC_HOME")]
    home: Option<PathBuf>,

    #[arg(long, env = "PC_WORKSPACE")]
    workspace: Option<PathBuf>,

    #[arg(long, env = "PC_SECURITY_MODE")]
    security_mode: Option<SecurityMode>,

    #[arg(long, env = "PC_SECURITY_NETWORK")]
    security_network: Option<bool>,

    #[arg(long, env = "PC_SECURITY_PROTECT_SECRETS")]
    security_protect_secrets: Option<bool>,

    #[arg(long, env = "PC_ALLOWED_REDIRECT_HOSTS")]
    allowed_redirect_hosts: Option<String>,

    #[arg(
        long,
        env = "PC_PRODUCTION",
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    production: Option<bool>,
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
    let log_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("pc=info"));
    tracing_subscriber::fmt().with_env_filter(log_filter).init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        git_sha = env!("PC_BUILD_GIT_SHA"),
        "pc starting"
    );

    let args = Args::parse();
    let home = args.home.clone().unwrap_or(config::default_home()?);
    let PcConfig {
        workspace,
        oauth_password,
        public_url,
        production,
        allowed_redirect_hosts,
        security,
    } = config::load_or_create(
        &home,
        ConfigOverrides {
            workspace: args.workspace.clone(),
            oauth_password: args.oauth_password.clone(),
            public_url: args.public_url.clone(),
            production: args.production,
            allowed_redirect_hosts: args.allowed_redirect_hosts.as_deref().map(parse_hosts),
            security_mode: args.security_mode,
            security_network: args.security_network,
            security_protect_secrets: args.security_protect_secrets,
        },
    )
    .await?;
    let public_url = public_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.trim_end_matches('/').to_string());
    let allowed_redirect_hosts = normalize_hosts(allowed_redirect_hosts);

    if let Some(public) = public_url.as_deref() {
        validate_public_url(public)?;
    }
    if production {
        let public = public_url
            .as_deref()
            .context("public_url is required in production")?;
        let parsed = Url::parse(public).context("parse public_url")?;
        ensure!(
            parsed.scheme() == "https" && parsed.host_str().is_some(),
            "public_url must be an absolute https:// URL in production"
        );
        ensure!(
            oauth_password.as_deref().is_some_and(|v| v.len() >= 16),
            "oauth_password must be at least 16 characters in production"
        );
        ensure!(
            !allowed_redirect_hosts.is_empty(),
            "allowed_redirect_hosts is required in production"
        );
    }

    let home = tokio::fs::canonicalize(&home)
        .await
        .with_context(|| format!("canonicalize PC_HOME {}", home.display()))?;
    let database_path = home.join("pc.db");
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

    let connect_options = if let Some(database_url) = args.database_url.as_deref() {
        SqliteConnectOptions::from_str(database_url).context("parse sqlite URL")?
    } else {
        SqliteConnectOptions::new().filename(&database_path)
    }
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
        oauth_password,
        workspace,
        security,
        sandbox,
        allowed_redirect_hosts,
        production,
        processes: ProcessRegistry::default(),
    });

    let oauth_state = Arc::new(
        OAuthState::open_migrating_legacy(
            home.join("oauth.db"),
            OAuthConfig {
                service_name: "pc".into(),
                scope: "pc".into(),
                public_url: state.public_url.clone(),
                oauth_password: state.oauth_password.clone(),
                default_host: "127.0.0.1:8686".into(),
                token_prefixes: TokenPrefixes::new("pc"),
                redirect_policy: RedirectPolicy::Restricted {
                    production: state.production,
                    allowed_hosts: state.allowed_redirect_hosts.clone(),
                },
                client_id_metadata_document_supported: false,
            },
            &state.db,
        )
        .await
        .context("open OAuth database")?,
    );

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
            oauth_state.clone(),
            oauth::require_mcp_auth,
        ));

    let app = Router::new()
        .merge(oauth::router(oauth_state.clone()))
        .merge(mcp_router)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(log_http_request))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    info!(
        listen = %args.listen,
        workspace = %state.workspace.display(),
        security_mode = ?state.security.mode,
        version = env!("CARGO_PKG_VERSION"),
        git_sha = env!("PC_BUILD_GIT_SHA"),
        "pc listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn log_http_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let mcp_method = request
        .headers()
        .get("mcp-method")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let protocol_version = request
        .headers()
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let started = Instant::now();

    info!(
        method = %method,
        path = %path,
        mcp_method = %mcp_method,
        protocol_version = %protocol_version,
        "http request"
    );
    let response = next.run(request).await;
    info!(
        method = %method,
        path = %path,
        mcp_method = %mcp_method,
        protocol_version = %protocol_version,
        status = %response.status(),
        elapsed_ms = started.elapsed().as_millis(),
        "http response"
    );
    response
}

fn parse_hosts(raw: &str) -> Vec<String> {
    normalize_hosts(raw.split(',').map(str::to_string).collect())
}

fn normalize_hosts(hosts: Vec<String>) -> Vec<String> {
    hosts
        .into_iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

fn validate_public_url(raw: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(raw).context("parse public_url")?;
    ensure!(
        parsed.host_str().is_some(),
        "public_url must contain a host"
    );
    ensure!(
        parsed.username().is_empty(),
        "public_url must not contain username"
    );
    ensure!(
        parsed.password().is_none(),
        "public_url must not contain password"
    );
    ensure!(
        parsed.query().is_none(),
        "public_url must not contain query"
    );
    ensure!(
        parsed.fragment().is_none(),
        "public_url must not contain fragment"
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
        let parsed = Url::parse(public).context("parse public_url for MCP host guard")?;
        if let Some(host) = parsed.host_str() {
            let host = host.to_ascii_lowercase();
            if !allowed_hosts.contains(&host) {
                allowed_hosts.push(host);
            }
        }
    }
    Ok(StreamableHttpServerConfig::default()
        .with_allowed_hosts(allowed_hosts)
        // ChatGPT's current connector lifecycle starts with server/discover.
        // Keep pc on the 2026-07-28 stateless path instead of creating legacy sessions.
        .with_legacy_session_mode(false)
        .with_stateless_protocol_metadata_required(true)
        .with_json_response(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_transport_uses_modern_stateless_discovery() {
        let config = mcp_http_config(None).expect("MCP HTTP config");
        assert!(!config.legacy_session_mode);
        assert!(config.stateless_protocol_metadata_required);
    }
}
