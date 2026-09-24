use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{DefaultBodyLimit, Request},
    http::header,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use clap::{Parser, Subcommand};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tower_http::trace::TraceLayer;
use tracing::info;
use url::Url;

mod config;
mod sandbox;
mod service;
mod tools;

use config::{ConfigOverrides, PcConfig, SecurityConfig, SecurityMode};
use oauth::{OAuthConfig, OAuthState, RedirectPolicy, TokenPrefixes};
use sandbox::SafeSandbox;
use tools::{PcMcp, ProcessRegistry};

#[derive(Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: Option<CliCommand>,

    #[arg(long, env = "PC_LISTEN", default_value = "0.0.0.0:8686")]
    listen: SocketAddr,

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

    #[arg(long, env = "PC_TASK_LOG_RETENTION_SECS")]
    task_log_retention_secs: Option<u64>,

    #[arg(
        long,
        env = "PC_PRODUCTION",
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    production: Option<bool>,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Manage pc as a native per-user background service.
    Service {
        #[command(subcommand)]
        action: service::ServiceAction,
    },
}

pub(crate) struct AppState {
    pub public_url: Option<String>,
    pub oauth_password: Option<String>,
    pub workspace: PathBuf,
    pub security: SecurityConfig,
    pub sandbox: Option<Arc<SafeSandbox>>,
    pub allowed_redirect_hosts: Vec<String>,
    pub production: bool,
    pub task_log_retention: Duration,
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
    if let Some(CliCommand::Service { action }) = args.command.as_ref() {
        return service::run(*action, args.home.as_deref());
    }

    let home = args.home.clone().unwrap_or(config::default_home()?);
    let PcConfig {
        workspace,
        oauth_password,
        public_url,
        production,
        allowed_redirect_hosts,
        task_log_retention_secs,
        security,
    } = config::load_or_create(
        &home,
        ConfigOverrides {
            workspace: args.workspace.clone(),
            oauth_password: args.oauth_password.clone(),
            public_url: args.public_url.clone(),
            production: args.production,
            allowed_redirect_hosts: args.allowed_redirect_hosts.as_deref().map(parse_hosts),
            task_log_retention_secs: args.task_log_retention_secs,
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

    let state = Arc::new(AppState {
        public_url,
        oauth_password,
        workspace,
        security,
        sandbox,
        allowed_redirect_hosts,
        production,
        task_log_retention: Duration::from_secs(task_log_retention_secs),
        processes: ProcessRegistry::default(),
    });
    tools::spawn_task_log_cleanup(state.clone());

    let oauth_state = Arc::new(
        OAuthState::open(
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
                client_id_metadata_document_supported: true,
            },
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
        ))
        .route_layer(middleware::from_fn(normalize_chatgpt_action_scan))
        .route_layer(middleware::from_fn(mcp_streamable_response_headers));

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
        task_log_retention_secs = state.task_log_retention.as_secs(),
        version = env!("CARGO_PKG_VERSION"),
        git_sha = env!("PC_BUILD_GIT_SHA"),
        "pc listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn mcp_streamable_response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let is_event_stream = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    if is_event_stream {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-cache, no-transform"),
        );
    }
    response
}

async fn normalize_chatgpt_action_scan(request: Request, next: Next) -> Response {
    let is_tools_list = request
        .headers()
        .get("mcp-method")
        .and_then(|value| value.to_str().ok())
        == Some("tools/list");
    if !is_tools_list {
        return next.run(request).await;
    }

    let protocol_version = request
        .headers()
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("2026-07-28")
        .to_string();

    let (mut parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, 1024 * 1024).await else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "invalid tools/list request body",
        )
            .into_response();
    };
    let Ok(mut payload) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        let request = Request::from_parts(parts, Body::from(bytes));
        return next.run(request).await;
    };

    if let Some(params) = payload
        .as_object_mut()
        .and_then(|root| root.get_mut("params"))
        .and_then(serde_json::Value::as_object_mut)
    {
        let meta = params
            .entry("_meta")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(meta) = meta.as_object_mut() {
            meta.entry("io.modelcontextprotocol/protocolVersion")
                .or_insert_with(|| serde_json::Value::String(protocol_version));
            meta.entry("io.modelcontextprotocol/clientCapabilities")
                .or_insert_with(|| serde_json::json!({}));
        }
    }

    let Ok(rewritten) = serde_json::to_vec(&payload) else {
        let request = Request::from_parts(parts, Body::from(bytes));
        return next.run(request).await;
    };
    if let Ok(value) = header::HeaderValue::from_str(&rewritten.len().to_string()) {
        parts.headers.insert(header::CONTENT_LENGTH, value);
    }
    next.run(Request::from_parts(parts, Body::from(rewritten)))
        .await
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
        // Match MCPX's ChatGPT-facing transport exactly: stateless Streamable
        // HTTP with the default SSE response mode. In particular, do not force
        // application/json for POST responses; MCPX leaves JSONResponse disabled.
        .with_legacy_session_mode(false)
        .with_stateless_protocol_metadata_required(false)
        .with_json_response(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn mcp_transport_uses_modern_stateless_discovery() {
        let config = mcp_http_config(None).expect("MCP HTTP config");
        assert!(!config.legacy_session_mode);
        assert!(
            !config.stateless_protocol_metadata_required,
            "automatic ChatGPT tools/list must not require per-request _meta"
        );
        assert!(
            !config.json_response,
            "MCPX-compatible ChatGPT discovery uses Streamable HTTP SSE responses"
        );
    }

    #[tokio::test]
    async fn chatgpt_action_discovery_accepts_plain_tools_list_after_discover() {
        let workspace =
            std::env::temp_dir().join(format!("pc-action-discovery-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&workspace)
            .await
            .expect("create workspace");

        let state = Arc::new(AppState {
            public_url: None,
            oauth_password: None,
            workspace: workspace.clone(),
            security: crate::config::SecurityConfig::default(),
            sandbox: None,
            allowed_redirect_hosts: Vec::new(),
            production: false,
            task_log_retention: Duration::from_secs(2 * 60 * 60),
            processes: ProcessRegistry::default(),
        });
        let service_state = state.clone();
        let service = StreamableHttpService::new(
            move || Ok(PcMcp::new(service_state.clone())),
            LocalSessionManager::default().into(),
            mcp_http_config(None).expect("MCP HTTP config"),
        );
        let root_service_state = state.clone();
        let root_service = StreamableHttpService::new(
            move || Ok(PcMcp::new(root_service_state.clone())),
            LocalSessionManager::default().into(),
            mcp_http_config(None).expect("root MCP HTTP config"),
        );
        let app = Router::new()
            .route_service("/", root_service)
            .route_service("/mcp", service)
            .route_layer(middleware::from_fn(normalize_chatgpt_action_scan))
            .route_layer(middleware::from_fn(mcp_streamable_response_headers));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let discover = r#"{"jsonrpc":"2.0","id":"d1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"chatgpt-action-scan","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}"#;
        let discover_response = raw_mcp_post(addr, "/mcp", "server/discover", discover).await;
        assert!(
            discover_response.starts_with("HTTP/1.1 200"),
            "discover failed: {discover_response}"
        );
        assert!(
            discover_response
                .to_ascii_lowercase()
                .contains("content-type: text/event-stream"),
            "discover must use MCPX-compatible SSE response mode: {discover_response}"
        );
        assert!(
            discover_response
                .to_ascii_lowercase()
                .contains("cache-control: no-cache, no-transform"),
            "discover must preserve Streamable HTTP no-transform semantics: {discover_response}"
        );
        assert!(
            discover_response.contains("2026-07-28"),
            "discover did not advertise modern protocol: {discover_response}"
        );
        assert!(
            discover_response.contains(r#""cacheScope":"public""#),
            "discover must match MCPX/go-sdk public cache scope: {discover_response}"
        );
        assert!(
            discover_response.contains(r#""name":"pc""#),
            "discover must identify pc rather than the rmcp library: {discover_response}"
        );

        // This intentionally has no per-request _meta. MCPX accepts this shape,
        // and ChatGPT's automatic action scan uses it immediately after discover.
        let list = r#"{"jsonrpc":"2.0","id":"d2","method":"tools/list","params":{}}"#;
        let list_response = raw_mcp_post(addr, "/mcp", "tools/list", list).await;
        assert!(
            list_response.starts_with("HTTP/1.1 200"),
            "automatic tools/list failed: {list_response}"
        );
        assert!(
            list_response
                .to_ascii_lowercase()
                .contains("content-type: text/event-stream"),
            "tools/list must use MCPX-compatible SSE response mode: {list_response}"
        );
        for tool in ["read", "write", "edit", "bash"] {
            assert!(
                list_response.contains(&format!(r#""name":"{tool}""#)),
                "tools/list missing {tool}: {list_response}"
            );
        }
        assert!(
            list_response.contains(
                r#""io.modelcontextprotocol/serverInfo":{"name":"pc","version":"0.1.0"}"#
            ),
            "tools/list must carry the same server identity metadata as server/discover: {list_response}"
        );

        let root_discover = raw_mcp_post(addr, "/", "server/discover", discover).await;
        assert!(
            root_discover.starts_with("HTTP/1.1 200"),
            "root MCP compatibility alias must remain usable: {root_discover}"
        );

        server.abort();
        let _ = tokio::fs::remove_dir_all(workspace).await;
    }

    async fn raw_mcp_post(addr: SocketAddr, path: &str, method: &str, body: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect test server");
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        String::from_utf8(response).expect("HTTP response is UTF-8")
    }
}
