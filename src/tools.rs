use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    io::{Cursor, SeekFrom},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use image::{GenericImageView, ImageFormat, codecs::jpeg::JpegEncoder, imageops::FilterType};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        Annotations, CacheScope, CallToolResult, ContentBlock, DiscoverResult, EmbeddedResource,
        Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ResourceContents,
        Role, ServerCapabilities, ServerConfig, SubscriptionFilter,
    },
    schemars,
    service::{RequestContext, SubscriptionContext},
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::RwLock,
};
use uuid::Uuid;

use crate::{AppState, config::SecurityMode};

const MAX_OUTPUT_BYTES: usize = 50 * 1024;
const MAX_IMAGE_BYTES: usize = 25 * 1024 * 1024;
const MAX_IMAGE_PREVIEW_EDGE: u32 = 2048;
const IMAGE_PREVIEW_JPEG_QUALITY: u8 = 85;
const MAX_OUTPUT_LINES: usize = 2000;
const MAX_TAIL_READ_BYTES: u64 = 128 * 1024;
const SYNC_WAIT: Duration = Duration::from_secs(2);
const LOG_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_LOG_DIR_BYTES: u64 = 256 * 1024 * 1024;
const PC_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2026_07_28,
    ProtocolVersion::V_2025_11_25,
    ProtocolVersion::V_2025_06_18,
    ProtocolVersion::V_2025_03_26,
    ProtocolVersion::V_2024_11_05,
];

#[derive(Clone, Default)]
pub struct ProcessRegistry {
    inner: Arc<RwLock<HashMap<u32, Arc<ProcessEntry>>>>,
}

struct ProcessEntry {
    pid: u32,
    log_path: PathBuf,
    visible_log_path: String,
    state: RwLock<ProcessState>,
}

#[derive(Clone, Copy)]
struct ProcessState {
    finished: bool,
    exit_code: Option<i32>,
}

#[derive(Clone)]
pub struct PcMcp {
    state: Arc<AppState>,
    #[allow(dead_code)]
    tool_router: ToolRouter<PcMcp>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadParams {
    pub path: String,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ReadOutput {
    #[serde(rename = "mimeType")]
    mime_type: String,
    bytes: usize,
    path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImageReadMetadata {
    path: String,
    original_mime_type: String,
    original_bytes: usize,
    original_width: u32,
    original_height: u32,
    preview_mime_type: String,
    preview_bytes: usize,
    preview_width: u32,
    preview_height: u32,
    resized: bool,
}

struct ImagePreview {
    bytes: Vec<u8>,
    mime_type: String,
    original_width: u32,
    original_height: u32,
    width: u32,
    height: u32,
    resized: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteParams {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct WriteOutput {
    path: String,
    bytes: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReplaceEdit {
    #[serde(rename = "oldText")]
    pub old_text: String,
    #[serde(rename = "newText")]
    pub new_text: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EditParams {
    pub path: String,
    pub edits: Vec<ReplaceEdit>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct EditOutput {
    path: String,
    edits_applied: usize,
    bytes: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BashParams {
    pub command: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct BashResult {
    status: &'static str,
    pid: u32,
    exit_code: Option<i32>,
    output: String,
    full_output_path: Option<String>,
    truncated: bool,
    instruction: Option<&'static str>,
}

#[tool_router]
impl PcMcp {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        name = "read",
        title = "Read file",
        description = "Read UTF-8 text or images. Text: 2000 lines/50KB max. Images: embedded preview, 2048px max edge; original unchanged.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ReadOutput>(),
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn read(
        &self,
        Parameters(input): Parameters<ReadParams>,
    ) -> Result<CallToolResult, McpError> {
        let path = resolve_path(&self.state.workspace, &input.path);
        let bytes = match self.state.security.mode {
            SecurityMode::Safe => self
                .state
                .sandbox
                .as_ref()
                .ok_or_else(|| tool_error("safe sandbox is not running"))?
                .read_file(&input.path)
                .await
                .map_err(|e| tool_error(e.to_string()))?,
            SecurityMode::Full => tokio::fs::read(&path)
                .await
                .map_err(|e| tool_error(format!("read {}: {e}", input.path)))?,
            SecurityMode::Readonly => {
                ensure_secret_access(&path, self.state.security.protect_secrets)?;
                tokio::fs::read(&path)
                    .await
                    .map_err(|e| tool_error(format!("read {}: {e}", input.path)))?
            }
        };
        let total_bytes = bytes.len();
        if let Some(mime_type) = image_mime_type(&bytes) {
            if bytes.len() > MAX_IMAGE_BYTES {
                return Err(tool_error(format!(
                    "{} is a {mime_type} image larger than the {} MiB read limit",
                    input.path,
                    MAX_IMAGE_BYTES / (1024 * 1024)
                )));
            }

            let preview = prepare_image_preview(&bytes, mime_type)?;
            let metadata = serde_json::to_string(&ImageReadMetadata {
                path: input.path,
                original_mime_type: mime_type.to_string(),
                original_bytes: total_bytes,
                original_width: preview.original_width,
                original_height: preview.original_height,
                preview_mime_type: preview.mime_type.clone(),
                preview_bytes: preview.bytes.len(),
                preview_width: preview.width,
                preview_height: preview.height,
                resized: preview.resized,
            })
            .map_err(|e| tool_error(format!("serialize read result: {e}")))?;
            let extension = match preview.mime_type.as_str() {
                "image/jpeg" => "jpg",
                "image/png" => "png",
                "image/webp" => "webp",
                "image/gif" => "gif",
                _ => "bin",
            };
            let resource = EmbeddedResource::new(
                ResourceContents::blob(
                    STANDARD.encode(&preview.bytes),
                    format!("pc://read-image/{}/preview.{extension}", Uuid::new_v4()),
                )
                .with_mime_type(preview.mime_type),
            )
            .with_annotations(
                Annotations::default()
                    .with_audience(vec![Role::Assistant, Role::User])
                    .with_priority(1.0),
            );
            return Ok(CallToolResult::success(vec![
                ContentBlock::text(metadata),
                ContentBlock::Resource(resource),
            ]));
        }

        let text = String::from_utf8(bytes)
            .map_err(|_| tool_error(format!("{} is not a UTF-8 text file", input.path)))?;

        let lines: Vec<&str> = text.lines().collect();
        let start = input.offset.unwrap_or(1).saturating_sub(1).min(lines.len());
        let end = input
            .limit
            .map(|limit| start.saturating_add(limit).min(lines.len()))
            .unwrap_or(lines.len());
        let selected = &lines[start..end];

        let mut output = String::new();
        let mut output_lines = 0usize;
        let mut truncated = false;
        for line in selected {
            let needed = line.len() + usize::from(!output.is_empty());
            if output_lines >= MAX_OUTPUT_LINES
                || output.len().saturating_add(needed) > MAX_OUTPUT_BYTES
            {
                truncated = true;
                break;
            }
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(line);
            output_lines += 1;
        }

        if truncated {
            let next = start + output_lines + 1;
            output.push_str(&format!(
                "\n\n[Output truncated. Continue reading with offset={next}.]"
            ));
        }

        let mut result = text_result(output);
        result.structured_content = Some(
            serde_json::to_value(ReadOutput {
                mime_type: "text/plain; charset=utf-8".to_string(),
                bytes: total_bytes,
                path: input.path,
            })
            .map_err(|e| tool_error(format!("serialize read result: {e}")))?,
        );
        Ok(result)
    }

    #[tool(
        name = "write",
        title = "Write file",
        description = "Write/overwrite a file; creates parent directories.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<WriteOutput>(),
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn write(
        &self,
        Parameters(input): Parameters<WriteParams>,
    ) -> Result<CallToolResult, McpError> {
        if self.state.security.mode == SecurityMode::Readonly {
            return Err(tool_error("write is disabled in readonly mode"));
        }
        let path = resolve_path(&self.state.workspace, &input.path);
        let bytes = input.content.len();
        match self.state.security.mode {
            SecurityMode::Safe => self
                .state
                .sandbox
                .as_ref()
                .ok_or_else(|| tool_error("safe sandbox is not running"))?
                .write_file(&input.path, input.content.as_bytes())
                .await
                .map_err(|e| tool_error(e.to_string()))?,
            SecurityMode::Full => {
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|e| tool_error(format!("create parent directory: {e}")))?;
                }
                tokio::fs::write(&path, input.content)
                    .await
                    .map_err(|e| tool_error(format!("write {}: {e}", input.path)))?;
            }
            SecurityMode::Readonly => unreachable!(),
        }
        let output = WriteOutput {
            path: input.path.clone(),
            bytes,
        };
        structured_text_result(format!("Successfully wrote to {}", input.path), &output)
    }

    #[tool(
        name = "edit",
        title = "Edit file",
        description = "Exact replacements; each oldText must match once and edits may not overlap.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<EditOutput>(),
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn edit(
        &self,
        Parameters(input): Parameters<EditParams>,
    ) -> Result<CallToolResult, McpError> {
        if self.state.security.mode == SecurityMode::Readonly {
            return Err(tool_error("edit is disabled in readonly mode"));
        }
        if input.edits.is_empty() {
            return Err(tool_error("edits must not be empty"));
        }
        let path = resolve_path(&self.state.workspace, &input.path);
        let original = match self.state.security.mode {
            SecurityMode::Safe => {
                let bytes = self
                    .state
                    .sandbox
                    .as_ref()
                    .ok_or_else(|| tool_error("safe sandbox is not running"))?
                    .read_file(&input.path)
                    .await
                    .map_err(|e| tool_error(e.to_string()))?;
                String::from_utf8(bytes)
                    .map_err(|_| tool_error(format!("{} is not a UTF-8 text file", input.path)))?
            }
            SecurityMode::Full => tokio::fs::read_to_string(&path)
                .await
                .map_err(|e| tool_error(format!("read {}: {e}", input.path)))?,
            SecurityMode::Readonly => unreachable!(),
        };

        let mut replacements = Vec::with_capacity(input.edits.len());
        for edit in &input.edits {
            if edit.old_text.is_empty() {
                return Err(tool_error("edits[].oldText must not be empty"));
            }
            let matches: Vec<(usize, &str)> = original.match_indices(&edit.old_text).collect();
            if matches.len() != 1 {
                return Err(tool_error(format!(
                    "edits[].oldText must match exactly once; matched {} times",
                    matches.len()
                )));
            }
            let start = matches[0].0;
            let end = start + edit.old_text.len();
            replacements.push((start, end, edit.new_text.clone()));
        }

        replacements.sort_by_key(|(start, _, _)| *start);
        for pair in replacements.windows(2) {
            if pair[0].1 > pair[1].0 {
                return Err(tool_error(
                    "edits overlap; merge nearby edits into one replacement",
                ));
            }
        }

        let mut updated = original;
        for (start, end, new_text) in replacements.into_iter().rev() {
            updated.replace_range(start..end, &new_text);
        }

        let updated_bytes = updated.len();
        match self.state.security.mode {
            SecurityMode::Safe => self
                .state
                .sandbox
                .as_ref()
                .ok_or_else(|| tool_error("safe sandbox is not running"))?
                .write_file(&input.path, updated.as_bytes())
                .await
                .map_err(|e| tool_error(e.to_string()))?,
            SecurityMode::Full => tokio::fs::write(&path, updated)
                .await
                .map_err(|e| tool_error(format!("write {}: {e}", input.path)))?,
            SecurityMode::Readonly => unreachable!(),
        }
        let output = EditOutput {
            path: input.path.clone(),
            edits_applied: input.edits.len(),
            bytes: updated_bytes,
        };
        structured_text_result(
            format!(
                "Successfully applied {} edit(s) to {}",
                input.edits.len(),
                input.path
            ),
            &output,
        )
    }

    #[tool(
        name = "bash",
        title = "Run shell command",
        description = "Run command or attach pid. Wait <=2s; long jobs continue. Attach is immediate. Output <=2000 lines/50KB; full log path returned.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<BashResult>(),
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn bash(
        &self,
        Parameters(input): Parameters<BashParams>,
    ) -> Result<CallToolResult, McpError> {
        if self.state.security.mode == SecurityMode::Readonly {
            return Err(tool_error("bash is disabled in readonly mode"));
        }
        match (input.command, input.pid) {
            (Some(command), None) => self.start_command(command).await,
            (None, Some(pid)) => self.attach_process(pid).await,
            _ => Err(tool_error("provide exactly one of command or pid")),
        }
    }

    async fn start_command(&self, command: String) -> Result<CallToolResult, McpError> {
        let (log_dir, visible_log_dir) = if let Some(sandbox) = self.state.sandbox.as_ref() {
            let dir = sandbox.temp_dir().join("pc").join("tasks");
            (dir.clone(), dir)
        } else {
            let dir = std::env::temp_dir().join("pc").join("tasks");
            (dir.clone(), dir)
        };
        tokio::fs::create_dir_all(&log_dir)
            .await
            .map_err(|e| tool_error(format!("create command log directory: {e}")))?;
        cleanup_task_logs(&log_dir, &self.state.processes).await?;
        let file_name = format!("{}.log", Uuid::new_v4());
        let log_path = log_dir.join(&file_name);
        let visible_log_path = visible_log_dir
            .join(file_name)
            .to_string_lossy()
            .to_string();

        let stdout_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| tool_error(format!("open command log: {e}")))?;
        let stderr_file = stdout_file
            .try_clone()
            .map_err(|e| tool_error(format!("clone command log: {e}")))?;

        let mut child = if let Some(sandbox) = self.state.sandbox.as_ref() {
            sandbox
                .bash_command(&command)
                .map_err(|e| tool_error(format!("prepare sandbox shell: {e}")))?
        } else {
            native_shell_command(&command, &self.state.workspace)
        };
        let mut child = child
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .map_err(|e| tool_error(format!("spawn shell: {e}")))?;

        let pid = child
            .id()
            .ok_or_else(|| tool_error("spawned bash has no pid"))?;
        let entry = Arc::new(ProcessEntry {
            pid,
            log_path,
            visible_log_path,
            state: RwLock::new(ProcessState {
                finished: false,
                exit_code: None,
            }),
        });
        self.state
            .processes
            .inner
            .write()
            .await
            .insert(pid, entry.clone());

        match tokio::time::timeout(SYNC_WAIT, child.wait()).await {
            Ok(waited) => {
                let status = waited.map_err(|e| tool_error(format!("wait for bash: {e}")))?;
                finish_entry(&entry, status.code()).await;
                self.process_result(&entry).await
            }
            Err(_) => {
                let background = entry.clone();
                tokio::spawn(async move {
                    let code = child.wait().await.ok().and_then(|status| status.code());
                    finish_entry(&background, code).await;
                });
                self.process_result(&entry).await
            }
        }
    }

    async fn attach_process(&self, pid: u32) -> Result<CallToolResult, McpError> {
        let entry = self
            .state
            .processes
            .inner
            .read()
            .await
            .get(&pid)
            .cloned()
            .ok_or_else(|| tool_error(format!("unknown pid {pid}")))?;

        self.process_result(&entry).await
    }

    async fn process_result(&self, entry: &Arc<ProcessEntry>) -> Result<CallToolResult, McpError> {
        let state = *entry.state.read().await;
        let (output, truncated) = bounded_tail(&entry.log_path).await?;
        let full_path = entry.visible_log_path.clone();

        if !state.finished {
            let result = BashResult {
                status: "running",
                pid: entry.pid,
                exit_code: None,
                output,
                full_output_path: Some(full_path),
                truncated,
                instruction: Some("Still running. Continue other work and attach this pid later."),
            };
            return bash_result(result);
        }

        let result = BashResult {
            status: "exited",
            pid: entry.pid,
            exit_code: state.exit_code,
            output,
            full_output_path: Some(full_path),
            truncated,
            instruction: None,
        };

        bash_result(result)
    }
}

#[tool_handler]
impl ServerHandler for PcMcp {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(PC_PROTOCOL_VERSIONS)
    }

    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_server_info(Implementation::new("pc", env!("CARGO_PKG_VERSION")))
        .with_instructions(format!(
            "Four tools: read/write/edit/bash. Security={:?}. Long bash commands detach after 2s; attach by pid.",
            self.state.security.mode
        ))
    }

    fn discover(
        &self,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<DiscoverResult, McpError>> + Send + '_ {
        let result = DiscoverResult::from_server_info(
            self.supported_protocol_versions().into_owned(),
            self.get_info(),
        )
        // Match MCPX/go-sdk's connect-time discovery contract. ChatGPT uses
        // this response to decide whether to perform the automatic action scan.
        .with_cache_scope(CacheScope::Public);
        std::future::ready(Ok(result))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<rmcp::RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let modern = context
            .protocol_version()
            .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28);
        let mut result = ListToolsResult::with_all_items(self.tool_router.list_all());

        if modern {
            result.ttl_ms = Some(0);
            result.cache_scope = Some(CacheScope::Public);
            result.meta.get_or_insert_default().insert(
                "io.modelcontextprotocol/serverInfo".to_string(),
                serde_json::to_value(self.get_info().server_info)
                    .expect("server implementation serialization cannot fail"),
            );
        }

        Ok(result)
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        Some(requested.supported_by(&self.get_info().capabilities))
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), McpError> {
        context.cancelled().await;
        Ok(())
    }
}

async fn finish_entry(entry: &Arc<ProcessEntry>, exit_code: Option<i32>) {
    let mut state = entry.state.write().await;
    state.finished = true;
    state.exit_code = exit_code;
    drop(state);
}

#[cfg(windows)]
fn native_shell_command(command: &str, workspace: &Path) -> tokio::process::Command {
    let mut process = tokio::process::Command::new("cmd.exe");
    process
        .arg("/D")
        .arg("/S")
        .arg("/C")
        .arg(command)
        .current_dir(workspace);
    process
}

#[cfg(not(windows))]
fn native_shell_command(command: &str, workspace: &Path) -> tokio::process::Command {
    let mut process = tokio::process::Command::new("bash");
    process.arg("-lc").arg(command).current_dir(workspace);
    process
}

fn ensure_secret_access(path: &Path, protect_secrets: bool) -> Result<(), McpError> {
    if !protect_secrets {
        return Ok(());
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Ok(());
    };
    let protected = [
        home.join(".ssh"),
        home.join(".aws"),
        home.join(".config/gh"),
        home.join(".config/gcloud"),
        home.join(".git-credentials"),
        home.join(".netrc"),
        home.join(".npmrc"),
        home.join(".docker/config.json"),
        home.join(".kube/config"),
    ];
    if protected
        .iter()
        .any(|secret| path == secret || path.starts_with(secret))
    {
        return Err(tool_error(format!(
            "access to {} is blocked by protect_secrets",
            path.display()
        )));
    }
    Ok(())
}

fn resolve_path(workspace: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    }
}

async fn cleanup_task_logs(log_dir: &Path, processes: &ProcessRegistry) -> Result<(), McpError> {
    cleanup_task_logs_with_limits(log_dir, processes, LOG_RETENTION, MAX_LOG_DIR_BYTES).await
}

async fn cleanup_task_logs_with_limits(
    log_dir: &Path,
    processes: &ProcessRegistry,
    retention: Duration,
    max_bytes: u64,
) -> Result<(), McpError> {
    let entries = {
        let registry = processes.inner.read().await;
        registry.values().cloned().collect::<Vec<_>>()
    };

    let mut active = HashSet::new();
    let mut finished_by_path = HashMap::new();
    for entry in entries {
        if entry.state.read().await.finished {
            finished_by_path.insert(entry.log_path.clone(), entry.pid);
        } else {
            active.insert(entry.log_path.clone());
        }
    }

    let mut dir = tokio::fs::read_dir(log_dir)
        .await
        .map_err(|e| tool_error(format!("read command log directory: {e}")))?;
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    while let Some(item) = dir
        .next_entry()
        .await
        .map_err(|e| tool_error(format!("scan command log directory: {e}")))?
    {
        let path = item.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("log") {
            continue;
        }
        let metadata = item
            .metadata()
            .await
            .map_err(|e| tool_error(format!("stat command log {}: {e}", path.display())))?;
        let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
        total_bytes = total_bytes.saturating_add(metadata.len());
        files.push((path, metadata.len(), modified));
    }

    let now = std::time::SystemTime::now();
    let mut deleted = HashSet::new();
    let mut deleted_pids = Vec::new();

    for (path, bytes, modified) in &files {
        if active.contains(path) {
            continue;
        }
        let age = now.duration_since(*modified).unwrap_or_default();
        if age < retention {
            continue;
        }
        if tokio::fs::remove_file(path).await.is_ok() {
            deleted.insert(path.clone());
            total_bytes = total_bytes.saturating_sub(*bytes);
            if let Some(pid) = finished_by_path.get(path) {
                deleted_pids.push(*pid);
            }
        }
    }

    if total_bytes > max_bytes {
        files.sort_by_key(|(_, _, modified)| *modified);
        for (path, bytes, _) in &files {
            if total_bytes <= max_bytes {
                break;
            }
            if active.contains(path) || deleted.contains(path) {
                continue;
            }
            if tokio::fs::remove_file(path).await.is_ok() {
                deleted.insert(path.clone());
                total_bytes = total_bytes.saturating_sub(*bytes);
                if let Some(pid) = finished_by_path.get(path) {
                    deleted_pids.push(*pid);
                }
            }
        }
    }

    if !deleted_pids.is_empty() {
        let mut registry = processes.inner.write().await;
        for pid in deleted_pids {
            registry.remove(&pid);
        }
    }

    Ok(())
}

async fn bounded_tail(path: &Path) -> Result<(String, bool), McpError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| tool_error(format!("read command log: {e}")))?;
    let len = file
        .metadata()
        .await
        .map_err(|e| tool_error(format!("stat command log: {e}")))?
        .len();
    let start = len.saturating_sub(MAX_TAIL_READ_BYTES);
    if start > 0 {
        file.seek(SeekFrom::Start(start))
            .await
            .map_err(|e| tool_error(format!("seek command log: {e}")))?;
    }

    let mut bytes = Vec::with_capacity((len - start) as usize);
    file.read_to_end(&mut bytes)
        .await
        .map_err(|e| tool_error(format!("read command log tail: {e}")))?;

    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    let mut truncated = start > 0;
    if start > 0
        && let Some(newline) = text.find('\n')
    {
        text.drain(..=newline);
    }

    let total_lines = text.lines().count();
    if total_lines > MAX_OUTPUT_LINES {
        let mut lines: Vec<&str> = text.lines().rev().take(MAX_OUTPUT_LINES).collect();
        lines.reverse();
        text = lines.join("\n");
        truncated = true;
    }

    if text.len() > MAX_OUTPUT_BYTES {
        let mut boundary = text.len() - MAX_OUTPUT_BYTES;
        while !text.is_char_boundary(boundary) {
            boundary += 1;
        }
        text = text[boundary..].to_string();
        if let Some(newline) = text.find('\n') {
            text = text[newline + 1..].to_string();
        }
        truncated = true;
    }

    if truncated {
        text.push_str(&format!(
            "\n\n[Output truncated. Full output: {}]",
            path.display()
        ));
    }
    Ok((text, truncated))
}

fn prepare_image_preview(bytes: &[u8], mime_type: &str) -> Result<ImagePreview, McpError> {
    let format = match mime_type {
        "image/png" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        "image/webp" => ImageFormat::WebP,
        "image/gif" => ImageFormat::Gif,
        _ => {
            return Err(tool_error(format!(
                "unsupported image MIME type: {mime_type}"
            )));
        }
    };

    let image = image::load_from_memory_with_format(bytes, format)
        .map_err(|e| tool_error(format!("decode {mime_type} image: {e}")))?;
    let (original_width, original_height) = image.dimensions();

    if original_width <= MAX_IMAGE_PREVIEW_EDGE && original_height <= MAX_IMAGE_PREVIEW_EDGE {
        return Ok(ImagePreview {
            bytes: bytes.to_vec(),
            mime_type: mime_type.to_string(),
            original_width,
            original_height,
            width: original_width,
            height: original_height,
            resized: false,
        });
    }

    let resized = image.resize(
        MAX_IMAGE_PREVIEW_EDGE,
        MAX_IMAGE_PREVIEW_EDGE,
        FilterType::Triangle,
    );
    let (width, height) = resized.dimensions();

    let (preview_bytes, preview_mime_type) = if resized.color().has_alpha() {
        let mut cursor = Cursor::new(Vec::new());
        resized
            .write_to(&mut cursor, ImageFormat::Png)
            .map_err(|e| tool_error(format!("encode PNG image preview: {e}")))?;
        (cursor.into_inner(), "image/png")
    } else {
        let rgb = resized.to_rgb8();
        let mut encoded = Vec::new();
        JpegEncoder::new_with_quality(&mut encoded, IMAGE_PREVIEW_JPEG_QUALITY)
            .encode(rgb.as_raw(), width, height, image::ExtendedColorType::Rgb8)
            .map_err(|e| tool_error(format!("encode JPEG image preview: {e}")))?;
        (encoded, "image/jpeg")
    };

    Ok(ImagePreview {
        bytes: preview_bytes,
        mime_type: preview_mime_type.to_string(),
        original_width,
        original_height,
        width,
        height,
        resized: true,
    })
}

fn image_mime_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else {
        None
    }
}

fn text_result(text: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text.into())])
}

fn structured_text_result(
    text: impl Into<String>,
    value: &impl Serialize,
) -> Result<CallToolResult, McpError> {
    let mut result = text_result(text);
    result.structured_content =
        Some(serde_json::to_value(value).map_err(|e| tool_error(e.to_string()))?);
    Ok(result)
}

fn bash_result(value: BashResult) -> Result<CallToolResult, McpError> {
    let summary = match value.exit_code {
        Some(code) => format!(
            "{} pid={} exit_code={} log={}",
            value.status,
            value.pid,
            code,
            value.full_output_path.as_deref().unwrap_or("-")
        ),
        None => format!(
            "{} pid={} log={}",
            value.status,
            value.pid,
            value.full_output_path.as_deref().unwrap_or("-")
        ),
    };
    structured_text_result(summary, &value)
}

fn tool_error(message: impl Into<String>) -> McpError {
    McpError::internal_error(message.into(), None)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn publishes_explicit_tool_safety_annotations() {
        let read = PcMcp::read_tool_attr();
        assert_eq!(read.title.as_deref(), Some("Read file"));
        let read = read.annotations.expect("read annotations");
        assert_eq!(read.title, None);
        assert_eq!(read.read_only_hint, Some(true));
        assert_eq!(read.destructive_hint, Some(false));
        assert_eq!(read.idempotent_hint, Some(true));
        assert_eq!(read.open_world_hint, Some(false));

        let write = PcMcp::write_tool_attr();
        assert_eq!(write.title.as_deref(), Some("Write file"));
        let write = write.annotations.expect("write annotations");
        assert_eq!(write.title, None);
        assert_eq!(write.read_only_hint, Some(false));
        assert_eq!(write.destructive_hint, Some(true));
        assert_eq!(write.idempotent_hint, Some(true));
        assert_eq!(write.open_world_hint, Some(false));

        let edit = PcMcp::edit_tool_attr();
        assert_eq!(edit.title.as_deref(), Some("Edit file"));
        let edit = edit.annotations.expect("edit annotations");
        assert_eq!(edit.title, None);
        assert_eq!(edit.read_only_hint, Some(false));
        assert_eq!(edit.destructive_hint, Some(true));
        assert_eq!(edit.idempotent_hint, Some(false));
        assert_eq!(edit.open_world_hint, Some(false));

        let bash = PcMcp::bash_tool_attr();
        assert_eq!(bash.title.as_deref(), Some("Run shell command"));
        let bash = bash.annotations.expect("bash annotations");
        assert_eq!(bash.title, None);
        assert_eq!(bash.read_only_hint, Some(false));
        assert_eq!(bash.destructive_hint, Some(true));
        assert_eq!(bash.idempotent_hint, Some(false));
        assert_eq!(bash.open_world_hint, Some(true));
    }

    #[test]
    fn advertises_mcpx_compatible_discovery_protocols() {
        assert_eq!(
            PC_PROTOCOL_VERSIONS,
            &[
                ProtocolVersion::V_2026_07_28,
                ProtocolVersion::V_2025_11_25,
                ProtocolVersion::V_2025_06_18,
                ProtocolVersion::V_2025_03_26,
                ProtocolVersion::V_2024_11_05,
            ]
        );
    }

    #[test]
    fn publishes_compact_schemas_for_all_tools() {
        for tool in [
            PcMcp::read_tool_attr(),
            PcMcp::write_tool_attr(),
            PcMcp::edit_tool_attr(),
            PcMcp::bash_tool_attr(),
        ] {
            let input_json =
                serde_json::to_string(&tool.input_schema).expect("serialize tool input schema");
            assert!(
                input_json.len() < 1536,
                "{} inputSchema must remain compact; got {} bytes",
                tool.name,
                input_json.len()
            );

            let output = tool
                .output_schema
                .as_ref()
                .unwrap_or_else(|| panic!("{} must expose outputSchema", tool.name));
            let output_json = serde_json::to_string(output).expect("serialize tool output schema");
            assert!(
                output_json.len() < 1024,
                "{} outputSchema must remain compact; got {} bytes",
                tool.name,
                output_json.len()
            );

            let tool_json = serde_json::to_string(&tool).expect("serialize tool declaration");
            assert!(
                tool_json.len() < 2500,
                "{} tool declaration must remain compact; got {} bytes",
                tool.name,
                tool_json.len()
            );
        }
    }

    #[test]
    fn detects_supported_image_formats_by_content() {
        assert_eq!(image_mime_type(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(image_mime_type(b"\xff\xd8\xffrest"), Some("image/jpeg"));
        assert_eq!(
            image_mime_type(b"RIFF\x00\x00\x00\x00WEBPrest"),
            Some("image/webp")
        );
        assert_eq!(image_mime_type(b"GIF89arest"), Some("image/gif"));
        assert_eq!(image_mime_type(b"plain text"), None);
    }

    fn encode_test_png(width: u32, height: u32) -> Vec<u8> {
        let image = image::DynamicImage::new_rgb8(width, height);
        let mut cursor = Cursor::new(Vec::new());
        image
            .write_to(&mut cursor, ImageFormat::Png)
            .expect("encode test PNG");
        cursor.into_inner()
    }

    fn image_test_state(workspace: &Path) -> Arc<AppState> {
        Arc::new(AppState {
            public_url: None,
            oauth_password: None,
            workspace: workspace.to_path_buf(),
            security: crate::config::SecurityConfig::default(),
            sandbox: None,
            allowed_redirect_hosts: Vec::new(),
            production: false,
            processes: ProcessRegistry::default(),
        })
    }

    #[tokio::test]
    async fn read_small_image_returns_original_as_embedded_resource_only() {
        let workspace = std::env::temp_dir().join(format!("pc-image-test-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&workspace)
            .await
            .expect("create test workspace");
        let image_bytes = encode_test_png(640, 320);
        let image_path = workspace.join("test.png");
        tokio::fs::write(&image_path, &image_bytes)
            .await
            .expect("write test image");

        let mcp = PcMcp::new(image_test_state(&workspace));
        let result = mcp
            .read(Parameters(ReadParams {
                path: "test.png".into(),
                offset: None,
                limit: None,
            }))
            .await
            .expect("read image");

        assert_eq!(result.content.len(), 2);
        assert!(result.content.iter().all(|item| item.as_image().is_none()));

        let metadata: serde_json::Value = serde_json::from_str(
            &result.content[0]
                .as_text()
                .expect("first content block must be metadata text")
                .text,
        )
        .expect("parse image metadata");
        assert_eq!(metadata["originalWidth"], 640);
        assert_eq!(metadata["originalHeight"], 320);
        assert_eq!(metadata["previewWidth"], 640);
        assert_eq!(metadata["previewHeight"], 320);
        assert_eq!(metadata["previewMimeType"], "image/png");
        assert_eq!(metadata["resized"], false);

        let resource = result.content[1]
            .as_resource()
            .expect("second content block must be an embedded resource");
        match &resource.resource {
            ResourceContents::BlobResourceContents {
                uri,
                mime_type,
                blob,
                ..
            } => {
                assert!(uri.starts_with("pc://read-image/"));
                assert!(uri.ends_with("/preview.png"));
                assert_eq!(mime_type.as_deref(), Some("image/png"));
                assert_eq!(
                    STANDARD.decode(blob).expect("decode embedded blob"),
                    image_bytes
                );
            }
            _ => panic!("embedded resource must contain a blob"),
        }
        assert_eq!(result.structured_content, None);
        assert_eq!(
            tokio::fs::read(&image_path).await.expect("reread original"),
            image_bytes
        );

        let _ = tokio::fs::remove_dir_all(workspace).await;
    }

    #[tokio::test]
    async fn read_large_image_downscales_preview_without_modifying_original() {
        let workspace = std::env::temp_dir().join(format!("pc-image-test-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&workspace)
            .await
            .expect("create test workspace");
        let image_bytes = encode_test_png(4096, 1024);
        let image_path = workspace.join("large.png");
        tokio::fs::write(&image_path, &image_bytes)
            .await
            .expect("write test image");

        let mcp = PcMcp::new(image_test_state(&workspace));
        let result = mcp
            .read(Parameters(ReadParams {
                path: "large.png".into(),
                offset: None,
                limit: None,
            }))
            .await
            .expect("read large image");

        assert_eq!(result.content.len(), 2);
        assert!(result.content.iter().all(|item| item.as_image().is_none()));

        let metadata: serde_json::Value = serde_json::from_str(
            &result.content[0]
                .as_text()
                .expect("first content block must be metadata text")
                .text,
        )
        .expect("parse image metadata");
        assert_eq!(metadata["originalWidth"], 4096);
        assert_eq!(metadata["originalHeight"], 1024);
        assert_eq!(metadata["previewWidth"], 2048);
        assert_eq!(metadata["previewHeight"], 512);
        assert_eq!(metadata["previewMimeType"], "image/jpeg");
        assert_eq!(metadata["resized"], true);

        let resource = result.content[1]
            .as_resource()
            .expect("second content block must be an embedded resource");
        match &resource.resource {
            ResourceContents::BlobResourceContents {
                uri,
                mime_type,
                blob,
                ..
            } => {
                assert!(uri.ends_with("/preview.jpg"));
                assert_eq!(mime_type.as_deref(), Some("image/jpeg"));
                let preview_bytes = STANDARD.decode(blob).expect("decode embedded preview");
                let preview =
                    image::load_from_memory_with_format(&preview_bytes, ImageFormat::Jpeg)
                        .expect("decode preview JPEG");
                assert_eq!(preview.dimensions(), (2048, 512));
            }
            _ => panic!("embedded resource must contain a blob"),
        }
        assert_eq!(result.structured_content, None);
        assert_eq!(
            tokio::fs::read(&image_path).await.expect("reread original"),
            image_bytes
        );

        let _ = tokio::fs::remove_dir_all(workspace).await;
    }

    #[test]
    fn bash_result_does_not_duplicate_full_output_in_text_content() {
        let result = bash_result(BashResult {
            status: "exited",
            pid: 7,
            exit_code: Some(0),
            output: "very large output body".to_string(),
            full_output_path: Some("/tmp/task.log".to_string()),
            truncated: false,
            instruction: None,
        })
        .expect("build bash result");

        let text = result.content[0]
            .as_text()
            .expect("bash summary must be text")
            .text
            .clone();
        assert!(!text.contains("very large output body"));
        assert_eq!(
            result.structured_content.as_ref().unwrap()["output"],
            "very large output body"
        );
    }

    #[tokio::test]
    async fn bounded_tail_reads_only_a_bounded_suffix() {
        let workspace = std::env::temp_dir().join(format!("pc-tail-test-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&workspace)
            .await
            .expect("create tail test workspace");
        let path = workspace.join("large.log");

        let mut content = String::new();
        for index in 0..20_000 {
            content.push_str(&format!("line-{index:05} payload payload payload\n"));
        }
        tokio::fs::write(&path, content)
            .await
            .expect("write large log");

        let (tail, truncated) = bounded_tail(&path).await.expect("read bounded tail");
        assert!(truncated);
        assert!(tail.len() <= MAX_OUTPUT_BYTES + 256);
        assert!(tail.contains("line-19999"));

        let _ = tokio::fs::remove_dir_all(workspace).await;
    }

    #[tokio::test]
    async fn log_cleanup_preserves_active_logs_and_enforces_quota() {
        let workspace = std::env::temp_dir().join(format!("pc-log-cleanup-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&workspace)
            .await
            .expect("create cleanup workspace");

        let stale = workspace.join("stale.log");
        let active_path = workspace.join("active.log");
        tokio::fs::write(&stale, b"stale")
            .await
            .expect("write stale log");
        tokio::fs::write(&active_path, b"active")
            .await
            .expect("write active log");

        let registry = ProcessRegistry::default();
        registry.inner.write().await.insert(
            42,
            Arc::new(ProcessEntry {
                pid: 42,
                log_path: active_path.clone(),
                visible_log_path: active_path.to_string_lossy().into_owned(),
                state: RwLock::new(ProcessState {
                    finished: false,
                    exit_code: None,
                }),
            }),
        );

        cleanup_task_logs_with_limits(&workspace, &registry, Duration::ZERO, u64::MAX)
            .await
            .expect("remove stale logs");
        assert!(!stale.exists());
        assert!(active_path.exists());

        let q1 = workspace.join("q1.log");
        let q2 = workspace.join("q2.log");
        tokio::fs::write(&q1, vec![b'a'; 10])
            .await
            .expect("write q1");
        tokio::fs::write(&q2, vec![b'b'; 10])
            .await
            .expect("write q2");
        cleanup_task_logs_with_limits(&workspace, &registry, Duration::from_secs(3600), 16)
            .await
            .expect("enforce log quota");

        let mut dir = tokio::fs::read_dir(&workspace)
            .await
            .expect("scan cleanup workspace");
        let mut total = 0u64;
        while let Some(entry) = dir.next_entry().await.expect("read cleanup entry") {
            total += entry.metadata().await.expect("stat cleanup entry").len();
        }
        assert!(
            total <= 16,
            "active log is protected; non-active logs must be pruned"
        );
        assert!(active_path.exists());

        let _ = tokio::fs::remove_dir_all(workspace).await;
    }

    #[tokio::test]
    async fn long_bash_detaches_then_attaches_same_pid() {
        let workspace = std::env::temp_dir().join(format!("pc-bash-test-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&workspace)
            .await
            .expect("create test workspace");

        let state = Arc::new(AppState {
            public_url: None,
            oauth_password: None,
            workspace: workspace.clone(),
            security: crate::config::SecurityConfig::default(),
            sandbox: None,
            allowed_redirect_hosts: Vec::new(),
            production: false,
            processes: ProcessRegistry::default(),
        });
        let mcp = PcMcp::new(state.clone());

        let started = Instant::now();
        let first = mcp
            .start_command(long_test_command().into())
            .await
            .expect("long command should detach cleanly");

        assert!(
            started.elapsed() < Duration::from_millis(3_500),
            "bash call waited too long before detaching"
        );
        assert_eq!(
            first.structured_content.as_ref().unwrap()["status"],
            "running"
        );

        let entry = {
            let processes = state.processes.inner.read().await;
            assert_eq!(processes.len(), 1);
            processes.values().next().unwrap().clone()
        };
        let pid = entry.pid;
        assert!(!entry.state.read().await.finished);

        let attach_started = Instant::now();
        let attached = mcp
            .attach_process(pid)
            .await
            .expect("attach should return an immediate snapshot");
        assert!(
            attach_started.elapsed() < Duration::from_millis(750),
            "attach waited instead of returning immediately"
        );
        assert_eq!(
            attached.structured_content.as_ref().unwrap()["status"],
            "running"
        );

        tokio::time::sleep(Duration::from_millis(2_500)).await;
        let finished = mcp
            .attach_process(pid)
            .await
            .expect("finished process should remain attachable");
        assert_eq!(
            finished.structured_content.as_ref().unwrap()["status"],
            "exited"
        );

        let final_state = *entry.state.read().await;
        assert!(final_state.finished);
        assert_eq!(final_state.exit_code, Some(0));

        let log = tokio::fs::read_to_string(&entry.log_path)
            .await
            .expect("read command log");
        assert_eq!(log.trim(), "done");

        let _ = tokio::fs::remove_dir_all(workspace).await;
    }

    #[cfg(windows)]
    fn long_test_command() -> &'static str {
        "ping -n 5 127.0.0.1 >NUL & echo done"
    }

    #[cfg(not(windows))]
    fn long_test_command() -> &'static str {
        "sleep 4; printf done"
    }
}
