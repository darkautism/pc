use std::{
    borrow::Cow,
    collections::HashMap,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CacheScope, CallToolResult, ContentBlock, DiscoverResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
        SubscriptionFilter,
    },
    schemars,
    service::{RequestContext, SubscriptionContext},
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};
use uuid::Uuid;

use crate::{AppState, config::SecurityMode};

const MAX_OUTPUT_BYTES: usize = 50 * 1024;
const MAX_IMAGE_BYTES: usize = 25 * 1024 * 1024;
const MAX_OUTPUT_LINES: usize = 2000;
const SYNC_WAIT: Duration = Duration::from_secs(10);
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
    notify: Notify,
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
    #[schemars(description = "Path to the file to read (relative or absolute)")]
    pub path: String,
    #[schemars(description = "Line number to start reading from (1-indexed)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum number of lines to read")]
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteParams {
    #[schemars(description = "Path to the file to write (relative or absolute)")]
    pub path: String,
    #[schemars(description = "Content to write to the file")]
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
    #[schemars(
        description = "Exact text for one targeted replacement. It must be unique in the original file and must not overlap with any other edits[].oldText in the same call."
    )]
    pub old_text: String,
    #[serde(rename = "newText")]
    #[schemars(description = "Replacement text for this targeted edit.")]
    pub new_text: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EditParams {
    #[schemars(description = "Path to the file to edit (relative or absolute)")]
    pub path: String,
    #[schemars(
        description = "One or more targeted replacements. Each edit is matched against the original file, not incrementally. Do not include overlapping or nested edits."
    )]
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
    #[schemars(
        description = "Shell command to execute. Mutually exclusive with pid. Commands are never synchronously awaited for more than 10 seconds."
    )]
    pub command: Option<String>,
    #[schemars(
        description = "PID returned by an earlier long-running bash call. Mutually exclusive with command. Attach waits at most 10 seconds."
    )]
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
        description = "Read a file. PNG, JPEG, WebP, and GIF files are returned as native MCP image content so vision-capable clients can inspect them directly. Other files are read as UTF-8 text. Relative paths resolve from the configured working directory; absolute paths are allowed anywhere the server process can access. Text output is truncated to 2000 lines or 50KB (whichever is hit first); use offset/limit to continue large text files. offset/limit are ignored for recognized images.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ReadOutput>(),
        annotations(
            title = "Read file",
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

            let structured = ReadOutput {
                mime_type: mime_type.to_string(),
                bytes: total_bytes,
                path: input.path,
            };
            let metadata = serde_json::to_string(&structured)
                .map_err(|e| tool_error(format!("serialize read result: {e}")))?;
            return Ok(CallToolResult::success(vec![
                ContentBlock::text(metadata),
                ContentBlock::image(STANDARD.encode(&bytes), mime_type),
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
        description = "Write content to a file. Relative paths resolve from the configured working directory; absolute paths are allowed anywhere the server process can access. Creates the file if it doesn't exist, overwrites if it does, and automatically creates parent directories.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<WriteOutput>(),
        annotations(
            title = "Write file",
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
        description = "Make precise file edits with exact text replacement, including multiple disjoint edits in one call. Relative paths resolve from the configured working directory; absolute paths are allowed anywhere the server process can access. Each edits[].oldText must match exactly once in the original file.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<EditOutput>(),
        annotations(
            title = "Edit file",
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
        description = "Execute a non-interactive shell command in the configured workspace, or attach to a PID returned by a prior call. Unix uses bash; Windows uses cmd.exe. A command is synchronously awaited for at most 10 seconds. If still running, it is NOT killed: the tool returns its PID and asks you to do other independent work before attaching later. Attach also waits at most 10 seconds. stdout/stderr are combined; visible output is limited to the last 2000 lines or 50KB, with full output stored in the returned log path. Pipes and redirection are supported; interactive TTY/curses programs are not.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<BashResult>(),
        annotations(
            title = "Run shell command",
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
            notify: Notify::new(),
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

        let notified = entry.notify.notified();
        if !entry.state.read().await.finished {
            let _ = tokio::time::timeout(SYNC_WAIT, notified).await;
        }
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
                instruction: Some(
                    "This task is taking longer than 10 seconds. Continue with other independent work and attach this pid later. Do not immediately wait on it again unless its result is now required.",
                ),
            };
            return json_result(&result);
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

        json_result(&result)
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
        .with_instructions(
            format!("pc exposes exactly four coding tools: read, write, edit, and bash. Security mode is {:?}. In full mode, paths and bash use the host directly under OS permissions. In safe mode, each tool command self-reexecs through an embedded rootless Linux sandbox: Landlock when fully available, otherwise a rootless user/mount namespace allowlist, plus no-new-privileges and a seccomp denylist. Only the workspace, pc temp/home, required runtime paths, and optional explicit credential paths are visible. In readonly mode, write/edit/bash are disabled. bash never spends more than 10 seconds synchronously waiting for a command; when status=running, continue useful independent work and attach the returned pid later. Pipes/redirection are supported; curses/TTY programs are not. Every bash invocation writes combined stdout/stderr to a readable temp log.", self.state.security.mode),
        )
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
    entry.notify.notify_waiters();
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

async fn bounded_tail(path: &Path) -> Result<(String, bool), McpError> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| tool_error(format!("read command log: {e}")))?;
    let text = String::from_utf8_lossy(&bytes);
    let total_lines = text.lines().count();

    if bytes.len() <= MAX_OUTPUT_BYTES && total_lines <= MAX_OUTPUT_LINES {
        return Ok((text.into_owned(), false));
    }

    let mut lines: Vec<&str> = text.lines().rev().take(MAX_OUTPUT_LINES).collect();
    lines.reverse();
    let mut output = lines.join("\n");

    if output.len() > MAX_OUTPUT_BYTES {
        let start = output.len() - MAX_OUTPUT_BYTES;
        let mut boundary = start;
        while !output.is_char_boundary(boundary) {
            boundary += 1;
        }
        output = output[boundary..].to_string();
        if let Some(newline) = output.find('\n') {
            output = output[newline + 1..].to_string();
        }
    }

    output.push_str(&format!(
        "\n\n[Output truncated. Showing the last bounded portion. Full output: {}]",
        path.display()
    ));
    Ok((output, true))
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

fn json_result(value: &impl Serialize) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(value).map_err(|e| tool_error(e.to_string()))?;
    structured_text_result(text, value)
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
        assert_eq!(read.read_only_hint, Some(true));
        assert_eq!(read.destructive_hint, Some(false));
        assert_eq!(read.idempotent_hint, Some(true));
        assert_eq!(read.open_world_hint, Some(false));

        let write = PcMcp::write_tool_attr();
        assert_eq!(write.title.as_deref(), Some("Write file"));
        let write = write.annotations.expect("write annotations");
        assert_eq!(write.read_only_hint, Some(false));
        assert_eq!(write.destructive_hint, Some(true));
        assert_eq!(write.idempotent_hint, Some(true));
        assert_eq!(write.open_world_hint, Some(false));

        let edit = PcMcp::edit_tool_attr();
        assert_eq!(edit.title.as_deref(), Some("Edit file"));
        let edit = edit.annotations.expect("edit annotations");
        assert_eq!(edit.read_only_hint, Some(false));
        assert_eq!(edit.destructive_hint, Some(true));
        assert_eq!(edit.idempotent_hint, Some(false));
        assert_eq!(edit.open_world_hint, Some(false));

        let bash = PcMcp::bash_tool_attr();
        assert_eq!(bash.title.as_deref(), Some("Run shell command"));
        let bash = bash.annotations.expect("bash annotations");
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
    fn publishes_compact_output_schemas_for_all_tools() {
        for tool in [
            PcMcp::read_tool_attr(),
            PcMcp::write_tool_attr(),
            PcMcp::edit_tool_attr(),
            PcMcp::bash_tool_attr(),
        ] {
            let schema = tool
                .output_schema
                .as_ref()
                .unwrap_or_else(|| panic!("{} must expose outputSchema", tool.name));
            let schema_json = serde_json::to_string(schema).expect("serialize tool output schema");
            assert!(
                schema_json.len() < 4096,
                "{} outputSchema must remain compact; got {} bytes",
                tool.name,
                schema_json.len()
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

    #[tokio::test]
    async fn read_returns_native_mcp_image_content() {
        let workspace = std::env::temp_dir().join(format!("pc-image-test-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&workspace)
            .await
            .expect("create test workspace");
        let image_bytes = b"\x89PNG\r\n\x1a\npc-test-image";
        tokio::fs::write(workspace.join("test.png"), image_bytes)
            .await
            .expect("write test image");

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
        let mcp = PcMcp::new(state);
        let result = mcp
            .read(Parameters(ReadParams {
                path: "test.png".into(),
                offset: None,
                limit: None,
            }))
            .await
            .expect("read image");

        assert_eq!(result.content.len(), 2);
        assert!(
            result.content[0]
                .as_text()
                .is_some_and(|text| text.text.contains("image/png"))
        );
        let image = result.content[1]
            .as_image()
            .expect("second content block must be an image");
        assert_eq!(image.mime_type, "image/png");
        assert_eq!(image.data, STANDARD.encode(image_bytes));
        assert_eq!(result.structured_content, None);

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
        mcp.start_command(long_test_command().into())
            .await
            .expect("long command should detach cleanly");

        assert!(
            started.elapsed() < Duration::from_millis(11_500),
            "bash call waited for the command instead of detaching"
        );

        let entry = {
            let processes = state.processes.inner.read().await;
            assert_eq!(processes.len(), 1);
            processes.values().next().unwrap().clone()
        };
        let pid = entry.pid;
        assert!(!entry.state.read().await.finished);

        mcp.attach_process(pid)
            .await
            .expect("attach should observe the original process finishing");

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
        "ping -n 13 127.0.0.1 >NUL & echo done"
    }

    #[cfg(not(windows))]
    fn long_test_command() -> &'static str {
        "sleep 12; printf done"
    }
}
