use std::{
    collections::HashMap,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};
use uuid::Uuid;

use crate::AppState;

const MAX_OUTPUT_BYTES: usize = 50 * 1024;
const MAX_OUTPUT_LINES: usize = 2000;
const SYNC_WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Default)]
pub struct ProcessRegistry {
    inner: Arc<RwLock<HashMap<u32, Arc<ProcessEntry>>>>,
}

struct ProcessEntry {
    pid: u32,
    log_path: PathBuf,
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteParams {
    #[schemars(description = "Path to the file to write (relative or absolute)")]
    pub path: String,
    #[schemars(description = "Content to write to the file")]
    pub content: String,
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

#[derive(Debug, Serialize)]
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
        description = "Read the contents of a file. Relative paths resolve from the configured working directory; absolute paths are allowed anywhere the server process can access. For text files, output is truncated to 2000 lines or 50KB (whichever is hit first). Use offset/limit for large files. When you need the full file, continue with offset until complete."
    )]
    async fn read(
        &self,
        Parameters(input): Parameters<ReadParams>,
    ) -> Result<CallToolResult, McpError> {
        let path = resolve_path(&self.state.workspace, &input.path);
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| tool_error(format!("read {}: {e}", input.path)))?;
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

        Ok(text_result(output))
    }

    #[tool(
        name = "write",
        description = "Write content to a file. Relative paths resolve from the configured working directory; absolute paths are allowed anywhere the server process can access. Creates the file if it doesn't exist, overwrites if it does, and automatically creates parent directories."
    )]
    async fn write(
        &self,
        Parameters(input): Parameters<WriteParams>,
    ) -> Result<CallToolResult, McpError> {
        let path = resolve_path(&self.state.workspace, &input.path);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| tool_error(format!("create parent directory: {e}")))?;
        }
        tokio::fs::write(&path, input.content)
            .await
            .map_err(|e| tool_error(format!("write {}: {e}", input.path)))?;
        Ok(text_result(format!("Successfully wrote to {}", input.path)))
    }

    #[tool(
        name = "edit",
        description = "Make precise file edits with exact text replacement, including multiple disjoint edits in one call. Relative paths resolve from the configured working directory; absolute paths are allowed anywhere the server process can access. Each edits[].oldText must match exactly once in the original file."
    )]
    async fn edit(
        &self,
        Parameters(input): Parameters<EditParams>,
    ) -> Result<CallToolResult, McpError> {
        if input.edits.is_empty() {
            return Err(tool_error("edits must not be empty"));
        }
        let path = resolve_path(&self.state.workspace, &input.path);
        let original = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| tool_error(format!("read {}: {e}", input.path)))?;

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

        tokio::fs::write(&path, updated)
            .await
            .map_err(|e| tool_error(format!("write {}: {e}", input.path)))?;
        Ok(text_result(format!(
            "Successfully applied {} edit(s) to {}",
            input.edits.len(),
            input.path
        )))
    }

    #[tool(
        name = "bash",
        description = "Execute a non-interactive bash command in the configured workspace, or attach to a PID returned by a prior call. A command is synchronously awaited for at most 10 seconds. If still running, it is NOT killed: the tool returns its PID and asks you to do other independent work before attaching later. Attach also waits at most 10 seconds. stdout/stderr are combined; visible output is limited to the last 2000 lines or 50KB, with full output stored in the returned log path. Pipes and redirection are supported; interactive TTY/curses programs are not."
    )]
    async fn bash(
        &self,
        Parameters(input): Parameters<BashParams>,
    ) -> Result<CallToolResult, McpError> {
        match (input.command, input.pid) {
            (Some(command), None) => self.start_command(command).await,
            (None, Some(pid)) => self.attach_process(pid).await,
            _ => Err(tool_error("provide exactly one of command or pid")),
        }
    }

    async fn start_command(&self, command: String) -> Result<CallToolResult, McpError> {
        let log_dir = std::env::temp_dir().join("pc").join("tasks");
        tokio::fs::create_dir_all(&log_dir)
            .await
            .map_err(|e| tool_error(format!("create command log directory: {e}")))?;
        let log_path = log_dir.join(format!("{}.log", Uuid::new_v4()));

        let stdout_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| tool_error(format!("open command log: {e}")))?;
        let stderr_file = stdout_file
            .try_clone()
            .map_err(|e| tool_error(format!("clone command log: {e}")))?;

        let mut child = tokio::process::Command::new("bash")
            .arg("-lc")
            .arg(command)
            .current_dir(&self.state.workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .map_err(|e| tool_error(format!("spawn bash: {e}")))?;

        let pid = child
            .id()
            .ok_or_else(|| tool_error("spawned bash has no pid"))?;
        let entry = Arc::new(ProcessEntry {
            pid,
            log_path,
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
        let full_path = entry.log_path.to_string_lossy().to_string();

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
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "pc exposes exactly four coding tools: read, write, edit, and bash. read/write/edit intentionally follow Pi-style schemas. Relative file paths use the configured working directory, while absolute paths are not workspace-contained and may access anything allowed by the server OS user. bash is deliberately different: never spend more than 10 seconds synchronously waiting for a command. When bash returns status=running, continue useful independent work and attach the returned pid later. Do not busy-loop by immediately reattaching. bash is non-interactive; pipes/redirection are supported, curses/TTY programs are not. Every bash invocation writes combined stdout/stderr to a system-temp log and returns its absolute path; visible output is a bounded tail.".to_string(),
            )
    }
}

async fn finish_entry(entry: &Arc<ProcessEntry>, exit_code: Option<i32>) {
    let mut state = entry.state.write().await;
    state.finished = true;
    state.exit_code = exit_code;
    drop(state);
    entry.notify.notify_waiters();
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

fn text_result(text: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text.into())])
}

fn json_result(value: &impl Serialize) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(value).map_err(|e| tool_error(e.to_string()))?;
    Ok(text_result(text))
}

fn tool_error(message: impl Into<String>) -> McpError {
    McpError::internal_error(message.into(), None)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[tokio::test]
    async fn long_bash_detaches_then_attaches_same_pid() {
        let workspace = std::env::temp_dir().join(format!("pc-bash-test-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&workspace)
            .await
            .expect("create test workspace");

        let state = Arc::new(AppState {
            db: sqlx::SqlitePool::connect_lazy("sqlite::memory:").expect("lazy sqlite"),
            public_url: None,
            oauth_password: None,
            workspace: workspace.clone(),
            allowed_redirect_hosts: Vec::new(),
            production: false,
            processes: ProcessRegistry::default(),
        });
        let mcp = PcMcp::new(state.clone());

        let started = Instant::now();
        mcp.start_command("sleep 12; printf done".into())
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
        assert_eq!(log, "done");

        let _ = tokio::fs::remove_dir_all(workspace).await;
    }
}
