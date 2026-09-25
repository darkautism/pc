# pc

A deliberately small remote coding MCP server.

## Tools

Exactly four tools are exposed:

- `read { path, offset?, limit? }`
- `write { path, content }`
- `edit { path, edits: [{ oldText, newText }] }`
- `bash { command }` or `bash { pid }`

The first three follow Pi's coding-tool shape. `bash` intentionally does not.

## The 10-second bash rule

`bash({ command })` waits synchronously for at most 10 seconds.

If the command is still running after 10 seconds, pc does **not** kill it. It returns the OS PID, bounded current output, `full_output_path`, and asks the caller to continue independent work before attaching later.

`bash({ pid })` attaches to that same process and also waits for at most 10 seconds. stdout and stderr are combined into a log file from process start. Tool-visible output is limited to the last 2000 lines or 50 KiB; the complete log remains readable with `read` or normal shell tools.

`bash` is a non-interactive shell tool: it uses Bash on Unix and `cmd.exe` on Windows. Pipes and redirection follow the native shell; PTY/curses programs and interactive REPLs are not supported.

Task logs are cleaned every 60 seconds. Logs older than `task_log_retention_secs` are removed; the default is `7200` (2 hours). Running-command logs are protected, and the existing 256 MiB task-log directory quota is still enforced.

## Native / manual install

A normal installation stores its config here:

```text
~/.config/pc/config.yaml
```

To use another config directory, set `PC_HOME`, for example `PC_HOME=/srv/pc pc`.

If the file does not exist, pc creates it automatically and generates `oauth_password` internally; no external OpenSSL installation is required.

A complete config can contain both coding/security settings and public OAuth deployment settings:

```yaml
workspace: /path/to/project
oauth_password: "replace-with-a-long-password"
public_url: "https://pc.example.com"
production: true
allowed_redirect_hosts:
  - "client.example.com"
task_log_retention_secs: 7200
security:
  mode: safe
  network: true
  protect_secrets: true
```

After writing that file, starting `pc` is enough. On Windows, native paths such as `workspace: E:\project` are accepted directly; the common `workspace: "E:\project"` form is also tolerated. The SQLite database and sandbox state are stored beside the config using native filesystem paths, so Windows drive letters are never forced through a SQLite URL.

`allowed_redirect_hosts` is watched and hot-reloaded when `config.yaml` changes, so redirect allowlist edits do not require restarting pc. Entries are host-only exact names or `*.example.com` wildcards for HTTPS redirects; exact IP literals are also valid. Standard loopback HTTP callbacks such as `http://127.0.0.1:<port>/...` are accepted automatically for native/desktop OAuth clients and do not need to be added to this list. If `PC_ALLOWED_REDIRECT_HOSTS` or `--allowed-redirect-hosts` is set, that explicit override remains authoritative and hot reload is disabled for this field.

Environment variables can override the corresponding config values for that process:

| config | environment |
| --- | --- |
| `workspace` | `PC_WORKSPACE` |
| `oauth_password` | `PC_OAUTH_PASSWORD` |
| `public_url` | `PC_PUBLIC_URL` |
| `production` | `PC_PRODUCTION` |
| `allowed_redirect_hosts` | `PC_ALLOWED_REDIRECT_HOSTS` (comma-separated) |
| `task_log_retention_secs` | `PC_TASK_LOG_RETENTION_SECS` |
| `security.mode` | `PC_SECURITY_MODE` |
| `security.network` | `PC_SECURITY_NETWORK` |
| `security.protect_secrets` | `PC_SECURITY_PROTECT_SECRETS` |

## Native user service

pc can install itself as a per-user background service. This does not require sudo and keeps credentials out of the generated service definition; the service persists only `PC_HOME`, `PATH`, and development-tool path selectors such as `RUSTUP_HOME`, `CARGO_HOME`, or `DEVELOPER_DIR`.

Linux quick start:

```bash
cargo install --git https://github.com/darkautism/pc.git --locked
pc service install
pc service status
```

Linux uses `~/.config/systemd/user/pc.service` (or `$XDG_CONFIG_HOME/systemd/user/pc.service`) and `systemctl --user`. `install` is idempotent: it rewrites the unit, runs `daemon-reload`, then `enable --now`.

macOS quick start:

```bash
cargo install --git https://github.com/darkautism/pc.git --locked
pc service install
pc service status
```

macOS uses `~/Library/LaunchAgents/io.github.darkautism.pc.plist` with modern `launchctl bootstrap/bootout/kickstart`. The current `safe` sandbox is Linux-only and fails closed on macOS; use `full` or `readonly` there.

Available commands are `install`, `start`, `stop`, `restart`, `status`, and `uninstall`. To use a non-default config directory, pass `--home` before the subcommand, for example `pc --home /srv/pc service install`.

## Security modes

`full` keeps Pi-like host access: relative paths start at `workspace`, absolute paths are allowed subject to OS permissions.

`safe` uses the embedded rootless mini-sandbox derived from LazyTeam: Landlock when fully supported, otherwise a rootless user/mount namespace allowlist, plus no-new-privileges, dropped capabilities, and a seccomp denylist. It has no Docker/Podman runtime dependency.

`readonly` allows reads while rejecting write, edit, and bash.

`protect_secrets` hides common host credential locations in `safe` and `readonly`; `full` deliberately means full host access.

## OAuth

The OAuth implementation includes:

- protected-resource and authorization-server metadata
- dynamic client registration
- Authorization Code + PKCE S256
- access and refresh tokens
- bearer authentication on MCP endpoints
- reverse-proxy/public URL handling
- redirect-host allowlisting in production

For public deployment, set `production: true`, `public_url`, and `allowed_redirect_hosts` in `config.yaml`. The equivalent `PC_*` environment variables remain available as overrides.

## Docker

Only the container image uses `/app/data`. The image sets `PC_HOME=/app/data`; its entrypoint writes `/app/data/config.yaml` before starting pc.

Docker defaults:

```text
PC_WORKSPACE=/workspace
PC_SECURITY_MODE=full
PC_SECURITY_NETWORK=true
PC_SECURITY_PROTECT_SECRETS=true
PC_TASK_LOG_RETENTION_SECS=7200
PC_PRODUCTION=false
```

Set the OAuth password explicitly:

```bash
docker run --rm -p 8686:8686 \
  -v "$PWD:/workspace" \
  -v pc-data:/app/data \
  -e PC_OAUTH_PASSWORD='a-long-password' \
  ghcr.io/darkautism/pc:latest
```

Container settings can also be supplied as environment variables:

```bash
docker run --rm -p 8686:8686 \
  -v "$PWD:/workspace" \
  -v pc-data:/app/data \
  -e PC_WORKSPACE=/workspace \
  -e PC_OAUTH_PASSWORD='a-long-password' \
  -e PC_SECURITY_MODE=full \
  -e PC_SECURITY_NETWORK=true \
  -e PC_SECURITY_PROTECT_SECRETS=true \
  -e PC_TASK_LOG_RETENTION_SECS=7200 \
  -e PC_PUBLIC_URL='https://pc.example.com' \
  -e PC_PRODUCTION=true \
  -e PC_ALLOWED_REDIRECT_HOSTS='client.example.com' \
  ghcr.io/darkautism/pc:latest
```

The entrypoint validates these values and atomically rewrites `/app/data/config.yaml` before launching pc. The OAuth SQLite database is derived from `PC_HOME` and stored at `/app/data/oauth.db`.

