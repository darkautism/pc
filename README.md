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

bash is non-interactive. Pipes and redirection are supported; PTY/curses programs such as `vim`, `less`, `top`, and interactive REPLs are not.

## Native / manual install

A normal installation does **not** use `/app/data`. On startup pc reads:

```text
~/.config/pc/config.yaml
```

If `XDG_CONFIG_HOME` is set, the path is `$XDG_CONFIG_HOME/pc/config.yaml`. `PC_HOME` can explicitly override the config directory.

The user-facing config has five settings:

```yaml
workspace: /path/to/project
oauth_password: "replace-with-a-long-password"
security:
  mode: safe
  network: true
  protect_secrets: true
```

After writing that file, starting `pc` is enough. The SQLite database and sandbox state are stored beside it under the pc config directory, so the launch working directory does not own application state.

The five equivalent environment overrides are:

| config | environment |
| --- | --- |
| `workspace` | `PC_WORKSPACE` |
| `oauth_password` | `PC_OAUTH_PASSWORD` |
| `security.mode` | `PC_SECURITY_MODE` |
| `security.network` | `PC_SECURITY_NETWORK` |
| `security.protect_secrets` | `PC_SECURITY_PROTECT_SECRETS` |

Environment values override the corresponding config values for that process.

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

For public deployment, `PC_PRODUCTION=true`, `PC_PUBLIC_URL=https://...`, and `PC_ALLOWED_REDIRECT_HOSTS` remain deployment settings. They are not part of the five user-facing coding/security settings.

## Docker

Only the container image uses `/app/data`. The image sets `PC_HOME=/app/data`; its entrypoint writes `/app/data/config.yaml` from the same five settings before starting pc.

Docker defaults:

```text
PC_WORKSPACE=/workspace
PC_SECURITY_MODE=full
PC_SECURITY_NETWORK=true
PC_SECURITY_PROTECT_SECRETS=true
```

Set the OAuth password explicitly:

```bash
docker run --rm -p 8787:8787 \
  -v "$PWD:/workspace" \
  -v pc-data:/app/data \
  -e PC_OAUTH_PASSWORD='a-long-password' \
  ghcr.io/darkautism/pc:latest
```

All five container settings can be supplied as environment variables:

```bash
docker run --rm -p 8787:8787 \
  -v "$PWD:/workspace" \
  -v pc-data:/app/data \
  -e PC_WORKSPACE=/workspace \
  -e PC_OAUTH_PASSWORD='a-long-password' \
  -e PC_SECURITY_MODE=full \
  -e PC_SECURITY_NETWORK=true \
  -e PC_SECURITY_PROTECT_SECRETS=true \
  ghcr.io/darkautism/pc:latest
```

The entrypoint validates these values and atomically rewrites `/app/data/config.yaml` before launching pc. The OAuth SQLite database is then derived from `PC_HOME` and stored at `/app/data/pc.db`.

GitHub Actions builds `linux/amd64` and `linux/arm64` on native runners in parallel. Pull requests build both architectures without pushing. Pushes to `main` publish architecture-specific SHA images first, then create `ghcr.io/darkautism/pc:latest` and `ghcr.io/darkautism/pc:sha-<commit>` multi-architecture manifests.
