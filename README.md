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

If the command is still running after 10 seconds, pc does **not** kill it. It returns:

- `status: "running"`
- the OS `pid`
- bounded current output
- `full_output_path`
- an instruction to continue independent work and attach the PID later

`bash({ pid })` attaches to that same process and also waits for at most 10 seconds. It never creates a replacement task.

stdout and stderr are combined into a server-side log file from process start, so a noisy child cannot block on a full pipe. Tool-visible output is limited to the last 2000 lines or 50 KiB, matching Pi's bash output budget. The complete log remains readable with normal shell tools such as `tail`, `grep`, or `sed`, or with `read`.

bash is non-interactive. Pipes and redirection are supported; PTY/curses programs such as `vim`, `less`, `top`, and interactive REPLs are not.

## OAuth

The OAuth implementation is ported from LazyTeam and includes:

- protected-resource and authorization-server metadata
- dynamic client registration
- Authorization Code + PKCE S256
- access and refresh tokens
- bearer authentication on MCP endpoints
- reverse-proxy/public URL handling
- redirect-host allowlisting in production

## Run

```bash
PC_WORKSPACE=/path/to/workspace \
PC_OAUTH_PASSWORD='a-long-password' \
cargo run
```

For public deployment, set `PC_PRODUCTION=true`, `PC_PUBLIC_URL=https://...`, and `PC_ALLOWED_REDIRECT_HOSTS`.

## Docker

The image uses `/workspace` as the coding workspace and `/app/data` for the OAuth SQLite database.

```bash
docker run --rm -p 8787:8787 \
  -v "$PWD:/workspace" \
  -v pc-data:/app/data \
  -e PC_OAUTH_PASSWORD='a-long-password' \
  ghcr.io/darkautism/pc:latest
```

GitHub Actions builds `linux/amd64` and `linux/arm64` on native runners in parallel. Pull requests build both architectures without pushing. Pushes to `main` publish architecture-specific SHA images first, then create `ghcr.io/darkautism/pc:latest` and `ghcr.io/darkautism/pc:sha-<commit>` multi-architecture manifests.
