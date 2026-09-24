#!/bin/sh
set -eu

PC_HOME="${PC_HOME:-/app/data}"
PC_WORKSPACE="${PC_WORKSPACE:-/workspace}"
PC_SECURITY_MODE="${PC_SECURITY_MODE:-full}"
PC_SECURITY_NETWORK="${PC_SECURITY_NETWORK:-true}"
PC_SECURITY_PROTECT_SECRETS="${PC_SECURITY_PROTECT_SECRETS:-true}"
PC_TASK_LOG_RETENTION_SECS="${PC_TASK_LOG_RETENTION_SECS:-7200}"
PC_PRODUCTION="${PC_PRODUCTION:-false}"
PC_PUBLIC_URL="${PC_PUBLIC_URL:-}"
PC_ALLOWED_REDIRECT_HOSTS="${PC_ALLOWED_REDIRECT_HOSTS:-}"

case "$PC_SECURITY_MODE" in
  full|safe|readonly) ;;
  *) echo "invalid PC_SECURITY_MODE: $PC_SECURITY_MODE" >&2; exit 2 ;;
esac

case "$PC_SECURITY_NETWORK" in
  true|false) ;;
  *) echo "PC_SECURITY_NETWORK must be true or false" >&2; exit 2 ;;
esac

case "$PC_SECURITY_PROTECT_SECRETS" in
  true|false) ;;
  *) echo "PC_SECURITY_PROTECT_SECRETS must be true or false" >&2; exit 2 ;;
esac

case "$PC_TASK_LOG_RETENTION_SECS" in
  ''|*[!0-9]*) echo "PC_TASK_LOG_RETENTION_SECS must be a non-negative integer" >&2; exit 2 ;;
  *) ;;
esac

case "$PC_PRODUCTION" in
  true|false) ;;
  *) echo "PC_PRODUCTION must be true or false" >&2; exit 2 ;;
esac

yaml_string() {
  case "$1" in
    *'
'*) echo "pc config environment values must not contain newlines" >&2; exit 2 ;;
  esac
  escaped="$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  printf '"%s"' "$escaped"
}

mkdir -p "$PC_HOME"
umask 077
config="$PC_HOME/config.yaml"
tmp="$config.tmp.$$"

{
  printf 'workspace: '
  yaml_string "$PC_WORKSPACE"
  printf '\n'

  if [ "${PC_OAUTH_PASSWORD+x}" = x ]; then
    printf 'oauth_password: '
    yaml_string "$PC_OAUTH_PASSWORD"
    printf '\n'
  else
    printf 'oauth_password: null\n'
  fi

  if [ -n "$PC_PUBLIC_URL" ]; then
    printf 'public_url: '
    yaml_string "$PC_PUBLIC_URL"
    printf '\n'
  else
    printf 'public_url: null\n'
  fi

  printf 'production: %s\n' "$PC_PRODUCTION"
  printf 'task_log_retention_secs: %s\n' "$PC_TASK_LOG_RETENTION_SECS"

  if [ -n "$PC_ALLOWED_REDIRECT_HOSTS" ]; then
    printf 'allowed_redirect_hosts:\n'
    old_ifs="$IFS"
    IFS=','
    for host in $PC_ALLOWED_REDIRECT_HOSTS; do
      host="$(printf '%s' "$host" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      [ -z "$host" ] && continue
      printf '  - '
      yaml_string "$host"
      printf '\n'
    done
    IFS="$old_ifs"
  else
    printf 'allowed_redirect_hosts: []\n'
  fi

  printf 'security:\n'
  printf '  mode: %s\n' "$PC_SECURITY_MODE"
  printf '  network: %s\n' "$PC_SECURITY_NETWORK"
  printf '  protect_secrets: %s\n' "$PC_SECURITY_PROTECT_SECRETS"
} > "$tmp"

mv "$tmp" "$config"
exec pc "$@"

