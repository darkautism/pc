#!/bin/sh
set -eu

PC_HOME="${PC_HOME:-/app/data}"
PC_WORKSPACE="${PC_WORKSPACE:-/workspace}"
PC_SECURITY_MODE="${PC_SECURITY_MODE:-full}"
PC_SECURITY_NETWORK="${PC_SECURITY_NETWORK:-true}"
PC_SECURITY_PROTECT_SECRETS="${PC_SECURITY_PROTECT_SECRETS:-true}"

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

  printf 'security:\n'
  printf '  mode: %s\n' "$PC_SECURITY_MODE"
  printf '  network: %s\n' "$PC_SECURITY_NETWORK"
  printf '  protect_secrets: %s\n' "$PC_SECURITY_PROTECT_SECRETS"
} > "$tmp"

mv "$tmp" "$config"
exec pc "$@"

