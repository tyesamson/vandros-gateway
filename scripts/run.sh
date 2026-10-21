#!/usr/bin/env bash
# Pull ghcr.io/tyesamson/vandros-gateway:latest and run it read-only.
#
#   cp config.example.yaml config.yaml
#   # point each mount at a real directory
#   export VANDROS_SESSION_SECRET='at least 32 characters'
#   export VANDROS_ADMIN_USER=admin          # first start only
#   export VANDROS_ADMIN_PASSWORD='...'      # first start only
#   ./scripts/run.sh
#
# Mount paths come from config.yaml. Each one is mounted at the same path
# inside the container, read-only. uid 10001 must already be able to read them.
# Publish on one address with VANDROS_PUBLISH=192.168.20.112:8080:8080.

set -euo pipefail

image=ghcr.io/tyesamson/vandros-gateway:latest
config=${1:-${CONFIG:-config.yaml}}
publish=${VANDROS_PUBLISH:-8080:8080}

if [[ ! -f "$config" ]]; then
  echo "Missing $config. Copy config.example.yaml and point each mount at a real directory." >&2
  exit 1
fi

secret=${VANDROS_SESSION_SECRET:-}
if [[ ${#secret} -lt 32 ]]; then
  echo "Set VANDROS_SESSION_SECRET to at least 32 characters." >&2
  exit 1
fi

if [[ "$config" = /* ]]; then
  config_host=$config
else
  config_host=$PWD/$config
fi

mount_args=()
in_mounts=0
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ ^mounts: ]]; then
    in_mounts=1
    continue
  fi
  if [[ $in_mounts -eq 1 && "$line" =~ ^[^[:space:]#] ]]; then
    in_mounts=0
  fi
  if [[ $in_mounts -eq 1 && "$line" =~ ^[[:space:]]+path:[[:space:]]*(.*)$ ]]; then
    path=${BASH_REMATCH[1]}
    path=${path%#*}
    path=${path//\"/}
    path=${path//\'/}
    path=${path%"${path##*[![:space:]]}"}
    [[ -n "$path" ]] || continue
    if [[ "$path" != /* ]]; then
      echo "Mount path must be absolute: $path" >&2
      exit 1
    fi
    if [[ ! -d "$path" ]]; then
      echo "Mount path does not exist: $path" >&2
      exit 1
    fi
    mount_args+=(-v "${path}:${path}:ro")
  fi
done < "$config"

if [[ ${#mount_args[@]} -eq 0 ]]; then
  echo "No mounts in $config." >&2
  exit 1
fi

if docker container inspect vandros >/dev/null 2>&1; then
  echo "A container named vandros already exists. Remove it before starting another." >&2
  exit 1
fi

args=(
  run -d --name vandros
  --restart unless-stopped
  --read-only
  --tmpfs /tmp
  --stop-timeout 15
  --pull always
  -p "$publish"
  -e VANDROS_SESSION_SECRET
  --user 10001:10001
  -v "$config_host:/etc/vandros/config.yaml:ro"
  -v vandros-data:/var/lib/vandros
)
if [[ -n "${TZ:-}" ]]; then
  args+=(-e "TZ=$TZ")
fi
if [[ -n "${VANDROS_ADMIN_USER:-}" ]]; then
  args+=(-e VANDROS_ADMIN_USER)
fi
if [[ -n "${VANDROS_ADMIN_PASSWORD:-}" ]]; then
  args+=(-e VANDROS_ADMIN_PASSWORD)
else
  echo "VANDROS_ADMIN_PASSWORD is unset. That is fine when the volume already has a user." >&2
fi
args+=("${mount_args[@]}")
args+=("$image")

exec docker "${args[@]}"
