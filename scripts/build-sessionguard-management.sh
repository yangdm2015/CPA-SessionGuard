#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="$(mktemp -d "${TMPDIR:-/tmp}/sessionguard-management.XXXXXX")"
git clone https://github.com/router-for-me/Cli-Proxy-API-Management-Center.git "$build_dir/source"
git -C "$build_dir/source" checkout 714de0760a3ce86094b178fb46f834d34bc4a2a5
git -C "$build_dir/source" apply "$root/scripts/sessionguard-management.patch"
cd "$build_dir/source"
bun install --frozen-lockfile
VERSION=v1.26.7-sessionguard bun run build
printf 'Management artifact: %s/dist/index.html\n' "$build_dir/source"
