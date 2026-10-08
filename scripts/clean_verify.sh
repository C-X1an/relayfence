#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
git diff --quiet HEAD -- cmd internal scripts Makefile go.mod infra .github public-files.json || { echo 'Commit source before clean reproduction'; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
git clone --no-hardlinks --no-local "$ROOT" "$tmp/repo"
mkdir -p "$tmp/home" "$tmp/cache" "$tmp/modcache"
export HOME="$tmp/home" GOCACHE="$tmp/cache" GOMODCACHE="$tmp/modcache" GOTOOLCHAIN=local GOPROXY=off
cd "$tmp/repo"
printf 'Fresh checkout: '; git rev-parse HEAD
printf '%s\n' 'Same host/toolchain, fresh checkout, HOME and Go caches.'
make verify demo
cd "$ROOT"
id=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "verification/clean/$id"
cp -R "$tmp/repo/verification/runs" "verification/clean/$id/"
cp -R "$tmp/repo/verification/raw" "verification/clean/$id/"
