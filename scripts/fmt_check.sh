#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
files=$(gofmt -l cmd internal)
if [ -n "$files" ]; then printf '%s\n' "$files"; exit 1; fi
printf '%s\n' 'PASS: Go formatting'
