#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
command -v go >/dev/null || { echo 'Go is required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'Python3.11+ is required' >&2; exit 1; }
command -v git >/dev/null || { echo 'Git is required' >&2; exit 1; }
python3 - <<'PY'
import subprocess,sys
if sys.version_info < (3,11): raise SystemExit('Python3.11+ is required')
print(subprocess.check_output(['go','version'],text=True).strip())
PY
mkdir -p bin .state
chmod 700 .state
go mod verify
