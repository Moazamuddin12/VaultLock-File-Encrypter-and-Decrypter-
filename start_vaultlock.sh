#!/usr/bin/env sh
# VaultLock launcher for macOS / Linux.  Run:  sh start_vaultlock.sh
set -e
cd "$(dirname "$0")"

PY=""
for c in python3.13 python3.12 python3.11 python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
if [ -z "$PY" ]; then
  echo "Python 3.11 or newer is required (https://www.python.org/downloads/)." >&2
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  rm -rf .venv
  echo "Creating the virtual environment with $PY ..."
  "$PY" -m venv .venv
fi

if ! .venv/bin/python -c 'import cryptography, flask, argon2' 2>/dev/null; then
  echo "Installing VaultLock (first run only) ..."
  .venv/bin/python -m pip install --disable-pip-version-check -e .
fi

echo "Starting VaultLock. Press Ctrl+C to quit."
exec .venv/bin/python -m vaultlock gui --browser
