#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -x .venv/bin/python ]; then PY=.venv/bin/python; else PY=python3; fi
"$PY" -m unittest discover -s tests -v

# Optional: real-HTTP naive vs secure comparison (needs both servers running):
#   python app.py & python naive_lab.py &
#   python scripts/security_compare.py
