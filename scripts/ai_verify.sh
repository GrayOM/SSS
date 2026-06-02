#!/usr/bin/env bash
set -euo pipefail

python -m compileall app tests
python -m pytest tests/ -q -p no:cacheprovider
git status --short
