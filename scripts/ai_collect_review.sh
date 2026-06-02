#!/usr/bin/env bash
set -euo pipefail

if [ -f docs/AI_REVIEW.md ]; then
  printf '%s\n' '===== docs/AI_REVIEW.md ====='
  cat docs/AI_REVIEW.md
fi

if [ -f docs/AI_RESULT.md ]; then
  printf '%s\n' '===== docs/AI_RESULT.md ====='
  cat docs/AI_RESULT.md
fi

printf '%s\n' '===== git status --short ====='
git status --short

printf '%s\n' '===== git diff --stat ====='
git diff --stat
