---
name: sss-dev-loop
description: Run the SSS development loop using architecture review, implementation, PoC review, and tests.
---

Run the SSS development loop.

Phase 1 - Inspect:
- Read CLAUDE.md.
- Check git status.
- Identify the current implementation area.
- Use sss-architect if the task touches core pipeline logic.

Phase 2 - Plan:
- Produce a short implementation plan.
- Name exact files/functions to modify.
- Define tests to add or update.

Phase 3 - Implement:
- Make minimal changes.
- Keep common_console_helper separate from finding-specific PoCs.
- Preserve review candidate vs confirmed finding separation.

Phase 4 - Validate:
- Use sss-test-runner for targeted tests.
- Use sss-browser-verifier if PoC logic changed.
- Fix failures.

Phase 5 - Output:
- changed files
- what changed
- tests run
- remaining risks
- next recommended task
