---
description: Drive a Halos rollout end to end, stopping only at the human gates
argument-hint: <what to roll out, e.g. "claude-code 2.1.300 to ring1">
---

Use the `halos-autopilot` skill for: $ARGUMENTS

Start with the `status` tool. Follow every tool's `next_steps`. Stop at GATE 1 (start) and GATE 2 (promote), and whenever a verdict is `expired` or an eval gate is `hold`/`block`. Do not publish, retag, merge or push to main; print the human's command and stop.
