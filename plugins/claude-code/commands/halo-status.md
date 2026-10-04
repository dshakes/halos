---
description: Summarize rings, experiments and their health
allowed-tools: mcp__plugin_halos_halos__status, mcp__plugin_halos_halos__list_rings, mcp__plugin_halos_halos__list_experiments, mcp__plugin_halos_halos__analyze_experiment, mcp__plugin_halos_halos__validate
---

Read-only status report using the Halos MCP tools: call `status` (one call: policy health, rings, experiments, rollouts, kill switch when halo-server is configured), then `validate`, `list_rings` and `list_experiments` for detail; for each running experiment call `analyze_experiment` if available. Output a compact table (ring -> profile/release, experiment -> status/verdict) and list anything needing a human decision. Change nothing.
