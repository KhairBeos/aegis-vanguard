# AEGIS-VANGUARD Project Rules

This repository is an isolated defensive SIEM/SOC learning lab.

## Safety and approvals

- Do not run Atomic Red Team or any attack simulation without explicit user approval for the exact run.
- Never switch the victim VM to bridged or public networking for a scenario.
- Never expose Elasticsearch, Kibana, an API, or a dashboard publicly.
- During documentation-only tasks, do not change VM, Docker, service, firewall, certificate, or network state.
- Stop before any destructive action, dependency installation, runtime modification, attack execution, `git commit`, or `git push`.

## Claims and evidence

- Never upgrade a capability status without linked evidence that satisfies `README.md` and `PROJECT_PLAN.md`.
- Manual behavior validation may reach `Runtime verified`; it must never receive `Live verified`.
- `Live verified` requires one approved Atomic-backed rule-scenario run with a complete evidence bundle.

## Sources of truth

- `README.md` and `PROJECT_PLAN.md` define project scope, roadmap, and claim status.
- Existing code and configuration define actual implementation state.
- Official primary documentation defines external technical behavior.
- `CONTEXT.md` is non-authoritative working memory and must not override the sources above.
- If a listed skill or MCP is unavailable, report that fact and use an equivalent safe workflow; never claim unavailable tool usage.
