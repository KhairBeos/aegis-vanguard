# AGENTS.md — Project AI Agent Rules

> Purpose: This file tells AI coding agents (Codex, Antigravity, Claude-like agents, Aider, etc.) how to work in this repository.
>
> Style: plan-first, skill-aware, safe-by-default, minimal changes.
>
> Core rule: **Do not modify code before understanding the project, choosing the right skill/workflow, and presenting a plan for approval.**

---

## 0. Required Behavior

Before doing any non-trivial task, the agent must:

1. Read this `AGENTS.md`.
2. Identify the task type.
3. Select the most appropriate skill/tool workflow.
4. Read the relevant files.
5. Summarize the current flow.
6. Propose a minimal plan.
7. Wait for explicit approval before editing code.

For simple questions or explanations, the agent may answer directly after reading the relevant context.

---

## 1. Golden Rules

- Always make a plan before code changes.
- Do not edit code until the user approves the plan.
- Keep changes minimal and inside the requested scope.
- Do not refactor unrelated code.
- Do not change API contracts unless explicitly requested.
- Do not rename fields, response shapes, routes, or database columns without approval.
- Do not add new libraries without approval.
- Do not run destructive commands without approval.
- Do not delete files, drop databases, reset branches, force push, or run migrations without explicit approval.
- For audit/review/security tasks: **report only** unless the user explicitly asks to implement fixes.
- When uncertain, ask a concise clarifying question.

---

## 2. Skill Selection Router

Use the following routing table before starting work.

| Task Type | Preferred Skills / Tools | Behavior |
|---|---|---|
| Open/understand project | `codebase-memory-mcp`, `Engram`, `project-structure` | Index/recall context, summarize architecture |
| Feature planning | `Spec Kit`, `writing-plans`, `gstack-autoplan`, `agency architect` | Write spec/plan/tasks first |
| Bug fixing | `systematic-debugging`, `codebase-memory-mcp`, `Engram` | Identify root cause before fix |
| Backend Node.js/API | `agency backend architect`, `server-api`, `architecture-guardrails` | Read route/controller/service/model first |
| Frontend React/UI | `agency frontend architect`, `taste-skill`, `gpt-tasteskill`, `ui-elements` | Review UI/data flow and propose plan |
| Security audit | `agency security reviewer`, `api-security`, `llm-security`, `supply-chain-security` | Report only by default |
| SQL injection audit | `agency security reviewer`, `api-security`, `systematic-debugging` | Find risky query patterns and safe fixes |
| Reverse engineering / pentest | `reverse-skill`, `apk-reverse`, `js-reverse`, `ida-reverse`, `radare2`, `pentest-tools` | Only authorized tasks; plan first |
| PR/code review | `gstack-review`, `caveman-review`, `ponytail-review`, `pr-review-deep` | Report findings; do not edit |
| QA/testing | `gstack-qa`, `testing-coverage`, `test-driven-development`, `agency QA` | Create test plan or TDD workflow |
| Docs | `docs-generator`, `docs-alignment`, `gstack-document-generate` | Generate/update docs after reading code |
| Diagrams | `diagram-generator`, `gstack-diagram` | Create Mermaid/PlantUML/flow diagrams |
| Git/branch/commit | `commit-hygiene`, `branch-pr`, `wednesday-git`, `caveman-commit` | Propose branch/commit/PR messages |
| Reduce complexity | `ponytail-audit`, `ponytail-review`, `caveman-compress` | Identify code to simplify/remove |
| UI redesign | `taste-skill`, `redesign-skill`, `minimalist-skill`, `soft-skill`, `brutalist-skill` | Propose visual direction before code |

If multiple skills apply, choose the smallest effective combination.

---

## 3. Always Start With Context

For any project task, start with:

```text
Use codebase-memory-mcp to understand this project.
Use Engram to recall project memories.
Then read the relevant files for the task.
```

If `codebase-memory-mcp` is unavailable, manually inspect files using normal project search/read tools.

If `Engram` is unavailable, continue without memory but mention that project memory could not be recalled.

---

## 4. Standard Workflows

### 4.1. New Project / First Inspection

Use:

- `codebase-memory-mcp`
- `Engram`
- `project-structure`
- `architecture-guardrails`

Expected output:

1. Project purpose.
2. Entry points.
3. Main modules.
4. Data flow.
5. External integrations.
6. Risky areas.
7. Suggested next steps.

Prompt behavior:

```text
Index and inspect the project.
Summarize architecture and risks.
Do not modify code.
```

---

### 4.2. Feature Development

Use:

- `Spec Kit`
- `writing-plans`
- `gstack-autoplan`
- `agency backend/frontend architect`
- `codebase-memory-mcp`

Process:

1. Clarify requirement.
2. Inspect similar existing flows.
3. Write spec.
4. Create implementation plan.
5. Break into small tasks.
6. Ask for approval.
7. Implement one task at a time.
8. Summarize changed files and testing steps.

Never implement a large feature in one uncontrolled pass.

---

### 4.3. Bug Fixing

Use:

- `systematic-debugging`
- `codebase-memory-mcp`
- `Engram`

Process:

1. Reproduce or reason from logs/error.
2. Locate related files.
3. Explain current flow.
4. Identify root cause.
5. Propose minimal fix.
6. Wait for approval.
7. Implement fix.
8. Verify.

Do not guess. Do not patch symptoms without explaining the cause.

---

### 4.4. Backend API Changes

Use:

- `agency backend architect`
- `server-api`
- `architecture-guardrails`
- `business-rules`

Before editing backend code, read:

- Route definition.
- Controller.
- Service.
- Model/schema/query layer.
- Middleware/auth/permission layer.
- Similar existing APIs.

Rules:

- Preserve existing response format.
- Preserve field names unless approved.
- Validate user input.
- Avoid raw SQL string concatenation.
- Use parameter binding/replacements for SQL.
- Keep transaction behavior consistent.
- Do not add libraries without approval.

---

### 4.5. Frontend React/UI Changes

Use:

- `agency frontend architect`
- `taste-skill`
- `gpt-tasteskill`
- `ui-elements`
- `visual-language`

Before editing frontend code, read:

- Route/page component.
- Child components.
- Hooks.
- API client.
- Store/state management.
- Similar existing screens.
- Styling conventions.

Rules:

- Follow current project structure.
- Reuse existing API clients/hooks.
- Avoid generic UI.
- Preserve behavior unless asked.
- Do not add UI libraries without approval.
- Do not introduce global state unless needed.

For design tasks, propose the visual direction first.

---

### 4.6. Security Review

Use:

- `agency security reviewer`
- `api-security`
- `llm-security`
- `supply-chain-security`
- `gstack-review`

Default mode: **report only**.

Check:

- SQL injection.
- Auth bypass.
- IDOR/BOLA.
- Unsafe file upload.
- Exposed secrets.
- Weak validation.
- SSRF.
- XSS.
- Unsafe deserialization.
- Dependency/supply-chain risk.
- Over-permissive CORS.
- Dangerous logging.

For each issue, report:

1. Severity.
2. File path.
3. Risky code/pattern.
4. Impact.
5. Suggested safe fix.
6. Whether immediate action is needed.

Do not exploit, exfiltrate, or run destructive tests.

---

### 4.7. SQL Injection Review

Use:

- `agency security reviewer`
- `api-security`
- `systematic-debugging`

Search for:

- Raw SQL query strings.
- Sequelize `query`, `literal`, dynamic `where`, dynamic `order`, dynamic `group`.
- String concatenation/interpolation inside SQL.
- User input passed into SQL.
- Unvalidated sort/filter/search parameters.

Safe patterns:

- Parameterized queries.
- Replacements/bind variables.
- Whitelisted sort fields.
- Validated enum filters.
- Escaped LIKE input where applicable.

Report only unless user approves fixes.

---

### 4.8. PR / Code Review

Use:

- `gstack-review`
- `pr-review-deep`
- `caveman-review`
- `ponytail-review`

Review for:

- Correctness.
- Scope creep.
- Regression risks.
- Security.
- Performance.
- Maintainability.
- Tests.
- API contract changes.
- Unnecessary complexity.

Final review comments should be concise:

```text
[file:line] problem → suggested fix
```

Do not modify code unless asked.

---

### 4.9. QA / Testing

Use:

- `gstack-qa`
- `testing-coverage`
- `test-driven-development`
- `agency QA`

For each feature, cover:

- Normal path.
- Edge cases.
- Permission cases.
- Invalid input.
- Empty state.
- Error state.
- Regression risk.
- Database state.
- API failure.
- UI loading state.

If using TDD:

1. Write failing test.
2. Implement minimal fix.
3. Refactor only if needed.
4. Verify tests pass.

Ask before adding new test frameworks.

---

### 4.10. Docs / Diagrams

Use:

- `docs-generator`
- `docs-alignment`
- `diagram-generator`
- `gstack-diagram`

For docs:

1. Read code first.
2. Compare docs to current implementation.
3. List outdated/missing docs.
4. Propose updates.
5. Generate Markdown after approval.

For diagrams:

- Prefer Mermaid unless user asks otherwise.
- Use sequence diagrams for API flows.
- Use flowcharts for business processes.
- Use ER diagrams for data models.

---

### 4.11. Reverse Engineering / Pentest

Use only for authorized work.

Use:

- `reverse-skill`
- `api-security`
- `apk-reverse`
- `js-reverse`
- `ida-reverse`
- `radare2`
- `mobile-reverse`
- `firmware-pentest`
- `malware-analysis`
- `pentest-tools`

Rules:

- Confirm task is authorized.
- Route to correct skill first.
- Make a plan before commands.
- Do not run destructive payloads.
- Do not target third-party systems without permission.
- Keep evidence and report clearly.
- Prefer safe static analysis before dynamic execution.

---

## 5. Memory Rules

Use `Engram` for durable project knowledge.

Save memory when discovering:

- Project architecture.
- Important conventions.
- Business rules.
- API response contracts.
- Database/migration risks.
- Integration details.
- Repeated bugs.
- User preferences.
- Decisions made during review.

Do not save:

- Secrets.
- Passwords.
- API keys.
- Access tokens.
- Private customer data.
- Temporary one-off facts.

Memory prompts:

```text
Use Engram to save this project rule:
[rule]
```

```text
Use Engram to recall project memories before working.
Summarize relevant rules and decisions.
```

---

## 6. Spec Kit Rules

Use Spec Kit for:

- Large feature.
- Complex business flow.
- Multi-screen or multi-API work.
- Any task that needs traceable requirements.

Spec Kit workflow:

1. `/specify` or equivalent spec creation.
2. Clarify requirements.
3. Write acceptance criteria.
4. Create technical plan.
5. Split tasks.
6. Implement task-by-task.

Do not skip directly to implementation for large features.

---

## 7. UI Taste Rules

For frontend/UI work, use `taste-skill` or related skills.

Avoid:

- Generic dashboard look.
- Random colors.
- Too many borders.
- Dense unstructured layout.
- Weak typography hierarchy.
- Placeholder copy.
- Unclear loading/empty/error states.

Prefer:

- Strong hierarchy.
- Clear spacing.
- Consistent component rhythm.
- Useful data density.
- Clean interaction states.
- Accessible contrast.
- Existing design language.

When redesigning:

1. Describe current UI issues.
2. Propose visual direction.
3. Propose component changes.
4. Wait for approval before coding.

---

## 8. Minimalism / Complexity Rules

Use `ponytail` and `caveman` when the task risks over-engineering.

Rules:

- Prefer deleting code over adding code when possible.
- Avoid abstractions until repeated pattern is proven.
- Keep functions small but not fragmented.
- Do not add new layers without clear benefit.
- Keep review comments short and actionable.

Use `caveman-review` for terse review output.
Use `ponytail-audit` for complexity/debt audit.

---

## 9. Git Rules

Use:

- `commit-hygiene`
- `branch-pr`
- `wednesday-git`
- `caveman-commit`

Before commit/PR:

1. Summarize changed files.
2. Check accidental secrets.
3. Check generated files.
4. Check test impact.
5. Propose commit message.
6. Propose PR title/summary.

Never run:

- `git reset --hard`
- `git clean -fd`
- `git push --force`
- destructive rebase

unless explicitly approved.

---

## 10. Commands Safety

Before running commands, explain why if they are:

- Database migrations.
- Data deletion.
- Docker cleanup.
- Production-affecting.
- Deployment.
- Package upgrades.
- Large formatting changes.
- Git destructive commands.

Safe commands usually allowed after context:

- Read/list files.
- Search code.
- Run tests.
- Run linters.
- Run type checks.
- Build locally.

Still summarize what command will do.

---

## 11. Output Format

For planning tasks, output:

```md
## Current understanding
...

## Files to inspect / inspected
...

## Current flow
...

## Risks
...

## Plan
1. ...
2. ...

## Need approval
Please approve before I edit files.
```

For implementation summary, output:

```md
## Changed files
- `path`: what changed

## Why
...

## Risks
...

## How to test
1. ...
2. ...
```

For review/audit, output:

```md
## Summary
...

## Findings
### Critical
- ...

### High
- ...

### Medium
- ...

### Low
- ...

## Suggested next steps
...
```

---

## 12. Default Prompt To Follow

If the user gives a vague coding task, behave as if they said:

```text
Use codebase-memory-mcp to index/understand this project.
Use Engram to recall project memories.
Choose the right skill for this task.
Read related files first.
Summarize the current flow.
Propose a minimal plan.
Do not modify code until I approve.
```

---

## 13. Project-Specific Conventions

Add project-specific rules below this line.

<!--
Example:

## Project: realerp-server

- Backend Node.js.
- Preserve successResponse/errorResponse format.
- Read controller/service/model before changes.
- Do not change API response field names.
- Do not add libraries without approval.
- Review/audit mode is report-only.
-->

