# Standalone Elastic Agent Runtime Policy Workflow

This directory intentionally contains documentation only. Initial Phase 1 scaffolding does not invent or commit an Agent policy.

## Fixed boundary

- Agent version: `9.4.3`.
- Mode: standalone; no enrollment and no Fleet Server.
- Elasticsearch output: `https://192.168.15.1:9200` with the local CA and full certificate verification.
- Windows event-log streams: Application, Security, and System only.
- Metrics and all unrelated streams remain disabled.
- The Agent API key stays in the protected live configuration on `AEGIS-WIN-VICTIM-01`, outside this repository.

## Integration assets and policy generation

After all runtime resource gates pass, Elasticsearch and Kibana are available, and a package-install session is separately approved:

1. Use Kibana Integrations to install the exact compatible System integration package from Elastic Package Registry.
2. Record the installed System package version and installation timestamp before creating a policy.
3. Create an Agent policy in Kibana and add only the System integration inputs for Windows Application, Security, and System event logs.
4. Disable metrics and every unrelated stream.
5. Select **Run standalone** and download the generated policy. This workflow installs integration assets without deploying Fleet Server. See Elastic's [standalone policy workflow](https://www.elastic.co/docs/reference/fleet/create-standalone-agent-policy).
6. Stage the unsanitized download exactly at `deploy/elastic-agent/runtime/elastic-agent.yml`. Git ignores the entire runtime directory.
7. Supply the least-privilege Agent API key only in the protected guest-local runtime configuration.

Before every policy download and every later scenario session, use Kibana's installed-packages API to compare the installed System package version with the recorded value. Stop on drift. A package change requires a new policy download, diff, sanitization review, guest deployment, and ECS re-verification.

## Deferred sanitized example

`deploy/elastic-agent/elastic-agent.yml.example` must not be created until a real policy has been generated and reviewed. Before a later commit, remove or replace all:

- API keys, passwords, tokens, and authorization headers;
- CA fingerprints and generated certificate details;
- machine-specific paths;
- generated policy IDs and Agent IDs;
- namespaces and runtime identifiers that disclose local state.

The future example must identify the recorded System package version and generation timestamp, pass repository secret and ignore checks, and receive manual review. The runtime policy must never be copied into Git as-is.

## Package-registry boundary

Kibana may reach `epr.elastic.co:443` only during an explicitly approved package-install session. This is package-management traffic from the host-side Compose bridge, not victim traffic. The victim VM remains host-only without Internet access. Scenario sessions use already-installed assets and perform no repeat download.

If the registry is unavailable, stop and prepare a separately approved design using Elastic's official [air-gapped Fleet guidance](https://www.elastic.co/docs/reference/fleet/air-gapped). Do not use unofficial mirrors, copied package assets, or invented integration YAML.
