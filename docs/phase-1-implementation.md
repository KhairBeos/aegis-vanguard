# Phase 1 Secure Repository Scaffolding

- **Stack:** Elasticsearch `9.4.3`, Kibana `9.4.3`, and one documented standalone Elastic Agent `9.4.3`.
- **Repository scope:** secure configuration and workflow scaffolding only.
- **Runtime state:** not started; resource remediation and separate runtime approval remain required.

## Architecture

Compose defines exactly `elasticsearch` and `kibana` under the explicit `elastic` profile. Both use `restart: "no"`, separate named data volumes, and one project-private bridge that remains outbound-capable for a controlled Kibana package-install session.

Host publications are fixed:

- Elasticsearch HTTPS: `192.168.15.1:9200`.
- Kibana HTTP: `127.0.0.1:5601`.

Elasticsearch transport and Fleet Server ports are not published. Container-internal listeners do not change the narrow host publication.

## TLS and secrets

`deploy/tls/instances.yml` defines one local CA and one Elasticsearch HTTP certificate with DNS SAN `elasticsearch` and IP SAN `192.168.15.1`. The generation script uses the already-present pinned Elasticsearch image with networking disabled and refuses to overwrite generated material. It is not executed during scaffolding.

Each approved run uses the ignored `deploy/tls/.runtime-staging/<guid>/` boundary with separate `archives/` and `material/` trees. The run directory is ACL-restricted before certificate generation. Expected certificate and private-key files must exist and be non-empty, unexpected private-key or archive content is rejected, archives are deleted and their absence verified, and private-key ACL hardening and validation occur before the only promotion into ignored `deploy/tls/generated/`.

Promotion is transactional: post-promotion file and ACL checks repeat against the final paths; a promotion or post-promotion failure rolls back only the exact final directory. The exact run directory is removed in `finally`, cleanup failures are surfaced with path-only messages, and unexplained stale staging material is never silently removed.

Generated TLS material, the bootstrap-password source file, Kibana keystore, and unsanitized Agent policy are ignored. Elasticsearch receives its password through a file-backed Compose secret. Kibana reads `elasticsearch.serviceAccountToken` only from its ignored keystore. The Agent API key remains on the Windows guest.

Kibana and the standalone Agent must use the local CA with full hostname verification. Broad host publication and weakened certificate verification are not fallbacks.

## Elasticsearch readiness

Docker health invokes the committed helper through `/bin/sh`. The helper reads the mounted CA and password secret, supplies authentication to curl through stdin configuration, applies bounded client and API timeouts, and emits neither the password nor response body. It succeeds only for HTTP success with `timed_out=false` and cluster status `yellow` or `green`; every other result exits `1`.

The unauthenticated CA-verified HTTP `401` probe in `scripts/Wait-Phase1ElasticsearchReady.ps1` is listener-only. It never marks the service healthy or authorizes later bootstrap steps. Kibana depends on authenticated `service_healthy` Elasticsearch.

## Kibana readiness

Kibana health uses the committed, read-only-mounted `deploy/kibana/bin/kibana-healthcheck.js` helper. The built-in HTTP client requests `http://127.0.0.1:5601/api/status`, permits at most five seconds and 64 KiB, requires HTTP `200`, parses JSON, and succeeds only when `status.overall.level` equals `available`. It sends no authorization header and emits no response body, credential, or sensitive diagnostic.

Compose invokes `/usr/share/kibana/node/bin/node /usr/local/bin/kibana-healthcheck.js` with the approved health timing. The bundled Node path is runtime-pending verification and is not claimed as runtime-verified by static validation.

## Package-registry egress boundary

Kibana may use outbound HTTPS to `epr.elastic.co:443` only in the approved System-package installation session. This does not add a host publication or victim Internet path. The Windows victim remains on the VirtualBox host-only network.

Record the exact installed System version and timestamp below before policy generation. Compare it through Kibana's installed-packages API before every policy download and scenario session. Stop on drift; do not accept a silent upgrade.

| Installed System version | Installation timestamp | Evidence path | State |
| --- | --- | --- | --- |
| — | — | — | `Unverified` |

Scenario sessions use installed assets and do not download them again. If EPR is unavailable, stop and plan Elastic's official air-gapped route separately; unofficial mirrors, copied assets, and invented packages are forbidden.

## First-start sequence

This sequence is documented only and was not executed by scaffolding:

1. Reverify RAM, Docker storage, and `vm.max_map_count`.
2. Confirm Docker data resides on the separately approved storage location.
3. Obtain the pinned images through a separately approved action.
4. Generate the CA and Elasticsearch HTTP certificate.
5. Create the ignored bootstrap-password file with restrictive host ACLs.
6. Start Elasticsearch only.
7. Require the CA-verified listener probe to return HTTP `401`, treating it only as listener readiness.
8. Wait for authenticated Compose health to prove non-timeout `yellow` or `green` cluster state.
9. Create a named token for the predefined `elastic/kibana` service account through the official API.
10. Create or update the ignored Kibana keystore.
11. Pipe the token through stdin into `elasticsearch.serviceAccountToken`, suppress output, and clear the in-memory value.
12. Start Kibana.
13. Verify `/api/status` returns HTTP `200` with `status.overall.level` equal to `available`.
14. Install the exact compatible System integration version; record its version and installation timestamp.
15. Generate and download the standalone Agent policy.
16. Stage the unsanitized policy, then sanitize and review any future committed example.
17. Run the confirmed firewall creation script for inbound TCP `9200` only.
18. Verify listener and firewall scope are limited to `192.168.15.1`, guest `192.168.15.6`, and the uniquely discovered host-only interface.
19. Verify the already-downloaded Agent `9.4.3` artifact against the official SHA-512 file and any official signature mechanism published for that exact artifact.
20. Install the Agent only after every preceding gate passes.

Starting both Compose services initially is invalid because the required Kibana service token does not yet exist in the keystore.

## Firewall lifecycle

The paired scripts dynamically require exactly one Up VirtualBox host-only adapter carrying `192.168.15.1` and exactly one applicable Domain, Private, or Public profile. Actual mutation requires administrator rights, `-Approve`, and explicit `ShouldProcess` confirmation.

The creation script is idempotent. An exact existing rule is a no-op; any same-name drift fails closed. The removal script deletes only the exact verified rule. Neither script is executed by static validation.

## Static validation

The approved Windows PowerShell 5.1 fallback command is:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-Phase1Scaffolding.ps1
```

The validator renders Compose with conspicuously invalid temporary source material outside the repository, inspects the JSON model, validates source and documentation contracts, and runs `git diff --check`. It also performs PowerShell AST/structural TLS checks, strict Kibana telemetry and health checks, 13 negative fixtures, and strict UTF-8, final-newline, line-ending, trailing-whitespace, and indentation checks across approved tracked and untracked scaffold text paths. All temporary material remains outside the repository and is removed in `finally`. The validator never starts containers or performs runtime actions.

## Rollback boundaries

Repository-only scaffolding rollback should use a later normal Git revert after commit. Do not use hard reset, clean, or historical-evidence edits. Runtime firewall rollback uses only the paired exact-rule removal script. The certificate-generation script owns only its unique staging run and an exact partially promoted final directory; secret, keystore, volume, or service cleanup still requires a separately reviewed runtime rollback after dependents are stopped.
