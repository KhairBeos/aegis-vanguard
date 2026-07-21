# Phase 1 Local Secrets

This directory is a local runtime staging area. Git ignores every file here except this README.

## Elasticsearch bootstrap password

The runtime source path is `deploy/secrets/elasticsearch-bootstrap-password.txt`. Create it only after the Phase 1 resource gates pass and runtime preparation is separately approved.

Requirements:

- Generate a unique high-entropy value; do not reuse a personal or external-system password.
- Write exactly one value to the file. Do not place it in Compose, `.env`, shell history, documentation, or evidence.
- Remove inherited ACLs and grant access only to the current operator and required local system account.
- Do not print the value while creating, validating, or rotating it.
- Stop Elasticsearch before removing or rotating the source file.

Compose mounts this file as `elasticsearch-bootstrap-password` under `/run/secrets`. Elasticsearch reads it through `ELASTIC_PASSWORD_FILE`; the authenticated health helper reads the same mounted secret without emitting it.

## Kibana service token

The token for the predefined `elastic/kibana` service account belongs only in the ignored file `deploy/kibana/config/kibana.keystore`, under the key `elasticsearch.serviceAccountToken`.

Create the named token only after Elasticsearch has passed authenticated cluster health. Pipe the token to the pinned Kibana keystore command through standard input, suppress command output, clear the in-memory value, and protect the resulting file with restrictive host ACLs. Never store the token here as plain text.

## Standalone Agent API key

The Agent API key remains in the protected live configuration on `AEGIS-WIN-VICTIM-01`. It must not be written anywhere under this repository.
