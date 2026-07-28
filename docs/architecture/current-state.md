# Current Architecture Baseline

This document records the runtime architecture before the lifecycle roadmap refactoring.

## Feature Matrix

| Capability | Current implementation |
|---|---|
| Asset TLS scan | `ScanJobService` and Python certificate worker |
| CIDR discovery | `NetworkDiscoveryService` and Python range worker |
| Inventory | EF Core/SQLite, SHA-256 fingerprint deduplication |
| ACME issuance | Certes DNS-01 flow in `CertificateRequestService` |
| Manual DNS | Challenge names and values are persisted and displayed |
| Cloudflare DNS | Direct Cloudflare v4 HTTP calls in `CertificateRequestService` |
| Certificate storage | Vault KV v2 HTTP write in `CertificateRequestService` |
| Renewal | `CertificateRequestRenewalWorker` polls once per minute |
| Vault discovery | Public endpoint, PKI and KV discovery services |
| Authorization | Cookie authentication with Admin and Read roles |
| Observability | Health endpoints, Prometheus and OpenTelemetry |

## Runtime Components

The ASP.NET Core application owns the UI, APIs, SQLite persistence, scheduling,
ACME issuance and integrations. Two Python worker processes poll the application
for asset scans and CIDR discovery. Vault is an external integration; Docker
Compose supplies a development-mode Vault instance.

`CertificateRequestService` currently performs command validation, name
normalization, dependency lookup, Certes account/order operations, DNS challenge
generation, Cloudflare publishing and cleanup, certificate generation, inventory
upsert, Vault KV storage, DTO mapping and renewal decisions. This concentration
is the primary boundary targeted by P1.

## Cloudflare Behavior

The service finds an active zone by configured zone name, queries TXT records by
record name, and compares exact content. Publishing creates a missing record or
updates the exact matching record with TTL 120. Cleanup queries the same name and
deletes only record IDs whose content exactly equals the stored challenge value.
Unrelated TXT values are left intact. Cleanup errors are stored on the request
and do not undo successful issuance.

## Vault Behavior

Certificate requests require an enabled Vault server. A path such as
`secret/certificates/example.com` is converted to the KV v2 endpoint
`/v1/secret/data/certificates/example.com`. The payload contains the domain,
SANs, leaf certificate, private key, full chain, provider name, issuance time and
request ID. The configured Vault token is sent in `X-Vault-Token`.

## Scheduler Behavior

`CertificateRequestRenewalWorker` creates a scope every minute and calls
`RunDueScheduledChecksAsync`. At most ten due requests are processed in order.
Valid certificates beyond the renewal threshold are rescheduled. Requests
already validating are retried later. Pending automatic DNS requests are
published, delayed for propagation and validated. Manual DNS requests remain
waiting. Requests at or inside the threshold start a fresh challenge.

