# Development Plan P0 — Baseline and Safety Net

## Objective

Create a verified baseline of the current CertDiscovery behavior before refactoring. This phase must not introduce new user-facing features.

## Existing Capabilities to Preserve

- Asset-based TLS scans
- CIDR network discovery
- Certificate inventory and fingerprint deduplication
- Manual DNS-01 ACME workflow
- Cloudflare DNS automation
- Standard and wildcard certificate requests
- SAN support
- Scheduled renewal
- Vault KV certificate storage
- Vault PKI and KV discovery
- Admin and Read roles
- Prometheus and OpenTelemetry
- Docker Compose startup

## Work Items

### P0.1 — Document Current Architecture

Create:

```text
docs/architecture/current-state.md
docs/architecture/current-acme-flow.md
docs/architecture/current-data-model.md
```

Document:

- `CertificateRequestService` responsibilities
- ACME request state transitions
- Cloudflare publish and cleanup behavior
- Vault storage behavior
- Scheduler behavior
- Database fields containing sensitive data

### P0.2 — Add Characterization Tests

Add tests covering the current behavior before moving code.

Required scenarios:

- Create standard certificate request
- Create wildcard certificate request
- Normalize SAN list
- Start DNS challenge
- Generate expected `_acme-challenge` records
- Manual DNS workflow
- Cloudflare publish
- Cloudflare cleanup
- Issue certificate
- Persist certificate inventory record
- Store certificate bundle in Vault
- Scheduled renewal triggers
- Failed challenge changes request status
- Timeout leaves request retryable

### P0.3 — Introduce Test Fixtures

Create reusable fixtures for:

- Fake ACME directory
- Fake ACME order and authorization
- Fake DNS API
- Fake Vault server
- Test certificates
- Standard and wildcard requests

Suggested structure:

```text
tests/
  CertificateDiscovery.Infrastructure.Tests/
    Fixtures/
    Acme/
    Dns/
    Vault/
```

### P0.4 — Security Inventory

Create:

```text
docs/security/secret-inventory.md
```

List every sensitive value:

- ACME account key
- Certificate private key
- EAB HMAC key
- Cloudflare token
- Vault token
- Future AWS and Azure credentials
- Worker API key
- Cookie and application secrets

Classify each as:

```text
Plaintext DB
Environment variable
Vault
Generated runtime value
Not yet protected
```

## Acceptance Criteria

- [ ] Current feature matrix is documented.
- [ ] Existing ACME behavior is covered by characterization tests.
- [ ] Cloudflare publishing and cleanup are tested.
- [ ] Vault storage is tested.
- [ ] Renewal scheduling is tested.
- [ ] Sensitive data inventory is documented.
- [ ] No production behavior changes.
- [ ] `dotnet test CertificateDiscovery.sln` passes.
- [ ] Python worker tests pass.
- [ ] Docker Compose smoke test passes.

## VibeCode Prompt

```text
Analyze the current CertDiscovery repository without changing runtime behavior.

Create characterization tests around CertificateRequestService, ACME DNS-01,
Cloudflare publishing and cleanup, Vault storage, certificate inventory updates,
and scheduled renewal.

Document the current architecture, request state transitions, data model, and all
sensitive values currently stored or passed by the application.

Do not refactor production code in this phase. Preserve all existing behavior.
Run all .NET and Python tests and report any uncovered behavior or testability
blockers.
```
