# Development Plan P6 — Enterprise Security, Reliability and Scale

## Objective

Make CertDiscovery safe and reliable for production and multi-instance enterprise deployments.

## P6.1 — Secret Provider Architecture

Create:

```csharp
ISecretProvider
```

Implement:

1. HashiCorp Vault
2. Encrypted database provider
3. Azure Key Vault
4. AWS Secrets Manager, optional

Move:

- EAB HMAC
- ACME account key
- DNS credentials
- Vault tokens
- Deployment credentials
- Certificate private keys

out of plaintext application tables.

Requirements:

- Secret references in entities
- Key rotation
- Version support
- Access audit
- Secret redaction
- Migration tool for existing plaintext values

---

## P6.2 — PostgreSQL

Complete existing PostgreSQL roadmap.

Requirements:

- Provider selection by configuration
- PostgreSQL migrations
- SQLite compatibility
- Integration tests
- Docker Compose profile
- Backup and restore guidance
- Concurrency testing

---

## P6.3 — Distributed Job Processing

Add RabbitMQ or a robust database job queue.

Job types:

- Asset scan
- Network discovery
- ACME renewal
- DNS propagation
- Deployment
- Verification
- Notification
- Revocation check

Requirements:

- At-least-once processing
- Idempotent handlers
- Lease/lock
- Retry with backoff
- Dead-letter queue
- Correlation ID
- Cancellation
- Worker heartbeat

---

## P6.4 — Audit Logging

Record all security-sensitive actions:

- Login
- User/role change
- Provider change
- Secret reference change
- Certificate request
- Renewal
- Revocation
- Deployment
- Rollback
- Manual approval
- Failed authorization

Audit records must be append-only.

---

## P6.5 — Notification System

Channels:

- Email
- Slack
- Microsoft Teams
- Generic webhook

Events:

- Certificate expiration
- Renewal success/failure
- DNS challenge failure
- Deployment success/failure
- Partial rollout
- Rollback
- Revoked certificate
- Worker offline
- Provider unhealthy

Requirements:

- Deduplication
- Escalation
- Per-environment rules
- Quiet hours
- Test notification
- Retry and dead letter

---

## P6.6 — RBAC Expansion

Roles:

```text
PlatformAdmin
CertificateAdmin
Operator
Approver
Auditor
ReadOnly
```

Permissions should be capability-based:

- Manage assets
- Manage providers
- Issue certificate
- Approve deployment
- Deploy certificate
- Revoke certificate
- View secrets metadata
- View audit
- Manage tenants

---

## P6.7 — Multi-Tenancy

Tenant separation:

- Assets
- Certificates
- Providers
- Accounts
- DNS integrations
- Deployment targets
- Users and roles
- Audit
- Notifications

Requirements:

- Tenant ID enforced in queries
- No cross-tenant secret access
- Tenant-scoped worker jobs
- Tenant-aware metrics labels with cardinality control

---

## P6.8 — SSRF and Network Controls

Add:

- Allowed CIDRs
- Denied CIDRs
- Block metadata IPs
- Block loopback by policy
- DNS rebinding mitigation
- Port allowlist
- Worker egress policies
- Audit denied attempts

---

## P6.9 — Kubernetes and Helm

Provide:

- Web/API deployment
- Discovery worker
- Range worker
- Renewal worker
- Deployment worker
- PostgreSQL optional dependency
- RabbitMQ optional dependency
- ConfigMaps
- Secret references
- NetworkPolicies
- Probes
- Resource limits
- Pod disruption budgets
- Helm chart

---

## P6.10 — Observability

Metrics:

- ACME order duration
- ACME failure count
- DNS propagation duration
- Renewal success rate
- Deployment success rate
- Rollback count
- Verification latency
- Queue depth
- Worker health
- Certificate risk by tenant/environment

Tracing:

```text
Request -> ACME -> DNS -> issuance -> storage -> deployment -> verification
```

Add correlation IDs throughout.

## Acceptance Criteria

- [ ] No production secret is stored plaintext.
- [ ] PostgreSQL is supported.
- [ ] Distributed workers are supported.
- [ ] Audit log is append-only.
- [ ] Notifications cover lifecycle failures.
- [ ] Fine-grained RBAC is available.
- [ ] Multi-tenancy is enforced.
- [ ] SSRF controls are implemented.
- [ ] Kubernetes deployment is documented.
- [ ] End-to-end traces and metrics exist.
- [ ] Disaster recovery documentation exists.

## VibeCode Prompt

```text
Harden CertDiscovery for enterprise production.

Implement external secret providers, PostgreSQL, distributed job processing,
append-only audit logging, lifecycle notifications, fine-grained RBAC,
multi-tenancy, SSRF/network controls, Kubernetes/Helm deployment and complete
observability.

All job handlers must be idempotent. All secrets must be referenced rather than
stored in plaintext. Add integration tests for tenant isolation, distributed
locking, secret redaction, audit immutability and failure recovery.
```
