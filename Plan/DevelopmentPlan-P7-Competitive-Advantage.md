# Development Plan P7 — Capabilities Beyond Conventional ACME CaaS

## Objective

Add differentiating features that make CertDiscovery more valuable than a CA-specific ACME renewal service.

## Competitive Position

A conventional ACME CaaS focuses on:

```text
Order -> Validate -> Issue -> Renew
```

CertDiscovery must own:

```text
Discover -> Inventory -> Govern -> Issue -> Store -> Deploy -> Verify -> Monitor
```

## P7.1 — Certificate Policy Engine

Policies:

- Allowed issuers
- Allowed key algorithms
- Minimum RSA size
- Allowed curves
- Maximum certificate age
- Required SAN patterns
- Wildcard restrictions
- Environment restrictions
- Renewal window
- Deployment approval
- Private-key rotation requirement

Outcomes:

```text
Allow
Warn
RequireApproval
Block
```

---

## P7.2 — Drift Detection

Detect:

- Endpoint serves unknown certificate
- Deployment target differs from inventory
- Vault version differs from active endpoint
- Unauthorized self-signed certificate
- Certificate replaced outside CertDiscovery
- Old certificate remains on one load-balanced node
- SAN set changed unexpectedly

---

## P7.3 — Ownership and Dependency Mapping

Add:

- Business owner
- Technical owner
- Team
- Application
- Environment
- Criticality
- Dependency
- Maintenance window
- Escalation contact

Use this information in notifications and deployment approvals.

---

## P7.4 — Revocation Intelligence

Implement:

- OCSP checks
- CRL checks
- Revocation reason
- Last check
- Next update
- Stapling observation
- Alert when endpoint serves revoked certificate
- Automatic emergency deployment workflow

---

## P7.5 — Certificate Chain Analysis

Detect:

- Missing intermediate
- Expired intermediate
- Untrusted root
- Weak signature algorithm
- Short key
- Chain order problem
- Duplicate chain entry
- Cross-signed chain differences

---

## P7.6 — Kubernetes Discovery and Closed Loop

Combine:

- Discover `kubernetes.io/tls` secrets
- Import certificate metadata
- Associate workloads/ingresses
- Renew certificate
- Deploy updated secret
- Restart or wait for reload
- Verify ingress endpoint
- Detect unmanaged changes

This creates a complete closed-loop capability.

---

## P7.7 — Provider Health and Failover

Health checks:

- ACME directory availability
- Account validity
- DNS provider access
- Secret provider access
- Deployment target connectivity

Optional failover:

- Primary and secondary ACME provider
- Policy-controlled CA fallback
- Manual approval before fallback
- Prevent accidental issuer change

---

## P7.8 — Renewal Simulation

Before enabling automation, simulate:

- Certificates due in next 30/60/90 days
- Expected order volume
- DNS provider operations
- Deployment targets
- Approval bottlenecks
- Failure blast radius

Provide a readiness report.

---

## P7.9 — Compliance Reports

Reports:

- Certificates expiring by period
- Unmanaged certificates
- Weak cryptography
- Unknown owners
- Failed renewals
- Failed deployments
- Revoked certificates
- Policy violations
- Deployment verification coverage
- Audit export

Formats:

- CSV
- JSON
- PDF later
- API

---

## P7.10 — Plugin SDK

Allow external extensions:

```text
ICertificateIssuerProvider
IDnsChallengeProvider
ICertificateStore
ICertificateDeployer
INotificationChannel
ICertificateDiscoverySource
IPolicyRule
```

Provide:

- SDK package
- Sample plugin
- Version compatibility
- Plugin manifest
- Isolated loading
- Security guidance

## Final Acceptance Criteria

- [ ] Discovery and lifecycle operate as a closed loop.
- [ ] Policy violations can block issuance or deployment.
- [ ] Drift is detected automatically.
- [ ] Revoked certificates trigger emergency workflows.
- [ ] Chain quality is analyzed.
- [ ] Kubernetes supports discover-renew-deploy-verify.
- [ ] Provider health is visible.
- [ ] Renewal simulation exists.
- [ ] Compliance reporting exists.
- [ ] External plugins can be built without editing core code.

## VibeCode Prompt

```text
Add the competitive capabilities that differentiate CertDiscovery from a
CA-specific ACME CaaS.

Implement a certificate policy engine, drift detection, ownership and dependency
mapping, OCSP/CRL revocation intelligence, chain analysis, Kubernetes closed-loop
management, provider health, controlled failover, renewal simulation, compliance
reports and a plugin SDK.

Prioritize features that combine CertDiscovery's discovery inventory with
issuance, deployment and post-deployment verification. Preserve provider
independence and enforce tenant and secret boundaries.
```
