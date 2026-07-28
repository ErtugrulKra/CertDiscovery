# Development Plan P5 — Deployers, Verification and Rollback

## Objective

Implement practical deployment adapters and use CertDiscovery's discovery engine to verify successful activation.

## Recommended Implementation Order

1. Vault KV
2. File system/export
3. Kubernetes TLS Secret
4. IIS
5. Nginx/Apache over SSH
6. AWS ACM
7. Azure Key Vault
8. Azure Application Gateway

---

## P5.1 — Vault KV Deployer

Convert existing Vault storage behavior into a deployer/store adapter.

Capabilities:

- Write certificate
- Write private key
- Write full chain
- Versioned KV storage
- Preserve previous version
- Verify written data
- Rollback by restoring prior version or metadata pointer

This becomes the reference deployer.

---

## P5.2 — File System Export Deployer

Capabilities:

- PEM bundle
- Fullchain
- Private key
- PFX export
- Configurable file names
- Atomic write using temporary file and rename
- File permission configuration
- Backup previous files
- Rollback
- Hash verification

This adapter is useful for sidecar and shared-volume patterns.

---

## P5.3 — Kubernetes TLS Secret Deployer

Configuration:

```text
Cluster integration
Namespace
Secret name
Create if missing
Additional annotations
Restart strategy optional
```

Capabilities:

- Create/update `kubernetes.io/tls`
- Preserve unrelated metadata
- Store `tls.crt` and `tls.key`
- Optional CA bundle field
- ResourceVersion conflict handling
- Verify secret fingerprint
- Roll back prior secret version
- Optional rollout restart for selected workloads

Security:

- Minimum RBAC
- Never expose private key in UI or logs
- Prefer workload identity/service account

---

## P5.4 — IIS Deployer

Capabilities:

- Generate PFX
- Import into Windows certificate store
- Identify site and HTTPS binding
- Replace binding certificate
- Preserve SNI and host name
- Support Central Certificate Store as separate mode
- Verify certificate binding
- Back up previous thumbprint
- Roll back binding

Execution model:

- Windows agent or WinRM
- Do not assume the main web application runs on Windows

---

## P5.5 — Nginx and Apache SSH Deployer

Capabilities:

- Upload certificate, key and chain
- Atomic file replacement
- Preserve permissions
- Run configuration test:
  - `nginx -t`
  - `apachectl configtest`
- Reload service
- Verify endpoint
- Restore previous files on failure

Security:

- SSH key secret reference
- Host key verification
- Command allowlist
- No arbitrary shell commands in UI

---

## P5.6 — AWS ACM Deployer

Capabilities:

- Import certificate into ACM
- Update or create imported certificate
- Preserve ARN where possible
- Track certificate ARN
- Support regional configuration
- Verify imported metadata
- Integrate later with ALB/CloudFront mapping

Important:

ACM public certificates are a different issuance model. This deployer initially targets externally issued/imported certificates.

---

## P5.7 — Azure Key Vault Certificate Deployer

Capabilities:

- Import PFX/PEM
- Configure content type
- Version handling
- Tag certificate with CertDiscovery metadata
- Verify resulting secret/certificate version
- Preserve previous version for rollback

---

## P5.8 — Azure Application Gateway Deployer

Capabilities:

- Reference Key Vault certificate or upload certificate
- Update listener certificate
- Wait for provisioning state
- Verify listener configuration
- Verify external endpoint
- Roll back previous certificate reference

---

# Post-Deployment Verification

## Verification Methods

### External TLS Verification

Reuse discovery worker:

1. Scan configured endpoint.
2. Retrieve active leaf certificate.
3. Compare fingerprint with expected certificate.
4. Validate SAN and expiration.
5. Record observed chain.
6. Mark deployment successful only after match.

### Internal Target Verification

Examples:

- Kubernetes Secret fingerprint
- IIS binding thumbprint
- Vault version metadata
- File hash
- ACM certificate ARN and fingerprint
- Azure Key Vault version

Both internal and external verification should be supported.

## Multi-Node Verification

For load-balanced systems:

- Allow multiple verification endpoints.
- Require configurable quorum:
  - all nodes,
  - any node,
  - percentage.
- Detect partial rollout where old and new certificates are both served.
- Keep deployment in `PartiallyVerified` state when inconsistent.

## Rollback Rules

Rollback is mandatory when:

- Activation fails.
- External endpoint serves wrong certificate after timeout.
- Config validation fails.
- Target health check fails.
- Only part of a required node set updates.

Rollback may be disabled by policy for immutable/versioned targets.

## Acceptance Criteria

- [ ] Vault deployer works.
- [ ] File-system deployer works.
- [ ] Kubernetes TLS Secret deployer works.
- [ ] At least one web-server deployer works.
- [ ] External fingerprint verification works.
- [ ] Multi-node partial rollout is detected.
- [ ] Rollback is tested.
- [ ] Private keys never appear in logs.
- [ ] Deployment metrics are exposed.
- [ ] Deployment history is visible in UI.

## VibeCode Prompt

```text
Implement concrete certificate deployers using the P4 adapter architecture.

Start with Vault KV and file-system export, then add Kubernetes TLS Secret,
IIS, and Nginx/Apache SSH deployers. Add AWS ACM, Azure Key Vault and Azure
Application Gateway adapters after the core adapters are stable.

Use CertDiscovery's existing discovery worker for post-deployment external TLS
verification. Compare the observed leaf certificate fingerprint with the
expected certificate. Support multi-node verification, partial rollout
detection and rollback.

Add contract tests for all deployers and never expose private keys in logs or UI.
```
