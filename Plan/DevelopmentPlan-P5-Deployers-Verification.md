# Development Plan P5 — Deployers, Verification and Rollback

## Objective

Implement practical deployment adapters on top of the P4 architecture and use CertDiscovery's discovery engine to verify successful activation. Preserve the original P5 scope and execution models, except that Microsoft IIS deployment must be performed by an independently installed Windows agent.

## Recommended Implementation Order

1. Vault KV
2. File system/export
3. Kubernetes TLS Secret
4. Microsoft IIS through `winDeployAgent.exe`
5. NGNIX/Apache over SSH
6. AWS ACM
7. Azure Key Vault
8. Azure Application Gateway
9. Post-deployment and multi-node verification
10. Rollback, metrics, history and UI

Each section must pass its build, automated tests, security checks and applicable integration validation before implementation proceeds to the next section.

---

## P5.1 — Vault KV Deployer

Convert the existing Vault storage behavior into a deployer/store adapter.

Capabilities:

- Write certificate
- Write private key
- Write full chain
- Versioned KV storage
- Preserve the previous version
- Verify written data and fingerprint
- Roll back by restoring the prior version or metadata pointer
- Never expose private keys in logs or UI

This becomes the reference deployer.

---

## P5.2 — File System Export Deployer

Capabilities:

- PEM bundle
- Fullchain
- Private key
- PFX export
- Configurable file names
- Atomic write using a temporary file and rename
- File permission configuration
- Back up previous files
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
- Roll back the prior Secret version
- Optional rollout restart for selected workloads

Security:

- Minimum RBAC
- Never expose private keys in UI or logs
- Prefer workload identity/service account

---

## P5.4 — Microsoft IIS Deployer

Microsoft IIS is the only P5 deployer that uses the independent agent model. CertDiscovery Central must not connect directly to IIS using WinRM or remotely supplied PowerShell.

### Agent and Installer

- Create a separate Windows agent project that publishes as `winDeployAgent.exe`.
- Run as a Windows Service, with a console diagnostics mode.
- Provide `winDeployAgent-Setup.exe` or MSI installation.
- Configure Central URL, administrator-approved registration exchange, service identity and startup policy.
- Retain a short-lived one-time bootstrap token only for unattended provisioning.
- Support install, repair, upgrade and uninstall.
- Keep the main web application platform-independent.

### Agent Registration and Identity

Create a central `DeploymentAgent` model containing:

- Agent ID and name
- Machine name
- Agent type and version
- Operating system and capabilities
- Status and last heartbeat
- Identity, assigned jobs and tags

Supported states:

```text
PendingRegistration
Online
Busy
Stale
Offline
Disabled
Revoked
UpgradeRequired
```

Registration and communication rules:

- Use a short-lived device-code-style registration exchange by default.
- Display the machine identity, approval code and public-key fingerprint in Central before administrator approval.
- Generate the permanent agent token only when an approved exchange is consumed.
- Keep the short-lived, one-time registration token as an optional unattended bootstrap method.
- Generate the agent private key locally.
- Prefer mTLS; an agent token may be used where required.
- Protect local credentials with Windows DPAPI machine scope.
- Restrict each agent to its own jobs.
- Support credential revocation, payload nonce and expiry.
- Never log registration tokens, PFX passwords or private keys.

### Pull-Based Job Execution

The agent performs outbound-only polling:

1. Send heartbeat.
2. Claim an assigned deployment job.
3. Acquire and renew a job lease.
4. Download a short-lived certificate bundle encrypted for that agent.
5. Execute the deployment locally.
6. Report stage and final results.
7. Report rollback results separately when required.

Offline agents leave jobs queued. Expired leases follow the central retry and dead-letter policy.

### Bundle Protection

- Encrypt the bundle to the agent identity or protect it through mTLS.
- Never persist plaintext private keys or PFX passwords.
- Apply a restrictive ACL to any temporary PFX.
- Remove temporary material after success, failure, restart or recovery.

### Local IIS Deployment

1. Validate that Microsoft IIS and its administration APIs are available.
2. Locate the configured site and HTTPS binding.
3. Back up the current thumbprint and binding configuration.
4. Import the PFX into the configured Windows certificate store.
5. Update the binding to the new certificate.
6. Preserve IP, port, hostname and SNI settings.
7. Commit the IIS configuration.
8. Verify the binding thumbprint locally.
9. Report the result to Central.
10. Let Central perform external TLS verification.

Use `X509Store` and Microsoft IIS administration APIs. Do not execute arbitrary PowerShell received from Central.

### Central Certificate Store Mode

- Treat Central Certificate Store as a separate deployment mode.
- Validate PFX naming and CCS configuration.
- Use atomic file replacement.
- Preserve permissions and back up the previous file.
- Verify that the binding uses CCS.
- Restore the previous file on rollback.

### Target Configuration

```text
Deployment agent
IIS site name
Binding protocol
IP address
Port
Hostname
SNI enabled
Certificate store name and location
Deployment mode
Central Certificate Store settings
Application pool and restart/recycle policy
External verification endpoints and quorum
Backup retention
Old-certificate removal policy
```

### Agent API

```text
POST /api/deployment-agents/register
POST /api/deployment-agents/heartbeat
POST /api/deployment-agents/jobs/claim
POST /api/deployment-agents/jobs/{id}/renew-lease
GET  /api/deployment-agents/jobs/{id}/bundle
POST /api/deployment-agents/jobs/{id}/stage-result
POST /api/deployment-agents/jobs/{id}/complete
POST /api/deployment-agents/jobs/{id}/fail
POST /api/deployment-agents/jobs/{id}/rollback-result
```

### IIS Rollback

- Restore the previous certificate thumbprint.
- Preserve the previous binding IP, port, hostname and SNI settings.
- Re-import the previous certificate when required.
- Restore the previous CCS file in CCS mode.
- Verify the restored binding locally and externally.
- Report the rollback result to Central.

### IIS Validation

- Registration token is single-use and expires.
- Authentication, heartbeat, revocation and agent isolation work.
- Job claim, lease renewal, expiration and retry work.
- Bundle encryption and log redaction work.
- Certificate Store import and IIS binding replacement work.
- Hostname and SNI are preserved.
- CCS deployment and rollback work.
- Temporary files are removed.
- Service restart recovers unfinished work safely.
- Installer install/repair/upgrade/uninstall works.
- IIS integration tests run on a Windows-based test environment.

---

## P5.5 — NGNIX and Apache SSH Deployer

Capabilities:

- Upload certificate, key and chain
- Atomic file replacement
- Preserve permissions
- Run configuration tests:
  - NGNIX display target uses the real `nginx -t` executable command
  - Apache uses `apachectl configtest`
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

- Import a certificate into ACM
- Update or create an imported certificate
- Preserve ARN where possible
- Track certificate ARN
- Support regional configuration
- Verify imported metadata
- Integrate later with ALB/CloudFront mapping

ACM public certificates are a different issuance model. This deployer initially targets externally issued/imported certificates.

---

## P5.7 — Azure Key Vault Certificate Deployer

Capabilities:

- Import PFX/PEM
- Configure content type
- Version handling
- Tag certificates with CertDiscovery metadata
- Verify the resulting secret/certificate version
- Preserve the previous version for rollback

---

## P5.8 — Azure Application Gateway Deployer

Capabilities:

- Reference a Key Vault certificate or upload a certificate
- Update listener certificate
- Wait for provisioning state
- Verify listener configuration
- Verify the external endpoint
- Roll back the previous certificate reference

---

# Post-Deployment Verification

## External TLS Verification

Reuse the discovery worker:

1. Scan each configured endpoint.
2. Retrieve the active leaf certificate.
3. Compare its fingerprint with the expected certificate.
4. Validate SAN and expiration.
5. Record the observed chain.
6. Mark deployment successful only after the required match.

## Internal Target Verification

Examples:

- Vault version metadata and fingerprint
- File hash
- Kubernetes Secret fingerprint
- IIS binding thumbprint reported by the authenticated agent
- ACM certificate ARN and fingerprint
- Azure Key Vault version
- Azure Application Gateway listener configuration

Both internal and external results must be retained.

## Multi-Node Verification

For load-balanced systems:

- Allow multiple verification endpoints.
- Require configurable quorum: all nodes, any node or percentage.
- Detect partial rollout where old and new certificates are both served.
- Keep deployment in `PartiallyVerified` state while inconsistent.
- Trigger rollback when required by policy.

## Rollback Rules

Rollback is mandatory when:

- Activation fails.
- An external endpoint serves the wrong certificate after timeout.
- Configuration validation fails.
- Target health check fails.
- Only part of a required node set updates.

Rollback may be disabled by policy for immutable/versioned targets.

## Metrics, History and UI

- Show deployment stages, durations and history.
- Show internal and external verification results.
- Show rollback cause and outcome.
- Show IIS agent state and last heartbeat.
- Expose success, failure, retry, rollback and verification metrics.
- Never place sensitive certificate material in UI or metric labels.

## Acceptance Criteria

- [x] Vault deployer works.
- [x] File-system deployer works.
- [x] Kubernetes TLS Secret deployer works.
- [x] `winDeployAgent.exe` runs as an independent Windows Service.
- [x] The IIS agent can be installed and upgraded.
- [x] The IIS agent registers securely and receives only its own jobs.
- [x] IIS bindings are updated through the agent while preserving SNI and host settings.
- [x] IIS deployment can be verified and rolled back.
- [ ] NGNIX/Apache SSH deployer works.
- [ ] AWS ACM deployer works.
- [ ] Azure Key Vault deployer works.
- [ ] Azure Application Gateway deployer works.
- [ ] External fingerprint verification works.
- [ ] Multi-node partial rollout is detected.
- [ ] Rollback is tested.
- [x] Private keys never appear in logs or UI.
- [ ] Deployment metrics are exposed.
- [ ] Deployment history is visible in UI.
- [x] IIS integration tests pass in a Windows environment.
- [ ] Contract and integration tests pass for the other deployers.

## VibeCode Prompt

```text
Implement concrete certificate deployers using the P4 adapter architecture.

Start with Vault KV and file-system export, then add Kubernetes TLS Secret.
Implement Microsoft IIS only through an independently installed Windows Service
named winDeployAgent.exe. The IIS agent must use outbound pull-based jobs,
authenticated registration, leases, protected certificate bundles, local IIS
administration APIs, local verification and rollback. Do not use direct WinRM
or arbitrary remotely supplied PowerShell.

Continue with NGNIX/Apache SSH, AWS ACM, Azure Key Vault and Azure Application
Gateway without changing their planned execution models.

Use CertDiscovery's discovery worker for post-deployment external TLS
verification. Compare observed leaf fingerprints with the expected certificate.
Support multi-node verification, partial rollout detection and rollback. Add
contract tests for all deployers and never expose private keys in logs or UI.
```
