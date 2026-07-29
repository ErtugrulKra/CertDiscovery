# Certificate deployment architecture

Certificate issuance/storage and certificate deployment are separate lifecycle
stages. A deployment failure never changes a successfully issued certificate
request from `StoredInVault`.

## Flow

```text
CertificateDeployment
  -> database DeploymentJob
  -> lease-based DeploymentWorker
  -> ICertificateDeployerResolver
  -> Validate -> Precheck -> Backup -> Deploy -> Activate -> Verify
  -> Succeeded
```

When a stage after backup fails and the policy enables rollback:

```text
Failure -> RollingBack -> RolledBack | RollbackFailed
```

Every transition is persisted as a `DeploymentAuditEvent`. Jobs use a unique
idempotency key, claim owner, lease expiration, retry count, next-attempt time
and dead-letter state. Expired claims can be recovered by another worker.

## Adapter boundary

`ICertificateDeployer` owns target-specific behavior. The orchestrator contains
no concrete target switch. P4 includes a deterministic fake adapter for
contract and failure-path testing. Microsoft IIS, NGNIX, HA Proxy, Traefik,
Apache Web Server, Kubernetes and cloud adapters
are intentionally deferred to P5.

Target credentials are stored through `ISecretProvider`; DTOs expose only
whether a secret exists. `ICertificateBundleConverter` produces PEM and
password-protected PKCS#12 data entirely in memory.
