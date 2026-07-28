# Development Plan P4 — Certificate Deployer Adapter Architecture

## Objective

Create a generic deployment orchestration layer capable of delivering issued certificates to heterogeneous infrastructure.

## Key Outcome

Issuance and deployment must become separate, observable lifecycle stages.

## Domain Model

### DeploymentTarget

```text
Id
Name
TargetType
AssetId optional
ConfigurationJson
SecretReference optional
IsEnabled
CreatedAtUtc
UpdatedAtUtc
```

### CertificateDeployment

```text
Id
CertificateRequestId
CertificateId
DeploymentTargetId
Status
Attempt
PreviousFingerprint
ExpectedFingerprint
ObservedFingerprint
StartedAtUtc
CompletedAtUtc
ErrorCode
ErrorMessage
BackupReference
RollbackStatus
VerificationStatus
CreatedAtUtc
```

### DeploymentPolicy

```text
Id
Name
RequireApproval
AutomaticDeployment
MaxAttempts
RetryDelaySeconds
RollbackOnFailure
VerificationTimeoutSeconds
DeploymentWindow optional
```

## Status Model

```text
Pending
AwaitingApproval
Prechecking
BackingUp
Deploying
Activating
Verifying
Succeeded
Failed
RollingBack
RolledBack
RollbackFailed
Cancelled
```

## Adapter Contract

```csharp
public interface ICertificateDeployer
{
    DeploymentTargetType TargetType { get; }

    Task<DeploymentValidationResult> ValidateTargetAsync(
        DeploymentTargetContext context,
        CancellationToken cancellationToken);

    Task<DeploymentPrecheckResult> PrecheckAsync(
        DeploymentContext context,
        CancellationToken cancellationToken);

    Task<DeploymentBackupResult> BackupAsync(
        DeploymentContext context,
        CancellationToken cancellationToken);

    Task<DeploymentApplyResult> DeployAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken);

    Task<DeploymentActivationResult> ActivateAsync(
        DeploymentContext context,
        CancellationToken cancellationToken);

    Task<DeploymentVerificationResult> VerifyAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken);

    Task<DeploymentRollbackResult> RollbackAsync(
        DeploymentContext context,
        DeploymentBackupResult backup,
        CancellationToken cancellationToken);
}
```

## Orchestrator

Create:

```text
ICertificateDeploymentOrchestrator
CertificateDeploymentOrchestrator
```

Workflow:

```text
Validate target
  -> Precheck
  -> Backup
  -> Deploy
  -> Activate
  -> Verify
  -> Success
```

Failure workflow:

```text
Failure
  -> Evaluate rollback policy
  -> Rollback
  -> Verify previous state
  -> Record final status
```

## Work Items

### P4.1 — Add Deployment Entities and Migrations

Add indexes:

- Deployment target and certificate
- Status and next retry
- Request and target uniqueness where appropriate

### P4.2 — Add Adapter Resolver

```text
ICertificateDeployerResolver
```

No switch statements in controller or orchestrator.

### P4.3 — Add Deployment Queue

Initial implementation may use database-backed jobs.

Required properties:

- Idempotency key
- Claim owner
- Lease expiry
- Retry count
- Next attempt
- Dead-letter state

### P4.4 — Add Approval Flow

UI actions:

- Approve
- Reject
- Retry
- Rollback
- Cancel

Policy controls whether deployment starts automatically.

### P4.5 — Add Deployment Target UI

Screens:

- Target list
- Create/edit target
- Test connection
- Associate request with target
- Deployment history
- Error details
- Verification result

### P4.6 — Bundle Conversion Service

Create:

```text
ICertificateBundleConverter
```

Formats:

- PEM certificate
- PEM private key
- Full chain PEM
- PKCS#12/PFX
- Optional JKS in later phase

Ensure temporary files are securely deleted.

### P4.7 — Audit Events

Record:

- Who initiated deployment
- Automatic/manual origin
- Target
- Certificate fingerprint
- Previous fingerprint
- Result
- Rollback
- Error
- Duration

## Tests

- State transitions
- Idempotent deployment creation
- Retry and lease handling
- Approval required
- Automatic deployment
- Backup failure
- Deploy failure
- Verification failure
- Rollback success
- Rollback failure
- Secret redaction
- Temporary-file cleanup

## Acceptance Criteria

- [ ] Deployment is a separate lifecycle stage.
- [ ] Generic deployer interface exists.
- [ ] Orchestrator manages precheck through rollback.
- [ ] Deployment history is persisted.
- [ ] Approval policy is supported.
- [ ] Retry and idempotency exist.
- [ ] UI displays deployment status.
- [ ] No concrete infrastructure deployer is required to complete this phase.
- [ ] Fake deployer integration tests pass.

## VibeCode Prompt

```text
Add a generic certificate deployment architecture to CertDiscovery.

Create DeploymentTarget, CertificateDeployment and DeploymentPolicy entities,
migrations, status transitions, a deployment job model, ICertificateDeployer,
ICertificateDeployerResolver and CertificateDeploymentOrchestrator.

The orchestrator must execute validate, precheck, backup, deploy, activate,
verify and optional rollback stages. Add approval, retry, idempotency, audit and
deployment-history UI.

Use a fake deployer for integration tests. Do not implement IIS, Nginx,
Kubernetes or cloud deployers in this phase.
```
