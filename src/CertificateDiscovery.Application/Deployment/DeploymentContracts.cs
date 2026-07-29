using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Application.Deployment;

public sealed record DeploymentTargetContext(DeploymentTarget Target, string? Secret);
public sealed record DeploymentContext(CertificateDeployment Deployment, DeploymentTarget Target, DeploymentPolicy Policy, string? Secret = null);
public sealed record IssuedCertificateBundle(
    string CertificatePem,
    string PrivateKeyPem,
    string FullChainPem,
    string Fingerprint,
    int? VaultVersion = null);
public sealed record DeploymentValidationResult(bool IsValid, string? Message = null);
public sealed record DeploymentPrecheckResult(bool IsReady, string? PreviousFingerprint = null, string? Message = null);
public sealed record DeploymentBackupResult(bool Succeeded, string? BackupReference = null, string? Message = null);
public sealed record DeploymentApplyResult(bool Succeeded, string? Message = null, bool PendingExternalCompletion = false);
public sealed record DeploymentActivationResult(bool Succeeded, string? Message = null);
public sealed record DeploymentVerificationResult(bool Succeeded, string? ObservedFingerprint = null, string? Message = null);
public sealed record DeploymentRollbackResult(bool Succeeded, string? ObservedFingerprint = null, string? Message = null);
public sealed record ConvertedCertificateBundle(byte[] Pfx, string CertificatePem, string PrivateKeyPem, string FullChainPem);

public interface ICertificateDeployer
{
    DeploymentTargetType TargetType { get; }
    Task<DeploymentValidationResult> ValidateTargetAsync(DeploymentTargetContext context, CancellationToken cancellationToken);
    Task<DeploymentPrecheckResult> PrecheckAsync(DeploymentContext context, CancellationToken cancellationToken);
    Task<DeploymentBackupResult> BackupAsync(DeploymentContext context, CancellationToken cancellationToken);
    Task<DeploymentApplyResult> DeployAsync(DeploymentContext context, IssuedCertificateBundle bundle, CancellationToken cancellationToken);
    Task<DeploymentActivationResult> ActivateAsync(DeploymentContext context, CancellationToken cancellationToken);
    Task<DeploymentVerificationResult> VerifyAsync(DeploymentContext context, IssuedCertificateBundle bundle, CancellationToken cancellationToken);
    Task<DeploymentRollbackResult> RollbackAsync(DeploymentContext context, DeploymentBackupResult backup, CancellationToken cancellationToken);
}

public interface ICertificateDeployerResolver
{
    ICertificateDeployer Resolve(DeploymentTargetType targetType);
}

public interface ICertificateBundleConverter
{
    ConvertedCertificateBundle Convert(IssuedCertificateBundle bundle, string pfxPassword);
}

public interface IDeploymentCertificateBundleSource
{
    Task<IssuedCertificateBundle> LoadAsync(CertificateDeployment deployment, CancellationToken cancellationToken);
}

public interface IVersionedDeploymentCertificateBundleSource : IDeploymentCertificateBundleSource
{
    Task<IssuedCertificateBundle> LoadVersionAsync(
        CertificateDeployment deployment,
        int version,
        CancellationToken cancellationToken);
}

public interface IDeploymentStateMachine
{
    bool CanTransition(CertificateDeploymentStatus from, CertificateDeploymentStatus to);
    void Transition(CertificateDeployment deployment, CertificateDeploymentStatus target);
}

public interface ICertificateDeploymentOrchestrator
{
    Task<Guid> CreateAsync(Guid requestId, Guid targetId, Guid policyId, string actor, DeploymentOrigin origin, CancellationToken cancellationToken);
    Task ExecuteAsync(Guid deploymentId, string actor, CancellationToken cancellationToken);
    Task ApproveAsync(Guid deploymentId, string actor, CancellationToken cancellationToken);
    Task RejectAsync(Guid deploymentId, string actor, CancellationToken cancellationToken);
    Task CancelAsync(Guid deploymentId, string actor, CancellationToken cancellationToken);
    Task RollbackAsync(Guid deploymentId, string actor, CancellationToken cancellationToken);
}

public interface IDeploymentQueue
{
    Task EnqueueAsync(Guid deploymentId, string idempotencyKey, DateTime nextAttemptAtUtc, CancellationToken cancellationToken);
    Task<DeploymentJob?> ClaimAsync(string owner, TimeSpan lease, CancellationToken cancellationToken);
    Task CompleteAsync(Guid jobId, CancellationToken cancellationToken);
    Task FailAsync(Guid jobId, string error, int maxAttempts, TimeSpan retryDelay, CancellationToken cancellationToken);
}
