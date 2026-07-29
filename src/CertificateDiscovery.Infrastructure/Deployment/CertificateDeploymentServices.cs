using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class CertificateDeployerResolver(IEnumerable<ICertificateDeployer> deployers) : ICertificateDeployerResolver
{
    private readonly IReadOnlyDictionary<DeploymentTargetType, ICertificateDeployer> deployers =
        deployers.ToDictionary(x => x.TargetType);

    public ICertificateDeployer Resolve(DeploymentTargetType targetType) =>
        deployers.TryGetValue(targetType, out var deployer)
            ? deployer
            : throw new NotSupportedException($"Deployment target type {targetType} is not supported.");
}

public sealed class CertificateBundleConverter : ICertificateBundleConverter
{
    public ConvertedCertificateBundle Convert(IssuedCertificateBundle bundle, string pfxPassword)
    {
        using var certificate = X509Certificate2.CreateFromPem(bundle.CertificatePem, bundle.PrivateKeyPem);
        var pfx = certificate.Export(X509ContentType.Pkcs12, pfxPassword);
        return new(pfx, bundle.CertificatePem, bundle.PrivateKeyPem, bundle.FullChainPem);
    }
}

public sealed class FakeCertificateDeployer : ICertificateDeployer
{
    public DeploymentTargetType TargetType => DeploymentTargetType.Fake;

    public Task<DeploymentValidationResult> ValidateTargetAsync(DeploymentTargetContext context, CancellationToken cancellationToken) =>
        Task.FromResult(Fails(context.Target, "validate") ? new(false, "Fake target validation failed.") : new DeploymentValidationResult(true));

    public Task<DeploymentPrecheckResult> PrecheckAsync(DeploymentContext context, CancellationToken cancellationToken) =>
        Task.FromResult(Fails(context.Target, "precheck") ? new(false, Message: "Fake precheck failed.") : new DeploymentPrecheckResult(true, Read(context.Target, "previousFingerprint")));

    public Task<DeploymentBackupResult> BackupAsync(DeploymentContext context, CancellationToken cancellationToken) =>
        Task.FromResult(Fails(context.Target, "backup") ? new(false, Message: "Fake backup failed.") : new DeploymentBackupResult(true, $"fake-backup:{context.Deployment.Id:D}"));

    public Task<DeploymentApplyResult> DeployAsync(DeploymentContext context, IssuedCertificateBundle bundle, CancellationToken cancellationToken) =>
        Task.FromResult(Fails(context.Target, "deploy") ? new(false, "Fake deployment failed.") : new DeploymentApplyResult(true));

    public Task<DeploymentActivationResult> ActivateAsync(DeploymentContext context, CancellationToken cancellationToken) =>
        Task.FromResult(Fails(context.Target, "activate") ? new(false, "Fake activation failed.") : new DeploymentActivationResult(true));

    public Task<DeploymentVerificationResult> VerifyAsync(DeploymentContext context, IssuedCertificateBundle bundle, CancellationToken cancellationToken) =>
        Task.FromResult(Fails(context.Target, "verify")
            ? new(false, Read(context.Target, "observedFingerprint"), "Fake verification failed.")
            : new DeploymentVerificationResult(true, Read(context.Target, "observedFingerprint") ?? bundle.Fingerprint));

    public Task<DeploymentRollbackResult> RollbackAsync(DeploymentContext context, DeploymentBackupResult backup, CancellationToken cancellationToken) =>
        Task.FromResult(Fails(context.Target, "rollback")
            ? new(false, Message: "Fake rollback failed.")
            : new DeploymentRollbackResult(true, context.Deployment.PreviousFingerprint));

    private static bool Fails(DeploymentTarget target, string stage) =>
        string.Equals(Read(target, "failStage"), stage, StringComparison.OrdinalIgnoreCase);

    private static string? Read(DeploymentTarget target, string property)
    {
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(target.ConfigurationJson) ? "{}" : target.ConfigurationJson);
        return document.RootElement.TryGetProperty(property, out var value) ? value.GetString() : null;
    }
}

public sealed class DeploymentQueue(CertificateDiscoveryDbContext db) : IDeploymentQueue
{
    public async Task EnqueueAsync(Guid deploymentId, string idempotencyKey, DateTime nextAttemptAtUtc, CancellationToken cancellationToken)
    {
        if (await db.DeploymentJobs.AnyAsync(x => x.IdempotencyKey == idempotencyKey, cancellationToken)) return;
        db.DeploymentJobs.Add(new DeploymentJob
        {
            CertificateDeploymentId = deploymentId,
            IdempotencyKey = idempotencyKey,
            NextAttemptAtUtc = nextAttemptAtUtc
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<DeploymentJob?> ClaimAsync(string owner, TimeSpan lease, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var candidate = await db.DeploymentJobs.AsNoTracking()
            .Where(x => (x.Status == DeploymentJobStatus.Pending ||
                         x.Status == DeploymentJobStatus.Claimed && x.LeaseExpiresAtUtc < now) &&
                        x.NextAttemptAtUtc <= now)
            .OrderBy(x => x.NextAttemptAtUtc).ThenBy(x => x.CreatedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);
        if (candidate is null) return null;
        var claimed = await db.DeploymentJobs
            .Where(x => x.Id == candidate.Id &&
                        (x.Status == DeploymentJobStatus.Pending ||
                         x.Status == DeploymentJobStatus.Claimed && x.LeaseExpiresAtUtc < now))
            .ExecuteUpdateAsync(update => update
                .SetProperty(x => x.Status, DeploymentJobStatus.Claimed)
                .SetProperty(x => x.ClaimOwner, owner)
                .SetProperty(x => x.LeaseExpiresAtUtc, now.Add(lease)), cancellationToken);
        return claimed == 1 ? await db.DeploymentJobs.AsNoTracking().FirstAsync(x => x.Id == candidate.Id, cancellationToken) : null;
    }

    public async Task CompleteAsync(Guid jobId, CancellationToken cancellationToken) =>
        _ = await db.DeploymentJobs.Where(x => x.Id == jobId).ExecuteUpdateAsync(update => update
            .SetProperty(x => x.Status, DeploymentJobStatus.Completed)
            .SetProperty(x => x.CompletedAtUtc, DateTime.UtcNow)
            .SetProperty(x => x.LeaseExpiresAtUtc, (DateTime?)null), cancellationToken);

    public async Task FailAsync(Guid jobId, string error, int maxAttempts, TimeSpan retryDelay, CancellationToken cancellationToken)
    {
        var job = await db.DeploymentJobs.FirstAsync(x => x.Id == jobId, cancellationToken);
        job.RetryCount++;
        job.LastError = Redact(error);
        job.ClaimOwner = null;
        job.LeaseExpiresAtUtc = null;
        job.Status = job.RetryCount >= maxAttempts ? DeploymentJobStatus.DeadLetter : DeploymentJobStatus.Pending;
        job.NextAttemptAtUtc = DateTime.UtcNow.Add(retryDelay);
        if (job.Status == DeploymentJobStatus.DeadLetter) job.CompletedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    private static string Redact(string value) => value.Length <= 2048 ? value : value[..2048];
}

public sealed class CertificateDeploymentOrchestrator(
    CertificateDiscoveryDbContext db,
    ICertificateDeployerResolver resolver,
    IDeploymentStateMachine stateMachine,
    IDeploymentQueue queue,
    ISecretProvider secrets,
    IDeploymentCertificateBundleSource bundleSource,
    IMultiNodeTlsVerifier multiNodeVerifier) : ICertificateDeploymentOrchestrator
{
    public CertificateDeploymentOrchestrator(
        CertificateDiscoveryDbContext db,
        ICertificateDeployerResolver resolver,
        IDeploymentStateMachine stateMachine,
        IDeploymentQueue queue,
        ISecretProvider secrets,
        IDeploymentCertificateBundleSource bundleSource)
        : this(db, resolver, stateMachine, queue, secrets, bundleSource, new TlsEndpointVerifier()) { }

    public async Task<Guid> CreateAsync(Guid requestId, Guid targetId, Guid policyId, string actor, DeploymentOrigin origin, CancellationToken cancellationToken)
    {
        var request = await db.AcmeCertificateRequests.Include(x => x.Certificate).FirstOrDefaultAsync(x => x.Id == requestId, cancellationToken)
            ?? throw new InvalidOperationException("Certificate request was not found.");
        if (request.CertificateId is null || request.Certificate is null || request.Status != CertificateRequestStatus.StoredInVault)
            throw new InvalidOperationException("Only a stored, issued certificate can be deployed.");
        var target = await db.DeploymentTargets.FindAsync([targetId], cancellationToken) ?? throw new InvalidOperationException("Deployment target was not found.");
        var policy = await db.DeploymentPolicies.FindAsync([policyId], cancellationToken) ?? throw new InvalidOperationException("Deployment policy was not found.");
        if (!target.IsEnabled || !policy.IsEnabled) throw new InvalidOperationException("Deployment target and policy must be enabled.");
        var key = $"{request.Id:N}:{request.CertificateId:N}:{target.Id:N}";
        var existing = await db.CertificateDeployments.FirstOrDefaultAsync(x => x.IdempotencyKey == key, cancellationToken);
        if (existing is not null) return existing.Id;
        var deployment = new CertificateDeployment
        {
            CertificateRequestId = request.Id,
            CertificateId = request.CertificateId.Value,
            DeploymentTargetId = target.Id,
            DeploymentPolicyId = policy.Id,
            ExpectedFingerprint = request.Certificate.FingerprintSha256,
            IdempotencyKey = key,
            Origin = origin,
            RequestedBy = actor,
            Status = policy.RequireApproval ? CertificateDeploymentStatus.AwaitingApproval : CertificateDeploymentStatus.Pending
        };
        db.CertificateDeployments.Add(deployment);
        Audit(deployment, policy.RequireApproval ? "AwaitingApproval" : "Created", actor, "Deployment was created.");
        await db.SaveChangesAsync(cancellationToken);
        if (!policy.RequireApproval) await queue.EnqueueAsync(deployment.Id, $"{key}:attempt:0", DateTime.UtcNow, cancellationToken);
        return deployment.Id;
    }

    public async Task ApproveAsync(Guid deploymentId, string actor, CancellationToken cancellationToken)
    {
        var deployment = await LoadAsync(deploymentId, cancellationToken);
        stateMachine.Transition(deployment, CertificateDeploymentStatus.Pending);
        deployment.ApprovedBy = actor;
        deployment.ApprovedAtUtc = DateTime.UtcNow;
        Audit(deployment, "Approved", actor, "Deployment was approved.");
        await db.SaveChangesAsync(cancellationToken);
        await queue.EnqueueAsync(deployment.Id, $"{deployment.IdempotencyKey}:attempt:{deployment.Attempt}", DateTime.UtcNow, cancellationToken);
    }

    public async Task RejectAsync(Guid deploymentId, string actor, CancellationToken cancellationToken)
    {
        var deployment = await LoadAsync(deploymentId, cancellationToken);
        stateMachine.Transition(deployment, CertificateDeploymentStatus.Rejected);
        deployment.CompletedAtUtc = DateTime.UtcNow;
        Audit(deployment, "Rejected", actor, "Deployment was rejected.");
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task CancelAsync(Guid deploymentId, string actor, CancellationToken cancellationToken)
    {
        var deployment = await LoadAsync(deploymentId, cancellationToken);
        stateMachine.Transition(deployment, CertificateDeploymentStatus.Cancelled);
        deployment.CompletedAtUtc = DateTime.UtcNow;
        Audit(deployment, "Cancelled", actor, "Deployment was cancelled.");
        await db.DeploymentJobs.Where(x => x.CertificateDeploymentId == deploymentId && x.Status != DeploymentJobStatus.Completed)
            .ExecuteUpdateAsync(x => x.SetProperty(j => j.Status, DeploymentJobStatus.Cancelled), cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task ExecuteAsync(Guid deploymentId, string actor, CancellationToken cancellationToken)
    {
        var deployment = await LoadAsync(deploymentId, cancellationToken);
        if (deployment.Status != CertificateDeploymentStatus.Pending) return;
        var deployer = resolver.Resolve(deployment.DeploymentTarget.TargetType);
        var secret = string.IsNullOrWhiteSpace(deployment.DeploymentTarget.SecretReference) ? null : await secrets.GetAsync(deployment.DeploymentTarget.SecretReference, cancellationToken);
        var context = new DeploymentContext(deployment, deployment.DeploymentTarget, deployment.DeploymentPolicy, secret);
        var bundle = await bundleSource.LoadAsync(deployment, cancellationToken);
        var backup = new DeploymentBackupResult(false);
        deployment.Attempt++;
        deployment.StartedAtUtc ??= DateTime.UtcNow;
        try
        {
            var validation = await deployer.ValidateTargetAsync(new(deployment.DeploymentTarget, secret), cancellationToken);
            Ensure(validation.IsValid, "TargetValidationFailed", validation.Message);
            await MoveAsync(deployment, CertificateDeploymentStatus.Prechecking, actor, cancellationToken);
            var precheck = await deployer.PrecheckAsync(context, cancellationToken);
            Ensure(precheck.IsReady, "PrecheckFailed", precheck.Message);
            deployment.PreviousFingerprint = precheck.PreviousFingerprint;
            await MoveAsync(deployment, CertificateDeploymentStatus.BackingUp, actor, cancellationToken);
            backup = await deployer.BackupAsync(context, cancellationToken);
            Ensure(backup.Succeeded, "BackupFailed", backup.Message);
            deployment.BackupReference = backup.BackupReference;
            await MoveAsync(deployment, CertificateDeploymentStatus.Deploying, actor, cancellationToken);
            var applied = await deployer.DeployAsync(context, bundle, cancellationToken);
            Ensure(applied.Succeeded, "DeployFailed", applied.Message);
            if (applied.PendingExternalCompletion)
            {
                Audit(deployment, "AgentJobQueued", actor, applied.Message ?? "Deployment was handed to an external agent.");
                await db.SaveChangesAsync(cancellationToken);
                return;
            }
            await MoveAsync(deployment, CertificateDeploymentStatus.Activating, actor, cancellationToken);
            var activation = await deployer.ActivateAsync(context, cancellationToken);
            Ensure(activation.Succeeded, "ActivationFailed", activation.Message);
            await MoveAsync(deployment, CertificateDeploymentStatus.Verifying, actor, cancellationToken);
            using var verificationTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            verificationTimeout.CancelAfter(TimeSpan.FromSeconds(deployment.DeploymentPolicy.VerificationTimeoutSeconds));
            var verification = await deployer.VerifyAsync(context, bundle, verificationTimeout.Token);
            deployment.ObservedFingerprint = verification.ObservedFingerprint;
            deployment.InternalVerificationStatus = verification.Message ?? (verification.Succeeded ? "Verified" : "Failed");
            Ensure(verification.Succeeded && string.Equals(verification.ObservedFingerprint, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase),
                "VerificationFailed", verification.Message ?? "Observed fingerprint does not match the expected certificate.");
            var endpoints = DeploymentVerificationEndpoints.Parse(deployment.DeploymentTarget);
            if (endpoints.Count > 0)
            {
                var started = DateTime.UtcNow;
                var external = await multiNodeVerifier.VerifyAsync(
                    endpoints, bundle.Fingerprint, deployment.DeploymentPolicy, verificationTimeout.Token);
                var run = new DeploymentVerificationRun
                {
                    CertificateDeploymentId = deployment.Id,
                    Attempt = deployment.Attempt,
                    QuorumMode = deployment.DeploymentPolicy.VerificationQuorumMode,
                    QuorumPercentage = deployment.DeploymentPolicy.VerificationQuorumPercentage,
                    MinimumSuccessfulNodes = deployment.DeploymentPolicy.VerificationMinimumSuccessfulNodes,
                    TotalNodes = external.Quorum.TotalNodes,
                    SuccessfulNodes = external.Quorum.SuccessfulNodes,
                    FailedNodes = external.Quorum.TotalNodes - external.Quorum.SuccessfulNodes,
                    DistinctFingerprints = external.Quorum.DistinctFingerprints,
                    Outcome = external.Quorum.Outcome,
                    Summary = external.Quorum.Message,
                    StartedAtUtc = started,
                    CompletedAtUtc = DateTime.UtcNow,
                    DurationMilliseconds = (long)(DateTime.UtcNow - started).TotalMilliseconds,
                    Endpoints = external.Endpoints.ToList()
                };
                db.DeploymentVerificationRuns.Add(run);
                deployment.ExternalVerificationStatus = external.Quorum.Message;
                deployment.VerificationStatus = $"Internal: {deployment.InternalVerificationStatus} External: {external.Quorum.Message}";
                deployment.ObservedFingerprint = external.Endpoints.LastOrDefault()?.ObservedFingerprint;
                await db.SaveChangesAsync(cancellationToken);
                if (external.Quorum.Outcome == DeploymentVerificationOutcome.PartiallyVerified &&
                    !deployment.DeploymentPolicy.RollbackOnPartialVerification)
                {
                    stateMachine.Transition(deployment, CertificateDeploymentStatus.PartiallyVerified);
                    deployment.CompletedAtUtc = DateTime.UtcNow;
                    Audit(deployment, "PartiallyVerified", actor, external.Quorum.Message);
                    await db.SaveChangesAsync(cancellationToken);
                    return;
                }
                Ensure(external.Quorum.Outcome == DeploymentVerificationOutcome.Verified,
                    external.Quorum.Outcome == DeploymentVerificationOutcome.PartiallyVerified
                        ? "PartialRolloutDetected"
                        : "VerificationQuorumFailed",
                    external.Quorum.Message);
            }
            else
            {
                deployment.ExternalVerificationStatus = "No external verification endpoints configured.";
                deployment.VerificationStatus = deployment.InternalVerificationStatus;
            }
            stateMachine.Transition(deployment, CertificateDeploymentStatus.Succeeded);
            deployment.CompletedAtUtc = DateTime.UtcNow;
            deployment.ErrorCode = deployment.ErrorMessage = null;
            Audit(deployment, "Succeeded", actor, "Deployment and verification succeeded.");
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            deployment.ErrorCode = ex is DeploymentStageException stage ? stage.Code : "UnhandledError";
            deployment.ErrorMessage = SafeMessage(ex.Message, secret);
            if (deployment.DeploymentPolicy.RollbackOnFailure && backup.Succeeded)
                await RollbackCoreAsync(deployment, deployer, context, backup, actor, cancellationToken);
            else
            {
                stateMachine.Transition(deployment, CertificateDeploymentStatus.Failed);
                deployment.CompletedAtUtc = DateTime.UtcNow;
                Audit(deployment, "Failed", actor, deployment.ErrorMessage);
                await db.SaveChangesAsync(cancellationToken);
            }
            throw new InvalidOperationException(deployment.ErrorMessage, ex);
        }
    }

    public async Task RollbackAsync(Guid deploymentId, string actor, CancellationToken cancellationToken)
    {
        var deployment = await LoadAsync(deploymentId, cancellationToken);
        if (string.IsNullOrWhiteSpace(deployment.BackupReference)) throw new InvalidOperationException("Deployment has no backup reference.");
        var deployer = resolver.Resolve(deployment.DeploymentTarget.TargetType);
        var secret = string.IsNullOrWhiteSpace(deployment.DeploymentTarget.SecretReference) ? null : await secrets.GetAsync(deployment.DeploymentTarget.SecretReference, cancellationToken);
        await RollbackCoreAsync(deployment, deployer, new(deployment, deployment.DeploymentTarget, deployment.DeploymentPolicy, secret),
            new(true, deployment.BackupReference), actor, cancellationToken);
    }

    private async Task RollbackCoreAsync(CertificateDeployment deployment, ICertificateDeployer deployer, DeploymentContext context, DeploymentBackupResult backup, string actor, CancellationToken cancellationToken)
    {
        stateMachine.Transition(deployment, CertificateDeploymentStatus.RollingBack);
        Audit(deployment, "RollingBack", actor, "Rollback started.");
        await db.SaveChangesAsync(cancellationToken);
        var result = await deployer.RollbackAsync(context, backup, cancellationToken);
        var rollbackFingerprint = result.ObservedFingerprint ?? deployment.PreviousFingerprint;
        var endpoints = DeploymentVerificationEndpoints.Parse(deployment.DeploymentTarget);
        if (result.Succeeded && !string.IsNullOrWhiteSpace(rollbackFingerprint) && endpoints.Count > 0)
        {
            var started = DateTime.UtcNow;
            var external = await multiNodeVerifier.VerifyAsync(
                endpoints, rollbackFingerprint, deployment.DeploymentPolicy, cancellationToken);
            db.DeploymentVerificationRuns.Add(new DeploymentVerificationRun
            {
                CertificateDeploymentId = deployment.Id,
                Attempt = deployment.Attempt,
                IsRollbackVerification = true,
                QuorumMode = deployment.DeploymentPolicy.VerificationQuorumMode,
                QuorumPercentage = deployment.DeploymentPolicy.VerificationQuorumPercentage,
                MinimumSuccessfulNodes = deployment.DeploymentPolicy.VerificationMinimumSuccessfulNodes,
                TotalNodes = external.Quorum.TotalNodes,
                SuccessfulNodes = external.Quorum.SuccessfulNodes,
                FailedNodes = external.Quorum.TotalNodes - external.Quorum.SuccessfulNodes,
                DistinctFingerprints = external.Quorum.DistinctFingerprints,
                Outcome = external.Quorum.Outcome,
                Summary = external.Quorum.Message,
                StartedAtUtc = started,
                CompletedAtUtc = DateTime.UtcNow,
                DurationMilliseconds = (long)(DateTime.UtcNow - started).TotalMilliseconds,
                Endpoints = external.Endpoints.ToList()
            });
            if (external.Quorum.Outcome != DeploymentVerificationOutcome.Verified)
                result = result with
                {
                    Succeeded = false,
                    ObservedFingerprint = external.Endpoints.LastOrDefault()?.ObservedFingerprint,
                    Message = $"Rollback target changed, but external verification failed: {external.Quorum.Message}"
                };
        }
        stateMachine.Transition(deployment, result.Succeeded ? CertificateDeploymentStatus.RolledBack : CertificateDeploymentStatus.RollbackFailed);
        deployment.RollbackStatus = result.Message ?? deployment.Status.ToString();
        deployment.ObservedFingerprint = result.ObservedFingerprint;
        deployment.CompletedAtUtc = DateTime.UtcNow;
        Audit(deployment, deployment.Status.ToString(), actor, deployment.RollbackStatus);
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task<CertificateDeployment> LoadAsync(Guid id, CancellationToken cancellationToken) =>
        await db.CertificateDeployments.Include(x => x.DeploymentTarget).Include(x => x.DeploymentPolicy)
            .Include(x => x.CertificateRequest).ThenInclude(x => x.VaultServer).Include(x => x.Certificate)
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
        ?? throw new InvalidOperationException("Certificate deployment was not found.");

    private async Task MoveAsync(CertificateDeployment deployment, CertificateDeploymentStatus status, string actor, CancellationToken cancellationToken)
    {
        stateMachine.Transition(deployment, status);
        Audit(deployment, status.ToString(), actor, $"Deployment entered {status}.");
        await db.SaveChangesAsync(cancellationToken);
    }

    private void Audit(CertificateDeployment deployment, string type, string actor, string? message) =>
        db.DeploymentAuditEvents.Add(new DeploymentAuditEvent
        {
            CertificateDeploymentId = deployment.Id, EventType = type, Actor = actor,
            Message = SafeMessage(message), Status = deployment.Status,
            CertificateFingerprint = deployment.ExpectedFingerprint,
            DurationMilliseconds = deployment.StartedAtUtc is null ? null : (long)(DateTime.UtcNow - deployment.StartedAtUtc.Value).TotalMilliseconds
        });

    private static void Ensure(bool condition, string code, string? message = null)
    {
        if (!condition) throw new DeploymentStageException(code, message ?? code);
    }

    private static string? SafeMessage(string? value, string? secret = null)
    {
        if (value is null) return null;
        var safe = !string.IsNullOrWhiteSpace(secret) ? value.Replace(secret, "[REDACTED]", StringComparison.Ordinal) : value;
        return safe[..Math.Min(safe.Length, 2048)];
    }
    private sealed class DeploymentStageException(string code, string message) : InvalidOperationException(message) { public string Code { get; } = code; }
}
