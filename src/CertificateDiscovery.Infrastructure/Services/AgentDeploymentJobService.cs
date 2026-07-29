using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Services;

public sealed class AgentDeploymentJobService(
    CertificateDiscoveryDbContext db,
    DeploymentAgentService agents,
    IDeploymentStateMachine stateMachine,
    ICertificateBundleConverter bundleConverter,
    IDeploymentCertificateBundleSource bundleSource)
{
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(2);

    public async Task<Guid> QueueAsync(
        DeploymentContext context,
        Guid agentId,
        CancellationToken cancellationToken)
    {
        var existing = await db.AgentDeploymentJobs.AsNoTracking()
            .FirstOrDefaultAsync(x => x.CertificateDeploymentId == context.Deployment.Id, cancellationToken);
        if (existing is not null) return existing.Id;
        var agent = await db.DeploymentAgents.AsNoTracking().FirstOrDefaultAsync(x => x.Id == agentId, cancellationToken)
            ?? throw new InvalidOperationException("Microsoft IIS deployment agent was not found.");
        if (agent.Status is not (DeploymentAgentStatus.Online or DeploymentAgentStatus.Busy) ||
            agent.LastHeartbeatAtUtc < DateTime.UtcNow.AddMinutes(-2))
            throw new InvalidOperationException("Microsoft IIS deployment agent is not available.");
        if (string.IsNullOrWhiteSpace(agent.PublicKeyPem))
            throw new InvalidOperationException("Microsoft IIS deployment agent has no bundle-encryption public key.");

        var job = new AgentDeploymentJob
        {
            DeploymentAgentId = agentId,
            CertificateDeploymentId = context.Deployment.Id,
            TargetConfigurationJson = context.Target.ConfigurationJson
        };
        db.AgentDeploymentJobs.Add(job);
        await db.SaveChangesAsync(cancellationToken);
        return job.Id;
    }

    public async Task<AgentJobClaimResponse?> ClaimAsync(
        Guid agentId,
        string? agentToken,
        CancellationToken cancellationToken)
    {
        _ = await agents.AuthenticateAsync(agentId, agentToken, cancellationToken);
        var now = DateTime.UtcNow;
        var candidate = await db.AgentDeploymentJobs.AsNoTracking()
            .Where(x => x.DeploymentAgentId == agentId &&
                        (x.Status == AgentDeploymentJobStatus.Pending ||
                         x.Status == AgentDeploymentJobStatus.Claimed && x.LeaseExpiresAtUtc < now))
            .OrderBy(x => x.CreatedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);
        if (candidate is null) return null;

        var leaseToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        var expires = now.Add(LeaseDuration);
        var claimed = await db.AgentDeploymentJobs
            .Where(x => x.Id == candidate.Id && x.DeploymentAgentId == agentId &&
                        (x.Status == AgentDeploymentJobStatus.Pending ||
                         x.Status == AgentDeploymentJobStatus.Claimed && x.LeaseExpiresAtUtc < now))
            .ExecuteUpdateAsync(update => update
                .SetProperty(x => x.Status, AgentDeploymentJobStatus.Claimed)
                .SetProperty(x => x.LeaseTokenHash, Hash(leaseToken))
                .SetProperty(x => x.LeaseExpiresAtUtc, expires)
                .SetProperty(x => x.ClaimedAtUtc, now)
                .SetProperty(x => x.UpdatedAtUtc, now)
                .SetProperty(x => x.Attempt, x => x.Attempt + 1), cancellationToken);
        return claimed == 1
            ? new(candidate.Id, leaseToken, expires, candidate.TargetConfigurationJson)
            : null;
    }

    public async Task RenewLeaseAsync(
        Guid agentId,
        Guid jobId,
        string? agentToken,
        string leaseToken,
        CancellationToken cancellationToken)
    {
        _ = await agents.AuthenticateAsync(agentId, agentToken, cancellationToken);
        var job = await LoadLeasedAsync(agentId, jobId, leaseToken, cancellationToken);
        job.LeaseExpiresAtUtc = DateTime.UtcNow.Add(LeaseDuration);
        job.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<AgentJobBundleResponse> GetBundleAsync(
        Guid agentId,
        Guid jobId,
        string? agentToken,
        string leaseToken,
        CancellationToken cancellationToken)
    {
        _ = await agents.AuthenticateAsync(agentId, agentToken, cancellationToken);
        var job = await LoadLeasedAsync(agentId, jobId, leaseToken, cancellationToken);
        await db.Entry(job).Reference(x => x.DeploymentAgent).LoadAsync(cancellationToken);
        await db.Entry(job).Reference(x => x.CertificateDeployment).LoadAsync(cancellationToken);
        await db.Entry(job.CertificateDeployment).Reference(x => x.CertificateRequest).LoadAsync(cancellationToken);
        await db.Entry(job.CertificateDeployment.CertificateRequest).Reference(x => x.VaultServer).LoadAsync(cancellationToken);
        var publicKey = job.DeploymentAgent.PublicKeyPem
            ?? throw new InvalidOperationException("Microsoft IIS deployment agent has no bundle-encryption public key.");
        var bundle = await bundleSource.LoadAsync(job.CertificateDeployment, cancellationToken);
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var converted = bundleConverter.Convert(bundle, password);
        var clearPayload = JsonSerializer.SerializeToUtf8Bytes(new AgentCertificateBundle(
            Convert.ToBase64String(converted.Pfx), password, bundle.Fingerprint));
        try
        {
            return new(job.Id, Encrypt(clearPayload, publicKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearPayload);
        }
    }

    public async Task RecordStageAsync(
        Guid agentId,
        Guid jobId,
        string? agentToken,
        AgentJobStageResultRequest request,
        CancellationToken cancellationToken)
    {
        _ = await agents.AuthenticateAsync(agentId, agentToken, cancellationToken);
        var job = await LoadLeasedAsync(agentId, jobId, request.LeaseToken, cancellationToken);
        job.Stage = Safe(request.Stage, 80);
        job.UpdatedAtUtc = DateTime.UtcNow;
        if (!string.IsNullOrWhiteSpace(request.Message))
            AddAudit(job.CertificateDeploymentId, "AgentStage", job.Stage, request.Message);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task CompleteAsync(
        Guid agentId,
        Guid jobId,
        string? agentToken,
        AgentJobCompleteRequest request,
        CancellationToken cancellationToken)
    {
        _ = await agents.AuthenticateAsync(agentId, agentToken, cancellationToken);
        await ReloadTrackedJobAsync(jobId, cancellationToken);
        var job = await db.AgentDeploymentJobs.Include(x => x.CertificateDeployment)
            .FirstOrDefaultAsync(x => x.Id == jobId && x.DeploymentAgentId == agentId, cancellationToken)
            ?? throw new KeyNotFoundException("Agent deployment job was not found.");
        ValidateLease(job, request.LeaseToken);
        var deployment = job.CertificateDeployment;
        job.ObservedFingerprint = Normalize(request.ObservedFingerprint, 128);
        job.PreviousFingerprint = Normalize(request.PreviousFingerprint, 128);
        job.ErrorCode = Normalize(request.ErrorCode, 120);
        job.ErrorMessage = Normalize(request.ErrorMessage, 2048);
        job.CompletedAtUtc = DateTime.UtcNow;
        job.UpdatedAtUtc = DateTime.UtcNow;
        job.LeaseExpiresAtUtc = null;
        job.LeaseTokenHash = null;
        deployment.ObservedFingerprint = job.ObservedFingerprint;
        deployment.PreviousFingerprint = job.PreviousFingerprint;
        deployment.CompletedAtUtc = DateTime.UtcNow;

        if (request.Succeeded &&
            string.Equals(deployment.ExpectedFingerprint, request.ObservedFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            stateMachine.Transition(deployment, CertificateDeploymentStatus.Activating);
            stateMachine.Transition(deployment, CertificateDeploymentStatus.Verifying);
            stateMachine.Transition(deployment, CertificateDeploymentStatus.Succeeded);
            deployment.VerificationStatus = "Verified by Microsoft IIS agent.";
            job.Status = AgentDeploymentJobStatus.Completed;
            AddAudit(deployment.Id, "AgentDeploymentSucceeded", "Completed", "Microsoft IIS agent deployment succeeded.");
        }
        else if (request.RolledBack)
        {
            stateMachine.Transition(deployment, CertificateDeploymentStatus.RollingBack);
            stateMachine.Transition(deployment, CertificateDeploymentStatus.RolledBack);
            deployment.RollbackStatus = "Rolled back by Microsoft IIS agent.";
            deployment.ErrorCode = job.ErrorCode ?? "AgentDeploymentFailed";
            deployment.ErrorMessage = job.ErrorMessage;
            job.Status = AgentDeploymentJobStatus.RolledBack;
            AddAudit(deployment.Id, "AgentDeploymentRolledBack", "RolledBack", job.ErrorMessage);
        }
        else
        {
            stateMachine.Transition(deployment, CertificateDeploymentStatus.Failed);
            deployment.ErrorCode = job.ErrorCode ?? "AgentDeploymentFailed";
            deployment.ErrorMessage = job.ErrorMessage ?? "Microsoft IIS agent deployment failed.";
            job.Status = AgentDeploymentJobStatus.Failed;
            AddAudit(deployment.Id, "AgentDeploymentFailed", "Failed", deployment.ErrorMessage);
        }
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task<AgentDeploymentJob> LoadLeasedAsync(
        Guid agentId,
        Guid jobId,
        string leaseToken,
        CancellationToken cancellationToken)
    {
        await ReloadTrackedJobAsync(jobId, cancellationToken);
        var job = await db.AgentDeploymentJobs.FirstOrDefaultAsync(
            x => x.Id == jobId && x.DeploymentAgentId == agentId,
            cancellationToken) ?? throw new KeyNotFoundException("Agent deployment job was not found.");
        ValidateLease(job, leaseToken);
        return job;
    }

    private async Task ReloadTrackedJobAsync(Guid jobId, CancellationToken cancellationToken)
    {
        var tracked = db.AgentDeploymentJobs.Local.FirstOrDefault(x => x.Id == jobId);
        if (tracked is not null)
            await db.Entry(tracked).ReloadAsync(cancellationToken);
    }

    private static void ValidateLease(AgentDeploymentJob job, string leaseToken)
    {
        if (job.Status != AgentDeploymentJobStatus.Claimed ||
            job.LeaseExpiresAtUtc is null ||
            job.LeaseExpiresAtUtc <= DateTime.UtcNow ||
            string.IsNullOrWhiteSpace(job.LeaseTokenHash) ||
            !FixedHashEquals(job.LeaseTokenHash, Hash(leaseToken)))
            throw new UnauthorizedAccessException("Agent deployment job lease is invalid or expired.");
    }

    private void AddAudit(Guid deploymentId, string eventType, string? stage, string? message) =>
        db.DeploymentAuditEvents.Add(new()
        {
            CertificateDeploymentId = deploymentId,
            EventType = eventType,
            Actor = "winDeployAgent",
            Message = Safe($"{stage}: {message}", 2048),
            Status = db.CertificateDeployments.Local.FirstOrDefault(x => x.Id == deploymentId)?.Status
                     ?? CertificateDeploymentStatus.Deploying
        });

    private static string Encrypt(byte[] clearPayload, string publicKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[clearPayload.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, clearPayload, ciphertext, tag);
            var envelope = new AgentBundleEnvelope(
                Convert.ToBase64String(rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256)),
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(ciphertext),
                Convert.ToBase64String(tag));
            return JsonSerializer.Serialize(envelope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static bool FixedHashEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string Safe(string? value, int length) => string.IsNullOrWhiteSpace(value) ? string.Empty : value[..Math.Min(value.Length, length)];
    private static string? Normalize(string? value, int length) => string.IsNullOrWhiteSpace(value) ? null : Safe(value.Trim(), length);

    private sealed record AgentCertificateBundle(string PfxBase64, string Password, string Fingerprint);
    private sealed record AgentBundleEnvelope(string EncryptedKey, string Nonce, string Ciphertext, string Tag);
}
