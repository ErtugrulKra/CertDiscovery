using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class IisAgentCertificateDeployer(
    CertificateDiscoveryDbContext db,
    AgentDeploymentJobService jobs) : ICertificateDeployer
{
    public DeploymentTargetType TargetType => DeploymentTargetType.Iis;

    public async Task<DeploymentValidationResult> ValidateTargetAsync(
        DeploymentTargetContext context,
        CancellationToken cancellationToken)
    {
        if (context.Target.DeploymentAgentId is not Guid agentId || agentId == Guid.Empty)
            return new(false, "Microsoft IIS target is not assigned to a registered deployment agent.");
        var agent = await db.DeploymentAgents.AsNoTracking().FirstOrDefaultAsync(x => x.Id == agentId, cancellationToken);
        if (agent is null) return new(false, "Microsoft IIS deployment agent was not found.");
        if (agent.Status is not (DeploymentAgentStatus.Online or DeploymentAgentStatus.Busy) ||
            agent.LastHeartbeatAtUtc < DateTime.UtcNow.AddMinutes(-2))
            return new(false, "Microsoft IIS deployment agent is not available.");
        if (!SupportsMicrosoftIis(agent))
            return new(false, "The selected deployment agent does not support Microsoft IIS.");
        if (string.IsNullOrWhiteSpace(agent.PublicKeyPem))
            return new(false, "Microsoft IIS deployment agent has no encryption public key.");
        return new(true);
    }

    public Task<DeploymentPrecheckResult> PrecheckAsync(DeploymentContext context, CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentPrecheckResult(true, Message: "Precheck will run on the Microsoft IIS agent."));
    public Task<DeploymentBackupResult> BackupAsync(DeploymentContext context, CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentBackupResult(true, $"agent-managed:{context.Deployment.Id:D}", "Backup will run on the Microsoft IIS agent."));

    public async Task<DeploymentApplyResult> DeployAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        if (context.Target.DeploymentAgentId is not Guid agentId || agentId == Guid.Empty)
            return new(false, "Microsoft IIS target is not assigned to a registered deployment agent.");
        var jobId = await jobs.QueueAsync(context, agentId, cancellationToken);
        return new(true, $"Microsoft IIS agent job {jobId:D} was queued.", PendingExternalCompletion: true);
    }

    public Task<DeploymentActivationResult> ActivateAsync(DeploymentContext context, CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentActivationResult(false, "Activation is performed by the Microsoft IIS agent."));
    public Task<DeploymentVerificationResult> VerifyAsync(DeploymentContext context, IssuedCertificateBundle bundle, CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentVerificationResult(false, Message: "Verification is performed by the Microsoft IIS agent."));
    public Task<DeploymentRollbackResult> RollbackAsync(DeploymentContext context, DeploymentBackupResult backup, CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentRollbackResult(false, Message: "Rollback must be requested through the Microsoft IIS agent job."));

    private static bool SupportsMicrosoftIis(DeploymentAgent agent)
    {
        if (!string.Equals(agent.AgentType, "MicrosoftIis", StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            var capabilities = System.Text.Json.JsonSerializer.Deserialize<string[]>(agent.CapabilitiesJson) ?? [];
            return capabilities.Contains("MicrosoftIis", StringComparer.OrdinalIgnoreCase);
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }
    }
}
