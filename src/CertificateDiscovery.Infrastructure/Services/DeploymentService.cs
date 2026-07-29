using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Services;

public sealed class DeploymentService(
    CertificateDiscoveryDbContext db,
    ISecretProvider secrets,
    ICertificateDeployerResolver resolver,
    ICertificateDeploymentOrchestrator orchestrator,
    IDeploymentQueue queue)
{
    public async Task<DeploymentIndexDto> GetIndexAsync(CancellationToken cancellationToken) => new(
        await db.DeploymentTargets.AsNoTracking().Include(x => x.DeploymentAgent).OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken),
        await db.DeploymentPolicies.AsNoTracking().OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken),
        await DeploymentQuery().OrderByDescending(x => x.CreatedAtUtc).Select(x => ToDto(x)).ToListAsync(cancellationToken));

    public async Task<DeploymentDetailDto?> GetAsync(Guid id, CancellationToken cancellationToken)
    {
        var item = await DeploymentQuery().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (item is null) return null;
        var events = await db.DeploymentAuditEvents.AsNoTracking().Where(x => x.CertificateDeploymentId == id)
            .OrderBy(x => x.CreatedAtUtc).Select(x => new DeploymentAuditEventDto(x.EventType, x.Actor, x.Message, x.Status, x.CreatedAtUtc, x.DurationMilliseconds))
            .ToListAsync(cancellationToken);
        return new(ToDto(item), events);
    }

    public async Task CreateTargetAsync(DeploymentTargetUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateTargetConfiguration(request);
        await ValidateDeploymentAgentAsync(request, cancellationToken);
        var target = new DeploymentTarget
        {
            Name = request.Name.Trim(), TargetType = request.TargetType, AssetId = request.AssetId,
            DeploymentAgentId = request.TargetType == DeploymentTargetType.Iis ? request.DeploymentAgentId : null,
            ConfigurationJson = NormalizeTargetJson(request), IsEnabled = request.IsEnabled
        };
        if (!string.IsNullOrWhiteSpace(request.Secret))
            target.SecretReference = await secrets.StoreAsync($"deployment-target:{target.Id:D}", request.Secret, cancellationToken);
        db.DeploymentTargets.Add(target);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<DeploymentTargetUpsertRequest?> GetTargetAsync(Guid id, CancellationToken cancellationToken)
    {
        var target = await db.DeploymentTargets.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return target is null ? null : new(target.Name, target.TargetType, target.AssetId, target.ConfigurationJson, null, target.IsEnabled, target.DeploymentAgentId);
    }

    public async Task<bool> UpdateTargetAsync(Guid id, DeploymentTargetUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateTargetConfiguration(request);
        await ValidateDeploymentAgentAsync(request, cancellationToken);
        var target = await db.DeploymentTargets.FindAsync([id], cancellationToken);
        if (target is null) return false;
        target.Name = request.Name.Trim(); target.TargetType = request.TargetType; target.AssetId = request.AssetId;
        target.DeploymentAgentId = request.TargetType == DeploymentTargetType.Iis ? request.DeploymentAgentId : null;
        target.ConfigurationJson = NormalizeTargetJson(request); target.IsEnabled = request.IsEnabled; target.UpdatedAtUtc = DateTime.UtcNow;
        if (!string.IsNullOrWhiteSpace(request.Secret))
        {
            var old = target.SecretReference;
            target.SecretReference = await secrets.StoreAsync($"deployment-target:{target.Id:D}", request.Secret, cancellationToken);
            if (!string.IsNullOrWhiteSpace(old)) await secrets.DeleteAsync(old, cancellationToken);
        }
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<IReadOnlyList<DeploymentAgentOptionDto>> GetMicrosoftIisAgentOptionsAsync(
        Guid? includeAgentId,
        CancellationToken cancellationToken)
    {
        var agents = await db.DeploymentAgents.AsNoTracking()
            .Where(x => x.AgentType == "MicrosoftIis" || x.Id == includeAgentId)
            .OrderBy(x => x.MachineName).ThenBy(x => x.Name)
            .ToListAsync(cancellationToken);
        return agents
            .Where(x => HasMicrosoftIisCapability(x) || x.Id == includeAgentId)
            .Select(x => new DeploymentAgentOptionDto(
                x.Id, x.Name, x.MachineName, EffectiveAgentStatus(x), IsAgentSelectable(x)))
            .ToList();
    }

    public async Task TestTargetAsync(Guid id, CancellationToken cancellationToken)
    {
        var target = await db.DeploymentTargets.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
            ?? throw new InvalidOperationException("Deployment target was not found.");
        var secret = string.IsNullOrWhiteSpace(target.SecretReference) ? null : await secrets.GetAsync(target.SecretReference, cancellationToken);
        var result = await resolver.Resolve(target.TargetType).ValidateTargetAsync(new(target, secret), cancellationToken);
        if (!result.IsValid) throw new InvalidOperationException(result.Message ?? "Target validation failed.");
    }

    public async Task CreatePolicyAsync(DeploymentPolicyUpsertRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Name)) throw new ArgumentException("Policy name is required.");
        if (request.MaxAttempts is < 1 or > 20) throw new ArgumentException("Max attempts must be between 1 and 20.");
        db.DeploymentPolicies.Add(new DeploymentPolicy
        {
            Name = request.Name.Trim(), RequireApproval = request.RequireApproval, AutomaticDeployment = request.AutomaticDeployment,
            MaxAttempts = request.MaxAttempts, RetryDelaySeconds = request.RetryDelaySeconds,
            RollbackOnFailure = request.RollbackOnFailure, VerificationTimeoutSeconds = request.VerificationTimeoutSeconds,
            DeploymentWindow = Normalize(request.DeploymentWindow), IsEnabled = request.IsEnabled
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    public Task<Guid> CreateDeploymentAsync(DeploymentCreateRequest request, string actor, CancellationToken cancellationToken) =>
        orchestrator.CreateAsync(request.CertificateRequestId, request.DeploymentTargetId, request.DeploymentPolicyId, actor, DeploymentOrigin.Manual, cancellationToken);

    public async Task<DeploymentCreateOptionsDto> GetDeploymentCreateOptionsAsync(CancellationToken cancellationToken) => new(
        await db.AcmeCertificateRequests.AsNoTracking()
            .Where(x => x.Status == CertificateRequestStatus.StoredInVault && x.CertificateId != null)
            .OrderBy(x => x.Domain)
            .Select(x => new DeploymentCertificateOptionDto(
                x.Id,
                x.Domain,
                x.VaultSecretPath,
                x.Certificate!.FingerprintSha256,
                x.StoredAtUtc))
            .ToListAsync(cancellationToken),
        await db.DeploymentTargets.AsNoTracking()
            .Where(x => x.IsEnabled)
            .OrderBy(x => x.Name)
            .Select(x => new DeploymentTargetOptionDto(
                x.Id,
                x.Name,
                x.TargetType,
                x.DeploymentAgent == null ? null : $"{x.DeploymentAgent.Name} ({x.DeploymentAgent.MachineName})"))
            .ToListAsync(cancellationToken),
        await db.DeploymentPolicies.AsNoTracking()
            .Where(x => x.IsEnabled)
            .OrderBy(x => x.Name)
            .Select(x => new DeploymentPolicyOptionDto(
                x.Id,
                x.Name,
                x.RequireApproval,
                x.AutomaticDeployment,
                x.RollbackOnFailure))
            .ToListAsync(cancellationToken));
    public Task ApproveAsync(Guid id, string actor, CancellationToken token) => orchestrator.ApproveAsync(id, actor, token);
    public Task RejectAsync(Guid id, string actor, CancellationToken token) => orchestrator.RejectAsync(id, actor, token);
    public Task CancelAsync(Guid id, string actor, CancellationToken token) => orchestrator.CancelAsync(id, actor, token);
    public Task RollbackAsync(Guid id, string actor, CancellationToken token) => orchestrator.RollbackAsync(id, actor, token);

    public async Task RetryAsync(Guid id, string actor, CancellationToken token)
    {
        var deployment = await db.CertificateDeployments.FindAsync([id], token) ?? throw new InvalidOperationException("Deployment was not found.");
        if (deployment.Status is not (CertificateDeploymentStatus.Failed or CertificateDeploymentStatus.RollbackFailed))
            throw new InvalidOperationException("Only failed deployments can be retried.");
        deployment.Status = CertificateDeploymentStatus.Pending;
        deployment.ErrorCode = deployment.ErrorMessage = null;
        deployment.UpdatedAtUtc = DateTime.UtcNow;
        db.DeploymentAuditEvents.Add(new() { CertificateDeploymentId = id, EventType = "RetryQueued", Actor = actor, Status = deployment.Status });
        await db.SaveChangesAsync(token);
        await queue.EnqueueAsync(id, $"{deployment.IdempotencyKey}:attempt:{deployment.Attempt}", DateTime.UtcNow, token);
    }

    private IQueryable<CertificateDeployment> DeploymentQuery() => db.CertificateDeployments.AsNoTracking()
        .Include(x => x.CertificateRequest).Include(x => x.DeploymentTarget).Include(x => x.DeploymentPolicy);
    private static CertificateDeploymentDto ToDto(CertificateDeployment x) => new(x.Id, x.CertificateRequestId,
        x.CertificateRequest.Domain, x.CertificateId, x.DeploymentTargetId, x.DeploymentTarget.Name, x.DeploymentPolicyId,
        x.DeploymentPolicy.Name, x.Status, x.Origin, x.Attempt, x.ExpectedFingerprint, x.ObservedFingerprint,
        x.ErrorCode, x.ErrorMessage, x.BackupReference, x.RollbackStatus, x.VerificationStatus, x.RequestedBy,
        x.ApprovedBy, x.CreatedAtUtc, x.StartedAtUtc, x.CompletedAtUtc);
    private static DeploymentTargetDto ToDto(DeploymentTarget x) => new(x.Id, x.Name, x.TargetType, x.AssetId, x.ConfigurationJson,
        !string.IsNullOrWhiteSpace(x.SecretReference), x.IsEnabled, x.CreatedAtUtc, x.UpdatedAtUtc,
        x.DeploymentAgentId, x.DeploymentAgent == null ? null : $"{x.DeploymentAgent.Name} ({x.DeploymentAgent.MachineName})");
    private static DeploymentPolicyDto ToDto(DeploymentPolicy x) => new(x.Id, x.Name, x.RequireApproval, x.AutomaticDeployment,
        x.MaxAttempts, x.RetryDelaySeconds, x.RollbackOnFailure, x.VerificationTimeoutSeconds, x.DeploymentWindow, x.IsEnabled);
    private static void ValidateTargetConfiguration(DeploymentTargetUpsertRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name)) throw new ArgumentException("Target name is required.");
        using var configuration = JsonDocument.Parse(NormalizeJson(request.ConfigurationJson));
        var required = request.TargetType switch
        {
            DeploymentTargetType.Iis => new[] { "siteName", "bindingPort", "certificateStoreName" },
            DeploymentTargetType.Nginx => new[] { "host", "username", "vaultBaseUrl", "sshKeySecretPath", "hostKeyFingerprint", "certificatePath", "privateKeyPath", "fullChainPath" },
            DeploymentTargetType.HaProxy => new[] { "host", "pemBundlePath", "configurationPath", "validateCommand", "reloadCommand" },
            DeploymentTargetType.Traefik => new[] { "host", "dynamicConfigurationPath", "certificatePath", "privateKeyPath" },
            DeploymentTargetType.ApacheWebServer => new[] { "host", "username", "vaultBaseUrl", "sshKeySecretPath", "hostKeyFingerprint", "certificatePath", "privateKeyPath", "fullChainPath" },
            DeploymentTargetType.VaultKv => new[] { "baseUrl", "secretPath" },
            DeploymentTargetType.FileSystem => new[] { "outputDirectory", "certificateFile", "privateKeyFile", "fullChainFile" },
            DeploymentTargetType.Kubernetes => new[] { "apiServer", "namespace", "secretName" },
            DeploymentTargetType.AwsAcm => new[] { "region", "authenticationMode" },
            _ => []
        };
        var missing = required.Where(name =>
            !configuration.RootElement.TryGetProperty(name, out var value) ||
            value.ValueKind == JsonValueKind.Null ||
            value.ValueKind == JsonValueKind.String && string.IsNullOrWhiteSpace(value.GetString())).ToList();
        if (missing.Count > 0)
            throw new ArgumentException($"{request.TargetType.GetDisplayName()} configuration requires: {string.Join(", ", missing)}.");
    }

    private async Task ValidateDeploymentAgentAsync(
        DeploymentTargetUpsertRequest request,
        CancellationToken cancellationToken)
    {
        if (request.TargetType != DeploymentTargetType.Iis)
        {
            if (request.DeploymentAgentId is not null)
                throw new ArgumentException("A deployment agent can only be selected for a Microsoft IIS target.");
            return;
        }
        if (request.DeploymentAgentId is null || request.DeploymentAgentId == Guid.Empty)
            throw new ArgumentException("Select a registered Microsoft IIS deployment agent.");
        var agent = await db.DeploymentAgents.AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == request.DeploymentAgentId, cancellationToken)
            ?? throw new ArgumentException("The selected Microsoft IIS deployment agent was not found.");
        if (!HasMicrosoftIisCapability(agent))
            throw new ArgumentException("The selected agent does not support Microsoft IIS deployment.");
        if (!IsAgentSelectable(agent))
            throw new ArgumentException($"The selected Microsoft IIS deployment agent is {EffectiveAgentStatus(agent)} and cannot be assigned.");
        if (string.IsNullOrWhiteSpace(agent.PublicKeyPem))
            throw new ArgumentException("The selected Microsoft IIS deployment agent has no encryption public key.");
    }

    private static bool HasMicrosoftIisCapability(DeploymentAgent agent)
    {
        if (!string.Equals(agent.AgentType, "MicrosoftIis", StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            var capabilities = JsonSerializer.Deserialize<string[]>(agent.CapabilitiesJson) ?? [];
            return capabilities.Contains("MicrosoftIis", StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsAgentSelectable(DeploymentAgent agent) =>
        agent.Status is DeploymentAgentStatus.Online or DeploymentAgentStatus.Busy &&
        agent.LastHeartbeatAtUtc >= DateTime.UtcNow.AddMinutes(-2);

    private static DeploymentAgentStatus EffectiveAgentStatus(DeploymentAgent agent) =>
        agent.Status is DeploymentAgentStatus.Online or DeploymentAgentStatus.Busy &&
        agent.LastHeartbeatAtUtc < DateTime.UtcNow.AddMinutes(-2)
            ? DeploymentAgentStatus.Stale
            : agent.Status;

    private static string NormalizeTargetJson(DeploymentTargetUpsertRequest request)
    {
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(request.ConfigurationJson) ? "{}" : request.ConfigurationJson);
        if (request.TargetType != DeploymentTargetType.Iis)
            return JsonSerializer.Serialize(document.RootElement);
        var values = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in document.RootElement.EnumerateObject())
            if (!string.Equals(property.Name, "agentId", StringComparison.OrdinalIgnoreCase))
                values[property.Name] = property.Value.Clone();
        return JsonSerializer.Serialize(values);
    }
    private static string NormalizeJson(string value)
    {
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(value) ? "{}" : value);
        return JsonSerializer.Serialize(document.RootElement);
    }
    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
