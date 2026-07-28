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
        await db.DeploymentTargets.AsNoTracking().OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken),
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
        ValidateTarget(request);
        var target = new DeploymentTarget
        {
            Name = request.Name.Trim(), TargetType = request.TargetType, AssetId = request.AssetId,
            ConfigurationJson = NormalizeJson(request.ConfigurationJson), IsEnabled = request.IsEnabled
        };
        if (!string.IsNullOrWhiteSpace(request.Secret))
            target.SecretReference = await secrets.StoreAsync($"deployment-target:{target.Id:D}", request.Secret, cancellationToken);
        db.DeploymentTargets.Add(target);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<DeploymentTargetUpsertRequest?> GetTargetAsync(Guid id, CancellationToken cancellationToken)
    {
        var target = await db.DeploymentTargets.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return target is null ? null : new(target.Name, target.TargetType, target.AssetId, target.ConfigurationJson, null, target.IsEnabled);
    }

    public async Task<bool> UpdateTargetAsync(Guid id, DeploymentTargetUpsertRequest request, CancellationToken cancellationToken)
    {
        ValidateTarget(request);
        var target = await db.DeploymentTargets.FindAsync([id], cancellationToken);
        if (target is null) return false;
        target.Name = request.Name.Trim(); target.TargetType = request.TargetType; target.AssetId = request.AssetId;
        target.ConfigurationJson = NormalizeJson(request.ConfigurationJson); target.IsEnabled = request.IsEnabled; target.UpdatedAtUtc = DateTime.UtcNow;
        if (!string.IsNullOrWhiteSpace(request.Secret))
        {
            var old = target.SecretReference;
            target.SecretReference = await secrets.StoreAsync($"deployment-target:{target.Id:D}", request.Secret, cancellationToken);
            if (!string.IsNullOrWhiteSpace(old)) await secrets.DeleteAsync(old, cancellationToken);
        }
        await db.SaveChangesAsync(cancellationToken);
        return true;
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
        !string.IsNullOrWhiteSpace(x.SecretReference), x.IsEnabled, x.CreatedAtUtc, x.UpdatedAtUtc);
    private static DeploymentPolicyDto ToDto(DeploymentPolicy x) => new(x.Id, x.Name, x.RequireApproval, x.AutomaticDeployment,
        x.MaxAttempts, x.RetryDelaySeconds, x.RollbackOnFailure, x.VerificationTimeoutSeconds, x.DeploymentWindow, x.IsEnabled);
    private static void ValidateTarget(DeploymentTargetUpsertRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name)) throw new ArgumentException("Target name is required.");
        using var configuration = JsonDocument.Parse(NormalizeJson(request.ConfigurationJson));
        var required = request.TargetType switch
        {
            DeploymentTargetType.Iis => new[] { "host", "siteName", "bindingPort", "certificateStoreName" },
            DeploymentTargetType.Nginx => new[] { "host", "certificatePath", "privateKeyPath", "validateCommand", "reloadCommand" },
            DeploymentTargetType.HaProxy => new[] { "host", "pemBundlePath", "configurationPath", "validateCommand", "reloadCommand" },
            DeploymentTargetType.Traefik => new[] { "host", "dynamicConfigurationPath", "certificatePath", "privateKeyPath" },
            DeploymentTargetType.ApacheWebServer => new[] { "host", "virtualHost", "certificatePath", "privateKeyPath", "validateCommand", "reloadCommand" },
            _ => []
        };
        var missing = required.Where(name =>
            !configuration.RootElement.TryGetProperty(name, out var value) ||
            value.ValueKind == JsonValueKind.Null ||
            value.ValueKind == JsonValueKind.String && string.IsNullOrWhiteSpace(value.GetString())).ToList();
        if (missing.Count > 0)
            throw new ArgumentException($"{request.TargetType.GetDisplayName()} configuration requires: {string.Join(", ", missing)}.");
    }
    private static string NormalizeJson(string value)
    {
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(value) ? "{}" : value);
        return JsonSerializer.Serialize(document.RootElement);
    }
    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
