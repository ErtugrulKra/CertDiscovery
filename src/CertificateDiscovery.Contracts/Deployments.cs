using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Contracts;

public sealed record DeploymentTargetDto(Guid Id, string Name, DeploymentTargetType TargetType, Guid? AssetId,
    string ConfigurationJson, bool HasSecret, bool IsEnabled, DateTime CreatedAtUtc, DateTime? UpdatedAtUtc);
public sealed record DeploymentTargetUpsertRequest(string Name, DeploymentTargetType TargetType, Guid? AssetId,
    string ConfigurationJson, string? Secret, bool IsEnabled);
public sealed record DeploymentPolicyDto(Guid Id, string Name, bool RequireApproval, bool AutomaticDeployment,
    int MaxAttempts, int RetryDelaySeconds, bool RollbackOnFailure, int VerificationTimeoutSeconds,
    string? DeploymentWindow, bool IsEnabled);
public sealed record DeploymentPolicyUpsertRequest(string Name, bool RequireApproval, bool AutomaticDeployment,
    int MaxAttempts, int RetryDelaySeconds, bool RollbackOnFailure, int VerificationTimeoutSeconds,
    string? DeploymentWindow, bool IsEnabled);
public sealed record CertificateDeploymentDto(Guid Id, Guid CertificateRequestId, string Domain, Guid CertificateId,
    Guid DeploymentTargetId, string TargetName, Guid DeploymentPolicyId, string PolicyName,
    CertificateDeploymentStatus Status, DeploymentOrigin Origin, int Attempt, string ExpectedFingerprint,
    string? ObservedFingerprint, string? ErrorCode, string? ErrorMessage, string? BackupReference,
    string? RollbackStatus, string? VerificationStatus, string? RequestedBy, string? ApprovedBy,
    DateTime CreatedAtUtc, DateTime? StartedAtUtc, DateTime? CompletedAtUtc);
public sealed record DeploymentAuditEventDto(string EventType, string? Actor, string? Message,
    CertificateDeploymentStatus Status, DateTime CreatedAtUtc, long? DurationMilliseconds);
public sealed record DeploymentDetailDto(CertificateDeploymentDto Deployment, IReadOnlyList<DeploymentAuditEventDto> Events);
public sealed record DeploymentIndexDto(IReadOnlyList<DeploymentTargetDto> Targets,
    IReadOnlyList<DeploymentPolicyDto> Policies, IReadOnlyList<CertificateDeploymentDto> Deployments);
public sealed record DeploymentCreateRequest(Guid CertificateRequestId, Guid DeploymentTargetId, Guid DeploymentPolicyId);
