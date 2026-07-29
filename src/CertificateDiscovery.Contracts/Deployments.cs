using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Contracts;

public sealed record DeploymentTargetDto(Guid Id, string Name, DeploymentTargetType TargetType, Guid? AssetId,
    string ConfigurationJson, bool HasSecret, bool IsEnabled, DateTime CreatedAtUtc, DateTime? UpdatedAtUtc,
    Guid? DeploymentAgentId = null, string? DeploymentAgentName = null);
public sealed record DeploymentTargetUpsertRequest(string Name, DeploymentTargetType TargetType, Guid? AssetId,
    string ConfigurationJson, string? Secret, bool IsEnabled, Guid? DeploymentAgentId = null);
public sealed record DeploymentAgentOptionDto(
    Guid Id, string Name, string MachineName, DeploymentAgentStatus Status, bool IsSelectable);
public sealed record DeploymentPolicyDto(Guid Id, string Name, bool RequireApproval, bool AutomaticDeployment,
    int MaxAttempts, int RetryDelaySeconds, bool RollbackOnFailure, int VerificationTimeoutSeconds,
    string? DeploymentWindow, bool IsEnabled,
    VerificationQuorumMode VerificationQuorumMode = VerificationQuorumMode.All,
    int VerificationQuorumPercentage = 100,
    int VerificationMinimumSuccessfulNodes = 1,
    int VerificationAttempts = 1,
    int VerificationIntervalSeconds = 5,
    bool RollbackOnPartialVerification = true);
public sealed record DeploymentPolicyUpsertRequest(string Name, bool RequireApproval, bool AutomaticDeployment,
    int MaxAttempts, int RetryDelaySeconds, bool RollbackOnFailure, int VerificationTimeoutSeconds,
    string? DeploymentWindow, bool IsEnabled,
    VerificationQuorumMode VerificationQuorumMode = VerificationQuorumMode.All,
    int VerificationQuorumPercentage = 100,
    int VerificationMinimumSuccessfulNodes = 1,
    int VerificationAttempts = 1,
    int VerificationIntervalSeconds = 5,
    bool RollbackOnPartialVerification = true);
public sealed record CertificateDeploymentDto(Guid Id, Guid CertificateRequestId, string Domain, Guid CertificateId,
    Guid DeploymentTargetId, string TargetName, Guid DeploymentPolicyId, string PolicyName,
    CertificateDeploymentStatus Status, DeploymentOrigin Origin, int Attempt, string ExpectedFingerprint,
    string? ObservedFingerprint, string? ErrorCode, string? ErrorMessage, string? BackupReference,
    string? RollbackStatus, string? VerificationStatus, string? RequestedBy, string? ApprovedBy,
    DateTime CreatedAtUtc, DateTime? StartedAtUtc, DateTime? CompletedAtUtc,
    string? ExternalResourceReference = null,
    string? InternalVerificationStatus = null,
    string? ExternalVerificationStatus = null);
public sealed record DeploymentAuditEventDto(string EventType, string? Actor, string? Message,
    CertificateDeploymentStatus Status, DateTime CreatedAtUtc, long? DurationMilliseconds);
public sealed record DeploymentEndpointVerificationDto(
    string Endpoint, string? ObservedAddress, string? ObservedFingerprint,
    EndpointVerificationOutcome Outcome, bool SanMatches, bool TimeValid, bool ChainValid,
    DateTime? NotAfterUtc, string? ErrorCode, string? ErrorMessage, long DurationMilliseconds);
public sealed record DeploymentVerificationRunDto(
    Guid Id, int Attempt, bool IsRollbackVerification, VerificationQuorumMode QuorumMode,
    int TotalNodes, int SuccessfulNodes, int FailedNodes, int DistinctFingerprints,
    DeploymentVerificationOutcome Outcome, string? Summary, DateTime StartedAtUtc,
    DateTime? CompletedAtUtc, IReadOnlyList<DeploymentEndpointVerificationDto> Endpoints);
public sealed record DeploymentDetailDto(
    CertificateDeploymentDto Deployment,
    IReadOnlyList<DeploymentAuditEventDto> Events,
    IReadOnlyList<DeploymentVerificationRunDto>? VerificationRuns = null);
public sealed record DeploymentIndexDto(IReadOnlyList<DeploymentTargetDto> Targets,
    IReadOnlyList<DeploymentPolicyDto> Policies, IReadOnlyList<CertificateDeploymentDto> Deployments);
public sealed record DeploymentCreateRequest(Guid CertificateRequestId, Guid DeploymentTargetId, Guid DeploymentPolicyId);
public sealed record DeploymentCertificateOptionDto(
    Guid CertificateRequestId, string Domain, string VaultSecretPath, string Fingerprint, DateTime? StoredAtUtc);
public sealed record DeploymentTargetOptionDto(
    Guid Id, string Name, DeploymentTargetType TargetType, string? DeploymentAgentName);
public sealed record DeploymentPolicyOptionDto(
    Guid Id, string Name, bool RequireApproval, bool AutomaticDeployment, bool RollbackOnFailure);
public sealed record DeploymentCreateOptionsDto(
    IReadOnlyList<DeploymentCertificateOptionDto> Certificates,
    IReadOnlyList<DeploymentTargetOptionDto> Targets,
    IReadOnlyList<DeploymentPolicyOptionDto> Policies);
