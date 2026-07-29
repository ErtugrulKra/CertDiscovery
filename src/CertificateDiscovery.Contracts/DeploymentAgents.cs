using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Contracts;

public sealed record DeploymentAgentRegistrationTokenRequest(string Description, int LifetimeMinutes = 15);
public sealed record DeploymentAgentRegistrationTokenResponse(string Token, DateTime ExpiresAtUtc);
public sealed record DeploymentAgentRegisterRequest(
    string RegistrationToken,
    string Name,
    string MachineName,
    string Version,
    string OperatingSystem,
    IReadOnlyList<string> Capabilities,
    string? PublicKeyPem);
public sealed record DeploymentAgentRegisterResponse(Guid AgentId, string AgentToken, DateTime RegisteredAtUtc);
public sealed record DeploymentAgentExchangeCreateRequest(
    string Name,
    string MachineName,
    string Version,
    string OperatingSystem,
    IReadOnlyList<string> Capabilities,
    string PublicKeyPem);
public sealed record DeploymentAgentExchangeCreateResponse(
    Guid ExchangeId,
    string ExchangeSecret,
    string UserCode,
    DateTime ExpiresAtUtc,
    string VerificationUri,
    int PollIntervalSeconds);
public sealed record DeploymentAgentExchangePollResponse(
    string Status,
    DeploymentAgentRegisterResponse? Registration = null,
    string? Message = null);
public sealed record DeploymentAgentExchangeDto(
    Guid Id,
    string UserCode,
    string Name,
    string MachineName,
    string Version,
    string OperatingSystem,
    IReadOnlyList<string> Capabilities,
    string PublicKeyFingerprint,
    DeploymentAgentExchangeStatus Status,
    DateTime CreatedAtUtc,
    DateTime ExpiresAtUtc,
    DateTime? ApprovedAtUtc,
    string? ApprovedBy);
public sealed record DeploymentAgentHeartbeatRequest(
    string Version,
    string OperatingSystem,
    IReadOnlyList<string> Capabilities,
    bool Busy);
public sealed record DeploymentAgentDto(
    Guid Id,
    string Name,
    string MachineName,
    string Version,
    string OperatingSystem,
    IReadOnlyList<string> Capabilities,
    DeploymentAgentStatus Status,
    DateTime LastHeartbeatAtUtc,
    DateTime RegisteredAtUtc);
public sealed record AgentJobClaimResponse(Guid JobId, string LeaseToken, DateTime LeaseExpiresAtUtc, string TargetConfigurationJson);
public sealed record AgentJobLeaseRequest(string LeaseToken);
public sealed record AgentJobBundleResponse(Guid JobId, string EncryptedBundleJson);
public sealed record AgentJobStageResultRequest(string LeaseToken, string Stage, string? Message);
public sealed record AgentJobCompleteRequest(
    string LeaseToken,
    bool Succeeded,
    bool RolledBack,
    string? ObservedFingerprint,
    string? PreviousFingerprint,
    string? ErrorCode,
    string? ErrorMessage);
