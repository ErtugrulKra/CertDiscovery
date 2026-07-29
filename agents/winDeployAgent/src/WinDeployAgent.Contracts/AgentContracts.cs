namespace WinDeployAgent.Contracts;

public sealed record AgentRegisterRequest(
    string RegistrationToken,
    string Name,
    string MachineName,
    string Version,
    string OperatingSystem,
    IReadOnlyList<string> Capabilities,
    string? PublicKeyPem);
public sealed record AgentRegisterResponse(Guid AgentId, string AgentToken, DateTime RegisteredAtUtc);
public sealed record AgentExchangeCreateRequest(
    string Name,
    string MachineName,
    string Version,
    string OperatingSystem,
    IReadOnlyList<string> Capabilities,
    string PublicKeyPem);
public sealed record AgentExchangeCreateResponse(
    Guid ExchangeId,
    string ExchangeSecret,
    string UserCode,
    DateTime ExpiresAtUtc,
    string VerificationUri,
    int PollIntervalSeconds);
public sealed record AgentExchangePollResponse(
    string Status,
    AgentRegisterResponse? Registration = null,
    string? Message = null);
public sealed record AgentHeartbeatRequest(
    string Version,
    string OperatingSystem,
    IReadOnlyList<string> Capabilities,
    bool Busy);
public sealed record AgentJobClaimResponse(Guid JobId, string LeaseToken, DateTime LeaseExpiresAtUtc, string TargetConfigurationJson);
public sealed record AgentJobBundleResponse(Guid JobId, string EncryptedBundleJson);
public sealed record AgentJobLeaseRequest(string LeaseToken);
public sealed record AgentJobStageResultRequest(string LeaseToken, string Stage, string? Message);
public sealed record AgentJobCompleteRequest(
    string LeaseToken,
    bool Succeeded,
    bool RolledBack,
    string? ObservedFingerprint,
    string? PreviousFingerprint,
    string? ErrorCode,
    string? ErrorMessage);
