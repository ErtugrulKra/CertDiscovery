namespace WinDeployAgent;

public sealed record PendingAgentRegistration(
    Guid ExchangeId,
    string ExchangeSecret,
    string UserCode,
    Uri VerificationUri,
    DateTime ExpiresAtUtc,
    int PollIntervalSeconds,
    string PrivateKeyPem,
    string PublicKeyFingerprint);
