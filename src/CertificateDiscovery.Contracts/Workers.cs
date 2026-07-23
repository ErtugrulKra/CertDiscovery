namespace CertificateDiscovery.Contracts;

public sealed record WorkerHeartbeatRequest(string WorkerName, string? Version, string? LastError, int ProcessedJobCount);

public sealed record WorkerNodeDto(
    Guid Id,
    string WorkerName,
    string? Description,
    string? Version,
    string Status,
    bool IsEnabled,
    DateTime LastHeartbeatAtUtc,
    DateTime StartedAtUtc,
    DateTime CreatedAtUtc,
    DateTime? UpdatedAtUtc,
    int ProcessedJobCount,
    string? LastError);
