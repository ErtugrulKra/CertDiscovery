namespace CertificateDiscovery.Contracts;

using CertificateDiscovery.Domain;

public sealed record VaultDiscoveryJobCreateRequest(
    string Name,
    Guid VaultServerId,
    string KvMountPath,
    string BasePath,
    bool Recursive,
    bool CreateAssets);

public sealed record VaultDiscoveryJobDto(
    Guid Id,
    string Name,
    string VaultServerName,
    string KvMountPath,
    string BasePath,
    bool Recursive,
    bool CreateAssets,
    ScanJobStatus Status,
    DateTime RequestedAtUtc,
    DateTime? StartedAtUtc,
    DateTime? CompletedAtUtc,
    int SecretCount,
    int CertificateFoundCount,
    int AssetCreatedCount,
    int FailedSecretCount,
    string RequestedBy,
    string? ErrorMessage,
    long? DurationMilliseconds);

public sealed record VaultDiscoveryCreateOptionsDto(IReadOnlyList<VaultServerDto> VaultServers);
