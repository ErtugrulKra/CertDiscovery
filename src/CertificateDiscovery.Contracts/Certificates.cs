namespace CertificateDiscovery.Contracts;

using CertificateDiscovery.Domain;

public sealed record CertificateSummaryDto(
    Guid Id,
    string FingerprintSha256,
    string? CommonName,
    string Subject,
    string Issuer,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    int RemainingDays,
    CertificateHealthStatus Status,
    bool IsSelfSigned,
    CertificateSource Source,
    string? SourceName,
    int AssetCount,
    DateTime LastSeenAtUtc);

public sealed record CertificateDetailDto(
    Guid Id,
    string FingerprintSha256,
    string? SerialNumber,
    string Subject,
    string? CommonName,
    string Issuer,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    int RemainingDays,
    CertificateHealthStatus Status,
    string? SignatureAlgorithm,
    string? PublicKeyAlgorithm,
    int? PublicKeySize,
    int? Version,
    bool IsSelfSigned,
    CertificateSource Source,
    string? SourceName,
    string? ExternalReference,
    DateTime CreatedAtUtc,
    DateTime LastSeenAtUtc,
    IReadOnlyList<CertificateChainEntryDto> ChainEntries,
    IReadOnlyList<SubjectAlternativeNameDto> SubjectAlternativeNames,
    IReadOnlyList<CertificateAssetUsageDto> Assets);

public sealed record SubjectAlternativeNameDto(string Name, CertificateSanType Type);

public sealed record CertificateChainEntryDto(
    int Position,
    string FingerprintSha256,
    string? SerialNumber,
    string Subject,
    string? CommonName,
    string Issuer,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    string? SignatureAlgorithm,
    string? PublicKeyAlgorithm,
    int? PublicKeySize,
    int? Version,
    bool IsSelfSigned,
    DateTime LastSeenAtUtc);

public sealed record CertificateAssetUsageDto(
    Guid AssetId,
    string AssetName,
    string Host,
    int Port,
    AssetProtocol Protocol,
    AssetEnvironment Environment,
    string? Owner,
    DateTime FirstSeenAtUtc,
    DateTime LastSeenAtUtc,
    bool IsCurrentlyActive);
