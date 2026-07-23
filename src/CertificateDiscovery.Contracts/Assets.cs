namespace CertificateDiscovery.Contracts;

using CertificateDiscovery.Domain;

public sealed record AssetDto(
    Guid Id,
    string Name,
    string? Description,
    string Host,
    int Port,
    AssetProtocol Protocol,
    string? Path,
    string? SniHost,
    AssetEnvironment Environment,
    AssetType AssetType,
    string? Owner,
    bool IsEnabled,
    int ScanIntervalMinutes,
    int TimeoutSeconds,
    string? Tags,
    DateTime CreatedAtUtc,
    DateTime? UpdatedAtUtc,
    DateTime? LastScanAtUtc,
    DateTime? NextScanAtUtc,
    string? LastScanStatus,
    CertificateSummaryDto? ActiveCertificate);

public sealed record AssetCreateRequest(
    string Name,
    string Host,
    int Port,
    AssetProtocol Protocol,
    string? Description,
    string? Path,
    string? SniHost,
    AssetEnvironment Environment,
    AssetType AssetType,
    string? Owner,
    bool IsEnabled,
    int ScanIntervalMinutes,
    int TimeoutSeconds,
    string? Tags);

public sealed record AssetUpdateRequest(
    string Name,
    string Host,
    int Port,
    AssetProtocol Protocol,
    string? Description,
    string? Path,
    string? SniHost,
    AssetEnvironment Environment,
    AssetType AssetType,
    string? Owner,
    bool IsEnabled,
    int ScanIntervalMinutes,
    int TimeoutSeconds,
    string? Tags);

public sealed record AssetFilter(
    AssetEnvironment? Environment,
    AssetProtocol? Protocol,
    AssetType? AssetType,
    string? Owner,
    bool? IsEnabled,
    int? ExpiresWithinDays);
