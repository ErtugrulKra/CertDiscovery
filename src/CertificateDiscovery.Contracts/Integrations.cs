namespace CertificateDiscovery.Contracts;

using CertificateDiscovery.Domain;

public sealed record VaultServerDto(
    Guid Id,
    string Name,
    Uri BaseUrl,
    string? Description,
    string? PkiMountPath,
    bool HasToken,
    bool ScanPublicEndpoint,
    bool ImportPkiCertificates,
    bool IsEnabled,
    DateTime CreatedAtUtc,
    DateTime? UpdatedAtUtc,
    DateTime? LastSyncAtUtc,
    string? LastSyncStatus,
    string? LastSyncError);

public sealed record VaultServerUpsertRequest(
    string Name,
    string BaseUrl,
    string? Description,
    string? PkiMountPath,
    string? Token,
    bool ScanPublicEndpoint,
    bool ImportPkiCertificates,
    bool IsEnabled);

public sealed record AcmeProviderDto(
    Guid Id,
    string Name,
    AcmeProviderType ProviderType,
    Uri DirectoryUrl,
    string AccountEmail,
    bool HasExternalAccountBinding,
    bool IsStaging,
    bool IsEnabled,
    string? Notes,
    DateTime CreatedAtUtc,
    DateTime? UpdatedAtUtc);

public sealed record AcmeProviderUpsertRequest(
    string Name,
    AcmeProviderType ProviderType,
    string DirectoryUrl,
    string AccountEmail,
    string? ExternalAccountBindingKeyId,
    string? ExternalAccountBindingHmacKey,
    bool IsStaging,
    bool IsEnabled,
    string? Notes);

public sealed record DnsProviderDto(
    Guid Id,
    string Name,
    DnsProviderType ProviderType,
    string ZoneName,
    bool HasApiToken,
    bool IsEnabled,
    string? Notes,
    DateTime CreatedAtUtc,
    DateTime? UpdatedAtUtc);

public sealed record DnsProviderUpsertRequest(
    string Name,
    DnsProviderType ProviderType,
    string ZoneName,
    string? ApiToken,
    bool IsEnabled,
    string? Notes);

public sealed record IntegrationIndexDto(
    IReadOnlyList<VaultServerDto> VaultServers,
    IReadOnlyList<AcmeProviderDto> AcmeProviders,
    IReadOnlyList<DnsProviderDto> DnsProviders);
