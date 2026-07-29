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
    DateTime? UpdatedAtUtc,
    string? Organization = null,
    string? Department = null,
    string? CertificateProfile = null,
    string? ProductType = null,
    string? AllowedDomainPattern = null,
    Guid? ActiveAccountId = null,
    AcmeAccountStatus? ActiveAccountStatus = null,
    DateTime? LastAccountUseAtUtc = null);

public sealed record AcmeProviderUpsertRequest(
    string Name,
    AcmeProviderType ProviderType,
    string DirectoryUrl,
    string AccountEmail,
    string? ExternalAccountBindingKeyId,
    string? ExternalAccountBindingHmacKey,
    bool IsStaging,
    bool IsEnabled,
    string? Notes,
    string? Organization = null,
    string? Department = null,
    string? CertificateProfile = null,
    string? ProductType = null,
    string? AllowedDomainPattern = null);

public sealed record DnsProviderDto(
    Guid Id,
    string Name,
    DnsProviderType ProviderType,
    string ZoneName,
    bool HasApiToken,
    bool IsEnabled,
    string? Notes,
    DateTime CreatedAtUtc,
    DateTime? UpdatedAtUtc,
    string? HostedZoneId = null,
    AwsDnsAuthenticationMode AwsAuthenticationMode = AwsDnsAuthenticationMode.DefaultCredentialChain,
    bool HasAwsAccessKey = false,
    bool HasAwsSecretKey = false,
    bool HasAwsSessionToken = false,
    string? RoleArn = null,
    string? Region = null,
    AzureDnsAuthenticationMode AzureAuthenticationMode = AzureDnsAuthenticationMode.DefaultAzureCredential,
    string? TenantId = null,
    string? SubscriptionId = null,
    string? ResourceGroup = null,
    string? ClientId = null,
    bool HasAzureClientSecret = false,
    string? ManagedIdentityClientId = null,
    int TtlSeconds = 120,
    int PropagationTimeoutSeconds = 300,
    int PropagationPollingIntervalSeconds = 10,
    DateTime? LastHealthCheckAtUtc = null,
    string? LastHealthCheckStatus = null,
    string? LastHealthCheckError = null);

public sealed record DnsProviderUpsertRequest(
    string Name,
    DnsProviderType ProviderType,
    string ZoneName,
    string? ApiToken,
    bool IsEnabled,
    string? Notes,
    string? HostedZoneId = null,
    AwsDnsAuthenticationMode AwsAuthenticationMode = AwsDnsAuthenticationMode.DefaultCredentialChain,
    string? AwsAccessKey = null,
    string? AwsSecretKey = null,
    string? AwsSessionToken = null,
    string? RoleArn = null,
    string? Region = null,
    AzureDnsAuthenticationMode AzureAuthenticationMode = AzureDnsAuthenticationMode.DefaultAzureCredential,
    string? TenantId = null,
    string? SubscriptionId = null,
    string? ResourceGroup = null,
    string? ClientId = null,
    string? AzureClientSecret = null,
    string? ManagedIdentityClientId = null,
    int TtlSeconds = 120,
    int PropagationTimeoutSeconds = 300,
    int PropagationPollingIntervalSeconds = 10);

public sealed record KubernetesClusterDto(
    Guid Id,
    string Name,
    Uri ApiServer,
    string? Description,
    string? Namespaces,
    bool HasBearerToken,
    bool IsEnabled,
    DateTime CreatedAtUtc,
    DateTime? UpdatedAtUtc,
    DateTime? LastSyncAtUtc,
    string? LastSyncStatus,
    string? LastSyncError);

public sealed record KubernetesClusterUpsertRequest(
    string Name,
    string ApiServer,
    string? Description,
    string? Namespaces,
    string? BearerToken,
    bool IsEnabled);

public sealed record IntegrationIndexDto(
    IReadOnlyList<VaultServerDto> VaultServers,
    IReadOnlyList<AcmeProviderDto> AcmeProviders,
    IReadOnlyList<DnsProviderDto> DnsProviders,
    IReadOnlyList<KubernetesClusterDto> KubernetesClusters);
