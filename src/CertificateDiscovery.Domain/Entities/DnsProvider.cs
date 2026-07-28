namespace CertificateDiscovery.Domain.Entities;

public sealed class DnsProvider
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public DnsProviderType ProviderType { get; set; } = DnsProviderType.Cloudflare;
    public string ZoneName { get; set; } = string.Empty;
    [Obsolete("Retained only for migration. New credentials must use secret references.")]
    public string? ApiToken { get; set; }
    public string? ApiTokenSecretReference { get; set; }
    public string? HostedZoneId { get; set; }
    public AwsDnsAuthenticationMode AwsAuthenticationMode { get; set; } = AwsDnsAuthenticationMode.DefaultCredentialChain;
    public string? RoleArn { get; set; }
    public string? AccessKeySecretReference { get; set; }
    public string? SecretKeySecretReference { get; set; }
    public string? SessionTokenSecretReference { get; set; }
    public string? Region { get; set; }
    public AzureDnsAuthenticationMode AzureAuthenticationMode { get; set; } = AzureDnsAuthenticationMode.DefaultAzureCredential;
    public string? TenantId { get; set; }
    public string? SubscriptionId { get; set; }
    public string? ResourceGroup { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecretReference { get; set; }
    public string? ManagedIdentityClientId { get; set; }
    public int TtlSeconds { get; set; } = 120;
    public int PropagationTimeoutSeconds { get; set; } = 300;
    public int PropagationPollingIntervalSeconds { get; set; } = 10;
    public DateTime? LastHealthCheckAtUtc { get; set; }
    public string? LastHealthCheckStatus { get; set; }
    public string? LastHealthCheckError { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? Notes { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
}
