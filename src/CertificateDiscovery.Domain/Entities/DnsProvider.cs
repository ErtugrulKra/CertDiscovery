namespace CertificateDiscovery.Domain.Entities;

public sealed class DnsProvider
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public DnsProviderType ProviderType { get; set; } = DnsProviderType.Cloudflare;
    public string ZoneName { get; set; } = string.Empty;
    public string? ApiToken { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? Notes { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
}
