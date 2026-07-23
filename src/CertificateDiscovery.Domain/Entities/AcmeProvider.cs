namespace CertificateDiscovery.Domain.Entities;

public sealed class AcmeProvider
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public AcmeProviderType ProviderType { get; set; } = AcmeProviderType.Generic;
    public Uri DirectoryUrl { get; set; } = new("https://acme-v02.api.letsencrypt.org/directory");
    public string AccountEmail { get; set; } = string.Empty;
    public string? ExternalAccountBindingKeyId { get; set; }
    public string? ExternalAccountBindingHmacKey { get; set; }
    public bool IsStaging { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? Notes { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
}
