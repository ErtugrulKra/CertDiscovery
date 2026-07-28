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
    public string? ExternalAccountBindingHmacSecretReference { get; set; }
    public string? Organization { get; set; }
    public string? Department { get; set; }
    public string? CertificateProfile { get; set; }
    public string? ProductType { get; set; }
    public string? AllowedDomainPattern { get; set; }
    public bool IsStaging { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? Notes { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
    public ICollection<AcmeAccount> Accounts { get; set; } = new List<AcmeAccount>();
}
