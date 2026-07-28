namespace CertificateDiscovery.Domain.Entities;

public sealed class AcmeAccount
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid AcmeProviderId { get; set; }
    public AcmeProvider? AcmeProvider { get; set; }
    public string AccountLocation { get; set; } = string.Empty;
    public string AccountKeySecretReference { get; set; } = string.Empty;
    public string? ExternalAccountBindingKeyId { get; set; }
    public AcmeAccountStatus Status { get; set; } = AcmeAccountStatus.Active;
    public string ContactEmail { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
    public DateTime? LastUsedAtUtc { get; set; }
    public DateTime? DeactivatedAtUtc { get; set; }
}

