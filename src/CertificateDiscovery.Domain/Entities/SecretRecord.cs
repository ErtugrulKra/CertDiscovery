namespace CertificateDiscovery.Domain.Entities;

public sealed class SecretRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Purpose { get; set; } = string.Empty;
    public string ProtectedValue { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
}

