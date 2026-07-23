namespace CertificateDiscovery.Domain.Entities;

public sealed class AssetCertificate
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid AssetId { get; set; }
    public Asset Asset { get; set; } = null!;
    public Guid CertificateId { get; set; }
    public Certificate Certificate { get; set; } = null!;
    public DateTime FirstSeenAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAtUtc { get; set; } = DateTime.UtcNow;
    public bool IsCurrentlyActive { get; set; } = true;
    public int ObservedChainPosition { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
}
