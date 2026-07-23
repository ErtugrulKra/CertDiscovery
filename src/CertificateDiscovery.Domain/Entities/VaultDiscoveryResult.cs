namespace CertificateDiscovery.Domain.Entities;

public sealed class VaultDiscoveryResult
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid VaultDiscoveryJobId { get; set; }
    public VaultDiscoveryJob VaultDiscoveryJob { get; set; } = null!;
    public string SecretPath { get; set; } = string.Empty;
    public string? Domain { get; set; }
    public string? SubjectAlternativeNames { get; set; }
    public ScanResultStatus Status { get; set; }
    public Guid? CertificateId { get; set; }
    public Certificate? Certificate { get; set; }
    public Guid? PromotedAssetId { get; set; }
    public Asset? PromotedAsset { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime StartedAtUtc { get; set; }
    public DateTime CompletedAtUtc { get; set; }
    public long DurationMilliseconds { get; set; }
}
