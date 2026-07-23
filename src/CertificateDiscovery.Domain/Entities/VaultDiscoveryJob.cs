namespace CertificateDiscovery.Domain.Entities;

public sealed class VaultDiscoveryJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public Guid VaultServerId { get; set; }
    public VaultServer VaultServer { get; set; } = null!;
    public string KvMountPath { get; set; } = "secret";
    public string BasePath { get; set; } = "certificates";
    public bool Recursive { get; set; } = true;
    public bool CreateAssets { get; set; }
    public ScanJobStatus Status { get; set; } = ScanJobStatus.Pending;
    public DateTime RequestedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public int SecretCount { get; set; }
    public int CertificateFoundCount { get; set; }
    public int AssetCreatedCount { get; set; }
    public int FailedSecretCount { get; set; }
    public string RequestedBy { get; set; } = "system";
    public string? ErrorMessage { get; set; }
    public ICollection<VaultDiscoveryResult> Results { get; set; } = new List<VaultDiscoveryResult>();
}
