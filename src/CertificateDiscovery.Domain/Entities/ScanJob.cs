namespace CertificateDiscovery.Domain.Entities;

using CertificateDiscovery.Domain;

public sealed class ScanJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public ScanJobStatus Status { get; set; } = ScanJobStatus.Pending;
    public ScanTriggerType TriggerType { get; set; } = ScanTriggerType.Scheduled;
    public DateTime RequestedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public int TotalAssetCount { get; set; }
    public int SuccessfulAssetCount { get; set; }
    public int FailedAssetCount { get; set; }
    public string? WorkerId { get; set; }
    public string? ErrorMessage { get; set; }
    public ICollection<ScanJobAsset> Assets { get; set; } = new List<ScanJobAsset>();
    public ICollection<ScanResult> Results { get; set; } = new List<ScanResult>();
}
