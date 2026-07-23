namespace CertificateDiscovery.Domain.Entities;

public sealed class ScanJobAsset
{
    public Guid ScanJobId { get; set; }
    public ScanJob ScanJob { get; set; } = null!;
    public Guid AssetId { get; set; }
    public Asset Asset { get; set; } = null!;
}
