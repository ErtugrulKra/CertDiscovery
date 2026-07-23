namespace CertificateDiscovery.Domain.Entities;

using CertificateDiscovery.Domain;

public sealed class Asset
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 443;
    public AssetProtocol Protocol { get; set; } = AssetProtocol.HTTPS;
    public string? Path { get; set; }
    public string? SniHost { get; set; }
    public AssetEnvironment Environment { get; set; } = AssetEnvironment.Production;
    public AssetType AssetType { get; set; } = AssetType.WebApplication;
    public string? Owner { get; set; }
    public bool IsEnabled { get; set; } = true;
    public int ScanIntervalMinutes { get; set; } = 1440;
    public int TimeoutSeconds { get; set; } = 10;
    public string? Tags { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
    public DateTime? LastScanAtUtc { get; set; }
    public DateTime? NextScanAtUtc { get; set; }

    public ICollection<AssetCertificate> AssetCertificates { get; set; } = new List<AssetCertificate>();
    public ICollection<ScanResult> ScanResults { get; set; } = new List<ScanResult>();
}
