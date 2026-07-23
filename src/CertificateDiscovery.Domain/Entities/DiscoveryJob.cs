namespace CertificateDiscovery.Domain.Entities;

using CertificateDiscovery.Domain;

public sealed class DiscoveryJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Cidr { get; set; } = string.Empty;
    public string Ports { get; set; } = "443,8443,9443,465,993,995,636";
    public ScanJobStatus Status { get; set; } = ScanJobStatus.Pending;
    public DateTime RequestedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public int TotalEndpointCount { get; set; }
    public int ScannedEndpointCount { get; set; }
    public int CertificateFoundCount { get; set; }
    public int FailedEndpointCount { get; set; }
    public int TimeoutSeconds { get; set; } = 3;
    public int MaxConcurrency { get; set; } = 100;
    public string? WorkerId { get; set; }
    public string? ErrorMessage { get; set; }
    public string RequestedBy { get; set; } = "system";
    public ICollection<DiscoveredEndpoint> Results { get; set; } = new List<DiscoveredEndpoint>();
}
