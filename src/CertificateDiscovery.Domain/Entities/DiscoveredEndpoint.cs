namespace CertificateDiscovery.Domain.Entities;

using CertificateDiscovery.Domain;

public sealed class DiscoveredEndpoint
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DiscoveryJobId { get; set; }
    public DiscoveryJob DiscoveryJob { get; set; } = null!;
    public string IpAddress { get; set; } = string.Empty;
    public int Port { get; set; }
    public AssetProtocol ProtocolGuess { get; set; } = AssetProtocol.TLS;
    public ScanResultStatus Status { get; set; }
    public DateTime StartedAtUtc { get; set; }
    public DateTime CompletedAtUtc { get; set; }
    public long DurationMilliseconds { get; set; }
    public string? TlsProtocol { get; set; }
    public string? CipherSuite { get; set; }
    public Guid? CertificateId { get; set; }
    public Certificate? Certificate { get; set; }
    public string? ReverseDnsName { get; set; }
    public ScanErrorType ErrorType { get; set; } = ScanErrorType.None;
    public string? ErrorMessage { get; set; }
    public string? RawDiagnosticData { get; set; }
    public Guid? PromotedAssetId { get; set; }
    public Asset? PromotedAsset { get; set; }
}
