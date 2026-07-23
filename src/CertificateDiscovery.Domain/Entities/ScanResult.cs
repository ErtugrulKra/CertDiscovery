namespace CertificateDiscovery.Domain.Entities;

using CertificateDiscovery.Domain;

public sealed class ScanResult
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ScanJobId { get; set; }
    public ScanJob ScanJob { get; set; } = null!;
    public Guid AssetId { get; set; }
    public Asset Asset { get; set; } = null!;
    public ScanResultStatus Status { get; set; }
    public DateTime StartedAtUtc { get; set; }
    public DateTime CompletedAtUtc { get; set; }
    public long DurationMilliseconds { get; set; }
    public string? ResolvedIpAddress { get; set; }
    public string? TlsProtocol { get; set; }
    public string? CipherSuite { get; set; }
    public Guid? CertificateId { get; set; }
    public Certificate? Certificate { get; set; }
    public ScanErrorType ErrorType { get; set; } = ScanErrorType.None;
    public string? ErrorMessage { get; set; }
    public string? RawDiagnosticData { get; set; }
}
