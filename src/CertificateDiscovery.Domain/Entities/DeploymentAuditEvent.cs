namespace CertificateDiscovery.Domain.Entities;

public sealed class DeploymentAuditEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CertificateDeploymentId { get; set; }
    public CertificateDeployment CertificateDeployment { get; set; } = null!;
    public string EventType { get; set; } = string.Empty;
    public string? Actor { get; set; }
    public string? Message { get; set; }
    public CertificateDeploymentStatus Status { get; set; }
    public string? CertificateFingerprint { get; set; }
    public long? DurationMilliseconds { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
