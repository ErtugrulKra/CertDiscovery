namespace CertificateDiscovery.Domain.Entities;

public sealed class DeploymentJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CertificateDeploymentId { get; set; }
    public CertificateDeployment CertificateDeployment { get; set; } = null!;
    public string IdempotencyKey { get; set; } = string.Empty;
    public DeploymentJobStatus Status { get; set; } = DeploymentJobStatus.Pending;
    public string? ClaimOwner { get; set; }
    public DateTime? LeaseExpiresAtUtc { get; set; }
    public int RetryCount { get; set; }
    public DateTime NextAttemptAtUtc { get; set; } = DateTime.UtcNow;
    public string? LastError { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAtUtc { get; set; }
}
