namespace CertificateDiscovery.Domain.Entities;

public sealed class AgentDeploymentJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DeploymentAgentId { get; set; }
    public DeploymentAgent DeploymentAgent { get; set; } = null!;
    public Guid CertificateDeploymentId { get; set; }
    public CertificateDeployment CertificateDeployment { get; set; } = null!;
    public AgentDeploymentJobStatus Status { get; set; } = AgentDeploymentJobStatus.Pending;
    public string TargetConfigurationJson { get; set; } = "{}";
    public string? LeaseTokenHash { get; set; }
    public DateTime? LeaseExpiresAtUtc { get; set; }
    public int Attempt { get; set; }
    public string? Stage { get; set; }
    public string? ObservedFingerprint { get; set; }
    public string? PreviousFingerprint { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ClaimedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public DateTime? UpdatedAtUtc { get; set; }
}
