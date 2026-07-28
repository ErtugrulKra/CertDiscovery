namespace CertificateDiscovery.Domain.Entities;

public sealed class CertificateDeployment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CertificateRequestId { get; set; }
    public AcmeCertificateRequest CertificateRequest { get; set; } = null!;
    public Guid CertificateId { get; set; }
    public Certificate Certificate { get; set; } = null!;
    public Guid DeploymentTargetId { get; set; }
    public DeploymentTarget DeploymentTarget { get; set; } = null!;
    public Guid DeploymentPolicyId { get; set; }
    public DeploymentPolicy DeploymentPolicy { get; set; } = null!;
    public CertificateDeploymentStatus Status { get; set; } = CertificateDeploymentStatus.Pending;
    public DeploymentOrigin Origin { get; set; } = DeploymentOrigin.Manual;
    public int Attempt { get; set; }
    public string IdempotencyKey { get; set; } = string.Empty;
    public string? PreviousFingerprint { get; set; }
    public string ExpectedFingerprint { get; set; } = string.Empty;
    public string? ObservedFingerprint { get; set; }
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public string? BackupReference { get; set; }
    public string? RollbackStatus { get; set; }
    public string? VerificationStatus { get; set; }
    public string? RequestedBy { get; set; }
    public string? ApprovedBy { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
}
