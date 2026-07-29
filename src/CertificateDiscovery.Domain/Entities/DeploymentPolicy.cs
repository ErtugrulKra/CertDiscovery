namespace CertificateDiscovery.Domain.Entities;

public sealed class DeploymentPolicy
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public bool RequireApproval { get; set; } = true;
    public bool AutomaticDeployment { get; set; }
    public int MaxAttempts { get; set; } = 3;
    public int RetryDelaySeconds { get; set; } = 60;
    public bool RollbackOnFailure { get; set; } = true;
    public int VerificationTimeoutSeconds { get; set; } = 120;
    public VerificationQuorumMode VerificationQuorumMode { get; set; } = VerificationQuorumMode.All;
    public int VerificationQuorumPercentage { get; set; } = 100;
    public int VerificationMinimumSuccessfulNodes { get; set; } = 1;
    public int VerificationAttempts { get; set; } = 1;
    public int VerificationIntervalSeconds { get; set; } = 5;
    public bool RollbackOnPartialVerification { get; set; } = true;
    public string? DeploymentWindow { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
}
