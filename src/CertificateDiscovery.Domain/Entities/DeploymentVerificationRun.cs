namespace CertificateDiscovery.Domain.Entities;

public sealed class DeploymentVerificationRun
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CertificateDeploymentId { get; set; }
    public CertificateDeployment CertificateDeployment { get; set; } = null!;
    public int Attempt { get; set; }
    public bool IsRollbackVerification { get; set; }
    public VerificationQuorumMode QuorumMode { get; set; }
    public int QuorumPercentage { get; set; }
    public int MinimumSuccessfulNodes { get; set; }
    public int TotalNodes { get; set; }
    public int SuccessfulNodes { get; set; }
    public int FailedNodes { get; set; }
    public int DistinctFingerprints { get; set; }
    public DeploymentVerificationOutcome Outcome { get; set; }
    public string? Summary { get; set; }
    public DateTime StartedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAtUtc { get; set; }
    public long? DurationMilliseconds { get; set; }
    public ICollection<DeploymentEndpointVerification> Endpoints { get; set; } = new List<DeploymentEndpointVerification>();
}

public sealed class DeploymentEndpointVerification
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DeploymentVerificationRunId { get; set; }
    public DeploymentVerificationRun DeploymentVerificationRun { get; set; } = null!;
    public string Endpoint { get; set; } = string.Empty;
    public string? ObservedAddress { get; set; }
    public string ExpectedFingerprint { get; set; } = string.Empty;
    public string? ObservedFingerprint { get; set; }
    public string? Subject { get; set; }
    public string? Issuer { get; set; }
    public DateTime? NotBeforeUtc { get; set; }
    public DateTime? NotAfterUtc { get; set; }
    public string SubjectAlternativeNamesJson { get; set; } = "[]";
    public bool FingerprintMatches { get; set; }
    public bool SanMatches { get; set; }
    public bool TimeValid { get; set; }
    public bool ChainValid { get; set; }
    public string PublicChainJson { get; set; } = "[]";
    public EndpointVerificationOutcome Outcome { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public long DurationMilliseconds { get; set; }
    public DateTime ObservedAtUtc { get; set; } = DateTime.UtcNow;
}
