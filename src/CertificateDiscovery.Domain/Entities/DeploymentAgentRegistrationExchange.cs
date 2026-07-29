namespace CertificateDiscovery.Domain.Entities;

public sealed class DeploymentAgentRegistrationExchange
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string ExchangeSecretHash { get; set; } = string.Empty;
    public string UserCode { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public string CapabilitiesJson { get; set; } = "[]";
    public string PublicKeyPem { get; set; } = string.Empty;
    public string PublicKeyFingerprint { get; set; } = string.Empty;
    public DeploymentAgentExchangeStatus Status { get; set; } = DeploymentAgentExchangeStatus.Pending;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public string? ApprovedBy { get; set; }
    public DateTime? RejectedAtUtc { get; set; }
    public string? RejectedBy { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public Guid? RegisteredAgentId { get; set; }
    public DeploymentAgent? RegisteredAgent { get; set; }
}
