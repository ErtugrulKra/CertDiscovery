namespace CertificateDiscovery.Domain.Entities;

public sealed class DeploymentAgent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public string AgentType { get; set; } = "MicrosoftIis";
    public string Version { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public string CapabilitiesJson { get; set; } = "[]";
    public DeploymentAgentStatus Status { get; set; } = DeploymentAgentStatus.Online;
    public string AuthenticationTokenHash { get; set; } = string.Empty;
    public string? PublicKeyPem { get; set; }
    public DateTime LastHeartbeatAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime RegisteredAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? RevokedAtUtc { get; set; }
    public DateTime? UpdatedAtUtc { get; set; }
    public ICollection<DeploymentTarget> DeploymentTargets { get; set; } = new List<DeploymentTarget>();
}
