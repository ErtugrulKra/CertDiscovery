namespace CertificateDiscovery.Domain.Entities;

public sealed class DeploymentTarget
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public DeploymentTargetType TargetType { get; set; } = DeploymentTargetType.Fake;
    public Guid? AssetId { get; set; }
    public Asset? Asset { get; set; }
    public string ConfigurationJson { get; set; } = "{}";
    public string? SecretReference { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
}
