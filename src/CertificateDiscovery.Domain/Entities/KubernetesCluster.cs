namespace CertificateDiscovery.Domain.Entities;

public sealed class KubernetesCluster
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public Uri ApiServer { get; set; } = new("https://kubernetes.default.svc");
    public string? Description { get; set; }
    public string? Namespaces { get; set; }
    public string? BearerTokenSecretReference { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
    public DateTime? LastSyncAtUtc { get; set; }
    public string? LastSyncStatus { get; set; }
    public string? LastSyncError { get; set; }
}
