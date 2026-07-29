namespace CertificateDiscovery.Domain.Entities;

public sealed class KubernetesCertificateSource
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid KubernetesClusterId { get; set; }
    public KubernetesCluster KubernetesCluster { get; set; } = null!;
    public Guid CertificateId { get; set; }
    public Certificate Certificate { get; set; } = null!;
    public string Namespace { get; set; } = string.Empty;
    public string SecretName { get; set; } = string.Empty;
    public DateTime FirstSeenAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAtUtc { get; set; } = DateTime.UtcNow;
}
