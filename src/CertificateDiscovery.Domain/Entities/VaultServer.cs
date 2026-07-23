namespace CertificateDiscovery.Domain.Entities;

public sealed class VaultServer
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public Uri BaseUrl { get; set; } = new("https://vault.example.com");
    public string? Description { get; set; }
    public string? PkiMountPath { get; set; }
    public string? Token { get; set; }
    public bool ScanPublicEndpoint { get; set; } = true;
    public bool ImportPkiCertificates { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
    public DateTime? LastSyncAtUtc { get; set; }
    public string? LastSyncStatus { get; set; }
    public string? LastSyncError { get; set; }
}
