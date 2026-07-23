namespace CertificateDiscovery.Domain.Entities;

public sealed class CertificateChainEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CertificateId { get; set; }
    public int Position { get; set; }
    public string FingerprintSha256 { get; set; } = string.Empty;
    public string? SerialNumber { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string? CommonName { get; set; }
    public string Issuer { get; set; } = string.Empty;
    public DateTime NotBeforeUtc { get; set; }
    public DateTime NotAfterUtc { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public string? PublicKeyAlgorithm { get; set; }
    public int? PublicKeySize { get; set; }
    public int? Version { get; set; }
    public bool IsSelfSigned { get; set; }
    public string? PemEncodedCertificate { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAtUtc { get; set; } = DateTime.UtcNow;

    public Certificate Certificate { get; set; } = null!;
}
