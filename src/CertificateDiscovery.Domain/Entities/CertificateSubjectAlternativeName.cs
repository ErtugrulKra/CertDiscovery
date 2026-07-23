namespace CertificateDiscovery.Domain.Entities;

using CertificateDiscovery.Domain;

public sealed class CertificateSubjectAlternativeName
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CertificateId { get; set; }
    public Certificate Certificate { get; set; } = null!;
    public string Name { get; set; } = string.Empty;
    public CertificateSanType Type { get; set; } = CertificateSanType.DNS;
}
