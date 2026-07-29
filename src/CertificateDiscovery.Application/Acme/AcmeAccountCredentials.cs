namespace CertificateDiscovery.Application.Acme;

public sealed record AcmeAccountCredentials(
    Guid AccountId,
    string AccountLocation,
    string AccountKeyPem);

