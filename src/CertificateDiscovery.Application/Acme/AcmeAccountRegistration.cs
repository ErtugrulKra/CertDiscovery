namespace CertificateDiscovery.Application.Acme;

public sealed record AcmeAccountRegistration(
    string AccountLocation,
    string AccountKeyPem);

