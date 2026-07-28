namespace CertificateDiscovery.Application.Acme;

public sealed record IssuedCertificateBundle(
    string CertificatePem,
    string FullChainPem,
    string PrivateKeyPem);

