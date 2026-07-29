namespace CertificateDiscovery.Application.Acme;

public sealed record AcmeOrderContext(
    string AccountKeyPem,
    string OrderLocation,
    IReadOnlyList<AcmeChallengeResult> Challenges);

