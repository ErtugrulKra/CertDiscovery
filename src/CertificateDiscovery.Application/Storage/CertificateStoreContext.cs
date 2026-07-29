using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Application.Storage;

public sealed record CertificateStoreContext(
    AcmeCertificateRequest Request,
    VaultServer VaultServer,
    AcmeProvider? AcmeProvider,
    IReadOnlyList<string> Domains,
    string CertificatePem,
    string PrivateKeyPem,
    string FullChainPem,
    string Fingerprint);
