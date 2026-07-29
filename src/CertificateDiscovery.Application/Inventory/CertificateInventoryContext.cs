using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Application.Inventory;

public sealed record CertificateInventoryContext(
    AcmeCertificateRequest Request,
    AcmeProvider? AcmeProvider,
    IReadOnlyList<string> Domains,
    string CertificatePem,
    string FullChainPem);

