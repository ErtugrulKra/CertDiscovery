using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Application.Acme;

public interface IAcmeCertificateClient
{
    Task TestDirectoryAsync(AcmeProvider provider, CancellationToken cancellationToken);
    Task TestAccountAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken);
    Task<string> RotateAccountKeyAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken);

    Task<AcmeAccountRegistration> RegisterAccountAsync(
        AcmeProvider provider,
        string? eabKeyId,
        string? eabHmacKey,
        CancellationToken cancellationToken);

    Task<AcmeOrderContext> CreateOrderAsync(
        AcmeProvider provider,
        AcmeAccountCredentials account,
        IReadOnlyList<string> domains,
        CancellationToken cancellationToken);

    Task<IssuedCertificateBundle> ValidateAndFinalizeAsync(
        AcmeProvider provider,
        AcmeAccountCredentials account,
        AcmeOrderContext order,
        string commonName,
        CancellationToken cancellationToken);

    Task RevokeAsync(
        AcmeProvider provider,
        string accountKeyPem,
        string certificatePem,
        CancellationToken cancellationToken);
}
