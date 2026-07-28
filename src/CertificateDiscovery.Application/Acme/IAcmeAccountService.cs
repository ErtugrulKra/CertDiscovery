using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Application.Acme;

public interface IAcmeAccountService
{
    Task<AcmeAccountCredentials> GetOrCreateAsync(AcmeProvider provider, CancellationToken cancellationToken);
    Task<AcmeAccountCredentials> GetCredentialsAsync(Guid accountId, CancellationToken cancellationToken);
    Task DisableAsync(Guid accountId, CancellationToken cancellationToken);
    Task RotateKeyAsync(Guid accountId, CancellationToken cancellationToken);
}
