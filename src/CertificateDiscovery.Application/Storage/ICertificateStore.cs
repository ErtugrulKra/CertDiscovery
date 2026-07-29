namespace CertificateDiscovery.Application.Storage;

public interface ICertificateStore
{
    Task<CertificateStoreResult> StoreAsync(CertificateStoreContext context, CancellationToken cancellationToken);
}

