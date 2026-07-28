namespace CertificateDiscovery.Application.Inventory;

public interface ICertificateInventoryWriter
{
    Task<Guid> UpsertAsync(CertificateInventoryContext context, CancellationToken cancellationToken);
}

