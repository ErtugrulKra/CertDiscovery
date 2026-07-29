namespace CertificateDiscovery.Application.Secrets;

public interface ISecretProvider
{
    Task<string> StoreAsync(string purpose, string value, CancellationToken cancellationToken);
    Task<string> GetAsync(string secretReference, CancellationToken cancellationToken);
    Task DeleteAsync(string secretReference, CancellationToken cancellationToken);
}

