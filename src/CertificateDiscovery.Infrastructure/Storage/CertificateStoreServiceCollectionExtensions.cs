using CertificateDiscovery.Application.Storage;
using Microsoft.Extensions.DependencyInjection;

namespace CertificateDiscovery.Infrastructure.Storage;

public static class CertificateStoreServiceCollectionExtensions
{
    public static IServiceCollection AddCertificateStores(this IServiceCollection services)
    {
        services.AddScoped<ICertificateStore, VaultKvCertificateStore>();
        return services;
    }
}

