using CertificateDiscovery.Application.Acme;
using Microsoft.Extensions.DependencyInjection;

namespace CertificateDiscovery.Infrastructure.Acme;

public static class AcmeServiceCollectionExtensions
{
    public static IServiceCollection AddAcmeServices(this IServiceCollection services)
    {
        services.AddScoped<IAcmeCertificateClient, CertesAcmeCertificateClient>();
        return services;
    }
}

