using CertificateDiscovery.Application.Dns;
using Microsoft.Extensions.DependencyInjection;

namespace CertificateDiscovery.Infrastructure.Dns;

public static class DnsServiceCollectionExtensions
{
    public static IServiceCollection AddDnsChallengeProviders(this IServiceCollection services)
    {
        services.AddScoped<IDnsChallengeProvider, ManualDnsChallengeProvider>();
        services.AddScoped<IDnsChallengeProvider, CloudflareDnsChallengeProvider>();
        services.AddScoped<IDnsChallengeProvider, Route53DnsChallengeProvider>();
        services.AddScoped<IDnsChallengeProvider, AzureDnsChallengeProvider>();
        services.AddSingleton<IDnsPropagationChecker, AuthoritativeDnsPropagationChecker>();
        services.AddScoped<IDnsChallengeProviderResolver, DnsChallengeProviderResolver>();
        return services;
    }
}
