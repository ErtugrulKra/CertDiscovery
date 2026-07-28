using CertificateDiscovery.Application.Dns;
using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Infrastructure.Dns;

public sealed class DnsChallengeProviderResolver(IEnumerable<IDnsChallengeProvider> providers) : IDnsChallengeProviderResolver
{
    private readonly IReadOnlyDictionary<DnsProviderType, IDnsChallengeProvider> providers =
        providers.ToDictionary(x => x.ProviderType);

    public IDnsChallengeProvider Resolve(DnsProviderType providerType) =>
        providers.TryGetValue(providerType, out var provider)
            ? provider
            : throw new NotSupportedException($"DNS provider type {providerType} is not supported.");
}

