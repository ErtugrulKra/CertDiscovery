using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Application.Dns;

public interface IDnsChallengeProviderResolver
{
    IDnsChallengeProvider Resolve(DnsProviderType providerType);
}

