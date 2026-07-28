using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Application.Dns;

public interface IDnsChallengeProvider
{
    DnsProviderType ProviderType { get; }
    Task ValidateConfigurationAsync(DnsProvider provider, CancellationToken cancellationToken);
    Task<DnsPublishResult> PublishAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken);
    Task<DnsPropagationResult> WaitForPropagationAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken);
    Task<int> CleanupAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken);
}
