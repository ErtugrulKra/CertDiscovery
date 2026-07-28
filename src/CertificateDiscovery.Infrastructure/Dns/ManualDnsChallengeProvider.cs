using CertificateDiscovery.Application.Dns;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Dns;

public sealed class ManualDnsChallengeProvider : IDnsChallengeProvider
{
    public DnsProviderType ProviderType => DnsProviderType.Generic;

    public Task ValidateConfigurationAsync(DnsProvider provider, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<DnsPublishResult> PublishAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken) =>
        Task.FromResult(new DnsPublishResult(0, "Manual DNS publication is required."));

    public Task<DnsPropagationResult> WaitForPropagationAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken) =>
        Task.FromResult(new DnsPropagationResult(false, [], "Manual DNS propagation must be confirmed by the operator."));

    public Task<int> CleanupAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken) =>
        Task.FromResult(0);
}
