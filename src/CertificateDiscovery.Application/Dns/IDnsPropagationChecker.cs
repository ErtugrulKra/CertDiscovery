namespace CertificateDiscovery.Application.Dns;

public interface IDnsPropagationChecker
{
    Task<DnsPropagationResult> WaitForAuthoritativeTxtAsync(
        string zoneName,
        IReadOnlyList<DnsTxtChallenge> challenges,
        TimeSpan timeout,
        TimeSpan pollingInterval,
        CancellationToken cancellationToken);
}
