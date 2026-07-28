using CertificateDiscovery.Application.Dns;
using DnsClient;
using DnsClient.Protocol;

namespace CertificateDiscovery.Infrastructure.Dns;

public sealed class AuthoritativeDnsPropagationChecker : IDnsPropagationChecker
{
    public async Task<DnsPropagationResult> WaitForAuthoritativeTxtAsync(
        string zoneName,
        IReadOnlyList<DnsTxtChallenge> challenges,
        TimeSpan timeout,
        TimeSpan pollingInterval,
        CancellationToken cancellationToken)
    {
        if (challenges.Count == 0) return new(true, []);
        var deadline = DateTime.UtcNow.Add(timeout);
        var expected = challenges.GroupBy(x => NormalizeName(x.Name))
            .ToDictionary(x => x.Key, x => x.Select(y => y.Value).ToHashSet(StringComparer.Ordinal));
        IReadOnlyList<string> lastObserved = [];

        while (DateTime.UtcNow <= deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var lookup = await CreateAuthoritativeClientAsync(zoneName, cancellationToken);
            var observed = new List<string>();
            var complete = true;
            foreach (var item in expected)
            {
                var response = await lookup.QueryAsync(item.Key, QueryType.TXT, cancellationToken: cancellationToken);
                var values = response.Answers.TxtRecords()
                    .SelectMany(x => x.Text)
                    .ToHashSet(StringComparer.Ordinal);
                observed.AddRange(values);
                complete &= item.Value.IsSubsetOf(values);
            }

            lastObserved = observed.Distinct(StringComparer.Ordinal).ToList();
            if (complete)
                return new(true, lastObserved, "All expected TXT values were observed on authoritative DNS.");

            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero) break;
            await Task.Delay(remaining < pollingInterval ? remaining : pollingInterval, cancellationToken);
        }

        return new(false, lastObserved,
            $"DNS propagation timed out. Expected: {string.Join(", ", challenges.Select(x => x.Value).Distinct())}; observed: {string.Join(", ", lastObserved)}.");
    }

    private static async Task<LookupClient> CreateAuthoritativeClientAsync(string zoneName, CancellationToken cancellationToken)
    {
        var bootstrap = new LookupClient(new LookupClientOptions { UseCache = false });
        var nsResponse = await bootstrap.QueryAsync(NormalizeName(zoneName), QueryType.NS, cancellationToken: cancellationToken);
        var nameServers = nsResponse.Answers.NsRecords().Select(x => x.NSDName.Value).Distinct().ToList();
        if (nameServers.Count == 0)
            throw new InvalidOperationException($"No authoritative name servers were found for DNS zone '{zoneName}'.");

        var endpoints = new List<System.Net.IPAddress>();
        foreach (var nameServer in nameServers)
        {
            var addresses = await System.Net.Dns.GetHostAddressesAsync(nameServer, cancellationToken);
            endpoints.AddRange(addresses);
        }
        if (endpoints.Count == 0)
            throw new InvalidOperationException($"Authoritative name servers for DNS zone '{zoneName}' could not be resolved.");

        return new LookupClient(new LookupClientOptions(endpoints.Distinct().ToArray())
        {
            UseCache = false,
            Retries = 1,
            Timeout = TimeSpan.FromSeconds(5)
        });
    }

    private static string NormalizeName(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
}
