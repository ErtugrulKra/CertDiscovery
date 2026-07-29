using Amazon;
using Amazon.Route53;
using Amazon.Route53.Model;
using Amazon.Runtime;
using Amazon.Runtime.Credentials;
using CertificateDiscovery.Application.Dns;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Dns;

public sealed class Route53DnsChallengeProvider(
    ISecretProvider secretProvider,
    IDnsPropagationChecker propagationChecker) : IDnsChallengeProvider
{
    public DnsProviderType ProviderType => DnsProviderType.Route53;

    public async Task ValidateConfigurationAsync(DnsProvider provider, CancellationToken cancellationToken)
    {
        ValidateRequiredConfiguration(provider);
        using var client = await CreateClientAsync(provider, cancellationToken);
        _ = await ResolveHostedZoneAsync(client, provider, cancellationToken);
    }

    public async Task<DnsPublishResult> PublishAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken)
    {
        ValidateRequiredConfiguration(provider);
        using var client = await CreateClientAsync(provider, cancellationToken);
        var zone = await ResolveHostedZoneAsync(client, provider, cancellationToken);
        var changes = new List<Change>();

        foreach (var group in challenges.GroupBy(x => NormalizeName(x.Name)))
        {
            var existing = await GetTxtRecordSetAsync(client, zone.Id, group.Key, cancellationToken);
            var values = DnsTxtRecordSetSemantics.Merge(
                existing?.ResourceRecords.Select(x => Unquote(x.Value)) ?? [],
                group.Select(x => x.Value));
            changes.Add(new Change
            {
                Action = ChangeAction.UPSERT,
                ResourceRecordSet = new ResourceRecordSet
                {
                    Name = group.Key,
                    Type = RRType.TXT,
                    TTL = existing?.TTL ?? provider.TtlSeconds,
                    ResourceRecords = values.Select(x => new ResourceRecord { Value = Quote(x) }).ToList()
                }
            });
        }

        if (changes.Count > 0)
        {
            var response = await client.ChangeResourceRecordSetsAsync(new ChangeResourceRecordSetsRequest
            {
                HostedZoneId = zone.Id,
                ChangeBatch = new ChangeBatch { Comment = "CertDiscovery ACME DNS-01", Changes = changes }
            }, cancellationToken);
            await WaitForChangeAsync(client, response.ChangeInfo.Id, provider, cancellationToken);
        }
        return new(challenges.Count, $"Published {challenges.Count} Route53 TXT value(s) in zone {zone.Name}.");
    }

    public Task<DnsPropagationResult> WaitForPropagationAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken) =>
        propagationChecker.WaitForAuthoritativeTxtAsync(provider.ZoneName, challenges,
            TimeSpan.FromSeconds(provider.PropagationTimeoutSeconds),
            TimeSpan.FromSeconds(provider.PropagationPollingIntervalSeconds), cancellationToken);

    public async Task<int> CleanupAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken)
    {
        ValidateRequiredConfiguration(provider);
        using var client = await CreateClientAsync(provider, cancellationToken);
        var zone = await ResolveHostedZoneAsync(client, provider, cancellationToken);
        var changes = new List<Change>();
        var removed = 0;
        foreach (var group in challenges.GroupBy(x => NormalizeName(x.Name)))
        {
            var existing = await GetTxtRecordSetAsync(client, zone.Id, group.Key, cancellationToken);
            if (existing is null) continue;
            var remaining = DnsTxtRecordSetSemantics.RemoveOwned(
                existing.ResourceRecords.Select(x => Unquote(x.Value)),
                group.Select(x => x.Value)).ToList();
            removed += existing.ResourceRecords.Count - remaining.Count;
            changes.Add(new Change
            {
                Action = remaining.Count == 0 ? ChangeAction.DELETE : ChangeAction.UPSERT,
                ResourceRecordSet = remaining.Count == 0
                    ? existing
                    : new ResourceRecordSet
                    {
                        Name = existing.Name, Type = RRType.TXT, TTL = existing.TTL,
                        ResourceRecords = remaining.Select(x => new ResourceRecord { Value = Quote(x) }).ToList()
                    }
            });
        }
        if (changes.Count > 0)
        {
            var response = await client.ChangeResourceRecordSetsAsync(new ChangeResourceRecordSetsRequest
            {
                HostedZoneId = zone.Id,
                ChangeBatch = new ChangeBatch { Comment = "CertDiscovery ACME DNS-01 cleanup", Changes = changes }
            }, cancellationToken);
            await WaitForChangeAsync(client, response.ChangeInfo.Id, provider, cancellationToken);
        }
        return removed;
    }

    private async Task<IAmazonRoute53> CreateClientAsync(DnsProvider provider, CancellationToken cancellationToken)
    {
        var config = new AmazonRoute53Config();
        if (!string.IsNullOrWhiteSpace(provider.Region))
            config.RegionEndpoint = RegionEndpoint.GetBySystemName(provider.Region);

        AWSCredentials? credentials = provider.AwsAuthenticationMode switch
        {
            AwsDnsAuthenticationMode.StaticCredentials => await CreateStaticCredentialsAsync(provider, cancellationToken),
            AwsDnsAuthenticationMode.AssumeRole => new AssumeRoleAWSCredentials(
                DefaultAWSCredentialsIdentityResolver.GetCredentials(config),
                provider.RoleArn!,
                $"certdiscovery-{provider.Id:N}"),
            _ => null
        };
        return credentials is null ? new AmazonRoute53Client(config) : new AmazonRoute53Client(credentials, config);
    }

    private async Task<AWSCredentials> CreateStaticCredentialsAsync(DnsProvider provider, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(provider.AccessKeySecretReference) || string.IsNullOrWhiteSpace(provider.SecretKeySecretReference))
            throw new InvalidOperationException("Static AWS authentication requires stored access-key and secret-key references.");
        var accessKey = await secretProvider.GetAsync(provider.AccessKeySecretReference, cancellationToken);
        var secretKey = await secretProvider.GetAsync(provider.SecretKeySecretReference, cancellationToken);
        if (string.IsNullOrWhiteSpace(provider.SessionTokenSecretReference))
            return new BasicAWSCredentials(accessKey, secretKey);
        var sessionToken = await secretProvider.GetAsync(provider.SessionTokenSecretReference, cancellationToken);
        return new SessionAWSCredentials(accessKey, secretKey, sessionToken);
    }

    private static async Task<HostedZone> ResolveHostedZoneAsync(IAmazonRoute53 client, DnsProvider provider, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(provider.HostedZoneId))
            return (await client.GetHostedZoneAsync(new GetHostedZoneRequest { Id = provider.HostedZoneId }, cancellationToken)).HostedZone;

        var normalizedZone = NormalizeName(provider.ZoneName);
        var response = await client.ListHostedZonesByNameAsync(new ListHostedZonesByNameRequest
        {
            DNSName = normalizedZone,
            MaxItems = "100"
        }, cancellationToken);
        return SelectHostedZone(response.HostedZones, provider);
    }

    internal static HostedZone SelectHostedZone(IEnumerable<HostedZone> hostedZones, DnsProvider provider)
    {
        var normalizedZone = NormalizeName(provider.ZoneName);
        var matches = hostedZones.Where(x => NormalizeName(x.Name) == normalizedZone).ToList();
        if (matches.Count == 0) throw new InvalidOperationException($"Route53 hosted zone '{provider.ZoneName}' was not found.");
        if (matches.Count > 1)
            throw new InvalidOperationException($"Route53 hosted zone '{provider.ZoneName}' is ambiguous (public/private or duplicate zones). Configure HostedZoneId explicitly.");
        return matches[0];
    }

    private static async Task<ResourceRecordSet?> GetTxtRecordSetAsync(IAmazonRoute53 client, string zoneId, string name, CancellationToken cancellationToken)
    {
        var response = await client.ListResourceRecordSetsAsync(new ListResourceRecordSetsRequest
        {
            HostedZoneId = zoneId,
            StartRecordName = name,
            StartRecordType = RRType.TXT,
            MaxItems = "1"
        }, cancellationToken);
        return response.ResourceRecordSets.FirstOrDefault(x => x.Type == RRType.TXT && NormalizeName(x.Name) == NormalizeName(name));
    }

    private static async Task WaitForChangeAsync(IAmazonRoute53 client, string changeId, DnsProvider provider, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow.AddSeconds(provider.PropagationTimeoutSeconds);
        while (DateTime.UtcNow <= deadline)
        {
            var response = await client.GetChangeAsync(new GetChangeRequest { Id = changeId }, cancellationToken);
            if (response.ChangeInfo.Status == ChangeStatus.INSYNC) return;
            await Task.Delay(TimeSpan.FromSeconds(provider.PropagationPollingIntervalSeconds), cancellationToken);
        }
        throw new TimeoutException("Route53 change did not reach INSYNC before the configured timeout.");
    }

    internal static void ValidateRequiredConfiguration(DnsProvider provider)
    {
        if (string.IsNullOrWhiteSpace(provider.ZoneName)) throw new InvalidOperationException("Route53 zone name is required.");
        if (provider.AwsAuthenticationMode == AwsDnsAuthenticationMode.AssumeRole && string.IsNullOrWhiteSpace(provider.RoleArn))
            throw new InvalidOperationException("Route53 assume-role authentication requires a role ARN.");
        if (provider.AwsAuthenticationMode == AwsDnsAuthenticationMode.StaticCredentials &&
            (string.IsNullOrWhiteSpace(provider.AccessKeySecretReference) ||
             string.IsNullOrWhiteSpace(provider.SecretKeySecretReference)))
            throw new InvalidOperationException(
                "Route53 static authentication requires stored access-key and secret-key references.");
    }

    internal static string NormalizeName(string value) => value.Trim().TrimStart('*', '.').TrimEnd('.').ToLowerInvariant();
    public static string Quote(string value) => $"\"{value.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"";
    public static string Unquote(string value) =>
        value.Length >= 2 && value[0] == '"' && value[^1] == '"'
            ? value[1..^1].Replace("\\\"", "\"").Replace("\\\\", "\\")
            : value;
}
