using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Dns;
using Azure.ResourceManager.Dns.Models;
using CertificateDiscovery.Application.Dns;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Dns;

public sealed class AzureDnsChallengeProvider(
    ISecretProvider secretProvider,
    IDnsPropagationChecker propagationChecker) : IDnsChallengeProvider
{
    public DnsProviderType ProviderType => DnsProviderType.AzureDns;

    public async Task ValidateConfigurationAsync(DnsProvider provider, CancellationToken cancellationToken)
    {
        ValidateRequiredConfiguration(provider);
        var zone = await GetZoneAsync(provider, cancellationToken);
        _ = zone.Data.Name;
    }

    public async Task<DnsPublishResult> PublishAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken)
    {
        ValidateRequiredConfiguration(provider);
        var zone = await GetZoneAsync(provider, cancellationToken);
        var records = zone.GetDnsTxtRecords();
        foreach (var group in challenges.GroupBy(x => ToRelativeRecordName(x.Name, provider.ZoneName)))
        {
            var existing = await GetIfExistsAsync(records, group.Key, cancellationToken);
            var values = DnsTxtRecordSetSemantics.Merge(
                existing?.Data.DnsTxtRecords.SelectMany(x => x.Values) ?? [],
                group.Select(x => x.Value));
            var data = new DnsTxtRecordData { TtlInSeconds = existing?.Data.TtlInSeconds ?? provider.TtlSeconds };
            foreach (var value in values)
                data.DnsTxtRecords.Add(new DnsTxtRecordInfo { Values = { value } });
            await records.CreateOrUpdateAsync(
                WaitUntil.Completed,
                group.Key,
                data,
                existing?.Data.ETag,
                cancellationToken: cancellationToken);
        }
        return new(challenges.Count, $"Published {challenges.Count} Azure DNS TXT value(s) in zone {provider.ZoneName}.");
    }

    public Task<DnsPropagationResult> WaitForPropagationAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken) =>
        propagationChecker.WaitForAuthoritativeTxtAsync(provider.ZoneName, challenges,
            TimeSpan.FromSeconds(provider.PropagationTimeoutSeconds),
            TimeSpan.FromSeconds(provider.PropagationPollingIntervalSeconds), cancellationToken);

    public async Task<int> CleanupAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken)
    {
        ValidateRequiredConfiguration(provider);
        var zone = await GetZoneAsync(provider, cancellationToken);
        var records = zone.GetDnsTxtRecords();
        var removed = 0;
        foreach (var group in challenges.GroupBy(x => ToRelativeRecordName(x.Name, provider.ZoneName)))
        {
            var existing = await GetIfExistsAsync(records, group.Key, cancellationToken);
            if (existing is null) continue;
            var remaining = DnsTxtRecordSetSemantics.RemoveOwned(
                existing.Data.DnsTxtRecords.SelectMany(x => x.Values),
                group.Select(x => x.Value)).ToList();
            removed += existing.Data.DnsTxtRecords.SelectMany(x => x.Values).Count() - remaining.Count;
            if (remaining.Count == 0)
            {
                await existing.DeleteAsync(WaitUntil.Completed, existing.Data.ETag, cancellationToken);
                continue;
            }
            var data = new DnsTxtRecordData { TtlInSeconds = existing.Data.TtlInSeconds };
            foreach (var value in remaining)
                data.DnsTxtRecords.Add(new DnsTxtRecordInfo { Values = { value } });
            await records.CreateOrUpdateAsync(WaitUntil.Completed, group.Key, data, existing.Data.ETag, cancellationToken: cancellationToken);
        }
        return removed;
    }

    private async Task<DnsZoneResource> GetZoneAsync(DnsProvider provider, CancellationToken cancellationToken)
    {
        var credential = await CreateCredentialAsync(provider, cancellationToken);
        var arm = new ArmClient(credential, provider.SubscriptionId);
        var id = DnsZoneResource.CreateResourceIdentifier(provider.SubscriptionId!, provider.ResourceGroup!, provider.ZoneName);
        return (await arm.GetDnsZoneResource(id).GetAsync(cancellationToken)).Value;
    }

    private async Task<TokenCredential> CreateCredentialAsync(DnsProvider provider, CancellationToken cancellationToken) =>
        provider.AzureAuthenticationMode switch
        {
            AzureDnsAuthenticationMode.ManagedIdentity => string.IsNullOrWhiteSpace(provider.ManagedIdentityClientId)
                ? new ManagedIdentityCredential()
                : new ManagedIdentityCredential(provider.ManagedIdentityClientId),
            AzureDnsAuthenticationMode.WorkloadIdentity => new WorkloadIdentityCredential(new WorkloadIdentityCredentialOptions
            {
                TenantId = provider.TenantId,
                ClientId = provider.ClientId
            }),
            AzureDnsAuthenticationMode.ServicePrincipal => new ClientSecretCredential(
                provider.TenantId!,
                provider.ClientId!,
                await GetClientSecretAsync(provider, cancellationToken)),
            _ => new DefaultAzureCredential()
        };

    private async Task<string> GetClientSecretAsync(DnsProvider provider, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(provider.ClientSecretReference))
            throw new InvalidOperationException("Azure service-principal authentication requires a stored client-secret reference.");
        return await secretProvider.GetAsync(provider.ClientSecretReference, cancellationToken);
    }

    private static async Task<DnsTxtRecordResource?> GetIfExistsAsync(DnsTxtRecordCollection records, string name, CancellationToken cancellationToken)
    {
        if (!await records.ExistsAsync(name, cancellationToken)) return null;
        return (await records.GetAsync(name, cancellationToken)).Value;
    }

    private static void ValidateRequiredConfiguration(DnsProvider provider)
    {
        if (string.IsNullOrWhiteSpace(provider.SubscriptionId)) throw new InvalidOperationException("Azure subscription ID is required.");
        if (string.IsNullOrWhiteSpace(provider.ResourceGroup)) throw new InvalidOperationException("Azure resource group is required.");
        if (string.IsNullOrWhiteSpace(provider.ZoneName)) throw new InvalidOperationException("Azure DNS zone name is required.");
        if (provider.AzureAuthenticationMode == AzureDnsAuthenticationMode.ServicePrincipal &&
            (string.IsNullOrWhiteSpace(provider.TenantId) || string.IsNullOrWhiteSpace(provider.ClientId)))
            throw new InvalidOperationException("Azure service-principal authentication requires tenant ID and client ID.");
        if (provider.AzureAuthenticationMode == AzureDnsAuthenticationMode.WorkloadIdentity &&
            (string.IsNullOrWhiteSpace(provider.TenantId) || string.IsNullOrWhiteSpace(provider.ClientId)))
            throw new InvalidOperationException("Azure workload identity requires tenant ID and client ID.");
    }

    public static string ToRelativeRecordName(string fqdn, string zoneName)
    {
        var name = fqdn.Trim().TrimEnd('.').ToLowerInvariant();
        var zone = zoneName.Trim().TrimEnd('.').ToLowerInvariant();
        if (name == zone) return "@";
        var suffix = "." + zone;
        if (!name.EndsWith(suffix, StringComparison.Ordinal))
            throw new InvalidOperationException($"TXT record '{fqdn}' is outside Azure DNS zone '{zoneName}'.");
        return name[..^suffix.Length];
    }
}
