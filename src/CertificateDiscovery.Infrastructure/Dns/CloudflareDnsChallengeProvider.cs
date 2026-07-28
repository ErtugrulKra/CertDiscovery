using System.Net.Http.Json;
using System.Text.Json;
using CertificateDiscovery.Application.Dns;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Dns;

public sealed class CloudflareDnsChallengeProvider(
    IHttpClientFactory httpClientFactory,
    ISecretProvider secretProvider,
    IDnsPropagationChecker propagationChecker) : IDnsChallengeProvider
{
    public CloudflareDnsChallengeProvider(IHttpClientFactory httpClientFactory)
        : this(httpClientFactory, new LegacyInlineSecretProvider(), new ImmediatePropagationChecker())
    {
    }

    public DnsProviderType ProviderType => DnsProviderType.Cloudflare;

    public async Task ValidateConfigurationAsync(DnsProvider provider, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(provider.ApiTokenSecretReference) && string.IsNullOrWhiteSpace(provider.ApiToken))
            throw new InvalidOperationException("Cloudflare API token is required.");
        if (string.IsNullOrWhiteSpace(provider.ZoneName)) throw new InvalidOperationException("Cloudflare zone name is required.");
        using var client = await CreateClientAsync(provider, cancellationToken);
        _ = await GetZoneIdAsync(client, provider.ZoneName, cancellationToken);
    }

    public async Task<DnsPublishResult> PublishAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken)
    {
        await ValidateConfigurationAsync(provider, cancellationToken);
        using var client = await CreateClientAsync(provider, cancellationToken);
        var zoneId = await GetZoneIdAsync(client, provider.ZoneName, cancellationToken);
        foreach (var challenge in challenges)
        {
            var existingId = (await GetTxtRecordIdsAsync(client, zoneId, challenge, cancellationToken)).FirstOrDefault();
            var payload = new { type = "TXT", name = challenge.Name, content = challenge.Value, ttl = provider.TtlSeconds };
            using var response = existingId is null
                ? await client.PostAsJsonAsync($"zones/{zoneId}/dns_records", payload, cancellationToken)
                : await client.PutAsJsonAsync($"zones/{zoneId}/dns_records/{existingId}", payload, cancellationToken);
            await EnsureSuccessAsync(response, cancellationToken);
        }

        return new DnsPublishResult(challenges.Count, $"Published {challenges.Count} TXT record(s)");
    }

    public Task<DnsPropagationResult> WaitForPropagationAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken) =>
        propagationChecker.WaitForAuthoritativeTxtAsync(
            provider.ZoneName,
            challenges,
            TimeSpan.FromSeconds(provider.PropagationTimeoutSeconds),
            TimeSpan.FromSeconds(provider.PropagationPollingIntervalSeconds),
            cancellationToken);

    public async Task<int> CleanupAsync(DnsProvider provider, IReadOnlyList<DnsTxtChallenge> challenges, CancellationToken cancellationToken)
    {
        await ValidateConfigurationAsync(provider, cancellationToken);
        using var client = await CreateClientAsync(provider, cancellationToken);
        var zoneId = await GetZoneIdAsync(client, provider.ZoneName, cancellationToken);
        var deleted = 0;
        foreach (var challenge in challenges)
        {
            foreach (var id in await GetTxtRecordIdsAsync(client, zoneId, challenge, cancellationToken))
            {
                using var response = await client.DeleteAsync($"zones/{zoneId}/dns_records/{id}", cancellationToken);
                await EnsureSuccessAsync(response, cancellationToken);
                deleted++;
            }
        }

        return deleted;
    }

    private async Task<HttpClient> CreateClientAsync(DnsProvider provider, CancellationToken cancellationToken)
    {
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = new Uri("https://api.cloudflare.com/client/v4/");
        var token = !string.IsNullOrWhiteSpace(provider.ApiTokenSecretReference)
            ? await secretProvider.GetAsync(provider.ApiTokenSecretReference, cancellationToken)
            : provider.ApiToken!;
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task<string> GetZoneIdAsync(HttpClient client, string zoneName, CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync($"zones?name={Uri.EscapeDataString(zoneName)}&status=active", cancellationToken);
        using var document = await ReadResponseAsync(response, cancellationToken);
        var result = document.RootElement.GetProperty("result");
        if (result.GetArrayLength() == 0) throw new InvalidOperationException($"Cloudflare zone '{zoneName}' was not found or is not active.");
        return result[0].GetProperty("id").GetString()!;
    }

    private static async Task<List<string>> GetTxtRecordIdsAsync(HttpClient client, string zoneId, DnsTxtChallenge challenge, CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync($"zones/{zoneId}/dns_records?type=TXT&name={Uri.EscapeDataString(challenge.Name)}", cancellationToken);
        using var document = await ReadResponseAsync(response, cancellationToken);
        return document.RootElement.GetProperty("result").EnumerateArray()
            .Where(x => string.Equals(x.GetProperty("content").GetString(), challenge.Value, StringComparison.Ordinal))
            .Select(x => x.GetProperty("id").GetString())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Cast<string>()
            .ToList();
    }

    private static async Task<JsonDocument> ReadResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        var document = JsonDocument.Parse(content);
        if (!response.IsSuccessStatusCode || !document.RootElement.TryGetProperty("success", out var success) || !success.GetBoolean())
        {
            var message = TryGetError(document) ?? response.ReasonPhrase ?? "Cloudflare API request failed.";
            document.Dispose();
            throw new InvalidOperationException(message);
        }

        return document;
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var document = await ReadResponseAsync(response, cancellationToken);
    }

    private static string? TryGetError(JsonDocument document)
    {
        if (!document.RootElement.TryGetProperty("errors", out var errors) || errors.ValueKind != JsonValueKind.Array || errors.GetArrayLength() == 0) return null;
        var first = errors[0];
        return first.TryGetProperty("message", out var message) ? message.GetString() : first.ToString();
    }

    private sealed class LegacyInlineSecretProvider : ISecretProvider
    {
        public Task<string> StoreAsync(string purpose, string value, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<string> GetAsync(string secretReference, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task DeleteAsync(string secretReference, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class ImmediatePropagationChecker : IDnsPropagationChecker
    {
        public Task<DnsPropagationResult> WaitForAuthoritativeTxtAsync(string zoneName, IReadOnlyList<DnsTxtChallenge> challenges, TimeSpan timeout, TimeSpan pollingInterval, CancellationToken cancellationToken) =>
            Task.FromResult(new DnsPropagationResult(true, challenges.Select(x => x.Value).ToList()));
    }
}
