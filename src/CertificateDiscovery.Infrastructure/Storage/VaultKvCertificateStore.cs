using System.Net.Http.Json;
using System.Text.Json;
using CertificateDiscovery.Application.Storage;

namespace CertificateDiscovery.Infrastructure.Storage;

public sealed class VaultKvCertificateStore(IHttpClientFactory httpClientFactory) : ICertificateStore
{
    public async Task<CertificateStoreResult> StoreAsync(CertificateStoreContext context, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(context.VaultServer.Token)) throw new InvalidOperationException("Vault token is required to store certificates.");
        var (mount, path) = SplitVaultKvPath(context.Request.VaultSecretPath);
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = context.VaultServer.BaseUrl;
        client.DefaultRequestHeaders.Add("X-Vault-Token", context.VaultServer.Token);
        var payload = new
        {
            data = new
            {
                domain = context.Request.Domain,
                sans = context.Domains,
                certificate_pem = context.CertificatePem,
                private_key_pem = context.PrivateKeyPem,
                fullchain_pem = context.FullChainPem,
                fingerprint_sha256 = context.Fingerprint,
                acme_provider = context.AcmeProvider?.Name,
                issued_at_utc = context.Request.IssuedAtUtc,
                certificate_request_id = context.Request.Id
            }
        };
        using var response = await client.PostAsJsonAsync($"/v1/{mount}/data/{path}", payload, cancellationToken);
        response.EnsureSuccessStatusCode();
        using var responseBody = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        var version = responseBody.RootElement.TryGetProperty("data", out var data) &&
                      data.TryGetProperty("version", out var versionElement)
            ? versionElement.GetInt32()
            : (int?)null;
        return new CertificateStoreResult(context.Request.VaultSecretPath, DateTime.UtcNow, version);
    }

    private static (string Mount, string Path) SplitVaultKvPath(string value)
    {
        var parts = value.Trim().Trim('/').Split('/', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2) throw new InvalidOperationException("Vault secret path must be in '<mount>/<path>' format, for example secret/certificates/example.com.");
        return (parts[0], parts[1].StartsWith("data/", StringComparison.OrdinalIgnoreCase) ? parts[1][5..] : parts[1]);
    }
}
