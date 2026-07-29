using System.Net;
using System.Text.Json;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class VaultSshCredentialSource(IHttpClientFactory httpClientFactory) : ISshCredentialSource
{
    public async Task<SshPrivateKeyCredential> LoadAsync(
        SshCertificateTargetOptions options,
        string vaultToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(vaultToken))
            throw new InvalidOperationException("A Vault token secret is required for SSH credential retrieval.");
        var parts = options.SshKeySecretPath.Split('/', 2);
        var relative = parts[1].StartsWith("data/", StringComparison.OrdinalIgnoreCase)
            ? parts[1][5..]
            : parts[1];
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = options.VaultBaseUrl;
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/v1/{parts[0]}/data/{relative}");
        request.Headers.Add("X-Vault-Token", vaultToken);
        using var response = await client.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
            throw new InvalidOperationException("The SSH private key was not found in Vault.");
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Vault SSH credential read failed with HTTP {(int)response.StatusCode}.");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        if (!document.RootElement.TryGetProperty("data", out var outer) ||
            !outer.TryGetProperty("data", out var data))
            throw new InvalidOperationException("Vault SSH credential response is invalid.");
        var privateKey = Required(data, "private_key_pem");
        var passphrase = data.TryGetProperty("passphrase", out var passphraseValue) &&
                         passphraseValue.ValueKind == JsonValueKind.String
            ? passphraseValue.GetString()
            : null;
        return new(privateKey, passphrase);
    }

    private static string Required(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!
            : throw new InvalidOperationException($"Vault SSH credential is missing {property}.");
}
