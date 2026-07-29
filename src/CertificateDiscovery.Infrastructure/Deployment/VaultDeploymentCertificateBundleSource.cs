using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class VaultDeploymentCertificateBundleSource(IHttpClientFactory httpClientFactory)
    : IDeploymentCertificateBundleSource
{
    public async Task<IssuedCertificateBundle> LoadAsync(
        CertificateDeployment deployment,
        CancellationToken cancellationToken)
    {
        var request = deployment.CertificateRequest
            ?? throw new InvalidOperationException("Certificate request is not available.");
        var vault = request.VaultServer
            ?? throw new InvalidOperationException("Certificate request has no Vault server.");
        if (string.IsNullOrWhiteSpace(vault.Token))
            throw new InvalidOperationException("Vault token is required to load the deployment certificate.");
        var (mount, path) = SplitPath(request.VaultSecretPath);
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = vault.BaseUrl;
        using var httpRequest = new HttpRequestMessage(HttpMethod.Get, $"/v1/{mount}/data/{path}");
        httpRequest.Headers.Add("X-Vault-Token", vault.Token);
        using var response = await client.SendAsync(httpRequest, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
            throw new InvalidOperationException("The deployment certificate was not found in Vault.");
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Vault deployment bundle read failed with HTTP {(int)response.StatusCode}.");

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        if (!document.RootElement.TryGetProperty("data", out var outer) ||
            !outer.TryGetProperty("data", out var data))
            throw new InvalidOperationException("Vault KV v2 response does not contain certificate data.");
        var certificatePem = Required(data, "certificate_pem");
        var privateKeyPem = Required(data, "private_key_pem");
        var fullChainPem = Required(data, "fullchain_pem");
        var fingerprint = data.TryGetProperty("fingerprint_sha256", out var storedFingerprint) &&
                          storedFingerprint.ValueKind == JsonValueKind.String &&
                          !string.IsNullOrWhiteSpace(storedFingerprint.GetString())
            ? storedFingerprint.GetString()!
            : Fingerprint(certificatePem);
        if (!string.Equals(fingerprint, deployment.ExpectedFingerprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The latest Vault certificate version does not match the deployment fingerprint.");
        return new(certificatePem, privateKeyPem, fullChainPem, fingerprint);
    }

    private static (string Mount, string Path) SplitPath(string value)
    {
        var parts = value.Trim().Trim('/').Split('/', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2)
            throw new InvalidOperationException("Vault secret path must be in '<mount>/<path>' format.");
        return (parts[0], parts[1].StartsWith("data/", StringComparison.OrdinalIgnoreCase) ? parts[1][5..] : parts[1]);
    }

    private static string Required(JsonElement data, string property) =>
        data.TryGetProperty(property, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!
            : throw new InvalidOperationException($"Vault deployment bundle is missing {property}.");

    private static string Fingerprint(string certificatePem)
    {
        using var certificate = X509Certificate2.CreateFromPem(certificatePem);
        return Convert.ToHexString(SHA256.HashData(certificate.RawData));
    }
}
