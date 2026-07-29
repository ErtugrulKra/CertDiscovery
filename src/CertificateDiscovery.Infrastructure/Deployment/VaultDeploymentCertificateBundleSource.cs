using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class VaultDeploymentCertificateBundleSource(IHttpClientFactory httpClientFactory)
    : IVersionedDeploymentCertificateBundleSource
{
    public Task<IssuedCertificateBundle> LoadAsync(
        CertificateDeployment deployment,
        CancellationToken cancellationToken) =>
        LoadCoreAsync(deployment, null, requireExpectedFingerprint: true, cancellationToken);

    public Task<IssuedCertificateBundle> LoadVersionAsync(
        CertificateDeployment deployment,
        int version,
        CancellationToken cancellationToken)
    {
        if (version < 1) throw new ArgumentOutOfRangeException(nameof(version));
        return LoadCoreAsync(deployment, version, requireExpectedFingerprint: false, cancellationToken);
    }

    private async Task<IssuedCertificateBundle> LoadCoreAsync(
        CertificateDeployment deployment,
        int? version,
        bool requireExpectedFingerprint,
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
        var requestPath = $"/v1/{mount}/data/{path}";
        if (version is not null)
            requestPath += $"?version={version.Value}";
        using var httpRequest = new HttpRequestMessage(HttpMethod.Get, requestPath);
        httpRequest.Headers.Add("X-Vault-Token", vault.Token);
        using var response = await client.SendAsync(httpRequest, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
            throw new InvalidOperationException("The deployment certificate was not found in Vault.");
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Vault deployment bundle read failed with HTTP {(int)response.StatusCode}.");

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        if (!document.RootElement.TryGetProperty("data", out var outer) ||
            !outer.TryGetProperty("data", out var data) ||
            !outer.TryGetProperty("metadata", out var metadata) ||
            !metadata.TryGetProperty("version", out var versionElement) ||
            !versionElement.TryGetInt32(out var observedVersion))
            throw new InvalidOperationException("Vault KV v2 response does not contain certificate data.");
        var certificatePem = Required(data, "certificate_pem");
        var privateKeyPem = Required(data, "private_key_pem");
        var fullChainPem = Required(data, "fullchain_pem");
        var fingerprint = data.TryGetProperty("fingerprint_sha256", out var storedFingerprint) &&
                          storedFingerprint.ValueKind == JsonValueKind.String &&
                          !string.IsNullOrWhiteSpace(storedFingerprint.GetString())
            ? storedFingerprint.GetString()!
            : Fingerprint(certificatePem);
        if (requireExpectedFingerprint &&
            !string.Equals(fingerprint, deployment.ExpectedFingerprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The latest Vault certificate version does not match the deployment fingerprint.");
        return new(certificatePem, privateKeyPem, fullChainPem, fingerprint, observedVersion);
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
