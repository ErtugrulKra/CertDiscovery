using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class VaultKvCertificateDeployer(IHttpClientFactory httpClientFactory) : ICertificateDeployer
{
    public DeploymentTargetType TargetType => DeploymentTargetType.VaultKv;

    public async Task<DeploymentValidationResult> ValidateTargetAsync(
        DeploymentTargetContext context,
        CancellationToken cancellationToken)
    {
        VaultKvTargetOptions options;
        try
        {
            options = Parse(context.Target);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or UriFormatException)
        {
            return new(false, exception.Message);
        }

        if (string.IsNullOrWhiteSpace(context.Secret))
            return new(false, "Vault token is required.");

        using var request = CreateRequest(HttpMethod.Get, options, $"metadata/{options.Path}", context.Secret);
        using var response = await CreateClient(options).SendAsync(request, cancellationToken);
        return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotFound
            ? new(true)
            : new(false, $"Vault target validation failed with HTTP {(int)response.StatusCode}.");
    }

    public async Task<DeploymentPrecheckResult> PrecheckAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(Parse(context.Target), context.Secret, null, cancellationToken);
        return current.StatusCode == HttpStatusCode.NotFound
            ? new(true)
            : current.Succeeded
                ? new(true, current.Fingerprint)
                : new(false, Message: current.Error);
    }

    public async Task<DeploymentBackupResult> BackupAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        var options = Parse(context.Target);
        var current = await ReadAsync(options, context.Secret, null, cancellationToken);
        if (current.StatusCode == HttpStatusCode.NotFound)
            return new(true, BuildBackupReference(options, null));
        return current.Succeeded
            ? new(true, BuildBackupReference(options, current.Version))
            : new(false, Message: current.Error);
    }

    public async Task<DeploymentApplyResult> DeployAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        var options = Parse(context.Target);
        var payload = new
        {
            data = new
            {
                certificate_pem = bundle.CertificatePem,
                private_key_pem = bundle.PrivateKeyPem,
                fullchain_pem = bundle.FullChainPem,
                fingerprint_sha256 = bundle.Fingerprint,
                certificate_deployment_id = context.Deployment.Id,
                deployed_at_utc = DateTime.UtcNow
            }
        };
        using var request = CreateRequest(HttpMethod.Post, options, $"data/{options.Path}", context.Secret);
        request.Content = JsonContent.Create(payload);
        using var response = await CreateClient(options).SendAsync(request, cancellationToken);
        return response.IsSuccessStatusCode
            ? new(true)
            : new(false, $"Vault KV write failed with HTTP {(int)response.StatusCode}.");
    }

    public Task<DeploymentActivationResult> ActivateAsync(
        DeploymentContext context,
        CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentActivationResult(true, "Vault KV writes are active immediately."));

    public async Task<DeploymentVerificationResult> VerifyAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(Parse(context.Target), context.Secret, null, cancellationToken);
        if (!current.Succeeded)
            return new(false, Message: current.Error);
        var matches = string.Equals(current.Fingerprint, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase);
        return new(matches, current.Fingerprint, matches
            ? $"Vault KV version {current.Version} verified."
            : "Vault KV fingerprint does not match the expected certificate.");
    }

    public async Task<DeploymentRollbackResult> RollbackAsync(
        DeploymentContext context,
        DeploymentBackupResult backup,
        CancellationToken cancellationToken)
    {
        VaultKvBackupReference reference;
        try
        {
            reference = ParseBackupReference(backup.BackupReference);
        }
        catch (InvalidOperationException exception)
        {
            return new(false, Message: exception.Message);
        }

        var options = Parse(context.Target);
        if (!string.Equals(reference.Mount, options.Mount, StringComparison.Ordinal) ||
            !string.Equals(reference.Path, options.Path, StringComparison.Ordinal))
            return new(false, Message: "Vault backup reference does not belong to this target.");

        if (reference.Version is null)
        {
            using var deleteRequest = CreateRequest(HttpMethod.Delete, options, $"data/{options.Path}", context.Secret);
            using var deleteResponse = await CreateClient(options).SendAsync(deleteRequest, cancellationToken);
            return deleteResponse.IsSuccessStatusCode || deleteResponse.StatusCode == HttpStatusCode.NotFound
                ? new(true, Message: "Vault KV secret created by the deployment was deleted.")
                : new(false, Message: $"Vault KV rollback delete failed with HTTP {(int)deleteResponse.StatusCode}.");
        }

        var previous = await ReadAsync(options, context.Secret, reference.Version, cancellationToken);
        if (!previous.Succeeded || previous.Data is null)
            return new(false, Message: previous.Error ?? "Vault KV backup version could not be read.");

        using var restoreRequest = CreateRequest(HttpMethod.Post, options, $"data/{options.Path}", context.Secret);
        restoreRequest.Content = JsonContent.Create(new { data = previous.Data });
        using var restoreResponse = await CreateClient(options).SendAsync(restoreRequest, cancellationToken);
        return restoreResponse.IsSuccessStatusCode
            ? new(true, previous.Fingerprint, $"Vault KV version {reference.Version} was restored as a new version.")
            : new(false, Message: $"Vault KV restore failed with HTTP {(int)restoreResponse.StatusCode}.");
    }

    private HttpClient CreateClient(VaultKvTargetOptions options)
    {
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = options.BaseUrl;
        return client;
    }

    private static HttpRequestMessage CreateRequest(
        HttpMethod method,
        VaultKvTargetOptions options,
        string relativePath,
        string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new InvalidOperationException("Vault token is required.");
        var request = new HttpRequestMessage(method, $"/v1/{options.Mount}/{relativePath}");
        request.Headers.Add("X-Vault-Token", token);
        if (!string.IsNullOrWhiteSpace(options.Namespace))
            request.Headers.Add("X-Vault-Namespace", options.Namespace);
        return request;
    }

    private async Task<VaultKvReadResult> ReadAsync(
        VaultKvTargetOptions options,
        string? token,
        int? version,
        CancellationToken cancellationToken)
    {
        var suffix = version is null ? string.Empty : $"?version={version.Value}";
        using var request = CreateRequest(HttpMethod.Get, options, $"data/{options.Path}{suffix}", token);
        using var response = await CreateClient(options).SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
            return new(false, response.StatusCode, Error: $"Vault KV read failed with HTTP {(int)response.StatusCode}.");

        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        if (!document.RootElement.TryGetProperty("data", out var outer) ||
            !outer.TryGetProperty("data", out var data) ||
            !outer.TryGetProperty("metadata", out var metadata) ||
            !metadata.TryGetProperty("version", out var versionElement))
            return new(false, response.StatusCode, Error: "Vault KV response does not contain KV v2 data and metadata.");

        var values = JsonSerializer.Deserialize<Dictionary<string, object?>>(data.GetRawText());
        var fingerprint = data.TryGetProperty("fingerprint_sha256", out var fingerprintElement)
            ? fingerprintElement.GetString()
            : null;
        return new(true, response.StatusCode, versionElement.GetInt32(), fingerprint, values);
    }

    private static VaultKvTargetOptions Parse(DeploymentTarget target)
    {
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(target.ConfigurationJson) ? "{}" : target.ConfigurationJson);
        var root = document.RootElement;
        var baseUrlText = RequiredString(root, "baseUrl");
        var secretPath = RequiredString(root, "secretPath");
        var uri = new Uri(baseUrlText, UriKind.Absolute);
        if (uri.Scheme is not ("http" or "https"))
            throw new InvalidOperationException("Vault baseUrl must use HTTP or HTTPS.");
        var parts = secretPath.Trim().Trim('/').Split('/', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2)
            throw new InvalidOperationException("Vault secretPath must be in '<mount>/<path>' format.");
        var path = parts[1].StartsWith("data/", StringComparison.OrdinalIgnoreCase) ? parts[1][5..] : parts[1];
        var vaultNamespace = root.TryGetProperty("namespace", out var namespaceElement) &&
                             namespaceElement.ValueKind == JsonValueKind.String
            ? namespaceElement.GetString()?.Trim()
            : null;
        return new(uri, parts[0], path, vaultNamespace);
    }

    private static string RequiredString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : throw new InvalidOperationException($"Vault configuration requires {name}.");

    private static string BuildBackupReference(VaultKvTargetOptions options, int? version) =>
        $"vault-kv:{Uri.EscapeDataString(options.Mount)}:{Uri.EscapeDataString(options.Path)}:{version?.ToString() ?? "none"}";

    private static VaultKvBackupReference ParseBackupReference(string? value)
    {
        var parts = value?.Split(':');
        if (parts is not { Length: 4 } || parts[0] != "vault-kv")
            throw new InvalidOperationException("Vault backup reference is invalid.");
        int? version = parts[3] == "none"
            ? null
            : int.TryParse(parts[3], out var parsed) && parsed > 0
                ? parsed
                : throw new InvalidOperationException("Vault backup version is invalid.");
        return new(Uri.UnescapeDataString(parts[1]), Uri.UnescapeDataString(parts[2]), version);
    }

    private sealed record VaultKvTargetOptions(Uri BaseUrl, string Mount, string Path, string? Namespace);
    private sealed record VaultKvBackupReference(string Mount, string Path, int? Version);
    private sealed record VaultKvReadResult(
        bool Succeeded,
        HttpStatusCode StatusCode,
        int? Version = null,
        string? Fingerprint = null,
        Dictionary<string, object?>? Data = null,
        string? Error = null);
}
