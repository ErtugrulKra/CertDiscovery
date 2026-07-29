using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class KubernetesTlsSecretDeployer(
    IHttpClientFactory httpClientFactory,
    ISecretProvider secretProvider) : ICertificateDeployer
{
    private const int MaximumConflictAttempts = 3;
    private const string MissingBackupValue = """{"missing":true}""";

    public DeploymentTargetType TargetType => DeploymentTargetType.Kubernetes;

    public async Task<DeploymentValidationResult> ValidateTargetAsync(
        DeploymentTargetContext context,
        CancellationToken cancellationToken)
    {
        KubernetesTargetOptions options;
        try
        {
            options = Parse(context.Target);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or UriFormatException)
        {
            return new(false, exception.Message);
        }
        if (string.IsNullOrWhiteSpace(context.Secret))
            return new(false, "Kubernetes service-account bearer token is required.");

        using var request = Request(HttpMethod.Get, options, $"/api/v1/namespaces/{Escape(options.Namespace)}", context.Secret);
        using var response = await Client(options).SendAsync(request, cancellationToken);
        return response.IsSuccessStatusCode
            ? new(true)
            : new(false, $"Kubernetes target validation failed with HTTP {(int)response.StatusCode}.");
    }

    public async Task<DeploymentPrecheckResult> PrecheckAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        var options = Parse(context.Target);
        var current = await ReadSecretAsync(options, context.Secret, cancellationToken);
        if (current.StatusCode == HttpStatusCode.NotFound)
            return options.CreateIfMissing
                ? new(true)
                : new(false, Message: "Kubernetes TLS Secret does not exist and createIfMissing is false.");
        if (!current.Succeeded)
            return new(false, Message: current.Error);
        return new(true, Fingerprint(current.Document));
    }

    public async Task<DeploymentBackupResult> BackupAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        var options = Parse(context.Target);
        var current = await ReadSecretAsync(options, context.Secret, cancellationToken);
        if (!current.Succeeded && current.StatusCode != HttpStatusCode.NotFound)
            return new(false, Message: current.Error);
        var protectedReference = await secretProvider.StoreAsync(
            $"kubernetes-secret-backup:{context.Deployment.Id:D}",
            current.StatusCode == HttpStatusCode.NotFound ? MissingBackupValue : current.RawJson!,
            cancellationToken);
        return new(true, protectedReference);
    }

    public async Task<DeploymentApplyResult> DeployAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        var options = Parse(context.Target);
        for (var attempt = 1; attempt <= MaximumConflictAttempts; attempt++)
        {
            var current = await ReadSecretAsync(options, context.Secret, cancellationToken);
            if (!current.Succeeded && current.StatusCode != HttpStatusCode.NotFound)
                return new(false, current.Error);
            if (current.StatusCode == HttpStatusCode.NotFound && !options.CreateIfMissing)
                return new(false, "Kubernetes TLS Secret does not exist and createIfMissing is false.");

            var body = BuildSecret(options, bundle, current.Document);
            var creating = current.StatusCode == HttpStatusCode.NotFound;
            using var request = Request(
                creating ? HttpMethod.Post : HttpMethod.Put,
                options,
                creating ? $"/api/v1/namespaces/{Escape(options.Namespace)}/secrets" : SecretPath(options),
                context.Secret);
            request.Content = JsonContent.Create(body);
            using var response = await Client(options).SendAsync(request, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var restart = await RestartWorkloadsAsync(options, context.Secret, cancellationToken);
                return restart.Succeeded ? new(true) : restart;
            }
            if (response.StatusCode != HttpStatusCode.Conflict || attempt == MaximumConflictAttempts)
                return new(false, $"Kubernetes TLS Secret write failed with HTTP {(int)response.StatusCode}.");
        }
        return new(false, "Kubernetes TLS Secret update exhausted conflict retries.");
    }

    public Task<DeploymentActivationResult> ActivateAsync(
        DeploymentContext context,
        CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentActivationResult(true, "Kubernetes Secret updates are active immediately."));

    public async Task<DeploymentVerificationResult> VerifyAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        var current = await ReadSecretAsync(Parse(context.Target), context.Secret, cancellationToken);
        if (!current.Succeeded)
            return new(false, Message: current.Error);
        var observed = Fingerprint(current.Document);
        var matches = string.Equals(observed, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase);
        return new(matches, observed, matches
            ? "Kubernetes TLS Secret fingerprint verified."
            : "Kubernetes TLS Secret fingerprint does not match the expected certificate.");
    }

    public async Task<DeploymentRollbackResult> RollbackAsync(
        DeploymentContext context,
        DeploymentBackupResult backup,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(backup.BackupReference))
            return new(false, Message: "Kubernetes backup reference is missing.");
        var options = Parse(context.Target);
        string backupJson;
        try
        {
            backupJson = await secretProvider.GetAsync(backup.BackupReference, cancellationToken);
        }
        catch (Exception exception)
        {
            return new(false, Message: exception.Message);
        }

        using var backupDocument = JsonDocument.Parse(backupJson);
        if (backupDocument.RootElement.TryGetProperty("missing", out var missing) && missing.GetBoolean())
        {
            using var deleteRequest = Request(HttpMethod.Delete, options, SecretPath(options), context.Secret);
            using var deleteResponse = await Client(options).SendAsync(deleteRequest, cancellationToken);
            return deleteResponse.IsSuccessStatusCode || deleteResponse.StatusCode == HttpStatusCode.NotFound
                ? new(true, Message: "Kubernetes TLS Secret created by the deployment was deleted.")
                : new(false, Message: $"Kubernetes TLS Secret rollback delete failed with HTTP {(int)deleteResponse.StatusCode}.");
        }

        for (var attempt = 1; attempt <= MaximumConflictAttempts; attempt++)
        {
            var current = await ReadSecretAsync(options, context.Secret, cancellationToken);
            if (!current.Succeeded && current.StatusCode != HttpStatusCode.NotFound)
                return new(false, Message: current.Error);
            var restore = JsonNode.Parse(backupJson)?.AsObject()
                ?? throw new InvalidOperationException("Kubernetes backup payload is invalid.");
            var metadata = restore["metadata"]?.AsObject()
                ?? throw new InvalidOperationException("Kubernetes backup metadata is invalid.");
            RemoveServerManagedMetadata(metadata);
            if (current.Succeeded)
                metadata["resourceVersion"] = current.Document!.RootElement.GetProperty("metadata").GetProperty("resourceVersion").GetString();
            else
                metadata.Remove("resourceVersion");

            var creating = current.StatusCode == HttpStatusCode.NotFound;
            using var request = Request(
                creating ? HttpMethod.Post : HttpMethod.Put,
                options,
                creating ? $"/api/v1/namespaces/{Escape(options.Namespace)}/secrets" : SecretPath(options),
                context.Secret);
            request.Content = JsonContent.Create(restore);
            using var response = await Client(options).SendAsync(request, cancellationToken);
            if (response.IsSuccessStatusCode)
                return new(true, Fingerprint(backupDocument), "Previous Kubernetes TLS Secret was restored.");
            if (response.StatusCode != HttpStatusCode.Conflict || attempt == MaximumConflictAttempts)
                return new(false, Message: $"Kubernetes TLS Secret restore failed with HTTP {(int)response.StatusCode}.");
        }
        return new(false, Message: "Kubernetes TLS Secret rollback exhausted conflict retries.");
    }

    private async Task<DeploymentApplyResult> RestartWorkloadsAsync(
        KubernetesTargetOptions options,
        string? token,
        CancellationToken cancellationToken)
    {
        foreach (var workload in options.RestartWorkloads)
        {
            var resource = workload.Kind.ToLowerInvariant() switch
            {
                "deployment" => "deployments",
                "statefulset" => "statefulsets",
                "daemonset" => "daemonsets",
                _ => null
            };
            if (resource is null)
                return new(false, $"Unsupported Kubernetes restart workload kind '{workload.Kind}'.");
            using var request = Request(
                HttpMethod.Patch,
                options,
                $"/apis/apps/v1/namespaces/{Escape(options.Namespace)}/{resource}/{Escape(workload.Name)}",
                token);
            request.Content = new StringContent(
                JsonSerializer.Serialize(new
                {
                    spec = new
                    {
                        template = new
                        {
                            metadata = new
                            {
                                annotations = new Dictionary<string, string>
                                {
                                    ["certdiscovery.io/restartedAt"] = DateTime.UtcNow.ToString("O")
                                }
                            }
                        }
                    }
                }),
                Encoding.UTF8,
                "application/merge-patch+json");
            using var response = await Client(options).SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
                return new(false, $"Kubernetes {workload.Kind} restart failed with HTTP {(int)response.StatusCode}.");
        }
        return new(true);
    }

    private async Task<KubernetesReadResult> ReadSecretAsync(
        KubernetesTargetOptions options,
        string? token,
        CancellationToken cancellationToken)
    {
        using var request = Request(HttpMethod.Get, options, SecretPath(options), token);
        using var response = await Client(options).SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
            return new(false, response.StatusCode, Error: $"Kubernetes TLS Secret read failed with HTTP {(int)response.StatusCode}.");
        var raw = await response.Content.ReadAsStringAsync(cancellationToken);
        try
        {
            return new(true, response.StatusCode, JsonDocument.Parse(raw), raw);
        }
        catch (JsonException exception)
        {
            return new(false, response.StatusCode, Error: $"Kubernetes TLS Secret response is invalid: {exception.Message}");
        }
    }

    private static JsonObject BuildSecret(
        KubernetesTargetOptions options,
        IssuedCertificateBundle bundle,
        JsonDocument? current)
    {
        var root = current is null
            ? new JsonObject()
            : JsonNode.Parse(current.RootElement.GetRawText())!.AsObject();
        root["apiVersion"] = "v1";
        root["kind"] = "Secret";
        root["type"] = "kubernetes.io/tls";
        var metadata = root["metadata"]?.AsObject() ?? new JsonObject();
        root["metadata"] = metadata;
        RemoveServerManagedMetadata(metadata);
        metadata["name"] = options.SecretName;
        metadata["namespace"] = options.Namespace;
        var annotations = metadata["annotations"]?.AsObject() ?? new JsonObject();
        metadata["annotations"] = annotations;
        foreach (var item in options.Annotations)
            annotations[item.Key] = item.Value;
        var data = root["data"]?.AsObject() ?? new JsonObject();
        root["data"] = data;
        data["tls.crt"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(bundle.FullChainPem));
        data["tls.key"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(bundle.PrivateKeyPem));
        if (!string.IsNullOrWhiteSpace(options.CaBundleField))
            data[options.CaBundleField] = Convert.ToBase64String(Encoding.UTF8.GetBytes(bundle.CertificatePem));
        return root;
    }

    private static void RemoveServerManagedMetadata(JsonObject metadata)
    {
        metadata.Remove("uid");
        metadata.Remove("creationTimestamp");
        metadata.Remove("managedFields");
        metadata.Remove("generation");
        metadata.Remove("selfLink");
    }

    private static string? Fingerprint(JsonDocument? document)
    {
        if (document is null ||
            !document.RootElement.TryGetProperty("data", out var data) ||
            !data.TryGetProperty("tls.crt", out var certificateValue))
            return null;
        try
        {
            var pem = Encoding.UTF8.GetString(Convert.FromBase64String(certificateValue.GetString() ?? string.Empty));
            using var certificate = X509Certificate2.CreateFromPem(pem);
            return Convert.ToHexString(SHA256.HashData(certificate.RawData));
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            return null;
        }
    }

    private HttpClient Client(KubernetesTargetOptions options)
    {
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = options.ApiServer;
        return client;
    }

    private static HttpRequestMessage Request(
        HttpMethod method,
        KubernetesTargetOptions options,
        string path,
        string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new InvalidOperationException("Kubernetes service-account bearer token is required.");
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private static KubernetesTargetOptions Parse(DeploymentTarget target)
    {
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(target.ConfigurationJson) ? "{}" : target.ConfigurationJson);
        var root = document.RootElement;
        var apiServer = new Uri(RequiredString(root, "apiServer"), UriKind.Absolute);
        if (apiServer.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Kubernetes apiServer must use HTTPS.");
        var kubernetesNamespace = KubernetesName(RequiredString(root, "namespace"), "namespace");
        var secretName = KubernetesName(RequiredString(root, "secretName"), "secretName");
        var create = !root.TryGetProperty("createIfMissing", out var createElement) || createElement.GetBoolean();
        var caField = OptionalString(root, "caBundleField");
        if (caField is not null && (caField.Contains('/') || caField.Length > 253))
            throw new InvalidOperationException("Kubernetes caBundleField is invalid.");
        var annotations = root.TryGetProperty("annotations", out var annotationsElement) &&
                          annotationsElement.ValueKind == JsonValueKind.Object
            ? annotationsElement.EnumerateObject().ToDictionary(x => x.Name, x => x.Value.GetString() ?? string.Empty)
            : [];
        var workloads = root.TryGetProperty("restartWorkloads", out var workloadsElement) &&
                        workloadsElement.ValueKind == JsonValueKind.Array
            ? workloadsElement.EnumerateArray()
                .Select(x => new KubernetesWorkload(RequiredString(x, "kind"), KubernetesName(RequiredString(x, "name"), "workload name")))
                .ToList()
            : [];
        return new(apiServer, kubernetesNamespace, secretName, create, caField, annotations, workloads);
    }

    private static string RequiredString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : throw new InvalidOperationException($"Kubernetes configuration requires {name}.");

    private static string? OptionalString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : null;

    private static string KubernetesName(string value, string field)
    {
        if (value.Length > 253 ||
            value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '-' or '.')) ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            !char.IsAsciiLetterOrDigit(value[^1]))
            throw new InvalidOperationException($"Kubernetes {field} is not a valid DNS name.");
        return value;
    }

    private static string SecretPath(KubernetesTargetOptions options) =>
        $"/api/v1/namespaces/{Escape(options.Namespace)}/secrets/{Escape(options.SecretName)}";
    private static string Escape(string value) => Uri.EscapeDataString(value);

    private sealed record KubernetesTargetOptions(
        Uri ApiServer,
        string Namespace,
        string SecretName,
        bool CreateIfMissing,
        string? CaBundleField,
        IReadOnlyDictionary<string, string> Annotations,
        IReadOnlyList<KubernetesWorkload> RestartWorkloads);
    private sealed record KubernetesWorkload(string Kind, string Name);
    private sealed record KubernetesReadResult(
        bool Succeeded,
        HttpStatusCode StatusCode,
        JsonDocument? Document = null,
        string? RawJson = null,
        string? Error = null);
}
