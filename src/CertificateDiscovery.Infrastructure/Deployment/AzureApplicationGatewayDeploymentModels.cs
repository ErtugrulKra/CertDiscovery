using System.Text.Json;
using System.Text.RegularExpressions;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed record AzureApplicationGatewayTargetOptions(
    string SubscriptionId, string ResourceGroup, string ApplicationGatewayName,
    string ListenerName, string SslCertificateName,
    AzureApplicationGatewayDeploymentMode DeploymentMode, Uri? KeyVaultSecretId,
    AzureKeyVaultAuthenticationMode AuthenticationMode, string? TenantId, string? ClientId,
    string? ManagedIdentityClientId, int ProvisioningTimeoutSeconds,
    bool RequirePreviousVaultVersionForRollback, IReadOnlyList<Uri> ExternalVerificationEndpoints)
{
    private static readonly Regex NamePattern = new("^[A-Za-z0-9._-]{1,80}$", RegexOptions.Compiled);

    public static AzureApplicationGatewayTargetOptions Parse(DeploymentTarget target)
    {
        if (target.TargetType != DeploymentTargetType.AzureApplicationGateway)
            throw new InvalidOperationException("Azure Application Gateway target type is required.");
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(target.ConfigurationJson) ? "{}" : target.ConfigurationJson);
        var root = document.RootElement;
        if (new[] { "clientSecret", "password", "pfxPassword", "certificateData", "privateKey" }
            .Any(name => root.TryGetProperty(name, out _)))
            throw new InvalidOperationException("Azure Application Gateway configuration must not contain credentials or certificate material.");

        var mode = EnumValue<AzureApplicationGatewayDeploymentMode>(root, "deploymentMode", nameof(AzureApplicationGatewayDeploymentMode.KeyVaultReference));
        Uri? secretId = null;
        var secretText = Optional(root, "keyVaultSecretId");
        if (mode == AzureApplicationGatewayDeploymentMode.KeyVaultReference)
        {
            if (!Uri.TryCreate(secretText, UriKind.Absolute, out secretId) || secretId.Scheme != Uri.UriSchemeHttps ||
                !secretId.AbsolutePath.TrimEnd('/').Contains("/secrets/", StringComparison.OrdinalIgnoreCase) &&
                !Regex.IsMatch(secretId.AbsolutePath.TrimEnd('/'), "^/secrets/[^/]+$", RegexOptions.IgnoreCase))
                throw new InvalidOperationException("KeyVaultReference requires an HTTPS Key Vault /secrets/{name} URI.");
            if (secretId.AbsolutePath.Trim('/').Split('/').Length != 2)
                throw new InvalidOperationException("keyVaultSecretId must be versionless so Application Gateway certificate rotation remains enabled.");
        }
        else if (secretText is not null)
            throw new InvalidOperationException("DirectUpload must not define keyVaultSecretId.");

        var auth = EnumValue<AzureKeyVaultAuthenticationMode>(root, "authenticationMode", nameof(AzureKeyVaultAuthenticationMode.DefaultAzureCredential));
        var tenant = Optional(root, "tenantId");
        var client = Optional(root, "clientId");
        var managed = Optional(root, "managedIdentityClientId");
        if (auth is AzureKeyVaultAuthenticationMode.ServicePrincipal or AzureKeyVaultAuthenticationMode.WorkloadIdentity &&
            (tenant is null || client is null))
            throw new InvalidOperationException("Azure authentication requires tenantId and clientId.");
        if (auth != AzureKeyVaultAuthenticationMode.ManagedIdentity && managed is not null)
            throw new InvalidOperationException("managedIdentityClientId is accepted only with ManagedIdentity authentication.");
        var timeout = OptionalInt(root, "provisioningTimeoutSeconds", 900);
        if (timeout is < 60 or > 3600) throw new InvalidOperationException("provisioningTimeoutSeconds must be between 60 and 3600.");
        var endpoints = ParseEndpoints(root);
        if (endpoints.Count == 0) throw new InvalidOperationException("At least one externalVerificationEndpoint is required.");

        return new(Required(root, "subscriptionId"), Required(root, "resourceGroup"),
            SafeName(root, "applicationGatewayName"), SafeName(root, "listenerName"), SafeName(root, "sslCertificateName"),
            mode, secretId, auth, tenant, client, managed, timeout,
            OptionalBool(root, "requirePreviousVaultVersionForRollback", true), endpoints);
    }

    private static string SafeName(JsonElement root, string name)
    {
        var value = Required(root, name);
        return NamePattern.IsMatch(value) ? value : throw new InvalidOperationException($"{name} contains unsupported characters.");
    }
    private static T EnumValue<T>(JsonElement root, string name, string fallback) where T : struct, Enum =>
        Enum.TryParse<T>(Optional(root, name) ?? fallback, true, out var value) ? value : throw new InvalidOperationException($"{name} is invalid.");
    private static IReadOnlyList<Uri> ParseEndpoints(JsonElement root)
    {
        if (!root.TryGetProperty("externalVerificationEndpoints", out var value) || value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 20) return [];
        return value.EnumerateArray().Select(x =>
            x.ValueKind == JsonValueKind.String && Uri.TryCreate(x.GetString(), UriKind.Absolute, out var uri) &&
            uri.Scheme == Uri.UriSchemeHttps ? uri : throw new InvalidOperationException("Verification endpoints must be HTTPS URLs.")).ToList();
    }
    private static string Required(JsonElement root, string name) => Optional(root, name) ??
        throw new InvalidOperationException($"Azure Application Gateway configuration requires {name}.");
    private static string? Optional(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString()) ? value.GetString()!.Trim() : null;
    private static int OptionalInt(JsonElement root, string name, int fallback) =>
        root.TryGetProperty(name, out var value) && value.TryGetInt32(out var parsed) ? parsed : fallback;
    private static bool OptionalBool(JsonElement root, string name, bool fallback) =>
        root.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : fallback;
}

public sealed record AzureApplicationGatewayState(
    string ResourceId, string ProvisioningState, bool HasUserAssignedIdentity,
    bool ListenerExists, bool ListenerIsHttps, string? ListenerCertificateId,
    string? CertificateResourceId, string? KeyVaultSecretId);

public sealed record AzureApplicationGatewayBackupManifest(
    Guid DeploymentId, string? PreviousListenerCertificateId, string? PreviousKeyVaultSecretId,
    string? PreviousFingerprint, int? PreviousSourceVaultVersion);
