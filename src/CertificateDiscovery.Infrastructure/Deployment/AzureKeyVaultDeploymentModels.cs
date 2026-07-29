using System.Text.Json;
using System.Text.RegularExpressions;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed record AzureKeyVaultTargetOptions(
    Uri VaultUri,
    string CertificateName,
    AzureKeyVaultAuthenticationMode AuthenticationMode,
    string? TenantId,
    string? ClientId,
    string? ManagedIdentityClientId,
    AzureKeyVaultImportFormat ImportFormat,
    string ContentType,
    bool Enabled,
    bool PreserveCertificateOrder,
    bool RequirePreviousVaultVersionForRollback,
    IReadOnlyDictionary<string, string> Tags,
    IReadOnlyList<Uri> ExternalVerificationEndpoints)
{
    private static readonly Regex CertificateNamePattern =
        new("^[0-9A-Za-z-]{1,127}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static AzureKeyVaultTargetOptions Parse(DeploymentTarget target)
    {
        if (target.TargetType != DeploymentTargetType.AzureKeyVault)
            throw new InvalidOperationException("Azure Key Vault target type is required.");
        using var document = JsonDocument.Parse(
            string.IsNullOrWhiteSpace(target.ConfigurationJson) ? "{}" : target.ConfigurationJson);
        var root = document.RootElement;
        var forbidden = new[] { "clientSecret", "password", "certificatePassword", "pfxPassword", "accessToken" };
        if (forbidden.Any(name => root.TryGetProperty(name, out _)))
            throw new InvalidOperationException("Azure Key Vault target configuration must not contain credentials or passwords.");

        var vaultUriText = Required(root, "vaultUri");
        if (!Uri.TryCreate(vaultUriText, UriKind.Absolute, out var vaultUri) ||
            vaultUri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(vaultUri.UserInfo) ||
            !string.IsNullOrEmpty(vaultUri.Query) ||
            !string.IsNullOrEmpty(vaultUri.Fragment) ||
            vaultUri.AbsolutePath != "/")
            throw new InvalidOperationException("Azure Key Vault vaultUri must be an HTTPS vault root URI.");
        var certificateName = Required(root, "certificateName");
        if (!CertificateNamePattern.IsMatch(certificateName))
            throw new InvalidOperationException("Azure Key Vault certificateName must contain only letters, numbers, and hyphens.");

        if (!Enum.TryParse<AzureKeyVaultAuthenticationMode>(
                Optional(root, "authenticationMode", nameof(AzureKeyVaultAuthenticationMode.DefaultAzureCredential)),
                true,
                out var authenticationMode))
            throw new InvalidOperationException("Azure Key Vault authenticationMode is invalid.");
        var tenantId = OptionalNullable(root, "tenantId");
        var clientId = OptionalNullable(root, "clientId");
        var managedIdentityClientId = OptionalNullable(root, "managedIdentityClientId");
        if (authenticationMode is AzureKeyVaultAuthenticationMode.ServicePrincipal or
            AzureKeyVaultAuthenticationMode.WorkloadIdentity &&
            (tenantId is null || clientId is null))
            throw new InvalidOperationException("Azure Key Vault authentication requires tenantId and clientId.");
        if (authenticationMode != AzureKeyVaultAuthenticationMode.ManagedIdentity && managedIdentityClientId is not null)
            throw new InvalidOperationException("managedIdentityClientId is accepted only with ManagedIdentity authentication.");

        if (!Enum.TryParse<AzureKeyVaultImportFormat>(
                Optional(root, "importFormat", nameof(AzureKeyVaultImportFormat.Pfx)),
                true,
                out var importFormat))
            throw new InvalidOperationException("Azure Key Vault importFormat is invalid.");
        var expectedContentType = importFormat == AzureKeyVaultImportFormat.Pfx
            ? "application/x-pkcs12"
            : "application/x-pem-file";
        var contentType = Optional(root, "contentType", expectedContentType);
        if (!string.Equals(contentType, expectedContentType, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Azure Key Vault {importFormat} import requires contentType '{expectedContentType}'.");

        return new(
            vaultUri,
            certificateName,
            authenticationMode,
            tenantId,
            clientId,
            managedIdentityClientId,
            importFormat,
            expectedContentType,
            OptionalBool(root, "enabled", true),
            OptionalBool(root, "preserveCertificateOrder", false),
            OptionalBool(root, "requirePreviousVaultVersionForRollback", true),
            ParseTags(root),
            ParseEndpoints(root));
    }

    private static IReadOnlyDictionary<string, string> ParseTags(JsonElement root)
    {
        if (!root.TryGetProperty("tags", out var value) || value.ValueKind == JsonValueKind.Null)
            return new Dictionary<string, string>();
        if (value.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("Azure Key Vault tags must be a JSON object.");
        var tags = value.EnumerateObject().ToDictionary(
            item => item.Name,
            item => item.Value.ValueKind == JsonValueKind.String
                ? item.Value.GetString() ?? string.Empty
                : throw new InvalidOperationException("Azure Key Vault tag values must be strings."),
            StringComparer.Ordinal);
        if (tags.Count > 12 || tags.Any(x => x.Key.Length is < 1 or > 512 || x.Value.Length > 256))
            throw new InvalidOperationException("Azure Key Vault tags violate Key Vault tag limits.");
        return tags;
    }

    private static IReadOnlyList<Uri> ParseEndpoints(JsonElement root)
    {
        if (!root.TryGetProperty("externalVerificationEndpoints", out var value) ||
            value.ValueKind == JsonValueKind.Null)
            return [];
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 20)
            throw new InvalidOperationException("Azure Key Vault externalVerificationEndpoints must contain at most 20 URLs.");
        return value.EnumerateArray().Select(item =>
        {
            if (item.ValueKind != JsonValueKind.String ||
                !Uri.TryCreate(item.GetString(), UriKind.Absolute, out var endpoint) ||
                endpoint.Scheme != Uri.UriSchemeHttps ||
                string.IsNullOrWhiteSpace(endpoint.Host))
                throw new InvalidOperationException("Azure Key Vault verification endpoints must be absolute HTTPS URLs.");
            return endpoint;
        }).ToList();
    }

    private static string Required(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : throw new InvalidOperationException($"Azure Key Vault target configuration requires {name}.");
    private static string Optional(JsonElement root, string name, string fallback) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : fallback;
    private static string? OptionalNullable(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : null;
    private static bool OptionalBool(JsonElement root, string name, bool fallback) =>
        root.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : fallback;
}

public sealed record AzureKeyVaultBackupManifest(
    Guid DeploymentId,
    string CertificateName,
    string? PreviousAzureCertificateUri,
    string? PreviousAzureVersion,
    string? PreviousFingerprint,
    int? PreviousSourceVaultVersion,
    bool CertificateExisted);
