using System.Text.Json;
using System.Text.RegularExpressions;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed record AwsAcmTargetOptions(
    string Region,
    AwsAcmAuthenticationMode AuthenticationMode,
    string? RoleArn,
    string? CertificateArn,
    bool CreateIfMissing,
    bool RequirePreviousVaultVersionForUpdate,
    IReadOnlyDictionary<string, string> Tags,
    IReadOnlyList<Uri> ExternalVerificationEndpoints)
{
    private static readonly Regex RegionPattern =
        new("^[a-z]{2}(?:-gov)?-[a-z]+-\\d+$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex RoleArnPattern =
        new("^arn:(aws|aws-us-gov|aws-cn):iam::\\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex CertificateArnPattern =
        new("^arn:(aws|aws-us-gov|aws-cn):acm:([a-z0-9-]+):\\d{12}:certificate/[0-9a-fA-F-]{36}$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static AwsAcmTargetOptions Parse(DeploymentTarget target)
    {
        if (target.TargetType != DeploymentTargetType.AwsAcm)
            throw new InvalidOperationException("AWS ACM target type is required.");
        using var document = JsonDocument.Parse(
            string.IsNullOrWhiteSpace(target.ConfigurationJson) ? "{}" : target.ConfigurationJson);
        var root = document.RootElement;
        var forbiddenCredentialFields = new[] { "accessKeyId", "secretAccessKey", "sessionToken", "awsAccessKeyId", "awsSecretAccessKey" };
        if (forbiddenCredentialFields.Any(name => root.TryGetProperty(name, out _)))
            throw new InvalidOperationException("AWS ACM target configuration must not contain static AWS credentials.");
        var region = Required(root, "region");
        if (!RegionPattern.IsMatch(region))
            throw new InvalidOperationException("AWS ACM region is invalid.");
        if (!Enum.TryParse<AwsAcmAuthenticationMode>(
                Optional(root, "authenticationMode", nameof(AwsAcmAuthenticationMode.DefaultCredentialChain)),
                ignoreCase: true,
                out var authenticationMode))
            throw new InvalidOperationException("AWS ACM authenticationMode is invalid.");
        var roleArn = OptionalNullable(root, "roleArn");
        if (authenticationMode == AwsAcmAuthenticationMode.AssumeRole &&
            (roleArn is null || !RoleArnPattern.IsMatch(roleArn)))
            throw new InvalidOperationException("AWS ACM AssumeRole authentication requires a valid roleArn.");
        if (authenticationMode != AwsAcmAuthenticationMode.AssumeRole && roleArn is not null)
            throw new InvalidOperationException("AWS ACM roleArn is accepted only with AssumeRole authentication.");
        var certificateArn = OptionalNullable(root, "certificateArn");
        if (certificateArn is not null)
        {
            var match = CertificateArnPattern.Match(certificateArn);
            if (!match.Success)
                throw new InvalidOperationException("AWS ACM certificateArn is invalid.");
            if (!string.Equals(match.Groups[2].Value, region, StringComparison.Ordinal))
                throw new InvalidOperationException("AWS ACM certificateArn region does not match the target region.");
        }
        var createIfMissing = OptionalBool(root, "createIfMissing", true);
        if (certificateArn is null && !createIfMissing)
            throw new InvalidOperationException("AWS ACM certificateArn is required when createIfMissing is false.");
        return new(
            region,
            authenticationMode,
            roleArn,
            certificateArn,
            createIfMissing,
            OptionalBool(root, "requirePreviousVaultVersionForUpdate", true),
            ParseTags(root),
            ParseEndpoints(root));
    }

    private static IReadOnlyDictionary<string, string> ParseTags(JsonElement root)
    {
        if (!root.TryGetProperty("tags", out var value) || value.ValueKind == JsonValueKind.Null)
            return new Dictionary<string, string>();
        if (value.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("AWS ACM tags must be a JSON object.");
        var tags = value.EnumerateObject().ToDictionary(
            x => x.Name,
            x => x.Value.ValueKind == JsonValueKind.String
                ? x.Value.GetString() ?? string.Empty
                : throw new InvalidOperationException("AWS ACM tag values must be strings."),
            StringComparer.Ordinal);
        if (tags.Count > 50 || tags.Any(x =>
                x.Key.Length is < 1 or > 128 ||
                x.Value.Length > 256 ||
                x.Key.StartsWith("aws:", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("AWS ACM tags violate AWS tag limits.");
        return tags;
    }

    private static IReadOnlyList<Uri> ParseEndpoints(JsonElement root)
    {
        if (!root.TryGetProperty("externalVerificationEndpoints", out var value) ||
            value.ValueKind == JsonValueKind.Null)
            return [];
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 20)
            throw new InvalidOperationException("AWS ACM externalVerificationEndpoints must contain at most 20 URLs.");
        return value.EnumerateArray().Select(item =>
        {
            if (item.ValueKind != JsonValueKind.String ||
                !Uri.TryCreate(item.GetString(), UriKind.Absolute, out var endpoint) ||
                endpoint.Scheme != Uri.UriSchemeHttps ||
                string.IsNullOrWhiteSpace(endpoint.Host))
                throw new InvalidOperationException("AWS ACM external verification endpoints must be absolute HTTPS URLs.");
            return endpoint;
        }).ToList();
    }

    private static string Required(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : throw new InvalidOperationException($"AWS ACM target configuration requires {name}.");
    private static string Optional(JsonElement root, string name, string fallback) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : fallback;
    private static string? OptionalNullable(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : null;
    private static bool OptionalBool(JsonElement root, string name, bool fallback) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : fallback;
}

public sealed record AwsAcmBackupManifest(
    Guid DeploymentId,
    string? CertificateArn,
    int? PreviousVaultVersion,
    string? PreviousFingerprint,
    bool CertificateExisted);
