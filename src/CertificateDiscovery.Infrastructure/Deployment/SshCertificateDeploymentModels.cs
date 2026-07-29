using System.Text.Json;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed record SshCertificateTargetOptions(
    DeploymentTargetType TargetType,
    string Host,
    int Port,
    string Username,
    Uri VaultBaseUrl,
    string SshKeySecretPath,
    string HostKeyFingerprint,
    string CertificatePath,
    string PrivateKeyPath,
    string FullChainPath,
    string? ChainPath,
    string FileOwner,
    string FileGroup,
    string CertificateMode,
    string PrivateKeyMode,
    string ServiceName,
    bool ConfigurationTest,
    bool ReloadService,
    bool UseSudo,
    int BackupRetention,
    IReadOnlyList<Uri> ExternalVerificationEndpoints)
{
    public string ValidationCommand => TargetType switch
    {
        DeploymentTargetType.Nginx => "nginx -t",
        DeploymentTargetType.ApacheWebServer => "apachectl configtest",
        _ => throw new InvalidOperationException("Unsupported SSH certificate target.")
    };

    public string ReloadCommand => $"systemctl reload {ServiceName}";

    public static SshCertificateTargetOptions Parse(DeploymentTarget target)
    {
        if (target.TargetType is not (DeploymentTargetType.Nginx or DeploymentTargetType.ApacheWebServer))
            throw new InvalidOperationException("SSH certificate deployment supports only NGNIX and Apache Web Server.");
        using var document = JsonDocument.Parse(
            string.IsNullOrWhiteSpace(target.ConfigurationJson) ? "{}" : target.ConfigurationJson);
        var root = document.RootElement;
        RejectArbitraryCommands(root);
        var service = Optional(root, "serviceName",
            target.TargetType == DeploymentTargetType.Nginx ? "nginx" : "apache2");
        var allowedServices = target.TargetType == DeploymentTargetType.Nginx
            ? new[] { "nginx" }
            : new[] { "apache2", "httpd" };
        if (!allowedServices.Contains(service, StringComparer.Ordinal))
            throw new InvalidOperationException("The configured serviceName is not allowlisted for this target.");
        var host = Required(root, "host");
        if (Uri.CheckHostName(host) == UriHostNameType.Unknown)
            throw new InvalidOperationException("SSH host is invalid.");
        var port = OptionalInt(root, "sshPort", 22);
        if (port is < 1 or > 65535)
            throw new InvalidOperationException("SSH port is invalid.");
        var fingerprint = Required(root, "hostKeyFingerprint");
        if (!fingerprint.StartsWith("SHA256:", StringComparison.Ordinal) || fingerprint.Length < 20)
            throw new InvalidOperationException("SSH hostKeyFingerprint must use the SHA256 OpenSSH format.");
        var certificatePath = AbsoluteUnixPath(root, "certificatePath");
        var privateKeyPath = AbsoluteUnixPath(root, "privateKeyPath");
        var fullChainPath = AbsoluteUnixPath(root, "fullChainPath");
        var chainPath = OptionalUnixPath(root, "chainPath");
        var paths = new[] { certificatePath, privateKeyPath, fullChainPath, chainPath }
            .Where(x => x is not null).ToList();
        if (paths.Distinct(StringComparer.Ordinal).Count() != paths.Count)
            throw new InvalidOperationException("Remote certificate paths must be unique.");
        var privateMode = Mode(root, "privateKeyMode", "0600");
        if ((Convert.ToInt32(privateMode, 8) & 0x3F) != 0)
            throw new InvalidOperationException("SSH privateKeyMode must not grant group or other permissions.");
        return new(
            target.TargetType,
            host,
            port,
            SafeIdentifier(root, "username"),
            HttpsUri(root, "vaultBaseUrl"),
            VaultPath(root, "sshKeySecretPath"),
            fingerprint,
            certificatePath,
            privateKeyPath,
            fullChainPath,
            chainPath,
            SafeIdentifier(root, "fileOwner", "root"),
            SafeIdentifier(root, "fileGroup", target.TargetType == DeploymentTargetType.Nginx ? "nginx" : service),
            Mode(root, "certificateMode", "0644"),
            privateMode,
            service,
            OptionalBool(root, "configurationTest", true),
            OptionalBool(root, "reloadService", true),
            OptionalBool(root, "useSudo", true),
            Math.Clamp(OptionalInt(root, "backupRetention", 5), 1, 50),
            Endpoints(root));
    }

    private static void RejectArbitraryCommands(JsonElement root)
    {
        foreach (var property in new[] { "validateCommand", "reloadCommand", "command", "preCommand", "postCommand" })
            if (root.TryGetProperty(property, out _))
                throw new InvalidOperationException($"{property} is not accepted; deployment commands are fixed by the allowlist.");
    }

    private static string Required(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : throw new InvalidOperationException($"SSH target configuration requires {name}.");
    private static string Optional(JsonElement root, string name, string fallback) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString()) ? value.GetString()!.Trim() : fallback;
    private static int OptionalInt(JsonElement root, string name, int fallback) =>
        root.TryGetProperty(name, out var value) && value.TryGetInt32(out var result) ? result : fallback;
    private static bool OptionalBool(JsonElement root, string name, bool fallback) =>
        root.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean() : fallback;
    private static string SafeIdentifier(JsonElement root, string name, string? fallback = null)
    {
        var value = fallback is null ? Required(root, name) : Optional(root, name, fallback);
        return value.Length <= 64 && value.All(x => char.IsAsciiLetterOrDigit(x) || x is '_' or '-')
            ? value
            : throw new InvalidOperationException($"{name} contains unsupported characters.");
    }
    private static Uri HttpsUri(JsonElement root, string name)
    {
        var uri = new Uri(Required(root, name), UriKind.Absolute);
        return uri.Scheme == Uri.UriSchemeHttps
            ? uri
            : throw new InvalidOperationException($"{name} must use HTTPS.");
    }
    private static string VaultPath(JsonElement root, string name)
    {
        var value = Required(root, name).Trim('/');
        if (value.Split('/', StringSplitOptions.RemoveEmptyEntries).Length < 2 || value.Contains("..", StringComparison.Ordinal))
            throw new InvalidOperationException($"{name} must identify a Vault KV mount and path.");
        return value;
    }
    private static string AbsoluteUnixPath(JsonElement root, string name) => UnixPath(Required(root, name), name);
    private static string? OptionalUnixPath(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString()) ? UnixPath(value.GetString()!.Trim(), name) : null;
    private static string UnixPath(string value, string name)
    {
        if (!value.StartsWith('/') || value.Contains('\0') || value.Split('/').Any(x => x is "." or "..") ||
            value.Any(x => !(char.IsAsciiLetterOrDigit(x) || x is '/' or '.' or '_' or '-')))
            throw new InvalidOperationException($"{name} must be a safe absolute Unix path.");
        return value;
    }
    private static string Mode(JsonElement root, string name, string fallback)
    {
        var value = Optional(root, name, fallback);
        if (value.Length != 4 || value[0] != '0' || value.Skip(1).Any(x => x is < '0' or > '7'))
            throw new InvalidOperationException($"{name} must be a four-digit octal mode such as 0600.");
        return value;
    }

    private static IReadOnlyList<Uri> Endpoints(JsonElement root)
    {
        if (!root.TryGetProperty("externalVerificationEndpoints", out var value) ||
            value.ValueKind == JsonValueKind.Null)
            return [];
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 20)
            throw new InvalidOperationException("externalVerificationEndpoints must be an array with at most 20 entries.");
        return value.EnumerateArray().Select(item =>
        {
            if (item.ValueKind != JsonValueKind.String ||
                !Uri.TryCreate(item.GetString(), UriKind.Absolute, out var endpoint) ||
                endpoint.Scheme != Uri.UriSchemeHttps ||
                string.IsNullOrWhiteSpace(endpoint.Host))
                throw new InvalidOperationException("External verification endpoints must be absolute HTTPS URLs.");
            return endpoint;
        }).ToList();
    }
}

public sealed record SshPrivateKeyCredential(string PrivateKeyPem, string? Passphrase);

public interface ISshCredentialSource
{
    Task<SshPrivateKeyCredential> LoadAsync(
        SshCertificateTargetOptions options,
        string vaultToken,
        CancellationToken cancellationToken);
}

public sealed record RemoteFileBackup(string Path, bool Existed, string? BackupPath);
public sealed record SshDeploymentBackup(Guid DeploymentId, IReadOnlyList<RemoteFileBackup> Files);
