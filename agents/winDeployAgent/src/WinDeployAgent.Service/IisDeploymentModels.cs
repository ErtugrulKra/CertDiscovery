using System.Text.Json;

namespace WinDeployAgent;

public sealed record IisTargetOptions(
    string SiteName,
    string BindingProtocol,
    string BindingIpAddress,
    int BindingPort,
    string BindingHost,
    bool SniEnabled,
    string CertificateStoreName,
    string CertificateStoreLocation,
    string DeploymentMode,
    string? ApplicationPool,
    bool RestartApplicationPool,
    string? CentralCertificateStorePath,
    string? PfxFileName)
{
    public static IisTargetOptions Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var options = new IisTargetOptions(
            Required(root, "siteName"),
            Optional(root, "bindingProtocol", "https"),
            Optional(root, "bindingIpAddress", "*"),
            RequiredInt(root, "bindingPort"),
            Optional(root, "bindingHost", string.Empty),
            OptionalBool(root, "sniEnabled", false),
            Optional(root, "certificateStoreName", "My"),
            Optional(root, "certificateStoreLocation", "LocalMachine"),
            Optional(root, "deploymentMode", "Binding"),
            OptionalNullable(root, "applicationPool"),
            OptionalBool(root, "restartApplicationPool", false),
            OptionalNullable(root, "centralCertificateStorePath"),
            OptionalNullable(root, "pfxFileName"));

        if (!string.Equals(options.BindingProtocol, "https", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Microsoft IIS deployment requires an HTTPS binding.");
        if (options.BindingPort is < 1 or > 65535)
            throw new InvalidOperationException("Microsoft IIS binding port is invalid.");
        if (!string.Equals(options.CertificateStoreLocation, "LocalMachine", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only the LocalMachine certificate store is supported.");
        if (!string.Equals(options.DeploymentMode, "Binding", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(options.DeploymentMode, "CentralCertificateStore", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Microsoft IIS deploymentMode must be Binding or CentralCertificateStore.");
        if (string.Equals(options.DeploymentMode, "CentralCertificateStore", StringComparison.OrdinalIgnoreCase) &&
            (string.IsNullOrWhiteSpace(options.CentralCertificateStorePath) || string.IsNullOrWhiteSpace(options.PfxFileName)))
            throw new InvalidOperationException("Central Certificate Store mode requires centralCertificateStorePath and pfxFileName.");
        if (string.Equals(options.DeploymentMode, "CentralCertificateStore", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(options.BindingHost) &&
            !string.Equals(options.PfxFileName, $"{options.BindingHost}.pfx", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Central Certificate Store pfxFileName must match the binding hostname.");
        return options;
    }

    private static string Required(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : throw new InvalidOperationException($"Microsoft IIS target requires '{name}'.");
    private static int RequiredInt(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.TryGetInt32(out var result)
            ? result
            : throw new InvalidOperationException($"Microsoft IIS target requires numeric '{name}'.");
    private static string Optional(JsonElement root, string name, string fallback) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : fallback;
    private static string? OptionalNullable(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : null;
    private static bool OptionalBool(JsonElement root, string name, bool fallback) =>
        root.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : fallback;
}

public sealed record CertificateImportResult(
    byte[] BindingHash,
    string Sha256Fingerprint,
    IReadOnlyList<byte[]> AddedCertificateHashes);

public sealed record IisBindingSnapshot(
    string SiteName,
    string BindingInformation,
    string Protocol,
    byte[]? CertificateHash,
    string? CertificateStoreName,
    int SslFlags,
    string? ApplicationPool);

public sealed record IisExecutionResult(
    bool Succeeded,
    bool RolledBack,
    string? ObservedFingerprint,
    string? PreviousFingerprint,
    string? ErrorCode,
    string? ErrorMessage);

public interface IWindowsCertificateStore
{
    CertificateImportResult Import(byte[] pfx, string password, string storeName);
    string? FindSha256Fingerprint(byte[]? bindingHash, string? storeName);
    void Remove(IReadOnlyList<byte[]> certificateHashes, string storeName);
}

public interface IIisBindingStore
{
    IisBindingSnapshot Capture(IisTargetOptions options);
    void Apply(IisBindingSnapshot snapshot, byte[] certificateHash, string certificateStoreName, bool recycleApplicationPool);
    void Restore(IisBindingSnapshot snapshot, bool recycleApplicationPool);
    bool IsApplied(IisBindingSnapshot snapshot, byte[] certificateHash, string certificateStoreName);
    bool UsesCentralCertificateStore(IisBindingSnapshot snapshot);
}

public sealed record CcsFileSnapshot(string TargetPath, string? BackupPath, bool Existed);

public interface ICentralCertificateStore
{
    CcsFileSnapshot Replace(byte[] pfx, string password, IisTargetOptions options);
    string VerifyFingerprint(CcsFileSnapshot snapshot, string password);
    void Restore(CcsFileSnapshot snapshot);
}
