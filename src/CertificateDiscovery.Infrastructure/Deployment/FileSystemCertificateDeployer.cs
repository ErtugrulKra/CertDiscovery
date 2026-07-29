using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class FileSystemCertificateDeployer(ICertificateBundleConverter bundleConverter) : ICertificateDeployer
{
    private const string ManifestName = "backup-manifest.json";
    public DeploymentTargetType TargetType => DeploymentTargetType.FileSystem;

    public Task<DeploymentValidationResult> ValidateTargetAsync(
        DeploymentTargetContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            if (options.PfxFile is not null && string.IsNullOrWhiteSpace(context.Secret))
                return Task.FromResult(new DeploymentValidationResult(false, "A PFX password secret is required when pfxFile is configured."));
            Directory.CreateDirectory(options.OutputDirectory);
            var probe = Path.Combine(options.OutputDirectory, $".certdiscovery-write-probe-{Guid.NewGuid():N}");
            using (File.Create(probe, 1, FileOptions.DeleteOnClose)) { }
            return Task.FromResult(new DeploymentValidationResult(true));
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return Task.FromResult(new DeploymentValidationResult(false, exception.Message));
        }
    }

    public Task<DeploymentPrecheckResult> PrecheckAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            Directory.CreateDirectory(options.OutputDirectory);
            return Task.FromResult(new DeploymentPrecheckResult(true));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return Task.FromResult(new DeploymentPrecheckResult(false, Message: exception.Message));
        }
    }

    public async Task<DeploymentBackupResult> BackupAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            var backupDirectory = BackupDirectory(options, context.Deployment.Id);
            Directory.CreateDirectory(backupDirectory);
            var entries = new List<FileBackupEntry>();
            foreach (var destination in DestinationPaths(options))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var existed = File.Exists(destination);
                var backupFile = Path.Combine(backupDirectory, Path.GetFileName(destination));
                if (existed)
                    File.Copy(destination, backupFile, true);
                entries.Add(new(destination, existed, existed ? backupFile : null));
            }
            var manifest = new FileBackupManifest(context.Deployment.Id, options.OutputDirectory, entries);
            await File.WriteAllTextAsync(
                Path.Combine(backupDirectory, ManifestName),
                JsonSerializer.Serialize(manifest),
                cancellationToken);
            return new(true, backupDirectory);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new(false, Message: exception.Message);
        }
    }

    public async Task<DeploymentApplyResult> DeployAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            await AtomicWriteAsync(PathFor(options, options.CertificateFile), Encoding.UTF8.GetBytes(bundle.CertificatePem), options.PublicFileMode, cancellationToken);
            await AtomicWriteAsync(PathFor(options, options.PrivateKeyFile), Encoding.UTF8.GetBytes(bundle.PrivateKeyPem), options.PrivateKeyMode, cancellationToken);
            await AtomicWriteAsync(PathFor(options, options.FullChainFile), Encoding.UTF8.GetBytes(bundle.FullChainPem), options.PublicFileMode, cancellationToken);
            if (options.PfxFile is not null)
            {
                if (string.IsNullOrWhiteSpace(context.Secret))
                    return new(false, "A PFX password secret is required.");
                var pfx = bundleConverter.Convert(bundle, context.Secret).Pfx;
                await AtomicWriteAsync(PathFor(options, options.PfxFile), pfx, options.PrivateKeyMode, cancellationToken);
            }
            return new(true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException or InvalidOperationException)
        {
            return new(false, exception.Message);
        }
    }

    public Task<DeploymentActivationResult> ActivateAsync(
        DeploymentContext context,
        CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentActivationResult(true, "Atomic file replacement is active immediately."));

    public async Task<DeploymentVerificationResult> VerifyAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            var expected = new Dictionary<string, byte[]>
            {
                [PathFor(options, options.CertificateFile)] = Encoding.UTF8.GetBytes(bundle.CertificatePem),
                [PathFor(options, options.PrivateKeyFile)] = Encoding.UTF8.GetBytes(bundle.PrivateKeyPem),
                [PathFor(options, options.FullChainFile)] = Encoding.UTF8.GetBytes(bundle.FullChainPem)
            };
            if (options.PfxFile is not null)
            {
                if (string.IsNullOrWhiteSpace(context.Secret))
                    return new(false, Message: "A PFX password secret is required.");
                expected[PathFor(options, options.PfxFile)] = bundleConverter.Convert(bundle, context.Secret).Pfx;
            }

            foreach (var item in expected)
            {
                if (!File.Exists(item.Key))
                    return new(false, Message: $"Exported file '{Path.GetFileName(item.Key)}' is missing.");
                var actualHash = await HashFileAsync(item.Key, cancellationToken);
                var expectedHash = Convert.ToHexString(SHA256.HashData(item.Value));
                if (!string.Equals(actualHash, expectedHash, StringComparison.Ordinal))
                    return new(false, Message: $"Exported file '{Path.GetFileName(item.Key)}' failed hash verification.");
            }
            return new(true, bundle.Fingerprint, "All exported files passed SHA-256 verification.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException or InvalidOperationException)
        {
            return new(false, Message: exception.Message);
        }
    }

    public async Task<DeploymentRollbackResult> RollbackAsync(
        DeploymentContext context,
        DeploymentBackupResult backup,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            var expectedBackup = Path.GetFullPath(BackupDirectory(options, context.Deployment.Id));
            var suppliedBackup = Path.GetFullPath(backup.BackupReference ?? string.Empty);
            if (!string.Equals(expectedBackup, suppliedBackup, PathComparison))
                return new(false, Message: "File-system backup reference does not belong to this deployment.");
            var manifestPath = Path.Combine(suppliedBackup, ManifestName);
            var manifest = JsonSerializer.Deserialize<FileBackupManifest>(
                await File.ReadAllTextAsync(manifestPath, cancellationToken))
                ?? throw new InvalidOperationException("File-system backup manifest is invalid.");
            if (manifest.DeploymentId != context.Deployment.Id ||
                !string.Equals(Path.GetFullPath(manifest.OutputDirectory), options.OutputDirectory, PathComparison))
                return new(false, Message: "File-system backup manifest does not belong to this target.");

            foreach (var entry in manifest.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                EnsureWithin(options.OutputDirectory, entry.Destination);
                if (entry.Existed)
                {
                    if (entry.BackupFile is null || !File.Exists(entry.BackupFile))
                        return new(false, Message: $"Backup for '{Path.GetFileName(entry.Destination)}' is missing.");
                    await AtomicWriteAsync(entry.Destination, await File.ReadAllBytesAsync(entry.BackupFile, cancellationToken), null, cancellationToken);
                }
                else if (File.Exists(entry.Destination))
                {
                    File.Delete(entry.Destination);
                }
            }
            return new(true, context.Deployment.PreviousFingerprint, "Previous files were restored.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return new(false, Message: exception.Message);
        }
    }

    private static async Task AtomicWriteAsync(
        string destination,
        byte[] content,
        UnixFileMode? mode,
        CancellationToken cancellationToken)
    {
        var temporary = $"{destination}.tmp-{Guid.NewGuid():N}";
        try
        {
            await File.WriteAllBytesAsync(temporary, content, cancellationToken);
            if (!OperatingSystem.IsWindows() && mode is not null)
                File.SetUnixFileMode(temporary, mode.Value);
            File.Move(temporary, destination, true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken));
    }

    private static FileSystemTargetOptions Parse(DeploymentTarget target)
    {
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(target.ConfigurationJson) ? "{}" : target.ConfigurationJson);
        var root = document.RootElement;
        var configuredOutput = RequiredString(root, "outputDirectory");
        if (!Path.IsPathFullyQualified(configuredOutput))
            throw new InvalidOperationException("File-system outputDirectory must be an absolute path.");
        var output = Path.GetFullPath(configuredOutput);
        var certificateFile = SafeFileName(root, "certificateFile");
        var privateKeyFile = SafeFileName(root, "privateKeyFile");
        var fullChainFile = SafeFileName(root, "fullChainFile");
        var pfxFile = OptionalSafeFileName(root, "pfxFile");
        var names = new[] { certificateFile, privateKeyFile, fullChainFile, pfxFile }.Where(x => x is not null).ToList();
        if (names.Distinct(PathComparer).Count() != names.Count)
            throw new InvalidOperationException("File-system export file names must be unique.");
        return new(
            output,
            certificateFile,
            privateKeyFile,
            fullChainFile,
            pfxFile,
            ParseMode(root, "privateKeyUnixMode", UnixFileMode.UserRead | UnixFileMode.UserWrite),
            ParseMode(root, "publicFileUnixMode", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead));
    }

    private static string RequiredString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : throw new InvalidOperationException($"File-system configuration requires {name}.");

    private static string SafeFileName(JsonElement root, string name)
    {
        var value = RequiredString(root, name);
        return value == Path.GetFileName(value) && value.IndexOfAny(Path.GetInvalidFileNameChars()) < 0
            ? value
            : throw new InvalidOperationException($"{name} must be a file name without a directory.");
    }

    private static string? OptionalSafeFileName(JsonElement root, string name) =>
        !root.TryGetProperty(name, out var value) ||
        value.ValueKind is JsonValueKind.Null ||
        value.ValueKind == JsonValueKind.String && string.IsNullOrWhiteSpace(value.GetString())
            ? null
            : SafeFileName(root, name);

    private static UnixFileMode ParseMode(JsonElement root, string name, UnixFileMode fallback)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
            return fallback;
        var text = value.GetString();
        if (text is null || text.Length != 3 || text.Any(character => character is < '0' or > '7'))
            throw new InvalidOperationException($"{name} must be a three-digit octal mode such as 600 or 644.");
        return (UnixFileMode)Convert.ToInt32(text, 8);
    }

    private static IEnumerable<string> DestinationPaths(FileSystemTargetOptions options)
    {
        yield return PathFor(options, options.CertificateFile);
        yield return PathFor(options, options.PrivateKeyFile);
        yield return PathFor(options, options.FullChainFile);
        if (options.PfxFile is not null)
            yield return PathFor(options, options.PfxFile);
    }

    private static string PathFor(FileSystemTargetOptions options, string name)
    {
        var path = Path.GetFullPath(Path.Combine(options.OutputDirectory, name));
        EnsureWithin(options.OutputDirectory, path);
        return path;
    }

    private static string BackupDirectory(FileSystemTargetOptions options, Guid deploymentId) =>
        Path.Combine(options.OutputDirectory, ".certdiscovery-backups", deploymentId.ToString("N"));

    private static void EnsureWithin(string root, string path)
    {
        var relative = Path.GetRelativePath(root, Path.GetFullPath(path));
        if (relative == ".." || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            throw new InvalidOperationException("File-system path escapes the configured output directory.");
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    private static StringComparer PathComparer =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private sealed record FileSystemTargetOptions(
        string OutputDirectory,
        string CertificateFile,
        string PrivateKeyFile,
        string FullChainFile,
        string? PfxFile,
        UnixFileMode PrivateKeyMode,
        UnixFileMode PublicFileMode);
    private sealed record FileBackupEntry(string Destination, bool Existed, string? BackupFile);
    private sealed record FileBackupManifest(Guid DeploymentId, string OutputDirectory, IReadOnlyList<FileBackupEntry> Entries);
}
