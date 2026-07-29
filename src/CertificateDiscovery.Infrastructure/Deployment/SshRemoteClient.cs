using System.Security.Cryptography;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace CertificateDiscovery.Infrastructure.Deployment;

public interface ISshRemoteClient
{
    Task ProbeAsync(SshCertificateTargetOptions options, SshPrivateKeyCredential credential, CancellationToken cancellationToken);
    Task<IReadOnlyList<RemoteFileBackup>> BackupAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        Guid deploymentId,
        IReadOnlyList<string> paths,
        CancellationToken cancellationToken);
    Task WriteAtomicAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        string path,
        byte[] content,
        string mode,
        CancellationToken cancellationToken);
    Task<string?> HashAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        string path,
        CancellationToken cancellationToken);
    Task ExecuteValidationAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        CancellationToken cancellationToken);
    Task ExecuteReloadAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        CancellationToken cancellationToken);
    Task RestoreAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        IReadOnlyList<RemoteFileBackup> files,
        CancellationToken cancellationToken);
}

public sealed class SshNetRemoteClient : ISshRemoteClient
{
    public async Task ProbeAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        CancellationToken cancellationToken)
    {
        using var client = CreateSftp(options, credential);
        await client.ConnectAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<RemoteFileBackup>> BackupAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        Guid deploymentId,
        IReadOnlyList<string> paths,
        CancellationToken cancellationToken)
    {
        using var client = CreateSftp(options, credential);
        await client.ConnectAsync(cancellationToken);
        var results = new List<RemoteFileBackup>();
        foreach (var path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var exists = await client.ExistsAsync(path, cancellationToken);
            var backupPath = exists ? $"{path}.certdiscovery-{deploymentId:N}.bak" : null;
            if (exists)
            {
                await using var memory = new MemoryStream();
                try
                {
                    await client.DownloadFileAsync(path, memory, cancellationToken);
                    memory.Position = 0;
                    await client.UploadFileAsync(memory, backupPath!, cancellationToken);
                    var attributes = await client.GetAttributesAsync(path, cancellationToken);
                    client.SetAttributes(backupPath!, attributes);
                }
                finally
                {
                    ZeroMemoryStream(memory);
                }
                PruneBackups(client, path, backupPath!, options.BackupRetention);
            }
            results.Add(new(path, exists, backupPath));
        }
        return results;
    }

    public async Task WriteAtomicAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        string path,
        byte[] content,
        string mode,
        CancellationToken cancellationToken)
    {
        var temporary = $"{path}.certdiscovery-{Guid.NewGuid():N}.tmp";
        using var client = CreateSftp(options, credential);
        await client.ConnectAsync(cancellationToken);
        try
        {
            await using var memory = new MemoryStream(content, writable: false);
            await client.UploadFileAsync(memory, temporary, cancellationToken);
            var attributes = await client.GetAttributesAsync(temporary, cancellationToken);
            attributes.SetPermissions(short.Parse(mode, System.Globalization.CultureInfo.InvariantCulture));
            client.SetAttributes(temporary, attributes);
            client.RenameFile(temporary, path, isPosix: true);
            await ApplyOwnershipAsync(options, credential, path, mode, cancellationToken);
        }
        finally
        {
            if (client.IsConnected && await client.ExistsAsync(temporary, CancellationToken.None))
                await client.DeleteFileAsync(temporary, CancellationToken.None);
        }
    }

    public async Task<string?> HashAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        string path,
        CancellationToken cancellationToken)
    {
        using var client = CreateSftp(options, credential);
        await client.ConnectAsync(cancellationToken);
        if (!await client.ExistsAsync(path, cancellationToken))
            return null;
        await using var memory = new MemoryStream();
        try
        {
            await client.DownloadFileAsync(path, memory, cancellationToken);
            return Convert.ToHexString(SHA256.HashData(memory.GetBuffer().AsSpan(0, checked((int)memory.Length))));
        }
        finally
        {
            ZeroMemoryStream(memory);
        }
    }

    public Task ExecuteValidationAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        CancellationToken cancellationToken) =>
        ExecuteFixedAsync(
            options, credential, options.UseSudo ? $"sudo -- {options.ValidationCommand}" : options.ValidationCommand,
            cancellationToken);

    public Task ExecuteReloadAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        CancellationToken cancellationToken) =>
        ExecuteFixedAsync(
            options, credential, options.UseSudo ? $"sudo -- {options.ReloadCommand}" : options.ReloadCommand,
            cancellationToken);

    public async Task RestoreAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        IReadOnlyList<RemoteFileBackup> files,
        CancellationToken cancellationToken)
    {
        using var client = CreateSftp(options, credential);
        await client.ConnectAsync(cancellationToken);
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!file.Existed)
            {
                if (await client.ExistsAsync(file.Path, cancellationToken))
                    await client.DeleteFileAsync(file.Path, cancellationToken);
                continue;
            }
            if (file.BackupPath is null || !await client.ExistsAsync(file.BackupPath, cancellationToken))
                throw new InvalidOperationException($"Remote backup for '{file.Path}' is missing.");
            await using var memory = new MemoryStream();
            try
            {
                await client.DownloadFileAsync(file.BackupPath, memory, cancellationToken);
                memory.Position = 0;
                var temporary = $"{file.Path}.certdiscovery-restore-{Guid.NewGuid():N}.tmp";
                try
                {
                    await client.UploadFileAsync(memory, temporary, cancellationToken);
                    var attributes = await client.GetAttributesAsync(file.BackupPath, cancellationToken);
                    client.SetAttributes(temporary, attributes);
                    client.RenameFile(temporary, file.Path, isPosix: true);
                }
                finally
                {
                    if (await client.ExistsAsync(temporary, CancellationToken.None))
                        await client.DeleteFileAsync(temporary, CancellationToken.None);
                }
            }
            finally
            {
                ZeroMemoryStream(memory);
            }
        }
    }

    private static void PruneBackups(
        SftpClient client,
        string targetPath,
        string currentBackupPath,
        int retention)
    {
        var separator = targetPath.LastIndexOf('/');
        var directory = separator <= 0 ? "/" : targetPath[..separator];
        var fileName = targetPath[(separator + 1)..];
        var prefix = $"{fileName}.certdiscovery-";
        var backups = client.ListDirectory(directory)
            .Where(x => x.IsRegularFile &&
                        x.Name.StartsWith(prefix, StringComparison.Ordinal) &&
                        x.Name.EndsWith(".bak", StringComparison.Ordinal))
            .OrderByDescending(x => string.Equals(x.FullName, currentBackupPath, StringComparison.Ordinal))
            .ThenByDescending(x => x.LastWriteTimeUtc)
            .Skip(retention);
        foreach (var backup in backups)
            client.DeleteFile(backup.FullName);
    }

    private static void ZeroMemoryStream(MemoryStream stream)
    {
        if (stream.TryGetBuffer(out var buffer) && buffer.Array is not null)
            CryptographicOperations.ZeroMemory(buffer.Array.AsSpan(buffer.Offset, buffer.Count));
    }

    private static async Task ApplyOwnershipAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        string path,
        string mode,
        CancellationToken cancellationToken)
    {
        var prefix = options.UseSudo ? "sudo -- " : string.Empty;
        var command =
            $"{prefix}chmod {mode} -- '{path}' && {prefix}chown {options.FileOwner}:{options.FileGroup} -- '{path}'";
        await ExecuteFixedAsync(options, credential, command, cancellationToken);
    }

    private static async Task ExecuteFixedAsync(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential,
        string commandText,
        CancellationToken cancellationToken)
    {
        using var client = CreateSsh(options, credential);
        await client.ConnectAsync(cancellationToken);
        using var command = client.CreateCommand(commandText);
        command.CommandTimeout = TimeSpan.FromSeconds(30);
        await command.ExecuteAsync(cancellationToken);
        if (command.ExitStatus != 0)
            throw new InvalidOperationException($"Remote allowlisted operation failed with exit status {command.ExitStatus}.");
    }

    private static SftpClient CreateSftp(SshCertificateTargetOptions options, SshPrivateKeyCredential credential)
    {
        var client = new SftpClient(Connection(options, credential));
        PinHostKey(client, options.HostKeyFingerprint);
        return client;
    }

    private static SshClient CreateSsh(SshCertificateTargetOptions options, SshPrivateKeyCredential credential)
    {
        var client = new SshClient(Connection(options, credential));
        PinHostKey(client, options.HostKeyFingerprint);
        return client;
    }

    private static ConnectionInfo Connection(
        SshCertificateTargetOptions options,
        SshPrivateKeyCredential credential)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(credential.PrivateKeyPem);
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            var key = string.IsNullOrEmpty(credential.Passphrase)
                ? new PrivateKeyFile(stream)
                : new PrivateKeyFile(stream, credential.Passphrase);
            return new ConnectionInfo(
                options.Host,
                options.Port,
                options.Username,
                new PrivateKeyAuthenticationMethod(options.Username, key))
            {
                Timeout = TimeSpan.FromSeconds(15)
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void PinHostKey(BaseClient client, string expected) =>
        client.HostKeyReceived += (_, eventArgs) =>
            eventArgs.CanTrust = string.Equals(
                $"SHA256:{eventArgs.FingerPrintSHA256}",
                expected,
                StringComparison.Ordinal);
}
