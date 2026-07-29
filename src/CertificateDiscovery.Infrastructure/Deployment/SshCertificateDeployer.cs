using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public abstract class SshCertificateDeployer(
    ISshCredentialSource credentials,
    ISshRemoteClient remote,
    ITlsEndpointVerifier tlsVerifier) : ICertificateDeployer
{
    public abstract DeploymentTargetType TargetType { get; }

    public async Task<DeploymentValidationResult> ValidateTargetAsync(
        DeploymentTargetContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            var credential = await CredentialAsync(options, context.Secret, cancellationToken);
            await remote.ProbeAsync(options, credential, cancellationToken);
            return new(true);
        }
        catch (Exception exception) when (IsExpected(exception))
        {
            return new(false, Safe(exception.Message));
        }
    }

    public async Task<DeploymentPrecheckResult> PrecheckAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            var credential = await CredentialAsync(options, context.Secret, cancellationToken);
            await remote.ProbeAsync(options, credential, cancellationToken);
            return new(true, Message: "SSH host identity and connectivity verified.");
        }
        catch (Exception exception) when (IsExpected(exception))
        {
            return new(false, Message: Safe(exception.Message));
        }
    }

    public async Task<DeploymentBackupResult> BackupAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            var credential = await CredentialAsync(options, context.Secret, cancellationToken);
            var files = await remote.BackupAsync(
                options, credential, context.Deployment.Id, Paths(options), cancellationToken);
            return new(true, JsonSerializer.Serialize(new SshDeploymentBackup(context.Deployment.Id, files)));
        }
        catch (Exception exception) when (IsExpected(exception))
        {
            return new(false, Message: Safe(exception.Message));
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
            var credential = await CredentialAsync(options, context.Secret, cancellationToken);
            foreach (var file in Files(options, bundle))
            {
                var bytes = Encoding.UTF8.GetBytes(file.Content);
                try
                {
                    await remote.WriteAtomicAsync(
                        options, credential, file.Path, bytes, file.Mode, cancellationToken);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
            return new(true, "Certificate files were replaced atomically over SSH.");
        }
        catch (Exception exception) when (IsExpected(exception))
        {
            return new(false, Safe(exception.Message));
        }
    }

    public async Task<DeploymentActivationResult> ActivateAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            var credential = await CredentialAsync(options, context.Secret, cancellationToken);
            if (options.ConfigurationTest)
                await remote.ExecuteValidationAsync(options, credential, cancellationToken);
            if (options.ReloadService)
                await remote.ExecuteReloadAsync(options, credential, cancellationToken);
            return new(true, $"{DisplayName()} configuration validated and service reloaded.");
        }
        catch (Exception exception) when (IsExpected(exception))
        {
            return new(false, Safe(exception.Message));
        }
    }

    public async Task<DeploymentVerificationResult> VerifyAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = Parse(context.Target);
            var credential = await CredentialAsync(options, context.Secret, cancellationToken);
            foreach (var file in Files(options, bundle))
            {
                var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(file.Content)));
                var observed = await remote.HashAsync(options, credential, file.Path, cancellationToken);
                if (!string.Equals(expected, observed, StringComparison.Ordinal))
                    return new(false, Message: $"Remote file '{file.Path}' failed SHA-256 verification.");
            }
            if (options.ExternalVerificationEndpoints.Count > 0)
            {
                var external = await tlsVerifier.VerifyAsync(
                    options.ExternalVerificationEndpoints, bundle.Fingerprint, cancellationToken);
                if (!external.Succeeded)
                    return new(false, external.ObservedFingerprint, external.Message);
            }
            return new(true, bundle.Fingerprint,
                $"{DisplayName()} remote file hashes and external TLS endpoints verified.");
        }
        catch (Exception exception) when (IsExpected(exception))
        {
            return new(false, Message: Safe(exception.Message));
        }
    }

    public async Task<DeploymentRollbackResult> RollbackAsync(
        DeploymentContext context,
        DeploymentBackupResult backup,
        CancellationToken cancellationToken)
    {
        try
        {
            var manifest = JsonSerializer.Deserialize<SshDeploymentBackup>(backup.BackupReference ?? string.Empty)
                ?? throw new InvalidOperationException("SSH backup reference is invalid.");
            if (manifest.DeploymentId != context.Deployment.Id)
                throw new InvalidOperationException("SSH backup reference does not belong to this deployment.");
            var options = Parse(context.Target);
            if (!manifest.Files.Select(x => x.Path).Order().SequenceEqual(Paths(options).Order(), StringComparer.Ordinal))
                throw new InvalidOperationException("SSH backup reference does not belong to this target.");
            var credential = await CredentialAsync(options, context.Secret, cancellationToken);
            await remote.RestoreAsync(options, credential, manifest.Files, cancellationToken);
            if (options.ConfigurationTest)
                await remote.ExecuteValidationAsync(options, credential, cancellationToken);
            if (options.ReloadService)
                await remote.ExecuteReloadAsync(options, credential, cancellationToken);
            return new(true, context.Deployment.PreviousFingerprint, "Previous remote certificate files were restored and activated.");
        }
        catch (Exception exception) when (IsExpected(exception))
        {
            return new(false, Message: Safe(exception.Message));
        }
    }

    private SshCertificateTargetOptions Parse(DeploymentTarget target)
    {
        var options = SshCertificateTargetOptions.Parse(target);
        if (options.TargetType != TargetType)
            throw new InvalidOperationException("SSH deployer target type mismatch.");
        return options;
    }

    private async Task<SshPrivateKeyCredential> CredentialAsync(
        SshCertificateTargetOptions options,
        string? token,
        CancellationToken cancellationToken) =>
        await credentials.LoadAsync(
            options,
            !string.IsNullOrWhiteSpace(token)
                ? token
                : throw new InvalidOperationException("A Vault token secret is required for SSH deployment."),
            cancellationToken);

    private static IReadOnlyList<string> Paths(SshCertificateTargetOptions options) =>
        new[] { options.CertificatePath, options.PrivateKeyPath, options.FullChainPath, options.ChainPath }
            .Where(x => x is not null).Cast<string>().ToList();

    private static IEnumerable<RemoteCertificateFile> Files(
        SshCertificateTargetOptions options,
        IssuedCertificateBundle bundle)
    {
        yield return new(options.CertificatePath, bundle.CertificatePem, options.CertificateMode);
        yield return new(options.PrivateKeyPath, bundle.PrivateKeyPem, options.PrivateKeyMode);
        yield return new(options.FullChainPath, bundle.FullChainPem, options.CertificateMode);
        if (options.ChainPath is not null)
            yield return new(options.ChainPath, ChainOnly(bundle.FullChainPem), options.CertificateMode);
    }

    private static string ChainOnly(string fullChain)
    {
        const string end = "-----END CERTIFICATE-----";
        var first = fullChain.IndexOf(end, StringComparison.Ordinal);
        return first >= 0 && first + end.Length < fullChain.Length
            ? fullChain[(first + end.Length)..].TrimStart() + Environment.NewLine
            : string.Empty;
    }

    private string DisplayName() => TargetType == DeploymentTargetType.Nginx ? "NGNIX" : "Apache Web Server";
    private static bool IsExpected(Exception exception) =>
        exception is InvalidOperationException or JsonException or IOException or
            UnauthorizedAccessException or TimeoutException or System.Net.Sockets.SocketException or
            Renci.SshNet.Common.SshException or CryptographicException;
    private static string Safe(string message) => message[..Math.Min(message.Length, 1024)];
    private sealed record RemoteCertificateFile(string Path, string Content, string Mode);
}

public sealed class NginxSshCertificateDeployer(
    ISshCredentialSource credentials,
    ISshRemoteClient remote,
    ITlsEndpointVerifier tlsVerifier) : SshCertificateDeployer(credentials, remote, tlsVerifier)
{
    public override DeploymentTargetType TargetType => DeploymentTargetType.Nginx;
}

public sealed class ApacheSshCertificateDeployer(
    ISshCredentialSource credentials,
    ISshRemoteClient remote,
    ITlsEndpointVerifier tlsVerifier) : SshCertificateDeployer(credentials, remote, tlsVerifier)
{
    public override DeploymentTargetType TargetType => DeploymentTargetType.ApacheWebServer;
}
