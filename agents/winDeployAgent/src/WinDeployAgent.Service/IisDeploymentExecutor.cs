using System.Security.Cryptography;

namespace WinDeployAgent;

public sealed class IisDeploymentExecutor(
    IWindowsCertificateStore certificates,
    IIisBindingStore bindings,
    ICentralCertificateStore centralCertificateStore,
    ILogger<IisDeploymentExecutor> logger)
{
    public Task<IisExecutionResult> ExecuteAsync(
        AgentJobProcessor.AgentCertificateBundle bundle,
        string targetConfigurationJson,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var options = IisTargetOptions.Parse(targetConfigurationJson);
        IisBindingSnapshot? snapshot = null;
        CertificateImportResult? imported = null;
        CcsFileSnapshot? ccsSnapshot = null;
        byte[]? pfx = null;
        try
        {
            snapshot = bindings.Capture(options);
            pfx = Convert.FromBase64String(bundle.PfxBase64);
            if (string.Equals(options.DeploymentMode, "CentralCertificateStore", StringComparison.OrdinalIgnoreCase))
            {
                if (!bindings.UsesCentralCertificateStore(snapshot))
                    throw new InvalidOperationException("The configured Microsoft IIS binding does not use Central Certificate Store.");
                ccsSnapshot = centralCertificateStore.Replace(pfx, bundle.Password, options);
                var observed = centralCertificateStore.VerifyFingerprint(ccsSnapshot, bundle.Password);
                if (!string.Equals(observed, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Central Certificate Store fingerprint verification failed.");
                return Task.FromResult(new IisExecutionResult(true, false, observed, null, null, null));
            }

            var previousFingerprint = certificates.FindSha256Fingerprint(
                snapshot.CertificateHash, snapshot.CertificateStoreName);
            imported = certificates.Import(pfx, bundle.Password, options.CertificateStoreName);
            if (!string.Equals(imported.Sha256Fingerprint, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The PFX fingerprint does not match the deployment job.");

            cancellationToken.ThrowIfCancellationRequested();
            bindings.Apply(snapshot, imported.BindingHash, options.CertificateStoreName, options.RestartApplicationPool);
            if (!bindings.IsApplied(snapshot, imported.BindingHash, options.CertificateStoreName))
                throw new InvalidOperationException("Microsoft IIS binding verification failed.");

            return Task.FromResult(new IisExecutionResult(
                true, false, imported.Sha256Fingerprint, previousFingerprint, null, null));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            var rolledBack = false;
            if (ccsSnapshot is not null)
            {
                try
                {
                    centralCertificateStore.Restore(ccsSnapshot);
                    rolledBack = true;
                }
                catch (Exception rollbackException)
                {
                    logger.LogError("Microsoft IIS CCS rollback failed with {ErrorType}.", rollbackException.GetType().Name);
                }
            }
            else if (snapshot is not null && imported is not null)
            {
                try
                {
                    bindings.Restore(snapshot, options.RestartApplicationPool);
                    rolledBack = snapshot.CertificateHash is null ||
                                 bindings.IsApplied(snapshot, snapshot.CertificateHash, snapshot.CertificateStoreName ?? options.CertificateStoreName);
                    certificates.Remove(imported.AddedCertificateHashes, options.CertificateStoreName);
                }
                catch (Exception rollbackException)
                {
                    logger.LogError(
                        "Microsoft IIS rollback failed with {ErrorType}.",
                        rollbackException.GetType().Name);
                }
            }
            return Task.FromResult(new IisExecutionResult(
                false,
                rolledBack,
                null,
                snapshot is null ? null : certificates.FindSha256Fingerprint(snapshot.CertificateHash, snapshot.CertificateStoreName),
                exception is InvalidOperationException ? "IisValidationFailed" : "IisDeploymentFailed",
                exception.Message));
        }
        finally
        {
            if (pfx is not null) CryptographicOperations.ZeroMemory(pfx);
        }
    }
}
