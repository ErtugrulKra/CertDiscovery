using System.Security.Cryptography;
using System.Text.Json;
using WinDeployAgent.Contracts;

namespace WinDeployAgent;

public sealed class AgentJobProcessor(
    CentralClient central,
    IisDeploymentExecutor executor,
    ILogger<AgentJobProcessor> logger)
{
    public async Task<bool> ProcessAsync(AgentIdentity identity, AgentJobClaimResponse job, CancellationToken cancellationToken)
    {
        using var leaseCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var leaseRenewal = RenewLeaseUntilCancelledAsync(identity, job, leaseCancellation.Token);
        try
        {
            await central.StageAsync(identity, job, "BundleDownload", null, cancellationToken);
            var encrypted = await central.GetBundleAsync(identity, job, cancellationToken);
            var bundle = Decrypt(encrypted.EncryptedBundleJson, identity.PrivateKeyPem);
            await central.StageAsync(identity, job, "BundleDecrypted", null, cancellationToken);
            await central.StageAsync(identity, job, "IisDeployment", null, cancellationToken);
            var result = await executor.ExecuteAsync(bundle, job.TargetConfigurationJson, cancellationToken);
            await central.StageAsync(
                identity,
                job,
                result.Succeeded ? "BindingVerified" : result.RolledBack ? "RolledBack" : "Failed",
                result.ErrorCode,
                cancellationToken);
            await central.CompleteAsync(identity, job, new(
                job.LeaseToken,
                result.Succeeded,
                result.RolledBack,
                result.ObservedFingerprint,
                result.PreviousFingerprint,
                result.ErrorCode,
                result.ErrorMessage), cancellationToken);
            return true;
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogError("Agent job {JobId} failed with {ErrorType}.", job.JobId, exception.GetType().Name);
            try
            {
                await central.CompleteAsync(identity, job,
                    new(job.LeaseToken, false, false, null, null, "AgentJobFailed", exception.GetType().Name),
                    cancellationToken);
                return true;
            }
            catch (Exception reportException)
            {
                logger.LogError("Agent job {JobId} result reporting failed with {ErrorType}.", job.JobId, reportException.GetType().Name);
                return false;
            }
        }
        finally
        {
            leaseCancellation.Cancel();
            try
            {
                await leaseRenewal;
            }
            catch (OperationCanceledException) when (leaseCancellation.IsCancellationRequested)
            {
            }
        }
    }

    private async Task RenewLeaseUntilCancelledAsync(
        AgentIdentity identity,
        AgentJobClaimResponse job,
        CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            await central.RenewLeaseAsync(identity, job, cancellationToken);
        }
    }

    internal static AgentCertificateBundle Decrypt(string envelopeJson, string privateKeyPem)
    {
        var envelope = JsonSerializer.Deserialize<AgentBundleEnvelope>(envelopeJson)
            ?? throw new InvalidOperationException("Encrypted bundle envelope is invalid.");
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var key = rsa.Decrypt(Convert.FromBase64String(envelope.EncryptedKey), RSAEncryptionPadding.OaepSHA256);
        var nonce = Convert.FromBase64String(envelope.Nonce);
        var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
        var tag = Convert.FromBase64String(envelope.Tag);
        var clear = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, clear);
            return JsonSerializer.Deserialize<AgentCertificateBundle>(clear)
                ?? throw new InvalidOperationException("Decrypted certificate bundle is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(clear);
        }
    }

    public sealed record AgentCertificateBundle(string PfxBase64, string Password, string Fingerprint);
    private sealed record AgentBundleEnvelope(string EncryptedKey, string Nonce, string Ciphertext, string Tag);
}
