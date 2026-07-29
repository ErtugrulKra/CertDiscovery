using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class AzureKeyVaultCertificateDeployer(
    IAzureKeyVaultCertificateGateway keyVault,
    IVersionedDeploymentCertificateBundleSource bundles,
    ITlsEndpointVerifier tlsVerifier) : ICertificateDeployer
{
    public DeploymentTargetType TargetType => DeploymentTargetType.AzureKeyVault;

    public async Task<DeploymentValidationResult> ValidateTargetAsync(
        DeploymentTargetContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var options = AzureKeyVaultTargetOptions.Parse(context.Target);
            ValidateSecret(options, context.Secret);
            _ = await keyVault.GetCurrentAsync(options, context.Secret, cancellationToken);
            return new(true, "Azure Key Vault target and data-plane access were validated.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or JsonException or Azure.RequestFailedException)
        {
            return new(false, SafeMessage(ex));
        }
    }

    public async Task<DeploymentPrecheckResult> PrecheckAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        var options = AzureKeyVaultTargetOptions.Parse(context.Target);
        ValidateSecret(options, context.Secret);
        var current = await keyVault.GetCurrentAsync(options, context.Secret, cancellationToken);
        if (current is null)
            return new(true, Message: "A first Azure Key Vault certificate version will be created.");
        return new(
            true,
            current.Fingerprint,
            $"Azure Key Vault certificate version '{current.Version}' is ready for replacement.");
    }

    public async Task<DeploymentBackupResult> BackupAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        var existingManifest = ReadManifest(context.Deployment.BackupReference, context.Deployment.Id);
        if (existingManifest is not null)
            return new(true, context.Deployment.BackupReference, "The existing Azure Key Vault rollback manifest was reused.");

        var options = AzureKeyVaultTargetOptions.Parse(context.Target);
        var current = await keyVault.GetCurrentAsync(options, context.Secret, cancellationToken);
        if (current is null)
            return Manifest(context, options.CertificateName, null, null, null, null, false,
                "No existing Azure Key Vault certificate requires rollback material.");

        var latest = await bundles.LoadAsync(context.Deployment, cancellationToken);
        if (latest.VaultVersion is null || latest.VaultVersion <= 1)
            return options.RequirePreviousVaultVersionForRollback
                ? new(false, Message: "The previous certificate version is not available in source Vault; Azure Key Vault update was blocked.")
                : Manifest(context, options.CertificateName, current.CertificateUri, current.Version,
                    current.Fingerprint, null, true, "Azure metadata recorded without source Vault rollback material.");
        var previousVersion = latest.VaultVersion.Value - 1;
        var previous = await bundles.LoadVersionAsync(context.Deployment, previousVersion, cancellationToken);
        if (!string.Equals(previous.Fingerprint, current.Fingerprint, StringComparison.OrdinalIgnoreCase))
            return new(false,
                Message: "The previous source Vault version does not match the certificate currently stored in Azure Key Vault.");
        return Manifest(
            context,
            options.CertificateName,
            current.CertificateUri,
            current.Version,
            current.Fingerprint,
            previousVersion,
            true,
            $"Rollback references source Vault certificate version {previousVersion}; no certificate material was copied.");
    }

    public async Task<DeploymentApplyResult> DeployAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        var options = AzureKeyVaultTargetOptions.Parse(context.Target);
        var current = await keyVault.GetCurrentAsync(options, context.Secret, cancellationToken);
        if (current is not null &&
            string.Equals(current.Fingerprint, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase) &&
            MatchesConfiguration(current, options, bundle))
        {
            context.Deployment.ExternalResourceReference = current.CertificateUri;
            return new(true, $"Azure Key Vault certificate version '{current.Version}' already contains the expected certificate.");
        }
        var imported = await keyVault.ImportAsync(options, context.Secret, bundle, cancellationToken);
        context.Deployment.ExternalResourceReference = imported.CertificateUri;
        return new(true, $"Created Azure Key Vault certificate version '{imported.Version}'.");
    }

    public Task<DeploymentActivationResult> ActivateAsync(
        DeploymentContext context,
        CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentActivationResult(
            true,
            "Azure Key Vault certificate import is versioned and requires no separate activation."));

    public async Task<DeploymentVerificationResult> VerifyAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        var options = AzureKeyVaultTargetOptions.Parse(context.Target);
        var current = await keyVault.GetCurrentAsync(options, context.Secret, cancellationToken);
        if (current is null)
            return new(false, Message: "Azure Key Vault did not return the imported certificate.");
        if (!string.Equals(current.Fingerprint, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase))
            return new(false, current.Fingerprint, "Azure Key Vault returned a different certificate fingerprint.");
        if (!MatchesConfiguration(current, options, bundle))
            return new(false, current.Fingerprint,
                "Azure Key Vault certificate content type, enabled state, or managed tags do not match the target.");
        if (current.ExpiresOn is not null && current.ExpiresOn <= DateTimeOffset.UtcNow)
            return new(false, current.Fingerprint, "Azure Key Vault returned an expired certificate version.");
        if (context.Deployment.ExternalResourceReference is not null &&
            !string.Equals(current.CertificateUri, context.Deployment.ExternalResourceReference, StringComparison.OrdinalIgnoreCase))
            return new(false, current.Fingerprint, "Azure Key Vault current version URI changed during verification.");
        return new(true, current.Fingerprint,
            $"Azure Key Vault certificate version '{current.Version}' internal state was verified.");
    }

    public async Task<DeploymentRollbackResult> RollbackAsync(
        DeploymentContext context,
        DeploymentBackupResult backup,
        CancellationToken cancellationToken)
    {
        var manifest = ReadManifest(backup.BackupReference, context.Deployment.Id);
        if (manifest is null)
            return new(false, Message: "Azure Key Vault rollback manifest is missing or invalid.");
        if (!manifest.CertificateExisted)
            return new(true, Message: "The first Azure Key Vault certificate version was retained by the safe rollback policy.");
        if (manifest.PreviousSourceVaultVersion is null || manifest.PreviousFingerprint is null)
            return new(false, Message: "Azure Key Vault rollback has no previous source Vault version.");

        var options = AzureKeyVaultTargetOptions.Parse(context.Target);
        var previous = await bundles.LoadVersionAsync(
            context.Deployment,
            manifest.PreviousSourceVaultVersion.Value,
            cancellationToken);
        if (!string.Equals(previous.Fingerprint, manifest.PreviousFingerprint, StringComparison.OrdinalIgnoreCase))
            return new(false, manifest.PreviousFingerprint,
                "The rollback source Vault version fingerprint does not match the manifest.");
        var restored = await keyVault.ImportAsync(options, context.Secret, previous, cancellationToken);
        if (!string.Equals(restored.Fingerprint, previous.Fingerprint, StringComparison.OrdinalIgnoreCase))
            return new(false, restored.Fingerprint, "Azure Key Vault rollback fingerprint verification failed.");
        if (!MatchesConfiguration(restored, options, previous))
            return new(false, restored.Fingerprint, "Azure Key Vault rollback metadata verification failed.");
        if (options.ExternalVerificationEndpoints.Count > 0)
        {
            var external = await tlsVerifier.VerifyAsync(
                options.ExternalVerificationEndpoints,
                previous.Fingerprint,
                cancellationToken);
            if (!external.Succeeded)
                return new(false, external.ObservedFingerprint, external.Message);
        }
        context.Deployment.ExternalResourceReference = restored.CertificateUri;
        return new(true, restored.Fingerprint,
            $"Azure Key Vault rollback created version '{restored.Version}' from source Vault version {manifest.PreviousSourceVaultVersion.Value}.");
    }

    private static bool MatchesConfiguration(
        AzureKeyVaultCertificateState state,
        AzureKeyVaultTargetOptions options,
        IssuedCertificateBundle bundle) =>
        string.Equals(state.Name, options.CertificateName, StringComparison.Ordinal) &&
        string.Equals(state.ContentType, options.ContentType, StringComparison.OrdinalIgnoreCase) &&
        state.Enabled == options.Enabled &&
        HasTag(state, "certdiscovery-managed-by", "CertDiscovery") &&
        HasTag(state, "certdiscovery-fingerprint", bundle.Fingerprint) &&
        (bundle.VaultVersion is null ||
         HasTag(state, "certdiscovery-source-vault-version", bundle.VaultVersion.Value.ToString())) &&
        options.Tags.All(tag => HasTag(state, tag.Key, tag.Value));

    private static bool HasTag(AzureKeyVaultCertificateState state, string key, string value) =>
        state.Tags.TryGetValue(key, out var observed) &&
        string.Equals(observed, value, StringComparison.Ordinal);

    private static void ValidateSecret(AzureKeyVaultTargetOptions options, string? clientSecret)
    {
        if (options.AuthenticationMode == AzureKeyVaultAuthenticationMode.ServicePrincipal &&
            string.IsNullOrWhiteSpace(clientSecret))
            throw new InvalidOperationException(
                "Azure Key Vault service-principal authentication requires a protected client secret.");
        if (options.AuthenticationMode != AzureKeyVaultAuthenticationMode.ServicePrincipal &&
            !string.IsNullOrWhiteSpace(clientSecret))
            throw new InvalidOperationException(
                "Azure Key Vault target Secret is accepted only with ServicePrincipal authentication.");
    }

    private static AzureKeyVaultBackupManifest? ReadManifest(string? json, Guid deploymentId)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            var manifest = JsonSerializer.Deserialize<AzureKeyVaultBackupManifest>(json);
            return manifest?.DeploymentId == deploymentId ? manifest : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static DeploymentBackupResult Manifest(
        DeploymentContext context,
        string certificateName,
        string? previousAzureUri,
        string? previousAzureVersion,
        string? previousFingerprint,
        int? previousSourceVaultVersion,
        bool existed,
        string message) =>
        new(
            true,
            JsonSerializer.Serialize(new AzureKeyVaultBackupManifest(
                context.Deployment.Id,
                certificateName,
                previousAzureUri,
                previousAzureVersion,
                previousFingerprint,
                previousSourceVaultVersion,
                existed)),
            message);

    private static string SafeMessage(Exception exception)
    {
        var message = exception is Azure.RequestFailedException requestFailed
            ? $"Azure Key Vault request failed with status {requestFailed.Status} and code '{requestFailed.ErrorCode ?? "Unknown"}'."
            : exception.Message;
        return message[..Math.Min(message.Length, 1024)];
    }
}
