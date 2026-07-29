using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class AwsAcmCertificateDeployer(
    IAwsAcmGateway acm,
    IVersionedDeploymentCertificateBundleSource bundles,
    ITlsEndpointVerifier tlsVerifier) : ICertificateDeployer
{
    public DeploymentTargetType TargetType => DeploymentTargetType.AwsAcm;

    public Task<DeploymentValidationResult> ValidateTargetAsync(
        DeploymentTargetContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            _ = AwsAcmTargetOptions.Parse(context.Target);
            return Task.FromResult(new DeploymentValidationResult(true));
        }
        catch (Exception ex) when (ex is InvalidOperationException or JsonException)
        {
            return Task.FromResult(new DeploymentValidationResult(false, ex.Message));
        }
    }

    public async Task<DeploymentPrecheckResult> PrecheckAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        var options = AwsAcmTargetOptions.Parse(context.Target);
        var arn = ResourceArn(context, options);
        if (arn is null)
            return new(true, Message: "A new imported ACM certificate will be created.");
        var state = await acm.DescribeAsync(options, context.Secret, arn, cancellationToken);
        if (state is null)
            return options.CreateIfMissing
                ? new(true, Message: "The configured ACM certificate is absent; a new certificate will be created.")
                : new(false, Message: "The configured AWS ACM certificate was not found.");
        if (!string.Equals(state.Type, "IMPORTED", StringComparison.OrdinalIgnoreCase))
            return new(false, Message: "Only imported AWS ACM certificates can be replaced.");
        var fingerprint = await acm.GetFingerprintAsync(options, context.Secret, arn, cancellationToken);
        return new(true, fingerprint, $"Imported ACM certificate '{arn}' is ready for replacement.");
    }

    public async Task<DeploymentBackupResult> BackupAsync(
        DeploymentContext context,
        CancellationToken cancellationToken)
    {
        var options = AwsAcmTargetOptions.Parse(context.Target);
        var arn = ResourceArn(context, options);
        if (arn is null)
            return Manifest(context, null, null, null, false, "No existing ACM certificate requires rollback material.");
        var state = await acm.DescribeAsync(options, context.Secret, arn, cancellationToken);
        if (state is null)
            return Manifest(context, null, null, null, false, "The missing ACM certificate will be created as a new resource.");
        if (!string.Equals(state.Type, "IMPORTED", StringComparison.OrdinalIgnoreCase))
            return new(false, Message: "Only imported AWS ACM certificates can be backed up for replacement.");

        var currentFingerprint = await acm.GetFingerprintAsync(options, context.Secret, arn, cancellationToken);
        var latest = await bundles.LoadAsync(context.Deployment, cancellationToken);
        if (latest.VaultVersion is null || latest.VaultVersion <= 1)
            return options.RequirePreviousVaultVersionForUpdate
                ? new(false, Message: "The previous certificate version is not available in Vault; ACM update was blocked.")
                : Manifest(context, arn, null, currentFingerprint, true, "ACM metadata recorded without rollback material.");
        var previousVersion = latest.VaultVersion.Value - 1;
        var previous = await bundles.LoadVersionAsync(context.Deployment, previousVersion, cancellationToken);
        if (!string.Equals(previous.Fingerprint, currentFingerprint, StringComparison.OrdinalIgnoreCase))
            return new(false, Message: "The previous Vault version does not match the certificate currently stored in ACM.");
        return Manifest(
            context,
            arn,
            previousVersion,
            currentFingerprint,
            true,
            $"Rollback points to Vault certificate version {previousVersion}; no certificate material was copied.");
    }

    public async Task<DeploymentApplyResult> DeployAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        var options = AwsAcmTargetOptions.Parse(context.Target);
        var arn = ResourceArn(context, options);
        if (arn is not null && await acm.DescribeAsync(options, context.Secret, arn, cancellationToken) is null)
            arn = null;
        var importedArn = await acm.ImportAsync(options, context.Secret, arn, bundle, cancellationToken);
        context.Deployment.ExternalResourceReference = importedArn;
        return new(true, arn is null
            ? $"Created imported ACM certificate '{importedArn}'."
            : $"Updated imported ACM certificate '{importedArn}' in place.");
    }

    public Task<DeploymentActivationResult> ActivateAsync(
        DeploymentContext context,
        CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentActivationResult(true, "AWS ACM import is active without a separate activation step."));

    public async Task<DeploymentVerificationResult> VerifyAsync(
        DeploymentContext context,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        var options = AwsAcmTargetOptions.Parse(context.Target);
        var arn = ResourceArn(context, options);
        if (arn is null)
            return new(false, Message: "The imported AWS ACM certificate ARN was not recorded.");
        var state = await acm.DescribeAsync(options, context.Secret, arn, cancellationToken);
        if (state is null || !string.Equals(state.Type, "IMPORTED", StringComparison.OrdinalIgnoreCase))
            return new(false, Message: "The imported AWS ACM certificate could not be verified.");
        var observed = await acm.GetFingerprintAsync(options, context.Secret, arn, cancellationToken);
        if (!string.Equals(observed, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase))
            return new(false, observed, "AWS ACM returned a different certificate fingerprint.");
        return new(true, observed, $"AWS ACM certificate '{arn}' internal state was verified.");
    }

    public async Task<DeploymentRollbackResult> RollbackAsync(
        DeploymentContext context,
        DeploymentBackupResult backup,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(backup.BackupReference))
            return new(false, Message: "AWS ACM rollback manifest is missing.");
        AwsAcmBackupManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<AwsAcmBackupManifest>(backup.BackupReference);
        }
        catch (JsonException)
        {
            return new(false, Message: "AWS ACM rollback manifest is invalid.");
        }
        if (manifest is null || manifest.DeploymentId != context.Deployment.Id)
            return new(false, Message: "AWS ACM rollback manifest does not belong to this deployment.");
        if (!manifest.CertificateExisted)
            return new(true, Message: "The newly created ACM certificate was retained by the safe rollback policy.");
        if (manifest.CertificateArn is null || manifest.PreviousVaultVersion is null)
            return new(false, Message: "AWS ACM rollback has no previous Vault version.");

        var options = AwsAcmTargetOptions.Parse(context.Target);
        var previous = await bundles.LoadVersionAsync(
            context.Deployment,
            manifest.PreviousVaultVersion.Value,
            cancellationToken);
        if (!string.Equals(previous.Fingerprint, manifest.PreviousFingerprint, StringComparison.OrdinalIgnoreCase))
            return new(false, ObservedFingerprint: manifest.PreviousFingerprint,
                Message: "The rollback Vault version fingerprint does not match the manifest.");
        var arn = await acm.ImportAsync(
            options,
            context.Secret,
            manifest.CertificateArn,
            previous,
            cancellationToken);
        var observed = await acm.GetFingerprintAsync(options, context.Secret, arn, cancellationToken);
        if (!string.Equals(observed, previous.Fingerprint, StringComparison.OrdinalIgnoreCase))
            return new(false, observed, "AWS ACM rollback fingerprint verification failed.");
        if (options.ExternalVerificationEndpoints.Count > 0)
        {
            var external = await tlsVerifier.VerifyAsync(
                options.ExternalVerificationEndpoints,
                previous.Fingerprint,
                cancellationToken);
            if (!external.Succeeded)
                return new(false, external.ObservedFingerprint, external.Message);
        }
        context.Deployment.ExternalResourceReference = arn;
        return new(true, observed,
            $"AWS ACM certificate was restored from Vault version {manifest.PreviousVaultVersion.Value}.");
    }

    private static string? ResourceArn(DeploymentContext context, AwsAcmTargetOptions options) =>
        context.Deployment.ExternalResourceReference ?? options.CertificateArn;

    private static DeploymentBackupResult Manifest(
        DeploymentContext context,
        string? arn,
        int? previousVaultVersion,
        string? previousFingerprint,
        bool existed,
        string message) =>
        new(
            true,
            JsonSerializer.Serialize(new AwsAcmBackupManifest(
                context.Deployment.Id,
                arn,
                previousVaultVersion,
                previousFingerprint,
                existed)),
            message);
}
