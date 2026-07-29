using System.Text.Json;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Infrastructure.Deployment;

public interface IAzureApplicationGateway
{
    Task<AzureApplicationGatewayState> GetAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, CancellationToken cancellationToken);
    Task<AzureApplicationGatewayState> ApplyKeyVaultReferenceAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, Uri secretId, CancellationToken cancellationToken);
    Task<AzureApplicationGatewayState> UploadAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, IssuedCertificateBundle bundle, CancellationToken cancellationToken);
    Task<AzureApplicationGatewayState> RestoreReferenceAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, string listenerCertificateId, string? secretId, CancellationToken cancellationToken);
}

public sealed class AzureApplicationGatewayDeployer(
    IAzureApplicationGateway gateway, IVersionedDeploymentCertificateBundleSource bundles,
    ITlsEndpointVerifier tlsVerifier) : ICertificateDeployer
{
    public DeploymentTargetType TargetType => DeploymentTargetType.AzureApplicationGateway;

    public async Task<DeploymentValidationResult> ValidateTargetAsync(DeploymentTargetContext context, CancellationToken cancellationToken)
    {
        try
        {
            var options = AzureApplicationGatewayTargetOptions.Parse(context.Target);
            ValidateSecret(options, context.Secret);
            var state = await gateway.GetAsync(options, context.Secret, cancellationToken);
            return ValidateState(options, state);
        }
        catch (Exception ex) when (ex is InvalidOperationException or JsonException or Azure.RequestFailedException)
        {
            return new(false, ex is Azure.RequestFailedException request ? $"Azure request failed with status {request.Status} and code '{request.ErrorCode ?? "Unknown"}'." : ex.Message);
        }
    }

    public async Task<DeploymentPrecheckResult> PrecheckAsync(DeploymentContext context, CancellationToken cancellationToken)
    {
        var options = AzureApplicationGatewayTargetOptions.Parse(context.Target);
        ValidateSecret(options, context.Secret);
        var validation = ValidateState(options, await gateway.GetAsync(options, context.Secret, cancellationToken));
        return new(validation.IsValid, Message: validation.Message);
    }

    public async Task<DeploymentBackupResult> BackupAsync(DeploymentContext context, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(context.Deployment.BackupReference)) return new(true, context.Deployment.BackupReference, "Existing rollback manifest reused.");
        var options = AzureApplicationGatewayTargetOptions.Parse(context.Target);
        var state = await gateway.GetAsync(options, context.Secret, cancellationToken);
        var current = await bundles.LoadAsync(context.Deployment, cancellationToken);
        int? previousVersion = null;
        string? previousFingerprint = context.Deployment.PreviousFingerprint;
        if (options.DeploymentMode == AzureApplicationGatewayDeploymentMode.DirectUpload && state.ListenerCertificateId is not null)
        {
            if (current.VaultVersion is null || current.VaultVersion <= 1)
                return options.RequirePreviousVaultVersionForRollback ? new(false, Message: "Previous source Vault version is required for direct-upload rollback.") : new(true);
            previousVersion = current.VaultVersion.Value - 1;
            var previous = await bundles.LoadVersionAsync(context.Deployment, previousVersion.Value, cancellationToken);
            previousFingerprint = previous.Fingerprint;
        }
        var manifest = new AzureApplicationGatewayBackupManifest(context.Deployment.Id, state.ListenerCertificateId,
            state.KeyVaultSecretId, previousFingerprint, previousVersion);
        return new(true, JsonSerializer.Serialize(manifest), "Application Gateway rollback metadata recorded; certificate material was not persisted.");
    }

    public async Task<DeploymentApplyResult> DeployAsync(DeploymentContext context, IssuedCertificateBundle bundle, CancellationToken cancellationToken)
    {
        var options = AzureApplicationGatewayTargetOptions.Parse(context.Target);
        var state = options.DeploymentMode == AzureApplicationGatewayDeploymentMode.KeyVaultReference
            ? await gateway.ApplyKeyVaultReferenceAsync(options, context.Secret, options.KeyVaultSecretId!, cancellationToken)
            : await gateway.UploadAsync(options, context.Secret, bundle, cancellationToken);
        context.Deployment.ExternalResourceReference = state.CertificateResourceId;
        return new(IsSucceeded(state), $"Application Gateway listener certificate '{options.SslCertificateName}' was updated.");
    }

    public Task<DeploymentActivationResult> ActivateAsync(DeploymentContext context, CancellationToken cancellationToken) =>
        Task.FromResult(new DeploymentActivationResult(true, "Application Gateway update activates the listener certificate atomically."));

    public async Task<DeploymentVerificationResult> VerifyAsync(DeploymentContext context, IssuedCertificateBundle bundle, CancellationToken cancellationToken)
    {
        var options = AzureApplicationGatewayTargetOptions.Parse(context.Target);
        var state = await gateway.GetAsync(options, context.Secret, cancellationToken);
        if (!IsSucceeded(state) || !state.ListenerExists || !state.ListenerIsHttps ||
            !string.Equals(state.ListenerCertificateId, state.CertificateResourceId, StringComparison.OrdinalIgnoreCase))
            return new(false, Message: "Application Gateway listener configuration or provisioning state could not be verified.");
        if (options.DeploymentMode == AzureApplicationGatewayDeploymentMode.KeyVaultReference &&
            !string.Equals(state.KeyVaultSecretId?.TrimEnd('/'), options.KeyVaultSecretId!.ToString().TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
            return new(false, Message: "Application Gateway Key Vault secret reference does not match.");
        var external = await tlsVerifier.VerifyAsync(options.ExternalVerificationEndpoints, bundle.Fingerprint, cancellationToken);
        return new(external.Succeeded, external.ObservedFingerprint, external.Message);
    }

    public async Task<DeploymentRollbackResult> RollbackAsync(DeploymentContext context, DeploymentBackupResult backup, CancellationToken cancellationToken)
    {
        AzureApplicationGatewayBackupManifest? manifest;
        try { manifest = JsonSerializer.Deserialize<AzureApplicationGatewayBackupManifest>(backup.BackupReference ?? ""); }
        catch (JsonException) { manifest = null; }
        if (manifest is null || manifest.DeploymentId != context.Deployment.Id) return new(false, Message: "Application Gateway rollback manifest is invalid.");
        var options = AzureApplicationGatewayTargetOptions.Parse(context.Target);
        AzureApplicationGatewayState state;
        string expected;
        if (options.DeploymentMode == AzureApplicationGatewayDeploymentMode.DirectUpload)
        {
            if (manifest.PreviousSourceVaultVersion is null) return new(false, Message: "Previous source Vault version is unavailable.");
            var previous = await bundles.LoadVersionAsync(context.Deployment, manifest.PreviousSourceVaultVersion.Value, cancellationToken);
            expected = previous.Fingerprint;
            state = await gateway.UploadAsync(options, context.Secret, previous, cancellationToken);
        }
        else
        {
            if (manifest.PreviousListenerCertificateId is null) return new(false, Message: "Previous listener certificate reference is unavailable.");
            expected = manifest.PreviousFingerprint ?? string.Empty;
            state = await gateway.RestoreReferenceAsync(options, context.Secret, manifest.PreviousListenerCertificateId, manifest.PreviousKeyVaultSecretId, cancellationToken);
        }
        if (!IsSucceeded(state)) return new(false, Message: "Application Gateway rollback provisioning failed.");
        if (!string.IsNullOrWhiteSpace(expected))
        {
            var external = await tlsVerifier.VerifyAsync(options.ExternalVerificationEndpoints, expected, cancellationToken);
            return new(external.Succeeded, external.ObservedFingerprint, external.Message);
        }
        return new(true, Message: "Previous Application Gateway certificate reference was restored.");
    }

    private static DeploymentValidationResult ValidateState(AzureApplicationGatewayTargetOptions options, AzureApplicationGatewayState state)
    {
        if (!IsSucceeded(state)) return new(false, $"Application Gateway provisioning state is '{state.ProvisioningState}'.");
        if (!state.ListenerExists) return new(false, $"HTTPS listener '{options.ListenerName}' was not found.");
        if (!state.ListenerIsHttps) return new(false, $"Listener '{options.ListenerName}' is not HTTPS.");
        if (options.DeploymentMode == AzureApplicationGatewayDeploymentMode.KeyVaultReference && !state.HasUserAssignedIdentity)
            return new(false, "Key Vault reference mode requires a user-assigned identity on Application Gateway.");
        return new(true, "Azure Application Gateway target was validated.");
    }
    private static bool IsSucceeded(AzureApplicationGatewayState state) => string.Equals(state.ProvisioningState, "Succeeded", StringComparison.OrdinalIgnoreCase);
    private static void ValidateSecret(AzureApplicationGatewayTargetOptions options, string? secret)
    {
        if (options.AuthenticationMode == AzureKeyVaultAuthenticationMode.ServicePrincipal && string.IsNullOrWhiteSpace(secret))
            throw new InvalidOperationException("ServicePrincipal authentication requires a protected client secret.");
        if (options.AuthenticationMode != AzureKeyVaultAuthenticationMode.ServicePrincipal && !string.IsNullOrWhiteSpace(secret))
            throw new InvalidOperationException("Target Secret is accepted only with ServicePrincipal authentication.");
    }
}
