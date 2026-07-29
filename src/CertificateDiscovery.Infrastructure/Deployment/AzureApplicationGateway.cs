using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models;
using Azure.ResourceManager.Resources;
using CertificateDiscovery.Application.Deployment;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed class AzureApplicationGateway : IAzureApplicationGateway
{
    public Task<AzureApplicationGatewayState> GetAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, CancellationToken cancellationToken) =>
        MutateAsync(options, clientSecret, null, cancellationToken);

    public Task<AzureApplicationGatewayState> ApplyKeyVaultReferenceAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, Uri secretId, CancellationToken cancellationToken) =>
        MutateAsync(options, clientSecret, data =>
        {
            var certificate = FindOrCreateCertificate(data, options);
            certificate.Data = null;
            certificate.Password = null;
            certificate.KeyVaultSecretId = secretId.ToString();
            BindListener(data, options, certificate.Id);
        }, cancellationToken);

    public async Task<AzureApplicationGatewayState> UploadAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, IssuedCertificateBundle bundle, CancellationToken cancellationToken)
    {
        var password = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var pfx = AzureKeyVaultCertificateGateway.CreatePfx(bundle, password);
        try
        {
            return await MutateAsync(options, clientSecret, data =>
            {
                var certificate = FindOrCreateCertificate(data, options);
                certificate.KeyVaultSecretId = null;
                certificate.Data = BinaryData.FromBytes(pfx);
                certificate.Password = password;
                BindListener(data, options, certificate.Id);
            }, cancellationToken);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(pfx);
        }
    }

    public Task<AzureApplicationGatewayState> RestoreReferenceAsync(AzureApplicationGatewayTargetOptions options, string? clientSecret, string listenerCertificateId, string? secretId, CancellationToken cancellationToken) =>
        MutateAsync(options, clientSecret, data =>
        {
            var listener = Listener(data, options);
            listener.SslCertificateId = new ResourceIdentifier(listenerCertificateId);
            if (!string.IsNullOrWhiteSpace(secretId))
            {
                var certificate = data.SslCertificates.FirstOrDefault(x => x.Id == listener.SslCertificateId);
                if (certificate is not null) certificate.KeyVaultSecretId = secretId;
            }
        }, cancellationToken);

    private static async Task<AzureApplicationGatewayState> MutateAsync(
        AzureApplicationGatewayTargetOptions options, string? clientSecret,
        Action<ApplicationGatewayData>? mutation, CancellationToken cancellationToken)
    {
        var arm = new ArmClient(Credential(options, clientSecret), options.SubscriptionId);
        var subscription = arm.GetSubscriptionResource(SubscriptionResource.CreateResourceIdentifier(options.SubscriptionId));
        var group = await subscription.GetResourceGroupAsync(options.ResourceGroup, cancellationToken);
        var collection = group.Value.GetApplicationGateways();
        var response = await collection.GetAsync(options.ApplicationGatewayName, cancellationToken);
        var data = response.Value.Data;
        if (mutation is not null)
        {
            mutation(data);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(options.ProvisioningTimeoutSeconds));
            var operation = await collection.CreateOrUpdateAsync(WaitUntil.Completed, options.ApplicationGatewayName, data, timeout.Token);
            data = operation.Value.Data;
        }
        return State(data, options);
    }

    private static AzureApplicationGatewayState State(ApplicationGatewayData data, AzureApplicationGatewayTargetOptions options)
    {
        var listener = data.HttpListeners.FirstOrDefault(x => string.Equals(x.Name, options.ListenerName, StringComparison.OrdinalIgnoreCase));
        var certificate = data.SslCertificates.FirstOrDefault(x => string.Equals(x.Name, options.SslCertificateName, StringComparison.OrdinalIgnoreCase));
        return new(data.Id.ToString(), data.ProvisioningState?.ToString() ?? "Unknown",
            data.Identity?.UserAssignedIdentities?.Count > 0, listener is not null,
            listener?.Protocol == ApplicationGatewayProtocol.Https, listener?.SslCertificateId?.ToString(),
            certificate?.Id?.ToString(), certificate?.KeyVaultSecretId?.ToString());
    }

    private static ApplicationGatewaySslCertificate FindOrCreateCertificate(ApplicationGatewayData data, AzureApplicationGatewayTargetOptions options)
    {
        var certificate = data.SslCertificates.FirstOrDefault(x => string.Equals(x.Name, options.SslCertificateName, StringComparison.OrdinalIgnoreCase));
        if (certificate is not null) return certificate;
        certificate = new ApplicationGatewaySslCertificate
        {
            Name = options.SslCertificateName,
            Id = new ResourceIdentifier($"{data.Id}/sslCertificates/{options.SslCertificateName}")
        };
        data.SslCertificates.Add(certificate);
        return certificate;
    }

    private static void BindListener(ApplicationGatewayData data, AzureApplicationGatewayTargetOptions options, ResourceIdentifier? certificateId) =>
        Listener(data, options).SslCertificateId = certificateId;

    private static ApplicationGatewayHttpListener Listener(ApplicationGatewayData data, AzureApplicationGatewayTargetOptions options) =>
        data.HttpListeners.FirstOrDefault(x => string.Equals(x.Name, options.ListenerName, StringComparison.OrdinalIgnoreCase))
        ?? throw new InvalidOperationException($"Application Gateway listener '{options.ListenerName}' was not found.");

    private static TokenCredential Credential(AzureApplicationGatewayTargetOptions options, string? secret) =>
        options.AuthenticationMode switch
        {
            Domain.AzureKeyVaultAuthenticationMode.ManagedIdentity => string.IsNullOrWhiteSpace(options.ManagedIdentityClientId)
                ? new ManagedIdentityCredential() : new ManagedIdentityCredential(options.ManagedIdentityClientId),
            Domain.AzureKeyVaultAuthenticationMode.WorkloadIdentity => new WorkloadIdentityCredential(new WorkloadIdentityCredentialOptions { TenantId = options.TenantId, ClientId = options.ClientId }),
            Domain.AzureKeyVaultAuthenticationMode.ServicePrincipal => new ClientSecretCredential(options.TenantId!, options.ClientId!, secret!),
            _ => new DefaultAzureCredential()
        };
}
