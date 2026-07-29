using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Infrastructure.Deployment;

public interface IAzureKeyVaultCertificateClientFactory
{
    CertificateClient Create(AzureKeyVaultTargetOptions options, string? clientSecret);
}

public sealed class AzureKeyVaultCertificateClientFactory : IAzureKeyVaultCertificateClientFactory
{
    public CertificateClient Create(AzureKeyVaultTargetOptions options, string? clientSecret) =>
        new(options.VaultUri, Credential(options, clientSecret));

    private static TokenCredential Credential(AzureKeyVaultTargetOptions options, string? clientSecret) =>
        options.AuthenticationMode switch
        {
            AzureKeyVaultAuthenticationMode.ManagedIdentity =>
                string.IsNullOrWhiteSpace(options.ManagedIdentityClientId)
                    ? new ManagedIdentityCredential()
                    : new ManagedIdentityCredential(options.ManagedIdentityClientId),
            AzureKeyVaultAuthenticationMode.WorkloadIdentity =>
                new WorkloadIdentityCredential(new WorkloadIdentityCredentialOptions
                {
                    TenantId = options.TenantId,
                    ClientId = options.ClientId
                }),
            AzureKeyVaultAuthenticationMode.ServicePrincipal =>
                new ClientSecretCredential(
                    options.TenantId!,
                    options.ClientId!,
                    !string.IsNullOrWhiteSpace(clientSecret)
                        ? clientSecret
                        : throw new InvalidOperationException(
                            "Azure Key Vault service-principal authentication requires a protected client secret.")),
            _ => new DefaultAzureCredential()
        };
}
