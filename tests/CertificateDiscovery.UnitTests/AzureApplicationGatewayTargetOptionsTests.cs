using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class AzureApplicationGatewayTargetOptionsTests
{
    [Fact]
    public void Parses_versionless_Key_Vault_reference()
    {
        var options = AzureApplicationGatewayTargetOptions.Parse(Target());
        Assert.Equal(AzureApplicationGatewayDeploymentMode.KeyVaultReference, options.DeploymentMode);
        Assert.Equal("listener", options.ListenerName);
        Assert.Equal("https://certs.vault.azure.net/secrets/example-com", options.KeyVaultSecretId!.ToString());
    }

    [Theory]
    [InlineData("\"clientSecret\":\"unsafe\",")]
    [InlineData("\"privateKey\":\"unsafe\",")]
    [InlineData("\"pfxPassword\":\"unsafe\",")]
    public void Rejects_sensitive_configuration(string fragment) =>
        Assert.Throws<InvalidOperationException>(() => AzureApplicationGatewayTargetOptions.Parse(Target(fragment)));

    [Fact]
    public void Rejects_versioned_Key_Vault_secret_reference() =>
        Assert.Throws<InvalidOperationException>(() => AzureApplicationGatewayTargetOptions.Parse(
            Target(keyVaultSecretId: "https://certs.vault.azure.net/secrets/example-com/version")));

    [Fact]
    public void Requires_external_verification_endpoint() =>
        Assert.Throws<InvalidOperationException>(() => AzureApplicationGatewayTargetOptions.Parse(
            Target(endpoints: "[]")));

    internal static DeploymentTarget Target(
        string fragment = "",
        string keyVaultSecretId = "https://certs.vault.azure.net/secrets/example-com",
        string mode = "KeyVaultReference",
        string endpoints = "[\"https://example.com\"]") => new()
    {
        TargetType = DeploymentTargetType.AzureApplicationGateway,
        ConfigurationJson = $$"""
        {
          {{fragment}}
          "subscriptionId":"00000000-0000-0000-0000-000000000000",
          "resourceGroup":"network-rg",
          "applicationGatewayName":"appgw",
          "listenerName":"listener",
          "sslCertificateName":"example-com",
          "deploymentMode":"{{mode}}",
          "keyVaultSecretId":{{(mode == "DirectUpload" ? "null" : $"\"{keyVaultSecretId}\"")}},
          "authenticationMode":"DefaultAzureCredential",
          "provisioningTimeoutSeconds":900,
          "externalVerificationEndpoints":{{endpoints}}
        }
        """
    };
}
