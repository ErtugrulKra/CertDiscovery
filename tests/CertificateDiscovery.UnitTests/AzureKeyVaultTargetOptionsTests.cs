using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class AzureKeyVaultTargetOptionsTests
{
    [Theory]
    [InlineData("Pfx", "application/x-pkcs12")]
    [InlineData("Pem", "application/x-pem-file")]
    public void Parses_supported_import_formats(string format, string contentType)
    {
        var options = AzureKeyVaultTargetOptions.Parse(Target(
            $"\"importFormat\":\"{format}\",\"contentType\":\"{contentType}\","));

        Assert.Equal(format, options.ImportFormat.ToString());
        Assert.Equal(contentType, options.ContentType);
        Assert.Equal("certificates", options.VaultUri.Host.Split('.')[0]);
    }

    [Fact]
    public void Requires_service_principal_identity_fields()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            AzureKeyVaultTargetOptions.Parse(Target(
                "\"authenticationMode\":\"ServicePrincipal\",")));

        Assert.Contains("tenantId and clientId", exception.Message);
    }

    [Fact]
    public void Rejects_credentials_in_configuration()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            AzureKeyVaultTargetOptions.Parse(Target(
                "\"clientSecret\":\"must-not-be-here\",")));

        Assert.Contains("must not contain credentials", exception.Message);
    }

    [Fact]
    public void Rejects_content_type_that_conflicts_with_format()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            AzureKeyVaultTargetOptions.Parse(Target(
                "\"importFormat\":\"Pem\",\"contentType\":\"application/x-pkcs12\",")));

        Assert.Contains("application/x-pem-file", exception.Message);
    }

    internal static DeploymentTarget Target(string additional = "") => new()
    {
        TargetType = DeploymentTargetType.AzureKeyVault,
        ConfigurationJson =
            $$"""
              {
                "vaultUri":"https://certificates.vault.azure.net/",
                "certificateName":"example-com",
                {{additional}}
                "enabled":true,
                "preserveCertificateOrder":false,
                "requirePreviousVaultVersionForRollback":true,
                "tags":{"environment":"test"},
                "externalVerificationEndpoints":[]
              }
              """
    };
}
