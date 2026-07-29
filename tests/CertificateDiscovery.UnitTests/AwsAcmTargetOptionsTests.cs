using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class AwsAcmTargetOptionsTests
{
    [Fact]
    public void Parses_secure_default_chain_target()
    {
        var options = AwsAcmTargetOptions.Parse(Target());

        Assert.Equal("eu-central-1", options.Region);
        Assert.Equal(AwsAcmAuthenticationMode.DefaultCredentialChain, options.AuthenticationMode);
        Assert.True(options.CreateIfMissing);
        Assert.True(options.RequirePreviousVaultVersionForUpdate);
        Assert.Equal("CertDiscovery", options.Tags["ManagedBy"]);
    }

    [Fact]
    public void Requires_role_arn_for_assume_role()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            AwsAcmTargetOptions.Parse(Target("\"authenticationMode\":\"AssumeRole\",")));

        Assert.Contains("roleArn", exception.Message);
    }

    [Fact]
    public void Rejects_certificate_arn_from_another_region()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            AwsAcmTargetOptions.Parse(Target(
                "\"certificateArn\":\"arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555\",")));

        Assert.Contains("region", exception.Message);
    }

    [Theory]
    [InlineData("StaticCredentials")]
    [InlineData("AccessKey")]
    public void Rejects_static_credentials(string mode) =>
        Assert.Throws<InvalidOperationException>(() =>
            AwsAcmTargetOptions.Parse(Target($"\"authenticationMode\":\"{mode}\",")));

    [Fact]
    public void Rejects_static_credential_fields_even_with_default_chain()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            AwsAcmTargetOptions.Parse(Target(
                "\"accessKeyId\":\"AKIAEXAMPLE\",\"secretAccessKey\":\"secret\",")));

        Assert.Contains("static AWS credentials", exception.Message);
    }

    internal static DeploymentTarget Target(string additional = "") => new()
    {
        TargetType = DeploymentTargetType.AwsAcm,
        ConfigurationJson =
            $$"""
              {
                "region":"eu-central-1",
                {{additional}}
                "createIfMissing":true,
                "requirePreviousVaultVersionForUpdate":true,
                "tags":{"ManagedBy":"CertDiscovery"},
                "externalVerificationEndpoints":["https://example.com:443"]
              }
              """
    };
}
