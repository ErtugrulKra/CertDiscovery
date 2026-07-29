using Amazon;
using Amazon.CertificateManager;
using Amazon.Runtime;
using Amazon.Runtime.Credentials;
using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Infrastructure.Deployment;

public interface IAwsAcmClientFactory
{
    Task<IAmazonCertificateManager> CreateAsync(
        AwsAcmTargetOptions options,
        string? externalId,
        CancellationToken cancellationToken);
}

public sealed class AwsAcmClientFactory : IAwsAcmClientFactory
{
    public Task<IAmazonCertificateManager> CreateAsync(
        AwsAcmTargetOptions options,
        string? externalId,
        CancellationToken cancellationToken)
    {
        var config = new AmazonCertificateManagerConfig
        {
            RegionEndpoint = RegionEndpoint.GetBySystemName(options.Region)
        };
        AWSCredentials? credentials = null;
        if (options.AuthenticationMode == AwsAcmAuthenticationMode.AssumeRole)
        {
            var source = DefaultAWSCredentialsIdentityResolver.GetCredentials(config);
            var assumeRoleOptions = new AssumeRoleAWSCredentialsOptions();
            if (!string.IsNullOrWhiteSpace(externalId))
                assumeRoleOptions.ExternalId = externalId;
            credentials = new AssumeRoleAWSCredentials(
                source,
                options.RoleArn!,
                $"certdiscovery-acm-{Guid.NewGuid():N}",
                assumeRoleOptions);
        }
        IAmazonCertificateManager client = credentials is null
            ? new AmazonCertificateManagerClient(config)
            : new AmazonCertificateManagerClient(credentials, config);
        return Task.FromResult(client);
    }
}
