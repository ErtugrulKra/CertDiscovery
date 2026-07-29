using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Infrastructure.Deployment;
using CertificateDiscovery.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CertificateDiscovery.UnitTests;

public sealed class CertificateDeployerContractTests
{
    [Fact]
    public void Dependency_injection_registers_every_planned_P5_deployer_once()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:DefaultConnection"] = "Data Source=:memory:",
            ["CertificateDiscovery:SchedulerEnabled"] = "false"
        }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCertificateDiscoveryInfrastructure(configuration);
        var registeredTypes = services
            .Where(x => x.ServiceType == typeof(ICertificateDeployer))
            .Select(x => x.ImplementationType)
            .ToList();
        var expected = new Type[]
        {
            typeof(FakeCertificateDeployer),
            typeof(VaultKvCertificateDeployer),
            typeof(FileSystemCertificateDeployer),
            typeof(KubernetesTlsSecretDeployer),
            typeof(IisAgentCertificateDeployer),
            typeof(NginxSshCertificateDeployer),
            typeof(ApacheSshCertificateDeployer),
            typeof(AwsAcmCertificateDeployer),
            typeof(AzureKeyVaultCertificateDeployer),
            typeof(AzureApplicationGatewayDeployer)
        };

        Assert.Equal(expected.OrderBy(x => x.FullName), registeredTypes.OrderBy(x => x!.FullName));
        Assert.Equal(registeredTypes.Count, registeredTypes.Distinct().Count());
    }
}
