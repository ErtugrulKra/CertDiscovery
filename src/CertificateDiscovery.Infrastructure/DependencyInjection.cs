namespace CertificateDiscovery.Infrastructure;

using CertificateDiscovery.Application.Options;
using CertificateDiscovery.Application.Acme;
using CertificateDiscovery.Application.Inventory;
using CertificateDiscovery.Application.Requests;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Infrastructure.Acme;
using CertificateDiscovery.Infrastructure.Dns;
using CertificateDiscovery.Infrastructure.Inventory;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Scheduling;
using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Infrastructure.Secrets;
using CertificateDiscovery.Infrastructure.Storage;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Infrastructure.Deployment;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

public static class DependencyInjection
{
    public static IServiceCollection AddCertificateDiscoveryInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetSection("CertificateDiscovery");
        services.Configure<CertificateDiscoveryOptions>(options =>
        {
            options.WorkerApiKey = section["WorkerApiKey"] ?? options.WorkerApiKey;
            options.SchedulerEnabled = ReadBool(section["SchedulerEnabled"], options.SchedulerEnabled);
            options.DefaultScanIntervalMinutes = ReadInt(section["DefaultScanIntervalMinutes"], options.DefaultScanIntervalMinutes);
            options.ExpireAttentionDays = ReadInt(section["ExpireAttentionDays"], options.ExpireAttentionDays);
            options.ExpireWarningDays = ReadInt(section["ExpireWarningDays"], options.ExpireWarningDays);
            options.ExpireCriticalDays = ReadInt(section["ExpireCriticalDays"], options.ExpireCriticalDays);
            options.MaxConcurrentScans = ReadInt(section["MaxConcurrentScans"], options.MaxConcurrentScans);
            options.ApplyMigrationsOnStartup = ReadBool(section["ApplyMigrationsOnStartup"], options.ApplyMigrationsOnStartup);
        });
        services.AddDbContext<CertificateDiscoveryDbContext>(options =>
            options.UseSqlite(configuration.GetConnectionString("DefaultConnection") ?? "Data Source=certificate-discovery.db"));

        services.AddScoped<AssetService>();
        services.AddScoped<CertificateService>();
        services.AddScoped<ScanJobService>();
        services.AddScoped<WorkerService>();
        services.AddScoped<DashboardService>();
        services.AddScoped<UserService>();
        services.AddScoped<NetworkDiscoveryService>();
        services.AddScoped<ApplicationSettingsService>();
        services.AddScoped<PrometheusMetricsService>();
        services.AddScoped<IntegrationService>();
        services.AddScoped<VaultCertificateImportService>();
        services.AddScoped<CertificateRequestService>();
        services.AddScoped<VaultDiscoveryService>();
        services.AddScoped<DeploymentService>();
        services.AddScoped<DeploymentAgentService>();
        services.AddScoped<AgentDeploymentJobService>();
        services.AddScoped<ICertificateInventoryWriter, CertificateInventoryWriter>();
        services.AddScoped<ICertificateRequestStateMachine, CertificateRequestStateMachine>();
        services.AddScoped<ISecretProvider, ProtectedDbSecretProvider>();
        services.AddScoped<LegacySecretMigrationService>();
        services.AddScoped<IAcmeAccountService, AcmeAccountService>();
        services.AddScoped<IDeploymentStateMachine, DeploymentStateMachine>();
        services.AddScoped<ICertificateBundleConverter, CertificateBundleConverter>();
        services.AddScoped<VaultDeploymentCertificateBundleSource>();
        services.AddScoped<IDeploymentCertificateBundleSource>(
            provider => provider.GetRequiredService<VaultDeploymentCertificateBundleSource>());
        services.AddScoped<IVersionedDeploymentCertificateBundleSource>(
            provider => provider.GetRequiredService<VaultDeploymentCertificateBundleSource>());
        services.AddScoped<IDeploymentQueue, DeploymentQueue>();
        services.AddScoped<ICertificateDeploymentOrchestrator, CertificateDeploymentOrchestrator>();
        services.AddScoped<ICertificateDeployer, FakeCertificateDeployer>();
        services.AddScoped<ICertificateDeployer, VaultKvCertificateDeployer>();
        services.AddScoped<ICertificateDeployer, FileSystemCertificateDeployer>();
        services.AddScoped<ICertificateDeployer, KubernetesTlsSecretDeployer>();
        services.AddScoped<ICertificateDeployer, IisAgentCertificateDeployer>();
        services.AddScoped<ISshCredentialSource, VaultSshCredentialSource>();
        services.AddScoped<ISshRemoteClient, SshNetRemoteClient>();
        services.AddScoped<ITlsEndpointVerifier, TlsEndpointVerifier>();
        services.AddScoped<IAwsAcmClientFactory, AwsAcmClientFactory>();
        services.AddScoped<IAwsAcmGateway, AwsAcmGateway>();
        services.AddScoped<ICertificateDeployer, AwsAcmCertificateDeployer>();
        services.AddScoped<IAzureKeyVaultCertificateClientFactory, AzureKeyVaultCertificateClientFactory>();
        services.AddScoped<IAzureKeyVaultCertificateGateway, AzureKeyVaultCertificateGateway>();
        services.AddScoped<ICertificateDeployer, AzureKeyVaultCertificateDeployer>();
        services.AddScoped<ICertificateDeployer, NginxSshCertificateDeployer>();
        services.AddScoped<ICertificateDeployer, ApacheSshCertificateDeployer>();
        services.AddScoped<ICertificateDeployerResolver, CertificateDeployerResolver>();
        services.AddAcmeServices();
        services.AddDnsChallengeProviders();
        services.AddCertificateStores();
        services.AddHttpClient();
        services.AddHostedService<ScanSchedulerService>();
        services.AddHostedService<CertificateRequestRenewalWorker>();
        services.AddHostedService<DeploymentWorker>();
        return services;
    }

    private static int ReadInt(string? value, int fallback) => int.TryParse(value, out var parsed) ? parsed : fallback;
    private static bool ReadBool(string? value, bool fallback) => bool.TryParse(value, out var parsed) ? parsed : fallback;
}
